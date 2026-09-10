#!/usr/bin/env python3
"""
IDOR candidate scanner — SINGLE-SESSION ID manipulation only.

====================================================================
LIMITATION — READ BEFORE USING ANY OUTPUT FROM THIS SCANNER
====================================================================
This scanner uses exactly ONE session/identity throughout an entire run.
That structurally limits what it can ever detect to the "no ownership
check at all" case: an endpoint that doesn't verify the caller owns the
object at all, so even re-requesting under the SAME session with a
different ID returns different data. That is real, but it is the LESS
COMMON IDOR pattern in practice.

The far more common pattern — "checks that you're logged in, but not that
you own THIS specific object" — is invisible to this scanner by
construction: detecting it requires comparing what TWO DIFFERENT real
user identities can each reach (does User A's session return User B's
data?), and this scanner never has more than one identity to work with.
That comparison is out of scope here on purpose, not an oversight.

Every finding this scanner produces is therefore a CANDIDATE requiring
manual verification with a second identity — never a confirmed IDOR.
Severity is POSSIBLE at every single finding, never CONFIRMED/CRITICAL,
and every finding's `note` field restates this requirement explicitly, not
just once in this docstring. Same "don't let a weaker claim get read as a
stronger one" discipline as ssrf_scanner.py's --oob ambiguity handling.

A known false-positive source in the other direction: APIs that echo the
requested ID back inside an otherwise-generic error message (e.g. "Order
124 not found") can push the not-found-control similarity ratio below the
reject threshold on the digit difference alone, surfacing an already-secure
endpoint as a candidate. This is exactly the kind of ambiguous case manual
verification exists to filter out — see classify_candidate()'s tests.
====================================================================

Detection: identifies URLs with a numeric object reference either in the
path (/api/orders/123, /user/456/profile) or in a query parameter
(?id=123, ?order_id=456). For each, fires 7 requests under the SAME
session (Cookie header, if provided, unchanged across every request):
  1 baseline           — the original ID, unmodified
  1 negative control   — a deliberately out-of-range ID (999999999), to
                          learn what "not found" looks like for THIS app
  4 nearby IDs         — original -2, -1, +1, +2
  1 far-away ID        — original + a random offset (1000-100000)

A nearby/far ID is a candidate only if its response is HTTP 200 AND its
body is meaningfully different from BOTH the baseline response (not just
a byte-identical page shell re-served regardless of ID) AND the negative
control (not just another "not found" page) — using difflib content
similarity, not just length/status, per the two explicit conditions this
scanner was asked to check.

Query-param ID names are not invented fresh: reused verbatim from
tools/lead_board.py's existing hunt-idor routing rule (id, uid, user_id,
userid, account, account_id, order, order_id, invoice, doc, doc_id,
file_id, record, profile, customer, cid, pid, num, no, key), with a
stricter numeric-value requirement than that rule's own "starts with a
digit" match, because this scanner does integer arithmetic on the value.
Path-segment ID detection has no existing pattern anywhere in this repo
(grepped first, confirmed absent) -- that part is new.

Cost note: 7 requests per candidate ID found. A URL with several
candidate IDs gets expensive fast.

Uses safe_http.py's safe_urlopen() with its DEFAULT redirect-following
behavior (unlike openredirect_scanner.py/ssrf_scanner.py, which
deliberately used follow_redirects=False because a raw redirect hop WAS
the signal there) -- here we want the final rendered content to compare,
not an intermediate hop, so the default is the right mode, not a
follow_redirects=False override.

Usage:
  tools/idor_scanner.py "https://api.target.com/orders/1042" --cookie "session=..."
  tools/idor_scanner.py -l urls.txt --cookie "session=..." --json
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import random
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
from tools.safe_http import safe_urlopen  # noqa: E402

USER_AGENT = "agentic-bug-hunter/idor_scanner"

POSSIBLE = "POSSIBLE"  # the only severity this scanner ever produces -- see module docstring

MAX_BODY_BYTES = 65536
NEGATIVE_CONTROL_ID = 999999999  # deliberately out of range; safer than 0, which can be a
                                  # genuinely valid ID in 0-indexed systems

# >= this similarity ratio to baseline -> treated as the same generic page
# shell re-served regardless of ID, not ID-specific content.
SIMILARITY_SAME_AS_BASELINE = 0.97
# >= this similarity ratio to the negative-control response -> treated as
# just another "not found" page, i.e. correctly rejected.
SIMILARITY_SAME_AS_NOT_FOUND = 0.90

ID_QUERY_PARAM_NAMES = {
    # Reused verbatim from tools/lead_board.py's hunt-idor routing rule:
    "id", "uid", "user_id", "userid", "account", "account_id", "order",
    "order_id", "invoice", "doc", "doc_id", "file_id", "record", "profile",
    "customer", "cid", "pid", "num", "no", "key",
}


@dataclass
class IdCandidate:
    kind: str  # "path" | "query"
    label: str
    original_value: int
    path_index: int | None = None
    query_param: str | None = None


@dataclass
class IdorFinding:
    url: str
    id_source: str
    original_id: int
    candidate_id: int
    evidence: str
    severity: str
    title: str
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "id_source": self.id_source,
            "original_id": self.original_id,
            "candidate_id": self.candidate_id,
            "evidence": self.evidence,
            "severity": self.severity,
            "title": self.title,
            "note": self.note,
        }


def find_id_candidates(url: str) -> list[IdCandidate]:
    """Numeric object references on `url`: path segments that are entirely
    digits, plus query params whose name matches ID_QUERY_PARAM_NAMES and
    whose value is entirely digits. Pure function."""
    candidates: list[IdCandidate] = []
    parsed = urlparse(url)

    segments = parsed.path.split("/")
    for idx, seg in enumerate(segments):
        if seg.isdigit():
            candidates.append(IdCandidate(
                kind="path", label=f"path segment #{idx} ({seg!r})",
                original_value=int(seg), path_index=idx,
            ))

    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in ID_QUERY_PARAM_NAMES and value.isdigit():
            candidates.append(IdCandidate(
                kind="query", label=f"query param `{key}`",
                original_value=int(value), query_param=key,
            ))

    return candidates


def build_candidate_url(url: str, candidate: IdCandidate, new_value: int) -> str:
    """`url` with `candidate`'s path segment or query param replaced by
    `new_value`. Pure function."""
    parsed = urlparse(url)
    if candidate.kind == "path":
        segments = parsed.path.split("/")
        segments[candidate.path_index] = str(new_value)
        return urlunparse(parsed._replace(path="/".join(segments)))
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [
        (k, str(new_value) if k == candidate.query_param else v) for k, v in pairs
    ]
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def _nearby_ids(original: int) -> list[int]:
    """original -2, -1, +1, +2 -- excluding negatives and the original
    itself. Pure function."""
    return sorted({v for v in (original - 2, original - 1, original + 1, original + 2)
                   if v >= 0 and v != original})


def _far_id(original: int) -> int:
    """original + a random offset in [1000, 100000) -- clearly outside the
    near-neighbor range, staying positive."""
    return original + random.randint(1000, 100000)


def _similarity(a: str, b: str) -> float:
    """difflib content-similarity ratio, 0.0-1.0. Pure function."""
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def classify_candidate(
    candidate: IdCandidate,
    test_id: int,
    baseline_status: int | None,
    baseline_body: str,
    notfound_status: int | None,
    notfound_body: str,
    test_status: int | None,
    test_body: str,
) -> tuple[str, float, float] | None:
    """Pure classification logic: returns (evidence, sim_to_baseline,
    sim_to_notfound) if `test_id` looks like a genuine candidate, else
    None. HTTP 200 required; body must differ meaningfully from BOTH the
    baseline and the negative control -- either condition alone isn't
    enough (matches both explicit checks this scanner was asked to make).
    """
    if test_status != 200 or not test_body:
        return None

    sim_to_notfound = _similarity(test_body, notfound_body)
    if sim_to_notfound >= SIMILARITY_SAME_AS_NOT_FOUND:
        return None  # looks like another "not found" page -- correctly rejected

    sim_to_baseline = _similarity(test_body, baseline_body)
    if sim_to_baseline >= SIMILARITY_SAME_AS_BASELINE:
        return None  # same generic shell as baseline, no ID-specific content

    evidence = (
        f"HTTP 200; {sim_to_baseline:.0%} similar to baseline (original ID "
        f"{candidate.original_value}), {sim_to_notfound:.0%} similar to the "
        f"not-found control -- response looks like genuinely different, "
        f"ID-specific content, not a generic shell or an error page"
    )
    return evidence, sim_to_baseline, sim_to_notfound


def _fetch_body(url: str, cookie: str | None, timeout: int) -> tuple[int | None, str]:
    """GET `url` (default redirect-following -- see module docstring for
    why this scanner doesn't use follow_redirects=False); return
    (status_or_None, body_text)."""
    headers = {"User-Agent": USER_AGENT}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        resp = safe_urlopen(req, timeout=timeout)
        try:
            raw = resp.read(MAX_BODY_BYTES)
            return resp.status, raw.decode("utf-8", errors="replace") if raw else ""
        finally:
            close = getattr(resp, "close", None)
            if callable(close):
                close()
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(MAX_BODY_BYTES) if hasattr(e, "read") else b""
        except Exception:  # noqa: BLE001
            raw = b""
        return e.code, raw.decode("utf-8", errors="replace") if raw else ""
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return None, ""


def scan_url(url: str, cookie: str | None = None, timeout: int = 15) -> list[IdorFinding]:
    findings: list[IdorFinding] = []

    candidates = find_id_candidates(url)
    if not candidates:
        return findings

    # Fetched once per URL, not once per candidate -- every candidate shares
    # the same unmodified baseline response, so a URL with N candidate IDs
    # (e.g. a path ID and a query-param ID on the same URL) doesn't fire N
    # identical baseline requests.
    baseline_status, baseline_body = _fetch_body(url, cookie, timeout)

    for candidate in candidates:
        notfound_url = build_candidate_url(url, candidate, NEGATIVE_CONTROL_ID)
        notfound_status, notfound_body = _fetch_body(notfound_url, cookie, timeout)

        test_ids = _nearby_ids(candidate.original_value) + [_far_id(candidate.original_value)]
        for test_id in test_ids:
            test_url = build_candidate_url(url, candidate, test_id)
            test_status, test_body = _fetch_body(test_url, cookie, timeout)

            result = classify_candidate(
                candidate, test_id,
                baseline_status, baseline_body,
                notfound_status, notfound_body,
                test_status, test_body,
            )
            if result is None:
                continue
            evidence, _sim_b, _sim_nf = result
            findings.append(IdorFinding(
                url, candidate.label, candidate.original_value, test_id,
                evidence, POSSIBLE,
                f"Possible IDOR candidate via {candidate.label} "
                f"(ID {candidate.original_value} -> {test_id})",
                "CANDIDATE ONLY, NOT CONFIRMED -- this scanner used a single "
                "session throughout and can only detect a 'no ownership "
                "check at all' pattern. It CANNOT detect the more common "
                "'checks login but not ownership' pattern, which requires "
                "comparing access from two DIFFERENT real user identities. "
                "Manually verify with a second, unrelated account before "
                "treating this as a real finding.",
            ))

    return findings


def _print_human(url: str, findings: list[IdorFinding]) -> None:
    if not findings:
        print(f"[ok] {url} — no IDOR candidates detected")
        return
    for f in findings:
        print(f"[{f.severity}] {f.title}")
        print(f"    url:      {f.url}")
        print(f"    source:   {f.id_source}")
        print(f"    ids:      {f.original_id} -> {f.candidate_id}")
        print(f"    evidence: {f.evidence}")
        if f.note:
            print(f"    note:     {f.note}")
    print(
        f"\n{len(findings)} IDOR CANDIDATE(S) on {url} — manual verification "
        f"with a second identity required; none of these are confirmed."
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="IDOR candidate scanner (single-session; every finding needs manual verification)"
    )
    ap.add_argument("url", nargs="?", help="target URL (with a numeric ID in the path or a query param)")
    ap.add_argument("-l", "--list", help="file of URLs (one per line)")
    ap.add_argument("--cookie", help="Cookie header for the single session used throughout (see module docstring)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    urls: list[str] = []
    if args.list:
        urls += [l.strip() for l in Path(args.list).read_text().splitlines() if l.strip()]
    if args.url:
        urls.append(args.url)
    if not urls:
        ap.error("provide a URL or -l <file>")

    all_findings: list[IdorFinding] = []
    for u in urls:
        fs = scan_url(u, cookie=args.cookie, timeout=args.timeout)
        all_findings += fs
        if not args.json:
            _print_human(u, fs)

    if args.json:
        print(json.dumps([f.as_dict() for f in all_findings], indent=2))
    return 2 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
