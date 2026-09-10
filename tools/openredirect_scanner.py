#!/usr/bin/env python3
"""
Open redirect scanner.

For each query-string parameter on a URL that looks like it controls a
redirect, sends two GET requests without following redirects: one with the
original value (baseline, for evidentiary context), one with the value
replaced by a controlled, obviously-fake external domain
(open-redirect-test.invalid -- guaranteed not to resolve to anything real).
If the payload response's Location header reflects that test domain
verbatim, it's a confirmed open redirect. If the param exists but Location
never reflects the payload at all, nothing is reported -- absence of a
vulnerability is not itself a finding.

Redirect-controlling parameter names are not invented fresh: the base set
is tools/lead_board.py's existing purpose-built hunt-open-redirect pattern
(next, redirect, redirect_uri, return, returnurl, return_to, continue,
goto, rurl, checkout_url, success_url, back), extended with the additional
names this scanner was asked to also cover (redirect_url, url, dest,
destination, redir, r, to, callback) that lead_board.py's narrower pattern
doesn't include.

Severity model:
  MEDIUM  confirmed open redirect (Location reflects the test domain
          verbatim). Deliberately not CRITICAL/HIGH on its own -- this
          codebase's own triage stance (skills/triage-validation,
          commands/chain.md) treats a bare open redirect as low/rejected
          standalone value, real impact coming from chaining it (open
          redirect -> OAuth redirect_uri -> auth code theft). See
          agents/chain-builder.md's A-to-B table for that chain.
  (no finding at all) -- a param that doesn't reflect the payload into
          Location isn't reported. There is no INFO/LOW tier here the way
          cors_scanner.py has one: open redirect is a binary "it worked or
          it didn't", not a severity gradient.

Uses tools/safe_http.py's safe_urlopen(..., follow_redirects=False) so
scope-check / rate-limit / audit-log protection is built in from the start
(no "add it later" gap, unlike cors_scanner.py's history this session).

Usage:
  tools/openredirect_scanner.py "https://api.target.com/login?redirect=/home"
  tools/openredirect_scanner.py -l urls.txt --json
"""
from __future__ import annotations

import argparse
import json
import os
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

USER_AGENT = "agentic-bug-hunter/openredirect_scanner"

MEDIUM = "MEDIUM"

TEST_DOMAIN = "open-redirect-test.invalid"

REDIRECT_PARAM_NAMES = {
    # From tools/lead_board.py's hunt-open-redirect routing rule:
    "next", "redirect", "redirect_uri", "return", "returnurl", "return_to",
    "continue", "goto", "rurl", "checkout_url", "success_url", "back",
    # Additional names this scanner was asked to also cover:
    "redirect_url", "url", "dest", "destination", "redir", "r", "to", "callback",
}


@dataclass
class RedirectFinding:
    url: str
    param: str
    payload: str
    location: str | None
    severity: str
    title: str
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "location": self.location,
            "severity": self.severity,
            "title": self.title,
            "note": self.note,
        }


def find_redirect_params(url: str) -> list[str]:
    """Query-string param names on `url` that match REDIRECT_PARAM_NAMES
    (case-insensitive). Pure function."""
    query = urlparse(url).query
    if not query:
        return []
    names = [k for k, _ in parse_qsl(query, keep_blank_values=True)]
    seen = set()
    matched = []
    for n in names:
        if n.lower() in REDIRECT_PARAM_NAMES and n not in seen:
            seen.add(n)
            matched.append(n)
    return matched


def build_payload_url(url: str, param: str, new_value: str) -> str:
    """`url` with `param`'s value replaced by `new_value`; every other
    param and the original param order is preserved. Pure function."""
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [(k, new_value if k == param else v) for k, v in pairs]
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def classify(
    url: str,
    param: str,
    payload_value: str,
    location: str | None,
    baseline_location: str | None = None,
) -> RedirectFinding | None:
    """Decide whether a payload response's Location header proves an open
    redirect. Pure function -- no finding (None) if Location is absent or
    doesn't contain the test domain verbatim; absence of a vulnerability
    is deliberately not itself reported.
    """
    if not location:
        return None
    if TEST_DOMAIN.lower() not in location.lower():
        return None

    if baseline_location:
        baseline_note = f" Baseline (unmodified param) redirected to: {baseline_location!r}."
    else:
        baseline_note = " Baseline (unmodified param) did not redirect at all."

    return RedirectFinding(
        url, param, payload_value, location, MEDIUM,
        f"Open redirect via `{param}` parameter",
        "Location header reflects the attacker-controlled domain verbatim -- "
        "confirmed unvalidated redirect." + baseline_note +
        " Standalone impact is typically low/rejected on its own in most "
        "programs; check for an OAuth redirect_uri chain (open redirect -> "
        "auth code theft, see agents/chain-builder.md) before reporting alone.",
    )


def _fetch_location(url: str, timeout: int) -> str | None:
    """GET `url` WITHOUT following redirects (safe_urlopen's single-hop
    mode); return the Location header of a 3xx response, or None if the
    response wasn't a redirect or the request failed outright."""
    headers = {"User-Agent": USER_AGENT}
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        resp = safe_urlopen(req, timeout=timeout, follow_redirects=False)
        try:
            if resp.status in (301, 302, 303, 307, 308):
                return resp.headers.get("Location")
            return None
        finally:
            close = getattr(resp, "close", None)
            if callable(close):
                close()
    except urllib.error.HTTPError:
        return None  # genuine 4xx/5xx -- not a redirect
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return None


def scan_url(url: str, timeout: int = 15) -> list[RedirectFinding]:
    findings: list[RedirectFinding] = []
    payload_value = f"https://{TEST_DOMAIN}/"

    for param in find_redirect_params(url):
        baseline_location = _fetch_location(url, timeout)

        payload_url = build_payload_url(url, param, payload_value)
        payload_location = _fetch_location(payload_url, timeout)

        finding = classify(url, param, payload_value, payload_location, baseline_location)
        if finding:
            findings.append(finding)

    return findings


def _print_human(url: str, findings: list[RedirectFinding]) -> None:
    if not findings:
        print(f"[ok] {url} — no open redirect detected")
        return
    for f in findings:
        print(f"[{f.severity}] {f.title}")
        print(f"    url:      {f.url}")
        print(f"    param:    {f.param}")
        print(f"    payload:  {f.payload}")
        print(f"    location: {f.location}")
        if f.note:
            print(f"    note:     {f.note}")
    print(f"\n{len(findings)} open redirect finding(s) on {url}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Open redirect scanner")
    ap.add_argument("url", nargs="?", help="target URL (with query params)")
    ap.add_argument("-l", "--list", help="file of URLs (one per line)")
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

    all_findings: list[RedirectFinding] = []
    for u in urls:
        fs = scan_url(u, timeout=args.timeout)
        all_findings += fs
        if not args.json:
            _print_human(u, fs)

    if args.json:
        print(json.dumps([f.as_dict() for f in all_findings], indent=2))
    # exit 2 if any finding -- every finding here is by definition
    # confirmed (see module docstring), unlike cors_scanner.py's INFO tier
    return 2 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
