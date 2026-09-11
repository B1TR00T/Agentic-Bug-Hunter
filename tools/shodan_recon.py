#!/usr/bin/env python3
"""tools/shodan_recon.py — passive Shodan-based host discovery, scope-enforced.

Environment checked before writing this:
  - The `shodan` Python library IS installed in this environment (v1.31.0,
    verified via `pip show shodan` / `import shodan`) -- it is used directly
    rather than hand-rolling raw HTTP calls to Shodan's REST API. get_client()
    raises ShodanLibraryMissingError with an actionable message if it's ever
    absent on a different machine, rather than assuming it's always there.
  - Rate limit: read straight out of the installed library's own source
    (shodan/client.py, class Shodan.__init__: `self.api_rate_limit = 1  #
    Requests per second`, enforced inside _request() before every single API
    call). That is the actual documented/enforced constraint -- NOT
    BBHUNT_RATE_LIMIT_RPS, which governs requests to the bounty TARGET, not
    to a third-party OSINT API. This module never touches BBHUNT_RATE_LIMIT_RPS
    and adds no duplicate throttling of its own on top of the library's.
    The tighter real-world constraint for Shodan is query CREDITS, not
    requests/sec: each call to /shodan/host/search costs 1 query credit and
    returns up to 100 results (one page), charged against your plan's
    monthly allotment (see https://developer.shodan.io/api) -- so this
    module caps pages-per-query (max_pages, default 1) instead of trying to
    rate-limit something that isn't the actual bottleneck. /api-info (used
    for the pre-flight credit check below) is a free metadata endpoint and
    does not itself consume a query credit.

Setup, same fail-loud/fail-closed posture as BBHUNT_SCOPE_FILE and
BBHUNT_USER_AGENT_SUFFIX elsewhere in this toolkit:
  - SHODAN_API_KEY must be set, or this refuses to run at all.
  - BBHUNT_SCOPE_FILE must be set and readable, or this refuses to spend a
    single query credit.

Query strategy: for every domain/wildcard entry in BBHUNT_SCOPE_FILE, this
runs exactly one `hostname:<domain>` search -- never a broad net:/org:/asn:
search -- specifically to avoid pulling in infrastructure that merely sits
near the target (shared hosting, a cloud provider's whole ASN, an
org-name collision) rather than infrastructure actually covered by the
program's scope.

Scope enforcement (the part that matters most here): every hostname on
every match Shodan returns is checked with tools.safe_http.is_in_scope()
before it is written ANYWHERE -- stdout summary counts aside, neither
hosts.txt nor raw.json ever contains a host that failed that check.
is_in_scope() is the existing Python port of bb_curl.sh's is_in_scope()
(see tools/safe_http.py's own docstring: "ported deliberately ... so a
scope file produces identical accept/reject decisions") -- this module
reuses that single shared implementation rather than writing wildcard
matching a third time in a third file. Shodan is a third-party OSINT
service, not the bounty target, so its own API calls do NOT go through
is_in_scope()/bb_curl.sh/safe_urlopen() (that machinery exists to gate
requests made TO the target) -- only the DATA Shodan hands back is scope
-checked, exactly like crt.sh's output in tools/recon_engine.sh is queried
directly with plain curl and only the resulting hostnames are of interest.

Output, matching the existing recon/<target>/subdomains/all.txt convention
so recon_engine.sh's later phases (httpx -l, etc.) can consume it
identically:
  - recon/<target>/shodan/hosts.txt  -- bare, sorted, unique in-scope
    hostnames, one per line, no ports/banners/extra columns.
  - recon/<target>/shodan/raw.json   -- the full in-scope record list
    (hostname, ip, port, transport, product, org, banner excerpt,
    timestamp) for anything downstream that wants more than a bare list.

Not wired into recon_engine.sh yet -- run standalone:
    export SHODAN_API_KEY=...
    export BBHUNT_SCOPE_FILE=recon/target.com/scope.txt
    python3 tools/shodan_recon.py target.com
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
from tools.safe_http import is_in_scope  # noqa: E402

try:
    import shodan
except ImportError:
    shodan = None  # checked explicitly in get_client(); every other function
    # here takes an already-built client rather than importing shodan itself,
    # so pure/offline unit tests never need the real package present either.


DEFAULT_MAX_PAGES_PER_QUERY = 1  # 1 page = up to 100 results = 1 query credit, per scope entry
RESULTS_PER_PAGE = 100  # Shodan's fixed page size for /shodan/host/search


class MissingApiKeyError(RuntimeError):
    """SHODAN_API_KEY is unset/blank."""


class MissingScopeFileError(RuntimeError):
    """BBHUNT_SCOPE_FILE is unset, or the path it names doesn't exist/isn't readable."""


class ShodanLibraryMissingError(RuntimeError):
    """The `shodan` package is not importable in this environment."""


class InsufficientCreditsError(RuntimeError):
    """The Shodan account backing SHODAN_API_KEY has 0 query credits left."""


def require_api_key() -> str:
    """Fail loud -- same pattern as build_user_agent()'s BBHUNT_USER_AGENT_SUFFIX
    check in tools/safe_http.py: an unset key is a hard error raised up front,
    not something left to surface later as a confusing 401 mid-pagination."""
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        raise MissingApiKeyError(
            "SHODAN_API_KEY is not set -- refusing to run. Get a key at "
            "https://account.shodan.io and export it: "
            "export SHODAN_API_KEY='yourkeyhere'"
        )
    return key


def require_scope_entries(scope_file: str | None) -> list[str]:
    """Fail loud on an unset/unreadable BBHUNT_SCOPE_FILE -- identical
    fail-closed stance to is_in_scope() itself, checked here too (not just
    left to is_in_scope() silently returning False on every call) so a
    broken scope file is caught before a single Shodan query credit is spent.

    Returns the raw domain/wildcard entries to build search queries from
    ('#' comments and blank lines skipped, same convention as the scope
    file's own matching rules). This only reads entries to construct
    queries -- it does NOT re-implement is_in_scope()'s wildcard matching;
    that logic is called separately, once per result, further down.
    """
    if not scope_file:
        raise MissingScopeFileError(
            "BBHUNT_SCOPE_FILE is not set -- refusing to query Shodan without "
            "an explicit scope file. export BBHUNT_SCOPE_FILE=recon/target.com/scope.txt"
        )
    if not os.path.isfile(scope_file) or not os.access(scope_file, os.R_OK):
        raise MissingScopeFileError(
            f"BBHUNT_SCOPE_FILE={scope_file!r} does not exist or is not readable"
        )
    entries: list[str] = []
    with open(scope_file, encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.split("#", 1)[0].strip()
            if line:
                entries.append(line)
    return entries


def query_term_for_entry(entry: str) -> str:
    """Turn one scope-file entry into the domain used in a Shodan
    `hostname:<domain>` search. Strips a leading '*.' wildcard marker --
    Shodan's hostname filter already does substring/subdomain matching on
    the bare domain, and the real apex-vs-subdomain distinction the scope
    file cares about is enforced downstream by is_in_scope() on each
    result, not by how the query is phrased."""
    return entry[2:] if entry.startswith("*.") else entry


def get_client(api_key: str):
    """Build the real shodan.Shodan client. Kept as its own function --
    rather than constructing shodan.Shodan(...) inline wherever it's needed
    -- purely so tests can monkeypatch this one seam with a fake client
    instead of touching the shodan module itself."""
    if shodan is None:
        raise ShodanLibraryMissingError(
            "the `shodan` package is not installed in this environment -- "
            "install it with: pip install shodan"
        )
    return shodan.Shodan(api_key)


def check_credits(client) -> int:
    """Pre-flight check via the free /api-info endpoint (does not itself
    consume a query credit) -- abort before spending any credits if the
    account backing this key already has none left. Returns the credit
    count for the caller to log/report."""
    info = client.info()
    credits_left = info.get("query_credits", 0)
    if credits_left <= 0:
        raise InsufficientCreditsError(
            f"Shodan account has {credits_left} query credits left -- "
            "refusing to run any searches. Check https://account.shodan.io"
        )
    return credits_left


def search_domain(client, domain: str, max_pages: int = DEFAULT_MAX_PAGES_PER_QUERY):
    """Run a `hostname:<domain>` search (never a broad net:/org:/asn: search)
    and yield raw Shodan match dicts across up to `max_pages` pages. One
    client.search() call = one query credit; max_pages bounds how many
    credits a single scope-file entry can consume in one run. Relies
    entirely on the shodan library's own built-in 1-request/second
    throttle (see module docstring) -- no additional sleep is added here."""
    query = f"hostname:{domain}"
    for page in range(1, max_pages + 1):
        result = client.search(query, page=page)
        matches = result.get("matches", [])
        if not matches:
            break
        yield from matches
        if len(matches) < RESULTS_PER_PAGE:
            break  # short page -- no more results to page through


@dataclass
class ShodanRecord:
    hostname: str
    ip_str: str
    port: int
    transport: str
    product: str | None
    org: str | None
    banner: str
    timestamp: str | None

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ip_str": self.ip_str,
            "port": self.port,
            "transport": self.transport,
            "product": self.product,
            "org": self.org,
            "banner": self.banner,
            "timestamp": self.timestamp,
        }


def matches_to_scoped_records(matches) -> list[ShodanRecord]:
    """THE scope gate -- every hostname on every match Shodan returned is
    checked with tools.safe_http.is_in_scope() (the same scope-file
    matching logic bb_curl.sh's is_in_scope()/bb_filter_scope_list()
    already implement, reused here as its existing Python port -- not
    reimplemented a third time) before it can become a ShodanRecord.

    Two deliberate conservative choices, both because Shodan is known to
    return infrastructure adjacent to but outside actual scope:
      - A match with NO hostnames at all (a bare IP -- shared hosting, a
        CDN edge, misattributed reverse-DNS) can never be confirmed
        in-scope against a domain-based scope file, and is dropped
        outright -- it is never emitted under any hostname or IP.
      - A match with MULTIPLE hostnames sharing one IP keeps only the
        hostnames that individually pass is_in_scope() -- not the whole
        match on an "any hostname matches" basis -- so one in-scope name
        never drags an out-of-scope sibling hostname along with it.

    Deduplicates by (hostname, ip_str, port, transport) -- the same host
    can legitimately surface from more than one scope-file entry's query.
    """
    seen: set[tuple[str, str, int, str]] = set()
    records: list[ShodanRecord] = []
    for match in matches:
        hostnames = match.get("hostnames") or []
        ip_str = match.get("ip_str", "")
        port = match.get("port", 0)
        transport = match.get("transport", "")
        for hostname in hostnames:
            if not is_in_scope(f"https://{hostname}"):
                continue
            key = (hostname, ip_str, port, transport)
            if key in seen:
                continue
            seen.add(key)
            records.append(
                ShodanRecord(
                    hostname=hostname,
                    ip_str=ip_str,
                    port=port,
                    transport=transport,
                    product=match.get("product"),
                    org=match.get("org"),
                    banner=(match.get("data") or "")[:500],
                    timestamp=match.get("timestamp"),
                )
            )
    return records


def write_outputs(
    target: str, records: list[ShodanRecord], recon_root: str | None = None
) -> tuple[str, str]:
    """Write recon/<target>/shodan/hosts.txt (bare, sorted, unique hostnames
    -- the same plain-list format recon/<target>/subdomains/all.txt already
    uses, so recon_engine.sh's later phases, e.g. `httpx -l`, can consume it
    identically) and recon/<target>/shodan/raw.json (the full in-scope
    record list -- ports, services, banners -- for anything downstream that
    wants more than a bare host list).

    `records` must already be scope-filtered by matches_to_scoped_records()
    -- this function has no scope logic of its own and writes exactly what
    it's handed, so nothing out-of-scope reaches this point in the first
    place."""
    root = recon_root or os.path.join(_REPO, "recon")
    out_dir = os.path.join(root, target, "shodan")
    os.makedirs(out_dir, exist_ok=True)

    hosts_path = os.path.join(out_dir, "hosts.txt")
    raw_path = os.path.join(out_dir, "raw.json")

    hostnames = sorted({r.hostname for r in records})
    with open(hosts_path, "w", encoding="utf-8") as fh:
        for hostname in hostnames:
            fh.write(hostname + "\n")

    with open(raw_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "target": target,
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "record_count": len(records),
                "records": [r.to_dict() for r in records],
            },
            fh,
            indent=2,
        )

    return hosts_path, raw_path


def run(
    target: str,
    *,
    recon_root: str | None = None,
    max_pages: int = DEFAULT_MAX_PAGES_PER_QUERY,
) -> dict:
    """End-to-end: validate config, pre-flight credit check, query Shodan
    once per scope-file entry, scope-filter every result, write outputs.
    Returns a summary dict (also printed by main())."""
    api_key = require_api_key()
    scope_file = os.environ.get("BBHUNT_SCOPE_FILE")
    entries = require_scope_entries(scope_file)
    client = get_client(api_key)
    credits_before = check_credits(client)

    all_matches: list[dict] = []
    queries_run = 0
    for entry in entries:
        domain = query_term_for_entry(entry)
        if not domain:
            continue
        all_matches.extend(search_domain(client, domain, max_pages=max_pages))
        queries_run += 1

    hostnames_seen = {h for m in all_matches for h in (m.get("hostnames") or [])}
    records = matches_to_scoped_records(all_matches)
    hostnames_kept = {r.hostname for r in records}

    hosts_path, raw_path = write_outputs(target, records, recon_root=recon_root)

    return {
        "target": target,
        "credits_available_before_run": credits_before,
        "scope_entries_queried": queries_run,
        "raw_matches": len(all_matches),
        "hostnames_seen": len(hostnames_seen),
        "hostnames_in_scope": len(hostnames_kept),
        "hostnames_dropped_out_of_scope": len(hostnames_seen - hostnames_kept),
        "hosts_path": hosts_path,
        "raw_json_path": raw_path,
    }


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: shodan_recon.py <target> [--max-pages N] [--recon-root DIR]", file=sys.stderr)
        return 2
    target = argv[0]

    max_pages = DEFAULT_MAX_PAGES_PER_QUERY
    if "--max-pages" in argv:
        idx = argv.index("--max-pages")
        try:
            max_pages = int(argv[idx + 1])
        except (IndexError, ValueError):
            print("[shodan_recon] --max-pages requires an integer", file=sys.stderr)
            return 2

    recon_root = None
    if "--recon-root" in argv:
        idx = argv.index("--recon-root")
        try:
            recon_root = argv[idx + 1]
        except IndexError:
            print("[shodan_recon] --recon-root requires a path", file=sys.stderr)
            return 2

    try:
        summary = run(target, max_pages=max_pages, recon_root=recon_root)
    except (
        MissingApiKeyError,
        MissingScopeFileError,
        ShodanLibraryMissingError,
        InsufficientCreditsError,
    ) as e:
        print(f"[shodan_recon] FATAL — {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 -- only shodan.APIError is special-cased
        if shodan is not None and isinstance(e, shodan.APIError):
            print(f"[shodan_recon] Shodan API error — {e}", file=sys.stderr)
            return 1
        raise

    print(f"[shodan_recon] target={summary['target']}")
    print(f"[shodan_recon] query credits available before this run: {summary['credits_available_before_run']}")
    print(f"[shodan_recon] scope entries queried: {summary['scope_entries_queried']}")
    print(f"[shodan_recon] raw matches: {summary['raw_matches']}")
    print(f"[shodan_recon] hostnames seen (pre-scope-filter): {summary['hostnames_seen']}")
    print(f"[shodan_recon] hostnames in scope (kept): {summary['hostnames_in_scope']}")
    print(f"[shodan_recon] hostnames dropped (out of scope): {summary['hostnames_dropped_out_of_scope']}")
    print(f"[shodan_recon] hosts -> {summary['hosts_path']}")
    print(f"[shodan_recon] raw json -> {summary['raw_json_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
