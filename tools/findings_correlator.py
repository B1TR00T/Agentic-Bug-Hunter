#!/usr/bin/env python3
"""
Findings Correlator — deterministic cross-referencing across vuln_scanner.sh's
per-check findings output.

The problem this solves: vuln_scanner.sh writes each check's hits into its own
category directory (findings/<target>/{upload,sqli,ssti,mfa,saml,...}/*.txt)
with zero cross-referencing between them. A SQLi hit and an MFA hit on the
same host are two isolated text files today -- nothing notices they might be
the same target's attack surface. This script reads every category's output,
extracts (host, path, confidence, category) per finding, and groups findings
that share a host (2+ findings only -- a lone finding isn't a chain
candidate). Within a host group, findings whose paths are exact matches or
prefix-related (e.g. /api/orders/123 under /api/orders) get the same
path_group id.

Deliberately NOT included: chain reasoning, severity, "is this exploitable"
judgment. Output is grouped facts only -- a clean input for a later reasoning
step (chain-builder or similar), not a finished analysis.

NOTE ON INPUT FORMAT (confirmed against the real tools/vuln_scanner.sh source,
not assumed):
  - upload/*.txt   : "[TAG] [SUBCAT] <bare-url>"                  (URL first/only token after tags)
  - sqli/*.txt      : "[TAG] [SUBCAT] dialect=X param=N url=<url>" (URL is a url= key, not positional)
  - ssti/*.txt      : "[TAG] [SUBCAT] engine=X url=<url>"          (same url= pattern as sqli)
  - mfa/findings.txt: "[TAG] [SUBCAT] <bare-url> [| suffix text]"  (suffix format is NOT consistent
                       across the three MFA sub-checks -- sometimes " | ...", sometimes plain text)
  - saml/*.txt      : "[TAG] [SUBCAT] <bare-url> [| HTTP code [| more]]"
  - cms              : NO MATCHING DIRECTORY EXISTS. Check 7 (CMS Detection) only writes
                       findings/<target>/metasploit/*.rc resource scripts -- no [TAG]-format
                       .txt output at all. Included in CATEGORIES below for forward
                       compatibility (harmless no-op glob) but will never produce findings today.
  - sqli/nuclei_sqli.txt and saml/certs.txt sit inside these directories but hold raw
    nuclei JSONL / raw X509 cert text respectively -- not [TAG]-format lines. Lines that
    don't start with a known confidence tag are silently skipped and counted, not misparsed.

Usage:
  python3 tools/findings_correlator.py <target>
  python3 tools/findings_correlator.py <target> --findings-dir DIR --out FILE

Output: <findings-dir>/correlated_groups.json (default), or --out path.
"""

import argparse
import glob
import json
import os
import re
import sys
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directory names under findings/<target>/ that vuln_scanner.sh's checks
# write [TAG]-format lines into. "cms" is listed for forward compatibility
# even though no such directory exists today -- see module docstring.
CATEGORIES = ["upload", "sqli", "ssti", "cms", "mfa", "saml", "cors"]

CONFIDENCE_TAGS = ("CONFIRMED", "POSSIBLE", "INFORMATIONAL")
_CONFIDENCE_RE = re.compile(r"^\[(" + "|".join(CONFIDENCE_TAGS) + r")\]")
_URL_RE = re.compile(r"https?://\S+")


def parse_finding_line(line, category):
    """Extract one finding from a single line, or None if it doesn't match
    the [TAG] ... <url> ... shape at all (e.g. raw nuclei JSONL, raw cert
    dump, blank lines). Deliberately permissive about what comes between the
    confidence tag and the URL, and what follows it -- confirmed against the
    real formats in the docstring above, which are NOT identical across
    categories.
    """
    stripped = line.strip()
    if not stripped:
        return None

    tag_match = _CONFIDENCE_RE.match(stripped)
    if not tag_match:
        return None
    confidence = tag_match.group(1)

    url_match = _URL_RE.search(stripped)
    if not url_match:
        return None
    raw_url = url_match.group(0)
    # Defensive trailing-punctuation strip -- none of the current formats
    # append punctuation directly against the URL (there's always a space
    # before any " | suffix"), but this guards against a future format that
    # wraps the URL in parens/quotes without a space.
    raw_url = raw_url.rstrip(").,;\"'")

    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except ValueError:
        return None
    if not parsed.netloc:
        return None

    host = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"

    return {
        "category": category,
        "confidence": confidence,
        "host": host,
        "path": path,
        "line": stripped,
    }


def load_findings(findings_dir):
    """Read every *.txt file under each known category directory. Returns
    (findings, total_lines_read, unparsed_line_count). A missing category
    directory (e.g. cms/, or any category a given hunt never populated) is
    silently skipped -- glob on a nonexistent dir just returns nothing.
    """
    findings = []
    total_lines = 0
    unparsed_lines = 0

    for category in CATEGORIES:
        cat_dir = os.path.join(findings_dir, category)
        if not os.path.isdir(cat_dir):
            continue
        for file_path in sorted(glob.glob(os.path.join(cat_dir, "*.txt"))):
            try:
                with open(file_path, encoding="utf-8", errors="replace") as fh:
                    for raw_line in fh:
                        total_lines += 1
                        parsed = parse_finding_line(raw_line, category)
                        if parsed is None:
                            if raw_line.strip():
                                unparsed_lines += 1
                            continue
                        parsed["source_file"] = os.path.relpath(file_path, findings_dir)
                        findings.append(parsed)
            except OSError:
                continue

    return findings, total_lines, unparsed_lines


def _path_segments(path):
    return [seg for seg in path.strip("/").split("/") if seg]


def _paths_related(path_a, path_b):
    """True if the two paths are identical, or one's segment list is a
    prefix of the other's -- e.g. /api/orders is a prefix of
    /api/orders/123. Segment-aware on purpose: a naive string-prefix check
    would wrongly treat /api/order as a prefix of /api/orders.
    """
    segs_a, segs_b = _path_segments(path_a), _path_segments(path_b)
    shorter, longer = (segs_a, segs_b) if len(segs_a) <= len(segs_b) else (segs_b, segs_a)
    return longer[: len(shorter)] == shorter


def _assign_path_groups(host_findings):
    """Union-find over a single host's findings, connecting any pair whose
    paths are related (see _paths_related). Returns a list of small integer
    ids, one per finding, same order as host_findings -- findings sharing an
    id are in the same path cluster. Every finding gets an id, including
    ones that don't relate to anything else (their own singleton cluster).
    """
    n = len(host_findings)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    for i in range(n):
        for j in range(i + 1, n):
            if _paths_related(host_findings[i]["path"], host_findings[j]["path"]):
                union(i, j)

    root_to_id = {}
    ids = []
    for i in range(n):
        root = find(i)
        if root not in root_to_id:
            root_to_id[root] = len(root_to_id)
        ids.append(root_to_id[root])
    return ids


def build_groups(findings_dir):
    findings, total_lines, unparsed_lines = load_findings(findings_dir)

    by_host = defaultdict(list)
    for finding in findings:
        by_host[finding["host"]].append(finding)

    groups = []
    for host in sorted(by_host):
        host_findings = by_host[host]
        if len(host_findings) < 2:
            continue  # a host with one finding is not a candidate group

        path_group_ids = _assign_path_groups(host_findings)
        entries = [
            {
                "category": f["category"],
                "confidence": f["confidence"],
                "path": f["path"],
                "path_group": pg_id,
                "line": f["line"],
            }
            for f, pg_id in zip(host_findings, path_group_ids)
        ]
        groups.append(
            {
                "host": host,
                "finding_count": len(entries),
                "findings": entries,
            }
        )

    stats = {
        "total_lines_read": total_lines,
        "findings_parsed": len(findings),
        "unparsed_lines": unparsed_lines,
        "hosts_with_2plus_findings": len(groups),
    }
    return groups, stats


def main():
    parser = argparse.ArgumentParser(
        description="Deterministic cross-referencing across vuln_scanner.sh findings output. "
        "Groups findings by host (2+ findings only) and flags path-related findings within "
        "each host via path_group ids. No chain reasoning, no severity -- grouped facts only."
    )
    parser.add_argument("target", help="Target name (matches findings/<target>/ by default)")
    parser.add_argument(
        "--findings-dir",
        default="",
        help="Override input directory (default: findings/<target>)",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Override output path (default: <findings-dir>/correlated_groups.json)",
    )
    args = parser.parse_args()

    findings_dir = args.findings_dir or os.path.join(ROOT, "findings", args.target)
    out_path = args.out or os.path.join(findings_dir, "correlated_groups.json")

    if not os.path.isdir(findings_dir):
        print(f"[!] findings directory not found: {findings_dir}", file=sys.stderr)
        sys.exit(1)

    groups, stats = build_groups(findings_dir)

    payload = {
        "target": args.target,
        "findings_dir": findings_dir,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "stats": stats,
        "groups": groups,
    }

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")

    print(f"[+] {len(groups)} correlated group(s) -> {out_path}")
    print(
        f"    parsed {stats['findings_parsed']} finding(s) from "
        f"{stats['total_lines_read']} line(s) ({stats['unparsed_lines']} unparsed)"
    )


if __name__ == "__main__":
    main()
