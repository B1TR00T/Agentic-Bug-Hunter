#!/bin/bash
# =============================================================================
# Enhanced Recon Engine
# Full reconnaissance pipeline for bug bounty targets
# Usage: ./recon_engine.sh <target-domain> [--quick] [--shodan] [--cve-check]
#
# --shodan is opt-in and OFF by default (same pattern as hunt.py's
# --graphql/--cve-hunt flags: an explicit flag gates an entire optional
# module, nothing about it runs unless asked). When passed, it requires
# SHODAN_API_KEY to be set (checked up front, before Phase 1 starts) and
# runs tools/shodan_recon.py against $TARGET using the same BBHUNT_SCOPE_FILE
# already required for this whole script; its scope-checked hosts.txt output
# is merged into subdomains/ so it flows through the existing Phase 1 merge
# and every later phase (httpx, katana, etc.) picks it up automatically.
#
# --cve-check is opt-in and OFF by default, same reasoning as --shodan: it
# hits NVD's external, rate-limited API (tools/cve_lookup.py), so nothing
# about it runs unless asked. Unlike SHODAN_API_KEY, NVD_API_KEY is genuinely
# OPTIONAL, not required -- if unset, cve_lookup.py itself proceeds at NVD's
# unauthenticated rate (5 req/30s) rather than refusing to run; if set, it's
# picked up automatically since it's just an inherited environment variable,
# no extra plumbing needed here. Runs as Phase 2.6, right after Phase 2.5
# (Tech Fingerprinting) completes, feeding it that phase's raw.json.
#
# --rapyd-sign is opt-in and OFF by default, same SHODAN_API_KEY-style
# posture: it requires RAPYD_ACCESS_KEY/RAPYD_SECRET_KEY, checked up front
# before Phase 1 (below), and refuses to run at all if either is missing
# rather than silently falling back to unsigned requests partway through.
# When on, it just exports BBHUNT_RAPYD_SIGN=1 for the rest of this script
# to inherit -- the actual signing logic lives entirely in bb_curl.sh's
# _bb_rapyd_sign_headers(), and is scoped there to ONLY
# sandboxapi.rapyd.net (tools/rapyd_sign.py's own hardcoded sandbox-only
# gate; production is never touched by this flag no matter what). A no-op
# for every target other than Rapyd's own sandbox API, so it's harmless to
# leave on across unrelated engagements.
# =============================================================================

set -o pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_err()   { echo -e "${RED}[-]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_info()  { echo -e "${CYAN}[*]${NC} $1"; }
log_step()  { echo -e "    ${CYAN}[>]${NC} $1"; }
log_done()  { echo -e "    ${GREEN}[✓]${NC} $1"; }
log_vuln()  { echo -e "    ${RED}[VULN]${NC} $1"; }

TARGET="${1:?Usage: $0 <target> [--quick] [--shodan] [--cve-check] [--rapyd-sign]  (target = FQDN, IP, CIDR, or path to a file of domains/hosts)}"
QUICK_MODE="${2:-}"
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# --shodan/--cve-check/--rapyd-sign can appear in any position (alongside/
# instead of --quick), unlike QUICK_MODE's fixed $2 slot -- scanned for
# explicitly rather than folded into the positional args so adding any of
# these never disturbs the existing $1/$2 contract callers (including
# hunt.py) already rely on.
SHODAN_MODE=0
CVE_CHECK_MODE=0
RAPYD_SIGN_MODE=0
for _arg in "$@"; do
    [ "$_arg" = "--shodan" ] && SHODAN_MODE=1
    [ "$_arg" = "--cve-check" ] && CVE_CHECK_MODE=1
    [ "$_arg" = "--rapyd-sign" ] && RAPYD_SIGN_MODE=1
done

# Auth-aware hunting: load BBHUNT_AUTH_HEADERS / BBHUNT_SESSION_ID into
# BB_AUTH_ARGS=(-H 'Name: val' ...). Empty session = no-op.
# shellcheck source=tools/_auth_helper.sh
. "$(dirname "$0")/_auth_helper.sh"

# bb_curl() wraps curl with scope + rate-limit enforcement (tools/bb_curl.sh).
# Wired into Phase 5 (JS fetch) and Phase 6.5 (config-exposure probe) only —
# every other phase in this script is untouched and still uses BB_AUTH_ARGS /
# raw curl (or httpx/katana/nuclei's own -H flags) directly.
# shellcheck source=tools/bb_curl.sh
. "$(dirname "$0")/bb_curl.sh"

# bb_curl() refuses every request without BBHUNT_SCOPE_FILE set to an
# existing scope file (fail-loud, fail-closed — see is_in_scope() in
# bb_curl.sh). Check that up front, before Phase 1 even starts, so a missing
# scope file surfaces immediately instead of after minutes of subdomain
# enum/nmap/etc., only to fail cryptically once Phase 5 is reached.
if [ -z "${BBHUNT_SCOPE_FILE:-}" ] || [ ! -f "${BBHUNT_SCOPE_FILE:-/nonexistent}" ]; then
    log_err "BBHUNT_SCOPE_FILE is not set, or does not point to an existing file."
    log_err "Phase 5 (JS fetch) and Phase 6.5 (config-exposure probe) route their"
    log_err "requests through bb_curl(), which refuses to run without a scope file."
    log_err "Create one and re-run, e.g.:"
    log_err "  echo '$TARGET' > /tmp/${TARGET}-scope.txt"
    log_err "  echo '*.$TARGET' >> /tmp/${TARGET}-scope.txt"
    log_err "  BBHUNT_SCOPE_FILE=/tmp/${TARGET}-scope.txt bash tools/recon_engine.sh $TARGET"
    exit 1
fi

# Every outbound request this pipeline sends must be identifiable as coming
# from a specific hacker — same fail-loud/fail-closed requirement as the
# scope-file check above, and checked just as early, before Phase 1, so the
# whole run refuses rather than partially executing unattributed.
#
# _bb_user_agent() (from bb_curl.sh, sourced above) is reused here rather
# than reimplemented — same unset/blank/CR-LF validation, same base string
# convention as bb_curl()'s own "agentic-bug-hunter/bb_curl <suffix>".
# RECON_USER_AGENT is then wired into every httpx/katana/ffuf/nuclei
# invocation below via -H "User-Agent: ...".
#
# This gate still blocks the ENTIRE run — including subfinder, amass, gau,
# and nmap — even though none of those four have any flag to carry a custom
# User-Agent/header at all (checked against each tool's own --help output;
# see the comment at each of their invocations below for specifics). The
# alternative — silently letting the unattributable tools run while only
# the attributable ones get marked — would defeat the point: a program that
# requires every request to be identifiable shouldn't get some of a
# hacker's recon traffic for free just because the tool that sent it has no
# header to set.
if ! RECON_USER_AGENT="$(_bb_user_agent "agentic-bug-hunter/recon")"; then
    log_err "BBHUNT_USER_AGENT_SUFFIX is not set (or contains a CR/LF) — refusing to run."
    log_err "Every outbound request this pipeline sends must be identifiable as coming"
    log_err "from a specific hacker. Set it and re-run, e.g.:"
    log_err "  export BBHUNT_USER_AGENT_SUFFIX='yourhandle (+https://hackerone.com/yourhandle)'"
    exit 1
fi

# Shodan step (--shodan) is opt-in and off by default -- but if it WAS
# requested, its prerequisite is checked here, before anything else in the
# run starts, same fail-loud/fail-closed posture as the two gates just
# above: a missing SHODAN_API_KEY should abort before Phase 1 even begins,
# not surface as a confusing failure inside shodan_recon.py after
# subfinder/amass/crt.sh/wayback have already spent several minutes.
if [ "$SHODAN_MODE" = "1" ] && [ -z "${SHODAN_API_KEY:-}" ]; then
    log_err "SHODAN_API_KEY is not set, but --shodan was passed — refusing to run."
    log_err "Get a key at https://account.shodan.io and export it:"
    log_err "  export SHODAN_API_KEY='yourkeyhere'"
    exit 1
fi

# --rapyd-sign: same fail-loud/fail-closed posture as --shodan just above —
# checked here, before Phase 1, so a missing key aborts immediately rather
# than surfacing as a cryptic bb_curl failure deep inside Phase 5/6.5 after
# everything else has already run. Both keys are required (not one
# optional like NVD_API_KEY above) because tools/rapyd_sign.py's sign()
# needs both to compute anything at all -- there's no "degraded but
# working" mode to fall back to.
if [ "$RAPYD_SIGN_MODE" = "1" ] && { [ -z "${RAPYD_ACCESS_KEY:-}" ] || [ -z "${RAPYD_SECRET_KEY:-}" ]; }; then
    log_err "RAPYD_ACCESS_KEY/RAPYD_SECRET_KEY are not both set, but --rapyd-sign was passed — refusing to run."
    log_err "Export both sandbox keys and re-run, e.g.:"
    log_err "  export RAPYD_ACCESS_KEY='yourkeyhere'"
    log_err "  export RAPYD_SECRET_KEY='yourkeyhere'"
    exit 1
fi

# Export so bb_curl.sh (sourced above) picks it up in every phase that
# calls bb_curl() -- currently Phase 5 (JS fetch) and Phase 6.5
# (config-exposure probe). A no-op for every host except
# sandboxapi.rapyd.net (bb_curl.sh's _bb_rapyd_sign_headers() enforces
# that, mirroring tools/rapyd_sign.py's own hardcoded gate), so this is
# harmless to leave set even when $TARGET isn't a Rapyd host at all.
[ "$RAPYD_SIGN_MODE" = "1" ] && export BBHUNT_RAPYD_SIGN=1

# Domain-list mode: if the target is a readable regular file, treat its
# contents as a pre-resolved scope list (one host per line, # comments OK).
# Useful for programs without wildcards where subdomain enum is wasted work.
# Output dir is derived from the file basename so multiple lists don't collide.
if [ -f "$TARGET" ] && [ -r "$TARGET" ]; then
    TARGET_TYPE="list"
    LIST_FILE="$TARGET"
    TARGET="$(basename "$LIST_FILE")"
    TARGET="${TARGET%.*}"
fi

RECON_DIR="${RECON_OUT_DIR:-$BASE_DIR/recon/$TARGET}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
THREADS="${BB_THREADS:-50}"
RATE_LIMIT="${BB_RATE_LIMIT:-150}"  # requests per second

# shellcheck source=tools/banner.sh
. "$(dirname "$0")/banner.sh"
print_banner "Recon Engine · Bug Bounty" "$TARGET" \
    "Subdomain enum|subfinder · amass · crt.sh · wayback" \
    "Live probe|httpx + dnsx with tech fingerprinting" \
    "URL crawl|gau · waybackurls (passive archives only -- katana removed, see Phase 4)" \
    "Templates|nuclei sweep (optional)"

# Prefer Go tools in ~/go/bin
export PATH="$HOME/go/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

# macOS compatibility: GNU timeout may not exist; use gtimeout or passthrough
if ! command -v timeout &>/dev/null; then
    if command -v gtimeout &>/dev/null; then
        timeout() { gtimeout "$@"; }
        export -f timeout
    else
        timeout() { shift; "$@"; }
        export -f timeout
    fi
fi

# ── Detect target type (passed from hunt.py or auto-detected here) ────────────
_detect_target_type() {
    local t="$1"
    if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then echo "cidr"
    elif [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]];        then echo "ip"
    else echo "domain"; fi
}

_expand_cidr_hosts() {
    local target="$1"
    python3 - "$target" <<'PY'
import ipaddress
import itertools
import sys

network = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = [str(host) for host in itertools.islice(network.hosts(), 254)]
if not hosts:
    hosts = [str(network.network_address)]
print("\n".join(hosts))
PY
}
TARGET_TYPE="${TARGET_TYPE:-$(_detect_target_type "$TARGET")}"

# For IP/CIDR: always scope-lock — no subdomain enum needed
if [ "$TARGET_TYPE" = "ip" ] || [ "$TARGET_TYPE" = "cidr" ]; then
    SCOPE_LOCK=1
fi

# Resolve an absolute path to the *ProjectDiscovery* httpx, NOT the unrelated
# Python httpx CLI which Brew installs at /opt/homebrew/bin/httpx and which
# silently rejects PD flags like -silent / -tech-detect with "No such option"
# — producing 0 live hosts on macs where Brew's bin precedes ~/go/bin on PATH
# despite the export above.
#
# The PD binary's `-version` output contains the literal substring
# "projectdiscovery"; the Python httpx CLI doesn't. Fall back to the bare
# `httpx` token when no PD binary is found anywhere so the existing
# command-not-found error path still fires with a clear message.
_resolve_pd_httpx() {
    local cand
    for cand in \
        "$HOME/go/bin/httpx" \
        "/opt/homebrew/bin/httpx" \
        "/usr/local/bin/httpx" \
        "$(command -v httpx 2>/dev/null)"; do
        [ -z "$cand" ] && continue
        [ -x "$cand" ] || continue
        if "$cand" -version 2>&1 | grep -qi "projectdiscovery"; then
            echo "$cand"; return 0
        fi
    done
    echo "httpx"
    return 1
}
HTTPX_BIN="$(_resolve_pd_httpx || true)"
if ! "$HTTPX_BIN" -version 2>&1 | grep -qi "projectdiscovery"; then
    echo "[!] WARNING: ProjectDiscovery httpx not found on PATH. Live-host probing will fail." >&2
    echo "    Install with:  GOBIN=\"\$HOME/go/bin\" go install github.com/projectdiscovery/httpx/cmd/httpx@latest" >&2
fi
export HTTPX_BIN

mkdir -p "$RECON_DIR"/{subdomains,live,ports,urls,js,dirs,params}

# Safety net: merge partial subdomain results on early exit (watchdog kill, etc.)
_emergency_merge_subs() {
    if [ ! -s "$RECON_DIR/subdomains/all.txt" ] && \
       ls "$RECON_DIR/subdomains/"*.txt &>/dev/null; then
        cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/^\*\.//' \
            | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" \
            | sort -u > "$RECON_DIR/subdomains/all.txt" 2>/dev/null || true
    fi
}
trap _emergency_merge_subs EXIT

echo "============================================="
echo "  Recon Engine — $TARGET"
echo "  Output: $RECON_DIR/"
echo "  Mode: $([ "$QUICK_MODE" = "--quick" ] && echo "Quick" || echo "Full")"
echo "  Shodan: $([ "$SHODAN_MODE" = "1" ] && echo "Enabled (--shodan)" || echo "Disabled (default)")"
echo "  CVE check: $([ "$CVE_CHECK_MODE" = "1" ] && echo "Enabled (--cve-check)" || echo "Disabled (default)")"
echo "  Rapyd signing: $([ "$RAPYD_SIGN_MODE" = "1" ] && echo "Enabled (--rapyd-sign, sandboxapi.rapyd.net only)" || echo "Disabled (default)")"
echo "  Time: $(date)"
bb_auth_active && bb_auth_banner
echo "============================================="
echo ""

# ============================================================
# DNS wildcard pre-check — surfaces wildcard zones BEFORE Phase 1
# brute-forces 5,000+ candidates that all collapse to a single IP.
# Three random labels are queried under the apex; if 2+ resolve, the
# zone has a wildcard A record. Persists `subdomains/wildcard_dns.json`
# so a downstream pass can filter brute-forced subs whose A record
# matches `WILDCARD_DNS_IP`, saving 10+ min of dead-host probing on
# CDN-fronted brands and parked-domain marketing zones.
# Skipped for IP/CIDR/list targets (no apex to dork) and when `dig`
# isn't on PATH.
# ============================================================
_detect_dns_wildcard() {
    local apex="$1" hits=0 r1 r2 r3
    [ -z "$apex" ] && return
    [[ "$apex" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]] && return
    if ! command -v dig &>/dev/null; then return; fi
    r1=$(dig +short +time=2 +tries=1 "bb-no-such-$RANDOM-$RANDOM.$apex" A 2>/dev/null | head -1)
    r2=$(dig +short +time=2 +tries=1 "bb-no-such-$RANDOM-$RANDOM.$apex" A 2>/dev/null | head -1)
    r3=$(dig +short +time=2 +tries=1 "bb-no-such-$RANDOM-$RANDOM.$apex" A 2>/dev/null | head -1)
    [ -n "$r1" ] && hits=$((hits+1))
    [ -n "$r2" ] && hits=$((hits+1))
    [ -n "$r3" ] && hits=$((hits+1))
    if [ "$hits" -ge 2 ]; then
        export WILDCARD_DNS=1
        export WILDCARD_DNS_IP="$r1"
        log_warn "DNS wildcard detected on $apex (random labels resolved to $r1) — brute-forced subs will collapse to wildcard_ip"
        cat > "$RECON_DIR/subdomains/wildcard_dns.json" <<EOF
{"target":"$apex","wildcard":true,"wildcard_ip":"${WILDCARD_DNS_IP:-}","detected_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","note":"random labels resolved — brute-forced subs that resolve to wildcard_ip should be filtered before httpx live-probe to avoid wasted dirsearch on dead hosts."}
EOF
    fi
}
if [ "${TARGET_TYPE:-domain}" = "domain" ]; then
    _detect_dns_wildcard "$TARGET"
fi

# ============================================================
# Phase 1: Subdomain Enumeration (or Host Discovery for IP/CIDR)
# ============================================================
log_info "Phase 1: Subdomain Enumeration"

# ── For domain-list targets: load the file directly, skip enum entirely ───
if [ "$TARGET_TYPE" = "list" ]; then
    log_info "Domain-list target — loading $LIST_FILE (skipping subdomain enum)"
    grep -vE '^[[:space:]]*(#|$)' "$LIST_FILE" \
        | tr -d '\r' \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/^\*\.//' \
        | awk 'NF' \
        | sort -u > "$RECON_DIR/subdomains/all.txt"
    LIST_COUNT=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
    if [ "$LIST_COUNT" -eq 0 ]; then
        log_err "Domain list $LIST_FILE has no usable entries — aborting"
        exit 1
    fi
    log_ok "Loaded $LIST_COUNT host(s) from list"
    SCOPE_LOCK=1
elif [ "$TARGET_TYPE" = "cidr" ]; then
    log_info "CIDR target — running nmap ping sweep to discover live hosts"
    if command -v nmap &>/dev/null; then
        # No -H/--user-agent equivalent: nmap operates at the packet level
        # (ICMP/TCP/UDP), not HTTP, so there is no header field to carry an
        # identifying string. See the note at the Phase 3 -sV invocation
        # below for the full explanation of why this isn't just an oversight.
        nmap -sn "$TARGET" -oG - 2>/dev/null \
            | awk '/Up$/{print $2}' \
            > "$RECON_DIR/subdomains/all.txt" || true
        LIVE_COUNT=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
        if [ "$LIVE_COUNT" -eq 0 ]; then
            log_warn "nmap did not identify live hosts — expanding the CIDR locally for downstream probing"
            _expand_cidr_hosts "$TARGET" > "$RECON_DIR/subdomains/all.txt"
        fi
        log_ok "CIDR sweep: $(wc -l < "$RECON_DIR/subdomains/all.txt") live host(s) discovered"
    else
        log_warn "nmap not installed — expanding the CIDR locally for downstream probing"
        _expand_cidr_hosts "$TARGET" > "$RECON_DIR/subdomains/all.txt"
    fi
    # Skip all subdomain enum tools — jump straight to live host probing
elif [ "${SCOPE_LOCK:-0}" = "1" ] && [ "$TARGET_TYPE" = "ip" ]; then
    log_info "Single IP target — skipping subdomain enumeration"
    echo "$TARGET" > "$RECON_DIR/subdomains/all.txt"
else

# Subfinder (passive, fast)
# No -H/-ua/User-Agent flag exists anywhere in `subfinder -h` — checked
# directly against its own help output, not assumed. Also, unlike
# httpx/katana/ffuf/nuclei, subfinder in passive mode never talks to the
# TARGET at all: it queries third-party OSINT sources (crt.sh, VirusTotal,
# SecurityTrails, etc. — see `subfinder -ls`) about the target. The
# attribution gap here is real (subfinder still can't be marked as coming
# from a specific hacker) but it's a different kind of gap than an
# unattributed request landing on the target's own infrastructure.
if command -v subfinder &>/dev/null; then
    log_step "Running subfinder..."
    subfinder -d "$TARGET" -silent -all -t 50 -o "$RECON_DIR/subdomains/subfinder.txt" 2>/dev/null || true
    log_done "subfinder: $(wc -l < "$RECON_DIR/subdomains/subfinder.txt" 2>/dev/null || echo 0) subdomains"
else
    log_warn "subfinder not installed — skipping"
fi

# Amass (passive)
# Same story as subfinder immediately above: `amass enum -h` has no
# User-Agent/header flag, and -passive mode queries third-party sources
# rather than the target directly.
if command -v amass &>/dev/null && [ "$QUICK_MODE" != "--quick" ]; then
    log_step "Running amass (passive, 5min timeout)..."
    timeout 300 amass enum -passive -d "$TARGET" -o "$RECON_DIR/subdomains/amass.txt" 2>/dev/null || true
    # Ensure amass output file exists even if amass failed
    [ ! -f "$RECON_DIR/subdomains/amass.txt" ] && touch "$RECON_DIR/subdomains/amass.txt"
    log_done "amass: $(wc -l < "$RECON_DIR/subdomains/amass.txt" 2>/dev/null || echo 0) subdomains"
else
    [ "$QUICK_MODE" = "--quick" ] && log_warn "Skipping amass (quick mode)"
fi

# crt.sh (certificate transparency)
log_step "Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        for name in entry.get('name_value', '').split('\n'):
            name = name.strip().lower()
            if name and '*' not in name and name.endswith('.$TARGET'):
                names.add(name)
            elif name and '*' not in name and '.' in name:
                names.add(name)
    for n in sorted(names):
        print(n)
except: pass
" > "$RECON_DIR/subdomains/crtsh.txt" 2>/dev/null || true
log_done "crt.sh: $(wc -l < "$RECON_DIR/subdomains/crtsh.txt" 2>/dev/null || echo 0) subdomains"

# Wayback subdomains
log_step "Querying Wayback Machine for subdomains..."
curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" 2>/dev/null \
    | sed -nE "s|.*://([a-zA-Z0-9._-]+\.$TARGET).*|\1|p" \
    | sort -u > "$RECON_DIR/subdomains/wayback_subs.txt" 2>/dev/null || true
log_done "wayback: $(wc -l < "$RECON_DIR/subdomains/wayback_subs.txt" 2>/dev/null || echo 0) subdomains"

# Shodan passive recon (opt-in via --shodan, off by default -- see the
# SHODAN_API_KEY gate near the top of this script). Every host in its
# hosts.txt output already passed tools.safe_http.is_in_scope() inside
# shodan_recon.py itself before being written there -- nothing further to
# scope-check here. Copying that file into subdomains/ (rather than
# writing a second, separate merge step) means it flows through the exact
# same "cat subdomains/*.txt | sort -u > all.txt" merge every other source
# above already uses, so every later phase (httpx, katana, gau, etc.)
# consumes it identically without any extra wiring anywhere else.
# Best-effort/non-fatal by design (same posture as hunt.py's
# run_cors_scan()/run_openredirect_scan()): a Shodan failure here should
# never take down the rest of the recon run.
if [ "$SHODAN_MODE" = "1" ]; then
    log_step "Running Shodan passive recon (hostname: search, scope-checked per-host)..."
    SHODAN_RECON_ROOT="$(dirname "$RECON_DIR")"
    python3 "$(dirname "$0")/shodan_recon.py" "$TARGET" --recon-root "$SHODAN_RECON_ROOT" \
        || log_warn "shodan_recon.py failed or found nothing -- continuing without it"
    if [ -s "$RECON_DIR/shodan/hosts.txt" ]; then
        cp "$RECON_DIR/shodan/hosts.txt" "$RECON_DIR/subdomains/shodan_hosts.txt"
        log_done "Shodan: $(wc -l < "$RECON_DIR/shodan/hosts.txt") in-scope host(s) merged into subdomains/"
    fi
fi

# Merge and deduplicate all subdomains
cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/subdomains/all.txt"
TOTAL_SUBS=$(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)

# Fallback: every source above (subfinder/amass/crt.sh/wayback) can
# legitimately return zero results for a host that's still live and in
# scope -- crt.sh in particular only surfaces hosts with a logged cert, and
# a freshly-issued or internal-CA host won't have one yet. Without this,
# Phase 2 (HTTP probing) and everything downstream silently skip even
# though the caller explicitly asked to scan $TARGET. Seed the literal
# requested hostname so it always gets probed at least once.
if [ "$TOTAL_SUBS" -eq 0 ]; then
    log_warn "All enumeration sources returned zero results — seeding the literal target hostname so Phase 2+ isn't skipped"
    echo "$TARGET" > "$RECON_DIR/subdomains/all.txt"
    TOTAL_SUBS=1
fi

log_ok "Total unique subdomains: $TOTAL_SUBS"

fi  # end of domain-only subdomain enum block

# ============================================================
# Phase 2: HTTP Probing
# ============================================================
echo ""
log_info "Phase 2: HTTP Probing"

if [ -x "$HTTPX_BIN" ] && [ -s "$RECON_DIR/subdomains/all.txt" ]; then
    log_step "Probing with httpx (status, title, tech, content-length)..."
    # -random-agent defaults to true in httpx (i.e. it picks a random UA
    # per request unless told otherwise) -- that's the opposite of
    # attribution, so it's explicitly disabled here rather than left to
    # fight with the -H override below.
    "$HTTPX_BIN" -l "$RECON_DIR/subdomains/all.txt" \
        -silent \
        -status-code \
        -title \
        -tech-detect \
        -content-length \
        -follow-redirects \
        -random-agent=false \
        -H "User-Agent: $RECON_USER_AGENT" \
        -threads "$THREADS" \
        -rate-limit "$RATE_LIMIT" \
        ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
        -o "$RECON_DIR/live/httpx_full.txt" 2>/dev/null || true

    # Extract just the URLs for other tools
    awk '{print $1}' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/urls.txt" 2>/dev/null || true

    LIVE_COUNT=$(wc -l < "$RECON_DIR/live/urls.txt" 2>/dev/null || echo 0)
    log_done "Live hosts: $LIVE_COUNT"

    # Separate by status code
    grep '\[200\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_200.txt" 2>/dev/null || true
    grep '\[30[12]\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || true
    grep '\[403\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_403.txt" 2>/dev/null || true
    grep '\[401\]' "$RECON_DIR/live/httpx_full.txt" > "$RECON_DIR/live/status_401.txt" 2>/dev/null || true

    log_done "200 OK: $(wc -l < "$RECON_DIR/live/status_200.txt" 2>/dev/null || echo 0)"
    log_done "3xx Redirect: $(wc -l < "$RECON_DIR/live/status_3xx.txt" 2>/dev/null || echo 0)"
    log_done "403 Forbidden: $(wc -l < "$RECON_DIR/live/status_403.txt" 2>/dev/null || echo 0)"
    log_done "401 Auth Required: $(wc -l < "$RECON_DIR/live/status_401.txt" 2>/dev/null || echo 0)"
else
    log_warn "httpx not installed or no subdomains found — skipping"
fi

# ============================================================
# Phase 2.5: Tech Fingerprinting (always-on -- same risk/cost profile as
# the httpx/nuclei phases in this pipeline; no flag gates this)
# ============================================================
echo ""
log_info "Phase 2.5: Tech Fingerprinting"

FINGERPRINT_DIR="$RECON_DIR/fingerprint"
FINGERPRINT_FINDINGS_DIR="$BASE_DIR/findings/$TARGET/fingerprint"
mkdir -p "$FINGERPRINT_DIR"

FP_TARGETS="$RECON_DIR/live/fingerprint_targets.txt"
: > "$FP_TARGETS"
if [ -s "$RECON_DIR/live/httpx_full.txt" ]; then
    # Basic-connectivity filter: httpx already recorded a status code for
    # every host in this file, including dead-on-arrival 404s -- don't
    # waste tech_fingerprint.py's several-request-per-host probe budget
    # re-confirming a host we already know 404s at the root. Hosts httpx
    # couldn't connect to at all never made it into this file to begin
    # with, so no separate connection-error filter is needed on top.
    grep -v '\[404\]' "$RECON_DIR/live/httpx_full.txt" | awk '{print $1}' | sort -u > "$FP_TARGETS" 2>/dev/null || true
elif [ -s "$RECON_DIR/live/urls.txt" ]; then
    sort -u "$RECON_DIR/live/urls.txt" > "$FP_TARGETS" 2>/dev/null || true
fi

TECH_FINGERPRINT_SCRIPT="$(dirname "$0")/tech_fingerprint.py"
if [ ! -s "$FP_TARGETS" ]; then
    log_warn "No live hosts (or all 404 at root) — skipping tech fingerprinting"
elif [ ! -f "$TECH_FINGERPRINT_SCRIPT" ]; then
    log_warn "tech_fingerprint.py missing — skipping tech fingerprinting"
else
    N_FP_TARGETS=$(wc -l < "$FP_TARGETS" | tr -d ' ')
    log_step "Fingerprinting $N_FP_TARGETS live host(s) (Jira/Confluence/Sentry/Jenkins/GitLab/Grafana/Kibana/FleetDM/Cachix)..."

    # Best-effort/non-fatal, same posture as hunt.py's
    # run_findings_correlator(): a missing script, non-zero exit, timeout,
    # or malformed JSON here must not take down the rest of this recon
    # run. Everything runs in a subshell with its own `set -e` so any of
    # those failure modes short-circuits straight past the write step
    # instead of writing partial/bogus output -- the parent script (no
    # `set -e` of its own) is completely unaffected by the subshell's exit
    # status either way, same as every other best-effort block above.
    (
        set -e
        # tech_fingerprint.py's exit code follows cors_scanner.py's
        # grep-style pipeline convention: 1 means "ran fine, nothing
        # identified", not a crash -- the `|| true` here stops `set -e`
        # from treating that common, legitimate outcome as a failure. A
        # REAL crash still gets caught below: it leaves raw.json
        # empty/unparseable, and json.load on that raises -- still inside
        # `set -e` -- which is what actually aborts this subshell.
        timeout 600 python3 "$TECH_FINGERPRINT_SCRIPT" -l "$FP_TARGETS" --json \
            > "$FINGERPRINT_DIR/raw.json" || true

        python3 - "$FINGERPRINT_DIR/raw.json" "$FINGERPRINT_DIR/results.txt" "$FINGERPRINT_FINDINGS_DIR/results.txt" <<'PY'
import json
import os
import sys

raw_path, recon_out, findings_out = sys.argv[1:4]
with open(raw_path, encoding="utf-8") as fh:
    results = json.load(fh)

# Only identified products get a line -- an "unidentified" host isn't an
# informational finding, it's a non-result, same reasoning as why other
# phases in this script only write positive hits (e.g. exposure/config_files.txt).
lines = []
for r in results:
    product = r.get("product") or "unidentified"
    if product == "unidentified":
        continue
    version = r.get("version") or "not disclosed"
    confidence = r.get("confidence") or "none"
    url = r.get("url", "")
    lines.append(f"[INFORMATIONAL] [{product}] {url} — version: {version} — confidence: {confidence}")

text = ("\n".join(lines) + "\n") if lines else ""
# Written to BOTH recon/<target>/fingerprint/ (this phase's own output)
# and findings/<target>/fingerprint/ (so findings_correlator.py -- which
# only ever reads from findings/<target>/<category>/*.txt -- can group a
# fingerprinted product together with any other finding on the same host).
for out_path in (recon_out, findings_out):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
print(len(lines))
PY
    ) > "$FINGERPRINT_DIR/count.txt" 2> "$FINGERPRINT_DIR/stderr.log"
    FP_STATUS=$?

    if [ "$FP_STATUS" -eq 0 ] && [ -s "$FINGERPRINT_DIR/count.txt" ]; then
        FP_COUNT="$(tail -1 "$FINGERPRINT_DIR/count.txt" | tr -dc '0-9')"
        if [ -n "$FP_COUNT" ] && [ "$FP_COUNT" -gt 0 ] 2>/dev/null; then
            log_done "Tech fingerprinting: $FP_COUNT product(s) identified — see $FINGERPRINT_DIR/results.txt"
        else
            log_done "Tech fingerprinting: no known products identified"
        fi
    else
        log_warn "Tech fingerprinting failed (see $FINGERPRINT_DIR/stderr.log) — continuing without it"
    fi
fi

# ============================================================
# Phase 2.6: CVE Lookup (opt-in via --cve-check, OFF by default -- hits
# NVD's external, rate-limited API; see the --cve-check note at the top
# of this file)
# ============================================================
if [ "$CVE_CHECK_MODE" = "1" ]; then
    echo ""
    log_info "Phase 2.6: CVE Lookup (--cve-check)"

    CVE_DIR="$RECON_DIR/cve"
    CVE_FINDINGS_DIR="$BASE_DIR/findings/$TARGET/cve"
    mkdir -p "$CVE_DIR"

    CVE_LOOKUP_SCRIPT="$(dirname "$0")/cve_lookup.py"
    FINGERPRINT_RAW="$RECON_DIR/fingerprint/raw.json"

    # NVD_API_KEY is genuinely OPTIONAL (unlike BBHUNT_SCOPE_FILE /
    # BBHUNT_USER_AGENT_SUFFIX's hard fail-closed gates above) -- this is
    # informational only, never a refusal. cve_lookup.py reads the env var
    # itself at request time and picks the matching rate automatically; no
    # extra plumbing is needed here since it's already inherited from this
    # shell's environment into the python3 subprocess below.
    if [ -z "${NVD_API_KEY:-}" ]; then
        log_step "NVD_API_KEY not set — proceeding at NVD's unauthenticated rate (5 req/30s). Optional: https://nvd.nist.gov/developers/request-an-api-key for 50 req/30s."
    else
        log_step "NVD_API_KEY set — using NVD's authenticated rate (50 req/30s)."
    fi

    if [ ! -s "$FINGERPRINT_RAW" ]; then
        log_warn "No tech-fingerprint data ($FINGERPRINT_RAW missing/empty) — skipping CVE lookup"
    elif [ ! -f "$CVE_LOOKUP_SCRIPT" ]; then
        log_warn "cve_lookup.py missing — skipping CVE lookup"
    else
        # Best-effort/non-fatal, same posture as Phase 2.5 above and
        # hunt.py's run_findings_correlator(): a missing script, non-zero
        # exit, timeout, or malformed JSON here must not take down the
        # rest of this recon run. Same `set -e` subshell + JSON-validity-
        # is-the-real-gate structure as Phase 2.5 -- see the comments
        # there for the full reasoning, not repeated here.
        (
            set -e
            # cve_lookup.py's exit code convention: 2 means "ran fine,
            # candidate CVEs found", 0 means "ran fine, none found" --
            # neither is a crash, so `|| true` stops `set -e` from
            # treating either as a failure. A REAL crash leaves
            # cve_raw.json empty/unparseable, and json.load on that
            # raises -- still inside `set -e` -- which is what actually
            # aborts this subshell.
            timeout 900 python3 "$CVE_LOOKUP_SCRIPT" --from-fingerprint "$FINGERPRINT_RAW" --json \
                > "$CVE_DIR/cve_raw.json" || true

            python3 - "$FINGERPRINT_RAW" "$CVE_DIR/cve_raw.json" "$CVE_DIR/results.txt" "$CVE_FINDINGS_DIR/results.txt" <<'PY'
import json
import os
import sys

fp_path, cve_path, recon_out, findings_out = sys.argv[1:5]

with open(fp_path, encoding="utf-8") as fh:
    fingerprints = json.load(fh)
with open(cve_path, encoding="utf-8") as fh:
    cve_results = json.load(fh)

# cve_lookup.py's --json output is keyed by (product, version), not by
# host -- multiple fingerprinted hosts can share the same product+version
# and must each get their own line here, so this cross-joins
# tech_fingerprint.py's url -> (product, version) mapping against
# cve_lookup.py's product/version -> CVE data.
cve_by_key = {(r["product"], r["version"]): r for r in cve_results}

lines = []
for fp in fingerprints:
    product = fp.get("product") or "unidentified"
    version = fp.get("version") or "not disclosed"
    if product == "unidentified" or version == "not disclosed":
        continue
    result = cve_by_key.get((product, version))
    if not result:
        continue
    url = fp.get("url", "")
    for cve in result.get("cves", []):
        severity = cve.get("severity")
        score = cve.get("cvss_score")
        sev_str = f"{severity} ({score})" if severity else "no CVSS score on record"
        match_tag = "version-mentioned" if cve.get("version_mentioned") else "product-match-only"
        # [INFORMATIONAL], never [CONFIRMED] -- every candidate here
        # requires manual verification, per cve_lookup.py's own framing.
        lines.append(
            f"[INFORMATIONAL] [{cve.get('cve_id', '?')}] {url} "
            f"— product={product} version={version} severity={sev_str} match={match_tag} "
            f"— {cve.get('summary', '')} — {result.get('note', '')}"
        )

text = ("\n".join(lines) + "\n") if lines else ""
# Written to BOTH recon/<target>/cve/ (this phase's own output) and
# findings/<target>/cve/ (so findings_correlator.py -- which only ever
# reads from findings/<target>/<category>/*.txt -- can group a candidate
# CVE together with any other finding on the same host), same dual-write
# pattern as Phase 2.5's fingerprint output.
for out_path in (recon_out, findings_out):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
print(len(lines))
PY
        ) > "$CVE_DIR/count.txt" 2> "$CVE_DIR/stderr.log"
        CVE_STATUS=$?

        if [ "$CVE_STATUS" -eq 0 ] && [ -s "$CVE_DIR/count.txt" ]; then
            CVE_COUNT="$(tail -1 "$CVE_DIR/count.txt" | tr -dc '0-9')"
            if [ -n "$CVE_COUNT" ] && [ "$CVE_COUNT" -gt 0 ] 2>/dev/null; then
                log_done "CVE lookup: $CVE_COUNT candidate CVE(s) — see $CVE_DIR/results.txt"
            else
                log_done "CVE lookup: no candidate CVEs found"
            fi
        else
            log_warn "CVE lookup failed (see $CVE_DIR/stderr.log) — continuing without it"
        fi
    fi
fi

# ============================================================
# Phase 3: Port Scanning
# ============================================================
echo ""
log_info "Phase 3: Port Scanning"

if command -v nmap &>/dev/null; then
    log_step "Running nmap (top 1000 ports) on $TARGET..."
    # No User-Agent equivalent here, and this is not an oversight to fix
    # later -- a TCP/SYN port scan has no application-layer field to carry
    # an identifying string in at all. -sV's service/version detection does
    # send a handful of fixed protocol probes (nmap-service-probes), and
    # one of the built-in HTTP probes is a literal "GET / HTTP/1.0\r\n\r\n"
    # -- but nmap has no flag to inject a custom header into that probe,
    # and doing so would corrupt the exact byte-for-byte signature its
    # service-fingerprint matching relies on. NSE's http.useragent script
    # argument is a different thing entirely -- it only affects HTTP
    # requests made BY NSE scripts (e.g. --script http-title), and this
    # invocation runs no NSE scripts at all, so it wouldn't apply here
    # even if it were added.
    #
    # What actually identifies a scan at this layer is the source IP (and,
    # to a fingerprinting target, nmap's own packet/timing signature) --
    # not an injectable marker. That's a real, structural difference from
    # HTTP-based tools, not a gap this script can close by trying harder.
    nmap -sV --top-ports 1000 -T4 --open "$TARGET" \
        -oN "$RECON_DIR/ports/nmap_results.txt" \
        -oG "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null || true
    log_done "Nmap scan complete"

    # Extract open ports (macOS compatible - no grep -P)
    grep "open" "$RECON_DIR/ports/nmap_greppable.txt" 2>/dev/null \
        | sed -nE 's/.*[^0-9]([0-9]+)\/open.*/\1\/open/p' \
        | sort -u > "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || true
    log_done "Open ports: $(wc -l < "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || echo 0)"
else
    log_warn "nmap not installed — skipping"
fi

# ============================================================
# Phase 4: URL Collection
# ============================================================
echo ""
log_info "Phase 4: URL Collection"

# GAU - Get All URLs (wayback, commoncrawl, otx, urlscan)
# `gau -h` has no User-Agent/header flag either. Same nature as
# subfinder/amass above: gau queries wayback/commoncrawl/otx/urlscan about
# the target, it doesn't send requests to the target's own infrastructure.
if command -v gau &>/dev/null; then
    log_step "Running gau (historical URLs)..."
    echo "$TARGET" | gau --threads 20 --o "$RECON_DIR/urls/gau.txt" 2>/dev/null || \
    echo "$TARGET" | gau > "$RECON_DIR/urls/gau.txt" 2>/dev/null || true
    log_done "gau: $(wc -l < "$RECON_DIR/urls/gau.txt" 2>/dev/null || echo 0) URLs"
else
    log_warn "gau not installed — using wayback fallback"
    curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey&limit=5000" \
        > "$RECON_DIR/urls/wayback.txt" 2>/dev/null || true
    log_done "wayback: $(wc -l < "$RECON_DIR/urls/wayback.txt" 2>/dev/null || echo 0) URLs"
fi

# katana (active crawl) was removed from this pipeline entirely -- not
# disabled, not gated behind a flag, gone. Three consecutive attempts to
# make its crawl scope trustworthy against a real target all failed:
#   1. -cs (crawl-scope allow-regex) alone: leaked 4 URLs to
#      shop.vodafone.om/careers.vodafone.om/numbers.vodafone.om.
#   2. -cs + -dr (disable-redirects): leaked the SAME 4 URLs, identically
#      -- despite -dr passing ~20/20 local trials against a synthetic
#      same-host-redirector harness. Whatever mechanism causes the real
#      leak isn't a followed redirect at all.
#   3. -cs + -proxy (a local scope-enforcing forward proxy -- see
#      tools/scope_proxy.py, kept in the repo as a standalone reusable
#      tool even though it's no longer wired in here): closed every
#      leak vector tested EXCEPT redirect-following, which bypasses
#      katana's own -proxy setting entirely and connects directly. Adding
#      -dr back to plug that specific hole made katana hang for the
#      FULL 300s timeout on every single run (4/4 trials, including one
#      at the actual 300s production ceiling) -- -dr and -proxy are
#      mutually incompatible in this katana version, not just flaky
#      together.
# Every one of katana's own scope mechanisms either doesn't get consulted
# by every internal subsystem, or breaks something else when combined
# with the fix for that. gau (below) is passive-archive-only -- it never
# touches the live target at all, so it has no equivalent scope risk; it
# is now the sole URL-collection source for this phase. The tradeoff is
# real: katana was finding genuine value gau doesn't have (live API
# endpoints not yet in any archive), and losing it is a real completeness
# cost, not a free win -- accepted deliberately because guessing at
# katana flags against a live target has cost two real, if now small,
# scope violations and does not currently converge on a fix that also
# keeps katana usable.

# Merge all collected URLs
cat "$RECON_DIR/urls/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/urls/all.txt" 2>/dev/null || true
log_done "Total unique URLs: $(wc -l < "$RECON_DIR/urls/all.txt" 2>/dev/null || echo 0)"

# Filter interesting URLs
if [ -s "$RECON_DIR/urls/all.txt" ]; then
    # URLs with parameters (potential injection points)
    grep '?' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/with_params.txt" 2>/dev/null || true
    log_done "URLs with parameters: $(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null || echo 0)"

    # JS files
    grep -iE '\.js(\?|$)' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/js_files.txt" 2>/dev/null || true
    log_done "JS files: $(wc -l < "$RECON_DIR/urls/js_files.txt" 2>/dev/null || echo 0)"

    # API endpoints
    grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/)' "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || true
    log_done "API endpoints: $(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || echo 0)"

    # Potentially sensitive paths
    grep -iE '\.(env|config|xml|json|yaml|yml|bak|backup|old|orig|sql|db|log|txt|conf|ini|htaccess|htpasswd|git)' \
        "$RECON_DIR/urls/all.txt" > "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || true
    log_done "Sensitive paths: $(wc -l < "$RECON_DIR/urls/sensitive_paths.txt" 2>/dev/null || echo 0)"
fi

# ============================================================
# Phase 5: JS Analysis
# ============================================================
echo ""
log_info "Phase 5: JavaScript Analysis"

if [ -s "$RECON_DIR/urls/js_files.txt" ]; then
    log_step "Extracting endpoints from JS files (top 50)..."
    mkdir -p "$RECON_DIR/js"

    head -50 "$RECON_DIR/urls/js_files.txt" | while IFS= read -r js_url; do
        bb_curl "$js_url" -s --max-time 10 2>/dev/null | \
            sed -nE 's/.*["'"'"']([a-zA-Z0-9_/.-]*(\/[a-zA-Z0-9_/.-]+)+)["'"'"'].*/\1/p' \
            >> "$RECON_DIR/js/endpoints_raw.txt" 2>/dev/null || true
    done

    if [ -f "$RECON_DIR/js/endpoints_raw.txt" ]; then
        sort -u "$RECON_DIR/js/endpoints_raw.txt" > "$RECON_DIR/js/endpoints.txt"
        log_done "JS endpoints: $(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null || echo 0)"

        # Extract potential secrets from JS
        head -50 "$RECON_DIR/urls/js_files.txt" | while IFS= read -r js_url; do
            bb_curl "$js_url" -s --max-time 10 2>/dev/null | \
                grep -oiE '(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret[_-]?key)["\s]*[:=]["\s]*[a-zA-Z0-9_\-]{8,}' \
                >> "$RECON_DIR/js/potential_secrets.txt" 2>/dev/null || true
        done
        if [ -s "$RECON_DIR/js/potential_secrets.txt" ]; then
            sort -u "$RECON_DIR/js/potential_secrets.txt" -o "$RECON_DIR/js/potential_secrets.txt"
            log_warn "Potential secrets found in JS: $(wc -l < "$RECON_DIR/js/potential_secrets.txt")"
        fi
    fi
else
    log_warn "No JS files found — skipping JS analysis"
fi

# ============================================================
# Phase 6: Directory Fuzzing
# ============================================================
echo ""
log_info "Phase 6: Directory Fuzzing"

WORDLIST_DIR="$BASE_DIR/wordlists"
LEGACY_WORDLIST_DIR="$BASE_DIR/tools/wordlists"

if command -v ffuf &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
    # Select wordlist
    WORDLIST=""
    if [ -f "$WORDLIST_DIR/common.txt" ]; then
        WORDLIST="$WORDLIST_DIR/common.txt"
    elif [ -f "$LEGACY_WORDLIST_DIR/common.txt" ]; then
        WORDLIST="$LEGACY_WORDLIST_DIR/common.txt"
    elif [ -f "$WORDLIST_DIR/raft-medium-dirs.txt" ]; then
        WORDLIST="$WORDLIST_DIR/raft-medium-dirs.txt"
    elif [ -f "$LEGACY_WORDLIST_DIR/raft-medium-dirs.txt" ]; then
        WORDLIST="$LEGACY_WORDLIST_DIR/raft-medium-dirs.txt"
    elif [ -f /usr/share/wordlists/dirb/common.txt ]; then
        WORDLIST="/usr/share/wordlists/dirb/common.txt"
    fi

    if [ -n "$WORDLIST" ]; then
        # Fuzz top 5 live hosts
        FUZZ_COUNT=0
        MAX_FUZZ=$([ "$QUICK_MODE" = "--quick" ] && echo 2 || echo 5)

        while IFS= read -r url && [ "$FUZZ_COUNT" -lt "$MAX_FUZZ" ]; do
            domain=$(echo "$url" | sed 's|https\?://||;s|[/:].*||')
            log_step "Fuzzing: $url"
            ffuf -u "${url}/FUZZ" \
                -w "$WORDLIST" \
                -mc 200,301,302,403,405 \
                -t "$THREADS" \
                -rate "$RATE_LIMIT" \
                -sf \
                -timeout 10 \
                -H "User-Agent: $RECON_USER_AGENT" \
                ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
                -o "$RECON_DIR/dirs/ffuf_${domain}.json" \
                -of json 2>/dev/null || true
            ((FUZZ_COUNT++))
        done < "$RECON_DIR/live/urls.txt"

        log_done "Directory fuzzing complete ($FUZZ_COUNT hosts)"
    else
        log_warn "No wordlist found — run: python3 tools/hunt.py --setup-wordlists"
    fi
else
    log_warn "ffuf not installed or no live hosts — skipping directory fuzzing"
fi

# ============================================================
# Phase 6.5: Config File Exposure Check
# ============================================================
echo ""
log_info "Phase 6.5: Config File Exposure Check"

if [ -s "$RECON_DIR/live/urls.txt" ]; then
    log_step "Checking for exposed config files (env.js, app_env.js, .env, etc.)..."
    CONFIG_PATHS=(
        "/env.js"
        "/app_env.js"
        "/config.js"
        "/settings.js"
        "/.env"
        "/.env.local"
        "/.env.production"
        "/.env.development"
        "/config/env.js"
        "/static/env.js"
        "/assets/env.js"
    )

    mkdir -p "$RECON_DIR/exposure"
    : > "$RECON_DIR/exposure/config_files.txt"

    while IFS= read -r base_url; do
        # Catch-all guard: a host that answers every path the same way --
        # a client-routed SPA shell, or a backend API that ignores the
        # requested path entirely -- defeats the content-type check below
        # on its own. Confirmed live: a PKI/CA host returned
        # `Content-Type: application/json` for every single CONFIG_PATHS
        # entry (a catch-all API always answering with the same cert-chain
        # JSON regardless of path), which passed the content-type filter
        # and got flagged as 11 separate "exposed config files" that were
        # never real. bb_catchall_baseline()/bb_response_signature()
        # (tools/bb_curl.sh) catch this class regardless of which
        # status/content-type the shared answer happens to have, by
        # comparing each probed path against a deliberately nonexistent
        # one instead of trusting content-type alone -- checked per PATH,
        # not as a single blanket per-host skip (a host with no index page
        # at "/" would otherwise look identical to a real catch-all).
        # Uses bb_curl (with auth), not the default bb_curl_no_auth, to
        # match how this phase's own probes below are already sent --
        # an unauthenticated baseline compared against authenticated
        # probe results would be comparing two different things.
        BASELINE="$(bb_catchall_baseline "$base_url" bb_curl)"
        for path in "${CONFIG_PATHS[@]}"; do
            SIG="$(bb_response_signature "${base_url}${path}" bb_curl)"
            [ "$SIG" = "$BASELINE" ] && continue
            STATUS="${SIG%%:*}"
            if [ "$STATUS" = "200" ]; then
                CONTENT_TYPE=$(bb_curl "${base_url}${path}" -sI --max-time 5 2>/dev/null | grep -i content-type | head -1)
                # Only flag if it returns JS/JSON/text (not HTML error pages)
                if echo "$CONTENT_TYPE" | grep -qiE '(javascript|json|text/plain)'; then
                    echo "[EXPOSED] ${base_url}${path}" >> "$RECON_DIR/exposure/config_files.txt"
                    log_vuln "Config exposed: ${base_url}${path}"
                fi
            fi
        done
    done < <(head -30 "$RECON_DIR/live/urls.txt")

    CONFIG_COUNT=$(wc -l < "$RECON_DIR/exposure/config_files.txt" 2>/dev/null | tr -d ' ')
    [ "$CONFIG_COUNT" -gt 0 ] && log_warn "Exposed config files: $CONFIG_COUNT" || log_done "Config files: clean"
else
    log_warn "No live hosts — skipping config check"
fi

# ============================================================
# Phase 7: Parameter Discovery
# ============================================================
echo ""
log_info "Phase 7: Parameter Discovery"

if [ -s "$RECON_DIR/urls/with_params.txt" ]; then
    log_step "Extracting parameters from collected URLs..."

    # Extract parameter names (macOS compatible - no grep -P)
    sed -nE 's/.*[?&]([^=&]+)=.*/\1/p' "$RECON_DIR/urls/with_params.txt" 2>/dev/null \
        | sort | uniq -c | sort -rn > "$RECON_DIR/params/param_frequency.txt" 2>/dev/null || true

    # Get unique param names
    awk '{print $2}' "$RECON_DIR/params/param_frequency.txt" > "$RECON_DIR/params/unique_params.txt" 2>/dev/null || true
    log_done "Unique parameters: $(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null || echo 0)"

    # Flag interesting params (potential injection points)
    grep -iE '(url|redirect|next|return|callback|dest|file|path|page|template|include|src|ref|uri|link|target|goto|out|view|dir|show|site|domain|rurl|return_to|continue|window|data|reference|to|img|load|doc|download)' \
        "$RECON_DIR/params/unique_params.txt" > "$RECON_DIR/params/interesting_params.txt" 2>/dev/null || true

    if [ -s "$RECON_DIR/params/interesting_params.txt" ]; then
        log_warn "Interesting params (potential vulns): $(wc -l < "$RECON_DIR/params/interesting_params.txt")"
        echo "      Params: $(head -5 "$RECON_DIR/params/interesting_params.txt" | tr '\n' ', ')"
    fi
else
    log_warn "No parameterized URLs found — skipping"
fi

# ============================================================
# Phase 8: CI/CD Workflow Scan (auto-detect GitHub org)
# ============================================================
log_info "Phase 8: CI/CD Workflow Scan"

GITHUB_ORGS=""
CICD_SCANNER="$(dirname "$0")/cicd_scanner.sh"

# Extract github.com/<org> patterns from recon data
for f in "$RECON_DIR/live/httpx_full.txt" "$RECON_DIR/js/endpoints.txt" "$RECON_DIR/urls/all.txt"; do
    if [ -f "$f" ]; then
        GITHUB_ORGS="$GITHUB_ORGS $(grep -oP 'github\.com/\K[a-zA-Z0-9_-]+' "$f" 2>/dev/null || true)"
    fi
done

# Deduplicate and limit to 5
GITHUB_ORGS=$(echo "$GITHUB_ORGS" | tr ' ' '\n' | grep -v '^$' | sort -u | head -5)

if [ -n "$GITHUB_ORGS" ] && [ -x "$CICD_SCANNER" ] && command -v sisakulint &>/dev/null; then
    for ORG in $GITHUB_ORGS; do
        log_info "CI/CD scan: org:$ORG"
        bash "$CICD_SCANNER" "org:$ORG" --output-dir "$RECON_DIR/cicd/$ORG/" || true
    done
else
    if [ -z "$GITHUB_ORGS" ]; then
        log_warn "GitHub org not detected — CI/CD scan skipped"
    elif ! command -v sisakulint &>/dev/null; then
        log_warn "sisakulint not installed — CI/CD scan skipped"
    fi
fi

# ============================================================
# Phase 9: Nuclei vulnerability sweep (optional, gated on installed binary)
# ============================================================
echo ""
log_info "Phase 9: Nuclei Vulnerability Sweep"

if command -v nuclei &>/dev/null && [ -s "$RECON_DIR/live/urls.txt" ]; then
    NUCLEI_OUT="$RECON_DIR/nuclei"
    mkdir -p "$NUCLEI_OUT"
    NUC_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 50 || echo 200)
    NUC_SEV=$([ "$QUICK_MODE" = "--quick" ] && echo "high,critical" || echo "medium,high,critical")
    NUC_TIMEOUT=$([ "$QUICK_MODE" = "--quick" ] && echo 600 || echo 1800)

    head -"$NUC_LIMIT" "$RECON_DIR/live/urls.txt" > "$NUCLEI_OUT/targets.txt"
    log_step "nuclei on $(wc -l < "$NUCLEI_OUT/targets.txt" | tr -d ' ') hosts (severity=$NUC_SEV, timeout=${NUC_TIMEOUT}s)..."

    NUC_RL="${NUC_RATE_LIMIT:-300}"
    NUC_C="${NUC_CONCURRENCY:-50}"
    NUC_BS="${NUC_BULK_SIZE:-50}"

    timeout "$NUC_TIMEOUT" nuclei \
        -l "$NUCLEI_OUT/targets.txt" \
        -severity "$NUC_SEV" \
        -rl "$NUC_RL" \
        -c "$NUC_C" \
        -bs "$NUC_BS" \
        -silent \
        -stats \
        -H "User-Agent: $RECON_USER_AGENT" \
        ${BB_AUTH_ARGS[@]+"${BB_AUTH_ARGS[@]}"} \
        -jsonl \
        -o "$NUCLEI_OUT/findings.jsonl" 2>/dev/null || true

    if [ -s "$NUCLEI_OUT/findings.jsonl" ]; then
        # Severity buckets for human review
        for sev in critical high medium low info; do
            grep -F "\"severity\":\"$sev\"" "$NUCLEI_OUT/findings.jsonl" \
                > "$NUCLEI_OUT/${sev}.jsonl" 2>/dev/null || true
            n=$(wc -l < "$NUCLEI_OUT/${sev}.jsonl" 2>/dev/null | tr -d ' ')
            [ "$n" -gt 0 ] && log_done "nuclei $sev: $n"
        done
    else
        log_done "nuclei: no findings"
    fi
else
    [ -z "$(command -v nuclei)" ] && log_warn "nuclei not installed — see ./tools/external_arsenal.sh --install-hint nuclei"
fi

# ============================================================
# Phase 10: Subdomain takeover quick-check (CNAME fingerprint grep)
# ============================================================
echo ""
log_info "Phase 10: Subdomain Takeover Quick-Check"

if command -v dig &>/dev/null && [ -s "$RECON_DIR/subdomains/all.txt" ]; then
    TAKEOVER_OUT="$RECON_DIR/takeover_candidates.txt"
    : > "$TAKEOVER_OUT"
    SUB_LIMIT=$([ "$QUICK_MODE" = "--quick" ] && echo 100 || echo 500)

    log_step "Resolving CNAMEs for top $SUB_LIMIT subdomains..."
    head -"$SUB_LIMIT" "$RECON_DIR/subdomains/all.txt" | while IFS= read -r host; do
        [ -z "$host" ] && continue
        cname=$(dig +short "$host" CNAME 2>/dev/null | head -1)
        [ -z "$cname" ] && continue
        # Match common claimable-service CNAME suffixes (extend list as needed)
        case "$cname" in
            *github.io.*|*herokuapp.com.*|*herokussl.com.*|\
            *s3.amazonaws.com.*|*s3-website*.amazonaws.com.*|\
            *azurewebsites.net.*|*cloudapp.net.*|*trafficmanager.net.*|\
            *shopify.com.*|*myshopify.com.*|\
            *wordpress.com.*|*ghost.io.*|*tumblr.com.*|\
            *pantheonsite.io.*|*surge.sh.*|*netlify.app.*|*vercel.app.*|\
            *zendesk.com.*|*helpjuice.com.*|*helpscout.net.*|*statuspage.io.*|\
            *fastly.net.*|*readme.io.*|*intercom.help.*)
                echo "$host  CNAME→ $cname" >> "$TAKEOVER_OUT" ;;
        esac
    done

    n=$(wc -l < "$TAKEOVER_OUT" | tr -d ' ')
    if [ "$n" -gt 0 ]; then
        log_warn "$n potential takeover candidate(s) — review $TAKEOVER_OUT"
        log_warn "Confirm with: ./tools/takeover_scanner.sh --recon $RECON_DIR"
    else
        log_done "Takeover quick-check: clean"
    fi
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================="
echo "  Recon Summary — $TARGET"
echo "  Completed: $(date)"
echo "============================================="
echo ""
echo "  Subdomains:        $(wc -l < "$RECON_DIR/subdomains/all.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/live/urls.txt" ] && \
echo "  Live hosts:        $(wc -l < "$RECON_DIR/live/urls.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/ports/open_ports.txt" ] && \
echo "  Open ports:        $(wc -l < "$RECON_DIR/ports/open_ports.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/all.txt" ] && \
echo "  URLs collected:    $(wc -l < "$RECON_DIR/urls/all.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/with_params.txt" ] && \
echo "  Parameterized:     $(wc -l < "$RECON_DIR/urls/with_params.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/urls/api_endpoints.txt" ] && \
echo "  API endpoints:     $(wc -l < "$RECON_DIR/urls/api_endpoints.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/js/endpoints.txt" ] && \
echo "  JS endpoints:      $(wc -l < "$RECON_DIR/js/endpoints.txt" 2>/dev/null || echo 0)"
[ -f "$RECON_DIR/params/unique_params.txt" ] && \
echo "  Unique params:     $(wc -l < "$RECON_DIR/params/unique_params.txt" 2>/dev/null || echo 0)"

[ -d "$RECON_DIR/cicd" ] && \
echo "  CI/CD findings:   $(find "$RECON_DIR/cicd" -name 'scan_results.txt' -exec grep -cP '\.github/workflows/' {} + 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}')"

[ -f "$RECON_DIR/nuclei/findings.jsonl" ] && \
echo "  Nuclei hits:       $(wc -l < "$RECON_DIR/nuclei/findings.jsonl" | tr -d ' ')"
[ -f "$RECON_DIR/takeover_candidates.txt" ] && \
echo "  Takeover candidates: $(wc -l < "$RECON_DIR/takeover_candidates.txt" | tr -d ' ')"

echo ""
echo "  Results: $RECON_DIR/"
echo "============================================="
echo ""
echo "  Next:"
echo "    ./tools/vuln_scanner.sh $RECON_DIR        # active vuln probes"
echo "    ./tools/takeover_scanner.sh --recon $RECON_DIR   # confirm CNAME takeovers"
echo "    ./tools/secrets_hunter.sh --js-bundle $RECON_DIR  # leaked-cred sweep"
echo "============================================="
