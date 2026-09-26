#!/bin/bash
# =============================================================================
# bb_curl.sh — scope-and-rate-limit-enforcing curl wrapper
#
# NOT wired into any other script yet. This file only defines functions when
# sourced; it does nothing on its own and makes no requests until a caller
# explicitly invokes bb_curl().
#
# Usage (from another script):
#
#   . "$(dirname "$0")/bb_curl.sh"
#
#   export BBHUNT_SCOPE_FILE="recon/target.com/scope.txt"   # required, no default
#   export BBHUNT_USER_AGENT_SUFFIX="yourhandle (+https://hackerone.com/yourhandle)"
#                                                            # required, no default —
#                                                            # every outbound request must be
#                                                            # identifiable as coming from a
#                                                            # specific hacker; see _bb_user_agent()
#   export BBHUNT_RATE_LIMIT_RPS=2                          # optional, default 2
#   export BBHUNT_AUDIT_LOG="logs/audit.log"                # optional, default shown
#   export BBHUNT_AUTH_HEADERS=$'Authorization: Bearer xyz\nX-Custom: val'  # optional
#   export BBHUNT_RESEARCH_HEADER="X-HackerOne-Research: b1tr00t"  # optional,
#                                                            # no default — unlike
#                                                            # BBHUNT_USER_AGENT_SUFFIX,
#                                                            # unset means "send
#                                                            # nothing extra", not an
#                                                            # error; see _bb_research_header()
#   export BBHUNT_RAPYD_SIGN=1                              # optional, OFF by default —
#                                                            # opt-in Rapyd request-signing.
#                                                            # See _bb_rapyd_sign_headers()
#                                                            # below for exactly what this
#                                                            # does and doesn't cover.
#
#   bb_curl "https://api.target.com/v1/users/123" -s -o /tmp/out.json
#   # ^ any trailing args after the URL are passed straight through to curl.
#
# Scope file format (one entry per line, '#' comments allowed):
#   example.com          # exact host only — not www.example.com, not api.example.com
#   api.example.com      # exact host only
#   *.example.com        # any subdomain at any depth — foo.example.com,
#                         # a.b.example.com — but NOT bare example.com itself.
#                         # List example.com on its own line too if the apex
#                         # is also in scope. See is_in_scope() below for why
#                         # this split is deliberate, not an oversight.
#
# Functions exported for callers:
#   is_in_scope <url>   — returns 0 if in scope, non-zero otherwise. Logs
#                          blocks and hard config errors to the audit log.
#   bb_curl <url> [curl-args...] — enforces scope + rate limit, then runs
#                          curl with BBHUNT_AUTH_HEADERS, an identifying
#                          User-Agent (BBHUNT_USER_AGENT_SUFFIX), the
#                          optional BBHUNT_RESEARCH_HEADER, and — only when
#                          BBHUNT_RAPYD_SIGN=1 AND the URL's host is
#                          tools/rapyd_sign.py's hardcoded sandbox host —
#                          Rapyd's HMAC auth headers (see
#                          _bb_rapyd_sign_headers() below). Refuses to send
#                          (returns 2) rather than send unsigned if signing
#                          was requested but RAPYD_ACCESS_KEY/RAPYD_SECRET_KEY
#                          aren't both set.
#                          Logs every request it actually sends, and every
#                          request it blocks, to the audit log.
# =============================================================================

# Guard: source-only, no execution (same pattern as _auth_helper.sh).
[ "${BASH_SOURCE[0]}" = "$0" ] && {
    echo "bb_curl.sh must be sourced, not executed" >&2
    return 1 2>/dev/null || exit 1
}

# ── Internal: audit log ──────────────────────────────────────────────────────
# Every line is UTC timestamp + a tagged message. Used for both blocked and
# sent requests so the log is a complete record either way.
_bb_audit_log() {
    local msg="$1"
    local log_file="${BBHUNT_AUDIT_LOG:-logs/audit.log}"
    local log_dir
    log_dir="$(dirname "$log_file")"
    [ -d "$log_dir" ] || mkdir -p "$log_dir" 2>/dev/null
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$msg" >> "$log_file" 2>/dev/null
}

# ── Internal: write directly to the controlling terminal ────────────────────
# Used for messages that must stay visible even when a caller has redirected
# stderr (every bb_curl call site wired into recon_engine.sh appends
# `2>/dev/null`, which would otherwise swallow this along with ordinary curl
# errors). Opens /dev/tty on a private fd (9) rather than writing straight to
# stderr, so it bypasses that redirection entirely.
#
# Falls back to a silent no-op when there's no controlling terminal (cron,
# CI, a fully detached background job) — never errors, never blocks. Note
# the `{ ...; } 2>/dev/null` grouping is load-bearing, not decorative: a bare
# `exec 9>/dev/tty 2>/dev/null` on one line does NOT suppress the "No such
# device or address" message bash prints when the open fails, because bash
# evaluates a command's redirections left-to-right and reports the first
# failure before the later `2>/dev/null` redirection has taken effect.
# Wrapping the attempt in a `{ }` group and redirecting the *group's* stderr
# applies that redirection before anything inside it runs, so the failure
# is caught. Verified empirically in an environment with no attached tty at
# all (see conversation) — the bare form leaks the bash error, the grouped
# form does not.
_bb_tty_echo() {
    if { exec 9>/dev/tty; } 2>/dev/null; then
        printf '%s\n' "$1" >&9
        exec 9>&-
    fi
}

# ── Internal: hostname extraction ────────────────────────────────────────────
# Strips scheme, userinfo (user:pass@), path/query/fragment, and port;
# unwraps bracketed IPv6 literals; lowercases; strips a trailing FQDN dot.
_bb_extract_host() {
    local url="$1" rest host

    case "$url" in
        *://*) rest="${url#*://}" ;;
        *)     rest="$url" ;;
    esac

    case "$rest" in
        *@*) rest="${rest#*@}" ;;
    esac

    # Keep only the authority component (host[:port]).
    rest="${rest%%/*}"
    rest="${rest%%\?*}"
    rest="${rest%%#*}"
    host="$rest"

    case "$host" in
        \[*\]*)
            # Bracketed IPv6 literal, e.g. [2001:db8::1]:8443 -> 2001:db8::1
            host="${host#\[}"
            host="${host%%\]*}"
            ;;
        *)
            # Strip :port. Unbracketed IPv6 (multiple colons, no brackets)
            # is not supported here — callers must bracket IPv6 URLs per
            # RFC 3986, same as curl itself requires.
            case "$host" in
                *:*) host="${host%%:*}" ;;
            esac
            ;;
    esac

    host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
    host="${host%.}"   # tolerate a trailing-dot FQDN in the URL

    printf '%s\n' "$host"
}

# ── is_in_scope ──────────────────────────────────────────────────────────────
# Fails LOUD and CLOSED: an unset or missing BBHUNT_SCOPE_FILE is a hard
# error (exit 2), not "allow everything". A URL whose host isn't covered by
# any scope-file entry is blocked (exit 1) and logged.
is_in_scope() {
    local url="$1" host scope_file line pattern base

    if [ -z "${BBHUNT_SCOPE_FILE:-}" ]; then
        echo "[FATAL] BBHUNT_SCOPE_FILE is not set — refusing to allow any request without an explicit scope file" >&2
        _bb_audit_log "[FATAL-NO-SCOPE-FILE] BBHUNT_SCOPE_FILE unset, url=$url"
        return 2
    fi
    scope_file="$BBHUNT_SCOPE_FILE"
    if [ ! -f "$scope_file" ] || [ ! -r "$scope_file" ]; then
        echo "[FATAL] BBHUNT_SCOPE_FILE=$scope_file does not exist or is not readable — refusing to allow any request" >&2
        _bb_audit_log "[FATAL-NO-SCOPE-FILE] BBHUNT_SCOPE_FILE=$scope_file unreadable, url=$url"
        return 2
    fi

    host="$(_bb_extract_host "$url")"
    if [ -z "$host" ]; then
        _bb_audit_log "[BLOCKED-BAD-URL] could not extract host, url=$url"
        return 1
    fi

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        [ -z "$line" ] && continue

        pattern="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
        pattern="${pattern%.}"

        case "$pattern" in
            \*.*)
                # Wildcard entry ("*.example.com"): matches any subdomain at
                # any depth (foo.example.com, a.b.example.com, ...) via an
                # anchored suffix check. Deliberately does NOT match the bare
                # apex "example.com" — that requires its own separate line.
                # See explanation below for why this split is intentional.
                base="${pattern#\*.}"
                case "$host" in
                    *".$base") return 0 ;;
                esac
                ;;
            *)
                # Exact entry: matches only this literal hostname.
                [ "$host" = "$pattern" ] && return 0
                ;;
        esac
    done < "$scope_file"

    _bb_audit_log "[BLOCKED-OUT-OF-SCOPE] host=$host url=$url scope_file=$scope_file"
    _bb_tty_echo "[BLOCKED-OUT-OF-SCOPE] $url is not in scope (host=$host) — see BBHUNT_AUDIT_LOG for the full record"
    return 1
}

# ── bb_filter_scope_list ─────────────────────────────────────────────────────
# bb_filter_scope_list <input-file> <output-file>
# For callers that hand an entire URL list to a binary that makes its own
# requests directly (nuclei -l, dalfox pipe, ...) rather than going through
# bb_curl() one URL at a time -- those binaries never touch is_in_scope() on
# their own, so their input needs to be scope-checked before they ever see
# it. Filters <input-file> (one URL/host per line; blank lines and '#'
# comments skipped, same convention as a scope file) down to only the
# lines that pass is_in_scope(), writing the result to <output-file>.
#
# Deliberately calls is_in_scope() itself per line rather than reimplementing
# its matching logic -- same fail-loud behavior on a missing/unreadable
# BBHUNT_SCOPE_FILE (is_in_scope's own [FATAL...] log entry and non-zero
# return propagate straight through), and every filtered-out line is logged
# via is_in_scope()'s own _bb_audit_log calls (e.g. [BLOCKED-OUT-OF-SCOPE]),
# the exact same log entries a blocked bb_curl() request would produce --
# not a separate, weaker notion of "filtered". A trailing summary line is
# added on top so the filtering pass itself (not just each individual drop)
# shows up in the audit trail.
#
# Returns is_in_scope's exit status on a hard config error (2 = scope file
# itself missing/unreadable) so callers can distinguish "scope file broken"
# from "every URL happened to be out of scope" (which still exits 0 with an
# empty output file). Truncates <output-file> up front so a failed run
# never leaves a stale prior result lying around to be picked up by mistake.
bb_filter_scope_list() {
    local input_file="$1" output_file="$2" line kept=0 dropped=0 rc=0

    : > "$output_file"
    [ -f "$input_file" ] || return 0

    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*) continue ;;
        esac
        if is_in_scope "$line"; then
            printf '%s\n' "$line" >> "$output_file"
            kept=$(( kept + 1 ))
        else
            rc=$?
            [ "$rc" -eq 2 ] && return 2   # scope file itself is broken -- abort, don't half-filter
            dropped=$(( dropped + 1 ))
        fi
    done < "$input_file"

    _bb_audit_log "[SCOPE-FILTER] input=$input_file output=$output_file kept=$kept dropped=$dropped"
    return 0
}

# ── Internal: required identifying User-Agent suffix ────────────────────────
# Every outbound request this toolkit sends must be identifiable as coming
# from a specific hacker. BBHUNT_USER_AGENT_SUFFIX is required, no default —
# same fail-loud/fail-closed stance as is_in_scope() above, not "send it
# unmarked and hope". Prints the combined "<base> <suffix>" User-Agent value
# on success; prints nothing and returns non-zero if the suffix is unset,
# blank, or contains a CR/LF (which would otherwise corrupt the header or
# smuggle a second header into the request via `curl -H`).
_bb_user_agent() {
    local base="$1" suffix="${BBHUNT_USER_AGENT_SUFFIX:-}"
    if [ -z "$suffix" ]; then
        return 1
    fi
    case "$suffix" in
        *$'\r'*|*$'\n'*) return 1 ;;
    esac
    printf '%s %s\n' "$base" "$suffix"
}

# ── Internal: optional research/attribution header ──────────────────────────
# BBHUNT_RESEARCH_HEADER is genuinely optional, unlike BBHUNT_USER_AGENT_SUFFIX
# above — unset or blank means "attach nothing extra", not an error. Format:
# a single "HeaderName: value" line (e.g. "X-HackerOne-Research: b1tr00t").
#
# If it IS set, it must be well-formed: prints nothing and returns non-zero
# (same signature as _bb_user_agent()) if the value contains a CR/LF (header
# injection guard, same check used for BBHUNT_AUTH_HEADERS and
# BBHUNT_USER_AGENT_SUFFIX) or has no ':' separator / a blank header name.
# Callers treat a non-zero return as "attach nothing" for the unset case,
# but see _bb_curl_impl for how a set-but-malformed value is surfaced loudly
# instead of silently swallowed.
_bb_research_header() {
    local raw="${BBHUNT_RESEARCH_HEADER:-}"
    [ -z "$raw" ] && return 1
    case "$raw" in
        *$'\r'*|*$'\n'*) return 2 ;;
    esac
    case "$raw" in
        *:*) : ;;
        *) return 2 ;;
    esac
    local name="${raw%%:*}"
    name="$(printf '%s' "$name" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [ -z "$name" ] && return 2
    printf '%s\n' "$raw"
    return 0
}

# ── Internal: opt-in Rapyd request signing ──────────────────────────────────
# BBHUNT_RAPYD_SIGN=1 (opt-in, OFF by default) makes bb_curl() automatically
# attach Rapyd's HMAC auth headers (access_key/salt/timestamp/signature) to
# any request whose host is EXACTLY tools/rapyd_sign.py's own hardcoded
# sandbox host — kept as a literal duplicate of that constant, not derived
# from it, since bash can't import the Python module's value directly; if
# rapyd_sign.py's _SANDBOX_API_HOST is ever deliberately changed, this
# constant must be updated to match by hand, on purpose, same as any other
# cross-language duplication in this toolkit.
#
# This is scoped to that ONE host on purpose: a request to api.rapyd.net
# (production) is NEVER signed by this feature, even with BBHUNT_RAPYD_SIGN=1
# set, because tools/rapyd_sign.py's own hardcoded gate refuses to sign
# anything else — see rapyd_sign.py's module docstring, gate #1. Widening
# that is a deliberate, separately-reviewed change to rapyd_sign.py, never a
# side effect of anything in this file.
#
# A request to any OTHER host — including every ordinary bug-bounty target
# this toolkit is normally pointed at — is completely unaffected whether
# BBHUNT_RAPYD_SIGN is set or not: the host check below makes this a no-op
# for anything that isn't the Rapyd sandbox API.
_BB_RAPYD_SANDBOX_HOST="sandboxapi.rapyd.net"

# ── Internal: best-effort method/body extraction from curl-style args ───────
# Rapyd's signature must cover the exact HTTP method and exact body bytes
# being sent, so bb_curl()'s own curl-args (everything after the URL) need
# to be inspected for -X/--request and -d/--data/--data-raw/--data-binary
# before signing. Deliberately narrow: handles the single-occurrence case
# that's the only pattern any current bb_curl call site in this toolkit
# actually uses (checked against every existing call site before writing
# this) — a caller stacking multiple -d flags (curl concatenates those with
# '&') would get an incomplete body here and a signature that doesn't match
# what curl actually sends; there is no such call site today, but a future
# one would need this function extended, not just used as-is.
_bb_extract_method_from_curl_args() {
    local prev=""
    for _bb_a in "$@"; do
        case "$prev" in
            -X|--request) printf '%s\n' "$_bb_a"; return 0 ;;
        esac
        prev="$_bb_a"
    done
    for _bb_a in "$@"; do
        case "$_bb_a" in
            -d|--data|--data-raw|--data-binary|--data-urlencode)
                printf 'POST\n'; return 0 ;;
        esac
    done
    printf 'GET\n'
}

_bb_extract_body_from_curl_args() {
    local prev=""
    for _bb_a in "$@"; do
        case "$prev" in
            -d|--data|--data-raw|--data-binary)
                case "$_bb_a" in
                    @*)
                        # curl's @file syntax -- read the same local file
                        # curl itself would read, so the signed body matches
                        # what curl actually sends on the wire.
                        cat "${_bb_a#@}" 2>/dev/null
                        ;;
                    *)
                        printf '%s' "$_bb_a"
                        ;;
                esac
                return 0
                ;;
        esac
        prev="$_bb_a"
    done
}

# ── _bb_rapyd_sign_headers ───────────────────────────────────────────────────
# _bb_rapyd_sign_headers <url> <method> <body>
# No-op (prints nothing, returns 0) unless BOTH BBHUNT_RAPYD_SIGN=1 AND
# <url>'s host is exactly $_BB_RAPYD_SANDBOX_HOST — every other combination
# (feature off, or feature on but a different host) sends the request
# completely unsigned and unaffected, same as before this feature existed.
#
# Once both of those hold, this is no longer allowed to silently do nothing:
# RAPYD_ACCESS_KEY/RAPYD_SECRET_KEY missing is a hard failure (prints a clear
# error to stderr, returns 2) -- the whole point of making this opt-in is
# that once opted in, a misconfigured environment must never fall back to
# quietly sending an unsigned request against the host it was explicitly
# turned on for.
#
# On success, prints one "Header: value" line per line to stdout (from
# tools/rapyd_sign.py's own `sign-headers` CLI bridge -- the actual HMAC
# math is never reimplemented here) and returns 0.
_bb_rapyd_sign_headers() {
    local url="$1" method="$2" body="$3"

    [ "${BBHUNT_RAPYD_SIGN:-0}" = "1" ] || return 0

    local host
    host="$(_bb_extract_host "$url")"
    [ "$host" = "$_BB_RAPYD_SANDBOX_HOST" ] || return 0

    if [ -z "${RAPYD_ACCESS_KEY:-}" ] || [ -z "${RAPYD_SECRET_KEY:-}" ]; then
        echo "[bb_curl] FATAL — BBHUNT_RAPYD_SIGN=1 but RAPYD_ACCESS_KEY/RAPYD_SECRET_KEY are not both set — refusing to send this request to $host unsigned. export RAPYD_ACCESS_KEY=... RAPYD_SECRET_KEY=... or unset BBHUNT_RAPYD_SIGN." >&2
        _bb_audit_log "[FATAL-RAPYD-SIGN-NO-KEYS] url=$url"
        return 2
    fi

    local tools_dir
    tools_dir="$(dirname "${BASH_SOURCE[0]}")"
    local sign_output
    if ! sign_output="$(python3 "$tools_dir/rapyd_sign.py" sign-headers --method "$method" --url "$url" --body "$body" 2>&1)"; then
        echo "[bb_curl] FATAL — Rapyd request signing failed for $url: $sign_output" >&2
        _bb_audit_log "[FATAL-RAPYD-SIGN-ERROR] url=$url"
        return 2
    fi
    printf '%s\n' "$sign_output"
}

# ── Internal: rate limiting ──────────────────────────────────────────────────
# Per-process minimum-interval enforcement via a global "last request" clock.
# NOTE: this state is a plain shell variable, so it's only shared across
# sequential bb_curl calls within the SAME shell process. It does NOT
# coordinate across parallel subshells/background jobs (e.g. `xargs -P`,
# `&` backgrounding) — each would get its own independent clock and the
# effective aggregate rate could exceed BBHUNT_RATE_LIMIT_RPS. Fine for the
# straight-line sequential use this file is designed for; not a substitute
# for a real cross-process limiter if a caller ever parallelizes bb_curl.
_BB_LAST_REQUEST_NS=0

_bb_rate_limit_wait() {
    local rps="${BBHUNT_RATE_LIMIT_RPS:-2}"

    # Fail safe to the conservative default on bad input rather than
    # disabling rate limiting or erroring out.
    case "$rps" in
        ''|*[!0-9.]*) rps=2 ;;
    esac
    awk -v r="$rps" 'BEGIN { exit !(r > 0) }' || rps=2

    local min_interval_ns now_ns elapsed_ns wait_ns wait_sec
    min_interval_ns=$(awk -v r="$rps" 'BEGIN { printf "%.0f", (1 / r) * 1000000000 }')
    now_ns=$(date +%s%N)

    if [ "$_BB_LAST_REQUEST_NS" != "0" ]; then
        elapsed_ns=$(( now_ns - _BB_LAST_REQUEST_NS ))
        if [ "$elapsed_ns" -lt "$min_interval_ns" ]; then
            wait_ns=$(( min_interval_ns - elapsed_ns ))
            wait_sec=$(awk -v ns="$wait_ns" 'BEGIN { printf "%.3f", ns / 1000000000 }')
            sleep "$wait_sec"
        fi
    fi

    _BB_LAST_REQUEST_NS=$(date +%s%N)
}

# ── Public: rate-limit wait only, no request ─────────────────────────────────
# For callers that measure precise request timing (e.g. SQLi time-based
# blind detection) and must not have the rate-limit sleep land inside their
# measured window. Call this explicitly BEFORE capturing the start
# timestamp, then fire the request with bb_curl_no_wait() (not bb_curl())
# so the wait isn't applied a second time.
bb_rate_limit_wait() {
    _bb_rate_limit_wait
}

# ── Internal: shared implementation behind bb_curl / bb_curl_no_wait /
#    bb_curl_no_auth ──────────────────────────────────────────────────────────
# _bb_curl_impl <do_rate_limit:0|1> <do_auth:0|1> <url> [curl-args...]
# All three public entry points delegate here so scope-checking, logging,
# and the curl invocation itself stay in exactly one place — only whether
# the rate-limit wait and auth-header attachment happen is parameterized.
_bb_curl_impl() {
    local do_rate_limit="$1" do_auth="$2"
    shift 2
    local url="$1"
    if [ -z "$url" ]; then
        echo "[bb_curl] usage: bb_curl <url> [curl-args...]" >&2
        return 2
    fi
    shift

    local scope_rc
    is_in_scope "$url"
    scope_rc=$?
    if [ "$scope_rc" -ne 0 ]; then
        echo "[bb_curl] BLOCKED — $url is not in scope (see BBHUNT_SCOPE_FILE / audit log)" >&2
        return "$scope_rc"
    fi

    local user_agent
    if ! user_agent="$(_bb_user_agent "agentic-bug-hunter/bb_curl")"; then
        echo "[bb_curl] FATAL — BBHUNT_USER_AGENT_SUFFIX is not set (or contains a CR/LF) — refusing to send an unmarked request. export BBHUNT_USER_AGENT_SUFFIX='yourhandle (+https://hackerone.com/yourhandle)'" >&2
        _bb_audit_log "[FATAL-NO-USER-AGENT-SUFFIX] BBHUNT_USER_AGENT_SUFFIX unset or invalid, url=$url"
        return 2
    fi

    local -a research_args=()
    local research_header research_rc
    research_header="$(_bb_research_header)"
    research_rc=$?
    if [ "$research_rc" -eq 0 ]; then
        research_args+=(-H "$research_header")
    elif [ "$research_rc" -eq 2 ]; then
        # Set but malformed (CR/LF, no ':' separator, or blank header name)
        # -- surfaced loudly rather than silently sending the request
        # without the header the operator explicitly asked for.
        echo "[bb_curl] FATAL — BBHUNT_RESEARCH_HEADER is set but invalid (expected 'HeaderName: value', no CR/LF): ${BBHUNT_RESEARCH_HEADER:-}" >&2
        _bb_audit_log "[FATAL-BAD-RESEARCH-HEADER] BBHUNT_RESEARCH_HEADER invalid, url=$url"
        return 2
    fi
    # research_rc == 1: unset/blank -- attach nothing, not an error.

    [ "$do_rate_limit" = "1" ] && _bb_rate_limit_wait

    local -a rapyd_sign_args=()
    local rapyd_sign_output rapyd_sign_rc
    rapyd_sign_output="$(_bb_extract_method_from_curl_args "$@")"
    local rapyd_method="$rapyd_sign_output"
    rapyd_sign_output="$(_bb_rapyd_sign_headers "$url" "$rapyd_method" "$(_bb_extract_body_from_curl_args "$@")")"
    rapyd_sign_rc=$?
    if [ "$rapyd_sign_rc" -ne 0 ]; then
        return "$rapyd_sign_rc"
    fi
    if [ -n "$rapyd_sign_output" ]; then
        while IFS= read -r _bb_rs_line; do
            [ -z "$_bb_rs_line" ] && continue
            rapyd_sign_args+=(-H "$_bb_rs_line")
        done <<< "$rapyd_sign_output"
    fi

    local -a auth_args=()
    if [ "$do_auth" = "1" ] && [ -n "${BBHUNT_AUTH_HEADERS:-}" ]; then
        local _bb_h
        while IFS= read -r _bb_h; do
            case "$_bb_h" in
                ''|'#'*) continue ;;
            esac
            # Reject headers containing CR — same injection guard used by
            # _auth_helper.sh, applied independently here so bb_curl.sh has
            # no hard dependency on that file being sourced first.
            case "$_bb_h" in
                *$'\r'*) continue ;;
            esac
            auth_args+=(-H "$_bb_h")
        done <<< "$BBHUNT_AUTH_HEADERS"
    fi

    if [ "${#research_args[@]}" -gt 0 ]; then
        _bb_audit_log "[REQUEST] url=$url ua=$user_agent research_header=${research_args[1]}"
    else
        _bb_audit_log "[REQUEST] url=$url ua=$user_agent"
    fi

    curl -H "User-Agent: $user_agent" "${auth_args[@]}" "${research_args[@]}" "${rapyd_sign_args[@]}" "$url" "$@"
}

# ── bb_curl ───────────────────────────────────────────────────────────────────
# bb_curl <url> [curl-args...]
# Scope-checks, rate-limits, attaches auth headers, runs curl, logs the
# request. Returns curl's own exit status on success; 1 if blocked out of
# scope; 2 if BBHUNT_SCOPE_FILE itself is misconfigured (propagated from
# is_in_scope). This is the default, unchanged entry point — most callers
# should use this one.
bb_curl() {
    _bb_curl_impl 1 1 "$@"
}

# ── bb_curl_no_wait ───────────────────────────────────────────────────────────
# bb_curl_no_wait <url> [curl-args...]
# Same as bb_curl(), but skips its own internal rate-limit wait. Pair with
# an explicit bb_rate_limit_wait() call made BEFORE starting a timing
# measurement — see the comment on bb_rate_limit_wait() above. Calling this
# without a preceding bb_rate_limit_wait() does NOT rate-limit the request
# at all; that responsibility moves to the caller.
bb_curl_no_wait() {
    _bb_curl_impl 0 1 "$@"
}

# ── bb_curl_no_auth ───────────────────────────────────────────────────────────
# bb_curl_no_auth <url> [curl-args...]
# Same as bb_curl(), but never attaches BBHUNT_AUTH_HEADERS, even if set.
# For probes that must stay deliberately unauthenticated (e.g. checking
# whether an endpoint is reachable without credentials) rather than callers
# that simply have no auth session configured — bb_curl() already omits
# headers on its own when BBHUNT_AUTH_HEADERS is unset.
bb_curl_no_auth() {
    _bb_curl_impl 1 0 "$@"
}

# ── bb_curl_no_wait_no_auth ───────────────────────────────────────────────────
# bb_curl_no_wait_no_auth <url> [curl-args...]
# Combines bb_curl_no_wait() and bb_curl_no_auth(): skips both the internal
# rate-limit wait and auth-header attachment. For a deliberate, rapid,
# unauthenticated burst where the burst's own speed is what's being tested
# (e.g. firing N rapid guesses to check whether a target rate-limits them) —
# pacing between the individual requests in the burst would invalidate the
# test, and the burst is inherently unauthenticated (testing a pre-auth
# attacker's surface). Call bb_rate_limit_wait() ONCE before the burst
# starts if you want normal pacing relative to whatever ran immediately
# before it — the requests inside the burst itself should not each wait.
bb_curl_no_wait_no_auth() {
    _bb_curl_impl 0 0 "$@"
}

# ── bb_response_signature ────────────────────────────────────────────────────
# bb_response_signature <url> [curl-fn]
# Prints "STATUS:SIZE" for one GET (e.g. "200:1127"), via [curl-fn] if
# given (default bb_curl_no_auth). Used by bb_catchall_baseline() /
# bb_matches_baseline() below to compare whether two different paths on
# the same host are actually distinguishable, or just the same canned
# response. [curl-fn] exists so a caller that probes WITH auth headers
# (bb_curl, not bb_curl_no_auth -- e.g. recon_engine.sh's Phase 5/6.5)
# can build its baseline the same way it builds its actual probes; an
# unauthenticated baseline compared against authenticated probe results
# would be comparing two different things.
bb_response_signature() {
    local url="$1" curl_fn="${2:-bb_curl_no_auth}"
    "$curl_fn" "$url" -sk --max-time 10 -o /dev/null -w '%{http_code}:%{size_download}' 2>/dev/null \
        || printf '000:0\n'
}

# ── bb_catchall_baseline ────────────────────────────────────────────────────
# bb_catchall_baseline <base-url> [curl-fn]
# Prints the STATUS:SIZE signature (see bb_response_signature above) of a
# deliberately nonexistent path on <base-url>. Fetch this ONCE per host,
# before probing any specific paths on it, and compare each probed path's
# own signature against this baseline with bb_matches_baseline() below.
#
# Earlier version of this fix compared each probed path against the
# host's ROOT path ("/") instead of a second nonexistent path, as a
# one-time per-host go/no-go check. That was wrong and caught by testing
# it against a real (if synthetic) normally-routed host before shipping:
# a host that simply has no index page at "/" — genuinely common, e.g.
# an API-only backend — 404s at root exactly like a nonexistent path
# does, which made that version flag every such host as "catchall" and
# skip it entirely, including any real, distinct, genuinely-vulnerable
# path it might have. Comparing one nonexistent path against another
# nonexistent path (both of which SHOULD produce the same "not found"
# signature on any normally-routed host) and then checking each probed
# path against THAT baseline — rather than blanket-skipping a whole host
# based on one aggregate guess — only ever discards a specific probed
# path when its own response is indistinguishable from a path that
# provably doesn't exist, and never discards a path that responds
# differently, no matter what the host's root does.
bb_catchall_baseline() {
    local base_url="${1%/}" curl_fn="${2:-bb_curl_no_auth}"
    local nonce="non_existent_$(date +%s)_$RANDOM"
    bb_response_signature "${base_url}/${nonce}" "$curl_fn"
}

# ── bb_matches_baseline ─────────────────────────────────────────────────────
# bb_matches_baseline <url> <baseline-signature> [curl-fn]
# True (exit 0) if <url>'s own response signature exactly matches
# <baseline-signature> (from bb_catchall_baseline(), fetched once per host,
# with the same [curl-fn] passed to both calls) — i.e. this specific path's
# response is indistinguishable from a path that's confirmed not to exist,
# so a 200/301/302/403/whatever here is not evidence the path means
# anything, only that this host answers every path the same way. Confirmed
# against three real, structurally different catch-all patterns in one
# engagement: a client-routed SPA returning its index shell for any path
# (200), a backend API that ignores the path entirely (200, same JSON body
# regardless), and a host applying the same blanket redirect to every path
# (301/302). Callers that also need the status code itself (not just the
# yes/no match) should call bb_response_signature() directly and derive
# both from one fetch, the way Check 0/Check 9 in vuln_scanner.sh do,
# rather than fetching the same URL twice via this wrapper.
bb_matches_baseline() {
    local url="$1" baseline="$2" curl_fn="${3:-bb_curl_no_auth}"
    [ "$(bb_response_signature "$url" "$curl_fn")" = "$baseline" ]
}
