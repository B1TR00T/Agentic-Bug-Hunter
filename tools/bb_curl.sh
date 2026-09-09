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
#   export BBHUNT_RATE_LIMIT_RPS=2                          # optional, default 2
#   export BBHUNT_AUDIT_LOG="logs/audit.log"                # optional, default shown
#   export BBHUNT_AUTH_HEADERS=$'Authorization: Bearer xyz\nX-Custom: val'  # optional
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
#                          curl with BBHUNT_AUTH_HEADERS attached. Logs every
#                          request it actually sends, and every request it
#                          blocks, to the audit log.
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

# ── bb_curl ───────────────────────────────────────────────────────────────────
# bb_curl <url> [curl-args...]
# Scope-checks, rate-limits, attaches auth headers, runs curl, logs the
# request. Returns curl's own exit status on success; 1 if blocked out of
# scope; 2 if BBHUNT_SCOPE_FILE itself is misconfigured (propagated from
# is_in_scope).
bb_curl() {
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

    _bb_rate_limit_wait

    local -a auth_args=()
    if [ -n "${BBHUNT_AUTH_HEADERS:-}" ]; then
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

    _bb_audit_log "[REQUEST] url=$url"

    curl "${auth_args[@]}" "$url" "$@"
}
