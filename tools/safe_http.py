"""Redirect-safe wrapper around urllib.request.urlopen. Plain urlopen
follows 3xx redirects with no check on the destination — a hostile target
can 302 a scanner into cloud metadata (169.254.169.254), localhost, or an
RFC1918 address, turning the tool into an SSRF proxy against the
operator's own network. See SECURITY-REVIEW-2026-08-22.md finding #8.

Also enforces the same BBHUNT_SCOPE_FILE scope check, BBHUNT_AUDIT_LOG
audit trail, and BBHUNT_RATE_LIMIT_RPS rate limit as tools/bb_curl.sh --
ported deliberately (not reimplemented independently) so a scope file
produces identical accept/reject decisions regardless of whether a bash
tool or a Python tool processes a URL. is_in_scope() mirrors bb_curl.sh's
is_in_scope() line for line: same fail-loud/fail-closed behavior on an
unset/missing scope file, same suffix-anchored wildcard matching
("*.example.com" covers any-depth subdomains but never the bare apex).

Unlike bb_curl.sh, safe_urlopen() drives redirect hops itself, so the
scope check and rate limit apply to EVERY hop, not just the first --
closing a gap bb_curl.sh can't (curl -L would follow redirects with no
per-hop scope re-check at all)."""
from __future__ import annotations

import ipaddress
import os
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal"}


def _is_blocked_redirect_target(hostname: str) -> bool:
    if not hostname:
        return True
    if hostname.lower() in ("localhost",) or hostname.lower() in _METADATA_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            addr = ipaddress.ip_address(socket.gethostbyname(hostname))
        except (socket.gaierror, ValueError):
            return False  # can't resolve — let the real request fail naturally
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast
    )


def is_private_or_internal_host(hostname: str) -> bool:
    """Public wrapper around the same private/loopback/link-local/reserved/
    multicast/metadata-host classification the SSRF redirect-target guard
    already uses internally (_is_blocked_redirect_target, unchanged, still
    the sole implementation). Exposed for callers outside this module that
    need the identical IP-range logic -- e.g. an SSRF scanner inspecting a
    target's own redirect Location header -- without reimplementing it."""
    return _is_blocked_redirect_target(hostname)


# =============================================================================
# Scope check, audit log, rate limit — ported from tools/bb_curl.sh so both
# toolchains share one scope file, one audit log, and identical accept/reject
# behavior for the same URL. See that file for the canonical bash version;
# is_in_scope() below is a deliberate line-for-line port of its matching
# logic, not an independent reimplementation.
# =============================================================================

def _audit_log(msg: str) -> None:
    """Append one UTC-timestamped line to BBHUNT_AUDIT_LOG (default
    logs/audit.log), matching bb_curl.sh's _bb_audit_log() format exactly
    so entries from both toolchains interleave in one readable log."""
    log_file = os.environ.get("BBHUNT_AUDIT_LOG") or "logs/audit.log"
    log_dir = os.path.dirname(log_file)
    if log_dir:
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError:
            pass
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(f"{timestamp} {msg}\n")
    except OSError:
        pass


def is_in_scope(url: str) -> bool:
    """Fail-loud, fail-closed scope check — identical behavior to
    is_in_scope() in tools/bb_curl.sh:

      - BBHUNT_SCOPE_FILE unset, or the path it names doesn't exist/isn't
        readable -> hard refusal (never "allow everything").
      - Scope file lines: '#' comments and blank lines skipped; a bare
        line ("example.com") matches ONLY that exact host; a wildcard
        line ("*.example.com") matches any subdomain at any depth
        (foo.example.com, a.b.example.com) via an anchored suffix check,
        but deliberately NOT the bare apex — list the apex on its own
        line too if it's also in scope. Matching is case-insensitive;
        both host and pattern have a trailing FQDN dot stripped.
      - A URL that has no BLOCKED-OUT-OF-SCOPE / FATAL log entry does
        NOT mean this call passed silently: every rejection path writes
        to the shared audit log before returning False.
    """
    scope_file = os.environ.get("BBHUNT_SCOPE_FILE") or ""
    if not scope_file:
        _audit_log(f"[FATAL-NO-SCOPE-FILE] BBHUNT_SCOPE_FILE unset, url={url}")
        return False
    if not os.path.isfile(scope_file) or not os.access(scope_file, os.R_OK):
        _audit_log(f"[FATAL-NO-SCOPE-FILE] BBHUNT_SCOPE_FILE={scope_file} unreadable, url={url}")
        return False

    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    if not host:
        _audit_log(f"[BLOCKED-BAD-URL] could not extract host, url={url}")
        return False

    try:
        with open(scope_file, encoding="utf-8", errors="replace") as fh:
            scope_lines = fh.readlines()
    except OSError:
        _audit_log(f"[FATAL-NO-SCOPE-FILE] BBHUNT_SCOPE_FILE={scope_file} unreadable, url={url}")
        return False

    for raw_line in scope_lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        pattern = line.lower().rstrip(".")
        if pattern.startswith("*."):
            base = pattern[2:]
            if host.endswith("." + base):
                return True
        elif host == pattern:
            return True

    _audit_log(f"[BLOCKED-OUT-OF-SCOPE] host={host} url={url} scope_file={scope_file}")
    return False


_last_request_monotonic: float | None = None


def _rate_limit_wait() -> None:
    """Sleep out whatever's left of the minimum inter-request interval
    (1 / BBHUNT_RATE_LIMIT_RPS, default 2 rps — same default as
    bb_curl.sh's _bb_rate_limit_wait()). Process-local state, same
    per-process (not cross-process) caveat as the bash version."""
    global _last_request_monotonic
    rps_raw = os.environ.get("BBHUNT_RATE_LIMIT_RPS", "2")
    try:
        rps = float(rps_raw)
        if rps <= 0:
            rps = 2.0
    except ValueError:
        rps = 2.0

    min_interval = 1.0 / rps
    now = time.monotonic()
    if _last_request_monotonic is not None:
        elapsed = now - _last_request_monotonic
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
    _last_request_monotonic = time.monotonic()


def _one_hop(req: urllib.request.Request, timeout: float, **kwargs):
    # OpenerDirector.open() (used below) does NOT accept a context=
    # kwarg — only the module-level urllib.request.urlopen() does. Callers
    # that pass context=<ssl.SSLContext>, expecting the same behavior as
    # passing it straight to urlopen(), would otherwise hit a TypeError on
    # every single call. Bind the SSL context to the opener itself via an
    # HTTPSHandler instead of forwarding it as a kwarg to .open().
    context = kwargs.pop("context", None)
    handlers = [_NoRedirectHandler]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    try:
        return opener.open(req, timeout=timeout, **kwargs)
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            # _NoRedirectHandler.redirect_request returning None makes every
            # installed redirect handler decline, so urllib's chain falls
            # through to HTTPDefaultErrorHandler, which raises HTTPError
            # instead of returning the response. HTTPError doubles as a
            # response object (.status/.code, .headers) — hand it back to
            # the caller's redirect-driving loop instead of letting it
            # propagate as an error.
            return e
        raise


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # never auto-follow; safe_urlopen drives redirects itself


def safe_urlopen(
    req: urllib.request.Request,
    timeout: float = 10,
    max_redirects: int = 5,
    follow_redirects: bool = True,
    **kwargs,
):
    """Like urllib.request.urlopen(req), but validates every redirect hop's
    hostname before following it, rejecting private/loopback/link-local/
    metadata addresses.

    Extra keyword arguments are forwarded to the underlying opener on
    every hop, so callers that pass a custom SSL context to urlopen()
    keep that behavior unchanged. context=<ssl.SSLContext> is handled
    specially by _one_hop: OpenerDirector.open() doesn't accept a
    context= kwarg the way module-level urlopen() does, so it's bound to
    an HTTPSHandler on the opener instead of being forwarded as-is.

    follow_redirects=False (default True): fire exactly one request and
    return its response as-is, 3xx included, without inspecting or
    validating any Location header. This is a genuinely different mode,
    not a weaker version of the default -- callers that need to observe a
    server's raw redirect response (e.g. an open-redirect scanner reading
    the Location header itself) need the single hop to actually complete
    rather than being silently followed and hidden by this wrapper. Scope
    check and rate limit still apply to that one request; the SSRF
    redirect-target guard doesn't apply here because no redirect is ever
    followed in this mode -- there's nothing for it to guard."""
    if not follow_redirects:
        if not is_in_scope(req.full_url):
            raise urllib.error.URLError(
                f"blocked out of scope (BBHUNT_SCOPE_FILE guard): {req.full_url!r}"
            )
        _rate_limit_wait()
        return _one_hop(req, timeout, **kwargs)

    current = req
    for _ in range(max_redirects + 1):
        if not is_in_scope(current.full_url):
            raise urllib.error.URLError(
                f"blocked out of scope (BBHUNT_SCOPE_FILE guard): {current.full_url!r}"
            )
        _rate_limit_wait()
        resp = _one_hop(current, timeout, **kwargs)
        if resp.status not in (301, 302, 303, 307, 308):
            return resp
        location = resp.headers.get("Location")
        if not location:
            return resp
        next_url = urljoin(current.full_url, location)
        hostname = urlparse(next_url).hostname
        if _is_blocked_redirect_target(hostname):
            raise urllib.error.URLError(
                f"blocked redirect to disallowed host (SSRF guard): {hostname!r}"
            )
        preserve_body = resp.status in (307, 308)
        current = urllib.request.Request(
            next_url,
            data=current.data if preserve_body else None,
            headers=dict(current.header_items()),
            method=current.get_method() if preserve_body else None,
        )
    raise urllib.error.URLError(f"too many redirects (>{max_redirects})")
