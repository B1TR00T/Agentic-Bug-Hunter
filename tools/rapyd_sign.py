"""tools/rapyd_sign.py — Rapyd REST API request-signing (HMAC-SHA256).

Implements Rapyd's official request-signature scheme. The algorithm below
is NOT reconstructed from memory -- it is a line-for-line port of Rapyd's
own reference implementation, cross-checked against two other official
language samples and against docs.rapyd.net's own description before a
single line of this file was written:

  - sign-node.js, sign.php, sign.java, all three fetched verbatim from
    Rapyd-Samples/rapyd-api-signature-snippets (the actual code-sample
    repo -- RapydPayments/rapyd-request-signatures, which this task first
    pointed at, turned out to hold only a purpose-statement README with no
    algorithm detail, and that repo's own README example is missing the
    salt parameter and uses a wrong function signature, so it was
    deliberately NOT used as a basis for anything here). All three agree
    exactly on every step below.
  - docs.rapyd.net/en/request-signatures.html, confirming header names,
    salt/timestamp format, and explicitly that http_method is lower-cased.
  - tools/testdata/sign-node.js holds that fetched Node sample verbatim,
    unedited, so tests/test_rapyd_sign.py can run the REAL official code
    (via a local `node` binary) as its cross-validation oracle instead of
    trusting a second manual transcription of the algorithm.

Algorithm (identical across all three official samples):

    body_string = ""  if body is empty/None (deliberately NOT "{}")
                  else the exact JSON body string being sent on the wire

    to_sign   = http_method.lower() + url_path + salt + str(timestamp)
                + access_key + secret_key + body_string

    digest    = HMAC-SHA256(key=secret_key, msg=to_sign)      # raw bytes
    hex_str   = digest.hex()                                   # lowercase
                                                                # hex STRING
    signature = base64.b64encode(hex_str.encode("ascii"))      # b64 of the
                                                                # HEX STRING,
                                                                # NOT of the
                                                                # raw digest
                                                                # bytes --
                                                                # the one
                                                                # detail
                                                                # every naive
                                                                # reimplementation
                                                                # gets wrong.

url_path per docs.rapyd.net includes the query string when the request
has one (path + "?" + query), never the scheme/host.

This module deliberately takes body as an already-serialized string (the
exact bytes the caller is about to send), not a dict it would re-encode
itself -- Rapyd's server hashes the raw bytes it receives, so re-encoding
a dict here (with Python's own key-ordering/whitespace choices) could
silently produce a signature that doesn't match what was actually sent.
Callers own serializing their own request body; this module only signs
the exact string handed to it.

Headers sent on the real request: access_key, salt, timestamp, signature.

Safety gates (both hard, code-level -- not comments, not reminders):

  1. Sandbox-only. build_signed_request()/signed_request() refuse to
     construct or send anything whose target host isn't exactly
     _SANDBOX_API_HOST. This check runs BEFORE anything else in either
     function -- before an env var is even read -- so a copy-paste
     mistake (a stray api.rapyd.net URL) cannot get far enough to touch a
     real key or sign anything, let alone send it. There is no parameter
     or env var that disables this; widening it to production is a
     deliberate future edit to this file and its docstring, reviewed on
     its own, never a runtime flag.

  2. Keys never appear as plain, loggable function arguments. sign() and
     everything built on it take NO access_key/secret_key parameters --
     they read RAPYD_ACCESS_KEY / RAPYD_SECRET_KEY from the environment
     themselves, at call time, and never pass either value to anything
     that logs its arguments (safe_http._audit_log() calls made from this
     module log the URL/method/salt/timestamp only, exactly like every
     other tool in this toolkit -- never the key or the signature). The
     one function that *does* take key values as plain arguments,
     _compute_signature(), is a private, pure, no-env/no-network helper
     that exists solely so tests/test_rapyd_sign.py can feed it fixture
     values (public test vectors, never a real secret) and diff its
     output against the real official implementation byte-for-byte.

  3. Reuses, rather than reimplements, this toolkit's existing safety
     gates: build_signed_request() returns a urllib.request.Request that
     signed_request() fires through safe_http.safe_urlopen() -- the same
     BBHUNT_SCOPE_FILE scope check, BBHUNT_AUDIT_LOG audit trail,
     BBHUNT_RATE_LIMIT_RPS rate limit, and BBHUNT_USER_AGENT_SUFFIX
     attribution requirement every other tool in this toolkit already
     goes through. The sandbox-host gate above is *additional* to that,
     not a replacement for it -- BBHUNT_SCOPE_FILE must also list
     sandboxapi.rapyd.net or the request is still blocked.
"""
from __future__ import annotations

import base64
import hmac
import os
import random
import string
import sys
import time
import urllib.request
from hashlib import sha256
from urllib.parse import urlparse

import safe_http  # tools/safe_http.py — same directory; reused, not reimplemented

# ─────────────────────────────────────────────────────────────────────────
# Hardcoded sandbox-only gate. Not a default, not a suggestion in a
# comment — the ONE host this module will ever sign or send a request
# for. Confirmed earlier this engagement (GET /v1/checkout/client/{token}
# testing) as Rapyd's real sandbox API hostname.
# ─────────────────────────────────────────────────────────────────────────
_SANDBOX_API_HOST = "sandboxapi.rapyd.net"


class SandboxOnlyViolation(RuntimeError):
    """Raised when something asked this module to build or send a signed
    request against a host other than _SANDBOX_API_HOST. No parameter,
    env var, or call path bypasses this — widening it to production is a
    deliberate edit to the constant above, reviewed on its own."""


class MissingKeyError(RuntimeError):
    """RAPYD_ACCESS_KEY or RAPYD_SECRET_KEY is unset/blank in the
    environment at sign time. Never falls back to a hardcoded/default
    key."""


def _require_sandbox_host(url: str) -> str:
    """Hard gate: return the lower-cased hostname if it's exactly
    _SANDBOX_API_HOST, else raise SandboxOnlyViolation. Called first —
    before any key is read or any signing math runs — by every function
    in this module that ever sees a full target URL."""
    host = (urlparse(url).hostname or "").lower()
    if host != _SANDBOX_API_HOST:
        raise SandboxOnlyViolation(
            f"refusing to build/send a signed request against {host!r} — "
            f"this module only ever signs requests for {_SANDBOX_API_HOST!r}. "
            "There is no override; widening this is a deliberate source "
            "change to tools/rapyd_sign.py, not a runtime flag."
        )
    return host


def _compute_signature(
    method: str,
    url_path: str,
    salt: str,
    timestamp: int | str,
    access_key: str,
    secret_key: str,
    body: str = "",
) -> str:
    """Pure, private, no env/no network. The exact algorithm from
    sign-node.js / sign.php / sign.java, all three agreeing:

        to_sign = method.lower() + url_path + salt + str(timestamp)
                  + access_key + secret_key + body

        signature = base64( HMAC_SHA256(key=secret_key, msg=to_sign).hexdigest() )

    Takes access_key/secret_key as plain arguments deliberately — this is
    the one function in this module meant to be called with fixture/test
    values by tests/test_rapyd_sign.py, never with a real secret. Every
    real-request code path (sign(), build_signed_request(),
    signed_request()) calls this internally but never exposes key
    parameters of its own; see the module docstring, gate #2.
    """
    body_string = body if body else ""
    to_sign = (
        method.lower()
        + url_path
        + str(salt)
        + str(timestamp)
        + access_key
        + secret_key
        + body_string
    )
    digest_hex = hmac.new(
        secret_key.encode("utf-8"), to_sign.encode("utf-8"), sha256
    ).hexdigest()
    return base64.b64encode(digest_hex.encode("ascii")).decode("ascii")


def _generate_salt(length: int | None = None) -> str:
    """Random 8-16 char alphanumeric string, per docs.rapyd.net. A fresh
    salt must be generated per request — never reused, never cached."""
    n = length if length is not None else random.randint(8, 16)
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def _read_env_keys() -> tuple[str, str]:
    """Read RAPYD_ACCESS_KEY / RAPYD_SECRET_KEY from the environment.
    Raises MissingKeyError (naming which var is missing, never the value
    of the other one) if either is unset or blank. This is the ONLY place
    in this module that touches these env vars."""
    access_key = os.environ.get("RAPYD_ACCESS_KEY", "").strip()
    secret_key = os.environ.get("RAPYD_SECRET_KEY", "").strip()
    if not access_key:
        raise MissingKeyError("RAPYD_ACCESS_KEY is not set (or blank) in the environment")
    if not secret_key:
        raise MissingKeyError("RAPYD_SECRET_KEY is not set (or blank) in the environment")
    return access_key, secret_key


def sign(method: str, url_path: str, body: str = "") -> dict[str, str]:
    """Build the four Rapyd auth headers for one request. Reads the real
    access/secret key straight from the environment (RAPYD_ACCESS_KEY /
    RAPYD_SECRET_KEY) — takes NO key parameters of its own, so a real key
    never appears in this function's arguments, a traceback, or a log
    line. Generates a fresh salt and current Unix timestamp every call.

    `url_path` must be exactly the path (+ "?query" if any) that will be
    requested, no scheme/host. `body` must be exactly the string that
    will be sent as the request body ("" for none) — see the module
    docstring for why this is a string, not a dict this function would
    re-encode itself.

    Returns {"access_key", "salt", "timestamp", "signature"} — attach all
    four as headers on the outgoing request.
    """
    access_key, secret_key = _read_env_keys()
    salt = _generate_salt()
    timestamp = str(int(time.time()))
    signature = _compute_signature(
        method, url_path, salt, timestamp, access_key, secret_key, body
    )
    return {
        "access_key": access_key,
        "salt": salt,
        "timestamp": timestamp,
        "signature": signature,
    }


def build_signed_request(method: str, url: str, body: str = "") -> urllib.request.Request:
    """Build a fully-headed, signed urllib.request.Request for `url` —
    but ONLY if `url`'s host is exactly _SANDBOX_API_HOST (gate #1, checked
    first, before sign() is ever called). Attaches the four Rapyd auth
    headers from sign(), plus this toolkit's required identifying
    User-Agent (safe_http.build_user_agent — same
    BBHUNT_USER_AGENT_SUFFIX requirement as every other tool here) and the
    optional BBHUNT_RESEARCH_HEADER (safe_http.build_research_headers).

    Does NOT send anything — fire the result through
    safe_http.safe_urlopen() yourself, or use signed_request() below,
    which does exactly that (scope check + rate limit + redirect guard
    included).
    """
    _require_sandbox_host(url)  # gate #1 — before sign() touches any key

    parsed = urlparse(url)
    url_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")

    headers = sign(method, url_path, body)
    headers["User-Agent"] = safe_http.build_user_agent("agentic-bug-hunter/rapyd_sign")
    headers.update(safe_http.build_research_headers())
    if body:
        headers.setdefault("Content-Type", "application/json")

    data = body.encode("utf-8") if body else None
    return urllib.request.Request(url, data=data, headers=headers, method=method.upper())


def signed_request(method: str, url: str, body: str = "", timeout: float = 10):
    """Build (build_signed_request — sandbox-host gate included) and fire
    a signed request through safe_http.safe_urlopen(), so it gets the
    same BBHUNT_SCOPE_FILE scope check, BBHUNT_AUDIT_LOG audit trail,
    BBHUNT_RATE_LIMIT_RPS rate limit, and redirect-target SSRF guard as
    every other request this toolkit sends. The sandbox-host gate here is
    additional to, not a replacement for, the scope file — the scope file
    must ALSO list sandboxapi.rapyd.net or safe_urlopen's own
    is_in_scope() check will still block it.
    """
    req = build_signed_request(method, url, body)
    return safe_http.safe_urlopen(req, timeout=timeout)


# ─────────────────────────────────────────────────────────────────────────
# CLI bridge — lets bb_curl.sh (bash) get signed headers without needing a
# Python-to-bash binding of its own. Deliberately the ONLY way this
# module is driven from outside a Python import: prints headers to
# stdout, never touches the network itself, and never accepts a key on
# argv (still env-only — see gate #2 above; this CLI mode doesn't change
# that, it just gives bash a way to invoke the same env-only sign()).
#
#   python3 rapyd_sign.py sign-headers --method GET --url <url> [--body S | --body-file F]
#
# Exit codes (bb_curl.sh's _bb_rapyd_sign_headers() branches on these):
#   0 — success, one "Header: value" line per header on stdout.
#   1 — SandboxOnlyViolation (wrong host).
#   2 — MissingKeyError (RAPYD_ACCESS_KEY/RAPYD_SECRET_KEY unset) or a
#       usage error. Distinguished from 1 the same way bb_curl.sh's own
#       is_in_scope() distinguishes "blocked" (1) from "hard config
#       error" (2), so callers can tell "wrong host, expected" apart
#       from "misconfigured, fix your environment".
# ─────────────────────────────────────────────────────────────────────────

def _cli_sign_headers(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="rapyd_sign.py sign-headers",
        description="Print the four Rapyd auth headers for one request, "
        "reading RAPYD_ACCESS_KEY/RAPYD_SECRET_KEY from the environment. "
        "Sandbox-host gate applies exactly as it does to build_signed_request().",
    )
    parser.add_argument("--method", required=True)
    parser.add_argument("--url", required=True)
    body_group = parser.add_mutually_exclusive_group()
    body_group.add_argument("--body", default=None, help="Exact request body string, if any.")
    body_group.add_argument(
        "--body-file",
        default=None,
        help="Read the exact request body from this file instead of --body "
        "(for a body too large/awkward to pass as one argv string).",
    )
    args = parser.parse_args(argv)

    if args.body_file:
        try:
            with open(args.body_file, "r", encoding="utf-8") as fh:
                body = fh.read()
        except OSError as exc:
            print(f"rapyd_sign.py: cannot read --body-file {args.body_file!r}: {exc}", file=sys.stderr)
            return 2
    else:
        body = args.body or ""

    try:
        _require_sandbox_host(args.url)
    except SandboxOnlyViolation as exc:
        print(f"rapyd_sign.py: {exc}", file=sys.stderr)
        return 1

    try:
        headers = sign(args.method, urlparse(args.url).path + (
            f"?{urlparse(args.url).query}" if urlparse(args.url).query else ""
        ), body)
    except MissingKeyError as exc:
        print(f"rapyd_sign.py: {exc}", file=sys.stderr)
        return 2

    for name, value in headers.items():
        print(f"{name}: {value}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "sign-headers":
        sys.exit(_cli_sign_headers(sys.argv[2:]))
    print("usage: rapyd_sign.py sign-headers --method M --url U [--body S | --body-file F]", file=sys.stderr)
    sys.exit(2)
