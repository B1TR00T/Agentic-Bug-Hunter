"""Tests for bb_curl.sh's opt-in Rapyd request-signing wiring
(BBHUNT_RAPYD_SIGN=1 -> tools/rapyd_sign.py's `sign-headers` CLI bridge).

No live network calls anywhere in this file. Every test that exercises the
full bb_curl() path (not just the header-generation helper in isolation)
does so against a fake `curl` shim prepended to PATH that dumps its argv to
a file instead of making a request -- the same "stub the external tool"
technique tests/test_recon_engine_cve_phase.py already uses for
cve_lookup.py, applied here to curl itself so even a "success" test case
never reaches the network.

Covers all four states the wiring can be in:
  1. BBHUNT_RAPYD_SIGN unset/0            -> no-op, regardless of host.
  2. BBHUNT_RAPYD_SIGN=1, non-sandbox host -> no-op (production/other hosts
     are never touched by this feature -- see rapyd_sign.py's own hardcoded
     sandbox-only gate, kept in force by design).
  3. BBHUNT_RAPYD_SIGN=1, sandbox host, keys missing -> hard failure, curl
     is NEVER invoked (fails clearly and early, never falls back to
     sending unsigned).
  4. BBHUNT_RAPYD_SIGN=1, sandbox host, keys present -> curl IS invoked,
     with the four Rapyd headers attached, matching what
     rapyd_sign._compute_signature() independently computes for the same
     inputs.
"""

import os
import re
import stat
import subprocess
import sys

import pytest

import rapyd_sign

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")
BB_CURL_SH = os.path.join(TOOLS_DIR, "bb_curl.sh")

FAKE_CURL_SCRIPT = """#!/bin/bash
# Fake curl for tests -- dumps argv (one per line) to $FAKE_CURL_CAPTURE and
# exits 0. Never touches the network.
printf '%s\\n' "$@" > "$FAKE_CURL_CAPTURE"
exit 0
"""


@pytest.fixture
def fake_curl(tmp_path):
    """Put a fake, network-free `curl` first on PATH and return the path to
    the file it will dump its argv into."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    curl_path = bin_dir / "curl"
    curl_path.write_text(FAKE_CURL_SCRIPT)
    curl_path.chmod(curl_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    capture_path = tmp_path / "curl_argv.txt"
    return str(bin_dir), str(capture_path)


def _run_bb_curl(url, extra_curl_args, env_overrides, fake_curl_bindir, capture_path, scope_file):
    """Source bb_curl.sh in a fresh bash process, with the fake curl bindir
    prepended to PATH, and call bb_curl <url> [extra_curl_args...]. Returns
    (returncode, stdout, stderr)."""
    env = os.environ.copy()
    env["PATH"] = fake_curl_bindir + os.pathsep + env.get("PATH", "")
    env["FAKE_CURL_CAPTURE"] = capture_path
    env["BBHUNT_SCOPE_FILE"] = scope_file
    env["BBHUNT_USER_AGENT_SUFFIX"] = "test-suite (+no-network)"
    env.pop("BBHUNT_RAPYD_SIGN", None)
    env.pop("RAPYD_ACCESS_KEY", None)
    env.pop("RAPYD_SECRET_KEY", None)
    env.update(env_overrides)

    script = ". '{bb_curl}'; bb_curl '{url}' {extra}".format(
        bb_curl=BB_CURL_SH, url=url, extra=extra_curl_args
    )
    proc = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env, timeout=15
    )
    return proc.returncode, proc.stdout, proc.stderr


@pytest.fixture
def scope_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("sandboxapi.rapyd.net\napi.rapyd.net\nother-target.example\n")
    return str(f)


class TestRapydSignOptInNoOp:
    """Feature must be a complete no-op unless BOTH BBHUNT_RAPYD_SIGN=1 AND
    the host is the sandbox host — every other case sends the request
    exactly as it would have before this feature existed."""

    def test_unset_sign_flag_is_noop_even_on_sandbox_host(self, fake_curl, scope_file):
        bindir, capture = fake_curl
        rc, out, err = _run_bb_curl(
            "https://sandboxapi.rapyd.net/v1/data/countries", "",
            {}, bindir, capture, scope_file,
        )
        assert rc == 0, err
        argv = open(capture).read()
        assert "access_key" not in argv
        assert "signature" not in argv

    def test_sign_flag_on_but_non_sandbox_host_is_noop(self, fake_curl, scope_file):
        bindir, capture = fake_curl
        rc, out, err = _run_bb_curl(
            "https://api.rapyd.net/v1/data/countries", "",
            {"BBHUNT_RAPYD_SIGN": "1", "RAPYD_ACCESS_KEY": "ak", "RAPYD_SECRET_KEY": "sk"},
            bindir, capture, scope_file,
        )
        # Must NOT fail even though keys are present -- production is simply
        # never signed, by rapyd_sign.py's own hardcoded gate.
        assert rc == 0, err
        argv = open(capture).read()
        assert "access_key" not in argv
        assert "signature" not in argv

    def test_sign_flag_on_but_unrelated_host_is_noop(self, fake_curl, scope_file):
        bindir, capture = fake_curl
        rc, out, err = _run_bb_curl(
            "https://other-target.example/foo", "",
            {"BBHUNT_RAPYD_SIGN": "1", "RAPYD_ACCESS_KEY": "ak", "RAPYD_SECRET_KEY": "sk"},
            bindir, capture, scope_file,
        )
        assert rc == 0, err
        argv = open(capture).read()
        assert "access_key" not in argv


class TestRapydSignFailsClearlyWhenKeysMissing:
    """Once BBHUNT_RAPYD_SIGN=1 AND the host matches, a missing key is a
    hard failure -- curl must never be invoked, and the request must never
    go out unsigned."""

    def test_missing_both_keys_blocks_before_curl_runs(self, fake_curl, scope_file):
        bindir, capture = fake_curl
        rc, out, err = _run_bb_curl(
            "https://sandboxapi.rapyd.net/v1/data/countries", "",
            {"BBHUNT_RAPYD_SIGN": "1"}, bindir, capture, scope_file,
        )
        assert rc != 0
        assert "RAPYD_ACCESS_KEY" in err
        assert not os.path.exists(capture), "curl ran despite missing keys — request would have gone out unsigned"

    def test_missing_secret_key_only_blocks_before_curl_runs(self, fake_curl, scope_file):
        bindir, capture = fake_curl
        rc, out, err = _run_bb_curl(
            "https://sandboxapi.rapyd.net/v1/data/countries", "",
            {"BBHUNT_RAPYD_SIGN": "1", "RAPYD_ACCESS_KEY": "ak"},
            bindir, capture, scope_file,
        )
        assert rc != 0
        assert not os.path.exists(capture)


class TestRapydSignSucceedsAndMatchesTheRealAlgorithm:
    """With the flag on, the sandbox host, and both keys present, curl must
    actually be invoked, carrying all four Rapyd headers, and the
    signature must match what rapyd_sign._compute_signature() computes
    independently for the same inputs (proves the bash wiring is passing
    the right method/path/body through, not just that *some* signature got
    attached)."""

    def _parsed_headers(self, argv_text):
        headers = {}
        lines = argv_text.splitlines()
        for i, tok in enumerate(lines):
            if tok == "-H" and i + 1 < len(lines):
                name, _, value = lines[i + 1].partition(": ")
                headers[name] = value
        return headers

    def test_get_request_signed_and_matches_python_algorithm(self, fake_curl, scope_file, monkeypatch):
        bindir, capture = fake_curl
        rc, out, err = _run_bb_curl(
            "https://sandboxapi.rapyd.net/v1/data/countries", "",
            {"BBHUNT_RAPYD_SIGN": "1", "RAPYD_ACCESS_KEY": "test_ak", "RAPYD_SECRET_KEY": "test_sk"},
            bindir, capture, scope_file,
        )
        assert rc == 0, err
        argv = open(capture).read()
        headers = self._parsed_headers(argv)
        for h in ("access_key", "salt", "timestamp", "signature"):
            assert h in headers, f"missing {h!r} header in curl invocation: {argv!r}"
        assert headers["access_key"] == "test_ak"

        expected_sig = rapyd_sign._compute_signature(
            "GET", "/v1/data/countries", headers["salt"], headers["timestamp"],
            "test_ak", "test_sk", "",
        )
        assert headers["signature"] == expected_sig

    def test_post_request_with_explicit_method_and_body_is_signed_correctly(self, fake_curl, scope_file):
        bindir, capture = fake_curl
        body = '{"amount":100}'
        rc, out, err = _run_bb_curl(
            "https://sandboxapi.rapyd.net/v1/checkout", f"-X POST -d '{body}'",
            {"BBHUNT_RAPYD_SIGN": "1", "RAPYD_ACCESS_KEY": "test_ak", "RAPYD_SECRET_KEY": "test_sk"},
            bindir, capture, scope_file,
        )
        assert rc == 0, err
        argv = open(capture).read()
        headers = self._parsed_headers(argv)
        assert "signature" in headers, argv

        expected_sig = rapyd_sign._compute_signature(
            "POST", "/v1/checkout", headers["salt"], headers["timestamp"],
            "test_ak", "test_sk", body,
        )
        assert headers["signature"] == expected_sig
        # The actual request body must still be present in the curl argv —
        # signing must not swallow or alter what's actually sent.
        assert body in argv

    def test_scope_block_still_takes_priority_over_signing(self, fake_curl, scope_file):
        """A host that's simply out of scope must still be blocked by the
        existing scope gate -- signing is layered on top of, not instead
        of, that check."""
        bindir, capture = fake_curl
        rc, out, err = _run_bb_curl(
            "https://sandboxapi.rapyd.net.evil.com/v1/x", "",
            {"BBHUNT_RAPYD_SIGN": "1", "RAPYD_ACCESS_KEY": "ak", "RAPYD_SECRET_KEY": "sk"},
            bindir, capture, scope_file,
        )
        assert rc != 0
        assert not os.path.exists(capture)


class TestMethodAndBodyExtractionHelpers:
    """_bb_extract_method_from_curl_args / _bb_extract_body_from_curl_args
    in isolation -- fast, no curl/network involved at all."""

    def _run(self, func, args):
        script = f". '{BB_CURL_SH}'; {func} {args}"
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        return proc.stdout.strip()

    def test_default_method_is_get(self):
        assert self._run("_bb_extract_method_from_curl_args", "-s -o /dev/null") == "GET"

    def test_explicit_dash_x_method(self):
        assert self._run("_bb_extract_method_from_curl_args", "-X PUT") == "PUT"

    def test_data_flag_implies_post_without_explicit_x(self):
        assert self._run("_bb_extract_method_from_curl_args", "-d 'a=b'") == "POST"

    def test_explicit_method_wins_over_data_flag(self):
        assert self._run("_bb_extract_method_from_curl_args", "-X PATCH -d 'a=b'") == "PATCH"

    def test_body_extraction_literal(self):
        assert self._run("_bb_extract_body_from_curl_args", "-d 'hello=world'") == "hello=world"

    def test_body_extraction_at_file(self, tmp_path):
        f = tmp_path / "body.json"
        f.write_text('{"x":1}')
        assert self._run("_bb_extract_body_from_curl_args", f"-d @{f}") == '{"x":1}'

    def test_no_body_flag_yields_empty(self):
        assert self._run("_bb_extract_body_from_curl_args", "-s") == ""
