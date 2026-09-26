"""Tests for tools/rapyd_sign.py — Rapyd HMAC request signing.

No live network calls anywhere in this file. Two kinds of coverage:

1. Cross-validation of the core signing math against Rapyd's REAL,
   verbatim, unedited official sign-node.js (tools/testdata/sign-node.js),
   run for real via a local `node` binary (tools/testdata/node_driver.js)
   on a fixed set of test vectors — chosen because no official
   input->output worked example exists anywhere in Rapyd's repo or docs
   (confirmed by direct fetch, not assumed). This is the strongest
   evidence available that the Python port is correct: it isn't diffed
   against a second manual transcription of the algorithm, it's diffed
   against the actual official code.

   Skipped (not failed) if `node` isn't on PATH, so this suite still runs
   somewhere without Node installed — but on this machine node IS present
   (confirmed: /usr/bin/node, v26.7.0), so it runs for real here.

2. The hard safety gates: sandbox-only host enforcement, and that env
   vars (not plain args) are the only path real keys travel through.

3. The `sign-headers` CLI entrypoint's error paths (wrong host, missing
   keys, bad args) never print RAPYD_SECRET_KEY's actual value to stdout
   or stderr, on any path -- see TestCliNeverLeaksSecretKeyValue below.
   Run as real subprocesses (not just calling _cli_sign_headers()
   in-process) specifically so this checks the actual bytes that would
   land in a terminal or a log, not an internal call's return value.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

import rapyd_sign


TESTDATA_DIR = os.path.join(os.path.dirname(__file__), "..", "tools", "testdata")
NODE_DRIVER = os.path.join(TESTDATA_DIR, "node_driver.js")

# Must mirror node_driver.js's `cases` list exactly — same salt, timestamp,
# keys, method, path. The json_body_post case's `body` string here must be
# byte-identical to what JSON.stringify() produces for node_driver.js's
# equivalent object literal (same key order, no extra whitespace) since
# this module signs over the exact wire-body string, not a dict it
# re-encodes itself — see rapyd_sign.py's module docstring.
FIXTURES = [
    dict(
        name="empty_body_get",
        method="GET",
        url_path="/v1/data/countries",
        salt="abcd1234",
        timestamp="1700000000",
        access_key="test_access_key_fixture",
        secret_key="test_secret_key_fixture",
        body="",
    ),
    dict(
        name="json_body_post",
        method="POST",
        url_path="/v1/checkout",
        salt="Xy9Zq2Ab7Lm1",
        timestamp="1700000042",
        access_key="test_access_key_fixture",
        secret_key="test_secret_key_fixture",
        body='{"amount":100,"currency":"USD","country":"US"}',
    ),
    dict(
        name="mixed_case_method_and_path_with_query",
        method="GeT",
        url_path="/v1/checkout/client/checkout_deadbeefdeadbeefdeadbeefdeadbeef?expand=payment",
        salt="9",
        timestamp="1",
        access_key="ak",
        secret_key="sk",
        body="",
    ),
]


def _node_available() -> bool:
    return shutil.which("node") is not None


@pytest.fixture(scope="module")
def node_signatures():
    """Run node_driver.js once, return {case_name: signature} from the
    REAL official sign-node.js. No network access — generateSignature()
    is pure local HMAC math, and node_driver.js only reads sign-node.js
    off local disk."""
    if not _node_available():
        pytest.skip("node is not on PATH — cannot cross-validate against the official JS sample")
    result = subprocess.run(
        ["node", NODE_DRIVER],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    out = {}
    for line in result.stdout.strip().splitlines():
        row = json.loads(line)
        out[row["name"]] = row["signature"]
    return out


class TestCrossValidationAgainstOfficialNodeSample:
    """The Python port's core signing math must produce byte-identical
    output to Rapyd's own official sign-node.js on the same inputs."""

    @pytest.mark.parametrize("fx", FIXTURES, ids=[f["name"] for f in FIXTURES])
    def test_matches_official_node_sample(self, node_signatures, fx):
        expected = node_signatures[fx["name"]]
        actual = rapyd_sign._compute_signature(
            fx["method"],
            fx["url_path"],
            fx["salt"],
            fx["timestamp"],
            fx["access_key"],
            fx["secret_key"],
            fx["body"],
        )
        assert actual == expected, (
            f"{fx['name']}: Python port produced {actual!r}, "
            f"official sign-node.js produced {expected!r}"
        )


class TestSignatureMathProperties:
    """Sanity properties that don't need the node oracle — fast, always
    run, catch obvious regressions immediately."""

    def test_deterministic_for_same_inputs(self):
        args = ("get", "/v1/x", "salt1", "1700000000", "ak", "sk", "")
        assert rapyd_sign._compute_signature(*args) == rapyd_sign._compute_signature(*args)

    def test_method_case_insensitive(self):
        base = dict(
            url_path="/v1/x", salt="s", timestamp="1", access_key="ak",
            secret_key="sk", body="",
        )
        upper = rapyd_sign._compute_signature("GET", **base)
        lower = rapyd_sign._compute_signature("get", **base)
        mixed = rapyd_sign._compute_signature("GeT", **base)
        assert upper == lower == mixed

    def test_different_salt_changes_signature(self):
        base = dict(
            method="GET", url_path="/v1/x", timestamp="1", access_key="ak",
            secret_key="sk", body="",
        )
        sig_a = rapyd_sign._compute_signature(salt="aaaaaaaa", **base)
        sig_b = rapyd_sign._compute_signature(salt="bbbbbbbb", **base)
        assert sig_a != sig_b

    def test_empty_body_is_empty_string_not_curly_braces(self):
        # Mirrors sign-node.js's explicit special case: an empty/falsy
        # body must contribute "" to the signed string, never "{}".
        base = dict(
            method="GET", url_path="/v1/x", salt="s", timestamp="1",
            access_key="ak", secret_key="sk",
        )
        sig_empty_string = rapyd_sign._compute_signature(body="", **base)
        sig_none_ish = rapyd_sign._compute_signature(body=None, **base)
        sig_literal_braces = rapyd_sign._compute_signature(body="{}", **base)
        assert sig_empty_string == sig_none_ish
        assert sig_empty_string != sig_literal_braces

    def test_output_is_valid_base64_of_a_hex_string(self):
        import base64

        sig = rapyd_sign._compute_signature(
            "GET", "/v1/x", "salt1", "1700000000", "ak", "sk", ""
        )
        decoded = base64.b64decode(sig)
        # Decoding the base64 must yield an ASCII hex string (the
        # HMAC-SHA256 hexdigest), not 32 raw binary bytes — this is the
        # single detail every naive reimplementation gets wrong (base64
        # of the raw digest instead of base64 of its hex representation).
        assert len(decoded) == 64  # 32-byte digest -> 64 hex chars
        int(decoded, 16)  # raises ValueError if not valid hex


class TestSandboxOnlyGate:
    """The hardcoded, code-level sandbox-only enforcement — gate #1."""

    def test_sandbox_host_is_allowed(self, monkeypatch):
        monkeypatch.setenv("RAPYD_ACCESS_KEY", "ak")
        monkeypatch.setenv("RAPYD_SECRET_KEY", "sk")
        monkeypatch.setenv("BBHUNT_USER_AGENT_SUFFIX", "b1tr00t (+test)")
        req = rapyd_sign.build_signed_request(
            "GET", "https://sandboxapi.rapyd.net/v1/data/countries"
        )
        assert req.full_url == "https://sandboxapi.rapyd.net/v1/data/countries"
        assert "access_key" in req.headers or "Access_key" in req.headers

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.rapyd.net/v1/data/countries",  # real production
            "https://sandboxapi.rapyd.net.evil.com/v1/x",  # lookalike suffix
            "https://checkout.rapyd.net/v1/x",  # in-scope elsewhere, still not this host
        ],
    )
    def test_non_sandbox_host_is_rejected(self, monkeypatch, url):
        monkeypatch.setenv("RAPYD_ACCESS_KEY", "ak")
        monkeypatch.setenv("RAPYD_SECRET_KEY", "sk")
        monkeypatch.setenv("BBHUNT_USER_AGENT_SUFFIX", "b1tr00t (+test)")
        with pytest.raises(rapyd_sign.SandboxOnlyViolation):
            rapyd_sign.build_signed_request("GET", url)

    def test_gate_runs_before_any_key_is_read(self, monkeypatch):
        # No RAPYD_ACCESS_KEY/RAPYD_SECRET_KEY set at all — if the gate
        # ran after key-reading, this would raise MissingKeyError
        # instead, which would be the wrong failure for a production URL.
        monkeypatch.delenv("RAPYD_ACCESS_KEY", raising=False)
        monkeypatch.delenv("RAPYD_SECRET_KEY", raising=False)
        with pytest.raises(rapyd_sign.SandboxOnlyViolation):
            rapyd_sign.build_signed_request("GET", "https://api.rapyd.net/v1/data/countries")


class TestKeysComeOnlyFromEnv:
    """Gate #2 — real keys travel only through RAPYD_ACCESS_KEY /
    RAPYD_SECRET_KEY, never as a plain function argument on any
    real-request code path."""

    def test_sign_has_no_key_parameters(self):
        import inspect

        params = inspect.signature(rapyd_sign.sign).parameters
        assert "access_key" not in params
        assert "secret_key" not in params

    def test_build_signed_request_has_no_key_parameters(self):
        import inspect

        params = inspect.signature(rapyd_sign.build_signed_request).parameters
        assert "access_key" not in params
        assert "secret_key" not in params

    def test_missing_access_key_raises(self, monkeypatch):
        monkeypatch.delenv("RAPYD_ACCESS_KEY", raising=False)
        monkeypatch.setenv("RAPYD_SECRET_KEY", "sk")
        with pytest.raises(rapyd_sign.MissingKeyError):
            rapyd_sign.sign("GET", "/v1/x")

    def test_missing_secret_key_raises(self, monkeypatch):
        monkeypatch.setenv("RAPYD_ACCESS_KEY", "ak")
        monkeypatch.delenv("RAPYD_SECRET_KEY", raising=False)
        with pytest.raises(rapyd_sign.MissingKeyError):
            rapyd_sign.sign("GET", "/v1/x")

    def test_sign_reads_real_env_keys_and_returns_headers(self, monkeypatch):
        monkeypatch.setenv("RAPYD_ACCESS_KEY", "my_access_key")
        monkeypatch.setenv("RAPYD_SECRET_KEY", "my_secret_key")
        headers = rapyd_sign.sign("GET", "/v1/data/countries")
        assert headers["access_key"] == "my_access_key"
        assert set(headers) == {"access_key", "salt", "timestamp", "signature"}
        assert 8 <= len(headers["salt"]) <= 16


class TestCliNeverLeaksSecretKeyValue:
    """`python3 rapyd_sign.py sign-headers ...` must never print
    RAPYD_SECRET_KEY's actual value to stdout or stderr, on ANY path —
    success or error. The access key is fine to appear (it's the
    semi-public half of the pair, meant to travel in a request header);
    only the secret key is the thing that must never show up, including
    inside an error message string. Run as real subprocesses so this
    checks the actual bytes that would land in a terminal or a log file,
    not just an in-process function's return value.
    """

    RAPYD_SIGN_PY = os.path.join(os.path.dirname(__file__), "..", "tools", "rapyd_sign.py")
    SECRET_MARKER = "SUPER_SECRET_MARKER_should_never_appear_9f3a2b"
    ACCESS_MARKER = "test_access_key_semi_public_ok_to_appear"

    def _run_cli(self, args, env_overrides):
        env = os.environ.copy()
        env.pop("RAPYD_ACCESS_KEY", None)
        env.pop("RAPYD_SECRET_KEY", None)
        env.update(env_overrides)
        return subprocess.run(
            [sys.executable, self.RAPYD_SIGN_PY, "sign-headers"] + args,
            capture_output=True, text=True, env=env, timeout=10,
        )

    def test_wrong_host_error_never_leaks_secret(self):
        result = self._run_cli(
            ["--method", "GET", "--url", "https://api.rapyd.net/v1/data/countries"],
            {"RAPYD_ACCESS_KEY": self.ACCESS_MARKER, "RAPYD_SECRET_KEY": self.SECRET_MARKER},
        )
        assert result.returncode == 1
        combined = result.stdout + result.stderr
        assert self.SECRET_MARKER not in combined
        # The sandbox gate runs before any key is read at all (see
        # TestSandboxOnlyGate for the same property on build_signed_request),
        # so the access key shouldn't appear here either -- sign() is never
        # reached on this path.
        assert self.ACCESS_MARKER not in combined

    def test_missing_both_keys_never_leaks_secret(self):
        result = self._run_cli(
            ["--method", "GET", "--url", "https://sandboxapi.rapyd.net/v1/data/countries"], {},
        )
        assert result.returncode == 2
        combined = result.stdout + result.stderr
        assert self.SECRET_MARKER not in combined
        assert "RAPYD_ACCESS_KEY" in combined  # names the var, never a value

    def test_missing_secret_key_only_never_leaks_it(self):
        result = self._run_cli(
            ["--method", "GET", "--url", "https://sandboxapi.rapyd.net/v1/data/countries"],
            {"RAPYD_ACCESS_KEY": self.ACCESS_MARKER},
        )
        assert result.returncode == 2
        combined = result.stdout + result.stderr
        assert self.SECRET_MARKER not in combined
        assert "RAPYD_SECRET_KEY" in combined  # names the var, never a value

    def test_missing_access_key_only_never_leaks_secret(self):
        result = self._run_cli(
            ["--method", "GET", "--url", "https://sandboxapi.rapyd.net/v1/data/countries"],
            {"RAPYD_SECRET_KEY": self.SECRET_MARKER},
        )
        assert result.returncode == 2
        combined = result.stdout + result.stderr
        assert self.SECRET_MARKER not in combined
        assert "RAPYD_ACCESS_KEY" in combined

    def test_missing_required_url_arg_never_leaks_secret(self):
        # argparse usage error -- missing --url entirely.
        result = self._run_cli(
            ["--method", "GET"],
            {"RAPYD_ACCESS_KEY": self.ACCESS_MARKER, "RAPYD_SECRET_KEY": self.SECRET_MARKER},
        )
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert self.SECRET_MARKER not in combined

    def test_unreadable_body_file_never_leaks_secret(self, tmp_path):
        missing_file = tmp_path / "does_not_exist.json"
        result = self._run_cli(
            [
                "--method", "POST", "--url", "https://sandboxapi.rapyd.net/v1/checkout",
                "--body-file", str(missing_file),
            ],
            {"RAPYD_ACCESS_KEY": self.ACCESS_MARKER, "RAPYD_SECRET_KEY": self.SECRET_MARKER},
        )
        assert result.returncode == 2
        combined = result.stdout + result.stderr
        assert self.SECRET_MARKER not in combined

    def test_success_path_shows_access_key_but_never_secret(self):
        result = self._run_cli(
            ["--method", "GET", "--url", "https://sandboxapi.rapyd.net/v1/data/countries"],
            {"RAPYD_ACCESS_KEY": self.ACCESS_MARKER, "RAPYD_SECRET_KEY": self.SECRET_MARKER},
        )
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert self.ACCESS_MARKER in combined  # semi-public, expected to appear
        assert self.SECRET_MARKER not in combined
