"""Isolated tests for recon_engine.sh's --rapyd-sign early gate.

Same extraction technique as tests/test_recon_engine_cve_phase.py: the
REAL, current source is sliced directly out of tools/recon_engine.sh
(between the arg-parsing block's opening and the RAPYD_SIGN_MODE export
line) and run inside a minimal bash harness -- so these tests exercise the
actual current gate logic, not a hand-copied reimplementation.

The extracted slice also includes the pre-existing BBHUNT_SCOPE_FILE,
BBHUNT_USER_AGENT_SUFFIX, and --shodan/SHODAN_API_KEY gates that sit ahead
of the --rapyd-sign one in the real file, plus the two `. "$(dirname
"$0")/..."` lines that source _auth_helper.sh and bb_curl.sh. In the real
script $0 is tools/recon_engine.sh itself, so that resolves to tools/; in
this harness $0 is a temp file elsewhere, so `$(dirname "$0")` in the
extracted text is repointed at the real tools/ dir before being embedded
-- the only text altered in the slice, everything else (every gate/check
itself) runs verbatim. A valid scope file and user agent suffix are
supplied in every test's environment so the earlier gates pass through
cleanly and don't mask what's being tested here.

No live network call anywhere in this file -- this slice of
recon_engine.sh never invokes curl/httpx/nuclei/etc. at all (bb_curl.sh is
only sourced, defining functions -- nothing calls bb_curl() here), it's
pure bash argument parsing and env-var checks.

Covers:
  1. --rapyd-sign not passed -> RAPYD_SIGN_MODE stays 0, BBHUNT_RAPYD_SIGN
     is never exported, regardless of whether the keys happen to be set.
  2. --rapyd-sign passed, either key missing -> hard failure (non-zero
     exit), before the harness's own "REACHED_END" marker is ever printed.
  3. --rapyd-sign passed, both keys present -> succeeds, and
     BBHUNT_RAPYD_SIGN=1 is exported for the rest of the script.
"""
import os
import subprocess
import textwrap

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
RECON_ENGINE_SH = os.path.join(TOOLS_DIR, "recon_engine.sh")

_START_SENTINEL = "SHODAN_MODE=0"
_END_SENTINEL = '[ "$RAPYD_SIGN_MODE" = "1" ] && export BBHUNT_RAPYD_SIGN=1'


def _extract_gate_block():
    text = open(RECON_ENGINE_SH, encoding="utf-8").read()
    start = text.index(_START_SENTINEL)
    end = text.index(_END_SENTINEL, start) + len(_END_SENTINEL)
    block = text[start:end]
    # Repoint the two `$(dirname "$0")/...` sourcing lines at the real
    # tools/ dir -- see module docstring for why this is the one
    # substitution made in an otherwise-verbatim slice. The original text
    # is `. "$(dirname "$0")/foo.sh"` -- the surrounding double quotes are
    # already part of that line, so the replacement must be the bare path
    # with no quoting of its own (adding quotes here would nest a second
    # quote style inside the existing double quotes and corrupt the path).
    block = block.replace('$(dirname "$0")', TOOLS_DIR)
    return block


def _write_harness(tmp_path, extra_args):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("sandboxapi.rapyd.net\n")
    test_log = tmp_path / "test.log"

    gate_block = _extract_gate_block()
    harness = tmp_path / "harness.sh"
    args_str = " ".join(f"'{a}'" for a in extra_args)
    harness.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/bash
            log_ok()   {{ :; }}
            log_err()  {{ echo "[ERR] $1" >> '{test_log}'; }}
            log_warn() {{ :; }}
            log_info() {{ :; }}
            log_step() {{ :; }}
            log_done() {{ :; }}
            log_vuln() {{ :; }}

            set -- '/tmp/nonexistent-target' {args_str}

            {gate_block}

            echo "REACHED_END" >> '{test_log}'
            echo "BBHUNT_RAPYD_SIGN=$BBHUNT_RAPYD_SIGN" >> '{test_log}'
            """
        ),
        encoding="utf-8",
    )
    return harness, test_log


def _run(harness_path, env_overrides, scope_file):
    env = os.environ.copy()
    env.pop("RAPYD_ACCESS_KEY", None)
    env.pop("RAPYD_SECRET_KEY", None)
    env["BBHUNT_SCOPE_FILE"] = str(scope_file)
    env["BBHUNT_USER_AGENT_SUFFIX"] = "test-suite (+no-network)"
    env.update(env_overrides)
    return subprocess.run(
        ["bash", str(harness_path)], capture_output=True, text=True, env=env, timeout=15
    )


class TestRapydSignFlagNotPassed:
    def test_flag_absent_never_exports_even_with_keys_present(self, tmp_path):
        harness, log = _write_harness(tmp_path, [])
        scope_file = tmp_path / "scope.txt"
        result = _run(
            harness, {"RAPYD_ACCESS_KEY": "ak", "RAPYD_SECRET_KEY": "sk"}, scope_file
        )
        assert result.returncode == 0, result.stderr
        log_text = log.read_text()
        assert "REACHED_END" in log_text
        assert "BBHUNT_RAPYD_SIGN=" in log_text and "BBHUNT_RAPYD_SIGN=1" not in log_text


class TestRapydSignFlagPassedWithMissingKeys:
    def test_both_keys_missing_fails_before_reaching_end(self, tmp_path):
        harness, log = _write_harness(tmp_path, ["--rapyd-sign"])
        scope_file = tmp_path / "scope.txt"
        result = _run(harness, {}, scope_file)
        assert result.returncode == 1
        assert "REACHED_END" not in log.read_text()
        assert "RAPYD_ACCESS_KEY" in log.read_text()

    def test_only_access_key_set_still_fails(self, tmp_path):
        harness, log = _write_harness(tmp_path, ["--rapyd-sign"])
        scope_file = tmp_path / "scope.txt"
        result = _run(harness, {"RAPYD_ACCESS_KEY": "ak"}, scope_file)
        assert result.returncode == 1
        assert "REACHED_END" not in log.read_text()

    def test_only_secret_key_set_still_fails(self, tmp_path):
        harness, log = _write_harness(tmp_path, ["--rapyd-sign"])
        scope_file = tmp_path / "scope.txt"
        result = _run(harness, {"RAPYD_SECRET_KEY": "sk"}, scope_file)
        assert result.returncode == 1
        assert "REACHED_END" not in log.read_text()


class TestRapydSignFlagPassedWithBothKeys:
    def test_both_keys_present_succeeds_and_exports_flag(self, tmp_path):
        harness, log = _write_harness(tmp_path, ["--rapyd-sign"])
        scope_file = tmp_path / "scope.txt"
        result = _run(
            harness, {"RAPYD_ACCESS_KEY": "ak", "RAPYD_SECRET_KEY": "sk"}, scope_file
        )
        assert result.returncode == 0, result.stderr
        log_text = log.read_text()
        assert "REACHED_END" in log_text
        assert "BBHUNT_RAPYD_SIGN=1" in log_text
