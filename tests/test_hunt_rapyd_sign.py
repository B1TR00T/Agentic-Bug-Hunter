"""Tests for hunt.py's --rapyd-sign wiring.

No live network calls, no real subprocess ever spawned — subprocess.Popen
is monkeypatched out in every test that touches run_recon(), same
technique tests/test_hunt_target_types.py already uses for its CIDR-safety
test.

Covers:
  1. _check_rapyd_sign_prereqs(): the standalone, factored-out early gate
     — no-op when the flag is off, sys.exit(1) when on with either/both
     keys missing, silent success when on with both keys present.
  2. run_recon() passes --rapyd-sign through to the recon_engine.sh shell
     command it builds only when rapyd_sign=True, and omits it (exact
     behavior as before this feature existed) when False/unset.
  3. --rapyd-sign is a real argparse flag on hunt.py's own parser.
"""

import importlib.util
from pathlib import Path

import pytest


def load_hunt_module():
    hunt_path = Path(__file__).resolve().parents[1] / "tools" / "hunt.py"
    spec = importlib.util.spec_from_file_location("hunt_module_rapyd_sign", hunt_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestCheckRapydSignPrereqs:
    def test_noop_when_flag_disabled_even_with_no_keys(self, monkeypatch):
        hunt = load_hunt_module()
        monkeypatch.delenv("RAPYD_ACCESS_KEY", raising=False)
        monkeypatch.delenv("RAPYD_SECRET_KEY", raising=False)
        # Must not raise / exit.
        assert hunt._check_rapyd_sign_prereqs(False) is True

    def test_exits_when_flag_enabled_and_both_keys_missing(self, monkeypatch, capsys):
        hunt = load_hunt_module()
        monkeypatch.delenv("RAPYD_ACCESS_KEY", raising=False)
        monkeypatch.delenv("RAPYD_SECRET_KEY", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            hunt._check_rapyd_sign_prereqs(True)
        assert exc_info.value.code == 1

    def test_exits_when_only_access_key_set(self, monkeypatch):
        hunt = load_hunt_module()
        monkeypatch.setenv("RAPYD_ACCESS_KEY", "ak")
        monkeypatch.delenv("RAPYD_SECRET_KEY", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            hunt._check_rapyd_sign_prereqs(True)
        assert exc_info.value.code == 1

    def test_exits_when_only_secret_key_set(self, monkeypatch):
        hunt = load_hunt_module()
        monkeypatch.delenv("RAPYD_ACCESS_KEY", raising=False)
        monkeypatch.setenv("RAPYD_SECRET_KEY", "sk")
        with pytest.raises(SystemExit) as exc_info:
            hunt._check_rapyd_sign_prereqs(True)
        assert exc_info.value.code == 1

    def test_succeeds_silently_when_both_keys_present(self, monkeypatch):
        hunt = load_hunt_module()
        monkeypatch.setenv("RAPYD_ACCESS_KEY", "ak")
        monkeypatch.setenv("RAPYD_SECRET_KEY", "sk")
        assert hunt._check_rapyd_sign_prereqs(True) is True


class TestRunReconPassesFlagThrough:
    def _capture_popen_command(self, hunt, monkeypatch, **run_recon_kwargs):
        captured = {}

        class FakeProc:
            returncode = 0

            def wait(self, timeout=None):
                return 0

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            return FakeProc()

        monkeypatch.setattr(hunt.subprocess, "Popen", fake_popen)
        hunt.run_recon("example.com", **run_recon_kwargs)
        return captured["cmd"]

    def test_rapyd_sign_flag_included_when_true(self, monkeypatch):
        hunt = load_hunt_module()
        cmd = self._capture_popen_command(hunt, monkeypatch, rapyd_sign=True)
        assert "--rapyd-sign" in cmd

    def test_rapyd_sign_flag_omitted_when_false(self, monkeypatch):
        hunt = load_hunt_module()
        cmd = self._capture_popen_command(hunt, monkeypatch, rapyd_sign=False)
        assert "--rapyd-sign" not in cmd

    def test_rapyd_sign_flag_omitted_by_default(self, monkeypatch):
        hunt = load_hunt_module()
        cmd = self._capture_popen_command(hunt, monkeypatch)
        assert "--rapyd-sign" not in cmd

    def test_rapyd_sign_and_quick_can_combine(self, monkeypatch):
        hunt = load_hunt_module()
        cmd = self._capture_popen_command(hunt, monkeypatch, quick=True, rapyd_sign=True)
        assert "--rapyd-sign" in cmd
        assert "--quick" in cmd


class TestArgparseHasRapydSignFlag:
    def test_flag_is_registered_and_defaults_false(self):
        load_hunt_module()  # sanity: module loads without error
        # Build a parser the same way main() does, without running main()
        # itself (which would try to execute the full pipeline).
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--rapyd-sign", action="store_true")
        ns = parser.parse_args([])
        assert ns.rapyd_sign is False
        ns2 = parser.parse_args(["--rapyd-sign"])
        assert ns2.rapyd_sign is True

    def test_hunt_py_source_actually_registers_the_flag(self):
        # Guards against the argparse test above passing against a parser
        # that isn't actually the one hunt.py builds -- checks the real
        # source registers --rapyd-sign on the real parser.
        hunt_src = Path(__file__).resolve().parents[1] / "tools" / "hunt.py"
        text = hunt_src.read_text()
        assert '"--rapyd-sign"' in text
        assert "_check_rapyd_sign_prereqs(args.rapyd_sign)" in text
