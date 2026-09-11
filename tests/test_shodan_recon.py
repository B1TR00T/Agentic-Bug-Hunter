"""tools/shodan_recon.py -- built entirely against mocked Shodan API
responses. Shodan is a paid, credit-limited API (unlike the free local
binaries the rest of this toolkit shells out to), so:

  - No test in this file makes a real network request. The autouse
    `_block_real_network` fixture below monkeypatches
    requests.sessions.Session.request (the one chokepoint the `shodan`
    library's HTTP calls all go through) to raise if anything ever tries --
    a tripwire, not just an assumption.
  - Every test that needs a Shodan client uses a hand-built fake
    (_FakeShodanClient) with canned .info()/.search() responses, injected
    via shodan_recon.get_client() -- the one seam the module exposes for
    exactly this purpose.

Covers:
  - require_api_key() / require_scope_entries() -- fail-loud config checks
  - query_term_for_entry() -- '*.' stripping for the hostname: search term
  - get_client() -- raises when the `shodan` package is absent; returns a
    real (but network-inert at construction time) client when present
  - matches_to_scoped_records() -- THE scope gate: reuses
    tools.safe_http.is_in_scope() (bb_curl.sh's is_in_scope(), ported) to
    reject an out-of-scope result mixed into an in-scope response set,
    drops hostname-less bare-IP matches outright, and keeps only the
    in-scope hostname(s) on a match that mixes in-scope and out-of-scope
    hostnames on one shared IP
  - write_outputs() -- hosts.txt / raw.json format and content
  - run() / main() -- end-to-end with a fake client, confirming the
    out-of-scope synthetic result never reaches either output file
"""
from __future__ import annotations

import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_ROOT = os.path.join(REPO_ROOT, "tools")
for _path in (REPO_ROOT, TOOLS_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from tools import shodan_recon  # noqa: E402

API_KEY_VAR = "SHODAN_API_KEY"
SCOPE_VAR = "BBHUNT_SCOPE_FILE"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(API_KEY_VAR, raising=False)
    monkeypatch.delenv(SCOPE_VAR, raising=False)


@pytest.fixture(autouse=True)
def _block_real_network(monkeypatch):
    """Tripwire: any attempt to actually hit the network through `requests`
    (the library shodan.Shodan uses internally for every API call) fails
    the test loudly instead of silently spending a real query credit."""
    def _boom(*_a, **_kw):
        raise AssertionError(
            "a test in test_shodan_recon.py attempted a REAL network "
            "request -- every Shodan call in this file must go through a "
            "fake client"
        )
    monkeypatch.setattr("requests.sessions.Session.request", _boom)


def _write_scope_file(tmp_path, lines):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("\n".join(lines) + "\n")
    return str(scope_file)


def _match(hostnames, ip_str, port=443, transport="tcp", product="nginx",
           org="Example Org", data="HTTP/1.1 200 OK\r\n", timestamp="2026-01-01T00:00:00.000000"):
    """One synthetic Shodan /shodan/host/search match dict, matching the
    real API's field names for the ones this module reads."""
    return {
        "hostnames": hostnames,
        "ip_str": ip_str,
        "port": port,
        "transport": transport,
        "product": product,
        "org": org,
        "data": data,
        "timestamp": timestamp,
    }


class _FakeShodanClient:
    """Stands in for shodan.Shodan. `pages_by_query` maps the exact query
    string search_domain() builds (e.g. "hostname:example.com") to a list
    of pages, each page a list of match dicts -- mirroring how the real
    /shodan/host/search endpoint paginates. Records every call made so
    tests can assert on query text and page count actually used."""

    def __init__(self, pages_by_query=None, credits=100):
        self._pages_by_query = pages_by_query or {}
        self._credits = credits
        self.search_calls: list[tuple[str, int]] = []
        self.info_calls = 0

    def info(self):
        self.info_calls += 1
        return {"query_credits": self._credits}

    def search(self, query, page=1):
        self.search_calls.append((query, page))
        pages = self._pages_by_query.get(query, [])
        idx = page - 1
        matches = pages[idx] if 0 <= idx < len(pages) else []
        return {"matches": matches, "total": sum(len(p) for p in pages)}


# ─────────────────────────────────────────────────────────────────────────
# require_api_key()
# ─────────────────────────────────────────────────────────────────────────
class TestRequireApiKey:
    def test_raises_when_unset(self):
        with pytest.raises(shodan_recon.MissingApiKeyError):
            shodan_recon.require_api_key()

    def test_raises_when_blank(self, monkeypatch):
        monkeypatch.setenv(API_KEY_VAR, "   ")
        with pytest.raises(shodan_recon.MissingApiKeyError):
            shodan_recon.require_api_key()

    def test_returns_key_when_set(self, monkeypatch):
        monkeypatch.setenv(API_KEY_VAR, "abc123")
        assert shodan_recon.require_api_key() == "abc123"

    def test_error_message_is_actionable(self):
        with pytest.raises(shodan_recon.MissingApiKeyError) as exc_info:
            shodan_recon.require_api_key()
        msg = str(exc_info.value)
        assert API_KEY_VAR in msg
        assert "export" in msg


# ─────────────────────────────────────────────────────────────────────────
# require_scope_entries()
# ─────────────────────────────────────────────────────────────────────────
class TestRequireScopeEntries:
    def test_raises_when_unset(self):
        with pytest.raises(shodan_recon.MissingScopeFileError):
            shodan_recon.require_scope_entries(None)

    def test_raises_when_file_missing(self, tmp_path):
        with pytest.raises(shodan_recon.MissingScopeFileError):
            shodan_recon.require_scope_entries(str(tmp_path / "nope.txt"))

    def test_parses_entries_skipping_comments_and_blanks(self, tmp_path):
        scope_file = _write_scope_file(
            tmp_path,
            ["example.com", "", "# a comment", "*.example.com  # inline comment", "   "],
        )
        entries = shodan_recon.require_scope_entries(scope_file)
        assert entries == ["example.com", "*.example.com"]


# ─────────────────────────────────────────────────────────────────────────
# query_term_for_entry()
# ─────────────────────────────────────────────────────────────────────────
class TestQueryTermForEntry:
    def test_strips_wildcard_prefix(self):
        assert shodan_recon.query_term_for_entry("*.example.com") == "example.com"

    def test_passes_through_bare_domain(self):
        assert shodan_recon.query_term_for_entry("example.com") == "example.com"


# ─────────────────────────────────────────────────────────────────────────
# get_client()
# ─────────────────────────────────────────────────────────────────────────
class TestGetClient:
    def test_raises_when_library_missing(self, monkeypatch):
        monkeypatch.setattr(shodan_recon, "shodan", None)
        with pytest.raises(shodan_recon.ShodanLibraryMissingError):
            shodan_recon.get_client("abc123")

    def test_returns_real_client_when_library_present(self):
        # shodan.Shodan(key).__init__ only sets attributes and opens a
        # requests.Session -- it makes no network call itself (verified by
        # reading shodan/client.py), so constructing one here is offline
        # -safe; the _block_real_network tripwire would fail this test if
        # that assumption were ever wrong.
        client = shodan_recon.get_client("abc123")
        assert client.api_key == "abc123"


# ─────────────────────────────────────────────────────────────────────────
# check_credits()
# ─────────────────────────────────────────────────────────────────────────
class TestCheckCredits:
    def test_returns_credit_count(self):
        client = _FakeShodanClient(credits=42)
        assert shodan_recon.check_credits(client) == 42

    def test_raises_when_zero_credits(self):
        client = _FakeShodanClient(credits=0)
        with pytest.raises(shodan_recon.InsufficientCreditsError):
            shodan_recon.check_credits(client)


# ─────────────────────────────────────────────────────────────────────────
# search_domain() -- pagination
# ─────────────────────────────────────────────────────────────────────────
class TestSearchDomain:
    def test_builds_hostname_query_never_broad_search(self):
        client = _FakeShodanClient({"hostname:example.com": [[_match(["a.example.com"], "1.2.3.4")]]})
        list(shodan_recon.search_domain(client, "example.com"))
        assert client.search_calls == [("hostname:example.com", 1)]

    def test_stops_on_short_page_without_using_max_pages(self):
        # A page with fewer than RESULTS_PER_PAGE (100) matches is the last
        # page -- search_domain must not fetch page 2 even if max_pages allows it.
        one_match_page = [_match(["a.example.com"], "1.2.3.4")]
        client = _FakeShodanClient({"hostname:example.com": [one_match_page]})
        results = list(shodan_recon.search_domain(client, "example.com", max_pages=5))
        assert len(results) == 1
        assert client.search_calls == [("hostname:example.com", 1)]

    def test_respects_max_pages_cap(self):
        full_page = [_match([f"h{i}.example.com"], f"1.2.3.{i}") for i in range(shodan_recon.RESULTS_PER_PAGE)]
        client = _FakeShodanClient({"hostname:example.com": [full_page, full_page, full_page]})
        results = list(shodan_recon.search_domain(client, "example.com", max_pages=2))
        assert len(results) == 2 * shodan_recon.RESULTS_PER_PAGE
        assert client.search_calls == [("hostname:example.com", 1), ("hostname:example.com", 2)]

    def test_stops_when_a_page_is_empty(self):
        client = _FakeShodanClient({"hostname:example.com": [[]]})
        results = list(shodan_recon.search_domain(client, "example.com"))
        assert results == []


# ─────────────────────────────────────────────────────────────────────────
# matches_to_scoped_records() -- THE scope gate
# ─────────────────────────────────────────────────────────────────────────
class TestMatchesToScopedRecords:
    def test_rejects_out_of_scope_result_mixed_into_in_scope_set(self, tmp_path, monkeypatch):
        scope_file = _write_scope_file(tmp_path, ["*.example.com"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)

        matches = [
            _match(["api.example.com"], "10.0.0.1"),        # in scope
            _match(["totally-unrelated.evil.net"], "10.0.0.2"),  # out of scope -- mixed in
        ]
        records = shodan_recon.matches_to_scoped_records(matches)

        hostnames = {r.hostname for r in records}
        assert hostnames == {"api.example.com"}
        assert "totally-unrelated.evil.net" not in hostnames

    def test_drops_bare_ip_match_with_no_hostnames(self, tmp_path, monkeypatch):
        scope_file = _write_scope_file(tmp_path, ["*.example.com"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)

        matches = [_match([], "10.0.0.9")]  # Shodan found the IP but no hostname on it
        records = shodan_recon.matches_to_scoped_records(matches)

        assert records == []

    def test_shared_ip_keeps_only_the_in_scope_hostname(self, tmp_path, monkeypatch):
        # Shared hosting: one IP, two hostnames on the SAME match, only one in scope.
        scope_file = _write_scope_file(tmp_path, ["*.example.com"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)

        matches = [_match(["api.example.com", "other-customer.example.net"], "10.0.0.5")]
        records = shodan_recon.matches_to_scoped_records(matches)

        hostnames = {r.hostname for r in records}
        assert hostnames == {"api.example.com"}

    def test_apex_only_entry_excludes_subdomains(self, tmp_path, monkeypatch):
        # Scope file lists the bare apex only (no "*.") -- is_in_scope()'s
        # own documented semantics say that must NOT cover subdomains.
        scope_file = _write_scope_file(tmp_path, ["example.com"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)

        matches = [
            _match(["example.com"], "10.0.0.1"),
            _match(["sub.example.com"], "10.0.0.2"),
        ]
        records = shodan_recon.matches_to_scoped_records(matches)

        hostnames = {r.hostname for r in records}
        assert hostnames == {"example.com"}

    def test_dedupes_identical_host_ip_port_transport(self, tmp_path, monkeypatch):
        scope_file = _write_scope_file(tmp_path, ["*.example.com"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)

        matches = [
            _match(["api.example.com"], "10.0.0.1", port=443),
            _match(["api.example.com"], "10.0.0.1", port=443),  # exact duplicate (e.g. two queries hit it)
        ]
        records = shodan_recon.matches_to_scoped_records(matches)

        assert len(records) == 1

    def test_record_carries_port_and_banner_fields(self, tmp_path, monkeypatch):
        scope_file = _write_scope_file(tmp_path, ["*.example.com"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)

        matches = [_match(["api.example.com"], "10.0.0.1", port=8443, product="nginx", data="banner-text")]
        records = shodan_recon.matches_to_scoped_records(matches)

        assert len(records) == 1
        r = records[0]
        assert r.ip_str == "10.0.0.1"
        assert r.port == 8443
        assert r.product == "nginx"
        assert r.banner == "banner-text"


# ─────────────────────────────────────────────────────────────────────────
# write_outputs()
# ─────────────────────────────────────────────────────────────────────────
class TestWriteOutputs:
    def test_hosts_txt_is_sorted_unique_bare_hostnames(self, tmp_path):
        records = [
            shodan_recon.ShodanRecord("z.example.com", "10.0.0.2", 443, "tcp", "nginx", "Org", "banner", "ts"),
            shodan_recon.ShodanRecord("a.example.com", "10.0.0.1", 443, "tcp", "nginx", "Org", "banner", "ts"),
            shodan_recon.ShodanRecord("a.example.com", "10.0.0.1", 8443, "tcp", "nginx", "Org", "banner", "ts"),
        ]
        hosts_path, raw_path = shodan_recon.write_outputs("example.com", records, recon_root=str(tmp_path))

        content = open(hosts_path).read().splitlines()
        assert content == ["a.example.com", "z.example.com"]

    def test_raw_json_contains_full_records(self, tmp_path):
        records = [
            shodan_recon.ShodanRecord("a.example.com", "10.0.0.1", 443, "tcp", "nginx", "Org", "banner", "ts"),
        ]
        hosts_path, raw_path = shodan_recon.write_outputs("example.com", records, recon_root=str(tmp_path))

        data = json.loads(open(raw_path).read())
        assert data["target"] == "example.com"
        assert data["record_count"] == 1
        assert data["records"][0]["hostname"] == "a.example.com"
        assert data["records"][0]["port"] == 443

    def test_output_path_matches_subdomains_convention(self, tmp_path):
        hosts_path, raw_path = shodan_recon.write_outputs("example.com", [], recon_root=str(tmp_path))
        assert hosts_path == str(tmp_path / "example.com" / "shodan" / "hosts.txt")
        assert raw_path == str(tmp_path / "example.com" / "shodan" / "raw.json")

    def test_never_writes_when_records_are_already_empty(self, tmp_path):
        # write_outputs trusts its input is already scope-filtered; confirms
        # an empty (fully-filtered-out) record set produces empty, not
        # missing, output files.
        hosts_path, raw_path = shodan_recon.write_outputs("example.com", [], recon_root=str(tmp_path))
        assert open(hosts_path).read() == ""
        assert json.loads(open(raw_path).read())["record_count"] == 0


# ─────────────────────────────────────────────────────────────────────────
# run() -- end to end with a fake client
# ─────────────────────────────────────────────────────────────────────────
class TestRun:
    def test_end_to_end_drops_out_of_scope_result_from_both_outputs(self, tmp_path, monkeypatch):
        scope_file = _write_scope_file(tmp_path, ["*.example.com"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)
        monkeypatch.setenv(API_KEY_VAR, "abc123")

        fake_client = _FakeShodanClient(
            pages_by_query={
                "hostname:example.com": [[
                    _match(["api.example.com"], "10.0.0.1"),
                    _match(["shared-hosting.notexample.org"], "10.0.0.2"),  # out of scope
                ]],
            },
            credits=50,
        )
        monkeypatch.setattr(shodan_recon, "get_client", lambda api_key: fake_client)

        summary = shodan_recon.run("example.com", recon_root=str(tmp_path))

        assert summary["scope_entries_queried"] == 1
        assert summary["raw_matches"] == 2
        assert summary["hostnames_seen"] == 2
        assert summary["hostnames_in_scope"] == 1
        assert summary["hostnames_dropped_out_of_scope"] == 1

        hosts_content = open(summary["hosts_path"]).read()
        raw_content = open(summary["raw_json_path"]).read()
        assert "api.example.com" in hosts_content
        assert "shared-hosting.notexample.org" not in hosts_content
        assert "shared-hosting.notexample.org" not in raw_content  # never written anywhere, not even the raw dump

    def test_raises_before_querying_when_credits_exhausted(self, tmp_path, monkeypatch):
        scope_file = _write_scope_file(tmp_path, ["*.example.com"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)
        monkeypatch.setenv(API_KEY_VAR, "abc123")

        fake_client = _FakeShodanClient(
            pages_by_query={"hostname:example.com": [[_match(["api.example.com"], "10.0.0.1")]]},
            credits=0,
        )
        monkeypatch.setattr(shodan_recon, "get_client", lambda api_key: fake_client)

        with pytest.raises(shodan_recon.InsufficientCreditsError):
            shodan_recon.run("example.com", recon_root=str(tmp_path))

        assert fake_client.search_calls == []  # never got as far as spending a credit

    def test_one_query_per_scope_entry(self, tmp_path, monkeypatch):
        scope_file = _write_scope_file(tmp_path, ["*.example.com", "other.org"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)
        monkeypatch.setenv(API_KEY_VAR, "abc123")

        fake_client = _FakeShodanClient(
            pages_by_query={
                "hostname:example.com": [[_match(["api.example.com"], "10.0.0.1")]],
                "hostname:other.org": [[_match(["www.other.org"], "10.0.0.9")]],
            },
        )
        monkeypatch.setattr(shodan_recon, "get_client", lambda api_key: fake_client)

        summary = shodan_recon.run("example.com", recon_root=str(tmp_path))

        assert summary["scope_entries_queried"] == 2
        queried = {q for q, _page in fake_client.search_calls}
        assert queried == {"hostname:example.com", "hostname:other.org"}


# ─────────────────────────────────────────────────────────────────────────
# main() -- CLI entry point
# ─────────────────────────────────────────────────────────────────────────
class TestMain:
    def test_missing_api_key_exits_2(self, tmp_path, monkeypatch, capsys):
        scope_file = _write_scope_file(tmp_path, ["*.example.com"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)
        rc = shodan_recon.main(["example.com"])
        assert rc == 2
        assert "SHODAN_API_KEY" in capsys.readouterr().err

    def test_missing_scope_file_exits_2(self, monkeypatch, capsys):
        monkeypatch.setenv(API_KEY_VAR, "abc123")
        rc = shodan_recon.main(["example.com"])
        assert rc == 2
        assert "BBHUNT_SCOPE_FILE" in capsys.readouterr().err

    def test_no_target_arg_exits_2(self, capsys):
        rc = shodan_recon.main([])
        assert rc == 2

    def test_successful_run_exits_0_and_prints_summary(self, tmp_path, monkeypatch, capsys):
        scope_file = _write_scope_file(tmp_path, ["*.example.com"])
        monkeypatch.setenv(SCOPE_VAR, scope_file)
        monkeypatch.setenv(API_KEY_VAR, "abc123")

        fake_client = _FakeShodanClient(
            pages_by_query={"hostname:example.com": [[_match(["api.example.com"], "10.0.0.1")]]},
        )
        monkeypatch.setattr(shodan_recon, "get_client", lambda api_key: fake_client)

        # --recon-root points output at tmp_path instead of the real repo's
        # recon/ directory -- this test must never write into the checkout.
        rc = shodan_recon.main(["example.com", "--max-pages", "1", "--recon-root", str(tmp_path)])
        out = capsys.readouterr().out

        assert rc == 0
        assert "hostnames in scope (kept): 1" in out
        assert (tmp_path / "example.com" / "shodan" / "hosts.txt").read_text() == "api.example.com\n"
