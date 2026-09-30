"""ARD conformance: making "implements ARD" checkable in one command.

The design decision this file pins is the **error/warning split**. ARD §D.2 makes
``representativeQueries`` a warning rather than a validation failure, explicitly
so that output from existing tooling still validates. A checker that rejects
conformant input is worse than no checker, because it teaches people to add
``|| true`` to a CI step — so the split is asserted here rather than left to the
implementation's discretion.

The other decision is that this module is *not* the specification's official
conformance CLI, and does not pretend to be. The official tool is offered through
``run_official`` for a second opinion, and its absence is reported as exit 127 —
the shell's own convention for "command not found" — so a caller can tell it
apart from a conformance failure without parsing prose.
"""

from __future__ import annotations

import json

import pytest

from agent_ledger.conform import (
    ConformanceReport,
    Finding,
    check_manifest,
    check_registry,
    run_official,
)

GOOD_ENTRY = {
    "identifier": "urn:air:acme.com:server:weather",
    "displayName": "Weather Data Node",
    "type": "application/mcp-server-card+json",
    "url": "https://api.acme.com/mcp/weather.json",
    "capabilities": ["WeatherTool"],
    "representativeQueries": ["wind speed in Chicago", "5-day forecast for Seattle"],
}


def codes(report: ConformanceReport) -> set[str]:
    return {f.code for f in report.findings}


# --------------------------------------------------------------------------- #
# Entry rules
# --------------------------------------------------------------------------- #


class TestEntryRules:
    def test_a_well_formed_entry_passes_cleanly(self) -> None:
        report = check_manifest({"entries": [GOOD_ENTRY]})
        assert report.ok, report.describe()
        assert report.warnings == (), "a conformant entry should produce no warnings either"

    @pytest.mark.parametrize("term", ["identifier", "displayName", "type"])
    def test_each_required_term_is_enforced(self, term: str) -> None:
        entry = {k: v for k, v in GOOD_ENTRY.items() if k != term}
        report = check_manifest({"entries": [entry]})
        assert not report.ok
        assert "entry.missing_term" in codes(report)

    def test_both_url_and_data_is_an_error(self) -> None:
        """ARD §4.3: exactly one, mutually exclusive."""
        report = check_manifest({"entries": [{**GOOD_ENTRY, "data": {"a": 1}}]})
        assert not report.ok
        assert "entry.url_and_data" in codes(report)

    def test_neither_url_nor_data_is_an_error(self) -> None:
        entry = {k: v for k, v in GOOD_ENTRY.items() if k != "url"}
        report = check_manifest({"entries": [entry]})
        assert not report.ok
        assert "entry.no_target" in codes(report)

    def test_a_malformed_urn_is_an_error(self) -> None:
        report = check_manifest({"entries": [{**GOOD_ENTRY, "identifier": "some-agent"}]})
        assert not report.ok
        assert "entry.urn_shape" in codes(report)

    def test_a_publisher_that_is_not_a_domain_is_an_error(self) -> None:
        """Appendix C anchors the identifier to DNS; that anchor is the point of
        the form, so a non-domain publisher defeats it."""
        report = check_manifest(
            {"entries": [{**GOOD_ENTRY, "identifier": "urn:air:NotADomain:x:y"}]}
        )
        assert not report.ok
        assert "entry.publisher_not_fqdn" in codes(report)

    def test_a_two_segment_urn_is_an_error(self) -> None:
        report = check_manifest({"entries": [{**GOOD_ENTRY, "identifier": "urn:air:acme.com:x"}]})
        assert not report.ok
        assert "entry.urn_shape" in codes(report)


class TestWarningsAreNotFailures:
    """The distinction the specification draws, preserved all the way out."""

    def test_missing_representative_queries_is_a_warning_not_an_error(self) -> None:
        entry = {k: v for k, v in GOOD_ENTRY.items() if k != "representativeQueries"}
        report = check_manifest({"entries": [entry]})
        assert report.ok, "ARD §D.2 says this must not fail validation"
        assert "entry.no_queries" in codes(report)
        assert len(report.warnings) == 1

    @pytest.mark.parametrize("count", [0, 1, 6, 9])
    def test_a_query_count_outside_two_to_five_warns(self, count: int) -> None:
        entry = {**GOOD_ENTRY, "representativeQueries": [f"query {i}" for i in range(count)]}
        report = check_manifest({"entries": [entry]})
        assert report.ok, "a count outside the guidance is a warning, per §D.2"
        assert "entry.query_count" in codes(report)

    @pytest.mark.parametrize("count", [2, 3, 4, 5])
    def test_a_query_count_inside_the_range_does_not_warn(self, count: int) -> None:
        entry = {**GOOD_ENTRY, "representativeQueries": [f"query {i}" for i in range(count)]}
        assert check_manifest({"entries": [entry]}).warnings == ()

    def test_a_non_media_type_warns_rather_than_failing(self) -> None:
        """The type space is deliberately open (§3.3), so a checker that rejected
        an extension type would defeat the extension mechanism."""
        report = check_manifest({"entries": [{**GOOD_ENTRY, "type": "nonsense"}]})
        assert report.ok
        assert "entry.media_type" in codes(report)

    def test_an_extension_media_type_is_accepted(self) -> None:
        report = check_manifest({"entries": [{**GOOD_ENTRY, "type": "application/vnd.acme+json"}]})
        assert report.warnings == ()

    def test_a_legacy_collections_member_warns_only(self) -> None:
        report = check_manifest({"entries": [GOOD_ENTRY], "collections": []})
        assert report.ok
        assert "manifest.legacy_collections" in codes(report)


class TestPublisherBinding:
    def test_a_contradicting_trust_identity_is_an_error(self) -> None:
        """ARD §4.5.1's defence against namespace squatting, and the one thing a
        manifest can be checked for without a trust framework."""
        entry = {
            **GOOD_ENTRY,
            "identifier": "urn:air:google.com:agent:weather",
            "trustManifest": {"identity": "spiffe://evil.example/agents/x"},
        }
        report = check_manifest({"entries": [entry]})
        assert not report.ok
        assert "entry.publisher_binding" in codes(report)

    def test_a_consistent_trust_identity_is_accepted(self) -> None:
        entry = {
            **GOOD_ENTRY,
            "trustManifest": {"identity": "spiffe://acme.com/agents/weather"},
        }
        assert check_manifest({"entries": [entry]}).ok

    def test_an_absent_identity_is_not_a_squat(self) -> None:
        """Nothing to bind is not a contradiction."""
        entry = {**GOOD_ENTRY, "trustManifest": {"framework": "spiffe"}}
        assert check_manifest({"entries": [entry]}).ok


# --------------------------------------------------------------------------- #
# Manifest shapes
# --------------------------------------------------------------------------- #


class TestManifestShapes:
    def test_a_bare_array_is_accepted(self) -> None:
        """Publishers do both, and the entry model is the same either way."""
        assert check_manifest([GOOD_ENTRY]).ok

    def test_a_manifest_without_entries_is_an_error(self) -> None:
        report = check_manifest({"something": "else"})
        assert not report.ok
        assert "manifest.no_entries" in codes(report)

    def test_a_non_array_entries_member_is_an_error(self) -> None:
        report = check_manifest({"entries": "nope"})
        assert not report.ok
        assert "manifest.entries_type" in codes(report)

    def test_a_non_object_manifest_is_an_error(self) -> None:
        report = check_manifest("not a manifest")
        assert not report.ok
        assert "manifest.not_an_object" in codes(report)

    def test_a_non_object_entry_is_an_error_and_does_not_stop_the_others(self) -> None:
        """One bad entry must not hide the assessment of the rest."""
        report = check_manifest({"entries": ["nope", GOOD_ENTRY]})
        assert not report.ok
        assert "entry.not_an_object" in codes(report)
        assert report.checked == 1, "the good entry was still checked"

    def test_an_empty_manifest_warns(self) -> None:
        report = check_manifest({"entries": []})
        assert report.ok
        assert "manifest.empty" in codes(report)


# --------------------------------------------------------------------------- #
# Our own material has to pass
# --------------------------------------------------------------------------- #


class TestSelfConformance:
    def test_the_demo_agents_are_conformant(self) -> None:
        """The sharpest available cross-check.

        If the checker and our own demo entries disagree, one of them is wrong —
        and a project that ships a conformance checker while failing it is the
        shortest possible route to an embarrassing issue report.
        """
        from agent_ledger.demo import AGENTS, _entry_document

        report = check_manifest([_entry_document(agent) for agent in AGENTS], subject="demo agents")
        assert report.ok, report.describe()
        assert report.warnings == (), report.describe()
        assert report.checked == len(AGENTS)


# --------------------------------------------------------------------------- #
# The official tool
# --------------------------------------------------------------------------- #


class TestOfficialTool:
    def test_an_absent_tool_is_reported_as_127(self) -> None:
        """The shell's own convention for "command not found", so a caller can
        tell it apart from a conformance failure without parsing prose."""
        code, output = run_official("--help", tool="definitely-not-a-real-tool-xyz")
        assert code == 127
        assert "not on PATH" in output
        assert "built-in checks run without it" in output


# --------------------------------------------------------------------------- #
# Report shape
# --------------------------------------------------------------------------- #


class TestReportShape:
    def test_errors_and_warnings_are_separated(self) -> None:
        report = check_manifest({"entries": [{**GOOD_ENTRY, "data": {}}]})
        assert report.errors and not report.warnings
        assert not report.ok

    def test_describe_names_the_subject_and_the_counts(self) -> None:
        report = check_manifest({"entries": [GOOD_ENTRY]}, subject="ard.json")
        assert "ard.json" in report.describe()
        assert "conformant" in report.describe()

    def test_json_output_is_serialisable_and_complete(self) -> None:
        report = check_manifest({"entries": [{**GOOD_ENTRY, "identifier": "bad"}]})
        payload = json.loads(json.dumps(report.to_json()))
        assert payload["ok"] is False
        assert payload["mode"] == "manifest"
        assert payload["errors"]
        assert payload["findings"]

    def test_findings_cite_their_section(self) -> None:
        """A conformance report that cannot be argued with is one nobody trusts."""
        report = check_manifest({"entries": [{**GOOD_ENTRY, "data": {}}]})
        assert any("§4.3" in f.section for f in report.errors)

    def test_a_finding_describes_itself_readably(self) -> None:
        finding = Finding("error", "x", "something is wrong", "entries[0]", "§4.3")
        assert "something is wrong" in finding.describe()
        assert "§4.3" in finding.describe()
        assert "entries[0]" in finding.describe()


# --------------------------------------------------------------------------- #
# Registry probing, against a real local server
# --------------------------------------------------------------------------- #


class TestRegistryProbe:
    """A local HTTP server, because the thing under test *is* the HTTP shape.

    Stubbing the transport here would test the stub. The three endpoints have
    three different required-ness rules, and getting the optional ones wrong —
    reporting a 501 as a failure — is the most common way a conformance tool
    wastes a reader's afternoon.
    """

    @pytest.fixture
    def registry(self):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                return

            def _send(self, code: int, payload: object) -> None:
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                if self.path.endswith("/search"):
                    self._send(
                        200, {"results": [{"identifier": "urn:air:acme.com:agent:x", "score": 91}]}
                    )
                elif self.path.endswith("/explore"):
                    self._send(501, {"error": "not implemented"})
                else:
                    self._send(404, {"error": "no such endpoint"})

            def do_GET(self):  # noqa: N802
                if self.path.endswith("/agents"):
                    self._send(404, {"error": "not implemented"})
                else:
                    self._send(404, {"error": "nope"})

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{server.server_address[1]}"
        server.shutdown()

    def test_a_conformant_registry_passes(self, registry: str) -> None:
        report = check_registry(registry, timeout=5.0)
        assert report.ok, report.describe()
        assert report.mode == "registry"

    def test_a_501_from_explore_is_conformance_not_failure(self, registry: str) -> None:
        """§5.3.3: a registry that does not implement Explore returns 501."""
        report = check_registry(registry, timeout=5.0)
        assert "registry.explore_absent" in {f.code for f in report.findings}
        assert report.ok

    def test_a_404_from_agents_is_conformance_not_failure(self, registry: str) -> None:
        """§5.3.4: deterministic listing is optional."""
        report = check_registry(registry, timeout=5.0)
        assert "registry.agents_absent" in {f.code for f in report.findings}
        assert report.ok

    def test_search_is_probed_as_a_hard_requirement(self) -> None:
        import http.server
        import threading

        class NoSearch(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_POST(self):  # noqa: N802
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):  # noqa: N802
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

        server = http.server.HTTPServer(("127.0.0.1", 0), NoSearch)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            report = check_registry(f"http://127.0.0.1:{server.server_address[1]}", timeout=5.0)
            assert not report.ok
            assert "registry.search_status" in {f.code for f in report.findings}
        finally:
            server.shutdown()

    def test_an_unreachable_registry_is_reported_not_raised(self) -> None:
        report = check_registry("http://127.0.0.1:1", timeout=2.0)
        assert not report.ok
        assert "registry.unreachable" in {f.code for f in report.findings}
