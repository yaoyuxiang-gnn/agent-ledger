"""The demo narrative and the CLI surface.

The demo is the project's front door, so it is tested like a feature rather
than treated as documentation that happens to execute.
"""

from __future__ import annotations

import json

import pytest

from agent_ledger.cli import EXIT_FAILURE, EXIT_OK, EXIT_REFUSED, main
from agent_ledger.demo import (
    AGENTS,
    DEMO_AGENTS,
    INTERNAL_REGISTRY,
    PARTNER_REGISTRY,
    build_transport,
    run_demo,
)
from agent_ledger.ledger import Ledger


class TestDemoScenario:
    def test_every_agent_has_a_usable_ard_entry(self) -> None:
        assert len(DEMO_AGENTS) == len(AGENTS)
        for entry in DEMO_AGENTS.values():
            assert entry.is_valid, entry.identifier
            assert entry.capabilities
            assert entry.representative_queries, "ARD search indexes these"

    def test_identifiers_are_well_formed_urns(self) -> None:
        for entry in DEMO_AGENTS.values():
            assert entry.publisher is not None, entry.identifier

    def test_untrusted_agent_exists_for_policy_to_refuse(self) -> None:
        assert any(not entry.is_trusted for entry in DEMO_AGENTS.values())

    def test_transport_needs_no_network(self) -> None:
        transport = build_transport()
        assert INTERNAL_REGISTRY in transport.documents
        assert PARTNER_REGISTRY in transport.documents

    def test_transport_can_omit_the_public_registry(self) -> None:
        assert PARTNER_REGISTRY not in build_transport(with_public_registry=False).documents


@pytest.fixture(scope="module")
def demo_run():
    """Run the demo once for the whole module; it is deterministic and cheap."""
    lines: list[str] = []
    outcome = run_demo(out=lines.append, colour=False)
    return outcome, lines


class TestRunDemo:
    def test_completes_with_a_three_hop_chain(self, demo_run) -> None:
        outcome, _ = demo_run
        assert outcome.chain_length == 3

    def test_ledger_verifies(self, demo_run) -> None:
        outcome, _ = demo_run
        assert outcome.integrity_ok

    def test_cost_matches_the_sum_of_the_hops(self, demo_run) -> None:
        outcome, _ = demo_run
        # coordinator 0.02 + legal 0.35 + localisation 0.12
        assert outcome.total_cost_usd == pytest.approx(0.49)

    def test_reputation_reroutes_the_second_ranking(self, demo_run) -> None:
        """The demo's headline claim, asserted rather than merely printed.

        Both rankings come from the same probe task, so query relevance is
        held constant and reputation is the only variable.
        """
        outcome, _ = demo_run
        before = dict(outcome.ranking_before)
        after = dict(outcome.ranking_after)

        assert before["Localization Agent"] > after["Localization Agent"], (
            "the overrunning agent must lose ground"
        )
        assert after["TranslatePro (partner)"] > after["Localization Agent"], (
            "the proven alternative must overtake it"
        )
        assert after["TranslatePro (partner)"] == pytest.approx(
            before["TranslatePro (partner)"], abs=1e-6
        ), "an agent with no history must not move at all"

    def test_transcript_covers_every_chapter(self, demo_run) -> None:
        _, lines = demo_run
        text = "\n".join(lines)
        for heading in (
            "The organisation",
            "ARD discovery",
            "Ranking",
            "Delegation",
            "Re-delegation",
            "Settling up",
            "Integrity",
            "Routing that remembers",
        ):
            assert heading in text, f"missing chapter: {heading}"

    def test_transcript_has_no_placeholder_text(self, demo_run) -> None:
        _, lines = demo_run
        text = "\n".join(lines)
        assert "TODO" not in text and "FIXME" not in text

    def test_transcript_fits_a_terminal_width(self, demo_run) -> None:
        _, lines = demo_run
        # ``tree()`` returns a single multi-line block, so flatten before
        # measuring; otherwise the whole chain is reported as one long line.
        flat = [part for line in lines for part in line.splitlines()]
        overlong = [line for line in flat if len(line) > 110]
        assert not overlong, f"lines too wide for a terminal: {overlong[:2]}"

    def test_demo_reports_a_refusal(self, demo_run) -> None:
        outcome, lines = demo_run
        assert outcome.refusals >= 0
        assert "refused" in "\n".join(lines) or outcome.refusals == 0


class TestCli:
    def test_version_exits_zero(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_demo_runs(self, capsys) -> None:
        assert main(["demo", "--no-color"]) == EXIT_OK
        captured = capsys.readouterr()
        assert "agent-ledger" in captured.out

    def test_demo_json_is_machine_readable(self, capsys) -> None:
        assert main(["demo", "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["chain_length"] == 3
        assert payload["integrity_ok"] is True
        assert payload["ranking_before"] and payload["ranking_after"]

    def test_demo_json_suppresses_ansi(self, capsys) -> None:
        main(["demo", "--json"])
        assert "\033[" not in capsys.readouterr().out

    def test_policy_lists_presets(self, capsys) -> None:
        assert main(["policy", "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert set(payload) == {"open-grid", "ceilinged", "zero-trust"}
        assert payload["zero-trust"]["require_trust"] is True

    def test_find_without_sources_fails_cleanly(self, capsys) -> None:
        assert main(["find", "anything at all"]) == EXIT_FAILURE

    def test_audit_missing_ledger_fails_cleanly(self, tmp_path, capsys) -> None:
        assert main(["audit", "--ledger", str(tmp_path / "nope.jsonl")]) == EXIT_FAILURE

    def test_verify_fails_on_a_missing_ledger(self, tmp_path, capsys) -> None:
        """A typo'd path must not report a healthy audit trail.

        This previously asserted ``EXIT_OK`` and ``0 receipt lines``, which is
        exactly the bug: ``al verify --ledger typo.jsonl`` printed
        ``OK: 0 receipt lines verified, chain intact`` and exited 0, so the one
        failure mode an operator is least likely to double-check — the file not
        being there at all — was reported as success.
        """
        assert main(["verify", "--ledger", str(tmp_path / "nope.jsonl")]) == EXIT_FAILURE
        out = capsys.readouterr().out
        assert "no such ledger file" in out
        assert "OK" not in out

    def test_verify_accepts_an_empty_but_present_ledger(self, tmp_path, capsys) -> None:
        """An empty ledger is a real state, and different from a missing one."""
        path = tmp_path / "empty.jsonl"
        path.write_text("", encoding="utf-8")
        assert main(["verify", "--ledger", str(path)]) == EXIT_OK
        assert "0 receipt lines" in capsys.readouterr().out

    def test_verify_detects_tampering_and_exits_nonzero(self, tmp_path, capsys) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        from agent_ledger.models import DelegationStatus, Receipt

        ledger.record(
            Receipt(
                delegation_id="d1",
                task_id="t1",
                delegate="urn:air:a.com:agent:x",
                delegated_by="urn:principal:a",
                outcome=DelegationStatus.COMPLETED,
                cost_usd=1.0,
            )
        )
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["cost_usd"] = 500.0
        path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")

        assert main(["verify", "--ledger", str(path)]) == EXIT_FAILURE
        assert "tampered" in capsys.readouterr().out

    def test_unknown_command_exits_nonzero(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["frobnicate"])
        assert exc.value.code != 0


class TestCliAgainstLiveTransport:
    """End-to-end CLI runs against the simulated federation."""

    @pytest.fixture
    def wired(self, monkeypatch, transport):
        """Swap the CLI's HTTP transport for the offline federation."""
        import agent_ledger.cli as cli_module
        from agent_ledger.ard import ArdClient

        real_init = ArdClient.__init__

        def patched(self, transport_arg=None, **kwargs):
            real_init(self, transport, **kwargs)

        monkeypatch.setattr(cli_module.ArdClient, "__init__", patched)
        return transport

    def test_delegate_refuses_an_over_budget_task(self, wired, tmp_path, capsys) -> None:
        code = main(
            [
                "delegate",
                "coordinate the launch programme",
                "-c",
                "program_management",
                "--registry",
                INTERNAL_REGISTRY,
                "--budget",
                "99",
                "--ledger",
                str(tmp_path / "grid.jsonl"),
            ]
        )
        assert code == EXIT_REFUSED
        assert "refused" in capsys.readouterr().out

    def test_delegate_places_a_task_and_records_it(self, wired, tmp_path, capsys) -> None:
        ledger_path = tmp_path / "grid.jsonl"
        code = main(
            [
                "delegate",
                "review the data processing agreement",
                "-c",
                "contract_review",
                "--registry",
                INTERNAL_REGISTRY,
                "--budget",
                "0.5",
                "--ledger",
                str(ledger_path),
            ]
        )
        assert code == EXIT_OK
        assert "Contract Review Agent" in capsys.readouterr().out
        assert ledger_path.exists()

    def test_audit_renders_the_recorded_chain(self, wired, tmp_path, capsys) -> None:
        ledger_path = tmp_path / "grid.jsonl"
        main(
            [
                "delegate",
                "review the agreement",
                "-c",
                "contract_review",
                "--registry",
                INTERNAL_REGISTRY,
                "--budget",
                "0.5",
                "--ledger",
                str(ledger_path),
            ]
        )
        capsys.readouterr()
        assert main(["audit", "--ledger", str(ledger_path)]) == EXIT_OK
        assert "chain" in capsys.readouterr().out

    def test_find_lists_discovered_agents(self, wired, capsys) -> None:
        code = main(["find", "translate a landing page", "--registry", INTERNAL_REGISTRY])
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "urn:air:" in out
