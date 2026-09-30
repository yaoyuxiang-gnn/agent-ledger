"""Adapters and OpenTelemetry export.

Two things this file is careful about.

**It does not pretend the adapters are verified integrations.** AGNTCY, ClawTeam
and OpenClaw each have their own evolving metadata formats and none of their
specifications is vendored here, so the adapters are documented field mappings
with an explicit confidence. ``TestAdaptersAreHonest`` asserts that honesty — a
mapping that claimed more than it checked would be the first thing a reader
tested and the first thing to embarrass the project.

**It does not pretend the OTLP export is an SDK.** It emits OTLP JSON, which is a
documented shape any collector accepting ``application/json`` can ingest, and
which the real SDK can also consume through :func:`to_spans`. The tests check the
*document* rather than a network round trip, because that is what the module
actually promises.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_ledger import HmacSigner, Ledger
from agent_ledger.adapters import (
    ADAPTERS,
    CONFIDENCE_INFERRED,
    adapt,
    agntcy_to_ard,
    clawteam_to_ard,
    openclaw_to_ard,
    to_ard_entry,
)
from agent_ledger.models import DelegationStatus, Receipt
from agent_ledger.otlp import (
    ATTR_PREFIX,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNSET,
    chain_to_trace,
    ledger_to_otlp,
    otlp_payload,
    to_span,
    to_spans,
)


def make_receipt(
    rid: str,
    did: str,
    *,
    task_id: str = "task_1",
    outcome: DelegationStatus = DelegationStatus.COMPLETED,
    parent: str | None = None,
    cost: float = 0.1,
    budget: float | None = 1.0,
    note: str = "",
) -> Receipt:
    return Receipt(
        delegation_id=did,
        task_id=task_id,
        delegate="urn:air:acme.com:agent:legal-review",
        delegated_by="urn:principal:acme.com:alice",
        outcome=outcome,
        receipt_id=rid,
        parent_receipt_id=parent,
        cost_usd=cost,
        budget_usd=budget,
        issued_at=1000.0,
        note=note,
    )


# --------------------------------------------------------------------------- #
# Adapters
# --------------------------------------------------------------------------- #


class TestAdaptersAreHonest:
    def test_every_adapter_declares_that_it_is_unverified(self) -> None:
        """The summary is the deliverable as much as the mapping is.

        An adapter presented as a working integration would be the first claim a
        reader checked, and the first to be wrong.
        """
        for name, adapter in ADAPTERS.items():
            assert "NOT verified" in adapter.summary, name
            assert adapter.expects, f"{name} should say which fields it reads"

    def test_a_mapping_that_lost_something_is_not_declared_confidence(self) -> None:
        result = agntcy_to_ard(
            {
                "name": "Translator",
                "skills": ["translation"],
                "locator": "https://x",
                "publisher": "a.com",
            }
        )
        assert result.confidence == CONFIDENCE_INFERRED
        assert result.problems, "an inferred mapping must say what it could not establish"

    def test_no_publisher_means_no_entry_rather_than_a_guessed_domain(self) -> None:
        """A fabricated domain would pass ARD's shape check and then defeat the
        §4.5.1 authority binding — an entry that *looks* governed and is not."""
        result = to_ard_entry({"name": "Nameless", "capabilities": ["x"]})
        assert result.entry is None
        assert not result.ok
        assert any("publisher" in p for p in result.problems)

    def test_missing_capabilities_are_reported(self) -> None:
        result = to_ard_entry({"name": "X", "publisher": "a.com"})
        assert result.entry is not None
        assert any("capability tokens" in p for p in result.problems)

    def test_a_declared_urn_is_preferred_over_synthesis(self) -> None:
        result = to_ard_entry(
            {"identifier": "urn:air:real.com:agent:thing", "name": "Thing", "capabilities": ["x"]}
        )
        assert result.entry.identifier == "urn:air:real.com:agent:thing"
        assert not any("synthesised" in p for p in result.problems)


class TestKnownAdapters:
    def test_agntcy_maps_a_typical_record(self) -> None:
        result = agntcy_to_ard(
            {
                "name": "Translator",
                "description": "Translates things",
                "skills": [{"name": "translation"}, "localization"],
                "locator": "https://acme.com/a2a",
                "publisher": "acme.com",
            }
        )
        assert result.ok
        assert result.entry.identifier == "urn:air:acme.com:agntcy:translator"
        assert result.entry.capability_set == {"translation", "localization"}
        assert result.entry.url == "https://acme.com/a2a"
        assert result.entry.has_target

    def test_clawteam_reads_agent_name_and_team(self) -> None:
        result = clawteam_to_ard(
            {
                "agent_name": "Reviewer",
                "team": "legal.example",
                "tools": ["contract_review"],
                "endpoint": "https://legal.example/mcp",
            }
        )
        assert result.ok
        assert result.entry.identifier == "urn:air:legal.example:clawteam:reviewer"
        assert "contract_review" in result.entry.capability_set

    def test_openclaw_reads_channel_and_webhook(self) -> None:
        result = openclaw_to_ard(
            {
                "channel": "support",
                "webhook": "https://bot.example/hook",
                "commands": ["triage"],
                "domain": "bot.example",
            }
        )
        assert result.ok
        assert result.entry.identifier == "urn:air:bot.example:openclaw:support"
        assert result.entry.url == "https://bot.example/hook"

    def test_an_explicit_publisher_argument_is_used(self) -> None:
        """The caller often knows the domain from the source it fetched from."""
        result = clawteam_to_ard({"agent_name": "Reviewer", "tools": ["x"]}, publisher="acme.com")
        assert result.entry.identifier.startswith("urn:air:acme.com:")

    def test_a_foreign_identifier_shape_is_not_accepted_as_a_urn(self) -> None:
        result = to_ard_entry(
            {"identifier": "did:web:acme.com:agent", "name": "X", "publisher": "acme.com"}
        )
        assert result.entry.identifier.startswith("urn:air:acme.com:")
        assert any("synthesised" in p for p in result.problems)


class TestAdaptBatch:
    def test_it_drops_unmappable_records_by_default(self) -> None:
        """Carrying them forward would fill the candidate list with entries that
        can never be scored, policy-checked or invoked."""
        results = adapt(
            [{"name": "NoDomain"}, {"name": "Fine", "publisher": "a.com", "capabilities": ["x"]}],
            adapter="agntcy",
        )
        assert len(results) == 1
        assert results[0].ok

    def test_keep_unmappable_surfaces_the_reasons(self) -> None:
        results = adapt([{"name": "NoDomain"}], adapter="agntcy", keep_unmappable=True)
        assert len(results) == 1
        assert results[0].entry is None
        assert results[0].problems

    def test_an_unknown_adapter_names_the_known_ones(self) -> None:
        with pytest.raises(KeyError, match="agntcy"):
            adapt([], adapter="nope")

    def test_a_malformed_record_becomes_a_finding_not_a_crash(self) -> None:
        """A foreign record is data. One that raises must cost its own mapping,
        not the batch."""
        results = adapt(
            [{}, {"name": "Good", "publisher": "a.com", "capabilities": ["x"]}],
            adapter="agntcy",
            keep_unmappable=True,
        )
        assert len(results) == 2
        assert results[1].ok

    def test_an_entry_with_no_identifier_is_not_ok(self) -> None:
        result = to_ard_entry({"name": "NoPublisher", "capabilities": ["x"]})
        assert not result.ok


# --------------------------------------------------------------------------- #
# OpenTelemetry
# --------------------------------------------------------------------------- #


class TestSpanShape:
    def test_a_span_carries_the_otlp_required_fields(self) -> None:
        span = to_span(make_receipt("r1", "d1"))
        assert len(span["traceId"]) == 32
        assert len(span["spanId"]) == 16
        assert span["startTimeUnixNano"].isdigit(), "OTLP wants nanoseconds as a string"
        assert span["kind"] == 1
        assert isinstance(span["attributes"], list)
        assert "code" in span["status"]

    def test_attributes_carry_otlp_type_tags(self) -> None:
        """OTLP refuses an untagged scalar, and a wrong tag is the most common
        way a hand-rolled exporter is silently rejected."""
        span = to_span(make_receipt("r1", "d1", cost=0.25))
        by_key = {a["key"]: a["value"] for a in span["attributes"]}

        assert "doubleValue" in by_key[f"{ATTR_PREFIX}.cost_usd"]
        assert "intValue" in by_key[f"{ATTR_PREFIX}.depth"]
        assert "stringValue" in by_key[f"{ATTR_PREFIX}.receipt_id"]
        assert "boolValue" in by_key[f"{ATTR_PREFIX}.over_budget"]

    def test_the_span_is_named_after_the_delegate(self) -> None:
        """Because "which agent did this" is why a trace is being read."""
        span = to_span(make_receipt("r1", "d1"))
        assert span["name"] == "legal-review"

    def test_nanosecond_precision_is_not_lost_to_a_float(self) -> None:
        receipt = make_receipt("r1", "d1")
        span = to_span(receipt)
        assert span["startTimeUnixNano"] == str(int(1000.0 * 1_000_000_000))

    def test_exporting_twice_produces_the_same_ids(self) -> None:
        """A trace id that changed between runs would make two exports of one
        ledger look like two separate incidents."""
        receipt = make_receipt("r1", "d1")
        assert to_span(receipt)["spanId"] == to_span(receipt)["spanId"]
        assert to_span(receipt)["traceId"] == to_span(receipt)["traceId"]


class TestSpanStatus:
    def test_a_completed_delegation_is_ok(self) -> None:
        assert to_span(make_receipt("r1", "d1"))["status"]["code"] == STATUS_OK

    def test_a_failed_delegation_is_an_error_with_its_note(self) -> None:
        span = to_span(
            make_receipt("r1", "d1", outcome=DelegationStatus.FAILED, note="executor raised")
        )
        assert span["status"]["code"] == STATUS_ERROR
        assert "executor raised" in span["status"]["message"]

    @pytest.mark.parametrize("outcome", [DelegationStatus.PENDING, DelegationStatus.ACCEPTED])
    def test_unsettled_work_is_unset_not_ok(self, outcome: DelegationStatus) -> None:
        """A span claiming success before the work landed is worse than one that
        says nothing."""
        assert to_span(make_receipt("r1", "d1", outcome=outcome))["status"]["code"] == STATUS_UNSET

    def test_a_revoked_delegation_is_terminal_but_not_an_error(self) -> None:
        """A refusal is a recorded *decision*. Marking it an error would paint a
        policy working correctly as a system fault."""
        assert (
            to_span(make_receipt("r1", "d1", outcome=DelegationStatus.REVOKED))["status"]["code"]
            != STATUS_ERROR
        )

    def test_an_overrun_is_recorded_as_an_attribute(self) -> None:
        span = to_span(make_receipt("r1", "d1", cost=9.99))
        by_key = {a["key"]: a["value"] for a in span["attributes"]}
        assert by_key[f"{ATTR_PREFIX}.over_budget"]["boolValue"] is True


class TestTraceStructure:
    def test_a_chain_becomes_one_trace(self) -> None:
        """The observation that makes this module small: a receipt already has a
        parent-child relation, so a delegation chain *is* a trace."""
        root = make_receipt("r1", "d1")
        child = make_receipt("r2", "d2", parent="r1")
        spans = to_spans([root, child])

        assert len(spans) == 2
        assert {s["traceId"] for s in spans} == {to_span(root)["traceId"]}
        assert spans[0]["spanId"] == to_span(root)["spanId"]
        assert spans[1]["parentSpanId"] == to_span(root)["spanId"]

    def test_different_tasks_produce_different_traces(self) -> None:
        a = to_span(make_receipt("r1", "d1", task_id="T1"))
        b = to_span(make_receipt("r2", "d2", task_id="T2"))
        assert a["traceId"] != b["traceId"]

    def test_parents_are_emitted_before_children(self) -> None:
        spans = to_spans(
            [
                make_receipt("r2", "d2", parent="r1"),
                make_receipt("r1", "d1"),
                make_receipt("r3", "d3", parent="r2"),
            ]
        )
        order = [s["spanId"] for s in spans]
        assert order.index(to_span(make_receipt("r1", "d1"))["spanId"]) < order.index(
            to_span(make_receipt("r2", "d2", parent="r1"))["spanId"]
        )

    def test_an_orphan_is_still_emitted_with_its_parent_reference(self) -> None:
        """It is a real hop. Dropping it would make a partial export look
        complete, and dropping its ``parentSpanId`` would lose the one fact that
        says the export is partial — so the reference is kept even though the
        span it points at is not in this batch."""
        from agent_ledger.otlp import _span_id

        spans = to_spans([make_receipt("r2", "d2", parent="missing")])
        assert len(spans) == 1
        assert spans[0]["parentSpanId"] == _span_id("missing")

    def test_a_root_has_no_parent_span(self) -> None:
        spans = to_spans([make_receipt("r1", "d1")])
        assert "parentSpanId" not in spans[0]

    def test_a_child_follows_its_parents_last_transition(self) -> None:
        """A parent's receipt id names a delegation that may appear several
        times; a child follows the parent as it *finished*."""
        from agent_ledger.models import (
            ArdEntry,
            Delegation,
            PolicyDecision,
            PolicyOutcome,
            Task,
        )

        delegation = Delegation(
            task=Task(intent="i", task_id="t1", budget_usd=5.0),
            delegate=ArdEntry(
                identifier="urn:air:a.com:agent:x", display_name="X", type="t", url="https://x"
            ),
            delegated_by="urn:p",
            policy=PolicyDecision(PolicyOutcome.ALLOW, "r"),
        )
        pending = delegation.receipt(status=DelegationStatus.PENDING)
        completed = delegation.receipt(status=DelegationStatus.COMPLETED, cost_usd=1.0)
        child = make_receipt("r_child", "d_child", parent=delegation.receipt_id)

        spans = to_spans([pending, completed, child])
        completed_span = next(
            s
            for s in spans
            if s["status"]["code"] == STATUS_OK and s["spanId"] == to_span(completed)["spanId"]
        )
        child_span = next(s for s in spans if s["name"] == child.delegate.rsplit(":", 1)[-1])
        assert child_span["parentSpanId"] == completed_span["spanId"]

    def test_every_transition_in_a_full_export_gets_its_own_span(self, tmp_path: Path) -> None:
        """Keying spans by receipt id alone collapsed them, silently losing two
        of three lines."""
        signer = HmacSigner(secret=b"k", key_id="k1", principal="urn:p")
        ledger = Ledger(tmp_path / "g.jsonl", ledger_id="L", signer=signer)
        from agent_ledger.models import (
            ArdEntry,
            Delegation,
            PolicyDecision,
            PolicyOutcome,
            Task,
        )

        delegation = Delegation(
            task=Task(intent="i", task_id="t1", budget_usd=5.0),
            delegate=ArdEntry(
                identifier="urn:air:a.com:agent:x", display_name="X", type="t", url="https://x"
            ),
            delegated_by="urn:p",
            policy=PolicyDecision(PolicyOutcome.ALLOW, "r"),
        )
        ledger.receipt_delegation(delegation, status=DelegationStatus.PENDING)
        ledger.receipt_delegation(delegation, status=DelegationStatus.ACCEPTED)
        ledger.receipt_delegation(delegation, status=DelegationStatus.COMPLETED, cost_usd=1.0)

        spans = to_spans(ledger.lines)
        assert len(spans) == 3
        assert len({s["spanId"] for s in spans}) == 3, "distinct span ids"
        assert len({s["traceId"] for s in spans}) == 1, "one delegation, one trace"

    def test_chain_to_trace_matches_to_spans(self) -> None:
        from agent_ledger.models import DelegationChain

        chain = DelegationChain((make_receipt("r1", "d1"), make_receipt("r2", "d2", parent="r1")))
        assert chain_to_trace(chain) == to_spans(chain.receipts)


class TestOtlpPayload:
    def test_the_payload_has_the_resource_spans_shape(self) -> None:
        payload = otlp_payload([make_receipt("r1", "d1")], service_name="grid")
        resource_spans = payload["resourceSpans"]
        assert len(resource_spans) == 1
        resource = resource_spans[0]["resource"]["attributes"]
        assert {"key": "service.name", "value": {"stringValue": "grid"}} in resource
        scope = resource_spans[0]["scopeSpans"][0]
        assert scope["scope"]["name"] == "agent_ledger"
        assert len(scope["spans"]) == 1

    def test_the_payload_is_json_serialisable(self) -> None:
        """The whole point of emitting JSON rather than protobuf."""
        payload = otlp_payload([make_receipt("r1", "d1")])
        assert json.loads(json.dumps(payload))["resourceSpans"]

    def test_a_ledger_exports_its_current_state_only_by_default(self, tmp_path: Path) -> None:
        """The ledger keeps every transition, so exporting all lines would emit
        three spans for one delegation, two describing it at an earlier moment."""
        signer = HmacSigner(secret=b"k", key_id="k1", principal="urn:p")
        ledger = Ledger(tmp_path / "g.jsonl", ledger_id="L", signer=signer)
        from agent_ledger.models import (
            ArdEntry,
            Delegation,
            PolicyDecision,
            PolicyOutcome,
            Task,
        )

        delegation = Delegation(
            task=Task(intent="i", task_id="t1", budget_usd=5.0),
            delegate=ArdEntry(
                identifier="urn:air:a.com:agent:x", display_name="X", type="t", url="https://x"
            ),
            delegated_by="urn:p",
            policy=PolicyDecision(PolicyOutcome.ALLOW, "r"),
        )
        ledger.receipt_delegation(delegation, status=DelegationStatus.PENDING)
        ledger.receipt_delegation(delegation, status=DelegationStatus.ACCEPTED)
        ledger.receipt_delegation(delegation, status=DelegationStatus.COMPLETED, cost_usd=1.0)
        assert len(ledger.lines) == 3

        current = ledger_to_otlp(ledger)
        spans = current["resourceSpans"][0]["scopeSpans"][0]["spans"]
        assert len(spans) == 1, "one span per hop, not one per transition"

        everything = ledger_to_otlp(ledger, current_only=False)
        assert len(everything["resourceSpans"][0]["scopeSpans"][0]["spans"]) == 3

    def test_the_ledger_id_travels_as_a_resource_attribute(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "g.jsonl", ledger_id="acme-prod")
        ledger.record(make_receipt("r1", "d1"))
        payload = ledger_to_otlp(ledger)
        resource = payload["resourceSpans"][0]["resource"]["attributes"]
        assert any(a["value"].get("stringValue") == "acme-prod" for a in resource)

    def test_signed_receipts_export_their_provenance(self) -> None:
        """A trace that cannot say whether a receipt was signed cannot answer the
        question the receipt exists for."""
        receipt = Receipt(
            **{
                **{f: getattr(make_receipt("r1", "d1"), f) for f in Receipt.__slots__},
                "signature": "deadbeef",
                "key_id": "k1",
                "alg": "hmac-sha256",
                "signer": "urn:principal:acme.com:alice",
            }
        )
        by_key = {a["key"]: a["value"] for a in to_span(receipt)["attributes"]}
        assert by_key[f"{ATTR_PREFIX}.key_id"]["stringValue"] == "k1"
        assert by_key[f"{ATTR_PREFIX}.signer"]["stringValue"] == "urn:principal:acme.com:alice"

    def test_an_execution_record_exports(self) -> None:
        from agent_ledger.models import ExecutionRecord

        receipt = Receipt(
            **{
                **{f: getattr(make_receipt("r1", "d1"), f) for f in Receipt.__slots__},
                "execution": ExecutionRecord(task_ref="remote-1", state="TASK_STATE_COMPLETED"),
            }
        )
        by_key = {a["key"]: a["value"] for a in to_span(receipt)["attributes"]}
        assert by_key[f"{ATTR_PREFIX}.execution.task_ref"]["stringValue"] == "remote-1"


class TestPostOtlpFailsQuietly:
    def test_an_unreachable_collector_returns_false(self) -> None:
        """Telemetry that can fail a delegation is worse than telemetry that is
        missing, so this reports rather than raises."""
        from agent_ledger.otlp import post_otlp

        assert post_otlp({"resourceSpans": []}, "http://127.0.0.1:1/v1/traces") is False
