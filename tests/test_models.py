"""Value objects: ARD entry rules, identifiers, digests, chains."""

from __future__ import annotations

import pytest

from agent_ledger.models import (
    ArdEntry,
    DelegationChain,
    DelegationStatus,
    Receipt,
    Task,
    canonical_json,
    content_digest,
    parse_ard_urn,
)


class TestArdUrn:
    def test_parses_well_formed_identifier(self) -> None:
        assert parse_ard_urn("urn:air:acme.com:server:weather") == (
            "acme.com",
            "server",
            "weather",
        )

    @pytest.mark.parametrize(
        "identifier",
        [
            "https://acme.com/agents/weather",
            "urn:air:acme.com:weather",  # too few segments
            "urn:air:acme.com:a:b:c",  # too many segments
            "urn:air:acme.com::weather",  # empty namespace
            "",
        ],
    )
    def test_rejects_malformed_identifiers(self, identifier: str) -> None:
        assert parse_ard_urn(identifier) is None


class TestArdEntry:
    def test_valid_entry_requires_exactly_one_target(self) -> None:
        base = {
            "identifier": "urn:air:acme.com:agent:x",
            "displayName": "X",
            "type": "application/a2a-agent-card+json",
        }
        assert ArdEntry.from_ard({**base, "url": "https://x"}).is_valid
        assert ArdEntry.from_ard({**base, "data": {"a": 1}}).is_valid
        # Neither, or both, violates ARD 4.3.
        assert not ArdEntry.from_ard(base).is_valid
        assert not ArdEntry.from_ard({**base, "url": "https://x", "data": {}}).is_valid

    def test_capabilities_are_case_insensitive_set(self) -> None:
        entry = ArdEntry.from_ard(
            {
                "identifier": "urn:air:acme.com:agent:x",
                "displayName": "X",
                "type": "application/a2a-agent-card+json",
                "url": "https://x",
                "capabilities": ["Translation", "LEGAL_REVIEW"],
            }
        )
        assert entry.capability_set == frozenset({"translation", "legal_review"})

    def test_single_string_capability_is_tolerated(self) -> None:
        entry = ArdEntry.from_ard(
            {
                "identifier": "urn:air:acme.com:agent:x",
                "displayName": "X",
                "type": "application/a2a-agent-card+json",
                "url": "https://x",
                "capabilities": "translation",
            }
        )
        assert entry.capabilities == ("translation",)

    def test_unknown_extension_terms_do_not_break_parsing(self) -> None:
        """ARD 4.1: entries may carry terms from other namespaces."""
        entry = ArdEntry.from_ard(
            {
                "identifier": "urn:air:acme.com:agent:x",
                "displayName": "X",
                "type": "application/a2a-agent-card+json",
                "url": "https://x",
                "acme:serviceTier": "enterprise",
            }
        )
        assert entry.is_valid

    def test_roundtrip_preserves_core_terms(self) -> None:
        entry = ArdEntry.from_ard(
            {
                "identifier": "urn:air:acme.com:agent:x",
                "displayName": "X",
                "type": "application/a2a-agent-card+json",
                "url": "https://x",
                "capabilities": ["a"],
                "representativeQueries": ["do a thing"],
            }
        )
        again = ArdEntry.from_ard(entry.to_ard())
        assert again.identifier == entry.identifier
        assert again.capabilities == entry.capabilities
        assert again.representative_queries == entry.representative_queries

    def test_trust_presence_is_not_verification(self) -> None:
        entry = ArdEntry.from_ard(
            {
                "identifier": "urn:air:acme.com:agent:x",
                "displayName": "X",
                "type": "application/a2a-agent-card+json",
                "url": "https://x",
                "trustManifest": {"identity": "spiffe://acme.com/x"},
            }
        )
        assert entry.is_trusted  # a claim exists; verification is the registry's job


class TestDigests:
    def test_canonical_json_is_order_independent(self) -> None:
        assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})

    def test_digest_is_stable_and_prefixed(self) -> None:
        digest = content_digest({"a": 1})
        assert digest.startswith("sha256:")
        assert digest == content_digest({"a": 1})

    def test_digest_changes_with_content(self) -> None:
        assert content_digest({"a": 1}) != content_digest({"a": 2})


class TestTask:
    def test_child_records_parent(self) -> None:
        parent = Task(intent="root", required_capabilities=("a",))
        child = parent.child("sub work", ["b"])
        assert child.parent_delegation == parent.task_id
        assert child.task_id != parent.task_id
        assert child.required_capabilities == ("b",)

    def test_expired_reflects_deadline(self) -> None:
        assert not Task(intent="x").expired
        assert Task(intent="x", deadline_epoch=1.0).expired


class TestReceipt:
    def _receipt(self, **overrides: object) -> Receipt:
        base = dict(
            delegation_id="dlg_1",
            task_id="task_1",
            delegate="urn:air:acme.com:agent:x",
            delegated_by="urn:principal:alice",
            outcome=DelegationStatus.COMPLETED,
            cost_usd=0.25,
            budget_usd=0.5,
        )
        base.update(overrides)
        return Receipt(**base)  # type: ignore[arg-type]

    def test_digest_is_reproducible_for_identical_bodies(self) -> None:
        first = Receipt(
            receipt_id="rcpt_fixed",
            issued_at=1000.0,
            delegation_id="dlg_1",
            task_id="task_1",
            delegate="urn:air:acme.com:agent:x",
            delegated_by="urn:principal:alice",
            outcome=DelegationStatus.COMPLETED,
        )
        second = Receipt(
            receipt_id="rcpt_fixed",
            issued_at=1000.0,
            delegation_id="dlg_1",
            task_id="task_1",
            delegate="urn:air:acme.com:agent:x",
            delegated_by="urn:principal:alice",
            outcome=DelegationStatus.COMPLETED,
        )
        assert first.digest() == second.digest()

    def test_any_field_change_changes_the_digest(self) -> None:
        assert self._receipt().digest() != self._receipt(cost_usd=0.26).digest()

    def test_over_budget_detection(self) -> None:
        assert not self._receipt().over_budget
        assert self._receipt(cost_usd=0.75).over_budget

    def test_uncapped_receipt_is_never_over_budget(self) -> None:
        assert not self._receipt(budget_usd=None, cost_usd=999.0).over_budget

    def test_json_roundtrip_preserves_identity_and_digest(self) -> None:
        original = self._receipt()
        restored = Receipt.from_json(original.to_json())
        assert restored.receipt_id == original.receipt_id
        assert restored.digest() == original.digest()


class TestDelegationChain:
    def _chain(self, costs: list[float], depths: list[int] | None = None) -> DelegationChain:
        depths = depths or list(range(len(costs)))
        return DelegationChain(
            tuple(
                Receipt(
                    delegation_id=f"dlg_{i}",
                    task_id="t",
                    delegate=f"urn:air:acme.com:agent:a{i}",
                    delegated_by="urn:principal:alice",
                    outcome=DelegationStatus.COMPLETED,
                    cost_usd=cost,
                    depth=depth,
                )
                for i, (cost, depth) in enumerate(zip(costs, depths, strict=True))
            )
        )

    def test_total_cost_sums_hops(self) -> None:
        assert self._chain([0.1, 0.2, 0.3]).total_cost == pytest.approx(0.6)

    def test_root_and_leaf(self) -> None:
        chain = self._chain([0.1, 0.2])
        assert chain.root is not None and chain.root.delegate.endswith("a0")
        assert chain.leaf is not None and chain.leaf.delegate.endswith("a1")

    def test_clean_chain_has_no_violations(self) -> None:
        assert self._chain([0.1]).is_clean

    def test_overrun_is_reported(self) -> None:
        chain = DelegationChain(
            (
                Receipt(
                    delegation_id="d",
                    task_id="t",
                    delegate="urn:air:acme.com:agent:a",
                    delegated_by="urn:principal:alice",
                    outcome=DelegationStatus.COMPLETED,
                    cost_usd=9.0,
                    budget_usd=1.0,
                ),
            )
        )
        assert not chain.is_clean
        assert any("over authorised" in v for v in chain.violations())

    def test_failure_and_revocation_are_violations(self) -> None:
        for status in (DelegationStatus.FAILED, DelegationStatus.REVOKED):
            chain = DelegationChain(
                (
                    Receipt(
                        delegation_id="d",
                        task_id="t",
                        delegate="urn:air:acme.com:agent:a",
                        delegated_by="urn:principal:alice",
                        outcome=status,
                    ),
                )
            )
            assert not chain.is_clean

    def test_empty_chain_is_safe(self) -> None:
        empty = DelegationChain()
        assert len(empty) == 0
        assert empty.root is None
        assert empty.total_cost == 0.0
        assert empty.is_clean

    def test_max_depth(self) -> None:
        assert self._chain([0.1, 0.2, 0.3], [0, 1, 2]).max_depth == 2
