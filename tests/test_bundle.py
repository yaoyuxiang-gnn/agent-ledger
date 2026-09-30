"""Bundle exchange: evidence that crosses an organisational boundary.

The organising idea is that two organisations do not need to write to one mutable
store; they need to show each other evidence each can check without trusting the
other's storage. So a bundle is a ledger excerpt plus a manifest, and it is
verified by running the *same* checks a local ledger gets — reused rather than
reimplemented, because a second verifier would be a second home for the same
class of bug.

Two tests in here are unusual and deliberate:

* ``test_a_shortened_bundle_still_verifies_without_the_head`` asserts a
  **failure to detect**, because that limitation is the whole reason
  ``expected_head`` exists. A test suite that only proved what works would let a
  reader assume completeness is covered.
* ``test_an_unsigned_bundle_is_rejected_by_default`` asserts the opposite default
  from the local-ledger path, and the asymmetry is the point: a local ledger may
  predate signing, but a bundle is evidence *offered to someone else*.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_ledger import HmacSigner, KeyRing, Ledger
from agent_ledger.bundle import (
    BUNDLE_FORMAT,
    Bundle,
    bundle_receipts,
    export_bundle,
    read_bundle,
    verify_bundle,
    write_bundle,
)
from agent_ledger.models import DelegationStatus, Receipt

ALICE = "urn:principal:acme.com:alice"
MALLORY = "urn:principal:evil.example:mallory"
SECRET = b"inter-org-secret"


def make_receipt(rid: str, did: str, *, cost: float = 0.1) -> Receipt:
    return Receipt(
        delegation_id=did,
        task_id="t1",
        delegate="urn:air:acme.com:agent:x",
        delegated_by=ALICE,
        outcome=DelegationStatus.COMPLETED,
        receipt_id=rid,
        cost_usd=cost,
        budget_usd=1.0,
        issued_at=1000.0,
    )


def sender_ledger(tmp_path: Path, *receipts: Receipt, ledger_id: str = "acme-prod") -> Ledger:
    signer = HmacSigner(secret=SECRET, key_id="k1", principal=ALICE)
    ledger = Ledger(tmp_path / "sender.jsonl", ledger_id=ledger_id, signer=signer)
    for receipt in receipts or (make_receipt("r1", "d1"),):
        ledger.record(receipt)
    return ledger


def receiver_keyring() -> KeyRing:
    """What the receiving organisation pinned, from a channel it already trusts."""
    return KeyRing().add("k1", HmacSigner(secret=SECRET, key_id="k1"), principal=ALICE)


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #


class TestExportAndVerify:
    def test_a_bundle_verifies_on_the_receiving_side(self, tmp_path: Path) -> None:
        bundle = export_bundle(sender_ledger(tmp_path))
        result = verify_bundle(bundle, keyring=receiver_keyring())
        assert result.ok, result.describe()
        assert result.receipts == 1
        assert result.signed == 1
        assert result.ledger_id == "acme-prod"

    def test_a_bundle_round_trips_through_a_file(self, tmp_path: Path) -> None:
        bundle = export_bundle(sender_ledger(tmp_path))
        path = write_bundle(bundle, tmp_path / "out" / "bundle.json")
        reloaded = read_bundle(path)

        assert reloaded.lines == bundle.lines
        assert reloaded.head == bundle.head
        assert verify_bundle(reloaded, keyring=receiver_keyring()).ok

    def test_lines_are_stored_verbatim(self, tmp_path: Path) -> None:
        """Re-serialising would be a silent opportunity to change a byte, and
        the digest is over bytes."""
        ledger = sender_ledger(tmp_path)
        bundle = export_bundle(ledger)
        stored = [json.dumps(r.to_json(), sort_keys=True) for r in ledger.lines]
        assert list(bundle.lines) == stored

    def test_a_subset_export_carries_whole_delegations(self, tmp_path: Path) -> None:
        """A partner needs the chain behind one piece of work, not the ledger.

        Selecting by receipt id takes every transition of that delegation, so the
        chain the receiver reconstructs is complete rather than one frame of it.
        """
        ledger = sender_ledger(tmp_path, make_receipt("r1", "d1"), make_receipt("r2", "d2"))
        bundle = export_bundle(ledger, receipt_ids=["r2"])
        assert len(bundle.lines) == 1
        assert verify_bundle(bundle, keyring=receiver_keyring()).ok

    def test_the_note_and_metadata_travel(self, tmp_path: Path) -> None:
        bundle = export_bundle(
            sender_ledger(tmp_path), note="for the audit", metadata={"case": "X-1"}
        )
        reloaded = Bundle.from_json(bundle.to_json())
        assert reloaded.note == "for the audit"
        assert reloaded.metadata == {"case": "X-1"}

    def test_receipts_can_be_recovered_after_verification(self, tmp_path: Path) -> None:
        bundle = export_bundle(sender_ledger(tmp_path))
        receipts = bundle_receipts(bundle)
        assert [r.receipt_id for r in receipts] == ["r1"]


# --------------------------------------------------------------------------- #
# What a bundle must refuse
# --------------------------------------------------------------------------- #


class TestBundleTampering:
    def _tampered(self, tmp_path: Path, mutate) -> Bundle:
        bundle = export_bundle(sender_ledger(tmp_path))
        rows = [json.loads(line) for line in bundle.lines]
        mutate(rows)
        return Bundle(
            ledger_id=bundle.ledger_id,
            head=bundle.head,
            lines=tuple(json.dumps(r, sort_keys=True) for r in rows),
        )

    def test_an_edited_line_is_rejected(self, tmp_path: Path) -> None:
        def inflate(rows: list[dict]) -> None:
            rows[0]["cost_usd"] = 999.0

        result = verify_bundle(self._tampered(tmp_path, inflate), keyring=receiver_keyring())
        assert not result.ok
        assert any("tampered" in p for p in result.problems)

    def test_a_removed_line_is_rejected(self, tmp_path: Path) -> None:
        ledger = sender_ledger(
            tmp_path, make_receipt("r1", "d1"), make_receipt("r2", "d2"), make_receipt("r3", "d3")
        )
        bundle = export_bundle(ledger)
        trimmed = Bundle(
            ledger_id=bundle.ledger_id, head=bundle.head, lines=(bundle.lines[0], bundle.lines[2])
        )
        result = verify_bundle(trimmed, keyring=receiver_keyring())
        assert not result.ok
        assert any("chain link" in p for p in result.problems)

    def test_a_reordered_bundle_is_rejected(self, tmp_path: Path) -> None:
        ledger = sender_ledger(tmp_path, make_receipt("r1", "d1"), make_receipt("r2", "d2"))
        bundle = export_bundle(ledger)
        swapped = Bundle(
            ledger_id=bundle.ledger_id, head=bundle.head, lines=(bundle.lines[1], bundle.lines[0])
        )
        assert not verify_bundle(swapped, keyring=receiver_keyring()).ok

    def test_a_line_signed_by_an_untrusted_key_is_rejected(self, tmp_path: Path) -> None:
        """The default that makes the exchange mean something.

        A bundle from a stranger, or from someone whose key the receiver never
        pinned, proves nothing about authorship — and this library is not in the
        business of accepting "a key I have never seen signed this" as evidence.
        """
        bundle = export_bundle(sender_ledger(tmp_path))
        result = verify_bundle(bundle, keyring=KeyRing())
        assert not result.ok
        assert any("untrusted key" in p for p in result.problems)

    def test_a_forged_principal_claim_is_rejected(self, tmp_path: Path) -> None:
        bundle = self._tampered(tmp_path, lambda rows: rows[0].update(signer=MALLORY))
        result = verify_bundle(bundle, keyring=receiver_keyring())
        assert not result.ok
        assert any("principal mismatch" in p for p in result.problems)

    def test_a_revoked_key_is_rejected(self, tmp_path: Path) -> None:
        bundle = export_bundle(sender_ledger(tmp_path))
        ring = receiver_keyring().revoke("k1", note="key compromised")
        result = verify_bundle(bundle, keyring=ring)
        assert not result.ok
        assert any("revoked" in p for p in result.problems)

    def test_a_bundle_from_the_wrong_ledger_is_rejected(self, tmp_path: Path) -> None:
        """Matters when a bundle is dropped into an existing store."""
        bundle = export_bundle(sender_ledger(tmp_path, ledger_id="acme-prod"))
        result = verify_bundle(
            bundle, keyring=receiver_keyring(), expected_ledger_id="partner-prod"
        )
        assert not result.ok
        assert any("expected" in p for p in result.problems)


# --------------------------------------------------------------------------- #
# Completeness, and the honest limit
# --------------------------------------------------------------------------- #


class TestCompleteness:
    def test_a_shortened_bundle_is_caught_by_an_expected_head(self, tmp_path: Path) -> None:
        ledger = sender_ledger(
            tmp_path, make_receipt("r1", "d1"), make_receipt("r2", "d2"), make_receipt("r3", "d3")
        )
        bundle = export_bundle(ledger)
        expected_head = bundle.head

        shortened = Bundle(ledger_id=bundle.ledger_id, head=expected_head, lines=bundle.lines[:2])
        result = verify_bundle(shortened, keyring=receiver_keyring(), expected_head=expected_head)
        assert not result.ok
        assert any("tail is missing" in p for p in result.problems)

    def test_a_shortened_bundle_still_verifies_without_the_head(self, tmp_path: Path) -> None:
        """**A failure to detect, asserted on purpose.**

        A truncated prefix is a perfectly consistent chain, and the manifest's own
        head is written by whoever truncated it. So without an independently
        obtained head, this library cannot tell. That is not a defect to fix — it
        is why `--expect-head` exists and why the export command prints the head
        with a note to send it over another channel.

        A test suite that only proved what works would let a reader assume
        completeness was covered.
        """
        ledger = sender_ledger(
            tmp_path, make_receipt("r1", "d1"), make_receipt("r2", "d2"), make_receipt("r3", "d3")
        )
        bundle = export_bundle(ledger)

        # The sender truncates *and* rewrites the manifest to match.
        truncated_lines = bundle.lines[:2]
        reloaded = Ledger(ledger_id=bundle.ledger_id, keyring=receiver_keyring())
        for line in truncated_lines:
            reloaded.backend.append(line)
        reloaded._reload()  # noqa: SLF001
        shortened = Bundle(
            ledger_id=bundle.ledger_id,
            head=reloaded.verify().chain_head,  # the forger's own head
            lines=truncated_lines,
        )

        result = verify_bundle(shortened, keyring=receiver_keyring())
        assert result.ok, "documented: without a trusted head, truncation is invisible"

    def test_a_manifest_that_disagrees_with_its_lines_is_rejected(self, tmp_path: Path) -> None:
        """Not a completeness guarantee, but an inconsistency with no innocent
        explanation."""
        bundle = export_bundle(sender_ledger(tmp_path))
        lying = Bundle(ledger_id=bundle.ledger_id, head="sha256:" + "0" * 64, lines=bundle.lines)
        result = verify_bundle(lying, keyring=receiver_keyring())
        assert not result.ok
        assert any("manifest claims head" in p for p in result.problems)

    def test_the_head_is_reported_back_for_comparison(self, tmp_path: Path) -> None:
        bundle = export_bundle(sender_ledger(tmp_path))
        result = verify_bundle(bundle, keyring=receiver_keyring())
        assert result.head == bundle.head
        assert result.head_matches is None, "no expectation was supplied"


# --------------------------------------------------------------------------- #
# Provenance defaults
# --------------------------------------------------------------------------- #


class TestSignatureDefaults:
    def test_an_unsigned_bundle_is_rejected_by_default(self, tmp_path: Path) -> None:
        """The asymmetric default, and why it is asymmetric.

        A local ledger may legitimately predate signing, so demanding signatures
        there would declare existing users' data corrupt — it reports *unchained*
        / *unsigned* and lets the operator decide. A bundle is evidence offered to
        someone else, and an unsigned bundle proves nothing about who wrote it,
        so accepting one by default would make the entire exchange decorative.
        """
        ledger = Ledger(tmp_path / "unsigned.jsonl", ledger_id="acme-prod")
        ledger.record(make_receipt("r1", "d1"))
        bundle = export_bundle(ledger)

        assert not verify_bundle(bundle, keyring=receiver_keyring()).ok
        accepted = verify_bundle(bundle, keyring=receiver_keyring(), require_signature=False)
        assert accepted.ok
        assert accepted.signed == 0

    def test_verification_reuses_the_local_checks(self, tmp_path: Path) -> None:
        """The bundle path must not have its own, divergent verifier."""
        bundle = export_bundle(sender_ledger(tmp_path))
        result = verify_bundle(bundle, keyring=receiver_keyring())
        assert result.integrity is not None
        assert result.integrity.ledger_id == "acme-prod"
        assert result.integrity.checked == 1


class TestBundleEnvelope:
    def test_the_format_is_declared_and_versioned(self, tmp_path: Path) -> None:
        document = export_bundle(sender_ledger(tmp_path)).to_json()
        assert document["format"] == BUNDLE_FORMAT
        assert document["count"] == len(document["lines"])

    def test_a_future_format_is_refused_rather_than_guessed(self) -> None:
        with pytest.raises(ValueError, match="not supported"):
            Bundle.from_json({"format": 99, "ledger_id": "L", "lines": []})

    def test_a_bundle_that_omits_the_ledger_id_is_refused(self) -> None:
        """Defaulting it would verify every line against the wrong identity."""
        with pytest.raises(ValueError, match="name the ledger"):
            Bundle.from_json({"format": BUNDLE_FORMAT, "lines": []})

    def test_a_line_count_mismatch_is_refused(self) -> None:
        """A cheap envelope check, before any cryptography runs."""
        with pytest.raises(ValueError, match="declares 3 lines"):
            Bundle.from_json(
                {"format": BUNDLE_FORMAT, "ledger_id": "L", "lines": ["a"], "count": 3}
            )

    def test_a_non_array_lines_field_is_refused(self) -> None:
        with pytest.raises(ValueError, match="'lines' array"):
            Bundle.from_json({"format": BUNDLE_FORMAT, "ledger_id": "L", "lines": "nope"})

    def test_non_string_lines_are_refused(self) -> None:
        with pytest.raises(ValueError, match="must be a string"):
            Bundle.from_json({"format": BUNDLE_FORMAT, "ledger_id": "L", "lines": [1, 2]})

    def test_a_non_object_bundle_file_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "bundle.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(ValueError, match="JSON object"):
            read_bundle(path)
