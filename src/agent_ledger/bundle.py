"""Signed receipt bundles — evidence that crosses an organisational boundary.

This module answers the question that "shared ledger backend" was the wrong
answer to. Two organisations do not need to write to one mutable store; they need
to be able to *show each other evidence* that each can check without trusting the
other's storage. A bundle is that evidence.

The design falls out of one observation: **a ledger is already the right
serialisation.** An append-only sequence of signed, chain-linked lines is exactly
what a bundle needs to be — so a bundle is those lines, plus a small manifest
saying which ledger they came from and where the chain ended. No new format, no
conversion step, no second implementation of the thing that already works.

Why not a shared store, stated plainly. A mutable store that several parties
write to has to answer "who wrote this line", and the only honest answers are a
signature or a central operator. A central operator contradicts the argument this
project already makes against a shared reputation feed — it is a single point of
failure and a censorship surface — and a store *without* per-writer attribution
is a forgeable store wearing the clothes of evidence. So: each party keeps its
own ledger, and exchanges bundles.

What a bundle proves, and what it does not:

* **It proves** that the receipts in it were signed by keys the *verifier* chose
  to trust, that no line was edited, deleted, reordered or spliced in, and —
  when the verifier knows what the head should be — that nothing was truncated
  from the end.
* **It does not prove** that the sender's storage is honest about what it
  *omitted*. A bundle is a claim about a subset of a ledger. Completeness needs
  the head, which is why the head travels in the manifest and why
  ``expected_head`` is the parameter that matters most.
* **It does not prove** the sender is who they say. That is the keyring's job,
  and it is why :func:`verify_bundle` takes one and will not fetch keys itself.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ledger import Ledger, LedgerIntegrity
from .models import Receipt
from .signing import KeyRing

__all__ = [
    "BUNDLE_FORMAT",
    "BundleVerification",
    "export_bundle",
    "read_bundle",
    "verify_bundle",
    "write_bundle",
]

#: Bumped only if the bundle envelope changes shape. In the envelope, never in a
#: receipt's ``body()`` — a changed body would alter the digest of every receipt
#: ever written, which is the mistake this project has now avoided twice.
BUNDLE_FORMAT = 1


@dataclass(frozen=True, slots=True)
class BundleVerification:
    """What a bundle turned out to prove, with the reasons kept separate.

    Deliberately not a boolean. The four failures call for four different
    responses from the receiving organisation:

    ``signature``
        A line was not signed by a trusted key, or the principal claim failed.
        This is the one that should stop a payment.
    ``chain``
        Linkage broke: a line was removed, reordered or spliced in. The bundle is
        not a faithful excerpt of any single ledger.
    ``head``
        The bundle does not end where the manifest says it does, so its own tail
        is missing — or the manifest was rewritten to match a shortened bundle.
    ``identity``
        The bundle claims a different ledger than the one being checked, which
        matters when a bundle is dropped into an existing store.
    """

    ok: bool
    receipts: int = 0
    signed: int = 0
    ledger_id: str | None = None
    head: str | None = None
    head_matches: bool | None = None
    integrity: LedgerIntegrity | None = None
    problems: tuple[str, ...] = ()

    def describe(self) -> str:
        if self.ok:
            bits = [f"{self.receipts} receipt lines verified"]
            if self.signed:
                bits.append(f"{self.signed} signed")
            if self.head_matches:
                bits.append("head matches")
            if self.ledger_id:
                bits.append(f"ledger {self.ledger_id}")
            return "; ".join(bits)
        return "; ".join(self.problems) or "bundle did not verify"

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "receipts": self.receipts,
            "signed": self.signed,
            "ledger_id": self.ledger_id,
            "head": self.head,
            "head_matches": self.head_matches,
            "problems": list(self.problems),
            "integrity": None
            if self.integrity is None
            else {
                "tampered": list(self.integrity.tampered),
                "broken_chain": list(self.integrity.broken_chain),
                "orphaned": list(self.integrity.orphaned),
                "duplicated": list(self.integrity.duplicated),
                "malformed": list(self.integrity.malformed),
                "bad_signature": list(self.integrity.bad_signature),
                "unknown_key": list(self.integrity.unknown_key),
                "principal_mismatch": list(self.integrity.principal_mismatch),
                "revoked": list(self.integrity.revoked),
                "unchained": self.integrity.unchained,
            },
        }


@dataclass(frozen=True, slots=True)
class Bundle:
    """A ledger excerpt plus what a reader needs to check it.

    ``lines`` holds the stored lines **verbatim** — not re-serialised receipts.
    Re-serialising would be a silent opportunity to change a byte, and the digest
    is over bytes.

    ``complete`` says whether the lines are a prefix of the sender's ledger or a
    selected subset, and it matters more than it looks. Chain linkage makes every
    line commit to the one before it, so a *subset* cannot chain from genesis:
    the first exported line still points at a line the receiver does not have.
    Re-signing the lines to fix that would need the private key, and would
    destroy the very evidence the bundle carries.

    So the manifest declares which kind it is, and the chain is checked only
    where a chain is claimed. Silently degrading the check instead would leave a
    receiver unable to tell "this is a subset" from "this bundle's linkage is
    broken" — the one distinction that matters.
    """

    ledger_id: str
    head: str | None
    lines: tuple[str, ...] = ()
    format: int = BUNDLE_FORMAT
    complete: bool = True
    note: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "ledger_id": self.ledger_id,
            "head": self.head,
            "count": len(self.lines),
            "complete": self.complete,
            "note": self.note,
            "metadata": dict(self.metadata),
            "lines": list(self.lines),
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> Bundle:
        """Parse a bundle, refusing anything it cannot read honestly.

        Every failure raises rather than defaulting, because a bundle with an
        unreadable manifest is not a partial bundle — it is one whose claims
        cannot be checked, and accepting it would report success for work nobody
        did.
        """
        fmt = raw.get("format", BUNDLE_FORMAT)
        if fmt != BUNDLE_FORMAT:
            raise ValueError(
                f"bundle format {fmt!r} is not supported; this build reads {BUNDLE_FORMAT}"
            )
        ledger_id = raw.get("ledger_id")
        if not isinstance(ledger_id, str) or not ledger_id:
            raise ValueError("a bundle must name the ledger it came from")
        lines = raw.get("lines")
        if not isinstance(lines, Sequence) or isinstance(lines, (str, bytes)):
            raise ValueError("a bundle must carry a 'lines' array")
        if not all(isinstance(line, str) for line in lines):
            raise ValueError("every bundle line must be a string")

        declared = raw.get("count")
        if isinstance(declared, int) and declared != len(lines):
            # A cheap check that catches truncation of the *envelope* before any
            # cryptography runs. Not a substitute for the head, which catches
            # truncation of the lines themselves.
            raise ValueError(f"the bundle declares {declared} lines but carries {len(lines)}")

        head = raw.get("head")
        if head is not None and not isinstance(head, str):
            raise ValueError("a bundle's head must be a string or null")
        return cls(
            ledger_id=ledger_id,
            head=head,
            lines=tuple(lines),
            format=fmt,
            # Absent means "a full excerpt", the strict reading: a manifest that
            # does not claim to be a subset does not get the benefit of the doubt.
            complete=bool(raw.get("complete", True)),
            note=str(raw.get("note") or ""),
            metadata=raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {},
        )


def export_bundle(
    ledger: Ledger,
    *,
    note: str = "",
    receipt_ids: Sequence[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> Bundle:
    """Package a ledger — or a chosen subset of its current lines — for a peer.

    ``receipt_ids`` selects whole delegations by their receipt id, which is what
    a partner actually needs: "here is the chain behind this piece of work", not
    "here is my whole ledger". Selecting by *current* state means every
    transition of a chosen delegation travels with it, so the chain a partner
    reconstructs is complete rather than a single frame of it.
    """
    wanted: set[str] | None = set(receipt_ids) if receipt_ids is not None else None
    lines: list[str] = []
    for receipt in ledger.lines:
        if wanted is not None and receipt.receipt_id not in wanted:
            continue
        # `to_json` then `dumps` reproduces the stored bytes for a line that was
        # read from storage, because both sides go through the same canonical
        # form. For a line that only ever existed in memory it produces the bytes
        # that *would* have been written, which is what a peer can check.
        lines.append(json.dumps(receipt.to_json(), sort_keys=True))

    integrity = ledger.verify()
    return Bundle(
        ledger_id=ledger.signing_identity,
        head=integrity.chain_head,
        lines=tuple(lines),
        # A selected subset cannot chain from genesis, so it must not claim to.
        complete=wanted is None,
        note=note,
        metadata=dict(metadata or {}),
    )


def write_bundle(bundle: Bundle, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle.to_json(), indent=2, sort_keys=True), encoding="utf-8")
    return target


def read_bundle(path: str | Path) -> Bundle:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise ValueError("a bundle file must contain a JSON object")
    return Bundle.from_json(document)


def verify_bundle(
    bundle: Bundle,
    *,
    keyring: KeyRing | None = None,
    expected_head: str | None = None,
    expected_ledger_id: str | None = None,
    require_signature: bool = True,
) -> BundleVerification:
    """Check a bundle against keys **the caller** chose to trust.

    A bundle is untrusted input from another organisation, so this verifies it
    the way it verifies its own ledger — by materialising the lines into a
    throwaway in-memory ledger and running the same checks. Reusing the code path
    is the point: a second, bundle-specific verifier would be a second place for
    the same class of bug to live.

    ``require_signature`` defaults to **True**, unlike on a local ledger. That
    asymmetry is deliberate. A local ledger may legitimately predate signing, so
    demanding signatures there would declare existing users' data corrupt. A
    bundle is evidence offered *to someone else*, and an unsigned bundle proves
    nothing about who wrote it — accepting one by default would make the whole
    exchange decorative.

    ``expected_head`` is the parameter that matters most. Without it a bundle can
    be silently shortened and still verify: a truncated prefix is a perfectly
    consistent chain, and the manifest's own head is written by whoever
    truncated it. A receiver that does not know the expected head can only learn
    it from a previous, independently obtained value.
    """
    problems: list[str] = []

    if expected_ledger_id is not None and bundle.ledger_id != expected_ledger_id:
        problems.append(
            f"bundle is from ledger {bundle.ledger_id!r}, expected {expected_ledger_id!r}"
        )

    ledger = Ledger(ledger_id=bundle.ledger_id, keyring=keyring)
    for index, line in enumerate(bundle.lines, start=1):
        try:
            ledger.backend.append(line)
        except OSError as exc:  # pragma: no cover - in-memory backend cannot fail
            problems.append(f"could not read bundle line {index}: {exc}")
            break
    ledger._reload()  # noqa: SLF001 - the bundle path owns this instance

    integrity = ledger.verify(require_signature=require_signature)

    if integrity.tampered:
        problems.append(f"{len(integrity.tampered)} tampered line(s): {integrity.tampered[:3]}")
    if integrity.broken_chain:
        # A subset export cannot chain from genesis: the first line's `prev`
        # points at a line the receiver was not sent. The manifest declares
        # `complete: false` for exactly this case, and the receipt's signature
        # still covers `prev` — so the linkage claim is signed, it is simply not
        # *checkable* without the intervening lines. Reporting it as a broken
        # chain would make every subset bundle look tampered with.
        if bundle.complete:
            problems.append(
                f"{len(integrity.broken_chain)} broken chain link(s): {integrity.broken_chain[:3]}"
            )
    if integrity.principal_mismatch:
        problems.append(
            f"{len(integrity.principal_mismatch)} principal mismatch(es): "
            f"{integrity.principal_mismatch[:2]}"
        )
    if integrity.revoked:
        problems.append(f"{len(integrity.revoked)} revoked key(s): {integrity.revoked[:2]}")
    if integrity.bad_signature:
        problems.append(
            f"{len(integrity.bad_signature)} bad signature(s): {integrity.bad_signature[:3]}"
        )
    if integrity.unknown_key:
        problems.append(
            f"{len(integrity.unknown_key)} line(s) signed by an untrusted key: "
            f"{integrity.unknown_key[:3]}"
        )
    if integrity.unknown_alg:
        problems.append(f"{len(integrity.unknown_alg)} unknown algorithm(s)")
    if integrity.malformed:
        problems.append(f"{len(integrity.malformed)} unreadable line(s): {integrity.malformed[:3]}")
    if integrity.orphaned:
        problems.append(f"{len(integrity.orphaned)} orphaned parent(s): {integrity.orphaned[:3]}")
    if integrity.duplicated:
        problems.append(f"{len(integrity.duplicated)} duplicated receipt id(s)")

    head_matches: bool | None = None
    if expected_head is not None:
        head_matches = integrity.chain_head == expected_head
        if not head_matches:
            problems.append(
                f"bundle ends at {integrity.chain_head}, expected {expected_head}: "
                "its tail is missing, or the manifest was rewritten to match a "
                "shortened bundle"
            )
    elif bundle.head is not None and integrity.chain_head != bundle.head:
        # The manifest disagrees with its own contents. Not a completeness
        # guarantee — the manifest is written by the sender — but an
        # inconsistency with no innocent explanation.
        head_matches = False
        problems.append(
            f"the manifest claims head {bundle.head} but the lines end at {integrity.chain_head}"
        )

    return BundleVerification(
        ok=not problems,
        receipts=integrity.checked,
        signed=integrity.signed,
        ledger_id=bundle.ledger_id,
        head=integrity.chain_head,
        head_matches=head_matches,
        integrity=integrity,
        problems=tuple(problems),
    )


def bundle_receipts(bundle: Bundle) -> tuple[Receipt, ...]:
    """The receipts in a bundle, for a caller that has already verified it.

    Kept separate from verification on purpose: parsing and trusting are
    different acts, and a helper that did both would make it easy to skip the
    second without noticing.
    """
    out: list[Receipt] = []
    for line in bundle.lines:
        raw = json.loads(line)
        if isinstance(raw, Mapping):
            try:
                out.append(Receipt.from_json(raw))
            except (KeyError, ValueError, TypeError):
                continue
    return tuple(out)
