"""Signed receipts: what a signature proves, and what it does not.

Two things make this file different from the other integrity tests.

**The negative tests are the feature.** A signing implementation that only
verifies signatures it produced itself provides no guarantee at all. So the cases
here are removal, substitution, replay, downgrade and algorithm confusion —
each of which must fail, and each of which is a plausible way to ship a signing
feature that does nothing.

**One test asserts a limitation on purpose.** HMAC cannot be verified by a third
party, because it is symmetric: every verifier is also a forger. That is not a
bug to fix, it is a property to state, and `TestHmacProvesTheHolderNotTheAuthor`
pins it so that no future docstring quietly implies otherwise.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_ledger import HmacSigner, KeyRing, Ledger, SignatureCheck
from agent_ledger.models import DelegationStatus, Receipt
from agent_ledger.signing import (
    ALG_ED25519,
    ALG_HMAC_SHA256,
    ALG_NONE,
    DOMAIN_SEPARATOR,
    Ed25519Signer,
    signing_payload,
)

SECRET = b"a-shared-secret"
#: The principal this key acts for. A signer that names one produces receipts
#: whose `signer` field a pinned keyring can check; without it, a keyring can only
#: report `unattributed`, which is strictly less useful.
ALICE = "urn:principal:acme.com:alice"
SIGNER = HmacSigner(secret=SECRET, key_id="k1", principal=ALICE)


def make_receipt(rid: str = "r1", did: str = "d1", *, cost: float = 0.1) -> Receipt:
    return Receipt(
        delegation_id=did,
        task_id="t1",
        delegate="urn:air:acme.com:agent:x",
        delegated_by="urn:principal:acme.com:alice",
        outcome=DelegationStatus.COMPLETED,
        receipt_id=rid,
        cost_usd=cost,
        budget_usd=1.0,
        issued_at=1000.0,
    )


def rewrite(path: Path, mutate) -> None:
    """Apply *mutate* to each stored line and write it back."""
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        mutate(row)
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def ed25519_available() -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


# --------------------------------------------------------------------------- #
# The positive path
# --------------------------------------------------------------------------- #


class TestSigningBasics:
    def test_a_signed_ledger_verifies(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path, signer=SIGNER)
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r2", "d2"))

        integrity = Ledger(path, verifier=SIGNER).verify(require_signature=True)
        assert integrity.ok, integrity.describe()
        assert integrity.signed == 2
        assert integrity.checked == 2

    def test_the_signature_is_not_part_of_the_digested_body(self, tmp_path: Path) -> None:
        """The whole reason signing is backward compatible.

        A signature inside `body()` would change the digest of every receipt ever
        written, and there is no version marker to explain it.
        """
        path = tmp_path / "grid.jsonl"
        receipt = make_receipt()
        unsigned_digest = receipt.digest()

        Ledger(path, signer=SIGNER).record(receipt)
        stored = json.loads(path.read_text(encoding="utf-8").splitlines()[0])

        assert set(stored) - set(unsigned_digest and receipt.body()) == {
            "digest",
            "prev",
            "signature",
            "key_id",
            "alg",
            "signer",
        }
        assert "signature" not in Receipt.from_json(stored).body()
        assert Receipt.from_json(stored).digest() == unsigned_digest

    def test_the_digest_is_unchanged_by_signing(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        receipt = make_receipt()
        before = receipt.digest()
        Ledger(path, signer=SIGNER).record(receipt)
        assert Ledger(path).current()[0].digest() == before

    def test_to_json_emits_nothing_new_when_unsigned(self) -> None:
        """An unconditional `"signature": null` would rewrite every ledger."""
        line = make_receipt().to_json()
        for field in ("signature", "key_id", "alg"):
            assert field not in line

    def test_the_envelope_fields_round_trip(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())
        receipt = Ledger(path).current()[0]
        assert receipt.signature is not None
        assert receipt.key_id == "k1"
        assert receipt.alg == ALG_HMAC_SHA256

    def test_signing_covers_every_line_including_refusals(self) -> None:
        """`Grid._record_refusal` builds a bare Receipt, bypassing `Delegation`.

        Signing at `Ledger.record` rather than at `Delegation.receipt` is what
        makes refusals signed too — otherwise they would be the only unsigned
        lines in an otherwise signed ledger, which is exactly the line an
        attacker would want to forge.

        The refusal is triggered with a publisher *denylist* rather than a trust
        requirement, for a reason worth recording: a trust rule rejects the
        candidate during ranking, so policy never evaluates it and no refusal is
        written at all. Denylisting is applied by the policy engine on an
        otherwise eligible candidate, which is the path that produces a receipt.
        """
        from agent_ledger import Grid, Policy, Task
        from agent_ledger.ard import ArdClient, StaticTransport
        from agent_ledger.router import GridConfig

        entry = {
            "identifier": "urn:air:acme.com:agent:x",
            "displayName": "X",
            "type": "application/a2a-agent-card+json",
            "url": "https://acme.com/a2a",
            "capabilities": ["work"],
            "representativeQueries": ["do some work"],
        }
        transport = StaticTransport({"https://acme.com/.well-known/ard.json": {"entries": [entry]}})
        ledger = Ledger(signer=SIGNER)
        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid().with_(denied_publishers=frozenset({"acme.com"})),
            ledger=ledger,
            domains=("acme.com",),
            config=GridConfig(record_refusals=True),
        )
        outcome = grid.dispatch(Task(intent="do some work", required_capabilities=("work",)))
        assert not outcome.ok, "the policy should have refused this"

        refusals = [r for r in ledger.lines if r.delegate == "urn:air:refused"]
        assert refusals, "a refusal that leaves no trace is indistinguishable from a bug"
        assert all(r.signature is not None for r in refusals), "refusals must be signed too"
        assert ledger.verify(require_signature=True).ok


# --------------------------------------------------------------------------- #
# The negative cases — each is a plausible way to ship signing that does nothing
# --------------------------------------------------------------------------- #


class TestSignatureTampering:
    def test_flipping_one_hex_character_is_caught(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())

        def flip(row: dict) -> None:
            sig = row["signature"]
            row["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]

        rewrite(path, flip)
        integrity = Ledger(path, verifier=SIGNER).verify()
        assert not integrity.ok
        assert integrity.bad_signature

    def test_a_signature_from_a_different_key_is_caught(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())
        other = HmacSigner(secret=b"a-different-secret", key_id="k1")
        integrity = Ledger(path, verifier=other).verify()
        assert not integrity.ok
        assert integrity.bad_signature

    def test_substituting_the_payload_is_caught(self, tmp_path: Path) -> None:
        """Proves the signature covers the *content*, not merely "some digest".

        Keeping the digest and swapping the body would pass a naive check that
        only verified the digest was well-formed.
        """
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt("r1", "d1", cost=0.1))

        def inflate(row: dict) -> None:
            row["cost_usd"] = 999.0  # digest now wrong too, so also tampered

        rewrite(path, inflate)
        integrity = Ledger(path, verifier=SIGNER).verify()
        assert not integrity.ok
        assert integrity.tampered and integrity.bad_signature

    def test_swapping_two_lines_signatures_is_caught(self, tmp_path: Path) -> None:
        """Both signatures are valid; neither belongs where it now is.

        This is why `prev` is inside the signed payload. Without linkage, one
        line's signature would verify perfectly on another line.
        """
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path, signer=SIGNER)
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r2", "d2"))

        def swap(rows: list[dict]) -> None:
            rows[0]["signature"], rows[1]["signature"] = rows[1]["signature"], rows[0]["signature"]

        lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
        swap(lines)
        path.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in lines), encoding="utf-8"
        )

        integrity = Ledger(path, verifier=SIGNER).verify()
        assert not integrity.ok
        assert len(integrity.bad_signature) == 2

    def test_removing_the_signature_is_caught_when_required(self, tmp_path: Path) -> None:
        """**The most important negative test in this file.**

        Stripping a signature is the exact analogue of the missing-`digest`
        bypass fixed in Phase 1: the line becomes *unchecked* rather than
        *wrong*, and a verifier that treats "nothing to check" as "fine" reports
        success for a forged ledger.
        """
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())

        def strip(row: dict) -> None:
            for field in ("signature", "key_id", "alg"):
                row.pop(field, None)

        rewrite(path, strip)

        lenient = Ledger(path, verifier=SIGNER).verify()
        assert lenient.ok, "an unsigned line is not corrupt, it is unchecked"
        assert lenient.signed == 0

        strict = Ledger(path, verifier=SIGNER).verify(require_signature=True)
        assert not strict.ok, "but a deployment that demands signatures must fail"
        assert strict.bad_signature

    def test_clearing_the_signature_to_an_empty_string_is_caught(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())
        rewrite(path, lambda row: row.update(signature=""))
        assert not Ledger(path, verifier=SIGNER).verify().ok

    def test_an_alg_of_none_is_rejected(self, tmp_path: Path) -> None:
        """`alg: none` is a downgrade attempt, not an absence of one."""
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())
        rewrite(path, lambda row: row.update(alg=ALG_NONE))
        integrity = Ledger(path, verifier=SIGNER).verify()
        assert not integrity.ok
        assert integrity.bad_signature

    def test_a_cross_algorithm_claim_is_rejected(self, tmp_path: Path) -> None:
        """An HMAC tag must never be accepted where Ed25519 was claimed.

        Otherwise the weaker algorithm becomes a forgery tool for the stronger:
        anyone who can compute a MAC could claim it was a signature.
        """
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())
        rewrite(path, lambda row: row.update(alg=ALG_ED25519))
        integrity = Ledger(path, verifier=SIGNER).verify()
        assert not integrity.ok
        assert integrity.unknown_alg

    def test_a_signature_with_no_signature_value_is_caught(self, tmp_path: Path) -> None:
        """`alg` set but no `signature`: a half-written line, not a valid one."""
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())

        def half(row: dict) -> None:
            row.pop("signature")

        rewrite(path, half)
        assert not Ledger(path, verifier=SIGNER).verify().ok


class TestReplay:
    def test_a_receipt_replayed_from_another_ledger_is_caught(self, tmp_path: Path) -> None:
        """Audience binding: the signed payload includes the ledger identity.

        Without it, a receipt copied out of ledger A verifies as a legitimate
        root of ledger B — and a chain root is exactly the line that names the
        accountable principal, so the forger would get to choose who is
        answerable.
        """
        a = tmp_path / "a.jsonl"
        b = tmp_path / "b.jsonl"
        Ledger(a, ledger_id="ledger-A", signer=SIGNER).record(make_receipt("rA", "dA"))
        stolen = a.read_text(encoding="utf-8").splitlines()[0]

        ledger_b = Ledger(b, ledger_id="ledger-B", signer=SIGNER)
        ledger_b.record(make_receipt("r1", "d1"))
        b.write_text(b.read_text(encoding="utf-8") + stolen + "\n", encoding="utf-8")

        integrity = Ledger(b, ledger_id="ledger-B", verifier=SIGNER).verify()
        assert not integrity.ok
        assert integrity.bad_signature, "the signature is bound to ledger A"
        assert integrity.broken_chain, "and the chain link is ledger A's genesis"

    def test_two_ledgers_with_the_same_id_accept_each_others_receipts(self, tmp_path: Path) -> None:
        """The residual risk, asserted rather than assumed away.

        Two ledgers that share an identity are the *same* ledger as far as
        signatures are concerned. Identity has to be chosen deliberately, and
        this test documents that a default identity provides no replay
        protection between separately-created ledgers.
        """
        a = tmp_path / "a.jsonl"
        b = tmp_path / "b.jsonl"
        Ledger(a, signer=SIGNER).record(make_receipt("rA", "dA"))
        stolen = a.read_text(encoding="utf-8").splitlines()[0]
        b.write_text(stolen, encoding="utf-8")

        # Same default identity, so the signature is valid here too — but the
        # chain link is the genesis of *this* ledger, so it still checks out.
        integrity = Ledger(b, verifier=SIGNER).verify()
        assert integrity.signed == 1
        assert integrity.ok, "documented: a default identity is not an audience"


# --------------------------------------------------------------------------- #
# What HMAC does not prove
# --------------------------------------------------------------------------- #


class TestHmacProvesTheHolderNotTheAuthor:
    """HMAC is symmetric, so it cannot be verified by a third party.

    This class exists so the limitation is *tested* rather than merely
    documented. A future change that starts describing HMAC output as a
    third-party-verifiable signature would fail here.
    """

    def test_anyone_holding_the_key_can_forge_a_valid_receipt(self, tmp_path: Path) -> None:
        """A verifier is a forger. State it, do not paper over it."""
        path = tmp_path / "grid.jsonl"
        # The "attacker" is simply anyone who can verify — same secret.
        forger = HmacSigner(secret=SECRET, key_id="k1")
        Ledger(path, signer=forger).record(make_receipt("r_forged", "d_forged", cost=0.0))

        integrity = Ledger(path, verifier=SIGNER).verify(require_signature=True)
        assert integrity.ok, "a MAC cannot distinguish the operator from an impostor"

    def test_signatures_carry_no_author_identity(self, tmp_path: Path) -> None:
        """The gap that a keyring is for, and that SPIFFE/DIDs solve."""
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())
        stored = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert stored["key_id"] == "k1"
        # `delegated_by` is the principal the *writer* claims. Nothing
        # cryptographic connects it to `key_id`; that is the missing link.
        assert stored["delegated_by"] == "urn:principal:acme.com:alice"

    def test_the_module_says_so(self) -> None:
        """The docstring is the deliverable here, so assert it is present."""
        import agent_ledger.signing as signing

        doc = signing.HmacSigner.__doc__ or ""
        assert "does not prove" in doc.lower()
        assert "symmetric" in doc.lower()


# --------------------------------------------------------------------------- #
# The signed payload
# --------------------------------------------------------------------------- #


class TestSignedPayload:
    def test_it_binds_the_domain(self) -> None:
        assert signing_payload(ledger_id="L", prev=None, digest="sha256:x").startswith(
            DOMAIN_SEPARATOR
        )

    def test_it_binds_the_ledger_identity(self) -> None:
        a = signing_payload(ledger_id="A", prev=None, digest="sha256:x")
        b = signing_payload(ledger_id="B", prev=None, digest="sha256:x")
        assert a != b

    def test_it_binds_the_chain_position(self) -> None:
        a = signing_payload(ledger_id="L", prev="sha256:p1", digest="sha256:x")
        b = signing_payload(ledger_id="L", prev="sha256:p2", digest="sha256:x")
        assert a != b

    def test_it_binds_the_digest(self) -> None:
        a = signing_payload(ledger_id="L", prev=None, digest="sha256:x")
        b = signing_payload(ledger_id="L", prev=None, digest="sha256:y")
        assert a != b

    def test_no_two_distinct_inputs_collide(self) -> None:
        """Field-order ambiguity would let one payload be read as another.

        Only realistic shapes are enumerated: a digest is ``sha256:<64 hex>``, a
        ``prev`` is a link or ``None``, and an empty string is not a value either
        can take. An earlier version of this test fed an empty digest and
        "found" a collision between ``prev=""`` and ``prev=None`` — which is not
        reachable, and would have been a false alarm.
        """
        digest = "sha256:" + "a" * 64
        other_digest = "sha256:" + "b" * 64
        link = "sha256:" + "c" * 64
        seen: set[bytes] = set()
        for ledger in ("L", "L2", "ledger-with-dashes"):
            for prev in (None, link):
                for dig in (digest, other_digest):
                    payload = signing_payload(ledger_id=ledger, prev=prev, digest=dig)
                    assert payload not in seen, (ledger, prev, dig)
                    seen.add(payload)
        assert len(seen) == 3 * 2 * 2

    def test_a_receipt_computes_its_own_payload(self) -> None:
        receipt = make_receipt()
        assert receipt.signed_payload("L") == signing_payload(
            ledger_id="L", prev=receipt.prev, digest=receipt.digest()
        )


# --------------------------------------------------------------------------- #
# Per-receipt checking, and the keyring
# --------------------------------------------------------------------------- #


class TestCheckSignature:
    def test_a_good_signature_reports_ok(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())
        receipt = Ledger(path).current()[0]
        assert Ledger(path, verifier=SIGNER).check_signature(receipt).ok

    def test_a_missing_signature_is_distinct_from_a_bad_one(self, tmp_path: Path) -> None:
        """Four different situations, four different responses."""
        ledger = Ledger()
        unsigned = make_receipt()
        check = ledger.check_signature(unsigned)
        assert check.status == "unsigned"
        assert not check.is_failure, "unsigned is unchecked, not wrong"

    def test_no_verifier_is_unknown_key_not_success(self) -> None:
        """A line that *is* signed but cannot be checked must not report "fine"."""
        ledger = Ledger()
        import dataclasses

        signed = dataclasses.replace(
            make_receipt(), signature="deadbeef", alg=ALG_HMAC_SHA256, key_id="k1"
        )
        check = ledger.check_signature(signed)
        assert check.status == "unknown_key"
        assert check.is_failure

    def test_a_keyring_resolves_by_key_id(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())
        ring = KeyRing().add("k1", SIGNER, principal=ALICE)
        integrity = Ledger(path, keyring=ring).verify(require_signature=True)
        assert integrity.ok, integrity.describe()
        assert integrity.signed == 1

    def test_an_unpinned_key_is_reported_not_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=SIGNER).record(make_receipt())
        ring = KeyRing().add("some-other-key", SIGNER, principal=ALICE)
        integrity = Ledger(path, keyring=ring).verify(require_signature=True)
        assert not integrity.ok
        assert integrity.unknown_key

    def test_a_pinned_keyring_catches_a_whole_ledger_resigned_by_a_forger(
        self, tmp_path: Path
    ) -> None:
        """The attack an *unpinned* keyring cannot stop, and why pinning matters.

        A forger who appends a receipt signed with their own key, labelled with
        their own ``key_id``, produces a line whose signature is internally
        perfect and whose chain link is correct. Nothing inside the file can
        distinguish it from a second legitimate writer — that is the point, and
        it is why a verifier must be *pinned* to the keys it expects rather than
        resolving whatever the ledger names.
        """
        path = tmp_path / "grid.jsonl"
        Ledger(path, ledger_id="shared", signer=SIGNER).record(make_receipt("r1", "d1", cost=0.10))

        bob = "urn:principal:acme.com:bob"
        forger = HmacSigner(secret=b"the-forgers-secret", key_id="k2", principal=bob)
        Ledger(path, ledger_id="shared", signer=forger).record(make_receipt("r2", "d2", cost=0.01))

        # A verifier pinned to the victim's key alone: the forged line is caught.
        pinned = Ledger(path, ledger_id="shared", verifier=SIGNER).verify(require_signature=True)
        assert not pinned.ok
        assert pinned.bad_signature

        # A keyring that trusts *both* keys cannot tell a second legitimate writer
        # from an impostor: each line is internally perfect and names a principal
        # the keyring happens to trust. Deciding whether Bob is *supposed* to be
        # writing in this ledger is not a cryptographic question.
        trusting = KeyRing().add("k1", SIGNER, principal=ALICE).add("k2", forger, principal=bob)
        unpinned = Ledger(path, ledger_id="shared", keyring=trusting).verify(require_signature=True)
        assert unpinned.ok, "documented: an unpinned verifier cannot tell the two apart"
        assert unpinned.signed == 2


# --------------------------------------------------------------------------- #
# Ed25519, when the optional dependency is present
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not ed25519_available(), reason="requires the [sign] extra")
class TestEd25519:
    def test_a_public_key_alone_can_verify(self, tmp_path: Path) -> None:
        """The property HMAC cannot have: verification without the power to forge."""
        private = Ed25519Signer.generate(key_id="ed-1")
        public = Ed25519Signer.from_public_bytes(private.public_bytes(), key_id="ed-1")

        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=private).record(make_receipt())

        integrity = Ledger(path, verifier=public).verify(require_signature=True)
        assert integrity.ok, integrity.describe()
        assert integrity.signed == 1

    def test_the_private_key_never_reaches_the_line(self, tmp_path: Path) -> None:
        private = Ed25519Signer.generate(key_id="ed-1")
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=private).record(make_receipt())
        stored = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert stored["alg"] == ALG_ED25519
        assert len(stored["signature"]) == 128, "64 bytes, hex"
        assert set(stored) >= {"signature", "key_id", "alg"}

    def test_a_different_public_key_fails(self, tmp_path: Path) -> None:
        private = Ed25519Signer.generate(key_id="ed-1")
        path = tmp_path / "grid.jsonl"
        Ledger(path, signer=private).record(make_receipt())
        wrong = Ed25519Signer.from_public_bytes(
            Ed25519Signer.generate().public_bytes(), key_id="ed-1"
        )
        assert not Ledger(path, verifier=wrong).verify().ok

    def test_a_public_only_signer_refuses_to_sign(self) -> None:
        public = Ed25519Signer.from_public_bytes(Ed25519Signer.generate().public_bytes())
        with pytest.raises(TypeError, match="private half"):
            public.sign(b"payload")


class TestTheExtraStaysOptional:
    """`cryptography` must never become a de facto requirement.

    A module-scope import would make `pip install ai-agent-ledger-py` pull it
    in, or fail outright without it — and zero runtime dependencies is a headline
    claim, not a preference.
    """

    def test_importing_the_package_does_not_load_cryptography(self) -> None:
        script = (
            "import sys; sys.path.insert(0, 'src'); import agent_ledger;"
            "print(any(m == 'cryptography' or m.startswith('cryptography.')"
            " for m in sys.modules))"
        )
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, check=True
        )
        assert result.stdout.strip() == "False", "cryptography was imported eagerly"

    def test_hmac_signing_works_without_cryptography(self) -> None:
        script = (
            "import sys; sys.path.insert(0, 'src');"
            "sys.modules['cryptography'] = None;"
            "import agent_ledger as a;"
            "from agent_ledger.signing import HmacSigner;"
            "print(a.HmacSigner is HmacSigner)"
        )
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, check=True
        )
        assert result.stdout.strip() == "True"

    def test_pyproject_declares_cryptography_only_as_an_extra(self) -> None:
        import pathlib
        import re

        text = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
        deps = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.S | re.M)
        assert deps is not None
        assert deps.group(1).strip() == "", "runtime dependencies must stay empty"
        assert re.search(r"^sign\s*=\s*\[.*cryptography", text, re.M), "[sign] extra missing"


class TestSignatureCheckSemantics:
    def test_is_failure_distinguishes_unchecked_from_wrong(self) -> None:
        assert SignatureCheck("ok").ok
        assert not SignatureCheck("unsigned").is_failure
        assert not SignatureCheck("absent").is_failure
        for bad in ("bad_signature", "unknown_key", "unknown_alg"):
            assert SignatureCheck(bad).is_failure, bad


class TestTheLedgerIdentityHasToBeKnown:
    """The identity is not stored in the file, by design — and that has a cost.

    Binding signatures to a ledger identity is what stops a receipt being
    replayed into another ledger. Recording the identity alongside the line would
    let a forger supply their own, so it cannot be recorded. The consequence is
    that a verifier which was not told the identity checks against the wrong
    thing and sees a broken chain *and* a bad signature — which reads as
    corruption rather than as a missing input.

    These tests pin the diagnosis, not a weakening of the binding.
    """

    def test_integrity_reports_the_identity_it_checked_against(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path, ledger_id="acme-prod-grid", signer=SIGNER).record(make_receipt())
        assert Ledger(path, ledger_id="acme-prod-grid").verify().ledger_id == "acme-prod-grid"
        assert Ledger(path).verify().ledger_id != "acme-prod-grid"

    def test_a_wrong_identity_looks_like_corruption(self, tmp_path: Path) -> None:
        """Stated so the failure mode is understood rather than rediscovered."""
        path = tmp_path / "grid.jsonl"
        Ledger(path, ledger_id="acme-prod-grid", signer=SIGNER).record(make_receipt())

        wrong = Ledger(path, verifier=SIGNER).verify(require_signature=True)
        assert not wrong.ok
        assert wrong.broken_chain, "the genesis link belongs to another identity"
        assert wrong.bad_signature, "and so does the signature"

    def test_the_right_identity_verifies(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path, ledger_id="acme-prod-grid", signer=SIGNER).record(make_receipt())
        right = Ledger(path, ledger_id="acme-prod-grid", verifier=SIGNER).verify(
            require_signature=True
        )
        assert right.ok, right.describe()

    def test_the_cli_names_the_identity_it_used(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        """A missing input must not be reported as corruption."""
        from agent_ledger.cli import main

        path = tmp_path / "grid.jsonl"
        Ledger(path, ledger_id="acme-prod-grid", signer=SIGNER).record(make_receipt())
        monkeypatch.setenv("AL_TEST_KEY", SECRET.decode())

        assert main(["verify", "--ledger", str(path), "--sign-key-env", "AL_TEST_KEY"]) == 1
        out = capsys.readouterr().out
        assert "ledger identity" in out
        assert "default-ledger" in out, "it must name the identity it actually used"

        assert (
            main(
                [
                    "verify",
                    "--ledger",
                    str(path),
                    "--ledger-id",
                    "acme-prod-grid",
                    "--sign-key-env",
                    "AL_TEST_KEY",
                    "--require-signature",
                ]
            )
            == 0
        )
        assert "OK" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# The CLI surface
# --------------------------------------------------------------------------- #


class TestCliSigningAndWitnessing:
    """The CLI is where a reader meets these guarantees, so it is tested like a
    feature rather than a thin wrapper."""

    def _signed_ledger(self, path: Path) -> None:
        ledger = Ledger(path, signer=SIGNER)
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r2", "d2"))

    def test_signed_ledger_verifies_with_the_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        from agent_ledger.cli import main

        path = tmp_path / "grid.jsonl"
        self._signed_ledger(path)
        monkeypatch.setenv("AL_TEST_KEY", SECRET.decode())

        assert main(["verify", "--ledger", str(path), "--sign-key-env", "AL_TEST_KEY"]) == 0
        assert "signed" in capsys.readouterr().out

    def test_require_signature_passes_on_a_signed_ledger(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agent_ledger.cli import main

        path = tmp_path / "grid.jsonl"
        self._signed_ledger(path)
        monkeypatch.setenv("AL_TEST_KEY", SECRET.decode())
        code = main(
            [
                "verify",
                "--ledger",
                str(path),
                "--sign-key-env",
                "AL_TEST_KEY",
                "--require-signature",
            ]
        )
        assert code == 0

    def test_a_wrong_key_exits_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agent_ledger.cli import main

        path = tmp_path / "grid.jsonl"
        self._signed_ledger(path)
        monkeypatch.setenv("AL_TEST_KEY", "not-the-secret")
        assert main(["verify", "--ledger", str(path), "--sign-key-env", "AL_TEST_KEY"]) == 1

    def test_an_unset_key_variable_is_refused_loudly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Failing closed, with the reason, beats verifying nothing quietly."""
        from agent_ledger.cli import main

        path = tmp_path / "grid.jsonl"
        self._signed_ledger(path)
        monkeypatch.delenv("AL_TEST_KEY", raising=False)
        with pytest.raises(SystemExit, match="unset"):
            main(["verify", "--ledger", str(path), "--sign-key-env", "AL_TEST_KEY"])

    def test_expect_head_detects_tail_truncation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The one attack no amount of in-file checking can catch.

        A shortened prefix is a perfectly consistent chain, so the only way to
        notice is to know what the end should have been.
        """
        from agent_ledger.cli import main

        path = tmp_path / "grid.jsonl"
        self._signed_ledger(path)
        monkeypatch.setenv("AL_TEST_KEY", SECRET.decode())

        head = Ledger(path).verify().chain_head
        assert head is not None
        assert (
            main(
                [
                    "verify",
                    "--ledger",
                    str(path),
                    "--sign-key-env",
                    "AL_TEST_KEY",
                    "--expect-head",
                    head,
                ]
            )
            == 0
        )

        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

        assert (
            main(
                [
                    "verify",
                    "--ledger",
                    str(path),
                    "--sign-key-env",
                    "AL_TEST_KEY",
                    "--expect-head",
                    head,
                ]
            )
            == 1
        )

    def test_json_output_exposes_the_head_for_publishing(self, tmp_path: Path, capsys) -> None:
        import json as jsonlib

        from agent_ledger.cli import main

        path = tmp_path / "grid.jsonl"
        self._signed_ledger(path)
        assert main(["verify", "--ledger", str(path), "--json"]) == 0
        payload = jsonlib.loads(capsys.readouterr().out)
        assert payload["chain_head"] == Ledger(path).verify().chain_head
        assert payload["ok"] is True

    def test_signing_requires_a_ledger(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        """Signing into an in-memory ledger signs nothing anyone can check."""
        from agent_ledger.cli import main

        monkeypatch.setenv("AL_TEST_KEY", SECRET.decode())
        code = main(
            [
                "delegate",
                "review a contract",
                "-c",
                "contract_review",
                "--registry",
                "https://none.invalid/s",
                "--sign-key-env",
                "AL_TEST_KEY",
            ]
        )
        assert code == 1
        assert "requires --ledger" in capsys.readouterr().err
