"""The keyring: turning "a key signed this" into "**this principal** signed it".

This file exists because signing alone answers the wrong question. A signature
establishes a *key*. Accountability needs a *who*, and the only bridge between
them is a mapping somebody decided in advance — which is why the mapping cannot
be derived from the ledger, and why an attacker who controls the ledger cannot
supply it.

The tests are organised around the three things a pinned keyring can do that a
bare verifier cannot:

1. **Refuse a valid key used under another name.** The signature checks out; the
   claim beside it does not.
2. **Refuse a revoked key while keeping history attributable.** Deleting a pin
   would make every historical signature look like a forgery; revocation keeps
   the *who* and drops the *authority*.
3. **Survive a restart**, because a trust store has to be a file somewhere, and a
   store that quietly drops an entry it cannot parse sends an operator to debug
   the wrong artefact.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_ledger import HmacSigner, KeyRing, Ledger
from agent_ledger.models import DelegationStatus, Receipt
from agent_ledger.signing import ALG_ED25519, Ed25519Signer, PinnedKey

ALICE = "urn:principal:acme.com:alice"
BOB = "urn:principal:acme.com:bob"
MALLORY = "urn:principal:evil.example:mallory"


def make_receipt(rid: str = "r1", did: str = "d1") -> Receipt:
    return Receipt(
        delegation_id=did,
        task_id="t1",
        delegate="urn:air:acme.com:agent:x",
        delegated_by=ALICE,
        outcome=DelegationStatus.COMPLETED,
        receipt_id=rid,
        cost_usd=0.1,
        budget_usd=1.0,
        issued_at=1000.0,
    )


def ed25519_available() -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


def signed_ledger(path: Path, *, key_id: str = "k1", principal: str | None = ALICE) -> Ledger:
    signer = HmacSigner(secret=b"secret", key_id=key_id, principal=principal)
    ledger = Ledger(path, ledger_id="L", signer=signer)
    ledger.record(make_receipt())
    return ledger


# --------------------------------------------------------------------------- #
# The three things a pinned keyring buys
# --------------------------------------------------------------------------- #


class TestPrincipalBinding:
    def test_a_correctly_pinned_key_verifies(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        signed_ledger(path)
        ring = KeyRing().add("k1", HmacSigner(secret=b"secret", key_id="k1"), principal=ALICE)

        integrity = Ledger(path, ledger_id="L", keyring=ring).verify(require_signature=True)
        assert integrity.ok, integrity.describe()
        assert integrity.signed == 1

    def test_a_valid_key_used_under_another_name_is_caught(self, tmp_path: Path) -> None:
        """**The finding this whole item exists for.**

        The signature is genuine — it is Alice's key. The *claim* beside it says
        Mallory. A bare verifier sees a valid signature and reports success; only
        a pinned keyring knows the key is not Mallory's to use.
        """
        path = tmp_path / "grid.jsonl"
        signed_ledger(path)

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[0]["signer"] = MALLORY  # the claim, not the signature, is forged
        path.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8"
        )

        ring = KeyRing().add("k1", HmacSigner(secret=b"secret", key_id="k1"), principal=ALICE)
        integrity = Ledger(path, ledger_id="L", keyring=ring).verify(require_signature=True)

        assert not integrity.ok
        assert integrity.principal_mismatch
        # And the message has to name both sides, or it is unactionable.
        assert ALICE in integrity.principal_mismatch[0]
        assert MALLORY in integrity.principal_mismatch[0]

    def test_without_a_keyring_the_same_forgery_passes(self, tmp_path: Path) -> None:
        """Stated so the limitation is explicit rather than implied.

        A verifier that was handed only a key cannot know what the key is
        entitled to claim. This is not a defect to fix; it is the reason the
        keyring exists.
        """
        path = tmp_path / "grid.jsonl"
        signed_ledger(path)

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[0]["signer"] = MALLORY
        path.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8"
        )

        # The signature is over the *digest*, not over the signer claim, so the
        # forged claim does not break the signature either — only the keyring
        # notices, because only the keyring knows who holds the key.
        bare = Ledger(
            path, ledger_id="L", verifier=HmacSigner(secret=b"secret", key_id="k1")
        ).verify(require_signature=True)
        assert bare.ok, "documented: a bare verifier cannot check a principal claim"

    def test_a_line_with_no_signer_claim_is_reported(self, tmp_path: Path) -> None:
        """Signed by a pinned key, but silent about who — that is unattributed.

        Failing closed here matters: "a key we trust signed it, and it does not
        say who" is strictly weaker than "Alice signed it", and reporting the two
        as equivalent would inflate what the ledger proves.
        """
        path = tmp_path / "grid.jsonl"
        signed_ledger(path, principal=None)  # signer claims no principal
        ring = KeyRing().add("k1", HmacSigner(secret=b"secret", key_id="k1"), principal=ALICE)

        integrity = Ledger(path, ledger_id="L", keyring=ring).verify(require_signature=True)
        assert not integrity.ok
        assert integrity.bad_signature, "reported with the unattributed detail"
        assert "names no signer" in integrity.bad_signature[0]

    def test_the_ledger_records_the_signers_claim(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        signed_ledger(path)
        stored = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert stored["signer"] == ALICE
        assert stored["key_id"] == "k1"


class TestRevocation:
    def test_a_revoked_key_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        signed_ledger(path)
        ring = (
            KeyRing()
            .add("k1", HmacSigner(secret=b"secret", key_id="k1"), principal=ALICE)
            .revoke("k1", note="laptop stolen")
        )

        integrity = Ledger(path, ledger_id="L", keyring=ring).verify(require_signature=True)
        assert not integrity.ok
        assert integrity.revoked
        assert "laptop stolen" in integrity.revoked[0]

    def test_revocation_keeps_the_history_attributable(self, tmp_path: Path) -> None:
        """The reason this is not implemented by deleting the pin.

        Deleting it would report `unknown_key`, which is indistinguishable from a
        forgery by a key nobody has ever seen — and it would erase the one thing
        an investigation needs, which is who held the key that signed.
        """
        ring = (
            KeyRing()
            .add("k1", HmacSigner(secret=b"secret", key_id="k1"), principal=ALICE)
            .revoke("k1")
        )

        pinned = ring.pin("k1")
        assert pinned is not None
        assert pinned.principal == ALICE, "we still know whose key it was"
        assert pinned.revoked is True
        assert ring.get("k1") is not None, "the verifier is retained, not removed"

    def test_revoking_an_unknown_key_is_an_error(self) -> None:
        with pytest.raises(KeyError, match="unknown key"):
            KeyRing().revoke("nope")


# --------------------------------------------------------------------------- #
# The trust store
# --------------------------------------------------------------------------- #


class TestKeyRingPersistence:
    @pytest.mark.skipif(not ed25519_available(), reason="requires the [sign] extra")
    def test_a_keyring_round_trips_through_a_file(self, tmp_path: Path) -> None:
        private = Ed25519Signer.generate(key_id="k1", principal=ALICE)
        ring = KeyRing().add("k1", private, principal=ALICE)
        path = ring.save(tmp_path / "trust" / "keyring.json")

        loaded = KeyRing.load(path)
        assert loaded.pin("k1").principal == ALICE
        assert loaded.pin("k1").verifier.alg == ALG_ED25519

    def test_it_refuses_to_write_a_symmetric_key(self, tmp_path: Path) -> None:
        """An HMAC "public key" is the secret.

        Writing one would quietly turn a verification artefact into a signing
        capability shared by everyone holding the file — so the refusal happens
        at the write, where the operator can see it, rather than at load time
        where it would look like a problem with the ledger.
        """
        ring = KeyRing().add("k1", HmacSigner(secret=b"secret", key_id="k1"), principal=ALICE)
        with pytest.raises(ValueError, match="cannot be distributed"):
            ring.to_json()
        with pytest.raises(ValueError, match="cannot be distributed"):
            ring.save(tmp_path / "keyring.json")

    def test_a_keyring_that_was_never_writable_cannot_be_loaded(self) -> None:
        """The failure mode refusing prevents: a keyless entry that loads.

        Without the write-time refusal this is exactly what `to_json` produced,
        and it fails every receipt the key ever signed.
        """
        with pytest.raises(ValueError, match="no public key"):
            KeyRing.from_json({"keys": {"k1": {"alg": ALG_ED25519, "principal": ALICE}}})

    def test_an_entry_without_a_principal_is_refused(self) -> None:
        """Skipping it would report every receipt it signed as unknown_key, and
        send the operator to debug the ledger instead of the trust store."""
        with pytest.raises(ValueError, match="no principal"):
            KeyRing.from_json({"keys": {"k1": {"alg": ALG_ED25519, "public": "00"}}})

    def test_an_unknown_algorithm_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unsupported alg"):
            KeyRing.from_json({"keys": {"k1": {"alg": "rot13", "principal": ALICE}}})

    def test_a_malformed_keyring_is_refused(self) -> None:
        with pytest.raises(ValueError, match="must have a 'keys' object"):
            KeyRing.from_json({"nope": True})

    @pytest.mark.skipif(not ed25519_available(), reason="requires the [sign] extra")
    def test_ed25519_public_keys_round_trip(self, tmp_path: Path) -> None:
        """The distribution story: 64 hex characters is all a verifier needs."""
        private = Ed25519Signer.generate(key_id="k1", principal=ALICE)
        ring = KeyRing().add("k1", private, principal=ALICE)
        path = ring.save(tmp_path / "keyring.json")

        document = json.loads(path.read_text(encoding="utf-8"))
        assert "secret" not in json.dumps(document).lower()
        assert len(document["keys"]["k1"]["public"]) == 64

        loaded = KeyRing.load(path)
        verifier = loaded.pin("k1").verifier
        payload = b"payload"
        assert verifier.verify(payload, private.sign(payload))
        # The loaded verifier cannot sign — it holds only the public half.
        with pytest.raises(TypeError):
            verifier.sign(payload)  # type: ignore[attr-defined]

    def test_an_empty_keyring_is_truthy(self) -> None:
        """No keyring means "do not check"; an empty one means "trust nothing"."""
        assert KeyRing()
        assert KeyRing().principals() == frozenset()


# --------------------------------------------------------------------------- #
# End to end over Ed25519, where the claim is actually verifiable
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not ed25519_available(), reason="requires the [sign] extra")
class TestEd25519PrincipalBinding:
    """The honest configuration: a public key a third party can check.

    With HMAC the principal claim is *unfalsifiable to a third party*, because
    anyone who can verify can also forge. With Ed25519 the claim is checkable by
    someone who holds only the public key — which is the whole point of the
    exercise, so it gets its own tests.
    """

    def test_a_third_party_verifies_without_the_power_to_forge(self, tmp_path: Path) -> None:
        alice = Ed25519Signer.generate(key_id="alice-key", principal=ALICE)
        path = tmp_path / "grid.jsonl"
        Ledger(path, ledger_id="L", signer=alice).record(make_receipt())

        # The verifier holds only what was published.
        published = Ed25519Signer.from_public_hex(alice.public_hex(), key_id="alice-key")
        ring = KeyRing().add("alice-key", published, principal=ALICE)

        integrity = Ledger(path, ledger_id="L", keyring=ring).verify(require_signature=True)
        assert integrity.ok, integrity.describe()

    def test_a_different_principals_claim_is_caught(self, tmp_path: Path) -> None:
        alice = Ed25519Signer.generate(key_id="alice-key", principal=ALICE)
        path = tmp_path / "grid.jsonl"
        Ledger(path, ledger_id="L", signer=alice).record(make_receipt())

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[0]["signer"] = MALLORY
        path.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8"
        )

        published = Ed25519Signer.from_public_hex(alice.public_hex(), key_id="alice-key")
        ring = KeyRing().add("alice-key", published, principal=ALICE)
        integrity = Ledger(path, ledger_id="L", keyring=ring).verify(require_signature=True)

        assert not integrity.ok
        assert integrity.principal_mismatch

    def test_a_key_pinned_to_the_wrong_principal_fails(self, tmp_path: Path) -> None:
        """The operator's own mistake, caught rather than silently accepted."""
        alice = Ed25519Signer.generate(key_id="k", principal=ALICE)
        path = tmp_path / "grid.jsonl"
        Ledger(path, ledger_id="L", signer=alice).record(make_receipt())

        published = Ed25519Signer.from_public_hex(alice.public_hex(), key_id="k")
        wrong = KeyRing().add("k", published, principal=BOB)
        integrity = Ledger(path, ledger_id="L", keyring=wrong).verify(require_signature=True)

        assert not integrity.ok
        assert integrity.principal_mismatch

    def test_pinned_key_carries_its_principal(self) -> None:
        alice = Ed25519Signer.generate(key_id="k")
        pinned = PinnedKey(verifier=alice, principal=ALICE)
        assert pinned.to_json()["principal"] == ALICE
        assert pinned.to_json()["alg"] == ALG_ED25519
