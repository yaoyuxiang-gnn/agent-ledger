"""Signed receipts — saying *who* wrote a line, not merely that it is intact.

The digest and the chain together answer two questions: was this line edited, and
was anything removed, reordered or spliced in. Neither answers the third, which
is the one that matters most in a dispute: **who wrote it**. Anyone holding the
ledger can recompute every digest and every link, so a full, consistent rewrite
verifies clean. That was the top gap this module exists to close.

Three design decisions worth stating, because each of them is load-bearing.

**Sign the digest; never digest the signature.** ``Receipt.body()`` stays exactly
as it was, and the signature lives beside the digest in the stored envelope. If a
signature were part of the digested body, every ledger ever written would start
failing verification, and there is no version marker to explain why. There is
also a fixed-point problem: the signature covers the digest, so the digest cannot
also cover the signature.

**Domain-separate, and bind the audience.** The signed message is
``b"al-receipt-v1\\0" || ledger_id || prev || digest``. Signing a bare
``sha256:<hex>`` invites a signature made here being replayed as a signature over
something else that happens to hash the same way — and omitting ``ledger_id``
means a receipt copied out of one ledger verifies in another. A per-receipt
signature without linkage would *launder* replay and splicing by lending them
cryptographic authority, which is worse than having no signature at all.

**Say plainly what each algorithm proves.** This is the part most projects get
wrong, and it is the part a security reader checks first.

===================  ==========================  ==============================
Provider             Proves                      Does **not** prove
===================  ==========================  ==============================
``HmacSigner``       The holder of the shared    **Who.** It is symmetric, so
                     secret wrote these bytes.   every verifier is also a
                     Stops a storage operator    forger. To check a MAC you
                     hand-editing a ledger.      must hold the key, and holding
                                                 the key lets you mint anything.
                                                 A key leak is unrecoverable: you
                                                 cannot separate historically
                                                 valid tags from forged ones.
``Ed25519Signer``    A specific key signed it,   That the key belongs to the
                     and any third party can     identity named in
                     check that without being   ``delegated_by``. That is a key
                     able to forge it.           *distribution* problem, not a
                                                 cryptographic one — see the
                                                 keyring note below.
===================  ==========================  ==============================

The Python standard library has **no asymmetric signature primitive** in any
version this project supports. ``hashlib`` and ``hmac`` are symmetric, ``ssl``
wraps OpenSSL but exposes no signing API, and 3.13 removed ``crypt`` without
adding anything in its place. So Ed25519 needs ``cryptography``, which would
break the zero-dependency promise — hence an optional extra, imported lazily, so
that the extra never becomes *de facto* mandatory. ``pip install
ai-agent-ledger-py`` still pulls in nothing.

**What signing still does not do on its own.** A signature proves a *key* signed a
receipt. It says nothing about who holds that key, and a receipt's own ``signer``
or ``delegated_by`` is a claim by its author — believing it is precisely the
mistake the field invites. :class:`KeyRing` is the independent statement that
closes it: *this* key belongs to *that* principal, decided in advance, over a
channel the reader already trusts. It takes the decision as input and declines to
derive it, because deciding what a principal *means* is what SPIFFE, DIDs and
enterprise PKI exist for.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "ALG_ED25519",
    "ALG_HMAC_SHA256",
    "ALG_NONE",
    "DOMAIN_SEPARATOR",
    "Ed25519Signer",
    "HmacSigner",
    "KeyRing",
    "PinnedKey",
    "SIGNATURE_FIELDS",
    "SignatureCheck",
    "Signer",
    "Verifier",
    "signing_payload",
]

#: Bumped only if the signed message format changes. Mixed into every payload so
#: a signature made under one format can never be read as one made under another.
DOMAIN_SEPARATOR = b"al-receipt-v1\x00"

ALG_HMAC_SHA256 = "hmac-sha256"
ALG_ED25519 = "ed25519"

#: The value a line carries when it is deliberately unsigned. Distinct from a
#: missing signature: absence means "written before signing existed", and the two
#: are reported separately because they call for different responses.
ALG_NONE = "none"

#: Envelope members that are never part of the digested body. Exported so tests
#: can assert the body is untouched by signing.
SIGNATURE_FIELDS = ("signature", "key_id", "alg")


def signing_payload(*, ledger_id: str, prev: str | None, digest: str) -> bytes:
    """The exact bytes a receipt signature covers.

    Length-prefixing is not used, and does not need to be: ``digest`` and ``prev``
    are always fixed-shape ``sha256:<64 hex>`` strings or the literal ``None``,
    and ``ledger_id`` is separated from them by the domain separator, so no two
    distinct inputs can serialise to the same payload.
    """
    return DOMAIN_SEPARATOR + b"|".join(
        part.encode("utf-8") for part in (ledger_id, prev or "", digest)
    )


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #


@runtime_checkable
class Signer(Protocol):
    """Produces a signature over a receipt's canonical identity."""

    #: Identifier stored in the line, so a verifier knows which provider to use.
    @property
    def alg(self) -> str: ...

    #: Identifies *which* key signed. Needed for rotation and revocation: without
    #: it, a key change makes every historical signature unverifiable.
    @property
    def key_id(self) -> str: ...

    #: The principal this signer acts for, or ``None`` if it does not claim one.
    #: Optional so that every existing signer keeps working, and because a
    #: signer with no identity is a legitimate configuration — it just cannot
    #: benefit from principal checking.
    @property
    def principal(self) -> str | None: ...

    def sign(self, payload: bytes) -> str: ...


@runtime_checkable
class Verifier(Protocol):
    """Checks a signature. May or may not be the same object as the signer."""

    @property
    def alg(self) -> str: ...

    def verify(self, payload: bytes, signature: str, *, key_id: str | None = None) -> bool: ...


@dataclass(frozen=True)
class HmacSigner:
    """HMAC-SHA256 over a shared secret. Standard library only.

    **This proves the holder of the secret wrote the bytes. It does not prove
    who that holder is.** Symmetric cryptography means anyone who can verify can
    also forge, so a MAC is evidence *within* a trust domain — one organisation,
    its own storage operator — and is not evidence *between* organisations.
    Presenting a MAC as third-party-verifiable authorship would be a false
    claim, and the docstring on the module says so at length rather than leaving
    a reader to infer it from the algorithm name.

    It is nonetheless the right default: it needs no dependency, no key
    distribution and no revocation infrastructure, and it closes the most
    immediate hole — a storage operator editing a ledger by hand.
    """

    secret: bytes
    key_id: str = "hmac-default"
    alg: str = ALG_HMAC_SHA256
    #: The principal this key acts for. Recording one is what lets a receipt say
    #: *who* signed it — but note that for HMAC the claim is unfalsifiable to a
    #: third party, because anyone who can check the tag can also produce one.
    principal: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.secret, str):
            object.__setattr__(self, "secret", self.secret.encode("utf-8"))
        if not self.secret:
            raise ValueError("an empty HMAC secret provides no integrity at all")

    def sign(self, payload: bytes) -> str:
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str, *, key_id: str | None = None) -> bool:
        """Constant-time comparison.

        ``hmac.compare_digest`` rather than ``==``: a byte-by-byte comparison
        leaks how much of a guess was correct, which is enough to forge a tag one
        byte at a time.
        """
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)


@dataclass(frozen=True)
class Ed25519Signer:
    """Ed25519 over an optional dependency. The only third-party-verifiable option.

    ``cryptography`` is imported **inside** these methods, never at module scope.
    A module-scope import would make the ``[sign]`` extra mandatory in practice —
    merely importing ``agent_ledger`` would fail without it — and the
    zero-dependency promise is a headline claim, not a preference.

    Accepts either a private key (to sign) or a public key (to verify). The
    distinction matters: a verifier should hold only the public half, which is
    what makes forgery impossible rather than merely inconvenient.
    """

    key: Any
    key_id: str = "ed25519-default"
    alg: str = ALG_ED25519
    principal: str | None = None

    @classmethod
    def from_private_bytes(
        cls, raw: bytes, *, key_id: str = "ed25519-default", principal: str | None = None
    ) -> Ed25519Signer:
        return cls(
            key=_ed25519().Ed25519PrivateKey.from_private_bytes(raw),
            key_id=key_id,
            principal=principal,
        )

    @classmethod
    def from_public_bytes(
        cls, raw: bytes, *, key_id: str = "ed25519-default", principal: str | None = None
    ) -> Ed25519Signer:
        return cls(
            key=_ed25519().Ed25519PublicKey.from_public_bytes(raw),
            key_id=key_id,
            principal=principal,
        )

    @classmethod
    def from_public_hex(
        cls, raw: str, *, key_id: str = "ed25519-default", principal: str | None = None
    ) -> Ed25519Signer:
        """Rebuild a verifying signer from the hex a keyring stores.

        This is what makes third-party verification practical: the only thing a
        verifier needs is 64 hex characters, published somewhere they already
        trust. No secret is involved, so distributing it is safe.
        """
        return cls.from_public_bytes(bytes.fromhex(raw), key_id=key_id, principal=principal)

    @classmethod
    def generate(
        cls, *, key_id: str = "ed25519-default", principal: str | None = None
    ) -> Ed25519Signer:
        return cls(key=_ed25519().Ed25519PrivateKey.generate(), key_id=key_id, principal=principal)

    def sign(self, payload: bytes) -> str:
        try:
            return self.key.sign(payload).hex()
        except AttributeError as exc:
            raise TypeError(
                "this Ed25519Signer holds a public key; signing needs the private half"
            ) from exc

    def verify(self, payload: bytes, signature: str, *, key_id: str | None = None) -> bool:
        public = self.key if hasattr(self.key, "public_bytes") else self.key.public_key()
        try:
            public.verify(bytes.fromhex(signature), payload)
        except Exception:  # noqa: BLE001 - any failure is a failed verification
            return False
        return True

    def public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        public = self.key if hasattr(self.key, "public_bytes") else self.key.public_key()
        return public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_hex(self) -> str:
        """The public half as hex — the only part a keyring should ever hold."""
        return self.public_bytes().hex()


def _ed25519():
    """Import the Ed25519 backend, or explain precisely how to get it.

    Imported here rather than at module scope on purpose. A module-scope import
    would make the ``[sign]`` extra mandatory in practice — merely importing
    ``agent_ledger`` would fail without ``cryptography`` installed — and
    the zero-dependency promise is a headline claim, not a preference.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            "Ed25519 signing requires the optional dependency:\n"
            "    pip install 'ai-agent-ledger-py[sign]'\n"
            "HmacSigner is available in the core package and needs no extra, but "
            "it is symmetric and therefore cannot be verified by a third party."
        ) from exc
    return ed25519


# --------------------------------------------------------------------------- #
# Verification result
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class SignatureCheck:
    """The outcome of checking one line's signature, with the *reason*.

    A bare boolean would force the caller to guess between "no signature", "wrong
    key", "principal mismatch" and "tampered", and those call for four different
    responses — including, in one case, no response beyond an upgrade note.
    """

    #: "ok" | "unsigned" | "bad_signature" | "unknown_key" | "unknown_alg"
    #: | "principal_mismatch" | "unattributed" | "revoked"
    status: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def is_failure(self) -> bool:
        """Whether this should make ``verify()`` report the ledger as bad.

        ``unsigned`` is not a failure. A ledger written before signing existed is
        not corrupt, and neither is one whose operator chose not to sign — it is
        *unchecked*, and the honest report says so rather than claiming either
        success or failure.
        """
        return self.status in (
            "bad_signature",
            "unknown_key",
            "unknown_alg",
            "principal_mismatch",
            "unattributed",
            "revoked",
        )


@dataclass(frozen=True, slots=True)
class PinnedKey:
    """A public key, the principal it belongs to, and whether it still counts.

    The pairing is the whole point. A signature answers "which key signed this";
    accountability needs "**who** signed this", and the only way to get from one
    to the other is a mapping that someone decided in advance. That decision is
    the trust anchor, and it cannot be derived from the ledger.

    ``revoked`` exists because a key that is *known* to be compromised must stop
    counting immediately, without deleting the pin — deleting it would turn every
    historical signature into ``unknown_key``, which is indistinguishable from a
    forgery. A revoked key keeps its signatures *attributable* (we know who it
    was) while making them no longer *authoritative*.
    """

    verifier: Verifier
    principal: str
    revoked: bool = False
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        """Serialise for a trust store. **Only public key material may appear.**

        Raises for a symmetric verifier rather than writing an entry without a
        public key. That is not pedantry: an HMAC "public key" *is* the secret,
        so writing one would quietly turn a verification artefact into a signing
        capability that everyone holding the file shares. And writing a keyless
        entry would be worse still — it loads fine, then fails every receipt that
        key signed, sending an operator to debug the ledger instead of the store.
        So this refuses at the point of writing, where the mistake is visible.
        """
        public = getattr(self.verifier, "public_hex", None)
        if not callable(public):
            raise ValueError(
                f"key {getattr(self.verifier, 'key_id', '?')!r} uses "
                f"{self.verifier.alg}, which is symmetric and therefore cannot be "
                "distributed: a shared secret in a trust store is a secret every "
                "reader can forge with. Use Ed25519 for anything a third party "
                "verifies, or keep HMAC verification to the process that holds "
                "the secret."
            )
        out: dict[str, Any] = {
            "alg": self.verifier.alg,
            "principal": self.principal,
            "revoked": self.revoked,
            "public": public(),
        }
        if self.note:
            out["note"] = self.note
        key_id = getattr(self.verifier, "key_id", None)
        if key_id:
            out["key_id"] = key_id
        return out


@dataclass(frozen=True)
class KeyRing:
    """Key identity to principal, pinned by the verifier and nothing else.

    **This is the object that closes the gap signing alone cannot.** A signature
    proves a key signed a receipt. It says nothing about who holds that key, and
    a receipt's own ``signer`` or ``delegated_by`` is a claim by its author —
    believing it is exactly the mistake the field invites. A keyring is the
    independent statement: *this* key belongs to *that* principal, decided in
    advance, over a channel the reader already trusts.

    Deliberately **pinned**. A keyring that fetched keys from wherever a receipt
    said they were would be worse than useless, because an attacker who rewrote
    the ledger would simply also rewrite the key reference — which is the whole
    attack, restated as a feature.

    And deliberately **not a directory service**. Deciding what a principal
    *means* — that `spiffe://acme.com/agents/grid` is really Acme's grid — is what
    SPIFFE, DIDs and enterprise PKI exist for. This library takes that as input
    and declines to invent a fifth answer.

    Two things it defends against that a bare verifier cannot:

    * **Key reuse under another name.** A valid key presented as a different
      principal fails, because the mapping is fixed and the receipt's claim is
      checked against it.
    * **Silent revocation.** A revoked key is reported rather than deleted, so
      old receipts stay attributable while new ones stop being authoritative.
    """

    keys: Mapping[str, PinnedKey] = field(default_factory=dict)

    def add(
        self,
        key_id: str,
        verifier: Verifier,
        *,
        principal: str,
        revoked: bool = False,
        note: str = "",
    ) -> KeyRing:
        """Pin a key to a principal. ``principal`` is required, on purpose."""
        return KeyRing(
            {
                **self.keys,
                key_id: PinnedKey(
                    verifier=verifier, principal=principal, revoked=revoked, note=note
                ),
            }
        )

    def revoke(self, key_id: str, *, note: str = "") -> KeyRing:
        """Stop trusting a key without forgetting who held it."""
        pinned = self.keys.get(key_id)
        if pinned is None:
            raise KeyError(f"cannot revoke unknown key {key_id!r}")
        return KeyRing(
            {
                **self.keys,
                key_id: PinnedKey(
                    verifier=pinned.verifier,
                    principal=pinned.principal,
                    revoked=True,
                    note=note or pinned.note,
                ),
            }
        )

    def get(self, key_id: str) -> Verifier | None:
        pinned = self.keys.get(key_id)
        return pinned.verifier if pinned is not None else None

    def pin(self, key_id: str) -> PinnedKey | None:
        return self.keys.get(key_id)

    def principals(self) -> frozenset[str]:
        return frozenset(p.principal for p in self.keys.values())

    # -- persistence --------------------------------------------------------- #

    def to_json(self) -> dict[str, Any]:
        return {"keys": {k: v.to_json() for k, v in self.keys.items()}}

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> KeyRing:
        """Rebuild for verification. Public keys only; there is no private half here.

        Raises rather than skipping an entry it cannot read: a trust store that
        silently drops a key would report ``unknown_key`` for every receipt that
        key signed, and an operator would debug the ledger instead of the store.
        """
        entries = raw.get("keys")
        if not isinstance(entries, Mapping):
            raise ValueError("a keyring must have a 'keys' object")
        ring = cls()
        for key_id, entry in entries.items():
            if not isinstance(entry, Mapping):
                raise ValueError(f"keyring entry {key_id!r} is not an object")
            alg = entry.get("alg")
            principal = entry.get("principal")
            if not isinstance(principal, str) or not principal:
                raise ValueError(f"keyring entry {key_id!r} has no principal")
            verifier: Verifier
            if alg == ALG_ED25519:
                public = entry.get("public")
                if not isinstance(public, str) or not public:
                    raise ValueError(
                        f"keyring entry {key_id!r} is Ed25519 but carries no public key"
                    )
                verifier = Ed25519Signer.from_public_hex(public, key_id=str(key_id))
            elif alg == ALG_HMAC_SHA256:
                raise ValueError(
                    f"keyring entry {key_id!r} is HMAC, which cannot be distributed: "
                    "a shared secret in a trust store is a secret every reader can "
                    "forge with. Use Ed25519 for anything a third party verifies."
                )
            else:
                raise ValueError(f"keyring entry {key_id!r} has unsupported alg {alg!r}")
            ring = ring.add(
                str(key_id),
                verifier,
                principal=principal,
                revoked=bool(entry.get("revoked")),
                note=str(entry.get("note") or ""),
            )
        return ring

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_json(), indent=2, sort_keys=True), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | Path) -> KeyRing:
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))

    def __bool__(self) -> bool:
        """Always true, so an empty keyring is not mistaken for "no keyring".

        The distinction matters: no keyring means "do not check signatures",
        an empty keyring means "check them, and trust nothing".
        """
        return True
