"""Core value objects for accountable agent delegation.

Every object that records a decision is immutable and hashable, and every
receipt carries a deterministic content digest. That is what separates a
*receipt* from a *log line*: a receipt can be recomputed and checked by a
third party who trusts neither the delegator nor the delegate.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

__all__ = [
    "ARD_URN_PREFIX",
    "ArdEntry",
    "Candidate",
    "Delegation",
    "DelegationChain",
    "DelegationStatus",
    "DigestError",
    "PolicyDecision",
    "PolicyOutcome",
    "Receipt",
    "Task",
    "canonical_json",
    "content_digest",
    "new_id",
    "parse_ard_urn",
]

ARD_URN_PREFIX = "urn:air:"

#: Media types ARD defines for commonly discovered artefacts.
TYPE_A2A_AGENT_CARD = "application/a2a-agent-card+json"
TYPE_MCP_SERVER_CARD = "application/mcp-server-card+json"
TYPE_AI_SKILL = "application/ai-skill+md"
TYPE_AI_REGISTRY = "application/ai-registry+json"


# --------------------------------------------------------------------------- #
# Deterministic serialisation helpers
# --------------------------------------------------------------------------- #


class DigestError(TypeError):
    """Raised when a value cannot be digested reproducibly.

    A digest that two machines might disagree about is worse than no digest: it
    makes verification fail for reasons the operator cannot see or fix. So this
    is raised rather than silently papered over. It subclasses ``TypeError``
    because that is what is actually wrong — the caller passed something the
    canonical form does not admit.
    """


def canonical_json(value: Any) -> str:
    """Serialise *value* deterministically *by construction*.

    Keys are sorted and separators are tight, so two processes on two machines
    agree on the bytes. Nothing here may depend on dict order, locale, hash
    randomisation, or float repr beyond what ``json`` guarantees.

    ``json.dumps(..., default=str)`` is **not** used, and that is deliberate.
    ``str()`` is not deterministic for a ``set`` — its iteration order follows
    hash randomisation, so ``str({"a", "b"})`` differs between interpreter runs
    and two processes would compute different digests for identical content.
    Sets are handled structurally instead (see :func:`_canonical`), and anything
    genuinely unsupported raises :class:`DigestError` rather than producing a
    digest that only happens to verify on the machine that wrote it.
    """
    return json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"))


def _canonical(value: Any) -> Any:
    """Return *value* in a form ``json.dumps`` serialises reproducibly."""
    if value is None or isinstance(value, (bool, str, int)):
        return value

    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            # NaN and Infinity are not valid JSON; json.dumps emits bare `NaN`
            # and `Infinity`, which strict parsers reject and which compare
            # unequal to themselves (NaN), so a digest over them cannot be
            # re-checked.
            raise DigestError(f"{value!r} is not representable in canonical JSON")
        # Normalise integral floats to int so that Receipt(cost_usd=1) and
        # Receipt(cost_usd=1.0) agree — the same value must not have two
        # digests depending on which numeric type the caller happened to pass.
        return int(value) if value.is_integer() else value

    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                # JSON object keys are strings. Coercing silently would let
                # {1: "a"} and {"1": "a"} collide into one digest; sorting
                # mixed types directly raises an opaque TypeError from sorted().
                raise DigestError(
                    f"canonical JSON requires string keys, got {type(key).__name__} ({key!r})"
                )
            out[key] = _canonical(item)
        return out

    if isinstance(value, (set, frozenset)):
        # Sorted, so iteration order cannot leak into the digest.
        return [_canonical(item) for item in sorted(value, key=repr)]

    if isinstance(value, (bytes, bytearray)):
        # Must precede the Sequence branch: bytes *are* a Sequence of ints, so
        # otherwise a blob would silently canonicalise to a list of numbers
        # rather than being refused.
        raise DigestError("bytes are not canonical JSON; encode them explicitly (e.g. base64)")

    if isinstance(value, Sequence):
        return [_canonical(item) for item in value]

    raise DigestError(
        f"cannot canonicalise {type(value).__name__}; "
        "convert it to a JSON-representable value first"
    )


def content_digest(value: Any) -> str:
    """Return ``sha256:<hex>`` over the canonical form of *value*.

    Raises :class:`DigestError` if *value* cannot be serialised reproducibly.
    """
    payload = canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def new_id(prefix: str) -> str:
    """Short, collision-resistant, human-scannable identifier."""
    return f"{prefix}_{int(time.time() * 1000):013d}_{secrets.token_hex(4)}"


def parse_ard_urn(identifier: str) -> tuple[str, str, str] | None:
    """Split an ARD identifier into ``(publisher, namespace, name)``.

    ARD Appendix C anchors identity to a domain so a registry can reject
    namespace squatting by cross-checking ``trustManifest.identity``. Returns
    ``None`` when *identifier* is not a well-formed ``urn:air:`` handle, which
    lets callers decide whether to skip or reject an entry.
    """
    if not identifier.startswith(ARD_URN_PREFIX):
        return None
    parts = identifier[len(ARD_URN_PREFIX) :].split(":")
    if len(parts) != 3 or not all(parts):
        return None
    return parts[0], parts[1], parts[2]


# --------------------------------------------------------------------------- #
# Discovery: the ARD entry
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ArdEntry:
    """One agentic resource as described by the ARD specification (v0.91).

    ARD itself is discovery-only. It deliberately says nothing about
    authentication, invocation, task lifecycle, or cost. This object therefore
    carries exactly the fields discovery guarantees, plus the provenance of
    *which registry said so* — nothing that ARD declined to define.
    """

    identifier: str
    display_name: str
    type: str
    url: str | None = None
    data: Mapping[str, Any] | None = None
    description: str | None = None
    capabilities: tuple[str, ...] = ()
    representative_queries: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    trust_manifest: Mapping[str, Any] | None = None
    # Provenance, not part of the ARD entry itself.
    source: str | None = None
    registry_score: float | None = None

    # -- ARD structural rules ------------------------------------------------ #

    @property
    def is_valid(self) -> bool:
        """ARD §4.2/§4.3: identifier, displayName and type are MUST; exactly
        one of ``url`` or ``data`` must be present.

        This is the *complete entry* rule, and it applies to entries a publisher
        emits — a manifest, an embedded document. It is deliberately **not** the
        rule for a search result; use :attr:`is_searchable` for that.
        """
        return self.has_identifier and self.has_target

    @property
    def has_identifier(self) -> bool:
        """ARD §4.2: the three MUST terms, minus the value-or-reference rule.

        ARD §5.3.2 requires only ``identifier`` of a search result: "a result is
        therefore not necessarily a complete ARD entry; its ``identifier`` names
        the authoritative one."
        """
        return bool(self.identifier and self.display_name and self.type)

    @property
    def has_target(self) -> bool:
        """True when the entry names how to reach the artifact.

        ARD §4.3 — exactly one of ``url`` (a reference) or ``data`` (inline).
        An entry can be perfectly discoverable and still have no target: a
        registry is permitted to omit ``url`` from a search result, and a client
        that needs the artifact then resolves it from the source that published
        the entry. Callers that intend to *invoke* something must check this;
        callers that intend to *rank* something need only ``has_identifier``.
        """
        return (self.url is None) != (self.data is None)

    @property
    def is_searchable(self) -> bool:
        """Whether this may be kept as a search result (ARD §5.3.2).

        Weaker than :attr:`is_valid` on purpose: a scored result with no target
        is still a legitimate answer to "which agents could do this", and
        throwing it away would lose candidates the registry meant to return.
        """
        return self.has_identifier

    @property
    def publisher(self) -> str | None:
        parsed = parse_ard_urn(self.identifier)
        return parsed[0] if parsed else None

    @property
    def capability_set(self) -> frozenset[str]:
        """Capabilities folded to a case-insensitive set for matching."""
        return frozenset(c.strip().lower() for c in self.capabilities if c and c.strip())

    @property
    def is_trusted(self) -> bool:
        """True when the entry carries a trust manifest (ARD §4.5).

        Presence is not verification. A registry is expected to verify the
        declared framework; we only record that a claim exists, and the policy
        engine decides whether an unverified claim is acceptable.
        """
        return bool(self.trust_manifest)

    @classmethod
    def from_ard(cls, raw: Mapping[str, Any], *, source: str | None = None) -> ArdEntry:
        """Build an entry from a parsed ARD document.

        Deliberately lenient: unknown terms from extension namespaces
        (ARD §4.1) are preserved rather than rejected, because a discovery
        layer that drops forward-compatible fields is useless in a federation.
        """

        def _str_tuple(value: Any) -> tuple[str, ...]:
            if value is None:
                return ()
            if isinstance(value, str):
                return (value,)
            if isinstance(value, Iterable):
                return tuple(str(v) for v in value if v is not None)
            return ()

        return cls(
            identifier=str(raw.get("identifier", "")),
            display_name=str(raw.get("displayName") or raw.get("display_name") or ""),
            type=str(raw.get("type", "")),
            url=raw.get("url"),
            data=raw.get("data"),
            description=raw.get("description"),
            capabilities=_str_tuple(raw.get("capabilities")),
            representative_queries=_str_tuple(
                raw.get("representativeQueries") or raw.get("representative_queries")
            ),
            tags=_str_tuple(raw.get("tags")),
            trust_manifest=raw.get("trustManifest") or raw.get("trust_manifest"),
            source=source,
            # ARD 5.3.2: search results carry a semantic relevance score. It is
            # informational only and explicitly not a trust signal, so it is
            # carried through untouched and never treated as one.
            registry_score=(
                float(raw["score"]) if isinstance(raw.get("score"), (int, float)) else None
            ),
        )

    def to_ard(self) -> dict[str, Any]:
        """Serialise back to an ARD-shaped document."""
        doc: dict[str, Any] = {
            "identifier": self.identifier,
            "displayName": self.display_name,
            "type": self.type,
        }
        if self.url is not None:
            doc["url"] = self.url
        if self.data is not None:
            doc["data"] = dict(self.data)
        if self.description:
            doc["description"] = self.description
        if self.capabilities:
            doc["capabilities"] = list(self.capabilities)
        if self.representative_queries:
            doc["representativeQueries"] = list(self.representative_queries)
        if self.tags:
            doc["tags"] = list(self.tags)
        if self.trust_manifest is not None:
            doc["trustManifest"] = dict(self.trust_manifest)
        return doc

    def fingerprint(self) -> str:
        """Stable digest of the description used to bind a receipt to it."""
        return content_digest(self.to_ard())


# --------------------------------------------------------------------------- #
# Work: the task
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Task:
    """A unit of work a principal wants performed.

    ARD will tell you which agents *could* do this. It will not tell you who
    asked, what they are willing to spend, or when it stops being worth doing.
    Those live here, because they are the inputs to accountability.
    """

    intent: str
    required_capabilities: tuple[str, ...] = ()
    task_id: str = field(default_factory=lambda: new_id("task"))
    issued_by: str = "urn:principal:anonymous"
    budget_usd: float | None = None
    deadline_epoch: float | None = None
    parent_delegation: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def capability_set(self) -> frozenset[str]:
        return frozenset(c.strip().lower() for c in self.required_capabilities if c.strip())

    @property
    def expired(self) -> bool:
        return self.deadline_epoch is not None and time.time() > self.deadline_epoch

    def child(self, intent: str, capabilities: Sequence[str], **kwargs: Any) -> Task:
        """Derive a sub-task that remembers which delegation spawned it.

        Sub-tasks are how a delegate re-delegates. Keeping the link explicit is
        what later lets the ledger reconstruct the whole chain rather than
        showing an orphaned hop.
        """
        return replace(
            self,
            intent=intent,
            required_capabilities=tuple(capabilities),
            task_id=new_id("task"),
            parent_delegation=kwargs.pop("parent_delegation", self.task_id),
            metadata={**self.metadata, **kwargs.pop("metadata", {})},
            **kwargs,
        )


# --------------------------------------------------------------------------- #
# Decision: policy
# --------------------------------------------------------------------------- #


class PolicyOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Why a delegation was permitted, refused, or held for a human.

    A denial is a first-class result, not an exception. Half the value of an
    accountability layer is being able to say *why* something did not happen.
    """

    outcome: PolicyOutcome
    rule: str
    detail: str = ""

    @property
    def allowed(self) -> bool:
        return self.outcome is PolicyOutcome.ALLOW


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Candidate:
    """An ARD entry scored against a task, with the signals kept visible.

    Scores are never collapsed into a single opaque number: ``signals`` exists
    so an operator can see *why* an agent was chosen, and so a bad route can be
    debugged after the fact.
    """

    entry: ArdEntry
    score: float
    signals: Mapping[str, float] = field(default_factory=dict)
    rejected_reason: str | None = None

    @property
    def eligible(self) -> bool:
        return self.rejected_reason is None


# --------------------------------------------------------------------------- #
# Delegation and its receipt
# --------------------------------------------------------------------------- #


class DelegationStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    COMPLETED = "completed"
    FAILED = "failed"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    """What a remote agent actually did, as attested by the executor.

    This lives on the receipt because a delegation that records only *that*
    something was invoked cannot answer the questions an audit actually asks:
    which remote task was it, how did that agent say it went, and under which
    credential was it authorised to ask.

    ``task_ref`` and ``state`` come from the wire (A2A); ``credential_ref`` comes
    from the executor's own configuration. All three are *attested* rather than
    verified — the same honesty the receipt already applies to ``cost_usd``,
    which only the callee can know. See :mod:`agent_ledger.a2a` for what
    is and is not checked.

    **Deliberately not part of :meth:`Receipt.body`.** It is mixed into the
    canonical form only when present, so a receipt from before this existed —
    or one produced by a local executor — digests to exactly the bytes it always
    did. Adding an unconditional field would have changed every historical
    digest, and there is no version marker to make that migration safe.
    """

    #: The remote system's own identifier for the work, opaque to this library.
    task_ref: str | None = None
    #: The remote state, verbatim. Kept because it is richer than anything this
    #: library models — see :data:`agent_ledger.a2a.TASK_STATE_MEANING`.
    state: str | None = None
    #: Which credential was presented, as a *reference* (a SPIFFE ID, a key id,
    #: an OAuth client id) and never the secret itself.
    credential_ref: str | None = None
    #: The protocol binding used, e.g. ``"JSONRPC"``.
    binding: str | None = None

    @property
    def empty(self) -> bool:
        return not any((self.task_ref, self.state, self.credential_ref, self.binding))

    def to_json(self) -> dict[str, Any]:
        """Only the members that are set, so an absent field is absent."""
        out: dict[str, Any] = {}
        for key in ("task_ref", "state", "credential_ref", "binding"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> ExecutionRecord:
        return cls(
            task_ref=raw.get("task_ref"),
            state=raw.get("state"),
            credential_ref=raw.get("credential_ref"),
            binding=raw.get("binding"),
        )


@dataclass(frozen=True, slots=True)
class Delegation:
    """An authorised handoff of a task to one specific agent.

    This is the object the ecosystem is missing. A2A can *deliver* a task and
    ARD can *find* an agent, but neither produces an artefact stating "principal
    P, through chain C, authorised agent A to do scope S for at most B dollars
    until time T". Without that artefact there is nothing to audit.
    """

    task: Task
    delegate: ArdEntry
    delegated_by: str
    policy: PolicyDecision
    delegation_id: str = field(default_factory=lambda: new_id("dlg"))
    #: One stable receipt identity per delegation. Status transitions append a
    #: new line under the same id, so a chain can be reassembled at any point
    #: in a delegation's life rather than only after it settles.
    receipt_id: str = field(default_factory=lambda: new_id("rcpt"))
    parent_delegation_id: str | None = None
    depth: int = 0
    status: DelegationStatus = DelegationStatus.PENDING
    created_at: float = field(default_factory=time.time)

    @property
    def scope(self) -> dict[str, Any]:
        """The authority actually granted — the thing a receipt attests to."""
        return {
            "capabilities": sorted(self.task.capability_set),
            "budget_usd": self.task.budget_usd,
            "deadline_epoch": self.task.deadline_epoch,
            "delegate": self.delegate.identifier,
            "parent": self.parent_delegation_id,
            "depth": self.depth,
        }

    def receipt(
        self,
        *,
        status: DelegationStatus,
        cost_usd: float = 0.0,
        result_digest: str | None = None,
        parent_receipt_id: str | None = None,
        note: str = "",
        execution: ExecutionRecord | None = None,
    ) -> Receipt:
        return Receipt(
            delegation_id=self.delegation_id,
            task_id=self.task.task_id,
            delegate=self.delegate.identifier,
            delegated_by=self.delegated_by,
            outcome=status,
            cost_usd=cost_usd,
            budget_usd=self.task.budget_usd,
            scope_digest=content_digest(self.scope),
            result_digest=result_digest,
            parent_receipt_id=parent_receipt_id,
            depth=self.depth,
            note=note,
            receipt_id=self.receipt_id,
            execution=execution,
            # The delegation's own creation time, not ``time.time()``.
            #
            # One delegation keeps one receipt id across its whole life, so its
            # transitions must share an issuance time too — otherwise a receipt
            # changes a field that "when was this authorised" depends on, every
            # time its status advances. It also made every transition of one
            # delegation look like a forged duplicate to `Ledger.verify`, which
            # is how this was found.
            issued_at=self.created_at,
        )


@dataclass(frozen=True, slots=True)
class Receipt:
    """Verifiable evidence that a delegation was issued and how it ended.

    ``parent_receipt_id`` is the load-bearing field: it turns a bag of receipts
    into a chain, and a chain is what lets you answer "who is accountable for
    this outcome" after work has crossed three organisational boundaries.

    Numeric fields are normalised in :meth:`__post_init__` so that a receipt
    built in memory and the same receipt after a write/read cycle have identical
    digests. Without that, ``Receipt(cost_usd=1)`` and its reloaded counterpart
    (coerced to ``1.0`` by :meth:`from_json`) disagreed, and ``Ledger.verify()``
    reported an untouched file as tampered.
    """

    delegation_id: str
    task_id: str
    delegate: str
    delegated_by: str
    outcome: DelegationStatus
    cost_usd: float = 0.0
    budget_usd: float | None = None
    scope_digest: str = ""
    result_digest: str | None = None
    parent_receipt_id: str | None = None
    depth: int = 0
    note: str = ""
    receipt_id: str = field(default_factory=lambda: new_id("rcpt"))
    issued_at: float = field(default_factory=time.time)
    #: Populated only for chained lines (see :mod:`agent_ledger.ledger`).
    #: A sibling of the digest, never part of :meth:`body` — a field added to
    #: ``body()`` would change the digest of every receipt ever written.
    prev: str | None = None
    #: What a remote agent did, when the delegation was executed over a protocol
    #: that reports more than success or failure. Absent for local executions.
    execution: ExecutionRecord | None = None
    #: Envelope members, never part of :meth:`body`. See
    #: :mod:`agent_ledger.signing` for what each one proves.
    signature: str | None = None
    key_id: str | None = None
    alg: str | None = None
    #: The principal the signer *claims* to be. A claim, like ``delegated_by`` —
    #: it only becomes evidence when a pinned keyring says that principal
    #: controls ``key_id``. Recorded separately because a key identifies a key,
    #: not a person, and conflating the two is how a signature gets described as
    #: proving more than it does.
    signer: str | None = None

    def __post_init__(self) -> None:
        # ``object.__setattr__`` because the dataclass is frozen. The alternative
        # — coercing in ``from_json`` only — is what caused the round-trip bug:
        # one code path normalised, the other did not, so the digest depended on
        # which path the object came from.
        object.__setattr__(self, "cost_usd", float(self.cost_usd))
        if self.budget_usd is not None:
            object.__setattr__(self, "budget_usd", float(self.budget_usd))
        object.__setattr__(self, "issued_at", float(self.issued_at))
        object.__setattr__(self, "depth", int(self.depth))

    @property
    def chained(self) -> bool:
        """True when this line carries a link to its predecessor.

        Lines written before chain linkage existed are ``unchained``. They are
        not corrupt; they simply cannot be checked for deletion, and
        ``Ledger.verify()`` reports that rather than failing them.
        """
        return self.prev is not None

    def link_digest(self, *, prev: str | None) -> str:
        """Digest covering this line *and* its position in the chain.

        Separate from :meth:`digest` on purpose. ``digest`` must stay stable for
        every receipt ever written, so chain linkage is defined as a distinct
        value over ``body + digest + prev`` rather than by adding a field to
        ``body``.
        """
        return content_digest({"prev": prev, "digest": self.digest()})

    def body(self) -> dict[str, Any]:
        """Everything the digest covers, minus the digest itself.

        ``execution`` is included **only when present**, which is what keeps this
        backward compatible: a receipt without one — every receipt written before
        A2A execution existed, and every receipt from a local executor — digests
        to exactly the bytes it always did. Emitting ``"execution": null``
        unconditionally would have changed every historical digest, and with no
        version marker in the body there would be no way to tell those receipts
        from corrupt ones.

        The cost of that choice: a receipt that *does* carry an execution record
        has a digest that old verifiers cannot reproduce. That is the correct
        trade — it is the new receipts that need the new field protected.
        """
        body: dict[str, Any] = {
            "receipt_id": self.receipt_id,
            "delegation_id": self.delegation_id,
            "task_id": self.task_id,
            "delegate": self.delegate,
            "delegated_by": self.delegated_by,
            "outcome": self.outcome.value,
            "cost_usd": self.cost_usd,
            "budget_usd": self.budget_usd,
            "scope_digest": self.scope_digest,
            "result_digest": self.result_digest,
            "parent_receipt_id": self.parent_receipt_id,
            "depth": self.depth,
            "note": self.note,
            "issued_at": self.issued_at,
        }
        if self.execution is not None and not self.execution.empty:
            body["execution"] = self.execution.to_json()
        return body

    def digest(self) -> str:
        return content_digest(self.body())

    @property
    def over_budget(self) -> bool:
        return self.budget_usd is not None and self.cost_usd > self.budget_usd

    def signed_payload(self, ledger_id: str) -> bytes:
        """The bytes a signature covers: version, audience, linkage, content.

        A method rather than a bare function so a caller cannot accidentally omit
        ``prev`` — which would let a signed receipt be moved within a ledger — or
        ``ledger_id``, which would let it be moved between ledgers.
        """
        from .signing import signing_payload

        return signing_payload(ledger_id=ledger_id, prev=self.prev, digest=self.digest())

    def to_json(self) -> dict[str, Any]:
        """The stored line: the digested body, the digest, and the envelope.

        ``prev`` and the signature members are emitted only when present, so a
        plain receipt serialises to exactly the bytes this project has always
        written. Emitting ``"prev": null`` or ``"signature": null``
        unconditionally would silently rewrite every existing ledger on its next
        append.
        """
        line: dict[str, Any] = {**self.body(), "digest": self.digest()}
        if self.prev is not None:
            line["prev"] = self.prev
        if self.signature is not None:
            line["signature"] = self.signature
        if self.key_id is not None:
            line["key_id"] = self.key_id
        if self.alg is not None:
            line["alg"] = self.alg
        if self.signer is not None:
            line["signer"] = self.signer
        return line

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> Receipt:
        """Rebuild a receipt from a stored line.

        Deliberately strict, and deliberately a pure function of its input:

        * Missing mandatory terms raise ``KeyError``/``ValueError`` rather than
          being defaulted. This used to mint a *fresh random* ``receipt_id`` and
          a *current* ``issued_at`` for a line that lacked them, which made two
          parses of the same bytes produce different ids and therefore different
          digests — an unreproducible verification failure.
        * Numeric terms must be numeric. ``float("abc")`` raising ``ValueError``
          is the desired behaviour: the caller can report the line as malformed,
          which is better than storing a string where policy arithmetic expects
          a number.
        """
        return cls(
            delegation_id=str(raw["delegation_id"]),
            task_id=str(raw["task_id"]),
            delegate=str(raw["delegate"]),
            delegated_by=str(raw["delegated_by"]),
            outcome=DelegationStatus(str(raw["outcome"])),
            cost_usd=float(raw.get("cost_usd", 0.0)),
            budget_usd=raw.get("budget_usd"),
            scope_digest=str(raw.get("scope_digest", "")),
            result_digest=raw.get("result_digest"),
            parent_receipt_id=raw.get("parent_receipt_id"),
            depth=int(raw.get("depth", 0)),
            note=str(raw.get("note", "")),
            receipt_id=str(raw["receipt_id"]),
            issued_at=float(raw["issued_at"]),
            prev=raw.get("prev"),
            execution=(
                ExecutionRecord.from_json(raw["execution"])
                if isinstance(raw.get("execution"), Mapping)
                else None
            ),
            signature=raw.get("signature"),
            key_id=raw.get("key_id"),
            alg=raw.get("alg"),
            signer=raw.get("signer"),
        )


# --------------------------------------------------------------------------- #
# The chain
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class DelegationChain:
    """A reconstructed lineage of receipts, root principal first.

    This is the answer to the question no current registry can answer: given a
    finished piece of work, which human or system is accountable for it, what
    was each hop allowed to do, and did any hop exceed its authority.
    """

    receipts: tuple[Receipt, ...] = ()

    def __iter__(self) -> Iterator[Receipt]:
        return iter(self.receipts)

    def __len__(self) -> int:
        return len(self.receipts)

    @property
    def root(self) -> Receipt | None:
        return self.receipts[0] if self.receipts else None

    @property
    def leaf(self) -> Receipt | None:
        return self.receipts[-1] if self.receipts else None

    @property
    def total_cost(self) -> float:
        return round(sum(r.cost_usd for r in self.receipts), 6)

    @property
    def max_depth(self) -> int:
        return max((r.depth for r in self.receipts), default=0)

    def violations(self) -> tuple[str, ...]:
        """Every way this chain broke its own rules.

        Returned rather than raised: an auditor wants the full list, not the
        first problem.
        """
        problems: list[str] = []
        for receipt in self.receipts:
            if receipt.over_budget:
                problems.append(
                    f"{receipt.receipt_id}: spent ${receipt.cost_usd:.4f} "
                    f"over authorised ${receipt.budget_usd:.4f}"
                )
            if receipt.outcome is DelegationStatus.REVOKED:
                problems.append(f"{receipt.receipt_id}: revoked")
            if receipt.outcome is DelegationStatus.FAILED:
                problems.append(f"{receipt.receipt_id}: failed")
        return tuple(problems)

    @property
    def is_clean(self) -> bool:
        return not self.violations()

    def to_json(self) -> dict[str, Any]:
        return {
            "length": len(self.receipts),
            "total_cost_usd": self.total_cost,
            "max_depth": self.max_depth,
            "clean": self.is_clean,
            "violations": list(self.violations()),
            "receipts": [r.to_json() for r in self.receipts],
        }
