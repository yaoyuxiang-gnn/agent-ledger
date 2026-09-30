"""The ledger — append-only evidence of every delegation this grid issued.

Four properties make this different from a log file:

1. **Chains, not rows.** Every receipt carries the receipt id of its parent
   delegation's receipt, so a finished piece of work can be traced back through
   every hop to the principal who authorised it. A log tells you what happened;
   a chain tells you who owns it.
2. **Tamper-evident, by digest and by linkage.** The digest proves a line was
   not *edited*. ``prev`` proves it was not *deleted, reordered or inserted*.
   Neither proves authorship: a rewrite can recompute every digest. That needs
   signed receipts, which this library now implements — see ``signing.py``.
3. **Stable identity, evolving state.** A delegation keeps one receipt id for
   its whole life. Status transitions (issued -> accepted -> completed) append
   new lines under that id. The log keeps every transition; the *view*
   (:meth:`Ledger.current`) keeps only the latest. That split is what lets a
   chain be reassembled mid-flight instead of only after everything settles.
4. **Storage is a seam.** :class:`LedgerBackend` is four operations —
   ``append``, ``scan``, ``refresh``, ``close`` — so the append-only semantics
   are the contract and JSONL is merely the default implementation. The
   in-process and on-disk backends ship here; a shared or SQL-backed one is a
   follow-on behind the same protocol.

Storage defaults to JSONL: append-only, greppable, diffable, and readable by
anything that can read a text file. An audit trail that needs a database to
inspect is an audit trail nobody inspects.

**What "shared" does and does not mean yet.** A backend makes the *storage*
pluggable; it does not make a ledger safe to share between organisations.
Nothing here attributes a line to a writer, so a shared log without signed
receipts is a forgeable shared log, and presenting one as multi-party evidence
would launder "the ledger says" into apparent proof.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .matcher import ReputationIndex
from .models import (
    Delegation,
    DelegationChain,
    DelegationStatus,
    ExecutionRecord,
    Receipt,
    canonical_json,
    content_digest,
)
from .signing import (
    ALG_NONE,
    KeyRing,
    SignatureCheck,
    Signer,
    Verifier,
    signing_payload,
)

__all__ = [
    "JsonlBackend",
    "Ledger",
    "LedgerBackend",
    "LedgerIntegrity",
    "LedgerStats",
    "MemoryBackend",
    "RawLine",
    "SqliteBackend",
]

_ACTIVE = frozenset({DelegationStatus.PENDING, DelegationStatus.ACCEPTED})

#: Bumped when the *stored line format* changes in a way verification must know
#: about. It is mixed into the genesis link rather than added to a receipt's
#: ``body()``, because a new field in ``body()`` would change the digest of every
#: receipt ever written — and without a version marker there would be no way to
#: tell an old line from a corrupt one.
_FORMAT_VERSION = 1

#: Used when a ledger is not given an explicit identity. Stable so that digests
#: stay reproducible across processes and machines.
_DEFAULT_LEDGER_ID = "agent-ledger/default-ledger"


def _label(lineno: int, raw: Mapping[str, Any]) -> str:
    """Name a bad line for a human.

    Prefers the line's own ``receipt_id`` for readability but always includes
    the line number, because the id is attacker-controlled: a forged line can
    claim any id, and a report that echoes it points the operator at the wrong
    place.
    """
    claimed = raw.get("receipt_id")
    return (
        f"line {lineno} ({claimed})" if isinstance(claimed, str) and claimed else f"line {lineno}"
    )


def _indexed(
    entries: Sequence[tuple[int, Any]], malformed: list[int]
) -> list[tuple[int, Mapping[str, Any]]]:
    """Split raw lines into receipts we can judge and lines we cannot.

    Anything that parses as a JSON object but fails ``Receipt.from_json`` is
    appended to *malformed* **in place**, preserving line order, so the two
    categories can be reported side by side.
    """
    parsed: list[tuple[int, Mapping[str, Any]]] = []
    for lineno, raw in entries:
        if not isinstance(raw, Mapping):
            malformed.append(lineno)
            continue
        try:
            Receipt.from_json(raw)
        except (KeyError, ValueError, TypeError):
            malformed.append(lineno)
            continue
        parsed.append((lineno, raw))
    malformed.sort()
    return parsed


def _walk_chain(
    parsed: Sequence[tuple[int, Mapping[str, Any]]], genesis: str
) -> tuple[list[str], int, str | None]:
    """Follow ``prev`` links; return (broken labels, unchained count, head).

    A break means the line's ``prev`` does not equal the previous line's link,
    which is what a deletion, an insertion or a reorder looks like from inside
    the file. Lines with no ``prev`` at all are counted as *unchained* rather
    than failed: they predate linkage and cannot be checked either way. Saying
    so is the honest report; claiming the chain is intact is not.
    """
    broken: list[str] = []
    unchained = 0
    expected = genesis
    head: str | None = None
    for lineno, raw in parsed:
        prev = raw.get("prev")
        if prev is None:
            unchained += 1
            expected = genesis if not broken else expected
            try:
                head = _link_of_raw(raw)
            except (KeyError, ValueError, TypeError):
                head = None
            continue
        if prev != expected:
            broken.append(_label(lineno, raw))
        try:
            expected = _link_of_raw(raw)
            head = expected
        except (KeyError, ValueError, TypeError):
            expected = ""
            head = None
    return broken, unchained, head


def _link_of_raw(raw: Mapping[str, Any]) -> str:
    """Recompute the chain link a stored line should carry."""
    receipt = Receipt.from_json(raw)
    return receipt.link_digest(prev=receipt.prev)


def _orphans(parsed: Sequence[tuple[int, Mapping[str, Any]]]) -> list[str]:
    """Lines whose ``parent_receipt_id`` resolves to nothing in this ledger.

    Either history was truncated upstream, or the line was spliced in from
    another ledger. Today a missing parent silently becomes a chain *root*, so
    the claimed accountable principal is whatever the forger wrote.
    """
    known = {raw.get("receipt_id") for _, raw in parsed}
    return [
        _label(lineno, raw)
        for lineno, raw in parsed
        if raw.get("parent_receipt_id") and raw["parent_receipt_id"] not in known
    ]


def _duplicates(parsed: Sequence[tuple[int, Mapping[str, Any]]]) -> list[str]:
    """Receipt ids reused by lines that cannot both be genuine transitions.

    One delegation keeps **one** ``receipt_id`` for its whole life; status
    transitions append new lines under that id, and the view keeps the latest.
    So a repeated id is normal and must not be reported.

    What is not normal is a repeated id where the two lines disagree about
    something a transition cannot change — the task, the delegate, who
    authorised it, the budget, the scope — while claiming the same outcome. That
    is a forged line riding in under a real id, and the view will silently prefer
    whichever came last, rewriting budget accounting and reputation with a
    perfectly valid digest.

    The excluded set is exactly the fields a legitimate transition may alter:
    ``outcome``, ``cost_usd``, ``result_digest``, ``parent_receipt_id``, ``note``,
    ``execution``, the signature members, and the linkage fields. Everything else
    — the task, the delegate, the principal, the budget, the scope digest — is
    fixed at issuance, and a disagreement there is the finding.

    The signature members have to be excluded because every transition of one
    delegation carries a *different* signature: the signature covers the digest,
    and the digest changes with the outcome. Including them made the identity
    differ on every line, which reported each legitimate transition as a forged
    duplicate — the third time a field that legitimately varies caused exactly
    this false positive, after ``result_digest`` and ``issued_at``.
    """
    mutable = {
        "outcome",
        "cost_usd",
        "result_digest",
        "parent_receipt_id",
        "note",
        "execution",
        "digest",
        "prev",
        "issued_at",
        "signature",
        "key_id",
        "alg",
    }
    seen: dict[str, tuple[int, str, str | None]] = {}
    out: list[str] = []
    for lineno, raw in parsed:
        rid = raw.get("receipt_id")
        if not isinstance(rid, str) or not rid:
            continue
        identity = canonical_json({k: v for k, v in raw.items() if k not in mutable})
        # `outcome` arrives as a `DelegationStatus` when the line came from
        # `_lines` and as a plain string when it came straight from JSON.
        # Comparing the two directly is always unequal, which reported every
        # legitimate state transition as a forged duplicate. Normalise to the
        # stored form, which is what the comparison actually means.
        outcome = _outcome_text(raw.get("outcome"))
        prior = seen.get(rid)
        if prior is None:
            seen[rid] = (lineno, identity, outcome)
            continue
        prior_lineno, prior_identity, prior_outcome = prior
        if identity != prior_identity or outcome == prior_outcome:
            out.append(f"line {lineno} ({rid}) also on line {prior_lineno}")
        else:
            # A genuine transition: same identity, a different outcome.
            seen[rid] = (lineno, identity, outcome)
    return out


def _outcome_text(value: Any) -> str | None:
    """The stored text of an outcome, whichever form it arrived in."""
    if value is None:
        return None
    return value.value if isinstance(value, DelegationStatus) else str(value)


def _parses_as_receipt(line: str) -> bool:
    text = line.strip()
    if not text:
        return True
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return False
    if not isinstance(raw, Mapping):
        return False
    try:
        Receipt.from_json(raw)
    except (KeyError, ValueError, TypeError):
        return False
    return True


def _count_lines(path: Path) -> int:
    """Count stored lines cheaply, for change detection on refresh."""
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


# --------------------------------------------------------------------------- #
# Storage seam
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RawLine:
    """One stored line, exactly as it was written.

    ``raw`` is ``None`` when the line could not be parsed as a JSON object. It is
    kept rather than dropped because :meth:`Ledger.verify` must judge the file as
    it is — including a stored digest it needs to compare against, and a
    malformed line it needs to report.
    """

    lineno: int
    raw: Mapping[str, Any] | None


@runtime_checkable
class LedgerBackend(Protocol):
    """Where ledger lines live. Four operations, deliberately.

    This is the honest form of "a shared ledger backend": the append-only
    semantics are the contract, and JSONL is just the default implementation.
    A networked service, SQLite, or object storage can slot in behind this
    without touching ``Ledger``, ``Grid`` or the CLI — and without adding a
    runtime dependency to the core package.

    ``scan`` yields *raw* lines rather than :class:`Receipt` objects on purpose.
    Verification is about what is written down, including lines that do not
    parse; a backend that parsed for the caller would have to discard precisely
    the evidence an audit needs. Scan order is storage order, which for an
    append-only log is write order.
    """

    def append(self, line: str) -> None:
        """Append one serialised line, durably, or raise.

        Must not silently succeed when the write failed: the caller only
        advances its in-memory view after this returns.
        """
        ...

    def scan(self) -> Iterator[RawLine]:
        """Yield every stored line in write order."""
        ...

    def refresh(self) -> int:
        """Return how many lines were appended since the last call.

        The storage layer knows this cheaply; the ledger needs it so two
        instances on one store cannot diverge.
        """
        ...

    def close(self) -> None:
        """Release whatever this backend holds."""
        ...


class MemoryBackend:
    """A process-local backend. The default for ``Ledger()``.

    Used by the demo, the test suite, and anything that wants the delegation
    logic without persistence.
    """

    def __init__(self, lines: Iterable[str] = ()) -> None:
        self._lines: list[str] = list(lines)

    def append(self, line: str) -> None:
        self._lines.append(line)

    def scan(self) -> Iterator[RawLine]:
        for position, text in enumerate(self._lines):
            yield RawLine(position + 1, _parse_line(text))

    def refresh(self) -> int:
        """Report the current size. The ledger tracks its own read cursor.

        The count is honest rather than always-zero because a backend that
        claims nothing changed while holding new lines would leave the caller
        believing it is up to date.
        """
        return len(self._lines)

    def close(self) -> None:
        self._lines = []

    def __len__(self) -> int:
        return len(self._lines)


class JsonlBackend:
    """Append-only JSONL on the local filesystem.

    Chosen as the default because it can be read, diffed and grepped by anything
    — an audit trail that needs a database to inspect is an audit trail nobody
    inspects. ``O_APPEND`` semantics mean concurrent appends of a line smaller
    than the platform's write buffer do not interleave.

    It is **not** safe to share between organisations, and not merely because of
    concurrency: nothing here attributes a line to a writer.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._seen_lines = 0

    def append(self, line: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()

    def scan(self) -> Iterator[RawLine]:
        if not self.path.is_file():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for lineno, text in enumerate(handle, start=1):
                stripped = text.strip()
                if not stripped:
                    continue
                yield RawLine(lineno, _parse_line(stripped))

    def refresh(self) -> int:
        if not self.path.is_file():
            return 0
        try:
            current = _count_lines(self.path)
        except OSError:  # pragma: no cover - transient filesystem state
            return 0
        if current <= self._seen_lines:
            return 0
        new = current - self._seen_lines
        self._seen_lines = current
        return new

    def close(self) -> None:
        return

    @property
    def exists(self) -> bool:
        return self.path.is_file()

    def truncate_torn_tail(self) -> list[int]:
        """Drop the trailing run of unparseable lines; return their line numbers.

        A crash mid-append leaves a partial line. It is deliberately not removed
        on load — silently discarding bytes from an evidence file is worse than
        the problem — but it also cannot stay, because ``verify()`` reports it
        forever and a later append moves it mid-file, where it can no longer be
        attributed to the crash that caused it.
        """
        if not self.path.is_file():
            return []
        raw_lines = self.path.read_text(encoding="utf-8").splitlines()
        keep = len(raw_lines)
        while keep > 0 and _parse_line(raw_lines[keep - 1]) is None:
            keep -= 1
        if keep == len(raw_lines):
            return []

        removed = list(range(keep + 1, len(raw_lines) + 1))
        body = "\n".join(raw_lines[:keep])
        self.path.write_text(body + ("\n" if keep else ""), encoding="utf-8")
        self._seen_lines = keep
        return removed


def _parse_line(text: str) -> Mapping[str, Any] | None:
    """Parse one stored line into a JSON object, or ``None`` if it is not one."""
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return None
    return raw if isinstance(raw, Mapping) else None


#: Schema for :class:`SqliteBackend`. One column, deliberately — see the class
#: docstring for why per-field columns would silently break digests.
_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    lineno   INTEGER PRIMARY KEY AUTOINCREMENT,
    line     TEXT    NOT NULL
);
CREATE TRIGGER IF NOT EXISTS receipts_are_append_only_update
BEFORE UPDATE ON receipts
BEGIN
    SELECT RAISE(ABORT, 'the ledger is append-only: UPDATE is not permitted');
END;
CREATE TRIGGER IF NOT EXISTS receipts_are_append_only_delete
BEFORE DELETE ON receipts
BEGIN
    SELECT RAISE(ABORT, 'the ledger is append-only: DELETE is not permitted');
END;
"""


class SqliteBackend:
    """Append-only storage in SQLite. Standard library, so still zero deps.

    The reason to reach for this over JSONL is not speed, it is **atomicity and
    enforcement**. A row insert is atomic, so the torn-tail class of corruption
    cannot happen at all; and the append-only rule stops being a convention the
    code follows and becomes one the database refuses to break, via triggers that
    raise on ``UPDATE`` and ``DELETE``. For a store several processes write to,
    that is a materially stronger position than a text file plus discipline.

    What it costs is the property ``ledger.py`` opens by defending: JSONL can be
    read, diffed and grepped by anything, and a database cannot. So this is an
    option, not the default.

    **The receipt is stored as one canonical-JSON text column, never as
    per-field columns.** That is not laziness. Field columns would round-trip
    ``1`` as ``1.0``, ``None`` as ``NULL`` or ``""``, and reorder nothing but
    look like it might — every one of which changes the digest, and the digest is
    what the whole design rests on. Storing the exact bytes that were hashed is
    the only safe mapping.

    ``sqlite3`` is imported inside ``__init__`` rather than at module scope, so
    that the JSONL path — the default — never pays for it.
    """

    def __init__(self, path: str | Path, *, timeout: float = 5.0) -> None:
        import sqlite3

        self.sqlite3 = sqlite3
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # `check_same_thread=False` because a Ledger is passed between threads in
        # ordinary use; SQLite serialises access itself, and `timeout` is what
        # makes a second process wait rather than fail immediately.
        self._conn = sqlite3.connect(str(self.path), timeout=timeout, check_same_thread=False)
        self._conn.executescript(_SQLITE_SCHEMA)
        self._conn.commit()
        self._seen = 0

    def append(self, line: str) -> None:
        self._conn.execute("INSERT INTO receipts (line) VALUES (?)", (line,))
        self._conn.commit()

    def scan(self) -> Iterator[RawLine]:
        cursor = self._conn.execute("SELECT lineno, line FROM receipts ORDER BY lineno")
        for lineno, text in cursor:
            yield RawLine(int(lineno), _parse_line(text))

    def refresh(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()
        current = int(row[0]) if row else 0
        new = max(0, current - self._seen)
        self._seen = current
        return new

    def close(self) -> None:
        self._conn.close()

    def integrity_check(self) -> bool:
        """SQLite's own consistency check, for a store rather than a sequence.

        Complements :meth:`Ledger.verify` rather than duplicating it: this finds
        corruption *in the database file*, verify finds inconsistency in the
        receipts.
        """
        row = self._conn.execute("PRAGMA integrity_check").fetchone()
        return bool(row) and row[0] == "ok"

    @property
    def exists(self) -> bool:
        return self.path.is_file()


@dataclass(frozen=True, slots=True)
class LedgerIntegrity:
    """Outcome of re-checking every line in the ledger.

    Each tuple names a distinct failure, because "the ledger is bad" is not an
    actionable statement. The distinctions that matter in practice:

    ``tampered``
        A line whose content no longer matches its own digest, or a line whose
        digest is missing — a missing digest is not an absence of evidence, it
        *is* the evidence, since every line this library writes carries one.
    ``malformed``
        A line that cannot be parsed as a receipt at all, by line number.
    ``broken_chain``
        A line whose ``prev`` does not match the preceding line's link, which is
        what a deletion, an insertion or a reordering looks like.
    ``orphaned``
        A ``parent_receipt_id`` that resolves to no receipt in this ledger —
        either a truncated history or a receipt spliced in from another ledger.
    ``duplicated``
        A ``receipt_id`` appearing in two *different* lines. The same id in a
        later line is a legitimate state transition; two lines with the same id
        and different content are not.
    ``unchained``
        A count, not a failure. Lines written before chain linkage existed.
    ``bad_signature`` / ``unknown_key`` / ``unknown_alg``
        A line whose signature does not check out. Populated only when a verifier
        was supplied: the ledger cannot check a signature it holds no key for, and
        reporting "unsigned" for a line that *is* signed but unverifiable would be
        a different lie.
    ``signed``
        A count. Lines carrying a signature that verified.
    """

    checked: int
    tampered: tuple[str, ...] = ()
    malformed: tuple[int, ...] = ()
    broken_chain: tuple[str, ...] = ()
    orphaned: tuple[str, ...] = ()
    duplicated: tuple[str, ...] = ()
    no_digest: tuple[str, ...] = ()
    unchained: int = 0
    #: The path does not exist. Reported as a failure, not as an empty ledger:
    #: ``al verify --ledger typo.jsonl`` printing *0 receipt lines verified* and
    #: exiting 0 is a typo that reads as a clean audit trail.
    missing: bool = False
    bad_signature: tuple[str, ...] = ()
    unknown_key: tuple[str, ...] = ()
    unknown_alg: tuple[str, ...] = ()
    #: A good signature on a key that is not allowed to speak for the principal
    #: the line claims. Only a pinned keyring can detect this, and it is the
    #: difference between "a key signed this" and "**this principal** signed it".
    principal_mismatch: tuple[str, ...] = ()
    #: A good signature by a key that has been revoked. Kept distinct from
    #: ``bad_signature`` because the history is still attributable — we know who
    #: held the key — it is only the authority that lapsed.
    revoked: tuple[str, ...] = ()
    signed: int = 0
    #: The ledger identity signatures and the genesis link were computed against.
    #: Surfaced because it is *not* stored in the file: a verifier that was not
    #: told which identity to use sees a broken chain and a bad signature, when
    #: the real problem is that it checked against the wrong thing. Reporting it
    #: turns a mystery into an instruction.
    ledger_id: str | None = None
    #: Digest of the last chained line, or ``None``. Publishing this out of band
    #: (a commit, a peer, a release artefact) is the only thing that makes
    #: truncation of the *tail* detectable — a truncated prefix is otherwise a
    #: perfectly consistent hash chain.
    chain_head: str | None = None

    @property
    def ok(self) -> bool:
        return not self.missing and not any(
            (
                self.tampered,
                self.malformed,
                self.broken_chain,
                self.orphaned,
                self.duplicated,
                self.no_digest,
                self.bad_signature,
                self.unknown_key,
                self.unknown_alg,
                self.principal_mismatch,
                self.revoked,
            )
        )

    def describe(self) -> str:
        if self.missing:
            return "no such ledger file"
        if self.ok:
            base = f"{self.checked} receipt lines verified"
            notes: list[str] = []
            if self.signed:
                notes.append(f"{self.signed} signed")
            if self.unchained:
                # Saying "chain intact" here would be a claim about a property
                # this ledger does not have. Lines written before chain linkage
                # existed cannot be checked for deletion, and the report says so.
                notes.append(
                    f"{self.unchained} unchained (written before chain linkage, "
                    "so deletion is not detectable)"
                )
            return f"{base}; " + ", ".join(notes) if notes else f"{base}, chain intact"
        bits = []
        if self.tampered:
            bits.append(f"{len(self.tampered)} tampered ({', '.join(self.tampered[:3])})")
        if self.malformed:
            bits.append(f"{len(self.malformed)} unreadable lines {list(self.malformed[:3])}")
        if self.no_digest:
            bits.append(f"{len(self.no_digest)} lines with no digest")
        if self.broken_chain:
            bits.append(
                f"{len(self.broken_chain)} broken chain links ({', '.join(self.broken_chain[:3])})"
            )
        if self.bad_signature:
            bits.append(
                f"{len(self.bad_signature)} bad signatures ({', '.join(self.bad_signature[:3])})"
            )
        if self.unknown_key:
            bits.append(f"{len(self.unknown_key)} unknown keys ({', '.join(self.unknown_key[:3])})")
        if self.unknown_alg:
            bits.append(
                f"{len(self.unknown_alg)} unknown algorithms ({', '.join(self.unknown_alg[:3])})"
            )
        if self.principal_mismatch:
            bits.append(
                f"{len(self.principal_mismatch)} principal mismatches "
                f"({', '.join(self.principal_mismatch[:3])})"
            )
        if self.revoked:
            bits.append(f"{len(self.revoked)} revoked keys ({', '.join(self.revoked[:3])})")
        if self.orphaned:
            bits.append(f"{len(self.orphaned)} orphaned parents ({', '.join(self.orphaned[:3])})")
        if self.duplicated:
            bits.append(f"{len(self.duplicated)} duplicated receipt ids")
        if self.unchained:
            bits.append(f"{self.unchained} unchained")
        return "; ".join(bits)


@dataclass(frozen=True, slots=True)
class LedgerStats:
    """Aggregate view over current delegation state."""

    receipts: int = 0
    delegations: int = 0
    agents: int = 0
    total_cost_usd: float = 0.0
    by_outcome: Mapping[str, int] = field(default_factory=dict)

    def describe(self) -> str:
        outcomes = ", ".join(f"{k}={v}" for k, v in sorted(self.by_outcome.items()))
        return (
            f"{self.delegations} delegations / {self.agents} agents / "
            f"${self.total_cost_usd:.4f}" + (f" ({outcomes})" if outcomes else "")
        )


class Ledger:
    """Append-only receipt log with a derived current-state view.

    An in-memory ledger (``Ledger()``) behaves identically minus persistence,
    which is what the offline demo and the test suite use.

    **Limits, stated where the code is.** The digest proves a line was not
    *edited*. Chain linkage (``prev``) proves a line was not *deleted,
    reordered or inserted*. Neither proves *who wrote it* — that needs signed
    receipts. And neither detects truncation of the **tail**: a shortened prefix
    is still a perfectly consistent chain, so completeness requires an
    externally published ``chain_head``.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        ledger_id: str | None = None,
        backend: LedgerBackend | None = None,
        signer: Signer | None = None,
        verifier: Verifier | None = None,
        keyring: KeyRing | None = None,
    ) -> None:
        """Open a ledger over *backend*, or over JSONL at *path*.

        ``path`` remains the common case and behaves exactly as before. Passing
        ``backend`` instead is how a host swaps storage without touching any
        caller: ``Grid``, the CLI and the tests only ever go through this class.

        ``signer`` signs every line at :meth:`record`, which is the only place a
        line is written — so no call site can forget, including
        ``Grid._record_refusal``, which builds a bare :class:`Receipt` directly
        and would otherwise produce the only unsigned lines in a signed ledger.
        ``verifier`` or ``keyring`` are used by :meth:`verify`.
        """
        if backend is not None:
            self.backend: LedgerBackend = backend
            self.path: Path | None = getattr(backend, "path", None)
        elif path is not None:
            self.path = Path(path)
            self.backend = JsonlBackend(self.path)
        else:
            self.path = None
            self.backend = MemoryBackend()
        #: Identity mixed into the genesis link. Two ledgers with different ids
        #: produce different links for their first line, so a receipt copied
        #: from one into the other shows up as a broken chain instead of
        #: verifying as a legitimate root. It is *also* bound into every signed
        #: payload, so a signed receipt cannot be replayed into another ledger.
        self.ledger_id = ledger_id
        #: The identity signatures are bound to. Explicit when given, otherwise
        #: derived from ``ledger_id`` so that a caller who set one gets the other
        #: for free rather than silently signing against the default.
        self.signing_identity = ledger_id or _DEFAULT_LEDGER_ID
        self.signer = signer
        self.verifier = verifier
        self.keyring = keyring
        self._lines: list[Receipt] = []
        self._latest: dict[str, Receipt] = {}
        self._by_delegation: dict[str, Receipt] = {}
        #: First-seen line index per receipt_id, so a duplicate id can be told
        #: apart from a legitimate later state transition.
        self._first_index: dict[str, int] = {}
        self._order: list[str] = []
        #: Every stored line, kept because verify() must judge what is *stored*
        #: (including malformed lines and stored digests) rather than a
        #: reconstructed view of it.
        self._raw: list[RawLine] = []
        self._malformed_lines: list[int] = []
        #: How many entries of ``backend.scan()`` have been consumed. A cursor
        #: rather than a high-water line number, because a backend may yield
        #: every line on every scan (``MemoryBackend`` does) and re-indexing
        #: them would duplicate the view.
        self._consumed = 0
        self._load()

    # -- loading ------------------------------------------------------------- #

    def _load(self) -> None:
        """Read new lines from the backend, tolerating one that cannot be parsed.

        A ledger is evidence, so a single bad line must not make the rest
        unreadable — `verify()` reports it instead. Nothing is silently dropped
        from the record: malformed lines are kept by line number.

        Reading appends rather than restarts, so ``refresh()`` can call this
        after another writer has extended the store. A line's digest never
        changes, so a line already read is the same object it was before.
        """
        start = self._consumed
        for position, entry in enumerate(self.backend.scan()):
            if position < start:
                continue
            self._consumed = position + 1
            self._raw.append(entry)
            if entry.raw is None:
                self._malformed_lines.append(entry.lineno)
                continue
            try:
                self._index(Receipt.from_json(entry.raw), lineno=entry.lineno)
            except (KeyError, ValueError, TypeError):
                # Parses as JSON but is not a receipt. Reported by verify(),
                # not raised here: one bad line must not stop an audit.
                self._malformed_lines.append(entry.lineno)

    def _index(self, receipt: Receipt, *, lineno: int | None = None) -> None:
        """Append to the log and advance the current-state view."""
        self._lines.append(receipt)
        self._latest[receipt.receipt_id] = receipt
        self._by_delegation[receipt.delegation_id] = receipt
        if receipt.receipt_id not in self._first_index:
            self._first_index[receipt.receipt_id] = len(self._lines) - 1
            self._order.append(receipt.receipt_id)

    # -- writing ------------------------------------------------------------- #

    def record(self, receipt: Receipt) -> Receipt:
        """Append a receipt and return it, so calls can be chained.

        The file is written **before** the in-memory view is updated. The reverse
        order meant a failed append still mutated the view, so a ledger that
        could not write reported delegations it did not hold.

        A chained ledger stamps ``prev`` here rather than at construction, so
        existing callers that build a bare :class:`Receipt` get linkage for free
        — including ``Grid._record_refusal``, which builds one directly and would
        otherwise produce the only unchained lines in the ledger.
        """
        if receipt.prev is None:
            receipt = replace(receipt, prev=self._head())
        if self.signer is not None and receipt.signature is None:
            payload = signing_payload(
                ledger_id=self.signing_identity,
                prev=receipt.prev,
                digest=receipt.digest(),
            )
            receipt = replace(
                receipt,
                signature=self.signer.sign(payload),
                key_id=self.signer.key_id,
                alg=self.signer.alg,
                # The signer's own claim about who it acts for. Recorded so a
                # pinned keyring has something to check against; on its own it is
                # a claim, not evidence, and the module docstring says so.
                signer=getattr(self.signer, "principal", None),
            )
        self.backend.append(json.dumps(receipt.to_json(), sort_keys=True))
        # Index directly, and advance the scan cursor past our own line.
        #
        # Re-reading storage here would also be correct, but it would make every
        # append O(n) — and with the per-candidate policy scans in `Grid`, that
        # turns a linear workload quadratic. The cursor is what keeps the two
        # views consistent: the next scan skips the line we just indexed instead
        # of replaying it.
        self._index(receipt)
        self._consumed += 1
        return receipt

    def _head(self) -> str:
        """Link value for the next line: the genesis link, or the last link."""
        if not self._lines:
            return self._genesis()
        return self._link_of(self._lines[-1])

    def _link_of(self, receipt: Receipt) -> str:
        return receipt.link_digest(prev=receipt.prev)

    def receipt_delegation(
        self,
        delegation: Delegation,
        *,
        status: DelegationStatus,
        cost_usd: float = 0.0,
        result_digest: str | None = None,
        note: str = "",
        execution: ExecutionRecord | None = None,
    ) -> Receipt:
        """Advance a delegation's state, automatically linking it to its parent.

        That lookup is the whole trick: a caller reports one hop and the ledger
        reconstructs the lineage. It works mid-flight because a parent's
        receipt exists from the moment the parent delegation is issued.
        """
        parent_receipt_id: str | None = None
        if delegation.parent_delegation_id:
            parent = self._by_delegation.get(delegation.parent_delegation_id)
            if parent is not None:
                parent_receipt_id = parent.receipt_id

        return self.record(
            delegation.receipt(
                status=status,
                cost_usd=cost_usd,
                result_digest=result_digest,
                parent_receipt_id=parent_receipt_id,
                note=note,
                execution=execution,
            )
        )

    # -- reading ------------------------------------------------------------- #

    def __iter__(self) -> Iterator[Receipt]:
        """Iterate current state, one entry per delegation."""
        return iter(self.current())

    def __len__(self) -> int:
        """Number of delegations currently tracked."""
        return len(self._by_delegation)

    def __bool__(self) -> bool:
        """Always true, so an empty ledger stops being falsy.

        ``__len__`` made ``Ledger()`` falsy, which is documented but is still a
        footgun: ``ledger or Ledger()`` silently discards the caller's ledger —
        the exact bug that once made this project report an empty audit trail
        while holding a full one. Emptiness is a property of the contents, not a
        reason to substitute a different object, so this defers to ``is not
        None`` the way every other object does.
        """
        return True

    def current(self) -> tuple[Receipt, ...]:
        """The current receipt for every delegation, in first-seen order.

        O(n). The previous version scanned an accumulating list per line to
        deduplicate, which is O(n²) and sat on the hot path: reputation seeding
        and each policy check re-scanned the whole ledger, so a 20k-line ledger
        cost ~11 full scans per ``delegate()``.
        """
        self.refresh()
        return tuple(self._latest[rid] for rid in self._order if rid in self._latest)

    @property
    def receipts(self) -> Sequence[Receipt]:
        """Current state. Use :attr:`lines` for the raw append-only log."""
        return self.current()

    @property
    def lines(self) -> Sequence[Receipt]:
        """Every line ever appended, including superseded transitions."""
        self.refresh()
        return tuple(self._lines)

    def by_delegation(self, delegation_id: str) -> Receipt | None:
        self.refresh()
        return self._by_delegation.get(delegation_id)

    def by_id(self, receipt_id: str) -> Receipt | None:
        self.refresh()
        return self._latest.get(receipt_id)

    # -- chains -------------------------------------------------------------- #

    def chain(self, receipt: Receipt | str) -> DelegationChain:
        """Rebuild the lineage ending at *receipt*, root principal first.

        Walks ``parent_receipt_id`` upward. Cycles are impossible in a
        correctly written ledger but are guarded against anyway, because a
        corrupted ledger must never be able to hang an audit.
        """
        if isinstance(receipt, str):
            node = self.by_id(receipt)
        else:
            node = self._latest.get(receipt.receipt_id, receipt)
        if node is None:
            return DelegationChain()

        lineage: list[Receipt] = []
        seen: set[str] = set()
        while node is not None and node.receipt_id not in seen:
            seen.add(node.receipt_id)
            lineage.append(node)
            node = self._latest.get(node.parent_receipt_id) if node.parent_receipt_id else None

        lineage.reverse()
        return DelegationChain(tuple(lineage))

    def leaves(self) -> list[Receipt]:
        """Current receipts nothing else claims as a parent — chain tips."""
        current = self.current()
        parents = {r.parent_receipt_id for r in current if r.parent_receipt_id}
        return [r for r in current if r.receipt_id not in parents]

    def chains(self) -> list[DelegationChain]:
        """One lineage per chain tip, so every delegation is accounted for."""
        return [self.chain(leaf) for leaf in self.leaves()]

    def walk(self, root_receipt_id: str) -> DelegationChain:
        """Everything downstream of a root, in breadth-first issue order."""
        current = self.current()
        children: dict[str, list[Receipt]] = {}
        for receipt in current:
            if receipt.parent_receipt_id:
                children.setdefault(receipt.parent_receipt_id, []).append(receipt)

        ordered: list[Receipt] = []
        queue = [root_receipt_id]
        seen: set[str] = set()
        while queue:
            node_id = queue.pop(0)
            if node_id in seen:
                continue
            seen.add(node_id)
            node = self._latest.get(node_id)
            if node is None:
                continue
            ordered.append(node)
            queue.extend(child.receipt_id for child in children.get(node_id, []))
        return DelegationChain(tuple(ordered))

    # -- budget accounting --------------------------------------------------- #

    def spent_for_task(self, task_id: str) -> float:
        """Money already spent by any delegation derived from *task_id*."""
        return round(sum(r.cost_usd for r in self.current() if r.task_id == task_id), 6)

    def committed_for_task(self, task_id: str) -> float:
        """Budget still outstanding on delegations that have not settled.

        Policy must count commitments, not just spend, or a chain can authorise
        five concurrent delegations that are each under the cap and
        collectively far over it.
        """
        return round(
            sum(
                r.budget_usd or 0.0
                for r in self.current()
                if r.task_id == task_id and r.outcome in _ACTIVE
            ),
            6,
        )

    # -- derived views ------------------------------------------------------- #

    def reputation(self) -> ReputationIndex:
        """Seed a reputation index from the current state of every delegation."""
        return ReputationIndex().extend(self.current())

    def stats(self) -> LedgerStats:
        current = self.current()
        outcomes: dict[str, int] = {}
        for receipt in current:
            key = receipt.outcome.value
            outcomes[key] = outcomes.get(key, 0) + 1
        return LedgerStats(
            receipts=len(self._lines),
            delegations=len({r.delegation_id for r in current}),
            agents=len({r.delegate for r in current}),
            total_cost_usd=round(sum(r.cost_usd for r in current), 6),
            by_outcome=outcomes,
        )

    def verify(
        self,
        *,
        strict_chain: bool = False,
        require_signature: bool = False,
        verifier: Verifier | None = None,
    ) -> LedgerIntegrity:
        """Re-check every stored line and report what does not hold.

        Checks what is **on disk**, not the derived view: a superseded
        transition that was edited after the fact is still tampering, and a
        malformed line is evidence about the file even though it contributes
        nothing to the view.

        This never raises. A ledger is evidence, and an evidence checker that
        crashes on hostile input hands the attacker exactly what they want — the
        previous implementation traced back with ``KeyError`` on a line as
        ordinary as ``{"receipt_id": "x", "digest": "..."}``, which meant one
        appended line could disable ``al verify`` entirely.

        Signature checking is opt-in via *verifier* (or a ``keyring`` given to
        the constructor). It has to be: the ledger cannot check a signature it
        holds no key for, and silently reporting "fine" for a signed line it
        could not check would be worse than saying nothing. With
        ``require_signature=True`` an unsigned line is a failure — which is the
        setting a deployment wants, and the wrong default for a ledger written
        before signing existed.

        What this does **not** detect, and cannot without help from outside the
        file:

        * **Truncation of the tail.** A shortened prefix is a consistent chain.
          Publish :attr:`LedgerIntegrity.chain_head` somewhere out of band to
          detect it.
        * **A missing file.** ``checked`` stays 0 rather than the count of lines
          once read, because reporting a healthy audit for a file that is not
          there is the one failure mode an operator will not notice.
        * **A signature whose key is unknown.** Reported as ``unknown_key``, not
          as a pass. A signature is only evidence if you know whose it is, and
          that needs a pinned keyring — see :class:`agent_ledger.signing.KeyRing`.
        """
        if self.path is not None and not self.path.is_file():
            # A file that is not there is not a healthy ledger. Say so rather
            # than returning the same shape as a legitimately empty one.
            return LedgerIntegrity(0, missing=True)

        entries: list[RawLine] = list(self.backend.scan())
        malformed = [entry.lineno for entry in entries if entry.raw is None]
        objects: list[tuple[int, Any]] = [
            (entry.lineno, entry.raw) for entry in entries if entry.raw is not None
        ]

        parsed = _indexed(objects, malformed)

        # A missing digest is itself the finding: every line this library writes
        # carries one, so its absence is not "nothing to check" but evidence of
        # an edit.
        no_digest = [_label(lineno, raw) for lineno, raw in parsed if raw.get("digest") is None]
        tampered = list(no_digest)
        for lineno, raw in parsed:
            if raw.get("digest") is None:
                continue
            try:
                recomputed = Receipt.from_json(raw).digest()
            except (KeyError, ValueError, TypeError):
                # Already reported as malformed; the digest cannot be judged.
                continue
            if raw["digest"] != recomputed:
                tampered.append(_label(lineno, raw))

        broken_chain, unchained, head = _walk_chain(parsed, self._genesis())
        if strict_chain and unchained:
            # Only for a deployment that has committed to linkage everywhere.
            # Off by default so upgrading does not declare existing ledgers
            # corrupt — but then the report says how many lines it could not
            # check, rather than claiming the chain is intact.
            broken_chain.extend(_label(n, r) for n, r in parsed if r.get("prev") is None)

        # Fall back to the verifier the ledger was constructed with. Without
        # this, `Ledger(path, verifier=...)` silently checked nothing: the
        # early-return below saw a `None` parameter and skipped signature
        # checking entirely, so a bad signature reported a clean ledger.
        verifier = verifier if verifier is not None else self.verifier
        if verifier is None and self.keyring is None and self.signer is not None:
            # A signer that can also verify is the overwhelmingly common case
            # (HMAC, and any Ed25519 signer holding its own key). Requiring the
            # caller to pass the same object twice would be a footgun with no
            # upside, so `require_signature=True` works out of the box. A
            # *public-key-only* verifier is the case that must be passed
            # explicitly, and that is the case where it matters.
            verifier = self.signer if isinstance(self.signer, Verifier) else None

        signed, bad_signature, unknown_key, unknown_alg, mismatch, revoked = self._check_signatures(
            parsed, verifier=verifier, require_signature=require_signature
        )

        return LedgerIntegrity(
            checked=len(parsed),
            tampered=tuple(tampered),
            malformed=tuple(malformed),
            broken_chain=tuple(broken_chain),
            orphaned=tuple(_orphans(parsed)),
            duplicated=tuple(_duplicates(parsed)),
            no_digest=tuple(no_digest),
            unchained=0 if strict_chain else unchained,
            missing=False,
            bad_signature=tuple(bad_signature),
            unknown_key=tuple(unknown_key),
            unknown_alg=tuple(unknown_alg),
            principal_mismatch=tuple(mismatch),
            revoked=tuple(revoked),
            signed=signed,
            ledger_id=self.signing_identity,
            chain_head=head,
        )

    def check_signature(
        self, receipt: Receipt, *, verifier: Verifier | None = None
    ) -> SignatureCheck:
        """Check one receipt's signature and say precisely what was wrong.

        Public so a caller can check a *single* receipt — one shipped to a
        partner, say — without handing over the ledger it came from.

        With a pinned ``keyring`` this answers the question signing alone cannot:
        not merely "which key signed this" but "**who** signed this", by comparing
        the principal the receipt claims against the principal the keyring says
        owns that key.
        """
        if receipt.signature is None:
            return SignatureCheck(
                "unsigned" if receipt.alg is None else "bad_signature",
                "no signature on this line" if receipt.alg is None else "alg set but no signature",
            )
        if receipt.alg == ALG_NONE:
            # An explicit "none" is a downgrade attempt, not an absence.
            return SignatureCheck("bad_signature", "alg is 'none'")

        checker: Verifier | None = verifier if verifier is not None else self.verifier
        pinned = self.keyring.pin(receipt.key_id) if (self.keyring and receipt.key_id) else None
        if checker is None and pinned is not None:
            checker = pinned.verifier
        elif checker is None and self.keyring is not None and receipt.key_id is not None:
            return SignatureCheck("unknown_key", f"no key pinned for {receipt.key_id!r}")
        if checker is None:
            return SignatureCheck("unknown_key", "no verifier configured for this ledger")
        if receipt.alg is not None and receipt.alg != checker.alg:
            # Algorithm confusion: an HMAC tag must never be accepted where an
            # Ed25519 signature was claimed, or the weaker one becomes a forgery
            # tool for the stronger.
            return SignatureCheck(
                "unknown_alg", f"line claims {receipt.alg}, verifier is {checker.alg}"
            )

        payload = signing_payload(
            ledger_id=self.signing_identity, prev=receipt.prev, digest=receipt.digest()
        )
        if not checker.verify(payload, receipt.signature, key_id=receipt.key_id):
            return SignatureCheck("bad_signature", "signature does not match")

        # The signature is good, which establishes a *key*. The remaining question
        # is whether that key may speak for the principal claimed, and only a
        # pinned keyring can answer it — which is precisely why an unpinned
        # verifier cannot catch a forger who signs with their own key and writes
        # someone else's name beside it.
        if pinned is not None:
            if pinned.revoked:
                detail = f"key {receipt.key_id!r} ({pinned.principal}) is revoked"
                if pinned.note:
                    detail += f": {pinned.note}"
                return SignatureCheck("revoked", detail)
            if receipt.signer is None:
                return SignatureCheck(
                    "unattributed",
                    f"signed by {pinned.principal} but the line names no signer",
                )
            if receipt.signer != pinned.principal:
                return SignatureCheck(
                    "principal_mismatch",
                    f"key {receipt.key_id!r} belongs to {pinned.principal!r}, "
                    f"but the line claims {receipt.signer!r}",
                )
        return SignatureCheck("ok")

    def _check_signatures(
        self,
        parsed: Sequence[tuple[int, Mapping[str, Any]]],
        *,
        verifier: Verifier | None,
        require_signature: bool,
    ) -> tuple[int, list[str], list[str], list[str], list[str], list[str]]:
        """Check every signature that can be checked; return the six buckets."""
        if verifier is None and self.keyring is None and not require_signature:
            # Nothing to check with, and nothing demanded. Reporting a count of
            # verified signatures here would be a claim about work not done.
            return 0, [], [], [], [], []

        signed = 0
        bad: list[str] = []
        no_key: list[str] = []
        bad_alg: list[str] = []
        mismatch: list[str] = []
        revoked: list[str] = []
        for lineno, raw in parsed:
            try:
                receipt = Receipt.from_json(raw)
            except (KeyError, ValueError, TypeError):
                continue  # already reported as malformed
            check = self.check_signature(receipt, verifier=verifier)
            if check.ok:
                signed += 1
                continue
            label = _label(lineno, raw)
            if check.status == "unknown_key":
                no_key.append(label)
            elif check.status == "unknown_alg":
                bad_alg.append(label)
            elif check.status == "principal_mismatch":
                # Carries the detail: "belongs to X but the line claims Y" is the
                # whole finding, and a bare line number would lose it.
                mismatch.append(f"{label}: {check.detail}")
            elif check.status == "revoked":
                revoked.append(f"{label}: {check.detail}")
            elif check.status in ("bad_signature", "unattributed"):
                bad.append(label if not check.detail else f"{label}: {check.detail}")
            elif require_signature:
                # "unsigned": not a failure unless demanded. A line written before
                # signing existed is not corrupt, and saying so is the difference
                # between a usable report and noise.
                bad.append(f"{label}: unsigned")
        return signed, bad, no_key, bad_alg, mismatch, revoked

    # -- chain identity ------------------------------------------------------ #

    def _genesis(self) -> str:
        """The ``prev`` value of the first line, bound to this ledger's identity.

        Binding matters: without it, a receipt copied out of one ledger verifies
        as a legitimate first line in another. With it, the link of line 1 is a
        value no other ledger produces, so a splice shows up as a broken chain.
        """
        identity = self.ledger_id or _DEFAULT_LEDGER_ID
        return content_digest({"genesis": identity, "version": _FORMAT_VERSION})

    # -- repair -------------------------------------------------------------- #

    def repair_tail(self) -> list[int]:
        """Drop unparseable lines from the end of the file, and report them.

        A crash mid-append leaves a partial line. It is deliberately *not*
        removed on load — silently discarding bytes from an evidence file is
        worse than the problem — but it also cannot be left there, because
        ``verify()`` will report it forever and a later append makes it
        mid-file, where it can never be attributed to the crash that caused it.

        Only the trailing run of unparseable lines is removed. A malformed line
        with valid lines after it is not a torn write; it is something else, and
        this refuses to touch it.

        Requires a backend that can rewrite its tail (:class:`JsonlBackend`);
        the in-memory backend has no torn writes to repair and returns ``[]``.
        """
        truncate = getattr(self.backend, "truncate_torn_tail", None)
        if truncate is None:
            return []
        removed = truncate()
        if removed:
            self._reload()
        return removed

    def _reload(self) -> None:
        """Re-read from the backend, discarding the in-memory view."""
        self._lines = []
        self._latest = {}
        self._by_delegation = {}
        self._first_index = {}
        self._order = []
        self._raw = []
        self._malformed_lines = []
        self._consumed = 0
        self._load()

    # -- refresh ------------------------------------------------------------- #

    def refresh(self) -> int:
        """Pick up lines written by someone else; return how many are new.

        Without this a ``Ledger`` is a snapshot, and two instances on one store
        silently diverge. That is not a locking problem — the write path is
        fine — it is a *read* problem, and it has teeth: a second process
        holding stale state can append a transition that un-settles a
        delegation the first process already completed, re-opening its budget
        and erasing its spend, while every digest still verifies.

        Read entry points call this, so a caller cannot forget it. The backend
        decides how expensive it is: :class:`MemoryBackend` is always 0, and
        :class:`JsonlBackend` counts lines, so nothing is re-parsed unless the
        store actually grew.
        """
        self.backend.refresh()
        before = len(self._lines)
        self._load()
        return len(self._lines) - before

    def close(self) -> None:
        """Release the backend. A no-op for both backends that ship here."""
        self.backend.close()

    # -- export -------------------------------------------------------------- #

    def to_json(self) -> dict[str, Any]:
        stats = self.stats()
        return {
            "stats": {
                "receipt_lines": stats.receipts,
                "delegations": stats.delegations,
                "agents": stats.agents,
                "total_cost_usd": stats.total_cost_usd,
                "by_outcome": dict(stats.by_outcome),
            },
            "chains": [chain.to_json() for chain in self.chains()],
            "receipts": [r.to_json() for r in self.current()],
        }

    def export(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_json(), indent=2), encoding="utf-8")
        return target

    @classmethod
    def from_receipts(cls, receipts: Iterable[Receipt]) -> Ledger:
        ledger = cls()
        for receipt in receipts:
            ledger.record(receipt)
        return ledger
