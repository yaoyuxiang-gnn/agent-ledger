"""The storage seam, and the guarantees a backend must not break.

The point of `LedgerBackend` is that the append-only
semantics are the *contract*, and JSONL is merely the default implementation —
so a host can swap storage without touching `Grid`, the CLI or the tests.

Two things this file is careful about, because both were tempting to get wrong:

1. **A backend is not a trust boundary.** Making storage pluggable does not make
   a ledger safe to share between organisations. Nothing here attributes a line
   to a writer, so a shared log without signed receipts is a forgeable shared
   log. The last test in this file pins that honestly rather than implying
   otherwise.
2. **A backend that lies about refresh is worse than one that is slow.** The
   divergence bug this replaced was not a locking failure — the write path was
   fine — it was a *read* failure. So `refresh()` honesty is a conformance
   requirement, tested directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from agent_ledger import Grid, HmacSigner, Ledger, Policy, Task
from agent_ledger.ledger import (
    JsonlBackend,
    LedgerBackend,
    LedgerIntegrity,
    MemoryBackend,
    RawLine,
    SqliteBackend,
)
from agent_ledger.models import DelegationStatus, Receipt


def make_receipt(
    receipt_id: str,
    delegation_id: str,
    *,
    cost_usd: float = 0.1,
    task_id: str = "task_1",
) -> Receipt:
    return Receipt(
        delegation_id=delegation_id,
        task_id=task_id,
        delegate="urn:air:acme.com:agent:x",
        delegated_by="urn:principal:acme.com:alice",
        outcome=DelegationStatus.COMPLETED,
        cost_usd=cost_usd,
        budget_usd=1.0,
        receipt_id=receipt_id,
        issued_at=1000.0,
    )


class RecordingBackend:
    """A minimal third-party backend, to prove the protocol is implementable.

    Deliberately does not subclass anything: satisfying a ``Protocol``
    structurally is the whole claim being tested.
    """

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.appends = 0
        self.closed = False

    def append(self, line: str) -> None:
        self.appends += 1
        self.lines.append(line)

    def scan(self):
        for position, text in enumerate(self.lines):
            yield RawLine(position + 1, json.loads(text))

    def refresh(self) -> int:
        return len(self.lines)

    def close(self) -> None:
        self.closed = True


class TestProtocolConformance:
    def test_the_shipped_backends_satisfy_the_protocol(self) -> None:
        assert isinstance(MemoryBackend(), LedgerBackend)
        assert isinstance(JsonlBackend("unused.jsonl"), LedgerBackend)

    def test_a_third_party_backend_satisfies_the_protocol(self) -> None:
        assert isinstance(RecordingBackend(), LedgerBackend)

    def test_a_ledger_can_run_entirely_on_a_custom_backend(self) -> None:
        backend = RecordingBackend()
        ledger = Ledger(backend=backend)
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r2", "d2"))

        assert backend.appends == 2
        assert len(ledger) == 2
        assert ledger.verify().ok
        assert [r.receipt_id for r in ledger.current()] == ["r1", "r2"]

    def test_a_custom_backend_has_no_path(self) -> None:
        """`path` is None for non-file storage, and verify() still works.

        The missing-file check keys off `path`, so a path-less backend must not
        be mistaken for a missing file.
        """
        ledger = Ledger(backend=RecordingBackend())
        assert ledger.path is None
        ledger.record(make_receipt("r1", "d1"))
        integrity = ledger.verify()
        assert integrity.ok, integrity.describe()
        assert not integrity.missing

    def test_close_is_forwarded_to_the_backend(self) -> None:
        backend = RecordingBackend()
        Ledger(backend=backend).close()
        assert backend.closed

    def test_repair_tail_is_a_no_op_for_a_backend_without_one(self) -> None:
        """Not every store can have a torn write, so this is optional."""
        ledger = Ledger(backend=RecordingBackend())
        ledger.record(make_receipt("r1", "d1"))
        assert ledger.repair_tail() == []
        assert ledger.verify().ok


class TestBackendEquivalence:
    """The two shipped backends must agree on every observable behaviour."""

    @pytest.fixture(params=["memory", "jsonl"])
    def ledger(self, request, tmp_path: Path) -> Ledger:
        if request.param == "memory":
            return Ledger()
        return Ledger(tmp_path / "grid.jsonl")

    def test_record_and_read_back(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1"))
        assert ledger.by_id("r1") is not None
        assert len(ledger) == 1
        assert len(ledger.lines) == 1

    def test_verify_passes_on_a_clean_ledger(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1"))
        integrity = ledger.verify()
        assert integrity.ok, integrity.describe()
        assert integrity.checked == 1
        assert integrity.chain_head is not None

    def test_chaining_works(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r2", "d2"))
        assert all(r.chained for r in ledger.lines)
        assert ledger.verify().broken_chain == ()

    def test_state_transitions_collapse_into_one_delegation(self, ledger: Ledger) -> None:
        base = make_receipt("r1", "d1")
        ledger.record(base)
        ledger.record(
            Receipt(
                **{
                    **{f: getattr(base, f) for f in base.__slots__},
                    "outcome": DelegationStatus.FAILED,
                    "prev": None,
                }
            )
        )
        assert len(ledger) == 1
        assert len(ledger.lines) == 2
        assert ledger.verify().ok


class TestJsonlBackendOnDisk:
    def test_lines_are_one_json_object_per_line(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path).record(make_receipt("r1", "d1"))
        text = path.read_text(encoding="utf-8")
        assert text.endswith("\n")
        assert len(text.strip().splitlines()) == 1
        json.loads(text.strip())

    def test_a_reopened_ledger_sees_the_same_view(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        first = Ledger(path, ledger_id="L1")
        first.record(make_receipt("r1", "d1"))

        second = Ledger(path, ledger_id="L1")
        assert [r.receipt_id for r in second.current()] == ["r1"]
        assert second.verify().ok

    def test_the_ledger_id_changes_the_genesis_link(self, tmp_path: Path) -> None:
        """Identity is what makes a cross-ledger splice detectable."""
        a = tmp_path / "a.jsonl"
        b = tmp_path / "b.jsonl"
        Ledger(a, ledger_id="A").record(make_receipt("r1", "d1"))
        Ledger(b, ledger_id="B").record(make_receipt("r1", "d1"))

        first_a = json.loads(a.read_text(encoding="utf-8").splitlines()[0])
        first_b = json.loads(b.read_text(encoding="utf-8").splitlines()[0])
        assert first_a["prev"] != first_b["prev"]

    def test_a_directory_at_the_ledger_path_surfaces_on_write_not_construction(
        self, tmp_path: Path
    ) -> None:
        """A misconfiguration should not look like a permissions bug on open."""
        target = tmp_path / "grid.jsonl"
        target.mkdir()
        ledger = Ledger(target)  # must not raise
        assert ledger.current() == ()
        with pytest.raises(OSError):
            ledger.record(make_receipt("r1", "d1"))

    def test_truncate_torn_tail_reports_line_numbers(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1"))
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"torn"\n')
            handle.write("also not json\n")

        assert path.read_text(encoding="utf-8").count("\n") == 3
        assert ledger.repair_tail() == [2, 3]
        assert len(path.read_text(encoding="utf-8").strip().splitlines()) == 1
        assert ledger.verify().ok


class TestRefreshHonesty:
    """`refresh()` must not claim there is nothing new when there is."""

    def test_memory_backend_reports_its_size(self) -> None:
        ledger = Ledger()
        assert ledger.refresh() == 0
        ledger.record(make_receipt("r1", "d1"))
        assert ledger.refresh() == 0, "already read; nothing new"

    def test_jsonl_backend_reports_new_lines_only_once(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        writer = Ledger(path)
        reader = Ledger(path)
        assert reader.refresh() == 0
        writer.record(make_receipt("r1", "d1"))
        assert reader.refresh() == 1
        assert reader.refresh() == 0

    def test_a_backend_that_under_reports_refresh_is_caught(self, tmp_path: Path) -> None:
        """The failure mode, stated as a test.

        A backend whose `refresh()` always returns 0 leaves the caller believing
        it is up to date while holding stale state — which is how a second
        process came to un-settle a completed delegation.
        """

        class LyingBackend(RecordingBackend):
            def refresh(self) -> int:
                return 0

        backend = LyingBackend()
        # The ledger still detects new lines, because it tracks its own cursor
        # over scan() rather than trusting the reported count.
        ledger = Ledger(backend=backend)
        backend.append(json.dumps(make_receipt("r1", "d1").to_json(), sort_keys=True))
        assert ledger.by_id("r1") is not None, "scan is the source of truth, not the count"


class TestGridWorksOverAnyBackend:
    """The seam must hold for the real caller, not only for direct use."""

    def test_a_grid_can_delegate_through_a_custom_backend(self) -> None:
        from agent_ledger.ard import ArdClient, StaticTransport

        entry = {
            "identifier": "urn:air:acme.com:agent:review",
            "displayName": "Review",
            "type": "application/a2a-agent-card+json",
            "url": "https://acme.com/a2a",
            "capabilities": ["contract_review"],
            "representativeQueries": ["review a contract"],
        }
        transport = StaticTransport({"https://r.example/s": {"results": [entry]}})
        backend = RecordingBackend()
        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid(),
            ledger=Ledger(backend=backend),
            registries=("https://r.example/s",),
        )

        outcome = grid.dispatch(
            Task(intent="review a contract", required_capabilities=("contract_review",))
        )
        assert outcome.ok
        assert backend.appends >= 1, "the receipt reached the custom backend"
        assert grid.verify().startswith(str(len(backend.lines)))


class TestSqliteBackend:
    """The second shipped backend: atomic appends, enforced append-only.

    Worth having because it is stronger than JSONL in two specific ways — a row
    insert cannot tear, and `UPDATE`/`DELETE` are refused by the database rather
    than by convention. Worth *testing* because a backend that quietly changes
    the bytes changes every digest.
    """

    def _ledger(self, tmp_path: Path) -> tuple[Ledger, Path]:
        path = tmp_path / "grid.sqlite3"
        return Ledger(backend=SqliteBackend(path)), path

    def test_it_satisfies_the_protocol(self, tmp_path: Path) -> None:
        assert isinstance(SqliteBackend(tmp_path / "x.sqlite3"), LedgerBackend)

    def test_records_round_trip(self, tmp_path: Path) -> None:
        ledger, path = self._ledger(tmp_path)
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r2", "d2"))
        ledger.close()

        reopened = Ledger(backend=SqliteBackend(path))
        assert [r.receipt_id for r in reopened.current()] == ["r1", "r2"]
        reopened.close()

    def test_the_verdict_matches_the_jsonl_backend(self, tmp_path: Path) -> None:
        """A backend must not change what a receipt hashes to.

        This is the test that would have caught storing per-field columns, where
        `1` comes back as `1.0` and the digest silently changes.
        """
        receipt = make_receipt("r1", "d1", cost_usd=1)

        jsonl = Ledger(tmp_path / "a.jsonl")
        jsonl.record(receipt)
        jsonl_digest = jsonl.current()[0].digest()

        sqlite_ledger = Ledger(backend=SqliteBackend(tmp_path / "b.sqlite3"))
        sqlite_ledger.record(receipt)
        sqlite_digest = sqlite_ledger.current()[0].digest()

        assert jsonl_digest == sqlite_digest
        assert sqlite_ledger.verify().ok
        sqlite_ledger.close()

    def test_integrity_verification_works(self, tmp_path: Path) -> None:
        ledger, _ = self._ledger(tmp_path)
        Signer = HmacSigner  # noqa: N806 - keep the module import list short
        ledger.record(make_receipt("r1", "d1"))
        integrity = ledger.verify()
        assert integrity.ok, integrity.describe()
        assert integrity.chain_head is not None
        assert Signer is HmacSigner
        ledger.close()

    def test_update_is_refused_by_the_database(self, tmp_path: Path) -> None:
        """Append-only by construction, not by convention.

        With JSONL, nothing stops an editor. Here the store itself refuses.
        """
        ledger, path = self._ledger(tmp_path)
        ledger.record(make_receipt("r1", "d1"))
        backend = cast(SqliteBackend, ledger.backend)
        with pytest.raises(Exception, match="append-only"):
            backend._conn.execute("UPDATE receipts SET line = '{}' WHERE lineno = 1")
        ledger.close()

    def test_delete_is_refused_by_the_database(self, tmp_path: Path) -> None:
        ledger, _ = self._ledger(tmp_path)
        ledger.record(make_receipt("r1", "d1"))
        backend = cast(SqliteBackend, ledger.backend)
        with pytest.raises(Exception, match="append-only"):
            backend._conn.execute("DELETE FROM receipts WHERE lineno = 1")
        ledger.close()

    def test_sqlite_reports_its_own_file_integrity(self, tmp_path: Path) -> None:
        """Complements Ledger.verify: this is about the file, not the receipts."""
        ledger, _ = self._ledger(tmp_path)
        ledger.record(make_receipt("r1", "d1"))
        assert cast(SqliteBackend, ledger.backend).integrity_check() is True
        ledger.close()

    def test_signing_works_over_sqlite(self, tmp_path: Path) -> None:
        path = tmp_path / "signed.sqlite3"
        signer = HmacSigner(secret=b"k", key_id="k1")
        ledger = Ledger(backend=SqliteBackend(path), signer=signer)
        ledger.record(make_receipt("r1", "d1"))
        ledger.close()

        reopened = Ledger(backend=SqliteBackend(path), verifier=signer)
        integrity = reopened.verify(require_signature=True)
        assert integrity.ok, integrity.describe()
        assert integrity.signed == 1
        reopened.close()

    def test_two_connections_do_not_diverge(self, tmp_path: Path) -> None:
        """The refresh-on-read property, over a store rather than a file."""
        path = tmp_path / "shared.sqlite3"
        first = Ledger(backend=SqliteBackend(path))
        second = Ledger(backend=SqliteBackend(path))
        first.record(make_receipt("r1", "d1"))
        assert second.by_id("r1") is not None
        assert len(second.current()) == 1
        first.close()
        second.close()

    def test_a_grid_can_delegate_over_sqlite(self, tmp_path: Path) -> None:
        from agent_ledger.ard import ArdClient, StaticTransport

        entry = {
            "identifier": "urn:air:acme.com:agent:review",
            "displayName": "Review",
            "type": "application/a2a-agent-card+json",
            "url": "https://acme.com/a2a",
            "capabilities": ["contract_review"],
            "representativeQueries": ["review a contract"],
        }
        transport = StaticTransport({"https://r.example/s": {"results": [entry]}})
        ledger = Ledger(backend=SqliteBackend(tmp_path / "grid.sqlite3"))
        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid(),
            ledger=ledger,
            registries=("https://r.example/s",),
        )
        outcome = grid.dispatch(
            Task(intent="review a contract", required_capabilities=("contract_review",))
        )
        assert outcome.ok
        # No executor configured, so the delegation is issued and receipted as
        # pending — one line, and it verifies.
        assert grid.verify().startswith("1 receipt lines")
        ledger.close()


class TestBackendIsNotATrustBoundary:
    """A pluggable store is not a shared, trusted store.

    This test asserts the *absence* of a guarantee. It exists so that a future
    change which quietly implies otherwise — an API named `trusted`, a docstring
    promising multi-party evidence — fails here rather than in production.
    """

    def test_a_backend_line_carries_no_writer_identity(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path).record(make_receipt("r1", "d1"))
        stored = json.loads(path.read_text(encoding="utf-8").splitlines()[0])

        assert "signature" not in stored, "no signature exists yet"
        assert "key_id" not in stored, "so nothing attributes this line to a writer"
        # `delegated_by` is a claim by the writer, not evidence about the writer.
        assert stored["delegated_by"] == "urn:principal:acme.com:alice"

    def test_a_rewritten_ledger_verifies_clean(self, tmp_path: Path) -> None:
        """Stated plainly, because it is the limit that matters most.

        Anyone holding the store can recompute every digest and every link.
        Chain linkage raises the cost — it detects deletion, reordering and
        splicing — but it does not stop a full, consistent rewrite. Only signed
        receipts do, and they do not ship yet.
        """
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1", cost_usd=0.10))
        ledger.record(make_receipt("r2", "d2", cost_usd=0.10))

        rewritten = Ledger(path)
        assert rewritten.current()[0].cost_usd == 0.10, "the honest value, before the rewrite"

        # Rebuild the whole file from scratch, forged, with correct linkage.
        path.unlink()
        forger = Ledger(path)
        forger.record(make_receipt("r1", "d1", cost_usd=0.01))
        forger.record(make_receipt("r2", "d2", cost_usd=0.01))

        integrity = Ledger(path).verify()
        assert integrity.ok, "a consistent rewrite is not detectable without signatures"
        assert Ledger(path).current()[0].cost_usd == 0.01
        assert isinstance(integrity, LedgerIntegrity)
