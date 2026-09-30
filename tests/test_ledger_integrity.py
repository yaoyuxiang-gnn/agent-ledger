"""Integrity: the ledger must not be able to lie about itself.

Every test here is a *negative* test, because the
defects this file guards against were all of one shape: `verify()` reporting
success for work it had not done.

The pattern that produced them is worth stating once, because it is the reason
this file exists at all. The suite was fast, clean and 193 tests strong, and it
missed a crash on the primary code path plus six integrity defects — because
every fixture was more cooperative than reality. A test that only feeds the
ledger well-formed lines it wrote itself cannot fail in any interesting way.

Read the class docstrings here as the specification: each one names an attack,
and the assertion is that the attack is *reported*, not merely survived.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_ledger import Ledger, Task
from agent_ledger.ledger import LedgerIntegrity
from agent_ledger.models import (
    DelegationStatus,
    DigestError,
    Receipt,
    canonical_json,
    content_digest,
)


def make_receipt(
    receipt_id: str,
    delegation_id: str,
    *,
    cost_usd: float = 0.1,
    budget_usd: float | None = 1.0,
    outcome: DelegationStatus = DelegationStatus.COMPLETED,
    parent_receipt_id: str | None = None,
    issued_at: float = 1000.0,
) -> Receipt:
    return Receipt(
        delegation_id=delegation_id,
        task_id="task_1",
        delegate="urn:air:acme.com:agent:x",
        delegated_by="urn:principal:acme.com:alice",
        outcome=outcome,
        cost_usd=cost_usd,
        budget_usd=budget_usd,
        parent_receipt_id=parent_receipt_id,
        receipt_id=receipt_id,
        issued_at=issued_at,
    )


def write_lines(path: Path, *lines: dict) -> None:
    path.write_text(
        "".join(json.dumps(line, sort_keys=True) + "\n" for line in lines),
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- #
# Hostile input
# --------------------------------------------------------------------------- #


class TestVerifyNeverRaises:
    """`verify()` must report, never traceback.

    A checker that crashes on hostile input hands the attacker the win: one
    appended line disables ``al verify`` entirely. Before this, a line as
    ordinary as ``{"receipt_id": "evil", "digest": "..."}`` raised ``KeyError``
    out of ``verify()``, and ``[1, 2, 3]`` raised ``AttributeError``.
    """

    HOSTILE = [
        pytest.param([], id="json-array"),
        pytest.param([1, 2, 3], id="json-array-of-ints"),
        pytest.param(123, id="bare-int"),
        pytest.param("a string", id="bare-string"),
        pytest.param(None, id="json-null"),
        pytest.param(True, id="json-true"),
        pytest.param({}, id="empty-object"),
        pytest.param({"hello": "world"}, id="object-with-wrong-keys"),
        pytest.param(
            {"receipt_id": "evil", "digest": "sha256:" + "0" * 64}, id="id-and-digest-only"
        ),
        pytest.param({"delegation_id": 1}, id="non-string-delegation-id"),
        pytest.param(
            {"receipt_id": "x", "delegation_id": "d", "depth": "deep"}, id="non-numeric-depth"
        ),
        pytest.param(
            {"receipt_id": "x", "delegation_id": "d", "outcome": "approved"}, id="unknown-outcome"
        ),
        pytest.param(
            {"receipt_id": "x", "delegation_id": "d", "cost_usd": "free"}, id="non-numeric-cost"
        ),
        pytest.param({"receipt_id": None, "delegation_id": "d"}, id="null-receipt-id"),
        pytest.param({"receipt_id": "x", "delegation_id": "d", "cost_usd": None}, id="null-cost"),
    ]

    @pytest.mark.parametrize("line", HOSTILE)
    def test_verify_reports_instead_of_raising(self, tmp_path: Path, line) -> None:
        path = tmp_path / "grid.jsonl"
        path.write_text(json.dumps(line) + "\n", encoding="utf-8")

        integrity = Ledger(path).verify()  # must not raise

        assert isinstance(integrity, LedgerIntegrity)
        assert not integrity.ok, f"{line!r} was accepted as a healthy ledger"

    @pytest.mark.parametrize("line", HOSTILE)
    def test_loading_reports_instead_of_raising(self, tmp_path: Path, line) -> None:
        """Construction must survive too; a bad line cannot block the audit."""
        path = tmp_path / "grid.jsonl"
        path.write_text(json.dumps(line) + "\n", encoding="utf-8")
        assert Ledger(path).current() == ()

    @pytest.mark.parametrize("garbage", ["{not json}", "}{", '{"a": '])
    def test_unparseable_lines_are_reported_by_line_number(
        self, tmp_path: Path, garbage: str
    ) -> None:
        path = tmp_path / "grid.jsonl"
        path.write_text(garbage + "\n", encoding="utf-8")
        integrity = Ledger(path).verify()
        assert not integrity.ok
        assert integrity.malformed == (1,)

    @pytest.mark.parametrize("blank", ["", "   ", "\t"])
    def test_blank_lines_are_ignored_not_reported(self, tmp_path: Path, blank: str) -> None:
        """An empty line is formatting, not evidence of tampering.

        Trailing newlines are normal in an append-only text file, so treating
        them as malformed would make a ledger fail merely for having been touched
        by an editor.
        """
        path = tmp_path / "grid.jsonl"
        path.write_text(blank + "\n", encoding="utf-8")
        integrity = Ledger(path).verify()
        assert integrity.ok, integrity.describe()
        assert integrity.malformed == ()

    def test_a_hostile_line_does_not_hide_the_good_lines_before_it(self, tmp_path: Path) -> None:
        """Order matters: an audit wants every finding, not the first."""
        path = tmp_path / "grid.jsonl"
        good = make_receipt("r1", "d1").to_json()
        path.write_text(
            json.dumps(good, sort_keys=True) + "\n" + '{"receipt_id": "evil"}\n',
            encoding="utf-8",
        )
        integrity = Ledger(path).verify()
        assert integrity.checked == 1, "the good line was still checked"
        assert integrity.malformed == (2,)


# --------------------------------------------------------------------------- #
# The missing-digest bypass
# --------------------------------------------------------------------------- #


class TestMissingDigestIsTampering:
    """Deleting the `digest` key must be a finding, not an absence of one.

    This was the sharpest defect in the ledger. ``verify()`` read
    ``if stored and stored != ...`` — a missing or empty digest is falsy, so it
    meant "nothing to check" — while still incrementing the verified count. An
    attacker could forge a receipt's contents, delete the ``digest`` key, and
    ``al verify`` would print ``N receipt lines verified, chain intact`` and
    exit 0 with the forged value in place.
    """

    def test_removing_the_digest_key_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1", cost_usd=0.1))

        line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        line["cost_usd"] = 999.0
        del line["digest"]
        write_lines(path, line)

        integrity = Ledger(path).verify()
        assert not integrity.ok
        assert integrity.no_digest, "a missing digest is itself the evidence"
        # And the forged value is what a naive reader would now believe.
        assert Ledger(path).current()[0].cost_usd == 999.0

    def test_an_empty_digest_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path).record(make_receipt("r1", "d1"))
        line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        line["digest"] = ""
        write_lines(path, line)
        assert not Ledger(path).verify().ok

    def test_a_null_digest_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        Ledger(path).record(make_receipt("r1", "d1"))
        line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        line["digest"] = None
        write_lines(path, line)
        assert not Ledger(path).verify().ok

    def test_a_clean_ledger_reports_no_missing_digest(self, tmp_path: Path) -> None:
        """The other half: no false positives on a healthy ledger."""
        path = tmp_path / "grid.jsonl"
        Ledger(path).record(make_receipt("r1", "d1"))
        integrity = Ledger(path).verify()
        assert integrity.ok, integrity.describe()
        assert integrity.no_digest == ()
        assert integrity.checked == 1


# --------------------------------------------------------------------------- #
# Deletion, insertion, reordering
# --------------------------------------------------------------------------- #


class TestChainLinkage:
    """Deleting a line must be detectable — a whole-line deletion leaves nothing
    behind to disagree with, so per-line digests alone can never catch it.

    Linkage is what does: each line carries ``prev``, the link of the line
    before it, so a gap, a swap or a splice shows up as a mismatch. The tests
    below are the six ways a ledger can be edited while every stored digest stays
    individually valid.
    """

    def _three_lines(self, tmp_path: Path) -> Path:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r2", "d2"))
        ledger.record(make_receipt("r3", "d3"))
        return path

    def test_a_chain_is_intact_when_untouched(self, tmp_path: Path) -> None:
        integrity = Ledger(self._three_lines(tmp_path)).verify()
        assert integrity.ok, integrity.describe()
        assert integrity.broken_chain == ()
        assert integrity.unchained == 0

    def test_deleting_a_middle_line_breaks_the_chain(self, tmp_path: Path) -> None:
        path = self._three_lines(tmp_path)
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

        integrity = Ledger(path).verify()
        assert not integrity.ok
        assert integrity.broken_chain, "the surviving line's prev no longer matches"

    def test_deleting_the_last_line_is_not_detectable_from_inside(self, tmp_path: Path) -> None:
        """Honest about the limit: a truncated prefix is a consistent chain.

        This is why `chain_head` is exposed. Publishing it out of band — a
        commit, a peer, a release artefact — is the only way to detect
        truncation of the tail, and the docstring says so rather than implying
        the chain covers it.
        """
        path = self._three_lines(tmp_path)
        intact = Ledger(path).verify()
        head_before = intact.chain_head

        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

        truncated = Ledger(path).verify()
        assert truncated.ok, "a shorter prefix is internally consistent"
        assert truncated.chain_head != head_before, "but the head moved, which is the tell"

    def test_reordering_two_lines_breaks_the_chain(self, tmp_path: Path) -> None:
        path = self._three_lines(tmp_path)
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join([lines[1], lines[0], lines[2]]) + "\n", encoding="utf-8")
        assert not Ledger(path).verify().ok

    def test_inserting_a_forged_line_breaks_the_chain(self, tmp_path: Path) -> None:
        """A plausible forgery with a valid digest still fails on linkage."""
        path = self._three_lines(tmp_path)
        forged = make_receipt("r_forged", "d_forged", cost_usd=0.01).to_json()
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text(
            "\n".join([lines[0], json.dumps(forged, sort_keys=True), *lines[1:]]) + "\n",
            encoding="utf-8",
        )
        integrity = Ledger(path).verify()
        assert not integrity.ok
        assert integrity.broken_chain, "the inserted line cannot know the real prev"

    def test_a_receipt_spliced_from_another_ledger_is_detected(self, tmp_path: Path) -> None:
        """Two ledgers have different genesis links, so a splice is visible.

        Without ledger identity in the genesis, a receipt copied out of ledger A
        verifies as a legitimate *root* of ledger B — and a chain root is
        precisely the line that names the accountable principal, so the forger
        gets to choose who is answerable.
        """
        other = tmp_path / "other.jsonl"
        Ledger(other, ledger_id="ledger-A").record(make_receipt("rA", "dA"))
        stolen = other.read_text(encoding="utf-8").splitlines()[0]

        mine = tmp_path / "mine.jsonl"
        Ledger(mine, ledger_id="ledger-B").record(make_receipt("r1", "d1"))
        mine.write_text(mine.read_text(encoding="utf-8") + stolen + "\n", encoding="utf-8")

        integrity = Ledger(mine, ledger_id="ledger-B").verify()
        assert not integrity.ok
        assert integrity.broken_chain, "ledger A's genesis link is not ledger B's"

    def test_unlinked_lines_are_counted_not_failed(self, tmp_path: Path) -> None:
        """Ledgers written before linkage existed must stay valid, and say so."""
        path = tmp_path / "legacy.jsonl"
        line = make_receipt("r1", "d1").to_json()  # no `prev` key
        assert "prev" not in line
        write_lines(path, line)

        integrity = Ledger(path).verify()
        assert integrity.ok, "an unchained line is not corrupt, it is unchecked"
        assert integrity.unchained == 1
        assert "unchained" in integrity.describe()
        assert "chain intact" not in integrity.describe(), (
            "must not claim a property it could not check"
        )

    def test_strict_chain_mode_fails_on_unlinked_lines(self, tmp_path: Path) -> None:
        """Opt-in, for a deployment that has committed to linkage everywhere."""
        path = tmp_path / "legacy.jsonl"
        write_lines(path, make_receipt("r1", "d1").to_json())
        assert Ledger(path).verify().ok
        assert not Ledger(path).verify(strict_chain=True).ok


# --------------------------------------------------------------------------- #
# Parent linkage
# --------------------------------------------------------------------------- #


class TestOrphanedParents:
    """A `parent_receipt_id` that resolves to nothing is a finding.

    A missing parent currently becomes a silent ``None``, so the orphan resolves
    as a chain *root* — the line that names who is accountable.
    """

    def test_an_unresolvable_parent_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        write_lines(path, make_receipt("r1", "d1", parent_receipt_id="rcpt_ghost").to_json())

        integrity = Ledger(path).verify()
        assert not integrity.ok
        assert integrity.orphaned

    def test_a_resolvable_parent_is_not_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r2", "d2", parent_receipt_id="r1"))
        integrity = Ledger(path).verify()
        assert integrity.ok, integrity.describe()
        assert integrity.orphaned == ()


# --------------------------------------------------------------------------- #
# Duplicate ids
# --------------------------------------------------------------------------- #


class TestDuplicateReceiptIds:
    """One id, two lines, disagreeing content, both with valid digests.

    The view keeps the last, so a forged duplicate silently rewrites budget
    accounting and reputation. But a repeated id is *also* how a legitimate
    state transition is recorded, so the rule has to distinguish them — and
    getting that wrong would have made every normal ledger fail.
    """

    def test_a_legitimate_transition_is_not_reported(self, tmp_path: Path) -> None:
        """The same delegation keeps one receipt_id for its whole life."""
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        receipt = make_receipt("r1", "d1", outcome=DelegationStatus.PENDING)
        ledger.record(receipt)
        ledger.record(
            Receipt(
                **{
                    **{f: getattr(receipt, f) for f in receipt.__slots__},
                    "outcome": DelegationStatus.COMPLETED,
                    "cost_usd": 0.25,
                    "prev": None,
                }
            )
        )

        integrity = Ledger(path).verify()
        assert integrity.ok, integrity.describe()
        assert integrity.duplicated == ()
        assert len(Ledger(path)) == 1, "one delegation, two transitions"

    def test_a_forged_duplicate_is_reported(self, tmp_path: Path) -> None:
        """Same id, same outcome, different content — not a transition."""
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1", cost_usd=0.1))
        ledger.record(make_receipt("r1", "d1", cost_usd=999.0))

        integrity = Ledger(path).verify()
        assert not integrity.ok
        assert integrity.duplicated

    def test_a_forged_duplicate_cannot_rewrite_the_view_silently(self, tmp_path: Path) -> None:
        """The reason it matters: the view believes the forgery."""
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1", cost_usd=0.1))
        ledger.record(make_receipt("r1", "d1", cost_usd=999.0))

        reloaded = Ledger(path)
        assert reloaded.current()[0].cost_usd == 999.0
        assert not reloaded.verify().ok, "but the ledger says so out loud"

    def test_a_full_real_lifecycle_is_not_reported(self, tmp_path: Path) -> None:
        """The false positive this rule first produced, pinned.

        A delegation issued through `Grid` goes pending -> accepted -> completed,
        and the completion carries a `result_digest` the earlier lines do not.
        An earlier version of the rule compared the *whole* line and so reported
        every real delegation as forged — a check that fails on correct input is
        worse than no check, because it trains the operator to ignore it.

        This test exists because the two-line version of the rule passed while
        the three-line version failed, so the shape of the lifecycle matters.
        """
        from agent_ledger import CallableExecutor, ExecutionResult, Grid
        from agent_ledger.ard import ArdClient, StaticTransport

        entry = {
            "identifier": "urn:air:acme.com:agent:review",
            "displayName": "Review",
            "type": "application/a2a-agent-card+json",
            "url": "https://acme.com/a2a",
            "capabilities": ["contract_review"],
            "representativeQueries": ["review a vendor contract"],
        }
        transport = StaticTransport({"https://acme.com/.well-known/ard.json": {"entries": [entry]}})
        path = tmp_path / "grid.jsonl"
        grid = Grid(
            client=ArdClient(transport),
            ledger=Ledger(path),
            domains=("acme.com",),
            executor=CallableExecutor(
                lambda task, e: ExecutionResult(ok=True, cost_usd=0.02, output={"ok": True})
            ),
        )
        outcome = grid.dispatch(
            Task(
                intent="review a vendor contract",
                required_capabilities=("contract_review",),
                budget_usd=0.5,
            )
        )
        assert outcome.ok, outcome.reason

        ledger = Ledger(path)
        assert len(ledger.lines) == 3, "pending, accepted, completed"
        assert len(ledger) == 1, "but one delegation"
        integrity = ledger.verify()
        assert integrity.ok, integrity.describe()
        assert integrity.duplicated == ()
        assert integrity.broken_chain == ()

    def test_transitions_of_one_delegation_share_an_issuance_time(self, tmp_path: Path) -> None:
        """`issued_at` means when the delegation was authorised, not when the
        status changed — otherwise a receipt mutates a field that "when was this
        authorised" depends on, every time it advances."""
        from agent_ledger import CallableExecutor, ExecutionResult, Grid
        from agent_ledger.ard import ArdClient, StaticTransport

        entry = {
            "identifier": "urn:air:acme.com:agent:review",
            "displayName": "Review",
            "type": "application/a2a-agent-card+json",
            "url": "https://acme.com/a2a",
            "capabilities": ["contract_review"],
            "representativeQueries": ["review a vendor contract"],
        }
        transport = StaticTransport({"https://acme.com/.well-known/ard.json": {"entries": [entry]}})
        grid = Grid(
            client=ArdClient(transport),
            ledger=Ledger(tmp_path / "grid.jsonl"),
            domains=("acme.com",),
            executor=CallableExecutor(
                lambda task, e: ExecutionResult(ok=True, cost_usd=0.02, output={"ok": True})
            ),
        )
        grid.dispatch(
            Task(
                intent="review a vendor contract",
                required_capabilities=("contract_review",),
                budget_usd=0.5,
            )
        )
        stamps = {r.issued_at for r in grid.ledger.lines}
        assert len(stamps) == 1, f"one delegation, one issuance time; got {stamps}"


# --------------------------------------------------------------------------- #
# The digest itself
# --------------------------------------------------------------------------- #


class TestDigestStability:
    """A digest that changes on reload is worse than no digest.

    `from_json` coerced numeric fields with ``float()`` while the constructor did
    not, so ``Receipt(cost_usd=1)`` and the same receipt after a write/read cycle
    disagreed and ``verify()`` reported an untouched file as tampered. A
    signature layered on such a digest would fail on the library's own output.
    """

    def test_int_and_float_cost_digest_identically(self) -> None:
        as_int = make_receipt("r1", "d1", cost_usd=1)
        as_float = make_receipt("r1", "d1", cost_usd=1.0)
        assert as_int.digest() == as_float.digest()

    def test_an_untouched_file_round_trips_clean(self, tmp_path: Path) -> None:
        """The regression, stated exactly."""
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1", cost_usd=1, issued_at=1000))

        integrity = Ledger(path).verify()
        assert integrity.ok, f"an untouched file reported: {integrity.describe()}"
        assert integrity.tampered == ()

    def test_mixed_numeric_types_all_round_trip_clean(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1", cost_usd=2, budget_usd=4, issued_at=1000))
        ledger.record(make_receipt("r2", "d2", cost_usd=0.5, budget_usd=None, issued_at=1000.5))
        assert Ledger(path).verify().ok

    def test_the_golden_digest_is_unchanged(self) -> None:
        """Pinned so a refactor cannot silently change what a receipt hashes to.

        Changing this value invalidates every ledger ever written, so if this
        test fails the fix is almost never to update the constant.

        Note the digest is taken over a receipt built with ``cost_usd=0.25`` and
        ``issued_at=1000.0``: both are already floats, so this value was
        unaffected by the integral-float normalisation that
        ``test_int_and_float_cost_digest_identically`` covers. That is the point
        — normalisation had to be a no-op on data this project already wrote.
        """
        receipt = Receipt(
            receipt_id="rcpt_golden",
            delegation_id="dlg_golden",
            task_id="task_golden",
            delegate="urn:air:acme.com:agent:x",
            delegated_by="urn:principal:alice",
            outcome=DelegationStatus.COMPLETED,
            cost_usd=0.25,
            budget_usd=0.5,
            scope_digest="sha256:" + "0" * 64,
            issued_at=1000.0,
        )
        assert receipt.digest() == (
            "sha256:427ee1cdb15d070c28736fb2f02f594bc4d0706ff85b337d94926669826f7bea"
        )

    def test_body_has_exactly_the_digested_fields(self) -> None:
        """`body()` is a hand-maintained literal, so it needs a tripwire.

        A field added there changes the digest of every receipt ever written;
        a field added to the dataclass but *not* to ``body()`` is silently
        undigested — editable without detection. Both are failures, so the set is
        pinned.
        """
        assert set(make_receipt("r", "d").body()) == {
            "receipt_id",
            "delegation_id",
            "task_id",
            "delegate",
            "delegated_by",
            "outcome",
            "cost_usd",
            "budget_usd",
            "scope_digest",
            "result_digest",
            "parent_receipt_id",
            "depth",
            "note",
            "issued_at",
        }

    def test_prev_is_not_part_of_the_digested_body(self) -> None:
        """Linkage must not change what a stored receipt hashes to."""
        bare = make_receipt("r1", "d1")
        linked = Receipt(
            **{**{f: getattr(bare, f) for f in bare.__slots__}, "prev": content_digest("x")}
        )
        assert bare.digest() == linked.digest()
        assert bare.link_digest(prev=None) != linked.link_digest(prev=content_digest("x"))

    def test_to_json_omits_prev_when_unchained(self) -> None:
        """An unchained receipt must serialise to the bytes we always wrote.

        Emitting ``"prev": null`` unconditionally would rewrite every existing
        ledger on its next append.
        """
        assert "prev" not in make_receipt("r1", "d1").to_json()

    def test_from_json_round_trips_prev(self) -> None:
        original = Receipt(
            **{**{f: getattr(make_receipt("r1", "d1"), f) for f in Receipt.__slots__}, "prev": "x"}
        )
        assert Receipt.from_json(original.to_json()).prev == "x"


class TestCanonicalJson:
    """`canonical_json` must be reproducible across processes, or the digest is
    a value only the writing machine can verify."""

    def test_a_set_does_not_leak_iteration_order(self) -> None:
        values = {"alpha", "beta", "gamma", "delta", "epsilon"}
        digests = {
            content_digest({"s": set(values)})
            for _ in range(25)
            if id(values) is not None  # same set, many passes
        }
        assert len(digests) == 1, "digest varied across passes in one process"
        assert content_digest({"s": {"b", "a"}}) == content_digest({"s": {"a", "b"}})

    def test_a_set_is_stable_across_interpreter_runs(self) -> None:
        """The only honest test of hash-seed independence is a fresh process."""
        script = (
            "import sys; sys.path.insert(0, 'src');"
            "from agent_ledger.models import content_digest;"
            "print(content_digest({'s': {'alpha','beta','gamma','delta','epsilon','zeta'}}))"
        )
        digests = {
            subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                check=True,
                env={"PYTHONHASHSEED": seed, "PATH": ""},
            ).stdout.strip()
            for seed in ("0", "1", "42", "12345")
        }
        assert len(digests) == 1, f"digest depends on PYTHONHASHSEED: {digests}"

    def test_nested_sets_are_handled(self) -> None:
        assert content_digest({"a": {"b": frozenset({"x", "y"})}}) == content_digest(
            {"a": {"b": frozenset({"y", "x"})}}
        )

    def test_float_and_int_agree(self) -> None:
        assert canonical_json({"v": 1.0}) == canonical_json({"v": 1})

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_floats_are_refused(self, value: float) -> None:
        """NaN is not valid JSON and does not compare equal to itself."""
        with pytest.raises(DigestError):
            content_digest({"v": value})

    @pytest.mark.parametrize("value", [{1: "a", "b": 2}, {None: "a"}, {(1, 2): "a"}])
    def test_non_string_keys_are_refused(self, value: dict) -> None:
        """Coercing silently would make {1: 'a'} and {'1': 'a'} collide."""
        with pytest.raises(DigestError):
            content_digest(value)

    def test_arbitrary_objects_are_refused(self) -> None:
        class Opaque:
            def __repr__(self) -> str:
                return "<opaque at 0xdeadbeef>"

        with pytest.raises(DigestError):
            content_digest({"o": Opaque()})

    def test_bytes_are_refused_with_a_hint(self) -> None:
        with pytest.raises(DigestError, match="encode them explicitly"):
            content_digest({"b": b"raw"})

    def test_json_representable_values_still_work(self) -> None:
        value = {"s": "x", "i": 3, "f": 1.5, "b": True, "n": None, "l": [1, "two"], "d": {"k": "v"}}
        assert content_digest(value).startswith("sha256:")


# --------------------------------------------------------------------------- #
# The file itself
# --------------------------------------------------------------------------- #


class TestMissingFile:
    """A ledger that is not there is not a healthy ledger.

    ``verify()`` used to return ``ok=True`` for a missing path, so
    ``al verify --ledger typo.jsonl`` printed ``OK: 0 receipt lines verified``
    and exited 0 — a typo reported a clean audit trail.
    """

    def test_a_missing_path_is_not_ok(self, tmp_path: Path) -> None:
        integrity = Ledger(tmp_path / "typo.jsonl").verify()
        assert not integrity.ok, "a missing file must not report a clean ledger"
        assert integrity.checked == 0

    def test_the_cli_exits_non_zero_for_a_missing_ledger(self, tmp_path: Path) -> None:
        from agent_ledger.cli import main

        code = main(["verify", "--ledger", str(tmp_path / "typo.jsonl")])
        assert code != 0

    def test_a_file_deleted_after_loading_is_not_still_verified(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1"))
        assert ledger.verify().ok

        path.unlink()
        integrity = ledger.verify()
        assert not integrity.ok
        assert integrity.checked == 0, "nothing was read"


class TestRefresh:
    """Two instances on one path must not diverge.

    Without refresh-on-read, a second process holding stale state can append a
    transition that un-settles a delegation the first process already completed
    — re-opening its budget and erasing its spend, while every digest verifies.
    File locking does not fix this; it is a read problem.
    """

    def test_receipts_appended_elsewhere_become_visible(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        first = Ledger(path)
        first.record(make_receipt("r1", "d1"))

        second = Ledger(path)
        first.record(make_receipt("r2", "d2"))

        assert second.by_id("r2") is not None, "the stale instance must see the new line"
        assert len(second.current()) == 2

    def test_a_stale_writer_cannot_un_settle_a_completed_delegation(self, tmp_path: Path) -> None:
        """The concrete failure this prevents, asserted end to end."""
        from agent_ledger.models import (
            ArdEntry,
            Delegation,
            PolicyDecision,
            PolicyOutcome,
            Task,
        )

        path = tmp_path / "grid.jsonl"
        entry = ArdEntry(
            identifier="urn:air:acme.com:agent:x", display_name="X", type="t", url="https://x"
        )
        delegation = Delegation(
            task=Task(intent="i", task_id="t1", budget_usd=5.0),
            delegate=entry,
            delegated_by="urn:principal:acme.com:alice",
            policy=PolicyDecision(PolicyOutcome.ALLOW, "r"),
        )

        writer = Ledger(path)
        stale = Ledger(path)
        writer.receipt_delegation(delegation, status=DelegationStatus.PENDING)
        writer.receipt_delegation(delegation, status=DelegationStatus.COMPLETED, cost_usd=4.0)

        assert writer.spent_for_task("t1") == 4.0
        assert writer.committed_for_task("t1") == 0.0

        # The stale instance must now see the completion, so its next write is a
        # genuine transition rather than a rollback to `accepted`.
        assert stale.by_delegation(delegation.delegation_id).outcome is DelegationStatus.COMPLETED
        assert stale.spent_for_task("t1") == 4.0
        assert stale.committed_for_task("t1") == 0.0

    def test_refresh_reports_how_many_lines_are_new(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        first = Ledger(path)
        second = Ledger(path)
        assert second.refresh() == 0
        first.record(make_receipt("r1", "d1"))
        assert second.refresh() == 1
        assert second.refresh() == 0, "idempotent when nothing changed"


class TestRepairTail:
    """A torn final line needs a remedy, not permanent failure.

    A crash mid-append leaves a partial line. It is deliberately not discarded on
    load — silently dropping bytes from an evidence file is worse than the
    problem — but it also cannot stay, because ``verify()`` reports it forever
    and a later append moves it mid-file, where it can no longer be attributed to
    the crash that caused it.
    """

    def test_a_torn_tail_is_repaired(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1"))
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"partial": ')

        assert not ledger.verify().ok, "the torn line is reported first"
        removed = ledger.repair_tail()
        assert removed == [2]
        assert ledger.verify().ok
        assert ledger.by_id("r1") is not None

    def test_repair_refuses_to_touch_a_mid_file_bad_line(self, tmp_path: Path) -> None:
        """Only a trailing run is a torn write. Anything else is not."""
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1"))
        with path.open("a", encoding="utf-8") as handle:
            handle.write("{bad}\n")
        ledger.record(make_receipt("r2", "d2"))

        assert ledger.repair_tail() == [], "a bad line with good lines after it stays, for a human"
        assert not ledger.verify().ok

    def test_repair_is_a_no_op_on_a_clean_ledger(self, tmp_path: Path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1"))
        assert ledger.repair_tail() == []
        assert ledger.verify().ok


class TestWriteThenIndex:
    """The view must not advance when the write failed.

    ``record()`` used to call ``_index`` before appending, so a ledger that could
    not write still reported the delegation.
    """

    def test_a_failed_write_does_not_advance_the_view(self, tmp_path: Path) -> None:
        # A directory where the file should be: opening for append raises.
        target = tmp_path / "grid.jsonl"
        target.mkdir()
        ledger = Ledger(target)
        with pytest.raises(OSError):
            ledger.record(make_receipt("r1", "d1"))
        assert ledger.current() == (), "nothing was written, so nothing is held"
        assert len(ledger) == 0
