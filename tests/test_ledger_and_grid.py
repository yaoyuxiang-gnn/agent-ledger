"""Ledger integrity, chain reconstruction, and end-to-end grid behaviour."""

from __future__ import annotations

import json

import pytest

from agent_ledger import Grid, Ledger, Policy, Task
from agent_ledger.ard import ArdError
from agent_ledger.ledger import LedgerStats
from agent_ledger.models import (
    ArdEntry,
    DelegationStatus,
    PolicyDecision,
    PolicyOutcome,
    Receipt,
)
from agent_ledger.policy import RuleContext
from agent_ledger.router import CallableExecutor, ExecutionResult, GridConfig

from .conftest import INTERNAL_REGISTRY


def make_receipt(receipt_id: str, delegation_id: str, **overrides) -> Receipt:
    base = dict(
        receipt_id=receipt_id,
        delegation_id=delegation_id,
        task_id="task_root",
        delegate="urn:air:acme.com:agent:a",
        delegated_by="urn:principal:alice",
        outcome=DelegationStatus.PENDING,
    )
    base.update(overrides)
    return Receipt(**base)  # type: ignore[arg-type]


class TestLedgerStateModel:
    def test_log_and_view_are_separate(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r1", "d1", outcome=DelegationStatus.COMPLETED))

        assert len(ledger.lines) == 2, "the append-only log keeps every transition"
        assert len(ledger.current()) == 1, "the view keeps only the latest"
        assert ledger.by_id("r1").outcome is DelegationStatus.COMPLETED

    def test_len_counts_delegations_not_lines(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r1", "d1", outcome=DelegationStatus.COMPLETED))
        assert len(ledger) == 1

    def test_empty_ledger_is_truthy(self, ledger: Ledger) -> None:
        """An empty ledger is still a ledger.

        This used to be the opposite, and it shipped a bug: ``__len__`` made a
        fresh ``Ledger`` falsy, so ``ledger or Ledger()`` silently handed a
        different object downstream and the grid reported an empty audit trail
        while holding a full one. ``__bool__`` now defers to ``is not None``
        like every other object, so the idiom can no longer misfire.

        ``len()`` still reports delegations, because "how many are in here" is a
        real question; it just no longer doubles as a truth test.
        """
        assert ledger
        assert len(ledger) == 0

    def test_an_empty_ledger_survives_an_or_default(self, ledger: Ledger) -> None:
        """The specific idiom that caused the bug now behaves."""
        chosen = ledger or Ledger()
        assert chosen is ledger

    def test_current_preserves_issue_order(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r2", "d2"))
        ledger.record(make_receipt("r1", "d1", outcome=DelegationStatus.COMPLETED))
        assert [r.receipt_id for r in ledger.current()] == ["r1", "r2"]

    def test_by_delegation_returns_latest(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1"))
        ledger.record(make_receipt("r1", "d1", outcome=DelegationStatus.FAILED))
        assert ledger.by_delegation("d1").outcome is DelegationStatus.FAILED

    def test_unknown_lookups_return_none(self, ledger: Ledger) -> None:
        assert ledger.by_id("nope") is None
        assert ledger.by_delegation("nope") is None


class TestChains:
    def _three_hop(self) -> Ledger:
        ledger = Ledger()
        ledger.record(make_receipt("r0", "d0", delegate="urn:air:a.com:agent:root", depth=0))
        ledger.record(
            make_receipt(
                "r1", "d1", delegate="urn:air:a.com:agent:mid", depth=1, parent_receipt_id="r0"
            )
        )
        ledger.record(
            make_receipt(
                "r2", "d2", delegate="urn:air:a.com:agent:leaf", depth=2, parent_receipt_id="r1"
            )
        )
        return ledger

    def test_chain_is_root_first(self) -> None:
        chain = self._three_hop().chain("r2")
        assert len(chain) == 3
        assert chain.root.receipt_id == "r0"
        assert chain.leaf.receipt_id == "r2"

    def test_chain_accepts_a_receipt_object(self) -> None:
        ledger = self._three_hop()
        assert len(ledger.chain(ledger.by_id("r2"))) == 3

    def test_single_root_chain(self) -> None:
        assert len(self._three_hop().chain("r0")) == 1

    def test_unknown_receipt_yields_empty_chain(self) -> None:
        assert len(self._three_hop().chain("missing")) == 0

    def test_cycles_terminate(self) -> None:
        ledger = Ledger()
        ledger.record(make_receipt("a", "d1", parent_receipt_id="b"))
        ledger.record(make_receipt("b", "d2", parent_receipt_id="a"))
        assert len(ledger.chain("a")) == 2

    def test_leaves_and_chains(self) -> None:
        ledger = self._three_hop()
        assert [r.receipt_id for r in ledger.leaves()] == ["r2"]
        assert len(ledger.chains()) == 1

    def test_walk_is_breadth_first(self) -> None:
        ledger = Ledger()
        ledger.record(make_receipt("r0", "d0", depth=0))
        ledger.record(make_receipt("r1", "d1", depth=1, parent_receipt_id="r0"))
        ledger.record(make_receipt("r2", "d2", depth=1, parent_receipt_id="r0"))
        ledger.record(make_receipt("r3", "d3", depth=2, parent_receipt_id="r1"))
        walked = [r.receipt_id for r in ledger.walk("r0")]
        assert walked[0] == "r0"
        assert set(walked[1:3]) == {"r1", "r2"}


class TestBudgetAccounting:
    def test_spend_sums_completed_work(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1", outcome=DelegationStatus.COMPLETED, cost_usd=0.3))
        ledger.record(make_receipt("r2", "d2", outcome=DelegationStatus.COMPLETED, cost_usd=0.2))
        assert ledger.spent_for_task("task_root") == pytest.approx(0.5)

    def test_commitments_count_unsettled_budgets(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1", outcome=DelegationStatus.PENDING, budget_usd=1.5))
        ledger.record(make_receipt("r2", "d2", outcome=DelegationStatus.ACCEPTED, budget_usd=2.5))
        assert ledger.committed_for_task("task_root") == pytest.approx(4.0)

    def test_settled_delegations_release_their_commitment(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1", outcome=DelegationStatus.PENDING, budget_usd=1.5))
        ledger.record(
            make_receipt(
                "r1", "d1", outcome=DelegationStatus.COMPLETED, budget_usd=1.5, cost_usd=1.2
            )
        )
        assert ledger.committed_for_task("task_root") == 0.0
        assert ledger.spent_for_task("task_root") == pytest.approx(1.2)

    def test_other_tasks_do_not_leak(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1", task_id="other", cost_usd=9.0))
        assert ledger.spent_for_task("task_root") == 0.0


class TestPersistenceAndTampering:
    def test_roundtrip_through_a_file(self, tmp_path) -> None:
        path = tmp_path / "grid.jsonl"
        first = Ledger(path)
        first.record(make_receipt("r1", "d1", outcome=DelegationStatus.COMPLETED))
        first.record(make_receipt("r2", "d2", parent_receipt_id="r1"))

        reloaded = Ledger(path)
        assert len(reloaded) == 2
        assert len(reloaded.chain("r2")) == 2
        assert reloaded.verify().ok

    def test_verify_reports_clean_ledger(self, tmp_path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1"))
        integrity = ledger.verify()
        assert integrity.ok and integrity.checked == 1

    def test_verify_detects_an_edited_line(self, tmp_path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1", cost_usd=0.1))

        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["cost_usd"] = 999.0  # tamper, leave the digest alone
        path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")

        integrity = Ledger(path).verify()
        assert not integrity.ok
        # The label names both the line and the id it claims, because the id
        # alone is attacker-controlled and would point the operator at the
        # wrong place in the file.
        assert any("r1" in label for label in integrity.tampered), integrity.tampered

    def test_verify_reports_unreadable_lines(self, tmp_path) -> None:
        path = tmp_path / "grid.jsonl"
        path.write_text("{not json}\n", encoding="utf-8")
        integrity = Ledger(path).verify()
        assert not integrity.ok
        assert integrity.malformed == (1,)

    def test_torn_final_line_does_not_break_loading(self, tmp_path) -> None:
        path = tmp_path / "grid.jsonl"
        ledger = Ledger(path)
        ledger.record(make_receipt("r1", "d1"))
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"partial": ')

        reloaded = Ledger(path)
        assert len(reloaded) == 1

    def test_export_writes_json(self, tmp_path) -> None:
        ledger = Ledger()
        ledger.record(make_receipt("r1", "d1"))
        target = ledger.export(tmp_path / "out" / "audit.json")
        payload = json.loads(target.read_text(encoding="utf-8"))
        assert payload["stats"]["delegations"] == 1
        assert payload["receipts"][0]["receipt_id"] == "r1"


class TestStatsAndReputation:
    def test_stats_summarise_current_state(self, ledger: Ledger) -> None:
        ledger.record(make_receipt("r1", "d1", outcome=DelegationStatus.COMPLETED, cost_usd=0.5))
        ledger.record(make_receipt("r2", "d2", outcome=DelegationStatus.FAILED))
        stats = ledger.stats()
        assert isinstance(stats, LedgerStats)
        assert stats.delegations == 2
        assert stats.total_cost_usd == pytest.approx(0.5)
        assert stats.by_outcome == {"completed": 1, "failed": 1}

    def test_reputation_is_seeded_from_history(self, ledger: Ledger) -> None:
        for index in range(4):
            ledger.record(
                make_receipt(
                    f"r{index}",
                    f"d{index}",
                    delegate="urn:air:acme.com:agent:good",
                    outcome=DelegationStatus.COMPLETED,
                )
            )
        assert ledger.reputation().score("urn:air:acme.com:agent:good") == pytest.approx(1.0)


class TestGridDelegation:
    def test_delegates_to_the_best_eligible_agent(self, grid: Grid) -> None:
        task = Task(
            intent="review the data processing agreement",
            required_capabilities=("contract_review",),
            budget_usd=0.5,
        )
        outcome = grid.delegate(task)
        assert outcome.ok
        assert outcome.delegation is not None
        assert outcome.delegation.delegate.identifier.endswith("legal-review")

    def test_issuing_records_a_pending_receipt(self, grid: Grid) -> None:
        task = Task(
            intent="review a contract", required_capabilities=("contract_review",), budget_usd=0.5
        )
        outcome = grid.delegate(task)
        receipt = grid.ledger.by_delegation(outcome.delegation.delegation_id)
        assert receipt is not None
        assert receipt.outcome is DelegationStatus.PENDING

    def test_no_capable_agent_is_refused_not_raised(self, grid: Grid) -> None:
        outcome = grid.delegate(
            Task(intent="paint a mural", required_capabilities=("oil_painting",))
        )
        assert not outcome.ok
        assert "no eligible candidate" in outcome.reason

    def test_refusal_is_written_to_the_ledger(self, grid: Grid) -> None:
        grid.delegate(
            Task(intent="x", required_capabilities=("program_management",), budget_usd=99.0)
        )
        refusals = [r for r in grid.ledger if r.delegate == "urn:air:refused"]
        assert refusals and "policy.budget_exceeded" in refusals[0].note

    def test_refusals_can_be_suppressed(self, transport) -> None:
        grid = Grid(
            policy=Policy.ceilinged(budget=0.01),
            registries=(INTERNAL_REGISTRY,),
            config=GridConfig(record_refusals=False),
        )
        grid.delegate(
            Task(intent="x", required_capabilities=("program_management",), budget_usd=5.0)
        )
        assert len(grid.ledger) == 0

    def test_fallback_moves_to_the_next_candidate(self, transport) -> None:
        """The top-ranked agent is denied, so routing continues down the list.

        Three agents advertise ``translation``. Denying the incumbent must
        produce a denial record *and* a successful delegation to the runner-up,
        rather than an outright failure.
        """
        from agent_ledger.ard import ArdClient

        incumbent = "urn:air:northwind.internal:agent:localization"
        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid().with_(denied_agents=frozenset({incumbent})),
            registries=(INTERNAL_REGISTRY,),
            config=GridConfig(fallback_to_next=True),
        )
        outcome = grid.delegate(
            Task(intent="translate the landing page", required_capabilities=("translation",))
        )
        assert outcome.ok, "a denial of the first choice must not end the attempt"
        assert outcome.delegation is not None
        assert outcome.delegation.delegate.identifier != incumbent
        assert any(d.rule == "policy.agent_denied" for d in outcome.decisions)

    def test_fallback_can_be_disabled(self, transport) -> None:
        from agent_ledger.ard import ArdClient

        incumbent = "urn:air:northwind.internal:agent:localization"
        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid().with_(denied_agents=frozenset({incumbent})),
            registries=(INTERNAL_REGISTRY,),
            config=GridConfig(fallback_to_next=False),
        )
        outcome = grid.delegate(
            Task(intent="translate the landing page", required_capabilities=("translation",))
        )
        assert not outcome.ok
        assert len(outcome.decisions) == 1

    def test_approval_requirement_halts_routing(self, grid: Grid) -> None:
        from agent_ledger.models import PolicyDecision

        def needs_human(ctx: RuleContext) -> PolicyDecision:
            return PolicyDecision(PolicyOutcome.REQUIRE_APPROVAL, "custom.human", "ask Dana")

        grid.policy = Policy.open_grid().with_(rules=(needs_human,))
        outcome = grid.delegate(
            Task(intent="review a contract", required_capabilities=("contract_review",))
        )
        assert not outcome.ok
        assert "held for approval" in outcome.reason

    def test_max_attempts_is_respected(self, transport) -> None:
        grid = Grid(
            policy=Policy.open_grid().with_(
                denied_agents=frozenset(
                    {
                        "urn:air:northwind.internal:agent:legal-review",
                        "urn:air:northwind.internal:agent:localization",
                    }
                )
            ),
            registries=(INTERNAL_REGISTRY,),
            config=GridConfig(fallback_to_next=True, max_attempts=1),
        )
        outcome = grid.delegate(Task(intent="translate", required_capabilities=("translation",)))
        assert not outcome.ok
        assert len(outcome.decisions) <= 1


class TestGridChains:
    def _run_three_hops(self, grid: Grid):
        root = grid.delegate(
            Task(
                intent="coordinate the launch programme",
                required_capabilities=("program_management",),
                budget_usd=0.5,
            )
        )
        assert root.ok
        mid_task = root.delegation.task.child(
            "review the agreement", ["contract_review"], budget_usd=0.4
        )
        mid = grid.delegate(mid_task, parent=root.delegation)
        assert mid.ok
        leaf_task = mid_task.child("translate the page", ["translation"], budget_usd=0.3)
        leaf = grid.delegate(leaf_task, parent=mid.delegation)
        assert leaf.ok
        return root.delegation, mid.delegation, leaf.delegation

    def test_three_hop_chain_is_reconstructed(self, grid: Grid) -> None:
        root, mid, leaf = self._run_three_hops(grid)
        grid.complete(leaf, cost_usd=0.12)
        grid.complete(mid, cost_usd=0.35)
        grid.complete(root, cost_usd=0.02)

        chains = [c for c in grid.audit_trail() if len(c) > 1]
        chain = max(chains, key=len)
        assert len(chain) == 3
        assert chain.root.delegate.endswith("program-coordinator")
        assert chain.leaf.delegate.endswith("localization")
        assert chain.total_cost == pytest.approx(0.49)
        assert chain.is_clean

    def test_depths_increase_per_hop(self, grid: Grid) -> None:
        root, mid, leaf = self._run_three_hops(grid)
        assert (root.depth, mid.depth, leaf.depth) == (0, 1, 2)

    def test_parent_links_to_parent_receipt(self, grid: Grid) -> None:
        root, mid, leaf = self._run_three_hops(grid)
        mid_receipt = grid.ledger.by_delegation(mid.delegation_id)
        root_receipt = grid.ledger.by_delegation(root.delegation_id)
        assert mid_receipt.parent_receipt_id == root_receipt.receipt_id

    def test_chain_traces_back_to_the_principal(self, grid: Grid) -> None:
        root, mid, leaf = self._run_three_hops(grid)
        chain = grid.ledger.chain(grid.ledger.by_delegation(leaf.delegation_id))
        assert chain.root.delegated_by == root.delegated_by

    def test_depth_limit_stops_runaway_delegation(self, transport) -> None:
        """``max_depth`` is the maximum chain length in hops.

        Depth is zero-based, so ``max_depth=2`` permits depths 0 and 1 and
        refuses depth 2 — two hops beyond the principal, then stop.
        """
        from agent_ledger.ard import ArdClient

        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.ceilinged(budget=1.0, depth=2),
            registries=(INTERNAL_REGISTRY,),
        )
        root = grid.delegate(
            Task(intent="coordinate", required_capabilities=("program_management",), budget_usd=0.5)
        )
        assert root.ok and root.delegation.depth == 0

        second = grid.delegate(
            Task(
                intent="review the agreement",
                required_capabilities=("contract_review",),
                budget_usd=0.5,
            ),
            parent=root.delegation,
        )
        assert second.ok and second.delegation.depth == 1

        # depth 2 exceeds the limit and must be refused, not truncated
        third = grid.delegate(
            Task(
                intent="translate the page", required_capabilities=("translation",), budget_usd=0.5
            ),
            parent=second.delegation,
        )
        assert not third.ok
        assert any(d.rule == "policy.max_depth" for d in third.decisions)


class TestDiscoveryFailureIsContained:
    """A remote discovery source must never be able to abort a delegation.

    ``Grid.discover`` originally caught only :class:`ArdError`. A parsing bug on
    a hostile or merely unexpected registry response therefore escaped as a raw
    traceback — which is how the ``ArdEntry.__dict__`` crash reached users. A bad
    response costs a candidate, not the whole call.
    """

    def _grid_with_failing_client(self, exc: BaseException) -> Grid:
        grid = Grid(policy=Policy.open_grid(), ledger=Ledger(), domains=("nowhere.invalid",))

        def explode(**kwargs):
            raise exc

        grid.client.discover = explode  # type: ignore[method-assign]
        return grid

    @pytest.mark.parametrize(
        "exc",
        [
            ArdError("HTTP 500 from registry"),
            AttributeError("'ArdEntry' object has no attribute '__dict__'"),
            ValueError("bad registry payload"),
            TypeError("unexpected shape"),
            KeyError("results"),
        ],
    )
    def test_discovery_failure_returns_no_candidates_instead_of_raising(
        self, exc: BaseException
    ) -> None:
        grid = self._grid_with_failing_client(exc)
        assert grid.discover(Task(intent="anything")) == []

    def test_a_contained_failure_is_still_reportable(self) -> None:
        """Contained must not mean silent — the reason stays on the grid."""
        grid = self._grid_with_failing_client(AttributeError("no __dict__"))
        grid.discover(Task(intent="anything"))
        assert grid._last_discovery_error is not None
        assert "AttributeError" in grid._last_discovery_error

    def test_delegate_still_refuses_cleanly_when_discovery_fails(self) -> None:
        grid = self._grid_with_failing_client(RuntimeError("registry exploded"))
        outcome = grid.delegate(Task(intent="anything"))
        assert not outcome.ok
        assert outcome.candidates == ()


class TestGridDispatch:
    def test_dispatch_runs_and_receipts(self, grid: Grid) -> None:
        grid.executor = CallableExecutor(
            lambda task, entry: ExecutionResult(ok=True, cost_usd=0.05, output={"ok": True})
        )
        outcome = grid.dispatch(
            Task(
                intent="review a contract",
                required_capabilities=("contract_review",),
                budget_usd=0.5,
            )
        )
        assert outcome.ok
        assert outcome.receipt is not None
        assert outcome.receipt.outcome is DelegationStatus.COMPLETED
        assert outcome.receipt.cost_usd == pytest.approx(0.05)
        assert outcome.receipt.result_digest is not None

    def test_failing_execution_is_recorded_not_raised(self, grid: Grid) -> None:
        grid.executor = CallableExecutor(
            lambda task, entry: ExecutionResult(ok=False, cost_usd=0.01, note="upstream 500")
        )
        outcome = grid.dispatch(
            Task(intent="review", required_capabilities=("contract_review",), budget_usd=0.5)
        )
        assert not outcome.ok
        assert outcome.receipt.outcome is DelegationStatus.FAILED

    def test_executor_exception_becomes_a_failed_receipt(self, grid: Grid) -> None:
        def boom(task, entry):
            raise RuntimeError("delegate crashed")

        grid.executor = CallableExecutor(boom)
        outcome = grid.dispatch(
            Task(intent="review", required_capabilities=("contract_review",), budget_usd=0.5)
        )
        assert not outcome.ok
        assert outcome.receipt is not None
        assert "delegate crashed" in outcome.receipt.note

    def test_dispatch_without_executor_only_places(self, grid: Grid) -> None:
        """No executor means no execution — but the issuance is still receipted.

        ``outcome.ok`` being ``True`` while ``outcome.receipt`` was ``None`` was
        a trap: the README's quick-start calls ``outcome.receipt.digest()`` on
        exactly this path and got an ``AttributeError``. The issuance receipt
        already existed in the ledger; the fix is to hand it back.
        """
        outcome = grid.dispatch(
            Task(intent="review", required_capabilities=("contract_review",), budget_usd=0.5)
        )
        assert outcome.ok
        assert outcome.receipt is not None
        assert outcome.receipt.outcome is DelegationStatus.PENDING
        assert outcome.receipt.note.startswith("issued by")

    def test_dispatch_without_executor_returns_the_ledgers_own_receipt(self, grid: Grid) -> None:
        """The returned receipt must be the ledgered one, not a copy."""
        outcome = grid.dispatch(
            Task(intent="review", required_capabilities=("contract_review",), budget_usd=0.5)
        )
        ledgered = grid.ledger.by_delegation(outcome.delegation.delegation_id)
        assert ledgered is not None
        assert outcome.receipt.receipt_id == ledgered.receipt_id
        assert outcome.receipt.digest() == ledgered.digest()

    def test_dispatch_refuses_to_invoke_a_delegate_with_no_target(self, transport) -> None:
        """ARD §5.3.2 lets a search result omit ``url``.

        Such a result is rankable and not invocable. Asking it to execute must
        produce a named failure, not an ``AttributeError`` on ``entry.url``.
        """
        from agent_ledger.ard import ArdClient, StaticTransport

        # A registry response shaped the way ARD §5.3.2 permits: identifier
        # names the authoritative entry, no url is carried.
        targetless = StaticTransport(
            {
                "https://registry.example/api/v1/search": {
                    "results": [
                        {
                            "identifier": "urn:air:northwind.internal:agent:legal-review",
                            "displayName": "Contract Review Agent",
                            "type": "application/a2a-agent-card+json",
                            "capabilities": ["contract_review"],
                            "score": 93,
                        }
                    ]
                }
            }
        )
        invoked: list[str] = []

        def must_not_run(task, entry):  # pragma: no cover - the guard is the test
            invoked.append(entry.identifier)
            raise AssertionError("executor must not be called without a target")

        grid = Grid(
            client=ArdClient(targetless),
            policy=Policy.open_grid(),
            ledger=Ledger(),
            registries=("https://registry.example/api/v1/search",),
            executor=CallableExecutor(must_not_run),
        )
        outcome = grid.dispatch(
            Task(intent="review", required_capabilities=("contract_review",), budget_usd=0.5)
        )

        assert not outcome.ok
        assert "no url or data" in outcome.reason
        assert "urn:air:northwind.internal:agent:legal-review" in outcome.reason
        assert invoked == [], "the executor must not have been reached"
        # The refusal is receipted, so the ledger explains why nothing ran.
        assert outcome.receipt is not None
        assert outcome.receipt.outcome is DelegationStatus.FAILED

    def test_overrun_is_visible_on_the_receipt(self, grid: Grid) -> None:
        grid.executor = CallableExecutor(
            lambda task, entry: ExecutionResult(ok=True, cost_usd=9.99)
        )
        outcome = grid.dispatch(
            Task(intent="review", required_capabilities=("contract_review",), budget_usd=0.1)
        )
        assert outcome.receipt.over_budget


class TestRoutingThatRemembers:
    def test_a_budget_overrun_changes_the_next_ranking(self, transport) -> None:
        """The headline behaviour: no rule written, the ledger reroutes.

        The probe task is defined once, so the only variable between the two
        rankings is reputation. Ranking two different intents would confound
        the comparison with query relevance.
        """
        from agent_ledger.ard import ArdClient

        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid(),
            registries=(INTERNAL_REGISTRY,),
        )
        probe = Task(
            intent="translate a product landing page into Japanese",
            required_capabilities=("translation",),
            budget_usd=0.5,
        )

        before = [c for c in grid.candidates(probe) if c.eligible]
        assert before[0].entry.identifier.endswith("localization"), (
            "precondition: the incumbent leads before any history exists"
        )

        for _ in range(2):
            overrun = Task(
                intent=probe.intent,
                required_capabilities=("translation",),
                budget_usd=0.05,
            )
            outcome = grid.delegate(overrun)
            assert outcome.ok
            grid.complete(outcome.delegation, cost_usd=0.42)

        after = [c for c in grid.candidates(probe) if c.eligible]
        localization = next(c for c in after if c.entry.identifier.endswith("localization"))
        assert localization.signals["reputation"] < 0.5, "the overrun lowered its score"
        assert after[0].entry.identifier.endswith("translate-pro"), (
            "the proven alternative must now lead"
        )

    def test_unknown_agents_keep_the_neutral_prior(self, transport) -> None:
        from agent_ledger.ard import ArdClient

        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid(),
            registries=(INTERNAL_REGISTRY,),
        )
        ranked = grid.candidates(Task(intent="translate", required_capabilities=("translation",)))
        assert all(c.signals["reputation"] == 0.5 for c in ranked if c.eligible)


class TestGridWiring:
    def test_caller_ledger_is_not_discarded(self, transport) -> None:
        """Regression: ``ledger or Ledger()`` threw away empty ledgers.

        The bug this guards is now fixed twice over — ``Ledger.__bool__`` makes
        an empty ledger truthy, and ``Grid.__init__`` uses ``is not None``
        regardless. Both are asserted, because either one alone would be enough
        to stop this particular regression and neither alone is enough to stop
        the class of it.
        """
        from agent_ledger.ard import ArdClient

        supplied = Ledger()
        assert supplied, "an empty ledger must be truthy, or `or` discards it"

        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid(),
            ledger=supplied,
            registries=(INTERNAL_REGISTRY,),
        )
        assert grid.ledger is supplied, "the grid must keep the ledger it was given"
        grid.delegate(
            Task(
                intent="review the agreement",
                required_capabilities=("contract_review",),
                budget_usd=0.5,
            )
        )
        assert len(supplied) > 0, "receipts must land in the ledger we were given"
        assert grid.ledger is supplied

    def test_empty_ard_entry_is_rejected(self) -> None:
        assert not ArdEntry(identifier="x", display_name="", type="").is_valid
