"""Matching, reputation, and policy rules."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agent_ledger.matcher import (
    MatchWeights,
    ReputationIndex,
    lexical_similarity,
    rank_candidates,
    summarise,
    tokenize,
)
from agent_ledger.models import (
    ArdEntry,
    DelegationStatus,
    PolicyOutcome,
    Receipt,
    Task,
)
from agent_ledger.policy import Policy, RuleContext


def entry(
    identifier: str,
    capabilities: list[str],
    queries: list[str] | None = None,
    trust: bool = False,
    score: float | None = None,
) -> ArdEntry:
    raw: dict = {
        "identifier": identifier,
        "displayName": identifier.rsplit(":", 1)[-1],
        "type": "application/a2a-agent-card+json",
        "url": "https://example.com/a.json",
        "capabilities": capabilities,
        "representativeQueries": queries or [],
    }
    if trust:
        raw["trustManifest"] = {"identity": f"spiffe://{identifier.split(':')[2]}/x"}
    parsed = ArdEntry.from_ard(raw)
    # ArdEntry is a slots dataclass, so there is no __dict__ to spread.
    return replace(parsed, registry_score=score) if score is not None else parsed


def receipt(
    delegate: str, outcome: DelegationStatus, cost: float = 0.0, budget: float | None = 1.0
) -> Receipt:
    return Receipt(
        delegation_id=f"d_{delegate}",
        task_id="t",
        delegate=delegate,
        delegated_by="urn:principal:a",
        outcome=outcome,
        cost_usd=cost,
        budget_usd=budget,
    )


class TestTokenize:
    def test_strips_stopwords_and_short_tokens(self) -> None:
        assert tokenize("Please review the DPA for me") == ["review", "dpa"]

    def test_empty_input(self) -> None:
        assert tokenize("") == []


class TestLexicalSimilarity:
    def test_identical_text_scores_one(self) -> None:
        assert lexical_similarity("translate the page", "translate the page") == 1.0

    def test_disjoint_text_scores_zero(self) -> None:
        assert lexical_similarity("translate", "audit") == 0.0

    def test_suffix_folding_matches_word_forms(self) -> None:
        assert lexical_similarity("translate the page", "translating pages") > 0.0

    def test_empty_side_scores_zero(self) -> None:
        assert lexical_similarity("", "anything") == 0.0


class TestReputationIndex:
    def test_unknown_agent_gets_neutral_prior(self) -> None:
        assert ReputationIndex().score("urn:air:a.com:agent:x") == 0.5

    def test_below_min_samples_stays_neutral(self) -> None:
        index = ReputationIndex()
        index.record(receipt("agent", DelegationStatus.FAILED))
        assert index.score("agent") == 0.5
        assert not index.is_known("agent")

    def test_all_successes_reaches_the_ceiling(self) -> None:
        index = ReputationIndex()
        for _ in range(4):
            index.record(receipt("agent", DelegationStatus.COMPLETED))
        assert index.score("agent") == pytest.approx(1.0)

    def test_budget_overrun_is_penalised_harder_than_failure(self) -> None:
        """An overrun still reports success, so it must cost more than a failure.

        Both histories below contain three good runs out of four, so neither
        saturates at the floor and the comparison is meaningful.
        """
        overrun = ReputationIndex()
        failed = ReputationIndex()
        for _ in range(3):
            overrun.record(receipt("a", DelegationStatus.COMPLETED, cost=0.1, budget=1.0))
            failed.record(receipt("a", DelegationStatus.COMPLETED, cost=0.1, budget=1.0))
        overrun.record(receipt("a", DelegationStatus.COMPLETED, cost=9.0, budget=1.0))
        failed.record(receipt("a", DelegationStatus.FAILED))

        assert overrun.score("a") < failed.score("a")
        assert 0.0 < overrun.score("a") < 1.0, "the sample is not saturated"

    def test_failures_drive_the_score_down(self) -> None:
        index = ReputationIndex()
        for _ in range(4):
            index.record(receipt("a", DelegationStatus.FAILED))
        assert index.score("a") < 0.5

    def test_work_in_flight_is_not_evidence(self) -> None:
        index = ReputationIndex()
        for _ in range(4):
            index.record(receipt("a", DelegationStatus.PENDING))
        assert index.score("a") == 0.5

    def test_score_is_bounded(self) -> None:
        index = ReputationIndex()
        for _ in range(10):
            index.record(receipt("a", DelegationStatus.FAILED, cost=9.0, budget=1.0))
        assert 0.0 <= index.score("a") <= 1.0

    def test_leaderboard_is_sorted(self) -> None:
        index = ReputationIndex()
        for _ in range(3):
            index.record(receipt("good", DelegationStatus.COMPLETED))
            index.record(receipt("bad", DelegationStatus.FAILED))
        ranked = index.leaderboard()
        assert ranked[0][0] == "good"

    def test_extend_consumes_iterables(self) -> None:
        index = ReputationIndex().extend([receipt("a", DelegationStatus.COMPLETED)] * 3)
        assert index.is_known("a")


class TestRankCandidates:
    def test_missing_required_capability_is_ineligible(self, simple_task: Task) -> None:
        entries = [entry("urn:air:a.com:agent:x", ["auditing"])]
        ranked = rank_candidates(simple_task, entries)
        assert not ranked[0].eligible
        assert "missing capability" in (ranked[0].rejected_reason or "")

    def test_partial_capability_coverage_is_ineligible_when_required(
        self, simple_task: Task
    ) -> None:
        task = Task(intent="x", required_capabilities=("translation", "auditing"))
        ranked = rank_candidates(task, [entry("urn:air:a.com:agent:x", ["translation"])])
        assert not ranked[0].eligible

    def test_coverage_can_be_optional(self, simple_task: Task) -> None:
        task = Task(intent="x", required_capabilities=("translation", "auditing"))
        ranked = rank_candidates(
            task,
            [entry("urn:air:a.com:agent:x", ["translation"])],
            require_capabilities=False,
        )
        assert ranked[0].eligible
        assert ranked[0].signals["capability"] == pytest.approx(0.5)

    def test_trust_requirement_filters(self, simple_task: Task) -> None:
        entries = [entry("urn:air:a.com:agent:x", ["translation"])]
        assert not rank_candidates(simple_task, entries, require_trust=True)[0].eligible
        assert rank_candidates(simple_task, entries, require_trust=False)[0].eligible

    def test_exclusions_are_honoured(self, simple_task: Task) -> None:
        entries = [entry("urn:air:a.com:agent:x", ["translation"])]
        ranked = rank_candidates(simple_task, entries, exclude=["urn:air:a.com:agent:x"])
        assert not ranked[0].eligible
        assert ranked[0].rejected_reason == "excluded by caller"

    def test_malformed_entry_is_ineligible(self, simple_task: Task) -> None:
        broken = ArdEntry(identifier="urn:air:a.com:agent:x", display_name="x", type="t")
        assert not rank_candidates(simple_task, [broken])[0].eligible

    def test_eligible_candidates_sort_first(self, simple_task: Task) -> None:
        good = entry("urn:air:a.com:agent:good", ["translation"])
        bad = entry("urn:air:a.com:agent:bad", ["auditing"])
        ranked = rank_candidates(simple_task, [bad, good])
        assert ranked[0].entry.identifier == good.identifier
        assert ranked[-1].eligible is False

    def test_registry_score_influences_ranking(self, simple_task: Task) -> None:
        low = entry("urn:air:a.com:agent:low", ["translation"], score=10)
        high = entry("urn:air:a.com:agent:high", ["translation"], score=99)
        ranked = [c for c in rank_candidates(simple_task, [low, high]) if c.eligible]
        assert ranked[0].entry.identifier.endswith("high")

    def test_reputation_can_override_registry_score(self, simple_task: Task) -> None:
        """The whole point: observed behaviour beats an advertised number."""
        favoured = entry("urn:air:a.com:agent:favoured", ["translation"], score=99)
        proven = entry("urn:air:a.com:agent:proven", ["translation"], score=10)

        reputation = ReputationIndex()
        for _ in range(5):
            reputation.record(receipt(proven.identifier, DelegationStatus.COMPLETED))
            reputation.record(
                receipt(favoured.identifier, DelegationStatus.COMPLETED, cost=9.0, budget=1.0)
            )

        ranked = [
            c
            for c in rank_candidates(
                simple_task,
                [favoured, proven],
                reputation=reputation,
                weights=MatchWeights(
                    capability=0.1, query=0.0, registry=0.1, trust=0.0, reputation=0.8
                ),
            )
            if c.eligible
        ]
        assert ranked[0].entry.identifier == proven.identifier

    def test_signals_are_always_exposed(self, simple_task: Task) -> None:
        ranked = rank_candidates(simple_task, [entry("urn:air:a.com:agent:x", ["translation"])])
        assert set(ranked[0].signals) == {
            "capability",
            "query",
            "registry",
            "trust",
            "reputation",
        }

    def test_custom_scorer_is_used(self, simple_task: Task) -> None:
        ranked = rank_candidates(
            simple_task,
            [entry("urn:air:a.com:agent:x", ["translation"])],
            scorer=lambda task, entry: 0.0,
        )
        assert ranked[0].signals["query"] == 0.0

    def test_weights_are_normalised(self) -> None:
        weights = MatchWeights(capability=2, query=2, registry=2, trust=2, reputation=2)
        norm = weights.normalised()
        assert sum(
            [norm.capability, norm.query, norm.registry, norm.trust, norm.reputation]
        ) == pytest.approx(1.0)

    def test_zero_weights_do_not_divide_by_zero(self) -> None:
        assert MatchWeights(0, 0, 0, 0, 0).normalised().capability > 0

    def test_empty_pool(self, simple_task: Task) -> None:
        assert rank_candidates(simple_task, []) == []

    def test_summarise(self, simple_task: Task) -> None:
        ranked = rank_candidates(
            simple_task,
            [
                entry("urn:air:a.com:agent:ok", ["translation"]),
                entry("urn:air:a.com:agent:no", ["auditing"]),
            ],
        )
        summary = summarise(ranked)
        assert summary["considered"] == 2
        assert summary["eligible"] == 1
        assert "urn:air:a.com:agent:no" in summary["rejected"]


class TestPolicy:
    def ctx(
        self,
        *,
        capabilities=("translation",),
        budget=1.0,
        depth=0,
        trust=False,
        spent=0.0,
        committed=0.0,
        identifier="urn:air:acme.com:agent:x",
        deadline=None,
    ) -> RuleContext:
        return RuleContext(
            task=Task(
                intent="x",
                required_capabilities=capabilities,
                budget_usd=budget,
                deadline_epoch=deadline,
            ),
            entry=entry(identifier, list(capabilities), trust=trust),
            depth=depth,
            spent_usd=spent,
            committed_usd=committed,
        )

    def test_open_grid_allows(self) -> None:
        assert Policy.open_grid().evaluate(self.ctx()).allowed

    def test_budget_over_cap_denied(self) -> None:
        decision = Policy.ceilinged(budget=0.5).evaluate(self.ctx(budget=5.0))
        assert decision.outcome is PolicyOutcome.DENY
        assert decision.rule == "policy.budget_exceeded"

    def test_uncapped_task_denied_when_policy_caps(self) -> None:
        decision = Policy.ceilinged(budget=0.5).evaluate(self.ctx(budget=None))
        assert decision.rule == "policy.budget_unspecified"

    def test_negative_budget_denied(self) -> None:
        decision = Policy.open_grid().evaluate(self.ctx(budget=-1.0))
        assert decision.rule == "policy.budget_negative"

    def test_depth_limit(self) -> None:
        decision = Policy.ceilinged(depth=2).evaluate(self.ctx(depth=2))
        assert decision.rule == "policy.max_depth"

    def test_chain_ceiling_counts_spend_and_commitments(self) -> None:
        policy = Policy.ceilinged(budget=10.0, chain=10.0)
        assert policy.evaluate(self.ctx(budget=4.0, spent=3.0, committed=2.0)).allowed
        denied = policy.evaluate(self.ctx(budget=4.0, spent=5.0, committed=2.0))
        assert denied.rule == "policy.chain_budget_exceeded"

    def test_expired_deadline_denied(self) -> None:
        decision = Policy.open_grid().evaluate(self.ctx(deadline=1.0))
        assert decision.rule == "policy.deadline_passed"

    def test_publisher_denylist(self) -> None:
        policy = Policy.open_grid().with_(denied_publishers=frozenset({"acme.com"}))
        assert policy.evaluate(self.ctx()).rule == "policy.publisher_denied"

    def test_publisher_allowlist(self) -> None:
        policy = Policy.open_grid().with_(allowed_publishers=frozenset({"other.com"}))
        assert policy.evaluate(self.ctx()).rule == "policy.publisher_not_allowed"

    def test_agent_denylist_and_allowlist(self) -> None:
        target = "urn:air:acme.com:agent:x"
        denied = Policy.open_grid().with_(denied_agents=frozenset({target}))
        assert denied.evaluate(self.ctx()).rule == "policy.agent_denied"
        allowed = Policy.open_grid().with_(allowed_agents=frozenset({"urn:air:a.com:b:c"}))
        assert allowed.evaluate(self.ctx()).rule == "policy.agent_not_allowed"

    def test_zero_trust_requires_manifest(self) -> None:
        assert Policy.zero_trust().evaluate(self.ctx()).rule == "policy.trust_required"
        assert Policy.zero_trust().evaluate(self.ctx(trust=True)).allowed

    def test_unaddressable_delegate_denied(self) -> None:
        decision = Policy.open_grid().evaluate(self.ctx(identifier="https://not-a-urn"))
        assert decision.rule == "policy.unaddressable_delegate"

    def test_custom_rule_runs_after_builtins(self) -> None:
        from agent_ledger.models import PolicyDecision

        def never(ctx: RuleContext) -> PolicyDecision:
            return PolicyDecision(PolicyOutcome.DENY, "custom.no", "always refuse")

        policy = Policy.open_grid().with_(rules=(never,))
        assert policy.evaluate(self.ctx()).rule == "custom.no"

    def test_first_rule_wins(self) -> None:
        from agent_ledger.models import PolicyDecision

        def first(ctx: RuleContext) -> PolicyDecision:
            return PolicyDecision(PolicyOutcome.DENY, "custom.first", "")

        def second(ctx: RuleContext) -> PolicyDecision:
            return PolicyDecision(PolicyOutcome.DENY, "custom.second", "")

        assert (
            Policy.open_grid().with_(rules=(first, second)).evaluate(self.ctx()).rule
            == "custom.first"
        )

    def test_with_does_not_mutate_original(self) -> None:
        base = Policy.open_grid()
        base.with_(denied_publishers=frozenset({"acme.com"}))
        assert base.denied_publishers == frozenset()

    def test_denial_carries_an_explanation(self) -> None:
        decision = Policy.ceilinged(budget=0.5).evaluate(self.ctx(budget=5.0))
        assert "0.50" in decision.detail and "5.00" in decision.detail
