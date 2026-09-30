"""Policy — the rules that decide whether a delegation may happen.

A routing layer that only ever routes is a liability. Before work leaves a
principal's control, something must check that the principal is allowed to
spend that money, that the target is an acceptable party, and that the request
is not the fourth hop of a chain that was only authorised for two.

Every rule returns a *named* decision. When a delegation is refused, the
refusal carries the rule that refused it, because "denied" without "by what"
is not an audit trail.

This module is intentionally not a policy *language*. It is a small set of
rules you can read in one sitting, plus a hook for your own.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace

from .models import ArdEntry, PolicyDecision, PolicyOutcome, Task

__all__ = ["Policy", "Rule", "RuleContext", "DEFAULT_POLICY"]

#: A rule inspects a proposed delegation and either abstains (``None``) or
#: returns a decision. First non-``None`` decision wins, so order is authority.
Rule = Callable[["RuleContext"], "PolicyDecision | None"]


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Everything a rule may consider. No globals, no hidden state."""

    task: Task
    entry: ArdEntry
    depth: int
    spent_usd: float = 0.0
    committed_usd: float = 0.0

    @property
    def projected_spend(self) -> float:
        """What the chain will have spent if this delegation runs to budget."""
        return self.spent_usd + self.committed_usd + (self.task.budget_usd or 0.0)

    @property
    def publisher(self) -> str | None:
        return self.entry.publisher


@dataclass(frozen=True, slots=True)
class Policy:
    """A named, ordered rule set.

    Presets cover the two postures that matter in practice: an open grid for
    experimentation and a ceilinged grid for anything touching production
    money.
    """

    name: str = "default"
    rules: tuple[Rule, ...] = ()
    max_budget_usd: float | None = 5.0
    max_total_cost_usd: float | None = 25.0
    max_depth: int = 3
    require_trust: bool = False
    allowed_publishers: frozenset[str] = frozenset()
    denied_publishers: frozenset[str] = frozenset()
    allowed_agents: frozenset[str] = frozenset()
    denied_agents: frozenset[str] = frozenset()
    metadata: Mapping[str, object] = field(default_factory=dict)

    # -- evaluation ---------------------------------------------------------- #

    def evaluate(self, context: RuleContext) -> PolicyDecision:
        """Apply built-in rules, then custom ones, returning the first verdict."""
        for check in self._builtin_rules():
            decision = check(context)
            if decision is not None:
                return decision
        for check in self.rules:
            decision = check(context)
            if decision is not None:
                return decision
        return PolicyDecision(
            PolicyOutcome.ALLOW, "policy.default_allow", f"permitted by '{self.name}'"
        )

    def _builtin_rules(self) -> list[Rule]:
        return [
            self._rule_task_not_expired,
            self._rule_depth,
            self._rule_allow_deny_agent,
            self._rule_allow_deny_publisher,
            self._rule_trust,
            self._rule_budget,
            self._rule_total_cost,
        ]

    # -- built-in rules ------------------------------------------------------ #

    @staticmethod
    def _rule_task_not_expired(ctx: RuleContext) -> PolicyDecision | None:
        if ctx.task.expired:
            return PolicyDecision(
                PolicyOutcome.DENY,
                "policy.deadline_passed",
                "the task deadline has already elapsed",
            )
        return None

    def _rule_depth(self, ctx: RuleContext) -> PolicyDecision | None:
        if ctx.depth >= self.max_depth:
            return PolicyDecision(
                PolicyOutcome.DENY,
                "policy.max_depth",
                f"delegation depth {ctx.depth} would exceed limit {self.max_depth}",
            )
        return None

    def _rule_allow_deny_agent(self, ctx: RuleContext) -> PolicyDecision | None:
        identifier = ctx.entry.identifier
        if identifier in self.denied_agents:
            return PolicyDecision(
                PolicyOutcome.DENY, "policy.agent_denied", f"{identifier} is denylisted"
            )
        if self.allowed_agents and identifier not in self.allowed_agents:
            return PolicyDecision(
                PolicyOutcome.DENY,
                "policy.agent_not_allowed",
                f"{identifier} is not on the allowlist",
            )
        return None

    def _rule_allow_deny_publisher(self, ctx: RuleContext) -> PolicyDecision | None:
        publisher = ctx.publisher
        if publisher is None:
            return PolicyDecision(
                PolicyOutcome.DENY,
                "policy.unaddressable_delegate",
                "delegate identifier is not a valid urn:air: handle",
            )
        if publisher in self.denied_publishers:
            return PolicyDecision(
                PolicyOutcome.DENY,
                "policy.publisher_denied",
                f"publisher domain {publisher} is denylisted",
            )
        if self.allowed_publishers and publisher not in self.allowed_publishers:
            return PolicyDecision(
                PolicyOutcome.DENY,
                "policy.publisher_not_allowed",
                f"publisher domain {publisher} is not on the allowlist",
            )
        return None

    def _rule_trust(self, ctx: RuleContext) -> PolicyDecision | None:
        if self.require_trust and not ctx.entry.is_trusted:
            return PolicyDecision(
                PolicyOutcome.DENY,
                "policy.trust_required",
                "delegate publishes no trustManifest",
            )
        return None

    def _rule_budget(self, ctx: RuleContext) -> PolicyDecision | None:
        budget = ctx.task.budget_usd
        if budget is None:
            if self.max_budget_usd is not None:
                return PolicyDecision(
                    PolicyOutcome.DENY,
                    "policy.budget_unspecified",
                    f"policy caps spend at ${self.max_budget_usd:.2f}; the task carries no budget",
                )
            return None
        if budget < 0:
            return PolicyDecision(PolicyOutcome.DENY, "policy.budget_negative", "negative budget")
        if self.max_budget_usd is not None and budget > self.max_budget_usd:
            return PolicyDecision(
                PolicyOutcome.DENY,
                "policy.budget_exceeded",
                f"requested ${budget:.2f} exceeds per-delegation cap ${self.max_budget_usd:.2f}",
            )
        return None

    def _rule_total_cost(self, ctx: RuleContext) -> PolicyDecision | None:
        if self.max_total_cost_usd is None:
            return None
        if ctx.projected_spend > self.max_total_cost_usd:
            return PolicyDecision(
                PolicyOutcome.DENY,
                "policy.chain_budget_exceeded",
                f"chain would reach ${ctx.projected_spend:.2f}, over the "
                f"${self.max_total_cost_usd:.2f} ceiling",
            )
        return None

    # -- presets ------------------------------------------------------------- #

    @classmethod
    def open_grid(cls) -> Policy:
        """No ceilings. For experiments and the offline demo.

        Even here the depth limit stays on: a delegation loop is a bug in any
        configuration, not a policy choice.
        """
        return cls(
            name="open-grid",
            max_budget_usd=None,
            max_total_cost_usd=None,
            max_depth=5,
            require_trust=False,
        )

    @classmethod
    def ceilinged(cls, *, budget: float = 2.0, chain: float = 10.0, depth: int = 3) -> Policy:
        """The sensible default for anything touching real money."""
        return cls(
            name="ceilinged",
            max_budget_usd=budget,
            max_total_cost_usd=chain,
            max_depth=depth,
            require_trust=False,
        )

    @classmethod
    def zero_trust(cls) -> Policy:
        """Every delegate must publish a trust manifest and be allowlisted."""
        return cls(
            name="zero-trust",
            max_budget_usd=1.0,
            max_total_cost_usd=5.0,
            max_depth=2,
            require_trust=True,
        )

    def with_(
        self,
        *,
        rules: Sequence[Rule] | None = None,
        **overrides: object,
    ) -> Policy:
        """Derive a modified policy, leaving the original untouched."""
        base = replace(self, **overrides)  # type: ignore[arg-type]
        if rules:
            return replace(base, rules=tuple(base.rules) + tuple(rules))
        return base


#: Default posture: ceilinged, three hops, no trust requirement.
DEFAULT_POLICY = Policy.ceilinged()
