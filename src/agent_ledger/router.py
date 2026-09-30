"""The grid — where discovery becomes an accountable delegation.

:class:`Grid` is the whole library in one object. It wires an ARD client to a
matcher, a policy and a ledger, and exposes the four verbs the ecosystem is
missing:

* ``discover``  — ask ARD what could do this (delegated to the registry layer)
* ``candidates`` — rank what came back, using this grid's own history
* ``delegate``  — authorise one specific agent for one specific scope
* ``complete`` / ``fail`` / ``revoke`` — close the loop with a receipt

Refusals are first-class. :meth:`Grid.delegate` returns the policy decision that
stopped it, and :meth:`Grid.delegate_and_record` writes that refusal to the
ledger, because "why did nothing happen" is an audit question too.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Protocol

from .ard import ArdClient, ArdError
from .ledger import Ledger
from .matcher import MatchWeights, ReputationIndex, Scorer, explain, rank_candidates
from .models import (
    ArdEntry,
    Candidate,
    Delegation,
    DelegationChain,
    DelegationStatus,
    ExecutionRecord,
    PolicyDecision,
    PolicyOutcome,
    Receipt,
    Task,
    content_digest,
)
from .policy import DEFAULT_POLICY, Policy, RuleContext

__all__ = [
    "DelegationOutcome",
    "ExecutionResult",
    "Executor",
    "Grid",
    "GridConfig",
]


# --------------------------------------------------------------------------- #
# Execution seam
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """What came back from actually invoking a delegate.

    ``cost_usd`` is reported by the executor rather than estimated by the grid,
    because only the callee knows what it spent. That makes cost an attested
    fact on the receipt instead of a guess — and ``execution`` is held to the
    same standard. If an executor fills it in, that is a claim by the party that
    made the call; it is recorded, not verified. See
    :mod:`agent_ledger.a2a` for what a real executor actually checks.
    """

    ok: bool
    cost_usd: float = 0.0
    output: Any = None
    note: str = ""
    #: Remote task identity, remote state, and the credential presented. Optional
    #: because a local executor has none of these, and requiring them would make
    #: every existing executor implementation invalid.
    execution: ExecutionRecord | None = None

    @property
    def output_digest(self) -> str | None:
        return None if self.output is None else content_digest(self.output)


class Executor(Protocol):
    """Invokes a delegate. A2A, MCP, HTTP or a simulator all satisfy this.

    The grid never talks to an agent directly. Keeping invocation behind a
    protocol is what lets the same delegation logic drive a demo, a test, and a
    production A2A client without changing a line of policy.
    """

    def execute(self, task: Task, entry: ArdEntry) -> ExecutionResult: ...


class CallableExecutor:
    """Adapt a plain function into an :class:`Executor`."""

    def __init__(self, fn: Callable[[Task, ArdEntry], ExecutionResult]) -> None:
        self._fn = fn

    def execute(self, task: Task, entry: ArdEntry) -> ExecutionResult:
        return self._fn(task, entry)


def _is_settled(result: ExecutionResult) -> bool:
    """Whether an executor's result means the work is finished.

    An executor that reports no ``execution`` record is treated as settled — the
    only two things it can express are success and failure, and that has been the
    contract since the ``Executor`` protocol existed. A result *with* a record
    names a remote state, and a state that the A2A module considers
    non-terminal means the delegation is still open.
    """
    if result.execution is None or result.execution.state is None:
        return True
    from .a2a import TERMINAL_STATES

    return result.execution.state in TERMINAL_STATES


# --------------------------------------------------------------------------- #
# Outcome
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class DelegationOutcome:
    """The result of one attempt to place work.

    Carries the candidates *and* the refusals, so a failed placement is
    debuggable without re-running the discovery that produced it.
    """

    ok: bool
    reason: str = ""
    delegation: Delegation | None = None
    receipt: Receipt | None = None
    candidates: tuple[Candidate, ...] = ()
    decisions: tuple[PolicyDecision, ...] = ()
    duration_ms: float = 0.0

    @property
    def delegate_identifier(self) -> str | None:
        return self.delegation.delegate.identifier if self.delegation else None

    def explain(self) -> list[str]:
        """Line-by-line narrative suitable for a terminal or a bug report."""
        lines: list[str] = []
        eligible = [c for c in self.candidates if c.eligible]
        lines.append(
            f"considered {len(self.candidates)} entries, {len(eligible)} eligible "
            f"({self.duration_ms:.0f} ms)"
        )
        for candidate in self.candidates[:5]:
            lines.append("  " + explain(candidate))
        for decision in self.decisions:
            lines.append(f"  policy {decision.rule}: {decision.detail}")
        if self.delegation is not None:
            lines.append(
                f"delegated to {self.delegation.delegate.display_name} "
                f"as {self.delegation.delegation_id}"
            )
        elif self.reason:
            lines.append(f"not delegated: {self.reason}")
        return lines


@dataclass(frozen=True, slots=True)
class GridConfig:
    """Knobs that do not belong in policy because they are not refusals."""

    #: Try the next-ranked candidate when policy refuses the top one. Turning
    #: this off makes routing deterministic at the cost of throughput.
    fallback_to_next: bool = True
    #: Maximum candidates to put through policy before giving up.
    max_attempts: int = 5
    #: Write a receipt for refusals, not just for delegations.
    record_refusals: bool = True


# --------------------------------------------------------------------------- #
# The grid
# --------------------------------------------------------------------------- #


class Grid:
    """Accountable delegation over ARD discovery."""

    def __init__(
        self,
        *,
        client: ArdClient | None = None,
        policy: Policy | None = None,
        ledger: Ledger | None = None,
        weights: MatchWeights | None = None,
        scorer: Scorer | None = None,
        executor: Executor | None = None,
        config: GridConfig | None = None,
        domains: Sequence[str] = (),
        registries: Sequence[str] = (),
    ) -> None:
        # NOTE: every one of these uses an explicit ``is not None`` test rather
        # than ``or``. ``Ledger`` defines ``__len__``, so an empty ledger is
        # falsy and ``ledger or Ledger()`` would silently discard the caller's
        # ledger — including one that was about to receive the receipts.
        self.client = client if client is not None else ArdClient()
        self.policy = policy if policy is not None else DEFAULT_POLICY
        self.ledger = ledger if ledger is not None else Ledger()
        self.weights = weights if weights is not None else MatchWeights()
        self.scorer = scorer
        self.executor = executor
        self.config = config if config is not None else GridConfig()
        #: Static ARD domains and dynamic registry endpoints to consult.
        self.domains = tuple(domains)
        self.registries = tuple(registries)
        self._last_discovery: list[ArdEntry] = []
        #: Populated when a discovery source failed, so a thin candidate pool is
        #: explainable after the fact rather than merely surprising.
        self._last_discovery_error: str | None = None

    # -- discovery ----------------------------------------------------------- #

    def discover(self, task: Task, *, filter: Mapping[str, Any] | None = None) -> list[ArdEntry]:
        """Ask ARD what could serve *task*.

        Discovery failures are not fatal: an unreachable registry degrades the
        candidate pool, it does not abort a delegation that a static manifest
        could still satisfy.

        A failure is contained whatever its type, not only when it is an
        :class:`ArdError`. That matters because a discovery source is remote,
        untrusted and capable of returning shapes the client did not anticipate
        — and a parsing bug on a hostile response should cost a candidate, not
        the whole delegation. The error is recorded on the outcome rather than
        swallowed silently, so it stays diagnosable.
        """
        try:
            entries = self.client.discover(
                domains=self.domains,
                registries=self.registries,
                text=task.intent,
                filter=filter,
            )
        except ArdError as exc:
            self._last_discovery_error = str(exc)
            entries = []
        except Exception as exc:  # noqa: BLE001 - a bad remote response is data
            self._last_discovery_error = f"{type(exc).__name__}: {exc}"
            entries = []
        self._last_discovery = entries
        return entries

    def candidates(
        self,
        task: Task,
        entries: Iterable[ArdEntry] | None = None,
        *,
        reputation: ReputationIndex | None = None,
    ) -> list[Candidate]:
        """Rank discovered entries, seeded with this grid's own history.

        The ledger is the default reputation source, which is what makes the
        router stateful: an agent that overran its budget last week is ranked
        lower today without anybody writing a rule.
        """
        pool = list(entries) if entries is not None else self.discover(task)
        return rank_candidates(
            task,
            pool,
            weights=self.weights,
            reputation=reputation if reputation is not None else self.ledger.reputation(),
            scorer=self.scorer,
            require_trust=self.policy.require_trust,
        )

    # -- delegation ---------------------------------------------------------- #

    def _policy_context(self, task: Task, entry: ArdEntry, depth: int) -> RuleContext:
        return RuleContext(
            task=task,
            entry=entry,
            depth=depth,
            spent_usd=self.ledger.spent_for_task(task.task_id),
            committed_usd=self.ledger.committed_for_task(task.task_id),
        )

    def delegate(
        self,
        task: Task,
        *,
        delegated_by: str | None = None,
        parent: Delegation | None = None,
        entries: Iterable[ArdEntry] | None = None,
    ) -> DelegationOutcome:
        """Place *task* with the best eligible agent that policy will allow."""
        started = time.perf_counter()
        principal = delegated_by or task.issued_by
        depth = (parent.depth + 1) if parent else 0
        parent_id = parent.delegation_id if parent else None

        candidates = self.candidates(task, entries)
        decisions: list[PolicyDecision] = []
        attempts = 0

        for candidate in candidates:
            if not candidate.eligible:
                continue
            attempts += 1
            if attempts > self.config.max_attempts:
                break

            context = self._policy_context(task, candidate.entry, depth)
            decision = self.policy.evaluate(context)
            decisions.append(decision)

            if decision.allowed:
                delegation = Delegation(
                    task=task,
                    delegate=candidate.entry,
                    delegated_by=principal,
                    policy=decision,
                    parent_delegation_id=parent_id,
                    depth=depth,
                )
                # Receipt the issuance immediately. Without this, a child
                # delegation issued before its parent settles would have no
                # receipt to link to and would surface as an orphaned chain.
                self.ledger.receipt_delegation(
                    delegation,
                    status=DelegationStatus.PENDING,
                    note=f"issued by {principal}",
                )
                outcome = DelegationOutcome(
                    ok=True,
                    reason="delegated",
                    delegation=delegation,
                    candidates=tuple(candidates),
                    decisions=tuple(decisions),
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
                if self.config.record_refusals:
                    for refused in decisions[:-1]:
                        if refused.outcome is PolicyOutcome.DENY:
                            self._record_refusal(task, principal, refused)
                return outcome

            if decision.outcome is PolicyOutcome.REQUIRE_APPROVAL:
                # Held for a human. Do not silently fall through to a cheaper
                # agent — that would convert "ask someone" into "route around".
                return DelegationOutcome(
                    ok=False,
                    reason=f"held for approval: {decision.detail}",
                    candidates=tuple(candidates),
                    decisions=tuple(decisions),
                    duration_ms=(time.perf_counter() - started) * 1000,
                )

            if not self.config.fallback_to_next:
                break

        reason = (
            decisions[-1].detail
            if decisions
            else "no eligible candidate advertised the required capabilities"
        )
        outcome = DelegationOutcome(
            ok=False,
            reason=reason,
            candidates=tuple(candidates),
            decisions=tuple(decisions),
            duration_ms=(time.perf_counter() - started) * 1000,
        )
        if self.config.record_refusals and decisions:
            self._record_refusal(task, principal, decisions[-1])
        return outcome

    def _record_refusal(self, task: Task, principal: str, decision: PolicyDecision) -> Receipt:
        """Write a refusal to the ledger as a receipt against no delegate.

        A refusal that leaves no trace is indistinguishable from a bug.
        """
        receipt = Receipt(
            delegation_id=f"refused_{task.task_id}",
            task_id=task.task_id,
            delegate="urn:air:refused",
            delegated_by=principal,
            outcome=DelegationStatus.REVOKED,
            scope_digest=content_digest({"intent": task.intent, "rule": decision.rule}),
            note=f"{decision.rule}: {decision.detail}",
        )
        return self.ledger.record(receipt)

    # -- closing the loop ---------------------------------------------------- #

    def _settle(
        self,
        delegation: Delegation,
        status: DelegationStatus,
        *,
        cost_usd: float = 0.0,
        result_digest: str | None = None,
        note: str = "",
        execution: ExecutionRecord | None = None,
    ) -> Receipt:
        return self.ledger.receipt_delegation(
            delegation,
            status=status,
            cost_usd=cost_usd,
            result_digest=result_digest,
            note=note,
            execution=execution,
        )

    def accept(self, delegation: Delegation, *, note: str = "") -> Receipt:
        """Acknowledge a delegation without settling it.

        Recording acceptance separately is what makes ``committed_for_task``
        meaningful: money is committed at acceptance, spent at completion.
        """
        return self._settle(delegation, DelegationStatus.ACCEPTED, note=note)

    def complete(
        self,
        delegation: Delegation,
        *,
        cost_usd: float = 0.0,
        output: Any = None,
        result_digest: str | None = None,
        note: str = "",
        execution: ExecutionRecord | None = None,
    ) -> Receipt:
        digest = result_digest
        if digest is None and output is not None:
            digest = content_digest(output)
        return self._settle(
            delegation,
            DelegationStatus.COMPLETED,
            cost_usd=cost_usd,
            result_digest=digest,
            note=note,
            execution=execution,
        )

    def fail(
        self,
        delegation: Delegation,
        *,
        cost_usd: float = 0.0,
        note: str = "",
        execution: ExecutionRecord | None = None,
    ) -> Receipt:
        return self._settle(
            delegation,
            DelegationStatus.FAILED,
            cost_usd=cost_usd,
            note=note,
            execution=execution,
        )

    def revoke(self, delegation: Delegation, *, note: str = "") -> Receipt:
        return self._settle(delegation, DelegationStatus.REVOKED, note=note)

    # -- the full loop ------------------------------------------------------- #

    def dispatch(
        self,
        task: Task,
        *,
        delegated_by: str | None = None,
        executor: Executor | None = None,
    ) -> DelegationOutcome:
        """Discover, delegate, execute and receipt — the complete round trip.

        This is the method a real integration calls. Everything before it is
        also public, because operators need to inspect and override each stage.

        Two things it deliberately does *not* do:

        * **Invoke a delegate with no target.** See below.
        * **Return before receipting.** With no ``executor`` configured the
          delegation is issued and receipted as ``pending`` — the receipt for
          that issuance is on the outcome, so ``outcome.receipt`` is never
          ``None`` merely because nothing was executed. Otherwise
          ``outcome.ok`` could be ``True`` while ``outcome.receipt`` was
          ``None``, which is a trap for exactly the call the README shows.
        """
        outcome = self.delegate(task, delegated_by=delegated_by)
        if not outcome.ok or outcome.delegation is None:
            return outcome

        runner = executor or self.executor
        if runner is None:
            # Nothing to execute, but the delegation happened and is already in
            # the ledger. Hand back its issuance receipt rather than a bare
            # success with no artefact to check.
            return replace(
                outcome,
                receipt=self.ledger.by_delegation(outcome.delegation.delegation_id),
            )

        if not outcome.delegation.delegate.has_target:
            # ARD §5.3.2 permits a search result with no `url` — it names an
            # authoritative entry without carrying it. Such a result is fine to
            # rank, and impossible to invoke. Say which, instead of letting the
            # executor fail with an AttributeError on `None`.
            identifier = outcome.delegation.delegate.identifier
            receipt = self.fail(
                outcome.delegation,
                note=f"no invocation target for {identifier} (ARD §5.3.2 partial result)",
            )
            return DelegationOutcome(
                ok=False,
                reason=(
                    f"cannot invoke {identifier}: the discovery source returned a "
                    "partial result with no url or data, so there is no endpoint to call"
                ),
                delegation=outcome.delegation,
                receipt=receipt,
                candidates=outcome.candidates,
                decisions=outcome.decisions,
                duration_ms=outcome.duration_ms,
            )

        self.accept(outcome.delegation)
        try:
            result = runner.execute(task, outcome.delegation.delegate)
        except Exception as exc:  # noqa: BLE001 - a delegate crash is data
            receipt = self.fail(outcome.delegation, note=f"executor raised: {exc!r}")
            return DelegationOutcome(
                ok=False,
                reason=f"execution failed: {exc}",
                delegation=outcome.delegation,
                receipt=receipt,
                candidates=outcome.candidates,
                decisions=outcome.decisions,
                duration_ms=outcome.duration_ms,
            )

        execution = result.execution

        if result.ok and not _is_settled(result):
            # The remote accepted the work but has not finished it — an A2A task
            # still working, or interrupted waiting for the principal. Completing
            # the delegation here would claim work that has not landed, and
            # failing it would blame the delegate for a question nobody has
            # answered. So the delegation stays open: `accepted`, budget still
            # committed, ready for `grid.complete()` when the task settles.
            receipt = self._settle(
                outcome.delegation,
                DelegationStatus.ACCEPTED,
                note=result.note or "accepted, not yet settled",
                execution=execution,
            )
            return DelegationOutcome(
                ok=True,
                reason=result.note or "accepted, not yet settled",
                delegation=outcome.delegation,
                receipt=receipt,
                candidates=outcome.candidates,
                decisions=outcome.decisions,
                duration_ms=outcome.duration_ms,
            )

        if result.ok:
            receipt = self.complete(
                outcome.delegation,
                cost_usd=result.cost_usd,
                output=result.output,
                note=result.note,
                execution=execution,
            )
        else:
            receipt = self.fail(
                outcome.delegation,
                cost_usd=result.cost_usd,
                note=result.note,
                execution=execution,
            )

        return DelegationOutcome(
            ok=result.ok,
            reason=result.note or ("completed" if result.ok else "failed"),
            delegation=outcome.delegation,
            receipt=receipt,
            candidates=outcome.candidates,
            decisions=outcome.decisions,
            duration_ms=outcome.duration_ms,
        )

    # -- audit --------------------------------------------------------------- #

    def audit(self, receipt: Receipt | str) -> DelegationChain:
        """Rebuild the lineage behind a receipt or receipt id."""
        return self.ledger.chain(receipt)

    def audit_trail(self) -> list[DelegationChain]:
        """Every chain this grid has produced."""
        return self.ledger.chains()

    def verify(self) -> str:
        """Integrity statement for the whole ledger."""
        return self.ledger.verify().describe()
