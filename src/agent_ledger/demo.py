"""A complete, offline, zero-configuration demonstration of the grid.

This module exists for one reason: a visitor should be able to run
``al demo`` and understand the entire project in under a minute, with no API
key, no network, and no account. Everything here is simulated — a fake
enterprise with a fake internal registry and fake agents — but every code path
it exercises is the real one.

The scenario is chosen to show the thing that is hard to show in prose:

* a three-hop delegation chain that stays attributable across two organisations
* a policy refusal that is recorded rather than swallowed
* reputation that changes a routing decision, because the grid remembers a
  budget overrun that happened earlier in the same run
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .ard import ArdClient, StaticTransport
from .ledger import Ledger
from .matcher import MatchWeights
from .models import (
    TYPE_A2A_AGENT_CARD,
    ArdEntry,
    DelegationStatus,
    PolicyDecision,
    PolicyOutcome,
    Task,
)
from .policy import Policy, RuleContext
from .render import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    RED,
    YELLOW,
    bar,
    c,
    g,
    header,
    kv,
    rule,
    tree,
)
from .router import CallableExecutor, ExecutionResult, Grid, GridConfig

__all__ = ["DemoResult", "build_grid", "run_demo"]

# --------------------------------------------------------------------------- #
# The fictional organisation
# --------------------------------------------------------------------------- #

INTERNAL_REGISTRY = "https://registry.northwind.internal/api/v1/search"
PARTNER_REGISTRY = "https://finder.partner.example/search"

AGENTS: tuple[Mapping[str, Any], ...] = (
    {
        "identifier": "urn:air:northwind.internal:agent:program-coordinator",
        "displayName": "Program Coordinator",
        "description": "Plans and dispatches multi-team launch programmes.",
        "capabilities": ["program_management", "task_planning"],
        "representativeQueries": [
            "coordinate a product launch across several teams",
            "plan and dispatch a multi-step programme of work",
        ],
        "registry": INTERNAL_REGISTRY,
        "score": 96,
        "trust": {"identity": "spiffe://northwind.internal/agents/coordinator"},
        "cost": 0.02,
    },
    {
        "identifier": "urn:air:northwind.internal:agent:legal-review",
        "displayName": "Contract Review Agent",
        "description": "Reviews data processing agreements and vendor contracts.",
        "capabilities": ["contract_review", "dpa_review", "risk_assessment"],
        "representativeQueries": [
            "review a data processing agreement for GDPR gaps",
            "check this vendor contract for risky clauses",
        ],
        "registry": INTERNAL_REGISTRY,
        "score": 93,
        "trust": {"identity": "spiffe://northwind.internal/agents/legal"},
        "cost": 0.35,
    },
    {
        "identifier": "urn:air:northwind.internal:agent:localization",
        "displayName": "Localization Agent",
        "description": "In-house translation and locale adaptation for product copy.",
        "capabilities": ["translation", "localization"],
        "representativeQueries": [
            "translate the landing page into German and Japanese",
            "localize product copy for a new market",
        ],
        "registry": INTERNAL_REGISTRY,
        "score": 88,
        "trust": {"identity": "spiffe://northwind.internal/agents/l10n"},
        "cost": 0.12,
    },
    {
        "identifier": "urn:air:partner.example:agent:translate-pro",
        "displayName": "TranslatePro (partner)",
        "description": "Certified translation vendor with legal review included.",
        "capabilities": ["translation", "legal_translation"],
        "representativeQueries": [
            "certified legal translation into Japanese",
            "translate regulated marketing copy",
        ],
        "registry": PARTNER_REGISTRY,
        "score": 84,
        "trust": {"identity": "spiffe://partner.example/agents/translate"},
        "cost": 0.31,
    },
    {
        "identifier": "urn:air:cheapapi.io:agent:bargain-llm",
        "displayName": "BargainLLM",
        "description": "Lowest-cost bulk translation. No compliance attestation.",
        "capabilities": ["translation"],
        "representativeQueries": ["cheap bulk translation", "translate text on a budget"],
        "registry": PARTNER_REGISTRY,
        "score": 71,
        "trust": None,  # no trustManifest -> policy has something to say
        "cost": 0.01,
    },
    {
        "identifier": "urn:air:northwind.internal:agent:security-desk",
        "displayName": "Vendor Security Desk",
        "description": "Completes vendor security questionnaires from policy templates.",
        "capabilities": ["security_review", "questionnaire"],
        "representativeQueries": [
            "complete a vendor security questionnaire",
            "answer a customer security assessment",
        ],
        "registry": INTERNAL_REGISTRY,
        "score": 90,
        "trust": {"identity": "spiffe://northwind.internal/agents/sec"},
        "cost": 0.08,
    },
)


def _entry_document(agent: Mapping[str, Any]) -> dict[str, Any]:
    trust = agent["trust"]
    return {
        "identifier": agent["identifier"],
        "displayName": agent["displayName"],
        "description": agent["description"],
        "type": TYPE_A2A_AGENT_CARD,
        "url": agent["identifier"].replace("urn:air:", "https://").replace(":", "/") + ".json",
        "capabilities": agent["capabilities"],
        "representativeQueries": agent["representativeQueries"],
        **({"trustManifest": trust} if trust else {}),
    }


DEMO_AGENTS: dict[str, ArdEntry] = {
    a["identifier"]: ArdEntry.from_ard(_entry_document(a)) for a in AGENTS
}


def _make_registry(registry_url: str) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    """A registry that behaves like a real one: ranks by overlap, returns referrals."""

    pool = [a for a in AGENTS if a["registry"] == registry_url]

    def handler(payload: Mapping[str, Any]) -> dict[str, Any]:
        query = payload.get("query", {})
        text = str(query.get("text", "")).lower()
        wanted = {str(cap).lower() for cap in (query.get("filter") or {}).get("capabilities", [])}

        results = []
        for agent in pool:
            caps = {cap.lower() for cap in agent["capabilities"]}
            if wanted and not (wanted & caps):
                continue
            haystack = " ".join(
                [agent["displayName"], agent["description"], *agent["representativeQueries"]]
            ).lower()
            # Cheap lexical boost so different queries surface different agents.
            overlap = sum(1 for token in set(text.split()) if token in haystack)
            score = min(99, agent["score"] + overlap)
            results.append({**_entry_document(agent), "score": score})

        results.sort(key=lambda r: r["score"], reverse=True)

        response: dict[str, Any] = {"results": results}
        if registry_url == INTERNAL_REGISTRY:
            # ARD §5.4 referrals: the client decides whether to follow these.
            response["referrals"] = [
                {
                    "identifier": "urn:air:partner.example:registry:public",
                    "displayName": "Partner Agent Finder",
                    "type": "application/ai-registry+json",
                    "url": PARTNER_REGISTRY,
                }
            ]
        return response

    return handler


def build_transport(*, with_public_registry: bool = True) -> StaticTransport:
    """Wire up the fake federation used by the demo and the tests."""
    transport = StaticTransport()
    transport.add(INTERNAL_REGISTRY, _make_registry(INTERNAL_REGISTRY))
    if with_public_registry:
        transport.add(PARTNER_REGISTRY, _make_registry(PARTNER_REGISTRY))

    # Static discovery is exercised too: the internal domain publishes a
    # well-known manifest alongside its search API.
    transport.add(
        "https://northwind.internal/.well-known/ard.json",
        {"entries": [_entry_document(a) for a in AGENTS if a["registry"] == INTERNAL_REGISTRY]},
    )
    return transport


# --------------------------------------------------------------------------- #
# The scenario
# --------------------------------------------------------------------------- #


def _regulated_work_needs_attestation(ctx: RuleContext) -> PolicyDecision | None:
    """A custom rule, to show that policy extends without forking the library.

    Translation for a regulated launch must not go to an unattested delegate —
    a reasonable house rule that ships with the demo scenario but not with the
    library itself.
    """
    if ctx.entry.is_trusted or "translation" not in ctx.task.capability_set:
        return None
    return PolicyDecision(
        PolicyOutcome.DENY,
        "policy.regulated_work_needs_attestation",
        "translation for a regulated launch requires a trustManifest",
    )


def build_grid(
    *,
    transport: StaticTransport | None = None,
    policy: Policy | None = None,
    ledger: Ledger | None = None,
) -> Grid:
    """A grid configured exactly as the demo describes it."""
    if transport is None:
        transport = build_transport()
    if policy is None:
        policy = Policy.ceilinged(budget=0.50, chain=2.00, depth=3).with_(
            denied_publishers=frozenset({"cheapapi.io"}),
            rules=(_regulated_work_needs_attestation,),
        )
    # Explicit ``is not None``: Ledger defines __len__, so an empty ledger is
    # falsy and ``ledger or Ledger()`` would throw away the caller's ledger.
    if ledger is None:
        ledger = Ledger()
    return Grid(
        client=ArdClient(transport),
        policy=policy,
        ledger=ledger,
        weights=MatchWeights(),
        domains=("northwind.internal",),
        registries=(INTERNAL_REGISTRY,),
        executor=None,
        config=GridConfig(fallback_to_next=True, record_refusals=True),
    )


PRINCIPAL = "urn:principal:northwind.internal:dana"


def _executor(agent_costs: Mapping[str, float]) -> CallableExecutor:
    """Agents that always succeed, except for a deliberately flaky one."""

    def run(task: Task, entry: ArdEntry) -> ExecutionResult:
        cost = agent_costs.get(entry.identifier, 0.05)
        if entry.identifier.endswith("security-desk"):
            return ExecutionResult(
                ok=True,
                cost_usd=cost,
                output={"questionnaire": "completed", "gaps": 0},
                note="questionnaire completed from policy templates",
            )
        return ExecutionResult(
            ok=True,
            cost_usd=cost,
            output={"task": task.intent, "agent": entry.display_name},
            note=f"{entry.display_name} completed the work",
        )

    return CallableExecutor(run)


@dataclass
class DemoResult:
    """Everything the demo did, so tests and callers can assert on it."""

    chain_length: int = 0
    total_cost_usd: float = 0.0
    delegations: int = 0
    refusals: int = 0
    integrity_ok: bool = False
    ranking_before: list[tuple[str, float]] = None  # type: ignore[assignment]
    ranking_after: list[tuple[str, float]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.ranking_before is None:
            self.ranking_before = []
        if self.ranking_after is None:
            self.ranking_after = []


def _short(identifier: str) -> str:
    """Compact label for a URN or a URL, for terminal display only."""
    if identifier.startswith("urn:"):
        return identifier.rsplit(":", 1)[-1]
    stripped = identifier.split("://", 1)[-1]
    return stripped.split("/", 1)[0]


def run_demo(*, out: Callable[[str], None] = print, colour: bool = True) -> DemoResult:
    """Run the full narrative. Returns a summary for tests."""
    if not colour:
        import os

        os.environ["NO_COLOR"] = "1"

    costs = {a["identifier"]: float(a["cost"]) for a in AGENTS}
    ledger = Ledger()
    grid = build_grid(ledger=ledger)
    # The demo drives delegation hop by hop so each step is visible. Wiring the
    # executor means ``grid.dispatch(task)`` would work identically, which is
    # what a real integration calls.
    grid.executor = _executor(costs)

    out(rule("agent-ledger"))
    out(
        c("  Accountable delegation for AI agents.", BOLD)
        + "\n"
        + c(
            "  ARD finds them. A2A talks to them. This is the ledger of what they did.",
            DIM,
        )
    )

    # ---------------------------------------------------------------- step 1
    out(header(1, "The organisation"))
    out(kv("principal", c(PRINCIPAL, CYAN)))
    out(kv("publishers", "northwind.internal (internal), partner.example"))
    out(kv("registries", "1 internal + 1 federated referral"))
    out(kv("policy", c(grid.policy.name, YELLOW) + c(f"  depth<={grid.policy.max_depth}", DIM)))
    out("")
    out(c("  Registered agents:", DIM))
    for agent in AGENTS:
        mark = c(g("check"), GREEN) if agent["trust"] else c(g("cross"), RED)
        out(f"    {mark} {agent['displayName']:<26}" + c(", ".join(agent["capabilities"]), DIM))

    # ---------------------------------------------------------------- step 2
    out(header(2, "ARD discovery — the layer we do not reinvent"))
    task = Task(
        intent="coordinate the EU launch programme across legal, localisation and security",
        required_capabilities=("program_management",),
        issued_by=PRINCIPAL,
        budget_usd=0.50,
    )
    entries = grid.discover(task)
    manifest = grid.client.fetch_manifest("northwind.internal")
    out(kv("static", f"GET /.well-known/ard.json → {len(manifest)} entries"))
    out(kv("dynamic", f"POST {_short(INTERNAL_REGISTRY)} → {len(entries)} entries"))
    out(
        kv(
            "referrals",
            c("finder.partner.example", DIM) + c("  (inside the budgeted federation)", DIM),
        )
    )
    out(c("  These are ARD calls. Any conformant registry works here.", DIM))

    # ---------------------------------------------------------------- step 3
    out(header(3, "Ranking — the layer we do own"))
    candidates = grid.candidates(task, entries)
    eligible = [cand for cand in candidates if cand.eligible]
    skipped = [cand for cand in candidates if not cand.eligible]
    out(
        c(
            f"  {len(candidates)} entries discovered, {len(eligible)} eligible "
            f"for [{', '.join(task.required_capabilities)}], {len(skipped)} filtered out:",
            DIM,
        )
    )
    out("")
    for cand in eligible:
        signals = cand.signals
        out(
            f"    {c(g('check'), GREEN)} {cand.entry.display_name:<28} "
            + bar(cand.score)
            + f" {cand.score:.3f}"
        )
        out(
            "        "
            + c(
                f"capability={signals.get('capability', 0):.2f}  "
                f"query={signals.get('query', 0):.2f}  "
                f"trust={signals.get('trust', 0):.2f}  "
                f"reputation={signals.get('reputation', 0):.2f}",
                DIM,
            )
        )
    for cand in skipped[:3]:
        out(
            f"    {c(g('cross'), RED)} {cand.entry.display_name:<28} "
            + c(cand.rejected_reason or "", DIM)
        )
    eligible.sort(key=lambda x: x.score, reverse=True)
    assert eligible and eligible[0].entry.identifier.endswith("program-coordinator")

    # ---------------------------------------------------------------- step 4
    out(header(4, "Delegation — hop 0"))
    outcome = grid.delegate(task)
    if not outcome.ok or outcome.delegation is None:
        out(c(f"  delegation refused: {outcome.reason}", RED))
        return DemoResult()
    coordinator = outcome.delegation
    out(kv("delegate", c(coordinator.delegate.display_name, GREEN, BOLD)))
    out(kv("delegation_id", c(coordinator.delegation_id, DIM)))
    out(kv("scope", c(str(sorted(coordinator.scope["capabilities"])), DIM)))
    out(kv("budget", f"${task.budget_usd:.2f}"))
    grid.accept(coordinator, note="coordinator picked up the programme")

    # ---------------------------------------------------------------- step 5
    out(header(5, "Re-delegation — the chain forms"))
    legal_task = task.child(
        "review the data processing agreement for the EU launch",
        ["contract_review"],
        budget_usd=0.40,
        parent_delegation=coordinator.delegation_id,
    )
    legal_outcome = grid.delegate(legal_task, parent=coordinator)
    if not legal_outcome.ok or legal_outcome.delegation is None:
        out(c(f"  refused: {legal_outcome.reason}", RED))
        return DemoResult()
    legal = legal_outcome.delegation
    out(
        kv(
            "hop 1",
            f"{c(coordinator.delegate.display_name, DIM)} → "
            f"{c(legal.delegate.display_name, GREEN)} " + c(f"(depth {legal.depth})", DIM),
        )
    )

    l10n_task = legal_task.child(
        "localize the landing page into German and Japanese",
        ["translation"],
        budget_usd=0.20,
        parent_delegation=legal.delegation_id,
    )
    ranks = grid.candidates(l10n_task)
    out("")
    out(c("  Candidates for the localisation sub-task:", DIM))
    for cand in ranks:
        if cand.eligible:
            out(f"    {c(g('arrow'), GREEN)} {cand.entry.display_name:<26} {cand.score:.3f}")
        else:
            out(
                f"    {c(g('cross'), RED)} {cand.entry.display_name:<26} "
                + c(cand.rejected_reason or "", RED)
            )

    l10n_outcome = grid.delegate(l10n_task, parent=legal)
    if not l10n_outcome.ok or l10n_outcome.delegation is None:
        out(c(f"  refused: {l10n_outcome.reason}", RED))
        return DemoResult()
    l10n = l10n_outcome.delegation
    out(
        kv(
            "hop 2",
            f"{c(legal.delegate.display_name, DIM)} → "
            f"{c(l10n.delegate.display_name, GREEN)} " + c(f"(depth {l10n.depth})", DIM),
        )
    )
    for decision in l10n_outcome.decisions:
        if decision.outcome.value == "deny":
            out(
                kv(
                    "refused",
                    c(decision.rule, YELLOW) + c(f"  {decision.detail}", DIM),
                )
            )

    # ---------------------------------------------------------------- step 6
    out(header(6, "Settling up — receipts all the way down"))
    # Each receipt records only what *that* delegate spent. A parent that
    # sub-delegates does not absorb its children's costs, or the chain total
    # would multiply-count and every parent would look like it overspent.
    grid.complete(
        l10n,
        cost_usd=costs[l10n.delegate.identifier],
        note="German and Japanese live",
    )
    grid.complete(
        legal,
        cost_usd=costs[legal.delegate.identifier],
        note="DPA reviewed, localisation sub-delegated",
    )
    grid.complete(
        coordinator,
        cost_usd=costs[coordinator.delegate.identifier],
        note="programme closed",
    )

    chains = [ch for ch in grid.audit_trail() if len(ch) > 1]
    chain = max(chains, key=len) if chains else grid.audit_trail()[0]
    out("")
    lines: list[tuple[int, str]] = []
    for receipt in chain:
        status_colour = {
            DelegationStatus.COMPLETED: GREEN,
            DelegationStatus.FAILED: RED,
            DelegationStatus.REVOKED: YELLOW,
        }.get(receipt.outcome, DIM)
        lines.append(
            (
                receipt.depth,
                f"{_short(receipt.delegate):<22} "
                + c(receipt.outcome.value, status_colour)
                + c(f"  ${receipt.cost_usd:.4f}", DIM)
                + c(f"  {receipt.receipt_id}", DIM),
            )
        )
    out(tree(lines))
    out("")
    out(kv("chain length", f"{len(chain)} hops"))
    out(kv("total cost", c(f"${chain.total_cost:.4f}", BOLD)))
    out(kv("violations", c("none", GREEN) if chain.is_clean else c(str(chain.violations()), RED)))
    out(
        kv(
            "answerable to",
            c(chain.root.delegated_by if chain.root else "unknown", CYAN),
        )
    )

    # ---------------------------------------------------------------- step 7
    out(header(7, "Integrity"))
    integrity = ledger.verify()
    out(kv("verify", c(integrity.describe(), GREEN if integrity.ok else RED)))
    out(c("  Each receipt carries a sha256 over its own canonical form.", DIM))
    out(c("  Edit a line in the JSONL and verify() will say so.", DIM))

    # ---------------------------------------------------------------- step 8
    out(header(8, "Routing that remembers"))
    out(
        c(
            "  Rank the same request twice. Nothing changes but the ledger.",
            DIM,
        )
    )
    probe = Task(
        intent="translate a product landing page into Japanese",
        required_capabilities=("translation",),
        issued_by=PRINCIPAL,
        budget_usd=0.20,
    )
    ranking_before = [
        (cand.entry.display_name, cand.score) for cand in grid.candidates(probe) if cand.eligible
    ]
    out("")
    out(c("  Before — nobody has a history yet:", DIM))
    for name, score in ranking_before:
        out(f"    {name:<28} {c(bar(score), DIM)} {score:.3f}")

    # Two budget overruns, delegated for real and receipted for real. The
    # probe task is never re-defined, so the only variable is reputation.
    for attempt in range(2):
        overrun_task = Task(
            intent="translate a product landing page into Japanese",
            required_capabilities=("translation",),
            issued_by=PRINCIPAL,
            budget_usd=0.05,
            metadata={"attempt": attempt},
        )
        overrun = grid.delegate(overrun_task)
        if overrun.ok and overrun.delegation is not None:
            grid.complete(overrun.delegation, cost_usd=0.42, note="overran budget 8x")

    reranked = [cand for cand in grid.candidates(probe) if cand.eligible]
    ranking_after = [(cand.entry.display_name, cand.score) for cand in reranked]

    out("")
    out(c("  After — the localisation agent overran its budget twice:", DIM))
    before_map = dict(ranking_before)
    for cand in reranked:
        name = cand.entry.display_name
        delta = cand.score - before_map.get(name, cand.score)
        arrow = (
            c(f"  {g('up')}{delta:+.3f}", GREEN)
            if delta > 0.001
            else c(f"  {g('down')}{delta:+.3f}", RED)
            if delta < -0.001
            else c(f"  {g('flat')}", DIM)
        )
        reputation = cand.signals.get("reputation", 0.0)
        out(
            f"    {name:<28} {bar(cand.score)} {cand.score:.3f}{arrow}"
            + c(f"   reputation={reputation:.2f}", DIM)
        )
    out("")
    out(c("  No rule was written. The ledger did the ranking.", DIM))
    out(
        c(
            "  A registry can tell you an agent claims a capability. "
            "Only a receipt can tell you it blew the budget.",
            DIM,
        )
    )
    out(rule())
    out(
        c("  Next: ", BOLD)
        + c("al demo --json", CYAN)
        + c("   ·   ", DIM)
        + c("pip install ai-agent-ledger-py", CYAN)
    )

    return DemoResult(
        chain_length=len(chain),
        total_cost_usd=chain.total_cost,
        delegations=ledger.stats().delegations,
        refusals=len([r for r in ledger if r.delegate == "urn:air:refused"]),
        integrity_ok=integrity.ok,
        ranking_before=ranking_before,
        ranking_after=ranking_after,
    )
