"""Capability matching — turning an ARD result set into a ranked shortlist.

ARD answers "which resources claim this capability". That is a filter, not a
decision. Choosing *which* of forty capable agents should receive work needs
signals ARD deliberately does not carry: how reliable the publisher has been,
whether the trust claim is verifiable, and how this agent performed the last
time this grid delegated to it.

That last signal is the point of the module. Most routers are stateless — they
score, they dispatch, they forget. A grid that keeps its own receipts can
down-rank an agent that overran its budget last week without anyone writing a
rule about it.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .models import (
    ArdEntry,
    Candidate,
    DelegationStatus,
    Receipt,
    Task,
)

__all__ = [
    "MatchWeights",
    "ReputationIndex",
    "Scorer",
    "lexical_similarity",
    "rank_candidates",
    "tokenize",
]

#: Outcomes that count against an agent's reputation. ``PENDING`` and
#: ``ACCEPTED`` are deliberately absent: work in flight is not evidence.
_BAD_OUTCOMES = frozenset(
    {
        DelegationStatus.FAILED,
        DelegationStatus.REVOKED,
        DelegationStatus.EXPIRED,
    }
)

_STOPWORDS = frozenset(
    """
    a an and are as at be by for from has have how i in is it its me my of on or
    that the their there these this to was were what when where which who will
    with you your please can could would should do does
    """.split()
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    """Lowercase word tokens with stopwords removed.

    Deliberately simple and dependency-free. It is a lexical proxy, not a
    semantic one — see :class:`Scorer` for how to substitute a real embedding
    model without touching the rest of the grid.
    """
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS and len(t) > 1]


def _stem(token: str) -> str:
    """Crude suffix folding so 'book' matches 'booking' and 'flights' 'flight'.

    A trailing ``e`` is dropped as well, which is what makes *translate* and
    *translating* collapse to the same stem. Getting that pair wrong is the
    difference between a translation request matching a translation agent and
    silently matching nothing.
    """
    for suffix in ("ing", "ers", "er", "ies", "es", "ed", "s"):
        if len(token) > len(suffix) + 2 and token.endswith(suffix):
            token = token[: -len(suffix)]
            break
    if len(token) > 3 and token.endswith("e"):
        token = token[:-1]
    return token


def lexical_similarity(left: str, right: str) -> float:
    """Cosine-ish overlap of stemmed token sets, in ``[0, 1]``."""
    a = {_stem(t) for t in tokenize(left)}
    b = {_stem(t) for t in tokenize(right)}
    if not a or not b:
        return 0.0
    return len(a & b) / math.sqrt(len(a) * len(b))


# --------------------------------------------------------------------------- #
# Reputation: the signal nobody else has
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ReputationIndex:
    """Historical reliability derived from this grid's own receipts.

    There is no central authority here and no shared blacklist. An index only
    ever reflects delegations this installation actually issued, which is what
    makes it defensible: it is evidence, not gossip.
    """

    _stats: dict[str, dict[str, float]] = field(default_factory=dict)
    #: Receipts below this many samples contribute nothing, so a single bad
    #: afternoon cannot permanently sideline an otherwise good agent.
    min_samples: int = 2
    #: How much an overrun costs relative to a plain failure. An overrun is a
    #: governance breach that still reports success, so it is worse than a
    #: failure you can at least see.
    overrun_penalty: float = 0.8
    failure_penalty: float = 0.5

    def record(self, receipt: Receipt) -> None:
        bucket = self._stats.setdefault(
            receipt.delegate,
            {"attempts": 0.0, "successes": 0.0, "failures": 0.0, "overruns": 0.0, "cost": 0.0},
        )
        bucket["attempts"] += 1
        bucket["cost"] += receipt.cost_usd

        if receipt.over_budget:
            # An overrun is counted separately and also denies the success
            # credit: the work landed, but outside the authority granted.
            bucket["overruns"] += 1
        elif receipt.outcome is DelegationStatus.COMPLETED:
            bucket["successes"] += 1
        elif receipt.outcome in _BAD_OUTCOMES:
            bucket["failures"] += 1

    def extend(self, receipts: Iterable[Receipt]) -> ReputationIndex:
        for receipt in receipts:
            self.record(receipt)
        return self

    def stats(self, identifier: str) -> Mapping[str, float]:
        return dict(self._stats.get(identifier, {}))

    def score(self, identifier: str) -> float:
        """A ``[0, 1]`` reliability score; the neutral prior is ``0.5``.

        Unknown agents are neither rewarded nor punished. The score starts at
        the neutral prior and moves with observed behaviour, so a mixed record
        lands between the extremes instead of saturating at one.
        """
        bucket = self._stats.get(identifier)
        if not bucket or bucket["attempts"] < self.min_samples:
            return 0.5
        attempts = bucket["attempts"]
        raw = (
            0.5
            + 0.5 * (bucket["successes"] / attempts)
            - self.failure_penalty * (bucket["failures"] / attempts)
            - self.overrun_penalty * (bucket["overruns"] / attempts)
        )
        return max(0.0, min(1.0, raw))

    def is_known(self, identifier: str) -> bool:
        bucket = self._stats.get(identifier)
        return bool(bucket) and bucket["attempts"] >= self.min_samples

    def leaderboard(self, limit: int = 10) -> list[tuple[str, float]]:
        ranked = sorted(
            ((k, self.score(k)) for k in self._stats),
            key=lambda kv: kv[1],
            reverse=True,
        )
        return ranked[:limit]


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class MatchWeights:
    """Tunable importance of each signal. Weights are normalised at use.

    Defaults reflect an opinion worth stating out loud: hard capability fit
    dominates, semantic similarity matters but is the weakest evidence of
    competence, and reputation — the only signal grounded in observed
    behaviour — is weighted as heavily as query relevance.
    """

    capability: float = 0.40
    query: float = 0.15
    registry: float = 0.10
    trust: float = 0.10
    reputation: float = 0.25

    def normalised(self) -> MatchWeights:
        total = self.capability + self.query + self.registry + self.trust + self.reputation
        if total <= 0:
            return MatchWeights()
        return MatchWeights(
            capability=self.capability / total,
            query=self.query / total,
            registry=self.registry / total,
            trust=self.trust / total,
            reputation=self.reputation / total,
        )


#: A scorer maps ``(task, entry)`` to a similarity in ``[0, 1]``. Supply one to
#: swap lexical matching for embeddings without touching anything else.
Scorer = Callable[[Task, ArdEntry], float]


def _default_scorer(task: Task, entry: ArdEntry) -> float:
    texts = list(entry.representative_queries) or [entry.display_name]
    if entry.description:
        texts.append(entry.description)
    return max((lexical_similarity(task.intent, t) for t in texts), default=0.0)


def _capability_coverage(task: Task, entry: ArdEntry) -> tuple[float, frozenset[str]]:
    """Fraction of required capabilities the entry advertises, plus the gaps."""
    required = task.capability_set
    if not required:
        return (1.0, frozenset())
    available = entry.capability_set
    missing = required - available
    return (len(required & available) / len(required), frozenset(missing))


def rank_candidates(
    task: Task,
    entries: Iterable[ArdEntry],
    *,
    weights: MatchWeights | None = None,
    reputation: ReputationIndex | None = None,
    scorer: Scorer | None = None,
    require_capabilities: bool = True,
    require_trust: bool = False,
    exclude: Iterable[str] = (),
) -> list[Candidate]:
    """Score and rank discovered entries for *task*, best first.

    Ineligible candidates are returned too, each carrying ``rejected_reason``,
    so a caller can explain why an obvious-looking agent was skipped. Silent
    filtering is how routing bugs survive to production.
    """
    w = (weights or MatchWeights()).normalised()
    score_query = scorer or _default_scorer
    reputation = reputation or ReputationIndex()
    excluded = {e for e in exclude}

    candidates: list[Candidate] = []

    for entry in entries:
        signals: dict[str, float] = {}

        if entry.identifier in excluded:
            candidates.append(Candidate(entry, 0.0, signals, "excluded by caller"))
            continue

        if not entry.is_searchable:
            # ARD §5.3.2: a registry may return a result carrying only
            # `identifier`, `displayName` and `type`. That is a legitimate
            # answer, not a malformed entry — so it is ranked, not discarded.
            # What it cannot do is be invoked, and `Grid.dispatch` is where that
            # distinction gets enforced, with a reason that names the real
            # problem instead of calling the entry malformed.
            candidates.append(Candidate(entry, 0.0, signals, "not a usable ARD entry"))
            continue

        coverage, missing = _capability_coverage(task, entry)
        signals["capability"] = coverage

        if require_capabilities and missing:
            gaps = ", ".join(sorted(missing))
            candidates.append(Candidate(entry, 0.0, signals, f"missing capability: {gaps}"))
            continue

        if require_trust and not entry.is_trusted:
            candidates.append(Candidate(entry, 0.0, signals, "no trust manifest"))
            continue

        signals["query"] = score_query(task, entry)
        signals["registry"] = (
            max(0.0, min(1.0, entry.registry_score / 100.0))
            if entry.registry_score is not None
            else 0.5
        )
        signals["trust"] = 1.0 if entry.is_trusted else 0.25
        signals["reputation"] = reputation.score(entry.identifier)

        total = (
            w.capability * signals["capability"]
            + w.query * signals["query"]
            + w.registry * signals["registry"]
            + w.trust * signals["trust"]
            + w.reputation * signals["reputation"]
        )

        candidates.append(Candidate(entry, round(total, 6), signals))

    candidates.sort(key=lambda c: (c.eligible, c.score), reverse=True)
    return candidates


def explain(candidate: Candidate, weights: MatchWeights | None = None) -> str:
    """Human-readable justification for a ranking decision.

    Printed by the CLI and stored next to receipts: a delegation that cannot be
    explained six months later was never really accountable.
    """
    w = (weights or MatchWeights()).normalised()
    if not candidate.eligible:
        return f"{candidate.entry.display_name}: skipped — {candidate.rejected_reason}"
    parts = [
        f"{name}={candidate.signals.get(name, 0.0):.2f}x{weight:.2f}"
        for name, weight in (
            ("capability", w.capability),
            ("query", w.query),
            ("registry", w.registry),
            ("trust", w.trust),
            ("reputation", w.reputation),
        )
    ]
    return f"{candidate.entry.display_name}: score={candidate.score:.3f} [{' '.join(parts)}]"


def summarise(candidates: Sequence[Candidate]) -> Mapping[str, Any]:
    eligible = [c for c in candidates if c.eligible]
    return {
        "considered": len(candidates),
        "eligible": len(eligible),
        "top": eligible[0].entry.identifier if eligible else None,
        "rejected": {
            c.entry.identifier: c.rejected_reason
            for c in candidates
            if not c.eligible and c.rejected_reason
        },
    }
