"""Adapters — other agent ecosystems, mapped onto ARD entries.

This module is honest about a limit that is worth stating first: these adapters
are **best-effort mappings onto declared shapes**, not exercised integrations.
AGNTCY, ClawTeam and OpenClaw each have their own evolving metadata format, and
none of their specifications is vendored here, so an adapter is a documented
translation with an explicit `confidence` — not a claim that traffic has been
exchanged with a live deployment. Where a mapping cannot be made honestly it
returns an entry marked ineligible rather than inventing the missing field.

The reason to ship them anyway is that the interesting cost is not the
translation, it is deciding *what an entry from another ecosystem has to carry to
be governed by this one*. Three things must survive any mapping:

1. **A domain-anchored identifier.** Policy's publisher rules and the ARD §4.5.1
   authority binding both key off the URN, so an adapter that cannot produce one
   produces an entry this grid will refuse. That is correct — an agent whose
   publisher cannot be named cannot be held to a publisher policy — and it is why
   :func:`to_ard_entry` reports what it could not find instead of guessing a
   domain.
2. **Capability tokens.** Matching is a filter on them; no tokens means no
   candidate. An adapter that silently drops them makes an agent invisible rather
   than misrouted, which is the better failure but still a failure.
3. **A target.** ``is_searchable`` and ``has_target`` are different questions, and
   an entry without a target can be ranked but not invoked.

Each adapter is a plain function plus a registry entry, so replacing a guessed
mapping with a verified one is a one-line change in one place.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .models import TYPE_A2A_AGENT_CARD, TYPE_MCP_SERVER_CARD, ArdEntry

__all__ = [
    "ADAPTERS",
    "Adapter",
    "AdapterResult",
    "adapt",
    "agntcy_to_ard",
    "clawteam_to_ard",
    "openclaw_to_ard",
    "to_ard_entry",
]

#: How much of a mapping was actually checkable.
#: ``declared`` means the source documents the field we mapped. ``inferred`` means
#: we found something plausible and said so. ``missing`` means the entry cannot be
#: governed without it.
CONFIDENCE_DECLARED = "declared"
CONFIDENCE_INFERRED = "inferred"


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """One mapped entry, plus what the mapping could not establish.

    ``problems`` is not decoration. An adapter that silently drops a field
    produces an agent that is invisible to matching, and an operator debugging
    "why was nothing selected" needs to see the adapter's own reasoning rather
    than infer it.
    """

    entry: ArdEntry | None
    confidence: str = CONFIDENCE_INFERRED
    problems: tuple[str, ...] = ()
    source: Mapping[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.entry is not None and self.entry.has_identifier


@dataclass(frozen=True, slots=True)
class Adapter:
    """A named mapping from another ecosystem's record to an ARD entry."""

    name: str
    #: One line on what this maps, and how much of it is verified.
    summary: str
    convert: Callable[[Mapping[str, Any]], AdapterResult]
    #: Field names this adapter looks for, for error messages.
    expects: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# Shared mapping helpers
# --------------------------------------------------------------------------- #


def _first(mapping: Mapping[str, Any], *keys: str) -> Any:
    """First present, non-empty value among *keys*.

    Adapters meet several spellings of the same field in the wild — ``name``,
    ``displayName``, ``display_name`` — and normalising here keeps each adapter's
    body about the mapping rather than about spelling.
    """
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable) and not isinstance(value, Mapping):
        out: list[str] = []
        for item in value:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, Mapping):
                # The common shape: `[{"name": "translate"}, ...]`, or a skill
                # object with an id. Take whichever identifier it offers.
                candidate = _first(item, "id", "name", "token", "capability")
                if isinstance(candidate, str):
                    out.append(candidate)
        return tuple(out)
    return ()


def _declared_identity(raw: Mapping[str, Any]) -> str | None:
    """The URN, if the source states one in the ARD form."""
    for key in ("identifier", "urn", "air", "agentId", "agent_id"):
        value = raw.get(key)
        if isinstance(value, str) and value.startswith("urn:air:"):
            return value
    return None


def _synthesised_identity(publisher: str | None, namespace: str, name: str) -> str | None:
    """Build a URN from parts, or refuse.

    Refuses without a publisher rather than inventing a domain. A fabricated
    domain would pass ARD's shape check and then defeat the §4.5.1 authority
    binding — an entry that *looks* governed and is not, which is worse than one
    this grid visibly rejects.
    """
    if not publisher or not name:
        return None
    return f"urn:air:{publisher}:{namespace}:{name}"


def to_ard_entry(
    raw: Mapping[str, Any],
    *,
    publisher: str | None = None,
    namespace: str = "agent",
    type_: str | None = None,
    source: str | None = None,
    url_keys: Sequence[str] = ("url", "endpoint", "address", "href"),
    capability_keys: Sequence[str] = ("capabilities", "skills", "tools", "functions"),
    query_keys: Sequence[str] = ("representativeQueries", "exampleQueries", "examples"),
) -> AdapterResult:
    """Map a foreign record onto an :class:`ArdEntry`, reporting what was missing.

    :func:`_first`-style tolerance is applied to *spelling*, never to *meaning*:
    the adapter will happily look for ``endpoint`` or ``url``, and will refuse
    just as happily to invent a publisher domain.
    """
    problems: list[str] = []

    name = _first(raw, "name", "displayName", "display_name", "title", "id")
    identifier = _declared_identity(raw)
    if identifier is None:
        stated_publisher = _first(raw, "publisher", "publisherId", "owner", "domain")
        identifier = _synthesised_identity(
            str(stated_publisher or publisher or "") or None,
            namespace,
            str(name or "").replace(" ", "-").lower(),
        )
        if identifier is None:
            problems.append(
                "no urn:air: identifier and no publisher domain: an agent whose "
                "publisher cannot be named cannot be held to a publisher policy, "
                "so it is not mapped rather than mapped with a guessed domain"
            )
        else:
            problems.append(
                "identifier synthesised from the publisher field; ARD §4.5.1 "
                "authority binding was not checked against a trustManifest"
            )

    url = _first(raw, *url_keys)
    capabilities = _as_tuple(_first(raw, *capability_keys))
    if not capabilities:
        problems.append(
            "no capability tokens: matching is a filter on them, so this entry "
            "will never be selected"
        )

    queries = _as_tuple(_first(raw, *query_keys))
    description = _first(raw, "description", "summary", "about")
    if not queries and description:
        # ARD expects representative queries for the semantic index. A description
        # is a poor substitute, and saying so is more useful than leaving the
        # field empty with no explanation.
        problems.append("no representative queries; the description is not indexed by ARD")

    if identifier is None:
        return AdapterResult(entry=None, problems=tuple(problems), source=raw)

    entry = ArdEntry.from_ard(
        {
            "identifier": identifier,
            "displayName": str(name or identifier.split(":")[-1]),
            "type": type_ or str(_first(raw, "type", "kind", "protocol") or TYPE_A2A_AGENT_CARD),
            "url": url if isinstance(url, str) else None,
            "description": description if isinstance(description, str) else None,
            "capabilities": list(capabilities),
            "representativeQueries": list(queries),
        },
        source=source,
    )
    confidence = CONFIDENCE_DECLARED if not problems else CONFIDENCE_INFERRED
    return AdapterResult(entry=entry, confidence=confidence, problems=tuple(problems), source=raw)


# --------------------------------------------------------------------------- #
# The adapters
# --------------------------------------------------------------------------- #
#
# Each of these documents *which* fields it maps and *how much of that is
# verified*. None of them has been exercised against a live deployment, and the
# `summary` says so — an adapter presented as a verified integration would be the
# first thing a reader checked and the first thing to embarrass the project.


def agntcy_to_ard(raw: Mapping[str, Any], *, publisher: str | None = None) -> AdapterResult:
    """Map an AGNTCY-style agent record.

    AGNTCY publishes agents as OASF records with ``name``, ``description``,
    ``skills`` and often an ``authors``/``locator`` pair. Mapped on declared
    field names; **not verified against a deployment.**
    """
    locator = _first(raw, "locator", "url", "endpoint")
    normalised = {
        **raw,
        "url": locator,
        # OASF carries skills as objects with `name`; `_as_tuple` handles that.
        "capabilities": _first(raw, "skills", "capabilities") or (),
    }
    result = to_ard_entry(
        normalised,
        publisher=publisher,
        namespace="agntcy",
        type_=TYPE_A2A_AGENT_CARD,
        source="agntcy",
    )
    return result


def clawteam_to_ard(raw: Mapping[str, Any], *, publisher: str | None = None) -> AdapterResult:
    """Map a ClawTeam-style agent record.

    ClawTeam records tend to carry ``agent_name``, ``team`` and a tool list.
    Mapped on declared field names; **not verified against a deployment.**
    """
    normalised = {
        **raw,
        "name": _first(raw, "agent_name", "name", "displayName"),
        "publisher": _first(raw, "team", "organisation", "organization", "publisher"),
        "capabilities": _first(raw, "tools", "capabilities", "skills") or (),
    }
    return to_ard_entry(
        normalised,
        publisher=publisher,
        namespace="clawteam",
        type_=TYPE_MCP_SERVER_CARD,
        source="clawteam",
    )


def openclaw_to_ard(raw: Mapping[str, Any], *, publisher: str | None = None) -> AdapterResult:
    """Map an OpenClaw-style channel record.

    OpenClaw exposes channels rather than agents, so a channel that can accept
    A2A traffic maps to the same entry shape. Mapped on declared field names;
    **not verified against a deployment.**
    """
    normalised = {
        **raw,
        "name": _first(raw, "channel", "name", "displayName"),
        "url": _first(raw, "webhook", "url", "endpoint", "address"),
        "capabilities": _first(raw, "commands", "capabilities", "tools") or (),
    }
    return to_ard_entry(
        normalised,
        publisher=publisher,
        namespace="openclaw",
        type_=TYPE_A2A_AGENT_CARD,
        source="openclaw",
    )


ADAPTERS: Mapping[str, Adapter] = {
    adapter.name: adapter
    for adapter in (
        Adapter(
            name="agntcy",
            summary=(
                "AGNTCY/OASF agent records. Maps name, description, skills and "
                "locator. Declared field names; NOT verified against a deployment."
            ),
            convert=agntcy_to_ard,
            expects=("name", "description", "skills", "locator"),
        ),
        Adapter(
            name="clawteam",
            summary=(
                "ClawTeam agent records. Maps agent_name, team, tools. Declared "
                "field names; NOT verified against a deployment."
            ),
            convert=clawteam_to_ard,
            expects=("agent_name", "team", "tools"),
        ),
        Adapter(
            name="openclaw",
            summary=(
                "OpenClaw channel records. Maps channel, webhook, commands. "
                "Declared field names; NOT verified against a deployment."
            ),
            convert=openclaw_to_ard,
            expects=("channel", "webhook", "commands"),
        ),
    )
}


def adapt(
    records: Iterable[Mapping[str, Any]],
    *,
    adapter: str,
    publisher: str | None = None,
    keep_unmappable: bool = False,
) -> list[AdapterResult]:
    """Run one adapter over a batch, dropping unmappable records by default.

    Dropping is the default because an entry with no identifier cannot be scored,
    policy-checked or invoked — carrying it forward would produce a candidate
    list full of entries that can never be selected. ``keep_unmappable`` exists
    for the case that actually needs it: showing an operator which records were
    rejected and why.
    """
    chosen = ADAPTERS.get(adapter)
    if chosen is None:
        known = ", ".join(sorted(ADAPTERS))
        raise KeyError(f"unknown adapter {adapter!r}; known adapters: {known}")

    results: list[AdapterResult] = []
    for record in records:
        try:
            result = chosen.convert(record, publisher=publisher)  # type: ignore[call-arg]
        except Exception as exc:  # noqa: BLE001 - a foreign record is data, not a crash
            result = AdapterResult(
                entry=None,
                problems=(f"{chosen.name} adapter raised {type(exc).__name__}: {exc}",),
                source=record,
            )
        if result.ok or keep_unmappable:
            results.append(result)
    return results
