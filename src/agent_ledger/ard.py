"""ARD client — the discovery half of the grid, implemented, not reinvented.

The Agentic Resource Discovery specification already defines how agentic
resources are described, published and searched across federated registries.
Re-implementing that would be wasted effort and would forfeit interoperability
with every registry that adopts it.

So this module implements ARD and stops exactly where ARD stops:

* Static discovery  — ``/.well-known/ard.json`` (plus the predecessor path)
* Dynamic discovery — ``POST /search`` / ``POST /explore`` / ``GET /agents``
* Federation        — ``auto`` / ``referrals`` / ``none``

What it deliberately does *not* do is invoke anything. ARD §6 ends with
"the orchestrator now has both capabilities and can proceed to invoke them" —
the delegation layer picks up from that sentence.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from ._identity import USER_AGENT
from .models import (
    TYPE_AI_REGISTRY,
    ArdEntry,
    parse_ard_urn,
)

__all__ = [
    "ArdClient",
    "ArdError",
    "HttpTransport",
    "SearchResult",
    "StaticTransport",
    "Transport",
    "WELL_KNOWN_PATH",
    "PREDECESSOR_PATH",
]

#: ARD §5.1 — the normative well-known location for a domain's entries.
WELL_KNOWN_PATH = "/.well-known/ard.json"

#: ARD §5.1 — the predecessor path. Consumers MAY consult it; publishers
#: SHOULD migrate off it. We read it, and we say so when we do.
PREDECESSOR_PATH = "/.well-known/ai-catalog.json"

DEFAULT_TIMEOUT = 10.0
DEFAULT_PAGE_SIZE = 10


class ArdError(RuntimeError):
    """Raised when a discovery source is reachable but unusable."""


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #


class Transport(Protocol):
    """The narrow seam between the grid and the network.

    Everything the client does over the wire goes through here, which is why
    the whole test suite and the offline demo run with no sockets at all.
    """

    def get_json(self, url: str, *, timeout: float = DEFAULT_TIMEOUT) -> Any: ...

    def post_json(
        self, url: str, payload: Mapping[str, Any], *, timeout: float = DEFAULT_TIMEOUT
    ) -> Any: ...


class HttpTransport:
    """Standard-library HTTP transport. The package has no runtime deps."""

    def __init__(self, headers: Mapping[str, str] | None = None) -> None:
        self.headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            **(headers or {}),
        }

    def _request(self, request: urllib.request.Request, timeout: float) -> Any:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise ArdError(f"HTTP {exc.code} from {request.full_url}") from exc
        except urllib.error.URLError as exc:
            raise ArdError(f"cannot reach {request.full_url}: {exc.reason}") from exc
        except TimeoutError as exc:  # pragma: no cover - platform dependent
            raise ArdError(f"timeout contacting {request.full_url}") from exc
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise ArdError(f"{request.full_url} did not return JSON") from exc

    def get_json(self, url: str, *, timeout: float = DEFAULT_TIMEOUT) -> Any:
        request = urllib.request.Request(url, headers=dict(self.headers), method="GET")
        return self._request(request, timeout)

    def post_json(
        self, url: str, payload: Mapping[str, Any], *, timeout: float = DEFAULT_TIMEOUT
    ) -> Any:
        body = json.dumps(payload).encode("utf-8")
        headers = {**self.headers, "Content-Type": "application/json"}
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        return self._request(request, timeout)


class StaticTransport:
    """In-memory transport for tests, offline demos and air-gapped rehearsals.

    Keyed by URL. Registries are declared as ``{url: {"entries": [...]}}`` so a
    demo can present a realistic federated topology without a server.
    """

    def __init__(self, documents: Mapping[str, Any] | None = None) -> None:
        self.documents: dict[str, Any] = dict(documents or {})
        self.calls: list[tuple[str, str]] = []

    def add(self, url: str, document: Any) -> StaticTransport:
        self.documents[url] = document
        return self

    def get_json(self, url: str, *, timeout: float = DEFAULT_TIMEOUT) -> Any:
        self.calls.append(("GET", url))
        if url not in self.documents:
            raise ArdError(f"HTTP 404 from {url}")
        return self.documents[url]

    def post_json(
        self, url: str, payload: Mapping[str, Any], *, timeout: float = DEFAULT_TIMEOUT
    ) -> Any:
        self.calls.append(("POST", url))
        if url not in self.documents:
            raise ArdError(f"HTTP 404 from {url}")
        document = self.documents[url]
        if callable(document):
            return document(payload)
        return document


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class SearchResult:
    """What one registry answered, plus where referrals could lead next.

    ``referrals`` is retained rather than followed silently so the caller keeps
    control of federation topology (ARD §5.4).
    """

    entries: list[ArdEntry] = field(default_factory=list)
    referrals: list[dict[str, Any]] = field(default_factory=list)
    next_page_token: str | None = None
    registry: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    def __iter__(self):
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def extend(self, other: SearchResult) -> SearchResult:
        self.entries.extend(other.entries)
        self.referrals.extend(other.referrals)
        return self


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class ArdClient:
    """Discovery over ARD, with no opinion about what happens next."""

    def __init__(
        self,
        transport: Transport | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        verify_publisher_binding: bool = True,
    ) -> None:
        self.transport: Transport = transport or HttpTransport()
        self.timeout = timeout
        #: ARD §4.5.1 — reject entries whose trust identity does not match the
        #: publisher domain embedded in their URN. This is the spec's defence
        #: against namespace squatting, so it is on by default.
        self.verify_publisher_binding = verify_publisher_binding

    # -- static discovery ---------------------------------------------------- #

    def fetch_manifest(self, domain_or_url: str) -> list[ArdEntry]:
        """Resolve a domain's published entries (ARD §5.1).

        Tries the normative path first and falls back to the predecessor path,
        recording which one answered so the result is honest about its origin.
        """
        if "://" in domain_or_url:
            url = domain_or_url
        else:
            url = f"https://{domain_or_url.strip('/')}{WELL_KNOWN_PATH}"

        try:
            document = self.transport.get_json(url, timeout=self.timeout)
        except ArdError:
            if "://" in domain_or_url:
                raise
            fallback = f"https://{domain_or_url.strip('/')}{PREDECESSOR_PATH}"
            try:
                document = self.transport.get_json(fallback, timeout=self.timeout)
            except ArdError:
                raise ArdError(f"no ARD entries published at {domain_or_url}") from None
            url = fallback

        return self._entries_from_manifest(document, source=url)

    def _entries_from_manifest(self, document: Any, *, source: str) -> list[ArdEntry]:
        if isinstance(document, list):
            raw_entries: Sequence[Any] = document
        elif isinstance(document, Mapping):
            raw_entries = document.get("entries") or []
        else:
            raise ArdError(f"malformed ARD manifest from {source}")

        entries: list[ArdEntry] = []
        for raw in raw_entries:
            if not isinstance(raw, Mapping):
                continue
            entry = ArdEntry.from_ard(raw, source=source)
            if entry.is_valid and self._publisher_ok(entry):
                entries.append(entry)
        return entries

    def _publisher_ok(self, entry: ArdEntry) -> bool:
        """ARD §4.5.1 — bind URN publisher to the trust identity, when claimed."""
        if not self.verify_publisher_binding or not entry.trust_manifest:
            return True
        parsed = parse_ard_urn(entry.identifier)
        if parsed is None:
            return False
        identity = entry.trust_manifest.get("identity")
        if not identity:
            # No identity claim at all is not a squat — there is nothing to
            # bind. Only a *contradicting* claim is rejected.
            return True
        return parsed[0] in str(identity)

    # -- dynamic discovery --------------------------------------------------- #

    def search(
        self,
        registry_url: str,
        text: str,
        *,
        filter: Mapping[str, Any] | None = None,
        federation: str = "none",
        page_size: int = DEFAULT_PAGE_SIZE,
        context: Mapping[str, Any] | None = None,
    ) -> SearchResult:
        """``POST /search`` (ARD §5.3.2).

        ``text`` is required by the specification; ``score`` comes back as
        semantic relevance only and is explicitly *not* a trust signal, so it
        is carried through untouched and never used as one.
        """
        if not text:
            raise ArdError("ARD search requires non-empty text")

        query: dict[str, Any] = {"text": text}
        if context:
            query["@context"] = dict(context)
        if filter:
            query["filter"] = {k: (v if isinstance(v, list) else [v]) for k, v in filter.items()}

        payload = {
            "query": query,
            "federation": federation,
            "pageSize": max(1, min(int(page_size), 100)),
        }

        document = self.transport.post_json(registry_url, payload, timeout=self.timeout)
        if not isinstance(document, Mapping):
            raise ArdError(f"registry {registry_url} returned a non-object response")

        entries: list[ArdEntry] = []
        for raw in document.get("results") or []:
            if not isinstance(raw, Mapping):
                continue
            entry = ArdEntry.from_ard(raw, source=registry_url)
            # ARD §5.3.2: a result is *not necessarily a complete ARD entry* —
            # the registry returns what helps a caller select, and `url` may be
            # omitted entirely. `identifier` is authoritative, so such a result
            # is still worth keeping: it is discoverable, it simply has no
            # invocation target yet (see `ArdEntry.has_target`). Keeping it is
            # deliberate. Fabricating a target to satisfy `is_valid` would not
            # be.
            if entry.is_searchable and self._publisher_ok(entry):
                entries.append(entry)

        return SearchResult(
            entries=entries,
            referrals=list(document.get("referrals") or []),
            next_page_token=document.get("pageToken"),
            registry=registry_url,
            raw=document,
        )

    def federated_search(
        self,
        registry_urls: Sequence[str],
        text: str,
        *,
        filter: Mapping[str, Any] | None = None,
        max_registries: int = 8,
        follow_referrals: bool = True,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> SearchResult:
        """Query several registries and merge, following referrals breadth-first.

        ARD gives the client control of federation topology; this is the
        ``referrals`` strategy implemented explicitly, with a hard cap so a
        hostile or looping federation cannot make us chase our own tail.
        """
        merged = SearchResult()
        seen: set[str] = set()
        queue: list[str] = [u for u in registry_urls if u]

        while queue and len(seen) < max_registries:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                result = self.search(
                    url, text, filter=filter, page_size=page_size, federation="none"
                )
            except ArdError:
                # One unreachable registry must not sink a federated query.
                continue
            merged.extend(result)

            if follow_referrals:
                for referral in result.referrals:
                    if not isinstance(referral, Mapping):
                        continue
                    target = referral.get("url")
                    if target and target not in seen:
                        queue.append(str(target))

        return merged

    # -- convenience --------------------------------------------------------- #

    def discover(
        self,
        *,
        domains: Sequence[str] = (),
        registries: Sequence[str] = (),
        text: str,
        filter: Mapping[str, Any] | None = None,
    ) -> list[ArdEntry]:
        """One call covering both halves of ARD discovery.

        Static manifests from *domains* and dynamic search against
        *registries*, deduplicated by identifier with search results winning,
        because a registry result carries a relevance score.
        """
        by_identifier: dict[str, ArdEntry] = {}

        for domain in domains:
            try:
                for entry in self.fetch_manifest(domain):
                    by_identifier.setdefault(entry.identifier, entry)
            except ArdError:
                continue

        if registries:
            result = self.federated_search(registries, text, filter=filter)
            for entry in result.entries:
                by_identifier[entry.identifier] = entry

        return list(by_identifier.values())

    @staticmethod
    def registry_entries(entries: Iterable[ArdEntry]) -> list[ArdEntry]:
        """Filter a discovery result down to registries (ARD §5.3)."""
        return [e for e in entries if e.type == TYPE_AI_REGISTRY]
