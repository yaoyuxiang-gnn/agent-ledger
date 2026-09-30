"""ARD client: static discovery, dynamic search, federation, binding checks."""

from __future__ import annotations

import pytest

from agent_ledger.ard import (
    PREDECESSOR_PATH,
    WELL_KNOWN_PATH,
    ArdClient,
    ArdError,
    HttpTransport,
    StaticTransport,
)

from .conftest import INTERNAL_REGISTRY, PARTNER_REGISTRY

DOMAIN = "northwind.internal"
MANIFEST_URL = f"https://{DOMAIN}{WELL_KNOWN_PATH}"
PREDECESSOR_URL = f"https://{DOMAIN}{PREDECESSOR_PATH}"


class TestStaticDiscovery:
    def test_resolves_well_known_manifest(self, client: ArdClient) -> None:
        entries = client.fetch_manifest(DOMAIN)
        assert entries
        assert all(entry.is_valid for entry in entries)
        assert all(entry.source == MANIFEST_URL for entry in entries)

    def test_explicit_url_is_used_verbatim(self, client: ArdClient) -> None:
        entries = client.fetch_manifest(MANIFEST_URL)
        assert len(entries) == 4

    def test_falls_back_to_predecessor_path(self) -> None:
        """ARD 5.1: the old ``ai-catalog.json`` path is a courtesy read."""
        transport = StaticTransport()
        transport.add(PREDECESSOR_URL, {"entries": []})
        client = ArdClient(transport)
        assert client.fetch_manifest(DOMAIN) == []
        assert ("GET", PREDECESSOR_URL) in transport.calls

    def test_missing_domain_raises(self, client: ArdClient) -> None:
        with pytest.raises(ArdError):
            client.fetch_manifest("nowhere.invalid")

    def test_malformed_manifest_raises(self) -> None:
        transport = StaticTransport({MANIFEST_URL: "not-an-object"})
        with pytest.raises(ArdError):
            ArdClient(transport).fetch_manifest(DOMAIN)

    def test_invalid_entries_are_dropped_silently(self) -> None:
        transport = StaticTransport(
            {
                MANIFEST_URL: {
                    "entries": [
                        {
                            "identifier": "urn:air:a.com:b:c",
                            "displayName": "ok",
                            "type": "t",
                            "url": "https://x",
                        },
                        {"displayName": "missing identifier"},
                        {
                            "identifier": "urn:air:a.com:b:d",
                            "displayName": "no target",
                            "type": "t",
                        },
                    ]
                }
            }
        )
        entries = ArdClient(transport).fetch_manifest(DOMAIN)
        assert len(entries) == 1


class TestPublisherBinding:
    """ARD 4.5.1 — a URN publisher must match the claimed trust identity."""

    def _transport(self, identity: str) -> StaticTransport:
        return StaticTransport(
            {
                MANIFEST_URL: {
                    "entries": [
                        {
                            "identifier": "urn:air:acme.com:agent:x",
                            "displayName": "X",
                            "type": "t",
                            "url": "https://x",
                            "trustManifest": {"identity": identity},
                        }
                    ]
                }
            }
        )

    def test_matching_identity_is_accepted(self) -> None:
        client = ArdClient(self._transport("spiffe://acme.com/agents/x"))
        assert len(client.fetch_manifest(DOMAIN)) == 1

    def test_squatted_identity_is_rejected(self) -> None:
        client = ArdClient(self._transport("spiffe://attacker.example/x"))
        assert client.fetch_manifest(DOMAIN) == []

    def test_check_can_be_disabled(self) -> None:
        client = ArdClient(
            self._transport("spiffe://attacker.example/x"), verify_publisher_binding=False
        )
        assert len(client.fetch_manifest(DOMAIN)) == 1

    def test_absent_identity_is_not_a_squat(self) -> None:
        client = ArdClient(self._transport(""))
        assert len(client.fetch_manifest(DOMAIN)) == 1


class TestSearch:
    def test_search_returns_scored_entries(self, client: ArdClient) -> None:
        result = client.search(INTERNAL_REGISTRY, "review a contract")
        assert len(result) > 0
        assert all(entry.registry_score is not None for entry in result.entries)

    def test_empty_text_is_refused(self, client: ArdClient) -> None:
        with pytest.raises(ArdError):
            client.search(INTERNAL_REGISTRY, "")

    def test_capability_filter_narrows_results(self, client: ArdClient) -> None:
        everything = client.search(INTERNAL_REGISTRY, "work")
        filtered = client.search(
            INTERNAL_REGISTRY, "work", filter={"capabilities": ["translation"]}
        )
        assert len(filtered) <= len(everything)
        assert all("translation" in entry.capability_set for entry in filtered.entries)

    def test_page_size_is_clamped_to_spec_maximum(self) -> None:
        seen: dict[str, object] = {}

        def handler(payload: dict) -> dict:
            seen.update(payload)
            return {"results": []}

        transport = StaticTransport({INTERNAL_REGISTRY: handler})
        ArdClient(transport).search(INTERNAL_REGISTRY, "x", page_size=5000)
        assert seen["pageSize"] == 100

    def test_referrals_are_returned_not_followed(self, client: ArdClient) -> None:
        result = client.search(INTERNAL_REGISTRY, "contract")
        assert result.referrals, "the internal registry advertises a referral"

    def test_non_object_response_raises(self) -> None:
        transport = StaticTransport({INTERNAL_REGISTRY: ["nope"]})
        with pytest.raises(ArdError):
            ArdClient(transport).search(INTERNAL_REGISTRY, "x")

    def test_unreachable_registry_raises(self) -> None:
        with pytest.raises(ArdError):
            ArdClient(StaticTransport()).search("https://gone.invalid/search", "x")


class TestFederation:
    def test_follows_referrals_and_merges(self, client: ArdClient) -> None:
        merged = client.federated_search([INTERNAL_REGISTRY], "translation")
        sources = {entry.source for entry in merged.entries}
        assert INTERNAL_REGISTRY in sources
        assert PARTNER_REGISTRY in sources

    def test_referrals_can_be_ignored(self, client: ArdClient) -> None:
        merged = client.federated_search([INTERNAL_REGISTRY], "translation", follow_referrals=False)
        assert {entry.source for entry in merged.entries} == {INTERNAL_REGISTRY}

    def test_registry_cap_is_enforced(self, client: ArdClient) -> None:
        merged = client.federated_search([INTERNAL_REGISTRY], "x", max_registries=1)
        assert {entry.source for entry in merged.entries} == {INTERNAL_REGISTRY}

    def test_one_dead_registry_does_not_sink_the_query(self, client: ArdClient) -> None:
        merged = client.federated_search(["https://gone.invalid/s", INTERNAL_REGISTRY], "contract")
        assert merged.entries

    def test_referral_loops_terminate(self) -> None:
        """A registry that refers to itself must not spin forever."""
        transport = StaticTransport()
        transport.add(
            "https://loop.invalid/s",
            {
                "results": [],
                "referrals": [{"url": "https://loop.invalid/s"}],
            },
        )
        result = ArdClient(transport).federated_search(["https://loop.invalid/s"], "x")
        assert result.entries == []


class TestLeanSearchResults:
    """Responses shaped the way ARD §5.3.2 actually permits.

    This class exists because of a real bug. The suite's registry fixture gives
    every result a ``url`` and full discovery terms — a *complete* ARD entry. The
    specification says the opposite is normal:

        "In a response, an entry MUST carry ``identifier``; every other term is
        at the registry's discretion... A result is therefore not necessarily a
        complete ARD entry; its ``identifier`` names the authoritative one."

    Because the fixture was more cooperative than the wire, ``search()`` raised
    ``AttributeError`` on **every** real registry response and 176 green tests
    did not notice. These cases are deliberately unhelpful: the point is to make
    the fixture as lean as the specification allows.
    """

    LEAN = {
        "results": [
            # Minimum the specification permits: identifier only, plus what a
            # registry returns to help selection (displayName, type, score).
            {
                "identifier": "urn:air:google.com:agents:translator",
                "displayName": "Translator",
                "type": "application/a2a-agent-card+json",
                "score": 92.5,
            },
            # `representativeQueries` is normally omitted: they serve indexing,
            # not presentation.
            {
                "identifier": "urn:air:acme.com:legal:review",
                "displayName": "Legal Review",
                "type": "application/a2a-agent-card+json",
                "capabilities": ["contract_review"],
                "score": 88,
            },
        ],
        "referrals": [],
    }

    def _client(self) -> ArdClient:
        return ArdClient(StaticTransport({INTERNAL_REGISTRY: self.LEAN}))

    def test_a_result_without_a_url_is_returned_not_raised(self) -> None:
        result = self._client().search(INTERNAL_REGISTRY, "translate a contract")
        assert len(result.entries) == 2
        assert [e.identifier for e in result.entries] == [
            "urn:air:google.com:agents:translator",
            "urn:air:acme.com:legal:review",
        ]

    def test_a_result_without_a_url_keeps_a_score(self) -> None:
        result = self._client().search(INTERNAL_REGISTRY, "x")
        assert result.entries[0].registry_score == 92.5

    def test_a_result_without_a_url_does_not_get_a_fabricated_target(self) -> None:
        """Keeping the entry must not mean inventing a target for it."""
        entry = self._client().search(INTERNAL_REGISTRY, "x").entries[0]
        assert entry.url is None
        assert entry.data is None
        assert entry.has_target is False

    def test_lean_result_is_searchable_but_not_a_complete_entry(self) -> None:
        """The two predicates answer different questions on purpose."""
        entry = self._client().search(INTERNAL_REGISTRY, "x").entries[0]
        assert entry.is_searchable, "it is a legitimate answer to a search"
        assert not entry.is_valid, "it is not a complete ARD entry"

    def test_a_result_with_no_identifier_is_dropped(self) -> None:
        """ARD §5.3.2: identifier is the one term a result MUST carry."""
        transport = StaticTransport(
            {INTERNAL_REGISTRY: {"results": [{"displayName": "Nameless", "type": "t"}]}}
        )
        assert ArdClient(transport).search(INTERNAL_REGISTRY, "x").entries == []

    def test_federated_search_survives_lean_results(self) -> None:
        merged = self._client().federated_search([INTERNAL_REGISTRY], "contract")
        assert len(merged.entries) == 2

    def test_discover_survives_lean_results(self) -> None:
        entries = self._client().discover(registries=[INTERNAL_REGISTRY], text="contract")
        assert len(entries) == 2


class TestDiscover:
    def test_combines_static_and_dynamic(self, client: ArdClient) -> None:
        entries = client.discover(
            domains=[DOMAIN], registries=[INTERNAL_REGISTRY], text="contract review"
        )
        assert entries
        identifiers = [e.identifier for e in entries]
        assert len(identifiers) == len(set(identifiers)), "results are deduplicated"

    def test_works_with_no_sources(self, client: ArdClient) -> None:
        assert client.discover(text="anything") == []

    def test_registry_entries_filter(self, client: ArdClient) -> None:
        entries = client.fetch_manifest(DOMAIN)
        assert ArdClient.registry_entries(entries) == []


class TestHttpTransport:
    def test_instantiating_needs_no_network(self) -> None:
        transport = HttpTransport()
        assert "User-Agent" in transport.headers
