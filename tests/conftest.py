"""Shared fixtures.

``src`` is placed on ``sys.path`` here so that ``pytest`` works on a fresh
clone with no install step. Contributors should not have to fight packaging
before they can run a test.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_ledger import ArdClient, Grid, Ledger, Policy, Task  # noqa: E402
from agent_ledger.ard import StaticTransport  # noqa: E402
from agent_ledger.demo import (  # noqa: E402
    INTERNAL_REGISTRY,
    PARTNER_REGISTRY,
    build_grid,
    build_transport,
)
from agent_ledger.models import ArdEntry  # noqa: E402


@pytest.fixture
def transport() -> StaticTransport:
    return build_transport()


@pytest.fixture
def client(transport: StaticTransport) -> ArdClient:
    return ArdClient(transport)


@pytest.fixture
def ledger() -> Ledger:
    return Ledger()


@pytest.fixture
def grid(ledger: Ledger, transport: StaticTransport) -> Grid:
    return build_grid(transport=transport, ledger=ledger)


@pytest.fixture
def simple_entry() -> ArdEntry:
    return ArdEntry.from_ard(
        {
            "identifier": "urn:air:acme.com:agent:translator",
            "displayName": "Translator",
            "type": "application/a2a-agent-card+json",
            "url": "https://acme.com/agents/translator.json",
            "capabilities": ["translation"],
            "representativeQueries": ["translate this document into German"],
            "trustManifest": {"identity": "spiffe://acme.com/agents/translator"},
        }
    )


@pytest.fixture
def simple_task() -> Task:
    return Task(
        intent="translate the landing page into German",
        required_capabilities=("translation",),
        issued_by="urn:principal:test:alice",
        budget_usd=1.0,
    )


@pytest.fixture
def open_grid(transport: StaticTransport) -> Grid:
    """A grid with no ceilings, for tests that are not about policy."""
    return Grid(
        client=ArdClient(transport),
        policy=Policy.open_grid(),
        ledger=Ledger(),
        registries=(INTERNAL_REGISTRY,),
    )


__all__ = ["INTERNAL_REGISTRY", "PARTNER_REGISTRY"]
