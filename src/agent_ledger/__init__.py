"""agent-ledger — accountable delegation for AI agents.

ARD finds agents. A2A talks to them. Neither answers the question that matters
once work starts moving on its own: *who authorised this, within what limits,
and who is answerable for the result?*

This package owns that layer. It implements ARD for discovery rather than
reinventing it, then adds the parts ARD explicitly declines to define — task
publication, capability matching, delegated authority, budget enforcement,
receipts, and a verifiable chain of custody.

Quick start::

    from agent_ledger import Grid, Task

    grid = Grid(registries=["https://registry.example/api/v1/search"])
    outcome = grid.dispatch(
        Task(intent="review the vendor DPA", required_capabilities=["contract_review"])
    )
    print(outcome.delegation.delegate.display_name)

Or from a terminal::

    al demo
"""

from __future__ import annotations

from ._identity import REPO_URL, USER_AGENT
from ._identity import VERSION as __version__
from .a2a import (
    A2AClient,
    A2AError,
    A2AExecutor,
    AgentCard,
    BearerCredential,
    Credential,
    StaticCredential,
    UrllibJsonRpcTransport,
    map_task_state,
)
from .adapters import ADAPTERS, Adapter, AdapterResult, adapt
from .ard import ArdClient, ArdError, HttpTransport, SearchResult, StaticTransport
from .bundle import (
    Bundle,
    BundleVerification,
    bundle_receipts,
    export_bundle,
    read_bundle,
    verify_bundle,
    write_bundle,
)
from .conform import (
    ConformanceReport,
    Finding,
    check_manifest,
    check_registry,
    resolve_publisher,
)
from .ledger import (
    JsonlBackend,
    Ledger,
    LedgerBackend,
    LedgerIntegrity,
    LedgerStats,
    MemoryBackend,
    RawLine,
    SqliteBackend,
)
from .matcher import (
    MatchWeights,
    ReputationIndex,
    lexical_similarity,
    rank_candidates,
)
from .models import (
    ARD_URN_PREFIX,
    TYPE_A2A_AGENT_CARD,
    TYPE_AI_REGISTRY,
    TYPE_AI_SKILL,
    TYPE_MCP_SERVER_CARD,
    ArdEntry,
    Candidate,
    Delegation,
    DelegationChain,
    DelegationStatus,
    DigestError,
    ExecutionRecord,
    PolicyDecision,
    PolicyOutcome,
    Receipt,
    Task,
    canonical_json,
    content_digest,
    parse_ard_urn,
)
from .otlp import chain_to_trace, ledger_to_otlp, otlp_payload, post_otlp, to_span, to_spans
from .policy import DEFAULT_POLICY, Policy, RuleContext
from .router import (
    CallableExecutor,
    DelegationOutcome,
    ExecutionResult,
    Executor,
    Grid,
    GridConfig,
)
from .signing import (
    ALG_ED25519,
    ALG_HMAC_SHA256,
    Ed25519Signer,
    HmacSigner,
    KeyRing,
    SignatureCheck,
    signing_payload,
)

__all__ = [
    "REPO_URL",
    "USER_AGENT",
    "A2AClient",
    "A2AError",
    "A2AExecutor",
    "ADAPTERS",
    "ALG_ED25519",
    "ALG_HMAC_SHA256",
    "ARD_URN_PREFIX",
    "Adapter",
    "AdapterResult",
    "AgentCard",
    "ArdClient",
    "ArdEntry",
    "ArdError",
    "BearerCredential",
    "Bundle",
    "BundleVerification",
    "CallableExecutor",
    "Candidate",
    "ConformanceReport",
    "Credential",
    "DEFAULT_POLICY",
    "Delegation",
    "DelegationChain",
    "DelegationOutcome",
    "DelegationStatus",
    "DigestError",
    "Ed25519Signer",
    "ExecutionRecord",
    "ExecutionResult",
    "Executor",
    "Finding",
    "Grid",
    "GridConfig",
    "HmacSigner",
    "HttpTransport",
    "JsonlBackend",
    "KeyRing",
    "Ledger",
    "LedgerBackend",
    "LedgerIntegrity",
    "LedgerStats",
    "MatchWeights",
    "MemoryBackend",
    "Policy",
    "PolicyDecision",
    "PolicyOutcome",
    "RawLine",
    "Receipt",
    "ReputationIndex",
    "RuleContext",
    "SearchResult",
    "SignatureCheck",
    "SqliteBackend",
    "StaticCredential",
    "StaticTransport",
    "TYPE_A2A_AGENT_CARD",
    "TYPE_AI_REGISTRY",
    "TYPE_AI_SKILL",
    "TYPE_MCP_SERVER_CARD",
    "Task",
    "UrllibJsonRpcTransport",
    "__version__",
    "canonical_json",
    "chain_to_trace",
    "check_manifest",
    "check_registry",
    "content_digest",
    "bundle_receipts",
    "export_bundle",
    "ledger_to_otlp",
    "lexical_similarity",
    "map_task_state",
    "otlp_payload",
    "parse_ard_urn",
    "post_otlp",
    "rank_candidates",
    "read_bundle",
    "resolve_publisher",
    "signing_payload",
    "to_span",
    "to_spans",
    "verify_bundle",
    "write_bundle",
    "adapt",
]
