"""OpenTelemetry export — receipts as spans, without the SDK.

The observation that makes this small: a receipt already carries everything a
span needs. It has a start time, a name, a status, and a bag of attributes. What
it also has, and a generic tracing setup does not, is ``parent_receipt_id`` —
which is exactly the parent-child relation a trace needs. So a delegation chain
*is* a trace, and no instrumentation is required to produce it; the ledger
already recorded one.

**No dependency, and that is not a compromise.** OTLP's JSON encoding is a
documented, stable shape, and emitting it directly keeps the zero-dependency
promise intact while remaining compatible with any collector that accepts
``application/json``. A caller who already runs the OpenTelemetry SDK can take
:func:`to_spans` and feed it to their own exporter instead; both paths are one
function call apart.

The honest limit: this emits OTLP **JSON**, not protobuf, and it does not speak
gRPC. A collector configured for protobuf-only ingestion needs a bridge. Saying
so here is better than letting someone discover it from a 415 response.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from ._identity import USER_AGENT
from .ledger import Ledger
from .models import DelegationChain, DelegationStatus, Receipt

__all__ = [
    "ATTR_PREFIX",
    "SPAN_KIND_INTERNAL",
    "STATUS_ERROR",
    "STATUS_OK",
    "STATUS_UNSET",
    "chain_to_trace",
    "otlp_payload",
    "post_otlp",
    "to_span",
    "to_spans",
]

#: Every attribute this module emits is namespaced, so a collector can route or
#: drop the whole set with one rule and nothing collides with a user's own keys.
ATTR_PREFIX = "agent.ledger"

#: OTLP status codes. ``STATUS_ERROR`` is for a delegation that *failed*, not for
#: one that was refused — a refusal is a recorded decision, and marking it an
#: error would paint a policy working correctly as a system fault. Refusals get
#: ``STATUS_OK`` plus a ``policy.outcome`` attribute, which is where a reader
#: looks for it anyway.
STATUS_UNSET = 0
STATUS_OK = 1
STATUS_ERROR = 2

#: An agent call is an internal span: it is work this system performed, not an
#: inbound request or an outbound client call in the tracing sense.
SPAN_KIND_INTERNAL = 1

_TERMINAL = frozenset(
    {
        DelegationStatus.COMPLETED,
        DelegationStatus.FAILED,
        DelegationStatus.REVOKED,
        DelegationStatus.EXPIRED,
    }
)


def _attr(key: str, value: Any) -> dict[str, Any]:
    """One OTLP attribute, with the type tag OTLP's JSON encoding requires.

    OTLP refuses an untagged scalar, and getting the tag wrong is the most common
    way a hand-rolled exporter is silently rejected — so the tag is derived from
    the Python type here rather than written out at each call site.
    """
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    if isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


def to_span(receipt: Receipt, *, ledger_id: str | None = None) -> dict[str, Any]:
    """One receipt as an OTLP span.

    The span is named after the delegate, because "which agent did this" is the
    question a trace is being read to answer. The receipt id travels as an
    attribute rather than in the name, so an operator can group by delegate
    without the name becoming noise.
    """
    attributes: list[dict[str, Any]] = [
        _attr(f"{ATTR_PREFIX}.receipt_id", receipt.receipt_id),
        _attr(f"{ATTR_PREFIX}.delegation_id", receipt.delegation_id),
        _attr(f"{ATTR_PREFIX}.task_id", receipt.task_id),
        _attr(f"{ATTR_PREFIX}.delegate", receipt.delegate),
        _attr(f"{ATTR_PREFIX}.delegated_by", receipt.delegated_by),
        _attr(f"{ATTR_PREFIX}.outcome", receipt.outcome.value),
        _attr(f"{ATTR_PREFIX}.cost_usd", float(receipt.cost_usd)),
        _attr(f"{ATTR_PREFIX}.depth", int(receipt.depth)),
    ]
    if receipt.budget_usd is not None:
        attributes.append(_attr(f"{ATTR_PREFIX}.budget_usd", float(receipt.budget_usd)))
        attributes.append(_attr(f"{ATTR_PREFIX}.over_budget", bool(receipt.over_budget)))
    if receipt.parent_receipt_id is not None:
        attributes.append(_attr(f"{ATTR_PREFIX}.parent_receipt_id", receipt.parent_receipt_id))
    if receipt.result_digest is not None:
        attributes.append(_attr(f"{ATTR_PREFIX}.result_digest", receipt.result_digest))
    if receipt.scope_digest:
        attributes.append(_attr(f"{ATTR_PREFIX}.scope_digest", receipt.scope_digest))
    if receipt.note:
        attributes.append(_attr(f"{ATTR_PREFIX}.note", receipt.note))
    if ledger_id:
        attributes.append(_attr(f"{ATTR_PREFIX}.ledger_id", ledger_id))
    for key in ("signature", "key_id", "alg", "signer"):
        value = getattr(receipt, key)
        if value is not None:
            # Recorded because a trace that cannot say whether a receipt was
            # signed is a trace you cannot use to answer the question the
            # receipt exists for. The signature itself is included: it is public
            # evidence, not a secret.
            attributes.append(_attr(f"{ATTR_PREFIX}.{key}", value))
    if receipt.execution is not None:
        for key, value in receipt.execution.to_json().items():
            attributes.append(_attr(f"{ATTR_PREFIX}.execution.{key}", value))

    if receipt.outcome is DelegationStatus.FAILED:
        status = {"code": STATUS_ERROR, "message": receipt.note or "delegation failed"}
    elif receipt.outcome in _TERMINAL:
        status = {"code": STATUS_OK}
    else:
        # Pending or accepted: still running. UNSET, not OK — a span that claims
        # success before the work has landed is worse than one that says nothing.
        status = {"code": STATUS_UNSET}

    span: dict[str, Any] = {
        "traceId": _trace_id(receipt),
        "spanId": _line_span_id(receipt),
        "name": _short_name(receipt.delegate),
        "kind": SPAN_KIND_INTERNAL,
        # OTLP carries nanoseconds since the epoch as a string, because JSON
        # numbers cannot hold them precisely.
        "startTimeUnixNano": str(int(receipt.issued_at * 1_000_000_000)),
        "attributes": attributes,
        "status": status,
    }
    if receipt.parent_receipt_id is not None:
        # Parents are addressed by receipt id, which is stable across a parent's
        # own transitions. The *last* transition of a parent is the one a child
        # follows, and `to_spans` resolves which span that is.
        span["parentSpanId"] = _span_id(receipt.parent_receipt_id)
    return span


def _short_name(identifier: str) -> str:
    """The last URN segment — "legal-review", not the whole handle.

    A span name is read in a list beside dozens of others; the domain is the same
    for all of them and the terminal segment is the part that distinguishes.
    """
    return identifier.rsplit(":", 1)[-1] if ":" in identifier else identifier


def _span_id(receipt_id: str) -> str:
    """A deterministic 16-hex span id from a receipt id.

    Derived rather than random so that exporting the same ledger twice produces
    the same trace — a trace id that changed between runs would make two exports
    of one ledger look like two separate incidents.
    """
    import hashlib

    return hashlib.sha256(f"span:{receipt_id}".encode()).hexdigest()[:16]


def _line_span_id(receipt: Receipt) -> str:
    """A span id that distinguishes state transitions of one delegation.

    Keying by receipt id alone is wrong: a delegation keeps **one**
    ``receipt_id`` for its whole life, so exporting every transition would
    collapse three lines into one span and silently lose two. The digest differs
    per transition, so mixing it in keeps them distinct — and remains
    deterministic, which is what makes two exports of one ledger comparable.
    """
    import hashlib

    return hashlib.sha256(f"span:{receipt.receipt_id}:{receipt.digest()}".encode()).hexdigest()[:16]


def _trace_id(receipt: Receipt) -> str:
    """A trace id shared by every hop of one chain.

    Every receipt in a chain carries the same ``task_id`` — the task is what the
    principal asked for, and the hops are how it was carried out — so it is the
    honest trace identity. Using the receipt id instead would make every hop its
    own trace, which is precisely the thing this export exists to avoid.
    """
    import hashlib

    return hashlib.sha256(f"trace:{receipt.task_id}".encode()).hexdigest()[:32]


def to_spans(receipts: Iterable[Receipt], *, ledger_id: str | None = None) -> list[dict[str, Any]]:
    """Every receipt as a span, parents before children.

    One span per receipt *passed in*, including several transitions of one
    delegation — because silently collapsing them would make a full export look
    identical to a current-state one, and the caller asked for what they asked
    for. ``current_only`` on :func:`ledger_to_otlp` is how a caller opts out.

    A receipt whose parent is absent from *receipts* is still emitted: it is a
    real hop, and dropping it would make a partial export look like a complete
    one.

    ``parentSpanId`` is rewritten to point at the parent's **last** span. A
    receipt's ``parent_receipt_id`` names a delegation, which may have several
    transitions in the same export; a child follows the parent as it finished,
    so the last one is the honest target.
    """
    order = list(receipts)
    spans = [to_span(r, ledger_id=ledger_id) for r in order]

    # Map each delegation's receipt id to the position of its final transition.
    last_of: dict[str, int] = {}
    for position, receipt in enumerate(order):
        last_of[receipt.receipt_id] = position

    for position, receipt in enumerate(order):
        if receipt.parent_receipt_id is None:
            spans[position].pop("parentSpanId", None)
            continue
        target = last_of.get(receipt.parent_receipt_id)
        spans[position]["parentSpanId"] = (
            spans[target]["spanId"] if target is not None else _span_id(receipt.parent_receipt_id)
        )

    ordered: list[dict[str, Any]] = []
    emitted: set[int] = set()
    by_parent: dict[int | None, list[int]] = {}
    for position, receipt in enumerate(order):
        parent = last_of.get(receipt.parent_receipt_id or "")
        if parent == position:  # a self-parent would loop
            parent = None
        by_parent.setdefault(parent, []).append(position)

    queue = list(by_parent.get(None, []))
    while queue:
        position = queue.pop(0)
        if position in emitted:
            continue
        emitted.add(position)
        ordered.append(spans[position])
        queue.extend(by_parent.get(position, []))
    for position, span in enumerate(spans):
        if position not in emitted:
            ordered.append(span)
    return ordered


def chain_to_trace(chain: DelegationChain, *, ledger_id: str | None = None) -> list[dict[str, Any]]:
    """One delegation chain as one trace, root first."""
    return to_spans(chain.receipts, ledger_id=ledger_id)


def otlp_payload(
    receipts: Iterable[Receipt],
    *,
    service_name: str = "agent-ledger",
    ledger_id: str | None = None,
    scope_name: str = "agent_ledger",
    scope_version: str | None = None,
) -> dict[str, Any]:
    """A complete OTLP ``resourceSpans`` document, ready to POST."""
    from . import __version__

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        _attr("service.name", service_name),
                        _attr(f"{ATTR_PREFIX}.version", scope_version or __version__),
                        *([_attr(f"{ATTR_PREFIX}.ledger_id", ledger_id)] if ledger_id else []),
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": scope_name, "version": scope_version or __version__},
                        "spans": to_spans(receipts, ledger_id=ledger_id),
                    }
                ],
            }
        ]
    }


def ledger_to_otlp(
    ledger: Ledger,
    *,
    service_name: str = "agent-ledger",
    current_only: bool = True,
) -> dict[str, Any]:
    """Every delegation in *ledger* as an OTLP document.

    ``current_only`` defaults to True: the ledger keeps every state transition, so
    exporting all lines would emit three spans per delegation, two of which
    describe the same work at an earlier moment. A trace wants one span per hop.
    """
    receipts: Sequence[Receipt] = ledger.current() if current_only else ledger.lines
    return otlp_payload(
        receipts,
        service_name=service_name,
        ledger_id=getattr(ledger, "signing_identity", None),
    )


def post_otlp(
    payload: Mapping[str, Any],
    endpoint: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float = 15.0,
) -> bool:
    """POST an OTLP JSON document to a collector.

    Returns whether the collector accepted it rather than raising, because
    telemetry that can fail a delegation is worse than telemetry that is missing.
    A caller that wants to know should check the return value; a caller that does
    not should not have to wrap this in a try.

    Sends ``application/json``. A collector configured for protobuf only will
    answer 415, and this returns False — the limitation is documented at module
    level rather than hidden behind a retry.
    """
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            **(headers or {}),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return 200 <= response.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return False
