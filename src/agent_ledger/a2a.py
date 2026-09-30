"""A2A execution — the transport seam, filled in.

ARD finds an agent. This module talks to it. Nothing here decides *whether* work
should be delegated — policy does that — and nothing here invents a new protocol:
it speaks A2A as the specification defines it, and hands the result back to the
grid to be receipted.

**Why this module is the interesting half of the project.** A2A's task lifecycle
is richer than "worked / did not work". A remote task can be interrupted waiting
for a human, or waiting for a credential, and those are not failures — they are
states this library has no equivalent for, because a *delegation* is either
outstanding or settled. Bridging the two is not plumbing; it is the part that has
to be got right, and it is why the remote state is preserved verbatim on the
receipt rather than collapsed into a boolean.

The mapping, stated once and tested exhaustively:

===============================================  =================  ==========
A2A ``TaskState``                                receipt outcome    ``ok``
===============================================  =================  ==========
``TASK_STATE_SUBMITTED``                         ``accepted``       ``True``
``TASK_STATE_WORKING``                           ``accepted``       ``True``
``TASK_STATE_COMPLETED``                         ``completed``      ``True``
``TASK_STATE_FAILED``                            ``failed``         ``False``
``TASK_STATE_CANCELED``                          ``failed``         ``False``
``TASK_STATE_REJECTED``                          ``failed``         ``False``
``TASK_STATE_INPUT_REQUIRED``                    ``accepted``       ``True``
``TASK_STATE_AUTH_REQUIRED``                     ``accepted``       ``True``
``TASK_STATE_UNSPECIFIED`` / unknown             ``failed``         ``False``
===============================================  =================  ==========

The two interrupted states map to ``accepted`` with ``ok=True`` deliberately.
Reporting ``ok=False`` for a task that is waiting for input would be a lie that
costs the delegate reputation for a question the *principal* has not answered,
and it would release a budget commitment that is genuinely still outstanding.
``ExecutionResult.terminal`` is what distinguishes "finished" from "still going",
and it is what the grid uses to decide whether to settle the delegation.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ._identity import USER_AGENT
from .models import (
    DelegationStatus,
    ExecutionRecord,
    Task,
    canonical_json,
    new_id,
)

__all__ = [
    "A2AClient",
    "A2AError",
    "A2AExecution",
    "A2AExecutor",
    "AgentCard",
    "BINDING_SUPPORT",
    "BearerCredential",
    "Credential",
    "GetTaskResult",
    "JsonRpcTransport",
    "SendMessageResult",
    "StaticCredential",
    "StreamingTransport",
    "TASK_STATE_MEANING",
    "TERMINAL_STATES",
    "UnsupportedBindingError",
    "UrllibJsonRpcTransport",
    "map_task_state",
    "require_supported_binding",
]

#: A2A v1.0 task lifecycle (verbatim from the protocol definition). Kept as
#: strings because that is what arrives on the wire, and a lower-cased or
#: prettified copy would make a mismatch with the remote hard to see.
TASK_STATE_UNSPECIFIED = "TASK_STATE_UNSPECIFIED"
TASK_STATE_SUBMITTED = "TASK_STATE_SUBMITTED"
TASK_STATE_WORKING = "TASK_STATE_WORKING"
TASK_STATE_COMPLETED = "TASK_STATE_COMPLETED"
TASK_STATE_FAILED = "TASK_STATE_FAILED"
TASK_STATE_CANCELED = "TASK_STATE_CANCELED"
TASK_STATE_INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
TASK_STATE_REJECTED = "TASK_STATE_REJECTED"
TASK_STATE_AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED"

#: What each remote state means for the delegation it belongs to.
#: ``(receipt outcome, ok, terminal)``.
_STATE_TABLE: dict[str, tuple[DelegationStatus, bool, bool]] = {
    TASK_STATE_SUBMITTED: (DelegationStatus.ACCEPTED, True, False),
    TASK_STATE_WORKING: (DelegationStatus.ACCEPTED, True, False),
    TASK_STATE_COMPLETED: (DelegationStatus.COMPLETED, True, True),
    TASK_STATE_FAILED: (DelegationStatus.FAILED, False, True),
    TASK_STATE_CANCELED: (DelegationStatus.FAILED, False, True),
    TASK_STATE_REJECTED: (DelegationStatus.FAILED, False, True),
    TASK_STATE_INPUT_REQUIRED: (DelegationStatus.ACCEPTED, True, False),
    TASK_STATE_AUTH_REQUIRED: (DelegationStatus.ACCEPTED, True, False),
    TASK_STATE_UNSPECIFIED: (DelegationStatus.FAILED, False, True),
}

#: One-line explanations, for CLI output and for the error message an unknown
#: state produces. A raw enum string tells an operator nothing.
TASK_STATE_MEANING: Mapping[str, str] = {
    TASK_STATE_SUBMITTED: "submitted and acknowledged",
    TASK_STATE_WORKING: "actively being processed",
    TASK_STATE_COMPLETED: "finished successfully",
    TASK_STATE_FAILED: "finished with an error",
    TASK_STATE_CANCELED: "canceled before completion",
    TASK_STATE_REJECTED: "the agent declined to perform it",
    TASK_STATE_INPUT_REQUIRED: "waiting for input from the principal",
    TASK_STATE_AUTH_REQUIRED: "waiting for a credential",
    TASK_STATE_UNSPECIFIED: "an unknown or indeterminate state",
}

#: States from which a task will not move again.
TERMINAL_STATES = frozenset(
    {TASK_STATE_COMPLETED, TASK_STATE_FAILED, TASK_STATE_CANCELED, TASK_STATE_REJECTED}
)

#: States where the agent is blocked on something the principal must supply.
INTERRUPTED_STATES = frozenset({TASK_STATE_INPUT_REQUIRED, TASK_STATE_AUTH_REQUIRED})

#: A2A v1.0 uses PascalCase JSON-RPC method names. v0.3 used lowercase
#: ``message/send``; a server on either is worth talking to, so the binding tries
#: the current name and falls back once, remembering which worked.
_METHOD_SEND = "SendMessage"
_METHOD_GET_TASK = "GetTask"
_METHOD_CANCEL = "CancelTask"
_METHOD_SEND_STREAM = "SendStreamingMessage"
_METHOD_EXTENDED_CARD = "GetExtendedAgentCard"
_LEGACY_METHOD_SEND = "message/send"
_LEGACY_METHOD_GET_TASK = "tasks/get"
_LEGACY_METHOD_CANCEL = "tasks/cancel"


def _error_text(error: Any) -> str:
    if isinstance(error, Mapping):
        return f"{error.get('code')} {error.get('message') or ''}".strip()
    return repr(error)


def _parts_text_joined(parts: Any) -> str:
    return "\n".join(chunk for chunk in _parts_text(parts) if chunk)


class A2AError(RuntimeError):
    """An A2A peer was reachable but the exchange did not succeed."""


def map_task_state(state: str | None) -> tuple[DelegationStatus, bool, bool]:
    """Translate an A2A task state into ``(outcome, ok, terminal)``.

    Unknown states are treated as failure rather than success. That is the safe
    direction: a state this library does not recognise might mean anything, and
    silently reporting ``ok=True`` for it would let work that never happened be
    receipted as done.
    """
    if state is None:
        return _STATE_TABLE[TASK_STATE_UNSPECIFIED]
    return _STATE_TABLE.get(state, (DelegationStatus.FAILED, False, True))


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #


class Credential(Protocol):
    """Something that can authorise a request to a remote agent.

    ARD §3.6 delegates authentication to the artifact protocol, so credentials
    are the executor's business, not the discovery layer's. This protocol exists
    so the receipt can record *which* credential was used without the core
    library ever handling a secret.
    """

    #: A stable, non-secret identifier. This is what reaches the receipt.
    @property
    def reference(self) -> str: ...

    def headers(self) -> Mapping[str, str]: ...


@dataclass(frozen=True, slots=True)
class StaticCredential:
    """A fixed header, plus a non-secret reference to record on the receipt.

    The reference is required and explicit because the receipt must never carry
    the secret, and "we forgot to give it a name" is exactly how a token ends up
    in an audit log.
    """

    reference: str
    header: str
    value: str

    def headers(self) -> Mapping[str, str]:
        return {self.header: self.value}


def BearerCredential(token: str, *, reference: str) -> StaticCredential:
    """An OAuth/JWT bearer token. ``reference`` must not be the token."""
    return StaticCredential(reference=reference, header="Authorization", value=f"Bearer {token}")


# --------------------------------------------------------------------------- #
# JSON-RPC binding
# --------------------------------------------------------------------------- #


class JsonRpcTransport(Protocol):
    """The narrow seam between this module and the network.

    Same shape as ARD's ``Transport``, and for the same reason: it is what lets
    the whole A2A surface be tested, including its error handling and its state
    mapping, with no sockets at all.
    """

    def post_json(
        self, url: str, payload: Mapping[str, Any], *, timeout: float = 30.0
    ) -> Mapping[str, Any]: ...


@runtime_checkable
class StreamingTransport(Protocol):
    """A transport that can also deliver a server-sent event stream.

    Separate from :class:`JsonRpcTransport` rather than a method added to it,
    because a transport that cannot stream should not have to implement a method
    that only raises — and a caller should be able to ask, with ``isinstance`` or
    ``hasattr``, whether streaming is available before offering it. A protocol
    every implementation must pretend to satisfy is not a seam, it is a stub.
    """

    def post_json(
        self, url: str, payload: Mapping[str, Any], *, timeout: float = 30.0
    ) -> Mapping[str, Any]: ...

    def post_sse(
        self, url: str, payload: Mapping[str, Any], *, timeout: float = 30.0
    ) -> Iterator[Mapping[str, Any]]:
        """Yield one decoded JSON object per SSE ``data:`` frame."""
        ...


class UrllibJsonRpcTransport:
    """Standard-library JSON-RPC over HTTP, including SSE. No runtime deps."""

    def __init__(self, headers: Mapping[str, str] | None = None) -> None:
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            **(headers or {}),
        }

    def _open(self, url: str, payload: Mapping[str, Any], timeout: float, accept: str):
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={**self.headers, "Accept": accept},
            method="POST",
        )
        try:
            return urllib.request.urlopen(request, timeout=timeout)  # noqa: S310
        except urllib.error.HTTPError as exc:
            raise A2AError(f"HTTP {exc.code} from {url}") from exc
        except urllib.error.URLError as exc:
            raise A2AError(f"cannot reach {url}: {exc.reason}") from exc
        except TimeoutError as exc:  # pragma: no cover - platform dependent
            raise A2AError(f"timeout contacting {url}") from exc

    def post_json(
        self, url: str, payload: Mapping[str, Any], *, timeout: float = 30.0
    ) -> Mapping[str, Any]:
        with self._open(url, payload, timeout, "application/json") as response:
            body = response.read().decode("utf-8")
        try:
            document = json.loads(body)
        except json.JSONDecodeError as exc:
            raise A2AError(f"{url} did not return JSON") from exc
        if not isinstance(document, Mapping):
            raise A2AError(f"{url} returned a non-object JSON-RPC response")
        return document

    def post_sse(
        self, url: str, payload: Mapping[str, Any], *, timeout: float = 30.0
    ) -> Iterator[Mapping[str, Any]]:
        """Consume an ``text/event-stream`` response, yielding decoded frames.

        Deliberately minimal, because SSE used well is minimal: a frame is a run
        of ``field: value`` lines ending in a blank line, and only ``data``
        carries payload. ``id`` and ``event`` are accepted and ignored — A2A
        puts everything that matters in the data object, and inventing meaning
        for fields the specification does not use here would be guesswork.

        Comment lines (``: keep-alive``) are skipped rather than treated as
        malformed: they are how servers keep a long-lived connection open, and
        failing on them would break streaming against well-behaved peers.
        """
        with self._open(url, payload, timeout, "text/event-stream") as response:
            chunk: list[str] = []
            for raw_line in response:
                line = raw_line.decode("utf-8").rstrip("\r\n")
                if line.startswith(":"):
                    continue
                if line == "":
                    if chunk:
                        joined = "\n".join(chunk)
                        chunk = []
                        try:
                            decoded = json.loads(joined)
                        except json.JSONDecodeError:
                            # A frame that is not JSON is reported, not silently
                            # skipped: it means the peer is not speaking the
                            # protocol, and continuing would produce a stream
                            # that looks empty rather than broken.
                            raise A2AError(
                                f"{url} sent an SSE frame that is not JSON: {joined[:120]!r}"
                            ) from None
                        if isinstance(decoded, Mapping):
                            yield decoded
                    continue
                if line.startswith("data:"):
                    chunk.append(line[len("data:") :].lstrip())
                # `event:`, `id:`, `retry:` carry no payload we use.


@dataclass(frozen=True, slots=True)
class SendMessageResult:
    """Outcome of a ``SendMessage`` call, whether it returned a task or a message."""

    task: Mapping[str, Any] | None = None
    message: Mapping[str, Any] | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def task_id(self) -> str | None:
        if self.task is None:
            return None
        value = self.task.get("id")
        return str(value) if value else None

    @property
    def context_id(self) -> str | None:
        if self.task is None:
            return None
        value = self.task.get("contextId")
        return str(value) if value else None

    @property
    def state(self) -> str | None:
        return _task_state(self.task)

    @property
    def text(self) -> str:
        """Best-effort text from the task's artifacts, else the returned message.

        ``_streamed_text`` is checked first because a stream may deliver artifacts
        the final Task object does not repeat — the reduced stream carries the
        concatenation, and ignoring it would silently drop every artifact that
        arrived in its own frame.
        """
        if self.task is not None:
            streamed = self.task.get("_streamed_text")
            if isinstance(streamed, str) and streamed:
                return streamed
            text = _artifacts_text(self.task)
            if text:
                return text
        return _message_text(self.message)


@dataclass(frozen=True, slots=True)
class GetTaskResult:
    """Outcome of a ``GetTask`` call."""

    task: Mapping[str, Any]
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def task_id(self) -> str | None:
        value = self.task.get("id")
        return str(value) if value else None

    @property
    def state(self) -> str | None:
        return _task_state(self.task)

    @property
    def text(self) -> str:
        return _artifacts_text(self.task)


def _task_state(task: Mapping[str, Any] | None) -> str | None:
    if not isinstance(task, Mapping):
        return None
    status = task.get("status")
    if not isinstance(status, Mapping):
        return None
    state = status.get("state")
    return str(state) if state else None


def _artifacts_text(task: Mapping[str, Any]) -> str:
    """Concatenate text parts across a task's artifacts."""
    chunks: list[str] = []
    artifacts = task.get("artifacts")
    if isinstance(artifacts, Sequence):
        for artifact in artifacts:
            if isinstance(artifact, Mapping):
                chunks.extend(_parts_text(artifact.get("parts")))
    return "\n".join(chunk for chunk in chunks if chunk)


def _message_text(message: Mapping[str, Any] | None) -> str:
    if not isinstance(message, Mapping):
        return ""
    return "\n".join(chunk for chunk in _parts_text(message.get("parts")) if chunk)


def _parts_text(parts: Any) -> list[str]:
    """Text out of A2A ``Part`` values, ignoring non-text parts.

    A part is a union — text, raw bytes, a url, or structured data. Only the text
    case has a string to contribute; the others are summarised rather than
    dropped, so an artifact that is entirely a file still leaves a trace in the
    receipt's result digest.
    """
    out: list[str] = []
    if not isinstance(parts, Sequence) or isinstance(parts, (str, bytes)):
        return out
    for part in parts:
        if not isinstance(part, Mapping):
            continue
        if isinstance(part.get("text"), str):
            out.append(part["text"])
        elif "data" in part:
            out.append(canonical_json(part["data"]))
        elif isinstance(part.get("url"), str):
            out.append(f"[file {part['url']}]")
        elif isinstance(part.get("raw"), str):
            out.append(f"[binary, {len(part['raw'])} base64 chars]")
    return out


# --------------------------------------------------------------------------- #
# Agent Card
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AgentCard:
    """The parts of an A2A Agent Card this library has an opinion about.

    Fetched before invoking anything, because an ARD entry's ``url`` is a claim
    about where an artifact lives and an Agent Card is evidence about how to
    speak to it. Everything else in the card is preserved in ``raw`` and not
    interpreted — a client that rejects a card for carrying fields it does not
    recognise is a client that breaks on every version bump.
    """

    name: str = ""
    description: str = ""
    url: str | None = None
    protocol_binding: str | None = None
    protocol_version: str | None = None
    capabilities: Mapping[str, Any] = field(default_factory=dict)
    skills: tuple[Mapping[str, Any], ...] = ()
    security_schemes: Mapping[str, Any] = field(default_factory=dict)
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def supports_streaming(self) -> bool:
        return bool(self.capabilities.get("streaming"))

    @property
    def requires_auth(self) -> bool:
        """True when the card declares any security requirement.

        Used to produce a *useful* failure: "this agent requires a credential and
        none is configured" beats an HTTP 401 arriving three layers down.
        """
        return bool(self.security_schemes) or bool(self.raw.get("securityRequirements"))

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> AgentCard:
        interfaces = raw.get("supportedInterfaces")
        first: Mapping[str, Any] = {}
        if isinstance(interfaces, Sequence) and interfaces:
            candidate = interfaces[0]
            if isinstance(candidate, Mapping):
                first = candidate
        skills = raw.get("skills")
        return cls(
            name=str(raw.get("name") or ""),
            description=str(raw.get("description") or ""),
            url=first.get("url") or raw.get("url"),
            protocol_binding=first.get("protocolBinding"),
            protocol_version=first.get("protocolVersion"),
            capabilities=raw.get("capabilities") or {},
            skills=tuple(s for s in skills if isinstance(s, Mapping))
            if isinstance(skills, Sequence)
            else (),
            security_schemes=raw.get("securitySchemes") or {},
            raw=raw,
        )


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class A2AClient:
    """Speaks A2A to one endpoint. Holds no policy and makes no decisions."""

    def __init__(
        self,
        transport: JsonRpcTransport | None = None,
        *,
        credential: Credential | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.transport = transport if transport is not None else UrllibJsonRpcTransport()
        self.credential = credential
        self.timeout = timeout
        #: Which method-naming convention the peer accepted. Learned once so a
        #: v0.3 server costs one extra round trip, not one per call.
        self._send_method = _METHOD_SEND
        self._get_method = _METHOD_GET_TASK

    # -- low level ----------------------------------------------------------- #

    def _rpc(self, url: str, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        payload = {"jsonrpc": "2.0", "id": new_id("rpc"), "method": method, "params": dict(params)}
        document = self.transport.post_json(url, payload, timeout=self.timeout)
        error = document.get("error")
        if error is not None:
            if isinstance(error, Mapping):
                raise A2AError(
                    f"{method} failed: {error.get('code')} {error.get('message') or ''}".strip()
                )
            raise A2AError(f"{method} failed: {error!r}")
        result = document.get("result")
        if not isinstance(result, Mapping):
            raise A2AError(f"{method} returned no result object")
        return result

    def _rpc_with_fallback(
        self, url: str, method: str, legacy: str, params: Mapping[str, Any], label: str
    ) -> Mapping[str, Any]:
        """Try the current method name, then the v0.3 one.

        Only a *method-not-found* style failure justifies the retry. Retrying
        after a genuine application error would send the work twice, which for a
        `SendMessage` means the agent does it twice.
        """
        try:
            return self._rpc(url, method, params)
        except A2AError as exc:
            if not _is_unknown_method(exc):
                raise
            result = self._rpc(url, legacy, params)
            if method == _METHOD_SEND:
                self._send_method = legacy
            else:
                self._get_method = legacy
            return result

    # -- operations ---------------------------------------------------------- #

    def fetch_agent_card(self, base_url: str) -> AgentCard:
        """Fetch ``/.well-known/agent-card.json`` relative to *base_url*.

        The well-known path is the registered, version-independent location. A
        JSON-RPC call without this is guesswork about which protocol version and
        binding the peer speaks.
        """
        root = base_url.rstrip("/")
        # A card lives at the *domain* root, not under the RPC path: an endpoint
        # of https://host/a2a/v1 publishes at https://host/.well-known/...
        parts = root.split("/", 3)
        origin = "/".join(parts[:3]) if len(parts) >= 3 else root
        url = f"{origin}/.well-known/agent-card.json"
        document = self._get_json(url)
        return AgentCard.from_json(document)

    def _get_json(self, url: str) -> Mapping[str, Any]:
        """GET JSON through the transport.

        A JSON-RPC transport only posts, so this uses urllib directly. Kept
        separate and small because it is the one operation the injectable
        transport cannot fake — and `fetch_agent_card` is therefore tested
        against a real local HTTP server rather than a stub.
        """
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise A2AError(f"HTTP {exc.code} fetching agent card from {url}") from exc
        except urllib.error.URLError as exc:
            raise A2AError(f"cannot reach {url}: {exc.reason}") from exc
        try:
            document = json.loads(body)
        except json.JSONDecodeError as exc:
            raise A2AError(f"agent card at {url} is not JSON") from exc
        if not isinstance(document, Mapping):
            raise A2AError(f"agent card at {url} is not a JSON object")
        return document

    def send_message(
        self,
        url: str,
        text: str,
        *,
        context_id: str | None = None,
        task_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        return_immediately: bool = True,
    ) -> SendMessageResult:
        """``SendMessage`` — hand a task to the agent.

        ``return_immediately`` defaults to **True**: by the specification the
        default is to *block* until the task reaches a terminal or interrupted
        state, which for a long-running agent means holding a socket open for
        minutes. A delegating grid wants the task id back so it can record the
        delegation and poll, rather than stalling inside a single call.

        ``messageId`` is generated per call. It is the idempotency key: reusing
        one for a retry is how a caller avoids the work being done twice, so it
        is deliberately not derived from the intent.
        """
        message: dict[str, Any] = {
            "messageId": new_id("msg"),
            "role": "ROLE_USER",
            "parts": [{"text": text}],
        }
        if context_id:
            message["contextId"] = context_id
        if task_id:
            message["taskId"] = task_id
        if metadata:
            message["metadata"] = dict(metadata)

        params: dict[str, Any] = {
            "message": message,
            "configuration": {"returnImmediately": return_immediately},
        }
        result = self._rpc_with_fallback(
            url, self._send_method, _LEGACY_METHOD_SEND, params, "send"
        )

        task = result.get("task")
        reply = result.get("message")
        return SendMessageResult(
            task=task if isinstance(task, Mapping) else None,
            message=reply if isinstance(reply, Mapping) else None,
            raw=result,
        )

    def get_task(
        self, url: str, task_id: str, *, history_length: int | None = None
    ) -> GetTaskResult:
        """``GetTask`` — the latest state of work already handed over."""
        params: dict[str, Any] = {"id": task_id}
        if history_length is not None:
            params["historyLength"] = history_length
        result = self._rpc_with_fallback(
            url, self._get_method, _LEGACY_METHOD_GET_TASK, params, "get_task"
        )
        return GetTaskResult(task=result, raw=result)

    def cancel_task(self, url: str, task_id: str) -> GetTaskResult:
        """``CancelTask`` — ask the agent to stop.

        Returns the task as it now stands rather than a bare success, because a
        cancellation is a *request*: the agent may already have finished, and the
        returned state is the only honest answer to "did it stop". A caller that
        treats this returning as proof of cancellation is reading a hope as a
        fact.
        """
        params: dict[str, Any] = {"id": task_id}
        result = self._rpc_with_fallback(
            url, _METHOD_CANCEL, _LEGACY_METHOD_CANCEL, params, "cancel_task"
        )
        return GetTaskResult(task=result, raw=result)

    @property
    def can_stream(self) -> bool:
        """Whether the configured transport can deliver an SSE stream.

        Asked rather than assumed, so a caller can offer streaming only where it
        works instead of discovering the limitation mid-delegation.
        """
        return hasattr(self.transport, "post_sse")

    def send_streaming_message(
        self,
        url: str,
        text: str,
        *,
        context_id: str | None = None,
        task_id: str | None = None,
        return_immediately: bool = True,
    ) -> SendMessageResult:
        """``SendStreamingMessage`` — fold an SSE stream down to its final state.

        This library is not a UI, so it has no use for intermediate frames: it
        needs the *terminal* state to receipt and the accumulated artifact text
        to hash. So the stream is consumed to completion and reduced to the same
        shape ``SendMessage`` returns.

        Deliberately not a generator. A generator would push the burden of
        knowing when the stream ended onto every caller, and the one caller that
        matters here — a delegation that must be receipted exactly once — would
        get it wrong the same way every time. A caller that does want individual
        frames can use the transport's ``post_sse`` directly.
        """
        if not self.can_stream:
            raise A2AError(
                "this transport cannot stream; use UrllibJsonRpcTransport, or any "
                "transport that implements post_sse"
            )

        message: dict[str, Any] = {
            "messageId": new_id("msg"),
            "role": "ROLE_USER",
            "parts": [{"text": text}],
        }
        if context_id:
            message["contextId"] = context_id
        if task_id:
            message["taskId"] = task_id
        payload = {
            "jsonrpc": "2.0",
            "id": new_id("rpc"),
            "method": _METHOD_SEND_STREAM,
            "params": {
                "message": message,
                "configuration": {"returnImmediately": return_immediately},
            },
        }

        task: Mapping[str, Any] | None = None
        reply: Mapping[str, Any] | None = None
        texts: list[str] = []

        for frame in self.transport.post_sse(url, payload, timeout=self.timeout):  # type: ignore[attr-defined]
            error = frame.get("error")
            if error is not None:
                raise A2AError(f"SendStreamingMessage failed: {_error_text(error)}")
            body = frame.get("result")
            if not isinstance(body, Mapping):
                continue
            # A frame carries one of four shapes. The last full Task seen wins,
            # because each is a more complete view of the same object; artifact
            # and status updates are merged into whatever we have so far.
            if isinstance(body.get("task"), Mapping):
                task = body["task"]
                texts.append(_artifacts_text(task))
            elif isinstance(body.get("artifactUpdate"), Mapping):
                artifact = body["artifactUpdate"].get("artifact")
                if isinstance(artifact, Mapping):
                    texts.append(_parts_text_joined(artifact.get("parts")))
            elif isinstance(body.get("statusUpdate"), Mapping):
                update = body["statusUpdate"]
                if task is None:
                    task = {"id": update.get("taskId"), "contextId": update.get("contextId")}
                status = update.get("status")
                if isinstance(status, Mapping):
                    task = {**task, "status": status}
            elif isinstance(body.get("message"), Mapping):
                reply = body["message"]
                texts.append(_message_text(reply))

        if task is not None and any(texts):
            task = {**task, "_streamed_text": "\n".join(t for t in texts if t)}
        return SendMessageResult(task=task, message=reply, raw={"streamed": True})

    def fetch_extended_agent_card(self, url: str) -> AgentCard:
        """``GetExtendedAgentCard`` — the authenticated view of a card.

        Some agents publish a deliberately reduced public card and a fuller one
        to authenticated callers. Worth having because invoking an agent whose
        real skills appear only in the extended card is otherwise guesswork.
        """
        return AgentCard.from_json(self._rpc(url, _METHOD_EXTENDED_CARD, {}))


def _is_unknown_method(exc: A2AError) -> bool:
    """Whether a JSON-RPC error means "no such method" rather than "it failed".

    -32601 is Method Not Found. -32602 (Invalid Params) is included because an
    older server that does know the method but not a newer parameter should be
    retried on the legacy name rather than abandoned — the retry either works or
    fails the same way, and it costs one call.
    """
    text = str(exc)
    return "-32601" in text or "-32602" in text or "not found" in text.lower()


#: Bindings the A2A card may declare, and whether this executor speaks them.
#: Recorded explicitly so that asking for one that is not implemented produces a
#: named failure rather than a request sent in the wrong protocol — which would
#: look like a broken peer rather than a missing client.
BINDING_SUPPORT: Mapping[str, bool] = {
    "JSONRPC": True,
    "GRPC": False,
    "HTTP+JSON": False,
}


class UnsupportedBindingError(A2AError):
    """The peer offers a binding this library does not implement."""


def require_supported_binding(card: AgentCard) -> str:
    """Return the binding to use for *card*, or explain what is missing.

    Called before invoking anything, because the alternative is discovering the
    gap halfway through a delegation. A card with no usable interface is a real
    configuration: an agent may publish gRPC only, and the honest answer is to
    say which binding is missing rather than to fail with a parse error.
    """
    declared = card.protocol_binding
    if declared is None:
        return "JSONRPC"  # no declaration: JSON-RPC is the mandated floor
    if BINDING_SUPPORT.get(declared):
        return declared
    if not BINDING_SUPPORT.get(declared, False):
        supported = ", ".join(sorted(b for b, ok in BINDING_SUPPORT.items() if ok))
        raise UnsupportedBindingError(
            f"the agent declares the {declared!r} binding, which this library does "
            f"not implement; it speaks {supported}. "
            + (
                "Streaming, push notifications and CancelTask are available over "
                "JSON-RPC; a gRPC or REST peer needs a different client."
                if declared in ("GRPC", "HTTP+JSON")
                else "Unknown binding."
            )
        )
    return declared


# --------------------------------------------------------------------------- #
# The executor
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class A2AExecution:
    """What one A2A round trip produced, before the grid receipts it.

    Carries the raw remote identifiers, because ``message/send`` returning a
    *message* rather than a *task* is a legitimate answer — a stateless agent
    replies directly — and losing that distinction is how a client ends up
    inventing a task id that the remote has never heard of.
    """

    record: ExecutionRecord
    output: Any = None
    note: str = ""
    ok: bool = True
    terminal: bool = True


class A2AExecutor:
    """Drives a delegate over A2A and reports what happened.

    Satisfies the grid's ``Executor`` protocol, so it drops into
    ``Grid(executor=A2AExecutor())`` and needs no change to policy, matching or
    the ledger.

    It is deliberately conservative about what it claims:

    * It does **not** poll unless the remote leaves the task unfinished. A
      synchronous agent returns ``TASK_STATE_COMPLETED`` on the first call and
      there is nothing to poll.
    * It **does** record the remote state verbatim, because a state this library
      does not model is still evidence.
    * It reports ``ok=True`` for interrupted states. Work waiting on the
      principal is not a failure of the delegate — see the module docstring.
    """

    def __init__(
        self,
        client: A2AClient | None = None,
        *,
        credential: Credential | None = None,
        #: Poll budget. ``None`` means "never poll": take whatever the first
        #: response said, which is right for a synchronous agent and wrong for a
        #: long-running one, so it is explicit rather than a magic number.
        max_polls: int | None = None,
        poll_interval: float = 0.0,
        sleep: Callable[[float], None] | None = None,
        credential_ref: str | None = None,
        #: Use ``SendStreamingMessage`` when the transport supports it. Off by
        #: default because it is a different negotiation with the peer, not a
        #: strictly better one: a request/response agent that never sends a
        #: terminal frame would hang a stream where a plain call would return.
        prefer_streaming: bool = False,
    ) -> None:
        self.client = client if client is not None else A2AClient(credential=credential)
        self.credential = credential
        self.max_polls = max_polls
        self.poll_interval = poll_interval
        self._sleep = sleep
        self._credential_ref = credential_ref
        self.prefer_streaming = prefer_streaming

    @property
    def transport_binding(self) -> str:
        """Which A2A binding this executor actually speaks.

        The A2A card declares ``JSONRPC``, ``GRPC`` or ``HTTP+JSON``. This
        executor implements JSON-RPC only, and the *name* of the binding is
        recorded on every receipt — so a receipt cannot quietly claim a binding
        that was never used.
        """
        return "JSONRPC"

    @property
    def credential_reference(self) -> str | None:
        """What to record on the receipt as the credential used.

        Read from the executor's own configuration, never from the remote's
        response: a record of "which credential did we present" that the callee
        supplies is not evidence about the caller.
        """
        if self._credential_ref is not None:
            return self._credential_ref
        return self.credential.reference if self.credential is not None else None

    def execute(self, task: Task, entry: Any) -> Any:
        """Run one delegation. Returns the grid's ``ExecutionResult``.

        Imported lazily to avoid a circular import: ``router`` imports this
        module's types only for documentation, and this module needs
        ``ExecutionResult`` at call time. The dependency direction is
        ``router -> a2a``, never the reverse.
        """
        from .router import ExecutionResult

        binding = self.transport_binding

        if not entry.url:
            return ExecutionResult(
                ok=False,
                note=f"no A2A endpoint for {entry.identifier}: the entry carries no url",
                execution=ExecutionRecord(
                    binding=binding, credential_ref=self.credential_reference
                ),
            )

        try:
            sent = self._send(entry.url, task)
        except A2AError as exc:
            return ExecutionResult(
                ok=False,
                note=f"A2A send failed: {exc}",
                execution=ExecutionRecord(
                    binding=binding, credential_ref=self.credential_reference
                ),
            )

        state = sent.state
        state = self._poll_if_unfinished(entry.url, sent, state)
        _, ok, _ = map_task_state(state)

        return ExecutionResult(
            ok=ok,
            cost_usd=0.0,  # A2A has no cost field; the caller supplies its own.
            output=sent.text or None,
            note=self._note(state, sent),
            execution=ExecutionRecord(
                task_ref=sent.task_id,
                state=state,
                credential_ref=self.credential_reference,
                binding=binding,
            ),
        )

    def _send(self, url: str, task: Task) -> SendMessageResult:
        """Send by whichever binding this executor was configured to prefer.

        Streaming is asked for only when both the caller wants it and the
        transport can do it, so asking for it cannot turn into a runtime failure
        for a caller who merely left a flag on.
        """
        if self.prefer_streaming and self.client.can_stream:
            return self.client.send_streaming_message(url, task.intent)
        return self.client.send_message(url, task.intent)

    def cancel(self, url: str, task_id: str) -> GetTaskResult:
        """Ask the remote to stop, and return the state it reports afterwards.

        Exposed rather than folded into ``execute``, because cancelling is a
        *decision the principal makes*, not something an executor should do on
        its own initiative when a delegation goes badly. The caller revokes the
        delegation locally and asks the agent to stop here — the two are separate
        acts, and collapsing them would let a policy change silently cancel
        remote work.
        """
        return self.client.cancel_task(url, task_id)

    def _poll_if_unfinished(
        self, url: str, sent: SendMessageResult, state: str | None
    ) -> str | None:
        """Poll ``GetTask`` while the remote says the work is still moving.

        Only polled when there is a task to poll *and* a budget to poll with. An
        interrupted task is never polled: it is waiting on the principal, and no
        amount of asking the agent again will change that.
        """
        if self.max_polls is None or sent.task_id is None:
            return state
        if state in TERMINAL_STATES or state in INTERRUPTED_STATES:
            return state

        task_id = sent.task_id
        for _ in range(self.max_polls):
            if self._sleep is not None and self.poll_interval:
                self._sleep(self.poll_interval)
            try:
                polled = self.client.get_task(url, task_id)
            except A2AError as exc:
                # A failed poll is not a failed task. Report the last state we
                # actually saw rather than inventing a terminal one.
                raise A2AError(f"lost contact while polling {task_id}: {exc}") from exc
            state = polled.state
            if state in TERMINAL_STATES or state in INTERRUPTED_STATES:
                return state
        return state

    def _note(self, state: str | None, sent: SendMessageResult) -> str:
        if state is None:
            # No task came back: the agent answered directly and statelessly.
            return "A2A: agent replied without creating a task"
        meaning = TASK_STATE_MEANING.get(state, "an unrecognised state")
        prefix = f"A2A: {state} — {meaning}"
        if state is None or sent.task_id is None:
            return prefix
        return f"{prefix} (task {sent.task_id})"
