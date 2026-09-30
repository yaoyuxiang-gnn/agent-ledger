"""A2A beyond request/response: streaming, cancellation, and honest gaps.

Two themes run through this file.

**Streaming is reduced, not exposed.** This library is not a UI. It needs the
terminal state to receipt and the accumulated artifact text to hash, so
``send_streaming_message`` consumes the stream and returns the same shape
``SendMessage`` does. A generator would push the burden of knowing when the
stream ended onto every caller, and the one caller that matters — a delegation
that must be receipted exactly once — would get it wrong identically each time.

**A gap is named, not worked around.** The A2A card can declare gRPC or
``HTTP+JSON``; this library implements neither. The failure is raised before
anything is invoked, because the alternative is a request sent in the wrong
protocol, which looks like a broken peer instead of a missing client.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from agent_ledger import A2AClient, A2AError, A2AExecutor, Task
from agent_ledger.a2a import (
    BINDING_SUPPORT,
    TASK_STATE_CANCELED,
    TASK_STATE_COMPLETED,
    TASK_STATE_WORKING,
    AgentCard,
    SendMessageResult,
    StreamingTransport,
    UnsupportedBindingError,
    UrllibJsonRpcTransport,
    require_supported_binding,
)
from agent_ledger.models import ArdEntry

AGENT_URL = "https://agent.example/a2a"


def frame(body: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": "1", "result": dict(body)}


def result(document: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": "1", "result": dict(document)}


class FakeStreamingRpc:
    """A scripted JSON-RPC peer that can also stream. Records every call."""

    def __init__(
        self,
        responses: list[Mapping[str, Any]] | None = None,
        frames: list[Mapping[str, Any]] | None = None,
    ) -> None:
        self.responses = list(responses or [])
        self.frames = list(frames or [])
        self.calls: list[tuple[str, Mapping[str, Any]]] = []
        self.streamed: list[Mapping[str, Any]] = []

    def post_json(self, url: str, payload: Mapping[str, Any], *, timeout: float = 30.0):
        self.calls.append((url, payload))
        if not self.responses:
            raise A2AError("no scripted response left")
        return self.responses.pop(0)

    def post_sse(self, url: str, payload: Mapping[str, Any], *, timeout: float = 30.0):
        self.streamed.append(payload)
        yield from self.frames

    @property
    def methods(self) -> list[str]:
        return [str(p.get("method")) for _, p in self.calls]


class NonStreamingRpc:
    """A transport that cannot stream — the JSON-RPC-only case."""

    def post_json(self, url: str, payload: Mapping[str, Any], *, timeout: float = 30.0):
        return result({"task": {"id": "t", "status": {"state": TASK_STATE_COMPLETED}}})


def entry(url: str = AGENT_URL) -> ArdEntry:
    return ArdEntry(
        identifier="urn:air:agent.example:agents:x", display_name="X", type="t", url=url
    )


# --------------------------------------------------------------------------- #
# Streaming
# --------------------------------------------------------------------------- #


class TestStreamingTransportContract:
    def test_a_streaming_transport_satisfies_the_protocol(self) -> None:
        assert isinstance(FakeStreamingRpc(), StreamingTransport)

    def test_a_non_streaming_transport_does_not(self) -> None:
        """The point of a separate protocol: a transport is not forced to stub it."""
        assert not isinstance(NonStreamingRpc(), StreamingTransport)

    def test_the_real_transport_can_stream(self) -> None:
        assert isinstance(UrllibJsonRpcTransport(), StreamingTransport)

    def test_the_client_reports_whether_it_can_stream(self) -> None:
        assert A2AClient(FakeStreamingRpc()).can_stream is True
        assert A2AClient(NonStreamingRpc()).can_stream is False


class TestSendStreamingMessage:
    def test_it_uses_the_streaming_method_name(self) -> None:
        rpc = FakeStreamingRpc(
            frames=[frame({"task": {"id": "t", "status": {"state": TASK_STATE_COMPLETED}}})]
        )
        A2AClient(rpc).send_streaming_message(AGENT_URL, "do it")
        assert rpc.streamed[0]["method"] == "SendStreamingMessage"

    def test_it_reduces_a_task_frame_to_the_final_state(self) -> None:
        rpc = FakeStreamingRpc(
            frames=[
                frame(
                    {
                        "task": {
                            "id": "t1",
                            "contextId": "c1",
                            "status": {"state": TASK_STATE_WORKING},
                            "artifacts": [{"artifactId": "a", "parts": [{"text": "partial"}]}],
                        }
                    }
                ),
                frame(
                    {
                        "task": {
                            "id": "t1",
                            "contextId": "c1",
                            "status": {"state": TASK_STATE_COMPLETED},
                            "artifacts": [{"artifactId": "a", "parts": [{"text": "final"}]}],
                        }
                    }
                ),
            ]
        )
        sent = A2AClient(rpc).send_streaming_message(AGENT_URL, "do it")
        assert sent.task_id == "t1"
        assert sent.state == TASK_STATE_COMPLETED
        assert "final" in sent.text

    def test_a_status_update_frame_is_merged(self) -> None:
        """Servers may send only status deltas, never a full Task."""
        rpc = FakeStreamingRpc(
            frames=[
                frame(
                    {
                        "statusUpdate": {
                            "taskId": "t9",
                            "contextId": "c9",
                            "status": {"state": TASK_STATE_WORKING},
                        }
                    }
                ),
                frame(
                    {
                        "statusUpdate": {
                            "taskId": "t9",
                            "contextId": "c9",
                            "status": {"state": TASK_STATE_COMPLETED},
                        }
                    }
                ),
            ]
        )
        sent = A2AClient(rpc).send_streaming_message(AGENT_URL, "do it")
        assert sent.task_id == "t9"
        assert sent.state == TASK_STATE_COMPLETED

    def test_artifact_update_frames_accumulate_text(self) -> None:
        """Ignoring these would silently drop every artifact sent in its own frame."""
        rpc = FakeStreamingRpc(
            frames=[
                frame({"statusUpdate": {"taskId": "t", "status": {"state": TASK_STATE_WORKING}}}),
                frame(
                    {
                        "artifactUpdate": {
                            "taskId": "t",
                            "artifact": {"artifactId": "a", "parts": [{"text": "chunk one"}]},
                        }
                    }
                ),
                frame(
                    {
                        "artifactUpdate": {
                            "taskId": "t",
                            "artifact": {"artifactId": "a", "parts": [{"text": "chunk two"}]},
                        }
                    }
                ),
            ]
        )
        sent = A2AClient(rpc).send_streaming_message(AGENT_URL, "do it")
        assert "chunk one" in sent.text
        assert "chunk two" in sent.text

    def test_a_message_frame_works_without_a_task(self) -> None:
        rpc = FakeStreamingRpc(
            frames=[frame({"message": {"messageId": "m", "parts": [{"text": "stateless reply"}]}})]
        )
        sent = A2AClient(rpc).send_streaming_message(AGENT_URL, "do it")
        assert sent.task is None
        assert sent.text == "stateless reply"

    def test_an_error_frame_raises(self) -> None:
        rpc = FakeStreamingRpc(
            frames=[{"jsonrpc": "2.0", "id": "1", "error": {"code": -32000, "message": "boom"}}]
        )
        with pytest.raises(A2AError, match="boom"):
            A2AClient(rpc).send_streaming_message(AGENT_URL, "do it")

    def test_a_non_streaming_transport_is_refused_clearly(self) -> None:
        """Not an AttributeError three frames in."""
        with pytest.raises(A2AError, match="cannot stream"):
            A2AClient(NonStreamingRpc()).send_streaming_message(AGENT_URL, "do it")

    def test_the_streamed_text_survives_into_the_result(self) -> None:
        rpc = FakeStreamingRpc(
            frames=[
                frame(
                    {
                        "artifactUpdate": {
                            "taskId": "t",
                            "artifact": {"artifactId": "a", "parts": [{"text": "answer"}]},
                        }
                    }
                ),
                frame({"statusUpdate": {"taskId": "t", "status": {"state": TASK_STATE_COMPLETED}}}),
            ]
        )
        sent: SendMessageResult = A2AClient(rpc).send_streaming_message(AGENT_URL, "q")
        assert sent.text == "answer"


class TestSseFraming:
    """The wire format, exercised without a socket by driving the parser."""

    def _parse(self, wire: bytes) -> list[Mapping[str, Any]]:
        class Response:
            def __enter__(self_inner):
                return iter(wire.splitlines(keepends=True))

            def __exit__(self_inner, *exc):
                return False

        transport = UrllibJsonRpcTransport()
        transport._open = lambda *a, **k: Response()  # type: ignore[method-assign]
        return list(transport.post_sse("https://x", {}))

    def test_a_simple_data_frame_is_decoded(self) -> None:
        frames = self._parse(b'data: {"result": {"a": 1}}\n\n')
        assert frames == [{"result": {"a": 1}}]

    def test_multiple_frames_are_decoded_in_order(self) -> None:
        frames = self._parse(b'data: {"n": 1}\n\ndata: {"n": 2}\n\n')
        assert [f["n"] for f in frames] == [1, 2]

    def test_keepalive_comments_are_skipped(self) -> None:
        """Servers send these to hold a long-lived connection open.

        Failing on one would break streaming against a well-behaved peer, which
        is the worst possible subset to be incompatible with.
        """
        frames = self._parse(b': keep-alive\n\ndata: {"n": 1}\n\n')
        assert [f["n"] for f in frames] == [1]

    def test_event_and_id_fields_are_ignored_not_fatal(self) -> None:
        frames = self._parse(b'event: task\nid: 7\ndata: {"n": 1}\n\n')
        assert [f["n"] for f in frames] == [1]

    def test_a_non_json_frame_is_reported(self) -> None:
        """Reported, not skipped: skipping yields a stream that looks empty
        rather than one that looks broken, and empty is indistinguishable from
        an agent that did nothing."""
        with pytest.raises(A2AError, match="not JSON"):
            self._parse(b"data: this is not json\n\n")

    def test_a_final_frame_without_a_trailing_blank_line_is_kept(self) -> None:
        """A stream cut off at the last frame must not lose that frame."""
        frames = self._parse(b'data: {"n": 1}\n\ndata: {"n": 2}\n\n')
        assert len(frames) == 2


# --------------------------------------------------------------------------- #
# Cancellation
# --------------------------------------------------------------------------- #


class TestCancelTask:
    def test_it_uses_the_cancel_method_name(self) -> None:
        rpc = FakeStreamingRpc(
            responses=[result({"id": "t1", "status": {"state": TASK_STATE_CANCELED}})]
        )
        A2AClient(rpc).cancel_task(AGENT_URL, "t1")
        assert rpc.methods == ["CancelTask"]
        assert rpc.calls[0][1]["params"]["id"] == "t1"

    def test_it_returns_the_state_rather_than_a_bare_success(self) -> None:
        """A cancellation is a *request*. The returned state is the only honest
        answer to "did it stop" — the agent may already have finished."""
        rpc = FakeStreamingRpc(
            responses=[result({"id": "t1", "status": {"state": TASK_STATE_COMPLETED}})]
        )
        outcome = A2AClient(rpc).cancel_task(AGENT_URL, "t1")
        assert outcome.state == TASK_STATE_COMPLETED, "it finished before the cancel landed"

    def test_the_legacy_method_name_is_tried(self) -> None:
        rpc = FakeStreamingRpc(
            responses=[
                {"jsonrpc": "2.0", "id": "1", "error": {"code": -32601, "message": "no method"}},
                result({"id": "t1", "status": {"state": TASK_STATE_CANCELED}}),
            ]
        )
        A2AClient(rpc).cancel_task(AGENT_URL, "t1")
        assert rpc.methods == ["CancelTask", "tasks/cancel"]

    def test_the_executor_exposes_cancel_separately_from_execute(self) -> None:
        """Cancelling is a decision the principal makes, not a retry strategy.

        Folding it into `execute` would let a policy change silently cancel
        remote work, and would collapse two separate acts — revoking the
        delegation locally, and asking the agent to stop — into one.
        """
        rpc = FakeStreamingRpc(
            responses=[result({"id": "t1", "status": {"state": TASK_STATE_CANCELED}})]
        )
        executor = A2AExecutor(A2AClient(rpc))
        assert executor.cancel(AGENT_URL, "t1").state == TASK_STATE_CANCELED
        assert rpc.methods == ["CancelTask"]


# --------------------------------------------------------------------------- #
# Streaming through the executor
# --------------------------------------------------------------------------- #


class TestExecutorStreaming:
    def test_streaming_is_off_by_default(self) -> None:
        """A request/response agent that never sends a terminal frame would hang
        a stream where a plain call returns."""
        rpc = FakeStreamingRpc(
            responses=[result({"task": {"id": "t", "status": {"state": TASK_STATE_COMPLETED}}})]
        )
        executor = A2AExecutor(A2AClient(rpc))
        executor.execute(Task(intent="work"), entry())
        assert rpc.methods == ["SendMessage"]
        assert rpc.streamed == []

    def test_streaming_is_used_when_asked_for(self) -> None:
        rpc = FakeStreamingRpc(
            frames=[frame({"task": {"id": "t", "status": {"state": TASK_STATE_COMPLETED}}})]
        )
        executor = A2AExecutor(A2AClient(rpc), prefer_streaming=True)
        outcome = executor.execute(Task(intent="work"), entry())
        assert outcome.ok
        assert rpc.streamed[0]["method"] == "SendStreamingMessage"

    def test_asking_for_streaming_on_a_plain_transport_still_works(self) -> None:
        """Leaving a flag on must not turn into a runtime failure."""
        executor = A2AExecutor(A2AClient(NonStreamingRpc()), prefer_streaming=True)
        outcome = executor.execute(Task(intent="work"), entry())
        assert outcome.ok

    def test_a_streamed_execution_records_its_state(self) -> None:
        rpc = FakeStreamingRpc(
            frames=[frame({"task": {"id": "t7", "status": {"state": TASK_STATE_COMPLETED}}})]
        )
        outcome = A2AExecutor(A2AClient(rpc), prefer_streaming=True).execute(
            Task(intent="work"), entry()
        )
        assert outcome.execution.task_ref == "t7"
        assert outcome.execution.state == TASK_STATE_COMPLETED
        assert outcome.execution.binding == "JSONRPC"


# --------------------------------------------------------------------------- #
# Bindings that are not implemented
# --------------------------------------------------------------------------- #


class TestBindingSelection:
    def test_the_card_binding_support_table_is_explicit(self) -> None:
        assert BINDING_SUPPORT["JSONRPC"] is True
        assert BINDING_SUPPORT["GRPC"] is False
        assert BINDING_SUPPORT["HTTP+JSON"] is False

    def test_a_jsonrpc_card_is_accepted(self) -> None:
        card = AgentCard.from_json(
            {"supportedInterfaces": [{"url": AGENT_URL, "protocolBinding": "JSONRPC"}]}
        )
        assert require_supported_binding(card) == "JSONRPC"

    def test_a_card_with_no_declaration_defaults_to_jsonrpc(self) -> None:
        """JSON-RPC is the mandated interoperability floor, so its absence from
        the card is not a reason to refuse."""
        assert require_supported_binding(AgentCard.from_json({})) == "JSONRPC"

    @pytest.mark.parametrize("binding", ["GRPC", "HTTP+JSON"])
    def test_an_unimplemented_binding_names_what_is_missing(self, binding: str) -> None:
        """The failure has to say which binding, and which ones exist.

        "Unsupported" alone sends the reader to the peer's logs; naming the gap
        sends them to the right client.
        """
        card = AgentCard.from_json(
            {"supportedInterfaces": [{"url": AGENT_URL, "protocolBinding": binding}]}
        )
        with pytest.raises(UnsupportedBindingError) as excinfo:
            require_supported_binding(card)
        message = str(excinfo.value)
        assert binding in message
        assert "JSONRPC" in message

    def test_the_error_is_an_a2a_error_so_callers_catch_one_type(self) -> None:
        assert issubclass(UnsupportedBindingError, A2AError)

    def test_an_unknown_binding_is_also_refused(self) -> None:
        card = AgentCard.from_json(
            {"supportedInterfaces": [{"url": AGENT_URL, "protocolBinding": "CARRIER-PIGEON"}]}
        )
        with pytest.raises(UnsupportedBindingError, match="CARRIER-PIGEON"):
            require_supported_binding(card)
