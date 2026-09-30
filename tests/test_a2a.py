"""A2A execution: the state mapping, the binding, and what it refuses to claim.

The tests that matter here are the ones about the *interrupted* states. A2A has
two states — ``INPUT_REQUIRED`` and ``AUTH_REQUIRED`` — that this library has no
equivalent for, because a delegation is either outstanding or settled. Mapping
them to a failure would blame the delegate for a question the principal has not
answered, and would release a budget commitment that is genuinely still
outstanding. That mistake is invisible in a happy-path test, so it gets its own
class.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from agent_ledger import (
    A2AClient,
    A2AError,
    A2AExecutor,
    CallableExecutor,
    ExecutionResult,
    Grid,
    Ledger,
    Policy,
    StaticCredential,
    Task,
    map_task_state,
)
from agent_ledger.a2a import (
    INTERRUPTED_STATES,
    TASK_STATE_AUTH_REQUIRED,
    TASK_STATE_CANCELED,
    TASK_STATE_COMPLETED,
    TASK_STATE_FAILED,
    TASK_STATE_INPUT_REQUIRED,
    TASK_STATE_REJECTED,
    TASK_STATE_SUBMITTED,
    TASK_STATE_UNSPECIFIED,
    TASK_STATE_WORKING,
    TERMINAL_STATES,
)
from agent_ledger.ard import ArdClient, StaticTransport
from agent_ledger.models import DelegationStatus

AGENT_URL = "https://agent.example/a2a"

ENTRY_DOC = {
    "identifier": "urn:air:agent.example:agents:reviewer",
    "displayName": "Reviewer",
    "type": "application/a2a-agent-card+json",
    "url": AGENT_URL,
    "capabilities": ["contract_review"],
    "representativeQueries": ["review a vendor contract"],
}


def a_task(state: str, *, task_id: str = "task-1", text: str | None = "done") -> dict[str, Any]:
    task: dict[str, Any] = {"id": task_id, "contextId": "ctx-1", "status": {"state": state}}
    if text is not None:
        task["artifacts"] = [{"artifactId": "a1", "parts": [{"text": text}]}]
    return task


class FakeRpc:
    """A scripted JSON-RPC peer. Records what was sent so the wire shape can be
    asserted, not merely the outcome."""

    def __init__(self, responses: list[Mapping[str, Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def post_json(self, url: str, payload: Mapping[str, Any], *, timeout: float = 30.0):
        self.calls.append((url, payload))
        if not self.responses:
            raise A2AError("no scripted response left")
        return self.responses.pop(0)

    @property
    def methods(self) -> list[str]:
        return [str(payload.get("method")) for _, payload in self.calls]


def result(document: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": "1", "result": dict(document)}


class TestStateMapping:
    """The table in the module docstring, asserted row by row."""

    @pytest.mark.parametrize(
        ("state", "outcome", "ok", "terminal"),
        [
            (TASK_STATE_SUBMITTED, DelegationStatus.ACCEPTED, True, False),
            (TASK_STATE_WORKING, DelegationStatus.ACCEPTED, True, False),
            (TASK_STATE_COMPLETED, DelegationStatus.COMPLETED, True, True),
            (TASK_STATE_FAILED, DelegationStatus.FAILED, False, True),
            (TASK_STATE_CANCELED, DelegationStatus.FAILED, False, True),
            (TASK_STATE_REJECTED, DelegationStatus.FAILED, False, True),
            (TASK_STATE_INPUT_REQUIRED, DelegationStatus.ACCEPTED, True, False),
            (TASK_STATE_AUTH_REQUIRED, DelegationStatus.ACCEPTED, True, False),
            (TASK_STATE_UNSPECIFIED, DelegationStatus.FAILED, False, True),
        ],
    )
    def test_every_known_state_maps(self, state, outcome, ok, terminal) -> None:
        assert map_task_state(state) == (outcome, ok, terminal)

    @pytest.mark.parametrize("state", ["TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED"])
    def test_interrupted_states_are_not_failures(self, state: str) -> None:
        """Work waiting on the principal is not a failure of the delegate.

        Reported as a failure it would cost the agent reputation for a question
        nobody has answered, and `committed_for_task` would release a budget that
        is still genuinely committed.
        """
        outcome, ok, terminal = map_task_state(state)
        assert ok is True
        assert terminal is False
        assert outcome is DelegationStatus.ACCEPTED
        assert state not in TERMINAL_STATES
        assert state in INTERRUPTED_STATES

    def test_an_unknown_state_fails_rather_than_succeeding(self) -> None:
        """The safe direction: a state this library does not model might mean
        anything, and reporting success for it would receipt work that never
        happened."""
        for unknown in ("TASK_STATE_FUTURE_THING", "completed", "", None):
            outcome, ok, terminal = map_task_state(unknown)
            assert ok is False, unknown
            assert terminal is True, unknown

    def test_terminal_and_interrupted_sets_are_disjoint(self) -> None:
        assert not (TERMINAL_STATES & INTERRUPTED_STATES)

    def test_every_terminal_state_agrees_with_the_table(self) -> None:
        """Guards against the two definitions drifting apart."""
        for state in TERMINAL_STATES:
            _, _, terminal = map_task_state(state)
            assert terminal is True, state


class TestJsonRpcBinding:
    def test_send_message_uses_the_current_method_name(self) -> None:
        rpc = FakeRpc([result({"task": a_task(TASK_STATE_COMPLETED)})])
        A2AClient(rpc).send_message(AGENT_URL, "review this")
        assert rpc.methods == ["SendMessage"]

    def test_the_request_is_well_formed_json_rpc(self) -> None:
        rpc = FakeRpc([result({"task": a_task(TASK_STATE_COMPLETED)})])
        A2AClient(rpc).send_message(AGENT_URL, "review this")
        _, payload = rpc.calls[0]
        assert payload["jsonrpc"] == "2.0"
        assert isinstance(payload["id"], str) and payload["id"]
        assert payload["method"] == "SendMessage"

    def test_the_message_carries_the_expected_members(self) -> None:
        rpc = FakeRpc([result({"task": a_task(TASK_STATE_COMPLETED)})])
        A2AClient(rpc).send_message(AGENT_URL, "review this")
        message = rpc.calls[0][1]["params"]["message"]
        assert message["role"] == "ROLE_USER"
        assert message["parts"] == [{"text": "review this"}]
        assert message["messageId"], "the idempotency key must be present"

    def test_return_immediately_defaults_to_true(self) -> None:
        """The spec default is to block until terminal; a grid wants the task id."""
        rpc = FakeRpc([result({"task": a_task(TASK_STATE_WORKING)})])
        A2AClient(rpc).send_message(AGENT_URL, "x")
        assert rpc.calls[0][1]["params"]["configuration"]["returnImmediately"] is True

    def test_message_ids_are_unique_per_call(self) -> None:
        rpc = FakeRpc(
            [
                result({"task": a_task(TASK_STATE_COMPLETED)}),
                result({"task": a_task(TASK_STATE_COMPLETED)}),
            ]
        )
        client = A2AClient(rpc)
        client.send_message(AGENT_URL, "x")
        client.send_message(AGENT_URL, "x")
        ids = {call[1]["params"]["message"]["messageId"] for call in rpc.calls}
        assert len(ids) == 2

    def test_it_falls_back_to_the_legacy_method_name_once(self) -> None:
        """A v0.3 server should cost one extra round trip, not one per call."""
        rpc = FakeRpc(
            [
                {"jsonrpc": "2.0", "id": "1", "error": {"code": -32601, "message": "no method"}},
                result({"task": a_task(TASK_STATE_COMPLETED)}),
                result({"task": a_task(TASK_STATE_COMPLETED)}),
            ]
        )
        client = A2AClient(rpc)
        client.send_message(AGENT_URL, "first")
        client.send_message(AGENT_URL, "second")
        assert rpc.methods == ["SendMessage", "message/send", "message/send"]

    def test_a_real_error_is_not_retried(self) -> None:
        """Retrying a genuine failure would make the agent do the work twice."""
        rpc = FakeRpc([{"jsonrpc": "2.0", "id": "1", "error": {"code": -32000, "message": "boom"}}])
        with pytest.raises(A2AError, match="boom"):
            A2AClient(rpc).send_message(AGENT_URL, "x")
        assert len(rpc.calls) == 1, "no fallback attempt on an application error"

    def test_a_json_rpc_error_becomes_an_a2a_error(self) -> None:
        rpc = FakeRpc([{"jsonrpc": "2.0", "id": "1", "error": {"code": -32600, "message": "bad"}}])
        with pytest.raises(A2AError):
            A2AClient(rpc).send_message(AGENT_URL, "x")

    def test_a_response_without_a_result_raises(self) -> None:
        rpc = FakeRpc([{"jsonrpc": "2.0", "id": "1"}])
        with pytest.raises(A2AError, match="no result"):
            A2AClient(rpc).send_message(AGENT_URL, "x")

    def test_get_task_uses_the_current_method_name(self) -> None:
        rpc = FakeRpc([result(a_task(TASK_STATE_WORKING))])
        A2AClient(rpc).get_task(AGENT_URL, "task-1")
        assert rpc.methods == ["GetTask"]
        assert rpc.calls[0][1]["params"]["id"] == "task-1"


class TestResponseParsing:
    def test_text_comes_from_artifacts(self) -> None:
        rpc = FakeRpc([result({"task": a_task(TASK_STATE_COMPLETED, text="the answer")})])
        assert A2AClient(rpc).send_message(AGENT_URL, "x").text == "the answer"

    def test_a_stateless_agent_may_reply_with_a_message_not_a_task(self) -> None:
        """A legitimate answer. Inventing a task id here is how a client ends up
        polling for something the remote has never heard of."""
        rpc = FakeRpc(
            [
                result(
                    {
                        "message": {
                            "messageId": "m1",
                            "role": "ROLE_AGENT",
                            "parts": [{"text": "here is your answer"}],
                        }
                    }
                )
            ]
        )
        sent = A2AClient(rpc).send_message(AGENT_URL, "x")
        assert sent.task is None
        assert sent.task_id is None
        assert sent.state is None
        assert sent.text == "here is your answer"

    def test_structured_data_in_a_part_is_summarised(self) -> None:
        rpc = FakeRpc(
            [
                result(
                    {
                        "task": {
                            "id": "t",
                            "status": {"state": TASK_STATE_COMPLETED},
                            "artifacts": [{"artifactId": "a", "parts": [{"data": {"k": "v"}}]}],
                        }
                    }
                )
            ]
        )
        assert '"k":"v"' in A2AClient(rpc).send_message(AGENT_URL, "x").text

    def test_non_text_parts_leave_a_trace(self) -> None:
        """An artifact that is entirely a file must still affect the result digest."""
        rpc = FakeRpc(
            [
                result(
                    {
                        "task": {
                            "id": "t",
                            "status": {"state": TASK_STATE_COMPLETED},
                            "artifacts": [
                                {"artifactId": "a", "parts": [{"url": "https://x/f.pdf"}]}
                            ],
                        }
                    }
                )
            ]
        )
        assert "f.pdf" in A2AClient(rpc).send_message(AGENT_URL, "x").text

    def test_a_task_with_no_state_reports_no_state(self) -> None:
        rpc = FakeRpc([result({"task": {"id": "t"}})])
        assert A2AClient(rpc).send_message(AGENT_URL, "x").state is None


class TestExecutor:
    def _executor(self, responses: list[Mapping[str, Any]], **kwargs: Any) -> A2AExecutor:
        return A2AExecutor(A2AClient(FakeRpc(responses)), **kwargs)

    def _entry(self):
        from agent_ledger.models import ArdEntry

        return ArdEntry.from_ard(ENTRY_DOC)

    def test_a_completed_task_reports_success_and_records_the_state(self) -> None:
        executor = self._executor([result({"task": a_task(TASK_STATE_COMPLETED)})])
        outcome = executor.execute(Task(intent="review"), self._entry())
        assert outcome.ok is True
        assert outcome.execution.state == TASK_STATE_COMPLETED
        assert outcome.execution.task_ref == "task-1"
        assert outcome.execution.binding == "JSONRPC"

    def test_a_failed_task_reports_failure(self) -> None:
        executor = self._executor([result({"task": a_task(TASK_STATE_FAILED, text=None)})])
        outcome = executor.execute(Task(intent="review"), self._entry())
        assert outcome.ok is False
        assert outcome.execution.state == TASK_STATE_FAILED

    def test_an_interrupted_task_reports_success_and_stays_open(self) -> None:
        executor = self._executor([result({"task": a_task(TASK_STATE_INPUT_REQUIRED)})])
        outcome = executor.execute(Task(intent="review"), self._entry())
        assert outcome.ok is True
        assert outcome.execution.state == TASK_STATE_INPUT_REQUIRED

    def test_the_credential_reference_is_recorded_but_never_the_secret(self) -> None:
        credential = StaticCredential(
            reference="spiffe://acme.com/agents/grid", header="Authorization", value="Bearer s3cret"
        )
        executor = A2AExecutor(
            A2AClient(
                FakeRpc([result({"task": a_task(TASK_STATE_COMPLETED)})]), credential=credential
            ),
            credential=credential,
        )
        outcome = executor.execute(Task(intent="review"), self._entry())
        assert outcome.execution.credential_ref == "spiffe://acme.com/agents/grid"
        assert "s3cret" not in json.dumps(outcome.execution.to_json())

    def test_no_credential_means_no_reference(self) -> None:
        executor = self._executor([result({"task": a_task(TASK_STATE_COMPLETED)})])
        assert executor.execute(Task(intent="r"), self._entry()).execution.credential_ref is None

    def test_an_entry_without_a_url_fails_before_reaching_the_network(self) -> None:
        from agent_ledger.models import ArdEntry

        rpc = FakeRpc([])
        executor = A2AExecutor(A2AClient(rpc))
        targetless = ArdEntry(identifier="urn:air:acme.com:agent:x", display_name="X", type="t")
        outcome = executor.execute(Task(intent="review"), targetless)
        assert outcome.ok is False
        assert "no A2A endpoint" in outcome.note
        assert rpc.calls == []

    def test_a_transport_failure_becomes_a_receipted_failure_not_an_exception(self) -> None:
        executor = A2AExecutor(A2AClient(FakeRpc([])))
        outcome = executor.execute(Task(intent="review"), self._entry())
        assert outcome.ok is False
        assert "A2A send failed" in outcome.note

    def test_no_polling_by_default(self) -> None:
        """A synchronous agent returns a terminal state; polling it wastes calls."""
        rpc = FakeRpc([result({"task": a_task(TASK_STATE_WORKING)})])
        executor = A2AExecutor(A2AClient(rpc))
        executor.execute(Task(intent="review"), self._entry())
        assert rpc.methods == ["SendMessage"]

    def test_polling_stops_at_a_terminal_state(self) -> None:
        rpc = FakeRpc(
            [
                result({"task": a_task(TASK_STATE_WORKING)}),
                result(a_task(TASK_STATE_WORKING)),
                result(a_task(TASK_STATE_COMPLETED)),
            ]
        )
        executor = A2AExecutor(A2AClient(rpc), max_polls=5)
        outcome = executor.execute(Task(intent="review"), self._entry())
        assert outcome.ok is True
        assert outcome.execution.state == TASK_STATE_COMPLETED
        assert rpc.methods == ["SendMessage", "GetTask", "GetTask"]

    def test_polling_stops_at_an_interrupted_state(self) -> None:
        """No amount of asking the agent again resolves a question for the principal."""
        rpc = FakeRpc(
            [
                result({"task": a_task(TASK_STATE_WORKING)}),
                result(a_task(TASK_STATE_INPUT_REQUIRED)),
            ]
        )
        executor = A2AExecutor(A2AClient(rpc), max_polls=5)
        outcome = executor.execute(Task(intent="review"), self._entry())
        assert outcome.ok is True
        assert outcome.execution.state == TASK_STATE_INPUT_REQUIRED
        assert rpc.methods == ["SendMessage", "GetTask"]

    def test_polling_gives_up_at_its_budget(self) -> None:
        rpc = FakeRpc(
            [result({"task": a_task(TASK_STATE_WORKING)})]
            + [result(a_task(TASK_STATE_WORKING)) for _ in range(3)]
        )
        executor = A2AExecutor(A2AClient(rpc), max_polls=2)
        outcome = executor.execute(Task(intent="review"), self._entry())
        assert outcome.execution.state == TASK_STATE_WORKING
        assert outcome.ok is True, "still working is not a failure"
        assert rpc.methods == ["SendMessage", "GetTask", "GetTask"]

    def test_a_stateless_reply_is_not_polled(self) -> None:
        rpc = FakeRpc([result({"message": {"messageId": "m", "parts": [{"text": "hi"}]}})])
        executor = A2AExecutor(A2AClient(rpc), max_polls=5)
        outcome = executor.execute(Task(intent="review"), self._entry())
        assert rpc.methods == ["SendMessage"], "there is no task id to poll"
        assert "without creating a task" in outcome.note


class TestGridIntegration:
    """The executor is only useful if it drives the real delegation path."""

    def _grid(self, rpc: FakeRpc, **kwargs: Any) -> Grid:
        transport = StaticTransport(
            {"https://agent.example/.well-known/ard.json": {"entries": [ENTRY_DOC]}}
        )
        return Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid(),
            ledger=Ledger(),
            domains=("agent.example",),
            executor=A2AExecutor(A2AClient(rpc), **kwargs),
        )

    def _task(self) -> Task:
        return Task(
            intent="review a vendor contract",
            required_capabilities=("contract_review",),
            budget_usd=0.5,
        )

    def test_a_completed_task_settles_the_delegation(self) -> None:
        grid = self._grid(FakeRpc([result({"task": a_task(TASK_STATE_COMPLETED)})]))
        outcome = grid.dispatch(self._task())
        assert outcome.ok
        assert outcome.receipt.outcome is DelegationStatus.COMPLETED

    def test_the_execution_record_reaches_the_receipt(self) -> None:
        grid = self._grid(FakeRpc([result({"task": a_task(TASK_STATE_COMPLETED)})]))
        outcome = grid.dispatch(self._task())
        assert outcome.receipt.execution is not None
        assert outcome.receipt.execution.state == TASK_STATE_COMPLETED
        assert outcome.receipt.execution.task_ref == "task-1"
        assert "execution" in outcome.receipt.body(), "it must be covered by the digest"

    def test_a_failed_task_fails_the_delegation(self) -> None:
        grid = self._grid(FakeRpc([result({"task": a_task(TASK_STATE_FAILED, text=None)})]))
        outcome = grid.dispatch(self._task())
        assert not outcome.ok
        assert outcome.receipt.outcome is DelegationStatus.FAILED

    def test_an_interrupted_task_leaves_the_delegation_open_not_failed(self) -> None:
        """The integration-level version of the mapping test.

        The delegation must stay `accepted` so its budget commitment survives,
        and it must be receipted rather than reported as a failure.
        """
        grid = self._grid(FakeRpc([result({"task": a_task(TASK_STATE_INPUT_REQUIRED)})]))
        outcome = grid.dispatch(self._task())

        assert outcome.ok, "waiting on the principal is not a failure"
        assert outcome.receipt.outcome is DelegationStatus.ACCEPTED
        assert outcome.receipt.execution.state == TASK_STATE_INPUT_REQUIRED
        # The commitment is still outstanding, which is the point.
        assert grid.ledger.committed_for_task(outcome.delegation.task.task_id) == 0.5

    def test_a_transport_failure_is_receipted_not_raised(self) -> None:
        grid = self._grid(FakeRpc([]))
        outcome = grid.dispatch(self._task())
        assert not outcome.ok
        assert outcome.receipt is not None
        assert outcome.receipt.outcome is DelegationStatus.FAILED

    def test_the_ledger_verifies_after_an_a2a_execution(self) -> None:
        grid = self._grid(FakeRpc([result({"task": a_task(TASK_STATE_COMPLETED)})]))
        grid.dispatch(self._task())
        integrity = grid.ledger.verify()
        assert integrity.ok, integrity.describe()

    def test_a2a_receipts_and_local_receipts_coexist_in_one_ledger(self) -> None:
        """Mixed ledgers must stay verifiable.

        The execution field is optional precisely so that a receipt without one —
        a local settlement, or any receipt written before A2A execution existed —
        digests to exactly the bytes it always did. A ledger holding both kinds
        is the normal case, not an edge case.
        """
        transport = StaticTransport(
            {"https://agent.example/.well-known/ard.json": {"entries": [ENTRY_DOC]}}
        )
        ledger = Ledger()
        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid(),
            ledger=ledger,
            domains=("agent.example",),
            executor=A2AExecutor(
                A2AClient(FakeRpc([result({"task": a_task(TASK_STATE_COMPLETED)})]))
            ),
        )
        assert grid.dispatch(self._task()).receipt.execution is not None

        # A second delegation, settled locally through the same ledger.
        local_grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid(),
            ledger=ledger,
            domains=("agent.example",),
        )
        placed = local_grid.delegate(self._task())
        local_receipt = local_grid.complete(placed.delegation, cost_usd=0.1)

        assert local_receipt.execution is None
        assert "execution" not in local_receipt.body()
        assert len(ledger) == 2
        integrity = ledger.verify()
        assert integrity.ok, integrity.describe()


class TestCallableExecutorStillWorks:
    """The zero-config path must not have been disturbed by the A2A work."""

    def test_a_local_executor_produces_no_execution_record(self) -> None:
        transport = StaticTransport(
            {"https://agent.example/.well-known/ard.json": {"entries": [ENTRY_DOC]}}
        )
        grid = Grid(
            client=ArdClient(transport),
            policy=Policy.open_grid(),
            ledger=Ledger(),
            domains=("agent.example",),
            executor=CallableExecutor(
                lambda task, entry: ExecutionResult(ok=True, cost_usd=0.01, output="ok")
            ),
        )
        outcome = grid.dispatch(
            Task(
                intent="review a vendor contract",
                required_capabilities=("contract_review",),
                budget_usd=0.5,
            )
        )
        assert outcome.ok
        assert outcome.receipt.execution is None
        assert "execution" not in outcome.receipt.body()
        assert grid.ledger.verify().ok
