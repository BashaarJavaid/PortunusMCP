import asyncio
import logging
import os
import time
import uuid
from types import SimpleNamespace
from typing import Any, cast

import pytest
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse
from prometheus_client import REGISTRY

from services.gateway import logging_config, risk_engine
from services.gateway.approvals import APPROVAL_META_KEY
from services.gateway.decision import DecisionMode, DecisionOutcome, EventType
from services.gateway.jsonrpc_interceptor import Forward, Interceptor, Respond
from services.gateway.policy_engine import PolicyEngine, PolicyFile
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY

# Route structlog through stdlib so caplog sees the records (main.py does this in
# production; unit tests never import main).
logging_config.configure()

POLICY = PolicyFile.model_validate(
    {
        "version": 1,
        "servers": {"default": {"image": "example/upstream:test", "command": ["unused-command"]}},
        "identities": [
            {
                "id": "agent-readonly",
                "api_key_hash": "sha256:0",
                "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
            }
        ],
    }
)

ECHO_SCHEMA = {
    "type": "object",
    "properties": {"text": {"type": "string"}},
    "required": ["text"],
}

FAKE_HASH = "cafe" * 16


class FakeWriter:
    def __init__(self) -> None:
        self.events: list[EventType] = []
        self.rows: list[dict[str, Any]] = []

    async def write(
        self,
        event_type: EventType,
        identity_id: str,
        server_id: str | None = None,
        tool_name: str | None = None,
        payload_extra: dict[str, Any] | None = None,
        risk_score: int | None = None,
    ) -> int:
        self.events.append(event_type)
        self.rows.append(
            {
                "event_type": event_type,
                "payload": payload_extra or {},
                "risk_score": risk_score,
            }
        )
        return 42


class FakeDetector:
    def __init__(self) -> None:
        self.blocked: set[str] = set()
        self.checked: list[list[dict[str, Any]]] = []
        self.lookups: list[str] = []

    async def check(self, server_id: str, tools: list[dict[str, Any]], identity_id: str) -> None:
        self.checked.append(tools)

    async def is_blocked(self, server_id: str, tool_name: str) -> bool:
        self.lookups.append(tool_name)
        return tool_name in self.blocked


class FakeReplay:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    async def check(self, nonce: object, timestamp: object) -> str | None:
        if not isinstance(nonce, str) or not isinstance(timestamp, int | float):
            return "missing or invalid nonce or timestamp"
        if nonce in self.seen:
            return "nonce already seen within the timestamp window"
        self.seen.add(nonce)
        return None


class FakeCache:
    def __init__(self) -> None:
        self.data: dict[str, list[dict[str, Any]]] = {}
        self.invalidated: list[str] = []

    async def get(self, server_id: str) -> list[dict[str, Any]] | None:
        return self.data.get(server_id)

    async def put(self, server_id: str, tools: list[dict[str, Any]]) -> str:
        self.data[server_id] = tools
        return FAKE_HASH

    async def invalidate(self, server_id: str) -> None:
        self.data.pop(server_id, None)
        self.invalidated.append(server_id)


class FakeRisk:
    """Stage-6 stand-in: fixed score (default 0 → continue) or a raised exception."""

    def __init__(self, score: int = 0, error: Exception | None = None) -> None:
        self.result = (score, [])
        self.error = error
        self.denials: list[str] = []
        self.denial_error: Exception | None = None
        self.calls: list[str] = []

    async def score(
        self,
        identity_id: str,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        risk_policy: Any,
    ) -> tuple[int, list[Any]]:
        self.calls.append(tool_name)
        if self.error is not None:
            raise self.error
        return self.result

    async def record_denial(self, identity_id: str) -> None:
        if self.denial_error is not None:
            raise self.denial_error
        self.denials.append(identity_id)


class FakeApprovals:
    def __init__(self) -> None:
        self.redeemed: list[str] = []
        self.created: list[str] = []
        self.denial: tuple[EventType, str] | None = None

    async def redeem(
        self, approval_id: str, identity_id: str, server_id: str, tool_name: str, args_hash: str
    ) -> tuple[EventType, str] | None:
        self.redeemed.append(approval_id)
        return self.denial

    async def create(
        self, identity_id: str, server_id: str, tool_name: str, args_hash: str, audit_id: int
    ) -> str:
        self.created.append(tool_name)
        return "approval-1"


class FakeChallenges:
    def __init__(self) -> None:
        self.redeemed: list[str] = []
        self.created: list[str] = []
        self.failure: str | None = None

    async def redeem(
        self,
        challenge_id: str,
        identity_id: str,
        server_id: str,
        tool_name: str,
        args_hash: str,
        proof: object,
        secret_b32: str,
    ) -> str | None:
        self.redeemed.append(challenge_id)
        return self.failure

    async def create(
        self, identity_id: str, server_id: str, tool_name: str, args_hash: str, audit_id: int
    ) -> str:
        self.created.append(tool_name)
        return "challenge-1"


async def _no_upstream(message: JSONRPCMessage) -> None:
    raise AssertionError("unexpected gateway-initiated upstream send")


def make_interceptor(
    identity: str = "agent-readonly",
    with_schema: bool = True,
    risk: FakeRisk | None = None,
    policy: PolicyFile | None = None,
    mode: DecisionMode = DecisionMode.ENFORCE,
) -> tuple[Interceptor, FakeWriter, FakeCache, FakeDetector]:
    writer = FakeWriter()
    cache = FakeCache()
    detector = FakeDetector()
    if with_schema:
        cache.data["default"] = [{"name": "echo", "inputSchema": ECHO_SCHEMA}]
    interceptor = Interceptor(
        identity_id=identity,
        server_id="default",
        session_id="test-session",
        store=cast(Any, SimpleNamespace(engine=PolicyEngine(policy or POLICY))),
        writer=cast(Any, writer),
        cache=cast(Any, cache),
        detector=cast(Any, detector),
        replay=cast(Any, FakeReplay()),
        risk=cast(Any, risk or FakeRisk()),
        approvals=cast(Any, FakeApprovals()),
        challenges=cast(Any, FakeChallenges()),
        send_upstream=_no_upstream,
        mode=mode,
    )
    return interceptor, writer, cache, detector


def abac_policy(conditions: list[str], attributes: dict[str, Any] | None = None) -> PolicyFile:
    return PolicyFile.model_validate(
        {
            "version": 1,
            "servers": {
                "default": {"image": "example/upstream:test", "command": ["unused-command"]}
            },
            "identities": [
                {
                    "id": "agent-readonly",
                    "api_key_hash": "sha256:0",
                    "attributes": {"team": "engineering"} if attributes is None else attributes,
                    "allowed_servers": [
                        {
                            "server_id": "default",
                            "allowed_tools": ["echo"],
                            "conditions": conditions,
                        }
                    ],
                }
            ],
        }
    )


def fresh_meta() -> dict[str, Any]:
    return {NONCE_META_KEY: str(uuid.uuid4()), TIMESTAMP_META_KEY: time.time()}


def request(method: str, params: dict | None = None, id: int = 1) -> SessionMessage:  # noqa: A002
    if method == "tools/call" and params is not None and "_meta" not in params:
        params = {**params, "_meta": fresh_meta()}
    return SessionMessage(
        JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=id, method=method, params=params))
    )


async def test_unhandled_method_passes_through_unmodified_but_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    message = request("weird/unknown", {"x": 1})
    interceptor, _, _, _ = make_interceptor()
    with caplog.at_level(logging.INFO, logger="services.gateway.jsonrpc_interceptor"):
        outcome = await interceptor.on_client_message(message)

    assert isinstance(outcome, Forward)
    assert outcome.message is message  # passed through, not rebuilt
    assert "weird/unknown" in caplog.text


async def test_decision_log_lines_are_structured_with_session_correlation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """§7: one line per decision, correlation id = session id — allow and deny alike."""
    interceptor, _, _, _ = make_interceptor()
    with caplog.at_level(logging.INFO, logger="services.gateway.jsonrpc_interceptor"):
        allowed = await interceptor.on_client_message(
            request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
        )
        denied = await interceptor.on_client_message(
            request("tools/call", {"name": "forbidden", "arguments": {}}, id=2)
        )
    assert isinstance(allowed, Forward)
    assert isinstance(denied, Respond)

    decisions = [
        record.msg
        for record in caplog.records
        if isinstance(record.msg, dict) and record.msg.get("event") == "decision"
    ]
    assert [d["decision"] for d in decisions] == ["allow", "deny"]
    allow_line, deny_line = decisions
    assert allow_line["event_type"] == "ALLOW"
    assert allow_line["tool"] == "echo"
    assert deny_line["event_type"] == "DENY_RBAC"
    assert deny_line["tool"] == "forbidden"
    assert deny_line["audit_id"] == "42"  # FakeWriter's seq
    for line in decisions:
        assert line["session_id"] == "test-session"
        assert line["identity"] == "agent-readonly"
        assert line["mode"] == "enforce"


async def test_unauthorized_tools_call_is_denied_with_canonical_decision() -> None:
    interceptor, writer, _, _ = make_interceptor()
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "delete_repo", "arguments": {}})
    )

    assert isinstance(outcome, Respond)
    error = outcome.message.message.root
    assert error.id == 1
    assert error.error.data["event_type"] == "DENY_RBAC"
    assert error.error.data["decision"] == "deny"
    assert error.error.data["mode"] == "enforce"
    assert error.error.data["policy_version"] == 1
    assert error.error.data["audit_id"] == "42"  # the audit row's seq
    assert writer.events == [EventType.DENY_RBAC]


async def test_authorized_tools_call_is_audited_then_forwarded() -> None:
    interceptor, writer, _, _ = make_interceptor()
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Forward)
    assert writer.events == [EventType.ALLOW]  # recorded before forwarding


async def test_allow_that_cannot_be_recorded_is_denied() -> None:
    interceptor, writer, _, _ = make_interceptor()

    async def broken_write(*args: Any, **kwargs: Any) -> int:
        raise ConnectionError("postgres down")

    writer.write = broken_write  # type: ignore[method-assign]
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {}})
    )
    assert isinstance(outcome, Respond)  # no record, no action (§5)


async def test_drift_blocked_tool_is_denied() -> None:
    interceptor, writer, _, detector = make_interceptor()
    detector.blocked.add("echo")
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    error = outcome.message.message.root
    assert error.error.data["event_type"] == "DENY_DRIFT"
    assert error.error.data["audit_id"] == "42"
    assert writer.events == [EventType.DENY_DRIFT]


async def test_drift_status_lookup_failure_denies() -> None:
    interceptor, _, _, detector = make_interceptor()

    async def broken(server_id: str, tool_name: str) -> bool:
        raise ConnectionError("postgres down")

    detector.is_blocked = broken  # type: ignore[method-assign]
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_DRIFT"


async def test_initialize_invalidates_schema_cache() -> None:
    interceptor, _, cache, _ = make_interceptor()
    outcome = await interceptor.on_client_message(request("initialize", {}))
    assert isinstance(outcome, Forward)
    assert cache.invalidated == ["default"]


async def test_cache_miss_triggers_transparent_refetch_then_forwards() -> None:
    interceptor, writer, cache, _ = make_interceptor(with_schema=False)
    sent: list[JSONRPCMessage] = []

    async def capture(message: JSONRPCMessage) -> None:
        sent.append(message)

    interceptor.send_upstream = capture
    task = asyncio.create_task(
        interceptor.on_client_message(
            request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
        )
    )
    while not sent:  # wait for the gateway's own tools/list to go out
        await asyncio.sleep(0.01)
    internal_id = sent[0].root.id
    assert str(internal_id).startswith("portunusmcp:")

    swallowed = await interceptor.on_upstream_message(
        SessionMessage(
            JSONRPCMessage(
                JSONRPCResponse(
                    jsonrpc="2.0",
                    id=internal_id,
                    result={"tools": [{"name": "echo", "inputSchema": ECHO_SCHEMA}]},
                )
            )
        )
    )
    assert swallowed is None  # internal responses never reach the client

    outcome = await task
    assert isinstance(outcome, Forward)
    assert cache.data["default"] == [{"name": "echo", "inputSchema": ECHO_SCHEMA}]
    assert writer.events == [EventType.ALLOW]


async def test_failed_refetch_is_denied_validation() -> None:
    interceptor, writer, _, _ = make_interceptor(with_schema=False)
    # send_upstream raises (default _no_upstream would too, but be explicit)

    async def broken(message: JSONRPCMessage) -> None:
        raise BrokenPipeError("upstream gone")

    interceptor.send_upstream = broken
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_VALIDATION"
    assert writer.events == [EventType.DENY_VALIDATION]


async def test_invalid_arguments_are_denied_and_audited() -> None:
    interceptor, writer, _, _ = make_interceptor()
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi", "bogus": 1}})
    )
    assert isinstance(outcome, Respond)
    error = outcome.message.message.root
    assert error.error.data["event_type"] == "DENY_VALIDATION"
    assert error.error.data["audit_id"] == "42"
    assert "bogus" in error.error.message
    assert writer.events == [EventType.DENY_VALIDATION]


async def test_tools_list_response_is_pruned_audited_and_etagged() -> None:
    interceptor, writer, cache, detector = make_interceptor(with_schema=False)
    await interceptor.on_client_message(request("tools/list", id=7))
    response = SessionMessage(
        JSONRPCMessage(
            JSONRPCResponse(
                jsonrpc="2.0",
                id=7,
                result={"tools": [{"name": "echo"}, {"name": "delete_repo"}]},
            )
        )
    )

    out = await interceptor.on_upstream_message(response)

    assert out is not None
    assert out.message.root.result["tools"] == [{"name": "echo"}]
    assert out.message.root.result["_meta"] == {"etag": f"1-{FAKE_HASH}"}
    assert cache.data["default"] == [{"name": "echo"}, {"name": "delete_repo"}]
    assert writer.events == [EventType.TOOLS_LIST]
    assert writer.rows[0]["payload"] == {
        "mode": "enforce",
        "served_tools": ["echo"],
        "pruned_tools": ["delete_repo"],
        "would_prune_tools": ["delete_repo"],
    }
    assert detector.checked == [[{"name": "echo"}, {"name": "delete_repo"}]]  # full list


async def test_observe_forwards_rbac_deny_after_remaining_stages_and_audit() -> None:
    risk = FakeRisk()
    interceptor, writer, _, detector = make_interceptor(risk=risk, mode=DecisionMode.OBSERVE)
    message = request(
        "tools/call",
        {"name": "delete_repo", "arguments": {}, "_meta": fresh_meta()},
    )

    outcome = await interceptor.on_client_message(message)

    assert isinstance(outcome, Forward)
    assert detector.lookups == ["delete_repo"]
    assert risk.calls == ["delete_repo"]
    assert risk.denials == ["agent-readonly"]
    assert writer.events == [EventType.DENY_RBAC]
    assert writer.rows[0]["risk_score"] == 0
    assert writer.rows[0]["payload"]["mode"] == "observe"
    assert writer.rows[0]["payload"]["risk_factors"] == []
    assert "_meta" not in message.message.root.params


async def test_observe_tools_list_serves_all_and_records_would_be_pruning() -> None:
    interceptor, writer, _, _ = make_interceptor(with_schema=False, mode=DecisionMode.OBSERVE)
    await interceptor.on_client_message(request("tools/list", id=7))
    response = SessionMessage(
        JSONRPCMessage(
            JSONRPCResponse(
                jsonrpc="2.0",
                id=7,
                result={"tools": [{"name": "echo"}, {"name": "delete_repo"}]},
            )
        )
    )

    out = await interceptor.on_upstream_message(response)

    assert out is not None
    assert out.message.root.result["tools"] == [
        {"name": "echo"},
        {"name": "delete_repo"},
    ]
    assert writer.rows[0]["payload"] == {
        "mode": "observe",
        "served_tools": ["echo", "delete_repo"],
        "pruned_tools": [],
        "would_prune_tools": ["delete_repo"],
    }


async def test_observe_preserves_first_blocker_and_enriches_it_with_failed_risk() -> None:
    policy = abac_policy(["identity.team == 'sales'"])
    interceptor, writer, _, detector = make_interceptor(
        policy=policy,
        risk=FakeRisk(error=RuntimeError("redis down")),
        mode=DecisionMode.OBSERVE,
    )
    detector.blocked.add("echo")

    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"bogus": 1}})
    )

    assert isinstance(outcome, Forward)
    assert writer.events == [EventType.DENY_ABAC]
    row = writer.rows[0]
    assert row["risk_score"] == 100
    assert row["payload"]["risk_factors"][0]["factor"] == "risk_engine_unavailable"


async def test_observe_ignores_hold_metadata_and_never_creates_or_consumes_holds() -> None:
    interceptor, writer, _, _ = make_interceptor(risk=FakeRisk(75), mode=DecisionMode.OBSERVE)
    approvals = cast(FakeApprovals, interceptor.approvals)
    challenges = cast(FakeChallenges, interceptor.challenges)
    message = request(
        "tools/call",
        {
            "name": "echo",
            "arguments": {"text": "hi"},
            "_meta": {
                **fresh_meta(),
                APPROVAL_META_KEY: "approval-1",
                "portunusmcp/challenge_id": "challenge-1",
                "portunusmcp/challenge_proof": "123456",
            },
        },
    )

    outcome = await interceptor.on_client_message(message)

    assert isinstance(outcome, Forward)
    assert writer.events == [EventType.HUMAN_APPROVAL_REQUIRED]
    assert "would require human approval" in writer.rows[0]["payload"]["reason"]
    assert approvals.redeemed == approvals.created == []
    assert challenges.redeemed == challenges.created == []
    assert "_meta" not in message.message.root.params


async def test_observe_audit_failure_still_blocks_forwarding() -> None:
    interceptor, writer, _, _ = make_interceptor(mode=DecisionMode.OBSERVE)

    async def broken_write(*args: Any, **kwargs: Any) -> int:
        raise ConnectionError("postgres down")

    writer.write = broken_write  # type: ignore[method-assign]
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )

    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.code == -32004


async def test_replayed_nonce_is_denied_with_canonical_decision() -> None:
    interceptor, writer, _, _ = make_interceptor()
    meta = fresh_meta()
    first = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}, "_meta": dict(meta)})
    )
    assert isinstance(first, Forward)

    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}, "_meta": dict(meta)})
    )
    assert isinstance(outcome, Respond)
    error = outcome.message.message.root
    assert error.error.data["event_type"] == "DENY_REPLAY"
    assert error.error.data["decision"] == "deny"
    assert error.error.data["matched_rules"] == ["replay_guard"]
    assert error.error.data["audit_id"] == "42"
    assert writer.events == [EventType.ALLOW, EventType.DENY_REPLAY]


async def test_observe_replay_is_detected_but_forwarded_without_denied_metric() -> None:
    interceptor, writer, _, _ = make_interceptor(mode=DecisionMode.OBSERVE)
    before = REGISTRY.get_sample_value("portunusmcp_replay_denied_total") or 0
    meta = fresh_meta()
    first = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}, "_meta": dict(meta)})
    )
    second = await interceptor.on_client_message(
        request(
            "tools/call",
            {"name": "echo", "arguments": {"text": "again"}, "_meta": dict(meta)},
            id=2,
        )
    )

    assert isinstance(first, Forward)
    assert isinstance(second, Forward)
    assert writer.events == [EventType.ALLOW, EventType.DENY_REPLAY]
    assert (REGISTRY.get_sample_value("portunusmcp_replay_denied_total") or 0) == before


async def test_malformed_nonce_is_denied_before_rbac() -> None:
    # Replay is pipeline stage 1 (§4.2): a volunteered-but-malformed nonce reports
    # DENY_REPLAY even for an RBAC-denied tool (present → fully enforced, item 34).
    interceptor, writer, _, _ = make_interceptor()
    outcome = await interceptor.on_client_message(
        request(
            "tools/call",
            {"name": "delete_repo", "arguments": {}, "_meta": {NONCE_META_KEY: "not-a-uuid"}},
        )
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_REPLAY"
    assert writer.events == [EventType.DENY_REPLAY]


async def test_bearer_call_without_nonce_skips_replay_and_forwards() -> None:
    # Item 34: a stock MCP client sends no portunusmcp _meta at all — bearer identities
    # skip stage 1 entirely and the rest of the pipeline still runs.
    interceptor, writer, _, _ = make_interceptor()
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}, "_meta": {}})
    )
    assert isinstance(outcome, Forward)
    assert writer.events == [EventType.ALLOW]


async def test_signed_identity_missing_nonce_is_denied() -> None:
    # For signed identities the nonce/timestamp pair stays mandatory (item 34).
    os.environ["INTERCEPTOR_TEST_SECRET"] = "s3cret"
    policy = PolicyFile.model_validate(
        {
            "version": 1,
            "servers": {
                "default": {"image": "example/upstream:test", "command": ["unused-command"]}
            },
            "identities": [
                {
                    "id": "agent-readonly",
                    "auth_mode": "signed",
                    "key_id": "kid_interceptor",
                    "signing_secret_env": "INTERCEPTOR_TEST_SECRET",
                    "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
                }
            ],
        }
    )
    interceptor, writer, _, _ = make_interceptor(policy=policy)
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}, "_meta": {}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_REPLAY"
    assert writer.events == [EventType.DENY_REPLAY]


async def test_replay_check_failure_denies() -> None:
    interceptor, _, _, _ = make_interceptor()

    async def broken(nonce: object, timestamp: object) -> str | None:
        raise ConnectionError("redis down")

    interceptor.replay.check = broken  # type: ignore[method-assign]
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_REPLAY"


async def test_forwarded_call_has_replay_meta_stripped() -> None:
    interceptor, _, _, _ = make_interceptor()
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Forward)
    assert "_meta" not in outcome.message.message.root.params


async def test_other_meta_content_survives_the_strip() -> None:
    interceptor, _, _, _ = make_interceptor()
    outcome = await interceptor.on_client_message(
        request(
            "tools/call",
            {
                "name": "echo",
                "arguments": {"text": "hi"},
                "_meta": {**fresh_meta(), "progressToken": "tok-1"},
            },
        )
    )
    assert isinstance(outcome, Forward)
    assert outcome.message.message.root.params["_meta"] == {"progressToken": "tok-1"}


# --- Prior-denial-rate telemetry hook (item 18) ---


async def test_every_deny_terminal_records_one_denial() -> None:
    interceptor, _, _, _ = make_interceptor()
    risk = cast(FakeRisk, interceptor.risk)
    await interceptor.on_client_message(
        request("tools/call", {"name": "forbidden", "arguments": {}})  # DENY_RBAC
    )
    await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"bogus": 1}}, id=2)  # DENY_VALIDATION
    )
    assert risk.denials == ["agent-readonly", "agent-readonly"]


async def test_allow_records_no_denial() -> None:
    interceptor, _, _, _ = make_interceptor()
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Forward)
    assert cast(FakeRisk, interceptor.risk).denials == []


async def test_denial_count_failure_does_not_disturb_the_deny() -> None:
    interceptor, writer, _, _ = make_interceptor()
    cast(FakeRisk, interceptor.risk).denial_error = ConnectionError("redis down")
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "forbidden", "arguments": {}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_RBAC"
    assert writer.events == [EventType.DENY_RBAC]


# --- ABAC conditions stage 4 + deferred risk.* (item 17) ---


async def test_satisfied_conditions_pass_through_to_allow() -> None:
    policy = abac_policy(["identity.team == 'engineering'", "risk.score < 60"])
    interceptor, writer, _, _ = make_interceptor(policy=policy)
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Forward)
    assert writer.events == [EventType.ALLOW]


async def test_failed_condition_is_denied_abac_before_drift() -> None:
    policy = abac_policy(["identity.team == 'sales'"])
    interceptor, writer, _, detector = make_interceptor(policy=policy)
    detector.blocked.add("echo")  # would be DENY_DRIFT if ABAC ran later than stage 4
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    error = outcome.message.message.root
    assert error.error.data["event_type"] == "DENY_ABAC"
    assert error.error.data["decision"] == "deny"
    assert error.error.data["matched_rules"] == ["policy-v1:abac:identity.team == 'sales'"]
    assert error.error.data["audit_id"] == "42"
    assert writer.events == [EventType.DENY_ABAC]


async def test_missing_attribute_writes_policy_error_and_denies() -> None:
    policy = abac_policy(["identity.region == 'eu'"])  # identity has no `region`
    interceptor, writer, _, _ = make_interceptor(policy=policy)
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_ABAC"
    assert writer.events == [EventType.POLICY_ERROR, EventType.DENY_ABAC]


async def test_missing_attribute_inside_not_still_denies() -> None:
    # §11 inversion case end-to-end: not(missing) must not evaluate to a grant.
    policy = abac_policy(["not (identity.region == 'eu')"])
    interceptor, writer, _, _ = make_interceptor(policy=policy)
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_ABAC"
    assert writer.events == [EventType.POLICY_ERROR, EventType.DENY_ABAC]


async def test_type_mismatch_condition_writes_policy_error_and_denies() -> None:
    policy = abac_policy(["identity.team < 5"])  # str vs int comparison raises
    interceptor, writer, _, _ = make_interceptor(policy=policy)
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_ABAC"
    assert writer.events == [EventType.POLICY_ERROR, EventType.DENY_ABAC]


async def test_context_hour_comes_from_replay_timestamp() -> None:
    policy = abac_policy(["context.hour < 20"])
    interceptor, writer, _, _ = make_interceptor(policy=policy)
    late = {NONCE_META_KEY: str(uuid.uuid4()), TIMESTAMP_META_KEY: 22 * 3600}  # 22:00 UTC
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}, "_meta": late})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_ABAC"

    early = {NONCE_META_KEY: str(uuid.uuid4()), TIMESTAMP_META_KEY: 14 * 3600}  # 14:00 UTC
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}, "_meta": early}, id=2)
    )
    assert isinstance(outcome, Forward)
    assert writer.events == [EventType.DENY_ABAC, EventType.ALLOW]


async def test_risk_condition_is_evaluated_after_scoring() -> None:
    policy = abac_policy(["risk.score < 20"])
    interceptor, writer, _, _ = make_interceptor(policy=policy, risk=FakeRisk(35))
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    data = outcome.message.message.root.error.data
    assert data["event_type"] == "DENY_ABAC"
    assert data["risk_score"] == 35  # the deferred deny carries the computed score
    assert writer.events == [EventType.DENY_ABAC]


async def test_risk_condition_deny_wins_over_challenge_and_approval() -> None:
    """User-confirmed precedence: deferred ABAC runs before the threshold mapping,
    so a score that would CHALLENGE/HUMAN_APPROVAL_REQUIRED still lands DENY_ABAC."""
    policy = abac_policy(["risk.score < 60"])
    interceptor, writer, _, _ = make_interceptor(policy=policy, risk=FakeRisk(75))
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_ABAC"
    assert writer.events == [EventType.DENY_ABAC]  # not HUMAN_APPROVAL_REQUIRED


async def test_redemption_skips_risk_conditions_but_not_stage_4() -> None:
    """An approved retry has no fresh score: risk.* conditions are skipped by design
    (a human approved that exact call); non-risk conditions still apply."""
    policy = abac_policy(["identity.team == 'engineering'", "risk.score < 20"])
    interceptor, writer, _, _ = make_interceptor(policy=policy, risk=FakeRisk(91))
    outcome = await interceptor.on_client_message(
        request(
            "tools/call",
            {
                "name": "echo",
                "arguments": {"text": "hi"},
                "_meta": {**fresh_meta(), APPROVAL_META_KEY: "approval-1"},
            },
        )
    )
    assert isinstance(outcome, Forward)
    assert writer.events == [EventType.ALLOW]

    # Same retry shape, but with a failing stage-4 condition: still denied.
    policy = abac_policy(["identity.team == 'sales'", "risk.score < 20"])
    interceptor, writer, _, _ = make_interceptor(policy=policy, risk=FakeRisk(91))
    outcome = await interceptor.on_client_message(
        request(
            "tools/call",
            {
                "name": "echo",
                "arguments": {"text": "hi"},
                "_meta": {**fresh_meta(), APPROVAL_META_KEY: "approval-1"},
            },
        )
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_ABAC"
    assert writer.events == [EventType.DENY_ABAC]


# --- Risk Engine stage 6 (item 16) ---


@pytest.mark.parametrize(
    ("score", "expected_event"),
    [
        (39, EventType.ALLOW),  # continue: eventually forwarded
        (40, EventType.CHALLENGE),
        (69, EventType.CHALLENGE),
        (70, EventType.HUMAN_APPROVAL_REQUIRED),
        (90, EventType.HUMAN_APPROVAL_REQUIRED),
        (91, EventType.DENY_RISK),
    ],
)
async def test_risk_threshold_boundaries(score: int, expected_event: EventType) -> None:
    """§4.8 exact bands: <40 continue, 40-69 challenge, 70-90 approval, >90 deny."""
    interceptor, writer, _, _ = make_interceptor(risk=FakeRisk(score))
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert writer.events == [expected_event]
    if expected_event is EventType.ALLOW:
        assert isinstance(outcome, Forward)
    else:
        assert isinstance(outcome, Respond)
        data = outcome.message.message.root.error.data
        assert data["event_type"] == expected_event.value
        assert data["risk_score"] == score


@pytest.mark.parametrize("score", [45, 75, 95])
async def test_moved_band_constants_keep_live_and_predicted_outcomes_agreeing(
    monkeypatch: pytest.MonkeyPatch, score: int
) -> None:
    """Item 32 canary: shift every band constant, then assert live enforcement still
    matches threshold_outcome() — the mapping the Decision Explainer predicts with.
    Each score sits where the old inline comparisons (>= 40, >= 70, > 90) and the
    shifted bands disagree, so this fails if the interceptor ever forks them again."""
    monkeypatch.setattr(risk_engine, "RISK_CHALLENGE_MIN", 60)
    monkeypatch.setattr(risk_engine, "RISK_APPROVAL_MIN", 80)
    monkeypatch.setattr(risk_engine, "RISK_DENY_ABOVE", 96)
    predicted = risk_engine.threshold_outcome(score)

    interceptor, _, _, _ = make_interceptor(risk=FakeRisk(score))
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    if isinstance(outcome, Forward):
        live = DecisionOutcome.ALLOW
    else:
        live = DecisionOutcome(outcome.message.message.root.error.data["decision"])
    assert live is predicted


async def test_human_approval_decision_carries_approval_id() -> None:
    interceptor, writer, _, _ = make_interceptor(risk=FakeRisk(75))
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    data = outcome.message.message.root.error.data
    assert data["decision"] == "human_approval_required"
    assert data["approval_id"] == "approval-1"  # FakeApprovals
    assert data["audit_id"] == "42"


async def test_risk_scoring_exception_fails_closed_as_deny_risk() -> None:
    """§5: a crashed risk calculation is maximum risk, not low risk."""
    interceptor, writer, _, _ = make_interceptor(risk=FakeRisk(error=RuntimeError("redis down")))
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    data = outcome.message.message.root.error.data
    assert data["event_type"] == "DENY_RISK"
    assert data["risk_score"] == 100
    assert writer.events == [EventType.DENY_RISK]


async def test_risk_runs_before_param_validation() -> None:
    """Pipeline order regression (§4.2): stage 6 terminates before stage 7 sees the
    call — invalid arguments must not surface as DENY_VALIDATION when risk trips."""
    interceptor, writer, _, _ = make_interceptor(risk=FakeRisk(40))
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {}})  # missing required "text"
    )
    assert isinstance(outcome, Respond)
    assert writer.events == [EventType.CHALLENGE]


async def test_approved_retry_redeems_and_skips_risk_scoring() -> None:
    """A valid portunusmcp/approval_id bypasses stage 6 (a human approved this exact
    call) but not param validation; the approval meta key never leaks upstream."""
    interceptor, writer, _, _ = make_interceptor(risk=FakeRisk(91))  # would deny if scored
    outcome = await interceptor.on_client_message(
        request(
            "tools/call",
            {
                "name": "echo",
                "arguments": {"text": "hi"},
                "_meta": {**fresh_meta(), APPROVAL_META_KEY: "approval-1"},
            },
        )
    )
    assert isinstance(outcome, Forward)
    assert writer.events == [EventType.ALLOW]
    assert "_meta" not in outcome.message.message.root.params
    assert cast(Any, interceptor.approvals).redeemed == ["approval-1"]


async def test_rejected_approval_id_is_denied_with_its_classification() -> None:
    interceptor, writer, _, _ = make_interceptor()
    cast(Any, interceptor.approvals).denial = (
        EventType.DENY_APPROVAL_MISMATCH,
        "arguments differ from the ones that were approved",
    )
    outcome = await interceptor.on_client_message(
        request(
            "tools/call",
            {
                "name": "echo",
                "arguments": {"text": "mutated"},
                "_meta": {**fresh_meta(), APPROVAL_META_KEY: "approval-1"},
            },
        )
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_APPROVAL_MISMATCH"
    assert writer.events == [EventType.DENY_APPROVAL_MISMATCH]
