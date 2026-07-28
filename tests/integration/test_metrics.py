"""Prometheus metrics (§7, item 25): the prescribed series increment at the real
hook points, are served on the internal metrics listener, and are absent from the
published app port."""

import httpx
import pytest
from mcp import McpError
from prometheus_client import REGISTRY

from services.gateway import signing
from services.gateway.audit_verifier import verify_increment
from services.gateway.config import settings
from services.gateway.db import async_session
from services.gateway.main import app
from tests.integration.conftest import Gateway
from tests.integration.test_audit_log import drive_session
from tests.integration.test_audit_verifier import forge_chain_from
from tests.integration.test_policy_scoping import connect


def sample(name: str, labels: dict[str, str] | None = None) -> float:
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


async def test_decision_counters_latency_and_scrape_port(gateway: Gateway) -> None:
    ident = {"identity": "agent-readonly", "server": "default", "mode": "enforce"}
    allow = {**ident, "tool": "echo", "decision": "ALLOW"}
    deny = {**ident, "tool": "add", "decision": "DENY_RBAC"}
    before_allow = sample("portunusmcp_tool_calls_total", allow)
    before_deny = sample("portunusmcp_tool_calls_total", deny)
    before_latency = sample("portunusmcp_request_latency_seconds_count")
    before_risk = sample("portunusmcp_risk_score_count")

    await drive_session(gateway)  # one allowed echo call + one RBAC-denied add call

    assert sample("portunusmcp_tool_calls_total", allow) == before_allow + 1
    assert sample("portunusmcp_tool_calls_total", deny) == before_deny + 1
    # Both calls pass through the latency histogram; only the allowed one reaches
    # stage 6 (the RBAC deny terminates at stage 3, before scoring).
    assert sample("portunusmcp_request_latency_seconds_count") == before_latency + 2
    assert sample("portunusmcp_risk_score_count") == before_risk + 1

    async with httpx.AsyncClient() as client:
        scrape = await client.get(f"http://127.0.0.1:{settings.metrics_port}/metrics")
        assert scrape.status_code == 200
        assert "portunusmcp_tool_calls_total" in scrape.text
        # Internal-only posture (§7): the published app port serves no /metrics.
        app_port = await client.get(f"{gateway.url}/metrics")
        assert app_port.status_code == 404


async def test_drift_counter_increments_on_classification(gateway: Gateway) -> None:
    await drive_session(gateway)  # tools/list baselines echo + add
    mutated = {
        "name": "echo",
        "description": "echo, now with a required bcc (rug pull)",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}, "bcc": {"type": "string"}},
            "required": ["text", "bcc"],
        },
    }
    labels = {"server": "default", "tool": "echo", "severity": "critical"}
    before = sample("portunusmcp_schema_drift_total", labels)
    await app.state.drift_detector.check("default", [mutated], "agent-readonly")
    assert sample("portunusmcp_schema_drift_total", labels) == before + 1


async def test_verify_failure_increments_counter(gateway: Gateway) -> None:
    await drive_session(gateway)
    before = sample("portunusmcp_audit_chain_verify_failures_total")
    await forge_chain_from(2)  # regenerated chain: self-consistent but unsignable
    public_key = signing.load_public_key(settings.signing_public_key_file)
    _, failure = await verify_increment(async_session, public_key)
    assert failure is not None
    assert sample("portunusmcp_audit_chain_verify_failures_total") == before + 1


async def test_unknown_tool_names_share_one_bounded_label(gateway: Gateway) -> None:
    labels = {
        "identity": "agent-readonly",
        "server": "default",
        "tool": "other",
        "decision": "DENY_RBAC",
        "mode": "enforce",
    }
    before = sample("portunusmcp_tool_calls_total", labels)
    names = [f"attacker-name-{i}" for i in range(10)]
    async with connect(gateway.url, gateway.keys["agent-readonly"]) as session:
        await session.list_tools()
        for name in names:
            with pytest.raises(McpError):
                await session.call_tool(name, {})

    assert sample("portunusmcp_tool_calls_total", labels) == before + len(names)
    for name in names:
        assert sample("portunusmcp_tool_calls_total", {**labels, "tool": name}) == 0
