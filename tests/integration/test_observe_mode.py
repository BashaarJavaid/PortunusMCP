"""Item 49 acceptance: observe exposes and forwards a would-be RBAC denial while
preserving its canonical signed audit Decision and the enforcing HTTP edge."""

import secrets
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import yaml
from mcp.types import TextContent
from sqlalchemy import select

from services.gateway.db import AuditLog, async_session
from services.gateway.decision import DecisionMode
from tests.integration.conftest import ECHO_SERVER, Gateway, policy_dict, running_gateway
from tests.integration.test_audit_log import run_verifier
from tests.integration.test_policy_scoping import connect


@pytest.fixture
async def observe_gateway(clean_audit: None, tmp_path: Path) -> AsyncIterator[Gateway]:
    keys = {
        "agent-readonly": secrets.token_urlsafe(32),
        "agent-full": secrets.token_urlsafe(32),
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy_dict(keys)))
    async with running_gateway(
        policy_path,
        f"{sys.executable} {ECHO_SERVER}",
        keys,
        mode=DecisionMode.OBSERVE,
    ) as gateway:
        yield gateway


async def test_observe_forwards_denied_call_and_records_would_be_decision(
    observe_gateway: Gateway,
) -> None:
    async with connect(observe_gateway.url, observe_gateway.keys["agent-readonly"]) as session:
        tools = await session.list_tools()
        assert [tool.name for tool in tools.tools] == ["echo", "add"]
        result = await session.call_tool("add", {"a": 2, "b": 3})
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "5"

    async with async_session() as db:
        rows = list(
            (
                await db.execute(
                    select(AuditLog)
                    .where(AuditLog.identity_id == "agent-readonly")
                    .order_by(AuditLog.seq)
                )
            ).scalars()
        )
    tools_list = next(row for row in rows if row.event_type == "TOOLS_LIST")
    denied = next(row for row in rows if row.event_type == "DENY_RBAC")
    assert tools_list.payload["mode"] == "observe"
    assert tools_list.payload["served_tools"] == ["echo", "add"]
    assert tools_list.payload["pruned_tools"] == []
    assert tools_list.payload["would_prune_tools"] == ["add"]
    assert denied.payload["mode"] == "observe"
    assert denied.payload["matched_rules"] == ["policy-v1:rbac"]
    assert denied.risk_score is not None
    assert isinstance(denied.payload["risk_factors"], list)
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{observe_gateway.url}/admin/decisions/{denied.seq}",
            headers={"X-PortunusMCP-Key": observe_gateway.keys["agent-full"]},
        )
    assert response.status_code == 200
    decision = response.json()
    assert decision["event_type"] == "DENY_RBAC"
    assert decision["decision"] == "deny"
    assert decision["mode"] == "observe"
    assert decision["risk_score"] == denied.risk_score
    assert decision["risk_factors"] == denied.payload["risk_factors"]
    assert run_verifier().returncode == 0


async def test_observe_does_not_weaken_http_auth(observe_gateway: Gateway) -> None:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{observe_gateway.url}/mcp/",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
    assert response.status_code == 401
