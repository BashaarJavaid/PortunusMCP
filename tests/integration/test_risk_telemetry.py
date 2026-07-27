"""Risk telemetry end to end: repeated denials raise the next scored call's risk,
failed authentication does not affect another source's score (item 43), and a tool's
drift history keeps counting after re-approval (audit log, not tool_baselines, is the
source of truth). Business hours are dropped so scores are time-of-day independent."""

import secrets
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
import redis.asyncio as aioredis
import yaml
from mcp import McpError
from mcp.types import TextContent
from sqlalchemy import select

from services.gateway import risk_engine
from services.gateway.config import settings
from services.gateway.db import AuditLog, async_session
from services.gateway.policy_engine import RiskPolicy
from tests.adversarial.conftest import set_mutation, upstream_command
from tests.integration.conftest import ECHO_SERVER, Gateway, _key_hash, running_gateway
from tests.integration.test_policy_scoping import connect


def _policy(keys: dict[str, str], allowed_tool: str) -> dict:
    return {
        "version": 1,
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "allowed_servers": [{"server_id": "default", "allowed_tools": [allowed_tool]}],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "admin": True,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }


@pytest.fixture
def no_business_hours(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        risk_engine,
        "FACTORS",
        [fn for fn in risk_engine.FACTORS if fn is not risk_engine._business_hours],
    )


@pytest.fixture
async def telemetry_gateway(
    clean_audit: None, no_business_hours: None, tmp_path: Path
) -> AsyncIterator[Gateway]:
    keys = {"agent": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(_policy(keys, "echo")))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


async def allow_factors(tool_name: str) -> set[str]:
    async with async_session() as db:
        rows = (
            (
                await db.execute(
                    select(AuditLog)
                    .where(AuditLog.event_type == "ALLOW", AuditLog.tool_name == tool_name)
                    .order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
    assert rows, f"no ALLOW row for {tool_name!r}"
    return {f["factor"] for f in rows[-1].payload.get("risk_factors", [])}


async def test_repeated_denials_raise_the_next_scored_call(telemetry_gateway: Gateway) -> None:
    async with connect(telemetry_gateway.url, telemetry_gateway.keys["agent"]) as session:
        # Walk the identity past the denial threshold (default >3 in 10 min).
        for _ in range(4):
            with pytest.raises(McpError) as excinfo:
                await session.call_tool("add", {"a": 1, "b": 2})
            assert excinfo.value.error.data["event_type"] == "DENY_RBAC"

        # The next allowed call is scored with the denial history behind it.
        result = await session.call_tool("echo", {"text": "hi"})
        assert isinstance(result.content[0], TextContent)
    assert await allow_factors("echo") == {"prior_denial_rate"}


async def test_auth_failures_throttle_the_source_without_changing_victim_risk(
    telemetry_gateway: Gateway,
) -> None:
    # Credential stuffing: the sixth wrong key is source-throttled.
    async with httpx.AsyncClient() as client:
        for attempt in range(6):
            response = await client.post(
                f"{telemetry_gateway.url}/mcp/",
                headers={
                    "X-PortunusMCP-Key": "not-a-real-key",
                    "X-Forwarded-For": "198.51.100.10",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            assert response.status_code == (401 if attempt < 5 else 429)
        assert int(response.headers["Retry-After"]) > 0

    # A different source's valid call remains unchanged by the attacker's failures.
    async with connect(telemetry_gateway.url, telemetry_gateway.keys["agent"]) as session:
        result = await session.call_tool("echo", {"text": "hi"})
        assert isinstance(result.content[0], TextContent)
    assert await allow_factors("echo") == set()


async def test_auth_failure_budget_is_shared_with_admin_and_missing_keys_stay_401(
    telemetry_gateway: Gateway,
) -> None:
    source = "198.51.100.20"
    async with httpx.AsyncClient() as client:
        for _ in range(6):
            await client.post(
                f"{telemetry_gateway.url}/mcp/",
                headers={"X-PortunusMCP-Key": "wrong", "X-Forwarded-For": source},
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
        blocked = await client.get(
            f"{telemetry_gateway.url}/admin/policy",
            headers={
                "X-PortunusMCP-Key": telemetry_gateway.keys["ops-admin"],
                "X-Forwarded-For": source,
            },
        )
        assert blocked.status_code == 429
        assert blocked.json()["detail"] == "authentication rate limit exceeded"
        assert int(blocked.headers["Retry-After"]) > 0

        missing = await client.post(
            f"{telemetry_gateway.url}/mcp/",
            headers={"X-Forwarded-For": source},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert missing.status_code == 401


@pytest.fixture
async def drift_history_gateway(
    clean_audit: None, no_business_hours: None, tmp_path: Path
) -> AsyncIterator[Gateway]:
    keys = {"agent": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(_policy(keys, "send_email")))
    async with running_gateway(policy_path, upstream_command("none"), keys) as gw:
        yield gw


async def test_drift_history_survives_reapproval(drift_history_gateway: Gateway) -> None:
    gw = drift_history_gateway
    # Baseline the pristine shape, then drift it twice (High: description change,
    # item 36a; Medium: optional param) — two DRIFT_* audit events. The block from
    # the first drift is cleared by the re-approval below, before the scored call.
    async with connect(gw.url, gw.keys["agent"]) as session:
        await session.list_tools()
    for mutation in ("description", "optional_param"):
        set_mutation(mutation)
        async with connect(gw.url, gw.keys["agent"]) as session:
            await session.list_tools()

    # Re-approval promotes the observed schema and clears drift-in-review...
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{gw.url}/admin/tools/default/send_email/approve",
            headers={"X-PortunusMCP-Key": gw.keys["ops-admin"]},
        )
        assert response.status_code == 200

    # ...but the tool's drift history keeps scoring: the audit rows don't reset.
    async with connect(gw.url, gw.keys["agent"]) as session:
        result = await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi"})
        assert isinstance(result.content[0], TextContent)
    factors = await allow_factors("send_email")
    assert "drift_history" in factors
    assert "drift_in_review" not in factors  # cleared by the approval, §4.8


class _DriftInReview:
    """Detector stub: the tool has unresolved observed drift, no drift history."""

    async def has_pending_drift(self, server_id: str, tool_name: str) -> bool:
        return True

    async def recent_drift_count(self, server_id: str, tool_name: str, window: int) -> int:
        return 0

    async def is_suspicious(self, server_id: str, tool_name: str) -> bool:
        return False


async def test_fifty_approvals_cannot_zero_behavioral_scoring(
    clean_audit: None, no_business_hours: None
) -> None:
    """Item 33: the decay offset is capped at risk_decay_max and expires, so a
    rubber-stamped (identity, tool) pair still lands in the CHALLENGE band when a
    frequency-spiking, denial-heavy call with drift in review arrives. Uncapped,
    50 approvals would be a 250-point offset zeroing all 60 behavioral points."""
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    try:
        engine = risk_engine.RiskEngine(redis_client, cast(Any, _DriftInReview()))
        for _ in range(50):
            await engine.apply_decay("agent", "default", "echo")
        assert await redis_client.ttl("risk:decay:agent:default:echo") > 0  # ages out
        for _ in range(4):  # past the >3-denials/window threshold
            await engine.record_denial("agent")
        score = 0
        for _ in range(11):  # past the >10-calls/window frequency threshold
            score, _ = await engine.score("agent", "default", "echo", {}, RiskPolicy())
        assert score >= risk_engine.RISK_CHALLENGE_MIN
    finally:
        await redis_client.aclose()
