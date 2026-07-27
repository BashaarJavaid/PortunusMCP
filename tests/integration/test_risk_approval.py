"""Risk Engine stage 6 + the human-approval lifecycle, end to end (item 16, §11):
a high-risk call lands in HUMAN_APPROVAL_REQUIRED (not ALLOW), an admin grant lets
the retry through exactly once, mutated-arguments retries hit the TOCTOU check, and
the approval applies one risk-decay step to the pair's behavioral factors.

Scores are made time-of-day independent by dropping the business-hours factor (it's
unit-tested) and lowering the frequency-spike threshold to 2: echo is tiered medium
(20), "prod-*" arguments add 30, a spike adds 20 — so 20 → ALLOW, 50 → CHALLENGE,
70 → HUMAN_APPROVAL_REQUIRED, and one decay step (-5, behavioral only) makes the
same call score 65 → CHALLENGE."""

import asyncio
import json
import os
import secrets
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import yaml
from mcp import McpError
from mcp.types import TextContent
from sqlalchemy import select

from services.gateway import risk_engine
from services.gateway.approvals import APPROVAL_META_KEY
from services.gateway.config import settings
from services.gateway.db import AuditLog, async_session
from tests.integration.conftest import ECHO_SERVER, Gateway, _key_hash, running_gateway
from tests.integration.test_policy_scoping import connect


@pytest.fixture
async def risk_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Gateway]:
    monkeypatch.setattr(
        risk_engine,
        "FACTORS",
        [fn for fn in risk_engine.FACTORS if fn is not risk_engine._business_hours],
    )
    monkeypatch.setattr(settings, "risk_freq_threshold", 2)
    keys = {"agent": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy = {
        "version": 1,
        "risk": {
            "tool_sensitivity": {"echo": "medium"},
            "protected_repos": ["prod-*"],
        },
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "admin": True,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }
    policy_path = tmp_path / "risk-policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


async def test_risk_scoring_and_approval_lifecycle(risk_gateway: Gateway) -> None:
    async with connect(risk_gateway.url, risk_gateway.keys["agent"]) as session:
        # Tier alone (20) stays under every threshold: forwarded and allowed.
        result = await session.call_tool("echo", {"text": "hello"})
        assert isinstance(result.content[0], TextContent)

        # Protected argument (20+30=50): terminal CHALLENGE, no upstream forward.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "prod-db"})
        data = excinfo.value.error.data
        assert data["event_type"] == "CHALLENGE"
        assert data["decision"] == "challenge"
        assert data["risk_score"] == 50

        # Third scored call trips the spike (+20 → 70): held for human approval.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "prod-db"})
        data = excinfo.value.error.data
        assert data["event_type"] == "HUMAN_APPROVAL_REQUIRED"
        assert data["decision"] == "human_approval_required"
        assert data["risk_score"] == 70
        assert {f["factor"] for f in data["risk_factors"]} == {
            "tool_sensitivity",
            "protected_repository",
            "call_frequency",
        }
        approval_id = data["approval_id"]
        assert approval_id

        # Approval is an admin-only action.
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{risk_gateway.url}/admin/approvals/{approval_id}/approve",
                headers={"X-PortunusMCP-Key": risk_gateway.keys["agent"]},
            )
            assert response.status_code == 403

            headers = {"X-PortunusMCP-Key": risk_gateway.keys["ops-admin"]}
            listing = await client.get(f"{risk_gateway.url}/admin/approvals", headers=headers)
            assert listing.status_code == 200
            assert listing.json()["items"][0]["approval_id"] == approval_id
            detail = await client.get(
                f"{risk_gateway.url}/admin/approvals/{approval_id}", headers=headers
            )
            assert detail.status_code == 200
            assert detail.json()["arguments"] == {"text": "prod-db"}
            assert detail.json()["decision"]["event_type"] == "HUMAN_APPROVAL_REQUIRED"

        cli = str(Path(sys.executable).with_name("portunusmcp"))
        cli_env = {
            **os.environ,
            "PORTUNUSMCP_URL": risk_gateway.url,
            "PORTUNUSMCP_ADMIN_KEY": risk_gateway.keys["ops-admin"],
        }
        listed = await asyncio.to_thread(
            subprocess.run,
            [cli, "--json", "approvals", "list"],
            capture_output=True,
            text=True,
            env=cli_env,
        )
        assert listed.returncode == 0, listed.stderr
        assert json.loads(listed.stdout)["items"][0]["approval_id"] == approval_id
        approved = await asyncio.to_thread(
            subprocess.run,
            [cli, "--json", "--yes", "approvals", "approve", approval_id],
            capture_output=True,
            text=True,
            env=cli_env,
        )
        assert approved.returncode == 0, approved.stderr
        assert json.loads(approved.stdout)["event_type"] == "APPROVED"

        # TOCTOU: the retry carries mutated arguments — neither version forwards.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo", {"text": "prod-mutated"}, meta={APPROVAL_META_KEY: approval_id}
            )
        assert excinfo.value.error.data["event_type"] == "DENY_APPROVAL_MISMATCH"

        # The approved retry with the original arguments forwards exactly once...
        result = await session.call_tool(
            "echo", {"text": "prod-db"}, meta={APPROVAL_META_KEY: approval_id}
        )
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "prod-db"

        # ...and reusing the approval is a replay class.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo", {"text": "prod-db"}, meta={APPROVAL_META_KEY: approval_id}
            )
        assert excinfo.value.error.data["event_type"] == "DENY_REPLAY"

        # Risk decay: the approval discounted the behavioral subtotal by one step
        # (-5), so the call that scored 70 now scores 65 — a challenge, not another
        # approval — while the static tier contribution is untouched.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "prod-db"})
        data = excinfo.value.error.data
        assert data["event_type"] == "CHALLENGE"
        assert data["risk_score"] == 65

    async with async_session() as db:
        held = (
            (
                await db.execute(
                    select(AuditLog).where(AuditLog.event_type == "HUMAN_APPROVAL_REQUIRED")
                )
            )
            .scalars()
            .all()
        )
        assert len(held) == 1
        assert held[0].risk_score == 70  # §4.8: score + factors land in the audit log
        assert {f["factor"] for f in held[0].payload["risk_factors"]} == {
            "tool_sensitivity",
            "protected_repository",
            "call_frequency",
        }
        events = (
            (
                await db.execute(
                    select(AuditLog.event_type)
                    .where(
                        AuditLog.event_type.in_(
                            [
                                "CHALLENGE",
                                "HUMAN_APPROVAL_REQUIRED",
                                "APPROVED",
                                "DENY_APPROVAL_MISMATCH",
                                "DENY_REPLAY",
                            ]
                        )
                    )
                    .order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
        assert events == [
            "CHALLENGE",
            "HUMAN_APPROVAL_REQUIRED",
            "APPROVED",
            "DENY_APPROVAL_MISMATCH",
            "DENY_REPLAY",
            "CHALLENGE",
        ]


async def test_expired_approval_cannot_be_granted_or_redeemed(
    risk_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "approval_ttl_seconds", 0)  # born expired
    async with connect(risk_gateway.url, risk_gateway.keys["agent"]) as session:
        for _ in range(2):  # walk the counter up to the spike (50 → CHALLENGE each)
            with pytest.raises(McpError):
                await session.call_tool("echo", {"text": "prod-db"})
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "prod-db"})
        data = excinfo.value.error.data
        assert data["event_type"] == "HUMAN_APPROVAL_REQUIRED"
        approval_id = data["approval_id"]

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{risk_gateway.url}/admin/approvals/{approval_id}/approve",
                headers={"X-PortunusMCP-Key": risk_gateway.keys["ops-admin"]},
            )
        assert response.status_code == 404
        assert "expired" in response.json()["detail"]

        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo", {"text": "prod-db"}, meta={APPROVAL_META_KEY: approval_id}
            )
        assert excinfo.value.error.data["event_type"] == "EXPIRED"
