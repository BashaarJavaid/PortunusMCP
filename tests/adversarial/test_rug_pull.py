"""ARCHITECTURE.md §11: simulate a rug pull at each severity tier and assert the
classification AND the action — description-only blocks by default (item 36a, and the
knob loosens it back to log-only), required-change blocks, a rename is treated as a
new unapproved tool. Plus the re-approval flow."""

import httpx
import pytest
from mcp import McpError
from mcp.types import TextContent
from sqlalchemy import select

from services.gateway.config import settings
from services.gateway.db import AuditLog, async_session
from tests.adversarial.conftest import Gateway, set_mutation
from tests.integration.test_policy_scoping import connect


async def drift_events() -> list[str]:
    async with async_session() as db:
        rows = (
            await db.execute(
                select(AuditLog.event_type)
                .where(AuditLog.event_type.like("DRIFT_%"))
                .order_by(AuditLog.seq)
            )
        ).scalars()
        return list(rows)


async def baseline(gateway: Gateway) -> None:
    """First session: the 'none' shape becomes the approved baseline."""
    async with connect(gateway.url, gateway.keys["dev"]) as session:
        await session.list_tools()


async def test_description_only_drift_blocks_by_default(drift_gateway: Gateway) -> None:
    # Item 36a: a description changed after human approval is the rug pull —
    # High by default, so the call is DENY_DRIFT until re-approval.
    await baseline(drift_gateway)
    set_mutation("description")
    async with connect(drift_gateway.url, drift_gateway.keys["dev"]) as session:
        await session.list_tools()
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi"})
        assert excinfo.value.error.data["event_type"] == "DENY_DRIFT"

        # Same drift again in the same shape: logged once, not per poll.
        await session.list_tools()
    events = await drift_events()
    assert events == ["DRIFT_HIGH"]


async def test_description_drift_severity_is_configurable(
    drift_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The knob loosens too: "low" restores the pre-item-36 log-only posture.
    monkeypatch.setattr(settings, "drift_description_severity", "low")
    await baseline(drift_gateway)
    set_mutation("description")
    async with connect(drift_gateway.url, drift_gateway.keys["dev"]) as session:
        await session.list_tools()
        result = await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi"})
        assert isinstance(result.content[0], TextContent)  # still allowed
    assert await drift_events() == ["DRIFT_LOW"]


async def test_optional_param_drift_is_logged_medium_and_allowed(
    drift_gateway: Gateway,
) -> None:
    await baseline(drift_gateway)
    set_mutation("optional_param")
    async with connect(drift_gateway.url, drift_gateway.keys["dev"]) as session:
        await session.list_tools()
        await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi"})
    assert await drift_events() == ["DRIFT_MEDIUM"]


async def test_required_change_is_critical_and_blocks(drift_gateway: Gateway) -> None:
    await baseline(drift_gateway)
    set_mutation("required_change")
    async with connect(drift_gateway.url, drift_gateway.keys["dev"]) as session:
        await session.list_tools()
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi"})
        assert excinfo.value.error.data["event_type"] == "DENY_DRIFT"
    assert await drift_events() == ["DRIFT_CRITICAL"]


async def test_param_removed_is_high_and_blocks(drift_gateway: Gateway) -> None:
    await baseline(drift_gateway)
    set_mutation("remove_param")
    async with connect(drift_gateway.url, drift_gateway.keys["dev"]) as session:
        await session.list_tools()
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_email", {"to": "a@b.c"})
        assert excinfo.value.error.data["event_type"] == "DENY_DRIFT"
    assert await drift_events() == ["DRIFT_HIGH"]


async def test_rename_is_critical_and_blocked_as_unapproved(drift_gateway: Gateway) -> None:
    await baseline(drift_gateway)
    set_mutation("rename")
    async with connect(drift_gateway.url, drift_gateway.keys["dev"]) as session:
        await session.list_tools()
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_mail", {"to": "a@b.c", "subject": "hi"})
        assert excinfo.value.error.data["event_type"] == "DENY_DRIFT"
    events = await drift_events()
    assert events == ["DRIFT_CRITICAL"]  # rename, not rename + removal noise


async def test_approve_flow_unblocks(drift_gateway: Gateway) -> None:
    await baseline(drift_gateway)
    set_mutation("remove_param")
    async with connect(drift_gateway.url, drift_gateway.keys["dev"]) as session:
        await session.list_tools()
        with pytest.raises(McpError):
            await session.call_tool("send_email", {"to": "a@b.c"})

        approve_url = f"{drift_gateway.url}/admin/tools/default/send_email/approve"
        async with httpx.AsyncClient() as client:
            # Non-admin identity: 403. Bad key: 401.
            response = await client.post(
                approve_url, headers={"X-PortunusMCP-Key": drift_gateway.keys["dev"]}
            )
            assert response.status_code == 403
            response = await client.post(approve_url, headers={"X-PortunusMCP-Key": "nope"})
            assert response.status_code == 401

            headers = {"X-PortunusMCP-Key": drift_gateway.keys["admin"]}
            listing = await client.get(
                f"{drift_gateway.url}/admin/baselines/flagged", headers=headers
            )
            assert listing.status_code == 200
            assert listing.json()["items"][0]["severity"] == "high"
            detail = await client.get(
                f"{drift_gateway.url}/admin/baselines/default/send_email",
                headers=headers,
            )
            assert detail.status_code == 200
            assert detail.json()["observed_schema"] is not None

            response = await client.post(approve_url, headers=headers)
            assert response.status_code == 200
            decision = response.json()
            assert decision["event_type"] == "APPROVED"
            assert decision["decision"] == "allow"
            assert decision["audit_id"] is not None

        # The same call now succeeds against the newly approved baseline.
        result = await session.call_tool("send_email", {"to": "a@b.c"})
        assert isinstance(result.content[0], TextContent)

    async with async_session() as db:
        approved = (
            await db.execute(select(AuditLog).where(AuditLog.event_type == "APPROVED"))
        ).scalar_one()
    assert approved.identity_id == "admin"  # who approved is on the record
