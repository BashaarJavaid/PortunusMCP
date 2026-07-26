"""Cache invalidation end-to-end (ARCHITECTURE.md §8): SIGHUP policy hot-reload,
transparent schema re-fetch on cache miss/TTL expiry, and the (policy_version,
schema_hash) ETag on tools/list responses."""

import asyncio
import os
import signal
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as aioredis
import yaml
from mcp import McpError
from mcp.types import TextContent
from sqlalchemy import select

from services.gateway import upstream_client
from services.gateway.config import settings
from services.gateway.db import AuditLog, async_session
from services.gateway.main import app
from tests.integration.conftest import Gateway, policy_dict
from tests.integration.test_policy_scoping import connect


async def fetch_events() -> list[tuple[str, int]]:
    async with async_session() as db:
        rows = (await db.execute(select(AuditLog).order_by(AuditLog.seq))).scalars()
        return [(row.event_type, row.policy_version) for row in rows]


async def sighup_and_wait_for_activation(version: int) -> None:
    # Startup writes its own POLICY_ACTIVATED (item 19), so wait for the row that
    # carries the reloaded version, not just any activation.
    os.kill(os.getpid(), signal.SIGHUP)  # handled by the gateway's loop handler
    for _ in range(60):
        if ("POLICY_ACTIVATED", version) in await fetch_events():
            return
        await asyncio.sleep(0.05)
    pytest.fail(f"POLICY_ACTIVATED for v{version} never appeared after SIGHUP")


async def test_sighup_reload_applies_to_inflight_session(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-readonly"]) as session:
        with pytest.raises(McpError):  # v1 policy: readonly may not call add
            await session.call_tool("add", {"a": 1, "b": 2})

        gateway.policy_path.write_text(
            yaml.safe_dump(policy_dict(gateway.keys, readonly_tools=["echo", "add"], version=2))
        )
        await sighup_and_wait_for_activation(2)

        # The same in-flight session re-resolves against v2 on its next request (§8).
        tools = await session.list_tools()
        assert [tool.name for tool in tools.tools] == ["echo", "add"]
        result = await session.call_tool("add", {"a": 2, "b": 3})
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "5"

    events = await fetch_events()
    assert events[-1][1] == 2  # rows after activation carry the new version


async def test_broken_reload_keeps_last_known_good(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        gateway.policy_path.write_text("version: [broken\n")
        os.kill(os.getpid(), signal.SIGHUP)
        await asyncio.sleep(0.3)

        tools = await session.list_tools()  # old policy still enforced, gateway alive
        assert [tool.name for tool in tools.tools] == ["echo", "add"]

    # Only the boot-time activation (item 19) — the broken reload never activated.
    assert [event for event, _ in await fetch_events()].count("POLICY_ACTIVATED") == 1


async def test_runtime_preflight_failure_keeps_last_known_good(
    gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        app.state.upstream_runtime,
        "preflight",
        AsyncMock(side_effect=upstream_client.RuntimeError("image missing")),
    )
    gateway.policy_path.write_text(yaml.safe_dump(policy_dict(gateway.keys, version=2)))
    os.kill(os.getpid(), signal.SIGHUP)
    await asyncio.sleep(0.3)

    assert app.state.policy_store.engine.version == 1
    assert [event for event, _ in await fetch_events()].count("POLICY_ACTIVATED") == 1


async def test_call_without_listing_succeeds_via_transparent_refetch(gateway: Gateway) -> None:
    # Supersedes item 6's interim deny-on-never-listed behavior (§8 re-fetch).
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        result = await session.call_tool("echo", {"text": "no list first"})
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "no list first"


async def test_mid_session_cache_eviction_is_transparent(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        await session.list_tools()
        redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
        await redis_client.delete("schema:default")
        await redis_client.aclose()

        result = await session.call_tool("echo", {"text": "still works"})
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "still works"


async def test_ttl_expiry_refetches(gateway: Gateway) -> None:
    old_ttl = settings.schema_cache_ttl
    settings.schema_cache_ttl = 1
    try:
        async with connect(gateway.url, gateway.keys["agent-full"]) as session:
            await session.list_tools()
            await asyncio.sleep(1.2)  # let the schema key expire
            result = await session.call_tool("echo", {"text": "post-expiry"})
            assert isinstance(result.content[0], TextContent)
            assert result.content[0].text == "post-expiry"
    finally:
        settings.schema_cache_ttl = old_ttl


async def test_etag_stable_then_changes_on_policy_reload(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        first = await session.list_tools()
        second = await session.list_tools()
        assert first.meta is not None
        etag = first.meta["etag"]
        assert etag.startswith("1-")
        assert second.meta is not None and second.meta["etag"] == etag  # stable

        gateway.policy_path.write_text(yaml.safe_dump(policy_dict(gateway.keys, version=2)))
        await sighup_and_wait_for_activation(2)

        third = await session.list_tools()
        assert third.meta is not None
        assert third.meta["etag"].startswith("2-")
        assert third.meta["etag"] != etag
