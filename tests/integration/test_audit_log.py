"""Audit chain integration (§4.8/§11): every decision point writes a chained row,
the basic verifier validates the chain, tampering is caught, concurrent writes don't
collide, and an unrecordable action is denied (§5)."""

import asyncio
import logging
import os
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest
import redis.asyncio as aioredis
from cryptography.hazmat.primitives.asymmetric import ec
from mcp import McpError
from redis.asyncio.client import Pipeline
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import select, text

from services.gateway import signing
from services.gateway.audit_log import GENESIS_HASH, POINTER_KEY, AuditWriter
from services.gateway.config import settings
from services.gateway.db import AuditLog, async_session
from services.gateway.decision import EventType
from services.gateway.main import app
from tests.integration.conftest import Gateway
from tests.integration.test_policy_scoping import connect


async def drive_session(gateway: Gateway) -> None:
    """initialize → tools/list → allowed call → denied call, as agent-readonly."""
    async with connect(gateway.url, gateway.keys["agent-readonly"]) as session:
        await session.list_tools()
        await session.call_tool("echo", {"text": "hi"})
        with pytest.raises(McpError):
            await session.call_tool("add", {"a": 1, "b": 2})


async def fetch_rows() -> list[AuditLog]:
    async with async_session() as db:
        return list((await db.execute(select(AuditLog).order_by(AuditLog.seq))).scalars())


def run_verifier() -> "subprocess.CompletedProcess[str]":
    # Point the subprocess at the per-run keyring, not any local secrets/ directory.
    env = dict(os.environ, SIGNING_PUBLIC_KEYS_DIR=settings.signing_public_keys_dir)
    return subprocess.run(
        [sys.executable, "scripts/verify_audit_chain.py"],
        capture_output=True,
        text=True,
        env=env,
    )


def fail_next_pipeline_execute(monkeypatch: pytest.MonkeyPatch) -> None:
    original_execute = Pipeline.execute
    failed = False

    async def fail_once(self: Pipeline, *args: Any, **kwargs: Any) -> Any:
        nonlocal failed
        if not failed:
            failed = True
            raise RedisConnectionError("pointer write failed")
        return await original_execute(self, *args, **kwargs)

    monkeypatch.setattr(Pipeline, "execute", fail_once)


async def test_decision_points_write_chained_rows(gateway: Gateway) -> None:
    await drive_session(gateway)
    rows = await fetch_rows()

    # Row 0 is the boot-time activation (item 19); the session's rows follow.
    assert [r.event_type for r in rows] == [
        "POLICY_ACTIVATED",
        "SESSION_START",
        "TOOLS_LIST",
        "ALLOW",
        "DENY_RBAC",
    ]
    assert rows[0].identity_id == "startup"
    assert all(r.identity_id == "agent-readonly" for r in rows[1:])
    assert all(r.policy_version == 1 for r in rows)
    assert rows[3].tool_name == "echo"
    assert rows[4].tool_name == "add"
    assert rows[2].payload["served_tools"] == ["echo"]
    assert rows[2].payload["pruned_tools"] == ["add"]

    assert rows[0].prev_hash == GENESIS_HASH
    for prev, row in zip(rows, rows[1:], strict=False):
        assert row.prev_hash == prev.curr_hash

    # Every row is ECDSA-signed by the gateway's key (item 11).
    public_key = signing.load_public_key(settings.signing_public_key_file)
    assert all(signing.verify(public_key, r.signature, r.curr_hash) for r in rows)


async def test_deny_error_carries_audit_id(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-readonly"]) as session:
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("add", {"a": 1, "b": 2})
    rows = await fetch_rows()
    deny_row = rows[-1]
    assert deny_row.event_type == "DENY_RBAC"
    assert excinfo.value.error.data["audit_id"] == str(deny_row.seq)


async def test_verifier_passes_then_catches_tampering(gateway: Gateway) -> None:
    await drive_session(gateway)

    result = await asyncio.to_thread(run_verifier)
    assert result.returncode == 0, result.stdout + result.stderr

    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE audit_log SET payload = jsonb_set(payload, '{tool_name}', '\"evil\"')"
                " WHERE event_type = 'ALLOW'"
            )
        )
        await db.commit()

    result = await asyncio.to_thread(run_verifier)
    assert result.returncode == 1
    assert "TAMPERED" in result.stdout


async def test_pointer_write_failure_recovers_from_postgres(
    gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    writer: AuditWriter = app.state.audit_writer
    before = (await fetch_rows())[-1]
    fail_next_pipeline_execute(monkeypatch)

    with pytest.raises(RedisConnectionError, match="pointer write failed"):
        await writer.write(EventType.ALLOW, "pointer-test", tool_name="echo")

    failed_row = (await fetch_rows())[-1]
    assert failed_row.prev_hash == before.curr_hash
    assert await app.state.redis.get(POINTER_KEY) is None

    recovered_seq = await writer.write(EventType.ALLOW, "pointer-test", tool_name="echo")
    recovered_row = (await fetch_rows())[-1]
    assert recovered_row.seq == recovered_seq
    assert recovered_row.prev_hash == failed_row.curr_hash
    assert await app.state.redis.get(POINTER_KEY) == recovered_row.curr_hash.encode()

    result = await asyncio.to_thread(run_verifier)
    assert result.returncode == 0, result.stdout + result.stderr


async def test_pointer_delete_failure_recovers_after_restart(
    gateway: Gateway,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    writer: AuditWriter = app.state.audit_writer
    before = (await fetch_rows())[-1]
    fail_next_pipeline_execute(monkeypatch)
    original_delete = app.state.redis.delete

    async def fail_delete(*args: Any, **kwargs: Any) -> None:
        raise RedisConnectionError("pointer delete failed")

    monkeypatch.setattr(app.state.redis, "delete", fail_delete)
    with caplog.at_level(logging.ERROR, logger="services.gateway.audit_log"):
        with pytest.raises(RedisConnectionError, match="pointer write failed"):
            await writer.write(EventType.ALLOW, "pointer-test", tool_name="echo")
    monkeypatch.setattr(app.state.redis, "delete", original_delete)

    failed_row = (await fetch_rows())[-1]
    assert failed_row.prev_hash == before.curr_hash
    assert await app.state.redis.get(POINTER_KEY) == before.curr_hash.encode()
    assert "audit_pointer_invalidation_failed" in caplog.text

    restarted = AuditWriter(
        app.state.redis,
        async_session,
        app.state.policy_store,
        app.state.signing_key,
        writer.key_id,
    )
    recovered_seq = await restarted.write(EventType.ALLOW, "pointer-test", tool_name="echo")
    recovered_row = (await fetch_rows())[-1]
    assert recovered_row.seq == recovered_seq
    assert recovered_row.prev_hash == failed_row.curr_hash
    assert await app.state.redis.get(POINTER_KEY) == recovered_row.curr_hash.encode()

    result = await asyncio.to_thread(run_verifier)
    assert result.returncode == 0, result.stdout + result.stderr


async def test_concurrent_audit_writes_do_not_collide(clean_audit: None) -> None:
    """§11's named test: 100 concurrent write() calls against the Redis-cached
    latest_audit_hash pointer — every seq unique, every curr_hash unique, and
    the chain contiguous with no gaps. One writer instance, deliberately: that
    is the supported deployment envelope (one gateway process owns one writer;
    multi-replica write ordering is the documented §10 deferral, and two writer
    instances demonstrably fork the chain via the WatchError retry re-insert)."""
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    writer = AuditWriter(
        redis_client,
        async_session,
        cast(Any, SimpleNamespace(engine=SimpleNamespace(version=1))),
        ec.generate_private_key(ec.SECP256R1()),
    )
    try:
        seqs = await asyncio.gather(
            *(writer.write(EventType.ALLOW, f"id-{i}", tool_name="echo") for i in range(100))
        )
    finally:
        await redis_client.aclose()

    assert len(set(seqs)) == 100
    rows = await fetch_rows()
    assert len(rows) == 100
    assert len({row.curr_hash for row in rows}) == 100
    assert rows[0].prev_hash == GENESIS_HASH
    for prev, row in zip(rows, rows[1:], strict=False):
        assert row.prev_hash == prev.curr_hash


async def test_unrecordable_call_is_denied(
    gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        await session.list_tools()  # prime the schema cache before breaking the writer
        writer = app.state.session_manager._writer

        async def broken_write(*args: Any, **kwargs: Any) -> int:
            raise ConnectionError("postgres down")

        monkeypatch.setattr(writer, "write", broken_write)
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "x"})
        assert "audit log unavailable" in excinfo.value.error.message
