"""Policy versioning end to end (§4.8, item 19): every activation leaves a revision
snapshot + policy_versions row, forward activation is monotonic (same version with
different content is rejected fail-closed), and admin rollback re-activates a prior
snapshot in memory with a fresh POLICY_ACTIVATED audit record."""

import asyncio
import hashlib
import os
import secrets
import signal
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
import yaml
from mcp import McpError
from sqlalchemy import select

from services.gateway import upstream_client
from services.gateway.config import settings
from services.gateway.db import AuditLog, PolicyVersion, async_session
from services.gateway.main import app
from tests.integration.conftest import (
    ECHO_SERVER,
    Gateway,
    _key_hash,
    running_gateway,
    server_spec,
)
from tests.integration.test_cache_invalidation import sighup_and_wait_for_activation
from tests.integration.test_policy_scoping import connect


def _policy(keys: dict[str, str], version: int = 1, agent_tools: list[str] | None = None) -> dict:
    return {
        "version": version,
        "servers": {"default": server_spec(f"{sys.executable} {ECHO_SERVER}")},
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "allowed_servers": [
                    {"server_id": "default", "allowed_tools": agent_tools or ["echo"]}
                ],
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
async def versioned_gateway(clean_audit: None, tmp_path: Path) -> AsyncIterator[Gateway]:
    keys = {"agent": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(_policy(keys)))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


async def version_rows() -> list[PolicyVersion]:
    async with async_session() as db:
        result = await db.execute(select(PolicyVersion).order_by(PolicyVersion.version))
        return list(result.scalars())


async def activation_payloads() -> list[dict]:
    async with async_session() as db:
        result = await db.execute(
            select(AuditLog).where(AuditLog.event_type == "POLICY_ACTIVATED").order_by(AuditLog.seq)
        )
        return [row.payload for row in result.scalars()]


async def test_startup_registers_version_snapshot_row_and_audit(
    versioned_gateway: Gateway,
) -> None:
    raw = versioned_gateway.policy_path.read_bytes()
    snapshot = Path(settings.policy_revisions_dir) / "v1.yaml"
    assert snapshot.read_bytes() == raw  # exact file bytes, never re-serialized

    (row,) = await version_rows()
    assert row.version == 1
    assert row.content_hash == hashlib.sha256(raw).hexdigest()
    assert row.activated_by == "startup"

    (payload,) = await activation_payloads()
    assert payload["identity_id"] == "startup"
    assert payload["new_version"] == 1 and payload["old_version"] is None


async def test_sighup_bump_snapshots_and_records(versioned_gateway: Gateway) -> None:
    v2 = yaml.safe_dump(_policy(versioned_gateway.keys, version=2, agent_tools=["echo", "add"]))
    versioned_gateway.policy_path.write_text(v2)
    await sighup_and_wait_for_activation(2)

    assert (Path(settings.policy_revisions_dir) / "v2.yaml").read_text() == v2
    rows = await version_rows()
    assert [(row.version, row.activated_by) for row in rows] == [(1, "startup"), (2, "operator")]
    assert rows[1].content_hash == hashlib.sha256(v2.encode()).hexdigest()
    assert (await activation_payloads())[-1]["new_version"] == 2


async def test_same_version_different_content_is_rejected(versioned_gateway: Gateway) -> None:
    original_hash = (await version_rows())[0].content_hash
    versioned_gateway.policy_path.write_text(
        yaml.safe_dump(_policy(versioned_gateway.keys, version=1, agent_tools=["echo", "add"]))
    )
    os.kill(os.getpid(), signal.SIGHUP)
    await asyncio.sleep(0.3)

    async with connect(versioned_gateway.url, versioned_gateway.keys["agent"]) as session:
        with pytest.raises(McpError):  # last-known-good v1 still enforced: no "add"
            await session.call_tool("add", {"a": 1, "b": 2})
    (row,) = await version_rows()  # no new row, original hash untouched
    assert row.content_hash == original_hash
    assert len(await activation_payloads()) == 1  # startup only


async def test_rollback_reactivates_prior_revision(versioned_gateway: Gateway) -> None:
    keys = versioned_gateway.keys
    versioned_gateway.policy_path.write_text(
        yaml.safe_dump(_policy(keys, version=2, agent_tools=["echo", "add"]))
    )
    await sighup_and_wait_for_activation(2)

    async with connect(versioned_gateway.url, keys["agent"]) as session:
        await session.call_tool("add", {"a": 1, "b": 2})  # v2 grants add

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{versioned_gateway.url}/admin/policy/rollback/1",
                headers={"X-PortunusMCP-Key": keys["ops-admin"]},
            )
        assert response.status_code == 200
        decision = response.json()
        assert decision["event_type"] == "POLICY_ACTIVATED"
        assert decision["policy_version"] == 1

        with pytest.raises(McpError):  # the live session re-resolves against v1
            await session.call_tool("add", {"a": 1, "b": 2})

    rows = await version_rows()
    assert rows[0].activated_by == "ops-admin"  # refreshed by the rollback
    assert rows[0].activated_at > rows[1].activated_at
    payload = (await activation_payloads())[-1]
    assert payload["rollback"] is True
    assert payload["old_version"] == 2 and payload["new_version"] == 1
    assert payload["identity_id"] == "ops-admin"


async def test_rollback_authz_and_missing_version(versioned_gateway: Gateway) -> None:
    url = f"{versioned_gateway.url}/admin/policy/rollback/1"
    async with httpx.AsyncClient() as client:
        assert (await client.post(url)).status_code == 401
        response = await client.post(
            url, headers={"X-PortunusMCP-Key": versioned_gateway.keys["agent"]}
        )
        assert response.status_code == 403
        response = await client.post(
            f"{versioned_gateway.url}/admin/policy/rollback/99",
            headers={"X-PortunusMCP-Key": versioned_gateway.keys["ops-admin"]},
        )
        assert response.status_code == 404


async def test_rollback_rejects_unavailable_runtime(
    versioned_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    versioned_gateway.policy_path.write_text(
        yaml.safe_dump(_policy(versioned_gateway.keys, version=2))
    )
    await sighup_and_wait_for_activation(2)
    monkeypatch.setattr(
        app.state.upstream_runtime,
        "preflight",
        AsyncMock(side_effect=upstream_client.RuntimeError("image missing")),
    )

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{versioned_gateway.url}/admin/policy/rollback/1",
            headers={"X-PortunusMCP-Key": versioned_gateway.keys["ops-admin"]},
        )

    assert response.status_code == 409
    assert app.state.policy_store.engine.version == 2
