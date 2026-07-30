"""Item 52: verified observe traffic -> validate/simulate/rollout/enforce policy."""

import asyncio
import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import yaml
from mcp import McpError
from sqlalchemy import func, select

from services.gateway.db import AuditLog, async_session
from services.gateway.decision import DecisionMode
from services.gateway.policy_engine import load_bytes
from tests.integration.conftest import (
    ECHO_SERVER,
    _key_hash,
    running_gateway,
    server_spec,
)
from tests.integration.test_policy_scoping import connect


def _policy(keys: dict[str, str]) -> dict:
    return {
        "version": 1,
        "servers": {"default": server_spec(f"{sys.executable} {ECHO_SERVER}")},
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "attributes": {"team": "evaluation"},
                "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
            },
            {
                "id": "unused",
                "api_key_hash": _key_hash(keys["unused"]),
                "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "admin": True,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
        "risk": {
            "tool_sensitivity": {"add": "critical"},
            "protected_repos": ["acme/prod-*"],
        },
    }


async def _audit_count() -> int:
    async with async_session() as session:
        return (await session.execute(select(func.count()).select_from(AuditLog))).scalar_one()


async def _cli(
    executable: str, gateway_url: str, admin_key: str, *args: str
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "PORTUNUSMCP_URL": gateway_url,
        "PORTUNUSMCP_ADMIN_KEY": admin_key,
    }
    return await asyncio.to_thread(
        subprocess.run,
        [executable, "--json", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


async def test_live_scaffold_adoption_flow(clean_audit: None, tmp_path: Path) -> None:
    keys = {name: secrets.token_urlsafe(32) for name in ("agent", "unused", "ops-admin")}
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(_policy(keys), sort_keys=False))
    command = f"{sys.executable} {ECHO_SERVER}"
    today = datetime.now(UTC).date().isoformat()
    window = f"{today}..{today}"

    async with running_gateway(policy_path, command, keys, mode=DecisionMode.OBSERVE) as gateway:
        async with connect(gateway.url, keys["agent"]) as session:
            assert not (await session.call_tool("echo", {"text": "seen"})).isError
            assert not (await session.call_tool("add", {"a": 1, "b": 2})).isError

        async with async_session() as db:
            denied = (
                await db.execute(
                    select(AuditLog).where(
                        AuditLog.event_type == "DENY_RBAC",
                        AuditLog.tool_name == "add",
                    )
                )
            ).scalar_one()
        assert denied.payload["mode"] == "observe"

        headers = {"X-PortunusMCP-Key": keys["ops-admin"]}
        before = await _audit_count()
        async with httpx.AsyncClient() as client:
            unauthenticated = await client.post(
                f"{gateway.url}/admin/policy/scaffold",
                json={"source": "audit", "window": window},
            )
            assert unauthenticated.status_code == 401
            invalid = await client.post(
                f"{gateway.url}/admin/policy/scaffold",
                headers=headers,
                json={"source": "other", "window": window},
            )
            assert invalid.status_code == 400
            extra = await client.post(
                f"{gateway.url}/admin/policy/scaffold",
                headers=headers,
                json={"source": "audit", "window": window, "extra": True},
            )
            assert extra.status_code == 422

        executable = shutil.which("portunusmcp")
        if executable is None:
            pytest.fail("installed portunusmcp CLI is required")
        output = tmp_path / "candidate.yaml"
        generated = await _cli(
            executable,
            gateway.url,
            keys["ops-admin"],
            "policy",
            "scaffold",
            "--from-audit",
            "--window",
            window,
            "--output",
            str(output),
        )
        assert generated.returncode == 0, generated.stderr
        result = json.loads(generated.stdout)
        assert await _audit_count() == before

        raw = output.read_bytes()
        candidate = load_bytes(raw)
        assert candidate.version == 2
        assert [identity.id for identity in candidate.policy.identities] == [
            "agent",
            "ops-admin",
        ]
        agent, admin = candidate.policy.identities
        assert agent.attributes == {"team": "evaluation"}
        assert agent.allowed_servers[0].allowed_tools == ["add", "echo"]
        assert admin.allowed_servers == []
        assert candidate.policy.risk.tool_sensitivity == {}
        assert candidate.policy.risk.protected_repos == ["acme/prod-*"]
        assert result["metadata"]["candidate"] == {
            "version": 2,
            "content_hash": candidate.content_hash,
            "identity_count": 2,
            "grant_count": 1,
            "server_tool_count": 2,
        }
        assert result["metadata"]["audit"]["qualifying_call_row_count"] == 2

        validated = await _cli(
            executable,
            gateway.url,
            keys["ops-admin"],
            "policy",
            "validate",
            str(output),
        )
        assert validated.returncode == 0, validated.stderr
        simulated = await _cli(
            executable,
            gateway.url,
            keys["ops-admin"],
            "policy",
            "simulate",
            str(output),
            "--window",
            window,
        )
        assert simulated.returncode == 0, simulated.stderr
        assert json.loads(simulated.stdout)["newly_allowed"] == 1

        async with httpx.AsyncClient() as client:
            rollout = await client.post(
                f"{gateway.url}/admin/policy/rollout",
                headers={**headers, "Content-Type": "application/yaml"},
                content=raw,
            )
            assert rollout.status_code == 200, rollout.text

    async with running_gateway(policy_path, command, keys) as gateway:
        async with connect(gateway.url, keys["agent"]) as session:
            assert not (await session.call_tool("add", {"a": 2, "b": 3})).isError
            with pytest.raises(McpError):
                await session.call_tool("forbidden_tool", {"value": "unseen"})

        async with async_session() as db:
            events = list(
                (
                    await db.execute(
                        select(AuditLog.event_type, AuditLog.tool_name)
                        .where(AuditLog.tool_name.in_(["add", "forbidden_tool"]))
                        .order_by(AuditLog.seq.desc())
                        .limit(2)
                    )
                ).all()
            )
        assert events == [("DENY_RBAC", "forbidden_tool"), ("ALLOW", "add")]


async def test_scaffold_rejects_tampered_audit_projection(
    clean_audit: None, tmp_path: Path
) -> None:
    keys = {name: secrets.token_urlsafe(32) for name in ("agent", "unused", "ops-admin")}
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(_policy(keys), sort_keys=False))
    today = datetime.now(UTC).date().isoformat()
    async with running_gateway(
        policy_path,
        f"{sys.executable} {ECHO_SERVER}",
        keys,
        mode=DecisionMode.OBSERVE,
    ) as gateway:
        async with connect(gateway.url, keys["agent"]) as session:
            await session.call_tool("echo", {"text": "seen"})
        async with async_session() as db:
            row = (
                await db.execute(select(AuditLog).where(AuditLog.event_type == "ALLOW"))
            ).scalar_one()
            row.tool_name = "tampered"
            await db.commit()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{gateway.url}/admin/policy/scaffold",
                headers={"X-PortunusMCP-Key": keys["ops-admin"]},
                json={"source": "audit", "window": f"{today}..{today}"},
            )
        assert response.status_code == 409
        assert response.json()["detail"] == "audit integrity verification failed"
