"""Item-39 verify: a real per-session container cannot see gateway secrets and an
OOM-killed upstream is removed. CI requires Docker; local runs skip without it/image."""

import asyncio
import hashlib
import json
import os
import secrets
import subprocess
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import httpx
import pytest
import yaml
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from services.gateway.main import app
from tests.integration.conftest import Gateway, running_gateway

IMAGE = "portunusmcp:dev"
NAMESPACE = "portunusmcp-test"


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _require_docker() -> None:
    required = os.environ.get("REQUIRE_DOCKER_TESTS") == "1"
    try:
        _docker("version")
        _docker("image", "inspect", IMAGE)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        if required:
            pytest.fail(f"required Docker isolation prerequisite missing: {exc}")
        pytest.skip("Docker daemon and portunusmcp:dev image are required for isolation test")


@pytest.fixture
async def isolated_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[Gateway, str]]:
    _require_docker()
    monkeypatch.setenv("UPSTREAM_RUNTIME_NAMESPACE", NAMESPACE)
    monkeypatch.setenv("PORTUNUSMCP_UPSTREAM_TEST_MARKER", "allowed")
    monkeypatch.setenv("PORTUNUSMCP_GATEWAY_SENTINEL", "gateway-only")
    monkeypatch.setenv("PORTUNUSMCP_TEST_SIGNING_SECRET", "signing-only")
    monkeypatch.setenv("PORTUNUSMCP_TEST_TOTP_SECRET", "totp-only")

    orphan = f"{NAMESPACE}-orphan-{secrets.token_hex(4)}"
    _docker(
        "run",
        "-d",
        "--name",
        orphan,
        "--label",
        "io.portunusmcp.managed=true",
        "--label",
        f"io.portunusmcp.namespace={NAMESPACE}",
        IMAGE,
        "python",
        "-c",
        "import time; time.sleep(300)",
    )

    key = secrets.token_urlsafe(32)
    policy = {
        "version": 1,
        "servers": {
            "probe": {
                "image": IMAGE,
                "command": ["python", "sample_target/isolation_probe.py"],
                "env": {
                    "ALLOWED_MARKER": "PORTUNUSMCP_UPSTREAM_TEST_MARKER",
                },
            }
        },
        "identities": [
            {
                "id": "probe-agent",
                "api_key_hash": f"sha256:{hashlib.sha256(key.encode()).hexdigest()}",
                "allowed_servers": [
                    {
                        "server_id": "probe",
                        "allowed_tools": ["inspect_boundary", "exhaust_memory"],
                    }
                ],
            }
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    try:
        async with running_gateway(
            policy_path, "", {"probe-agent": key}, isolate_upstreams=True
        ) as gateway:
            yield gateway, orphan
    finally:
        _docker("rm", "-f", orphan, check=False)


@asynccontextmanager
async def _connect(gateway: Gateway) -> AsyncIterator[ClientSession]:
    async with httpx.AsyncClient(
        headers={"X-PortunusMCP-Key": gateway.keys["probe-agent"]},
        follow_redirects=True,
        timeout=30,
    ) as client:
        async with streamable_http_client(f"{gateway.url}/mcp/probe", http_client=client) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


async def test_upstream_is_confined_and_memory_breach_is_reaped(
    isolated_gateway: tuple[Gateway, str],
) -> None:
    gateway, orphan = isolated_gateway
    assert _docker("inspect", orphan, check=False).returncode != 0

    container_name = ""
    async with _connect(gateway) as session:
        result = await session.call_tool("inspect_boundary", {})
        boundary = json.loads(result.content[0].text)  # type: ignore[union-attr]
        assert boundary == {
            "environment": {
                "ALLOWED_MARKER": "allowed",
                "DATABASE_URL": None,
                "REDIS_URL": None,
                "PORTUNUSMCP_GATEWAY_SENTINEL": None,
                "PORTUNUSMCP_TEST_SIGNING_SECRET": None,
                "PORTUNUSMCP_TEST_TOTP_SECRET": None,
            },
            "uid": 65532,
            "secrets_dir": False,
            "private_key": False,
            "docker_socket": False,
        }

        active = next(iter(app.state.session_manager._sessions.values()))
        container_name = active.process.name
        inspected = json.loads(_docker("inspect", container_name).stdout)[0]
        host = inspected["HostConfig"]
        assert inspected["Config"]["User"] == "65532:65532"
        assert host["ReadonlyRootfs"] is True
        assert host["Init"] is True
        assert host["Memory"] == 256 * 1024 * 1024
        assert host["MemorySwap"] == host["Memory"]
        assert host["NanoCpus"] == 500_000_000
        assert host["PidsLimit"] == 64
        assert host["NetworkMode"] == "none"
        assert host["CapDrop"] == ["ALL"]
        assert "no-new-privileges" in host["SecurityOpt"]
        assert "/tmp" in host["Tmpfs"]
        assert inspected["Config"]["Labels"]["io.portunusmcp.server"] == "probe"
        assert "ALLOWED_MARKER=allowed" in inspected["Config"]["Env"]
        assert not any(
            value.startswith(("DATABASE_URL=", "REDIS_URL="))
            for value in inspected["Config"]["Env"]
        )

        call = asyncio.create_task(session.call_tool("exhaust_memory", {}))
        for _ in range(100):
            if _docker("inspect", container_name, check=False).returncode != 0:
                break
            await asyncio.sleep(0.05)
        call.cancel()
        with suppress(asyncio.CancelledError):
            await call

    assert container_name
    assert _docker("inspect", container_name, check=False).returncode != 0
