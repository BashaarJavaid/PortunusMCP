"""Item 35 verify: two registered upstreams exposing an identically-named tool —
RBAC granted on server A must not allow the tool on server B, drift on A must not
block B, and an unregistered server id is a 404."""

import secrets
import shlex
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import yaml
from mcp import ClientSession, McpError
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from services.gateway import risk_engine
from services.gateway.main import app
from tests.adversarial.conftest import upstream_command
from tests.integration.conftest import Gateway, _key_hash, running_gateway


@asynccontextmanager
async def connect_to(url: str, server_id: str, api_key: str) -> AsyncIterator[ClientSession]:
    async with httpx.AsyncClient(
        headers={"X-PortunusMCP-Key": api_key}, follow_redirects=True
    ) as http_client:
        async with streamable_http_client(f"{url}/mcp/{server_id}", http_client=http_client) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


@pytest.fixture
async def multi_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Gateway]:
    """Two upstreams, both the mutable fixture server (same `send_email` tool on
    each). Like the adversarial drift fixture, the clock-dependent business-hours
    factor is dropped — this test is about isolation, not scoring."""
    monkeypatch.setattr(
        risk_engine,
        "FACTORS",
        [fn for fn in risk_engine.FACTORS if fn is not risk_engine._business_hours],
    )
    keys = {"scoped": secrets.token_urlsafe(32), "full": secrets.token_urlsafe(32)}
    policy = {
        "version": 1,
        "servers": {"alpha": upstream_command("none"), "beta": upstream_command("none")},
        "identities": [
            {
                "id": "scoped",
                "api_key_hash": _key_hash(keys["scoped"]),
                "allowed_servers": [{"server_id": "alpha", "allowed_tools": ["send_email"]}],
            },
            {
                "id": "full",
                "api_key_hash": _key_hash(keys["full"]),
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, upstream_command("none"), keys) as gw:
        yield gw


async def test_rbac_is_isolated_per_server(multi_gateway: Gateway) -> None:
    async with connect_to(multi_gateway.url, "alpha", multi_gateway.keys["scoped"]) as session:
        result = await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi"})
        assert isinstance(result.content[0], TextContent)

    # The identical tool name on the other registered server is a different grant.
    async with connect_to(multi_gateway.url, "beta", multi_gateway.keys["scoped"]) as session:
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi"})
        assert excinfo.value.error.data["event_type"] == "DENY_RBAC"


async def test_unregistered_server_id_is_404(multi_gateway: Gateway) -> None:
    headers = {"X-PortunusMCP-Key": multi_gateway.keys["full"]}
    async with httpx.AsyncClient(headers=headers) as client:
        response = await client.post(f"{multi_gateway.url}/mcp/gamma", json={})
        assert response.status_code == 404


async def test_drift_on_one_server_does_not_block_the_other(multi_gateway: Gateway) -> None:
    # First sessions baseline the identical tool on both servers independently.
    for server in ("alpha", "beta"):
        async with connect_to(multi_gateway.url, server, multi_gateway.keys["full"]) as session:
            await session.list_tools()

    # Rug-pull beta only (Critical: required status flipped) via the live registry.
    app.state.policy_store.engine.policy.servers["beta"].command = shlex.split(
        upstream_command("required_change")
    )
    async with connect_to(multi_gateway.url, "beta", multi_gateway.keys["full"]) as session:
        await session.list_tools()
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi"})
        assert excinfo.value.error.data["event_type"] == "DENY_DRIFT"

    # alpha's identically-named tool is a different baseline — still allowed.
    async with connect_to(multi_gateway.url, "alpha", multi_gateway.keys["full"]) as session:
        result = await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi"})
        assert isinstance(result.content[0], TextContent)
