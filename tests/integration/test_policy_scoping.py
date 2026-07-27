"""Identity-scoped tools/list (pruning), §4.1 point-of-action enforcement, and the
§4.8 auth layer: key → identity on every request, 401 on anything else."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest
from mcp import ClientSession, McpError
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from tests.integration.conftest import Gateway


@asynccontextmanager
async def connect(url: str, api_key: str) -> AsyncIterator[ClientSession]:
    # follow_redirects matches the SDK's default client (Mount("/mcp") redirects to /mcp/).
    async with httpx.AsyncClient(
        headers={"X-PortunusMCP-Key": api_key}, follow_redirects=True
    ) as http_client:
        async with streamable_http_client(f"{url}/mcp/default", http_client=http_client) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


async def test_readonly_identity_sees_and_calls_only_allowed_tools(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-readonly"]) as session:
        tools = await session.list_tools()
        assert [tool.name for tool in tools.tools] == ["echo"]  # add pruned away

        result = await session.call_tool("echo", {"text": "hi"})
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "hi"

        # Not in the menu is not the boundary — calling it directly is denied too (§4.1).
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("add", {"a": 2, "b": 3})
        assert excinfo.value.error.data["event_type"] == "DENY_RBAC"
        assert excinfo.value.error.data["decision"] == "deny"


async def test_full_identity_sees_and_calls_everything(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        tools = await session.list_tools()
        assert [tool.name for tool in tools.tools] == ["echo", "add"]

        result = await session.call_tool("add", {"a": 2, "b": 3})
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "5"


async def test_missing_key_is_401(gateway: Gateway) -> None:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{gateway.url}/mcp/", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
        assert response.status_code == 401


async def test_wrong_key_is_401(gateway: Gateway) -> None:
    async with httpx.AsyncClient(headers={"X-PortunusMCP-Key": "not-a-real-key"}) as client:
        response = await client.post(
            f"{gateway.url}/mcp/", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
        assert response.status_code == 401


async def test_valid_key_cannot_ride_another_identitys_session(gateway: Gateway) -> None:
    async with httpx.AsyncClient(
        headers={"X-PortunusMCP-Key": gateway.keys["agent-readonly"]}, follow_redirects=True
    ) as http_client:
        async with streamable_http_client(
            f"{gateway.url}/mcp/default", http_client=http_client
        ) as (
            read,
            write,
            get_session_id,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                session_id = get_session_id()
                assert session_id is not None

                # agent-full's key is valid, but it isn't this session's identity.
                async with httpx.AsyncClient() as other:
                    response = await other.get(
                        f"{gateway.url}/mcp/default",
                        headers={
                            "X-PortunusMCP-Key": gateway.keys["agent-full"],
                            "mcp-session-id": session_id,
                        },
                    )
                    assert response.status_code == 401
