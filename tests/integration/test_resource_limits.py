import asyncio
import json
import secrets
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
import yaml

from services.gateway.config import settings
from services.gateway.main import app
from tests.integration.conftest import Gateway, _key_hash, running_gateway

SLEEP_SERVER = Path(__file__).parent / "fixtures" / "sleep_server.py"
ACCEPT = "application/json, text/event-stream"


@pytest.fixture
async def limited_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Gateway]:
    key = secrets.token_urlsafe(32)
    policy = {
        "version": 1,
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(key),
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            }
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    monkeypatch.setattr(settings, "business_hours_start_utc", 0)
    monkeypatch.setattr(settings, "business_hours_end_utc", 24)
    monkeypatch.setattr(settings, "risk_freq_threshold", 10**9)
    async with running_gateway(
        policy_path, f"{sys.executable} {SLEEP_SERVER}", {"agent": key}
    ) as gateway:
        yield gateway


def init_message(request_id: int = 1) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "resource-test", "version": "1"},
        },
    }


def headers(gateway: Gateway, session_id: str | None = None) -> dict[str, str]:
    result = {
        "X-PortunusMCP-Key": gateway.keys["agent"],
        "Accept": ACCEPT,
        "Content-Type": "application/json",
    }
    if session_id is not None:
        result["mcp-session-id"] = session_id
    return result


async def initialize(client: httpx.AsyncClient, gateway: Gateway) -> str:
    response = await client.post(
        f"{gateway.url}/mcp/default", headers=headers(gateway), json=init_message()
    )
    assert response.status_code == 200, response.text
    session_id = response.headers["mcp-session-id"]
    initialized = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }
    response = await client.post(
        f"{gateway.url}/mcp/default",
        headers=headers(gateway, session_id),
        json=initialized,
    )
    assert response.status_code == 202
    return session_id


def call(request_id: int, seconds: float) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "sleep", "arguments": {"seconds": seconds}},
    }


async def test_body_size_depth_utf8_and_jsonrpc_edge(
    limited_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"{limited_gateway.url}/mcp/default"
    edge_headers = headers(limited_gateway)
    async with httpx.AsyncClient(timeout=10) as client:
        declared = await client.post(
            url,
            headers={**edge_headers, "Content-Length": str(settings.max_mcp_body_bytes + 1)},
            content=b" " * (settings.max_mcp_body_bytes + 1),
        )
        assert (declared.status_code, declared.text) == (413, "request body too large")

        async def oversized() -> AsyncIterator[bytes]:
            yield b" " * settings.max_mcp_body_bytes
            yield b" "

        actual = await client.post(url, headers=edge_headers, content=oversized())
        assert (actual.status_code, actual.text) == (413, "request body too large")

        raw = json.dumps(init_message()).encode()
        exact = raw + b" " * (settings.max_mcp_body_bytes - len(raw))
        accepted = await client.post(url, headers=edge_headers, content=exact)
        assert accepted.status_code == 200

        ping = {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}}
        ping["params"]["nested"] = value = []  # type: ignore[index]
        for _ in range(29):  # root + params + 30 arrays = depth 32
            child: list[object] = []
            value.append(child)
            value = child
        depth_32 = await client.post(url, headers=edge_headers, json=ping)
        assert depth_32.text == "initialize request required"

        value.append([])
        depth_33 = await client.post(url, headers=edge_headers, json=ping)
        assert (depth_33.status_code, depth_33.text) == (400, "JSON depth exceeded")

        ping["params"] = {"text": r"escaped \"] } [ still text"}  # type: ignore[index]
        escaped = await client.post(url, headers=edge_headers, json=ping)
        assert escaped.text == "initialize request required"

        bad_utf8 = await client.post(url, headers=edge_headers, content=b"\xff")
        assert (bad_utf8.status_code, bad_utf8.text) == (400, "invalid JSON-RPC")
        malformed = await client.post(url, headers=edge_headers, content=b'{"jsonrpc":"2.0"}')
        assert (malformed.status_code, malformed.text) == (400, "invalid JSON-RPC")


async def test_transport_host_and_origin_validation(
    limited_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"{limited_gateway.url}/mcp/default"
    async with httpx.AsyncClient() as client:
        missing_origin = await client.post(
            url, headers=headers(limited_gateway), json=init_message()
        )
        assert missing_origin.status_code == 200

        invalid_origin = await client.post(
            url,
            headers={**headers(limited_gateway), "Origin": "https://attacker.example"},
            json=init_message(2),
        )
        assert (invalid_origin.status_code, invalid_origin.text) == (
            403,
            "Invalid Origin header",
        )

        invalid_host = await client.post(
            url,
            headers={**headers(limited_gateway), "Host": "attacker.example"},
            json=init_message(3),
        )
        assert (invalid_host.status_code, invalid_host.text) == (421, "Invalid Host header")

        monkeypatch.setattr(settings, "allowed_hosts", ["gateway.example"])
        monkeypatch.setattr(settings, "allowed_origins", ["https://client.example"])
        configured = await client.post(
            url,
            headers={
                **headers(limited_gateway),
                "Host": "gateway.example",
                "Origin": "https://client.example",
            },
            json=init_message(4),
        )
        assert configured.status_code == 200


async def test_session_limit_and_sessionless_messages_do_not_spawn(
    limited_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "max_sessions_per_identity", 3)
    manager = app.state.session_manager
    async with httpx.AsyncClient(timeout=10) as client:
        session_ids = [await initialize(client, limited_gateway) for _ in range(3)]
        fourth = await client.post(
            f"{limited_gateway.url}/mcp/default",
            headers=headers(limited_gateway),
            json=init_message(10),
        )
        assert (fourth.status_code, fourth.text) == (429, "session limit exceeded")

        before = len(manager._sessions)
        sessionless = await client.post(
            f"{limited_gateway.url}/mcp/default",
            headers=headers(limited_gateway),
            json={"jsonrpc": "2.0", "id": 11, "method": "ping"},
        )
        notification = await client.post(
            f"{limited_gateway.url}/mcp/default",
            headers=headers(limited_gateway),
            json={"jsonrpc": "2.0", "method": "tools/call", "params": {}},
        )
        assert sessionless.status_code == 400
        assert notification.status_code == 400
        assert len(manager._sessions) == before

        for session_id in session_ids:
            await client.delete(
                f"{limited_gateway.url}/mcp/default",
                headers=headers(limited_gateway, session_id),
            )


async def test_rate_limit_counts_invalid_session_and_notification(
    limited_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "tool_call_rate_limit", 2)
    monkeypatch.setattr(settings, "tool_call_rate_window_seconds", 30)
    url = f"{limited_gateway.url}/mcp/default"
    async with httpx.AsyncClient() as client:
        invalid_session = await client.post(
            url, headers=headers(limited_gateway, "missing"), json=call(1, 0)
        )
        notification = await client.post(
            url,
            headers=headers(limited_gateway),
            json={"jsonrpc": "2.0", "method": "tools/call", "params": {}},
        )
        limited = await client.post(
            url, headers=headers(limited_gateway, "missing"), json=call(2, 0)
        )
    assert invalid_session.status_code == 404
    assert notification.status_code == 400
    assert limited.status_code == 429
    assert 1 <= int(limited.headers["Retry-After"]) <= 30


async def test_rate_limiter_failure_is_503(
    limited_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        app.state.session_manager._redis,
        "incr",
        AsyncMock(side_effect=ConnectionError),
    )
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{limited_gateway.url}/mcp/default",
            headers=headers(limited_gateway, "missing"),
            json=call(1, 0),
        )
    assert (response.status_code, response.text) == (503, "rate limiter unavailable")


async def test_duplicate_and_inflight_limits_release_after_completion(
    limited_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "max_inflight_calls_per_identity", 1)
    async with httpx.AsyncClient(timeout=10) as client:
        session_id = await initialize(client, limited_gateway)
        url = f"{limited_gateway.url}/mcp/default"
        first = asyncio.create_task(
            client.post(url, headers=headers(limited_gateway, session_id), json=call(20, 0.3))
        )
        while not app.state.session_manager._outstanding:
            await asyncio.sleep(0.01)

        duplicate = await client.post(
            url, headers=headers(limited_gateway, session_id), json=call(20, 0)
        )
        full = await client.post(
            url, headers=headers(limited_gateway, session_id), json=call(21, 0)
        )
        assert duplicate.status_code == 400
        assert "Retry-After" not in duplicate.headers
        assert full.status_code == 429
        assert "Retry-After" not in full.headers
        assert (await first).status_code == 200

        released = await client.post(
            url, headers=headers(limited_gateway, session_id), json=call(22, 0)
        )
        assert released.status_code == 200


async def test_deadline_reaps_session_and_returns_jsonrpc_error(
    limited_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "tool_call_deadline_seconds", 0.2)
    async with httpx.AsyncClient(timeout=10) as client:
        session_id = await initialize(client, limited_gateway)
        response = await client.post(
            f"{limited_gateway.url}/mcp/default",
            headers=headers(limited_gateway, session_id),
            json=call(30, 2),
        )
        payload = json.loads(response.text.split("data: ", 1)[1])
        assert payload["error"] == {
            "code": -32005,
            "message": "tool call exceeded execution deadline; session terminated",
        }
        assert app.state.session_manager.get(session_id) is None
        unavailable = await client.post(
            f"{limited_gateway.url}/mcp/default",
            headers=headers(limited_gateway, session_id),
            json=call(31, 0),
        )
        assert unavailable.status_code == 404


async def test_inflight_heartbeat_prevents_idle_reap_then_stops(
    limited_gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "session_idle_ttl", 1)
    monkeypatch.setattr(settings, "tool_call_deadline_seconds", 5)
    manager = app.state.session_manager
    async with httpx.AsyncClient(timeout=10) as client:
        session_id = await initialize(client, limited_gateway)
        pending = asyncio.create_task(
            client.post(
                f"{limited_gateway.url}/mcp/default",
                headers=headers(limited_gateway, session_id),
                json=call(40, 1.5),
            )
        )
        while not manager._outstanding:
            await asyncio.sleep(0.01)
        await asyncio.sleep(1.1)
        await manager.sweep_once()
        assert manager.get(session_id) is not None
        assert (await pending).status_code == 200

        await asyncio.sleep(1.1)
        await manager.sweep_once()
        assert manager.get(session_id) is None
