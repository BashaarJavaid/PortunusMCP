"""ROADMAP item 34 verify: a captured `signed` request (headers + body) replayed
byte-identically dies on nonce dedup (DENY_REPLAY), and replayed with a fresh
nonce/timestamp dies at the HTTP edge (401) — the captured request carries no
credential, so the attacker cannot recompute the HMAC."""

import json
import time
import uuid
from typing import Any

import httpx
from mcp.types import LATEST_PROTOCOL_VERSION

from services.gateway import auth
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY
from tests.integration.conftest import SignedGateway

HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}


def signed_meta(
    gw: SignedGateway, method: str, tool: str | None = None, arguments: dict | None = None
) -> dict[str, Any]:
    nonce, timestamp = str(uuid.uuid4()), int(time.time())
    return {
        NONCE_META_KEY: nonce,
        TIMESTAMP_META_KEY: timestamp,
        auth.KEY_ID_META_KEY: gw.key_id,
        auth.SIGNATURE_META_KEY: auth.sign_request(
            gw.secret, nonce, timestamp, method, tool, arguments
        ),
    }


def sse_json(response: httpx.Response) -> dict[str, Any]:
    """The transport answers POSTs as SSE; the JSON-RPC message rides a data: line."""
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()  # type: ignore[no-any-return]
    payload = None
    for line in response.text.splitlines():
        if line.startswith("data: "):
            payload = json.loads(line[len("data: ") :])
    assert payload is not None, response.text
    return payload  # type: ignore[no-any-return]


async def handshake(client: httpx.AsyncClient, gw: SignedGateway) -> dict[str, str]:
    """Raw signed initialize + initialized; returns request headers with the session id."""
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "adversary", "version": "0"},
            "_meta": signed_meta(gw, "initialize"),
        },
    }
    response = await client.post(f"{gw.url}/mcp/default", headers=HEADERS, json=init)
    assert response.status_code == 200, response.text
    headers = {**HEADERS, "mcp-session-id": response.headers["mcp-session-id"]}
    initialized = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {"_meta": signed_meta(gw, "notifications/initialized")},
    }
    response = await client.post(f"{gw.url}/mcp/default", headers=headers, json=initialized)
    assert response.status_code in (200, 202), response.text
    return headers


def signed_call_body(gw: SignedGateway, text: str, id: int = 2) -> bytes:  # noqa: A002
    arguments = {"text": text}
    call = {
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": arguments,
            "_meta": signed_meta(gw, "tools/call", "echo", arguments),
        },
    }
    return json.dumps(call).encode()


def unknown_key_initialize(gw: SignedGateway) -> dict[str, Any]:
    nonce, timestamp = str(uuid.uuid4()), int(time.time())
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "adversary", "version": "0"},
            "_meta": {
                NONCE_META_KEY: nonce,
                TIMESTAMP_META_KEY: timestamp,
                auth.KEY_ID_META_KEY: "kid_unknown",
                auth.SIGNATURE_META_KEY: auth.sign_request(
                    b"guessed-secret", nonce, timestamp, "initialize", None, None
                ),
            },
        },
    }


async def test_captured_signed_request_cannot_be_replayed(signed_gateway: SignedGateway) -> None:
    gw = signed_gateway
    async with httpx.AsyncClient() as client:
        headers = await handshake(client, gw)
        body = signed_call_body(gw, "captured")  # the attacker's capture: headers + body

        first = await client.post(f"{gw.url}/mcp/default", headers=headers, content=body)
        assert "result" in sse_json(first), first.text  # the original call executed

        # Byte-identical resubmission: valid signature, dead nonce.
        replay = await client.post(f"{gw.url}/mcp/default", headers=headers, content=body)
        error = sse_json(replay)["error"]
        assert error["data"]["event_type"] == "DENY_REPLAY"
        assert error["data"]["decision"] == "deny"

        # Fresh nonce + timestamp, captured signature: the request held no secret,
        # so the attacker cannot recompute the HMAC — rejected at the edge.
        fresh = json.loads(body)
        fresh["params"]["_meta"][NONCE_META_KEY] = str(uuid.uuid4())
        fresh["params"]["_meta"][TIMESTAMP_META_KEY] = int(time.time())
        forged = await client.post(
            f"{gw.url}/mcp/default", headers=headers, content=json.dumps(fresh).encode()
        )
        assert forged.status_code == 401


async def test_tampered_arguments_are_rejected_at_the_edge(
    signed_gateway: SignedGateway,
) -> None:
    gw = signed_gateway
    async with httpx.AsyncClient() as client:
        headers = await handshake(client, gw)
        call = json.loads(signed_call_body(gw, "benign"))
        call["params"]["arguments"] = {"text": "tampered"}
        response = await client.post(
            f"{gw.url}/mcp/default", headers=headers, content=json.dumps(call)
        )
        assert response.status_code == 401


async def test_unknown_key_id_is_source_throttled_and_gets_no_session(
    signed_gateway: SignedGateway,
) -> None:
    gw = signed_gateway
    headers = {**HEADERS, "X-Forwarded-For": "198.51.100.30"}
    async with httpx.AsyncClient() as client:
        for attempt in range(6):
            response = await client.post(
                f"{gw.url}/mcp/default",
                headers=headers,
                json=unknown_key_initialize(gw),
            )
            assert response.status_code == (401 if attempt < 5 else 429)
        assert "mcp-session-id" not in response.headers
        assert int(response.headers["Retry-After"]) > 0


async def test_auth_block_does_not_break_existing_signed_get_or_delete(
    signed_gateway: SignedGateway,
) -> None:
    gw = signed_gateway
    source_headers = {"X-Forwarded-For": "198.51.100.31"}
    async with httpx.AsyncClient(headers=source_headers, timeout=5) as client:
        session_headers = await handshake(client, gw)
        for _ in range(6):
            response = await client.post(
                f"{gw.url}/mcp/default",
                headers=HEADERS,
                json=unknown_key_initialize(gw),
            )
        assert response.status_code == 429

        async with client.stream("GET", f"{gw.url}/mcp/default", headers=session_headers) as stream:
            assert stream.status_code == 200
        deleted = await client.delete(f"{gw.url}/mcp/default", headers=session_headers)
        assert deleted.status_code == 200
