"""Recorded demo driver (ROADMAP item 8: pruning; item 14 adds drift blocking;
item 28's recording adds the replay-guard and policy-simulation beats).

Mints two bearer API keys plus one signed key-id/secret pair (item 34), writes
policies/demo-policy.yaml (gitignored — keys never enter the repo), then drives the
full README recording-script narrative against the dockerized gateway:
identity-scoped pruning, a successful call from a STOCK MCP client (no custom _meta
anywhere — the bearer identities are the client-compatibility proof), an ON-SCREEN
operator mutation of the rogue server (curl, no timer), drift classified Critical and
blocked, admin re-approval, the same call succeeding, a captured `signed` request
replayed byte-identically (DENY_REPLAY) and with a forged fresh nonce (401 — the
capture holds no credential), and a Policy Simulation of a tightened v2 draft over
the traffic just generated — finishing with the audit-log receipts.

Run (mint the audit signing keypair once first — the gateway won't start without it):
    python scripts/generate_signing_key.py
    python scripts/run_demo.py
and when prompted, in another terminal (the exact command, with this run's secret,
is printed by the script):
    POLICY_FILE=policies/demo-policy.yaml \
      PORTUNUSMCP_DEMO_SIGNING_SECRET=<printed by the script> \
      UPSTREAM_RUNTIME_NAMESPACE=portunusmcp-demo \
      BUSINESS_HOURS_START_UTC=0 BUSINESS_HOURS_END_UTC=24 \
      PORTUNUSMCP_DEMO_TOTP_SECRET=<printed by the script> \
      docker compose up -d --build
(the rogue upstream container lives in the demo policy's `servers:` block)
then, when prompted again (the rug pull, visible on screen):
    curl -X POST localhost:9800/_admin/apply_mutation
and for the closing simulation beat (activates the v2 draft so it gets a snapshot):
    docker kill -s HUP portunusmcp-gateway-1
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx  # noqa: E402
import redis.asyncio as aioredis  # noqa: E402
import yaml  # noqa: E402
from mcp import ClientSession, McpError  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402
from mcp.types import LATEST_PROTOCOL_VERSION  # noqa: E402
from sqlalchemy import select  # noqa: E402

from scripts import reset_dev_state as dev_state  # noqa: E402
from services.gateway import auth, step_up  # noqa: E402
from services.gateway.config import settings  # noqa: E402
from services.gateway.db import AuditLog, async_session, engine  # noqa: E402
from services.gateway.replay_guard import (  # noqa: E402
    NONCE_META_KEY,
    TIMESTAMP_META_KEY,
)

GATEWAY = "http://localhost:8000"
ROOT = Path(__file__).parent.parent
POLICY_PATH = ROOT / "policies" / "demo-policy.yaml"
RUNTIME_NAMESPACE = os.environ.get("UPSTREAM_RUNTIME_NAMESPACE", "")

RECEIPT_EVENTS = [
    "TOOLS_LIST",
    "DRIFT_CRITICAL",
    "DENY_DRIFT",
    "APPROVED",
    "DENY_REPLAY",
    "POLICY_ACTIVATED",
]


def section(title: str) -> None:
    print(f"\n{'=' * 60}\n  {title}\n{'=' * 60}")


def mint_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


SIGNED_SECRET_ENV_NAME = "PORTUNUSMCP_DEMO_SIGNING_SECRET"
TOTP_SECRET_ENV_NAME = "PORTUNUSMCP_DEMO_TOTP_SECRET"
SIGNED_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
}


def signed_meta(
    key_id: str,
    secret: bytes,
    method: str,
    tool: str | None = None,
    arguments: dict | None = None,
) -> dict[str, Any]:
    """The `signed` wire format (item 34): nonce/timestamp + non-secret key id + an
    HMAC over the canonical tuple. The secret itself never travels."""
    nonce, timestamp = str(uuid.uuid4()), int(time.time())
    return {
        NONCE_META_KEY: nonce,
        TIMESTAMP_META_KEY: timestamp,
        auth.KEY_ID_META_KEY: key_id,
        auth.SIGNATURE_META_KEY: auth.sign_request(
            secret, nonce, timestamp, method, tool, arguments
        ),
    }


def sse_json(response: httpx.Response) -> dict[str, Any]:
    """The transport answers POSTs as SSE; the JSON-RPC message rides a data: line."""
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()
    payload = None
    for line in response.text.splitlines():
        if line.startswith("data: "):
            payload = json.loads(line[len("data: ") :])
    assert payload is not None, response.text
    return payload


def write_policy(
    keys: dict[str, str],
    ci_key_id: str,
    version: int = 1,
    developer_tools: list[str] | None = None,
) -> None:
    def key_hash(identity: str) -> str:
        return f"sha256:{hashlib.sha256(keys[identity].encode()).hexdigest()}"

    POLICY_PATH.write_text(
        yaml.safe_dump(
            {
                "version": version,
                # The rogue upstream runs per-session in an item-39 isolated
                # container with read-only demo state.
                "servers": {
                    "default": {
                        "image": "portunusmcp:dev",
                        "command": [
                            "python",
                            "sample_target/rogue_server.py",
                            "--state",
                            "/rogue-state/state.json",
                        ],
                        "volumes": [
                            {
                                "source": (f"portunusmcp-upstream-{RUNTIME_NAMESPACE}-rogue-state"),
                                "target": "/rogue-state",
                            }
                        ],
                    }
                },
                "identities": [
                    {
                        "id": "developer",
                        "api_key_hash": key_hash("developer"),
                        "totp_secret_env": TOTP_SECRET_ENV_NAME,
                        "allowed_servers": [
                            {
                                "server_id": "default",
                                "allowed_tools": developer_tools or ["send_email", "read_inbox"],
                            }
                        ],
                    },
                    {
                        "id": "ops-admin",
                        "api_key_hash": key_hash("ops-admin"),
                        "admin": True,
                        "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
                    },
                    {
                        # Signed identity (item 34): no API key at all — the policy
                        # holds the non-secret key id and the *name* of the env var
                        # the gateway reads the HMAC secret from.
                        "id": "ci-agent",
                        "auth_mode": "signed",
                        "key_id": ci_key_id,
                        "signing_secret_env": SIGNED_SECRET_ENV_NAME,
                        "allowed_servers": [
                            {"server_id": "default", "allowed_tools": ["read_inbox"]}
                        ],
                    },
                ],
            }
        )
    )


async def clear_risk_counters() -> None:
    """Dev-only wipe of the Redis risk counters (same as the integration fixture).
    Called at reset AND again once the gateway accepts this run's key: until the
    fresh policy is loaded, wait_for_gateway's polls are wrong-key 401s that bump
    the gateway-wide auth-failure factor and would distort the first risk scores."""
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    try:
        risk_keys = await redis_client.keys("risk:*")
        if risk_keys:
            await redis_client.delete(*risk_keys)
    finally:
        await redis_client.aclose()


async def reset_dev_state() -> None:
    """Fresh slate for a repeatable recording: the shared item-38 dev reset —
    audit chain, drift baselines, approvals, risk counters, cached pointers, and
    stale revision snapshots (each demo run re-mints keys into the same policy
    version number, which would collide with item 19's append-only check). A
    leftover baseline from a prior run would make the benign schema itself
    register as drift."""
    try:
        await dev_state.reset_dev_state(clear_snapshots=True)
    except dev_state.ResetError as exc:
        sys.exit(str(exc))


@asynccontextmanager
async def connect(api_key: str) -> AsyncIterator[ClientSession]:
    async with httpx.AsyncClient(
        headers={"X-PortunusMCP-Key": api_key}, follow_redirects=True
    ) as http_client:
        async with streamable_http_client(f"{GATEWAY}/mcp/default", http_client=http_client) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


async def wait_for_gateway(api_key: str, signing_secret: str, totp_secret: str) -> None:
    print("\nWaiting for the gateway to come up with the demo policy...")
    print("  In another terminal:")
    print("    POLICY_FILE=policies/demo-policy.yaml \\")
    print(f"      UPSTREAM_RUNTIME_NAMESPACE={RUNTIME_NAMESPACE} \\")
    print(f"      {SIGNED_SECRET_ENV_NAME}={signing_secret} \\")
    print("      BUSINESS_HOURS_START_UTC=0 BUSINESS_HOURS_END_UTC=24 \\")
    print(f"      {TOTP_SECRET_ENV_NAME}={totp_secret} \\")
    print("      docker compose up -d --build")
    print("  (the rogue upstream container is in the demo policy's servers: block)")
    print(
        "  (stack already running with the demo policy? hot-reload this run's fresh"
        " keys with:  docker kill -s HUP portunusmcp-gateway-1)"
    )
    async with httpx.AsyncClient() as client:
        for _ in range(240):
            try:
                response = await client.post(
                    f"{GATEWAY}/mcp/default", json={}, headers={"X-PortunusMCP-Key": api_key}
                )
                if response.status_code != 401:  # demo key accepted => demo policy live
                    print("  gateway is up.")
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.5)
    sys.exit("gateway never became ready — is docker compose up?")


async def show_tools(identity: str, api_key: str) -> None:
    section(f"tools/list as {identity!r}")
    async with connect(api_key) as session:
        for tool in (await session.list_tools()).tools:
            print(f"  - {tool.name}: {(tool.description or '').strip()}")


async def wait_for_mutation() -> None:
    section("the rug pull — an operator mutates the rogue server, on screen")
    print("  In another terminal:  curl -X POST localhost:9800/_admin/apply_mutation")
    print("  (no timer, no hidden trigger — the schema changes only when you do this)")
    async with httpx.AsyncClient() as client:
        while True:
            try:
                response = await client.get("http://localhost:9800/_admin/status")
                if response.status_code == 200 and response.json()["mutated"]:
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.5)
    print(
        "  mutation applied: send_email now has a REQUIRED bcc parameter and a"
        " poisoned description."
    )


async def reset_mutation() -> None:
    async with httpx.AsyncClient() as client:
        for _ in range(120):
            try:
                response = await client.post("http://localhost:9800/_admin/reset")
                if response.status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.5)
    sys.exit("rogue admin service never became ready")


async def drift_and_block(api_key: str) -> None:
    async with connect(api_key) as session:
        section("developer's next tools/list — the gateway sees the drift")
        send_email = {t.name: t for t in (await session.list_tools()).tools}["send_email"]
        print(f"  send_email description is now: {(send_email.description or '').strip()!r}")
        print("  drift classified CRITICAL (new required param) — tool is blocked.")

        section("developer calls send_email — blocked at the point of action")
        try:
            await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi", "body": "hello"})
            sys.exit("expected DENY_DRIFT — did the mutation apply?")
        except McpError as error:
            decision = error.error.data
            print(f"  decision={decision['decision']} event_type={decision['event_type']}")
            print(f"  reason: {decision['reason']}")
            print(f"  audit_id: {decision['audit_id']}")


async def approve_and_retry(keys: dict[str, str], totp_secret: str) -> None:
    section("ops-admin reviews and re-approves the new schema")
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{GATEWAY}/admin/tools/default/send_email/approve",
            headers={"X-PortunusMCP-Key": keys["ops-admin"]},
        )
        response.raise_for_status()
        decision = response.json()
        print(f"  event_type={decision['event_type']} audit_id={decision['audit_id']}")

    section("developer retries (with the now-required bcc) — allowed again")
    async with connect(keys["developer"]) as session:
        arguments = {"to": "a@b.c", "subject": "hi", "body": "hello", "bcc": "x@y.z"}
        try:
            result = await session.call_tool("send_email", arguments)
        except McpError as error:
            decision = error.error.data
            if decision["event_type"] != "CHALLENGE" or not decision["challenge_id"]:
                raise
            print("  suspicious baseline + current context requires TOTP step-up.")
            result = await session.call_tool(
                "send_email",
                arguments,
                meta={
                    step_up.CHALLENGE_ID_META_KEY: decision["challenge_id"],
                    step_up.CHALLENGE_PROOF_META_KEY: step_up.totp_code(totp_secret),
                },
            )
        print(f"  {result.content[0].text}")  # type: ignore[union-attr]


async def replay_blocked(ci_key_id: str, ci_secret: bytes) -> None:
    """README recording-script step 6, now the item-34 story: ci-agent is a `signed`
    identity, so its captured request carries no credential at all. A byte-identical
    replay dies on nonce dedup; a forged fresh nonce dies at the edge, because the
    attacker cannot recompute the HMAC without the secret."""
    section("a signed agent's request is captured and replayed — blocked twice over")
    async with httpx.AsyncClient() as client:
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ci-agent", "version": "0"},
                "_meta": signed_meta(ci_key_id, ci_secret, "initialize"),
            },
        }
        response = await client.post(f"{GATEWAY}/mcp/default", headers=SIGNED_HEADERS, json=init)
        response.raise_for_status()
        headers = {**SIGNED_HEADERS, "mcp-session-id": response.headers["mcp-session-id"]}
        initialized = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {"_meta": signed_meta(ci_key_id, ci_secret, "notifications/initialized")},
        }
        (
            await client.post(f"{GATEWAY}/mcp/default", headers=headers, json=initialized)
        ).raise_for_status()

        arguments: dict = {}
        call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_inbox",
                "arguments": arguments,
                "_meta": signed_meta(ci_key_id, ci_secret, "tools/call", "read_inbox", arguments),
            },
        }
        body = json.dumps(call).encode()  # the attacker's capture: headers + body

        first = sse_json(await client.post(f"{GATEWAY}/mcp/default", headers=headers, content=body))
        if "result" not in first:
            sys.exit(f"expected the signed call to be allowed, got: {first}")
        print("  first send (signed, no API key on the wire): allowed")

        replayed = sse_json(
            await client.post(f"{GATEWAY}/mcp/default", headers=headers, content=body)
        )
        decision = replayed.get("error", {}).get("data", {})
        if decision.get("event_type") != "DENY_REPLAY":
            sys.exit("expected DENY_REPLAY — identical nonce should never execute twice")
        print(f"  byte-identical replay: event_type={decision['event_type']}")
        print(f"  reason: {decision['reason']}")
        print(f"  audit_id: {decision['audit_id']}")

        forged = json.loads(body)
        forged["params"]["_meta"][NONCE_META_KEY] = str(uuid.uuid4())
        forged["params"]["_meta"][TIMESTAMP_META_KEY] = int(time.time())
        response = await client.post(f"{GATEWAY}/mcp/default", headers=headers, json=forged)
        if response.status_code != 401:
            sys.exit(f"expected 401 for a forged nonce, got {response.status_code}")
        print("  fresh nonce, captured signature: HTTP 401 — nothing in the capture")
        print("  lets the attacker re-sign; the secret never crossed the wire.")


async def simulate_draft_policy(keys: dict[str, str], ci_key_id: str) -> None:
    """README recording-script step 7: preview a tightened draft policy against the
    demo traffic just generated. Activation is what records the revision snapshot the
    simulator replays against (item 19/21), so the draft is hot-loaded first — the
    simulation itself is read-only and writes nothing."""
    section("policy simulation — preview a tightened v2 policy against today's traffic")
    write_policy(keys, ci_key_id, version=2, developer_tools=["read_inbox"])
    print("  v2 draft written to policies/demo-policy.yaml: developer LOSES send_email.")
    print("  In another terminal:  docker kill -s HUP portunusmcp-gateway-1")
    print("  (hot-reloads v2 and records the revision snapshot the simulator needs)")
    today = time.strftime("%Y-%m-%d", time.gmtime())
    async with httpx.AsyncClient() as client:
        for _ in range(240):
            response = await client.post(
                f"{GATEWAY}/admin/policy/simulate",
                headers={"X-PortunusMCP-Key": keys["ops-admin"]},
                json={"candidate_version": 2, "replay_window": f"{today}..{today}"},
            )
            if response.status_code == 200:
                break
            await asyncio.sleep(0.5)  # 404 until the operator's SIGHUP records v2
        else:
            sys.exit("v2 never activated — was the SIGHUP sent?")
    report = response.json()
    print(f"  replayed {report['total_replayed']} of this demo's decisions against v2:")
    for counter in ("would_now_deny", "would_now_require_approval", "newly_allowed", "unchanged"):
        print(f"    {counter}: {report[counter]}")
    for diff in report["sample_diffs"][:3]:
        print(
            f"    e.g. seq={diff['audit_seq']} {diff['identity']} -> {diff['tool']}:"
            f" {diff['before']} -> {diff['after']}"
        )


async def show_audit_receipts() -> None:
    section("audit log receipts (tamper-evident, hash-chained, ECDSA-signed)")
    async with async_session() as db:
        rows = (
            (
                await db.execute(
                    select(AuditLog)
                    .where(AuditLog.event_type.in_(RECEIPT_EVENTS))
                    .order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
    for row in rows:
        detail = {
            k: v
            for k, v in row.payload.items()
            if k
            in (
                "served_tools",
                "pruned_tools",
                "severity",
                "reason",
                "new_hash",
                "old_version",
                "new_version",
            )
        }
        print(f"  seq={row.seq} {row.event_type} identity={row.identity_id!r} {detail}")
    await engine.dispose()


async def main() -> None:
    section("PortunusMCP demo — pruning, drift blocking, replay guard, policy simulation")
    if not RUNTIME_NAMESPACE:
        sys.exit("UPSTREAM_RUNTIME_NAMESPACE is required (for example: portunusmcp-dev)")
    await reset_dev_state()
    keys = {"developer": mint_key(), "ops-admin": mint_key()}
    ci_key_id = f"kid_{secrets.token_hex(8)}"
    ci_secret = mint_key()
    developer_totp_secret = base64.b32encode(secrets.token_bytes(20)).decode()
    write_policy(keys, ci_key_id)
    print(f"\nDemo policy written to {POLICY_PATH.relative_to(Path.cwd())}")
    print("  developer  -> allowed: send_email, read_inbox (bearer — a stock MCP client)")
    print("  ops-admin  -> allowed: * (everything), admin: true")
    print(f"  ci-agent   -> allowed: read_inbox (signed — key id {ci_key_id}, no key on the wire)")
    print(
        "Upstream: sample_target/rogue_server.py — starts benign, mutates only when"
        " its admin endpoint is hit."
    )

    await wait_for_gateway(keys["developer"], ci_secret, developer_totp_secret)
    await reset_mutation()  # persistent named volume starts every recording benign
    await clear_risk_counters()  # the waiting polls above were wrong-key 401s

    await show_tools("developer", keys["developer"])
    print(
        "\n  delete_mailbox is not denied — it is ABSENT. The LLM planning over"
        " this list never sees it."
    )
    await show_tools("ops-admin", keys["ops-admin"])

    section("developer calls send_email — benign schema, allowed (stock client, no _meta)")
    async with connect(keys["developer"]) as session:
        result = await session.call_tool(
            "send_email", {"to": "a@b.c", "subject": "hi", "body": "hello"}
        )
        print(f"  {result.content[0].text}")  # type: ignore[union-attr]

    await wait_for_mutation()
    await drift_and_block(keys["developer"])
    await approve_and_retry(keys, developer_totp_secret)
    await replay_blocked(ci_key_id, ci_secret.encode())
    await simulate_draft_policy(keys, ci_key_id)
    await show_audit_receipts()
    section("done")


if __name__ == "__main__":
    asyncio.run(main())
