"""Simulation accuracy for the historical-hour claim (item 21, §11): replay derives
context.hour from each audit row's stored timestamp, not from the wall clock at
simulation time. Indistinguishable when rows are written "now", so this test shifts
the rows' timestamps by SQL (precedent: test_audit_log tampers rows the same way;
the simulator reads rows, it doesn't verify the chain) and hand-computes the split
a candidate hour-conditioned policy must report."""

import secrets
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from sqlalchemy import select, text

from services.gateway.db import AuditLog, async_session
from tests.integration.conftest import (
    ECHO_SERVER,
    Gateway,
    _key_hash,
    running_gateway,
    server_spec,
)
from tests.integration.test_policy_scoping import connect
from tests.integration.test_policy_simulation import _seed_revision, _window


def _policy(keys: dict[str, str], version: int, conditions: list[str] | None = None) -> dict:
    grant: dict[str, Any] = {"server_id": "default", "allowed_tools": ["echo"]}
    if conditions:
        grant["conditions"] = conditions
    return {
        "version": version,
        "servers": {"default": server_spec(f"{sys.executable} {ECHO_SERVER}")},
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "allowed_servers": [grant],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "admin": True,
                "allowed_servers": [],
            },
        ],
    }


@pytest.fixture
async def hour_gateway(clean_audit: None, tmp_path: Path) -> AsyncIterator[Gateway]:
    keys = {"agent": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(_policy(keys, version=1)))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


async def test_replay_evaluates_the_historical_hour(hour_gateway: Gateway) -> None:
    gw = hour_gateway
    # Two ALLOWs under v1 (no conditions, echo untier'd — risk stays under 40).
    async with connect(gw.url, gw.keys["agent"]) as session:
        await session.call_tool("echo", {"text": "night"})
        await session.call_tool("echo", {"text": "day"})

    async with async_session() as db:
        night_seq, day_seq = (
            (
                await db.execute(
                    select(AuditLog.seq)
                    .where(AuditLog.event_type == "ALLOW")
                    .order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
        # Rewrite history: one call at 03:00 UTC, one at 12:00 UTC, same day.
        today = datetime.now(UTC).date()
        for seq, hour in ((night_seq, 3), (day_seq, 12)):
            await db.execute(
                text("UPDATE audit_log SET timestamp = :ts WHERE seq = :seq"),
                {"ts": datetime(today.year, today.month, today.day, hour, tzinfo=UTC), "seq": seq},
            )
        await db.commit()

    # Candidate v2 gates the same grant on business hours: context.hour >= 9.
    await _seed_revision(
        yaml.safe_dump(_policy(gw.keys, version=2, conditions=["context.hour >= 9"])).encode(),
        version=2,
    )

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{gw.url}/admin/policy/simulate",
            headers={"X-PortunusMCP-Key": gw.keys["ops-admin"]},
            json={"candidate_version": 2, "replay_window": _window()},
        )
    assert response.status_code == 200
    report = response.json()

    # Hand-computed: only the 03:00 row flips (hour 3 fails `context.hour >= 9`).
    # If replay used the wall clock instead of the row's epoch, both rows would
    # get the same hour and the split below would be 0/2 or 2/0, never 1/1.
    assert report["total_replayed"] == 2
    assert report["would_now_deny"] == 1
    assert report["unchanged"] == 1
    assert report["would_now_require_approval"] == 0
    assert report["newly_allowed"] == 0
    (diff,) = report["sample_diffs"]
    assert diff["audit_seq"] == night_seq
    assert (diff["before"], diff["after"]) == ("allow", "deny")
