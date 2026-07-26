"""Policy Simulation Mode end to end (§4.8, item 21): POST /admin/policy/simulate
replays real audit rows against candidate revision snapshots and reports hand-computed
diff counts (§11's simulation-accuracy requirement), writes nothing (no audit rows, no
policy activation), and fails closed on a tampered snapshot.

Business-hours factor dropped like test_decision_explanation, so replayed risk scores
are time-of-day independent (zero here — no risk block in the policy)."""

import hashlib
import secrets
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import yaml
from mcp import McpError
from sqlalchemy import func, select

from services.gateway import risk_engine
from services.gateway.config import settings
from services.gateway.db import AuditLog, PolicyVersion, async_session
from tests.integration.conftest import (
    ECHO_SERVER,
    Gateway,
    _key_hash,
    running_gateway,
    server_spec,
)
from tests.integration.test_policy_scoping import connect


def _policy(keys: dict[str, str], version: int, agent_tools: list[str]) -> dict:
    return {
        "version": version,
        "servers": {"default": server_spec(f"{sys.executable} {ECHO_SERVER}")},
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "allowed_servers": [{"server_id": "default", "allowed_tools": agent_tools}],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "admin": True,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }


def _window() -> str:
    today = datetime.now(UTC).date()
    return f"{today - timedelta(days=1)}..{today + timedelta(days=1)}"


async def _seed_revision(raw: bytes, version: int) -> None:
    """Record a candidate revision exactly as an activation would have: snapshot
    bytes on disk + a policy_versions row — without activating it."""
    Path(settings.policy_revisions_dir).mkdir(parents=True, exist_ok=True)
    (Path(settings.policy_revisions_dir) / f"v{version}.yaml").write_bytes(raw)
    async with async_session() as db:
        db.add(
            PolicyVersion(
                version=version,
                content_hash=hashlib.sha256(raw).hexdigest(),
                activated_by="test",
            )
        )
        await db.commit()


async def _audit_count() -> int:
    async with async_session() as db:
        return (await db.execute(select(func.count()).select_from(AuditLog))).scalar_one()


@pytest.fixture
async def sim_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Gateway]:
    monkeypatch.setattr(
        risk_engine,
        "FACTORS",
        [fn for fn in risk_engine.FACTORS if fn is not risk_engine._business_hours],
    )
    keys = {"agent": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(_policy(keys, version=1, agent_tools=["echo", "add"])))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        # Historical traffic under v1: three echo ALLOWs, one add ALLOW, one
        # DENY_RBAC (which now records its arguments — item 21).
        async with connect(gw.url, keys["agent"]) as session:
            for text in ("a", "b", "c"):
                await session.call_tool("echo", {"text": text})
            await session.call_tool("add", {"a": 1, "b": 2})
            with pytest.raises(McpError):
                await session.call_tool("forbidden_tool", {"x": 1})
        # Candidate v2 revokes add — strictly stricter for the agent.
        await _seed_revision(
            yaml.safe_dump(_policy(keys, version=2, agent_tools=["echo"])).encode(), version=2
        )
        yield gw


async def _simulate(gw: Gateway, body: dict, key_id: str = "ops-admin") -> httpx.Response:
    async with httpx.AsyncClient() as client:
        return await client.post(
            f"{gw.url}/admin/policy/simulate",
            headers={"X-PortunusMCP-Key": gw.keys[key_id]},
            json=body,
        )


async def test_candidate_vs_history_hand_computed(sim_gateway: Gateway) -> None:
    rows_before = await _audit_count()
    response = await _simulate(sim_gateway, {"candidate_version": 2, "replay_window": _window()})
    assert response.status_code == 200
    result = response.json()
    # 5 replayed: 4 ALLOWs + the DENY_RBAC (its arguments were persisted).
    assert result["total_replayed"] == 5
    # v2 revokes add: the one historical add ALLOW is the one new deny.
    assert result["would_now_deny"] == 1
    assert result["would_now_require_approval"] == 0
    assert result["newly_allowed"] == 0
    assert result["unchanged"] == 4
    (diff,) = result["sample_diffs"]
    assert diff["tool"] == "add"
    assert (diff["before"], diff["after"]) == ("allow", "deny")
    # Read-only: a simulation leaves no trace in the chain.
    assert await _audit_count() == rows_before


async def test_compare_versions_hand_computed(sim_gateway: Gateway) -> None:
    response = await _simulate(
        sim_gateway, {"compare_versions": [1, 2], "replay_window": _window()}
    )
    assert response.status_code == 200
    result = response.json()
    assert result["total_replayed"] == 5
    assert result["compared_versions"] == [1, 2]
    # add: v1 allows, v2 denies — the only divergence between the revisions.
    assert result["new_denials"] == 1
    assert result["new_approvals"] == 0
    # The v1 allow was risk-scored; the v2 RBAC deny never reaches scoring.
    assert result["changed_risk_scores"] == 1
    assert result["changed_explanations"] == 1
    (diff,) = result["sample_diffs"]
    assert diff["tool"] == "add"
    assert "not authorized" in diff["reason"]


async def test_simulate_validation_and_authz(sim_gateway: Gateway) -> None:
    window = _window()
    # Exactly one mode is required.
    assert (await _simulate(sim_gateway, {"replay_window": window})).status_code == 400
    both = {"candidate_version": 2, "compare_versions": [1, 2], "replay_window": window}
    assert (await _simulate(sim_gateway, both)).status_code == 400
    pair = {"compare_versions": [1], "replay_window": window}
    assert (await _simulate(sim_gateway, pair)).status_code == 400
    bad_window = {"candidate_version": 2, "replay_window": "not-a-window"}
    assert (await _simulate(sim_gateway, bad_window)).status_code == 400
    missing = {"candidate_version": 99, "replay_window": window}
    assert (await _simulate(sim_gateway, missing)).status_code == 404
    non_admin = {"candidate_version": 2, "replay_window": window}
    assert (await _simulate(sim_gateway, non_admin, key_id="agent")).status_code == 403
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{sim_gateway.url}/admin/policy/simulate", json=non_admin)
    assert response.status_code == 401


async def test_tampered_snapshot_is_409(sim_gateway: Gateway) -> None:
    # Same posture as rollback (item 19): snapshot bytes must match the recorded hash.
    (Path(settings.policy_revisions_dir) / "v2.yaml").write_text("version: 2\nidentities: []\n")
    response = await _simulate(sim_gateway, {"candidate_version": 2, "replay_window": _window()})
    assert response.status_code == 409
