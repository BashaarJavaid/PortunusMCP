"""First-run state reset (item 38): the boot-time activation conflict names the
reset command instead of just stack-tracing, and scripts/reset_dev_state.py
actually clears everything item 19's fail-closed checks trip over — without
weakening the checks themselves (the conflict still fails startup)."""

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import redis.asyncio as aioredis
from sqlalchemy import func, select

from scripts.reset_dev_state import reset_dev_state
from services.gateway import policy_versions
from services.gateway.config import settings
from services.gateway.db import Approval, async_session
from services.gateway.main import _record_startup_activation
from services.gateway.policy_engine import load_bytes

DEMO_POLICY = (
    b"version: 1\nservers:\n  default:\n"
    b"    image: example/demo:test\n    command: [demo-command]\n"
)
DEFAULT_POLICY = (
    b"version: 1\nservers:\n  default:\n"
    b"    image: example/default:test\n    command: [example-command]\n"
)


@pytest.fixture
async def revisions_tmp(clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    revisions = tmp_path / "revisions"
    revisions.mkdir()
    monkeypatch.setattr(settings, "policy_revisions_dir", str(revisions))
    return revisions


async def test_startup_conflict_names_the_reset_command(revisions_tmp: Path) -> None:
    # The demo's policy v1 is on record; a fresh demo-stack startup boots the
    # default policy — same version, different content.
    await policy_versions.record_activation(load_bytes(DEMO_POLICY), "startup", async_session)
    with pytest.raises(
        policy_versions.ActivationError,
        match=r"version 1 is already recorded.*reset_dev_state",
    ):
        await _record_startup_activation(load_bytes(DEFAULT_POLICY))


async def test_reset_clears_the_conflict_and_the_gateway_state(revisions_tmp: Path) -> None:
    # Leftover demo state: the policy_versions row + its revision snapshot, an
    # approvals row, and Redis risk/challenge keys.
    await policy_versions.record_activation(load_bytes(DEMO_POLICY), "startup", async_session)
    assert (revisions_tmp / "v1.yaml").exists()
    (revisions_tmp / ".gitkeep").touch()
    async with async_session() as session:
        session.add(
            Approval(
                approval_id=uuid.uuid4().hex,
                audit_id=1,
                identity_id="agent",
                server_id="default",
                tool_name="echo",
                arguments_hash="0" * 64,
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            )
        )
        await session.commit()
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    try:
        await redis_client.set("risk:decay:agent:default:echo", 5)
        await redis_client.set("challenge:deadbeef", b"{}")

        await reset_dev_state(clear_snapshots=True)

        assert not await redis_client.exists("risk:decay:agent:default:echo")
        assert not await redis_client.exists("challenge:deadbeef")
    finally:
        await redis_client.aclose()
    assert not (revisions_tmp / "v1.yaml").exists()
    assert (revisions_tmp / ".gitkeep").exists()
    async with async_session() as session:
        assert (await session.execute(select(func.count(Approval.approval_id)))).scalar() == 0
    # The item's "gateway starts after reset", in miniature: the same activation
    # that just conflicted now records cleanly.
    await _record_startup_activation(load_bytes(DEFAULT_POLICY))


async def test_snapshots_survive_when_not_cleared(revisions_tmp: Path) -> None:
    # The test/benchmark callers pass clear_snapshots=False — a suite run must
    # never delete a developer's real policies/revisions/ (item 38).
    await policy_versions.record_activation(load_bytes(DEMO_POLICY), "startup", async_session)
    await reset_dev_state(clear_snapshots=False)
    assert (revisions_tmp / "v1.yaml").exists()
