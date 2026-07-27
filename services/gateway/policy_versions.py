"""Policy activation record-keeping (ARCHITECTURE.md §4.8, item 19).

Every successful activation (startup, SIGHUP reload, admin rollback) leaves two
records: an append-only revision snapshot at policies/revisions/v{n}.yaml holding
the exact policy file bytes, and a policy_versions row (version, content_hash,
activated_at, activated_by). Forward activations are monotonic: the YAML `version`
must be strictly greater than the highest ever recorded; re-activating the same
(version, content_hash) pair is an idempotent no-op; the same version with different
content is rejected fail-closed (§5). Rollback is exempt — it re-activates an
already-recorded version, refreshing that row's activated_at/activated_by.
"""

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway.config import settings
from services.gateway.db import PolicyVersion
from services.gateway.policy_engine import PolicyEngine


class ActivationError(Exception):
    """A policy activation that must be rejected (monotonicity or content conflict)."""


async def activation_status(
    engine: PolicyEngine, sessionmaker: async_sessionmaker[AsyncSession]
) -> tuple[bool, int | None]:
    """Read-only forward-activation eligibility and the historical maximum."""
    async with sessionmaker() as session:
        existing = await session.get(PolicyVersion, engine.version)
        max_version = (await session.execute(select(func.max(PolicyVersion.version)))).scalar()
    if existing is not None:
        if existing.content_hash == engine.content_hash:
            raise ActivationError(
                f"policy version {engine.version} is already recorded; activate it via rollback"
            )
        raise ActivationError(
            f"policy version {engine.version} is already recorded with different content"
        )
    if max_version is not None and engine.version <= max_version:
        raise ActivationError(
            f"policy version {engine.version} is not greater than the highest "
            f"recorded version {max_version}"
        )
    path = snapshot_path(engine.version)
    if path.exists() and path.read_bytes() != engine.raw:
        raise ActivationError(f"revision snapshot {path} exists with different content")
    return True, max_version


def snapshot_path(version: int) -> Path:
    return Path(settings.policy_revisions_dir) / f"v{version}.yaml"


async def record_activation(
    engine: PolicyEngine, activated_by: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> bool:
    """Record a forward activation; returns False for the idempotent same-version,
    same-hash no-op. Raises ActivationError on any conflict — the caller must not
    swap the engine in (fail closed, §5)."""
    async with sessionmaker() as session:
        existing = await session.get(PolicyVersion, engine.version)
        if existing is not None:
            if existing.content_hash == engine.content_hash:
                return False
            raise ActivationError(
                f"policy version {engine.version} is already recorded with different content"
            )
        max_version = (await session.execute(select(func.max(PolicyVersion.version)))).scalar()
        if max_version is not None and engine.version <= max_version:
            raise ActivationError(
                f"policy version {engine.version} is not greater than the highest "
                f"recorded version {max_version}"
            )
        _write_snapshot(engine)
        session.add(
            PolicyVersion(
                version=engine.version,
                content_hash=engine.content_hash,
                activated_by=activated_by,
            )
        )
        await session.commit()
    return True


async def record_rollback(
    engine: PolicyEngine, activated_by: str, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """Record re-activation of an already-recorded version (rollback). Raises
    LookupError if the version was never recorded, ActivationError if the snapshot
    bytes no longer match the recorded content_hash (a tampered snapshot must not
    activate — fail closed)."""
    async with sessionmaker() as session:
        row = await session.get(PolicyVersion, engine.version)
        if row is None:
            raise LookupError(f"policy version {engine.version} was never recorded")
        if row.content_hash != engine.content_hash:
            raise ActivationError(
                f"snapshot for version {engine.version} does not match its recorded content_hash"
            )
        row.activated_at = datetime.now(UTC)
        row.activated_by = activated_by
        await session.commit()


def _write_snapshot(engine: PolicyEngine) -> None:
    path = snapshot_path(engine.version)
    if path.exists():
        if path.read_bytes() != engine.raw:
            raise ActivationError(f"revision snapshot {path} exists with different content")
        return  # byte-identical: append-only invariant holds
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(engine.raw)
