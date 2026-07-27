"""Shared audit-row verification for live, incremental, and exported chains."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway import signing
from services.gateway.audit_keys import AuditKeyStore
from services.gateway.audit_log import GENESIS_HASH, compute_hash
from services.gateway.db import AuditLog


class VerificationError(ValueError):
    pass


class PublicKeyLoader(Protocol):
    def __call__(self, key_id: str) -> ec.EllipticCurvePublicKey: ...


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    prev_hash: str
    curr_hash: str
    signature: bytes
    key_id: str | None
    timestamp: datetime
    identity_id: str
    server_id: str | None
    tool_name: str | None
    policy_version: int
    event_type: str
    risk_score: int | None
    payload: dict[str, Any]
    latency_ms: int | None

    @classmethod
    def from_row(cls, row: AuditLog) -> "AuditRecord":
        return cls(
            seq=row.seq,
            prev_hash=row.prev_hash,
            curr_hash=row.curr_hash,
            signature=row.signature,
            key_id=row.key_id,
            timestamp=row.timestamp,
            identity_id=row.identity_id,
            server_id=row.server_id,
            tool_name=row.tool_name,
            policy_version=row.policy_version,
            event_type=row.event_type,
            risk_score=row.risk_score,
            payload=row.payload,
            latency_ms=row.latency_ms,
        )


def verify_record(
    record: AuditRecord,
    expected_prev: str,
    load_public_key: PublicKeyLoader,
    *,
    legacy_key_id: str | None = None,
) -> str:
    key_id = record.key_id or legacy_key_id
    if key_id is None:
        raise VerificationError(f"MISSING KEY ID at seq={record.seq}")
    if record.prev_hash != expected_prev:
        raise VerificationError(
            f"BROKEN LINK at seq={record.seq}: prev_hash does not continue the chain"
        )
    if compute_hash(expected_prev, record.payload) != record.curr_hash:
        raise VerificationError(
            f"TAMPERED ROW at seq={record.seq}: payload does not match curr_hash"
        )
    public_key = load_public_key(key_id)
    if signing.key_id(public_key) != key_id:
        raise VerificationError(f"KEY FINGERPRINT MISMATCH at seq={record.seq}: {key_id}")
    if not signing.verify(public_key, record.signature, record.curr_hash):
        raise VerificationError(
            f"BAD SIGNATURE at seq={record.seq}: curr_hash was not signed by {key_id}"
        )
    protected = {
        "event_type": record.event_type,
        "identity_id": record.identity_id,
        "server_id": record.server_id,
        "tool_name": record.tool_name,
        "policy_version": record.policy_version,
    }
    for field, projected in protected.items():
        if record.payload.get(field) != projected:
            raise VerificationError(
                f"TAMPERED PROJECTION at seq={record.seq}: {field} differs from payload"
            )
    payload_key_id = record.payload.get("key_id")
    if payload_key_id is not None and payload_key_id != key_id:
        raise VerificationError(
            f"TAMPERED PROJECTION at seq={record.seq}: key_id differs from payload"
        )
    return record.curr_hash


async def backfill_legacy_key_ids(
    sessionmaker: async_sessionmaker[AsyncSession],
    key_store: AuditKeyStore,
    active_key_id: str,
) -> int:
    """Verify the complete chain before binding pre-item-42 rows to the active key."""
    async with sessionmaker() as session:
        has_legacy = (
            await session.execute(select(AuditLog.seq).where(AuditLog.key_id.is_(None)).limit(1))
        ).scalar_one_or_none()
        if has_legacy is None:
            return 0
        previous = GENESIS_HASH
        rows = await session.stream_scalars(select(AuditLog).order_by(AuditLog.seq))
        count = 0
        async for row in rows:
            previous = verify_record(
                AuditRecord.from_row(row),
                previous,
                key_store.load_public,
                legacy_key_id=active_key_id,
            )
            if row.key_id is None:
                count += 1
        await session.execute(
            update(AuditLog).where(AuditLog.key_id.is_(None)).values(key_id=active_key_id)
        )
        await session.commit()
        return count
