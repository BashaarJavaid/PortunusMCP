"""Incremental audit-chain verifier (ARCHITECTURE.md §4.8, ROADMAP item 11).

Verifies forward from the last_verified_seq checkpoint instead of rescanning from
seq=1 — O(recent writes), which is what makes "run this every minute" credible. Each
row is checked three ways: chain linkage (prev_hash continues), chain math (recomputed
curr_hash matches), and the ECDSA signature over curr_hash (a regenerated chain is
self-consistent but unsignable without the gateway's private key).

On a break the checkpoint stops advancing at the last good row and never moves past
it — everything downstream of a confirmed break is untrusted regardless of whether it
individually re-verifies. Alerting is the structured error log plus the §7
portunusmcp_audit_chain_verify_failures_total counter (item 25) — alert on any increase.
The daemon being down never blocks live traffic (§5): it is a detective control, not
a preventive one.
"""

import structlog
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway import metrics, signing
from services.gateway.audit_keys import AuditKeyStore
from services.gateway.audit_log import GENESIS_HASH
from services.gateway.audit_verification import AuditRecord, verify_record
from services.gateway.db import AuditLog, VerifierCheckpoint

logger = structlog.get_logger(__name__)

CHECKPOINT_ID = 1


async def verify_increment(
    sessionmaker: async_sessionmaker[AsyncSession],
    public_keys: AuditKeyStore | ec.EllipticCurvePublicKey,
) -> tuple[int, str | None]:
    """One verification pass from the checkpoint forward. Returns (rows verified this
    pass, failure description or None). The checkpoint advances only through the last
    good row; a failing row is re-hit on every subsequent pass until resolved."""
    async with sessionmaker() as session:
        checkpoint = await session.get(VerifierCheckpoint, CHECKPOINT_ID)
        last_verified = checkpoint.last_verified_seq if checkpoint is not None else 0

        if last_verified == 0:
            prev_hash = GENESIS_HASH
        else:
            anchor = await session.get(AuditLog, last_verified)
            if anchor is None:
                return 0, f"checkpoint row seq={last_verified} is missing from audit_log"
            prev_hash = anchor.curr_hash

        if isinstance(public_keys, ec.EllipticCurvePublicKey):
            legacy_id = signing.key_id(public_keys)

            def load_public_key(key_id: str) -> ec.EllipticCurvePublicKey:
                if key_id != legacy_id:
                    raise ValueError(f"missing public key {key_id}")
                return public_keys

        else:
            legacy_id = None
            load_public_key = public_keys.load_public

        verified = 0
        failure: str | None = None
        rows = await session.stream_scalars(
            select(AuditLog).where(AuditLog.seq > last_verified).order_by(AuditLog.seq)
        )
        async for row in rows:
            try:
                prev_hash = verify_record(
                    AuditRecord.from_row(row),
                    prev_hash,
                    load_public_key,
                    legacy_key_id=legacy_id,
                )
            except (OSError, ValueError) as exc:
                failure = str(exc)
                logger.error("audit_chain_verification_failed", failure=failure, seq=row.seq)
                metrics.AUDIT_VERIFY_FAILURES.inc()
                break
            last_verified = row.seq
            verified += 1

        if verified:
            if checkpoint is None:
                session.add(VerifierCheckpoint(id=CHECKPOINT_ID, last_verified_seq=last_verified))
            else:
                checkpoint.last_verified_seq = last_verified
            await session.commit()
        return verified, failure
