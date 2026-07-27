"""Incremental verifier (§4.8, item 11): checkpointed forward verification, and the
attack the signature closes — a regenerated (self-consistent) hash chain forged
without the private key is caught, and the checkpoint never advances past the break."""

import asyncio
import os
import subprocess
import sys

from sqlalchemy import select

from services.gateway import signing
from services.gateway.audit_log import compute_hash
from services.gateway.audit_verifier import CHECKPOINT_ID, verify_increment
from services.gateway.config import settings
from services.gateway.db import AuditLog, VerifierCheckpoint, async_session
from tests.integration.conftest import Gateway
from tests.integration.test_audit_log import drive_session


async def checkpoint_seq() -> int:
    async with async_session() as db:
        row = await db.get(VerifierCheckpoint, CHECKPOINT_ID)
        return row.last_verified_seq if row is not None else 0


async def row_count() -> int:
    async with async_session() as db:
        return len(list((await db.execute(select(AuditLog.seq))).scalars()))


async def forge_chain_from(seq: int) -> None:
    """Tamper the payload at `seq` and recompute a self-consistent hash chain forward —
    what an attacker with Postgres write access but no private key can do (§4.8)."""
    async with async_session() as db:
        rows = list(
            (
                await db.execute(select(AuditLog).where(AuditLog.seq >= seq).order_by(AuditLog.seq))
            ).scalars()
        )
        rows[0].payload = {**rows[0].payload, "tool_name": "evil"}
        prev_hash = rows[0].prev_hash
        for row in rows:
            row.curr_hash = compute_hash(prev_hash, row.payload)
            row.prev_hash = prev_hash
            prev_hash = row.curr_hash
        await db.commit()


async def test_checkpoint_advances_and_verifies_only_new_rows(gateway: Gateway) -> None:
    await drive_session(gateway)
    total = await row_count()
    public_key = signing.load_public_key(settings.signing_public_key_file)

    verified, failure = await verify_increment(async_session, public_key)
    assert failure is None
    assert verified == total
    assert await checkpoint_seq() == total

    await drive_session(gateway)  # more traffic after the checkpoint
    new_total = await row_count()
    verified, failure = await verify_increment(async_session, public_key)
    assert failure is None
    assert verified == new_total - total  # only the delta, not a rescan from seq=1
    assert await checkpoint_seq() == new_total


async def test_forged_chain_is_caught_and_checkpoint_stops(gateway: Gateway) -> None:
    await drive_session(gateway)
    public_key = signing.load_public_key(settings.signing_public_key_file)
    await forge_chain_from(2)  # chain math is now self-consistent, signatures are not

    verified, failure = await verify_increment(async_session, public_key)
    assert failure is not None and "BAD SIGNATURE at seq=2" in failure
    assert verified == 1  # only the untouched row before the break
    assert await checkpoint_seq() == 1

    # Repeat runs stay stopped at the break; nothing downstream is trusted.
    verified, failure = await verify_increment(async_session, public_key)
    assert failure is not None and "BAD SIGNATURE at seq=2" in failure
    assert verified == 0
    assert await checkpoint_seq() == 1


def run_full_scan() -> "subprocess.CompletedProcess[str]":
    env = dict(os.environ, SIGNING_PUBLIC_KEYS_DIR=settings.signing_public_keys_dir)
    return subprocess.run(
        [sys.executable, "scripts/verify_audit_chain.py"],
        capture_output=True,
        text=True,
        env=env,
    )


async def test_full_scan_checks_signatures_too(gateway: Gateway) -> None:
    await drive_session(gateway)

    result = await asyncio.to_thread(run_full_scan)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "skipping signature checks" not in result.stdout

    await forge_chain_from(2)
    result = await asyncio.to_thread(run_full_scan)
    assert result.returncode == 1
    assert "BAD SIGNATURE at seq=2" in result.stdout
