"""Verified, self-contained NDJSON audit export."""

import base64
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway.audit_keys import AuditKeyStore
from services.gateway.audit_log import GENESIS_HASH
from services.gateway.audit_verification import AuditRecord, verify_record
from services.gateway.db import AuditLog


async def prepare(
    sessionmaker: async_sessionmaker[AsyncSession],
    key_store: AuditKeyStore,
    from_seq: int | None,
    to_seq: int | None,
) -> tuple[dict[str, Any], int | None, int | None]:
    if from_seq is not None and from_seq <= 0 or to_seq is not None and to_seq <= 0:
        raise ValueError("audit sequence bounds must be positive integers")
    async with sessionmaker() as session:
        minimum, maximum = (
            await session.execute(select(func.min(AuditLog.seq), func.max(AuditLog.seq)))
        ).one()
    if minimum is None:
        manifest = _manifest(None, None, 0, True, {})
        return manifest, None, None
    start = from_seq if from_seq is not None else int(minimum)
    end = to_seq if to_seq is not None else int(maximum)
    if start > end:
        raise ValueError("from_seq must not exceed to_seq")
    async with sessionmaker() as session:
        rows = await session.stream_scalars(
            select(AuditLog)
            .where(AuditLog.seq >= start, AuditLog.seq <= end)
            .order_by(AuditLog.seq)
        )
        previous: str | None = GENESIS_HASH if start == 1 else None
        expected_seq = start
        used: set[str] = set()
        count = 0
        async for row in rows:
            if row.seq != expected_seq:
                raise ValueError(f"audit export range has a gap before seq {row.seq}")
            record = AuditRecord.from_row(row)
            if previous is None:
                previous = record.prev_hash
            previous = verify_record(record, previous, key_store.load_public)
            if record.key_id is None:
                raise ValueError(f"audit row {record.seq} has no key id")
            used.add(record.key_id)
            count += 1
            expected_seq += 1
    if count != end - start + 1:
        raise ValueError("audit export range does not exist in full")
    keys = {
        key_id: key_store.public_path(key_id).read_text(encoding="utf-8") for key_id in sorted(used)
    }
    return _manifest(start, end, count, start == 1, keys), start, end


def _manifest(
    start: int | None,
    end: int | None,
    count: int,
    genesis_anchored: bool,
    keys: dict[str, str],
) -> dict[str, Any]:
    return {
        "type": "manifest",
        "format": "portunusmcp-audit-export",
        "version": 1,
        "bounds": {"from_seq": start, "to_seq": end},
        "genesis_anchored": genesis_anchored,
        "prefix_attested": genesis_anchored,
        "row_count": count,
        "export_timestamp": datetime.now(UTC).isoformat(),
        "public_keys": keys,
    }


def row_dict(row: AuditLog) -> dict[str, Any]:
    return {
        "type": "audit_row",
        "seq": row.seq,
        "prev_hash": row.prev_hash,
        "curr_hash": row.curr_hash,
        "signature": base64.b64encode(row.signature).decode("ascii"),
        "timestamp": row.timestamp.isoformat(),
        "identity_id": row.identity_id,
        "server_id": row.server_id,
        "tool_name": row.tool_name,
        "policy_version": row.policy_version,
        "event_type": row.event_type,
        "risk_score": row.risk_score,
        "payload": row.payload,
        "latency_ms": row.latency_ms,
        "key_id": row.key_id,
    }


async def stream(
    sessionmaker: async_sessionmaker[AsyncSession],
    manifest: dict[str, Any],
    start: int | None,
    end: int | None,
) -> AsyncIterator[bytes]:
    yield (json.dumps(manifest, ensure_ascii=False, sort_keys=True) + "\n").encode()
    if start is None or end is None:
        return
    async with sessionmaker() as session:
        rows = await session.stream_scalars(
            select(AuditLog)
            .where(AuditLog.seq >= start, AuditLog.seq <= end)
            .order_by(AuditLog.seq)
        )
        async for row in rows:
            yield (json.dumps(row_dict(row), ensure_ascii=False, sort_keys=True) + "\n").encode()


def verify_file(path: str | Path) -> tuple[int, bool]:
    with Path(path).open(encoding="utf-8") as source:
        try:
            manifest = json.loads(next(source))
        except (StopIteration, json.JSONDecodeError) as exc:
            raise ValueError("audit export has no valid manifest") from exc
        if (
            manifest.get("type") != "manifest"
            or manifest.get("format") != "portunusmcp-audit-export"
            or manifest.get("version") != 1
        ):
            raise ValueError("unsupported audit export format")
        keys: dict[str, ec.EllipticCurvePublicKey] = {}
        for key_id, pem in manifest.get("public_keys", {}).items():
            key = serialization.load_pem_public_key(pem.encode())
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise ValueError(f"audit key {key_id} is not EC")
            keys[key_id] = key

        def load_public(key_id: str) -> ec.EllipticCurvePublicKey:
            try:
                return keys[key_id]
            except KeyError:
                raise ValueError(f"missing public key {key_id}") from None

        bounds = manifest.get("bounds") or {}
        start, end = bounds.get("from_seq"), bounds.get("to_seq")
        previous: str | None = GENESIS_HASH if start == 1 else None
        expected_seq = start
        count = 0
        used: set[str] = set()
        for line in source:
            try:
                item = json.loads(line)
                record = AuditRecord(
                    seq=item["seq"],
                    prev_hash=item["prev_hash"],
                    curr_hash=item["curr_hash"],
                    signature=base64.b64decode(item["signature"], validate=True),
                    key_id=item["key_id"],
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    identity_id=item["identity_id"],
                    server_id=item["server_id"],
                    tool_name=item["tool_name"],
                    policy_version=item["policy_version"],
                    event_type=item["event_type"],
                    risk_score=item["risk_score"],
                    payload=item["payload"],
                    latency_ms=item["latency_ms"],
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid audit export row after {count} rows") from exc
            if expected_seq is None or record.seq != expected_seq:
                raise ValueError(f"audit export sequence mismatch at seq {record.seq}")
            if previous is None:
                previous = record.prev_hash
            previous = verify_record(record, previous, load_public)
            assert record.key_id is not None
            used.add(record.key_id)
            expected_seq += 1
            count += 1
    if count != manifest.get("row_count"):
        raise ValueError("audit export row count does not match manifest")
    if count and (not isinstance(end, int) or expected_seq != end + 1):
        raise ValueError("audit export bounds do not match rows")
    if used != set(keys):
        raise ValueError("audit export key bundle is not exact")
    return count, bool(manifest.get("genesis_anchored"))
