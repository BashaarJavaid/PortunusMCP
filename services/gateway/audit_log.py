"""Hash-chain audit writer (ARCHITECTURE.md §4.8).

Chain: H_t = SHA256(H_(t-1) || canonical_json(payload_t)). The payload is
self-contained — identity, server, tool, event type and policy version live *inside*
it — because the hash covers only the payload; the bare columns on audit_log are
queryable projections, and tampering them is caught via their hash-protected copies.
Every row's curr_hash is additionally ECDSA-signed (item 11) so a regenerated chain
is detectable without the private key.

The latest chain hash is cached in Redis (`latest_audit_hash`) so the hot path never
does a Postgres read; the Postgres insert itself stays synchronous and awaited —
"no record, no action" (§5): if the insert fails, the exception propagates and the
caller must deny.
"""

import asyncio
import hashlib
from typing import Any

import canonicaljson
import redis.asyncio as aioredis
import structlog
from cryptography.hazmat.primitives.asymmetric import ec
from redis.exceptions import WatchError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway import signing
from services.gateway.audit_keys import AuditKeyStore, Rotation
from services.gateway.db import AuditLog
from services.gateway.decision import EventType
from services.gateway.policy_engine import PolicyStore

logger = structlog.get_logger(__name__)

GENESIS_HASH = "0" * 64
POINTER_KEY = "latest_audit_hash"


def compute_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        prev_hash.encode() + canonicaljson.encode_canonical_json(payload)
    ).hexdigest()


def _jsonb_safe(value: Any) -> Any:
    """Postgres JSONB cannot store \\u0000 in strings, and deny rows persist raw
    attacker arguments (item 21) — escape it so a null byte can't kill the write
    and leave a terminal unaudited. Applied before hashing, so the chain covers
    exactly what's stored."""
    if isinstance(value, str):
        return value.replace("\x00", "\\u0000")
    if isinstance(value, dict):
        return {_jsonb_safe(k): _jsonb_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonb_safe(v) for v in value]
    return value


class AuditWriter:
    def __init__(
        self,
        redis_client: aioredis.Redis,
        sessionmaker: async_sessionmaker[AsyncSession],
        policy_store: PolicyStore,
        signing_key: ec.EllipticCurvePrivateKey,
        key_id: str | None = None,
    ) -> None:
        self._redis = redis_client
        self._sessions = sessionmaker
        self._policy_store = policy_store
        self._signing_key = signing_key
        self._key_id = key_id or signing.key_id(signing_key.public_key())
        self._available = True
        # Serializes chain writes so seq order matches chain order. Sufficient for the
        # single-instance Phase 1 deployment; multi-replica write ordering is the
        # documented §10 concern, deferred with the rest of the scaling story.
        self._lock = asyncio.Lock()

    async def write(
        self,
        event_type: EventType,
        identity_id: str,
        server_id: str | None = None,
        tool_name: str | None = None,
        payload_extra: dict[str, Any] | None = None,
        risk_score: int | None = None,
    ) -> int:
        """Append one chained row and return its seq. Raises on any failure — callers
        must treat that as a terminal deny (§5 fail-closed)."""
        if not self._available:
            raise RuntimeError("audit signing-key recovery is pending")
        async with self._lock:
            return await self._write_locked(
                event_type,
                identity_id,
                server_id,
                tool_name,
                payload_extra,
                risk_score,
            )

    async def _write_locked(
        self,
        event_type: EventType,
        identity_id: str,
        server_id: str | None,
        tool_name: str | None,
        payload_extra: dict[str, Any] | None,
        risk_score: int | None,
    ) -> int:
        while True:
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(POINTER_KEY)
                    prev_hash = await self._prev_hash(pipe)
                    payload: dict[str, Any] = _jsonb_safe(
                        {
                            "event_type": event_type.value,
                            "identity_id": identity_id,
                            "server_id": server_id,
                            "tool_name": tool_name,
                            "policy_version": self._policy_store.engine.version,
                            "key_id": self._key_id,
                            **(payload_extra or {}),
                        }
                    )
                    curr_hash = compute_hash(prev_hash, payload)
                    seq = await self._insert(
                        prev_hash,
                        curr_hash,
                        payload,
                        event_type,
                        identity_id,
                        server_id,
                        tool_name,
                        risk_score,
                    )
                    pipe.multi()  # type: ignore[no-untyped-call]  # redis-py lacks a stub here
                    await pipe.set(POINTER_KEY, curr_hash)
                    await pipe.execute()
                    return seq
                except WatchError:
                    continue

    async def rotate(self, key_store: AuditKeyStore, approved_by: str) -> tuple[int, str, str]:
        if not self._available:
            raise RuntimeError("audit signing-key recovery is pending")
        async with self._lock:
            rotation: Rotation | None = None
            handed_off = False
            try:
                rotation, new_private = key_store.prepare(approved_by)
                seq = await self._write_locked(
                    EventType.AUDIT_KEY_ROTATED,
                    approved_by,
                    None,
                    None,
                    {
                        "operation_id": rotation.operation_id,
                        "old_key_id": rotation.old_key_id,
                        "new_key_id": rotation.new_key_id,
                    },
                    None,
                )
                handed_off = True
                rotation = key_store.mark_handoff(rotation, seq)
                key_store.promote(rotation)
                self._signing_key = new_private
                self._key_id = rotation.new_key_id
                key_store.finish()
                return seq, rotation.old_key_id, rotation.new_key_id
            except Exception:
                if handed_off:
                    self._available = False
                else:
                    key_store.finish()
                raise

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def available(self) -> bool:
        return self._available

    async def _prev_hash(self, pipe: "aioredis.client.Pipeline") -> str:
        cached: bytes | None = await pipe.get(POINTER_KEY)
        if cached is not None:
            return cached.decode()
        # Cold start / evicted pointer: the one-off slow path §4.8 keeps off the hot path.
        async with self._sessions() as session:
            result = await session.execute(
                select(AuditLog.curr_hash).order_by(AuditLog.seq.desc()).limit(1)
            )
            row = result.scalar_one_or_none()
        return row if row is not None else GENESIS_HASH

    async def _insert(
        self,
        prev_hash: str,
        curr_hash: str,
        payload: dict[str, Any],
        event_type: EventType,
        identity_id: str,
        server_id: str | None,
        tool_name: str | None,
        risk_score: int | None,
    ) -> int:
        async with self._sessions() as session:
            row = AuditLog(
                prev_hash=prev_hash,
                curr_hash=curr_hash,
                signature=signing.sign(self._signing_key, curr_hash),
                key_id=self._key_id,
                identity_id=identity_id,
                server_id=server_id,
                tool_name=tool_name,
                policy_version=self._policy_store.engine.version,
                event_type=event_type.value,
                risk_score=risk_score,
                payload=payload,
            )
            session.add(row)
            await session.commit()
            return row.seq
