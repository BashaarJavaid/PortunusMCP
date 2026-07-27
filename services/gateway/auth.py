"""API key verification, identity resolution (ARCHITECTURE.md §4.8 Auth Layer).

Two per-identity auth modes (item 34). `bearer` is hash-and-lookup: the policy store
holds only SHA256(key) as "sha256:<hex>"; the presented key is hashed and looked up
directly. Keys are 256-bit random values (see scripts/generate_api_key.py), so no
salting is needed — and deterministic hashing is what makes direct lookup possible.
Never log the key (§6). `signed` puts no secret on the wire at all: the request
carries a non-secret key id plus an HMAC-SHA256 over the canonical
(nonce, timestamp, method, tool, arguments) tuple in params._meta, verified against
a secret the gateway resolves from the environment at policy load. A captured signed
request contains no credential, so a fresh nonce cannot be re-signed.

Item 43 replaces the old gateway-wide risk signal with a source-scoped fixed-window
limiter shared by MCP and admin authentication. Uvicorn resolves trusted proxy
headers before this module sees the ASGI scope; only the resulting client IP is used.
Redis failure fails closed because the limiter is now a preventive control.
"""

import hashlib
import hmac
from collections.abc import Awaitable, Mapping
from typing import Any, Literal, cast

import canonicaljson
import redis.asyncio as aioredis
import structlog

from services.gateway import metrics
from services.gateway.config import settings
from services.gateway.policy_engine import PolicyEngine
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY

logger = structlog.get_logger(__name__)

KEY_ID_META_KEY = "portunusmcp/key-id"
SIGNATURE_META_KEY = "portunusmcp/signature"

_FAILURE_SCRIPT = """
local count = redis.call("INCR", KEYS[1])
if count == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return {count, redis.call("TTL", KEYS[1])}
"""


class AuthRateLimited(Exception):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after


class AuthLimiterUnavailable(Exception):
    pass


def client_source(scope: Mapping[str, Any]) -> str | None:
    client = scope.get("client")
    if not isinstance(client, tuple | list) or not client or not isinstance(client[0], str):
        return None
    return client[0] or None


def _failure_key(source: str) -> str:
    digest = hashlib.sha256(source.encode()).hexdigest()
    return f"rate:auth_failure:{digest}"


async def _blocked_ttl(redis_client: aioredis.Redis, source: str) -> int | None:
    key = _failure_key(source)
    try:
        raw = await redis_client.get(key)
        if int(raw or 0) <= settings.auth_failure_rate_limit:
            return None
        ttl: int = await redis_client.ttl(key)
    except Exception as exc:
        raise AuthLimiterUnavailable from exc
    return max(ttl, 1) if ttl > 0 else None


def _throttled(retry_after: int) -> None:
    metrics.AUTH_THROTTLED.inc()
    raise AuthRateLimited(retry_after)


async def _check_source(redis_client: aioredis.Redis, source: str) -> None:
    if (retry_after := await _blocked_ttl(redis_client, source)) is not None:
        _throttled(retry_after)


async def _record_failure(
    redis_client: aioredis.Redis,
    source: str,
    surface: Literal["mcp", "admin"],
) -> None:
    try:
        result = await cast(
            Awaitable[Any],
            redis_client.eval(
                _FAILURE_SCRIPT,
                1,
                _failure_key(source),
                str(settings.auth_failure_rate_window_seconds),
            ),
        )
        count, ttl = int(result[0]), max(int(result[1]), 1)
    except Exception as exc:
        raise AuthLimiterUnavailable from exc
    if count > settings.auth_failure_rate_limit:
        if count == settings.auth_failure_rate_limit + 1:
            logger.warning(
                "auth_source_throttled",
                source=source,
                surface=surface,
                retry_after_seconds=ttl,
            )
        _throttled(ttl)


def resolve_identity(api_key: str | None, engine: PolicyEngine) -> str | None:
    if not api_key:
        return None
    digest = hashlib.sha256(api_key.encode()).hexdigest()
    return engine.identity_for_key_hash(f"sha256:{digest}")


async def resolve_identity_tracked(
    api_key: str | None,
    engine: PolicyEngine,
    redis_client: aioredis.Redis,
    source: str | None,
    surface: Literal["mcp", "admin"],
) -> str | None:
    """Resolve a presented bearer key under the source limiter. Missing keys remain
    ordinary uncounted 401s at the caller."""
    if not api_key:
        return None
    if source is None:
        raise AuthLimiterUnavailable
    await _check_source(redis_client, source)
    identity_id = resolve_identity(api_key, engine)
    if identity_id is None:
        await _record_failure(redis_client, source, surface)
    return identity_id


def signature_payload(
    nonce: object, timestamp: object, method: str, tool: object, arguments: object
) -> bytes:
    """The canonical bytes a signed request's HMAC covers (item 34). canonicaljson —
    the same canonicalization the audit chain and drift hashes pin — kills every
    separator/encoding ambiguity a hand-rolled concatenation would reintroduce."""
    return canonicaljson.encode_canonical_json(
        {
            "nonce": nonce,
            "timestamp": timestamp,
            "method": method,
            "tool": tool,
            "arguments": arguments,
        }
    )


def sign_request(
    secret: bytes, nonce: object, timestamp: object, method: str, tool: object, arguments: object
) -> str:
    return hmac.new(
        secret, signature_payload(nonce, timestamp, method, tool, arguments), hashlib.sha256
    ).hexdigest()


def verify_signed_request(message: dict[str, Any], engine: PolicyEngine) -> str | None:
    """Resolve + verify a signed-mode JSON-RPC request: identity id on success, None
    on any failure — unknown key id, missing fields, bad signature (fail closed, §5).
    The nonce/timestamp are required members of the signed tuple here; their format
    and freshness are the Replay Guard's job (dedup → DENY_REPLAY, not 401)."""
    params = message.get("params") or {}
    if not isinstance(params, dict):
        return None
    meta = params.get("_meta") or {}
    if not isinstance(meta, dict):
        return None
    method = message.get("method")
    key_id = meta.get(KEY_ID_META_KEY)
    signature = meta.get(SIGNATURE_META_KEY)
    nonce = meta.get(NONCE_META_KEY)
    timestamp = meta.get(TIMESTAMP_META_KEY)
    if (
        not isinstance(method, str)
        or not isinstance(key_id, str)
        or not isinstance(signature, str)
        or nonce is None
        or timestamp is None
    ):
        return None
    identity_id = engine.identity_for_key_id(key_id)
    if identity_id is None:
        return None
    identity = engine.identity(identity_id)
    if identity is None or identity.auth_mode != "signed":
        return None
    if method == "tools/call":
        tool, arguments = params.get("name"), params.get("arguments")
    else:
        tool, arguments = None, None
    expected = sign_request(identity.signing_secret, nonce, timestamp, method, tool, arguments)
    if not hmac.compare_digest(expected, signature):
        return None
    return identity_id


async def verify_signed_request_tracked(
    message: dict[str, Any],
    engine: PolicyEngine,
    redis_client: aioredis.Redis,
    source: str | None,
    surface: Literal["mcp", "admin"],
) -> str | None:
    """Verify presented signed credentials under the source limiter. Requests with
    no key material remain ordinary uncounted 401s at the caller."""
    params = message.get("params") if isinstance(message, dict) else None
    meta = params.get("_meta") if isinstance(params, dict) else None
    presented = isinstance(meta, dict) and (
        meta.get(KEY_ID_META_KEY) is not None or meta.get(SIGNATURE_META_KEY) is not None
    )
    if not presented:
        return verify_signed_request(message, engine)
    if source is None:
        raise AuthLimiterUnavailable
    await _check_source(redis_client, source)
    identity_id = verify_signed_request(message, engine)
    if identity_id is None:
        await _record_failure(redis_client, source, surface)
    return identity_id
