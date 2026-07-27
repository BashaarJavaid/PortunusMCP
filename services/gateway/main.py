"""FastAPI app entrypoint."""

import asyncio
import json
import signal
from collections.abc import AsyncIterator, MutableMapping
from contextlib import asynccontextmanager, suppress
from typing import Any

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI, HTTPException, Request
from mcp.server.streamable_http import MCP_SESSION_ID_HEADER
from mcp.server.transport_security import (
    TransportSecurityMiddleware,
    TransportSecuritySettings,
)
from mcp.types import JSONRPCMessage, JSONRPCNotification, JSONRPCRequest
from prometheus_client import start_http_server
from pydantic import BaseModel
from sqlalchemy import text
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse, Response
from starlette.types import Receive, Scope, Send

from services.gateway import (
    auth,
    decision_explainer,
    logging_config,
    policy_engine,
    policy_simulator,
    policy_versions,
    signing,
    upstream_client,
)
from services.gateway.approvals import ApprovalStore
from services.gateway.audit_log import AuditWriter
from services.gateway.config import settings
from services.gateway.db import AuditLog, async_session
from services.gateway.decision import Decision, DecisionOutcome, EventType
from services.gateway.drift_detector import DriftDetector
from services.gateway.policy_engine import PolicyStore
from services.gateway.replay_guard import ReplayGuard
from services.gateway.risk_engine import RiskEngine
from services.gateway.schema_cache import SchemaCache
from services.gateway.session_manager import (
    DuplicateRequestId,
    InflightLimitExceeded,
    RateLimiterUnavailable,
    SessionLimitExceeded,
    SessionManager,
)
from services.gateway.step_up import ChallengeStore

logging_config.configure()
logger = structlog.get_logger(__name__)

KEY_HEADER = "x-portunusmcp-key"


async def _reload_policy(
    store: PolicyStore,
    writer: AuditWriter,
    manager: SessionManager,
    runtime: upstream_client.DockerRuntime,
) -> None:
    old_version = store.engine.version
    candidate = store.load_candidate()
    if candidate is None:
        return  # last-known-good stays active; failure already logged
    try:
        await runtime.preflight(candidate.policy.servers)
        # Record before swap (item 19): a rejected or unrecordable activation keeps
        # last-known-good (§5 fail-closed).
        await policy_versions.record_activation(candidate, "operator", async_session)
    except Exception:
        logger.exception("policy_activation_rejected_keeping_last_known_good")
        return
    store.swap(candidate)
    await manager.evict_outdated()
    try:
        await writer.write(
            EventType.POLICY_ACTIVATED,
            "operator",
            payload_extra={
                "old_version": old_version,
                "new_version": store.engine.version,
                "content_hash": store.engine.content_hash,
            },
        )
    except Exception:
        logger.exception("audit_write_failed", event_type="POLICY_ACTIVATED")


async def _record_startup_activation(engine: policy_engine.PolicyEngine) -> None:
    """Boot-time activation record (item 19). A conflict here is almost always
    leftover dev/demo state hitting the fail-closed monotonicity check — a good
    security property with a terrible first-run experience (item 38). Startup
    still fails, but with the remedy in the message; SIGHUP and rollback conflicts
    keep their own handling, where a state wipe would be the wrong advice."""
    try:
        await policy_versions.record_activation(engine, "startup", async_session)
    except policy_versions.ActivationError as exc:
        hint = (
            f"{exc} — leftover dev/demo state? reset with:"
            " python scripts/reset_dev_state.py (in docker:"
            " docker compose run --rm gateway python scripts/reset_dev_state.py --yes)"
        )
        logger.error("policy_activation_conflict_at_startup", detail=hint)
        raise policy_versions.ActivationError(hint) from exc


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # An invalid or missing policy file must fail startup (ARCHITECTURE.md §5);
    # so must a missing/unreadable audit signing key (§4.8, item 11).
    store = PolicyStore(settings.policy_file)
    app.state.policy_store = store
    signing_key = signing.load_private_key(settings.signing_key_file)
    app.state.signing_key = signing_key
    runtime = await upstream_client.DockerRuntime.create(store.engine.policy.servers)
    app.state.upstream_runtime = runtime
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    app.state.redis = redis_client  # auth-failure counter (§4.8, item 18)
    writer = AuditWriter(redis_client, async_session, store, signing_key)
    app.state.audit_writer = writer  # rollback endpoint (item 19)
    # Record + audit the boot-time activation (item 19). A monotonicity conflict
    # (e.g. same version, different content) fails startup; the snapshot/row are
    # idempotent on a re-seen version but the audit row is unconditional, so every
    # boot's active policy — including one reverting a rollback — is in the chain.
    await _record_startup_activation(store.engine)
    await writer.write(
        EventType.POLICY_ACTIVATED,
        "startup",
        payload_extra={
            "old_version": None,
            "new_version": store.engine.version,
            "content_hash": store.engine.content_hash,
        },
    )
    detector = DriftDetector(async_session, writer)
    app.state.drift_detector = detector
    risk_engine = RiskEngine(redis_client, detector)
    app.state.risk_engine = risk_engine
    approval_store = ApprovalStore(async_session, writer)
    app.state.approval_store = approval_store
    # Restart-durable approvals (§4.8): expire pending rows whose TTL lapsed while
    # the gateway was down before serving traffic.
    await approval_store.expire_stale()
    manager = SessionManager(
        redis_client,
        store,
        writer,
        SchemaCache(redis_client),
        detector,
        ReplayGuard(redis_client, settings.replay_window_seconds),
        risk_engine,
        approval_store,
        ChallengeStore(redis_client),
        runtime,
    )
    app.state.session_manager = manager
    # §7 metrics on a separate internal-only listener — never the published app
    # port, since labels carry identity ids and tool names (item 25). Loopback
    # unless METRICS_HOST opens it (compose does; see config.py).
    metrics_server, _ = start_http_server(settings.metrics_port, settings.metrics_host)
    sweep = asyncio.create_task(manager.sweep_loop())
    # Policy hot-reload on SIGHUP (§8): docker kill -s HUP <gateway>.
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(
        signal.SIGHUP,
        lambda: loop.create_task(_reload_policy(store, writer, manager, runtime)),
    )
    try:
        yield
    finally:
        # SIGTERM lands here via uvicorn's graceful shutdown (ARCHITECTURE.md §4.8).
        metrics_server.shutdown()
        with suppress(ValueError):
            loop.remove_signal_handler(signal.SIGHUP)
        sweep.cancel()
        await manager.shutdown_all()
        await redis_client.aclose()


app = FastAPI(title="PortunusMCP Gateway", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


async def _readiness_check(app: FastAPI) -> dict[str, str]:
    async def postgres() -> None:
        async with async_session() as session:
            await session.execute(text("SELECT 1"))

    async def redis() -> None:
        await app.state.redis.ping()

    async def signing_key() -> None:
        private_key = app.state.signing_key
        signature = signing.sign(private_key, "readiness")
        if not signing.verify(private_key.public_key(), signature, "readiness"):
            raise ValueError

    checks = {"postgres": postgres, "redis": redis, "signing": signing_key}
    tasks = {asyncio.create_task(check()): name for name, check in checks.items()}
    done, pending = await asyncio.wait(tasks, timeout=settings.readiness_timeout_seconds)
    result = {name: "failed" for name in checks}
    for task in done:
        try:
            task.result()
        except Exception:
            pass
        else:
            result[tasks[task]] = "ok"
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    return result


@app.get("/ready")
async def ready(request: Request) -> JSONResponse:
    checks = await _readiness_check(request.app)
    is_ready = all(value == "ok" for value in checks.values())
    return JSONResponse(
        {"status": "ready" if is_ready else "not_ready", "checks": checks},
        status_code=200 if is_ready else 503,
    )


@app.post("/admin/tools/{server_id}/{tool_name}/approve")
async def approve_tool(server_id: str, tool_name: str, request: Request) -> dict[str, object]:
    """Drift re-approval (§4.8): snapshot the observed schema as the accepted baseline.
    Audited, authenticated admin action — requires a key resolving to an admin identity."""
    store: PolicyStore = request.app.state.policy_store
    identity_id = await auth.resolve_identity_tracked(
        request.headers.get(KEY_HEADER), store.engine, request.app.state.redis
    )
    if identity_id is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    if not store.engine.is_admin(identity_id):
        raise HTTPException(status_code=403, detail="admin identity required")
    detector: DriftDetector = request.app.state.drift_detector
    try:
        seq = await detector.approve(server_id, tool_name, approved_by=identity_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    decision = Decision(
        decision=DecisionOutcome.ALLOW,
        event_type=EventType.APPROVED,
        reason=f"schema for {tool_name!r} on {server_id!r} re-approved by {identity_id!r}",
        matched_rules=["admin_approval"],
        policy_version=store.engine.version,
        audit_id=str(seq),
    )
    return decision.model_dump(mode="json")


@app.post("/admin/approvals/{approval_id}/approve")
async def approve_call(approval_id: str, request: Request) -> dict[str, object]:
    """Human approval grant (§4.8, item 16): flips a pending approval to approved so
    the client's retry (params._meta["portunusmcp/approval_id"]) can redeem it once.
    Also applies one risk-decay step for the (identity, tool) pair — a human judged
    this high-risk call fine, and that calibrates future behavioral scoring."""
    store: PolicyStore = request.app.state.policy_store
    identity_id = await auth.resolve_identity_tracked(
        request.headers.get(KEY_HEADER), store.engine, request.app.state.redis
    )
    if identity_id is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    if not store.engine.is_admin(identity_id):
        raise HTTPException(status_code=403, detail="admin identity required")
    approval_store: ApprovalStore = request.app.state.approval_store
    try:
        seq, requester_id, server_id, tool_name = await approval_store.approve(
            approval_id, approved_by=identity_id
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    risk_engine: RiskEngine = request.app.state.risk_engine
    await risk_engine.apply_decay(requester_id, server_id, tool_name)
    decision = Decision(
        decision=DecisionOutcome.ALLOW,
        event_type=EventType.APPROVED,
        reason=f"call to {tool_name!r} approved by {identity_id!r}",
        matched_rules=["admin_approval"],
        policy_version=store.engine.version,
        audit_id=str(seq),
        approval_id=approval_id,
    )
    return decision.model_dump(mode="json")


@app.post("/admin/policy/rollback/{version}")
async def rollback_policy(version: int, request: Request) -> dict[str, object]:
    """Re-activate a prior policy revision (§4.8, item 19): loads the append-only
    snapshot, verifies it against the recorded content_hash, swaps the in-memory
    PolicyStore, and refreshes the policy_versions row. In-memory only — POLICY_FILE
    on disk is mounted read-only and keeps the newer version until the operator
    updates it; a restart re-activates whatever is on disk (audited)."""
    store: PolicyStore = request.app.state.policy_store
    identity_id = await auth.resolve_identity_tracked(
        request.headers.get(KEY_HEADER), store.engine, request.app.state.redis
    )
    if identity_id is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    if not store.engine.is_admin(identity_id):
        raise HTTPException(status_code=403, detail="admin identity required")
    snapshot = policy_versions.snapshot_path(version)
    if not snapshot.exists():
        raise HTTPException(status_code=404, detail=f"no revision snapshot for v{version}")
    try:
        engine = policy_engine.load_bytes(snapshot.read_bytes())
    except Exception as exc:
        raise HTTPException(status_code=409, detail=f"revision v{version} is invalid") from exc
    runtime: upstream_client.DockerRuntime = request.app.state.upstream_runtime
    try:
        await runtime.preflight(engine.policy.servers)
    except upstream_client.RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        await policy_versions.record_rollback(engine, identity_id, async_session)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except policy_versions.ActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    old_version = store.engine.version
    writer: AuditWriter = request.app.state.audit_writer
    seq = await writer.write(
        EventType.POLICY_ACTIVATED,
        identity_id,
        payload_extra={
            "old_version": old_version,
            "new_version": engine.version,
            "content_hash": engine.content_hash,
            "rollback": True,
        },
    )
    store.swap(engine)
    manager: SessionManager = request.app.state.session_manager
    await manager.evict_outdated()
    logger.warning(
        "policy_rolled_back_in_memory_only",
        old_version=old_version,
        new_version=engine.version,
        hint="POLICY_FILE on disk still holds the newer version; update it or a restart reverts",
    )
    decision = Decision(
        decision=DecisionOutcome.ALLOW,
        event_type=EventType.POLICY_ACTIVATED,
        reason=f"policy rolled back from v{old_version} to v{engine.version} by {identity_id!r}",
        matched_rules=["admin_rollback"],
        policy_version=engine.version,
        audit_id=str(seq),
    )
    return decision.model_dump(mode="json")


async def _require_admin(request: Request) -> str:
    """Shared /admin/* auth (item 20 endpoints): key resolves to an admin identity."""
    store: PolicyStore = request.app.state.policy_store
    identity_id = await auth.resolve_identity_tracked(
        request.headers.get(KEY_HEADER), store.engine, request.app.state.redis
    )
    if identity_id is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    if not store.engine.is_admin(identity_id):
        raise HTTPException(status_code=403, detail="admin identity required")
    return identity_id


@app.get("/admin/decisions/{seq}")
async def get_decision(seq: int, request: Request) -> dict[str, object]:
    """Decision Explanation, historical entry point (§4.8, item 20): reconstruct the
    canonical Decision an audit row recorded. {seq} is the audit_log seq — the same
    value clients receive as Decision.audit_id. Non-decision rows are 404."""
    await _require_admin(request)
    async with async_session() as session:
        row = await session.get(AuditLog, seq)
    if row is None:
        raise HTTPException(status_code=404, detail=f"no audit row {seq}")
    try:
        decision = decision_explainer.from_audit_row(row)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return decision.model_dump(mode="json")


class ExplainRequest(BaseModel):
    identity: str
    tool: str
    # Omitted + exactly one registered server -> that server; ambiguous -> 400.
    server: str | None = None
    arguments: dict[str, Any] = {}
    context: dict[str, Any] = {}


@app.post("/admin/decisions/explain")
async def explain_decision(body: ExplainRequest, request: Request) -> dict[str, object]:
    """Decision Explanation, hypothetical entry point (§4.8, item 20): dry-run the
    §4.2 pipeline for a would-be call against the current in-memory policy — no
    audit rows, no approvals, no counter bumps, no upstream traffic."""
    await _require_admin(request)
    engine = request.app.state.policy_store.engine
    server_id = body.server
    if server_id is None:
        if len(engine.policy.servers) != 1:
            raise HTTPException(
                status_code=400, detail="multiple servers registered; specify `server`"
            )
        server_id = next(iter(engine.policy.servers))
    decision = await decision_explainer.explain_call(
        body.identity,
        body.tool,
        server_id,
        body.arguments,
        body.context,
        engine=engine,
        detector=request.app.state.drift_detector,
        risk=request.app.state.risk_engine,
        schema_cache=SchemaCache(request.app.state.redis),
    )
    return decision.model_dump(mode="json")


@app.post("/admin/policy/simulate")
async def simulate_policy(
    body: policy_simulator.SimulateRequest, request: Request
) -> dict[str, object]:
    """Policy Simulation Mode (§4.8, item 21): replay historical decisions against
    a candidate revision (candidate_version) or diff two revisions
    (compare_versions) — read-only, nothing is activated and nothing is audited."""
    await _require_admin(request)
    if (body.candidate_version is None) == (body.compare_versions is None):
        raise HTTPException(
            status_code=400,
            detail="exactly one of candidate_version or compare_versions is required",
        )
    if body.compare_versions is not None and len(body.compare_versions) != 2:
        raise HTTPException(status_code=400, detail="compare_versions must be exactly 2 versions")
    deps: dict[str, Any] = {
        "sessionmaker": async_session,
        "detector": request.app.state.drift_detector,
        "risk": request.app.state.risk_engine,
        "schema_cache": SchemaCache(request.app.state.redis),
    }
    try:
        result: policy_simulator.HistoricalSimulation | policy_simulator.CompareSimulation
        if body.candidate_version is not None:
            result = await policy_simulator.simulate_historical(
                body.candidate_version, body.replay_window, **deps
            )
        else:
            assert body.compare_versions is not None
            result = await policy_simulator.simulate_compare(
                body.compare_versions, body.replay_window, **deps
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except policy_versions.ActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return result.model_dump(mode="json")


class _BodyRejected(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message


async def _buffer_body(receive: Receive) -> tuple[bytes, Receive, asyncio.Event]:
    """Drain a bounded body and return the same bytes through a replayable receive."""
    chunks: list[bytes] = []
    size = 0
    while True:
        event = await receive()
        if event["type"] != "http.request":
            raise _BodyRejected(400, "invalid request body")
        chunk = event.get("body", b"")
        size += len(chunk)
        if size > settings.max_mcp_body_bytes:
            raise _BodyRejected(413, "request body too large")
        chunks.append(chunk)
        if not event.get("more_body"):
            break
    body = b"".join(chunks)
    replayed = False
    disconnected = asyncio.Event()

    async def replay() -> MutableMapping[str, Any]:
        nonlocal replayed
        if not replayed:
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        event = await receive()
        if event["type"] == "http.disconnect":
            disconnected.set()
        return event

    return body, replay, disconnected


def _parse_mcp_body(body: bytes) -> tuple[dict[str, Any], JSONRPCMessage]:
    try:
        source = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _BodyRejected(400, "invalid JSON-RPC") from exc
    depth = 0
    in_string = False
    escaped = False
    for char in source:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > settings.max_json_depth:
                raise _BodyRejected(400, "JSON depth exceeded")
        elif char in "]}":
            depth -= 1
    try:
        parsed = json.loads(source)
        if not isinstance(parsed, dict):
            raise ValueError
        return parsed, JSONRPCMessage.model_validate(parsed)
    except (ValueError, TypeError) as exc:
        raise _BodyRejected(400, "invalid JSON-RPC") from exc


async def mcp_endpoint(scope: Scope, receive: Receive, send: Send) -> None:
    """Raw ASGI endpoint: routes each request to its session's Streamable HTTP transport.

    Path-based upstream routing (item 35): clients connect to /mcp/{server_id}; the
    id must be registered in the policy's `servers:` block. One session = one
    upstream, chosen here at connect time."""
    manager: SessionManager = scope["app"].state.session_manager
    security = TransportSecurityMiddleware(
        TransportSecuritySettings(
            allowed_hosts=settings.allowed_hosts,
            allowed_origins=settings.allowed_origins,
        )
    )
    security_failure = await security.validate_request(
        HTTPConnection(scope), is_post=scope["method"] == "POST"
    )
    if security_failure is not None:
        await security_failure(scope, receive, send)
        return

    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
    session_id = headers.get(MCP_SESSION_ID_HEADER)
    engine = scope["app"].state.policy_store.engine
    parsed: dict[str, Any] | None = None
    message: JSONRPCMessage | None = None
    body_disconnected: asyncio.Event | None = None

    if scope["method"] == "POST":
        content_length = headers.get("content-length")
        try:
            if content_length is not None and int(content_length) > settings.max_mcp_body_bytes:
                raise _BodyRejected(413, "request body too large")
            if content_length is not None and int(content_length) < 0:
                raise _BodyRejected(400, "invalid request body")
            body, receive, body_disconnected = await _buffer_body(receive)
            parsed, message = _parse_mcp_body(body)
        except ValueError:
            await Response("invalid request body", status_code=400)(scope, receive, send)
            return
        except _BodyRejected as exc:
            await Response(exc.message, status_code=exc.status)(scope, receive, send)
            return

    # The mount keeps the full path and puts its own prefix in root_path.
    server_id = scope["path"].removeprefix(scope.get("root_path", "")).strip("/")

    # Auth on every request, not just session creation (ARCHITECTURE.md §4.8).
    # Bearer: the key header, hash-and-lookup. Signed (item 34): no header — the
    # POSTed message carries key id + HMAC in params._meta, verified here at the
    # edge so a forged signature is an HTTP 401, never a parsed session message.
    if headers.get(KEY_HEADER) is not None:
        identity_id = await auth.resolve_identity_tracked(
            headers.get(KEY_HEADER), engine, scope["app"].state.redis
        )
    elif scope["method"] == "POST":
        identity_id = None
        if parsed is not None:
            identity_id = await auth.verify_signed_request_tracked(
                parsed, engine, scope["app"].state.redis
            )
    else:
        # GET (SSE stream) / DELETE carry no JSON-RPC body to sign. A signed
        # session was created by a signature-verified initialize, so possession of
        # its session id binds these to that identity (residual exposure — reading
        # the response stream off a captured session id — is documented, item 34).
        identity_id = None
        if session_id is not None:
            session = manager.get(session_id)
            if session is not None:
                identity = engine.identity(session.interceptor.identity_id)
                if identity is not None and identity.auth_mode == "signed":
                    identity_id = session.interceptor.identity_id
    if identity_id is None:
        await Response("invalid or missing API key or signature", status_code=401)(
            scope, receive, send
        )
        return

    root = message.root if message is not None else None
    is_tool_call = (
        isinstance(root, JSONRPCRequest | JSONRPCNotification) and root.method == "tools/call"
    )
    if is_tool_call:
        try:
            retry_after = await manager.check_rate_limit(identity_id)
        except RateLimiterUnavailable:
            await Response("rate limiter unavailable", status_code=503)(scope, receive, send)
            return
        if retry_after is not None:
            await Response(
                "rate limit exceeded",
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )(scope, receive, send)
            return
        if isinstance(root, JSONRPCNotification):
            await Response("tools/call notifications are not supported", status_code=400)(
                scope, receive, send
            )
            return

    if (
        scope["method"] == "POST"
        and session_id is None
        and (not isinstance(root, JSONRPCRequest) or root.method != "initialize")
    ):
        await Response("initialize request required", status_code=400)(scope, receive, send)
        return

    # After auth, so an unauthenticated probe can't enumerate registered server ids.
    if engine.server_config(server_id) is None:
        await Response("unknown server", status_code=404)(scope, receive, send)
        return

    if session_id is not None:
        session = manager.get(session_id)
        if session is None:
            await Response("session not found", status_code=404)(scope, receive, send)
            return
        if session.interceptor.identity_id != identity_id:
            # A valid key for a different identity must not ride an existing session.
            await Response("key does not match session identity", status_code=401)(
                scope, receive, send
            )
            return
        if session.interceptor.server_id != server_id:
            # A session is bound to the upstream it was created against (item 35).
            await Response("session not found", status_code=404)(scope, receive, send)
            return
    elif scope["method"] == "POST":
        # A POST without a session header is a new session (the initialize request).
        # Any failure here — including the SESSION_START audit write — means no
        # session (§5: no record, no action).
        try:
            session = await manager.create(identity_id, server_id)
        except SessionLimitExceeded:
            await Response("session limit exceeded", status_code=429)(scope, receive, send)
            return
        except Exception:
            logger.exception("session_creation_failed", identity=identity_id)
            await Response("session could not be created", status_code=503)(scope, receive, send)
            return
    else:
        await Response("missing mcp-session-id header", status_code=400)(scope, receive, send)
        return

    admitted_request_id = None
    if is_tool_call:
        assert isinstance(root, JSONRPCRequest)
        try:
            await manager.admit_call(session.id, identity_id, root.id)
            admitted_request_id = root.id
        except DuplicateRequestId:
            await Response("duplicate active request id", status_code=400)(scope, receive, send)
            return
        except InflightLimitExceeded:
            await Response("in-flight call limit exceeded", status_code=429)(scope, receive, send)
            return
        except LookupError:
            await Response("session not found", status_code=404)(scope, receive, send)
            return

    try:
        await session.transport.handle_request(scope, receive, send)
    except asyncio.CancelledError:
        if admitted_request_id is not None:
            await manager.disconnect_call(session.id, admitted_request_id)
        raise
    except BaseException:
        if admitted_request_id is not None:
            await manager.finish_call(session.id, admitted_request_id)
        raise
    else:
        if admitted_request_id is not None:
            if body_disconnected is not None and body_disconnected.is_set():
                await manager.disconnect_call(session.id, admitted_request_id)
            else:
                await manager.finish_call(session.id, admitted_request_id)
    if scope["method"] == "DELETE":
        await manager.teardown(session.id)


app.mount("/mcp", mcp_endpoint)
