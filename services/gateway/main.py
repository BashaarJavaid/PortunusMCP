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
from sqlalchemy import case, func, select, text
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.types import Receive, Scope, Send

from services.gateway import (
    audit_export,
    auth,
    decision_explainer,
    logging_config,
    policy_engine,
    policy_simulator,
    policy_versions,
    upstream_client,
)
from services.gateway.approvals import ApprovalStore
from services.gateway.audit_keys import AuditKeyStore
from services.gateway.audit_log import AuditWriter
from services.gateway.audit_verification import backfill_legacy_key_ids
from services.gateway.config import settings
from services.gateway.db import Approval, AuditLog, PolicyVersion, ToolBaseline, async_session
from services.gateway.decision import Decision, DecisionMode, DecisionOutcome, EventType
from services.gateway.drift_detector import (
    REMOVED_SENTINEL,
    DriftDetector,
    classify,
    scan_descriptions,
)
from services.gateway.policy_engine import PolicyStore
from services.gateway.policy_operations import PolicyOperationStore
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
ADMIN_BODY_LIMIT = 1024 * 1024


async def _reload_policy(
    store: PolicyStore,
    writer: AuditWriter,
    manager: SessionManager,
    runtime: upstream_client.DockerRuntime,
    operations: PolicyOperationStore,
    lock: asyncio.Lock,
) -> None:
    path = operations.manual_candidate_path
    if not path.exists():
        logger.warning("policy_reload_skipped", detail=f"{path} does not exist")
        return
    try:
        candidate = policy_engine.load_bytes(path.read_bytes())
        if not any(identity.admin for identity in candidate.policy.identities):
            raise ValueError("candidate policy must contain at least one admin identity")
        await _activate_policy(
            candidate,
            activated_by="operator",
            kind="sighup",
            store=store,
            writer=writer,
            manager=manager,
            runtime=runtime,
            operations=operations,
            lock=lock,
        )
        path.unlink()
    except Exception:
        logger.exception("policy_activation_rejected_keeping_last_known_good")


async def _activate_policy(
    candidate: policy_engine.PolicyEngine,
    *,
    activated_by: str,
    kind: str,
    store: PolicyStore,
    writer: AuditWriter,
    manager: SessionManager,
    runtime: upstream_client.DockerRuntime,
    operations: PolicyOperationStore,
    lock: asyncio.Lock,
    rollback: bool = False,
) -> tuple[int, int]:
    if lock.locked():
        raise RuntimeError("another policy mutation is already in progress")
    await lock.acquire()
    operation = None
    handed_off = False
    old_version = store.engine.version
    try:
        if operations.blocked or operations.read_journal() is not None:
            raise RuntimeError("policy activation recovery is pending")
        await runtime.preflight(candidate.policy.servers)
        if not rollback:
            await policy_versions.activation_status(candidate, async_session)
        operation = operations.prepare(
            candidate.raw,
            kind=kind,
            activated_by=activated_by,
            old_version=old_version,
            new_version=candidate.version,
        )
        if rollback:
            await policy_versions.record_rollback(candidate, activated_by, async_session)
        else:
            await policy_versions.record_activation(candidate, activated_by, async_session)
        seq = await writer.write(
            EventType.POLICY_ACTIVATED,
            activated_by,
            payload_extra={
                "old_version": old_version,
                "new_version": candidate.version,
                "content_hash": candidate.content_hash,
                "rollback": rollback,
                "operation_id": operation.operation_id,
                "source": kind,
                "durable": True,
            },
        )
        operation = operations.mark_handoff(operation, seq)
        handed_off = True
        operations.promote(operation)
        store.swap(candidate)
        await manager.evict_outdated()
        operations.finish()
        return seq, old_version
    except Exception:
        if handed_off:
            operations.blocked = True
        elif operation is not None:
            operations.abort_before_handoff()
        raise
    finally:
        lock.release()


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
            " docker compose --env-file .env.demo -f compose.demo.yml run --rm gateway"
            " python scripts/reset_dev_state.py --yes)"
        )
        logger.error("policy_activation_conflict_at_startup", detail=hint)
        raise policy_versions.ActivationError(hint) from exc


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    mode_log = logger.warning if settings.enforcement_mode is DecisionMode.OBSERVE else logger.info
    mode_log("enforcement_mode", mode=settings.enforcement_mode.value)
    # An invalid or missing policy file must fail startup (ARCHITECTURE.md §5);
    # so must a missing/unreadable audit signing key (§4.8, item 11).
    policy_operations = PolicyOperationStore(settings.policy_file)
    await policy_operations.recover(async_session)
    app.state.policy_operations = policy_operations
    app.state.policy_mutation_lock = asyncio.Lock()
    app.state.key_rotation_lock = asyncio.Lock()
    store = PolicyStore(settings.policy_file)
    app.state.policy_store = store
    key_store = AuditKeyStore(settings.signing_key_file, settings.signing_public_keys_dir)
    signing_key, key_id = await key_store.recover(async_session)
    await backfill_legacy_key_ids(async_session, key_store, key_id)
    app.state.legacy_key_backfill_complete = True
    app.state.audit_key_store = key_store
    app.state.signing_key = signing_key
    runtime = await upstream_client.DockerRuntime.create(store.engine.policy.servers)
    app.state.upstream_runtime = runtime
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    app.state.redis = redis_client  # source auth limiter and other short-TTL state
    writer = AuditWriter(redis_client, async_session, store, signing_key, key_id)
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
        lambda: loop.create_task(
            _reload_policy(
                store,
                writer,
                manager,
                runtime,
                policy_operations,
                app.state.policy_mutation_lock,
            )
        ),
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
        writer: AuditWriter = app.state.audit_writer
        key_store: AuditKeyStore = app.state.audit_key_store
        if not writer.available:
            raise ValueError
        private_key, active_key_id = key_store.initialize()
        if active_key_id != writer.key_id:
            raise ValueError
        public_key = key_store.load_public(writer.key_id)
        if public_key.public_numbers() != private_key.public_key().public_numbers():
            raise ValueError
        if not app.state.legacy_key_backfill_complete or key_store.read_journal() is not None:
            raise ValueError

    async def policy() -> None:
        operations: PolicyOperationStore = app.state.policy_operations
        if operations.blocked or operations.read_journal() is not None:
            raise ValueError

    checks = {"postgres": postgres, "redis": redis, "signing": signing_key, "policy": policy}
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
    identity_id = await _require_admin(request)
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
    identity_id = await _require_admin(request)
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
    """Durably re-activate a prior policy revision."""
    store: PolicyStore = request.app.state.policy_store
    identity_id = await _require_admin(request)
    snapshot = policy_versions.snapshot_path(version)
    if not snapshot.exists():
        raise HTTPException(status_code=404, detail=f"no revision snapshot for v{version}")
    try:
        engine = policy_engine.load_bytes(snapshot.read_bytes())
    except Exception as exc:
        raise HTTPException(status_code=409, detail=f"revision v{version} is invalid") from exc
    try:
        seq, old_version = await _activate_policy(
            engine,
            activated_by=identity_id,
            kind="rollback",
            store=store,
            writer=request.app.state.audit_writer,
            manager=request.app.state.session_manager,
            runtime=request.app.state.upstream_runtime,
            operations=request.app.state.policy_operations,
            lock=request.app.state.policy_mutation_lock,
            rollback=True,
        )
    except Exception as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    decision = Decision(
        decision=DecisionOutcome.ALLOW,
        event_type=EventType.POLICY_ACTIVATED,
        reason=f"policy rolled back from v{old_version} to v{engine.version} by {identity_id!r}",
        matched_rules=["admin_rollback"],
        policy_version=engine.version,
        audit_id=str(seq),
    )
    return {
        "decision": decision.model_dump(mode="json"),
        "metadata": {"old_version": old_version, "new_version": engine.version},
    }


async def _require_admin(request: Request) -> str:
    """Shared /admin/* auth (item 20 endpoints): key resolves to an admin identity."""
    store: PolicyStore = request.app.state.policy_store
    try:
        identity_id = await auth.resolve_identity_tracked(
            request.headers.get(KEY_HEADER),
            store.engine,
            request.app.state.redis,
            auth.client_source(request.scope),
            "admin",
        )
    except auth.AuthRateLimited as exc:
        raise HTTPException(
            status_code=429,
            detail="authentication rate limit exceeded",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except auth.AuthLimiterUnavailable as exc:
        raise HTTPException(status_code=503, detail="authentication limiter unavailable") from exc
    if identity_id is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    if not store.engine.is_admin(identity_id):
        raise HTTPException(status_code=403, detail="admin identity required")
    return identity_id


def _approval_view(row: Approval, audit_row: AuditLog) -> dict[str, object]:
    decision = decision_explainer.from_audit_row(audit_row)
    return {
        "approval_id": row.approval_id,
        "status": row.status,
        "consumed": row.consumed,
        "created_at": row.created_at.isoformat(),
        "expires_at": row.expires_at.isoformat(),
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "approved_by": row.approved_by,
        "identity": row.identity_id,
        "server": row.server_id,
        "tool": row.tool_name,
        "arguments_hash": row.arguments_hash,
        "arguments": (audit_row.payload or {}).get("arguments", {}),
        "decision": decision.model_dump(mode="json"),
    }


@app.get("/admin/approvals")
async def list_approvals(request: Request) -> dict[str, object]:
    await _require_admin(request)
    try:
        await request.app.state.approval_store.expire_stale()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="approval expiry audit failed") from exc
    async with async_session() as session:
        result = await session.execute(
            select(Approval, AuditLog)
            .join(AuditLog, AuditLog.seq == Approval.audit_id)
            .where(Approval.status == "pending")
            .order_by(Approval.expires_at, Approval.approval_id)
            .limit(101)
        )
        rows = list(result.all())
    return {
        "items": [_approval_view(row, audit_row) for row, audit_row in rows[:100]],
        "truncated": len(rows) > 100,
    }


@app.get("/admin/approvals/{approval_id}")
async def get_approval(approval_id: str, request: Request) -> dict[str, object]:
    await _require_admin(request)
    try:
        await request.app.state.approval_store.expire_stale()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="approval expiry audit failed") from exc
    async with async_session() as session:
        result = await session.execute(
            select(Approval, AuditLog)
            .join(AuditLog, AuditLog.seq == Approval.audit_id)
            .where(Approval.approval_id == approval_id)
        )
        pair = result.one_or_none()
    if pair is None:
        raise HTTPException(status_code=404, detail="unknown approval id")
    return _approval_view(*pair)


def _baseline_view(row: ToolBaseline) -> dict[str, object]:
    observed = row.observed_schema
    removed = row.observed_hash == REMOVED_SENTINEL
    severity = None
    if removed:
        severity = "medium"
    elif observed is not None:
        severity_value = classify(row.approved_schema, observed)
        severity = (severity_value.name if severity_value else "high").lower()
    return {
        "server": row.server_id,
        "tool": row.tool_name,
        "approved_schema": row.approved_schema,
        "approved_hash": row.approved_hash,
        "approved_at": row.approved_at.isoformat(),
        "observed_schema": observed,
        "observed_hash": row.observed_hash,
        "blocked": row.blocked,
        "removed": removed,
        "severity": severity,
        "suspicious": row.suspicious,
        "flagged_at": row.flagged_at.isoformat() if row.flagged_at else None,
        "scanner_findings": {
            "approved": scan_descriptions(row.approved_schema),
            "observed": scan_descriptions(observed) if observed is not None else [],
        },
    }


@app.get("/admin/baselines/flagged")
async def list_flagged_baselines(request: Request, kind: str = "all") -> dict[str, object]:
    await _require_admin(request)
    if kind not in {"all", "drift", "suspicious"}:
        raise HTTPException(status_code=400, detail="kind must be all, drift, or suspicious")
    conditions = {
        "all": (ToolBaseline.observed_hash.is_not(None) | ToolBaseline.suspicious),
        "drift": ToolBaseline.observed_hash.is_not(None),
        "suspicious": ToolBaseline.suspicious,
    }
    async with async_session() as session:
        rows = list(
            (
                await session.execute(
                    select(ToolBaseline)
                    .where(conditions[kind])
                    .order_by(
                        case((ToolBaseline.observed_hash.is_not(None), 0), else_=1),
                        ToolBaseline.flagged_at,
                        ToolBaseline.server_id,
                        ToolBaseline.tool_name,
                    )
                    .limit(101)
                )
            ).scalars()
        )
    return {"items": [_baseline_view(row) for row in rows[:100]], "truncated": len(rows) > 100}


@app.get("/admin/baselines/{server_id}/{tool_name}")
async def get_baseline(server_id: str, tool_name: str, request: Request) -> dict[str, object]:
    await _require_admin(request)
    async with async_session() as session:
        row = await session.get(ToolBaseline, (server_id, tool_name))
    if row is None:
        raise HTTPException(status_code=404, detail="unknown baseline")
    return _baseline_view(row)


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
        mode=DecisionMode(settings.enforcement_mode),
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


def _require_yaml(request: Request) -> None:
    if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/yaml":
        raise HTTPException(status_code=415, detail="Content-Type must be application/yaml")


async def _candidate(request: Request) -> policy_engine.PolicyEngine:
    _require_yaml(request)
    raw = await request.body()
    try:
        raw.decode("utf-8")
        return policy_engine.load_bytes(raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid policy: {exc}") from exc


def _require_admin_candidate(engine: policy_engine.PolicyEngine) -> None:
    if not any(identity.admin for identity in engine.policy.identities):
        raise HTTPException(
            status_code=409, detail="candidate policy must contain at least one admin identity"
        )


@app.get("/admin/policy")
async def policy_status(request: Request) -> dict[str, object]:
    await _require_admin(request)
    store: PolicyStore = request.app.state.policy_store
    operations: PolicyOperationStore = request.app.state.policy_operations
    operation = operations.read_journal()
    async with async_session() as session:
        recorded = (
            await session.execute(select(func.max(PolicyVersion.version)))
        ).scalar_one_or_none()
    return {
        "active_version": store.engine.version,
        "content_hash": store.engine.content_hash,
        "highest_recorded_version": recorded,
        "mutation_in_progress": request.app.state.policy_mutation_lock.locked(),
        "recovery_required": operations.blocked or operation is not None,
        "operation": operation.__dict__ if operation else None,
        "candidate_path": str(operations.manual_candidate_path),
    }


@app.get("/admin/policy/revisions")
async def policy_revisions(request: Request) -> dict[str, object]:
    await _require_admin(request)
    active_version = request.app.state.policy_store.engine.version
    async with async_session() as session:
        versions = list(
            (
                await session.execute(
                    select(PolicyVersion).order_by(PolicyVersion.version.desc()).limit(101)
                )
            ).scalars()
        )
        activations = list(
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.event_type == EventType.POLICY_ACTIVATED.value)
                )
            ).scalars()
        )
    activated_versions = {
        row.payload.get("new_version")
        for row in activations
        if isinstance((row.payload or {}).get("new_version"), int)
    }
    items = [
        {
            "version": row.version,
            "content_hash": row.content_hash,
            "activated_at": row.activated_at.isoformat(),
            "activated_by": row.activated_by,
            "state": (
                "active"
                if row.version == active_version
                else "inactive"
                if row.version in activated_versions
                else "recorded-unactivated"
            ),
        }
        for row in versions[:100]
    ]
    return {"items": items, "truncated": len(versions) > 100}


@app.post("/admin/policy/validate")
async def validate_policy(request: Request) -> dict[str, object]:
    identity_id = await _require_admin(request)
    engine = await _candidate(request)
    _require_admin_candidate(engine)
    if auth.resolve_identity(
        request.headers.get(KEY_HEADER), engine
    ) != identity_id or not engine.is_admin(identity_id):
        raise HTTPException(
            status_code=409,
            detail="the calling bearer key must remain an admin in the candidate policy",
        )
    try:
        _, highest = await policy_versions.activation_status(engine, async_session)
        await request.app.state.upstream_runtime.preflight(engine.policy.servers)
    except (policy_versions.ActivationError, upstream_client.RuntimeError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "valid": True,
        "version": engine.version,
        "content_hash": engine.content_hash,
        "highest_recorded_version": highest,
        "servers": sorted(engine.policy.servers),
        "identities": len(engine.policy.identities),
    }


@app.post("/admin/policy/simulate-candidate")
async def simulate_candidate_policy(request: Request, replay_window: str) -> dict[str, object]:
    await _require_admin(request)
    engine = await _candidate(request)
    try:
        result = await policy_simulator.simulate_candidate(
            engine,
            replay_window,
            sessionmaker=async_session,
            detector=request.app.state.drift_detector,
            risk=request.app.state.risk_engine,
            schema_cache=SchemaCache(request.app.state.redis),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result.model_dump(mode="json")


@app.post("/admin/policy/rollout")
async def rollout_policy(request: Request) -> dict[str, object]:
    identity_id = await _require_admin(request)
    engine = await _candidate(request)
    _require_admin_candidate(engine)
    if auth.resolve_identity(
        request.headers.get(KEY_HEADER), engine
    ) != identity_id or not engine.is_admin(identity_id):
        raise HTTPException(
            status_code=409,
            detail="the calling bearer key must remain an admin in the candidate policy",
        )
    try:
        seq, old_version = await _activate_policy(
            engine,
            activated_by=identity_id,
            kind="api",
            store=request.app.state.policy_store,
            writer=request.app.state.audit_writer,
            manager=request.app.state.session_manager,
            runtime=request.app.state.upstream_runtime,
            operations=request.app.state.policy_operations,
            lock=request.app.state.policy_mutation_lock,
        )
    except (policy_versions.ActivationError, upstream_client.RuntimeError, RuntimeError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    decision = Decision(
        decision=DecisionOutcome.ALLOW,
        event_type=EventType.POLICY_ACTIVATED,
        reason=f"policy v{engine.version} activated by {identity_id!r}",
        matched_rules=["admin_rollout"],
        policy_version=engine.version,
        audit_id=str(seq),
    )
    return {
        "decision": decision.model_dump(mode="json"),
        "metadata": {"old_version": old_version, "new_version": engine.version},
    }


@app.get("/admin/keys/audit")
async def audit_key_status(request: Request) -> dict[str, object]:
    await _require_admin(request)
    writer: AuditWriter = request.app.state.audit_writer
    key_store: AuditKeyStore = request.app.state.audit_key_store
    operation = key_store.read_journal()
    return {
        "active_key_id": writer.key_id,
        "available": writer.available,
        "public_key_count": key_store.public_count(),
        "rotation_in_progress": request.app.state.key_rotation_lock.locked(),
        "recovery_required": operation is not None or not writer.available,
        "operation": operation.__dict__ if operation else None,
    }


@app.post("/admin/keys/audit/rotate")
async def rotate_audit_key(request: Request) -> dict[str, object]:
    identity_id = await _require_admin(request)
    lock: asyncio.Lock = request.app.state.key_rotation_lock
    if lock.locked():
        raise HTTPException(status_code=409, detail="another audit key rotation is in progress")
    await lock.acquire()
    try:
        writer: AuditWriter = request.app.state.audit_writer
        seq, old_key_id, new_key_id = await writer.rotate(
            request.app.state.audit_key_store, identity_id
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        lock.release()
    decision = Decision(
        decision=DecisionOutcome.ALLOW,
        event_type=EventType.AUDIT_KEY_ROTATED,
        reason=f"audit signing key rotated by {identity_id!r}",
        matched_rules=["admin_key_rotation"],
        policy_version=request.app.state.policy_store.engine.version,
        audit_id=str(seq),
    )
    return {
        "decision": decision.model_dump(mode="json"),
        "metadata": {"old_key_id": old_key_id, "new_key_id": new_key_id},
    }


@app.get("/admin/audit/export")
async def export_audit(
    request: Request, from_seq: int | None = None, to_seq: int | None = None
) -> StreamingResponse:
    await _require_admin(request)
    try:
        manifest, start, end = await audit_export.prepare(
            async_session, request.app.state.audit_key_store, from_seq, to_seq
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    headers = {"Content-Disposition": 'attachment; filename="portunusmcp-audit.ndjson"'}
    return StreamingResponse(
        audit_export.stream(async_session, manifest, start, end),
        media_type="application/x-ndjson",
        headers=headers,
    )


class _BodyRejected(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message


async def _buffer_body(
    receive: Receive, limit: int | None = None
) -> tuple[bytes, Receive, asyncio.Event]:
    """Drain a bounded body and return the same bytes through a replayable receive."""
    limit = settings.max_mcp_body_bytes if limit is None else limit
    chunks: list[bytes] = []
    size = 0
    while True:
        event = await receive()
        if event["type"] != "http.request":
            raise _BodyRejected(400, "invalid request body")
        chunk = event.get("body", b"")
        size += len(chunk)
        if size > limit:
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
    if scope["app"].state.policy_operations.blocked:
        await Response("policy activation recovery pending", status_code=503)(scope, receive, send)
        return
    if not scope["app"].state.audit_writer.available:
        await Response("audit key rotation recovery pending", status_code=503)(scope, receive, send)
        return
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
    try:
        if headers.get(KEY_HEADER) is not None:
            identity_id = await auth.resolve_identity_tracked(
                headers.get(KEY_HEADER),
                engine,
                scope["app"].state.redis,
                auth.client_source(scope),
                "mcp",
            )
        elif scope["method"] == "POST":
            identity_id = None
            if parsed is not None:
                identity_id = await auth.verify_signed_request_tracked(
                    parsed,
                    engine,
                    scope["app"].state.redis,
                    auth.client_source(scope),
                    "mcp",
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
    except auth.AuthRateLimited as exc:
        await Response(
            "authentication rate limit exceeded",
            status_code=429,
            headers={"Retry-After": str(exc.retry_after)},
        )(scope, receive, send)
        return
    except auth.AuthLimiterUnavailable:
        await Response("authentication limiter unavailable", status_code=503)(scope, receive, send)
        return
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


class _AdminBodyLimitMiddleware:
    def __init__(self, application: Any) -> None:
        self.application = application

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] == "http"
            and scope["path"].startswith("/admin/")
            and scope["method"] in {"POST", "PUT", "PATCH"}
        ):
            headers = {
                key.decode("latin-1").lower(): value.decode("latin-1")
                for key, value in scope["headers"]
            }
            try:
                content_length = headers.get("content-length")
                if content_length is not None and int(content_length) < 0:
                    raise _BodyRejected(400, "invalid request body")
                if content_length is not None and int(content_length) > ADMIN_BODY_LIMIT:
                    raise _BodyRejected(413, "request body too large")
                _, receive, _ = await _buffer_body(receive, ADMIN_BODY_LIMIT)
            except (ValueError, _BodyRejected) as exc:
                status = exc.status if isinstance(exc, _BodyRejected) else 400
                message = exc.message if isinstance(exc, _BodyRejected) else "invalid request body"
                await Response(message, status_code=status)(scope, receive, send)
                return
        await self.application(scope, receive, send)


app.add_middleware(_AdminBodyLimitMiddleware)
app.mount("/mcp", mcp_endpoint)
