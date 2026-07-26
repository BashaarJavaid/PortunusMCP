"""Per-client session lifecycle (ARCHITECTURE.md §4.8).

One session = one client connection + one isolated upstream container + one message
pump. The registry of live handles exists so lifespan/SIGTERM cleanup can stop every
container; idle sessions are reaped via a Redis TTL key.
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field

import redis.asyncio as aioredis
import structlog
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.server.streamable_http import StreamableHTTPServerTransport
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage

from services.gateway import upstream_client
from services.gateway.approvals import ApprovalStore
from services.gateway.audit_log import AuditWriter
from services.gateway.config import settings
from services.gateway.decision import EventType
from services.gateway.drift_detector import DriftDetector
from services.gateway.jsonrpc_interceptor import Interceptor, Respond
from services.gateway.policy_engine import PolicyStore
from services.gateway.replay_guard import ReplayGuard
from services.gateway.risk_engine import RiskEngine
from services.gateway.schema_cache import SchemaCache
from services.gateway.step_up import ChallengeStore

logger = structlog.get_logger(__name__)

_SWEEP_INTERVAL_S = 30


def _last_seen_key(session_id: str) -> str:
    return f"session:{session_id}:last_seen"


@dataclass
class Session:
    id: str
    transport: StreamableHTTPServerTransport
    process: upstream_client.ContainerProcess
    interceptor: Interceptor
    runtime_fingerprint: str
    task: asyncio.Task[None] | None = None
    ready: asyncio.Event = field(default_factory=asyncio.Event)


class SessionManager:
    def __init__(
        self,
        redis_client: aioredis.Redis,
        policy_store: PolicyStore,
        writer: AuditWriter,
        schema_cache: SchemaCache,
        drift_detector: DriftDetector,
        replay_guard: ReplayGuard,
        risk_engine: RiskEngine,
        approval_store: ApprovalStore,
        challenge_store: ChallengeStore,
        runtime: upstream_client.DockerRuntime,
    ) -> None:
        self._redis = redis_client
        self._policy_store = policy_store
        self._writer = writer
        self._schema_cache = schema_cache
        self._drift_detector = drift_detector
        self._replay_guard = replay_guard
        self._risk_engine = risk_engine
        self._approval_store = approval_store
        self._challenge_store = challenge_store
        self._runtime = runtime
        self._sessions: dict[str, Session] = {}

    def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    async def create(self, identity_id: str, server_id: str) -> Session:
        # Resolved against the live registry (item 35) — an id that vanished in a
        # policy swap fails here, before anything is recorded or spawned.
        server = self._policy_store.engine.server_config(server_id)
        if server is None:
            raise LookupError(f"unknown server {server_id!r}")
        session_id = uuid.uuid4().hex
        # No record, no session (§5): the SESSION_START row lands before anything spawns.
        await self._writer.write(
            EventType.SESSION_START,
            identity_id,
            server_id=server_id,
            payload_extra={"session_id": session_id},
        )
        transport = StreamableHTTPServerTransport(mcp_session_id=session_id)
        process = await self._runtime.spawn(server, session_id, server_id)

        async def send_upstream(message: JSONRPCMessage) -> None:
            await upstream_client.write_message(process, message)

        session = Session(
            id=session_id,
            transport=transport,
            process=process,
            runtime_fingerprint=server.runtime_fingerprint,
            interceptor=Interceptor(
                identity_id=identity_id,
                server_id=server_id,
                session_id=session_id,
                store=self._policy_store,
                writer=self._writer,
                cache=self._schema_cache,
                detector=self._drift_detector,
                replay=self._replay_guard,
                risk=self._risk_engine,
                approvals=self._approval_store,
                challenges=self._challenge_store,
                send_upstream=send_upstream,
            ),
        )
        self._sessions[session_id] = session
        await self._touch(session_id)
        session.task = asyncio.create_task(self._run(session))
        # handle_request() must not race transport.connect(); wait until the pump owns the streams.
        await session.ready.wait()
        return session

    async def _run(self, session: Session) -> None:
        try:
            async with session.transport.connect() as (read_stream, write_stream):
                session.ready.set()
                pumps = [
                    asyncio.create_task(
                        self._client_to_upstream(session, read_stream, write_stream)
                    ),
                    asyncio.create_task(self._upstream_to_client(session, write_stream)),
                ]
                # Either direction ending (client disconnect, upstream exit, Redis failure —
                # fail closed per ARCHITECTURE.md §5) ends the session.
                done, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                for task in done:
                    if not task.cancelled() and task.exception() is not None:
                        logger.warning(
                            "session_pump_failed",
                            session_id=session.id,
                            error=repr(task.exception()),
                        )
        finally:
            session.ready.set()
            await self.teardown(session.id)

    async def _client_to_upstream(
        self,
        session: Session,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
    ) -> None:
        async for item in read_stream:
            if isinstance(item, Exception):
                raise item
            await self._touch(session.id)
            outcome = await session.interceptor.on_client_message(item)
            if isinstance(outcome, Respond):
                # Terminal decision (e.g. DENY_RBAC): answer the client directly.
                await write_stream.send(outcome.message)
            else:
                await upstream_client.write_message(session.process, outcome.message.message)

    async def _upstream_to_client(
        self,
        session: Session,
        write_stream: MemoryObjectSendStream[SessionMessage],
    ) -> None:
        async for message in upstream_client.read_messages(session.process):
            outcome = await session.interceptor.on_upstream_message(SessionMessage(message))
            if outcome is not None:  # None = response to a gateway-internal request
                await write_stream.send(outcome)

    async def _touch(self, session_id: str) -> None:
        await self._redis.set(
            _last_seen_key(session_id), int(time.time()), ex=settings.session_idle_ttl
        )

    async def sweep_once(self) -> None:
        for session_id in list(self._sessions):
            if not await self._redis.exists(_last_seen_key(session_id)):
                logger.info("session_idle_expired", session_id=session_id)
                await self.teardown(session_id)

    async def sweep_loop(self) -> None:
        while True:
            await asyncio.sleep(_SWEEP_INTERVAL_S)
            await self.sweep_once()

    async def teardown(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        if session.task is not None and session.task is not asyncio.current_task():
            session.task.cancel()
        try:
            await self._runtime.stop(session.process, settings.shutdown_grace_seconds)
        except (ProcessLookupError, OSError, upstream_client.RuntimeError):
            logger.warning(
                "session_container_cleanup_failed", session_id=session_id, during="teardown"
            )
        await self._redis.delete(_last_seen_key(session_id))

    async def evict_outdated(self) -> None:
        """Disconnect sessions whose container launch specification is no longer active."""
        outdated = []
        for session in list(self._sessions.values()):
            server = self._policy_store.engine.server_config(session.interceptor.server_id)
            if server is None or server.runtime_fingerprint != session.runtime_fingerprint:
                outdated.append(session.id)
        await asyncio.gather(*(self.teardown(session_id) for session_id in outdated))

    async def shutdown_all(self) -> None:
        """Lifespan/SIGTERM handler: stop every registered upstream container."""
        sessions = list(self._sessions.values())
        self._sessions.clear()
        for session in sessions:
            if session.task is not None:
                session.task.cancel()
        results = await asyncio.gather(
            *(
                self._runtime.stop(session.process, settings.shutdown_grace_seconds)
                for session in sessions
            ),
            return_exceptions=True,
        )
        for session, result in zip(sessions, results, strict=True):
            if isinstance(result, BaseException):
                logger.warning(
                    "session_container_cleanup_failed",
                    session_id=session.id,
                    during="shutdown",
                    error=repr(result),
                )
