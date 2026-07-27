"""Item 39: one failed container cleanup must not abort cleanup of later sessions."""

import asyncio
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCResponse

from services.gateway.config import settings
from services.gateway.policy_engine import UpstreamServer
from services.gateway.session_manager import (
    Session,
    SessionLimitExceeded,
    SessionManager,
)


class FakeProcess:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.stopped = False


class FakeRuntime:
    async def stop(self, process: FakeProcess, grace_seconds: int) -> None:
        if process.fail:
            raise ProcessLookupError
        process.stopped = True


def make_manager_with(processes: list[FakeProcess]) -> SessionManager:
    runtime = FakeRuntime()
    manager = SessionManager(  # dependencies unused by shutdown_all
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, runtime),
    )
    for i, process in enumerate(processes):
        session = Session(
            id=f"s{i}",
            transport=cast(Any, None),
            process=cast(Any, process),
            interceptor=cast(Any, None),
            runtime_fingerprint="test",
        )
        manager._sessions[session.id] = session
    return manager


async def test_failed_container_cleanup_does_not_abort_the_rest() -> None:
    failed = FakeProcess(fail=True)
    alive_after = [FakeProcess(), FakeProcess()]
    manager = make_manager_with([failed, *alive_after])

    await manager.shutdown_all()

    assert all(process.stopped for process in alive_after)


async def test_policy_change_evicts_only_runtime_mismatches() -> None:
    manager = make_manager_with([])
    unchanged = UpstreamServer(image="example/upstream:test", command=["serve"])
    changed = UpstreamServer(image="example/upstream:test", command=["serve", "--new"])
    manager._policy_store = cast(
        Any,
        SimpleNamespace(
            engine=SimpleNamespace(
                server_config=lambda server_id: changed if server_id == "a" else unchanged
            )
        ),
    )
    manager._sessions = cast(
        Any,
        {
            "evict": SimpleNamespace(
                id="evict",
                runtime_fingerprint=unchanged.runtime_fingerprint,
                interceptor=SimpleNamespace(server_id="a"),
            ),
            "keep": SimpleNamespace(
                id="keep",
                runtime_fingerprint=unchanged.runtime_fingerprint,
                interceptor=SimpleNamespace(server_id="b"),
            ),
        },
    )
    manager.teardown = AsyncMock()  # type: ignore[method-assign]

    await manager.evict_outdated()

    manager.teardown.assert_awaited_once_with("evict")  # type: ignore[attr-defined]


class FakeRedis:
    def __init__(self, fail_set: bool = False) -> None:
        self.fail_set = fail_set

    async def set(self, *args: object, **kwargs: object) -> None:
        if self.fail_set:
            raise ConnectionError

    async def delete(self, key: str) -> None:
        pass


def admission_manager(writer: object, runtime: object, redis: object) -> SessionManager:
    server = UpstreamServer(image="example/upstream:test", command=["serve"])
    store = SimpleNamespace(engine=SimpleNamespace(server_config=lambda server_id: server))
    return SessionManager(
        cast(Any, redis),
        cast(Any, store),
        cast(Any, writer),
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, None),
        cast(Any, runtime),
    )


async def test_starting_session_keeps_its_identity_slot() -> None:
    entered, release = asyncio.Event(), asyncio.Event()

    async def blocked_write(*args: object, **kwargs: object) -> None:
        entered.set()
        await release.wait()
        raise RuntimeError

    manager = admission_manager(SimpleNamespace(write=blocked_write), FakeRuntime(), FakeRedis())
    old_limit = settings.max_sessions_per_identity
    settings.max_sessions_per_identity = 1
    try:
        starting = asyncio.create_task(manager.create("identity", "server"))
        await entered.wait()
        with pytest.raises(SessionLimitExceeded):
            await manager.create("identity", "server")
        release.set()
        with pytest.raises(RuntimeError):
            await starting
        assert manager._session_counts == {}
    finally:
        settings.max_sessions_per_identity = old_limit


async def test_failed_creation_reaps_spawn_and_releases_slot() -> None:
    process = FakeProcess()

    class Runtime(FakeRuntime):
        async def spawn(self, server: object, session_id: str, server_id: str) -> FakeProcess:
            return process

    manager = admission_manager(
        SimpleNamespace(write=AsyncMock()), Runtime(), FakeRedis(fail_set=True)
    )
    with pytest.raises(ConnectionError):
        await manager.create("identity", "server")
    assert process.stopped
    assert manager._session_counts == {}
    assert manager._sessions == {}


async def test_stopping_session_keeps_its_identity_slot() -> None:
    entered, release = asyncio.Event(), asyncio.Event()

    class Runtime(FakeRuntime):
        async def stop(self, process: FakeProcess, grace_seconds: int) -> None:
            entered.set()
            await release.wait()
            process.stopped = True

    manager = admission_manager(SimpleNamespace(write=AsyncMock()), Runtime(), FakeRedis())
    session = Session(
        id="stopping",
        transport=cast(Any, None),
        process=cast(Any, FakeProcess()),
        interceptor=cast(Any, SimpleNamespace(identity_id="identity")),
        runtime_fingerprint="test",
    )
    manager._sessions[session.id] = session
    manager._session_counts["identity"] = 1
    old_limit = settings.max_sessions_per_identity
    settings.max_sessions_per_identity = 1
    try:
        stopping = asyncio.create_task(manager.teardown(session.id))
        await entered.wait()
        with pytest.raises(SessionLimitExceeded):
            await manager.create("identity", "server")
        release.set()
        await stopping
        assert manager._session_counts == {}
    finally:
        settings.max_sessions_per_identity = old_limit


async def test_disconnected_call_keeps_slot_until_upstream_response() -> None:
    manager = admission_manager(SimpleNamespace(write=AsyncMock()), FakeRuntime(), FakeRedis())
    session = Session(
        id="active",
        transport=cast(Any, None),
        process=cast(Any, FakeProcess()),
        interceptor=cast(Any, SimpleNamespace(identity_id="identity")),
        runtime_fingerprint="test",
    )
    manager._sessions[session.id] = session
    manager._session_counts["identity"] = 1

    await manager.admit_call(session.id, "identity", 7)
    await manager.disconnect_call(session.id, 7)
    assert manager._inflight_counts == {"identity": 1}

    await manager._response_ready(
        session.id,
        SessionMessage(JSONRPCMessage(JSONRPCResponse(jsonrpc="2.0", id=7, result={"ok": True}))),
    )
    assert manager._inflight_counts == {}
    await manager.teardown(session.id)
