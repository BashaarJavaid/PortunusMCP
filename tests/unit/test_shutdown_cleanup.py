"""Item 39: one failed container cleanup must not abort cleanup of later sessions."""

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

from services.gateway.policy_engine import UpstreamServer
from services.gateway.session_manager import Session, SessionManager


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
