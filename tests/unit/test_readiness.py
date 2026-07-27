import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from services.gateway import signing
from services.gateway.config import settings
from services.gateway.main import _readiness_check, app


def set_ready_state(*, signing_available: bool = True, policy_blocked: bool = False) -> None:
    key = signing.ec.generate_private_key(signing.ec.SECP256R1())
    key_id = signing.key_id(key.public_key())
    app.state.audit_writer = SimpleNamespace(available=signing_available, key_id=key_id)
    app.state.audit_key_store = SimpleNamespace(
        initialize=lambda: (key, key_id),
        load_public=lambda _key_id: key.public_key(),
        read_journal=lambda: None,
    )
    app.state.policy_operations = SimpleNamespace(blocked=policy_blocked, read_journal=lambda: None)
    app.state.legacy_key_backfill_complete = True


class Result:
    def scalar_one_or_none(self) -> None:
        return None


async def test_ready_exact_body_and_health_stays_liveness() -> None:
    redis = SimpleNamespace(ping=AsyncMock())
    set_ready_state()

    class Session:
        async def __aenter__(self) -> "Session":
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def execute(self, statement: object) -> Result:
            return Result()

    app.state.redis = redis
    with patch("services.gateway.main.async_session", return_value=Session()):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/ready")
            assert response.status_code == 200
            assert response.json() == {
                "status": "ready",
                "checks": {
                    "postgres": "ok",
                    "redis": "ok",
                    "signing": "ok",
                    "policy": "ok",
                },
            }
            assert (await client.get("/health")).json() == {"status": "ok"}


async def test_readiness_names_failures_without_exception_text() -> None:
    set_ready_state(signing_available=False, policy_blocked=True)
    app.state.redis = SimpleNamespace(ping=AsyncMock(side_effect=RuntimeError("secret redis")))

    class BrokenSession:
        async def __aenter__(self) -> "BrokenSession":
            raise RuntimeError("secret postgres")

        async def __aexit__(self, *args: object) -> None:
            pass

    with patch("services.gateway.main.async_session", return_value=BrokenSession()):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/ready")
            assert response.status_code == 503
            assert response.json() == {
                "status": "not_ready",
                "checks": {
                    "postgres": "failed",
                    "redis": "failed",
                    "signing": "failed",
                    "policy": "failed",
                },
            }
            assert (await client.get("/health")).status_code == 200
    assert "secret" not in response.text


async def test_readiness_uses_one_overall_timeout() -> None:
    old_timeout = settings.readiness_timeout_seconds
    settings.readiness_timeout_seconds = 0.01
    set_ready_state()

    async def slow() -> None:
        await asyncio.sleep(1)

    app.state.redis = SimpleNamespace(ping=slow)

    class SlowSession:
        async def __aenter__(self) -> "SlowSession":
            await asyncio.sleep(1)
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

    try:
        with patch("services.gateway.main.async_session", return_value=SlowSession()):
            result = await _readiness_check(app)
    finally:
        settings.readiness_timeout_seconds = old_timeout
    assert result == {
        "postgres": "failed",
        "redis": "failed",
        "signing": "ok",
        "policy": "ok",
    }


async def test_readiness_dependencies_fail_independently() -> None:
    def session_type(broken: bool) -> type:
        class Session:
            async def __aenter__(self) -> "Session":
                if broken:
                    raise RuntimeError
                return self

            async def __aexit__(self, *args: object) -> None:
                pass

            async def execute(self, statement: object) -> Result:
                return Result()

        return Session

    for failed in ("postgres", "redis", "signing", "policy"):
        set_ready_state(signing_available=failed != "signing", policy_blocked=failed == "policy")
        app.state.redis = SimpleNamespace(
            ping=AsyncMock(side_effect=RuntimeError if failed == "redis" else None)
        )

        with patch(
            "services.gateway.main.async_session",
            return_value=session_type(failed == "postgres")(),
        ):
            result = await _readiness_check(app)
        assert result[failed] == "failed"
        assert all(result[name] == "ok" for name in result if name != failed)
