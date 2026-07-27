import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from services.gateway import signing
from services.gateway.config import settings
from services.gateway.main import _readiness_check, app


async def test_ready_exact_body_and_health_stays_liveness() -> None:
    redis = SimpleNamespace(ping=AsyncMock())
    key = signing.ec.generate_private_key(signing.ec.SECP256R1())

    class Session:
        async def __aenter__(self) -> "Session":
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def execute(self, statement: object) -> None:
            pass

    app.state.redis = redis
    app.state.signing_key = key
    with patch("services.gateway.main.async_session", return_value=Session()):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/ready")
            assert response.status_code == 200
            assert response.json() == {
                "status": "ready",
                "checks": {"postgres": "ok", "redis": "ok", "signing": "ok"},
            }
            assert (await client.get("/health")).json() == {"status": "ok"}


async def test_readiness_names_failures_without_exception_text() -> None:
    key = signing.ec.generate_private_key(signing.ec.SECP256R1())
    app.state.signing_key = key
    app.state.redis = SimpleNamespace(ping=AsyncMock(side_effect=RuntimeError("secret redis")))

    class BrokenSession:
        async def __aenter__(self) -> "BrokenSession":
            raise RuntimeError("secret postgres")

        async def __aexit__(self, *args: object) -> None:
            pass

    with (
        patch("services.gateway.main.async_session", return_value=BrokenSession()),
        patch("services.gateway.main.signing.verify", return_value=False),
    ):
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
                },
            }
            assert (await client.get("/health")).status_code == 200
    assert "secret" not in response.text


async def test_readiness_uses_one_overall_timeout() -> None:
    old_timeout = settings.readiness_timeout_seconds
    settings.readiness_timeout_seconds = 0.01
    key = signing.ec.generate_private_key(signing.ec.SECP256R1())
    app.state.signing_key = key

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
    assert result == {"postgres": "failed", "redis": "failed", "signing": "ok"}


async def test_readiness_dependencies_fail_independently() -> None:
    app.state.signing_key = signing.ec.generate_private_key(signing.ec.SECP256R1())

    def session_type(broken: bool) -> type:
        class Session:
            async def __aenter__(self) -> "Session":
                if broken:
                    raise RuntimeError
                return self

            async def __aexit__(self, *args: object) -> None:
                pass

            async def execute(self, statement: object) -> None:
                pass

        return Session

    for failed in ("postgres", "redis", "signing"):
        app.state.redis = SimpleNamespace(
            ping=AsyncMock(side_effect=RuntimeError if failed == "redis" else None)
        )

        with (
            patch(
                "services.gateway.main.async_session",
                return_value=session_type(failed == "postgres")(),
            ),
            patch(
                "services.gateway.main.signing.verify",
                return_value=failed != "signing",
            ),
        ):
            result = await _readiness_check(app)
        assert result[failed] == "failed"
        assert all(result[name] == "ok" for name in result if name != failed)
