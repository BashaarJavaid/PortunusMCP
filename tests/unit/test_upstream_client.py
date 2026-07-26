from unittest.mock import AsyncMock, call

import pytest

from services.gateway import upstream_client
from services.gateway.policy_engine import UpstreamServer


def server(**overrides: object) -> UpstreamServer:
    return UpstreamServer.model_validate(
        {"image": "example/upstream:test", "command": ["serve"], **overrides}
    )


async def test_preflight_checks_image_and_namespaced_volumes() -> None:
    runtime = upstream_client.DockerRuntime("docker", "unix:///var/run/docker.sock", "test")
    run = AsyncMock(return_value=(0, b"", b""))
    runtime._run = run  # type: ignore[method-assign]
    configured = server(
        volumes=[
            {
                "source": "portunusmcp-upstream-test-state",
                "target": "/state",
            }
        ]
    )

    await runtime.preflight({"default": configured})

    assert run.await_args_list == [
        call("image", "inspect", "example/upstream:test"),
        call("volume", "inspect", "portunusmcp-upstream-test-state"),
    ]


async def test_preflight_rejects_volume_from_another_namespace() -> None:
    runtime = upstream_client.DockerRuntime("docker", "unix:///var/run/docker.sock", "test")
    runtime._run = AsyncMock(return_value=(0, b"", b""))  # type: ignore[method-assign]

    with pytest.raises(upstream_client.RuntimeError, match="must start with"):
        await runtime.preflight(
            {
                "default": server(
                    volumes=[
                        {
                            "source": "portunusmcp-upstream-other-state",
                            "target": "/state",
                        }
                    ]
                )
            }
        )
