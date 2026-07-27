"""Item-41 verification for the explicit single-replica production Compose profile."""

import asyncio
import hashlib
import json
import os
import secrets
import socket
import subprocess
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from tests.integration.conftest import write_signing_keypair

ROOT = Path(__file__).parents[2]
COMPOSE = ROOT / "compose.prod.yml"
LOCAL_IMAGE = "portunusmcp:dev"
SERVICES = ("postgres", "redis", "gateway", "verifier", "prometheus", "grafana")
ALL_SERVICES = (*SERVICES, "migrate")
LIMITS = {
    "postgres": (1024**3, 1_000_000_000, 256),
    "redis": (512 * 1024**2, 500_000_000, 128),
    "gateway": (1024**3, 1_000_000_000, 256),
    "verifier": (256 * 1024**2, 250_000_000, 64),
    "prometheus": (512 * 1024**2, 500_000_000, 128),
    "grafana": (512 * 1024**2, 500_000_000, 128),
}


def _run(*args: str, env: dict[str, str] | None = None, check: bool = True) -> str:
    return subprocess.run(
        args,
        check=check,
        capture_output=True,
        text=True,
        env=env,
    ).stdout


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _docker_socket_gid() -> str:
    return _run(
        "docker",
        "run",
        "--rm",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "docker:29.6.1-cli",
        "stat",
        "-c",
        "%g",
        "/var/run/docker.sock",
    ).strip()


def _require_docker() -> None:
    required = os.environ.get("REQUIRE_DOCKER_TESTS") == "1"
    try:
        _run("docker", "version")
        _run("docker", "image", "inspect", LOCAL_IMAGE)
        os.stat("/var/run/docker.sock")
    except (FileNotFoundError, OSError, subprocess.CalledProcessError) as exc:
        if required:
            pytest.fail(f"required production Compose prerequisite missing: {exc}")
        pytest.skip("Docker daemon, socket, and portunusmcp:dev are required")


def _write_env(
    tmp_path: Path,
    policy: Path,
    revisions: Path,
    private_key: Path,
    public_key: Path,
) -> tuple[Path, Path, dict[str, int]]:
    ports = {
        "gateway": _free_port(),
        "prometheus": _free_port(),
        "grafana": _free_port(),
    }
    gateway_env = tmp_path / ".env.prod.gateway"
    gateway_env.write_text("# intentionally empty for this bearer-only policy\n")
    values = {
        "GATEWAY_IMAGE_DIGEST": f"sha256:{'0' * 64}",
        "POSTGRES_IMAGE_DIGEST": f"sha256:{'1' * 64}",
        "REDIS_IMAGE_DIGEST": f"sha256:{'2' * 64}",
        "PROMETHEUS_IMAGE_DIGEST": f"sha256:{'3' * 64}",
        "GRAFANA_IMAGE_DIGEST": f"sha256:{'4' * 64}",
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "REDIS_PASSWORD": secrets.token_urlsafe(32),
        "GRAFANA_ADMIN_USER": "compose-admin",
        "GRAFANA_ADMIN_PASSWORD": secrets.token_urlsafe(32),
        "POLICY_FILE_HOST": str(policy),
        "POLICY_REVISIONS_DIR_HOST": str(revisions),
        "AUDIT_SIGNING_PRIVATE_KEY_FILE": str(private_key),
        "AUDIT_SIGNING_PUBLIC_KEY_FILE": str(public_key),
        "UPSTREAM_RUNTIME_NAMESPACE": f"prod-test-{uuid.uuid4().hex[:8]}",
        "DOCKER_GID": _docker_socket_gid(),
        "GATEWAY_PORT": str(ports["gateway"]),
        "PROMETHEUS_PORT": str(ports["prometheus"]),
        "GRAFANA_PORT": str(ports["grafana"]),
        "ALLOWED_HOSTS": '["127.0.0.1:*","localhost:*"]',
        "ALLOWED_ORIGINS": "[]",
        "MAX_MCP_BODY_BYTES": "1048576",
        "MAX_JSON_DEPTH": "32",
        "MAX_SESSIONS_PER_IDENTITY": "3",
        "MAX_INFLIGHT_CALLS_PER_IDENTITY": "5",
        "TOOL_CALL_RATE_LIMIT": "60",
        "TOOL_CALL_RATE_WINDOW_SECONDS": "60",
        "TOOL_CALL_DEADLINE_SECONDS": "60",
        "READINESS_TIMEOUT_SECONDS": "1.0",
        "SCHEMA_CACHE_TTL": "600",
        "SESSION_IDLE_TTL": "300",
        "SHUTDOWN_GRACE_SECONDS": "5",
        "REPLAY_WINDOW_SECONDS": "30",
        "BUSINESS_HOURS_START_UTC": "9",
        "BUSINESS_HOURS_END_UTC": "18",
        "RISK_FREQ_WINDOW_SECONDS": "60",
        "RISK_FREQ_THRESHOLD": "10",
        "RISK_DECAY_STEP": "5",
        "RISK_DECAY_MAX": "10",
        "RISK_DECAY_TTL_SECONDS": "2592000",
        "RISK_DENIAL_WINDOW_SECONDS": "600",
        "RISK_DENIAL_THRESHOLD": "3",
        "RISK_AUTH_FAILURE_WINDOW_SECONDS": "300",
        "RISK_AUTH_FAILURE_THRESHOLD": "5",
        "RISK_DRIFT_HISTORY_WINDOW_SECONDS": "604800",
        "RISK_DRIFT_HISTORY_THRESHOLD": "2",
        "DRIFT_DESCRIPTION_SEVERITY": "high",
        "APPROVAL_TTL_SECONDS": "900",
        "STEP_UP_TTL_SECONDS": "300",
        "VERIFY_INTERVAL_SECONDS": "60",
        "GATEWAY_ENV_FILE": str(gateway_env),
    }
    env_file = tmp_path / ".env.prod"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    return env_file, gateway_env, ports


def _compose(
    env_file: Path,
    project: str,
    override: Path | None,
    *args: str,
    check: bool = True,
) -> str:
    command = [
        "docker",
        "compose",
        "--env-file",
        str(env_file),
        "-p",
        project,
        "-f",
        str(COMPOSE),
    ]
    if override is not None:
        command.extend(["-f", str(override)])
    command.extend(["--profile", "monitoring", *args])
    return _run(*command, check=check)


def _render(env_file: Path, project: str) -> dict[str, Any]:
    return json.loads(_compose(env_file, project, None, "config", "--format", "json"))


def _inspect(env_file: Path, project: str, override: Path, service: str) -> dict[str, Any]:
    container_id = _compose(env_file, project, override, "ps", "-q", service).strip()
    assert container_id, service
    return json.loads(_run("docker", "inspect", container_id))[0]


async def _wait_ready(url: str) -> None:
    async with httpx.AsyncClient() as client:
        for _ in range(180):
            try:
                if (await client.get(url)).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(1)
    pytest.fail(f"service did not become ready: {url}")


async def test_production_compose_is_hardened_and_calls_a_tool(tmp_path: Path) -> None:
    _require_docker()
    tmp_path.chmod(0o755)
    revisions = tmp_path / "revisions"
    revisions.mkdir(mode=0o777)
    revisions.chmod(0o777)
    private_key, public_key = write_signing_keypair(tmp_path)
    private_key.chmod(0o644)  # test runner UID can differ from the image's UID 1000

    api_key = secrets.token_urlsafe(32)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "servers": {
                    "default": {
                        "image": LOCAL_IMAGE,
                        "command": ["python", "sample_target/overscoped_server.py"],
                    }
                },
                "identities": [
                    {
                        "id": "developer",
                        "api_key_hash": f"sha256:{hashlib.sha256(api_key.encode()).hexdigest()}",
                        "allowed_servers": [
                            {
                                "server_id": "default",
                                "allowed_tools": ["read_file", "list_issues"],
                            }
                        ],
                    }
                ],
            }
        )
    )
    policy.chmod(0o644)
    env_file, _, ports = _write_env(tmp_path, policy, revisions, private_key, public_key)
    project = f"portunusmcp-prod-test-{uuid.uuid4().hex[:8]}"

    rendered = _render(env_file, project)
    services = rendered["services"]
    assert "rogue" not in services
    assert "ports" not in services["postgres"]
    assert "ports" not in services["redis"]
    assert services["gateway"]["scale"] == 1
    assert rendered["networks"]["data"]["internal"] is True
    assert services["gateway"]["image"].startswith("ghcr.io/bashaarjavaid/portunusmcp@sha256:")
    assert services["postgres"]["image"].startswith("postgres:16@sha256:")
    assert services["redis"]["image"].startswith("redis:7@sha256:")
    assert services["prometheus"]["image"].startswith("prom/prometheus:v3.4.1@sha256:")
    assert services["grafana"]["image"].startswith("grafana/grafana:12.0.2@sha256:")
    assert "GRAFANA_ADMIN_PASSWORD" not in services["gateway"]["environment"]
    for service in ALL_SERVICES:
        assert services[service]["read_only"] is True
        assert services[service]["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in services[service]["security_opt"]
        assert services[service]["logging"]["options"] == {
            "max-file": "5",
            "max-size": "10m",
        }
    assert services["migrate"]["restart"] == "no"
    for service in ("gateway", "prometheus", "grafana"):
        assert services[service]["ports"][0]["host_ip"] == "127.0.0.1"

    override = tmp_path / "compose.test.yml"
    override.write_text(
        yaml.safe_dump(
            {
                "services": {
                    "postgres": {"image": "postgres:16"},
                    "redis": {"image": "redis:7"},
                    "migrate": {"image": LOCAL_IMAGE},
                    "gateway": {"image": LOCAL_IMAGE},
                    "verifier": {"image": LOCAL_IMAGE},
                    "prometheus": {"image": "prom/prometheus:v3.4.1"},
                    "grafana": {"image": "grafana/grafana:12.0.2"},
                }
            }
        )
    )

    try:
        try:
            _compose(env_file, project, override, "up", "-d", "--wait", "--wait-timeout", "240")
        except subprocess.CalledProcessError as exc:
            logs = _compose(env_file, project, override, "logs", "--no-color", check=False)
            pytest.fail(f"production Compose startup failed: {exc.stderr}\n{logs}")
        await _wait_ready(f"http://127.0.0.1:{ports['gateway']}/ready")
        await _wait_ready(f"http://127.0.0.1:{ports['prometheus']}/-/ready")
        await _wait_ready(f"http://127.0.0.1:{ports['grafana']}/api/health")

        for service in SERVICES:
            inspected = _inspect(env_file, project, override, service)
            host = inspected["HostConfig"]
            assert host["ReadonlyRootfs"] is True
            assert host["CapDrop"] == ["ALL"]
            assert "no-new-privileges:true" in host["SecurityOpt"]
            assert host["Memory"], service
            assert host["NanoCpus"], service
            assert host["PidsLimit"], service
            assert (host["Memory"], host["NanoCpus"], host["PidsLimit"]) == LIMITS[service]
            assert host["RestartPolicy"]["Name"] == "unless-stopped"
        assert _inspect(env_file, project, override, "postgres")["Config"]["User"] == "999:999"
        assert _inspect(env_file, project, override, "redis")["Config"]["User"] == "999:999"

        redis_config = _compose(
            env_file,
            project,
            override,
            "exec",
            "-T",
            "redis",
            "redis-cli",
            "CONFIG",
            "GET",
            "appendonly",
            "appendfsync",
        )
        assert "appendonly\nyes" in redis_config
        assert "appendfsync\neverysec" in redis_config

        async with httpx.AsyncClient() as client:
            assert (
                await client.get(f"http://127.0.0.1:{ports['grafana']}/api/user")
            ).status_code == 401
            assert (
                await client.get(
                    f"http://127.0.0.1:{ports['grafana']}/api/user",
                    auth=(
                        "compose-admin",
                        rendered["services"]["grafana"]["environment"][
                            "GF_SECURITY_ADMIN_PASSWORD"
                        ],
                    ),
                )
            ).status_code == 200

        async with httpx.AsyncClient(
            headers={"X-PortunusMCP-Key": api_key}, follow_redirects=True, timeout=30
        ) as client:
            async with streamable_http_client(
                f"http://127.0.0.1:{ports['gateway']}/mcp/default",
                http_client=client,
            ) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    assert [tool.name for tool in tools.tools] == ["read_file", "list_issues"]
                    result = await session.call_tool("read_file", {"path": "README.md"})
                    assert isinstance(result.content[0], TextContent)
                    assert result.content[0].text == "<contents of README.md>"
    finally:
        _compose(
            env_file,
            project,
            override,
            "down",
            "--volumes",
            "--remove-orphans",
            check=False,
        )
