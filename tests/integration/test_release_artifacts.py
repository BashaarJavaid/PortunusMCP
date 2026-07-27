"""Published item-47 bundle smoke and phase-state upgrade verification."""

import hashlib
import json
import os
import secrets
import subprocess
import sys
import uuid
from pathlib import Path

import httpx
import pytest
import yaml
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from tests.integration.conftest import write_signing_keypair
from tests.integration.test_production_compose import (
    _docker_socket_gid,
    _free_port,
    _run,
    _wait_ready,
)


def _release_inputs() -> tuple[Path, str, str, str | None]:
    root = os.environ.get("PORTUNUSMCP_RELEASE_ROOT")
    image = os.environ.get("PORTUNUSMCP_RELEASE_IMAGE")
    if not root or not image:
        pytest.skip("published release root and image are required")
    return (
        Path(root),
        image,
        os.environ.get("PORTUNUSMCP_RELEASE_LOCAL_IMAGE", image),
        os.environ.get("PORTUNUSMCP_UPGRADE_FROM_IMAGE"),
    )


def _env_values(example: Path) -> dict[str, str]:
    return {
        key: value
        for line in example.read_text().splitlines()
        if line and not line.startswith("#")
        for key, value in [line.split("=", 1)]
    }


def _write_env(
    root: Path,
    tmp_path: Path,
    policy_dir: Path,
    signing_dir: Path,
) -> tuple[Path, dict[str, int]]:
    values = _env_values(root / ".env.prod.example")
    assert all(
        values[f"{name}_IMAGE_DIGEST"].startswith("sha256:")
        and "REPLACE" not in values[f"{name}_IMAGE_DIGEST"]
        for name in ("GATEWAY", "POSTGRES", "REDIS", "PROMETHEUS", "GRAFANA")
    )
    ports = {name: _free_port() for name in ("gateway", "prometheus", "grafana")}
    gateway_env = tmp_path / ".env.prod.gateway"
    gateway_env.write_text("# bearer-only release verification\n")
    values.update(
        POSTGRES_PASSWORD=secrets.token_urlsafe(32),
        REDIS_PASSWORD=secrets.token_urlsafe(32),
        GRAFANA_ADMIN_USER="release-admin",
        GRAFANA_ADMIN_PASSWORD=secrets.token_urlsafe(32),
        POLICY_DIR_HOST=str(policy_dir),
        AUDIT_SIGNING_KEY_DIR=str(signing_dir),
        UPSTREAM_RUNTIME_NAMESPACE=f"release-{uuid.uuid4().hex[:8]}",
        DOCKER_GID=_docker_socket_gid(),
        GATEWAY_PORT=str(ports["gateway"]),
        PROMETHEUS_PORT=str(ports["prometheus"]),
        GRAFANA_PORT=str(ports["grafana"]),
        FORWARDED_ALLOW_IPS="*",
        ALLOWED_HOSTS='["127.0.0.1:*","localhost:*"]',
        ALLOWED_ORIGINS="[]",
        GATEWAY_ENV_FILE=str(gateway_env),
    )
    env_file = tmp_path / ".env.prod"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    return env_file, ports


def _compose(
    root: Path,
    env_file: Path,
    project: str,
    override: Path | None,
    *arguments: str,
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
        str(root / "compose.prod.yml"),
    ]
    if override:
        command.extend(["-f", str(override)])
    command.extend(arguments)
    return _run(*command, check=check)


async def _authorized_call(url: str, api_key: str) -> None:
    async with httpx.AsyncClient(
        headers={"X-PortunusMCP-Key": api_key}, follow_redirects=True, timeout=30
    ) as client:
        async with streamable_http_client(f"{url}/mcp/default", http_client=client) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert [tool.name for tool in tools.tools] == ["read_file", "list_issues"]
                result = await session.call_tool("read_file", {"path": "README.md"})
                assert isinstance(result.content[0], TextContent)
                assert result.content[0].text == "<contents of README.md>"


async def test_published_release_bundle_and_upgrade(tmp_path: Path) -> None:
    root, release_image, runtime_image, upgrade_image = _release_inputs()
    manifest = json.loads((root / "release.json").read_text())
    assert release_image == manifest["images"]["gateway"]["reference"]

    if runtime_image == release_image:
        _run("docker", "pull", release_image)
    else:
        _run("docker", "image", "inspect", runtime_image)
    policy_dir = tmp_path / "config"
    signing_dir = tmp_path / "secrets"
    policy_dir.mkdir()
    signing_dir.mkdir()
    (policy_dir / "revisions").mkdir()
    (signing_dir / "public").mkdir()
    write_signing_keypair(signing_dir)
    api_key = secrets.token_urlsafe(32)
    (policy_dir / "policy.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "servers": {
                    "default": {
                        "image": runtime_image,
                        "command": ["python", "sample_target/overscoped_server.py"],
                    }
                },
                "identities": [
                    {
                        "id": "release-admin",
                        "admin": True,
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
    env_file, ports = _write_env(root, tmp_path, policy_dir, signing_dir)
    project = f"portunusmcp-release-{uuid.uuid4().hex[:8]}"
    url = f"http://127.0.0.1:{ports['gateway']}"
    override: Path | None = None
    if runtime_image != release_image:
        override = tmp_path / "compose.candidate.yml"
        override.write_text(
            yaml.safe_dump(
                {
                    "services": {
                        service: {"image": runtime_image}
                        for service in ("migrate", "gateway", "verifier")
                    }
                }
            )
        )
    candidate_override = override

    _run(
        "docker",
        "run",
        "--rm",
        "--user",
        "0",
        "-v",
        f"{policy_dir}:/policy",
        "-v",
        f"{signing_dir}:/secrets",
        runtime_image,
        "sh",
        "-c",
        "chown -R 1000:1000 /policy /secrets && chmod 700 /policy /secrets",
    )

    try:
        _compose(
            root,
            env_file,
            project,
            candidate_override,
            "pull",
            "postgres",
            "redis",
        )
        if upgrade_image:
            override = tmp_path / "compose.upgrade.yml"
            override.write_text(
                yaml.safe_dump(
                    {
                        "services": {
                            service: {"image": upgrade_image}
                            for service in ("migrate", "gateway", "verifier")
                        }
                    }
                )
            )
            _compose(
                root,
                env_file,
                project,
                override,
                "up",
                "-d",
                "--wait",
                "--wait-timeout",
                "240",
            )
            await _wait_ready(f"{url}/ready")
            await _authorized_call(url, api_key)
            _compose(root, env_file, project, override, "down")
            override = candidate_override

        _compose(
            root,
            env_file,
            project,
            candidate_override,
            "up",
            "-d",
            "--wait",
            "--wait-timeout",
            "240",
        )
        await _wait_ready(f"{url}/ready")
        assert (
            "verifier"
            in _compose(
                root,
                env_file,
                project,
                candidate_override,
                "ps",
                "--services",
                "--status",
                "running",
            ).splitlines()
        )
        await _authorized_call(url, api_key)

        cli_env = {
            **os.environ,
            "PORTUNUSMCP_URL": url,
            "PORTUNUSMCP_ADMIN_KEY": api_key,
        }
        cli = str(Path(sys.executable).with_name("portunusmcp"))
        assert (
            json.loads(_run(cli, "--json", "policy", "status", env=cli_env))["active_version"] == 1
        )
        export = tmp_path / "audit.ndjson"
        exported = json.loads(
            _run(
                cli,
                "--json",
                "audit",
                "export",
                "--output",
                str(export),
                env=cli_env,
            )
        )
        assert exported["rows"] >= (4 if upgrade_image else 2)
    except subprocess.CalledProcessError as exc:
        logs = _compose(root, env_file, project, override, "logs", "--no-color", check=False)
        pytest.fail(f"release Compose verification failed: {exc.stderr}\n{logs}")
    finally:
        _compose(
            root,
            env_file,
            project,
            override,
            "down",
            "--volumes",
            "--remove-orphans",
            check=False,
        )
        _run(
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "-v",
            f"{policy_dir}:/policy",
            "-v",
            f"{signing_dir}:/secrets",
            runtime_image,
            "chown",
            "-R",
            f"{os.getuid()}:{os.getgid()}",
            "/policy",
            "/secrets",
            check=False,
        )
