"""Required real-Docker recovery proof for ROADMAP item 50."""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
import yaml

from tests.integration.conftest import write_signing_keypair
from tests.integration.test_production_compose import (
    COMPOSE,
    LOCAL_IMAGE,
    _require_docker,
    _wait_ready,
    _write_env,
)


def _compose(root: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(root / ".env.prod"),
            "-f",
            str(root / "compose.prod.yml"),
            *arguments,
        ],
        check=check,
        capture_output=True,
        text=True,
    )


def _local_test_compose(root: Path) -> None:
    source = COMPOSE.read_text()
    source = source.replace(
        "image: postgres:16@${POSTGRES_IMAGE_DIGEST:?set POSTGRES_IMAGE_DIGEST to sha256:...}",
        "image: postgres:16",
    )
    source = source.replace(
        "image: redis:7@${REDIS_IMAGE_DIGEST:?set REDIS_IMAGE_DIGEST to sha256:...}",
        "image: redis:7",
    )
    source = source.replace(
        "image: ghcr.io/bashaarjavaid/portunusmcp@${GATEWAY_IMAGE_DIGEST:"
        "?set GATEWAY_IMAGE_DIGEST to sha256:...}",
        f"image: {LOCAL_IMAGE}",
    )
    source = source.replace(
        "image: prom/prometheus:v3.4.1@${PROMETHEUS_IMAGE_DIGEST:"
        "?set PROMETHEUS_IMAGE_DIGEST to sha256:...}",
        "image: prom/prometheus:v3.4.1",
    )
    source = source.replace(
        "image: grafana/grafana:12.0.2@${GRAFANA_IMAGE_DIGEST:"
        "?set GRAFANA_IMAGE_DIGEST to sha256:...}",
        "image: grafana/grafana:12.0.2",
    )
    source = source.replace(
        "  gateway:\n    <<: *security\n",
        '  gateway:\n    <<: *security\n    user: "${HOST_UID}:${HOST_GID}"\n',
    )
    source = source.replace(
        "  verifier:\n    <<: *security\n",
        '  verifier:\n    <<: *security\n    user: "${HOST_UID}:${HOST_GID}"\n',
    )
    (root / "compose.prod.yml").write_text(source)


@pytest.mark.asyncio
async def test_installed_doctor_repairs_production_and_recovers_readiness(
    tmp_path: Path,
) -> None:
    _require_docker()
    cli = Path(sys.executable).with_name("portunusmcp")
    if not cli.is_file():
        pytest.fail("installed portunusmcp CLI is required")

    root = tmp_path / "doctor-production"
    config = root / "config"
    secrets = root / "secrets"
    public = secrets / "public"
    revisions = config / "revisions"
    for directory in (root, config, secrets, public, revisions):
        directory.mkdir(mode=0o700)
    _local_test_compose(root)
    private, _ = write_signing_keypair(secrets)
    private.chmod(0o600)

    image_id = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", LOCAL_IMAGE],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    api_key = "doctor-test-key"
    required_name = "PORTUNUSMCP_UPSTREAM_DOCTOR_SECRET"
    (config / "policy.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "servers": {
                    "default": {
                        "image": image_id,
                        "command": ["python", "sample_target/overscoped_server.py"],
                        "env": {"DOCTOR_SECRET": required_name},
                    }
                },
                "identities": [
                    {
                        "id": "doctor-admin",
                        "api_key_hash": (f"sha256:{hashlib.sha256(api_key.encode()).hexdigest()}"),
                        "admin": True,
                        "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
                    }
                ],
            },
            sort_keys=False,
        )
    )
    (config / "policy.yaml").chmod(0o600)
    env_file, gateway_env, ports = _write_env(root, config, secrets)
    project = f"doctor-prod-{uuid.uuid4().hex[:8]}"
    with env_file.open("a") as stream:
        stream.write(
            f"COMPOSE_PROJECT_NAME={project}\nHOST_UID={os.getuid()}\nHOST_GID={os.getgid()}\n"
        )
    env_file.chmod(0o600)
    gateway_env.write_text(f"{required_name}=do-not-print-this\n")
    gateway_env.chmod(0o600)

    try:
        started = _compose(root, "up", "-d", "--wait", "--wait-timeout", "240")
        assert started.returncode == 0, started.stderr
        await _wait_ready(f"http://127.0.0.1:{ports['gateway']}/ready")

        root.chmod(0o755)
        env_file.chmod(0o644)
        config.chmod(0o755)
        revisions.chmod(0o755)
        secrets.chmod(0o755)
        public.chmod(0o755)
        private.chmod(0o644)
        env_file.write_text(env_file.read_text().replace("DOCKER_GID=", "DOCKER_GID=999999#"))

        fixed = subprocess.run(
            [str(cli), "--json", "--yes", "doctor", str(root), "--fix"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert fixed.returncode == 1, fixed.stderr or fixed.stdout
        report = json.loads(fixed.stdout)
        assert report["summary"]["restart_required"] is True
        assert "do-not-print-this" not in fixed.stdout + fixed.stderr
        assert any(
            finding["id"] == "docker.socket_gid" and finding["status"] == "FIXED"
            for finding in report["findings"]
        )
        assert any(
            finding["id"] == "filesystem.private_key" and finding["status"] == "FIXED"
            for finding in report["findings"]
        )
        assert stat_mode(private) == 0o600

        recreated = subprocess.run(
            shlex.split(report["commands"]["recreate"]),
            capture_output=True,
            text=True,
            timeout=300,
        )
        if recreated.returncode:
            key_check = _compose(
                root,
                "exec",
                "-T",
                "gateway",
                "python",
                "-c",
                (
                    "from services.gateway.audit_keys import AuditKeyStore;"
                    "s=AuditKeyStore('/app/secrets/audit_signing_key.pem',"
                    "'/app/secrets/public');print(s.initialize())"
                ),
                check=False,
            )
            logs = _compose(root, "logs", "--no-color", "--tail", "100", check=False)
            pytest.fail(
                recreated.stderr
                + "\nkey check:\n"
                + key_check.stdout
                + key_check.stderr
                + "\nlogs:\n"
                + logs.stdout
                + logs.stderr
            )

        healthy = subprocess.run(
            [str(cli), "--json", "doctor", str(root)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        logs = _compose(root, "logs", "--no-color", "--tail", "100", check=False)
        assert healthy.returncode == 0, (
            (healthy.stderr or healthy.stdout) + "\n" + logs.stdout + logs.stderr
        )
        assert json.loads(healthy.stdout)["summary"]["healthy"] is True

        gateway_env.write_text("# missing required policy value\n")
        gateway_env.chmod(0o600)
        missing = subprocess.run(
            [str(cli), "--json", "doctor", str(root)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert missing.returncode == 1
        assert required_name in missing.stdout
        assert "do-not-print-this" not in missing.stdout + missing.stderr
    finally:
        _compose(root, "down", "--volumes", "--remove-orphans", check=False)
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
