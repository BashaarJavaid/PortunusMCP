"""Required CI proof that the installed item-48 CLI reaches both decisions."""

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_installed_quickstart_proves_allow_and_deny(tmp_path: Path) -> None:
    if os.environ.get("REQUIRE_DOCKER_TESTS") != "1":
        pytest.skip("required real-Docker quickstart runs in CI")
    cli = Path(sys.executable).with_name("portunusmcp")
    if not cli.is_file() or shutil.which("docker") is None:
        pytest.fail("installed portunusmcp CLI and Docker are required")
    output = tmp_path / "quickstart"
    command = [
        str(cli),
        "--timeout",
        "300",
        "--json",
        "quickstart",
        "--upstream-image",
        "portunusmcp:dev",
        "--allow-tool",
        "read_file",
        "--arguments",
        '{"path":"README.md"}',
        "--port",
        str(_free_port()),
        "--output-dir",
        str(output),
        "--command",
        "python",
        "sample_target/overscoped_server.py",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=360)
        assert result.returncode == 0, result.stderr
        proof = json.loads(result.stdout)
        assert proof["decisions"]["allow"]["event_type"] == "ALLOW"
        assert proof["decisions"]["allow"]["decision"] == "allow"
        assert proof["decisions"]["allow"]["mode"] == "enforce"
        assert proof["decisions"]["deny"]["event_type"] == "DENY_RBAC"
        assert proof["decisions"]["deny"]["decision"] == "deny"
        assert proof["decisions"]["deny"]["mode"] == "enforce"
        assert proof["metadata"]["upstream_image_id"].startswith("sha256:")
        credentials = (output / "credentials.env").read_text().splitlines()
        for line in credentials[1:]:
            key = line.split("=", 1)[1]
            assert key not in result.stdout
            assert key not in result.stderr
    finally:
        if (output / ".env.quickstart").is_file():
            env = output / ".env.quickstart"
            compose = output / "compose.quickstart.yml"
            namespace = next(
                (
                    line.split("=", 1)[1].strip("'")
                    for line in env.read_text().splitlines()
                    if line.startswith("QUICKSTART_NAMESPACE=")
                ),
                "",
            )
            if namespace:
                subprocess.run(
                    [
                        "docker",
                        "compose",
                        "--env-file",
                        str(env),
                        "-p",
                        namespace,
                        "-f",
                        str(compose),
                        "down",
                        "--volumes",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
