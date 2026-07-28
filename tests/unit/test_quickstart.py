import argparse
import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from services import cli, quickstart
from services.gateway.policy_engine import load_bytes

IMAGE_ID = f"sha256:{'a' * 64}"


def _args(tmp_path: Path, **overrides: object) -> argparse.Namespace:
    values = {
        "upstream_image": "local/upstream:test",
        "allow_tool": "echo",
        "arguments": {"text": "hello"},
        "command": ["python", "-m", "server"],
        "output_dir": str(tmp_path / "quickstart"),
        "port": 8765,
        "timeout": 300.0,
        "json": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_parser_validates_objects_ports_and_command_remainder(tmp_path: Path) -> None:
    parsed = cli._parser().parse_args(
        [
            "--timeout",
            "10",
            "--json",
            "quickstart",
            "--upstream-image",
            "local:test",
            "--allow-tool",
            "echo",
            "--arguments",
            '{"text":"hello"}',
            "--port",
            "8765",
            "--output-dir",
            str(tmp_path),
            "--command",
            "python",
            "-m",
            "server",
            "--flag",
        ]
    )
    assert parsed.arguments == {"text": "hello"}
    assert parsed.command == ["python", "-m", "server", "--flag"]
    with pytest.raises(argparse.ArgumentTypeError):
        quickstart.json_object("[]")
    with pytest.raises(argparse.ArgumentTypeError):
        quickstart.json_object("{")
    with pytest.raises(argparse.ArgumentTypeError):
        quickstart.port_number("0")
    with pytest.raises(argparse.ArgumentTypeError):
        quickstart.port_number("65536")


def test_preflight_validation_refuses_unsafe_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "file").write_text("x")
    with pytest.raises(quickstart.QuickstartUsageError, match="nonexistent or an empty"):
        quickstart._validate_args(_args(tmp_path, output_dir=str(nonempty)))
    with pytest.raises(quickstart.QuickstartUsageError, match="NUL-free"):
        quickstart._validate_args(_args(tmp_path, command=["python", "bad\0arg"]))
    with pytest.raises(quickstart.QuickstartUsageError, match="reserved"):
        quickstart._validate_args(_args(tmp_path, allow_tool=quickstart.DENIED_TOOL))
    with pytest.raises(quickstart.QuickstartUsageError, match="NUL"):
        quickstart._validate_args(_args(tmp_path, output_dir="bad\0path"))

    monkeypatch.setattr(os, "getuid", lambda: 0)
    with pytest.raises(quickstart.QuickstartError, match="non-root"):
        quickstart._validate_platform("Linux", "x86_64")
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    with pytest.raises(quickstart.QuickstartError, match="unsupported"):
        quickstart._validate_platform("Windows", "AMD64")

    regular = tmp_path / "not-a-socket"
    regular.touch()
    with pytest.raises(quickstart.QuickstartError, match="not a Unix socket"):
        quickstart._check_socket(regular)

    class Occupied:
        def __enter__(self) -> "Occupied":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def bind(self, _address: object) -> None:
            raise OSError("occupied")

    monkeypatch.setattr(quickstart.socket, "socket", lambda *_args: Occupied())
    with pytest.raises(quickstart.QuickstartError, match="unavailable"):
        quickstart._check_port(8765)


def test_generation_is_private_pinned_and_uses_existing_policy_defaults(tmp_path: Path) -> None:
    first = quickstart._generate(
        tmp_path / "one", IMAGE_ID, "echo", ["python", "-m", "server"], 8765, "42"
    )
    second = quickstart._generate(
        tmp_path / "two", IMAGE_ID, "echo", ["python", "-m", "server"], 8766, "42"
    )
    assert first.admin_key != first.client_key
    assert {first.admin_key, first.client_key}.isdisjoint({second.admin_key, second.client_key})
    for key in (first.admin_key, first.client_key):
        assert len(base64.b64decode(key, validate=True)) == 32

    root = first.root
    assert (root / ".gitignore").read_text() == "*\n!.gitignore\n"
    assert _mode(root) == _mode(root / "config") == _mode(root / "secrets") == 0o700
    assert _mode(root / "config" / "revisions") == _mode(root / "secrets" / "public") == 0o700
    assert _mode(root / ".gitignore") == _mode(root / "compose.quickstart.yml") == 0o644
    assert _mode(root / ".env.quickstart") == _mode(root / "credentials.env") == 0o600
    assert _mode(root / "config" / "policy.yaml") == 0o600
    assert _mode(root / "secrets" / "audit_signing_key.pem") == 0o600
    public_keys = list((root / "secrets" / "public").glob("*.pub.pem"))
    assert len(public_keys) == 1
    assert _mode(public_keys[0]) == 0o444
    assert not (root / "secrets" / "audit_signing_key.pub.pem").exists()

    credentials = dict(
        line.split("=", 1) for line in (root / "credentials.env").read_text().splitlines()
    )
    assert list(credentials) == [
        "PORTUNUSMCP_URL",
        "PORTUNUSMCP_ADMIN_KEY",
        "PORTUNUSMCP_API_KEY",
    ]
    assert credentials["PORTUNUSMCP_ADMIN_KEY"] == first.admin_key
    assert credentials["PORTUNUSMCP_API_KEY"] == first.client_key
    for path in (
        root / ".gitignore",
        root / "compose.quickstart.yml",
        root / ".env.quickstart",
        root / "config" / "policy.yaml",
    ):
        content = path.read_text()
        assert first.admin_key not in content
        assert first.client_key not in content

    raw_policy = (root / "config" / "policy.yaml").read_bytes()
    policy = yaml.safe_load(raw_policy)
    assert policy["servers"]["default"] == {
        "image": IMAGE_ID,
        "command": ["python", "-m", "server"],
    }
    assert policy["identities"][0]["allowed_servers"] == [
        {"server_id": "*", "allowed_tools": ["*"]}
    ]
    assert policy["identities"][1]["allowed_servers"] == [
        {"server_id": "default", "allowed_tools": ["echo"]}
    ]
    assert policy["identities"][0]["api_key_hash"] == (
        f"sha256:{hashlib.sha256(first.admin_key.encode()).hexdigest()}"
    )
    loaded = load_bytes(raw_policy)
    server = loaded.server_config("default")
    assert server is not None
    assert server.image == IMAGE_ID
    assert server.network == "none"
    assert server.env == {}
    assert server.volumes == []
    assert server.resources.model_dump() == {"memory_mb": 256, "cpus": 0.5, "pids": 64}


def test_generated_compose_renders_hardened_core(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is required to render the packaged asset")
    generated = quickstart._generate(
        tmp_path / "render", IMAGE_ID, "echo", ["python", "-m", "server"], 8765, "42"
    )
    command = [
        *quickstart._compose(generated),
        "config",
        "--format",
        "json",
    ]
    rendered = json.loads(
        subprocess.run(command, check=True, capture_output=True, text=True).stdout
    )
    services = rendered["services"]
    assert set(services) == {
        "postgres",
        "redis",
        "migrate",
        "keys-init",
        "gateway",
        "verifier",
    }
    assert rendered["networks"]["data"]["internal"] is True
    assert "ports" not in services["postgres"]
    assert "ports" not in services["redis"]
    assert services["gateway"]["ports"][0]["host_ip"] == "127.0.0.1"
    assert services["gateway"]["user"] == f"{os.getuid()}:{os.getgid()}"
    assert services["verifier"]["user"] == f"{os.getuid()}:{os.getgid()}"
    assert services["gateway"]["group_add"] == ["42"]
    assert services["gateway"]["image"] == quickstart.GATEWAY_IMAGE
    assert services["postgres"]["image"] == quickstart.POSTGRES_IMAGE
    assert services["redis"]["image"] == quickstart.REDIS_IMAGE
    for service in services.values():
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
    assert services["migrate"]["restart"] == "no"
    assert services["keys-init"]["restart"] == "no"
    assert services["keys-init"]["user"] == "0:0"
    assert set(services["keys-init"]["cap_add"]) == {"SETUID", "SETGID"}
    assert services["keys-init"]["network_mode"] == "none"
    assert services["gateway"]["depends_on"]["keys-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert "build" not in json.dumps(rendered)
    assert "prometheus" not in services
    assert "grafana" not in services
    assert "rogue" not in services


def test_deadline_versions_and_failure_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(quickstart.QuickstartError, match="timed out"):
        quickstart.Deadline(time.monotonic() - 1).remaining()
    assert quickstart._version_warnings("29.6.2", "5.3.1") == []
    assert len(quickstart._version_warnings("28.0", "2.40")) == 2

    generated = quickstart._generate(tmp_path / "cleanup", IMAGE_ID, "echo", ["server"], 8765, "42")
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], _deadline: quickstart.Deadline, *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(quickstart, "_run", fake_run)
    quickstart._cleanup(generated, quickstart.Deadline.after(10), True)
    assert calls[0][-4:] == ["logs", "--no-color", "--tail", "200"]
    assert calls[1][-1] == "down"
    assert all("--volumes" not in call for call in calls)


def test_docker_preflight_pulls_only_immutable_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], _deadline: quickstart.Deadline, *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[1:3] == ["context", "inspect"]:
            output = f"unix://{quickstart.DOCKER_SOCKET.resolve()}\n"
        elif command[1:3] == ["version", "--format"]:
            output = "29.6.2\n"
        elif command[1:4] == ["compose", "version", "--short"]:
            output = "5.3.1\n"
        elif command[1:3] == ["image", "inspect"]:
            output = IMAGE_ID + "\n"
        elif command[1] == "run":
            output = "42\n"
        else:
            output = ""
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(quickstart, "_run", fake_run)
    upstream_id, gid, engine, compose = quickstart._docker_preflight(
        "local:test", quickstart.Deadline.after(10), True
    )
    assert (upstream_id, gid, engine, compose) == (IMAGE_ID, "42", "29.6.2", "5.3.1")
    pulls = [call[2] for call in calls if call[1] == "pull"]
    assert pulls == [
        quickstart.GATEWAY_IMAGE,
        quickstart.POSTGRES_IMAGE,
        quickstart.REDIS_IMAGE,
    ]
    assert "local:test" not in pulls


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (quickstart.QuickstartUsageError("bad input"), 2),
        (quickstart.QuickstartError("docker failed"), 1),
        (KeyboardInterrupt(), 130),
    ],
)
def test_cli_quickstart_exit_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: BaseException,
    expected: int,
) -> None:
    def fail(_args: argparse.Namespace) -> dict[str, object]:
        raise error

    monkeypatch.setattr(quickstart, "run", fail)
    result = cli.main(
        [
            "--json",
            "quickstart",
            "--upstream-image",
            "local:test",
            "--allow-tool",
            "echo",
            "--arguments",
            "{}",
            "--output-dir",
            str(tmp_path / "out"),
            "--command",
            "server",
        ]
    )
    captured = capsys.readouterr()
    assert result == expected
    assert captured.out == ""
    assert captured.err
