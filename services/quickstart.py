"""Non-interactive item-48 quickstart for the released PortunusMCP stack."""

import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import platform
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import httpx
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from mcp import ClientSession, McpError
from mcp.client.streamable_http import streamable_http_client

from services.gateway.audit_export import verify_file
from services.gateway.audit_keys import AuditKeyStore
from services.gateway.decision import Decision, EventType

GATEWAY_IMAGE = (
    "ghcr.io/bashaarjavaid/portunusmcp"
    "@sha256:fdbfb388e68830fb6dff44c285fb0b3b43633113e586c448ab3e76abd6811073"
)
POSTGRES_IMAGE = (
    "postgres:16" "@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"
)
REDIS_IMAGE = "redis:7" "@sha256:595cc6f2bb3af6e03347b90deb6123c6aa2c81dea05ce08128de8a174b6ac67b"
DENIED_TOOL = "portunusmcp_quickstart_denied"
DOCKER_SOCKET = Path("/var/run/docker.sock")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_DEFAULTS = {
    "MAX_MCP_BODY_BYTES": "1048576",
    "MAX_JSON_DEPTH": "32",
    "MAX_SESSIONS_PER_IDENTITY": "3",
    "MAX_INFLIGHT_CALLS_PER_IDENTITY": "5",
    "TOOL_CALL_RATE_LIMIT": "60",
    "TOOL_CALL_RATE_WINDOW_SECONDS": "60",
    "AUTH_FAILURE_RATE_LIMIT": "5",
    "AUTH_FAILURE_RATE_WINDOW_SECONDS": "300",
    "TOOL_CALL_DEADLINE_SECONDS": "60",
    "READINESS_TIMEOUT_SECONDS": "1.0",
    "SCHEMA_CACHE_TTL": "600",
    "SESSION_IDLE_TTL": "300",
    "SHUTDOWN_GRACE_SECONDS": "5",
    "REPLAY_WINDOW_SECONDS": "30",
    "ALLOWED_HOSTS": '["127.0.0.1:*","localhost:*"]',
    "ALLOWED_ORIGINS": "[]",
    "FORWARDED_ALLOW_IPS": "*",
    "BUSINESS_HOURS_START_UTC": "9",
    "BUSINESS_HOURS_END_UTC": "18",
    "RISK_FREQ_WINDOW_SECONDS": "60",
    "RISK_FREQ_THRESHOLD": "10",
    "RISK_DECAY_STEP": "5",
    "RISK_DECAY_MAX": "10",
    "RISK_DECAY_TTL_SECONDS": "2592000",
    "RISK_DENIAL_WINDOW_SECONDS": "600",
    "RISK_DENIAL_THRESHOLD": "3",
    "RISK_DRIFT_HISTORY_WINDOW_SECONDS": "604800",
    "RISK_DRIFT_HISTORY_THRESHOLD": "2",
    "DRIFT_DESCRIPTION_SEVERITY": "high",
    "APPROVAL_TTL_SECONDS": "900",
    "STEP_UP_TTL_SECONDS": "300",
    "VERIFY_INTERVAL_SECONDS": "60",
}


class QuickstartError(Exception):
    pass


class QuickstartUsageError(QuickstartError):
    pass


@dataclass(frozen=True)
class Deadline:
    end: float

    @classmethod
    def after(cls, seconds: float) -> "Deadline":
        return cls(time.monotonic() + seconds)

    def remaining(self) -> float:
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise QuickstartError("quickstart timed out")
        return remaining


@dataclass(frozen=True)
class Generated:
    root: Path
    env_file: Path
    compose_file: Path
    credentials_file: Path
    namespace: str
    admin_key: str
    client_key: str


def json_object(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"must be valid JSON: {exc.msg}") from exc
    if not isinstance(decoded, dict):
        raise argparse.ArgumentTypeError("must decode to a JSON object")
    return decoded


def port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return port


def _progress(message: str, json_mode: bool) -> None:
    print(message, file=sys.stderr if json_mode else sys.stdout, flush=True)


def _validate_platform(system: str | None = None, machine: str | None = None) -> None:
    system = system or platform.system()
    machine = (machine or platform.machine()).lower()
    supported = (system == "Linux" and machine in {"x86_64", "amd64", "aarch64", "arm64"}) or (
        system == "Darwin" and machine in {"aarch64", "arm64"}
    )
    if not supported:
        raise QuickstartError(
            f"unsupported host {system} {machine}; use Linux amd64/arm64 or macOS arm64"
        )
    if not hasattr(os, "getuid") or os.getuid() == 0:
        raise QuickstartError("quickstart requires a non-root host user")


def _validate_args(args: argparse.Namespace) -> tuple[str, str, list[str], Path]:
    image = args.upstream_image
    tool = args.allow_tool
    command = list(args.command)
    if not image or image.strip() != image or "\0" in image:
        raise QuickstartUsageError(
            "--upstream-image must be non-empty and have no surrounding space"
        )
    if not tool or tool.strip() != tool or "\0" in tool:
        raise QuickstartUsageError("--allow-tool must be non-empty and have no surrounding space")
    if tool == DENIED_TOOL:
        raise QuickstartUsageError(f"--allow-tool value {DENIED_TOOL!r} is reserved")
    if not command or any(not part or "\0" in part for part in command):
        raise QuickstartUsageError("--command requires non-empty, NUL-free argv entries")
    raw_output = str(args.output_dir)
    if "\0" in raw_output or "\n" in raw_output or "\r" in raw_output:
        raise QuickstartUsageError("--output-dir must not contain NUL or newlines")
    output = Path(raw_output).expanduser().resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise QuickstartUsageError(f"{output} must be nonexistent or an empty directory")
    return image, tool, command, output


def _check_socket(path: Path = DOCKER_SOCKET) -> None:
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise QuickstartError(f"{path} is required") from exc
    if not stat.S_ISSOCK(mode):
        raise QuickstartError(f"{path} is not a Unix socket")


def _check_port(port: int) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise QuickstartError(f"127.0.0.1:{port} is unavailable") from exc


def _run(
    command: list[str], deadline: Deadline, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=deadline.remaining(),
            check=False,
        )
    except FileNotFoundError as exc:
        raise QuickstartError(f"{command[0]} was not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise QuickstartError("quickstart timed out") from exc
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise QuickstartError(f"{shlex.join(command[:3])} failed{suffix}")
    return result


def _version_warnings(engine: str, compose: str) -> list[str]:
    def major(value: str) -> int | None:
        match = re.search(r"\d+", value)
        return int(match.group()) if match else None

    warnings = []
    if major(engine) != 29:
        warnings.append(f"Docker Engine {engine} is outside tested 29.x")
    if major(compose) != 5:
        warnings.append(f"Docker Compose {compose} is outside tested 5.x")
    return warnings


def _docker_preflight(
    upstream_ref: str, deadline: Deadline, json_mode: bool
) -> tuple[str, str, str, str]:
    docker_host = _run(
        [
            "docker",
            "context",
            "inspect",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ],
        deadline,
    ).stdout.strip()
    if not docker_host.startswith("unix://") or (
        Path(docker_host.removeprefix("unix://")).resolve() != DOCKER_SOCKET.resolve()
    ):
        raise QuickstartError("Docker must use the local /var/run/docker.sock")
    engine = _run(["docker", "version", "--format", "{{.Server.Version}}"], deadline).stdout.strip()
    compose = _run(["docker", "compose", "version", "--short"], deadline).stdout.strip()
    if not engine or not compose:
        raise QuickstartError("Docker daemon and Compose versions could not be detected")
    _progress(f"Docker Engine {engine}; Compose {compose}", json_mode)
    for warning in _version_warnings(engine, compose):
        _progress(f"warning: {warning}", json_mode)

    upstream_id = _run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", upstream_ref], deadline
    ).stdout.strip()
    if not _IMAGE_ID.fullmatch(upstream_id):
        raise QuickstartError(f"local upstream image {upstream_ref!r} has no valid image ID")
    _progress(f"Local upstream {upstream_ref} resolved to {upstream_id}", json_mode)

    for image in (GATEWAY_IMAGE, POSTGRES_IMAGE, REDIS_IMAGE):
        _progress(f"Pulling immutable core image {image}", json_mode)
        _run(["docker", "pull", image], deadline)

    docker_gid = _run(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--entrypoint",
            "stat",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock:ro",
            GATEWAY_IMAGE,
            "-c",
            "%g",
            "/var/run/docker.sock",
        ],
        deadline,
    ).stdout.strip()
    if not docker_gid.isdigit():
        raise QuickstartError("Docker socket GID probe returned an invalid value")
    return upstream_id, docker_gid, engine, compose


def _write(path: Path, data: str | bytes, mode: int) -> None:
    raw = data.encode() if isinstance(data, str) else data
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def _env_value(value: str) -> str:
    if "\0" in value or "\n" in value or "\r" in value:
        raise QuickstartUsageError("generated environment values must not contain NUL or newlines")
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _key_hash(key: str) -> str:
    return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


def _mint_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


def _generate(
    root: Path,
    upstream_id: str,
    tool: str,
    command: list[str],
    port: int,
    docker_gid: str,
) -> Generated:
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    config = root / "config"
    revisions = config / "revisions"
    secrets_dir = root / "secrets"
    public_dir = secrets_dir / "public"
    for directory in (config, revisions, secrets_dir, public_dir):
        directory.mkdir(mode=0o700)

    admin_key = _mint_key()
    client_key = _mint_key()
    while client_key == admin_key:
        client_key = _mint_key()
    namespace = f"portunusmcp-quickstart-{secrets.token_hex(4)}"
    policy = {
        "version": 1,
        "servers": {"default": {"image": upstream_id, "command": command}},
        "identities": [
            {
                "id": "quickstart-admin",
                "api_key_hash": _key_hash(admin_key),
                "admin": True,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
            {
                "id": "quickstart-client",
                "api_key_hash": _key_hash(client_key),
                "allowed_servers": [{"server_id": "default", "allowed_tools": [tool]}],
            },
        ],
    }
    _write(root / ".gitignore", "*\n!.gitignore\n", 0o644)
    _write(config / "policy.yaml", yaml.safe_dump(policy, sort_keys=False), 0o600)

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_path = secrets_dir / "audit_signing_key.pem"
    _write(
        private_path,
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    AuditKeyStore(str(private_path), str(public_dir)).initialize()

    compose_file = root / "compose.quickstart.yml"
    _write(compose_file, files("services").joinpath("quickstart.compose.yml").read_bytes(), 0o644)
    env = {
        "QUICKSTART_NAMESPACE": namespace,
        "GATEWAY_IMAGE": GATEWAY_IMAGE,
        "POSTGRES_IMAGE": POSTGRES_IMAGE,
        "REDIS_IMAGE": REDIS_IMAGE,
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "REDIS_PASSWORD": secrets.token_urlsafe(32),
        "CONFIG_DIR": str(config),
        "SECRETS_DIR": str(secrets_dir),
        "HOST_UID": str(os.getuid()),
        "HOST_GID": str(os.getgid()),
        "DOCKER_GID": docker_gid,
        "GATEWAY_PORT": str(port),
        **_DEFAULTS,
    }
    env_file = root / ".env.quickstart"
    _write(
        env_file,
        "".join(f"{name}={_env_value(value)}\n" for name, value in env.items()),
        0o600,
    )
    credentials_file = root / "credentials.env"
    _write(
        credentials_file,
        (
            f"PORTUNUSMCP_URL=http://127.0.0.1:{port}\n"
            f"PORTUNUSMCP_ADMIN_KEY={admin_key}\n"
            f"PORTUNUSMCP_API_KEY={client_key}\n"
        ),
        0o600,
    )
    return Generated(
        root, env_file, compose_file, credentials_file, namespace, admin_key, client_key
    )


def _compose(generated: Generated) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        str(generated.env_file),
        "-p",
        generated.namespace,
        "-f",
        str(generated.compose_file),
    ]


def _wait_ready(url: str, deadline: Deadline) -> None:
    try:
        with urllib.request.urlopen(f"{url}/ready", timeout=deadline.remaining()) as response:
            if response.status != 200:
                raise QuickstartError(f"/ready returned HTTP {response.status}")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise QuickstartError(f"/ready failed: {exc}") from exc


def _proof_row(
    rows: list[dict[str, Any]], identity: str, tool: str, event_type: str
) -> dict[str, Any]:
    matches = [
        row
        for row in rows
        if row.get("identity_id") == identity
        and row.get("server_id") == "default"
        and row.get("tool_name") == tool
        and row.get("event_type") == event_type
    ]
    if len(matches) != 1:
        raise QuickstartError(
            f"audit export contained {len(matches)} matching {event_type} rows for {tool!r}"
        )
    return matches[0]


async def _prove_async(
    generated: Generated,
    tool: str,
    arguments: dict[str, Any],
    url: str,
    deadline: Deadline,
    json_mode: bool,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    deny_wire: dict[str, Any] | None = None
    async with asyncio.timeout(deadline.remaining()):
        async with httpx.AsyncClient(
            headers={"X-PortunusMCP-Key": generated.client_key},
            follow_redirects=True,
            timeout=deadline.remaining(),
        ) as http_client:
            async with streamable_http_client(f"{url}/mcp/default", http_client=http_client) as (
                read,
                write,
                _,
            ):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    visible = {item.name for item in (await session.list_tools()).tools}
                    if tool not in visible:
                        raise QuickstartError(f"allowed tool {tool!r} was not visible")
                    result = await session.call_tool(tool, arguments)
                    if result.isError:
                        raise QuickstartError(f"upstream tool {tool!r} returned isError=true")
                    _progress(
                        (
                            f"Allowed call succeeded ({len(result.content)} content block(s); "
                            "content hidden)"
                        ),
                        json_mode,
                    )
                    try:
                        await session.call_tool(DENIED_TOOL, {})
                    except McpError as exc:
                        if isinstance(exc.error.data, dict):
                            deny_wire = exc.error.data
                    else:
                        raise QuickstartError("fixed denied call unexpectedly succeeded")
        if deny_wire is None or deny_wire.get("event_type") != EventType.DENY_RBAC.value:
            raise QuickstartError("fixed denied call did not return canonical DENY_RBAC")

        descriptor, temporary_name = tempfile.mkstemp(prefix="portunusmcp-audit-", suffix=".ndjson")
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as target:
                async with httpx.AsyncClient(
                    headers={"X-PortunusMCP-Key": generated.admin_key},
                    timeout=deadline.remaining(),
                ) as admin:
                    async with admin.stream("GET", f"{url}/admin/audit/export") as response:
                        response.raise_for_status()
                        async for chunk in response.aiter_bytes():
                            target.write(chunk)
                    target.flush()
                    os.fsync(target.fileno())
                    row_count, anchored = verify_file(temporary)
                    if not anchored:
                        raise QuickstartError("audit export was not anchored at genesis")
                    with temporary.open(encoding="utf-8") as source:
                        next(source)
                        rows = [json.loads(line) for line in source]
                    allow_row = _proof_row(rows, "quickstart-client", tool, EventType.ALLOW.value)
                    deny_row = _proof_row(
                        rows,
                        "quickstart-client",
                        DENIED_TOOL,
                        EventType.DENY_RBAC.value,
                    )
                    allow_response, deny_response = await asyncio.gather(
                        admin.get(f"{url}/admin/decisions/{allow_row['seq']}"),
                        admin.get(f"{url}/admin/decisions/{deny_row['seq']}"),
                    )
                    allow_response.raise_for_status()
                    deny_response.raise_for_status()
                    allow = allow_response.json()
                    deny = deny_response.json()
        finally:
            temporary.unlink(missing_ok=True)

    if deny != deny_wire:
        raise QuickstartError("DENY_RBAC audit Decision did not match the MCP error")
    allow_model = Decision.model_validate(allow)
    deny_model = Decision.model_validate(deny)
    if allow_model.event_type is not EventType.ALLOW or allow_model.decision.value != "allow":
        raise QuickstartError("audited allowed call was not canonical ALLOW")
    if deny_model.event_type is not EventType.DENY_RBAC or deny_model.decision.value != "deny":
        raise QuickstartError("audited denied call was not canonical DENY_RBAC")
    return allow_model.model_dump(mode="json"), deny_model.model_dump(mode="json"), row_count


def _cleanup(generated: Generated, deadline: Deadline, json_mode: bool) -> None:
    base = _compose(generated)
    _progress("Quickstart failed; last 200 Compose log lines follow:", json_mode)
    try:
        logs = _run([*base, "logs", "--no-color", "--tail", "200"], deadline, check=False)
        if logs.stdout:
            print(logs.stdout.rstrip(), file=sys.stderr)
        if logs.stderr:
            print(logs.stderr.rstrip(), file=sys.stderr)
    except QuickstartError as exc:
        _progress(f"warning: could not read Compose logs: {exc}", json_mode)
    try:
        _run([*base, "down"], deadline, check=False)
    except QuickstartError as exc:
        _progress(f"warning: could not stop Compose stack: {exc}", json_mode)
    _progress(f"Retry: {shlex.join([*base, 'up', '-d', '--wait', '--pull', 'never'])}", json_mode)
    _progress(f"Reset: {shlex.join([*base, 'down', '--volumes'])}", json_mode)


def run(args: argparse.Namespace) -> dict[str, Any]:
    started_at = time.monotonic()
    deadline = Deadline.after(args.timeout)
    upstream_ref, tool, command, output = _validate_args(args)
    _validate_platform()
    _check_socket()
    _check_port(args.port)
    upstream_id, docker_gid, engine, compose = _docker_preflight(upstream_ref, deadline, args.json)
    generated = _generate(output, upstream_id, tool, command, args.port, docker_gid)
    base = _compose(generated)
    up = [
        *base,
        "up",
        "-d",
        "--wait",
        "--wait-timeout",
        str(max(1, math.ceil(deadline.remaining()))),
        "--pull",
        "never",
    ]
    _progress(f"Compose: {shlex.join(up)}", args.json)
    started = False
    try:
        _run([*base, "config", "--quiet"], deadline)
        started = True
        _run(up, deadline)
        url = f"http://127.0.0.1:{args.port}"
        _wait_ready(url, deadline)
        allow, deny, audit_rows = asyncio.run(
            _prove_async(generated, tool, args.arguments, url, deadline, args.json)
        )
    except KeyboardInterrupt:
        if started:
            _cleanup(generated, Deadline.after(60), args.json)
        raise
    except TimeoutError as exc:
        if started:
            _cleanup(generated, Deadline.after(60), args.json)
        raise QuickstartError("quickstart timed out") from exc
    except Exception as exc:
        if started:
            cleanup_deadline = Deadline.after(60)
            _cleanup(generated, cleanup_deadline, args.json)
        if isinstance(exc, QuickstartError):
            raise
        raise QuickstartError(str(exc)) from exc

    elapsed = round(time.monotonic() - started_at, 3)
    start_command = shlex.join([*base, "up", "-d", "--wait", "--pull", "never"])
    stop_command = shlex.join([*base, "down"])
    reset_command = shlex.join([*base, "down", "--volumes"])
    return {
        "metadata": {
            "work_directory": str(generated.root),
            "namespace": generated.namespace,
            "identities": ["quickstart-admin", "quickstart-client"],
            "server_id": "default",
            "upstream_reference": upstream_ref,
            "upstream_image_id": upstream_id,
            "upstream_command": command,
            "gateway_url": url,
            "mcp_url": f"{url}/mcp/default",
            "security": {
                "upstream_network": "none",
                "upstream_environment": {},
                "upstream_volumes": [],
                "upstream_resources": {"memory_mb": 256, "cpus": 0.5, "pids": 64},
                "gateway_binding": f"127.0.0.1:{args.port}",
                "gateway_user": f"{os.getuid()}:{os.getgid()}",
                "docker_socket_gid": docker_gid,
                "core_images_immutable": True,
                "audit_key_runtime": "named volume seeded from generated host key files",
                "key_initializer_capabilities": ["SETUID", "SETGID"],
            },
            "audit_rows_verified": audit_rows,
        },
        "paths": {
            "compose": str(generated.compose_file),
            "environment": str(generated.env_file),
            "credentials": str(generated.credentials_file),
            "policy": str(generated.root / "config" / "policy.yaml"),
        },
        "elapsed_seconds": elapsed,
        "versions": {"docker_engine": engine, "docker_compose": compose},
        "commands": {"start": start_command, "stop": stop_command, "reset": reset_command},
        "decisions": {"allow": allow, "deny": deny},
    }


def human(result: dict[str, Any]) -> str:
    metadata = result["metadata"]
    security = metadata["security"]
    return "\n".join(
        [
            "",
            "Quickstart proof passed.",
            f"Elapsed: {result['elapsed_seconds']}s",
            (
                f"Docker Engine {result['versions']['docker_engine']}; "
                f"Compose {result['versions']['docker_compose']}"
            ),
            f"Work directory: {metadata['work_directory']}",
            f"Namespace: {metadata['namespace']}",
            "Identities: quickstart-admin, quickstart-client",
            "Server: default",
            f"Upstream supplied: {metadata['upstream_reference']}",
            f"Upstream image ID: {metadata['upstream_image_id']}",
            f"Upstream command: {shlex.join(metadata['upstream_command'])}",
            f"Gateway: {metadata['gateway_url']}",
            f"MCP: {metadata['mcp_url']}",
            (
                "Security: immutable core images; loopback-only gateway; upstream "
                f"network={security['upstream_network']}; env/volumes empty; "
                "resources=256 MiB/0.5 CPU/64 PIDs"
            ),
            (
                f"Runtime: gateway/verifier user={security['gateway_user']}; "
                f"Docker socket GID={security['docker_socket_gid']}; key initializer "
                "network=none and capabilities=SETUID,SETGID"
            ),
            "",
            "ALLOW Decision:",
            json.dumps(result["decisions"]["allow"], ensure_ascii=False, indent=2, sort_keys=True),
            "",
            "DENY Decision:",
            json.dumps(result["decisions"]["deny"], ensure_ascii=False, indent=2, sort_keys=True),
            "",
            "Load credentials without printing them:",
            (
                f"  cd {shlex.quote(metadata['work_directory'])} && "
                "set -a && source ./credentials.env && set +a"
            ),
            f"Start/restart: {result['commands']['start']}",
            f"Stop (preserves state): {result['commands']['stop']}",
            f"Reset (deletes named volumes): {result['commands']['reset']}",
            (
                "Warning: mounting the Docker socket grants the gateway root-equivalent "
                "control of this host; use only trusted upstream images and operators."
            ),
        ]
    )
