"""Local deployment diagnostics and safe repairs (ROADMAP item 50)."""

import argparse
import builtins
import functools
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives.asymmetric import ec

from services.gateway import signing
from services.gateway.audit_keys import AuditKeyStore
from services.gateway.policy_engine import PolicyEngine, load_bytes

_NAMESPACE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_ENV_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_PUBLIC_KEY = re.compile(r"^([0-9a-f]{64})\.pub\.pem$")
_DOCKER_ENV = (
    "PATH",
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "XDG_CONFIG_HOME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


class DoctorError(Exception):
    pass


@dataclass(frozen=True)
class Layout:
    kind: str
    root: Path
    primary_env: Path
    compose: Path


@dataclass(frozen=True)
class Repair:
    finding_id: str
    message: str
    apply: Callable[[], object]
    restart: bool = False


def _finding(
    finding_id: str,
    status: str,
    message: str,
    *,
    fixable: bool = False,
    action: str | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "status": status,
        "message": message,
        "fixable": fixable,
        "action": action,
    }


def _discover(raw: str) -> Layout:
    if "\0" in raw or "\n" in raw or "\r" in raw:
        raise DoctorError("deployment directory must not contain NUL or newlines")
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        raise DoctorError(f"{root} is not a directory")
    production = any((root / name).exists() for name in ("compose.prod.yml", ".env.prod"))
    quickstart = any(
        (root / name).exists() for name in ("compose.quickstart.yml", ".env.quickstart")
    )
    if production and quickstart:
        raise DoctorError(f"{root} contains both production and quickstart deployment markers")
    if production:
        return Layout("production", root, root / ".env.prod", root / "compose.prod.yml")
    if quickstart:
        return Layout("quickstart", root, root / ".env.quickstart", root / "compose.quickstart.yml")
    if (root / "compose.demo.yml").exists() or (root / ".env.demo").exists():
        raise DoctorError("doctor supports production and quickstart deployments, not demo")
    raise DoctorError(f"{root} is not a recognized production or quickstart deployment")


def _decode_env(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("\\'", "'").replace("\\\\", "\\")
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise DoctorError(f"invalid double-quoted environment value: {exc.msg}") from exc
        if not isinstance(decoded, str):
            raise DoctorError("double-quoted environment value must be a string")
        return decoded
    return value


def _env_file(path: Path) -> tuple[dict[str, str], set[str]]:
    values: dict[str, str] = {}
    duplicates: set[str] = set()
    for number, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_ASSIGNMENT.fullmatch(stripped)
        if match is None:
            raise DoctorError(f"{path}:{number} is not a KEY=VALUE assignment")
        key, raw_value = match.groups()
        if key in values:
            duplicates.add(key)
        values[key] = _decode_env(raw_value)
    return values, duplicates


def _atomic_env_update(path: Path, key: str, value: str) -> None:
    lines = path.read_text().splitlines(keepends=True)
    indexes = [
        index
        for index, line in enumerate(lines)
        if (match := _ENV_ASSIGNMENT.fullmatch(line.strip())) and match.group(1) == key
    ]
    if len(indexes) > 1:
        raise DoctorError(f"{path} contains duplicate {key} assignments")
    replacement = f"{key}={value}\n"
    if indexes:
        lines[indexes[0]] = replacement
    else:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += "\n"
        lines.append(replacement)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.writelines(lines)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(stat.S_IMODE(path.stat().st_mode))
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _docker_environment() -> dict[str, str]:
    return {name: os.environ[name] for name in _DOCKER_ENV if name in os.environ}


def _command(
    command: list[str], timeout: float, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=_docker_environment(),
        )
    except FileNotFoundError as exc:
        raise DoctorError(f"{command[0]} was not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise DoctorError(f"{shlex.join(command[:3])} timed out") from exc
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise DoctorError(f"{shlex.join(command[:3])} failed{suffix}")
    return result


def _compose_command(layout: Layout) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        str(layout.primary_env),
        "-f",
        str(layout.compose),
    ]


def _render(layout: Layout, timeout: float) -> dict[str, Any]:
    raw = _command(
        [*_compose_command(layout), "--profile", "*", "config", "--format", "json"],
        timeout,
    ).stdout
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise DoctorError("Docker Compose rendered a non-object configuration")
    return result


def _matching_containers(project: str, timeout: float) -> dict[str, dict[str, Any]]:
    if not project:
        return {}
    result = _command(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        timeout,
        check=False,
    )
    ids = result.stdout.split()
    if result.returncode or not ids:
        return {}
    raw = _command(["docker", "inspect", *ids], timeout).stdout
    inspected = json.loads(raw)
    return {
        item.get("Config", {}).get("Labels", {}).get("com.docker.compose.service", ""): item
        for item in inspected
        if item.get("Config", {}).get("Labels", {}).get("com.docker.compose.service")
    }


def _infer_namespace(layout: Layout, timeout: float) -> str | None:
    result = _command(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project.config_files={layout.compose}",
            "--filter",
            "label=com.docker.compose.service=gateway",
        ],
        timeout,
        check=False,
    )
    ids = result.stdout.split()
    if result.returncode or not ids:
        return None
    inspected = json.loads(_command(["docker", "inspect", *ids], timeout).stdout)
    values = {
        value.split("=", 1)[1]
        for item in inspected
        for value in item.get("Config", {}).get("Env", [])
        if value.startswith("UPSTREAM_RUNTIME_NAMESPACE=")
        and _NAMESPACE.fullmatch(value.split("=", 1)[1])
    }
    return values.pop() if len(values) == 1 else None


def _policy_references(data: object) -> tuple[set[str], set[str]]:
    upstream: set[str] = set()
    secrets: set[str] = set()
    if not isinstance(data, dict):
        return upstream, secrets
    servers = data.get("servers")
    if isinstance(servers, dict):
        for server in servers.values():
            if isinstance(server, dict) and isinstance(server.get("env"), dict):
                upstream.update(value for value in server["env"].values() if isinstance(value, str))
    identities = data.get("identities")
    if isinstance(identities, list):
        for identity in identities:
            if not isinstance(identity, dict):
                continue
            for name in ("signing_secret_env", "totp_secret_env"):
                value = identity.get(name)
                if isinstance(value, str):
                    secrets.add(value)
    return upstream, secrets


@contextmanager
def _policy_environment(values: dict[str, str]) -> Any:
    old = os.environ.copy()
    os.environ.clear()
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


def _mint_key(private_path: Path, public_dir: Path) -> None:
    private_key = signing.generate_private_key()
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(signing.private_pem(private_key))
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        private_path.unlink(missing_ok=True)
        raise
    AuditKeyStore(str(private_path), str(public_dir)).ensure_public(private_key.public_key())


def _loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _Scan:
    def __init__(self, layout: Layout, timeout: float, *, repairs: bool) -> None:
        self.layout = layout
        self.timeout = timeout
        self.offer_repairs = repairs
        self.findings: list[dict[str, Any]] = []
        self.repairs: list[Repair] = []
        self.values: dict[str, str] = {}
        self.rendered: dict[str, Any] | None = None
        self.containers: dict[str, dict[str, Any]] = {}
        self.stack_exists = False
        self.namespace = ""
        self.policy: PolicyEngine | None = None

    def add(
        self,
        finding_id: str,
        status: str,
        message: str,
        *,
        action: str | None = None,
        repair: Repair | None = None,
    ) -> None:
        self.findings.append(
            _finding(
                finding_id,
                status,
                message,
                fixable=repair is not None,
                action=repair.message if repair is not None else action,
            )
        )
        if repair is not None and self.offer_repairs:
            self.repairs.append(repair)

    def check_file(
        self,
        finding_id: str,
        path: Path,
        mode: int,
        *,
        restart: bool,
        owner: tuple[int, int] | None = None,
    ) -> bool:
        if path.is_symlink():
            self.add(
                finding_id,
                "ERROR",
                f"{path} is a symlink",
                action="replace the symlink with an operator-owned regular file",
            )
            return False
        if not path.is_file():
            self.add(finding_id, "ERROR", f"{path} is missing", action=f"restore {path}")
            return False
        actual = stat.S_IMODE(path.stat().st_mode)
        if actual != mode:
            repair = Repair(
                finding_id,
                f"chmod {mode:04o} {path}",
                functools.partial(path.chmod, mode),
                restart,
            )
            self.add(
                finding_id,
                "ERROR",
                f"{path} has mode {actual:04o}; expected {mode:04o}",
                repair=repair,
            )
        else:
            self.add(finding_id, "PASS", f"{path} has mode {mode:04o}")
        if owner is not None:
            info = path.stat()
            if (info.st_uid, info.st_gid) != owner:
                self.add(
                    f"{finding_id}.owner",
                    "ERROR",
                    (
                        f"{path} is owned by {info.st_uid}:{info.st_gid}; "
                        f"expected {owner[0]}:{owner[1]}"
                    ),
                    action=(
                        f"have the operator change ownership of {path} " f"to {owner[0]}:{owner[1]}"
                    ),
                )
            else:
                self.add(
                    f"{finding_id}.owner",
                    "PASS",
                    f"{path} is owned by {owner[0]}:{owner[1]}",
                )
        return True

    def check_directory(
        self,
        finding_id: str,
        path: Path,
        *,
        owner: tuple[int, int] | None = None,
        restart: bool = True,
    ) -> bool:
        if path.is_symlink():
            self.add(
                finding_id,
                "ERROR",
                f"{path} is a symlink",
                action="replace the symlink with an operator-owned directory",
            )
            return False
        if not path.exists():
            repair = Repair(
                finding_id,
                f"create {path} at mode 0700",
                functools.partial(path.mkdir, parents=True, mode=0o700, exist_ok=True),
                restart,
            )
            self.add(finding_id, "ERROR", f"{path} is missing", repair=repair)
            return False
        if not path.is_dir():
            self.add(
                finding_id,
                "ERROR",
                f"{path} is not a directory",
                action=f"replace {path} with a directory",
            )
            return False
        actual = stat.S_IMODE(path.stat().st_mode)
        if actual != 0o700:
            self.add(
                finding_id,
                "ERROR",
                f"{path} has mode {actual:04o}; expected 0700",
                repair=Repair(
                    finding_id,
                    f"chmod 0700 {path}",
                    functools.partial(path.chmod, 0o700),
                    restart,
                ),
            )
        else:
            self.add(finding_id, "PASS", f"{path} has mode 0700")
        if owner is not None:
            info = path.stat()
            if (info.st_uid, info.st_gid) != owner:
                self.add(
                    f"{finding_id}.owner",
                    "ERROR",
                    (
                        f"{path} is owned by {info.st_uid}:{info.st_gid}; "
                        f"expected {owner[0]}:{owner[1]}"
                    ),
                    action=f"have the operator change ownership of {path} to {owner[0]}:{owner[1]}",
                )
            else:
                self.add(
                    f"{finding_id}.owner",
                    "PASS",
                    f"{path} is owned by {owner[0]}:{owner[1]}",
                )
        return True

    def deployment(self) -> None:
        self.add(
            "deployment.shape",
            "PASS",
            f"recognized {self.layout.kind} deployment at {self.layout.root}",
        )
        if self.layout.kind == "quickstart":
            self.check_directory("filesystem.deployment", self.layout.root, restart=False)
        else:
            self.add(
                "filesystem.deployment",
                "PASS",
                f"{self.layout.root} is an operator-owned production bundle directory",
            )
        for finding_id, path in (
            ("deployment.environment", self.layout.primary_env),
            ("deployment.compose", self.layout.compose),
        ):
            if path.is_symlink():
                self.add(
                    finding_id,
                    "ERROR",
                    f"{path} is a symlink",
                    action="replace it with an operator-owned regular file",
                )
            elif not path.is_file():
                self.add(finding_id, "ERROR", f"{path} is missing", action=f"restore {path}")
            else:
                self.add(finding_id, "PASS", f"found {path}")
        if not self.layout.primary_env.is_file() or self.layout.primary_env.is_symlink():
            return
        self.check_file("filesystem.primary_env", self.layout.primary_env, 0o600, restart=False)
        try:
            self.values, duplicates = _env_file(self.layout.primary_env)
        except (OSError, DoctorError) as exc:
            self.add("deployment.environment.parse", "ERROR", str(exc))
            return
        if duplicates:
            self.add(
                "deployment.environment.duplicates",
                "ERROR",
                "duplicate assignments: " + ", ".join(sorted(duplicates)),
                action="remove duplicate assignments before running doctor --fix",
            )
        else:
            self.add("deployment.environment.duplicates", "PASS", "no duplicate assignments")

    def docker(self) -> bool:
        if shutil.which("docker") is None:
            self.add("docker.cli", "ERROR", "docker CLI was not found", action="install Docker")
            return False
        self.add("docker.cli", "PASS", "docker CLI is available")
        try:
            host = _command(
                ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                self.timeout,
            ).stdout.strip()
            if not host.startswith("unix://") or (
                Path(host.removeprefix("unix://")).resolve()
                != Path("/var/run/docker.sock").resolve()
            ):
                raise DoctorError(f"Docker context uses {host!r}, not unix:///var/run/docker.sock")
            mode = Path("/var/run/docker.sock").stat().st_mode
            if not stat.S_ISSOCK(mode):
                raise DoctorError("/var/run/docker.sock is not a Unix socket")
            engine = _command(
                ["docker", "version", "--format", "{{.Server.Version}}"], self.timeout
            ).stdout.strip()
            compose = _command(
                ["docker", "compose", "version", "--short"], self.timeout
            ).stdout.strip()
        except (OSError, DoctorError) as exc:
            self.add(
                "docker.daemon",
                "ERROR",
                str(exc),
                action="start the supported local Docker daemon",
            )
            return False
        self.add(
            "docker.daemon",
            "PASS",
            "local Docker daemon is reachable through /var/run/docker.sock",
        )
        for finding_id, product, value, expected in (
            ("docker.version.engine", "Docker Engine", engine, "29"),
            ("docker.version.compose", "Docker Compose", compose, "5"),
        ):
            match = re.search(r"\d+", value)
            if match and match.group() == expected:
                self.add(
                    finding_id,
                    "PASS",
                    f"{product} {value} is on the tested {expected}.x line",
                )
            else:
                self.add(
                    finding_id,
                    "WARN",
                    f"{product} {value or '<unknown>'} is outside the tested {expected}.x line",
                )
        return True

    def compose(self) -> None:
        if not self.layout.compose.is_file() or not self.layout.primary_env.is_file():
            return
        try:
            self.rendered = _render(self.layout, self.timeout)
        except (DoctorError, json.JSONDecodeError) as exc:
            self.add("compose.render", "ERROR", str(exc), action="correct the Compose/env error")
            return
        self.add("compose.render", "PASS", "Docker Compose rendered every profile")
        project = str(self.rendered.get("name", ""))
        self.containers = _matching_containers(project, self.timeout)
        self.stack_exists = bool(self.containers)

    def paths(self) -> tuple[Path, Path, Path, Path, tuple[int, int]] | None:
        try:
            if self.layout.kind == "production":
                policy_dir = Path(self.values["POLICY_DIR_HOST"])
                audit_dir = Path(self.values["AUDIT_SIGNING_KEY_DIR"])
                if not policy_dir.is_absolute() or not audit_dir.is_absolute():
                    raise DoctorError(
                        "production policy and audit-key directories must be absolute"
                    )
                gateway_env = Path(
                    self.values.get("GATEWAY_ENV_FILE", str(self.layout.root / ".env.prod.gateway"))
                )
                if not gateway_env.is_absolute():
                    gateway_env = self.layout.root / gateway_env
                rendered_user = (
                    (self.rendered or {})
                    .get("services", {})
                    .get("gateway", {})
                    .get("user", "1000:1000")
                )
                uid, gid = str(rendered_user).split(":", 1)
                owner = (int(uid), int(gid))
            else:
                policy_dir = Path(self.values["CONFIG_DIR"])
                audit_dir = Path(self.values["SECRETS_DIR"])
                gateway_env = self.layout.primary_env
                owner = (int(self.values["HOST_UID"]), int(self.values["HOST_GID"]))
        except (KeyError, ValueError, DoctorError) as exc:
            self.add(
                "deployment.paths",
                "ERROR",
                f"deployment paths are invalid: {exc}",
                action="complete the deployment environment file",
            )
            return None
        policy_dir = policy_dir.expanduser()
        audit_dir = audit_dir.expanduser()
        gateway_env = gateway_env.expanduser()
        self.check_directory("filesystem.policy_dir", policy_dir, owner=owner)
        self.check_directory("filesystem.revisions_dir", policy_dir / "revisions", owner=owner)
        self.check_directory("filesystem.audit_dir", audit_dir, owner=owner)
        self.check_directory("filesystem.public_dir", audit_dir / "public", owner=owner)
        return policy_dir, audit_dir, audit_dir / "public", gateway_env, owner

    def gateway_environment(
        self, policy_data: object, gateway_env: Path
    ) -> tuple[dict[str, str], bool]:
        upstream, secrets = _policy_references(policy_data)
        references = upstream | secrets
        if self.layout.kind == "production":
            if gateway_env.is_symlink():
                self.add(
                    "filesystem.gateway_env",
                    "ERROR",
                    f"{gateway_env} is a symlink",
                    action="replace it with an operator-owned regular file",
                )
                return {}, False
            if not gateway_env.exists():
                if references:
                    self.add(
                        "filesystem.gateway_env",
                        "ERROR",
                        f"{gateway_env} is missing; policy references "
                        + ", ".join(sorted(references)),
                        action="create the file and supply the named values",
                    )
                    return {}, False
                self.add(
                    "filesystem.gateway_env",
                    "ERROR",
                    f"{gateway_env} is missing",
                    repair=Repair(
                        "filesystem.gateway_env",
                        f"create empty mode-0600 {gateway_env}",
                        functools.partial(_create_empty, gateway_env),
                        True,
                    ),
                )
                return {}, False
            self.check_file("filesystem.gateway_env", gateway_env, 0o600, restart=True)
            try:
                _, duplicates = _env_file(gateway_env)
            except (OSError, DoctorError) as exc:
                self.add("deployment.gateway_environment.parse", "ERROR", str(exc))
                return {}, False
            if duplicates:
                self.add(
                    "deployment.gateway_environment.duplicates",
                    "ERROR",
                    "duplicate assignments: " + ", ".join(sorted(duplicates)),
                    action="remove duplicate assignments before running doctor --fix",
                )
                return {}, False
        if self.rendered is None:
            return {}, not references
        environment = self.rendered.get("services", {}).get("gateway", {}).get("environment", {})
        if not isinstance(environment, dict):
            environment = {}
        missing = sorted(
            name
            for name in references
            if name not in environment or (name in secrets and not environment[name])
        )
        for name in missing:
            self.add(
                "policy.environment",
                "ERROR",
                f"policy-referenced environment variable {name} is missing",
                action=f"set {name} in the deployed gateway environment",
            )
        if not missing:
            self.add(
                "policy.environment",
                "PASS",
                f"all {len(references)} policy-referenced environment variables are present",
            )
        return {str(key): str(value) for key, value in environment.items()}, not missing

    def policy_and_runtime(
        self, policy_dir: Path, gateway_env: Path, owner: tuple[int, int]
    ) -> None:
        policy_path = policy_dir / "policy.yaml"
        if not self.check_file("filesystem.policy", policy_path, 0o600, restart=True, owner=owner):
            return
        try:
            raw = policy_path.read_bytes()
            policy_data = yaml.safe_load(raw)
        except (OSError, yaml.YAMLError) as exc:
            self.add("policy.validation", "ERROR", f"policy could not be read: {exc}")
            return
        environment, complete = self.gateway_environment(policy_data, gateway_env)
        if not complete:
            return
        try:
            with _policy_environment(environment):
                self.policy = load_bytes(raw)
        except Exception as exc:
            self.add("policy.validation", "ERROR", f"policy validation failed: {exc}")
            return
        self.add("policy.validation", "PASS", "policy passes the canonical loader")
        if not self.namespace:
            return
        prefix = f"portunusmcp-upstream-{self.namespace}-"
        for server_id, server in self.policy.policy.servers.items():
            if not (_IMAGE_ID.fullmatch(server.image) or _IMAGE_DIGEST.fullmatch(server.image)):
                self.add(
                    "policy.image.digest",
                    "ERROR",
                    f"server {server_id!r} image {server.image!r} is not immutable",
                    action="choose a local image ID or registry digest",
                )
            else:
                self.add(
                    "policy.image.digest",
                    "PASS",
                    f"server {server_id!r} uses an immutable image reference",
                )
            result = _command(
                ["docker", "image", "inspect", server.image], self.timeout, check=False
            )
            if result.returncode:
                self.add(
                    "policy.image.available",
                    "ERROR",
                    f"server {server_id!r} image {server.image!r} is unavailable locally",
                    action="load or pull the explicitly chosen immutable image",
                )
            else:
                self.add(
                    "policy.image.available",
                    "PASS",
                    f"server {server_id!r} image is available locally",
                )
            for mount in server.volumes:
                if not mount.source.startswith(prefix):
                    self.add(
                        "policy.volume.namespace",
                        "ERROR",
                        f"server {server_id!r} volume {mount.source!r} must start with {prefix!r}",
                        action="choose a volume in this deployment namespace",
                    )
                else:
                    self.add(
                        "policy.volume.namespace",
                        "PASS",
                        f"server {server_id!r} volume {mount.source!r} is namespaced",
                    )
                result = _command(
                    ["docker", "volume", "inspect", mount.source],
                    self.timeout,
                    check=False,
                )
                if result.returncode:
                    self.add(
                        "policy.volume.available",
                        "ERROR",
                        f"server {server_id!r} volume {mount.source!r} is missing",
                        action="provision or restore the expected named volume",
                    )
                else:
                    self.add(
                        "policy.volume.available",
                        "PASS",
                        f"server {server_id!r} volume {mount.source!r} exists",
                    )

    def namespace_and_gid(self, docker_ready: bool) -> None:
        key = (
            "UPSTREAM_RUNTIME_NAMESPACE"
            if self.layout.kind == "production"
            else "QUICKSTART_NAMESPACE"
        )
        self.namespace = self.values.get(key, "")
        if _NAMESPACE.fullmatch(self.namespace):
            self.add("docker.namespace", "PASS", f"runtime namespace {self.namespace!r} is valid")
        elif docker_ready:
            inferred = _infer_namespace(self.layout, self.timeout)
            if inferred is None:
                self.add(
                    "docker.namespace",
                    "ERROR",
                    f"{key} is missing or invalid and no exact running value can be inferred",
                    action="choose a unique namespace matching ^[a-z0-9][a-z0-9-]{0,31}$",
                )
            else:
                self.add(
                    "docker.namespace",
                    "ERROR",
                    f"{key} is missing or invalid; existing deployment uses {inferred!r}",
                    repair=Repair(
                        "docker.namespace",
                        f"write {key}={inferred} to {self.layout.primary_env}",
                        functools.partial(
                            _atomic_env_update, self.layout.primary_env, key, inferred
                        ),
                        True,
                    ),
                )
                self.namespace = inferred
        if not docker_ready:
            return
        running_image = self.containers.get("gateway", {}).get("Config", {}).get("Image", "")
        if running_image:
            image = str(running_image)
        elif self.layout.kind == "production":
            digest = self.values.get("GATEWAY_IMAGE_DIGEST", "")
            image = f"ghcr.io/bashaarjavaid/portunusmcp@{digest}" if digest else ""
        else:
            image = self.values.get("GATEWAY_IMAGE", "")
        if not image:
            self.add(
                "docker.socket_gid",
                "ERROR",
                "configured gateway image is missing, so the socket GID cannot be probed",
                action="complete the gateway image setting",
            )
            return
        result = _command(
            [
                "docker",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--entrypoint",
                "stat",
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock:ro",
                image,
                "-c",
                "%g",
                "/var/run/docker.sock",
            ],
            self.timeout,
            check=False,
        )
        detected = result.stdout.strip()
        if result.returncode or not detected.isdigit():
            self.add(
                "docker.socket_gid",
                "ERROR",
                "Docker socket GID could not be detected from the configured gateway image",
                action="make the configured gateway image available locally, then rerun doctor",
            )
            return
        configured = self.values.get("DOCKER_GID", "")
        if configured == detected:
            self.add("docker.socket_gid", "PASS", f"DOCKER_GID matches socket GID {detected}")
        else:
            self.add(
                "docker.socket_gid",
                "ERROR",
                f"DOCKER_GID is {configured or '<unset>'}; socket GID is {detected}",
                repair=Repair(
                    "docker.socket_gid",
                    f"write DOCKER_GID={detected} to {self.layout.primary_env}",
                    functools.partial(
                        _atomic_env_update, self.layout.primary_env, "DOCKER_GID", detected
                    ),
                    True,
                ),
            )

    def audit_keys(self, audit_dir: Path, public_dir: Path, owner: tuple[int, int]) -> None:
        private_path = audit_dir / "audit_signing_key.pem"
        public_files = list(public_dir.glob("*.pub.pem")) if public_dir.is_dir() else []
        private_key: ec.EllipticCurvePrivateKey | None = None
        if private_path.is_symlink():
            self.add(
                "audit.private_key",
                "ERROR",
                f"{private_path} is a symlink",
                action="restore the operator-owned private key from backup",
            )
        elif not private_path.exists():
            if not public_files:
                self.add(
                    "audit.private_key",
                    "ERROR",
                    f"{private_path} is missing from a pristine key directory",
                    repair=Repair(
                        "audit.private_key",
                        f"mint initial audit key material in {audit_dir}",
                        functools.partial(_mint_key, private_path, public_dir),
                        True,
                    ),
                )
            else:
                self.add(
                    "audit.private_key",
                    "ERROR",
                    f"{private_path} is missing but historical public keys exist",
                    action="restore the matching private key and database/key backup set",
                )
        else:
            self.check_file(
                "filesystem.private_key",
                private_path,
                0o600,
                restart=True,
                owner=owner,
            )
            try:
                loaded = signing.load_private_key(str(private_path))
                if not isinstance(loaded.curve, ec.SECP256R1):
                    raise ValueError("active audit key is not P-256")
                private_key = loaded
                self.add("audit.private_key", "PASS", "active audit private key is valid P-256")
            except Exception as exc:
                self.add(
                    "audit.private_key",
                    "ERROR",
                    f"active audit private key is invalid: {exc}",
                    action="restore the matching private key and database/key backup set",
                )
        for path in public_files:
            if path.is_symlink():
                self.add(
                    "audit.public_key",
                    "ERROR",
                    f"{path} is a symlink",
                    action="restore the archived public key as a regular file",
                )
                continue
            match = _PUBLIC_KEY.fullmatch(path.name)
            try:
                public_key = signing.load_public_key(str(path))
                if not isinstance(public_key.curve, ec.SECP256R1):
                    raise ValueError("not P-256")
                digest = signing.key_id(public_key).removeprefix("sha256:")
                if match is None or match.group(1) != digest:
                    raise ValueError("filename does not match the key fingerprint")
            except Exception as exc:
                self.add(
                    "audit.public_key",
                    "ERROR",
                    f"archived public key {path} is invalid: {exc}",
                    action="restore the fingerprinted public key from backup",
                )
                continue
            self.check_file("filesystem.public_key", path, 0o444, restart=True, owner=owner)
            self.add("audit.public_key", "PASS", f"archived public key {path.name} is valid")
        if private_key is not None and public_dir.is_dir():
            key_id = signing.key_id(private_key.public_key())
            active_public = AuditKeyStore(str(private_path), str(public_dir)).public_path(key_id)
            if not active_public.exists():
                self.add(
                    "audit.public_key.active",
                    "ERROR",
                    f"active public archive {active_public} is missing",
                    repair=Repair(
                        "audit.public_key.active",
                        f"derive {active_public.name} from the active private key",
                        functools.partial(
                            AuditKeyStore(str(private_path), str(public_dir)).ensure_public,
                            private_key.public_key(),
                        ),
                        True,
                    ),
                )
            else:
                self.add(
                    "audit.public_key.active",
                    "PASS",
                    f"active public archive {active_public.name} exists",
                )

    def network(self) -> None:
        if self.rendered is None:
            return
        services = self.rendered.get("services", {})
        names = (
            ("gateway",)
            if self.layout.kind == "quickstart"
            else (
                "gateway",
                "prometheus",
                "grafana",
            )
        )
        owned: set[tuple[str, int]] = set()
        for container in self.containers.values():
            for bindings in container.get("NetworkSettings", {}).get("Ports", {}).values():
                for binding in bindings or []:
                    try:
                        owned.add((binding["HostIp"], int(binding["HostPort"])))
                    except (KeyError, TypeError, ValueError):
                        continue
        gateway_ports: list[tuple[str, int]] = []
        for name in names:
            ports = services.get(name, {}).get("ports", [])
            if not ports:
                self.add(
                    "network.port",
                    "ERROR",
                    f"service {name!r} has no published host port",
                    action="restore the shipped loopback port binding",
                )
                continue
            for binding in ports:
                host = str(binding.get("host_ip", "0.0.0.0"))
                try:
                    port = int(binding["published"])
                    if not 1 <= port <= 65535:
                        raise ValueError
                except (KeyError, TypeError, ValueError):
                    self.add(
                        "network.port",
                        "ERROR",
                        f"service {name!r} has an invalid published port",
                        action="choose a valid port from 1 through 65535",
                    )
                    continue
                if name == "gateway":
                    gateway_ports.append((host, port))
                if not _loopback(host):
                    self.add(
                        "network.binding",
                        "ERROR",
                        f"service {name!r} binds non-loopback host {host}:{port}",
                        action="restore a loopback-only host binding",
                    )
                else:
                    self.add(
                        "network.binding",
                        "PASS",
                        f"service {name!r} binds loopback {host}:{port}",
                    )
                try:
                    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET) as probe:
                        probe.bind((host, port))
                except OSError:
                    if (host, port) in owned:
                        self.add(
                            "network.port",
                            "PASS",
                            f"{host}:{port} is owned by this Compose deployment",
                        )
                    else:
                        self.add(
                            "network.port",
                            "ERROR",
                            f"{host}:{port} is occupied by another process",
                            action="stop the conflicting process or choose an explicit port",
                        )
                else:
                    self.add("network.port", "PASS", f"{host}:{port} is available")
        forwarded = self.values.get("FORWARDED_ALLOW_IPS", "")
        if forwarded == "*":
            if gateway_ports and all(_loopback(host) for host, _ in gateway_ports):
                self.add(
                    "network.forwarded_allow_ips",
                    "PASS",
                    "FORWARDED_ALLOW_IPS=* is bounded by loopback-only gateway publishing",
                )
            else:
                self.add(
                    "network.forwarded_allow_ips",
                    "ERROR",
                    "FORWARDED_ALLOW_IPS=* requires every gateway binding to be loopback",
                    action="choose the trusted proxy IP/CIDR or restore loopback publishing",
                )
        else:
            invalid = []
            for value in forwarded.split(","):
                value = value.strip()
                if not value:
                    invalid.append("<empty>")
                    continue
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError:
                    invalid.append(value)
            if invalid:
                self.add(
                    "network.forwarded_allow_ips",
                    "ERROR",
                    "invalid FORWARDED_ALLOW_IPS entries: " + ", ".join(invalid),
                    action="supply only comma-separated trusted proxy IPs or CIDRs",
                )
            else:
                self.add(
                    "network.forwarded_allow_ips",
                    "PASS",
                    "FORWARDED_ALLOW_IPS contains valid IP/CIDR entries",
                )
        gateway = self.containers.get("gateway")
        if gateway is None or not gateway.get("State", {}).get("Running"):
            self.add("runtime.readiness", "INFO", "gateway container is not running")
            return
        if not gateway_ports:
            self.add("runtime.readiness", "ERROR", "running gateway has no rendered host port")
            return
        _, port = gateway_ports[0]
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/ready", timeout=min(self.timeout, 2)
            ) as response:
                if response.status != 200:
                    raise DoctorError(f"/ready returned HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read(64 * 1024))
                failed = sorted(
                    name
                    for name, status_value in payload.get("checks", {}).items()
                    if status_value != "ok"
                )
            except (json.JSONDecodeError, AttributeError):
                failed = []
            detail = f"HTTP {exc.code}" + (
                f"; failed checks: {', '.join(failed)}" if failed else ""
            )
            self.add(
                "runtime.readiness",
                "ERROR",
                f"running gateway is not ready: {detail}",
                action="inspect gateway logs and resolve the reported dependency",
            )
        except (urllib.error.URLError, TimeoutError, DoctorError) as exc:
            self.add(
                "runtime.readiness",
                "ERROR",
                f"running gateway is not ready: {exc}",
                action="inspect gateway logs and resolve the reported dependency",
            )
        else:
            self.add("runtime.readiness", "PASS", "running gateway returned /ready 200")

    def run(self) -> tuple[list[dict[str, Any]], list[Repair], bool]:
        self.deployment()
        docker_ready = self.docker()
        self.compose()
        self.namespace_and_gid(docker_ready)
        resolved = self.paths()
        if resolved is not None:
            policy_dir, audit_dir, public_dir, gateway_env, owner = resolved
            self.audit_keys(audit_dir, public_dir, owner)
            self.policy_and_runtime(policy_dir, gateway_env, owner)
        if docker_ready:
            self.network()
        return self.findings, self.repairs, self.stack_exists


def _create_empty(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)


def _recreate_command(layout: Layout, values: dict[str, str]) -> str:
    command = _compose_command(layout)
    if layout.kind == "quickstart":
        namespace = values.get("QUICKSTART_NAMESPACE")
        if namespace:
            command[2:2] = ["-p", namespace]
        command.extend(
            [
                "up",
                "-d",
                "--wait",
                "--pull",
                "never",
                "--force-recreate",
                "gateway",
                "verifier",
            ]
        )
    else:
        command.extend(["up", "-d", "--wait", "--force-recreate", "gateway", "verifier"])
    return shlex.join(command)


def _summary(findings: list[dict[str, Any]], *, restart_required: bool) -> dict[str, Any]:
    counts = {
        status: sum(item["status"] == status for item in findings)
        for status in ("PASS", "INFO", "WARN", "ERROR", "FIXED")
    }
    return {
        **counts,
        "healthy": counts["ERROR"] == 0,
        "restart_required": restart_required,
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    layout = _discover(args.deployment_dir)
    initial = _Scan(layout, args.timeout, repairs=args.fix)
    findings, repairs, stack_exists = initial.run()
    fixed: list[dict[str, Any]] = []
    restart_required = False
    if args.fix and repairs:
        if args.json and not args.yes:
            raise DoctorError("doctor --fix requires --yes with --json")
        if not args.yes:
            print("Planned safe repairs:")
            for repair in repairs:
                print(f"  - {repair.message}")
            if builtins.input("Apply these repairs? [y/N] ").strip().lower() not in {"y", "yes"}:
                raise DoctorError("cancelled")
        for repair in repairs:
            try:
                repair.apply()
            except Exception as exc:
                fixed.append(
                    _finding(
                        repair.finding_id,
                        "ERROR",
                        f"repair failed: {exc}",
                        action=repair.message,
                    )
                )
            else:
                fixed.append(
                    _finding(
                        repair.finding_id,
                        "FIXED",
                        repair.message,
                    )
                )
                restart_required = restart_required or (repair.restart and stack_exists)
        final_scan = _Scan(layout, args.timeout, repairs=False)
        findings, _, _ = final_scan.run()
        values = final_scan.values
    else:
        values = initial.values
    if restart_required:
        command = _recreate_command(layout, values)
        findings.append(
            _finding(
                "runtime.recreate_required",
                "ERROR",
                "existing Compose runtime may still use configuration changed by --fix",
                action=command,
            )
        )
    else:
        command = ""
    all_findings = [*fixed, *findings]
    return {
        "deployment": {"kind": layout.kind, "root": str(layout.root)},
        "findings": all_findings,
        "summary": _summary(all_findings, restart_required=restart_required),
        "commands": {"recreate": command},
    }


def human(result: dict[str, Any]) -> str:
    lines = [
        f"PortunusMCP doctor: {result['deployment']['kind']} at {result['deployment']['root']}"
    ]
    for finding in result["findings"]:
        lines.append(f"{finding['status']:5} {finding['id']}: {finding['message']}")
        if finding["action"]:
            lines.append(f"      action: {finding['action']}")
    summary = result["summary"]
    lines.append(
        "Summary: "
        + ", ".join(
            f"{status}={summary[status]}" for status in ("PASS", "INFO", "WARN", "ERROR", "FIXED")
        )
    )
    if summary["restart_required"]:
        lines.append(f"Recreate: {result['commands']['recreate']}")
    return "\n".join(lines)
