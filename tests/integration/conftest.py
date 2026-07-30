import asyncio
import hashlib
import os
import secrets
import shlex
import socket
import sys
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import uvicorn
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from mcp import ClientSession
from mcp.types import NotificationParams, PaginatedRequestParams, RequestParams

from scripts.reset_dev_state import ResetError, reset_dev_state
from services.gateway import auth, upstream_client
from services.gateway.config import settings
from services.gateway.db import engine
from services.gateway.decision import DecisionMode
from services.gateway.main import app
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY

ECHO_SERVER = Path(__file__).parent / "fixtures" / "echo_server.py"

SIGNED_SECRET_ENV = "PORTUNUSMCP_TEST_SIGNING_SECRET"


def server_spec(command: str, image: str = "portunusmcp:dev") -> dict[str, object]:
    return {"image": image, "command": shlex.split(command)}


class LocalRuntime:
    """Fast test-only launcher; production has no local-process setting or fallback."""

    namespace = "test"

    async def preflight(self, servers: object) -> None:
        pass

    async def spawn(
        self, server: object, session_id: str, server_id: str
    ) -> upstream_client.ContainerProcess:
        command = server.command  # type: ignore[attr-defined]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            limit=4 * 1024 * 1024,
            env=os.environ.copy(),
        )
        return upstream_client.ContainerProcess(process=process, name=f"local-{session_id}")

    async def stop(self, container: upstream_client.ContainerProcess, grace_seconds: int) -> None:
        if container.returncode is None:
            container.process.terminate()
            try:
                await asyncio.wait_for(container.wait(), timeout=grace_seconds)
            except TimeoutError:
                container.process.kill()
                await container.wait()


class SignedSession(ClientSession):
    """ClientSession for a `signed` identity (item 34): every outgoing request AND
    notification carries key id, nonce/timestamp, and an HMAC over the canonical
    tuple in params._meta — the wire format a custom signing client implements.
    (Client→server *responses* — server-initiated sampling — are not signed; the
    echo/rogue upstreams never send them.)"""

    def __init__(self, *args: Any, key_id: str, secret: bytes, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._key_id = key_id
        self._secret = secret

    def _sign(self, root: Any) -> None:
        nonce, timestamp = str(uuid.uuid4()), int(time.time())
        params = root.params
        if root.method == "tools/call":
            tool, arguments = params.name, params.arguments
        else:
            tool, arguments = None, None
        signature = auth.sign_request(self._secret, nonce, timestamp, root.method, tool, arguments)
        meta = {
            NONCE_META_KEY: nonce,
            TIMESTAMP_META_KEY: timestamp,
            auth.KEY_ID_META_KEY: self._key_id,
            auth.SIGNATURE_META_KEY: signature,
        }
        if params is None:
            cls = (
                NotificationParams
                if root.method.startswith("notifications/")
                else PaginatedRequestParams
            )
            root.params = cls.model_validate({"_meta": meta})
        else:
            params.meta = RequestParams.Meta.model_validate(meta)

    async def send_request(self, request: Any, result_type: Any, **kwargs: Any) -> Any:
        self._sign(request.root)
        return await super().send_request(request, result_type, **kwargs)

    async def send_notification(self, notification: Any, **kwargs: Any) -> None:
        self._sign(notification.root)
        await super().send_notification(notification, **kwargs)


@pytest.fixture
async def clean_audit() -> None:
    """Skip unless postgres + redis are reachable; start each test from an empty,
    consistent chain via the shared item-38 reset. Snapshots stay untouched — the
    per-test revisions dir is only patched in later, by running_gateway."""
    # Each test runs in a fresh event loop; drop connections pooled under the old one.
    await engine.dispose()
    try:
        await reset_dev_state(clear_snapshots=False)
    except ResetError as exc:
        pytest.skip(str(exc))


@dataclass
class Gateway:
    url: str
    keys: dict[str, str]  # identity id -> raw API key
    policy_path: Path


def _key_hash(key: str) -> str:
    return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


def policy_dict(
    keys: dict[str, str], readonly_tools: list[str] | None = None, version: int = 1
) -> dict:
    return {
        "version": version,
        "servers": {"default": server_spec(f"{sys.executable} {ECHO_SERVER}")},
        "identities": [
            {
                "id": "agent-readonly",
                "api_key_hash": _key_hash(keys["agent-readonly"]),
                "allowed_servers": [
                    {"server_id": "default", "allowed_tools": readonly_tools or ["echo"]}
                ],
            },
            {
                "id": "agent-full",
                "api_key_hash": _key_hash(keys["agent-full"]),
                "admin": True,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }


def write_signing_keypair(directory: Path) -> tuple[Path, Path]:
    """Per-run audit signing keypair — never a checked-in key (§4.8)."""
    key = ec.generate_private_key(ec.SECP256R1())
    private_path = directory / "audit_signing_key.pem"
    public_path = directory / "audit_signing_key.pub.pem"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private_path, public_path


@asynccontextmanager
async def running_gateway(
    policy_path: Path,
    upstream_command: str,
    keys: dict[str, str],
    *,
    isolate_upstreams: bool = False,
    mode: DecisionMode = DecisionMode.ENFORCE,
) -> AsyncIterator[Gateway]:
    """The gateway app on an ephemeral port with the given policy file and upstream.
    A policy without a `servers:` block (the single-server fixtures) gets the given
    command registered as "default" — item 35's registry, transparently."""
    policy = yaml.safe_load(policy_path.read_text())
    if "servers" not in policy:
        policy["servers"] = {"default": server_spec(upstream_command)}
        policy_path.write_text(yaml.safe_dump(policy))
    elif any(isinstance(server, str) for server in policy["servers"].values()):
        policy["servers"] = {
            server_id: server_spec(server) if isinstance(server, str) else server
            for server_id, server in policy["servers"].items()
        }
        policy_path.write_text(yaml.safe_dump(policy))
    old_policy_file = settings.policy_file
    old_signing_key = settings.signing_key_file
    old_signing_pub = settings.signing_public_key_file
    old_signing_pub_dir = settings.signing_public_keys_dir
    old_revisions_dir = settings.policy_revisions_dir
    old_enforcement_mode = settings.enforcement_mode
    settings.policy_file = str(policy_path)
    settings.policy_revisions_dir = str(policy_path.parent / "revisions")
    private_path, public_path = write_signing_keypair(policy_path.parent)
    settings.signing_key_file = str(private_path)
    settings.signing_public_key_file = str(public_path)
    settings.signing_public_keys_dir = str(policy_path.parent / "public")
    settings.enforcement_mode = mode

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    runtime = LocalRuntime()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    runtime_patch = (
        nullcontext()
        if isolate_upstreams
        else patch.object(
            upstream_client.DockerRuntime, "create", new=AsyncMock(return_value=runtime)
        )
    )
    with runtime_patch:
        task = asyncio.create_task(server.serve())
        while not server.started:
            if task.done():
                await task
                raise RuntimeError("gateway stopped during startup")
            await asyncio.sleep(0.05)

        try:
            yield Gateway(url=f"http://127.0.0.1:{port}", keys=keys, policy_path=policy_path)
        finally:
            settings.policy_file = old_policy_file
            settings.signing_key_file = old_signing_key
            settings.signing_public_key_file = old_signing_pub
            settings.signing_public_keys_dir = old_signing_pub_dir
            settings.policy_revisions_dir = old_revisions_dir
            settings.enforcement_mode = old_enforcement_mode
            server.should_exit = True
            await task


@pytest.fixture
async def gateway(clean_audit: None, tmp_path: Path) -> AsyncIterator[Gateway]:
    """Echo fixture upstream, with a policy file generated at runtime so no
    real-looking API keys ever land in the repo. Identities are plain `bearer` —
    every test on this fixture doubles as proof that a stock MCP client works."""
    keys = {
        "agent-readonly": secrets.token_urlsafe(32),
        "agent-full": secrets.token_urlsafe(32),
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy_dict(keys)))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


@dataclass
class SignedGateway:
    url: str
    key_id: str
    secret: bytes
    policy_path: Path


@pytest.fixture
async def signed_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[SignedGateway]:
    """Echo fixture upstream behind a single `signed` identity (item 34): the secret
    lives only in an env var; the policy YAML carries the key id + the var's name."""
    key_id = f"kid_{secrets.token_hex(8)}"
    secret = secrets.token_urlsafe(32)
    monkeypatch.setenv(SIGNED_SECRET_ENV, secret)
    policy = {
        "version": 1,
        "identities": [
            {
                "id": "ci-agent",
                "auth_mode": "signed",
                "key_id": key_id,
                "signing_secret_env": SIGNED_SECRET_ENV,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            }
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", {}) as gw:
        yield SignedGateway(
            url=gw.url, key_id=key_id, secret=secret.encode(), policy_path=policy_path
        )
