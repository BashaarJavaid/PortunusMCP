"""Container-isolated stdio connection to an upstream MCP server (item 39).

The gateway attaches to `docker run -i` exactly as it previously attached to a child
process: stdin/stdout still carry SDK-framed newline-delimited JSON-RPC. Docker owns
the security boundary and resource limits; this module owns launch/preflight/cleanup.
"""

import asyncio
import os
import re
import shutil
from collections.abc import AsyncIterator
from dataclasses import dataclass

from mcp.types import JSONRPCMessage

from services.gateway.policy_engine import UpstreamServer

# readline() ceiling for a single JSON-RPC message from upstream (asyncio default is 64KB,
# too small for large tools/list responses).
_STREAM_LIMIT = 4 * 1024 * 1024
_NAMESPACE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_MANAGED_LABEL = "io.portunusmcp.managed=true"


class RuntimeError(Exception):
    """The local Docker runtime cannot enforce the configured upstream boundary."""


@dataclass
class ContainerProcess:
    process: asyncio.subprocess.Process
    name: str

    @property
    def returncode(self) -> int | None:
        return self.process.returncode

    async def wait(self) -> int:
        return await self.process.wait()


class DockerRuntime:
    def __init__(self, docker: str, host: str, namespace: str) -> None:
        self._docker = docker
        self._host = host
        self.namespace = namespace

    @classmethod
    async def create(cls, servers: dict[str, UpstreamServer]) -> "DockerRuntime":
        namespace = os.environ.get("UPSTREAM_RUNTIME_NAMESPACE", "")
        if not _NAMESPACE.fullmatch(namespace):
            raise RuntimeError(
                "UPSTREAM_RUNTIME_NAMESPACE is required and must match" " ^[a-z0-9][a-z0-9-]{0,31}$"
            )
        docker = shutil.which("docker")
        if docker is None:
            raise RuntimeError("docker CLI not found")
        probe = await asyncio.create_subprocess_exec(
            docker,
            "context",
            "inspect",
            "--format",
            "{{.Endpoints.docker.Host}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await probe.communicate()
        if probe.returncode != 0:
            raise RuntimeError(f"cannot inspect Docker context: {stderr.decode().strip()}")
        host = stdout.decode().strip()
        if not host.startswith("unix://"):
            raise RuntimeError("item 39 supports only a local Unix Docker socket")
        runtime = cls(docker, host, namespace)
        await runtime._run("version")
        await runtime.cleanup_orphans()
        await runtime.preflight(servers)
        return runtime

    async def _run(self, *args: str, check: bool = True) -> tuple[int, bytes, bytes]:
        process = await asyncio.create_subprocess_exec(
            self._docker,
            "--host",
            self._host,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={},
        )
        stdout, stderr = await process.communicate()
        if check and process.returncode != 0:
            detail = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"docker {' '.join(args[:2])} failed: {detail}")
        return process.returncode or 0, stdout, stderr

    async def cleanup_orphans(self) -> None:
        _, stdout, _ = await self._run(
            "ps",
            "-aq",
            "--filter",
            f"label={_MANAGED_LABEL}",
            "--filter",
            f"label=io.portunusmcp.namespace={self.namespace}",
        )
        containers = stdout.decode().split()
        if containers:
            await self._run("rm", "-f", *containers)

    async def preflight(self, servers: dict[str, UpstreamServer]) -> None:
        expected_volume_prefix = f"portunusmcp-upstream-{self.namespace}-"
        for server_id, server in servers.items():
            await self._run("image", "inspect", server.image)
            for mount in server.volumes:
                if not mount.source.startswith(expected_volume_prefix):
                    raise RuntimeError(
                        f"server {server_id!r} volume {mount.source!r} must start with"
                        f" {expected_volume_prefix!r}"
                    )
                await self._run("volume", "inspect", mount.source)

    async def spawn(
        self, server: UpstreamServer, session_id: str, server_id: str
    ) -> ContainerProcess:
        name = f"{self.namespace}-upstream-{session_id}"
        resources = server.resources
        args = [
            self._docker,
            "--host",
            self._host,
            "run",
            "--rm",
            "-i",
            "--init",
            "--pull",
            "never",
            "--name",
            name,
            "--label",
            _MANAGED_LABEL,
            "--label",
            f"io.portunusmcp.namespace={self.namespace}",
            "--label",
            f"io.portunusmcp.session={session_id}",
            "--label",
            f"io.portunusmcp.server={server_id}",
            "--user",
            "65532:65532",
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16m",
            "--memory",
            f"{resources.memory_mb}m",
            "--memory-swap",
            f"{resources.memory_mb}m",
            "--cpus",
            str(resources.cpus),
            "--pids-limit",
            str(resources.pids),
            "--network",
            server.network,
        ]
        for mount in server.volumes:
            args.extend(
                [
                    "--mount",
                    f"type=volume,src={mount.source},dst={mount.target},readonly",
                ]
            )
        for name_in_container in server.resolved_environment:
            args.extend(["--env", name_in_container])
        args.extend([server.image, *server.command])
        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,
            limit=_STREAM_LIMIT,
            env=server.resolved_environment,
        )
        container = ContainerProcess(process=process, name=name)
        for _ in range(50):
            if container.returncode is not None:
                raise RuntimeError(
                    f"upstream container {server_id!r} exited during session creation"
                )
            status, _, _ = await self._run("inspect", name, check=False)
            if status == 0:
                return container
            await asyncio.sleep(0.05)
        await self.stop(container, 0)
        raise RuntimeError(f"upstream container {server_id!r} did not start")

    async def stop(self, container: ContainerProcess, grace_seconds: int) -> None:
        if container.returncode is None:
            await self._run(
                "stop",
                "--time",
                str(grace_seconds),
                container.name,
                check=False,
            )
        try:
            await asyncio.wait_for(container.wait(), timeout=grace_seconds + 2)
        except TimeoutError:
            await self._run("rm", "-f", container.name, check=False)
            try:
                await asyncio.wait_for(container.wait(), timeout=2)
            except TimeoutError:
                container.process.kill()
                await container.wait()


def encode(message: JSONRPCMessage) -> bytes:
    return (message.model_dump_json(by_alias=True, exclude_none=True) + "\n").encode()


async def read_messages(process: ContainerProcess) -> AsyncIterator[JSONRPCMessage]:
    assert process.process.stdout is not None
    while line := await process.process.stdout.readline():
        yield JSONRPCMessage.model_validate_json(line)


async def write_message(process: ContainerProcess, message: JSONRPCMessage) -> None:
    assert process.process.stdin is not None
    process.process.stdin.write(encode(message))
    await process.process.stdin.drain()
