"""Item-39 integration probe: proves the upstream container boundary end to end."""

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("isolation-probe")


@mcp.tool()
def inspect_boundary() -> str:
    names = (
        "ALLOWED_MARKER",
        "DATABASE_URL",
        "REDIS_URL",
        "PORTUNUSMCP_GATEWAY_SENTINEL",
        "PORTUNUSMCP_TEST_SIGNING_SECRET",
        "PORTUNUSMCP_TEST_TOTP_SECRET",
    )
    return json.dumps(
        {
            "environment": {name: os.environ.get(name) for name in names},
            "uid": os.getuid(),
            "secrets_dir": Path("/app/secrets").exists(),
            "private_key": Path("/app/secrets/audit_signing_key.pem").exists(),
            "docker_socket": Path("/var/run/docker.sock").exists(),
        }
    )


@mcp.tool()
def exhaust_memory() -> str:
    chunks: list[bytearray] = []
    while True:
        chunks.append(bytearray(16 * 1024 * 1024))


if __name__ == "__main__":
    mcp.run()
