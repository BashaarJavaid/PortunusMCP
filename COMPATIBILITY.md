# Compatibility

This matrix is the supported surface for PortunusMCP v0.1.0. Exact release image
references and file hashes are recorded in the downloadable bundle's `release.json`.

| Component | Supported |
|---|---|
| Operator CLI | CPython 3.12.x (`>=3.12,<3.13`) |
| Container platform | Linux `amd64` and `arm64` |
| Docker host | Docker Engine 29.x with Docker Compose 5.x |
| macOS host | macOS arm64 with current Docker Desktop, Engine 29.x, and Compose 5.x |
| PostgreSQL | 16.x, using the v0.1.0 bundle's manifest digest |
| Redis | 7.x, using the v0.1.0 bundle's manifest digest |
| MCP Python SDK | 1.28.1 |
| MCP protocol | `2025-11-25` |
| Alembic head | `0007` |

The supported deployment is the bundled, single-host, single-gateway-replica production
Compose profile. Multiple gateway replicas, Kubernetes, remote network upstreams, and
in-place database downgrades are not supported in v0.1.0.

## Unreleased adoption path — 2026-07-29

The item-51 implementation candidate adds one devcontainer definition for default
2-core GitHub Codespaces on Linux amd64 and local VS Code Dev Containers on macOS
arm64. It pins the Python 3.12 Bookworm base image and Docker-in-Docker feature digest,
installs Moby Engine 29.6.2, and lets that feature resolve current Compose. The
post-create lifecycle runs the released quickstart proof within one 600-second budget
and reuses generated namespace, credentials, keys, and volumes on rebuild.

This is unreleased adoption evidence, not a change to the v0.1.0 support matrix above.
Required Codespaces evidence remains pending before roadmap item 51 can close.

Local editor acceptance passed on macOS 15.7.3 arm64 with VS Code 1.131.0,
Dev Containers 0.466.0 (CLI 0.88.0), Python 3.12.13, Moby 29.6.2-1, and Compose
5.3.1. From a fresh workspace it completed in 125.79 seconds (quickstart: 47.949
seconds), produced canonical `ALLOW` and `DENY_RBAC`, and passed doctor with 38
`PASS` findings. A true container rebuild completed in 18.75 seconds with namespace
`portunusmcp-quickstart-d97dd0ac` and credential-file SHA-256
`b785e354d8ff6cbc5b2c3faf67751fb292f39d723b97f3e0591251d5cc6b2dce`
unchanged; stop/resume restored `/ready` in 8 seconds without a post-start hook.
The earlier VS Code 1.99.3 / Dev Containers 0.422.1 runtime stalled before
`postCreateCommand`; upgrading the editor and extension resolved that compatibility
failure. Candidate and default-branch Codespaces acceptance remain open.

## Client evidence

Bearer mode requires a remote MCP client that can attach `X-PortunusMCP-Key`. The exact
Cursor, Python SDK, and Claude Desktop results and configuration are in the
[README compatibility table](./README.md#client-compatibility).

## Tested release candidates

| Date | Source | Host | Result |
|---|---|---|---|
| 2026-07-27 | Pre-tag `v0.1.0` candidate | macOS 15.7.3 arm64 / Docker Desktop 4.83.0, Engine 29.6.2, Compose 5.3.1 | Candidate image built; enforced suite passed (407 passed, one tag-artifact test skipped); extracted bundle smoke and persisted-state upgrades from both supported tips passed |

The final release workflow separately verifies the published bundle on a fresh Ubuntu
24.04 amd64 runner and checks that every bundled image digest contains both supported
platform manifests.
