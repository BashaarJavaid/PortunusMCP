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
