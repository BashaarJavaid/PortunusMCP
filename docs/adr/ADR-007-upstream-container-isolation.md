# ADR-007 — Per-Session Container Isolation for Local Upstreams

**Status:** Accepted

**Decision:** Run every registered stdio upstream in a dedicated Docker container owned by its MCP session. The policy registry stores a typed container specification (`image`, required argv `command`, optional environment-source mappings, read-only named volumes, network mode, and resource limits); legacy command strings are rejected.

The gateway launches containers through the local Unix Docker socket with a minimal environment and these fixed controls: UID 65532, read-only root filesystem, `/tmp` as a 16 MiB `noexec,nosuid,nodev` tmpfs, init, `no-new-privileges`, all capabilities dropped, bounded memory/CPU/PIDs, and no swap beyond the memory limit. Network access defaults to `none`; `bridge` must be explicit. Images are never pulled at runtime. Named volumes must belong to the configured `UPSTREAM_RUNTIME_NAMESPACE`, are mounted read-only, and cannot target the gateway's secrets path or Docker socket.

Startup fails closed if the local daemon, a referenced image, or a referenced volume is unavailable. SIGHUP keeps the last-known-good policy on the same failure; rollback returns 409. A successful policy change disconnects only sessions whose runtime fingerprint changed. Containers are reaped on disconnect, shutdown, resource exhaustion, and startup orphan cleanup.

**Security boundary:** the Docker socket is root-equivalent access to the Docker host. This design isolates an upstream from gateway credentials; it does not isolate a user who gains a shell in the gateway container, because that user can control Docker through the mounted socket. The gateway and Docker host therefore remain one administrative trust domain.

**Why Docker CLI:** Docker is already the project's local deployment substrate. Calling its CLI keeps the implementation small, preserves exact runtime flags in tests, and avoids another daemon-client dependency.

**Alternatives considered:**

- **An in-process or same-container OS sandbox:** still shares too much of the gateway's environment and filesystem, and is less portable than the existing Docker requirement.
- **A persistent sidecar per upstream:** shares one server instance across sessions and complicates lifecycle/isolation without improving the local trust boundary.
- **Remote Streamable HTTP with mTLS/workload identity:** the right future design for remote upstreams, but a separate transport and identity project; explicitly deferred beyond v1.
- **Kubernetes Jobs/Pods:** adds an orchestrator the self-hosted Compose deployment does not otherwise require.
