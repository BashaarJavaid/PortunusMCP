# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-27

### Added

- Identity-scoped MCP tool visibility with RBAC, ABAC, schema-drift enforcement,
  deterministic risk decisions, approvals, step-up authentication, and replay-resistant
  signed identities.
- Tamper-evident ECDSA-signed audit chain with independent verification, exports, policy
  simulation, decision explanation, policy rollback, and signing-key rotation.
- Per-session hardened Docker isolation for registered upstream servers.
- Hardened single-replica production Compose profile with PostgreSQL 16, Redis 7,
  migrations, readiness checks, verifier sidecar, and optional Prometheus/Grafana.
- Installed `portunusmcp` operator CLI for policy, approval, baseline, audit, and key
  operations.

### Changed

- Documented tested bearer compatibility for Cursor 3.13.10 and MCP Python SDK 1.28.1;
  Claude Desktop 1.20186.0 cannot attach the required bearer header.

### Fixed

- Applied schema-drift severity recursively through nested object and array schemas.
- Rebuilt the Redis audit-chain pointer from authoritative PostgreSQL state after pointer
  write failures, preventing a transient cache failure from forking the chain.

### Security

- Added fail-closed identity/key collision validation, source-scoped authentication
  throttling, bounded request/session/call lifecycles, and description-drift integrity.

### Upgrade

- See [UPGRADING.md](./UPGRADING.md) for supported `phase-6` and `phase-6.1` upgrades.

[Unreleased]: https://github.com/BashaarJavaid/PortunusMCP/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/BashaarJavaid/PortunusMCP/releases/tag/v0.1.0
