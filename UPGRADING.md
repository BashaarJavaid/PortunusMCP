# Upgrading to v0.1.0

## Unreleased configuration requirement

Production deployments upgrading to a build with item 49 must add
`ENFORCEMENT_MODE=enforce` to `.env.prod` before rendering Compose; the production
profile intentionally refuses a missing value. `observe` is an explicit audit-only
choice that forwards would-be policy, replay, drift, risk, and validation denials.

Mode changes require recreating/restarting the gateway. Policy rollout, rollback, and
SIGHUP do not change the process-wide mode. No database migration is added.

v0.1.0 supports persisted production-profile state from the `phase-6` tip
(`95e04cf7e5a2261b4b7d8ac0870fca8948c90cde`) and the pre-release `phase-6.1` tip
(`dbec74ec3a7f27a5b31c16372613ec4178dee523`). Earlier phase/demo state is not a
supported production upgrade source.

The expected Alembic head before and after this upgrade is `0007`. The release changes
runtime correctness and packaging, not the database schema.

## Before upgrading

1. Stop client traffic and verify the existing audit chain.
2. Stop the old Compose project without deleting volumes.
3. Snapshot the PostgreSQL and Redis volumes, policy directory, audit signing-key
   directory, `.env.prod`, and `.env.prod.gateway`.
4. Keep that snapshot together: restoring only the database or only the signing keys can
   make a valid historical chain unverifiable.

## Upgrade

1. Download `portunusmcp-v0.1.0-production.tar.gz` and verify it against the attached
   `SHA256SUMS`.
2. Copy the existing secrets, paths, namespace, allowlists, and policy-referenced
   variables into the bundled env examples. Keep the bundle's tested image digests.
3. Render and pull the exact profile:

   ```bash
   docker compose --env-file .env.prod -f compose.prod.yml config
   docker compose --env-file .env.prod -f compose.prod.yml pull
   docker compose --env-file .env.prod -f compose.prod.yml up -d
   ```

   The one-shot `migrate` service runs `alembic upgrade head` before the gateway and
   verifier start.
4. Require `GET /ready` to return 200, make one authorized tool call, then independently
   verify the complete audit chain.

## Rollback

Do not run an in-place Alembic downgrade. Stop v0.1.0 and restore the complete
pre-upgrade snapshot—database, Redis, policy, keys, env files, and old image references—
as one unit. Verify the restored audit chain before reopening traffic.
