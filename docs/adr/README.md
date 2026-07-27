# Architecture Decision Records

One file per consequential architecture decision. Load the specific ADR relevant to what you're working on rather than all of them.

- [`ADR-001-fastapi.md`](./ADR-001-fastapi.md) — FastAPI over Flask/Django
- [`ADR-002-postgres-vs-dynamodb.md`](./ADR-002-postgres-vs-dynamodb.md) — PostgreSQL over DynamoDB
- [`ADR-003-redis.md`](./ADR-003-redis.md) — Redis state and production AOF posture
- [`ADR-004-no-opa-for-v1.md`](./ADR-004-no-opa-for-v1.md) — No OPA/Rego/Cedar for v1 (auditability-first reasoning)
- [`ADR-005-no-kubernetes-for-v1.md`](./ADR-005-no-kubernetes-for-v1.md) — Single-replica Compose, no cloud orchestrator for v1
- [`ADR-006-why-not-alternatives.md`](./ADR-006-why-not-alternatives.md) — Why not Envoy / NGINX / Kong / sidecars / client-SDK middleware
