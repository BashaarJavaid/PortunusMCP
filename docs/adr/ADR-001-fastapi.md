# ADR-001 — FastAPI over Flask/Django

**Status:** Accepted

**Decision:** Use FastAPI (async-native) as the gateway's web/proxy framework.

**Reasoning:** The gateway is fundamentally I/O-bound — most of its time is spent waiting on upstream MCP servers (stdio-attached containers or future network transports), Redis, and Postgres. Flask would need an async extension bolted on to handle this well; Django brings ORM/admin machinery this project doesn't use and adds framework weight without a corresponding benefit for a proxy service with no server-rendered pages or admin panel in the traditional Django sense.

**Alternatives considered:** Flask (+async extensions), Django, a bare ASGI app with no framework.
