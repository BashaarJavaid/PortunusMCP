# ADR-003 — Redis for session/replay/rate-limit state, not Postgres

**Status:** Accepted

**Decision:** Use Redis for replay-nonce tracking, per-identity tool-call and source-auth-failure rate counters, session idle-timeout TTLs, the cached `latest_audit_hash` chain pointer, risk-decay calibration counters, and one-time step-up challenges. The production Compose profile enables AOF with `appendfsync everysec`; demo/test Redis remains disposable.

**Reasoning:** This state is high-churn and mostly short-TTL. Its correctness posture already fails closed while Redis is unavailable, but losing recent state across a routine container replacement unnecessarily drops nonce, rate, session, and challenge history. AOF reduces that operational loss window without promoting Redis to the durability-critical system of record; `everysec` can still lose roughly one second after a host failure. PostgreSQL remains the durable store for the signed audit chain, baselines, policy versions, approvals, and verifier checkpoint.

**Alternatives considered:** Keeping all high-churn state in Postgres alongside the audit log; ephemeral production Redis; `appendfsync always`. Redis does not make the gateway stateless: session objects and Docker container handles remain in memory, and the audit chain still has one safe writer, so production is explicitly one gateway replica.
