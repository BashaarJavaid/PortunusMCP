# ADR-008: Journal operator mutations before atomic promotion

**Status:** Accepted  
**Date:** 2026-07-27

## Context

Policy rollout, rollback, and audit-key rotation change both durable files and in-memory security state. An ordinary “write file, then swap memory, then audit” sequence can crash between steps and leave the audit trail, active file, and running process disagreeing. Audit-key rotation also has to preserve verification of every historical row.

The supported deployment remains one gateway process. A distributed writer or cross-host transaction protocol is outside item 42.

## Decision

Use one process-local lock and one small fsynced JSON journal per mutation class.

Policy mutation stages exact candidate bytes, records the revision, appends a `POLICY_ACTIVATED` handoff under the old policy, atomically replaces `policy.yaml`, swaps memory, then removes the journal. SIGHUP consumes adjacent `policy.next.yaml` through this same path. Startup discards work with no audit handoff and completes work whose handoff is present.

Audit-key rotation generates a new P-256 key, archives its public key under its SHA-256 DER-SPKI fingerprint, appends an old-key-signed `AUDIT_KEY_ROTATED` handoff naming both fingerprints, atomically replaces the active private key, swaps memory, then removes the journal. Public keys are append-only. Each audit row records its signing `key_id`.

After an audited handoff, failure to promote marks that subsystem unavailable: policy readiness fails and MCP returns 503, or audit signing fails closed for all audited actions, until startup recovery. Before the handoff, staged private/policy material is discarded; an unused archived public key may remain.

## Consequences

- A committed audit handoff is the recovery boundary; durable files converge to it on restart.
- Rollback is durable rather than an in-memory exception.
- Historical signatures remain independently verifiable across rotations.
- Production mounts one writable policy root and one writable audit-key root into the gateway; the verifier sees only the public-key subdirectory.
- This does not make multiple gateway writers safe. The experimentally confirmed two-writer chain fork and all true horizontal scaling work remain deferred.
