"""Environment-driven settings for the gateway."""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Defaults are local-dev only; docker-compose.yml / .env override them.
    database_url: str = "postgresql+asyncpg://portunusmcp:portunusmcp@localhost:5432/portunusmcp"
    redis_url: str = "redis://localhost:6379/0"
    policy_file: str = "policies/example-policy.yaml"
    # Append-only revision snapshots written on every policy activation (§4.8, item 19).
    policy_revisions_dir: str = "policies/revisions"
    schema_cache_ttl: int = 600
    session_idle_ttl: int = 300
    shutdown_grace_seconds: int = 5
    max_mcp_body_bytes: int = Field(default=1048576, gt=0)
    max_json_depth: int = Field(default=32, gt=0)
    max_sessions_per_identity: int = Field(default=3, gt=0)
    max_inflight_calls_per_identity: int = Field(default=5, gt=0)
    tool_call_rate_limit: int = Field(default=60, gt=0)
    tool_call_rate_window_seconds: int = Field(default=60, gt=0)
    tool_call_deadline_seconds: int = Field(default=60, gt=0)
    readiness_timeout_seconds: float = Field(default=1.0, gt=0)
    allowed_hosts: list[str] = ["localhost:*", "127.0.0.1:*"]
    allowed_origins: list[str] = []
    # Half-width of the Replay Guard's accepted timestamp window (±30s, §4.8).
    replay_window_seconds: int = 30
    # Audit-log ECDSA keypair (§4.8): minted via scripts/generate_signing_key.py.
    # A gateway with no usable private key must not start (§5, fail closed).
    signing_key_file: str = "secrets/audit_signing_key.pem"
    signing_public_key_file: str = "secrets/audit_signing_key.pub.pem"
    # Risk Engine v1 (§4.8, item 16). Business hours are Mon-Fri in UTC — v1 has no
    # per-identity timezone; a policy timezone field is a documented later extension.
    business_hours_start_utc: int = 9
    business_hours_end_utc: int = 18
    # Call-frequency factor: spike when > threshold calls per identity+tool in window.
    risk_freq_window_seconds: int = 60
    risk_freq_threshold: int = 10
    # Risk decay (§4.8): offset added per admin approval, behavioral factors only.
    # Capped and expiring (item 33) so rubber-stamp approvals can dampen behavioral
    # scoring but never permanently zero it.
    risk_decay_step: int = 5
    risk_decay_max: int = 10
    risk_decay_ttl_seconds: int = 2592000  # 30 days
    # Richer risk telemetry (§4.8, item 18). Prior-denial-rate: fires when an identity
    # collects more than this many DENY_* terminals within the window.
    risk_denial_window_seconds: int = 600
    risk_denial_threshold: int = 3
    # Auth-failure factor: one gateway-wide counter of failed API-key lookups; fires
    # for every identity while more than this many failures sit within the window.
    risk_auth_failure_window_seconds: int = 300
    risk_auth_failure_threshold: int = 5
    # Drift-history factor: fires when a tool has this many DRIFT_* audit events in
    # the window, even if re-approved ("changed shape twice in the last week").
    risk_drift_history_window_seconds: int = 604800
    risk_drift_history_threshold: int = 2
    # Severity of a description-only change (item 36a). The description is the LLM
    # attack surface, so a change after human approval blocks by default (>= high
    # blocks until re-approval); "low" restores the old log-only posture. An invalid
    # value fails startup — fail closed on authoring mistakes (§5).
    drift_description_severity: Literal["low", "medium", "high", "critical"] = "high"
    # Human approval lifecycle (§4.8): pending approvals expire after this TTL.
    approval_ttl_seconds: int = 900
    # Step-up auth (item 37): pending challenges live in Redis for this long; the
    # human just needs time to read a code off their authenticator app. TOTP
    # step/digits/skew are RFC 6238 spec constants in step_up.py, not knobs.
    step_up_ttl_seconds: int = 300
    # Prometheus scrape port (§7, item 25) — a separate internal-only listener,
    # never the published app port (labels carry identity ids and tool names).
    # The verifier sidecar sets its own via METRICS_PORT in compose.
    metrics_port: int = 9100
    # Bind address for that listener. Loopback by default so a gateway run directly
    # on a host does not expose identity ids and tool names on every interface;
    # compose sets METRICS_HOST=0.0.0.0, where container network isolation (the port
    # is deliberately not published) is the boundary instead.
    metrics_host: str = "127.0.0.1"


settings = Settings()
