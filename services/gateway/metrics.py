"""Prometheus metrics (ARCHITECTURE.md §7, ROADMAP items 25 and 43).

Exactly the §7-prescribed set, no more. Definitions only — increments live at the
interceptor's three terminal emission points, the Drift Detector's classification
writes, the audit verifier's failure branch, and source auth throttling. Served via
start_http_server on a separate internal-only port (settings.metrics_port), never on
the published app port: labels carry identity ids and tool names, and the §7 posture
is an unauthenticated endpoint unreachable from outside the compose network.
"""

from prometheus_client import Counter, Histogram

TOOL_CALLS = Counter(
    "portunusmcp_tool_calls",
    "Terminal tools/call decisions, labeled with the audit event type",
    ["identity", "server", "tool", "decision"],
)

SCHEMA_DRIFT = Counter(
    "portunusmcp_schema_drift",
    "Schema drift events by classified severity",
    ["server", "tool", "severity"],
)

RISK_SCORE = Histogram(
    "portunusmcp_risk_score",
    "Risk Engine scores for freshly scored tools/call requests",
    buckets=(10, 20, 30, 40, 50, 60, 70, 80, 90, 100),
)

REQUEST_LATENCY = Histogram(
    "portunusmcp_request_latency_seconds",
    "Gateway decision-pipeline time per tools/call (proxy overhead, excludes upstream)",
)

AUDIT_VERIFY_FAILURES = Counter(
    "portunusmcp_audit_chain_verify_failures",
    "Audit rows failing chain linkage, chain math, or signature verification",
)

REPLAY_DENIED = Counter(
    "portunusmcp_replay_denied",
    "tools/call requests denied by the Replay Guard",
)

AUTH_THROTTLED = Counter(
    "portunusmcp_auth_throttled",
    "Presented MCP or admin credentials blocked by the source auth-failure limiter",
)
