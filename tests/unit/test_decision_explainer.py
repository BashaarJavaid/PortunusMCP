"""Unit tests for the Decision Explanation module (item 20): audit-row → Decision
reconstruction (new rows with payload matched_rules and legacy rows without), the
`alternative` threshold rule, context.hour precedence, and the explain_call dry-run
pipeline against fakes. Redis/Postgres-backed parity runs in the integration suite."""

from datetime import UTC, datetime
from typing import Any

import pytest

from services.gateway.db import AuditLog
from services.gateway.decision import DecisionMode, DecisionOutcome, EventType, RiskFactor
from services.gateway.decision_explainer import (
    _alternative,
    _context_hour,
    explain_call,
    from_audit_row,
)
from services.gateway.policy_engine import Identity, PolicyEngine, PolicyFile, ServerGrant

FACTORS = [
    {"factor": "protected_repository", "contribution": 30, "reason": "repo matches"},
    {"factor": "business_hours", "contribution": 25, "reason": "off-hours"},
]


def row(**overrides: Any) -> AuditLog:
    defaults: dict[str, Any] = {
        "seq": 42,
        "identity_id": "agent",
        "tool_name": "delete_repo",
        "policy_version": 7,
        "event_type": EventType.DENY_RISK.value,
        "risk_score": None,
        "payload": {},
    }
    return AuditLog(**{**defaults, **overrides})


def test_deny_row_with_persisted_payload_is_faithful() -> None:
    decision = from_audit_row(
        row(
            event_type=EventType.DENY_ABAC.value,
            risk_score=74,
            payload={
                "reason": "condition 'risk.score < 60' not satisfied",
                "matched_rules": ["policy-v7:abac:risk.score < 60"],
                "risk_factors": FACTORS,
            },
        )
    )
    assert decision.decision is DecisionOutcome.DENY
    assert decision.event_type is EventType.DENY_ABAC
    assert decision.reason == "condition 'risk.score < 60' not satisfied"
    assert decision.matched_rules == ["policy-v7:abac:risk.score < 60"]
    assert decision.risk_score == 74
    assert decision.risk_factors is not None
    assert decision.risk_factors[0].reason == "repo matches"
    assert decision.policy_version == 7
    assert decision.audit_id == "42"
    # Score 74 maps to the 70-90 band; the actual outcome was an ABAC deny.
    assert decision.alternative is DecisionOutcome.HUMAN_APPROVAL_REQUIRED


def test_challenge_row() -> None:
    decision = from_audit_row(
        row(
            event_type=EventType.CHALLENGE.value,
            risk_score=55,
            payload={"reason": "risk score 55 requires confirmation", "risk_factors": FACTORS},
        )
    )
    assert decision.decision is DecisionOutcome.CHALLENGE
    # The score itself drove the outcome — no alternative.
    assert decision.alternative is None
    assert decision.matched_rules == ["risk_engine"]  # legacy fallback


def test_allow_row() -> None:
    decision = from_audit_row(
        row(
            event_type=EventType.ALLOW.value,
            risk_score=10,
            payload={"arguments": {}, "matched_rules": ["policy-v7:rbac"]},
        )
    )
    assert decision.decision is DecisionOutcome.ALLOW
    assert decision.matched_rules == ["policy-v7:rbac"]
    assert decision.alternative is None


def test_deny_step_up_row_is_a_decision() -> None:
    decision = from_audit_row(
        row(
            event_type=EventType.DENY_STEP_UP.value,
            payload={
                "reason": "step-up verification failed: TOTP proof is invalid",
                "matched_rules": ["step_up"],
            },
        )
    )
    assert decision.decision is DecisionOutcome.DENY
    assert decision.event_type is EventType.DENY_STEP_UP
    assert decision.matched_rules == ["step_up"]


def test_legacy_rbac_deny_reconstructs_rules_and_reason() -> None:
    decision = from_audit_row(row(event_type=EventType.DENY_RBAC.value, payload={}))
    assert decision.mode is DecisionMode.ENFORCE
    assert decision.matched_rules == ["policy-v7:rbac"]
    assert "DENY_RBAC" in decision.reason
    assert decision.alternative is None  # no score, no alternative


@pytest.mark.parametrize(
    "event_type",
    ["SESSION_START", "TOOLS_LIST", "DRIFT_HIGH", "POLICY_ACTIVATED", "POLICY_ERROR"],
)
def test_non_decision_rows_raise(event_type: str) -> None:
    with pytest.raises(LookupError, match="not a decision"):
        from_audit_row(row(event_type=event_type))


def test_alternative_rule() -> None:
    assert _alternative(DecisionOutcome.DENY, None) is None
    assert _alternative(DecisionOutcome.DENY, 74) is DecisionOutcome.HUMAN_APPROVAL_REQUIRED
    assert _alternative(DecisionOutcome.DENY, 95) is None  # mapping equals the outcome
    assert _alternative(DecisionOutcome.HUMAN_APPROVAL_REQUIRED, 74) is None
    assert _alternative(DecisionOutcome.ALLOW, 12) is None


def test_context_hour_precedence() -> None:
    five_am = datetime(2026, 7, 8, 5, 30, tzinfo=UTC).timestamp()
    assert _context_hour({"hour": 23, "timestamp": five_am}) == 23  # explicit hour wins
    assert _context_hour({"timestamp": five_am}) == 5
    assert _context_hour({"hour": True, "timestamp": five_am}) == 5  # bool is not an hour
    assert _context_hour({}) == datetime.now(UTC).hour


# --- explain_call against fakes (no Redis/Postgres) ---


class FakeDetector:
    def __init__(self, blocked: bool = False) -> None:
        self.blocked = blocked

    async def is_blocked(self, server_id: str, tool_name: str) -> bool:
        return self.blocked


class FakeRisk:
    def __init__(self, score: int = 0, factors: list[RiskFactor] | None = None) -> None:
        self.score_value, self.factors = score, factors or []

    async def score(self, *args: Any, dry_run: bool = False) -> tuple[int, list[RiskFactor]]:
        assert dry_run, "explain must never live-score"
        return self.score_value, self.factors


class FakeCache:
    def __init__(self, tools: list[dict[str, Any]] | None) -> None:
        self.tools = tools

    async def get(self, server_id: str) -> list[dict[str, Any]] | None:
        return self.tools


def make_engine(conditions: list[str] | None = None) -> PolicyEngine:
    policy = PolicyFile(
        version=7,
        identities=[
            Identity(
                id="agent",
                api_key_hash="sha256:unused",
                allowed_servers=[
                    ServerGrant(server_id="*", allowed_tools=["echo"], conditions=conditions or [])
                ],
                attributes={"team": "dev"},
            )
        ],
    )
    return PolicyEngine(policy)


ECHO_TOOLS = [{"name": "echo", "inputSchema": {"type": "object", "properties": {}}}]


async def explain(
    identity: str = "agent",
    tool: str = "echo",
    arguments: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    *,
    engine: PolicyEngine | None = None,
    detector: FakeDetector | None = None,
    risk: FakeRisk | None = None,
    cache: FakeCache | None = None,
    mode: DecisionMode = DecisionMode.ENFORCE,
) -> Any:
    return await explain_call(
        identity,
        tool,
        "default",
        arguments or {},
        context or {},
        engine=engine or make_engine(),
        detector=detector or FakeDetector(),  # type: ignore[arg-type]
        risk=risk or FakeRisk(),  # type: ignore[arg-type]
        schema_cache=cache or FakeCache(ECHO_TOOLS),  # type: ignore[arg-type]
        mode=mode,
    )


async def test_explain_rbac_deny() -> None:
    decision = await explain(identity="nobody")
    assert decision.decision is DecisionOutcome.DENY
    assert decision.event_type is EventType.DENY_RBAC
    assert decision.matched_rules == ["policy-v7:rbac"]
    assert decision.audit_id is None


async def test_explain_abac_deny_uses_context_hour() -> None:
    engine = make_engine(conditions=["context.hour < 18"])
    decision = await explain(context={"hour": 23}, engine=engine)
    assert decision.event_type is EventType.DENY_ABAC
    assert "context.hour < 18" in decision.matched_rules[0]
    allowed = await explain(context={"hour": 9}, engine=engine)
    assert allowed.decision is DecisionOutcome.ALLOW


async def test_explain_drift_block() -> None:
    decision = await explain(detector=FakeDetector(blocked=True))
    assert decision.event_type is EventType.DENY_DRIFT


async def test_explain_risk_bands() -> None:
    approval = await explain(risk=FakeRisk(score=74))
    assert approval.decision is DecisionOutcome.HUMAN_APPROVAL_REQUIRED
    assert approval.approval_id is None  # dry run creates no approvals row
    challenge = await explain(risk=FakeRisk(score=55))
    assert challenge.decision is DecisionOutcome.CHALLENGE
    deny = await explain(risk=FakeRisk(score=95))
    assert deny.event_type is EventType.DENY_RISK
    assert deny.alternative is None


async def test_explain_risk_condition_deny_wins_over_threshold() -> None:
    engine = make_engine(conditions=["risk.score < 60"])
    decision = await explain(engine=engine, risk=FakeRisk(score=74))
    assert decision.event_type is EventType.DENY_ABAC
    assert decision.risk_score == 74
    assert decision.alternative is DecisionOutcome.HUMAN_APPROVAL_REQUIRED


async def test_explain_cold_cache_fails_closed() -> None:
    decision = await explain(cache=FakeCache(None))
    assert decision.event_type is EventType.DENY_VALIDATION
    assert "not cached" in decision.reason


async def test_explain_invalid_arguments() -> None:
    decision = await explain(arguments={"unknown_field": 1})
    assert decision.event_type is EventType.DENY_VALIDATION
    assert "unknown argument field" in decision.reason


async def test_observe_explain_keeps_first_blocker_and_adds_downstream_risk() -> None:
    factors = [RiskFactor(factor="example", contribution=50)]
    decision = await explain(
        identity="nobody",
        risk=FakeRisk(score=50, factors=factors),
        mode=DecisionMode.OBSERVE,
    )
    assert decision.mode is DecisionMode.OBSERVE
    assert decision.event_type is EventType.DENY_RBAC
    assert decision.risk_score == 50
    assert decision.risk_factors == factors
