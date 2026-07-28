"""Decision Explanation API internals (ARCHITECTURE.md §4.8, item 20).

Two entry points over the same canonical Decision shape (§4.3):

- from_audit_row: reconstruct the Decision a past audit row recorded. New rows
  carry matched_rules (and reason/risk_factors) in their payload; older rows fall
  back to a per-event-type reconstruction. Non-decision rows (SESSION_START,
  TOOLS_LIST, DRIFT_*, POLICY_ACTIVATED, POLICY_ERROR) raise LookupError — the
  endpoint answers 404 rather than bending the Decision shape around telemetry.

- explain_call: dry-run the §4.2 tools/call pipeline for a hypothetical call
  against the *current* in-memory policy. Same stage order and fail-closed logic
  as the live interceptor, minus the replay guard (no nonce/timestamp exists for
  a hypothetical call) and minus every side effect: no audit rows (including
  POLICY_ERROR), no approvals, no upstream re-fetch or forward, no Redis counter
  bumps (risk scoring runs dry_run=True).

The `alternative` field (§4.8 GET example) is the outcome the 40/70/90 threshold
mapping gives for risk_score, set only when that differs from the actual outcome
— e.g. an ABAC risk-condition deny at score 74 → "human_approval_required".
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from services.gateway import abac, param_validator
from services.gateway.db import AuditLog
from services.gateway.decision import Decision, DecisionMode, DecisionOutcome, EventType, RiskFactor
from services.gateway.drift_detector import DriftDetector
from services.gateway.policy_engine import PolicyEngine
from services.gateway.risk_engine import RiskEngine, threshold_outcome
from services.gateway.schema_cache import SchemaCache

logger = structlog.get_logger(__name__)

_OUTCOMES: dict[EventType, DecisionOutcome] = {
    EventType.ALLOW: DecisionOutcome.ALLOW,
    EventType.APPROVED: DecisionOutcome.ALLOW,
    EventType.DENY_RBAC: DecisionOutcome.DENY,
    EventType.DENY_ABAC: DecisionOutcome.DENY,
    EventType.DENY_REPLAY: DecisionOutcome.DENY,
    EventType.DENY_DRIFT: DecisionOutcome.DENY,
    EventType.DENY_RISK: DecisionOutcome.DENY,
    EventType.DENY_VALIDATION: DecisionOutcome.DENY,
    EventType.DENY_APPROVAL_MISMATCH: DecisionOutcome.DENY,
    EventType.DENY_STEP_UP: DecisionOutcome.DENY,
    EventType.EXPIRED: DecisionOutcome.DENY,
    EventType.CHALLENGE: DecisionOutcome.CHALLENGE,
    EventType.HUMAN_APPROVAL_REQUIRED: DecisionOutcome.HUMAN_APPROVAL_REQUIRED,
}

# Fallback matched_rules for rows written before item 20 persisted them in the
# payload — mirrors what the interceptor passed at each terminal.
_FALLBACK_RULES: dict[EventType, list[str]] = {
    EventType.DENY_REPLAY: ["replay_guard"],
    EventType.DENY_DRIFT: ["drift_detector"],
    EventType.DENY_RISK: ["risk_engine"],
    EventType.CHALLENGE: ["risk_engine"],
    EventType.HUMAN_APPROVAL_REQUIRED: ["risk_engine"],
    EventType.DENY_VALIDATION: ["param_validator"],
    EventType.DENY_APPROVAL_MISMATCH: ["approval_lifecycle"],
    EventType.EXPIRED: ["approval_lifecycle"],
    EventType.APPROVED: ["admin_approval"],
}


def _alternative(outcome: DecisionOutcome, risk_score: int | None) -> DecisionOutcome | None:
    if risk_score is None:
        return None
    mapped = threshold_outcome(risk_score)
    return mapped if mapped is not outcome else None


def from_audit_row(row: AuditLog) -> Decision:
    """Reconstruct the canonical Decision a past audit row recorded. Raises
    LookupError when the row's event type isn't a decision."""
    try:
        event_type = EventType(row.event_type)
    except ValueError:
        raise LookupError(f"audit row {row.seq} is not a decision") from None
    outcome = _OUTCOMES.get(event_type)
    if outcome is None:
        raise LookupError(f"audit row {row.seq} is not a decision")
    payload = row.payload or {}
    matched_rules = payload.get("matched_rules")
    if matched_rules is None:
        # Legacy rows: RBAC/ABAC denies referenced the policy version live; the
        # rest map straight from the deciding stage.
        if event_type is EventType.DENY_RBAC:
            matched_rules = [f"policy-v{row.policy_version}:rbac"]
        elif event_type is EventType.DENY_ABAC:
            matched_rules = [f"policy-v{row.policy_version}:abac"]
        elif event_type is EventType.ALLOW:
            matched_rules = [f"policy-v{row.policy_version}:rbac"]
        else:
            matched_rules = _FALLBACK_RULES[event_type]
    reason = payload.get("reason") or f"{event_type.value} recorded for {row.tool_name!r}"
    raw_factors = payload.get("risk_factors")
    risk_factors = (
        [RiskFactor.model_validate(f) for f in raw_factors] if raw_factors is not None else None
    )
    return Decision(
        decision=outcome,
        event_type=event_type,
        mode=DecisionMode(payload.get("mode", DecisionMode.ENFORCE)),
        reason=reason,
        matched_rules=list(matched_rules),
        risk_score=row.risk_score,
        risk_factors=risk_factors,
        policy_version=row.policy_version,
        audit_id=str(row.seq),
        alternative=_alternative(outcome, row.risk_score),
    )


def _context_hour(context: dict[str, Any]) -> int:
    """context.hour precedence (documented choice, item 20): an explicit integer
    `hour` in the request wins; else the UTC hour of a numeric `timestamp`; else
    now(UTC) — a hypothetical call is assumed to happen now."""
    hour = context.get("hour")
    if not isinstance(hour, bool) and isinstance(hour, int):
        return hour
    timestamp = context.get("timestamp")
    if not isinstance(timestamp, bool) and isinstance(timestamp, int | float):
        return datetime.fromtimestamp(timestamp, UTC).hour
    return datetime.now(UTC).hour


async def explain_call(
    identity_id: str,
    tool_name: str,
    server_id: str,
    arguments: dict[str, Any],
    context: dict[str, Any],
    *,
    engine: PolicyEngine,
    detector: DriftDetector,
    risk: RiskEngine,
    schema_cache: SchemaCache,
    validate_params: bool = True,
    mode: DecisionMode = DecisionMode.ENFORCE,
) -> Decision:
    """Dry-run the §4.2 pipeline (minus replay, minus all side effects) for a
    hypothetical call against the current policy. Always returns a Decision with
    audit_id=None; never raises for a policy outcome.

    validate_params=False skips stage 7 entirely (item 21): tool schemas aren't
    part of the policy, so Policy Simulation replays the pure policy pipeline
    without schema-cache state leaking into the comparison."""

    def decide(
        outcome: DecisionOutcome,
        event_type: EventType,
        reason: str,
        matched_rules: list[str],
        risk_score: int | None = None,
        risk_factors: list[RiskFactor] | None = None,
    ) -> Decision:
        return Decision(
            decision=outcome,
            event_type=event_type,
            mode=mode,
            reason=reason,
            matched_rules=matched_rules,
            risk_score=risk_score,
            risk_factors=risk_factors,
            policy_version=engine.version,
            alternative=_alternative(outcome, risk_score),
        )

    terminal: Decision | None = None

    def retain(candidate: Decision) -> Decision | None:
        nonlocal terminal
        terminal = terminal or candidate
        return terminal if mode is DecisionMode.ENFORCE else None

    def deny_abac(
        condition: abac.Condition,
        problem: str | None,
        risk_score: int | None = None,
        risk_factors: list[RiskFactor] | None = None,
    ) -> Decision:
        reason = f"condition {condition.source!r} not satisfied"
        if problem is not None:
            reason += f" ({problem})"
        return decide(
            DecisionOutcome.DENY,
            EventType.DENY_ABAC,
            reason,
            [f"policy-v{engine.version}:abac:{condition.source}"],
            risk_score=risk_score,
            risk_factors=risk_factors,
        )

    def check_conditions(
        conditions: list[abac.Condition], attrs: dict[str, abac.AttrValue]
    ) -> tuple[abac.Condition, str | None] | None:
        """First failing condition (with its problem, if evaluation itself broke),
        or None. Unlike the live path, an authoring problem is only logged — a dry
        run writes no POLICY_ERROR rows."""
        for condition in conditions:
            problem: str | None = None
            try:
                satisfied, missing = abac.evaluate(condition, attrs)
                if missing:
                    problem = f"unresolvable attributes: {', '.join(missing)}"
            except Exception:
                logger.exception("abac_evaluation_failed", condition=condition.source)
                satisfied, problem = False, "condition evaluation raised"
            if problem is not None:
                logger.warning("explain_policy_error", condition=condition.source, reason=problem)
            if not satisfied:
                return condition, problem
        return None

    # Stage 3: RBAC (stages 1-2, replay + auth, don't apply to a hypothetical call).
    grant = engine.matching_grant(identity_id, server_id, tool_name)
    conditions = grant.compiled_conditions if grant is not None else []
    if grant is None:
        stopped = retain(
            decide(
                DecisionOutcome.DENY,
                EventType.DENY_RBAC,
                f"identity {identity_id!r} is not authorized to call {tool_name!r}",
                [f"policy-v{engine.version}:rbac"],
            )
        )
        if stopped is not None:
            return stopped

    # Stage 4: ABAC, non-risk conditions (risk.* defers until a score exists).
    attrs: dict[str, abac.AttrValue] = {
        "identity.id": identity_id,
        "tool.name": tool_name,
        "tool.server_id": server_id,
        "context.hour": _context_hour(context),
    }
    identity = engine.identity(identity_id)
    if identity is not None:
        for key, value in identity.attributes.items():
            attrs[f"identity.{key}"] = value
    failed = check_conditions([c for c in conditions if not c.references_risk], attrs)
    if failed is not None:
        stopped = retain(deny_abac(*failed))
        if stopped is not None:
            return stopped

    # Stage 5: drift status; a lookup failure denies like the live path (§5).
    try:
        drift_blocked = await detector.is_blocked(server_id, tool_name)
    except Exception:
        logger.exception("drift_status_lookup_failed_fail_closed", tool=tool_name)
        drift_blocked = True
    if drift_blocked:
        stopped = retain(
            decide(
                DecisionOutcome.DENY,
                EventType.DENY_DRIFT,
                f"{tool_name!r} is blocked: schema drifted from its approved baseline"
                " and is pending re-approval",
                ["drift_detector"],
            )
        )
        if stopped is not None:
            return stopped

    # Stage 6: risk scoring, side-effect-free; a crashed calculation is maximum
    # risk (§5). No approval-redemption branch — explain has no approval id.
    try:
        risk_score, risk_factors = await risk.score(
            identity_id, server_id, tool_name, arguments, engine.policy.risk, dry_run=True
        )
    except Exception:
        logger.exception("risk_scoring_failed_fail_closed", tool=tool_name)
        risk_score, risk_factors = (
            100,
            [
                RiskFactor(
                    factor="risk_engine_unavailable",
                    contribution=100,
                    reason="risk scoring failed; treated as maximum risk",
                )
            ],
        )
    if terminal is not None:
        terminal.risk_score = risk_score
        terminal.risk_factors = risk_factors
    attrs["risk.score"] = risk_score
    failed = check_conditions([c for c in conditions if c.references_risk], attrs)
    if failed is not None:
        condition, problem = failed
        stopped = retain(
            deny_abac(
                condition,
                problem,
                risk_score=risk_score,
                risk_factors=risk_factors,
            )
        )
        if stopped is not None:
            return stopped
    threshold = threshold_outcome(risk_score)
    if threshold is DecisionOutcome.DENY:
        stopped = retain(
            decide(
                DecisionOutcome.DENY,
                EventType.DENY_RISK,
                f"risk score {risk_score} for {tool_name!r} exceeds the deny threshold (90)",
                ["risk_engine"],
                risk_score=risk_score,
                risk_factors=risk_factors,
            )
        )
        if stopped is not None:
            return stopped
    if threshold is DecisionOutcome.HUMAN_APPROVAL_REQUIRED:
        # No approvals row on a dry run — the Decision says what would happen.
        qualifier = "would require" if mode is DecisionMode.OBSERVE else "requires"
        stopped = retain(
            decide(
                DecisionOutcome.HUMAN_APPROVAL_REQUIRED,
                EventType.HUMAN_APPROVAL_REQUIRED,
                f"risk score {risk_score} for {tool_name!r} {qualifier} human approval",
                ["risk_engine"],
                risk_score=risk_score,
                risk_factors=risk_factors,
            )
        )
        if stopped is not None:
            return stopped
    if threshold is DecisionOutcome.CHALLENGE:
        qualifier = "would require" if mode is DecisionMode.OBSERVE else "requires"
        stopped = retain(
            decide(
                DecisionOutcome.CHALLENGE,
                EventType.CHALLENGE,
                f"risk score {risk_score} for {tool_name!r} {qualifier} confirmation",
                ["risk_engine"],
                risk_score=risk_score,
                risk_factors=risk_factors,
            )
        )
        if stopped is not None:
            return stopped

    # Stage 7: param validation from the shared cache only — a dry run never
    # re-fetches from the upstream, so a cold cache fails closed with an explicit
    # reason (a live call may still succeed via the §8 transparent re-fetch).
    def deny_validation(detail: str) -> Decision:
        return decide(
            DecisionOutcome.DENY,
            EventType.DENY_VALIDATION,
            f"invalid arguments for {tool_name!r}: {detail}",
            ["param_validator"],
            risk_score=risk_score,
            risk_factors=risk_factors,
        )

    if not validate_params:
        return terminal or decide(
            DecisionOutcome.ALLOW,
            EventType.ALLOW,
            f"call to {tool_name!r} would be allowed",
            [f"policy-v{engine.version}:rbac"],
            risk_score=risk_score,
            risk_factors=risk_factors,
        )

    try:
        tools = await schema_cache.get(server_id)
    except Exception:
        logger.exception("schema_cache_read_failed_fail_closed", tool=tool_name)
        tools = None
    if tools is None:
        stopped = retain(
            deny_validation(
                "tool schema not cached; explain fails closed"
                " (a live call would re-fetch it from the upstream)"
            )
        )
        if stopped is not None:
            return stopped
    input_schema = (
        next((t.get("inputSchema", {}) for t in tools if t.get("name") == tool_name), None)
        if tools is not None
        else None
    )
    if input_schema is None:
        stopped = retain(deny_validation("tool schema unavailable from upstream"))
        if stopped is not None:
            return stopped
    error = param_validator.validate(arguments, input_schema) if input_schema is not None else None
    if error is not None:
        stopped = retain(deny_validation(error))
        if stopped is not None:
            return stopped

    # Stage 8: ALLOW — no forward/audit on a dry run.
    return terminal or decide(
        DecisionOutcome.ALLOW,
        EventType.ALLOW,
        f"call to {tool_name!r} would be allowed",
        [f"policy-v{engine.version}:rbac"],
        risk_score=risk_score,
        risk_factors=risk_factors,
    )
