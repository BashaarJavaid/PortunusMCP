"""Canonical Decision object and event-type enum (ARCHITECTURE.md §4.3). Types only —
the pipeline that produces these lands across later ROADMAP items."""

from enum import StrEnum

from pydantic import BaseModel


class EventType(StrEnum):
    SESSION_START = "SESSION_START"
    TOOLS_LIST = "TOOLS_LIST"
    ALLOW = "ALLOW"
    DENY_RBAC = "DENY_RBAC"
    DENY_ABAC = "DENY_ABAC"
    DENY_REPLAY = "DENY_REPLAY"
    DENY_DRIFT = "DENY_DRIFT"
    DENY_RISK = "DENY_RISK"
    DENY_VALIDATION = "DENY_VALIDATION"
    DENY_APPROVAL_MISMATCH = "DENY_APPROVAL_MISMATCH"
    # Item 37: a step-up retry whose challenge/proof failed — unknown/expired/
    # consumed challenge, mismatched call, or an invalid or reused TOTP code.
    DENY_STEP_UP = "DENY_STEP_UP"
    CHALLENGE = "CHALLENGE"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    APPROVED = "APPROVED"
    EXPIRED = "EXPIRED"
    DRIFT_LOW = "DRIFT_LOW"
    DRIFT_MEDIUM = "DRIFT_MEDIUM"
    DRIFT_HIGH = "DRIFT_HIGH"
    DRIFT_CRITICAL = "DRIFT_CRITICAL"
    # Item 36b: a newly baselined/promoted schema matched the description-content
    # heuristics — flagged (risk factor), never blocked. Non-decision row.
    BASELINE_FLAGGED = "BASELINE_FLAGGED"
    # Item 42: old-key-signed handoff to a fingerprint-addressed new audit key.
    AUDIT_KEY_ROTATED = "AUDIT_KEY_ROTATED"
    POLICY_ACTIVATED = "POLICY_ACTIVATED"
    POLICY_ERROR = "POLICY_ERROR"


class DecisionOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"


class DecisionMode(StrEnum):
    ENFORCE = "enforce"
    OBSERVE = "observe"


class RiskFactor(BaseModel):
    factor: str
    contribution: int
    # Human-readable explanation per §4.8's factor interface (surfaced by item 20).
    reason: str | None = None


class Decision(BaseModel):
    decision: DecisionOutcome
    event_type: EventType
    # Missing on pre-item-49 rows and v0.1.0 responses: those were always enforcing.
    mode: DecisionMode = DecisionMode.ENFORCE
    reason: str
    matched_rules: list[str]
    risk_score: int | None = None
    risk_factors: list[RiskFactor] | None = None
    policy_version: int
    # None until the audit log writer lands (Phase 1, item 5).
    audit_id: str | None = None
    # Set only on HUMAN_APPROVAL_REQUIRED: the id the client passes back via
    # params._meta["portunusmcp/approval_id"] on the approved retry (§4.8).
    approval_id: str | None = None
    # Set only on an answerable CHALLENGE (item 37 — the identity has a TOTP
    # factor): the one-time id the client passes back via
    # params._meta["portunusmcp/challenge_id"] alongside a fresh TOTP code.
    challenge_id: str | None = None
    # Decision Explanation only (§4.8, item 20): the outcome the 40/70/90 threshold
    # mapping gives for risk_score, set when that differs from the actual outcome
    # (e.g. an ABAC risk-condition deny at score 74 → "human_approval_required").
    alternative: DecisionOutcome | None = None
