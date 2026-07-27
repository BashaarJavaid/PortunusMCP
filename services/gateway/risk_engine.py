"""Risk Engine v1 (ARCHITECTURE.md §4.8, item 16): rule-based factor-list scoring.

Each signal is a small pure function over a pre-gathered RiskContext, returning a
weighted contribution and a human-readable reason; the engine sums a fixed list of
them (a common-interface function list, deliberately not a plugin system) into a
0-100 score. Deterministic and rule-based by design — no ML, ever (§4.8).

Risk decay (§4.8): a per-(identity, tool) Redis counter, incremented on each admin
approval, discounts the *behavioral* subtotal (call frequency, prior-denial-rate,
drift-in-review) — never the static tool-sensitivity tier — floored at 0. The
offset is clamped to risk_decay_max at read time and the counter expires (item 33),
so rubber-stamp approvals dampen behavioral scoring but can't switch it off, and
never desensitize the engine to an inherently dangerous tool's static tier.

Item 18 telemetry: prior-denial-rate (per-identity Redis rolling counter, bumped by
the interceptor on every DENY_* terminal) and drift-history (DRIFT_* audit events for
the tool in a rolling window, surviving re-approval). Counter *writes* are best-effort
at their call sites; the *reads* here raise on failure like every other input — fail
closed. Item 43 moved failed authentication into source throttling, outside scoring.

Scoring exceptions propagate to the caller, which must treat them as score 100 and
deny (§5 fail-closed).
"""

import fnmatch
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis

from services.gateway.config import settings
from services.gateway.decision import DecisionOutcome, RiskFactor
from services.gateway.drift_detector import DriftDetector
from services.gateway.policy_engine import RiskPolicy

# Weighted contributions. Anchored to §4.3's worked example (protected repo 30,
# business hours 25, prior denial rate ~25); the tier ladder is chosen so the §11
# canary scenario (high-sensitivity tool + protected repo + off-hours = 85) lands
# in 70-90 — the item-18 factors need their own triggers and leave it untouched.
TIER_CONTRIBUTION = {"low": 10, "medium": 20, "high": 30, "critical": 45}
PROTECTED_CONTRIBUTION = 30
OFF_HOURS_CONTRIBUTION = 25
FREQUENCY_CONTRIBUTION = 20
DRIFT_IN_REVIEW_CONTRIBUTION = 15
PRIOR_DENIAL_CONTRIBUTION = 25
DRIFT_HISTORY_CONTRIBUTION = 15
SUSPICIOUS_BASELINE_CONTRIBUTION = 20

# Factors risk decay may discount — §4.8 names them exactly: call frequency,
# prior-denial-rate, drift-in-review; never the tier, and deliberately not
# drift_history (approving one call shouldn't erase a tool's instability record).
BEHAVIORAL_FACTORS = frozenset({"call_frequency", "prior_denial_rate", "drift_in_review"})


@dataclass
class RiskContext:
    identity_id: str
    tool_name: str
    arguments: dict[str, Any]
    policy: RiskPolicy
    now: datetime  # timezone-aware UTC
    call_count: int  # calls for this identity+tool in the rolling window, incl. this one
    drift_in_review: bool
    denial_count: int  # DENY_* terminals for this identity in the rolling window
    drift_event_count: int  # DRIFT_* audit events for this tool in the rolling window
    suspicious_baseline: bool  # approved content matched the item-36b heuristics


def _string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


def _tool_sensitivity(ctx: RiskContext) -> RiskFactor | None:
    tier = ctx.policy.tool_sensitivity.get(ctx.tool_name)
    if tier is None:
        return None
    return RiskFactor(
        factor="tool_sensitivity",
        contribution=TIER_CONTRIBUTION[tier],
        reason=f"{ctx.tool_name!r} is policy-tiered {tier}",
    )


def _blast_radius(ctx: RiskContext) -> RiskFactor | None:
    for value in _string_values(ctx.arguments):
        for pattern in ctx.policy.protected_repos:
            if fnmatch.fnmatch(value, pattern):
                return RiskFactor(
                    factor="protected_repository",
                    contribution=PROTECTED_CONTRIBUTION,
                    reason=f"argument {value!r} matches protected pattern {pattern!r}",
                )
    return None


def _business_hours(ctx: RiskContext) -> RiskFactor | None:
    # v1 window: Mon-Fri, settings-configured hours, UTC only (no per-identity
    # timezone yet — documented choice, see config.py).
    off_hours = (
        ctx.now.weekday() >= 5
        or not settings.business_hours_start_utc <= ctx.now.hour < settings.business_hours_end_utc
    )
    if not off_hours:
        return None
    return RiskFactor(
        factor="business_hours",
        contribution=OFF_HOURS_CONTRIBUTION,
        reason=f"call at {ctx.now:%a %H:%M} UTC is outside business hours",
    )


def _call_frequency(ctx: RiskContext) -> RiskFactor | None:
    if ctx.call_count <= settings.risk_freq_threshold:
        return None
    return RiskFactor(
        factor="call_frequency",
        contribution=FREQUENCY_CONTRIBUTION,
        reason=(
            f"{ctx.call_count} calls to {ctx.tool_name!r} in the last"
            f" {settings.risk_freq_window_seconds}s exceeds {settings.risk_freq_threshold}"
        ),
    )


def _drift_in_review(ctx: RiskContext) -> RiskFactor | None:
    if not ctx.drift_in_review:
        return None
    return RiskFactor(
        factor="drift_in_review",
        contribution=DRIFT_IN_REVIEW_CONTRIBUTION,
        reason=f"{ctx.tool_name!r} has unresolved schema drift pending review",
    )


def _prior_denial_rate(ctx: RiskContext) -> RiskFactor | None:
    if ctx.denial_count <= settings.risk_denial_threshold:
        return None
    return RiskFactor(
        factor="prior_denial_rate",
        contribution=PRIOR_DENIAL_CONTRIBUTION,
        reason=(
            f"{ctx.denial_count} denials for {ctx.identity_id!r} in the last"
            f" {settings.risk_denial_window_seconds}s exceeds {settings.risk_denial_threshold}"
        ),
    )


def _drift_history(ctx: RiskContext) -> RiskFactor | None:
    if ctx.drift_event_count < settings.risk_drift_history_threshold:
        return None
    return RiskFactor(
        factor="drift_history",
        contribution=DRIFT_HISTORY_CONTRIBUTION,
        reason=(
            f"{ctx.tool_name!r} drifted {ctx.drift_event_count} times in the last"
            f" {settings.risk_drift_history_window_seconds}s, even if since re-approved"
        ),
    )


def _suspicious_baseline(ctx: RiskContext) -> RiskFactor | None:
    # Item 36b: a property of the tool's approved content, like the sensitivity
    # tier — deliberately not in BEHAVIORAL_FACTORS, so approvals can't decay it.
    if not ctx.suspicious_baseline:
        return None
    return RiskFactor(
        factor="suspicious_baseline",
        contribution=SUSPICIOUS_BASELINE_CONTRIBUTION,
        reason=(
            f"{ctx.tool_name!r}'s approved description matched instruction-injection"
            " heuristics when it was baselined"
        ),
    )


FACTORS: list[Callable[[RiskContext], RiskFactor | None]] = [
    _tool_sensitivity,
    _blast_radius,
    _business_hours,
    _call_frequency,
    _drift_in_review,
    _prior_denial_rate,
    _drift_history,
    _suspicious_baseline,
]


def _freq_key(identity_id: str, server_id: str, tool_name: str) -> str:
    return f"risk:freq:{identity_id}:{server_id}:{tool_name}"


def _decay_key(identity_id: str, server_id: str, tool_name: str) -> str:
    return f"risk:decay:{identity_id}:{server_id}:{tool_name}"


def _denial_key(identity_id: str) -> str:
    return f"risk:denials:{identity_id}"


# The §4.8 threshold bands: <40 continue (allow), 40-69 CHALLENGE, 70-90
# HUMAN_APPROVAL_REQUIRED, >90 DENY. Compared only in threshold_outcome() (item 32).
RISK_CHALLENGE_MIN = 40
RISK_APPROVAL_MIN = 70
RISK_DENY_ABOVE = 90


def threshold_outcome(score: int) -> DecisionOutcome:
    """The §4.8 threshold bands as a pure mapping — the single source of truth
    (item 32): the interceptor branches on this for live enforcement, and the
    Decision Explanation API (item 20) uses it for predictions and `alternative`,
    so the two can't fork."""
    if score > RISK_DENY_ABOVE:
        return DecisionOutcome.DENY
    if score >= RISK_APPROVAL_MIN:
        return DecisionOutcome.HUMAN_APPROVAL_REQUIRED
    if score >= RISK_CHALLENGE_MIN:
        return DecisionOutcome.CHALLENGE
    return DecisionOutcome.ALLOW


def combine(factors: list[RiskFactor], decay_offset: int) -> int:
    """Weighted sum with the decay boundary: the offset discounts only the behavioral
    subtotal, floored at 0, and the total is clamped to 0-100."""
    behavioral = sum(f.contribution for f in factors if f.factor in BEHAVIORAL_FACTORS)
    static = sum(f.contribution for f in factors if f.factor not in BEHAVIORAL_FACTORS)
    return min(static + max(0, behavioral - decay_offset), 100)


class RiskEngine:
    def __init__(self, redis_client: aioredis.Redis, detector: DriftDetector) -> None:
        self._redis = redis_client
        self._detector = detector

    async def score(
        self,
        identity_id: str,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        risk_policy: RiskPolicy,
        dry_run: bool = False,
    ) -> tuple[int, list[RiskFactor]]:
        """Score one prospective call. Raises on Redis/Postgres failure — callers
        treat that as score 100 and deny (§5). dry_run (item 20 explain) predicts
        what a live call would score — the frequency counter is read + 1 instead
        of INCRed, so explaining never mutates telemetry."""
        if dry_run:
            call_count = await self._counter(_freq_key(identity_id, server_id, tool_name)) + 1
        else:
            call_count = await self._bump_frequency(identity_id, server_id, tool_name)
        ctx = RiskContext(
            identity_id=identity_id,
            tool_name=tool_name,
            arguments=arguments,
            policy=risk_policy,
            now=datetime.now(UTC),
            call_count=call_count,
            drift_in_review=await self._detector.has_pending_drift(server_id, tool_name),
            denial_count=await self._counter(_denial_key(identity_id)),
            drift_event_count=await self._detector.recent_drift_count(
                server_id,
                tool_name,
                settings.risk_drift_history_window_seconds,
            ),
            suspicious_baseline=await self._detector.is_suspicious(server_id, tool_name),
        )
        factors = [factor for fn in FACTORS if (factor := fn(ctx)) is not None]
        decay_raw = await self._redis.get(_decay_key(identity_id, server_id, tool_name))
        decay = min(int(decay_raw or 0), settings.risk_decay_max)
        return combine(factors, decay), factors

    async def _bump_frequency(self, identity_id: str, server_id: str, tool_name: str) -> int:
        key = _freq_key(identity_id, server_id, tool_name)
        count: int = await self._redis.incr(key)
        if count == 1:
            await self._redis.expire(key, settings.risk_freq_window_seconds)
        return count

    async def _counter(self, key: str) -> int:
        raw = await self._redis.get(key)
        return int(raw or 0)

    async def record_denial(self, identity_id: str) -> None:
        """Count one DENY_* terminal toward the prior-denial-rate window. The caller
        treats a failure here as best-effort telemetry — the deny already stands."""
        key = _denial_key(identity_id)
        count: int = await self._redis.incr(key)
        if count == 1:
            await self._redis.expire(key, settings.risk_denial_window_seconds)

    async def apply_decay(self, identity_id: str, server_id: str, tool_name: str) -> None:
        """One admin approval = one calibration step (§4.8): grow this pair's offset.
        The TTL refreshes on every approval (item 33) so active calibration persists
        while idle calibration ages out; score() clamps the read to risk_decay_max."""
        key = _decay_key(identity_id, server_id, tool_name)
        await self._redis.incrby(key, settings.risk_decay_step)
        await self._redis.expire(key, settings.risk_decay_ttl_seconds)
