"""Policy Simulation Mode (ARCHITECTURE.md §4.8, item 21).

Replays historical tools/call decisions from the audit log against candidate
policy revision snapshots — read-only: the live PolicyStore is never touched,
no audit rows are written, and risk scoring runs dry_run=True inside
decision_explainer.explain_call. Two mutually exclusive modes:

- candidate vs. historical reality: what would revision N have decided for the
  calls that actually happened in the window, versus what was decided.
- compare two revisions: replay the same window through both and diff them.

Stage 7 (param validation) is skipped during replay (validate_params=False):
tool schemas aren't part of the policy, so schema-cache state must not leak
into a policy comparison. v1 bounds and caveats: at most ROW_CAP rows per
simulation; drift baselines and Redis telemetry are *current* state, not
time-traveled (business-hours ABAC does use each row's historical timestamp);
rows written before item 21 lack `arguments` on deny-family events and are
skipped.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway import decision_explainer, policy_engine, policy_versions
from services.gateway.db import AuditLog, PolicyVersion
from services.gateway.decision import Decision, DecisionOutcome, EventType
from services.gateway.drift_detector import DriftDetector
from services.gateway.policy_engine import PolicyEngine
from services.gateway.policy_versions import ActivationError
from services.gateway.risk_engine import RiskEngine
from services.gateway.schema_cache import SchemaCache

# ponytail: hard row bound keeps the endpoint O(window); paginate if real windows outgrow it
ROW_CAP = 10_000
SAMPLE_CAP = 10
_REASON_SNIPPET_LEN = 160

# Every decision event type is replayable except APPROVED — a redemption row
# would double-count the HUMAN_APPROVAL_REQUIRED row it redeemed.
_REPLAYABLE = [e for e in decision_explainer._OUTCOMES if e is not EventType.APPROVED]


class SimulateRequest(BaseModel):
    candidate_version: int | None = None
    compare_versions: list[int] | None = None
    replay_window: str


class SampleDiff(BaseModel):
    audit_seq: int
    identity: str
    tool: str
    before: str
    after: str
    reason: str


class HistoricalSimulation(BaseModel):
    total_replayed: int
    would_now_deny: int
    would_now_require_approval: int
    newly_allowed: int
    unchanged: int
    sample_diffs: list[SampleDiff]


class CompareSimulation(BaseModel):
    total_replayed: int
    compared_versions: list[int]
    new_denials: int
    new_approvals: int
    changed_risk_scores: int
    changed_explanations: int
    sample_diffs: list[SampleDiff]


def parse_window(window: str) -> tuple[datetime, datetime]:
    """Inclusive UTC date range 'YYYY-MM-DD..YYYY-MM-DD' -> [start, end) datetimes
    (the exclusive end is the day after the inclusive end date). Raises ValueError."""
    try:
        start_s, end_s = window.split("..")
        start = datetime.strptime(start_s, "%Y-%m-%d").replace(tzinfo=UTC)
        end = datetime.strptime(end_s, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        raise ValueError(
            f"replay_window must be 'YYYY-MM-DD..YYYY-MM-DD', got {window!r}"
        ) from None
    if start > end:
        raise ValueError(f"replay_window start {start_s} is after its end {end_s}")
    return start, end + timedelta(days=1)


async def load_version(
    version: int, sessionmaker: async_sessionmaker[AsyncSession]
) -> PolicyEngine:
    """Load a recorded revision snapshot as a PolicyEngine, without activating it.
    Raises LookupError for an unrecorded version or missing snapshot file, and
    ActivationError when the snapshot bytes no longer match the recorded
    content_hash — a tampered snapshot must not be simulated as authentic (§5)."""
    async with sessionmaker() as session:
        row = await session.get(PolicyVersion, version)
    if row is None:
        raise LookupError(f"policy version {version} was never recorded")
    path = policy_versions.snapshot_path(version)
    if not path.exists():
        raise LookupError(f"no revision snapshot for policy version {version}")
    engine = policy_engine.load_bytes(path.read_bytes())
    if engine.content_hash != row.content_hash:
        raise ActivationError(
            f"snapshot for version {version} does not match its recorded content_hash"
        )
    return engine


async def replay_rows(
    start: datetime, end: datetime, sessionmaker: async_sessionmaker[AsyncSession]
) -> list[AuditLog]:
    """The replay set: decision rows in [start, end) that carry a tool name and
    arguments, oldest first, capped at ROW_CAP."""
    async with sessionmaker() as session:
        result = await session.execute(
            select(AuditLog)
            .where(
                AuditLog.event_type.in_([e.value for e in _REPLAYABLE]),
                AuditLog.tool_name.is_not(None),
                AuditLog.timestamp >= start,
                AuditLog.timestamp < end,
            )
            .order_by(AuditLog.seq)
            .limit(ROW_CAP)
        )
        rows = list(result.scalars())
    return [r for r in rows if isinstance((r.payload or {}).get("arguments"), dict)]


def historical_bucket(row: AuditLog) -> DecisionOutcome:
    return decision_explainer._OUTCOMES[EventType(row.event_type)]


def _snippet(reason: str) -> str:
    return reason if len(reason) <= _REASON_SNIPPET_LEN else reason[: _REASON_SNIPPET_LEN - 1] + "…"


def _label(decision: Decision) -> str:
    if decision.risk_score is None:
        return decision.decision.value
    return f"{decision.decision.value} (risk {decision.risk_score})"


def summarize_historical(pairs: list[tuple[AuditLog, Decision]]) -> HistoricalSimulation:
    """Mode A counters (§4.8): the buckets are DecisionOutcome values; any bucket
    change (e.g. CHALLENGE -> DENY) leaves `unchanged`, whether or not it lands in
    one of the three named counters."""
    would_now_deny = would_now_require_approval = newly_allowed = unchanged = 0
    diffs: list[SampleDiff] = []
    for row, after in pairs:
        before = historical_bucket(row)
        after_bucket = after.decision
        if before is after_bucket:
            unchanged += 1
            continue
        if before is DecisionOutcome.ALLOW and after_bucket is DecisionOutcome.DENY:
            would_now_deny += 1
        if after_bucket is DecisionOutcome.HUMAN_APPROVAL_REQUIRED:
            would_now_require_approval += 1
        if (
            before in (DecisionOutcome.DENY, DecisionOutcome.CHALLENGE)
            and after_bucket is DecisionOutcome.ALLOW
        ):
            newly_allowed += 1
        if len(diffs) < SAMPLE_CAP:
            diffs.append(
                SampleDiff(
                    audit_seq=row.seq,
                    identity=row.identity_id,
                    tool=row.tool_name or "",
                    before=before.value,
                    after=after_bucket.value,
                    reason=_snippet(after.reason),
                )
            )
    return HistoricalSimulation(
        total_replayed=len(pairs),
        would_now_deny=would_now_deny,
        would_now_require_approval=would_now_require_approval,
        newly_allowed=newly_allowed,
        unchanged=unchanged,
        sample_diffs=diffs,
    )


def summarize_compare(
    triples: list[tuple[AuditLog, Decision, Decision]], versions: list[int]
) -> CompareSimulation:
    """Mode B counters (§4.8): both decisions are simulated; `old` is the first
    compared version, `new` the second."""
    new_denials = new_approvals = changed_risk_scores = changed_explanations = 0
    diffs: list[SampleDiff] = []
    for row, old, new in triples:
        old_bucket, new_bucket = old.decision, new.decision
        if (
            old_bucket in (DecisionOutcome.ALLOW, DecisionOutcome.CHALLENGE)
            and new_bucket is DecisionOutcome.DENY
        ):
            new_denials += 1
        if (
            new_bucket is DecisionOutcome.HUMAN_APPROVAL_REQUIRED
            and old_bucket is not DecisionOutcome.HUMAN_APPROVAL_REQUIRED
        ):
            new_approvals += 1
        if old.risk_score != new.risk_score:
            changed_risk_scores += 1
        if old_bucket is not new_bucket or old.reason != new.reason:
            changed_explanations += 1
            if len(diffs) < SAMPLE_CAP:
                diffs.append(
                    SampleDiff(
                        audit_seq=row.seq,
                        identity=row.identity_id,
                        tool=row.tool_name or "",
                        before=_label(old),
                        after=_label(new),
                        reason=_snippet(new.reason),
                    )
                )
    return CompareSimulation(
        total_replayed=len(triples),
        compared_versions=versions,
        new_denials=new_denials,
        new_approvals=new_approvals,
        changed_risk_scores=changed_risk_scores,
        changed_explanations=changed_explanations,
        sample_diffs=diffs,
    )


async def _simulate_row(
    row: AuditLog,
    engine: PolicyEngine,
    detector: DriftDetector,
    risk: RiskEngine,
    schema_cache: SchemaCache,
) -> Decision:
    arguments: dict[str, Any] = (row.payload or {})["arguments"]
    # context.timestamp = the row's historical epoch, so business-hours ABAC
    # evaluates the hour the call actually happened, not the hour of the replay.
    return await decision_explainer.explain_call(
        row.identity_id,
        row.tool_name or "",
        # Decision rows always record their server; "" on a legacy row fails
        # closed as DENY_RBAC.
        row.server_id or "",
        arguments,
        {"timestamp": row.timestamp.timestamp()},
        engine=engine,
        detector=detector,
        risk=risk,
        schema_cache=schema_cache,
        validate_params=False,
    )


async def simulate_historical(
    candidate_version: int,
    replay_window: str,
    *,
    sessionmaker: async_sessionmaker[AsyncSession],
    detector: DriftDetector,
    risk: RiskEngine,
    schema_cache: SchemaCache,
) -> HistoricalSimulation:
    start, end = parse_window(replay_window)
    engine = await load_version(candidate_version, sessionmaker)
    rows = await replay_rows(start, end, sessionmaker)
    pairs = [(row, await _simulate_row(row, engine, detector, risk, schema_cache)) for row in rows]
    return summarize_historical(pairs)


async def simulate_candidate(
    engine: PolicyEngine,
    replay_window: str,
    *,
    sessionmaker: async_sessionmaker[AsyncSession],
    detector: DriftDetector,
    risk: RiskEngine,
    schema_cache: SchemaCache,
) -> HistoricalSimulation:
    """Replay an unrecorded, unactivated candidate policy."""
    start, end = parse_window(replay_window)
    rows = await replay_rows(start, end, sessionmaker)
    pairs = [(row, await _simulate_row(row, engine, detector, risk, schema_cache)) for row in rows]
    return summarize_historical(pairs)


async def simulate_compare(
    versions: list[int],
    replay_window: str,
    *,
    sessionmaker: async_sessionmaker[AsyncSession],
    detector: DriftDetector,
    risk: RiskEngine,
    schema_cache: SchemaCache,
) -> CompareSimulation:
    start, end = parse_window(replay_window)
    old_engine = await load_version(versions[0], sessionmaker)
    new_engine = await load_version(versions[1], sessionmaker)
    rows = await replay_rows(start, end, sessionmaker)
    triples = [
        (
            row,
            await _simulate_row(row, old_engine, detector, risk, schema_cache),
            await _simulate_row(row, new_engine, detector, risk, schema_cache),
        )
        for row in rows
    ]
    return summarize_compare(triples, versions)
