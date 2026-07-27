"""Drift Detector (ARCHITECTURE.md §4.8): severity-classified schema-change detection.

The first successful tools/list for a (server_id, tool_name) is the trust anchor —
hash AND full schema stored as the approved baseline. Every later sighting is diffed
field-by-field and classified rather than "block on any change"; High/Critical drift
blocks tools/call (pipeline stage 5, DENY_DRIFT) until an admin re-approves.

Canonicalization is canonicaljson (pinned) — see the key-reordering smoke test.
"""

import hashlib
import re
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import Any

import canonicaljson
import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway import metrics
from services.gateway.audit_log import AuditWriter
from services.gateway.config import settings
from services.gateway.db import AuditLog, ToolBaseline
from services.gateway.decision import EventType

logger = structlog.get_logger(__name__)

# Sentinel stored in observed_hash while a baselined tool is absent from the live list,
# so its removal (DRIFT_MEDIUM) is logged once, not on every poll.
REMOVED_SENTINEL = "-" * 64


class DriftSeverity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def event(self) -> EventType:
        return EventType[f"DRIFT_{self.name}"]

    @property
    def blocks(self) -> bool:
        return self >= DriftSeverity.HIGH


def tool_hash(tool: dict[str, Any]) -> str:
    return hashlib.sha256(canonicaljson.encode_canonical_json(tool)).hexdigest()


def shape_hash(tool: dict[str, Any]) -> str:
    """Hash of everything except the name and cosmetic `title` fields — SDK servers
    derive titles from the function name (e.g. 'send_emailArguments'), which would
    otherwise defeat the rename heuristic's 'same-shaped tool' comparison."""

    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k != "title"}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value

    return tool_hash({k: strip(v) for k, v in tool.items() if k != "name"})


def classify(old: dict[str, Any], new: dict[str, Any]) -> DriftSeverity | None:
    """Severity of the change between two tool definitions (§4.8 table); None if
    identical. Multiple changes report the maximum severity."""
    severities: list[DriftSeverity] = []
    if old.get("description") != new.get("description"):
        # Item 36a: the description is the LLM attack surface — a change after human
        # approval is the rug pull, so it blocks by default (config.py).
        severities.append(DriftSeverity[settings.drift_description_severity.upper()])

    old_schema = old.get("inputSchema") or {}
    new_schema = new.get("inputSchema") or {}
    old_props: dict[str, Any] = old_schema.get("properties") or {}
    new_props: dict[str, Any] = new_schema.get("properties") or {}
    old_required = set(old_schema.get("required") or [])
    new_required = set(new_schema.get("required") or [])

    for prop in new_props.keys() - old_props.keys():
        # A new *required* parameter changes what a valid call even looks like.
        severities.append(DriftSeverity.CRITICAL if prop in new_required else DriftSeverity.MEDIUM)
    if old_props.keys() - new_props.keys():
        severities.append(DriftSeverity.HIGH)
    for prop in old_props.keys() & new_props.keys():
        if old_props[prop].get("type") != new_props[prop].get("type"):
            severities.append(DriftSeverity.CRITICAL)
        elif old_props[prop] != new_props[prop]:
            severities.append(DriftSeverity.LOW)
    if (old_required ^ new_required) & (old_props.keys() & new_props.keys()):
        severities.append(DriftSeverity.CRITICAL)  # required status flipped

    if severities:
        return max(severities)
    if tool_hash(old) != tool_hash(new):
        # Changed in a way the table doesn't name — unclassifiable drift fails closed.
        return DriftSeverity.HIGH
    return None


# Baseline-time content heuristics (item 36b). A pattern list is inherently
# incomplete — novel phrasing evades it, and a protocol-layer gateway cannot
# semantically evaluate intent — so a hit flags (risk factor + audit event),
# it never blocks, and the miss case guarantees nothing.
_SUSPICIOUS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all)\b.{0,40}\binstructions\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "instruction-override phrasing",
    ),
    (
        re.compile(
            r"\byou are now\b|\bsystem prompt\b|\bdo not (tell|reveal|mention)\b", re.IGNORECASE
        ),
        "imperative text aimed at a model",
    ),
    (
        re.compile(r"[​-‏⁠-⁤‪-‮﻿]"),
        "hidden/zero-width or bidi-control unicode",
    ),
    (
        re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b"),
        "long base64-looking blob (possible encoded payload)",
    ),
]


def scan_descriptions(tool: dict[str, Any]) -> list[str]:
    """Heuristic findings for a tool definition's LLM-visible text: the top-level
    description plus every nested `description` string inside inputSchema (property
    descriptions are equally model-visible). Empty list = nothing matched, which is
    NOT a clean bill of health — see _SUSPICIOUS_PATTERNS."""

    def texts(value: Any, path: str) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        if isinstance(value, dict):
            description = value.get("description")
            if isinstance(description, str):
                found.append((f"{path}.description", description))
            for key, item in value.items():
                if key != "description":
                    found.extend(texts(item, f"{path}.{key}"))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                found.extend(texts(item, f"{path}[{i}]"))
        return found

    candidates: list[tuple[str, str]] = []
    description = tool.get("description")
    if isinstance(description, str):
        candidates.append(("description", description))
    candidates.extend(texts(tool.get("inputSchema"), "inputSchema"))
    return [
        f"{label} in {path}"
        for path, text in candidates
        for pattern, label in _SUSPICIOUS_PATTERNS
        if pattern.search(text)
    ]


class DriftDetector:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession], writer: AuditWriter) -> None:
        self._sessions = sessionmaker
        self._writer = writer

    async def check(self, server_id: str, tools: list[dict[str, Any]], identity_id: str) -> None:
        """Run drift detection over a freshly observed tools list. Raises on storage
        failure — callers withhold the list (fail closed, §5)."""
        live = {str(tool.get("name")): tool for tool in tools}
        async with self._sessions() as session:
            result = await session.execute(
                select(ToolBaseline).where(ToolBaseline.server_id == server_id)
            )
            baselines = {row.tool_name: row for row in result.scalars()}
            renamed_sources: set[str] = set()

            for name, tool in live.items():
                row = baselines.get(name)
                if row is None:
                    await self._first_sighting(
                        session,
                        server_id,
                        name,
                        tool,
                        live,
                        baselines,
                        renamed_sources,
                        identity_id,
                    )
                    continue
                live_hash = tool_hash(tool)
                if live_hash == row.approved_hash:
                    if row.observed_hash is not None:  # reverted to the approved shape
                        row.observed_hash = None
                        row.observed_schema = None
                        row.blocked = False
                        if not row.suspicious:
                            row.flagged_at = None
                    continue
                if live_hash == row.observed_hash:
                    continue  # this exact drift is already logged
                severity = classify(row.approved_schema, tool) or DriftSeverity.HIGH
                await self._writer.write(
                    severity.event,
                    identity_id,
                    server_id=server_id,
                    tool_name=name,
                    payload_extra={
                        "severity": severity.name.lower(),
                        "approved_hash": row.approved_hash,
                        "observed_hash": live_hash,
                        "blocked": severity.blocks,
                    },
                )
                metrics.SCHEMA_DRIFT.labels(server_id, name, severity.name.lower()).inc()
                row.observed_schema = tool
                row.observed_hash = live_hash
                row.flagged_at = row.flagged_at or datetime.now(UTC)
                if severity.blocks:
                    row.blocked = True

            for name, row in baselines.items():
                if name in live or name in renamed_sources:
                    continue
                if row.observed_hash != REMOVED_SENTINEL:
                    await self._writer.write(
                        EventType.DRIFT_MEDIUM,
                        identity_id,
                        server_id=server_id,
                        tool_name=name,
                        payload_extra={"severity": "medium", "removed": True},
                    )
                    metrics.SCHEMA_DRIFT.labels(server_id, name, "medium").inc()
                    row.observed_hash = REMOVED_SENTINEL
                    row.observed_schema = None
                    row.flagged_at = row.flagged_at or datetime.now(UTC)
            await session.commit()

    async def _first_sighting(
        self,
        session: AsyncSession,
        server_id: str,
        name: str,
        tool: dict[str, Any],
        live: dict[str, dict[str, Any]],
        baselines: dict[str, ToolBaseline],
        renamed_sources: set[str],
        identity_id: str,
    ) -> None:
        live_hash = tool_hash(tool)
        # Item 36b: a poisoned first contact must not become a *silent* trust anchor
        # — the schema is still baselined (flag, not block), but the finding is
        # audited and feeds the suspicious_baseline risk factor.
        findings = scan_descriptions(tool)
        if findings:
            await self._writer.write(
                EventType.BASELINE_FLAGGED,
                identity_id,
                server_id=server_id,
                tool_name=name,
                payload_extra={"findings": findings},
            )
        source = next(
            (
                row
                for row in baselines.values()
                if row.tool_name not in live and shape_hash(row.approved_schema) == shape_hash(tool)
            ),
            None,
        )
        if source is None:
            # First successful sighting is the trust anchor (§4.8).
            session.add(
                ToolBaseline(
                    server_id=server_id,
                    tool_name=name,
                    approved_schema=tool,
                    approved_hash=live_hash,
                    suspicious=bool(findings),
                    flagged_at=datetime.now(UTC) if findings else None,
                )
            )
            return
        renamed_sources.add(source.tool_name)
        await self._writer.write(
            EventType.DRIFT_CRITICAL,
            identity_id,
            server_id=server_id,
            tool_name=name,
            payload_extra={
                "severity": "critical",
                "renamed_from": source.tool_name,
                "observed_hash": live_hash,
                "blocked": True,
            },
        )
        metrics.SCHEMA_DRIFT.labels(server_id, name, "critical").inc()
        # Treated as a new, unapproved tool: baselined but blocked until approval.
        session.add(
            ToolBaseline(
                server_id=server_id,
                tool_name=name,
                approved_schema=tool,
                approved_hash=live_hash,
                blocked=True,
                observed_schema=tool,
                observed_hash=live_hash,
                suspicious=bool(findings),
                flagged_at=datetime.now(UTC),
            )
        )

    async def has_pending_drift(self, server_id: str, tool_name: str) -> bool:
        """Unresolved observed drift at any severity — the Risk Engine's drift-in-review
        signal (§4.8): Low/Medium drift doesn't block but still elevates risk. Blocked
        tools never reach risk scoring (stage 5 denies first)."""
        async with self._sessions() as session:
            result = await session.execute(
                select(ToolBaseline.observed_hash).where(
                    ToolBaseline.server_id == server_id,
                    ToolBaseline.tool_name == tool_name,
                )
            )
            return result.scalar_one_or_none() is not None

    async def recent_drift_count(self, server_id: str, tool_name: str, window_seconds: int) -> int:
        """DRIFT_* audit events for this tool within the window — the Risk Engine's
        drift-history signal (§4.8, item 18): counts survive re-approval by design,
        because the audit log, not tool_baselines, is the source of truth. Raises on
        DB failure — the scoring caller fails closed."""
        since = datetime.now(UTC) - timedelta(seconds=window_seconds)
        drift_events = [severity.event.value for severity in DriftSeverity]
        async with self._sessions() as session:
            result = await session.execute(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.event_type.in_(drift_events),
                    AuditLog.server_id == server_id,
                    AuditLog.tool_name == tool_name,
                    AuditLog.timestamp > since,
                )
            )
            return int(result.scalar_one())

    async def is_blocked(self, server_id: str, tool_name: str) -> bool:
        async with self._sessions() as session:
            result = await session.execute(
                select(ToolBaseline.blocked).where(
                    ToolBaseline.server_id == server_id,
                    ToolBaseline.tool_name == tool_name,
                )
            )
            return bool(result.scalar_one_or_none())

    async def is_suspicious(self, server_id: str, tool_name: str) -> bool:
        """Whether the tool's *approved* baseline matched the item-36b content
        heuristics — the Risk Engine's suspicious_baseline signal. A flag, never a
        block; cleared only when re-approval promotes content that scans clean."""
        async with self._sessions() as session:
            result = await session.execute(
                select(ToolBaseline.suspicious).where(
                    ToolBaseline.server_id == server_id,
                    ToolBaseline.tool_name == tool_name,
                )
            )
            return bool(result.scalar_one_or_none())

    async def approve(self, server_id: str, tool_name: str, approved_by: str) -> int:
        """Promote the observed schema to the accepted baseline (admin action).
        Returns the APPROVED audit row's seq. Raises LookupError if there is no
        pending drift to approve."""
        async with self._sessions() as session:
            result = await session.execute(
                select(ToolBaseline)
                .where(
                    ToolBaseline.server_id == server_id,
                    ToolBaseline.tool_name == tool_name,
                )
                .with_for_update()
            )
            row = result.scalar_one_or_none()
            if row is None or row.observed_schema is None:
                raise LookupError("no pending drift for this tool")
            old_hash = row.approved_hash
            row.approved_schema = row.observed_schema
            row.approved_hash = row.observed_hash or tool_hash(row.observed_schema)
            row.observed_schema = None
            row.observed_hash = None
            row.blocked = False
            # Item 36b: the flag tracks the *current* approved content — rescan on
            # promotion, and audit the finding when a clean baseline turns suspicious.
            findings = scan_descriptions(row.approved_schema)
            if findings and not row.suspicious:
                await self._writer.write(
                    EventType.BASELINE_FLAGGED,
                    approved_by,
                    server_id=server_id,
                    tool_name=tool_name,
                    payload_extra={"findings": findings},
                )
            row.suspicious = bool(findings)
            if not row.suspicious:
                row.flagged_at = None
            seq = await self._writer.write(
                EventType.APPROVED,
                approved_by,
                server_id=server_id,
                tool_name=tool_name,
                payload_extra={"old_hash": old_hash, "new_hash": row.approved_hash},
            )
            await session.commit()
            return seq
