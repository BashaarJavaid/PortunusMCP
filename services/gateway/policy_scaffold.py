"""Verified observe-audit rows -> review-only RBAC policy scaffold (item 52)."""

import copy
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
import yaml
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway import policy_engine, policy_simulator
from services.gateway.audit_keys import AuditKeyStore
from services.gateway.audit_log import GENESIS_HASH
from services.gateway.audit_verification import AuditRecord, verify_record
from services.gateway.db import AuditLog, PolicyVersion
from services.gateway.decision import EventType
from services.gateway.policy_engine import PolicyStore

logger = structlog.get_logger(__name__)

MAX_POLICY_BYTES = 1024 * 1024
_TERMINALS = {
    EventType.ALLOW.value,
    EventType.CHALLENGE.value,
    EventType.HUMAN_APPROVAL_REQUIRED.value,
    *(event.value for event in EventType if event.value.startswith("DENY_")),
}
_SENSITIVITY_TODO = (
    "TODO(human): review observed-tool sensitivity; {} adds no static sensitivity "
    "risk contribution."
)
_ABAC_TODO = (
    "TODO(human): review contextual restrictions; [] applies no ABAC restriction " "to this grant."
)


class ScaffoldRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    window: str


class ScaffoldConflict(RuntimeError):
    pass


class ScaffoldTooLarge(RuntimeError):
    pass


class _SequenceGap(ValueError):
    pass


def _window(value: str) -> tuple[datetime, datetime]:
    start, end = policy_simulator.parse_window(value, "window")
    if end - timedelta(days=1) > datetime.now(UTC).replace(
        hour=0, minute=0, second=0, microsecond=0
    ):
        raise ValueError("window end must not be in the future")
    return start, end


def _grant(record: AuditRecord) -> tuple[str, str, str] | None:
    if record.event_type not in _TERMINALS or record.payload.get("mode") != "observe":
        return None
    if not record.identity_id or not record.server_id or not record.tool_name:
        raise ScaffoldConflict(
            f"observe terminal at audit seq {record.seq} is missing identity, server, or tool"
        )
    if record.tool_name == "*":
        raise ScaffoldConflict(f"observe terminal at audit seq {record.seq} uses wildcard tool")
    return record.identity_id, record.server_id, record.tool_name


def _candidate_data(
    base: policy_engine.PolicyEngine,
    highest_version: int,
    observed: dict[str, dict[str, set[str]]],
) -> tuple[dict[str, Any], int, int]:
    raw = yaml.safe_load(base.raw)
    if not isinstance(raw, dict):
        raise ScaffoldConflict("active policy source is not a mapping")
    raw_servers = raw.get("servers")
    raw_identities = raw.get("identities")
    if not isinstance(raw_servers, dict) or not isinstance(raw_identities, list):
        raise ScaffoldConflict("active policy source is missing servers or identities")

    active_identities = {identity.id: identity for identity in base.policy.identities}
    missing_identities = observed.keys() - active_identities.keys()
    missing_servers = {
        server for grants in observed.values() for server in grants
    } - base.policy.servers.keys()
    if missing_identities:
        raise ScaffoldConflict(
            f"observed identity is absent from the active policy: {min(missing_identities)!r}"
        )
    if missing_servers:
        raise ScaffoldConflict(
            f"observed server is absent from the active policy: {min(missing_servers)!r}"
        )

    identities: list[dict[str, Any]] = []
    grant_count = server_tool_count = 0
    for raw_identity in raw_identities:
        if not isinstance(raw_identity, dict) or not isinstance(raw_identity.get("id"), str):
            raise ScaffoldConflict("active policy identity source is inconsistent")
        identity_id = raw_identity["id"]
        identity = active_identities.get(identity_id)
        if identity is None:
            raise ScaffoldConflict("active policy identity source is inconsistent")
        if not identity.admin and identity_id not in observed:
            continue
        grants = [
            {
                "server_id": server_id,
                "allowed_tools": sorted(observed.get(identity_id, {}).get(server_id, set())),
                "conditions": [],
            }
            for server_id in raw_servers
            if observed.get(identity_id, {}).get(server_id)
        ]
        generated: dict[str, Any] = {}
        for key, value in raw_identity.items():
            generated[key] = grants if key == "allowed_servers" else copy.deepcopy(value)
        if "allowed_servers" not in generated:
            generated["allowed_servers"] = grants
        identities.append(generated)
        grant_count += len(grants)
        server_tool_count += sum(len(grant["allowed_tools"]) for grant in grants)

    protected_repos = copy.deepcopy((raw.get("risk") or {}).get("protected_repos", []))
    return (
        {
            "version": highest_version + 1,
            "servers": copy.deepcopy(raw_servers),
            "identities": identities,
            "risk": {"tool_sensitivity": {}, "protected_repos": protected_repos},
        },
        grant_count,
        server_tool_count,
    )


def _render(
    data: dict[str, Any],
    *,
    base: policy_engine.PolicyEngine,
    window: str,
    start_seq: int,
    end_seq: int,
    genesis_anchored: bool,
) -> bytes:
    dumped = yaml.safe_dump(data, sort_keys=False)
    lines: list[str] = []
    for line in dumped.splitlines():
        indent = line[: len(line) - len(line.lstrip())]
        if line.strip() == "tool_sensitivity: {}":
            lines.append(f"{indent}# {_SENSITIVITY_TODO}")
        elif line.strip() == "conditions: []":
            lines.append(f"{indent}# {_ABAC_TODO}")
        lines.append(line)
    attested = str(genesis_anchored).lower()
    header = [
        "# GENERATED SCAFFOLD — NOT FULLY VALIDATED OR APPLIED",
        f"# Base policy: version {base.version}, sha256 {base.content_hash}",
        f"# UTC window: {window}",
        (
            f"# Verified audit bounds: {start_seq}..{end_seq}; "
            f"genesis_anchored={attested}; prefix_attested={attested}"
        ),
        "# Review every TODO before rollout.",
    ]
    return ("\n".join([*header, *lines]) + "\n").encode()


async def scaffold(
    source: str,
    window: str,
    *,
    store: PolicyStore,
    sessionmaker: async_sessionmaker[AsyncSession],
    key_store: AuditKeyStore,
    max_policy_bytes: int = MAX_POLICY_BYTES,
) -> dict[str, Any]:
    if source != "audit":
        raise ValueError("source must be 'audit'")
    start_time, end_time = _window(window)
    base = store.engine
    base_hash = base.content_hash

    async with sessionmaker() as session:
        highest = (
            await session.execute(select(func.max(PolicyVersion.version)))
        ).scalar_one_or_none()
        start_seq, end_seq = (
            await session.execute(
                select(func.min(AuditLog.seq), func.max(AuditLog.seq)).where(
                    AuditLog.timestamp >= start_time,
                    AuditLog.timestamp < end_time,
                )
            )
        ).one()
    if highest is None:
        raise ScaffoldConflict("policy revision ledger is empty")
    if start_seq is None or end_seq is None:
        raise ScaffoldConflict("audit window is empty")
    start_seq, end_seq = int(start_seq), int(end_seq)

    observed: dict[str, dict[str, set[str]]] = {}
    qualifying_count = verified_count = 0
    previous: str | None = GENESIS_HASH if start_seq == 1 else None
    expected_seq = start_seq
    current_seq = start_seq
    try:
        async with sessionmaker() as session:
            rows = await session.stream_scalars(
                select(AuditLog)
                .where(AuditLog.seq >= start_seq, AuditLog.seq <= end_seq)
                .order_by(AuditLog.seq)
            )
            async for row in rows:
                current_seq = row.seq
                if row.seq != expected_seq:
                    raise _SequenceGap(f"gap before seq {row.seq}")
                record = AuditRecord.from_row(row)
                if previous is None:
                    previous = record.prev_hash
                previous = verify_record(record, previous, key_store.load_public)
                grant = _grant(record)
                if grant is not None:
                    identity, server, tool = grant
                    observed.setdefault(identity, {}).setdefault(server, set()).add(tool)
                    qualifying_count += 1
                verified_count += 1
                expected_seq += 1
        if expected_seq != end_seq + 1:
            current_seq = expected_seq
            raise _SequenceGap("selected audit span is incomplete")
    except ScaffoldConflict:
        raise
    except (OSError, TypeError, ValueError, AttributeError) as exc:
        logger.error(
            "policy_scaffold_audit_integrity_failed",
            failure_class=type(exc).__name__,
            seq=current_seq,
        )
        raise ScaffoldConflict("audit integrity verification failed") from exc
    if not qualifying_count:
        raise ScaffoldConflict("audit window has no qualifying observe-mode tool calls")

    data, grant_count, server_tool_count = _candidate_data(base, int(highest), observed)
    raw = _render(
        data,
        base=base,
        window=window,
        start_seq=start_seq,
        end_seq=end_seq,
        genesis_anchored=start_seq == 1,
    )
    if len(raw) > max_policy_bytes:
        raise ScaffoldTooLarge("generated policy exceeds the 1 MiB policy limit")
    try:
        candidate = policy_engine.load_bytes(raw)
    except Exception as exc:
        raise ScaffoldConflict("generated policy failed structural validation") from exc

    async with sessionmaker() as session:
        current_highest = (
            await session.execute(select(func.max(PolicyVersion.version)))
        ).scalar_one_or_none()
    if (
        store.engine is not base
        or store.engine.content_hash != base_hash
        or current_highest != highest
    ):
        raise ScaffoldConflict("active policy changed while the scaffold was generated")

    anchored = start_seq == 1
    return {
        "policy": raw.decode(),
        "metadata": {
            "audit": {
                "source": source,
                "window": window,
                "from_seq": start_seq,
                "to_seq": end_seq,
                "verified_row_count": verified_count,
                "qualifying_call_row_count": qualifying_count,
                "genesis_anchored": anchored,
                "prefix_attested": anchored,
            },
            "base_policy": {"version": base.version, "content_hash": base_hash},
            "candidate": {
                "version": candidate.version,
                "content_hash": candidate.content_hash,
                "identity_count": len(candidate.policy.identities),
                "grant_count": grant_count,
                "server_tool_count": server_tool_count,
            },
        },
    }
