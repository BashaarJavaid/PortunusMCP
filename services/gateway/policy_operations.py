"""Crash-recoverable active-policy file promotion (ROADMAP item 42)."""

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway.db import AuditLog

JOURNAL_NAME = ".policy-operation.json"
PENDING_NAME = ".policy-operation.pending.yaml"


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_bytes(data)
    temporary.chmod(mode)
    with temporary.open("rb") as stream:
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@dataclass(frozen=True)
class PolicyOperation:
    operation_id: str
    kind: str
    activated_by: str
    old_version: int
    new_version: int
    content_hash: str
    phase: str
    audit_seq: int | None = None


class PolicyOperationStore:
    def __init__(self, active_path: str) -> None:
        self.active_path = Path(active_path)
        self.root = self.active_path.parent
        self.journal_path = self.root / JOURNAL_NAME
        self.pending_path = self.root / PENDING_NAME
        self.blocked = False

    @property
    def manual_candidate_path(self) -> Path:
        return self.active_path.with_name(f"{self.active_path.stem}.next{self.active_path.suffix}")

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self.active_path.chmod(0o600)

    def read_journal(self) -> PolicyOperation | None:
        if not self.journal_path.exists():
            return None
        data: dict[str, Any] = json.loads(self.journal_path.read_text())
        return PolicyOperation(**data)

    def _write_journal(self, operation: PolicyOperation) -> None:
        _atomic_write(self.journal_path, json.dumps(asdict(operation), sort_keys=True).encode())

    def prepare(
        self,
        raw: bytes,
        *,
        kind: str,
        activated_by: str,
        old_version: int,
        new_version: int,
    ) -> PolicyOperation:
        if self.journal_path.exists():
            raise RuntimeError("policy operation recovery is pending")
        _atomic_write(self.pending_path, raw)
        operation = PolicyOperation(
            operation_id=uuid.uuid4().hex,
            kind=kind,
            activated_by=activated_by,
            old_version=old_version,
            new_version=new_version,
            content_hash=hashlib.sha256(raw).hexdigest(),
            phase="prepared",
        )
        self._write_journal(operation)
        return operation

    def mark_handoff(self, operation: PolicyOperation, audit_seq: int) -> PolicyOperation:
        handed_off = PolicyOperation(
            **{**asdict(operation), "phase": "handoff", "audit_seq": audit_seq}
        )
        self._write_journal(handed_off)
        return handed_off

    def promote(self, operation: PolicyOperation) -> None:
        if hashlib.sha256(self.pending_path.read_bytes()).hexdigest() != operation.content_hash:
            raise ValueError("pending policy does not match operation journal")
        os.replace(self.pending_path, self.active_path)
        self.active_path.chmod(0o600)
        self._write_journal(PolicyOperation(**{**asdict(operation), "phase": "promoted"}))

    def finish(self) -> None:
        self.pending_path.unlink(missing_ok=True)
        self.journal_path.unlink(missing_ok=True)
        self.blocked = False

    def abort_before_handoff(self) -> None:
        self.pending_path.unlink(missing_ok=True)
        self.journal_path.unlink(missing_ok=True)

    async def recover(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)
        operation = self.read_journal()
        if operation is None:
            self.initialize()
            return
        async with sessionmaker() as session:
            result = await session.execute(
                select(AuditLog.seq).where(
                    AuditLog.event_type == "POLICY_ACTIVATED",
                    AuditLog.payload["operation_id"].as_string() == operation.operation_id,
                )
            )
            audit_seq = result.scalar_one_or_none()
        if audit_seq is None:
            self.abort_before_handoff()
            self.initialize()
            return
        if (
            not self.active_path.exists()
            or hashlib.sha256(self.active_path.read_bytes()).hexdigest() != operation.content_hash
        ):
            if not self.pending_path.exists():
                raise RuntimeError("audited policy activation has no pending policy file")
            self.promote(
                PolicyOperation(**{**asdict(operation), "phase": "handoff", "audit_seq": audit_seq})
            )
        self.finish()
        self.initialize()
