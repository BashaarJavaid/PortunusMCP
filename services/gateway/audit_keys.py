"""Fingerprint-keyed audit signing key storage and crash recovery (item 42)."""

import json
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway import signing
from services.gateway.db import AuditLog

JOURNAL_NAME = ".rotation.json"
PENDING_NAME = ".audit_signing_key.pending.pem"


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
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
class Rotation:
    operation_id: str
    old_key_id: str
    new_key_id: str
    approved_by: str
    phase: str
    audit_seq: int | None = None


class AuditKeyStore:
    def __init__(self, private_path: str, public_dir: str) -> None:
        self.private_path = Path(private_path)
        self.root = self.private_path.parent
        self.public_dir = Path(public_dir)
        self.journal_path = self.root / JOURNAL_NAME
        self.pending_path = self.root / PENDING_NAME

    def initialize(self) -> tuple[ec.EllipticCurvePrivateKey, str]:
        self.root.mkdir(parents=True, exist_ok=True)
        self.public_dir.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self.public_dir.chmod(0o700)
        self.private_path.chmod(0o600)
        private_key = signing.load_private_key(str(self.private_path))
        key_id = signing.key_id(private_key.public_key())
        self.ensure_public(private_key.public_key())
        return private_key, key_id

    def public_path(self, key_id: str) -> Path:
        prefix, separator, digest = key_id.partition(":")
        if prefix != "sha256" or separator != ":" or len(digest) != 64:
            raise ValueError(f"invalid audit key id {key_id!r}")
        int(digest, 16)
        return self.public_dir / f"{digest}.pub.pem"

    def ensure_public(self, public_key: ec.EllipticCurvePublicKey) -> Path:
        key_id = signing.key_id(public_key)
        path = self.public_path(key_id)
        expected = signing.public_pem(public_key)
        if path.exists():
            if path.read_bytes() != expected:
                raise ValueError(f"public key file {path} does not match {key_id}")
            if stat.S_IMODE(path.stat().st_mode) != 0o444:
                path.chmod(0o444)
            return path
        try:
            with path.open("xb") as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            if path.read_bytes() != expected:
                raise ValueError(f"public key file {path} does not match {key_id}") from None
        path.chmod(0o444)
        return path

    def load_public(self, key_id: str) -> ec.EllipticCurvePublicKey:
        public_key = signing.load_public_key(str(self.public_path(key_id)))
        if signing.key_id(public_key) != key_id:
            raise ValueError(f"public key fingerprint mismatch for {key_id}")
        return public_key

    def public_count(self) -> int:
        return sum(1 for path in self.public_dir.glob("*.pub.pem") if path.is_file())

    def read_journal(self) -> Rotation | None:
        if not self.journal_path.exists():
            return None
        data: dict[str, Any] = json.loads(self.journal_path.read_text())
        return Rotation(**data)

    def _write_journal(self, rotation: Rotation) -> None:
        _atomic_write(
            self.journal_path,
            json.dumps(rotation.__dict__, sort_keys=True).encode(),
            0o600,
        )

    def prepare(self, approved_by: str) -> tuple[Rotation, ec.EllipticCurvePrivateKey]:
        if self.journal_path.exists():
            raise RuntimeError("audit key rotation recovery is pending")
        current = signing.load_private_key(str(self.private_path))
        new_private = signing.generate_private_key()
        new_key_id = signing.key_id(new_private.public_key())
        self.ensure_public(new_private.public_key())
        _atomic_write(self.pending_path, signing.private_pem(new_private), 0o600)
        rotation = Rotation(
            operation_id=uuid.uuid4().hex,
            old_key_id=signing.key_id(current.public_key()),
            new_key_id=new_key_id,
            approved_by=approved_by,
            phase="prepared",
        )
        self._write_journal(rotation)
        return rotation, new_private

    def mark_handoff(self, rotation: Rotation, audit_seq: int) -> Rotation:
        handed_off = Rotation(**{**rotation.__dict__, "phase": "handoff", "audit_seq": audit_seq})
        self._write_journal(handed_off)
        return handed_off

    def promote(self, rotation: Rotation) -> None:
        if signing.key_id(signing.load_private_key(str(self.pending_path)).public_key()) != (
            rotation.new_key_id
        ):
            raise ValueError("pending audit private key does not match rotation journal")
        os.replace(self.pending_path, self.private_path)
        self.private_path.chmod(0o600)
        self._write_journal(Rotation(**{**rotation.__dict__, "phase": "promoted"}))

    def finish(self) -> None:
        self.pending_path.unlink(missing_ok=True)
        self.journal_path.unlink(missing_ok=True)

    async def recover(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> tuple[ec.EllipticCurvePrivateKey, str]:
        rotation = self.read_journal()
        if rotation is None:
            return self.initialize()
        async with sessionmaker() as session:
            result = await session.execute(
                select(AuditLog.seq).where(
                    AuditLog.event_type == "AUDIT_KEY_ROTATED",
                    AuditLog.payload["operation_id"].as_string() == rotation.operation_id,
                )
            )
            handoff_seq = result.scalar_one_or_none()
        if handoff_seq is None:
            self.pending_path.unlink(missing_ok=True)
            self.journal_path.unlink(missing_ok=True)
            return self.initialize()
        active = signing.load_private_key(str(self.private_path))
        if signing.key_id(active.public_key()) != rotation.new_key_id:
            if not self.pending_path.exists():
                raise RuntimeError("audited key rotation has no pending private key")
            self.promote(
                Rotation(**{**rotation.__dict__, "phase": "handoff", "audit_seq": handoff_seq})
            )
        self.finish()
        return self.initialize()
