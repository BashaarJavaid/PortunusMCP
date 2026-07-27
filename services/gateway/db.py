"""Async engine/session factory and ORM models (ARCHITECTURE.md §4.8 schema)."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    CHAR,
    BigInteger,
    DateTime,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from services.gateway.config import settings


class Base(DeclarativeBase):
    pass


class AuditLog(Base):
    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    prev_hash: Mapped[str] = mapped_column(CHAR(64))
    curr_hash: Mapped[str] = mapped_column(CHAR(64))
    # ECDSA-SHA256 (DER) over curr_hash, signed by the gateway's private key (item 11).
    signature: Mapped[bytes] = mapped_column(LargeBinary)
    # Nullable only for the item-42 verified startup backfill of historical rows.
    key_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    identity_id: Mapped[str] = mapped_column(Text)
    server_id: Mapped[str | None] = mapped_column(Text)
    tool_name: Mapped[str | None] = mapped_column(Text)
    policy_version: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    latency_ms: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        Index("idx_audit_identity", "identity_id", "timestamp"),
        Index("idx_audit_event", "event_type", "timestamp"),
        Index("idx_audit_policy_version", "policy_version"),
    )


class ToolBaseline(Base):
    """Accepted schema baseline per (server, tool) — the Drift Detector's trust anchor.
    observed_* holds the latest drifted schema (what re-approval promotes) and dedups
    drift events across polls."""

    __tablename__ = "tool_baselines"

    server_id: Mapped[str] = mapped_column(Text, primary_key=True)
    tool_name: Mapped[str] = mapped_column(Text, primary_key=True)
    approved_schema: Mapped[dict[str, Any]] = mapped_column(JSONB)
    approved_hash: Mapped[str] = mapped_column(CHAR(64))
    approved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    blocked: Mapped[bool] = mapped_column(default=False)
    observed_schema: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    observed_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    # Item 36b: the approved content matched the description heuristics — feeds the
    # suspicious_baseline risk factor; a flag, never a block.
    suspicious: Mapped[bool] = mapped_column(default=False, server_default=text("false"))
    # Oldest time this baseline entered either drift or suspicious review.
    flagged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Approval(Base):
    """Human-approval lifecycle row (§4.8, item 16): created when a call lands in
    HUMAN_APPROVAL_REQUIRED, tied to that decision's audit row. Postgres-backed so a
    gateway restart doesn't lose pending approvals. `consumed` enforces one-time use;
    `arguments_hash` is re-checked at redemption (TOCTOU, DENY_APPROVAL_MISMATCH)."""

    __tablename__ = "approvals"

    approval_id: Mapped[str] = mapped_column(Text, primary_key=True)
    audit_id: Mapped[int] = mapped_column(BigInteger)
    identity_id: Mapped[str] = mapped_column(Text)
    # Approvals are per-server (item 35): an approval granted for a tool on one
    # server must not redeem an identically-named tool on another.
    server_id: Mapped[str] = mapped_column(Text, server_default=text("'default'"))
    tool_name: Mapped[str] = mapped_column(Text)
    arguments_hash: Mapped[str] = mapped_column(CHAR(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(Text, default="pending")  # pending/approved/expired
    approved_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed: Mapped[bool] = mapped_column(default=False)

    __table_args__ = (Index("idx_approvals_status_expiry", "status", "expires_at"),)


class VerifierCheckpoint(Base):
    """Single-row (id=1) last_verified_seq checkpoint for the audit verifier daemon —
    verification resumes forward from here instead of rescanning from seq=1 (§4.8)."""

    __tablename__ = "audit_verifier_checkpoint"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    last_verified_seq: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()")
    )


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    version: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    content_hash: Mapped[str] = mapped_column(CHAR(64))
    activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    activated_by: Mapped[str] = mapped_column(Text)


engine = create_async_engine(settings.database_url)
async_session = async_sessionmaker(engine, expire_on_commit=False)
