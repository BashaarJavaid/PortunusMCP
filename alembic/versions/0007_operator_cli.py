"""Operator queues and rotatable audit signing keys (ROADMAP item 42).

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # key_id stays nullable until the gateway verifies every historical signature
    # with the current key and backfills the fingerprint during first upgraded boot.
    op.add_column("audit_log", sa.Column("key_id", sa.Text(), nullable=True))
    op.add_column(
        "tool_baselines", sa.Column("flagged_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.execute(
        """
        UPDATE tool_baselines
        SET flagged_at = now()
        WHERE suspicious IS TRUE OR observed_hash IS NOT NULL
        """
    )


def downgrade() -> None:
    connection = op.get_bind()
    key_count = connection.execute(
        sa.text("SELECT count(DISTINCT key_id) FROM audit_log WHERE key_id IS NOT NULL")
    ).scalar_one()
    if key_count > 1:
        raise RuntimeError(
            "refusing item-42 downgrade: the audit chain uses multiple signing keys; "
            "export and preserve the chain before downgrading"
        )
    op.drop_column("tool_baselines", "flagged_at")
    op.drop_column("audit_log", "key_id")
