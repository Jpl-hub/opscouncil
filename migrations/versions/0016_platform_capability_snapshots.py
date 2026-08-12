"""persist task-bound platform capability snapshots

Revision ID: 0016_capability_snapshots
Revises: 0015_governed_operational_memory
Create Date: 2026-07-28 23:40:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0016_capability_snapshots"
down_revision: Union[str, Sequence[str], None] = "0015_governed_operational_memory"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "platform_capability_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("machine", sa.String(length=128), nullable=False),
        sa.Column("kernel", sa.String(length=255), nullable=False),
        sa.Column("os_name", sa.String(length=255), nullable=False),
        sa.Column("profile_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('SUPPORTED', 'DEGRADED', 'UNAVAILABLE')",
            name="ck_platform_capability_snapshots_status",
        ),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id"),
    )
    op.create_index(
        op.f("ix_platform_capability_snapshots_task_id"),
        "platform_capability_snapshots",
        ["task_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_platform_capability_snapshots_hostname"),
        "platform_capability_snapshots",
        ["hostname"],
    )
    op.create_index(
        op.f("ix_platform_capability_snapshots_status"),
        "platform_capability_snapshots",
        ["status"],
    )
    op.create_index(
        op.f("ix_platform_capability_snapshots_payload_hash"),
        "platform_capability_snapshots",
        ["payload_hash"],
    )
    op.create_index(
        op.f("ix_platform_capability_snapshots_created_at"),
        "platform_capability_snapshots",
        ["created_at"],
    )
    op.create_index(
        "ix_platform_capability_snapshots_node_latest",
        "platform_capability_snapshots",
        ["hostname", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_platform_capability_snapshots_node_latest",
        table_name="platform_capability_snapshots",
    )
    op.drop_index(
        op.f("ix_platform_capability_snapshots_created_at"),
        table_name="platform_capability_snapshots",
    )
    op.drop_index(
        op.f("ix_platform_capability_snapshots_payload_hash"),
        table_name="platform_capability_snapshots",
    )
    op.drop_index(
        op.f("ix_platform_capability_snapshots_status"),
        table_name="platform_capability_snapshots",
    )
    op.drop_index(
        op.f("ix_platform_capability_snapshots_hostname"),
        table_name="platform_capability_snapshots",
    )
    op.drop_index(
        op.f("ix_platform_capability_snapshots_task_id"),
        table_name="platform_capability_snapshots",
    )
    op.drop_table("platform_capability_snapshots")
