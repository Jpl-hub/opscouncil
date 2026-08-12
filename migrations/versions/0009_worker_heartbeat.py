"""worker runtime heartbeat

Revision ID: 0009_worker_heartbeat
Revises: 0008_model_invocations
Create Date: 2026-07-12 23:55:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0009_worker_heartbeat"
down_revision: Union[str, Sequence[str], None] = "0008_model_invocations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "worker_instances",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("pid > 0", name="ck_worker_instances_pid_positive"),
        sa.CheckConstraint(
            "status IN ('RUNNING', 'STOPPED')",
            name="ck_worker_instances_status",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_worker_instances_worker_id"), "worker_instances", ["worker_id"], unique=True)
    op.create_index(op.f("ix_worker_instances_status"), "worker_instances", ["status"])
    op.create_index(op.f("ix_worker_instances_last_seen_at"), "worker_instances", ["last_seen_at"])
    op.create_index(
        "ix_worker_instances_health",
        "worker_instances",
        ["status", "last_seen_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_worker_instances_health", table_name="worker_instances")
    op.drop_index(op.f("ix_worker_instances_last_seen_at"), table_name="worker_instances")
    op.drop_index(op.f("ix_worker_instances_status"), table_name="worker_instances")
    op.drop_index(op.f("ix_worker_instances_worker_id"), table_name="worker_instances")
    op.drop_table("worker_instances")
