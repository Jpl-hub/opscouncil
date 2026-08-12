"""cross-turn risk chain assessments

Revision ID: 0017_cross_turn_risk_chain
Revises: 0016_capability_snapshots
Create Date: 2026-07-29 00:25:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0017_cross_turn_risk_chain"
down_revision: Union[str, Sequence[str], None] = "0016_capability_snapshots"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "risk_chain_assessments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("conversation_id", sa.String(length=64), nullable=True),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("chain_type", sa.String(length=64), nullable=True),
        sa.Column("semantic_events_json", sa.JSON(), nullable=False),
        sa.Column("matched_task_ids_json", sa.JSON(), nullable=False),
        sa.Column("resource_refs_json", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('CLEAR', 'WATCH', 'BLOCKED')",
            name="ck_risk_chain_assessments_status",
        ),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name="ck_risk_chain_assessments_score",
        ),
        sa.ForeignKeyConstraint(
            ["conversation_id"],
            ["conversations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id"),
    )
    op.create_index(
        op.f("ix_risk_chain_assessments_task_id"),
        "risk_chain_assessments",
        ["task_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_risk_chain_assessments_conversation_id"),
        "risk_chain_assessments",
        ["conversation_id"],
    )
    op.create_index(
        op.f("ix_risk_chain_assessments_status"),
        "risk_chain_assessments",
        ["status"],
    )
    op.create_index(
        op.f("ix_risk_chain_assessments_created_at"),
        "risk_chain_assessments",
        ["created_at"],
    )
    op.create_index(
        "ix_risk_chain_assessments_conversation_latest",
        "risk_chain_assessments",
        ["conversation_id", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_risk_chain_assessments_conversation_latest",
        table_name="risk_chain_assessments",
    )
    op.drop_index(
        op.f("ix_risk_chain_assessments_created_at"),
        table_name="risk_chain_assessments",
    )
    op.drop_index(
        op.f("ix_risk_chain_assessments_status"),
        table_name="risk_chain_assessments",
    )
    op.drop_index(
        op.f("ix_risk_chain_assessments_conversation_id"),
        table_name="risk_chain_assessments",
    )
    op.drop_index(
        op.f("ix_risk_chain_assessments_task_id"),
        table_name="risk_chain_assessments",
    )
    op.drop_table("risk_chain_assessments")
