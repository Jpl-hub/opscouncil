"""persist action safety cases

Revision ID: 0018_action_safety_cases
Revises: 0017_cross_turn_risk_chain
Create Date: 2026-07-29 02:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0018_action_safety_cases"
down_revision: Union[str, Sequence[str], None] = "0017_cross_turn_risk_chain"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "action_safety_cases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("proposal_id", sa.Integer(), nullable=False),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("risk_level", sa.String(length=8), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("action_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("scope_json", sa.JSON(), nullable=False),
        sa.Column("preconditions_json", sa.JSON(), nullable=False),
        sa.Column("postconditions_json", sa.JSON(), nullable=False),
        sa.Column("verifier_tool", sa.String(length=128), nullable=False),
        sa.Column("rollback_strategy_json", sa.JSON(), nullable=False),
        sa.Column("evidence_refs_json", sa.JSON(), nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=False),
        sa.Column("case_hash", sa.String(length=64), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pre_verifier_call_id", sa.Integer(), nullable=True),
        sa.Column("execution_call_id", sa.Integer(), nullable=True),
        sa.Column("post_verifier_call_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ("
            "'READY', 'APPROVED', 'EXECUTING', 'VERIFIED', 'BLOCKED', "
            "'FAILED', 'NEEDS_OPERATOR', 'REJECTED', 'REVOKED'"
            ")",
            name="ck_action_safety_cases_status",
        ),
        sa.ForeignKeyConstraint(
            ["execution_call_id"],
            ["tool_calls.id"],
        ),
        sa.ForeignKeyConstraint(
            ["post_verifier_call_id"],
            ["tool_calls.id"],
        ),
        sa.ForeignKeyConstraint(
            ["pre_verifier_call_id"],
            ["tool_calls.id"],
        ),
        sa.ForeignKeyConstraint(
            ["proposal_id"],
            ["action_proposals.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("proposal_id"),
    )
    op.create_index(
        op.f("ix_action_safety_cases_task_id"),
        "action_safety_cases",
        ["task_id"],
    )
    op.create_index(
        op.f("ix_action_safety_cases_proposal_id"),
        "action_safety_cases",
        ["proposal_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_action_safety_cases_tool_name"),
        "action_safety_cases",
        ["tool_name"],
    )
    op.create_index(
        op.f("ix_action_safety_cases_risk_level"),
        "action_safety_cases",
        ["risk_level"],
    )
    op.create_index(
        op.f("ix_action_safety_cases_status"),
        "action_safety_cases",
        ["status"],
    )
    op.create_index(
        op.f("ix_action_safety_cases_action_fingerprint"),
        "action_safety_cases",
        ["action_fingerprint"],
    )
    op.create_index(
        op.f("ix_action_safety_cases_case_hash"),
        "action_safety_cases",
        ["case_hash"],
    )
    op.create_index(
        "ix_action_safety_cases_task_status",
        "action_safety_cases",
        ["task_id", "status", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_action_safety_cases_task_status",
        table_name="action_safety_cases",
    )
    op.drop_index(
        op.f("ix_action_safety_cases_case_hash"),
        table_name="action_safety_cases",
    )
    op.drop_index(
        op.f("ix_action_safety_cases_action_fingerprint"),
        table_name="action_safety_cases",
    )
    op.drop_index(
        op.f("ix_action_safety_cases_status"),
        table_name="action_safety_cases",
    )
    op.drop_index(
        op.f("ix_action_safety_cases_risk_level"),
        table_name="action_safety_cases",
    )
    op.drop_index(
        op.f("ix_action_safety_cases_tool_name"),
        table_name="action_safety_cases",
    )
    op.drop_index(
        op.f("ix_action_safety_cases_proposal_id"),
        table_name="action_safety_cases",
    )
    op.drop_index(
        op.f("ix_action_safety_cases_task_id"),
        table_name="action_safety_cases",
    )
    op.drop_table("action_safety_cases")
