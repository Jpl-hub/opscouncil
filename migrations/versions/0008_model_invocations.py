"""model invocation observability

Revision ID: 0008_model_invocations
Revises: 0007_feishu_channel
Create Date: 2026-07-12 23:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0008_model_invocations"
down_revision: Union[str, Sequence[str], None] = "0007_feishu_channel"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "model_invocations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=False),
        sa.Column("stage", sa.String(length=64), nullable=False),
        sa.Column("operation", sa.String(length=16), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("total_tokens", sa.Integer(), nullable=True),
        sa.Column("finish_reason", sa.String(length=64), nullable=True),
        sa.Column("error_category", sa.String(length=64), nullable=True),
        sa.Column("prompt_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "operation IN ('CHAT', 'EMBEDDING', 'RERANK')",
            name="ck_model_invocations_operation",
        ),
        sa.CheckConstraint(
            "status IN ('SUCCEEDED', 'FAILED')",
            name="ck_model_invocations_status",
        ),
        sa.CheckConstraint("duration_ms >= 0", name="ck_model_invocations_duration"),
        sa.CheckConstraint(
            "input_tokens IS NULL OR input_tokens >= 0",
            name="ck_model_invocations_input_tokens",
        ),
        sa.CheckConstraint(
            "output_tokens IS NULL OR output_tokens >= 0",
            name="ck_model_invocations_output_tokens",
        ),
        sa.CheckConstraint(
            "total_tokens IS NULL OR total_tokens >= 0",
            name="ck_model_invocations_total_tokens",
        ),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_model_invocations_task_id"), "model_invocations", ["task_id"])
    op.create_index(op.f("ix_model_invocations_trace_id"), "model_invocations", ["trace_id"])
    op.create_index(op.f("ix_model_invocations_stage"), "model_invocations", ["stage"])
    op.create_index(op.f("ix_model_invocations_status"), "model_invocations", ["status"])
    op.create_index(
        "ix_model_invocations_trace_time",
        "model_invocations",
        ["trace_id", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_model_invocations_trace_time", table_name="model_invocations")
    op.drop_index(op.f("ix_model_invocations_status"), table_name="model_invocations")
    op.drop_index(op.f("ix_model_invocations_stage"), table_name="model_invocations")
    op.drop_index(op.f("ix_model_invocations_trace_id"), table_name="model_invocations")
    op.drop_index(op.f("ix_model_invocations_task_id"), table_name="model_invocations")
    op.drop_table("model_invocations")
