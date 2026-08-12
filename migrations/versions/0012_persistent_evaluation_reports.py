"""persist benchmark and evaluation reports

Revision ID: 0012_evaluation_reports
Revises: 0011_feishu_task_results
Create Date: 2026-07-14 18:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0012_evaluation_reports"
down_revision: Union[str, Sequence[str], None] = "0011_feishu_task_results"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "evaluation_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("report_type", sa.String(length=32), nullable=False),
        sa.Column("report_id", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "report_type IN ('TOOL_PERFORMANCE', 'AGENT_ORCHESTRATION', 'SAFETY_GUARD', 'LAB_SCENARIO')",
            name="ck_evaluation_reports_type",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_id"),
    )
    op.create_index(
        "ix_evaluation_reports_created_at",
        "evaluation_reports",
        ["created_at"],
    )
    op.create_index(
        "ix_evaluation_reports_report_id",
        "evaluation_reports",
        ["report_id"],
        unique=True,
    )
    op.create_index(
        "ix_evaluation_reports_report_type",
        "evaluation_reports",
        ["report_type"],
    )
    op.create_index(
        "ix_evaluation_reports_latest",
        "evaluation_reports",
        ["report_type", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_evaluation_reports_latest", table_name="evaluation_reports")
    op.drop_index("ix_evaluation_reports_report_type", table_name="evaluation_reports")
    op.drop_index("ix_evaluation_reports_report_id", table_name="evaluation_reports")
    op.drop_index("ix_evaluation_reports_created_at", table_name="evaluation_reports")
    op.drop_table("evaluation_reports")
