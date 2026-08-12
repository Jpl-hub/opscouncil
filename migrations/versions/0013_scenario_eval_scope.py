"""persist per-scenario evaluation results

Revision ID: 0013_scenario_eval_scope
Revises: 0012_evaluation_reports
Create Date: 2026-07-14 19:15:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0013_scenario_eval_scope"
down_revision: Union[str, Sequence[str], None] = "0012_evaluation_reports"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "evaluation_reports",
        sa.Column("scope_key", sa.String(length=128), nullable=True),
    )
    op.create_index(
        "ix_evaluation_reports_scope_key",
        "evaluation_reports",
        ["scope_key"],
    )
    op.create_index(
        "ix_evaluation_reports_scope_latest",
        "evaluation_reports",
        ["report_type", "scope_key", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_evaluation_reports_scope_latest", table_name="evaluation_reports")
    op.drop_index("ix_evaluation_reports_scope_key", table_name="evaluation_reports")
    op.drop_column("evaluation_reports", "scope_key")
