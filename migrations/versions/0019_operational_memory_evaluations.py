"""allow persistent operational memory evaluation reports

Revision ID: 0019_memory_evaluations
Revises: 0018_action_safety_cases
Create Date: 2026-07-29 02:30:00.000000
"""
from typing import Sequence, Union

from alembic import op


revision: str = "0019_memory_evaluations"
down_revision: Union[str, Sequence[str], None] = "0018_action_safety_cases"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_OLD_VALUES = (
    "'TOOL_PERFORMANCE', 'AGENT_ORCHESTRATION', 'SAFETY_GUARD', 'LAB_SCENARIO'"
)
_NEW_VALUES = (
    "'TOOL_PERFORMANCE', 'AGENT_ORCHESTRATION', 'SAFETY_GUARD', "
    "'LAB_SCENARIO', 'OPERATIONAL_MEMORY'"
)


def upgrade() -> None:
    with op.batch_alter_table("evaluation_reports") as batch_op:
        batch_op.drop_constraint("ck_evaluation_reports_type", type_="check")
        batch_op.create_check_constraint(
            "ck_evaluation_reports_type",
            f"report_type IN ({_NEW_VALUES})",
        )


def downgrade() -> None:
    op.execute("DELETE FROM evaluation_reports WHERE report_type = 'OPERATIONAL_MEMORY'")
    with op.batch_alter_table("evaluation_reports") as batch_op:
        batch_op.drop_constraint("ck_evaluation_reports_type", type_="check")
        batch_op.create_check_constraint(
            "ck_evaluation_reports_type",
            f"report_type IN ({_OLD_VALUES})",
        )
