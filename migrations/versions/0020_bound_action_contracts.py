"""bind approved actions to immutable execution contracts

Revision ID: 0020_bound_action_contracts
Revises: 0019_memory_evaluations
Create Date: 2026-07-29 11:20:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0020_bound_action_contracts"
down_revision: Union[str, Sequence[str], None] = "0019_memory_evaluations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "action_safety_cases",
        sa.Column("bound_action_json", sa.JSON(), nullable=True),
    )

    proposals = sa.table(
        "action_proposals",
        sa.column("id", sa.Integer()),
        sa.column("task_id", sa.Integer()),
        sa.column("tool_name", sa.String()),
        sa.column("input_json", sa.JSON()),
        sa.column("risk_level", sa.String()),
    )
    safety_cases = sa.table(
        "action_safety_cases",
        sa.column("proposal_id", sa.Integer()),
        sa.column("bound_action_json", sa.JSON()),
    )
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(
            proposals.c.id,
            proposals.c.task_id,
            proposals.c.tool_name,
            proposals.c.input_json,
            proposals.c.risk_level,
        )
    ).mappings()
    for row in rows:
        connection.execute(
            safety_cases.update()
            .where(safety_cases.c.proposal_id == row["id"])
            .values(
                bound_action_json={
                    "proposal_id": row["id"],
                    "task_id": row["task_id"],
                    "tool_name": row["tool_name"],
                    "input": row["input_json"] or {},
                    "risk_level": row["risk_level"],
                }
            )
        )

    with op.batch_alter_table("action_safety_cases") as batch_op:
        batch_op.alter_column(
            "bound_action_json",
            existing_type=sa.JSON(),
            nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("action_safety_cases") as batch_op:
        batch_op.drop_column("bound_action_json")
