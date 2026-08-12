"""isolate live and lab configuration baselines

Revision ID: 0014_config_baseline_scope
Revises: 0013_scenario_eval_scope
Create Date: 2026-07-14 22:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0014_config_baseline_scope"
down_revision: Union[str, Sequence[str], None] = "0013_scenario_eval_scope"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "config_baselines",
        sa.Column(
            "scope",
            sa.String(length=16),
            server_default="LIVE",
            nullable=False,
        ),
    )
    op.execute(
        sa.text(
            "UPDATE config_baselines SET scope = 'LAB' "
            "WHERE created_by = 'kylinopsbench' "
            "OR CAST(paths_json AS TEXT) LIKE '%/tmp/opscouncil-lab/%'"
        )
    )
    with op.batch_alter_table("config_baselines") as batch_op:
        batch_op.create_check_constraint(
            "ck_config_baselines_scope",
            "scope IN ('LIVE', 'LAB')",
        )
    op.create_index(
        "ix_config_baselines_scope",
        "config_baselines",
        ["scope"],
    )
    op.create_index(
        "ix_config_baselines_scope_latest",
        "config_baselines",
        ["scope", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_config_baselines_scope_latest", table_name="config_baselines")
    op.drop_index("ix_config_baselines_scope", table_name="config_baselines")
    with op.batch_alter_table("config_baselines") as batch_op:
        batch_op.drop_constraint("ck_config_baselines_scope", type_="check")
        batch_op.drop_column("scope")
