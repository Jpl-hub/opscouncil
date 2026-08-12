"""incident recovery hysteresis

Revision ID: 0010_incident_hysteresis
Revises: 0009_worker_heartbeat
Create Date: 2026-07-13 00:35:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0010_incident_hysteresis"
down_revision: Union[str, Sequence[str], None] = "0009_worker_heartbeat"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.add_column(
            sa.Column(
                "healthy_streak",
                sa.Integer(),
                server_default=sa.text("0"),
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "recovery_target",
                sa.Integer(),
                server_default=sa.text("2"),
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column("last_healthy_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.create_check_constraint(
            "ck_incidents_healthy_streak",
            "healthy_streak >= 0",
        )
        batch_op.create_check_constraint(
            "ck_incidents_recovery_target",
            "recovery_target >= 1 AND recovery_target <= 12",
        )


def downgrade() -> None:
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.drop_constraint("ck_incidents_recovery_target", type_="check")
        batch_op.drop_constraint("ck_incidents_healthy_streak", type_="check")
        batch_op.drop_column("last_healthy_at")
        batch_op.drop_column("recovery_target")
        batch_op.drop_column("healthy_streak")
