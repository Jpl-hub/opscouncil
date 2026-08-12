"""add approved network listener expectations to service catalog

Revision ID: 0025_listener_expectations
Revises: 0024_operator_preferences
Create Date: 2026-07-30 13:20:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0025_listener_expectations"
down_revision: Union[str, Sequence[str], None] = "0024_operator_preferences"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "service_expectations",
        sa.Column(
            "listener_expectations_json",
            sa.JSON(),
            server_default=sa.text("'[]'"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("service_expectations", "listener_expectations_json")
