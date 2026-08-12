"""persist safety policy replay context

Revision ID: 0021_safety_policy_replay
Revises: 0020_bound_action_contracts
Create Date: 2026-07-29 16:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0021_safety_policy_replay"
down_revision: Union[str, Sequence[str], None] = "0020_bound_action_contracts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "safety_reviews",
        sa.Column(
            "policy_version",
            sa.String(length=64),
            nullable=False,
            server_default="legacy-unversioned",
        ),
    )
    op.add_column(
        "safety_reviews",
        sa.Column(
            "policy_digest",
            sa.String(length=64),
            nullable=False,
            server_default="",
        ),
    )
    op.add_column(
        "safety_reviews",
        sa.Column(
            "subject_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )


def downgrade() -> None:
    with op.batch_alter_table("safety_reviews") as batch_op:
        batch_op.drop_column("subject_json")
        batch_op.drop_column("policy_digest")
        batch_op.drop_column("policy_version")
