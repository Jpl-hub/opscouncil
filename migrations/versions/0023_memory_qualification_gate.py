"""add operational memory qualification gate

Revision ID: 0023_memory_qualification
Revises: 0022_service_expectations
Create Date: 2026-07-30 02:20:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0023_memory_qualification"
down_revision: Union[str, Sequence[str], None] = "0022_service_expectations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "operational_memories",
        sa.Column(
            "qualification_status",
            sa.String(length=16),
            server_default="PENDING",
            nullable=False,
        ),
    )
    op.add_column(
        "operational_memories",
        sa.Column(
            "qualification_report_json",
            sa.JSON(),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
    )
    op.add_column(
        "operational_memories",
        sa.Column(
            "qualified_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    with op.batch_alter_table("operational_memories") as batch_op:
        batch_op.create_check_constraint(
            "ck_operational_memories_qualification",
            "qualification_status IN ('PENDING', 'QUALIFIED', 'FAILED')",
        )
    op.create_index(
        op.f("ix_operational_memories_qualification_status"),
        "operational_memories",
        ["qualification_status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_operational_memories_qualification_status"),
        table_name="operational_memories",
    )
    with op.batch_alter_table("operational_memories") as batch_op:
        batch_op.drop_constraint(
            "ck_operational_memories_qualification",
            type_="check",
        )
    op.drop_column("operational_memories", "qualified_at")
    op.drop_column("operational_memories", "qualification_report_json")
    op.drop_column("operational_memories", "qualification_status")
