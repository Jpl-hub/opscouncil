"""add append-only service expectation records

Revision ID: 0022_service_expectations
Revises: 0021_safety_policy_replay
Create Date: 2026-07-29 18:05:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0022_service_expectations"
down_revision: Union[str, Sequence[str], None] = "0021_safety_policy_replay"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "service_expectations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("host_key", sa.String(length=256), nullable=False),
        sa.Column("unit_name", sa.String(length=256), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("record_status", sa.String(length=16), nullable=False),
        sa.Column("expected_active_state", sa.String(length=16), nullable=False),
        sa.Column("service_owner", sa.String(length=256), nullable=False),
        sa.Column("criticality", sa.String(length=16), nullable=False),
        sa.Column("environment", sa.String(length=16), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("source_ref", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "criticality IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name="ck_service_expectations_criticality",
        ),
        sa.CheckConstraint(
            "environment IN ('PRODUCTION', 'STAGING', 'TEST', 'DEVELOPMENT')",
            name="ck_service_expectations_environment",
        ),
        sa.CheckConstraint(
            "expected_active_state IN ('active', 'inactive')",
            name="ck_service_expectations_active_state",
        ),
        sa.CheckConstraint(
            "record_status IN ('ACTIVE', 'RETIRED')",
            name="ck_service_expectations_record_status",
        ),
        sa.CheckConstraint("version >= 1", name="ck_service_expectations_version"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "host_key",
            "unit_name",
            "version",
            name="uq_service_expectations_host_unit_version",
        ),
    )
    op.create_index(
        "ix_service_expectations_criticality",
        "service_expectations",
        ["criticality"],
        unique=False,
    )
    op.create_index(
        "ix_service_expectations_host_key",
        "service_expectations",
        ["host_key"],
        unique=False,
    )
    op.create_index(
        "ix_service_expectations_lookup",
        "service_expectations",
        ["host_key", "unit_name", "version"],
        unique=False,
    )
    op.create_index(
        "ix_service_expectations_record_status",
        "service_expectations",
        ["record_status"],
        unique=False,
    )
    op.create_index(
        "ix_service_expectations_unit_name",
        "service_expectations",
        ["unit_name"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_service_expectations_unit_name", table_name="service_expectations")
    op.drop_index("ix_service_expectations_record_status", table_name="service_expectations")
    op.drop_index("ix_service_expectations_lookup", table_name="service_expectations")
    op.drop_index("ix_service_expectations_host_key", table_name="service_expectations")
    op.drop_index("ix_service_expectations_criticality", table_name="service_expectations")
    op.drop_table("service_expectations")
