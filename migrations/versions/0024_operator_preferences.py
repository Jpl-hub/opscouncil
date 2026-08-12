"""add governed operator preference profiles

Revision ID: 0024_operator_preferences
Revises: 0023_memory_qualification
Create Date: 2026-07-30 11:45:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0024_operator_preferences"
down_revision: Union[str, Sequence[str], None] = "0023_memory_qualification"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operator_preference_profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("actor_key", sa.String(length=128), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "summary_density",
            sa.String(length=16),
            server_default="BALANCED",
            nullable=False,
        ),
        sa.Column(
            "evidence_view",
            sa.String(length=16),
            server_default="CORE",
            nullable=False,
        ),
        sa.Column(
            "notification_route",
            sa.String(length=16),
            server_default="WEB",
            nullable=False,
        ),
        sa.Column(
            "service_focus_json",
            sa.JSON(),
            server_default=sa.text("'[]'"),
            nullable=False,
        ),
        sa.Column(
            "learning_signals_json",
            sa.JSON(),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column(
            "learned_intents_json",
            sa.JSON(),
            server_default=sa.text("'[]'"),
            nullable=False,
        ),
        sa.Column(
            "change_log_json",
            sa.JSON(),
            server_default=sa.text("'[]'"),
            nullable=False,
        ),
        sa.Column("last_learning_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "version >= 1",
            name="ck_operator_preference_profiles_version",
        ),
        sa.CheckConstraint(
            "summary_density IN ('COMPACT', 'BALANCED', 'DETAILED')",
            name="ck_operator_preference_profiles_summary_density",
        ),
        sa.CheckConstraint(
            "evidence_view IN ('CORE', 'ALL')",
            name="ck_operator_preference_profiles_evidence_view",
        ),
        sa.CheckConstraint(
            "notification_route IN ('WEB', 'FEISHU', 'BOTH')",
            name="ck_operator_preference_profiles_notification_route",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "actor_key",
            name="uq_operator_preference_profiles_actor",
        ),
    )
    op.create_index(
        "ix_operator_preference_profiles_actor_key",
        "operator_preference_profiles",
        ["actor_key"],
        unique=False,
    )
    op.create_index(
        "ix_operator_preference_profiles_updated",
        "operator_preference_profiles",
        ["updated_at", "actor_key"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_operator_preference_profiles_updated",
        table_name="operator_preference_profiles",
    )
    op.drop_index(
        "ix_operator_preference_profiles_actor_key",
        table_name="operator_preference_profiles",
    )
    op.drop_table("operator_preference_profiles")
