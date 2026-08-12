"""governed operational memory

Revision ID: 0015_governed_operational_memory
Revises: 0014_config_baseline_scope
Create Date: 2026-07-28 23:05:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0015_governed_operational_memory"
down_revision: Union[str, Sequence[str], None] = "0014_config_baseline_scope"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "operational_memories",
        sa.Column(
            "memory_kind",
            sa.String(length=32),
            server_default="INCIDENT_CASE",
            nullable=False,
        ),
    )
    op.add_column(
        "operational_memories",
        sa.Column(
            "symptom_fingerprint",
            sa.String(length=64),
            server_default="",
            nullable=False,
        ),
    )
    op.add_column(
        "operational_memories",
        sa.Column(
            "applicability_json",
            sa.JSON(),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
    )
    op.add_column(
        "operational_memories",
        sa.Column(
            "confidence_score",
            sa.Integer(),
            server_default="50",
            nullable=False,
        ),
    )
    op.add_column(
        "operational_memories",
        sa.Column(
            "retrieval_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "operational_memories",
        sa.Column(
            "helpful_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "operational_memories",
        sa.Column(
            "incorrect_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "operational_memories",
        sa.Column(
            "valid_from",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.add_column(
        "operational_memories",
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "operational_memories",
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "operational_memories",
        sa.Column("forgotten_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "operational_memories",
        sa.Column("forgotten_by", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "operational_memories",
        sa.Column("forget_reason", sa.Text(), nullable=True),
    )

    with op.batch_alter_table("operational_memories") as batch_op:
        batch_op.drop_constraint("ck_operational_memories_status", type_="check")
        batch_op.create_check_constraint(
            "ck_operational_memories_status",
            "status IN ('DRAFT', 'CONFLICTED', 'CONFIRMED', 'CORRECTED', 'INACTIVE', 'FORGOTTEN')",
        )
        batch_op.create_check_constraint(
            "ck_operational_memories_kind",
            "memory_kind IN ('INCIDENT_CASE', 'OPERATOR_PREFERENCE', 'PROCEDURE_DRAFT')",
        )
        batch_op.create_check_constraint(
            "ck_operational_memories_confidence",
            "confidence_score >= 0 AND confidence_score <= 100",
        )
        batch_op.create_check_constraint(
            "ck_operational_memories_feedback_counts",
            "retrieval_count >= 0 AND helpful_count >= 0 AND incorrect_count >= 0",
        )

    op.create_index(
        op.f("ix_operational_memories_memory_kind"),
        "operational_memories",
        ["memory_kind"],
    )
    op.create_index(
        op.f("ix_operational_memories_symptom_fingerprint"),
        "operational_memories",
        ["symptom_fingerprint"],
    )
    op.create_index(
        "ix_operational_memories_governance",
        "operational_memories",
        ["status", "memory_kind", "symptom_fingerprint"],
    )

    op.create_table(
        "operational_memory_relations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source_memory_id", sa.Integer(), nullable=False),
        sa.Column("target_memory_id", sa.Integer(), nullable=False),
        sa.Column("relation", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("confidence_score", sa.Integer(), server_default="100", nullable=False),
        sa.Column(
            "detected_by",
            sa.String(length=32),
            server_default="governance_policy",
            nullable=False,
        ),
        sa.Column("status", sa.String(length=16), server_default="PENDING", nullable=False),
        sa.Column("resolution", sa.Text(), nullable=True),
        sa.Column("resolved_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "source_memory_id <> target_memory_id",
            name="ck_operational_memory_relation_distinct",
        ),
        sa.CheckConstraint(
            "relation IN ('SUPPORTS', 'DUPLICATES', 'CONFLICTS', 'SUPERSEDES')",
            name="ck_operational_memory_relation_type",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING', 'RESOLVED', 'DISMISSED')",
            name="ck_operational_memory_relation_status",
        ),
        sa.CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_operational_memory_relation_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["source_memory_id"],
            ["operational_memories.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_memory_id"],
            ["operational_memories.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_memory_id",
            "target_memory_id",
            "relation",
            name="uq_operational_memory_relation",
        ),
    )
    op.create_index(
        op.f("ix_operational_memory_relations_source_memory_id"),
        "operational_memory_relations",
        ["source_memory_id"],
    )
    op.create_index(
        op.f("ix_operational_memory_relations_target_memory_id"),
        "operational_memory_relations",
        ["target_memory_id"],
    )
    op.create_index(
        op.f("ix_operational_memory_relations_relation"),
        "operational_memory_relations",
        ["relation"],
    )
    op.create_index(
        op.f("ix_operational_memory_relations_status"),
        "operational_memory_relations",
        ["status"],
    )
    op.create_index(
        "ix_operational_memory_relations_pending",
        "operational_memory_relations",
        ["status", "relation", "created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_operational_memory_relations_pending",
        table_name="operational_memory_relations",
    )
    op.drop_index(
        op.f("ix_operational_memory_relations_status"),
        table_name="operational_memory_relations",
    )
    op.drop_index(
        op.f("ix_operational_memory_relations_relation"),
        table_name="operational_memory_relations",
    )
    op.drop_index(
        op.f("ix_operational_memory_relations_target_memory_id"),
        table_name="operational_memory_relations",
    )
    op.drop_index(
        op.f("ix_operational_memory_relations_source_memory_id"),
        table_name="operational_memory_relations",
    )
    op.drop_table("operational_memory_relations")

    op.drop_index("ix_operational_memories_governance", table_name="operational_memories")
    op.drop_index(
        op.f("ix_operational_memories_symptom_fingerprint"),
        table_name="operational_memories",
    )
    op.drop_index(
        op.f("ix_operational_memories_memory_kind"),
        table_name="operational_memories",
    )

    with op.batch_alter_table("operational_memories") as batch_op:
        batch_op.drop_constraint("ck_operational_memories_feedback_counts", type_="check")
        batch_op.drop_constraint("ck_operational_memories_confidence", type_="check")
        batch_op.drop_constraint("ck_operational_memories_kind", type_="check")
        batch_op.drop_constraint("ck_operational_memories_status", type_="check")
        batch_op.create_check_constraint(
            "ck_operational_memories_status",
            "status IN ('DRAFT', 'CONFIRMED', 'CORRECTED', 'INACTIVE')",
        )
        batch_op.drop_column("forget_reason")
        batch_op.drop_column("forgotten_by")
        batch_op.drop_column("forgotten_at")
        batch_op.drop_column("last_verified_at")
        batch_op.drop_column("valid_until")
        batch_op.drop_column("valid_from")
        batch_op.drop_column("incorrect_count")
        batch_op.drop_column("helpful_count")
        batch_op.drop_column("retrieval_count")
        batch_op.drop_column("confidence_score")
        batch_op.drop_column("applicability_json")
        batch_op.drop_column("symptom_fingerprint")
        batch_op.drop_column("memory_kind")
