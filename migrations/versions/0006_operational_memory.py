"""operational memory

Revision ID: 0006_operational_memory
Revises: 0005_hybrid_knowledge
Create Date: 2026-07-12 17:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
from pgvector.sqlalchemy import Vector
import sqlalchemy as sa


revision: str = "0006_operational_memory"
down_revision: Union[str, Sequence[str], None] = "0005_hybrid_knowledge"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operational_memories",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("memory_key", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("source_task_id", sa.Integer(), nullable=False),
        sa.Column("supersedes_id", sa.Integer(), nullable=True),
        sa.Column("host_scope", sa.String(length=256), nullable=False),
        sa.Column("service_scope", sa.String(length=256), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("root_cause", sa.Text(), nullable=False),
        sa.Column("resolution", sa.Text(), nullable=False),
        sa.Column("evidence_refs_json", sa.JSON(), nullable=False),
        sa.Column("search_text", sa.Text(), nullable=False),
        sa.Column("embedding", Vector(dim=1024), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("confirmed_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("version >= 1", name="ck_operational_memories_version"),
        sa.CheckConstraint(
            "status IN ('DRAFT', 'CONFIRMED', 'CORRECTED', 'INACTIVE')",
            name="ck_operational_memories_status",
        ),
        sa.ForeignKeyConstraint(["source_task_id"], ["tasks.id"]),
        sa.ForeignKeyConstraint(["supersedes_id"], ["operational_memories.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("memory_key", "version", name="uq_operational_memory_version"),
    )
    op.create_index(op.f("ix_operational_memories_memory_key"), "operational_memories", ["memory_key"])
    op.create_index(op.f("ix_operational_memories_status"), "operational_memories", ["status"])
    op.create_index(op.f("ix_operational_memories_source_task_id"), "operational_memories", ["source_task_id"])
    op.create_index(op.f("ix_operational_memories_supersedes_id"), "operational_memories", ["supersedes_id"])
    op.create_index(
        "ix_operational_memories_scope",
        "operational_memories",
        ["status", "host_scope", "service_scope"],
    )

    op.create_table(
        "operator_feedback",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("memory_id", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("correction", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "verdict IN ('HELPFUL', 'INCOMPLETE', 'INCORRECT')",
            name="ck_operator_feedback_verdict",
        ),
        sa.ForeignKeyConstraint(["memory_id"], ["operational_memories.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_operator_feedback_task_id"), "operator_feedback", ["task_id"])
    op.create_index(op.f("ix_operator_feedback_memory_id"), "operator_feedback", ["memory_id"])
    op.create_index(op.f("ix_operator_feedback_verdict"), "operator_feedback", ["verdict"])
    op.create_index(
        "ix_operator_feedback_task_memory",
        "operator_feedback",
        ["task_id", "memory_id", "created_at"],
    )

    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "CREATE UNIQUE INDEX uq_operational_memory_confirmed "
            "ON operational_memories (memory_key) WHERE status = 'CONFIRMED'"
        )
        op.execute(
            "CREATE INDEX ix_operational_memories_search_tsv "
            "ON operational_memories USING gin (to_tsvector('simple', search_text))"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP INDEX IF EXISTS ix_operational_memories_search_tsv")
        op.execute("DROP INDEX IF EXISTS uq_operational_memory_confirmed")
    op.drop_index("ix_operator_feedback_task_memory", table_name="operator_feedback")
    op.drop_index(op.f("ix_operator_feedback_verdict"), table_name="operator_feedback")
    op.drop_index(op.f("ix_operator_feedback_memory_id"), table_name="operator_feedback")
    op.drop_index(op.f("ix_operator_feedback_task_id"), table_name="operator_feedback")
    op.drop_table("operator_feedback")
    op.drop_index("ix_operational_memories_scope", table_name="operational_memories")
    op.drop_index(op.f("ix_operational_memories_supersedes_id"), table_name="operational_memories")
    op.drop_index(op.f("ix_operational_memories_source_task_id"), table_name="operational_memories")
    op.drop_index(op.f("ix_operational_memories_status"), table_name="operational_memories")
    op.drop_index(op.f("ix_operational_memories_memory_key"), table_name="operational_memories")
    op.drop_table("operational_memories")
