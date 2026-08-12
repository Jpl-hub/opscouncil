"""investigation graph

Revision ID: 0003_investigation_graph
Revises: 0002_async_task_runtime
Create Date: 2026-07-11 20:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_investigation_graph"
down_revision: Union[str, Sequence[str], None] = "0002_async_task_runtime"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("current_iteration", sa.Integer(), nullable=False),
        sa.Column("max_iterations", sa.Integer(), nullable=False),
        sa.Column("max_tool_calls", sa.Integer(), nullable=False),
        sa.Column("max_elapsed_ms", sa.Integer(), nullable=False),
        sa.Column("stop_reason", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "current_iteration >= 0",
            name="ck_investigations_current_iteration_nonnegative",
        ),
        sa.CheckConstraint("max_iterations > 0", name="ck_investigations_max_iterations_positive"),
        sa.CheckConstraint("max_tool_calls > 0", name="ck_investigations_max_tool_calls_positive"),
        sa.CheckConstraint("max_elapsed_ms > 0", name="ck_investigations_max_elapsed_ms_positive"),
        sa.CheckConstraint(
            "status IN ('RUNNING', 'CONCLUDED', 'INCONCLUSIVE', 'NEEDS_OPERATOR', 'CANCELLED', 'FAILED')",
            name="ck_investigations_status",
        ),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_investigations_status"), "investigations", ["status"], unique=False)
    op.create_index(op.f("ix_investigations_task_id"), "investigations", ["task_id"], unique=True)

    op.create_table(
        "investigation_steps",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("iteration", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("prompt_hash", sa.String(length=64), nullable=True),
        sa.Column("decision_json", sa.JSON(), nullable=False),
        sa.Column("requested_tool_name", sa.String(length=128), nullable=True),
        sa.Column("requested_arguments_json", sa.JSON(), nullable=False),
        sa.Column("tool_call_id", sa.Integer(), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("iteration > 0", name="ck_investigation_steps_iteration_positive"),
        sa.CheckConstraint(
            "decision IS NULL OR decision IN ('COLLECT', 'CONCLUDE')",
            name="ck_investigation_steps_decision",
        ),
        sa.CheckConstraint(
            "status IN ('DECIDED', 'COMPLETED', 'REJECTED', 'ERROR', 'CANCELLED')",
            name="ck_investigation_steps_status",
        ),
        sa.CheckConstraint("duration_ms >= 0", name="ck_investigation_steps_duration_nonnegative"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.ForeignKeyConstraint(["tool_call_id"], ["tool_calls.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "iteration", name="uq_investigation_step_iteration"),
    )
    op.create_index(
        op.f("ix_investigation_steps_investigation_id"),
        "investigation_steps",
        ["investigation_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_investigation_steps_prompt_hash"),
        "investigation_steps",
        ["prompt_hash"],
        unique=False,
    )
    op.create_index("ix_investigation_steps_status", "investigation_steps", ["status"], unique=False)
    op.create_index(
        op.f("ix_investigation_steps_tool_call_id"),
        "investigation_steps",
        ["tool_call_id"],
        unique=False,
    )

    op.create_table(
        "evidence_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("source_ref", sa.String(length=512), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_key", sa.String(length=256), nullable=False),
        sa.Column("tool_call_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("trust_level", sa.String(length=32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source_type IN ('MCP', 'KNOWLEDGE')",
            name="ck_evidence_items_source_type",
        ),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.ForeignKeyConstraint(["tool_call_id"], ["tool_calls.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "source_ref", name="uq_evidence_item_source_ref"),
    )
    op.create_index(
        op.f("ix_evidence_items_investigation_id"),
        "evidence_items",
        ["investigation_id"],
        unique=False,
    )
    op.create_index("ix_evidence_items_source", "evidence_items", ["source_type", "source_key"], unique=False)
    op.create_index(op.f("ix_evidence_items_source_key"), "evidence_items", ["source_key"], unique=False)
    op.create_index(op.f("ix_evidence_items_tool_call_id"), "evidence_items", ["tool_call_id"], unique=False)

    op.create_table(
        "hypotheses",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("investigation_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_gap", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("confidence_level", sa.String(length=16), nullable=False),
        sa.Column("confidence_score", sa.Integer(), nullable=False),
        sa.Column("first_seen_iteration", sa.Integer(), nullable=False),
        sa.Column("last_updated_iteration", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('OPEN', 'SUPPORTED', 'REJECTED', 'INCONCLUSIVE')",
            name="ck_hypotheses_status",
        ),
        sa.CheckConstraint(
            "confidence_level IN ('LOW', 'MEDIUM', 'HIGH')",
            name="ck_hypotheses_confidence_level",
        ),
        sa.CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_hypotheses_confidence_score",
        ),
        sa.CheckConstraint("first_seen_iteration > 0", name="ck_hypotheses_first_iteration_positive"),
        sa.CheckConstraint("last_updated_iteration > 0", name="ck_hypotheses_last_iteration_positive"),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "key", name="uq_hypothesis_key"),
    )
    op.create_index(op.f("ix_hypotheses_investigation_id"), "hypotheses", ["investigation_id"], unique=False)
    op.create_index(op.f("ix_hypotheses_status"), "hypotheses", ["status"], unique=False)
    op.create_index("ix_hypotheses_status_confidence", "hypotheses", ["status", "confidence_level"], unique=False)

    op.create_table(
        "hypothesis_evidence",
        sa.Column("hypothesis_id", sa.Integer(), nullable=False),
        sa.Column("evidence_item_id", sa.Integer(), nullable=False),
        sa.Column("relation", sa.String(length=16), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "relation IN ('SUPPORTS', 'REFUTES', 'CONTEXT')",
            name="ck_hypothesis_evidence_relation",
        ),
        sa.ForeignKeyConstraint(["evidence_item_id"], ["evidence_items.id"]),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["hypotheses.id"]),
        sa.PrimaryKeyConstraint("hypothesis_id", "evidence_item_id"),
    )


def downgrade() -> None:
    op.drop_table("hypothesis_evidence")
    op.drop_index("ix_hypotheses_status_confidence", table_name="hypotheses")
    op.drop_index(op.f("ix_hypotheses_status"), table_name="hypotheses")
    op.drop_index(op.f("ix_hypotheses_investigation_id"), table_name="hypotheses")
    op.drop_table("hypotheses")
    op.drop_index(op.f("ix_evidence_items_tool_call_id"), table_name="evidence_items")
    op.drop_index(op.f("ix_evidence_items_source_key"), table_name="evidence_items")
    op.drop_index("ix_evidence_items_source", table_name="evidence_items")
    op.drop_index(op.f("ix_evidence_items_investigation_id"), table_name="evidence_items")
    op.drop_table("evidence_items")
    op.drop_index(op.f("ix_investigation_steps_tool_call_id"), table_name="investigation_steps")
    op.drop_index("ix_investigation_steps_status", table_name="investigation_steps")
    op.drop_index(op.f("ix_investigation_steps_prompt_hash"), table_name="investigation_steps")
    op.drop_index(op.f("ix_investigation_steps_investigation_id"), table_name="investigation_steps")
    op.drop_table("investigation_steps")
    op.drop_index(op.f("ix_investigations_task_id"), table_name="investigations")
    op.drop_index(op.f("ix_investigations_status"), table_name="investigations")
    op.drop_table("investigations")
