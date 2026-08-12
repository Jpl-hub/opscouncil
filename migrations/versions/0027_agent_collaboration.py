"""add evidence-gated multi-agent incident collaboration

Revision ID: 0027_agent_collaboration
Revises: 0026_memory_integrity
Create Date: 2026-08-12 10:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0027_agent_collaboration"
down_revision: Union[str, Sequence[str], None] = "0026_memory_integrity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "incident_collaborations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("team_name", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("evidence_gate_status", sa.String(length=16), nullable=False),
        sa.Column("autonomy_mode", sa.String(length=32), nullable=False),
        sa.Column("agentteams_room_id", sa.String(length=255), nullable=True),
        sa.Column("context_version", sa.Integer(), nullable=False),
        sa.Column("shared_context_json", sa.JSON(), nullable=False),
        sa.Column("action_contract_json", sa.JSON(), nullable=True),
        sa.Column("action_contract_hash", sa.String(length=64), nullable=True),
        sa.Column("execution_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('TRIAGING', 'INVESTIGATING', 'PLANNING', "
            "'WAITING_EXECUTION', 'VERIFYING', 'LEARNING', 'RESOLVED', "
            "'NEEDS_OPERATOR', 'FAILED')",
            name="ck_incident_collaborations_status",
        ),
        sa.CheckConstraint(
            "evidence_gate_status IN ('PENDING', 'PASSED', 'FAILED', 'OVERRIDDEN')",
            name="ck_incident_collaborations_evidence_gate",
        ),
        sa.CheckConstraint(
            "autonomy_mode IN ('UNDECIDED', 'OBSERVE_ONLY', 'AUTO_REVERSIBLE', "
            "'HUMAN_GATED', 'BLOCKED')",
            name="ck_incident_collaborations_autonomy_mode",
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id"),
    )
    op.create_index(
        "ix_incident_collaborations_incident_id",
        "incident_collaborations",
        ["incident_id"],
        unique=True,
    )
    op.create_index(
        "ix_incident_collaborations_status",
        "incident_collaborations",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_incident_collaborations_status_updated",
        "incident_collaborations",
        ["status", "updated_at"],
        unique=False,
    )

    op.create_table(
        "agent_work_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("collaboration_id", sa.Integer(), nullable=False),
        sa.Column("work_key", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=False),
        sa.Column("skill_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("depends_on_json", sa.JSON(), nullable=False),
        sa.Column("input_json", sa.JSON(), nullable=False),
        sa.Column("output_json", sa.JSON(), nullable=True),
        sa.Column("evidence_refs_json", sa.JSON(), nullable=False),
        sa.Column("assigned_agent", sa.String(length=128), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('PENDING', 'READY', 'RUNNING', 'SUCCEEDED', "
            "'FAILED', 'BLOCKED', 'CANCELLED')",
            name="ck_agent_work_items_status",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_agent_work_items_attempt_count"),
        sa.ForeignKeyConstraint(
            ["collaboration_id"],
            ["incident_collaborations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "collaboration_id",
            "work_key",
            name="uq_agent_work_items_collaboration_key",
        ),
    )
    op.create_index(
        "ix_agent_work_items_collaboration_id",
        "agent_work_items",
        ["collaboration_id"],
        unique=False,
    )
    op.create_index("ix_agent_work_items_role", "agent_work_items", ["role"], unique=False)
    op.create_index("ix_agent_work_items_status", "agent_work_items", ["status"], unique=False)
    op.create_index(
        "ix_agent_work_items_ready",
        "agent_work_items",
        ["status", "role", "created_at"],
        unique=False,
    )

    op.create_table(
        "collaboration_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("collaboration_id", sa.Integer(), nullable=False),
        sa.Column("work_item_id", sa.Integer(), nullable=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("source_system", sa.String(length=64), nullable=False),
        sa.Column("source_event_id", sa.String(length=128), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=True),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("sequence > 0", name="ck_collaboration_events_sequence"),
        sa.CheckConstraint("length(payload_hash) = 64", name="ck_collaboration_events_payload_hash"),
        sa.CheckConstraint("length(event_hash) = 64", name="ck_collaboration_events_event_hash"),
        sa.CheckConstraint(
            "prev_hash IS NULL OR length(prev_hash) = 64",
            name="ck_collaboration_events_prev_hash",
        ),
        sa.ForeignKeyConstraint(
            ["collaboration_id"],
            ["incident_collaborations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["work_item_id"], ["agent_work_items.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "collaboration_id",
            "sequence",
            name="uq_collaboration_events_sequence",
        ),
        sa.UniqueConstraint(
            "source_system",
            "source_event_id",
            name="uq_collaboration_events_source",
        ),
    )
    op.create_index(
        "ix_collaboration_events_collaboration_id",
        "collaboration_events",
        ["collaboration_id"],
        unique=False,
    )
    op.create_index(
        "ix_collaboration_events_work_item_id",
        "collaboration_events",
        ["work_item_id"],
        unique=False,
    )
    op.create_index(
        "ix_collaboration_events_event_type",
        "collaboration_events",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        "ix_collaboration_events_timeline",
        "collaboration_events",
        ["collaboration_id", "sequence"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("collaboration_events")
    op.drop_table("agent_work_items")
    op.drop_table("incident_collaborations")
