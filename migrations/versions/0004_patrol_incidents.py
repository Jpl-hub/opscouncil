"""patrol incidents

Revision ID: 0004_patrol_incidents
Revises: 0003_investigation_graph
Create Date: 2026-07-12 09:40:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0004_patrol_incidents"
down_revision: Union[str, Sequence[str], None] = "0003_investigation_graph"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patrol_policies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("signal_keys_json", sa.JSON(), nullable=False),
        sa.Column("thresholds_json", sa.JSON(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("interval_seconds >= 60", name="ck_patrol_policies_interval"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(op.f("ix_patrol_policies_enabled"), "patrol_policies", ["enabled"], unique=False)
    op.create_index(op.f("ix_patrol_policies_next_run_at"), "patrol_policies", ["next_run_at"], unique=False)
    op.create_index("ix_patrol_policies_due", "patrol_policies", ["enabled", "next_run_at", "id"], unique=False)

    op.create_table(
        "patrol_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("host_key", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("snapshot_json", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('RUNNING', 'SUCCEEDED', 'FAILED')", name="ck_patrol_runs_status"),
        sa.ForeignKeyConstraint(["policy_id"], ["patrol_policies.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_patrol_runs_policy_id"), "patrol_runs", ["policy_id"], unique=False)
    op.create_index(op.f("ix_patrol_runs_host_key"), "patrol_runs", ["host_key"], unique=False)
    op.create_index(op.f("ix_patrol_runs_status"), "patrol_runs", ["status"], unique=False)
    op.create_index("ix_patrol_runs_host_started", "patrol_runs", ["host_key", "started_at"], unique=False)

    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("host_key", sa.String(length=256), nullable=False),
        sa.Column("signal_key", sa.String(length=128), nullable=False),
        sa.Column("dedupe_key", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED')", name="ck_incidents_status"),
        sa.CheckConstraint("severity IN ('WARN', 'CRITICAL')", name="ck_incidents_severity"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedupe_key"),
        sa.UniqueConstraint("task_id"),
    )
    op.create_index(op.f("ix_incidents_host_key"), "incidents", ["host_key"], unique=False)
    op.create_index(op.f("ix_incidents_signal_key"), "incidents", ["signal_key"], unique=False)
    op.create_index(op.f("ix_incidents_status"), "incidents", ["status"], unique=False)
    op.create_index(op.f("ix_incidents_severity"), "incidents", ["severity"], unique=False)
    op.create_index(op.f("ix_incidents_task_id"), "incidents", ["task_id"], unique=True)
    op.create_index("ix_incidents_open", "incidents", ["status", "severity", "updated_at"], unique=False)
    op.create_index("ix_incidents_host_signal", "incidents", ["host_key", "signal_key", "status"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("patrol_run_id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("host_key", sa.String(length=256), nullable=False),
        sa.Column("signal_key", sa.String(length=128), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("metric_json", sa.JSON(), nullable=False),
        sa.Column("evidence_refs_json", sa.JSON(), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("severity IN ('WARN', 'CRITICAL')", name="ck_findings_severity"),
        sa.CheckConstraint("status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')", name="ck_findings_status"),
        sa.CheckConstraint("occurrence_count >= 1", name="ck_findings_occurrence_count"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["patrol_run_id"], ["patrol_runs.id"]),
        sa.ForeignKeyConstraint(["policy_id"], ["patrol_policies.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint"),
    )
    op.create_index(op.f("ix_findings_policy_id"), "findings", ["policy_id"], unique=False)
    op.create_index(op.f("ix_findings_patrol_run_id"), "findings", ["patrol_run_id"], unique=False)
    op.create_index(op.f("ix_findings_incident_id"), "findings", ["incident_id"], unique=False)
    op.create_index(op.f("ix_findings_host_key"), "findings", ["host_key"], unique=False)
    op.create_index(op.f("ix_findings_signal_key"), "findings", ["signal_key"], unique=False)
    op.create_index(op.f("ix_findings_fingerprint"), "findings", ["fingerprint"], unique=True)
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)
    op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)
    op.create_index("ix_findings_open", "findings", ["status", "severity", "last_observed_at"], unique=False)
    op.create_index("ix_findings_host_signal", "findings", ["host_key", "signal_key", "status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_host_signal", table_name="findings")
    op.drop_index("ix_findings_open", table_name="findings")
    op.drop_index(op.f("ix_findings_status"), table_name="findings")
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index(op.f("ix_findings_fingerprint"), table_name="findings")
    op.drop_index(op.f("ix_findings_signal_key"), table_name="findings")
    op.drop_index(op.f("ix_findings_host_key"), table_name="findings")
    op.drop_index(op.f("ix_findings_incident_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_patrol_run_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_policy_id"), table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_incidents_host_signal", table_name="incidents")
    op.drop_index("ix_incidents_open", table_name="incidents")
    op.drop_index(op.f("ix_incidents_task_id"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_severity"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_status"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_signal_key"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_host_key"), table_name="incidents")
    op.drop_table("incidents")

    op.drop_index("ix_patrol_runs_host_started", table_name="patrol_runs")
    op.drop_index(op.f("ix_patrol_runs_status"), table_name="patrol_runs")
    op.drop_index(op.f("ix_patrol_runs_host_key"), table_name="patrol_runs")
    op.drop_index(op.f("ix_patrol_runs_policy_id"), table_name="patrol_runs")
    op.drop_table("patrol_runs")

    op.drop_index("ix_patrol_policies_due", table_name="patrol_policies")
    op.drop_index(op.f("ix_patrol_policies_next_run_at"), table_name="patrol_policies")
    op.drop_index(op.f("ix_patrol_policies_enabled"), table_name="patrol_policies")
    op.drop_table("patrol_policies")
