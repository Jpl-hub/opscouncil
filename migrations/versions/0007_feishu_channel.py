"""governed feishu channel

Revision ID: 0007_feishu_channel
Revises: 0006_operational_memory
Create Date: 2026-07-12 21:10:00.000000
"""
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0007_feishu_channel"
down_revision: Union[str, Sequence[str], None] = "0006_operational_memory"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operators",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "role IN ('VIEWER', 'OPERATOR', 'APPROVER', 'ADMIN')",
            name="ck_operators_role",
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED')",
            name="ck_operators_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_index(op.f("ix_operators_username"), "operators", ["username"], unique=True)
    op.create_index(op.f("ix_operators_role"), "operators", ["role"])
    op.create_index(op.f("ix_operators_status"), "operators", ["status"])
    op.create_index("ix_operators_role_status", "operators", ["role", "status"])
    now = datetime.now(timezone.utc)
    operators = sa.table(
        "operators",
        sa.column("username", sa.String),
        sa.column("display_name", sa.String),
        sa.column("role", sa.String),
        sa.column("status", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        operators,
        [
            {
                "username": "local-admin",
                "display_name": "本地管理员",
                "role": "ADMIN",
                "status": "ACTIVE",
                "created_at": now,
                "updated_at": now,
            }
        ],
    )

    op.create_table(
        "operator_external_identities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("operator_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("tenant_key", sa.String(length=128), nullable=False),
        sa.Column("external_user_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("provider IN ('FEISHU')", name="ck_operator_external_identities_provider"),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED')",
            name="ck_operator_external_identities_status",
        ),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provider",
            "tenant_key",
            "external_user_id",
            name="uq_operator_external_identity",
        ),
    )
    op.create_index(
        op.f("ix_operator_external_identities_operator_id"),
        "operator_external_identities",
        ["operator_id"],
    )
    op.create_index(
        op.f("ix_operator_external_identities_provider"),
        "operator_external_identities",
        ["provider"],
    )
    op.create_index(
        op.f("ix_operator_external_identities_status"),
        "operator_external_identities",
        ["status"],
    )
    op.create_index(
        "ix_operator_external_identities_operator",
        "operator_external_identities",
        ["operator_id", "status"],
    )

    op.create_table(
        "channel_inbound_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("external_event_id", sa.String(length=256), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("tenant_key", sa.String(length=128), nullable=False),
        sa.Column("external_actor_id", sa.String(length=128), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column("operator_id", sa.Integer(), nullable=True),
        sa.Column("task_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("channel IN ('FEISHU')", name="ck_channel_inbound_events_channel"),
        sa.CheckConstraint(
            "status IN ('ACCEPTED', 'REJECTED')",
            name="ck_channel_inbound_events_status",
        ),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("channel", "external_event_id", name="uq_channel_inbound_event"),
    )
    op.create_index(op.f("ix_channel_inbound_events_channel"), "channel_inbound_events", ["channel"])
    op.create_index(op.f("ix_channel_inbound_events_event_type"), "channel_inbound_events", ["event_type"])
    op.create_index(op.f("ix_channel_inbound_events_status"), "channel_inbound_events", ["status"])
    op.create_index(op.f("ix_channel_inbound_events_operator_id"), "channel_inbound_events", ["operator_id"])
    op.create_index(op.f("ix_channel_inbound_events_task_id"), "channel_inbound_events", ["task_id"])
    op.create_index(
        "ix_channel_inbound_events_created",
        "channel_inbound_events",
        ["channel", "created_at"],
    )

    op.create_table(
        "task_channel_bindings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("tenant_key", sa.String(length=128), nullable=False),
        sa.Column("external_chat_id", sa.String(length=256), nullable=False),
        sa.Column("external_message_id", sa.String(length=256), nullable=False),
        sa.Column("operator_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("channel IN ('FEISHU')", name="ck_task_channel_bindings_channel"),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id"),
        sa.UniqueConstraint("channel", "external_message_id", name="uq_task_channel_message"),
    )
    op.create_index(op.f("ix_task_channel_bindings_task_id"), "task_channel_bindings", ["task_id"], unique=True)
    op.create_index(op.f("ix_task_channel_bindings_channel"), "task_channel_bindings", ["channel"])
    op.create_index(op.f("ix_task_channel_bindings_operator_id"), "task_channel_bindings", ["operator_id"])
    op.create_index(
        "ix_task_channel_bindings_chat",
        "task_channel_bindings",
        ["channel", "tenant_key", "external_chat_id"],
    )

    op.create_table(
        "channel_instances",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("instance_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("detail_code", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("channel IN ('FEISHU')", name="ck_channel_instances_channel"),
        sa.CheckConstraint(
            "status IN ('CONNECTED', 'DEGRADED', 'STOPPED')",
            name="ck_channel_instances_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("channel", "instance_id", name="uq_channel_instance"),
    )
    op.create_index(op.f("ix_channel_instances_channel"), "channel_instances", ["channel"])
    op.create_index(op.f("ix_channel_instances_status"), "channel_instances", ["status"])
    op.create_index(op.f("ix_channel_instances_last_seen_at"), "channel_instances", ["last_seen_at"])
    op.create_index(
        "ix_channel_instances_health",
        "channel_instances",
        ["channel", "status", "last_seen_at"],
    )

    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=True),
        sa.Column("task_event_id", sa.Integer(), nullable=True),
        sa.Column("proposal_id", sa.Integer(), nullable=True),
        sa.Column("target_operator_id", sa.Integer(), nullable=True),
        sa.Column("recipient_type", sa.String(length=16), nullable=False),
        sa.Column("recipient_id", sa.String(length=256), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("dedupe_key", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("last_error_message", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("channel IN ('FEISHU')", name="ck_notification_outbox_channel"),
        sa.CheckConstraint(
            "kind IN ('TASK_ACCEPTED', 'INCIDENT', 'INVESTIGATION', 'APPROVAL_REQUEST', "
            "'EXECUTION', 'VERIFICATION', 'ROLLBACK', 'CHANNEL_NOTICE')",
            name="ck_notification_outbox_kind",
        ),
        sa.CheckConstraint(
            "recipient_type IN ('CHAT_ID', 'OPEN_ID')",
            name="ck_notification_outbox_recipient_type",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING', 'SENDING', 'SENT', 'FAILED', 'CANCELLED')",
            name="ck_notification_outbox_status",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_notification_outbox_attempt_count"),
        sa.CheckConstraint("max_attempts > 0", name="ck_notification_outbox_max_attempts"),
        sa.ForeignKeyConstraint(["proposal_id"], ["action_proposals.id"]),
        sa.ForeignKeyConstraint(["target_operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["task_event_id"], ["task_events.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedupe_key"),
    )
    for column in ("channel", "kind", "task_id", "task_event_id", "proposal_id", "target_operator_id", "status", "available_at"):
        op.create_index(op.f(f"ix_notification_outbox_{column}"), "notification_outbox", [column])
    op.create_index("ix_notification_outbox_claim", "notification_outbox", ["status", "available_at", "id"])
    op.create_index("ix_notification_outbox_lease", "notification_outbox", ["status", "lease_expires_at"])
    op.create_index("ix_notification_outbox_task", "notification_outbox", ["task_id", "created_at"])

    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("outbox_id", sa.Integer(), nullable=False),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("provider_message_id", sa.String(length=256), nullable=True),
        sa.Column("provider_card_id", sa.String(length=256), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("attempt_no > 0", name="ck_notification_deliveries_attempt_no"),
        sa.CheckConstraint("duration_ms >= 0", name="ck_notification_deliveries_duration"),
        sa.CheckConstraint(
            "status IN ('SENT', 'FAILED')",
            name="ck_notification_deliveries_status",
        ),
        sa.ForeignKeyConstraint(["outbox_id"], ["notification_outbox.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("outbox_id", "attempt_no", name="uq_notification_delivery_attempt"),
    )
    op.create_index(op.f("ix_notification_deliveries_outbox_id"), "notification_deliveries", ["outbox_id"])
    op.create_index(op.f("ix_notification_deliveries_status"), "notification_deliveries", ["status"])
    op.create_index(
        "ix_notification_deliveries_created",
        "notification_deliveries",
        ["status", "created_at"],
    )

    op.create_table(
        "approval_decision_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("proposal_id", sa.Integer(), nullable=False),
        sa.Column("operator_id", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("action_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("inbound_event_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "decision IN ('APPROVE', 'REJECT')",
            name="ck_approval_decision_tokens_decision",
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'CONSUMED', 'REVOKED', 'EXPIRED')",
            name="ck_approval_decision_tokens_status",
        ),
        sa.ForeignKeyConstraint(["inbound_event_id"], ["channel_inbound_events.id"]),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["proposal_id"], ["action_proposals.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_approval_decision_tokens_token_hash"), "approval_decision_tokens", ["token_hash"], unique=True)
    op.create_index(op.f("ix_approval_decision_tokens_proposal_id"), "approval_decision_tokens", ["proposal_id"])
    op.create_index(op.f("ix_approval_decision_tokens_operator_id"), "approval_decision_tokens", ["operator_id"])
    op.create_index(op.f("ix_approval_decision_tokens_status"), "approval_decision_tokens", ["status"])
    op.create_index(op.f("ix_approval_decision_tokens_expires_at"), "approval_decision_tokens", ["expires_at"])
    op.create_index(op.f("ix_approval_decision_tokens_inbound_event_id"), "approval_decision_tokens", ["inbound_event_id"])
    op.create_index(
        "ix_approval_decision_tokens_lookup",
        "approval_decision_tokens",
        ["proposal_id", "operator_id", "status", "expires_at"],
    )

    op.create_table(
        "approval_decision_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("proposal_id", sa.Integer(), nullable=False),
        sa.Column("token_id", sa.Integer(), nullable=False),
        sa.Column("operator_id", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.String(length=1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "decision IN ('APPROVE', 'REJECT')",
            name="ck_approval_decision_jobs_decision",
        ),
        sa.CheckConstraint(
            "status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'NEEDS_OPERATOR')",
            name="ck_approval_decision_jobs_status",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_approval_decision_jobs_attempt_count"),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["proposal_id"], ["action_proposals.id"]),
        sa.ForeignKeyConstraint(["token_id"], ["approval_decision_tokens.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("proposal_id"),
        sa.UniqueConstraint("token_id"),
    )
    op.create_index(op.f("ix_approval_decision_jobs_proposal_id"), "approval_decision_jobs", ["proposal_id"], unique=True)
    op.create_index(op.f("ix_approval_decision_jobs_token_id"), "approval_decision_jobs", ["token_id"], unique=True)
    op.create_index(op.f("ix_approval_decision_jobs_operator_id"), "approval_decision_jobs", ["operator_id"])
    op.create_index(op.f("ix_approval_decision_jobs_status"), "approval_decision_jobs", ["status"])
    op.create_index(op.f("ix_approval_decision_jobs_available_at"), "approval_decision_jobs", ["available_at"])
    op.create_index("ix_approval_decision_jobs_claim", "approval_decision_jobs", ["status", "available_at", "id"])
    op.create_index("ix_approval_decision_jobs_lease", "approval_decision_jobs", ["status", "lease_expires_at"])


def downgrade() -> None:
    op.drop_index("ix_approval_decision_jobs_lease", table_name="approval_decision_jobs")
    op.drop_index("ix_approval_decision_jobs_claim", table_name="approval_decision_jobs")
    op.drop_index(op.f("ix_approval_decision_jobs_available_at"), table_name="approval_decision_jobs")
    op.drop_index(op.f("ix_approval_decision_jobs_status"), table_name="approval_decision_jobs")
    op.drop_index(op.f("ix_approval_decision_jobs_operator_id"), table_name="approval_decision_jobs")
    op.drop_index(op.f("ix_approval_decision_jobs_token_id"), table_name="approval_decision_jobs")
    op.drop_index(op.f("ix_approval_decision_jobs_proposal_id"), table_name="approval_decision_jobs")
    op.drop_table("approval_decision_jobs")

    op.drop_index("ix_approval_decision_tokens_lookup", table_name="approval_decision_tokens")
    op.drop_index(op.f("ix_approval_decision_tokens_inbound_event_id"), table_name="approval_decision_tokens")
    op.drop_index(op.f("ix_approval_decision_tokens_expires_at"), table_name="approval_decision_tokens")
    op.drop_index(op.f("ix_approval_decision_tokens_status"), table_name="approval_decision_tokens")
    op.drop_index(op.f("ix_approval_decision_tokens_operator_id"), table_name="approval_decision_tokens")
    op.drop_index(op.f("ix_approval_decision_tokens_proposal_id"), table_name="approval_decision_tokens")
    op.drop_index(op.f("ix_approval_decision_tokens_token_hash"), table_name="approval_decision_tokens")
    op.drop_table("approval_decision_tokens")

    op.drop_index("ix_notification_deliveries_created", table_name="notification_deliveries")
    op.drop_index(op.f("ix_notification_deliveries_status"), table_name="notification_deliveries")
    op.drop_index(op.f("ix_notification_deliveries_outbox_id"), table_name="notification_deliveries")
    op.drop_table("notification_deliveries")

    op.drop_index("ix_notification_outbox_task", table_name="notification_outbox")
    op.drop_index("ix_notification_outbox_lease", table_name="notification_outbox")
    op.drop_index("ix_notification_outbox_claim", table_name="notification_outbox")
    for column in reversed(("channel", "kind", "task_id", "task_event_id", "proposal_id", "target_operator_id", "status", "available_at")):
        op.drop_index(op.f(f"ix_notification_outbox_{column}"), table_name="notification_outbox")
    op.drop_table("notification_outbox")

    op.drop_index("ix_channel_instances_health", table_name="channel_instances")
    op.drop_index(op.f("ix_channel_instances_last_seen_at"), table_name="channel_instances")
    op.drop_index(op.f("ix_channel_instances_status"), table_name="channel_instances")
    op.drop_index(op.f("ix_channel_instances_channel"), table_name="channel_instances")
    op.drop_table("channel_instances")

    op.drop_index("ix_task_channel_bindings_chat", table_name="task_channel_bindings")
    op.drop_index(op.f("ix_task_channel_bindings_operator_id"), table_name="task_channel_bindings")
    op.drop_index(op.f("ix_task_channel_bindings_channel"), table_name="task_channel_bindings")
    op.drop_index(op.f("ix_task_channel_bindings_task_id"), table_name="task_channel_bindings")
    op.drop_table("task_channel_bindings")

    op.drop_index("ix_channel_inbound_events_created", table_name="channel_inbound_events")
    op.drop_index(op.f("ix_channel_inbound_events_task_id"), table_name="channel_inbound_events")
    op.drop_index(op.f("ix_channel_inbound_events_operator_id"), table_name="channel_inbound_events")
    op.drop_index(op.f("ix_channel_inbound_events_status"), table_name="channel_inbound_events")
    op.drop_index(op.f("ix_channel_inbound_events_event_type"), table_name="channel_inbound_events")
    op.drop_index(op.f("ix_channel_inbound_events_channel"), table_name="channel_inbound_events")
    op.drop_table("channel_inbound_events")

    op.drop_index("ix_operator_external_identities_operator", table_name="operator_external_identities")
    op.drop_index(op.f("ix_operator_external_identities_status"), table_name="operator_external_identities")
    op.drop_index(op.f("ix_operator_external_identities_provider"), table_name="operator_external_identities")
    op.drop_index(op.f("ix_operator_external_identities_operator_id"), table_name="operator_external_identities")
    op.drop_table("operator_external_identities")

    op.drop_index("ix_operators_role_status", table_name="operators")
    op.drop_index(op.f("ix_operators_status"), table_name="operators")
    op.drop_index(op.f("ix_operators_role"), table_name="operators")
    op.drop_index(op.f("ix_operators_username"), table_name="operators")
    op.drop_table("operators")
