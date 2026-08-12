from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from backend.app.audit.service import AuditService
from backend.app.channels.feishu.identity import OperatorIdentityService
from backend.app.channels.feishu.outbox import NotificationOutboxService, OutboxStateError
from backend.app.models.entities import (
    ActionProposal,
    AuditChain,
    NotificationDelivery,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    Task,
    TaskChannelBinding,
    TaskEvent,
)


TABLES = (
    Operator,
    OperatorExternalIdentity,
    Task,
    TaskEvent,
    AuditChain,
    ActionProposal,
    TaskChannelBinding,
    NotificationOutbox,
    NotificationDelivery,
)


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    for model in TABLES:
        model.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


def add_task(session: Session, *, bound: bool = True) -> tuple[Task, Operator]:
    identities = OperatorIdentityService(session)
    operator = identities.create_operator("oncall-a", "值班工程师", "OPERATOR")
    task = Task(
        trace_id="trace-outbox",
        user_input="检查 /etc/ssh/sshd_config，password=hidden",
        intent="log_analysis",
        status="SEALED",
        risk_level="R1",
        summary="sshd 读取 /etc/ssh/sshd_config 失败，token=secret-value。",
    )
    session.add(task)
    session.flush()
    if bound:
        session.add(
            TaskChannelBinding(
                task_id=task.id,
                channel="FEISHU",
                tenant_key="tenant-a",
                external_chat_id="chat-a",
                external_message_id="message-a",
                operator_id=operator.id,
            )
        )
        session.flush()
    return task, operator


def add_event(session: Session, task: Task, event_type: str, payload: dict | None = None) -> TaskEvent:
    event = TaskEvent(
        task_id=task.id,
        stage="INVESTIGATE",
        event_type=event_type,
        message="raw event message must not be forwarded",
        payload_json=payload or {"tool_output": {"secret": "raw"}},
    )
    session.add(event)
    session.flush()
    return event


def test_terminal_task_result_is_redacted_routed_and_deduplicated() -> None:
    with build_session() as session:
        task, _ = add_task(session)
        event = add_event(session, task, "state_transition")
        service = NotificationOutboxService(session)

        created = service.enqueue_task_event(task, event)
        duplicate = service.enqueue_task_event(task, event)

        assert len(created) == 1
        assert duplicate == []
        item = created[0]
        assert item.kind == "TASK_RESULT"
        assert item.recipient_type == "CHAT_ID"
        assert item.recipient_id == "chat-a"
        encoded = str(item.payload_json)
        assert "tool_output" not in encoded
        assert "/etc/ssh" not in encoded
        assert "secret-value" not in encoded
        assert session.scalar(select(func.count()).select_from(NotificationOutbox)) == 1


def test_investigation_intermediate_event_does_not_publish_stale_summary() -> None:
    with build_session() as session:
        task, _ = add_task(session)
        task.status = "SUMMARIZE"
        task.summary = "初步摘要"
        event = add_event(session, task, "investigation_concluded")

        created = NotificationOutboxService(session).enqueue_task_event(task, event)

        assert created == []


def test_successful_tool_calls_do_not_flood_the_operator_channel() -> None:
    with build_session() as session:
        task, _ = add_task(session)
        task.status = "PERCEIVE"
        event = add_event(session, task, "tool_call")

        created = NotificationOutboxService(session).enqueue_task_event(task, event)

        assert created == []


def test_audit_event_and_notification_outbox_share_one_transaction() -> None:
    with build_session() as session:
        task, _ = add_task(session)
        outbox = NotificationOutboxService(session)
        audit = AuditService(session, event_sink=outbox.enqueue_task_event)

        event = audit.append_event(
            task,
            "SEALED",
            "state_transition",
            "任务审计链封存。",
            {"tool_output": {"must_not_leave_database": True}},
        )

        notification = session.scalar(
            select(NotificationOutbox).where(NotificationOutbox.task_event_id == event.id)
        )
        chain = session.scalar(select(AuditChain).where(AuditChain.event_id == event.id))
        assert notification is not None
        assert chain is not None
        session.rollback()
        assert session.scalar(select(func.count()).select_from(TaskEvent)) == 0
        assert session.scalar(select(func.count()).select_from(NotificationOutbox)) == 0


def test_approval_request_routes_only_to_active_approvers() -> None:
    with build_session() as session:
        task, _ = add_task(session)
        identities = OperatorIdentityService(session)
        approver = identities.create_operator("approver-a", "审批负责人", "APPROVER")
        identities.map_feishu_identity(
            approver.id,
            tenant_key="tenant-a",
            open_id="open-approver",
        )
        disabled = identities.create_operator("approver-b", "停用审批人", "ADMIN")
        disabled_identity = identities.map_feishu_identity(
            disabled.id,
            tenant_key="tenant-a",
            open_id="open-disabled",
        )
        identities.set_identity_status(disabled_identity.id, "DISABLED")
        proposal = ActionProposal(
            task_id=task.id,
            tool_name="safe_log_rotate",
            input_json={"path": "/var/log/private.log", "dry_run": False},
            risk_level="R2",
            reason="审批后执行可逆日志轮转。",
            status="PENDING_APPROVAL",
            dry_run_result_json={
                "status": "ok",
                "summary_fields": {"estimated_reclaim_bytes": 24 * 1024 * 1024},
            },
        )
        session.add(proposal)
        session.flush()
        event = add_event(
            session,
            task,
            "action_proposal_created",
            {"proposal_id": proposal.id, "input": proposal.input_json},
        )

        created = NotificationOutboxService(session).enqueue_task_event(task, event)

        assert len(created) == 1
        item = created[0]
        assert item.kind == "APPROVAL_REQUEST"
        assert item.target_operator_id == approver.id
        assert item.recipient_type == "OPEN_ID"
        assert item.recipient_id == "open-approver"
        assert item.proposal_id == proposal.id
        assert "/var/log" not in str(item.payload_json)
        assert item.payload_json["action_label"] == "安全轮转日志"
        assert item.payload_json["summary"] == (
            "干运行已验证日志可备份、压缩并轮转，预计释放约 24.0 MiB；当前未修改源文件。"
        )


def test_outbox_lease_delivery_and_bounded_retry_lifecycle() -> None:
    now = datetime(2026, 7, 12, 13, 0, tzinfo=timezone.utc)
    with build_session() as session:
        task, _ = add_task(session)
        event = add_event(session, task, "state_transition")
        service = NotificationOutboxService(session)
        item = service.enqueue_task_event(task, event)[0]
        item.available_at = now

        claimed = service.claim_next("channel-a", now=now, lease_seconds=30)
        assert claimed is not None
        assert claimed.id == item.id
        assert claimed.status == "SENDING"
        assert claimed.attempt_count == 1

        service.mark_failed(
            item.id,
            "channel-a",
            error_code="RATE_LIMITED",
            error_message="provider body token=must-not-persist",
            duration_ms=12,
            retryable=True,
            now=now,
        )
        assert item.status == "PENDING"
        assert item.available_at > now
        assert "must-not-persist" not in (item.last_error_message or "")

        item.available_at = now
        claimed_again = service.claim_next("channel-b", now=now, lease_seconds=30)
        assert claimed_again is not None
        service.mark_delivered(
            item.id,
            "channel-b",
            provider_message_id="om_message",
            provider_card_id=None,
            duration_ms=9,
            now=now,
        )
        assert item.status == "SENT"
        assert item.sent_at == now
        deliveries = list(
            session.scalars(
                select(NotificationDelivery).order_by(NotificationDelivery.attempt_no.asc())
            )
        )
        assert [delivery.status for delivery in deliveries] == ["FAILED", "SENT"]


def test_expired_lease_is_requeued_but_terminal_or_unowned_work_is_not_mutated() -> None:
    now = datetime(2026, 7, 12, 13, 0, tzinfo=timezone.utc)
    with build_session() as session:
        task, _ = add_task(session)
        event = add_event(session, task, "verify_result")
        service = NotificationOutboxService(session)
        item = service.enqueue_task_event(task, event)[0]
        item.available_at = now
        service.claim_next("channel-a", now=now, lease_seconds=30)

        service.recover_expired_leases(now + timedelta(seconds=31))

        assert item.status == "PENDING"
        try:
            service.mark_delivered(
                item.id,
                "channel-a",
                provider_message_id="late",
                provider_card_id=None,
                duration_ms=1,
                now=now + timedelta(seconds=32),
            )
        except OutboxStateError:
            pass
        else:
            raise AssertionError("a stale worker must not acknowledge recovered work")


def test_failed_delivery_can_be_explicitly_redriven_without_reusing_attempt_numbers() -> None:
    now = datetime(2026, 7, 12, 13, 0, tzinfo=timezone.utc)
    with build_session() as session:
        task, _ = add_task(session)
        event = add_event(session, task, "state_transition")
        service = NotificationOutboxService(session)
        item = service.enqueue_task_event(task, event)[0]
        item.available_at = now
        item.max_attempts = 1
        service.claim_next("channel-a", now=now, lease_seconds=30)
        service.mark_failed(
            item.id,
            "channel-a",
            error_code="CARD_INVALID",
            error_message="卡片结构无效。",
            duration_ms=8,
            retryable=False,
            now=now,
        )
        assert item.status == "FAILED"

        service.redrive_failed(item.id, now=now + timedelta(minutes=1), retry_budget=2)

        assert item.status == "PENDING"
        assert item.attempt_count == 1
        assert item.max_attempts == 3
        assert item.last_error_code is None
        claimed = service.claim_next(
            "channel-b",
            now=now + timedelta(minutes=1),
            lease_seconds=30,
        )
        assert claimed is not None
        assert claimed.attempt_count == 2


def test_stale_approval_delivery_cannot_be_redriven() -> None:
    now = datetime(2026, 7, 12, 13, 0, tzinfo=timezone.utc)
    with build_session() as session:
        task, _ = add_task(session)
        event = add_event(session, task, "state_transition")
        service = NotificationOutboxService(session)
        item = service.enqueue_task_event(task, event)[0]
        item.available_at = now
        service.claim_next("channel-a", now=now, lease_seconds=30)
        service.mark_failed(
            item.id,
            "channel-a",
            error_code="APPROVAL_TOKEN_REJECTED",
            error_message="审批已结束。",
            duration_ms=0,
            retryable=False,
            now=now,
        )

        assert service.retry_allowed(item) is False
        with pytest.raises(OutboxStateError, match="no longer retryable"):
            service.redrive_failed(item.id, now=now + timedelta(minutes=1))
