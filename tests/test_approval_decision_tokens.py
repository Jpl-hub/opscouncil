from __future__ import annotations

from datetime import datetime, timedelta, timezone
from collections.abc import Callable

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.channels.feishu.approval import ApprovalDecisionService
from backend.app.channels.feishu.identity import OperatorIdentityService
from backend.app.models.entities import (
    ActionProposal,
    ApprovalDecisionJob,
    ApprovalDecisionToken,
    ChannelInboundEvent,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    Task,
)


TABLES = (
    Operator,
    OperatorExternalIdentity,
    Task,
    ActionProposal,
    ChannelInboundEvent,
    NotificationOutbox,
    ApprovalDecisionToken,
    ApprovalDecisionJob,
)


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    for model in TABLES:
        model.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


def add_approval_delivery(session: Session) -> tuple[Operator, ActionProposal, NotificationOutbox]:
    identities = OperatorIdentityService(session)
    operator = identities.create_operator("approver-a", "审批负责人", "APPROVER")
    identities.map_feishu_identity(
        operator.id,
        tenant_key="tenant-a",
        open_id="open-approver",
    )
    task = Task(
        trace_id="trace-approval-token",
        user_input="安全清理日志",
        intent="disk_pressure_analysis",
        status="SEALED",
        risk_level="R2",
        summary="等待审批。",
    )
    session.add(task)
    session.flush()
    proposal = ActionProposal(
        task_id=task.id,
        tool_name="safe_log_rotate",
        input_json={"path": "/var/log/app.log", "dry_run": False},
        risk_level="R2",
        reason="可逆日志轮转。",
        status="PENDING_APPROVAL",
    )
    session.add(proposal)
    session.flush()
    outbox = NotificationOutbox(
        channel="FEISHU",
        kind="APPROVAL_REQUEST",
        task_id=task.id,
        proposal_id=proposal.id,
        target_operator_id=operator.id,
        recipient_type="OPEN_ID",
        recipient_id="open-approver",
        payload_json={"title": "安全处置待审批"},
        dedupe_key="approval-delivery",
        status="SENDING",
        lease_owner="channel-a",
        attempt_count=1,
    )
    session.add(outbox)
    session.flush()
    return operator, proposal, outbox


def token_factory() -> Callable[[], str]:
    values = iter(
        (
            "approve-token-0000000000000000000000000001",
            "reject-token-00000000000000000000000000001",
            "approve-token-0000000000000000000000000002",
            "reject-token-00000000000000000000000000002",
        )
    )
    return lambda: next(values)


def test_issue_returns_raw_tokens_once_and_persists_only_hashes() -> None:
    now = datetime(2026, 7, 12, 14, 0, tzinfo=timezone.utc)
    with build_session() as session:
        _, proposal, outbox = add_approval_delivery(session)
        service = ApprovalDecisionService(session, token_factory=token_factory())

        issued = service.issue_for_delivery(outbox.id, now=now, ttl_seconds=300)

        rows = list(
            session.scalars(
                select(ApprovalDecisionToken).order_by(ApprovalDecisionToken.decision.asc())
            )
        )
        assert issued.approve_token.startswith("approve-token")
        assert issued.reject_token.startswith("reject-token")
        assert issued.expires_at == now + timedelta(seconds=300)
        assert {row.decision for row in rows} == {"APPROVE", "REJECT"}
        assert all(row.proposal_id == proposal.id for row in rows)
        assert all(row.token_hash not in {issued.approve_token, issued.reject_token} for row in rows)
        assert issued.approve_token not in str(outbox.payload_json)
        assert issued.reject_token not in str(outbox.payload_json)


def test_delivery_retry_revokes_previous_tokens_before_issuing_new_pair() -> None:
    now = datetime(2026, 7, 12, 14, 0, tzinfo=timezone.utc)
    with build_session() as session:
        _, _, outbox = add_approval_delivery(session)
        service = ApprovalDecisionService(session, token_factory=token_factory())
        first = service.issue_for_delivery(outbox.id, now=now)

        second = service.issue_for_delivery(outbox.id, now=now + timedelta(seconds=5))

        rows = list(session.scalars(select(ApprovalDecisionToken).order_by(ApprovalDecisionToken.id)))
        assert [row.status for row in rows[:2]] == ["REVOKED", "REVOKED"]
        assert [row.status for row in rows[2:]] == ["ACTIVE", "ACTIVE"]
        assert second.approve_token != first.approve_token


def test_valid_click_consumes_one_token_revokes_siblings_and_queues_one_job() -> None:
    now = datetime(2026, 7, 12, 14, 0, tzinfo=timezone.utc)
    with build_session() as session:
        operator, proposal, outbox = add_approval_delivery(session)
        service = ApprovalDecisionService(session, token_factory=token_factory())
        issued = service.issue_for_delivery(outbox.id, now=now)

        accepted = service.consume(
            external_event_id="card-event-a",
            tenant_key="tenant-a",
            open_id="open-approver",
            token=issued.approve_token,
            now=now + timedelta(seconds=10),
        )
        duplicate = service.consume(
            external_event_id="card-event-a",
            tenant_key="tenant-a",
            open_id="open-approver",
            token=issued.approve_token,
            now=now + timedelta(seconds=11),
        )

        assert accepted.accepted is True
        assert accepted.decision == "APPROVE"
        assert accepted.job_id is not None
        assert duplicate.accepted is True
        assert duplicate.duplicate is True
        assert duplicate.job_id == accepted.job_id
        job = session.get(ApprovalDecisionJob, accepted.job_id)
        assert job is not None
        assert job.proposal_id == proposal.id
        assert job.operator_id == operator.id
        tokens = list(session.scalars(select(ApprovalDecisionToken).order_by(ApprovalDecisionToken.id)))
        assert [row.status for row in tokens] == ["CONSUMED", "REVOKED"]
        event = session.scalar(
            select(ChannelInboundEvent).where(
                ChannelInboundEvent.external_event_id == "card-event-a"
            )
        )
        assert event is not None
        assert issued.approve_token not in event.payload_hash


def test_expired_wrong_identity_or_mutated_proposal_is_rejected() -> None:
    now = datetime(2026, 7, 12, 14, 0, tzinfo=timezone.utc)
    with build_session() as session:
        _, proposal, outbox = add_approval_delivery(session)
        service = ApprovalDecisionService(session, token_factory=token_factory())
        issued = service.issue_for_delivery(outbox.id, now=now, ttl_seconds=30)

        wrong_identity = service.consume(
            external_event_id="card-event-wrong",
            tenant_key="tenant-a",
            open_id="unmapped",
            token=issued.approve_token,
            now=now + timedelta(seconds=1),
        )
        expired = service.consume(
            external_event_id="card-event-expired",
            tenant_key="tenant-a",
            open_id="open-approver",
            token=issued.approve_token,
            now=now + timedelta(seconds=31),
        )

        assert wrong_identity.reason_code == "IDENTITY_NOT_MAPPED"
        assert expired.reason_code == "TOKEN_EXPIRED"

        replacement = ApprovalDecisionService(session, token_factory=token_factory()).issue_for_delivery(
            outbox.id,
            now=now + timedelta(seconds=40),
        )
        proposal.input_json = {"path": "/var/log/other.log", "dry_run": False}
        session.flush()
        mutated = service.consume(
            external_event_id="card-event-mutated",
            tenant_key="tenant-a",
            open_id="open-approver",
            token=replacement.reject_token,
            now=now + timedelta(seconds=41),
        )
        assert mutated.reason_code == "PROPOSAL_CHANGED"
        assert session.scalar(select(ApprovalDecisionJob)) is None
