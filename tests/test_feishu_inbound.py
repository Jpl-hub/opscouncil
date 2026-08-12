from __future__ import annotations

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from backend.app.channels.feishu.identity import OperatorIdentityService
from backend.app.channels.feishu.inbound import FeishuInboundMessage, FeishuInboundService
from backend.app.models.entities import (
    AuditChain,
    ChannelInboundEvent,
    Conversation,
    ConversationTurn,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    Task,
    TaskChannelBinding,
    TaskEvent,
    TaskJob,
)


TABLES = (
    Operator,
    OperatorExternalIdentity,
    Conversation,
    Task,
    ConversationTurn,
    TaskEvent,
    AuditChain,
    TaskJob,
    ChannelInboundEvent,
    TaskChannelBinding,
    NotificationOutbox,
)


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    for model in TABLES:
        model.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


def inbound_message(**overrides: str) -> FeishuInboundMessage:
    values = {
        "event_id": "event-a",
        "tenant_key": "tenant-a",
        "open_id": "open-a",
        "chat_id": "chat-a",
        "message_id": "message-a",
        "text": "检查 sshd 服务状态和最近错误日志",
        "chat_type": "p2p",
    }
    values.update(overrides)
    return FeishuInboundMessage(**values)


def map_operator(session: Session, *, role: str = "OPERATOR", status: str = "ACTIVE") -> Operator:
    identities = OperatorIdentityService(session)
    operator = identities.create_operator("oncall-a", "值班工程师", role)
    identity = identities.map_feishu_identity(
        operator.id,
        tenant_key="tenant-a",
        open_id="open-a",
    )
    if status != "ACTIVE":
        identities.set_identity_status(identity.id, status)
    session.flush()
    return operator


def test_repeated_feishu_message_creates_exactly_one_task() -> None:
    with build_session() as session:
        operator = map_operator(session)
        service = FeishuInboundService(session)

        first = service.accept_message(inbound_message())
        duplicate = service.accept_message(
            inbound_message(text="重复投递不应覆盖原任务内容")
        )

        assert first.accepted is True
        assert first.duplicate is False
        assert first.task_id is not None
        assert duplicate.accepted is False
        assert duplicate.duplicate is True
        assert duplicate.task_id == first.task_id
        assert duplicate.reason_code == "EVENT_PAYLOAD_MISMATCH"
        assert session.scalar(select(func.count()).select_from(Task)) == 1
        task = session.get(Task, first.task_id)
        assert task is not None
        assert task.user_input == "检查 sshd 服务状态和最近错误日志"
        binding = session.scalar(
            select(TaskChannelBinding).where(TaskChannelBinding.task_id == task.id)
        )
        assert binding is not None
        assert binding.operator_id == operator.id
        assert binding.external_chat_id == "chat-a"
        receipt = session.scalar(
            select(NotificationOutbox).where(NotificationOutbox.task_id == task.id)
        )
        assert receipt is not None
        assert receipt.kind == "TASK_ACCEPTED"
        assert receipt.recipient_id == "chat-a"


def test_same_chat_continues_one_conversation() -> None:
    with build_session() as session:
        map_operator(session)
        service = FeishuInboundService(session)

        first = service.accept_message(inbound_message())
        second = service.accept_message(
            inbound_message(
                event_id="event-b",
                message_id="message-b",
                text="继续检查 22 端口对应的进程",
            )
        )

        first_turn = session.scalar(
            select(ConversationTurn).where(ConversationTurn.task_id == first.task_id)
        )
        second_turn = session.scalar(
            select(ConversationTurn).where(ConversationTurn.task_id == second.task_id)
        )
        assert first_turn is not None and second_turn is not None
        assert first_turn.conversation_id == second_turn.conversation_id
        assert first_turn.turn_index == 1
        assert second_turn.turn_index == 2
        assert second_turn.parent_task_id == first.task_id


def test_unmapped_cross_tenant_and_viewer_messages_are_rejected_without_tasks() -> None:
    with build_session() as session:
        map_operator(session, role="VIEWER")
        service = FeishuInboundService(session)

        viewer = service.accept_message(inbound_message())
        cross_tenant = service.accept_message(
            inbound_message(
                event_id="event-b",
                message_id="message-b",
                tenant_key="tenant-b",
            )
        )

        assert viewer.accepted is False
        assert viewer.reason_code == "ROLE_NOT_ALLOWED"
        assert cross_tenant.accepted is False
        assert cross_tenant.reason_code == "IDENTITY_NOT_MAPPED"
        assert session.scalar(select(func.count()).select_from(Task)) == 0
        assert session.scalar(select(func.count()).select_from(ChannelInboundEvent)) == 2


def test_blank_or_oversized_message_is_recorded_but_never_queued() -> None:
    with build_session() as session:
        map_operator(session)
        service = FeishuInboundService(session)

        blank = service.accept_message(inbound_message(text="   "))
        oversized = service.accept_message(
            inbound_message(event_id="event-b", message_id="message-b", text="x" * 4001)
        )

        assert blank.reason_code == "MESSAGE_EMPTY"
        assert oversized.reason_code == "MESSAGE_TOO_LARGE"
        assert session.scalar(select(func.count()).select_from(TaskJob)) == 0
