from __future__ import annotations

from dataclasses import dataclass
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.service import stable_hash
from backend.app.channels.feishu.identity import (
    ExternalIdentityError,
    OPERATION_ROLES,
    OperatorIdentityService,
)
from backend.app.channels.feishu.outbox import NotificationOutboxService
from backend.app.models.entities import (
    ChannelInboundEvent,
    Conversation,
    TaskChannelBinding,
    utcnow,
)
from backend.app.runtime.intake import TaskIntakeService


@dataclass(frozen=True)
class FeishuInboundMessage:
    event_id: str
    tenant_key: str
    open_id: str
    chat_id: str
    message_id: str
    text: str
    chat_type: str


@dataclass(frozen=True)
class InboundAcceptance:
    accepted: bool
    duplicate: bool
    event_id: int | None
    task_id: int | None
    conversation_id: str | None
    reason_code: str | None


class FeishuInboundService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.identities = OperatorIdentityService(session)

    def accept_message(self, message: FeishuInboundMessage) -> InboundAcceptance:
        normalized = _normalize_message(message)
        payload_hash = _message_hash(normalized)
        existing = self.session.scalar(
            select(ChannelInboundEvent).where(
                ChannelInboundEvent.channel == "FEISHU",
                ChannelInboundEvent.external_event_id == normalized.event_id,
            )
        )
        if existing is not None:
            if existing.payload_hash != payload_hash:
                return InboundAcceptance(
                    accepted=False,
                    duplicate=True,
                    event_id=existing.id,
                    task_id=existing.task_id,
                    conversation_id=_conversation_id(normalized.tenant_key, normalized.chat_id),
                    reason_code="EVENT_PAYLOAD_MISMATCH",
                )
            return InboundAcceptance(
                accepted=existing.status == "ACCEPTED",
                duplicate=True,
                event_id=existing.id,
                task_id=existing.task_id,
                conversation_id=(
                    _conversation_id(normalized.tenant_key, normalized.chat_id)
                    if existing.task_id is not None
                    else None
                ),
                reason_code=existing.reason_code,
            )

        invalid_reason = _message_validation_error(normalized)
        if invalid_reason is not None:
            event = self._record_event(
                normalized,
                payload_hash,
                status="REJECTED",
                reason_code=invalid_reason,
            )
            return InboundAcceptance(False, False, event.id, None, None, invalid_reason)

        try:
            operator = self.identities.resolve_feishu_identity(
                normalized.tenant_key,
                normalized.open_id,
                allowed_roles=OPERATION_ROLES,
            )
        except ExternalIdentityError as exc:
            event = self._record_event(
                normalized,
                payload_hash,
                status="REJECTED",
                reason_code=exc.code,
            )
            return InboundAcceptance(False, False, event.id, None, None, exc.code)

        conversation_id = _conversation_id(normalized.tenant_key, normalized.chat_id)
        if self.session.get(Conversation, conversation_id) is None:
            self.session.add(
                Conversation(
                    id=conversation_id,
                    title=_conversation_title(normalized.text),
                )
            )
            self.session.flush()
        accepted = TaskIntakeService(self.session).accept(
            normalized.text,
            conversation_id=conversation_id,
        )
        binding = TaskChannelBinding(
            task_id=accepted.task.id,
            channel="FEISHU",
            tenant_key=normalized.tenant_key,
            external_chat_id=normalized.chat_id,
            external_message_id=normalized.message_id,
            operator_id=operator.id,
        )
        self.session.add(binding)
        self.session.flush()
        NotificationOutboxService(self.session).enqueue_task_accepted(accepted.task, binding)
        event = self._record_event(
            normalized,
            payload_hash,
            status="ACCEPTED",
            operator_id=operator.id,
            task_id=accepted.task.id,
        )
        return InboundAcceptance(
            accepted=True,
            duplicate=False,
            event_id=event.id,
            task_id=accepted.task.id,
            conversation_id=conversation_id,
            reason_code=None,
        )

    def _record_event(
        self,
        message: FeishuInboundMessage,
        payload_hash: str,
        *,
        status: str,
        reason_code: str | None = None,
        operator_id: int | None = None,
        task_id: int | None = None,
    ) -> ChannelInboundEvent:
        now = utcnow()
        event = ChannelInboundEvent(
            channel="FEISHU",
            external_event_id=message.event_id,
            event_type="im.message.receive_v1",
            tenant_key=message.tenant_key,
            external_actor_id=message.open_id,
            payload_hash=payload_hash,
            status=status,
            reason_code=reason_code,
            operator_id=operator_id,
            task_id=task_id,
            created_at=now,
            processed_at=now,
        )
        self.session.add(event)
        self.session.flush()
        return event


def _normalize_message(message: FeishuInboundMessage) -> FeishuInboundMessage:
    return FeishuInboundMessage(
        event_id=" ".join(message.event_id.split())[:256],
        tenant_key=" ".join(message.tenant_key.split())[:128],
        open_id=" ".join(message.open_id.split())[:128],
        chat_id=" ".join(message.chat_id.split())[:256],
        message_id=" ".join(message.message_id.split())[:256],
        text=message.text.strip(),
        chat_type=" ".join(message.chat_type.split())[:32],
    )


def _message_validation_error(message: FeishuInboundMessage) -> str | None:
    if not all((message.event_id, message.tenant_key, message.open_id, message.chat_id, message.message_id)):
        return "EVENT_INVALID"
    if not message.text:
        return "MESSAGE_EMPTY"
    if len(message.text) > 4000:
        return "MESSAGE_TOO_LARGE"
    return None


def _message_hash(message: FeishuInboundMessage) -> str:
    return stable_hash(
        {
            "event_id": message.event_id,
            "tenant_key": message.tenant_key,
            "open_id": message.open_id,
            "chat_id": message.chat_id,
            "message_id": message.message_id,
            "text": message.text,
            "chat_type": message.chat_type,
        }
    )


def _conversation_id(tenant_key: str, chat_id: str) -> str:
    material = f"FEISHU\0{tenant_key}\0{chat_id}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _conversation_title(text: str) -> str:
    compact = " ".join(text.split())
    return compact[:80] or "飞书运维会话"
