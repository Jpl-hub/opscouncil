from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.channels.feishu.redaction import (
    build_task_notification_payload,
    redact_text,
)
from backend.app.models.entities import (
    ActionProposal,
    NotificationDelivery,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    Task,
    TaskChannelBinding,
    TaskEvent,
    utcnow,
)


EVENT_KIND = {
    "patrol_incident_created": "INCIDENT",
    "action_proposal_created": "APPROVAL_REQUEST",
    "rollback_proposal_created": "ROLLBACK",
    "approval_recorded": "EXECUTION",
    "tool_call_failed": "EXECUTION",
    "verify_result": "VERIFICATION",
}
APPROVAL_KINDS = frozenset({"APPROVAL_REQUEST", "ROLLBACK"})
NON_REDRIVABLE_ERROR_CODES = frozenset({"APPROVAL_TOKEN_REJECTED"})
TERMINAL_TASK_STATUSES = frozenset(
    {"SEALED", "REJECTED", "BLOCKED", "FAILED", "NEEDS_OPERATOR", "CANCELLED", "ROLLED_BACK"}
)


class OutboxStateError(RuntimeError):
    pass


class NotificationOutboxService:
    def __init__(self, session: Session, *, default_chat_id: str | None = None) -> None:
        self.session = session
        self.default_chat_id = (default_chat_id or "").strip() or None

    def enqueue_task_accepted(
        self,
        task: Task,
        binding: TaskChannelBinding,
    ) -> list[NotificationOutbox]:
        payload = build_task_notification_payload(task, None, kind="TASK_ACCEPTED")
        created = self._enqueue(
            kind="TASK_ACCEPTED",
            task=task,
            event=None,
            proposal=None,
            target_operator_id=None,
            recipient_type="CHAT_ID",
            recipient_id=binding.external_chat_id,
            payload=payload,
            dedupe_key=f"FEISHU:TASK_ACCEPTED:{task.id}:{binding.external_chat_id}",
        )
        return [created] if created is not None else []

    def enqueue_task_event(self, task: Task, event: TaskEvent) -> list[NotificationOutbox]:
        kind = EVENT_KIND.get(event.event_type)
        if event.event_type == "state_transition" and task.status in TERMINAL_TASK_STATUSES:
            kind = "TASK_RESULT"
        elif event.event_type == "investigation_needs_operator":
            kind = "TASK_RESULT"
        if kind is None:
            return []
        proposal = self._proposal_for_event(task, event) if kind in APPROVAL_KINDS else None
        if kind in APPROVAL_KINDS:
            if proposal is None or proposal.status != "PENDING_APPROVAL":
                return []
            return self._enqueue_for_approvers(task, event, kind, proposal)

        binding = self.session.scalar(
            select(TaskChannelBinding).where(
                TaskChannelBinding.task_id == task.id,
                TaskChannelBinding.channel == "FEISHU",
            )
        )
        recipient_id = binding.external_chat_id if binding is not None else self.default_chat_id
        if recipient_id is None:
            return []
        payload = build_task_notification_payload(task, event, kind=kind)
        created = self._enqueue(
            kind=kind,
            task=task,
            event=event,
            proposal=None,
            target_operator_id=None,
            recipient_type="CHAT_ID",
            recipient_id=recipient_id,
            payload=payload,
            dedupe_key=f"FEISHU:{event.id}:{kind}:CHAT_ID:{recipient_id}",
        )
        return [created] if created is not None else []

    def claim_next(
        self,
        worker_id: str,
        *,
        now: datetime | None = None,
        lease_seconds: int = 30,
    ) -> NotificationOutbox | None:
        claimed_at = now or utcnow()
        self.recover_expired_leases(claimed_at)
        item = self.session.scalar(
            select(NotificationOutbox)
            .where(
                NotificationOutbox.status == "PENDING",
                NotificationOutbox.available_at <= claimed_at,
            )
            .order_by(NotificationOutbox.available_at.asc(), NotificationOutbox.id.asc())
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if item is None:
            return None
        item.status = "SENDING"
        item.lease_owner = _bounded_worker_id(worker_id)
        item.lease_expires_at = claimed_at + timedelta(seconds=max(lease_seconds, 1))
        item.attempt_count += 1
        item.updated_at = claimed_at
        self.session.flush()
        return item

    def mark_delivered(
        self,
        outbox_id: int,
        worker_id: str,
        *,
        provider_message_id: str | None,
        provider_card_id: str | None,
        duration_ms: int,
        now: datetime | None = None,
    ) -> NotificationOutbox:
        delivered_at = now or utcnow()
        item = self._owned_sending_item(outbox_id, worker_id)
        self.session.add(
            NotificationDelivery(
                outbox_id=item.id,
                attempt_no=item.attempt_count,
                status="SENT",
                provider_message_id=_bounded_optional(provider_message_id, 256),
                provider_card_id=_bounded_optional(provider_card_id, 256),
                duration_ms=max(duration_ms, 0),
                created_at=delivered_at,
            )
        )
        item.status = "SENT"
        item.sent_at = delivered_at
        item.updated_at = delivered_at
        item.lease_owner = None
        item.lease_expires_at = None
        item.last_error_code = None
        item.last_error_message = None
        self.session.flush()
        return item

    def mark_failed(
        self,
        outbox_id: int,
        worker_id: str,
        *,
        error_code: str,
        error_message: str,
        duration_ms: int,
        retryable: bool,
        now: datetime | None = None,
    ) -> NotificationOutbox:
        failed_at = now or utcnow()
        item = self._owned_sending_item(outbox_id, worker_id)
        code = _bounded_error_code(error_code)
        message = redact_text(error_message, max_chars=240) or "通道投递失败"
        self.session.add(
            NotificationDelivery(
                outbox_id=item.id,
                attempt_no=item.attempt_count,
                status="FAILED",
                error_code=code,
                duration_ms=max(duration_ms, 0),
                created_at=failed_at,
            )
        )
        can_retry = retryable and item.attempt_count < item.max_attempts
        item.status = "PENDING" if can_retry else "FAILED"
        item.available_at = (
            failed_at + timedelta(seconds=min(2 ** max(item.attempt_count, 1), 300))
            if can_retry
            else failed_at
        )
        item.updated_at = failed_at
        item.lease_owner = None
        item.lease_expires_at = None
        item.last_error_code = code
        item.last_error_message = message
        self.session.flush()
        return item

    def recover_expired_leases(self, now: datetime | None = None) -> list[int]:
        recovered_at = now or utcnow()
        items = list(
            self.session.scalars(
                select(NotificationOutbox)
                .where(
                    NotificationOutbox.status == "SENDING",
                    NotificationOutbox.lease_expires_at.is_not(None),
                    NotificationOutbox.lease_expires_at < recovered_at,
                )
                .order_by(NotificationOutbox.id.asc())
                .with_for_update(skip_locked=True)
            )
        )
        recovered: list[int] = []
        for item in items:
            existing_delivery = self.session.scalar(
                select(NotificationDelivery).where(
                    NotificationDelivery.outbox_id == item.id,
                    NotificationDelivery.attempt_no == item.attempt_count,
                )
            )
            if existing_delivery is None:
                self.session.add(
                    NotificationDelivery(
                        outbox_id=item.id,
                        attempt_no=item.attempt_count,
                        status="FAILED",
                        error_code="LEASE_EXPIRED",
                        duration_ms=0,
                        created_at=recovered_at,
                    )
                )
            can_retry = item.attempt_count < item.max_attempts
            item.status = "PENDING" if can_retry else "FAILED"
            item.available_at = recovered_at
            item.lease_owner = None
            item.lease_expires_at = None
            item.last_error_code = "LEASE_EXPIRED"
            item.last_error_message = "通道投递租约过期。"
            item.updated_at = recovered_at
            recovered.append(item.id)
        self.session.flush()
        return recovered

    def redrive_failed(
        self,
        outbox_id: int,
        *,
        now: datetime | None = None,
        retry_budget: int = 3,
    ) -> NotificationOutbox:
        redriven_at = now or utcnow()
        item = self.session.scalar(
            select(NotificationOutbox)
            .where(NotificationOutbox.id == outbox_id)
            .with_for_update()
        )
        if item is None:
            raise LookupError("notification outbox item not found")
        if item.status != "FAILED":
            raise OutboxStateError("only failed notification deliveries can be retried")
        if item.last_error_code in NON_REDRIVABLE_ERROR_CODES:
            raise OutboxStateError("notification delivery is no longer retryable")
        item.status = "PENDING"
        item.available_at = redriven_at
        item.max_attempts = item.attempt_count + min(max(retry_budget, 1), 5)
        item.lease_owner = None
        item.lease_expires_at = None
        item.last_error_code = None
        item.last_error_message = None
        item.updated_at = redriven_at
        self.session.flush()
        return item

    @staticmethod
    def retry_allowed(item: NotificationOutbox) -> bool:
        return item.status == "FAILED" and item.last_error_code not in NON_REDRIVABLE_ERROR_CODES

    def _enqueue_for_approvers(
        self,
        task: Task,
        event: TaskEvent,
        kind: str,
        proposal: ActionProposal,
    ) -> list[NotificationOutbox]:
        rows = self.session.execute(
            select(OperatorExternalIdentity, Operator)
            .join(Operator, Operator.id == OperatorExternalIdentity.operator_id)
            .where(
                OperatorExternalIdentity.provider == "FEISHU",
                OperatorExternalIdentity.status == "ACTIVE",
                Operator.status == "ACTIVE",
                Operator.role.in_(("APPROVER", "ADMIN")),
            )
            .order_by(OperatorExternalIdentity.id.asc())
        ).all()
        payload = build_task_notification_payload(
            task,
            event,
            kind=kind,
            proposal=proposal,
        )
        created: list[NotificationOutbox] = []
        for identity, operator in rows:
            item = self._enqueue(
                kind=kind,
                task=task,
                event=event,
                proposal=proposal,
                target_operator_id=operator.id,
                recipient_type="OPEN_ID",
                recipient_id=identity.external_user_id,
                payload=payload,
                dedupe_key=f"FEISHU:{event.id}:{kind}:OPERATOR:{operator.id}",
            )
            if item is not None:
                created.append(item)
        return created

    def _proposal_for_event(self, task: Task, event: TaskEvent) -> ActionProposal | None:
        proposal_id = event.payload_json.get("proposal_id") if isinstance(event.payload_json, dict) else None
        if not isinstance(proposal_id, int):
            return None
        proposal = self.session.get(ActionProposal, proposal_id)
        if proposal is None or proposal.task_id != task.id:
            return None
        return proposal

    def _enqueue(
        self,
        *,
        kind: str,
        task: Task,
        event: TaskEvent | None,
        proposal: ActionProposal | None,
        target_operator_id: int | None,
        recipient_type: str,
        recipient_id: str,
        payload: dict,
        dedupe_key: str,
    ) -> NotificationOutbox | None:
        existing = self.session.scalar(
            select(NotificationOutbox).where(NotificationOutbox.dedupe_key == dedupe_key)
        )
        if existing is not None:
            return None
        item = NotificationOutbox(
            channel="FEISHU",
            kind=kind,
            task_id=task.id,
            task_event_id=event.id if event is not None else None,
            proposal_id=proposal.id if proposal is not None else None,
            target_operator_id=target_operator_id,
            recipient_type=recipient_type,
            recipient_id=recipient_id,
            payload_json=payload,
            dedupe_key=dedupe_key,
            status="PENDING",
        )
        self.session.add(item)
        self.session.flush()
        return item

    def _owned_sending_item(self, outbox_id: int, worker_id: str) -> NotificationOutbox:
        item = self.session.scalar(
            select(NotificationOutbox)
            .where(NotificationOutbox.id == outbox_id)
            .with_for_update()
        )
        if item is None:
            raise LookupError("notification outbox item not found")
        if item.status != "SENDING" or item.lease_owner != _bounded_worker_id(worker_id):
            raise OutboxStateError("channel worker does not own a sending outbox item")
        return item


def _bounded_worker_id(value: str) -> str:
    normalized = " ".join(str(value).split())[:128]
    if not normalized:
        raise ValueError("worker_id is required")
    return normalized


def _bounded_optional(value: str | None, max_chars: int) -> str | None:
    normalized = " ".join(str(value or "").split())[:max_chars]
    return normalized or None


def _bounded_error_code(value: str) -> str:
    normalized = "".join(character for character in str(value).upper() if character.isalnum() or character == "_")
    return normalized[:64] or "DELIVERY_FAILED"
