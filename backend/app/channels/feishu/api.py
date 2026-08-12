from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.channels.feishu.approval import ApprovalDecisionService
from backend.app.channels.feishu.auth import build_internal_channel_auth
from backend.app.channels.feishu.identity import (
    ExternalIdentityConflictError,
    OperatorIdentityService,
)
from backend.app.channels.feishu.inbound import FeishuInboundMessage, FeishuInboundService
from backend.app.channels.feishu.outbox import NotificationOutboxService, OutboxStateError
from backend.app.channels.feishu.schemas import (
    FeishuActionRequest,
    FeishuHeartbeatRequest,
    FeishuIdentityCreateRequest,
    FeishuMessageRequest,
    IdentityStatusRequest,
    OperatorCreateRequest,
    OutboxClaimRequest,
    OutboxDeliveredRequest,
    OutboxFailedRequest,
)
from backend.app.core.config import settings
from backend.app.core.database import SessionLocal
from backend.app.models.entities import (
    ChannelInstance,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    utcnow,
)


def build_feishu_router(
    *,
    session_factory: sessionmaker[Session] = SessionLocal,
    internal_token: str | None = None,
    enabled: bool | None = None,
    api_prefix: str = "/api",
) -> APIRouter:
    router = APIRouter(prefix=api_prefix)
    configured_token = settings.channel_internal_token if internal_token is None else internal_token
    channel_enabled = settings.feishu_enabled if enabled is None else enabled
    internal_auth = build_internal_channel_auth(configured_token)

    def get_channel_session():  # type: ignore[no-untyped-def]
        session = session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    internal = APIRouter(
        prefix="/internal/channels/feishu",
        dependencies=[Depends(internal_auth)],
    )

    @internal.post("/messages")
    def accept_message(
        payload: FeishuMessageRequest,
        session: Session = Depends(get_channel_session),
    ) -> dict[str, Any]:
        result = FeishuInboundService(session).accept_message(
            FeishuInboundMessage(
                event_id=payload.event_id,
                tenant_key=payload.tenant_key,
                open_id=payload.open_id,
                chat_id=payload.chat_id,
                message_id=payload.message_id,
                text=payload.text,
                chat_type=payload.chat_type,
            )
        )
        return asdict(result)

    @internal.post("/actions")
    def accept_action(
        payload: FeishuActionRequest,
        session: Session = Depends(get_channel_session),
    ) -> dict[str, Any]:
        result = ApprovalDecisionService(session).consume(
            external_event_id=payload.event_id,
            tenant_key=payload.tenant_key,
            open_id=payload.open_id,
            token=payload.token,
        )
        return asdict(result)

    @internal.post("/outbox/claim")
    def claim_outbox(
        payload: OutboxClaimRequest,
        session: Session = Depends(get_channel_session),
    ) -> dict[str, Any]:
        item = NotificationOutboxService(session).claim_next(
            payload.worker_id,
            lease_seconds=payload.lease_seconds,
        )
        if item is None:
            return {"item": None}
        response = _internal_outbox_item(item)
        if item.kind in {"APPROVAL_REQUEST", "ROLLBACK"}:
            try:
                issued = ApprovalDecisionService(session).issue_for_delivery(item.id)
            except (LookupError, ValueError) as exc:
                NotificationOutboxService(session).mark_failed(
                    item.id,
                    payload.worker_id,
                    error_code="APPROVAL_TOKEN_REJECTED",
                    error_message=str(exc),
                    duration_ms=0,
                    retryable=False,
                )
                # The outbox item is no longer deliverable, but this request must
                # still commit its terminal failure state so it cannot poison the
                # head of the queue. The worker will poll again for the next item.
                return {
                    "item": None,
                    "discarded": {
                        "id": item.id,
                        "error_code": "APPROVAL_TOKEN_REJECTED",
                    },
                }
            response["decision_tokens"] = {
                "approve": issued.approve_token,
                "reject": issued.reject_token,
                "expires_at": issued.expires_at.isoformat(),
            }
        return {"item": response}

    @internal.post("/outbox/{outbox_id}/delivered")
    def mark_outbox_delivered(
        outbox_id: int,
        payload: OutboxDeliveredRequest,
        session: Session = Depends(get_channel_session),
    ) -> dict[str, Any]:
        try:
            item = NotificationOutboxService(session).mark_delivered(
                outbox_id,
                payload.worker_id,
                provider_message_id=payload.provider_message_id,
                provider_card_id=payload.provider_card_id,
                duration_ms=payload.duration_ms,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except OutboxStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"id": item.id, "status": item.status}

    @internal.post("/outbox/{outbox_id}/failed")
    def mark_outbox_failed(
        outbox_id: int,
        payload: OutboxFailedRequest,
        session: Session = Depends(get_channel_session),
    ) -> dict[str, Any]:
        try:
            item = NotificationOutboxService(session).mark_failed(
                outbox_id,
                payload.worker_id,
                error_code=payload.error_code,
                error_message=payload.error_message,
                duration_ms=payload.duration_ms,
                retryable=payload.retryable,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except OutboxStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"id": item.id, "status": item.status}

    @internal.post("/heartbeat")
    def heartbeat(
        payload: FeishuHeartbeatRequest,
        session: Session = Depends(get_channel_session),
    ) -> dict[str, Any]:
        now = utcnow()
        instance = session.scalar(
            select(ChannelInstance)
            .where(
                ChannelInstance.channel == "FEISHU",
                ChannelInstance.instance_id == payload.instance_id,
            )
            .with_for_update()
        )
        if instance is None:
            instance = ChannelInstance(
                channel="FEISHU",
                instance_id=payload.instance_id,
                status=payload.status,
                detail_code=payload.detail_code,
                started_at=now,
                last_seen_at=now,
                updated_at=now,
            )
            session.add(instance)
        else:
            instance.status = payload.status
            instance.detail_code = payload.detail_code
            instance.last_seen_at = now
            instance.updated_at = now
        session.flush()
        return {"instance_id": instance.instance_id, "status": instance.status}

    router.include_router(internal)

    @router.get("/channels/feishu/status")
    def channel_status(session: Session = Depends(get_channel_session)) -> dict[str, Any]:
        now = utcnow()
        latest = session.scalar(
            select(ChannelInstance)
            .where(ChannelInstance.channel == "FEISHU")
            .order_by(ChannelInstance.last_seen_at.desc(), ChannelInstance.id.desc())
            .limit(1)
        )
        counts = {
            state: count
            for state, count in session.execute(
                select(NotificationOutbox.status, func.count(NotificationOutbox.id))
                .where(NotificationOutbox.channel == "FEISHU")
                .group_by(NotificationOutbox.status)
            )
        }
        identity_count = session.scalar(
            select(func.count(OperatorExternalIdentity.id)).where(
                OperatorExternalIdentity.provider == "FEISHU",
                OperatorExternalIdentity.status == "ACTIVE",
            )
        ) or 0
        approver_count = session.scalar(
            select(func.count(OperatorExternalIdentity.id))
            .join(Operator, Operator.id == OperatorExternalIdentity.operator_id)
            .where(
                OperatorExternalIdentity.provider == "FEISHU",
                OperatorExternalIdentity.status == "ACTIVE",
                Operator.status == "ACTIVE",
                Operator.role.in_(("APPROVER", "ADMIN")),
            )
        ) or 0
        connected = bool(
            latest is not None
            and latest.status == "CONNECTED"
            and _as_utc(latest.last_seen_at) >= _as_utc(now - timedelta(seconds=45))
        )
        recent = list(
            session.scalars(
                select(NotificationOutbox)
                .where(NotificationOutbox.channel == "FEISHU")
                .order_by(NotificationOutbox.id.desc())
                .limit(10)
            )
        )
        return {
            "enabled": channel_enabled,
            "connected": connected,
            "instance_status": latest.status if latest is not None else "STOPPED",
            "detail_code": latest.detail_code if latest is not None else None,
            "last_heartbeat_at": latest.last_seen_at.isoformat() if latest is not None else None,
            "identity_count": int(identity_count),
            "approver_count": int(approver_count),
            "outbox": {
                "pending": int(counts.get("PENDING", 0)),
                "sending": int(counts.get("SENDING", 0)),
                "sent": int(counts.get("SENT", 0)),
                "failed": int(counts.get("FAILED", 0)),
            },
            "recent_deliveries": [
                {
                    "id": item.id,
                    "kind": item.kind,
                    "status": item.status,
                    "attempt_count": item.attempt_count,
                    "max_attempts": item.max_attempts,
                    "last_error_code": item.last_error_code,
                    "retry_allowed": NotificationOutboxService.retry_allowed(item),
                    "updated_at": item.updated_at.isoformat(),
                }
                for item in recent
            ],
        }

    @router.post("/channels/feishu/deliveries/{outbox_id}/retry")
    def retry_failed_delivery(
        outbox_id: int,
        session: Session = Depends(get_channel_session),
    ) -> dict[str, Any]:
        try:
            item = NotificationOutboxService(session).redrive_failed(outbox_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except OutboxStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "id": item.id,
            "status": item.status,
            "attempt_count": item.attempt_count,
            "max_attempts": item.max_attempts,
        }

    @router.get("/operators")
    def list_operators(session: Session = Depends(get_channel_session)) -> list[dict[str, Any]]:
        return [_operator_response(item) for item in OperatorIdentityService(session).list_operators()]

    @router.post("/operators", status_code=status.HTTP_201_CREATED)
    def create_operator(
        payload: OperatorCreateRequest,
        session: Session = Depends(get_channel_session),
    ) -> dict[str, Any]:
        try:
            operator = OperatorIdentityService(session).create_operator(
                payload.username,
                payload.display_name,
                payload.role,
            )
        except ExternalIdentityConflictError as exc:
            raise HTTPException(status_code=409, detail=exc.code) from exc
        return _operator_response(operator)

    @router.get("/channels/feishu/identities")
    def list_identities(session: Session = Depends(get_channel_session)) -> list[dict[str, Any]]:
        rows = session.execute(
            select(OperatorExternalIdentity, Operator)
            .join(Operator, Operator.id == OperatorExternalIdentity.operator_id)
            .where(OperatorExternalIdentity.provider == "FEISHU")
            .order_by(OperatorExternalIdentity.id.asc())
        ).all()
        return [_identity_response(identity, operator) for identity, operator in rows]

    @router.get("/channels/feishu/pending-identities")
    def list_pending_identities(
        session: Session = Depends(get_channel_session),
    ) -> list[dict[str, Any]]:
        return [
            asdict(item)
            for item in OperatorIdentityService(session).list_pending_feishu_identities()
        ]

    @router.post("/channels/feishu/identities", status_code=status.HTTP_201_CREATED)
    def create_identity(
        payload: FeishuIdentityCreateRequest,
        session: Session = Depends(get_channel_session),
    ) -> dict[str, Any]:
        service = OperatorIdentityService(session)
        try:
            identity = service.map_feishu_identity(
                payload.operator_id,
                tenant_key=payload.tenant_key,
                open_id=payload.open_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ExternalIdentityConflictError as exc:
            raise HTTPException(status_code=409, detail=exc.code) from exc
        operator = session.get(Operator, identity.operator_id)
        assert operator is not None
        return _identity_response(identity, operator)

    @router.patch("/channels/feishu/identities/{identity_id}")
    def update_identity(
        identity_id: int,
        payload: IdentityStatusRequest,
        session: Session = Depends(get_channel_session),
    ) -> dict[str, Any]:
        try:
            identity = OperatorIdentityService(session).set_identity_status(
                identity_id,
                payload.status,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        operator = session.get(Operator, identity.operator_id)
        assert operator is not None
        return _identity_response(identity, operator)

    return router


def _operator_response(operator: Operator) -> dict[str, Any]:
    return {
        "id": operator.id,
        "username": operator.username,
        "display_name": operator.display_name,
        "role": operator.role,
        "status": operator.status,
    }


def _identity_response(
    identity: OperatorExternalIdentity,
    operator: Operator,
) -> dict[str, Any]:
    return {
        "id": identity.id,
        "operator_id": operator.id,
        "operator_username": operator.username,
        "operator_display_name": operator.display_name,
        "operator_role": operator.role,
        "tenant_key": identity.tenant_key,
        "open_id": identity.external_user_id,
        "status": identity.status,
    }


def _internal_outbox_item(item: NotificationOutbox) -> dict[str, Any]:
    return {
        "id": item.id,
        "kind": item.kind,
        "recipient_type": item.recipient_type,
        "recipient_id": item.recipient_id,
        "payload": item.payload_json,
        "attempt_count": item.attempt_count,
    }


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
