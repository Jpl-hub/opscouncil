from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi import APIRouter
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.channels.feishu.api import build_feishu_router
from backend.app.channels.feishu.identity import OperatorIdentityService
from backend.app.models.entities import (
    ActionProposal,
    ApprovalDecisionJob,
    ApprovalDecisionToken,
    AuditChain,
    ChannelInboundEvent,
    ChannelInstance,
    Conversation,
    ConversationTurn,
    NotificationDelivery,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    Task,
    TaskChannelBinding,
    TaskEvent,
    TaskJob,
)


INTERNAL_TOKEN = "internal-channel-token-0000000000000000"
TABLES = (
    Operator,
    OperatorExternalIdentity,
    Conversation,
    Task,
    ConversationTurn,
    TaskEvent,
    AuditChain,
    TaskJob,
    ActionProposal,
    ChannelInboundEvent,
    TaskChannelBinding,
    ChannelInstance,
    NotificationOutbox,
    NotificationDelivery,
    ApprovalDecisionToken,
    ApprovalDecisionJob,
)


def build_client(*, token: str = INTERNAL_TOKEN) -> tuple[TestClient, sessionmaker[Session]]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    for model in TABLES:
        model.__table__.create(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    with factory() as session:
        operator = Operator(
            username="local-admin",
            display_name="本地管理员",
            role="ADMIN",
            status="ACTIVE",
        )
        session.add(operator)
        session.flush()
        OperatorIdentityService(session).map_feishu_identity(
            operator.id,
            tenant_key="tenant-a",
            open_id="open-admin",
        )
        session.commit()
    app = FastAPI()
    app.include_router(
        build_feishu_router(
            session_factory=factory,
            internal_token=token,
            enabled=True,
        )
    )
    return TestClient(app), factory


def authorization(token: str = INTERNAL_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_internal_endpoints_fail_closed_without_a_valid_service_token() -> None:
    client, _ = build_client()
    payload = {
        "event_id": "message-event-a",
        "tenant_key": "tenant-a",
        "open_id": "open-admin",
        "chat_id": "chat-a",
        "message_id": "message-a",
        "text": "检查系统负载",
        "chat_type": "p2p",
    }

    assert client.post("/api/internal/channels/feishu/messages", json=payload).status_code == 401
    assert client.post(
        "/api/internal/channels/feishu/messages",
        json=payload,
        headers=authorization("wrong-token-000000000000000000000000"),
    ).status_code == 401

    unconfigured, _ = build_client(token="")
    assert unconfigured.post(
        "/api/internal/channels/feishu/messages",
        json=payload,
        headers=authorization(),
    ).status_code == 503


def test_mapped_message_is_idempotently_accepted_and_receipt_is_delivered() -> None:
    client, factory = build_client()
    payload = {
        "event_id": "message-event-a",
        "tenant_key": "tenant-a",
        "open_id": "open-admin",
        "chat_id": "chat-a",
        "message_id": "message-a",
        "text": "检查系统负载和异常进程",
        "chat_type": "p2p",
    }

    first = client.post(
        "/api/internal/channels/feishu/messages",
        json=payload,
        headers=authorization(),
    )
    duplicate = client.post(
        "/api/internal/channels/feishu/messages",
        json=payload,
        headers=authorization(),
    )

    assert first.status_code == 200
    assert first.json()["accepted"] is True
    assert duplicate.json()["duplicate"] is True
    claim = client.post(
        "/api/internal/channels/feishu/outbox/claim",
        json={"worker_id": "channel-a", "lease_seconds": 30},
        headers=authorization(),
    )
    assert claim.status_code == 200
    claimed = claim.json()["item"]
    assert claimed["kind"] == "TASK_ACCEPTED"
    assert "decision_tokens" not in claimed
    delivered = client.post(
        f"/api/internal/channels/feishu/outbox/{claimed['id']}/delivered",
        json={
            "worker_id": "channel-a",
            "provider_message_id": "om_receipt",
            "duration_ms": 8,
        },
        headers=authorization(),
    )
    assert delivered.status_code == 200
    with factory() as session:
        item = session.get(NotificationOutbox, claimed["id"])
        assert item is not None and item.status == "SENT"


def test_approval_claim_returns_ephemeral_tokens_and_callback_queues_decision() -> None:
    client, factory = build_client()
    with factory() as session:
        operator = session.scalar(select(Operator).where(Operator.username == "local-admin"))
        assert operator is not None
        task = Task(
            trace_id="trace-internal-approval",
            user_input="安全轮转日志",
            intent="disk_pressure_analysis",
            status="SEALED",
            risk_level="R2",
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
            recipient_id="open-admin",
            payload_json={"title": "待审批"},
            dedupe_key="internal-approval",
            status="PENDING",
            available_at=datetime(2020, 1, 1, 0, 0, tzinfo=timezone.utc),
        )
        session.add(outbox)
        session.commit()

    claim = client.post(
        "/api/internal/channels/feishu/outbox/claim",
        json={"worker_id": "channel-a", "lease_seconds": 30},
        headers=authorization(),
    )
    item = claim.json()["item"]
    approve_token = item["decision_tokens"]["approve"]
    reject_token = item["decision_tokens"]["reject"]
    assert approve_token != reject_token
    with factory() as session:
        stored = str(list(session.scalars(select(ApprovalDecisionToken))))
        outbox = session.get(NotificationOutbox, item["id"])
        assert approve_token not in stored
        assert reject_token not in stored
        assert approve_token not in str(outbox.payload_json if outbox else {})

    action = client.post(
        "/api/internal/channels/feishu/actions",
        json={
            "event_id": "card-action-a",
            "tenant_key": "tenant-a",
            "open_id": "open-admin",
            "token": approve_token,
        },
        headers=authorization(),
    )
    repeated = client.post(
        "/api/internal/channels/feishu/actions",
        json={
            "event_id": "card-action-a",
            "tenant_key": "tenant-a",
            "open_id": "open-admin",
            "token": approve_token,
        },
        headers=authorization(),
    )
    assert action.status_code == 200
    assert action.json()["accepted"] is True
    assert repeated.json()["duplicate"] is True
    with factory() as session:
        assert session.scalar(select(ApprovalDecisionJob)) is not None


def test_claim_quarantines_stale_approval_without_poisoning_the_queue() -> None:
    client, factory = build_client()
    with factory() as session:
        operator = session.scalar(select(Operator).where(Operator.username == "local-admin"))
        assert operator is not None
        task = Task(
            trace_id="trace-stale-approval",
            user_input="安全轮转日志",
            intent="disk_pressure_analysis",
            status="REJECTED",
            risk_level="R2",
        )
        session.add(task)
        session.flush()
        proposal = ActionProposal(
            task_id=task.id,
            tool_name="safe_log_rotate",
            input_json={"path": "/var/log/app.log", "dry_run": False},
            risk_level="R2",
            reason="可逆日志轮转。",
            status="REJECTED",
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
            recipient_id="open-admin",
            payload_json={"title": "待审批"},
            dedupe_key="stale-internal-approval",
            status="PENDING",
            available_at=datetime(2020, 1, 1, 0, 0, tzinfo=timezone.utc),
        )
        session.add(outbox)
        session.commit()
        outbox_id = outbox.id

    claim = client.post(
        "/api/internal/channels/feishu/outbox/claim",
        json={"worker_id": "channel-a", "lease_seconds": 30},
        headers=authorization(),
    )

    assert claim.status_code == 200
    assert claim.json() == {
        "item": None,
        "discarded": {
            "id": outbox_id,
            "error_code": "APPROVAL_TOKEN_REJECTED",
        },
    }
    with factory() as session:
        quarantined = session.get(NotificationOutbox, outbox_id)
        assert quarantined is not None
        assert quarantined.status == "FAILED"
        assert quarantined.last_error_code == "APPROVAL_TOKEN_REJECTED"
        assert quarantined.lease_owner is None


def test_heartbeat_updates_real_channel_instance_state() -> None:
    client, factory = build_client()

    response = client.post(
        "/api/internal/channels/feishu/heartbeat",
        json={
            "instance_id": "node-a-123",
            "status": "DEGRADED",
            "detail_code": "BOT_CAPABILITY_UNAVAILABLE",
        },
        headers=authorization(),
    )

    assert response.status_code == 200
    with factory() as session:
        instance = session.scalar(select(ChannelInstance))
        assert instance is not None
        assert instance.instance_id == "node-a-123"
        assert instance.status == "DEGRADED"
        assert instance.detail_code == "BOT_CAPABILITY_UNAVAILABLE"


def test_feishu_router_composes_under_the_product_api_prefix_once() -> None:
    _, factory = build_client()
    app = FastAPI()
    product_api = APIRouter(prefix="/api")
    product_api.include_router(
        build_feishu_router(
            session_factory=factory,
            internal_token=INTERNAL_TOKEN,
            enabled=True,
            api_prefix="",
        )
    )
    app.include_router(product_api)
    client = TestClient(app)

    assert client.get("/api/channels/feishu/status").status_code == 200
    assert client.get("/api/api/channels/feishu/status").status_code == 404
