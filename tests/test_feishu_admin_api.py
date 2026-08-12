from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.channels.feishu.api import build_feishu_router
from backend.app.models.entities import (
    ChannelInstance,
    ChannelInboundEvent,
    NotificationDelivery,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    utcnow,
)


def build_client() -> TestClient:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    for model in (
        Operator,
        OperatorExternalIdentity,
        ChannelInboundEvent,
        ChannelInstance,
        NotificationOutbox,
        NotificationDelivery,
    ):
        model.__table__.create(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    app = FastAPI()
    app.include_router(
        build_feishu_router(
            session_factory=factory,
            internal_token="x" * 32,
            enabled=True,
        )
    )
    client = TestClient(app)
    client.app.state.channel_session_factory = factory
    return client


def test_local_admin_api_manages_operator_and_explicit_identity_mapping() -> None:
    client = build_client()

    assert client.get("/api/channels/feishu/pending-identities").json() == []

    operator = client.post(
        "/api/operators",
        json={"username": "oncall-a", "display_name": "值班工程师", "role": "APPROVER"},
    )
    assert operator.status_code == 201
    operator_id = operator.json()["id"]
    identity = client.post(
        "/api/channels/feishu/identities",
        json={
            "operator_id": operator_id,
            "tenant_key": "tenant-a",
            "open_id": "open-a",
        },
    )
    assert identity.status_code == 201
    identity_id = identity.json()["id"]

    identities = client.get("/api/channels/feishu/identities").json()
    assert identities == [
        {
            "id": identity_id,
            "operator_id": operator_id,
            "operator_username": "oncall-a",
            "operator_display_name": "值班工程师",
            "operator_role": "APPROVER",
            "tenant_key": "tenant-a",
            "open_id": "open-a",
            "status": "ACTIVE",
        }
    ]
    disabled = client.patch(
        f"/api/channels/feishu/identities/{identity_id}",
        json={"status": "DISABLED"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "DISABLED"


def test_public_status_exposes_health_counts_without_secrets_or_payloads() -> None:
    client = build_client()

    response = client.get("/api/channels/feishu/status")

    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True
    assert body["connected"] is False
    assert body["detail_code"] is None
    assert body["identity_count"] == 0
    encoded = str(body).lower()
    assert "secret" not in encoded
    assert "internal_token" not in encoded
    assert "token_hash" not in encoded
    assert "payload_json" not in encoded


def test_local_admin_can_retry_only_failed_delivery() -> None:
    client = build_client()
    factory = client.app.state.channel_session_factory
    with factory.begin() as session:
        item = NotificationOutbox(
            channel="FEISHU",
            kind="CHANNEL_NOTICE",
            recipient_type="CHAT_ID",
            recipient_id="chat-a",
            payload_json={},
            dedupe_key="test-redrive",
            status="FAILED",
            available_at=utcnow(),
            attempt_count=5,
            max_attempts=5,
            last_error_code="CARD_INVALID",
            last_error_message="卡片结构无效。",
        )
        session.add(item)
        session.flush()
        outbox_id = item.id

    retried = client.post(f"/api/channels/feishu/deliveries/{outbox_id}/retry")
    assert retried.status_code == 200
    assert retried.json()["status"] == "PENDING"
    assert retried.json()["attempt_count"] == 5
    assert retried.json()["max_attempts"] == 8

    duplicate = client.post(f"/api/channels/feishu/deliveries/{outbox_id}/retry")
    assert duplicate.status_code == 409
