from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import httpx
import pytest

from backend.app.channels.feishu.client import (
    ChannelApiError,
    DeliveryReceipt,
    FeishuActionEvent,
    FeishuChannelService,
    FeishuDeliveryError,
    FeishuMessageEvent,
    InternalChannelApi,
    normalize_card_action,
    normalize_text_message,
    resolve_feishu_runtime_state,
)


TOKEN = "internal-channel-token-0000000000000000"


class RecordingSender:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def send(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return DeliveryReceipt(provider_message_id="om-delivered")


def notification_item() -> dict[str, Any]:
    return {
        "id": 11,
        "kind": "INVESTIGATION",
        "recipient_type": "CHAT_ID",
        "recipient_id": "oc_chat",
        "attempt_count": 1,
        "payload": {
            "schema_version": 1,
            "kind": "INVESTIGATION",
            "title": "调查形成结论",
            "task_id": 8,
            "trace_id": "trace-1234567890abcdef",
            "task_status": "SEALED",
            "risk_level": "R1",
            "summary": "异常进程调查已完成。",
            "occurred_at": "2026-07-12T10:00:00+00:00",
        },
    }


def build_api(handler):  # type: ignore[no-untyped-def]
    return InternalChannelApi(
        "http://127.0.0.1:8000",
        TOKEN,
        transport=httpx.MockTransport(handler),
    )


def test_internal_client_sends_only_to_loopback_with_bearer_auth() -> None:
    captured: list[tuple[str, dict[str, Any]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        captured.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"accepted": True, "duplicate": False})

    api = build_api(handler)
    result = api.accept_message(
        FeishuMessageEvent(
            event_id="event-a",
            tenant_key="tenant-a",
            open_id="ou-user",
            chat_id="oc-chat",
            message_id="om-message",
            text="检查系统负载",
        )
    )
    api.close()

    assert result["accepted"] is True
    assert captured == [
        (
            "/api/internal/channels/feishu/messages",
            {
                "event_id": "event-a",
                "tenant_key": "tenant-a",
                "open_id": "ou-user",
                "chat_id": "oc-chat",
                "message_id": "om-message",
                "text": "检查系统负载",
                "chat_type": "p2p",
            },
        )
    ]
    with pytest.raises(ValueError):
        InternalChannelApi("https://example.com", TOKEN)


def test_card_action_is_forwarded_as_an_opaque_token_only() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={"accepted": True, "duplicate": False, "job_id": 4})

    api = build_api(handler)
    result = api.accept_action(
        FeishuActionEvent(
            event_id="action-a",
            tenant_key="tenant-a",
            open_id="ou-approver",
            token="opaque-token-123456789012345678901234",
        )
    )
    api.close()

    assert result["job_id"] == 4
    assert set(captured) == {"event_id", "tenant_key", "open_id", "token"}


def test_outbox_delivery_uses_stable_provider_idempotency_and_acknowledges() -> None:
    claimed = False
    acknowledgements: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal claimed
        if request.url.path.endswith("/outbox/claim"):
            if claimed:
                return httpx.Response(200, json={"item": None})
            claimed = True
            return httpx.Response(200, json={"item": notification_item()})
        acknowledgements.append(json.loads(request.content))
        return httpx.Response(200, json={"id": 11, "status": "SENT"})

    api = build_api(handler)
    sender = RecordingSender()
    service = FeishuChannelService(api, sender, "channel-node-a")

    assert service.deliver_once() is True
    assert service.deliver_once() is False
    api.close()

    assert sender.calls[0]["idempotency_key"] == "kg-outbox-11"
    assert sender.calls[0]["recipient_type"] == "CHAT_ID"
    assert sender.calls[0]["message"].content["schema"] == "2.0"
    assert acknowledgements[0]["provider_message_id"] == "om-delivered"


def test_delivery_error_is_recorded_without_forwarding_exception_text() -> None:
    failures: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/outbox/claim"):
            return httpx.Response(200, json={"item": notification_item()})
        failures.append(json.loads(request.content))
        return httpx.Response(200, json={"id": 11, "status": "PENDING"})

    api = build_api(handler)
    sender = RecordingSender(
        FeishuDeliveryError("FEISHU_RATE_LIMIT", retryable=True)
    )
    service = FeishuChannelService(api, sender, "channel-node-a")

    assert service.deliver_once() is True
    api.close()

    assert failures[0]["error_code"] == "FEISHU_RATE_LIMIT"
    assert failures[0]["retryable"] is True
    assert "token" not in failures[0]["error_message"].lower()


def test_api_errors_never_include_response_or_service_token() -> None:
    secret_body = "server leaked secret=do-not-expose"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text=secret_body)

    api = build_api(handler)
    with pytest.raises(ChannelApiError) as raised:
        api.heartbeat("instance-a", "CONNECTED")
    api.close()

    rendered = repr(raised.value)
    assert TOKEN not in rendered
    assert secret_body not in rendered
    assert raised.value.retryable is True


def test_channel_client_imports_no_database_agent_or_executor_layers() -> None:
    root = Path(__file__).resolve().parents[1]
    code = """
import sys
import backend.app.channels.feishu.client
for name in sys.modules:
    assert not name.startswith('backend.app.models')
    assert not name.startswith('backend.app.core.database')
    assert not name.startswith('backend.app.agent')
    assert not name.startswith('backend.app.mcp')
    assert not name.startswith('backend.app.executor')
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        env={"PYTHONPATH": str(root)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_group_message_requires_the_configured_bot_mention() -> None:
    ignored = normalize_text_message(
        event_id="event-group",
        tenant_key="tenant-a",
        open_id="ou-user",
        chat_id="oc-group",
        message_id="om-group",
        message_type="text",
        content=json.dumps({"text": "检查系统负载"}),
        chat_type="group",
    )
    accepted = normalize_text_message(
        event_id="event-group",
        tenant_key="tenant-a",
        open_id="ou-user",
        chat_id="oc-group",
        message_id="om-group",
        message_type="text",
        content=json.dumps({"text": "@_user_1 检查系统负载"}),
        chat_type="group",
        bot_mention_keys=("@_user_1",),
    )

    assert ignored is None
    assert accepted is not None
    assert accepted.text == "检查系统负载"


def test_card_action_rejects_any_value_beyond_the_one_time_token() -> None:
    assert normalize_card_action(
        event_id="event-action",
        tenant_key="tenant-a",
        open_id="ou-approver",
        value={"token": "x" * 40, "decision": "APPROVE"},
    ) is None
    accepted = normalize_card_action(
        event_id="event-action",
        tenant_key="tenant-a",
        open_id="ou-approver",
        value={"token": "x" * 40},
    )
    assert accepted is not None
    assert accepted.token == "x" * 40


@pytest.mark.parametrize(
    ("socket_connected", "bot_ready", "expected"),
    [
        (False, False, ("DEGRADED", "LONG_CONNECTION_PENDING")),
        (True, False, ("DEGRADED", "BOT_CAPABILITY_UNAVAILABLE")),
        (True, True, ("CONNECTED", None)),
    ],
)
def test_runtime_state_requires_transport_and_bot_capability(
    socket_connected: bool,
    bot_ready: bool,
    expected: tuple[str, str | None],
) -> None:
    assert resolve_feishu_runtime_state(
        socket_connected=socket_connected,
        bot_capability_ready=bot_ready,
    ) == expected
