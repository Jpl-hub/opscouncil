from __future__ import annotations

import json
from typing import Any

import pytest

from backend.app.channels.feishu.cards import FeishuCardError, build_outbound_message


def payload(kind: str = "APPROVAL_REQUEST") -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": 1,
        "kind": kind,
        "title": "安全处置待审批" if kind == "APPROVAL_REQUEST" else "调查形成结论",
        "task_id": 21,
        "trace_id": "trace-1234567890abcdef",
        "task_status": "WAITING_APPROVAL",
        "risk_level": "R2",
        "summary": "磁盘压力调查已形成结论。",
        "occurred_at": "2026-07-12T10:00:00+00:00",
    }
    if kind == "APPROVAL_REQUEST":
        value.update(
            {
                "proposal_id": 7,
                "action_label": "安全轮转日志",
                "action_risk_level": "R2",
                "action_reason": "已有备份与回滚路径，等待审批。",
            }
        )
    return value


def walk(value: Any):  # type: ignore[no-untyped-def]
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def test_approval_card_uses_cardkit_v2_and_token_only_buttons() -> None:
    approve = "approve-opaque-token-12345678901234567890"
    reject = "reject-opaque-token-123456789012345678901"

    message = build_outbound_message(
        {
            "id": 31,
            "kind": "APPROVAL_REQUEST",
            "recipient_type": "OPEN_ID",
            "recipient_id": "ou_approver",
            "payload": payload(),
            "decision_tokens": {
                "approve": approve,
                "reject": reject,
                "expires_at": "2026-07-12T10:05:00+00:00",
            },
        }
    )

    assert message.msg_type == "interactive"
    assert message.content["schema"] == "2.0"
    buttons = [node for node in walk(message.content) if isinstance(node, dict) and node.get("tag") == "button"]
    assert len(buttons) == 2
    assert [button["behaviors"][0]["value"] for button in buttons] == [
        {"token": approve},
        {"token": reject},
    ]
    assert all(button["behaviors"][0]["type"] == "callback" for button in buttons)
    assert not [node for node in walk(message.content) if isinstance(node, dict) and node.get("tag") == "note"]
    encoded = json.dumps(message.content, ensure_ascii=False)
    assert '"proposal_id"' not in encoded
    assert '"decision"' not in encoded
    assert '"tool"' not in encoded
    assert "/var/" not in encoded


def test_status_card_has_no_callback_value() -> None:
    message = build_outbound_message(
        {
            "id": 32,
            "kind": "INVESTIGATION",
            "recipient_type": "CHAT_ID",
            "recipient_id": "oc_chat",
            "payload": payload("INVESTIGATION"),
        }
    )

    assert message.content["schema"] == "2.0"
    assert not [node for node in walk(message.content) if isinstance(node, dict) and node.get("tag") == "button"]


@pytest.mark.parametrize(
    "item",
    [
        {"kind": "APPROVAL_REQUEST", "payload": payload()},
        {
            "kind": "INVESTIGATION",
            "payload": payload("INVESTIGATION"),
            "decision_tokens": {"approve": "x" * 40},
        },
        {"kind": "VERIFICATION", "payload": payload("INVESTIGATION")},
    ],
)
def test_card_builder_rejects_crossed_or_incomplete_contracts(item: dict[str, Any]) -> None:
    with pytest.raises(FeishuCardError):
        build_outbound_message(item)
