from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any

APPROVAL_KINDS = frozenset({"APPROVAL_REQUEST", "ROLLBACK"})
MAX_CARD_BYTES = 16 * 1024
MAX_NOTIFICATION_BYTES = 8 * 1024
COMMON_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "title",
        "task_id",
        "trace_id",
        "task_status",
        "risk_level",
        "summary",
        "occurred_at",
    }
)
APPROVAL_PAYLOAD_FIELDS = COMMON_PAYLOAD_FIELDS | {
    "proposal_id",
    "action_label",
    "action_risk_level",
    "action_reason",
}


class FeishuCardError(ValueError):
    pass


@dataclass(frozen=True)
class OutboundMessage:
    msg_type: str
    content: dict[str, Any]


def build_outbound_message(item: dict[str, Any]) -> OutboundMessage:
    kind = _required_text(item, "kind", max_chars=64)
    payload = item.get("payload")
    if not isinstance(payload, dict):
        raise FeishuCardError("outbox payload must be an object")
    _assert_delivery_payload(payload, approval=kind in APPROVAL_KINDS)
    if payload.get("kind") != kind:
        raise FeishuCardError("outbox kind does not match its payload")

    decision_tokens = item.get("decision_tokens")
    if kind in APPROVAL_KINDS:
        if not isinstance(decision_tokens, dict):
            raise FeishuCardError("approval delivery requires decision tokens")
        card = build_approval_card(payload, decision_tokens)
    else:
        if decision_tokens is not None:
            raise FeishuCardError("ordinary delivery cannot contain decision tokens")
        card = build_status_card(payload)
    _assert_card_shape(card, approval=kind in APPROVAL_KINDS)
    return OutboundMessage(msg_type="interactive", content=card)


def build_status_card(payload: dict[str, Any]) -> dict[str, Any]:
    title = _required_text(payload, "title", max_chars=80)
    summary = _required_text(payload, "summary", max_chars=360)
    status = _required_text(payload, "task_status", max_chars=40)
    risk = _required_text(payload, "risk_level", max_chars=8)
    trace_id = _required_text(payload, "trace_id", max_chars=128)

    return {
        "schema": "2.0",
        "config": {
            "update_multi": True,
            "summary": {"content": title},
        },
        "header": {
            "title": {"tag": "plain_text", "content": title},
            "template": _header_template(risk),
        },
        "body": {
            "padding": "12px 16px 14px 16px",
            "vertical_spacing": "8px",
            "elements": [
                {"tag": "markdown", "content": summary},
                {
                    "tag": "markdown",
                    "content": f"**状态**  {status}    **风险**  {risk}\n**审计链**  `{_short_trace(trace_id)}`",
                },
            ],
        },
    }


def build_approval_card(
    payload: dict[str, Any],
    decision_tokens: dict[str, Any],
) -> dict[str, Any]:
    title = _required_text(payload, "title", max_chars=80)
    summary = _required_text(payload, "summary", max_chars=360)
    action = _required_text(payload, "action_label", max_chars=80)
    reason = _required_text(payload, "action_reason", max_chars=240)
    risk = _required_text(payload, "action_risk_level", max_chars=8)
    trace_id = _required_text(payload, "trace_id", max_chars=128)
    approve_token = _required_text(decision_tokens, "approve", max_chars=512)
    reject_token = _required_text(decision_tokens, "reject", max_chars=512)
    expires_at = _required_text(decision_tokens, "expires_at", max_chars=64)
    if approve_token == reject_token:
        raise FeishuCardError("approval decision tokens must be distinct")

    return {
        "schema": "2.0",
        "config": {
            "update_multi": True,
            "summary": {"content": title},
        },
        "header": {
            "title": {"tag": "plain_text", "content": title},
            "template": "orange",
        },
        "body": {
            "padding": "12px 16px 14px 16px",
            "vertical_spacing": "8px",
            "elements": [
                {
                    "tag": "markdown",
                    "content": (
                        f"**处置**  {action}\n"
                        f"**风险**  {risk}    **审计链**  `{_short_trace(trace_id)}`"
                    ),
                },
                {"tag": "markdown", "content": reason},
                {"tag": "markdown", "content": summary},
                {
                    "tag": "markdown",
                    "content": f"<font color='grey'>本次审批令牌有效至 {expires_at}</font>",
                    "text_size": "notation",
                },
                {
                    "tag": "column_set",
                    "horizontal_spacing": "8px",
                    "columns": [
                        {
                            "tag": "column",
                            "width": "weighted",
                            "weight": 1,
                            "elements": [
                                _decision_button(
                                    element_id="approve_action",
                                    label="批准执行",
                                    button_type="primary",
                                    token=approve_token,
                                    confirm_title="确认批准处置？",
                                    confirm_text="系统将重新校验动作指纹，并交由受限执行代理处理。",
                                )
                            ],
                        },
                        {
                            "tag": "column",
                            "width": "weighted",
                            "weight": 1,
                            "elements": [
                                _decision_button(
                                    element_id="reject_action",
                                    label="拒绝",
                                    button_type="default",
                                    token=reject_token,
                                    confirm_title="确认拒绝处置？",
                                    confirm_text="本次处置建议将保持未执行状态。",
                                )
                            ],
                        },
                    ],
                },
            ],
        },
    }


def _decision_button(
    *,
    element_id: str,
    label: str,
    button_type: str,
    token: str,
    confirm_title: str,
    confirm_text: str,
) -> dict[str, Any]:
    return {
        "tag": "button",
        "element_id": element_id,
        "type": button_type,
        "size": "medium",
        "width": "fill",
        "text": {"tag": "plain_text", "content": label},
        "behaviors": [
            {
                "type": "callback",
                "value": {"token": token},
            }
        ],
        "confirm": {
            "title": {"tag": "plain_text", "content": confirm_title},
            "text": {"tag": "plain_text", "content": confirm_text},
        },
    }


def _assert_card_shape(card: dict[str, Any], *, approval: bool) -> None:
    if card.get("schema") != "2.0":
        raise FeishuCardError("CardKit v2 schema is required")
    encoded = json.dumps(card, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_CARD_BYTES:
        raise FeishuCardError("card exceeds the bounded delivery size")
    values = _collect_button_values(card)
    if approval:
        if len(values) != 2 or any(set(value) != {"token"} for value in values):
            raise FeishuCardError("approval buttons may carry only one opaque token")
    elif values:
        raise FeishuCardError("status cards cannot contain actions")


def _assert_delivery_payload(payload: dict[str, Any], *, approval: bool) -> None:
    expected_fields = APPROVAL_PAYLOAD_FIELDS if approval else COMMON_PAYLOAD_FIELDS
    if set(payload) != expected_fields:
        raise FeishuCardError("notification payload does not match the channel contract")
    if payload.get("schema_version") != 1:
        raise FeishuCardError("unsupported notification payload version")
    for key, value in payload.items():
        if key in {"schema_version", "task_id", "proposal_id"}:
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise FeishuCardError(f"{key} must be a positive integer")
            continue
        if not isinstance(value, str):
            raise FeishuCardError(f"{key} must be text")
        _assert_no_prohibited_text(value)
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_NOTIFICATION_BYTES:
        raise FeishuCardError("notification payload exceeds 8 KiB")


def _assert_no_prohibited_text(value: str) -> None:
    if re.search(r"(?i)\bbearer\s+\S+", value):
        raise FeishuCardError("notification payload contains a credential")
    if re.search(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", value):
        raise FeishuCardError("notification payload contains a credential")
    if re.search(r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9_.@+-]+/)+[A-Za-z0-9_.@+-]+", value):
        raise FeishuCardError("notification payload contains an absolute path")
    if re.search(r"(?i)(?<![A-Za-z0-9])[A-Z]:\\(?:[^\s\\]+\\)+[^\s\\]+", value):
        raise FeishuCardError("notification payload contains an absolute path")


def _collect_button_values(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if value.get("tag") == "button":
            behaviors = value.get("behaviors")
            if not isinstance(behaviors, list) or len(behaviors) != 1:
                raise FeishuCardError("button requires one callback behavior")
            behavior = behaviors[0]
            if not isinstance(behavior, dict) or behavior.get("type") != "callback":
                raise FeishuCardError("button behavior must be a callback")
            button_value = behavior.get("value")
            if not isinstance(button_value, dict):
                raise FeishuCardError("button callback value must be an object")
            found.append(button_value)
        for child in value.values():
            found.extend(_collect_button_values(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_collect_button_values(child))
    return found


def _required_text(container: dict[str, Any], key: str, *, max_chars: int) -> str:
    value = container.get(key)
    if not isinstance(value, str):
        raise FeishuCardError(f"{key} must be text")
    normalized = " ".join(value.split())[:max_chars]
    if not normalized:
        raise FeishuCardError(f"{key} is required")
    return normalized


def _header_template(risk: str) -> str:
    if risk in {"R3", "R4"}:
        return "red"
    if risk == "R2":
        return "orange"
    if risk == "R1":
        return "yellow"
    return "green"


def _short_trace(trace_id: str) -> str:
    return trace_id if len(trace_id) <= 20 else f"{trace_id[:8]}...{trace_id[-8:]}"
