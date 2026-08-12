from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
import threading
import time
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from backend.app.channels.feishu.cards import (
    FeishuCardError,
    OutboundMessage,
    build_outbound_message,
)


LOCAL_API_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def resolve_feishu_runtime_state(
    *,
    socket_connected: bool,
    bot_capability_ready: bool,
) -> tuple[str, str | None]:
    if not socket_connected:
        return "DEGRADED", "LONG_CONNECTION_PENDING"
    if not bot_capability_ready:
        return "DEGRADED", "BOT_CAPABILITY_UNAVAILABLE"
    return "CONNECTED", None


class ChannelApiError(RuntimeError):
    def __init__(
        self,
        operation: str,
        *,
        status_code: int | None = None,
        retryable: bool,
    ) -> None:
        self.operation = operation
        self.status_code = status_code
        self.retryable = retryable
        status = str(status_code) if status_code is not None else "unavailable"
        super().__init__(f"internal channel API {operation} failed ({status})")


class FeishuDeliveryError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool) -> None:
        self.code = _error_code(code)
        self.retryable = retryable
        super().__init__("Feishu delivery failed")


@dataclass(frozen=True)
class FeishuMessageEvent:
    event_id: str
    tenant_key: str
    open_id: str
    chat_id: str
    message_id: str
    text: str
    chat_type: str = "p2p"


@dataclass(frozen=True)
class FeishuActionEvent:
    event_id: str
    tenant_key: str
    open_id: str
    token: str


@dataclass(frozen=True)
class DeliveryReceipt:
    provider_message_id: str | None = None
    provider_card_id: str | None = None


class FeishuSender(Protocol):
    def send(
        self,
        *,
        recipient_type: str,
        recipient_id: str,
        message: OutboundMessage,
        idempotency_key: str,
    ) -> DeliveryReceipt: ...


class InternalChannelApi:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout_seconds: float = 3.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        normalized_url = _local_api_url(base_url)
        if len(token) < 32:
            raise ValueError("internal channel token must contain at least 32 characters")
        self._lock = threading.Lock()
        self._client = httpx.Client(
            base_url=normalized_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=max(timeout_seconds, 0.2),
            transport=transport,
        )

    def close(self) -> None:
        with self._lock:
            self._client.close()

    def accept_message(self, event: FeishuMessageEvent) -> dict[str, Any]:
        return self._post("accept_message", "/api/internal/channels/feishu/messages", asdict(event))

    def accept_action(self, event: FeishuActionEvent) -> dict[str, Any]:
        return self._post("accept_action", "/api/internal/channels/feishu/actions", asdict(event))

    def claim_outbox(self, worker_id: str, *, lease_seconds: int = 30) -> dict[str, Any] | None:
        response = self._post(
            "claim_outbox",
            "/api/internal/channels/feishu/outbox/claim",
            {"worker_id": worker_id, "lease_seconds": lease_seconds},
        )
        item = response.get("item")
        if item is None:
            return None
        if not isinstance(item, dict):
            raise ChannelApiError("claim_outbox", retryable=False)
        return item

    def mark_delivered(
        self,
        outbox_id: int,
        worker_id: str,
        receipt: DeliveryReceipt,
        *,
        duration_ms: int,
    ) -> None:
        self._post(
            "mark_delivered",
            f"/api/internal/channels/feishu/outbox/{outbox_id}/delivered",
            {
                "worker_id": worker_id,
                "provider_message_id": receipt.provider_message_id,
                "provider_card_id": receipt.provider_card_id,
                "duration_ms": max(duration_ms, 0),
            },
        )

    def mark_failed(
        self,
        outbox_id: int,
        worker_id: str,
        *,
        code: str,
        message: str,
        duration_ms: int,
        retryable: bool,
    ) -> None:
        self._post(
            "mark_failed",
            f"/api/internal/channels/feishu/outbox/{outbox_id}/failed",
            {
                "worker_id": worker_id,
                "error_code": _error_code(code),
                "error_message": " ".join(message.split())[:240] or "通道投递失败",
                "duration_ms": max(duration_ms, 0),
                "retryable": retryable,
            },
        )

    def heartbeat(self, instance_id: str, status: str, detail_code: str | None = None) -> None:
        self._post(
            "heartbeat",
            "/api/internal/channels/feishu/heartbeat",
            {
                "instance_id": instance_id,
                "status": status,
                "detail_code": _optional_error_code(detail_code),
            },
        )

    def _post(self, operation: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            with self._lock:
                response = self._client.post(path, json=payload)
        except httpx.RequestError as exc:
            raise ChannelApiError(operation, retryable=True) from exc
        if response.status_code >= 400:
            raise ChannelApiError(
                operation,
                status_code=response.status_code,
                retryable=response.status_code == 429 or response.status_code >= 500,
            )
        try:
            value = response.json()
        except ValueError as exc:
            raise ChannelApiError(
                operation,
                status_code=response.status_code,
                retryable=False,
            ) from exc
        if not isinstance(value, dict):
            raise ChannelApiError(
                operation,
                status_code=response.status_code,
                retryable=False,
            )
        return value


class FeishuChannelService:
    def __init__(
        self,
        api: InternalChannelApi,
        sender: FeishuSender,
        worker_id: str,
        *,
        lease_seconds: int = 30,
    ) -> None:
        self.api = api
        self.sender = sender
        self.worker_id = _bounded_required(worker_id, "worker_id", 128)
        self.lease_seconds = min(max(lease_seconds, 10), 300)

    def accept_message(self, event: FeishuMessageEvent) -> dict[str, Any]:
        return self.api.accept_message(event)

    def accept_action(self, event: FeishuActionEvent) -> dict[str, Any]:
        return self.api.accept_action(event)

    def deliver_once(self) -> bool:
        item = self.api.claim_outbox(self.worker_id, lease_seconds=self.lease_seconds)
        if item is None:
            return False
        started = time.monotonic()
        try:
            outbox_id = _positive_int(item.get("id"), "outbox id")
            recipient_type = _bounded_required(item.get("recipient_type"), "recipient_type", 16)
            if recipient_type not in {"CHAT_ID", "OPEN_ID"}:
                raise FeishuCardError("unsupported recipient type")
            recipient_id = _bounded_required(item.get("recipient_id"), "recipient_id", 256)
            message = build_outbound_message(item)
            receipt = self.sender.send(
                recipient_type=recipient_type,
                recipient_id=recipient_id,
                message=message,
                idempotency_key=f"kg-outbox-{outbox_id}",
            )
        except FeishuCardError:
            self._mark_delivery_failure(
                item,
                started,
                code="OUTBOX_PAYLOAD_INVALID",
                message="通道消息未通过结构与敏感字段校验。",
                retryable=False,
            )
        except FeishuDeliveryError as exc:
            self._mark_delivery_failure(
                item,
                started,
                code=exc.code,
                message="飞书接口拒绝或未完成本次投递。",
                retryable=exc.retryable,
            )
        except Exception:
            self._mark_delivery_failure(
                item,
                started,
                code="FEISHU_SEND_FAILED",
                message="飞书投递出现未分类异常。",
                retryable=True,
            )
        else:
            self.api.mark_delivered(
                outbox_id,
                self.worker_id,
                receipt,
                duration_ms=_duration_ms(started),
            )
        return True

    def _mark_delivery_failure(
        self,
        item: dict[str, Any],
        started: float,
        *,
        code: str,
        message: str,
        retryable: bool,
    ) -> None:
        outbox_id = _positive_int(item.get("id"), "outbox id")
        self.api.mark_failed(
            outbox_id,
            self.worker_id,
            code=code,
            message=message,
            duration_ms=_duration_ms(started),
            retryable=retryable,
        )


def normalize_text_message(
    *,
    event_id: str,
    tenant_key: str,
    open_id: str,
    chat_id: str,
    message_id: str,
    message_type: str,
    content: str,
    chat_type: str,
    bot_mention_keys: tuple[str, ...] = (),
) -> FeishuMessageEvent | None:
    if message_type != "text" or chat_type not in {"p2p", "group"}:
        return None
    try:
        decoded = json.loads(content)
    except (TypeError, ValueError):
        return None
    if not isinstance(decoded, dict) or not isinstance(decoded.get("text"), str):
        return None
    text = decoded["text"]
    if chat_type == "group":
        if not bot_mention_keys:
            return None
        for key in bot_mention_keys:
            text = text.replace(key, "")
    return FeishuMessageEvent(
        event_id=" ".join(event_id.split())[:256],
        tenant_key=" ".join(tenant_key.split())[:128],
        open_id=" ".join(open_id.split())[:128],
        chat_id=" ".join(chat_id.split())[:256],
        message_id=" ".join(message_id.split())[:256],
        text=text.strip()[:4001],
        chat_type=chat_type,
    )


def normalize_card_action(
    *,
    event_id: str,
    tenant_key: str,
    open_id: str,
    value: Any,
) -> FeishuActionEvent | None:
    if not isinstance(value, dict) or set(value) != {"token"}:
        return None
    token = value.get("token")
    if not isinstance(token, str) or not 32 <= len(token) <= 512:
        return None
    return FeishuActionEvent(
        event_id=" ".join(event_id.split())[:256],
        tenant_key=" ".join(tenant_key.split())[:128],
        open_id=" ".join(open_id.split())[:128],
        token=token,
    )


def _local_api_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme != "http" or parsed.hostname not in LOCAL_API_HOSTS:
        raise ValueError("channel API must use a loopback HTTP address")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("channel API URL cannot contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("channel API URL cannot contain a path")
    return value.rstrip("/")


def _bounded_required(value: Any, field: str, max_chars: int) -> str:
    normalized = " ".join(str(value or "").split())[:max_chars]
    if not normalized:
        raise FeishuCardError(f"{field} is required")
    return normalized


def _positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise FeishuCardError(f"{field} must be a positive integer")
    return value


def _duration_ms(started: float) -> int:
    return min(max(int((time.monotonic() - started) * 1000), 0), 300_000)


def _error_code(value: str) -> str:
    code = re.sub(r"[^A-Z0-9_]", "", str(value).upper())[:64]
    return code or "DELIVERY_FAILED"


def _optional_error_code(value: str | None) -> str | None:
    return _error_code(value) if value else None
