#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
import signal
import socket
import sys
import threading
import time
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import lark_oapi as lark
from lark_oapi.api.im.v1.model.create_message_request import CreateMessageRequest
from lark_oapi.api.im.v1.model.create_message_request_body import CreateMessageRequestBody
from lark_oapi.channel.bot_identity import fetch_bot_identity
from lark_oapi.event.callback.model.p2_card_action_trigger import (
    P2CardActionTrigger,
    P2CardActionTriggerResponse,
)

from backend.app.channels.feishu.client import (
    ChannelApiError,
    DeliveryReceipt,
    FeishuChannelService,
    FeishuDeliveryError,
    InternalChannelApi,
    normalize_card_action,
    normalize_text_message,
    resolve_feishu_runtime_state,
)


LOGGER = logging.getLogger("opscouncil.feishu_channel")
NON_RETRYABLE_FEISHU_CODES = frozenset(
    {
        230001,  # invalid request
        230002,  # permission or scope rejected
        230099,  # invalid CardKit content
        99991661,
        99991663,
        99991664,
        99991668,
    }
)


class OfficialFeishuSender:
    def __init__(self, app_id: str, app_secret: str) -> None:
        self._client = (
            lark.Client.builder()
            .app_id(app_id)
            .app_secret(app_secret)
            .timeout(5)
            .log_level(lark.LogLevel.CRITICAL)
            .build()
        )

    def probe_bot_open_id(self) -> str | None:
        config = self._client.config
        if config is None:
            return None
        try:
            identity = asyncio.run(fetch_bot_identity(config))
        except Exception:
            return None
        return identity.open_id if identity is not None else None

    def send(
        self,
        *,
        recipient_type: str,
        recipient_id: str,
        message: Any,
        idempotency_key: str,
    ) -> DeliveryReceipt:
        receive_id_type = {"CHAT_ID": "chat_id", "OPEN_ID": "open_id"}.get(recipient_type)
        if receive_id_type is None:
            raise FeishuDeliveryError("RECIPIENT_TYPE_INVALID", retryable=False)
        body = (
            CreateMessageRequestBody.builder()
            .receive_id(recipient_id)
            .msg_type(message.msg_type)
            .content(json.dumps(message.content, ensure_ascii=False, separators=(",", ":")))
            .uuid(idempotency_key[:50])
            .build()
        )
        request = (
            CreateMessageRequest.builder()
            .receive_id_type(receive_id_type)
            .request_body(body)
            .build()
        )
        try:
            response = self._client.im.v1.message.create(request)
        except Exception as exc:
            raise FeishuDeliveryError("FEISHU_REQUEST_FAILED", retryable=True) from exc
        if not response.success():
            code = int(response.code or 0)
            raise FeishuDeliveryError(
                f"FEISHU_{code or 'UNKNOWN'}",
                retryable=code not in NON_RETRYABLE_FEISHU_CODES,
            )
        provider_message_id = getattr(response.data, "message_id", None) if response.data else None
        return DeliveryReceipt(provider_message_id=provider_message_id)


class FeishuRuntime:
    def __init__(self) -> None:
        self.app_id = _required_env("FEISHU_APP_ID")
        self.app_secret = _required_env("FEISHU_APP_SECRET")
        self.internal_token = _required_env("OPSCOUNCIL_CHANNEL_INTERNAL_TOKEN")
        self.api_base_url = os.getenv("OPSCOUNCIL_API_BASE_URL", "http://127.0.0.1:8000")
        self.bot_open_id = os.getenv("FEISHU_BOT_OPEN_ID", "").strip()
        self.instance_id = _bounded(
            os.getenv("OPSCOUNCIL_FEISHU_INSTANCE_ID") or f"{socket.gethostname()}-{os.getpid()}",
            128,
        )
        self.poll_seconds = _bounded_float("OPSCOUNCIL_FEISHU_POLL_SECONDS", 0.5, 0.1, 10.0)
        self.heartbeat_seconds = _bounded_float(
            "OPSCOUNCIL_FEISHU_HEARTBEAT_SECONDS", 15.0, 5.0, 30.0
        )
        self.capability_check_seconds = _bounded_float(
            "OPSCOUNCIL_FEISHU_CAPABILITY_CHECK_SECONDS", 60.0, 30.0, 3600.0
        )
        self.stop_event = threading.Event()
        self.socket_connected_event = threading.Event()
        self.bot_capability_event = threading.Event()
        self.ws_failed_event = threading.Event()
        self._next_capability_check_at = 0.0
        self._last_capability_state: bool | None = None
        self.api = InternalChannelApi(self.api_base_url, self.internal_token, timeout_seconds=2.2)
        self.sender = OfficialFeishuSender(self.app_id, self.app_secret)
        self.service = FeishuChannelService(
            self.api,
            self.sender,
            self.instance_id,
        )
        self.dispatcher = (
            lark.EventDispatcherHandler.builder("", "", lark.LogLevel.CRITICAL)
            .register_p2_im_message_receive_v1(self._on_message)
            .register_p2_card_action_trigger(self._on_card_action)
            .build()
        )
        self.ws_client = lark.ws.Client(
            self.app_id,
            self.app_secret,
            log_level=lark.LogLevel.CRITICAL,
            event_handler=self.dispatcher,
            auto_reconnect=True,
            source="opscouncil",
        )
        self.ws_client.on_reconnecting = self.socket_connected_event.clear
        self.ws_client.on_reconnected = self.socket_connected_event.set

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self._request_stop)
        signal.signal(signal.SIGINT, self._request_stop)
        threads = [
            threading.Thread(target=self._run_ws, name="feishu-ws", daemon=True),
            threading.Thread(target=self._run_outbox, name="feishu-outbox", daemon=True),
            threading.Thread(target=self._run_heartbeat, name="feishu-heartbeat", daemon=True),
        ]
        for thread in threads:
            thread.start()
        LOGGER.info("Feishu channel process started")
        while not self.stop_event.wait(0.5):
            if getattr(self.ws_client, "_conn", None) is not None:
                self.socket_connected_event.set()
            if self.ws_failed_event.is_set():
                self.stop_event.set()
        self._send_final_heartbeat()
        self.api.close()
        return 1 if self.ws_failed_event.is_set() else 0

    def _request_stop(self, signum, frame) -> None:  # type: ignore[no-untyped-def]
        self.stop_event.set()

    def _run_ws(self) -> None:
        try:
            self.ws_client.start()
        except Exception:
            LOGGER.error("Feishu long connection stopped unexpectedly")
            self.ws_failed_event.set()

    def _run_outbox(self) -> None:
        while not self.stop_event.is_set():
            try:
                worked = self.service.deliver_once()
            except ChannelApiError:
                LOGGER.error("Internal channel API is unavailable for outbound delivery")
                self.stop_event.wait(2.0)
                continue
            except Exception:
                LOGGER.error("Outbound channel loop encountered an unexpected error")
                self.stop_event.wait(2.0)
                continue
            self.stop_event.wait(0.02 if worked else self.poll_seconds)

    def _run_heartbeat(self) -> None:
        while not self.stop_event.is_set():
            self._refresh_bot_capability()
            socket_connected = self.socket_connected_event.is_set() or getattr(
                self.ws_client, "_conn", None
            ) is not None
            status, detail = resolve_feishu_runtime_state(
                socket_connected=socket_connected,
                bot_capability_ready=self.bot_capability_event.is_set(),
            )
            try:
                self.api.heartbeat(self.instance_id, status, detail)
            except ChannelApiError:
                LOGGER.error("Internal channel API is unavailable for heartbeat")
            self.stop_event.wait(self.heartbeat_seconds)

    def _refresh_bot_capability(self) -> None:
        now = time.monotonic()
        if now < self._next_capability_check_at:
            return
        self._next_capability_check_at = now + self.capability_check_seconds
        open_id = self.sender.probe_bot_open_id()
        ready = bool(open_id)
        if open_id:
            self.bot_open_id = open_id
            self.bot_capability_event.set()
        else:
            self.bot_capability_event.clear()
        if ready != self._last_capability_state:
            if ready:
                LOGGER.info("Feishu bot capability is ready")
            else:
                LOGGER.warning("Feishu bot capability is not ready")
            self._last_capability_state = ready

    def _send_final_heartbeat(self) -> None:
        try:
            self.api.heartbeat(self.instance_id, "STOPPED", "PROCESS_STOPPED")
        except ChannelApiError:
            pass

    def _on_message(self, data: Any) -> None:
        try:
            event = getattr(data, "event", None)
            sender = getattr(event, "sender", None)
            message = getattr(event, "message", None)
            if sender is None or message is None or getattr(sender, "sender_type", None) != "user":
                return
            sender_id = getattr(sender, "sender_id", None)
            bot_keys = tuple(
                str(getattr(mention, "key", ""))
                for mention in (getattr(message, "mentions", None) or [])
                if self.bot_open_id
                and getattr(getattr(mention, "id", None), "open_id", None) == self.bot_open_id
                and getattr(mention, "key", None)
            )
            normalized = normalize_text_message(
                event_id=str(getattr(getattr(data, "header", None), "event_id", "")),
                tenant_key=str(
                    getattr(sender, "tenant_key", None)
                    or getattr(getattr(data, "header", None), "tenant_key", "")
                ),
                open_id=str(getattr(sender_id, "open_id", "")),
                chat_id=str(getattr(message, "chat_id", "")),
                message_id=str(getattr(message, "message_id", "")),
                message_type=str(getattr(message, "message_type", "")),
                content=str(getattr(message, "content", "")),
                chat_type=str(getattr(message, "chat_type", "")),
                bot_mention_keys=bot_keys,
            )
            if normalized is None:
                return
            result = self.service.accept_message(normalized)
            if not result.get("accepted") and not result.get("duplicate"):
                LOGGER.warning(
                    "Inbound Feishu message was rejected: %s",
                    _safe_reason(result.get("reason_code")),
                )
        except ChannelApiError:
            LOGGER.error("Internal channel API is unavailable for inbound message")
        except Exception:
            LOGGER.error("Inbound Feishu message could not be normalized")

    def _on_card_action(self, data: P2CardActionTrigger) -> P2CardActionTriggerResponse:
        try:
            event = getattr(data, "event", None)
            operator = getattr(event, "operator", None)
            action = getattr(event, "action", None)
            normalized = normalize_card_action(
                event_id=str(getattr(getattr(data, "header", None), "event_id", "")),
                tenant_key=str(
                    getattr(operator, "tenant_key", None)
                    or getattr(getattr(data, "header", None), "tenant_key", "")
                ),
                open_id=str(getattr(operator, "open_id", "")),
                value=getattr(action, "value", None),
            )
            if normalized is None:
                return _toast("warning", "无效的审批请求")
            result = self.service.accept_action(normalized)
            if result.get("accepted"):
                return _toast("success", "审批决定已进入安全执行队列")
            if result.get("duplicate"):
                return _toast("info", "该审批请求已处理")
            return _toast("warning", "审批已失效或身份不匹配")
        except ChannelApiError:
            LOGGER.error("Internal channel API is unavailable for card action")
            return _toast("error", "审批服务暂时不可用")
        except Exception:
            LOGGER.error("Feishu card action could not be normalized")
            return _toast("error", "审批请求处理失败")


def _toast(kind: str, content: str) -> P2CardActionTriggerResponse:
    return P2CardActionTriggerResponse(
        {"toast": {"type": kind, "content": content}}
    )


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"required environment variable is missing: {name}")
    return value


def _bounded(value: str, max_chars: int) -> str:
    normalized = " ".join(value.split())[:max_chars]
    if not normalized:
        raise RuntimeError("channel instance id is empty")
    return normalized


def _bounded_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"invalid numeric environment variable: {name}") from exc
    return min(max(value, minimum), maximum)


def _safe_reason(value: Any) -> str:
    reason = "".join(character for character in str(value or "") if character.isalnum() or character == "_")
    return reason[:64] or "REJECTED"


def main() -> int:
    logging.basicConfig(
        level=os.getenv("OPSCOUNCIL_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        runtime = FeishuRuntime()
    except Exception:
        LOGGER.error("Feishu channel configuration is incomplete or invalid")
        return 2
    return runtime.run()


if __name__ == "__main__":
    raise SystemExit(main())
