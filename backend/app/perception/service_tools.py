from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import socket
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from backend.app.core.pydantic_compat import BaseModel, Field, field_validator
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.schemas.enums import RiskLevel


_LOG_ROOTS = (Path("/var/log"), Path("/tmp/opscouncil-lab"))
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|authorization|api[_-]?key)\s*[:=]\s*[^\s,;]+"
)


class ServiceHealthProbeInput(BaseModel):
    url: str = Field(min_length=12, max_length=512)
    timeout_ms: int = Field(default=1200, ge=100, le=5000)
    max_response_bytes: int = Field(default=32 * 1024, ge=1024, le=128 * 1024)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        _validate_loopback_url(value)
        return value


class ApplicationLogQueryInput(BaseModel):
    path: str = Field(min_length=1, max_length=512)
    lines: int = Field(default=120, ge=1, le=500)
    max_bytes: int = Field(default=256 * 1024, ge=4096, le=1024 * 1024)
    contains: str | None = Field(default=None, max_length=128)


def service_health_probe(payload: BaseModel) -> ToolResult:
    args = ServiceHealthProbeInput.model_validate(payload)
    started = time.monotonic()
    try:
        with httpx.Client(
            timeout=args.timeout_ms / 1000,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            with client.stream("GET", args.url) as response:
                status_code = response.status_code
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                content, truncated = _read_response_prefix(
                    response,
                    args.max_response_bytes,
                )
    except httpx.TimeoutException:
        return ToolResult(
            status="partial",
            observations=[
                {
                    "url": args.url,
                    "available": False,
                    "failure": "timeout",
                    "latency_ms": int((time.monotonic() - started) * 1000),
                }
            ],
            warnings=["本机健康检查在时限内未返回"],
            evidence_refs=[f"http-health:{args.url}"],
        )
    except httpx.HTTPError as exc:
        return ToolResult(
            status="partial",
            observations=[
                {
                    "url": args.url,
                    "available": False,
                    "failure": "connection_error",
                    "latency_ms": int((time.monotonic() - started) * 1000),
                }
            ],
            warnings=[f"本机健康检查连接失败：{type(exc).__name__}"],
            evidence_refs=[f"http-health:{args.url}"],
        )

    body_summary = _response_summary(content, content_type)
    observation = {
        "url": args.url,
        "available": 200 <= status_code < 400,
        "status_code": status_code,
        "latency_ms": int((time.monotonic() - started) * 1000),
        "content_type": content_type or None,
        "body_sha256": hashlib.sha256(content).hexdigest(),
        "body_truncated": truncated,
        "body_summary": body_summary,
    }
    return ToolResult(
        status="ok",
        observations=[observation],
        risk_hints=[] if observation["available"] else ["本机服务健康检查未通过"],
        evidence_refs=[f"http-health:{args.url}"],
    )


def application_log_query(payload: BaseModel) -> ToolResult:
    args = ApplicationLogQueryInput.model_validate(payload)
    try:
        path = _validated_log_path(args.path)
    except ValueError as exc:
        return ToolResult(status="rejected", warnings=[str(exc)])

    try:
        size_bytes = path.stat().st_size
        content, start_offset = _read_tail(path, args.max_bytes)
    except OSError as exc:
        return ToolResult(status="error", warnings=[f"应用日志读取失败：{exc}"])

    decoded = content.decode("utf-8", errors="replace")
    raw_lines = decoded.splitlines()
    if start_offset > 0 and raw_lines:
        raw_lines = raw_lines[1:]
    if args.contains:
        needle = args.contains.casefold()
        raw_lines = [line for line in raw_lines if needle in line.casefold()]
    selected = raw_lines[-args.lines :]
    redacted_lines = [_redact_log_line(line) for line in selected]
    observations = [
        {
            "path": str(path),
            "size_bytes": size_bytes,
            "start_offset": start_offset,
            "line_count": len(selected),
            "truncated": start_offset > 0 or len(raw_lines) > len(selected),
            "lines": redacted_lines,
            "records": _structured_log_records(redacted_lines),
        }
    ]
    return ToolResult(
        status="ok",
        observations=observations,
        evidence_refs=[f"log-tail:{path}:{start_offset}-{size_bytes}"],
    )


def build_service_tool_definitions() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="service_health_probe",
            version="1.0.0",
            description=(
                "Measure status and latency of an HTTP health endpoint on the local loopback "
                "interface. Remote hosts, redirects, credentials, query strings, and fragments "
                "are rejected."
            ),
            risk_level=RiskLevel.R0,
            input_model=ServiceHealthProbeInput,
            output_model=ToolResult,
            handler=service_health_probe,
        ),
        ToolDefinition(
            name="application_log_query",
            version="1.0.0",
            description=(
                "Read a bounded tail from one regular application log under /var/log or the "
                "isolated OpsBench directory, with credential-like assignments redacted."
            ),
            risk_level=RiskLevel.R0,
            input_model=ApplicationLogQueryInput,
            output_model=ToolResult,
            handler=application_log_query,
            capability_requirements=("filesystem.read",),
        ),
    ]


def _validate_loopback_url(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme != "http":
        raise ValueError("service health probe only supports http loopback URLs")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("service health probe URL cannot contain credentials, query, or fragment")
    if not parsed.hostname:
        raise ValueError("service health probe URL is missing a host")
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                parsed.hostname,
                parsed.port or 80,
                type=socket.SOCK_STREAM,
            )
        }
    except (OSError, ValueError) as exc:
        raise ValueError("service health probe host cannot be resolved") from exc
    if not addresses or any(not ipaddress.ip_address(address).is_loopback for address in addresses):
        raise ValueError("service health probe target must resolve only to loopback addresses")


def _response_summary(content: bytes, content_type: str) -> dict[str, Any] | str | None:
    text = content.decode("utf-8", errors="replace")
    if content_type == "application/json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return _redact_log_line(text[:1000])
        return _bounded_json_summary(payload)
    compact = " ".join(text.split())
    return _redact_log_line(compact[:1000]) if compact else None


def _read_response_prefix(
    response: httpx.Response,
    max_response_bytes: int,
) -> tuple[bytes, bool]:
    content = bytearray()
    for chunk in response.iter_bytes():
        remaining = max_response_bytes - len(content)
        if len(chunk) > remaining:
            content.extend(chunk[:remaining])
            return bytes(content), True
        content.extend(chunk)
    return bytes(content), False


def _structured_log_records(lines: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            summary = _bounded_json_summary(payload)
            if isinstance(summary, dict):
                records.append(summary)
    return records


def _bounded_json_summary(value: Any, *, depth: int = 0) -> Any:
    if depth > 3:
        return "[层级已截断]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:30]:
            key = str(raw_key)[:80]
            if any(part in key.casefold() for part in ("password", "secret", "token", "authorization", "api_key")):
                result[key] = "[已脱敏]"
            else:
                result[key] = _bounded_json_summary(item, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [_bounded_json_summary(item, depth=depth + 1) for item in value[:20]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_log_line(str(value)[:500])


def _validated_log_path(raw_path: str) -> Path:
    requested = Path(raw_path)
    if not requested.is_absolute():
        raise ValueError("应用日志路径必须为绝对路径")
    resolved = requested.resolve(strict=True)
    if not any(resolved == root or root in resolved.parents for root in _LOG_ROOTS):
        raise ValueError("应用日志路径不在允许的只读范围")
    if not resolved.is_file():
        raise ValueError("应用日志路径不是普通文件")
    return resolved


def _read_tail(path: Path, max_bytes: int) -> tuple[bytes, int]:
    size = path.stat().st_size
    start = max(size - max_bytes, 0)
    with path.open("rb") as handle:
        handle.seek(start)
        return handle.read(max_bytes), start


def _redact_log_line(value: str) -> str:
    redacted = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}=[已脱敏]",
        value,
    )
    return redacted[:2000]
