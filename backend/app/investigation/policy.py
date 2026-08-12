from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from backend.app.core.config import settings
from backend.app.core.pydantic_compat import ValidationError
from backend.app.investigation.schemas import InvestigationToolRequest
from backend.app.mcp.registry import ToolNotFoundError, ToolRegistry
from backend.app.schemas.enums import RISK_ORDER, RiskLevel


class InvestigationPolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class InvestigationBudget:
    max_iterations: int
    max_tool_calls: int
    max_elapsed_ms: int

    @classmethod
    def from_settings(cls) -> "InvestigationBudget":
        return cls(
            max_iterations=settings.investigation_max_iterations,
            max_tool_calls=settings.investigation_max_tool_calls,
            max_elapsed_ms=settings.investigation_max_elapsed_ms,
        )


@dataclass(frozen=True)
class ValidatedToolRequest:
    tool_name: str
    arguments: dict
    reason: str
    signature: str


def _large_file_scan_roots() -> tuple[Path, ...]:
    return (Path("/var/log"), Path("/tmp"), Path.home())


class InvestigationPolicy:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def validate_tool_request(
        self,
        request: InvestigationToolRequest,
        *,
        allowed_tools: set[str],
        existing_signatures: set[str],
        total_tool_calls: int,
        elapsed_ms: int,
        iteration: int,
        budget: InvestigationBudget,
        evidence_items: list[Any] | tuple[Any, ...] = (),
        user_input: str = "",
    ) -> ValidatedToolRequest:
        if iteration < 1 or iteration > budget.max_iterations:
            raise InvestigationPolicyError(
                "ITERATION_BUDGET_EXHAUSTED",
                "investigation iteration budget is exhausted",
            )
        if total_tool_calls >= budget.max_tool_calls:
            raise InvestigationPolicyError(
                "TOOL_CALL_BUDGET_EXHAUSTED",
                "investigation tool-call budget is exhausted",
            )
        if elapsed_ms >= budget.max_elapsed_ms:
            raise InvestigationPolicyError(
                "ELAPSED_BUDGET_EXHAUSTED",
                "investigation elapsed-time budget is exhausted",
            )
        if request.tool_name not in allowed_tools:
            raise InvestigationPolicyError(
                "TOOL_OUTSIDE_SKILL",
                f"tool {request.tool_name} is outside the selected skill",
            )

        try:
            tool = self.registry.get(request.tool_name)
        except ToolNotFoundError as exc:
            raise InvestigationPolicyError(
                "UNKNOWN_TOOL",
                f"tool {request.tool_name} is not registered",
            ) from exc

        availability = self.registry.tool_availability(request.tool_name)
        if not availability["available"]:
            raise InvestigationPolicyError(
                "TOOL_CAPABILITY_UNAVAILABLE",
                (
                    f"tool {request.tool_name} is unavailable on this host: "
                    + "; ".join(availability["reasons"])
                ),
            )

        if RISK_ORDER[tool.risk_level] > RISK_ORDER[RiskLevel.R1]:
            raise InvestigationPolicyError(
                "SIDE_EFFECT_TOOL",
                f"tool {request.tool_name} is not read-only and cannot be used for investigation",
            )

        normalized_request = _normalize_read_only_arguments(
            tool.name,
            request.arguments,
            user_input=user_input,
        )
        try:
            validated = tool.input_model.model_validate(normalized_request)
        except ValidationError as exc:
            raise InvestigationPolicyError(
                "INVALID_ARGUMENTS",
                f"tool arguments failed schema validation: {exc}",
            ) from exc
        arguments = validated.model_dump(mode="json")
        if tool.name == "find_large_files":
            _validate_large_file_roots(arguments.get("roots", []))
        _validate_evidence_bound_arguments(
            tool.name,
            arguments,
            evidence_items=evidence_items,
            user_input=user_input,
        )
        signature = tool_call_signature(tool.name, arguments)
        if signature in existing_signatures:
            raise InvestigationPolicyError(
                "DUPLICATE_TOOL_CALL",
                f"duplicate tool call rejected for {tool.name}",
            )

        return ValidatedToolRequest(
            tool_name=tool.name,
            arguments=arguments,
            reason=request.reason,
            signature=signature,
        )

    def allowed_argument_values(
        self,
        *,
        evidence_items: list[Any] | tuple[Any, ...],
        user_input: str,
    ) -> dict[str, list[Any]]:
        scope = _argument_scope(evidence_items, user_input)
        service_units = _service_units_in_scope(evidence_items, user_input)
        return {
            "process_runtime_detail.pid": sorted(scope.pids)[:100],
            "socket_process_context.port": sorted(scope.ports)[:100],
            "socket_process_context.protocol": sorted(scope.protocols),
            "service_dependency_snapshot.focus_ports": sorted(scope.ports)[:8],
            "service_dependency_snapshot.focus_units": sorted(service_units)[:8],
            "service_dependency_snapshot.change_action": ["observe", "restart"],
            "service_status.unit": sorted(service_units)[:100],
            "service_desired_state.unit": sorted(service_units)[:100],
            "journal_query.unit": sorted(service_units)[:100],
            "service_health_probe.url": sorted(scope.urls)[:100],
            "application_log_query.path": sorted(scope.paths)[:100],
            "config_integrity_scan.paths": sorted(scope.paths)[:100],
            "filesystem_mount_context.path": sorted(scope.paths)[:100],
            "find_large_files.min_size_mb": [
                _requested_large_file_threshold_mb(user_input) or 10
            ],
            "find_large_files.roots": [
                *_requested_large_file_roots(user_input),
            ]
            or ["/var/log", "/tmp"],
        }


@dataclass(frozen=True)
class _ArgumentScope:
    pids: frozenset[int]
    ports: frozenset[int]
    protocols: frozenset[str]
    units: frozenset[str]
    paths: frozenset[str]
    urls: frozenset[str]


def _validate_evidence_bound_arguments(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    evidence_items: list[Any] | tuple[Any, ...],
    user_input: str,
) -> None:
    if tool_name not in {
        "process_runtime_detail",
        "socket_process_context",
        "service_dependency_snapshot",
        "service_status",
        "service_desired_state",
        "journal_query",
        "service_health_probe",
        "application_log_query",
        "config_integrity_scan",
        "filesystem_mount_context",
    }:
        return
    scope = _argument_scope(evidence_items, user_input)
    if tool_name == "process_runtime_detail":
        pid = arguments.get("pid")
        if not isinstance(pid, int) or pid not in scope.pids:
            _raise_outside_scope(tool_name, f"pid {pid}")
        return
    if tool_name == "socket_process_context":
        port = arguments.get("port")
        protocol = str(arguments.get("protocol") or "").lower()
        if not isinstance(port, int) or port not in scope.ports:
            _raise_outside_scope(tool_name, f"port {port}")
        if protocol not in scope.protocols:
            _raise_outside_scope(tool_name, f"protocol {protocol}")
        return
    if tool_name == "service_dependency_snapshot":
        focus_ports = arguments.get("focus_ports", [])
        focus_units = arguments.get("focus_units", [])
        change_action = arguments.get("change_action", "observe")
        if not isinstance(focus_ports, list):
            _raise_outside_scope(tool_name, "focus_ports")
        for port in focus_ports:
            if not isinstance(port, int) or isinstance(port, bool) or port not in scope.ports:
                _raise_outside_scope(tool_name, f"port {port}")
        if not isinstance(focus_units, list):
            _raise_outside_scope(tool_name, "focus_units")
        allowed_units = _service_units_in_scope(evidence_items, user_input)
        for unit in focus_units:
            normalized_unit = _normalize_service_unit(str(unit))
            if normalized_unit not in allowed_units:
                _raise_outside_scope(tool_name, f"unit {normalized_unit}")
        if change_action not in {"observe", "restart"}:
            _raise_outside_scope(tool_name, f"change action {change_action}")
        return
    if tool_name in {"service_status", "service_desired_state"}:
        unit = arguments.get("unit")
        if unit is None and tool_name == "service_status":
            return
        if unit is None:
            _raise_outside_scope(tool_name, "unit")
        normalized_unit = _normalize_service_unit(str(unit))
        if normalized_unit not in _service_units_in_scope(evidence_items, user_input):
            _raise_outside_scope(tool_name, f"unit {normalized_unit}")
        if tool_name == "service_desired_state" and arguments.get("host_key") is not None:
            _raise_outside_scope(tool_name, "host_key must resolve to the current host")
        return
    if tool_name == "journal_query":
        unit = arguments.get("unit")
        if unit is None:
            return
        normalized_unit = _normalize_service_unit(str(unit))
        if normalized_unit not in _service_units_in_scope(evidence_items, user_input):
            _raise_outside_scope(tool_name, f"unit {normalized_unit}")
        return
    if tool_name == "service_health_probe":
        url = arguments.get("url")
        if not isinstance(url, str) or url not in scope.urls:
            _raise_outside_scope(tool_name, f"url {url}")
        return
    if tool_name == "application_log_query":
        path = arguments.get("path")
        if not isinstance(path, str) or _normalize_path(path) not in scope.paths:
            _raise_outside_scope(tool_name, f"path {path}")
        return
    if tool_name == "config_integrity_scan":
        paths = arguments.get("paths")
        if not isinstance(paths, list) or not paths:
            _raise_outside_scope(tool_name, "empty paths")
        for path in paths:
            if not isinstance(path, str) or _normalize_path(path) not in scope.paths:
                _raise_outside_scope(tool_name, f"path {path}")
        return
    path = arguments.get("path")
    if not isinstance(path, str) or not _path_is_in_scope(path, scope.paths):
        _raise_outside_scope(tool_name, f"path {path}")


def _normalize_read_only_arguments(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    user_input: str,
) -> dict[str, Any]:
    normalized = dict(arguments)
    if tool_name != "find_large_files":
        return normalized

    requested_roots = _requested_large_file_roots(user_input)
    roots = normalized.get("roots")
    if not isinstance(roots, list):
        roots = []
    default_roots = requested_roots or ["/var/log", "/tmp"]
    merged_roots: list[str] = []
    for raw_root in [*roots, *default_roots]:
        if not isinstance(raw_root, str) or not raw_root.strip():
            continue
        normalized_root = _normalize_path(raw_root)
        if normalized_root not in merged_roots:
            merged_roots.append(normalized_root)
    normalized["roots"] = merged_roots[:8]

    explicit_threshold = _requested_large_file_threshold_mb(user_input)
    if explicit_threshold is not None:
        normalized["min_size_mb"] = explicit_threshold
        return normalized

    requested = normalized.get("min_size_mb")
    if not isinstance(requested, int) or isinstance(requested, bool) or requested > 10:
        normalized["min_size_mb"] = 10
    return normalized


def _requested_large_file_roots(user_input: str) -> list[str]:
    roots: list[str] = []
    for match in re.finditer(r"(?<![A-Za-z0-9_])(/[^\s，。；;]*)", user_input):
        raw_path = match.group(1).rstrip('"\'）)]}')
        if not raw_path:
            continue
        normalized = _normalize_path(raw_path)
        if normalized not in roots:
            roots.append(normalized)
    return roots


def _validate_large_file_roots(roots: Any) -> None:
    if not isinstance(roots, list) or not roots:
        raise InvestigationPolicyError(
            "INVALID_SCAN_SCOPE",
            "find_large_files requires at least one scan root",
        )
    allowed_roots = _large_file_scan_roots()
    for raw_root in roots:
        if not isinstance(raw_root, str):
            raise InvestigationPolicyError(
                "INVALID_SCAN_SCOPE",
                "find_large_files scan roots must be absolute paths",
            )
        root = Path(raw_root).resolve(strict=False)
        if not any(root == allowed or allowed in root.parents for allowed in allowed_roots):
            raise InvestigationPolicyError(
                "INVALID_SCAN_SCOPE",
                f"find_large_files root outside allowed read-only scan scope: {root}",
            )


def _requested_large_file_threshold_mb(user_input: str) -> int | None:
    number_and_unit = r"(\d+(?:\.\d+)?)\s*(gib|gb|mib|mb)"
    patterns = (
        rf"(?:超过|大于|至少|不小于|不低于)\s*{number_and_unit}",
        rf"{number_and_unit}\s*(?:以上|及以上|起)",
    )
    lowered = user_input.lower()
    for pattern in patterns:
        match = re.search(pattern, lowered)
        if match is None:
            continue
        value = float(match.group(1))
        unit = match.group(2)
        megabytes = value * 1024 if unit in {"gb", "gib"} else value
        return min(max(int(round(megabytes)), 1), 10240)
    return None


def _argument_scope(
    evidence_items: list[Any] | tuple[Any, ...],
    user_input: str,
) -> _ArgumentScope:
    values: dict[str, set[Any]] = {
        "pids": set(),
        "ports": set(),
        "protocols": set(),
        "units": set(),
        "paths": set(),
        "urls": set(),
    }
    for item in evidence_items:
        payload = getattr(item, "payload_json", {})
        _collect_scope_values(payload, values, depth=0)
    _collect_user_scope(user_input, values)
    return _ArgumentScope(
        pids=frozenset(values["pids"]),
        ports=frozenset(values["ports"]),
        protocols=frozenset(values["protocols"]),
        units=frozenset(values["units"]),
        paths=frozenset(values["paths"]),
        urls=frozenset(values["urls"]),
    )


def _service_units_in_scope(
    evidence_items: list[Any] | tuple[Any, ...],
    user_input: str,
) -> frozenset[str]:
    user_units = _argument_scope((), user_input).units
    targeted_items = [
        item
        for item in evidence_items
        if getattr(item, "source_key", None) == "socket_process_context"
    ]
    if not targeted_items:
        return _argument_scope(evidence_items, user_input).units
    values: dict[str, set[Any]] = {
        "pids": set(),
        "ports": set(),
        "protocols": set(),
        "units": set(user_units),
        "paths": set(),
        "urls": set(),
    }
    for item in targeted_items:
        _collect_scope_values(getattr(item, "payload_json", {}), values, depth=0)
    return frozenset(values["units"])


def _collect_scope_values(
    value: Any,
    values: dict[str, set[Any]],
    *,
    depth: int,
) -> None:
    if depth > 4:
        return
    if isinstance(value, list):
        for item in value[:100]:
            _collect_scope_values(item, values, depth=depth + 1)
        return
    if not isinstance(value, dict):
        return
    for raw_key, item in list(value.items())[:100]:
        key = str(raw_key)
        if key in {"pid", "ppid", "ExecMainPID"} and isinstance(item, int) and not isinstance(item, bool):
            if item > 0:
                values["pids"].add(item)
        elif (
            key in {"port", "server.port", "network.peer.port"}
            and isinstance(item, int)
            and 1 <= item <= 65535
        ):
            values["ports"].add(item)
        elif key == "protocol" and str(item).lower() in {"tcp", "udp"}:
            values["protocols"].add(str(item).lower())
        elif key == "network.transport" and str(item).lower() in {"tcp", "udp"}:
            values["protocols"].add(str(item).lower())
        elif key in {"systemd_unit", "unit", "Id"} and isinstance(item, str):
            if item.endswith((".service", ".scope")):
                values["units"].add(_normalize_service_unit(item))
        elif key in {
            "path",
            "log_path",
            "config_path",
            "decoy_config_path",
            "requested_path",
            "resolved_path",
            "mount_target",
            "restore_target",
            "artifact_path",
        } and isinstance(item, str) and item.startswith("/"):
            values["paths"].add(_normalize_path(item))
        elif key in {"url", "health_url", "endpoint"} and isinstance(item, str):
            if item.startswith("http://"):
                values["urls"].add(item)
        elif key == "local_address" and isinstance(item, str):
            port = _port_from_endpoint(item)
            if port is not None:
                values["ports"].add(port)
        _collect_scope_values(item, values, depth=depth + 1)


def _collect_user_scope(user_input: str, values: dict[str, set[Any]]) -> None:
    lowered = user_input.lower()
    for match in re.finditer(r"\bpid\s*[=:：]?\s*(\d{1,7})\b", lowered):
        values["pids"].add(int(match.group(1)))
    for pattern in (
        r"\b(?:tcp|udp)\s*[/：:]?\s*(\d{1,5})\b",
        r"\b(\d{1,5})\s*(?:端口|port)\b",
    ):
        for match in re.finditer(pattern, lowered):
            port = int(match.group(1))
            if 1 <= port <= 65535:
                values["ports"].add(port)
    for protocol in ("tcp", "udp"):
        if re.search(rf"\b{protocol}\b", lowered):
            values["protocols"].add(protocol)
    for match in re.finditer(r"\b[A-Za-z0-9_.@:-]+\.service\b", user_input):
        values["units"].add(_normalize_service_unit(match.group(0)))
    for match in re.finditer(
        r"\b([A-Za-z0-9_.@:-]{1,128})\s*(?:服务|service)\b",
        user_input,
        flags=re.IGNORECASE,
    ):
        values["units"].add(_normalize_service_unit(match.group(1)))
    for match in re.finditer(r"(?<![A-Za-z0-9_])(/[^\s，。；;]*)", user_input):
        path = match.group(1).rstrip("\"'）)]}")
        if path and not path.startswith("//"):
            values["paths"].add(_normalize_path(path))
    for match in re.finditer(r"http://[^\s，。；;、)\]}）\"']+", user_input):
        values["urls"].add(match.group(0))


def _path_is_in_scope(candidate: str, allowed_paths: frozenset[str]) -> bool:
    normalized = Path(_normalize_path(candidate))
    for raw_allowed in allowed_paths:
        allowed = Path(raw_allowed)
        if allowed == Path("/") and normalized != allowed:
            continue
        if normalized == allowed or allowed in normalized.parents or normalized in allowed.parents:
            return True
    return False


def _port_from_endpoint(value: str) -> int | None:
    if ":" not in value:
        return None
    try:
        port = int(value.rsplit(":", 1)[-1])
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def _normalize_service_unit(value: str) -> str:
    normalized = value.strip()
    if not normalized.endswith((".service", ".scope")):
        normalized = f"{normalized}.service"
    return normalized


def _normalize_path(value: str) -> str:
    return str(Path(value).resolve(strict=False))


def _raise_outside_scope(tool_name: str, detail: str) -> None:
    raise InvestigationPolicyError(
        "ARGUMENT_OUTSIDE_EVIDENCE",
        f"tool {tool_name} argument is outside user and evidence scope: {detail}",
    )


def tool_call_signature(tool_name: str, arguments: dict) -> str:
    payload = json.dumps(
        {"tool_name": tool_name, "arguments": arguments},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
