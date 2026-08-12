from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
from pathlib import Path
from typing import Any

from backend.app.agent.health_contract import general_health_core_requirements


@dataclass(frozen=True)
class EvidenceObligation:
    key: str
    title: str
    tool_name: str
    arguments: dict[str, Any]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def next_evidence_obligation(
    task: Any,
    *,
    allowed_tool_names: set[str],
    allowed_argument_values: dict[str, list[Any]],
    tool_history: list[Any],
    evidence_items: list[Any] | tuple[Any, ...] = (),
) -> EvidenceObligation | None:
    """Return the next evidence required before a causal conclusion is allowed."""

    intent = getattr(task, "intent", "")
    if intent == "general_system_health":
        for requirement in general_health_core_requirements():
            if (
                requirement.tool_name in allowed_tool_names
                and not _tool_was_called(tool_history, requirement.tool_name)
            ):
                return EvidenceObligation(
                    key=f"general_health_{requirement.key}",
                    title=f"补齐{requirement.label}证据",
                    tool_name=requirement.tool_name,
                    arguments=dict(requirement.arguments),
                    reason=requirement.reason,
                )
        failed_unit = _first_failed_service_unit(evidence_items)
        if (
            failed_unit
            and "service_status" in allowed_tool_names
            and failed_unit in allowed_argument_values.get("service_status.unit", [])
            and not _unit_was_queried(tool_history, "service_status", failed_unit)
        ):
            return EvidenceObligation(
                key="general_health_failed_service_detail",
                title="核对失败服务启动上下文",
                tool_name="service_status",
                arguments={"unit": failed_unit},
                reason=(
                    "综合巡检已观测到失败服务，需取得该单元的启动入口、"
                    "退出状态与单元文件位置，避免把 failed 状态本身误当根因。"
                ),
            )
        if (
            failed_unit
            and "service_desired_state" in allowed_tool_names
            and failed_unit in allowed_argument_values.get("service_desired_state.unit", [])
            and not _unit_was_queried(tool_history, "service_desired_state", failed_unit)
        ):
            return EvidenceObligation(
                key="general_health_failed_service_expectation",
                title="核对失败服务期望状态",
                tool_name="service_desired_state",
                arguments={"unit": failed_unit},
                reason=(
                    "综合巡检已观测到失败服务，需读取经审批的责任方与期望状态记录，"
                    "避免根据单元名称或描述猜测该失败是否应被处置。"
                ),
            )
        if (
            failed_unit
            and "journal_query" in allowed_tool_names
            and failed_unit in allowed_argument_values.get("journal_query.unit", [])
            and not _unit_was_queried(tool_history, "journal_query", failed_unit)
        ):
            return EvidenceObligation(
                key="general_health_failed_service_log",
                title="追查失败服务日志",
                tool_name="journal_query",
                arguments={"unit": failed_unit, "lines": 80},
                reason="综合巡检已观测到失败服务，需读取该服务近期日志后再形成异常结论。",
            )
        return None

    if intent == "log_analysis":
        service_unit = _first_observed_service_unit(evidence_items)
        if (
            service_unit
            and "service_desired_state" in allowed_tool_names
            and service_unit in allowed_argument_values.get("service_desired_state.unit", [])
            and not _unit_was_queried(tool_history, "service_desired_state", service_unit)
        ):
            return EvidenceObligation(
                key="service_state_expectation",
                title="核对服务期望状态",
                tool_name="service_desired_state",
                arguments={"unit": service_unit},
                reason=(
                    "服务运行状态必须与经审批的责任方和期望状态记录比对，"
                    "不能根据单元名称、描述或退出命令推断资产意图。"
                ),
            )
        if (
            service_unit
            and _requests_service_restart(str(getattr(task, "user_input", "")))
            and "service_dependency_snapshot" in allowed_tool_names
            and service_unit
            in allowed_argument_values.get("service_dependency_snapshot.focus_units", [])
            and not _unit_change_was_assessed(
                tool_history,
                service_unit,
                action="restart",
            )
        ):
            return EvidenceObligation(
                key="service_restart_impact",
                title="核对重启影响范围",
                tool_name="service_dependency_snapshot",
                arguments={
                    "focus_units": [service_unit],
                    "change_action": "restart",
                    "max_listeners": 160,
                    "max_connections": 320,
                    "max_systemd_relations": 160,
                },
                reason=(
                    "重启方案必须先核对目标单元的 systemd 传播关系、"
                    "运行进程和当前连接，不能只依据服务状态进入审批。"
                ),
            )
        if (
            service_unit
            and "journal_query" in allowed_tool_names
            and service_unit in allowed_argument_values.get("journal_query.unit", [])
            and not _unit_was_queried(tool_history, "journal_query", service_unit)
        ):
            return EvidenceObligation(
                key="service_state_log",
                title="核对服务近期日志",
                tool_name="journal_query",
                arguments={"unit": service_unit, "lines": 80},
                reason="服务状态和期望记录已取得，需补充近期日志后再形成故障结论。",
            )
        return None

    if intent != "service_degradation_analysis":
        return None

    if _tool_was_called(tool_history, "service_health_probe"):
        log_path = _first_path(
            allowed_argument_values.get("application_log_query.path", []),
            _looks_like_log_path,
        )
        if (
            log_path
            and "application_log_query" in allowed_tool_names
            and not _path_was_queried(tool_history, "application_log_query", log_path)
        ):
            return EvidenceObligation(
                key="service_failure_log",
                title="关联服务失败日志",
                tool_name="application_log_query",
                arguments={"path": log_path, "lines": 120},
                reason="健康检查已经给出受证据约束的日志路径，需关联同一请求的依赖失败记录。",
            )

    dependency_port = _loopback_server_port(evidence_items)
    if (
        dependency_port is not None
        and "service_dependency_snapshot" in allowed_tool_names
        and dependency_port
        in allowed_argument_values.get("service_dependency_snapshot.focus_ports", [])
        and not _port_was_snapshotted(tool_history, dependency_port)
    ):
        return EvidenceObligation(
            key="dependency_listener_identity",
            title="核对依赖端口归属",
            tool_name="service_dependency_snapshot",
            arguments={"focus_ports": [dependency_port]},
            reason=(
                "应用失败日志以 server.address 和 server.port 指向本机目标，"
                "需核对该端口当时的监听进程。"
            ),
        )

    user_input = str(getattr(task, "user_input", ""))
    if not _requests_config_verification(user_input):
        return None
    config_path = _first_path(
        allowed_argument_values.get("config_integrity_scan.paths", []),
        _looks_like_config_path,
    )
    if (
        config_path
        and "config_integrity_scan" in allowed_tool_names
        and not _config_path_was_scanned(tool_history, config_path)
    ):
        return EvidenceObligation(
            key="configuration_counter_evidence",
            title="独立核验配置内容",
            tool_name="config_integrity_scan",
            arguments={"paths": [config_path]},
            reason="用户要求核验配置痕迹，必须用文件哈希独立确认或反驳配置内容漂移。",
        )
    return None


def _tool_was_called(tool_history: list[Any], tool_name: str) -> bool:
    return any(getattr(call, "tool_name", "") == tool_name for call in tool_history)


def _path_was_queried(tool_history: list[Any], tool_name: str, path: str) -> bool:
    normalized = _normalize_path(path)
    for call in tool_history:
        if getattr(call, "tool_name", "") != tool_name:
            continue
        arguments = getattr(call, "input_json", {})
        if (
            isinstance(arguments, dict)
            and _normalize_path(arguments.get("path")) == normalized
        ):
            return True
    return False


def _unit_was_queried(tool_history: list[Any], tool_name: str, unit: str) -> bool:
    normalized = unit.strip()
    for call in tool_history:
        if getattr(call, "tool_name", "") != tool_name:
            continue
        arguments = getattr(call, "input_json", {})
        if isinstance(arguments, dict) and str(arguments.get("unit") or "").strip() == normalized:
            return True
    return False


def _first_failed_service_unit(
    evidence_items: list[Any] | tuple[Any, ...],
) -> str | None:
    for item in evidence_items:
        if getattr(item, "source_key", "") != "service_status":
            continue
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        payload = getattr(item, "payload_json", {})
        if not isinstance(payload, dict):
            continue
        active_state = payload.get("active_state") or payload.get("active")
        if str(active_state or "").lower() != "failed":
            continue
        unit = payload.get("unit")
        if isinstance(unit, str) and unit.endswith(".service"):
            return unit
    return None


def _first_observed_service_unit(
    evidence_items: list[Any] | tuple[Any, ...],
) -> str | None:
    for item in evidence_items:
        if getattr(item, "source_key", "") != "service_status":
            continue
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        payload = getattr(item, "payload_json", {})
        unit = payload.get("unit") if isinstance(payload, dict) else None
        if isinstance(unit, str) and unit.endswith(".service"):
            return unit
    return None


def _config_path_was_scanned(tool_history: list[Any], path: str) -> bool:
    normalized = _normalize_path(path)
    for call in tool_history:
        if getattr(call, "tool_name", "") != "config_integrity_scan":
            continue
        arguments = getattr(call, "input_json", {})
        paths = arguments.get("paths", []) if isinstance(arguments, dict) else []
        if any(_normalize_path(item) == normalized for item in paths if isinstance(item, str)):
            return True
    return False


def _port_was_snapshotted(tool_history: list[Any], port: int) -> bool:
    for call in tool_history:
        if getattr(call, "tool_name", "") != "service_dependency_snapshot":
            continue
        arguments = getattr(call, "input_json", {})
        focus_ports = (
            arguments.get("focus_ports", []) if isinstance(arguments, dict) else []
        )
        if port in focus_ports:
            return True
    return False


def _unit_change_was_assessed(
    tool_history: list[Any],
    unit: str,
    *,
    action: str,
) -> bool:
    normalized = unit.strip()
    for call in tool_history:
        if getattr(call, "tool_name", "") != "service_dependency_snapshot":
            continue
        arguments = getattr(call, "input_json", {})
        if not isinstance(arguments, dict):
            continue
        focus_units = arguments.get("focus_units", [])
        if normalized in focus_units and arguments.get("change_action") == action:
            return True
    return False


def _requests_service_restart(user_input: str) -> bool:
    normalized = user_input.lower()
    return any(
        term in normalized
        for term in ("重启", "restart", "重新启动", "拉起服务")
    )


def _loopback_server_port(
    evidence_items: list[Any] | tuple[Any, ...],
) -> int | None:
    for item in reversed(evidence_items):
        if getattr(item, "source_key", "") != "application_log_query":
            continue
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        payload = getattr(item, "payload_json", {})
        records = payload.get("records", []) if isinstance(payload, dict) else []
        if not isinstance(records, list):
            continue
        for record in reversed(records):
            if not isinstance(record, dict) or record.get("event") != "request_failed":
                continue
            address = record.get("server.address")
            port = record.get("server.port")
            if _is_loopback_address(address) and _is_valid_port(port):
                return int(port)
    return None


def _is_loopback_address(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _is_valid_port(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= 65535
    )


def _first_path(values: list[Any], predicate: Any) -> str | None:
    candidates = sorted(
        {
            _normalize_path(value)
            for value in values
            if isinstance(value, str) and value.startswith("/") and predicate(value)
        }
    )
    return candidates[0] if candidates else None


def _looks_like_log_path(value: str) -> bool:
    path = Path(value)
    return (
        path.suffix.lower() in {".jsonl", ".log", ".out", ".err"}
        or "log" in path.name.lower()
    )


def _looks_like_config_path(value: str) -> bool:
    path = Path(value)
    return (
        path.suffix.lower() in {".conf", ".cfg", ".ini", ".toml", ".yaml", ".yml"}
        or str(path).startswith("/etc/")
    )


def _requests_config_verification(user_input: str) -> bool:
    return any(token in user_input for token in ("配置", "漂移", "哈希", "变更", "改动"))


def _normalize_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        return ""
    return str(Path(value).resolve(strict=False))
