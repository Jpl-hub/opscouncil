from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.app.perception.network_scope import classify_listener_scope
from backend.app.schemas.enums import RiskLevel, max_risk


@dataclass(frozen=True)
class EvidenceRiskAssessment:
    risk_level: RiskLevel
    reasons: tuple[str, ...]
    tool_names: tuple[str, ...]


def assess_evidence_risk(observations: list[dict[str, Any]]) -> EvidenceRiskAssessment:
    risk_level = RiskLevel.R0
    reasons: list[str] = []
    tool_names: list[str] = []

    def record(level: RiskLevel, reason: str, tool_name: str) -> None:
        nonlocal risk_level
        risk_level = max_risk(risk_level, level)
        if reason not in reasons:
            reasons.append(reason)
        if tool_name not in tool_names:
            tool_names.append(tool_name)

    for item in observations:
        tool_name = str(item.get("tool_name") or "unknown")
        result = item.get("result")
        if not isinstance(result, dict):
            record(RiskLevel.R1, f"{tool_name} 未返回结构化结果。", tool_name)
            continue

        status = str(result.get("status") or "ok")
        warnings = result.get("warnings")
        warnings = warnings if isinstance(warnings, list) else []
        if status != "ok":
            record(RiskLevel.R1, f"{tool_name} 采集状态为 {status}。", tool_name)
        elif warnings:
            record(RiskLevel.R1, f"{tool_name} 存在 {len(warnings)} 条采集提示。", tool_name)

        fields = result.get("summary_fields")
        fields = fields if isinstance(fields, dict) else {}
        if tool_name == "network_listeners":
            rows = result.get("observations")
            rows = rows if isinstance(rows, list) else []
            exposed_count = sum(
                _field_or_default(fields, key, _network_scope_count(rows, scope))
                for key, scope in (
                    ("wildcard_listener_count", "wildcard"),
                    ("public_listener_count", "public"),
                    ("unknown_scope_listener_count", "unknown"),
                )
            )
            unattributed_count = _field_or_default(
                fields,
                "unattributed_listener_count",
                sum(
                    row.get("pid") is None and not str(row.get("process") or "").strip()
                    for row in rows
                    if isinstance(row, dict)
                ),
            )
            if exposed_count:
                record(
                    RiskLevel.R2,
                    f"发现 {exposed_count} 个公网、全地址或范围未知监听。",
                    tool_name,
                )
            if unattributed_count:
                record(
                    RiskLevel.R1,
                    f"发现 {unattributed_count} 个监听端口缺少进程归属。",
                    tool_name,
                )

        if tool_name == "disk_usage":
            highest_percent = _number(fields.get("highest_used_percent"))
            if highest_percent is not None and highest_percent >= 90:
                record(
                    RiskLevel.R2,
                    f"文件系统最高使用率达到 {highest_percent:.1f}%。",
                    tool_name,
                )
            elif highest_percent is not None and highest_percent >= 80:
                record(
                    RiskLevel.R1,
                    f"文件系统最高使用率达到 {highest_percent:.1f}%。",
                    tool_name,
                )

        if tool_name == "deleted_open_files":
            rows = result.get("observations")
            rows = rows if isinstance(rows, list) else []
            retained_rows = [
                row
                for row in rows
                if isinstance(row, dict)
                and isinstance(row.get("size_bytes"), (int, float))
                and not isinstance(row.get("size_bytes"), bool)
                and float(row["size_bytes"]) > 0
            ]
            if retained_rows:
                retained_bytes = _field_or_default(
                    fields,
                    "retained_bytes",
                    sum(int(row["size_bytes"]) for row in retained_rows),
                )
                retained_file_count = _field_or_default(
                    fields,
                    "retained_file_count",
                    len(retained_rows),
                )
                record(
                    RiskLevel.R2,
                    (
                        f"发现 {retained_file_count} 个已删除但仍被进程持有的文件，"
                        f"保留 {retained_bytes} 字节磁盘空间。"
                    ),
                    tool_name,
                )

        if tool_name in {"config_integrity_scan", "config_baseline_check"}:
            rows = result.get("observations")
            rows = rows if isinstance(rows, list) else []
            expanded_permissions = [
                row
                for row in rows
                if isinstance(row, dict)
                and row.get("file_type") != "symlink"
                and _is_world_writable_mode(row.get("mode"))
            ]
            if expanded_permissions:
                record(
                    RiskLevel.R2,
                    f"发现 {len(expanded_permissions)} 个配置文件对其他用户开放写权限。",
                    tool_name,
                )
            if tool_name == "config_baseline_check":
                material_changes = [
                    row
                    for row in rows
                    if isinstance(row, dict)
                    and set(row.get("change_types") or [])
                    & {
                        "content_changed",
                        "permission_changed",
                        "added",
                        "missing",
                        "unavailable",
                    }
                ]
                metadata_changes = [
                    row
                    for row in rows
                    if isinstance(row, dict)
                    and set(row.get("change_types") or []) == {"metadata_changed"}
                ]
                if material_changes:
                    record(
                        RiskLevel.R2,
                        f"确认基线比较发现 {len(material_changes)} 个配置路径发生内容、权限或存在性漂移。",
                        tool_name,
                    )
                elif metadata_changes:
                    record(
                        RiskLevel.R1,
                        f"确认基线比较发现 {len(metadata_changes)} 个配置路径仅发生元数据变化。",
                        tool_name,
                    )

        if tool_name == "service_health_probe":
            rows = result.get("observations")
            rows = rows if isinstance(rows, list) else []
            failed_rows = [
                row
                for row in rows
                if isinstance(row, dict)
                and (
                    row.get("available") is False
                    or (
                        isinstance(row.get("status_code"), int)
                        and int(row["status_code"]) >= 500
                    )
                )
            ]
            if failed_rows:
                record(
                    RiskLevel.R2,
                    f"发现 {len(failed_rows)} 个服务健康端点返回失败或 5xx。",
                    tool_name,
                )

        if tool_name == "application_log_query":
            rows = result.get("observations")
            rows = rows if isinstance(rows, list) else []
            dependency_timeouts = sum(
                record_item.get("reason") == "dependency_timeout"
                for row in rows
                if isinstance(row, dict)
                for record_item in (
                    row.get("records") if isinstance(row.get("records"), list) else []
                )
                if isinstance(record_item, dict)
            )
            if dependency_timeouts:
                record(
                    RiskLevel.R2,
                    f"应用日志记录到 {dependency_timeouts} 次依赖超时。",
                    tool_name,
                )

    return EvidenceRiskAssessment(
        risk_level=risk_level,
        reasons=tuple(reasons),
        tool_names=tuple(tool_names),
    )


def _field_or_default(fields: dict[str, Any], key: str, default: int) -> int:
    value = fields.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return max(0, int(value))


def _network_scope_count(rows: list[Any], target_scope: str) -> int:
    return sum(
        str(row.get("exposure_scope") or classify_listener_scope(str(row.get("local_address") or "")))
        == target_scope
        for row in rows
        if isinstance(row, dict)
    )


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _is_world_writable_mode(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        mode = int(value, 8)
    except ValueError:
        return False
    return bool(mode & 0o002)
