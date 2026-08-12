from __future__ import annotations

from collections.abc import Callable
from typing import Any

from backend.app.mcp.types import ToolResult


SemanticBuilder = Callable[[list[dict[str, Any]], list[str]], tuple[dict[str, Any], list[str]]]


def enrich_tool_result(tool_name: str, result: ToolResult) -> ToolResult:
    summary_fields: dict[str, Any] = {
        "observation_count": len(result.observations),
        "warning_count": len(result.warnings),
        "evidence_count": len(result.evidence_refs),
    }
    risk_hints = list(result.risk_hints)
    builder = _SEMANTIC_BUILDERS.get(tool_name)
    if builder is not None:
        specialized_fields, specialized_hints = builder(result.observations, result.warnings)
        summary_fields.update(specialized_fields)
        risk_hints.extend(specialized_hints)

    summary_fields.update(result.summary_fields)
    return result.model_copy(
        update={
            "summary_fields": summary_fields,
            "risk_hints": list(dict.fromkeys(item for item in risk_hints if item)),
        }
    )


def _disk_usage_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    usage_rows = [
        item
        for item in observations
        if isinstance(item.get("used_percent"), (int, float))
    ]
    if not usage_rows:
        return {
            "highest_used_path": None,
            "highest_used_percent": None,
            "critical_filesystem_count": 0,
        }, []

    highest = max(usage_rows, key=lambda item: float(item["used_percent"]))
    highest_percent = float(highest["used_percent"])
    critical_count = sum(float(item["used_percent"]) >= 90 for item in usage_rows)
    hints: list[str] = []
    if highest_percent >= 90:
        hints.append(f"文件系统使用率达到 {highest_percent:.1f}%，需优先定位占用来源。")
    elif highest_percent >= 80:
        hints.append(f"文件系统使用率达到 {highest_percent:.1f}%，建议持续观察增长趋势。")
    return {
        "highest_used_path": highest.get("path"),
        "highest_used_percent": highest_percent,
        "critical_filesystem_count": critical_count,
    }, hints


def _network_listener_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    wildcard_count = 0
    unattributed_count = 0
    ss_attributed_count = 0
    procfs_attributed_count = 0
    scope_counts = {
        "loopback": 0,
        "private": 0,
        "link_local": 0,
        "wildcard": 0,
        "public": 0,
        "unknown": 0,
    }
    for item in observations:
        address = str(item.get("local_address") or "")
        if _is_wildcard_address(address):
            wildcard_count += 1
        scope = str(item.get("exposure_scope") or "unknown")
        scope_counts[scope if scope in scope_counts else "unknown"] += 1
        source = str(item.get("attribution_source") or "")
        if source == "ss":
            ss_attributed_count += 1
        elif source == "procfs":
            procfs_attributed_count += 1
        if item.get("pid") is None and not str(item.get("process") or "").strip():
            unattributed_count += 1

    hints: list[str] = []
    if wildcard_count:
        hints.append(f"发现 {wildcard_count} 个绑定所有地址的监听端口，需核查网络暴露范围。")
    if unattributed_count:
        hints.append(f"发现 {unattributed_count} 个监听端口缺少进程归属，需补充进程溯源。")
    return {
        "listener_count": len(observations),
        "wildcard_listener_count": wildcard_count,
        "unattributed_listener_count": unattributed_count,
        "ss_attributed_listener_count": ss_attributed_count,
        "procfs_attributed_listener_count": procfs_attributed_count,
        "loopback_listener_count": scope_counts["loopback"],
        "private_listener_count": scope_counts["private"],
        "link_local_listener_count": scope_counts["link_local"],
        "public_listener_count": scope_counts["public"],
        "unknown_scope_listener_count": scope_counts["unknown"],
        "attribution_rate_percent": round(
            (len(observations) - unattributed_count) / len(observations) * 100,
            1,
        )
        if observations
        else 0.0,
    }, hints


def _safe_log_rotate_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    observation = observations[0] if observations else {}
    dry_run = bool(observation.get("dry_run", True))
    hints = (
        ["当前仅生成 dry-run 计划，尚未修改文件。"]
        if dry_run
        else ["日志已按审批结果完成轮转，需保留备份产物用于回滚。"]
    )
    return {
        "dry_run": dry_run,
        "estimated_reclaim_bytes": observation.get(
            "estimated_reclaim_bytes",
            observation.get("reclaimed_bytes", 0),
        ),
        "rollback_strategy": observation.get("rollback_strategy"),
        "artifact_count": 0 if dry_run else 1,
    }, hints


def _restore_log_backup_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    observation = observations[0] if observations else {}
    dry_run = bool(observation.get("dry_run", True))
    hints = (
        ["当前仅验证恢复计划，尚未替换目标文件。"]
        if dry_run
        else ["目标文件已恢复，恢复前快照应继续保留。"]
    )
    return {
        "dry_run": dry_run,
        "restore_bytes": observation.get("restore_bytes", 0),
        "pre_restore_snapshot": bool(
            observation.get("pre_restore_snapshot")
            or observation.get("pre_restore_snapshot_path")
        ),
    }, hints


def _restart_managed_service_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    observation = observations[0] if observations else {}
    dry_run = bool(observation.get("dry_run", True))
    return {
        "unit": observation.get("unit"),
        "dry_run": dry_run,
        "active_state_before": observation.get("active_state"),
        "restart_requested": bool(observation.get("restart_requested")),
        "verification": "service_status",
    }, [
        "当前仅生成服务重启 dry-run 计划，尚未修改服务状态。"
        if dry_run
        else "重启请求已提交，恢复结果必须由独立服务状态证据确认。"
    ]


def _restore_config_mode_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    observation = observations[0] if observations else {}
    dry_run = bool(observation.get("dry_run", True))
    return {
        "path": observation.get("path"),
        "dry_run": dry_run,
        "current_mode": observation.get("current_mode"),
        "target_mode": observation.get("target_mode"),
        "baseline_id": observation.get("baseline_id"),
        "baseline_check_id": observation.get("baseline_check_id"),
        "verification": "config_integrity_scan",
    }, [
        "当前仅验证配置权限恢复计划，尚未修改权限。"
        if dry_run
        else "权限修改请求已提交，结果必须由独立配置扫描确认。"
    ]


def _file_integrity_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    missing_count = sum(item.get("exists") is False for item in observations)
    truncated_count = sum(
        item.get("hash_truncated") is True
        or item.get("content_hash_truncated") is True
        for item in observations
    )
    invalid_gzip_count = sum(item.get("gzip_valid") is False for item in observations)
    hints: list[str] = []
    if missing_count:
        hints.append(f"{missing_count} 个校验目标不存在。")
    if truncated_count:
        hints.append(f"{truncated_count} 个目标超过哈希读取上限，不能作为完整校验证据。")
    if invalid_gzip_count:
        hints.append(f"{invalid_gzip_count} 个压缩产物未通过 gzip 完整性校验。")
    return {
        "verified_file_count": sum(item.get("file_type") == "file" for item in observations),
        "missing_file_count": missing_count,
        "truncated_hash_count": truncated_count,
        "invalid_gzip_count": invalid_gzip_count,
    }, hints


def _process_runtime_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    observation = observations[0] if observations else {}
    utilization = observation.get("fd_utilization_percent")
    hints: list[str] = []
    if observation.get("exists") is False:
        hints.append("目标进程已不存在，可能已退出或发生 PID 变化。")
    if observation.get("fd_scan_truncated") is True:
        hints.append("文件句柄扫描达到上限，当前计数不能视为完整证据。")
    if isinstance(utilization, (int, float)) and utilization >= 80:
        hints.append(f"进程文件句柄使用率达到 {float(utilization):.1f}%，需核对增长趋势。")
    return {
        "pid": observation.get("pid"),
        "process_exists": observation.get("exists"),
        "open_fd_count": observation.get("open_fd_count"),
        "max_open_files_soft": observation.get("max_open_files_soft"),
        "fd_utilization_percent": utilization,
        "systemd_unit": observation.get("systemd_unit"),
        "fd_scan_truncated": observation.get("fd_scan_truncated"),
    }, hints


def _journal_storage_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    observation = observations[0] if observations else {}
    storage = observation.get("storage")
    storage = storage if isinstance(storage, list) else []
    total_scanned_bytes = sum(
        int(item.get("total_bytes") or 0)
        for item in storage
        if isinstance(item, dict)
    )
    archived_count = sum(
        int(item.get("archived_file_count") or 0)
        for item in storage
        if isinstance(item, dict)
    )
    scan_truncated = any(
        item.get("scan_truncated") is True
        for item in storage
        if isinstance(item, dict)
    )
    hints: list[str] = []
    if scan_truncated:
        hints.append("journal 文件扫描达到上限，目录统计不能视为完整证据。")
    settings_status = observation.get("settings_status")
    if settings_status == "no_explicit_settings_found":
        hints.append(
            "未发现显式 journald 留存覆盖；当前证据无法量化发行版默认阈值。"
        )
    elif not observation.get("settings_available"):
        hints.append("未取得 journald 有效留存设置，不能判断轮转策略是否符合预期。")
    return {
        "reported_disk_usage_bytes": observation.get("reported_disk_usage_bytes"),
        "scanned_journal_bytes": total_scanned_bytes,
        "archived_file_count": archived_count,
        "settings_available": bool(observation.get("settings_available")),
        "settings_status": settings_status,
        "scan_truncated": scan_truncated,
    }, hints


def _socket_process_context_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    observation = observations[0] if observations else {}
    listeners = observation.get("listeners")
    listeners = listeners if isinstance(listeners, list) else []
    listener_count = int(observation.get("listener_count") or 0)
    unattributed_count = int(observation.get("unattributed_count") or 0)
    exposed_count = sum(
        item.get("exposure_scope") in {"wildcard", "public", "unknown"}
        for item in listeners
        if isinstance(item, dict)
    )
    service_attributed_count = sum(
        bool(item.get("systemd_unit"))
        for item in listeners
        if isinstance(item, dict)
    )
    hints: list[str] = []
    if listener_count == 0:
        hints.append("目标端口当前未处于监听状态。")
    if exposed_count:
        hints.append(f"目标端口存在 {exposed_count} 个公网、全地址或范围未知监听。")
    if unattributed_count:
        hints.append(f"目标端口仍有 {unattributed_count} 个监听缺少进程归属。")
    if observation.get("scan_truncated") is True:
        hints.append("目标端口匹配结果达到上限，当前归属统计不完整。")
    return {
        "protocol": observation.get("protocol"),
        "port": observation.get("port"),
        "listener_count": listener_count,
        "unattributed_count": unattributed_count,
        "service_attributed_count": service_attributed_count,
        "exposed_listener_count": exposed_count,
        "scan_truncated": bool(observation.get("scan_truncated")),
    }, hints


def _filesystem_mount_context_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    observation = observations[0] if observations else {}
    used_percent = observation.get("used_percent")
    hints: list[str] = []
    if isinstance(used_percent, (int, float)) and used_percent >= 90:
        hints.append(f"目标挂载点使用率达到 {float(used_percent):.1f}%，需优先定位占用来源。")
    elif isinstance(used_percent, (int, float)) and used_percent >= 80:
        hints.append(f"目标挂载点使用率达到 {float(used_percent):.1f}%，建议观察增长趋势。")
    if observation.get("read_only") is True:
        hints.append("目标路径位于只读挂载点，副作用处置不可执行。")
    if observation.get("is_network_filesystem") is True:
        hints.append("目标路径位于网络文件系统，处置前需核对远端可用性和业务归属。")
    return {
        "resolved_path": observation.get("resolved_path"),
        "mount_target": observation.get("mount_target"),
        "filesystem_type": observation.get("filesystem_type"),
        "used_percent": used_percent,
        "read_only": bool(observation.get("read_only")),
        "noexec": bool(observation.get("noexec")),
        "nosuid": bool(observation.get("nosuid")),
        "nodev": bool(observation.get("nodev")),
        "is_network_filesystem": bool(observation.get("is_network_filesystem")),
        "is_separate_mount": observation.get("mount_target") not in {None, "", "/"},
    }, hints


def _service_dependency_snapshot_semantics(
    observations: list[dict[str, Any]],
    _: list[str],
) -> tuple[dict[str, Any], list[str]]:
    observation = observations[0] if observations else {}
    gaps = observation.get("evidence_gaps")
    gaps = gaps if isinstance(gaps, list) else []
    scan = observation.get("scan")
    scan = scan if isinstance(scan, dict) else {}
    hints: list[str] = []
    if gaps:
        hints.append(f"服务关系快照存在 {len(gaps)} 项证据缺口，未归属关系不进入结论。")
    if scan.get("listener_truncated") or scan.get("connection_truncated"):
        hints.append("服务关系采集达到行数上限，当前快照不代表完整业务拓扑。")
    impact = observation.get("change_impact")
    impact = impact if isinstance(impact, dict) else {}
    if impact.get("status") == "PARTIAL":
        hints.append("变更影响按部分证据评估，审批前需保留未归属关系和采集上限。")
    elif impact.get("status") == "UNKNOWN":
        hints.append("目标服务未进入运行关系图，当前影响判断不可用于批准变更。")
    return {
        "service_count": int(observation.get("service_count") or 0),
        "systemd_unit_count": int(observation.get("systemd_unit_count") or 0),
        "process_count": int(observation.get("process_count") or 0),
        "listener_count": int(observation.get("listener_count") or 0),
        "connection_relation_count": int(
            observation.get("connection_relation_count") or 0
        ),
        "external_endpoint_count": int(observation.get("external_endpoint_count") or 0),
        "evidence_gap_count": len(gaps),
        "focus_process_count": len(observation.get("focus_process_ids", []))
        if isinstance(observation.get("focus_process_ids"), list)
        else 0,
        "change_impact_status": impact.get("status"),
        "propagated_unit_count": int(impact.get("propagated_unit_count") or 0),
        "possible_client_count": int(impact.get("possible_client_count") or 0),
    }, hints


def _is_wildcard_address(value: str) -> bool:
    normalized = value.strip().lower()
    return (
        normalized.startswith("0.0.0.0:")
        or normalized.startswith("[::]:")
        or normalized.startswith(":::")
        or normalized.startswith("*:")
    )


_SEMANTIC_BUILDERS: dict[str, SemanticBuilder] = {
    "disk_usage": _disk_usage_semantics,
    "network_listeners": _network_listener_semantics,
    "safe_log_rotate": _safe_log_rotate_semantics,
    "restore_log_backup": _restore_log_backup_semantics,
    "restart_managed_service": _restart_managed_service_semantics,
    "restore_config_mode": _restore_config_mode_semantics,
    "file_integrity_state": _file_integrity_semantics,
    "process_runtime_detail": _process_runtime_semantics,
    "journal_storage_status": _journal_storage_semantics,
    "socket_process_context": _socket_process_context_semantics,
    "filesystem_mount_context": _filesystem_mount_context_semantics,
    "service_dependency_snapshot": _service_dependency_snapshot_semantics,
}
