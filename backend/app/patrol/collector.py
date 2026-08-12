from __future__ import annotations

import time
from typing import Any

from sqlalchemy.orm import Session

from backend.app.assets.exposure import reconcile_listener_expectations
from backend.app.assets.reconciliation import reconcile_service_expectations
from backend.app.assets.service import ServiceExpectationService
from backend.app.config_baseline.service import ConfigBaselineService, LIVE_SCOPE
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolResult
from backend.app.models.entities import ServiceExpectation
from backend.app.perception.tools import ServiceStatusInput
from backend.app.posture.service import LivePostureService


HARD_TOOL_FAILURES = {"error", "unavailable"}
SIGNAL_ORDER = {"ok": 0, "unknown": 0, "warn": 1, "critical": 2}


class PatrolCollector:
    def __init__(self, registry: ToolRegistry, session: Session) -> None:
        self.registry = registry
        self.session = session

    def read(self) -> dict[str, Any]:
        report = LivePostureService(self.registry, session=self.session).read()
        tool_runs = list(report.get("tool_runs") or [])
        service_run = self._call_tool("service_status", {})
        time_run = self._call_tool("time_sync_status", {})
        tool_runs.extend([service_run, time_run])

        signals = {
            str(item.get("key")): dict(item)
            for item in (report.get("signals") or [])
            if isinstance(item, dict) and isinstance(item.get("key"), str)
        }
        signals["inode_pressure"] = _inode_signal(report.get("disks"))
        signals["memory_pressure"] = _memory_pressure_signal(
            signals.get("memory_pressure"),
            report.get("snapshot"),
        )
        signals["failed_service"] = _failed_service_signal(service_run)
        signals["time_sync"] = _time_sync_signal(time_run)

        config_signal, config_run, config_summary = self._configuration_signal()
        signals["config_drift"] = config_signal
        if config_run is not None:
            tool_runs.append(config_run)

        service_expectation_signal, expectation_runs, expectation_summary = (
            self._service_expectation_signal(report)
        )
        signals["service_expectation"] = service_expectation_signal
        tool_runs.extend(expectation_runs)

        signals["mcp_health"] = _mcp_health_signal(tool_runs)
        collection_status = _collection_status(tool_runs)
        warnings = [
            warning
            for tool_run in tool_runs
            for warning in tool_run.get("warnings", [])
            if isinstance(warning, str) and warning.strip()
        ]
        ordered_signals = list(signals.values())
        return {
            **report,
            "collection_status": collection_status,
            "status": _operational_status(ordered_signals),
            "tool_runs": tool_runs,
            "signals": ordered_signals,
            "config_baseline": config_summary,
            "service_expectations": expectation_summary,
            "warnings": list(dict.fromkeys(warnings)),
        }

    def _configuration_signal(
        self,
    ) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
        baseline_service = ConfigBaselineService(self.session, self.registry)
        baseline = baseline_service.latest(scope=LIVE_SCOPE)
        if baseline is None:
            return (
                {
                    "key": "config_drift",
                    "title": "关键配置漂移",
                    "status": "unknown",
                    "metric": "未建立基线",
                    "detail": "当前没有可比较的关键配置基线。",
                    "evidence_refs": [],
                },
                None,
                None,
            )

        started = time.perf_counter()
        try:
            check = baseline_service.compare(baseline.id, scope=LIVE_SCOPE)
        except Exception as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            warning = _compact_error(exc)
            return (
                {
                    "key": "config_drift",
                    "title": "关键配置漂移",
                    "status": "unknown",
                    "metric": "采集失败",
                    "detail": "配置基线本轮未得到完整比较结果。",
                    "evidence_refs": [f"config_baseline:{baseline.id}"],
                },
                {
                    "tool_name": "config_integrity_scan",
                    "status": "error",
                    "duration_ms": duration_ms,
                    "observations": [],
                    "evidence_refs": [f"config_baseline:{baseline.id}"],
                    "warnings": [warning],
                },
                {"baseline_id": baseline.id, "status": "error"},
            )

        duration_ms = int((time.perf_counter() - started) * 1000)
        signal = _config_check_signal(baseline.id, check)
        tool_run = {
            "tool_name": "config_integrity_scan",
            "status": "partial" if check.status == "incomplete" else "ok",
            "duration_ms": duration_ms,
            "observations": [
                {
                    "baseline_id": baseline.id,
                    "check_id": check.id,
                    "status": check.status,
                    "summary": dict(check.summary_json),
                }
            ],
            "evidence_refs": list(signal["evidence_refs"]),
            "warnings": list(check.warnings_json)[:10],
        }
        return signal, tool_run, {
            "baseline_id": baseline.id,
            "check_id": check.id,
            "status": check.status,
            "summary": dict(check.summary_json),
        }

    def _service_expectation_signal(
        self,
        report: dict[str, Any],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
        snapshot = report.get("snapshot") if isinstance(report.get("snapshot"), dict) else {}
        host_key = str(snapshot.get("hostname") or "").strip()
        if not host_key:
            return (
                _unknown_signal(
                    "service_expectation",
                    "服务运行偏离",
                    "本轮未获得主机标识，无法核对服务期望状态。",
                ),
                [],
                {"overall_status": "UNKNOWN", "items": []},
            )

        records = ServiceExpectationService(self.session).list_current(host_key=host_key)
        if not records:
            return (
                _unknown_signal(
                    "service_expectation",
                    "服务运行偏离",
                    "当前主机尚未登记需要持续核对的服务期望。",
                ),
                [],
                {"host_key": host_key, "overall_status": "UNKNOWN", "items": []},
            )

        tool_runs: list[dict[str, Any]] = []

        def observe(payload: ServiceStatusInput) -> ToolResult:
            tool_run = self._call_tool(
                "service_status",
                payload.model_dump(mode="json", exclude_none=True),
            )
            tool_runs.append(tool_run)
            return ToolResult(
                status=tool_run["status"],
                observations=tool_run["observations"],
                evidence_refs=tool_run["evidence_refs"],
                warnings=tool_run["warnings"],
            )

        items, summary = reconcile_service_expectations(records, observer=observe)
        network_run = next(
            (
                item
                for item in (report.get("tool_runs") or [])
                if isinstance(item, dict)
                and item.get("tool_name") == "network_listeners"
            ),
            None,
        )
        network_result = ToolResult(
            status=str(network_run.get("status") or "error")
            if isinstance(network_run, dict)
            else "unavailable",
            observations=list(network_run.get("observations") or [])
            if isinstance(network_run, dict)
            else [],
            evidence_refs=list(network_run.get("evidence_refs") or [])
            if isinstance(network_run, dict)
            else [],
            warnings=list(network_run.get("warnings") or [])
            if isinstance(network_run, dict)
            else ["本轮未取得网络监听快照。"],
        )
        exposure = reconcile_listener_expectations(records, network_result)
        for item in items:
            item["network_exposure"] = exposure["by_service"].get(
                item["expectation"].id,
                {
                    "status": "NOT_DECLARED",
                    "reason": "未登记网络监听要求。",
                    "checks": [],
                },
            )
        if exposure["summary"]["drift_count"]:
            summary["overall_status"] = "DRIFT"
        elif (
            exposure["summary"]["unknown_count"]
            and summary["overall_status"] == "IN_SYNC"
        ):
            summary["overall_status"] = "UNKNOWN"
        summary.update(
            {
                "listener_expectation_count": exposure["summary"][
                    "listener_expectation_count"
                ],
                "network_drift_count": exposure["summary"]["drift_count"],
                "network_unknown_count": exposure["summary"]["unknown_count"],
                "unmanaged_listener_count": exposure["summary"][
                    "unmanaged_listener_count"
                ],
            }
        )
        return (
            _service_expectation_signal(items, summary),
            tool_runs,
            _service_expectation_summary(host_key, items, summary),
        )

    def _call_tool(self, tool_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            result = self.registry.call(tool_name, payload)
        except Exception as exc:
            return {
                "tool_name": tool_name,
                "status": "error",
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "observations": [],
                "evidence_refs": [],
                "warnings": [_compact_error(exc)],
            }
        payload_json = result.model_dump(mode="json") if isinstance(result, ToolResult) else {}
        return {
            "tool_name": tool_name,
            "status": payload_json.get("status", "error"),
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "observations": payload_json.get("observations", []),
            "evidence_refs": payload_json.get("evidence_refs", []),
            "warnings": payload_json.get("warnings", []),
        }


def _inode_signal(raw_disks: Any) -> dict[str, Any]:
    disks = raw_disks if isinstance(raw_disks, list) else []
    rows = [
        item
        for item in disks
        if isinstance(item, dict) and isinstance(item.get("inode_used_percent"), (int, float))
    ]
    if not rows:
        return {
            "key": "inode_pressure",
            "title": "inode 压力",
            "status": "unknown",
            "metric": "未采样",
            "detail": "本轮未得到文件系统 inode 使用率。",
            "evidence_refs": [],
        }
    highest = max(rows, key=lambda item: float(item["inode_used_percent"]))
    percent = float(highest["inode_used_percent"])
    status = "critical" if percent >= 90 else "warn" if percent >= 80 else "ok"
    path = str(highest.get("path") or "-")
    return {
        "key": "inode_pressure",
        "title": "inode 压力",
        "status": status,
        "metric": f"{percent:.1f}%",
        "detail": f"文件系统 {path} inode 使用率为 {percent:.1f}%。",
        "evidence_refs": ["disk_usage", f"statvfs:{path}"],
    }


def _memory_pressure_signal(current: Any, raw_snapshot: Any) -> dict[str, Any]:
    signal = dict(current) if isinstance(current, dict) else {
        "key": "memory_pressure",
        "title": "内存压力",
        "status": "unknown",
        "metric": "未采样",
        "detail": "本轮未获得内存容量证据。",
        "evidence_refs": [],
    }
    snapshot = raw_snapshot if isinstance(raw_snapshot, dict) else {}
    pressure = snapshot.get("pressure") if isinstance(snapshot.get("pressure"), dict) else {}
    memory = pressure.get("memory") if isinstance(pressure.get("memory"), dict) else {}
    some = memory.get("some") if isinstance(memory.get("some"), dict) else {}
    full = memory.get("full") if isinstance(memory.get("full"), dict) else {}
    some_avg10 = _number(some.get("avg10"))
    full_avg10 = _number(full.get("avg10"))
    psi_status = "ok"
    if full_avg10 is not None and full_avg10 >= 2.0:
        psi_status = "critical"
    elif some_avg10 is not None and some_avg10 >= 10.0:
        psi_status = "warn"
    if SIGNAL_ORDER.get(psi_status, 0) > SIGNAL_ORDER.get(str(signal.get("status")), 0):
        signal["status"] = psi_status
    if some_avg10 is not None or full_avg10 is not None:
        psi_text = (
            f"PSI some avg10={some_avg10 if some_avg10 is not None else '-'}，"
            f"full avg10={full_avg10 if full_avg10 is not None else '-'}。"
        )
        signal["detail"] = f"{str(signal.get('detail') or '').rstrip('。')}；{psi_text}"
        refs = signal.get("evidence_refs") if isinstance(signal.get("evidence_refs"), list) else []
        signal["evidence_refs"] = list(dict.fromkeys([*refs, "/proc/pressure/memory"]))
    return signal


def _failed_service_signal(tool_run: dict[str, Any]) -> dict[str, Any]:
    if tool_run.get("status") in HARD_TOOL_FAILURES:
        return _unknown_signal("failed_service", "失败服务", "服务状态采集不可用。")
    rows = tool_run.get("observations") if isinstance(tool_run.get("observations"), list) else []
    units = [
        str(item.get("unit")).strip()
        for item in rows
        if isinstance(item, dict)
        and isinstance(item.get("unit"), str)
        and str(item.get("unit")).strip().endswith(".service")
    ]
    if rows and not units:
        zero_summary = any(
            isinstance(item, dict)
            and item.get("scope") == "failed_services"
            and item.get("failed_count") == 0
            for item in rows
        )
        if not zero_summary:
            return _unknown_signal(
                "failed_service",
                "失败服务",
                "systemd 返回了失败服务摘要，但缺少可核验的单元标识。",
            )
    return {
        "key": "failed_service",
        "title": "失败服务",
        "status": "critical" if units else "ok",
        "metric": f"{len(units)} 个失败服务",
        "detail": (
            "、".join(units[:3]) + " 处于失败状态。"
            if units
            else "systemd 未报告失败服务。"
        ),
        "evidence_refs": list(tool_run.get("evidence_refs") or []),
    }


def _time_sync_signal(tool_run: dict[str, Any]) -> dict[str, Any]:
    if tool_run.get("status") in HARD_TOOL_FAILURES:
        return _unknown_signal("time_sync", "时间同步", "时间同步状态采集不可用。")
    rows = tool_run.get("observations") if isinstance(tool_run.get("observations"), list) else []
    observation = rows[0] if rows and isinstance(rows[0], dict) else {}
    synchronized = observation.get("ntp_synchronized")
    if synchronized is None:
        return _unknown_signal("time_sync", "时间同步", "未获得明确的 NTP 同步状态。")
    return {
        "key": "time_sync",
        "title": "时间同步",
        "status": "ok" if synchronized is True else "critical",
        "metric": "已同步" if synchronized is True else "未同步",
        "detail": (
            f"系统时间已通过 NTP 同步，时区 {observation.get('timezone') or '-'}。"
            if synchronized is True
            else "系统报告 NTP 未同步，审计时间线可能失真。"
        ),
        "evidence_refs": list(tool_run.get("evidence_refs") or []),
    }


def _config_check_signal(baseline_id: int, check: Any) -> dict[str, Any]:
    refs = [f"config_baseline:{baseline_id}", f"config_baseline_check:{check.id}"]
    if check.status == "incomplete":
        return {
            "key": "config_drift",
            "title": "关键配置漂移",
            "status": "unknown",
            "metric": "比较不完整",
            "detail": "关键配置本轮存在不可读取路径，不能形成完整结论。",
            "evidence_refs": refs,
        }
    changes = check.changes_json if isinstance(check.changes_json, list) else []
    change_types = {
        str(change_type)
        for change in changes
        if isinstance(change, dict)
        for change_type in (change.get("change_types") or [])
    }
    critical = bool(change_types & {"content_changed", "permission_changed", "missing", "added"})
    metadata_only = bool(changes) and change_types == {"metadata_changed"}
    return {
        "key": "config_drift",
        "title": "关键配置漂移",
        "status": "critical" if critical else "warn" if changes else "ok",
        "metric": (
            f"{len(changes)} 项元数据变化"
            if metadata_only
            else f"{len(changes)} 项变化"
        ),
        "detail": (
            f"{len(changes)} 个路径仅时间戳、解析路径或文件类型元数据发生变化，内容哈希与权限未变。"
            if metadata_only
            else
            f"关键配置基线发现 {len(changes)} 项变化。"
            if changes
            else "关键配置与已确认基线一致。"
        ),
        "evidence_refs": refs,
    }


def _service_expectation_signal(
    items: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, Any]:
    drifted = [item for item in items if item["compliance"] == "DRIFT"]
    network_drifted = [
        item
        for item in items
        if (item.get("network_exposure") or {}).get("status") == "DRIFT"
    ]
    unknown = [item for item in items if item["compliance"] == "UNKNOWN"]
    network_unknown = [
        item
        for item in items
        if (item.get("network_exposure") or {}).get("status") == "UNKNOWN"
    ]
    if drifted or network_drifted:
        affected = list(
            {
                item["expectation"].id: item
                for item in [*drifted, *network_drifted]
            }.values()
        )
        critical = any(
            item["expectation"].criticality in {"CRITICAL", "HIGH"}
            for item in affected
        )
        samples = "；".join(
            _service_expectation_detail(item) for item in affected[:3]
        )
        return {
            "key": "service_expectation",
            "title": "服务与开放范围",
            "status": "critical" if critical else "warn",
            "metric": (
                f"{len(drifted)} 项状态 / {len(network_drifted)} 项网络偏离"
            ),
            "detail": samples,
            "evidence_refs": _service_expectation_evidence(items),
        }
    if unknown or network_unknown:
        affected = list(
            {
                item["expectation"].id: item
                for item in [*unknown, *network_unknown]
            }.values()
        )
        units = "、".join(
            item["expectation"].unit_name for item in affected[:3]
        )
        return {
            "key": "service_expectation",
            "title": "服务与开放范围",
            "status": "unknown",
            "metric": f"{len(affected)} 项待核验",
            "detail": f"{units} 的运行状态或监听归属证据不完整。",
            "evidence_refs": _service_expectation_evidence(items),
        }
    return {
        "key": "service_expectation",
        "title": "服务与开放范围",
        "status": "ok",
        "metric": f"{summary['in_sync_count']}/{summary['total_count']} 项一致",
        "detail": "已登记服务的运行状态和网络开放范围均符合当前生效值。",
        "evidence_refs": _service_expectation_evidence(items),
    }


def _service_expectation_detail(item: dict[str, Any]) -> str:
    expectation: ServiceExpectation = item["expectation"]
    runtime = item.get("runtime") if isinstance(item.get("runtime"), dict) else {}
    actual = str(runtime.get("active_state") or "unknown")
    parts: list[str] = []
    if item.get("compliance") == "DRIFT":
        parts.append(
            f"当前 {actual}，期望 {expectation.expected_active_state}"
        )
    network = (
        item.get("network_exposure")
        if isinstance(item.get("network_exposure"), dict)
        else {}
    )
    if network.get("status") == "DRIFT":
        parts.append(str(network.get("reason") or "网络开放范围偏离"))
    detail = "；".join(parts) or "证据待核验"
    return (
        f"{expectation.unit_name}：{detail}，责任方 "
        f"{expectation.service_owner}"
    )


def _service_expectation_evidence(items: list[dict[str, Any]]) -> list[str]:
    refs: list[str] = []
    for item in items:
        expectation: ServiceExpectation = item["expectation"]
        refs.append(f"service_expectation:{expectation.id}:v{expectation.version}")
        refs.extend(
            str(ref)
            for ref in item.get("evidence_refs", [])
            if isinstance(ref, str) and ref.strip()
        )
        network = (
            item.get("network_exposure")
            if isinstance(item.get("network_exposure"), dict)
            else {}
        )
        for check in network.get("checks") or []:
            if isinstance(check, dict):
                for listener in check.get("observed") or []:
                    if isinstance(listener, dict) and listener.get("local_address"):
                        refs.append(
                            f"listener:{listener.get('protocol')}:{listener['local_address']}"
                        )
    return list(dict.fromkeys(refs))


def _service_expectation_summary(
    host_key: str,
    items: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "host_key": host_key,
        **summary,
        "items": [
            {
                "expectation_id": item["expectation"].id,
                "unit_name": item["expectation"].unit_name,
                "expected_active_state": item["expectation"].expected_active_state,
                "actual_active_state": (
                    item["runtime"].get("active_state")
                    if isinstance(item.get("runtime"), dict)
                    else None
                ),
                "service_owner": item["expectation"].service_owner,
                "criticality": item["expectation"].criticality,
                "compliance": item["compliance"],
                "network_exposure_status": (
                    item["network_exposure"].get("status")
                    if isinstance(item.get("network_exposure"), dict)
                    else "NOT_DECLARED"
                ),
            }
            for item in items
        ],
    }


def _mcp_health_signal(tool_runs: list[dict[str, Any]]) -> dict[str, Any]:
    hard = [item for item in tool_runs if item.get("status") in HARD_TOOL_FAILURES]
    partial = [item for item in tool_runs if item.get("status") == "partial"]
    status = "critical" if hard else "warn" if partial else "ok"
    healthy_count = len(tool_runs) - len(hard) - len(partial)
    return {
        "key": "mcp_health",
        "title": "感知链路",
        "status": status,
        "metric": f"{healthy_count}/{len(tool_runs)} 完整",
        "detail": (
            f"{len(hard)} 个探针不可用或失败。"
            if hard
            else f"{len(partial)} 个探针返回部分证据。"
            if partial
            else "本轮全部巡检探针返回完整结构化证据。"
        ),
        "evidence_refs": [str(item.get("tool_name")) for item in tool_runs],
    }


def _collection_status(tool_runs: list[dict[str, Any]]) -> str:
    if any(item.get("status") in HARD_TOOL_FAILURES for item in tool_runs):
        return "error"
    if any(item.get("status") == "partial" for item in tool_runs):
        return "partial"
    return "ok"


def _operational_status(signals: list[dict[str, Any]]) -> str:
    statuses = {str(item.get("status")) for item in signals}
    if "critical" in statuses:
        return "error"
    if "warn" in statuses:
        return "warn"
    return "ok"


def _unknown_signal(key: str, title: str, detail: str) -> dict[str, Any]:
    return {
        "key": key,
        "title": title,
        "status": "unknown",
        "metric": "不可用",
        "detail": detail,
        "evidence_refs": [],
    }


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _compact_error(exc: Exception) -> str:
    return " ".join(str(exc).split())[:500]
