from __future__ import annotations

from datetime import datetime, timedelta, timezone
from statistics import median
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolResult
from backend.app.models.entities import SystemSnapshot
from backend.app.perception.network_scope import classify_listener_scope
from backend.app.posture.trends import MetricSample, analyze_metric_trend, is_robust_positive_outlier


LIVE_POSTURE_TOOLS: tuple[dict[str, Any], ...] = (
    {"name": "system_snapshot", "payload": {}},
    {"name": "disk_usage", "payload": {"paths": ["/", "/tmp", "/var"]}},
    {"name": "network_listeners", "payload": {"limit": 160}},
    {"name": "process_list", "payload": {"limit": 12}},
)

BASELINE_MIN_SAMPLE_COUNT = 12
BASELINE_HISTORY_LIMIT = 96
BASELINE_HISTORY_WINDOW_HOURS = 24
BASELINE_PERSIST_INTERVAL_SECONDS = 60
BASELINE_METRICS = {
    "memory_used_percent": "内存使用率",
    "root_disk_used_percent": "根分区使用率",
    "listener_count": "监听端口数量",
    "top_cpu_percent": "最高进程 CPU",
}


class LivePostureService:
    def __init__(
        self,
        registry: ToolRegistry,
        session: Session | None = None,
        history_limit: int = BASELINE_HISTORY_LIMIT,
        minimum_sample_count: int = BASELINE_MIN_SAMPLE_COUNT,
        persist_interval_seconds: int = BASELINE_PERSIST_INTERVAL_SECONDS,
    ) -> None:
        self.registry = registry
        self.session = session
        self.history_limit = history_limit
        self.minimum_sample_count = minimum_sample_count
        self.persist_interval_seconds = persist_interval_seconds

    def read(self) -> dict[str, Any]:
        observed_at = datetime.now(timezone.utc)
        tool_runs = [self._call_tool(item["name"], item["payload"]) for item in LIVE_POSTURE_TOOLS]
        tool_map = {item["tool_name"]: item for item in tool_runs}
        snapshot = _first_observation(tool_map.get("system_snapshot"))
        disks = _observations(tool_map.get("disk_usage"))
        network_listeners = _observations(tool_map.get("network_listeners"))
        processes = _observations(tool_map.get("process_list"))
        metrics = _posture_metrics(snapshot, disks, network_listeners, processes)
        baseline = self._build_baseline(metrics, observed_at=observed_at)
        signals = _build_signals(snapshot, disks, network_listeners, processes, tool_runs, baseline)
        self._persist_metrics(metrics, tool_runs, observed_at=observed_at)
        return {
            "collected_at": observed_at.isoformat(),
            "status": _overall_status(tool_runs, signals),
            "snapshot": snapshot,
            "disks": disks,
            "network_listeners": network_listeners,
            "processes": processes,
            "tool_runs": tool_runs,
            "baseline": baseline,
            "signals": signals,
            "next_actions": _next_actions(signals, baseline),
            "warnings": [warning for item in tool_runs for warning in item.get("warnings", [])],
        }

    def _build_baseline(
        self,
        current_metrics: dict[str, float | None],
        *,
        observed_at: datetime,
    ) -> dict[str, Any]:
        history = self._history_metrics(observed_at=observed_at)
        sample_count = len(history)
        if sample_count < self.minimum_sample_count:
            return {
                "status": "collecting",
                "sample_count": sample_count,
                "minimum_sample_count": self.minimum_sample_count,
                "history_window_hours": BASELINE_HISTORY_WINDOW_HOURS,
                "anomaly_score": 0,
                "metrics": {},
                "anomalies": [],
                "capacity_forecast": None,
                "method": "median_mad_theil_sen.v1",
            }

        metric_rows: dict[str, dict[str, Any]] = {}
        anomalies: list[dict[str, Any]] = []
        anomaly_score = 0
        for key, title in BASELINE_METRICS.items():
            current = current_metrics.get(key)
            samples = [item.metrics[key] for item in history if isinstance(item.metrics.get(key), (int, float))]
            if current is None or not samples:
                continue
            baseline_value = float(median(samples))
            delta = round(current - baseline_value, 2)
            status, score = _baseline_deviation(key, delta)
            trend = analyze_metric_trend(key, current, observed_at, history)
            if status == "ok" and is_robust_positive_outlier(key, delta, trend["robust_score"]):
                status, score = "warn", 20
            row = {
                "title": title,
                "current": round(current, 2),
                "baseline": round(baseline_value, 2),
                "delta": delta,
                "status": status,
                **trend,
            }
            metric_rows[key] = row
            if status != "ok":
                anomaly_score += score
                anomalies.append({**row, "key": key, "detail": _baseline_detail(key, row)})

        anomaly_score = min(anomaly_score, 100)
        return {
            "status": "ready",
            "sample_count": sample_count,
            "minimum_sample_count": self.minimum_sample_count,
            "history_window_hours": BASELINE_HISTORY_WINDOW_HOURS,
            "anomaly_score": anomaly_score,
            "metrics": metric_rows,
            "anomalies": anomalies,
            "capacity_forecast": metric_rows.get("root_disk_used_percent", {}).get("forecast"),
            "method": "median_mad_theil_sen.v1",
        }

    def _history_metrics(self, *, observed_at: datetime) -> list[MetricSample]:
        if self.session is None:
            return []
        window_start = observed_at - timedelta(hours=BASELINE_HISTORY_WINDOW_HOURS)
        rows = self.session.execute(
            select(SystemSnapshot)
            .where(
                SystemSnapshot.task_id.is_(None),
                SystemSnapshot.created_at >= window_start,
            )
            .order_by(SystemSnapshot.created_at.desc(), SystemSnapshot.id.desc())
            .limit(self.history_limit * 2)
        ).scalars()
        history: list[MetricSample] = []
        for row in rows:
            payload = row.payload_json if isinstance(row.payload_json, dict) else {}
            if payload.get("source") != "live_posture":
                continue
            metrics = payload.get("metrics")
            if not isinstance(metrics, dict):
                continue
            normalized = {
                key: float(value)
                for key, value in metrics.items()
                if key in BASELINE_METRICS and isinstance(value, (int, float))
            }
            if normalized:
                history.append(MetricSample(observed_at=row.created_at, metrics=normalized))
            if len(history) >= self.history_limit:
                break
        return list(reversed(history))

    def _persist_metrics(
        self,
        metrics: dict[str, float | None],
        tool_runs: list[dict[str, Any]],
        *,
        observed_at: datetime,
    ) -> None:
        if self.session is None or any(item.get("status") != "ok" for item in tool_runs):
            return
        latest = self.session.execute(
            select(SystemSnapshot)
            .where(SystemSnapshot.task_id.is_(None))
            .order_by(SystemSnapshot.created_at.desc(), SystemSnapshot.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        if latest is not None and _elapsed_seconds(latest.created_at) < self.persist_interval_seconds:
            return
        self.session.add(
            SystemSnapshot(
                task_id=None,
                payload_json={
                    "source": "live_posture",
                    "metrics": {key: value for key, value in metrics.items() if value is not None},
                },
                created_at=observed_at,
            )
        )
        self.session.flush()

    def _call_tool(self, tool_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            result = self.registry.call(tool_name, payload)
        except Exception as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            return {
                "tool_name": tool_name,
                "status": "error",
                "duration_ms": duration_ms,
                "observations": [],
                "evidence_refs": [],
                "warnings": [str(exc)],
            }

        duration_ms = int((time.perf_counter() - started) * 1000)
        payload_json = result.model_dump(mode="json") if isinstance(result, ToolResult) else {}
        return {
            "tool_name": tool_name,
            "status": payload_json.get("status", "ok"),
            "duration_ms": duration_ms,
            "observations": payload_json.get("observations", []),
            "evidence_refs": payload_json.get("evidence_refs", []),
            "warnings": payload_json.get("warnings", []),
        }


def _first_observation(tool_run: dict[str, Any] | None) -> dict[str, Any]:
    observations = _observations(tool_run)
    return observations[0] if observations else {}


def _observations(tool_run: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not tool_run:
        return []
    observations = tool_run.get("observations")
    return observations if isinstance(observations, list) else []


def _build_signals(
    snapshot: dict[str, Any],
    disks: list[dict[str, Any]],
    network_listeners: list[dict[str, Any]],
    processes: list[dict[str, Any]],
    tool_runs: list[dict[str, Any]],
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    root_disk = next((item for item in disks if item.get("path") == "/"), disks[0] if disks else {})
    memory = snapshot.get("memory") if isinstance(snapshot.get("memory"), dict) else {}
    memory_used = _float_value(memory.get("used_percent") if isinstance(memory, dict) else None)
    disk_used = _float_value(root_disk.get("used_percent"))
    network_scopes = [
        (
            item,
            str(item.get("exposure_scope") or classify_listener_scope(str(item.get("local_address", "")))),
        )
        for item in network_listeners
    ]
    exposed_listeners = [
        item for item, scope in network_scopes if scope in {"wildcard", "public", "unknown"}
    ]
    unattributed_listeners = [
        item
        for item, _ in network_scopes
        if item.get("pid") is None and not str(item.get("process") or "").strip()
    ]
    zombies = [item for item in processes if item.get("is_zombie") is True]
    top_process = max(processes, key=lambda item: _float_value(item.get("cpu_percent")) or 0.0) if processes else {}
    top_cpu = _float_value(top_process.get("cpu_percent"))
    failed_tools = [item for item in tool_runs if item.get("status") != "ok"]

    platform_ok = _platform_ok(snapshot)
    signals = [
        {
            "key": "platform",
            "title": "部署平台",
            "status": "ok" if platform_ok else "warn",
            "metric": _platform_metric(snapshot),
            "detail": "Linux 发行版与处理器架构已识别。" if platform_ok else "平台标识不完整，需先恢复系统信息采集。",
            "evidence_refs": ["system_snapshot"],
        },
        {
            "key": "disk_pressure",
            "title": "磁盘压力",
            "status": _threshold_status(disk_used, warn=80.0, critical=90.0),
            "metric": _percent_metric(disk_used),
            "detail": f"根分区 {root_disk.get('path', '/')} 使用率 {_percent_metric(disk_used)}。",
            "evidence_refs": ["disk_usage", str(root_disk.get("path", "/"))],
        },
        {
            "key": "memory_pressure",
            "title": "内存压力",
            "status": _threshold_status(memory_used, warn=80.0, critical=90.0),
            "metric": _percent_metric(memory_used),
            "detail": f"内存使用率 {_percent_metric(memory_used)}，结合进程采样判断是否存在持续压力。",
            "evidence_refs": ["system_snapshot", "/proc/meminfo"],
        },
        {
            "key": "network_exposure",
            "title": "端口暴露面",
            "status": "warn" if exposed_listeners or unattributed_listeners else "ok",
            "metric": _network_metric(exposed_listeners, unattributed_listeners),
            "detail": _network_detail(exposed_listeners, unattributed_listeners),
            "evidence_refs": ["network_listeners"],
        },
        {
            "key": "process_pressure",
            "title": "进程压力",
            "status": "critical" if zombies else "warn" if (top_cpu is not None and top_cpu >= 80.0) else "ok",
            "metric": _process_metric(top_process, zombies, top_cpu),
            "detail": _process_detail(top_process, zombies, top_cpu),
            "evidence_refs": ["process_list"],
        },
        {
            "key": "mcp_health",
            "title": "感知链路",
            "status": "critical" if failed_tools else "ok",
            "metric": f"{len(tool_runs) - len(failed_tools)}/{len(tool_runs)} 正常" if tool_runs else "未采样",
            "detail": "所有实时感知工具返回正常。" if not failed_tools else f"{len(failed_tools)} 个感知工具异常，需先恢复证据采集能力。",
            "evidence_refs": [item["tool_name"] for item in tool_runs],
        },
        _baseline_signal(baseline),
        _capacity_forecast_signal(baseline),
    ]
    return signals


def _next_actions(
    signals: list[dict[str, Any]],
    baseline: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    action_map = {
        "disk_pressure": ("分析磁盘压力", "帮我分析一下磁盘空间，看看能不能安全清理系统垃圾"),
        "memory_pressure": ("分析内存压力", "分析当前内存压力和高占用进程，给出安全处置建议"),
        "network_exposure": ("检查端口暴露", "检查当前主机的网络监听端口和暴露风险"),
        "process_pressure": ("排查进程压力", "检查当前高负载或僵尸进程，给出安全处置建议"),
        "mcp_health": ("检查感知链路", "检查 MCP 感知工具状态，说明异常原因和修复建议"),
        "platform": ("核验运行环境", "检查当前 Linux 主机的发行版、架构与感知工具链"),
        "capacity_forecast": ("排查容量趋势", "分析根分区增长趋势，定位持续增长来源并给出安全处置建议"),
    }
    actions: list[tuple[int, int, dict[str, str]]] = []
    for signal in signals:
        if signal["status"] == "ok":
            continue
        if signal["key"] == "baseline_regression":
            baseline_action = _baseline_next_action(baseline or {})
            if baseline_action is None:
                continue
            label, prompt = baseline_action
        elif signal["key"] in action_map:
            label, prompt = action_map[signal["key"]]
        else:
            continue
        severity = 0 if signal["status"] == "critical" else 1
        baseline_priority = 0 if signal["key"] == "baseline_regression" else 1
        actions.append(
            (
                severity,
                baseline_priority,
                {
                    "key": str(signal["key"]),
                    "label": label,
                    "prompt": prompt,
                    "source_signal": str(signal["title"]),
                },
            )
        )
    return [item[2] for item in sorted(actions, key=lambda item: (item[0], item[1]))[:3]]


def _baseline_next_action(baseline: dict[str, Any]) -> tuple[str, str] | None:
    anomalies = baseline.get("anomalies")
    if not isinstance(anomalies, list) or not anomalies:
        return None
    ordered = sorted(
        (item for item in anomalies if isinstance(item, dict)),
        key=lambda item: 0 if item.get("status") == "critical" else 1,
    )
    if not ordered:
        return None
    anomaly = ordered[0]
    key = str(anomaly.get("key") or "")
    detail = str(anomaly.get("detail") or "").strip()
    actions = {
        "memory_used_percent": (
            "排查内存动态基线偏离",
            "排查当前内存压力和高占用进程",
        ),
        "root_disk_used_percent": (
            "分析磁盘动态基线偏离",
            "分析当前根分区容量和大文件占用",
        ),
        "listener_count": (
            "核查端口动态基线偏离",
            "检查当前监听端口、进程归属和暴露风险",
        ),
        "top_cpu_percent": (
            "排查 CPU 动态基线偏离",
            "检查当前高 CPU 进程、运行状态和服务归属",
        ),
    }
    action = actions.get(key)
    if action is None:
        return None
    label, objective = action
    prompt = f"{objective}。系统态势检测到动态基线偏离：{detail}请重新采集实时证据，定位异常来源并给出安全排查建议。"
    return label, prompt


def _overall_status(tool_runs: list[dict[str, Any]], signals: list[dict[str, Any]] | None = None) -> str:
    if any(item["status"] == "error" for item in tool_runs):
        return "error"
    signal_statuses = [item.get("status") for item in (signals or [])]
    if "critical" in signal_statuses:
        return "error"
    if "warn" in signal_statuses:
        return "warn"
    if any(item["status"] not in {"ok", "unavailable"} for item in tool_runs):
        return "warn"
    if any(item["status"] == "unavailable" for item in tool_runs):
        return "warn"
    return "ok"


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _float_value(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def _threshold_status(value: float | None, *, warn: float, critical: float) -> str:
    if value is None:
        return "warn"
    if value >= critical:
        return "critical"
    if value >= warn:
        return "warn"
    return "ok"


def _percent_metric(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f}%"


def _platform_ok(snapshot: dict[str, Any]) -> bool:
    os_release = snapshot.get("os_release") if isinstance(snapshot.get("os_release"), dict) else {}
    machine = str(snapshot.get("machine") or "").strip().lower()
    return bool(os_release.get("id") or os_release.get("name") or os_release.get("pretty_name")) and machine not in {"", "unknown"}


def _platform_metric(snapshot: dict[str, Any]) -> str:
    os_release = snapshot.get("os_release") if isinstance(snapshot.get("os_release"), dict) else {}
    os_name = os_release.get("name") or os_release.get("pretty_name") or "OS"
    machine = snapshot.get("machine") or "-"
    return f"{os_name} / {machine}"


def _network_metric(
    exposed_listeners: list[dict[str, Any]],
    unattributed_listeners: list[dict[str, Any]],
) -> str:
    wildcard_count = sum(
        str(item.get("exposure_scope") or classify_listener_scope(str(item.get("local_address", ""))))
        == "wildcard"
        for item in exposed_listeners
    )
    if wildcard_count:
        return f"{wildcard_count} 全地址 / {len(unattributed_listeners)} 未归属"
    return f"{len(exposed_listeners)} 高风险 / {len(unattributed_listeners)} 未归属"


def _network_detail(
    exposed_listeners: list[dict[str, Any]],
    unattributed_listeners: list[dict[str, Any]],
) -> str:
    if exposed_listeners:
        sample = "、".join(str(item.get("local_address", "-")) for item in exposed_listeners[:3])
        suffix = " 等" if len(exposed_listeners) > 3 else ""
        return f"发现 {len(exposed_listeners)} 个全地址、公网或范围未知监听：{sample}{suffix}。"
    if unattributed_listeners:
        return f"监听地址位于回环、内网或链路本地，但有 {len(unattributed_listeners)} 个端口缺少进程归属。"
    return "监听地址位于回环、内网或链路本地，且均已关联进程。"


def _process_metric(top_process: dict[str, Any], zombies: list[dict[str, Any]], top_cpu: float | None) -> str:
    if zombies:
        return f"{len(zombies)} 个僵尸"
    if top_cpu is None:
        return "未采样"
    return f"{top_cpu:.1f}% CPU"


def _process_detail(top_process: dict[str, Any], zombies: list[dict[str, Any]], top_cpu: float | None) -> str:
    if zombies:
        sample = "、".join(str(item.get("pid", "-")) for item in zombies[:3])
        return f"发现僵尸进程 PID {sample}，需确认父进程回收状态。"
    if top_cpu is None:
        return "尚未获得进程采样。"
    command = top_process.get("command") or f"PID {top_process.get('pid', '-')}"
    return f"当前最高 CPU 进程为 {command}，占用 {top_cpu:.1f}%。"


def _posture_metrics(
    snapshot: dict[str, Any],
    disks: list[dict[str, Any]],
    network_listeners: list[dict[str, Any]],
    processes: list[dict[str, Any]],
) -> dict[str, float | None]:
    root_disk = next((item for item in disks if item.get("path") == "/"), disks[0] if disks else {})
    memory = snapshot.get("memory") if isinstance(snapshot.get("memory"), dict) else {}
    top_cpu = max((_float_value(item.get("cpu_percent")) or 0.0 for item in processes), default=None)
    return {
        "memory_used_percent": _float_value(memory.get("used_percent")),
        "root_disk_used_percent": _float_value(root_disk.get("used_percent")),
        "listener_count": float(len(network_listeners)),
        "top_cpu_percent": top_cpu,
    }


def _baseline_deviation(key: str, delta: float) -> tuple[str, int]:
    thresholds = {
        "memory_used_percent": (15.0, 30.0),
        "root_disk_used_percent": (15.0, 30.0),
        "listener_count": (3.0, 10.0),
        "top_cpu_percent": (30.0, 60.0),
    }
    warn, critical = thresholds[key]
    if delta >= critical:
        return "critical", 45
    if delta >= warn:
        return "warn", 20
    return "ok", 0


def _baseline_detail(key: str, row: dict[str, Any]) -> str:
    unit = "%" if key in {"memory_used_percent", "root_disk_used_percent", "top_cpu_percent"} else " 个"
    return (
        f"当前 {row['current']}{unit}，历史中位数 {row['baseline']}{unit}，"
        f"高出 {row['delta']}{unit}。"
    )


def _baseline_signal(baseline: dict[str, Any]) -> dict[str, Any]:
    if baseline.get("status") != "ready":
        count = int(baseline.get("sample_count") or 0)
        minimum = int(baseline.get("minimum_sample_count") or BASELINE_MIN_SAMPLE_COUNT)
        return {
            "key": "baseline_regression",
            "title": "动态基线",
            "status": "ok",
            "metric": f"{count}/{minimum} 样本",
            "detail": "历史样本收集中，达到最小样本数后开始计算偏离评分。",
            "evidence_refs": ["system_snapshots"],
        }
    anomalies = baseline.get("anomalies") if isinstance(baseline.get("anomalies"), list) else []
    status = "critical" if any(item.get("status") == "critical" for item in anomalies) else "warn" if anomalies else "ok"
    detail = "近期历史样本未发现结构性上升。" if not anomalies else "；".join(
        str(item.get("detail")) for item in anomalies[:2]
    )
    return {
        "key": "baseline_regression",
        "title": "动态基线偏离",
        "status": status,
        "metric": f"{len(anomalies)} 项偏离",
        "detail": detail,
        "evidence_refs": ["system_snapshots"],
    }


def _capacity_forecast_signal(baseline: dict[str, Any]) -> dict[str, Any]:
    if baseline.get("status") != "ready":
        count = int(baseline.get("sample_count") or 0)
        minimum = int(baseline.get("minimum_sample_count") or BASELINE_MIN_SAMPLE_COUNT)
        return {
            "key": "capacity_forecast",
            "title": "容量趋势",
            "status": "ok",
            "metric": f"{count}/{minimum} 样本",
            "detail": "正在积累时序样本，达到稳健趋势门槛后预测根分区容量风险。",
            "evidence_refs": ["system_snapshots", "disk_usage:/"],
        }
    row = baseline.get("metrics", {}).get("root_disk_used_percent", {})
    forecast = baseline.get("capacity_forecast")
    slope = row.get("slope_per_hour") if isinstance(row, dict) else None
    if not isinstance(forecast, dict):
        slope_text = f"{float(slope):+.2f}%/小时" if isinstance(slope, (int, float)) else "样本不足"
        return {
            "key": "capacity_forecast",
            "title": "容量趋势",
            "status": "ok",
            "metric": "趋势稳定",
            "detail": f"根分区稳健斜率 {slope_text}，未达到容量预警条件。",
            "evidence_refs": ["system_snapshots", "disk_usage:/"],
        }
    hours = float(forecast.get("hours_to_threshold") or 0)
    threshold = float(forecast.get("threshold_percent") or 90)
    sample_count = int(forecast.get("sample_count") or 0)
    span_minutes = int(forecast.get("sample_span_minutes") or 0)
    return {
        "key": "capacity_forecast",
        "title": "容量耗尽趋势",
        "status": str(forecast.get("status") or "warn"),
        "metric": f"约 {hours:g} 小时至 {threshold:g}%",
        "detail": (
            f"近 {sample_count} 个真实样本（{span_minutes} 分钟）显示根分区"
            f"稳健斜率 {float(slope or 0):+.2f}%/小时，按当前趋势约 {hours:g} 小时触达 {threshold:g}%。"
        ),
        "evidence_refs": ["system_snapshots", "disk_usage:/"],
    }


def _elapsed_seconds(created_at: datetime) -> float:
    timestamp = created_at if created_at.tzinfo is not None else created_at.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - timestamp).total_seconds())
