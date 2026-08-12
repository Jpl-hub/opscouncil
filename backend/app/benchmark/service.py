from __future__ import annotations

from datetime import datetime, timezone
import time
import uuid
from typing import Any

from sqlalchemy.orm import Session

from backend.app.evaluations.store import EvaluationReportStore
from backend.app.mcp.registry import ToolRegistry


BENCHMARK_TOOLS = [
    {
        "tool_name": "system_snapshot",
        "label": "系统快照",
        "payload": {},
        "threshold_ms": 500,
    },
    {
        "tool_name": "disk_usage",
        "label": "磁盘用量",
        "payload": {"paths": ["/", "/tmp", "/var"]},
        "threshold_ms": 800,
    },
    {
        "tool_name": "network_listeners",
        "label": "网络监听",
        "payload": {"limit": 120},
        "threshold_ms": 1200,
    },
    {
        "tool_name": "config_integrity_scan",
        "label": "配置基线",
        "payload": {
            "paths": [
                "/etc/hosts",
                "/etc/resolv.conf",
                "/etc/fstab",
            ]
        },
        "threshold_ms": 1200,
    },
]


class BenchmarkService:
    def __init__(self, session: Session, registry: ToolRegistry) -> None:
        self.store = EvaluationReportStore(session, "TOOL_PERFORMANCE")
        self.registry = registry

    def run(self, rounds: int = 2) -> dict[str, Any]:
        round_count = min(max(rounds, 1), 5)
        started_at = _utc_iso()
        report_id = uuid.uuid4().hex
        environment: dict[str, Any] = {}
        metrics: list[dict[str, Any]] = []
        total_started = time.perf_counter()

        for tool in BENCHMARK_TOOLS:
            metric = self._run_tool(tool, round_count)
            metrics.append(metric)
            if tool["tool_name"] == "system_snapshot" and metric["samples"]:
                observations = metric["samples"][0].get("observations", [])
                if observations:
                    environment = _compact_environment(observations[0])

        completed_at = _utc_iso()
        report = {
            "id": report_id,
            "started_at": started_at,
            "completed_at": completed_at,
            "rounds": round_count,
            "total_duration_ms": round((time.perf_counter() - total_started) * 1000, 2),
            "environment": environment,
            "metrics": metrics,
            "summary": _summarize(metrics),
        }
        self.store.save(report)
        return report

    def read_latest(self) -> dict[str, Any] | None:
        return self.store.latest()

    def _run_tool(self, tool: dict[str, Any], rounds: int) -> dict[str, Any]:
        durations: list[float] = []
        samples: list[dict[str, Any]] = []
        error: str | None = None
        success_count = 0

        for _ in range(rounds):
            started = time.perf_counter()
            try:
                result = self.registry.call(tool["tool_name"], tool["payload"])
                duration_ms = round((time.perf_counter() - started) * 1000, 2)
                durations.append(duration_ms)
                result_payload = result.model_dump(mode="json")
                samples.append(_compact_sample(result_payload))
                if result.status == "ok":
                    success_count += 1
                elif error is None:
                    error = "; ".join(result.warnings) or f"tool status {result.status}"
            except Exception as exc:
                durations.append(round((time.perf_counter() - started) * 1000, 2))
                if error is None:
                    error = str(exc)

        avg_ms = round(sum(durations) / len(durations), 2) if durations else 0
        p50_ms = _percentile(durations, 0.50)
        p95_ms = _percentile(durations, 0.95)
        threshold_ms = int(tool["threshold_ms"])
        status = "ok"
        if success_count < rounds:
            status = "failed"
        elif avg_ms > threshold_ms:
            status = "warn"

        return {
            "tool_name": tool["tool_name"],
            "label": tool["label"],
            "rounds": rounds,
            "success_count": success_count,
            "success_rate": round((success_count / rounds) * 100, 2) if rounds else 0,
            "duration_ms_avg": avg_ms,
            "duration_ms_p50": p50_ms,
            "duration_ms_p95": p95_ms,
            "duration_ms_min": min(durations) if durations else 0,
            "duration_ms_max": max(durations) if durations else 0,
            "threshold_ms": threshold_ms,
            "status": status,
            "error": error,
            "samples": samples[:2],
        }

def _compact_sample(result: dict[str, Any]) -> dict[str, Any]:
    observations = result.get("observations", [])
    return {
        "status": result.get("status"),
        "observation_count": len(observations) if isinstance(observations, list) else 0,
        "observations": observations[:2] if isinstance(observations, list) else [],
        "warnings": result.get("warnings", [])[:3] if isinstance(result.get("warnings"), list) else [],
        "evidence_refs": result.get("evidence_refs", [])[:4] if isinstance(result.get("evidence_refs"), list) else [],
    }


def _compact_environment(snapshot: dict[str, Any]) -> dict[str, Any]:
    os_release = snapshot.get("os_release") if isinstance(snapshot.get("os_release"), dict) else {}
    return {
        "hostname": snapshot.get("hostname"),
        "machine": snapshot.get("machine"),
        "kernel": snapshot.get("kernel"),
        "os": os_release.get("pretty_name") or os_release.get("name"),
        "os_family": snapshot.get("os_family") or "linux",
        "is_loongarch": bool(snapshot.get("is_loongarch")),
    }


def _summarize(metrics: list[dict[str, Any]]) -> dict[str, Any]:
    failed_count = sum(1 for item in metrics if item["status"] == "failed")
    warn_count = sum(1 for item in metrics if item["status"] == "warn")
    ok_count = sum(1 for item in metrics if item["status"] == "ok")
    slowest = max(metrics, key=lambda item: item["duration_ms_avg"], default=None)
    worst_p95 = max(metrics, key=lambda item: item.get("duration_ms_p95", 0), default=None)
    overall_status = "failed" if failed_count else "warn" if warn_count else "ok"
    return {
        "tool_count": len(metrics),
        "ok_count": ok_count,
        "warn_count": warn_count,
        "failed_count": failed_count,
        "overall_status": overall_status,
        "slowest_tool": slowest["tool_name"] if slowest else None,
        "slowest_duration_ms": slowest["duration_ms_avg"] if slowest else 0,
        "worst_p95_tool": worst_p95["tool_name"] if worst_p95 else None,
        "worst_p95_ms": worst_p95.get("duration_ms_p95", 0) if worst_p95 else 0,
    }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 2)


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
