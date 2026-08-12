from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from backend.app.mcp.types import ToolResult
from backend.app.models.entities import ServiceExpectation
from backend.app.perception.tools import ServiceStatusInput


ServiceObserver = Callable[[ServiceStatusInput], ToolResult]


def reconcile_service_expectations(
    records: Iterable[ServiceExpectation],
    *,
    observer: ServiceObserver,
) -> tuple[list[dict[str, Any]], dict[str, int | str]]:
    items = [
        {
            "expectation": record,
            **reconcile_service_expectation(
                record,
                observer(ServiceStatusInput(unit=record.unit_name)),
            ),
        }
        for record in records
    ]
    counts = {
        status: sum(item["compliance"] == status for item in items)
        for status in ("IN_SYNC", "DRIFT", "UNKNOWN")
    }
    overall_status = (
        "DRIFT"
        if counts["DRIFT"]
        else "UNKNOWN"
        if counts["UNKNOWN"]
        else "IN_SYNC"
    )
    return items, {
        "total_count": len(items),
        "in_sync_count": counts["IN_SYNC"],
        "drift_count": counts["DRIFT"],
        "unknown_count": counts["UNKNOWN"],
        "overall_status": overall_status,
    }


def reconcile_service_expectation(
    record: ServiceExpectation,
    result: ToolResult,
) -> dict[str, Any]:
    observation = next(
        (
            item
            for item in result.observations
            if str(item.get("unit") or "") == record.unit_name
        ),
        None,
    )
    if observation is None:
        reason = _first_warning(result) or "systemd 未返回该服务单元的运行状态。"
        return {
            "runtime": None,
            "compliance": "UNKNOWN",
            "reason": reason,
            "evidence_refs": list(result.evidence_refs),
        }

    load_state = str(observation.get("load_state") or "").lower()
    active_state = str(observation.get("active_state") or "").lower()
    runtime = {
        "load_state": load_state or None,
        "active_state": active_state or None,
        "sub_state": observation.get("sub_state"),
        "result": observation.get("result"),
        "main_pid": observation.get("main_pid"),
        "restart_count": observation.get("restart_count"),
    }
    if load_state != "loaded":
        return {
            "runtime": runtime,
            "compliance": "DRIFT",
            "reason": f"systemd 当前加载状态为 {load_state or 'unknown'}。",
            "evidence_refs": list(result.evidence_refs),
        }
    if active_state == record.expected_active_state:
        return {
            "runtime": runtime,
            "compliance": "IN_SYNC",
            "reason": f"当前 {active_state}，与服务目录登记一致。",
            "evidence_refs": list(result.evidence_refs),
        }
    return {
        "runtime": runtime,
        "compliance": "DRIFT",
        "reason": (
            f"当前 {active_state or 'unknown'}，"
            f"服务目录登记为 {record.expected_active_state}。"
        ),
        "evidence_refs": list(result.evidence_refs),
    }


def _first_warning(result: ToolResult) -> str | None:
    return next((item.strip() for item in result.warnings if item.strip()), None)
