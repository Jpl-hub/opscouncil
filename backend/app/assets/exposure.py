from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from backend.app.mcp.types import ToolResult
from backend.app.models.entities import ServiceExpectation
from backend.app.perception.network_scope import classify_listener_scope


_SCOPE_RANK = {
    "loopback": 0,
    "link_local": 1,
    "private": 2,
    "public": 3,
    "wildcard": 4,
}
_DRIFT_CHECKS = {"MISSING", "OVEREXPOSED", "IDENTITY_MISMATCH"}


def reconcile_listener_expectations(
    records: Iterable[ServiceExpectation],
    listener_result: ToolResult,
) -> dict[str, Any]:
    record_list = list(records)
    listeners = [
        _normalize_listener(item)
        for item in listener_result.observations
        if isinstance(item, dict)
    ]
    listeners = [item for item in listeners if item is not None]
    expected_keys = {
        (str(expectation["protocol"]), int(expectation["port"]))
        for record in record_list
        for expectation in (record.listener_expectations_json or [])
        if isinstance(expectation, dict)
    }

    by_service: dict[int, dict[str, Any]] = {}
    all_checks: list[dict[str, Any]] = []
    for record in record_list:
        checks = [
            _reconcile_one(record, expectation, listeners)
            for expectation in (record.listener_expectations_json or [])
            if isinstance(expectation, dict)
        ]
        all_checks.extend(checks)
        by_service[record.id] = _service_exposure_summary(checks)

    unmanaged = [
        item
        for item in listeners
        if (str(item["protocol"]), int(item["port"])) not in expected_keys
    ]
    hard_drift_count = sum(
        check["status"] in _DRIFT_CHECKS for check in all_checks
    )
    unknown_count = sum(check["status"] == "UNKNOWN" for check in all_checks)
    return {
        "by_service": by_service,
        "unmanaged_listeners": unmanaged[:100],
        "summary": {
            "listener_expectation_count": len(all_checks),
            "in_sync_count": sum(
                check["status"] in {"IN_SYNC", "OPTIONAL_ABSENT"}
                for check in all_checks
            ),
            "drift_count": hard_drift_count,
            "unknown_count": unknown_count,
            "unmanaged_listener_count": len(unmanaged),
            "scan_status": listener_result.status,
            "overall_status": (
                "DRIFT"
                if hard_drift_count
                else "UNKNOWN"
                if unknown_count or listener_result.status != "ok"
                else "IN_SYNC"
            ),
        },
        "evidence_refs": list(listener_result.evidence_refs),
        "warnings": list(listener_result.warnings),
    }


def _reconcile_one(
    record: ServiceExpectation,
    expectation: dict[str, Any],
    listeners: list[dict[str, Any]],
) -> dict[str, Any]:
    protocol = str(expectation.get("protocol") or "").lower()
    port = int(expectation.get("port") or 0)
    allowed_scope = str(expectation.get("allowed_scope") or "")
    required = bool(expectation.get("required", True))
    matched = [
        item
        for item in listeners
        if item["protocol"] == protocol and item["port"] == port
    ]
    base = {
        "protocol": protocol,
        "port": port,
        "allowed_scope": allowed_scope,
        "required": required,
        "observed": matched,
    }
    if not matched:
        return {
            **base,
            "status": "MISSING" if required else "OPTIONAL_ABSENT",
            "reason": (
                f"{protocol.upper()}/{port} 未监听。"
                if required
                else f"{protocol.upper()}/{port} 当前未启用。"
            ),
        }

    known_other_owners = [
        item
        for item in matched
        if item.get("systemd_unit")
        and item["systemd_unit"] != record.unit_name
    ]
    if known_other_owners:
        owner = str(known_other_owners[0].get("systemd_unit") or "其他进程")
        return {
            **base,
            "status": "IDENTITY_MISMATCH",
            "reason": (
                f"{protocol.upper()}/{port} 由 {owner} 持有，"
                f"与登记服务 {record.unit_name} 不符。"
            ),
        }

    expected_owner_rows = [
        item for item in matched if item.get("systemd_unit") == record.unit_name
    ]
    if not expected_owner_rows:
        return {
            **base,
            "status": "UNKNOWN",
            "reason": (
                f"{protocol.upper()}/{port} 已监听，但当前权限下无法确认"
                f"是否归属 {record.unit_name}。"
            ),
        }

    overexposed = [
        item
        for item in expected_owner_rows
        if _scope_is_broader(str(item["exposure_scope"]), allowed_scope)
    ]
    if overexposed:
        observed_scope = str(overexposed[0]["exposure_scope"])
        return {
            **base,
            "status": "OVEREXPOSED",
            "reason": (
                f"{protocol.upper()}/{port} 实际开放范围为 {observed_scope}，"
                f"超过登记范围 {allowed_scope}。"
            ),
        }
    if any(str(item["exposure_scope"]) == "unknown" for item in expected_owner_rows):
        return {
            **base,
            "status": "UNKNOWN",
            "reason": f"{protocol.upper()}/{port} 的实际开放范围无法确定。",
        }
    return {
        **base,
        "status": "IN_SYNC",
        "reason": (
            f"{protocol.upper()}/{port} 的服务归属与开放范围均符合登记值。"
        ),
    }


def _service_exposure_summary(checks: list[dict[str, Any]]) -> dict[str, Any]:
    if not checks:
        return {
            "status": "NOT_DECLARED",
            "reason": "未登记网络监听要求。",
            "checks": [],
        }
    if any(item["status"] in _DRIFT_CHECKS for item in checks):
        status = "DRIFT"
    elif any(item["status"] == "UNKNOWN" for item in checks):
        status = "UNKNOWN"
    else:
        status = "IN_SYNC"
    return {
        "status": status,
        "reason": "；".join(
            str(item["reason"])
            for item in checks
            if item["status"] not in {"IN_SYNC", "OPTIONAL_ABSENT"}
        )
        or "网络监听与登记值一致。",
        "checks": checks,
    }


def _normalize_listener(item: dict[str, Any]) -> dict[str, Any] | None:
    port = _endpoint_port(str(item.get("local_address") or ""))
    if port is None:
        return None
    protocol = str(item.get("protocol") or "").lower()
    if protocol.startswith("tcp"):
        protocol = "tcp"
    elif protocol.startswith("udp"):
        protocol = "udp"
    else:
        return None
    return {
        "protocol": protocol,
        "port": port,
        "local_address": item.get("local_address"),
        "exposure_scope": str(
            item.get("exposure_scope")
            or classify_listener_scope(str(item.get("local_address") or ""))
        ),
        "pid": item.get("pid"),
        "process": item.get("process") or item.get("process_name"),
        "uid": item.get("uid"),
        "user": item.get("user"),
        "systemd_unit": item.get("systemd_unit"),
        "attribution_source": item.get("attribution_source"),
    }


def _scope_is_broader(actual: str, allowed: str) -> bool:
    actual_rank = _SCOPE_RANK.get(actual)
    allowed_rank = _SCOPE_RANK.get(allowed)
    return (
        actual_rank is not None
        and allowed_rank is not None
        and actual_rank > allowed_rank
    )


def _endpoint_port(value: str) -> int | None:
    raw = value.strip()
    if not raw or ":" not in raw:
        return None
    try:
        return int(raw.rsplit(":", 1)[1])
    except ValueError:
        return None
