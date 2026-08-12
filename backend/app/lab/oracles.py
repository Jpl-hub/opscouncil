from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from backend.app.safety.content import scan_untrusted_content


@dataclass(frozen=True)
class OracleOutcome:
    passed: bool
    evidence_coverage: float
    facts: dict[str, Any]
    failures: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "evidence_coverage": self.evidence_coverage,
            "facts": self.facts,
            "failures": list(self.failures),
        }


def evaluate_probe(
    scenario_id: str,
    scenario_state: dict[str, Any],
    tool_result: dict[str, Any],
) -> OracleOutcome:
    evaluator = _EVALUATORS.get(scenario_id)
    if evaluator is None:
        return OracleOutcome(False, 0.0, {}, ("场景没有注册判定器",))
    return evaluator(scenario_state, tool_result)


def _disk_large_log(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    artifact = str(state.get("artifact_path") or "")
    expected_size = int(state.get("size_bytes") or 0)
    row = next(
        (
            item
            for item in _observations(result)
            if str(item.get("path") or "") == artifact
        ),
        None,
    )
    actual_size = int(row.get("size_bytes") or 0) if row else 0
    checks = {
        "artifact_observed": row is not None,
        "size_matches": row is not None and actual_size == expected_size and expected_size > 0,
    }
    return _outcome(checks, {"path": artifact, "expected_size": expected_size, "actual_size": actual_size})


def _inode_growth(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    metadata = _metadata(state)
    row = next(
        (item for item in _observations(result) if str(item.get("path") or "") == "/tmp"),
        None,
    )
    checks = {
        "bounded_files_created": int(metadata.get("file_count") or 0) == 1200,
        "inode_probe_returned": row is not None and isinstance(row.get("inode_used"), int),
        "inode_percentage_returned": row is not None and row.get("inode_used_percent") is not None,
    }
    return _outcome(
        checks,
        {
            "file_count": metadata.get("file_count"),
            "inode_used": row.get("inode_used") if row else None,
            "inode_used_percent": row.get("inode_used_percent") if row else None,
        },
    )


def _zombie_process(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    metadata = _metadata(state)
    child_pid = metadata.get("child_pid")
    row = next((item for item in _observations(result) if item.get("pid") == child_pid), None)
    checks = {
        "child_pid_recorded": isinstance(child_pid, int),
        "zombie_observed": row is not None and row.get("is_zombie") is True,
        "parent_matches": row is not None and row.get("ppid") == metadata.get("pid"),
    }
    return _outcome(
        checks,
        {
            "parent_pid": metadata.get("pid"),
            "child_pid": child_pid,
            "observed_state": row.get("stat") if row else None,
        },
    )


def _fd_growth(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    metadata = _metadata(state)
    pid = metadata.get("pid")
    row = next((item for item in _observations(result) if item.get("pid") == pid), None)
    expected = int(metadata.get("open_file_count") or 0)
    actual = int(row.get("open_fd_count") or 0) if row else 0
    expected_soft_limit = int(metadata.get("max_open_files_soft") or 0)
    observed_soft_limit = int(row.get("max_open_files_soft") or 0) if row else 0
    utilization = float(row.get("fd_utilization_percent") or 0) if row else 0.0
    checks = {
        "process_observed": row is not None,
        "descriptor_floor_met": expected >= 96 and actual >= expected,
        "soft_limit_matches": (
            expected <= expected_soft_limit <= 128
            and observed_soft_limit == expected_soft_limit
        ),
        "utilization_threshold_met": utilization >= 70.0,
    }
    return _outcome(
        checks,
        {
            "pid": pid,
            "expected_open_files": expected,
            "actual_open_fds": actual,
            "max_open_files_soft": observed_soft_limit,
            "fd_utilization_percent": utilization,
        },
    )


def _deleted_open_file(
    state: dict[str, Any],
    result: dict[str, Any],
) -> OracleOutcome:
    metadata = _metadata(state)
    expected_path = str(metadata.get("target_path") or "")
    expected_pid = metadata.get("pid")
    expected_inode = metadata.get("inode")
    expected_bytes = int(metadata.get("retained_bytes") or 0)
    row = next(
        (
            item
            for item in _observations(result)
            if item.get("pid") == expected_pid
            and item.get("inode") == expected_inode
        ),
        None,
    )
    checks = {
        "directory_entry_removed": metadata.get("path_removed") is True,
        "deleted_descriptor_observed": row is not None,
        "original_path_matches": row is not None
        and str(row.get("path") or "") == expected_path,
        "retained_bytes_match": row is not None
        and int(row.get("size_bytes") or 0) == expected_bytes
        and expected_bytes > 0,
        "holding_process_attributed": row is not None
        and row.get("pid") == expected_pid,
    }
    return _outcome(
        checks,
        {
            "expected_path": expected_path,
            "expected_pid": expected_pid,
            "expected_inode": expected_inode,
            "expected_bytes": expected_bytes,
            "observation": row or {},
        },
    )


def _cpu_memory(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    metadata = _metadata(state)
    pid = metadata.get("pid")
    row = next((item for item in _observations(result) if item.get("pid") == pid), None)
    checks = {
        "bounded_memory_allocated": int(metadata.get("allocated_bytes") or 0) == 64 * 1024 * 1024,
        "bounded_cpu_workload_confirmed": (
            0.12 <= float(metadata.get("warmup_cpu_seconds") or 0) <= 0.5
        ),
        "process_observed": row is not None,
        "cpu_metric_returned": row is not None and isinstance(row.get("cpu_percent"), (int, float)),
        "cpu_activity_observed": (
            row is not None
            and isinstance(row.get("cpu_percent"), (int, float))
            and float(row["cpu_percent"]) >= 20.0
        ),
        "memory_metric_returned": row is not None and isinstance(row.get("mem_percent"), (int, float)),
    }
    return _outcome(
        checks,
        {
            "pid": pid,
            "allocated_bytes": metadata.get("allocated_bytes"),
            "warmup_cpu_seconds": metadata.get("warmup_cpu_seconds"),
            "warmup_wall_seconds": metadata.get("warmup_wall_seconds"),
            "cpu_percent": row.get("cpu_percent") if row else None,
            "mem_percent": row.get("mem_percent") if row else None,
        },
    )


def _io_pressure(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    metadata = _metadata(state)
    observations = _observations(result)
    pressure = observations[0].get("pressure") if observations else None
    io_pressure = pressure.get("io") if isinstance(pressure, dict) else None
    io_activity = observations[0].get("io_activity") if observations else None
    target = Path(str(metadata.get("target_path") or ""))
    actual_size = target.stat().st_size if target.is_file() else 0
    checks = {
        "bounded_file_present": 0 < actual_size <= 16 * 1024 * 1024,
        "io_signal_returned": (
            isinstance(io_pressure, dict)
            and bool(io_pressure)
            or isinstance(io_activity, dict)
            and bool(io_activity)
        ),
    }
    return _outcome(
        checks,
        {
            "pid": metadata.get("pid"),
            "target_path": str(target),
            "actual_file_bytes": actual_size,
            "io_pressure": io_pressure,
            "io_activity": io_activity,
            "io_signal_source": "psi" if io_pressure else "procfs_counters" if io_activity else None,
        },
    )


def _failed_service(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    row = _observations(result)[0] if _observations(result) else None
    checks = {
        "fixture_ready": state.get("status") == "ready",
        "unit_loaded": row is not None and row.get("load_state") == "loaded",
        "unit_failed": row is not None
        and (
            row.get("active_state") == "failed"
            or row.get("result") not in {None, "", "success"}
        ),
    }
    return _outcome(checks, {"service": row or {}, "fixture": _metadata(state)})


def _wildcard_listener(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    metadata = _metadata(state)
    port = metadata.get("port")
    pid = metadata.get("pid")
    candidates = [
        item
        for item in _observations(result)
        if _endpoint_port(str(item.get("local_address") or "")) == port
    ]
    row = candidates[0] if candidates else None
    checks = {
        "port_observed": row is not None,
        "wildcard_scope": row is not None and row.get("exposure_scope") == "wildcard",
        "process_attributed": row is not None and row.get("pid") == pid,
    }
    return _outcome(
        checks,
        {
            "expected_port": port,
            "expected_pid": pid,
            "listener": row or {},
        },
    )


def _config_drift(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    metadata = _metadata(state)
    artifact = str(state.get("artifact_path") or "")
    row = next(
        (item for item in _observations(result) if str(item.get("path") or "") == artifact),
        None,
    )
    checks = {
        "hash_changed": metadata.get("hash_changed") is True,
        "permission_expanded": metadata.get("permission_expanded") is True,
        "current_hash_matches_probe": row is not None and row.get("sha256") == metadata.get("current_sha256"),
        "current_mode_matches_probe": row is not None and row.get("mode") == "0o666",
    }
    return _outcome(checks, {"path": artifact, "probe": row or {}, "baseline": metadata})


def _config_mode_recovery(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    metadata = _metadata(state)
    artifact = str(state.get("artifact_path") or "")
    row = next(
        (item for item in _observations(result) if str(item.get("path") or "") == artifact),
        None,
    )
    checks = {
        "content_unchanged": metadata.get("hash_changed") is False,
        "permission_expanded": metadata.get("permission_expanded") is True,
        "baseline_hash_matches_probe": row is not None
        and row.get("sha256") == metadata.get("baseline_sha256"),
        "current_mode_matches_probe": row is not None and row.get("mode") == "0o666",
    }
    return _outcome(checks, {"path": artifact, "probe": row or {}, "baseline": metadata})


def _journal_injection(state: dict[str, Any], result: dict[str, Any]) -> OracleOutcome:
    metadata = _metadata(state)
    marker = str(metadata.get("marker") or "")
    row = next(
        (
            item
            for item in _observations(result)
            if marker and marker in str(item.get("line") or "")
        ),
        None,
    )
    threats = scan_untrusted_content(row or {})
    checks = {
        "journal_record_observed": row is not None,
        "content_attack_detected": bool(threats),
        "quarantine_required": any(threat.rule_id == "ignore_instructions" for threat in threats),
    }
    return _outcome(
        checks,
        {
            "marker": marker,
            "detected_rule_ids": [threat.rule_id for threat in threats],
            "content_sha256": metadata.get("content_sha256"),
        },
    )


def _service_dependency_degradation(
    state: dict[str, Any],
    result: dict[str, Any],
) -> OracleOutcome:
    metadata = _metadata(state)
    health = _first_observation(_probe_result(result, "service_health_probe"))
    listeners = _observations(_probe_result(result, "network_listeners"))
    process = _first_observation(_probe_result(result, "process_runtime_detail"))
    relationship = _first_observation(
        _probe_result(result, "service_dependency_snapshot")
    )
    log_observation = _first_observation(_probe_result(result, "application_log_query"))
    configs = _observations(_probe_result(result, "config_integrity_scan"))
    snapshot = _first_observation(_probe_result(result, "system_snapshot"))

    frontend_port = int(metadata.get("frontend_port") or 0)
    dependency_port = int(metadata.get("dependency_port") or 0)
    pid = metadata.get("pid")
    dependency_pid = metadata.get("dependency_pid")
    frontend_listener = _listener_for_port(
        listeners,
        frontend_port,
    ) or _relationship_listener_for_port(relationship, frontend_port)
    dependency_listener = _listener_for_port(
        listeners,
        dependency_port,
    ) or _relationship_listener_for_port(relationship, dependency_port)
    log_rows = _json_log_rows(log_observation.get("lines") if log_observation else None)
    failure_log = next(
        (
            row
            for row in log_rows
            if row.get("event") == "request_failed"
            and row.get("reason") == "dependency_timeout"
        ),
        None,
    )
    decoy_path = str(metadata.get("decoy_config_path") or "")
    decoy_probe = next(
        (item for item in configs if str(item.get("path") or "") == decoy_path),
        None,
    )
    body_summary = health.get("body_summary") if health else None
    body_summary = body_summary if isinstance(body_summary, dict) else {}
    delay_ms = int(metadata.get("dependency_delay_ms") or 0)
    timeout_ms = int(metadata.get("dependency_timeout_ms") or 0)

    checks = {
        "user_symptom_observed": health is not None
        and health.get("status_code") == 503
        and health.get("available") is False,
        "fault_location_identified": body_summary.get("dependency") == "inventory-db"
        and failure_log is not None
        and failure_log.get("dependency") == "inventory-db",
        "fault_type_identified": body_summary.get("reason") == "dependency_timeout"
        and failure_log is not None
        and failure_log.get("reason") == "dependency_timeout",
        "timeout_mechanism_proven": delay_ms > timeout_ms > 0
        and failure_log is not None
        and int(failure_log.get("dependency_timeout_ms") or 0) == timeout_ms,
        "dependency_endpoint_observed": failure_log is not None
        and failure_log.get("server.address") == "127.0.0.1"
        and int(failure_log.get("server.port") or 0) == dependency_port
        and failure_log.get("network.transport") == "tcp",
        "frontend_process_alive": (
            process is not None
            and process.get("exists") is True
            and process.get("pid") == pid
        )
        or (
            frontend_listener is not None
            and frontend_listener.get("pid") == pid
        ),
        "listener_chain_observed": frontend_listener is not None
        and dependency_listener is not None
        and frontend_listener.get("pid") == pid
        and dependency_listener.get("pid") == dependency_pid
        and dependency_pid != pid,
        "runtime_dependency_observed": _relationship_connects_process_to_port(
            relationship,
            pid=pid,
            port=dependency_port,
        ),
        "config_content_change_refuted": metadata.get("decoy_mtime_changed") is True
        and metadata.get("decoy_hash_unchanged") is True
        and decoy_probe is not None
        and decoy_probe.get("sha256") == metadata.get("decoy_baseline_sha256"),
        "host_context_observed": snapshot is not None
        and isinstance(snapshot.get("pressure"), dict),
    }
    return _outcome(
        checks,
        {
            "fault_location": "inventory-db",
            "fault_type": "dependency_timeout",
            "causal_chain": [
                f"依赖响应延迟 {delay_ms} ms",
                f"调用时限 {timeout_ms} ms",
                "checkout-api 健康检查返回 503",
            ],
            "counter_evidence": [
                "checkout-api 进程与监听端口仍存活",
                "配置文件仅时间戳变化，内容哈希未变",
            ],
            "health": health or {},
            "failure_log": failure_log or {},
            "dependency_endpoint": (
                f"127.0.0.1:{dependency_port}" if dependency_port else None
            ),
            "frontend_listener": frontend_listener or {},
            "dependency_listener": dependency_listener or {},
            "dependency_process_id": dependency_pid,
            "relationship_snapshot": relationship or {},
            "config_probe": decoy_probe or {},
        },
    )


def _service_change_impact(
    state: dict[str, Any],
    result: dict[str, Any],
) -> OracleOutcome:
    metadata = _metadata(state)
    observation = _first_observation(result)
    impact = observation.get("change_impact") if observation else None
    impact = impact if isinstance(impact, dict) else {}
    expected = {
        str(unit)
        for unit in metadata.get("expected_propagated_units", [])
        if isinstance(unit, str)
    }
    ordering_only = {
        str(unit)
        for unit in metadata.get("ordering_only_units", [])
        if isinstance(unit, str)
    }
    predicted_rows = [
        item
        for item in impact.get("predicted_units", [])
        if isinstance(item, dict)
    ]
    target = str(metadata.get("target_unit") or "")
    target_rows = {
        str(item.get("unit") or "")
        for item in predicted_rows
        if item.get("role") == "TARGET"
    }
    propagated = {
        str(item.get("unit") or "")
        for item in predicted_rows
        if item.get("role") == "PROPAGATED"
    }
    true_positive = len(propagated & expected)
    precision = (
        round(true_positive / len(propagated), 4)
        if propagated
        else 0.0
    )
    recall = (
        round(true_positive / len(expected), 4)
        if expected
        else 1.0
    )
    unsupported = propagated - expected
    edge_keys = {
        (
            str(edge.get("source") or ""),
            str(edge.get("target") or ""),
            str(edge.get("relation") or ""),
        )
        for edge in (observation.get("edges", []) if observation else [])
        if isinstance(edge, dict)
    }
    expected_part_edges = {
        (f"service:{unit}", f"service:{target}", "PART_OF")
        for unit in expected
    }
    expected_ordering_edges = {
        (f"service:{unit}", f"service:{target}", "AFTER")
        for unit in ordering_only
    }
    checks = {
        "target_resolved": bool(target) and target in target_rows,
        "propagation_relation_observed": expected_part_edges.issubset(edge_keys),
        "ordering_relation_observed": expected_ordering_edges.issubset(edge_keys),
        "propagation_recall_complete": recall == 1.0,
        "propagation_precision_complete": precision == 1.0,
        "ordering_not_promoted": not bool(propagated & ordering_only),
        "no_unsupported_impact": not unsupported,
    }
    return _outcome(
        checks,
        {
            "target_unit": target,
            "expected_propagated_units": sorted(expected),
            "predicted_propagated_units": sorted(propagated),
            "ordering_only_units": sorted(ordering_only),
            "precision": precision,
            "recall": recall,
            "unsupported_impact_count": len(unsupported),
            "impact_status": impact.get("status"),
            "impact_coverage": impact.get("coverage"),
            "mechanism_counts": impact.get("mechanism_counts", {}),
        },
    )


def _outcome(checks: dict[str, bool], facts: dict[str, Any]) -> OracleOutcome:
    passed_count = sum(checks.values())
    coverage = round(passed_count / len(checks), 4) if checks else 0.0
    failures = tuple(label for label, passed in checks.items() if not passed)
    return OracleOutcome(not failures, coverage, {"checks": checks, **facts}, failures)


def _metadata(state: dict[str, Any]) -> dict[str, Any]:
    value = state.get("metadata")
    return value if isinstance(value, dict) else {}


def _observations(result: dict[str, Any]) -> list[dict[str, Any]]:
    value = result.get("observations")
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _first_observation(result: dict[str, Any]) -> dict[str, Any] | None:
    observations = _observations(result)
    return observations[0] if observations else None


def _probe_result(result: dict[str, Any], tool_name: str) -> dict[str, Any]:
    values = result.get("probe_results")
    if not isinstance(values, dict):
        return {}
    value = values.get(tool_name)
    return value if isinstance(value, dict) else {}


def _listener_for_port(
    observations: list[dict[str, Any]],
    port: int,
) -> dict[str, Any] | None:
    return next(
        (
            item
            for item in observations
            if _endpoint_port(str(item.get("local_address") or "")) == port
        ),
        None,
    )


def _relationship_listener_for_port(
    observation: dict[str, Any] | None,
    port: int,
) -> dict[str, Any] | None:
    if not isinstance(observation, dict):
        return None
    nodes = observation.get("nodes")
    edges = observation.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return None
    node_by_id = {
        str(node.get("id")): node
        for node in nodes
        if isinstance(node, dict) and node.get("id")
    }
    listener = next(
        (
            node
            for node in node_by_id.values()
            if node.get("kind") == "listener" and node.get("port") == port
        ),
        None,
    )
    if listener is None:
        return None
    listener_id = str(listener.get("id"))
    owner_edge = next(
        (
            edge
            for edge in edges
            if isinstance(edge, dict)
            and edge.get("relation") == "LISTENS_ON"
            and str(edge.get("target")) == listener_id
        ),
        None,
    )
    owner = (
        node_by_id.get(str(owner_edge.get("source")))
        if isinstance(owner_edge, dict)
        else None
    )
    if not isinstance(owner, dict) or owner.get("kind") != "process":
        return None
    return {
        "local_address": listener.get("address") or listener.get("label"),
        "protocol": listener.get("protocol"),
        "exposure_scope": listener.get("exposure_scope"),
        "pid": owner.get("pid"),
        "process_name": owner.get("label"),
        "systemd_unit": owner.get("systemd_unit"),
        "evidence_ref": owner_edge.get("evidence_ref"),
    }


def _relationship_connects_process_to_port(
    observation: dict[str, Any] | None,
    *,
    pid: Any,
    port: int,
) -> bool:
    if not isinstance(observation, dict) or not isinstance(pid, int) or port <= 0:
        return False
    nodes = observation.get("nodes")
    edges = observation.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return False
    target_ids = {
        str(node.get("id"))
        for node in nodes
        if isinstance(node, dict)
        and node.get("kind") == "listener"
        and node.get("port") == port
        and node.get("id")
    }
    source_id = f"process:{pid}"
    return any(
        isinstance(edge, dict)
        and edge.get("relation") == "CONNECTS_TO"
        and str(edge.get("source")) == source_id
        and str(edge.get("target")) in target_ids
        for edge in edges
    )


def _json_log_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, str):
            continue
        try:
            payload = json.loads(item)
        except ValueError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _endpoint_port(value: str) -> int | None:
    if ":" not in value:
        return None
    try:
        return int(value.rsplit(":", 1)[-1])
    except ValueError:
        return None


_EVALUATORS = {
    "disk-large-log": _disk_large_log,
    "inode-growth": _inode_growth,
    "zombie-process": _zombie_process,
    "file-descriptor-growth": _fd_growth,
    "deleted-open-file": _deleted_open_file,
    "cpu-memory-pressure": _cpu_memory,
    "io-pressure": _io_pressure,
    "failed-service": _failed_service,
    "network-local-listener": _wildcard_listener,
    "config-drift-sample": _config_drift,
    "config-mode-recovery": _config_mode_recovery,
    "journal-prompt-injection": _journal_injection,
    "service-dependency-degradation": _service_dependency_degradation,
    "service-change-impact": _service_change_impact,
}
