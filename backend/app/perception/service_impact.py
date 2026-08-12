from __future__ import annotations

from collections import Counter, deque
import re
import shutil
import subprocess
from typing import Any


_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]+\.[A-Za-z0-9_-]+$")
_SYSTEMD_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "InvocationID",
    "ExecMainPID",
    "ActiveEnterTimestampMonotonic",
    "InactiveEnterTimestampMonotonic",
    "Requires",
    "RequiredBy",
    "Wants",
    "WantedBy",
    "BindsTo",
    "BoundBy",
    "PartOf",
    "ConsistsOf",
    "PropagatesStopTo",
    "StopPropagatedFrom",
    "PropagatesReloadTo",
    "ReloadPropagatedFrom",
    "Triggers",
    "TriggeredBy",
    "Before",
    "After",
)
_DIRECT_RELATIONS = {
    "Requires": "REQUIRES",
    "Wants": "WANTS",
    "BindsTo": "BINDS_TO",
    "PartOf": "PART_OF",
    "PropagatesStopTo": "PROPAGATES_STOP_TO",
    "PropagatesReloadTo": "PROPAGATES_RELOAD_TO",
    "Triggers": "TRIGGERS",
    "Before": "BEFORE",
    "After": "AFTER",
}
_REVERSE_RELATIONS = {
    "RequiredBy": "REQUIRES",
    "WantedBy": "WANTS",
    "BoundBy": "BINDS_TO",
    "ConsistsOf": "PART_OF",
    "StopPropagatedFrom": "PROPAGATES_STOP_TO",
    "ReloadPropagatedFrom": "PROPAGATES_RELOAD_TO",
    "TriggeredBy": "TRIGGERS",
}
_CERTAINTY_RANK = {"POSSIBLE": 1, "LIKELY": 2, "CERTAIN": 3, "DIRECT": 4}
_RELATION_CERTAINTY = {
    "PART_OF": "CERTAIN",
    "PROPAGATES_STOP_TO": "CERTAIN",
    "BINDS_TO": "LIKELY",
    "REQUIRES": "LIKELY",
    "PROPAGATES_RELOAD_TO": "CERTAIN",
}
_EXPANSION_PROPERTIES = {
    "Requires",
    "RequiredBy",
    "Wants",
    "WantedBy",
    "BindsTo",
    "BoundBy",
    "PartOf",
    "ConsistsOf",
    "PropagatesStopTo",
    "StopPropagatedFrom",
    "PropagatesReloadTo",
    "ReloadPropagatedFrom",
}


def collect_systemd_relationship_graph(
    focus_units: list[str],
    *,
    max_relations: int,
) -> dict[str, Any]:
    if not focus_units:
        return _empty_graph()
    if shutil.which("systemctl") is None:
        return {
            **_empty_graph(),
            "evidence_gaps": [
                {
                    "code": "SYSTEMCTL_UNAVAILABLE",
                    "count": len(focus_units),
                    "reason": "当前节点缺少 systemctl，无法核对服务单元依赖。",
                }
            ],
            "warnings": ["systemctl not found"],
        }

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    gaps: list[dict[str, Any]] = []
    warnings: list[str] = []
    evidence_refs: list[str] = []
    relation_count = 0
    truncated = False
    max_units = min(32, max(8, max_relations))
    pending = deque((unit, True) for unit in focus_units)
    queued = set(focus_units)
    queried: set[str] = set()

    while pending and len(queried) < max_units:
        requested_unit, is_focus = pending.popleft()
        if requested_unit in queried:
            continue
        queried.add(requested_unit)
        command = [
            "systemctl",
            "show",
            requested_unit,
            "--no-pager",
            f"--property={','.join(_SYSTEMD_PROPERTIES)}",
        ]
        evidence_ref = f"systemctl show {requested_unit}"
        evidence_refs.append(evidence_ref)
        run = _run_systemctl(command)
        if run is None:
            gaps.append(
                {
                    "code": "SYSTEMD_QUERY_FAILED",
                    "count": 1,
                    "reason": f"未能读取 {requested_unit} 的 systemd 依赖属性。",
                }
            )
            continue
        properties = parse_systemctl_show(run.stdout)
        unit = str(properties.get("Id") or requested_unit)
        _add_unit_node(nodes, unit, properties, focus=is_focus)
        if run.returncode != 0:
            warning = run.stderr.strip() or f"systemctl exited with code {run.returncode}"
            warnings.append(f"{requested_unit}: {warning}")
            gaps.append(
                {
                    "code": "SYSTEMD_QUERY_PARTIAL",
                    "count": 1,
                    "reason": f"{requested_unit} 的 systemd 属性读取不完整。",
                }
            )
        if str(properties.get("LoadState") or "").lower() != "loaded":
            gaps.append(
                {
                    "code": "FOCUS_UNIT_NOT_LOADED",
                    "count": 1,
                    "reason": f"{requested_unit} 当前未处于 loaded 状态。",
                }
            )

        for property_name, relation in _DIRECT_RELATIONS.items():
            for target in _unit_values(properties.get(property_name)):
                if relation_count >= max_relations:
                    truncated = True
                    break
                _add_unit_node(nodes, target, {}, focus=False)
                if _add_relation(
                    edges,
                    source=f"service:{unit}",
                    target=f"service:{target}",
                    relation=relation,
                    property_name=property_name,
                    evidence_ref=evidence_ref,
                ):
                    relation_count += 1
                _enqueue_related_service(
                    pending,
                    queued,
                    target,
                    property_name=property_name,
                    max_units=max_units,
                )
            if truncated:
                break

        if truncated:
            break

        for property_name, relation in _REVERSE_RELATIONS.items():
            for source in _unit_values(properties.get(property_name)):
                if relation_count >= max_relations:
                    truncated = True
                    break
                _add_unit_node(nodes, source, {}, focus=False)
                if _add_relation(
                    edges,
                    source=f"service:{source}",
                    target=f"service:{unit}",
                    relation=relation,
                    property_name=property_name,
                    evidence_ref=evidence_ref,
                ):
                    relation_count += 1
                _enqueue_related_service(
                    pending,
                    queued,
                    source,
                    property_name=property_name,
                    max_units=max_units,
                )
            if truncated:
                break

        if truncated:
            break

    if pending and len(queried) >= max_units:
        gaps.append(
            {
                "code": "SYSTEMD_UNIT_LIMIT",
                "count": len(queried),
                "reason": f"systemd 关系展开达到 {max_units} 个服务单元上限，影响范围按部分证据评估。",
            }
        )
        warnings.append(f"systemd related units truncated at {max_units}")

    if truncated:
        gaps.append(
            {
                "code": "SYSTEMD_RELATION_LIMIT",
                "count": relation_count,
                "reason": f"systemd 关系达到 {max_relations} 条采集上限，影响范围按部分证据评估。",
            }
        )
        warnings.append(f"systemd relationships truncated at {max_relations}")

    return {
        "nodes": sorted(nodes.values(), key=lambda item: (str(item["kind"]), str(item["id"]))),
        "edges": sorted(
            edges.values(),
            key=lambda item: (item["relation"], item["source"], item["target"]),
        ),
        "evidence_gaps": gaps,
        "warnings": warnings,
        "evidence_refs": evidence_refs,
    }


def assess_service_change_impact(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    target_units: list[str],
    change_action: str,
    evidence_gaps: list[dict[str, Any]],
) -> dict[str, Any]:
    targets = [f"service:{unit}" for unit in target_units]
    nodes_by_id = {
        str(node["id"]): node
        for node in nodes
        if isinstance(node, dict) and node.get("id")
    }
    missing_targets = [target for target in targets if target not in nodes_by_id]
    if change_action == "observe":
        return {
            "status": "OBSERVED",
            "action": change_action,
            "target_units": target_units,
            "coverage": "PARTIAL" if evidence_gaps else "FULL",
            "predicted_units": [],
            "predicted_clients": [],
            "propagated_unit_count": 0,
            "possible_client_count": 0,
            "mechanism_counts": {},
            "evidence_gaps": list(evidence_gaps),
        }

    affected: dict[str, dict[str, Any]] = {}
    clients: dict[str, dict[str, Any]] = {}
    for target, unit in zip(targets, target_units, strict=True):
        if target in nodes_by_id:
            affected[target] = {
                "node_id": target,
                "unit": unit,
                "role": "TARGET",
                "certainty": "DIRECT",
                "mechanism": "DIRECT_TARGET",
                "reason": "本次变更直接作用于该服务单元。",
                "path": [target],
                **_unit_runtime_state(nodes_by_id[target]),
            }

    if change_action in {"restart", "stop", "reload"}:
        pending_impact = deque(targets)
        while pending_impact:
            current = pending_impact.popleft()
            current_impact = affected.get(current)
            if current_impact is None:
                continue
            for candidate_id, certainty, mechanism in _propagation_neighbors(
                edges,
                current=current,
                action=change_action,
            ):
                inherited_certainty = _combine_certainty(
                    str(current_impact["certainty"]),
                    certainty,
                )
                changed = _record_affected_unit(
                    affected,
                    nodes_by_id,
                    candidate_id,
                    certainty=inherited_certainty,
                    mechanism=mechanism,
                    path=[*current_impact["path"], candidate_id],
                )
                if changed:
                    pending_impact.append(candidate_id)

        _record_observed_clients(
            clients,
            nodes_by_id,
            edges,
            targets=list(affected),
        )

    predicted_units = sorted(
        affected.values(),
        key=lambda item: (
            -_CERTAINTY_RANK[item["certainty"]],
            item["unit"],
        ),
    )
    predicted_clients = sorted(
        clients.values(),
        key=lambda item: (item.get("service_unit") or "", item["node_id"]),
    )
    combined_gaps = list(evidence_gaps)
    if missing_targets:
        combined_gaps.append(
            {
                "code": "CHANGE_TARGET_UNRESOLVED",
                "count": len(missing_targets),
                "reason": "目标服务未能进入运行关系图，不能给出完整影响判断。",
            }
        )
    mechanisms = Counter(
        item["mechanism"]
        for item in predicted_units
        if item["role"] != "TARGET"
    )
    status = "UNKNOWN" if missing_targets else "PARTIAL" if combined_gaps else "ASSESSED"
    return {
        "contract_version": "service-impact.v1",
        "status": status,
        "action": change_action,
        "target_units": target_units,
        "coverage": "NONE" if missing_targets else "PARTIAL" if combined_gaps else "FULL",
        "predicted_units": predicted_units,
        "predicted_clients": predicted_clients,
        "propagated_unit_count": sum(item["role"] != "TARGET" for item in predicted_units),
        "possible_client_count": len(predicted_clients),
        "mechanism_counts": dict(sorted(mechanisms.items())),
        "graph_node_count": len(nodes),
        "graph_edge_count": len(edges),
        "evidence_gaps": combined_gaps,
    }


def verify_service_change_impact(
    frozen_impact: dict[str, Any],
    post_observation: dict[str, Any],
) -> dict[str, Any]:
    post_impact = post_observation.get("change_impact")
    if not isinstance(post_impact, dict):
        return {
            "valid": False,
            "outcome": "DIVERGED",
            "reason": "执行后未取得服务影响复验结果。",
            "details": {
                "prediction_error_count": 1,
                "evidence_gaps": ["POST_IMPACT_MISSING"],
            },
        }

    frozen_rows = _impact_rows_by_unit(frozen_impact)
    observed_rows = _impact_rows_by_unit(post_impact)
    expected_units = set(frozen_rows)
    observed_units = set(observed_rows)
    missing_units = sorted(expected_units - observed_units)
    unexpected_units = sorted(observed_units - expected_units)
    expectation_mismatches: list[dict[str, Any]] = []
    propagation_checks: list[dict[str, Any]] = []
    evidence_gaps: list[str] = []

    for unit, frozen in frozen_rows.items():
        observed = observed_rows.get(unit)
        if observed is None:
            continue
        expected_state = frozen.get("expected_active_state")
        if (
            frozen.get("registered") is True
            and expected_state
            and observed.get("active_state") != expected_state
        ):
            expectation_mismatches.append(
                {
                    "unit": unit,
                    "expected_active_state": expected_state,
                    "observed_active_state": observed.get("active_state"),
                }
            )
        if (
            frozen.get("role") == "PROPAGATED"
            and frozen.get("mechanism") == "PART_OF"
            and frozen.get("active_state") == "active"
        ):
            before_invocation = frozen.get("invocation_id")
            after_invocation = observed.get("invocation_id")
            if not before_invocation or not after_invocation:
                evidence_gaps.append(f"INVOCATION_ID_UNAVAILABLE:{unit}")
                propagation_checks.append(
                    {
                        "unit": unit,
                        "mechanism": "PART_OF",
                        "result": "INCONCLUSIVE",
                    }
                )
            else:
                changed = before_invocation != after_invocation
                propagation_checks.append(
                    {
                        "unit": unit,
                        "mechanism": "PART_OF",
                        "result": "CONFIRMED" if changed else "DIVERGED",
                        "invocation_changed": changed,
                    }
                )

    diverged_propagations = [
        item
        for item in propagation_checks
        if item["result"] == "DIVERGED"
    ]
    post_gaps = post_impact.get("evidence_gaps")
    if isinstance(post_gaps, list) and post_gaps:
        evidence_gaps.extend(
            str(item.get("code") or "POST_IMPACT_PARTIAL")
            for item in post_gaps
            if isinstance(item, dict)
        )
    valid = not (
        missing_units
        or unexpected_units
        or expectation_mismatches
        or diverged_propagations
    )
    prediction_error_count = (
        len(missing_units)
        + len(unexpected_units)
        + len(expectation_mismatches)
        + len(diverged_propagations)
    )
    outcome = (
        "DIVERGED"
        if not valid
        else "INCONCLUSIVE"
        if evidence_gaps
        else "CONFIRMED"
    )
    return {
        "valid": valid,
        "outcome": outcome,
        "reason": {
            "CONFIRMED": "执行后关系范围、期望状态与可观测传播均符合执行前预测。",
            "INCONCLUSIVE": "执行后范围与期望状态一致，部分传播证据受运行环境限制。",
            "DIVERGED": "执行后实测结果偏离执行前影响预测，系统停止自动闭环。",
        }[outcome],
        "details": {
            "predicted_unit_count": len(expected_units),
            "observed_unit_count": len(observed_units),
            "missing_units": missing_units,
            "unexpected_units": unexpected_units,
            "expectation_mismatches": expectation_mismatches,
            "propagation_checks": propagation_checks,
            "confirmed_propagation_count": sum(
                item["result"] == "CONFIRMED"
                for item in propagation_checks
            ),
            "prediction_error_count": prediction_error_count,
            "evidence_gaps": list(dict.fromkeys(evidence_gaps)),
        },
    }


def verify_service_change_impact_precondition(
    frozen_impact: dict[str, Any],
    current_observation: dict[str, Any],
) -> dict[str, Any]:
    current_impact = current_observation.get("change_impact")
    if not isinstance(current_impact, dict):
        return {
            "valid": False,
            "outcome": "DIVERGED",
            "reason": "执行前未取得最新服务影响范围。",
            "details": {
                "prediction_error_count": 1,
                "evidence_gaps": ["PRE_IMPACT_MISSING"],
            },
        }

    frozen_rows = _impact_rows_by_unit(frozen_impact)
    current_rows = _impact_rows_by_unit(current_impact)
    frozen_units = set(frozen_rows)
    current_units = set(current_rows)
    missing_units = sorted(frozen_units - current_units)
    unexpected_units = sorted(current_units - frozen_units)
    relationship_mismatches: list[dict[str, Any]] = []
    runtime_mismatches: list[dict[str, Any]] = []

    for unit in sorted(frozen_units & current_units):
        frozen = frozen_rows[unit]
        current = current_rows[unit]
        relationship_fields = ("role", "mechanism", "certainty", "path")
        changed_relationships = {
            field: {
                "frozen": frozen.get(field),
                "current": current.get(field),
            }
            for field in relationship_fields
            if frozen.get(field) != current.get(field)
        }
        if changed_relationships:
            relationship_mismatches.append(
                {"unit": unit, "fields": changed_relationships}
            )

        runtime_fields = ("load_state", "active_state", "sub_state", "invocation_id")
        changed_runtime = {
            field: {
                "frozen": frozen.get(field),
                "current": current.get(field),
            }
            for field in runtime_fields
            if frozen.get(field) is not None
            and frozen.get(field) != current.get(field)
        }
        if changed_runtime:
            runtime_mismatches.append({"unit": unit, "fields": changed_runtime})

    frozen_clients = _impact_client_signatures(frozen_impact)
    current_clients = _impact_client_signatures(current_impact)
    missing_clients = sorted(frozen_clients - current_clients)
    unexpected_clients = sorted(current_clients - frozen_clients)
    current_gaps = current_impact.get("evidence_gaps")
    evidence_gaps = [
        str(item.get("code") or "PRE_IMPACT_PARTIAL")
        for item in current_gaps
        if isinstance(item, dict)
    ] if isinstance(current_gaps, list) else []
    prediction_error_count = (
        len(missing_units)
        + len(unexpected_units)
        + len(relationship_mismatches)
        + len(runtime_mismatches)
        + len(missing_clients)
        + len(unexpected_clients)
    )
    valid = prediction_error_count == 0 and not evidence_gaps
    return {
        "valid": valid,
        "outcome": "CONFIRMED" if valid else "DIVERGED",
        "reason": (
            "执行前最新运行关系与审批时冻结范围一致。"
            if valid
            else "审批后运行关系或服务状态已变化，原执行依据自动失效。"
        ),
        "details": {
            "predicted_unit_count": len(frozen_units),
            "observed_unit_count": len(current_units),
            "missing_units": missing_units,
            "unexpected_units": unexpected_units,
            "relationship_mismatches": relationship_mismatches,
            "runtime_mismatches": runtime_mismatches,
            "missing_clients": missing_clients,
            "unexpected_clients": unexpected_clients,
            "prediction_error_count": prediction_error_count,
            "evidence_gaps": evidence_gaps,
        },
    }


def parse_systemctl_show(text: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        properties[key.strip()] = value.strip()
    return properties


def _run_systemctl(command: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _empty_graph() -> dict[str, Any]:
    return {
        "nodes": [],
        "edges": [],
        "evidence_gaps": [],
        "warnings": [],
        "evidence_refs": [],
    }


def _unit_values(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    return [
        unit
        for unit in dict.fromkeys(value.split())
        if _UNIT_RE.fullmatch(unit)
    ]


def _add_unit_node(
    nodes: dict[str, dict[str, Any]],
    unit: str,
    properties: dict[str, str],
    *,
    focus: bool,
) -> None:
    node_id = f"service:{unit}"
    existing = nodes.get(node_id, {})
    nodes[node_id] = {
        "id": node_id,
        "kind": "service" if unit.endswith(".service") else "systemd_unit",
        "label": unit,
        "unit": unit,
        "focus": bool(existing.get("focus")) or focus,
        "load_state": properties.get("LoadState") or existing.get("load_state"),
        "active_state": properties.get("ActiveState") or existing.get("active_state"),
        "sub_state": properties.get("SubState") or existing.get("sub_state"),
        "invocation_id": properties.get("InvocationID") or existing.get("invocation_id"),
        "main_pid": _optional_int(
            properties.get("ExecMainPID"),
            existing.get("main_pid"),
        ),
        "active_enter_monotonic": _optional_int(
            properties.get("ActiveEnterTimestampMonotonic"),
            existing.get("active_enter_monotonic"),
        ),
        "inactive_enter_monotonic": _optional_int(
            properties.get("InactiveEnterTimestampMonotonic"),
            existing.get("inactive_enter_monotonic"),
        ),
    }


def _add_relation(
    edges: dict[tuple[str, str, str], dict[str, Any]],
    *,
    source: str,
    target: str,
    relation: str,
    property_name: str,
    evidence_ref: str,
) -> bool:
    if source == target:
        return False
    key = (source, target, relation)
    if key in edges:
        return False
    edges[key] = {
        "source": source,
        "target": target,
        "relation": relation,
        "observation_count": 1,
        "systemd_property": property_name,
        "evidence_ref": evidence_ref,
    }
    return True


def _record_affected_unit(
    affected: dict[str, dict[str, Any]],
    nodes_by_id: dict[str, dict[str, Any]],
    node_id: str,
    *,
    certainty: str,
    mechanism: str,
    path: list[str],
) -> bool:
    node = nodes_by_id.get(node_id)
    if node is None or not str(node.get("unit") or "").endswith(".service"):
        return False
    previous = affected.get(node_id)
    if previous is not None and _CERTAINTY_RANK[previous["certainty"]] >= _CERTAINTY_RANK[certainty]:
        return False
    affected[node_id] = {
        "node_id": node_id,
        "unit": str(node["unit"]),
        "role": "PROPAGATED",
        "certainty": certainty,
        "mechanism": mechanism,
        "reason": _impact_reason(mechanism),
        "path": path,
        **_unit_runtime_state(node),
    }
    return True


def _propagation_neighbors(
    edges: list[dict[str, Any]],
    *,
    current: str,
    action: str,
) -> list[tuple[str, str, str]]:
    neighbors: list[tuple[str, str, str]] = []
    for edge in edges:
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")
        relation = str(edge.get("relation") or "")
        candidate: str | None = None
        if action in {"restart", "stop"}:
            if relation in {"PART_OF", "BINDS_TO", "REQUIRES"} and target == current:
                candidate = source
            elif relation == "PROPAGATES_STOP_TO" and source == current:
                candidate = target
        elif (
            action == "reload"
            and relation == "PROPAGATES_RELOAD_TO"
            and source == current
        ):
            candidate = target
        if candidate is not None:
            neighbors.append(
                (
                    candidate,
                    _RELATION_CERTAINTY[relation],
                    relation,
                )
            )
    return neighbors


def _combine_certainty(upstream: str, relation: str) -> str:
    if upstream == "DIRECT":
        return relation
    rank = min(_CERTAINTY_RANK[upstream], _CERTAINTY_RANK[relation])
    return next(
        label
        for label in ("POSSIBLE", "LIKELY", "CERTAIN")
        if _CERTAINTY_RANK[label] == rank
    )


def _enqueue_related_service(
    pending: deque[tuple[str, bool]],
    queued: set[str],
    unit: str,
    *,
    property_name: str,
    max_units: int,
) -> None:
    if (
        property_name not in _EXPANSION_PROPERTIES
        or not unit.endswith(".service")
        or unit in queued
        or len(queued) >= max_units
    ):
        return
    queued.add(unit)
    pending.append((unit, False))


def _record_observed_clients(
    clients: dict[str, dict[str, Any]],
    nodes_by_id: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    targets: list[str],
) -> None:
    target_processes = {
        str(edge.get("target"))
        for edge in edges
        if str(edge.get("relation") or "") == "RUNS_PROCESS"
        and str(edge.get("source") or "") in targets
    }
    target_listeners = {
        str(edge.get("target"))
        for edge in edges
        if str(edge.get("relation") or "") == "LISTENS_ON"
        and str(edge.get("source") or "") in target_processes
    }
    if not target_listeners:
        return
    client_processes = {
        str(edge.get("source"))
        for edge in edges
        if str(edge.get("relation") or "") == "CONNECTS_TO"
        and str(edge.get("target") or "") in target_listeners
    }
    service_by_process = {
        str(edge.get("target")): str(edge.get("source"))
        for edge in edges
        if str(edge.get("relation") or "") == "RUNS_PROCESS"
    }
    for process_id in client_processes - target_processes:
        process = nodes_by_id.get(process_id, {})
        service_id = service_by_process.get(process_id)
        service = nodes_by_id.get(service_id or "", {})
        clients[process_id] = {
            "node_id": process_id,
            "process": process.get("label") or process_id,
            "pid": process.get("pid"),
            "service_unit": service.get("unit"),
            "certainty": "POSSIBLE",
            "mechanism": "OBSERVED_CLIENT_CONNECTION",
            "reason": "当前观测到该进程与目标监听端口存在连接，重启期间连接可能中断。",
        }


def _impact_reason(mechanism: str) -> str:
    return {
        "PART_OF": "该单元声明 PartOf，目标停止或重启会向其传播。",
        "PROPAGATES_STOP_TO": "目标声明停止传播关系，停止阶段会向该单元传播。",
        "BINDS_TO": "该单元与目标建立强绑定，目标进入 inactive 时可能被停止。",
        "REQUIRES": "该单元强依赖目标，显式停止目标可能将其纳入停止事务。",
        "PROPAGATES_RELOAD_TO": "目标声明重载传播关系，重载会向该单元传播。",
    }.get(mechanism, "该单元位于本次变更的已观测影响路径中。")


def _unit_runtime_state(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "load_state": node.get("load_state"),
        "active_state": node.get("active_state"),
        "sub_state": node.get("sub_state"),
        "invocation_id": node.get("invocation_id"),
        "main_pid": node.get("main_pid"),
        "active_enter_monotonic": node.get("active_enter_monotonic"),
        "inactive_enter_monotonic": node.get("inactive_enter_monotonic"),
    }


def _impact_rows_by_unit(impact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = impact.get("predicted_units")
    if not isinstance(rows, list):
        return {}
    return {
        str(item["unit"]): item
        for item in rows
        if isinstance(item, dict)
        and isinstance(item.get("unit"), str)
        and item["unit"]
    }


def _impact_client_signatures(impact: dict[str, Any]) -> set[str]:
    rows = impact.get("predicted_clients")
    if not isinstance(rows, list):
        return set()
    signatures: set[str] = set()
    for item in rows:
        if not isinstance(item, dict):
            continue
        signature = "|".join(
            str(item.get(field) or "")
            for field in (
                "node_id",
                "service_unit",
                "local_address",
                "local_port",
                "remote_address",
                "remote_port",
            )
        )
        if signature.strip("|"):
            signatures.add(signature)
    return signatures


def _optional_int(value: Any, fallback: Any = None) -> int | None:
    for candidate in (value, fallback):
        if isinstance(candidate, bool):
            continue
        try:
            return int(candidate)
        except (TypeError, ValueError):
            continue
    return None
