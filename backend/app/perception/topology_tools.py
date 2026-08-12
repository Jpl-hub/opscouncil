from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import shutil
import subprocess
from typing import Any, Literal

from backend.app.core.pydantic_compat import BaseModel, Field, field_validator
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.perception.service_impact import (
    assess_service_change_impact,
    collect_systemd_relationship_graph,
)
from backend.app.perception.socket_inventory import (
    collect_proc_socket_owners,
    parse_network_listener_line,
    read_process_cgroup_identity,
    read_process_uid,
    username,
)
from backend.app.schemas.enums import RiskLevel


class ServiceDependencySnapshotInput(BaseModel):
    focus_ports: list[int] = Field(default_factory=list)
    focus_units: list[str] = Field(default_factory=list)
    change_action: Literal["observe", "restart", "stop", "reload"] = "observe"
    max_listeners: int = Field(default=120, ge=1, le=500)
    max_connections: int = Field(default=240, ge=1, le=1000)
    max_systemd_relations: int = Field(default=120, ge=1, le=500)

    @field_validator("focus_ports")
    @classmethod
    def validate_focus_ports(cls, value: list[int]) -> list[int]:
        ports = list(dict.fromkeys(value))
        if len(ports) > 8 or any(port < 1 or port > 65535 for port in ports):
            raise ValueError("focus_ports must contain at most 8 valid TCP/UDP ports")
        return ports

    @field_validator("focus_units")
    @classmethod
    def validate_focus_units(cls, value: list[str]) -> list[str]:
        units = list(dict.fromkeys(item.strip() for item in value if item.strip()))
        if len(units) > 8 or any(
            not unit.endswith(".service")
            or not all(character.isalnum() or character in "_.@:-" for character in unit)
            for unit in units
        ):
            raise ValueError("focus_units must contain at most 8 complete systemd service names")
        return units


def service_dependency_snapshot(payload: BaseModel) -> ToolResult:
    args = ServiceDependencySnapshotInput.model_validate(payload)
    ss_available = shutil.which("ss") is not None
    if not ss_available and not args.focus_units:
        return ToolResult(status="unavailable", warnings=["ss not found"])

    listener_run = _run_ss(["ss", "-H", "-lntupe"]) if ss_available else None
    connection_run = _run_ss(["ss", "-H", "-ntupe"]) if ss_available else None
    listener_lines = listener_run.stdout.splitlines() if listener_run is not None else []
    connection_lines = connection_run.stdout.splitlines() if connection_run is not None else []
    observation = assemble_service_dependency_snapshot(
        listener_lines[: args.max_listeners],
        connection_lines[: args.max_connections],
        focus_ports=set(args.focus_ports),
        focus_units=set(args.focus_units),
        proc_root=Path("/proc"),
    )
    systemd_graph = collect_systemd_relationship_graph(
        args.focus_units,
        max_relations=args.max_systemd_relations,
    )
    _merge_relationship_graph(observation, systemd_graph)
    observation["change_impact"] = assess_service_change_impact(
        observation["nodes"],
        observation["edges"],
        target_units=args.focus_units,
        change_action=args.change_action,
        evidence_gaps=observation["evidence_gaps"],
    )
    observation["captured_at"] = datetime.now(timezone.utc).isoformat()
    observation["scan"] = {
        "listener_rows": len(listener_lines),
        "connection_rows": len(connection_lines),
        "listener_limit": args.max_listeners,
        "connection_limit": args.max_connections,
        "listener_truncated": len(listener_lines) > args.max_listeners,
        "connection_truncated": len(connection_lines) > args.max_connections,
    }

    warnings = list(systemd_graph["warnings"])
    if not ss_available:
        warnings.append("ss not found; socket relationship coverage is unavailable")
    elif listener_run is None or connection_run is None:
        warnings.append("service relationship snapshot could not execute ss")
    if listener_run is not None and listener_run.stderr.strip():
        warnings.append(listener_run.stderr.strip())
    if connection_run is not None and connection_run.stderr.strip():
        warnings.append(connection_run.stderr.strip())
    if listener_run is not None and listener_run.returncode != 0:
        warnings.append(f"listener scan exited with code {listener_run.returncode}")
    if connection_run is not None and connection_run.returncode != 0:
        warnings.append(f"connection scan exited with code {connection_run.returncode}")
    if observation["scan"]["listener_truncated"]:
        warnings.append(f"listener rows truncated at {args.max_listeners}")
    if observation["scan"]["connection_truncated"]:
        warnings.append(f"connection rows truncated at {args.max_connections}")
    if observation["scoped_unattributed_socket_count"]:
        warnings.append(
            "关注范围内 "
            f"{observation['scoped_unattributed_socket_count']} 个套接字因权限或进程退出未能归属"
        )
    if args.focus_ports and not observation["focus_process_ids"]:
        warnings.append("关注端口未能归属到存活进程，关系快照保持为空")

    return ToolResult(
        status="partial" if warnings or observation["evidence_gaps"] else "ok",
        observations=[observation],
        warnings=warnings[:10],
        evidence_refs=list(
            dict.fromkeys(
                [
                    *(
                        [
                            "ss -H -lntupe",
                            "ss -H -ntupe",
                            "/proc/<pid>/status",
                            "/proc/<pid>/comm",
                            "/proc/<pid>/cgroup",
                        ]
                        if ss_available
                        else []
                    ),
                    *systemd_graph["evidence_refs"],
                ]
            )
        ),
        summary_fields={
            "change_impact_status": observation["change_impact"]["status"],
            "propagated_unit_count": observation["change_impact"]["propagated_unit_count"],
            "possible_client_count": observation["change_impact"]["possible_client_count"],
        },
    )


def assemble_service_dependency_snapshot(
    listener_lines: list[str],
    connection_lines: list[str],
    *,
    focus_ports: set[int] | None = None,
    focus_units: set[str] | None = None,
    proc_root: Path = Path("/proc"),
) -> dict[str, Any]:
    listeners = _parse_rows(listener_lines)
    connections = [
        item
        for item in _parse_rows(connection_lines)
        if str(item.get("state") or "").upper() in {"ESTAB", "ESTABLISHED"}
    ]
    all_rows = [*listeners, *connections]
    unresolved_inodes = {
        int(item["socket_inode"])
        for item in all_rows
        if item.get("pid") is None and isinstance(item.get("socket_inode"), int)
    }
    owners = collect_proc_socket_owners(unresolved_inodes, proc_root=proc_root)
    for item in all_rows:
        _enrich_owner(item, owners, proc_root)

    focus = set(focus_ports or set())
    unit_focus = set(focus_units or set())
    focus_process_ids = {
        int(item["pid"])
        for item in listeners
        if isinstance(item.get("pid"), int)
        and bool(focus)
        and _endpoint_port(str(item.get("local_address") or "")) in focus
    }
    focus_unit_process_ids = {
        int(item["pid"])
        for item in all_rows
        if isinstance(item.get("pid"), int)
        and item.get("systemd_unit") in unit_focus
    }
    selected_process_ids = (
        focus_process_ids | focus_unit_process_ids
        if focus or unit_focus
        else {
            int(item["pid"])
            for item in all_rows
            if isinstance(item.get("pid"), int)
        }
    )

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    listener_by_loopback_port: dict[tuple[str, int], str] = {}
    listener_ports_by_process: dict[int, set[tuple[str, int]]] = {}
    unattributed = 0
    scoped_unattributed = 0

    for item in listeners:
        pid = item.get("pid")
        if not isinstance(pid, int):
            unattributed += 1
            if _unattributed_row_affects_scope(
                item,
                focus_ports=focus,
                focus_units=unit_focus,
                is_listener=True,
            ):
                scoped_unattributed += 1
            continue
        protocol = str(item.get("protocol") or "").lower()
        endpoint = str(item.get("local_address") or "")
        port = _endpoint_port(endpoint)
        if port is None:
            continue
        listener_id = f"listener:{protocol}:{endpoint}"
        listener_by_loopback_port[(protocol, port)] = listener_id
        listener_ports_by_process.setdefault(pid, set()).add((protocol, port))
        if pid not in selected_process_ids:
            continue
        process_id = _add_process_nodes(nodes, edges, item)
        nodes[listener_id] = {
            "id": listener_id,
            "kind": "listener",
            "label": endpoint,
            "protocol": protocol,
            "address": endpoint,
            "port": port,
            "exposure_scope": item.get("exposure_scope"),
        }
        _add_edge(
            edges,
            process_id,
            listener_id,
            "LISTENS_ON",
            "ss -H -lntupe",
        )

    for item in connections:
        pid = item.get("pid")
        if not isinstance(pid, int):
            unattributed += 1
            if _unattributed_row_affects_scope(
                item,
                focus_ports=focus,
                focus_units=unit_focus,
                is_listener=False,
            ):
                scoped_unattributed += 1
            continue
        if pid not in selected_process_ids:
            continue
        protocol = str(item.get("protocol") or "").lower()
        local_endpoint = str(item.get("local_address") or "")
        local_port = _endpoint_port(local_endpoint)
        if local_port is not None and (protocol, local_port) in listener_ports_by_process.get(pid, set()):
            continue

        process_id = _add_process_nodes(nodes, edges, item)
        peer_endpoint = str(item.get("peer_address") or "")
        peer_host, peer_port = _endpoint_parts(peer_endpoint)
        local_listener_id = (
            listener_by_loopback_port.get((protocol, peer_port))
            if peer_port is not None and _address_scope(peer_host) == "loopback"
            else None
        )
        if local_listener_id is not None:
            target_id = local_listener_id
            target_listener = next(
                (
                    listener
                    for listener in listeners
                    if f"listener:{str(listener.get('protocol') or '').lower()}:{listener.get('local_address')}"
                    == local_listener_id
                ),
                None,
            )
            if target_listener is not None and isinstance(target_listener.get("pid"), int):
                target_process_id = _add_process_nodes(nodes, edges, target_listener)
                if local_listener_id not in nodes:
                    nodes[local_listener_id] = {
                        "id": local_listener_id,
                        "kind": "listener",
                        "label": target_listener.get("local_address"),
                        "protocol": protocol,
                        "address": target_listener.get("local_address"),
                        "port": peer_port,
                        "exposure_scope": target_listener.get("exposure_scope"),
                    }
                _add_edge(
                    edges,
                    target_process_id,
                    local_listener_id,
                    "LISTENS_ON",
                    "ss -H -lntupe",
                )
            if local_listener_id not in nodes:
                local_listener_id = None

        if local_listener_id is None:
            target_id = f"endpoint:{protocol}:{peer_endpoint}"
            nodes[target_id] = {
                "id": target_id,
                "kind": "remote_endpoint",
                "label": peer_endpoint,
                "protocol": protocol,
                "address": peer_endpoint,
                "port": peer_port,
                "scope": _address_scope(peer_host),
            }
        _add_edge(
            edges,
            process_id,
            target_id,
            "CONNECTS_TO",
            "ss -H -ntupe",
        )

    node_rows = sorted(nodes.values(), key=lambda item: (str(item["kind"]), str(item["id"])))
    edge_rows = sorted(edges.values(), key=lambda item: (item["relation"], item["source"], item["target"]))
    kind_counts: dict[str, int] = {}
    for node in node_rows:
        kind = str(node["kind"])
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
    external_dependencies = sum(
        node.get("kind") == "remote_endpoint" and node.get("scope") == "external"
        for node in node_rows
    )
    gaps: list[dict[str, Any]] = []
    if scoped_unattributed:
        gaps.append(
            {
                "code": "SOCKET_OWNER_UNAVAILABLE",
                "count": scoped_unattributed,
                "reason": "关注范围内存在无法从 ss 或 /proc 取得所属进程的套接字，连接影响不能完整确认。",
            }
        )
    if focus and not focus_process_ids:
        gaps.append(
            {
                "code": "FOCUS_PROCESS_UNRESOLVED",
                "count": len(focus),
                "reason": "关注端口没有可归属的监听进程。",
            }
        )
    return {
        "focus_ports": sorted(focus),
        "focus_units": sorted(unit_focus),
        "focus_process_ids": sorted(focus_process_ids),
        "focus_unit_process_ids": sorted(focus_unit_process_ids),
        "node_count": len(node_rows),
        "edge_count": len(edge_rows),
        "service_count": kind_counts.get("service", 0),
        "process_count": kind_counts.get("process", 0),
        "listener_count": kind_counts.get("listener", 0),
        "connection_relation_count": sum(
            edge["relation"] == "CONNECTS_TO" for edge in edge_rows
        ),
        "external_endpoint_count": external_dependencies,
        "unattributed_socket_count": unattributed,
        "scoped_unattributed_socket_count": scoped_unattributed,
        "nodes": node_rows,
        "edges": edge_rows,
        "evidence_gaps": gaps,
    }


def _unattributed_row_affects_scope(
    item: dict[str, Any],
    *,
    focus_ports: set[int],
    focus_units: set[str],
    is_listener: bool,
) -> bool:
    if not focus_ports and not focus_units:
        return True
    if not focus_ports:
        # A unit-scoped query cannot safely attribute an ownerless global socket
        # to the target unit. Keep the global count for operator visibility, but
        # do not let unrelated host noise invalidate the target impact contract.
        return False
    local_port = _endpoint_port(str(item.get("local_address") or ""))
    if local_port in focus_ports:
        return True
    if is_listener:
        return False
    peer_port = _endpoint_port(str(item.get("peer_address") or ""))
    return peer_port in focus_ports


def build_topology_tool_definitions() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="service_dependency_snapshot",
            version="1.1.0",
            description=(
                "Build a bounded, point-in-time relationship graph from observed systemd "
                "dependencies, processes, listening sockets, and established connections. "
                "When a service change is named, report evidence-bounded propagation and "
                "client interruption impact without treating ordering edges as causal claims."
            ),
            risk_level=RiskLevel.R0,
            input_model=ServiceDependencySnapshotInput,
            output_model=ToolResult,
            handler=service_dependency_snapshot,
            capability_requirements=("command.ss", "command.systemctl", "kernel.procfs"),
        )
    ]


def _merge_relationship_graph(
    observation: dict[str, Any],
    addition: dict[str, Any],
) -> None:
    nodes = {
        str(item["id"]): item
        for item in observation.get("nodes", [])
        if isinstance(item, dict) and item.get("id")
    }
    for item in addition.get("nodes", []):
        if not isinstance(item, dict) or not item.get("id"):
            continue
        node_id = str(item["id"])
        nodes[node_id] = {**nodes.get(node_id, {}), **item}

    edges = {
        (str(item["source"]), str(item["target"]), str(item["relation"])): item
        for item in observation.get("edges", [])
        if isinstance(item, dict)
        and item.get("source")
        and item.get("target")
        and item.get("relation")
    }
    for item in addition.get("edges", []):
        if not isinstance(item, dict):
            continue
        key = (
            str(item.get("source") or ""),
            str(item.get("target") or ""),
            str(item.get("relation") or ""),
        )
        if all(key):
            edges.setdefault(key, item)

    node_rows = sorted(nodes.values(), key=lambda item: (str(item["kind"]), str(item["id"])))
    edge_rows = sorted(edges.values(), key=lambda item: (item["relation"], item["source"], item["target"]))
    kind_counts: dict[str, int] = {}
    for node in node_rows:
        kind = str(node["kind"])
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
    observation.update(
        {
            "nodes": node_rows,
            "edges": edge_rows,
            "node_count": len(node_rows),
            "edge_count": len(edge_rows),
            "service_count": kind_counts.get("service", 0),
            "systemd_unit_count": kind_counts.get("systemd_unit", 0),
            "process_count": kind_counts.get("process", 0),
            "listener_count": kind_counts.get("listener", 0),
            "connection_relation_count": sum(
                edge["relation"] == "CONNECTS_TO" for edge in edge_rows
            ),
            "external_endpoint_count": sum(
                node.get("kind") == "remote_endpoint" and node.get("scope") == "external"
                for node in node_rows
            ),
            "evidence_gaps": [
                *observation.get("evidence_gaps", []),
                *addition.get("evidence_gaps", []),
            ],
        }
    )


def _run_ss(command: list[str]) -> subprocess.CompletedProcess[str] | None:
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


def _parse_rows(lines: list[str]) -> list[dict[str, Any]]:
    return [row for line in lines if (row := parse_network_listener_line(line)) is not None]


def _enrich_owner(
    item: dict[str, Any],
    owners: dict[int, dict[str, Any]],
    proc_root: Path,
) -> None:
    inode = item.get("socket_inode")
    if item.get("pid") is None and isinstance(inode, int) and inode in owners:
        item.update(owners[inode])
        item["attribution_source"] = "procfs"
    pid = item.get("pid")
    if not isinstance(pid, int):
        return
    if not item.get("process_name"):
        try:
            item["process_name"] = (proc_root / str(pid) / "comm").read_text(
                encoding="utf-8",
                errors="replace",
            ).strip() or None
        except OSError:
            item["process_name"] = None
    if not isinstance(item.get("uid"), int):
        uid = read_process_uid(proc_root / str(pid) / "status")
        item["uid"] = uid
        item["user"] = username(uid)
    if not item.get("systemd_unit"):
        unit, container_hint = read_process_cgroup_identity(pid, proc_root=proc_root)
        item["systemd_unit"] = unit
        item["container_hint"] = container_hint


def _add_process_nodes(
    nodes: dict[str, dict[str, Any]],
    edges: dict[tuple[str, str, str], dict[str, Any]],
    item: dict[str, Any],
) -> str:
    pid = int(item["pid"])
    process_id = f"process:{pid}"
    process_name = item.get("process_name") or item.get("process") or f"PID {pid}"
    nodes[process_id] = {
        "id": process_id,
        "kind": "process",
        "label": process_name,
        "pid": pid,
        "user": item.get("user"),
        "systemd_unit": item.get("systemd_unit"),
        "container_hint": item.get("container_hint"),
        "attribution_source": item.get("attribution_source"),
    }
    unit = item.get("systemd_unit")
    if isinstance(unit, str) and unit:
        service_id = f"service:{unit}"
        nodes[service_id] = {
            "id": service_id,
            "kind": "service",
            "label": unit,
            "unit": unit,
        }
        _add_edge(edges, service_id, process_id, "RUNS_PROCESS", f"/proc/{pid}/cgroup")
    return process_id


def _add_edge(
    edges: dict[tuple[str, str, str], dict[str, Any]],
    source: str,
    target: str,
    relation: str,
    evidence_ref: str,
) -> None:
    key = (source, target, relation)
    edge = edges.get(key)
    if edge is None:
        edges[key] = {
            "source": source,
            "target": target,
            "relation": relation,
            "observation_count": 1,
            "evidence_ref": evidence_ref,
        }
    elif relation == "CONNECTS_TO":
        edge["observation_count"] = int(edge["observation_count"]) + 1


def _endpoint_port(value: str) -> int | None:
    return _endpoint_parts(value)[1]


def _endpoint_parts(value: str) -> tuple[str, int | None]:
    endpoint = value.strip()
    if endpoint.startswith("[") and "]:" in endpoint:
        host, raw_port = endpoint[1:].rsplit("]:", 1)
    elif ":" in endpoint:
        host, raw_port = endpoint.rsplit(":", 1)
    else:
        return endpoint, None
    try:
        return host, int(raw_port)
    except ValueError:
        return host, None


def _address_scope(value: str) -> str:
    host = value.strip().strip("[]").split("%", 1)[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_private or address.is_link_local:
        return "private"
    if address.is_unspecified:
        return "unspecified"
    return "external"
