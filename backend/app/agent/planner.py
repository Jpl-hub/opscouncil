from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any
from urllib.parse import urlsplit

from backend.app.agent.health_contract import GENERAL_HEALTH_EVIDENCE_CONTRACT
from backend.app.agent.intent import IntentDecision


@dataclass(frozen=True)
class PlannedToolCall:
    tool_name: str
    arguments: dict[str, Any]
    reason: str


@dataclass(frozen=True)
class Plan:
    intent: str
    tool_calls: list[PlannedToolCall]
    rationale: str


class Planner:
    def create_plan(self, decision: IntentDecision, *, user_input: str = "") -> Plan:
        if decision.intent == "agent_capability_help":
            return Plan(decision.intent, [], "模型识别为能力咨询，不需要调用 MCP 工具。")

        calls: list[PlannedToolCall] = [
            PlannedToolCall(
                "platform_capability_profile",
                {},
                "确认当前 Linux 主机的架构、内核接口与工具可用性。",
            ),
            PlannedToolCall("system_snapshot", {}, "建立主机基础上下文。")
        ]

        if decision.intent == "disk_pressure_analysis":
            calls.append(
                PlannedToolCall("disk_usage", {"paths": ["/", "/tmp", "/var"]}, "确认磁盘压力。")
            )
            calls.append(
                PlannedToolCall(
                    "deleted_open_files",
                    {
                        "limit": 30,
                        "min_size_mb": 1,
                        "max_processes": 8192,
                        "max_fd_scan": 50000,
                    },
                    "检查文件虽已删除但仍被进程持有、空间未释放的情况。",
                )
            )
            return Plan(
                decision.intent,
                calls,
                "模型识别为磁盘空间分析，先采集容量并核对已删除未释放文件。",
            )

        if decision.intent == "network_exposure_analysis":
            calls.append(PlannedToolCall("network_listeners", {"limit": 80}, "检查 TCP/UDP 监听端口和进程归属。"))
            calls.append(
                PlannedToolCall(
                    "service_catalog_snapshot",
                    {},
                    "读取经审批的服务责任方与监听范围，核对业务必要性。",
                )
            )
            target_port = _explicit_port(user_input)
            if target_port is not None:
                protocols = _explicit_protocols(user_input) or ("tcp", "udp")
                for protocol in protocols:
                    calls.append(
                        PlannedToolCall(
                            "socket_process_context",
                            {
                                "protocol": protocol,
                                "port": target_port,
                                "max_matches": 20,
                            },
                            f"精确核验 {protocol.upper()}/{target_port} 的监听状态、进程和服务归属。",
                        )
                    )
                return Plan(
                    decision.intent,
                    calls,
                    "请求明确指定端口；控制器执行精确套接字核验，全机监听清单仅作同期对照，不能替代目标结论。",
                )
            return Plan(
                decision.intent,
                calls,
                "模型识别为网络暴露分析，联合核对实际监听和经审批服务目录。",
            )

        if decision.intent == "process_health_analysis":
            calls.append(
                PlannedToolCall("process_list", {"limit": 30}, "检查进程状态和僵尸进程。")
            )
            target_pid = _explicit_pid(user_input)
            if target_pid is not None:
                calls.append(
                    PlannedToolCall(
                        "process_runtime_detail",
                        {"pid": target_pid, "max_fd_scan": 20000},
                        "核验用户明确指定 PID 的存活状态、资源上限、文件句柄和服务归属。",
                    )
                )
                return Plan(
                    decision.intent,
                    calls,
                    "请求明确指定进程号；控制器执行精确 PID 核验，全机进程列表仅作同期对照，不能替代目标结论。",
                )
            if _requests_file_handle_analysis(user_input):
                calls.append(
                    PlannedToolCall(
                        "process_file_handles",
                        {"limit": 50, "sample_per_process": 5},
                        "用户明确询问文件句柄，按相对软上限采集进程句柄压力。",
                    )
                )
                return Plan(
                    decision.intent,
                    calls,
                    "模型识别为进程健康分析；请求明确涉及文件句柄，基础计划必须覆盖句柄数量与软上限证据。",
                )
            return Plan(decision.intent, calls, "模型识别为进程健康分析，先采集进程状态。")

        if decision.intent == "config_integrity_analysis":
            paths = _explicit_config_paths(user_input)
            for slot_name in ("paths", "target_files", "files"):
                requested_paths = decision.slots.get(slot_name)
                if isinstance(requested_paths, list):
                    paths.extend(
                        item
                        for item in requested_paths
                        if isinstance(item, str)
                        and (not user_input or item in user_input)
                    )
            service = _first_string_slot(decision.slots, "service", "target_service", "unit")
            if (
                isinstance(service, str)
                and "ssh" in service.lower()
                and (not user_input or "ssh" in user_input.lower())
            ):
                paths.append("/etc/ssh/sshd_config")
            paths = list(dict.fromkeys(paths))[:20]
            if not paths:
                paths = ["/etc/hosts", "/etc/resolv.conf", "/etc/fstab"]
            live_paths = [path for path in paths if not _is_lab_path(path)]
            lab_paths = [path for path in paths if _is_lab_path(path)]
            for scope, scoped_paths in (("LIVE", live_paths), ("LAB", lab_paths)):
                if not scoped_paths:
                    continue
                calls.append(
                    PlannedToolCall(
                        "config_baseline_check",
                        {"paths": scoped_paths, "scope": scope},
                        (
                            "在隔离靶场作用域内比较已确认配置基线，不读取配置正文。"
                            if scope == "LAB"
                            else "比较已确认生产配置基线与当前权限、属主、时间戳和哈希，不读取配置正文。"
                        ),
                    )
                )
            return Plan(
                decision.intent,
                calls,
                "模型识别为配置完整性分析；控制器按 LIVE/LAB 作用域调用只读基线比较，禁止靶场样本污染生产判断。",
            )

        if decision.intent == "log_analysis":
            unit = _first_string_slot(
                decision.slots,
                "unit",
                "service",
                "service_name",
                "target_service",
            )
            if unit:
                calls.append(
                    PlannedToolCall("service_status", {"unit": unit}, "检查指定服务状态。")
                )
                if _requests_service_restart(user_input):
                    calls.append(
                        PlannedToolCall(
                            "service_desired_state",
                            {"unit": unit},
                            "核对目标服务经审批的责任方、重要级别和期望运行状态。",
                        )
                    )
                    calls.append(
                        PlannedToolCall(
                            "service_dependency_snapshot",
                            {
                                "focus_units": [unit],
                                "change_action": "restart",
                                "max_listeners": 160,
                                "max_connections": 320,
                                "max_systemd_relations": 160,
                            },
                            "采集目标服务的 systemd 依赖、运行进程和连接关系，并在重启前评估影响范围。",
                        )
                    )
            else:
                calls.append(
                    PlannedToolCall("journal_query", {"lines": 80, "unit": None}, "读取近期系统日志。")
                )
            return Plan(decision.intent, calls, "模型识别为日志服务排查，先采集首要服务证据。")

        if decision.intent == "service_degradation_analysis":
            health_url = _first_explicit_http_url(user_input)
            if health_url:
                focus_port = _http_url_port(health_url)
                calls.append(
                    PlannedToolCall(
                        "service_health_probe",
                        {"url": health_url},
                        "复现用户报告的本机服务症状并记录状态码与延迟。",
                    )
                )
                calls.append(
                    PlannedToolCall(
                        "service_dependency_snapshot",
                        {
                            "focus_ports": [focus_port] if focus_port is not None else [],
                            "max_listeners": 200,
                            "max_connections": 400,
                        },
                        "从健康端点对应进程出发，采集当时实际存在的监听与已建立连接，并记录归属缺口。",
                    )
                )
                return Plan(
                    decision.intent,
                    calls,
                    "模型识别为服务退化，先复现明确给出的本机健康端点，再采集可核验的进程与连接关系，后续按日志和反证追查根因。",
                )
            calls.append(
                PlannedToolCall(
                    "service_dependency_snapshot",
                    {
                        "focus_ports": [],
                        "max_listeners": 80,
                        "max_connections": 160,
                    },
                    "用户未提供健康端点，仅采集本机可观测的服务、监听和已建立连接，不主动探测未知接口。",
                )
            )
            return Plan(
                decision.intent,
                calls,
                "模型识别为服务退化，但缺少明确端点；先建立当次服务关系快照并保留目标缺口。",
            )

        calls = [
            PlannedToolCall(
                requirement.tool_name,
                dict(requirement.arguments),
                requirement.reason,
            )
            for requirement in GENERAL_HEALTH_EVIDENCE_CONTRACT
        ]
        return Plan(
            "general_system_health",
            calls,
            "模型识别为通用健康巡检，按最低证据契约核验资源、磁盘、进程、网络、服务和时间状态。",
        )


def _first_string_slot(slots: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = slots.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _requests_file_handle_analysis(user_input: str) -> bool:
    normalized = user_input.lower()
    return bool(
        any(
            term in normalized
            for term in ("文件句柄", "文件描述符", "打开文件数", "open files", "nofile")
        )
        or re.search(r"(?<![a-z0-9_])fd(?![a-z0-9_])", normalized)
    )


def _explicit_pid(user_input: str) -> int | None:
    match = re.search(
        r"(?i)(?:\bpid\b|进程号)\s*[=:：#]?\s*(\d{1,7})\b",
        user_input,
    )
    if match is None:
        return None
    pid = int(match.group(1))
    return pid if 1 <= pid <= 4_194_304 else None


def _explicit_port(user_input: str) -> int | None:
    patterns = (
        r"(?i)(?:tcp|udp)?\s*端口\s*[:：]?\s*(\d{1,5})\b",
        r"(?i)\b(\d{1,5})\s*端口\b",
        r"(?<!\d):(\d{1,5})\b",
        r"(?i)\b(?:tcp|udp)\s*/\s*(\d{1,5})\b",
    )
    for pattern in patterns:
        match = re.search(pattern, user_input)
        if match is None:
            continue
        port = int(match.group(1))
        if 1 <= port <= 65_535:
            return port
    return None


def _explicit_protocols(user_input: str) -> tuple[str, ...]:
    normalized = user_input.lower()
    return tuple(protocol for protocol in ("tcp", "udp") if protocol in normalized)


def _requests_service_restart(user_input: str) -> bool:
    normalized = user_input.lower()
    return any(
        term in normalized
        for term in ("重启", "restart", "重新启动", "拉起服务")
    )


def _explicit_config_paths(user_input: str) -> list[str]:
    paths: list[str] = []
    for match in re.finditer(r"(?<![A-Za-z0-9_.-])(/[A-Za-z0-9_./@:+-]+)", user_input):
        candidate = match.group(1).rstrip(".,;:，。；：、)]}）】")
        if candidate:
            paths.append(candidate)
    return list(dict.fromkeys(paths))


def _is_lab_path(path: str) -> bool:
    return path == "/tmp/opscouncil-lab" or path.startswith("/tmp/opscouncil-lab/")


def _first_explicit_http_url(user_input: str) -> str | None:
    for raw_token in user_input.split():
        candidate = raw_token.rstrip("，。；;、)]}）\"'")
        if not candidate.startswith("http://"):
            continue
        parsed = urlsplit(candidate)
        if parsed.hostname in {"127.0.0.1", "localhost", "::1"} and parsed.path:
            return candidate
    return None


def _http_url_port(url: str) -> int | None:
    try:
        parsed = urlsplit(url)
        return parsed.port or (80 if parsed.scheme == "http" else None)
    except ValueError:
        return None
