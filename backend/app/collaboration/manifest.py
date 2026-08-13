from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AgentIdentity:
    role: str
    display_name: str
    agent_name: str
    skill_id: str
    responsibility: str
    allowed_work: tuple[str, ...]
    denied_work: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["allowed_work"] = list(self.allowed_work)
        payload["denied_work"] = list(self.denied_work)
        return payload


TEAM_NAME = "opscouncil-response"
TEAM_VERSION = "1.0.0"

IDENTITIES = (
    AgentIdentity(
        role="incident_commander",
        display_name="事件指挥 Agent",
        agent_name="incident-commander",
        skill_id="incident-command",
        responsibility="维护事件目标、依赖图和终止条件，只协调，不代替专业角色下结论。",
        allowed_work=("coordinate", "learn"),
        denied_work=("execute", "verify_own_plan"),
    ),
    AgentIdentity(
        role="signal_correlator",
        display_name="信号归并 Agent",
        agent_name="signal-correlator",
        skill_id="signal-fusion",
        responsibility="归并同源告警、保留原始证据并形成事件边界。",
        allowed_work=("triage",),
        denied_work=("plan", "execute", "verify"),
    ),
    AgentIdentity(
        role="rca_investigator",
        display_name="因果调查 Agent",
        agent_name="rca-investigator",
        skill_id="causal-investigation",
        responsibility="提出可证伪假设，收集支持证据和反证，给出证据充分度。",
        allowed_work=("investigate",),
        denied_work=("execute", "approve", "verify"),
    ),
    AgentIdentity(
        role="remediation_planner",
        display_name="处置规划 Agent",
        agent_name="remediation-planner",
        skill_id="bounded-remediation",
        responsibility="把诊断转为带前置条件、影响范围、回滚和后置条件的动作契约。",
        allowed_work=("plan",),
        denied_work=("execute", "verify"),
    ),
    AgentIdentity(
        role="recovery_verifier",
        display_name="恢复验证 Agent",
        agent_name="recovery-verifier",
        skill_id="independent-recovery-verification",
        responsibility="使用独立证据验证服务恢复、回归风险和业务健康，不接受执行结果自证。",
        allowed_work=("verify",),
        denied_work=("plan", "execute", "approve"),
    ),
)

TEAM_MANIFEST = {
    "name": TEAM_NAME,
    "version": TEAM_VERSION,
    "orchestration": "AgentTeams",
    "leader": "incident-commander",
    "workers": [item.to_dict() for item in IDENTITIES if item.role != "incident_commander"],
    "identity_count": len(IDENTITIES),
    "context": {
        "shared_state": "versioned incident collaboration context",
        "memory": "qualified operational memory",
        "retrieval": "PostgreSQL + pgvector evidence retrieval",
        "trajectory": "hash-linked collaboration and tool events",
    },
}

ROLE_BY_WORK_KEY = {
    "triage": "signal_correlator",
    "investigate": "rca_investigator",
    "plan": "remediation_planner",
    "execute": "policy_controller",
    "verify": "recovery_verifier",
    "learn": "incident_commander",
}

AGENT_NAME_BY_ROLE = {
    item.role: item.agent_name
    for item in IDENTITIES
}


AGENT_TOOL_SCOPES: dict[str, frozenset[str]] = {
    "signal-correlator": frozenset(
        {
            "platform_capability_profile",
            "system_snapshot",
            "disk_usage",
            "process_list",
            "network_listeners",
            "service_catalog_snapshot",
        }
    ),
    "rca-investigator": frozenset(
        {
            "platform_capability_profile",
            "system_snapshot",
            "disk_usage",
            "process_list",
            "journal_query",
            "network_listeners",
            "service_dependency_snapshot",
            "process_file_handles",
            "service_status",
            "find_large_files",
            "config_integrity_scan",
            "config_baseline_check",
            "file_integrity_state",
            "process_runtime_detail",
            "journal_storage_status",
            "deleted_open_files",
            "socket_process_context",
            "filesystem_mount_context",
            "time_sync_status",
            "service_health_probe",
            "application_log_query",
            "service_desired_state",
            "service_catalog_snapshot",
        }
    ),
    "remediation-planner": frozenset(
        {
            "platform_capability_profile",
            "system_snapshot",
            "service_dependency_snapshot",
            "service_status",
            "service_health_probe",
            "config_integrity_scan",
            "config_baseline_check",
            "service_desired_state",
            "safe_log_rotate",
            "restore_log_backup",
            "restart_managed_service",
            "restore_config_mode",
        }
    ),
    "recovery-verifier": frozenset(
        {
            "system_snapshot",
            "disk_usage",
            "process_list",
            "journal_query",
            "network_listeners",
            "service_dependency_snapshot",
            "service_status",
            "config_integrity_scan",
            "config_baseline_check",
            "file_integrity_state",
            "process_runtime_detail",
            "journal_storage_status",
            "deleted_open_files",
            "socket_process_context",
            "filesystem_mount_context",
            "time_sync_status",
            "service_health_probe",
            "application_log_query",
            "service_desired_state",
        }
    ),
}
