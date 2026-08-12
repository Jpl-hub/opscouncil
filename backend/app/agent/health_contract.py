from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HealthEvidenceRequirement:
    key: str
    label: str
    tool_name: str
    arguments: dict[str, Any]
    reason: str
    required_for_complete_conclusion: bool = True


GENERAL_HEALTH_EVIDENCE_CONTRACT = (
    HealthEvidenceRequirement(
        key="platform",
        label="主机能力",
        tool_name="platform_capability_profile",
        arguments={},
        reason="确认当前 Linux 主机的架构、内核接口与工具可用性。",
        required_for_complete_conclusion=False,
    ),
    HealthEvidenceRequirement(
        key="host_resources",
        label="主机资源",
        tool_name="system_snapshot",
        arguments={},
        reason="采集负载、内存、运行时间和资源压力基础证据。",
    ),
    HealthEvidenceRequirement(
        key="filesystems",
        label="文件系统容量",
        tool_name="disk_usage",
        arguments={"paths": ["/", "/var/log", "/tmp"]},
        reason="核验根分区、日志目录和临时目录的容量与 inode 使用情况。",
    ),
    HealthEvidenceRequirement(
        key="processes",
        label="进程状态",
        tool_name="process_list",
        arguments={"limit": 30},
        reason="核验高负载进程与僵尸进程，避免把未采集误判为正常。",
    ),
    HealthEvidenceRequirement(
        key="listeners",
        label="网络监听",
        tool_name="network_listeners",
        arguments={"limit": 80},
        reason="核验监听端口、暴露范围与进程归属。",
    ),
    HealthEvidenceRequirement(
        key="services",
        label="失败服务",
        tool_name="service_status",
        arguments={"unit": None},
        reason="核验 systemd 失败服务，不能用进程存活替代服务状态证据。",
    ),
    HealthEvidenceRequirement(
        key="clock",
        label="时间同步",
        tool_name="time_sync_status",
        arguments={},
        reason="核验系统时间同步状态，保障日志、审计与事件关联的时间可信度。",
        required_for_complete_conclusion=False,
    ),
)


def general_health_core_requirements() -> tuple[HealthEvidenceRequirement, ...]:
    return tuple(
        item
        for item in GENERAL_HEALTH_EVIDENCE_CONTRACT
        if item.required_for_complete_conclusion
    )


def missing_general_health_evidence(
    evidence_items: list[Any],
) -> tuple[HealthEvidenceRequirement, ...]:
    successful_sources: set[str] = set()
    for item in evidence_items:
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        source_key = str(getattr(item, "source_key", ""))
        if not source_key:
            continue
        payload = getattr(item, "payload_json", {})
        payload = payload if isinstance(payload, dict) else {}
        status = str(payload.get("status") or "").lower()
        if status in {"error", "failed", "unavailable", "rejected", "blocked"}:
            continue
        successful_sources.add(source_key)
    return tuple(
        item
        for item in general_health_core_requirements()
        if item.tool_name not in successful_sources
    )
