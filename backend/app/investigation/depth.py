from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


InvestigationDepth = Literal["DIRECT_EVIDENCE", "ITERATIVE_RCA"]

_ALWAYS_ITERATIVE = frozenset(
    {
        "general_system_health",
        "log_analysis",
        "service_degradation_analysis",
    }
)
_ALWAYS_DIRECT = frozenset({"config_integrity_analysis"})
_DISK_INVESTIGATION_MARKERS = (
    "占满",
    "空间不足",
    "异常",
    "来源不明",
    "持续增长",
)
_RCA_MARKERS = (
    "根因",
    "调查根因",
    "根本原因",
    "为什么",
    "为何",
    "原因是什么",
    "故障原因",
    "异常原因",
    "退化原因",
    "因果",
    "反证",
)
_SERVICE_CHANGE_MARKERS = (
    "重启",
    "restart",
    "停止",
    "stop",
    "重新加载",
    "reload",
)
_CHANGE_PREVIEW_MARKERS = (
    "预演",
    "dry-run",
    "影响范围",
    "执行前条件",
    "回滚方案",
    "审批方案",
    "未经审批",
    "不要自动执行",
)


@dataclass(frozen=True)
class InvestigationDepthDecision:
    mode: InvestigationDepth
    reason: str


def select_investigation_depth(
    intent: str,
    user_input: str,
) -> InvestigationDepthDecision:
    if intent in _ALWAYS_DIRECT:
        return InvestigationDepthDecision(
            mode="DIRECT_EVIDENCE",
            reason="配置漂移由已确认基线与当前哈希、权限和属主直接比较，不重复调用模型猜测。",
        )
    if any(marker in user_input for marker in _RCA_MARKERS):
        return InvestigationDepthDecision(
            mode="ITERATIVE_RCA",
            reason="用户明确要求调查根因或因果关系，进入受预算约束的多轮研判。",
        )
    normalized = user_input.casefold()
    if (
        ".service" in normalized
        and any(marker in normalized for marker in _SERVICE_CHANGE_MARKERS)
        and any(marker in normalized for marker in _CHANGE_PREVIEW_MARKERS)
    ):
        return InvestigationDepthDecision(
            mode="DIRECT_EVIDENCE",
            reason="该任务是 systemd 变更预演，由实时关系、连接和服务目录直接计算影响，不虚构根因候选。",
        )
    if intent in _ALWAYS_ITERATIVE:
        return InvestigationDepthDecision(
            mode="ITERATIVE_RCA",
            reason="该任务涉及故障、服务日志或整机异常，需要多假设调查与反证。",
        )
    if intent == "disk_pressure_analysis" and any(
        marker in user_input for marker in _DISK_INVESTIGATION_MARKERS
    ):
        return InvestigationDepthDecision(
            mode="ITERATIVE_RCA",
            reason="用户要求定位磁盘占用来源或评估处置，需要在容量证据后继续核验文件与日志归属。",
        )
    return InvestigationDepthDecision(
        mode="DIRECT_EVIDENCE",
        reason="当前请求可由确定性系统观测直接回答，无需启动多轮根因调查。",
    )
