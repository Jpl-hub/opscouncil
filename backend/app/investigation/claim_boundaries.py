from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


_SERVICE_INTENT_OVERCLAIM_RE = re.compile(
    r"(?:符合预期|预期(?:行为|设计|失败|状态)|人为构造|"
    r"(?:测试|演练|占位|fixture|lab)(?:服务|单元|用途|意图|用例|行为|状态)|"
    r"无需(?:修复|重启|处理)|不构成[^。；]{0,24}(?:稳定性|安全)风险|"
    r"排除(?:于|出)[^。；]{0,20}告警)",
    re.IGNORECASE,
)

_DESIRED_STATE_SOURCE_KEYS = {
    "asset_inventory",
    "service_desired_state",
    "service_policy_baseline",
}


@dataclass(frozen=True)
class FailedServiceContext:
    unit: str
    exec_start_path: str | None
    exec_main_status: int | None
    result: str | None


@dataclass(frozen=True)
class ServiceDesiredStateContext:
    unit: str
    expected_active_state: str
    service_owner: str
    criticality: str
    environment: str
    source_ref: str
    approved_by: str
    version: int


@dataclass(frozen=True)
class BoundedServiceClaim:
    title: str
    rationale: str
    evidence_gap: str
    conclusion: str
    reasoning_summary: str
    action_title: str
    action_rationale: str
    residual_risk: str
    stop_reason: str


def claims_unproven_service_intent(value: str) -> bool:
    return bool(_SERVICE_INTENT_OVERCLAIM_RE.search(value))


def has_service_desired_state_evidence(
    evidence_items: list[Any],
    *,
    unit: str | None = None,
) -> bool:
    return service_desired_state_context(evidence_items, unit=unit) is not None


def service_desired_state_context(
    evidence_items: list[Any],
    *,
    unit: str | None = None,
) -> ServiceDesiredStateContext | None:
    for item in evidence_items:
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        if str(getattr(item, "source_type", "")).upper() == "KNOWLEDGE":
            continue
        if str(getattr(item, "source_key", "")) not in _DESIRED_STATE_SOURCE_KEYS:
            continue
        payload = getattr(item, "payload_json", {})
        if not isinstance(payload, dict):
            continue
        record_unit = payload.get("unit")
        expected_state = payload.get("expected_active_state") or payload.get("expected_state")
        owner = payload.get("service_owner") or payload.get("owner")
        source_ref = payload.get("source_ref")
        approved_by = payload.get("approved_by")
        version = payload.get("version")
        if unit is not None and record_unit != unit:
            continue
        if not isinstance(record_unit, str) or not record_unit.endswith(".service"):
            continue
        if expected_state not in {"active", "inactive"}:
            continue
        if str(payload.get("record_status") or "").upper() != "ACTIVE":
            continue
        if not all(isinstance(value, str) and value.strip() for value in (owner, source_ref, approved_by)):
            continue
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            continue
        return ServiceDesiredStateContext(
            unit=record_unit,
            expected_active_state=expected_state,
            service_owner=owner.strip(),
            criticality=str(payload.get("criticality") or "UNKNOWN").upper(),
            environment=str(payload.get("environment") or "UNKNOWN").upper(),
            source_ref=source_ref.strip(),
            approved_by=approved_by.strip(),
            version=version,
        )
    return None


def failed_service_context(evidence_items: list[Any]) -> FailedServiceContext | None:
    fallback: FailedServiceContext | None = None
    for item in evidence_items:
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        if str(getattr(item, "source_key", "")) != "service_status":
            continue
        payload = getattr(item, "payload_json", {})
        if not isinstance(payload, dict):
            continue
        state = str(
            payload.get("active_state")
            or payload.get("ActiveState")
            or payload.get("active")
            or ""
        ).lower()
        if state != "failed":
            continue
        unit = payload.get("unit") or payload.get("Id")
        if not isinstance(unit, str) or not unit:
            continue
        status = payload.get("exec_main_status", payload.get("ExecMainStatus"))
        context = FailedServiceContext(
            unit=unit,
            exec_start_path=_optional_text(
                payload.get("exec_start_path") or payload.get("ExecStart")
            ),
            exec_main_status=(
                int(status)
                if isinstance(status, int) and not isinstance(status, bool)
                else None
            ),
            result=_optional_text(payload.get("result") or payload.get("Result")),
        )
        if context.exec_start_path is not None:
            return context
        fallback = fallback or context
    return fallback


def failed_service_mechanism(context: FailedServiceContext) -> str:
    detail = f"{context.unit} 处于 failed 状态"
    if context.exec_start_path:
        detail += f"，启动入口为 {context.exec_start_path}"
    if context.exec_main_status is not None:
        detail += f"，主进程以状态 {context.exec_main_status} 退出"
    if context.result:
        detail += f"（{context.result}）"
    return f"{detail}；这些证据定位了直接失败机制，但不证明该失败符合预期。"


def bounded_service_claim(
    context: FailedServiceContext,
    desired: ServiceDesiredStateContext | None,
) -> BoundedServiceClaim:
    mechanism = failed_service_mechanism(context)
    if desired is None:
        return BoundedServiceClaim(
            title=f"{context.unit} 启动失败，预期运行状态待确认",
            rationale=mechanism,
            evidence_gap=(
                "缺少资产归属或服务期望状态证据，不能仅凭单元名称、"
                "描述或启动命令判断该失败是否符合预期。"
            ),
            conclusion=(
                f"{context.unit} 当前启动失败；已定位直接失败机制，"
                "但尚未确认该单元在当前主机上的期望状态。"
            ),
            reasoning_summary=(
                "服务状态、单元启动上下文与系统日志相互印证；"
                "单元名称和描述不作为资产期望状态证据。"
            ),
            action_title="确认服务期望状态",
            action_rationale=(
                f"先确认 {context.unit} 的资产归属与应运行状态，"
                "再决定是否修复、重启、停用或调整告警。"
            ),
            residual_risk=(
                "当前缺少资产归属和期望状态证据，不能判断该失败是否应被保留或处置。"
            ),
            stop_reason="服务失败机制已有系统证据；单元期望状态仍需资产归属证据确认。",
        )

    expected_label = "运行" if desired.expected_active_state == "active" else "停止"
    action_title = "联系责任方恢复服务" if desired.expected_active_state == "active" else "联系责任方清理失败状态"
    return BoundedServiceClaim(
        title=f"{context.unit} 启动失败，与登记状态不一致",
        rationale=(
            f"{mechanism} 服务目录 v{desired.version} 登记该单元应处于{expected_label}状态，"
            f"责任方为 {desired.service_owner}。"
        ),
        evidence_gap="已取得经审批期望状态；尚需由责任方确认处置窗口和更深层故障原因。",
        conclusion=(
            f"{context.unit} 当前为 failed，服务目录登记的期望状态为 "
            f"{desired.expected_active_state}，两者不一致。"
        ),
        reasoning_summary=(
            f"系统证据确认启动失败；服务目录 v{desired.version}（{desired.source_ref}）"
            f"确认责任方 {desired.service_owner} 和期望状态 {desired.expected_active_state}。"
        ),
        action_title=action_title,
        action_rationale=(
            f"由 {desired.service_owner} 核对故障原因并确认处置窗口；"
            "任何服务或配置变更仍须进入审批。"
        ),
        residual_risk=(
            f"当前状态偏离 {desired.environment} 环境的服务目录记录，"
            f"重要级别为 {desired.criticality}；处置完成前保留事件跟踪。"
        ),
        stop_reason="服务失败机制和经审批期望状态均已取得；后续变更需责任方确认与审批。",
    )


def _optional_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None
