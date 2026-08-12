from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from backend.app.agent.health_contract import missing_general_health_evidence
from backend.app.core.pydantic_compat import BaseModel, Field, ValidationError, field_validator
from backend.app.investigation.claim_boundaries import (
    bounded_service_claim,
    claims_unproven_service_intent,
    failed_service_context,
    service_desired_state_context,
)
from backend.app.schemas.enums import RiskLevel


class RecommendedAction(BaseModel):
    title: str
    rationale: str
    safety_gate: str
    tool_name: str | None = None

    @field_validator("title", "rationale", "safety_gate", mode="before")
    @classmethod
    def normalize_user_facing_text(cls, value: Any) -> str:
        return _humanize_tool_names(_stringify(value))


class AIAnalysisResult(BaseModel):
    conclusion: str
    root_cause: str
    risk_level: str = Field(pattern=r"^R[0-4]$")
    reasoning_summary: list[str] = Field(default_factory=list)
    counter_evidence: list[str] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    evidence_used: list[dict[str, str]] = Field(default_factory=list)
    residual_risk: str

    @field_validator("conclusion", "root_cause", "residual_risk", mode="before")
    @classmethod
    def normalize_required_text(cls, value: Any) -> str:
        return _humanize_tool_names(_stringify(value))[:800]

    @field_validator("risk_level", mode="before")
    @classmethod
    def normalize_risk_level(cls, value: Any) -> str:
        text = _stringify(value).upper()
        for level in ("R0", "R1", "R2", "R3", "R4"):
            if level in text:
                return level
        return text

    @field_validator("reasoning_summary", mode="before")
    @classmethod
    def normalize_reasoning_summary(cls, value: Any) -> list[str]:
        return [_humanize_tool_names(item) for item in _normalize_text_list(value)[:6]]

    @field_validator("counter_evidence", mode="before")
    @classmethod
    def normalize_counter_evidence(cls, value: Any) -> list[str]:
        return [_humanize_tool_names(item) for item in _normalize_text_list(value)[:4]]

    @field_validator("recommended_actions", mode="before")
    @classmethod
    def normalize_recommended_actions(cls, value: Any) -> list[dict[str, Any]]:
        if value is None:
            return []
        raw_items = value if isinstance(value, list) else [value]
        normalized: list[dict[str, Any]] = []
        for item in raw_items:
            if isinstance(item, dict):
                normalized.append({str(key): item_value for key, item_value in item.items()})
                continue
            text = _stringify(item)
            normalized.append(
                {
                    "title": "补充核查",
                    "rationale": text,
                    "safety_gate": "仅作为建议；实际动作需重新进入计划与安全校验。",
                    "tool_name": None,
                }
            )
        return normalized[:5]

    @field_validator("evidence_used", mode="before")
    @classmethod
    def normalize_evidence_used(cls, value: Any) -> list[dict[str, str]]:
        if value is None:
            return []
        raw_items = value if isinstance(value, list) else [value]
        normalized: list[dict[str, str]] = []
        for item in raw_items:
            if isinstance(item, str):
                normalized.append({"source": item, "summary": item})
                continue
            if isinstance(item, dict):
                normalized.append(
                    {str(key): _stringify(item_value) for key, item_value in item.items()}
                )
                continue
            text = _stringify(item)
            normalized.append({"source": text, "summary": text})
        return normalized[:8]


def ground_final_analysis(
    payload: dict[str, Any] | AIAnalysisResult,
    *,
    task_risk_level: str,
    evidence_items: list[Any],
    observed_tool_names: set[str],
    preferred_evidence_ids: list[int] | None = None,
    task_intent: str = "",
) -> AIAnalysisResult:
    if isinstance(payload, AIAnalysisResult):
        parsed = payload
    else:
        try:
            parsed = AIAnalysisResult.model_validate(_normalize_analysis_payload(payload))
        except ValidationError as exc:
            raise ValueError(f"model analysis schema validation failed: {exc}") from exc
    actions = [
        _enforce_action_policy(action, observed_tool_names)
        for action in parsed.recommended_actions
    ]
    grounded = parsed.model_copy(
        update={
            "risk_level": RiskLevel(task_risk_level).value,
            "recommended_actions": actions,
            "counter_evidence": _grounded_counter_evidence(
                parsed.counter_evidence,
                evidence_items,
            ),
            "evidence_used": _grounded_investigation_evidence(
                evidence_items,
                preferred_evidence_ids=preferred_evidence_ids,
            ),
        }
    )
    bounded = _enforce_config_drift_claim_boundary(grounded, evidence_items)
    bounded = _enforce_service_liveness_claim_boundary(bounded, evidence_items)
    bounded = _enforce_transient_connection_claim_boundary(bounded)
    bounded = _enforce_multi_source_support_boundary(bounded, evidence_items)
    bounded = _enforce_general_health_evidence_boundary(
        bounded,
        evidence_items,
        task_intent=task_intent,
    )
    bounded = _enforce_unproven_service_intent_boundary(bounded, evidence_items)
    bounded = _enforce_infrastructure_literal_boundary(bounded, evidence_items)
    return _enforce_absolute_residual_risk_boundary(
        bounded,
        task_risk_level=task_risk_level,
    )


_ABSOLUTE_NO_RISK_RE = re.compile(
    r"^\s*(?:无|没有|不存在)?(?:任何)?(?:残余|剩余)?(?:风险)?"
    r"(?:[:：]?\s*(?:无|没有|不存在))?[。.!！]?\s*$"
)


def _enforce_absolute_residual_risk_boundary(
    result: AIAnalysisResult,
    *,
    task_risk_level: str,
) -> AIAnalysisResult:
    residual = result.residual_risk.strip()
    if not (
        _ABSOLUTE_NO_RISK_RE.fullmatch(residual)
        or residual.startswith(("无残余风险", "无剩余风险"))
    ):
        return result
    boundary = (
        "系统变更尚未执行；审批后仍需执行前复核、执行后验证，并保留人工接管路径。"
        if task_risk_level in {"R2", "R3", "R4"}
        else "当前观测未发现新增风险，仍需关注未覆盖时间窗和未观测依赖。"
    )
    return result.model_copy(update={"residual_risk": boundary})


def _enforce_general_health_evidence_boundary(
    result: AIAnalysisResult,
    evidence_items: list[Any],
    *,
    task_intent: str,
) -> AIAnalysisResult:
    if task_intent != "general_system_health":
        return result
    missing = missing_general_health_evidence(evidence_items)
    if not missing:
        return result
    labels = "、".join(item.label for item in missing)
    boundary = f"{labels}尚无有效系统证据，不能据此断言整机健康。"
    residual_risk = result.residual_risk.rstrip("。")
    if boundary.rstrip("。") not in residual_risk:
        residual_risk = f"{residual_risk}；{boundary}".lstrip("；")
    return result.model_copy(
        update={
            "conclusion": f"本轮仅完成部分健康核验；{boundary}",
            "root_cause": "证据覆盖不足，暂不形成整机健康或异常根因结论。",
            "reasoning_summary": [boundary],
            "counter_evidence": [],
            "residual_risk": residual_risk,
        }
    )


def _enforce_unproven_service_intent_boundary(
    result: AIAnalysisResult,
    evidence_items: list[Any],
) -> AIAnalysisResult:
    context = failed_service_context(evidence_items)
    if context is None:
        return result
    desired = service_desired_state_context(evidence_items, unit=context.unit)
    analyzed_text = "\n".join(
        (
            result.conclusion,
            result.root_cause,
            result.residual_risk,
            *result.reasoning_summary,
            *(action.title for action in result.recommended_actions),
            *(action.rationale for action in result.recommended_actions),
        )
    )
    if not claims_unproven_service_intent(analyzed_text):
        return result

    boundary = bounded_service_claim(context, desired)
    return result.model_copy(
        update={
            "conclusion": boundary.conclusion,
            "root_cause": boundary.rationale,
            "reasoning_summary": [boundary.reasoning_summary],
            "counter_evidence": [],
            "recommended_actions": [
                RecommendedAction(
                    title=boundary.action_title,
                    rationale=boundary.action_rationale,
                    safety_gate=(
                        "只读核查可继续；任何服务或配置变更必须重新进入审批。"
                    ),
                    tool_name=None,
                )
            ],
            "residual_risk": boundary.residual_risk,
        }
    )


_CONFIG_DRIFT_EXCLUSION_PATTERNS = (
    re.compile(r"非[^。；]{0,32}配置(?:内容)?漂移(?:所致|导致|引起)?"),
    re.compile(r"配置(?:内容)?漂移(?:不成立|已排除|可排除|不是根因|并非根因)"),
    re.compile(r"排除[^。；]{0,16}配置(?:内容)?漂移"),
    re.compile(
        r"配置(?:完整性)?扫描[^。；]{0,20}(?:未发现|没有)"
        r"[^。；]{0,12}(?:变更|漂移)(?:痕迹|线索|迹象)?"
    ),
    re.compile(
        r"配置文件[^。；]{0,16}(?:未发现|没有)"
        r"[^。；]{0,12}(?:异常|变更|漂移)(?:摘要|痕迹|线索|迹象|元数据)?"
    ),
    re.compile(
        r"配置文件[^。；]{0,24}(?:无|未发现|没有)"
        r"[^。；]{0,20}异常(?:迹象|线索|痕迹|元数据)"
    ),
    re.compile(
        r"配置(?:完整性)?扫描[^。；]{0,40}(?:未发现|没有|无)"
        r"[^。；]{0,40}(?:权限|大小|哈希)[^。；]{0,20}异常(?:线索|痕迹)?"
    ),
    re.compile(r"不支持[^。；]{0,20}配置(?:内容)?漂移(?:假说|假设)?"),
    re.compile(r"(?:当前)?无(?:直接)?证据(?:表明|支持)[^。；]{0,20}配置(?:内容)?漂移"),
    re.compile(r"(?:当前)?无(?:直接)?证据(?:表明|支持)[^。；]{0,48}配置(?:内容)?异常"),
)
_CONFIG_DRIFT_BOUNDARY = (
    "现有证据不支持配置内容漂移，但缺少受信任历史基线，不能完全排除。"
)
_CONFIG_DRIFT_DETECTED_BOUNDARY = (
    "受信任配置基线与当前快照不一致，配置差异需要继续核查。"
)
_CONFIG_DRIFT_UNOBSERVED_BOUNDARY = (
    "尚未取得可比较的配置证据，无法判断是否存在配置内容漂移。"
)


def _enforce_config_drift_claim_boundary(
    result: AIAnalysisResult,
    evidence_items: list[Any],
) -> AIAnalysisResult:
    analyzed_text = "\n".join(
        (
            result.conclusion,
            result.root_cause,
            *result.reasoning_summary,
            *result.counter_evidence,
        )
    )
    baseline_status = _trusted_config_baseline_status(evidence_items)
    if not _claims_config_drift_excluded(analyzed_text) or baseline_status == "clean":
        return result
    has_current_config = _has_current_config_observation(evidence_items)
    boundary = (
        _CONFIG_DRIFT_DETECTED_BOUNDARY
        if baseline_status == "drifted"
        else (
            _CONFIG_DRIFT_BOUNDARY
            if has_current_config
            else _CONFIG_DRIFT_UNOBSERVED_BOUNDARY
        )
    )

    conclusion = _remove_config_drift_exclusion(result.conclusion)
    root_cause = _remove_config_drift_exclusion(result.root_cause)
    reasoning = [
        cleaned
        for item in result.reasoning_summary
        if (cleaned := _remove_config_drift_exclusion(item))
    ]
    reasoning.append(boundary)
    counter_evidence = [
        cleaned
        for item in result.counter_evidence
        if (cleaned := _remove_config_drift_exclusion(item))
    ]
    if baseline_status is None and has_current_config and not any(
        _CONFIG_DRIFT_BOUNDARY in item for item in counter_evidence
    ):
        counter_evidence.append(_CONFIG_DRIFT_BOUNDARY)
    residual_risk = result.residual_risk.rstrip("。")
    if boundary.rstrip("。") not in residual_risk:
        residual_risk = f"{residual_risk}；{boundary}".lstrip("；")
    return result.model_copy(
        update={
            "conclusion": f"{conclusion.rstrip('。')}。{boundary}",
            "root_cause": root_cause,
            "reasoning_summary": reasoning[:6],
            "counter_evidence": counter_evidence[:4],
            "residual_risk": residual_risk,
        }
    )


def _claims_config_drift_excluded(value: str) -> bool:
    unbounded = value
    for boundary in (
        _CONFIG_DRIFT_BOUNDARY,
        _CONFIG_DRIFT_DETECTED_BOUNDARY,
        _CONFIG_DRIFT_UNOBSERVED_BOUNDARY,
    ):
        unbounded = unbounded.replace(boundary, "")
    return any(pattern.search(unbounded) for pattern in _CONFIG_DRIFT_EXCLUSION_PATTERNS)


def _remove_config_drift_exclusion(value: str) -> str:
    protected_boundaries = {
        "__OPSCOUNCIL_CONFIG_DRIFT_BOUNDARY__": _CONFIG_DRIFT_BOUNDARY,
        "__OPSCOUNCIL_CONFIG_DRIFT_DETECTED__": _CONFIG_DRIFT_DETECTED_BOUNDARY,
        "__OPSCOUNCIL_CONFIG_DRIFT_UNOBSERVED__": _CONFIG_DRIFT_UNOBSERVED_BOUNDARY,
    }
    cleaned = value
    for placeholder, boundary in protected_boundaries.items():
        cleaned = cleaned.replace(boundary, placeholder)
    for pattern in _CONFIG_DRIFT_EXCLUSION_PATTERNS:
        cleaned = pattern.sub("", cleaned)
    for placeholder, boundary in protected_boundaries.items():
        cleaned = cleaned.replace(placeholder, boundary)
    cleaned = re.sub(r"[，,]{2,}", "，", cleaned)
    cleaned = re.sub(r"[，,]\s*([。；;])", r"\1", cleaned)
    cleaned = re.sub(r"[；;]{2,}", "；", cleaned)
    cleaned = re.sub(r"[；;]\s*([。])", r"\1", cleaned)
    return cleaned.strip(" ，,")


def _trusted_config_baseline_status(evidence_items: list[Any]) -> str | None:
    for item in evidence_items:
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        if getattr(item, "source_key", "") != "config_baseline_check":
            continue
        payload = getattr(item, "payload_json", {})
        if not isinstance(payload, dict):
            continue
        status = payload.get("status")
        summary = payload.get("summary")
        if status in {"clean", "drifted"} and isinstance(summary, dict):
            if int(summary.get("total") or 0) > 0:
                return str(status)
    return None


_SERVICE_LIVENESS_OVERCLAIM_RE = re.compile(
    r"(?:"
    r"排除(?:了)?(?:[A-Za-z0-9_.-]+\s*)?"
    r"(?:(?:服务|应用)?本体|服务进程|服务|自身)?(?:故障|崩溃|异常)|"
    r"(?:[A-Za-z0-9_.-]+\s*)?(?:(?:服务|应用)?本体|服务进程|服务|自身)"
    r"(?:故障|崩溃|异常)(?:已)?排除|"
    r"(?:当前)?无(?:直接)?证据(?:表明|支持)(?:[A-Za-z0-9_.-]+\s*)?"
    r"(?:自身|本体|服务进程|服务)?(?:故障|崩溃)"
    r")"
)


def _enforce_service_liveness_claim_boundary(
    result: AIAnalysisResult,
    evidence_items: list[Any],
) -> AIAnalysisResult:
    analyzed_text = "\n".join(
        (
            result.conclusion,
            result.root_cause,
            result.residual_risk,
            *result.reasoning_summary,
            *result.counter_evidence,
        )
    )
    if not _SERVICE_LIVENESS_OVERCLAIM_RE.search(analyzed_text):
        return result
    replacement = (
        "现有进程与监听证据不支持服务进程崩溃"
        if _has_process_liveness_evidence(evidence_items)
        else "现有证据不足以排除服务本体故障"
    )

    def replace(value: str) -> str:
        bounded = _SERVICE_LIVENESS_OVERCLAIM_RE.sub(replacement, value)
        return re.sub(
            r"(?:进程与(?:端口(?:监听)?|监听)(?:均)?(?:存活|存在)|"
            r"监听端口存在且进程活跃)"
            r"[，,]?(?=现有进程与监听证据不支持服务进程崩溃)",
            "",
            bounded,
        )

    return result.model_copy(
        update={
            "conclusion": replace(result.conclusion),
            "root_cause": replace(result.root_cause),
            "residual_risk": replace(result.residual_risk),
            "reasoning_summary": [replace(item) for item in result.reasoning_summary],
            "counter_evidence": [replace(item) for item in result.counter_evidence],
        }
    )


def _has_process_liveness_evidence(evidence_items: list[Any]) -> bool:
    for item in evidence_items:
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        if _evidence_supports_service_liveness(item):
            return True
    return False


def _evidence_supports_service_liveness(item: Any) -> bool:
    source_key = str(getattr(item, "source_key", ""))
    payload = getattr(item, "payload_json", {})
    payload = payload if isinstance(payload, dict) else {}
    if source_key == "service_status":
        state = str(
            payload.get("active_state")
            or payload.get("ActiveState")
            or payload.get("active")
            or ""
        ).lower()
        return state == "active"
    if source_key == "process_runtime_detail":
        pid = payload.get("pid")
        state = str(payload.get("state") or payload.get("stat") or "").upper()
        return (
            isinstance(pid, int)
            and not isinstance(pid, bool)
            and pid > 0
            and not state.startswith("Z")
        )
    if source_key == "service_dependency_snapshot":
        if any(
            isinstance(payload.get(key), int)
            and not isinstance(payload.get(key), bool)
            and int(payload[key]) > 0
            for key in ("process_count", "listener_count")
        ):
            return True
        summary = str(getattr(item, "summary", ""))
        return "->监听" in summary or "listener" in summary.lower()
    return False


def _grounded_counter_evidence(
    model_items: list[str],
    evidence_items: list[Any],
) -> list[str]:
    del model_items
    grounded: list[str] = []
    if _has_service_liveness_counter_evidence(evidence_items):
        grounded.append("当前进程与监听证据不支持服务进程崩溃。")
    baseline_status = _trusted_config_baseline_status(evidence_items)
    if baseline_status == "clean":
        grounded.append("受信任配置基线与当前快照一致，不支持配置内容漂移。")
    elif baseline_status is None and _has_current_config_observation(evidence_items):
        grounded.append(f"已记录当前配置状态；{_CONFIG_DRIFT_BOUNDARY}")
    return list(dict.fromkeys(grounded))[:4]


_TRANSIENT_CONNECTION_CAUSAL_RE = re.compile(
    r"[^；。\n]*(?:未观测到|未发现|未采到|未记录到|未捕获到|无(?:已建立)?)"
    r"[^；。\n]*连接[^；。\n]*(?:支持|佐证|证明|指向|表明)[^；。\n]*"
    r"(?:不可达|未建立|不存在|未响应)[；。]?"
)
_TRANSIENT_CONNECTION_BOUNDARY = (
    "本次采样未记录到已建立连接；该缺口不用于证明依赖不存在或不可达。"
)


def _enforce_transient_connection_claim_boundary(
    result: AIAnalysisResult,
) -> AIAnalysisResult:
    def replace(value: str) -> str:
        if not _TRANSIENT_CONNECTION_CAUSAL_RE.search(value):
            return value
        bounded = _TRANSIENT_CONNECTION_CAUSAL_RE.sub(
            _TRANSIENT_CONNECTION_BOUNDARY,
            value,
        )
        bounded = re.sub(r"[；;。]{2,}", "。", bounded)
        return bounded.strip(" ，,；;")

    return result.model_copy(
        update={
            "conclusion": replace(result.conclusion),
            "root_cause": replace(result.root_cause),
            "residual_risk": replace(result.residual_risk),
            "reasoning_summary": [replace(item) for item in result.reasoning_summary],
            "counter_evidence": [replace(item) for item in result.counter_evidence],
            "recommended_actions": [
                action.model_copy(update={"rationale": replace(action.rationale)})
                for action in result.recommended_actions
            ],
        }
    )


_SINGLE_LOG_SUPPORT_RE = re.compile(
    r"当前结论(?:仅)?基于[^；。]{0,40}(?:单向|单一)[^；。]{0,20}日志"
)
_OTHER_CAUSE_EXCLUSION_RE = re.compile(
    r"[，,；;]?\s*(?:无(?:证据|反证)支持|未发现)其他(?:候选)?根因"
)
_UNSUPPORTED_ABSENCE_CLAIM_RE = re.compile(
    r"[，,；;]?\s*(?:未发现|无)[^；。]{0,40}"
    r"(?:配置解析失败|资源耗尽)[^；。]{0,20}(?:迹象|证据|线索)"
)


def _enforce_multi_source_support_boundary(
    result: AIAnalysisResult,
    evidence_items: list[Any],
) -> AIAnalysisResult:
    reasoning_summary = [
        _UNSUPPORTED_ABSENCE_CLAIM_RE.sub(
            "",
            _OTHER_CAUSE_EXCLUSION_RE.sub("", item),
        )
        for item in result.reasoning_summary
    ]
    source_keys = {
        str(getattr(item, "source_key", ""))
        for item in evidence_items
        if str(getattr(item, "trust_level", "")).upper() != "QUARANTINED"
    }
    if not {"service_health_probe", "application_log_query"}.issubset(source_keys):
        return result.model_copy(update={"reasoning_summary": reasoning_summary})
    residual_risk = _SINGLE_LOG_SUPPORT_RE.sub(
        "当前结论由健康检查与应用日志共同支持",
        result.residual_risk,
    )
    return result.model_copy(
        update={
            "residual_risk": residual_risk,
            "reasoning_summary": reasoning_summary,
        }
    )


def _has_current_config_observation(evidence_items: list[Any]) -> bool:
    return any(
        str(getattr(item, "trust_level", "")).upper() != "QUARANTINED"
        and getattr(item, "source_key", "") == "config_integrity_scan"
        for item in evidence_items
    )


def _has_service_liveness_counter_evidence(evidence_items: list[Any]) -> bool:
    for item in evidence_items:
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        if _evidence_supports_service_liveness(item):
            return True
    return False


@dataclass
class _InfrastructureLiterals:
    ports: set[int] = field(default_factory=set)
    pids: set[int] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)


_URL_RE = re.compile(r"https?://[^\s，。；;）)\]}>\"']+", re.IGNORECASE)
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+")
_ENDPOINT_PORT_RE = re.compile(
    r"(?:(?:\d{1,3}\.){3}\d{1,3}|localhost|"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|\[[0-9A-Fa-f:]+\])"
    r":(\d{2,5})(?!\d)",
    re.IGNORECASE,
)
_PORT_CLAIM_RE = re.compile(
    r"(?:端口|port)[^\d。；;，,]{0,20}([1-9]\d{1,4})(?!\d)",
    re.IGNORECASE,
)
_LEADING_PORT_CLAIM_RE = re.compile(
    r"(?<!\d)([1-9]\d{1,4})(?!\d)[^\d。；;，,]{0,6}(?:端口|port)",
    re.IGNORECASE,
)
_PID_CLAIM_RE = re.compile(
    r"(?:PID|进程号)[^\d。；;，,]{0,12}([1-9]\d*)(?!\d)",
    re.IGNORECASE,
)


def _enforce_infrastructure_literal_boundary(
    result: AIAnalysisResult,
    evidence_items: list[Any],
) -> AIAnalysisResult:
    literals = _observed_infrastructure_literals(evidence_items)
    factual_texts = (
        result.conclusion,
        result.root_cause,
        result.residual_risk,
        *result.reasoning_summary,
        *result.counter_evidence,
    )
    violations = sorted(
        {
            violation
            for text in factual_texts
            for violation in _literal_violations(text, literals)
        }
    )
    if violations:
        raise ValueError(
            "model analysis contains ungrounded infrastructure identifiers: "
            + ", ".join(violations[:8])
        )

    actions: list[RecommendedAction] = []
    for action in result.recommended_actions:
        action_text = "\n".join((action.title, action.rationale, action.safety_gate))
        if not _literal_violations(action_text, literals):
            actions.append(action)
            continue
        actions.append(
            action.model_copy(
                update={
                    "title": "补充依赖侧证据",
                    "rationale": (
                        "核查已识别依赖的运行状态、监听关系与近期日志，"
                        "并将结果写入当前任务证据链。"
                    ),
                    "safety_gate": (
                        "仅作为建议；实际动作需重新进入计划与安全校验。"
                    ),
                    "tool_name": None,
                }
            )
        )
    return result.model_copy(update={"recommended_actions": actions})


def _observed_infrastructure_literals(
    evidence_items: list[Any],
) -> _InfrastructureLiterals:
    literals = _InfrastructureLiterals()
    for item in evidence_items:
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        if str(getattr(item, "source_type", "")).upper() == "KNOWLEDGE":
            continue
        for value in (
            getattr(item, "source_ref", ""),
            getattr(item, "source_key", ""),
            getattr(item, "title", ""),
            getattr(item, "summary", ""),
        ):
            _collect_literals_from_text(str(value), literals)
        _collect_literals_from_value(getattr(item, "payload_json", {}), literals)
    return literals


def _collect_literals_from_value(
    value: Any,
    literals: _InfrastructureLiterals,
    *,
    key: str = "",
) -> None:
    normalized_key = key.lower().replace("-", "_")
    if isinstance(value, dict):
        for item_key, item_value in value.items():
            _collect_literals_from_value(
                item_value,
                literals,
                key=str(item_key),
            )
        return
    if isinstance(value, list):
        for item in value:
            _collect_literals_from_value(item, literals, key=key)
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if "port" in normalized_key and 1 <= value <= 65535:
            literals.ports.add(value)
        if normalized_key in {"pid", "process_id", "process_pid"} and value > 0:
            literals.pids.add(value)
        return
    if not isinstance(value, str):
        return
    stripped = value.strip()
    if "port" in normalized_key and stripped.isdigit():
        port = int(stripped)
        if 1 <= port <= 65535:
            literals.ports.add(port)
    if normalized_key in {"pid", "process_id", "process_pid"} and stripped.isdigit():
        pid = int(stripped)
        if pid > 0:
            literals.pids.add(pid)
    _collect_literals_from_text(stripped, literals)


def _collect_literals_from_text(
    text: str,
    literals: _InfrastructureLiterals,
) -> None:
    for url in _URL_RE.findall(text):
        literals.urls.add(url)
        path = urlsplit(url).path
        if path and path != "/":
            literals.paths.add(path)
    literals.ips.update(_IP_RE.findall(text))
    literals.paths.update(_PATH_RE.findall(text))
    for match in _ENDPOINT_PORT_RE.finditer(text):
        port = int(match.group(1))
        if 1 <= port <= 65535:
            literals.ports.add(port)
    for match in _PORT_CLAIM_RE.finditer(text):
        port = int(match.group(1))
        if 1 <= port <= 65535:
            literals.ports.add(port)
    for match in _LEADING_PORT_CLAIM_RE.finditer(text):
        port = int(match.group(1))
        if 1 <= port <= 65535:
            literals.ports.add(port)
    for match in _PID_CLAIM_RE.finditer(text):
        literals.pids.add(int(match.group(1)))


def _literal_violations(
    text: str,
    allowed: _InfrastructureLiterals,
) -> set[str]:
    violations: set[str] = set()
    for value in _URL_RE.findall(text):
        if value not in allowed.urls:
            violations.add(f"url={value}")
    for value in _IP_RE.findall(text):
        if value not in allowed.ips:
            violations.add(f"ip={value}")
    for value in _PATH_RE.findall(text):
        if value not in allowed.paths:
            violations.add(f"path={value}")
    claimed_ports = {
        int(match.group(1))
        for pattern in (_ENDPOINT_PORT_RE, _PORT_CLAIM_RE, _LEADING_PORT_CLAIM_RE)
        for match in pattern.finditer(text)
    }
    for value in claimed_ports - allowed.ports:
        violations.add(f"port={value}")
    claimed_pids = {
        int(match.group(1))
        for match in _PID_CLAIM_RE.finditer(text)
    }
    for value in claimed_pids - allowed.pids:
        violations.add(f"pid={value}")
    return violations


def _grounded_investigation_evidence(
    evidence_items: list[Any],
    *,
    preferred_evidence_ids: list[int] | None = None,
) -> list[dict[str, str]]:
    selected = _select_grounded_evidence(evidence_items, preferred_evidence_ids or [])
    grounded: list[dict[str, str]] = []
    for item in selected:
        payload = item.payload_json if isinstance(item.payload_json, dict) else {}
        evidence_ref = payload.get("evidence_ref")
        if isinstance(evidence_ref, str) and evidence_ref:
            source = evidence_ref
        elif item.source_type == "KNOWLEDGE":
            source = f"知识库：{item.title}"
        else:
            source = f"MCP：{item.title}"
        grounded.append(
            {
                "evidence_id": str(item.id),
                "source": source[:300],
                "summary": str(item.summary)[:500],
            }
        )
    return grounded


def _select_grounded_evidence(
    evidence_items: list[Any],
    preferred_evidence_ids: list[int],
) -> list[Any]:
    by_id = {int(item.id): item for item in evidence_items}
    selected: list[Any] = []
    selected_ids: set[int] = set()

    for evidence_id in preferred_evidence_ids:
        item = by_id.get(int(evidence_id))
        if item is None or int(item.id) in selected_ids:
            continue
        selected.append(item)
        selected_ids.add(int(item.id))

    for item in _counter_evidence_source_items(evidence_items):
        item_id = int(item.id)
        if item_id in selected_ids:
            continue
        selected.append(item)
        selected_ids.add(item_id)

    if selected:
        return selected[:8]

    source_counts: dict[str, int] = {}
    for item in selected:
        key = str(getattr(item, "source_key", ""))
        source_counts[key] = source_counts.get(key, 0) + 1

    for item in evidence_items:
        if len(selected) >= 8:
            break
        item_id = int(item.id)
        if item_id in selected_ids:
            continue
        key = str(getattr(item, "source_key", ""))
        quota = 3 if key in {"find_large_files", "process_list"} else 1
        if source_counts.get(key, 0) >= quota:
            continue
        selected.append(item)
        selected_ids.add(item_id)
        source_counts[key] = source_counts.get(key, 0) + 1

    return selected[:8]


def _counter_evidence_source_items(evidence_items: list[Any]) -> list[Any]:
    selected: list[Any] = []
    liveness_added = False
    config_added = False
    for item in evidence_items:
        if str(getattr(item, "trust_level", "")).upper() == "QUARANTINED":
            continue
        source_key = str(getattr(item, "source_key", ""))
        if (
            not liveness_added
            and _evidence_supports_service_liveness(item)
        ):
            selected.append(item)
            liveness_added = True
        if (
            not config_added
            and source_key in {"config_baseline_check", "config_integrity_scan"}
        ):
            selected.append(item)
            config_added = True
    return selected


def _enforce_action_policy(
    action: RecommendedAction,
    allowed_tools: set[str],
) -> RecommendedAction:
    tool_name = action.tool_name if action.tool_name in allowed_tools else None
    update: dict[str, Any] = {
        "tool_name": tool_name,
    }
    if _contains_shell_command(action.rationale) or _contains_shell_command(action.safety_gate):
        update.update(
            {
                "rationale": "通过已注册的只读 MCP 工具补充核查，并保留工具输入、输出和版本证据。",
                "safety_gate": "仅允许已注册的只读 MCP 工具；涉及系统变更必须人工审批。",
            }
        )
    elif tool_name is None:
        update["safety_gate"] = "仅作为建议；实际动作需重新进入计划与安全校验。"
    else:
        update["safety_gate"] = "通过已注册工具重新发起；执行前按工具风险进入安全校验。"
    return action.model_copy(update=update)


def _contains_shell_command(value: str) -> bool:
    return bool(
        re.search(
            r"(?<![A-Za-z0-9_])(?:sudo|sh|bash|rm|chmod|chown|systemctl|journalctl|ss|lsof|"
            r"grep|find|cat|head|tail|ps|top|ip|netstat|df|du|stat|curl|wget|python|perl|"
            r"awk|sed)\s+(?:-|/|[A-Za-z0-9])|[|;&]|\$\(|`",
            value,
            flags=re.IGNORECASE,
        )
    )


_ANALYSIS_ALIASES = {
    "conclusion": ("结论", "分析结论", "summary", "diagnosis"),
    "root_cause": ("rootCause", "cause", "根因", "根因分析", "原因"),
    "risk_level": ("riskLevel", "risk", "风险等级", "风险级别"),
    "reasoning_summary": ("reasoningSummary", "reasoning", "分析依据", "判断依据", "推理摘要"),
    "counter_evidence": ("counterEvidence", "反证", "反证依据", "排除依据"),
    "recommended_actions": (
        "recommendedActions",
        "actions",
        "recommendations",
        "建议",
        "处置建议",
        "后续建议",
    ),
    "evidence_used": ("evidenceUsed", "evidence", "证据", "引用证据"),
    "residual_risk": ("residualRisk", "residual", "残余风险", "剩余风险"),
}


def _normalize_analysis_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    for canonical, aliases in _ANALYSIS_ALIASES.items():
        if canonical in normalized:
            continue
        for alias in aliases:
            if alias in payload:
                normalized[canonical] = payload[alias]
                break
    return normalized


def _normalize_text_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [_stringify(item) for item in value]
    return [_stringify(value)]


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


_TOOL_LABELS = {
    "platform_capability_profile": "主机能力画像",
    "system_snapshot": "系统快照",
    "disk_usage": "磁盘用量",
    "find_large_files": "大文件定位",
    "process_list": "进程列表",
    "process_file_handles": "文件句柄检查",
    "journal_query": "系统日志查询",
    "service_status": "服务状态",
    "time_sync_status": "时间同步状态",
    "network_listeners": "网络监听",
    "service_dependency_snapshot": "服务关系快照",
    "service_health_probe": "服务健康检查",
    "application_log_query": "应用日志",
    "config_integrity_scan": "配置完整性检查",
    "config_baseline_check": "配置基线比较",
    "safe_log_rotate": "日志安全轮转",
    "restore_log_backup": "日志备份恢复",
    "restart_managed_service": "受控服务重启",
    "restore_config_mode": "配置权限恢复",
    "file_integrity_state": "文件完整性校验",
    "process_runtime_detail": "进程运行详情",
    "journal_storage_status": "日志存储状态",
    "socket_process_context": "端口进程归属",
    "filesystem_mount_context": "文件系统挂载",
}


def _humanize_tool_names(value: str) -> str:
    text = value
    for tool_name, label in _TOOL_LABELS.items():
        text = re.sub(
            rf"(?<![A-Za-z0-9_]){re.escape(tool_name)}(?![A-Za-z0-9_])",
            label,
            text,
        )
    scope_labels = {
        "loopback": "本机回环",
        "private": "内网",
        "link_local": "链路本地",
        "wildcard": "所有地址",
        "public": "公网",
        "unknown": "范围未知",
    }
    for scope, label in scope_labels.items():
        text = re.sub(
            rf"(?<![A-Za-z0-9_])exposure_?scope\s*=\s*{scope}(?![A-Za-z0-9_])",
            f"暴露范围为{label}",
            text,
            flags=re.IGNORECASE,
        )
    return re.sub(r"(?<=[\u4e00-\u9fff])\s+(?=[\u4e00-\u9fff])", "", text)
