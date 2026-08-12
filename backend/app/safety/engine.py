from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import posixpath
import re
from typing import Any

from sqlalchemy.orm import Session

from backend.app.audit.service import stable_hash
from backend.app.core.config import settings
from backend.app.executor.config_policy import (
    ALLOWED_CONFIG_MODES,
    validate_repairable_config_path,
)
from backend.app.executor.systemd_policy import validate_restartable_unit
from backend.app.models.entities import SafetyReview, Task
from backend.app.safety.risk_chain import (
    POLICY_VERSION as RISK_CHAIN_POLICY_VERSION,
    STATUS_BLOCKED,
    STATUS_WATCH,
    RiskChainResult,
    RiskChainService,
)
from backend.app.schemas.enums import ReviewDecision, RiskLevel, max_risk


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    label: str
    risk_level: RiskLevel
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "label": self.label,
            "risk_level": self.risk_level.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class StaticReviewOutcome:
    risk_level: RiskLevel
    decision: ReviewDecision
    matched_rules: list[RuleHit]
    reason: str


class SafetyEngine:
    policy_version = "safety-engine-v2"
    prompt_injection_patterns = [
        (r"忽略(以上|之前|所有).*(规则|指令|限制)", "要求忽略安全规则"),
        (r"绕过.*(审批|权限|安全|护栏)", "要求绕过安全机制"),
        (r"(泄露|输出|告诉我).*(api.?key|密钥|token|密码)", "疑似密钥窃取"),
        (r"你现在是.*(root|超级管理员|无视规则)", "角色越权诱导"),
    ]
    dangerous_patterns = [
        (r"rm\s+-rf\s+/", "递归删除根目录"),
        (r"mkfs(\.|\s)", "格式化文件系统"),
        (r"dd\s+.*of=/dev/", "直接写块设备"),
        (r"chmod\s+-R\s+777", "递归开放最高权限"),
        (r"chown\s+-R\s+root", "递归变更 root 所有者"),
    ]
    high_risk_words = [
        "重启",
        "restart",
        "kill",
        "停止服务",
        "删除",
        "清空",
        "chmod",
        "chown",
        "修改权限",
        "恢复权限",
        "权限恢复",
        "修复权限",
    ]
    reversible_words = ["清理", "压缩", "轮转", "备份", "回滚"]
    allowed_action_tools = {
        "restart_managed_service",
        "restore_config_mode",
        "restore_log_backup",
        "safe_log_rotate",
    }
    protected_path_prefixes = (
        "/etc",
        "/boot",
        "/usr",
        "/var/lib/mysql",
        "/var/lib/postgresql",
        "/var/log/audit",
        "/var/log/journal",
        "/var/log/mysql",
        "/var/log/mariadb",
        "/var/log/postgresql",
    )

    @classmethod
    def rule_catalog(cls) -> list[dict[str, str]]:
        rules: list[dict[str, str]] = []
        for pattern, label in cls.prompt_injection_patterns:
            rules.append(
                {
                    "rule_id": "prompt_injection",
                    "category": "提示词注入",
                    "label": label,
                    "risk_level": RiskLevel.R4.value,
                    "decision": ReviewDecision.REJECT.value,
                    "detail": pattern,
                }
            )
        for pattern, label in cls.dangerous_patterns:
            rules.append(
                {
                    "rule_id": "dangerous_command",
                    "category": "危险命令",
                    "label": label,
                    "risk_level": RiskLevel.R4.value,
                    "decision": ReviewDecision.REJECT.value,
                    "detail": pattern,
                }
            )
        rules.append(
            {
                "rule_id": "high_risk_intent",
                "category": "高风险意图",
                "label": "请求可能涉及系统变更",
                "risk_level": RiskLevel.R3.value,
                "decision": ReviewDecision.APPROVAL_REQUIRED.value,
                "detail": "、".join(cls.high_risk_words),
            }
        )
        rules.append(
            {
                "rule_id": "reversible_ops",
                "category": "可逆处置",
                "label": "请求可能涉及可逆清理/备份动作",
                "risk_level": RiskLevel.R2.value,
                "decision": ReviewDecision.ALLOW.value,
                "detail": "、".join(cls.reversible_words),
            }
        )
        rules.append(
            {
                "rule_id": "path_scope",
                "category": "执行边界",
                "label": "副作用工具仅允许处理 /var/log 与 /tmp 范围",
                "risk_level": RiskLevel.R4.value,
                "decision": ReviewDecision.REJECT.value,
                "detail": "受保护目录：" + "、".join(cls.protected_path_prefixes),
            }
        )
        return rules

    def __init__(self, session: Session):
        self.session = session

    @classmethod
    def policy_identity(cls) -> dict[str, str]:
        descriptor = {
            "version": cls.policy_version,
            "rules": cls.rule_catalog(),
            "allowed_action_tools": sorted(cls.allowed_action_tools),
            "protected_path_prefixes": list(cls.protected_path_prefixes),
            "allowed_config_modes": sorted(ALLOWED_CONFIG_MODES),
            "restartable_systemd_units": sorted(
                getattr(settings, "restartable_systemd_units", ())
            ),
            "repairable_config_paths": sorted(
                getattr(settings, "repairable_config_paths", ())
            ),
            "risk_chain_policy_version": RISK_CHAIN_POLICY_VERSION,
        }
        return {
            "version": cls.policy_version,
            "digest": stable_hash(descriptor),
        }

    @staticmethod
    def user_review_subject(text: str) -> dict[str, Any]:
        return {
            "kind": "user_request",
            "text_digest": stable_hash({"text": text}),
        }

    @staticmethod
    def tool_review_subject(
        tool_name: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        subject = {
            "kind": "tool_action",
            "tool_name": tool_name,
            "input": deepcopy(payload),
        }
        subject["digest"] = stable_hash(subject)
        return subject

    @classmethod
    def classify_user_text(cls, text: str) -> StaticReviewOutcome:
        hits: list[RuleHit] = []
        normalized = text.lower()

        for pattern, label in cls.prompt_injection_patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                hits.append(RuleHit("prompt_injection", label, RiskLevel.R4, pattern))

        for pattern, label in cls.dangerous_patterns:
            if re.search(pattern, normalized, flags=re.IGNORECASE):
                hits.append(RuleHit("dangerous_command", label, RiskLevel.R4, pattern))

        if not hits:
            if any(word in normalized for word in cls.high_risk_words):
                hits.append(RuleHit("high_risk_intent", "请求可能涉及系统变更", RiskLevel.R3, "keyword"))
            elif any(word in normalized for word in cls.reversible_words):
                hits.append(RuleHit("reversible_ops", "请求可能涉及可逆清理/备份动作", RiskLevel.R2, "keyword"))
            else:
                hits.append(RuleHit("read_only", "只读诊断或咨询请求", RiskLevel.R0, "default"))

        risk = max_risk(*(hit.risk_level for hit in hits))
        if risk == RiskLevel.R4:
            decision = ReviewDecision.REJECT
            reason = "命中禁止级安全规则，拒绝执行。"
        elif risk == RiskLevel.R3:
            decision = ReviewDecision.APPROVAL_REQUIRED
            reason = "请求可能产生高风险变更，需要人工审批。"
        else:
            decision = ReviewDecision.ALLOW
            reason = "未命中禁止规则，允许进入只读感知/分析流程。"

        return StaticReviewOutcome(
            risk_level=risk,
            decision=decision,
            matched_rules=hits,
            reason=reason,
        )

    @classmethod
    def classify_tool_action(cls, tool_name: str, payload: dict[str, Any]) -> StaticReviewOutcome:
        hits: list[RuleHit] = []

        if tool_name not in cls.allowed_action_tools:
            hits.append(
                RuleHit(
                    "unapproved_tool",
                    "工具未进入安全执行白名单",
                    RiskLevel.R4,
                    tool_name,
                )
            )

        suspicious_keys = {"command", "shell", "script", "cmd", "exec"}
        if suspicious_keys.intersection(payload):
            hits.append(
                RuleHit(
                    "free_form_execution",
                    "结构化参数中出现自由命令字段",
                    RiskLevel.R4,
                    ",".join(sorted(suspicious_keys.intersection(payload))),
                )
            )

        if tool_name == "restart_managed_service":
            try:
                validate_restartable_unit(
                    payload.get("unit") if isinstance(payload.get("unit"), str) else "",
                    getattr(settings, "restartable_systemd_units", ()),
                )
            except ValueError as exc:
                hits.append(
                    RuleHit(
                        "service_scope",
                        "服务单元未通过精确白名单校验",
                        RiskLevel.R4,
                        str(exc),
                    )
                )
        elif tool_name == "restore_config_mode":
            try:
                validate_repairable_config_path(
                    payload.get("path") if isinstance(payload.get("path"), str) else "",
                    getattr(settings, "repairable_config_paths", ()),
                )
            except ValueError as exc:
                hits.append(
                    RuleHit(
                        "config_scope",
                        "配置文件未通过精确白名单校验",
                        RiskLevel.R4,
                        str(exc),
                    )
                )
            if payload.get("target_mode") not in ALLOWED_CONFIG_MODES:
                hits.append(
                    RuleHit(
                        "config_mode",
                        "目标权限位超出安全模式集合",
                        RiskLevel.R4,
                        str(payload.get("target_mode")),
                    )
                )
            baseline_ids = (payload.get("baseline_id"), payload.get("baseline_check_id"))
            if any(
                not isinstance(value, int) or isinstance(value, bool) or value < 1
                for value in baseline_ids
            ):
                hits.append(
                    RuleHit(
                        "baseline_binding",
                        "配置权限恢复缺少基线证据绑定",
                        RiskLevel.R4,
                        "baseline_id/baseline_check_id",
                    )
                )
            expected_hash = payload.get("expected_sha256")
            if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
                hits.append(
                    RuleHit(
                        "baseline_hash",
                        "配置权限恢复缺少完整基线哈希",
                        RiskLevel.R4,
                        "expected_sha256",
                    )
                )
        else:
            path_fields = ("path",) if tool_name == "safe_log_rotate" else ("restore_target", "artifact_path")
            for field_name in path_fields:
                path = payload.get(field_name)
                if not isinstance(path, str):
                    hits.append(
                        RuleHit(
                            "path_scope",
                            "副作用工具缺少结构化路径",
                            RiskLevel.R4,
                            field_name,
                        )
                    )
                    continue
                raw_path = path.strip()
                normalized_path = posixpath.normpath(raw_path)
                if not normalized_path.startswith("/"):
                    hits.append(
                        RuleHit(
                            "path_scope",
                            "处置路径不是绝对路径",
                            RiskLevel.R4,
                            raw_path,
                        )
                    )
                if not (normalized_path.startswith("/var/log/") or normalized_path.startswith("/tmp/")):
                    hits.append(
                        RuleHit(
                            "path_scope",
                            "处置路径超出允许范围",
                            RiskLevel.R4,
                            normalized_path,
                        )
                    )
                if any(
                    normalized_path == prefix or normalized_path.startswith(prefix + "/")
                    for prefix in cls.protected_path_prefixes
                ):
                    hits.append(
                        RuleHit(
                            "protected_path",
                            "处置路径属于受保护系统目录",
                            RiskLevel.R4,
                            normalized_path,
                        )
                    )

        if not hits:
            hits.append(
                RuleHit(
                    (
                        "approved_service_restart"
                        if tool_name in {"restart_managed_service", "restore_config_mode"}
                        else "approved_reversible_action"
                    ),
                    (
                        "审批后的受控配置或服务恢复"
                        if tool_name in {"restart_managed_service", "restore_config_mode"}
                        else "审批后的可逆处置动作"
                    ),
                    (
                        RiskLevel.R3
                        if tool_name in {"restart_managed_service", "restore_config_mode"}
                        else RiskLevel.R2
                    ),
                    tool_name,
                )
            )

        risk = max_risk(*(hit.risk_level for hit in hits))
        decision = ReviewDecision.REJECT if risk == RiskLevel.R4 else ReviewDecision.ALLOW
        reason = (
            "动态校验发现禁止级风险，拒绝执行。"
            if decision == ReviewDecision.REJECT
            else "动态校验通过，允许执行已审批的结构化动作。"
        )
        return StaticReviewOutcome(
            risk_level=risk,
            decision=decision,
            matched_rules=hits,
            reason=reason,
        )

    def evaluate_user_request(
        self,
        task: Task,
        text: str,
    ) -> StaticReviewOutcome:
        outcome = self.classify_user_text(text)
        chain = RiskChainService(self.session).evaluate(task, text)
        return self._apply_risk_chain(outcome, chain)

    @staticmethod
    def _apply_risk_chain(
        outcome: StaticReviewOutcome,
        chain: RiskChainResult,
    ) -> StaticReviewOutcome:
        matched_rules = list(outcome.matched_rules)
        risk_level = outcome.risk_level
        decision = outcome.decision
        reason = outcome.reason
        if chain.status == STATUS_BLOCKED:
            matched_rules.append(
                RuleHit(
                    "cross_turn_risk_chain",
                    "跨回合累积行为形成禁止级风险链",
                    RiskLevel.R4,
                    (
                        f"{chain.chain_type or 'unknown'}；"
                        f"任务 {','.join(str(item) for item in chain.matched_task_ids)}"
                    ),
                )
            )
            risk_level = RiskLevel.R4
            decision = ReviewDecision.REJECT
            reason = f"跨回合安全校验：{chain.reason}"
        elif chain.status == STATUS_WATCH:
            matched_rules.append(
                RuleHit(
                    "cross_turn_risk_chain",
                    "跨回合行为需要重新绑定审批",
                    RiskLevel.R3,
                    (
                        f"{chain.chain_type or 'unknown'}；"
                        f"任务 {','.join(str(item) for item in chain.matched_task_ids)}"
                    ),
                )
            )
            risk_level = max_risk(risk_level, RiskLevel.R3)
            if decision != ReviewDecision.REJECT:
                decision = ReviewDecision.APPROVAL_REQUIRED
                reason = f"跨回合安全校验：{chain.reason}"
        return StaticReviewOutcome(
            risk_level=risk_level,
            decision=decision,
            matched_rules=matched_rules,
            reason=reason,
        )

    def review_user_request(self, task: Task, text: str) -> SafetyReview:
        outcome = self.evaluate_user_request(task, text)
        RiskChainService(self.session).assess(task, text)
        policy = self.policy_identity()
        review = SafetyReview(
            task_id=task.id,
            review_type="static_user_intent",
            risk_level=outcome.risk_level.value,
            decision=outcome.decision.value,
            matched_rules_json=[hit.to_dict() for hit in outcome.matched_rules],
            reason=outcome.reason,
            policy_version=policy["version"],
            policy_digest=policy["digest"],
            subject_json=self.user_review_subject(text),
        )
        self.session.add(review)
        task.risk_level = outcome.risk_level.value
        return review

    def review_tool_action(self, task: Task, tool_name: str, payload: dict) -> SafetyReview:
        outcome = self.classify_tool_action(tool_name, payload)
        policy = self.policy_identity()
        review = SafetyReview(
            task_id=task.id,
            review_type="dynamic_tool_action",
            risk_level=outcome.risk_level.value,
            decision=outcome.decision.value,
            matched_rules_json=[hit.to_dict() for hit in outcome.matched_rules],
            reason=outcome.reason,
            policy_version=policy["version"],
            policy_digest=policy["digest"],
            subject_json=self.tool_review_subject(tool_name, payload),
        )
        self.session.add(review)
        task.risk_level = max_risk(RiskLevel(task.risk_level), outcome.risk_level).value
        return review
