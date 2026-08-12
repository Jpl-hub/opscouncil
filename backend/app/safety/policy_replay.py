from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import SafetyReview, Task
from backend.app.safety.engine import SafetyEngine, StaticReviewOutcome


_RISK_RANK = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}
_DECISION_RANK = {"ALLOW": 0, "APPROVAL_REQUIRED": 1, "REJECT": 2}


class SafetyPolicyReplayService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def evaluate(self, task: Task) -> dict[str, Any]:
        reviews = list(
            self.session.scalars(
                select(SafetyReview)
                .where(SafetyReview.task_id == task.id)
                .order_by(SafetyReview.id.asc())
            )
        )
        rows = [self._evaluate_review(task, review) for review in reviews]
        comparable = [row for row in rows if row["comparable"]]
        changed = [row for row in comparable if row["changed"]]
        not_comparable = len(rows) - len(comparable)
        status = (
            "drifted"
            if changed
            else "partial"
            if comparable and not_comparable
            else "consistent"
            if comparable
            else "unavailable"
        )
        policy = SafetyEngine.policy_identity()
        return {
            "status": status,
            "current_policy": policy,
            "review_count": len(rows),
            "evaluated_count": len(comparable),
            "not_comparable_count": not_comparable,
            "changed_count": len(changed),
            "tightened_count": sum(row["status"] == "tightened" for row in changed),
            "relaxed_count": sum(row["status"] == "relaxed" for row in changed),
            "legacy_review_count": sum(
                row["recorded_policy_version"] == "legacy-unversioned"
                for row in rows
            ),
            "rows": rows,
        }

    def _evaluate_review(
        self,
        task: Task,
        review: SafetyReview,
    ) -> dict[str, Any]:
        base = {
            "review_id": review.id,
            "review_type": review.review_type,
            "recorded_policy_version": review.policy_version,
            "recorded_policy_digest": review.policy_digest,
            "recorded_risk_level": review.risk_level,
            "recorded_decision": review.decision,
            "recorded_rule_ids": _rule_ids(review.matched_rules_json),
        }
        subject = review.subject_json if isinstance(review.subject_json, dict) else {}
        if review.review_type == "static_user_intent":
            expected_subject = SafetyEngine.user_review_subject(task.user_input)
            if subject and subject != expected_subject:
                return _not_comparable(
                    base,
                    "历史裁决对象与任务原始请求不一致。",
                )
            outcome = SafetyEngine(self.session).evaluate_user_request(
                task,
                task.user_input,
            )
            return _comparison(
                base,
                outcome,
                subject_kind="user_request",
                subject_digest=expected_subject["text_digest"],
            )
        if review.review_type == "dynamic_tool_action":
            if (
                subject.get("kind") != "tool_action"
                or not isinstance(subject.get("tool_name"), str)
                or not isinstance(subject.get("input"), dict)
            ):
                return _not_comparable(
                    base,
                    "历史动态裁决缺少精确工具与参数。",
                )
            expected_subject = SafetyEngine.tool_review_subject(
                subject["tool_name"],
                subject["input"],
            )
            if subject != expected_subject:
                return _not_comparable(
                    base,
                    "历史动态裁决对象摘要校验失败。",
                )
            outcome = SafetyEngine.classify_tool_action(
                subject["tool_name"],
                subject["input"],
            )
            return _comparison(
                base,
                outcome,
                subject_kind="tool_action",
                subject_digest=expected_subject["digest"],
                subject_label=subject["tool_name"],
            )
        return _not_comparable(
            base,
            "该裁决属于独立策略域，不参与当前规则集重放。",
        )


def _comparison(
    base: dict[str, Any],
    outcome: StaticReviewOutcome,
    *,
    subject_kind: str,
    subject_digest: str,
    subject_label: str = "",
) -> dict[str, Any]:
    current_risk = outcome.risk_level.value
    current_decision = outcome.decision.value
    current_rules = sorted(hit.rule_id for hit in outcome.matched_rules)
    changed = (
        base["recorded_risk_level"] != current_risk
        or base["recorded_decision"] != current_decision
        or base["recorded_rule_ids"] != current_rules
    )
    status = _change_status(
        base["recorded_risk_level"],
        base["recorded_decision"],
        current_risk,
        current_decision,
        changed=changed,
    )
    return {
        **base,
        "comparable": True,
        "changed": changed,
        "status": status,
        "current_risk_level": current_risk,
        "current_decision": current_decision,
        "current_rule_ids": current_rules,
        "subject_kind": subject_kind,
        "subject_label": subject_label,
        "subject_digest": subject_digest,
        "reason": outcome.reason,
    }


def _not_comparable(
    base: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    return {
        **base,
        "comparable": False,
        "changed": False,
        "status": "not_comparable",
        "current_risk_level": None,
        "current_decision": None,
        "current_rule_ids": [],
        "subject_kind": "",
        "subject_label": "",
        "subject_digest": "",
        "reason": reason,
    }


def _change_status(
    recorded_risk: str,
    recorded_decision: str,
    current_risk: str,
    current_decision: str,
    *,
    changed: bool,
) -> str:
    if not changed:
        return "unchanged"
    recorded_strength = (
        _RISK_RANK.get(recorded_risk, -1),
        _DECISION_RANK.get(recorded_decision, -1),
    )
    current_strength = (
        _RISK_RANK.get(current_risk, -1),
        _DECISION_RANK.get(current_decision, -1),
    )
    if current_strength > recorded_strength:
        return "tightened"
    if current_strength < recorded_strength:
        return "relaxed"
    return "changed"


def _rule_ids(rows: list[Any]) -> list[str]:
    return sorted(
        {
            str(item["rule_id"])
            for item in rows
            if isinstance(item, dict) and item.get("rule_id")
        }
    )
