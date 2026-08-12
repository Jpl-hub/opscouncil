from __future__ import annotations

from datetime import datetime
from math import pow
import re
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.models.entities import (
    OperationalMemory,
    OperatorFeedback,
    OperatorPreferenceProfile,
    Task,
    utcnow,
)


_SUMMARY_DENSITIES = frozenset({"COMPACT", "BALANCED", "DETAILED"})
_EVIDENCE_VIEWS = frozenset({"CORE", "ALL"})
_NOTIFICATION_ROUTES = frozenset({"WEB", "FEISHU", "BOTH"})
_VERDICT_WEIGHTS = {
    "HELPFUL": 1.0,
    "INCOMPLETE": 0.45,
    "INCORRECT": 0.15,
}
_INTENT_SUGGESTIONS = {
    "disk_pressure_analysis": (
        "容量与 I/O",
        "检查文件系统容量、inode、日志占用和 I/O 等待，定位持续增长来源",
    ),
    "network_exposure_analysis": (
        "网络暴露",
        "检查监听端口、进程归属、服务必要性和未归属暴露面",
    ),
    "process_health_analysis": (
        "进程健康",
        "检查进程资源、僵尸进程、文件句柄和服务归属，定位异常来源",
    ),
    "log_analysis": (
        "日志与服务",
        "分析近期系统日志、失败服务和同期变更，形成可核验根因",
    ),
    "service_degradation_analysis": (
        "服务退化",
        "检查关键服务健康、依赖关系、应用日志和近期变更，定位退化根因",
    ),
    "config_integrity_analysis": (
        "配置漂移",
        "检查关键配置与确认基线的差异，并评估关联服务影响",
    ),
    "general_system_health": (
        "系统巡检",
        "执行系统健康巡检，优先调查偏离动态基线且持续存在的信号",
    ),
}


class PreferenceVersionConflictError(ValueError):
    pass


class OperatorPreferenceService:
    """Learn UI preferences from governed feedback without changing safety policy."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def context(self, actor: str) -> dict[str, Any]:
        profile, created = self._get_or_create(actor)
        if created or self._learning_stale(profile):
            self._relearn(
                profile,
                event_type="INITIAL_LEARNING" if created else "CONTEXT_REFRESH",
            )
        return self._to_context(profile)

    def update(
        self,
        actor: str,
        *,
        expected_version: int,
        summary_density: str,
        evidence_view: str,
        notification_route: str,
        service_focus: list[str],
    ) -> dict[str, Any]:
        profile, _ = self._get_or_create(actor)
        if profile.version != expected_version:
            raise PreferenceVersionConflictError(
                f"preference version changed: expected {expected_version}, current {profile.version}"
            )
        density = summary_density.strip().upper()
        view = evidence_view.strip().upper()
        route = notification_route.strip().upper()
        if density not in _SUMMARY_DENSITIES:
            raise ValueError("unknown summary density")
        if view not in _EVIDENCE_VIEWS:
            raise ValueError("unknown evidence view")
        if route not in _NOTIFICATION_ROUTES:
            raise ValueError("unknown notification route")
        services = _normalized_services(service_focus)

        profile.summary_density = density
        profile.evidence_view = view
        profile.notification_route = route
        profile.service_focus_json = services
        profile.version += 1
        profile.updated_at = utcnow()
        self._append_change(
            profile,
            "MANUAL_UPDATE",
            {
                "summary_density": density,
                "evidence_view": view,
                "notification_route": route,
                "service_focus": services,
            },
        )
        self.session.flush()
        return self._to_context(profile)

    def observe_feedback(self, actor: str) -> dict[str, Any]:
        profile, _ = self._get_or_create(actor)
        self._relearn(profile, event_type="FEEDBACK_LEARNING")
        return self._to_context(profile)

    def forget_learned(self, actor: str, *, reason: str) -> dict[str, Any]:
        normalized_reason = re.sub(r"\s+", " ", reason.strip())
        if len(normalized_reason) < 5:
            raise ValueError("forget reason is too short")
        profile, _ = self._get_or_create(actor)
        profile.learning_signals_json = {}
        profile.learned_intents_json = []
        profile.last_learning_at = utcnow()
        profile.version += 1
        profile.updated_at = utcnow()
        self._append_change(
            profile,
            "LEARNED_PREFERENCES_FORGOTTEN",
            {"reason": normalized_reason[:500]},
        )
        self.session.flush()
        return self._to_context(profile)

    def _get_or_create(
        self,
        actor: str,
    ) -> tuple[OperatorPreferenceProfile, bool]:
        actor_key = _normalized_actor(actor)
        profile = self.session.scalar(
            select(OperatorPreferenceProfile).where(
                OperatorPreferenceProfile.actor_key == actor_key
            )
        )
        if profile is not None:
            return profile, False
        now = utcnow()
        profile = OperatorPreferenceProfile(
            actor_key=actor_key,
            version=1,
            summary_density="BALANCED",
            evidence_view="CORE",
            notification_route="WEB",
            service_focus_json=[],
            learning_signals_json={},
            learned_intents_json=[],
            change_log_json=[],
            created_at=now,
            updated_at=now,
        )
        self.session.add(profile)
        self.session.flush()
        return profile, True

    def _learning_stale(self, profile: OperatorPreferenceProfile) -> bool:
        if profile.last_learning_at is None:
            return True
        latest_feedback = self.session.scalar(
            select(OperatorFeedback.created_at)
            .where(OperatorFeedback.actor == profile.actor_key)
            .order_by(OperatorFeedback.created_at.desc(), OperatorFeedback.id.desc())
            .limit(1)
        )
        latest_memory = self.session.scalar(
            select(OperationalMemory.updated_at)
            .where(
                or_(
                    OperationalMemory.created_by == profile.actor_key,
                    OperationalMemory.confirmed_by == profile.actor_key,
                )
            )
            .order_by(OperationalMemory.updated_at.desc(), OperationalMemory.id.desc())
            .limit(1)
        )
        watermark = profile.last_learning_at
        return any(
            value is not None and _as_aware(value, watermark) > watermark
            for value in (latest_feedback, latest_memory)
        )

    def _relearn(
        self,
        profile: OperatorPreferenceProfile,
        *,
        event_type: str,
    ) -> None:
        now = utcnow()
        feedback_rows = self.session.execute(
            select(OperatorFeedback, Task)
            .join(Task, Task.id == OperatorFeedback.task_id)
            .where(OperatorFeedback.actor == profile.actor_key)
            .order_by(OperatorFeedback.created_at.desc(), OperatorFeedback.id.desc())
            .limit(200)
        ).all()
        memory_rows = list(
            self.session.scalars(
                select(OperationalMemory).where(
                    or_(
                        OperationalMemory.created_by == profile.actor_key,
                        OperationalMemory.confirmed_by == profile.actor_key,
                    ),
                    OperationalMemory.status.in_(["CONFIRMED", "CORRECTED"]),
                )
            )
        )

        scores: dict[str, float] = {}
        signals: dict[str, dict[str, int]] = {}
        for feedback, task in feedback_rows:
            intent = str(task.intent or "unknown")
            if intent == "unknown":
                continue
            age_days = _age_days(now, feedback.created_at)
            decay = pow(0.5, age_days / 30.0)
            scores[intent] = scores.get(intent, 0.0) + (
                _VERDICT_WEIGHTS.get(feedback.verdict, 0.0) * decay
            )
            intent_signals = signals.setdefault(
                intent,
                {"HELPFUL": 0, "INCOMPLETE": 0, "INCORRECT": 0},
            )
            intent_signals[feedback.verdict] = (
                intent_signals.get(feedback.verdict, 0) + 1
            )

        for memory in memory_rows:
            applicability = (
                memory.applicability_json
                if isinstance(memory.applicability_json, dict)
                else {}
            )
            intent = str(applicability.get("intent") or "")
            if intent:
                scores[intent] = scores.get(intent, 0.0) + 1.2

        learned = [
            {
                "intent": intent,
                "score": round(score, 3),
                "feedback_count": sum(signals.get(intent, {}).values()),
                "memory_count": sum(
                    1
                    for memory in memory_rows
                    if isinstance(memory.applicability_json, dict)
                    and memory.applicability_json.get("intent") == intent
                ),
            }
            for intent, score in scores.items()
            if score > 0
        ]
        learned.sort(key=lambda item: (-float(item["score"]), str(item["intent"])))
        profile.learning_signals_json = signals
        profile.learned_intents_json = learned[:8]
        profile.last_learning_at = now
        profile.version += 1
        profile.updated_at = now
        self._append_change(
            profile,
            event_type,
            {
                "feedback_count": len(feedback_rows),
                "memory_count": len(memory_rows),
                "learned_intent_count": len(learned),
            },
        )
        self.session.flush()

    def _to_context(self, profile: OperatorPreferenceProfile) -> dict[str, Any]:
        learned = (
            profile.learned_intents_json
            if isinstance(profile.learned_intents_json, list)
            else []
        )
        suggestions: list[dict[str, str]] = []
        for service in profile.service_focus_json or []:
            suggestions.append(
                {
                    "key": f"service:{service}",
                    "label": f"检查 {service}",
                    "prompt": (
                        f"检查 {service} 当前健康、依赖关系、近期日志和配置变更，"
                        "使用独立证据核验根因"
                    ),
                    "source": "关注服务",
                }
            )
        for item in learned:
            if not isinstance(item, dict):
                continue
            intent = str(item.get("intent") or "")
            suggestion = _INTENT_SUGGESTIONS.get(intent)
            if suggestion is None:
                continue
            suggestions.append(
                {
                    "key": f"intent:{intent}",
                    "label": suggestion[0],
                    "prompt": suggestion[1],
                    "source": "近期偏好",
                }
            )
        return {
            "actor": profile.actor_key,
            "version": profile.version,
            "explicit": {
                "summary_density": profile.summary_density,
                "evidence_view": profile.evidence_view,
                "notification_route": profile.notification_route,
                "service_focus": list(profile.service_focus_json or []),
            },
            "learned": {
                "intents": learned,
                "signal_count": sum(
                    sum(int(value) for value in values.values())
                    for values in (profile.learning_signals_json or {}).values()
                    if isinstance(values, dict)
                ),
                "last_learning_at": (
                    profile.last_learning_at.isoformat()
                    if profile.last_learning_at
                    else None
                ),
            },
            "prompt_suggestions": suggestions[:5],
            "change_log": list(profile.change_log_json or [])[-8:],
            "safety_invariants": {
                "risk_levels_mutable": False,
                "approval_thresholds_mutable": False,
                "tool_permissions_mutable": False,
            },
        }

    @staticmethod
    def _append_change(
        profile: OperatorPreferenceProfile,
        event_type: str,
        details: dict[str, Any],
    ) -> None:
        changes = list(profile.change_log_json or [])
        changes.append(
            {
                "version": profile.version,
                "event_type": event_type,
                "occurred_at": utcnow().isoformat(),
                "details": details,
            }
        )
        profile.change_log_json = changes[-20:]


def _normalized_actor(actor: str) -> str:
    normalized = re.sub(r"\s+", " ", actor.strip())
    if not normalized:
        raise ValueError("actor is required")
    if len(normalized) > 128:
        raise ValueError("actor is too long")
    return normalized


def _normalized_services(values: list[str]) -> list[str]:
    result: list[str] = []
    for raw in values:
        value = re.sub(r"\s+", " ", str(raw).strip())
        if not value or value in result:
            continue
        if len(value) > 128:
            raise ValueError("service focus entry is too long")
        result.append(value)
        if len(result) == 8:
            break
    return result


def _age_days(now: datetime, value: datetime) -> float:
    return max(0.0, (now - _as_aware(value, now)).total_seconds() / 86400.0)


def _as_aware(value: datetime, reference: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=reference.tzinfo)
    return value
