from __future__ import annotations

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.models.entities import (
    OperationalMemory,
    OperatorFeedback,
    OperatorPreferenceProfile,
    Task,
)
from backend.app.operators.preferences import (
    OperatorPreferenceService,
    PreferenceVersionConflictError,
)


TABLES = [
    Task.__table__,
    OperationalMemory.__table__,
    OperatorFeedback.__table__,
    OperatorPreferenceProfile.__table__,
]


class OperatorPreferenceServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in TABLES:
            table.create(engine)
        self.session = Session(engine, expire_on_commit=False)
        self.service = OperatorPreferenceService(self.session)

    def tearDown(self) -> None:
        self.session.close()

    def test_feedback_learning_orders_prompts_without_mutating_safety(self) -> None:
        network_task = self._task("network_exposure_analysis")
        service_task = self._task("service_degradation_analysis")
        self.session.add_all(
            [
                OperatorFeedback(
                    task_id=network_task.id,
                    actor="local-admin",
                    verdict="HELPFUL",
                ),
                OperatorFeedback(
                    task_id=service_task.id,
                    actor="local-admin",
                    verdict="INCOMPLETE",
                ),
            ]
        )
        self.session.commit()

        context = self.service.context("local-admin")

        self.assertEqual(
            context["learned"]["intents"][0]["intent"],
            "network_exposure_analysis",
        )
        self.assertEqual(context["prompt_suggestions"][0]["label"], "网络暴露")
        self.assertEqual(
            context["safety_invariants"],
            {
                "risk_levels_mutable": False,
                "approval_thresholds_mutable": False,
                "tool_permissions_mutable": False,
            },
        )

    def test_manual_preferences_are_versioned_and_conflict_checked(self) -> None:
        current = self.service.context("local-admin")
        updated = self.service.update(
            "local-admin",
            expected_version=current["version"],
            summary_density="COMPACT",
            evidence_view="ALL",
            notification_route="BOTH",
            service_focus=["checkout-api", "inventory-db"],
        )

        self.assertGreater(updated["version"], current["version"])
        self.assertEqual(updated["explicit"]["summary_density"], "COMPACT")
        self.assertEqual(updated["explicit"]["service_focus"], ["checkout-api", "inventory-db"])
        self.assertEqual(updated["prompt_suggestions"][0]["source"], "关注服务")
        with self.assertRaises(PreferenceVersionConflictError):
            self.service.update(
                "local-admin",
                expected_version=current["version"],
                summary_density="BALANCED",
                evidence_view="CORE",
                notification_route="WEB",
                service_focus=[],
            )

    def test_learned_preferences_can_be_forgotten_without_erasing_manual_settings(self) -> None:
        task = self._task("config_integrity_analysis")
        self.session.add(
            OperatorFeedback(
                task_id=task.id,
                actor="local-admin",
                verdict="HELPFUL",
            )
        )
        self.session.commit()
        learned = self.service.context("local-admin")
        self.service.update(
            "local-admin",
            expected_version=learned["version"],
            summary_density="DETAILED",
            evidence_view="CORE",
            notification_route="WEB",
            service_focus=["sshd"],
        )

        forgotten = self.service.forget_learned(
            "local-admin",
            reason="岗位调整，不再沿用近期任务偏好",
        )

        self.assertEqual(forgotten["learned"]["intents"], [])
        self.assertEqual(forgotten["explicit"]["summary_density"], "DETAILED")
        self.assertEqual(forgotten["explicit"]["service_focus"], ["sshd"])
        self.assertEqual(
            forgotten["change_log"][-1]["event_type"],
            "LEARNED_PREFERENCES_FORGOTTEN",
        )

    def _task(self, intent: str) -> Task:
        task = Task(
            trace_id=f"trace-{intent}-{self.session.query(Task).count()}",
            user_input="测试请求",
            intent=intent,
            status="SEALED",
            risk_level="R0",
            summary="测试摘要",
        )
        self.session.add(task)
        self.session.flush()
        return task


if __name__ == "__main__":
    unittest.main()
