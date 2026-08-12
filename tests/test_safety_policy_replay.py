from __future__ import annotations

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.models.entities import (
    Conversation,
    ConversationTurn,
    RiskChainAssessment,
    SafetyReview,
    Task,
)
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.policy_replay import SafetyPolicyReplayService


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    for table in (
        Task,
        Conversation,
        ConversationTurn,
        RiskChainAssessment,
        SafetyReview,
    ):
        table.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


class SafetyPolicyReplayServiceTest(unittest.TestCase):
    def test_current_static_policy_replays_consistently(self) -> None:
        with build_session() as session:
            task = Task(
                trace_id="policy-consistent",
                user_input="检查磁盘空间和 inode 使用情况",
                status="STATIC_REVIEW",
            )
            session.add(task)
            session.flush()
            review = SafetyEngine(session).review_user_request(
                task,
                task.user_input,
            )
            session.flush()

            report = SafetyPolicyReplayService(session).evaluate(task)

        self.assertEqual(report["status"], "consistent")
        self.assertEqual(report["evaluated_count"], 1)
        self.assertEqual(report["changed_count"], 0)
        self.assertEqual(report["rows"][0]["status"], "unchanged")
        self.assertEqual(len(review.policy_digest), 64)
        self.assertEqual(review.subject_json["kind"], "user_request")

    def test_stricter_current_policy_is_reported_as_tightened(self) -> None:
        with build_session() as session:
            task = Task(
                trace_id="policy-tightened",
                user_input="重启 managed-agent 服务",
                status="STATIC_REVIEW",
            )
            session.add(task)
            session.flush()
            policy = SafetyEngine.policy_identity()
            session.add(
                SafetyReview(
                    task_id=task.id,
                    review_type="static_user_intent",
                    risk_level="R0",
                    decision="ALLOW",
                    matched_rules_json=[
                        {
                            "rule_id": "read_only",
                            "label": "历史只读规则",
                            "risk_level": "R0",
                            "detail": "legacy",
                        }
                    ],
                    reason="历史策略允许。",
                    policy_version="historical-policy",
                    policy_digest=policy["digest"],
                    subject_json=SafetyEngine.user_review_subject(task.user_input),
                )
            )
            session.flush()

            report = SafetyPolicyReplayService(session).evaluate(task)

        self.assertEqual(report["status"], "drifted")
        self.assertEqual(report["changed_count"], 1)
        self.assertEqual(report["tightened_count"], 1)
        self.assertEqual(report["rows"][0]["status"], "tightened")
        self.assertEqual(report["rows"][0]["current_decision"], "APPROVAL_REQUIRED")

    def test_tampered_dynamic_subject_is_not_replayed(self) -> None:
        with build_session() as session:
            task = Task(
                trace_id="policy-subject-tampered",
                user_input="轮转应用日志",
                status="DYNAMIC_REVIEW",
            )
            session.add(task)
            session.flush()
            review = SafetyEngine(session).review_tool_action(
                task,
                "safe_log_rotate",
                {"path": "/tmp/application.log"},
            )
            session.flush()
            changed_subject = dict(review.subject_json)
            changed_subject["input"] = {"path": "/tmp/other.log"}
            review.subject_json = changed_subject
            session.flush()

            report = SafetyPolicyReplayService(session).evaluate(task)

        self.assertEqual(report["status"], "unavailable")
        self.assertEqual(report["evaluated_count"], 0)
        self.assertEqual(report["not_comparable_count"], 1)
        self.assertEqual(report["rows"][0]["status"], "not_comparable")
        self.assertIn("摘要校验失败", report["rows"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
