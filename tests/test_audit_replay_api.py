from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import build_router
from backend.app.audit.service import AuditService
from backend.app.core.database import get_session
from backend.app.models.entities import (
    AuditChain,
    Conversation,
    ConversationTurn,
    SafetyReview,
    Task,
    TaskEvent,
)
from backend.app.safety.engine import SafetyEngine


class EmptyRegistry:
    def list_tools(self) -> list[dict]:
        return []


class AuditReplayApiTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        Task.__table__.create(engine)
        Conversation.__table__.create(engine)
        ConversationTurn.__table__.create(engine)
        TaskEvent.__table__.create(engine)
        SafetyReview.__table__.create(engine)
        AuditChain.__table__.create(engine)
        self.session = Session(engine, expire_on_commit=False)

        task = Task(trace_id="trace-api", user_input="检查磁盘", status="RECEIVED")
        self.session.add(task)
        self.session.flush()
        policy = SafetyEngine.policy_identity()
        self.session.add(
            SafetyReview(
                task_id=task.id,
                review_type="static_user_intent",
                risk_level="R0",
                decision="ALLOW",
                matched_rules_json=[
                    {
                        "rule_id": "read_only",
                        "label": "只读诊断或咨询请求",
                        "risk_level": "R0",
                        "detail": "default",
                    }
                ],
                reason="允许只读感知。",
                policy_version=policy["version"],
                policy_digest=policy["digest"],
                subject_json=SafetyEngine.user_review_subject(task.user_input),
            )
        )
        audit = AuditService(self.session)
        audit.append_event(
            task,
            "RECEIVED",
            "task_created",
            "接收自然语言运维请求。",
            {"user_input": task.user_input},
        )
        audit.append_event(
            task,
            "STATIC_REVIEW",
            "safety_review",
            "未命中禁止规则，允许继续只读感知。",
            {"decision": "ALLOW", "risk_level": "R0"},
        )
        self.session.commit()

        app = FastAPI()
        app.include_router(build_router(EmptyRegistry()))  # type: ignore[arg-type]

        def override_session():
            yield self.session

        app.dependency_overrides[get_session] = override_session
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        self.session.close()

    def test_read_audit_replay_returns_verified_stage_summary(self) -> None:
        response = self.client.get("/api/audit/traces/trace-api/replay")

        self.assertEqual(response.status_code, 200)
        replay = response.json()
        self.assertEqual(replay["trace_id"], "trace-api")
        self.assertTrue(replay["integrity"]["valid"])
        self.assertEqual(replay["integrity"]["entry_count"], 2)
        self.assertEqual(replay["current_stage"], "安全校验")
        self.assertEqual(replay["stages"][0]["label"], "接收指令")
        self.assertEqual(replay["stages"][0]["status"], "passed")
        self.assertEqual(replay["stages"][1]["status"], "passed")
        self.assertEqual(replay["decision_points"][0]["label"], "安全校验")
        self.assertEqual(replay["policy_replay"]["status"], "consistent")
        self.assertEqual(replay["policy_replay"]["evaluated_count"], 1)
        self.assertEqual(replay["policy_replay"]["changed_count"], 0)


if __name__ == "__main__":
    unittest.main()
