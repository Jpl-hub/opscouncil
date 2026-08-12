from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import build_router
from backend.app.core.database import get_session
from backend.app.models.entities import (
    AIAnalysis,
    ActionProposal,
    ActionSafetyCase,
    AuditChain,
    ExecutionRecord,
    EvidenceItem,
    Hypothesis,
    HypothesisEvidence,
    Investigation,
    InvestigationStep,
    RiskChainAssessment,
    SafetyReview,
    Task,
    TaskEvent,
    ToolCall,
)


class EmptyRegistry:
    def list_tools(self) -> list[dict]:
        return []


class InvestigationApiTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in [
            Task.__table__,
            TaskEvent.__table__,
            ToolCall.__table__,
            Investigation.__table__,
            InvestigationStep.__table__,
            RiskChainAssessment.__table__,
            EvidenceItem.__table__,
            Hypothesis.__table__,
            HypothesisEvidence.__table__,
            SafetyReview.__table__,
            ActionProposal.__table__,
            ActionSafetyCase.__table__,
            ExecutionRecord.__table__,
            AIAnalysis.__table__,
            AuditChain.__table__,
        ]:
            table.create(engine)
        self.session = Session(engine, expire_on_commit=False)
        task = Task(
            trace_id="trace-api-investigation",
            user_input="检查端口暴露",
            intent="network_exposure_analysis",
            status="SEALED",
            risk_level="R0",
            summary="发现 1 个监听端口。",
        )
        self.session.add(task)
        self.session.flush()
        self.task_id = task.id
        self.session.add(
            ToolCall(
                task_id=task.id,
                tool_name="network_listeners",
                tool_version="1.0.0",
                input_json={"limit": 80},
                output_json={
                    "status": "ok",
                    "observations": [{"local_address": "127.0.0.1:8000"}],
                    "evidence_refs": ["ss -H -lntup"],
                },
                risk_level="R0",
                status="ok",
                duration_ms=9,
            )
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

    def test_read_task_investigation(self) -> None:
        response = self.client.get(f"/api/tasks/{self.task_id}/investigation")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["task"]["trace_id"], "trace-api-investigation")
        self.assertEqual(body["evidence_items"][0]["tool_name"], "network_listeners")

    def test_read_missing_task_investigation_returns_404(self) -> None:
        response = self.client.get("/api/tasks/999/investigation")

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
