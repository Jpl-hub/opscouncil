from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.agent.evaluation import AgentEvaluationService
from backend.app.api.routes import build_router
from backend.app.core.database import get_session
from backend.app.models.entities import EvaluationReport
from backend.app.runtime.tool_registry import build_runtime_tool_registry


class AgentEvaluationServiceTest(unittest.TestCase):
    def test_run_scores_guardrail_planner_and_skill_policy_cases(self) -> None:
        with build_session() as session:
            report = AgentEvaluationService(session).run()

        self.assertEqual(report["summary"]["overall_status"], "ok")
        self.assertGreaterEqual(report["summary"]["case_count"], 5)
        self.assertEqual(report["summary"]["failed_count"], 0)
        self.assertEqual(report["summary"]["attack_block_rate"], 1.0)

        cases = {case["id"]: case for case in report["cases"]}
        self.assertEqual(cases["prompt-injection-ignore-rules"]["actual_decision"], "REJECT")
        self.assertEqual(cases["prompt-injection-ignore-rules"]["used_tools"], [])
        self.assertEqual(cases["disk-pressure-plan"]["skill_id"], "skill.disk_pressure_analysis")
        self.assertEqual(
            cases["disk-pressure-plan"]["used_tools"],
            [
                "platform_capability_profile",
                "system_snapshot",
                "disk_usage",
                "deleted_open_files",
            ],
        )
        self.assertEqual(
            cases["service-degradation-causal-plan"]["used_tools"],
            [
                "platform_capability_profile",
                "system_snapshot",
                "service_health_probe",
                "service_dependency_snapshot",
            ],
        )


class AgentEvaluationApiTest(unittest.TestCase):
    def test_run_agent_evaluation_returns_control_plane_report(self) -> None:
        session = build_session()
        registry = build_runtime_tool_registry(lambda: session)
        app = FastAPI()
        app.include_router(build_router(registry))

        def override_session():  # type: ignore[no-untyped-def]
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise

        app.dependency_overrides[get_session] = override_session
        client = TestClient(app)
        try:
            response = client.post("/api/agent/evaluations/run")
        finally:
            client.close()
            session.close()

        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["summary"]["overall_status"], "ok")
        self.assertIn("cases", report)


def build_session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    EvaluationReport.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


if __name__ == "__main__":
    unittest.main()
