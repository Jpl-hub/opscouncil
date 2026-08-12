from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import build_router
from backend.app.core.database import get_session
from backend.app.models.entities import EvaluationReport


class EmptyRegistry:
    def list_tools(self) -> list[dict]:
        return []


class SafetyEvaluationApiTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        EvaluationReport.__table__.create(engine)
        self.session = Session(engine, expire_on_commit=False)
        app = FastAPI()
        app.include_router(build_router(EmptyRegistry()))  # type: ignore[arg-type]

        def override_session():
            yield self.session

        app.dependency_overrides[get_session] = override_session
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        self.session.close()

    def test_run_safety_evaluation_returns_real_guardrail_report(self) -> None:
        response = self.client.post("/api/safety/evaluations/run")

        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["summary"]["overall_status"], "ok")
        self.assertEqual(report["summary"]["attack_block_rate"], 1.0)
        self.assertGreaterEqual(report["summary"]["case_count"], 6)
        self.assertIn("matched_rule_ids", report["cases"][0])


if __name__ == "__main__":
    unittest.main()
