from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import build_router
from backend.app.core.database import get_session
from backend.app.models.entities import Task, TaskJob, WorkerInstance, utcnow


class FakeRegistry:
    def list_tools(self) -> list[dict]:
        return [{"name": "system_snapshot"}, {"name": "config_integrity_scan"}]


class HealthApiTest(unittest.TestCase):
    def test_health_reports_operational_dependencies_without_secrets(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        Task.__table__.create(engine)
        TaskJob.__table__.create(engine)
        WorkerInstance.__table__.create(engine)
        with Session(engine) as session:
            now = utcnow()
            session.add(
                WorkerInstance(
                    worker_id="worker-health-test",
                    hostname="test-host",
                    pid=1001,
                    status="RUNNING",
                    started_at=now,
                    last_seen_at=now,
                    updated_at=now,
                )
            )
            session.commit()
        app = FastAPI()
        app.include_router(build_router(FakeRegistry()))  # type: ignore[arg-type]

        def override_session():
            with Session(engine, expire_on_commit=False) as session:
                yield session

        app.dependency_overrides[get_session] = override_session
        client = TestClient(app)
        try:
            response = client.get("/api/health")
            worker_response = client.get("/api/runtime/worker")
        finally:
            client.close()

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["database"]["status"], "ok")
        self.assertEqual(body["mcp"]["tool_count"], 2)
        self.assertEqual(body["worker"]["overall_status"], "ok")
        self.assertEqual(body["worker"]["online_worker_count"], 1)
        self.assertEqual(worker_response.status_code, 200)
        self.assertEqual(worker_response.json()["overall_status"], "ok")
        self.assertIn("configured", body["ai"])
        self.assertNotIn("api_key", str(body).lower())
        self.assertNotIn("bearer", str(body).lower())


if __name__ == "__main__":
    unittest.main()
