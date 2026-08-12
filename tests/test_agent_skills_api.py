from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.api.routes import build_router


class EmptyRegistry:
    def list_tools(self) -> list[dict]:
        return []


class AgentSkillsApiTest(unittest.TestCase):
    def setUp(self) -> None:
        app = FastAPI()
        app.include_router(build_router(EmptyRegistry()))  # type: ignore[arg-type]
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()

    def test_list_agent_skills_returns_catalog(self) -> None:
        response = self.client.get("/api/agent/skills")

        self.assertEqual(response.status_code, 200)
        skills = response.json()
        self.assertGreaterEqual(len(skills), 6)
        skills_by_id = {skill["id"]: skill for skill in skills}
        self.assertIn("skill.disk_pressure_analysis", skills_by_id)
        disk_skill = skills_by_id["skill.disk_pressure_analysis"]
        self.assertIn("tools", disk_skill)
        self.assertIn("workflow", disk_skill)


if __name__ == "__main__":
    unittest.main()
