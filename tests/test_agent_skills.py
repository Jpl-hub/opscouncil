from __future__ import annotations

import unittest

from backend.app.agent.intent import IntentDecision
from backend.app.agent.planner import Planner
from backend.app.agent.skills import list_agent_skills


class AgentSkillsTest(unittest.TestCase):
    def test_every_skill_exposes_tools_used_by_planner(self) -> None:
        planner = Planner()
        skills = {skill["intent"]: skill for skill in list_agent_skills()}

        for intent, skill in skills.items():
            decision = IntentDecision(intent=intent, confidence=1.0)
            planned_tools = {call.tool_name for call in planner.create_plan(decision).tool_calls}
            skill_tools = {tool["name"] for tool in skill["tools"]}

            self.assertTrue(planned_tools.issubset(skill_tools), intent)
            self.assertGreaterEqual(len(skill["workflow"]), 3)
            self.assertGreaterEqual(len(skill["safety_gates"]), 1)
            self.assertTrue(skill["output_contract"])
            self.assertRegex(skill["version"], r"^\d+\.\d+\.\d+$")
            self.assertRegex(skill["catalog_version"], r"^\d+\.\d+\.\d+$")
            self.assertEqual(len(skill["catalog_hash"]), 64)
            self.assertIn("AUDIT", skill["control_nodes"])

    def test_skill_catalog_uses_user_facing_chinese_labels(self) -> None:
        disk_skill = next(skill for skill in list_agent_skills() if skill["intent"] == "disk_pressure_analysis")

        self.assertEqual(disk_skill["name"], "磁盘空间分析")
        self.assertIn("安全", " ".join(disk_skill["safety_gates"]))
        self.assertNotIn("disk_pressure_analysis", disk_skill["name"])


if __name__ == "__main__":
    unittest.main()
