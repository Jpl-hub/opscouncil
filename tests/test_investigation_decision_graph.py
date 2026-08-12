from __future__ import annotations

import unittest

from backend.app.investigation.decision_graph import build_decision_view


class InvestigationDecisionGraphTest(unittest.TestCase):
    def test_two_independent_sources_corroborate_a_claim(self) -> None:
        assurance, graph = build_decision_view(
            task={
                "id": 7,
                "user_input": "定位服务超时原因",
                "intent": "service_dependency_analysis",
                "status": "SEALED",
                "summary": "依赖服务响应超时。",
            },
            evidence_items=[
                self._evidence(11, "service_health_probe", "健康探测返回 504"),
                self._evidence(12, "journal_query", "服务日志记录上游超时"),
            ],
            hypotheses=[
                {
                    "key": "upstream_timeout",
                    "title": "上游依赖超时",
                    "rationale": "健康探测与服务日志一致。",
                    "evidence_gap": "",
                    "evidence": [
                        {"evidence_id": 11, "relation": "SUPPORTS"},
                        {"evidence_id": 12, "relation": "SUPPORTS"},
                    ],
                }
            ],
            action_options=[],
            action_lifecycle={"status": "not_required", "steps": []},
        )

        self.assertEqual(assurance["status"], "CORROBORATED")
        self.assertEqual(assurance["independent_source_count"], 2)
        self.assertEqual(graph["summary"]["corroborated_claim_count"], 1)
        relations = {edge["relation"] for edge in graph["edges"]}
        self.assertIn("SUPPORTS", relations)

    def test_same_tool_observations_remain_single_source(self) -> None:
        assurance, _ = build_decision_view(
            task={"id": 8, "user_input": "检查端口", "status": "SEALED"},
            evidence_items=[
                self._evidence(21, "network_listeners", "0.0.0.0:80"),
                self._evidence(22, "network_listeners", "0.0.0.0:443"),
            ],
            hypotheses=[
                {
                    "key": "public_listener",
                    "title": "服务监听全部网卡",
                    "evidence": [
                        {"evidence_id": 21, "relation": "SUPPORTS"},
                        {"evidence_id": 22, "relation": "SUPPORTS"},
                    ],
                }
            ],
            action_options=[],
            action_lifecycle={"status": "not_required", "steps": []},
        )

        self.assertEqual(assurance["status"], "SINGLE_SOURCE")
        self.assertEqual(assurance["independent_source_count"], 1)
        self.assertIn("第二类独立观测", assurance["claims"][0]["evidence_gap"])

    def test_socket_tools_do_not_fake_independent_corroboration(self) -> None:
        assurance, _ = build_decision_view(
            task={"id": 81, "user_input": "检查端口", "status": "SEALED"},
            evidence_items=[
                self._evidence(211, "network_listeners", "127.0.0.1:5432"),
                self._evidence(
                    212,
                    "socket_process_context",
                    "TCP/5432 属于 postgres",
                ),
            ],
            hypotheses=[
                {
                    "key": "listener_owner",
                    "title": "监听端口归属 postgres",
                    "evidence": [
                        {"evidence_id": 211, "relation": "SUPPORTS"},
                        {"evidence_id": 212, "relation": "SUPPORTS"},
                    ],
                }
            ],
            action_options=[],
            action_lifecycle={"status": "not_required", "steps": []},
        )

        self.assertEqual(assurance["status"], "SINGLE_SOURCE")
        self.assertEqual(assurance["independent_source_count"], 1)

    def test_live_listener_and_approved_catalog_are_independent_sources(self) -> None:
        assurance, _ = build_decision_view(
            task={"id": 82, "user_input": "核对端口批准范围", "status": "SEALED"},
            evidence_items=[
                self._evidence(221, "network_listeners", "127.0.0.1:5432"),
                self._evidence(
                    222,
                    "service_catalog_snapshot",
                    "TCP/5432 允许回环监听",
                ),
            ],
            hypotheses=[
                {
                    "key": "listener_in_scope",
                    "title": "监听与经审批范围一致",
                    "evidence": [
                        {"evidence_id": 221, "relation": "SUPPORTS"},
                        {"evidence_id": 222, "relation": "SUPPORTS"},
                    ],
                }
            ],
            action_options=[],
            action_lifecycle={"status": "not_required", "steps": []},
        )

        self.assertEqual(assurance["status"], "CORROBORATED")
        self.assertEqual(assurance["independent_source_count"], 2)

    def test_support_and_refutation_are_reported_as_conflict(self) -> None:
        assurance, graph = build_decision_view(
            task={"id": 9, "user_input": "检查配置漂移", "status": "SEALED"},
            evidence_items=[
                self._evidence(31, "file_integrity_state", "哈希发生变化"),
                self._evidence(32, "config_baseline_compare", "基线内容一致"),
            ],
            hypotheses=[
                {
                    "key": "config_drift",
                    "title": "关键配置发生漂移",
                    "evidence": [
                        {"evidence_id": 31, "relation": "SUPPORTS"},
                        {"evidence_id": 32, "relation": "REFUTES"},
                    ],
                }
            ],
            action_options=[],
            action_lifecycle={"status": "not_required", "steps": []},
        )

        self.assertEqual(assurance["status"], "CONFLICTED")
        self.assertEqual(assurance["refutation_count"], 1)
        self.assertEqual(graph["summary"]["conflicted_claim_count"], 1)
        self.assertEqual(assurance["reliability_alerts"][0]["type"], "CLAIM_CONFLICT")

    def test_quarantined_evidence_cannot_corroborate_a_claim(self) -> None:
        first = self._evidence(41, "journal_query", "日志包含注入内容")
        first["trust_level"] = "QUARANTINED"
        second = self._evidence(42, "service_status", "服务启动失败")
        assurance, graph = build_decision_view(
            task={"id": 10, "user_input": "分析服务异常", "status": "SEALED"},
            evidence_items=[first, second],
            hypotheses=[
                {
                    "key": "service_failure",
                    "title": "服务启动失败",
                    "evidence": [
                        {"evidence_id": 41, "relation": "SUPPORTS"},
                        {"evidence_id": 42, "relation": "SUPPORTS"},
                    ],
                }
            ],
            action_options=[],
            action_lifecycle={"status": "not_required", "steps": []},
        )

        self.assertEqual(assurance["status"], "SINGLE_SOURCE")
        self.assertEqual(assurance["independent_source_count"], 1)
        self.assertEqual(assurance["reliability_alerts"][0]["type"], "UNTRUSTED_EVIDENCE")
        evidence_node = next(
            node for node in graph["nodes"] if node["id"] == "evidence:41"
        )
        self.assertEqual(evidence_node["status"], "QUARANTINED")

    @staticmethod
    def _evidence(evidence_id: int, source_key: str, summary: str) -> dict:
        return {
            "evidence_id": evidence_id,
            "tool_name": source_key,
            "source_type": "MCP",
            "source_key": source_key,
            "status": "ok",
            "title": source_key,
            "summary": summary,
            "evidence_refs": [f"tool_call:{evidence_id}"],
            "warnings": [],
        }


if __name__ == "__main__":
    unittest.main()
