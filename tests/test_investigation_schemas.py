from __future__ import annotations

import unittest

from backend.app.investigation.schemas import (
    DecisionContractError,
    InvestigationDecision,
    validate_decision_shape,
)


def collect_payload() -> dict:
    return {
        "decision": "COLLECT",
        "hypotheses": [
            {
                "key": "disk_log_growth",
                "title": "日志持续增长",
                "rationale": "磁盘证据指向日志目录",
                "evidence_gap": "缺少大文件路径",
            }
        ],
        "evidence_links": [],
        "next_tool": {
            "tool_name": "find_large_files",
            "arguments": {"roots": ["/var/log"]},
            "reason": "定位容量增长源",
        },
        "conclusion": None,
        "stop_reason": "需要补充大文件证据",
    }


def conclusion_payload() -> dict:
    return {
        "decision": "CONCLUDE",
        "hypotheses": [
            {
                "key": "disk_log_growth",
                "title": "日志持续增长",
                "rationale": "大文件与分区用量证据一致",
                "evidence_gap": "尚未执行处置后验证",
            }
        ],
        "evidence_links": [
            {
                "hypothesis_key": "disk_log_growth",
                "evidence_id": 12,
                "relation": "SUPPORTS",
                "rationale": "大文件位于日志目录",
            }
        ],
        "next_tool": None,
        "conclusion": {
            "conclusion": "磁盘压力主要来自持续增长的日志。",
            "root_cause": "日志文件缺少轮转并持续增长。",
            "risk_level": "R2",
            "reasoning_summary": ["磁盘用量与大文件证据相互印证。"],
            "recommended_actions": [],
            "evidence_used": [],
            "residual_risk": "处置前仍需审批并保留备份。",
        },
        "stop_reason": "关键根因已有两类证据支持",
    }


class InvestigationSchemaTest(unittest.TestCase):
    def test_collect_requires_one_follow_up_tool_and_no_conclusion(self) -> None:
        decision = InvestigationDecision.model_validate(collect_payload())

        validate_decision_shape(decision)

        assert decision.next_tool is not None
        self.assertEqual(decision.next_tool.tool_name, "find_large_files")
        self.assertIsNone(decision.conclusion)

    def test_collect_without_tool_is_rejected(self) -> None:
        payload = collect_payload()
        payload["next_tool"] = None
        decision = InvestigationDecision.model_validate(payload)

        with self.assertRaisesRegex(DecisionContractError, "COLLECT.*next_tool"):
            validate_decision_shape(decision)

    def test_collect_with_conclusion_is_rejected(self) -> None:
        payload = collect_payload()
        payload["conclusion"] = conclusion_payload()["conclusion"]
        decision = InvestigationDecision.model_validate(payload)

        with self.assertRaisesRegex(DecisionContractError, "COLLECT.*conclusion"):
            validate_decision_shape(decision)

    def test_conclude_requires_conclusion_and_forbids_tool(self) -> None:
        payload = conclusion_payload()
        payload["next_tool"] = collect_payload()["next_tool"]
        decision = InvestigationDecision.model_validate(payload)

        with self.assertRaisesRegex(DecisionContractError, "CONCLUDE.*next_tool"):
            validate_decision_shape(decision)

    def test_evidence_link_must_reference_a_declared_hypothesis(self) -> None:
        payload = conclusion_payload()
        payload["evidence_links"][0]["hypothesis_key"] = "invented_hypothesis"
        decision = InvestigationDecision.model_validate(payload)

        with self.assertRaisesRegex(DecisionContractError, "invented_hypothesis"):
            validate_decision_shape(decision)

    def test_duplicate_hypothesis_keys_are_rejected(self) -> None:
        payload = collect_payload()
        payload["hypotheses"].append(dict(payload["hypotheses"][0]))
        decision = InvestigationDecision.model_validate(payload)

        with self.assertRaisesRegex(DecisionContractError, "duplicate hypothesis"):
            validate_decision_shape(decision)

    def test_hypothesis_key_must_be_stable_ascii_identifier(self) -> None:
        payload = collect_payload()
        payload["hypotheses"][0]["key"] = "日志增长"

        with self.assertRaises(ValueError):
            InvestigationDecision.model_validate(payload)

    def test_unknown_fields_are_rejected(self) -> None:
        payload = collect_payload()
        payload["shell_command"] = "rm -rf /"

        with self.assertRaises(ValueError):
            InvestigationDecision.model_validate(payload)


if __name__ == "__main__":
    unittest.main()
