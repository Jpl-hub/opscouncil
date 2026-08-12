from __future__ import annotations

import unittest

from backend.app.ai.analysis import AIAnalysisResult
from backend.app.ai.analysis import _contains_shell_command
from backend.app.ai.analysis import _normalize_analysis_payload


class AIAnalysisSchemaTest(unittest.TestCase):
    def test_shell_command_detection_handles_chinese_prefix_without_matching_word_suffixes(self) -> None:
        self.assertTrue(_contains_shell_command("请调用systemctl show查看服务状态。"))
        self.assertTrue(_contains_shell_command("再用cat /etc/hosts核对配置。"))
        self.assertFalse(_contains_shell_command("继续核查 SSH 服务配置。"))
        self.assertFalse(_contains_shell_command("compare process status with the baseline"))

    def test_normalizes_common_model_analysis_shapes(self) -> None:
        result = AIAnalysisResult.model_validate(
            {
                "conclusion": "网络暴露面已完成只读分析。",
                "root_cause": "主机存在多个监听端口。",
                "risk_level": "R1（低风险）",
                "reasoning_summary": "工具 network_listeners 返回监听端口证据。",
                "recommended_actions": [
                    {
                        "title": "复核监听端口",
                        "rationale": "确认业务必要性。",
                        "safety_gate": "只读确认，不修改服务配置。",
                    }
                ],
                "evidence_used": [
                    "ss -H -lntup (from network_listeners)",
                    {"tool": "system_snapshot", "count": 1},
                ],
                "residual_risk": "仍需人工确认端口是否面向外部网络。",
            }
        )

        self.assertEqual(result.reasoning_summary, ["工具网络监听返回监听端口证据。"])
        self.assertEqual(result.risk_level, "R1")
        self.assertEqual(
            result.evidence_used,
            [
                {
                    "source": "ss -H -lntup (from network_listeners)",
                    "summary": "ss -H -lntup (from network_listeners)",
                },
                {"tool": "system_snapshot", "count": "1"},
            ],
        )

    def test_normalizes_text_recommended_action(self) -> None:
        result = AIAnalysisResult.model_validate(
            {
                "conclusion": "磁盘日志已完成分析。",
                "root_cause": "应用日志持续增长。",
                "risk_level": "R2",
                "reasoning_summary": [],
                "recommended_actions": "将该日志路径纳入轮转策略，并经审批后执行。",
                "evidence_used": [],
                "residual_risk": "仍需观察后续日志增长速度。",
            }
        )

        self.assertEqual(result.recommended_actions[0].title, "补充核查")
        self.assertIn("轮转策略", result.recommended_actions[0].rationale)
        self.assertEqual(
            result.recommended_actions[0].safety_gate,
            "仅作为建议；实际动作需重新进入计划与安全校验。",
        )

    def test_humanizes_internal_tool_names_only_in_user_facing_narrative(self) -> None:
        result = AIAnalysisResult.model_validate(
            {
                "conclusion": "service_status 与 journal_query 未发现异常。",
                "root_cause": "system_snapshot 显示资源正常。",
                "risk_level": "R0",
                "reasoning_summary": ["network_listeners 返回 2 条观测。"],
                "recommended_actions": [
                    {
                        "title": "继续使用 service_status 复核",
                        "rationale": "必要时再次调用 journal_query。",
                        "safety_gate": "保持只读",
                    }
                ],
                "evidence_used": [
                    {"source": "MCP:service_status", "summary": "service_status 返回 0 条观测。"}
                ],
                "residual_risk": "config_integrity_scan 尚未执行。",
            }
        )

        self.assertEqual(result.conclusion, "服务状态与系统日志查询未发现异常。")
        self.assertEqual(result.root_cause, "系统快照显示资源正常。")
        self.assertEqual(result.reasoning_summary, ["网络监听返回 2 条观测。"])
        self.assertEqual(result.recommended_actions[0].title, "继续使用服务状态复核")
        self.assertEqual(result.recommended_actions[0].rationale, "必要时再次调用系统日志查询。")
        self.assertEqual(result.residual_risk, "配置完整性检查尚未执行。")
        self.assertEqual(result.evidence_used[0]["source"], "MCP:service_status")

    def test_normalizes_common_chinese_alias_fields_before_schema_validation(self) -> None:
        payload = _normalize_analysis_payload(
            {
                "结论": "配置采样完成。",
                "根因": "hosts 文件元数据变化。",
                "风险等级": "R2",
                "判断依据": ["config_integrity_scan 返回变化。"],
                "处置建议": ["先复核变更来源。"],
                "引用证据": ["MCP:config_integrity_scan"],
                "残余风险": "仍需确认是否为授权变更。",
            }
        )

        result = AIAnalysisResult.model_validate(payload)

        self.assertEqual(result.conclusion, "配置采样完成。")
        self.assertEqual(result.root_cause, "hosts 文件元数据变化。")
        self.assertEqual(result.risk_level, "R2")
        self.assertEqual(result.reasoning_summary, ["配置完整性检查返回变化。"])
        self.assertEqual(result.recommended_actions[0].rationale, "先复核变更来源。")


if __name__ == "__main__":
    unittest.main()
