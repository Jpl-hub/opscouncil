from __future__ import annotations

from types import SimpleNamespace
import unittest

from backend.app.agent.responder import AgentResponder


class AgentResponderTest(unittest.TestCase):
    def test_keeps_mcp_fact_summary_authoritative_over_model_claims(self) -> None:
        responder = AgentResponder()
        task = SimpleNamespace(risk_level="R1")
        analysis = {
            "conclusion": "发现 9 个公网监听，主机已经暴露。",
            "root_cause": "推测存在未经授权的远程服务。",
            "risk_level": "R3",
            "reasoning_summary": ["9 个端口绑定公网地址"],
            "recommended_actions": [
                {
                    "title": "补充归属核查",
                    "rationale": "先确认未归属端口对应的进程和服务。",
                    "safety_gate": "仅执行只读核查",
                    "tool_name": "network_listeners",
                }
            ],
            "evidence_used": [],
            "residual_risk": "未归属端口仍需人工确认。",
        }
        canonical = (
            "当前未发现公网或全地址监听；10 个监听中 6 个已关联进程，"
            "4 个仍需补充归属。本轮未修改网络配置。"
        )

        reply = responder.compose(task, analysis, canonical)

        self.assertTrue(reply.startswith(canonical))
        self.assertNotIn("9 个公网监听", reply)
        self.assertNotIn("主机已经暴露", reply)
        self.assertNotIn("未经授权的远程服务", reply)
        self.assertIn("研判建议：先确认未归属端口对应的进程和服务", reply)
        self.assertIn("待确认风险：未归属端口仍需人工确认", reply)

    def test_appends_validated_diagnosis_advice_without_calling_another_model(self) -> None:
        responder = AgentResponder()
        task = SimpleNamespace(
            id=7,
            trace_id="trace-7",
            user_input="检查端口暴露",
            intent="network_exposure_analysis",
            status="SUMMARIZE",
            risk_level="R1",
        )
        analysis = {
            "conclusion": "已完成只读检查，发现 2 个非回环监听。",
            "root_cause": "监听端口来自两个已识别的业务进程。",
            "risk_level": "R1",
            "reasoning_summary": ["network_listeners 返回 12 个监听套接字", "2 个绑定在非回环地址"],
            "recommended_actions": [
                {
                    "title": "确认业务归属",
                    "rationale": "先核对端口对应服务，再决定是否收敛暴露面。",
                    "safety_gate": "涉及服务变更时进入人工审批",
                    "tool_name": None,
                }
            ],
            "evidence_used": [{"source": "ss -H -lntup", "summary": "监听端口证据"}],
            "residual_risk": "本次未修改防火墙、服务或配置。",
        }

        reply = responder.compose(
            task,
            analysis,
            canonical_summary="已完成网络暴露面只读分析，发现 12 个监听套接字。未执行系统变更。",
        )

        self.assertTrue(reply.startswith("已完成网络暴露面只读分析"))
        self.assertNotIn("2 个非回环监听", reply)
        self.assertNotIn("监听端口来自两个已识别的业务进程", reply)
        self.assertIn("研判建议", reply)
        self.assertIn("未修改防火墙", reply)

    def test_sanitizes_markdown_and_shell_like_analysis_text(self) -> None:
        responder = AgentResponder()
        task = SimpleNamespace(risk_level="R2")
        analysis = {
            "conclusion": "```bash\nrm -rf /tmp/x\n```\n已完成分析。",
            "root_cause": "- 发现大日志",
            "risk_level": "R2",
            "reasoning_summary": ["1. 日志持续增长", "2. 磁盘空间下降"],
            "recommended_actions": [
                {
                    "title": "安全处置",
                    "rationale": "先审批\n再执行",
                    "safety_gate": "人工审批",
                    "tool_name": None,
                }
            ],
            "evidence_used": [],
            "residual_risk": "**未执行删除**",
        }

        reply = responder.compose(
            task,
            analysis,
            canonical_summary="已生成需审批的安全轮转建议。",
        )

        self.assertNotIn("```", reply)
        self.assertNotIn("rm -rf", reply)
        self.assertTrue(reply.startswith("已生成需审批的安全轮转建议"))
        self.assertIn("先审批", reply)
        self.assertIn("未执行删除", reply)

    def test_uses_canonical_summary_when_diagnosis_is_unavailable(self) -> None:
        responder = AgentResponder()

        reply = responder.compose(
            SimpleNamespace(risk_level="R0"),
            None,
            canonical_summary="已完成系统健康只读巡检，未执行系统变更。",
        )

        self.assertEqual(reply, "已完成系统健康只读巡检，未执行系统变更。")

    def test_humanizes_internal_diagnostic_field_names(self) -> None:
        responder = AgentResponder()

        reply = responder.compose(
            SimpleNamespace(risk_level="R0"),
            {
                "recommended_actions": [
                    {
                        "rationale": "持续观察 fd_utilization_percent 与 open_fd_count。",
                    }
                ],
                "residual_risk": "systemd_unit 已识别，fd_type_counts 尚无时间序列。",
            },
            canonical_summary="已完成进程只读分析。",
        )

        self.assertIn("文件句柄使用率与打开句柄数", reply)
        self.assertIn("服务单元已识别，句柄类型分布尚无时间序列", reply)
        self.assertNotIn("fdutilizationpercent", reply)

    def test_humanizes_network_scope_fields(self) -> None:
        responder = AgentResponder()

        reply = responder.compose(
            SimpleNamespace(risk_level="R1"),
            {
                "recommended_actions": [
                    {"rationale": "继续核验 exposure_scope=private 的监听归属。"}
                ],
                "residual_risk": "exposurescope=loopback 的端口尚缺服务单元。",
            },
            canonical_summary="已完成网络监听核验。",
        )

        self.assertIn("暴露范围为内网", reply)
        self.assertIn("暴露范围为本机回环", reply)
        self.assertNotIn("exposure", reply.lower())


if __name__ == "__main__":
    unittest.main()
