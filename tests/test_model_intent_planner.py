from __future__ import annotations

import unittest

from pydantic import ValidationError

from backend.app.agent.intent import IntentDecision, IntentResolver
from backend.app.agent.planner import Planner
from backend.app.ai.client import ModelNotConfiguredError


class FakeModelClient:
    chat_model = "fake-qwen"

    def __init__(self, response: dict | None = None, error: Exception | None = None) -> None:
        self.response = response or {}
        self.error = error
        self.messages: list[dict[str, str]] = []

    def chat_json(self, messages: list[dict[str, str]], max_tokens: int = 900) -> dict:
        self.messages = messages
        if self.error is not None:
            raise self.error
        return self.response


class ModelIntentPlannerTest(unittest.TestCase):
    def test_model_intent_drives_network_plan_without_keyword_branch(self) -> None:
        model = FakeModelClient(
            {
                "intent": "network_exposure_analysis",
                "confidence": 0.92,
                "risk_hints": ["监听端口需要核查"],
                "slots": {},
                "reasoning_summary": ["用户关注主机网络暴露面"],
            }
        )

        resolved = IntentResolver(model).resolve("帮我看看这台机器有没有暴露风险")
        plan = Planner().create_plan(resolved.decision)

        self.assertEqual(resolved.provider, "bailian")
        self.assertEqual(resolved.model, "fake-qwen")
        self.assertEqual(plan.intent, "network_exposure_analysis")
        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            [
                "platform_capability_profile",
                "system_snapshot",
                "network_listeners",
                "service_catalog_snapshot",
            ],
        )
        self.assertIn("白名单意图", model.messages[1]["content"])

    def test_explicit_port_requires_targeted_socket_evidence(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "network_exposure_analysis", "slots": {}},
        )()

        plan = Planner().create_plan(
            decision,  # type: ignore[arg-type]
            user_input="检查 TCP 端口 18090 的监听进程和暴露范围",
        )

        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            [
                "platform_capability_profile",
                "system_snapshot",
                "network_listeners",
                "service_catalog_snapshot",
                "socket_process_context",
            ],
        )
        self.assertEqual(
            plan.tool_calls[-1].arguments,
            {"protocol": "tcp", "port": 18090, "max_matches": 20},
        )
        self.assertIn("精确套接字核验", plan.rationale)

    def test_port_without_protocol_checks_tcp_and_udp(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "network_exposure_analysis", "slots": {}},
        )()

        plan = Planner().create_plan(
            decision,  # type: ignore[arg-type]
            user_input="检查端口 18090 是否仍在监听",
        )

        self.assertEqual(
            [
                (call.arguments["protocol"], call.arguments["port"])
                for call in plan.tool_calls
                if call.tool_name == "socket_process_context"
            ],
            [("tcp", 18090), ("udp", 18090)],
        )

    def test_explicit_port_contract_corrects_model_general_health_misclassification(self) -> None:
        model = FakeModelClient(
            {
                "intent": "general_system_health",
                "confidence": 0.84,
                "risk_hints": [],
                "slots": {},
                "reasoning_summary": ["模型误判为综合巡检。"],
            }
        )
        request = "继续检查 TCP 端口 18090 的监听进程和暴露范围"

        resolved = IntentResolver(model).resolve(request)
        plan = Planner().create_plan(resolved.decision, user_input=request)

        self.assertEqual(resolved.decision.intent, "network_exposure_analysis")
        self.assertEqual(resolved.decision.slots["port"], 18090)
        self.assertEqual(resolved.decision.slots["protocols"], ["tcp"])
        self.assertEqual(plan.tool_calls[-1].tool_name, "socket_process_context")
        self.assertEqual(
            plan.tool_calls[-1].arguments,
            {"protocol": "tcp", "port": 18090, "max_matches": 20},
        )
        self.assertIn("目标套接字证据流程", resolved.decision.reasoning_summary[0])

    def test_disk_plan_also_checks_deleted_files_that_still_hold_space(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "disk_pressure_analysis", "slots": {}},
        )()

        plan = Planner().create_plan(decision)  # type: ignore[arg-type]

        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            [
                "platform_capability_profile",
                "system_snapshot",
                "disk_usage",
                "deleted_open_files",
            ],
        )

    def test_disk_plan_honors_explicit_scan_scope_and_threshold(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "disk_pressure_analysis", "slots": {}},
        )()

        plan = Planner().create_plan(
            decision,  # type: ignore[arg-type]
            user_input="定位 /tmp/opscouncil-lab/logs 中超过 10 MB 的日志",
        )

        self.assertEqual(plan.tool_calls[-1].tool_name, "find_large_files")
        self.assertEqual(
            plan.tool_calls[-1].arguments,
            {
                "roots": ["/tmp/opscouncil-lab/logs"],
                "limit": 20,
                "min_size_mb": 10,
            },
        )

    def test_process_plan_leaves_handle_scan_for_evidence_driven_follow_up(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "process_health_analysis", "slots": {}},
        )()

        plan = Planner().create_plan(decision)  # type: ignore[arg-type]

        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            ["platform_capability_profile", "system_snapshot", "process_list"],
        )

    def test_explicit_file_handle_request_requires_handle_evidence_in_initial_plan(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "process_health_analysis", "slots": {}},
        )()

        plan = Planner().create_plan(
            decision,  # type: ignore[arg-type]
            user_input="检查文件句柄使用异常，按相对资源上限定位高风险进程",
        )

        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            [
                "platform_capability_profile",
                "system_snapshot",
                "process_list",
                "process_file_handles",
            ],
        )

    def test_explicit_pid_requires_targeted_runtime_evidence(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "process_health_analysis", "slots": {}},
        )()

        plan = Planner().create_plan(
            decision,  # type: ignore[arg-type]
            user_input=(
                "继续核查 PID 175499 的运行状态、资源占用和文件句柄，"
                "只采集证据，不执行系统变更"
            ),
        )

        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            [
                "platform_capability_profile",
                "system_snapshot",
                "process_list",
                "process_runtime_detail",
            ],
        )
        self.assertEqual(
            plan.tool_calls[-1].arguments,
            {"pid": 175499, "max_fd_scan": 20000},
        )
        self.assertIn("精确 PID 核验", plan.rationale)

    def test_explicit_pid_contract_corrects_model_general_health_misclassification(self) -> None:
        model = FakeModelClient(
            {
                "intent": "general_system_health",
                "confidence": 0.82,
                "risk_hints": [],
                "slots": {},
                "reasoning_summary": ["模型误判为综合巡检。"],
            }
        )
        request = "核查 PID 175499 的运行状态、资源占用和文件句柄"

        resolved = IntentResolver(model).resolve(request)
        plan = Planner().create_plan(resolved.decision, user_input=request)

        self.assertEqual(resolved.decision.intent, "process_health_analysis")
        self.assertEqual(resolved.decision.slots["pid"], 175499)
        self.assertEqual(plan.tool_calls[-1].tool_name, "process_runtime_detail")
        self.assertEqual(
            plan.tool_calls[-1].arguments,
            {"pid": 175499, "max_fd_scan": 20000},
        )
        self.assertIn("目标进程证据流程", resolved.decision.reasoning_summary[0])

    def test_general_health_plan_covers_minimum_evidence_contract(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "general_system_health", "slots": {}},
        )()

        plan = Planner().create_plan(decision)  # type: ignore[arg-type]

        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            [
                "platform_capability_profile",
                "system_snapshot",
                "disk_usage",
                "process_list",
                "network_listeners",
                "service_status",
                "time_sync_status",
            ],
        )
        self.assertEqual(plan.tool_calls[2].arguments, {"paths": ["/", "/var/log", "/tmp"]})

    def test_service_specific_log_plan_starts_with_service_state(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "log_analysis", "slots": {"unit": "sshd.service"}},
        )()

        plan = Planner().create_plan(decision)  # type: ignore[arg-type]

        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            ["platform_capability_profile", "system_snapshot", "service_status"],
        )

    def test_explicit_systemd_state_contract_corrects_model_config_misclassification(self) -> None:
        model = FakeModelClient(
            {
                "intent": "config_integrity_analysis",
                "confidence": 0.96,
                "risk_hints": ["服务状态与目录记录不一致"],
                "slots": {"service_name": "demo-lab.service"},
                "reasoning_summary": ["模型误将服务状态偏离解释成配置漂移。"],
            }
        )
        request = (
            "调查 demo-lab.service 当前 failed 与服务目录期望 inactive 不一致，"
            "核对 systemd 状态和近期日志。"
        )

        resolved = IntentResolver(model).resolve(request)
        plan = Planner().create_plan(resolved.decision, user_input=request)

        self.assertEqual(resolved.decision.intent, "log_analysis")
        self.assertEqual(resolved.decision.slots["unit"], "demo-lab.service")
        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            ["platform_capability_profile", "system_snapshot", "service_status"],
        )
        self.assertIn(
            "服务状态与变更影响调查流程",
            resolved.decision.reasoning_summary[0],
        )

    def test_explicit_service_restart_contract_corrects_model_process_misclassification(
        self,
    ) -> None:
        model = FakeModelClient(
            {
                "intent": "process_health_analysis",
                "confidence": 0.91,
                "risk_hints": [],
                "slots": {},
                "reasoning_summary": ["模型误判为通用进程检查。"],
            }
        )
        request = (
            "请预演重启 opsbench-impact-root.service：采集真实依赖和当前连接，"
            "评估影响范围与回滚方案，生成审批方案但不要自动执行。"
        )

        resolved = IntentResolver(model).resolve(request)
        plan = Planner().create_plan(resolved.decision, user_input=request)

        self.assertEqual(resolved.decision.intent, "log_analysis")
        self.assertEqual(
            resolved.decision.slots["unit"],
            "opsbench-impact-root.service",
        )
        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            [
                "platform_capability_profile",
                "system_snapshot",
                "service_status",
                "service_desired_state",
                "service_dependency_snapshot",
            ],
        )
        self.assertEqual(
            plan.tool_calls[-1].arguments["focus_units"],
            ["opsbench-impact-root.service"],
        )
        self.assertEqual(plan.tool_calls[-1].arguments["change_action"], "restart")
        self.assertIn(
            "服务状态与变更影响调查流程",
            resolved.decision.reasoning_summary[0],
        )

    def test_explicit_service_unit_does_not_override_configuration_file_request(self) -> None:
        model = FakeModelClient(
            {
                "intent": "config_integrity_analysis",
                "confidence": 0.94,
                "risk_hints": [],
                "slots": {"paths": ["/etc/systemd/system/demo.service"]},
                "reasoning_summary": ["用户要求检查配置文件权限。"],
            }
        )

        resolved = IntentResolver(model).resolve(
            "检查 demo.service 对应配置文件的文件权限和内容哈希"
        )

        self.assertEqual(resolved.decision.intent, "config_integrity_analysis")

    def test_service_degradation_plan_reproduces_only_explicit_loopback_endpoint(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "service_degradation_analysis", "slots": {"url": "http://invented/health"}},
        )()

        plan = Planner().create_plan(
            decision,  # type: ignore[arg-type]
            user_input="调查 http://127.0.0.1:18080/health 返回 503 的原因",
        )

        self.assertEqual(
            [call.tool_name for call in plan.tool_calls],
            [
                "platform_capability_profile",
                "system_snapshot",
                "service_health_probe",
                "service_dependency_snapshot",
            ],
        )
        self.assertEqual(plan.tool_calls[-2].arguments["url"], "http://127.0.0.1:18080/health")
        self.assertEqual(plan.tool_calls[-1].arguments["focus_ports"], [18080])

    def test_service_degradation_without_explicit_endpoint_does_not_invent_probe(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "service_degradation_analysis", "slots": {"url": "http://127.0.0.1:9999/health"}},
        )()

        plan = Planner().create_plan(decision, user_input="业务服务最近变慢了")  # type: ignore[arg-type]

        self.assertEqual(plan.tool_calls[-1].tool_name, "service_dependency_snapshot")
        self.assertEqual(plan.tool_calls[-1].arguments["focus_ports"], [])
        self.assertNotIn("service_health_probe", [call.tool_name for call in plan.tool_calls])

    def test_capability_question_plans_no_mcp_tool_calls(self) -> None:
        model = FakeModelClient(
            {
                "intent": "agent_capability_help",
                "confidence": 0.96,
                "risk_hints": [],
                "slots": {},
                "reasoning_summary": ["用户询问 Agent 支持哪些运维能力。"],
            }
        )

        resolved = IntentResolver(model).resolve("你好，你有哪些功能")
        plan = Planner().create_plan(resolved.decision)

        self.assertEqual(resolved.provider, "bailian")
        self.assertEqual(plan.intent, "agent_capability_help")
        self.assertEqual(plan.tool_calls, [])

    def test_invalid_model_intent_is_rejected_before_planning(self) -> None:
        model = FakeModelClient(
            {
                "intent": "execute_shell_command",
                "confidence": 0.99,
                "risk_hints": [],
                "slots": {},
                "reasoning_summary": [],
            }
        )

        with self.assertRaises(ValidationError):
            IntentResolver(model).resolve("执行一个命令")

    def test_single_text_reasoning_summary_is_normalized(self) -> None:
        model = FakeModelClient(
            {
                "intent": "config_integrity_analysis",
                "confidence": 0.88,
                "risk_hints": "只读配置基线采样",
                "slots": {"paths": ["/etc/hosts"]},
                "reasoning_summary": "用户要求检查关键配置漂移。",
            }
        )

        resolved = IntentResolver(model).resolve("检查 hosts 是否漂移")

        self.assertEqual(resolved.decision.intent, "config_integrity_analysis")
        self.assertEqual(resolved.decision.risk_hints, ["只读配置基线采样"])
        self.assertEqual(resolved.decision.reasoning_summary, ["用户要求检查关键配置漂移。"])

    def test_model_reasoning_text_is_kept_audit_sized(self) -> None:
        long_hint = "配置漂移可能影响服务解析和启动流程，需要确认变更来源、审批状态、文件权限和哈希基线。" * 4
        long_summary = "用户请求检查关键配置文件，模型应只输出可审计摘要，不应把长篇推理文本写入审计事件。" * 6
        model = FakeModelClient(
            {
                "intent": "config_integrity_analysis",
                "confidence": 0.91,
                "risk_hints": [long_hint],
                "slots": {},
                "reasoning_summary": [long_summary],
            }
        )

        resolved = IntentResolver(model).resolve("检查关键配置是否存在漂移")

        self.assertLessEqual(len(resolved.decision.risk_hints[0]), 80)
        self.assertLessEqual(len(resolved.decision.reasoning_summary[0]), 120)
        self.assertTrue(resolved.decision.risk_hints[0].endswith("..."))
        self.assertTrue(resolved.decision.reasoning_summary[0].endswith("..."))

    def test_config_target_files_slot_maps_to_integrity_scan_paths(self) -> None:
        model = FakeModelClient(
            {
                "intent": "config_integrity_analysis",
                "confidence": 0.93,
                "risk_hints": [],
                "slots": {"target_files": ["/etc/ssh/sshd_config"]},
                "reasoning_summary": [],
            }
        )

        resolved = IntentResolver(model).resolve("检查 sshd 配置漂移")
        plan = Planner().create_plan(
            resolved.decision,
            user_input="检查 /etc/ssh/sshd_config 配置漂移",
        )
        integrity_call = next(
            call for call in plan.tool_calls if call.tool_name == "config_baseline_check"
        )

        self.assertIn("/etc/ssh/sshd_config", integrity_call.arguments["paths"])

    def test_config_plan_keeps_live_defaults_separate_from_lab_samples(self) -> None:
        model = FakeModelClient(
            {
                "intent": "config_integrity_analysis",
                "confidence": 0.9,
                "risk_hints": [],
                "slots": {},
                "reasoning_summary": [],
            }
        )

        resolved = IntentResolver(model).resolve("检查关键配置是否存在漂移")
        plan = Planner().create_plan(
            resolved.decision,
            user_input="检查关键配置是否存在漂移",
        )
        baseline_call = next(
            call for call in plan.tool_calls if call.tool_name == "config_baseline_check"
        )

        self.assertEqual(baseline_call.arguments["scope"], "LIVE")
        self.assertNotIn(
            "/tmp/opscouncil-lab/etc/service-agent.conf",
            baseline_call.arguments["paths"],
        )

    def test_config_plan_uses_lab_scope_only_for_explicit_lab_path(self) -> None:
        decision = IntentDecision(
            intent="config_integrity_analysis",
            confidence=0.99,
            slots={},
        )
        path = "/tmp/opscouncil-lab/etc/service-agent.conf"

        plan = Planner().create_plan(
            decision,
            user_input=f"检查 {path} 是否漂移",
        )

        baseline_call = next(
            call for call in plan.tool_calls if call.tool_name == "config_baseline_check"
        )
        self.assertEqual(baseline_call.arguments, {"paths": [path], "scope": "LAB"})

    def test_explicit_restart_plan_collects_change_impact_before_proposal(self) -> None:
        decision = type(
            "Decision",
            (),
            {"intent": "log_analysis", "slots": {"unit": "demo.service"}},
        )()

        plan = Planner().create_plan(  # type: ignore[arg-type]
            decision,
            user_input="请检查并重启 demo.service",
        )

        impact_call = next(
            call
            for call in plan.tool_calls
            if call.tool_name == "service_dependency_snapshot"
        )
        desired_state_call = next(
            call
            for call in plan.tool_calls
            if call.tool_name == "service_desired_state"
        )
        self.assertEqual(desired_state_call.arguments, {"unit": "demo.service"})
        self.assertLess(
            plan.tool_calls.index(desired_state_call),
            plan.tool_calls.index(impact_call),
        )
        self.assertEqual(impact_call.arguments["focus_units"], ["demo.service"])
        self.assertEqual(impact_call.arguments["change_action"], "restart")

    def test_missing_model_configuration_is_not_replaced_by_rule_fallback(self) -> None:
        model = FakeModelClient(error=ModelNotConfiguredError("model key missing"))

        with self.assertRaises(ModelNotConfiguredError):
            IntentResolver(model).resolve("帮我分析磁盘")


if __name__ == "__main__":
    unittest.main()
