from __future__ import annotations

from types import SimpleNamespace
import unittest

from backend.app.ai.analysis import ground_final_analysis


def model_payload(risk_level: str = "R0") -> dict:
    return {
        "conclusion": "建议直接执行未注册工具。",
        "root_cause": "测试模型输出。",
        "risk_level": risk_level,
        "reasoning_summary": ["模型自行声称风险很低。"],
        "recommended_actions": [
            {
                "title": "执行任意命令",
                "rationale": "请调用systemctl show查看服务状态。",
                "safety_gate": "再用cat /etc/hosts核对配置后无需审批",
                "tool_name": "execute_shell",
            }
        ],
        "evidence_used": [
            {"source": "模型虚构证据", "summary": "并不存在的来源"},
        ],
        "residual_risk": "无",
    }


def health_evidence(
    evidence_id: int,
    source_key: str,
    *,
    status: str = "ok",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=evidence_id,
        source_type="MCP",
        source_ref=f"tool_call:{evidence_id}:result",
        source_key=source_key,
        title=source_key,
        summary=f"{source_key} status={status}",
        payload_json={"status": status},
        trust_level="SYSTEM_OBSERVATION",
    )


class AIAnalysisGroundingTest(unittest.TestCase):
    def test_absolute_no_risk_claim_is_replaced_for_change_request(self) -> None:
        result = ground_final_analysis(
            model_payload(risk_level="R3"),
            task_risk_level="R3",
            evidence_items=[],
            observed_tool_names=set(),
        )

        self.assertNotEqual(result.residual_risk, "无")
        self.assertIn("执行前复核", result.residual_risk)
        self.assertIn("人工接管", result.residual_risk)

    def test_general_health_report_is_bounded_when_a_core_dimension_failed(self) -> None:
        evidence_items = [
            health_evidence(index, source_key, status="unavailable" if source_key == "service_status" else "ok")
            for index, source_key in enumerate(
                (
                    "system_snapshot",
                    "disk_usage",
                    "process_list",
                    "network_listeners",
                    "service_status",
                ),
                start=1,
            )
        ]
        payload = model_payload()
        payload["conclusion"] = "主机当前健康状态良好。"
        payload["root_cause"] = "未发现异常。"

        result = ground_final_analysis(
            payload,
            task_risk_level="R1",
            evidence_items=evidence_items,
            observed_tool_names={item.source_key for item in evidence_items},
            task_intent="general_system_health",
        )

        self.assertIn("失败服务尚无有效系统证据", result.conclusion)
        self.assertIn("不能据此断言整机健康", result.conclusion)
        self.assertEqual(
            result.root_cause,
            "证据覆盖不足，暂不形成整机健康或异常根因结论。",
        )

    def test_general_health_report_remains_available_with_complete_core_evidence(self) -> None:
        source_keys = (
            "system_snapshot",
            "disk_usage",
            "process_list",
            "network_listeners",
            "service_status",
        )
        evidence_items = [
            health_evidence(index, source_key)
            for index, source_key in enumerate(source_keys, start=1)
        ]
        payload = model_payload()
        payload["conclusion"] = "已完成全部核心维度核验。"

        result = ground_final_analysis(
            payload,
            task_risk_level="R1",
            evidence_items=evidence_items,
            observed_tool_names=set(source_keys),
            task_intent="general_system_health",
        )

        self.assertEqual(result.conclusion, "已完成全部核心维度核验。")
        self.assertNotIn("证据覆盖不足", result.root_cause)

    def test_final_report_uses_authoritative_risk_and_persisted_evidence(self) -> None:
        evidence_items = [
            SimpleNamespace(
                id=21,
                source_type="MCP",
                source_ref="tool_call:8:observation:0",
                source_key="network_listeners",
                title="网络监听",
                summary="local_address=0.0.0.0:8080，pid=-",
                payload_json={"evidence_ref": "ss:tcp:8080"},
                trust_level="SYSTEM_OBSERVATION",
            )
        ]

        result = ground_final_analysis(
            model_payload(),
            task_risk_level="R2",
            evidence_items=evidence_items,
            observed_tool_names={"network_listeners"},
        )

        self.assertEqual(result.risk_level, "R2")
        self.assertEqual(
            result.evidence_used,
            [
                {
                    "evidence_id": "21",
                    "source": "ss:tcp:8080",
                    "summary": "local_address=0.0.0.0:8080，pid=-",
                }
            ],
        )
        action = result.recommended_actions[0]
        self.assertIsNone(action.tool_name)
        self.assertNotIn("systemctl", action.rationale)
        self.assertNotIn("cat ", action.safety_gate)
        self.assertIn("MCP", action.rationale)
        self.assertIn("人工审批", action.safety_gate)

    def test_report_preserves_only_an_observed_registered_tool_name(self) -> None:
        payload = model_payload()
        payload["recommended_actions"][0]["tool_name"] = "network_listeners"

        result = ground_final_analysis(
            payload,
            task_risk_level="R1",
            evidence_items=[],
            observed_tool_names={"network_listeners"},
        )

        self.assertEqual(result.recommended_actions[0].tool_name, "network_listeners")

    def test_report_humanizes_internal_service_tool_names(self) -> None:
        payload = model_payload()
        payload["reasoning_summary"] = [
            "service_health_probe 与 application_log_query 结果一致。"
        ]

        result = ground_final_analysis(
            payload,
            task_risk_level="R1",
            evidence_items=[],
            observed_tool_names=set(),
        )

        self.assertEqual(
            result.reasoning_summary,
            ["服务健康检查与应用日志结果一致。"],
        )

    def test_knowledge_evidence_is_labeled_from_persisted_record(self) -> None:
        evidence_item = SimpleNamespace(
            id=32,
            source_type="KNOWLEDGE",
            source_ref="knowledge_chunk:9",
            source_key="knowledge_document:3",
            title="端口暴露处置规范",
            summary="对外监听应先确认业务归属。",
            payload_json={"source_uri": "internal://network"},
            trust_level="verified",
        )

        result = ground_final_analysis(
            model_payload(),
            task_risk_level="R1",
            evidence_items=[evidence_item],
            observed_tool_names=set(),
        )

        self.assertEqual(result.evidence_used[0]["source"], "知识库：端口暴露处置规范")

    def test_report_prefers_evidence_bound_to_confirmed_hypothesis(self) -> None:
        evidence_items = [
            SimpleNamespace(
                id=41,
                source_type="MCP",
                source_ref="tool_call:10:observation:0",
                source_key="process_list",
                title="进程状态",
                summary="pid=530，cpu_percent=28.1",
                payload_json={"evidence_ref": "ps:530"},
                trust_level="SYSTEM_OBSERVATION",
            ),
            SimpleNamespace(
                id=42,
                source_type="MCP",
                source_ref="tool_call:10:observation:29",
                source_key="process_list",
                title="进程状态",
                summary="pid=88，cpu_percent=0.0",
                payload_json={"evidence_ref": "ps:88"},
                trust_level="SYSTEM_OBSERVATION",
            ),
            SimpleNamespace(
                id=43,
                source_type="KNOWLEDGE",
                source_ref="knowledge_chunk:12",
                source_key="knowledge_document:2",
                title="配置漂移规范",
                summary="与当前进程根因无关。",
                payload_json={},
                trust_level="verified",
            ),
        ]

        result = ground_final_analysis(
            model_payload(),
            task_risk_level="R0",
            evidence_items=evidence_items,
            observed_tool_names={"process_list"},
            preferred_evidence_ids=[41],
        )

        self.assertEqual([item["evidence_id"] for item in result.evidence_used], ["41"])
        self.assertEqual(result.evidence_used[0]["source"], "ps:530")

    def test_config_drift_exclusion_requires_a_trusted_baseline_comparison(self) -> None:
        payload = model_payload()
        payload.update(
            {
                "conclusion": "服务依赖超时，非服务崩溃或配置漂移所致。",
                "root_cause": "下游响应超过调用时限，配置漂移不成立。",
                "reasoning_summary": [
                    "健康检查与应用日志一致；配置完整性扫描未发现异常变更痕迹。"
                ],
                "residual_risk": "尚未取得下游日志。",
            }
        )
        current_only = SimpleNamespace(
            id=51,
            source_type="MCP",
            source_key="config_integrity_scan",
            title="配置完整性",
            summary="sha256=" + "a" * 64,
            payload_json={"sha256": "a" * 64, "hash_truncated": False},
            trust_level="SYSTEM_OBSERVATION",
        )

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=[current_only],
            observed_tool_names={"config_integrity_scan"},
        )

        self.assertNotIn("配置漂移不成立", result.root_cause)
        self.assertNotIn("未发现异常变更痕迹", "".join(result.reasoning_summary))
        self.assertNotIn("，所致", result.conclusion)
        self.assertIn("健康检查与应用日志一致", "".join(result.reasoning_summary))
        self.assertIn("缺少受信任历史基线", result.conclusion)
        self.assertIn("不能完全排除", result.residual_risk)

    def test_no_evidence_of_config_drift_is_bounded_without_a_trusted_baseline(self) -> None:
        payload = model_payload()
        payload["conclusion"] = "依赖响应超时，当前无证据表明配置漂移。"
        payload["root_cause"] = "依赖响应超过调用时限。"
        current_only = SimpleNamespace(
            id=511,
            source_type="MCP",
            source_key="config_integrity_scan",
            title="配置完整性",
            summary="path=/etc/demo.conf，sha256=" + "a" * 64,
            payload_json={"path": "/etc/demo.conf", "sha256": "a" * 64},
            trust_level="SYSTEM_OBSERVATION",
        )

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=[current_only],
            observed_tool_names={"config_integrity_scan"},
        )

        self.assertNotIn("无证据表明配置漂移", result.conclusion)
        self.assertIn("缺少受信任历史基线", result.conclusion)

    def test_drifted_baseline_cannot_support_excluding_config_drift(self) -> None:
        payload = model_payload()
        payload["conclusion"] = "服务异常，配置内容漂移已排除。"
        baseline = SimpleNamespace(
            id=512,
            source_type="SYSTEM",
            source_key="config_baseline_check",
            title="配置基线核验",
            summary="基线与当前内容不一致。",
            payload_json={
                "status": "drifted",
                "summary": {"total": 1, "changed": 1},
            },
            trust_level="SYSTEM_OBSERVATION",
        )

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=[baseline],
            observed_tool_names=set(),
        )

        self.assertNotIn("漂移已排除", result.conclusion)
        self.assertIn("基线与当前快照不一致", result.conclusion)
        self.assertNotIn("基线与当前快照不一致", "".join(result.counter_evidence))

    def test_trusted_baseline_comparison_preserves_supported_exclusion(self) -> None:
        payload = model_payload()
        payload["conclusion"] = "服务依赖超时，配置内容漂移已排除。"
        baseline = SimpleNamespace(
            id=52,
            source_type="SYSTEM",
            source_key="config_baseline_check",
            title="配置基线核验",
            summary="基线与当前内容一致。",
            payload_json={
                "status": "clean",
                "summary": {"total": 1, "unchanged": 1},
            },
            trust_level="SYSTEM_OBSERVATION",
        )

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=[baseline],
            observed_tool_names=set(),
        )

        self.assertEqual(result.conclusion, payload["conclusion"])

    def test_config_exclusion_without_config_evidence_reports_the_gap(self) -> None:
        payload = model_payload()
        payload["conclusion"] = "服务异常，配置内容漂移已排除。"

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=[],
            observed_tool_names=set(),
        )

        self.assertNotIn("漂移已排除", result.conclusion)
        self.assertIn("尚未取得可比较的配置证据", result.conclusion)
        self.assertFalse(result.counter_evidence)

    def test_ungrounded_port_in_recommended_action_is_removed(self) -> None:
        payload = model_payload()
        payload["conclusion"] = "checkout-api 的依赖调用发生超时。"
        payload["root_cause"] = "inventory-db 响应超过调用时限。"
        payload["reasoning_summary"] = ["应用日志和健康检查结论一致。"]
        payload["recommended_actions"] = [
            {
                "title": "检查依赖端口",
                "rationale": "核查 inventory-db 的监听端口（如 5432）和健康接口。",
                "safety_gate": "仅执行只读检查。",
                "tool_name": None,
            }
        ]
        evidence = SimpleNamespace(
            id=61,
            source_type="MCP",
            source_ref="log:dependency-timeout",
            source_key="application_log_query",
            title="应用日志",
            summary="dependency=inventory-db，server.address=127.0.0.1，server.port=18091",
            payload_json={"server.address": "127.0.0.1", "server.port": 18091},
            trust_level="SYSTEM_OBSERVATION",
        )

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=[evidence],
            observed_tool_names={"application_log_query"},
        )

        action = result.recommended_actions[0]
        self.assertNotIn("5432", action.rationale)
        self.assertEqual(action.title, "补充依赖侧证据")
        self.assertIn("证据链", action.rationale)

    def test_ungrounded_port_in_factual_conclusion_is_rejected(self) -> None:
        payload = model_payload()
        payload["conclusion"] = "127.0.0.1:5432 的依赖请求超时。"
        payload["root_cause"] = "依赖响应超过调用时限。"
        evidence = SimpleNamespace(
            id=62,
            source_type="MCP",
            source_ref="health:http://127.0.0.1:18091/health",
            source_key="service_health_probe",
            title="服务健康检查",
            summary="url=http://127.0.0.1:18091/health，status_code=503",
            payload_json={"url": "http://127.0.0.1:18091/health", "status_code": 503},
            trust_level="SYSTEM_OBSERVATION",
        )

        with self.assertRaisesRegex(ValueError, "ungrounded infrastructure"):
            ground_final_analysis(
                payload,
                task_risk_level="R2",
                evidence_items=[evidence],
                observed_tool_names={"service_health_probe"},
            )

    def test_observed_url_path_can_be_referenced_without_repeating_full_url(self) -> None:
        payload = model_payload()
        payload["conclusion"] = "服务的 /health 探针返回异常状态。"
        payload["root_cause"] = "健康检查结果表明服务尚未就绪。"
        evidence = SimpleNamespace(
            id=64,
            source_type="MCP",
            source_ref="health:http://127.0.0.1:18091/health",
            source_key="service_health_probe",
            title="服务健康检查",
            summary="url=http://127.0.0.1:18091/health，status_code=503",
            payload_json={"url": "http://127.0.0.1:18091/health", "status_code": 503},
            trust_level="SYSTEM_OBSERVATION",
        )

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=[evidence],
            observed_tool_names={"service_health_probe"},
        )

        self.assertIn("/health", result.conclusion)

    def test_live_process_evidence_does_not_exclude_all_service_faults(self) -> None:
        payload = model_payload()
        payload["conclusion"] = (
            "checkout-api 返回 503 的根因是依赖 inventory-db 超时，"
            "当前无证据表明 checkout-api 自身崩溃或配置异常。"
        )
        payload["root_cause"] = "下游依赖响应超过调用时限。"
        payload["reasoning_summary"] = [
            "健康探针与应用日志双源一致指向 dependency_timeout，"
            "进程与端口存活排除服务崩溃，"
            "配置文件存在且无异常迹象，无反证支持其他根因；"
            "无配置解析失败或资源耗尽迹象。"
        ]
        evidence_items = [
            SimpleNamespace(
                id=63,
                source_type="MCP",
                source_ref="ss:listeners",
                source_key="service_dependency_snapshot",
                title="服务关系快照",
                summary="python(pid=42)->监听->127.0.0.1:18090",
                payload_json={"pid": 42, "port": 18090},
                trust_level="SYSTEM_OBSERVATION",
            ),
            SimpleNamespace(
                id=631,
                source_type="MCP",
                source_ref="stat:config",
                source_key="config_integrity_scan",
                title="配置完整性",
                summary="path=/etc/demo.conf，sha256=" + "a" * 64,
                payload_json={"path": "/etc/demo.conf", "sha256": "a" * 64},
                trust_level="SYSTEM_OBSERVATION",
            ),
        ]

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=evidence_items,
            observed_tool_names={"service_dependency_snapshot"},
        )

        reasoning = "".join(result.reasoning_summary)
        self.assertNotIn("排除本体崩溃", reasoning)
        self.assertIn("不支持服务进程崩溃", reasoning)
        self.assertNotIn("存活现有进程", reasoning)
        self.assertNotIn("无异常迹象", reasoning)
        self.assertNotIn("其他根因", reasoning)
        self.assertNotIn("配置解析失败", reasoning)
        self.assertNotIn("资源耗尽", reasoning)
        self.assertNotIn("自身崩溃", result.conclusion)
        self.assertNotIn("配置异常", result.conclusion)

    def test_controller_derives_counter_evidence_from_persisted_observations(self) -> None:
        payload = model_payload()
        payload["conclusion"] = "服务依赖调用超时。"
        payload["root_cause"] = "下游响应超过调用时限。"
        payload["counter_evidence"] = [
            "evidence_id=999 声称某个未经控制器核验的事实。"
        ]
        evidence_items = [
            SimpleNamespace(
                id=65,
                source_type="MCP",
                source_ref="ss:service-map",
                source_key="service_dependency_snapshot",
                title="服务关系快照",
                summary="processes=1，listeners=2，connections=0，relations=python(pid=42)->监听",
                payload_json={"process_count": 1, "listener_count": 2},
                trust_level="SYSTEM_OBSERVATION",
            ),
            SimpleNamespace(
                id=66,
                source_type="MCP",
                source_ref="stat:config",
                source_key="config_integrity_scan",
                title="配置完整性",
                summary="path=/etc/demo.conf，sha256=" + "a" * 64,
                payload_json={"path": "/etc/demo.conf", "sha256": "a" * 64},
                trust_level="SYSTEM_OBSERVATION",
            ),
        ]

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=evidence_items,
            observed_tool_names={"service_dependency_snapshot", "config_integrity_scan"},
        )

        combined = "".join(result.counter_evidence)
        self.assertIn("不支持服务进程崩溃", combined)
        self.assertIn("缺少受信任历史基线", combined)
        self.assertIn("不能完全排除", combined)
        self.assertEqual(len(result.counter_evidence), 2)
        self.assertNotIn("现有证据，但", combined)
        self.assertNotIn("evidence_id=999", combined)
        self.assertEqual(
            {item["evidence_id"] for item in result.evidence_used},
            {"65", "66"},
        )

    def test_failed_service_status_is_not_misreported_as_liveness_counter_evidence(self) -> None:
        payload = model_payload()
        payload["conclusion"] = "demo.service 启动失败。"
        payload["root_cause"] = "启动程序返回非零状态。"
        evidence = SimpleNamespace(
            id=661,
            source_type="MCP",
            source_ref="systemctl:demo.service",
            source_key="service_status",
            title="服务状态",
            summary="unit=demo.service，active_state=failed，exec_main_status=1",
            payload_json={
                "unit": "demo.service",
                "active_state": "failed",
                "main_pid": 0,
                "exec_main_status": 1,
            },
            trust_level="SYSTEM_OBSERVATION",
        )

        result = ground_final_analysis(
            payload,
            task_risk_level="R1",
            evidence_items=[evidence],
            observed_tool_names={"service_status"},
        )

        self.assertFalse(result.counter_evidence)
        self.assertNotIn("不支持服务进程崩溃", "".join(result.reasoning_summary))

    def test_unit_name_cannot_authorize_ignoring_a_failed_service(self) -> None:
        payload = model_payload()
        payload.update(
            {
                "conclusion": "demo-lab.service 是测试服务，失败符合预期。",
                "root_cause": "ExecStart 为 /usr/bin/false，属于人为构造的测试用例。",
                "recommended_actions": [
                    {
                        "title": "无需处理",
                        "rationale": "无需修复或重启该服务。",
                        "safety_gate": "保持现状。",
                        "tool_name": None,
                    }
                ],
                "residual_risk": "不构成系统稳定性或安全风险。",
            }
        )
        evidence = SimpleNamespace(
            id=662,
            source_type="MCP",
            source_ref="systemctl:demo-lab.service",
            source_key="service_status",
            title="服务状态",
            summary=(
                "unit=demo-lab.service，active_state=failed，"
                "exec_start_path=/usr/bin/false，exec_main_status=1"
            ),
            payload_json={
                "unit": "demo-lab.service",
                "active_state": "failed",
                "result": "exit-code",
                "exec_start_path": "/usr/bin/false",
                "exec_main_status": 1,
            },
            trust_level="SYSTEM_OBSERVATION",
        )

        result = ground_final_analysis(
            payload,
            task_risk_level="R1",
            evidence_items=[evidence],
            observed_tool_names={"service_status"},
        )

        self.assertIn("尚未确认该单元", result.conclusion)
        self.assertIn("不证明该失败符合预期", result.root_cause)
        self.assertEqual(result.recommended_actions[0].title, "确认服务期望状态")
        self.assertIn("不能判断该失败是否应被保留或处置", result.residual_risk)
        self.assertFalse(result.counter_evidence)

    def test_transient_connection_absence_cannot_support_unreachable_conclusion(self) -> None:
        payload = model_payload()
        payload.update(
            {
                "conclusion": "checkout-api 的依赖调用发生超时。",
                "root_cause": "inventory-db 响应超过调用时限。",
                "reasoning_summary": [
                    "服务关系快照未捕获到对 inventory-db 的连接，支持依赖不可达假设。"
                ],
                "residual_risk": "仍需取得依赖侧日志。",
            }
        )
        evidence = SimpleNamespace(
            id=67,
            source_type="MCP",
            source_ref="ss:service-map",
            source_key="service_dependency_snapshot",
            title="服务关系快照",
            summary="processes=1，listeners=1，connections=0",
            payload_json={"connection_relation_count": 0},
            trust_level="SYSTEM_OBSERVATION",
        )

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=[evidence],
            observed_tool_names={"service_dependency_snapshot"},
        )

        reasoning = "".join(result.reasoning_summary)
        self.assertNotIn("支持依赖不可达", reasoning)
        self.assertIn("不用于证明依赖不存在或不可达", reasoning)

    def test_multi_source_residual_risk_cannot_claim_single_log_support(self) -> None:
        payload = model_payload()
        payload["conclusion"] = "服务依赖调用超时。"
        payload["root_cause"] = "下游响应超过调用时限。"
        payload["residual_risk"] = "当前结论基于 checkout-api 单向超时日志，尚缺依赖侧状态。"
        evidence_items = [
            SimpleNamespace(
                id=68,
                source_type="MCP",
                source_key="service_health_probe",
                title="服务健康检查",
                summary="status_code=503",
                payload_json={"status_code": 503},
                trust_level="SYSTEM_OBSERVATION",
            ),
            SimpleNamespace(
                id=69,
                source_type="MCP",
                source_key="application_log_query",
                title="应用日志",
                summary="reason=dependency_timeout",
                payload_json={"reason": "dependency_timeout"},
                trust_level="SYSTEM_OBSERVATION",
            ),
        ]

        result = ground_final_analysis(
            payload,
            task_risk_level="R2",
            evidence_items=evidence_items,
            observed_tool_names={"service_health_probe", "application_log_query"},
        )

        self.assertNotIn("单向超时日志", result.residual_risk)
        self.assertIn("健康检查与应用日志共同支持", result.residual_risk)


if __name__ == "__main__":
    unittest.main()
