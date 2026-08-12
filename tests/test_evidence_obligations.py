from __future__ import annotations

from types import SimpleNamespace
import unittest

from backend.app.investigation.obligations import next_evidence_obligation


ALLOWED_TOOLS = {
    "service_health_probe",
    "application_log_query",
    "config_integrity_scan",
    "service_dependency_snapshot",
}
ARGUMENT_VALUES = {
    "application_log_query.path": [
        "/tmp/opscouncil-lab/service/checkout-service.jsonl",
    ],
    "config_integrity_scan.paths": [
        "/tmp/opscouncil-lab/service/checkout-service.jsonl",
        "/tmp/opscouncil-lab/service/checkout-service.conf",
    ],
    "service_dependency_snapshot.focus_ports": [18090, 18091],
}


def task(user_input: str = "排查 503，并核验近期配置痕迹是否为根因") -> SimpleNamespace:
    return SimpleNamespace(
        intent="service_degradation_analysis",
        user_input=user_input,
    )


def call(tool_name: str, input_json: dict) -> SimpleNamespace:
    return SimpleNamespace(tool_name=tool_name, input_json=input_json)


def evidence(payload_json: dict, *, trust_level: str = "TRUSTED") -> SimpleNamespace:
    return SimpleNamespace(
        source_key="application_log_query",
        payload_json=payload_json,
        trust_level=trust_level,
    )


class EvidenceObligationTest(unittest.TestCase):
    def test_general_health_requires_the_first_missing_core_dimension(self) -> None:
        obligation = next_evidence_obligation(
            SimpleNamespace(intent="general_system_health", user_input="检查主机健康"),
            allowed_tool_names={
                "system_snapshot",
                "disk_usage",
                "process_list",
                "network_listeners",
                "service_status",
            },
            allowed_argument_values={},
            tool_history=[call("system_snapshot", {})],
        )

        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(obligation.key, "general_health_filesystems")
        self.assertEqual(obligation.tool_name, "disk_usage")
        self.assertEqual(obligation.arguments, {"paths": ["/", "/var/log", "/tmp"]})

    def test_general_health_contract_is_satisfied_after_all_core_calls(self) -> None:
        obligation = next_evidence_obligation(
            SimpleNamespace(intent="general_system_health", user_input="检查主机健康"),
            allowed_tool_names={
                "system_snapshot",
                "disk_usage",
                "process_list",
                "network_listeners",
                "service_status",
            },
            allowed_argument_values={},
            tool_history=[
                call("system_snapshot", {}),
                call("disk_usage", {"paths": ["/"]}),
                call("process_list", {"limit": 30}),
                call("network_listeners", {"limit": 80}),
                call("service_status", {"unit": None}),
            ],
        )

        self.assertIsNone(obligation)

    def test_general_health_requires_targeted_status_for_an_observed_failed_service(self) -> None:
        failed_unit = "opscouncil-lab-failed.service"
        obligation = next_evidence_obligation(
            SimpleNamespace(intent="general_system_health", user_input="检查主机健康"),
            allowed_tool_names={
                "system_snapshot",
                "disk_usage",
                "process_list",
                "network_listeners",
                "service_status",
                "journal_query",
            },
            allowed_argument_values={
                "service_status.unit": [failed_unit],
                "journal_query.unit": [failed_unit],
            },
            tool_history=[
                call("system_snapshot", {}),
                call("disk_usage", {"paths": ["/"]}),
                call("process_list", {"limit": 30}),
                call("network_listeners", {"limit": 80}),
                call("service_status", {"unit": None}),
            ],
            evidence_items=[
                SimpleNamespace(
                    source_key="service_status",
                    trust_level="SYSTEM_OBSERVATION",
                    payload_json={"unit": failed_unit, "active": "failed"},
                )
            ],
        )

        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(obligation.key, "general_health_failed_service_detail")
        self.assertEqual(obligation.tool_name, "service_status")
        self.assertEqual(obligation.arguments, {"unit": failed_unit})

    def test_general_health_requires_logs_after_targeted_failed_service_status(self) -> None:
        failed_unit = "opscouncil-lab-failed.service"
        obligation = next_evidence_obligation(
            SimpleNamespace(intent="general_system_health", user_input="检查主机健康"),
            allowed_tool_names={
                "system_snapshot",
                "disk_usage",
                "process_list",
                "network_listeners",
                "service_status",
                "journal_query",
            },
            allowed_argument_values={
                "service_status.unit": [failed_unit],
                "journal_query.unit": [failed_unit],
            },
            tool_history=[
                call("system_snapshot", {}),
                call("disk_usage", {"paths": ["/"]}),
                call("process_list", {"limit": 30}),
                call("network_listeners", {"limit": 80}),
                call("service_status", {"unit": None}),
                call("service_status", {"unit": failed_unit}),
            ],
            evidence_items=[
                SimpleNamespace(
                    source_key="service_status",
                    trust_level="SYSTEM_OBSERVATION",
                    payload_json={"unit": failed_unit, "active": "failed"},
                )
            ],
        )

        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(obligation.key, "general_health_failed_service_log")
        self.assertEqual(obligation.tool_name, "journal_query")
        self.assertEqual(obligation.arguments, {"unit": failed_unit, "lines": 80})

    def test_general_health_checks_operator_approved_expectation_before_logs(self) -> None:
        failed_unit = "opscouncil-lab-failed.service"
        obligation = next_evidence_obligation(
            SimpleNamespace(intent="general_system_health", user_input="检查主机健康"),
            allowed_tool_names={
                "system_snapshot",
                "disk_usage",
                "process_list",
                "network_listeners",
                "service_status",
                "service_desired_state",
                "journal_query",
            },
            allowed_argument_values={
                "service_status.unit": [failed_unit],
                "service_desired_state.unit": [failed_unit],
                "journal_query.unit": [failed_unit],
            },
            tool_history=[
                call("system_snapshot", {}),
                call("disk_usage", {"paths": ["/"]}),
                call("process_list", {"limit": 30}),
                call("network_listeners", {"limit": 80}),
                call("service_status", {"unit": None}),
                call("service_status", {"unit": failed_unit}),
            ],
            evidence_items=[
                SimpleNamespace(
                    source_key="service_status",
                    trust_level="SYSTEM_OBSERVATION",
                    payload_json={"unit": failed_unit, "active": "failed"},
                )
            ],
        )

        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(obligation.key, "general_health_failed_service_expectation")
        self.assertEqual(obligation.tool_name, "service_desired_state")
        self.assertEqual(obligation.arguments, {"unit": failed_unit})

    def test_service_state_investigation_requires_expectation_before_logs(self) -> None:
        unit = "demo-lab.service"
        obligation = next_evidence_obligation(
            SimpleNamespace(
                intent="log_analysis",
                user_input=f"调查 {unit} 当前 failed 与期望状态不一致",
            ),
            allowed_tool_names={
                "service_status",
                "service_desired_state",
                "journal_query",
            },
            allowed_argument_values={
                "service_desired_state.unit": [unit],
                "journal_query.unit": [unit],
            },
            tool_history=[call("service_status", {"unit": unit})],
            evidence_items=[
                SimpleNamespace(
                    source_key="service_status",
                    trust_level="SYSTEM_OBSERVATION",
                    payload_json={"unit": unit, "active_state": "failed"},
                )
            ],
        )

        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(obligation.key, "service_state_expectation")
        self.assertEqual(obligation.tool_name, "service_desired_state")
        self.assertEqual(obligation.arguments, {"unit": unit})

    def test_service_state_investigation_requires_logs_after_expectation(self) -> None:
        unit = "demo-lab.service"
        obligation = next_evidence_obligation(
            SimpleNamespace(
                intent="log_analysis",
                user_input=f"调查 {unit} 当前 failed 与期望状态不一致",
            ),
            allowed_tool_names={
                "service_status",
                "service_desired_state",
                "journal_query",
            },
            allowed_argument_values={
                "service_desired_state.unit": [unit],
                "journal_query.unit": [unit],
            },
            tool_history=[
                call("service_status", {"unit": unit}),
                call("service_desired_state", {"unit": unit}),
            ],
            evidence_items=[
                SimpleNamespace(
                    source_key="service_status",
                    trust_level="SYSTEM_OBSERVATION",
                    payload_json={"unit": unit, "active_state": "failed"},
                )
            ],
        )

        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(obligation.key, "service_state_log")
        self.assertEqual(obligation.tool_name, "journal_query")
        self.assertEqual(obligation.arguments, {"unit": unit, "lines": 80})

    def test_service_restart_requires_impact_assessment_before_logs(self) -> None:
        unit = "demo-lab.service"
        obligation = next_evidence_obligation(
            SimpleNamespace(
                intent="log_analysis",
                user_input=f"调查并重启 {unit}",
            ),
            allowed_tool_names={
                "service_status",
                "service_desired_state",
                "service_dependency_snapshot",
                "journal_query",
            },
            allowed_argument_values={
                "service_desired_state.unit": [unit],
                "service_dependency_snapshot.focus_units": [unit],
                "journal_query.unit": [unit],
            },
            tool_history=[
                call("service_status", {"unit": unit}),
                call("service_desired_state", {"unit": unit}),
            ],
            evidence_items=[
                SimpleNamespace(
                    source_key="service_status",
                    trust_level="SYSTEM_OBSERVATION",
                    payload_json={"unit": unit, "active_state": "failed"},
                )
            ],
        )

        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(obligation.key, "service_restart_impact")
        self.assertEqual(obligation.tool_name, "service_dependency_snapshot")
        self.assertEqual(obligation.arguments["focus_units"], [unit])
        self.assertEqual(obligation.arguments["change_action"], "restart")

    def test_failure_log_is_required_after_health_probe_exposes_log_path(self) -> None:
        obligation = next_evidence_obligation(
            task(),
            allowed_tool_names=ALLOWED_TOOLS,
            allowed_argument_values=ARGUMENT_VALUES,
            tool_history=[call("service_health_probe", {"url": "http://127.0.0.1:18090/health"})],
        )

        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(obligation.key, "service_failure_log")
        self.assertEqual(obligation.tool_name, "application_log_query")
        self.assertEqual(
            obligation.arguments["path"],
            "/tmp/opscouncil-lab/service/checkout-service.jsonl",
        )

    def test_config_hash_is_required_after_failure_log_when_user_requested_it(self) -> None:
        obligation = next_evidence_obligation(
            task(),
            allowed_tool_names=ALLOWED_TOOLS,
            allowed_argument_values=ARGUMENT_VALUES,
            tool_history=[
                call("service_health_probe", {"url": "http://127.0.0.1:18090/health"}),
                call(
                    "application_log_query",
                    {"path": "/tmp/opscouncil-lab/service/checkout-service.jsonl"},
                ),
            ],
        )

        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(obligation.key, "configuration_counter_evidence")
        self.assertEqual(obligation.tool_name, "config_integrity_scan")
        self.assertEqual(
            obligation.arguments["paths"],
            ["/tmp/opscouncil-lab/service/checkout-service.conf"],
        )

    def test_loopback_dependency_endpoint_requires_listener_attribution(self) -> None:
        obligation = next_evidence_obligation(
            task(),
            allowed_tool_names=ALLOWED_TOOLS,
            allowed_argument_values=ARGUMENT_VALUES,
            tool_history=[
                call("service_health_probe", {"url": "http://127.0.0.1:18090/health"}),
                call(
                    "application_log_query",
                    {"path": "/tmp/opscouncil-lab/service/checkout-service.jsonl"},
                ),
            ],
            evidence_items=[
                evidence(
                    {
                        "records": [
                            {
                                "event": "request_failed",
                                "server.address": "127.0.0.1",
                                "server.port": 18091,
                            }
                        ]
                    }
                )
            ],
        )

        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(obligation.key, "dependency_listener_identity")
        self.assertEqual(obligation.tool_name, "service_dependency_snapshot")
        self.assertEqual(obligation.arguments, {"focus_ports": [18091]})

    def test_remote_or_quarantined_endpoint_does_not_expand_obligation(self) -> None:
        history = [
            call("service_health_probe", {"url": "http://127.0.0.1:18090/health"}),
            call(
                "application_log_query",
                {"path": "/tmp/opscouncil-lab/service/checkout-service.jsonl"},
            ),
        ]
        for address, trust_level in (
            ("192.0.2.20", "TRUSTED"),
            ("127.0.0.1", "QUARANTINED"),
        ):
            with self.subTest(address=address, trust_level=trust_level):
                obligation = next_evidence_obligation(
                    task("排查 503 的依赖根因"),
                    allowed_tool_names=ALLOWED_TOOLS,
                    allowed_argument_values=ARGUMENT_VALUES,
                    tool_history=history,
                    evidence_items=[
                        evidence(
                            {
                                "records": [
                                    {
                                        "event": "request_failed",
                                        "server.address": address,
                                        "server.port": 18091,
                                    }
                                ]
                            },
                            trust_level=trust_level,
                        )
                    ],
                )

                self.assertIsNone(obligation)

    def test_config_hash_is_not_forced_without_explicit_config_request(self) -> None:
        obligation = next_evidence_obligation(
            task("排查 503 的依赖根因"),
            allowed_tool_names=ALLOWED_TOOLS,
            allowed_argument_values=ARGUMENT_VALUES,
            tool_history=[
                call("service_health_probe", {"url": "http://127.0.0.1:18090/health"}),
                call(
                    "application_log_query",
                    {"path": "/tmp/opscouncil-lab/service/checkout-service.jsonl"},
                ),
            ],
        )

        self.assertIsNone(obligation)

    def test_exact_existing_config_scan_satisfies_obligation(self) -> None:
        obligation = next_evidence_obligation(
            task(),
            allowed_tool_names=ALLOWED_TOOLS,
            allowed_argument_values=ARGUMENT_VALUES,
            tool_history=[
                call("service_health_probe", {"url": "http://127.0.0.1:18090/health"}),
                call(
                    "application_log_query",
                    {"path": "/tmp/opscouncil-lab/service/checkout-service.jsonl"},
                ),
                call(
                    "config_integrity_scan",
                    {"paths": ["/tmp/opscouncil-lab/service/checkout-service.conf"]},
                ),
            ],
        )

        self.assertIsNone(obligation)


if __name__ == "__main__":
    unittest.main()
