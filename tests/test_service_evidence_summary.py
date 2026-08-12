from __future__ import annotations

import unittest

from backend.app.investigation.evidence import _summarize_observation
from backend.app.investigation.service import _prioritize_diagnosis_evidence
from backend.app.models.entities import ToolCall


class ServiceEvidenceSummaryTest(unittest.TestCase):
    def test_health_summary_keeps_causal_fields_and_log_path(self) -> None:
        summary = _summarize_observation(
            {
                "url": "http://127.0.0.1:18080/health",
                "available": False,
                "status_code": 503,
                "latency_ms": 122,
                "body_summary": {
                    "service": "checkout-api",
                    "dependency": "inventory-db",
                    "reason": "dependency_timeout",
                    "correlation_id": "kg-1",
                    "log_path": "/tmp/opscouncil-lab/case/app.jsonl",
                },
            },
            "service_health_probe",
        )

        self.assertIn("inventory-db", summary)
        self.assertIn("dependency_timeout", summary)
        self.assertIn("log_path=/tmp/opscouncil-lab/case/app.jsonl", summary)

    def test_application_log_summary_keeps_timeout_and_config_counter_evidence(self) -> None:
        summary = _summarize_observation(
            {
                "path": "/tmp/opscouncil-lab/case/app.jsonl",
                "line_count": 3,
                "records": [
                    {
                        "event": "config_metadata_changed",
                        "path": "/tmp/opscouncil-lab/case/app.conf",
                        "content_hash_unchanged": True,
                    },
                    {
                        "event": "request_failed",
                        "correlation_id": "kg-1",
                        "dependency": "inventory-db",
                        "reason": "dependency_timeout",
                        "server.address": "127.0.0.1",
                        "server.port": 18091,
                        "network.transport": "tcp",
                        "error.type": "timeout",
                        "dependency_timeout_ms": 120,
                        "observed_latency_ms": 121,
                        "http_status": 503,
                    },
                ],
            },
            "application_log_query",
        )

        self.assertIn("inventory-db", summary)
        self.assertIn("server.port=18091", summary)
        self.assertIn("error.type=timeout", summary)
        self.assertIn("config_path=/tmp/opscouncil-lab/case/app.conf", summary)
        self.assertIn("content_hash_unchanged=True", summary)

    def test_change_preview_prioritizes_dependency_and_desired_state_evidence(self) -> None:
        calls = [
            self._tool_call("platform_capability_profile"),
            self._tool_call("system_snapshot"),
            self._tool_call("service_status"),
            self._tool_call("service_desired_state"),
            self._tool_call("service_dependency_snapshot"),
        ]

        selected = _prioritize_diagnosis_evidence("log_analysis", calls)

        self.assertEqual(
            [call.tool_name for call in selected],
            [
                "service_dependency_snapshot",
                "service_desired_state",
                "service_status",
                "platform_capability_profile",
            ],
        )

    def test_failed_evidence_collection_is_not_hidden_by_successful_context(self) -> None:
        calls = [
            self._tool_call("platform_capability_profile"),
            self._tool_call("system_snapshot"),
            self._tool_call("service_status"),
            self._tool_call("service_desired_state"),
            self._tool_call("service_dependency_snapshot", status="error"),
        ]

        selected = _prioritize_diagnosis_evidence("log_analysis", calls)

        self.assertEqual(selected[0].tool_name, "service_dependency_snapshot")

    @staticmethod
    def _tool_call(tool_name: str, *, status: str = "ok") -> ToolCall:
        return ToolCall(
            task_id=1,
            tool_name=tool_name,
            tool_version="1.0.0",
            input_json={},
            output_json={"observations": []},
            risk_level="R0",
            status=status,
            duration_ms=1,
        )


if __name__ == "__main__":
    unittest.main()
