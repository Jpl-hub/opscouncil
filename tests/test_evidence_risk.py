from __future__ import annotations

import unittest

from backend.app.agent.evidence_risk import assess_evidence_risk


class EvidenceRiskTest(unittest.TestCase):
    def test_public_or_wildcard_listener_is_r2(self) -> None:
        assessment = assess_evidence_risk(
            [
                {
                    "tool_name": "network_listeners",
                    "result": {
                        "status": "ok",
                        "observations": [
                            {
                                "local_address": "0.0.0.0:8080",
                                "exposure_scope": "wildcard",
                                "pid": 41,
                                "process": "demo",
                            }
                        ],
                        "summary_fields": {
                            "wildcard_listener_count": 1,
                            "public_listener_count": 0,
                            "unknown_scope_listener_count": 0,
                            "unattributed_listener_count": 0,
                        },
                    },
                }
            ]
        )

        self.assertEqual(assessment.risk_level.value, "R2")
        self.assertIn("公网、全地址或范围未知监听", assessment.reasons[0])

    def test_critical_disk_pressure_is_r2(self) -> None:
        assessment = assess_evidence_risk(
            [
                {
                    "tool_name": "disk_usage",
                    "result": {
                        "status": "ok",
                        "summary_fields": {
                            "highest_used_path": "/",
                            "highest_used_percent": 92.0,
                        },
                    },
                }
            ]
        )

        self.assertEqual(assessment.risk_level.value, "R2")
        self.assertIn("92.0%", assessment.reasons[0])

    def test_deleted_file_still_held_by_process_is_r2(self) -> None:
        assessment = assess_evidence_risk(
            [
                {
                    "tool_name": "deleted_open_files",
                    "result": {
                        "status": "ok",
                        "summary_fields": {
                            "retained_file_count": 3,
                            "retained_bytes": 25165824,
                            "returned_file_count": 1,
                        },
                        "observations": [
                            {
                                "path": "/var/log/app.log",
                                "size_bytes": 12582912,
                                "pid": 321,
                                "open_handle_count": 1,
                            }
                        ],
                    },
                }
            ]
        )

        self.assertEqual(assessment.risk_level.value, "R2")
        self.assertIn("仍被进程持有", assessment.reasons[0])
        self.assertIn("3 个", assessment.reasons[0])
        self.assertIn("25165824", assessment.reasons[0])

    def test_unavailable_tool_is_observability_r1(self) -> None:
        assessment = assess_evidence_risk(
            [
                {
                    "tool_name": "service_status",
                    "result": {
                        "status": "unavailable",
                        "warnings": ["systemctl not found"],
                    },
                }
            ]
        )

        self.assertEqual(assessment.risk_level.value, "R1")
        self.assertIn("unavailable", assessment.reasons[0])

    def test_world_writable_configuration_is_r2(self) -> None:
        assessment = assess_evidence_risk(
            [
                {
                    "tool_name": "config_integrity_scan",
                    "result": {
                        "status": "ok",
                        "observations": [
                            {
                                "path": "/tmp/opscouncil-lab/etc/service-agent.conf",
                                "mode": "0o666",
                                "sha256": "f" * 64,
                            }
                        ],
                    },
                }
            ]
        )

        self.assertEqual(assessment.risk_level.value, "R2")
        self.assertIn("开放写权限", assessment.reasons[0])

    def test_symlink_mode_does_not_raise_world_writable_risk(self) -> None:
        assessment = assess_evidence_risk(
            [
                {
                    "tool_name": "config_baseline_check",
                    "result": {
                        "status": "ok",
                        "observations": [
                            {
                                "path": "/etc/resolv.conf",
                                "file_type": "symlink",
                                "mode": "0o777",
                                "change_types": ["metadata_changed"],
                            }
                        ],
                    },
                }
            ]
        )

        self.assertEqual(assessment.risk_level.value, "R1")
        self.assertEqual(len(assessment.reasons), 1)
        self.assertIn("仅发生元数据变化", assessment.reasons[0])

    def test_failed_service_health_endpoint_is_r2(self) -> None:
        assessment = assess_evidence_risk(
            [
                {
                    "tool_name": "service_health_probe",
                    "result": {
                        "status": "ok",
                        "observations": [
                            {
                                "url": "http://127.0.0.1:18080/health",
                                "available": False,
                                "status_code": 503,
                            }
                        ],
                    },
                }
            ]
        )

        self.assertEqual(assessment.risk_level.value, "R2")
        self.assertIn("5xx", assessment.reasons[0])


if __name__ == "__main__":
    unittest.main()
