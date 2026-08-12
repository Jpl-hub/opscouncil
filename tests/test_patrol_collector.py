from __future__ import annotations

from datetime import datetime, timezone
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.mcp.types import ToolResult
from backend.app.models.entities import (
    ConfigBaseline,
    ConfigBaselineCheck,
    ServiceExpectation,
    SystemSnapshot,
)
from backend.app.patrol.collector import PatrolCollector


class FakeRegistry:
    def __init__(self, results: dict[str, ToolResult]) -> None:
        self.results = results
        self.calls: list[tuple[str, dict]] = []

    def call(self, tool_name: str, payload: dict) -> ToolResult:
        self.calls.append((tool_name, payload))
        return self.results[tool_name]


class PatrolCollectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
        for table in (
            SystemSnapshot.__table__,
            ConfigBaseline.__table__,
            ConfigBaselineCheck.__table__,
            ServiceExpectation.__table__,
        ):
            table.create(self.engine)
        self.session = Session(self.engine, expire_on_commit=False)

    def tearDown(self) -> None:
        self.session.close()
        self.engine.dispose()

    def test_builds_operational_signals_from_real_readonly_tool_results(self) -> None:
        registry = FakeRegistry(_healthy_results())
        registry.results["system_snapshot"] = ToolResult(
            observations=[
                {
                    "hostname": "node-a",
                    "machine": "loongarch64",
                    "memory": {"used_percent": 62.0},
                    "pressure": {
                        "memory": {
                            "some": {"avg10": 12.0},
                            "full": {"avg10": 0.4},
                        }
                    },
                }
            ],
            evidence_refs=["/proc/meminfo", "/proc/pressure/memory"],
        )
        registry.results["disk_usage"] = ToolResult(
            observations=[
                {
                    "path": "/",
                    "used_percent": 45.0,
                    "inode_used_percent": 92.5,
                }
            ],
            evidence_refs=["/", "statvfs:/"],
        )
        registry.results["process_list"] = ToolResult(
            observations=[
                {
                    "pid": 88,
                    "ppid": 1,
                    "command": "defunct-worker",
                    "cpu_percent": 0.0,
                    "is_zombie": True,
                }
            ],
            evidence_refs=["ps"],
        )
        registry.results["service_status"] = ToolResult(
            observations=[
                {
                    "unit": "demo.service",
                    "load": "loaded",
                    "active": "failed",
                    "sub": "failed",
                    "description": "Controlled demo service",
                }
            ],
            evidence_refs=["systemctl"],
        )
        registry.results["time_sync_status"] = ToolResult(
            observations=[
                {
                    "ntp_synchronized": False,
                    "ntp_enabled": True,
                    "timezone": "Asia/Shanghai",
                    "local_rtc": False,
                }
            ],
            evidence_refs=["timedatectl show"],
        )

        report = PatrolCollector(registry, self.session).read()  # type: ignore[arg-type]

        signals = {item["key"]: item for item in report["signals"]}
        self.assertEqual(report["collection_status"], "ok")
        self.assertEqual(signals["inode_pressure"]["status"], "critical")
        self.assertEqual(signals["memory_pressure"]["status"], "warn")
        self.assertIn("PSI", signals["memory_pressure"]["detail"])
        self.assertEqual(signals["process_pressure"]["status"], "critical")
        self.assertEqual(signals["failed_service"]["status"], "critical")
        self.assertEqual(signals["time_sync"]["status"], "critical")
        self.assertEqual(signals["config_drift"]["status"], "unknown")
        self.assertEqual(signals["mcp_health"]["status"], "ok")
        self.assertEqual(report["status"], "error")

    def test_zero_failed_service_summary_is_not_reported_as_unknown_unit(self) -> None:
        registry = FakeRegistry(_healthy_results())
        registry.results["service_status"] = ToolResult(
            observations=[{"scope": "failed_services", "failed_count": 0}],
            evidence_refs=["systemctl"],
        )

        report = PatrolCollector(registry, self.session).read()  # type: ignore[arg-type]

        signal = next(
            item for item in report["signals"] if item["key"] == "failed_service"
        )
        self.assertEqual(signal["status"], "ok")
        self.assertEqual(signal["metric"], "0 个失败服务")
        self.assertEqual(signal["detail"], "systemd 未报告失败服务。")
        self.assertNotIn("unknown", signal["detail"])

    def test_malformed_failed_service_summary_remains_an_evidence_gap(self) -> None:
        registry = FakeRegistry(_healthy_results())
        registry.results["service_status"] = ToolResult(
            observations=[{"scope": "failed_services", "failed_count": 1}],
            evidence_refs=["systemctl"],
        )

        report = PatrolCollector(registry, self.session).read()  # type: ignore[arg-type]

        signal = next(
            item for item in report["signals"] if item["key"] == "failed_service"
        )
        self.assertEqual(signal["status"], "unknown")
        self.assertIn("缺少可核验的单元标识", signal["detail"])

    def test_compares_latest_configuration_baseline_without_returning_content(self) -> None:
        self.session.add(
            ConfigBaseline(
                name="关键配置",
                paths_json=["/etc/hosts"],
                snapshot_json=[
                    {
                        "path": "/etc/hosts",
                        "exists": True,
                        "file_type": "file",
                        "size_bytes": 10,
                        "mtime": 1.0,
                        "mode": "0o644",
                        "uid": 0,
                        "gid": 0,
                        "sha256": "a" * 64,
                        "hash_truncated": False,
                    }
                ],
                warnings_json=[],
            )
        )
        self.session.commit()
        registry = FakeRegistry(_healthy_results())
        registry.results["config_integrity_scan"] = ToolResult(
            observations=[
                {
                    "path": "/etc/hosts",
                    "exists": True,
                    "file_type": "file",
                    "size_bytes": 10,
                    "mtime": 2.0,
                    "mode": "0o600",
                    "uid": 0,
                    "gid": 0,
                    "sha256": "b" * 64,
                    "hash_truncated": False,
                }
            ],
            evidence_refs=["/etc/hosts"],
        )

        report = PatrolCollector(registry, self.session).read()  # type: ignore[arg-type]

        signal = next(item for item in report["signals"] if item["key"] == "config_drift")
        self.assertEqual(signal["status"], "critical")
        self.assertEqual(signal["metric"], "1 项变化")
        self.assertEqual(signal["evidence_refs"], ["config_baseline:1", "config_baseline_check:1"])
        self.assertNotIn("content", str(report).lower())
        self.assertEqual(len(self.session.query(ConfigBaselineCheck).all()), 1)

    def test_lab_baseline_never_enters_live_patrol(self) -> None:
        self.session.add(
            ConfigBaseline(
                name="评测配置基线",
                scope="LAB",
                paths_json=["/tmp/opscouncil-lab/etc/managed-agent.conf"],
                snapshot_json=[
                    {
                        "path": "/tmp/opscouncil-lab/etc/managed-agent.conf",
                        "exists": True,
                        "sha256": "a" * 64,
                    }
                ],
                warnings_json=[],
                created_by="opsbench",
            )
        )
        self.session.commit()
        registry = FakeRegistry(_healthy_results())

        report = PatrolCollector(registry, self.session).read()  # type: ignore[arg-type]

        signal = next(item for item in report["signals"] if item["key"] == "config_drift")
        self.assertEqual(signal["status"], "unknown")
        self.assertEqual(signal["metric"], "未建立基线")
        self.assertNotIn("config_integrity_scan", [name for name, _ in registry.calls])
        self.assertEqual(self.session.query(ConfigBaselineCheck).count(), 0)

    def test_metadata_only_drift_is_reported_without_content_alarm(self) -> None:
        self.session.add(
            ConfigBaseline(
                name="关键配置",
                paths_json=["/etc/hosts"],
                snapshot_json=[
                    {
                        "path": "/etc/hosts",
                        "resolved_path": "/etc/hosts",
                        "exists": True,
                        "file_type": "file",
                        "size_bytes": 10,
                        "mtime": 1.0,
                        "mode": "0o644",
                        "uid": 0,
                        "gid": 0,
                        "sha256": "a" * 64,
                    }
                ],
                warnings_json=[],
            )
        )
        self.session.commit()
        registry = FakeRegistry(_healthy_results())
        registry.results["config_integrity_scan"] = ToolResult(
            observations=[
                {
                    "path": "/etc/hosts",
                    "resolved_path": "/etc/hosts",
                    "exists": True,
                    "file_type": "file",
                    "size_bytes": 10,
                    "mtime": 2.0,
                    "mode": "0o644",
                    "uid": 0,
                    "gid": 0,
                    "sha256": "a" * 64,
                }
            ],
            evidence_refs=["/etc/hosts"],
        )

        report = PatrolCollector(registry, self.session).read()  # type: ignore[arg-type]

        signal = next(item for item in report["signals"] if item["key"] == "config_drift")
        self.assertEqual(signal["status"], "warn")
        self.assertEqual(signal["metric"], "1 项元数据变化")
        self.assertIn("内容哈希与权限未变", signal["detail"])

    def test_unavailable_additional_probe_marks_collection_error(self) -> None:
        registry = FakeRegistry(_healthy_results())
        registry.results["time_sync_status"] = ToolResult(
            status="unavailable",
            warnings=["timedatectl not found"],
        )

        report = PatrolCollector(registry, self.session).read()  # type: ignore[arg-type]

        signals = {item["key"]: item for item in report["signals"]}
        self.assertEqual(report["collection_status"], "error")
        self.assertEqual(signals["time_sync"]["status"], "unknown")
        self.assertEqual(signals["mcp_health"]["status"], "critical")
        self.assertIn("timedatectl not found", report["warnings"])

    def test_service_expectation_drift_enters_patrol_signal_with_owner_context(self) -> None:
        self.session.add(
            ServiceExpectation(
                host_key="node-a",
                unit_name="billing-api.service",
                version=1,
                record_status="ACTIVE",
                expected_active_state="active",
                service_owner="支付平台组",
                criticality="CRITICAL",
                environment="PRODUCTION",
                rationale="核心交易接口必须持续运行",
                source_ref="cmdb://service/billing-api",
                approved_by="ops-lead",
                effective_from=datetime.now(timezone.utc),
            )
        )
        self.session.commit()
        registry = FakeRegistry(_healthy_results())
        registry.results["service_status"] = ToolResult(
            observations=[
                {
                    "unit": "billing-api.service",
                    "load_state": "loaded",
                    "active_state": "failed",
                    "sub_state": "failed",
                    "result": "exit-code",
                }
            ],
            evidence_refs=["systemctl"],
        )

        report = PatrolCollector(registry, self.session).read()  # type: ignore[arg-type]

        signals = {item["key"]: item for item in report["signals"]}
        signal = signals["service_expectation"]
        self.assertEqual(signal["status"], "critical")
        self.assertEqual(signal["metric"], "1 项状态 / 0 项网络偏离")
        self.assertIn("billing-api.service：当前 failed", signal["detail"])
        self.assertIn("责任方 支付平台组", signal["detail"])
        self.assertIn("service_expectation:1:v1", signal["evidence_refs"])
        self.assertEqual(report["service_expectations"]["drift_count"], 1)
        self.assertEqual(
            report["service_expectations"]["items"][0]["service_owner"],
            "支付平台组",
        )

    def test_listener_scope_drift_enters_patrol_with_approved_owner(self) -> None:
        self.session.add(
            ServiceExpectation(
                host_key="node-a",
                unit_name="billing-api.service",
                version=1,
                record_status="ACTIVE",
                expected_active_state="active",
                service_owner="支付平台组",
                criticality="CRITICAL",
                environment="PRODUCTION",
                listener_expectations_json=[
                    {
                        "protocol": "tcp",
                        "port": 8443,
                        "allowed_scope": "private",
                        "required": True,
                    }
                ],
                rationale="结算接口仅允许内网访问",
                source_ref="cmdb://service/billing-api",
                approved_by="ops-lead",
                effective_from=datetime.now(timezone.utc),
            )
        )
        self.session.commit()
        registry = FakeRegistry(_healthy_results())
        registry.results["service_status"] = ToolResult(
            observations=[
                {
                    "unit": "billing-api.service",
                    "load_state": "loaded",
                    "active_state": "active",
                    "sub_state": "running",
                    "result": "success",
                }
            ],
            evidence_refs=["systemctl"],
        )
        registry.results["network_listeners"] = ToolResult(
            observations=[
                {
                    "protocol": "tcp",
                    "local_address": "0.0.0.0:8443",
                    "exposure_scope": "wildcard",
                    "pid": 281,
                    "process": "billing-api",
                    "systemd_unit": "billing-api.service",
                }
            ],
            evidence_refs=["ss -H -lntupe", "/proc/281/cgroup"],
        )

        report = PatrolCollector(registry, self.session).read()  # type: ignore[arg-type]

        signal = next(
            item
            for item in report["signals"]
            if item["key"] == "service_expectation"
        )
        self.assertEqual(signal["status"], "critical")
        self.assertEqual(signal["metric"], "0 项状态 / 1 项网络偏离")
        self.assertIn("超过登记范围 private", signal["detail"])
        self.assertEqual(
            report["service_expectations"]["network_drift_count"],
            1,
        )
        self.assertEqual(
            report["service_expectations"]["items"][0][
                "network_exposure_status"
            ],
            "DRIFT",
        )


def _healthy_results() -> dict[str, ToolResult]:
    return {
        "system_snapshot": ToolResult(
            observations=[
                {
                    "hostname": "node-a",
                    "machine": "loongarch64",
                    "memory": {"used_percent": 42.0},
                    "pressure": {},
                }
            ],
            evidence_refs=["/proc/meminfo"],
        ),
        "disk_usage": ToolResult(
            observations=[
                {"path": "/", "used_percent": 42.0, "inode_used_percent": 20.0}
            ],
            evidence_refs=["/", "statvfs:/"],
        ),
        "network_listeners": ToolResult(observations=[], evidence_refs=["ss"]),
        "process_list": ToolResult(
            observations=[
                {
                    "pid": 1,
                    "ppid": 0,
                    "command": "systemd",
                    "cpu_percent": 0.1,
                    "is_zombie": False,
                }
            ],
            evidence_refs=["ps"],
        ),
        "service_status": ToolResult(observations=[], evidence_refs=["systemctl"]),
        "time_sync_status": ToolResult(
            observations=[
                {
                    "ntp_synchronized": True,
                    "ntp_enabled": True,
                    "timezone": "Asia/Shanghai",
                    "local_rtc": False,
                }
            ],
            evidence_refs=["timedatectl show"],
        ),
        "config_integrity_scan": ToolResult(observations=[]),
    }


if __name__ == "__main__":
    unittest.main()
