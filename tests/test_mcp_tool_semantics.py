from __future__ import annotations

from collections import namedtuple
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import unittest

from backend.app.executor.tools import register_executor_tools
from backend.app.mcp.semantics import enrich_tool_result
from backend.app.mcp.types import ToolResult
from backend.app.perception.tools import _collect_proc_socket_owners
from backend.app.perception.tools import build_perception_registry


DiskUsage = namedtuple("DiskUsage", "total used free")


class MCPToolSemanticsTest(unittest.TestCase):
    def test_procfs_socket_owner_mapping_reads_only_process_metadata(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
            proc_root = Path(temp_dir)
            process_root = proc_root / "241"
            fd_root = process_root / "fd"
            fd_root.mkdir(parents=True)
            (process_root / "comm").write_text("systemd-resolve\n", encoding="utf-8")
            (process_root / "status").write_text(
                "Name:\tsystemd-resolve\nUid:\t101\t101\t101\t101\n",
                encoding="utf-8",
            )
            (fd_root / "13").symlink_to("socket:[222]")
            (fd_root / "14").symlink_to("/tmp/not-a-socket")

            owners = _collect_proc_socket_owners({222}, proc_root=proc_root)

        self.assertEqual(
            owners[222],
            {
                "pid": 241,
                "process_name": "systemd-resolve",
                "uid": 101,
                "user": "systemd-resolve",
            },
        )

    def test_disk_usage_exposes_pressure_summary_and_risk_hint(self) -> None:
        registry = build_perception_registry()
        usage = DiskUsage(total=1000, used=920, free=80)

        with patch("backend.app.perception.tools.shutil.disk_usage", return_value=usage):
            result = registry.call("disk_usage", {"paths": ["/"]})

        self.assertEqual(result.summary_fields["observation_count"], 1)
        self.assertEqual(result.summary_fields["highest_used_path"], "/")
        self.assertEqual(result.summary_fields["highest_used_percent"], 92.0)
        self.assertEqual(result.summary_fields["critical_filesystem_count"], 1)
        self.assertIn("文件系统使用率达到 92.0%", result.risk_hints[0])

    def test_network_listener_summary_identifies_wildcard_and_unattributed_ports(self) -> None:
        registry = build_perception_registry()
        completed = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout=(
                "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"demo\",pid=7,fd=3)) uid:1000 ino:111\n"
                "udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* uid:101 ino:222\n"
            ),
        )

        with (
            patch("backend.app.perception.tools.shutil.which", return_value="/usr/bin/ss"),
            patch("backend.app.perception.tools.subprocess.run", return_value=completed),
            patch(
                "backend.app.perception.tools._collect_proc_socket_owners",
                return_value={
                    222: {
                        "pid": 241,
                        "process_name": "systemd-resolve",
                        "uid": 101,
                        "user": "systemd-resolve",
                    }
                },
            ),
        ):
            result = registry.call("network_listeners", {"limit": 10})

        self.assertEqual(result.summary_fields["listener_count"], 2)
        self.assertEqual(result.summary_fields["wildcard_listener_count"], 1)
        self.assertEqual(result.summary_fields["unattributed_listener_count"], 0)
        self.assertEqual(result.summary_fields["ss_attributed_listener_count"], 1)
        self.assertEqual(result.summary_fields["procfs_attributed_listener_count"], 1)
        self.assertEqual(result.summary_fields["attribution_rate_percent"], 100.0)
        self.assertEqual(result.observations[0]["pid"], 7)
        self.assertEqual(result.observations[0]["process_name"], "demo")
        self.assertEqual(result.observations[0]["uid"], 1000)
        self.assertEqual(result.observations[0]["attribution_source"], "ss")
        self.assertEqual(result.observations[0]["exposure_scope"], "wildcard")
        self.assertEqual(result.observations[1]["pid"], 241)
        self.assertEqual(result.observations[1]["process_name"], "systemd-resolve")
        self.assertEqual(result.observations[1]["user"], "systemd-resolve")
        self.assertEqual(result.observations[1]["socket_inode"], 222)
        self.assertEqual(result.observations[1]["attribution_source"], "procfs")
        self.assertEqual(result.observations[1]["exposure_scope"], "loopback")
        self.assertEqual(result.summary_fields["private_listener_count"], 0)
        self.assertEqual(result.summary_fields["public_listener_count"], 0)
        self.assertIn("绑定所有地址", " ".join(result.risk_hints))
        self.assertNotIn("缺少进程归属", " ".join(result.risk_hints))
        self.assertIn("/proc/*/fd", result.evidence_refs)

    def test_service_status_records_successful_zero_failed_services_as_evidence(self) -> None:
        registry = build_perception_registry()
        completed = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout="0 loaded units listed.\n",
        )

        with (
            patch("backend.app.perception.tools.shutil.which", return_value="/usr/bin/systemctl"),
            patch("backend.app.perception.tools.subprocess.run", return_value=completed),
        ):
            result = registry.call("service_status", {"unit": None})

        self.assertEqual(
            result.observations,
            [{"scope": "failed_services", "failed_count": 0}],
        )
        self.assertEqual(result.status, "ok")

    def test_service_status_normalizes_target_unit_startup_context(self) -> None:
        registry = build_perception_registry()
        completed = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout=(
                "Result=exit-code\n"
                "NRestarts=0\n"
                "ExecMainPID=314\n"
                "ExecMainCode=1\n"
                "ExecMainStatus=1\n"
                "ExecStart={ path=/usr/bin/false ; argv[]=/usr/bin/false ; status=1 }\n"
                "Id=demo.service\n"
                "LoadState=loaded\n"
                "ActiveState=failed\n"
                "SubState=failed\n"
                "FragmentPath=/etc/systemd/system/demo.service\n"
                "UnitFileState=static\n"
            ),
        )

        with (
            patch("backend.app.perception.tools.shutil.which", return_value="/usr/bin/systemctl"),
            patch("backend.app.perception.tools.subprocess.run", return_value=completed),
        ):
            result = registry.call("service_status", {"unit": "demo.service"})

        self.assertEqual(
            result.observations,
            [
                {
                    "unit": "demo.service",
                    "load_state": "loaded",
                    "active_state": "failed",
                    "sub_state": "failed",
                    "result": "exit-code",
                    "main_pid": 314,
                    "exec_main_code": 1,
                    "exec_main_status": 1,
                    "exec_start_path": "/usr/bin/false",
                    "fragment_path": "/etc/systemd/system/demo.service",
                    "unit_file_state": "static",
                    "restart_count": 0,
                }
            ],
        )

    def test_side_effect_dry_run_reports_reversibility_and_expected_reclaim(self) -> None:
        registry = build_perception_registry()
        register_executor_tools(registry)

        with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
            target = Path(temp_dir) / "application.log"
            target.write_bytes(b"x" * 128)

            result = registry.call(
                "safe_log_rotate",
                {"path": str(target), "dry_run": True, "backup": True, "compress": True},
            )

        self.assertTrue(result.summary_fields["dry_run"])
        self.assertEqual(result.summary_fields["estimated_reclaim_bytes"], 128)
        self.assertEqual(result.summary_fields["rollback_strategy"], "restore_backup")
        self.assertIn("尚未修改文件", " ".join(result.risk_hints))

    def test_targeted_socket_semantics_reports_scope_and_attribution(self) -> None:
        result = enrich_tool_result(
            "socket_process_context",
            ToolResult(
                observations=[
                    {
                        "protocol": "tcp",
                        "port": 8443,
                        "listener_count": 1,
                        "unattributed_count": 0,
                        "scan_truncated": False,
                        "listeners": [
                            {
                                "exposure_scope": "wildcard",
                                "pid": 42,
                                "systemd_unit": "gateway.service",
                            }
                        ],
                    }
                ]
            ),
        )

        self.assertEqual(result.summary_fields["listener_count"], 1)
        self.assertEqual(result.summary_fields["service_attributed_count"], 1)
        self.assertEqual(result.summary_fields["exposed_listener_count"], 1)
        self.assertIn("全地址", " ".join(result.risk_hints))

    def test_mount_semantics_reports_capacity_and_security_context(self) -> None:
        result = enrich_tool_result(
            "filesystem_mount_context",
            ToolResult(
                observations=[
                    {
                        "resolved_path": "/var/log",
                        "mount_target": "/var",
                        "filesystem_type": "xfs",
                        "used_percent": 91.2,
                        "read_only": False,
                        "noexec": True,
                        "nosuid": True,
                        "nodev": True,
                        "is_network_filesystem": False,
                    }
                ]
            ),
        )

        self.assertTrue(result.summary_fields["is_separate_mount"])
        self.assertTrue(result.summary_fields["noexec"])
        self.assertEqual(result.summary_fields["used_percent"], 91.2)
        self.assertIn("91.2%", " ".join(result.risk_hints))

    def test_service_relationship_semantics_report_facts_and_coverage_gaps(self) -> None:
        result = enrich_tool_result(
            "service_dependency_snapshot",
            ToolResult(
                observations=[
                    {
                        "service_count": 1,
                        "process_count": 2,
                        "listener_count": 2,
                        "connection_relation_count": 1,
                        "external_endpoint_count": 0,
                        "focus_process_ids": [42],
                        "evidence_gaps": [
                            {"code": "SOCKET_OWNER_UNAVAILABLE", "count": 1}
                        ],
                        "scan": {
                            "listener_truncated": False,
                            "connection_truncated": False,
                        },
                    }
                ]
            ),
        )

        self.assertEqual(result.summary_fields["connection_relation_count"], 1)
        self.assertEqual(result.summary_fields["focus_process_count"], 1)
        self.assertEqual(result.summary_fields["evidence_gap_count"], 1)
        self.assertIn("证据缺口", " ".join(result.risk_hints))
        self.assertNotIn("根因", " ".join(result.risk_hints))


if __name__ == "__main__":
    unittest.main()
