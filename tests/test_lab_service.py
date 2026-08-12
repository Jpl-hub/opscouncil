from __future__ import annotations

from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from backend.app.lab.service import LabService


class LabServiceTest(unittest.TestCase):
    def test_disk_large_log_lab_can_activate_and_reset_inside_root(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = LabService(root)

            ready = service.activate("disk-large-log", size_mb=1)

            artifact = Path(ready["artifact_path"])
            self.assertEqual(ready["status"], "ready")
            self.assertTrue(artifact.exists())
            self.assertTrue(artifact.is_relative_to(root))
            self.assertGreaterEqual(ready["size_bytes"], 1024 * 1024)

            idle = service.reset("disk-large-log")

            self.assertEqual(idle["status"], "idle")
            self.assertFalse(artifact.exists())

    def test_unknown_lab_scenario_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            service = LabService(Path(tmp))

            with self.assertRaises(LookupError):
                service.activate("unknown")

    def test_network_listener_lab_can_activate_and_reset_inside_root(self) -> None:
        with TemporaryDirectory() as tmp:
            port = _free_tcp_port()
            service = LabService(Path(tmp), network_port=port)

            ready = service.activate("network-local-listener")

            self.assertEqual(ready["status"], "ready")
            self.assertEqual(ready["metadata"]["port"], port)
            self.assertEqual(ready["metadata"]["bind"], "0.0.0.0")
            self.assertTrue(ready["metadata"]["reachable"])
            self.assertIsInstance(ready["metadata"]["pid"], int)

            idle = service.reset("network-local-listener")

            self.assertEqual(idle["status"], "idle")
            self.assertIsNone(idle["metadata"].get("pid"))

    def test_config_drift_lab_can_activate_and_reset_inside_root(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            service = LabService(root)

            ready = service.activate("config-drift-sample")

            artifact = Path(ready["artifact_path"])
            self.assertEqual(ready["status"], "ready")
            self.assertTrue(artifact.exists())
            self.assertTrue(artifact.is_relative_to(root))
            self.assertEqual(oct(artifact.stat().st_mode & 0o777), "0o666")
            self.assertTrue(ready["metadata"]["hash_changed"])
            self.assertTrue(ready["metadata"]["permission_expanded"])

            idle = service.reset("config-drift-sample")

            self.assertEqual(idle["status"], "idle")
            self.assertFalse(artifact.exists())

    def test_config_mode_recovery_preserves_content_and_only_expands_mode(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            service = LabService(root)

            prepared = service.prepare_confirmed_baseline("config-mode-recovery")
            artifact = Path(prepared["path"])
            baseline_content = artifact.read_bytes()
            ready = service.activate("config-mode-recovery")

            self.assertEqual(ready["status"], "ready")
            self.assertEqual(artifact.read_bytes(), baseline_content)
            self.assertEqual(oct(artifact.stat().st_mode & 0o777), "0o666")
            self.assertFalse(ready["metadata"]["hash_changed"])
            self.assertTrue(ready["metadata"]["permission_expanded"])
            self.assertEqual(service.reset("config-mode-recovery")["status"], "idle")

    def test_catalog_exposes_sixteen_bounded_scenarios(self) -> None:
        with TemporaryDirectory() as tmp:
            states = LabService(Path(tmp)).list_scenarios()

        self.assertEqual(len(states), 16)
        self.assertTrue(all(item["contract_version"] == "opsbench.v2" for item in states))
        self.assertTrue(all("resource_budget" in item for item in states))
        self.assertTrue(all("probe" in item and "oracle" in item for item in states))
        controller = next(item for item in states if item["id"] == "duplicate-tool-budget")
        self.assertEqual(controller["status"], "ready")
        self.assertFalse(controller["setup_required"])

    @patch("backend.app.lab.service.shutil.which", return_value="/usr/bin/systemctl")
    @patch("backend.app.lab.service.subprocess.run")
    def test_preinstalled_failed_service_fixture_is_read_only_and_ready(
        self,
        run_mock,
        _which_mock,
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=["systemctl", "show"],
            returncode=0,
            stdout="LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\n",
            stderr="",
        )
        with TemporaryDirectory() as tmp:
            service = LabService(Path(tmp))

            ready = service.activate("failed-service")
            reset = service.reset("failed-service")

        self.assertEqual(ready["status"], "ready")
        self.assertFalse(ready["setup_required"])
        self.assertEqual(ready["metadata"]["Result"], "exit-code")
        self.assertEqual(reset["status"], "ready")
        self.assertTrue(all(call.args[0][0:2] == ["systemctl", "show"] for call in run_mock.call_args_list))

    def test_inode_growth_is_real_and_cleanup_is_bounded(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            service = LabService(root)

            ready = service.activate("inode-growth")

            self.assertEqual(ready["status"], "ready")
            self.assertEqual(ready["metadata"]["file_count"], 1200)
            self.assertEqual(len(list(Path(ready["artifact_path"]).glob("*.sample"))), 1200)

            idle = service.reset("inode-growth")

            self.assertEqual(idle["status"], "idle")
            self.assertFalse(Path(ready["artifact_path"]).exists())

    def test_zombie_process_has_real_proc_state_and_is_reaped_on_reset(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            service = LabService(Path(tmp))

            ready = service.activate("zombie-process")
            parent_pid = int(ready["metadata"]["pid"])
            child_pid = int(ready["metadata"]["child_pid"])

            self.assertEqual(ready["status"], "ready")
            self.assertEqual(ready["metadata"]["child_state"], "Z")
            self.assertTrue((Path("/proc") / str(parent_pid)).exists())
            self.assertTrue((Path("/proc") / str(child_pid)).exists())

            idle = service.reset("zombie-process")

            self.assertEqual(idle["status"], "idle")
            self.assertFalse((Path("/proc") / str(parent_pid)).exists())

    def test_fd_workload_opens_real_descriptors(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            service = LabService(Path(tmp))

            ready = service.activate("file-descriptor-growth")
            pid = int(ready["metadata"]["pid"])

            self.assertEqual(ready["status"], "ready")
            self.assertGreaterEqual(ready["metadata"]["actual_fd_count"], 96)
            self.assertEqual(ready["metadata"]["max_open_files_soft"], 112)
            self.assertGreaterEqual(ready["metadata"]["fd_utilization_percent"], 70)
            self.assertGreaterEqual(len(list((Path("/proc") / str(pid) / "fd").iterdir())), 96)

            self.assertEqual(service.reset("file-descriptor-growth")["status"], "idle")

    def test_deleted_open_file_workload_retains_blocks_until_reset(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            service = LabService(Path(tmp))

            ready = service.activate("deleted-open-file")
            pid = int(ready["metadata"]["pid"])
            target = Path(ready["metadata"]["target_path"])

            self.assertEqual(ready["status"], "ready")
            self.assertFalse(target.exists())
            self.assertTrue(ready["metadata"]["deleted_fd_observed"])
            self.assertEqual(
                ready["metadata"]["actual_retained_bytes"],
                12 * 1024 * 1024,
            )

            idle = service.reset("deleted-open-file")

            self.assertEqual(idle["status"], "idle")
            self.assertFalse((Path("/proc") / str(pid)).exists())

    def test_cpu_memory_and_io_workloads_obey_resource_caps(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            service = LabService(Path(tmp))

            cpu = service.activate("cpu-memory-pressure")
            self.assertEqual(cpu["status"], "ready")
            self.assertEqual(cpu["metadata"]["allocated_bytes"], 64 * 1024 * 1024)
            self.assertGreaterEqual(cpu["metadata"]["warmup_cpu_seconds"], 0.12)
            self.assertLessEqual(cpu["metadata"]["warmup_cpu_seconds"], 0.5)
            self.assertGreaterEqual(cpu["metadata"]["cpu_percent"], 20.0)
            self.assertEqual(service.reset("cpu-memory-pressure")["status"], "idle")

            io_state = service.activate("io-pressure")
            self.assertEqual(io_state["status"], "ready")
            target = Path(io_state["metadata"]["target_path"])
            for _ in range(8):
                self.assertEqual(target.stat().st_size, 16 * 1024 * 1024)
                time.sleep(0.01)
            self.assertEqual(service.reset("io-pressure")["status"], "idle")

    def test_composite_service_scenario_creates_real_causal_chain_and_cleans_up(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            service_port = _free_adjacent_tcp_ports()
            service = LabService(
                Path(tmp),
                network_port=_free_tcp_port(),
                service_port=service_port,
            )

            ready = service.activate("service-dependency-degradation")

            self.assertEqual(ready["status"], "ready")
            self.assertEqual(ready["metadata"]["health_status_code"], 503)
            self.assertTrue(ready["metadata"]["frontend_reachable"])
            self.assertTrue(ready["metadata"]["dependency_reachable"])
            self.assertTrue(ready["metadata"]["dependency_process_alive"])
            self.assertTrue(ready["metadata"]["decoy_hash_unchanged"])
            self.assertTrue(ready["metadata"]["decoy_mtime_changed"])
            self.assertEqual(len(ready["probes"]), 7)
            self.assertEqual(
                ready["probes"][0]["arguments"]["url"],
                f"http://127.0.0.1:{service_port}/health",
            )
            pid = int(ready["metadata"]["pid"])
            dependency_pid = int(ready["metadata"]["dependency_pid"])
            self.assertNotEqual(pid, dependency_pid)

            idle = service.reset("service-dependency-degradation")

            self.assertEqual(idle["status"], "idle")
            self.assertFalse((Path("/proc") / str(pid)).exists())
            self.assertFalse((Path("/proc") / str(dependency_pid)).exists())
            self.assertFalse(Path(ready["artifact_path"]).parent.exists())


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _free_adjacent_tcp_ports() -> int:
    for _ in range(100):
        first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            first.bind(("127.0.0.1", 0))
            port = int(first.getsockname()[1])
            if port >= 65535:
                continue
            second.bind(("127.0.0.1", port + 1))
            return port
        except OSError:
            continue
        finally:
            first.close()
            second.close()
    raise RuntimeError("unable to reserve adjacent loopback ports")


if __name__ == "__main__":
    unittest.main()
