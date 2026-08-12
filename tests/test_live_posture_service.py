from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from backend.app.mcp.types import ToolResult
from backend.app.models.entities import SystemSnapshot
from backend.app.posture.service import LivePostureService


class FakeRegistry:
    def __init__(
        self,
        failures: set[str] | None = None,
        observations: dict[str, list[dict]] | None = None,
    ) -> None:
        self.failures = failures or set()
        self.observations = observations or {
            "system_snapshot": [
                {
                    "hostname": "linux-node",
                    "machine": "loongarch64",
                    "os_release": {"id": "linux", "name": "Linux"},
                }
            ],
            "disk_usage": [{"path": "/", "used_percent": 42.0}],
            "network_listeners": [{"protocol": "tcp", "local_address": "0.0.0.0:8000"}],
            "process_list": [{"pid": 1, "command": "systemd", "cpu_percent": 0.1}],
        }

    def call(self, tool_name: str, payload: dict) -> ToolResult:
        if tool_name in self.failures:
            raise RuntimeError(f"{tool_name} failed")
        observations = self.observations[tool_name]
        return ToolResult(observations=observations, evidence_refs=[tool_name])


class LivePostureServiceTest(unittest.TestCase):
    def test_collects_live_posture_from_registered_tools(self) -> None:
        report = LivePostureService(FakeRegistry()).read()

        self.assertEqual(report["status"], "warn")
        self.assertEqual(report["snapshot"]["hostname"], "linux-node")
        self.assertEqual(report["disks"][0]["path"], "/")
        self.assertEqual(report["network_listeners"][0]["local_address"], "0.0.0.0:8000")
        self.assertEqual(report["processes"][0]["command"], "systemd")
        self.assertEqual(len(report["tool_runs"]), 4)

        signals = {item["key"]: item for item in report["signals"]}
        self.assertEqual(signals["platform"]["status"], "ok")
        self.assertEqual(signals["network_exposure"]["status"], "warn")
        self.assertEqual(signals["network_exposure"]["metric"], "1 全地址 / 1 未归属")
        self.assertTrue(any(action["key"] == "network_exposure" for action in report["next_actions"]))

    def test_private_attributed_listener_does_not_create_exposure_warning(self) -> None:
        report = LivePostureService(
            FakeRegistry(
                observations={
                    "system_snapshot": [{"hostname": "linux-node", "machine": "loongarch64"}],
                    "disk_usage": [{"path": "/", "used_percent": 42.0}],
                    "network_listeners": [
                        {
                            "protocol": "tcp",
                            "local_address": "10.0.0.5:5432",
                            "pid": 337,
                            "process_name": "postgres",
                            "exposure_scope": "private",
                        },
                        {
                            "protocol": "tcp",
                            "local_address": "127.0.0.1:6379",
                            "pid": 293,
                            "process_name": "redis-server",
                            "exposure_scope": "loopback",
                        },
                    ],
                    "process_list": [{"pid": 1, "command": "systemd", "cpu_percent": 0.1}],
                }
            )
        ).read()

        signals = {item["key"]: item for item in report["signals"]}
        self.assertEqual(signals["network_exposure"]["status"], "ok")
        self.assertEqual(signals["network_exposure"]["metric"], "0 高风险 / 0 未归属")
        self.assertFalse(any(action["key"] == "network_exposure" for action in report["next_actions"]))

    def test_marks_report_error_when_any_tool_fails(self) -> None:
        report = LivePostureService(FakeRegistry(failures={"process_list"})).read()

        self.assertEqual(report["status"], "error")
        self.assertIn("process_list failed", report["warnings"])
        self.assertEqual(report["processes"], [])
        signals = {item["key"]: item for item in report["signals"]}
        self.assertEqual(signals["mcp_health"]["status"], "critical")

    def test_marks_resource_pressure_as_actionable_signals(self) -> None:
        report = LivePostureService(
            FakeRegistry(
                observations={
                    "system_snapshot": [
                        {
                            "hostname": "linux-node",
                            "machine": "loongarch64",
                            "memory": {"used_percent": 91.2},
                        }
                    ],
                    "disk_usage": [{"path": "/", "used_percent": 88.5}],
                    "network_listeners": [],
                    "process_list": [{"pid": 99, "command": "python", "cpu_percent": 92.0, "is_zombie": False}],
                }
            )
        ).read()

        signals = {item["key"]: item for item in report["signals"]}
        self.assertEqual(report["status"], "error")
        self.assertEqual(signals["memory_pressure"]["status"], "critical")
        self.assertEqual(signals["disk_pressure"]["status"], "warn")
        self.assertEqual(signals["process_pressure"]["status"], "warn")
        self.assertTrue(any(action["key"] == "memory_pressure" for action in report["next_actions"]))

    def test_compares_live_metrics_against_historical_baseline(self) -> None:
        session = _build_session()
        now = datetime.now(timezone.utc)
        for index in range(12):
            session.add(
                SystemSnapshot(
                    task_id=None,
                    payload_json={
                        "source": "live_posture",
                        "metrics": {
                            "memory_used_percent": 48.0 + index,
                            "root_disk_used_percent": 38.0 + index,
                            "listener_count": 1,
                            "top_cpu_percent": 15.0 + index,
                        },
                    },
                    created_at=now - timedelta(minutes=12 - index),
                )
            )
        session.commit()

        report = LivePostureService(
            FakeRegistry(
                observations={
                    "system_snapshot": [{"hostname": "linux-node", "memory": {"used_percent": 91.0}}],
                    "disk_usage": [{"path": "/", "used_percent": 85.0}],
                    "network_listeners": [
                        {"protocol": "tcp", "local_address": "127.0.0.1:53"},
                        {"protocol": "tcp", "local_address": "127.0.0.1:80"},
                        {"protocol": "tcp", "local_address": "127.0.0.1:443"},
                        {"protocol": "tcp", "local_address": "127.0.0.1:8080"},
                        {"protocol": "tcp", "local_address": "127.0.0.1:9000"},
                    ],
                    "process_list": [{"pid": 99, "command": "python", "cpu_percent": 92.0}],
                }
            ),
            session=session,
            persist_interval_seconds=0,
        ).read()

        baseline = report["baseline"]
        self.assertEqual(baseline["status"], "ready")
        self.assertEqual(baseline["sample_count"], 12)
        self.assertEqual(baseline["anomaly_score"], 100)
        self.assertEqual(baseline["metrics"]["memory_used_percent"]["baseline"], 53.5)
        self.assertEqual(baseline["metrics"]["listener_count"]["delta"], 4.0)
        signals = {item["key"]: item for item in report["signals"]}
        self.assertEqual(signals["baseline_regression"]["status"], "critical")
        baseline_action = next(action for action in report["next_actions"] if action["key"] == "baseline_regression")
        self.assertEqual(baseline_action["label"], "排查内存动态基线偏离")
        self.assertIn("动态基线偏离", baseline_action["prompt"])
        self.assertIn("内存压力和高占用进程", baseline_action["prompt"])
        self.assertEqual(
            session.scalar(select(func.count()).select_from(SystemSnapshot).where(SystemSnapshot.task_id.is_(None))),
            13,
        )
        session.close()

    def test_default_history_window_can_reach_capacity_forecast_horizon(self) -> None:
        session = _build_session()
        now = datetime.now(timezone.utc)
        for index in range(60):
            session.add(
                SystemSnapshot(
                    task_id=None,
                    payload_json={
                        "source": "live_posture",
                        "metrics": {
                            "memory_used_percent": 45.0,
                            "root_disk_used_percent": 70.0 + index * 0.2,
                            "listener_count": 1,
                            "top_cpu_percent": 8.0,
                        },
                    },
                    created_at=now - timedelta(minutes=60 - index),
                )
            )
        session.commit()

        report = LivePostureService(
            FakeRegistry(
                observations={
                    "system_snapshot": [
                        {"hostname": "linux-node", "memory": {"used_percent": 45.0}}
                    ],
                    "disk_usage": [{"path": "/", "used_percent": 82.0}],
                    "network_listeners": [
                        {
                            "protocol": "tcp",
                            "local_address": "127.0.0.1:8000",
                            "pid": 100,
                        }
                    ],
                    "process_list": [
                        {"pid": 100, "command": "python", "cpu_percent": 8.0}
                    ],
                }
            ),
            session=session,
            persist_interval_seconds=0,
        ).read()

        forecast = report["baseline"]["capacity_forecast"]
        self.assertIsInstance(forecast, dict)
        assert isinstance(forecast, dict)
        self.assertGreaterEqual(forecast["sample_span_minutes"], 45)
        session.close()

    def test_collects_history_before_reporting_baseline(self) -> None:
        session = _build_session()

        report = LivePostureService(
            FakeRegistry(),
            session=session,
            persist_interval_seconds=0,
        ).read()

        self.assertEqual(report["baseline"]["status"], "collecting")
        self.assertEqual(report["baseline"]["sample_count"], 0)
        self.assertEqual(report["baseline"]["minimum_sample_count"], 12)
        self.assertEqual(report["baseline"]["history_window_hours"], 24)
        self.assertEqual(
            session.scalar(select(func.count()).select_from(SystemSnapshot).where(SystemSnapshot.task_id.is_(None))),
            1,
        )
        session.close()

    def test_stale_samples_do_not_enter_the_dynamic_baseline(self) -> None:
        session = _build_session()
        now = datetime.now(timezone.utc)
        for index in range(12):
            session.add(
                SystemSnapshot(
                    task_id=None,
                    payload_json={
                        "source": "live_posture",
                        "metrics": {
                            "memory_used_percent": 40.0 + index,
                            "root_disk_used_percent": 45.0,
                            "listener_count": 1,
                            "top_cpu_percent": 5.0,
                        },
                    },
                    created_at=now - timedelta(hours=48, minutes=index),
                )
            )
        session.commit()

        report = LivePostureService(
            FakeRegistry(),
            session=session,
            persist_interval_seconds=0,
        ).read()

        self.assertEqual(report["baseline"]["status"], "collecting")
        self.assertEqual(report["baseline"]["sample_count"], 0)
        session.close()


def _build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    SystemSnapshot.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


if __name__ == "__main__":
    unittest.main()
