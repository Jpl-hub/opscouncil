from __future__ import annotations

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.benchmark.service import BENCHMARK_TOOLS, BenchmarkService
from backend.app.mcp.types import ToolResult
from backend.app.models.entities import EvaluationReport


class FakeRegistry:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def call(self, tool_name: str, payload: dict) -> ToolResult:
        self.calls.append((tool_name, payload))
        if tool_name == "system_snapshot":
            return ToolResult(
                observations=[
                    {
                        "hostname": "lab-node",
                        "machine": "loongarch64",
                        "kernel": "6.6.0",
                        "os_family": "linux",
                        "os_release": {"id": "enterprise-linux", "pretty_name": "Enterprise Linux 9"},
                    }
                ],
                evidence_refs=["/etc/os-release"],
            )
        return ToolResult(observations=[{"ok": True}], evidence_refs=[tool_name])


class FailingRegistry(FakeRegistry):
    def call(self, tool_name: str, payload: dict) -> ToolResult:
        if tool_name == "network_listeners":
            raise RuntimeError("ss failed")
        return super().call(tool_name, payload)


class BenchmarkServiceTest(unittest.TestCase):
    def test_run_records_mcp_tool_timings_and_persists_latest_report(self) -> None:
        with build_session() as session:
            service = BenchmarkService(session, FakeRegistry())

            report = service.run(rounds=2)
            latest = service.read_latest()

            self.assertEqual(report["rounds"], 2)
            self.assertEqual(report["environment"]["hostname"], "lab-node")
            self.assertEqual(report["environment"]["machine"], "loongarch64")
            self.assertEqual(report["summary"]["failed_count"], 0)
            self.assertGreaterEqual(report["summary"]["tool_count"], 4)
            self.assertEqual(latest["id"], report["id"])
            for metric in report["metrics"]:
                self.assertGreaterEqual(metric["duration_ms_avg"], 0)
                self.assertGreaterEqual(metric["duration_ms_p50"], 0)
                self.assertGreaterEqual(metric["duration_ms_p95"], metric["duration_ms_p50"])
                self.assertEqual(metric["success_rate"], 100)
                self.assertEqual(metric["success_count"], 2)
                self.assertIn(metric["status"], {"ok", "warn"})
            self.assertIn("worst_p95_tool", report["summary"])
            self.assertIn("worst_p95_ms", report["summary"])

    def test_run_marks_failed_tool_without_stopping_report(self) -> None:
        with build_session() as session:
            service = BenchmarkService(session, FailingRegistry())

            report = service.run(rounds=1)
            failed = [metric for metric in report["metrics"] if metric["status"] == "failed"]

            self.assertEqual(report["summary"]["failed_count"], 1)
            self.assertEqual(failed[0]["tool_name"], "network_listeners")
            self.assertEqual(failed[0]["success_rate"], 0)
            self.assertIn("ss failed", failed[0]["error"])

    def test_tool_performance_profile_does_not_mix_in_lab_fixture_paths(self) -> None:
        config_tool = next(
            item for item in BENCHMARK_TOOLS if item["tool_name"] == "config_integrity_scan"
        )

        self.assertEqual(
            config_tool["payload"]["paths"],
            ["/etc/hosts", "/etc/resolv.conf", "/etc/fstab"],
        )


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    EvaluationReport.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


if __name__ == "__main__":
    unittest.main()
