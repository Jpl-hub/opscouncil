from __future__ import annotations

from io import StringIO
import unittest

from scripts.opscouncilctl import build_parser, run


class FakeClient:
    def __init__(self) -> None:
        self.task_reads = 0

    def get(self, path: str, query: dict | None = None):
        if path == "/health":
            return {
                "status": "ok",
                "mcp": {"tool_count": 23},
                "ai": {
                    "chat_model": "qwen-plus-latest",
                    "embedding_model": "text-embedding-v4",
                },
                "worker": {"online_worker_count": 1},
            }
        if path == "/platform/capabilities":
            return {
                "platform": {
                    "hostname": "linux-node",
                    "machine": "loongarch64",
                    "os_release": {"pretty_name": "Enterprise Linux"},
                },
                "capabilities": {
                    "command.ps": {"status": "SUPPORTED"},
                    "command.ss": {"status": "SUPPORTED"},
                },
            }
        if path == "/deployment/readiness":
            return {
                "overall_status": "ok",
                "summary": "部署前置条件均满足。",
                "checks": [],
            }
        if path == "/tasks/7":
            self.task_reads += 1
            if self.task_reads == 1:
                return {
                    "id": 7,
                    "trace_id": "trace-7",
                    "status": "PERCEIVE",
                    "risk_level": "R0",
                    "queue_status": "RUNNING",
                    "summary": None,
                }
            return {
                "id": 7,
                "trace_id": "trace-7",
                "status": "SEALED",
                "risk_level": "R0",
                "queue_status": "SUCCEEDED",
                "summary": "系统快照与磁盘证据采集完成。",
            }
        if path == "/tasks/7/proposals":
            return []
        if path == "/audit/traces/trace-7/replay":
            return {
                "integrity": {
                    "valid": True,
                    "entry_count": 12,
                    "head_hash": "a" * 64,
                },
                "policy_replay": {
                    "status": "consistent",
                    "evaluated_count": 1,
                    "changed_count": 0,
                },
            }
        if path == "/proposals":
            assert query == {"status_filter": "PENDING_APPROVAL", "limit": 20}
            return []
        raise AssertionError(f"unexpected GET {path} {query}")

    def post(self, path: str, payload: dict | None = None):
        if path == "/tasks":
            assert payload == {"input": "检查磁盘空间"}
            return {
                "id": 7,
                "trace_id": "trace-7",
                "status": "RECEIVED",
                "risk_level": "R0",
                "queue_status": "QUEUED",
                "summary": None,
            }
        raise AssertionError(f"unexpected POST {path} {payload}")


class OpsCouncilCtlTest(unittest.TestCase):
    def test_doctor_reports_linux_runtime_without_bypassing_api(self) -> None:
        args = build_parser().parse_args(["doctor", "--strict"])
        output = StringIO()

        exit_code = run(args, FakeClient(), output=output)  # type: ignore[arg-type]

        self.assertEqual(exit_code, 0)
        text = output.getvalue()
        self.assertIn("Enterprise Linux", text)
        self.assertIn("loongarch64", text)
        self.assertIn("MCP 23 项", text)
        self.assertIn("2/2 可用", text)

    def test_ask_waits_for_governed_task_and_prints_audit_result(self) -> None:
        args = build_parser().parse_args(
            [
                "ask",
                "检查磁盘空间",
                "--timeout",
                "1",
                "--poll-interval",
                "0",
            ]
        )
        output = StringIO()

        exit_code = run(args, FakeClient(), output=output)  # type: ignore[arg-type]

        self.assertEqual(exit_code, 0)
        text = output.getvalue()
        self.assertIn("任务 #7：已入队", text)
        self.assertIn("任务 #7：正在调查", text)
        self.assertIn("SEALED", text)
        self.assertIn("系统快照与磁盘证据采集完成", text)
        self.assertIn("审计链    可信", text)
        self.assertIn("当前策略一致", text)

    def test_approvals_is_read_only_and_reports_empty_queue(self) -> None:
        args = build_parser().parse_args(["approvals"])
        output = StringIO()

        exit_code = run(args, FakeClient(), output=output)  # type: ignore[arg-type]

        self.assertEqual(exit_code, 0)
        self.assertIn("当前队列为空", output.getvalue())


if __name__ == "__main__":
    unittest.main()
