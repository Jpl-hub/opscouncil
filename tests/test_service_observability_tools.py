from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from tempfile import TemporaryDirectory
import unittest

from backend.app.perception.service_tools import (
    ApplicationLogQueryInput,
    ServiceHealthProbeInput,
    application_log_query,
    service_health_probe,
)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        payload = (
            b"x" * 8192
            if self.path == "/large"
            else json.dumps(
                {
                    "status": "degraded",
                    "dependency": "inventory-db",
                    "reason": "connect_timeout",
                    "token": "must-not-leak",
                }
            ).encode("utf-8")
        )
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


class ServiceObservabilityToolsTest(unittest.TestCase):
    def test_health_probe_reads_local_symptom_and_redacts_sensitive_fields(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = int(server.server_address[1])
            result = service_health_probe(
                ServiceHealthProbeInput(url=f"http://127.0.0.1:{port}/health")
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(result.status, "ok")
        observation = result.observations[0]
        self.assertFalse(observation["available"])
        self.assertEqual(observation["status_code"], 503)
        self.assertEqual(observation["body_summary"]["reason"], "connect_timeout")
        self.assertEqual(observation["body_summary"]["token"], "[已脱敏]")

    def test_health_probe_streams_only_the_configured_response_prefix(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = int(server.server_address[1])
            result = service_health_probe(
                ServiceHealthProbeInput(
                    url=f"http://127.0.0.1:{port}/large",
                    max_response_bytes=1024,
                )
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        observation = result.observations[0]
        self.assertTrue(observation["body_truncated"])
        self.assertEqual(len(observation["body_summary"]), 1000)

    def test_health_probe_rejects_non_loopback_target(self) -> None:
        with self.assertRaises(ValueError):
            ServiceHealthProbeInput(url="http://192.0.2.10/health")

    def test_health_probe_rejects_credentials_query_and_redirect_surface(self) -> None:
        for url in (
            "http://user:pass@127.0.0.1/health",
            "http://127.0.0.1/health?target=other",
            "https://127.0.0.1/health",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                ServiceHealthProbeInput(url=url)

    def test_application_log_query_is_bounded_and_redacts_credentials(self) -> None:
        root = Path("/tmp/opscouncil-lab/service-tool-test")
        root.mkdir(parents=True, exist_ok=True)
        path = root / "application.jsonl"
        path.write_text(
            "\n".join(
                (
                    '{"event":"ready"}',
                    '{"event":"request_failed","reason":"dependency_timeout"}',
                    "api_key=secret-value",
                )
            ),
            encoding="utf-8",
        )
        try:
            result = application_log_query(
                ApplicationLogQueryInput(path=str(path), lines=2)
            )
        finally:
            path.unlink(missing_ok=True)
            root.rmdir()

        self.assertEqual(result.status, "ok")
        observation = result.observations[0]
        self.assertEqual(observation["line_count"], 2)
        self.assertIn("dependency_timeout", observation["lines"][0])
        self.assertIn("[已脱敏]", observation["lines"][1])
        self.assertNotIn("secret-value", observation["lines"][1])
        self.assertEqual(observation["records"][0]["reason"], "dependency_timeout")

    def test_application_log_query_rejects_path_outside_read_scope(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.log"
            path.write_text("hello\n", encoding="utf-8")
            result = application_log_query(ApplicationLogQueryInput(path=str(path)))

        self.assertEqual(result.status, "rejected")
        self.assertIn("不在允许", result.warnings[0])

if __name__ == "__main__":
    unittest.main()
