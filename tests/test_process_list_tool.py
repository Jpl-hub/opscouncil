from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from backend.app.perception.tools import build_perception_registry


class ProcessListToolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = build_perception_registry()

    def test_parses_process_names_that_contain_spaces(self) -> None:
        completed = SimpleNamespace(
            stdout=(
                "123 1 Sl 12.5 3.4 Isolated Web Co\n"
                "124 1 R 0.5 0.1 python\n"
            ),
            stderr="",
            returncode=0,
        )

        with patch("backend.app.perception.tools.subprocess.run", return_value=completed):
            result = self.registry.call("process_list", {"limit": 5})

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 2)
        self.assertEqual(result.observations[0]["command"], "Isolated Web Co")
        self.assertEqual(result.observations[0]["cpu_percent"], 12.5)
        self.assertEqual(result.observations[0]["mem_percent"], 3.4)
        self.assertEqual(result.warnings, [])

    def test_skips_unparseable_rows_without_failing_tool(self) -> None:
        completed = SimpleNamespace(
            stdout=(
                "123 1 Sl not-a-cpu 3.4 broken process\n"
                "124 1 R 0.5 0.1 python\n"
            ),
            stderr="",
            returncode=0,
        )

        with patch("backend.app.perception.tools.subprocess.run", return_value=completed):
            result = self.registry.call("process_list", {"limit": 5})

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0]["command"], "python")
        self.assertTrue(any("process row skipped" in warning for warning in result.warnings))


if __name__ == "__main__":
    unittest.main()
