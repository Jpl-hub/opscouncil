from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import unittest

from backend.app.core.pydantic_compat import BaseModel
from backend.app.deployment.capabilities import (
    CAPABILITY_SUPPORTED,
    CAPABILITY_UNAVAILABLE,
    PlatformCapabilityProbe,
)
from backend.app.mcp.registry import (
    ToolCapabilityUnavailableError,
    ToolRegistry,
)
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.schemas.enums import RiskLevel


class EmptyInput(BaseModel):
    pass


class PlatformCapabilityProbeTest(unittest.TestCase):
    def test_profiles_linux_loongarch_and_runtime_evidence(self) -> None:
        readable = {
            "/",
            "/etc/os-release",
            "/proc/self/status",
            "/proc/meminfo",
            "/proc/pressure/cpu",
            "/proc/pressure/memory",
            "/proc/pressure/io",
            "/sys/fs/cgroup/cgroup.controllers",
            "/run/systemd/system",
        }
        commands = {
            "ps": "/usr/bin/ps",
            "ss": "/usr/sbin/ss",
            "journalctl": "/usr/bin/journalctl",
            "systemctl": "/usr/bin/systemctl",
            "timedatectl": "/usr/bin/timedatectl",
            "findmnt": "/usr/bin/findmnt",
        }
        probe = PlatformCapabilityProbe(
            which=lambda command: commands.get(command),
            path_exists=lambda path: str(path) in readable,
            path_readable=lambda path: str(path) in readable,
            command_runner=lambda command: (0, f"{Path(command[0]).name} 1.0"),
            uname_provider=lambda: SimpleNamespace(
                nodename="linux-node",
                release="5.10.0-loongarch64",
                machine="loongarch64",
            ),
            os_release_reader=lambda: {
                "id": "enterprise-linux",
                "name": "Enterprise Linux",
                "pretty_name": "Enterprise Linux 9",
                "version_id": "9",
            },
            now=lambda: datetime(2026, 7, 28, tzinfo=timezone.utc),
        )

        profile = probe.probe()

        self.assertEqual(profile["status"], CAPABILITY_SUPPORTED)
        self.assertEqual(profile["platform"]["os_family"], "linux")
        self.assertTrue(profile["platform"]["is_loongarch"])
        self.assertEqual(
            profile["capabilities"]["command.ss"]["status"],
            CAPABILITY_SUPPORTED,
        )
        self.assertEqual(
            profile["capabilities"]["command.ss"]["evidence"]["executable"],
            "/usr/sbin/ss",
        )
        self.assertEqual(profile["probed_at"], "2026-07-28T00:00:00+00:00")

    def test_missing_command_is_explicitly_unavailable(self) -> None:
        probe = PlatformCapabilityProbe(
            which=lambda command: None,
            path_exists=lambda path: True,
            path_readable=lambda path: True,
            uname_provider=lambda: SimpleNamespace(
                nodename="test",
                release="test",
                machine="x86_64",
            ),
            os_release_reader=lambda: {"id": "linux"},
        )

        profile = probe.probe()

        self.assertEqual(
            profile["capabilities"]["command.ss"]["status"],
            CAPABILITY_UNAVAILABLE,
        )
        self.assertIn(
            "PATH",
            profile["capabilities"]["command.ss"]["reason"],
        )


class ToolCapabilityNegotiationTest(unittest.TestCase):
    def test_registry_blocks_tool_before_handler_when_requirement_is_missing(
        self,
    ) -> None:
        called = False

        def handler(_: BaseModel) -> ToolResult:
            nonlocal called
            called = True
            return ToolResult(observations=[{"unexpected": True}])

        registry = ToolRegistry(
            capability_provider=lambda: {
                "profile_version": "1.0.0",
                "probed_at": "2026-07-28T00:00:00+00:00",
                "capabilities": {
                    "command.ss": {
                        "status": CAPABILITY_UNAVAILABLE,
                        "reason": "未在 PATH 中发现命令。",
                    }
                },
            }
        )
        registry.register(
            ToolDefinition(
                name="network_probe",
                version="1.0.0",
                description="test",
                risk_level=RiskLevel.R0,
                input_model=EmptyInput,
                output_model=ToolResult,
                handler=handler,
                capability_requirements=("command.ss",),
            )
        )

        availability = registry.tool_availability("network_probe")

        self.assertFalse(availability["available"])
        self.assertEqual(availability["status"], CAPABILITY_UNAVAILABLE)
        with self.assertRaises(ToolCapabilityUnavailableError):
            registry.call("network_probe", {})
        self.assertFalse(called)

    def test_registry_without_probe_reports_unknown_but_remains_testable(
        self,
    ) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name="test_probe",
                version="1.0.0",
                description="test",
                risk_level=RiskLevel.R0,
                input_model=EmptyInput,
                output_model=ToolResult,
                handler=lambda _: ToolResult(observations=[{"ok": True}]),
                capability_requirements=("command.test",),
            )
        )

        availability = registry.tool_availability("test_probe")

        self.assertEqual(availability["status"], "UNKNOWN")
        self.assertTrue(availability["available"])
        self.assertEqual(registry.call("test_probe", {}).status, "ok")


if __name__ == "__main__":
    unittest.main()
