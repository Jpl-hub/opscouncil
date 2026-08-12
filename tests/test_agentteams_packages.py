from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from agentteams.scripts.build_packages import (
    MCP_SERVER_BY_AGENT,
    ROLE_BY_AGENT,
    build_packages,
    derive_token,
)
from agentteams.scripts.deploy_team import DeploymentError, deploy, render_team_manifest


class AgentTeamsPackageTest(unittest.TestCase):
    def test_packages_are_deterministic_and_role_scoped(self) -> None:
        secret = "fixture-master-secret"
        api_url = "http://opscouncil.internal:8000"
        with tempfile.TemporaryDirectory(dir="/tmp") as first_root, tempfile.TemporaryDirectory(
            dir="/tmp"
        ) as second_root:
            first = Path(first_root) / "dist"
            second = Path(second_root) / "dist"
            build_packages(
                api_url=api_url,
                model="qwen3.6-plus",
                callback_secret=secret,
                output_dir=first,
            )
            build_packages(
                api_url=api_url,
                model="qwen3.6-plus",
                callback_secret=secret,
                output_dir=second,
            )

            for agent_name, role in ROLE_BY_AGENT.items():
                first_zip = first / "packages" / f"{agent_name}.zip"
                second_zip = second / "packages" / f"{agent_name}.zip"
                self.assertEqual(
                    hashlib.sha256(first_zip.read_bytes()).hexdigest(),
                    hashlib.sha256(second_zip.read_bytes()).hexdigest(),
                )
                self.assertNotIn(secret.encode("utf-8"), first_zip.read_bytes())
                with ZipFile(first_zip) as archive:
                    names = set(archive.namelist())
                    self.assertIn("manifest.json", names)
                    self.assertIn("config/SOUL.md", names)
                    self.assertIn("config/AGENTS.md", names)
                    self.assertIn("config/callback-client.mjs", names)
                    runtime = json.loads(
                        archive.read("config/opscouncil-runtime.json")
                    )
                    package_manifest = json.loads(archive.read("manifest.json"))
                    self.assertEqual(package_manifest["type"], "worker")
                    self.assertEqual(package_manifest["version"], 1)
                    self.assertEqual(runtime["agent_name"], agent_name)
                    self.assertEqual(runtime["role"], role)
                    self.assertEqual(
                        runtime["token"],
                        derive_token(secret, f"agent:{agent_name}"),
                    )

                    if agent_name in MCP_SERVER_BY_AGENT:
                        config = json.loads(
                            archive.read("config/config/mcporter.json")
                        )
                        servers = config["mcpServers"]
                        self.assertEqual(list(servers), [MCP_SERVER_BY_AGENT[agent_name]])
                        server = servers[MCP_SERVER_BY_AGENT[agent_name]]
                        self.assertEqual(
                            server["url"],
                            f"{api_url}/mcp/agents/{agent_name}",
                        )
                        self.assertEqual(
                            server["headers"]["X-OpsCouncil-Agent-Token"],
                            runtime["token"],
                        )
                    else:
                        self.assertNotIn("config/config/mcporter.json", names)

    def test_team_manifest_uses_current_agentteams_membership_contract(self) -> None:
        rendered = render_team_manifest()
        self.assertIn("apiVersion: agentteams.io/v1beta1", rendered)
        self.assertIn("kind: Team", rendered)
        self.assertIn("peerMentions: false", rendered)
        self.assertIn("workerMembers:", rendered)
        self.assertEqual(rendered.count("role: team_leader"), 1)
        self.assertEqual(rendered.count("role: worker"), 4)
        for agent_name in ROLE_BY_AGENT:
            self.assertIn(f"name: {agent_name}", rendered)
        self.assertNotIn("__", rendered)
        self.assertNotIn("token", rendered.lower())

    @patch("agentteams.scripts.deploy_team._managed_resources")
    @patch("agentteams.scripts.deploy_team._assert_manager_running")
    def test_deploy_refuses_silent_incremental_package_update(
        self,
        assert_manager_running,
        managed_resources,
    ) -> None:
        del assert_manager_running
        managed_resources.return_value = (True, ["signal-correlator"])

        with self.assertRaisesRegex(DeploymentError, "--replace"):
            deploy(
                runtime="docker",
                api_url="http://opscouncil.internal:8000",
                model="qwen3.6-plus",
                callback_secret="fixture-master-secret",
            )


if __name__ == "__main__":
    unittest.main()
