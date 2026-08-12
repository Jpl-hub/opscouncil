from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentteams.scripts.build_packages import derive_token as derive_package_token
from backend.app.collaboration.auth import (
    CollaborationIdentityConfigurationError,
    callback_token_matches,
    derive_callback_token,
)
from backend.app.mcp.protocol import MCP_PROTOCOL_VERSION, build_mcp_router
from backend.app.perception.tools import build_perception_registry


class CollaborationIdentityTest(unittest.TestCase):
    def test_build_and_server_use_the_same_subject_derivation(self) -> None:
        secret = "fixture-secret"
        subject = "agent:rca-investigator"
        self.assertEqual(
            derive_package_token(secret, subject),
            derive_callback_token(subject, secret=secret),
        )

    def test_missing_secret_is_a_configuration_error(self) -> None:
        with patch(
            "backend.app.collaboration.auth.settings",
            SimpleNamespace(agentteams_callback_secret=""),
        ):
            with self.assertRaises(CollaborationIdentityConfigurationError):
                derive_callback_token("agent:rca-investigator")

    def test_role_mcp_rejects_missing_and_wrong_identity(self) -> None:
        app = FastAPI()
        registry = build_perception_registry().scoped({"system_snapshot"})
        app.include_router(
            build_mcp_router(
                registry,
                path="/mcp/agents/rca-investigator",
                server_name="opscouncil-rca-investigator",
                identity_subject="agent:rca-investigator",
            )
        )
        client = TestClient(app)
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        headers = {"MCP-Protocol-Version": MCP_PROTOCOL_VERSION}
        secret = "fixture-secret"

        with patch(
            "backend.app.collaboration.auth.settings",
            SimpleNamespace(agentteams_callback_secret=secret),
        ):
            missing = client.post(
                "/mcp/agents/rca-investigator",
                json=message,
                headers=headers,
            )
            wrong = client.post(
                "/mcp/agents/rca-investigator",
                json=message,
                headers={
                    **headers,
                    "X-OpsCouncil-Agent-Token": derive_callback_token(
                        "agent:signal-correlator",
                        secret=secret,
                    ),
                },
            )
            accepted = client.post(
                "/mcp/agents/rca-investigator",
                json=message,
                headers={
                    **headers,
                    "X-OpsCouncil-Agent-Token": derive_callback_token(
                        "agent:rca-investigator",
                        secret=secret,
                    ),
                },
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(
            [item["name"] for item in accepted.json()["result"]["tools"]],
            ["system_snapshot"],
        )

    def test_token_comparison_rejects_empty_value(self) -> None:
        with patch(
            "backend.app.collaboration.auth.settings",
            SimpleNamespace(agentteams_callback_secret="fixture-secret"),
        ):
            self.assertFalse(callback_token_matches("agent:signal-correlator", None))


if __name__ == "__main__":
    unittest.main()
