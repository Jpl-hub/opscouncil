from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch

from backend.app.collaboration.agentteams import (
    AgentTeamsClient,
    AgentTeamsConnection,
)


class AgentTeamsClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = AgentTeamsConnection(
            matrix_url="http://matrix.test",
            username="dispatcher",
            password="secret",
            team_room_id="!team:matrix.test",
            leader_user_id="@incident-commander:matrix.test",
        )

    def test_connection_requires_team_room_and_leader_identity(self) -> None:
        self.assertTrue(self.connection.configured)
        self.assertFalse(
            AgentTeamsConnection(
                matrix_url="http://matrix.test",
                username="dispatcher",
                password="secret",
                team_room_id="!team:matrix.test",
                leader_user_id="",
            ).configured
        )

    @patch("backend.app.collaboration.agentteams.httpx.put")
    @patch("backend.app.collaboration.agentteams.httpx.post")
    def test_dispatch_mentions_bound_triage_agent_in_shared_team_room(self, post, put) -> None:
        login = Mock()
        login.raise_for_status.return_value = None
        login.json.return_value = {"access_token": "matrix-token"}
        post.return_value = login
        sent = Mock()
        sent.raise_for_status.return_value = None
        sent.json.return_value = {"event_id": "$event"}
        put.return_value = sent

        event_id = AgentTeamsClient(self.connection).dispatch_incident(
            {
                "id": 42,
                "context_version": 3,
                "incident": {
                    "id": 7,
                    "severity": "CRITICAL",
                    "title": "订单服务不可用",
                },
                "shared_context": {"initial_evidence_refs": ["tool-call:9"]},
                "work_items": [
                    {
                        "work_key": "triage",
                        "role": "signal_correlator",
                        "skill_id": "signal-fusion",
                        "status": "READY",
                        "input": {"incident_id": 7},
                    },
                    {
                        "work_key": "investigate",
                        "role": "rca_investigator",
                        "skill_id": "causal-investigation",
                        "status": "PENDING",
                        "input": {},
                    },
                ],
                "audit": {
                    "valid": True,
                    "event_count": 2,
                    "head_hash": "a" * 64,
                },
            }
        )

        self.assertEqual(event_id, "$event")
        url = put.call_args.args[0]
        self.assertIn("%21team%3Amatrix.test", url)
        message = put.call_args.kwargs["json"]
        self.assertTrue(message["body"].startswith("@signal-correlator:matrix.test "))
        self.assertEqual(
            message["m.mentions"],
            {"user_ids": ["@signal-correlator:matrix.test"]},
        )
        self.assertIn("Do not search for a separate event file", message["body"])
        envelope = json.loads(message["body"].splitlines()[-1])
        self.assertEqual(envelope["collaboration_id"], 42)
        self.assertTrue(envelope["audit"]["valid"])
        self.assertEqual(
            [item["work_key"] for item in envelope["ready_work_items"]],
            ["triage"],
        )
        self.assertEqual(envelope["output_contract"]["title"], "TriageOutput")
        self.assertEqual(envelope["context_refs"]["initial_evidence_refs"], ["tool-call:9"])
        self.assertEqual(message["org.opscouncil.incident"]["id"], 42)

    @patch("backend.app.collaboration.agentteams.httpx.put")
    @patch("backend.app.collaboration.agentteams.httpx.post")
    def test_dispatch_mentions_role_bound_agent_for_single_ready_item(self, post, put) -> None:
        login = Mock()
        login.raise_for_status.return_value = None
        login.json.return_value = {"access_token": "matrix-token"}
        post.return_value = login
        sent = Mock()
        sent.raise_for_status.return_value = None
        sent.json.return_value = {"event_id": "$event"}
        put.return_value = sent

        AgentTeamsClient(self.connection).dispatch_incident(
            {
                "id": 42,
                "incident": {"id": 7, "severity": "WARN", "title": "日志空间事件"},
                "work_items": [
                    {
                        "work_key": "plan",
                        "role": "remediation_planner",
                        "skill_id": "bounded-remediation",
                        "status": "READY",
                        "input": {"context_version": 4},
                    }
                ],
                "audit": {"valid": True},
            }
        )

        message = put.call_args.kwargs["json"]
        self.assertEqual(
            message["m.mentions"],
            {"user_ids": ["@remediation-planner:matrix.test"]},
        )
        self.assertIn("Do not delegate the item", message["body"])

    @patch("backend.app.collaboration.agentteams.httpx.put")
    @patch("backend.app.collaboration.agentteams.httpx.post")
    def test_dispatch_does_not_copy_large_agent_outputs_into_matrix(self, post, put) -> None:
        login = Mock()
        login.raise_for_status.return_value = None
        login.json.return_value = {"access_token": "matrix-token"}
        post.return_value = login
        sent = Mock()
        sent.raise_for_status.return_value = None
        sent.json.return_value = {"event_id": "$event"}
        put.return_value = sent

        AgentTeamsClient(self.connection).dispatch_incident(
            {
                "id": 42,
                "context_version": 9,
                "incident": {"id": 7, "severity": "WARN", "title": "日志空间事件"},
                "shared_context": {
                    "initial_evidence_refs": ["tool-call:9"],
                    "outputs": {"investigate": {"raw": "x" * 100_000}},
                    "action_candidates": [
                        {"proposal_id": 3, "tool_name": "safe_log_rotate", "risk_level": "R2"}
                    ],
                },
                "work_items": [
                    {
                        "work_key": "plan",
                        "role": "remediation_planner",
                        "skill_id": "bounded-remediation",
                        "status": "READY",
                        "input": {"context_version": 9, "shared_context": {"raw": "x" * 100_000}},
                    }
                ],
                "audit": {"valid": True, "event_count": 8, "head_hash": "b" * 64},
            }
        )

        message = put.call_args.kwargs["json"]
        self.assertLess(len(json.dumps(message)), 10_000)
        self.assertNotIn("x" * 1_000, message["body"])
        self.assertEqual(
            message["org.opscouncil.incident"]["context_refs"]["accepted_output_keys"],
            ["investigate"],
        )

    @patch("backend.app.collaboration.agentteams.httpx.put")
    @patch("backend.app.collaboration.agentteams.httpx.post")
    def test_dispatch_resumes_the_identity_holding_a_running_lease(self, post, put) -> None:
        login = Mock()
        login.raise_for_status.return_value = None
        login.json.return_value = {"access_token": "matrix-token"}
        post.return_value = login
        sent = Mock()
        sent.raise_for_status.return_value = None
        sent.json.return_value = {"event_id": "$event"}
        put.return_value = sent

        AgentTeamsClient(self.connection).dispatch_incident(
            {
                "id": 42,
                "incident": {"id": 7, "severity": "WARN", "title": "日志空间事件"},
                "work_items": [
                    {
                        "work_key": "plan",
                        "role": "remediation_planner",
                        "skill_id": "bounded-remediation",
                        "status": "RUNNING",
                        "assigned_agent": "remediation-planner",
                        "input": {"context_version": 4},
                    }
                ],
                "audit": {"valid": True},
            }
        )

        message = put.call_args.kwargs["json"]
        self.assertEqual(
            message["m.mentions"],
            {"user_ids": ["@remediation-planner:matrix.test"]},
        )
        self.assertIn("Do not claim it again", message["body"])
        self.assertEqual(
            message["org.opscouncil.incident"]["output_contract"]["title"],
            "RemediationOutput",
        )

    @patch("backend.app.collaboration.agentteams.httpx.put")
    @patch("backend.app.collaboration.agentteams.httpx.post")
    def test_dispatch_converts_float_schema_bounds_for_matrix_canonical_json(self, post, put) -> None:
        login = Mock()
        login.raise_for_status.return_value = None
        login.json.return_value = {"access_token": "matrix-token"}
        post.return_value = login
        sent = Mock()
        sent.raise_for_status.return_value = None
        sent.json.return_value = {"event_id": "$event"}
        put.return_value = sent

        AgentTeamsClient(self.connection).dispatch_incident(
            {
                "id": 42,
                "incident": {"id": 7, "severity": "WARN", "title": "日志空间事件"},
                "work_items": [
                    {
                        "work_key": "investigate",
                        "role": "rca_investigator",
                        "skill_id": "causal-investigation",
                        "status": "READY",
                        "input": {"context_version": 3},
                    }
                ],
                "audit": {"valid": True},
            }
        )

        schema = put.call_args.kwargs["json"]["org.opscouncil.incident"]["output_contract"]
        confidence = schema["properties"]["confidence"]
        self.assertEqual(confidence["minimum"], "0")
        self.assertEqual(confidence["maximum"], "1")


if __name__ == "__main__":
    unittest.main()
