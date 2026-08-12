from __future__ import annotations

import unittest

from backend.app.perception.topology_tools import (
    ServiceDependencySnapshotInput,
    assemble_service_dependency_snapshot,
    build_topology_tool_definitions,
)
from backend.app.perception.service_impact import (
    assess_service_change_impact,
    parse_systemctl_show,
    verify_service_change_impact,
    verify_service_change_impact_precondition,
)
from backend.app.schemas.enums import RiskLevel


LISTENERS = [
    'tcp LISTEN 0 2048 127.0.0.1:8000 0.0.0.0:* users:(("python",pid=100,fd=4)) uid:1000 ino:1004 cgroup:/system.slice/api.service <->',
    'tcp LISTEN 0 244 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=200,fd=5)) uid:109 ino:2005 cgroup:/system.slice/postgresql.service <->',
]

CONNECTIONS = [
    'tcp ESTAB 0 0 127.0.0.1:41000 127.0.0.1:5432 users:(("python",pid=100,fd=8)) uid:1000 ino:1008 cgroup:/system.slice/api.service <->',
    'tcp ESTAB 0 0 127.0.0.1:5432 127.0.0.1:41000 users:(("postgres",pid=200,fd=8)) uid:109 ino:2008 cgroup:/system.slice/postgresql.service <->',
    'tcp ESTAB 0 0 10.0.0.8:41001 8.8.8.8:443 users:(("python",pid=100,fd=9)) uid:1000 ino:1009 cgroup:/system.slice/api.service <->',
]


class ServiceDependencySnapshotTest(unittest.TestCase):
    def test_builds_only_observed_relationships_and_suppresses_server_reverse_edge(self) -> None:
        report = assemble_service_dependency_snapshot(
            LISTENERS,
            CONNECTIONS,
            focus_ports={8000},
        )

        self.assertEqual(report["focus_process_ids"], [100])
        self.assertEqual(report["connection_relation_count"], 2)
        self.assertEqual(report["external_endpoint_count"], 1)
        edge_keys = {
            (edge["source"], edge["target"], edge["relation"])
            for edge in report["edges"]
        }
        self.assertIn(
            ("process:100", "listener:tcp:127.0.0.1:5432", "CONNECTS_TO"),
            edge_keys,
        )
        self.assertIn(
            ("process:100", "endpoint:tcp:8.8.8.8:443", "CONNECTS_TO"),
            edge_keys,
        )
        self.assertNotIn(
            ("process:200", "endpoint:tcp:127.0.0.1:41000", "CONNECTS_TO"),
            edge_keys,
        )
        self.assertTrue(all("evidence_ref" in edge for edge in report["edges"]))
        edge_by_key = {
            (edge["source"], edge["target"], edge["relation"]): edge
            for edge in report["edges"]
        }
        self.assertEqual(
            edge_by_key[
                ("service:api.service", "process:100", "RUNS_PROCESS")
            ]["observation_count"],
            1,
        )
        self.assertEqual(
            edge_by_key[
                ("process:200", "listener:tcp:127.0.0.1:5432", "LISTENS_ON")
            ]["observation_count"],
            1,
        )

    def test_unresolved_focus_is_reported_as_gap_instead_of_broadening_scope(self) -> None:
        report = assemble_service_dependency_snapshot(
            LISTENERS,
            CONNECTIONS,
            focus_ports={9999},
        )

        self.assertEqual(report["focus_process_ids"], [])
        self.assertEqual(report["nodes"], [])
        self.assertEqual(report["edges"], [])
        self.assertIn(
            "FOCUS_PROCESS_UNRESOLVED",
            {gap["code"] for gap in report["evidence_gaps"]},
        )

    def test_tool_contract_is_read_only_and_bounded(self) -> None:
        definition = build_topology_tool_definitions()[0]
        self.assertEqual(definition.name, "service_dependency_snapshot")
        self.assertEqual(definition.version, "1.1.0")
        self.assertEqual(definition.risk_level, RiskLevel.R0)
        self.assertEqual(
            definition.capability_requirements,
            ("command.ss", "command.systemctl", "kernel.procfs"),
        )
        with self.assertRaises(ValueError):
            ServiceDependencySnapshotInput(focus_ports=list(range(1, 10)))
        with self.assertRaises(ValueError):
            ServiceDependencySnapshotInput(focus_units=["not-a-complete-unit"])

    def test_focus_unit_selects_its_observed_process_and_connections(self) -> None:
        report = assemble_service_dependency_snapshot(
            LISTENERS,
            CONNECTIONS,
            focus_units={"api.service"},
        )

        self.assertEqual(report["focus_unit_process_ids"], [100])
        self.assertIn(
            "service:api.service",
            {node["id"] for node in report["nodes"]},
        )
        self.assertEqual(report["connection_relation_count"], 2)

    def test_focus_unit_does_not_expand_to_every_listener_process(self) -> None:
        report = assemble_service_dependency_snapshot(
            LISTENERS,
            CONNECTIONS,
            focus_units={"missing.service"},
        )

        self.assertEqual(report["focus_process_ids"], [])
        self.assertEqual(report["focus_unit_process_ids"], [])
        self.assertEqual(report["nodes"], [])
        self.assertEqual(report["edges"], [])

    def test_unrelated_ownerless_socket_does_not_invalidate_unit_scope(self) -> None:
        report = assemble_service_dependency_snapshot(
            [
                *LISTENERS,
                "tcp LISTEN 0 128 127.0.0.1:9999 0.0.0.0:* ino:9999",
            ],
            CONNECTIONS,
            focus_units={"api.service"},
        )

        self.assertEqual(report["unattributed_socket_count"], 1)
        self.assertEqual(report["scoped_unattributed_socket_count"], 0)
        self.assertNotIn(
            "SOCKET_OWNER_UNAVAILABLE",
            {gap["code"] for gap in report["evidence_gaps"]},
        )

    def test_ownerless_focus_port_remains_a_blocking_gap(self) -> None:
        report = assemble_service_dependency_snapshot(
            ["tcp LISTEN 0 128 127.0.0.1:9999 0.0.0.0:* ino:9999"],
            [],
            focus_ports={9999},
        )

        self.assertEqual(report["scoped_unattributed_socket_count"], 1)
        self.assertIn(
            "SOCKET_OWNER_UNAVAILABLE",
            {gap["code"] for gap in report["evidence_gaps"]},
        )

    def test_restart_impact_uses_propagation_edges_not_ordering_edges(self) -> None:
        nodes = [
            {"id": "service:api.service", "kind": "service", "unit": "api.service"},
            {"id": "service:worker.service", "kind": "service", "unit": "worker.service"},
            {"id": "service:watcher.service", "kind": "service", "unit": "watcher.service"},
            {"id": "service:ordered.service", "kind": "service", "unit": "ordered.service"},
            {"id": "service:client.service", "kind": "service", "unit": "client.service"},
            {"id": "process:10", "kind": "process", "label": "api", "pid": 10},
            {"id": "process:20", "kind": "process", "label": "client", "pid": 20},
            {"id": "listener:tcp:127.0.0.1:8000", "kind": "listener"},
        ]
        edges = [
            {
                "source": "service:worker.service",
                "target": "service:api.service",
                "relation": "PART_OF",
            },
            {
                "source": "service:watcher.service",
                "target": "service:worker.service",
                "relation": "BINDS_TO",
            },
            {
                "source": "service:ordered.service",
                "target": "service:api.service",
                "relation": "AFTER",
            },
            {
                "source": "service:api.service",
                "target": "process:10",
                "relation": "RUNS_PROCESS",
            },
            {
                "source": "process:10",
                "target": "listener:tcp:127.0.0.1:8000",
                "relation": "LISTENS_ON",
            },
            {
                "source": "service:client.service",
                "target": "process:20",
                "relation": "RUNS_PROCESS",
            },
            {
                "source": "process:20",
                "target": "listener:tcp:127.0.0.1:8000",
                "relation": "CONNECTS_TO",
            },
        ]

        impact = assess_service_change_impact(
            nodes,
            edges,
            target_units=["api.service"],
            change_action="restart",
            evidence_gaps=[],
        )

        by_unit = {item["unit"]: item for item in impact["predicted_units"]}
        self.assertEqual(impact["status"], "ASSESSED")
        self.assertEqual(by_unit["worker.service"]["certainty"], "CERTAIN")
        self.assertEqual(by_unit["watcher.service"]["certainty"], "LIKELY")
        self.assertEqual(
            by_unit["watcher.service"]["path"],
            [
                "service:api.service",
                "service:worker.service",
                "service:watcher.service",
            ],
        )
        self.assertNotIn("ordered.service", by_unit)
        self.assertEqual(impact["possible_client_count"], 1)
        self.assertEqual(
            impact["predicted_clients"][0]["service_unit"],
            "client.service",
        )

    def test_systemctl_show_parser_preserves_dependency_values(self) -> None:
        parsed = parse_systemctl_show(
            "Id=api.service\nLoadState=loaded\nPartOf=platform.target audit.service\n"
        )

        self.assertEqual(parsed["Id"], "api.service")
        self.assertEqual(parsed["PartOf"], "platform.target audit.service")

    def test_post_action_impact_verification_compares_scope_state_and_invocation(self) -> None:
        frozen = {
            "predicted_units": [
                {
                    "unit": "api.service",
                    "role": "TARGET",
                    "registered": True,
                    "expected_active_state": "active",
                    "active_state": "failed",
                    "invocation_id": "target-before",
                },
                {
                    "unit": "worker.service",
                    "role": "PROPAGATED",
                    "mechanism": "PART_OF",
                    "registered": True,
                    "expected_active_state": "active",
                    "active_state": "active",
                    "invocation_id": "worker-before",
                },
            ]
        }
        post = {
            "change_impact": {
                "predicted_units": [
                    {
                        "unit": "api.service",
                        "role": "TARGET",
                        "active_state": "active",
                        "invocation_id": "target-after",
                    },
                    {
                        "unit": "worker.service",
                        "role": "PROPAGATED",
                        "mechanism": "PART_OF",
                        "active_state": "active",
                        "invocation_id": "worker-after",
                    },
                ],
                "evidence_gaps": [],
            }
        }

        verification = verify_service_change_impact(frozen, post)

        self.assertTrue(verification["valid"])
        self.assertEqual(verification["outcome"], "CONFIRMED")
        self.assertEqual(
            verification["details"]["confirmed_propagation_count"],
            1,
        )

    def test_pre_action_impact_verification_accepts_unchanged_runtime_scope(self) -> None:
        frozen = {
            "predicted_units": [
                {
                    "unit": "api.service",
                    "role": "TARGET",
                    "certainty": "DIRECT",
                    "mechanism": "DIRECT_TARGET",
                    "path": ["service:api.service"],
                    "active_state": "failed",
                    "invocation_id": "before",
                }
            ],
            "predicted_clients": [],
        }
        current = {
            "change_impact": {
                "predicted_units": [
                    {
                        "unit": "api.service",
                        "role": "TARGET",
                        "certainty": "DIRECT",
                        "mechanism": "DIRECT_TARGET",
                        "path": ["service:api.service"],
                        "active_state": "failed",
                        "invocation_id": "before",
                    }
                ],
                "predicted_clients": [],
                "evidence_gaps": [],
            }
        }

        verification = verify_service_change_impact_precondition(frozen, current)

        self.assertTrue(verification["valid"])
        self.assertEqual(verification["outcome"], "CONFIRMED")
        self.assertEqual(verification["details"]["prediction_error_count"], 0)

    def test_pre_action_impact_verification_rejects_approval_time_drift(self) -> None:
        frozen = {
            "predicted_units": [
                {
                    "unit": "api.service",
                    "role": "TARGET",
                    "certainty": "DIRECT",
                    "mechanism": "DIRECT_TARGET",
                    "path": ["service:api.service"],
                    "active_state": "failed",
                    "invocation_id": "before",
                }
            ],
            "predicted_clients": [],
        }
        current = {
            "change_impact": {
                "predicted_units": [
                    {
                        "unit": "api.service",
                        "role": "TARGET",
                        "certainty": "DIRECT",
                        "mechanism": "DIRECT_TARGET",
                        "path": ["service:api.service"],
                        "active_state": "active",
                        "invocation_id": "external-restart",
                    },
                    {
                        "unit": "new-worker.service",
                        "role": "PROPAGATED",
                        "certainty": "CERTAIN",
                        "mechanism": "PART_OF",
                        "path": [
                            "service:api.service",
                            "service:new-worker.service",
                        ],
                    },
                ],
                "predicted_clients": [],
                "evidence_gaps": [],
            }
        }

        verification = verify_service_change_impact_precondition(frozen, current)

        self.assertFalse(verification["valid"])
        self.assertEqual(verification["outcome"], "DIVERGED")
        self.assertEqual(
            verification["details"]["unexpected_units"],
            ["new-worker.service"],
        )
        self.assertEqual(len(verification["details"]["runtime_mismatches"]), 1)

    def test_post_action_impact_verification_rejects_scope_drift(self) -> None:
        frozen = {
            "predicted_units": [
                {
                    "unit": "api.service",
                    "role": "TARGET",
                    "registered": True,
                    "expected_active_state": "active",
                }
            ]
        }
        post = {
            "change_impact": {
                "predicted_units": [
                    {
                        "unit": "api.service",
                        "role": "TARGET",
                        "active_state": "active",
                    },
                    {
                        "unit": "unexpected.service",
                        "role": "PROPAGATED",
                        "active_state": "active",
                    },
                ],
                "evidence_gaps": [],
            }
        }

        verification = verify_service_change_impact(frozen, post)

        self.assertFalse(verification["valid"])
        self.assertEqual(verification["outcome"], "DIVERGED")
        self.assertEqual(
            verification["details"]["unexpected_units"],
            ["unexpected.service"],
        )


if __name__ == "__main__":
    unittest.main()
