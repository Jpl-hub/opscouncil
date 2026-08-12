from __future__ import annotations

import json
from pathlib import Path
import shutil
import socket
import unittest

from backend.app.lab.oracles import evaluate_probe
from backend.app.lab.service import LabService
from backend.app.perception.tools import build_perception_registry


class LabOracleTest(unittest.TestCase):
    def test_deleted_open_file_oracle_requires_real_inode_and_owner(self) -> None:
        state = {
            "metadata": {
                "target_path": "/tmp/rotated-worker.log",
                "pid": 123,
                "inode": 456,
                "retained_bytes": 8192,
                "path_removed": True,
            }
        }
        accepted = evaluate_probe(
            "deleted-open-file",
            state,
            {
                "observations": [
                    {
                        "path": "/tmp/rotated-worker.log",
                        "pid": 123,
                        "inode": 456,
                        "size_bytes": 8192,
                        "open_handle_count": 1,
                    }
                ]
            },
        )

        self.assertTrue(accepted.passed, accepted.failures)
        self.assertEqual(accepted.evidence_coverage, 1.0)

    def test_failed_service_oracle_enforces_normalized_tool_contract(self) -> None:
        state = {"status": "ready", "metadata": {"unit": "fixture.service"}}
        accepted = evaluate_probe(
            "failed-service",
            state,
            {
                "observations": [
                    {
                        "unit": "fixture.service",
                        "load_state": "loaded",
                        "active_state": "failed",
                        "result": "exit-code",
                    }
                ]
            },
        )
        legacy_shape = evaluate_probe(
            "failed-service",
            state,
            {
                "observations": [
                    {
                        "unit": "fixture.service",
                        "LoadState": "loaded",
                        "ActiveState": "failed",
                        "Result": "exit-code",
                    }
                ]
            },
        )

        self.assertTrue(accepted.passed, accepted.failures)
        self.assertEqual(accepted.evidence_coverage, 1.0)
        self.assertFalse(legacy_shape.passed)

    def test_service_change_impact_oracle_rejects_ordering_false_positive(self) -> None:
        state = {
            "metadata": {
                "target_unit": "api.service",
                "expected_propagated_units": ["worker.service"],
                "ordering_only_units": ["reporter.service"],
            }
        }
        observation = {
            "edges": [
                {
                    "source": "service:worker.service",
                    "target": "service:api.service",
                    "relation": "PART_OF",
                },
                {
                    "source": "service:reporter.service",
                    "target": "service:api.service",
                    "relation": "AFTER",
                },
            ],
            "change_impact": {
                "status": "ASSESSED",
                "coverage": "FULL",
                "predicted_units": [
                    {
                        "unit": "api.service",
                        "role": "TARGET",
                    },
                    {
                        "unit": "worker.service",
                        "role": "PROPAGATED",
                    },
                ],
                "mechanism_counts": {"PART_OF": 1},
            },
        }

        accepted = evaluate_probe(
            "service-change-impact",
            state,
            {"observations": [observation]},
        )
        rejected = evaluate_probe(
            "service-change-impact",
            state,
            {
                "observations": [
                    {
                        **observation,
                        "change_impact": {
                            **observation["change_impact"],
                            "predicted_units": [
                                *observation["change_impact"]["predicted_units"],
                                {
                                    "unit": "reporter.service",
                                    "role": "PROPAGATED",
                                },
                            ],
                        },
                    }
                ]
            },
        )

        self.assertTrue(accepted.passed, accepted.failures)
        self.assertEqual(accepted.facts["precision"], 1.0)
        self.assertEqual(accepted.facts["recall"], 1.0)
        self.assertFalse(rejected.passed)
        self.assertEqual(rejected.facts["unsupported_impact_count"], 1)

    def test_service_dependency_oracle_accepts_observed_relationship_edges(self) -> None:
        config_hash = "a" * 64
        result = {
            "probe_results": {
                "service_health_probe": {
                    "observations": [
                        {
                            "status_code": 503,
                            "available": False,
                            "body_summary": {
                                "dependency": "inventory-db",
                                "reason": "dependency_timeout",
                            },
                        }
                    ]
                },
                "service_dependency_snapshot": {
                    "observations": [
                        {
                            "nodes": [
                                {
                                    "id": "process:123",
                                    "kind": "process",
                                    "label": "checkout-api",
                                    "pid": 123,
                                },
                                {
                                    "id": "process:124",
                                    "kind": "process",
                                    "label": "inventory-db",
                                    "pid": 124,
                                },
                                {
                                    "id": "listener:tcp:127.0.0.1:18090",
                                    "kind": "listener",
                                    "address": "127.0.0.1:18090",
                                    "port": 18090,
                                    "protocol": "tcp",
                                },
                                {
                                    "id": "listener:tcp:127.0.0.1:18091",
                                    "kind": "listener",
                                    "address": "127.0.0.1:18091",
                                    "port": 18091,
                                    "protocol": "tcp",
                                },
                            ],
                            "edges": [
                                {
                                    "source": "process:123",
                                    "target": "listener:tcp:127.0.0.1:18090",
                                    "relation": "LISTENS_ON",
                                    "evidence_ref": "ss -H -lntupe",
                                },
                                {
                                    "source": "process:124",
                                    "target": "listener:tcp:127.0.0.1:18091",
                                    "relation": "LISTENS_ON",
                                    "evidence_ref": "ss -H -lntupe",
                                },
                                {
                                    "source": "process:123",
                                    "target": "listener:tcp:127.0.0.1:18091",
                                    "relation": "CONNECTS_TO",
                                    "evidence_ref": "ss -H -ntupe",
                                },
                            ],
                        }
                    ]
                },
                "application_log_query": {
                    "observations": [
                        {
                            "lines": [
                                json.dumps(
                                    {
                                        "event": "request_failed",
                                        "dependency": "inventory-db",
                                        "reason": "dependency_timeout",
                                        "dependency_timeout_ms": 120,
                                        "server.address": "127.0.0.1",
                                        "server.port": 18091,
                                        "network.transport": "tcp",
                                    }
                                )
                            ]
                        }
                    ]
                },
                "config_integrity_scan": {
                    "observations": [
                        {"path": "/tmp/service.conf", "sha256": config_hash}
                    ]
                },
                "system_snapshot": {"observations": [{"pressure": {}}]},
            }
        }
        outcome = evaluate_probe(
            "service-dependency-degradation",
            {
                "metadata": {
                    "frontend_port": 18090,
                    "dependency_port": 18091,
                    "pid": 123,
                    "dependency_pid": 124,
                    "dependency_delay_ms": 450,
                    "dependency_timeout_ms": 120,
                    "decoy_config_path": "/tmp/service.conf",
                    "decoy_baseline_sha256": config_hash,
                    "decoy_mtime_changed": True,
                    "decoy_hash_unchanged": True,
                }
            },
            result,
        )

        self.assertTrue(outcome.passed, outcome.failures)
        self.assertEqual(outcome.evidence_coverage, 1.0)

    def test_io_oracle_accepts_real_procfs_counters_when_psi_is_unavailable(self) -> None:
        root = Path("/tmp/opscouncil-lab/io-oracle-fallback")
        root.mkdir(parents=True, exist_ok=True)
        target = root / "io-pressure.bin"
        target.write_bytes(b"K" * 4096)
        try:
            outcome = evaluate_probe(
                "io-pressure",
                {"metadata": {"target_path": str(target), "pid": 123}},
                {
                    "observations": [
                        {
                            "pressure": {},
                            "io_activity": {
                                "iowait_ticks": 1,
                                "device_count": 1,
                                "read_ios": 2,
                                "write_ios": 3,
                                "io_time_ms": 4,
                            },
                        }
                    ]
                },
            )
        finally:
            shutil.rmtree(root, ignore_errors=True)

        self.assertTrue(outcome.passed, outcome.failures)
        self.assertEqual(outcome.facts["io_signal_source"], "procfs_counters")

    def test_real_fixture_probes_match_declared_oracles(self) -> None:
        root = Path("/tmp/opscouncil-lab/oracle-test")
        shutil.rmtree(root, ignore_errors=True)
        service = LabService(
            root,
            network_port=_free_tcp_port(),
            service_port=_free_adjacent_tcp_ports(),
        )
        registry = build_perception_registry()
        scenario_ids = (
            "disk-large-log",
            "inode-growth",
            "zombie-process",
            "file-descriptor-growth",
            "cpu-memory-pressure",
            "io-pressure",
            "network-local-listener",
            "config-drift-sample",
            "config-mode-recovery",
            "service-dependency-degradation",
        )
        try:
            for scenario_id in scenario_ids:
                with self.subTest(scenario_id=scenario_id):
                    state = service.activate(scenario_id, size_mb=12)
                    self.assertEqual(state["status"], "ready")
                    probe_results = {
                        probe["tool_name"]: registry.call(
                            probe["tool_name"],
                            probe["arguments"],
                        ).model_dump(mode="json")
                        for probe in state["probes"]
                    }
                    result = (
                        next(iter(probe_results.values()))
                        if len(probe_results) == 1
                        else {"probe_results": probe_results}
                    )

                    oracle = evaluate_probe(scenario_id, state, result)

                    self.assertTrue(oracle.passed, oracle.failures)
                    self.assertEqual(oracle.evidence_coverage, 1.0)
                    self.assertEqual(service.reset(scenario_id)["status"], "idle")
        finally:
            for scenario_id in scenario_ids:
                try:
                    service.reset(scenario_id)
                except Exception:
                    pass
            shutil.rmtree(root, ignore_errors=True)


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _free_adjacent_tcp_ports() -> int:
    for _ in range(100):
        first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            first.bind(("127.0.0.1", 0))
            port = int(first.getsockname()[1])
            if port >= 65535:
                continue
            second.bind(("127.0.0.1", port + 1))
            return port
        except OSError:
            continue
        finally:
            first.close()
            second.close()
    raise RuntimeError("unable to reserve adjacent loopback ports")


if __name__ == "__main__":
    unittest.main()
