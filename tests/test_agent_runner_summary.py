from __future__ import annotations

import unittest

from backend.app.agent.runner import AgentRunner, _collect_large_file_observations
from backend.app.models.entities import Task
from backend.app.schemas.enums import TaskStatus


class AgentRunnerSummaryTest(unittest.TestCase):
    def test_service_summary_reads_canonical_snake_case_status_fields(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="log_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "service_status",
                "result": {
                    "status": "ok",
                    "observations": [
                        {
                            "unit": "demo.service",
                            "load_state": "loaded",
                            "active_state": "failed",
                            "sub_state": "failed",
                            "result": "exit-code",
                            "main_pid": 0,
                        }
                    ],
                },
            }
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("demo.service 当前为 failed/failed", summary)
        self.assertNotIn("未知/未知", summary)

    def test_inconclusive_service_summary_separates_fact_from_unproven_cause(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="log_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "service_status",
                "result": {
                    "status": "ok",
                    "observations": [
                        {
                            "unit": "demo.service",
                            "active_state": "failed",
                            "sub_state": "failed",
                        }
                    ],
                },
            }
        ]

        summary = runner._summarize(
            task,
            observations,
            proposal_context=None,
            investigation_status="INCONCLUSIVE",
            investigation_stop_reason="ITERATION_BUDGET_EXHAUSTED",
        )

        self.assertIn("demo.service 当前为 failed/failed", summary)
        self.assertIn("现有证据尚不足以证明根因", summary)
        self.assertIn("单元专属日志", summary)
        self.assertNotIn("预算", summary)

    def test_service_change_summary_surfaces_propagation_and_excludes_ordering_only_units(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="log_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "service_dependency_snapshot",
                "result": {
                    "status": "partial",
                    "observations": [
                        {
                            "edges": [
                                {
                                    "source": "service:demo-root.service",
                                    "target": "service:demo-part.service",
                                    "relation": "PART_OF",
                                },
                                {
                                    "source": "service:demo-ordered.service",
                                    "target": "service:demo-root.service",
                                    "relation": "AFTER",
                                },
                            ],
                            "change_impact": {
                                "action": "restart",
                                "target_units": ["demo-root.service"],
                                "coverage": "PARTIAL",
                                "predicted_units": [
                                    {
                                        "node_id": "service:demo-root.service",
                                        "unit": "demo-root.service",
                                        "role": "TARGET",
                                        "mechanism": "DIRECT_TARGET",
                                    },
                                    {
                                        "node_id": "service:demo-part.service",
                                        "unit": "demo-part.service",
                                        "role": "PROPAGATED",
                                        "mechanism": "PART_OF",
                                    },
                                ],
                                "possible_client_count": 2,
                                "evidence_gaps": [{"code": "SOCKET_OWNER_UNAVAILABLE"}],
                            },
                        }
                    ],
                },
            }
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("影响预演", summary)
        self.assertIn("demo-root.service", summary)
        self.assertIn("demo-part.service", summary)
        self.assertIn("仅具启动顺序关系", summary)
        self.assertIn("当前连接方 2 个", summary)
        self.assertIn("不能据此自动执行", summary)
        self.assertNotIn("demo-ordered.service 将", summary)

        proposal_summary = runner._summarize(
            task,
            observations,
            proposal_context={
                "action": "service_restart",
                "unit": "demo-root.service",
                "active_state": "active",
            },
        )

        self.assertIn("demo-part.service", proposal_summary)
        self.assertIn("等待人工审批", proposal_summary)
        self.assertIn("重新采集运行关系", proposal_summary)
        self.assertIn("不自动重试", proposal_summary)

    def test_service_timeout_summary_does_not_claim_equal_values_exceed_boundary(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="service_degradation_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "service_health_probe",
                "result": {
                    "status": "partial",
                    "observations": [
                        {
                            "status_code": 503,
                            "latency_ms": 120,
                            "body_summary": {
                                "service": "checkout-api",
                                "dependency": "inventory-db",
                            },
                        }
                    ],
                },
            },
            {
                "tool_name": "application_log_query",
                "result": {
                    "status": "ok",
                    "observations": [
                        {
                            "records": [
                                {
                                    "event": "request_failed",
                                    "reason": "dependency_timeout",
                                    "dependency": "inventory-db",
                                    "observed_latency_ms": 120,
                                    "dependency_timeout_ms": 120,
                                }
                            ]
                        }
                    ],
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("调用在 120ms 超时边界被中止", summary)
        self.assertNotIn("120ms，超过 120ms", summary)

    def test_config_summary_distinguishes_metadata_change_from_material_drift(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="config_integrity_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "config_baseline_check",
                "result": {
                    "status": "ok",
                    "summary_fields": {
                        "baseline_available": True,
                        "scope": "LIVE",
                        "status": "drifted",
                    },
                    "observations": [
                        {
                            "path": "/etc/hosts",
                            "exists": True,
                            "mode": "0o644",
                            "uid": 0,
                            "gid": 0,
                            "sha256": "a" * 64,
                            "change_types": ["metadata_changed"],
                        }
                    ],
                },
            }
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("仅出现时间戳或解析路径变化", summary)
        self.assertIn("内容哈希、权限和属主仍与基线一致", summary)
        self.assertIn("当前不建议执行恢复", summary)

    def test_config_summary_does_not_call_current_sample_a_baseline(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="config_integrity_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "config_baseline_check",
                "result": {
                    "status": "ok",
                    "summary_fields": {
                        "baseline_available": False,
                        "scope": "LIVE",
                        "status": "unavailable",
                    },
                    "observations": [
                        {
                            "path": "/etc/hosts",
                            "exists": True,
                            "mode": "0o644",
                            "sha256": "a" * 64,
                            "change_types": [],
                        }
                    ],
                },
            }
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("没有覆盖这些路径的确认基线", summary)
        self.assertIn("不能判断漂移", summary)
        self.assertNotIn("生成 1 个配置文件", summary)

    def test_general_health_summary_reports_verified_dimensions_as_facts(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="general_system_health", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "system_snapshot",
                "result": {
                    "status": "ok",
                    "observations": [
                        {"loadavg": [0.75, 0.5, 0.25], "memory": {"used_percent": 42.3}}
                    ],
                },
            },
            {
                "tool_name": "disk_usage",
                "result": {
                    "status": "ok",
                    "observations": [
                        {"path": "/", "used_percent": 61.2, "inode_used_percent": 7.4}
                    ],
                },
            },
            {
                "tool_name": "process_list",
                "result": {
                    "status": "ok",
                    "observations": [
                        {
                            "pid": 42,
                            "command": "gateway",
                            "cpu_percent": 8.5,
                            "is_zombie": False,
                        }
                    ],
                },
            },
            {
                "tool_name": "network_listeners",
                "result": {
                    "status": "ok",
                    "observations": [],
                    "summary_fields": {
                        "listener_count": 3,
                        "wildcard_listener_count": 1,
                        "public_listener_count": 0,
                        "unknown_scope_listener_count": 0,
                        "unattributed_listener_count": 1,
                    },
                },
            },
            {
                "tool_name": "service_status",
                "result": {
                    "status": "ok",
                    "observations": [
                        {
                            "unit": "demo.service",
                            "load": "loaded",
                            "active": "failed",
                            "sub": "failed",
                        }
                    ],
                },
            },
            {
                "tool_name": "service_status",
                "result": {
                    "status": "ok",
                    "observations": [
                        {
                            "unit": "demo.service",
                            "active_state": "failed",
                            "sub_state": "failed",
                            "result": "exit-code",
                            "exec_start_path": "/usr/bin/false",
                            "exec_main_status": 1,
                        }
                    ],
                },
            },
            {
                "tool_name": "time_sync_status",
                "result": {
                    "status": "ok",
                    "observations": [{"ntp_synchronized": True}],
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("1 分钟负载 0.75，内存使用率 42.3%", summary)
        self.assertIn("根分区使用率 61.2%，inode 使用率 7.4%", summary)
        self.assertIn("僵尸进程 0 个", summary)
        self.assertIn("systemd 失败服务 1 个", summary)
        self.assertIn("demo.service 的启动入口 /usr/bin/false 以状态 1 退出", summary)
        self.assertIn("监听端口 3 个，其中外部或范围待确认 1 个、归属待确认 1 个", summary)
        self.assertIn("系统时间已同步", summary)
        self.assertNotIn("未取得有效证据", summary)

    def test_general_health_summary_never_treats_unavailable_service_check_as_healthy(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="general_system_health", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": tool_name,
                "result": {"status": "ok", "observations": []},
            }
            for tool_name in (
                "system_snapshot",
                "disk_usage",
                "process_list",
                "network_listeners",
            )
        ]
        observations.append(
            {
                "tool_name": "service_status",
                "result": {"status": "unavailable", "observations": []},
            }
        )

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("失败服务未取得有效证据", summary)
        self.assertIn("暂不判断整机健康", summary)
        self.assertNotIn("失败服务 0 个", summary)

    def test_process_summary_reports_resource_pressure_and_hot_processes(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="process_health_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="检查 CPU、内存和 PSI 压力",
        )
        observations = [
            {
                "tool_name": "system_snapshot",
                "result": {
                    "observations": [
                        {
                            "loadavg": [1.2, 1.56, 1.29],
                            "memory": {"used_percent": 30.95},
                            "pressure": {
                                "cpu": {"some": {"avg10": 0.12}},
                                "memory": {"some": {"avg10": 0.0}},
                                "io": {"full": {"avg10": 0.14}},
                            },
                        }
                    ]
                },
            },
            {
                "tool_name": "process_list",
                "result": {
                    "observations": [
                        {
                            "pid": 364535,
                            "command": "python",
                            "cpu_percent": 25.4,
                            "mem_percent": 1.3,
                            "is_zombie": False,
                        },
                        {
                            "pid": 274537,
                            "command": "checkout-api",
                            "cpu_percent": 22.3,
                            "mem_percent": 14.1,
                            "is_zombie": False,
                        },
                    ]
                },
            },
            {
                "tool_name": "process_runtime_detail",
                "result": {
                    "observations": [
                        {
                            "pid": 274537,
                            "name": "checkout-api",
                            "vm_rss_kb": 1048576,
                            "open_fd_count": 57,
                            "max_open_files_soft": 10240,
                            "fd_utilization_percent": 0.56,
                            "systemd_unit": None,
                        }
                    ]
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertTrue(summary.startswith("处置判断：无需立即停止或重启"))
        self.assertIn("重点进程：checkout-api（PID 274537）", summary)
        self.assertIn("1/5/15 分钟负载为 1.20/1.56/1.29", summary)
        self.assertIn("内存使用率 30.9%", summary)
        self.assertIn("CPU 争用 0.12%", summary)
        self.assertIn("I/O 全体停顿 0.14%", summary)
        self.assertIn("python（PID 364535，25.4%）", summary)
        self.assertIn("checkout-api（PID 274537，14.1%）", summary)
        self.assertIn("RSS 1024.0 MiB", summary)
        self.assertIn("文件句柄 57/10240（0.56%）", summary)
        self.assertIn("未关联 systemd 服务", summary)
        self.assertIn("当前没有持续过载、资源耗尽或僵尸进程等支持性证据", summary)
        self.assertIn("服务归属、资源上限和变化趋势", summary)
        self.assertIn("未执行系统变更", summary)

    def test_process_summary_marks_high_fd_pressure_for_investigation_without_stopping(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="process_health_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "process_runtime_detail",
                "result": {
                    "observations": [
                        {
                            "pid": 42,
                            "name": "database",
                            "open_fd_count": 900,
                            "max_open_files_soft": 1024,
                            "fd_utilization_percent": 87.89,
                            "systemd_unit": "database.service",
                        }
                    ]
                },
            }
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("需要继续调查的异常指标", summary)
        self.assertIn("证据不足以安全停止或重启进程", summary)

    def test_process_summary_does_not_replace_missing_target_with_other_processes(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="process_health_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="继续核查 PID 175499 的运行状态和文件句柄",
        )
        observations = [
            {
                "tool_name": "process_list",
                "result": {
                    "observations": [
                        {
                            "pid": 662,
                            "command": "checkout-api",
                            "cpu_percent": 30.5,
                            "mem_percent": 21.0,
                            "is_zombie": False,
                        }
                    ]
                },
            },
            {
                "tool_name": "process_runtime_detail",
                "result": {
                    "status": "unavailable",
                    "observations": [{"pid": 175499, "exists": False}],
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertTrue(summary.startswith("目标核验：PID 175499 在本次采样时已不存在"))
        self.assertIn("不能用其他高占用进程替代该目标", summary)
        self.assertIn("避免因进程退出或 PID 复用误判", summary)
        self.assertNotIn("当前没有持续过载", summary)

    def test_process_summary_ranks_file_handles_by_soft_limit_utilization(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="process_health_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "process_file_handles",
                "result": {
                    "observations": [
                        {
                            "pid": 10,
                            "command": "database",
                            "open_fd_count": 300,
                            "max_open_files_soft": 1_048_576,
                            "fd_utilization_percent": 0.03,
                        },
                        {
                            "pid": 20,
                            "command": "bounded-worker",
                            "open_fd_count": 100,
                            "max_open_files_soft": 128,
                            "fd_utilization_percent": 78.12,
                        },
                    ]
                },
            }
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("bounded-worker（PID 20）使用 100/128（78.12%）", summary)
        self.assertNotIn("database（PID 10）", summary)

    def test_process_summary_identifies_zombie_parent_relationship(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="process_health_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "process_list",
                "result": {
                    "observations": [
                        {
                            "pid": 43,
                            "ppid": 42,
                            "command": "python",
                            "stat": "Z",
                            "cpu_percent": 0.0,
                            "mem_percent": 0.0,
                            "is_zombie": True,
                        }
                    ]
                },
            }
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("PID 43（父进程 PID 42，状态 Z）", summary)

    def test_process_summary_keeps_sampled_hot_process_as_focus_when_parent_chain_follows(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="process_health_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "process_list",
                "result": {
                    "observations": [
                        {
                            "pid": 530,
                            "command": "checkout-api",
                            "cpu_percent": 95.0,
                            "mem_percent": 2.0,
                            "is_zombie": False,
                        },
                        {
                            "pid": 528,
                            "command": "SessionLeader",
                            "cpu_percent": 0.0,
                            "mem_percent": 0.1,
                            "is_zombie": False,
                        },
                    ]
                },
            },
            {
                "tool_name": "process_runtime_detail",
                "result": {
                    "observations": [
                        {"pid": 530, "name": "checkout-api", "open_fd_count": 42},
                        {"pid": 529, "name": "Relay", "open_fd_count": 10},
                        {"pid": 528, "name": "SessionLeader", "open_fd_count": 8},
                    ]
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertTrue(summary.startswith("处置判断：暂不建议立即停止或重启"))
        self.assertIn("重点进程：checkout-api（PID 530）", summary)
        self.assertNotIn("重点进程：SessionLeader", summary)

    def test_large_file_observations_survive_later_empty_scans_and_are_deduplicated(self) -> None:
        observations = [
            {
                "tool_name": "find_large_files",
                "result": {
                    "observations": [
                        {"path": "/tmp/opscouncil-lab/app.log", "size_bytes": 36 * 1024 * 1024}
                    ]
                },
            },
            {
                "tool_name": "find_large_files",
                "result": {
                    "observations": [
                        {"path": "/tmp/opscouncil-lab/app.log", "size_bytes": 36 * 1024 * 1024}
                    ]
                },
            },
            {"tool_name": "find_large_files", "result": {"observations": []}},
        ]

        scan_performed, files = _collect_large_file_observations(observations)

        self.assertTrue(scan_performed)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["path"], "/tmp/opscouncil-lab/app.log")

    def test_direct_disk_summary_reports_capacity_without_promising_future_work(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="disk_pressure_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "disk_usage",
                "result": {
                    "observations": [
                        {
                            "path": "/",
                            "used_percent": 13.3,
                            "free_bytes": 20 * 1024**3,
                            "inode_used_percent": 2.4,
                        }
                    ],
                },
            }
        ]

        summary = runner._summarize(
            task,
            observations,
            proposal_context=None,
            investigation_status="DIRECT_EVIDENCE",
        )

        self.assertIn("/ 使用率最高，为 13.3%", summary)
        self.assertIn("可用约 20.0 GiB", summary)
        self.assertIn("inode 使用率 2.4%", summary)
        self.assertIn("本次仅查询容量", summary)
        self.assertNotIn("后续调查将", summary)
        self.assertNotIn("未发现超过阈值", summary)

    def test_network_summary_uses_scope_and_attribution_facts(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="network_exposure_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "network_listeners",
                "result": {
                    "observations": [
                        {"local_address": "127.0.0.1:8000", "pid": 100},
                        {"local_address": "10.0.0.5:53", "pid": None},
                    ],
                    "summary_fields": {
                        "listener_count": 10,
                        "wildcard_listener_count": 0,
                        "public_listener_count": 0,
                        "unknown_scope_listener_count": 0,
                        "unattributed_listener_count": 4,
                        "attribution_rate_percent": 60.0,
                    },
                },
            }
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertEqual(
            summary,
            "当前未发现公网或全地址监听；10 个监听中 6 个已关联进程，"
            "4 个仍需补充归属。建议先核对未归属端口的服务来源，本轮未修改网络配置。",
        )

    def test_network_summary_reconciles_approved_listener_catalog(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="network_exposure_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="检查监听端口是否符合服务目录和批准范围",
        )
        observations = [
            {
                "tool_name": "network_listeners",
                "result": {
                    "observations": [
                        {
                            "protocol": "tcp",
                            "local_address": "127.0.0.1:5432",
                            "exposure_scope": "loopback",
                            "pid": 327,
                            "process": "postgres",
                            "systemd_unit": "postgresql@14-main.service",
                        },
                        {
                            "protocol": "tcp",
                            "local_address": "127.0.0.1:6379",
                            "exposure_scope": "loopback",
                            "pid": 328,
                            "process": "redis-server",
                            "systemd_unit": "redis-server.service",
                        },
                    ],
                    "summary_fields": {
                        "listener_count": 2,
                        "unattributed_listener_count": 0,
                        "wildcard_listener_count": 0,
                        "public_listener_count": 0,
                        "unknown_scope_listener_count": 0,
                    },
                },
            },
            {
                "tool_name": "service_catalog_snapshot",
                "result": {
                    "observations": [
                        {
                            "unit_name": "postgresql@14-main.service",
                            "listener_expectations": [
                                {
                                    "protocol": "tcp",
                                    "port": 5432,
                                    "allowed_scope": "loopback",
                                    "required": True,
                                }
                            ],
                        }
                    ],
                    "summary_fields": {
                        "service_count": 1,
                        "listener_expectation_count": 1,
                    },
                },
            },
        ]

        summary = runner._summarize(
            task,
            observations,
            proposal_context=None,
        )

        self.assertEqual(
            summary,
            "当前未发现公网或全地址监听；2 个监听均已关联进程。"
            "建议结合业务清单复核监听必要性，"
            "服务目录核对：1 个登记监听符合，1 个监听尚未纳管。"
            "本轮未修改网络配置。",
        )

    def test_network_summary_does_not_treat_unknown_scope_as_catalog_compliant(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="network_exposure_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="检查监听端口是否符合服务目录和批准范围",
        )
        observations = [
            {
                "tool_name": "network_listeners",
                "result": {
                    "observations": [
                        {
                            "protocol": "tcp",
                            "local_address": "10.0.0.8:8443",
                            "exposure_scope": "unknown",
                            "pid": 327,
                            "process": "checkout-api",
                            "systemd_unit": "checkout-api.service",
                        }
                    ],
                    "summary_fields": {
                        "listener_count": 1,
                        "unattributed_listener_count": 0,
                        "wildcard_listener_count": 0,
                        "public_listener_count": 0,
                        "unknown_scope_listener_count": 1,
                    },
                },
            },
            {
                "tool_name": "service_catalog_snapshot",
                "result": {
                    "observations": [
                        {
                            "unit_name": "checkout-api.service",
                            "listener_expectations": [
                                {
                                    "protocol": "tcp",
                                    "port": 8443,
                                    "allowed_scope": "private",
                                    "required": True,
                                }
                            ],
                        }
                    ],
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("1 个登记监听归属待确认", summary)
        self.assertNotIn("1 个登记监听符合", summary)

    def test_network_summary_preserves_duplicate_catalog_expectations(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="network_exposure_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="检查监听端口是否符合服务目录和批准范围",
        )
        observations = [
            {
                "tool_name": "network_listeners",
                "result": {
                    "observations": [],
                    "summary_fields": {
                        "listener_count": 0,
                        "unattributed_listener_count": 0,
                        "wildcard_listener_count": 0,
                        "public_listener_count": 0,
                        "unknown_scope_listener_count": 0,
                    },
                },
            },
            {
                "tool_name": "service_catalog_snapshot",
                "result": {
                    "observations": [
                        {
                            "unit_name": "api-a.service",
                            "listener_expectations": [
                                {
                                    "protocol": "tcp",
                                    "port": 9443,
                                    "allowed_scope": "private",
                                    "required": True,
                                }
                            ],
                        },
                        {
                            "unit_name": "api-b.service",
                            "listener_expectations": [
                                {
                                    "protocol": "tcp",
                                    "port": 9443,
                                    "allowed_scope": "private",
                                    "required": True,
                                }
                            ],
                        },
                    ],
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("2 个登记要求存在偏差", summary)

    def test_network_summary_preserves_overall_scope_for_broad_request(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="network_exposure_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="检查当前主机的网络监听端口和暴露风险",
        )
        observations = [
            {
                "tool_name": "network_listeners",
                "result": {
                    "observations": [],
                    "summary_fields": {
                        "listener_count": 10,
                        "unattributed_listener_count": 4,
                    },
                },
            },
            {
                "tool_name": "socket_process_context",
                "result": {
                    "observations": [
                        {
                            "protocol": "tcp",
                            "port": 8000,
                            "listener_count": 1,
                            "listeners": [
                                {
                                    "local_address": "127.0.0.1:8000",
                                    "exposure_scope": "loopback",
                                    "process_name": "uvicorn",
                                    "pid": 42,
                                    "user": "vmuser",
                                    "systemd_unit": "opscouncil.service",
                                }
                            ],
                        }
                    ]
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertEqual(
            summary,
            "当前未发现公网或全地址监听；10 个监听中 6 个已关联进程，"
            "4 个仍需补充归属。建议先核对未归属端口的服务来源，本轮未修改网络配置。",
        )

    def test_network_summary_uses_matching_context_for_explicit_socket_request(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="network_exposure_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="检查 TCP/8000 端口由哪个进程监听",
        )
        observations = [
            {
                "tool_name": "network_listeners",
                "result": {
                    "observations": [],
                    "summary_fields": {"listener_count": 10},
                },
            },
            {
                "tool_name": "socket_process_context",
                "result": {
                    "observations": [
                        {
                            "protocol": "tcp",
                            "port": 8000,
                            "listener_count": 1,
                            "listeners": [
                                {
                                    "local_address": "127.0.0.1:8000",
                                    "exposure_scope": "loopback",
                                    "process_name": "uvicorn",
                                    "pid": 42,
                                    "user": "vmuser",
                                    "systemd_unit": "opscouncil.service",
                                }
                            ],
                        }
                    ]
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertEqual(
            summary,
            "TCP/8000 当前监听 127.0.0.1:8000（回环地址），"
            "归属 uvicorn（PID 42，用户 vmuser），服务单元 opscouncil.service。"
            "本轮未修改网络配置。",
        )

    def test_network_summary_reports_both_protocols_when_target_port_is_absent(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="network_exposure_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="检查端口 18090 是否仍在监听",
        )
        observations = [
            {
                "tool_name": "network_listeners",
                "result": {
                    "observations": [],
                    "summary_fields": {"listener_count": 7},
                },
            },
            {
                "tool_name": "service_catalog_snapshot",
                "result": {"observations": []},
            },
            {
                "tool_name": "socket_process_context",
                "result": {
                    "observations": [
                        {
                            "protocol": "tcp",
                            "port": 18090,
                            "listener_count": 0,
                            "listeners": [],
                        }
                    ]
                },
            },
            {
                "tool_name": "socket_process_context",
                "result": {
                    "observations": [
                        {
                            "protocol": "udp",
                            "port": 18090,
                            "listener_count": 0,
                            "listeners": [],
                        }
                    ]
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertEqual(
            summary,
            "TCP/18090 与 UDP/18090 当前均未处于监听状态。"
            "服务目录未登记该端口。本轮未修改网络配置。",
        )
        self.assertNotIn("7 个监听", summary)

    def test_network_summary_does_not_replace_overview_with_negative_probe(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="network_exposure_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="检查当前主机的网络监听端口和暴露风险",
        )
        observations = [
            {
                "tool_name": "network_listeners",
                "result": {
                    "observations": [],
                    "summary_fields": {
                        "listener_count": 10,
                        "unattributed_listener_count": 4,
                    },
                },
            },
            {
                "tool_name": "socket_process_context",
                "result": {
                    "observations": [
                        {
                            "protocol": "tcp",
                            "port": 323,
                            "listener_count": 0,
                            "listeners": [],
                        }
                    ]
                },
            },
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertEqual(
            summary,
            "当前未发现公网或全地址监听；10 个监听中 6 个已关联进程，"
            "4 个仍需补充归属。建议先核对未归属端口的服务来源，本轮未修改网络配置。",
        )

    def test_network_summary_lists_unattributed_endpoints_for_follow_up(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="network_exposure_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="那哪些端口还没有确认归属？",
        )
        observations = [
            {
                "tool_name": "network_listeners",
                "result": {
                    "observations": [
                        {
                            "protocol": "udp",
                            "local_address": "10.0.0.2:53",
                            "exposure_scope": "private",
                            "process": "",
                            "pid": None,
                        },
                        {
                            "protocol": "udp",
                            "local_address": "127.0.0.1:323",
                            "exposure_scope": "loopback",
                            "process": "",
                            "pid": None,
                        },
                        {
                            "protocol": "tcp",
                            "local_address": "127.0.0.1:8000",
                            "exposure_scope": "loopback",
                            "process": "python",
                            "pid": 42,
                        },
                    ],
                    "summary_fields": {
                        "listener_count": 3,
                        "unattributed_listener_count": 2,
                    },
                },
            }
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertEqual(
            summary,
            "尚未确认进程归属的监听有 2 条：UDP 10.0.0.2:53、"
            "UDP 127.0.0.1:323。这些监听均位于内网或回环地址；"
            "建议结合套接字 inode 与宿主网络转发关系继续核验。"
            "本轮未修改网络配置。",
        )

    def test_disk_summary_does_not_claim_proposal_when_all_large_files_are_protected(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="disk_pressure_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "find_large_files",
                "result": {
                    "observations": [
                        {
                            "path": "/var/log/journal/machine/system.journal",
                            "size_bytes": 32 * 1024 * 1024,
                        }
                    ]
                },
            }
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("未生成处置建议", summary)
        self.assertNotIn("已生成需审批", summary)

    def test_disk_summary_describes_generated_safe_proposal_candidate(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="disk_pressure_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "find_large_files",
                "result": {
                    "observations": [
                        {
                            "path": "/var/log/journal/machine/system.journal",
                            "size_bytes": 32 * 1024 * 1024,
                        },
                        {
                            "path": "/tmp/opscouncil-lab/logs/app-large.log",
                            "size_bytes": 36 * 1024 * 1024,
                        },
                    ]
                },
            }
        ]

        summary = runner._summarize(
            task,
            observations,
            proposal_context={
                "path": "/tmp/opscouncil-lab/logs/app-large.log",
                "size_bytes": 36 * 1024 * 1024,
            },
        )

        self.assertIn("/tmp/opscouncil-lab/logs/app-large.log", summary)
        self.assertIn("已生成需审批", summary)
        self.assertNotIn("/var/log/journal", summary)

    def test_disk_summary_includes_verified_journal_storage_context(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(intent="disk_pressure_analysis", status=TaskStatus.SUMMARIZE.value)
        observations = [
            {
                "tool_name": "journal_storage_status",
                "result": {
                    "observations": [
                        {
                            "reported_disk_usage_bytes": 847563980,
                            "storage": [
                                {
                                    "storage_type": "persistent",
                                    "archived_file_count": 99,
                                    "scan_truncated": False,
                                }
                            ],
                            "settings": {},
                            "settings_available": False,
                            "settings_status": "no_explicit_settings_found",
                        }
                    ]
                },
            },
            {"tool_name": "find_large_files", "result": {"observations": []}},
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("journal 当前占用约 808.3 MiB", summary)
        self.assertIn("扫描到 99 个归档文件", summary)
        self.assertIn("未发现显式留存覆盖", summary)
        self.assertIn("未在允许扫描范围内发现超过阈值的大文件", summary)

    def test_disk_summary_includes_mount_mapping_when_investigation_collected_it(self) -> None:
        runner = AgentRunner.__new__(AgentRunner)
        task = Task(
            intent="disk_pressure_analysis",
            status=TaskStatus.SUMMARIZE.value,
            user_input="核对 /var/log 的挂载点和文件系统类型",
        )
        observations = [
            {
                "tool_name": "filesystem_mount_context",
                "result": {
                    "observations": [
                        {
                            "resolved_path": "/var/log",
                            "mount_target": "/var",
                            "filesystem_type": "xfs",
                            "used_percent": 82.4,
                            "is_network_filesystem": False,
                            "read_only": False,
                        }
                    ]
                },
            },
            {"tool_name": "find_large_files", "result": {"observations": []}},
        ]

        summary = runner._summarize(task, observations, proposal_context=None)

        self.assertIn("路径 /var/log 位于挂载点 /var（xfs，使用率 82.4%）", summary)
        self.assertIn("本轮未执行系统变更", summary)
        self.assertNotIn("大文件定位", summary)


if __name__ == "__main__":
    unittest.main()
