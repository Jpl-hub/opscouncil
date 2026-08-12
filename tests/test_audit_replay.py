from __future__ import annotations

import unittest

from backend.app.audit.replay import STAGE_GROUPS, build_audit_replay
from backend.app.schemas.enums import TaskStatus


class AuditReplayTest(unittest.TestCase):
    def test_every_task_status_is_mapped_to_an_audit_stage(self) -> None:
        mapped = {
            stage
            for group in STAGE_GROUPS
            for stage in group["stages"]
        }

        self.assertTrue({status.value for status in TaskStatus}.issubset(mapped))

    def test_build_replay_groups_events_and_marks_invalid_stage(self) -> None:
        events = [
            {
                "id": 1,
                "stage": "RECEIVED",
                "event_type": "task_created",
                "message": "接收自然语言运维请求。",
                "payload": {"user_input": "帮我分析磁盘空间"},
                "created_at": "2026-06-12T10:00:00+08:00",
            },
            {
                "id": 2,
                "stage": "STATIC_REVIEW",
                "event_type": "safety_review",
                "message": "未命中禁止规则，允许继续只读感知。",
                "payload": {"decision": "ALLOW", "risk_level": "R1"},
                "created_at": "2026-06-12T10:00:01+08:00",
            },
            {
                "id": 3,
                "stage": "PERCEIVE",
                "event_type": "tool_call",
                "message": "调用工具 disk_usage 完成，状态 ok。",
                "payload": {"tool_name": "disk_usage", "duration_ms": 18},
                "created_at": "2026-06-12T10:00:02+08:00",
            },
        ]
        verification = {
            "trace_id": "trace-1",
            "valid": False,
            "entry_count": 3,
            "head_hash": "abc123",
            "entries": [
                {"event_id": 1, "valid": True, "stored_event_hash": "a" * 64},
                {"event_id": 2, "valid": False, "stored_event_hash": "b" * 64},
                {"event_id": 3, "valid": True, "stored_event_hash": "c" * 64},
            ],
        }

        replay = build_audit_replay("trace-1", events, verification)

        self.assertEqual(replay["trace_id"], "trace-1")
        self.assertEqual(replay["integrity"]["entry_count"], 3)
        self.assertEqual(replay["integrity"]["failed_event_count"], 1)
        self.assertFalse(replay["integrity"]["valid"])
        self.assertEqual(replay["current_stage"], "环境感知")

        stages = {stage["key"]: stage for stage in replay["stages"]}
        self.assertEqual(stages["receive"]["status"], "passed")
        self.assertEqual(stages["safety"]["status"], "failed")
        self.assertEqual(stages["perceive"]["status"], "passed")
        self.assertEqual(stages["execute"]["status"], "pending")
        self.assertEqual(stages["perceive"]["events"][0]["component"], "磁盘用量")
        self.assertEqual(stages["safety"]["events"][0]["hash"], "bbbbbbbbbbbb")

        decision_points = replay["decision_points"]
        self.assertEqual(decision_points[0]["label"], "安全校验")
        self.assertEqual(decision_points[0]["decision"], "允许")
        self.assertEqual(decision_points[0]["risk_level"], "R1")

    def test_replay_keeps_model_decision_compact_and_groups_ai_analysis(self) -> None:
        events = [
            {
                "id": 1,
                "stage": "PLAN",
                "event_type": "intent_resolved",
                "message": "模型完成结构化意图解析。",
                "payload": {
                    "decision": {
                        "intent": "disk_pressure_analysis",
                        "confidence": 0.98,
                        "reasoning_summary": ["very long text"],
                    }
                },
                "created_at": "2026-06-12T10:00:00+08:00",
            },
            {
                "id": 2,
                "stage": "AI_ANALYSIS",
                "event_type": "ai_analysis_created",
                "message": "模型完成研判报告。",
                "payload": {"model": "qwen-plus-latest"},
                "created_at": "2026-06-12T10:00:01+08:00",
            },
        ]
        verification = {
            "trace_id": "trace-2",
            "valid": True,
            "entry_count": 2,
            "head_hash": "abc123",
            "entries": [
                {"event_id": 1, "valid": True, "stored_event_hash": "a" * 64},
                {"event_id": 2, "valid": True, "stored_event_hash": "b" * 64},
            ],
        }

        replay = build_audit_replay("trace-2", events, verification)

        self.assertEqual(replay["current_stage"], "总结封存")
        self.assertEqual(replay["decision_points"][0]["decision"], "磁盘空间分析")
        self.assertNotIn("reasoning_summary", replay["decision_points"][0]["decision"])
        stages = {stage["key"]: stage for stage in replay["stages"]}
        self.assertEqual(stages["seal"]["event_count"], 1)
        self.assertEqual(stages["seal"]["events"][0]["label"], "智能研判")

    def test_replay_labels_skill_policy_events_as_agent_governance(self) -> None:
        events = [
            {
                "id": 1,
                "stage": "PLAN",
                "event_type": "skill_selected",
                "message": "选择运维能力包：系统健康巡检。",
                "payload": {
                    "skill_name": "系统健康巡检",
                    "skill_id": "skill.general_system_health",
                    "used_tools": ["system_snapshot", "disk_usage"],
                },
                "created_at": "2026-06-12T10:00:00+08:00",
            }
        ]
        verification = {
            "trace_id": "trace-3",
            "valid": True,
            "entry_count": 1,
            "head_hash": "abc123",
            "entries": [{"event_id": 1, "valid": True, "stored_event_hash": "a" * 64}],
        }

        replay = build_audit_replay("trace-3", events, verification)

        stages = {stage["key"]: stage for stage in replay["stages"]}
        self.assertEqual(stages["plan"]["events"][0]["label"], "能力包治理")
        self.assertEqual(stages["plan"]["events"][0]["component"], "Agent Skill")
        self.assertEqual(replay["decision_points"][0]["decision"], "系统健康巡检")

    def test_replay_includes_investigation_events_and_marks_optional_stage_skipped(self) -> None:
        events = [
            {
                "id": 1,
                "stage": "INVESTIGATE",
                "event_type": "investigation_started",
                "message": "已建立受预算约束的根因调查。",
                "payload": {"investigation_id": 7},
                "created_at": "2026-07-14T10:00:00+08:00",
            },
            {
                "id": 2,
                "stage": "SUMMARIZE",
                "event_type": "summary_created",
                "message": "调查完成。",
                "payload": {},
                "created_at": "2026-07-14T10:00:01+08:00",
            },
        ]
        verification = {
            "valid": True,
            "entry_count": 2,
            "head_hash": "abc123",
            "entries": [
                {"event_id": 1, "valid": True, "stored_event_hash": "a" * 64},
                {"event_id": 2, "valid": True, "stored_event_hash": "b" * 64},
            ],
        }

        replay = build_audit_replay("trace-investigation", events, verification)
        stages = {stage["key"]: stage for stage in replay["stages"]}

        self.assertEqual(stages["investigate"]["status"], "passed")
        self.assertEqual(stages["investigate"]["event_count"], 1)
        self.assertEqual(stages["investigate"]["events"][0]["component"], "调查控制器")
        self.assertEqual(stages["execute"]["status"], "skipped")

    def test_replay_exposes_controller_enforced_evidence_obligation(self) -> None:
        events = [
            {
                "id": 1,
                "stage": "INVESTIGATE",
                "event_type": "evidence_obligation_enforced",
                "message": "结论前强制补齐证据：独立核验配置内容。",
                "payload": {
                    "obligation": {
                        "key": "configuration_counter_evidence",
                        "title": "独立核验配置内容",
                        "tool_name": "config_integrity_scan",
                    }
                },
                "created_at": "2026-07-29T01:00:00+08:00",
            }
        ]
        verification = {
            "valid": True,
            "entry_count": 1,
            "head_hash": "abc123",
            "entries": [{"event_id": 1, "valid": True, "stored_event_hash": "a" * 64}],
        }

        replay = build_audit_replay("trace-obligation", events, verification)

        stages = {stage["key"]: stage for stage in replay["stages"]}
        event = stages["investigate"]["events"][0]
        self.assertEqual(event["label"], "结论前补证")
        self.assertEqual(event["component"], "证据义务控制器")
        self.assertEqual(replay["decision_points"][0]["decision"], "独立核验配置内容")

    def test_replay_localizes_rollback_event_and_tool_component(self) -> None:
        events = [
            {
                "id": 1,
                "stage": "VERIFY",
                "event_type": "rollback_proposal_created",
                "message": "根据真实备份产物生成可审批的日志回滚方案。",
                "payload": {"tool_name": "restore_log_backup"},
                "created_at": "2026-06-18T10:00:00+08:00",
            }
        ]
        verification = {
            "trace_id": "trace-rollback",
            "valid": True,
            "entry_count": 1,
            "head_hash": "abc123",
            "entries": [{"event_id": 1, "valid": True, "stored_event_hash": "a" * 64}],
        }

        replay = build_audit_replay("trace-rollback", events, verification)

        stages = {stage["key"]: stage for stage in replay["stages"]}
        self.assertEqual(stages["execute"]["events"][0]["label"], "回滚方案")
        self.assertEqual(stages["execute"]["events"][0]["component"], "日志备份恢复")

    def test_replay_localizes_worker_event_and_approval_decision(self) -> None:
        events = [
            {
                "id": 1,
                "stage": "RECEIVED",
                "event_type": "worker_started",
                "message": "Worker 已领取任务。",
                "payload": {"worker_id": "worker-1"},
                "created_at": "2026-07-13T09:00:00+08:00",
            },
            {
                "id": 2,
                "stage": "STATIC_REVIEW",
                "event_type": "safety_review",
                "message": "请求需要人工审批。",
                "payload": {"decision": "APPROVAL_REQUIRED", "risk_level": "R3"},
                "created_at": "2026-07-13T09:00:01+08:00",
            },
        ]
        verification = {
            "valid": True,
            "entry_count": 2,
            "head_hash": "abc123",
            "entries": [
                {"event_id": 1, "valid": True, "stored_event_hash": "a" * 64},
                {"event_id": 2, "valid": True, "stored_event_hash": "b" * 64},
            ],
        }

        replay = build_audit_replay("trace-worker", events, verification)
        stages = {stage["key"]: stage for stage in replay["stages"]}

        self.assertEqual(stages["receive"]["events"][0]["label"], "任务执行器开始处理")
        self.assertEqual(stages["receive"]["events"][0]["component"], "任务执行器")
        self.assertEqual(replay["decision_points"][0]["decision"], "等待审批")

    def test_replay_localizes_patrol_and_unknown_event_codes(self) -> None:
        events = [
            {
                "id": 1,
                "stage": "RECEIVED",
                "event_type": "patrol_incident_created",
                "message": "巡检发现已聚合为事件。",
                "payload": {},
                "created_at": "2026-07-14T10:00:00+08:00",
            },
            {
                "id": 2,
                "stage": "RECEIVED",
                "event_type": "future_internal_code",
                "message": "保留事件正文。",
                "payload": {},
                "created_at": "2026-07-14T10:00:01+08:00",
            },
        ]
        verification = {
            "valid": True,
            "entry_count": 2,
            "head_hash": "abc123",
            "entries": [
                {"event_id": 1, "valid": True, "stored_event_hash": "a" * 64},
                {"event_id": 2, "valid": True, "stored_event_hash": "b" * 64},
            ],
        }

        replay = build_audit_replay("trace-patrol", events, verification)
        rows = {row["event_type"]: row for stage in replay["stages"] for row in stage["events"]}

        self.assertEqual(rows["patrol_incident_created"]["label"], "巡检事件接入")
        self.assertEqual(rows["patrol_incident_created"]["component"], "自动巡检")
        self.assertEqual(rows["future_internal_code"]["label"], "系统事件")

    def test_replay_marks_unneeded_execution_stage_after_read_only_task_is_sealed(self) -> None:
        events = [
            {
                "id": 1,
                "stage": "PERCEIVE",
                "event_type": "tool_call",
                "message": "调用进程运行详情工具完成，状态正常。",
                "payload": {"tool_name": "process_runtime_detail"},
                "created_at": "2026-07-14T10:00:00+08:00",
            },
            {
                "id": 2,
                "stage": "SUMMARIZE",
                "event_type": "investigation_evidence_risk_assessed",
                "message": "根据 MCP 证据将任务风险协调为 R0。",
                "payload": {"final_risk_level": "R0"},
                "created_at": "2026-07-14T10:00:01+08:00",
            },
            {
                "id": 3,
                "stage": "SEALED",
                "event_type": "state_transition",
                "message": "任务审计链封存。",
                "payload": {"status": "SEALED"},
                "created_at": "2026-07-14T10:00:02+08:00",
            },
        ]
        verification = {
            "valid": True,
            "entry_count": 3,
            "head_hash": "abc123",
            "entries": [
                {"event_id": item["id"], "valid": True, "stored_event_hash": "a" * 64}
                for item in events
            ],
        }

        replay = build_audit_replay("trace-read-only", events, verification)
        stages = {stage["key"]: stage for stage in replay["stages"]}

        self.assertEqual(stages["investigate"]["status"], "skipped")
        self.assertEqual(stages["execute"]["status"], "skipped")
        self.assertEqual(stages["perceive"]["events"][0]["component"], "进程运行详情")
        self.assertEqual(stages["seal"]["events"][0]["label"], "调查证据风险协调")
        self.assertEqual(stages["seal"]["events"][0]["component"], "安全护栏")


if __name__ == "__main__":
    unittest.main()
