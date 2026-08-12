from __future__ import annotations

import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.audit.service import AuditService
from backend.app.core.pydantic_compat import BaseModel, Field
from backend.app.investigation.tool_executor import MCPObservationExecutor
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolDefinition, ToolResult, schema_hash
from backend.app.models.entities import (
    AuditChain,
    PlatformCapabilitySnapshot,
    SystemSnapshot,
    Task,
    TaskEvent,
    ToolCall,
)
from backend.app.schemas.enums import RiskLevel


class EmptyInput(BaseModel):
    pass


class LimitInput(BaseModel):
    limit: int = Field(ge=1, le=10)


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    for table in (
        Task,
        ToolCall,
        SystemSnapshot,
        PlatformCapabilitySnapshot,
        TaskEvent,
        AuditChain,
    ):
        table.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


def add_task(session: Session, trace_id: str) -> Task:
    task = Task(trace_id=trace_id, user_input="检查系统", status="PERCEIVE")
    session.add(task)
    session.flush()
    return task


class MCPObservationExecutorTest(unittest.TestCase):
    def test_platform_profile_is_persisted_and_bound_to_task(self) -> None:
        with build_session() as session:
            registry = ToolRegistry()
            registry.register(
                ToolDefinition(
                    name="platform_capability_profile",
                    version="1.0.0",
                    description="主机能力画像",
                    risk_level=RiskLevel.R0,
                    input_model=EmptyInput,
                    output_model=ToolResult,
                    handler=lambda _: ToolResult(
                        observations=[
                            {
                                "profile_version": "1.0.0",
                                "status": "SUPPORTED",
                                "platform": {
                                    "hostname": "linux-node",
                                    "machine": "loongarch64",
                                    "kernel": "5.10.0",
                                    "os_release": {
                                        "pretty_name": "Enterprise Linux 9"
                                    },
                                },
                                "capabilities": {
                                    "kernel.procfs": {"status": "SUPPORTED"}
                                },
                            }
                        ]
                    ),
                )
            )
            task = add_task(session, "trace-platform-profile")

            call = MCPObservationExecutor(
                session,
                registry,
                AuditService(session),
            ).execute(
                task,
                "platform_capability_profile",
                {},
                reason="确认主机工具前置条件",
                source="baseline",
            )
            session.commit()

            snapshot = session.scalar(select(PlatformCapabilitySnapshot))
            self.assertIsNotNone(snapshot)
            assert snapshot is not None
            self.assertEqual(snapshot.task_id, task.id)
            self.assertEqual(snapshot.machine, "loongarch64")
            self.assertEqual(snapshot.status, "SUPPORTED")
            self.assertEqual(len(snapshot.payload_hash), 64)
            self.assertEqual(
                snapshot.payload_json,
                call.output_json["observations"][0],
            )

    def test_success_persists_tool_snapshot_schema_and_audit_source(self) -> None:
        with build_session() as session:
            registry = ToolRegistry()
            tool = ToolDefinition(
                name="system_snapshot",
                version="2.1.0",
                description="系统快照",
                risk_level=RiskLevel.R0,
                input_model=EmptyInput,
                output_model=ToolResult,
                handler=lambda _: ToolResult(
                    observations=[{"hostname": "lab", "machine": "loongarch64"}],
                    evidence_refs=["/etc/os-release"],
                ),
            )
            registry.register(tool)
            task = add_task(session, "trace-observation-success")
            executor = MCPObservationExecutor(session, registry, AuditService(session))

            call = executor.execute(
                task,
                "system_snapshot",
                {},
                reason="建立主机上下文",
                source="investigation",
                iteration=2,
            )
            session.commit()

            self.assertEqual(call.status, "ok")
            self.assertEqual(call.tool_version, "2.1.0")
            self.assertGreaterEqual(call.duration_ms, 0)
            self.assertIsNotNone(call.ended_at)
            snapshot = session.scalar(select(SystemSnapshot).where(SystemSnapshot.task_id == task.id))
            self.assertIsNotNone(snapshot)
            assert snapshot is not None
            self.assertEqual(snapshot.payload_json, call.output_json)
            event = session.scalar(
                select(TaskEvent).where(
                    TaskEvent.task_id == task.id,
                    TaskEvent.event_type == "tool_call",
                )
            )
            self.assertIsNotNone(event)
            assert event is not None
            self.assertEqual(event.payload_json["source"], "investigation")
            self.assertEqual(event.payload_json["iteration"], 2)
            self.assertEqual(event.payload_json["reason"], "建立主机上下文")
            self.assertEqual(
                event.payload_json["input_schema_hash"],
                schema_hash(tool.input_model.model_json_schema()),
            )
            self.assertEqual(
                event.payload_json["output_schema_hash"],
                schema_hash(tool.output_model.model_json_schema()),
            )
            self.assertTrue(AuditService(session).verify_trace(task.trace_id)["valid"])

    def test_handler_failure_is_recorded_once_without_hidden_retry(self) -> None:
        with build_session() as session:
            calls = 0

            def failing_handler(_: BaseModel) -> ToolResult:
                nonlocal calls
                calls += 1
                raise RuntimeError("collector failed")

            registry = ToolRegistry()
            registry.register(
                ToolDefinition(
                    name="process_list",
                    version="1.0.0",
                    description="进程列表",
                    risk_level=RiskLevel.R0,
                    input_model=LimitInput,
                    output_model=ToolResult,
                    handler=failing_handler,
                )
            )
            task = add_task(session, "trace-observation-error")
            executor = MCPObservationExecutor(session, registry, AuditService(session))

            call = executor.execute(
                task,
                "process_list",
                {"limit": 5},
                reason="检查异常进程",
                source="baseline",
            )

            self.assertEqual(calls, 1)
            self.assertEqual(call.status, "error")
            self.assertEqual(call.output_json["status"], "error")
            self.assertIn("collector failed", call.output_json["warnings"][0])
            self.assertEqual(
                len(session.scalars(select(ToolCall).where(ToolCall.task_id == task.id)).all()),
                1,
            )

    def test_schema_failure_is_audited_as_failed_tool_call(self) -> None:
        with build_session() as session:
            registry = ToolRegistry()
            registry.register(
                ToolDefinition(
                    name="process_list",
                    version="1.0.0",
                    description="进程列表",
                    risk_level=RiskLevel.R0,
                    input_model=LimitInput,
                    output_model=ToolResult,
                    handler=lambda _: ToolResult(),
                )
            )
            task = add_task(session, "trace-observation-schema-error")
            executor = MCPObservationExecutor(session, registry, AuditService(session))

            call = executor.execute(
                task,
                "process_list",
                {"limit": 999},
                reason="检查异常进程",
                source="investigation",
                iteration=1,
            )

            self.assertEqual(call.status, "error")
            self.assertTrue(call.output_json["warnings"])
            event = session.scalar(
                select(TaskEvent).where(
                    TaskEvent.task_id == task.id,
                    TaskEvent.event_type == "tool_call",
                )
            )
            self.assertIsNotNone(event)
            assert event is not None
            self.assertEqual(event.payload_json["output"]["status"], "error")

    def test_explicit_verification_stage_is_persisted_in_audit_event(self) -> None:
        with build_session() as session:
            registry = ToolRegistry()
            registry.register(
                ToolDefinition(
                    name="file_integrity_state",
                    version="1.0.0",
                    description="文件完整性",
                    risk_level=RiskLevel.R0,
                    input_model=EmptyInput,
                    output_model=ToolResult,
                    handler=lambda _: ToolResult(observations=[{"size_bytes": 0}]),
                )
            )
            task = add_task(session, "trace-verification-stage")
            executor = MCPObservationExecutor(session, registry, AuditService(session))

            executor.execute(
                task,
                "file_integrity_state",
                {},
                reason="独立验证动作结果",
                source="action_postcondition",
                stage="VERIFY",
            )

            event = session.scalar(select(TaskEvent).where(TaskEvent.task_id == task.id))
            self.assertIsNotNone(event)
            assert event is not None
            self.assertEqual(event.stage, "VERIFY")
            self.assertEqual(event.payload_json["source"], "action_postcondition")


if __name__ == "__main__":
    unittest.main()
