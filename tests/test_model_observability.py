from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.ai.observability import build_task_observability
from backend.app.models.entities import Investigation, ModelInvocation, SafetyReview, Task, ToolCall


def test_task_observability_separates_model_tool_and_controller_time() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    for model in (Task, Investigation, ToolCall, SafetyReview, ModelInvocation):
        model.__table__.create(engine)
    started = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)
    session = Session(engine)
    task = Task(
        trace_id="trace-observability",
        user_input="检查服务异常",
        intent="log_analysis",
        status="SEALED",
        risk_level="R1",
        created_at=started,
        updated_at=started + timedelta(seconds=2),
        sealed_at=started + timedelta(seconds=2),
    )
    session.add(task)
    session.flush()
    session.add_all(
        [
            ModelInvocation(
                task_id=task.id,
                trace_id=task.trace_id,
                stage="intent",
                operation="CHAT",
                provider="bailian",
                model="qwen-plus-latest",
                status="SUCCEEDED",
                duration_ms=320,
                input_tokens=120,
                output_tokens=20,
                total_tokens=140,
                finish_reason="stop",
                prompt_hash="a" * 64,
            ),
            ModelInvocation(
                task_id=task.id,
                trace_id=task.trace_id,
                stage="investigation",
                operation="CHAT",
                provider="bailian",
                model="qwen-plus-latest",
                status="FAILED",
                duration_ms=180,
                error_category="RATE_LIMIT",
                prompt_hash="b" * 64,
            ),
            ToolCall(
                task_id=task.id,
                tool_name="service_status",
                tool_version="1.0.0",
                input_json={},
                output_json={},
                risk_level="R0",
                status="ok",
                duration_ms=200,
            ),
            Investigation(
                task_id=task.id,
                status="INCONCLUSIVE",
                current_iteration=2,
                max_iterations=4,
                max_tool_calls=12,
                max_elapsed_ms=120000,
                stop_reason="DUPLICATE_TOOL_CALL",
            ),
            SafetyReview(
                task_id=task.id,
                review_type="intent",
                risk_level="R1",
                decision="ALLOW",
                matched_rules_json=[],
                reason="只读调查",
            ),
        ]
    )
    session.commit()

    report = build_task_observability(session, task.id)

    assert report["summary"] == {
        "task_elapsed_ms": 2000,
        "model_duration_ms": 500,
        "tool_duration_ms": 200,
        "other_duration_ms": 1300,
        "model_call_count": 2,
        "model_failure_count": 1,
        "tool_call_count": 1,
        "tool_failure_count": 0,
        "tool_partial_count": 0,
        "input_tokens": 120,
        "output_tokens": 20,
        "total_tokens": 140,
        "token_accounting_complete": False,
        "investigation_iterations": 2,
        "investigation_stop_reason": "DUPLICATE_TOOL_CALL",
        "duplicate_call_blocked": True,
        "safety_decisions": ["ALLOW"],
    }
    assert "user_input" not in report
    assert "output_json" not in str(report)
    session.close()
