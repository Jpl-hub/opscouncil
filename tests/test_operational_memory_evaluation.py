from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.memory.evaluation import OperationalMemoryEvaluationService
from backend.app.memory.integrity import seal_memory_content, verify_memory_content
from backend.app.models.entities import EvaluationReport, OperationalMemory, Task, utcnow


class FakeMemorySearch:
    def __init__(self, memories: list[OperationalMemory]) -> None:
        self.memories = memories
        self.calls: list[dict] = []
        self.model_client = SimpleNamespace(
            embedding_model="text-embedding-v4",
            rerank_model="qwen3-rerank",
        )

    def search_confirmed(self, query: str, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append({"query": query, **kwargs})
        host_scope = kwargs.get("host_scope")
        service_scope = kwargs.get("service_scope")
        rows = [
            memory
            for memory in self.memories
            if memory.status == "CONFIRMED"
            and memory.qualification_status == "QUALIFIED"
            and verify_memory_content(memory)
            and (memory.valid_until is None or memory.valid_until > utcnow())
            and (memory.host_scope == "*" or memory.host_scope == host_scope)
            and (
                service_scope is None
                or memory.service_scope == "*"
                or memory.service_scope == service_scope
            )
        ]
        return [SimpleNamespace(chunk_id=memory.id) for memory in rows[: kwargs.get("limit", 3)]]


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    for table in (Task, OperationalMemory, EvaluationReport):
        table.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


def add_memory(
    session: Session,
    *,
    key: str,
    status: str,
    host_scope: str,
    valid_until=None,  # type: ignore[no-untyped-def]
    qualification_status: str | None = None,
) -> OperationalMemory:
    task = Task(
        trace_id=f"trace-{key}",
        user_input="排查服务异常",
        intent="log_analysis",
        status="SEALED",
        risk_level="R1",
    )
    session.add(task)
    session.flush()
    memory = OperationalMemory(
        memory_key=key,
        version=1,
        status=status,
        memory_kind="INCIDENT_CASE",
        source_task_id=task.id,
        host_scope=host_scope,
        service_scope="sshd.service",
        symptom_fingerprint="a" * 64,
        applicability_json={},
        confidence_score=90,
        title=f"{key} 服务异常",
        root_cause="配置项不兼容导致服务启动失败。",
        resolution="备份配置后修正参数并独立验证服务状态。",
        evidence_refs_json=[],
        content_hash="0" * 64,
        parent_content_hash=None,
        search_text=key,
        embedding=[0.01] * 1024,
        created_by="admin",
        qualification_status=(
            qualification_status
            or ("QUALIFIED" if status == "CONFIRMED" else "PENDING")
        ),
        qualification_report_json={},
        valid_until=valid_until,
    )
    seal_memory_content(memory)
    session.add(memory)
    session.flush()
    return memory


def test_evaluates_recall_scope_and_state_exclusion_without_usage_side_effects() -> None:
    session = build_session()
    confirmed = add_memory(session, key="confirmed", status="CONFIRMED", host_scope="node-a")
    corrected = add_memory(session, key="corrected", status="CORRECTED", host_scope="node-a")
    expired = add_memory(
        session,
        key="expired",
        status="CONFIRMED",
        host_scope="node-a",
        valid_until=utcnow() - timedelta(minutes=1),
    )
    search = FakeMemorySearch([confirmed, corrected, expired])

    report = OperationalMemoryEvaluationService(session, search).run()

    assert report["overall_status"] == "ok"
    assert report["summary"]["eligible_count"] == 1
    assert report["summary"]["top1_recall_rate"] == 1.0
    assert report["summary"]["scope_isolation_rate"] == 1.0
    assert report["summary"]["state_exclusion_rate"] == 1.0
    assert report["summary"]["content_integrity_rate"] == 1.0
    assert report["cases"][0]["category"] == "CONTENT_INTEGRITY"
    assert all(call["record_usage"] is False for call in search.calls)
    assert confirmed.retrieval_count == 0
    assert session.query(EvaluationReport).count() == 1
    session.close()


def test_reports_missing_prerequisite_without_inventing_a_score() -> None:
    session = build_session()
    draft = add_memory(session, key="draft", status="DRAFT", host_scope="node-a")
    search = FakeMemorySearch([draft])

    report = OperationalMemoryEvaluationService(session, search).run()

    assert report["overall_status"] == "prerequisite_missing"
    assert report["summary"]["top1_recall_rate"] is None
    assert report["summary"]["content_integrity_rate"] == 1.0
    assert report["cases"][0]["category"] == "CONTENT_INTEGRITY"
    assert search.calls == []
    session.close()


def test_fails_closed_when_memory_content_is_modified_outside_version_flow() -> None:
    session = build_session()
    memory = add_memory(
        session,
        key="tampered",
        status="CONFIRMED",
        host_scope="node-a",
    )
    memory.resolution = "已绕过版本流程修改。"
    session.flush()
    search = FakeMemorySearch([memory])

    report = OperationalMemoryEvaluationService(session, search).run()

    assert report["overall_status"] == "failed"
    assert report["summary"]["eligible_count"] == 0
    assert report["summary"]["content_integrity_rate"] == 0.0
    assert report["cases"][0]["passed"] is False
    assert report["cases"][0]["observed_memory_ids"] == [memory.id]
    assert report["reason_codes"] == ["memory_content_integrity_failed"]
    assert search.calls == []
    session.close()
