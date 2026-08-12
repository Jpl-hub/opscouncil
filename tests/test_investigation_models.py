from __future__ import annotations

from datetime import datetime, timezone
import unittest

from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.models.entities import (
    EvidenceItem,
    Hypothesis,
    HypothesisEvidence,
    Investigation,
    InvestigationStep,
    Task,
    ToolCall,
)


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)

    @event.listens_for(engine, "connect")
    def enable_sqlite_foreign_keys(dbapi_connection, connection_record) -> None:  # type: ignore[no-untyped-def]
        del connection_record
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    for table in (
        Task,
        ToolCall,
        Investigation,
        InvestigationStep,
        EvidenceItem,
        Hypothesis,
        HypothesisEvidence,
    ):
        table.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


def add_task(session: Session, trace_id: str) -> Task:
    task = Task(trace_id=trace_id, user_input="检查磁盘", status="RECEIVED")
    session.add(task)
    session.flush()
    return task


class InvestigationModelTest(unittest.TestCase):
    def test_task_owns_at_most_one_investigation(self) -> None:
        with build_session() as session:
            task = add_task(session, "trace-one-investigation")
            session.add(
                Investigation(
                    task_id=task.id,
                    status="RUNNING",
                    max_iterations=4,
                    max_tool_calls=12,
                    max_elapsed_ms=120000,
                )
            )
            session.commit()
            session.add(
                Investigation(
                    task_id=task.id,
                    status="RUNNING",
                    max_iterations=4,
                    max_tool_calls=12,
                    max_elapsed_ms=120000,
                )
            )

            with self.assertRaises(IntegrityError):
                session.commit()

    def test_iteration_is_unique_inside_an_investigation(self) -> None:
        with build_session() as session:
            task = add_task(session, "trace-unique-iteration")
            investigation = Investigation(
                task_id=task.id,
                status="RUNNING",
                max_iterations=4,
                max_tool_calls=12,
                max_elapsed_ms=120000,
            )
            session.add(investigation)
            session.flush()
            session.add_all(
                [
                    InvestigationStep(
                        investigation_id=investigation.id,
                        iteration=1,
                        decision="COLLECT",
                        status="COMPLETED",
                    ),
                    InvestigationStep(
                        investigation_id=investigation.id,
                        iteration=1,
                        decision="CONCLUDE",
                        status="COMPLETED",
                    ),
                ]
            )

            with self.assertRaises(IntegrityError):
                session.commit()

    def test_hypothesis_confidence_is_database_bounded(self) -> None:
        with build_session() as session:
            task = add_task(session, "trace-confidence-bound")
            investigation = Investigation(
                task_id=task.id,
                status="RUNNING",
                max_iterations=4,
                max_tool_calls=12,
                max_elapsed_ms=120000,
            )
            session.add(investigation)
            session.flush()
            session.add(
                Hypothesis(
                    investigation_id=investigation.id,
                    key="disk_log_growth",
                    title="日志持续增长",
                    rationale="等待证据",
                    evidence_gap="缺少路径",
                    status="OPEN",
                    confidence_level="LOW",
                    confidence_score=101,
                    first_seen_iteration=1,
                    last_updated_iteration=1,
                )
            )

            with self.assertRaises(IntegrityError):
                session.commit()

    def test_evidence_relation_uses_existing_graph_nodes(self) -> None:
        with build_session() as session:
            task = add_task(session, "trace-evidence-relation")
            investigation = Investigation(
                task_id=task.id,
                status="RUNNING",
                max_iterations=4,
                max_tool_calls=12,
                max_elapsed_ms=120000,
            )
            session.add(investigation)
            session.flush()
            hypothesis = Hypothesis(
                investigation_id=investigation.id,
                key="disk_log_growth",
                title="日志持续增长",
                rationale="日志目录容量异常",
                evidence_gap="缺少增长速率",
                status="OPEN",
                confidence_level="LOW",
                confidence_score=20,
                first_seen_iteration=1,
                last_updated_iteration=1,
            )
            evidence_item = EvidenceItem(
                investigation_id=investigation.id,
                source_ref="tool_call:1:observation:0",
                source_type="MCP",
                source_key="disk_usage",
                title="磁盘用量观测",
                summary="/var/log 使用率较高",
                payload_json={"path": "/var/log", "percent": 88},
                trust_level="SYSTEM_OBSERVATION",
                observed_at=datetime.now(timezone.utc),
            )
            session.add_all([hypothesis, evidence_item])
            session.flush()
            session.add(
                HypothesisEvidence(
                    hypothesis_id=hypothesis.id,
                    evidence_item_id=evidence_item.id,
                    relation="SUPPORTS",
                    rationale="容量观测支持日志增长假设",
                )
            )
            session.commit()

            self.assertEqual(hypothesis.evidence_links[0].evidence_item_id, evidence_item.id)
            self.assertEqual(evidence_item.hypothesis_links[0].hypothesis_id, hypothesis.id)


if __name__ == "__main__":
    unittest.main()
