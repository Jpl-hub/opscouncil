from __future__ import annotations

from datetime import timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.audit.service import AuditService
from backend.app.memory.retrieval import confirmed_scope_filters
from backend.app.memory.integrity import verify_memory_content
from backend.app.memory.service import OperationalMemoryService
from backend.app.knowledge.retrieval import KnowledgeHit, RetrievalProvenance
from backend.app.models.entities import (
    AIAnalysis,
    AuditChain,
    EvidenceItem,
    Hypothesis,
    HypothesisEvidence,
    Investigation,
    OperationalMemoryRelation,
    OperationalMemory,
    OperatorFeedback,
    SystemSnapshot,
    Task,
    TaskEvent,
)


class FakeEmbeddingModel:
    def __init__(self) -> None:
        self.embedded: list[list[str]] = []

    def embed(self, texts: list[str]) -> list[list[float]]:
        self.embedded.append(texts)
        return [[0.01] * 1024 for _ in texts]


class ScopedMemoryRetriever:
    def __init__(
        self,
        session,
        model_client,
        *,
        host_scope,
        service_scope,
    ):  # type: ignore[no-untyped-def]
        del model_client
        self.session = session
        self.host_scope = host_scope
        self.service_scope = service_scope

    def search(self, query: str, limit: int) -> list[KnowledgeHit]:
        del query
        memories = list(
            self.session.scalars(
                select(OperationalMemory)
                .where(*confirmed_scope_filters(self.host_scope, self.service_scope))
                .order_by(OperationalMemory.id.desc())
                .limit(limit)
            )
        )
        return [
            KnowledgeHit(
                chunk_id=memory.id,
                document_id=memory.id,
                title=memory.title,
                source_uri=f"memory://{memory.memory_key}/v{memory.version}",
                trust_level="operator_confirmed",
                content=f"{memory.root_cause}\n{memory.resolution}",
                distance=0.1,
                retrieval=RetrievalProvenance(1, 1, 0.032, 0.98),
                source_kind="memory",
            )
            for memory in memories
        ]


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    for table in (
        Task,
        TaskEvent,
        AuditChain,
        Investigation,
        EvidenceItem,
        Hypothesis,
        HypothesisEvidence,
        AIAnalysis,
        SystemSnapshot,
        OperationalMemory,
        OperationalMemoryRelation,
        OperatorFeedback,
    ):
        table.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


def add_concluded_task(
    session: Session,
    *,
    trace_id: str = "trace-memory-source",
    user_input: str = "排查 sshd 服务启动失败",
) -> tuple[Task, EvidenceItem]:
    task = Task(
        trace_id=trace_id,
        user_input=user_input,
        intent="log_analysis",
        status="SEALED",
        risk_level="R1",
        summary="sshd 配置语法错误导致服务启动失败。",
    )
    session.add(task)
    session.flush()
    investigation = Investigation(
        task_id=task.id,
        status="CONCLUDED",
        current_iteration=2,
        max_iterations=4,
        max_tool_calls=12,
        max_elapsed_ms=120000,
    )
    session.add(investigation)
    session.flush()
    evidence = EvidenceItem(
        investigation_id=investigation.id,
        source_ref="tool_call:42:observation:0",
        source_type="MCP",
        source_key="journal_query",
        title="sshd 日志",
        summary="sshd_config 第 19 行存在不受支持的参数。",
        payload_json={"unit": "sshd.service"},
        trust_level="observed",
    )
    hypothesis = Hypothesis(
        investigation_id=investigation.id,
        key="sshd_invalid_option",
        title="sshd 配置参数无效",
        rationale="日志明确指向配置解析错误。",
        evidence_gap="",
        status="SUPPORTED",
        confidence_level="HIGH",
        confidence_score=92,
        first_seen_iteration=1,
        last_updated_iteration=2,
    )
    session.add_all([evidence, hypothesis])
    session.flush()
    session.add(
        HypothesisEvidence(
            hypothesis_id=hypothesis.id,
            evidence_item_id=evidence.id,
            relation="SUPPORTS",
            rationale="日志与根因直接对应。",
        )
    )
    session.add(
        AIAnalysis(
            task_id=task.id,
            provider="bailian",
            model="qwen-plus-latest",
            status="ok",
            prompt_hash="a" * 64,
            result_json={
                "root_cause": "sshd_config 包含当前版本不支持的参数。",
                "conclusion": "配置语法错误导致 sshd 启动失败。",
            },
            evidence_json=[{"evidence_id": evidence.id}],
        )
    )
    session.add(
        SystemSnapshot(
            task_id=task.id,
            payload_json={"observations": [{"hostname": "linux-node-a"}]},
        )
    )
    session.commit()
    return task, evidence


def build_service(
    session: Session,
    model: FakeEmbeddingModel | None = None,
    *,
    retriever_factory=ScopedMemoryRetriever,  # type: ignore[no-untyped-def]
) -> OperationalMemoryService:
    return OperationalMemoryService(
        session,
        model_client=model or FakeEmbeddingModel(),
        audit=AuditService(session),
        retriever_factory=retriever_factory,
    )


def test_memory_requires_confirmation_and_machine_qualification_before_retrieval() -> None:
    with build_session() as session:
        task, evidence = add_concluded_task(session)
        model = FakeEmbeddingModel()
        service = build_service(session, model)

        draft = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="回滚无效参数，执行 sshd -t 校验后再重启服务。",
            service_scope="sshd.service",
        )

        assert draft.status == "DRAFT"
        assert draft.version == 1
        assert draft.host_scope == "linux-node-a"
        assert draft.memory_kind == "INCIDENT_CASE"
        assert draft.symptom_fingerprint
        assert draft.applicability_json["intent"] == "log_analysis"
        assert draft.confidence_score == 92
        assert draft.evidence_refs_json[0]["evidence_item_id"] == evidence.id
        assert verify_memory_content(draft) is True
        assert service.list_memories(retrievable_only=True) == []
        assert len(model.embedded) == 1

        confirmed = service.confirm(draft.id, actor="on-call-admin")

        assert confirmed.status == "CONFIRMED"
        assert confirmed.confirmed_by == "on-call-admin"
        assert confirmed.valid_from is not None
        assert confirmed.qualification_status == "PENDING"
        assert service.list_memories(retrievable_only=True) == []

        qualified = service.qualify(draft.id, actor="on-call-admin")

        assert qualified.qualification_status == "QUALIFIED"
        assert qualified.qualified_at is not None
        assert qualified.qualification_report_json["passed"] is True
        assert qualified.qualification_report_json["permission_delta"] == 0
        assert [item.id for item in service.list_memories(retrievable_only=True)] == [draft.id]


def test_tampered_memory_fails_qualification_and_never_enters_retrieval() -> None:
    with build_session() as session:
        task, _ = add_concluded_task(session)
        service = build_service(session)
        draft = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="备份配置、修正参数并执行独立状态核验。",
            service_scope="sshd.service",
        )
        service.confirm(draft.id, actor="reviewer")

        draft.root_cause = "未经版本流程直接改写的错误根因。"
        session.flush()
        qualified = service.qualify(draft.id, actor="reviewer")

        assert qualified.qualification_status == "FAILED"
        integrity_case = next(
            item
            for item in qualified.qualification_report_json["cases"]
            if item["code"] == "CONTENT_INTEGRITY"
        )
        assert integrity_case["passed"] is False
        assert service.list_memories(retrievable_only=True) == []


def test_confirmation_quarantines_conflicting_memory_until_operator_resolves_it() -> None:
    with build_session() as session:
        first_task, _ = add_concluded_task(session)
        service = build_service(session)
        existing = service.create_draft_from_task(
            first_task.id,
            actor="admin",
            resolution="移除不兼容参数并完成语法核验。",
            service_scope="sshd.service",
        )
        service.confirm(existing.id, actor="admin")
        service.qualify(existing.id, actor="admin")

        second_task, _ = add_concluded_task(
            session,
            trace_id="trace-memory-conflict",
            user_input="排查 sshd 启动失败",
        )
        analysis = session.scalar(
            select(AIAnalysis)
            .where(AIAnalysis.task_id == second_task.id)
            .order_by(AIAnalysis.id.desc())
        )
        assert analysis is not None
        analysis.result_json = {
            "root_cause": "sshd 主机密钥文件权限不符合要求。",
            "conclusion": "主机密钥权限错误导致 sshd 启动失败。",
        }
        hypothesis = session.scalar(
            select(Hypothesis)
            .join(Investigation, Investigation.id == Hypothesis.investigation_id)
            .where(Investigation.task_id == second_task.id)
        )
        assert hypothesis is not None
        hypothesis.title = "sshd 主机密钥权限错误"
        hypothesis.rationale = "日志指向主机密钥权限错误。"
        session.flush()
        incoming = service.create_draft_from_task(
            second_task.id,
            actor="admin",
            resolution="按基线恢复主机密钥权限后重新验证服务。",
            service_scope="sshd.service",
        )

        reviewed = service.confirm(incoming.id, actor="reviewer")

        assert reviewed.status == "CONFLICTED"
        relation = session.scalar(
            select(OperationalMemoryRelation).where(
                OperationalMemoryRelation.source_memory_id == incoming.id,
                OperationalMemoryRelation.target_memory_id == existing.id,
            )
        )
        assert relation is not None
        assert relation.relation == "CONFLICTS"
        assert relation.status == "PENDING"
        assert [item.id for item in service.list_memories(retrievable_only=True)] == [existing.id]

        resolved = service.resolve_relation(
            relation.id,
            actor="senior-operator",
            decision="SUPERSEDE_EXISTING",
            reason="新任务证据更完整，旧经验不适用于当前配置。",
        )

        assert resolved.status == "RESOLVED"
        assert existing.status == "INACTIVE"
        assert incoming.status == "CONFIRMED"
        assert incoming.qualification_status == "PENDING"
        assert service.list_memories(retrievable_only=True) == []
        service.qualify(incoming.id, actor="senior-operator")
        assert [item.id for item in service.list_memories(retrievable_only=True)] == [incoming.id]


def test_confirmation_revalidates_evidence_binding() -> None:
    with build_session() as session:
        task, _ = add_concluded_task(session)
        service = build_service(session)
        draft = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="修复配置后完成语法核验。",
        )
        draft.evidence_refs_json = [{"evidence_item_id": 999, "source_ref": "forged"}]
        session.flush()

        try:
            service.confirm(draft.id, actor="admin")
        except ValueError as exc:
            assert "证据" in str(exc)
        else:
            raise AssertionError("forged evidence must block memory confirmation")


def test_confirmation_rejects_evidence_not_linked_to_supported_root_cause() -> None:
    with build_session() as session:
        task, _ = add_concluded_task(session)
        investigation = session.scalar(select(Investigation).where(Investigation.task_id == task.id))
        assert investigation is not None
        unrelated = EvidenceItem(
            investigation_id=investigation.id,
            source_ref="tool_call:77:observation:0",
            source_type="MCP",
            source_key="disk_usage",
            title="磁盘状态",
            summary="磁盘使用率正常，与 sshd 根因无关。",
            payload_json={},
            trust_level="observed",
        )
        session.add(unrelated)
        session.flush()
        service = build_service(session)
        draft = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="修复配置并完成语法核验后再重启服务。",
        )
        draft.evidence_refs_json = [
            {"evidence_item_id": unrelated.id, "source_ref": unrelated.source_ref}
        ]
        session.flush()

        try:
            service.confirm(draft.id, actor="admin")
        except ValueError as exc:
            assert "根因" in str(exc) or "证据" in str(exc)
        else:
            raise AssertionError("unlinked evidence must block memory confirmation")


def test_correction_creates_new_draft_version_and_replaces_confirmed_version() -> None:
    with build_session() as session:
        task, _ = add_concluded_task(session)
        service = build_service(session)
        first = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="删除错误参数并重启。",
        )
        service.confirm(first.id, actor="admin")
        service.qualify(first.id, actor="admin")

        corrected = service.correct(
            first.id,
            actor="senior-operator",
            root_cause="参数仅在旧版 OpenSSH 中有效，升级后不再支持。",
            resolution="先备份配置，移除旧参数，通过 sshd -t 后执行受控重启。",
            host_scope="linux-node-b",
            service_scope="*",
        )

        assert first.status == "CORRECTED"
        assert corrected.status == "DRAFT"
        assert corrected.version == 2
        assert corrected.memory_key == first.memory_key
        assert corrected.supersedes_id == first.id
        assert corrected.host_scope == "linux-node-b"
        assert corrected.service_scope == "*"
        assert service.list_memories(retrievable_only=True) == []

        service.confirm(corrected.id, actor="senior-operator")
        assert corrected.qualification_status == "PENDING"
        assert service.list_memories(retrievable_only=True) == []
        service.qualify(corrected.id, actor="senior-operator")
        assert [item.id for item in service.list_memories(retrievable_only=True)] == [corrected.id]


def test_deactivated_memory_leaves_retrieval_and_only_draft_can_be_deleted() -> None:
    with build_session() as session:
        task, _ = add_concluded_task(session)
        service = build_service(session)
        confirmed = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="修复配置并执行语法核验。",
        )
        service.confirm(confirmed.id, actor="admin")

        service.deactivate(confirmed.id, actor="admin")

        assert confirmed.status == "INACTIVE"
        assert service.list_memories(retrievable_only=True) == []
        try:
            service.delete(confirmed.id, actor="admin")
        except ValueError as exc:
            assert "精确遗忘" in str(exc)
        else:
            raise AssertionError("memory that participated in retrieval must keep an audit tombstone")
        service.forget(
            confirmed.id,
            actor="admin",
            reason="经验已经失效，按数据保留策略退出召回。",
        )
        assert confirmed.status == "FORGOTTEN"

        draft = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="先核对配置版本，再按变更流程执行语法校验。",
        )
        service.delete(draft.id, actor="admin")
        assert session.get(OperationalMemory, draft.id) is None


def test_feedback_is_persistent_and_incorrect_verdict_requires_correction() -> None:
    with build_session() as session:
        task, _ = add_concluded_task(session)
        service = build_service(session)

        try:
            service.record_feedback(task.id, actor="admin", verdict="INCORRECT")
        except ValueError as exc:
            assert "纠正" in str(exc)
        else:
            raise AssertionError("incorrect feedback without correction must be rejected")

        memory = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="先备份配置，完成语法核验后执行受控重启。",
        )
        service.confirm(memory.id, actor="admin")
        service.qualify(memory.id, actor="admin")
        feedback = service.record_feedback(
            task.id,
            actor="admin",
            verdict="INCORRECT",
            correction="根因应补充 OpenSSH 版本变化。",
            memory_id=memory.id,
        )

        assert feedback.task_id == task.id
        assert feedback.verdict == "INCORRECT"
        assert memory.incorrect_count == 1
        assert memory.status == "INACTIVE"
        assert session.scalar(select(OperatorFeedback).where(OperatorFeedback.id == feedback.id)) is feedback

        helpful_memory = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="依据当前版本文档修复配置并完成语法核验。",
        )
        service.confirm(helpful_memory.id, actor="admin")
        service.qualify(helpful_memory.id, actor="admin")
        helpful = service.record_feedback(
            task.id,
            actor="admin",
            verdict="HELPFUL",
            memory_id=helpful_memory.id,
        )
        listed = service.list_feedback(task.id)

        assert helpful_memory.helpful_count == 1
        assert [item.id for item in listed] == [helpful.id, feedback.id]
        try:
            service.list_feedback(999)
        except LookupError as exc:
            assert "task not found" in str(exc)
        else:
            raise AssertionError("feedback history for an unknown task must be rejected")


def test_confirmed_memory_search_respects_host_and_service_scope() -> None:
    with build_session() as session:
        task, _ = add_concluded_task(session)
        fake_hit = KnowledgeHit(
            chunk_id=1,
            document_id=1,
            title="sshd 配置参数无效",
            source_uri="memory://test/v1",
            trust_level="operator_confirmed",
            content="根因与处置经验",
            distance=0.12,
            retrieval=RetrievalProvenance(1, 1, 0.032, 0.96),
            source_kind="memory",
        )

        class FakeRetriever:
            calls: list[tuple[str, int]] = []

            def __init__(self, session, model_client, *, host_scope, service_scope):  # type: ignore[no-untyped-def]
                del session, model_client
                assert host_scope == "linux-node-a"
                assert service_scope == "sshd.service"

            def search(self, query: str, limit: int) -> list[KnowledgeHit]:
                self.calls.append((query, limit))
                return [fake_hit]

        service = OperationalMemoryService(
            session,
            model_client=FakeEmbeddingModel(),
            audit=AuditService(session),
            retriever_factory=FakeRetriever,
        )
        memory = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="先备份配置，完成语法核验后执行受控重启。",
            service_scope="sshd.service",
        )
        service.confirm(memory.id, actor="admin")
        memory.qualification_status = "QUALIFIED"
        session.flush()

        hits = service.search_confirmed(
            "sshd 为什么启动失败",
            host_scope="linux-node-a",
            service_scope="sshd.service",
            limit=2,
        )

        assert hits == [fake_hit]
        assert memory.retrieval_count == 1
        assert FakeRetriever.calls == [("sshd 为什么启动失败", 2)]
        assert service.search_confirmed(
            "sshd 为什么启动失败",
            host_scope="another-node",
            service_scope="sshd.service",
        ) == []


def test_expired_and_forgotten_memories_never_enter_retrieval() -> None:
    with build_session() as session:
        task, _ = add_concluded_task(session)
        fake_hit = KnowledgeHit(
            chunk_id=1,
            document_id=1,
            title="过期经验",
            source_uri="memory://expired/v1",
            trust_level="operator_confirmed",
            content="过期经验",
            distance=0.12,
            retrieval=RetrievalProvenance(1, 1, 0.032, 0.96),
            source_kind="memory",
        )

        class FakeRetriever:
            def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
                del args, kwargs

            def search(self, query: str, limit: int) -> list[KnowledgeHit]:
                del query, limit
                return [fake_hit]

        service = OperationalMemoryService(
            session,
            model_client=FakeEmbeddingModel(),
            audit=AuditService(session),
            retriever_factory=FakeRetriever,
        )
        memory = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="修复配置并完成语法核验。",
        )
        service.confirm(memory.id, actor="admin")
        memory.qualification_status = "QUALIFIED"
        memory.valid_until = memory.valid_from - timedelta(seconds=1)
        session.flush()

        assert service.search_confirmed("sshd 启动失败", host_scope="linux-node-a") == []

        memory.valid_until = None
        forgotten = service.forget(
            memory.id,
            actor="privacy-admin",
            reason="该主机已经退役，按数据保留策略移除经验。",
        )

        assert forgotten.status == "FORGOTTEN"
        assert forgotten.forgotten_by == "privacy-admin"
        assert forgotten.forgotten_at is not None
        assert session.get(OperationalMemory, memory.id) is memory
        assert service.search_confirmed("sshd 启动失败", host_scope="linux-node-a") == []


def test_failed_retrieval_probe_keeps_memory_out_of_production_retrieval() -> None:
    class EmptyRetriever:
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs

        def search(self, query: str, limit: int) -> list[KnowledgeHit]:
            del query, limit
            return []

    with build_session() as session:
        task, _ = add_concluded_task(session)
        service = build_service(session, retriever_factory=EmptyRetriever)
        memory = service.create_draft_from_task(
            task.id,
            actor="admin",
            resolution="先备份配置，完成语法核验后执行受控重启。",
            service_scope="sshd.service",
        )
        service.confirm(memory.id, actor="admin")

        reviewed = service.qualify(memory.id, actor="reviewer")

        assert reviewed.qualification_status == "FAILED"
        assert reviewed.qualified_at is None
        assert reviewed.qualification_report_json["passed"] is False
        top1 = next(
            case
            for case in reviewed.qualification_report_json["cases"]
            if case["code"] == "TOP1_RETRIEVAL"
        )
        assert top1["passed"] is False
        assert service.list_memories(retrievable_only=True) == []
