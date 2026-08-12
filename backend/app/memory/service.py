from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any, Callable

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.ai.client import BailianClient, model_invocation_scope
from backend.app.audit.service import AuditService
from backend.app.knowledge.retrieval import tokenize_for_search
from backend.app.knowledge.service import assert_knowledge_content_safe
from backend.app.memory.integrity import seal_memory_content, verify_memory_content
from backend.app.memory.retrieval import OperationalMemoryRetriever, confirmed_scope_filters
from backend.app.models.entities import (
    AIAnalysis,
    EvidenceItem,
    Hypothesis,
    HypothesisEvidence,
    Investigation,
    OperationalMemory,
    OperationalMemoryRelation,
    OperatorFeedback,
    SystemSnapshot,
    Task,
    utcnow,
)


class OperationalMemoryService:
    def __init__(
        self,
        session: Session,
        *,
        model_client: BailianClient | object | None = None,
        audit: AuditService | None = None,
        retriever_factory: Callable[..., Any] = OperationalMemoryRetriever,
    ) -> None:
        self.session = session
        self.model_client = model_client or BailianClient()
        self.audit = audit or AuditService(session)
        self.retriever_factory = retriever_factory

    def create_draft_from_task(
        self,
        task_id: int,
        *,
        actor: str,
        resolution: str,
        title: str | None = None,
        host_scope: str | None = None,
        service_scope: str = "*",
    ) -> OperationalMemory:
        actor = _required_text(actor, "操作者", 128)
        resolution = _required_text(resolution, "处置经验", 4000, minimum=10)
        task, investigation, hypothesis, analysis, evidence = self._source_context(task_id)
        memory_title = _required_text(title or hypothesis.title, "经验标题", 256)
        root_cause = _required_text(
            str((analysis.result_json or {}).get("root_cause") or hypothesis.rationale),
            "根因",
            4000,
        )
        resolved_host_scope = _scope(host_scope or self._task_hostname(task.id) or "*")
        resolved_service_scope = _scope(service_scope)
        symptom_tokens = _symptom_tokens(task.user_input)
        symptom_fingerprint = _symptom_fingerprint(symptom_tokens)
        memory_text = _memory_text(memory_title, root_cause, resolution)
        assert_knowledge_content_safe(memory_text)
        with model_invocation_scope(self.model_client, "memory_index_embedding"):
            embedding = self.model_client.embed([memory_text])[0]
        memory = OperationalMemory(
            memory_key=uuid.uuid4().hex,
            version=1,
            status="DRAFT",
            memory_kind="INCIDENT_CASE",
            source_task_id=task.id,
            supersedes_id=None,
            host_scope=resolved_host_scope,
            service_scope=resolved_service_scope,
            symptom_fingerprint=symptom_fingerprint,
            applicability_json={
                "intent": task.intent,
                "hypothesis_key": hypothesis.key,
                "symptom_tokens": symptom_tokens,
            },
            confidence_score=max(0, min(int(hypothesis.confidence_score or 0), 100)),
            title=memory_title,
            root_cause=root_cause,
            resolution=resolution,
            evidence_refs_json=[
                {
                    "evidence_item_id": item.id,
                    "source_ref": item.source_ref,
                    "source_type": item.source_type,
                }
                for item in evidence
            ],
            content_hash="0" * 64,
            parent_content_hash=None,
            search_text=tokenize_for_search(memory_text),
            embedding=embedding,
            created_by=actor,
            retrieval_count=0,
            helpful_count=0,
            incorrect_count=0,
            qualification_status="PENDING",
            qualification_report_json={},
            created_at=utcnow(),
            updated_at=utcnow(),
            valid_from=utcnow(),
            last_verified_at=task.sealed_at,
        )
        seal_memory_content(memory)
        self.session.add(memory)
        self.session.flush()
        self._audit(
            task,
            "memory_draft_created",
            "已从封存调查创建运维经验草稿。",
            memory,
            actor,
            {"investigation_id": investigation.id},
        )
        return memory

    def confirm(self, memory_id: int, *, actor: str) -> OperationalMemory:
        actor = _required_text(actor, "确认人", 128)
        memory = self._memory(memory_id)
        if memory.status != "DRAFT":
            raise ValueError("只有草稿状态的运维经验可以确认。")
        self._require_content_integrity(memory)
        task = self._validate_evidence_binding(memory)
        existing = self.session.scalar(
            select(OperationalMemory).where(
                OperationalMemory.memory_key == memory.memory_key,
                OperationalMemory.status == "CONFIRMED",
                OperationalMemory.id != memory.id,
            )
        )
        if existing is not None:
            raise ValueError("该运维经验已有确认版本。")
        blocking_relations = self._detect_material_relations(memory)
        if blocking_relations:
            memory.status = "CONFLICTED"
            memory.updated_at = utcnow()
            self.session.flush()
            self._audit(
                task,
                "memory_conflict_detected",
                "运维经验与现有经验存在待处理关系，已隔离出召回范围。",
                memory,
                actor,
                {
                    "relation_ids": [relation.id for relation in blocking_relations],
                    "relation_types": sorted({relation.relation for relation in blocking_relations}),
                },
            )
            return memory
        memory.status = "CONFIRMED"
        memory.confirmed_by = actor
        memory.confirmed_at = utcnow()
        memory.qualification_status = "PENDING"
        memory.qualification_report_json = {}
        memory.qualified_at = None
        memory.last_verified_at = memory.last_verified_at or task.sealed_at
        memory.updated_at = utcnow()
        self.session.flush()
        self._audit(
            task,
            "memory_confirmed",
            "运维经验已由人工确认，等待准入验证后参与调查。",
            memory,
            actor,
        )
        return memory

    def qualify(
        self,
        memory_id: int,
        *,
        actor: str,
    ) -> OperationalMemory:
        actor = _required_text(actor, "验证人", 128)
        memory = self._memory(memory_id)
        if memory.status != "CONFIRMED":
            raise ValueError("只有人工确认的运维经验可以执行准入验证。")

        cases: list[dict[str, Any]] = []
        task: Task | None = None
        content_integrity = verify_memory_content(memory)
        cases.append(
            _qualification_case(
                "CONTENT_INTEGRITY",
                content_integrity,
                "经验正文、适用范围和证据来源校验通过。"
                if content_integrity
                else "经验内容校验失败，疑似发生持久化污染或越过版本流程的修改。",
                {
                    "content_hash": memory.content_hash,
                    "parent_content_hash": memory.parent_content_hash,
                },
            )
        )
        try:
            task = self._validate_evidence_binding(memory)
            cases.append(_qualification_case("EVIDENCE_BOUND", True, "根因证据绑定有效。"))
        except (LookupError, ValueError) as exc:
            cases.append(_qualification_case("EVIDENCE_BOUND", False, str(exc)))

        pending_relation_count = int(
            self.session.scalar(
                select(OperationalMemoryRelation.id)
                .where(
                    OperationalMemoryRelation.status == "PENDING",
                    or_(
                        OperationalMemoryRelation.source_memory_id == memory.id,
                        OperationalMemoryRelation.target_memory_id == memory.id,
                    ),
                )
                .limit(1)
            )
            is not None
        )
        cases.append(
            _qualification_case(
                "CONFLICT_FREE",
                pending_relation_count == 0,
                "不存在待处理冲突。"
                if pending_relation_count == 0
                else "仍有待处理经验关系。",
            )
        )

        try:
            assert_knowledge_content_safe(
                _memory_text(memory.title, memory.root_cause, memory.resolution)
            )
            content_safe = True
            content_reason = "经验正文通过非可信内容检查。"
        except ValueError as exc:
            content_safe = False
            content_reason = str(exc)
        cases.append(
            _qualification_case(
                "CONTENT_SAFE",
                content_safe,
                content_reason,
            )
        )

        applicability = memory.applicability_json or {}
        forbidden_capability_keys = sorted(
            set(applicability)
            & {
                "arguments",
                "command",
                "permission",
                "risk_level",
                "shell",
                "tool_name",
            }
        )
        cases.append(
            _qualification_case(
                "ZERO_PERMISSION_DELTA",
                not forbidden_capability_keys,
                "经验只作为调查证据，不携带工具、参数或权限。"
                if not forbidden_capability_keys
                else f"经验包含能力字段：{', '.join(forbidden_capability_keys)}",
                {
                    "permission_delta": 0 if not forbidden_capability_keys else None,
                    "forbidden_keys": forbidden_capability_keys,
                },
            )
        )

        retrieval_prerequisites = all(item["passed"] for item in cases)
        if retrieval_prerequisites:
            query = _memory_text(
                memory.title,
                memory.root_cause,
                memory.resolution,
            )[:1000]
            host_scope = _query_scope(memory.host_scope)
            service_scope = _query_scope(memory.service_scope)
            original_qualification_status = memory.qualification_status
            try:
                # The candidate is visible only inside this uncommitted transaction while
                # the exact production retrieval path and its scope filters are probed.
                memory.qualification_status = "QUALIFIED"
                self.session.flush()
                try:
                    hits = self.search_confirmed(
                        query,
                        host_scope=host_scope,
                        service_scope=service_scope,
                        limit=3,
                        record_usage=False,
                    )
                    hit_ids = [int(hit.chunk_id) for hit in hits]
                    retrieval_passed = bool(hit_ids and hit_ids[0] == memory.id)
                    retrieval_reason = (
                        "目标经验在生产检索链路中位于 Top-1。"
                        if retrieval_passed
                        else "目标经验未通过生产检索 Top-1 校验。"
                    )
                except Exception as exc:
                    hit_ids = []
                    retrieval_passed = False
                    retrieval_reason = f"生产检索链路失败：{type(exc).__name__}"
                cases.append(
                    _qualification_case(
                        "TOP1_RETRIEVAL",
                        retrieval_passed,
                        retrieval_reason,
                        {"observed_memory_ids": hit_ids},
                    )
                )
                cases.extend(
                    self._qualification_scope_cases(
                        memory,
                        query=query,
                        host_scope=host_scope,
                        service_scope=service_scope,
                    )
                )
            finally:
                memory.qualification_status = original_qualification_status
                self.session.flush()
        else:
            cases.append(
                _qualification_case(
                    "TOP1_RETRIEVAL",
                    False,
                    "前置检查未通过，未放行生产检索。",
                    {"observed_memory_ids": []},
                )
            )

        passed = all(item["passed"] for item in cases)
        now = utcnow()
        memory.qualification_status = "QUALIFIED" if passed else "FAILED"
        memory.qualified_at = now if passed else None
        memory.last_verified_at = now if passed else memory.last_verified_at
        memory.updated_at = now
        report = {
            "contract_version": "memory-qualification.v1",
            "id": uuid.uuid4().hex,
            "memory_id": memory.id,
            "memory_version": memory.version,
            "passed": passed,
            "actor": actor,
            "completed_at": now.isoformat(),
            "permission_delta": 0,
            "cases": cases,
        }
        memory.qualification_report_json = report
        self.session.flush()
        audit_task = task or self.session.get(Task, memory.source_task_id)
        if audit_task is not None:
            self._audit(
                audit_task,
                "memory_qualification_passed"
                if passed
                else "memory_qualification_failed",
                "运维经验已通过准入验证并进入调查召回。"
                if passed
                else "运维经验未通过准入验证，继续隔离。",
                memory,
                actor,
                {
                    "qualification_id": report["id"],
                    "qualification_status": memory.qualification_status,
                    "case_count": len(cases),
                    "passed_count": sum(item["passed"] for item in cases),
                    "permission_delta": 0,
                },
            )
        return memory

    def correct(
        self,
        memory_id: int,
        *,
        actor: str,
        root_cause: str,
        resolution: str,
        title: str | None = None,
        host_scope: str | None = None,
        service_scope: str | None = None,
    ) -> OperationalMemory:
        actor = _required_text(actor, "纠正人", 128)
        current = self._memory(memory_id)
        if current.status != "CONFIRMED":
            raise ValueError("只有已确认的运维经验可以发起纠正。")
        self._require_content_integrity(current)
        root_cause = _required_text(root_cause, "根因", 4000)
        resolution = _required_text(resolution, "处置经验", 4000, minimum=10)
        corrected_title = _required_text(title or current.title, "经验标题", 256)
        corrected_host_scope = current.host_scope if host_scope is None else _scope(host_scope)
        corrected_service_scope = current.service_scope if service_scope is None else _scope(service_scope)
        memory_text = _memory_text(corrected_title, root_cause, resolution)
        assert_knowledge_content_safe(memory_text)
        with model_invocation_scope(self.model_client, "memory_index_embedding"):
            embedding = self.model_client.embed([memory_text])[0]
        current.status = "CORRECTED"
        current.updated_at = utcnow()
        corrected = OperationalMemory(
            memory_key=current.memory_key,
            version=current.version + 1,
            status="DRAFT",
            memory_kind=current.memory_kind,
            source_task_id=current.source_task_id,
            supersedes_id=current.id,
            host_scope=corrected_host_scope,
            service_scope=corrected_service_scope,
            symptom_fingerprint=current.symptom_fingerprint,
            applicability_json=dict(current.applicability_json or {}),
            confidence_score=current.confidence_score,
            title=corrected_title,
            root_cause=root_cause,
            resolution=resolution,
            evidence_refs_json=list(current.evidence_refs_json or []),
            content_hash="0" * 64,
            parent_content_hash=current.content_hash,
            search_text=tokenize_for_search(memory_text),
            embedding=embedding,
            created_by=actor,
            retrieval_count=0,
            helpful_count=0,
            incorrect_count=0,
            qualification_status="PENDING",
            qualification_report_json={},
            created_at=utcnow(),
            updated_at=utcnow(),
            valid_from=utcnow(),
            valid_until=current.valid_until,
            last_verified_at=current.last_verified_at,
        )
        seal_memory_content(corrected)
        self.session.add(corrected)
        self.session.flush()
        task = self.session.get(Task, current.source_task_id)
        assert task is not None
        self._audit(
            task,
            "memory_correction_drafted",
            "运维经验原版本已停止召回，并创建待确认的纠正版本。",
            corrected,
            actor,
            {"supersedes_id": current.id},
        )
        return corrected

    def deactivate(self, memory_id: int, *, actor: str) -> OperationalMemory:
        actor = _required_text(actor, "操作者", 128)
        memory = self._memory(memory_id)
        if memory.status != "CONFIRMED":
            raise ValueError("只有已确认的运维经验可以停用。")
        memory.status = "INACTIVE"
        memory.updated_at = utcnow()
        self.session.flush()
        task = self.session.get(Task, memory.source_task_id)
        assert task is not None
        self._audit(task, "memory_deactivated", "运维经验已停用并退出召回。", memory, actor)
        return memory

    def forget(self, memory_id: int, *, actor: str, reason: str) -> OperationalMemory:
        actor = _required_text(actor, "操作者", 128)
        reason = _required_text(reason, "遗忘原因", 1000, minimum=10)
        memory = self._memory(memory_id)
        if memory.status not in {"CONFIRMED", "CONFLICTED", "INACTIVE"}:
            raise ValueError("只有已确认、待解决冲突或已停用经验可以执行精确遗忘。")
        memory.status = "FORGOTTEN"
        memory.forgotten_at = utcnow()
        memory.forgotten_by = actor
        memory.forget_reason = reason
        memory.updated_at = utcnow()
        pending_relations = list(
            self.session.scalars(
                select(OperationalMemoryRelation).where(
                    OperationalMemoryRelation.status == "PENDING",
                    or_(
                        OperationalMemoryRelation.source_memory_id == memory.id,
                        OperationalMemoryRelation.target_memory_id == memory.id,
                    ),
                )
            )
        )
        for relation in pending_relations:
            relation.status = "DISMISSED"
            relation.resolution = f"关联经验已遗忘：{reason}"
            relation.resolved_by = actor
            relation.resolved_at = utcnow()
            relation.updated_at = utcnow()
        self.session.flush()
        task = self.session.get(Task, memory.source_task_id)
        assert task is not None
        self._audit(
            task,
            "memory_forgotten",
            "运维经验已按指定对象退出召回，并保留最小审计记录。",
            memory,
            actor,
            {"reason": reason},
        )
        return memory

    def list_relations(
        self,
        *,
        memory_id: int | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[OperationalMemoryRelation]:
        statement = select(OperationalMemoryRelation)
        if memory_id is not None:
            self._memory(memory_id)
            statement = statement.where(
                or_(
                    OperationalMemoryRelation.source_memory_id == memory_id,
                    OperationalMemoryRelation.target_memory_id == memory_id,
                )
            )
        if status:
            normalized_status = status.strip().upper()
            if normalized_status not in {"PENDING", "RESOLVED", "DISMISSED"}:
                raise ValueError("无效的经验关系状态。")
            statement = statement.where(OperationalMemoryRelation.status == normalized_status)
        return list(
            self.session.scalars(
                statement.order_by(
                    OperationalMemoryRelation.created_at.desc(),
                    OperationalMemoryRelation.id.desc(),
                ).limit(max(1, min(limit, 500)))
            )
        )

    def resolve_relation(
        self,
        relation_id: int,
        *,
        actor: str,
        decision: str,
        reason: str,
    ) -> OperationalMemoryRelation:
        actor = _required_text(actor, "处理人", 128)
        reason = _required_text(reason, "处理依据", 1000, minimum=10)
        normalized_decision = decision.strip().upper()
        if normalized_decision not in {"KEEP_EXISTING", "SUPERSEDE_EXISTING"}:
            raise ValueError("关系处理决定必须是 KEEP_EXISTING 或 SUPERSEDE_EXISTING。")
        relation = self.session.get(OperationalMemoryRelation, relation_id)
        if relation is None:
            raise LookupError("operational memory relation not found")
        if relation.status != "PENDING":
            raise ValueError("只有待处理的经验关系可以解决。")
        source = self._memory(relation.source_memory_id)
        target = self._memory(relation.target_memory_id)
        if source.status != "CONFLICTED" or target.status != "CONFIRMED":
            raise ValueError("经验状态已经变化，必须重新检查关系。")

        relation.status = "RESOLVED"
        relation.resolution = f"{normalized_decision}: {reason}"
        relation.resolved_by = actor
        relation.resolved_at = utcnow()
        relation.updated_at = utcnow()
        if normalized_decision == "KEEP_EXISTING":
            source.status = "INACTIVE"
            self._dismiss_other_pending_relations(source.id, relation.id, actor, reason)
        else:
            target.status = "INACTIVE"
            target.updated_at = utcnow()
            pending_count = len(
                list(
                    self.session.scalars(
                        select(OperationalMemoryRelation.id).where(
                            OperationalMemoryRelation.source_memory_id == source.id,
                            OperationalMemoryRelation.status == "PENDING",
                            OperationalMemoryRelation.id != relation.id,
                        )
                    )
                )
            )
            if pending_count == 0:
                source.status = "CONFIRMED"
                source.confirmed_by = actor
                source.confirmed_at = utcnow()
                source.qualification_status = "PENDING"
                source.qualification_report_json = {}
                source.qualified_at = None
        source.updated_at = utcnow()
        self.session.flush()
        task = self.session.get(Task, source.source_task_id)
        assert task is not None
        self._audit(
            task,
            "memory_relation_resolved",
            "运维经验关系已由人工处理。",
            source,
            actor,
            {
                "relation_id": relation.id,
                "decision": normalized_decision,
                "target_memory_id": target.id,
                "reason": reason,
            },
        )
        return relation

    def delete(self, memory_id: int, *, actor: str) -> None:
        actor = _required_text(actor, "操作者", 128)
        memory = self._memory(memory_id)
        if memory.status != "DRAFT":
            raise ValueError("只有从未参与召回的草稿可以物理删除；其他经验请执行精确遗忘。")
        task = self.session.get(Task, memory.source_task_id)
        assert task is not None
        self._audit(
            task,
            "memory_deleted",
            "运维经验已按状态约束删除。",
            memory,
            actor,
        )
        self.session.delete(memory)
        self.session.flush()

    def list_memories(
        self,
        *,
        retrievable_only: bool = False,
        status: str | None = None,
        host_scope: str | None = None,
        service_scope: str | None = None,
        limit: int = 100,
    ) -> list[OperationalMemory]:
        statement = select(OperationalMemory)
        if retrievable_only:
            statement = statement.where(
                OperationalMemory.status == "CONFIRMED",
                OperationalMemory.qualification_status == "QUALIFIED",
            )
        elif status:
            normalized_status = status.strip().upper()
            if normalized_status not in {
                "DRAFT",
                "CONFLICTED",
                "CONFIRMED",
                "CORRECTED",
                "INACTIVE",
                "FORGOTTEN",
            }:
                raise ValueError("无效的运维经验状态。")
            statement = statement.where(OperationalMemory.status == normalized_status)
        if host_scope:
            statement = statement.where(OperationalMemory.host_scope == _scope(host_scope))
        if service_scope:
            statement = statement.where(OperationalMemory.service_scope == _scope(service_scope))
        memories = list(
            self.session.scalars(
                statement.order_by(OperationalMemory.updated_at.desc(), OperationalMemory.id.desc()).limit(
                    max(1, min(limit, 500))
                )
            )
        )
        if retrievable_only:
            return [memory for memory in memories if verify_memory_content(memory)]
        return memories

    def search_confirmed(
        self,
        query: str,
        *,
        host_scope: str | None = None,
        service_scope: str | None = None,
        limit: int = 4,
        record_usage: bool = True,
    ) -> list:
        normalized_query = re.sub(r"\s+", " ", query.strip())
        if not normalized_query:
            return []
        exists = self.session.scalar(
            select(OperationalMemory.id)
            .where(*confirmed_scope_filters(host_scope, service_scope))
            .limit(1)
        )
        if exists is None:
            return []
        retriever = self.retriever_factory(
            self.session,
            self.model_client,
            host_scope=host_scope,
            service_scope=service_scope,
        )
        hits = retriever.search(normalized_query, limit=max(1, min(limit, 10)))
        if not hits:
            return []
        memories = {
            item.id: item
            for item in self.session.scalars(
                select(OperationalMemory).where(
                    OperationalMemory.id.in_([int(hit.chunk_id) for hit in hits]),
                    *confirmed_scope_filters(host_scope, service_scope),
                )
            )
        }
        eligible_hits = [hit for hit in hits if int(hit.chunk_id) in memories]
        eligible_hits.sort(
            key=lambda hit: (
                -_effective_memory_score(hit, memories[int(hit.chunk_id)]),
                int(hit.chunk_id),
            )
        )
        if record_usage:
            for hit in eligible_hits:
                memories[int(hit.chunk_id)].retrieval_count += 1
        self.session.flush()
        return eligible_hits

    def record_feedback(
        self,
        task_id: int,
        *,
        actor: str,
        verdict: str,
        correction: str | None = None,
        memory_id: int | None = None,
    ) -> OperatorFeedback:
        actor = _required_text(actor, "操作者", 128)
        normalized_verdict = verdict.strip().upper()
        if normalized_verdict not in {"HELPFUL", "INCOMPLETE", "INCORRECT"}:
            raise ValueError("反馈结论必须是 HELPFUL、INCOMPLETE 或 INCORRECT。")
        normalized_correction = re.sub(r"\s+", " ", (correction or "").strip()) or None
        if normalized_verdict == "INCORRECT" and not normalized_correction:
            raise ValueError("标记为不正确时必须填写纠正说明。")
        task = self.session.get(Task, task_id)
        if task is None:
            raise LookupError("task not found")
        memory = None
        if memory_id is not None:
            memory = self.session.get(OperationalMemory, memory_id)
            if memory is None:
                raise LookupError("operational memory not found")
            if memory.status != "CONFIRMED":
                raise ValueError("只有本次调查实际使用的已确认经验可以记录效果反馈。")
            if memory.qualification_status != "QUALIFIED":
                raise ValueError("只有通过准入验证并被调查使用的经验可以记录效果反馈。")
            self._require_content_integrity(memory)
        feedback = OperatorFeedback(
            task_id=task.id,
            memory_id=memory_id,
            actor=actor,
            verdict=normalized_verdict,
            correction=normalized_correction,
        )
        self.session.add(feedback)
        if memory is not None:
            if normalized_verdict == "HELPFUL":
                memory.helpful_count += 1
            elif normalized_verdict == "INCORRECT":
                memory.incorrect_count += 1
                memory.status = "INACTIVE"
            memory.updated_at = utcnow()
        self.session.flush()
        self.audit.append_event(
            task,
            "LEARN",
            "operator_feedback_recorded",
            "运维人员已记录本次调查反馈。",
            {
                "feedback_id": feedback.id,
                "memory_id": memory_id,
                "verdict": normalized_verdict,
                "actor": actor,
            },
        )
        return feedback

    def _qualification_scope_cases(
        self,
        memory: OperationalMemory,
        *,
        query: str,
        host_scope: str | None,
        service_scope: str | None,
    ) -> list[dict[str, Any]]:
        cases: list[dict[str, Any]] = []
        if host_scope is not None:
            wrong_host = f"__memory_qualification_host_{memory.id}__"
            try:
                hit_ids = [
                    int(hit.chunk_id)
                    for hit in self.search_confirmed(
                        query,
                        host_scope=wrong_host,
                        service_scope=service_scope,
                        limit=3,
                        record_usage=False,
                    )
                ]
                passed = memory.id not in hit_ids
                reason = (
                    "主机作用域隔离有效。"
                    if passed
                    else "经验越过主机作用域边界。"
                )
            except Exception as exc:
                hit_ids = []
                passed = False
                reason = f"主机作用域复验失败：{type(exc).__name__}"
            cases.append(
                _qualification_case(
                    "HOST_SCOPE_ISOLATED",
                    passed,
                    reason,
                    {"observed_memory_ids": hit_ids},
                )
            )
        if service_scope is not None:
            wrong_service = (
                f"__memory_qualification_service_{memory.id}__.service"
            )
            try:
                hit_ids = [
                    int(hit.chunk_id)
                    for hit in self.search_confirmed(
                        query,
                        host_scope=host_scope,
                        service_scope=wrong_service,
                        limit=3,
                        record_usage=False,
                    )
                ]
                passed = memory.id not in hit_ids
                reason = (
                    "服务作用域隔离有效。"
                    if passed
                    else "经验越过服务作用域边界。"
                )
            except Exception as exc:
                hit_ids = []
                passed = False
                reason = f"服务作用域复验失败：{type(exc).__name__}"
            cases.append(
                _qualification_case(
                    "SERVICE_SCOPE_ISOLATED",
                    passed,
                    reason,
                    {"observed_memory_ids": hit_ids},
                )
            )
        return cases

    def _detect_material_relations(
        self,
        memory: OperationalMemory,
    ) -> list[OperationalMemoryRelation]:
        candidates = list(
            self.session.scalars(
                select(OperationalMemory).where(
                    OperationalMemory.id != memory.id,
                    OperationalMemory.status == "CONFIRMED",
                    OperationalMemory.memory_kind == memory.memory_kind,
                    _scope_overlap_filter(OperationalMemory.host_scope, memory.host_scope),
                    _scope_overlap_filter(OperationalMemory.service_scope, memory.service_scope),
                )
            )
        )
        blocking: list[OperationalMemoryRelation] = []
        for candidate in candidates:
            if not verify_memory_content(candidate):
                continue
            symptom_similarity = _symptom_similarity(memory, candidate)
            if symptom_similarity < 0.5:
                continue
            existing = self.session.scalar(
                select(OperationalMemoryRelation).where(
                    OperationalMemoryRelation.source_memory_id == memory.id,
                    OperationalMemoryRelation.target_memory_id == candidate.id,
                    OperationalMemoryRelation.relation.in_(
                        ["SUPPORTS", "DUPLICATES", "CONFLICTS"]
                    ),
                )
            )
            if existing is not None:
                if existing.status == "PENDING":
                    blocking.append(existing)
                continue
            root_similarity = _text_similarity(memory.root_cause, candidate.root_cause)
            resolution_similarity = _text_similarity(memory.resolution, candidate.resolution)
            if root_similarity >= 0.85 and resolution_similarity >= 0.85:
                relation_type = "DUPLICATES"
                status = "PENDING"
                reason = "相同作用域内的症状、根因和处置高度重合，需要避免重复经验。"
            elif root_similarity >= 0.85:
                relation_type = "SUPPORTS"
                status = "RESOLVED"
                reason = "相同作用域内的独立案例支持同一根因，并保留不同处置细节。"
            else:
                relation_type = "CONFLICTS"
                status = "PENDING"
                reason = "相同作用域内的症状相近，但根因结论不同，需要人工核对适用条件。"
            relation = OperationalMemoryRelation(
                source_memory_id=memory.id,
                target_memory_id=candidate.id,
                relation=relation_type,
                reason=reason,
                confidence_score=max(0, min(round(symptom_similarity * 100), 100)),
                detected_by="governance_policy",
                status=status,
                resolution="自动确认同根因支持关系。" if status == "RESOLVED" else None,
                resolved_by="system" if status == "RESOLVED" else None,
                resolved_at=utcnow() if status == "RESOLVED" else None,
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            self.session.add(relation)
            self.session.flush()
            if status == "PENDING":
                blocking.append(relation)
        return blocking

    def _dismiss_other_pending_relations(
        self,
        source_memory_id: int,
        resolved_relation_id: int,
        actor: str,
        reason: str,
    ) -> None:
        relations = list(
            self.session.scalars(
                select(OperationalMemoryRelation).where(
                    OperationalMemoryRelation.source_memory_id == source_memory_id,
                    OperationalMemoryRelation.status == "PENDING",
                    OperationalMemoryRelation.id != resolved_relation_id,
                )
            )
        )
        for relation in relations:
            relation.status = "DISMISSED"
            relation.resolution = f"来源经验未启用：{reason}"
            relation.resolved_by = actor
            relation.resolved_at = utcnow()
            relation.updated_at = utcnow()

    def list_feedback(self, task_id: int, *, limit: int = 20) -> list[OperatorFeedback]:
        if self.session.get(Task, task_id) is None:
            raise LookupError("task not found")
        return list(
            self.session.scalars(
                select(OperatorFeedback)
                .where(OperatorFeedback.task_id == task_id)
                .order_by(OperatorFeedback.created_at.desc(), OperatorFeedback.id.desc())
                .limit(max(1, min(limit, 100)))
            )
        )

    def _source_context(
        self,
        task_id: int,
    ) -> tuple[Task, Investigation, Hypothesis, AIAnalysis, list[EvidenceItem]]:
        task = self.session.get(Task, task_id)
        if task is None:
            raise LookupError("task not found")
        if task.status != "SEALED":
            raise ValueError("只有已封存任务可以沉淀运维经验。")
        investigation = self.session.scalar(
            select(Investigation).where(
                Investigation.task_id == task.id,
                Investigation.status == "CONCLUDED",
            )
        )
        if investigation is None:
            raise ValueError("任务没有已闭环的根因调查。")
        hypothesis = self.session.scalar(
            select(Hypothesis)
            .where(
                Hypothesis.investigation_id == investigation.id,
                Hypothesis.status == "SUPPORTED",
            )
            .order_by(Hypothesis.confidence_score.desc(), Hypothesis.id.asc())
            .limit(1)
        )
        if hypothesis is None:
            raise ValueError("任务没有经过证据支持的根因。")
        analysis = self.session.scalar(
            select(AIAnalysis)
            .where(AIAnalysis.task_id == task.id, AIAnalysis.status == "ok")
            .order_by(AIAnalysis.id.desc())
            .limit(1)
        )
        if analysis is None:
            raise ValueError("任务没有可核验的研判结论。")
        evidence = list(
            self.session.scalars(
                select(EvidenceItem)
                .join(HypothesisEvidence, HypothesisEvidence.evidence_item_id == EvidenceItem.id)
                .where(
                    HypothesisEvidence.hypothesis_id == hypothesis.id,
                    HypothesisEvidence.relation == "SUPPORTS",
                    EvidenceItem.investigation_id == investigation.id,
                )
                .order_by(EvidenceItem.id.asc())
            )
        )
        if not evidence:
            raise ValueError("根因没有绑定可追溯证据。")
        return task, investigation, hypothesis, analysis, evidence

    def _validate_evidence_binding(self, memory: OperationalMemory) -> Task:
        task, _, _, _, supported_evidence = self._source_context(memory.source_task_id)
        stored_ids = {
            int(item.get("evidence_item_id"))
            for item in (memory.evidence_refs_json or [])
            if isinstance(item, dict) and item.get("evidence_item_id") is not None
        }
        if not stored_ids:
            raise ValueError("运维经验没有绑定证据。")
        supported_ids = {item.id for item in supported_evidence}
        if stored_ids != supported_ids:
            raise ValueError("运维经验证据必须与受支持根因的证据集合完全一致。")
        return task

    def _task_hostname(self, task_id: int) -> str | None:
        snapshot = self.session.scalar(
            select(SystemSnapshot)
            .where(SystemSnapshot.task_id == task_id)
            .order_by(SystemSnapshot.id.desc())
            .limit(1)
        )
        if snapshot is None:
            return None
        observations = (snapshot.payload_json or {}).get("observations")
        if not isinstance(observations, list) or not observations:
            return None
        hostname = observations[0].get("hostname") if isinstance(observations[0], dict) else None
        return str(hostname).strip() if hostname else None

    def _memory(self, memory_id: int) -> OperationalMemory:
        memory = self.session.get(OperationalMemory, memory_id)
        if memory is None:
            raise LookupError("operational memory not found")
        return memory

    @staticmethod
    def _require_content_integrity(memory: OperationalMemory) -> None:
        if not verify_memory_content(memory):
            raise ValueError(
                "运维经验正文、适用范围或证据来源校验失败，"
                "已拒绝确认、修订或参与调查。"
            )

    def _audit(
        self,
        task: Task,
        event_type: str,
        message: str,
        memory: OperationalMemory,
        actor: str,
        extra: dict | None = None,
    ) -> None:
        self.audit.append_event(
            task,
            "LEARN",
            event_type,
            message,
            {
                "memory_id": memory.id,
                "memory_key": memory.memory_key,
                "version": memory.version,
                "status": memory.status,
                "actor": actor,
                **(extra or {}),
            },
        )


def _memory_text(title: str, root_cause: str, resolution: str) -> str:
    return f"标题：{title}\n根因：{root_cause}\n处置：{resolution}"


def _required_text(value: str, label: str, limit: int, *, minimum: int = 1) -> str:
    normalized = re.sub(r"\s+", " ", str(value or "").strip())
    if len(normalized) < minimum:
        raise ValueError(f"{label}至少需要 {minimum} 个字符。")
    if len(normalized) > limit:
        raise ValueError(f"{label}超过长度限制。")
    return normalized


def _scope(value: str) -> str:
    normalized = re.sub(r"\s+", " ", str(value or "").strip()) or "*"
    if len(normalized) > 256:
        raise ValueError("经验作用域超过长度限制。")
    return normalized


def _query_scope(value: str) -> str | None:
    normalized = str(value or "").strip()
    return None if not normalized or normalized == "*" else normalized


def _qualification_case(
    code: str,
    passed: bool,
    reason: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "passed": passed,
        "reason": reason,
        "details": details or {},
    }


def _scope_overlap_filter(column: Any, requested_scope: str) -> Any:
    if requested_scope == "*":
        return column.is_not(None)
    return or_(column == "*", column == requested_scope)


def _symptom_tokens(value: str) -> list[str]:
    ignored = {
        "一下",
        "分析",
        "帮",
        "帮我",
        "当前",
        "检查",
        "排查",
        "看",
        "看看",
        "系统",
    }
    return sorted(
        {
            token
            for token in tokenize_for_search(value).split()
            if token and token not in ignored
        }
    )


def _symptom_fingerprint(tokens: list[str]) -> str:
    normalized = "|".join(tokens)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _symptom_similarity(left: OperationalMemory, right: OperationalMemory) -> float:
    if (
        left.symptom_fingerprint
        and right.symptom_fingerprint
        and left.symptom_fingerprint == right.symptom_fingerprint
    ):
        return 1.0
    left_tokens = set((left.applicability_json or {}).get("symptom_tokens") or [])
    right_tokens = set((right.applicability_json or {}).get("symptom_tokens") or [])
    if not left_tokens:
        left_tokens = set(_symptom_tokens(left.title))
    if not right_tokens:
        right_tokens = set(_symptom_tokens(right.title))
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def _text_similarity(left: str, right: str) -> float:
    left_tokens = set(tokenize_for_search(left).split())
    right_tokens = set(tokenize_for_search(right).split())
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def _effective_memory_score(hit: Any, memory: OperationalMemory) -> float:
    rerank_score = float(getattr(getattr(hit, "retrieval", None), "rerank_score", 0.0) or 0.0)
    confidence = max(0, min(int(memory.confidence_score or 0), 100)) / 100.0
    helpful_bonus = min(int(memory.helpful_count or 0), 10) * 0.005
    incorrect_penalty = min(int(memory.incorrect_count or 0), 10) * 0.05
    return rerank_score + confidence * 0.02 + helpful_bonus - incorrect_penalty
