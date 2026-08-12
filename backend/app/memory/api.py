from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.ai.client import ModelCallError, ModelNotConfiguredError
from backend.app.core.database import get_session
from backend.app.core.pydantic_compat import BaseModel, Field
from backend.app.knowledge.retrieval import KnowledgeRetrievalUnavailableError
from backend.app.memory.evaluation import OperationalMemoryEvaluationService
from backend.app.memory.integrity import verify_memory_content
from backend.app.memory.service import OperationalMemoryService
from backend.app.models.entities import OperationalMemory, OperationalMemoryRelation, OperatorFeedback


class OperationalMemoryDraftRequest(BaseModel):
    actor: str = Field(default="local-admin", min_length=1, max_length=128)
    resolution: str = Field(min_length=10, max_length=4000)
    title: str | None = Field(default=None, max_length=256)
    host_scope: str | None = Field(default=None, max_length=256)
    service_scope: str = Field(default="*", min_length=1, max_length=256)


class OperationalMemoryActorRequest(BaseModel):
    actor: str = Field(default="local-admin", min_length=1, max_length=128)


class OperationalMemoryForgetRequest(OperationalMemoryActorRequest):
    reason: str = Field(min_length=10, max_length=1000)


class OperationalMemoryCorrectionRequest(OperationalMemoryActorRequest):
    root_cause: str = Field(min_length=1, max_length=4000)
    resolution: str = Field(min_length=10, max_length=4000)
    title: str | None = Field(default=None, max_length=256)
    host_scope: str | None = Field(default=None, max_length=256)
    service_scope: str | None = Field(default=None, max_length=256)


class OperatorFeedbackRequest(OperationalMemoryActorRequest):
    verdict: str = Field(min_length=1, max_length=16)
    correction: str | None = Field(default=None, max_length=4000)
    memory_id: int | None = Field(default=None, ge=1)


class OperationalMemoryRelationResolutionRequest(OperationalMemoryActorRequest):
    decision: str = Field(min_length=1, max_length=32)
    reason: str = Field(min_length=10, max_length=1000)


def get_operational_memory_service(
    session: Session = Depends(get_session),
) -> OperationalMemoryService:
    return OperationalMemoryService(session)


def get_operational_memory_evaluation_service(
    service: OperationalMemoryService = Depends(get_operational_memory_service),
) -> OperationalMemoryEvaluationService:
    return OperationalMemoryEvaluationService(service.session, service)


def build_operational_memory_router() -> APIRouter:
    router = APIRouter()

    @router.get("/operational-memories")
    def list_operational_memories(
        status: str | None = None,
        host_scope: str | None = None,
        service_scope: str | None = None,
        limit: int = 100,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> list[dict[str, Any]]:
        try:
            memories = service.list_memories(
                status=status,
                host_scope=host_scope,
                service_scope=service_scope,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return [operational_memory_to_response(memory) for memory in memories]

    @router.get("/operational-memories/search")
    def search_operational_memories(
        q: str,
        host_scope: str | None = None,
        service_scope: str | None = None,
        limit: int = 4,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> list[dict[str, Any]]:
        try:
            hits = service.search_confirmed(
                q,
                host_scope=host_scope,
                service_scope=service_scope,
                limit=limit,
            )
        except ModelNotConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ModelCallError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except KnowledgeRetrievalUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return [hit.to_dict() for hit in hits]

    @router.post("/operational-memories/evaluations")
    def run_operational_memory_evaluation(
        limit: int = 8,
        evaluation: OperationalMemoryEvaluationService = Depends(
            get_operational_memory_evaluation_service
        ),
    ) -> dict[str, Any]:
        return evaluation.run(limit=max(1, min(limit, 20)))

    @router.get("/operational-memories/evaluations/latest")
    def latest_operational_memory_evaluation(
        evaluation: OperationalMemoryEvaluationService = Depends(
            get_operational_memory_evaluation_service
        ),
    ) -> dict[str, Any] | None:
        return evaluation.latest()

    @router.get("/operational-memories/forget-candidates")
    def find_operational_memory_forget_candidates(
        q: str,
        host_scope: str | None = None,
        service_scope: str | None = None,
        limit: int = 10,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> list[dict[str, Any]]:
        try:
            hits = service.search_confirmed(
                q,
                host_scope=host_scope,
                service_scope=service_scope,
                limit=limit,
            )
        except ModelNotConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ModelCallError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except KnowledgeRetrievalUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return [hit.to_dict() for hit in hits]

    @router.post("/operational-memories/from-task/{task_id}")
    def create_operational_memory(
        task_id: int,
        payload: OperationalMemoryDraftRequest,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> dict[str, Any]:
        try:
            memory = service.create_draft_from_task(
                task_id,
                actor=payload.actor,
                resolution=payload.resolution,
                title=payload.title,
                host_scope=payload.host_scope,
                service_scope=payload.service_scope,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ModelNotConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ModelCallError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return operational_memory_to_response(memory)

    @router.post("/operational-memories/{memory_id}/confirm")
    def confirm_operational_memory(
        memory_id: int,
        payload: OperationalMemoryActorRequest,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> dict[str, Any]:
        try:
            memory = service.confirm(memory_id, actor=payload.actor)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return operational_memory_to_response(memory)

    @router.post("/operational-memories/{memory_id}/qualify")
    def qualify_operational_memory(
        memory_id: int,
        payload: OperationalMemoryActorRequest,
        service: OperationalMemoryService = Depends(
            get_operational_memory_service
        ),
    ) -> dict[str, Any]:
        try:
            memory = service.qualify(memory_id, actor=payload.actor)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return operational_memory_to_response(memory)

    @router.post("/operational-memories/{memory_id}/correct")
    def correct_operational_memory(
        memory_id: int,
        payload: OperationalMemoryCorrectionRequest,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> dict[str, Any]:
        try:
            memory = service.correct(
                memory_id,
                actor=payload.actor,
                root_cause=payload.root_cause,
                resolution=payload.resolution,
                title=payload.title,
                host_scope=payload.host_scope,
                service_scope=payload.service_scope,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ModelNotConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ModelCallError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return operational_memory_to_response(memory)

    @router.post("/operational-memories/{memory_id}/deactivate")
    def deactivate_operational_memory(
        memory_id: int,
        payload: OperationalMemoryActorRequest,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> dict[str, Any]:
        try:
            memory = service.deactivate(memory_id, actor=payload.actor)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return operational_memory_to_response(memory)

    @router.post("/operational-memories/{memory_id}/forget")
    def forget_operational_memory(
        memory_id: int,
        payload: OperationalMemoryForgetRequest,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> dict[str, Any]:
        try:
            memory = service.forget(
                memory_id,
                actor=payload.actor,
                reason=payload.reason,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return operational_memory_to_response(memory)

    @router.get("/operational-memories/{memory_id}/relations")
    def list_operational_memory_relations(
        memory_id: int,
        status: str | None = None,
        limit: int = 100,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> list[dict[str, Any]]:
        try:
            relations = service.list_relations(
                memory_id=memory_id,
                status=status,
                limit=limit,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return [operational_memory_relation_to_response(relation) for relation in relations]

    @router.post("/operational-memory-relations/{relation_id}/resolve")
    def resolve_operational_memory_relation(
        relation_id: int,
        payload: OperationalMemoryRelationResolutionRequest,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> dict[str, Any]:
        try:
            relation = service.resolve_relation(
                relation_id,
                actor=payload.actor,
                decision=payload.decision,
                reason=payload.reason,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return operational_memory_relation_to_response(relation)

    @router.delete("/operational-memories/{memory_id}")
    def delete_operational_memory(
        memory_id: int,
        payload: OperationalMemoryActorRequest,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> dict[str, Any]:
        try:
            service.delete(memory_id, actor=payload.actor)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"memory_id": memory_id, "deleted": True}

    @router.post("/tasks/{task_id}/feedback")
    def create_operator_feedback(
        task_id: int,
        payload: OperatorFeedbackRequest,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> dict[str, Any]:
        try:
            feedback = service.record_feedback(
                task_id,
                actor=payload.actor,
                verdict=payload.verdict,
                correction=payload.correction,
                memory_id=payload.memory_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return operator_feedback_to_response(feedback)

    @router.get("/tasks/{task_id}/feedback")
    def list_operator_feedback(
        task_id: int,
        limit: int = 20,
        service: OperationalMemoryService = Depends(get_operational_memory_service),
    ) -> list[dict[str, Any]]:
        try:
            feedback = service.list_feedback(task_id, limit=limit)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return [operator_feedback_to_response(item) for item in feedback]

    return router


def operational_memory_to_response(memory: OperationalMemory) -> dict[str, Any]:
    return {
        "id": memory.id,
        "memory_key": memory.memory_key,
        "version": memory.version,
        "status": memory.status,
        "memory_kind": getattr(memory, "memory_kind", "INCIDENT_CASE"),
        "source_task_id": memory.source_task_id,
        "supersedes_id": memory.supersedes_id,
        "host_scope": memory.host_scope,
        "service_scope": memory.service_scope,
        "symptom_fingerprint": getattr(memory, "symptom_fingerprint", ""),
        "applicability": getattr(memory, "applicability_json", {}),
        "confidence_score": getattr(memory, "confidence_score", 50),
        "title": memory.title,
        "root_cause": memory.root_cause,
        "resolution": memory.resolution,
        "evidence_refs": memory.evidence_refs_json,
        "content_hash": getattr(memory, "content_hash", ""),
        "parent_content_hash": getattr(memory, "parent_content_hash", None),
        "integrity_status": (
            "VERIFIED" if verify_memory_content(memory) else "FAILED"
        ),
        "created_by": memory.created_by,
        "confirmed_by": memory.confirmed_by,
        "retrieval_count": getattr(memory, "retrieval_count", 0),
        "helpful_count": getattr(memory, "helpful_count", 0),
        "incorrect_count": getattr(memory, "incorrect_count", 0),
        "qualification_status": getattr(
            memory,
            "qualification_status",
            "PENDING",
        ),
        "qualification_report": getattr(
            memory,
            "qualification_report_json",
            {},
        ),
        "qualified_at": (
            memory.qualified_at.isoformat()
            if getattr(memory, "qualified_at", None)
            else None
        ),
        "created_at": memory.created_at.isoformat(),
        "updated_at": memory.updated_at.isoformat(),
        "valid_from": memory.valid_from.isoformat() if getattr(memory, "valid_from", None) else None,
        "valid_until": memory.valid_until.isoformat() if getattr(memory, "valid_until", None) else None,
        "last_verified_at": (
            memory.last_verified_at.isoformat()
            if getattr(memory, "last_verified_at", None)
            else None
        ),
        "confirmed_at": memory.confirmed_at.isoformat() if memory.confirmed_at else None,
        "forgotten_at": (
            memory.forgotten_at.isoformat()
            if getattr(memory, "forgotten_at", None)
            else None
        ),
        "forgotten_by": getattr(memory, "forgotten_by", None),
        "forget_reason": getattr(memory, "forget_reason", None),
    }


def operational_memory_relation_to_response(
    relation: OperationalMemoryRelation,
) -> dict[str, Any]:
    return {
        "id": relation.id,
        "source_memory_id": relation.source_memory_id,
        "target_memory_id": relation.target_memory_id,
        "relation": relation.relation,
        "reason": relation.reason,
        "confidence_score": relation.confidence_score,
        "detected_by": relation.detected_by,
        "status": relation.status,
        "resolution": relation.resolution,
        "resolved_by": relation.resolved_by,
        "created_at": relation.created_at.isoformat(),
        "updated_at": relation.updated_at.isoformat(),
        "resolved_at": relation.resolved_at.isoformat() if relation.resolved_at else None,
    }


def operator_feedback_to_response(feedback: OperatorFeedback) -> dict[str, Any]:
    return {
        "id": feedback.id,
        "task_id": feedback.task_id,
        "memory_id": feedback.memory_id,
        "actor": feedback.actor,
        "verdict": feedback.verdict,
        "correction": feedback.correction,
        "created_at": feedback.created_at.isoformat(),
    }
