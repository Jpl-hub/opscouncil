from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from backend.app.core.pydantic_compat import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.agent.evaluation import AgentEvaluationService
from backend.app.agent.conversation import ConversationService
from backend.app.ai.client import BailianClient, ModelCallError, ModelNotConfiguredError
from backend.app.ai.observability import build_task_observability
from backend.app.agent.runner import AgentRunner, get_task
from backend.app.agent.skills import list_agent_skills
from backend.app.assets.api import build_service_catalog_router
from backend.app.api.task_contracts import ApprovalQueueItemResponse, TaskResponse, task_to_response
from backend.app.api.task_runtime import build_task_runtime_router
from backend.app.audit.replay import build_audit_replay
from backend.app.audit.service import AuditService
from backend.app.benchmark.service import BenchmarkService
from backend.app.config_baseline.service import ConfigBaselineService, LAB_SCOPE, LIVE_SCOPE
from backend.app.collaboration.api import build_collaboration_router
from backend.app.channels.feishu.api import build_feishu_router
from backend.app.core.database import SessionLocal, get_session
from backend.app.deployment.readiness import DeploymentReadinessService
from backend.app.diagnostics.api import build_diagnostic_router
from backend.app.executor.runtime import runtime_safety_report
from backend.app.investigation.service import build_investigation_package
from backend.app.knowledge.service import (
    KnowledgeIngestionRejectedError,
    KnowledgeService,
)
from backend.app.knowledge.retrieval import KnowledgeRetrievalUnavailableError
from backend.app.knowledge.extraction import KnowledgeFileRejectedError, extract_knowledge_file
from backend.app.knowledge.qa import KnowledgeQAService
from backend.app.memory.api import build_operational_memory_router
from backend.app.operators.api import build_operator_preference_router
from backend.app.lab.evaluation import LabEvaluationService
from backend.app.lab.service import LabService
from backend.app.mcp.registry import ToolRegistry
from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    AuditChain,
    ConfigBaseline,
    ConfigBaselineCheck,
    ExecutionRecord,
    KnowledgeChunk,
    KnowledgeDocument,
    SafetyReview,
    Task,
    TaskEvent,
    ToolCall,
)
from backend.app.posture.service import LivePostureService
from backend.app.patrol.api import build_patrol_router
from backend.app.runtime.health import worker_runtime_status
from backend.app.safety.evaluation import SafetyEvaluationService
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.policy_replay import SafetyPolicyReplayService


class ProposalApprovalRequest(BaseModel):
    operator: str = Field(default="local-admin", min_length=1, max_length=128)
    comment: str | None = Field(default=None, max_length=1000)


class KnowledgeDocumentCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    source_type: str = Field(default="manual", min_length=1, max_length=64)
    source_uri: str = Field(default="manual://operator-note", min_length=1, max_length=1000)
    trust_level: str = Field(default="internal", min_length=1, max_length=32)
    content: str = Field(min_length=20, max_length=100_000)


class KnowledgeAnswerRequest(BaseModel):
    query: str = Field(min_length=2, max_length=1000)
    limit: int = Field(default=5, ge=1, le=8)


class LabActivateRequest(BaseModel):
    size_mb: int | None = Field(default=None, ge=1, le=128)


class BenchmarkRunRequest(BaseModel):
    rounds: int = Field(default=2, ge=1, le=5)


class ConfigBaselineCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    paths: list[str] = Field()
    created_by: str = Field(default="local-admin", min_length=1, max_length=128)

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, value: list[str]) -> list[str]:
        if not 1 <= len(value) <= 20:
            raise ValueError("paths must contain 1 to 20 items")
        return value


def knowledge_document_to_response(document: KnowledgeDocument, chunk_count: int = 0) -> dict[str, Any]:
    return {
        "id": document.id,
        "title": document.title,
        "source_type": document.source_type,
        "source_uri": document.source_uri,
        "trust_level": document.trust_level,
        "version": document.version,
        "status": document.status,
        "chunk_count": chunk_count,
        "created_at": document.created_at.isoformat(),
    }


def knowledge_index_status_response(session: Session) -> dict[str, Any]:
    return KnowledgeService(session).index_status()


def config_baseline_check_to_response(check: ConfigBaselineCheck) -> dict[str, Any]:
    return {
        "id": check.id,
        "baseline_id": check.baseline_id,
        "status": check.status,
        "summary": check.summary_json,
        "changes": check.changes_json,
        "warnings": check.warnings_json,
        "created_at": check.created_at.isoformat(),
    }


def config_baseline_to_response(
    baseline: ConfigBaseline,
    latest_check: ConfigBaselineCheck | None = None,
) -> dict[str, Any]:
    return {
        "id": baseline.id,
        "name": baseline.name,
        "paths": baseline.paths_json,
        "file_count": len(baseline.snapshot_json),
        "warnings": baseline.warnings_json,
        "created_by": baseline.created_by,
        "created_at": baseline.created_at.isoformat(),
        "latest_check": (
            config_baseline_check_to_response(latest_check)
            if latest_check is not None
            else None
        ),
    }


def build_router(
    registry: ToolRegistry,
    *,
    session_factory: sessionmaker[Session] = SessionLocal,
) -> APIRouter:
    router = APIRouter(prefix="/api")
    router.include_router(build_task_runtime_router())
    router.include_router(build_patrol_router(registry, session_factory))
    router.include_router(build_operational_memory_router())
    router.include_router(build_operator_preference_router())
    router.include_router(build_feishu_router(session_factory=session_factory, api_prefix=""))
    router.include_router(build_diagnostic_router())
    router.include_router(build_service_catalog_router())
    router.include_router(build_collaboration_router())

    @router.get("/tasks", response_model=list[TaskResponse])
    def list_tasks(session: Session = Depends(get_session), limit: int = 20) -> list[TaskResponse]:
        tasks = session.execute(
            select(Task).order_by(Task.id.desc()).limit(min(max(limit, 1), 100))
        ).scalars()
        return [task_to_response(task, session) for task in tasks]

    @router.get("/tasks/{task_id}", response_model=TaskResponse)
    def read_task(task_id: int, session: Session = Depends(get_session)) -> TaskResponse:
        task = get_task(session, task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")
        return task_to_response(task, session)

    @router.get("/conversations/{conversation_id}/tasks", response_model=list[TaskResponse])
    def list_conversation_tasks(
        conversation_id: str,
        session: Session = Depends(get_session),
    ) -> list[TaskResponse]:
        try:
            tasks = ConversationService(session).list_tasks(conversation_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return [task_to_response(task, session) for task in tasks]

    @router.get("/tasks/{task_id}/investigation")
    def read_task_investigation(task_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
        try:
            return build_investigation_package(session, task_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/tasks/{task_id}/observability")
    def read_task_observability(
        task_id: int,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            return build_task_observability(session, task_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/tasks/{task_id}/events")
    def read_task_events(task_id: int, session: Session = Depends(get_session)) -> list[dict[str, Any]]:
        if get_task(session, task_id) is None:
            raise HTTPException(status_code=404, detail="task not found")
        events = session.execute(
            select(TaskEvent).where(TaskEvent.task_id == task_id).order_by(TaskEvent.id.asc())
        ).scalars()
        return [
            {
                "id": event.id,
                "stage": event.stage,
                "event_type": event.event_type,
                "message": event.message,
                "payload": event.payload_json,
                "created_at": event.created_at.isoformat(),
            }
            for event in events
        ]

    @router.get("/tasks/{task_id}/tool-calls")
    def read_tool_calls(task_id: int, session: Session = Depends(get_session)) -> list[dict[str, Any]]:
        if get_task(session, task_id) is None:
            raise HTTPException(status_code=404, detail="task not found")
        calls = session.execute(
            select(ToolCall).where(ToolCall.task_id == task_id).order_by(ToolCall.id.asc())
        ).scalars()
        return [
            {
                "id": call.id,
                "tool_name": call.tool_name,
                "tool_version": call.tool_version,
                "input": call.input_json,
                "output": call.output_json,
                "risk_level": call.risk_level,
                "status": call.status,
                "duration_ms": call.duration_ms,
            }
            for call in calls
        ]

    @router.get("/tasks/{task_id}/proposals")
    def read_action_proposals(task_id: int, session: Session = Depends(get_session)) -> list[dict[str, Any]]:
        if get_task(session, task_id) is None:
            raise HTTPException(status_code=404, detail="task not found")
        proposals = session.execute(
            select(ActionProposal)
            .where(ActionProposal.task_id == task_id)
            .order_by(ActionProposal.id.asc())
        ).scalars()
        return [
            {
                "id": proposal.id,
                "tool_name": proposal.tool_name,
                "input": proposal.input_json,
                "risk_level": proposal.risk_level,
                "reason": proposal.reason,
                "status": proposal.status,
                "dry_run_result": proposal.dry_run_result_json,
                "created_at": proposal.created_at.isoformat(),
            }
            for proposal in proposals
        ]

    @router.get("/proposals", response_model=list[ApprovalQueueItemResponse])
    def list_action_proposals(
        status_filter: str = "PENDING_APPROVAL",
        limit: int = 100,
        session: Session = Depends(get_session),
    ) -> list[ApprovalQueueItemResponse]:
        allowed_statuses = {
            "PENDING_APPROVAL",
            "EXECUTED",
            "REJECTED",
            "FAILED",
            "NEEDS_OPERATOR",
            "ROLLED_BACK",
        }
        normalized_status = status_filter.strip().upper()
        if normalized_status not in allowed_statuses:
            raise HTTPException(status_code=422, detail="unsupported proposal status")
        statement = (
            select(ActionProposal, Task)
            .join(Task, Task.id == ActionProposal.task_id)
            .where(ActionProposal.status == normalized_status)
        )
        if normalized_status == "PENDING_APPROVAL":
            statement = statement.join(
                ActionSafetyCase,
                ActionSafetyCase.proposal_id == ActionProposal.id,
            ).where(ActionSafetyCase.status == "READY")
        rows = session.execute(
            statement
            .order_by(ActionProposal.created_at.desc(), ActionProposal.id.desc())
            .limit(min(max(limit, 1), 200))
        ).all()
        return [
            ApprovalQueueItemResponse(
                id=proposal.id,
                task_id=task.id,
                trace_id=task.trace_id,
                user_input=task.user_input,
                task_status=task.status,
                tool_name=proposal.tool_name,
                risk_level=proposal.risk_level,
                reason=proposal.reason,
                status=proposal.status,
                created_at=proposal.created_at,
            )
            for proposal, task in rows
        ]

    @router.get("/tasks/{task_id}/execution-records")
    def read_execution_records(task_id: int, session: Session = Depends(get_session)) -> list[dict[str, Any]]:
        if get_task(session, task_id) is None:
            raise HTTPException(status_code=404, detail="task not found")
        records = session.execute(
            select(ExecutionRecord)
            .where(ExecutionRecord.task_id == task_id)
            .order_by(ExecutionRecord.id.desc())
        ).scalars()
        return [
            {
                "id": record.id,
                "proposal_id": record.proposal_id,
                "tool_call_id": record.tool_call_id,
                "tool_name": record.tool_name,
                "risk_level": record.risk_level,
                "executor_mode": record.executor_mode,
                "runtime_user": record.runtime_user,
                "runtime_uid": record.runtime_uid,
                "target_user": record.target_user,
                "allowed": record.allowed,
                "reason": record.reason,
                "scope": record.scope_json,
                "created_at": record.created_at.isoformat(),
            }
            for record in records
        ]

    @router.post("/proposals/{proposal_id}/approve", response_model=TaskResponse)
    def approve_action_proposal(
        proposal_id: int,
        payload: ProposalApprovalRequest,
        session: Session = Depends(get_session),
    ) -> TaskResponse:
        runner = AgentRunner(session, registry)
        try:
            task = runner.approve_and_execute_proposal(
                proposal_id,
                operator=payload.operator,
                comment=payload.comment,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        session.commit()
        return task_to_response(task, session)

    @router.post("/proposals/{proposal_id}/reject", response_model=TaskResponse)
    def reject_action_proposal(
        proposal_id: int,
        payload: ProposalApprovalRequest,
        session: Session = Depends(get_session),
    ) -> TaskResponse:
        runner = AgentRunner(session, registry)
        try:
            task = runner.reject_proposal(
                proposal_id,
                operator=payload.operator,
                comment=payload.comment,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        session.commit()
        return task_to_response(task, session)

    @router.get("/ai/status")
    def read_ai_status() -> dict[str, Any]:
        client = BailianClient()
        return {
            "configured": client.configured,
            "provider": "bailian",
            "base_url": client.base_url,
            "chat_model": client.chat_model,
            "embedding_model": client.embedding_model,
        }

    @router.get("/health")
    def read_health(session: Session = Depends(get_session)) -> dict[str, Any]:
        client = BailianClient()
        database_status = "ok"
        task_count: int | None = None
        try:
            task_count = int(session.execute(select(func.count(Task.id))).scalar_one())
        except Exception:
            database_status = "error"
        runtime = runtime_safety_report()
        worker = worker_runtime_status(session)
        tool_count = len(registry.list_tools())
        status = (
            "ok"
            if database_status == "ok" and worker["overall_status"] == "ok"
            else "degraded"
        )
        return {
            "status": status,
            "database": {"status": database_status, "task_count": task_count},
            "mcp": {"status": "ok", "tool_count": tool_count},
            "ai": {
                "configured": client.configured,
                "provider": "bailian",
                "chat_model": client.chat_model,
                "embedding_model": client.embedding_model,
            },
            "runtime": {
                "status": runtime["overall_status"],
                "executor_mode": runtime["executor"]["mode"],
                "action_execution_enabled": runtime["executor"]["action_execution_enabled"],
            },
            "worker": worker,
        }

    @router.get("/runtime/worker")
    def read_worker_runtime(session: Session = Depends(get_session)) -> dict[str, Any]:
        return worker_runtime_status(session)

    @router.get("/runtime/safety")
    def read_runtime_safety() -> dict[str, Any]:
        return runtime_safety_report()

    @router.post("/config-baselines")
    def create_config_baseline(
        payload: ConfigBaselineCreateRequest,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            baseline = ConfigBaselineService(session, registry).create(
                name=payload.name,
                paths=payload.paths,
                created_by=payload.created_by,
                scope=LIVE_SCOPE,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        session.commit()
        return config_baseline_to_response(baseline)

    @router.get("/config-baselines")
    def list_config_baselines(
        session: Session = Depends(get_session),
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        baselines = ConfigBaselineService(session, registry).list(limit=limit, scope=LIVE_SCOPE)
        return [
            config_baseline_to_response(
                baseline,
                session.execute(
                    select(ConfigBaselineCheck)
                    .where(ConfigBaselineCheck.baseline_id == baseline.id)
                    .order_by(ConfigBaselineCheck.id.desc())
                    .limit(1)
                ).scalar_one_or_none(),
            )
            for baseline in baselines
        ]

    @router.post("/config-baselines/{baseline_id}/checks")
    def compare_config_baseline(
        baseline_id: int,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            check = ConfigBaselineService(session, registry).compare(
                baseline_id,
                scope=LIVE_SCOPE,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        session.commit()
        return config_baseline_check_to_response(check)

    @router.get("/config-baselines/{baseline_id}/checks")
    def list_config_baseline_checks(
        baseline_id: int,
        session: Session = Depends(get_session),
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        try:
            checks = ConfigBaselineService(session, registry).list_checks(
                baseline_id,
                limit=limit,
                scope=LIVE_SCOPE,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return [config_baseline_check_to_response(check) for check in checks]

    @router.post("/knowledge/documents")
    def create_knowledge_document(
        payload: KnowledgeDocumentCreateRequest,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            document = KnowledgeService(session).ingest_document(
                title=payload.title,
                source_type=payload.source_type,
                source_uri=payload.source_uri,
                content=payload.content,
                trust_level=payload.trust_level,
            )
        except ModelNotConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ModelCallError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except KnowledgeIngestionRejectedError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        chunk_count = session.scalar(
            select(func.count(KnowledgeChunk.id)).where(KnowledgeChunk.document_id == document.id)
        )
        session.commit()
        return knowledge_document_to_response(document, chunk_count or 0)

    @router.post("/knowledge/documents/upload")
    async def upload_knowledge_document(
        file: UploadFile = File(),
        source_type: str = Form(default="manual"),
        trust_level: str = Form(default="internal"),
        title: str | None = Form(default=None),
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            extracted = extract_knowledge_file(file.filename or "knowledge.txt", await file.read())
            document = KnowledgeService(session).ingest_document(
                title=(title or extracted.title).strip()[:256],
                source_type=source_type,
                source_uri=extracted.source_uri,
                content=extracted.content,
                trust_level=trust_level,
            )
        except KnowledgeFileRejectedError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ModelNotConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ModelCallError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except KnowledgeIngestionRejectedError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        chunk_count = session.scalar(
            select(func.count(KnowledgeChunk.id)).where(KnowledgeChunk.document_id == document.id)
        )
        session.commit()
        response = knowledge_document_to_response(document, chunk_count or 0)
        response["extraction"] = {
            "file_type": extracted.file_type,
            "char_count": extracted.char_count,
            "source_uri": extracted.source_uri,
        }
        return response

    @router.post("/knowledge/builtin/seed")
    def seed_builtin_knowledge(session: Session = Depends(get_session)) -> list[dict[str, Any]]:
        try:
            documents = KnowledgeService(session).seed_builtin_documents()
        except ModelNotConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ModelCallError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        document_ids = [document.id for document in documents]
        chunk_counts = dict(
            session.execute(
                select(KnowledgeChunk.document_id, func.count(KnowledgeChunk.id))
                .where(KnowledgeChunk.document_id.in_(document_ids))
                .group_by(KnowledgeChunk.document_id)
            ).all()
        )
        session.commit()
        return [knowledge_document_to_response(document, chunk_counts.get(document.id, 0)) for document in documents]

    @router.get("/knowledge/index/status")
    def read_knowledge_index_status(session: Session = Depends(get_session)) -> dict[str, Any]:
        return knowledge_index_status_response(session)

    @router.post("/knowledge/index/rebuild")
    def rebuild_knowledge_index(session: Session = Depends(get_session)) -> dict[str, Any]:
        service = KnowledgeService(session)
        try:
            indexed = service.rebuild_missing_embeddings()
        except ModelNotConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ModelCallError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        session.commit()
        status = service.index_status()
        return {**status, "rebuilt_chunk_count": indexed}

    @router.get("/knowledge/search")
    def search_knowledge(q: str, limit: int = 5, session: Session = Depends(get_session)) -> list[dict[str, Any]]:
        try:
            hits = KnowledgeService(session).search(q, limit=min(max(limit, 1), 10))
        except ModelNotConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ModelCallError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except KnowledgeRetrievalUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return [hit.to_dict() for hit in hits]

    @router.post("/knowledge/answer")
    def answer_knowledge(payload: KnowledgeAnswerRequest, session: Session = Depends(get_session)) -> dict[str, Any]:
        try:
            answer = KnowledgeQAService(session).answer(payload.query, limit=payload.limit)
        except ModelNotConfiguredError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ModelCallError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except KnowledgeRetrievalUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return answer.to_dict()

    @router.get("/knowledge/documents")
    def list_knowledge_documents(session: Session = Depends(get_session), limit: int = 50) -> list[dict[str, Any]]:
        documents = list(
            session.execute(
                select(KnowledgeDocument).order_by(KnowledgeDocument.id.desc()).limit(min(max(limit, 1), 200))
            ).scalars()
        )
        if not documents:
            return []
        document_ids = [document.id for document in documents]
        chunk_counts = dict(
            session.execute(
                select(KnowledgeChunk.document_id, func.count(KnowledgeChunk.id))
                .where(KnowledgeChunk.document_id.in_(document_ids))
                .group_by(KnowledgeChunk.document_id)
            ).all()
        )
        return [knowledge_document_to_response(document, chunk_counts.get(document.id, 0)) for document in documents]

    @router.delete("/knowledge/documents/{document_id}")
    def delete_knowledge_document(document_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
        service = KnowledgeService(session)
        try:
            deleted_chunk_count = service.delete_document(document_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        index_status = service.index_status()
        session.commit()
        return {
            "document_id": document_id,
            "deleted_chunk_count": deleted_chunk_count,
            "index_status": index_status,
        }

    @router.get("/lab/scenarios")
    def list_lab_scenarios() -> list[dict[str, Any]]:
        return LabService().list_scenarios()

    @router.post("/lab/scenarios/{scenario_id}/activate")
    def activate_lab_scenario(
        scenario_id: str,
        payload: LabActivateRequest | None = None,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        service = LabService()
        try:
            baseline = None
            if service.requires_confirmed_baseline(scenario_id):
                prepared = service.prepare_confirmed_baseline(scenario_id)
                baseline = ConfigBaselineService(session, registry).create(
                    name="OpsBench · 配置权限恢复",
                    paths=[prepared["path"]],
                    created_by="opsbench",
                    scope=LAB_SCOPE,
                )
            state = service.activate(scenario_id, size_mb=payload.size_mb if payload else None)
            if baseline is not None:
                metadata = dict(state.get("metadata") or {})
                metadata["baseline_id"] = baseline.id
                state = {**state, "metadata": metadata}
            session.commit()
            return state
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.post("/lab/scenarios/{scenario_id}/reset")
    def reset_lab_scenario(scenario_id: str) -> dict[str, Any]:
        try:
            return LabService().reset(scenario_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/lab/evaluations/latest")
    def read_latest_lab_evaluation(session: Session = Depends(get_session)) -> dict[str, Any] | None:
        return LabEvaluationService(session, registry).read_latest()

    @router.post("/lab/evaluations/run")
    def run_lab_evaluation(session: Session = Depends(get_session)) -> dict[str, Any]:
        return LabEvaluationService(session, registry).run()

    @router.post("/lab/scenarios/{scenario_id}/evaluate")
    def run_lab_scenario_evaluation(
        scenario_id: str,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            return LabEvaluationService(session, registry).run_scenario(scenario_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/lab/scenarios/evaluations/latest")
    def read_latest_lab_scenario_evaluations(
        session: Session = Depends(get_session),
    ) -> dict[str, dict[str, Any]]:
        return LabEvaluationService(session, registry).read_latest_scenarios()

    @router.get("/tools")
    def list_tools() -> list[dict[str, Any]]:
        return registry.list_tools()

    @router.get("/agent/skills")
    def read_agent_skills() -> list[dict[str, Any]]:
        return list_agent_skills()

    @router.get("/agent/evaluations/latest")
    def read_latest_agent_evaluation(session: Session = Depends(get_session)) -> dict[str, Any] | None:
        return AgentEvaluationService(session, registry=registry).read_latest()

    @router.post("/agent/evaluations/run")
    def run_agent_evaluation(session: Session = Depends(get_session)) -> dict[str, Any]:
        return AgentEvaluationService(session, registry=registry).run()

    @router.get("/benchmark/latest")
    def read_latest_benchmark(session: Session = Depends(get_session)) -> dict[str, Any] | None:
        return BenchmarkService(session, registry).read_latest()

    @router.post("/benchmark/run")
    def run_benchmark(
        payload: BenchmarkRunRequest | None = None,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        return BenchmarkService(session, registry).run(rounds=payload.rounds if payload else 2)

    @router.get("/deployment/readiness")
    def read_deployment_readiness() -> dict[str, Any]:
        return DeploymentReadinessService(registry).read()

    @router.get("/platform/capabilities")
    def read_platform_capabilities(refresh: bool = False) -> dict[str, Any]:
        profile = registry.capability_profile(force=refresh)
        if profile is None:
            raise HTTPException(
                status_code=503,
                detail="platform capability probe is not configured",
            )
        return profile

    @router.get("/posture/live")
    def read_live_posture(session: Session = Depends(get_session)) -> dict[str, Any]:
        return LivePostureService(registry, session=session).read()

    @router.get("/audit/traces/{trace_id}")
    def read_audit_trace(trace_id: str, session: Session = Depends(get_session)) -> dict[str, Any]:
        chain = session.execute(
            select(AuditChain).where(AuditChain.trace_id == trace_id).order_by(AuditChain.id.asc())
        ).scalars()
        return {
            "trace_id": trace_id,
            "chain": [
                {
                    "id": item.id,
                    "event_id": item.event_id,
                    "prev_hash": item.prev_hash,
                    "payload_hash": item.payload_hash,
                    "event_hash": item.event_hash,
                    "created_at": item.created_at.isoformat(),
                }
                for item in chain
            ],
        }

    @router.get("/audit/traces/{trace_id}/verify")
    def verify_audit_trace(trace_id: str, session: Session = Depends(get_session)) -> dict[str, Any]:
        return AuditService(session).verify_trace(trace_id)

    @router.get("/audit/traces/{trace_id}/replay")
    def read_audit_replay(trace_id: str, session: Session = Depends(get_session)) -> dict[str, Any]:
        task = session.scalar(select(Task).where(Task.trace_id == trace_id))
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")
        events = session.execute(
            select(TaskEvent)
            .where(TaskEvent.task_id == task.id)
            .order_by(TaskEvent.id.asc())
        ).scalars()
        event_rows = [
            {
                "id": event.id,
                "stage": event.stage,
                "event_type": event.event_type,
                "message": event.message,
                "payload": event.payload_json,
                "created_at": event.created_at.isoformat(),
            }
            for event in events
        ]
        verification = AuditService(session).verify_trace(trace_id)
        replay = build_audit_replay(trace_id, event_rows, verification)
        replay["policy_replay"] = SafetyPolicyReplayService(session).evaluate(task)
        return replay

    @router.get("/safety/reviews/{task_id}")
    def read_safety_reviews(task_id: int, session: Session = Depends(get_session)) -> list[dict[str, Any]]:
        if get_task(session, task_id) is None:
            raise HTTPException(status_code=404, detail="task not found")
        reviews = session.execute(
            select(SafetyReview).where(SafetyReview.task_id == task_id).order_by(SafetyReview.id.asc())
        ).scalars()
        return [
            {
                "id": review.id,
                "review_type": review.review_type,
                "risk_level": review.risk_level,
                "decision": review.decision,
                "matched_rules": review.matched_rules_json,
                "reason": review.reason,
                "policy_version": review.policy_version,
                "policy_digest": review.policy_digest,
                "subject": review.subject_json,
                "created_at": review.created_at.isoformat(),
            }
            for review in reviews
        ]

    @router.get("/safety/rules")
    def read_safety_rules() -> list[dict[str, str]]:
        return SafetyEngine.rule_catalog()

    @router.get("/safety/evaluations/latest")
    def read_latest_safety_evaluation(session: Session = Depends(get_session)) -> dict[str, Any] | None:
        return SafetyEvaluationService(session).read_latest()

    @router.post("/safety/evaluations/run")
    def run_safety_evaluation(session: Session = Depends(get_session)) -> dict[str, Any]:
        return SafetyEvaluationService(session).run()

    return router
