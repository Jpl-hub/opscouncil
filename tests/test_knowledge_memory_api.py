from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.api.routes import build_router
from backend.app.knowledge.retrieval import KnowledgeHit, RetrievalProvenance
from backend.app.memory.api import get_operational_memory_service


class EmptyRegistry:
    def list_tools(self) -> list[dict]:
        return []


class FeedbackService:
    def list_feedback(self, task_id: int, *, limit: int = 20) -> list[SimpleNamespace]:
        assert task_id == 19
        assert limit == 20
        return [
            SimpleNamespace(
                id=5,
                task_id=task_id,
                memory_id=7,
                actor="admin",
                verdict="HELPFUL",
                correction=None,
                created_at=datetime(2026, 7, 12, 10, 1, tzinfo=timezone.utc),
            )
        ]


def build_client() -> TestClient:
    app = FastAPI()
    app.include_router(build_router(EmptyRegistry()))  # type: ignore[arg-type]
    app.dependency_overrides[get_operational_memory_service] = FeedbackService
    return TestClient(app)


def test_ui_contract_exposes_feedback_retrieval_provenance_and_capability_version() -> None:
    hit = KnowledgeHit(
        chunk_id=11,
        document_id=3,
        title="日志轮转规范",
        source_uri="builtin://ops/log-rotation",
        trust_level="verified",
        content="先确认服务归属，再执行备份与轮转。",
        distance=0.12,
        retrieval=RetrievalProvenance(
            lexical_rank=2,
            vector_rank=1,
            rrf_score=0.032,
            rerank_score=0.97,
        ),
        source_kind="document",
    )
    client = build_client()
    try:
        with patch("backend.app.api.routes.KnowledgeService.search", return_value=[hit]):
            searched = client.get("/api/knowledge/search", params={"q": "日志轮转"})
        feedback = client.get("/api/tasks/19/feedback")
        capabilities = client.get("/api/agent/skills")
    finally:
        client.close()

    assert searched.status_code == 200
    retrieval = searched.json()[0]
    assert retrieval["source_kind"] == "document"
    assert set(retrieval["retrieval"]) == {
        "lexical_rank",
        "vector_rank",
        "rrf_score",
        "rerank_score",
    }
    assert retrieval["retrieval"]["rerank_score"] == 0.97

    assert feedback.status_code == 200
    assert feedback.json()[0]["verdict"] == "HELPFUL"
    assert feedback.json()[0]["memory_id"] == 7

    assert capabilities.status_code == 200
    capability = capabilities.json()[0]
    assert capability["version"]
    assert len(capability["catalog_hash"]) == 64
    assert all(tool["min_version"] for tool in capability["tools"])
