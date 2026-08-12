from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import build_router
from backend.app.core.database import get_session
from backend.app.core.config import settings
from backend.app.knowledge.service import KnowledgeService
from backend.app.models.entities import KnowledgeChunk, KnowledgeDocument


class EmptyRegistry:
    def list_tools(self) -> list[dict]:
        return []


class KnowledgeManagementApiTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        KnowledgeDocument.__table__.create(engine)
        KnowledgeChunk.__table__.create(engine)
        self.session = Session(engine, expire_on_commit=False)
        document = KnowledgeDocument(
            title="数据库日志处置规范",
            source_type="runbook",
            source_uri="manual://database-log",
            trust_level="verified",
            content_hash="a" * 64,
        )
        self.session.add(document)
        self.session.flush()
        self.document_id = document.id
        self.session.add(
            KnowledgeChunk(
                document_id=document.id,
                chunk_index=0,
                content="数据库日志不得直接删除，应先确认归属和备份状态。",
                embedding=None,
                metadata_json={"title": document.title},
                content_hash="b" * 64,
            )
        )
        self.session.commit()

        app = FastAPI()
        app.include_router(build_router(EmptyRegistry()))  # type: ignore[arg-type]

        def override_session():
            yield self.session

        app.dependency_overrides[get_session] = override_session
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        self.session.close()

    def test_delete_document_removes_chunks_and_refreshes_index_status(self) -> None:
        response = self.client.delete(f"/api/knowledge/documents/{self.document_id}")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["document_id"], self.document_id)
        self.assertEqual(body["deleted_chunk_count"], 1)
        self.assertEqual(body["index_status"]["document_count"], 0)
        self.assertFalse(body["index_status"]["ready"])
        self.assertIsNone(self.session.get(KnowledgeDocument, self.document_id))
        chunks = list(self.session.execute(select(KnowledgeChunk)).scalars())
        self.assertEqual(chunks, [])

    def test_delete_unknown_document_returns_not_found(self) -> None:
        response = self.client.delete("/api/knowledge/documents/999")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "knowledge document not found")

    def test_list_documents_exposes_version_and_lifecycle_status(self) -> None:
        response = self.client.get("/api/knowledge/documents")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["version"], 1)
        self.assertEqual(response.json()[0]["status"], "ACTIVE")

    def test_index_is_ready_only_when_vector_and_lexical_fields_are_complete(self) -> None:
        chunk = self.session.scalar(select(KnowledgeChunk))
        assert chunk is not None
        chunk.embedding = [0.0] * settings.embedding_dim
        chunk.search_text = ""
        self.session.commit()

        incomplete = KnowledgeService(self.session).index_status()

        self.assertFalse(incomplete["ready"])
        self.assertEqual(incomplete["missing_embedding_count"], 0)
        self.assertEqual(incomplete["missing_lexical_count"], 1)

        chunk.search_text = "数据库 日志 备份"
        self.session.commit()
        complete = KnowledgeService(self.session).index_status()
        self.assertTrue(complete["ready"])
        self.assertEqual(complete["lexical_chunk_count"], 1)


if __name__ == "__main__":
    unittest.main()
