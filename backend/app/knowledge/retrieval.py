from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

import jieba
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.ai.client import ModelCallError, ModelNotConfiguredError, model_invocation_scope
from backend.app.models.entities import KnowledgeChunk, KnowledgeDocument


@dataclass(frozen=True)
class FusedCandidate:
    chunk_id: int
    lexical_rank: int | None
    vector_rank: int | None
    rrf_score: float


@dataclass(frozen=True)
class RankedCandidate:
    chunk_id: int
    score: float


@dataclass(frozen=True)
class CandidateText:
    chunk_id: int
    document_id: int
    title: str
    source_uri: str
    trust_level: str
    content: str


@dataclass(frozen=True)
class RetrievalProvenance:
    lexical_rank: int | None
    vector_rank: int | None
    rrf_score: float
    rerank_score: float

    def to_dict(self) -> dict[str, int | float | None]:
        return {
            "lexical_rank": self.lexical_rank,
            "vector_rank": self.vector_rank,
            "rrf_score": self.rrf_score,
            "rerank_score": self.rerank_score,
        }


@dataclass(frozen=True)
class KnowledgeHit:
    chunk_id: int
    document_id: int
    title: str
    source_uri: str
    trust_level: str
    content: str
    distance: float | None
    retrieval: RetrievalProvenance
    source_kind: str = "document"

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "title": self.title,
            "source_uri": self.source_uri,
            "trust_level": self.trust_level,
            "content": self.content,
            "distance": self.distance,
            "retrieval": self.retrieval.to_dict(),
            "source_kind": self.source_kind,
        }


class KnowledgeRetrievalUnavailableError(RuntimeError):
    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        super().__init__(message)


class HybridKnowledgeRetriever:
    source_kind = "document"
    telemetry_stage_prefix = "knowledge"
    minimum_rerank_score = 0.55

    def __init__(self, session: Session, model_client: Any) -> None:
        self.session = session
        self.model_client = model_client

    def search(self, query: str, limit: int = 5) -> list[KnowledgeHit]:
        normalized_query = re.sub(r"\s+", " ", query.strip())
        if not normalized_query:
            return []
        normalized_limit = max(1, min(limit, 10))
        candidate_limit = min(100, max(20, normalized_limit * 8))
        try:
            index_ready = self._index_ready()
        except SQLAlchemyError as exc:
            raise KnowledgeRetrievalUnavailableError("index", f"知识索引状态读取失败：{exc}") from exc
        if not index_ready:
            raise KnowledgeRetrievalUnavailableError(
                "index",
                "知识库没有完整的全文与向量索引，请先导入资料并完成索引。",
            )

        try:
            with model_invocation_scope(
                self.model_client,
                f"{self.telemetry_stage_prefix}_query_embedding",
            ):
                query_vector = self.model_client.embed([normalized_query])[0]
        except (ModelCallError, ModelNotConfiguredError, IndexError) as exc:
            raise KnowledgeRetrievalUnavailableError("embedding", f"知识查询向量生成失败：{exc}") from exc

        query_text = tokenize_for_search(normalized_query)
        try:
            lexical = self._lexical_candidates(query_text, candidate_limit)
        except SQLAlchemyError as exc:
            raise KnowledgeRetrievalUnavailableError("lexical", f"知识全文检索失败：{exc}") from exc
        try:
            vector = self._vector_candidates(query_vector, candidate_limit)
        except SQLAlchemyError as exc:
            raise KnowledgeRetrievalUnavailableError("vector", f"知识向量检索失败：{exc}") from exc

        fused = reciprocal_rank_fusion(
            [item.chunk_id for item in lexical],
            [item.chunk_id for item in vector],
        )
        if not fused:
            return []
        try:
            candidates = self._load_candidates([item.chunk_id for item in fused])
        except SQLAlchemyError as exc:
            raise KnowledgeRetrievalUnavailableError("hydrate", f"知识候选加载失败：{exc}") from exc
        ordered_fused = [item for item in fused if item.chunk_id in candidates]
        documents = [candidates[item.chunk_id].content for item in ordered_fused]
        if not documents:
            return []
        try:
            with model_invocation_scope(
                self.model_client,
                f"{self.telemetry_stage_prefix}_rerank",
            ):
                reranked = self.model_client.rerank(
                    normalized_query,
                    documents,
                    top_n=min(normalized_limit, len(documents)),
                )
        except (ModelCallError, ModelNotConfiguredError, ValueError) as exc:
            raise KnowledgeRetrievalUnavailableError("rerank", f"知识重排失败：{exc}") from exc
        if not reranked:
            raise KnowledgeRetrievalUnavailableError("rerank", "知识重排未返回有效候选。")

        vector_scores = {item.chunk_id: item.score for item in vector}
        hits: list[KnowledgeHit] = []
        for result in reranked:
            if not 0 <= result.index < len(ordered_fused):
                raise KnowledgeRetrievalUnavailableError("rerank", "知识重排返回了越界候选。")
            if result.relevance_score < self.minimum_rerank_score:
                continue
            fused_item = ordered_fused[result.index]
            candidate = candidates[fused_item.chunk_id]
            hits.append(
                KnowledgeHit(
                    chunk_id=candidate.chunk_id,
                    document_id=candidate.document_id,
                    title=candidate.title,
                    source_uri=candidate.source_uri,
                    trust_level=candidate.trust_level,
                    content=candidate.content,
                    distance=vector_scores.get(candidate.chunk_id),
                    retrieval=RetrievalProvenance(
                        lexical_rank=fused_item.lexical_rank,
                        vector_rank=fused_item.vector_rank,
                        rrf_score=fused_item.rrf_score,
                        rerank_score=result.relevance_score,
                    ),
                    source_kind=self.source_kind,
                )
            )
        return hits

    def _index_ready(self) -> bool:
        total, vector_count, lexical_count = self.session.execute(
            select(
                func.count(KnowledgeChunk.id),
                func.count(KnowledgeChunk.id).filter(KnowledgeChunk.embedding.is_not(None)),
                func.count(KnowledgeChunk.id).filter(KnowledgeChunk.search_text != ""),
            )
            .join(KnowledgeDocument, KnowledgeDocument.id == KnowledgeChunk.document_id)
            .where(KnowledgeDocument.status == "ACTIVE")
        ).one()
        return int(total or 0) > 0 and int(total) == int(vector_count or 0) == int(lexical_count or 0)

    def _lexical_candidates(self, query_text: str, limit: int) -> list[RankedCandidate]:
        tsquery = tsquery_from_search_text(query_text)
        if not tsquery:
            return []
        rows = self.session.execute(
            text(
                """
                SELECT kc.id AS chunk_id,
                       ts_rank_cd(
                           to_tsvector('simple', kc.search_text),
                           to_tsquery('simple', :tsquery)
                       ) AS score
                  FROM knowledge_chunks AS kc
                  JOIN knowledge_documents AS kd ON kd.id = kc.document_id
                 WHERE kd.status = 'ACTIVE'
                   AND to_tsvector('simple', kc.search_text) @@ to_tsquery('simple', :tsquery)
                 ORDER BY score DESC, kc.id ASC
                 LIMIT :candidate_limit
                """
            ),
            {"tsquery": tsquery, "candidate_limit": limit},
        ).all()
        return [RankedCandidate(chunk_id=int(row.chunk_id), score=float(row.score)) for row in rows]

    def _vector_candidates(self, query_vector: list[float], limit: int) -> list[RankedCandidate]:
        distance = KnowledgeChunk.embedding.cosine_distance(query_vector).label("distance")
        rows = self.session.execute(
            select(KnowledgeChunk.id, distance)
            .join(KnowledgeDocument, KnowledgeDocument.id == KnowledgeChunk.document_id)
            .where(
                KnowledgeDocument.status == "ACTIVE",
                KnowledgeChunk.embedding.is_not(None),
            )
            .order_by(distance, KnowledgeChunk.id.asc())
            .limit(limit)
        ).all()
        return [RankedCandidate(chunk_id=int(row[0]), score=float(row[1])) for row in rows]

    def _load_candidates(self, chunk_ids: list[int]) -> dict[int, CandidateText]:
        rows = self.session.execute(
            select(KnowledgeChunk, KnowledgeDocument)
            .join(KnowledgeDocument, KnowledgeDocument.id == KnowledgeChunk.document_id)
            .where(
                KnowledgeChunk.id.in_(chunk_ids),
                KnowledgeDocument.status == "ACTIVE",
            )
        ).all()
        return {
            chunk.id: CandidateText(
                chunk_id=chunk.id,
                document_id=document.id,
                title=document.title,
                source_uri=document.source_uri,
                trust_level=document.trust_level,
                content=chunk.content,
            )
            for chunk, document in rows
        }


def tokenize_for_search(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text.strip().lower())
    tokens = (
        token.strip()
        for token in jieba.cut(normalized, cut_all=False)
    )
    return " ".join(
        token
        for token in tokens
        if token and re.search(r"[a-z0-9_\-\u4e00-\u9fff]", token)
    )


def reciprocal_rank_fusion(
    lexical_ranked_ids: list[int],
    vector_ranked_ids: list[int],
    *,
    k: int = 60,
) -> list[FusedCandidate]:
    if k <= 0:
        raise ValueError("RRF rank constant must be positive")

    lexical_ranks = _first_ranks(lexical_ranked_ids)
    vector_ranks = _first_ranks(vector_ranked_ids)
    candidates = []
    for chunk_id in lexical_ranks.keys() | vector_ranks.keys():
        lexical_rank = lexical_ranks.get(chunk_id)
        vector_rank = vector_ranks.get(chunk_id)
        score = 0.0
        if lexical_rank is not None:
            score += 1.0 / (k + lexical_rank)
        if vector_rank is not None:
            score += 1.0 / (k + vector_rank)
        candidates.append(
            FusedCandidate(
                chunk_id=chunk_id,
                lexical_rank=lexical_rank,
                vector_rank=vector_rank,
                rrf_score=score,
            )
        )
    return sorted(
        candidates,
        key=lambda item: (
            -item.rrf_score,
            min(rank for rank in (item.lexical_rank, item.vector_rank) if rank is not None),
            item.chunk_id,
        ),
    )


def _first_ranks(chunk_ids: list[int]) -> dict[int, int]:
    ranks: dict[int, int] = {}
    for rank, chunk_id in enumerate(chunk_ids, start=1):
        ranks.setdefault(chunk_id, rank)
    return ranks


def tsquery_from_search_text(search_text: str) -> str:
    tokens = re.findall(r"[a-z0-9_\u4e00-\u9fff]+", search_text.lower())
    return " | ".join(f"'{token}'" for token in dict.fromkeys(tokens))
