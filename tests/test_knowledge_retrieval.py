from __future__ import annotations

import pytest

from backend.app.ai.client import ModelCallError, RerankResult
from backend.app.knowledge.retrieval import (
    CandidateText,
    HybridKnowledgeRetriever,
    KnowledgeRetrievalUnavailableError,
    RankedCandidate,
    reciprocal_rank_fusion,
    tokenize_for_search,
)


def test_tokenize_for_search_is_stable_for_chinese_and_identifiers() -> None:
    first = tokenize_for_search("PostgreSQL WAL 日志如何安全清理？")
    second = tokenize_for_search(" PostgreSQL WAL 日志如何安全清理？ ")

    assert first == second
    assert "postgresql" in first.split()
    assert "wal" in first.split()
    assert "日志" in first.split()


def test_rrf_fuses_keyword_and_vector_ranks_without_duplicate_chunks() -> None:
    fused = reciprocal_rank_fusion(
        lexical_ranked_ids=[11, 12],
        vector_ranked_ids=[12, 13],
        k=60,
    )

    assert [item.chunk_id for item in fused] == [12, 11, 13]
    assert fused[0].lexical_rank == 2
    assert fused[0].vector_rank == 1
    assert fused[0].rrf_score > fused[1].rrf_score


def test_rrf_uses_first_occurrence_when_a_branch_contains_duplicates() -> None:
    fused = reciprocal_rank_fusion(
        lexical_ranked_ids=[7, 7, 8],
        vector_ranked_ids=[8, 7],
        k=60,
    )

    by_id = {item.chunk_id: item for item in fused}
    assert len(by_id) == 2
    assert by_id[7].lexical_rank == 1
    assert by_id[7].vector_rank == 2


def test_rrf_rejects_non_positive_rank_constant() -> None:
    try:
        reciprocal_rank_fusion([1], [2], k=0)
    except ValueError as exc:
        assert "positive" in str(exc)
    else:
        raise AssertionError("non-positive RRF k must be rejected")


class FakeHybridModel:
    def __init__(self, *, rerank_error: Exception | None = None) -> None:
        self.rerank_error = rerank_error
        self.embedding_queries: list[list[str]] = []
        self.rerank_calls: list[tuple[str, list[str], int]] = []

    def embed(self, texts: list[str]) -> list[list[float]]:
        self.embedding_queries.append(texts)
        return [[0.1, 0.2] for _ in texts]

    def rerank(self, query: str, documents: list[str], top_n: int) -> list[RerankResult]:
        self.rerank_calls.append((query, documents, top_n))
        if self.rerank_error is not None:
            raise self.rerank_error
        return [RerankResult(index=0, relevance_score=0.97), RerankResult(index=1, relevance_score=0.82)]


class InMemoryHybridRetriever(HybridKnowledgeRetriever):
    def __init__(self, model: FakeHybridModel, *, ready: bool = True) -> None:
        super().__init__(object(), model)  # type: ignore[arg-type]
        self.ready = ready

    def _index_ready(self) -> bool:
        return self.ready

    def _lexical_candidates(self, query_text: str, limit: int) -> list[RankedCandidate]:
        assert "wal" in query_text.split()
        assert limit >= 2
        return [RankedCandidate(chunk_id=11, score=0.8), RankedCandidate(chunk_id=12, score=0.7)]

    def _vector_candidates(self, query_vector: list[float], limit: int) -> list[RankedCandidate]:
        assert query_vector == [0.1, 0.2]
        assert limit >= 2
        return [RankedCandidate(chunk_id=12, score=0.12), RankedCandidate(chunk_id=13, score=0.21)]

    def _load_candidates(self, chunk_ids: list[int]) -> dict[int, CandidateText]:
        assert chunk_ids == [12, 11, 13]
        return {
            11: CandidateText(11, 3, "普通日志规范", "runbook://log", "verified", "普通日志可备份轮转。"),
            12: CandidateText(12, 4, "数据库日志边界", "policy://wal", "verified", "数据库 WAL 日志不得直接删除。"),
            13: CandidateText(13, 5, "端口规范", "runbook://network", "internal", "监听端口需要确认进程归属。"),
        }


def test_hybrid_search_executes_both_retrieval_branches_and_reranks_rrf_candidates() -> None:
    model = FakeHybridModel()
    retriever = InMemoryHybridRetriever(model)

    hits = retriever.search("WAL 日志如何安全处置", limit=2)

    assert [hit.chunk_id for hit in hits] == [12, 11]
    assert model.embedding_queries == [["WAL 日志如何安全处置"]]
    assert len(model.rerank_calls) == 1
    assert hits[0].retrieval.vector_rank == 1
    assert hits[0].retrieval.lexical_rank == 2
    assert hits[0].retrieval.rerank_score == 0.97
    assert hits[1].retrieval.vector_rank is None


def test_hybrid_search_drops_candidates_below_the_rerank_relevance_gate() -> None:
    class LowRelevanceModel(FakeHybridModel):
        def rerank(self, query: str, documents: list[str], top_n: int) -> list[RerankResult]:
            self.rerank_calls.append((query, documents, top_n))
            return [
                RerankResult(index=0, relevance_score=0.54),
                RerankResult(index=1, relevance_score=0.22),
            ]

    retriever = InMemoryHybridRetriever(LowRelevanceModel())

    assert retriever.search("WAL 日志如何安全处置", limit=2) == []


def test_hybrid_search_does_not_call_models_when_index_is_not_ready() -> None:
    model = FakeHybridModel()
    retriever = InMemoryHybridRetriever(model, ready=False)

    with pytest.raises(KnowledgeRetrievalUnavailableError) as raised:
        retriever.search("磁盘告警")

    assert raised.value.stage == "index"
    assert model.embedding_queries == []
    assert model.rerank_calls == []


def test_rerank_failure_is_not_returned_as_partial_search() -> None:
    model = FakeHybridModel(rerank_error=ModelCallError("provider unavailable"))
    retriever = InMemoryHybridRetriever(model)

    with pytest.raises(KnowledgeRetrievalUnavailableError) as raised:
        retriever.search("WAL 日志如何安全处置", limit=2)

    assert raised.value.stage == "rerank"
    assert "provider unavailable" in str(raised.value)
