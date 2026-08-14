from __future__ import annotations

import unittest

from backend.app.knowledge.qa import KnowledgeQAService
from backend.app.knowledge.retrieval import RetrievalProvenance
from backend.app.knowledge.service import KnowledgeHit


class FakeModelClient:
    chat_model = "fake-qwen"

    def __init__(self) -> None:
        self.messages: list[dict[str, str]] = []

    def chat_json(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 900,
        *,
        enable_thinking: bool | None = None,
    ) -> dict:
        self.messages = messages
        return {
            "answer": "先确认文件类型、进程占用和服务归属。数据库事务日志不得自动删除，普通日志应走备份、压缩和截断。",
            "next_actions": [
                "执行只读大文件定位",
                "核查 lsof 占用",
                "需要清理时进入审批",
                "执行 rm -rf /var/log",
                "运行 systemctl status <service>",
            ],
            "cited_chunk_ids": [11, 99],
        }

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[0.1, 0.2] for _ in texts]


class FakeKnowledge:
    def __init__(self, hits: list[KnowledgeHit]) -> None:
        self.hits = hits
        self.queries: list[tuple[str, int]] = []

    def search(self, query: str, limit: int = 5) -> list[KnowledgeHit]:
        self.queries.append((query, limit))
        return self.hits


class KnowledgeQAServiceTest(unittest.TestCase):
    def test_answers_from_vector_hits_and_keeps_citations_in_scope(self) -> None:
        hit = KnowledgeHit(
            chunk_id=11,
            document_id=3,
            title="数据库与中间件日志边界规范",
            source_uri="builtin://ops/database-log-boundary",
            trust_level="verified",
            content="数据库事务日志、WAL、binlog、redo、undo、AOF、RDB 和审计日志不得被 Agent 自动删除。",
            distance=0.13,
            retrieval=RetrievalProvenance(
                lexical_rank=1,
                vector_rank=1,
                rrf_score=0.032,
                rerank_score=0.98,
            ),
        )
        model = FakeModelClient()
        service = KnowledgeQAService(object(), model)  # type: ignore[arg-type]
        service.knowledge = FakeKnowledge([hit])  # type: ignore[assignment]

        answer = service.answer("数据库目录的大日志能不能清理？")

        self.assertEqual(answer.citations, [hit])
        self.assertIn("数据库事务日志不得自动删除", answer.answer)
        self.assertIn("执行只读大文件定位", answer.next_actions)
        self.assertNotIn("执行 rm -rf /var/log", answer.next_actions)
        self.assertNotIn("运行 systemctl status <service>", answer.next_actions)
        self.assertEqual(service.knowledge.queries, [("数据库目录的大日志能不能清理？", 5)])
        self.assertIn("只能依据用户问题和 evidence 中的知识片段回答", model.messages[0]["content"])
        self.assertIn("不得输出 shell 命令", model.messages[0]["content"])
        self.assertIn("chunk_id", model.messages[1]["content"])


if __name__ == "__main__":
    unittest.main()
