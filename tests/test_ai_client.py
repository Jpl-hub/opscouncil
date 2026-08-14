from __future__ import annotations

import json

import httpx
import pytest

from backend.app.ai.client import BailianClient, ModelCallError


def build_mock_client(handler) -> BailianClient:  # type: ignore[no-untyped-def]
    client = BailianClient(transport=httpx.MockTransport(handler))
    client.api_key = "fixture-model-credential"
    return client


def test_chat_json_forwards_explicit_thinking_and_output_budget() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"answer":"ok"}'}, "finish_reason": "stop"}]},
        )

    client = build_mock_client(handler)
    result = client.chat_json(
        [{"role": "user", "content": "简洁回答"}],
        max_tokens=700,
        enable_thinking=False,
    )

    assert result == {"answer": "ok"}
    assert captured["max_tokens"] == 700
    assert captured["enable_thinking"] is False


def test_rerank_uses_qwen_compatible_contract_and_validates_results() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "results": [
                    {"index": 1, "relevance_score": 0.97},
                    {"index": 0, "relevance_score": 0.61},
                ]
            },
        )

    client = build_mock_client(handler)
    client.rerank_base_url = "https://dashscope.aliyuncs.com/compatible-api/v1"

    results = client.rerank(
        "WAL 日志如何安全处置",
        ["普通应用日志可备份轮转。", "数据库 WAL 日志不得直接删除。"],
        top_n=2,
    )

    assert captured["path"] == "/compatible-api/v1/reranks"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["model"] == "qwen3-rerank"
    assert payload["query"] == "WAL 日志如何安全处置"
    assert payload["top_n"] == 2
    assert [item.index for item in results] == [1, 0]
    assert results[0].relevance_score == 0.97


def test_rerank_rejects_out_of_range_document_index() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, json={"results": [{"index": 9, "relevance_score": 0.9}]})

    client = build_mock_client(handler)

    with pytest.raises(ModelCallError, match="out-of-range"):
        client.rerank("磁盘告警", ["磁盘使用率过高。"], top_n=1)


def test_rerank_exposes_provider_error_without_leaking_request_content() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            429,
            json={"error": {"code": "RateLimitExceeded", "message": "too many requests"}},
        )

    client = build_mock_client(handler)

    with pytest.raises(ModelCallError, match="429 RateLimitExceeded") as raised:
        client.rerank("敏感查询内容", ["敏感候选内容"], top_n=1)
    assert "敏感查询内容" not in str(raised.value)
    assert "敏感候选内容" not in str(raised.value)
