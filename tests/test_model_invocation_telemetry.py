from __future__ import annotations

import json

import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.ai.client import BailianClient, ModelCallError
from backend.app.ai.telemetry import ModelInvocationRecorder
from backend.app.agent.runner import AgentRunner
from backend.app.models.entities import ModelInvocation, Task


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Task.__table__.create(engine)
    ModelInvocation.__table__.create(engine)
    return Session(engine)


def test_successful_chat_persists_only_bounded_metrics() -> None:
    captured_payload: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert "机密请求正文" in request.content.decode("utf-8")
        captured_payload.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"content": json.dumps({"intent": "ok"})},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 123, "completion_tokens": 17, "total_tokens": 140},
            },
        )

    session = build_session()
    task = Task(
        trace_id="trace-model-success",
        user_input="检查系统",
        intent="unknown",
        status="PLAN",
        risk_level="R0",
    )
    session.add(task)
    session.flush()
    client = BailianClient(
        transport=httpx.MockTransport(handler),
        invocation_sink=ModelInvocationRecorder(session, task),
    )
    client.api_key = "test-key"

    with client.invocation_scope("intent", "a" * 64):
        result = client.chat_json([{"role": "user", "content": "机密请求正文"}])
    session.commit()

    invocation = session.scalar(select(ModelInvocation))
    assert result == {"intent": "ok"}
    assert invocation is not None
    assert invocation.trace_id == task.trace_id
    assert invocation.stage == "intent"
    assert invocation.operation == "CHAT"
    assert invocation.status == "SUCCEEDED"
    assert (invocation.input_tokens, invocation.output_tokens, invocation.total_tokens) == (123, 17, 140)
    assert invocation.finish_reason == "stop"
    assert invocation.prompt_hash == "a" * 64
    assert captured_payload["response_format"] == {"type": "json_object"}
    assert "max_tokens" not in captured_payload
    assert "机密请求正文" not in str(invocation.__dict__)
    assert "test-key" not in str(invocation.__dict__)
    session.close()


def test_provider_failure_records_category_without_response_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            429,
            json={"error": {"code": "RateLimit", "message": "secret=response-body"}},
        )

    session = build_session()
    task = Task(
        trace_id="trace-model-failure",
        user_input="检查系统",
        intent="unknown",
        status="PLAN",
        risk_level="R0",
    )
    session.add(task)
    session.flush()
    client = BailianClient(
        transport=httpx.MockTransport(handler),
        invocation_sink=ModelInvocationRecorder(session, task),
    )
    client.api_key = "test-key"

    try:
        with client.invocation_scope("investigation", "b" * 64):
            client.chat_json([{"role": "user", "content": "故障上下文"}])
    except ModelCallError:
        pass
    else:
        raise AssertionError("provider failure must fail the model call")
    session.commit()

    invocation = session.scalar(select(ModelInvocation))
    assert invocation is not None
    assert invocation.status == "FAILED"
    assert invocation.error_category == "RATE_LIMIT"
    assert invocation.total_tokens is None
    assert "response-body" not in str(invocation.__dict__)
    session.close()


def test_embedding_and_rerank_emit_distinct_operations() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/embeddings"):
            return httpx.Response(
                200,
                json={"data": [{"index": 0, "embedding": [0.1, 0.2]}], "usage": {"total_tokens": 6}},
            )
        return httpx.Response(
            200,
            json={"results": [{"index": 0, "relevance_score": 0.9}], "usage": {"total_tokens": 9}},
        )

    telemetry = []
    client = BailianClient(
        transport=httpx.MockTransport(handler),
        invocation_sink=telemetry.append,
    )
    client.api_key = "test-key"

    with client.invocation_scope("knowledge_query_embedding"):
        client.embed(["数据库日志"])
    with client.invocation_scope("knowledge_rerank"):
        client.rerank("日志", ["数据库日志规范"], 1)

    assert [(item.stage, item.operation, item.total_tokens) for item in telemetry] == [
        ("knowledge_query_embedding", "EMBEDDING", 6),
        ("knowledge_rerank", "RERANK", 9),
    ]


def test_agent_runner_attaches_one_task_bound_recorder_to_all_default_model_clients() -> None:
    session = build_session()
    task = Task(
        trace_id="trace-runner-models",
        user_input="检查系统",
        intent="unknown",
        status="PLAN",
        risk_level="R0",
    )
    session.add(task)
    session.flush()
    runner = AgentRunner(session, object())  # type: ignore[arg-type]

    runner._attach_model_observability(task)

    clients = [
        runner.intent_resolver.model_client,
        runner.investigation_engine.model.model_client,
        runner.investigation_engine.knowledge.model_client,
        runner.investigation_engine.memory.model_client,
    ]
    assert all(client.invocation_sink is not None for client in clients)
    assert clients[1] is clients[2] is clients[3]
    session.close()
