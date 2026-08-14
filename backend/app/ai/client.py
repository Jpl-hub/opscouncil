from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
import time
from typing import Any, Callable, Iterator

import httpx

from backend.app.core.config import settings


class ModelNotConfiguredError(RuntimeError):
    pass


class ModelCallError(RuntimeError):
    def __init__(self, message: str, *, category: str = "UNKNOWN") -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class RerankResult:
    index: int
    relevance_score: float


@dataclass(frozen=True)
class ModelInvocationTelemetry:
    stage: str
    operation: str
    provider: str
    model: str
    status: str
    duration_ms: int
    input_tokens: int | None
    output_tokens: int | None
    total_tokens: int | None
    finish_reason: str | None
    error_category: str | None
    prompt_hash: str


@dataclass(frozen=True)
class _InvocationContext:
    stage: str
    prompt_hash: str


InvocationSink = Callable[[ModelInvocationTelemetry], Any]


class BailianClient:
    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        invocation_sink: InvocationSink | None = None,
    ) -> None:
        self.api_key = settings.bailian_api_key
        self.base_url = settings.bailian_base_url.rstrip("/")
        self.chat_model = settings.bailian_chat_model
        self.embedding_model = settings.bailian_embedding_model
        self.rerank_model = settings.bailian_rerank_model
        self.rerank_base_url = settings.bailian_rerank_base_url.rstrip("/")
        self.transport = transport
        self.invocation_sink = invocation_sink
        self._invocation_context: ContextVar[_InvocationContext | None] = ContextVar(
            f"bailian_invocation_context_{id(self)}",
            default=None,
        )

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict[str, str]:
        if not self.configured:
            raise ModelNotConfiguredError("BAILIAN_API_KEY or DASHSCOPE_API_KEY is not configured")
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    @contextmanager
    def invocation_scope(self, stage: str, prompt_hash: str = "") -> Iterator[None]:
        context = _InvocationContext(
            stage=_bounded_label(stage, "model_call"),
            prompt_hash=prompt_hash if _is_sha256(prompt_hash) else "",
        )
        token = self._invocation_context.set(context)
        try:
            yield
        finally:
            self._invocation_context.reset(token)

    def chat_json(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
        *,
        enable_thinking: bool | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.chat_model,
            "messages": messages,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if enable_thinking is not None:
            payload["enable_thinking"] = enable_thinking
        stage, prompt_hash = self._metadata("chat", payload)
        started = time.monotonic()
        try:
            with self._client(timeout=45) as client:
                response = client.post(
                    f"{self.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
                response.raise_for_status()
        except ModelNotConfiguredError:
            self._emit_failure(stage, "CHAT", self.chat_model, started, "NOT_CONFIGURED", prompt_hash)
            raise
        except httpx.HTTPStatusError as exc:
            category = _http_error_category(exc.response.status_code)
            self._emit_failure(
                stage,
                "CHAT",
                self.chat_model,
                started,
                category,
                prompt_hash,
            )
            raise ModelCallError(
                f"chat completion failed: {_format_response_error(exc.response)}",
                category=category,
            ) from exc
        except httpx.HTTPError as exc:
            self._emit_failure(stage, "CHAT", self.chat_model, started, "TRANSPORT", prompt_hash)
            raise ModelCallError(f"chat completion failed: {exc}", category="TRANSPORT") from exc

        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            self._emit_failure(stage, "CHAT", self.chat_model, started, "RESPONSE_SCHEMA", prompt_hash)
            raise ModelCallError(
                "chat completion response is missing message content",
                category="RESPONSE_SCHEMA",
            ) from exc
        try:
            parsed = _parse_json_object(content)
        except (ModelCallError, json.JSONDecodeError) as exc:
            self._emit_failure(stage, "CHAT", self.chat_model, started, "RESPONSE_SCHEMA", prompt_hash)
            raise ModelCallError(
                "chat completion response is not valid JSON",
                category="RESPONSE_SCHEMA",
            ) from exc
        usage = _usage(body)
        choice = body.get("choices", [{}])[0] if isinstance(body, dict) else {}
        self._emit(
            ModelInvocationTelemetry(
                stage=stage,
                operation="CHAT",
                provider="bailian",
                model=self.chat_model,
                status="SUCCEEDED",
                duration_ms=_elapsed_ms(started),
                input_tokens=usage[0],
                output_tokens=usage[1],
                total_tokens=usage[2],
                finish_reason=_bounded_optional(choice.get("finish_reason") if isinstance(choice, dict) else None),
                error_category=None,
                prompt_hash=prompt_hash,
            )
        )
        return parsed

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        if len(texts) > 10:
            embeddings: list[list[float]] = []
            for index in range(0, len(texts), 10):
                embeddings.extend(self.embed(texts[index : index + 10]))
            return embeddings
        payload: dict[str, Any] = {
            "model": self.embedding_model,
            "input": texts,
            "dimensions": settings.embedding_dim,
            "encoding_format": "float",
        }
        stage, prompt_hash = self._metadata("embedding", payload)
        started = time.monotonic()
        try:
            with self._client(timeout=60) as client:
                response = client.post(
                    f"{self.base_url}/embeddings",
                    headers=self._headers(),
                    json=payload,
                )
                response.raise_for_status()
        except ModelNotConfiguredError:
            self._emit_failure(stage, "EMBEDDING", self.embedding_model, started, "NOT_CONFIGURED", prompt_hash)
            raise
        except httpx.HTTPStatusError as exc:
            self._emit_failure(
                stage,
                "EMBEDDING",
                self.embedding_model,
                started,
                _http_error_category(exc.response.status_code),
                prompt_hash,
            )
            raise ModelCallError(f"embedding failed: {_format_response_error(exc.response)}") from exc
        except httpx.HTTPError as exc:
            self._emit_failure(stage, "EMBEDDING", self.embedding_model, started, "TRANSPORT", prompt_hash)
            raise ModelCallError(f"embedding failed: {exc}") from exc

        try:
            body = response.json()
            data = sorted(body["data"], key=lambda item: item["index"])
            embeddings = [item["embedding"] for item in data]
        except (KeyError, TypeError, ValueError) as exc:
            self._emit_failure(stage, "EMBEDDING", self.embedding_model, started, "RESPONSE_SCHEMA", prompt_hash)
            raise ModelCallError("embedding response has unexpected shape") from exc
        usage = _usage(body)
        self._emit(
            ModelInvocationTelemetry(
                stage=stage,
                operation="EMBEDDING",
                provider="bailian",
                model=self.embedding_model,
                status="SUCCEEDED",
                duration_ms=_elapsed_ms(started),
                input_tokens=usage[0],
                output_tokens=usage[1],
                total_tokens=usage[2],
                finish_reason=None,
                error_category=None,
                prompt_hash=prompt_hash,
            )
        )
        return embeddings

    def rerank(self, query: str, documents: list[str], top_n: int) -> list[RerankResult]:
        if not query.strip():
            raise ValueError("rerank query must not be blank")
        if not documents:
            return []
        if len(documents) > 100:
            raise ValueError("rerank documents must not exceed 100 candidates")
        normalized_top_n = min(max(1, top_n), len(documents))
        payload: dict[str, Any] = {
            "model": self.rerank_model,
            "query": query,
            "documents": documents,
            "top_n": normalized_top_n,
            "instruct": "Given an operations question, retrieve passages that provide actionable and safe evidence.",
        }
        stage, prompt_hash = self._metadata("rerank", payload)
        started = time.monotonic()
        try:
            with self._client(timeout=60) as client:
                response = client.post(
                    f"{self.rerank_base_url}/reranks",
                    headers=self._headers(),
                    json=payload,
                )
                response.raise_for_status()
        except ModelNotConfiguredError:
            self._emit_failure(stage, "RERANK", self.rerank_model, started, "NOT_CONFIGURED", prompt_hash)
            raise
        except httpx.HTTPStatusError as exc:
            self._emit_failure(
                stage,
                "RERANK",
                self.rerank_model,
                started,
                _http_error_category(exc.response.status_code),
                prompt_hash,
            )
            raise ModelCallError(f"rerank failed: {_format_response_error(exc.response)}") from exc
        except httpx.HTTPError as exc:
            self._emit_failure(stage, "RERANK", self.rerank_model, started, "TRANSPORT", prompt_hash)
            raise ModelCallError(f"rerank failed: {exc}") from exc

        try:
            body = response.json()
            raw_results = body["results"]
            if not isinstance(raw_results, list):
                raise TypeError("results is not a list")
            parsed: list[RerankResult] = []
            seen_indexes: set[int] = set()
            for item in raw_results:
                index = int(item["index"])
                score = float(item["relevance_score"])
                if not 0 <= index < len(documents):
                    raise ModelCallError("rerank response contains an out-of-range document index")
                if index in seen_indexes:
                    raise ModelCallError("rerank response contains duplicate document indexes")
                seen_indexes.add(index)
                parsed.append(RerankResult(index=index, relevance_score=score))
        except ModelCallError:
            self._emit_failure(stage, "RERANK", self.rerank_model, started, "RESPONSE_SCHEMA", prompt_hash)
            raise
        except (KeyError, TypeError, ValueError) as exc:
            self._emit_failure(stage, "RERANK", self.rerank_model, started, "RESPONSE_SCHEMA", prompt_hash)
            raise ModelCallError("rerank response has unexpected shape") from exc
        if not parsed:
            self._emit_failure(stage, "RERANK", self.rerank_model, started, "EMPTY_RESULT", prompt_hash)
            raise ModelCallError("rerank response did not contain ranked documents")
        usage = _usage(body)
        self._emit(
            ModelInvocationTelemetry(
                stage=stage,
                operation="RERANK",
                provider="bailian",
                model=self.rerank_model,
                status="SUCCEEDED",
                duration_ms=_elapsed_ms(started),
                input_tokens=usage[0],
                output_tokens=usage[1],
                total_tokens=usage[2],
                finish_reason=None,
                error_category=None,
                prompt_hash=prompt_hash,
            )
        )
        return parsed[:normalized_top_n]

    def _client(self, *, timeout: int) -> httpx.Client:
        return httpx.Client(timeout=timeout, transport=self.transport)

    def _metadata(self, default_stage: str, payload: dict[str, Any]) -> tuple[str, str]:
        context = self._invocation_context.get()
        stage = context.stage if context is not None else default_stage
        prompt_hash = context.prompt_hash if context is not None else ""
        return stage, prompt_hash or _payload_hash(payload)

    def _emit_failure(
        self,
        stage: str,
        operation: str,
        model: str,
        started: float,
        category: str,
        prompt_hash: str,
    ) -> None:
        self._emit(
            ModelInvocationTelemetry(
                stage=stage,
                operation=operation,
                provider="bailian",
                model=model,
                status="FAILED",
                duration_ms=_elapsed_ms(started),
                input_tokens=None,
                output_tokens=None,
                total_tokens=None,
                finish_reason=None,
                error_category=_bounded_label(category, "UNKNOWN"),
                prompt_hash=prompt_hash,
            )
        )

    def _emit(self, telemetry: ModelInvocationTelemetry) -> None:
        if self.invocation_sink is not None:
            self.invocation_sink(telemetry)


def model_invocation_scope(
    model_client: Any,
    stage: str,
    prompt_hash: str = "",
):
    scope = getattr(model_client, "invocation_scope", None)
    return scope(stage, prompt_hash) if callable(scope) else nullcontext()


def _parse_json_object(content: str) -> dict[str, Any]:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", content, flags=re.DOTALL)
        if match is None:
            raise ModelCallError("model did not return a JSON object")
        parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ModelCallError("model JSON response is not an object")
    return parsed


def _format_response_error(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        body = response.text
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            code = error.get("code") or error.get("type")
            if message and code:
                return f"{response.status_code} {code}: {message}"
            if message:
                return f"{response.status_code}: {message}"
    return f"{response.status_code}: {str(body)[:500]}"


def _payload_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _usage(body: Any) -> tuple[int | None, int | None, int | None]:
    usage = body.get("usage") if isinstance(body, dict) else None
    if not isinstance(usage, dict):
        return None, None, None
    input_tokens = _optional_token_count(
        usage.get("prompt_tokens", usage.get("input_tokens"))
    )
    output_tokens = _optional_token_count(
        usage.get("completion_tokens", usage.get("output_tokens"))
    )
    total_tokens = _optional_token_count(usage.get("total_tokens"))
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    return input_tokens, output_tokens, total_tokens


def _optional_token_count(value: Any) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _http_error_category(status_code: int) -> str:
    if status_code == 429:
        return "RATE_LIMIT"
    if status_code >= 500:
        return "PROVIDER_5XX"
    if status_code in {401, 403}:
        return "AUTHORIZATION"
    return "PROVIDER_4XX"


def _elapsed_ms(started: float) -> int:
    return max(int((time.monotonic() - started) * 1000), 0)


def _bounded_label(value: Any, fallback: str) -> str:
    normalized = "".join(
        character
        for character in str(value or "").strip()
        if character.isalnum() or character in {"_", "-", "."}
    )[:64]
    return normalized or fallback


def _bounded_optional(value: Any) -> str | None:
    if value is None:
        return None
    normalized = _bounded_label(value, "")
    return normalized or None


def _is_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", str(value or "")))
