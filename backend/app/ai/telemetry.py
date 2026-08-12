from __future__ import annotations

import re

from sqlalchemy.orm import Session

from backend.app.ai.client import ModelInvocationTelemetry
from backend.app.models.entities import ModelInvocation, Task


class ModelInvocationRecorder:
    def __init__(self, session: Session, task: Task) -> None:
        if task.id is None or not task.trace_id:
            raise ValueError("model telemetry requires a persisted task")
        self.session = session
        self.task_id = task.id
        self.trace_id = task.trace_id

    def __call__(self, telemetry: ModelInvocationTelemetry) -> ModelInvocation:
        if not re.fullmatch(r"[0-9a-f]{64}", telemetry.prompt_hash):
            raise ValueError("model telemetry prompt hash is invalid")
        invocation = ModelInvocation(
            task_id=self.task_id,
            trace_id=self.trace_id,
            stage=_label(telemetry.stage, 64),
            operation=_label(telemetry.operation, 16),
            provider=_label(telemetry.provider, 32),
            model=_label(telemetry.model, 128),
            status=_label(telemetry.status, 16),
            duration_ms=max(int(telemetry.duration_ms), 0),
            input_tokens=_tokens(telemetry.input_tokens),
            output_tokens=_tokens(telemetry.output_tokens),
            total_tokens=_tokens(telemetry.total_tokens),
            finish_reason=_optional(telemetry.finish_reason, 64),
            error_category=_optional(telemetry.error_category, 64),
            prompt_hash=telemetry.prompt_hash,
        )
        self.session.add(invocation)
        return invocation


def _label(value: str, max_chars: int) -> str:
    normalized = "".join(
        character for character in str(value).strip() if character.isalnum() or character in {"_", "-", "."}
    )[:max_chars]
    if not normalized:
        raise ValueError("model telemetry label is empty")
    return normalized


def _optional(value: str | None, max_chars: int) -> str | None:
    if not value:
        return None
    return _label(value, max_chars)


def _tokens(value: int | None) -> int | None:
    if value is None:
        return None
    return max(int(value), 0)
