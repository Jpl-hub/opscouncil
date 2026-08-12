from __future__ import annotations

from dataclasses import dataclass
import uuid

from sqlalchemy.orm import Session

from backend.app.agent.conversation import ConversationService
from backend.app.audit.service import AuditService
from backend.app.models.entities import Task, TaskJob
from backend.app.schemas.enums import TaskStatus


@dataclass(frozen=True)
class AcceptedTask:
    task: Task
    job: TaskJob
    conversation_id: str
    parent_task_id: int | None


class TaskIntakeService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.conversations = ConversationService(session)
        self.audit = AuditService(session)

    def accept(self, user_input: str, conversation_id: str | None = None) -> AcceptedTask:
        conversation = self.conversations.prepare(user_input, conversation_id)
        task = Task(
            trace_id=uuid.uuid4().hex,
            user_input=user_input,
            status=TaskStatus.RECEIVED.value,
        )
        self.session.add(task)
        self.session.flush()
        self.conversations.attach_task(task, conversation)
        self.audit.append_event(
            task,
            TaskStatus.RECEIVED.value,
            "task_created",
            "接收自然语言运维请求，任务已进入执行队列。",
            {
                "user_input": user_input,
                "conversation_id": conversation.conversation.id,
                "parent_task_id": conversation.parent_task_id,
            },
        )
        job = TaskJob(task_id=task.id, status="QUEUED")
        self.session.add(job)
        self.session.flush()
        return AcceptedTask(
            task=task,
            job=job,
            conversation_id=conversation.conversation.id,
            parent_task_id=conversation.parent_task_id,
        )
