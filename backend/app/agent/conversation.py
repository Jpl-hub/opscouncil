from __future__ import annotations

from dataclasses import dataclass
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import Conversation, ConversationTurn, Task, utcnow


@dataclass(frozen=True)
class PreparedConversation:
    conversation: Conversation
    parent_task_id: int | None
    next_turn_index: int
    context: list[dict[str, object]]


class ConversationService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def prepare(self, user_input: str, conversation_id: str | None = None) -> PreparedConversation:
        if conversation_id:
            conversation = self.session.get(Conversation, conversation_id)
            if conversation is None:
                raise LookupError("conversation not found")
        else:
            conversation = Conversation(
                id=uuid.uuid4().hex,
                title=_conversation_title(user_input),
            )
            self.session.add(conversation)
            self.session.flush()

        turns = list(
            self.session.execute(
                select(ConversationTurn, Task)
                .join(Task, Task.id == ConversationTurn.task_id)
                .where(ConversationTurn.conversation_id == conversation.id)
                .order_by(ConversationTurn.turn_index.desc())
                .limit(4)
            ).all()
        )
        turns.reverse()
        context = [_context_item(task) for _, task in turns if task.status == "SEALED"]
        parent_task_id = turns[-1][1].id if turns else None
        last_turn_index = turns[-1][0].turn_index if turns else 0
        return PreparedConversation(
            conversation=conversation,
            parent_task_id=parent_task_id,
            next_turn_index=last_turn_index + 1,
            context=context,
        )

    def attach_task(self, task: Task, state: PreparedConversation) -> ConversationTurn:
        turn = ConversationTurn(
            conversation_id=state.conversation.id,
            task_id=task.id,
            parent_task_id=state.parent_task_id,
            turn_index=state.next_turn_index,
        )
        state.conversation.updated_at = utcnow()
        self.session.add(turn)
        self.session.flush()
        return turn

    def get_turn(self, task_id: int) -> ConversationTurn:
        turn = self.session.execute(
            select(ConversationTurn).where(ConversationTurn.task_id == task_id)
        ).scalar_one_or_none()
        if turn is None:
            raise LookupError("conversation turn not found")
        return turn

    def context_for_task(self, task_id: int) -> list[dict[str, object]]:
        current_turn = self.get_turn(task_id)
        turns = list(
            self.session.execute(
                select(ConversationTurn, Task)
                .join(Task, Task.id == ConversationTurn.task_id)
                .where(
                    ConversationTurn.conversation_id == current_turn.conversation_id,
                    ConversationTurn.turn_index < current_turn.turn_index,
                )
                .order_by(ConversationTurn.turn_index.desc())
                .limit(4)
            ).all()
        )
        turns.reverse()
        return [_context_item(task) for _, task in turns if task.status == "SEALED"]

    def list_tasks(self, conversation_id: str) -> list[Task]:
        if self.session.get(Conversation, conversation_id) is None:
            raise LookupError("conversation not found")
        return list(
            self.session.execute(
                select(Task)
                .join(ConversationTurn, ConversationTurn.task_id == Task.id)
                .where(ConversationTurn.conversation_id == conversation_id)
                .order_by(ConversationTurn.turn_index.asc())
            ).scalars()
        )

def _context_item(task: Task) -> dict[str, object]:
    return {
        "task_id": task.id,
        "user_input": _truncate(task.user_input, 500),
        "intent": task.intent,
        "status": task.status,
        "risk_level": task.risk_level,
        "summary": _truncate(task.summary or "", 700),
    }


def _conversation_title(user_input: str) -> str:
    title = " ".join(user_input.split())
    return _truncate(title, 80) or "运维会话"


def _truncate(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return f"{value[: max_chars - 3].rstrip()}..."
