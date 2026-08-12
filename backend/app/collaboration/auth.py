from __future__ import annotations

import hashlib
import hmac

from backend.app.core.config import settings


class CollaborationIdentityConfigurationError(RuntimeError):
    pass


def derive_callback_token(subject: str, *, secret: str | None = None) -> str:
    normalized_subject = subject.strip()
    if not normalized_subject:
        raise ValueError("callback identity subject is required")
    key = (secret if secret is not None else settings.agentteams_callback_secret).encode("utf-8")
    if not key:
        raise CollaborationIdentityConfigurationError(
            "AgentTeams callback secret is not configured"
        )
    message = f"opscouncil-callback:{normalized_subject}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def callback_token_matches(subject: str, received: str | None) -> bool:
    if not received:
        return False
    return hmac.compare_digest(received, derive_callback_token(subject))
