from __future__ import annotations

import secrets
from collections.abc import Callable

from fastapi import Header, HTTPException


def build_internal_channel_auth(configured_token: str) -> Callable[..., None]:
    expected = configured_token.strip()

    def require_internal_channel(
        authorization: str | None = Header(default=None),
    ) -> None:
        if len(expected) < 32:
            raise HTTPException(
                status_code=503,
                detail="internal channel authentication is not configured",
            )
        scheme, separator, supplied = (authorization or "").partition(" ")
        valid = (
            bool(separator)
            and scheme.lower() == "bearer"
            and len(supplied) == len(expected)
            and secrets.compare_digest(supplied, expected)
        )
        if not valid:
            raise HTTPException(status_code=401, detail="invalid internal channel credential")

    return require_internal_channel
