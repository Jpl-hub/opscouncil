from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote
import uuid

import httpx


class AgentTeamsConfigurationError(RuntimeError):
    pass


class AgentTeamsProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentTeamsConnection:
    matrix_url: str
    username: str
    password: str
    leader_room_id: str
    server_name: str = "agentteams"

    @property
    def configured(self) -> bool:
        return all(
            value.strip()
            for value in (
                self.matrix_url,
                self.username,
                self.password,
                self.leader_room_id,
            )
        )


class AgentTeamsClient:
    """Small Matrix adapter for AgentTeams task dispatch and health inspection."""

    def __init__(
        self,
        connection: AgentTeamsConnection,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.connection = connection
        self.timeout_seconds = timeout_seconds

    def status(self) -> dict[str, Any]:
        if not self.connection.configured:
            return {
                "configured": False,
                "reachable": False,
                "server": self.connection.server_name,
                "reason": "AgentTeams Matrix connection is not configured",
            }
        try:
            response = httpx.get(
                f"{self.connection.matrix_url.rstrip('/')}/_matrix/client/versions",
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return {
                "configured": True,
                "reachable": False,
                "server": self.connection.server_name,
                "reason": str(exc),
            }
        return {
            "configured": True,
            "reachable": True,
            "server": self.connection.server_name,
            "versions": response.json().get("versions", []),
        }

    def dispatch_incident(self, payload: dict[str, Any]) -> str:
        if not self.connection.configured:
            raise AgentTeamsConfigurationError(
                "AgentTeams Matrix connection is not configured"
            )
        token = self._login()
        transaction_id = uuid.uuid4().hex
        room_id = quote(self.connection.leader_room_id, safe="")
        url = (
            f"{self.connection.matrix_url.rstrip('/')}/_matrix/client/v3/rooms/"
            f"{room_id}/send/m.room.message/{transaction_id}"
        )
        message = {
            "msgtype": "m.text",
            "body": _dispatch_message(payload),
            "org.opscouncil.incident": payload,
        }
        try:
            response = httpx.put(
                url,
                headers={"Authorization": f"Bearer {token}"},
                json=message,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise AgentTeamsProtocolError(f"AgentTeams dispatch failed: {exc}") from exc
        event_id = str(response.json().get("event_id") or "").strip()
        if not event_id:
            raise AgentTeamsProtocolError("AgentTeams dispatch returned no event_id")
        return event_id

    def _login(self) -> str:
        try:
            response = httpx.post(
                f"{self.connection.matrix_url.rstrip('/')}/_matrix/client/v3/login",
                json={
                    "type": "m.login.password",
                    "identifier": {
                        "type": "m.id.user",
                        "user": self.connection.username,
                    },
                    "password": self.connection.password,
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise AgentTeamsProtocolError(f"AgentTeams login failed: {exc}") from exc
        token = str(response.json().get("access_token") or "").strip()
        if not token:
            raise AgentTeamsProtocolError("AgentTeams login returned no access token")
        return token


def _dispatch_message(payload: dict[str, Any]) -> str:
    incident = payload.get("incident") or {}
    return (
        "[OpsCouncil Incident Assignment]\n"
        f"collaboration_id: {payload.get('id')}\n"
        f"incident_id: {incident.get('id')}\n"
        f"severity: {incident.get('severity')}\n"
        f"title: {incident.get('title')}\n"
        "Read the structured org.opscouncil.incident event, claim only work assigned "
        "to your Agent Identity, and return output conforming to the Skill schema."
    )
