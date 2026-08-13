from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote
import json
import uuid

import httpx

from backend.app.collaboration.manifest import AGENT_NAME_BY_ROLE
from backend.app.collaboration.contracts import OUTPUT_MODELS


class AgentTeamsConfigurationError(RuntimeError):
    pass


class AgentTeamsProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentTeamsConnection:
    matrix_url: str
    username: str
    password: str
    team_room_id: str
    leader_user_id: str
    server_name: str = "agentteams"

    @property
    def configured(self) -> bool:
        return all(
            value.strip()
            for value in (
                self.matrix_url,
                self.username,
                self.password,
                self.team_room_id,
                self.leader_user_id,
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
        target_user_id = _dispatch_target(payload, self.connection)
        transaction_id = uuid.uuid4().hex
        room_id = quote(self.connection.team_room_id, safe="")
        url = (
            f"{self.connection.matrix_url.rstrip('/')}/_matrix/client/v3/rooms/"
            f"{room_id}/send/m.room.message/{transaction_id}"
        )
        message = {
            "msgtype": "m.text",
            "body": _dispatch_message(payload, target_user_id),
            "m.mentions": {"user_ids": [target_user_id]},
            "org.opscouncil.incident": _matrix_canonical(_dispatch_envelope(payload)),
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


def _dispatch_message(payload: dict[str, Any], target_user_id: str) -> str:
    envelope = _matrix_canonical(_dispatch_envelope(payload))
    incident = payload.get("incident") or {}
    ready_items = envelope["ready_work_items"]
    running_items = envelope["running_work_items"]
    if ready_items:
        instruction = (
            "Use the authenticated callback client to claim the single READY item now, "
            "execute only the bound Skill, and submit exactly the supplied output_contract. "
            "Do not delegate the item or alter runtime identity."
        )
    elif running_items:
        instruction = (
            "Resume the single RUNNING item already leased to this identity. Do not claim it "
            "again; submit exactly the supplied output_contract. Do not alter runtime identity."
        )
    else:
        instruction = "Inspect the control-plane state and coordinate only work explicitly assigned."
    return (
        f"{target_user_id} [OpsCouncil Incident Assignment]\n"
        f"collaboration_id: {payload.get('id')}\n"
        f"incident_id: {incident.get('id')}\n"
        f"severity: {incident.get('severity')}\n"
        f"title: {incident.get('title')}\n"
        "The JSON envelope below is the authoritative control-plane context. "
        f"Do not search for a separate event file. {instruction}\n"
        f"{json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(',', ':'))}"
    )


def _dispatch_target(
    payload: dict[str, Any],
    connection: AgentTeamsConnection,
) -> str:
    ready_items = [
        item
        for item in payload.get("work_items") or []
        if item.get("status") == "READY"
    ]
    target_items = ready_items
    if not target_items:
        target_items = [
            item
            for item in payload.get("work_items") or []
            if item.get("status") == "RUNNING" and item.get("assigned_agent")
        ]
    if len(target_items) != 1:
        return connection.leader_user_id
    role = str(target_items[0].get("role") or "")
    agent_name = AGENT_NAME_BY_ROLE.get(role)
    if not agent_name:
        return connection.leader_user_id
    return _matrix_sibling_user_id(connection.leader_user_id, agent_name)


def _matrix_sibling_user_id(leader_user_id: str, agent_name: str) -> str:
    if not leader_user_id.startswith("@") or ":" not in leader_user_id:
        raise AgentTeamsConfigurationError("AgentTeams leader user ID is invalid")
    _, server = leader_user_id[1:].split(":", 1)
    return f"@{agent_name}:{server}"


def _matrix_canonical(value: Any) -> Any:
    """Convert schema number bounds to Matrix canonical-JSON-safe values."""
    if isinstance(value, dict):
        return {key: _matrix_canonical(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_matrix_canonical(item) for item in value]
    if isinstance(value, float):
        return format(value, ".15g")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < -(2**53 - 1) or value > 2**53 - 1:
            return str(value)
    return value


def _dispatch_envelope(payload: dict[str, Any]) -> dict[str, Any]:
    shared_context = payload.get("shared_context") or {}
    outputs = shared_context.get("outputs") or {}
    ready_items = [
        {
            "work_key": item.get("work_key"),
            "role": item.get("role"),
            "skill_id": item.get("skill_id"),
            "context_version": (item.get("input") or {}).get("context_version"),
        }
        for item in payload.get("work_items") or []
        if item.get("status") == "READY"
    ]
    running_items = [
        {
            "work_key": item.get("work_key"),
            "role": item.get("role"),
            "skill_id": item.get("skill_id"),
            "assigned_agent": item.get("assigned_agent"),
            "context_version": (item.get("input") or {}).get("context_version"),
        }
        for item in payload.get("work_items") or []
        if item.get("status") == "RUNNING" and item.get("assigned_agent")
    ]
    active_items = ready_items or running_items
    output_contract = None
    if len(active_items) == 1:
        model = OUTPUT_MODELS.get(str(active_items[0].get("work_key") or ""))
        if model is not None:
            output_contract = (
                model.model_json_schema()
                if hasattr(model, "model_json_schema")
                else model.schema()
            )
    audit = payload.get("audit") or {}
    return {
        "id": payload.get("id"),
        "collaboration_id": payload.get("id"),
        "context_version": payload.get("context_version"),
        "incident": payload.get("incident"),
        "context_refs": {
            "initial_evidence_refs": shared_context.get("initial_evidence_refs") or [],
            "accepted_output_keys": sorted(outputs),
            "action_candidates": [
                {
                    "proposal_id": candidate.get("proposal_id"),
                    "tool_name": candidate.get("tool_name"),
                    "risk_level": candidate.get("risk_level"),
                }
                for candidate in shared_context.get("action_candidates") or []
            ],
            "execution_policy": shared_context.get("execution_policy") or {},
        },
        "ready_work_items": ready_items,
        "running_work_items": running_items,
        "output_contract": output_contract,
        "audit": {
            "valid": audit.get("valid"),
            "event_count": audit.get("event_count"),
            "head_hash": audit.get("head_hash"),
        },
        "claim_contract": (
            "The assigned Agent must call its authenticated callback claim endpoint to "
            "retrieve the complete accepted context for this context_version."
        ),
    }
