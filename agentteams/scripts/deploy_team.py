#!/usr/bin/env python3
"""Deploy the OpsCouncil response team to AgentTeams v1.2.2."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlparse

from agentteams.scripts.build_packages import (
    DIST_DIR,
    ROLE_BY_AGENT,
    ROOT,
    build_packages,
    derive_token,
)


TEAM_NAME = "opscouncil-response"
MANAGER_CONTAINER = "agentteams-manager"
CONTROLLER_CONTAINER = "agentteams-controller"
AGENTTEAMS_CLI = "agt"
REMOTE_DIR = "/tmp/opscouncil-agentteams"
MODEL_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
TEAM_READY_TIMEOUT_SECONDS = 180.0
TEAM_MESSAGE_PLANE_TIMEOUT_SECONDS = 60.0


class DeploymentError(RuntimeError):
    pass


def _run(args: list[str], *, input_text: str | None = None) -> str:
    try:
        completed = subprocess.run(
            args,
            input=input_text,
            text=True,
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise DeploymentError(f"required command is not installed: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise DeploymentError(f"command failed: {detail}") from exc
    return completed.stdout.strip()


def detect_container_runtime(explicit: str | None = None) -> str:
    candidates = [explicit] if explicit else ["docker", "podman"]
    for candidate in candidates:
        if candidate and shutil.which(candidate):
            return candidate
    raise DeploymentError("docker or podman is required")


def validate_api_url(api_url: str) -> str:
    normalized = api_url.rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise DeploymentError("OpsCouncil API URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise DeploymentError("OpsCouncil API URL must not contain credentials")
    return normalized


def render_team_manifest() -> str:
    rendered = (ROOT / "team.template.yaml").read_text(encoding="utf-8")
    placeholders = sorted(set(re.findall(r"__[A-Z0-9_]+__", rendered)))
    if placeholders:
        raise DeploymentError(f"unresolved Team template placeholders: {placeholders}")
    if "apiVersion: agentteams.io/v1beta1" not in rendered:
        raise DeploymentError("Team template does not use the supported AgentTeams API")
    if rendered.count("role: team_leader") != 1:
        raise DeploymentError("Team template must declare exactly one team leader")
    for agent_name in ROLE_BY_AGENT:
        if rendered.count(f"name: {agent_name}") != 1:
            raise DeploymentError(f"Team template has an invalid member entry for {agent_name}")
    return rendered


def _assert_manager_running(runtime: str) -> None:
    names = _run([runtime, "ps", "--format", "{{.Names}}"])
    running = set(names.splitlines())
    for container in (MANAGER_CONTAINER, CONTROLLER_CONTAINER):
        if container not in running:
            raise DeploymentError(f"{container} is not running")
    _run([runtime, "exec", MANAGER_CONTAINER, AGENTTEAMS_CLI, "version"])
    _run([runtime, "exec", CONTROLLER_CONTAINER, AGENTTEAMS_CLI, "version"])


def _copy_packages(runtime: str) -> None:
    _run([runtime, "exec", MANAGER_CONTAINER, "mkdir", "-p", REMOTE_DIR])
    for agent_name in ROLE_BY_AGENT:
        source = DIST_DIR / "packages" / f"{agent_name}.zip"
        _run([runtime, "cp", str(source), f"{MANAGER_CONTAINER}:{REMOTE_DIR}/{source.name}"])


def _resource_names(runtime: str, plural_kind: str) -> set[str]:
    raw = _run(
        [
            runtime,
            "exec",
            MANAGER_CONTAINER,
            AGENTTEAMS_CLI,
            "get",
            plural_kind,
            "-o",
            "json",
        ]
    )
    try:
        payload = json.loads(raw)
        rows = payload[plural_kind]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise DeploymentError(f"invalid AgentTeams {plural_kind} list response") from exc
    if not isinstance(rows, list):
        raise DeploymentError(f"invalid AgentTeams {plural_kind} list response")
    return {
        str(row.get("name"))
        for row in rows
        if isinstance(row, dict) and str(row.get("name") or "").strip()
    }


def _managed_resources(runtime: str) -> tuple[bool, list[str]]:
    team_exists = TEAM_NAME in _resource_names(runtime, "teams")
    workers = _resource_names(runtime, "workers")
    managed_workers = sorted(set(ROLE_BY_AGENT).intersection(workers))
    return team_exists, managed_workers


def _delete_managed_resources(runtime: str, *, timeout_seconds: float = 90.0) -> None:
    team_exists, workers = _managed_resources(runtime)
    if team_exists:
        _run(
            [
                runtime,
                "exec",
                MANAGER_CONTAINER,
                AGENTTEAMS_CLI,
                "delete",
                "team",
                TEAM_NAME,
            ]
        )
    for agent_name in workers:
        _run(
            [
                runtime,
                "exec",
                MANAGER_CONTAINER,
                AGENTTEAMS_CLI,
                "delete",
                "worker",
                agent_name,
            ]
        )

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        team_exists, workers = _managed_resources(runtime)
        if not team_exists and not workers:
            return
        time.sleep(2.0)
    raise DeploymentError("timed out waiting for existing AgentTeams resources to be removed")


def _apply_worker_packages(runtime: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for agent_name in ROLE_BY_AGENT:
        remote_path = f"{REMOTE_DIR}/{agent_name}.zip"
        results[agent_name] = _run(
            [
                runtime,
                "exec",
                MANAGER_CONTAINER,
                AGENTTEAMS_CLI,
                "apply",
                "worker",
                "--zip",
                remote_path,
                "--name",
                agent_name,
            ]
        )
    return results


def _worker_container_name(agent_name: str) -> str:
    return f"agentteams-worker-{agent_name}"


def _verify_team_room_members(runtime: str, *, room_id: str) -> dict[str, Any]:
    """Require all declared Agent identities to be joined to the Team room."""

    verify_script = """\
import json
import os
from urllib.parse import quote
from urllib.request import Request, urlopen

base = os.environ["AGENTTEAMS_MATRIX_URL"].rstrip("/")
room_id = os.environ["OPSCOUNCIL_TEAM_ROOM_ID"]
token = os.environ["AGENTTEAMS_WORKER_MATRIX_TOKEN"]
agent_names = json.loads(os.environ["OPSCOUNCIL_TEAM_AGENT_NAMES"])
domain = os.environ["AGENTTEAMS_MATRIX_DOMAIN"]
expected = {"@" + name + ":" + domain for name in agent_names}
url = (
    base
    + "/_matrix/client/v3/rooms/"
    + quote(room_id, safe="")
    + "/joined_members"
)
request = Request(url, headers={"Authorization": "Bearer " + token})
with urlopen(request, timeout=15) as response:
    payload = json.load(response)
joined = set((payload.get("joined") or {}).keys())
missing = sorted(expected - joined)
print(json.dumps({"joined_agents": sorted(expected & joined), "missing": missing}))
if missing:
    raise SystemExit("Team room is missing Agent identities: " + ", ".join(missing))
"""
    raw = _run(
        [
            runtime,
            "exec",
            "-e",
            f"OPSCOUNCIL_TEAM_ROOM_ID={room_id}",
            "-e",
            "OPSCOUNCIL_TEAM_AGENT_NAMES=" + json.dumps(sorted(ROLE_BY_AGENT)),
            _worker_container_name("incident-commander"),
            "python3",
            "-c",
            verify_script,
        ]
    )
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DeploymentError("invalid Matrix Team membership response") from exc
    if result.get("missing") or len(result.get("joined_agents") or []) != len(ROLE_BY_AGENT):
        raise DeploymentError("AgentTeams Team room membership is incomplete")
    return result


def _ensure_team_message_plane(runtime: str, *, room_id: str) -> dict[str, Any]:
    if not room_id:
        raise DeploymentError("AgentTeams Team is Active but has no teamRoomID")
    deadline = time.monotonic() + TEAM_MESSAGE_PLANE_TIMEOUT_SECONDS
    last_error = ""
    while time.monotonic() < deadline:
        try:
            return _verify_team_room_members(runtime, room_id=room_id)
        except DeploymentError as exc:
            last_error = str(exc)
            time.sleep(1.0)
    raise DeploymentError(
        "timed out waiting for all Agent identities to join the Team room"
        + (f": {last_error}" if last_error else "")
    )


def _apply_team(runtime: str, manifest: str) -> str:
    local_manifest = DIST_DIR / "team.yaml"
    local_manifest.write_text(manifest, encoding="utf-8")
    remote_manifest = f"{REMOTE_DIR}/team.yaml"
    _run([runtime, "exec", CONTROLLER_CONTAINER, "mkdir", "-p", REMOTE_DIR])
    _run(
        [
            runtime,
            "cp",
            str(local_manifest),
            f"{CONTROLLER_CONTAINER}:{remote_manifest}",
        ]
    )
    create_script = f"""\
token="$(cut -d, -f1 /data/agentteams-controller/pki/token.csv | head -1)"
test -n "$token"
api="https://127.0.0.1:6443/apis/agentteams.io/v1beta1/namespaces/default"
ca="/data/agentteams-controller/pki/ca.crt"
payload="{REMOTE_DIR}/team.json"
response="{REMOTE_DIR}/team-response.json"
yq -o=json '.' "{remote_manifest}" >"$payload"
status="$(curl --silent --show-error --cacert "$ca" \\
  -H "Authorization: Bearer $token" \\
  -o /dev/null -w '%{{http_code}}' \\
  "$api/teams/{TEAM_NAME}")"
if [ "$status" != "404" ]; then
  echo "team resource must not exist before create (HTTP $status)" >&2
  exit 1
fi
curl --fail --silent --show-error --cacert "$ca" \\
  -H "Authorization: Bearer $token" \\
  -H 'Content-Type: application/json' \\
  --data-binary "@$payload" \\
  -o "$response" \\
  "$api/teams"
yq -r '"team/" + .metadata.name + " accepted by " + .apiVersion' "$response"
"""
    create_output = _run(
        [
            runtime,
            "exec",
            "-i",
            CONTROLLER_CONTAINER,
            "sh",
            "-seu",
        ],
        input_text=create_script,
    )
    deadline = time.monotonic() + TEAM_READY_TIMEOUT_SECONDS
    last_status: dict[str, Any] = {}
    while time.monotonic() < deadline:
        raw = _run(
            [
                runtime,
                "exec",
                MANAGER_CONTAINER,
                AGENTTEAMS_CLI,
                "get",
                "teams",
                TEAM_NAME,
                "-o",
                "json",
            ]
        )
        try:
            last_status = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DeploymentError("invalid AgentTeams Team status response") from exc
        phase = str(last_status.get("phase") or "")
        ready = int(last_status.get("readyWorkers") or 0)
        total = int(last_status.get("totalWorkers") or 0)
        if phase == "Active" and bool(last_status.get("leaderReady")) and ready == total:
            membership = _ensure_team_message_plane(
                runtime,
                room_id=str(last_status.get("teamRoomID") or ""),
            )
            return "\n".join(
                (create_output, raw, json.dumps(membership, ensure_ascii=False))
            )
        if phase == "Failed":
            raise DeploymentError(
                "AgentTeams Team reconciliation failed: "
                + str(last_status.get("message") or "unknown error")
            )
        time.sleep(2.0)
    raise DeploymentError(
        "timed out waiting for AgentTeams Team to become ready: "
        + json.dumps(last_status, ensure_ascii=False)
    )


def deploy(
    *,
    runtime: str,
    api_url: str,
    model: str,
    callback_secret: str,
    replace: bool = False,
) -> dict[str, Any]:
    _assert_manager_running(runtime)
    if not MODEL_PATTERN.fullmatch(model):
        raise DeploymentError("agent model contains unsupported characters")

    team_exists, workers = _managed_resources(runtime)
    if team_exists or workers:
        if not replace:
            names = ([TEAM_NAME] if team_exists else []) + workers
            raise DeploymentError(
                "managed AgentTeams resources already exist: "
                + ", ".join(names)
                + "; rerun with --replace to recreate packages and role instructions"
            )
        _delete_managed_resources(runtime)

    build_packages(api_url=api_url, model=model, callback_secret=callback_secret)
    _copy_packages(runtime)
    worker_results = _apply_worker_packages(runtime)
    status = _apply_team(runtime, render_team_manifest())

    controller_env = DIST_DIR / "policy-controller.env"
    controller_env.write_text(
        "OPSCOUNCIL_API_URL=" + api_url + "\n"
        "OPSCOUNCIL_CONTROLLER_ID=policy-controller\n"
        "OPSCOUNCIL_CONTROLLER_TOKEN="
        + derive_token(callback_secret, "controller:policy-controller")
        + "\n",
        encoding="utf-8",
    )
    controller_env.chmod(0o600)
    return {
        "team": TEAM_NAME,
        "manifest": str(DIST_DIR / "team.yaml"),
        "workers": worker_results,
        "status": status,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default=os.environ.get("OPSCOUNCIL_API_URL", ""))
    parser.add_argument("--model", default=os.environ.get("OPSCOUNCIL_AGENT_MODEL", "qwen3.6-plus"))
    parser.add_argument("--container-runtime", choices=("docker", "podman"))
    parser.add_argument(
        "--replace",
        action="store_true",
        help="delete and recreate the managed AgentTeams resources",
    )
    args = parser.parse_args()

    callback_secret = os.environ.get("AGENTTEAMS_CALLBACK_SECRET", "")
    if not callback_secret:
        parser.error("AGENTTEAMS_CALLBACK_SECRET must be set")
    if not args.api_url:
        parser.error("OPSCOUNCIL_API_URL or --api-url is required")

    try:
        result = deploy(
            runtime=detect_container_runtime(args.container_runtime),
            api_url=validate_api_url(args.api_url),
            model=args.model,
            callback_secret=callback_secret,
            replace=args.replace,
        )
    except DeploymentError as exc:
        print(f"deployment failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
