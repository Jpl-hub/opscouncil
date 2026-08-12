#!/usr/bin/env python3
"""Deploy the OpsCouncil response team to AgentTeams v1.2 or newer."""

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
REMOTE_DIR = "/tmp/opscouncil-agentteams"
MODEL_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


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
    if MANAGER_CONTAINER not in names.splitlines():
        raise DeploymentError(f"{MANAGER_CONTAINER} is not running")
    _run([runtime, "exec", MANAGER_CONTAINER, "agt", "version"])


def _copy_packages(runtime: str) -> None:
    _run([runtime, "exec", MANAGER_CONTAINER, "mkdir", "-p", REMOTE_DIR])
    for agent_name in ROLE_BY_AGENT:
        source = DIST_DIR / "packages" / f"{agent_name}.zip"
        _run([runtime, "cp", str(source), f"{MANAGER_CONTAINER}:{REMOTE_DIR}/{source.name}"])


def _resource_names(runtime: str, plural_kind: str) -> set[str]:
    raw = _run(
        [runtime, "exec", MANAGER_CONTAINER, "agt", "get", plural_kind, "-o", "json"]
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
        _run([runtime, "exec", MANAGER_CONTAINER, "agt", "delete", "team", TEAM_NAME])
    for agent_name in workers:
        _run([runtime, "exec", MANAGER_CONTAINER, "agt", "delete", "worker", agent_name])

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
                "agt",
                "apply",
                "worker",
                "--zip",
                remote_path,
                "--name",
                agent_name,
            ]
        )
    return results


def _apply_team(runtime: str, manifest: str) -> str:
    local_manifest = DIST_DIR / "team.yaml"
    local_manifest.write_text(manifest, encoding="utf-8")
    remote_manifest = f"{REMOTE_DIR}/team.yaml"
    _run([runtime, "cp", str(local_manifest), f"{MANAGER_CONTAINER}:{remote_manifest}"])
    apply_output = _run(
        [runtime, "exec", MANAGER_CONTAINER, "agt", "apply", "-f", remote_manifest]
    )
    status_output = _run(
        [
            runtime,
            "exec",
            MANAGER_CONTAINER,
            "agt",
            "get",
            "teams",
            TEAM_NAME,
            "-o",
            "json",
        ]
    )
    return "\n".join(item for item in (apply_output, status_output) if item)


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
