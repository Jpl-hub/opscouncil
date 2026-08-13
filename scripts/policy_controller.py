#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import signal
import sys
import time
import urllib.request


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.collaboration.policy_controller import PolicyControllerProcessor
from backend.app.core.config import settings
from backend.app.core.database import SessionLocal, init_db
from backend.app.runtime.tool_registry import build_runtime_tool_registry


def main() -> int:
    init_db()
    registry = build_runtime_tool_registry(SessionLocal)
    controller_id = os.getenv(
        "OPSCOUNCIL_POLICY_CONTROLLER_ID",
        "policy-controller",
    )
    idle_seconds = max(settings.policy_controller_idle_seconds, 0.05)
    lease_seconds = max(settings.policy_controller_lease_seconds, 30)
    stopping = False

    def request_stop(signum, frame) -> None:  # type: ignore[no-untyped-def]
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    controller = PolicyControllerProcessor(
        SessionLocal,
        registry,
        controller_id,
        ready_notifier=_notify_ready_work,
        lease_seconds=lease_seconds,
    )
    while not stopping:
        worked = controller.run_once()
        if not worked and not stopping:
            time.sleep(idle_seconds)
    return 0


def _notify_ready_work(collaboration_id: int, work_key: str) -> None:
    if work_key == "execute":
        return
    base_url = os.getenv("OPSCOUNCIL_API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    request = urllib.request.Request(
        f"{base_url}/api/collaboration/incidents/{collaboration_id}/agentteams/dispatch",
        data=b"",
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"AgentTeams dispatch returned HTTP {response.status}")


if __name__ == "__main__":
    raise SystemExit(main())
