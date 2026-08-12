#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import sys
import time

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.core.config import settings
from backend.app.channels.feishu.approval_queue import ApprovalDecisionProcessor
from backend.app.core.database import SessionLocal, init_db
from backend.app.patrol.service import PatrolService
from backend.app.runtime.health import WorkerHeartbeatReporter
from backend.app.runtime.tool_registry import build_runtime_tool_registry
from backend.app.runtime.worker import TaskWorker


def main() -> int:
    init_db()
    registry = build_runtime_tool_registry(SessionLocal)
    worker_id = os.getenv("OPSCOUNCIL_WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}"
    idle_seconds = max(float(os.getenv("OPSCOUNCIL_WORKER_IDLE_SECONDS", "0.5")), 0.05)
    lease_seconds = max(int(os.getenv("OPSCOUNCIL_WORKER_LEASE_SECONDS", "300")), 30)
    stopping = False

    def request_stop(signum, frame) -> None:  # type: ignore[no-untyped-def]
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    worker = TaskWorker(
        SessionLocal,
        registry,
        worker_id,
        lease_seconds=lease_seconds,
        approval_processor=ApprovalDecisionProcessor(
            SessionLocal,
            registry,
            f"{worker_id}:approval",
            lease_seconds=lease_seconds,
        ),
        patrol_service=(
            PatrolService(
                SessionLocal,
                registry,
                seed_default_policy=settings.patrol_seed_default_policy,
                default_interval_seconds=settings.patrol_interval_seconds,
            )
            if settings.patrol_enabled
            else None
        ),
    )
    heartbeat = WorkerHeartbeatReporter(SessionLocal, worker_id)
    heartbeat.start()
    try:
        while not stopping:
            worked = worker.run_once()
            if not worked and not stopping:
                time.sleep(idle_seconds)
    finally:
        heartbeat.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
