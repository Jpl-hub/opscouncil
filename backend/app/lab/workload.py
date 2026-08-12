from __future__ import annotations

import argparse
import ctypes
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import resource
import signal
import threading
import time
from typing import Any


_STOP = threading.Event()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded OpsBench workload")
    parser.add_argument(
        "mode",
        choices=(
            "zombie",
            "fd",
            "deleted-open",
            "cpu-memory",
            "io",
            "listener",
            "service-degradation",
        ),
    )
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--state-path", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--fd-count", type=int, default=96)
    parser.add_argument("--fd-soft-limit", type=int, default=128)
    parser.add_argument("--memory-mb", type=int, default=64)
    parser.add_argument("--file-size-mb", type=int, default=16)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--dependency-port", type=int, default=18091)
    parser.add_argument("--dependency-delay-ms", type=int, default=450)
    parser.add_argument("--dependency-timeout-ms", type=int, default=120)
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.state_path.parent.mkdir(parents=True, exist_ok=True)

    if args.mode == "zombie":
        _run_zombie(args)
    elif args.mode == "fd":
        _run_fd(args)
    elif args.mode == "deleted-open":
        _run_deleted_open(args)
    elif args.mode == "cpu-memory":
        _run_cpu_memory(args)
    elif args.mode == "io":
        _run_io(args)
    elif args.mode == "service-degradation":
        _run_service_degradation(args)
    else:
        _run_listener(args)


def _run_zombie(args: argparse.Namespace) -> None:
    child_pid = os.fork()
    if child_pid == 0:
        os._exit(0)
    _write_state(
        args.state_path,
        {
            "scenario_id": args.scenario_id,
            "mode": args.mode,
            "pid": os.getpid(),
            "child_pid": child_pid,
            "created_at": time.time(),
        },
    )
    _sleep_until_stopped()


def _run_fd(args: argparse.Namespace) -> None:
    count = min(max(args.fd_count, 16), 256)
    requested_soft_limit = min(max(args.fd_soft_limit, count + 8), 512)
    _, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    soft_limit = (
        requested_soft_limit
        if hard_limit == resource.RLIM_INFINITY
        else min(requested_soft_limit, hard_limit)
    )
    if soft_limit < count + 8:
        raise ValueError("file descriptor hard limit is too low for the bounded workload")
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, hard_limit))

    fd_root = args.work_dir / "open-files"
    fd_root.mkdir(parents=True, exist_ok=True)
    handles = []
    for index in range(count):
        path = fd_root / f"fd-{index:03d}.log"
        handle = path.open("w+b")
        handle.write(f"opsbench fd {index}\n".encode("ascii"))
        handle.flush()
        handles.append(handle)
    actual_fd_count = len(list(Path("/proc/self/fd").iterdir()))
    _write_state(
        args.state_path,
        {
            "scenario_id": args.scenario_id,
            "mode": args.mode,
            "pid": os.getpid(),
            "open_file_count": len(handles),
            "actual_fd_count": actual_fd_count,
            "max_open_files_soft": soft_limit,
            "max_open_files_hard": (
                None if hard_limit == resource.RLIM_INFINITY else hard_limit
            ),
            "fd_utilization_percent": round(actual_fd_count / soft_limit * 100, 2),
            "created_at": time.time(),
        },
    )
    try:
        _sleep_until_stopped()
    finally:
        for handle in handles:
            handle.close()


def _run_deleted_open(args: argparse.Namespace) -> None:
    file_size_mb = min(max(args.file_size_mb, 4), 24)
    target = args.work_dir / "rotated-worker.log"
    target_bytes = file_size_mb * 1024 * 1024
    block = b"OpsBench deleted-open-file evidence\n" * 1024
    handle = target.open("w+b", buffering=0)
    try:
        remaining = target_bytes
        while remaining:
            payload = block[:remaining]
            handle.write(payload)
            remaining -= len(payload)
        handle.flush()
        os.fsync(handle.fileno())
        file_stat = os.fstat(handle.fileno())
        target.unlink()
        _write_state(
            args.state_path,
            {
                "scenario_id": args.scenario_id,
                "mode": args.mode,
                "pid": os.getpid(),
                "target_path": str(target),
                "retained_bytes": int(file_stat.st_size),
                "inode": int(file_stat.st_ino),
                "device": int(file_stat.st_dev),
                "fd": handle.fileno(),
                "path_removed": not target.exists(),
                "created_at": time.time(),
            },
        )
        _sleep_until_stopped()
    finally:
        handle.close()


def _run_cpu_memory(args: argparse.Namespace) -> None:
    memory_mb = min(max(args.memory_mb, 16), 96)
    allocation = bytearray(memory_mb * 1024 * 1024)
    for offset in range(0, len(allocation), 4096):
        allocation[offset] = 1
    value = 0
    warmup_started_at = time.monotonic()
    warmup_cpu_started_at = time.process_time()
    while time.process_time() - warmup_cpu_started_at < 0.15:
        for index in range(50_000):
            value = (value + index) % 1_000_003
    warmup_cpu_seconds = time.process_time() - warmup_cpu_started_at
    warmup_wall_seconds = time.monotonic() - warmup_started_at
    _write_state(
        args.state_path,
        {
            "scenario_id": args.scenario_id,
            "mode": args.mode,
            "pid": os.getpid(),
            "allocated_bytes": len(allocation),
            "warmup_cpu_seconds": round(warmup_cpu_seconds, 4),
            "warmup_wall_seconds": round(warmup_wall_seconds, 4),
            "created_at": time.time(),
        },
    )
    while not _STOP.is_set():
        for index in range(200_000):
            value = (value + index) % 1_000_003
        if value < 0:
            allocation[0] = value


def _run_io(args: argparse.Namespace) -> None:
    file_size_mb = min(max(args.file_size_mb, 4), 32)
    target = args.work_dir / "io-pressure.bin"
    target_bytes = file_size_mb * 1024 * 1024
    block = b"K" * (1024 * 1024)
    with target.open("wb", buffering=0) as handle:
        handle.truncate(target_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    _write_state(
        args.state_path,
        {
            "scenario_id": args.scenario_id,
            "mode": args.mode,
            "pid": os.getpid(),
            "target_path": str(target),
            "bounded_file_bytes": target_bytes,
            "created_at": time.time(),
        },
    )
    with target.open("r+b", buffering=0) as handle:
        while not _STOP.is_set():
            handle.seek(0)
            written = 0
            while written < target_bytes and not _STOP.is_set():
                payload_size = min(len(block), target_bytes - written)
                handle.write(block[:payload_size])
                written += payload_size
            handle.flush()
            os.fsync(handle.fileno())


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        payload = b'{"service":"opsbench","status":"ready"}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        return


def _run_listener(args: argparse.Namespace) -> None:
    server = ThreadingHTTPServer((args.bind, args.port), _HealthHandler)
    server.timeout = 0.2
    _write_state(
        args.state_path,
        {
            "scenario_id": args.scenario_id,
            "mode": args.mode,
            "pid": os.getpid(),
            "bind": args.bind,
            "port": args.port,
            "created_at": time.time(),
        },
    )
    try:
        while not _STOP.is_set():
            server.handle_request()
    finally:
        server.server_close()


def _run_service_degradation(args: argparse.Namespace) -> None:
    dependency_delay_ms = min(max(args.dependency_delay_ms, 200), 1200)
    dependency_timeout_ms = min(max(args.dependency_timeout_ms, 50), 500)
    if dependency_timeout_ms >= dependency_delay_ms:
        raise ValueError("dependency timeout must be shorter than dependency delay")

    log_path = args.work_dir / "checkout-service.jsonl"
    decoy_config_path = args.work_dir / "checkout-service.conf"
    config_content = (
        "# OpsBench controlled service configuration\n"
        "service.mode = production\n"
        "dependency.timeout_ms = 120\n"
    )
    decoy_config_path.write_text(config_content, encoding="utf-8")
    baseline_stat = decoy_config_path.stat()
    baseline_hash = hashlib.sha256(config_content.encode("utf-8")).hexdigest()
    time.sleep(0.02)
    os.utime(decoy_config_path, None)
    changed_stat = decoy_config_path.stat()

    log_lock = threading.Lock()

    def append_log(event: str, **fields: Any) -> None:
        row = {
            "timestamp_ns": time.time_ns(),
            "service": "checkout-api",
            "event": event,
            **fields,
        }
        with log_lock, log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    class DependencyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path == "/__relationship":
                payload = b'{"status":"connected","component":"inventory-db"}\n'
            else:
                time.sleep(dependency_delay_ms / 1000)
                payload = b'{"status":"ready","component":"inventory-db"}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                self.wfile.write(payload)
            except BrokenPipeError:
                pass

        def log_message(self, format: str, *values: Any) -> None:
            return

    class FrontendHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            correlation_id = f"kg-{time.time_ns()}"
            started = time.monotonic()
            connection = http.client.HTTPConnection(
                "127.0.0.1",
                args.dependency_port,
                timeout=dependency_timeout_ms / 1000,
            )
            try:
                connection.request("GET", "/ready")
                response = connection.getresponse()
                response.read(4096)
                dependency_ok = 200 <= response.status < 300
            except (OSError, TimeoutError):
                dependency_ok = False
            finally:
                connection.close()

            latency_ms = int((time.monotonic() - started) * 1000)
            if dependency_ok:
                payload = {
                    "service": "checkout-api",
                    "status": "ready",
                    "correlation_id": correlation_id,
                }
                status_code = 200
            else:
                payload = {
                    "service": "checkout-api",
                    "status": "degraded",
                    "dependency": "inventory-db",
                    "reason": "dependency_timeout",
                    "correlation_id": correlation_id,
                    "log_path": str(log_path),
                }
                status_code = 503
                append_log(
                    "request_failed",
                    correlation_id=correlation_id,
                    dependency="inventory-db",
                    reason="dependency_timeout",
                    **{
                        "server.address": "127.0.0.1",
                        "server.port": args.dependency_port,
                        "network.transport": "tcp",
                        "http.request.method": "GET",
                        "error.type": "timeout",
                    },
                    dependency_timeout_ms=dependency_timeout_ms,
                    observed_latency_ms=latency_ms,
                    http_status=status_code,
                )

            encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *values: Any) -> None:
            return

    dependency_pid = os.fork()
    if dependency_pid == 0:
        _STOP.clear()
        _set_process_name("kg-inventory")
        dependency_server = ThreadingHTTPServer(
            ("127.0.0.1", args.dependency_port),
            DependencyHandler,
        )
        dependency_server.daemon_threads = True
        dependency_server.timeout = 0.25
        try:
            while not _STOP.is_set():
                dependency_server.handle_request()
        finally:
            dependency_server.server_close()
        os._exit(0)

    _set_process_name("kg-checkout-api")
    frontend_server = ThreadingHTTPServer(("127.0.0.1", args.port), FrontendHandler)
    frontend_server.daemon_threads = True
    frontend_thread = threading.Thread(target=frontend_server.serve_forever, daemon=True)
    frontend_thread.start()

    relationship_ready = threading.Event()

    def maintain_relationship() -> None:
        while not _STOP.is_set():
            connection = http.client.HTTPConnection(
                "127.0.0.1",
                args.dependency_port,
                timeout=1.0,
            )
            try:
                while not _STOP.is_set():
                    connection.request("GET", "/__relationship")
                    response = connection.getresponse()
                    response.read(4096)
                    if response.status != 200:
                        break
                    relationship_ready.set()
                    if _STOP.wait(0.75):
                        break
            except (OSError, TimeoutError, http.client.HTTPException):
                if _STOP.wait(0.1):
                    break
            finally:
                connection.close()

    relationship_thread = threading.Thread(target=maintain_relationship, daemon=True)
    relationship_thread.start()
    if not relationship_ready.wait(timeout=2.0):
        frontend_server.shutdown()
        frontend_server.server_close()
        frontend_thread.join(timeout=2)
        _stop_child_process(dependency_pid)
        raise RuntimeError("dependency relationship channel did not become ready")

    append_log(
        "service_started",
        pid=os.getpid(),
        dependency_pid=dependency_pid,
        listen_port=args.port,
        dependency_port=args.dependency_port,
    )
    append_log(
        "dependency_link_established",
        source="checkout-api",
        target="inventory-db",
        transport="tcp",
        target_port=args.dependency_port,
    )
    append_log(
        "config_metadata_changed",
        path=str(decoy_config_path),
        content_hash_unchanged=True,
    )
    _write_state(
        args.state_path,
        {
            "scenario_id": args.scenario_id,
            "mode": args.mode,
            "pid": os.getpid(),
            "dependency_pid": dependency_pid,
            "bind": "127.0.0.1",
            "port": args.port,
            "frontend_port": args.port,
            "dependency_port": args.dependency_port,
            "dependency_delay_ms": dependency_delay_ms,
            "dependency_timeout_ms": dependency_timeout_ms,
            "health_url": f"http://127.0.0.1:{args.port}/health",
            "log_path": str(log_path),
            "decoy_config_path": str(decoy_config_path),
            "decoy_baseline_sha256": baseline_hash,
            "decoy_current_sha256": hashlib.sha256(decoy_config_path.read_bytes()).hexdigest(),
            "decoy_baseline_mtime_ns": baseline_stat.st_mtime_ns,
            "decoy_current_mtime_ns": changed_stat.st_mtime_ns,
            "created_at": time.time(),
        },
    )
    try:
        _sleep_until_stopped()
    finally:
        frontend_server.shutdown()
        frontend_server.server_close()
        frontend_thread.join(timeout=2)
        relationship_thread.join(timeout=2)
        _stop_child_process(dependency_pid)


def _stop(signum: int, frame: Any) -> None:
    _STOP.set()


def _sleep_until_stopped() -> None:
    while not _STOP.wait(0.25):
        pass


def _set_process_name(name: str) -> None:
    try:
        libc = ctypes.CDLL(None)
        libc.prctl(15, name.encode("ascii")[:15], 0, 0, 0)
    except (AttributeError, OSError):
        return


def _stop_child_process(pid: int) -> None:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            finished, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if finished == pid:
            return
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            finished, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if finished == pid:
            return
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        return


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    temporary.replace(path)


if __name__ == "__main__":
    main()
