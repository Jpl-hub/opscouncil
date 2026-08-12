from __future__ import annotations

import hashlib
import hmac
import json
from collections import defaultdict
from collections.abc import Iterable
from typing import Any


MEMORY_CONTENT_CONTRACT = "operational-memory-content.v1"


def seal_memory_content(memory: Any) -> str:
    digest = calculate_memory_content_hash(memory)
    memory.content_hash = digest
    return digest


def verify_memory_content(memory: Any) -> bool:
    stored = str(getattr(memory, "content_hash", "") or "")
    if len(stored) != 64:
        return False
    return hmac.compare_digest(stored, calculate_memory_content_hash(memory))


def inspect_memory_version_chains(
    memories: Iterable[Any],
) -> dict[int, tuple[str, ...]]:
    """Return integrity failures keyed by memory id for complete version chains."""
    grouped: dict[str, list[Any]] = defaultdict(list)
    for memory in memories:
        grouped[str(getattr(memory, "memory_key", "") or "")].append(memory)

    failures: dict[int, list[str]] = {}
    for versions in grouped.values():
        ordered = sorted(
            versions,
            key=lambda item: (
                int(getattr(item, "version", 0) or 0),
                int(getattr(item, "id", 0) or 0),
            ),
        )
        previous: Any | None = None
        for memory in ordered:
            memory_id = int(getattr(memory, "id", 0) or 0)
            reasons: list[str] = []
            version = int(getattr(memory, "version", 0) or 0)
            parent_hash = str(getattr(memory, "parent_content_hash", "") or "")
            if not verify_memory_content(memory):
                reasons.append("CONTENT_HASH_MISMATCH")
            if previous is None:
                if version != 1:
                    reasons.append("MISSING_INITIAL_VERSION")
                if parent_hash:
                    reasons.append("UNEXPECTED_PARENT_HASH")
            else:
                previous_version = int(getattr(previous, "version", 0) or 0)
                previous_id = int(getattr(previous, "id", 0) or 0)
                previous_hash = str(getattr(previous, "content_hash", "") or "")
                if version != previous_version + 1:
                    reasons.append("VERSION_GAP")
                if not previous_hash or not hmac.compare_digest(
                    parent_hash, previous_hash
                ):
                    reasons.append("PARENT_HASH_MISMATCH")
                if getattr(memory, "supersedes_id", None) != previous_id:
                    reasons.append("SUPERSEDES_LINK_MISMATCH")
            if reasons:
                failures[memory_id] = reasons
            previous = memory
    return {memory_id: tuple(reasons) for memory_id, reasons in failures.items()}


def calculate_memory_content_hash(memory: Any) -> str:
    payload = {
        "contract": MEMORY_CONTENT_CONTRACT,
        "memory_key": str(getattr(memory, "memory_key", "") or ""),
        "version": int(getattr(memory, "version", 0) or 0),
        "source_task_id": int(getattr(memory, "source_task_id", 0) or 0),
        "supersedes_id": getattr(memory, "supersedes_id", None),
        "host_scope": str(getattr(memory, "host_scope", "") or ""),
        "service_scope": str(getattr(memory, "service_scope", "") or ""),
        "symptom_fingerprint": str(
            getattr(memory, "symptom_fingerprint", "") or ""
        ),
        "applicability": getattr(memory, "applicability_json", {}) or {},
        "confidence_score": int(getattr(memory, "confidence_score", 0) or 0),
        "title": str(getattr(memory, "title", "") or ""),
        "root_cause": str(getattr(memory, "root_cause", "") or ""),
        "resolution": str(getattr(memory, "resolution", "") or ""),
        "evidence_refs": getattr(memory, "evidence_refs_json", []) or [],
        "created_by": str(getattr(memory, "created_by", "") or ""),
        "parent_content_hash": (
            str(getattr(memory, "parent_content_hash", "") or "") or None
        ),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
