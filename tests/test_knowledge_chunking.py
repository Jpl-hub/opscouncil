from __future__ import annotations

from backend.app.knowledge.chunking import split_document


def test_runbook_chunking_keeps_procedure_steps_together() -> None:
    content = """适用场景：根分区空间持续升高，需要定位大文件来源。

排查流程：
1. 采集磁盘和 inode 使用率。
2. 定位大文件并核验进程占用。
3. 判断文件是否属于数据库或审计边界。

处置边界：涉及清理时必须先备份并进入人工审批。"""

    chunks = split_document(content, "runbook", max_chars=180)

    procedure = next(chunk for chunk in chunks if chunk.kind == "procedure")
    assert "采集磁盘" in procedure.content
    assert "核验进程占用" in procedure.content
    assert "人工审批" not in procedure.content


def test_incident_review_chunking_marks_event_and_resolution_sections() -> None:
    content = """故障现象：sshd 无法接受新连接。

时间线：10:01 配置发布；10:03 服务重启失败。

根因：配置文件中存在不受支持的参数。

恢复过程：回滚配置并完成语法核验后恢复服务。"""

    chunks = split_document(content, "incident_review")

    assert {chunk.kind for chunk in chunks} >= {"event", "root_cause", "resolution"}


def test_chunking_never_emits_blank_or_oversized_chunks() -> None:
    content = "架构说明：" + "主机感知与安全校验。" * 80

    chunks = split_document(content, "architecture", max_chars=120, overlap=20)

    assert chunks
    assert all(chunk.content.strip() for chunk in chunks)
    assert all(len(chunk.content) <= 120 for chunk in chunks)
