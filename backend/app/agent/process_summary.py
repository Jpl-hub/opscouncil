from __future__ import annotations


def summarize_process_health(
    snapshot: dict,
    processes: list,
    handles: list,
    runtime_details: list,
) -> str:
    process_rows = [item for item in processes if isinstance(item, dict)]
    handle_rows = [item for item in handles if isinstance(item, dict)]
    missing_detail_rows = [
        item
        for item in runtime_details
        if isinstance(item, dict) and item.get("exists") is False
    ]
    detail_rows = [
        item for item in runtime_details if isinstance(item, dict) and item.get("exists", True)
    ]
    sentences: list[str] = []
    focused_fd_percent: float | None = None
    top_cpu_percent = 0.0
    top_memory_percent = 0.0
    zombie_count = 0
    top_cpu: dict | None = None
    top_memory: dict | None = None
    zombie_rows: list[dict] = []
    hot_handle: dict | None = None

    if process_rows:
        top_cpu = max(process_rows, key=lambda item: _numeric(item.get("cpu_percent")) or 0.0)
        top_memory = max(process_rows, key=lambda item: _numeric(item.get("mem_percent")) or 0.0)
        top_cpu_percent = _numeric(top_cpu.get("cpu_percent")) or 0.0
        top_memory_percent = _numeric(top_memory.get("mem_percent")) or 0.0
        zombie_rows = [item for item in process_rows if item.get("is_zombie")]
        zombie_count = len(zombie_rows)

    if handle_rows:
        hot_handle = max(handle_rows, key=_fd_pressure_key)
        handle_percent = _numeric(hot_handle.get("fd_utilization_percent"))
        if handle_percent is not None:
            focused_fd_percent = handle_percent

    if detail_rows:
        detail = _focus_runtime_detail(detail_rows, top_cpu, top_memory, hot_handle)
        detail_parts: list[str] = []
        rss_kb = _numeric(detail.get("vm_rss_kb"))
        if rss_kb is not None:
            detail_parts.append(f"RSS {rss_kb / 1024:.1f} MiB")
        open_fds = _numeric(detail.get("open_fd_count"))
        fd_limit = _numeric(detail.get("max_open_files_soft"))
        fd_percent = _numeric(detail.get("fd_utilization_percent"))
        if fd_percent is not None:
            focused_fd_percent = max(focused_fd_percent or 0.0, fd_percent)
        if open_fds is not None and fd_limit is not None:
            fd_text = f"文件句柄 {int(open_fds)}/{int(fd_limit)}"
            if fd_percent is not None:
                fd_text += f"（{fd_percent:.2f}%）"
            detail_parts.append(fd_text)
        unit = detail.get("systemd_unit")
        detail_parts.append(f"关联服务 {unit}" if unit else "未关联 systemd 服务")
        sentences.append(
            f"重点进程：{_process_name(detail)}（PID {detail.get('pid') or '-'}），"
            + "，".join(detail_parts)
            + "。"
        )

    resource_parts: list[str] = []
    loadavg = snapshot.get("loadavg")
    if (
        isinstance(loadavg, list)
        and len(loadavg) >= 3
        and all(_numeric(value) is not None for value in loadavg[:3])
    ):
        resource_parts.append(
            "1/5/15 分钟负载为 " + "/".join(f"{float(value):.2f}" for value in loadavg[:3])
        )
    memory = snapshot.get("memory")
    memory_used = _numeric(memory.get("used_percent")) if isinstance(memory, dict) else None
    if memory_used is not None:
        resource_parts.append(f"内存使用率 {memory_used:.1f}%")
    pressure = snapshot.get("pressure")
    pressure_parts: list[str] = []
    if isinstance(pressure, dict):
        pressure_metrics = (
            ("CPU 争用", _nested_numeric(pressure, "cpu", "some", "avg10")),
            ("内存停顿", _nested_numeric(pressure, "memory", "some", "avg10")),
            ("I/O 全体停顿", _nested_numeric(pressure, "io", "full", "avg10")),
        )
        pressure_parts = [
            f"{label} {value:.2f}%" for label, value in pressure_metrics if value is not None
        ]
    system_parts: list[str] = []
    if resource_parts:
        system_parts.append("，".join(resource_parts))
    if pressure_parts:
        system_parts.append("PSI 近 10 秒：" + "、".join(pressure_parts))
    if system_parts:
        sentences.append("系统资源：" + "；".join(system_parts) + "。")

    if top_cpu is not None and top_memory is not None:
        zombie_text = f"发现 {zombie_count} 个僵尸进程" if zombie_count else "未发现僵尸进程"
        sentences.append(
            f"进程对比：CPU 占用最高为 {_process_name(top_cpu)}（PID {top_cpu.get('pid') or '-'}，{top_cpu_percent:.1f}%），"
            f"内存占用最高为 {_process_name(top_memory)}（PID {top_memory.get('pid') or '-'}，{top_memory_percent:.1f}%）；"
            f"{zombie_text}。"
        )
        if zombie_rows:
            examples = "；".join(
                f"PID {item.get('pid') or '-'}（父进程 PID {item.get('ppid') or '-'}，状态 {item.get('stat') or 'Z'}）"
                for item in zombie_rows[:3]
            )
            sentences.append(f"僵尸证据：{examples}。")

    if hot_handle is not None:
        open_fd_count = int(_numeric(hot_handle.get("open_fd_count")) or 0)
        soft_limit = _numeric(hot_handle.get("max_open_files_soft"))
        utilization = _numeric(hot_handle.get("fd_utilization_percent"))
        if soft_limit is not None and utilization is not None:
            sentences.append(
                f"文件句柄压力：{_process_name(hot_handle)}（PID {hot_handle.get('pid') or '-'}）"
                f"使用 {open_fd_count}/{int(soft_limit)}（{utilization:.2f}%），"
                "按相对软上限为当前最高。"
            )
        else:
            sentences.append(
                f"文件句柄数量：{_process_name(hot_handle)}（PID {hot_handle.get('pid') or '-'}）"
                f"打开 {open_fd_count} 个；缺少软上限证据，不能仅凭绝对数量判定异常。"
            )

    requires_followup = (
        zombie_count > 0
        or (focused_fd_percent is not None and focused_fd_percent >= 80.0)
        or top_cpu_percent >= 90.0
        or top_memory_percent >= 90.0
    )
    if missing_detail_rows:
        missing_pid = missing_detail_rows[0].get("pid") or "-"
        decision = (
            f"目标核验：PID {missing_pid} 在本次采样时已不存在；"
            "不能用其他高占用进程替代该目标作出健康或处置结论。"
        )
    elif requires_followup:
        decision = (
            "处置判断：暂不建议立即停止或重启；已发现需要继续调查的异常指标，"
            "但现有证据不足以安全停止或重启进程。"
        )
    else:
        decision = (
            "处置判断：无需立即停止或重启；当前没有持续过载、资源耗尽或僵尸进程等"
            "支持性证据。"
        )
    if missing_detail_rows:
        sentences.append(
            "若该进程号来自历史证据，应按服务单元或监听端口重新定位当前实例，"
            "避免因进程退出或 PID 复用误判；本轮仅执行只读采样，未执行系统变更。"
        )
    else:
        sentences.append(
            "建议结合告警时间窗继续核验服务归属、资源上限和变化趋势；"
            "本轮仅执行只读采样，未执行系统变更。"
        )
    return decision + "".join(sentences)


def _process_name(process: dict) -> str:
    value = process.get("command") or process.get("name") or process.get("comm") or "未知进程"
    text = "".join(character for character in str(value) if character.isprintable()).strip()
    return text[:40] or "未知进程"


def _focus_runtime_detail(
    detail_rows: list[dict],
    top_cpu: dict | None,
    top_memory: dict | None,
    hot_handle: dict | None,
) -> dict:
    by_pid = {str(item.get("pid")): item for item in detail_rows if item.get("pid") is not None}
    if (
        hot_handle is not None
        and (_numeric(hot_handle.get("fd_utilization_percent")) or 0.0) >= 80.0
        and hot_handle.get("pid") is not None
    ):
        matched = by_pid.get(str(hot_handle["pid"]))
        if matched is not None:
            return matched
    for process in (top_cpu, top_memory):
        if process is None or process.get("pid") is None:
            continue
        matched = by_pid.get(str(process["pid"]))
        if matched is not None:
            return matched
    return detail_rows[0]


def _fd_pressure_key(item: dict) -> tuple[int, float, float]:
    utilization = _numeric(item.get("fd_utilization_percent"))
    return (
        1 if utilization is not None else 0,
        utilization or -1.0,
        _numeric(item.get("open_fd_count")) or 0.0,
    )


def _numeric(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _nested_numeric(values: dict, *path: str) -> float | None:
    current: object = values
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return _numeric(current)
