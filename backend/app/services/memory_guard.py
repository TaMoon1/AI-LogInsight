"""上传内存预检：把「文件太大」在动手之前变成一句能看懂的话。

背景（2026-10-13 实测）：文本日志路径的内存峰值稳定为**文件大小的 4.4 倍**
（100 MB → 441 MB、200 MB → 883 MB，均含记录集构造）。因此 500 MB 日志需要约 2.2 GB
可用内存；本机实测可用内存 1.5~1.8 GB，**根本跑不动**——不预检的话，用户会看到
进程被杀或机器换页卡死，而不是「这份日志需要多少内存、你只有多少」。

口径：
- 预估倍数取自实测（4.4 倍）；再加固定余量，避免预检刚好卡在临界点上把机器压垮。
- 拿不到可用内存时**放行**（宁可让上传继续，也不因为读不到系统信息而误拒）。
- 这是提示性护栏，不是沙箱：它不改变解析器行为，也不对日志内容做任何限制。
"""

from __future__ import annotations

import ctypes
import os

#: 实测峰值倍数：100 MB → 4.4×、200 MB → 4.4×（见 `scripts/bench_large_log.py`）。
PEAK_FACTOR = 4.4
#: 预检额外余量（字节）：给系统与其他进程留出空间，避免刚好压在临界点上。
HEADROOM_BYTES = 300 * 1024 * 1024


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def available_bytes() -> int | None:
    """当前可用物理内存（字节）；读不到返回 None。"""

    try:  # Windows
        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(_MemoryStatusEx)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullAvailPhys)
    except (AttributeError, OSError):
        pass
    try:  # Linux / macOS
        pages = os.sysconf("SC_AVPHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return int(pages) * int(page_size)
    except (ValueError, OSError, AttributeError):
        return None


def estimate_peak_bytes(analysis_bytes: int) -> int:
    """按实测倍数预估解析 + 规则匹配的峰值内存。"""

    return int(analysis_bytes * PEAK_FACTOR)


def check_upload_memory(analysis_bytes: int) -> str | None:
    """返回预检不合格的原因；合格或无法判断时返回 None。

    只做一次「够不够」的判断，不做任何限流或排队——日志分析是手动触发的单次任务，
    排队与限流属于采集平台的职责，不在本项目范围内。
    """

    available = available_bytes()
    if available is None:
        return None
    needed = estimate_peak_bytes(analysis_bytes)
    if available >= needed + HEADROOM_BYTES:
        return None
    return (
        f"内存不足：本次日志 {analysis_bytes / 1048576:.0f} MB，按实测 {PEAK_FACTOR} 倍峰值 "
        f"约需 {needed / 1048576:.0f} MB，另需保留 {HEADROOM_BYTES // 1048576} MB 余量，"
        f"而当前可用内存仅 {available / 1048576:.0f} MB。"
        "请拆分文件后分批分析，或在内存更充裕的机器上执行；"
        "若确实需要单份大日志，可调整 LOGINSIGHT_MAX_ANALYSIS_BYTES 后自行承担换页风险。"
    )
