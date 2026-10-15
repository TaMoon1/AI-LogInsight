"""大日志性能基准：量出解析耗时、规则匹配耗时、峰值内存与解析覆盖率。

用法：
    cd backend && .venv\\Scripts\\python.exe scripts\\bench_large_log.py            # 默认 1/5/10 MB（内存内构造）
    cd backend && .venv\\Scripts\\python.exe scripts\\bench_large_log.py --mb 50   # 按上传上限压测
    cd backend && .venv\\Scripts\\python.exe scripts\\bench_large_log.py --file ..\\data\\bench\\web-100mb.log

`--mb` 走内存内构造（快，适合回归对比）；`--file` 走真实文件（含 `read_bytes()`，
与 `/api/logs/upload` 的读法一致），是量真实内存占用的口径。

结论口径（2026-09-22 实测，11 MB / 6 万条）：
- **解析**是线性的（约 13 MB/s），不是瓶颈；
- **规则匹配**原本是瓶颈（近似 O(规则数 × 记录数)，曾达 9.5 秒），现已按
  「日志类型 + 必要条件」索引挑候选规则，并预编译谓词匹配函数，降到约 2.2 秒；
- 峰值内存已从 90 MB 降到 **49 MB**（约 820 字节/条）：去掉了两处全量字典复制，
  并让重复的 IP / UA / 状态码等字段共享同一个字符串对象。
按 50 MB 上传上限外推，峰值约 0.25 GB 量级。

结论口径（2026-10-14 实测，11.12 MB / 60,018 条，规则量 2272）：
- 解析 0.89s（与历史一致，仍是线性）；
- **规则耗时随规则量近似线性**：全量 2272 条 15.75s，仅内置 74 条 8.61s——
  2198 条社区规则只多花 7.1s，说明「日志类型 + 必要条件」索引对导入规则有效。
  注意单次运行内离散很大（n=3，最大 23.11s / 17.09s），跨版本对比要看多轮均值。
- **峰值内存 56 MB（970 字节/条，5.0× 文件）**：比 2026-09-30 的 820 字节/条 **+18%**。
  增量来自「按标准格式原样收下字段」——Web 记录多 3 个字段（`remote_user` /
  `body_bytes_sent` / `http_referer`），EVTX 记录多得多。这是该改动的直接成本，如实记录。
  按 50 MB 上传上限外推，峰值约 0.3 GB 量级。

**内存随文件线性增长是文本日志的固有约束**：`parse_upload()` 返回全部记录的列表，
没有保留上限（EVTX 才有 `AUTH_RECORD_LIMIT` / `OTHER_RECORD_LIMIT`）。
2026-09-30 实测 11 MB → 峰值约 4.5 倍文件大小；项目验证范围上限为 500MB，
不外推或承诺 1GB 以上日志能力。
"""

from __future__ import annotations

import argparse
import ctypes
import sys
import time
import tracemalloc
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.analyzer import assign_record_ids, collect_records  # noqa: E402
from app.services.detector import detect_events_with_coverage  # noqa: E402
from app.services.parser import parse_upload  # noqa: E402

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
PATHS = ["/", "/assets/app.js", "/api/data", "/api/orders", "/health"]
ATTACK_LINES = (
    '203.0.113.99 - - [12/Sep/2026:09:59:59 +0800] '
    '"GET /../../../../etc/passwd HTTP/1.1" 400 1 "-" "sqlmap/1.7"\n',
    "203.0.113.98 - - [12/Sep/2026:09:59:59 +0800] "
    "\"GET /s?q=1' or '1'='1 HTTP/1.1\" 403 1 \"-\" \"ua\"\n",
    '203.0.113.97 - - [12/Sep/2026:09:59:59 +0800] "GET /.env HTTP/1.1" 404 1 "-" "ua"\n',
)


class _MemoryStatus(ctypes.Structure):
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


def available_mb() -> float:
    """当前可用物理内存（MB）。测大文件前必须看一眼——否则会把机器压到换页甚至 OOM。"""

    status = _MemoryStatus()
    status.dwLength = ctypes.sizeof(_MemoryStatus)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return float("inf")
    return status.ullAvailPhys / 1048576


def build_log(target_mb: int) -> bytes:
    """构造接近真实形态的 Web 访问日志（含少量攻击特征）。

    仅用于小规模回归；大样本请用 `scripts/gen_large_log.py`（它流式写盘，
    不会像这里一样先把整份内容堆在内存）。
    """

    limit = target_mb * 1024 * 1024
    chunks: list[str] = []
    size = 0
    index = 0
    while size < limit:
        block: list[str] = []
        for _ in range(10000):
            block.append(
                f"198.51.100.{index % 60 + 1} - - "
                f"[12/Sep/2026:09:{index % 60:02d}:{index % 60:02d} +0800] "
                f'"GET {PATHS[index % len(PATHS)]} HTTP/1.1" 200 1024 "-" "{USER_AGENT}"\n'
            )
            index += 1
        block.extend(ATTACK_LINES)
        text = "".join(block)
        chunks.append(text)
        size += len(text.encode("utf-8"))
    return "".join(chunks).encode("utf-8")


def _build_records(parsed):
    """按产品实际路径组装记录：就地补来源与编号，不额外复制字典。"""

    records = collect_records(["bench.log"], [_AsParsed(parsed)])
    return assign_record_ids(records)


class _AsParsed:
    """把已解析结果包装成 `collect_records` 需要的形态（基准只跑单文件）。"""

    def __init__(self, parsed):
        self.records = parsed.records
        self.log_type = parsed.log_type


def bench_content(content: bytes, label: str, repeat: int) -> None:
    actual_mb = len(content) / 1048576

    # 计时这一遍不能开 tracemalloc：它的开销会显著放大耗时。
    # 并且必须重复取最小值——单次测量会被 GC 与系统调度放大数倍（实测 11 MB 在 2.5s~7s 间摆动），
    # 拿单次结果比较优化前后会得出错误结论。
    parse_samples: list[float] = []
    rule_samples: list[float] = []
    events: list = []
    covered: set[str] = set()
    total_lines = 0
    total_records = 0
    coverage = 0.0
    parse_failures = 0
    retention_drops = 0
    for _ in range(repeat):
        start = time.perf_counter()
        parsed = parse_upload(content)
        parse_samples.append(time.perf_counter() - start)

        records = _build_records(parsed)
        start = time.perf_counter()
        events, covered = detect_events_with_coverage(records)
        rule_samples.append(time.perf_counter() - start)

        coverage = parsed.parsed_lines / max(1, parsed.total_lines)
        total_lines = parsed.total_lines
        total_records = len(records)
        parse_failures = parsed.parse_failures
        retention_drops = parsed.retention_drops
        del records, parsed

    parse_seconds = min(parse_samples)
    rule_seconds = min(rule_samples)

    # 内存单独量一遍（同样包含记录集构造）
    tracemalloc.start()
    peak_parsed = parse_upload(content)
    peak_records = _build_records(peak_parsed)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del peak_records, peak_parsed

    bytes_per_record = peak / total_records if total_records else 0
    print(
        f"{label:<22} | {actual_mb:>7.2f} MB | 行 {total_lines:>8} | 记录 {total_records:>8} | "
        f"解析 {parse_seconds:>6.2f}s | 规则 {rule_seconds:>7.2f}s "
        f"(n={repeat} 最大 {max(rule_samples):.2f}s) | "
        f"峰值 {peak / 1048576:>6.0f} MB ({bytes_per_record:>4.0f} B/条, "
        f"{peak / max(1, len(content)):.1f}× 文件) | 事件 {len(events):>3} | "
        f"命中 {len(covered):>7} | 覆盖率 {coverage:.1%} | "
        f"解析失败 {parse_failures} | 超保留 {retention_drops}"
    )


def bench(target_mb: int, repeat: int) -> None:
    content = build_log(target_mb)
    bench_content(content, f"内存构造 {target_mb} MB", repeat)
    del content


def bench_file(path: Path, repeat: int, min_free_mb: int) -> None:
    free_mb = available_mb()
    # 峰值实测约为文件大小的 4.4 倍，这里按 6 倍留余量：宁可少一条数据，
    # 也不要把用户机器压到换页甚至 OOM。
    needed_mb = max(min_free_mb, path.stat().st_size / 1048576 * 6)
    if free_mb < needed_mb:
        print(
            f"{path.name:<22} | 跳过：可用内存 {free_mb:.0f} MB < 需要 {needed_mb:.0f} MB"
            "（--min-free-mb 可调整下限）"
        )
        return
    # 与 /api/logs/upload 一致：整份读进内存
    content = path.read_bytes()
    bench_content(content, path.name, repeat)
    del content


def main() -> int:
    parser = argparse.ArgumentParser(description="大日志解析与规则匹配性能基准")
    parser.add_argument(
        "--mb", type=int, nargs="*", default=[], help="待测试的日志大小（MB，内存内构造）"
    )
    parser.add_argument(
        "--file", type=Path, nargs="*", default=[], help="待测试的真实文件路径（走 read_bytes）"
    )
    parser.add_argument(
        "--repeat", type=int, default=3, help="每个规模重复次数，取最小值（默认 3）"
    )
    parser.add_argument(
        "--min-free-mb", type=int, default=400, help="可用内存下限，低于该值跳过（默认 400）"
    )
    arguments = parser.parse_args()
    print(f"可用内存：{available_mb():.0f} MB")
    print(
        "样本                   | 实际大小 | 行数     | 记录数   | 解析耗时 | 规则耗时 | "
        "峰值内存 | 事件 | 命中 | 覆盖率 | 解析失败 | 超保留"
    )
    for target_mb in arguments.mb:
        bench(target_mb, max(1, arguments.repeat))
    for path in arguments.file:
        if not path.is_file():
            print(f"{str(path):<22} | 跳过：文件不存在")
            continue
        bench_file(path, max(1, arguments.repeat), arguments.min_free_mb)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
