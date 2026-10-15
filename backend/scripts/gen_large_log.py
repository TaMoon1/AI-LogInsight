"""生成可重复的大日志测试样本与边界样本。

刻意**流式写盘**：旧基准里的 `build_log()` 先把全部内容堆在内存再 join。
项目大文件验证上限为 500MB，生成过程不应因构造样本产生额外内存峰值。

用法：
    cd backend && .venv\\Scripts\\python.exe scripts\\gen_large_log.py --mb 10 100
    cd backend && .venv\\Scripts\\python.exe scripts\\gen_large_log.py --mb 500 --kind ssh
    cd backend && .venv\\Scripts\\python.exe scripts\\gen_large_log.py --edge

输出默认落在 `data/bench/`（`data/` 已在 .gitignore 中，不进版本库）。
同一 `--mb` / `--kind` 重复执行产出完全一致的内容与哈希，便于复测对比。
"""

from __future__ import annotations

import argparse
import hashlib
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = PROJECT_ROOT / "data" / "bench"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
PATHS = ["/", "/assets/app.js", "/api/data", "/api/orders", "/health"]
# 少量真实攻击特征：保证规则能命中，否则「跑完没事件」无法区分是解析问题还是规则问题
WEB_ATTACK_LINES = (
    '203.0.113.99 - - [12/Sep/2026:09:59:59 +0800] '
    '"GET /../../../../etc/passwd HTTP/1.1" 400 1 "-" "sqlmap/1.7"\n',
    "203.0.113.98 - - [12/Sep/2026:09:59:59 +0800] "
    "\"GET /s?q=1' or '1'='1 HTTP/1.1\" 403 1 \"-\" \"ua\"\n",
    '203.0.113.97 - - [12/Sep/2026:09:59:59 +0800] "GET /.env HTTP/1.1" 404 1 "-" "ua"\n',
)
CHUNK_LINES = 10000


def _web_block(index: int) -> str:
    # 序号必须取模后再拼 IP：直接拼 index 会在第二块之后产生 198.51.100.10000 这类
    # 非法地址，解析器整块拒收（实测 6 万行里 5.9 万条解析失败，覆盖率掉到 1.7%）。
    lines = [
        f"198.51.100.{(index + offset) % 60 + 1:02d} - - "
        f"[12/Sep/2026:09:{(index + offset) % 60:02d}:{(index + offset) % 60:02d} +0800] "
        f'"GET {PATHS[(index + offset) % len(PATHS)]} HTTP/1.1" 200 1024 "-" "{USER_AGENT}"\n'
        for offset in range(CHUNK_LINES)
    ]
    return "".join(lines) + "".join(WEB_ATTACK_LINES)


def _ssh_block(index: int) -> str:
    lines = []
    for offset in range(CHUNK_LINES):
        position = index + offset
        account = ("root", "admin", "deploy")[position % 3]
        # 每 100 行混入一次成功登录，避免整份日志只有失败而无法覆盖「失败聚集 + 成功」链路
        if position % 100 == 99:
            lines.append(
                f"Sep 12 09:{(position // 60) % 60:02d}:{position % 60:02d} host sshd[100]: "
                f"Accepted password for {account} from 10.0.0.8 port 22 ssh2\n"
            )
        else:
            lines.append(
                f"Sep 12 09:{(position // 60) % 60:02d}:{position % 60:02d} host sshd[100]: "
                f"Failed password for {account} from 10.0.0.8 port 22 ssh2\n"
            )
    return "".join(lines)


BUILDERS = {"web": _web_block, "ssh": _ssh_block}


def generate(target_mb: int, kind: str, out_dir: Path) -> dict[str, object]:
    limit = target_mb * 1024 * 1024
    path = out_dir / f"{kind}-{target_mb}mb.log"
    builder = BUILDERS[kind]
    digest = hashlib.sha256()
    written = 0
    lines = 0
    index = 0
    started = time.perf_counter()
    with path.open("w", encoding="utf-8", newline="") as handle:
        while written < limit:
            block = builder(index)
            handle.write(block)
            encoded = len(block.encode("utf-8"))
            digest.update(block.encode("utf-8"))
            written += encoded
            lines += CHUNK_LINES + (len(WEB_ATTACK_LINES) if kind == "web" else 0)
            index += CHUNK_LINES
    return {
        "path": path,
        "bytes": written,
        "lines": lines,
        "sha256": digest.hexdigest(),
        "seconds": time.perf_counter() - started,
    }


def generate_edge_cases(out_dir: Path) -> list[dict[str, object]]:
    """边界样本：超长单行、乱码、截断、字段缺失、空文件。

    这些样本都很小，重点是**内容形态**而不是体积——它们考的是解析器容错，
    不是内存。混在大文件里反而看不出是哪一条把解析打挂的。
    """

    results: list[dict[str, object]] = []
    valid = _web_block(0)

    cases: list[tuple[str, bytes]] = [
        # 单行 5 MB：考单行缓冲与正则回溯
        ("edge-long-line.log", ("198.51.100.1 - - " + "A" * (5 * 1024 * 1024) + "\n").encode()),
        # 乱码：合法行 + 非法 UTF-8 字节，考解码容错
        ("edge-garbled.log", valid.encode("utf-8")[:2000] + bytes(range(128, 256)) * 64 + b"\n"),
        # 截断：最后一行没有换行且字段不全
        ("edge-truncated.log", (valid[:4000] + "198.51.100.7 - - [12/Sep/2026:09:00:00 +0800] \"GET /x").encode()),
        # 字段缺失：缺状态码/字节数/UA
        (
            "edge-missing-fields.log",
            b"198.51.100.1 - - [12/Sep/2026:09:00:00 +0800]\n" * 200,
        ),
        # 空文件
        ("edge-empty.log", b""),
    ]
    for name, content in cases:
        path = out_dir / name
        path.write_bytes(content)
        results.append(
            {
                "path": path,
                "bytes": len(content),
                "lines": content.count(b"\n"),
                "sha256": hashlib.sha256(content).hexdigest(),
                "seconds": 0.0,
            }
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="生成可重复的大日志与边界测试样本")
    parser.add_argument("--mb", type=int, nargs="*", default=[10], help="样本大小（MB）")
    parser.add_argument("--kind", choices=sorted(BUILDERS), default="web", help="日志类型")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="输出目录")
    parser.add_argument("--edge", action="store_true", help="额外生成边界样本（超长行/乱码/截断/缺字段/空文件）")
    arguments = parser.parse_args()

    arguments.out.mkdir(parents=True, exist_ok=True)
    print(f"输出目录：{arguments.out}")
    print("文件                        | 实际大小 | 行数        | 耗时   | SHA-256(前 16)")
    results = [generate(mb, arguments.kind, arguments.out) for mb in arguments.mb]
    if arguments.edge:
        results.extend(generate_edge_cases(arguments.out))
    for item in results:
        print(
            f"{Path(item['path']).name:<27} | "
            f"{item['bytes'] / 1048576:>7.2f} MB | "
            f"{item['lines']:>10} | "
            f"{item['seconds']:>5.2f}s | {str(item['sha256'])[:16]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

