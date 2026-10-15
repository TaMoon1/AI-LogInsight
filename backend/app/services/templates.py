from __future__ import annotations

from collections import defaultdict

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

MAX_TEMPLATES = 20
MAX_SCAN_LINES = 20000
RARE_COUNT = 1

# 先屏蔽 IP 与长十六进制串，避免同类日志被拆成大量模板
MASKING_INSTRUCTIONS = (
    MaskingInstruction(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "IP"),
    MaskingInstruction(r"\b[0-9a-fA-F]{12,}\b", "HEX"),
)


def _create_miner() -> TemplateMiner:
    config = TemplateMinerConfig()
    config.masking_instructions = list(MASKING_INSTRUCTIONS)
    return TemplateMiner(None, config)


def mine_templates(text: str) -> list[dict[str, object]]:
    """对未结构化日志做在线模板挖掘。

    只扫描前 MAX_SCAN_LINES 行，返回按出现次数排序的模板；
    count 为 1 的模板标记为 rare（仅出现一次的罕见日志形态）。
    """

    lines = [line.strip() for line in text.splitlines() if line.strip()][:MAX_SCAN_LINES]
    if not lines:
        return []

    miner = _create_miner()
    counts: dict[int, int] = defaultdict(int)
    templates: dict[int, str] = {}
    for line in lines:
        try:
            mined = miner.add_log_message(line)
        except Exception:
            continue
        cluster = mined["cluster_id"]
        counts[cluster] += 1
        templates[cluster] = mined["template_mined"]

    total = len(lines)
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:MAX_TEMPLATES]
    return [
        {
            "template": templates[cluster],
            "count": count,
            "ratio": round(count / total, 4),
            "rare": count <= RARE_COUNT,
        }
        for cluster, count in ranked
    ]
