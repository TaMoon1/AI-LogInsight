"""ATT&CK 标签映射：把规则的 Sigma 标签翻成本项目使用的战术名与技术编号。

为什么需要它：内置规则靠 `analytics._TACTICS` 手写映射；而 503 条 Sigma 导入规则
只在 `tags` 里带 `attack.<tactic>` 与 `attack.Txxxx`。没有这层映射时，
导入规则的事件在战术网格与技术矩阵里全部落到「其他」——**等于白导入**。

口径：
- 战术名一律收敛到本项目既有的中文战术集合（见 `analytics._PHASE_ORDER`），
  这样战术网格、攻击链、Top 榜用的是同一套词，不会出现两个「发现」。
- `attack.stealth` 归到「防御规避」：ATT&CK 19.x 把它从 defense-evasion 拆出来，
  但本项目既有的 T1562.001 等映射都写作「防御规避」，两套词会让同一件事分成两格。
- 只认 `attack.` 前缀的标签；`attack.T1218` 这类技术编号原样保留（含子技术）。
"""

from __future__ import annotations

#: Sigma 标签里的战术名 → 本项目中文战术名
TACTIC_LABELS: dict[str, str] = {
    "reconnaissance": "侦察",
    "resource-development": "其他",
    "initial-access": "初始访问",
    "execution": "执行",
    "persistence": "持久化",
    "privilege-escalation": "权限提升",
    "defense-evasion": "防御规避",
    "stealth": "防御规避",
    "credential-access": "凭据访问",
    "discovery": "发现",
    "lateral-movement": "横向移动",
    "collection": "收集",
    "command-and-control": "命令与控制",
    "exfiltration": "数据渗出",
    "impact": "影响",
}


#: 同一战术的不同写法归一到项目内的正式名。
#: 真实事故（2026-10-13）：内置 ATT&CK 标尺清单里写的是「**凭证**访问」（8 项技术），
#: 而战术阶段表写的是「**凭据**访问」——一字之差让 T1110 等 8 项技术**永远进不了**
#: 按阶段排序的矩阵/网格（列被丢弃且不报错）。
TACTIC_ALIASES: dict[str, str] = {
    "凭证访问": "凭据访问",
    "防守规避": "防御规避",
    "指挥与控制": "命令与控制",
    "影响破坏": "影响",
}


def normalize_tactic(name: str | None) -> str:
    """把战术名归一为项目正式名；空值归入「其他」。"""

    value = (name or "").strip()
    if not value:
        return "其他"
    return TACTIC_ALIASES.get(value, value)


def tactic_from_tags(tags: list[str] | None) -> str | None:
    """从 `attack.<tactic>` 标签取战术名；没有则返回 None（由调用方决定兜底）。"""

    for tag in tags or []:
        value = tag.strip().lower()
        if not value.startswith("attack."):
            continue
        name = value[len("attack."):]
        if name in TACTIC_LABELS:
            return normalize_tactic(TACTIC_LABELS[name])
    return None


def techniques_from_tags(tags: list[str] | None) -> list[str]:
    """从 `attack.Txxxx` 标签取技术编号（保留 T1059.001 这类子技术写法）。"""

    found: list[str] = []
    for tag in tags or []:
        value = tag.strip()
        if not value.lower().startswith("attack.t"):
            continue
        technique = value[len("attack."):].upper()
        if technique not in found:
            found.append(technique)
    return found
