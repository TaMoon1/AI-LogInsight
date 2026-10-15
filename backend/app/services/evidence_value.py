"""证据价值评分（路线图 P4 ①）：把「谁进上下文」从静态查表变成可解释的评分。

## 这个模块解决什么

上下文预算有限，但「哪些证据值得花预算」原先只由一个维度决定——
`risk_level` 查表（critical/high 5 条、medium 3、low 2、info 1）。这有两个问题：

1. **同档位的事件被一视同仁**：一条孤立的 medium 命中，和一条位于攻击链关键节点上的
   medium 命中，拿到同样的 3 条证据预算；
2. **无法解释**：模型或人问「为什么这条只给了 1 条证据」，答案只有「因为它是 info」。

本模块把决策拆成 5 个**可单独复核**的分量，每个分量都能说出依据，并逐项写进上下文说明。

## 五个分量的依据（全部确定性、全部来自项目已有数据）

| 分量 | 依据 | 为什么是这个依据 |
|---|---|---|
| `risk` | 事件 `risk_level` | 项目主信号（AGENTS.md §8：结构化事件优先于统计与推测） |
| `confidence` | 同一归组实体上**不同规则**的命中数 | 事件结构里**没有** confidence 字段，不伪造一个。用「交叉印证」当置信度代理：同一实体被多条不同规则命中，比单条孤立命中更可能是真事件。**这是代理指标，不是模型置信度**，字段名与说明里都写明 |
| `reliability` | 规则 `source`：`builtin` / `sigma` | 项目已有的事实：74 条内置规则有本地标注语料，510 条 Sigma 是**未验证的导入规则**（只做过「正常流量零命中」筛查） |
| `novelty` | 事件在同实体时间轴上的位置 | 「首次出现」是本项目已有口径（IOA 基线一律是「与本批次相比首次出现」）；攻击起点比后续重复更值得看 |
| `correlation` | 该实体跨了几份日志、串了几个事件 | 「实体关联」在本项目的含义就是**跨日志类型串联**（来源 IP / 目的 IP / 账户）；用相对分量会在小日志上恒等于满分，见 `entity_correlation` |

## 硬约束：评分**不参与**任何研判判定

评分只决定「下发几条证据」。它**不改变** `events`、`risk_level`、`confidence`、
`behaviors` 或任何进入结论的字段。这一点由 `tests/test_evidence_value.py` 守住——
评分是成本控制手段，一旦它能影响结论，就成了「为了省钱而改判」。

## 为什么本模块不 import 项目内任何东西

与 `ai_metrics.py` 同一条理由：只做「给定已算好的事实 → 输出评分」，
因此可以被单测直接驱动，也不会与 `ai.py` 形成循环依赖。
"""

from __future__ import annotations

from dataclasses import dataclass

#: 风险等级 → 分量值。`info` 不给 0：它仍是「有事件」，只是价值低。
RISK_COMPONENT = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}

#: 规则来源 → 可靠性分量。无规则的事件（跨记录关联类）取中间值：
#: 它不是「未验证的导入规则」，但也没有本地正负样本。
RELIABILITY_COMPONENT = {
    "builtin": 1.0,
    "sigma": 0.6,
    None: 0.7,
}

#: 交叉印证 → 置信度分量。
CONFIDENCE_COMPONENT = {1: 0.4, 2: 0.7}

#: 权重。风险占大头，但不独占——否则其余 4 个分量等于摆设，
#: 「按证据价值排序」会退化成「按风险排序」，也就是现在的行为。
WEIGHTS = {
    "risk": 0.40,
    "confidence": 0.15,
    "reliability": 0.15,
    "novelty": 0.15,
    "correlation": 0.15,
}


@dataclass(frozen=True)
class EventFacts:
    """评分所需的、**已经算好**的事实。本模块不读任何项目数据，全部由调用方传入。"""

    risk_level: str
    #: 规则来源（`builtin` / `sigma`）；无规则时传 None。
    rule_source: str | None = None
    #: 同一归组实体上不同 `rule_id` 的命中数（≥1）。
    distinct_rules_on_entity: int = 1
    #: 该事件在同实体时间轴上的新颖度 0~1（1 = 该实体的首个事件）。
    novelty: float = 1.0
    #: 该实体在全部实体中的分量 0~1。
    entity_share: float = 0.0


@dataclass(frozen=True)
class ValueScore:
    """一份可逐项复核的评分。"""

    risk: float
    confidence: float
    reliability: float
    novelty: float
    correlation: float
    total: float

    def to_note(self) -> str:
        """逐项说明。**不写权重公式**——要能回答「为什么是这么多」，
        不是「公式长什么样」。
        """

        return (
            f"risk={self.risk:.2f} confidence={self.confidence:.2f} "
            f"reliability={self.reliability:.2f} novelty={self.novelty:.2f} "
            f"correlation={self.correlation:.2f} total={self.total:.2f}"
        )


def _clamp01(value: float) -> float:
    return 0.0 if value < 0.0 else 1.0 if value > 1.0 else value


def confidence_component(distinct_rules: int) -> float:
    """交叉印证 → 置信度分量。规则越多越接近 1.0，上限 1.0。"""

    if distinct_rules <= 1:
        return CONFIDENCE_COMPONENT[1]
    if distinct_rules == 2:
        return CONFIDENCE_COMPONENT[2]
    return 1.0


def score_event(facts: EventFacts) -> ValueScore:
    """算出一个事件的价值评分。`total` 为加权和，用于微调证据深度。"""

    risk = RISK_COMPONENT.get(str(facts.risk_level or "").lower(), 0.1)
    confidence = confidence_component(max(1, int(facts.distinct_rules_on_entity)))
    reliability = RELIABILITY_COMPONENT.get(facts.rule_source, 0.7)
    novelty = _clamp01(float(facts.novelty))
    correlation = _clamp01(float(facts.entity_share))

    total = (
        risk * WEIGHTS["risk"]
        + confidence * WEIGHTS["confidence"]
        + reliability * WEIGHTS["reliability"]
        + novelty * WEIGHTS["novelty"]
        + correlation * WEIGHTS["correlation"]
    )
    return ValueScore(
        risk=risk,
        confidence=confidence,
        reliability=reliability,
        novelty=novelty,
        correlation=correlation,
        total=round(total, 4),
    )


#: 评分高/低的门槛。用于在**基准档位**上做 ±1 微调。
#: 刻意用「微调」而不是「按评分从 0 重新映射深度」：后者会让 critical 事件
#: 在其余分量偏低时掉到比 high 还少，风险单调性被打破——而风险是本项目的主信号。
PROMOTE_THRESHOLD = 0.75
DEMOTE_THRESHOLD = 0.45


def depth_adjustment(total: float) -> int:
    """评分 → 基准档位上的调整量（-1 / 0 / +1）。"""

    if total >= PROMOTE_THRESHOLD:
        return 1
    if total < DEMOTE_THRESHOLD:
        return -1
    return 0


def novelty_rank(first_seen: str | None, group_firsts: list[str | None]) -> float:
    """事件在同实体时间轴上的新颖度：组内最早 = 1.0，越晚越低。

    `group_firsts` 为同一归组实体下全部事件的 `first_seen`。
    时间戳缺失或全部相同时返回 1.0——**不把「没时间」当成「不新颖」**，
    否则缺时间戳的日志里所有事件都会被打成低价值。
    """

    stamps = sorted({value for value in group_firsts if value})
    if not stamps or first_seen not in stamps:
        return 1.0
    position = stamps.index(first_seen)
    if len(stamps) == 1:
        return 1.0
    return 1.0 - position / (len(stamps) - 1)


def entity_correlation(source_file_count: int, entity_event_count: int) -> float:
    """实体关联度：该实体在多大程度上**把多份日志 / 多个事件串起来**。

    刻意**不用**「该实体活动量 / 最活跃实体活动量」这种相对口径：只有一份日志、
    一个实体时，自身就是峰值，相对分量恒等于 1.0——等于给每个事件白送满分，
    「关联度」这个分量就失去了区分能力。而相对口径退化时恰好是**最常见**的小日志场景。

    改用绝对口径：跨来源文件数 + 同实体事件数，各自减 1（「只有一份 / 只有一个」
    不构成关联），除以 4 封顶。因此：

    | 情况 | 关联度 |
    |---|---|
    | 1 份文件、1 个事件 | 0.00（无关联可言） |
    | 2 份文件、3 个事件 | 0.75 |
    | 3+ 份文件、5+ 个事件 | 1.00 |
    """

    extra_files = max(0, int(source_file_count) - 1)
    extra_events = max(0, int(entity_event_count) - 1)
    return _clamp01((extra_files + extra_events) / 4)
