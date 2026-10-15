"""单次 AI 研判的**成本 × 质量联合指标**（路线图 P3 ①②③）。

这个模块刻意**不 import 项目内任何东西**：它只做「给定已经算好的输入 → 输出指标」，
因此可以被单测直接驱动，也不会和 `ai.py` 形成循环依赖。价格表由调用方解析后传进来。

## 两类数字必须分开，不要混

1. **真实账单**（`tokens_total` / `tokens_first_round` / `tokens_tool_rounds` /
   `cache_hit_tokens`）：来自服务端回传的 `usage`，是真实发生的量。
   拿不到就是 `None`，**不填 0**——「没测到」和「零成本」是两件事。
2. **估算归属**（`event_tokens` / `evidence_tokens` / `estimated_input_tokens`）：
   服务端**不会**告诉你「这次调用里第 3 个事件花了多少 token」，
   所以只能按上下文体量分摊。这是估算，字段名与报告里都写明「估算」。

把估算当账单看，会让成本优化得出错误结论——所以两者在数据结构上就是分开的字段，
不共用一个 `tokens` 键。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

#: 中文 JSON 的经验换算：约 2 字节 = 1 token。
#: 与 `docs/ai-token-cost.md` §1 用的是同一个口径，改这里要同步改文档。
BYTES_PER_TOKEN = 2.0


def estimate_tokens(text: str) -> int:
    """按 UTF-8 字节数估算 token 数（向上取整）。

    这是**估算**：真正的分词依赖具体模型的词表，本模块不做假设。
    它的用途是比较不同事件 / 证据之间的相对体量，不是对账。
    """

    if not text:
        return 0
    return int(len(text.encode("utf-8")) / BYTES_PER_TOKEN + 0.999)


@dataclass(frozen=True)
class PriceTable:
    """单价表，单位是「每百万 token 的金额」。

    **不内置任何厂商价格**：价格会变，写死在代码里就会悄悄算出错的成本，
    而且没人会注意到。宁可不给数字（`None` → 报告显示 n/a），也不给过期的数字。
    由 `.env` 配置，配置不全就没有成本数字。
    """

    input_per_m: float | None = None
    output_per_m: float | None = None
    cache_hit_per_m: float | None = None

    @property
    def configured(self) -> bool:
        return self.input_per_m is not None and self.output_per_m is not None

    @property
    def note(self) -> str:
        if not self.configured:
            return (
                "未配置单价，成本不可估算（设置 AI_PRICE_INPUT_PER_M / "
                "AI_PRICE_OUTPUT_PER_M 后可见）"
            )
        return "按 .env 配置的单价估算，非服务端账单"


@dataclass(frozen=True)
class ContextBreakdown:
    """上下文体的构成。全部是**估算**（按序列化字节数换算）。"""

    context_bytes: int = 0
    estimated_input_tokens: int = 0
    #: 每个事件的上下文体量。事件上下文字典里没有稳定 id，因此按顺序给出，
    #: 与 `context["events"]` 一一对应；编造一个 id 反而会让人以为能拿去查库。
    event_tokens: list[dict[str, Any]] = field(default_factory=list)
    #: 每条进入上下文的证据的体量，键是 evidence id（这个是真的有 id）。
    evidence_tokens: dict[str, int] = field(default_factory=dict)
    #: 本次分析全部事件里的证据总条数。
    evidence_available: int = 0
    #: 实际进入上下文的证据条数（受事件采样与风险分档影响）。
    evidence_sent: int = 0

    @property
    def evidence_truncated(self) -> int:
        return max(0, self.evidence_available - self.evidence_sent)

    @property
    def evidence_truncation_rate(self) -> float | None:
        """因采样 / 分档而未下发的证据比例。

        这个比例高不一定坏——低风险事件的证据本来就不值得付成本。
        它要跟「引用覆盖率」一起看：截断很多但引用覆盖没掉，说明截掉的是噪音。
        """

        if not self.evidence_available:
            return None
        return self.evidence_truncated / self.evidence_available


@dataclass(frozen=True)
class JudgementMetrics:
    """一次研判的成本 × 质量联合指标。"""

    duration_ms: float = 0.0
    #: 以下四项来自服务端账单；拿不到就是 None，不填 0。
    tokens_total: int | None = None
    tokens_first_round: int | None = None
    tokens_tool_rounds: int | None = None
    cache_hit_tokens: int | None = None
    rounds: int = 0
    context: ContextBreakdown = field(default_factory=ContextBreakdown)
    #: AI 实际引用到的证据编号。
    evidence_referenced: list[str] = field(default_factory=list)
    estimated_cost: float | None = None
    price_note: str = ""

    @property
    def evidence_coverage(self) -> float | None:
        """下发的证据里被引用的比例。**没有下发证据时是 None（不可评估）**。

        不可评估不记 1.0——否则「一条证据都没发」会变成满分，和 P2 里
        「无行为时引用覆盖率不可评估」是同一条原则。
        """

        if not self.context.evidence_sent:
            return None
        return len(self.evidence_referenced) / self.context.evidence_sent

    @property
    def evidence_omission_rate(self) -> float | None:
        """下发了但没被引用的证据比例。与引用覆盖率互补。"""

        coverage = self.evidence_coverage
        return None if coverage is None else 1.0 - coverage

    def to_payload(self) -> dict[str, Any]:
        """转成可 JSON 序列化的字典，用于台账归档。

        缺账单写 `null` 不写 0；估算值单独放在 `estimated` 下，
        不和数据里的真实账单混在一起。
        """

        return {
            "duration_ms": round(self.duration_ms, 1),
            "rounds": self.rounds,
            "tokens": {
                "total": self.tokens_total,
                "first_round": self.tokens_first_round,
                "tool_rounds": self.tokens_tool_rounds,
                "cache_hit": self.cache_hit_tokens,
            },
            "context": {
                "bytes": self.context.context_bytes,
                "estimated_input_tokens": self.context.estimated_input_tokens,
                "evidence_available": self.context.evidence_available,
                "evidence_sent": self.context.evidence_sent,
                "evidence_truncation_rate": _round(self.context.evidence_truncation_rate),
                "event_tokens": list(self.context.event_tokens),
                "evidence_tokens": dict(self.context.evidence_tokens),
            },
            "evidence": {
                "referenced": list(self.evidence_referenced),
                "coverage": _round(self.evidence_coverage),
                "omission_rate": _round(self.evidence_omission_rate),
            },
            "cost": {"estimated": _round(self.estimated_cost, 6), "note": self.price_note},
        }


def _round(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(value, digits)


def _sum_tokens(usage: dict[str, Any] | None) -> int | None:
    """一轮用量的 prompt + completion。缺任一项就算不出来，返回 None。"""

    if not usage:
        return None
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if not isinstance(prompt, int) or not isinstance(completion, int):
        return None
    return prompt + completion


def measure_context(context: dict[str, Any], result: Any) -> ContextBreakdown:
    """量出上下文体量，并把体量分摊到每个事件 / 每条证据上。

    `result` 用来拿「全部证据条数」（含没进上下文的），从而算出截断率。
    """

    context_bytes = len(json.dumps(context, ensure_ascii=False).encode("utf-8"))

    event_tokens: list[dict[str, Any]] = []
    evidence_tokens: dict[str, int] = {}
    sent = 0
    for index, event in enumerate(context.get("events") or []):
        event_tokens.append(
            {
                "index": index,
                "name": str(event.get("name") or ""),
                "risk_level": str(event.get("risk_level") or ""),
                "tokens": estimate_tokens(json.dumps(event, ensure_ascii=False)),
            }
        )
        for item in event.get("evidence_items") or []:
            sent += 1
            evidence_id = item.get("id")
            if evidence_id:
                evidence_tokens[str(evidence_id)] = estimate_tokens(
                    json.dumps(item, ensure_ascii=False)
                )

    available = sum(len(getattr(event, "evidence_items", []) or []) for event in result.events)

    return ContextBreakdown(
        context_bytes=context_bytes,
        estimated_input_tokens=estimate_tokens(json.dumps(context, ensure_ascii=False)),
        event_tokens=event_tokens,
        evidence_tokens=evidence_tokens,
        evidence_available=available,
        # 计「条数」而不是 `len(evidence_tokens)`：同一条证据可能出现在多个事件里，
        # 按 id 去重会把分母算小，覆盖率就会虚高甚至超过 1。
        evidence_sent=sent,
    )


def estimate_cost(usage: dict[str, Any] | None, prices: PriceTable) -> float | None:
    """按单价估算成本。**单价没配全就返回 None**，不返回 0。

    缓存命中部分按 `cache_hit_per_m` 计价；没单独配就用输入价（保守估计，宁可高估）。
    """

    if not prices.configured or not usage:
        return None

    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if not isinstance(prompt, int) or not isinstance(completion, int):
        return None

    cache_hit = usage.get("cache_hit_tokens")
    cache_hit = cache_hit if isinstance(cache_hit, int) and cache_hit > 0 else 0
    cache_hit = min(cache_hit, prompt)
    cache_miss = prompt - cache_hit

    hit_price = prices.cache_hit_per_m if prices.cache_hit_per_m is not None else prices.input_per_m
    total = (
        cache_miss * prices.input_per_m
        + cache_hit * hit_price
        + completion * prices.output_per_m
    )
    return total / 1_000_000


def build_metrics(
    *,
    context: dict[str, Any],
    result: Any,
    tool_trace: list[dict[str, Any]] | None,
    evidence_referenced: list[str],
    duration_ms: float,
    prices: PriceTable,
) -> JudgementMetrics:
    """把一次研判的原始观测值汇总成指标。"""

    trace = tool_trace or []
    usage_entries = [
        entry.get("usage")
        for entry in trace
        if isinstance(entry, dict) and entry.get("tool") == "usage" and entry.get("usage")
    ]
    merged = usage_entries[-1] if usage_entries else None

    total = _sum_tokens(merged)
    first, tool_rounds = _split_rounds(merged, total)
    cache_hit = merged.get("cache_hit_tokens") if isinstance(merged, dict) else None

    return JudgementMetrics(
        duration_ms=duration_ms,
        tokens_total=total,
        tokens_first_round=first,
        tokens_tool_rounds=tool_rounds,
        cache_hit_tokens=cache_hit if isinstance(cache_hit, int) else None,
        rounds=int(merged.get("rounds") or 0) if isinstance(merged, dict) else 0,
        context=measure_context(context, result),
        evidence_referenced=list(evidence_referenced),
        estimated_cost=estimate_cost(merged, prices),
        price_note=prices.note,
    )


def _split_rounds(
    merged: dict[str, Any] | None, total: int | None
) -> tuple[int | None, int | None]:
    """从 `by_round` 明细里拆出首轮与工具轮次的 token。

    没有明细（旧数据、或服务端没回传）时返回 `(None, None)`——
    **不拿总数冒充首轮**。那会让「首轮成本」恒等于总成本，看起来像「后续轮次不花钱」，
    正好把历史裁剪的收益藏起来。
    """

    if not isinstance(merged, dict):
        return None, None
    by_round = merged.get("by_round")
    if not isinstance(by_round, list) or not by_round:
        return None, None

    first = _sum_tokens(by_round[0] if isinstance(by_round[0], dict) else None)
    if first is None or total is None:
        return None, None
    return first, max(0, total - first)
