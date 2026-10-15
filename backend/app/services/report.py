from __future__ import annotations

import html
import json

from ..models import AnalysisResult, HumanReview
from .review import REVIEW_LABELS


def build_provenance(
    result: AnalysisResult, review: HumanReview | None
) -> list[dict[str, str | int]]:
    """声明报告里每一层结论的来源，避免把 AI 推断当成事实读。

    只给「这一层在哪、有多少条」，不复制数据本身——报告体积不能因为分层而翻倍。
    """

    evidence_count = sum(len(event.evidence_items) for event in result.events)
    return [
        {
            "layer": "raw_fact",
            "label": "原始事实",
            "description": "日志原文，未经任何推断；每段都带 record_id 与来源文件。",
            "locator": "events[].evidence_items[]",
            "count": evidence_count,
        },
        {
            "layer": "rule_hit",
            "label": "规则命中",
            "description": "确定性规则检出，可追溯到 rule_id 与触发次数。",
            "locator": "events[]",
            "count": len(result.events),
        },
        {
            "layer": "ai_inference",
            "label": "AI 推断",
            "description": "模型推断，未经人工确认，不得当作事实；"
            "引用不存在的证据会被溯源校验拦下并记录在 ai_unsupported_claims。",
            "locator": "ai_behaviors[] / structured_verdict",
            "count": len(result.ai_behaviors),
        },
        {
            "layer": "human_confirmation",
            "label": "人工确认",
            "description": "人工对 AI 结论的确认状态与留痕。",
            "locator": "human_review",
            "count": len(review.history) if review else 0,
        },
    ]


def render_json_report(
    result: AnalysisResult, review: HumanReview | None = None
) -> str:
    payload = json.loads(result.model_dump_json())
    payload["provenance"] = build_provenance(result, review)
    payload["human_review"] = review.model_dump() if review else None
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _review_block(review: HumanReview | None) -> str:
    if review is None or not review.history:
        return (
            '<p style="color:#a32d2d;font-weight:bold">人工确认：未确认 —— '
            "以下 AI 内容均为模型推断，尚未经人工核实，不得作为事实结论使用。</p>"
        )
    latest = review.history[-1]
    rows = "".join(
        f"<li>{html.escape(item.created_at)} · "
        f"{html.escape(REVIEW_LABELS.get(item.status, item.status))} · "
        f"{html.escape(item.reviewer)}"
        f"{f' · {html.escape(item.note)}' if item.note else ''}</li>"
        for item in reversed(review.history)
    )
    return (
        f'<p><strong>人工确认：{html.escape(REVIEW_LABELS.get(latest.status, latest.status))}</strong>'
        f" · 确认人 {html.escape(latest.reviewer)}"
        f" · {html.escape(latest.created_at)}"
        f"{f' · 备注：{html.escape(latest.note)}' if latest.note else ''}</p>"
        f"<p>确认历史（新→旧）：</p><ul>{rows}</ul>"
    )


def _ai_block(result: AnalysisResult) -> str:
    """AI 推断单独成块并显式标注，避免读者把模型说法当规则结论。"""

    parts: list[str] = []
    verdict = result.structured_verdict
    if verdict is not None:
        fields = [
            ("事件时间", verdict.event_time),
            ("攻击源 IP", verdict.attack_source_ip),
            ("目标资产", verdict.target_asset),
            ("涉及账号", verdict.involved_account),
            ("异常行为", verdict.abnormal_behavior),
            ("攻击类型", verdict.attack_type),
            ("风险等级", verdict.risk_level),
            ("判断依据", verdict.judgment_basis),
            ("成功迹象", verdict.success_indicator),
        ]
        rows = "".join(
            f"<dt>{html.escape(label)}</dt><dd>{html.escape(value)}</dd>"
            for label, value in fields
            if value
        )
        if verdict.related_logs:
            rows += (
                "<dt>关联日志</dt><dd>"
                + html.escape("；".join(verdict.related_logs))
                + "</dd>"
            )
        if verdict.recommended_actions:
            rows += (
                "<dt>建议处置</dt><dd>"
                + html.escape("；".join(verdict.recommended_actions))
                + "</dd>"
            )
        parts.append(f"<h3>结构化研判</h3><dl>{rows}</dl>")
    if result.ai_behaviors:
        items = "".join(
            f"<li><strong>{html.escape(item.name)}</strong>"
            f"（置信度 {item.confidence:.0%}）"
            f"<br>{html.escape(item.analysis)}"
            f"<br>引用证据：{html.escape('、'.join(item.evidence_ids) or '未引用')}</li>"
            for item in result.ai_behaviors
        )
        parts.append(f"<h3>识别行为</h3><ul>{items}</ul>")
    if result.ai_unsupported_claims:
        items = "".join(
            f"<li>{html.escape(item)}</li>" for item in result.ai_unsupported_claims
        )
        parts.append(
            f"<h3>被溯源校验拦下的无证据说法</h3><ul>{items}</ul>"
        )
    if not parts:
        parts.append("<p>本次没有产出 AI 推断内容。</p>")
    return (
        "<section><h2>AI 推断（未经人工确认）</h2>"
        "<p>以下内容由模型根据日志推断得出，只表示「模型认为」，"
        "不构成规则命中或人工确认的事实；引用不存在的证据不会被采纳。</p>"
        f"{''.join(parts)}</section>"
    )


def render_html_report(
    result: AnalysisResult, review: HumanReview | None = None
) -> str:
    payload = json.loads(result.model_dump_json())
    title = html.escape(f"AI-LogInsight 研判报告 - {result.metadata.filename}")
    events = "".join(
        f"<li><strong>{html.escape(event['name'])}</strong> "
        f"[{html.escape(event['risk_level'])}] "
        f"{html.escape(event['summary'])}"
        f"<br>检测规则：{html.escape(event.get('rule_id') or '未标记')}"
        f"<br>来源文件：{html.escape(', '.join(event.get('source_files', [])) or '未标记')}"
        f"<br>关联依据：{html.escape('；'.join(event.get('correlation_basis', [])) or '单事件证据')}</li>"
        for event in payload["events"]
    ) or f"<li>{html.escape(payload['summary'])}</li>"
    recommendations = "".join(
        f"<li>{html.escape(item)}</li>" for item in payload["recommendations"]
    )
    timeline = "".join(
        f"<li>{html.escape(item)}</li>"
        for event in payload["events"]
        for item in event.get("timeline", [])
    ) or "<li>没有可展示的事件时间线。</li>"
    limitation_block = (
        f'<p style="color:#a32d2d;font-weight:bold">检测覆盖不足：'
        f"{html.escape(result.coverage.limitation or '')}</p>"
        if result.coverage.limitation
        else ""
    )
    drop_parts: list[str] = []
    if result.coverage.parse_errors:
        drop_parts.append(f"解析失败 {result.coverage.parse_errors} 条")
    if result.coverage.retention_drops:
        drop_parts.append(f"超出单次保留上限 {result.coverage.retention_drops} 条")
    drop_detail = f"（{'、'.join(drop_parts)}）" if drop_parts else ""
    parse_error_items: list[str] = []
    for item in result.coverage.parse_error_details:
        location = html.escape(str(item.get("source_file") or "未标记文件"))
        if item.get("line_number"):
            location += f" · 第 {item['line_number']} 条"
        raw_preview = (
            f"<br><code>{html.escape(str(item['raw_preview']))}</code>"
            if item.get("raw_preview")
            else ""
        )
        parse_error_items.append(
            f"<li><strong>{location}</strong>"
            f"<br>{html.escape(str(item.get('reason') or '解析失败'))}"
            f"{raw_preview}</li>"
        )
    parse_error_details = "".join(parse_error_items)
    parse_error_section = (
        "<section><h2>解析失败详情</h2>"
        "<p>以下仅展示受限数量的失败摘要，未展示内容不代表已解析成功。</p>"
        f"<ul>{parse_error_details}</ul></section>"
        if parse_error_details
        else ""
    )
    deviations = "".join(
        f"<li><strong>{html.escape(item['name'])}</strong>（{html.escape(item['basis'])}，×{item['count']}）"
        f"<br>{html.escape(item['detail'])}</li>"
        for item in payload.get("behavior_deviations", [])
    )
    deviations_section = (
        "<section><h2>行为偏离（IOA）</h2><ul>"
        f"{deviations}</ul>"
        "<p>以上为低置信度行为偏离，"
        "仅表示「与本批次相比首次出现」等偏离事实，不构成攻击结论，也不改变风险等级。</p></section>"
        if deviations
        else ""
    )
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:Arial,"Microsoft YaHei",sans-serif;max-width:960px;margin:40px auto;color:#172033;line-height:1.6}}
h1{{border-bottom:2px solid #1967d2;padding-bottom:12px}}.meta{{background:#f4f7fb;padding:16px}}
.risk{{font-size:24px;font-weight:bold}}section{{margin-top:28px}}li{{margin:8px 0}}
dl{{display:grid;grid-template-columns:140px 1fr;gap:4px 12px}}
dt{{font-weight:bold}}
pre{{background:#f5f7fa;padding:12px;white-space:pre-wrap}}</style></head>
<body><h1>{title}</h1>
<div class="meta"><p>日志类型：{html.escape(result.metadata.log_type)}</p>
<p>来源文件：{html.escape(", ".join(result.metadata.source_files))}</p>
<p class="risk">当前研判：{html.escape(result.risk_level)}</p>
<p>置信度：{result.confidence:.0%}</p><p>{html.escape(result.conclusion)}</p>
<p>检测覆盖：{result.coverage.covered_records}/{result.coverage.total_records} 条记录命中规则 ·
可判定字段 {result.coverage.evaluable_records} 条 ·
未纳入检测 {result.coverage.parse_failures} 条{drop_detail}</p>
{limitation_block}
{_review_block(review)}</div>
<section><h2>规则命中事件</h2>
<p>以下事件来自确定性规则检测，可追溯到具体规则编号与原始记录。</p>
<ul>{events}</ul></section>
{_ai_block(result)}
{deviations_section}
{parse_error_section}
<section><h2>进一步排查</h2><ul>{recommendations}</ul></section>
<section><h2>事件时间线</h2><ul>{timeline}</ul></section>
<section><h2>完整结构化结果</h2><pre>{html.escape(json.dumps(payload, ensure_ascii=False, indent=2))}</pre></section>
</body></html>"""
