"""MCP 只读接口：让 Claude Code / Cursor 等外部 AI 客户端直查本机分析结果。

对应用户侧诉求「开一扇门」：本项目的数据过去只能在自带网页里看，
现在按行业标准（MCP）暴露为只读工具。

纪律（与 AGENTS.md §3/§6 一致）：
- **全部工具只读**：不提供上传、分析、删除、封禁、处置类工具，不修改任何数据；
- 复用后端已有的只读工具层（`app.services.agent_tools.execute_tool`），
  不另写一套取数逻辑，保证 MCP 与页面看到的数字同源；
- 每个返回体都带 `summary`，便于客户端直接引用；数字口径与页面一致（含截断与总数）。

启动（stdio，供外部客户端拉起）：
    cd backend && .venv/Scripts/python.exe scripts/mcp_server.py

客户端配置（Claude Code 示例，命令按本机路径填写）：
    {
      "mcpServers": {
        "ai-loginsight": {
          "command": "<仓库路径>/backend/.venv/Scripts/python.exe",
          "args": ["<仓库路径>/backend/scripts/mcp_server.py"]
        }
      }
    }
"""

import sys
from pathlib import Path
from typing import Any

# 直接以脚本方式运行时，保证能 import 到 app 包
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from app.database import repository  # noqa: E402
from app.services.agent_tools import execute_tool  # noqa: E402
from app.services.ai_ledger import ai_ledger_repository  # noqa: E402
from app.services.threat_intel import enrich as enrich_threat_intel  # noqa: E402

mcp = FastMCP("ai-loginsight")


def _load(analysis_id: str) -> tuple[Any, list[dict[str, str | None]]]:
    """读取分析结果与原始记录；不存在时抛出可读错误（客户端会原样展示）。"""

    result = repository.get(analysis_id)
    if result is None:
        raise ValueError(
            f"分析记录不存在：{analysis_id}。可先用 list_analyses 查看可用的分析 ID。"
        )
    return result, repository.get_records(analysis_id) or []


def _tool(analysis_id: str, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """把请求转给后端已有只读工具层，避免 MCP 与页面出现两套口径。"""

    result, records = _load(analysis_id)
    return execute_tool(name, arguments or {}, result, records)


@mcp.tool()
def list_analyses(limit: int = 20) -> dict[str, Any]:
    """列出本机的历史分析记录（按时间倒序），返回分析 ID、文件名、日志类型、风险等级与状态。

    先用它拿到 analysis_id，再调用其它工具查看明细。
    """

    summaries = repository.list()
    items = sorted(summaries, key=lambda item: item.created_at, reverse=True)
    limited = items[: max(1, min(limit, 200))]
    return {
        "summary": f"共 {len(items)} 条分析记录，返回最近 {len(limited)} 条。",
        "total": len(items),
        "items": [
            {
                "analysis_id": item.id,
                "filename": item.filename,
                "log_type": item.log_type,
                "status": item.status,
                "risk_level": item.risk_level,
                "created_at": item.created_at,
            }
            for item in limited
        ],
    }


@mcp.tool()
def analysis_overview(analysis_id: str) -> dict[str, Any]:
    """查看一次分析的整体结论：风险等级、置信度、结论、检测覆盖度与建议。

    结论三态口径与页面一致：覆盖完整且未命中 → 「未发现异常」；
    覆盖不完整 → 「无法确认」（不代表正常）。

    注意：`events` / `events_total` 是规则命中事件数的真实口径，
    不要用返回条数推断总数。
    """

    result, _ = _load(analysis_id)
    coverage = result.coverage
    return {
        "summary": result.conclusion,
        "analysis_id": result.id,
        "filename": result.metadata.filename,
        "log_type": result.metadata.log_type,
        "risk_level": result.risk_level,
        "confidence": result.confidence,
        "events_total": result.events_total if result.events_total is not None else len(result.events),
        "behavior_deviations": len(result.behavior_deviations),
        "analysis_source": result.analysis_source,
        "ai_status": result.ai_status,
        "coverage": {
            "total_records": coverage.total_records,
            "covered_records": coverage.covered_records,
            "uncovered_records": coverage.uncovered_records,
            "parse_failures": coverage.parse_failures,
            "whitelisted_records": coverage.whitelisted_records,
            "limitation": coverage.limitation,
        },
        "recommendations": result.recommendations,
    }


@mcp.tool()
def analysis_metadata(analysis_id: str) -> dict[str, Any]:
    """读取日志类型、来源文件、行数、解析情况与时间范围。"""

    return _tool(analysis_id, "log_metadata")


@mcp.tool()
def analysis_statistics(analysis_id: str) -> dict[str, Any]:
    """读取认证成功/失败计数、来源 IP / 账户 / 状态码 Top 统计。"""

    return _tool(analysis_id, "log_statistics")


@mcp.tool()
def query_events(
    analysis_id: str,
    rule_id: str = "",
    risk_level: str = "",
    event_type: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    """查询规则命中的可疑事件，可按规则编号、风险等级（critical/high/medium/low/info）或事件类型过滤。"""

    return _tool(
        analysis_id,
        "query_events",
        {"rule_id": rule_id, "risk_level": risk_level, "event_type": event_type, "limit": limit},
    )


@mcp.tool()
def query_evidence(
    analysis_id: str,
    evidence_id: str = "",
    event_id: str = "",
    record_id: str = "",
) -> dict[str, Any]:
    """读取证据原文（`evidence-record-N` / `record-N`），是研判的事实依据。"""

    return _tool(
        analysis_id,
        "query_evidence",
        {"evidence_id": evidence_id, "event_id": event_id, "record_id": record_id},
    )


@mcp.tool()
def timeline(analysis_id: str, limit: int = 50) -> dict[str, Any]:
    """按时间顺序读取事件与证据，用于判断「失败之后是否成功」这类前后关系。"""

    return _tool(analysis_id, "timeline", {"limit": limit})


@mcp.tool()
def query_behavior_deviations(analysis_id: str) -> dict[str, Any]:
    """读取 IOA 行为偏离（同批次低频实体、非常用端口外联等）。

    偏离是低置信度信号，**不改变风险等级**；没有攻击特征时它才是主要产出。
    """

    return _tool(analysis_id, "query_behavior_deviations")


@mcp.tool()
def query_uncovered_records(analysis_id: str, log_type: str = "") -> dict[str, Any]:
    """读取未命中任何规则的原始记录样本（相当于「正常基线」），用于交叉验证结论。"""

    return _tool(analysis_id, "query_uncovered_records", {"log_type": log_type})


@mcp.tool()
def query_terminal_chains(analysis_id: str, target_asset: str = "", kind: str = "") -> dict[str, Any]:
    """读取终端证据链：按目标资产聚合的进程、文件、注册表、DNS 与外联节点。"""

    return _tool(analysis_id, "query_terminal_chains", {"target_asset": target_asset, "kind": kind})


@mcp.tool()
def query_records(
    analysis_id: str,
    field: str = "",
    contains: str = "",
    equals: str = "",
    log_type: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    """按字段查原始记录。字段示例：source_ip / destination_ip / username / url / status / query_name / process_image。

    `contains` 为包含匹配（忽略大小写），`equals` 为精确匹配。需要「某个来源 IP 到底做了什么」时用它。
    """

    return _tool(
        analysis_id,
        "query_records",
        {
            "field": field,
            "contains": contains,
            "equals": equals,
            "log_type": log_type,
            "limit": limit,
        },
    )


@mcp.tool()
def ai_ledger(analysis_id: str) -> dict[str, Any]:
    """读取 AI 研判台账：模型与参数、每次工具调用、结论引用的证据、溯源校验结果与耗时。

    人工确认状态与结论分层口径（原始事实 / 规则命中 / AI 推断 / 人工确认）同样从这里读。
    """

    ledger = ai_ledger_repository.get(analysis_id)
    if ledger is None:
        return {"summary": "该分析还没有 AI 研判台账。", "available": False}
    return {
        "summary": ledger.summary,
        "available": True,
        "model": ledger.model,
        "provider": ledger.provider,
        "status": ledger.status,
        "duration_ms": ledger.duration_ms,
        "evidence_ids": ledger.evidence_ids,
        "unsupported_claims": ledger.unsupported_claims,
        "tool_trace": [call.model_dump() for call in ledger.tool_trace],
        "usage": ledger.usage,
        "created_at": ledger.created_at,
    }


@mcp.tool()
def threat_intel(analysis_id: str, refresh: bool = False) -> dict[str, Any]:
    """把本批日志中的公网 IP / 域名送到公开威胁情报库比对（独立展示，不改变风险等级）。

    默认关闭：未开启时返回 `enabled=false` 与开启方法，不发出任何外部请求。
    `refresh=true` 忽略缓存强制重查。
    """

    result, records = _load(analysis_id)
    report = enrich_threat_intel(analysis_id, result, records, refresh=refresh)
    return report.model_dump()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
