"""MCP 只读接口测试。

走真实的 MCP 协议（内存传输），不是直接调函数——「客户端能不能列到工具、能不能调通」
才是这个接口的交付物。同时把「只读」这条边界钉进测试：工具名单里不允许出现
任何写 / 删 / 处置类动作。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402

from app.main import app  # noqa: E402
from mcp_server import mcp  # noqa: E402

client = TestClient(app)

#: 允许出现的工具名（白名单，新增工具必须同步更新这里，避免悄悄放开写操作）
EXPECTED_TOOLS = {
    "list_analyses",
    "analysis_overview",
    "analysis_metadata",
    "analysis_statistics",
    "query_events",
    "query_evidence",
    "timeline",
    "query_behavior_deviations",
    "query_uncovered_records",
    "query_terminal_chains",
    "query_records",
    "ai_ledger",
    "threat_intel",
}

FORBIDDEN_KEYWORDS = (
    "delete", "remove", "upload", "write", "create", "update", "patch", "run",
    "exec", "execute", "ban", "block", "isolate", "kill", "start_ai", "analyze_upload",
)


@pytest.fixture(scope="module")
def analysis_id() -> str:
    demos = client.get("/api/demo/logs").json()
    if not demos:
        pytest.skip("演示日志库为空")
    response = client.post("/api/demo/analyze", json={"files": [demos[0]["path"]]})
    assert response.status_code == 200
    return response.json()["analysis_id"]


def _structured(result) -> dict:
    """从工具调用结果里取回结构化内容（FastMCP 会转成 JSON 文本）。"""

    import json

    text = "".join(block.text for block in result.content if getattr(block, "text", None))
    return json.loads(text)


def test_tool_list_is_read_only():
    import anyio

    async def _check() -> None:
        async with create_connected_server_and_client_session(mcp._mcp_server) as session:
            listed = await session.list_tools()
            names = {tool.name for tool in listed.tools}
            assert names == EXPECTED_TOOLS
            for name in names:
                assert not any(keyword in name for keyword in FORBIDDEN_KEYWORDS), name
            # 每个工具都必须有可读描述，否则外部客户端只能靠猜
            assert all(tool.description for tool in listed.tools)

    anyio.run(_check)


def test_tools_query_real_analysis(analysis_id: str):
    import anyio

    async def _check() -> None:
        async with create_connected_server_and_client_session(mcp._mcp_server) as session:
            listed = await session.list_tools()
            assert {tool.name for tool in listed.tools} == EXPECTED_TOOLS

            overview = _structured(
                await session.call_tool("analysis_overview", {"analysis_id": analysis_id})
            )
            assert overview["analysis_id"] == analysis_id
            assert "coverage" in overview

            events = _structured(
                await session.call_tool(
                    "query_events", {"analysis_id": analysis_id, "limit": 5}
                )
            )
            assert "summary" in events

            metadata = _structured(
                await session.call_tool("analysis_metadata", {"analysis_id": analysis_id})
            )
            assert metadata["log_type"]

            # 威胁情报默认关闭：通过 MCP 调用同样不得触发外部请求
            intel = _structured(
                await session.call_tool("threat_intel", {"analysis_id": analysis_id})
            )
            assert intel["enabled"] is False

            analyses = _structured(await session.call_tool("list_analyses", {"limit": 5}))
            assert any(item["analysis_id"] == analysis_id for item in analyses["items"])

    anyio.run(_check)


def test_unknown_analysis_returns_readable_error():
    import anyio

    async def _check() -> None:
        async with create_connected_server_and_client_session(mcp._mcp_server) as session:
            result = await session.call_tool(
                "analysis_overview", {"analysis_id": "not-a-real-id"}
            )
            assert result.isError is True
            text = result.content[0].text
            assert "分析记录不存在" in text

    anyio.run(_check)
