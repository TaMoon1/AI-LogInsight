"""AI 用量历史的持久化与端点口径。

前端要展示「跨分析的 token 消耗趋势」，数据源是每次研判写进
`result_json` 里 `ai_tool_trace` 的那条 `tool == "usage"` 记录。
本文件锁住三件事：

1. 能在库内（`json_each` / `json_extract`）定位到用量，不必反序列化整份结果；
2. **没有用量记录时返回 `None`，绝不返回 0**——「没记录」与「消耗为 0」是两回事，
   用 0 填充会把趋势图画出误导性的低谷；
3. 汇总只按确实有用量的点计算，并如实报告 `with_usage` / `total_points`。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import AiToolCall
from app.services.analyzer import analyze_log

client = TestClient(app)

SAMPLE = "Sep 12 01:00:00 demo sshd[100]: Failed password for root from 10.0.0.8 port 22 ssh2"


@pytest.fixture()
def repo():
    """使用**与 app 同一个**仓储实例。

    conftest 已把 `LOGINSIGHT_DB_PATH` 指向临时库，所以这里直接复用
    `app.main.repository` 就是隔离的；若另开一个 `AnalysisRepository`，
    数据写进了别的库，端到端断言就看不到（这正是最初写错的地方）。
    每个用例前清空 `analyses`，避免用例间互相污染。
    """

    from app.main import repository

    with repository.connect() as connection:
        connection.execute("DELETE FROM analyses")
        connection.commit()
    return repository


def _seed(repo, analysis_id: str, filename: str, created_at: str, usage: dict | None) -> None:
    """写入一条已完成的分析；`usage=None` 表示这次研判没留下用量记录。"""

    result = analyze_log(filename, SAMPLE)
    trace = [
        {"tool": "log_metadata", "arguments": {}, "summary": "s", "source": "auto"},
        {"tool": "query_events", "arguments": {}, "summary": "s", "source": "model"},
    ]
    if usage is not None:
        trace.append({"tool": "usage", "source": "auto", "summary": "", "usage": usage})
    # 用 AiToolCall 校验，保证写进去的就是接口模型接受的结构
    result = result.model_copy(
        update={
            "id": analysis_id,
            "filename": filename,
            "ai_tool_trace": [AiToolCall.model_validate(item) for item in trace],
        }
    )
    repo.create(analysis_id, filename, created_at)
    repo.complete(result, [])


def test_usage_is_extracted_from_result_json(repo):
    """用量要能用 SQLite 的 json 函数直接从库里抽出来。"""

    _seed(repo, "a1", "with.json", "2026-09-23T00:00:00",
          {"prompt_tokens": 1000, "completion_tokens": 100, "cache_hit_ratio": 0.8})
    _seed(repo, "a2", "without.json", "2026-09-22T00:00:00", None)

    history = repo.ai_usage_history(10)
    by_name = {item["filename"]: item for item in history}

    assert by_name["with.json"]["usage"]["prompt_tokens"] == 1000
    # 关键：缺失就是 None，不能被填成 0
    assert by_name["without.json"]["usage"] is None


def test_missing_usage_is_not_coerced_to_zero(repo):
    """没有用量记录时必须是 None —— 0 会被前端画成「这次几乎没花钱」。"""

    _seed(repo, "a1", "nousage.json", "2026-09-23T00:00:00", None)

    history = repo.ai_usage_history(10)
    assert len(history) == 1
    assert history[0]["usage"] is None

    payload = client.get("/api/ai/usage-history").json()
    assert payload["with_usage"] == 0
    assert payload["avg_prompt_tokens"] == 0
    assert payload["avg_cache_hit_ratio"] is None


def test_history_is_ordered_newest_first(repo):
    """趋势图按时间推进，接口应给出「新的在前」，由前端决定是否反转。"""

    _seed(repo, "a1", "old.json", "2026-09-01T00:00:00",
          {"prompt_tokens": 100, "completion_tokens": 1})
    _seed(repo, "a2", "new.json", "2026-09-20T00:00:00",
          {"prompt_tokens": 900, "completion_tokens": 9})

    history = repo.ai_usage_history(10)
    assert [item["filename"] for item in history] == ["new.json", "old.json"]


def test_limit_caps_returned_points(repo):
    for index in range(5):
        _seed(repo, f"a{index}", f"f{index}.json", f"2026-09-0{index + 1}T00:00:00",
              {"prompt_tokens": 100 * (index + 1), "completion_tokens": 1})

    assert len(repo.ai_usage_history(2)) == 2


def test_records_without_usage_are_excluded_from_averages(repo):
    """汇总只按有用量的点算，否则会被人为拉低。"""

    _seed(repo, "a1", "u1.json", "2026-09-01T00:00:00",
          {"prompt_tokens": 1000, "completion_tokens": 100, "cache_hit_ratio": 0.8})
    _seed(repo, "a2", "u2.json", "2026-09-02T00:00:00",
          {"prompt_tokens": 2000, "completion_tokens": 200, "cache_hit_ratio": 0.5})
    _seed(repo, "a3", "none.json", "2026-09-03T00:00:00", None)

    payload = client.get("/api/ai/usage-history").json()
    # 三个点里只有两个有账单 —— 这一点必须如实告知前端
    assert payload["with_usage"] == 2
    assert payload["total_points"] == 3
    assert payload["avg_prompt_tokens"] == 1500
    assert payload["avg_completion_tokens"] == 150
    assert abs(payload["avg_cache_hit_ratio"] - 0.65) < 1e-6


def test_usage_history_endpoint_shape():
    """端点返回结构稳定，前端可以直接按字段读取。"""

    payload = client.get("/api/ai/usage-history?limit=5").json()
    assert {"points", "with_usage", "total_points", "avg_prompt_tokens",
            "avg_completion_tokens", "avg_cache_hit_ratio"} <= set(payload)
    assert isinstance(payload["points"], list)
    for point in payload["points"]:
        assert {"analysis_id", "filename", "log_type", "created_at", "usage"} <= set(point)


def test_usage_history_rejects_invalid_limit():
    assert client.get("/api/ai/usage-history?limit=0").status_code == 422
    assert client.get("/api/ai/usage-history?limit=999").status_code == 422
