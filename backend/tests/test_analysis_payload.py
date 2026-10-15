"""详情响应的事件上限：大记录的响应体必须可控，但总数不能谎报。

背景：域控导出曾让 `/api/analysis/{id}` 返回 37 MB（7536 个事件），前端要解析这份 JSON
并一次性渲染全部事件卡，界面就停在「正在加载分析结果…」。这里锁的是「按上限裁剪 +
events_total 保持真值 + 报告仍是全量」三条。

截断只留前 N 条，所以「前 N 条」必须是风险最高的 N 条：事件列表按风险从高到低排列
（同级按次数降序），否则用户点开大记录最先看到的是最早产出的事件，而不是最严重的。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import ANALYSIS_EVENT_LIMIT_DEFAULT, app, _trim_events
from app.models import AnalysisResult, Event, sort_events_by_risk

client = TestClient(app)

# 20 个不同来源各打一个敏感路径 → 规则按来源聚合后产生 20 个事件
LOG = "\n".join(
    f'198.51.100.{index + 1} - - [21/Sep/2026:09:{index:02d}:00 +0800] '
    f'"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
    for index in range(20)
)

# 风险混杂：3 个来源探测 .env（medium），最后一行才是敏感文件被成功读取（high）。
# 高风险写在文件末尾，就是为了让「按检测产出顺序截取」这种实现露馅。
MIXED_LOG = "\n".join(
    [
        *(
            f'198.51.100.{index + 10} - - [21/Sep/2026:09:{index:02d}:00 +0800] '
            f'"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
            for index in range(3)
        ),
        '203.0.113.7 - - [21/Sep/2026:09:30:00 +0800] "GET /id_rsa HTTP/1.1" 200 1 "-" "curl/8.0"',
    ]
)


def _event(event_id: str, count: int, level: str = "high") -> Event:
    return Event(id=event_id, type="t", name=event_id, risk_level=level, count=count, summary="s")


def _upload() -> dict:
    response = client.post(
        "/api/logs/upload", files={"file": ("a.log", LOG, "text/plain")}
    )
    assert response.status_code == 200
    return response.json()["result"]


def test_detail_response_is_capped_and_reports_the_real_total():
    body = _upload()
    assert len(body["events"]) == 20
    analysis_id = body["id"]

    page = client.get(f"/api/analysis/{analysis_id}?event_limit=5").json()
    assert len(page["events"]) == 5
    # 裁剪只影响列表长度，总数必须是真值，否则界面会谎报「只有 5 个事件」
    assert page["events_total"] == 20

    rejected = client.get(f"/api/analysis/{analysis_id}?event_limit=0")
    assert rejected.status_code == 422


def test_detail_response_default_limit_is_applied_to_large_records():
    body = _upload()
    assert ANALYSIS_EVENT_LIMIT_DEFAULT >= 20  # 小记录不该被裁
    page = client.get(f"/api/analysis/{body['id']}").json()
    assert len(page["events"]) == 20
    assert page["events_total"] == 20


def test_detail_response_supports_offset_pagination():
    body = _upload()
    first = client.get(f"/api/analysis/{body['id']}?event_offset=0&event_limit=5").json()
    second = client.get(f"/api/analysis/{body['id']}?event_offset=5&event_limit=5").json()

    assert len(first["events"]) == 5
    assert len(second["events"]) == 5
    assert first["events"][0]["id"] != second["events"][0]["id"]
    assert first["events_total"] == second["events_total"] == 20


def test_trim_events_backfills_total_for_records_saved_before_the_field_existed():
    """老记录里没有 events_total：裁剪时必须按裁剪前的真实长度补齐。"""

    body = _upload()
    page = client.get(f"/api/analysis/{body['id']}?event_limit=200").json()
    result = AnalysisResult.model_validate(page)
    result = result.model_copy(update={"events_total": None})

    trimmed = _trim_events(result, 3)
    assert len(trimmed.events) == 3
    assert trimmed.events_total == len(result.events)


def test_html_report_keeps_every_event_even_when_api_trims():
    """报告直接读存储，不受 HTTP 裁剪影响 —— 导出必须是完整清单。"""

    body = _upload()
    report = client.get(f"/api/analysis/{body['id']}/report?format=html")
    assert report.status_code == 200
    assert report.text.count("sensitive_path_access") >= 20


def test_events_are_listed_highest_risk_first():
    """事件列表按风险从高到低：高风险写在日志最后一行也要排在最前面。"""

    response = client.post(
        "/api/logs/upload", files={"file": ("mixed.log", MIXED_LOG, "text/plain")}
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert [event["risk_level"] for event in body["events"]] == [
        "high",
        "medium",
        "medium",
        "medium",
    ]

    page = client.get(f"/api/analysis/{body['id']}").json()
    assert [event["risk_level"] for event in page["events"]] == [
        "high",
        "medium",
        "medium",
        "medium",
    ]


def test_trimming_keeps_the_most_severe_event():
    """只返回前 1 条时，那一条必须是 high，而不是最早产出的 medium。"""

    response = client.post(
        "/api/logs/upload", files={"file": ("mixed.log", MIXED_LOG, "text/plain")}
    )
    body = response.json()["result"]

    page = client.get(f"/api/analysis/{body['id']}?event_limit=1").json()
    assert [event["risk_level"] for event in page["events"]] == ["high"]
    assert "203.0.113.7" in page["events"][0]["summary"]
    assert page["events_total"] == 4


def test_trim_events_sorts_records_that_were_saved_in_detection_order():
    """老记录落库时是检测产出顺序，读取时也要补上风险排序。"""

    response = client.post(
        "/api/logs/upload", files={"file": ("mixed.log", MIXED_LOG, "text/plain")}
    )
    body = response.json()["result"]
    stored = AnalysisResult.model_validate(
        client.get(f"/api/analysis/{body['id']}?event_limit=200").json()
    )
    # 模拟老记录：把事件恢复成「高风险在最后」的检测产出顺序
    legacy = stored.model_copy(
        update={"events": list(reversed(stored.events)), "events_total": None}
    )
    assert legacy.events[-1].risk_level == "high"

    trimmed = _trim_events(legacy, 1)
    assert len(trimmed.events) == 1
    assert trimmed.events[0].risk_level == "high"
    assert trimmed.events_total == len(legacy.events)


def test_same_level_events_are_ordered_by_count():
    ordered = sort_events_by_risk([_event("a", 1), _event("b", 9), _event("c", 9)])
    assert [item.id for item in ordered] == ["b", "c", "a"]
    assert [item.id for item in sort_events_by_risk(ordered)] == ["b", "c", "a"]  # 幂等
