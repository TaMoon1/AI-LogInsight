"""AI 结论人工确认与导出分层。

覆盖两件事：
① 确认状态（未确认 / 确认 / 否定 / 需复核）的留痕与历史累积；
② 导出里「原始事实 / 规则命中 / AI 推断 / 人工确认」四层必须分得开，
   不能让 AI 推断在报告里看起来像规则命中。
"""

import io
import json
import zipfile

from fastapi.testclient import TestClient

from app.main import app
from app.services.review import review_repository

client = TestClient(app)


def make_ssh_log(failures: int = 20) -> str:
    lines = [
        f"Sep 12 01:00:{index:02d} host sshd[100]: Failed password for root from 10.0.0.8 port 22 ssh2"
        for index in range(failures)
    ]
    return "\n".join(lines)


def upload_log(filename: str = "review.log", content: str | None = None) -> str:
    response = client.post(
        "/api/logs/upload",
        files={"file": (filename, content or make_ssh_log(), "text/plain")},
    )
    assert response.status_code == 200
    return response.json()["analysis_id"]


def test_review_defaults_to_pending_without_history():
    analysis_id = upload_log()
    response = client.get(f"/api/analysis/{analysis_id}/review")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "pending"
    assert payload["reviewer"] == ""
    assert payload["updated_at"] is None
    assert payload["history"] == []


def test_review_records_status_reviewer_and_keeps_history():
    analysis_id = upload_log()

    first = client.post(
        f"/api/analysis/{analysis_id}/review",
        json={"status": "confirmed", "reviewer": "张三", "note": "已比对原始日志"},
    )
    assert first.status_code == 200
    assert first.json()["status"] == "confirmed"
    assert first.json()["reviewer"] == "张三"
    assert first.json()["note"] == "已比对原始日志"
    assert len(first.json()["history"]) == 1

    second = client.post(
        f"/api/analysis/{analysis_id}/review",
        json={"status": "needs_review", "reviewer": "李四", "note": "需核实来源 IP"},
    )
    assert second.status_code == 200
    payload = second.json()
    assert payload["status"] == "needs_review"
    assert payload["reviewer"] == "李四"
    # 追加式留痕：改判不能把上一次的确认人和时间抹掉
    assert len(payload["history"]) == 2
    assert payload["history"][0]["status"] == "confirmed"
    assert payload["history"][0]["reviewer"] == "张三"
    assert payload["history"][1]["status"] == "needs_review"


def test_review_accepts_all_four_states():
    analysis_id = upload_log()
    for status in ("confirmed", "rejected", "needs_review", "pending"):
        response = client.post(
            f"/api/analysis/{analysis_id}/review",
            json={"status": status, "reviewer": "auditor"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == status


def test_review_requires_a_named_reviewer():
    analysis_id = upload_log()
    blank = client.post(
        f"/api/analysis/{analysis_id}/review",
        json={"status": "confirmed", "reviewer": "   "},
    )
    assert blank.status_code == 400
    assert "确认人" in blank.json()["detail"]

    empty = client.post(
        f"/api/analysis/{analysis_id}/review",
        json={"status": "confirmed", "reviewer": ""},
    )
    assert empty.status_code == 422


def test_review_rejects_unknown_status_and_missing_analysis():
    analysis_id = upload_log()
    assert (
        client.post(
            f"/api/analysis/{analysis_id}/review",
            json={"status": "probably", "reviewer": "auditor"},
        ).status_code
        == 422
    )
    assert client.get("/api/analysis/not-exist/review").status_code == 404
    assert (
        client.post(
            "/api/analysis/not-exist/review",
            json={"status": "confirmed", "reviewer": "auditor"},
        ).status_code
        == 404
    )


def test_report_json_declares_four_provenance_layers():
    analysis_id = upload_log()
    payload = client.get(f"/api/analysis/{analysis_id}/report?format=json").json()
    layers = {item["layer"]: item for item in payload["provenance"]}
    assert set(layers) == {
        "raw_fact",
        "rule_hit",
        "ai_inference",
        "human_confirmation",
    }
    assert layers["rule_hit"]["label"] == "规则命中"
    assert layers["rule_hit"]["count"] == len(payload["events"])
    assert layers["raw_fact"]["count"] > 0
    assert "不得当作事实" in layers["ai_inference"]["description"]
    # 未确认时 human_review 仍是空态而不是 None，前端不必做两套判断
    assert payload["human_review"]["status"] == "pending"
    assert payload["human_review"]["history"] == []
    assert layers["human_confirmation"]["count"] == 0


def test_report_json_carries_human_review_after_confirmation():
    analysis_id = upload_log()
    client.post(
        f"/api/analysis/{analysis_id}/review",
        json={"status": "rejected", "reviewer": "王五", "note": "误报，来源 IP 属扫描器白名单"},
    )
    payload = client.get(f"/api/analysis/{analysis_id}/report?format=json").json()
    assert payload["human_review"]["status"] == "rejected"
    assert payload["human_review"]["reviewer"] == "王五"
    assert payload["human_review"]["history"][0]["note"] == "误报，来源 IP 属扫描器白名单"
    layers = {item["layer"]: item for item in payload["provenance"]}
    assert layers["human_confirmation"]["count"] == 1


def test_report_html_separates_rule_hits_from_ai_inference():
    analysis_id = upload_log()
    unconfirmed = client.get(f"/api/analysis/{analysis_id}/report?format=html").text
    assert "规则命中事件" in unconfirmed
    assert "AI 推断（未经人工确认）" in unconfirmed
    assert "人工确认：未确认" in unconfirmed
    assert "不得作为事实结论使用" in unconfirmed

    client.post(
        f"/api/analysis/{analysis_id}/review",
        json={"status": "confirmed", "reviewer": "张三", "note": "已核实"},
    )
    confirmed = client.get(f"/api/analysis/{analysis_id}/report?format=html").text
    assert "人工确认：确认" in confirmed
    assert "张三" in confirmed
    assert "已核实" in confirmed


def test_case_package_report_carries_human_review():
    analysis_id = upload_log(filename="case-review.log")
    client.post(
        f"/api/analysis/{analysis_id}/review",
        json={"status": "needs_review", "reviewer": "赵六"},
    )
    response = client.get(f"/api/analysis/{analysis_id}/case-package")
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        report = json.loads(archive.read("report.json"))
        assert report["human_review"]["status"] == "needs_review"
        assert report["human_review"]["reviewer"] == "赵六"
        assert {item["layer"] for item in report["provenance"]} == {
            "raw_fact",
            "rule_hit",
            "ai_inference",
            "human_confirmation",
        }
        html_report = archive.read("report.html").decode("utf-8")
        assert "人工确认：需复核" in html_report


def test_deleting_analysis_removes_its_review_records():
    analysis_id = upload_log()
    client.post(
        f"/api/analysis/{analysis_id}/review",
        json={"status": "confirmed", "reviewer": "张三"},
    )
    assert review_repository.get(analysis_id).history

    assert client.delete(f"/api/analysis/{analysis_id}").status_code == 204
    # 分析已删除，确认留痕不能留成孤儿
    assert review_repository.get(analysis_id).history == []
