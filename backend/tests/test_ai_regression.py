"""AI 研判回归集：用固定模型输出检查结构、证据溯源和用量记录。

这里不访问真实模型，避免测试不稳定和产生费用；模型调用由固定 JSON
替身模拟，仍走真实的上下文构造、响应归一化和证据校验流程。
"""

from __future__ import annotations

import json

import pytest

from app.services import ai as ai_service
from app.services.analyzer import analyze_log
from app.services.parser import parse_log


CASES = [
    pytest.param(
        "正常行为",
        (
            '203.0.113.10 - - [29/Sep/2026:09:10:00 +0800] '
            '"GET /health HTTP/1.1" 200 12 "-" "Mozilla/5.0"'
        ),
        "info",
        0.25,
        False,
        id="normal",
    ),
    pytest.param(
        "明显异常",
        (
            '203.0.113.11 - - [29/Sep/2026:09:10:00 +0800] '
            '"GET /.env HTTP/1.1" 403 12 "-" "curl/8.0"'
        ),
        "medium",
        0.72,
        True,
        id="obvious-anomaly",
    ),
    pytest.param(
        "证据不足",
        "not a recognized log record",
        "info",
        0.20,
        False,
        id="insufficient-evidence",
    ),
    pytest.param(
        "多事件关联",
        "\n".join(
            [
                "Sep 29 09:00:00 host sshd[1]: Failed password for root from 203.0.113.12 port 40001 ssh2",
                "Sep 29 09:01:00 host sshd[2]: Failed password for admin from 203.0.113.12 port 40002 ssh2",
                "Sep 29 09:02:00 host sshd[3]: Accepted password for root from 203.0.113.12 port 40003 ssh2",
            ]
        ),
        "high",
        0.88,
        True,
        id="correlated-events",
    ),
    pytest.param(
        "误报场景",
        "\n".join(
            [
                '203.0.113.13 - admin [29/Sep/2026:09:10:00 +0800] "GET /health HTTP/1.1" 200 12 "-" "monitor"',
                '203.0.113.13 - admin [29/Sep/2026:09:11:00 +0800] "GET /health HTTP/1.1" 200 12 "-" "monitor"',
            ]
        ),
        "low",
        0.40,
        False,
        id="false-positive",
    ),
]


def _records(filename: str, log: str) -> list[dict[str, str | None]]:
    parsed = parse_log(log)
    return [
        {
            **record,
            "log_type": parsed.log_type,
            "record_id": f"record-{index}",
            "evidence_id": f"evidence-record-{index}",
        }
        for index, record in enumerate(parsed.records, 1)
    ]


@pytest.mark.parametrize(
    ("name", "log", "risk_level", "confidence", "has_behavior"),
    CASES,
)
def test_ai_regression_cases(
    monkeypatch,
    name: str,
    log: str,
    risk_level: str,
    confidence: float,
    has_behavior: bool,
):
    result = analyze_log(f"{name}.log", log)
    records = _records(f"{name}.log", log)
    evidence_ids = {
        item.id
        for event in result.events
        for item in event.evidence_items
    }
    evidence_ids.update(
        record["evidence_id"] for record in records if record.get("evidence_id")
    )
    referenced_id = next(iter(evidence_ids), "")
    behavior = (
        {
            "type": "review_candidate",
            "name": name,
            "confidence": confidence,
            "evidence": ["日志中存在对应记录"],
            "evidence_ids": [referenced_id] if referenced_id else [],
            "analysis": "依据本次日志中的结构化事件和原始证据进行判断。",
        }
        if has_behavior
        else None
    )
    answer = {
        "risk_level": risk_level,
        "confidence": confidence,
        "summary": f"{name}回归结论",
        "behaviors": [behavior] if behavior else [],
        "recommendations": ["结合业务背景继续核实。"],
    }

    class FakeProvider:
        supports_tools = False
        last_usage = {
            "rounds": 1,
            "prompt_tokens": 120,
            "completion_tokens": 48,
        }

        def complete(self, system_prompt, context, on_delta=None):
            return json.dumps(answer, ensure_ascii=False)

    monkeypatch.setattr(ai_service, "_create_provider", lambda: FakeProvider())
    monkeypatch.setattr(
        ai_service, "_run_auto_tools", lambda _result, _records: ({}, [])
    )

    raw = json.dumps(answer, ensure_ascii=False)
    parsed_json = json.loads(raw)
    assert {"risk_level", "confidence", "summary", "behaviors"} <= parsed_json.keys()

    judgement = ai_service.request_ai_judgement(result, records)
    assert judgement["risk_level"] == risk_level
    assert 0.0 <= judgement["confidence"] <= 1.0
    assert judgement["confidence"] == pytest.approx(confidence)
    assert bool(judgement["behaviors"]) is has_behavior
    assert all(
        evidence_id in evidence_ids
        for item in judgement["behaviors"]
        for evidence_id in item.evidence_ids
    )
    assert judgement["unsupported_claims"] == []

    usage = next(
        item["usage"]
        for item in judgement["tool_trace"]
        if item["tool"] == "usage"
    )
    assert usage["prompt_tokens"] > 0
    assert usage["completion_tokens"] > 0
    assert usage["rounds"] == 1

