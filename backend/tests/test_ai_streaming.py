"""AI 流式输出：实时文本只用于展示，结论仍由完整文本经校验后得出。

关键约定（也是本文件要守住的）：
1. SSE 分片能拼回与一次性响应等价的消息，**工具调用参数是分片到达的**；
2. 流式失败不能让研判失败——退回一次性请求照样出结论；
3. 流式与结论解耦：最终结论来自完整文本校验结果，不是流里的片段。
"""

from __future__ import annotations

import json

import pytest

from app.services import ai as ai_service


class _FakeStream:
    def __init__(self, lines: list[str]) -> None:
        self._lines = [line.encode("utf-8") for line in lines]

    def __iter__(self):
        return iter(self._lines)

    def read(self) -> bytes:
        return b"".join(self._lines)

    def __enter__(self) -> "_FakeStream":
        return self

    def __exit__(self, *_args) -> bool:
        return False


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}"


def test_stream_aggregates_text_and_rebuilds_fragmented_tool_calls(monkeypatch):
    """工具调用参数在流里是分片到达的，必须按 index 累积后拼成完整参数。"""

    lines = [
        _sse({"choices": [{"delta": {"content": "你"}}]}),
        _sse({"choices": [{"delta": {"content": "好"}}]}),
        _sse(
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_1",
                                    "function": {
                                        "name": "query_records",
                                        "arguments": '{"field"',
                                    },
                                }
                            ]
                        }
                    }
                ]
            }
        ),
        _sse(
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {"arguments": ': "status"}'},
                                }
                            ]
                        }
                    }
                ]
            }
        ),
        "data: [DONE]",
    ]
    monkeypatch.setattr(ai_service, "_open", lambda *_args, **_kwargs: _FakeStream(lines))

    chunks: list[str] = []
    body = ai_service._stream_message(
        "https://example.invalid", {"stream": True}, {}, chunks.append
    )
    message = ai_service._first_message(body)
    assert message["content"] == "你好"
    assert chunks == ["你", "好"]
    assert message["tool_calls"][0]["function"]["name"] == "query_records"
    assert message["tool_calls"][0]["function"]["arguments"] == '{"field": "status"}'


def test_stream_ignores_keepalive_and_broken_chunks(monkeypatch):
    lines = [
        ": keep-alive",
        "",
        "data: {not json}",
        _sse({"choices": [{"delta": {"content": "ok"}}]}),
        "data: [DONE]",
    ]
    monkeypatch.setattr(ai_service, "_open", lambda *_args, **_kwargs: _FakeStream(lines))
    body = ai_service._stream_message("https://example.invalid", {}, {}, lambda _c: None)
    assert ai_service._message_content(ai_service._first_message(body)) == "ok"


def test_stream_failure_falls_back_to_single_request(monkeypatch):
    """看不到实时输出可以接受，研判本身不能失败。"""

    def broken_open(*_args, **_kwargs):
        raise ai_service.AiRequestError("network", "断线", retryable=True)

    monkeypatch.setattr(ai_service, "_open", broken_open)
    monkeypatch.setattr(
        ai_service,
        "_request_json",
        lambda url, payload, headers: {"choices": [{"message": {"content": "兜底结论"}}]},
    )
    provider = ai_service.OpenAICompatibleProvider("https://x.invalid/v1", "m", "k")
    body = provider._post([{"role": "user", "content": "hi"}], on_delta=lambda _c: None)
    assert ai_service._message_content(ai_service._first_message(body)) == "兜底结论"


def test_deltas_are_forwarded_but_verdict_comes_from_validated_json(monkeypatch):
    """流式只影响展示：结论取完整文本的校验结果，不取流里的片段。"""

    from app.services.analyzer import analyze_log
    from app.services.parser import parse_log

    log = (
        '203.0.113.7 - - [21/Sep/2026:09:10:00 +0800] '
        '"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
    )
    result = analyze_log("a.log", log)
    records = [
        {**record, "log_type": "nginx_apache", "record_id": f"record-{i}"}
        for i, record in enumerate(parse_log(log).records, 1)
    ]

    final = json.dumps(
        {
            "risk_level": "medium",
            "confidence": 0.7,
            "summary": "存在敏感路径探测行为。",
            "behaviors": [],
        },
        ensure_ascii=False,
    )

    class FakeProvider:
        supports_tools = False

        def complete(self, system_prompt, context, on_delta=None):
            if on_delta:
                on_delta("正在")
                on_delta("分析")
            return final

    monkeypatch.setattr(ai_service, "_create_provider", lambda: FakeProvider())
    monkeypatch.setattr(ai_service, "_run_auto_tools", lambda result, records: ({}, []))

    seen: list[str] = []
    judgement = ai_service.request_ai_judgement(
        result, records, delta_cb=seen.append
    )
    assert seen == ["正在", "分析"]
    assert judgement["risk_level"] == "medium"
    assert judgement["conclusion"] == "存在敏感路径探测行为。"


def test_partial_answer_alone_does_not_become_the_verdict(monkeypatch):
    """若流里的片段不构成完整 JSON，仍按「格式错误」走重试，而不是把片段当结论。"""

    from app.services.analyzer import analyze_log
    from app.services.parser import parse_log

    log = (
        '203.0.113.7 - - [21/Sep/2026:09:10:00 +0800] '
        '"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
    )
    result = analyze_log("a.log", log)
    records = [
        {**record, "log_type": "nginx_apache", "record_id": f"record-{i}"}
        for i, record in enumerate(parse_log(log).records, 1)
    ]

    replies = iter(
        [
            '{"risk_level": "medium", "summary": "未写完',  # 流式中断留下的残片
            '{"risk_level": "medium", "confidence": 0.6, "summary": "完整结论", "behaviors": []}',
        ]
    )

    class FakeProvider:
        supports_tools = False

        def complete(self, system_prompt, context, on_delta=None):
            if on_delta:
                on_delta("片段")
            return next(replies)

    monkeypatch.setattr(ai_service, "_create_provider", lambda: FakeProvider())
    monkeypatch.setattr(ai_service, "_run_auto_tools", lambda result, records: ({}, []))

    judgement = ai_service.request_ai_judgement(result, records, delta_cb=lambda _c: None)
    assert judgement["conclusion"] == "完整结论"
    assert judgement["confidence"] == pytest.approx(0.6)
