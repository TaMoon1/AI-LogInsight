"""AI 研判的时长与深度上限。

产品取向：**结论准确优先于返回速度**，因此上限必须给足余量且可调；
同时非法配置不能让上限退化成「立即中断」，超时也要能和「服务不可用」区分开。
"""

from __future__ import annotations

import json
import time

import io as _io

import pytest

from app.services import ai as ai_service


def _parse_for_test(filename: str, lines: list[str]):
    """把文本日志解析成带 record_id 的记录列表——与生产路径同一口径。

    `build_ai_context` 需要真实的 records 才能做「事件证据去重」和「未覆盖记录采样」，
    直接传 `[]` 会让样本恒为空（那是测试构造问题，不是产品行为）。
    """

    from app.services.analyzer import assign_record_ids, collect_records
    from app.services.parser import parse_log

    parsed = parse_log("\n".join(lines))
    return assign_record_ids(collect_records([filename], [parsed]))


def test_default_limits_leave_room_for_accuracy():
    assert ai_service.DEFAULT_TIMEOUT_SECONDS >= 120
    assert ai_service.DEFAULT_TOOL_ROUNDS >= 3
    assert ai_service.DEFAULT_OUTPUT_TOKENS >= 4096


def test_limits_are_configurable_through_env(monkeypatch):
    monkeypatch.setenv("AI_MAX_TOOL_ROUNDS", "9")
    assert ai_service._int_setting("AI_MAX_TOOL_ROUNDS", 6) == 9
    monkeypatch.setenv("AI_MAX_OUTPUT_TOKENS", "8192")
    assert ai_service._int_setting("AI_MAX_OUTPUT_TOKENS", 4096) == 8192


@pytest.mark.parametrize("value", ["0", "-1", "abc", ""])
def test_invalid_limit_values_fall_back_to_default(monkeypatch, value):
    """0 / 负数 / 非数字都不能让上限变成 0 轮或 0 秒。"""

    monkeypatch.setenv("AI_MAX_TOOL_ROUNDS", value)
    assert ai_service._int_setting("AI_MAX_TOOL_ROUNDS", 6) == 6


def test_timeout_is_reported_differently_from_service_unavailable(monkeypatch):
    def raise_timeout(*_args, **_kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(ai_service.request, "urlopen", raise_timeout)
    with pytest.raises(RuntimeError) as excinfo:
        ai_service._request_json("https://example.invalid/v1/chat/completions", {}, {})
    message = str(excinfo.value)
    assert "超时" in message
    assert "AI_TIMEOUT_SECONDS" in message


def test_url_error_wrapping_timeout_is_also_reported_as_timeout(monkeypatch):
    def raise_url_error(*_args, **_kwargs):
        raise ai_service.error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr(ai_service.request, "urlopen", raise_url_error)
    with pytest.raises(RuntimeError) as excinfo:
        ai_service._request_json("https://example.invalid/v1/chat/completions", {}, {})
    assert "超时" in str(excinfo.value)


def test_connection_error_still_reports_service_unavailable(monkeypatch):
    def raise_url_error(*_args, **_kwargs):
        raise ai_service.error.URLError("connection refused")

    monkeypatch.setattr(ai_service.request, "urlopen", raise_url_error)
    monkeypatch.setattr(ai_service, "RETRY_BACKOFF_SECONDS", 0)
    with pytest.raises(RuntimeError) as excinfo:
        ai_service._request_json("https://example.invalid/v1/chat/completions", {}, {})
    message = str(excinfo.value)
    # 文案现在带错误分类与重试结果，用户据此知道该等还是该改配置
    assert "AI 服务暂时不可用" in message
    assert "网络不可达" in message


def _seed_task(task_id: str, status: str, age_seconds: float) -> dict:
    return {
        "task_id": task_id,
        "analysis_id": "analysis-x",
        "status": status,
        "stage": "completed",
        "progress": 100,
        "error": None,
        "result": None,
        "updated_at": time.time() - age_seconds,
    }


@pytest.fixture()
def ai_tasks():
    """隔离 AI_TASKS，避免用例之间以及和真实请求互相影响。"""

    from app import main as main_module

    saved = dict(main_module.AI_TASKS)
    main_module.AI_TASKS.clear()
    yield main_module
    main_module.AI_TASKS.clear()
    main_module.AI_TASKS.update(saved)


def test_finished_ai_tasks_are_pruned_after_ttl(ai_tasks):
    """已结束的任务过了保留期就要清理，否则 AI_TASKS 会随分析次数一直涨。"""

    module = ai_tasks
    module.AI_TASKS["old"] = _seed_task("old", "completed", module.AI_TASK_TTL_SECONDS + 60)
    module.AI_TASKS["fresh"] = _seed_task("fresh", "completed", 5)
    with module.AI_TASK_LOCK:
        module._prune_ai_tasks()
    assert set(module.AI_TASKS) == {"fresh"}


def test_running_ai_task_is_never_pruned(ai_tasks):
    """运行中的任务不能被清掉，否则前端轮询会突然拿到 404。"""

    module = ai_tasks
    module.AI_TASKS["running"] = _seed_task("running", "running", module.AI_TASK_TTL_SECONDS * 10)
    with module.AI_TASK_LOCK:
        module._prune_ai_tasks()
    assert "running" in module.AI_TASKS


def test_ai_tasks_are_capped_by_dropping_oldest_finished(ai_tasks):
    module = ai_tasks
    limit = module.AI_TASK_MAX_ENTRIES
    for index in range(limit + 4):
        task_id = f"t{index:04d}"
        module.AI_TASKS[task_id] = _seed_task(task_id, "completed", limit - index)
    module.AI_TASKS["running"] = _seed_task("running", "running", 0)
    with module.AI_TASK_LOCK:
        module._prune_ai_tasks()
    assert len(module.AI_TASKS) == limit
    assert "running" in module.AI_TASKS
    assert "t0000" not in module.AI_TASKS  # 最旧的已结束任务先被清掉


def test_stratified_sample_covers_multiple_entities_and_statuses():
    """样本必须覆盖多种形态。

    直接取前 N 条会让模型只看到同一来源、同一类结果——那样的「泛化」是偏的，
    而且模型还以为自己看的就是全部。
    """

    from app.services.ai import _stratified_sample

    records = [
        {
            "record_id": f"r{i}",
            "source_ip": f"10.0.0.{i % 40}",
            "status": "404" if i % 2 else "200",
            "url": f"/p{i % 25}",
        }
        for i in range(5000)
    ]
    sample = _stratified_sample(records, 200)
    assert len(sample) == 200
    assert len({record["source_ip"] for record in sample}) == 40
    assert {record["status"] for record in sample} == {"200", "404"}
    assert len({record["url"] for record in sample}) == 25


def test_information_gain_sample_prefers_new_structured_values_and_is_stable():
    from app.services.ai import _information_gain_sample

    records = [
        {
            "record_id": f"record-{index}",
            "source_ip": "10.0.0.1" if index < 3 else f"10.0.0.{index}",
            "username": "admin" if index < 3 else f"user-{index}",
            "status": "401" if index < 3 else "200",
            "url": "/login" if index < 3 else f"/resource/{index}",
        }
        for index in range(8)
    ]

    first = _information_gain_sample(records, 4)
    second = _information_gain_sample(records, 4)

    assert [record["record_id"] for record in first] == [
        record["record_id"] for record in second
    ]
    assert len({record["source_ip"] for record in first}) >= 3
    assert len({record["url"] for record in first}) == 4


def test_sample_limit_scales_with_log_size():
    from app.services.ai import SAMPLE_LIMIT_DEFAULT, SAMPLE_LIMIT_LARGE, _sample_limit

    assert _sample_limit(100) == SAMPLE_LIMIT_DEFAULT
    assert _sample_limit(100000) == SAMPLE_LIMIT_LARGE


def test_event_context_sends_each_raw_evidence_once():
    """`evidence` 与 `evidence_items[].raw` 是同一批原文，不能把同一段文本发两遍。

    实测 80 个事件里 306 条 evidence 有 293 条与 items 的 raw 逐字相同（约 100 KB 白花）。
    去重后必须满足：① 每个事件的 evidence 与 items 的 raw 无交集；② 原来出现过的原文
    一条都不能丢（信息量为零损失的瘦身，不是删证据）。
    """

    from app.services.ai import (
        EVENT_EVIDENCE_ITEM_LIMIT,
        EVENT_EVIDENCE_LIMIT,
        _event_context,
        sanitize_text,
    )
    from app.services.events import build_event

    records = [
        {
            "record_id": f"record-{index}",
            "timestamp": f"2026-09-22 09:{index:02d}:00",
            "source_ip": "10.0.0.8",
            "raw": f"原始日志行 {index}",
        }
        for index in range(12)
    ]
    event = build_event(
        "ssh.bruteforce.success",
        "失败认证后成功登录",
        "high",
        "摘要",
        source_ip="10.0.0.8",
        records=records,
        rule_id="ssh.bruteforce.success",
    )
    # 构造时 evidence 就已经限条（默认前 10 条原文），与 evidence_items 取的是同一批 record
    assert len(event.evidence) == 10

    # 深度由调用方按价值评分算好后传入（P4 ①）；这里给满额，验证去重本身
    context = _event_context(event, EVENT_EVIDENCE_ITEM_LIMIT)
    item_raws = {item["raw"] for item in context["evidence_items"]}
    assert len(context["evidence_items"]) == EVENT_EVIDENCE_ITEM_LIMIT
    # ① 两个列表不能有交集（同一段原文只发一次）
    assert item_raws and not (set(context["evidence"]) & item_raws)
    # ② 合起来仍是「上限内的全部原文」，一条都没被删掉
    assert set(context["evidence"]) | item_raws == {
        sanitize_text(item) for item in event.evidence[:EVENT_EVIDENCE_LIMIT]
    }
    assert len(context["evidence"]) == EVENT_EVIDENCE_LIMIT - EVENT_EVIDENCE_ITEM_LIMIT


def test_ai_timeout_and_rounds_scale_with_log_size(monkeypatch):
    """默认放宽；超大日志再放宽；无事件时收到 1 轮；显式配置优先。"""

    import app.services.ai as ai

    monkeypatch.delenv("AI_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("AI_MAX_TOOL_ROUNDS", raising=False)

    # 有事件：按默认轮次
    monkeypatch.setattr(ai, "_ACTIVE_RECORD_COUNT", 100)
    monkeypatch.setattr(ai, "_ACTIVE_EVENT_COUNT", 3)
    assert ai._effective_timeout() == ai.DEFAULT_TIMEOUT_SECONDS
    assert ai._effective_tool_rounds() == ai.DEFAULT_TOOL_ROUNDS
    # 默认值兼顾研判质量与 token 成本；需要更深轮次时由环境变量显式放宽。
    assert ai.DEFAULT_TIMEOUT_SECONDS >= 300
    assert 3 <= ai.DEFAULT_TOOL_ROUNDS <= 6

    # 超大日志：放宽
    monkeypatch.setattr(ai, "_ACTIVE_RECORD_COUNT", 50000)
    monkeypatch.setattr(ai, "_ACTIVE_EVENT_COUNT", 20)
    assert ai._effective_timeout() == ai.DEFAULT_TIMEOUT_SECONDS * 2
    assert ai._effective_tool_rounds() == ai.DEFAULT_TOOL_ROUNDS * 2


def test_clean_log_gets_a_single_tool_round(monkeypatch):
    """没有命中任何事件的日志不需要深挖：轮次收到 1，避免整份上下文重复发送。"""

    import app.services.ai as ai

    monkeypatch.delenv("AI_MAX_TOOL_ROUNDS", raising=False)
    monkeypatch.setattr(ai, "_ACTIVE_RECORD_COUNT", 50000)
    monkeypatch.setattr(ai, "_ACTIVE_EVENT_COUNT", 0)
    assert ai._effective_tool_rounds() == ai.CLEAN_LOG_TOOL_ROUNDS == 1
    # 显式配置仍然优先，便于需要时人工放宽
    monkeypatch.setenv("AI_MAX_TOOL_ROUNDS", "5")
    assert ai._effective_tool_rounds() == 5


def test_query_records_tool_filters_by_field_and_content():
    """query_records 让模型能主动查看样本之外的部分。"""

    from app.services.agent_tools import execute_tool
    from app.services.analyzer import analyze_log
    from app.services.parser import parse_log

    log = "\n".join(
        [
            '203.0.113.7 - - [21/Sep/2026:09:10:00 +0800] "GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"',
            '203.0.113.7 - - [21/Sep/2026:09:11:00 +0800] "GET /index.html HTTP/1.1" 200 1 "-" "Mozilla"',
            '198.51.100.9 - - [21/Sep/2026:09:12:00 +0800] "GET /wp-admin/ HTTP/1.1" 403 1 "-" "curl/8.0"',
        ]
    )
    result = analyze_log("a.log", log)
    parsed = parse_log(log)
    records = [
        {**record, "log_type": parsed.log_type, "record_id": f"record-{index}"}
        for index, record in enumerate(parsed.records, 1)
    ]

    assert execute_tool(
        "query_records", {"field": "source_ip", "equals": "203.0.113.7"}, result, records
    )["total_matched"] == 2
    assert execute_tool(
        "query_records", {"field": "status", "equals": "403"}, result, records
    )["total_matched"] == 2
    assert execute_tool(
        "query_records", {"contains": "wp-admin"}, result, records
    )["total_matched"] == 1
    assert execute_tool(
        "query_records", {"field": "source_ip", "equals": "10.9.9.9"}, result, records
    )["total_matched"] == 0


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_args) -> bool:
        return False


class _BytesReader(_io.BytesIO):
    """给 HTTPError 当 fp 用：让 _server_message 能读到服务端返回的错误体。"""



def _http_error(code: int, headers: dict[str, str] | None = None):
    return ai_service.error.HTTPError(
        "https://example.invalid/v1/chat/completions", code, "err", headers or {}, None
    )


def _ok_body() -> bytes:
    return '{"choices":[{"message":{"content":"ok"}}]}'.encode("utf-8")


def test_rate_limit_is_retried_with_server_hint(monkeypatch):
    """429 只是「现在别发」，退避后重试一次就能成功；服务端给了 Retry-After 要照办。"""

    calls: list[int] = []

    def fake_urlopen(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise _http_error(429, {"Retry-After": "0"})
        return _FakeResponse(_ok_body())

    monkeypatch.setattr(ai_service.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(ai_service, "RETRY_BACKOFF_SECONDS", 0)
    body = ai_service._request_json("https://example.invalid/v1/chat/completions", {}, {})
    assert body["choices"][0]["message"]["content"] == "ok"
    assert len(calls) == 2


def test_auth_error_is_not_retried(monkeypatch):
    """鉴权错误重试没有意义，要立刻停下并告诉用户去查配置。"""

    calls: list[int] = []

    def fake_urlopen(*_args, **_kwargs):
        calls.append(1)
        raise _http_error(401)

    monkeypatch.setattr(ai_service.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(ai_service, "RETRY_BACKOFF_SECONDS", 0)
    with pytest.raises(RuntimeError) as excinfo:
        ai_service._request_json("https://example.invalid/v1/chat/completions", {}, {})
    message = str(excinfo.value)
    assert len(calls) == 1
    assert "鉴权失败" in message
    # 文案要给出可行动的下一步，而不是笼统说「重试无效」
    assert "请检查模型、密钥与接口地址配置" in message


def test_server_error_exhausts_retries_and_says_so(monkeypatch):
    calls: list[int] = []

    def fake_urlopen(*_args, **_kwargs):
        calls.append(1)
        raise _http_error(503)

    monkeypatch.setattr(ai_service.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(ai_service, "RETRY_BACKOFF_SECONDS", 0)
    with pytest.raises(RuntimeError) as excinfo:
        ai_service._request_json("https://example.invalid/v1/chat/completions", {}, {})
    message = str(excinfo.value)
    assert len(calls) == ai_service.DEFAULT_MAX_RETRIES + 1
    assert "已自动重试 2 次" in message


def test_timeout_is_not_retried(monkeypatch):
    """单次上限已是数百秒，自动重试会让等待成倍增长，因此交给用户决定。"""

    calls: list[int] = []

    def fake_urlopen(*_args, **_kwargs):
        calls.append(1)
        raise TimeoutError("timed out")

    monkeypatch.setattr(ai_service.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(ai_service, "RETRY_BACKOFF_SECONDS", 0)
    with pytest.raises(RuntimeError) as excinfo:
        ai_service._request_json("https://example.invalid/v1/chat/completions", {}, {})
    message = str(excinfo.value)
    assert len(calls) == 1
    assert "超时" in message
    assert "AI_TIMEOUT_SECONDS" in message


def test_malformed_body_is_retried(monkeypatch):
    """网关偶尔会返回 HTML 错误页，这类响应体不是合法 JSON，值得重试一次。"""

    calls: list[int] = []

    def fake_urlopen(*_args, **_kwargs):
        calls.append(1)
        if len(calls) == 1:
            return _FakeResponse(b"<html>502 Bad Gateway</html>")
        return _FakeResponse(_ok_body())

    monkeypatch.setattr(ai_service.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(ai_service, "RETRY_BACKOFF_SECONDS", 0)
    body = ai_service._request_json("https://example.invalid/v1/chat/completions", {}, {})
    assert len(calls) == 2
    assert "choices" in body


def _fake_judgement_inputs():
    from app.services.analyzer import analyze_log
    from app.services.parser import parse_log

    log = (
        '203.0.113.7 - - [21/Sep/2026:09:10:00 +0800] '
        '"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
    )
    result = analyze_log("a.log", log)
    records = [
        {
            **record,
            "log_type": parsed_type,
            "record_id": f"record-{index}",
            "evidence_id": f"evidence-record-{index}",
        }
        for index, record in enumerate(parse_log(log).records, 1)
        for parsed_type in ["nginx_apache"]
    ]
    return result, records


def _patch_provider(monkeypatch, replies: list[str]) -> list[str]:
    prompts: list[str] = []
    iterator = iter(replies)

    class FakeProvider:
        supports_tools = False

        def complete(self, system_prompt, context, on_delta=None):
            prompts.append(system_prompt)
            return next(iterator)

    monkeypatch.setattr(ai_service, "_create_provider", lambda: FakeProvider())
    monkeypatch.setattr(
        ai_service, "_run_auto_tools", lambda result, records: ({}, [])
    )
    return prompts


def test_unparsable_answer_is_retried_once_with_format_reminder(monkeypatch):
    """模型没按格式返回时，复用同一份上下文再要一次并重申格式，而不是直接失败。"""

    result, records = _fake_judgement_inputs()
    prompts = _patch_provider(
        monkeypatch,
        [
            "这个问题我需要再看看，暂时给不出结构化结论。",
            '{"risk_level": "low", "confidence": 0.4, "summary": "未见明确攻击特征", "behaviors": []}',
        ],
    )
    judgement = ai_service.request_ai_judgement(result, records)
    assert len(prompts) == 2
    assert "无法解析为 JSON" in prompts[1]
    assert judgement["risk_level"] == "low"


def test_unparsable_answer_reports_a_readable_error_after_one_retry(monkeypatch):
    """两次都不成 JSON 时，给用户的必须是可行动的说明，而不是 json 的原始报错。"""

    result, records = _fake_judgement_inputs()
    _patch_provider(monkeypatch, ["不是 JSON", "还是不是 JSON"])
    with pytest.raises(RuntimeError) as excinfo:
        ai_service.request_ai_judgement(result, records)
    message = str(excinfo.value)
    assert "未按约定返回 JSON" in message
    assert "Expecting value" not in message


def test_ai_judgement_runs_over_real_events_and_real_tool_layer(monkeypatch):
    """回归：上下文的 events/evidence_items 是字典，工具层与溯源走的是对象属性。

    曾经在构造 AI 上下文时把 Pydantic 的 EvidenceItem 当 dict 调 `.get()`，
    研判在请求发出之前就 AttributeError 中断。这里刻意**不** stub 工具层，
    让真实事件、真实工具输出与证据溯源都跑一遍。
    """

    result, records = _fake_judgement_inputs()
    assert result.events, "用例本身必须产出事件，否则覆盖不到事件/证据路径"
    evidence_id = result.events[0].evidence_items[0].id
    answer = json.dumps(
        {
            "risk_level": "medium",
            "confidence": 0.6,
            "summary": "存在敏感路径探测行为。",
            "behaviors": [
                {
                    "type": "sensitive_path_access",
                    "name": "敏感路径访问",
                    "confidence": 0.6,
                    "evidence": ["请求 /.env 返回 403"],
                    "evidence_ids": [evidence_id],
                    "analysis": "存在对敏感文件的探测请求。",
                }
            ],
            "recommendations": ["核实该来源是否为已知扫描器。"],
        },
        ensure_ascii=False,
    )

    class FakeProvider:
        supports_tools = False

        def complete(self, system_prompt, context, on_delta=None):
            # 上下文里的证据必须是字典；工具层与溯源拿到的却是对象，两者不能混。
            assert isinstance(context["events"][0]["evidence_items"][0], dict)
            return answer

    monkeypatch.setattr(ai_service, "_create_provider", lambda: FakeProvider())

    judgement = ai_service.request_ai_judgement(result, records)
    assert judgement["risk_level"] == "medium"
    assert judgement["behaviors"][0].evidence_ids == [evidence_id]
    assert judgement["tool_trace"], "真实只读工具应留下调用轨迹"
    assert judgement["unsupported_claims"] == []


def test_oversized_request_is_reported_as_context_limit_not_config_error(monkeypatch):
    """400 不都是配置错：请求体过大时服务端也用 400，提示必须指向「减少日志量」。"""

    body = json.dumps(
        {
            "error": {
                "message": (
                    "This model's maximum context length is 1048576 tokens. "
                    "However, you requested 7981061 tokens"
                )
            }
        }
    ).encode("utf-8")

    def fake_urlopen(*_args, **_kwargs):
        raise ai_service.error.HTTPError(
            "https://example.invalid/v1/chat/completions",
            400,
            "Bad Request",
            {},
            _BytesReader(body),
        )

    monkeypatch.setattr(ai_service.request, "urlopen", fake_urlopen)
    with pytest.raises(RuntimeError) as excinfo:
        ai_service._request_json("https://example.invalid/v1/chat/completions", {}, {})
    message = str(excinfo.value)
    assert "输入上下文超出模型上限" in message
    assert "maximum context length" in message
    assert "减少一次性分析的日志量" in message
    assert "密钥" not in message


def test_plain_bad_request_keeps_the_config_advice(monkeypatch):
    body = json.dumps({"error": {"message": "model not found"}}).encode("utf-8")

    def fake_urlopen(*_args, **_kwargs):
        raise ai_service.error.HTTPError(
            "https://example.invalid/v1/chat/completions",
            400,
            "Bad Request",
            {},
            _BytesReader(body),
        )

    monkeypatch.setattr(ai_service.request, "urlopen", fake_urlopen)
    with pytest.raises(RuntimeError) as excinfo:
        ai_service._request_json("https://example.invalid/v1/chat/completions", {}, {})
    message = str(excinfo.value)
    assert "model not found" in message
    assert "请检查模型名与请求参数" in message


def test_event_context_is_capped_and_notes_the_total(monkeypatch):
    """事件必须分层抽样并写明总数：全量塞进上下文曾导致 400（798 万 tokens）。"""

    from app.services.ai import EVENT_SAMPLE_LIMIT, build_ai_context
    from app.services.analyzer import analyze_log

    # 用 200 个不同来源，让规则按来源聚合后产生 > EVENT_SAMPLE_LIMIT 个事件
    lines = [
        f'198.51.100.{index % 200 + 1} - - [21/Sep/2026:09:{index % 60:02d}:00 +0800] '
        f'"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
        for index in range(400)
    ]
    result = analyze_log("a.log", "\n".join(lines))
    assert len(result.events) > EVENT_SAMPLE_LIMIT

    context = build_ai_context(result, [])
    assert len(context["events"]) == EVENT_SAMPLE_LIMIT
    assert str(len(result.events)) in context["events_note"]
    assert "query_events" in context["events_note"]
    # 抽样要覆盖到不同来源，而不是只取前 80 条
    assert len({event["source_ip"] for event in context["events"]}) > 1


def test_ai_context_budget_reduces_samples_before_request(monkeypatch):
    from app.services.ai import build_ai_context
    from app.services.analyzer import analyze_log

    lines = [
        f'198.51.100.{index % 20 + 1} - - [21/Sep/2026:09:{index % 60:02d}:00 +0800] '
        f'"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
        for index in range(80)
    ]
    result = analyze_log("a.log", "\n".join(lines))
    monkeypatch.setenv("AI_CONTEXT_MAX_BYTES", "12000")

    context = build_ai_context(result, [])

    assert "context_budget_note" in context
    assert len(context.get("events", [])) < 80
    assert len(json.dumps(context, ensure_ascii=False).encode("utf-8")) <= 12000


def test_ai_context_budget_fails_when_even_minimum_context_cannot_fit(monkeypatch):
    from app.services.ai import build_ai_context
    from app.services.analyzer import analyze_log

    result = analyze_log("a.log", "not a recognized log line")
    monkeypatch.setenv("AI_CONTEXT_MAX_BYTES", "100")

    with pytest.raises(RuntimeError, match="AI 上下文超过安全发送上限"):
        build_ai_context(result, [])


def test_auto_tool_results_do_not_duplicate_context_blocks():
    """自动预取的工具结果不能把上下文里已有的块再发一遍。

    实测：log_metadata / log_statistics / timeline / query_events 的返回与
    context 的 metadata / statistics / timeline / events 同源，重复发送等于
    每轮多付一份体积（域控场景约 14 KB/轮）。
    """

    from app.services.ai import _run_auto_tools
    from app.services.analyzer import analyze_log

    lines = [
        f'10.0.0.{index % 5 + 1} - - [21/Sep/2026:09:{index % 60:02d}:00 +0800] '
        f'"GET /admin HTTP/1.1" 404 1 "-" "curl/8.0"'
        for index in range(60)
    ]
    result = analyze_log("a.log", "\n".join(lines))
    outputs, trace = _run_auto_tools(result, [])

    # 工具仍然真实执行，轨迹完整（前端展示不受影响）
    assert [item["tool"] for item in trace] == [
        "log_metadata",
        "log_statistics",
        "query_events",
        "timeline",
    ]
    assert all(item["summary"] for item in trace)

    # 但回传给模型的内容被换成指针，不再重复装载原始数据
    for name, field in (
        ("log_metadata", "metadata"),
        ("log_statistics", "statistics"),
        ("query_events", "events"),
        ("timeline", "timeline"),
    ):
        payload = outputs[name]
        assert payload["data_in"] == field
        assert "note" in payload
        assert "entries" not in payload and "events" not in payload
        assert "top_source_ips" not in payload

    # 计数锚点保留：模型做数量表述仍以总数为准
    assert outputs["query_events"]["events_total_in_batch"] == len(result.events)


def test_tool_results_are_inside_the_context_budget(monkeypatch):
    """tool_results 必须在预算校验之前并入，否则等于绕过硬上限。"""

    from app.services import ai as ai_module
    from app.services.ai import build_ai_context
    from app.services.analyzer import analyze_log

    lines = [
        f'203.0.113.{index % 30 + 1} - - [21/Sep/2026:10:{index % 60:02d}:00 +0800] '
        f'"GET /.git/config HTTP/1.1" 403 1 "-" "sqlmap/1.7"'
        for index in range(120)
    ]
    result = analyze_log("a.log", "\n".join(lines))
    monkeypatch.setenv("AI_CONTEXT_MAX_BYTES", "30000")

    # 模拟 request_ai_judgement 的顺序：先建上下文、再挂工具、最后统一校验
    context = build_ai_context(result, [])
    outputs, _ = ai_module._run_auto_tools(result, [])
    context["tool_results"] = outputs
    context = ai_module._fit_context_budget(context)

    # 口径必须与预算函数一致（紧凑分隔符），否则量到的是空白的差异而不是载荷差异
    size = len(
        json.dumps(context, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    assert size <= 30000, f"含 tool_results 的上下文仍应受硬上限约束，实际 {size}"

    # 另有一层语义保证：预算收紧时仍严格受约束（不因挂载 tool_results 而越界）
    monkeypatch.setenv("AI_CONTEXT_MAX_BYTES", "8000")
    tight = build_ai_context(result, [])
    tight["tool_results"] = outputs
    tight = ai_module._fit_context_budget(tight)
    tight_size = len(
        json.dumps(tight, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    assert tight_size <= 8000, f"收紧预算后仍不得越界，实际 {tight_size}"


def test_history_context_is_replaced_by_placeholder_on_later_rounds():
    """多轮工具调用时，首轮那份大上下文从第二轮起换成摘要占位。"""

    from app.services.ai import _history_context_placeholder, _shrink_history_context

    big_context = {
        "metadata": {
            "log_type": "nginx_apache",
            "total_lines": 6591,
            "parsed_lines": 6591,
            "time_range": {"start": "2026-09-21 00:00:00", "end": "2026-09-21 23:59:59"},
        },
        "coverage": {"covered": 100, "uncovered": 50},
        "risk_level": "medium",
        "conclusion": "存在异常行为",
        "statistics": {"failed_login": 12},
        "events_note": "共命中 7 个事件",
        "events_total": 7,
        "records_sample_note": "共 6591 条记录",
        "events": [{"raw": "x" * 5000} for _ in range(50)],
        "records_sample": [{"raw": "y" * 2000} for _ in range(200)],
    }
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": json.dumps(big_context, ensure_ascii=False)},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "1"}]},
        {"role": "tool", "tool_call_id": "1", "content": '{"total": 7}'},
    ]
    before = len(messages[1]["content"])

    _shrink_history_context(messages, big_context)

    after = len(messages[1]["content"])
    assert after < before / 10, "历史上下文应被大幅压缩"
    # 对话结构不变：role 与位置保持原样，工具消息原样保留
    assert messages[1]["role"] == "user"
    assert messages[3]["content"] == '{"total": 7}'
    # 计数与结论锚点必须保留，避免模型退化成「只看样本」
    payload = json.loads(messages[1]["content"])
    assert payload["total_records"] == 6591
    assert payload["local_risk_level"] == "medium"
    assert payload["coverage"] == {"covered": 100, "uncovered": 50}
    assert payload["events_total"] == 7
    assert "query_records" in payload["query_hint"]

    # 幂等：再调一次结果不变（占位内容是纯 JSON 字符串，不会被二次转义）
    once = messages[1]["content"]
    _shrink_history_context(messages, big_context)
    assert messages[1]["content"] == once
    assert json.loads(once)["total_records"] == 6591


def test_small_context_is_left_alone_on_later_rounds():
    """小上下文重发成本本来就低，不做替换以免模型丢细节。"""

    from app.services.ai import _shrink_history_context

    messages = [{"role": "user", "content": '{"metadata": {}}'}]
    _shrink_history_context(messages, {"metadata": {}})
    assert messages[0]["content"] == '{"metadata": {}}'


def test_record_sample_drops_derived_fields_and_keeps_evidence():
    """记录样本走字段白名单：派生字段不进上下文，原始原文与判定字段必须保留。"""

    from app.services.sanitizer import slim_records

    records = [
        {
            "record_id": "record-1",
            "evidence_id": "evidence-record-1",
            "timestamp": "2026-09-21 09:00:00",
            "timestamp_iso": "2026-09-21T09:00:00+08:00",
            "source_ip": "203.0.113.5",
            "url": "/.env",
            "status": "403",
            "action": "GET",
            "user_agent": "curl/8.0",
            "raw": "203.0.113.5 - - GET /.env 403",
            "correlation_basis": "same_source_ip",
            "extra_parser_field": "keep-me",
        }
    ]

    slimmed = slim_records(records, "nginx_apache")[0]

    # 原始原文是关键证据，必须保留
    assert slimmed["raw"] == "203.0.113.5 - - GET /.env 403"
    assert slimmed["source_ip"] == "203.0.113.5"
    assert slimmed["status"] == "403"
    assert slimmed["record_id"] == "record-1"
    # 派生 / 无判定价值字段被剔除
    assert "timestamp_iso" not in slimmed
    assert "correlation_basis" not in slimmed
    # 白名单外的自定义字段不静默丢弃
    assert slimmed.get("extra_parser_field") == "keep-me"


def test_terminal_records_keep_process_and_command_fields():
    """终端类日志的进程 / 命令行字段不能被白名单裁掉，否则 Sysmon 证据就没了。"""

    from app.services.sanitizer import slim_records

    record = {
        "record_id": "record-9",
        "target_asset": "WIN-DC01",
        "process_image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "parent_image": "winword.exe",
        "query_name": "evil.example.com",
        "status": "1",
        "raw": "Sysmon EventID 1 cmd.exe /c whoami",
    }

    slimmed = slim_records([record], "windows_evtx")[0]

    for key in ("process_image", "command_line", "parent_image", "query_name", "raw"):
        assert key in slimmed, f"{key} 是终端研判的关键证据字段，不应被裁剪"


def test_clean_log_uses_a_light_context():
    """无事件且覆盖完整时走轻量上下文：样本配额更小，并明确告知「不等于正常」。"""

    from app.services.ai import (
        LIGHT_SAMPLE_LIMIT,
        SAMPLE_LIMIT_DEFAULT,
        _is_light_context,
        build_ai_context,
    )
    from app.services.analyzer import analyze_log

    # 正常访问日志：解析成功、不命中任何规则
    lines = [
        f'10.0.0.{index % 8 + 1} - - [21/Sep/2026:14:{index % 60:02d}:00 +0800] '
        f'"GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        for index in range(400)
    ]
    result = analyze_log("access.log", "\n".join(lines))
    assert not result.events, "构造用例应不命中任何规则"
    assert _is_light_context(result), "无事件且覆盖完整应判定为轻量模式"

    parsed = _parse_for_test("access.log", lines)
    context = build_ai_context(result, parsed)
    assert len(context["records_sample"]) <= LIGHT_SAMPLE_LIMIT
    assert LIGHT_SAMPLE_LIMIT < SAMPLE_LIMIT_DEFAULT
    note = context["records_sample_note"]
    assert "light_context=no_events_and_full_coverage" in note
    assert "不等于" in note, "必须说明「没命中」不等于「日志正常」"


def test_eventful_log_keeps_a_bounded_sample_quota():
    """命中事件时保留普通记录形态样本，但不重复发送大量事件证据。"""

    from app.services.ai import (
        EVENT_RECORD_SAMPLE_LIMIT,
        _is_light_context,
        build_ai_context,
    )
    from app.services.analyzer import analyze_log

    # 混合日志：一部分命中敏感路径（产生事件），另一部分是普通请求（不进事件证据）
    lines = [
        f'203.0.113.{index % 20 + 1} - - [21/Sep/2026:09:{index % 60:02d}:00 +0800] '
        f'"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
        for index in range(200)
    ] + [
        f'198.51.100.{index % 15 + 1} - - [21/Sep/2026:09:{index % 60:02d}:30 +0800] '
        f'"GET /assets/app.js HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        for index in range(300)
    ]
    result = analyze_log("a.log", "\n".join(lines))
    assert result.events, "构造用例应命中敏感路径规则"
    assert not _is_light_context(result)

    context = build_ai_context(result, _parse_for_test("a.log", lines))
    # 事件证据是主要研判材料；普通记录只保留有界的形态样本。
    assert context["records_sample"]
    assert len(context["records_sample"]) <= EVENT_RECORD_SAMPLE_LIMIT
    event_record_ids = {
        item.get("record_id")
        for event in context["events"]
        for item in event.get("evidence_items", [])
        if item.get("record_id")
    }
    sample_record_ids = {
        item.get("record_id")
        for item in context["records_sample"]
        if item.get("record_id")
    }
    assert event_record_ids.isdisjoint(sample_record_ids)
    assert f"limit_each={EVENT_RECORD_SAMPLE_LIMIT}" in context["records_sample_note"]
    assert "query_records" in context["records_sample_note"]


def test_record_samples_are_mutually_exclusive():
    """两块记录样本必须互斥，否则同一批原文会发两遍。

    实测重叠率曾达 96%~97%：规则覆盖少时，「从全体抽样」与「从未覆盖池抽样」
    几乎命中同一批记录，两块合计约 47% 的体积是纯重复。
    """

    from app.services.ai import build_ai_context
    from app.services.analyzer import analyze_log

    # 规则覆盖少（仅 2 条命中敏感路径），其余为普通请求 → 触发高重叠场景
    lines = [
        f'203.0.113.{index % 20 + 1} - - [21/Sep/2026:09:{index % 60:02d}:00 +0800] '
        f'"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
        for index in range(2)
    ] + [
        f'198.51.100.{index % 15 + 1} - - [21/Sep/2026:09:{index % 60:02d}:30 +0800] '
        f'"GET /assets/app-{index}.js HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        for index in range(300)
    ]
    result = analyze_log("a.log", "\n".join(lines))
    context = build_ai_context(result, _parse_for_test("a.log", lines))

    sampled = {r.get("record_id") for r in context["records_sample"]}
    uncovered = {r.get("record_id") for r in context["uncovered_records_sample"]}
    assert sampled & uncovered == set(), "两块样本不得包含同一条记录"
    # 两块都要有内容（去重不等于把其中一块清空）
    assert sampled
    assert uncovered
    # 口径说明要如实告知「互不重复」，否则模型会以为两块可以相加
    assert "互不重复" in context["records_sample_note"]


def test_record_sample_union_is_not_shrunk_by_dedup():
    """去重不能缩小「两块并集」的覆盖范围——这是质量底线。

    去重只该去掉重复字节，不该减少模型能看到的记录种类。
    """

    from app.services.ai import build_ai_context
    from app.services.analyzer import analyze_log

    lines = [
        f'198.51.100.{index % 15 + 1} - - [21/Sep/2026:09:{index % 60:02d}:30 +0800] '
        f'"GET /assets/app-{index}.js HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        for index in range(300)
    ]
    result = analyze_log("a.log", "\n".join(lines))
    context = build_ai_context(result, _parse_for_test("a.log", lines))

    union = {r.get("record_id") for r in context["records_sample"]}
    union |= {r.get("record_id") for r in context["uncovered_records_sample"]}
    # 无事件时全部记录都属于「未覆盖」，并集应达到采样配额（而非因去重而腰斩）
    assert len(union) > 50


def test_incomplete_coverage_never_uses_light_context():
    """覆盖不完整时不能省上下文：「没事件」可能只是没解析出来，这时更需要原始记录。"""

    from app.services.ai import build_ai_context
    from app.services.analyzer import analyze_log

    result = analyze_log("broken.log", "this line cannot be parsed at all")
    if result.events or not result.coverage.limitation:
        pytest.skip("该用例在当前解析器下未产生覆盖限制，跳过")

    context = build_ai_context(result, [])
    note = context["records_sample_note"]
    assert "精简样本" not in note, "覆盖不完整时不应走轻量模式"


def test_event_evidence_depth_scales_with_risk():
    """事件证据按风险分档：高风险给满，低风险只留定位线索。"""

    from app.services.ai import EVENT_EVIDENCE_ITEM_LIMIT, _event_evidence_depth

    assert _event_evidence_depth("critical") == EVENT_EVIDENCE_ITEM_LIMIT
    assert _event_evidence_depth("high") == EVENT_EVIDENCE_ITEM_LIMIT
    assert _event_evidence_depth("medium") < EVENT_EVIDENCE_ITEM_LIMIT
    assert _event_evidence_depth("low") <= _event_evidence_depth("medium")
    assert _event_evidence_depth("info") <= _event_evidence_depth("low")
    # 未知等级要有确定行为，不能返回 0（否则事件会丢掉全部证据）
    assert _event_evidence_depth(None) >= 1
    assert _event_evidence_depth("unknown-level") >= 1


def test_system_prompt_keeps_every_hard_requirement_after_compression():
    """System Prompt 可以精简，但产品硬约束一个字都不能少。"""

    prompt = ai_service.SYSTEM_PROMPT

    # 只读边界与禁止编造
    assert "不得执行系统操作" in prompt
    assert "不得攻击" in prompt
    assert "编造" in prompt
    assert "无法确认时必须明确说明" in prompt
    # 判断质量要求
    assert "规则未命中不等于正常" in prompt
    assert "不得用样本条数代替总体" in prompt
    assert "query_records" in prompt
    # 输出契约：11 个 structured 键与顶层键全部在
    for key in (
        "has_suspicious_behavior",
        "risk_level",
        "confidence",
        "summary",
        "behaviors",
        "recommendations",
        "structured",
        "evidence_ids",
    ):
        assert key in prompt, f"输出契约字段 {key} 缺失"
    for key in (
        "event_time",
        "attack_source_ip",
        "target_asset",
        "involved_account",
        "abnormal_behavior",
        "related_logs",
        "attack_type",
        "judgment_basis",
        "success_indicator",
        "recommended_actions",
    ):
        assert key in prompt, f"structured 键 {key} 缺失"
    # 只返回 JSON
    assert "只返回 JSON" in prompt


def test_system_prompt_stays_compact():
    """压缩后的 System Prompt 要显著小于原始版本，避免每轮都付固定税。"""

    size = len(ai_service.SYSTEM_PROMPT.encode("utf-8"))
    assert size < 1900, f"System Prompt 应保持精简，当前 {size} 字节"


def test_context_notes_stay_compact():
    """上下文说明每轮都会发送，必须用短协议表达，不能退回大段说明文。"""

    from app.services.analyzer import analyze_log
    from app.services.ai import build_ai_context

    log = "\n".join(
        f'198.51.100.{index % 3} - - [12/Sep/2026:06:00:{index:02d} +0800] "GET /admin HTTP/1.1" 200 1 "-" "ua"'
        for index in range(10)
    )
    result = analyze_log("web.log", log)
    records = _parse_for_test("web.log", log.splitlines())
    context = build_ai_context(result, records)

    assert len(context["events_note"].encode("utf-8")) < 260
    assert len(context["records_sample_note"].encode("utf-8")) < 260
    assert "query_events" in context["events_note"]
    assert "query_records" in context["records_sample_note"]


def test_context_keys_are_ordered_stable_first_for_caching():
    """稳定字段在前、易变字段在后，让 prompt caching 能复用更长的前缀。"""

    from app.services.ai import _CONTEXT_KEY_ORDER, _order_context_for_cache

    # 打乱顺序输入，输出应恢复「稳定 → 易变」次序
    scrambled = {
        "records_sample": [],
        "tool_results": {},
        "metadata": {"log_type": "ssh"},
        "events": [],
        "statistics": {"failed_login": 1},
        "context_budget_note": "x",
    }
    ordered = _order_context_for_cache(scrambled)

    keys = list(ordered)
    assert keys.index("metadata") < keys.index("statistics") < keys.index("events")
    assert keys.index("events") < keys.index("records_sample")
    assert keys.index("records_sample") < keys.index("tool_results")
    # 未列入白名单的键不能被丢弃
    assert keys == [k for k in _CONTEXT_KEY_ORDER if k in scrambled] or set(keys) == set(scrambled)
    assert set(ordered) == set(scrambled)


def test_unknown_context_keys_survive_cache_ordering():
    """解析器后续新增的字段不能因为排序白名单而被静默丢弃。"""

    from app.services.ai import _order_context_for_cache

    context = {"metadata": {}, "brand_new_field": {"value": 1}}
    ordered = _order_context_for_cache(context)
    assert ordered["brand_new_field"] == {"value": 1}
    assert list(ordered) == ["metadata", "brand_new_field"]


def test_explicit_cache_marker_only_for_anthropic_family():
    """只有需要显式标记的服务端才注入 cache_control，避免严格网关拒收额外字段。"""

    from app.services.ai import _needs_explicit_cache_marker

    assert _needs_explicit_cache_marker("https://api.anthropic.com")
    assert _needs_explicit_cache_marker("https://openrouter.ai/api/v1")
    # DeepSeek / OpenAI 是自动前缀缓存，不需要显式字段
    assert not _needs_explicit_cache_marker("https://api.deepseek.com")
    assert not _needs_explicit_cache_marker("https://api.openai.com/v1")


def test_cache_marker_is_injected_on_system_prompt_only(monkeypatch):
    """system prompt 打标记、易变的 user 上下文不打，缓存前缀才不会每轮失效。"""

    from app.services.ai import OpenAICompatibleProvider

    monkeypatch.delenv("AI_PROMPT_CACHE", raising=False)
    provider = OpenAICompatibleProvider("https://api.anthropic.com", "m", "k")

    messages = [
        {"role": "system", "content": "SYSTEM"},
        {"role": "user", "content": "CONTEXT"},
    ]
    captured: dict = {}
    monkeypatch.setattr(
        ai_service,
        "_request_json",
        lambda url, payload, headers: captured.update(payload=payload)
        or {"choices": [{"message": {"content": "{}"}}]},
    )

    provider._post(messages)

    sent = captured["payload"]["messages"]
    assert isinstance(sent[0]["content"], list)
    assert sent[0]["content"][0]["cache_control"] == {"type": "ephemeral"}
    assert sent[0]["content"][0]["text"] == "SYSTEM"
    # user 上下文每轮都在变（尤其第二轮起会被摘要占位替换），不应打标记
    assert sent[1]["content"] == "CONTEXT"


def test_prompt_cache_can_be_disabled_by_env(monkeypatch):
    """AI_PROMPT_CACHE=false 时应完全退回纯字符串 content。"""

    from app.services.ai import OpenAICompatibleProvider

    monkeypatch.setenv("AI_PROMPT_CACHE", "false")
    provider = OpenAICompatibleProvider("https://api.anthropic.com", "m", "k")
    assert provider._cacheable("SYSTEM") == "SYSTEM"


def test_automatic_cache_providers_keep_plain_string_content(monkeypatch):
    """自动缓存的服务端不能因为加标记把 content 改成列表，否则会破坏兼容性。"""

    from app.services.ai import OpenAICompatibleProvider

    monkeypatch.delenv("AI_PROMPT_CACHE", raising=False)
    provider = OpenAICompatibleProvider("https://api.deepseek.com", "m", "k")
    assert provider._cacheable("SYSTEM") == "SYSTEM"


def test_usage_is_normalised_across_providers():
    """三家服务端字段名不同，必须归一化成同一份口径才能比较成本。"""

    from app.services.ai import _usage_tokens

    # DeepSeek
    deepseek = _usage_tokens(
        {"usage": {"prompt_tokens": 1000, "completion_tokens": 50,
                   "prompt_cache_hit_tokens": 900, "prompt_cache_miss_tokens": 100}}
    )
    assert deepseek["cache_hit_tokens"] == 900
    assert deepseek["cache_miss_tokens"] == 100
    assert deepseek["cache_hit_ratio"] == 0.9

    # OpenAI：命中数藏在 prompt_tokens_details.cached_tokens
    openai = _usage_tokens(
        {"usage": {"prompt_tokens": 1000, "completion_tokens": 50,
                   "prompt_tokens_details": {"cached_tokens": 512}}}
    )
    assert openai["cache_hit_tokens"] == 512
    assert openai["cache_miss_tokens"] == 488  # 未回传 miss 时按 prompt - hit 推算

    # Anthropic：input_tokens / output_tokens / cache_read_input_tokens
    anthropic = _usage_tokens(
        {"usage": {"input_tokens": 1000, "output_tokens": 50,
                   "cache_read_input_tokens": 800, "cache_creation_input_tokens": 200}}
    )
    assert anthropic["prompt_tokens"] == 1000
    assert anthropic["completion_tokens"] == 50
    assert anthropic["cache_hit_tokens"] == 800
    assert anthropic["cache_write_tokens"] == 200


def test_usage_is_omitted_when_provider_reports_nothing():
    """服务端不回传 usage 时应返回空字典，不能编造 0 掩盖真实情况。"""

    from app.services.ai import _usage_tokens

    assert _usage_tokens({"choices": []}) == {}
    assert _usage_tokens({"usage": None}) == {}
    assert _usage_tokens({}) == {}


def test_merged_usage_reports_overall_hit_ratio():
    """多轮总账要给出整体命中率——这是判断缓存是否真的生效的唯一信号。"""

    from app.services.ai import _merge_usage

    merged = _merge_usage(
        [
            {"round": 1, "prompt_tokens": 1000, "completion_tokens": 10, "cache_hit_tokens": 0},
            {"round": 2, "prompt_tokens": 500, "completion_tokens": 20, "cache_hit_tokens": 400},
        ]
    )
    assert merged["rounds"] == 2
    assert merged["prompt_tokens"] == 1500
    assert merged["completion_tokens"] == 30
    assert merged["cache_hit_tokens"] == 400
    assert merged["cache_hit_ratio"] == round(400 / 1500, 4)


def test_merged_usage_omits_ratio_without_hit_data():
    """没有命中数据时不输出命中率，避免把「未上报」误读成「命中 0%」。"""

    from app.services.ai import _merge_usage

    merged = _merge_usage([{"round": 1, "prompt_tokens": 1000, "completion_tokens": 10}])
    assert "cache_hit_ratio" not in merged
    assert merged["prompt_tokens"] == 1000


def test_tool_loop_records_usage_in_trace(monkeypatch):
    """端到端：工具轮次的用量要写进 trace，否则成本优化缺少真实账单印证。"""

    from app.services.ai import OpenAICompatibleProvider

    monkeypatch.setenv("AI_MAX_TOOL_ROUNDS", "2")
    monkeypatch.setenv("AI_PROMPT_CACHE", "false")

    provider = OpenAICompatibleProvider("https://api.deepseek.com", "m", "k")
    bodies = iter(
        [
            {
                "choices": [{"message": {"role": "assistant", "content": "", "tool_calls": [
                    {"id": "c1", "type": "function",
                     "function": {"name": "log_metadata", "arguments": "{}"}}
                ]}}],
                "usage": {"prompt_tokens": 1000, "completion_tokens": 10,
                          "prompt_cache_hit_tokens": 0},
            },
            {
                "choices": [{"message": {"role": "assistant", "content": "{\"ok\":true}"}}],
                "usage": {"prompt_tokens": 1200, "completion_tokens": 30,
                          "prompt_cache_hit_tokens": 1000},
            },
        ]
    )
    monkeypatch.setattr(ai_service, "_request_json", lambda *a, **k: next(bodies))

    result = _parse_for_test("access.log", [
        '1.2.3.4 - - [10/Oct/2024:00:00:01 +0800] "GET /a HTTP/1.1" 200 1 "-" "curl/8"',
    ])
    content, trace = provider.complete_with_tools(
        ai_service.SYSTEM_PROMPT, {"metadata": {}}, result, []
    )

    assert content == "{\"ok\":true}"
    usage = [entry for entry in trace if entry.get("tool") == "usage"]
    assert len(usage) == 1
    assert usage[0]["usage"]["rounds"] == 2
    assert usage[0]["usage"]["prompt_tokens"] == 2200
    assert usage[0]["usage"]["cache_hit_tokens"] == 1000
    # 也写回 provider，便于调用方在不改返回值的前提下读取
    assert provider.last_usage["prompt_tokens"] == 2200
    # 必须能被接口模型接受（tool == "usage" 是设计内的特例）
    from app.models import AiToolCall

    AiToolCall.model_validate(usage[0])


def test_tool_round_failure_keeps_completed_trace_and_usage(monkeypatch):
    """工具轮次中途失败降级时，已完成的调用轨迹与用量不能一起丢掉。

    真实缺陷：`_request_content` 的降级分支原本 `except Exception: pass`，
    把 `complete_with_tools` 已累积的 trace 直接丢弃。后果不只是「轨迹空白」——
    用量那条 `tool == "usage"` 也在 trace 里，一起丢掉后前端永远显示不出用量。
    生产库实测 49 条已完成分析里 **0 条**带用量，正是这条路径造成的。
    """

    monkeypatch.setenv("AI_MAX_TOOL_ROUNDS", "3")
    monkeypatch.setenv("AI_PROMPT_CACHE", "false")

    from app.services.ai import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider("https://api.deepseek.com", "m", "k")
    calls = {"n": 0}

    def flaky_post(messages, tools=None, on_delta=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "type": "function",
                                    "function": {
                                        "name": "log_metadata",
                                        "arguments": "{}",
                                    },
                                }
                            ],
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 1000,
                    "completion_tokens": 10,
                    "prompt_cache_hit_tokens": 900,
                    "prompt_cache_miss_tokens": 100,
                },
            }
        raise RuntimeError("simulated failure on round 2")

    provider._post = flaky_post
    provider.complete = lambda *a, **k: '{"risk_level":"low"}'

    result = _parse_for_test(
        "auth.log",
        ["Sep 12 01:00:00 demo sshd[100]: Failed password for root from 10.0.0.8 port 22 ssh2"],
    )
    _content, trace = ai_service._request_content(
        provider, {"metadata": {}}, result, result
    )

    tools = [entry.get("tool") for entry in trace]
    assert "log_metadata" in tools, "降级把已完成的工具调用轨迹丢了"
    usage = [entry for entry in trace if entry.get("tool") == "usage"]
    assert usage, "降级把用量记录一起丢了（前端将永远显示不出用量）"
    assert usage[0]["usage"]["prompt_tokens"] == 1000

    from app.models import AiToolCall

    AiToolCall.model_validate(usage[0])


def test_last_usage_is_updated_each_round_so_partial_failure_keeps_it(monkeypatch):
    """用量要每轮落一次，不能只在自然收敛时才写——否则中途失败就等于没记录。"""

    monkeypatch.setenv("AI_MAX_TOOL_ROUNDS", "3")
    monkeypatch.setenv("AI_PROMPT_CACHE", "false")

    from app.services.ai import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider("https://api.deepseek.com", "m", "k")
    round_no = {"n": 0}

    def post_then_fail(messages, tools=None, on_delta=None):
        round_no["n"] += 1
        if round_no["n"] == 1:
            return {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "type": "function",
                                    "function": {"name": "log_metadata", "arguments": "{}"},
                                }
                            ],
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 777,
                    "completion_tokens": 5,
                    "prompt_cache_hit_tokens": 0,
                },
            }
        raise RuntimeError("boom")

    provider._post = post_then_fail
    result = _parse_for_test(
        "auth.log",
        ["Sep 12 01:00:00 demo sshd[100]: Failed password for root from 10.0.0.8 port 22 ssh2"],
    )

    with pytest.raises(RuntimeError):
        provider.complete_with_tools(ai_service.SYSTEM_PROMPT, {"metadata": {}}, result, [])

    # 失败前第一轮的用量必须已经落在 provider 上，供降级路径取回
    assert provider.last_usage.get("prompt_tokens") == 777
    assert any(entry.get("tool") == "log_metadata" for entry in provider.last_trace)


def test_tool_loop_stops_sending_the_full_context_after_the_first_round(monkeypatch):
    """端到端：多轮工具调用时，只有首轮发送完整上下文，后续轮次发摘要占位。

    这是 token 成本的关键杠杆——Chat Completions 每轮重发全部历史，
    若不裁剪，N 轮就等于把整份上下文计费 N+1 次。
    """

    from app.services.ai import OpenAICompatibleProvider, build_ai_context
    from app.services.analyzer import analyze_log

    monkeypatch.setenv("AI_MAX_TOOL_ROUNDS", "4")

    lines = [
        f'203.0.113.{index % 20 + 1} - - [21/Sep/2026:09:{index % 60:02d}:00 +0800] '
        f'"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
        for index in range(200)
    ] + [
        f'198.51.100.{index % 15 + 1} - - [21/Sep/2026:09:{index % 60:02d}:30 +0800] '
        f'"GET /assets/app.js HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        for index in range(400)
    ]
    result = analyze_log("a.log", "\n".join(lines))
    records = _parse_for_test("a.log", lines)
    context = build_ai_context(result, records)

    sent_sizes: list[int] = []

    class FakeProvider(OpenAICompatibleProvider):
        def __init__(self):  # noqa: D107 - 绕过父类需要的凭据
            pass

        def _post(self, messages, tools=None, on_delta=None):
            sent_sizes.append(
                len(
                    json.dumps(messages, ensure_ascii=False, separators=(",", ":")).encode(
                        "utf-8"
                    )
                )
            )
            # 前两轮要求调用工具，第三轮给最终结论
            if len(sent_sizes) < 3:
                return {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": f"call-{len(sent_sizes)}",
                                        "function": {
                                            "name": "query_records",
                                            "arguments": '{"limit": 5}',
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                }
            return {"choices": [{"message": {"role": "assistant", "content": '{"ok": true}'}}]}

    content, trace = FakeProvider().complete_with_tools("SYS", context, result, records)

    assert content == '{"ok": true}'
    assert len(sent_sizes) == 3, "三轮：两次工具请求 + 一次结论"
    assert len(trace) == 2, "工具调用轨迹应完整记录"
    # 首轮完整，后续轮次只剩摘要占位 + 工具结果
    assert sent_sizes[1] < sent_sizes[0] // 5, (
        f"第二轮应大幅小于首轮（实际 {sent_sizes[1]} vs {sent_sizes[0]}）"
    )
    assert sent_sizes[2] < sent_sizes[0] // 5
