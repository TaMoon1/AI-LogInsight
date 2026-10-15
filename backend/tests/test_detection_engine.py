"""声明式规则引擎、Sigma 导入与异常评分的针对性测试。

这三块是「规则体系」的骨架：
- 引擎：条件 / 聚合 / 关联三类原语的语义；
- Sigma 导入：条件表达式（含取反）与字段映射的保语义转换；
- 异常评分：默认不影响定级，开启后按同源累计升级。
"""

from __future__ import annotations

import base64
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services import rules_engine
from app.services.parser import parse_log
from app.services.rule_quality import DEFAULT_CORPUS_DIR
from app.services.sigma_import import convert_path, convert_rule, convert_uploaded

client = TestClient(app)
SIGMA_SAMPLES = DEFAULT_CORPUS_DIR.parent / "sigma-samples"


def _records(log: str):
    return parse_log(log).records


def test_engine_matches_single_record_with_field_ops():
    rule = rules_engine.build_rule(
        {
            "id": "test.contains",
            "title": "测试规则",
            "level": "low",
            "detection": {
                "where": [
                    {"field": "url", "op": "any_contains", "values": ["/.git", "/.env"]},
                    {"field": "status", "op": "equals", "value": "404"},
                ]
            },
            "event": {
                "type": "test_hit",
                "name": "测试命中",
                "summary": "{ip} 命中 {sample}",
            },
        },
        source="test",
    )
    records = _records(
        '10.0.0.1 - - [12/Sep/2026:01:00:00 +0800] "GET /.git/config HTTP/1.1" 404 1 "-" "ua"\n'
        '10.0.0.1 - - [12/Sep/2026:01:00:01 +0800] "GET /.git/config HTTP/1.1" 200 1 "-" "ua"'
    )
    events = rules_engine.evaluate_rule(rule, records)
    assert len(events) == 1
    assert events[0].source_ip == "10.0.0.1"
    assert "/.git/config" in events[0].summary


def test_rule_metadata_is_preserved():
    rule = rules_engine.build_rule(
        {
            "id": "metadata.test",
            "title": "Metadata test",
            "level": "low",
            "author": "IR team",
            "version": "1.2.0",
            "license": "MIT",
            "references": ["https://example.test/rule"],
            "validation_status": "validated",
            "detection": {"where": []},
            "event": {"type": "metadata_test", "name": "Metadata test"},
        },
        source="builtin",
    )

    assert rule.author == "IR team"
    assert rule.version == "1.2.0"
    assert rule.license == "MIT"
    assert rule.references == ("https://example.test/rule",)
    assert rule.validation_status == "validated"


def test_engine_aggregate_window_and_threshold():
    rule = rules_engine.build_rule(
        {
            "id": "test.burst",
            "title": "测试聚合",
            "level": "medium",
            "detection": {
                "where": [{"field": "status", "op": "equals", "value": "500"}],
                "aggregate": {
                    "group_by": ["source_ip"],
                    "count_gte": 3,
                    "window_seconds": 60,
                },
            },
            "event": {"type": "t", "name": "t", "summary": "共 {count} 次"},
        },
        source="test",
    )
    below = _records(
        "\n".join(
            f'10.0.0.2 - - [12/Sep/2026:01:00:0{index} +0800] "GET /x HTTP/1.1" 500 1 "-" "ua"'
            for index in range(2)
        )
    )
    assert rules_engine.evaluate_rule(rule, below) == []

    above = _records(
        "\n".join(
            f'10.0.0.2 - - [12/Sep/2026:01:00:0{index} +0800] "GET /x HTTP/1.1" 500 1 "-" "ua"'
            for index in range(3)
        )
    )
    events = rules_engine.evaluate_rule(rule, above)
    assert len(events) == 1
    assert events[0].count == 3


def test_engine_follow_up_and_suppression():
    """失败聚集 + 后续成功 → 只输出升级事件（基础规则被压制）。"""
    records = _records(
        "\n".join(
            f"Sep 12 01:00:{index:02d} host sshd[100]: Failed password for root from 10.0.0.5 port 22 ssh2"
            for index in range(20)
        )
        + "\nSep 12 01:02:00 host sshd[100]: Accepted password for root from 10.0.0.5 port 22 ssh2"
    )
    rules = rules_engine.load_rules()
    events = rules_engine.evaluate_rules(records, rules=rules)
    rule_ids = {event.rule_id for event in events}
    assert "ssh.bruteforce.success" in rule_ids
    assert "ssh.bruteforce" not in rule_ids


def test_sigma_condition_parser_expands_negation():
    rule = convert_rule(
        {
            "title": "Negation Test",
            "id": "00000000-0000-0000-0000-000000000001",
            "level": "high",
            "logsource": {"category": "webserver"},
            "detection": {
                "selection": {"cs-method": "GET"},
                "keywords": ["union select"],
                "filter_main_status": {"sc-status": 404},
                "condition": "selection and keywords and not 1 of filter_main_*",
            },
        }
    )
    where = rule["detection"]["where"]
    # `cs-method` 声明了 `upper` 变换，转换后必须把它落盘
    assert {
        "field": "action",
        "op": "equals",
        "transform": "upper",
        "value": "GET",
    } in where
    assert any(item.get("negate") and item["field"] == "status" for item in where)
    keywords = next(item for item in where if item["op"] == "any_contains")
    # 多字段谓词逐字段写变换：url 先解码再比，raw 原样
    assert keywords["field"] == [{"field": "url", "transform": "url_decode"}, "raw"]
    assert rule["tags"] == []
    assert rule["id"].startswith("sigma.")


def test_sigma_conversion_reports_unsupported_rules_with_reasons():
    report = convert_path(SIGMA_SAMPLES)
    assert report.total == 9
    # 2026-10-14：转换器支持中间通配（转锚定正则）后，原「通配」跳过样例可转换
    assert report.converted_count == 8
    assert report.skipped_count == 1
    reasons = {item.path: item.reason for item in report.skipped}
    # 断言的是「机制」而不是某个具体字段名：字段覆盖范围会随解析器扩字段而变化，
    # 写死字段名会让这条测试在每次扩字段时无谓失败。
    assert any("修饰符" in reason for reason in reasons.values())
    assert all(item.reason for item in report.skipped)


def test_sigma_windash_expands_dash_variants_and_fires():
    rule = convert_rule(
        {
            "title": "Windash Test",
            "id": "00000000-0000-0000-0000-000000000002",
            "level": "high",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"CommandLine|contains|windash": "-encodedcommand"},
                "condition": "selection",
            },
        }
    )
    predicate = next(
        item
        for item in rule["detection"]["where"]
        if item.get("op") == "any_contains"
    )
    assert predicate["field"] == "command_line"
    # `-` 展开成 5 种破折号变体（- / – — ―），纯值侧展开
    assert set(predicate["values"]) == {
        "-encodedcommand",
        "/encodedcommand",
        "–encodedcommand",
        "—encodedcommand",
        "―encodedcommand",
    }
    built = rules_engine.build_rule(rule, source="test")
    hit_slash = {"status": "1", "command_line": "powershell /encodedcommand SQBFAFgA"}
    hit_plain = {"status": "1", "command_line": "powershell -encodedcommand SQBFAFgA"}
    miss = {"status": "1", "command_line": "powershell -command Get-Date"}
    # 逐条评估：两种破折号变体都要命中，无关命令不得命中
    assert rules_engine.evaluate_rule(built, [hit_slash])
    assert rules_engine.evaluate_rule(built, [hit_plain])
    assert not rules_engine.evaluate_rule(built, [miss])


def test_sigma_base64offset_expands_offsets_and_fires():
    rule = convert_rule(
        {
            "title": "Base64offset Test",
            "id": "00000000-0000-0000-0000-000000000003",
            "level": "high",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"CommandLine|base64offset|contains": "FromBase64String"},
                "condition": "selection",
            },
        }
    )
    predicate = next(
        item
        for item in rule["detection"]["where"]
        if item.get("op") == "any_contains"
    )
    # 3 种对齐偏移各产生一个「完全由原值决定」的 base64 子串
    assert len(predicate["values"]) == 3
    built = rules_engine.build_rule(rule, source="test")
    # 记录里的 base64 带任意前后缀（x…y，值起始不在 3 字节边界上），仍要命中
    encoded = base64.b64encode("xFromBase64Stringy".encode()).decode()
    hit = rules_engine.evaluate_rule(
        built,
        [{"status": "1", "command_line": f"powershell -enc {encoded}"}],
    )
    miss = rules_engine.evaluate_rule(
        built,
        [{"status": "1", "command_line": "powershell -enc RnJvbQ=="}],
    )
    assert len(hit) == 1
    assert not miss


def test_sigma_bare_modifier_key_is_implicit_keywords():
    rule = convert_rule(
        {
            "title": "Bare Modifier Test",
            "id": "00000000-0000-0000-0000-000000000004",
            "level": "medium",
            "logsource": {"category": "webserver"},
            "detection": {
                "sel": {"|re": "<script>"},
                "condition": "sel",
            },
        }
    )
    predicate = rule["detection"]["where"][0]
    # 只有修饰符的键：隐式指向 keywords（url / raw 两处），op 为 regex
    assert predicate["op"] == "regex"
    assert predicate["field"] == [
        {"field": "url", "transform": "url_decode"},
        "raw",
    ]
    assert predicate["value"] == "<script>"


def test_sigma_middle_wildcard_converts_to_anchored_regex():
    rule = convert_rule(
        {
            "title": "Middle Wildcard Test",
            "id": "00000000-0000-0000-0000-000000000005",
            "level": "medium",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"CommandLine": "net group*admin*"},
                "condition": "selection",
            },
        }
    )
    predicate = next(
        item for item in rule["detection"]["where"] if item.get("op") == "regex"
    )
    assert predicate["value"] == "^net\\ group.*admin.*$"
    built = rules_engine.build_rule(rule, source="test")
    hit = rules_engine.evaluate_rule(
        built,
        [{"status": "1", "command_line": 'net group "Domain Admins" /domain'}],
    )
    # 锚定正则：通配语义之外的记录不得命中
    miss = rules_engine.evaluate_rule(
        built,
        [{"status": "1", "command_line": "net group /domain"}],
    )
    assert len(hit) == 1
    assert not miss


def test_imported_sigma_rules_load_and_fire(monkeypatch):
    # conftest 默认关闭社区规则，这里要验证「全量启用」的加载状态
    monkeypatch.setenv("RULE_SIGMA_IMPORTED_ENABLED", "true")
    rules = {rule.id: rule for rule in rules_engine.load_rules()}
    imported = [rule_id for rule_id in rules if rule_id.startswith("sigma.")]
    assert len(imported) >= 7
    assert any(rules[rule_id].source == "sigma" for rule_id in imported)
    xss_id = next(
        rule_id for rule_id in imported if rules[rule_id].title.startswith("Cross Site Scripting")
    )
    records = _records(
        '203.0.113.9 - - [12/Sep/2026:08:00:00 +0800] "GET /c?t=<script>alert(1)</script> HTTP/1.1" 200 1 "-" "ua"'
    )
    events = rules_engine.evaluate_rule(rules[xss_id], records)
    assert len(events) == 1
    assert events[0].rule_id == xss_id
    assert rules[xss_id].source == "sigma"


def test_imported_rules_can_be_disabled_globally(monkeypatch):
    monkeypatch.setenv("RULE_SIGMA_IMPORTED_ENABLED", "false")
    rules = rules_engine.load_rules()
    assert [rule for rule in rules if rule.source == "sigma" and rule.enabled] == []
    assert [rule for rule in rules if rule.source != "sigma" and rule.enabled]


def test_sigma_preview_endpoint_does_not_write_rules(monkeypatch):
    content = (SIGMA_SAMPLES / "web_source_code_enumeration.yml").read_bytes()
    response = client.post(
        "/api/rules/sigma/preview",
        files={"file": ("rule.yml", content, "text/yaml")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["converted_count"] == 1
    assert body["converted"][0]["rule"]["detection"]["where"]


def test_sigma_preview_reports_yaml_errors():
    report = convert_uploaded("broken.yml", b"title: [unclosed")
    assert report.converted_count == 0
    assert "YAML 解析失败" in report.skipped[0].reason


def test_risk_scoring_is_off_by_default(monkeypatch):
    monkeypatch.delenv("RISK_SCORING_ENABLED", raising=False)
    log = "\n".join(
        [
            '203.0.113.70 - - [12/Sep/2026:09:00:00 +0800] "GET /../../etc/passwd HTTP/1.1" 400 1 "-" "ua"',
            '203.0.113.70 - - [12/Sep/2026:09:00:01 +0800] "GET /s?q=1\' or \'1\'=\'1 HTTP/1.1" 403 1 "-" "ua"',
            '203.0.113.70 - - [12/Sep/2026:09:00:02 +0800] "GET /exec?cmd=;cat /etc/passwd HTTP/1.1" 200 1 "-" "ua"',
        ]
    )
    response = client.post("/api/logs/upload", files={"file": ("access.log", log, "text/plain")})
    body = response.json()["result"]
    assert body["risk_score_enabled"] is False
    assert body["risk_score"] > 0
    # 三个高风险同源，累计分会「达到」critical 阈值（escalated=True），
    # 但默认关闭评分，所以结论等级仍停在 high 而不是被升级
    assert body["risk_level"] == "high"
    assert body["risk_scores"][0]["escalated"] is True
    assert body["risk_scores"][0]["escalated_level"] == "critical"


def test_risk_scoring_escalates_when_enabled(monkeypatch):
    monkeypatch.setenv("RISK_SCORING_ENABLED", "true")
    log = "\n".join(
        [
            '203.0.113.71 - - [12/Sep/2026:10:00:00 +0800] "GET /../../etc/passwd HTTP/1.1" 400 1 "-" "ua"',
            '203.0.113.71 - - [12/Sep/2026:10:00:01 +0800] "GET /s?q=1\' or \'1\'=\'1 HTTP/1.1" 403 1 "-" "ua"',
            '203.0.113.71 - - [12/Sep/2026:10:00:02 +0800] "GET /.env HTTP/1.1" 404 1 "-" "ua"',
            '203.0.113.71 - - [12/Sep/2026:10:00:03 +0800] "GET /actuator/heapdump HTTP/1.1" 404 1 "-" "ua"',
        ]
    )
    response = client.post("/api/logs/upload", files={"file": ("access.log", log, "text/plain")})
    body = response.json()["result"]
    assert body["risk_score_enabled"] is True
    assert body["risk_level"] == "critical"
    assert "异常评分升级风险等级" in body["conclusion"]


def test_risk_scoring_does_not_merge_different_sources(monkeypatch):
    monkeypatch.setenv("RISK_SCORING_ENABLED", "true")
    monkeypatch.setenv("RISK_SCORE_CRITICAL", "15")
    log = "\n".join(
        [
            '203.0.113.72 - - [12/Sep/2026:11:00:00 +0800] "GET /../../etc/passwd HTTP/1.1" 400 1 "-" "ua"',
            '203.0.113.73 - - [12/Sep/2026:11:00:01 +0800] "GET /s?q=1\' or \'1\'=\'1 HTTP/1.1" 403 1 "-" "ua"',
        ]
    )
    response = client.post("/api/logs/upload", files={"file": ("access.log", log, "text/plain")})
    body = response.json()["result"]
    assert len(body["risk_scores"]) == 2
    assert all(item["score"] < 15 for item in body["risk_scores"])
    assert body["risk_level"] == "high"


def test_rules_endpoint_exposes_source_and_tags():
    rules = {item["id"]: item for item in client.get("/api/rules").json()}
    assert rules["ssh.bruteforce"]["source"] == "builtin"
    sigma_rule = next(item for item in rules.values() if item["id"].startswith("sigma."))
    assert sigma_rule["source"] == "sigma"
    assert any(tag.startswith("attack.") for tag in sigma_rule["tags"])


def test_risk_scoring_covers_host_side_events_without_source_ip(monkeypatch):
    """主机侧日志（Sysmon / Windows）没有来源 IP，必须退回按目标主机评分。

    否则这部分事件完全拿不到异常评分——而终端取证正是产品的主要用途。
    """

    from pathlib import Path

    monkeypatch.delenv("RISK_SCORING_ENABLED", raising=False)
    log = (
        Path(__file__).resolve().parents[1]
        / "evaluation"
        / "scenarios"
        / "sysmon-intrusion-chain.log"
    ).read_text(encoding="utf-8", errors="replace")
    response = client.post(
        "/api/logs/upload", files={"file": ("sysmon.log", log, "text/plain")}
    )
    body = response.json()["result"]
    assert len(body["risk_scores"]) == 1
    item = body["risk_scores"][0]
    assert item["kind"] == "target_asset"
    assert item["key"] == "WK001.megacorpone.com"
    assert item["source_ip"] == ""
    assert item["score"] > 0
    # 默认不参与定级，风险等级仍由事件本身决定
    assert body["risk_score_enabled"] is False
    assert body["risk_level"] == "high"


def test_risk_scoring_keeps_ip_and_asset_dimensions_separate():
    """来源 IP 与目标主机是两个独立维度，分数不能互相叠加。"""

    from app.models import Event
    from app.services.risk_scoring import score_events

    items = score_events(
        [
            Event(id="e1", type="t", name="n", summary="s", risk_level="high", source_ip="203.0.113.9"),
            Event(id="e2", type="t", name="n", summary="s", risk_level="high", target_asset="WK001"),
            Event(id="e3", type="t", name="n", summary="s", risk_level="low"),
        ]
    )
    assert {(item.kind, item.key) for item in items} == {
        ("source_ip", "203.0.113.9"),
        ("target_asset", "WK001"),
    }
    assert all(item.score == 5 for item in items)
    assert all(item.rule_ids == [] for item in items)
