"""实体调查：精确匹配与分页截断。

两条都是**结论可信度**问题，不是体验问题：
① 子串匹配会让 `10.0.0.8` 命中 `10.0.0.80`、让 `root` 命中 `rootuser`，
   取证视图里等于凭空造出关联；
② events / timeline 不截断时，一个高频来源 IP 会一次返回几十 MB，
   而截断后如果不说清真实总数，界面就会谎报「只有 N 条」。
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def make_similar_entity_log() -> str:
    """同一份日志里同时出现 10.0.0.8 / 10.0.0.80 与 root / rootuser（各 5 条，不足以触发规则）。"""

    lines = [
        f"Sep 12 01:00:{index:02d} host sshd[100]: "
        f"Failed password for root from 10.0.0.8 port 22 ssh2"
        for index in range(5)
    ]
    lines += [
        f"Sep 12 01:01:{index:02d} host sshd[100]: "
        f"Failed password for rootuser from 10.0.0.80 port 22 ssh2"
        for index in range(5)
    ]
    return "\n".join(lines)


def make_two_bruteforce_log() -> str:
    """两个相似 IP 各自构成一次认证失败聚集，用于验证事件与时间线互不污染。"""

    lines = [
        f"Sep 12 01:00:{index:02d} host sshd[100]: "
        f"Failed password for root from 10.0.0.8 port 22 ssh2"
        for index in range(20)
    ]
    lines += [
        f"Sep 12 01:10:{index:02d} host sshd[100]: "
        f"Failed password for rootuser from 10.0.0.80 port 22 ssh2"
        for index in range(20)
    ]
    return "\n".join(lines)


def make_multi_rule_web_log() -> str:
    """同一来源 IP 触发多条不同风险的规则，用于验证截断顺序。"""

    lines = [
        f'10.0.0.9 - - [12/Sep/2026:01:00:{index:02d} +0800] '
        f'"GET /missing-{index} HTTP/1.1" 404 12 "-" "ua"'
        for index in range(20)
    ]
    lines.append(
        '10.0.0.9 - - [12/Sep/2026:01:01:00 +0800] '
        '"GET /../../../../etc/passwd HTTP/1.1" 400 12 "-" "ua"'
    )
    lines.append(
        '10.0.0.9 - - [12/Sep/2026:01:01:01 +0800] '
        '"GET /.env HTTP/1.1" 404 12 "-" "ua"'
    )
    return "\n".join(lines)


def upload(content: str, filename: str = "entity.log") -> str:
    response = client.post(
        "/api/logs/upload",
        files={"file": (filename, content, "text/plain")},
    )
    assert response.status_code == 200
    return response.json()["analysis_id"]


def _risk_rank(level: str) -> int:
    order = ("info", "low", "medium", "high", "critical")
    return order.index(level) if level in order else -1


def test_ip_match_is_exact_not_substring():
    analysis_id = upload(make_similar_entity_log())
    payload = client.get(f"/api/analysis/{analysis_id}/entities/ip/10.0.0.8").json()
    # 子串匹配会把 10.0.0.80 的 5 条一起算进来，总数变成 10
    assert payload["records"]["total"] == 5
    assert {item["source_ip"] for item in payload["records"]["items"]} == {"10.0.0.8"}


def test_account_match_is_exact_not_substring():
    analysis_id = upload(make_similar_entity_log())
    payload = client.get(f"/api/analysis/{analysis_id}/entities/account/root").json()
    # 同理：rootuser 的 5 条不能被算成 root 的行为
    assert payload["records"]["total"] == 5
    assert {item["username"] for item in payload["records"]["items"]} == {"root"}


def test_entity_match_ignores_case():
    analysis_id = upload(make_similar_entity_log())
    upper = client.get(f"/api/analysis/{analysis_id}/entities/account/ROOT").json()
    lower = client.get(f"/api/analysis/{analysis_id}/entities/account/root").json()
    assert upper["records"]["total"] == lower["records"]["total"] == 5


def test_absent_entity_returns_empty_without_fabricating():
    analysis_id = upload(make_similar_entity_log())
    payload = client.get(
        f"/api/analysis/{analysis_id}/entities/domain/evil.example.com"
    ).json()
    assert payload["records"]["total"] == 0
    assert payload["records"]["items"] == []
    assert payload["events"] == []
    assert payload["events_total"] == 0
    assert payload["timeline"] == []
    assert payload["timeline_total"] == 0


def test_invalid_kind_and_empty_value_are_rejected():
    analysis_id = upload(make_similar_entity_log())
    assert (
        client.get(f"/api/analysis/{analysis_id}/entities/nonsense/x").status_code == 400
    )
    assert client.get(f"/api/analysis/{analysis_id}/entities/ip/%20").status_code == 400
    assert client.get("/api/analysis/not-exist/entities/ip/10.0.0.8").status_code == 404


def test_similar_ips_do_not_share_events_or_timeline():
    """子串匹配下 10.0.0.8 会连带命中 10.0.0.80 的事件与时间线。"""

    analysis_id = upload(make_two_bruteforce_log())
    narrow = client.get(f"/api/analysis/{analysis_id}/entities/ip/10.0.0.8").json()
    wide = client.get(f"/api/analysis/{analysis_id}/entities/ip/10.0.0.80").json()

    assert narrow["events"], "10.0.0.8 应产出认证失败聚集事件"
    assert wide["events"], "10.0.0.80 应产出认证失败聚集事件"
    assert {item["source_ip"] for item in narrow["events"]} == {"10.0.0.8"}
    assert {item["source_ip"] for item in wide["events"]} == {"10.0.0.80"}
    assert not ({item["id"] for item in narrow["events"]} & {item["id"] for item in wide["events"]})

    # 时间线同样不能串味：每条引用的记录都要属于本实体
    own = {item["record_id"] for item in narrow["records"]["items"]}
    assert all(item["record_id"] in own for item in narrow["timeline"])


def test_events_are_capped_but_total_stays_true_and_severe_first():
    analysis_id = upload(make_multi_rule_web_log())
    full = client.get(f"/api/analysis/{analysis_id}/entities/ip/10.0.0.9").json()
    assert full["events_total"] >= 2
    assert full["events_total"] == len(full["events"])
    highest = max(full["events"], key=lambda item: _risk_rank(item["risk_level"]))

    capped = client.get(
        f"/api/analysis/{analysis_id}/entities/ip/10.0.0.9?event_limit=1"
    ).json()
    # 截断只影响展示条数，真实总数不变
    assert capped["events_total"] == full["events_total"]
    assert len(capped["events"]) == 1
    # 留下的是最严重的，而不是最先产出的
    assert capped["events"][0]["risk_level"] == highest["risk_level"]


def test_timeline_is_capped_but_total_stays_true():
    analysis_id = upload(make_two_bruteforce_log())
    full = client.get(f"/api/analysis/{analysis_id}/entities/ip/10.0.0.8").json()
    assert full["timeline_total"] >= 2
    assert full["timeline_total"] == len(full["timeline"])

    capped = client.get(
        f"/api/analysis/{analysis_id}/entities/ip/10.0.0.8?timeline_limit=1"
    ).json()
    assert capped["timeline_total"] == full["timeline_total"]
    assert len(capped["timeline"]) == 1
