"""AI 洞察的攻击链上限：链数等于「来源 IP 数」，不设上限会直接把页面压死。

背景：认证导出类日志有几千个来源 IP，`/insights` 就会返回几千条攻击链
（实测 11091 条记录 → 1999 条链 / 2.33 MB），前端为每条链渲染一张卡片。
这里锁的是「按风险排序后截断 + 总数不谎报 + 截断时留下的最值得看」三条。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import INSIGHTS_CHAIN_LIMIT_DEFAULT, app
from app.services.analytics import build_attack_chains
from app.services.events import build_event

client = TestClient(app)

SOURCES = 30
HIGH_RISK_SOURCE = "203.0.113.7"

# 30 个来源各探测一次敏感路径（medium / 单阶段），其中 203.0.113.7 还成功读取了敏感文件
# （high，多阶段）。高风险那个来源刻意写在日志最后，用来证明排序不是按出现顺序。
LOG = "\n".join(
    [
        *(
            f'198.51.100.{index + 1} - - [21/Sep/2026:09:{index:02d}:00 +0800] '
            f'"GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"'
            for index in range(SOURCES - 1)
        ),
        f'{HIGH_RISK_SOURCE} - - [21/Sep/2026:09:30:00 +0800] "GET /.env HTTP/1.1" 403 1 "-" "curl/8.0"',
        f'{HIGH_RISK_SOURCE} - - [21/Sep/2026:09:31:00 +0800] "GET /id_rsa HTTP/1.1" 200 1 "-" "curl/8.0"',
    ]
)


def _upload() -> str:
    response = client.post("/api/logs/upload", files={"file": ("many.log", LOG, "text/plain")})
    assert response.status_code == 200
    return response.json()["analysis_id"]


def test_attack_chains_are_capped_and_the_total_is_reported():
    analysis_id = _upload()
    body = client.get(f"/api/analysis/{analysis_id}/insights").json()

    assert body["attack_chains_total"] == SOURCES
    assert len(body["attack_chains"]) == INSIGHTS_CHAIN_LIMIT_DEFAULT
    assert INSIGHTS_CHAIN_LIMIT_DEFAULT < SOURCES  # 否则这条测试没意义


def test_chain_limit_zero_is_rejected_to_protect_large_responses():
    analysis_id = _upload()
    rejected = client.get(f"/api/analysis/{analysis_id}/insights?chain_limit=0")
    assert rejected.status_code == 422

    page = client.get(f"/api/analysis/{analysis_id}/insights?chain_limit=3").json()
    assert len(page["attack_chains"]) == 3
    assert page["attack_chains_total"] == SOURCES


def test_truncated_view_keeps_the_most_complete_chain_first():
    """截断后第一条必须是最严重的：高风险、阶段多的那条要排在前面。"""

    analysis_id = _upload()
    body = client.get(f"/api/analysis/{analysis_id}/insights?chain_limit=1").json()
    chain = body["attack_chains"][0]
    assert chain["key"] == HIGH_RISK_SOURCE
    assert chain["risk_level"] == "high"
    assert len(chain["stages"]) > 1, "同风险时阶段多的链应优先，说明排序生效"

    # 被截掉的那些来源仍然是 medium 单阶段链
    rest = client.get(f"/api/analysis/{analysis_id}/insights?chain_limit=20").json()
    others = [item for item in rest["attack_chains"] if item["key"] != HIGH_RISK_SOURCE]
    assert others and all(item["risk_level"] == "medium" for item in others)


def test_insights_supports_offset_pagination():
    analysis_id = _upload()
    first = client.get(
        f"/api/analysis/{analysis_id}/insights?chain_offset=0&chain_limit=3"
    ).json()
    second = client.get(
        f"/api/analysis/{analysis_id}/insights?chain_offset=3&chain_limit=3"
    ).json()

    assert len(first["attack_chains"]) == 3
    assert len(second["attack_chains"]) == 3
    assert first["attack_chains"][0]["key"] != second["attack_chains"][0]["key"]
    assert first["attack_chains_total"] == second["attack_chains_total"] == SOURCES


def test_service_level_cap_and_ordering():
    """服务层：同风险时阶段多的排前面，`max_chains` 生效且不改变传入列表。"""

    events = [
        build_event("t", "单阶段", "medium", "s1", source_ip="10.0.0.1", rule_id="r1"),
        build_event(
            "t", "两阶段", "medium", "s2", source_ip="10.0.0.2", rule_id="r2", count=5
        ),
        build_event("t", "额外阶段", "medium", "s3", source_ip="10.0.0.2", rule_id="r3"),
    ]
    chains = build_attack_chains(events, [])
    assert [chain.key for chain in chains] == ["10.0.0.2", "10.0.0.1"]
    assert [len(chain.stages) for chain in chains] == [2, 1]

    capped = build_attack_chains(events, [], max_chains=1)
    assert [chain.key for chain in capped] == ["10.0.0.2"]
    assert len(build_attack_chains(events, [])) == 2  # 默认不截断（服务层调用方自己决定）
    assert [event.rule_id for event in events] == ["r1", "r2", "r3"]
