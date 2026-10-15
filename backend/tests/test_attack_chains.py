"""杀伤链归组：优先来源 IP，其次目标资产（主机），最后规则。

主机侧日志（Sysmon / Windows）没有来源 IP，若不用 target_asset 归组，
同一主机的行为链会被拆成「一个规则一条链」，看不到完整攻击过程。
"""

from __future__ import annotations

from pathlib import Path

from app.services.analytics import build_attack_chains
from app.services.analyzer import analyze_log

SCENARIO_DIR = Path(__file__).resolve().parents[1] / "evaluation" / "scenarios"


def _scenario_log(name: str) -> str:
    return (SCENARIO_DIR / name).read_text(encoding="utf-8", errors="replace")


def test_host_log_events_form_one_chain_keyed_by_target_asset():
    result = analyze_log("sysmon-intrusion-chain.log", _scenario_log("sysmon-intrusion-chain.log"))
    chains = build_attack_chains(result.events, result.entities)

    assert len(result.events) == 13
    assert len(chains) == 1, "同一主机的行为应合成一条链，而不是一个规则一条链"
    chain = chains[0]
    assert chain.kind == "target_asset"
    assert chain.key == "WK001.megacorpone.com"
    assert chain.risk_level == "high"
    assert len(chain.stages) == 13
    # 阶段按 ATT&CK 阶段序排列，起点是「发现」
    assert chain.stages[0].phase == "发现"
    assert {stage.rule_id for stage in chain.stages} >= {
        "windows.lolbin_download",
        "windows.credential_file_access",
        "windows.archive_with_password",
    }


def test_events_carry_target_asset():
    result = analyze_log("sysmon-intrusion-chain.log", _scenario_log("sysmon-intrusion-chain.log"))
    assert all(event.target_asset == "WK001.megacorpone.com" for event in result.events)
    assert all(event.source_ip is None for event in result.events)
    assert any("同一目标资产" in item for item in result.events[0].correlation_basis)


def test_web_log_still_groups_by_source_ip():
    result = analyze_log(
        "nginx-sensitive-file-probe.log", _scenario_log("nginx-sensitive-file-probe.log")
    )
    chains = build_attack_chains(result.events, result.entities)
    assert {chain.kind for chain in chains} == {"source_ip"}
    assert {chain.key for chain in chains} == {"192.168.1.101", "172.16.0.2"}


def test_events_without_source_ip_and_asset_fall_back_to_rule_grouping():
    """既无来源 IP 也无目标资产时仍是「一个规则一条链」，不能丢事件。"""

    from app.services.events import build_event

    events = [
        build_event("type_a", "事件 A", "medium", "摘要 A", rule_id="rule.a"),
        build_event("type_b", "事件 B", "low", "摘要 B", rule_id="rule.b"),
    ]
    chains = build_attack_chains(events, [])
    assert {chain.kind for chain in chains} == {"rule"}
    assert {chain.key for chain in chains} == {"rule:rule.a", "rule:rule.b"}
    assert sum(len(chain.stages) for chain in chains) == 2


def test_terminal_chains_do_not_merge_unknown_assets_by_source_file():
    from app.services.correlation import build_terminal_evidence_chains

    records = [
        {
            "record_id": "record-1",
            "source_file": "combined.evtx",
            "process_image": r"C:\Temp\a.exe",
            "process_id": "101",
            "timestamp": "2026-09-20 10:00:00",
        },
        {
            "record_id": "record-2",
            "source_file": "combined.evtx",
            "process_image": r"C:\Temp\b.exe",
            "process_id": "202",
            "timestamp": "2026-09-20 10:01:00",
        },
    ]

    chains = build_terminal_evidence_chains(records, [])
    assert len(chains) == 2
    assert {chain["record_count"] for chain in chains} == {1}


def test_target_asset_is_exposed_by_upload_api():
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    payload = _scenario_log("sysmon-intrusion-chain.log")
    response = client.post(
        "/api/logs/upload",
        files={"file": ("log.txt", payload, "text/plain")},
    )
    assert response.status_code == 200
    body = response.json()["result"]
    assert all(item["target_asset"] == "WK001.megacorpone.com" for item in body["events"])
