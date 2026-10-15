"""规则质量门禁：语料必须覆盖全部**内置**规则，且不允许出现误报或漏报。

语料是「声明式引擎迁移」的等价性判据——迁移前后都必须保持 precision / recall 100%。

口径（2026-09-22 起，随 Sigma 社区规则批量导入调整）：
- **内置规则**（自己写的）必须每条有正样本；
- **导入的社区规则**做不到逐条配样本，验收口径是「在正常流量用例上零命中」，
  未验证的导入规则单独列出（unverified_rules），不允许混进「已覆盖」里蒙混；
- 误报的定义是**正常流量被当成异常**（负样本用例）；社区规则在攻击样本上
  重复命中属「重复检出」（duplicate_hits），计数但不判失败——否则没人敢导入任何规则。
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.rule_metadata import check_validation_consistency, render_violations
from app.services.rule_quality import evaluate, render_markdown
from app.services.rules import get_rules

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def _enable_community_rules():
    """门禁必须在「社区规则全量启用」的真实状态下评估，conftest 里默认关了它们。

    evaluate() 跑一遍 560 条规则要 20 秒，所以这里用 module 作用域：
    环境只设一次，`report` fixture 也只算一次，避免每个测试都重算一遍。
    """

    previous = os.environ.get("RULE_SIGMA_IMPORTED_ENABLED")
    os.environ["RULE_SIGMA_IMPORTED_ENABLED"] = "true"
    yield
    if previous is None:
        os.environ.pop("RULE_SIGMA_IMPORTED_ENABLED", None)
    else:
        os.environ["RULE_SIGMA_IMPORTED_ENABLED"] = previous


@pytest.fixture(scope="module")
def report():
    return evaluate()


def test_corpus_covers_every_rule_without_false_positive_or_negative(report):
    assert report.case_count >= 25
    assert report.uncovered_rules == [], "每条内置规则都必须至少有一个正样本用例"
    assert report.false_positive == 0
    assert report.false_negative == 0
    assert report.passed_count == report.case_count
    assert report.precision == 1.0
    assert report.recall == 1.0
    # 导入的社区规则必须被显式报告为「未验证」，不能藏起来
    assert report.imported_rule_count >= 400
    assert report.unverified_rule_count >= 400
    assert len(report.unverified_rules) == report.unverified_rule_count


def test_metadata_declaration_matches_corpus_evidence(report):
    """声明与证据必须一致：`validated` ⟺ 语料里有正样本（P5-①）。

    不允许「声明已验证但语料没验过」，也不允许反过来把有正样本的规则藏在未验证里。
    """

    covered = {item.rule_id for item in report.rules if item.positive > 0}
    violations = check_validation_consistency(get_rules(), covered)
    assert violations == [], render_violations(violations)


def test_negative_cases_produce_no_events(report):
    negatives = [case for case in report.cases if case.expected == "无事件"]
    assert len(negatives) >= 6, "负样本应覆盖阈值以下与正常流量"
    assert all(case.ok for case in negatives)
    assert all(case.actual == "无事件" for case in negatives)


def test_rule_quality_endpoint_exposes_report():
    response = client.get("/api/rules/quality")
    assert response.status_code == 200
    body = response.json()
    assert body["rule_count"] >= 21
    # 内置规则全有正样本；导入规则单独统计并显式列出未验证的
    assert body["covered_rule_count"] == body["builtin_rule_count"]
    assert body["builtin_rule_count"] + body["imported_rule_count"] == body["rule_count"]
    assert body["unverified_rule_count"] <= body["imported_rule_count"]
    assert body["false_positive"] == 0
    assert body["false_negative"] == 0
    assert len(body["rules"]) == body["rule_count"]


def test_markdown_report_lists_every_rule(report):
    markdown = render_markdown(report)
    for item in report.rules:
        assert f"`{item.rule_id}`" in markdown
    assert "## 未验证的导入规则清单" in markdown
    for rule_id in report.unverified_rules:
        assert f"- `{rule_id}`" in markdown


def test_attack_coverage_endpoint_reports_reference_gaps():
    """覆盖报告的三个口径必须都报出来：外部参考（只作标尺）、有规则、有本地正样本。"""

    response = client.get("/api/rules/attack-coverage")
    assert response.status_code == 200
    body = response.json()

    # 270 是外部参考集规模：没打包进仓库，也不能被读成「本项目有 270 个样本」
    assert body["reference_sample_count"] == 270
    assert body["reference_packaged"] is False
    assert "未打包" in body["scope_note"]
    assert "全量" in body["scope_note"], "必须说明 27 项不等于 ATT&CK 全量，避免覆盖率被误读"
    assert body["source_url"].startswith("https://github.com/")

    assert body["technique_count"] >= 20
    assert (
        body["covered_technique_count"] + len(body["uncovered_techniques"])
        == body["technique_count"]
    )
    # 「有规则」与「有本地正样本」分开统计：只报一个数会把未验证的规则说成已验证
    assert body["sample_validated_technique_count"] <= body["covered_technique_count"]
    covered_ids = {item["technique_id"] for item in body["techniques"] if item["covered"]}
    assert set(body["covered_without_sample"]) <= covered_ids

    # 整份真实日志用例（4）与攻击链场景 family（2）是两种口径，不能混成一个数
    assert body["local_whole_log_case_count"] >= 4
    assert body["local_chain_case_count"] >= 2
    assert body["local_whole_log_case_count"] > body["local_chain_case_count"]

    for item in body["techniques"]:
        assert item["covered"] == bool(item["rule_ids"])
        assert item["local_sample_count"] >= 0
        assert "reference_samples" not in item, "逐技术的「参考样本数」是编的，不该出现在报告里"


def test_attack_coverage_separates_external_and_project_techniques():
    """外部参考集原有技术与本项目补充技术必须分开统计。

    清单里混入自选技术后，如果只报一个合并的覆盖率，就会把「自己加进来的技术」
    算成「外部基准的覆盖情况」——这正是项目一贯反对的假覆盖。
    """

    body = client.get("/api/rules/attack-coverage").json()
    external = [item for item in body["techniques"] if item["origin"] == "external"]
    project = [item for item in body["techniques"] if item["origin"] == "project"]

    assert external, "外部参考集原有技术不应为空"
    assert project, "本项目补充技术不应为空"
    assert len(external) + len(project) == body["technique_count"]
    assert body["external_technique_count"] == len(external)
    assert body["project_technique_count"] == len(project)
    assert body["external_covered_count"] == sum(1 for item in external if item["covered"])
    assert body["project_covered_count"] == sum(1 for item in project if item["covered"])
    # 「补齐了缺口」的正确形态是「规则 + 本地正样本」一起到位。清单 2026-10-13 扩到 120 项后，
    # 新加入的 75 项暂时只有规则（导入规则还没有本地语料），所以这里断言的是**它没有被藏起来**：
    # 缺样本的技术必须在 `covered_without_sample` 里逐个列出，
    # 而不是被合并进「已覆盖」后悄悄当成验证过（那就是假覆盖）。
    assert body["sample_validated_technique_count"] == sum(
        1 for item in body["techniques"] if item["local_sample_count"]
    )
    assert len(body["covered_without_sample"]) == sum(
        1 for item in body["techniques"] if item["covered"] and not item["local_sample_count"]
    )
    assert body["covered_without_sample"], "扩清单后必须存在「有规则但缺样本」的技术并显式列出"


def test_script_interpreter_techniques_are_covered_and_validated():
    """T1059.001 / T1059.003 是这份清单里最后的两个缺口，必须靠「规则 + 本地正样本」一起关掉。

    只加规则不加样本的话，报告里会出现「已覆盖但缺本地正样本」，那是没验证过的规则，
    不能算补齐。
    """

    body = client.get("/api/rules/attack-coverage").json()
    by_id = {item["technique_id"]: item for item in body["techniques"]}

    for technique_id, rule_id in (
        ("T1059.001", "windows.script_interpreter_encoded"),
        ("T1059.003", "windows.command_shell_suspicious_parent"),
    ):
        item = by_id[technique_id]
        assert rule_id in item["rule_ids"]
        assert item["local_sample_count"] >= 1, f"{technique_id} 只有规则、没有正样本验证"
        assert technique_id not in body["covered_without_sample"]

    # 两条规则都必须在聚合门禁里被正样本覆盖（规则存在但不生效 = 假覆盖）
    report = evaluate()
    covered_rules = {item.rule_id for item in report.rules if item.positive >= 1}
    assert {"windows.script_interpreter_encoded", "windows.command_shell_suspicious_parent"} <= covered_rules
