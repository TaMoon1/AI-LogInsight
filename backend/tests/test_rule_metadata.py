"""规则元数据门禁：格式合法性 + 「声明与证据一致」。

对应路线图 P5-①：`RuleDefinition` 早就支持 author / version / license / references /
validation_status，但此前没有任何地方检查它们填得对不对。这里把两件事钉住：
① 出厂规则必须全部通过格式门禁；② 声明 `validated` 必须有本地正样本，不允许空口声明。
"""

from __future__ import annotations

from pathlib import Path

from app.services.rule_metadata import (
    check_rule_metadata,
    check_validation_consistency,
    render_violations,
)
from app.services.rules import get_rules
from app.services.rules_engine import build_rule, load_rules


def _rule(**overrides):
    raw = {"id": "test.rule", "title": "测试规则", "level": "low", **overrides}
    return build_rule(raw, source="builtin")


def test_shipped_rules_pass_metadata_gate():
    """出厂规则（1852 条）必须零违规——这是本轮改动的直接验收标准。"""

    violations = check_rule_metadata(get_rules())
    assert violations == [], render_violations(violations)


def test_document_metadata_is_inherited(tmp_path: Path):
    """文档级 `metadata` 块必须被文件内的规则继承（否则 1771 条导入规则要逐条重复）。"""

    path = tmp_path / "10-test.yaml"
    path.write_text(
        "source: builtin\n"
        "metadata:\n"
        "  author: 文档级作者\n"
        "  version: '1.0'\n"
        "  license: MIT\n"
        "  validation_status: unverified\n"
        "rules:\n"
        "  - id: test.inherit\n"
        "    title: 继承文档级元数据\n"
        "    level: low\n",
        encoding="utf-8",
    )
    rule = next(item for item in load_rules(tmp_path) if item.id == "test.inherit")
    assert rule.author == "文档级作者"
    assert rule.version == "1.0"
    assert rule.license == "MIT"
    assert rule.validation_status == "unverified"


def test_rule_level_metadata_overrides_document(tmp_path: Path):
    """规则级声明优先于文档级——例外规则必须能单独覆盖，否则只能改整份文件。"""

    path = tmp_path / "10-test.yaml"
    path.write_text(
        "source: builtin\n"
        "metadata:\n"
        "  author: 文档级作者\n"
        "  license: MIT\n"
        "  validation_status: unverified\n"
        "rules:\n"
        "  - id: test.override\n"
        "    title: 覆盖文档级元数据\n"
        "    level: low\n"
        "    author: 规则级作者\n"
        "    license: Apache-2.0\n",
        encoding="utf-8",
    )
    rule = next(item for item in load_rules(tmp_path) if item.id == "test.override")
    assert rule.author == "规则级作者"
    assert rule.license == "Apache-2.0"


def test_missing_author_is_flagged():
    violations = check_rule_metadata([_rule()])
    assert [item.field for item in violations] == ["author", "license"]


def test_invalid_license_is_flagged():
    violations = check_rule_metadata([_rule(author="a", license="随便写的")])
    assert len(violations) == 1
    assert violations[0].field == "license"
    assert "不在允许集合" in violations[0].reason


def test_invalid_validation_status_is_flagged():
    violations = check_rule_metadata(
        [_rule(author="a", license="MIT", validation_status="verified")]
    )
    assert len(violations) == 1
    assert violations[0].field == "validation_status"


def test_non_http_reference_is_flagged():
    violations = check_rule_metadata(
        [_rule(author="a", license="MIT", references=["见内部文档", "https://example.com/x"])]
    )
    assert len(violations) == 1
    assert violations[0].field == "references"
    assert "见内部文档" in violations[0].reason


def test_validation_consistency_flags_claim_without_sample():
    rule = _rule(author="a", license="MIT", validation_status="validated")
    violations = check_validation_consistency([rule], covered_rule_ids=[])
    assert len(violations) == 1
    assert "没有正样本" in violations[0].reason


def test_validation_consistency_flags_sample_declared_unverified():
    rule = _rule(author="a", license="MIT", validation_status="unverified")
    violations = check_validation_consistency([rule], covered_rule_ids=[rule.id])
    assert len(violations) == 1
    assert "却声明为未验证" in violations[0].reason


def test_render_violations_reports_true_total():
    """截断处必须给出真实总数——只显示前 20 条会让「20 项违规」和「2000 项」看起来一样。"""

    violations = check_rule_metadata([_rule(id=f"test.{index}") for index in range(25)])
    text = render_violations(violations)
    assert "50 项违规" in text
    assert "另有 30 项未列出" in text
    assert render_violations([]) == "规则元数据门禁：通过（0 项违规）"
