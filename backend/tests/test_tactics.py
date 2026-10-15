"""ATT&CK 标签映射测试。

这层映射的价值：503 条 Sigma 导入规则不靠手写映射，只靠 `attack.*` 标签。
映射失效时它们会全部落到「其他」——**等于白导入**，所以要钉住。
"""

from __future__ import annotations

from app.services.analytics import _PHASE_ORDER
from app.services.tactics import tactic_from_tags, techniques_from_tags


def test_tactic_from_sigma_tags():
    assert tactic_from_tags(["attack.discovery"]) == "发现"
    assert tactic_from_tags(["attack.execution", "attack.T1059"]) == "执行"
    assert tactic_from_tags(["attack.credential-access"]) == "凭据访问"


def test_stealth_maps_into_defense_evasion():
    """ATT&CK 19.x 把 stealth 从 defense-evasion 拆出，本项目统一写作「防御规避」，
    否则同一件事会分成两格。"""

    assert tactic_from_tags(["attack.stealth"]) == "防御规避"
    assert tactic_from_tags(["attack.defense-evasion"]) == "防御规避"


def test_unknown_or_missing_tags_return_none():
    assert tactic_from_tags([]) is None
    assert tactic_from_tags(None) is None
    assert tactic_from_tags(["attack.not-a-tactic"]) is None
    assert tactic_from_tags(["attack.T1059"]) is None  # 技术编号不是战术


def test_techniques_from_tags_keeps_subtechnique_case():
    assert techniques_from_tags(["attack.t1059.001"]) == ["T1059.001"]
    assert techniques_from_tags(["attack.T1218", "attack.t1105"]) == ["T1218", "T1105"]
    assert techniques_from_tags(["attack.t1218", "attack.T1218"]) == ["T1218"]


def test_every_mapped_tactic_has_a_phase_slot():
    """映射出的战术必须都在阶段顺序表里，否则它会以 99 排到最后，看起来像「没有战术」。"""

    from app.services.tactics import TACTIC_LABELS

    for tactic in set(TACTIC_LABELS.values()):
        assert tactic in _PHASE_ORDER, tactic


def test_tactic_aliases_normalize_to_official_names():
    """真实事故回归：内置 ATT&CK 标尺写「凭证访问」、战术阶段表写「凭据访问」，
    一字之差让 T1110 等 8 项技术永远进不了按阶段排序的矩阵。"""

    from app.services.tactics import normalize_tactic

    assert normalize_tactic("凭证访问") == "凭据访问"
    assert normalize_tactic("凭据访问") == "凭据访问"  # 正式名保持原样
    assert normalize_tactic("   ") == "其他"
    assert normalize_tactic(None) == "其他"
