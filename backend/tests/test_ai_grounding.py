"""`_check_grounding` 的反向验证：证明它真的能抓到编造。

**为什么单独写这个文件**：在这个文件出现之前，防幻觉的核心函数从未被证明能抓到任何东西——
测试里只有 `assert judgement["unsupported_claims"] == []`，那是「没抓到」的断言。
一个从未证明能报警的报警器，和没有报警器是一样的，而且更危险：
它让人以为有防护。所以这里逐类构造编造内容，验证每一类都被抓。

同时验证**不误报**：日志原文里确实出现过的值（解析器没提成结构化字段的）不算编造，
把日志事实报成幻觉，和对正确结论的误报是同一类问题。
"""

from __future__ import annotations

import pytest

from app.models import AiBehavior, StructuredVerdict
from app.services.ai import _check_grounding
from app.services.analyzer import analyze_log, assign_record_ids, collect_records
from app.services.parser import parse_log

# 一条真实日志：来源 IP 203.0.113.10，账号 admin，URL /.env。
# Referer 里还藏着一个 IP（192.168.200.51），它只在原文里、不会被提成结构化字段——
# 用来验证「原文里出现过就不算编造」。
LOG = (
    '203.0.113.10 - admin [29/Sep/2026:09:10:00 +0800] '
    '"GET /.env HTTP/1.1" 403 12 "http://192.168.200.51/" "curl/8.0"'
)


def _context():
    parsed = parse_log(LOG)
    records = assign_record_ids(collect_records(["access.log"], [parsed]))
    return analyze_log("access.log", LOG), records


def _judgement(conclusion: str = "", behaviors=None, verdict: StructuredVerdict | None = None) -> dict:
    return {
        "conclusion": conclusion,
        "behaviors": behaviors or [],
        "structured_verdict": verdict,
    }


def _behaviour(analysis: str = "", evidence=None, name: str = "行为") -> AiBehavior:
    return AiBehavior(
        type="t",
        name=name,
        confidence=0.5,
        evidence=evidence or [],
        evidence_ids=[],
        analysis=analysis,
    )


# --------------------------------------------------------------------------
# 抓编造：每一类都必须被抓到
# --------------------------------------------------------------------------


def test_fabricated_ip_in_conclusion_is_caught():
    result, records = _context()
    claims = _check_grounding(_judgement(conclusion="攻击来源为 10.9.9.9。"), result, records)
    assert any("10.9.9.9" in claim for claim in claims), claims


def test_fabricated_ip_in_behavior_analysis_is_caught():
    result, records = _context()
    judgement = _judgement(behaviors=[_behaviour(analysis="该 IP 10.9.9.9 持续扫描。")])
    claims = _check_grounding(judgement, result, records)
    assert any("10.9.9.9" in claim for claim in claims), claims


def test_fabricated_record_id_is_caught():
    """引用不存在的记录编号——AGENTS.md §16 明令禁止。"""

    result, records = _context()
    claims = _check_grounding(
        _judgement(behaviors=[_behaviour(analysis="依据 record-999 判断。")]), result, records
    )
    assert any("record-999" in claim for claim in claims), claims


def test_fabricated_account_in_verdict_is_caught():
    result, records = _context()
    verdict = StructuredVerdict(involved_account="attacker")
    claims = _check_grounding(_judgement(verdict=verdict), result, records)
    assert any("attacker" in claim for claim in claims), claims


def test_fabricated_target_asset_in_verdict_is_caught():
    result, records = _context()
    verdict = StructuredVerdict(target_asset="unknown-host")
    claims = _check_grounding(_judgement(verdict=verdict), result, records)
    assert any("unknown-host" in claim for claim in claims), claims


def test_fabricated_source_ip_in_verdict_is_caught():
    result, records = _context()
    verdict = StructuredVerdict(attack_source_ip="172.16.99.99")
    claims = _check_grounding(_judgement(verdict=verdict), result, records)
    assert any("172.16.99.99" in claim for claim in claims), claims


def test_similar_ip_is_not_swallowed_by_substring_match():
    """日志里有 192.168.200.51，结论说 192.168.200.5 —— 必须判为编造。

    这是子串匹配的经典陷阱：`"192.168.200.5" in "192.168.200.51"` 为真，
    用 `in` 做判断就会把编造的 IP 放过去。实现用正则取词再比，这里把它钉死。
    """

    result, records = _context()
    claims = _check_grounding(
        _judgement(conclusion="内网跳板 192.168.200.5 参与攻击。"), result, records
    )
    assert any("192.168.200.5" in claim for claim in claims), (
        f"192.168.200.5 不在日志中（日志里是 .51），应判为编造；实际 claims={claims}"
    )


# --------------------------------------------------------------------------
# 不误报：日志里真实存在的值必须放行
# --------------------------------------------------------------------------


def test_real_ip_is_not_reported():
    result, records = _context()
    claims = _check_grounding(
        _judgement(conclusion="来源 203.0.113.10 探测了敏感路径。"), result, records
    )
    assert claims == [], claims


def test_ip_present_only_in_raw_text_is_not_reported():
    """Referer 里的 192.168.200.51 只在日志原文中，解析器不会提成结构化字段。

    原文里确实出现过就不是编造——把日志事实报成幻觉属于对正确结论的误报。
    """

    result, records = _context()
    claims = _check_grounding(
        _judgement(conclusion="请求的 Referer 指向 192.168.200.51。"), result, records
    )
    assert claims == [], claims


def test_real_record_id_is_not_reported():
    result, records = _context()
    real_id = records[0]["record_id"]
    claims = _check_grounding(
        _judgement(behaviors=[_behaviour(analysis=f"依据 {real_id} 判断。")]), result, records
    )
    assert claims == [], claims


def test_real_account_in_verdict_is_not_reported():
    """回归：nginx combined 的 remote_user 不被解析器提取，账号校验必须回退查原文。

    `_parse_web_line` 里 `"username": None` 是**写死**的，所以 `admin`（combined
    格式的第二个字段，HTTP Basic 认证用户）不会进入 `index["accounts"]`。
    早先只有结构化字段这一条路径，于是「涉及账号 admin」被报成编造 —— 而它就在
    日志原文里。这正是文件头说的那类误报：把日志事实当成幻觉。
    """

    result, records = _context()
    verdict = StructuredVerdict(involved_account="admin")
    claims = _check_grounding(_judgement(verdict=verdict), result, records)
    assert claims == [], claims


def test_account_substring_of_real_account_is_still_reported():
    """`adm` 不能被 `admin` 吞掉——原文回退必须是词边界匹配，不是子串包含。

    和 IP 那条子串陷阱同理：若用 `in` 判断，`"adm" in "...admin..."` 为真，
    任何真账号的前缀都会被放行，回退就形同虚设。
    """

    result, records = _context()
    verdict = StructuredVerdict(involved_account="adm")
    claims = _check_grounding(_judgement(verdict=verdict), result, records)
    assert any("adm" in claim for claim in claims), claims


def test_empty_judgement_produces_no_claims():
    result, records = _context()
    assert _check_grounding(_judgement(), result, records) == []


def test_duplicate_fabrication_is_reported_once():
    """同一个编造值在多处出现，只报一次——否则噪音会淹没有效信息。"""

    result, records = _context()
    judgement = _judgement(
        conclusion="10.9.9.9 是攻击源。",
        behaviors=[_behaviour(analysis="10.9.9.9 再次出现。"), _behaviour(analysis="10.9.9.9 第三次。")],
    )
    claims = _check_grounding(judgement, result, records)
    assert sum(1 for claim in claims if "10.9.9.9" in claim) == 1, claims
