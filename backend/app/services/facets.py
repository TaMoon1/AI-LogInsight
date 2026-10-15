"""字段概览（facet）：一条记录里「哪些字段有值、取值都长什么样」。

用途：日志明细的字段侧栏——先看哪些字段可用（覆盖率），再看某个字段的取值分布，
然后一键加/排除筛选。参考 Zircolite Explore 的 FieldSidebar + FacetValues。

命名与口径：
- `coverage` = 该字段有值的记录数 / 总记录数。**低覆盖率字段要显示出来**：
  它说明「这份日志里这个字段基本没有」，而不是「这个字段没有异常」。
- `values` = 取值 Top N（按出现次数降序）。`values_total` 是去重后的取值总数，
  截断时必须给出真实总数（否则「就这几个值」会是假象）。

**刻意不收录 `raw` 与 `command_line`**：前者几乎全量覆盖且无区分度，
后者取值近乎唯一（每条命令不同），列进 facet 只会把侧栏刷屏。
"""

from __future__ import annotations

from collections import Counter

from ..models import AnalysisResult, FacetField, FacetValue, LogFacets

#: 参与统计的字段（顺序即展示顺序）
FACET_FIELDS: tuple[tuple[str, str], ...] = (
    ("source_ip", "来源 IP"),
    ("destination_ip", "目的 IP"),
    ("username", "账号"),
    ("status", "状态码"),
    ("action", "动作"),
    ("result", "结果"),
    ("url", "URL / 路径"),
    ("query_name", "DNS 查询"),
    ("process_image", "进程镜像"),
    ("parent_image", "父进程"),
    ("target_filename", "目标文件"),
    ("registry_key", "注册表路径"),
    ("service_name", "服务名"),
    ("destination_port", "目的端口"),
    ("protocol", "协议"),
    ("target_asset", "目标资产"),
    ("event_id", "事件编号"),
    ("log_type", "日志类型"),
    ("source_file", "来源文件"),
    ("timestamp", "时间"),
)

TOP_VALUES = 10


def build_facets(
    analysis_id: str,
    result: AnalysisResult,
    records: list[dict[str, str | None]] | None = None,
    top_values: int = TOP_VALUES,
) -> LogFacets:
    rows = records or []
    total = len(rows)
    fields: list[FacetField] = []
    for name, label in FACET_FIELDS:
        counts: Counter[str] = Counter()
        present = 0
        for row in rows:
            raw = row.get(name)
            if raw is None:
                continue
            value = str(raw).strip()
            if not value:
                continue
            present += 1
            counts[value] += 1
        top = counts.most_common(top_values)
        fields.append(
            FacetField(
                name=name,
                label=label,
                coverage=round(present / total, 4) if total else 0.0,
                present_records=present,
                values_total=len(counts),
                values=[FacetValue(value=value, count=count) for value, count in top],
            )
        )
    return LogFacets(
        analysis_id=analysis_id,
        total_records=total,
        fields=fields,
        note=(
            "覆盖率 = 有值记录数 / 总记录数；低覆盖率说明这份日志基本没有该字段，"
            "不代表该字段没有异常。`raw` 与 `command_line` 未列入（无区分度 / 取值近乎唯一）"
        ),
    )
