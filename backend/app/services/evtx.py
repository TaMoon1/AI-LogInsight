"""Windows EVTX（本机事件日志）解析：把二进制事件日志映射到统一记录结构。

只做解析与字段映射，不做风险判断；风险判断统一交给 detector 中的 Windows / RDP 规则。
"""

from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime
from xml.etree import ElementTree

try:  # 依赖缺失时只影响 EVTX 解析，不影响其它日志类型
    from Evtx.Evtx import Evtx
except ImportError:  # pragma: no cover - 由调用方给出明确提示
    Evtx = None  # type: ignore[assignment]

EVTX_MAGIC = b"ElfFile\x00"
AUTH_EVENT_IDS = {"4624": "success", "4625": "failure"}
RDP_LOGON_TYPES = {"7", "10"}
# 终端应急响应优先保留完整证据。认证事件与 Sysmon/其他事件分开限额，
# 避免大量认证失败挤占进程、文件、注册表和 DNS 记录。
AUTH_RECORD_LIMIT = 10000
OTHER_RECORD_LIMIT = 10000

# Sysmon 等非认证事件的 EventData → 统一记录字段（右侧为原始 Data 名称）。
# 认证事件只需要账户与来源地址；进程、命令行、落地文件、外联目标这些行为字段
# 只有映射进来，非认证类规则才有判据。
EVENT_DATA_FIELDS: tuple[tuple[str, str], ...] = (
    ("process_image", "Image"),
    ("command_line", "CommandLine"),
    ("parent_image", "ParentImage"),
    ("process_id", "ProcessId"),
    ("parent_process_id", "ParentProcessId"),
    ("target_filename", "TargetFilename"),
    ("registry_key", "TargetObject"),
    ("query_name", "QueryName"),
    ("query_results", "QueryResults"),
    ("destination_ip", "DestinationIp"),
    ("destination_port", "DestinationPort"),
    ("protocol", "Protocol"),
    ("hashes", "Hashes"),
)

# 未转义的裸 `&`（未构成合法实体引用），例如 Sysmon 命令行里的 `... & exit`
BARE_AMPERSAND = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")


class EvtxUnavailableError(RuntimeError):
    """缺少 EVTX 解析依赖。"""


def is_evtx(content: bytes) -> bool:
    return content[:8] == EVTX_MAGIC


def _parse_xml_with_reason(
    xml: str,
) -> tuple[ElementTree.Element | None, str | None]:
    """解析单条事件 XML；遇到未转义的裸 `&` 时转义后重试一次。

    命令行里的 `&` 不是合法 XML，直接丢弃会丢掉最关键的行为证据，
    因此先整体转义为 `&amp;` 再解析。
    """

    try:
        return ElementTree.fromstring(xml), None
    except ElementTree.ParseError as exc:
        repaired = BARE_AMPERSAND.sub("&amp;", xml)
        if repaired == xml:
            return None, f"XML 解析失败：{exc}"
        try:
            return ElementTree.fromstring(repaired), "已自动修复未转义的裸 &"
        except ElementTree.ParseError as repaired_exc:
            return None, f"XML 解析失败：{repaired_exc}"


def _parse_xml(xml: str) -> ElementTree.Element | None:
    return _parse_xml_with_reason(xml)[0]


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped in {"-", "N/A"}:
        return None
    return stripped


def _system_fields(root: ElementTree.Element) -> dict[str, str]:
    """按标准 EVTX `<System>` 结构取事件头字段。

    这些是每条事件都有的标准元素（Provider / EventID / Channel / Level / Task /
    Opcode / Keywords / EventRecordID / TimeCreated / Computer）。缺了 Channel
    就分不清同一条 EventID 来自哪个通道，规则也没法按通道区分。
    """

    system = next(
        (child for child in root if _localname(child.tag) == "System"), None
    )
    source = system if system is not None else root
    values: dict[str, str] = {}
    for element in source.iter():
        tag = _localname(element.tag)
        if tag == "EventID":
            values.setdefault("event_id", (element.text or "").strip())
        elif tag == "TimeCreated":
            values.setdefault("time_created", element.get("SystemTime") or "")
        elif tag == "Provider":
            values.setdefault("provider", element.get("Name") or "")
        elif tag == "Computer":
            values.setdefault("computer", (element.text or "").strip())
        elif tag == "Channel":
            values.setdefault("channel", (element.text or "").strip())
        elif tag == "Level":
            values.setdefault("level", (element.text or "").strip())
        elif tag == "Task":
            values.setdefault("task", (element.text or "").strip())
        elif tag == "Opcode":
            values.setdefault("opcode", (element.text or "").strip())
        elif tag == "Keywords":
            values.setdefault("keywords", (element.text or "").strip())
        elif tag == "EventRecordID":
            values.setdefault("event_record_id", (element.text or "").strip())
    return values


def _event_data(root: ElementTree.Element) -> dict[str, str]:
    """按标准 EVTX `<EventData>` 结构取出全部 `<Data Name="…">`。

    字段名**原样沿用日志里的标准名称**（`Image`、`OriginalFileName`、`Details`…）：
    Sigma 的 Windows 规则用的就是这套名字，改名会让两边对不上。
    没有 `Name` 属性的 `<Data>` 合并到 `Data` 键下（Sigma 也用 `Data` 引用它们）。
    """

    data: dict[str, str] = {}
    unnamed: list[str] = []
    for element in root.iter():
        if _localname(element.tag) != "Data":
            continue
        text = element.text or ""
        name = element.get("Name")
        if name:
            data.setdefault(name, text)
        elif text.strip():
            unnamed.append(text.strip())
    if unnamed:
        data["Data"] = " | ".join(unnamed)
    return data


def _parse_timestamp(value: str) -> tuple[str | None, str | None]:
    """返回（展示用时间, ISO 时间）。"""

    if not value:
        return None, None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return value.strip(), None
    display = parsed.strftime("%Y-%m-%d %H:%M:%S")
    return display, parsed.isoformat()


def event_to_record(xml: str) -> tuple[dict[str, str | None], bool] | None:
    """把单条事件 XML 映射为统一记录，返回（记录, 是否认证事件）。

    记录包含两部分：

    ① **语义别名**（`source_ip` / `username` / `process_image` …）：全流程通用的判据字段；
    ② **标准事件数据**：`<System>` 事件头 + `<EventData>` 里每个 `<Data Name="…">`，
       字段名原样沿用日志里的标准名称。Sigma 的 Windows 规则用的就是这套名字
       （`OriginalFileName` / `Details` / `ParentCommandLine` …），改名两边就对不上了。
    """

    root = _parse_xml(xml)
    if root is None:
        return None

    system = _system_fields(root)
    event_id = system.get("event_id", "")
    if not event_id:
        return None
    system_time = system.get("time_created", "")
    computer = system.get("computer", "")
    data = _event_data(root)
    display_time, iso_time = _parse_timestamp(system_time)
    result = AUTH_EVENT_IDS.get(event_id)
    logon_type = _clean(data.get("LogonType"))
    username = (
        _clean(data.get("TargetUserName"))
        or _clean(data.get("SubjectUserName"))
        or _clean(data.get("User"))
    )
    source_ip = _clean(data.get("IpAddress")) or _clean(data.get("WorkstationName"))

    # 标准事件数据：只保留有值的，字段名不改写
    standard: dict[str, str] = {}
    for name, value in data.items():
        cleaned = _clean(value)
        if cleaned is not None:
            standard[name] = cleaned
    data_parts = [f"{name}: {value}" for name, value in standard.items()]
    # 标准事件头：`<System>` 下这几个元素每条事件都有。`EventID` 与 `Computer` 已由
    # `status` / `target_asset` 承担，这里只补通道、提供者与等级类的元信息。
    for key in (
        "channel",
        "provider",
        "level",
        "task",
        "opcode",
        "keywords",
        "event_record_id",
    ):
        if system.get(key):
            standard.setdefault(key, system[key])

    header = [f"Event ID: {event_id}", f"Date: {display_time or system_time}"]
    if system.get("channel"):
        header.append(f"Channel: {system['channel']}")
    if system.get("provider"):
        header.append(f"Provider: {system['provider']}")
    if computer:
        header.append(f"Computer: {computer}")

    if result:
        action = "rdp_logon" if logon_type in RDP_LOGON_TYPES else "logon"
        summary_parts = header + [
            f"Account Name: {username or '-'}",
            f"Logon Type: {logon_type or '-'}",
            f"Source Network Address: {source_ip or '-'}",
        ]
        return (
            {
                **standard,
                "timestamp": display_time or system_time,
                "timestamp_iso": iso_time,
                "source_ip": source_ip,
                "destination_ip": None,
                "username": username,
                "action": action,
                "result": result,
                "status": event_id,
                "url": None,
                "event_id": event_id,
                "target_asset": computer or None,
                "raw": " | ".join(summary_parts + data_parts),
            },
            True,
        )

    details = header
    if username:
        details.append(f"User: {username}")
    extra = {
        field: _clean(data.get(source_name)) for field, source_name in EVENT_DATA_FIELDS
    }
    return (
        {
            **standard,
            "timestamp": display_time or system_time,
            "timestamp_iso": iso_time,
            "source_ip": source_ip,
            "username": username,
            "action": "event",
            "result": None,
            "status": event_id,
            "url": None,
            "event_id": event_id,
            "target_asset": computer or None,
            "raw": " | ".join(details + data_parts),
            **extra,
        },
        False,
    )


def parse_evtx_records(content: bytes) -> tuple[list[dict[str, str | None]], int, int]:
    """兼容旧调用方：返回记录、总事件数和未纳入总数。"""

    records, total, parse_errors, retention_drops = parse_evtx_records_detailed(content)
    return records, total, parse_errors + retention_drops


def parse_evtx_records_detailed(
    content: bytes,
    error_details: list[dict[str, str | int | None]] | None = None,
) -> tuple[list[dict[str, str | None]], int, int, int]:
    """解析 EVTX 二进制内容，返回（记录列表, 事件总数, 未纳入检测的事件数）。

    认证事件（4624 / 4625）与其他终端事件默认各保留最多 10000 条用于明细取证；
    返回值同时区分单条解析失败和超过保留上限的事件，便于对外如实说明覆盖范围。
    """

    if Evtx is None:
        raise EvtxUnavailableError("未安装 python-evtx，无法解析 EVTX 二进制日志")

    auth_records: list[dict[str, str | None]] = []
    other_records: list[dict[str, str | None]] = []
    total = 0
    parse_errors = 0
    retention_drops = 0
    tmp_path: str | None = None
    try:
        # python-evtx 的 Evtx 需要真实文件路径（内部用 mmap 需要 fileno），
        # 因此把上传的字节落成临时文件再解析。
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as handle:
            handle.write(content)
            tmp_path = handle.name
        with Evtx(tmp_path) as log:
            for record in log.records():
                total += 1
                try:
                    xml = record.xml()
                except Exception as exc:  # noqa: BLE001 - 单条损坏不应中断整个文件
                    parse_errors += 1
                    if error_details is not None and len(error_details) < 50:
                        error_details.append(
                            {
                                "line_number": total,
                                "reason": f"无法读取事件 XML：{exc}",
                                "raw_preview": "",
                            }
                        )
                    continue
                mapped = event_to_record(xml)
                if mapped is None:
                    parse_errors += 1
                    if error_details is not None and len(error_details) < 50:
                        _, reason = _parse_xml_with_reason(xml)
                        error_details.append(
                            {
                                "line_number": total,
                                "reason": reason or "XML 事件缺少 EventID 或无法映射",
                                "raw_preview": " ".join(xml.split())[:240],
                            }
                        )
                    continue
                mapped_record, is_auth = mapped
                if is_auth:
                    if len(auth_records) < AUTH_RECORD_LIMIT:
                        auth_records.append(mapped_record)
                    else:
                        retention_drops += 1
                elif len(other_records) < OTHER_RECORD_LIMIT:
                    other_records.append(mapped_record)
                else:
                    retention_drops += 1
    finally:
        if tmp_path is not None:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    return auth_records + other_records, total, parse_errors, retention_drops
