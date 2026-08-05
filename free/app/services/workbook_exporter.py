from __future__ import annotations

from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

HEADER_FILL = PatternFill('solid', fgColor='0F172A')
HEADER_FONT = Font(color='FFFFFF', bold=True)
THIN_GRAY = Side(style='thin', color='D9E2EC')
FILTER_FILL = PatternFill('solid', fgColor='F8FAFC')


def build_workbook(path: str | Path, sheets: dict[str, Any]) -> Path:
    path = Path(path)
    wb = Workbook()
    wb.remove(wb.active)

    ordered = [
        'firewall_policy',
        'firewall_proxy_policy',
        'firewall_address',
        'firewall_addrgrp',
        'firewall_proxy_address',
        'firewall_proxy_addrgrp',
        'firewall_service_custom',
        'firewall_service_group',
        'system_interface',
        'parse_warnings',
    ]

    for key in ordered:
        sheet_data = sheets.get(key)
        if not sheet_data:
            continue
        _add_sheet(wb, sheet_data.get('title') or key, sheet_data.get('headers') or [], sheet_data.get('rows') or [])

    if not wb.sheetnames:
        ws = wb.create_sheet('Export')
        ws['A1'] = 'No data'

    wb.save(path)
    return path


def _add_sheet(wb: Workbook, title: str, headers: list[str], rows: list[list[Any]]) -> None:
    safe_title = title[:31] if title else 'Sheet'
    ws = wb.create_sheet(safe_title)
    ws.freeze_panes = 'A2'
    ws.sheet_view.showGridLines = False

    for col_idx, header in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        cell.border = Border(bottom=THIN_GRAY)

    for row_idx, row in enumerate(rows, start=2):
        for col_idx, value in enumerate(row, start=1):
            cell = write_text_cell(ws, row_idx, col_idx, _stringify(value))
            cell.alignment = Alignment(vertical='top', wrap_text=True)

    if headers and rows:
        end_col = get_column_letter(len(headers))
        end_row = len(rows) + 1
        ref = f'A1:{end_col}{end_row}'
        table = Table(displayName=_table_name_from_title(safe_title), ref=ref)
        table.tableStyleInfo = TableStyleInfo(
            name='TableStyleMedium2',
            showFirstColumn=False,
            showLastColumn=False,
            showRowStripes=True,
            showColumnStripes=False,
        )
        ws.add_table(table)

    for i, header in enumerate(headers, start=1):
        max_len = max([len(str(header))] + [len(str(r[i - 1] if i - 1 < len(r) else '')) for r in rows[:500]])
        ws.column_dimensions[get_column_letter(i)].width = min(max(max_len + 2, 12), 40)

    ws.row_dimensions[1].height = 24


def _table_name_from_title(title: str) -> str:
    base = ''.join(ch for ch in title.title() if ch.isalnum())
    if not base:
        base = 'Sheet'
    return f'Tbl{base[:20]}'


def _stringify(value: Any) -> Any:
    if isinstance(value, (list, tuple, set)):
        return " | ".join(str(v) for v in value)
    if isinstance(value, dict):
        return str(value)
    return value


# 스프레드시트가 수식으로 해석하는 선두 문자.
# 리포트에 들어가는 값(정책명·주석·주소 객체명 등)은 전부 분석 대상 config에서
# 온 것이라 신뢰할 수 없다. 예: 정책명이 "=cmd|'/C calc'!A1" 이면 openpyxl이
# 이를 실제 수식 셀로 저장하고, 분석가가 파일을 열 때 DDE가 실행된다.
FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def is_formula_like(value: Any) -> bool:
    """수식으로 해석될 수 있는 값인지.

    선두 문자만 보고 전부 막으면 오탐이 크다. 실제로 이 리포트에는
    last_used="-" 같은 '데이터 없음' 표시가 1500건 넘게 들어가는데, 그것까지
    중화하면 리포트가 지저분해지고 값이 왜곡된다. 단독 기호와 순수 숫자는
    스프레드시트가 수식으로 실행할 수 없으므로 그대로 둔다.
    """
    if not isinstance(value, str) or not value.startswith(FORMULA_TRIGGERS):
        return False
    if len(value) == 1:          # "-", "@" 같은 단독 기호
        return False
    try:
        float(value)             # "-5", "+3.2" 같은 순수 숫자
        return False
    except ValueError:
        return True


def write_text_cell(ws, row: int, column: int, value: Any):
    """셀에 값을 쓰되, 수식으로 해석될 값은 문자열로 강제한다.

    아포스트로피를 덧붙이는 흔한 방식 대신 data_type을 문자열로 고정한다.
    화면에 보이는 값이 원본 그대로 유지돼야 리포트가 왜곡되지 않기 때문이다.
    (저장·재로드 후에도 data_type='s'가 유지되는 것을 확인했다.)
    """
    cell = ws.cell(row=row, column=column, value=value)
    if is_formula_like(value):
        cell.data_type = "s"
    return cell


from io import BytesIO

SEVERITY_FILLS = {
    0: PatternFill("solid", fgColor="F0EEE7"),
    1: PatternFill("solid", fgColor="FFCCCC"),
    2: PatternFill("solid", fgColor="D3D1C7"),
    3: PatternFill("solid", fgColor="FFE0B2"),
    4: PatternFill("solid", fgColor="B5D4F4"),
    5: PatternFill("solid", fgColor="FFF9C4"),
    6: PatternFill("solid", fgColor="C0DD97"),
    7: PatternFill("solid", fgColor="9FE1CB"),
}

SEVERITY_COLS = [
    ("urgency",             "Severity"),
    ("risk_level",          "Risk Level"),
    # 등급(위험도)과 조치(무엇을 할 것인가)는 다른 축이다. 등급만으로 정렬하면
    # 성격이 다른 작업이 섞이므로 조치 유형을 별도 컬럼으로 낸다.
    ("action_label",        "Action"),
    ("recommended_action",  "Recommended Action"),
    ("reason",              "Reason"),
    ("traffic_type",        "Traffic Type"),
    ("tags",                "Tags"),
    ("policy_id",           "Policy ID"),
    ("name",                "Policy Name"),
    ("srcaddr_display",     "Source Address"),
    ("dstaddr_display",     "Destination Address"),
    ("service_display",     "Service"),
    ("action",              "Action"),
    ("status",              "Status"),
    ("schedule",            "Schedule"),
    ("hit_count",           "Hit Count"),
    ("last_used",           "Last Used"),
]


def build_severity_workbook(result: dict) -> bytes:
    """result: {"firewall": [...], "proxy": [...]} -> xlsx bytes"""
    wb = Workbook()
    wb.remove(wb.active)

    all_policies = result.get("firewall", []) + result.get("proxy", [])

    sheet_map = [
        ("Severity_All",    all_policies),
        ("Firewall_Policy", result.get("firewall", [])),
        ("Proxy_Policy",    result.get("proxy", [])),
    ]

    for sheet_name, policies in sheet_map:
        ws = wb.create_sheet(sheet_name)
        for col_idx, (field, label) in enumerate(SEVERITY_COLS, 1):
            cell = ws.cell(row=1, column=col_idx, value=label)
            cell.fill = HEADER_FILL
            cell.font = HEADER_FONT
            cell.alignment = Alignment(horizontal='center', vertical='center')
        for row_idx, p in enumerate(policies, 2):
            sev = p.get("urgency", 0)
            fill = SEVERITY_FILLS.get(sev, SEVERITY_FILLS[0])
            for col_idx, (field, label) in enumerate(SEVERITY_COLS, 1):
                val = p.get(field, "")
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                # Hit=0(미사용 확정)과 None(데이터 없음)은 다른 사실이다.
                # 0을 falsy로 지우면 이 구분이 엑셀에서 소멸한다(재비판 4b).
                cell = write_text_cell(
                    ws, row_idx, col_idx,
                    str(val) if (val or val == 0) and val is not False else "")
                cell.fill = fill
        for col in ws.columns:
            max_len = max((len(str(c.value or "")) for c in col), default=10)
            ws.column_dimensions[col[0].column_letter].width = min(max_len + 4, 40)
        ws.freeze_panes = "A2"

    for sheet_name, policies in sheet_map:
        ws = wb[sheet_name]
        if ws.max_row > 1:
            ws.auto_filter.ref = ws.dimensions   # 감사자는 등급·조치로 걸러 본다

    _add_notes_sheet(wb, result)
    _add_summary_sheet(wb, result)
    _add_action_plan_sheet(wb, result)
    _add_unreachable_sheet(wb, result)

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.read()


def _add_summary_sheet(wb: Workbook, result: dict) -> None:
    """보고서 첫 장 — 문서 정보 · 판정 기준 · 결과 요약.

    감사 보고서는 수치 나열 전에 세 가지를 스스로 증명해야 한다:
    무엇을(설정 파일 식별: 파일명·SHA-256·장비·버전), 어떤 기준으로(프로파일·
    임계값 — 이게 없으면 "왜 이 정책이 이 등급인가"에 답할 수 없다),
    언제·무엇이 분석했나(생성 시각·도구 버전).

    report_meta가 있을 때만 만든다 — 서버가 주입하는 데이터라서, 이 축이
    없는 입력(회귀 픽스처·구형 클라이언트)에서는 산출물이 변하지 않는다.
    """
    rm = result.get("report_meta")
    if not rm:
        return

    from app.services.severity_engine import ACTION_LABELS, SEVERITY_META

    ws = wb.create_sheet("Summary", 0)
    ws.sheet_view.showGridLines = False
    title_font = Font(bold=True, size=14)
    head_font = Font(bold=True, size=11)

    def kv(r, key, val):
        write_text_cell(ws, r, 1, key).font = Font(bold=True)
        write_text_cell(ws, r, 2, "" if val is None else str(val))
        return r + 1

    r = 1
    ws.cell(row=r, column=1, value="APO Policy Analysis Report").font = title_font
    r += 2

    ws.cell(row=r, column=1, value="Document").font = head_font
    r += 1
    r = kv(r, "Generated", rm.get("generated_at"))
    r = kv(r, "Tool version", rm.get("apo_version"))
    r = kv(r, "Device hostname", rm.get("hostname"))
    r = kv(r, "Config version", rm.get("config_version"))
    r = kv(r, "Config file", rm.get("config_filename"))
    r = kv(r, "Config SHA-256", rm.get("config_sha256"))
    r = kv(r, "Usage CSV loaded", "yes" if rm.get("csv_loaded") else
           "no — hit-count / last-used based checks were limited")
    r += 1

    ws.cell(row=r, column=1, value="Assessment criteria").font = head_font
    r += 1
    r = kv(r, "Profile", rm.get("profile"))
    r = kv(r, "User IP ranges configured", rm.get("user_range_count"))
    th = rm.get("thresholds") or {}
    _TH_LABELS = [
        ("dormancy_days",              "Dormancy period (days)"),
        ("long_dormancy_days",         "Long dormancy (days)"),
        ("use_absolute_hit_threshold", "Absolute hit-count thresholds"),
        ("su_hit_multiplier",          "Server-User hit multiplier"),
        ("ss_hit_threshold",           "Server-Server hit threshold"),
        ("ss_schedule_age_years",      "Schedule age limit (years)"),
        ("registration_fallback_year", "Registration fallback year"),
    ]
    for key, label in _TH_LABELS:
        val = th.get(key)
        if isinstance(val, bool):
            val = "on" if val else "off"
        elif val is None:
            val = "not used"
        r = kv(r, label, val)
    rules = rm.get("rules") or {}
    r = kv(r, "ICMP-only policies kept",
           "yes" if rules.get("icmp_only_is_keep") else "no")
    r += 1

    all_policies = result.get("firewall", []) + result.get("proxy", [])
    ws.cell(row=r, column=1, value="Results").font = head_font
    r += 1
    r = kv(r, "Policies analyzed",
           f"{len(all_policies)} (firewall {len(result.get('firewall', []))}, "
           f"proxy {len(result.get('proxy', []))})")
    reach = result.get("reachability") or {}
    if reach:
        r = kv(r, "Unreachable policies",
               f"{len(reach.get('unreachable') or [])} "
               f"(assessed {reach.get('checked', 0)}/{reach.get('total_enabled', 0)}, "
               f"{len(reach.get('skipped') or [])} skipped — see Unreachable sheet)")
    r += 1

    write_text_cell(ws, r, 1, "Severity").font = Font(bold=True)
    write_text_cell(ws, r, 2, "Risk Level").font = Font(bold=True)
    write_text_cell(ws, r, 3, "Policies").font = Font(bold=True)
    r += 1
    from collections import Counter
    sev_counts = Counter(p.get("urgency", 0) for p in all_policies)
    for sev in sorted(sev_counts):
        risk = SEVERITY_META.get(sev, ("Unknown",))[0]
        c1 = write_text_cell(ws, r, 1, str(sev))
        c1.fill = SEVERITY_FILLS.get(sev, SEVERITY_FILLS[0])
        write_text_cell(ws, r, 2, risk)
        write_text_cell(ws, r, 3, str(sev_counts[sev]))
        r += 1
    r += 1

    write_text_cell(ws, r, 1, "Action").font = Font(bold=True)
    write_text_cell(ws, r, 3, "Policies").font = Font(bold=True)
    r += 1
    act_counts = Counter(p.get("action_label") or "(none)" for p in all_policies)
    # 조치 축은 작업 순서가 곧 우선순위다 — 라벨 정의 순서대로 나열한다.
    ordered_labels = list(ACTION_LABELS.values())
    for label in ordered_labels + sorted(set(act_counts) - set(ordered_labels)):
        if act_counts.get(label):
            write_text_cell(ws, r, 1, label)
            write_text_cell(ws, r, 3, str(act_counts[label]))
            r += 1

    ws.column_dimensions["A"].width = 34
    ws.column_dimensions["B"].width = 66
    ws.column_dimensions["C"].width = 12


# 조치 우선순위. 리스크 제거 효과와 되돌리기 쉬운 순서를 함께 고려한 작업
# 순서다 — 비활성화는 즉시 되돌릴 수 있고, 삭제 검토는 확인이 선행돼야 한다.
_CLI_DISABLE = (
    "config firewall policy\n"
    " edit {pid}\n"
    "  set status disable\n"
    " end")
_CLI_REMOVE_SVC = (
    "config firewall policy\n"
    " edit {pid}\n"
    "  (remove flagged services from 'set service')\n"
    " end")

_ACTION_PLAN_ORDER = [
    ("Disable now",         _CLI_DISABLE),
    ("Remove service only", _CLI_REMOVE_SVC),
    ("Disable & monitor",   _CLI_DISABLE),
    ("Review candidate",    None),
    ("Needs review",        None),
    ("Register ticket",     None),
]


def _add_action_plan_sheet(wb: Workbook, result: dict) -> None:
    """실행 계획 시트 — "무엇이 문제인가"가 아니라 "무엇부터 할 것인가".

    등급·조치 데이터는 이미 다른 시트에 있지만, 사용자는 그걸 작업 목록으로
    직접 조립해야 했다. 여기서는 조치 우선순위 순으로 정렬하고 담당자·완료·
    메모 칸을 비워 둬서 시트 자체가 진행 관리 문서가 되게 한다.

    도달불가 정책은 증거가 가장 강하므로(수학적 증명) 맨 위 그룹으로 올리고,
    아래 조치 그룹에서는 중복을 뺀다. report_meta 있을 때만 생성(회귀 픽스처
    불변 — Summary와 같은 게이트).
    """
    if not result.get("report_meta"):
        return
    # 정책 종류를 행에 태깅한다 — proxy 정책의 CLI 네임스페이스는
    # "firewall proxy-policy"라서, 구분 없이 "firewall policy"를 내면
    # ID가 충돌하는 무관한 firewall 정책을 끄게 만든다(재비판 NEW-BUG,
    # 실 config에서 fw/proxy ID 충돌 44건).
    all_policies = ([{**p, "_ptype": "firewall"} for p in result.get("firewall", [])]
                    + [{**p, "_ptype": "proxy"} for p in result.get("proxy", [])])
    reach = result.get("reachability") or {}
    unreachable = reach.get("unreachable") or []
    if not all_policies and not unreachable:
        return

    ws = wb.create_sheet("Action Plan", 1)
    ws.sheet_view.showGridLines = False
    headers = ["#", "Priority group", "Policy ID", "Policy Name",
               "Why (reason)", "Suggested CLI", "Owner", "Done", "Notes"]
    for col, htxt in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=htxt)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
    r = 2
    n = 1

    # reachability는 firewall 정책만 검사한다 — ID만으로 중복 제거하면
    # 같은 번호의 proxy 정책 조치가 소리 없이 사라진다(재비판 NEW-BUG).
    unreachable_ids = {u.get("policy_id") for u in unreachable}
    for u in unreachable:
        ws.cell(row=r, column=1, value=n)   # 숫자로 저장해야 필터 정렬이 맞다
        write_text_cell(ws, r, 2, "Unreachable (provably never matches)")
        # 가장 강한 증거 그룹이 가장 밋밋하면 시각 위계가 역전된다
        ws.cell(row=r, column=2).fill = SEVERITY_FILLS[1]
        write_text_cell(ws, r, 3, str(u.get("policy_id", "")))
        write_text_cell(ws, r, 4, str(u.get("name", "")))
        write_text_cell(ws, r, 5,
                        f"Shadowed by policy {u.get('shadowed_by')} — every packet "
                        "it could match is handled above it")
        write_text_cell(ws, r, 6, _CLI_DISABLE.format(pid=u.get("policy_id", "")))
        r += 1; n += 1

    by_label: dict = {}
    for p in all_policies:
        label = p.get("action_label") or ""
        if p.get("_ptype") == "firewall" and p.get("policy_id") in unreachable_ids:
            continue
        by_label.setdefault(label, []).append(p)

    for label, cli_tpl in _ACTION_PLAN_ORDER:
        for p in by_label.get(label, []):
            ws.cell(row=r, column=1, value=n)
            write_text_cell(ws, r, 2, label)
            write_text_cell(ws, r, 3, str(p.get("policy_id", "")))
            write_text_cell(ws, r, 4, str(p.get("name", "")))
            write_text_cell(ws, r, 5, str(p.get("reason", "")))
            if cli_tpl:
                tpl = cli_tpl if p.get("_ptype") != "proxy"                       else cli_tpl.replace("config firewall policy",
                                           "config firewall proxy-policy")
                write_text_cell(ws, r, 6, tpl.format(pid=p.get("policy_id", "")))
            sev = p.get("urgency", 0)
            ws.cell(row=r, column=2).fill = SEVERITY_FILLS.get(sev, SEVERITY_FILLS[0])
            r += 1; n += 1

    # 다중행 CLI가 한 줄로 뭉개지지 않게 전 데이터 셀에 wrap (재비판 NEW-BUG)
    for row in ws.iter_rows(min_row=2, max_row=max(r - 1, 2), max_col=9):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)

    if r > 2:
        ws.auto_filter.ref = f"A1:I{r - 1}"
        r += 1
        note = ws.cell(row=r, column=1, value=(
            "Note: on multi-VDOM devices, enter the policy's VDOM first "
            "(config vdom / edit <name>) before running these commands. "
            "Review each change with the policy owner; disabling is reversible, "
            "deletion is not."))
        note.alignment = Alignment(wrap_text=True)
        ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=9)
    for col, w in (("A", 6), ("B", 26), ("C", 10), ("D", 32), ("E", 48),
                   ("F", 34), ("G", 14), ("H", 8), ("I", 24)):
        ws.column_dimensions[col].width = w
    ws.freeze_panes = "A2"


def _add_unreachable_sheet(wb: Workbook, result: dict) -> None:
    """정적 도달불가 검출 결과 시트.

    결과에 reachability 데이터가 있을 때만 만든다 — 구형 클라이언트/골든
    픽스처처럼 이 축이 없는 입력에서는 산출물이 변하지 않아야 한다.
    """
    reach = result.get("reachability") or {}
    unreachable = reach.get("unreachable") or []
    skipped = reach.get("skipped") or []
    if not unreachable and not skipped:
        return

    ws = wb.create_sheet("Unreachable")
    headers = ["Policy ID", "Policy Name", "Shadowed By (ID)",
               "Shadowed By Name", "Shadower Action", "Detail"]
    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
    r = 2
    for u in unreachable:
        for col, key in enumerate(("policy_id", "name", "shadowed_by",
                                   "shadowed_by_name", "shadowed_by_action",
                                   "detail"), 1):
            write_text_cell(ws, r, col, str(u.get(key, "")))
        r += 1

    r += 1
    write_text_cell(ws, r, 1, "Coverage")
    ws.cell(row=r, column=1).font = Font(bold=True)
    r += 1
    write_text_cell(
        ws, r, 1,
        f"Assessed {reach.get('checked', 0)} of {reach.get('total_enabled', 0)} "
        f"enabled policies. {len(skipped)} skipped (listed below).")
    r += 1
    write_text_cell(ws, r, 1, str(reach.get("note", "")))
    ws.cell(row=r, column=1).alignment = Alignment(wrap_text=True)
    r += 2

    if skipped:
        write_text_cell(ws, r, 1, "Skipped policies (cannot be proven either way)")
        ws.cell(row=r, column=1).font = Font(bold=True)
        r += 1
        for s in skipped:
            write_text_cell(ws, r, 1, str(s.get("policy_id", "")))
            write_text_cell(ws, r, 2, str(s.get("name", "")))
            write_text_cell(ws, r, 3, str(s.get("reason", "")))
            r += 1

    for col, width in (("A", 12), ("B", 34), ("C", 16), ("D", 34), ("E", 14), ("F", 70)):
        ws.column_dimensions[col].width = width


def _add_notes_sheet(wb: Workbook, result: dict) -> None:
    """리포트를 읽기 전에 알아야 할 것들을 첫 시트로 넣는다.

    판정 결과만 주고 한계를 말하지 않으면, 읽는 사람이 수치를 실제보다 확정적인
    것으로 받아들인다. 특히 Hit Count는 장비 재시작으로 초기화되므로 '낮음'이
    '미사용'을 뜻하지 않는다.
    """
    from app.services.severity_engine import KNOWN_LIMITATIONS

    ws = wb.create_sheet("Notes", 0)
    title_font = Font(bold=True, size=12)
    head_font = Font(bold=True)

    r = 1
    ws.cell(row=r, column=1, value="APO Analysis Report — Read This First").font = title_font
    r += 2

    ws.cell(row=r, column=1, value="Limitations of this report").font = head_font
    r += 1
    for item in KNOWN_LIMITATIONS:
        c = write_text_cell(ws, r, 1, f"• {item}")
        c.alignment = Alignment(vertical="top", wrap_text=True)
        r += 1
    r += 1

    inactive = result.get("inactive_rules") or []
    if inactive:
        ws.cell(row=r, column=1, value="Checks not applied in this analysis").font = head_font
        r += 1
        for item in inactive:
            c = write_text_cell(
                ws, r, 1,
                f"• {item.get('item')} — {item.get('reason')} {item.get('effect')}")
            c.alignment = Alignment(vertical="top", wrap_text=True)
            r += 1
        r += 1

    ws.cell(row=r, column=1, value="What the Action column means").font = head_font
    r += 1
    for label, desc in (
        ("Disable now",            "Disable this policy now."),
        ("Review candidate",       "Candidate for removal — confirm first. Already disabled or past its expiry date."),
        ("Disable & monitor",      "Disable first, watch for 30–90 days, then decide whether to remove."),
        ("Remove service only",    "Keep the policy; remove only the flagged service from it."),
        ("Needs review",           "Needs a closer look before deciding."),
        ("Register ticket",        "Keep the policy, but register it through your approval process."),
        ("No risk",                "Assessed and found not to be a risk (deny rules, ICMP-only, and similar)."),
        ("Not assessed (exempted)", "An exception rule stopped this policy from being assessed. This does NOT mean it is safe."),
        ("Cannot assess",          "Not enough information to judge."),
    ):
        write_text_cell(ws, r, 1, label)
        write_text_cell(ws, r, 2, desc)
        r += 1

    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 100
