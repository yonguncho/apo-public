from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

# openpyxl이 거부하는 제어문자(탭·개행은 허용된다). 장비 설정에서 온 문자열에
# 이런 문자가 하나만 있어도 워크북 생성이 통째로 실패한다(리뷰 라운드 11).
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# ── 룰 소명(recertification) 시트: v127 에서 **출하하지 않는다** ──────────
# 2026-09-09 Jayden 결정. 이 시트는 재비판 4라운드 동안 **같은 계열 결함을
# 여섯 번** 냈다 — 전부 "확인하지 않은 것을 확인했다고 감사인에게 말한다"는
# 형태였다(티켓 미검사를 '없음'으로 / 만료를 근거로 / ipsec 을 deny 로 /
# PCI 요건번호 오기 / 이름 토큰을 담당자로 / 스케줄 '안 읽음'을 '없음'으로).
# 고칠 때마다 다음 결함이 나왔다. 근본 원인은 설계에 있다 — config 에서
# '업무 근거'를 추론하려 하는데, 도구가 실제로 증명할 수 있는 것은 그보다
# 훨씬 적다.
#
# 코드와 테스트는 남긴다. v128 에서 **증명 가능한 것만 인쇄하는 형태**로
# 다시 낸다(사실 나열 중심, 'Recertifiable/NO BASIS' 판정과 tally 재검토).
# 이 시트는 advisory 라 등급·reason·골든에 영향이 없어 빼는 것이 무위험이다.
RECERT_SHEET_ENABLED = False

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
    # openpyxl은 C0 제어문자가 든 셀 값을 거부한다(IllegalCharacterError).
    # 장비 설정에서 온 정책 이름 하나에 그런 문자가 있으면 **그 장비의 리포트가
    # 통째로 실패**하고, 예외 메시지에 정책명이 실려 배치 SUMMARY로 새어 나간다
    # (리뷰 라운드 11 실측). 값을 살균해 실패 자체를 없앤다.
    if isinstance(value, str):
        value = _CONTROL_CHARS.sub("", value)
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
    ("action_label",        "Action to Take"),
    ("recommended_action",  "Recommended Action"),
    ("reason",              "Reason"),
    ("traffic_type",        "Traffic Type"),
    ("tags",                "Tags"),
    ("policy_id",           "Policy ID"),
    ("name",                "Policy Name"),
    ("srcaddr_display",     "Source Address"),
    ("dstaddr_display",     "Destination Address"),
    ("service_display",     "Service"),
    ("action",              "Policy Action"),
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
    _add_logging_advisory_sheet(wb, result)
    if RECERT_SHEET_ENABLED:
        _add_recert_sheet(wb, result)

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
    r += 1
    if rm.get("sample"):
        # 샘플 워크북이 실제 장비 감사 결과로 오해되면, 그걸 근거로 정책을
        # 지우는 사고가 난다. 첫 줄에 못박는다.
        c = write_text_cell(ws, r, 1,
                            "SAMPLE REPORT — generated from a bundled demo "
                            "configuration (DEMO-FGT-01). This is not an audit "
                            "of any real device.")
        c.font = Font(bold=True, size=11, color="9C1F1F")
        r += 1
    branding = rm.get("branding") or {}
    if branding.get("company"):
        # MSP·컨설턴트 티어 화이트라벨. write_text_cell을 쓰는 이유:
        # 회사명도 사용자 입력이라 수식 인젝션 중화가 필요하다.
        line = f"Prepared by {branding['company']}"
        if branding.get("prepared_for"):
            line += f" for {branding['prepared_for']}"
        c = write_text_cell(ws, r, 1, line)
        c.font = Font(bold=True, size=11)
        r += 1
    r += 1

    ws.cell(row=r, column=1, value="Document").font = head_font
    r += 1
    r = kv(r, "Generated", rm.get("generated_at"))
    r = kv(r, "Tool version", rm.get("apo_version"))
    # 고객사명이 zip 파일명에만 있으면, 워크북 한 장을 떼어 보내는 순간 귀속이
    # 사라진다 — 문서 스스로 어느 고객의 것인지 말해야 한다.
    if rm.get("customer"):
        r = kv(r, "Customer", rm.get("customer"))
    r = kv(r, "Device hostname", rm.get("hostname"))
    r = kv(r, "Config version", rm.get("config_version"))
    r = kv(r, "Config file", rm.get("config_filename"))
    r = kv(r, "Config SHA-256", rm.get("config_sha256"))
    # 사용량이 한 VDOM 것이면 그 한정을 같은 줄에 적는다 — "yes" 만 적으면
    # 다른 VDOM 정책이 전부 'usage unknown' 인데 문서는 전 장비 사용량
    # 보유처럼 읽힌다(라운드 56 완성도 렌즈, 배치 SUMMARY 와 같은 규칙).
    _sv = str(rm.get("stats_vdom") or "").strip()
    r = kv(r, "Usage CSV loaded",
           (f"yes — VDOM '{_sv}' only; policies in other VDOMs are judged "
            "without usage data") if (rm.get("csv_loaded") and _sv)
           else "yes" if rm.get("csv_loaded") else
           "no — hit-count / last-used based checks were limited")
    # **장비 수집의 커버리지도 문서가 말한다**(라운드 70 R70-2, Jayden 승인).
    # 화면 경고는 수집 순간 1회성인데, 부분 절단(993/1750류)은 이후 모든
    # 판정에 지속되는 데이터 성질이다 — "loaded: yes" 뒤에 숨으면 라운드 46
    # 이 고친 화면-산출물 불일치가 재현된다.
    _cov = rm.get("collect_coverage") or {}
    for _ns in ("firewall", "proxy"):
        _c = _cov.get(_ns) or {}
        _tot = _c.get("total") or 0
        if not _tot:
            continue
        _got = _c.get("got") or 0
        _vd = str(_c.get("vdom") or "").strip()
        _lbl = f"Usage from device ({_ns})"
        _val = f"{_got} of {_tot} policies"
        if _vd:
            _val += f" in VDOM '{_vd}'"
        if _got < _tot:
            _val += " — policies without a row are judged as 'usage unknown'"
        r = kv(r, _lbl, _val)
    # 설정 파일에는 이름과 해시를 적으면서 사용량 CSV에는 'yes' 한 줄만 적었다.
    # 그러면 남의 장비 CSV를 얹은 사고를 이 문서로는 확인할 수 없다 — 미사용
    # 판정의 근거가 어느 파일이었는지가 감사에서 가장 먼저 묻는 것이다.
    seen_labels: set[str] = set()
    for i, src in enumerate(rm.get("usage_sources") or []):
        if not isinstance(src, dict):
            continue
        # 종류를 적지 않으면 FW CSV와 Proxy CSV를 문서만으로 구분할 수 없다.
        kind = str(src.get("kind") or "").strip()
        label = "Usage CSV file" if kind in ("", "unspecified") else \
            f"Usage CSV file ({kind})"
        # **종류를 안 밝힌 CSV 는 양쪽에 그대로 얹힌다** — 의도된 하위호환이다
        # (`policy_renderer._stats_for`: 구형 클라이언트·직접 API 가 조용히
        # 깨지지 않게). 문제는 그 사실이 **산출물에 없었다**는 것이다: firewall
        # 12행짜리 CSV 로 proxy 정책이 Hit=0 이 되어 Critical · Disable now 로
        # 인쇄됐다 — 한 번도 측정한 적 없는 정책이다(7라운드 F4 실측).
        # VDOM 축은 게이트와 고지가 둘 다 있는데 이 축은 없었다.
        _kind_note = ("" if kind not in ("", "unspecified")
                      else " — this file did not say whether it is firewall or "
                           "proxy usage, so it was applied to both. Policy "
                           "numbers restart at 1 for each kind, so a policy "
                           "shown as unused here may never have been measured.")
        if i and label in seen_labels:
            label = f"{label} #{i + 1}"
        seen_labels.add(label)
        detail = str(src.get("filename") or "")
        if src.get("rows") is not None:
            detail += f" — {src['rows']} row(s)"
        if src.get("imported_at"):
            detail += f", imported {src['imported_at']}"
        detail += _kind_note
        r = kv(r, label, detail)
        if src.get("sha256"):
            r = kv(r, "Usage CSV SHA-256", str(src["sha256"]))
        # **화면이 띄우는 경고가 파일에는 없었다.** "이 설정에 없는 정책 번호
        # 2/8행" 이라는 경고를 화면은 정확히 내는데, 납품 워크북은 파일명과
        # 행 수만 적어 조용했다 — 다른 장비 CSV 를 넣어도 문서가 말하지
        # 않는다(라운드 46 실측). 서버는 이 수치를 이미 들고 있었다.
        _un = src.get("unmatched")
        if _un:
            # V2(라운드 59) 후 unmatched 는 "지정 VDOM 에 없는 번호"다 — 다른
            # VDOM 에는 존재할 수 있으므로 단정 문구를 가른다(라운드 60).
            # **출처 자신의 vdom 만 본다.** rm.stats_vdom 폴백은 vdom 미기록
            # (레거시/당시 단일 VDOM) 출처에 **현재 장비 상태의 VDOM 을 소급
            # 지목**했다 — 그 파일의 unmatched 는 그 VDOM 과 대조한 적이
            # 없으므로 하지 않은 비교를 문서에 적는 것이다(라운드 62 계약
            # 렌즈 — C-1 과 같은 정직성 클래스, 라운드 61 이 도입한 폴백).
            _src_vd = str(src.get("vdom") or "").strip()
            c = write_text_cell(
                ws, r, 2,
                (f"WARNING — {_un} of {src.get('rows') or '?'} row(s) are policy "
                 f"numbers not found in VDOM '{_src_vd}' — they may belong to "
                 "another VDOM or another device; either way the usage figures "
                 "below do not cover them.") if _src_vd else
                (f"WARNING — {_un} of {src.get('rows') or '?'} row(s) are policy "
                 "numbers this configuration does not have. If that file came "
                 "from another device, the usage figures below are not this "
                 "device's."))
            c.font = Font(bold=True, color="9C1F1F")
            write_text_cell(ws, r, 1, "  Rows that did not match").font = Font(bold=True)
            r += 1
    r += 1

    ws.cell(row=r, column=1, value="Assessment criteria").font = head_font
    r += 1
    r = kv(r, "Profile", rm.get("profile"))
    # 적용 중인 이식 기준 묶음(룰 세트)의 식별자. **재현 근거는 아래 값들이다**
    # — 이 한 줄은 "어느 묶음을 적용했나"만 가리킨다(같은 해시로 다른 판정이
    # 가능하다: services·user_ranges 등은 룰 세트에 담기지 않는다). 그래서
    # 라벨에 그 한정을 적는다 — 해시만 보고 재현했다고 믿으면 안 된다.
    if rm.get("ruleset_hash"):
        r = kv(r, "Rule set applied (portable criteria only)",
               f"{rm['ruleset_hash']} — identifies the thresholds / object names "
               "/ ticket format carried by APO's rule set export. It is not a "
               "full fingerprint of this assessment; the values below are. "
               "Compare it only against a rule set exported from an APO "
               "installation using the same profile: object-name categories left "
               "empty in a rule set fall back to the receiving profile's "
               "defaults, so the same file can hash differently elsewhere.")
    # 배치 산출물은 세션의 객체 명명 규칙을 쓰지 않는다. 그 사실을 안 적으면
    # 단일 리포트와 나란히 놓았을 때 같은 기준으로 돌린 것처럼 보인다
    # (실측: 같은 장비가 Critical 3 vs 1 — 라운드 46).
    if rm.get("object_rules_note"):
        c = write_text_cell(ws, r, 2, str(rm["object_rules_note"]))
        c.font = Font(italic=True, color="9C6500")
        c.alignment = Alignment(wrap_text=True)
        write_text_cell(ws, r, 1, "Object naming rules").font = Font(bold=True)
        r += 1
    # 대역 목록의 출처가 의심스러우면 **산출물에도** 적는다. 경고가 내부용
    # 요약에만 있으면, 고객에게 가는 이 워크북은 근거 없는 트래픽 분류를
    # 확신에 찬 얼굴로 주장하게 된다(리뷰 라운드 7 명세 지적).
    # **"아래 값들이 완전한 지문" 이라 말하면서 판정을 가르는 축 하나가
    #   빠져 있었다.** 티켓 형식이 있으면 그 정책은 sev 7 *Approved*, 없으면
    #   sev 0 *Cannot assess* 다 — 임계값·대역·객체 이름을 값으로 싣는 것과
    #   같은 논리로 이것도 싣는다(7라운드 F3/S1).
    if rm.get("ticket_pattern") or rm.get("ticket_origin"):
        _origin = str(rm.get("ticket_origin") or "")
        _where = {
            "settings-prefixes": "from the prefixes set in Settings",
            "settings-regex": "from the pattern set in Settings",
            "profile": "from the profile file, not from Settings",
            "profile-unsafe": "the profile pattern was ignored (it can hang "
                              "the assessment)",
            "none": "not set - no policy was checked for a ticket number",
        }.get(_origin, _origin)
        if _origin.endswith("regex-disabled"):
            _where += (" (a pattern saved in an older version is no longer "
                       "used)")
        r = kv(r, "Ticket format",
               f"{rm.get('ticket_pattern') or '(none)'} - {_where}")
    _rng = rm.get("user_range_count")
    _rng_warn = rm.get("user_range_warning")
    r = kv(r, "User IP ranges configured",
           f"{_rng} — {_rng_warn}" if _rng_warn else _rng)
    # **개수만으로는 재현할 수 없다.** 대역은 판정 축(S-U/S-S)이라, 이 값이
    # 없으면 같은 설정으로 다시 돌려도 같은 결과가 나오는지 확인할 수 없다.
    if rm.get("user_ranges"):
        r = kv(r, "User IP ranges", ", ".join(rm["user_ranges"][:20])
               + (" …" if len(rm["user_ranges"]) > 20 else ""))
    # 객체 명명 규칙도 판정을 바꾼다 — 어떤 이름이 예외로 인정됐는지 적는다.
    for _k, _v in (rm.get("object_rules") or {}).items():
        r = kv(r, _k.replace("_objects", "").replace("_", " ").title()
               + " objects", ", ".join(str(x) for x in _v[:20]))
    th = rm.get("thresholds") or {}
    # **재현 근거는 판정을 바꾸는 값만 적는다 — 전부 적어야 한다.**
    # 두 가지가 틀려 있었다(2026-08-25, Jayden 배치 승인):
    #  · ss_schedule_age_years 를 실었다. severity_engine 은 이 값을 읽기만
    #    하고 비교하는 코드가 없다(라운드 45 에서 분기가 도달불가로 확인돼
    #    제거됨) — 판정에 쓰이지 않는 값을 '재현 근거'로 실으면, 이 파일을
    #    보는 감사자는 있지도 않은 비교를 근거로 읽는다. 화면 입력은
    #    이미 뺐고(d93b82a) 문서판만 남아 있었다.
    #  · approval_window_days 가 빠져 있었다. 위험서비스 정책을 Critical
    #    대신 검토(3)로 내리는 값인데 파일에 안 남아, 같은 config 로 같은
    #    결과가 나오는지 이 문서만으로 확인할 수 없었다.
    _TH_LABELS = [
        ("dormancy_days",              "Dormancy period (days)"),
        ("long_dormancy_days",         "Long dormancy (days)"),
        ("approval_window_days",       "Approval window (days)"),
        ("use_absolute_hit_threshold", "Absolute hit-count thresholds"),
        ("su_hit_multiplier",          "Server-User hit multiplier"),
        ("ss_hit_threshold",           "Server-Server hit threshold"),
        ("registration_fallback_year", "Registration fallback year"),
    ]
    for key, label in _TH_LABELS:
        val = th.get(key)
        if isinstance(val, bool):
            val = "on" if val else "off"
        elif val is None:
            val = "not used"
        r = kv(r, label, val)
    # **서비스 위험 목록도 판정을 가른다.** severity_engine 은 이 목록으로
    # '위험 서비스만' / '위험+일반 혼합 → Critical' 을 정하고, 배포 프로파일
    # (<customer>.yaml)이 실제로 이 값을 덮어쓴다. 임계값만 적어 두면 이 문서로는
    # 'Risky service mixed' 판정을 재현할 수 없다 — 프로파일 이름만 적혀
    # 있어 외부 파일을 열어 봐야 하는데, 그건 approval_window_days 에서
    # 이미 거부한 상태다(게이트 spec 렌즈).
    services = rm.get("services") or {}
    for _key, _label in (("risky",    "Risky services"),
                         ("auth_dns", "AD/DNS services"),
                         ("icmp",     "ICMP services")):
        _v = services.get(_key)
        if _v:
            r = kv(r, _label, ", ".join(str(x) for x in list(_v)[:30])
                   + (" …" if len(_v) > 30 else ""))
    rules = rm.get("rules") or {}
    r = kv(r, "ICMP-only policies kept",
           "yes" if rules.get("icmp_only_is_keep") else "no")
    # standby 키워드는 Hit=0 정책을 Critical 에서 '등록' 으로 완화한다 —
    # 완화의 근거가 되는 값이므로 무엇이 적용됐는지 남아야 한다.
    _sb = rules.get("standby_interface_keywords")
    if _sb:
        r = kv(r, "Standby interface keywords",
               ", ".join(str(x) for x in list(_sb)[:30]))
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
               # skipped 는 **firewall 정책의 판정 보류 수**다(서비스/FQDN
               # 환원 불가). proxy 절 뒤에 붙였더니 "proxy N건 skipped" 로
               # 읽혔다 — 실 고객 데이터: proxy 66 인데 "42 skipped"(라운드 60
               # 동적실행 렌즈 실측). firewall 절에 붙인다.
               f"(assessed {reach.get('checked', 0)}/{reach.get('total_enabled', 0)} "
               f"enabled firewall policies, {len(reach.get('skipped') or [])} "
               "skipped; proxy policies are outside this check"
               # **없는 시트를 가리키면 안 된다.** Unreachable 시트는 도달불가나
               # 건너뜀이 있을 때만 만들어지는데 안내는 무조건 붙었다
               # (라운드 47 실측: 시트 목록에 없는데 "see Unreachable sheet").
               + (" — see Unreachable sheet"
                  if (reach.get("unreachable") or reach.get("skipped")) else "")
               + ")")
    r += 1

    write_text_cell(ws, r, 1, "Severity").font = Font(bold=True)
    write_text_cell(ws, r, 2, "Risk Level").font = Font(bold=True)
    write_text_cell(ws, r, 3, "Policies").font = Font(bold=True)
    r += 1
    from collections import Counter
    sev_counts = Counter(p.get("urgency", 0) for p in all_policies)
    # **등급이 섞였다고 리포트 전체를 못 내면 안 된다.**
    # `sorted()` 에 등급 번호와 `None` 이 함께 들어가면
    # `TypeError: '<' not supported between 'NoneType' and 'int'` 로 터진다 —
    # 전부 None 이거나 전부 int 면 통과하고 **섞일 때만** 터지므로 평소에는
    # 안 보인다. 엔진은 이제 등급을 int 로만 내지만(`_override_sev`), 이 함수는
    # 보관소에서 복원한 결과나 구형 클라이언트가 준 결과도 받는다.
    # 숫자가 아닌 것은 맨 뒤로 보내고 **그대로 인쇄한다** — 조용히 0 으로
    # 바꾸면 '판정 불가'로 읽혀 사실이 아닌 요약이 된다.
    def _sev_key(v):
        return ((0, v, "") if isinstance(v, int) and not isinstance(v, bool)
                else (1, 0, str(v)))
    for sev in sorted(sev_counts, key=_sev_key):
        risk = SEVERITY_META.get(sev, ("Unknown",))[0]
        c1 = write_text_cell(ws, r, 1, str(sev))
        c1.fill = SEVERITY_FILLS.get(sev, SEVERITY_FILLS[0])
        write_text_cell(ws, r, 2, risk)
        write_text_cell(ws, r, 3, str(sev_counts[sev]))
        r += 1
    r += 1

    # **어느 축의 수인지 적는다.** 이 표는 정책마다 엔진이 권고한 것을 세고,
    # Action Plan 시트는 실제 작업 그룹을 센다 — 도달 불가로 밝혀진 정책이
    # 앞 그룹으로 옮겨 가므로 같은 라벨의 수가 다르다. 그 사실을 안 적으면
    # 한 파일 안에서 'Disable now 4' 와 'Disable now 1' 이 나란히 인쇄되고,
    # 읽는 사람은 둘 중 하나가 틀렸다고 결론 낸다(라운드 39).
    write_text_cell(ws, r, 1, "Recommended action (per policy)").font = Font(bold=True)
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

    # **파서가 버린 것을 감사 보고서가 말한다.** 잘린 백업이나 중복 번호로
    # 정책이 빠지거나 겹쳐도 유료 산출물은 아무 말도 하지 않았다(라운드 43).
    _pw = rm.get("parse_warnings") or []
    if _pw:
        r += 1
        ws.cell(row=r, column=1, value="Not read from the configuration").font = head_font
        r += 1
        # **'잘렸다' 판정은 넓게 잡는다.** 처음엔 `without 'next'` 만 셌는데,
        # 진짜 다운로드가 끊긴 두 경고("the file ends inside this section",
        # "ends with unclosed configuration block(s)")가 여기 안 잡혔다. 그
        # 결과 아래 Note 가 **재다운로드가 유일한 해결책인 경우에 그 지시를
        # 지우고** "다시 받아도 안 바뀐다"고 말했다(2026-09-10 재비판 F2).
        _dropped = sum(1 for w in _pw
                       if ("without 'next'" in str(w.get("warning", ""))
                           or "looks truncated" in str(w.get("warning", ""))
                           or "unclosed configuration block" in str(w.get("warning", ""))))
        _dupes = sum(1 for w in _pw if "more than once" in str(w.get("warning", "")))
        r = kv(r, "Lines APO could not read", len(_pw))
        if _dropped:
            r = kv(r, "Objects skipped (backup looks truncated)", _dropped)
        if _dupes:
            r = kv(r, "Numbers defined twice (later one used)", _dupes)

        # **개수만 세고 사유를 버리지 않는다.** 파서는 "This backup contains IPv6
        # policies (config firewall policy6). APO does not read that section…"
        # 처럼 정확한 문장을 이미 만들어 두는데, 예전에는 그것을 버리고 `1` 이라는
        # 숫자만 실었다. 그러면 감사인은 **무엇이 평가에서 빠졌는지 산출물로는 알
        # 수 없다** — IPv6 정책 200건이 통째로 빠져도 "읽지 못한 줄 1" 로만 보인다.
        # 화면과 API 는 이 문장을 이미 말하고 있었다(또 한 번의 화면-산출물 불일치).
        _seen: set[str] = set()
        _msgs: list[str] = []
        for _w in _pw:
            _m = re.sub(r"\s+", " ", str((_w or {}).get("warning") or "")).strip()
            if _m and _m not in _seen:
                _seen.add(_m)
                _msgs.append(_m)
        for _m in _msgs[:12]:
            c = write_text_cell(ws, r, 2, _m)
            c.alignment = Alignment(wrap_text=True, vertical="top")
            write_text_cell(ws, r, 1, "  Not read")
            r += 1
        if len(_msgs) > 12:
            r = kv(r, "  (and more)", f"{len(_msgs) - 12} further reason(s)")

        # **안 맞는 안내를 하지 않는다.** "백업을 다시 받으라" 는 잘린 백업에만
        # 맞는 말이다. IPv6·NGFW 처럼 APO 가 애초에 읽지 않는 섹션은 몇 번을 다시
        # 받아도 그대로다 — 그렇게 적으면 고객이 헛수고를 한다.
        write_text_cell(ws, r, 1, "Note")
        write_text_cell(ws, r, 2,
                        ("Those objects are not in this report. If the backup "
                         "looks truncated, download the configuration again and "
                         "re-run. Sections APO does not read (listed above) will "
                         "not change on a re-download.") if _dropped else
                        ("Those objects are not in this report. Sections APO does "
                         "not read will not change if you download the "
                         "configuration again.")).alignment = Alignment(
                            wrap_text=True, vertical="top")
        r += 1

    write_text_cell(ws, r, 1, "Note")
    write_text_cell(ws, r, 2,
                    "These are the engine's recommendations for each policy. The "
                    "Action Plan sheet groups the same policies by the work to "
                    "do, so its counts differ: a policy that is provably "
                    "unreachable moves to the unreachable group there, whatever "
                    "its own recommendation says.")
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
    ("Remove (already inert)", None),
    ("Needs review",        None),
    ("Register ticket",     None),
]
# 공개 별칭 — batch_report 등 외부 모듈이 "조치 필요"의 정의를 여기와
# 공유한다. 사설 심볼 의존은 리팩터 때 요청 시점 ImportError로 죽는다.
ACTION_PLAN_ORDER = _ACTION_PLAN_ORDER


def _vdom_of(p) -> str:
    """이 정책의 VDOM(단일 VDOM 설정이면 빈 문자열).

    **VDOM 은 정책 번호의 일부다.** 각주는 "정책의 VDOM 을 먼저 지정하라"고
    하면서 어느 VDOM 인지 어디에도 안 적어, 조치 계획에 1번이 두 줄 나와도
    root 의 ANY-ANY-PERMIT 인지 dmz 의 운영 정책인지 알 수 없었다(라운드 47
    실측). API 쓰기는 다중 VDOM 에서 막혀 있고, 수동 적용에 쓰는 문서가 바로
    이 워크북이다.
    """
    return str((p or {}).get("vdom") or "").strip()


def _cli_with_vdom(cli: str, vdom: str) -> str:
    """CLI 앞에 VDOM 진입을 붙인다 — 붙일 VDOM 이 있을 때만."""
    if not cli or not vdom:
        return cli
    return "config vdom" + chr(10) + f"edit {vdom}" + chr(10) + cli


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
    # Type 열이 없으면 firewall 1번과 proxy 1번이 같은 "1"로 나란히 실린다.
    # CLI가 비어 있는 조치(Needs review 등)에서는 구분할 단서가 아예 없다.
    headers = ["#", "Priority group", "Type", "Policy ID", "Policy Name",
               "Why (reason)", "Suggested CLI", "Owner", "Done", "Notes"]
    for col, htxt in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=htxt)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
    r = 2
    n = 1

    # reachability는 firewall 정책만 검사한다 — ID만으로 중복 제거하면
    # 같은 번호의 proxy 정책 조치가 소리 없이 사라진다(재비판 NEW-BUG).
    # **VDOM 은 정책 번호의 일부다.** FortiGate 는 정책 번호를 VDOM 마다
    # 매기므로 다중 VDOM 에서 번호 충돌은 예외가 아니라 기본이다. 키를 번호만
    # 잡으면 VDOM-B 의 살아있는 정책이, VDOM-A 에 같은 번호 도달불가가 있다는
    # 이유로 조치계획에서 소리 없이 사라진다(라운드 50 계약·동적실행 렌즈).
    unreachable_keys = {(_vdom_of(u), u.get("policy_id")) for u in unreachable}
    # 증명 등급을 조치 이름에 드러낸다. config 근거는 설정이 바뀌기 전까지
    # 영구히 참이지만, capture 근거는 DNS 캐시를 뜬 시점의 해석에 기댄다 —
    # FQDN이 다른 IP로 풀리면 그 정책은 다시 살아난다. 둘을 같은 이름으로
    # 적으면 시한부 근거가 영구 증명으로 읽힌다(재비판 3회전).
    # 강한 주장은 proof가 'config'라고 명시된 경우에만. 값이 없거나 모르는
    # 등급이면 약한 쪽으로 보낸다 — 기본값이 "설정상 확실"이면 새 등급이
    # 조용히 과대 주장으로 나간다.
    """이 계획이 스스로의 증명을 무효로 만들 수 있다.

    "정책 N은 절대 매칭되지 않는다"는 증명은 **N을 가리는 상위 정책이 켜져 있는
    동안만** 참이다. 그런데 그 상위 정책이 같은 계획의 "Disable now"에 올라
    있으면, 시키는 대로 상위를 끈 순간 아래 정책들이 되살아난다 — 그리고 계획은
    그것들을 "확인 후 삭제"하라고 적어 뒀다. 순서를 안 알려주면 장애가 난다.
    실제 샘플에서 6건 중 5건이 이 관계였다.
    """
    # 가림막(shadowed_by)은 가려진 정책과 같은 VDOM 안에 있다 — 그래서
    # 변경 집합도 (VDOM, 번호) 로 잡아야 다른 VDOM 의 같은 번호가 거짓
    # 선행관계를 만들지 않는다(라운드 50).
    # 번호가 None 인 정책(손편집 백업의 비숫자 _edit)은 키에서 제외한다.
    # 넣어 두면 (vdom, None) 키가 생겨, shadowed_by 가 None 인 도달불가 행과
    # 우연히 매칭돼 명령 있는 도달불가 정책이 '나중에 결정'으로 오분류된다
    # (라운드 52 경계값 렌즈, 라운드 50부터 상속된 결함).
    changed_keys = {(_vdom_of(p), p.get("policy_id")) for p in all_policies
                    if p.get("_ptype") == "firewall"
                    and p.get("policy_id") is not None
                    and p.get("action_label") in (
                        "Disable now", "Disable & monitor", "Remove (already inert)")}
    changed_keys |= unreachable_keys   # 도달불가끼리 서로 가리는 경우도 있다

    # **순번은 실행 순서다.** 위에서부터 하라고 번호를 매겨 놓고, 가려진
    # 정책을 먼저 끄고 그 가림막을 나중에 끄게 적어 놨다 — 인쇄된 순서대로
    # 실행하면 티켓 승인된 운영 정책이 죽는다(라운드 39 실측: 승인된
    # 사용자→웹 HTTPS, LDAP/DNS 인증, web→db MSSQL 3건). 경고 문장은
    # Why 칸에 있었지만, 순번과 Done 체크박스는 정반대를 지시했다.
    #
    # 증명이 다른 행에 기대는 정책은 **명령을 주지 않고 맨 뒤로 보낸다.**
    # 가림막을 어떻게 할지 정하기 전에는 이 정책에 대해 할 말이 없다.
    # 번호가 None 인 정책은 키에서 제외 — 같은 VDOM 에 None-id 가 둘이면
    # 마지막 승자가 (vdom, None) 을 덮어, 도달불가 행의 "본래 등급은 X" 가
    # **남의 등급**을 인쇄했다(라운드 54 경계값 렌즈 재현, 손편집 백업 한정).
    _own_verdict = {(_vdom_of(p), p.get("policy_id")): (p.get("action_label") or "")
                    for p in all_policies if p.get("_ptype") == "firewall"
                    and p.get("policy_id") is not None}
    _independent, _dependent = [], []
    for u in unreachable:
        # 가림막은 u 와 같은 VDOM 에 있으므로 그 VDOM 으로 함께 조회한다.
        # shadowed_by 가 None 이면 선행관계가 없는 것이므로 매칭하지 않는다
        # (None 키 우연 매칭 방지 — 라운드 52).
        _sh = u.get("shadowed_by")
        (_dependent if _sh is not None and (_vdom_of(u), _sh) in changed_keys
         else _independent).append(u)

    for u in sorted(_independent, key=lambda x: x.get("proof") != "config"):
        capture = u.get("proof") != "config"
        _pid = u.get("policy_id")
        ws.cell(row=r, column=1, value=n)   # 숫자로 저장해야 필터 정렬이 맞다
        write_text_cell(ws, r, 2, "Unreachable — verify before removing" if capture
                        else "Unreachable (provably never matches)")
        # 가장 강한 증거 그룹이 가장 밋밋하면 시각 위계가 역전된다
        ws.cell(row=r, column=2).fill = SEVERITY_FILLS[2 if capture else 1]
        # VDOM 을 Type 칸에 함께 적는다 — 같은 번호 두 줄을 구별할 유일한
        # 단서다(열을 새로 넣으면 뒤 열 번호가 전부 밀려 회귀 위험이 크다).
        _vd = _vdom_of(u)
        write_text_cell(ws, r, 3,
                        f"firewall ({_vd})" if _vd else "firewall")
        write_text_cell(ws, r, 4, str(_pid or ""))
        write_text_cell(ws, r, 5, str(u.get("name", "")))
        # **Findings 시트가 뭐라고 했는지 함께 적는다.** 같은 파일 안에서
        # 한 정책에 '유지'와 '비활성화'가 따로 인쇄되면 어느 쪽을 믿어야
        # 할지 알 수 없다(라운드 39: 4건).
        _ov = _own_verdict.get((_vd, _pid), "")
        write_text_cell(ws, r, 6,
                        f"Shadowed by policy {u.get('shadowed_by')} — every packet "
                        # 마침표가 없어 다음 문장과 붙어 인쇄됐다("above it On
                        # its own contents…"). 영업이 제일 먼저 보여주는 샘플
                        # 리포트에 그대로 나갔다(데모 리허설 C-2).
                        "it could match is handled above it."
                        + (f" On its own contents this policy was graded "
                           f"'{_ov}', but it is unreachable, so that grade "
                           "describes traffic that never arrives."
                           if _ov and _ov not in ("Disable now", "Disable & monitor",
                                                  "Remove (already inert)") else "")
                        + (" (not provable from the configuration alone; the "
                           "evidence can change over time, so re-check before "
                           "removing)" if capture else ""))
        # 번호를 모르는 정책(손편집 백업의 비숫자 _edit)에는 명령을 주지
        # 않는다 — `edit ` 빈 번호는 FortiOS 가 거부하거나, 최악에는 다음
        # 빈 번호로 **새 정책을 만든다**(라운드 54 경계값 렌즈).
        write_text_cell(ws, r, 7, _cli_with_vdom(
            _CLI_DISABLE.format(pid=_pid), _vd) if _pid is not None else "")
        r += 1; n += 1

    by_label: dict = {}
    for p in all_policies:
        label = p.get("action_label") or ""
        if p.get("_ptype") == "firewall" and (
                _vdom_of(p), p.get("policy_id")) in unreachable_keys:
            continue
        by_label.setdefault(label, []).append(p)

    for label, cli_tpl in _ACTION_PLAN_ORDER:
        for p in by_label.get(label, []):
            ws.cell(row=r, column=1, value=n)
            write_text_cell(ws, r, 2, label)
            _vd = _vdom_of(p)
            _ty = "proxy" if p.get("_ptype") == "proxy" else "firewall"
            write_text_cell(ws, r, 3, f"{_ty} ({_vd})" if _vd else _ty)
            # `p.get("policy_id", "")` 는 값이 None 이면 None 을 돌려준다 —
            # ID 칸에 파이썬 리터럴 'None', CLI 에 `edit None` 이 인쇄됐다
            # (라운드 54 경계값 렌즈). 번호를 모르면 칸은 비우고 명령은 주지
            # 않는다.
            _bpid = p.get("policy_id")
            write_text_cell(ws, r, 4, str(_bpid) if _bpid is not None else "")
            write_text_cell(ws, r, 5, str(p.get("name", "")))
            write_text_cell(ws, r, 6, str(p.get("reason", "")))
            if cli_tpl and _bpid is not None:
                tpl = cli_tpl if p.get("_ptype") != "proxy"                       else cli_tpl.replace("config firewall policy",
                                           "config firewall proxy-policy")
                write_text_cell(ws, r, 7, _cli_with_vdom(
                    tpl.format(pid=_bpid), _vd))
            sev = p.get("urgency", 0)
            ws.cell(row=r, column=2).fill = SEVERITY_FILLS.get(sev, SEVERITY_FILLS[0])
            r += 1; n += 1

    # **증명이 이 계획 자신에 기대는 정책은 맨 뒤에, 명령 없이.**
    # "정책 N 은 절대 매칭되지 않는다"는 증명은 N 을 가리는 정책이 켜져 있는
    # 동안만 참인데, 그 가림막이 같은 계획에 올라 있다. 가림막을 끄는 순간
    # 아래 정책들이 되살아나므로, 지금은 이 정책들에 대해 할 말이 없다 —
    # 명령을 인쇄하면 인쇄된 순서대로 실행해 승인된 정책을 죽인다(R39).
    for u in sorted(_dependent, key=lambda x: str(x.get("shadowed_by"))):
        _sh = u.get("shadowed_by")
        _pid = u.get("policy_id")
        # 형제 행(독립·라벨 행)은 VDOM 을 Type 칸에 적는데 이 가장 고위험 행만
        # "firewall" 하드코딩이라 같은 번호를 구별할 수 없었다(라운드 50 완성도
        # 렌즈). _own_verdict 도 (VDOM, 번호) 로 조회해 다른 VDOM 등급을 끌어오지
        # 않게 한다.
        _vd = _vdom_of(u)
        ws.cell(row=r, column=1, value=n)
        write_text_cell(ws, r, 2, "Decide after the changes above")
        ws.cell(row=r, column=2).fill = SEVERITY_FILLS[0]
        write_text_cell(ws, r, 3, f"firewall ({_vd})" if _vd else "firewall")
        write_text_cell(ws, r, 4, str(_pid or ""))
        write_text_cell(ws, r, 5, str(u.get("name", "")))
        write_text_cell(ws, r, 6,
                        f"Unreachable only while policy {_sh} stays enabled — and "
                        f"this plan also changes policy {_sh}. Do the rows above "
                        "first, take a fresh configuration backup, and run APO "
                        "again: this policy may be live by then."
                        + (f" On its own contents it was graded "
                           f"'{_own_verdict.get((_vd, _pid))}'."
                           if _own_verdict.get((_vd, _pid)) else ""))
        write_text_cell(ws, r, 7, "")     # 명령을 주지 않는다
        r += 1; n += 1

    # 다중행 CLI가 한 줄로 뭉개지지 않게 전 데이터 셀에 wrap (재비판 NEW-BUG)
    for row in ws.iter_rows(min_row=2, max_row=max(r - 1, 2), max_col=9):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)

    if r > 2:
        ws.auto_filter.ref = f"A1:J{r - 1}"   # Type 열 추가로 한 칸 늘었다
        r += 1
        note = ws.cell(row=r, column=1, value=(
            "Note: on multi-VDOM devices, enter the policy's VDOM first "
            "(config vdom / edit <name>) before running these commands. "
            "Review each change with the policy owner; disabling is reversible, "
            "deletion is not."))
        note.alignment = Alignment(wrap_text=True)
        ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=10)
    for col, w in (("A", 6), ("B", 26), ("C", 9), ("D", 10), ("E", 32),
                   ("F", 48), ("G", 34), ("H", 14), ("I", 8), ("J", 24)):
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
    # VDOM 열 — 같은 워크북의 Action Plan 시트는 VDOM 을 붙이는데 이 시트만
    # "정책 1은 정책 5가 가린다"를 VDOM 없이 적어, 두 시트를 대조하면 한쪽만
    # VDOM 이었다(라운드 50 완성도 렌즈). 가림막(shadowed_by)은 같은 VDOM 이라
    # VDOM 하나로 양쪽 번호를 함께 읽는다.
    headers = ["VDOM", "Policy ID", "Policy Name", "Shadowed By (ID)",
               "Shadowed By Name", "Shadower Action", "Proof", "Detail"]
    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
    r = 2
    for u in unreachable:
        for col, key in enumerate(("vdom", "policy_id", "name", "shadowed_by",
                                   "shadowed_by_name", "shadowed_by_action",
                                   "proof", "detail"), 1):
            # proof: config = 설정만으로 증명 / capture = DNS 캐시 수집 시점 기준.
            # 값이 없으면 "unverified" — 약한 쪽으로 두되, 있지도 않은 DNS 수집을
            # 주장하지도 않는다. Action Plan 시트도 같은 행을 약한 그룹에 넣는다.
            write_text_cell(ws, r, col, str(u.get(key, "") or
                                            ("unverified" if key == "proof" else "")))
        r += 1

    r += 1
    write_text_cell(ws, r, 1, "Coverage")
    ws.cell(row=r, column=1).font = Font(bold=True)
    r += 1
    write_text_cell(
        ws, r, 1,
        f"Assessed {reach.get('checked', 0)} of {reach.get('total_enabled', 0)} "
        f"enabled firewall policies (proxy policies are not examined by this "
        f"check). {len(skipped)} skipped (listed below).")
    r += 1
    write_text_cell(ws, r, 1, str(reach.get("note", "")))
    ws.cell(row=r, column=1).alignment = Alignment(wrap_text=True)
    r += 2

    if skipped:
        write_text_cell(ws, r, 1, "Skipped policies (cannot be proven either way)")
        ws.cell(row=r, column=1).font = Font(bold=True)
        r += 1
        for s in skipped:
            write_text_cell(ws, r, 1, str(s.get("vdom", "")))
            write_text_cell(ws, r, 2, str(s.get("policy_id", "")))
            write_text_cell(ws, r, 3, str(s.get("name", "")))
            write_text_cell(ws, r, 4, str(s.get("reason", "")))
            r += 1

    for col, width in (("A", 8), ("B", 12), ("C", 34), ("D", 16), ("E", 34),
                       ("F", 14), ("G", 10), ("H", 70)):
        ws.column_dimensions[col].width = width


def _add_logging_advisory_sheet(wb: Workbook, result: dict) -> None:
    """로깅 꺼진 정책 advisory 시트 — **판정이 아니라 권고다.**

    `set logtraffic disable` 인 활성 firewall 정책을 감사 신호로 싣는다. 등급·
    도달불가 판정에는 영향이 없다(reachability.detect_logging_disabled 참고).
    reachability 데이터에 이 축이 있을 때만 만든다 — 없는 입력(골든 픽스처·
    구형 클라이언트)에서는 산출물이 변하지 않는다. Unreachable 시트와 같은
    게이트.
    """
    reach = result.get("reachability") or {}
    logging_off = reach.get("logging_disabled") or []
    if not logging_off:
        return

    ws = wb.create_sheet("Logging Disabled")
    # 이 열은 accept/deny 다 — 등급 시트에서 같은 값을 "Policy Action"
    # 이라 부르기로 했으므로 여기도 맞춘다. 시트를 합쳐 피벗하면
    # 이름이 갈린 두 열이 "Action to Take" 와 뒤섞인다.
    headers = ["VDOM", "Policy ID", "Policy Name", "Policy Action", "Logging"]
    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
    r = 2
    for item in logging_off:
        write_text_cell(ws, r, 1, str(item.get("vdom", "")))
        write_text_cell(ws, r, 2, str(item.get("policy_id", "") or ""))
        write_text_cell(ws, r, 3, str(item.get("name", "")))
        write_text_cell(ws, r, 4, str(item.get("action", "")))
        write_text_cell(ws, r, 5, "disabled (set logtraffic disable)")
        r += 1

    r += 1
    note = write_text_cell(ws, r, 1, (
        "Advisory only — this does not change any reachability or severity "
        "verdict in this report. These enabled firewall policies have traffic "
        "logging turned off (set logtraffic disable), so sessions they allow or "
        "deny leave no record for a SIEM or incident review. Many audit "
        "frameworks (PCI-DSS, ISO 27001, ISMS-P) expect every permit/deny rule "
        "to be logged. Only rules that explicitly set 'disable' are listed; the "
        "FortiOS default varies by version and is not assumed. Scope: firewall "
        "policies only."))
    note.alignment = Alignment(wrap_text=True, vertical="top")
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=5)
    if r > 2:
        ws.auto_filter.ref = f"A1:E{len(logging_off) + 1}"
    for col, width in (("A", 10), ("B", 12), ("C", 40), ("D", 12), ("E", 34)):
        ws.column_dimensions[col].width = width
    ws.freeze_panes = "A2"


def _recert_today(result: dict):
    """이 리포트의 기준일. 문서가 스스로 말하는 생성일을 쓴다.

    `date.today()` 를 쓰면 같은 결과 파일을 다시 내보낼 때 스케줄 만료 판정이
    달라져, 리포트가 자기 생성 시각과 어긋난다.
    """
    from datetime import date, datetime
    raw = str(((result or {}).get("report_meta") or {}).get("generated_at") or "")
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw[:len(fmt) + 2].strip(), fmt).date()
        except ValueError:
            continue
    return date.today()


def _recert_signals(p: dict, today=None) -> dict:
    """룰 하나의 소명 근거 신호를 뽑는다.

    신호 4개 — 변경 티켓 · 업무 설명(comment) · **담당자(owner)** · 유효한
    기한부 스케줄. 전부 렌더 결과에 이미 있는 값이라 파서·판정을 건드리지 않는다.

    **'안 읽었다' 와 '없다' 를 가른다.** 티켓 형식이 설정되지 않은 배포에서는
    이름에 RITM 이 박혀 있어도 추출을 건너뛴다(`ticket_scanned=False`). 그걸
    '티켓 없음' 으로 세면 **없다고 단정하는 거짓말**이 되고, 실제로 이름에
    `RITM0099999` 가 있는 정책에 "근거 없음 — 문서화하거나 삭제하라" 를 인쇄했다
    (2026-09-09 재비판 실측). 레포는 이미 세 곳에서 이 구분을 지킨다 —
    `policy_renderer.ticket_scanned` · `severity_engine` 의 'Ticket unchecked'
    태그 · `app.js hasNoRitm()`. 여기가 네 번째다.

    **만료된 스케줄은 근거가 아니다.** 예전에는 `not is_always_schedule(...)` 만
    봐서, 2019 년에 끝난 스케줄이 소명 근거로 +1 을 받았다 — 같은 워크북의
    Severity 시트는 그 값을 'Expired Schedule' 위험 태그로 읽는다. 근거로 세는
    것은 **날짜가 있고 아직 지나지 않은** 스케줄뿐이다(`work-hours` 같은 이름만
    붙은 반복 스케줄은 기한이 없으므로 세지 않는다).
    """
    from datetime import date as _date
    from app.services.schedule_utils import get_schedule_date, is_expired_schedule
    if today is None:
        today = _date.today()

    scanned = p.get("ticket_scanned")
    scanned = True if scanned is None else bool(scanned)
    ritm = str(p.get("ritm") or "").strip()
    # comment 는 최상위 필드(policy_renderer)가 우선. 구형 payload(_raw 만 있는
    # 왕복분)도 놓치지 않게 _raw 를 폴백으로 본다.
    raw = p.get("_raw") or {}
    comment = str(p.get("comment")
                  or raw.get("comments") or raw.get("comment") or "").strip()
    # **담당자는 근거로 세지 않는다.** `requester` 는 정책명의 세 번째 밑줄
    # 토큰일 뿐이라(`policy_renderer.extract_name_metadata`), 규약을 안 따르는
    # 이름에서는 사람이 아니라 `DMZ`·`HTTP`·`SEOUL`·`all`·`jump` 가 잡힌다.
    # 이것을 근거 한 축으로 세었더니 **근거가 하나도 없는 룰 10건 전부가
    # 'Recertifiable' 로 인쇄**됐다(재비판 라운드 3 실측) — 이 시트의 존재
    # 이유를 정면으로 뒤집는 결함이었다.
    # 표시는 하되(문맥으로 쓸모가 있다) **규약을 실제로 따를 때만** 한다:
    # 문서화된 형식은 `YYMMDD_<ticket>_requester` 이므로 등록일과 티켓이 함께
    # 잡힌 이름에서만 세 번째 토큰이 담당자다.
    owner = str(p.get("requester") or "").strip()
    if not (p.get("request_date") and ritm):
        owner = ""
    sched = str(p.get("schedule") or "").strip()
    sched_date = get_schedule_date(sched)
    expired = bool(sched) and is_expired_schedule(sched, today)
    return {
        "ticket_scanned": scanned,
        "ticket": bool(ritm) if scanned else None,   # None = 확인하지 않음
        "ticket_id": ritm,
        "comment": bool(comment),
        "owner": bool(owner),
        "owner_name": owner,
        "schedule_valid": bool(sched_date) and not expired,
        "schedule_expired": expired,
    }


def _recert_score(sig: dict) -> tuple[int, int]:
    """(충족 신호 수, 확인 가능한 신호 수). 확인 못 한 축은 분모에서 뺀다.

    근거 축은 셋이다 — 변경 티켓 · 업무 설명(comment) · 유효한 기한부 스케줄.
    담당자(owner)는 **세지 않는다**(`_recert_signals` 참조: 정책명 토큰이라
    규약 밖 이름에서 사람이 아닌 값이 잡힌다). 표시만 한다.
    """
    vals = [sig["ticket"], sig["comment"], sig["schedule_valid"]]
    known = [v for v in vals if v is not None]
    return sum(1 for v in known if v), len(known)


def _needs_justification(p: dict) -> bool:
    """소명이 필요한 룰인가 — 켜져 있고 트래픽을 여는(accept) 룰만.

    트래픽을 열지 않는 룰(deny·비활성)은 PCI-DSS 4.0 **1.2.5**('허용되는
    서비스·프로토콜·포트마다 업무상 필요')의 대상이 아니다. 이들을 '근거 없음'
    으로 세면 헤드라인 수치가 부풀어 오해를 준다(실 고객 데이터: 7등급 745건).
    시트에는 전부 싣되 tally 에서만 뺀다 — 열로 구분하니 숨기는 것은 아니다.

    판별식은 `severity_engine` 과 같다(accept 가 아니면 전부 deny 취급).
    """
    action = str(p.get("action") or "").strip().lower()
    status = str(p.get("status") or "").strip().lower()
    return action == "accept" and status not in ("disabled", "disable")


def _add_recert_sheet(wb: Workbook, result: dict) -> None:
    """룰 소명(recertification) 커버리지 시트 — **판정이 아니라 커버리지다.**

    PCI-DSS 4.0 **1.2.5** 는 허용되는 서비스·프로토콜·포트마다 업무상 필요를,
    **1.2.7** 은 6개월마다의 설정 검토를 요구하고, ISMS-P 는 검토대상·검토결과
    리포트를 증적으로 요구한다(두 조항을 뭉뚱그리지 않는다 — `audit_evidence.py`
    가 1.2.7 을 '6개월 검토'로 인용하는 것과 같은 기준). APO 는 지금 comment 를
    티켓 인식용으로만 읽고 정책별 '소명 가능/불가'를 시트로 내지 않았다 —
    이 시트가 그 표다.

    등급·reason·도달불가 판정에는 영향이 없다(값을 새로 만들지 않고 렌더 결과의
    ritm·ticket_scanned·comment·requester·schedule 만 읽는다). report_meta 있을
    때만 만든다 — 골든 픽스처·구형 클라이언트처럼 이 축이 없는 입력에서는
    산출물이 변하지 않는다(Summary·Action Plan 과 같은 게이트).
    """
    if not result.get("report_meta"):
        return
    all_policies = ([{**p, "_ptype": "firewall"} for p in result.get("firewall", [])]
                    + [{**p, "_ptype": "proxy"} for p in result.get("proxy", [])])
    if not all_policies:
        return

    ws = wb.create_sheet("Rule Recertification")
    ws.sheet_view.showGridLines = False

    today = _recert_today(result)
    sigs = {id(p): _recert_signals(p, today) for p in all_policies}

    # 정합성 한 줄 — 근거가 필요한 룰(켜진 accept)만 대상으로 센다.
    # **암산을 요구하지 않는다**: 전체 = 대상 + 제외 가 한 줄에서 맞아떨어져야
    # 한다(예전에는 '대상 N' 과 '제외 M' 만 적어 전체를 독자가 더해야 했다).
    in_scope = [p for p in all_policies if _needs_justification(p)]
    with_basis = unknown = expired = 0
    for p in in_scope:
        _sig = sigs[id(p)]
        got, known = _recert_score(_sig)
        # 순서는 행 판정과 **같아야 한다** — 다르면 헤드라인과 행이 갈린다.
        if _sig["schedule_expired"]:
            expired += 1
        elif got:
            with_basis += 1
        elif known < 3:      # 확인 못 한 축이 있어 '없다' 고 단정할 수 없다
            unknown += 1
    no_basis = len(in_scope) - with_basis - unknown - expired
    excluded = len(all_policies) - len(in_scope)

    r = 1
    ws.cell(row=r, column=1, value="Rule Recertification Coverage").font = Font(bold=True, size=13)
    r += 1
    _line = (f"Total {len(all_policies)} policies = {len(in_scope)} needing a "
             f"business justification (enabled 'accept' rules) + {excluded} not "
             f"assessed (deny, disabled, or another non-accept action).  "
             f"Of the {len(in_scope)}: "
             f"{with_basis} with a documented basis · {no_basis} with none")
    if expired:
        _line += f" · {expired} expired (remove or renew)"
    if unknown:
        _line += f" · {unknown} undetermined (ticket format not configured)"
    c = write_text_cell(ws, r, 1, _line + ".")
    c.font = Font(bold=True)
    r += 2

    headers = ["VDOM", "Policy ID", "Policy Name", "Type", "Action", "Status",
               "Ticket ID", "Comment", "Owner (from name)", "Schedule", "Schedule status",
               "Justification", "Recertification", "Current Grade (reference)"]
    hdr_row = r
    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=hdr_row, column=col, value=h)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
    r += 1

    for p in all_policies:
        sig = sigs[id(p)]
        scope = _needs_justification(p)
        got, known = _recert_score(sig)
        _act = str(p.get("action") or "").strip()
        _st = str(p.get("status") or "").strip().lower()
        if not scope:
            # **하지 않은 관찰을 단정하지 않는다.** 예전에는 무엇이든
            # "N/A (deny / disabled)" 라고 적어, 트래픽을 실제로 여는
            # `action ipsec` 과 `set action` 줄이 없는 정책까지 deny 라고
            # 인쇄했다. severity_engine 은 같은 자리에서 실제 action 을 밝힌다.
            if _st in ("disabled", "disable"):
                verdict = "N/A (disabled in the configuration)"
            else:
                # `ipsec` 처럼 accept 가 아닌 action 은 **트래픽을 열지 않는다고
                # 단정하지 않는다** — 엔진도 `Action = Deny ('ipsec')` 로 원문을
                # 따옴표에 넣어 보존한다. 여기서 판단할 수 있는 사실은
                # "accept 가 아니라 이 시트의 대상이 아니다" 까지다.
                verdict = (f"N/A (not an 'accept' rule — action '{_act}')"
                           if _act else "N/A (no 'set action' — treated as deny)")
        elif sig["schedule_expired"]:
            # **만료는 다른 근거보다 앞선다.** 스케줄 축에만 만료 게이트를 걸고
            # 티켓 축에 안 걸었더니, 만료 룰에 티켓이 하나 있으면 같은 행이
            # `expired` 와 `Recertifiable` 을 나란히 인쇄했다(재비판 라운드 2).
            # 이 시트의 각주가 "만료는 근거가 아니라 정리 대상"이라고 약속하고,
            # 엔진도 `has_ritm and not is_expired` 일 때만 유효 티켓으로 본다
            # (severity_engine: Valid ITS). 셋을 같은 규칙으로 맞춘다.
            # 신호 열은 사실 그대로 둔다 — 티켓이 있었다는 것은 지우지 않는다.
            verdict = "Expired — remove or renew before recertifying"
        elif got:
            verdict = "Recertifiable"
        elif known < 3:
            verdict = "Undetermined — configure a ticket format to check"
        else:
            verdict = "NO BASIS — document or remove"

        if sig["ticket"] is None:
            _ticket_cell = "not checked"
        else:
            _ticket_cell = sig["ticket_id"] or "—"
        _sched = str(p.get("schedule") or "")
        if sig["schedule_expired"]:
            _sched_state = "expired"
        elif sig["schedule_valid"]:
            _sched_state = "time-bounded"
        elif not _sched or _sched.strip().lower() == "always":
            _sched_state = "always"
        else:
            # **하지 않은 관찰을 단정하지 않는다.** 이름 붙은 스케줄 객체
            # (`config firewall schedule onetime`)는 기간을 가질 수 있는데
            # 여기서는 그 객체를 읽지 않는다 — `schedule_utils` 는 이름이
            # 리터럴 `YYMMDD` 일 때만 날짜로 본다. "기한 없음" 이라고 적으면
            # 2019 년에 끝난 스케줄을 '기한 없음' 으로 인쇄한다(라운드 3 실측).
            # 파이프라인은 그 정보를 갖고 있으나 이 함수까지 오지 않는다(backlog).
            _sched_state = "named (end date not read)"

        _grade = p.get("urgency")
        _risk = p.get("risk_level") or ""
        row_vals = [
            _vdom_of(p),
            str(p.get("policy_id") if p.get("policy_id") is not None else ""),
            str(p.get("name") or ""),
            "proxy" if p.get("_ptype") == "proxy" else "firewall",
            _act,
            str(p.get("status") or ""),
            _ticket_cell,
            "Yes" if sig["comment"] else "No",
            sig["owner_name"] or "—",
            _sched,
            _sched_state,
            f"{got}/{known}" if known else "—",
            verdict,
            f"{_grade} — {_risk}" if _grade is not None else "",
        ]
        for col, val in enumerate(row_vals, 1):
            cell = write_text_cell(ws, r, col, val)
            cell.alignment = Alignment(vertical="top", wrap_text=True)
        # 조치가 필요한 행만 붉게 — 근거 0, 그리고 만료(정리 대상).
        # '확인 못 함' 은 붉게 칠하지 않는다(단정이 아니므로).
        if scope and (sig["schedule_expired"] or (not got and known == 3)):
            ws.cell(row=r, column=13).fill = SEVERITY_FILLS[1]
        r += 1

    if r > hdr_row + 1:
        end_col = get_column_letter(len(headers))
        ws.auto_filter.ref = f"A{hdr_row}:{end_col}{r - 1}"

    r += 1
    note = write_text_cell(ws, r, 1, (
        "Advisory only — this sheet does not change any severity or reachability "
        "verdict in this report. It reports, per rule, whether a business "
        "justification can be traced from the configuration, to support periodic "
        "rule recertification. PCI-DSS 4.0 req 1.2.5 expects every allowed "
        "service, protocol and port to have an identified, approved business "
        "need; req 1.2.7 expects the configuration to be reviewed at least once "
        "every six months; ISMS-P expects a review-result record. Three signals "
        "are counted: a change-ticket ID (read from the policy name, and from "
        "the device comment when comment scanning is on), a comment, and a "
        "schedule whose end date is written into its name and has not passed. "
        "The 'Owner (from name)' column is shown for context but is NOT counted: "
        "it is the third underscore-separated token of the policy name, which is "
        "only a person when the name follows the YYMMDD_<ticket>_requester "
        "convention, so it is left blank otherwise. Named schedule objects "
        "(config firewall schedule) are not resolved here, so such a rule is "
        "reported as 'named (end date not read)' rather than as having none. "
        "An expired schedule is NOT counted as a basis — such a rule is "
        "reported as 'Expired' and marked for cleanup no matter what else it "
        "has, which is what the Severity sheet calls it too (the engine treats "
        "a ticket as valid only while the schedule still is). "
        "If no ticket format is configured, ticket IDs are not read at all: "
        "those rules are reported as 'Undetermined', never as having no basis. "
        "Rules that are not 'accept' (deny, or another action) and rules that "
        "are disabled are listed but excluded from the tally, since req 1.2.5 "
        "applies to what is allowed. This is a "
        "coverage view, not an approval — confirm each rule with its owner."))
    note.alignment = Alignment(wrap_text=True, vertical="top")
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=len(headers))

    for col, width in (("A", 10), ("B", 10), ("C", 34), ("D", 9), ("E", 9),
                       ("F", 10), ("G", 16), ("H", 10), ("I", 12), ("J", 20),
                       ("K", 12), ("L", 12), ("M", 26), ("N", 20)):
        ws.column_dimensions[col].width = width
    ws.freeze_panes = f"A{hdr_row + 1}"


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

    ws.cell(row=r, column=1, value="What the Action to Take column means").font = head_font
    r += 1
    for label, desc in (
        ("Disable now",            "Disable this policy now."),
        ("Remove (already inert)", "Already disabled or past its expiry date — the configuration itself "
                                   "prevents any traffic from matching, so removal is a cleanup step."),
        ("Disable & monitor",      "Disable first, watch for 30–90 days, then decide whether to remove."),
        ("Remove service only",    "Keep the policy; remove only the flagged service from it."),
        ("Needs review",           "Needs a closer look before deciding."),
        ("Register ticket",        "Keep the policy, but register it through your approval process."),
        ("No risk",                "Assessed and found not to be a risk (deny rules, ICMP-only, and similar)."),
        ("Approved (ticket verified)", "An approval ticket is recorded in the policy name and its schedule is still valid."),
        ("Not assessed (exempted)", "An exception rule stopped this policy from being assessed. This does NOT mean it is safe."),
        ("Cannot assess",          "Not enough information to judge."),
    ):
        write_text_cell(ws, r, 1, label)
        write_text_cell(ws, r, 2, desc)
        r += 1
    r += 1

    # **판정 기준이 산출물에 없으면 감사인은 확인할 수 없다.** 임계값 숫자만
    # 싣고 등급 결정 규칙은 화면에만 뒀더니, 파일만 받은 사람은 '왜 5가 아니라
    # 6인가'를 되짚을 근거가 없었다(라운드 43 지적).
    from app.services.severity_engine import SEVERITY_META
    ws.cell(row=r, column=1, value="What each severity means").font = head_font
    r += 1
    write_text_cell(ws, r, 1, "Severity").font = head_font
    write_text_cell(ws, r, 2, "Risk level / recommended action").font = head_font
    r += 1
    for sev in sorted(SEVERITY_META):
        risk, rec = SEVERITY_META[sev][0], SEVERITY_META[sev][1]
        write_text_cell(ws, r, 1, str(sev))
        write_text_cell(ws, r, 2, f"{risk} — {rec}")
        r += 1
    r += 1
    c = write_text_cell(
        ws, r, 1,
        "Two exceptions sit above these rules. A policy that only opens AD/DNS "
        "services is graded 6 even with a wide source or destination, because "
        "domain controllers legitimately serve everyone. A policy that "
        "references one of your admin objects is graded 6 or 3 rather than "
        "removed, because that access is needed. Neither applies when source, "
        "destination and service are all Any/All. The object names behind those "
        "exceptions are listed on the Summary sheet.")
    c.alignment = Alignment(vertical="top", wrap_text=True)
    r += 1

    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 100
