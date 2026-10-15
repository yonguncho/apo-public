"""설정 마이그레이션 변경내역 워크북.

**왜 텍스트가 아니라 엑셀인가.** 3단계 Build 가 끝나면 `migrated_*.conf` 와
`migration_notes_*.txt` 두 개가 떨어진다. 그 `.txt` 가 승인 결재에 올라가는
문서인데, 탭으로 구분된 평문이라 정렬도 필터도 안 되고 이 제품의 다른 모든
산출물(워크북·변경비교·조치·증적)과 혼자 형식이 달랐다. 감사자는 이 표를
등급이나 구역으로 걸러 보고, 표본을 뽑아 장비와 대사한다 — 그러려면 시트여야
한다(2026-09-15 Jayden 지시: "3단계에서 보여주는 표와 같이 한눈에").

**이 파일이 존재하는 진짜 이유는 따로 있다.** 화면 3단계 표는
`as_is_display || as_is` 를 쓰는데 다운로드 `.txt` 는 원시 `as_is` 를 썼다.
그 두 값은 다르다 —

    WHERE  edit "208.97.24.208/32_MingleProxy"
    AS-IS  208.97.24.208/32        ← 원시값은 이름의 '조각'
    TO-BE  12.1.1.208/32           ← 실제 결과는 12.1.1.208/32_MingleProxy

    AS-IS  10.20.40.6 255.255.255.255
    TO-BE  11.11.40.6              ← 마스크가 지워지는 것처럼 읽힌다

`server.py` 의 `_row_json` 주석이 2026-09-08 실사용 보고를 적어 두었다:
**"승인자가 이 표를 캡처해 결재에 올리면 존재하지 않는 이름을 승인하는 셈이다."**
화면은 그때 고쳤고 다운로드 파일은 안 고쳤다. 결재에 올라가는 건 화면 캡처가
아니라 이 파일이다. 그래서 여기서는 **표가 쓰는 표시 필드를 쓴다** — 원시값을
쓰면 깨지도록 계약 테스트를 걸어 두었다(`test_migration_export.py`).

시트 구성은 NSPM 관례를 따른다(조사 2026-09-15). Palo Alto Expedition 이
마이그레이션 결과 엑셀을 "offline reviewing" 과 "기록 보관" 목적으로 권하고,
Cisco 마이그레이션 툴은 원본 config 와 해시를 산출물에 동봉한다. 감사 규정
(PCI-DSS 6.5.1 / ISO 27001 A.8.32 / ISMS-P 2.9.1)이 공통으로 요구하는 여섯 항목
중 APO 가 **사실로 채울 수 있는 것은 '변경 내용(전/후)' 과 '시각' 둘뿐**이다.
사유·보안영향·승인자·롤백 판단은 도구가 알 수 없으므로 **빈칸으로 제공한다** —
아는 척하지 않는 것이 이 제품의 규칙이고, ISO 8.32 도 그렇게 하라고 말한다.
"""
from __future__ import annotations

from io import BytesIO
from typing import Any, Iterable, Mapping, Sequence

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from app.services.workbook_exporter import is_formula_like, write_text_cell

# 화면 3단계 표와 같은 순서다. 여기를 바꾸면 화면도 함께 바꿔야 한다 —
# 같은 것을 두 군데서 다르게 보여주면 그게 이 파일이 고치려는 결함이다.
CHANGE_HEADERS = ("Line", "Where", "AS-IS", "TO-BE", "Action", "Why", "Warnings")

_HEAD_FILL = PatternFill("solid", fgColor="1F3A2E")
_HEAD_FONT = Font(bold=True, color="FFFFFF")
_NOTE_FONT = Font(italic=True, color="666666")
_BLANK_FILL = PatternFill("solid", fgColor="FFF7E0")   # 사람이 채울 칸


def _row_display(row: Mapping[str, Any]) -> tuple:
    """행 하나를 화면과 **같은 값**으로 편다.

    `as_is_display`/`to_be_display` 는 이름 행·마스크 보존 행에서만 채워지고
    나머지는 None 이다. 화면과 똑같이 `display or 원시값` 으로 고른다.
    """
    to_be = row.get("to_be")
    to_be_display = row.get("to_be_display")
    # to_be 가 None 인 행(변경 없음)은 화면도 빈칸으로 둔다.
    shown_to_be = "" if to_be is None and to_be_display is None else (
        to_be_display if to_be_display is not None else to_be)

    reason = row.get("reason") or ""
    arg = row.get("reason_arg")
    why = f"{reason} ({arg})" if arg else reason

    return (
        row.get("line_no"),
        row.get("location") or "",
        row.get("as_is_display") or row.get("as_is") or "",
        shown_to_be,
        row.get("action") or "",
        why,
        " ".join(row.get("warnings") or ()),
    )


def _as_values(value: Any) -> list[str]:
    """되돌리기 대상을 문자열 목록으로 편다.

    `reverse_mapping()` 은 옛 값이 하나면 문자열, 여럿이면 모음을 준다. 셀에
    그대로 넣으면 openpyxl 이 "Cannot convert {} to Excel" 로 죽는다 — 파일이
    아예 안 나오는 것보다 **모호함을 적어 주는 쪽**이 낫다. 여기서 빈 값을
    조용히 버리지 않는 이유도 같다: 되돌릴 대상이 비었다는 사실 자체가 정보다.
    """
    if value is None:
        return []
    if isinstance(value, dict):
        return [str(k) for k in sorted(map(str, value))]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(v) for v in sorted(map(str, value))]
    return [str(value)]


def build_changes_csv(rows: Sequence[Mapping[str, Any]]) -> bytes:
    """Changes 시트를 CSV 로. **ITSM·CMDB 로 import 하거나 대사할 때 쓴다.**

    xlsx 를 대체하지 않는다 — 감사 제출은 절이 넷이라 워크북이어야 하고,
    이건 표 한 장을 기계가 읽게 하는 용도다(Tufin·FireMon·Cisco 도 고정본과
    CSV 를 함께 낸다).

    **한글이 깨지면 안 된다.** BOM 없는 UTF-8 CSV 를 한국 Excel 이 열면
    CP949 로 읽어 정책 이름이 통째로 깨진다. 이 레포는 그것을 한 번 겪고
    `export_csv` 에서 BOM 접두로 못박았다 — 같은 방식을 쓴다.
    """
    import csv
    import io

    def _safe(value: Any) -> str:
        """CSV 에는 셀 타입이 없다 — 수식 중화는 아포스트로피로만 가능하다."""
        s = "" if value is None else str(value)
        return "'" + s if is_formula_like(s) else s

    out = io.StringIO()
    # Excel 은 CRLF 를 기대한다. `csv` 의 기본 `\r\n` 을 그대로 쓰되
    # `newline=""` 대신 StringIO 라 이중 개행이 안 생긴다.
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(CHANGE_HEADERS)
    for row in rows:
        # xlsx 와 **같은 함수**로 편다 — 두 산출물이 다른 값을 적으면
        # 그게 이 파일이 고치려던 결함이다.
        w.writerow([_safe(v) for v in _row_display(row)])
    return ("﻿" + out.getvalue()).encode("utf-8")


def _head(ws, headers: Sequence[str], row: int = 1) -> None:
    for i, h in enumerate(headers, start=1):
        c = ws.cell(row=row, column=i, value=h)
        c.fill, c.font = _HEAD_FILL, _HEAD_FONT
        c.alignment = Alignment(vertical="center")


def _autosize(ws, max_width: int = 52) -> None:
    for col in ws.columns:
        longest = max((len(str(c.value)) for c in col if c.value is not None),
                      default=0)
        ws.column_dimensions[col[0].column_letter].width = min(
            max(longest + 3, 10), max_width)


def _kv_sheet(ws, pairs: Iterable[tuple], start: int = 1) -> int:
    r = start
    for label, value in pairs:
        ws.cell(row=r, column=1, value=label).font = Font(bold=True)
        write_text_cell(ws, r, 2, value)
        r += 1
    return r


def build_migration_workbook(
    *,
    kind: str,
    rows: Sequence[Mapping[str, Any]],
    summary: Mapping[str, Any] | None = None,
    verification: Mapping[str, Any] | None = None,
    mapping: Mapping[str, Any] | None = None,
    reverse_mapping: Mapping[str, Any] | None = None,
    retired: Sequence[str] | None = None,
    renamed: Sequence[Mapping[str, Any]] | None = None,
    rows_truncated: bool = False,
    total_rows: int | None = None,
    source_name: str = "",
    source_sha256: str = "",
    device_label: str = "",
    #: 장비 이관에서 **어느 장비로** 옮기는가(대상 백업의 헤더). IP 개번에는
    #: 대상 장비라는 것이 없어 기본값은 빈 문자열이고, 그때는 줄을 안 만든다 —
    #: 없는 칸을 빈 채로 두면 "대상을 모른다"로 읽힌다.
    target_label: str = "",
    #: `reverse_mapping` 이 무엇의 짝인가. IP 개번은 주소지만 장비 이관은
    #: **인터페이스 이름**이다 — 롤백 문서가 "Addresses" 라고 적으면 되돌릴
    #: 대상을 틀리게 말하는 셈이다. 기본값은 기존 동작 그대로.
    undo_label: str = "Addresses (new → old)",
    generated_at: str = "",
    post_apply_check: str = "",
) -> bytes:
    """변경내역 워크북 바이트를 만든다.

    `rows` 는 서버가 계획에서 만든 `_row_json` 결과다. **브라우저가 들고 있던
    표를 돌려받아 찍지 않는다** — 그러면 파일이 APO 의 판단을 증명하지 못한다
    (`/api/config/diff/export` 가 같은 이유로 입력에서 다시 계산한다).
    """
    summary = summary or {}
    verification = verification or {}
    wb = Workbook()
    wb.remove(wb.active)

    # ── 1) Summary — 무엇을 근거로 만든 파일인지, 그리고 사람이 채울 칸 ────
    ws = wb.create_sheet("Summary")
    shown = len(rows)
    total = total_rows if total_rows is not None else shown
    r = _kv_sheet(ws, [
        ("Migration type", kind),
        ("Generated at", generated_at),
        ("Device", device_label),
        # 대상이 있는 이관(장비 교체)에서만 나온다. 위 `target_label` 주석 참조.
        *([("Moving to", target_label)] if target_label else []),
        ("Source configuration", source_name),
        # 롤백은 "원본을 다시 올리기" 다. 그 원본이 무엇이었는지 해시로 못박는다.
        ("Source SHA-256", source_sha256),
        ("Rows in this report", f"{shown} of {total}"
                                if rows_truncated else str(shown)),
    ])
    if rows_truncated:
        c = ws.cell(row=r, column=1,
                    value=f"Only the first {shown} of {total} rows are listed.")
        c.font = _NOTE_FONT
        r += 1
    for label, value in (("Changed lines", summary.get("changed_lines")),
                         ("Total lines", summary.get("total_lines")),
                         ("Rows in plan", summary.get("rows"))):
        if value is not None:
            ws.cell(row=r, column=1, value=label).font = Font(bold=True)
            ws.cell(row=r, column=2, value=value)
            r += 1
    if post_apply_check:
        r += 1
        ws.cell(row=r, column=1, value="Run on the device after restoring").font = Font(bold=True)
        write_text_cell(ws, r, 2, post_apply_check)
        r += 1

    # **아는 척하지 않는다.** 아래 네 가지는 도구가 알 수 없다. 규정
    # (PCI-DSS 6.5.1 / ISO 27001 A.8.32 / ISMS-P 2.9.1)이 변경 기록에 요구하는
    # 항목이므로 칸만 만들어 두고 고객이 채운다.
    r += 1
    ws.cell(row=r, column=1, value="To be completed by the requester / approver").font = Font(bold=True)
    r += 1
    for label in ("Reason for the change", "Security impact",
                  "Approved by (name, date)", "Roll-back decision criteria"):
        ws.cell(row=r, column=1, value=label).font = Font(bold=True)
        ws.cell(row=r, column=2).fill = _BLANK_FILL
        r += 1
    ws.column_dimensions["A"].width = 34
    ws.column_dimensions["B"].width = 72

    # ── 2) Changes — 화면 3단계 표 그대로 ────────────────────────────────
    ws = wb.create_sheet("Changes")
    _head(ws, CHANGE_HEADERS)
    for i, row in enumerate(rows, start=2):
        for j, value in enumerate(_row_display(row), start=1):
            # config 에서 온 문자열이 그대로 셀에 들어간다. `=cmd|...` 로 시작하는
            # 객체명이 실제로 있으므로 수식 중화는 선택이 아니다(v68).
            write_text_cell(ws, i, j, value)
    ws.freeze_panes = "A2"
    if rows:
        ws.auto_filter.ref = ws.dimensions   # 감사자는 구역·조치로 걸러 본다
    _autosize(ws)

    # ── 3) Mapping — 무엇을 무엇으로 바꾸라고 했는가(입력) ────────────────
    if mapping:
        ws = wb.create_sheet("Mapping")
        _head(ws, ("From (old)", "To (new)"))
        for i, (old, new) in enumerate(sorted(mapping.items()), start=2):
            write_text_cell(ws, i, 1, old)
            write_text_cell(ws, i, 2, new)
        ws.freeze_panes = "A2"
        _autosize(ws)

    # ── 4) Undo — 되돌리려면 무엇을 무엇으로 돌려야 하는가 ────────────────
    if reverse_mapping or renamed or retired:
        ws = wb.create_sheet("Undo")
        row_at = 1
        if reverse_mapping:
            ws.cell(row=row_at, column=1, value=undo_label).font = Font(bold=True)
            row_at += 1
            _head(ws, ("New value", "Original value"), row=row_at)
            row_at += 1
            for new, old in sorted(reverse_mapping.items()):
                write_text_cell(ws, row_at, 1, new)
                # 한 새 값이 여러 옛 값에서 왔으면 되돌리기가 모호하다 — 감춘 채
                # 하나만 적으면 복구가 조용히 틀어진다. 전부 적고 표시한다.
                olds = _as_values(old)
                write_text_cell(ws, row_at, 2, " | ".join(olds))
                if len(olds) > 1:
                    write_text_cell(ws, row_at, 3, "ambiguous")
                row_at += 1
            row_at += 1
        if retired:
            # 새 값이 없는 주소다 — 되돌릴 짝이 아니라 **없어지는 것**이다.
            # 짝 목록에 섞어 놓으면 "이건 어디로 돌아가나"를 답할 수 없다.
            ws.cell(row=row_at, column=1,
                    value="Retired (no new value — decommissioned)").font = Font(bold=True)
            row_at += 1
            for ip in retired:
                write_text_cell(ws, row_at, 1, ip)
                row_at += 1
            row_at += 1
        if renamed:
            ws.cell(row=row_at, column=1, value="Object names (new → old)").font = Font(bold=True)
            row_at += 1
            _head(ws, ("New name", "Original name"), row=row_at)
            row_at += 1
            for item in renamed:
                write_text_cell(ws, row_at, 1, item.get("new", ""))
                write_text_cell(ws, row_at, 2, item.get("old", ""))
                row_at += 1
        _autosize(ws)

    # ── 5) Self-check — APO 가 자기 산출물을 다시 읽어 본 결과 ────────────
    ws = wb.create_sheet("Self-check")
    labels = {
        "old_values_remaining": "Old values still in the target range",
        "unexpected_old_values": "Unexpected old values",
        "broken_references": "Broken object references",
        "duplicate_names": "Object names defined more than once",
        "extra_definitions": "Extra definitions",
    }
    pairs = [(labels.get(k, k), v) for k, v in verification.items()
             if not isinstance(v, (list, dict))]
    row_at = _kv_sheet(ws, pairs) if pairs else 1
    # 목록형(실제로 무엇이 걸렸는지)은 값만 세는 것보다 훨씬 쓸모 있다.
    for key, value in verification.items():
        if isinstance(value, list) and value:
            row_at += 1
            ws.cell(row=row_at, column=1,
                    value=labels.get(key, key)).font = Font(bold=True)
            row_at += 1
            for item in value:
                write_text_cell(ws, row_at, 1, item if isinstance(item, str) else str(item))
                row_at += 1
    ws.column_dimensions["A"].width = 46
    ws.column_dimensions["B"].width = 18

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()
