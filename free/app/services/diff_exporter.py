"""설정 비교 결과를 감사용 워크북으로.

화면은 정책별로 무엇이 무엇으로 바뀌었는지 보여주는데, 그 값이 어떤 파일에도
남지 않았다 — 감사 증적 워크북의 Changes 시트는 건수와 정책 번호만 싣는다.
그래서 "변경분을 검토했다"는 증적은 되지만 "무엇을 검토했나"에는 답하지
못했다(백로그 B-29).

시트 구성은 화면 탭과 같다. 다만 **Changed Policies 는 필드 한 줄씩 편다** —
화면은 한 셀 안에 여러 변경을 쌓아 보여줘도 되지만, 파일은 걸러내고 정렬하고
합계를 내야 하므로 한 행이 한 사실이어야 한다.
"""
from __future__ import annotations

from io import BytesIO
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font
from openpyxl.utils import get_column_letter

from app.services.workbook_exporter import (
    HEADER_FILL, HEADER_FONT, write_text_cell,
)

# 화면 표와 같은 열·같은 순서. 사람이 두 개를 나란히 놓고 볼 것이기 때문이다.
_POLICY_COLS = [
    ("policy_type", "Policy Type"),
    ("policy_id", "Policy ID"),
    ("name", "Policy Name"),
    ("srcaddr_display", "Source"),
    ("dstaddr_display", "Destination"),
    ("service_display", "Service"),
    ("schedule", "Schedule"),
    ("action", "Action"),
    ("status", "Status"),
]

def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "-"
    if isinstance(value, dict):
        return "; ".join(f"{k}={v}" for k, v in value.items()) or "-"
    return str(value).strip() or "-"


def _humanize(key: Any) -> str:
    s = str(key or "")
    for pre in ("firewall_", "system_"):
        if s.startswith(pre):
            s = s[len(pre):]
            break
    return s.replace("_", " ").replace("-", " ").title()


def _policy_cell(policy: dict, col: str) -> Any:
    """정책 한 칸 — 화면과 같이 풀린 값(`*_display`)이 있으면 그쪽을 쓴다."""
    if col == "policy_type":
        return policy.get("_ptype") or "firewall"
    if col.endswith("_display"):
        return policy.get(col) or policy.get(col[:-len("_display")])
    return policy.get(col)


def _sheet(wb: Workbook, title: str, headers: list[str], rows: list[list[Any]],
           empty_note: str) -> None:
    ws = wb.create_sheet(title[:31])
    ws.sheet_view.showGridLines = False
    for col, head in enumerate(headers, start=1):
        c = write_text_cell(ws, 1, col, head)
        c.fill, c.font = HEADER_FILL, HEADER_FONT
    for r, row in enumerate(rows, start=2):
        for col, val in enumerate(row, start=1):
            write_text_cell(ws, r, col, _cell(val)).alignment = Alignment(
                vertical="top", wrap_text=True)
    if not rows:
        # **빈 시트는 '변경 없음'이 아니라 '못 찾았다'로도 읽힌다.** 사실을
        # 적어 둔다 — 이 문서가 혼자 돌아다닐 것이기 때문이다.
        write_text_cell(ws, 2, 1, empty_note).font = Font(italic=True,
                                                          color="6B7280")
    ws.freeze_panes = "A2"
    for col in range(1, len(headers) + 1):
        width = max([len(str(headers[col - 1]))]
                    + [min(len(_cell(row[col - 1])), 60)
                       for row in rows if col <= len(row)] or [0])
        ws.column_dimensions[get_column_letter(col)].width = min(max(width + 3, 12), 62)


def _add_summary(wb: Workbook, result: dict, meta: dict) -> None:
    ws = wb.create_sheet("Summary", 0)
    ws.sheet_view.showGridLines = False
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 78
    head = Font(bold=True, size=11)

    def kv(r, key, val):
        write_text_cell(ws, r, 1, key).font = Font(bold=True)
        write_text_cell(ws, r, 2, "" if val is None else str(val))
        return r + 1

    r = 1
    ws.cell(row=r, column=1,
            value="APO Configuration Comparison").font = Font(bold=True, size=14)
    r += 1
    branding = meta.get("branding") or {}
    if branding.get("company"):
        line = f"Prepared by {branding['company']}"
        if branding.get("prepared_for"):
            line += f" for {branding['prepared_for']}"
        write_text_cell(ws, r, 1, line).font = Font(bold=True, size=11)
        r += 1
    r += 1

    ws.cell(row=r, column=1, value="Document").font = head
    r += 1
    r = kv(r, "Generated", meta.get("generated_at"))
    r = kv(r, "Tool version", meta.get("apo_version"))
    r += 1

    # **무엇과 무엇을 비교했는가.** 파일명은 바뀌므로 해시를 함께 적는다.
    src = result.get("sources") or {}
    hosts = result.get("hostnames") or {}
    ws.cell(row=r, column=1, value="What was compared").font = head
    r += 1
    for label, key in (("Baseline (before)", "baseline"), ("Target (after)", "target")):
        s = src.get(key) or {}
        r = kv(r, label, s.get("filename") or "(not recorded)")
        r = kv(r, "  SHA-256", s.get("sha256") or "")
        r = kv(r, "  Hostname in file", hosts.get(key) or "(none recorded)")
    r += 1

    # **같은 방화벽인지 확인됐는지가 이 문서의 전제다.** 화면은 경고를 띄우는데
    # 파일이 조용하면, 다른 고객사 설정끼리 비교한 '변경 0건'이 깨끗한
    # 정기검토 결론으로 실린다(라운드 28 실측). 화면과 같은 말을 싣는다.
    ws.cell(row=r, column=1, value="Same device?").font = head
    r += 1
    if result.get("mixed_devices"):
        c = write_text_cell(
            ws, r, 2,
            "WARNING — these snapshots are from different firewalls ("
            + ", ".join(result["mixed_devices"])
            + "). Differences between them are not one device's change history.")
        c.font = Font(bold=True, color="9C1F1F")
        write_text_cell(ws, r, 1, "Verdict").font = Font(bold=True)
        r += 1
    else:
        u = result.get("same_name_unverified") or {}
        reason = u.get("reason")
        text = ("Neither backup records a hostname, so APO cannot confirm they "
                "are the same firewall."
                if reason == "no_hostname" else
                f"Only one backup records a hostname ({u.get('hostname') or ''}), "
                "so APO cannot confirm they are the same firewall."
                if reason == "one_hostname" else
                f"Both backups report the hostname {u.get('hostname') or ''}. "
                "A hostname is not unique, so this alone does not prove they "
                "are one firewall."
                if reason == "same_name" else
                "Not determined.")
        write_text_cell(ws, r, 1, "Verdict").font = Font(bold=True)
        write_text_cell(ws, r, 2, text).alignment = Alignment(wrap_text=True)
        r += 1
    r += 1

    s = result.get("summary") or {}
    ws.cell(row=r, column=1, value="Changes found").font = head
    r += 1
    for key, label in (("added_policies", "Policies added"),
                       ("removed_policies", "Policies removed"),
                       ("changed_policies", "Policies changed"),
                       ("added_objects", "Objects added"),
                       ("removed_objects", "Objects removed"),
                       ("changed_objects", "Objects redefined"),
                       ("other_changes", "Other configuration sections changed")):
        r = kv(r, label, s.get(key, 0))
    # 바뀐 정책 수와 바뀐 설정 항목 수는 다르다 — 정책 하나에서 여러 필드가
    # 바뀔 수 있고, 시트는 필드 단위로 펼쳐진다. 두 숫자가 안 맞아 보이는
    # 이유를 여기 적어 둔다.
    field_rows = sum(len(item.get("changes") or [])
                     for item in result.get("changed_policies") or [])
    r = kv(r, "Individual settings changed", field_rows)
    r += 1
    write_text_cell(
        ws, r, 1,
        "The Changed Policies sheet has one row per changed setting, so it has "
        f"{field_rows} row(s) for {s.get('changed_policies', 0)} policy(ies)."
    ).font = Font(italic=True, color="6B7280")


def build_diff_workbook(result: dict, meta: dict | None = None) -> bytes:
    meta = meta or {}
    wb = Workbook()
    wb.remove(wb.active)
    _add_summary(wb, result, meta)

    # 한 행이 한 사실 — 정책 하나에서 세 필드가 바뀌면 세 행이다.
    changed_rows = []
    for item in result.get("changed_policies") or []:
        after = item.get("after") or {}
        before = item.get("before") or {}
        pid = item.get("policy_id") or after.get("policy_id") or before.get("policy_id")
        name = item.get("name") or after.get("name") or before.get("name") or ""
        ptype = item.get("policy_type") or after.get("_ptype") or "firewall"
        # `changes` 는 서버가 화면과 공유하는 목록이다. 여기서 다시 계산하면
        # 파일과 화면이 다른 말을 하게 된다.
        for ch in item.get("changes") or []:
            changed_rows.append([ptype, pid, name, ch.get("label"),
                                 ch.get("before"), ch.get("after")])
    _sheet(wb, "Changed Policies",
           ["Policy Type", "Policy ID", "Policy Name", "Setting",
            "Before", "After"],
           changed_rows,
           # **'못 찾았다'와 '없다'를 구별해 적는다.** 이 시트는 필드 단위
           # 변경만 싣는데, 예전 문구는 정책 자체가 안 바뀌었다고 단언했다.
           "No policy setting was changed between these two backups. "
           "(Policy numbers, UUIDs and usage counters are not treated as "
           "changes.)")

    for key, title, note in (
            ("added_policies", "Added Policies",
             "No policy was added between these two backups."),
            ("removed_policies", "Removed Policies",
             "No policy was removed between these two backups.")):
        rows = [[_policy_cell(p, col) for col, _ in _POLICY_COLS]
                for p in (result.get(key) or [])]
        _sheet(wb, title, [label for _, label in _POLICY_COLS], rows, note)

    # 요약 문자열은 **서버가 만들어 보낸 것**을 쓴다 — 여기서 다시 만들면
    # 화면과 다른 값을 적게 된다(라운드 45: 같은 인터페이스를 파일은 별칭으로,
    # 화면은 멤버 포트로 적었다).
    obj_rows = []
    for key, verb in (("added_objects", "Added"), ("removed_objects", "Removed")):
        for o in result.get(key) or []:
            obj_rows.append([verb, _humanize(o.get("section")), o.get("name"),
                             "-", o.get("summary") or "-"])
    for o in result.get("changed_objects") or []:
        # 한 행이 한 사실 — 객체 하나에서 두 필드가 바뀌면 두 행이다.
        for ch in o.get("changes") or []:
            obj_rows.append(["Changed", _humanize(o.get("section")), o.get("name"),
                             f"{ch.get('label')}: {ch.get('before')}",
                             f"{ch.get('label')}: {ch.get('after')}"])
    _sheet(wb, "Object Changes",
           ["Change", "Configuration Area", "Object Name", "Before", "After"],
           obj_rows,
           "No address, service, or interface object was added, removed or "
           "redefined.")

    other_rows = []
    for sec in result.get("other_changes") or []:
        for verb, field in (("Added", "added"), ("Removed", "removed"),
                            ("Changed", "changed")):
            for name in sec.get(field) or []:
                other_rows.append([_humanize(sec.get("section")), verb, name])
    _sheet(wb, "Other Changes",
           ["Configuration Area", "Change", "Entry"], other_rows,
           "No other configuration section changed.")

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()
