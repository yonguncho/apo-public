# -*- coding: utf-8 -*-
"""
verification.py
===============
판정 정확도 검증 하네스 (Phase 2).

APO의 판정이 실제 장비 상태와 맞는지 사람이 표본 대조할 수 있게 돕는다.
세 부분으로 나뉜다.

  1) stratified_sample()   등급별 층화 표본 추출
  2) build_worksheet()     대조용 체크리스트 (확인 항목 + FortiGate CLI 명령어)
  3) compute_precision()   대조 결과를 넣으면 등급별 정확도 리포트

**이 모듈은 장비에 접속하지 않는다.** 명령어를 적어 줄 뿐이고, 실행과 대조는
사람이 한다. 자동 대조는 오히려 검증의 의미를 없앤다 — APO가 스스로 채점하면
APO의 해석 오류를 그대로 정답으로 삼게 된다.

기존 판정 코드는 건드리지 않는다. 이 모듈은 판정 결과를 읽기만 한다.
"""
from __future__ import annotations

import csv
import io
import random
import re as _re
from collections import Counter, defaultdict
from typing import Any, Iterable

# 워크시트 컬럼. 앞쪽은 APO가 채우고, 뒤 3개는 사람이 채운다.
WORKSHEET_COLUMNS = [
    ("policy_id",     "정책 ID"),
    # **VDOM 은 정책 번호의 일부다.** 이 칸이 없던 동안, root 1번과 guest
    # 1번이 표본에 같은 행처럼 나란히 실렸고 채점은 둘 중 하나를 버리면서
    # '내가 발급하지 않은 행'이라고 인쇄했다(라운드 40 실측).
    ("vdom",          "VDOM (수정하지 마세요)"),
    ("policy_type",   "종류"),
    ("name",          "정책 이름"),
    ("urgency",       "APO 등급"),
    ("risk_level",    "위험도"),
    # 등급과 조치는 다른 축이다(Phase 3). 검증자가 "등급이 맞나"와
    # "조치가 맞나"를 따로 판단할 수 있어야 하므로 조치 유형도 낸다.
    ("action_label",  "조치 유형"),
    ("reason",        "APO 판정 근거"),
    ("recommended",   "권고 조치"),
    ("check_items",   "확인할 것"),
    ("cli_commands",  "실행할 명령어"),
    ("actual",        "실제 확인 결과 (사람이 입력)"),
    ("verdict",       "판정 일치? 일치/불일치/보류 (사람이 입력)"),
    ("note",          "비고 (사람이 입력)"),
    # **행마다 APO 가 발급한 값을 넣는다.** 표지 한 줄은 엑셀에서 지우기 쉽고,
    # 정책 이름·번호는 다른 고객 장비에도 똑같이 있다(MSP 템플릿·이름 없는
    # 정책). 남의 행을 붙여도 이 값이 없으면 분모에 못 들어간다 — 파일을
    # 인증하는 대신 **행마다 발급 사실을 확인한다.**
    ("sample_token",  "표본 ID (수정하지 마세요)"),
]

VERDICT_MATCH = "일치"
VERDICT_MISMATCH = "불일치"
VERDICT_HOLD = "보류"


# ---------------------------------------------------------------------------
# 1) 층화 표본 추출
# ---------------------------------------------------------------------------

def _is_ungraded(level) -> bool:
    """등급 0 = 'Cannot assess'. APO 가 판정하지 못했다는 표시이지 판정이 아니다."""
    try:
        return int(str(level).strip()) == 0
    except (TypeError, ValueError):
        return False


def stratified_sample(
    policies: Iterable[dict],
    per_level_min: int = 5,
    per_level_max: int = 10,
    total_cap: int = 50,
    seed: int = 20260729,
) -> list[dict]:
    """등급별로 고르게 표본을 뽑는다.

    등급이 편중된 실데이터에서 무작위로 뽑으면 다수 등급만 검증하게 된다.
    등급마다 최소 per_level_min개를 확보해, 건수가 적은 등급의 정확도도
    측정할 수 있게 한다.

    같은 등급 안에서는 '판정 근거'가 서로 다른 정책을 우선 고른다. 같은 사유
    5건을 보는 것보다 5가지 사유를 보는 편이 규칙을 더 많이 검증한다.

    seed를 고정해 재실행 시 같은 표본이 나오게 한다(대조 작업 중 표본이
    바뀌면 진행 중인 검증이 무의미해진다).
    """
    rng = random.Random(seed)
    by_level: dict[Any, list[dict]] = defaultdict(list)
    for p in policies:
        # **'판정 못 함'은 판정이 아니다.** 등급 0 은 "Cannot assess — set User
        # IP ranges first" 로, APO 가 결론을 내지 못했다는 뜻이다. 검증자가
        # 할 수 있는 대답은 "맞다, 판정 못 했다"(일치)뿐이라 **구조적으로 100%**
        # 가 나오고, 표본의 14% 를 차지하며 헤드라인을 끌어올렸다(라운드 48
        # 실측: 50.0% → 71.4%). 도구가 **덜 설정돼 있을수록 성적이 좋아지는**
        # 셈이었다. 표본은 실제 판정에만 쓴다.
        if _is_ungraded(p.get("urgency")):
            continue
        by_level[p.get("urgency")].append(p)

    picked: list[dict] = []
    per_level: dict[Any, list[dict]] = {}
    for level in sorted(by_level, key=lambda x: (x is None, x)):
        rows = list(by_level[level])
        rng.shuffle(rows)

        # 사유가 다른 것부터 채운다
        seen_reasons: set[str] = set()
        chosen: list[dict] = []
        for r in rows:
            key = _reason_key(r.get("reason"))
            if key not in seen_reasons:
                seen_reasons.add(key)
                chosen.append(r)
            if len(chosen) >= per_level_max:
                break
        # 사유 종류가 모자라면 남은 것으로 최소치를 채운다
        if len(chosen) < per_level_min:
            for r in rows:
                if r not in chosen:
                    chosen.append(r)
                if len(chosen) >= per_level_min:
                    break
        per_level[level] = chosen[:per_level_max]
        picked.extend(per_level[level])

    if len(picked) > total_cap:
        # **등급을 통째로 잃지 않으면서** 상한에 맞춘다.
        #
        # 예전 코드는 `sorted(picked, key=lambda x: (counts[x['urgency']], ...))`
        # 로 등급을 번갈아 뽑으려 했는데, `sorted` 는 정렬 **전에** 키를 다
        # 계산한다 — 그래서 `counts` 는 전부 0 이었고 사실상 등급 문자열
        # 오름차순이 됐다. 등급 1~7 이 각각 10건씩(70건) 나오면 앞에서부터
        # 50건을 잘라 **6·7 등급이 표본에서 통째로 사라졌다**(라운드 47 실측).
        # 6·7 은 APO 가 "그대로 둬도 된다"고 말한 정책들이라, 정확히 그
        # 판단의 정확도만 측정되지 않았다.
        #
        # 실제로 등급을 돌아가며 한 건씩 가져간다.
        trimmed: list[dict] = []
        queues = [list(per_level[lv])
                  for lv in sorted(per_level, key=lambda x: (x is None, x))]
        while len(trimmed) < total_cap and any(queues):
            for q in queues:
                if not q:
                    continue
                trimmed.append(q.pop(0))
                if len(trimmed) >= total_cap:
                    break
        picked = trimmed
    return picked


def _reason_key(reason: Any) -> str:
    """숫자를 뺀 사유 문자열. 'Hit 13 < 500'과 'Hit 7 < 500'을 같은 종류로 본다."""
    s = str(reason or "")
    return "".join(ch for ch in s if not ch.isdigit())[:60]


# ---------------------------------------------------------------------------
# 2) 검증 워크시트
# ---------------------------------------------------------------------------

def _is_proxy(policy: dict) -> bool:
    ptype = (policy.get("policy_type") or policy.get("type")
             or policy.get("_ptype") or "firewall").lower()
    return "proxy" in ptype


def _vdom_of(policy: dict) -> str:
    """이 정책이 속한 VDOM 이름(없으면 빈 문자열)."""
    return str(policy.get("vdom") or "").strip()


def _with_vdom_block(cmds: list, vdom: str) -> list:
    """명령 목록 **전체**를 한 번만 `config vdom / edit <이름>` 으로 감싼다.

    **접두를 명령마다 붙이면 붙여넣기가 깨진다.** 라운드 47 에서 VDOM 을
    지정하도록 고치면서 `_policy_show_command` 와 `_runtime_command` 가 **각자**
    접두를 붙였다. 그래서 다중 VDOM 정책의 CLI 칸이 이렇게 나갔다:

        config vdom / edit guest / show firewall policy 7
        config vdom / edit guest        ← 이미 edit guest 안이다. parse error
        edit guest                      ← parse error
        diagnose ...

    검증자는 중간에 오류를 보고 **APO 가 준 명령 전체를 불신하게 된다** —
    없는 불일치를 막으려던 수정이 같은 자리에서 새 잡음을 만들었다
    (라운드 48 실측). 블록은 `end` 로 닫는다.

    VDOM 이 없으면(단일 VDOM 장비) 아무것도 붙이지 않는다.
    """
    if not vdom or not cmds:
        return cmds
    return ["config vdom", f"edit {vdom}"] + list(cmds) + ["end"]


def _policy_show_command(policy: dict) -> str:
    pid = str(policy.get("policy_id", "")).strip()
    table = "firewall proxy-policy" if _is_proxy(policy) else "firewall policy"
    return f"show {table} {pid}"


def _runtime_command(policy: dict) -> str:
    """사용량 확인. APO의 런타임 임포트가 이 출력 형식을 그대로 읽는다.

    **프록시 정책에는 이 명령을 주지 않는다.** iprope 00100004 는 firewall
    정책 표다. 프록시에도 그대로 줘서, 검증자가 친 명령이 빈 출력을 내거나
    같은 번호의 **다른(firewall) 정책** 카운터를 보여 줬다 — 어느 쪽이든
    "Hit=0 이라더니 아니네" 같은 없는 불일치가 만들어진다(라운드 47).
    대신할 명령을 지어내지 않고 빈 문자열을 돌려준다. 모르는 것은 모른다고
    적는 편이 틀린 명령보다 낫다(호출측이 그 사실을 확인 항목으로 알린다).
    """
    if _is_proxy(policy):
        return ""
    pid = str(policy.get("policy_id", "")).strip()
    return f"diagnose firewall iprope show 00100004 {pid}"


def derive_checks(policy: dict) -> tuple[list[str], list[str]]:
    """판정 근거에 따라 '확인할 것'과 '실행할 명령어'를 만든다.

    무엇을 근거로 그 등급이 나왔는지에 따라 확인 지점이 달라진다. 전부 같은
    명령어를 주면 사람이 무엇을 봐야 할지 알 수 없다.
    """
    reason = str(policy.get("reason") or "")
    checks: list[str] = []
    cmds: list[str] = [_policy_show_command(policy)]

    def add(check: str, cmd: str | None = None):
        if check not in checks:
            checks.append(check)
        if cmd and cmd not in cmds:
            cmds.append(cmd)

    low = reason.lower()

    def has(*words) -> bool:
        """단어 경계 매칭. 부분문자열이면 "S-U fallback"의 'fallback'이
        'all'로 잡혀 판정과 무관한 확인 항목이 붙는다(실장비 대조에서
        불일치 3건의 원인이었다)."""
        return any(_re.search(r"(?<![a-z])" + _re.escape(w) + r"(?![a-z])", low)
                   for w in words)

    if has("disabled"):
        add("정책이 실제로 비활성(status disable) 상태인가")
    if "schedule expired" in low or "sched_age" in low:
        add("스케줄 만료일이 실제로 지났는가. 이름만 날짜이고 always는 아닌가")
    if "hit=0" in low or "unused" in low:
        add("누적 접속 횟수가 정말 0인가. 장비 재시작·이중화 전환으로 카운터가 "
            "초기화된 이력은 없는가", _runtime_command(policy))
    # "hit>0 but no last-used record"(하이픈·무공백) 는 라운드 53 이 넣은
    # 문구다 — 공백 변형("last used"/"hit ")만 찾다가 이 사유의 사용량
    # 확인 항목과 장비 명령이 통째로 빠졌다(라운드 54 계약 렌즈 실측).
    # dormant 도 사용량 판정이므로 명시한다.
    if ("last used" in low or "last-used" in low or "hit " in low
            or "hit>0" in low or "low hit" in low or "dormant" in low):
        add("마지막 사용 시각이 실제로 그 시점인가", _runtime_command(policy))
    if "risky service" in low:
        add("문제로 지목된 평문 프로토콜이 실제로 이 정책에 포함되는가")
        add("해당 서비스만 빼도 업무에 지장이 없는가 (담당자 확인 필요)")
        cmds.append("show firewall service custom <서비스명>")
        cmds.append("show firewall service group <그룹명>")
    if has("any", "all"):
        add("출발지/목적지/서비스가 실제로 all 인가. 이름만 'all'인 객체는 아닌가")
        cmds.append("show firewall address all")
    if "object" in low or "admin policy" in low:
        add("판정에 쓰인 예외 객체가 실제로 이 정책에 포함되는가")
        cmds.append("show firewall addrgrp <그룹명>")
    if "valid its" in low:
        add("정책 이름의 티켓 번호가 실제 승인 건과 일치하는가 (ITSM 대조)")
    if "noticket" in low.replace(" ", "") or "no ticket" in low:
        add("이 정책이 정말 승인 없이 만들어졌는가. 티켓 번호가 이름에 없을 뿐 "
            "별도 승인 기록이 있는 경우가 흔하다 (ITSM 대조)")
    if has("temp", "temp+noticket"):
        add("이름의 '임시' 표기가 실제로 임시 정책이라는 뜻인가. 이름만 그렇고 "
            "상시 운영 중인 경우가 있다 (담당자 확인 필요)")

    # 판정이 어떤 근거 위에 서 있는지를 검증자에게 알린다.
    # 사용량 데이터 없이 이름만으로 내린 판정은 근거가 약한데, 그 사실이
    # 등급 숫자에는 드러나지 않는다.
    # 판정 엔진이 실제로 쓰는 말은 "usage unknown (no usage data)" 다.
    # 여기서만 "csv not loaded" 를 찾고 있어서 **이 경고가 한 번도 뜬 적이
    # 없었다** — 사용량 없이 이름만으로 내린 판정을 검증자가 그런 줄 모르고
    # 대조했다(라운드 47 실측). 문구가 또 바뀔 수 있으니 계약으로 묶는다.
    if ("no usage data" in low or "usage unknown" in low
            or "csv not loaded" in low):
        add("[주의] 이 판정은 사용량 데이터 없이 정책 이름만으로 내려졌다. "
            "실제 사용 중인지 반드시 장비에서 확인할 것", _runtime_command(policy))
    if "reg date unknown" in low or "age=none" in low:
        add("[주의] 등록일을 알 수 없어 사용 기간 판정이 생략됐다. "
            "실제 생성 시점을 확인할 것")
    # **사용자 대역이 맞는지 묻는 항목이 한 번도 붙지 않았다.**
    # 여기서는 `s-u`·`server-user`(하이픈)를 찾는데, 판정 엔진이 쓰는 말은
    # `server ↔ user`(U+2194, 공백)다. 15개 문구 중 legacy 하이픈 하나만
    # 걸렸다 — 즉 이 확인 항목과 `show firewall address` 명령은 사실상
    # 죽은 코드였다(라운드 48 실측).
    #
    # `user_ranges` 는 **고객이 손으로 넣는 유일한 입력**이고 등급 3~6 을
    # 좌우한다. 그 입력이 틀리면 1,591건 중 대다수의 등급이 틀리는데,
    # 검증 시트가 그걸 한 번도 확인하라고 하지 않았다.
    #
    # 라운드 47 에서 바로 위 '사용량 없음' 문구에 같은 결함을 고쳤으면서
    # **바로 옆 형제 문구는 안 고쳤다.** 그래서 이제 문구를 손으로 적지 않고
    # 엔진 출력으로 계약을 건다(test_verification).
    if ("s-u" in low or "s-s" in low or "server-user" in low
            or "server-server" in low
            or "server ↔ user" in low or "server ↔ server" in low
            or "server ↔" in low):
        add("출발지/목적지가 실제로 사용자 대역/서버 대역이 맞는가. "
            "APO 에 넣은 사용자 IP 대역 목록이 이 정책에 맞는가")
        cmds.append("show firewall address <객체명>")
    if has("deny"):
        add("action이 실제로 deny 인가")
    if has("icmp"):
        add("허용 서비스가 ICMP 계열뿐인가")

    if not checks:
        checks.append("APO 판정 근거가 실제 설정과 맞는가")

    # 사용량을 물어야 하는 판정인데 프록시라 확인 명령이 없다면, 그 사실을
    # 검증자에게 말한다. 조용히 빼면 "명령이 없네" 하고 넘어가거나 firewall
    # 명령을 임의로 만들어 친다.
    if _is_proxy(policy) and any(
            k in low for k in ("hit=0", "unused", "last used", "last-used",
                               "hit ", "hit>0", "dormant",
                               "no usage data", "usage unknown")):
        checks.append(
            "[주의] 프록시 정책은 iprope 사용량 표에 없다. 접속 횟수는 "
            "UTM/웹필터 로그나 FortiAnalyzer 에서 확인해야 한다")

    return checks, _with_vdom_block(cmds, _vdom_of(policy))


def build_rows(samples: Iterable[dict]) -> list[dict]:
    rows = []
    for p in samples:
        checks, cmds = derive_checks(p)
        rows.append({
            "policy_id":   p.get("policy_id"),
            "vdom":        p.get("vdom") or "",
            "policy_type": p.get("policy_type") or p.get("type") or "firewall",
            "name":        p.get("name"),
            "urgency":     p.get("urgency"),
            "risk_level":  p.get("risk_level"),
            "action_label": p.get("action_label"),
            "reason":      p.get("reason"),
            "recommended": p.get("recommended_action"),
            "check_items": "\n".join(f"{i}. {c}" for i, c in enumerate(checks, 1)),
            "cli_commands": "\n".join(cmds),
            "actual": "",
            "verdict": "",
            "note": "",
        })
    return rows


# 표지행의 형식은 **한 곳에만** 적는다. 쓰는 쪽(csv/xlsx)과 읽는 쪽(채점)이
# 각자 문자열을 들고 있으면, 한쪽만 바뀌는 순간 채점이 표지를 못 읽는다 —
# 그러면 '어느 장비의 표본인가'를 확인하지 못한 채 점수를 내게 된다.
DEVICE_BANNER = "장비 / Device: "


def device_from_banner(cells) -> str:
    """표지행에서 장비명을 되읽는다 — 아니면 빈 문자열."""
    for c in (cells or []):
        s = str(c or "").strip().lstrip("#").strip()
        if s.startswith(DEVICE_BANNER):
            return s[len(DEVICE_BANNER):].strip()
    return ""


def to_csv(rows: list[dict], device: str = "") -> bytes:
    """UTF-8 BOM CSV (Excel 한글 호환).

    device: 이 표본이 어느 장비의 것인지. 파일명에만 있으면 받는 쪽에서
    이름이 바뀌는 순간 귀속이 사라진다 — 정책 번호 1·2·3 은 어느 FortiGate
    에나 있어 섞이면 구분할 방법이 없다(라운드 25 지적).
    """
    from app.services.remediation_service import _csv_safe

    out = io.StringIO()
    w = csv.writer(out)
    if device:
        w.writerow([f"# {DEVICE_BANNER}{_csv_safe(device)}"])
    w.writerow([label for _, label in WORKSHEET_COLUMNS])
    for r in rows:
        w.writerow([_csv_safe(r.get(key, "")) for key, _ in WORKSHEET_COLUMNS])
    return out.getvalue().encode("utf-8-sig")


def to_xlsx(rows: list[dict], device: str = "") -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill

    from app.services.workbook_exporter import SEVERITY_FILLS, write_text_cell

    wb = Workbook()
    ws = wb.active
    ws.title = "Verification"
    # **보이는 자리에 적는다.** 문서 속성에만 넣었더니 시트 어디에도 장비가
    # 없어, 두 고객의 표본을 나란히 놓으면 구분할 단서가 없었다 — 정책 번호
    # 1·2·3 은 어느 FortiGate 에나 있다(라운드 26 실측). 감사자가 서명하는
    # 것은 이 시트이지 파일 속성 창이 아니다. 되올려 채점할 때 이 줄을
    # 헤더로 읽지 않도록 읽는 쪽(verification_score)도 함께 고쳤다.
    top = 0
    if device:
        wb.properties.title = f"APO verification sample — {device}"
        banner = ws.cell(row=1, column=1, value=f"{DEVICE_BANNER}{device}")
        banner.font = Font(bold=True)
        top = 1

    header_fill = PatternFill("solid", fgColor="0F172A")
    header_font = Font(color="FFFFFF", bold=True)
    for col, (_, label) in enumerate(WORKSHEET_COLUMNS, 1):
        c = ws.cell(row=top + 1, column=col, value=label)
        c.fill, c.font = header_fill, header_font
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    for r_i, row in enumerate(rows, top + 2):
        fill = SEVERITY_FILLS.get(row.get("urgency"), SEVERITY_FILLS[0])
        for c_i, (key, _) in enumerate(WORKSHEET_COLUMNS, 1):
            val = row.get(key, "")
            cell = write_text_cell(ws, r_i, c_i, "" if val is None else str(val))
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            # 사람이 채울 칸은 색을 칠하지 않아 눈에 띄게 둔다
            if key not in ("actual", "verdict", "note"):
                cell.fill = fill

    widths = {"policy_id": 10, "policy_type": 10, "name": 28, "urgency": 9,
              "risk_level": 10, "action_label": 20, "reason": 40, "recommended": 30,
              "check_items": 46, "cli_commands": 44, "actual": 30,
              "verdict": 16, "note": 24}
    for c_i, (key, _) in enumerate(WORKSHEET_COLUMNS, 1):
        ws.column_dimensions[ws.cell(row=top + 1, column=c_i).column_letter].width = \
            widths.get(key, 18)
    ws.freeze_panes = f"A{top + 2}"

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.read()


# ---------------------------------------------------------------------------
# 3) 정밀도 계산
# ---------------------------------------------------------------------------

# ── 판정 칸 정규화 ──────────────────────────────────────────────────────────
# **문구를 더 넣는 방식은 실패한다.** 처음에는 `불일치`·`mismatch` 만 보고
# 그 뒤에 `일치 in v` 로 넘어가서 "일치하지 않음"이 일치로 채점됐다. 그걸
# 고치며 `맞음·동일·정확·correct·same·true` 를 일치 큐에 더했더니, 이번엔
# 그것들의 부정형("부정확", "동일하지 않음", "not correct", "안 맞음")이 다시
# 일치로 채점됐다 — **같은 함정이 네 개 더 생긴 것이다**(라운드 47 실측).
#
# 부분문자열 큐는 자기 부정형에 삼켜진다. 그래서 **부정 표지를 먼저 세고**,
# 남은 어간으로 판정한 뒤 부정 개수가 홀수면 뒤집는다.
#
# 이 칸은 이 도구의 **정확도 수치를 만드는 칸**이다. 애매하면 APO 에게 불리한
# 쪽(또는 '못 읽음')으로 떨어뜨린다 — 자기 성적을 부풀리지 않기 위해서다.

# 부정 표지. 짧은 한글 표지는 어간 앞에 붙는 형태만 세도록 뒤에서 따로 다룬다.
_NEG_MARKERS = (
    "않", "못", "아님", "아니", "없",
    "안함", "안됨", "안된", "안돼",     # "일치 안 함" — 어간 뒤에 오는 형태
    "not", "isn't", "doesn't", "didn't", "n't",
)
# 어간 **바로 앞**에서만 부정으로 보는 접두 표지. 아무 데서나 세면 무관한
# 글자에 걸려 정상 '일치'를 뒤집는다("in"·"un"·"mis" 가 특히 위험하다).
_NEG_PREFIXES = ("불", "부", "미", "비", "안",
                 "no", "non", "un", "mis", "in", "dis")

# 일치를 뜻하는 어간
_MATCH_STEMS = ("일치", "맞", "동일", "정확", "match", "correct", "same",
                "true", "agree")
# 그 자체로 불일치를 뜻하는 어간(부정 표지가 없어도 불일치)
_MISMATCH_STEMS = ("틀리", "틀림", "틀렸", "다름", "다릅", "오탐", "오판",
                   "wrong", "false", "differ")

_MATCH_EXACT = frozenset({"o", "ok", "yes", "y", "1", "✓", "✔"})
_MISMATCH_EXACT = frozenset({"x", "no", "n", "0", "ng", "✗", "✘"})


def _count_negations(v: str) -> int:
    """부정 표지가 몇 번 나오는가. 홀수면 뜻이 뒤집힌다."""
    n = sum(v.count(m) for m in _NEG_MARKERS)
    # 1글자 접두 표지는 **어간 바로 앞**에 있을 때만 센다 — 그러지 않으면
    # 무관한 글자에 걸려 정상 '일치'를 뒤집는다.
    for pre in _NEG_PREFIXES:
        for stem in _MATCH_STEMS + _MISMATCH_STEMS:
            n += v.count(pre + stem)
    return n


def _normalize_verdict(raw) -> str:
    """사람이 적은 판정 값을 정규화한다. 못 읽으면 빈 문자열.

    반환은 `일치`·`불일치`·`보류`·`""`(못 읽음) 넷 중 하나다. 못 읽은 값은
    분모에서 빠지되, 호출측이 **몇 건을 못 읽었는지 셀 수 있어야** 한다 —
    조용히 미기입에 섞으면 검토자가 적은 값이 소리 없이 버려진다.
    """
    v = str(raw or "").strip().lower().replace(" ", "")
    if not v:
        return ""
    if v in _MATCH_EXACT:
        return VERDICT_MATCH
    if v in _MISMATCH_EXACT:
        return VERDICT_MISMATCH
    if VERDICT_HOLD in v or "hold" in v or "pending" in v or "유보" in v:
        return VERDICT_HOLD

    has_match = any(st in v for st in _MATCH_STEMS)
    has_mismatch = any(st in v for st in _MISMATCH_STEMS)
    if has_match and has_mismatch:
        return ""          # 둘 다 들어 있으면 사람이 확인해야 한다
    if not (has_match or has_mismatch):
        return ""

    negated = _count_negations(v) % 2 == 1
    positive = has_match          # 어간 자체의 방향
    if negated:
        positive = not positive
    return VERDICT_MATCH if positive else VERDICT_MISMATCH


def count_unreadable(rows) -> int:
    """값을 적었는데 **읽지 못한** 행 수. 미기입과 구별해 화면에 보여 준다."""
    n = 0
    for r in rows:
        raw = str(r.get("verdict") or "").strip()
        if raw and not _normalize_verdict(raw):
            n += 1
    return n


def compute_precision(rows: Iterable[dict]) -> dict:
    """사람이 채운 워크시트를 받아 등급별 정확도를 낸다.

    '보류'와 미기입은 분모에서 뺀다. 확인하지 못한 건을 정답이나 오답으로
    치면 수치가 실제보다 좋아지거나 나빠진다.
    """
    per_level: dict[Any, Counter] = defaultdict(Counter)
    for r in rows:
        v = _normalize_verdict(r.get("verdict"))
        # **등급 키는 반드시 문자열이다.** 사람이 'APO 등급' 칸을 지우면 None 이
        # 섞여 들어와, 정렬에서 None 과 문자열을 견주다 500 이 났다 — 워크시트
        # 한 칸을 비웠을 뿐인데 서버 오류가 나면 원인을 알 수 없다(라운드 31).
        level = r.get("urgency")
        level = "" if level is None else str(level).strip()
        if v == VERDICT_MATCH:
            per_level[level]["match"] += 1
        elif v == VERDICT_MISMATCH:
            per_level[level]["mismatch"] += 1
        elif v == VERDICT_HOLD:
            per_level[level]["hold"] += 1
        elif str(r.get("verdict") or "").strip():
            # **적었는데 못 읽은 값**을 미기입에 섞으면, 검토자가 적은 것이
            # 소리 없이 버려진다. 따로 세어 화면이 그 수를 말하게 한다
            # (라운드 47 지적).
            per_level[level]["unreadable"] += 1
        else:
            per_level[level]["unfilled"] += 1

    levels = {}
    tot_m = tot_x = 0
    for level, c in per_level.items():
        judged = c["match"] + c["mismatch"]
        levels[level] = {
            "match": c["match"], "mismatch": c["mismatch"],
            "hold": c["hold"], "unfilled": c["unfilled"],
            "unreadable": c["unreadable"],
            "judged": judged,
            "precision": (c["match"] / judged) if judged else None,
        }
        # 헤드라인에는 '판정 못 함'을 넣지 않는다 — 검증자가 줄 수 있는 답이
        # 일치뿐이라 100% 가 보장된 행이다. 등급별 줄에는 그대로 남겨,
        # 몇 건이 판정 불가였는지는 여전히 보이게 한다.
        if _is_ungraded(level):
            continue
        tot_m += c["match"]
        tot_x += c["mismatch"]

    overall_judged = tot_m + tot_x
    return {
        "levels": dict(sorted(levels.items(), key=lambda kv: (kv[0] is None, kv[0]))),
        "overall": {
            "match": tot_m, "mismatch": tot_x, "judged": overall_judged,
            "precision": (tot_m / overall_judged) if overall_judged else None,
        },
        # 표본이 적으면 수치를 신뢰하기 어렵다는 점을 호출측이 알 수 있게 남긴다
        "weak_levels": [lv for lv, d in levels.items()
                        if d["judged"] and d["judged"] < 5],
        "unreadable": sum(d["unreadable"] for d in levels.values()),
        # 헤드라인에서 뺀 '판정 못 함' 건수 — 뺀 사실을 화면이 말할 수 있게.
        "ungraded_judged": sum(d["judged"] for lv, d in levels.items()
                               if _is_ungraded(lv)),
    }


def format_precision_report(result: dict) -> str:
    lines = ["=" * 64, "  APO 판정 정확도 리포트", "=" * 64, ""]
    lines.append(f"{'등급':<6}{'일치':>6}{'불일치':>8}{'보류':>6}{'미기입':>8}{'정확도':>10}")
    lines.append("-" * 64)
    for lv, d in result["levels"].items():
        p = "—" if d["precision"] is None else f"{d['precision']*100:.1f}%"
        lines.append(f"{str(lv):<6}{d['match']:>6}{d['mismatch']:>8}{d['hold']:>6}{d['unfilled']:>8}{p:>10}")
    o = result["overall"]
    lines.append("-" * 64)
    p = "—" if o["precision"] is None else f"{o['precision']*100:.1f}%"
    lines.append(f"{'표본':<6}{o['match']:>6}{o['mismatch']:>8}{'':>6}{'':>8}{p:>10}")
    if o["judged"] == 0:
        lines += ["", "대조 결과가 아직 입력되지 않았습니다."]
    else:
        # **이 줄을 '전체 정확도'라고 부르면 안 된다.** 표본은 등급별로
        # 고르게 뽑는다 — 5등급이 600건이고 1등급이 3건이어도 표본에는 비슷한
        # 수가 들어간다. 그 둘을 그냥 합친 값은 이 장비의 정확도가 아니라
        # **표본 안에서의 비율**일 뿐인데, '전체'라고 적어 두니 그대로 인용됐다
        # (라운드 47). 등급별 줄이 실제로 쓸 수 있는 수치다.
        lines += ["", "참고: 표본은 등급별로 고르게 뽑으므로 위 '표본' 줄은 "
                      "장비 전체의 정확도가 아닙니다. 등급별 줄을 보세요."]
    if result.get("unreadable"):
        lines += ["", f"주의: 값을 적었으나 읽지 못한 칸이 "
                      f"{result['unreadable']}건 있습니다 — 그 행은 집계에서 "
                      "빠졌습니다. '일치' / '불일치' / '보류' 로 적어 주세요."]
    if result["weak_levels"]:
        lines += ["", f"주의: 대조 건수가 5건 미만인 등급 {result['weak_levels']} 은 "
                      "수치를 신뢰하기 어렵습니다."]
    return "\n".join(lines)
