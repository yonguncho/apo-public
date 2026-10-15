"""
APO Severity Engine
===================
판정 규칙 중 조직마다 다른 부분은 프로파일(profiles/*.yaml)로 관리한다.
구형 customer_rules.json이 실행 디렉토리(또는 exe 인접 경로)에 있으면
하위호환으로 병합된다 — profile_loader.py 참고.
파일이 하나도 없으면 중립 기본값으로 동작한다.
"""

import re
from datetime import date
from .schedule_utils import is_expired_schedule, is_always_schedule, get_schedule_date
from .ip_classifier import classify_traffic_type
from .profile_loader import load_profile, to_customer_rules

# ================================================================
# CUSTOMER_RULES — 활성 프로파일에서 파생 (구형 customer_rules.json 병합 포함).
# context에 customer_rules를 넘기지 않는 호출부(구형·테스트)용 폴백이다.
# ================================================================
CUSTOMER_RULES = to_customer_rules(load_profile())
# ================================================================

RISKY_SERVICES  = {"FTP", "TELNET", "TFTP", "RLOGIN", "RSH"}
AD_DNS_SERVICES = {"AD_AUTH", "DNS", "LDAP", "Kerberos", "LDAPS"}
ICMP_SERVICES   = {"ALL_ICMP", "ICMP_ALL", "PING", "ALL_ICMP_ALL"}
CONTROLLED_KW   = ["controlled"]

# 대기 경로(backup/DR) 인터페이스 키워드 — 평시 트래픽이 없는 것이 정상인
# 경로라, '확인된 무트래픽(Hit=0)'을 미사용 근거로 쓰면 안 된다
# (2026-08-24 Jayden 실사용 지적). 토큰 단위로 비교한다: "wan-dr"·
# "BACKUP_LINE" 은 잡고 "drain"·"address" 는 안 잡는다(부분 문자열 매칭
# 오탐 — 객체 규칙 두 글자 'F1' 사고와 같은 클래스).
STANDBY_INTF_KEYWORDS = {"backup", "dr", "standby"}
_INTF_TOKEN_RE = re.compile(r"[^0-9a-z]+")


def _standby_intf(policy: dict, keywords: set) -> str:
    """정책 인터페이스가 대기 경로(backup/DR)로 보이면 그 이름, 아니면 ""."""
    for field in ("srcintf", "dstintf"):
        v = policy.get(field) or []
        if isinstance(v, str):
            v = [v]
        for name in v:
            toks = _INTF_TOKEN_RE.split(str(name).lower())
            if any(t in keywords for t in toks if t):
                return str(name)
    return ""

SEVERITY_META = {
    0: ("Unknown",  "Cannot assess — set User IP ranges first", "#F0EEE7"),
    1: ("Critical", "Disable, then monitor 30–90 days before removing", "#FFCCCC"),
    2: ("High",     "Review candidate — confirm before removing",       "#D3D1C7"),
    3: ("Medium",   "Review required",                          "#FFE0B2"),
    4: ("Medium",   "Review required",                          "#B5D4F4"),
    5: ("Low",      "Request ITS Ticket",                       "#FFF9C4"),
    6: ("Low",      "Request ITS Ticket",                       "#C0DD97"),
    7: ("None",     "Keep",                                     "#9FE1CB"),
}

# ── 조치 유형 ───────────────────────────────────────────────────────────────
# 등급(위험도)과 조치(무엇을 할 것인가)는 서로 다른 축이다. 등급만으로 정렬하면
# 성격이 다른 작업이 섞인다 — 예를 들어 등급 3에는 "추가 검토"와 "특정 서비스만
# 제거"가 함께 들어가고, 등급 7에는 "위험 아님"과 "예외 처리해 판정 안 함"이
# 함께 들어간다. 후자는 재검토 여지가 있는데 "안전"으로 읽히기 쉽다.
ACTION_DISABLE        = "DISABLE"          # 즉시 비활성화
ACTION_REVIEW_REMOVE  = "REVIEW_REMOVE"    # 검토 후보 — 확인 후 삭제
ACTION_DISABLE_FIRST  = "DISABLE_FIRST"    # 비활성화 후 모니터링
ACTION_SERVICE_REMOVE = "SERVICE_REMOVE"   # 특정 서비스만 제거 (정책은 유지)
ACTION_REVIEW         = "REVIEW"           # 추가 검토 필요
ACTION_TICKET         = "TICKET"           # 등록 요청
ACTION_NO_RISK        = "NO_RISK"          # 위험 아님
ACTION_APPROVED       = "APPROVED"         # 승인 확인됨 (유효 티켓)
ACTION_EXCLUDED       = "EXCLUDED"         # 예외로 판정하지 않음
ACTION_UNKNOWN        = "UNKNOWN"          # 판정 불가

ACTION_LABELS = {
    ACTION_DISABLE:        "Disable now",
    ACTION_REVIEW_REMOVE:  "Remove (already inert)",
    ACTION_DISABLE_FIRST:  "Disable & monitor",
    ACTION_SERVICE_REMOVE: "Remove service only",
    ACTION_REVIEW:         "Needs review",
    ACTION_TICKET:         "Register ticket",
    ACTION_NO_RISK:        "No risk",
    ACTION_APPROVED:       "Approved (ticket verified)",
    ACTION_EXCLUDED:       "Not assessed (exempted)",
    ACTION_UNKNOWN:        "Cannot assess",
}

# 리포트에 함께 실어야 하는 한계. 이 도구의 판정은 아래 데이터 위에 서 있고,
# 그 데이터가 언제 부정확해지는지 읽는 사람이 알아야 한다.
KNOWN_LIMITATIONS = [
    "Hit counters reset to zero when the device reboots or fails over to its HA "
    "peer. A low hit count does not prove a policy is unused.",
    "Last Used timestamps can be lost the same way. 'No record' is not the same "
    "as 'not used'.",
    "This analysis reads the configuration and hit count / last used statistics "
    "only. It cannot tell whether a policy is still needed by the business — "
    "confirm with the policy owner before removing anything.",
    "Request dates and requesters are read from policy names and depend on your "
    "naming convention. Names that do not follow it are not parsed.",
    # **리포트가 자기 판정 근거를 정확히 고지해야 한다.** comment 한 줄이
    # 정책을 Keep 으로 올릴 수 있는데(‘Valid ITS’ 조기종결) 독자가 그 사실을
    # 모르면 근거를 검증할 수 없다(게이트 spec 렌즈 검출).
    "Ticket IDs are read from the policy name, and from the device comment when "
    "that option is on. A ticket number recorded in either place is taken as "
    "evidence that the policy was approved — the ticket itself is not verified. "
    "If no ticket format is configured, ticket IDs are not read at all and "
    "policies are reported as 'ticket unchecked' rather than as having none.",
]


# 등급 2의 조치를 가르는 **사실**. 사유 문장이 아니라 이 값으로 고른다 —
# 사유에는 고객 객체 이름이 섞이므로 문자열 검사는 고객 데이터에 좌우된다.
CAUSE_INERT = "inert"                  # 설정이 실제로 매칭을 막는다(비활성)
CAUSE_MAYBE_EXPIRED = "maybe_expired"  # 만료로 보이나 백업만으로는 확정 불가


def derive_action(urgency: int, reason: str, recommended_action: str = "",
                  cause: str = "") -> str:
    """등급과 판정 근거로부터 조치 유형을 정한다.

    등급 숫자는 그대로 두고(기존 체계 유지), 조치 축만 따로 뽑는다.
    `cause` 는 사유를 만든 쪽이 함께 실어 보내는 **사실**이다(위 상수).
    """
    r = (reason or "").lower()
    rec = (recommended_action or "").lower()

    if "remove risky services only" in rec:
        return ACTION_SERVICE_REMOVE
    if urgency == 0:
        return ACTION_UNKNOWN
    if urgency == 7:
        # 같은 7이라도 '봐도 문제없음'과 '예외라 안 봄'은 다르다.
        # **`in` 을 쓴 한 줄이 새고 있었다.** 사유에는 고객 객체 이름이
        # 들어가므로(`Override: {obj} -> 7`), `ICMP ONLY SENSORS` 같은 객체
        # 하나로 "검사하지 않았다(예외)" 가 "위험 아님(확인함)" 으로
        # 뒤집혔다 — '안 본 것을 0으로 인쇄'와 같은 형태다(라운드 46 실측).
        # 같은 자리의 다른 두 검사는 `startswith` 라 `Override:` 로 시작하는
        # 사유를 막아 준다. 이 줄만 같은 규칙으로 맞춘다.
        if r.startswith("action = deny") or r.startswith("service = icmp only"):
            return ACTION_NO_RISK
        # 유효 티켓은 '검사를 안 한 것'이 아니라 '승인을 확인한 것'이다.
        # Not assessed로 표기하면 점검 누락처럼 읽힌다(실장비 대조 지적).
        if r.startswith("valid its"):
            return ACTION_APPROVED
        return ACTION_EXCLUDED
    if urgency == 1:
        return ACTION_DISABLE
    if urgency == 2:
        # 이미 꺼져 있거나 만료된 정책은 삭제 검토 단계,
        # 살아 있는데 미사용인 정책은 비활성화부터가 순서다.
        #
        # **'expired' 부분 문자열로 고르면 취소한 확정이 되살아난다.**
        # 스케줄은 config 백업만으로 만료를 알 수 없으므로 사유를 '~로 보인다'
        # 로 고쳤는데(라운드 42), 이 자리는 여전히 'expired' 를 보고
        # `Remove (already inert)` 를 골랐다. 그 라벨의 설명은 화면과 워크북
        # 양쪽에서 "설정 자체가 매칭을 막는다" 다 — Reason 칸에서 뺀 단정을
        # 조치 칸과 엑셀 범례가 두 번 다시 주장했다(라운드 43 실측).
        # 감사자는 Reason 이 아니라 조치 칸으로 작업을 분류한다.
        # **사유 문자열로 조치를 고르는 것을 그만둔다.** 사유에는 고객이 등록한
        # 객체 이름이 그대로 들어간다(`Override: {obj} -> {sev}`). 그래서
        # `GRP_EXPIRED_DMZ` 나 `HOSTS_DISABLED_LEGACY` 같은 흔한 이름 하나로,
        # 히트 5,000에 어제도 매칭된 **살아 있는 정책**이 `Remove (already
        # inert)` 로 납품됐다 — 그 라벨의 설명은 화면과 워크북 양쪽에서
        # "설정 자체가 매칭을 막는다" 다(라운드 45 실측).
        # 라운드 43에서 같은 결함을 `looks expired` 한 케이스만 막았는데,
        # 오염원은 그것이 아니라 **자유 문자열을 검사로 쓴 것** 자체였다.
        # 이제 사유를 만든 쪽이 사실을 함께 실어 보내고, 여기서는 그것만 본다.
        if cause == CAUSE_INERT:
            return ACTION_REVIEW_REMOVE   # 설정이 실제로 매칭을 막는다
        if cause == CAUSE_MAYBE_EXPIRED:
            return ACTION_REVIEW          # 확인이 먼저다
        return ACTION_DISABLE_FIRST
    if urgency in (3, 4):
        return ACTION_REVIEW
    return ACTION_TICKET

# URGENCY_LABELS 호환성 유지
URGENCY_LABELS = {k: v[0] for k, v in SEVERITY_META.items()}


def _override_sev(value):
    """`severity_overrides` 의 값을 **등급 번호로만** 받는다. 아니면 None.

    이 값은 고객이 손으로 고치는 자리(`customer_rules.json` · 룰 세트 문서)에서
    검증 없이 그대로 `urgency` 가 됐다. 두 가지가 새어 들어왔다:

      `{"SRV1": null}` → `urgency = None`
        → 워크북 Summary 의 `sorted(sev_counts)` 가
          `TypeError: '<' not supported between 'int' and 'NoneType'` 로 터진다.
          **정책 하나의 오타가 리포트 전체를 못 내게 만든다.** 등급이 전부
          None 이거나 전부 int 면 통과하고 **섞일 때만** 터져서, 평소에는
          안 보이다가 실 config 에서만 터진다.

      `{"SRV1": "2"}` → `urgency = "2"` (문자열)
        → 등급 비교·필터·집계가 전부 빗나간다. 화면에는 뭔가 나오는데
          "High 2건" 같은 숫자에는 안 잡힌다 — **조용한 쪽이 더 나쁘다.**

    잘못된 값은 **오버라이드를 적용하지 않는다**(그 정책은 원래 규칙대로
    판정된다). 오타 하나로 판정을 멈추거나 산출물을 못 내는 것보다 낫고,
    "모를 때는 손대지 않는다" 는 이 엔진의 규칙과 같다.
    """
    if isinstance(value, bool):        # bool 은 int 의 하위형 — 등급이 아니다
        return None
    if isinstance(value, int):
        return value if value in SEVERITY_META else None
    if isinstance(value, str) and value.strip().isdigit():
        n = int(value.strip())
        return n if n in SEVERITY_META else None
    return None


def onetime_schedule_map(parsed: dict) -> dict:
    """(vdom_lower, name_lower) -> end date. 승인 유효기간 판정의 1차 신호.

    이 고객은 유저-서버 정책을 처음 신청할 때 1년짜리 onetime 스케줄로 연다
    (2026-08-24 Jayden). VDOM 은 스케줄 이름공간의 일부다 — 정책과 같은
    VDOM 의 스케줄만 그 정책의 기간이다.
    """
    out: dict = {}
    for it in (parsed or {}).get("firewall_schedule_onetime") or []:
        name = str(it.get("name") or it.get("_edit") or "").strip().lower()
        if not name:
            continue
        end = _sched_datetime_date(it.get("end"))
        if end:
            out[(str(it.get("vdom") or "").strip().lower(), name)] = end
    return out


def _sched_datetime_date(val):
    """FortiGate 'hh:mm yyyy/mm/dd' (파서는 토큰 리스트로 준다) -> date."""
    if isinstance(val, (list, tuple)):
        val = " ".join(str(v) for v in val)
    m = re.search(r"(\d{4})/(\d{2})/(\d{2})", str(val or ""))
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


# 이름·주석의 날짜 표기 — 20xx 연도의 8자리 또는 구분자형만 인정한다.
# 구분자 없는 6자리(YYMMDD)는 스케줄 이름 관례와 충돌하므로 여기서는 안 본다.
_APPROVAL_DATE_RE = re.compile(
    r"\b(20\d{2})([-/.]?)(\d{2})\2(\d{2})\b")


def _planned_end_date(policy: dict, onetime_map: dict, today):
    """이 정책에 **명시된 미래 종료일**이 있으면 그 날짜, 없으면 None.

    (2026-08-28 Jayden 지시 — 안 A)
    "종료일이 아직 남은 정책을 지금 끄라고 하지 마라". 종료 예정일이 적혀
    있다는 것은 **임시 개통이고 정리 계획이 이미 있다**는 실제 신호다 —
    그 정책을 미사용이라는 이유로 비활성 후보에 올리면, 절차상 아직 유효한
    개통을 정리 대상으로 모는 셈이다.

    **`always` 는 여기 해당하지 않는다.** 그건 종료일이 아니라 종료일이
    없다는 뜻이고, 실 config 에서 정책의 대다수가 `always` 다(가진 백업
    13개 전부 100%). `always` 를 '유효한 스케줄'로 인정하면 후보 목록이
    통째로 비어 이 도구가 하는 일이 사라진다.

    근거 우선순위는 `_approval_window_basis` 와 같다:
      ① 정책이 가리키는 onetime 스케줄 객체의 종료일 — config 사실
      ② 스케줄 이름의 YYMMDD — APO 는 스케줄 객체를 파싱하지 못할 때가
         있어(다른 VDOM·미수록) 이름이 유일한 단서인 경우가 있다. 짐작이
         므로 ① 이 있으면 ① 만 본다.

    **상한을 두지 않는다** (2026-08-28 Jayden 결정, 안 '가').
    미래이기만 하면 얼마나 멀든 유예한다. 알려진 대가: `991231`(2099년)
    처럼 아주 먼 날짜를 적으면 사실상 영구 면제가 되고, 오타로도 그렇게
    된다. 승인 유효기간(`approval_window_days`)처럼 상한을 두는 안도 있었
    으나, "종료일이 적혀 있으면 정리 계획이 있는 것"이라는 규칙의 취지를
    기간으로 다시 자르지 않기로 했다. 상한이 필요해지면 여기 한 곳만 고치면
    된다 — 판정 사유에 종료일이 그대로 찍히므로 감사에서 눈에 띈다.
    """
    sched = str(policy.get("schedule") or "").strip()
    if not sched or sched.lower() == "always":
        return None
    if onetime_map:
        end = onetime_map.get(
            (str(policy.get("vdom") or "").strip().lower(), sched.lower()))
        if end is not None:
            # config 사실이 있으면 그것만 본다 — 이름으로 되살리지 않는다
            # (라운드 77 F2 와 같은 규칙: 신호 우선순위지 다수결이 아니다).
            return end if end >= today else None
    named = get_schedule_date(sched)
    return named if (named and named >= today) else None


def _schedule_end(policy: dict, onetime_map: dict, schedule_val):
    """(종료일, 근거) — 근거는 `"config"` / `"name"` / `""`(모름).

    근거를 함께 돌려주는 이유는 **판정 사유가 무엇을 근거로 말하는지 달라지기
    때문**이다. config 의 onetime 객체에서 온 종료일은 **사실**이고, 이름의
    YYMMDD 는 **짐작**이다(요청일자를 이름으로 쓴 recurring 스케줄도 같은
    모양이다). 사실을 "이름이 만료처럼 보인다" 고 말하면 감사에서 근거를
    되짚을 수 없다 — 이 세션이 증적 정합으로 세 번 고친 그 문제다.
    """
    sched = str(schedule_val or "").strip()
    if not sched or sched.lower() == "always":
        return None, ""
    if onetime_map:
        end = onetime_map.get(
            (str(policy.get("vdom") or "").strip().lower(), sched.lower()))
        if end is not None:
            # config 사실이 있으면 그것만 본다 — 이름으로 되살리지 않는다
            # (`_planned_end_date` 와 같은 우선순위).
            return end, "config"
    named = get_schedule_date(sched)
    return (named, "name") if named else (None, "")


def _schedule_has_expired(policy: dict, onetime_map: dict, schedule_val,
                          today) -> bool:
    """이 정책의 스케줄이 **이미 끝났는가**.

    (2026-09-13 Jayden 승인 — 9라운드 판정 정확성 렌즈 A)

    `is_expired_schedule` 은 스케줄 **이름이 `^\\d{6}$`(YYMMDD) 일 때만**
    만료를 본다. 그런데 같은 엔진이 `context["onetime_schedules"]` 로 **실제
    종료일**을 이미 들고 있다 — `_planned_end_date` 와 `_approval_window_basis`
    는 그걸 쓴다. **아는 사실을 이 분기만 안 보고 있었다.**

    실 고객 config 실측(today=2026-07-29): policy 2670 의 스케줄
    `250531_홍길동` 은 onetime 종료일이 2025-05-31(14개월 전)인데, 이름이
    YYMMDD 가 아니라는 이유로 만료가 아니게 되어 티켓이 있다는 것만으로
    sev 7 "Valid ITS: …, Schedule valid" 가 됐다. 이름이 `250531` 이었으면
    sev 2 다(그 경로로 151건이 정상 처리된다). **이름 관례가 우연히 구해
    주고 있었을 뿐이다** — 같은 config 의 onetime 83개 중 비-YYMMDD 이름
    5개는 전부 이미 만료였다.

    화면의 판정 기준표도 조건을 이렇게 명시하고 있다 — "③ Valid change
    ticket (ticket ID present **+ schedule not expired**)". 구현이 자기
    명세와 어긋난 것이지 설계 결정이 아니었다.

    근거 우선순위는 `_planned_end_date`·`_approval_window_basis` 와 같다:
      ① 정책이 가리키는 onetime 스케줄 객체의 종료일 — config 사실
      ② 스케줄 이름의 YYMMDD — 짐작이므로 ① 이 있으면 ① 만 본다
    """
    end, _src = _schedule_end(policy, onetime_map, schedule_val)
    return bool(end and end < today)


def _approval_window_basis(policy: dict, onetime_map: dict, today,
                           window_days: int) -> str:
    """정책이 승인 유효기간 안이라는 근거 문구("" = 근거 없음).

    신호 우선순위: ① 정책의 onetime 스케줄 종료일(config 사실),
    ② 이름·주석의 날짜(과거 = 신청일로 보고 +window, 미래 = 만료일).
    미래 만료일도 window 를 넘게 남았으면 인정하지 않는다 — "1년짜리 신청"
    이라는 절차 사실에 맞춘 상한이다(2026-08-24 Jayden 승인, 등급 3).
    """
    if not window_days:
        return ""
    sched = str(policy.get("schedule") or "").strip().lower()
    if sched and sched != "always" and onetime_map:
        end = onetime_map.get(
            (str(policy.get("vdom") or "").strip().lower(), sched))
        if end is not None:
            # **config 사실이 있으면 그것만 본다** — 스케줄이 만료됐거나
            # 기간 밖이면 이름·주석의 날짜로 되살리지 않는다(라운드 77 F2:
            # 만료 스케줄 + 이름의 최근 날짜에서 이름이 이겨 "기간 내"라는
            # 거짓 사유가 나갔다. 신호 우선순위 ① config ② 이름은 폴백
            # 이지 다수결이 아니다).
            if today <= end and (end - today).days <= window_days:
                return f"schedule until {end.isoformat()}"
            return ""
    text = f"{policy.get('name') or ''} {policy.get('comments') or ''}"
    for m in _APPROVAL_DATE_RE.finditer(text):
        try:
            d = date(int(m.group(1)), int(m.group(3)), int(m.group(4)))
        except ValueError:
            continue
        if d <= today and (today - d).days < window_days:
            return f"dated {d.isoformat()}"
        if d > today and (d - today).days <= window_days:
            return f"valid until {d.isoformat()}"
    return ""


def evaluate_severity(policy: dict, context: dict) -> dict:
    today       = context.get("today") or date.today()
    svc_groups  = context.get("service_groups", {})
    user_ranges = context.get("user_ranges", [])
    customer_rules = context.get("customer_rules")
    if customer_rules is None:
        customer_rules = CUSTOMER_RULES

    # 판정 임계값. context로 주면 그것을, 없으면 customer_rules에서, 그것도
    # 없으면 현행 납품 값을 쓴다(하위호환 — 기존 호출부는 임계값을 넘기지 않는다).
    th = context.get("thresholds") or customer_rules.get("thresholds") or {}
    use_absolute_hit   = th.get("use_absolute_hit_threshold", True)
    su_multiplier      = th.get("su_hit_multiplier", 100)
    ss_hit_threshold   = th.get("ss_hit_threshold", 50)
    reg_fallback_year  = th.get("registration_fallback_year", 2021)
    # 미사용 판정 기간. 표준에 숫자 근거가 없으므로(docs/inventory.md §2.3)
    # 조직이 프로파일·UI로 조정한다. 365로 나누는 이유: _within_yrs가
    # days/365.25로 비교하므로 365.25로 나누면 기본값에서 경계일이 하루
    # 어긋난다(365/365.25 < 1.0). 365.0으로 나눠야 기존 '1년'과 정확히 같다.
    dormancy_days      = th.get("dormancy_days") or 365
    long_dormancy_days = th.get("long_dormancy_days") or 730
    ss_sched_age_years = th.get("ss_schedule_age_years") or 2
    # 승인 유효기간(일). 0 = 기능 끔. 이 고객: 유저-서버는 1년 승인으로 열리므로
    # 그 기간 안의 정책을 '정리 대상'으로 몰지 않는다(2026-08-24 Jayden —
    # 사용량 미상인 위험서비스 Critical 에 한해 3으로 완화. 전면허용·확인된
    # 미사용은 유예하지 않는다).
    approval_window_days = th.get("approval_window_days", 365)
    dorm_yrs = dormancy_days / 365.0
    long_yrs = long_dormancy_days / 365.0
    # 판정 근거 문구용 라벨. 기본값이면 기존 문구를 그대로 유지한다(회귀 픽스처).
    dorm_lbl = "1yr" if dormancy_days == 365 else f"{dormancy_days}d"
    long_lbl = "2yr" if long_dormancy_days == 730 else f"{long_dormancy_days}d"
    mid_lbl  = "1~2yr" if (dormancy_days == 365 and long_dormancy_days == 730) \
               else f"{dorm_lbl}~{long_lbl}"

    # 서비스 분류 목록. 프로파일에서 주면 그것을, 없으면 내장 기본값을 쓴다.
    svc_cfg = context.get("services") or {}
    risky_services   = set(svc_cfg.get("risky") or RISKY_SERVICES)
    auth_dns_services = set(svc_cfg.get("auth_dns") or AD_DNS_SERVICES)
    icmp_services     = set(svc_cfg.get("icmp") or ICMP_SERVICES)

    # 규칙 on/off
    rules_cfg = context.get("rules") or {}
    icmp_only_is_keep = rules_cfg.get("icmp_only_is_keep", True)

    name         = policy.get("name") or ""
    action       = (policy.get("action") or "").lower()
    status       = (policy.get("status") or "").lower()
    schedule_val = policy.get("schedule") or "always"
    hit_count_raw = policy.get("hit_count")
    # "1,234" 같은 문자열이 int() 실패로 0이 되면 실사용 정책이 "Hit=0
    # (Unused)" Critical이 된다(감사 A5). 파싱 실패는 0이 아니라 '미상'이다.
    hit_count    = _sane_hit(_parse_hit(hit_count_raw))
    hit_count_known = hit_count is not None
    hit_count    = hit_count or 0
    last_used    = _parse_date(policy.get("last_used"))
    request_date = _parse_date(policy.get("request_date"))
    ritm         = policy.get("ritm")
    has_ritm     = bool(ritm)
    # **'티켓 없음' 과 '티켓을 안 읽었음' 은 다르다.** 티켓 패턴이 설정되지
    # 않은 배포(중립 프로파일을 그대로 쓰는 경우)에서는 이름에 RITM0282811 이
    # 박혀 있어도 추출을 건너뛴다. 그것을 "No Ticket" 으로 표시하면 **없다고
    # 단정하는 거짓말**이 되고, 같은 산출물의 미판정 사유("패턴이 없어
    # 판정하지 않았음")와 정면으로 어긋난다. KNOWN_LIMITATIONS 의
    # "기록 없음 ≠ 미사용" 과 같은 종류의 오류다.
    ticket_scanned = policy.get("ticket_scanned")
    if ticket_scanned is None:
        ticket_scanned = context.get("ticket_pattern_configured", True)
    # **사유 문장에도 같은 규칙이 적용돼야 한다.** 태그만 고치고 사유를 두면
    # 같은 정책이 태그로는 "Ticket unchecked", 사유로는 "no ticket ID" 라고
    # 말한다 — 산출물이 스스로 모순된다(게이트 correctness 렌즈 검출).
    # 패턴이 설정된 환경에서는 문구가 그대로이므로 골든은 불변이다.
    _no_ticket = "no ticket ID" if ticket_scanned else "ticket not checked"
    _temp_no_ticket = "Temp+NoTicket" if ticket_scanned else "Temp+TicketUnchecked"

    src_names = policy.get("srcaddr_names") or []
    dst_names = policy.get("dstaddr_names") or []
    src_list = policy.get("srcaddr_display") or []
    dst_list = policy.get("dstaddr_display") or []
    svc_list = policy.get("service_display") or []

    expanded_svcs  = _expand(svc_list, svc_groups)
    traffic_type   = classify_traffic_type(src_list, dst_list, user_ranges)
    # **그룹 한 겹이 'ALL' 을 숨긴다.** `set service "SVCGRP"`(멤버에 ALL)은
    # 사실상 전 서비스 허용인데, 펼치기 전 이름만 보면 특정 서비스처럼 읽힌다.
    # 그 탓에 `src=all dst=all service=그룹{ALL,DNS}` 정책이 'Src, Dst, Service
    # all Any·All'(등급 1)에 걸리지 않았다(라운드 43 실측). 펼친 집합도 본다.
    svc_any        = _is_any(svc_list) or _is_any(expanded_svcs)
    is_any_all     = _is_any(src_list) or _is_any(dst_list) or svc_any
    # **AD/DNS 예외는 '그 서비스만' 여는 정책에 준다.** 도메인 컨트롤러는
    # 넓은 출발지·목적지가 정상이라 등급을 낮춰 왔는데, 조건이 '집합에 하나라도
    # 섞여 있으면' 이었다. 그래서 `src=all, dst=all, service=[ALL, DNS]` 처럼
    # **모든 것을 허용하는 정책**이 DNS 를 하나 끼고 있다는 이유로 Critical 이
    # 아니라 Low('티켓만 등록하세요')로 나갔다 — 화면의 판정 기준표는 같은
    # 조건을 Severity 1 로 명시한다(라운드 42 실측).
    # 서비스가 Any/All 이면 그건 AD/DNS 정책이 아니다.
    # **가드와 판정이 같은 집합을 봐야 한다.** 예외 판정은 그룹을 펼친
    # `expanded_svcs` 로 하는데 가드는 펼치기 **전** 목록을 봤다. 그래서
    # `set service "SVCGRP_DC"`(멤버 ALL, DNS)로 한 겹 감싸면 `src=all
    # dst=all` 정책이 그대로 등급 6 '티켓만 등록'으로 나갔다 — 같은 config 에
    # 인라인으로 적은 동일 접근은 등급 1이었다(라운드 43 실측). 비대칭 하나로
    # 예외 범위 축소가 무효가 됐다.
    is_ad_dns      = (bool(set(expanded_svcs) & auth_dns_services)
                      and not _is_any(expanded_svcs))
    is_risky       = bool(set(expanded_svcs) & risky_services)
    is_icmp_only   = bool(expanded_svcs) and set(expanded_svcs) <= icmp_services
    is_expired     = _schedule_has_expired(
        policy, context.get("onetime_schedules") or {}, schedule_val, today)
    is_always      = is_always_schedule(schedule_val)
    sched_date     = get_schedule_date(schedule_val)
    # 'controlled' 는 이 고객의 다중 방화벽 운영 관례다(출발지 인접
    # 방화벽에서 세부 정책을 정의하고 하위 방화벽은 범위를 넓혀 등록).
    # 범용 규칙이 아니므로 프로파일에서 온다 — 기본은 비어 있다(실장비
    # 대조에서 "범용적으로 이렇게 사용하지 않는다"로 확인, 2026-08-06).
    controlled_kw  = customer_rules.get("controlled_keywords", CONTROLLED_KW)
    all_temp_kw    = customer_rules.get("temp_keywords", []) + customer_rules.get("extra_temp_keywords", [])
    has_temp_kw    = any(_kw_in_name(name, kw) for kw in all_temp_kw)
    # 부분 문자열 매칭 — temp 키워드와 달리 경계를 요구하면 안 된다.
    # 실제 정책명이 "ControlledbySourceFW"처럼 붙여 쓴 형태라 경계가 없다.
    # 'controlled'는 길고 특징적인 단어라 오탐 위험도 낮다.
    has_controlled = any(kw.lower() in name.lower() for kw in controlled_kw)

    tags = _compute_tags(
        status, action, hit_count, hit_count_known, last_used, schedule_val,
        name, ritm, expanded_svcs, today, all_temp_kw, dormancy_days, dorm_lbl,
        ticket_scanned=ticket_scanned,
        risky_services=risky_services, icmp_services=icmp_services,
        expired=is_expired,
    )

    def done(sev, reason, recommended=None, cause=""):
        risk, rec, color = SEVERITY_META.get(sev, ("Unknown", "", "#F0EEE7"))
        rec = recommended or rec
        _act = derive_action(sev, reason, rec, cause)
        return {
            "urgency": sev, "risk_level": risk,
            "recommended_action": rec, "reason": reason,
            "action_type": _act,
            "action_label": ACTION_LABELS.get(_act, ""),
            "traffic_type": traffic_type, "color": color, "tags": tags,
        }

    if action != "accept":   # "deny", "" 빈 값 모두 deny 정책으로 처리
        return done(7, f"Action = Deny ('{action}')")
    # Disabled 정책은 예외 규칙들보다 우선 → 항상 2 (Deny만 그보다 먼저 7)
    if status in ("disabled", "disable"):
        # 사실 기반 판정 — 설정상 이미 무효라 "확인 후 삭제"할 게 없다.
        # 추론(미사용 추정)과 같은 문구를 쓰면 확실한 것이 불확실해 보인다
        # (2026-08-10 실장비 대조: 등급 2 전건이 이 문구를 지적).
        return done(2, "Status = Disabled",
                    recommended="Remove — disabled in the configuration, "
                                "so no traffic can match it",
                    cause=CAUSE_INERT)
    # 판정 순서 원칙(감사 A6·A7 + 재비판): 사실(deny·disabled)이 먼저,
    # 그다음 고객의 명시 지정(override), 그다음 '항상 Critical' 고위험 객체,
    # ICMP 예외 같은 일반 면제 규칙은 그 뒤다. 명시 지정이 일반 면제에
    # 지면 설정한 사람 입장에서 오버라이드가 소리 없이 무시된다.
    for obj, sev in customer_rules.get("severity_overrides", {}).items():
        sev = _override_sev(sev)
        if sev is None:      # 등급 번호가 아니면 이 지정은 없는 것으로 본다
            continue
        if _in_obj(obj, name, src_list, dst_list, src_names, dst_names):
            # `-> 5` 는 내부 등급 번호다. `age=None`·`-> 4` 를 지운 릴리스가
            # 같은 화살표를 여기 남겨 실 고객 config 에 계속 인쇄했다
            # (2026-09-10 재비판 F4). 접두 `Override:` 는 유지해야 한다 —
            # `_action_axis` 가 reason 접두로 조치 축을 가른다.
            return done(sev, f"Override: {obj}")
    for obj in customer_rules.get("high_risk_objects", []):
        if _in_obj(obj, name, src_list, dst_list, src_names, dst_names):
            return done(1, f"High-risk object: {obj}")
    # ICMP 전용 정책을 판정 대상에서 뺄지는 방화벽 위치에 달렸다.
    # NIST SP 800-41 r1 §4.1.4는 ICMP 전면 차단이 진단·성능 문제를 일으킨다고
    # 하면서도, 경계 방화벽에서는 허용 타입 외 차단을 권고한다. 내부 방화벽에서만
    # 타당한 규칙이라 프로파일로 켜고 끈다.
    if is_icmp_only and icmp_only_is_keep:
        return done(7, "Service = ICMP only")
    if has_ritm and not is_expired:
        return done(7, f"Valid ITS: {ritm}, Schedule valid")
    if is_any_all and has_controlled:
        return done(7, "Any/All + 'controlled' keyword")

    # 관리자 객체(admin_objects) 정책은 접근 자체가 필요하다고 보고 유지한다.
    # 다만 평문 프로토콜이 섞여 있으면 정책을 없애는 대신 '그 서비스만 제거'를
    # 권고한다. 예외를 무조건 Keep으로 두면 관리자 정책 안의 FTP·TELNET이
    # 검토 대상에서 통째로 사라진다(실 고객 config에서 6건 확인).
    # 정책 삭제·비활성(1·2)보다 우선순위가 낮은 3으로 분류한다.
    for obj in customer_rules.get("admin_objects", []):
        if _in_obj(obj, name, src_list, dst_list, src_names, dst_names):
            # **예외의 전제는 "이 접근이 필요하다" 다.** 광범위 허용(출발지·
            # 목적지 중 하나가 Any + 서비스 ALL)인데 **한 번도 안 쓰였다면**
            # 그 전제를 받쳐 줄 근거가 없다 — '관리자 객체를 가리킨다'는 것
            # 말고는 아무것도 없는데, 그것만으로 가장 위험한 형태의 정책이
            # 검토 대상에서 빠진다(B-23).
            # 실 고객 설정 측정: 관리자 예외 64건 중 이 형태는 0건이었다.
            # 즉 지금 판정은 안 움직이고, 다른 환경에서 생길 구멍만 막는다.
            # (위험 서비스 혼합을 이미 같은 이유로 예외에서 뺀 것과 같은 결.)
            _broad = (_is_any(src_list) or _is_any(dst_list)) and svc_any
            if _broad and hit_count_known and hit_count == 0:
                break          # 예외를 적용하지 않고 일반 판정으로 내려간다
            if is_risky:
                found = sorted(set(expanded_svcs) & risky_services)
                return done(
                    3,
                    f"Admin policy ({obj}) + risky service — remove service only: {', '.join(found)}",
                    recommended=f"Keep policy, remove risky services only ({', '.join(found)})",
                )
            # 여기 도달했다면 유효 티켓이 없다(티켓 검사가 앞에 있다).
            # 예외(면제)와 승인은 다른 축이다 — 역할상 정당한 접근이라도
            # 결재 기록이 없으면 등록을 요청해야 한다. Keep으로 덮으면
            # 미승인 정책이 영구히 검토 대상에서 사라진다(2026-08-10 대조).
            if traffic_type == "Server-User":
                return done(5, f"Admin policy ({obj}), {_no_ticket} — register")
            return done(6, f"Admin policy ({obj}), {_no_ticket} — register")

    if is_risky:
        found = set(expanded_svcs) & risky_services
        non_risky = [s for s in expanded_svcs if s and s not in risky_services]
        is_mixed = bool(non_risky)   # 위험 서비스 + 정상 서비스 혼합

        if is_mixed:
            if hit_count_known and hit_count > 0 and _within_yrs(last_used, today, dorm_yrs):
                # 혼합 + 활성 사용 → 위험 서비스 포트만 제거
                return done(
                    3,
                    f"Risky service mixed + active — remove: {', '.join(sorted(found))}",
                    recommended=f"Keep policy, remove risky services only ({', '.join(sorted(found))})",
                )
            if not hit_count_known:
                # **승인 유효기간 유예** — 신청 1년 이내(스케줄/날짜 근거)의
                # 사용량 미상 정책은 긴급(1)이 아니라 검토(3)다. 절차상 아직
                # 유효한 개통을 정리 대상으로 몰면 판정이 절차와 어긋난다
                # (2026-08-24 Jayden 승인. 확인된 미사용·전면허용은 제외).
                # 전면허용(any-any-any)은 나이와 무관한 구조적 위험 —
                # 유예 대상이 아니다(라운드 77 F1: 위험 서비스를 **추가**하면
                # 오히려 등급이 내려가는 비단조가 생겼다).
                _all3 = (_is_any(src_list) and _is_any(dst_list) and svc_any)
                _basis = "" if _all3 else _approval_window_basis(
                    policy, context.get("onetime_schedules") or {},
                    today, approval_window_days)
                if _basis:
                    return done(
                        3,
                        f"Risky service mixed + usage unknown, within "
                        f"approval window ({_basis}) — review removal: "
                        f"{', '.join(sorted(found))}",
                        recommended=f"Keep policy, remove risky services only ({', '.join(sorted(found))})",
                    )
                # 사용량 CSV 가 없으면 "unused" 는 거짓 단정이다("기록 없음 ≠
                # 미사용", KNOWN_LIMITATIONS). 같은 미지 조건의 Any/All 분기는
                # 이미 "usage unknown" 으로 정직하게 적는데 이 분기만 "unused"
                # 라 단정했다(라운드 50 동적실행 렌즈). 위험 서비스 존재 자체가
                # 강한 신호라 등급 1 은 유지하되(Jayden 라운드 51 승인: 사유
                # 문구만 정정), 사유는 사용량 미상임을 밝힌다.
                # hit 줄 없는 diag 변형은 last_used 만 실려 온다 — 그때
                # "usage unknown" 으로 뭉개면 있는 데이터를 없다고 말하는
                # 것이다(라운드 56 경계값 렌즈, Jayden 라운드 57 승인: 문구만).
                if last_used:
                    return done(1, f"Risky service mixed + hit count unknown (last-used on record) — remove: {', '.join(sorted(found))}")
                return done(1, f"Risky service mixed + usage unknown — remove: {', '.join(sorted(found))}")
            # 여기는 hit_count_known=True 인 fall-through 다. "unused" 로 뭉개면
            # hit>0 인데 last-used 만 오래된 정책(dormant)까지 미사용이라 거짓
            # 서술한다(라운드 52 동적실행 렌즈). 바로 아래 Any/All 분기가 이미
            # 쓰는 3분할과 같은 말로 정직하게 적는다 — 등급은 어느 경우든 1 유지.
            _tail = f" — remove: {', '.join(sorted(found))}"
            if hit_count == 0:
                return done(1, f"Risky service mixed + unused (Hit=0){_tail}")
            if last_used:
                return done(1, f"Risky service mixed + dormant (last used > {dorm_lbl}){_tail}")
            # 기록 없음 ≠ 미사용 확정 — 위험 서비스 존재로 등급 1 유지하되 정직하게.
            return done(1, f"Risky service mixed + Hit>0 but no last-used record{_tail}")
        if not hit_count_known:
            _all3 = (_is_any(src_list) and _is_any(dst_list) and svc_any)
            _basis = "" if _all3 else _approval_window_basis(
                policy, context.get("onetime_schedules") or {},
                today, approval_window_days)
            if _basis:
                return done(
                    3,
                    f"Risky service only ({', '.join(sorted(found))}) + usage "
                    f"unknown, within approval window ({_basis}) — review",
                    recommended=f"Keep policy, remove risky services only ({', '.join(sorted(found))})",
                )
        return done(1, f"Risky service only: {', '.join(sorted(found))}")

    src_dst_any = _is_any(src_list) or _is_any(dst_list)
    all_three_any = _is_any(src_list) and _is_any(dst_list) and svc_any

    # ── 명시된 종료일이 남은 정책은 지금 끄라고 하지 않는다 ──────────────
    # (2026-08-28 Jayden 지시 — 안 A)
    #
    # **위치가 규칙의 절반이다.** 두 가지를 지킨다.
    #
    # ① 위험 서비스 블록 *뒤*에 있다 — 위험 서비스(FTP·TELNET…)는 종료일이
    #    남았든 아니든 유예 대상이 아니다. 평문 프로토콜이 열려 있다는 것은
    #    미사용 여부와 무관한 구조적 위험이고, 유예하면 "위험 서비스를
    #    추가하면 등급이 내려가는" 비단조가 생긴다(라운드 77 F1).
    #
    # ② **1·2 가 나오는 자리에만 건다.** 블록 앞에 조기 반환으로 두었더니
    #    이미 3 이상이던 판정까지 3 으로 끌어올렸다 — 실 골든에서 standby/DR
    #    완화(6)가 3 으로, S-S 등록일 미상(4)이 3 으로 **올라갔다**. 완화하러
    #    넣은 규칙이 등급을 올리는 것이다. 라운드 77 F3 가 승인 유예에서
    #    똑같이 겪고 각 지점 가드로 고친 그 함정이라, 여기서도 같게 한다.
    #    후보 목록은 1·2 만 올리므로(_DISABLE_URGENCIES) 3 이상은 이미
    #    "지금 끄라"가 아니다 — 건드릴 이유가 없다.
    _planned_end = _planned_end_date(
        policy, context.get("onetime_schedules") or {}, today)

    def _planned_defer():
        return done(
            3,
            f"Scheduled to end {_planned_end.isoformat()} — still within its "
            f"planned life, so it is not proposed for removal yet",
            recommended=f"Re-check after {_planned_end.isoformat()}; if the "
                        "schedule is extended, assess it again then")

    if src_dst_any:
        if is_ad_dns:
            return done(6, "Src/Dst Any·All + AD/DNS service")
        if all_three_any:
            if _planned_end:
                return _planned_defer()
            return done(1, "Src, Dst, Service all Any·All")
        if hit_count_known and hit_count > 0 and _within_yrs(last_used, today, dorm_yrs):
            if traffic_type == "Server-User":
                return done(3, f"Src/Dst Any·All + active (within {dorm_lbl}) + server ↔ user")
            if traffic_type == "Server-Server":
                return done(4, f"Src/Dst Any·All + active (within {dorm_lbl}) + server ↔ server")
            return done(3, f"Src/Dst Any·All + active (within {dorm_lbl})")
        if not hit_count_known:
            # 광범위 허용 + 사용량 미상 — 미사용 '확정' 서술 금지(감사 A2).
            # Any/All 자체가 검토 사유이므로 3으로 두고 CSV 로드를 안내한다.
            # last_used 가 실려 왔으면 "no usage data" 는 거짓이다 — hit 만
            # 미상이라고 사실대로 적는다(라운드 56, 등급 불변).
            if last_used:
                return done(3, "Src/Dst Any·All + hit count unknown (last-used on record) — review")
            return done(3, "Src/Dst Any·All + usage unknown (no usage data) — review")
        if hit_count == 0:
            reason = "Src/Dst Any·All + unused (Hit=0)"
        elif last_used:
            reason = f"Src/Dst Any·All + dormant (last used > {dorm_lbl})"
        else:
            # 기록 없음 ≠ 장기 미사용 확정 (재비판 NEW-BUG). 등급 근거는
            # 광범위 허용 + 활성 사용 증거 부재이므로 1을 유지하되 정직하게 쓴다.
            reason = "Src/Dst Any·All + Hit>0 but no last-used record"
        if _planned_end:
            return _planned_defer()
        return done(1, reason)

    if svc_any:   # 서비스만 ALL인 경우
        if is_ad_dns:
            return done(6, "Service ALL + AD/DNS")
        if hit_count_known and hit_count > 0 and _within_yrs(last_used, today, dorm_yrs):
            if traffic_type == "Server-User":
                return done(5, f"Service ALL + active (within {dorm_lbl}) + server ↔ user")
            if traffic_type == "Server-Server":
                return done(4, f"Service ALL + active (within {dorm_lbl}) + server ↔ server")
            return done(3, f"Service ALL + active (within {dorm_lbl})")
        if not hit_count_known:
            if last_used:   # "no usage data" 거짓 방지 — 형제 분기와 같은 규칙
                return done(3, "Service ALL + hit count unknown (last-used on record) — review")
            return done(3, "Service ALL + usage unknown (no usage data) — review")
        if hit_count == 0:
            reason = "Service ALL + unused (Hit=0)"
        elif last_used:
            reason = f"Service ALL + dormant (last used > {dorm_lbl})"
        else:
            # 기록 없음 ≠ 장기 미사용 확정 (재비판 NEW-BUG). 등급 근거는
            # 광범위 허용 + 활성 사용 증거 부재이므로 1을 유지하되 정직하게 쓴다.
            reason = "Service ALL + Hit>0 but no last-used record"
        if _planned_end:
            return _planned_defer()
        return done(1, reason)
    if has_temp_kw and not has_ritm:
        if hit_count_known and hit_count > 0:
            if last_used and not _within_yrs(last_used, today, dorm_yrs):
                # Last Used >= dormancy
                if not _within_yrs(last_used, today, long_yrs):
                    # Last Used >= long dormancy → 삭제 후보
                    return done(2, f"{_temp_no_ticket}, Hit>0, Last Used >= {long_lbl}")
                # dormancy <= Last Used < long dormancy → DT 검토
                if traffic_type == "Server-User":
                    return done(3, f"{_temp_no_ticket}, Hit>0, Last Used {mid_lbl}, server ↔ user")
                return done(4, f"{_temp_no_ticket}, Hit>0, Last Used {mid_lbl}, server ↔ server")
            # Last Used < dormancy 또는 미상 → ITS 요청
            if traffic_type == "Server-User":
                return done(5, f"{_temp_no_ticket}, Hit>0, Last Used within {dorm_lbl}, server ↔ user")
            return done(6, f"{_temp_no_ticket}, Hit>0, Last Used within {dorm_lbl}, server ↔ server")
        if hit_count_known:
            if _planned_end:
                return _planned_defer()
            return done(1, f"{_temp_no_ticket}, Hit=0 (Unused)")
        # 사용량 미상(CSV 미로드)을 '미사용 확정'으로 승격하지 않는다(감사 A1,
        # KNOWN_LIMITATIONS "No record ≠ not used"). 임시 명명+무티켓 자체는
        # 검토 사유이므로 3(Needs review)으로 남긴다.
        # last_used 가 실려 왔으면 "no usage data" 는 거짓이다 — G3 세 형제
        # 분기와 같은 규칙의 네 번째 지점(라운드 58 완성도 렌즈, Jayden
        # 라운드 59 승인: 문구만, 등급 불변).
        if last_used:
            return done(3, f"{_temp_no_ticket}, hit count unknown (last-used on record) — review")
        return done(3, f"{_temp_no_ticket}, usage unknown (no usage data) — review")

    if is_expired:
        # **이건 확정이 아니라 이름에서 온 추론이다.** APO 는
        # `config firewall schedule` 을 파싱하지 않으므로, 스케줄이 정말
        # 만료됐는지 알 방법이 없다. 값이 6자리 숫자면 YYMMDD onetime 이라고
        # 짐작할 뿐인데, 요청일자를 이름으로 쓴 **recurring** 스케줄도 그
        # 모양이다(현장에서 흔한 관례).
        #
        # 그 짐작을 '확정'처럼 말했더니, 어제도 매칭됐고 히트가 98,234 인
        # 정책에 "the schedule ended, so no traffic can match it" 이 붙었다
        # (라운드 42 실측). 반증 증거를 근거 없는 추론이 덮은 것이다.
        # 사용 흔적이 있으면 그 흔적이 이긴다 — 짐작은 검토 사유로만 남긴다.
        # **반증이 있을 때만 뒤집는다.** '히트가 있다'만으로는 부족하다 —
        # 만료 전에 쓰이다 멈춘 정책이 정확히 그 모습이고, 그건 추론과
        # 모순되지 않는다. 모순되는 것은 **추론한 만료일 이후의 사용 흔적**
        # 하나뿐이다(라운드 42: 스케줄 260331 인데 2026-07-01 에 매칭됐다).
        # **위 문단은 종료일을 이름에서만 읽던 시절의 이야기다.** config 의
        # `firewall schedule onetime` 을 파싱하게 된 뒤로는 근거가 둘이고,
        # 둘은 확신의 무게가 다르다. 사실을 짐작처럼 말하지 않는다.
        _sched_dt, _sched_src = _schedule_end(
            policy, context.get("onetime_schedules") or {}, schedule_val)
        _refuted = bool(last_used and _sched_dt and last_used > _sched_dt)
        _from_config = (_sched_src == "config")
        if _refuted:
            _lead = (f"One-time schedule {schedule_val} ended "
                     f"{_sched_dt.isoformat()}" if _from_config
                     else f"Schedule name looks expired ({schedule_val})")
            return done(3, f"{_lead} but traffic matched it later ({last_used}) "
                           "— check the schedule object",
                        recommended=(
                            "Check the schedule object on the device — the "
                            "configuration says this one-time schedule has "
                            "ended, but traffic matched it afterwards"
                            if _from_config else
                            "Check the schedule object on the device; this "
                            "name may be a recurring schedule rather than a "
                            "one-time date"))
        if _from_config:
            return done(2,
                        f"One-time schedule {schedule_val} ended "
                        f"{_sched_dt.isoformat()} (from the configuration)",
                        recommended="This one-time schedule has ended, so the "
                                    "policy can no longer match traffic — it "
                                    "can be removed",
                        cause=CAUSE_MAYBE_EXPIRED)
        return done(2, f"Schedule name looks expired: {schedule_val}",
                    recommended=f"Check the schedule object ({schedule_val}) on "
                                "the device — if it is a one-time schedule that "
                                "ended, this policy can be removed",
                    cause=CAUSE_MAYBE_EXPIRED)

    if hit_count_known and hit_count == 0 and action == "accept":
        # **대기 경로(backup/DR)의 무트래픽은 정상이다** — 확인된 Hit=0 이
        # 근거의 전부인 2등급 3형제에서만 완화한다(각 지점에 가드). 위험
        # 서비스·전면허용 같은 구조적 위험은 위 분기에서 이미 결정돼 여기
        # 오지 않고, 4등급(등록일 미상)·미래 스케줄(6)·판정불가(0)는
        # 완화 대상이 아니다(라운드 77 F3).
        _kw_raw = rules_cfg.get("standby_interface_keywords")
        # None = 미설정(내장 기본). [] = 명시적으로 끔 — or 폴백을 쓰면
        # 빈 목록이 기본값을 부활시켜 끄기 스위치가 새는 클래스(라운드 45).
        _standby_kw = ({str(k).strip().lower() for k in _kw_raw if str(k).strip()}
                       if _kw_raw is not None else set(STANDBY_INTF_KEYWORDS))
        _standby = _standby_intf(policy, _standby_kw)

        def _standby_done():
            # 완화는 **확인된 Hit=0 이 근거의 전부인 2등급 3형제에만** 건다.
            # 블록 상단 조기 반환으로 두면 4등급(등록일 미상)·6등급(미래
            # 스케줄)·판정불가(0)까지 6으로 승격돼 승인 범위를 넘는다
            # (라운드 77 F3 — 특히 '판정불가'가 판정이 돼 검증 표본의
            # 등급0 제외 규칙을 우회했다).
            return done(
                6,
                f"Hit=0, but interface '{_standby}' looks like a "
                "standby/DR path — zero traffic is expected there; "
                "register instead of removing",
                recommended="Confirm it is a backup/DR path and register "
                            "a ticket — traffic counters cannot prove a "
                            "standby policy unused",
            )
        age = _age(request_date, today)
        if traffic_type == "Server-User":
            if age is None or age >= 1:
                if _standby:
                    return _standby_done()
                # 종료일이 남았으면 유예 — standby 완화(6)보다 뒤에 둔다.
                # 앞에 두면 6 이 3 으로 **올라간다**(라운드 77 F3 와 같은 결).
                if _planned_end:
                    return _planned_defer()
                # **내부 표현을 고객 문서에 인쇄하지 않는다.** `age=None` 은
                # 파이썬 None 이 그대로 샌 것이고, 실 config 에서 53행이나
                # 유료 워크북의 Reason 칸에 찍혔다(2026-09-10 데모 리허설).
                # 등록일을 아는 경우의 문구는 **그대로 둔다** — 골든 불변.
                return done(2, "Hit=0, Accept, Server-User, "
                            + (f"age={_fmt(age)}" if age is not None
                               else "registration date unknown"))
        elif traffic_type == "Server-Server":
            if age is None:
                # `-> 4` 는 내부 등급 번호다. 감사 문서에 이런 화살표가 있으면
                # 읽는 사람이 도구의 완성도를 의심한다.
                return done(4, "Hit=0, Accept, server ↔ server, "
                            "registration date unknown")
            if is_always:
                if age > 1:
                    if _standby:
                        return _standby_done()
                    # is_always 분기라 _planned_end 는 None 이다(always 에는
                    # 종료일이 없다). 대칭을 위해 남겨 둔다 — 나중에 이
                    # 분기의 조건이 바뀌어도 규칙이 빠지지 않는다.
                    if _planned_end:
                        return _planned_defer()
                    return done(2, f"Hit=0, Accept, server ↔ server, always, age={_fmt(age)}yr > 1")
            else:
                if sched_date:
                    # 만료된 스케줄은 위에서 이미 2로 확정됐으므로 여기 오는
                    # sched_date는 항상 미래다(sched_age < 0). 과거 스케줄용
                    # 상향(4) 분기는 도달 불가라 제거했다 — YYMMDD 전수 실험으로
                    # 확인(감사 A10). inventory.md R18의 2/4/6 서술은 2/6이 실제다.
                    # **하지 않은 비교를 사유에 적고 있었다.** 위 주석대로 여기
                    # 오는 스케줄은 항상 미래라 `sched_age` 는 늘 ≤ 0 이고,
                    # `ss_schedule_age_years` 와 비교하는 코드는 어디에도 없다.
                    # 그런데 사유는 "sched_age=-0.6yr <= 2 -> 6" 이라 적어,
                    # 고객이 그 값을 1↔20 으로 바꿔도 숫자만 바뀌는 **가짜
                    # 근거**를 리포트에 실었다. 게다가 음수 연수가 나갔다
                    # (라운드 45 실측). 아는 사실만 적는다 — 스케줄이 아직
                    # 시작 전이라는 것.
                    days_ahead = (sched_date - today).days
                    return done(6, f"Hit=0, server ↔ server traffic, schedule {schedule_val} starts "
                                   f"in {days_ahead}d (not yet active)")
                else:
                    if age > 1:
                        if _standby:
                            return _standby_done()
                        # 스케줄 이름이 YYMMDD 가 아니어서 sched_date 는 없지만,
                        # onetime 스케줄 **객체**에 종료일이 있을 수 있다 —
                        # 그쪽이 config 사실이다(_planned_end_date 우선순위 ①).
                        if _planned_end:
                            return _planned_defer()
                        return done(2, f"Hit=0, server ↔ server traffic, age={_fmt(age)}yr > 1")

    if traffic_type == "Unknown":
        return done(0, "Unknown traffic type — set User IP ranges first")

    # 절대 hit 수 기준 저사용 판정.
    # 프로파일에서 끄면(use_absolute_hit_threshold=false) 이 두 블록을 건너뛴다.
    # 절대 수치는 트래픽 볼륨을 가정하고, hit 카운터는 재부팅·HA 페일오버로
    # 리셋되므로 조직 고유 기준일 때만 의미가 있다(docs/inventory.md Q4/Q9).
    if use_absolute_hit:
        if traffic_type == "Server-User" and su_multiplier is not None:
            age      = _age(request_date, today)
            reg_year = request_date.year if request_date else reg_fallback_year
            if reg_year is not None:
                threshold = (today.year - reg_year) * su_multiplier
                if hit_count_known and (age is None or age > 1) and hit_count < threshold:
                    # Last Used < dormancy → 최근 사용 중 → Severity 5 (ITS 요청)
                    if _within_yrs(last_used, today, dorm_yrs):
                        return done(5, f"Server ↔ user traffic, low hit ({hit_count}<{threshold}) + last used within {dorm_lbl} — ITS request")
                    # _within_yrs 의 False 는 "1년 초과"와 "기록 없음"을 합친다 —
                    # 기록이 없는데 "last used > 1yr" 라 적으면 하지 않은 비교를
                    # 사유에 적는 것이다(라운드 60 완성도 렌즈 — G3 네 형제가
                    # 고친 정직성 규칙의 다섯 번째이자 마지막 지점, Jayden
                    # 라운드 61 승인: 문구만, 등급 3 불변. 골든 s3 재생성).
                    # 계산식에 등록연도를 인쇄하는데, 그 연도가 **추정치**면
                    # 존재하지 않는 사실을 식으로 보여 주는 셈이다
                    # (`(2026-2021x100)` — 2021 은 프로파일 폴백이다).
                    _calc = (f" ({today.year}-{reg_year}x{su_multiplier})"
                             if request_date else
                             f" (registration date unknown; assumed "
                             f"{reg_year} for the threshold)")
                    if last_used:
                        return done(3, f"Server ↔ user traffic, hit {hit_count} < {threshold}{_calc}, last used > {dorm_lbl}")
                    return done(3, f"Server ↔ user traffic, hit {hit_count} < {threshold}{_calc}, no last-used record")

        if traffic_type == "Server-Server" and ss_hit_threshold is not None:
            age     = _age(request_date, today)
            eff_age = age if age is not None else (
                float(today.year - reg_fallback_year) if reg_fallback_year is not None else None
            )
            if hit_count_known and eff_age is not None and eff_age > 2 and hit_count < ss_hit_threshold:
                # **모르는 사실을 구체적인 수치로 단정하지 않는다.**
                # `request_date` 가 없으면 프로파일의 `registration_fallback_year`
                # 로 나이를 만들어 "age=5.0yr" 라고 인쇄했다 — 같은 파일이 다른
                # 분기에서는 같은 결측을 "registration date unknown" 이라고
                # 정직하게 쓴다. 한 리포트 안에 두 가지 말이 있었고, 실 고객
                # config 1,525건 중 **256건(17%)** 이 그 문장을 받았다
                # (9라운드 F4). 임계값 계산에 폴백을 쓰는 것은 그대로 두되,
                # 사유는 가정임을 밝힌다. 이 레포가 다섯 번 고친 클래스다.
                _age_txt = (f"age={_fmt(eff_age)}yr" if age is not None
                            else f"registration date unknown (assumed "
                                 f"{reg_fallback_year} for the threshold)")
                return done(4, f"Server ↔ server traffic, {_age_txt}, hit {hit_count} < {ss_hit_threshold}")

    for obj in customer_rules.get("user_segment_objects", []):
        if _in_obj(obj, name, src_list, dst_list, src_names, dst_names):
            return done(5, f"User-segment object: {obj}")
    if traffic_type == "Server-User":
        age = _age(request_date, today)
        # 등록일 미상을 0년(신규)으로 단정하면 사유가 거짓이 된다(감사 A9).
        if not has_ritm and age is not None and age <= 1:
            return done(5, f"Server ↔ user traffic, registered within 1yr, {_no_ticket}")
        # **내부 약어를 고객 산출물에 그대로 내보내면 안 된다.** 컨설턴트가
        # "S-U fallback" 을 설명할 방법이 없다(라운드 45 지적).
        return done(5, "Server ↔ user traffic, no other finding")

    if is_ad_dns and hit_count_known and hit_count > 0:
        return done(6, "AD_AUTH or DNS, Hit > 0")
    # **인프라와 관리망은 한 목록이다.** 예전에는 mgmt_objects 를 따로 돌면서
    # 사유만 "Mgmt-segment object" 로 달랐다 — 등급은 둘 다 6 이라 판정은
    # 같은데 설정 화면에는 칸이 둘이었고, 사용자는 "어디 넣지?"를 고민해야
    # 했다(실사용 지적). to_customer_rules 가 두 목록을 infra_objects 로
    # 합쳐 주므로 기존 설정의 mgmt 값도 여기서 그대로 걸린다.
    for obj in customer_rules.get("infra_objects", []):
        if _in_obj(obj, name, src_list, dst_list, src_names, dst_names):
            return done(6, f"Infra object: {obj}")
    if traffic_type == "Server-Server":
        age = _age(request_date, today)
        if not has_ritm and age is not None and age <= 2:
            return done(6, f"Server ↔ server traffic, registered within 2yr, {_no_ticket}")
        # **끄기 스위치가 새고 있었다.** 이 줄은 `if use_absolute_hit:` 블록
        # 밖에 있으면서 임계값 50 을 하드코딩했다. 그래서 프로파일에서 절대
        # 히트 규칙을 꺼도(`use_absolute_hit_threshold: false`), 또 임계값을
        # 5000 으로 올려도, 사유는 여전히 "Hit 60 >= 50" 이라 말했다 —
        # 설정한 적 없는 기준을 근거로 댄 것이다(라운드 45 실측).
        # 등급은 어느 분기든 6이라 판정은 변하지 않는다. 사유만 사실로 만든다.
        if (use_absolute_hit and ss_hit_threshold is not None
                and hit_count_known and hit_count >= ss_hit_threshold):
            return done(6, f"Server ↔ server traffic, hit {hit_count} >= {ss_hit_threshold}")
        return done(6, "Server ↔ server traffic, no other finding")

    return done(0, "Cannot assess")


def _compute_tags(status, action, hit_count, hit_count_known, last_used_dt,
                  schedule_val, name, ritm, expanded_svcs, today, all_temp_kw,
                  dormancy_days=365, dorm_lbl="1yr",
                  ticket_scanned=True,
                  risky_services=None, icmp_services=None,
                  expired=None) -> list:
    """**태그는 판정과 같은 자를 써야 한다.**

    여기만 모듈 상수(`RISKY_SERVICES`·`ICMP_SERVICES`)를 보고 판정 본문은
    프로파일 목록을 봤다. `profiles/default.yaml` 이 "OT 환경이라면 HTTP·NFS
    를 추가하라" 고 **편집을 안내**하는데, 그 안내를 따르면 두 자가 갈린다:
    HTTP 를 위험 목록에 넣으면 등급은 1 "Risky service only: HTTP" 인데
    태그에는 `Risky Service` 가 **없고**, 반대로 FTP 를 뺐는데 태그는 붙는다.
    화면에서 "Risky Service" 로 거르면 **Critical 로 판정된 바로 그 정책이
    빠진다**(9라운드 F3 실측).

    라운드 45 가 dormancy 축에서 고친 "태그와 사유는 같은 자를 쓴다" 규칙의
    남은 두 지점이다. 기본 프로파일에서는 두 집합이 같으므로 골든 불변.
    """
    risky_services = RISKY_SERVICES if risky_services is None else risky_services
    icmp_services = ICMP_SERVICES if icmp_services is None else icmp_services
    tags = []
    if status in ("disabled", "disable"):
        tags.append("Disabled")
    if hit_count_known and hit_count == 0:
        tags.append("No HitCount")
    # **태그와 사유가 같은 자를 써야 한다.** 사유는 `_within_yrs`
    # (`days/365.25 < dormancy_days/365.0`)로 재는데 태그는 `days >
    # dormancy_days` 로 쟀다. 분모가 달라 실제 컷오프가 어긋나, 같은 행에서
    # 사유는 "활성(within 2000d)", 태그는 "Last Used > 2000d" 라고 말했다 —
    # UI 가 허용하는 1~3650 중 **2,190개 값(60%)** 에 그런 날이 있었다
    # (라운드 45 실측 6,048건). 등급은 사유 쪽이 정하므로, 태그를 사유에
    # 맞춘다(등급 불변).
    if last_used_dt and not _within_yrs(last_used_dt, today, dormancy_days / 365.0):
        tags.append(f"Last Used > {dorm_lbl}")
    # **만료 여부는 판정이 쓴 값을 그대로 받는다.** 여기서 다시 계산하면
    # 판정은 onetime 종료일(config 사실)을 보고 태그는 이름만 봐서, 같은
    # 정책이 sev 2 "Expired schedule" 인데 태그에는 `Expired Schedule` 이
    # 없는 상태가 된다 — 화면에서 태그로 거르면 그 정책이 사라진다.
    # (`feedback_fix_all_display_paths_together`: 표시는 네 곳을 함께 고친다.
    #  값을 넘겨받아 **구조적으로** 갈릴 수 없게 한다.)
    if (is_expired_schedule(schedule_val, today) if expired is None else expired):
        tags.append("Expired Schedule")
    if not name:
        tags.append("No Name")
    if not ticket_scanned:
        # 안 읽은 것을 "없다" 고 하지 않는다 — 위 evaluate_severity 주석 참조.
        tags.append("Ticket unchecked")
    elif not ritm:
        tags.append("No Ticket")
    if any(_kw_in_name(name, kw) for kw in all_temp_kw):
        tags.append("Temp Rule")
    if set(expanded_svcs) & set(risky_services):
        tags.append("Risky Service")
    if action != "accept":   # "deny", "" 빈 값 모두 Deny Rule 태그
        tags.append("Deny Rule")
    if bool(expanded_svcs) and set(expanded_svcs) <= set(icmp_services):
        tags.append("ICMP Only")
    return tags


import re as _re

def _kw_in_name(name: str, kw: str) -> bool:
    """임시 키워드 매칭 — 영문 키워드는 단어 경계 필수.

    단순 부분문자열이면 "G**old**mine", "con**test**"가 임시 정책으로
    오판돼 Critical이 된다(감사 A3). 비ASCII(한글) 키워드는 언어 특성상
    경계 개념이 약해 부분 매칭을 유지한다.
    """
    if not name or not kw:
        return False
    if _re.search(r"[A-Za-z]", kw):
        # 경계는 '문자'만 본다. 숫자를 경계에 넣으면 "temp2"·"test11" 같은
        # 번호 붙은 임시 명명이 전부 미탐된다(재비판 NEW-BUG, 실 config
        # policy 1297 "test11"에서 발생). "attempt"(문자 연속)는 여전히 미매칭.
        return bool(_re.search(
            r"(?<![A-Za-z])" + _re.escape(kw) + r"(?![A-Za-z])",
            name, _re.IGNORECASE))
    return kw in name


def _is_any(val) -> bool:
    # "0.0.0.0/0": show full-configuration 추출 시 "all" 객체가 CIDR로 해석되는 경우
    if val is None:
        return True
    items = val if isinstance(val, list) else [val]
    return any(str(v).lower().strip() in ("all", "any", "", "0.0.0.0/0") for v in items)

def _in_obj(obj: str, name: str, src, dst, src_names=None, dst_names=None) -> bool:
    """정책이 예외 객체에 해당하는가.

    우선순위가 있다:
      1) **주소 객체 이름**과의 부분 일치 — 고객이 예외 목록에 적는 것이
         객체명이므로 이게 본 경로다. 그룹 객체도 여기서 걸린다.
      2) 펼쳐진 주소값(display) — 예외 목록에 CIDR을 적은 경우.
    정책 '이름'은 보지 않는다. "이름에 ADMIN이 들어간다"는 조직마다 다른
    명명 관례일 뿐인데, 그것만으로 정책 전체가 검사 면제되면 감사 도구로서
    위험하다(2026-08-10 대조 정책 583: DNS 정책이 이름 때문에 Keep 판정).
    예외는 고객이 실제로 등록한 **객체**로만 인정한다.
    """
    # **빈 값·None 은 규칙이 아니다.** 프로파일 YAML 에 `- ` 만 있는 줄이
    # 들어가면 `None` 이 되어 판정 전체가 AttributeError 로 죽었고, 빈
    # 문자열이면 반대로 **모든 정책에 매칭**됐다(`"" in anything`) — 전건이
    # `High-risk object: ` 로 뒤집힌다(라운드 45 실측). HTTP 입력은 이미 빈
    # 값을 거르지만 프로파일 로더에는 검증이 없었다.
    needle = str(obj or "").strip().lower()
    if not needle:
        return False
    for t in (src_names or []) + (dst_names or []) + (src or []) + (dst or []):
        if _obj_matches(needle, str(t).lower()):
            return True
    return False


# 짧은 패턴이 단어 속에 우연히 걸리는 것을 막는 최소 길이.
# 실 고객 설정 측정(라운드 45): 단어 속 매칭 21건 중 **17건이 2글자 패턴**
# (`F1`·`F2`)에서 나왔고, 그 17건은 전부 `RFID READER RF19` 처럼 무관한
# 장비였다 — RFID 리더 17대가 '인프라 객체'로 판정 예외를 받고 있었다.
# 반대로 4글자 이상(`MGMT` → `cust-dbmgmtpap`)은 단어 속이어도 정당했다.
# 그래서 "경계를 항상 요구"가 아니라 **짧은 패턴에만 요구**한다.
_MIN_LEN_FOR_INSIDE_WORD = 4
# 경계 문자를 목록으로 두었지만 `or not isalnum()` 이 그것을 완전히 덮어
# **죽은 코드**였다(목록 안 alnum 문자 0개 — 지워도 동작이 안 바뀐다).
# 이 프로젝트가 경계하라고 적어 둔 '아무것도 안 바꾸는 코드'라 지운다.
# 규칙은 하나다: **영숫자가 아니면 경계**. 유니코드 하이픈·전각 문자·탭도
# 자동으로 포함된다(실측 확인).


def _obj_matches(needle: str, hay: str) -> bool:
    """예외 객체 이름이 이 값에 걸리는가 (양쪽 소문자 전제).

    부분문자열 매칭은 이 예외 체계가 실제로 작동하는 방식이다 — 실 설정에서
    '정확히 일치'하는 객체는 **1개뿐**이었고 경계 일치가 45개였다. 규칙을
    통째로 엄격하게 바꾸면 걸려 있던 예외가 사라진다(그건 판정 변화다).
    바꾸는 것은 **짧은 패턴이 단어 한가운데 걸리는 경우**뿐이다.
    """
    if needle not in hay:
        return False
    if len(needle) >= _MIN_LEN_FOR_INSIDE_WORD or hay == needle:
        return True

    # **출현이 여러 번이면 전부 본다.** 첫 출현만 검사했더니, 앞쪽이 단어 속일
    # 때 뒤에 있는 **경계가 깨끗한 출현을 아예 보지 않고** 버렸다 —
    # `RF19-F1` 은 진짜 F1 객체인데 앞의 `RF19` 때문에 예외를 잃었다
    # (라운드 46 실측). 오탐을 막으려다 정탐을 죽인 것이다.
    i = hay.find(needle)
    while i >= 0:
        before = hay[i - 1] if i > 0 else ""
        after = hay[i + len(needle)] if i + len(needle) < len(hay) else ""
        if ((before == "" or not before.isalnum())
                and (after == "" or not after.isalnum())):
            return True
        i = hay.find(needle, i + 1)
    return False

def _expand(svc_list, svc_groups: dict) -> list:
    """서비스 목록 전개 — 중첩 그룹 재귀 (순환 안전).

    1단계 전개만 하면 그룹 속 그룹의 TELNET 같은 위험 서비스를 놓친다
    (감사 A8). 파서의 expand_services와 같은 의미론으로 맞춘다.
    """
    out: set = set()
    stack = list(svc_list or [])
    seen_groups: set = set()
    while stack:
        item = stack.pop()
        if item in svc_groups:
            if item in seen_groups:
                continue
            seen_groups.add(item)
            stack.extend(svc_groups[item])
        else:
            out.add(item)
    return list(out)

def _int(val) -> int:
    try:
        return int(val or 0)
    except Exception:
        return 0

def _parse_hit(val):
    """hit count -> int 또는 None(미상). 천단위 콤마 허용, 쓰레기는 미상.

    nan/inf/"1e400"도 미상이다 — int() 변환이 ValueError/OverflowError를
    던지면 판정 전체가 죽는다(재비판 NEW-BUG).
    """
    if val is None:
        return None
    try:
        if isinstance(val, (int, float)):
            return int(val)
        t = str(val).strip().replace(",", "")
        if t in ("", "-", "N/A", "n/a"):
            return None
        return int(float(t))
    except (ValueError, TypeError, OverflowError):
        return None


def _sane_hit(n):
    """음수 히트는 '사용됐다'가 아니다.

    카운터는 음수가 될 수 없다. 그런데 `-1` 이 그대로 통과해 `hit_count > 0`
    은 거짓, `hit_count == 0` 도 거짓이 되어 **두 분기 모두 빠져나간 뒤**
    "Hit>0 but no last-used record"(= 쓰이고 있다)라는 사유가 붙었다
    (라운드 45 실측). 값을 못 믿겠으면 0 이 아니라 **미상**이다.
    """
    return None if (n is not None and n < 0) else n

def _age(reg_date, today: date):
    if not reg_date:
        return None
    return (today - reg_date).days / 365.25

def _within_yrs(dt, today: date, yrs: float) -> bool:
    if not dt:
        return False
    return (today - dt).days / 365.25 < yrs

def _fmt(v) -> str:
    if v is None:
        return "None"
    return f"{v:.1f}"

def _parse_date(val):
    """날짜/날짜시간 문자열 -> date. FortiGate GUI CSV의 다양한 형식 처리."""
    if not val:
        return None
    s = str(val).strip()
    if s in ("-", "N/A", "n/a", "never", ""):
        return None
    from datetime import datetime
    for fmt in (
        # FortiGate GUI CSV 실제 형식 (날짜+시간)
        "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M",    "%Y-%m-%d %H:%M",
        # 날짜만
        "%Y/%m/%d", "%Y-%m-%d", "%Y%m%d",
        "%d/%m/%Y", "%m/%d/%Y",
    ):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            continue
    return None
