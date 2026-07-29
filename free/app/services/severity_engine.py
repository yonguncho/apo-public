"""
APO Severity Engine
===================
고객별 예외 조건은 실행 디렉토리(또는 exe 인접 경로)의 customer_rules.json 파일로 관리한다.
파일이 없으면 중립 기본값(빈 리스트)으로 동작 — 기본 배포본은 이 파일 없이도 정상 동작한다.
customer_rules_loader.py 참고.
"""

from datetime import date
from .schedule_utils import is_expired_schedule, is_always_schedule, get_schedule_date
from .ip_classifier import classify_traffic_type
from .customer_rules_loader import load_customer_rules

# ================================================================
# CUSTOMER_RULES — customer_rules.json 에서 로드 (없으면 중립 기본값)
# ================================================================
CUSTOMER_RULES = load_customer_rules()
# ================================================================

RISKY_SERVICES  = {"FTP", "TELNET", "TFTP", "RLOGIN", "RSH"}
AD_DNS_SERVICES = {"AD_AUTH", "DNS", "LDAP", "Kerberos", "LDAPS"}
ICMP_SERVICES   = {"ALL_ICMP", "ICMP_ALL", "PING", "ALL_ICMP_ALL"}
CONTROLLED_KW   = ["controlled"]

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
ACTION_EXCLUDED       = "EXCLUDED"         # 예외로 판정하지 않음
ACTION_UNKNOWN        = "UNKNOWN"          # 판정 불가

ACTION_LABELS = {
    ACTION_DISABLE:        "Disable now",
    ACTION_REVIEW_REMOVE:  "Review candidate",
    ACTION_DISABLE_FIRST:  "Disable & monitor",
    ACTION_SERVICE_REMOVE: "Remove service only",
    ACTION_REVIEW:         "Needs review",
    ACTION_TICKET:         "Register ticket",
    ACTION_NO_RISK:        "No risk",
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
    "This analysis reads the configuration and usage statistics only. It cannot "
    "tell whether a policy is still needed by the business — confirm with the "
    "policy owner before removing anything.",
    "Request dates, requesters, and ticket IDs are read from policy names and "
    "depend on your naming convention. Names that do not follow it are not parsed.",
]


def derive_action(urgency: int, reason: str, recommended_action: str = "") -> str:
    """등급과 판정 근거로부터 조치 유형을 정한다.

    등급 숫자는 그대로 두고(기존 체계 유지), 조치 축만 따로 뽑는다.
    """
    r = (reason or "").lower()
    rec = (recommended_action or "").lower()

    if "remove risky services only" in rec:
        return ACTION_SERVICE_REMOVE
    if urgency == 0:
        return ACTION_UNKNOWN
    if urgency == 7:
        # 같은 7이라도 '봐도 문제없음'과 '예외라 안 봄'은 다르다.
        if r.startswith("action = deny") or "icmp only" in r:
            return ACTION_NO_RISK
        return ACTION_EXCLUDED
    if urgency == 1:
        return ACTION_DISABLE
    if urgency == 2:
        # 이미 꺼져 있거나 만료된 정책은 삭제 검토 단계,
        # 살아 있는데 미사용인 정책은 비활성화부터가 순서다.
        if "disabled" in r or "expired" in r:
            return ACTION_REVIEW_REMOVE
        return ACTION_DISABLE_FIRST
    if urgency in (3, 4):
        return ACTION_REVIEW
    return ACTION_TICKET

# URGENCY_LABELS 호환성 유지
URGENCY_LABELS = {k: v[0] for k, v in SEVERITY_META.items()}


def evaluate_severity(policy: dict, context: dict) -> dict:
    today       = context.get("today") or date.today()
    svc_groups  = context.get("service_groups", {})
    user_ranges = context.get("user_ranges", [])
    customer_rules = context.get("customer_rules")
    if customer_rules is None:
        customer_rules = CUSTOMER_RULES

    # 판정 임계값. context로 주면 그것을, 없으면 customer_rules에서, 그것도
    # 없으면 현행 SKBA 값을 쓴다(하위호환 — 기존 호출부는 임계값을 넘기지 않는다).
    th = context.get("thresholds") or customer_rules.get("thresholds") or {}
    use_absolute_hit   = th.get("use_absolute_hit_threshold", True)
    su_multiplier      = th.get("su_hit_multiplier", 100)
    ss_hit_threshold   = th.get("ss_hit_threshold", 50)
    reg_fallback_year  = th.get("registration_fallback_year", 2021)

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
    hit_count_known = hit_count_raw is not None   # False = CSV 미로드
    hit_count    = _int(hit_count_raw)
    last_used    = _parse_date(policy.get("last_used"))
    request_date = _parse_date(policy.get("request_date"))
    ritm         = policy.get("ritm")
    has_ritm     = bool(ritm)

    src_list = policy.get("srcaddr_display") or []
    dst_list = policy.get("dstaddr_display") or []
    svc_list = policy.get("service_display") or []

    expanded_svcs  = _expand(svc_list, svc_groups)
    traffic_type   = classify_traffic_type(src_list, dst_list, user_ranges)
    svc_any        = _is_any(svc_list)
    is_any_all     = _is_any(src_list) or _is_any(dst_list) or svc_any
    is_ad_dns      = bool(set(expanded_svcs) & auth_dns_services)
    is_risky       = bool(set(expanded_svcs) & risky_services)
    is_icmp_only   = bool(expanded_svcs) and set(expanded_svcs) <= icmp_services
    is_expired     = is_expired_schedule(schedule_val, today)
    is_always      = is_always_schedule(schedule_val)
    sched_date     = get_schedule_date(schedule_val)
    all_temp_kw    = customer_rules.get("temp_keywords", []) + customer_rules.get("extra_temp_keywords", [])
    has_temp_kw    = any(kw.lower() in name.lower() for kw in all_temp_kw)
    has_controlled = any(kw.lower() in name.lower() for kw in CONTROLLED_KW)

    tags = _compute_tags(
        status, action, hit_count, hit_count_known, last_used, schedule_val,
        name, ritm, expanded_svcs, today, all_temp_kw
    )

    def done(sev, reason, recommended=None):
        risk, rec, color = SEVERITY_META.get(sev, ("Unknown", "", "#F0EEE7"))
        rec = recommended or rec
        return {
            "urgency": sev, "risk_level": risk,
            "recommended_action": rec, "reason": reason,
            "action_type": derive_action(sev, reason, rec),
            "action_label": ACTION_LABELS.get(derive_action(sev, reason, rec), ""),
            "traffic_type": traffic_type, "color": color, "tags": tags,
        }

    for obj, sev in customer_rules.get("severity_overrides", {}).items():
        if _in_obj(obj, name, src_list, dst_list):
            return done(sev, f"Override: {obj} -> {sev}")

    if action != "accept":   # "deny", "" 빈 값 모두 deny 정책으로 처리
        return done(7, f"Action = Deny ('{action}')")
    # ICMP 전용 정책을 판정 대상에서 뺄지는 방화벽 위치에 달렸다.
    # NIST SP 800-41 r1 §4.1.4는 ICMP 전면 차단이 진단·성능 문제를 일으킨다고
    # 하면서도, 경계 방화벽에서는 허용 타입 외 차단을 권고한다. 내부 방화벽에서만
    # 타당한 규칙이라 프로파일로 켜고 끈다.
    if is_icmp_only and icmp_only_is_keep:
        return done(7, "Service = ICMP only")
    # Disabled 정책은 유효 티켓/관리자/특례 객체 규칙보다 우선 → 항상 2 (Deny/ICMP-only는 예외적으로 그보다 먼저 7 처리)
    if status in ("disabled", "disable"):
        return done(2, "Status = Disabled")
    if has_ritm and not is_expired:
        return done(7, f"Valid ITS: {ritm}, Schedule valid")
    if is_any_all and has_controlled:
        return done(7, "Any/All + 'controlled' keyword")

    # 관리자 객체(admin_objects) 정책은 접근 자체가 필요하다고 보고 유지한다.
    # 다만 평문 프로토콜이 섞여 있으면 정책을 없애는 대신 '그 서비스만 제거'를
    # 권고한다. 예외를 무조건 Keep으로 두면 관리자 정책 안의 FTP·TELNET이
    # 검토 대상에서 통째로 사라진다(실 SKBA config에서 6건 확인).
    # 정책 삭제·비활성(1·2)보다 우선순위가 낮은 3으로 분류한다.
    for obj in customer_rules.get("admin_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            if is_risky:
                found = sorted(set(expanded_svcs) & risky_services)
                return done(
                    3,
                    f"Admin policy ({obj}) + risky service — remove service only: {', '.join(found)}",
                    recommended=f"Keep policy, remove risky services only ({', '.join(found)})",
                )
            return done(7, f"Admin policy — keep ({obj})")

    for obj in customer_rules.get("high_risk_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(1, f"High-risk object: {obj}")
    if is_risky:
        found = set(expanded_svcs) & risky_services
        non_risky = [s for s in expanded_svcs if s and s not in risky_services]
        is_mixed = bool(non_risky)   # 위험 서비스 + 정상 서비스 혼합

        if is_mixed:
            if hit_count_known and hit_count > 0 and _within_yrs(last_used, today, 1):
                # 혼합 + 활성 사용 → 위험 서비스 포트만 제거
                return done(
                    3,
                    f"Risky service mixed + active — remove: {', '.join(sorted(found))}",
                    recommended=f"Keep policy, remove risky services only ({', '.join(sorted(found))})",
                )
            return done(1, f"Risky service mixed + unused — remove: {', '.join(sorted(found))}")
        return done(1, f"Risky service only: {', '.join(sorted(found))}")

    src_dst_any = _is_any(src_list) or _is_any(dst_list)
    all_three_any = _is_any(src_list) and _is_any(dst_list) and svc_any

    if src_dst_any:
        if is_ad_dns:
            return done(6, "Src/Dst Any·All + AD/DNS service")
        if all_three_any:
            return done(1, "Src, Dst, Service all Any·All")
        if hit_count_known and hit_count > 0 and _within_yrs(last_used, today, 1):
            if traffic_type == "Server-User":
                return done(3, "Src/Dst Any·All + active (within 1yr) + S-U")
            if traffic_type == "Server-Server":
                return done(4, "Src/Dst Any·All + active (within 1yr) + S-S")
            return done(3, "Src/Dst Any·All + active (within 1yr)")
        return done(1, "Src/Dst Any·All + unused or long inactive")

    if svc_any:   # 서비스만 ALL인 경우
        if is_ad_dns:
            return done(6, "Service ALL + AD/DNS")
        if hit_count_known and hit_count > 0 and _within_yrs(last_used, today, 1):
            if traffic_type == "Server-User":
                return done(5, "Service ALL + active (within 1yr) + S-U")
            if traffic_type == "Server-Server":
                return done(4, "Service ALL + active (within 1yr) + S-S")
            return done(3, "Service ALL + active (within 1yr)")
        return done(1, "Service ALL + unused or long inactive")
    if has_temp_kw and not has_ritm:
        if hit_count_known and hit_count > 0:
            if last_used and not _within_yrs(last_used, today, 1):
                # Last Used >= 1yr
                if not _within_yrs(last_used, today, 2):
                    # Last Used >= 2yr → 삭제 후보
                    return done(2, "Temp+NoTicket, Hit>0, Last Used >= 2yr")
                # 1yr <= Last Used < 2yr → DT 검토
                if traffic_type == "Server-User":
                    return done(3, "Temp+NoTicket, Hit>0, Last Used 1~2yr, S-U")
                return done(4, "Temp+NoTicket, Hit>0, Last Used 1~2yr, S-S")
            # Last Used < 1yr 또는 미상 → ITS 요청
            if traffic_type == "Server-User":
                return done(5, "Temp+NoTicket, Hit>0, Last Used within 1yr, S-U")
            return done(6, "Temp+NoTicket, Hit>0, Last Used within 1yr, S-S")
        reason_sfx = "CSV Not Loaded" if not hit_count_known else "Hit=0 (Unused)"
        return done(1, f"Temp+NoTicket, {reason_sfx}")

    if is_expired:
        return done(2, f"Schedule expired: {schedule_val}")

    if hit_count_known and hit_count == 0 and action == "accept":
        age = _age(request_date, today)
        if traffic_type == "Server-User":
            if age is None or age >= 1:
                return done(2, f"Hit=0, Accept, Server-User, age={_fmt(age)}")
        elif traffic_type == "Server-Server":
            if age is None:
                return done(4, "Hit=0, Accept, S-S, reg date unknown -> 4")
            if is_always:
                if age > 1:
                    return done(2, f"Hit=0, Accept, S-S, always, age={_fmt(age)}yr > 1")
            else:
                if sched_date:
                    sched_age = (today - sched_date).days / 365.25
                    if sched_age > 2:
                        return done(4, f"Hit=0, S-S, sched_age={_fmt(sched_age)}yr > 2 -> 4")
                    else:
                        return done(6, f"Hit=0, S-S, sched_age={_fmt(sched_age)}yr <= 2 -> 6")
                else:
                    if age > 1:
                        return done(2, f"Hit=0, S-S, age={_fmt(age)}yr > 1")

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
                    # Last Used < 1yr → 최근 사용 중 → Severity 5 (ITS 요청)
                    if _within_yrs(last_used, today, 1):
                        return done(5, f"S-U, Low hit ({hit_count}<{threshold}) + Last Used within 1yr — ITS request")
                    return done(3, f"S-U, Hit {hit_count} < {threshold} ({today.year}-{reg_year}x{su_multiplier}), Last Used > 1yr")

        if traffic_type == "Server-Server" and ss_hit_threshold is not None:
            age     = _age(request_date, today)
            eff_age = age if age is not None else (
                float(today.year - reg_fallback_year) if reg_fallback_year is not None else None
            )
            if hit_count_known and eff_age is not None and eff_age > 2 and hit_count < ss_hit_threshold:
                return done(4, f"S-S, age={_fmt(eff_age)}yr, Hit {hit_count} < {ss_hit_threshold}")

    for obj in customer_rules.get("user_segment_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(5, f"User-segment object: {obj}")
    if traffic_type == "Server-User":
        age = _age(request_date, today) or 0
        if not has_ritm and age <= 1:
            return done(5, "S-U, within 1yr, No ticket ID")
        return done(5, "S-U fallback")

    if is_ad_dns and hit_count_known and hit_count > 0:
        return done(6, "AD_AUTH or DNS, Hit > 0")
    for obj in customer_rules.get("infra_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(6, f"Infra object: {obj}")
    for obj in customer_rules.get("mgmt_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(6, f"Mgmt-segment object: {obj}")
    if traffic_type == "Server-Server":
        age = _age(request_date, today) or 0
        if not has_ritm and age <= 2:
            return done(6, "S-S, within 2yr, No ticket ID")
        if hit_count_known and hit_count >= 50:
            return done(6, f"S-S, Hit {hit_count} >= 50")
        return done(6, "S-S fallback")

    return done(0, "Cannot assess")


def _compute_tags(status, action, hit_count, hit_count_known, last_used_dt,
                  schedule_val, name, ritm, expanded_svcs, today, all_temp_kw) -> list:
    tags = []
    if status in ("disabled", "disable"):
        tags.append("Disabled")
    if hit_count_known and hit_count == 0:
        tags.append("No HitCount")
    if last_used_dt and (today - last_used_dt).days > 365:
        tags.append("Last Used > 1yr")
    if is_expired_schedule(schedule_val, today):
        tags.append("Expired Schedule")
    if not name:
        tags.append("No Name")
    if not ritm:
        tags.append("No Ticket")
    if any(kw.lower() in name.lower() for kw in all_temp_kw):
        tags.append("Temp Rule")
    if set(expanded_svcs) & RISKY_SERVICES:
        tags.append("Risky Service")
    if action != "accept":   # "deny", "" 빈 값 모두 Deny Rule 태그
        tags.append("Deny Rule")
    if bool(expanded_svcs) and set(expanded_svcs) <= ICMP_SERVICES:
        tags.append("ICMP Only")
    return tags


def _is_any(val) -> bool:
    # "0.0.0.0/0": show full-configuration 추출 시 "all" 객체가 CIDR로 해석되는 경우
    if val is None:
        return True
    items = val if isinstance(val, list) else [val]
    return any(str(v).lower().strip() in ("all", "any", "", "0.0.0.0/0") for v in items)

def _in_obj(obj: str, name: str, src, dst) -> bool:
    targets = [name] + (src or []) + (dst or [])
    return any(obj.lower() in str(t).lower() for t in targets)

def _expand(svc_list, svc_groups: dict) -> list:
    result = []
    for s in (svc_list or []):
        result.extend(svc_groups.get(s, [s]))
    return list(set(result))

def _int(val) -> int:
    try:
        return int(val or 0)
    except Exception:
        return 0

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
