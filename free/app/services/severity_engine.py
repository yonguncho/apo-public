"""
APO Severity Engine — Public / Generic Edition
================================================
NIST SP 800-41 기반 방화벽 정책 긴급도 분류 엔진.
고객별 예외 조건은 실행 디렉토리의 customer_rules.json 파일로 관리합니다.

Severity 기준:
  1 Critical  — 즉시 비활성화 (보안 정책 위반 규칙)
  2 High      — 삭제 필요 (불필요 규칙)
  3 Medium-H  — DT 검토 → 비활성화 또는 유지+ITS
  4 Medium-L  — DT 검토 → 비활성화 또는 유지+ITS
  5 Low-H     — 유지 + ITS Ticket 요청
  6 Low-L     — 유지 + ITS Ticket 요청
  7 None      — 유지 (NIST 기준 적합 규칙)
  0 Unknown   — 판단 불가 (User IP 대역 설정 필요)
"""

import json
import os
from datetime import date
from .schedule_utils import is_expired_schedule, is_always_schedule, get_schedule_date
from .ip_classifier import classify_traffic_type

# ================================================================
# CUSTOMER_RULES — customer_rules.json 에서 로드 (없으면 빈 기본값)
# 필드 설명:
#   high_risk_objects    : 항상 Critical(1)로 분류할 오브젝트 목록
#   user_segment_objects : 사용자 세그먼트 오브젝트 (Low-High S5)
#   mgmt_objects         : 관리 망 오브젝트 (Low-Low S6)
#   infra_objects        : 인프라 오브젝트 (Low-Low S6)
#   admin_objects        : 관리자 전용 정책 오브젝트 (유지 S7)
#   extra_temp_keywords  : 임시 정책 판단에 추가할 키워드
#   severity_overrides   : 특정 오브젝트의 심각도를 직접 지정
# ================================================================
def _load_customer_rules() -> dict:
    default = {
        "high_risk_objects":    [],
        "user_segment_objects": [],
        "mgmt_objects":         [],
        "infra_objects":        [],
        "admin_objects":        [],
        "extra_temp_keywords":  [],
        "severity_overrides":   {},
    }
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "customer_rules.json"),
        os.path.join(os.getcwd(), "customer_rules.json"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                    default.update({k: v for k, v in data.items() if not k.startswith("_")})
                    return default
            except Exception:
                pass
    return default

CUSTOMER_RULES = _load_customer_rules()
# ================================================================

# NIST SP 800-41 / 일반 보안 기준 위험 서비스
RISKY_SERVICES  = {"FTP", "TELNET", "TFTP", "RLOGIN", "RSH", "REXEC"}
AD_DNS_SERVICES = {"AD_AUTH", "DNS", "LDAP", "Kerberos", "LDAPS", "LDAP_UDP"}
ICMP_SERVICES   = {"ALL_ICMP", "ICMP_ALL", "PING", "ALL_ICMP_ALL"}

BASE_TEMP_KW = [
    "임시", "Temp", "temp", "test", "테스트", "작업",
    "migration", "backup", "old", "tmp", "temporary",
    "testing", "trial", "poc", "pilot",
]
CONTROLLED_KW = ["controlled"]

SEVERITY_META = {
    0: ("Unknown",  "판단 불가 — User IP 대역 설정 필요",          "#F1EFE8"),
    1: ("Critical", "즉시 비활성화 (Disable Rule)",                 "#FFCCCC"),
    2: ("High",     "삭제 필요 (Delete Rule)",                      "#D3D1C7"),
    3: ("Medium",   "DT 검토 → 비활성화 또는 유지+ITS (High)",      "#FFE0B2"),
    4: ("Medium",   "DT 검토 → 비활성화 또는 유지+ITS (Low)",       "#B5D4F4"),
    5: ("Low",      "유지 + ITS Ticket 요청 (High)",                "#FFF9C4"),
    6: ("Low",      "유지 + ITS Ticket 요청 (Low)",                 "#C0DD97"),
    7: ("None",     "유지 (Keep Rule)",                             "#9FE1CB"),
}

URGENCY_LABELS = {k: v[0] for k, v in SEVERITY_META.items()}


def evaluate_severity(policy: dict, context: dict) -> dict:
    today       = context.get("today") or date.today()
    svc_groups  = context.get("service_groups", {})
    user_ranges = context.get("user_ranges", [])

    name          = policy.get("name") or ""
    action        = (policy.get("action") or "").lower()
    status        = (policy.get("status") or "").lower()
    schedule_val  = policy.get("schedule") or "always"
    hit_count_raw = policy.get("hit_count")
    hit_count_known = hit_count_raw is not None
    hit_count     = _int(hit_count_raw)
    last_used     = _parse_date(policy.get("last_used"))
    request_date  = _parse_date(policy.get("request_date"))
    ritm          = policy.get("ritm")
    has_ritm      = bool(ritm)

    src_list = policy.get("srcaddr_display") or []
    dst_list = policy.get("dstaddr_display") or []
    svc_list = policy.get("service_display") or []

    expanded_svcs = _expand(svc_list, svc_groups)
    traffic_type  = classify_traffic_type(src_list, dst_list, user_ranges)
    is_any_all    = _is_any(src_list) or _is_any(dst_list) or _is_any(svc_list)
    is_ad_dns     = bool(set(expanded_svcs) & AD_DNS_SERVICES)
    is_risky      = bool(set(expanded_svcs) & RISKY_SERVICES)
    is_icmp_only  = bool(expanded_svcs) and set(expanded_svcs) <= ICMP_SERVICES
    is_expired    = is_expired_schedule(schedule_val, today)
    is_always     = is_always_schedule(schedule_val)
    sched_date    = get_schedule_date(schedule_val)
    all_temp_kw   = BASE_TEMP_KW + CUSTOMER_RULES.get("extra_temp_keywords", [])
    has_temp_kw   = any(kw.lower() in name.lower() for kw in all_temp_kw)
    has_controlled = any(kw.lower() in name.lower() for kw in CONTROLLED_KW)

    tags = _compute_tags(
        status, action, hit_count, hit_count_known, last_used, schedule_val,
        name, ritm, expanded_svcs, today
    )

    def done(sev, reason):
        risk, rec, color = SEVERITY_META.get(sev, ("Unknown", "", "#F1EFE8"))
        return {
            "urgency": sev, "risk_level": risk,
            "recommended_action": rec, "reason": reason,
            "traffic_type": traffic_type, "color": color, "tags": tags,
        }

    # ── 고객 오버라이드 ─────────────────────────────────────────
    for obj, sev in CUSTOMER_RULES.get("severity_overrides", {}).items():
        if _in_obj(obj, name, src_list, dst_list):
            return done(sev, f"Customer override: {obj} → S{sev}")

    # ── 관리자 전용 정책 (S7 유지) ──────────────────────────────
    for obj in CUSTOMER_RULES.get("admin_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(7, f"Admin policy object: {obj}")

    # ── S7 — 즉시 유지 판단 ────────────────────────────────────
    if action == "deny":
        return done(7, "Action = Deny (NIST: Deny rules are by design)")
    if is_icmp_only:
        return done(7, "Service = ICMP only (diagnostic traffic)")
    if has_ritm and not is_expired:
        return done(7, f"Valid change ticket: {ritm}, schedule valid")
    if is_any_all and has_controlled:
        return done(7, "Any/All + 'controlled' keyword")

    # ── S1 — Critical (즉시 비활성화) ──────────────────────────
    # 고객 지정 고위험 오브젝트
    for obj in CUSTOMER_RULES.get("high_risk_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(1, f"High-risk object designated by policy: {obj}")
    # 위험 프로토콜 (NIST SP 800-41 §3.3: legacy insecure protocols)
    if is_risky:
        found = set(expanded_svcs) & RISKY_SERVICES
        return done(1, f"Insecure/legacy protocol (NIST SP 800-41): {', '.join(sorted(found))}")
    # 최소 권한 위반 — ANY/ALL (NIST: least-privilege principle)
    if is_any_all:
        if is_ad_dns:
            return done(6, "Any/All + AD/DNS service → monitor (S6)")
        return done(1, "Source/Destination/Service = Any/All (NIST: violates least-privilege)")
    # 임시 정책 + 티켓 없음
    if has_temp_kw and not has_ritm:
        active = hit_count_known and (hit_count > 0) and _within_yrs(last_used, today, 1)
        if active:
            return done(6, "Temp keyword + no ticket + active use → S6")
        return done(1, "Temporary policy without change ticket (NIST: unauthorized temporary rules)")

    # ── S2 — High (삭제 필요) ──────────────────────────────────
    if status in ("disabled", "disable"):
        return done(2, "Status = Disabled (NIST: remove unused rules)")
    if is_expired:
        return done(2, f"Schedule expired: {schedule_val} (NIST: remove time-limited expired rules)")

    # 히트 없는 accept 규칙
    if hit_count_known and hit_count == 0 and action == "accept":
        age = _age(request_date, today)
        if traffic_type == "Server-User":
            if age is None or age >= 1:
                return done(2, f"Zero-hit Server-User rule, age={_fmt(age)}yr (NIST: remove unused rules)")
        elif traffic_type == "Server-Server":
            if age is None:
                return done(4, "Zero-hit S-S rule, registration date unknown → S4")
            if is_always:
                if age > 1:
                    return done(2, f"Zero-hit S-S, always-on, age={_fmt(age)}yr > 1yr")
            else:
                if sched_date:
                    sched_age = (today - sched_date).days / 365.25
                    if sched_age > 2:
                        return done(4, f"Zero-hit S-S, schedule age={_fmt(sched_age)}yr > 2yr → S4")
                    else:
                        return done(6, f"Zero-hit S-S, schedule age={_fmt(sched_age)}yr ≤ 2yr → S6")
                else:
                    if age > 1:
                        return done(2, f"Zero-hit S-S, age={_fmt(age)}yr > 1yr")

    # ── Unknown — User IP 대역 미설정 ──────────────────────────
    if traffic_type == "Unknown":
        return done(0, "Traffic type unknown — set User IP ranges to enable full classification")

    # ── S3 — Medium-High (Server-User 저활용) ──────────────────
    if traffic_type == "Server-User":
        age      = _age(request_date, today)
        reg_year = request_date.year if request_date else 2021
        threshold = (today.year - reg_year) * 100
        if hit_count_known and (age is None or age > 1) and hit_count < threshold:
            return done(3, f"S-U low utilization: Hit {hit_count} < {threshold} ({today.year}-{reg_year}×100)")

    # ── S4 — Medium-Low (Server-Server 저활용) ─────────────────
    if traffic_type == "Server-Server":
        age     = _age(request_date, today)
        eff_age = age if age is not None else float(today.year - 2021)
        if hit_count_known and eff_age > 2 and hit_count < 50:
            return done(4, f"S-S low utilization: age={_fmt(eff_age)}yr, Hit {hit_count} < 50")

    # ── S5 — Low-High ──────────────────────────────────────────
    for obj in CUSTOMER_RULES.get("user_segment_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(5, f"User segment object: {obj}")
    if traffic_type == "Server-User":
        age = _age(request_date, today) or 0
        if not has_ritm and age <= 1:
            return done(5, "S-U, within 1yr, no ticket")
        return done(5, "S-U fallback → S5")

    # ── S6 — Low-Low ───────────────────────────────────────────
    if is_ad_dns and hit_count_known and hit_count > 0:
        return done(6, "AD/DNS service with active hits → S6")
    for obj in CUSTOMER_RULES.get("infra_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(6, f"Infrastructure object: {obj}")
    for obj in CUSTOMER_RULES.get("mgmt_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(6, f"Management object: {obj}")
    if traffic_type == "Server-Server":
        age = _age(request_date, today) or 0
        if not has_ritm and age <= 2:
            return done(6, "S-S, within 2yr, no ticket")
        if hit_count_known and hit_count >= 50:
            return done(6, f"S-S, Hit {hit_count} ≥ 50 (active)")
        return done(6, "S-S fallback → S6")

    return done(0, "Classification undetermined")


def _compute_tags(status, action, hit_count, hit_count_known, last_used_dt,
                  schedule_val, name, ritm, expanded_svcs, today) -> list:
    tags = []
    if status in ("disabled", "disable"):
        tags.append("Disabled")
    if hit_count_known and hit_count == 0:
        tags.append("No HitCount")
    if last_used_dt and (today - last_used_dt).days > 365:
        tags.append("Last Used > 1yr")
    if is_expired_schedule(schedule_val, today):
        tags.append("Expired Schedule")
    if not ritm:
        tags.append("No ITS Request")
    all_temp = BASE_TEMP_KW + CUSTOMER_RULES.get("extra_temp_keywords", [])
    if any(kw.lower() in name.lower() for kw in all_temp):
        tags.append("Temp Rule")
    if set(expanded_svcs) & RISKY_SERVICES:
        tags.append("Risky Service")
    if action != "accept":
        tags.append("Deny Rule")
    if bool(expanded_svcs) and set(expanded_svcs) <= ICMP_SERVICES:
        tags.append("ICMP Only")
    return tags


def _is_any(val) -> bool:
    if val is None:
        return True
    items = val if isinstance(val, list) else [val]
    return any(str(v).lower().strip() in ("all", "any", "") for v in items)

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
    if not val:
        return None
    s = str(val).strip()
    if s in ("-", "N/A", "n/a", "never", ""):
        return None
    from datetime import datetime
    for fmt in (
        "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M",    "%Y-%m-%d %H:%M",
        "%Y/%m/%d", "%Y-%m-%d", "%Y%m%d",
        "%d/%m/%Y", "%m/%d/%Y",
    ):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            continue
    return None
