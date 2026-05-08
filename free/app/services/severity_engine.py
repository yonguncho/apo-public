"""
APO Severity Engine — Public / Generic Edition
================================================
NIST SP 800-41 / CIS Controls based firewall policy risk classification.
Customer-specific exceptions are managed via customer_rules.json.
"""

import json
import os
from datetime import date
from .schedule_utils import is_expired_schedule, is_always_schedule, get_schedule_date
from .ip_classifier import classify_traffic_type

# ================================================================
# CUSTOMER_RULES — loaded from customer_rules.json (empty defaults)
# Fields:
#   high_risk_objects    : Objects always classified Critical (S1)
#   user_segment_objects : User-side segment objects -> Low-High (S5)
#   mgmt_objects         : Management network objects -> Low-Low (S6)
#   infra_objects        : Infrastructure objects -> Low-Low (S6)
#   admin_objects        : Admin-only policy objects -> Keep (S7)
#   extra_temp_keywords  : Additional keywords for temporary rule detection
#   severity_overrides   : Override severity for specific objects {name: 1-7}
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

# NIST SP 800-41 §3.3 — insecure/legacy protocols
RISKY_SERVICES  = {"FTP", "TELNET", "TFTP", "RLOGIN", "RSH", "REXEC"}
AD_DNS_SERVICES = {"AD_AUTH", "DNS", "LDAP", "Kerberos", "LDAPS", "LDAP_UDP"}
ICMP_SERVICES   = {"ALL_ICMP", "ICMP_ALL", "PING", "ALL_ICMP_ALL"}

# General temporary/test rule keywords (language-neutral)
BASE_TEMP_KW = [
    "temp", "tmp", "test", "temporary", "trial", "poc", "pilot",
    "migration", "backup", "old", "deprecated", "legacy",
    "임시", "테스트", "작업", "이관",
]
CONTROLLED_KW = ["controlled"]

SEVERITY_META = {
    0: ("Unknown",  "Set User IP ranges to enable full classification", "#F1EFE8"),
    1: ("Critical", "Disable immediately",                              "#FFCCCC"),
    2: ("High",     "Delete rule",                                      "#D3D1C7"),
    3: ("Medium",   "Review required — disable or formalize",           "#FFE0B2"),
    4: ("Medium",   "Review required — disable or formalize",           "#B5D4F4"),
    5: ("Low",      "Keep + request change ticket",                     "#FFF9C4"),
    6: ("Low",      "Keep + request change ticket",                     "#C0DD97"),
    7: ("None",     "Keep rule",                                        "#9FE1CB"),
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
    # Support both "ritm" (legacy) and "ticket" field names
    ticket        = policy.get("ticket") or policy.get("ritm")
    has_ticket    = bool(ticket)

    src_list = policy.get("srcaddr_display") or []
    dst_list = policy.get("dstaddr_display") or []
    svc_list = policy.get("service_display") or []

    expanded_svcs  = _expand(svc_list, svc_groups)
    traffic_type   = classify_traffic_type(src_list, dst_list, user_ranges)
    svc_any        = _is_any(svc_list)
    is_any_all     = _is_any(src_list) or _is_any(dst_list) or svc_any
    is_ad_dns      = bool(set(expanded_svcs) & AD_DNS_SERVICES)
    is_risky       = bool(set(expanded_svcs) & RISKY_SERVICES)
    is_icmp_only   = bool(expanded_svcs) and set(expanded_svcs) <= ICMP_SERVICES
    is_expired     = is_expired_schedule(schedule_val, today)
    is_always      = is_always_schedule(schedule_val)
    sched_date     = get_schedule_date(schedule_val)
    all_temp_kw    = BASE_TEMP_KW + CUSTOMER_RULES.get("extra_temp_keywords", [])
    has_temp_kw    = any(kw.lower() in name.lower() for kw in all_temp_kw)
    has_controlled = any(kw.lower() in name.lower() for kw in CONTROLLED_KW)

    tags = _compute_tags(
        status, action, hit_count, hit_count_known, last_used, schedule_val,
        name, ticket, expanded_svcs, today
    )

    def done(sev, reason):
        risk, rec, color = SEVERITY_META.get(sev, ("Unknown", "", "#F1EFE8"))
        return {
            "urgency": sev, "risk_level": risk,
            "recommended_action": rec, "reason": reason,
            "traffic_type": traffic_type, "color": color, "tags": tags,
        }

    # ── Customer overrides ──────────────────────────────────────
    for obj, sev in CUSTOMER_RULES.get("severity_overrides", {}).items():
        if _in_obj(obj, name, src_list, dst_list):
            return done(sev, f"Customer override: {obj} -> S{sev}")

    # ── S7 — Keep immediately ───────────────────────────────────
    if action != "accept":
        return done(7, f"Action = Deny ('{action}') — by design")
    if is_icmp_only:
        return done(7, "ICMP-only service (diagnostic traffic)")
    if has_ticket and not is_expired:
        return done(7, f"Valid change ticket: {ticket}, schedule active")
    if is_any_all and has_controlled:
        return done(7, "Any/All scope + 'controlled' keyword (multi-firewall policy)")

    # Admin-designated policy objects -> always Keep
    for obj in CUSTOMER_RULES.get("admin_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(7, f"Admin policy object: {obj}")

    # ── S1 — Critical: disable immediately ─────────────────────
    # Customer-designated high-risk objects
    for obj in CUSTOMER_RULES.get("high_risk_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(1, f"High-risk object (customer-defined): {obj}")

    # NIST SP 800-41 §3.3: insecure/legacy protocols
    if is_risky:
        found = set(expanded_svcs) & RISKY_SERVICES
        non_risky = [s for s in expanded_svcs if s and s not in RISKY_SERVICES]
        is_mixed = bool(non_risky)
        if is_mixed:
            if hit_count_known and hit_count > 0 and _within_yrs(last_used, today, 1):
                result = done(3, f"Mixed risky+normal services, active use — remove risky ports: {', '.join(sorted(found))}")
                result["recommended_action"] = f"Keep rule, remove insecure service(s): {', '.join(sorted(found))}"
                return result
            return done(1, f"Mixed risky+normal services, unused — remove risky ports: {', '.join(sorted(found))}")
        return done(1, f"Insecure/legacy protocol (NIST SP 800-41): {', '.join(sorted(found))}")

    # NIST: Least-privilege — overly permissive rules
    src_dst_any   = _is_any(src_list) or _is_any(dst_list)
    all_three_any = _is_any(src_list) and _is_any(dst_list) and svc_any

    if src_dst_any:
        if is_ad_dns:
            return done(6, "Source/destination Any/All + AD/DNS service")
        if all_three_any:
            return done(1, "Source, destination, AND service all Any/All (violates least-privilege)")
        if hit_count_known and hit_count > 0 and _within_yrs(last_used, today, 1):
            if traffic_type == "Server-User":
                return done(3, "Source/dest Any/All + active use (< 1yr) + Server-User")
            if traffic_type == "Server-Server":
                return done(4, "Source/dest Any/All + active use (< 1yr) + Server-Server")
            return done(3, "Source/dest Any/All + active use (< 1yr)")
        return done(1, "Source/dest Any/All + unused or long-idle (violates least-privilege)")

    if svc_any:
        if is_ad_dns:
            return done(6, "Service ALL + AD/DNS service")
        if hit_count_known and hit_count > 0 and _within_yrs(last_used, today, 1):
            if traffic_type == "Server-User":
                return done(5, "Service ALL + active use (< 1yr) + Server-User")
            if traffic_type == "Server-Server":
                return done(4, "Service ALL + active use (< 1yr) + Server-Server")
            return done(3, "Service ALL + active use (< 1yr)")
        return done(1, "Service ALL + unused or long-idle (violates least-privilege)")

    # Temporary rule without change ticket (CIS Control 11)
    if has_temp_kw and not has_ticket:
        if hit_count_known and hit_count > 0:
            if last_used and not _within_yrs(last_used, today, 1):
                if not _within_yrs(last_used, today, 2):
                    return done(2, "Temp rule, no ticket, last used > 2yr ago — delete")
                if traffic_type == "Server-User":
                    return done(3, "Temp rule, no ticket, last used 1-2yr ago, Server-User")
                return done(4, "Temp rule, no ticket, last used 1-2yr ago, Server-Server")
            if traffic_type == "Server-User":
                return done(5, "Temp rule, no ticket, active use (< 1yr), Server-User")
            return done(6, "Temp rule, no ticket, active use (< 1yr), Server-Server")
        reason_sfx = "no CSV loaded" if not hit_count_known else "hit count = 0 (unused)"
        return done(1, f"Temporary rule without change ticket ({reason_sfx})")

    # ── S2 — High: delete rule ──────────────────────────────────
    if status in ("disabled", "disable"):
        return done(2, "Rule disabled — remove to reduce attack surface (NIST SP 800-41)")
    if is_expired:
        return done(2, f"Schedule expired: {schedule_val} — rule no longer needed")

    # Zero-hit accept rules
    if hit_count_known and hit_count == 0 and action == "accept":
        age = _age(request_date, today)
        if traffic_type == "Server-User":
            if age is None or age >= 1:
                return done(2, f"Zero-hit Server-User rule, age={_fmt(age)}yr — likely unused")
        elif traffic_type == "Server-Server":
            if age is None:
                return done(4, "Zero-hit Server-Server rule, creation date unknown")
            if is_always:
                if age > 1:
                    return done(2, f"Zero-hit Server-Server, always-on, age={_fmt(age)}yr > 1yr")
            else:
                if sched_date:
                    sched_age = (today - sched_date).days / 365.25
                    if sched_age > 2:
                        return done(4, f"Zero-hit Server-Server, schedule age={_fmt(sched_age)}yr > 2yr")
                    else:
                        return done(6, f"Zero-hit Server-Server, schedule age={_fmt(sched_age)}yr <= 2yr")
                else:
                    if age > 1:
                        return done(2, f"Zero-hit Server-Server, age={_fmt(age)}yr > 1yr")

    # ── Unknown traffic type ────────────────────────────────────
    if traffic_type == "Unknown":
        return done(0, "Traffic type unknown — configure User IP ranges for full classification")

    # ── S3 — Medium-High: Server-User low utilization ───────────
    if traffic_type == "Server-User":
        age      = _age(request_date, today)
        # Expected ~100 hits/year; configurable via severity_overrides
        age_yrs  = age if age is not None else 3.0
        threshold = max(int(age_yrs * 100), 50)
        if hit_count_known and (age is None or age > 1) and hit_count < threshold:
            if _within_yrs(last_used, today, 1):
                return done(5, f"Server-User low utilization (hit {hit_count} < {threshold}), active use < 1yr — request ticket")
            return done(3, f"Server-User low utilization (hit {hit_count} < {threshold}), last used > 1yr")

    # ── S4 — Medium-Low: Server-Server low utilization ──────────
    if traffic_type == "Server-Server":
        age     = _age(request_date, today)
        eff_age = age if age is not None else 3.0
        if hit_count_known and eff_age > 2 and hit_count < 50:
            return done(4, f"Server-Server low utilization: age={_fmt(eff_age)}yr, hit count {hit_count} < 50")

    # ── S5 — Low-High ───────────────────────────────────────────
    for obj in CUSTOMER_RULES.get("user_segment_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(5, f"User segment object: {obj}")
    if traffic_type == "Server-User":
        age = _age(request_date, today) or 0
        if not has_ticket and age <= 1:
            return done(5, "Server-User, within 1yr, no change ticket — formalize")
        return done(5, "Server-User rule — request change ticket")

    # ── S6 — Low-Low ────────────────────────────────────────────
    if is_ad_dns and hit_count_known and hit_count > 0:
        return done(6, "AD/DNS/LDAP service with active hit count")
    for obj in CUSTOMER_RULES.get("infra_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(6, f"Infrastructure object: {obj}")
    for obj in CUSTOMER_RULES.get("mgmt_objects", []):
        if _in_obj(obj, name, src_list, dst_list):
            return done(6, f"Management network object: {obj}")
    if traffic_type == "Server-Server":
        age = _age(request_date, today) or 0
        if not has_ticket and age <= 2:
            return done(6, "Server-Server, within 2yr, no change ticket — formalize")
        if hit_count_known and hit_count >= 50:
            return done(6, f"Server-Server, active rule (hit count {hit_count} >= 50)")
        return done(6, "Server-Server rule — request change ticket")

    return done(0, "Classification undetermined")


def _compute_tags(status, action, hit_count, hit_count_known, last_used_dt,
                  schedule_val, name, ticket, expanded_svcs, today) -> list:
    tags = []
    if status in ("disabled", "disable"):
        tags.append("Disabled")
    if hit_count_known and hit_count == 0:
        tags.append("No HitCount")
    if last_used_dt and (today - last_used_dt).days > 365:
        tags.append("Last Used > 1yr")
    if is_expired_schedule(schedule_val, today):
        tags.append("Expired Schedule")
    if not ticket:
        tags.append("No Change Ticket")
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
