"""
version_advisor.py — FortiOS version-based CVE/bug advisory service.
Reads vuln_db.json and returns vulnerabilities, known issues, and upgrade fixes
for the current firmware version. When a raw config is provided, only items
relevant to detected active features are included.
"""

from __future__ import annotations
import json
import re
import sys as _sys
from pathlib import Path
from functools import lru_cache

# FortiOS build number → version mapping (static table, no build_vuln_db.py needed)
BUILD_TO_VERSION: dict[int, str] = {
    # 7.2.x
    1157: "7.2.0", 1254: "7.2.1", 1255: "7.2.2", 1262: "7.2.3",
    1396: "7.2.4", 1517: "7.2.5", 1575: "7.2.6", 1577: "7.2.7",
    1639: "7.2.8", 1702: "7.2.9", 1703: "7.2.10", 1790: "7.2.11",
    1802: "7.2.12", 1804: "7.2.13",
    # 7.4.x
    2360: "7.4.0", 2463: "7.4.1", 2571: "7.4.2", 2575: "7.4.3",
    2662: "7.4.4", 2703: "7.4.5", 2726: "7.4.6", 2727: "7.4.7",
    2816: "7.4.8", 2913: "7.4.9", 2914: "7.4.10", 3003: "7.4.11",
    3007: "7.4.12",
    # 7.6.x
    3401: "7.6.0", 3457: "7.6.1", 3464: "7.6.2", 3557: "7.6.3",
    3602: "7.6.4", 3662: "7.6.5", 3666: "7.6.6", 3706: "7.6.7",
}

# ── Feature detection patterns ───────────────────────────────────────────────
# _NEEDS_EDIT_ENTRIES: block header alone is not enough — real edit entries required.
# FortiGate exports empty blocks too, so this prevents false positives.
_NEEDS_EDIT_ENTRIES: frozenset[str] = frozenset({
    "automation", "wifi", "ldap", "saml", "fortitoken",
    "ztna", "ipsec_vpn", "web_filter", "ips", "antivirus",
    "app_control", "fortilink", "rest_api", "dns_filter", "endpoint_ctrl",
})

FEATURE_PATTERNS: dict[str, list[str]] = {
    "ssl_vpn":        [r"config vpn ssl"],
    "ipsec_vpn":      [r"config vpn ipsec phase"],
    "ha":             [r"config system ha\b"],
    "ldap":           [r"config user ldap\b"],
    "saml":           [r"config user saml\b"],
    "captive_portal": [r"config firewall auth-portal\b", r"set captive-portal "],
    "security_fabric":[r"config system csf\b"],
    "automation":     [r"config system automation-stitch\b"],
    "fortitoken":     [r"config user fortitoken\b"],
    "bluetooth":      [r"config system bluetooth\b"],
    "ztna":           [r"config firewall access-proxy\b"],
    "proxy":          [r"config web-proxy\b", r"config firewall proxy-policy\b"],
    "wifi":           [r"config wireless-controller\b"],
    "web_filter":     [r"config webfilter profile\b"],
    "ips":            [r"config ips sensor\b"],
    "antivirus":      [r"config antivirus profile\b"],
    "app_control":    [r"config application list\b"],
    "fortilink":      [r"config switch-controller\b", r"config system fortilink\b"],
    "rest_api":       [r"config system api-user\b"],
    "sdwan":          [r"config system sdwan\b", r"config router sd-wan\b"],
    "dns_filter":     [r"config dnsfilter profile\b"],
    "endpoint_ctrl":  [r"config endpoint-control\b"],
    "vm":             [r"#config-version=fgvm", r"#config-version=fgv[0-9]"],
    "hw_6k7k":        [r"#config-version=fgt[67][0-9]{3}[a-z]?-", r"#config-version=fgh[67]"],
}

# Features where active use requires the profile to be applied inside a firewall policy.
# A profile merely existing in config (e.g. "config antivirus profile") is not enough;
# it must appear as "set av-profile <name>" inside a firewall policy.
_POLICY_APPLIED_FEATURES: frozenset[str] = frozenset({
    "antivirus", "web_filter", "ips", "app_control", "dns_filter",
})

# Regex patterns that detect profile binding inside firewall/proxy policies
_POLICY_PROFILE_BINDINGS: dict[str, str] = {
    "antivirus":   r"\bset av-profile\b",
    "web_filter":  r"\bset webfilter-profile\b",
    "ips":         r"\bset ips-sensor\b",
    "app_control": r"\bset application-list\b",
    "dns_filter":  r"\bset dnsfilter-profile\b",
}

# Bug components treated as general system issues — shown regardless of active features,
# but capped to _GENERAL_BUG_LIMIT entries to keep the list readable.
_GENERAL_COMPONENTS: frozenset[str] = frozenset({
    "System", "GUI", "CLI", "Firewall", "Routing", "Log & Report", "Log and Report",
    "Certificate", "SNMP", "NTP", "DNS", "DHCP", "Upgrade", "FortiView",
    "User & Authentication", "User and Authentication", "Authentication",
    "FortiGuard", "VDOM", "Hardware", "Performance", "VoIP",
    "Common Vulnerabilities and Exposures",
})

# Max general (unmapped/always-show) bugs included per query when config is loaded.
_GENERAL_BUG_LIMIT = 10

# ── CVE title keyword → feature mapping ─────────────────────────────────────
FEATURE_CVE_KEYWORDS: dict[str, list[str]] = {
    "ssl_vpn":        ["sslvpn", "ssl vpn", "ssl-vpn", "sslvpnd", "ssl vp"],
    "ipsec_vpn":      ["ipsec", " ike ", "ikev"],
    "ha":             [" ha ", "ha request", "high availability"],
    "ldap":           ["ldap", "clear-text credentials"],
    "saml":           ["saml"],
    "captive_portal": ["captive portal"],
    "security_fabric":["fabric daemon", "security fabric", " csfd"],
    "automation":     ["automation-stitch", "automation stitch"],
    "fortitoken":     ["fortitoken"],
    "bluetooth":      ["bluetooth"],
    "ztna":           ["ztna", "access proxy"],
    "proxy":          ["explicit proxy"],
    "wifi":           ["wifi", "wireless"],
    "web_filter":     ["webfilter", "web filter"],
    "fortilink":      ["fortilink", "switch controller"],
    "rest_api":       ["rest api", "rest-api"],
    "sdwan":          ["sd-wan", "sdwan"],
    "dns_filter":     ["dns filter", "dnsfilter"],
    "endpoint_ctrl":  ["endpoint control", "forticlient"],
}

# ── Bug component → feature mapping ─────────────────────────────────────────
# None = always show (general item unrelated to a specific feature)
COMPONENT_TO_FEATURE: dict[str, str | None] = {
    "SSL VPN":                          "ssl_vpn",
    "SSL-VPN":                          "ssl_vpn",
    "Agentless VPN (formerly SSL VPN web mode)": "ssl_vpn",
    "IPsec VPN":                        "ipsec_vpn",
    "HA":                               "ha",
    "WiFi Controller":                  "wifi",
    "Web Filter":                       "web_filter",
    "Proxy":                            "proxy",
    "Explicit Proxy":                   "proxy",
    "ZTNA":                             "ztna",
    "Anti Virus":                       "antivirus",
    "Intrusion Prevention":             "ips",
    "Application Control":              "app_control",
    "Security Fabric":                  "security_fabric",
    "Switch Controller":                "fortilink",
    "REST API":                         "rest_api",
    "SD-WAN":                           "sdwan",
    "DNS Filter":                       "dns_filter",
    "Endpoint Control":                 "endpoint_ctrl",
    "VM":                               "vm",
    "Hyperscale":                       "hw_6k7k",
    "HyperScale":                       "hw_6k7k",
    "FortiGate 6000 and 7000 platforms": "hw_6k7k",
    "FortiGate 6000/7000 Platform":     "hw_6k7k",
    "Automation":                       "automation",
    "Automation Stitch":                "automation",
    "WiFi":                             "wifi",
    "Wireless":                         "wifi",
    "Wireless Controller":              "wifi",
    "CAPWAP":                           "wifi",
    "FortiLink":                        "fortilink",
    "FortiToken":                       "fortitoken",
    "SAML":                             "saml",
    "LDAP":                             "ldap",
    "Data Loss Prevention":             None,
    "Anti Spam":                        None,
    "File Filter":                      None,
    "Web Application Firewall":         None,
}
# Components not listed above and not in _GENERAL_COMPONENTS are treated as
# feature-specific unknowns — shown conservatively (capped as general items).


def _ver_tuple(v: str) -> tuple[int, ...]:
    """버전 문자열을 (major, minor, patch) 3요소 튜플로 정규화.
    길이를 3으로 패딩해 '7.4' vs '7.4.0' 같은 불균형 비교 오류를 방지한다."""
    try:
        parts = [int(x) for x in v.split(".")]
    except (ValueError, AttributeError):
        return (0, 0, 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


@lru_cache(maxsize=1)
def _load_db() -> dict:
    if getattr(_sys, 'frozen', False) and hasattr(_sys, '_MEIPASS'):
        db_path = Path(_sys._MEIPASS) / "app" / "data" / "vuln_db.json"
    else:
        db_path = Path(__file__).resolve().parent.parent / "data" / "vuln_db.json"
    if not db_path.exists():
        return {"bugs": {}, "cves": []}
    with open(db_path, encoding="utf-8") as f:
        return json.load(f)


def _block_has_edit_entries(text_lower: str, block_pattern: str) -> bool:
    """Returns True only if the config block contains real edit entries.
    FortiGate exports empty blocks, so header presence alone is not conclusive."""
    m = re.search(block_pattern, text_lower)
    if not m:
        return False
    chunk = text_lower[m.start():m.start() + 4000]
    depth = 0
    for i, line in enumerate(chunk.split('\n')):
        s = line.strip()
        if i == 0:
            depth = 1
            continue
        if s.startswith('config '):
            depth += 1
        elif s == 'end':
            depth -= 1
            if depth <= 0:
                return False  # empty block — end reached without any edit
        elif s.startswith('edit ') and depth >= 1:
            return True  # real entry found (including nested sub-blocks)
    return False


def detect_active_features(raw_config: str) -> set[str]:
    """Scans config text and returns the set of active features.
    Features in _NEEDS_EDIT_ENTRIES require real edit entries inside the block."""
    active: set[str] = set()
    text_lower = raw_config.lower()
    for feature, patterns in FEATURE_PATTERNS.items():
        for pat in patterns:
            if not re.search(pat, text_lower):
                continue
            if feature in _NEEDS_EDIT_ENTRIES:
                if not _block_has_edit_entries(text_lower, pat):
                    break  # empty block — not active
            active.add(feature)
            break
    return active


def detect_policy_applied_features(raw_config: str) -> set[str]:
    """Returns which security profile features are actually applied inside
    firewall / proxy policies (i.e. the profile is bound to at least one policy).
    This is stricter than detect_active_features — a profile can exist in config
    without ever being applied to a policy."""
    applied: set[str] = set()
    text_lower = raw_config.lower()
    for feature, pat in _POLICY_PROFILE_BINDINGS.items():
        if re.search(pat, text_lower):
            applied.add(feature)
    return applied


def _effective_features_for_fixes(
    active: set[str],
    policy_applied: set[str],
) -> set[str]:
    """For upgrade-fix filtering, profile-type features count only when the
    profile is actually bound to a policy. Other features use config-level detection."""
    effective = set(active)
    for feat in _POLICY_APPLIED_FEATURES:
        if feat in effective and feat not in policy_applied:
            effective.discard(feat)
    return effective


def _cve_feature(title: str) -> str | None:
    """Returns the feature associated with a CVE title, or None (general)."""
    title_lower = title.lower()
    for feature, keywords in FEATURE_CVE_KEYWORDS.items():
        if any(kw in title_lower for kw in keywords):
            return feature
    return None


# FortiGate model code → display name mapping
_MODEL_NAME: dict[str, str] = {
    "FGT60D": "FortiGate 60D", "FGT60E": "FortiGate 60E", "FGT60F": "FortiGate 60F",
    "FGT61E": "FortiGate 61E", "FGT61F": "FortiGate 61F",
    "FGT80D": "FortiGate 80D", "FGT80E": "FortiGate 80E", "FGT80F": "FortiGate 80F",
    "FGT81E": "FortiGate 81E", "FGT81F": "FortiGate 81F",
    "FGT90D": "FortiGate 90D", "FGT90E": "FortiGate 90E", "FGT90G": "FortiGate 90G",
    "FGT91G": "FortiGate 91G",
    "FGT100D": "FortiGate 100D", "FGT100E": "FortiGate 100E", "FGT100F": "FortiGate 100F",
    "FGT101E": "FortiGate 101E", "FGT101F": "FortiGate 101F",
    "FGT200D": "FortiGate 200D", "FGT200E": "FortiGate 200E", "FGT200F": "FortiGate 200F",
    "FGT201E": "FortiGate 201E", "FGT201F": "FortiGate 201F",
    "FGT300D": "FortiGate 300D", "FGT300E": "FortiGate 300E",
    "FGT301E": "FortiGate 301E",
    "FGT400D": "FortiGate 400D", "FGT400E": "FortiGate 400E",
    "FGT401E": "FortiGate 401E",
    "FGT500D": "FortiGate 500D", "FGT500E": "FortiGate 500E",
    "FGT501E": "FortiGate 501E",
    "FGT600D": "FortiGate 600D", "FGT600E": "FortiGate 600E",
    "FGT601E": "FortiGate 601E",
    "FGT800D": "FortiGate 800D",
    "FGT1K":  "FortiGate 1000",
    "FGT1KD": "FortiGate 1000D", "FGT1KE": "FortiGate 1000E", "FGT1KF": "FortiGate 1000F",
    "FGT1K1F": "FortiGate 1001F",
    "FGT18K": "FortiGate 1800F",
    "FGT2K":  "FortiGate 2000", "FGT2KE": "FortiGate 2000E", "FGT2KF": "FortiGate 2000F",
    "FGT3K":  "FortiGate 3000", "FGT3KD": "FortiGate 3000D", "FGT3KE": "FortiGate 3000E",
    "FGT3KF": "FortiGate 3000F",
    "FGT35K": "FortiGate 3500D", "FGT35KF": "FortiGate 3500F",
    "FGT36K": "FortiGate 3600E", "FGT36KF": "FortiGate 3600F",
    "FGT37K": "FortiGate 3700D", "FGT37KF": "FortiGate 3700F",
    "FGT4K":  "FortiGate 4000", "FGT4KE": "FortiGate 4000E",
    "FGT5K":  "FortiGate 5000", "FGT5KE": "FortiGate 5000E",
    "FGT6K":  "FortiGate 6000", "FGT6KF": "FortiGate 6000F",
    "FGT7K":  "FortiGate 7000", "FGT7KE": "FortiGate 7000E",
    "FGR30D": "FortiGate Rugged 30D", "FGR35D": "FortiGate Rugged 35D",
    "FGR60D": "FortiGate Rugged 60D", "FGR90D": "FortiGate Rugged 90D",
    "FGVM01": "FortiGate VM01", "FGVM02": "FortiGate VM02",
    "FGVM04": "FortiGate VM04", "FGVM08": "FortiGate VM08",
    "FGVM16": "FortiGate VM16", "FGVM32": "FortiGate VM32",
    "FGVMUL": "FortiGate VM Unlimited", "FGVM64": "FortiGate VM64",
    "FGT40F": "FortiGate 40F", "FGT41F": "FortiGate 41F",
    "FGT50E": "FortiGate 50E",
    "FGT70D": "FortiGate 70D", "FGT70E": "FortiGate 70E",
    "FGT70F": "FortiGate 70F", "FGT71F": "FortiGate 71F",
    "FGT120D": "FortiGate 120D", "FGT120E": "FortiGate 120E",
    "FGT121E": "FortiGate 121E",
    "FGTAWS": "FortiGate-VM (AWS)", "FGTAZR": "FortiGate-VM (Azure)",
    "FGTGCP": "FortiGate-VM (GCP)", "FGTOCI": "FortiGate-VM (OCI)",
}


def _resolve_model_name(raw_code: str) -> str:
    code = raw_code.upper()
    if code in _MODEL_NAME:
        return _MODEL_NAME[code]
    base = re.sub(r"[-_].*$", "", code)
    if base in _MODEL_NAME:
        return _MODEL_NAME[base]
    m = re.match(r"FGT(\d{2,4})([A-Z]*)", code)
    if m:
        num, suffix = m.group(1), m.group(2)
        return f"FortiGate {int(num)}{suffix}"
    return raw_code


def parse_fortios_version(meta: dict) -> dict:
    """Extracts FortiOS version info from config meta.
    Returns: {branch, version, build, model, model_code, raw}
    Supported formats:
      FGT100F-7.04-FW-build2726-230430
      FGT60F-v7.00-FW-build0450-20220209
      FGT60F-v7.00-build0450-20220209
      FGT1KD-7.02-FW-build1396-230430
    """
    config_version = str(meta.get("config_version", "") or "")
    buildno_str = str(meta.get("buildno", "") or "")

    model_code = ""
    branch = ""
    build = 0

    if buildno_str:
        try:
            build = int(buildno_str)
        except ValueError:
            pass

    cv_match = re.search(
        r"([\w]+)-v?(\d+\.\d+)(?:-FW)?-build(\d+)",
        config_version,
        re.IGNORECASE,
    )
    if cv_match:
        model_code = cv_match.group(1).upper()
        raw_minor = cv_match.group(2)
        if not build:
            build = int(cv_match.group(3))
        parts = raw_minor.split(".")
        if len(parts) == 2:
            branch = f"{parts[0]}.{int(parts[1])}"
        else:
            branch = raw_minor
    else:
        ver_match = re.search(r"\b(7|8)\.(\d{1,2})\b", config_version)
        if ver_match:
            branch = f"{ver_match.group(1)}.{int(ver_match.group(2))}"

    if not branch and build:
        ver_from_build = BUILD_TO_VERSION.get(build, "")
        if ver_from_build:
            parts = ver_from_build.split(".")
            branch = f"{parts[0]}.{parts[1]}"
            model_code = model_code or "FortiGate"

    exact_version = BUILD_TO_VERSION.get(build, "")
    if not exact_version and branch:
        exact_version = branch

    model_display = _resolve_model_name(model_code) if model_code else ""

    if not model_code and config_version:
        token = re.split(r"[-_\s]", config_version)[0].upper()
        if re.match(r"FGT\w+|FGVM\w+|FGR\w+", token):
            model_code = token
            model_display = _resolve_model_name(model_code)

    return {
        "model": model_display,
        "model_code": model_code,
        "branch": branch,
        "version": exact_version,
        "build": build,
        "raw": config_version,
        "meta_keys": list(meta.keys()),
    }


def _version_is_affected(user_ver: str, affected_range: str, branch: str) -> bool:
    user_t = _ver_tuple(user_ver)
    if not user_t or user_t == (0, 0, 0):
        return True

    m = re.search(r"([\d.]+)\s+through\s+([\d.]+)", affected_range, re.IGNORECASE)
    if m:
        lo = _ver_tuple(m.group(1))
        hi = _ver_tuple(m.group(2))
        return lo <= user_t <= hi

    if re.search(r"all\s+versions", affected_range, re.IGNORECASE):
        return True

    single = re.search(r"([\d]+\.[\d]+\.[\d]+)", affected_range)
    if single:
        return user_t == _ver_tuple(single.group(1))

    # 인식 불가한 범위 표현은 '영향 없음'으로 처리해 오탐(거짓 영향)을 줄인다.
    return False


def query_cves(ver_info: dict, active_features: set[str] | None = None) -> list[dict]:
    """Returns CVEs for the detected branch.
    When active_features is provided, only CVEs related to active features are included.
    General CVEs (no feature mapping) are always included.
    is_patched=True when fix_version <= user_version.
    """
    db = _load_db()
    branch = ver_info.get("branch", "")
    exact = ver_info.get("version", "")
    user_t = _ver_tuple(exact) if exact else (0, 0, 0)

    results = []
    for cve in db.get("cves", []):
        for av in cve.get("affected_versions", []):
            if av.get("branch", "") != branch:
                continue

            if active_features is not None:
                feature = _cve_feature(cve.get("title", ""))
                if feature and feature not in active_features:
                    break

            fix_ver = av.get("fix_version", "")
            fix_t = _ver_tuple(fix_ver) if fix_ver else (0, 0, 0)
            is_patched = bool(user_t and fix_t and user_t >= fix_t)

            results.append({
                "advisory_id": cve.get("advisory_id"),
                "cve_id": cve.get("cve_id"),
                "title": cve.get("title"),
                "severity": cve.get("severity"),
                "workaround": cve.get("workaround"),
                "affected_range": av.get("affected_range"),
                "fix_version": fix_ver,
                "is_patched": is_patched,
            })
            break

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    results.sort(key=lambda x: (x["is_patched"], sev_order.get(x["severity"], 4)))
    return results


def query_known_issues(ver_info: dict, active_features: set[str] | None = None) -> list[dict]:
    """Returns Known Issues for the current version.
    When active_features is provided:
    - Feature-specific bugs (component in COMPONENT_TO_FEATURE): only if feature is active.
    - General bugs (_GENERAL_COMPONENTS / unmapped): included up to _GENERAL_BUG_LIMIT items.
    Without active_features: returns up to 50 items (no filtering).
    """
    db = _load_db()
    version = ver_info.get("version", "")
    bugs = db.get("bugs", {}).get(version, [])
    known = [b for b in bugs if b.get("type") == "known"]

    if active_features is None:
        return known[:50]

    feature_relevant: list[dict] = []
    general_items: list[dict] = []

    for b in known:
        comp = b.get("component", "")

        if comp in COMPONENT_TO_FEATURE:
            feat = COMPONENT_TO_FEATURE[comp]
            if feat is None:
                general_items.append(b)
            elif feat in active_features:
                feature_relevant.append(b)
            # else: feature mapped but not active → skip
        elif comp in _GENERAL_COMPONENTS:
            general_items.append(b)
        else:
            # Unknown component — apply keyword filter on description to catch
            # feature-specific items with non-standard component names.
            desc = (b.get("description", "") + " " + comp).lower()
            matched_feature = None
            for feat, kws in FEATURE_CVE_KEYWORDS.items():
                if any(kw in desc for kw in kws):
                    matched_feature = feat
                    break
            if matched_feature and matched_feature not in active_features:
                pass  # keyword matched an inactive feature — skip
            else:
                general_items.append(b)

    # Cap general items so the list stays actionable
    return (feature_relevant + general_items[:_GENERAL_BUG_LIMIT])[:50]


def query_upgrade_fixes(
    ver_info: dict,
    active_features: set[str] | None = None,
    policy_applied_features: set[str] | None = None,
) -> list[dict]:
    """Returns resolved issues from newer patch versions (up to 3 versions, 30 per version).
    When active_features is provided, only issues relevant to active features are shown.
    For profile-type features (antivirus, web_filter, ips, app_control, dns_filter),
    the feature only counts when the profile is actually bound to a firewall policy
    (policy_applied_features). If the profile exists in config but is never applied
    to a policy, those fix entries are excluded.
    """
    db = _load_db()
    branch = ver_info.get("branch", "")
    version = ver_info.get("version", "")
    user_t = _ver_tuple(version)

    # Compute effective feature set for fix filtering
    effective_features: set[str] | None = None
    if active_features is not None:
        if policy_applied_features is not None:
            effective_features = _effective_features_for_fixes(active_features, policy_applied_features)
        else:
            effective_features = set(active_features)

    branch_versions = sorted(
        [v for v in db.get("bugs", {}).keys() if v.startswith(branch + ".")],
        key=_ver_tuple,
    )

    results = []
    count = 0
    for v in branch_versions:
        if _ver_tuple(v) <= user_t:
            continue
        bugs = db["bugs"][v]
        resolved = [b for b in bugs if b.get("type") == "resolved"]

        if effective_features is not None:
            filtered: list[dict] = []
            general_in_fix: list[dict] = []
            for b in resolved:
                comp = b.get("component", "")
                if comp in COMPONENT_TO_FEATURE:
                    feat = COMPONENT_TO_FEATURE[comp]
                    if feat is None:
                        general_in_fix.append(b)
                    elif feat in effective_features:
                        filtered.append(b)
                elif comp in _GENERAL_COMPONENTS:
                    general_in_fix.append(b)
                else:
                    desc = (b.get("description", "") + " " + comp).lower()
                    matched = None
                    for feat, kws in FEATURE_CVE_KEYWORDS.items():
                        if any(kw in desc for kw in kws):
                            matched = feat
                            break
                    if matched and matched not in effective_features:
                        pass
                    else:
                        general_in_fix.append(b)
            resolved = (filtered + general_in_fix[:_GENERAL_BUG_LIMIT])[:30]
        else:
            resolved = resolved[:30]

        # 실제로 표시할 결과가 있는 버전만 카운트 → 빈 버전으로 3개 예산이 조기 소진되지 않도록.
        if resolved:
            results.append({"version": v, "resolved": resolved})
            count += 1
        if count >= 3:
            break

    return results


def run_advisor(meta: dict, raw_config: str = "") -> dict:
    """Main entry point for Version Advisor."""
    ver_info = parse_fortios_version(meta)
    if not ver_info.get("branch"):
        return {
            "error": "FortiOS version could not be determined from config.",
            "debug": {
                "meta": meta,
                "ver_info": ver_info,
                "hint": "Config file must contain #config-version= or #buildno= lines at the top.",
            },
        }

    active_features: set[str] | None = None
    policy_applied: set[str] | None = None

    if raw_config.strip():
        active_features = detect_active_features(raw_config)
        policy_applied = detect_policy_applied_features(raw_config)

    cves = query_cves(ver_info, active_features)
    known_issues = query_known_issues(ver_info, active_features)
    upgrade_fixes = query_upgrade_fixes(ver_info, active_features, policy_applied)

    unpatched_cves = [c for c in cves if not c["is_patched"]]
    patched_cves   = [c for c in cves if c["is_patched"]]

    return {
        "ver_info": ver_info,
        "active_features": sorted(active_features) if active_features is not None else None,
        "policy_applied_features": sorted(policy_applied) if policy_applied is not None else None,
        "summary": {
            "unpatched_cves": len(unpatched_cves),
            "patched_cves": len(patched_cves),
            "known_issues": len(known_issues),
            "upgrade_fix_versions": len(upgrade_fixes),
        },
        "unpatched_cves": unpatched_cves,
        "patched_cves": patched_cves,
        "known_issues": known_issues,
        "upgrade_fixes": upgrade_fixes,
    }
