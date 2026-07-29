"""
profile_loader.py
=================
판정 프로파일 로더 (Phase 1b).

APO의 판정 규칙 중 조직마다 달라지는 부분(PROFILE 층)을 코드에서 분리해
profiles/*.yaml 로 관리한다. 어떤 항목이 왜 PROFILE인지는 docs/inventory.md 참조.

우선순위 (뒤가 앞을 덮어씀):
  1. profiles/default.yaml   — 중립 기본값. 항상 로드된다.
  2. profiles/<name>.yaml    — APO_PROFILE 환경변수 또는 인자로 지정
  3. customer_rules.json     — 구형 설정. 있으면 마지막에 병합(하위호환)

프로파일이 하나도 없어도 내장 기본값으로 동작한다. 배포본에 profiles/가
빠져도 크래시하지 않는다.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

_PROFILE_DIR = "profiles"
_LEGACY_FILE = "customer_rules.json"

# 구(舊) customer_rules.json 키 -> 프로파일 경로.
# 특정 고객사 용어(BOSK/VDI)가 스키마에 남아 있던 것을 정리하면서도
# 이미 배포된 설정 파일이 계속 동작하도록 별칭을 유지한다.
_LEGACY_KEY_MAP = {
    "bosk_objects":         ("objects", "high_risk"),
    "high_risk_objects":    ("objects", "high_risk"),
    "vdi_objects":          ("objects", "user_segment"),
    "user_segment_objects": ("objects", "user_segment"),
    "mgmt_objects":         ("objects", "mgmt"),
    "infra_objects":        ("objects", "infra"),
    "admin_objects":        ("objects", "admin"),
    "severity_overrides":   ("objects", "severity_overrides"),
    "extra_temp_keywords":  ("naming", "extra_temp_keywords"),
    "temp_keywords":        ("naming", "temp_keywords"),
    "ticket_id_pattern":    ("naming", "ticket_id_pattern"),
}


def builtin_defaults() -> dict:
    """프로파일 파일이 전혀 없을 때의 최종 기본값.

    여기 값은 '표준 근거가 있는 것'과 '중립적으로 안전한 것'만 둔다.
    조직 고유 값(예외 객체 목록, 티켓 패턴)은 비워 둔다 — 비어 있으면
    해당 판정을 건너뛰고 리포트에 N/A로 표기한다.
    """
    return {
        "meta": {"name": "builtin", "description": "내장 기본값"},
        "thresholds": {
            # 표준에 숫자 근거 없음(docs/inventory.md §2.3). 조직이 정할 값이며
            # 365일은 연간 주기 업무(연말 배치 등)를 오탐하지 않기 위한 기본 제안치다.
            "dormancy_days": 365,
            "long_dormancy_days": 730,
            # 절대 hit 수 기준은 트래픽 볼륨을 가정하고, hit 카운터는 재부팅·HA
            # 페일오버로 리셋되므로 기본에서는 쓰지 않는다.
            "use_absolute_hit_threshold": False,
            "su_hit_multiplier": None,
            "ss_hit_threshold": None,
            "ss_schedule_age_years": 2,
            # 등록일 미상 시 가정 연도. 폴백을 두면 임계값이 해마다 자동으로
            # 강해지므로(inventory F2) 기본은 없음.
            "registration_fallback_year": None,
        },
        "services": {
            # S7 (NIST SP 800-82r3): telnet/FTP를 평문 프로토콜 취약점으로 명시.
            # HTTP·NFS도 명시돼 있으나 사내 웹서비스 오탐이 커서 기본 제외(Q11).
            "risky": ["FTP", "TELNET", "TFTP", "RLOGIN", "RSH"],
            "auth_dns": ["AD_AUTH", "DNS", "LDAP", "Kerberos", "LDAPS"],
            "icmp": ["ALL_ICMP", "ICMP_ALL", "PING", "ALL_ICMP_ALL"],
        },
        "rules": {
            # S3 (NIST SP 800-41 r1 §4.1.4): ICMP 전면 차단은 진단·성능 문제를
            # 일으키지만, 경계 방화벽에서는 허용 타입 외 차단을 권고한다.
            # 조건부라 기본은 끈다.
            "icmp_only_is_keep": False,
        },
        "objects": {
            "high_risk": [],
            "user_segment": [],
            "mgmt": [],
            "infra": [],
            "admin": [],
            "severity_overrides": {},
        },
        "naming": {
            # 조직 고유. 미설정 시 티켓 ID 추출을 건너뛴다(오탐 방지).
            "ticket_id_pattern": None,
            "temp_keywords": ["Temp", "temp", "test", "테스트", "작업", "임시",
                              "migration", "backup", "old"],
            "extra_temp_keywords": [],
            "controlled_keywords": ["controlled"],
        },
    }


def _search_roots() -> list[Path]:
    roots = []
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).parent)
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(Path(meipass))
    roots.append(Path.cwd())
    roots.append(Path(__file__).resolve().parents[2])
    return roots


def _read_yaml(path: Path) -> dict | None:
    try:
        import yaml
    except ImportError:
        return None
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _deep_merge(base: dict, over: dict) -> dict:
    """over의 값으로 base를 덮어쓴다. dict는 재귀, 그 외는 교체."""
    out = dict(base)
    for k, v in over.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _apply_legacy(profile: dict, legacy: dict) -> dict:
    """구형 customer_rules.json을 프로파일 구조로 접어 넣는다."""
    out = profile
    for key, value in legacy.items():
        if key.startswith("_"):
            continue
        target = _LEGACY_KEY_MAP.get(key)
        if not target:
            continue
        section, field = target
        out = _deep_merge(out, {section: {field: value}})
    return out


def load_profile(name: str | None = None, search_roots: list[Path] | None = None) -> dict:
    """프로파일을 병합해 반환한다. 파일이 없어도 예외를 던지지 않는다."""
    profile = builtin_defaults()
    roots = search_roots or _search_roots()
    name = name or os.environ.get("APO_PROFILE") or None

    seen: set[Path] = set()
    for root in roots:
        pdir = root / _PROFILE_DIR
        for fname in ("default.yaml", f"{name}.yaml" if name else None):
            if not fname:
                continue
            path = pdir / fname
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            data = _read_yaml(path)
            if data:
                profile = _deep_merge(profile, data)

    # 구형 customer_rules.json은 **프로파일을 명시하지 않았을 때만** 병합한다.
    # 명시적으로 프로파일을 고른 사용자는 그 프로파일대로 동작하길 기대한다.
    # 이걸 무조건 병합하면 default를 골라도 그 배포본에 남아 있던 고객 데이터가
    # 섞여 들어와, 범용 프로파일이 범용이 아니게 된다.
    if name is None:
        for root in roots:
            legacy = root / _LEGACY_FILE
            if legacy.is_file():
                try:
                    with legacy.open(encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict):
                        profile = _apply_legacy(profile, data)
                except Exception:
                    pass
                break

    return profile


def describe_inactive_rules(profile: dict) -> list[dict]:
    """이번 분석에서 '적용되지 않은' 판정 규칙을 사람이 읽을 수 있게 설명한다.

    셀마다 "N/A"를 뿌리면 보는 사람이 그게 무슨 뜻인지 알 수 없다. 대신
    리포트 앞에 "무엇을, 왜 판정하지 않았는지"를 문장으로 남긴다. 그래야
    '데이터가 없어서 판정을 안 한 것'과 '판정했더니 문제가 없는 것'을
    구분할 수 있다.

    반환: [{"item":..., "reason":..., "effect":...}]
    """
    th = profile.get("thresholds", {})
    obj = profile.get("objects", {})
    nam = profile.get("naming", {})
    rules = profile.get("rules", {})
    out: list[dict] = []

    if not nam.get("ticket_id_pattern"):
        out.append({
            "item": "ITSM ticket linkage",
            "reason": "No pattern is configured for reading ticket IDs from policy names (ticket_id_pattern).",
            "effect": "Policies were not assessed for 'created without an approved request'. If you use a ticketing system, add its pattern to the profile.",
        })

    if not th.get("use_absolute_hit_threshold"):
        out.append({
            "item": "Absolute hit-count thresholds",
            "reason": "Traffic volume differs too much between environments for a fixed number to be meaningful, and hit counters reset on reboot or HA failover.",
            "effect": "A low hit count alone was not treated as evidence of disuse. Policies were assessed on when they were last used instead.",
        })

    if th.get("registration_fallback_year") is None:
        out.append({
            "item": "Policy age when the registration date is unknown",
            "reason": "No fallback year is configured for policies whose name carries no registration date.",
            "effect": "Those policies were excluded from age-based assessment rather than assumed to be old.",
        })

    empty_objs = [label for key, label in (
        ("high_risk", "high-risk"), ("user_segment", "user-segment"),
        ("mgmt", "management"), ("infra", "infrastructure"), ("admin", "admin-policy"),
    ) if not obj.get(key)]
    if empty_objs:
        out.append({
            "item": "Organization exception objects (" + ", ".join(empty_objs) + ")",
            "reason": "No object lists are configured for these exception categories.",
            "effect": "Every policy was assessed by the same rules. To exempt specific objects, list them in the profile.",
        })

    if not rules.get("icmp_only_is_keep", True):
        out.append({
            "item": "ICMP-only policy exemption",
            "reason": "Whether this is appropriate depends on where the firewall sits (internal segment vs. internet perimeter), so it is off by default.",
            "effect": "Policies permitting only ICMP were assessed by the same rules as any other policy.",
        })

    return out


def to_customer_rules(profile: dict) -> dict:
    """프로파일을 기존 severity_engine이 쓰는 평면 dict로 변환한다.

    엔진 호출부를 한 번에 갈아엎지 않기 위한 어댑터다. 프로파일 구조가
    바뀌어도 엔진 쪽 키 이름은 유지된다.
    """
    obj = profile.get("objects", {})
    nam = profile.get("naming", {})
    return {
        "high_risk_objects":    list(obj.get("high_risk") or []),
        "user_segment_objects": list(obj.get("user_segment") or []),
        "mgmt_objects":         list(obj.get("mgmt") or []),
        "infra_objects":        list(obj.get("infra") or []),
        "admin_objects":        list(obj.get("admin") or []),
        "severity_overrides":   dict(obj.get("severity_overrides") or {}),
        "temp_keywords":        list(nam.get("temp_keywords") or []),
        "extra_temp_keywords":  list(nam.get("extra_temp_keywords") or []),
        "ticket_id_pattern":    nam.get("ticket_id_pattern"),
    }
