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
    # mgmt 는 infra 로 합쳐졌지만(같은 등급 6) **여기서 같은 자리로 보내지
    # 않는다.** 구형 파일에 mgmt_objects 와 infra_objects 가 둘 다 있으면
    # _deep_merge 가 뒤엣것으로 덮어써 한쪽이 통째로 사라진다. 각자
    # 제자리에 두고, 병합은 to_customer_rules 한 곳에서만 한다.
    "mgmt_objects":         ("objects", "mgmt"),
    "infra_objects":        ("objects", "infra"),
    "admin_objects":        ("objects", "admin"),
    "severity_overrides":   ("objects", "severity_overrides"),
    "extra_temp_keywords":  ("naming", "extra_temp_keywords"),
    "temp_keywords":        ("naming", "temp_keywords"),
    "ticket_id_pattern":    ("naming", "ticket_id_pattern"),
    "controlled_keywords":  ("naming", "controlled_keywords"),
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
            # 조직 고유 관례. 기본은 없음 — 범용 규칙이 아니다.
            "controlled_keywords": [],
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

    # **더 구체적인 것이 이긴다 — 루트 순서가 아니라.**
    # 예전에는 루트를 바깥 고리로 돌아서 `exe/profiles/<customer>.yaml`(고객 납품분)
    # 다음에 `_MEIPASS/profiles/default.yaml`(번들 기본값)이 병합됐고, 나중
    # 값이 이기므로 **고객 임계값이 기본값으로 덮였다.** 개발 환경에서는 루트가
    # 중복 제거돼 드러나지 않고 exe 에서만 나타난다(라운드 39: 절대 히트수
    # 임계값 off, 등록연도 fallback 소실 — 심각도 판정 자체가 달라진다).
    #
    # default.yaml 은 바탕이고 {name}.yaml 은 그 위의 특화다. 그러니 파일을
    # 바깥 고리로 돌고, 같은 파일끼리는 **가까운 루트가 나중에** 오게 한다
    # (exe 옆에 둔 것이 번들된 것을 이긴다).
    seen: set[Path] = set()
    for fname in ("default.yaml", f"{name}.yaml" if name else None):
        if not fname:
            continue
        for root in reversed(roots):
            path = root / _PROFILE_DIR / fname
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
                # 구형 설정 파일이 있는 배포는 프로파일 도입 *이전* 동작을
                # 기대한다(v62 등 기 납품본). 당시 엔진 내장 기본값이던
                # 임계값을 복원하지 않으면, 이 프로파일을 런타임에 연결하는
                # 순간 중립 기본값이 우선해 기존 고객의 판정 결과가 바뀐다.
                profile = _deep_merge(profile, _legacy_compat())
                try:
                    with legacy.open(encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict):
                        profile = _apply_legacy(profile, data)
                        # **어디서 온 값인지 화면이 말할 수 있어야 한다.**
                        # 이 병합 뒤에도 프로파일 이름은 여전히 'default' 라,
                        # 설정 화면이 특정 고객 전용 객체명(관리자·DMZ 그룹명 등)을
                        # "profile default" 라고 소개했다 — 중립 기본값처럼
                        # 보인다(라운드 45 지적). 값은 그대로 두고(하위호환이
                        # 목적이다) **출처를 기록**한다.
                        profile.setdefault("meta", {})["legacy_file"] = str(
                            legacy.name)
                except Exception:
                    pass
                break

    return profile


def _legacy_compat() -> dict:
    """프로파일 도입 전(v62~v70) 엔진 내장 기본값. <customer>.yaml의 임계값과 동일."""
    return {
        "thresholds": {
            "dormancy_days": 365,
            "long_dormancy_days": 730,
            "use_absolute_hit_threshold": True,
            "su_hit_multiplier": 100,
            "ss_hit_threshold": 50,
            "ss_schedule_age_years": 2,
            "registration_fallback_year": 2021,
        },
        "rules": {"icmp_only_is_keep": True},
        "naming": {"controlled_keywords": ["controlled"]},
    }


def engine_context(profile: dict) -> dict:
    """severity_engine의 context에 넣을 프로파일 파생 항목.

    서버·스크립트가 같은 변환을 반복 구현하다 어긋나는 것을 막는다.
    호출부는 여기에 service_groups / user_ranges / today를 추가해 쓴다.
    """
    return {
        "customer_rules": to_customer_rules(profile),
        "thresholds": dict(profile.get("thresholds") or {}),
        "services": dict(profile.get("services") or {}),
        "rules": dict(profile.get("rules") or {}),
        # 티켓 패턴. 엔진은 있고 없음만 보지만(‘티켓 없음’과 ‘티켓을 안
        # 읽었음’을 가른다), **패턴 문자열도 함께 넣는다** — 이 값이 바뀌면
        # 판정이 바뀌므로 판정 근거 지문(_judgement_basis)에 잡혀야 한다.
        # bool 만 넣으면 RITM→CHG 처럼 값만 바뀐 경우 지문이 그대로다.
        "ticket_pattern": _ticket_pattern_source(profile),
        "ticket_pattern_configured": ticket_pattern_configured(profile),
        # **comment 스캔도 판정 입력이다.** 이걸 끄고 켜면 티켓을 찾느냐가
        # 갈리고, 그것이 'Valid ITS' 조기종결(Keep)을 좌우한다 — 실측으로
        # sev7 이 708→745 로 움직였다. 지문에 없으면 토글 후 판정이 갈렸는데
        # 점검 결과와 조치 계획의 불일치 경고가 침묵한다(정책 498 부류).
        "scan_comment": _scan_comment_enabled(),
    }


def _scan_comment_enabled() -> bool:
    from .runtime_settings import scan_comment_enabled
    return scan_comment_enabled()


def _ticket_pattern_source(profile: dict) -> str:
    return _ticket_pattern_state(profile)[0]


def _ticket_pattern_state(profile: dict) -> tuple[str, str]:
    """패턴과 **그 출처**. 출처를 버리면 산출물이 사실을 못 말한다.

    옛 버전에서 저장한 정규식이 무시된 경우와 "애초에 설정한 적 없는" 경우는
    **고객에게 전혀 다른 사실**인데, 여기서 출처를 버려 리포트가 둘을 같은
    문장으로 인쇄했다 — 자기가 넣은 값이 버려졌다는 것을 산출물에서 읽을 수
    없었다(6라운드 B3).
    """
    from .runtime_settings import resolve_pattern_source
    source, origin = resolve_pattern_source(
        (profile.get("naming") or {}).get("ticket_id_pattern"))
    return (source or ""), origin


def ticket_pattern_configured(profile: dict) -> bool:
    """티켓 ID를 읽을 패턴이 (설정 또는 프로파일에) 있는가."""
    return bool(_ticket_pattern_source(profile))


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

    # 화면 설정으로 넣은 패턴도 유효하다 — 프로파일만 보면, 설정에서 티켓
    # 형식을 입력해 실제로 판정이 이뤄지는데도 "판정하지 않았다"고 보고한다.
    if not ticket_pattern_configured(profile):
        _, _origin = _ticket_pattern_state(profile)
        if str(_origin).endswith("regex-disabled"):
            # 설정한 적 없는 것과 **넣은 값이 버려진 것**은 다른 사실이다.
            out.append({
                "item": "ITSM ticket linkage",
                "reason": "A ticket pattern saved in an older version is no "
                          "longer used, and no prefix has replaced it.",
                "effect": "Policies were not assessed for 'created without an "
                          "approved request'. Enter the prefix your tickets "
                          "start with in Settings (for example RITM).",
            })
        elif _origin == "profile-unsafe":
            out.append({
                "item": "ITSM ticket linkage",
                "reason": "The profile's ticket_id_pattern can hang the "
                          "assessment, so it was ignored.",
                "effect": "Policies were not assessed for 'created without an "
                          "approved request'. Fix ticket_id_pattern in the "
                          "profile, or set a prefix in Settings.",
            })
        else:
            out.append({
                "item": "ITSM ticket linkage",
                "reason": "No pattern is configured for reading ticket IDs from policy names (ticket_id_pattern).",
                "effect": "Policies were not assessed for 'created without an approved request'. Set your ticket number format in Settings, or add its pattern to the profile.",
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

    # infra 는 mgmt 를 흡수했다(to_customer_rules 가 병합한다). 여기서 infra
    # 만 보면, mgmt 만 채운 구형 설정에서 **실제로는 판정에 쓰이고 있는데도**
    # "설정 없음 — 이 검사를 건너뜀"이라고 거짓 고지한다(게이트 correctness).
    _obj_filled = dict(obj)
    _obj_filled["infra"] = (obj.get("infra") or []) or (obj.get("mgmt") or [])
    empty_objs = [label for key, label in (
        ("high_risk", "high-risk"), ("user_segment", "user-segment"),
        ("infra", "infrastructure/management"), ("admin", "admin-policy"),
    ) if not _obj_filled.get(key)]
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
    # **infra 와 mgmt 는 하나다.** 둘 다 같은 등급(6)을 냈고 사유 문구만
    # 달랐다 — 화면에서는 "어디 넣지?"를 고민하게 만들고, 코드에서는 같은
    # 일을 하는 목록이 둘로 갈려 있었다(실사용 지적). infra 로 합친다.
    #
    # **기존 설정의 mgmt 값은 그대로 살린다.** 납품된 프로파일
    # (고객 프로파일의 관리 객체 등)과 구형 customer_rules.json 이 이미
    # mgmt 를 쓰고 있다. 읽기를 끊으면 그 고객의 예외가 조용히 사라진다
    # — bosk/vdi 별칭과 같은 원칙이다.
    _infra = list(obj.get("infra") or [])
    for extra in (obj.get("mgmt") or []):
        if extra not in _infra:
            _infra.append(extra)
    return {
        "high_risk_objects":    list(obj.get("high_risk") or []),
        "user_segment_objects": list(obj.get("user_segment") or []),
        "infra_objects":        _infra,
        "admin_objects":        list(obj.get("admin") or []),
        "severity_overrides":   dict(obj.get("severity_overrides") or {}),
        "temp_keywords":        list(nam.get("temp_keywords") or []),
        "extra_temp_keywords":  list(nam.get("extra_temp_keywords") or []),
        "ticket_id_pattern":    nam.get("ticket_id_pattern"),
        "controlled_keywords":  list(nam.get("controlled_keywords") or []),
    }
