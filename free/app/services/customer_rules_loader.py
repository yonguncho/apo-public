"""
customer_rules_loader.py
=========================
severity_engine.py / policy_renderer.py가 공유하는 고객별 예외 규칙 로더.

기본 배포본은 이 파일이 없어도 중립 기본값으로 정상 동작한다.
고객 전용 빌드는 아래 후보 경로 중 하나에 customer_rules.json을 두면
해당 내용이 기본값에 병합(override)된다.
"""
from __future__ import annotations

import json
import os
import sys

_FILENAME = "customer_rules.json"

# 구(舊) 키 -> 현재 중립 키. 특정 고객사 용어(BOSK/VDI)가 설정 스키마에
# 남아 있던 것을 중립 명칭으로 정리하면서, 기존 배포본의 설정 파일도
# 계속 동작하도록 별칭을 유지한다.
_LEGACY_KEY_ALIASES = {
    "bosk_objects": "high_risk_objects",
    "vdi_objects":  "user_segment_objects",
}

# mgmt 는 infra 로 합쳐졌다(둘 다 등급 6이라 칸을 나눌 이유가 없었다).
# **단순 별칭으로 두면 안 된다** — 구형 파일에 mgmt_objects 와 infra_objects
# 가 둘 다 있으면 나중 것이 앞엣것을 덮어써 한쪽이 통째로 사라진다.
# 합집합으로 병합한다.
#
# 이 모듈은 현재 어디서도 호출되지 않는다(profile_loader 가 그 역할을 한다).
# 그래도 맞춰 두는 이유는, 이 경로가 되살아났을 때 예외가 조용히 사라지는
# 것이 곧 판정변화이기 때문이다.
_LEGACY_MERGE_KEYS = {"mgmt_objects": "infra_objects"}


def _default_rules() -> dict:
    return {
        "high_risk_objects": [],      # 항상 Critical(S1)로 분류할 객체
        "user_segment_objects": [],   # 사용자 세그먼트 객체 -> S5
        "infra_objects": [],          # 인프라 객체 -> S6
        "admin_objects": [],          # 관리자 전용 정책 객체 -> Keep(S7)
        "extra_temp_keywords": [],
        "severity_overrides": {},
        # 임시 정책 탐지 키워드. 특정 고객사 용어가 아닌 범용 표현이므로
        # 설정 파일이 없어도 동작하도록 기본값으로 둔다. 고객사 고유 용어는
        # extra_temp_keywords로 추가한다.
        "temp_keywords": ["Temp", "temp", "test", "테스트", "작업", "임시",
                          "migration", "backup", "old"],
        # ITSM 티켓 ID 추출 정규식. 고객사마다 체계가 다르므로 기본값 없음
        # (미설정 시 티켓 ID 추출을 건너뛰어 오탐을 방지).
        "ticket_id_pattern": None,
    }


def _candidate_paths() -> list[str]:
    paths = []
    if getattr(sys, "frozen", False):
        paths.append(os.path.join(os.path.dirname(sys.executable), _FILENAME))
    paths.append(os.path.join(os.getcwd(), _FILENAME))
    here = os.path.dirname(os.path.abspath(__file__))
    app_root = os.path.dirname(os.path.dirname(here))  # app/services -> app -> project root
    paths.append(os.path.join(app_root, _FILENAME))
    return paths


def load_customer_rules(path: str | None = None) -> dict:
    """customer_rules.json을 찾아 병합한다. 없거나 읽기 실패 시 중립 기본값 반환."""
    rules = _default_rules()
    candidates = [path] if path else _candidate_paths()
    for p in candidates:
        if p and os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as f:
                    data = json.load(f)
                # **병합은 대입이 모두 끝난 뒤에 한다.** 루프 안에서 곧바로
                # 합치면 키 순서에 의존한다 — {"mgmt_objects":[A],
                # "infra_objects":[B]} 순서면 뒤의 infra 대입이 방금 합친 A 를
                # 덮어써 예외가 사라진다(예외 소실 = 등급 상승 = 판정변화).
                pending: dict[str, list] = {}
                for k, v in data.items():
                    if k.startswith("_"):
                        continue
                    target = _LEGACY_MERGE_KEYS.get(k)
                    if target:
                        pending.setdefault(target, []).extend(v or [])
                        continue
                    rules[_LEGACY_KEY_ALIASES.get(k, k)] = v
                for target, extra in pending.items():
                    merged = list(rules.get(target) or [])
                    for item in extra:
                        if item not in merged:
                            merged.append(item)
                    rules[target] = merged
                return rules
            except Exception:
                continue
    return rules
