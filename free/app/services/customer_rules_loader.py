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


def _default_rules() -> dict:
    return {
        "high_risk_objects": [],      # 항상 Critical(S1)로 분류할 객체
        "user_segment_objects": [],   # 사용자 세그먼트 객체 -> S5
        "mgmt_objects": [],           # 관리망 객체 -> S6
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
                for k, v in data.items():
                    if k.startswith("_"):
                        continue
                    rules[_LEGACY_KEY_ALIASES.get(k, k)] = v
                return rules
            except Exception:
                continue
    return rules
