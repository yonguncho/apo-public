"""룰 세트 — 고객이 조정한 판정 입력을 **하나의 이름 붙은 이식 가능한 문서**로.

임계값(세션)·객체 분류(장비 대장)·티켓 형식(디스크)은 지금 세 화면에 흩어져
있고 저장소도 제각각이다. 이것을 한 파일로 묶으면 두 가지가 된다:

1. **이식** — 같은 판정 기준을 다른 장비·다른 PC·다른 고객에 그대로 적용한다
   (MSP 가 고객마다 재입력하는 수고를 없앤다). 이것이 이 모듈의 목적이다.
2. **식별** — 그 이식 단위에 SHA-256 을 붙여 "**어떤 기준 묶음을 적용했는가**"를
   한 값으로 가리킨다. 워크북 Summary 의 'Rule set applied' 가 이 값이다.

**이 해시는 '판정 지문' 이 아니다 — 그렇게 쓰면 안 된다.**
한때 독스트링이 "이 판정이 어떤 기준으로 나왔는가를 한 값으로 고정한다"고
적었으나 사실이 아니었다(2026-09-09 5렌즈 감사). 이유는 둘이다:

  · 여기 담기는 것은 판정 입력의 **부분집합**이다. `services`(위험·AD/DNS·ICMP
    목록)·`rules`(icmp_only_is_keep·standby 키워드)·`severity_overrides`·
    `user_ranges` 가 빠져 있고, 그것들도 등급을 가른다. 즉 **같은 해시로 다른
    판정이 가능하다.**
  · 그리고 그 일을 하는 것이 이미 있다 — `server._judgement_basis()` 가
    config 해시·사용량·날짜·`_engine_ctx()` 전체·user_ranges 까지 묶은 완전한
    지문이고, 워크북 Summary 는 그 값들을 **값 그대로** 인쇄한다(라운드 43 이후
    확립: "이름·해시로는 재현할 수 없다").

빠진 축들이 여기 없는 것은 실수가 아니라 성격 차이다 — `user_ranges` 는 그
장비의 사실이라 다른 고객에게 옮기면 안 되고, `services`·`rules` 는 프로파일
소관이라 아직 덮어쓰기 경로가 없다(backlog). **이식 단위와 재현 지문은 다른
것이고, 이 모듈은 앞의 것이다.**

**이 모듈은 판정을 바꾸지 않는다.** 지금 적용 중인 값을 직렬화할 뿐이다 —
같은 내용이면 입력 순서·군더더기에 무관하게 같은 해시가 나오도록 정규화한다.
이 함수는 순수 함수다(서버·디스크·시간에 의존하지 않는다).
"""

from __future__ import annotations

import hashlib
import json

SCHEMA = "apo-ruleset/v1"

# 객체 분류 종류. server.py 의 OBJECT_RULE_KINDS 와 같아야 한다 — 두 곳에
# 적으면 갈린다(한쪽만 늘어나면 해시가 서로 다른 내용을 같다고 본다).
OBJECT_RULE_KINDS = ("admin", "high_risk", "user_segment", "infra")


def canonical_ruleset(thresholds=None, object_rules=None, ticket=None) -> dict:
    """정규형 룰 세트. 같은 내용이면 항상 같은 dict 를 만든다.

    - thresholds: `{key: int|bool|None}` — 이미 `_sanitize_thresholds` 를
      통과한 값을 받는다고 가정한다(임의 키는 여기서 다시 거르지 않는다).
    - object_rules: `{kind: [name, ...]}` — 객체 분류는 **집합 멤버십**이라
      목록의 순서가 판정에 영향을 주지 않는다. 순서로 해시가 갈리면 "같은
      규칙"이 다른 해시를 받으므로, 중복을 없애고 정렬한다.
    - ticket: `{prefixes: [...], regex: str|None, scan_comment: bool}`.
    """
    th = {k: (thresholds or {})[k] for k in sorted((thresholds or {}))}

    obj = {}
    for kind in OBJECT_RULE_KINDS:
        vals = (object_rules or {}).get(kind) or []
        obj[kind] = sorted({str(v) for v in vals})

    tk = ticket or {}
    regex = tk.get("regex")
    ticket_out = {
        "prefixes": sorted({str(p) for p in (tk.get("prefixes") or [])}),
        # 빈 문자열과 '미설정'은 같은 뜻이다 — 해시가 갈리지 않게 None 으로 모은다.
        "regex": (regex.strip() if isinstance(regex, str) and regex.strip() else None),
        "scan_comment": bool(tk.get("scan_comment", True)),
    }
    return {"thresholds": th, "object_rules": obj, "ticket": ticket_out}


def ruleset_hash(ruleset: dict) -> str:
    """정규형 룰 세트의 SHA-256(hex). 같은 내용 → 같은 해시(키·순서 무관).

    정규화를 한 번 더 태우므로, 이미 정규형이든 원본이든 같은 값을 돌려준다.
    """
    canon = canonical_ruleset(
        ruleset.get("thresholds"),
        ruleset.get("object_rules"),
        ruleset.get("ticket"),
    )
    blob = json.dumps(
        canon, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def build_ruleset(thresholds=None, object_rules=None, ticket=None) -> dict:
    """export 용 전체 문서 — 스키마 + 정규형 내용 + 해시."""
    canon = canonical_ruleset(thresholds, object_rules, ticket)
    return {"schema": SCHEMA, **canon, "hash": ruleset_hash(canon)}
