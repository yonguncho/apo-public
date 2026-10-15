"""화면에서 바꾸는 설정 중 **디스크에 남아야 하는 것**.

임계값(thresholds)은 세션 한정이어도 된다 — 점검할 때마다 조정하는 값이다.
그러나 **티켓 번호 형식은 고객사 고정값**이다. 한 번 입력하면 재시작 후에도
남아야 한다. 세션 한정으로 두면 매번 다시 입력해야 하고, 그러면 exe 옆에
`profiles/<name>.yaml` 을 두는 것과 견줘 나아지는 게 없다(이 기능의 목적이
바로 그 파일 배치를 없애는 것이다).

**정규식을 사용자에게 그대로 받지 않는 이유.** ReDoS 방어의 1순위 권고는
"사용자가 정규식을 제공하게 하지 마라"다. Python `re` 는 백트래킹 엔진이고
매칭 타임아웃이 없어서, `(a+)+b` 같은 입력 하나로 서버가 멈춘다. 그래서
기본 입력은 **접두어 목록**이고, 거기서 안전한 패턴을 조립한다. 정규식
직접 입력은 고급 항목으로 열어 두되 길이·중첩 수량자를 검사하고, 매칭
대상 길이도 잘라서 최악의 경우를 유한하게 만든다.
"""

from __future__ import annotations

import functools
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# 정규식을 적용할 문자열의 상한. 정책 이름은 FortiGate 에서 수십 자이고
# comment 도 255 자 제한이다. 상한을 두면 설령 위험한 패턴이 검사를
# 빠져나가도 백트래킹이 유한해진다 — 길이 제한은 OWASP 가 드는 핵심 방어다.
MAX_SCAN_LEN = 256

# 사용자 정규식 길이 상한. 실제 티켓 패턴은 20 자를 넘지 않는다.
MAX_PATTERN_LEN = 200

# 접두어 하나의 상한과 개수 상한. 조립 결과가 길어지는 것을 막는다.
MAX_PREFIX_LEN = 24
MAX_PREFIXES = 20

# 중첩 수량자 — `(x+)+`, `(x*)*`, `(x+)*` 류. 전형적인 catastrophic
# backtracking 유발 형태다. 완전 탐지는 불가능하므로 보수적으로 거부한다.
# **티켓 패턴 컴파일 플래그는 여기 하나뿐이다.** 검사와 실사용이 갈리면
# 검사가 다른 객체를 재게 되고, 그 틈으로 브릭 패턴이 통과한다(2026-09-10 실측:
# `([A-Z]{1,3})+!` 가 플래그 없는 검사는 0.2ms, 실제 판정은 10.9초).
_TICKET_FLAGS = re.IGNORECASE

# **사용자 정규식 직접 입력을 끈다** (2026-09-11, Jayden 승인).
#
# 이 파일 서두가 적어 둔 1순위 권고("사용자가 정규식을 제공하게 하지 마라")를
# 그대로 따른다. 재비판 다섯 라운드 중 **세 라운드의 주요 발견이 전부 이
# 입력에서 나왔고**, 막을 때마다 다른 모양으로 뚫리고 동시에 정상 패턴을
# 잘랐다(누적 오탐 15종). 구조 휴리스틱으로는 수렴하지 않는다.
#
# 대가는 측정했다: 실제 ITSM 형식 20종 중 접두어 조립이 **20종 전부**를
# 잡는다(한글 접두어를 막던 ASCII 제한을 함께 풀었다 — 못 하던 2종이 전부
# 그것 때문이었다). 즉 이 기능을 끄는 비용이 실질적으로 없다.
#
# **코드와 테스트는 지운 게 아니라 남긴다.** 다시 켜야 할 형식이 나오면
# 검증자와 그 계약(위험 63종/정상 48종)이 그대로 필요하다.
TICKET_REGEX_ENABLED = False

# ── 파국적 백트래킹 탐지: 정규식이 아니라 AST 로 ────────────────────────────
#
# **정규식으로 정규식을 검사하면 진다.** 세 라운드 연속, 매번 다른 모양으로
# 뚫렸다(2026-09-09~10 보안 렌즈):
#   1차: `(a{1,10})+` — 안쪽이 `{m,n}` 이면 `[+*]` 만 보던 규칙이 놓쳤다
#   2차: `_((([a-z]{1,2})))+!` — 괄호 한 겹이면 본문 `[^()]*` 가 안 문다
#   3차: `HQ_(\w+\d*)+!` — 본문에 원소를 하나 더 붙이면 `len(body)==1` 이 꺼진다
# 그때마다 반대로 **정상 패턴을 새로 잘랐다**(`(RITM\d{7})+`, `(?:[A-Z]{2,5})?\d{6,10}`).
#
# 판단 기준을 실측으로 다시 세웠다(`demo_assets/_redos_bench.py` — 자식
# 프로세스에 재우고 벽시계로 끊는다. 인프로세스로 재면 측정 스크립트가 멈춘다):
#   위험: `(a+)+b` `(a|a)*b` `HQ_(\w+\d*)+!` `([B-Z]+\d*)+!` `Change(\W*\w+)+#`
#         `(\w+){6}!`(1.8초) `((\w+){2}){4}!`(타임아웃)
#   안전: `(A|B)*C!` `(a|b)*` `(?:RITM|INC)+\d{7}` `(?:[A-Z]{2,5})?\d{6,10}`
#         `(RITM\d{7})+` `(\d{7})+`
#
# 규칙은 셋이다:
#   ① 바깥 반복이 **두 번 이상** 돌 수 있어야 한다(max > 1). `?` 는 0/1 이라
#      되짚을 분할이 없다 — 이것을 "가변" 으로 본 탓에 정상 5종이 잘렸다.
#      반대로 `{8}` 같은 **고정 횟수**도 위험하다(다항 폭발). 옛 `min != max`
#      조건은 이 둘을 정확히 반대로 판정했다.
#   ② 본문에서 **빈 문자열에 매치될 수 있는 원소를 걷어낸다.** `\d*`·`_*`·`\W*`
#      는 앵커 역할을 못 하므로 폭발을 막지 못하는데, 원소 수만 늘려 검사를
#      꺼 버렸다. 걷어내고 남은 것이 **하나뿐**이고 그것이 길이가 변하는
#      반복이면 같은 문자열을 여러 방식으로 쪼갤 수 있다 = 파국적이다.
#   ③ 교대는 **분기가 서로 겹칠 때만** 위험하다. `(a|a)*` 는 위험하고
#      `(?:RITM|INC)+` 는 안전하다 — 옛 정규식 규칙은 이 둘을 구분 못 해
#      정상 3종을 잘랐다.
try:                                    # 3.11+
    from re import _parser as _sre_parse
except ImportError:                     # 3.10 이하
    import sre_parse as _sre_parse      # type: ignore[no-redef]


def _op(name: str):
    """오피코드 상수. 파이썬 버전에 따라 없는 것도 있다(POSSESSIVE_REPEAT 등)."""
    return getattr(_sre_parse, name, None)


_OP_MAX_REPEAT = _op("MAX_REPEAT")
_OP_MIN_REPEAT = _op("MIN_REPEAT")
_OP_POSSESSIVE = _op("POSSESSIVE_REPEAT")
_OP_SUBPATTERN = _op("SUBPATTERN")
_OP_BRANCH = _op("BRANCH")
_OP_ATOMIC = _op("ATOMIC_GROUP")
_OP_ASSERT = _op("ASSERT")
_OP_ASSERT_NOT = _op("ASSERT_NOT")
_OP_AT = _op("AT")
_OP_LITERAL = _op("LITERAL")
_OP_IN = _op("IN")
_OP_RANGE = _op("RANGE")
_OP_CATEGORY = _op("CATEGORY")
_REPEATS = {o for o in (_OP_MAX_REPEAT, _OP_MIN_REPEAT, _OP_POSSESSIVE) if o}
_ZERO_WIDTH = {o for o in (_OP_ASSERT, _OP_ASSERT_NOT, _OP_AT) if o}

_MAX_DEPTH = 60


def _kids(node):
    """이 노드가 품은 하위 패턴들."""
    op, av = node[0], node[1]
    if op in _REPEATS:
        return [av[2]]
    if op == _OP_SUBPATTERN:
        return [av[3]]
    if op == _OP_BRANCH:
        return list(av[1])
    if _OP_ATOMIC and op == _OP_ATOMIC:
        return [av]
    if op in (_OP_ASSERT, _OP_ASSERT_NOT):
        return [av[1]]
    return []


def _matches_empty(node, depth: int = 0) -> bool:
    """빈 문자열에 매치될 수 있는가 — 그렇다면 앵커 역할을 못 한다."""
    if depth > _MAX_DEPTH:
        return False
    op, av = node[0], node[1]
    if op in _ZERO_WIDTH:
        return True
    if op in _REPEATS:
        return av[0] == 0 or all(_matches_empty(n, depth + 1) for n in av[2])
    if op == _OP_SUBPATTERN:
        return all(_matches_empty(n, depth + 1) for n in av[3])
    if op == _OP_BRANCH:
        return any(all(_matches_empty(n, depth + 1) for n in b) for b in av[1])
    if _OP_ATOMIC and op == _OP_ATOMIC:
        return all(_matches_empty(n, depth + 1) for n in av)
    return False


def _varies_in_length(sp, depth: int = 0) -> bool:
    """이 하위 패턴이 **길이가 다른** 매치를 만들 수 있는가.

    길이가 하나로 정해지면(`\d{7}`) 쪼갤 방법이 하나뿐이라 안전하다.
    """
    if depth > _MAX_DEPTH:
        return True                      # 모르면 위험한 쪽으로
    for node in sp:
        op, av = node[0], node[1]
        if op in _REPEATS:
            if av[0] != av[1] or _varies_in_length(av[2], depth + 1):
                return True
        elif op == _OP_BRANCH:
            if any(_varies_in_length(b, depth + 1) for b in av[1]):
                return True
        elif _kids(node):
            if any(_varies_in_length(k, depth + 1) for k in _kids(node)):
                return True
    return False


def _strip_body(sp, depth: int = 0):
    """그룹 껍질을 벗기고 **빈 매치 가능한 원소를 걷어낸** 본문.

    `((( x )))` → `x`, `(\w+\d*)` → `\w+`.
    """
    seen = 0
    while len(sp) == 1 and seen < _MAX_DEPTH:
        node = sp[0]
        if node[0] == _OP_SUBPATTERN:
            sp = node[1][3]
        elif _OP_ATOMIC and node[0] == _OP_ATOMIC:
            sp = node[1]
        else:
            break
        seen += 1
    # **빈 매치 가능한 원소를 걷어내지 않는다.** 한때 `(\w+\d*)+` 에서
    # `\d*` 를 걷어내 `\w+` 를 드러내려 했는데, 같은 걷어내기가
    # `(\w*_)+` 에서는 **위험한 쪽인 `\w*` 를 지워** 리터럴 하나만 남겼고
    # 검사가 꺼졌다(5라운드 미탐 5종). 이제 다원소 본문을 직접 다루므로
    # 걷어낼 이유가 없다 — `(\w+\d*)+` 는 원소 둘 다 가변 반복이라 잡히고,
    # `(\w*_)+` 는 `_` 가 `\w` 와 겹쳐 앵커가 못 되므로 잡힌다.
    return list(sp)


def _branches_overlap(branches) -> bool:
    """분기가 서로 겹치는가 — 같은 문자열을 두 갈래로 받으면 파국적이다.

    일반적인 겹침 판정은 어렵다. **구조가 같은 분기**만 본다(`(a|a)`).
    겹치지 않는 교대(`(?:RITM|INC)`)는 분할이 하나뿐이라 안전하다.
    """
    seen = []
    for b in branches:
        key = repr(list(b))
        if key in seen:
            return True
        seen.append(key)
    return False


def _has_overlapping_branch(sp, depth: int = 0) -> bool:
    """본문 안에 **겹치는 분기**가 있는가.

    `(a|a)*` 는 파서가 공통 접두어를 뽑아 `a` + `(|)` 로 바꾼다 — 즉 본문이
    `[LITERAL a, BRANCH([[], []])]` 가 되고, 빈 분기는 "빈 매치 가능" 이라
    걷어내기에 걸려 사라졌다. 그러면 남는 건 리터럴 하나뿐이라 검사가 꺼진다.
    그런데 빈 분기가 **둘**이라는 것이 바로 "같은 문자열을 두 갈래로 받는다"
    는 뜻이다. 걷어내기 전에 따로 본다.
    """
    if depth > _MAX_DEPTH:
        return True
    for node in sp:
        if node[0] == _OP_BRANCH and _branches_overlap(node[1][1]):
            return True
        for kid in _kids(node):
            if _has_overlapping_branch(kid, depth + 1):
                return True
    return False


def _first_chars(node, depth: int = 0) -> set | None:
    """이 노드가 매치할 수 있는 **한 글자** 집합. 모르면 None(=무엇이든)."""
    if depth > _MAX_DEPTH:
        return None
    op, av = node[0], node[1]
    if op == _OP_LITERAL:
        return {av}
    if op == _OP_IN:
        out = set()
        for sub in av:
            if sub[0] == _OP_LITERAL:
                out.add(sub[1])
            elif sub[0] == _OP_RANGE:
                lo, hi = sub[1]
                if hi - lo > 4096:          # 너무 넓으면 세지 않는다
                    return None
            elif sub[0] == _OP_CATEGORY:
                # `\d`·`\s` 는 집합을 정확히 안다. `\w` 는 유니코드까지
                # 넓어 **모른다고 둔다** — 좁게 잡으면 "겹치지 않는다" 를
                # 잘못 증명해 위험한 패턴을 놓친다.
                name = str(sub[1])
                if name.endswith("CATEGORY_DIGIT"):
                    out.update(range(ord("0"), ord("9") + 1))
                elif name.endswith("CATEGORY_SPACE"):
                    out.update({9, 10, 11, 12, 13, 32})  # 공백류
                else:
                    return None
            else:
                return None
            if sub[0] == _OP_RANGE:
                lo, hi = sub[1]
                out.update(range(lo, hi + 1))
        return out
    if op in _REPEATS:
        return _first_chars(av[2][0], depth + 1) if av[2] else None
    for kid in _kids(node):
        if kid:
            return _first_chars(kid[0], depth + 1)
    return None


def _anchors(sep, neighbour) -> bool:
    """`sep` 이 `neighbour` 반복의 경계를 **고정하는가**.

    `(\w+_\w+)+` 의 `_` 는 리터럴이지만 `\w` 가 **그것도 매치한다** —
    그래서 경계를 못 고정하고 분할이 여러 가지가 된다(실측 2.3초).
    반대로 `(RITM\d{7})+` 의 `R` 은 `\d` 가 못 받으므로 매 반복을 고정한다.
    이웃이 무엇을 받을 수 있는지 모르면(`\w` 같은 CATEGORY) **안전한 쪽으로
    가정하지 않는다** — 고정 못 한다고 본다.
    """
    mine = _first_chars(sep)
    if mine is None:
        return False
    theirs = _first_chars(neighbour)
    if theirs is None:
        return False                        # 이웃이 무엇이든 받을 수 있다
    return not (mine & theirs)


def _repeat_is_variable(node) -> bool:
    """이 반복이 **길이가 다른** 매치를 만드는가.

    횟수가 가변이거나(`\w+`), 횟수는 고정인데 본문이 가변이면(`(\w+){2}`)
    그렇다. 한때 이 판단이 두 곳에 서로 다르게 적혀 있어, 다원소 본문에서만
    `\w+` 가 "가변이 아님" 으로 분류됐다 — `(\w+\w+)+` 가 통째로 통과했다.
    """
    return node[0] in _REPEATS and (node[1][0] != node[1][1]
                                    or _varies_in_length(node[1][2]))


def _body_is_ambiguous(body) -> bool:
    """이 본문을 반복하면 같은 문자열을 여러 방식으로 쪼갤 수 있는가."""
    if not body:
        return False
    if len(body) == 1:
        node = body[0]
        op, av = node[0], node[1]
        if op in _REPEATS:
            return _repeat_is_variable(node)
        if op == _OP_BRANCH:
            return _branches_overlap(av[1]) or any(
                _varies_in_length(b) for b in av[1])
        return False

    # 원소가 둘 이상이면 검사를 꺼 버렸다 — `(\w+\w+)+` 도 `(\w+_\w+)+` 도
    # 그대로 통과했다(실측 타임아웃, 5라운드 미탐 22건의 한 축). 리터럴이
    # 섞였다고 안전한 것이 아니다: 그 리터럴을 **이웃 반복이 함께 받을 수
    # 있으면** 경계를 못 고정한다.
    reps = [n for n in body if _repeat_is_variable(n)]
    if not reps:
        return False                        # 가변 반복이 없으면 쪼갤 일이 없다
    # 비반복 원소 하나가 **모든** 가변 반복과 문자가 겹치지 않으면, 매 반복이
    # 그 글자에서 시작(또는 끝)해야 하므로 경계가 하나로 정해진다.
    # `(CHG\d{6}[,;]?)+` 의 `C` 가 그렇다 — `[,;]` 도 `\d` 도 C 를 못 받는다.
    # 반대로 `(\w+_\w+)+` 의 `_` 는 `\w` 가 함께 받으므로 고정하지 못한다.
    for node in body:
        if _repeat_is_variable(node):
            continue
        if all(_anchors(node, r) for r in reps):
            return False
    return True


def _may_fail(node) -> bool:
    """이 원소가 매치를 **실패시킬 수 있는가**.

    "빈 문자열에 매치된다" 와 "실패하지 않는다" 는 다르다 — `$`·`^`·선읽기는
    아무것도 소비하지 않지만 실패할 수 있다. 그 둘을 같게 봤더니 교과서적
    `(\d+)+$` 가 "뒤에 아무것도 없다" 로 분류돼 면제됐다.
    """
    if node[0] in _ZERO_WIDTH:
        return True
    return not _matches_empty(node)


def _has_catastrophic_repeat(sp, depth: int = 0, tail_can_fail: bool = False) -> bool:
    """`tail_can_fail` — 이 하위패턴 **뒤에** 실패할 수 있는 것이 있는가.

    파국적 백트래킹은 **끝에서 실패해야** 일어난다. 뒤에 아무것도 없으면
    `re.search` 가 첫 유효 위치에서 바로 성공하고 되짚을 일이 없다 —
    `([A-Z]{2,5})+` 는 0.0ms 인데 `([A-Z]{2,5})+\d{7}` 은 타임아웃이다
    (5라운드 실측). 꼬리를 안 보던 규칙이 정상 패턴 5종을 잘랐다.
    """
    if depth > _MAX_DEPTH:
        # **모르면 거절한다.** 예전에는 여기서 False 를 돌려줘, 괄호를 61겹
        # 씌운 교과서적 `(x+)+` 가 통째로 통과했다(4라운드 S4).
        return True
    for i, node in enumerate(sp):
        op, av = node[0], node[1]
        after = tail_can_fail or any(_may_fail(n) for n in sp[i + 1:])
        if op in _REPEATS:
            # 두 번 이상 돌 수 있어야 되짚을 분할이 생긴다.
            if after and av[1] > 1 and (_body_is_ambiguous(_strip_body(av[2]))
                                        or _has_overlapping_branch(av[2])):
                return True
        for kid in _kids(node):
            if _has_catastrophic_repeat(kid, depth + 1, after):
                return True
    return False


# **판정 경로는 정책마다 돈다 — 여기서 매번 파싱하면 안 된다.**
# 프로파일 패턴에 구조 검사를 걸었더니 정책 2,000건에 6초가 붙었고
# `test_parsing_time_stays_linear_in_object_count` 가 잡았다(2026-09-11).
# 순수 함수이므로 결과를 기억한다 — 같은 문자열이면 같은 답이다.
# 패턴 종류는 설정·프로파일에서 오므로 한 자릿수를 넘지 않는다.
@functools.lru_cache(maxsize=256)
def _looks_catastrophic(pattern: str) -> bool:
    """구조만 보는 판단 — 순수 함수라 판정 경로에서도 쓸 수 있다."""
    try:
        parsed = _sre_parse.parse(pattern, _TICKET_FLAGS)
    except Exception:
        return False                        # 파싱 실패는 여기서 판단할 일이 아니다
    return _has_catastrophic_repeat(parsed)


def _base_dir() -> Path:
    """설정을 둘 곳.

    frozen exe 에서 `DATA_DIR` 는 `_MEIPASS`(매 실행 새로 풀고 종료 시 삭제)
    하위라, 거기 쓰면 **재시작마다 설정이 사라진다.** 브랜딩·라이선스가 이미
    같은 이유로 exe 인접 경로를 쓴다.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parents[2] / "data"


def _user_dir() -> Path:
    """exe 옆에 쓸 수 없을 때의 대비책.

    exe 인접 경로만 쓰면 **쓰기 권한이 없는 자리에서 설정이 통째로 안 된다** —
    `Program Files` 설치, 회사 PC 의 폴더 정책, 읽기전용 매체, 네트워크 드라이브.
    실사용 보고: 저장이 503 으로 실패하는데 화면은 "티켓 형식이 설정되지
    않았습니다"만 계속 보여줘, 사용자는 무엇이 잘못됐는지 알 수 없었다.
    """
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CONFIG_HOME")
    return (Path(root) if root else Path.home()) / "APO"


def _candidate_dirs() -> list[Path]:
    """설정을 둘 후보. 앞의 것이 우선이고, 못 쓰면 뒤로 넘어간다."""
    return [_base_dir(), _user_dir()]


SETTINGS_FILENAME = "apo_settings.json"


def settings_path() -> Path:
    """읽을 설정 파일.

    **이미 있는 파일을 먼저 찾는다.** 그래야 지난번에 대비책 위치에 저장된
    설정을 계속 읽는다 — 우선순위만 보고 고르면 저장 위치와 읽기 위치가
    갈려서, 저장은 됐는데 반영이 안 되는 상태가 된다.
    """
    for d in _candidate_dirs():
        p = d / SETTINGS_FILENAME
        try:
            if p.is_file():
                return p
        except OSError:
            continue
    return _candidate_dirs()[0] / SETTINGS_FILENAME


# 파일을 요청마다 읽지 않는다. mtime 이 바뀌면 다시 읽는다.
_cache: dict[str, Any] = {"mtime": None, "data": {}}


def load_settings() -> dict:
    path = settings_path()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        # 파일이 없는 것은 정상이다(아직 설정하지 않은 상태).
        _cache["mtime"], _cache["data"] = None, {}
        return {}
    if _cache["mtime"] == mtime:
        return _cache["data"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data = data if isinstance(data, dict) else {}
    except Exception as exc:
        # 깨진 설정 때문에 앱이 못 뜨면 안 된다. 다만 조용히 넘기지도 않는다 —
        # 사용자는 자기가 넣은 설정이 무시된 이유를 알아야 한다.
        print(f"[APO] could not read settings ({path}): {exc!r} - "
              f"falling back to the profile.", flush=True)
        data = {}
    _cache["mtime"], _cache["data"] = mtime, data
    return data


def save_settings(data: dict) -> Path:
    """설정을 저장하고 **실제로 쓴 경로**를 돌려준다.

    exe 옆에 못 쓰면 사용자 폴더로 넘어간다. 어디에 썼는지 돌려주는 이유는
    화면이 그것을 말할 수 있어야 하기 때문이다 — 설정 파일을 백업하거나
    다른 PC 로 옮기려면 위치를 알아야 하고, 대비책 위치로 넘어간 사실도
    감춰서는 안 된다.
    """
    text = json.dumps(data, ensure_ascii=False, indent=2)
    errors = []
    for d in _candidate_dirs():
        path = d / SETTINGS_FILENAME
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except Exception as exc:
            errors.append(f"{path}: {exc!r}")
            continue
        # 방금 쓴 것을 곧바로 읽는 경로가 있으므로 캐시를 무효화한다.
        _cache["mtime"], _cache["data"] = None, {}
        if errors:
            # 조용히 넘어가지 않는다 — 왜 여기 저장됐는지 흔적을 남긴다.
            print(f"[APO] settings saved to {path} "
                  f"(could not write next to the program: {errors[0]})",
                  flush=True)
        return path
    raise OSError("could not write settings to any of: " + "; ".join(errors))


# ── 패턴 조립·검증 ─────────────────────────────────────────────────────────

def normalize_prefixes(raw: Any) -> list[str]:
    """`"RITM, CHG"` 또는 `["RITM","CHG"]` 를 정리된 목록으로."""
    if isinstance(raw, str):
        items = re.split(r"[,\n]", raw)
    elif isinstance(raw, (list, tuple)):
        items = [str(x) for x in raw]
    else:
        return []
    out: list[str] = []
    for item in items:
        # **ASCII 로 제한하지 않는다.** 예전에는 `[^A-Za-z0-9-]` 를 지웠는데,
        # 그러면 한글 접두어(`업무요청`)가 통째로 사라져 **빈 목록**이 됐다 —
        # 사용자는 저장이 된 줄 알고 티켓이 하나도 안 잡히는 이유를 모른다.
        # 기본 언어가 한국어가 된 제품에서 이건 "그래서 정규식 칸으로 간다" 의
        # 직접 원인이다(2026-09-11 커버리지 측정: 실 형식 20종 중 못 하는 2종이
        # 전부 이 제한 때문이었다).
        #
        # 안전은 여기서가 아니라 `build_prefix_pattern` 의 `re.escape` 가
        # 책임진다 — 어떤 글자든 리터럴로 바뀌므로 메타문자가 생길 수 없다.
        # 여기서는 **패턴을 깨뜨리거나 목록 구분을 흐리는 것만** 지운다.
        token = "".join(str(item).split())[:MAX_PREFIX_LEN]
        if token and token.upper() not in [o.upper() for o in out]:
            out.append(token)
        if len(out) >= MAX_PREFIXES:
            break
    return out


def build_prefix_pattern(prefixes: list[str]) -> str | None:
    """접두어 목록 → **ReDoS 가 불가능한** 패턴.

    교대(alternation)는 서로 겹치지 않는 리터럴이고 수량자는 `{3,12}` 로
    상한이 있다. 중첩 수량자가 생길 여지가 없으므로 백트래킹이 폭발하지
    않는다. `RITM0282811`, `CHG-0012345`, `REQ_012345` 를 모두 잡는다.

    **경계로 `\\b` 를 쓰면 안 된다.** 정책명은 보통
    `250822_RITM0282811_홍길동` 처럼 언더스코어로 구분되는데, `_` 는 단어
    (이름은 **예시다** — 실 고객 설정에서 가져온 실명을 소스에 남기지 않는다.)
    문자라서 `_RITM` 사이에 단어 경계가 없다 — `\\b` 로 감싸면 이 형식이
    통째로 미인식된다(실측: 실 설정 1,525건 중 이 형태가 전량 누락됐다).
    그래서 앞은 '영숫자가 아님'(언더스코어·한글·문자열 시작 허용), 뒤는
    '숫자가 더 오지 않음'으로 잡는다.
    """
    safe = [re.escape(p) for p in prefixes if p]
    if not safe:
        return None
    return (r"(?<![A-Za-z0-9])(?:" + "|".join(safe)
            + r")[-_ ]?\d{3,12}(?![0-9])")


def validate_regex(pattern: str, deep: bool = True) -> tuple[bool, str]:
    """고급 입력(정규식 직접)의 안전성 검사. (ok, 사유).

    `deep=True`(기본)는 **저장·가져오기 시점**용이다 — 구조 검사에 더해 실제로
    돌려 보는 실행시간 검사(`_runs_in_bounded_time`)까지 한다.

    `deep=False` 는 **판정 경로**용이다(`resolve_pattern_source`). 판정 경로에서
    시간을 재면 안 된다 — 판정이 PC 부하에 의존하게 된다. 실측(재비판 라운드 2):
    8코어에 64프로세스를 걸면 개별 `re.search` 가 스케줄링 스톨로 밀려
    정상 패턴 `RITM\\d{3,12}` 이 정책 30,000건 중 1건에서 거부됐고, **그 정책만
    등급이 7→3 으로 뛰었다**(화면에는 아무 표시도 없다). 같은 config 를 다시
    돌리면 결과가 달라지는 것은 이 도구가 절대 해서는 안 되는 일이다.
    구조 검사는 순수 함수라 언제 돌려도 같은 답을 준다.
    """
    if not pattern or not pattern.strip():
        return False, "Pattern is empty."
    if len(pattern) > MAX_PATTERN_LEN:
        # **실제 길이(201자)를 문장에 넣지 않는다.** 값이 끼면 매번 문장이 달라
        # 사전 키가 못 되고, 한국어 사용자는 이 문장만 영어로 본다. 상한은
        # 고정 상수라 문장이 안정적이다(v129 재비판 발견 3의 형제 건 —
        # 새 계약 테스트가 잡았다).
        return False, (f"That pattern is too long. Keep it under "
                       f"{MAX_PATTERN_LEN} characters.")
    if _looks_catastrophic(pattern):
        return False, ("Nested quantifiers such as (x+)+ can hang the "
                       "assessment on some names. Use a bounded form like "
                       r"[A-Z]{3}\d{3,12} instead.")
    # 반복되는 교대(`(a|a)*`)는 위의 AST 검사가 함께 본다. 예전에는 정규식
    # 규칙을 따로 뒀는데, 분기가 **겹치는지**를 못 봐서 `(?:RITM|INC)+\d{7}`
    # 같은 정상 패턴 3종을 잘랐다(실측 0.0ms). AST 는 겹치는 분기만 막는다.
    try:
        # **판정이 실제로 쓰는 것과 같은 플래그로 컴파일한다.** 여기서 플래그
        # 없이 컴파일해 놓고 `compile_ticket_pattern` 은 `re.IGNORECASE` 로
        # 컴파일했다 — 아래 실행 프로브가 **다른 객체를 재고 있었다**.
        # IGNORECASE 는 문자 클래스를 넓히므로 시간이 완전히 달라진다:
        # `([A-Z]{1,3})+!` 는 소문자 미끼에 0.2ms 로 통과했지만, 실제 판정에서
        # ALL-CAPS 정책명 "SEOULDCTOHQDMZWEBSERVERACCESS"(29자)에 **10.9초**가
        # 걸렸다(2026-09-10 실측). MAX_SCAN_LEN 은 256 이고 정책은 1,500건대다.
        # 설정은 파일에 남고 판정 경로는 구조 검사만 하므로 매 실행 다시
        # 채택된다 = **영구 브릭**. 게다가 설정 화면(GET /api/settings/ticket)이
        # 미리보기로 그 패턴을 전 정책에 돌리므로 지우러 들어가지도 못한다.
        compiled = re.compile(pattern, _TICKET_FLAGS)
    except re.error as exc:
        # 파이썬 `re` 의 내부 문구("unterminated character set at position 1")
        # 를 그대로 보여주면 사용자는 무엇을 고쳐야 할지 모른다.
        #
        # **사용자 패턴 글자를 콘솔에 그대로 싣지 않는다** — `re.error` 는
        # 문제가 된 문자를 메시지에 넣는다("bad character range 가-나"). exe 는
        # console=True 이고 윈도우 콘솔은 CP949 라, 인코딩 안 되는 글자가 섞이면
        # 이 `print` 자체가 UnicodeEncodeError 를 던져 **번역된 400 대신 맨 500**
        # 이 나갔다. 로그는 ASCII 로 이스케이프해 남긴다.
        _safe = str(exc).encode("ascii", "backslashreplace").decode("ascii")
        print(f"[APO] ticket regex rejected: {_safe}", flush=True)
        return False, ("That is not a valid regular expression. Check that "
                       "brackets and parentheses are closed.")
    if deep and not _runs_in_bounded_time(compiled):
        return False, ("This pattern takes too long on ordinary policy names. "
                       "Patterns like (a{1,10})+ or ((a)*)* can take hours on a "
                       r"41-character name. Use a bounded form like [A-Z]{3}\d{3,12}.")
    return True, ""


# 파국적 백트래킹 탐지용 미끼 문자열. 정책명에 실제로 나오는 문자들로,
# **끝에서 매치가 실패하도록** 만든다 — 실패해야 엔진이 모든 분할을 되짚는다.
#
# **미끼가 실제 입력을 모형화하지 않으면 프로브는 장식이다.** 옛 미끼는
# 인공 문자열 넷뿐이라 셋이 통째로 빠져 있었다(2026-09-11 실측, 미탐 22건 중
# 13건이 이 경로):
#   ① **리터럴 접두어** — `SEOUL(\w+\w+)+!` 는 미끼 어디에도 "SEOUL" 이 없어
#      `re.search` 가 0번 위치에서 즉시 실패하고 0ms 로 통과한다. 그런데 실제
#      정책명은 거의 다 이런 접두어를 갖는다.
#   ② **공백** — `scan_comment` 가 기본 True 라 패턴이 변경관리 코멘트(산문)
#      에도 도는데, 미끼에는 공백이 한 글자도 없었다.
#   ③ **한글** — `([가-힣]+[가-힣]+)+!` 가 20자에서 폭발하는데 못 잰다.
# 그래서 미끼를 **실제 모양**으로 바꾼다. `demo_assets/_redos_bench.py` 의
# 코퍼스와 같은 종류다 — 벤치는 이미 실물을 쓰는데 정작 검증자만 옛것이었다.
_REDOS_SEEDS = (
    "a", "A", "A1_", "0",
    "SEOULDCTOHQDMZWEBSERVERPRODACCESSALLOWRULE",
    "HQ_DMZ_WEB_SERVER_ALLOW_TCP443_FROM_BRANCH_OFFICE_",
    "250822_RITM0282811_PROD_WEB_ACCESS_CHANGE_",
    "서울센터웹서버접근허용정책설정변경요청건",
    "Change request CHG0012345 approved by the network security team ",
)

# **미끼는 재는 최대 길이보다 짧으면 안 된다.** 짧으면 `bait[:n]` 이 조용히
# 더 짧은 문자열을 재고, 긴 길이에서만 터지는 패턴을 놓친다. 씨앗을 상한까지
# 반복해 만든다 — `test_redos_detection_is_absolute_time_only` 가 이 계약을
# 고정한다(실제로 이 실수를 잡았다).
_REDOS_BAIT = tuple(
    (s * (MAX_SCAN_LEN // len(s) + 1))[:MAX_SCAN_LEN] for s in _REDOS_SEEDS)

# 미끼 길이를 늘려 가며 잰다. 파국적 패턴은 길이가 늘수록 지수로 커지므로
# 어느 단계에서든 임계를 넘고, 그 순간 멈추므로 검사 자체가 유한하다.
#
# **길이를 늘리면 프로브 자체가 무기가 된다.** 한때 `MAX_SCAN_LEN`(256)까지
# 재도록 늘렸는데, 예산 검사는 `search` 가 **돌아온 뒤**에 하므로 32자에서
# 0.09초인 패턴이 64자에서 몇 분이 될 수 있다 — 설정 저장 한 번이 서버를
# 멈춘다(2026-09-11 실측: 변이 테스트가 10분을 넘겨 중단됐다).
#
# 그래서 길이는 32 에 둔다. 긴 입력에서만 터지는 것은 **구조 검사가** 잡는다
# (지금 위험 63종 전부 구조만으로 차단된다). 프로브는 구조가 못 본 모양을
# 위한 2차 그물이고, 2차 그물이 1차보다 위험하면 안 된다.
#
# 근본 해법(자식 프로세스 + 벽시계 상한)은 backlog 의 방향 결정 항목이다 —
# 번들 exe 에서는 `sys.executable` 이 APO 자신이라 그대로는 못 쓴다.
_REDOS_LENGTHS = (20, 24, 28, 32)

# 한 번의 매칭이 이 시간을 넘으면 정상 패턴이 아니다.
# 실측(2026-09-09): 정상 패턴 5종은 32자에서 **3마이크로초**, 폭발 패턴 6종은
# 전부 이 임계를 넘는다 — 33,000 배 여유라 부하로 뒤집히지 않는다.
_REDOS_BUDGET_SEC = 0.10


def _runs_in_bounded_time(compiled) -> bool:
    """이 패턴이 평범한 정책명에서 지수적으로 폭발하지 않는가.

    **정규식 모양 검사만으로는 못 막는다.** `_NESTED_QUANTIFIER` 는 괄호 안의
    `+`/`*` 만 보므로 `(a{1,10})+b`·`(a{2,})+b`·`((a)*)*b`·`((a+))+b` 가 전부
    통과했고, 12자짜리 `(\\w{1,10})+!` 와 41자짜리 평범한 FortiGate 정책명
    하나로 요청이 영영 돌아오지 않았다(2026-09-09 보안 렌즈 실측).

    그래서 모양이 아니라 **실행 시간**을 본다. 판단은 **절대시간 하나뿐**이다.

    한때 '증가율(20자 대비 4배)' 규칙을 함께 썼다 — `(a{2,})+b` 가 24자에서
    8ms 라 절대시간을 빠져나갔기 때문이다. 그런데 그 규칙이 **부하에서 뒤집혔다**:
    20자 측정이 스케줄링 스톨로 부풀면 배수가 4를 못 넘어 폭발 패턴이 통과했고,
    전체 스위트에서 그 테스트가 실제로 빨갛게 났다(2026-09-09 릴리스 재검증).
    시간 **차이**를 재는 판단은 잡음에 약하다. 시간 **크기**만 본다.

    대신 미끼를 32자까지 늘려 가며 잰다. `(a{2,})+b` 는 32자에서 0.6초가 되어
    절대시간에 걸린다. 더 폭발적인 것들은 20자에서 이미 걸려 그 자리에서 멈추므로
    검사 비용도 유한하다(실측 최악 0.6초).

    남는 구멍은 정직하게 적어 둔다 — 32자까지 100ms 안이면서 256자
    (`MAX_SCAN_LEN`)에서 폭발하는 **아주 완만한** 지수 패턴은 통과한다.
    그런 패턴을 잡으려면 미끼를 더 늘려야 하는데, 그러면 검사 자체가 수십 초가
    될 수 있다. 결정성을 택했다.
    """
    import time
    for bait in _REDOS_BAIT:
        for n in _REDOS_LENGTHS:
            s = bait[:n]
            t0 = time.perf_counter()
            try:
                compiled.search(s)
            except Exception:
                return True          # 실행 오류는 여기서 판단할 일이 아니다
            if time.perf_counter() - t0 > _REDOS_BUDGET_SEC:
                return False
    return True


# ── 최종 패턴 해석 ─────────────────────────────────────────────────────────

def ticket_settings() -> dict:
    raw = load_settings().get("ticket")
    return raw if isinstance(raw, dict) else {}


def resolve_pattern_source(profile_pattern: str | None) -> tuple[str | None, str]:
    """어떤 패턴을 쓸지와 **그것이 어디서 왔는지** 돌려준다.

    출처를 함께 돌려주는 이유: 화면이 "이 값이 어디서 왔는지" 말할 수 있어야
    한다. 설정 화면에서 넣었는데 프로파일 값이 이기고 있으면 사용자는 자기
    입력이 왜 무시됐는지 알 방법이 없다.
    """
    cfg = ticket_settings()
    regex = cfg.get("regex")
    if not TICKET_REGEX_ENABLED and isinstance(regex, str) and regex.strip():
        # **옛 버전에서 저장한 값이 남아 있을 수 있다.** 조용히 무시하면
        # 티켓 인식률이 이유 없이 떨어진 것처럼 보인다 — 화면이 설명할 수
        # 있도록 출처를 따로 돌려준다.
        prefixes = normalize_prefixes(cfg.get("prefixes"))
        built = build_prefix_pattern(prefixes)
        if built:
            return built, "settings-prefixes-regex-disabled"
        if profile_pattern:
            return str(profile_pattern), "profile-regex-disabled"
        return None, "regex-disabled"
    if isinstance(regex, str) and regex.strip():
        # **판정 경로다 — 시간을 재지 않는다**(deep=False). 여기서 실행시간
        # 검사를 하면 같은 config 가 PC 부하에 따라 다른 등급을 받는다.
        # 폭발하는 패턴은 저장·가져오기 시점(deep=True)에서 이미 걸러진다.
        ok, _ = validate_regex(regex.strip(), deep=False)
        if ok:
            return regex.strip(), "settings-regex"
        # 저장된 값이 나중 규칙으로 부적격이 돼도 앱은 떠야 한다. 프로파일로
        # 떨어뜨리되 조용히 넘기지 않는다.
        # **em dash 를 쓰지 않는다.** 이 print 는 판정 루프 한가운데서 불릴 수
        # 있고, 한국어 Windows 콘솔은 CP949 라 U+2014 가 UnicodeEncodeError 를
        # 던져 **점검 전체를 죽인다**(재비판 라운드 2 실측, console=True 빌드).
        print("[APO] the saved ticket pattern failed validation and was "
              "ignored - re-enter it in Settings.", flush=True)
    prefixes = normalize_prefixes(cfg.get("prefixes"))
    built = build_prefix_pattern(prefixes)
    if built:
        return built, "settings-prefixes"
    if profile_pattern:
        # **막은 문과 안 막은 문이 나란히 있었다.** 사용자 정규식은 껐는데
        # 프로파일 파일(`profiles/*.yaml` 의 `ticket_id_pattern`)은 무검사로
        # 채택됐다 — 실측: `([A-Z]{1,3})+!` 가 정책 **1건에 21.5초**(1,500건
        # 이면 약 9시간). 같은 패턴을 저장 경로는 정확히 거절한다.
        # 배포 파일이라 원격 위험은 아니지만, 컨설턴트가 고객사용으로 이 줄을
        # 손보면 **경고 없이 점검이 멈춘다**(6라운드 S1).
        #
        # 구조 검사는 순수 함수라 판정 경로에서도 결정적이다 — 시간을 재지
        # 않으므로 PC 부하에 따라 등급이 흔들리지 않는다.
        if _looks_catastrophic(str(profile_pattern)):
            print("[APO] the profile ticket pattern can hang the assessment "
                  "and was ignored - fix ticket_id_pattern in the profile.",
                  flush=True)
            return None, "profile-unsafe"
        return str(profile_pattern), "profile"
    return None, "none"


_pattern_cache: dict[str, Any] = {"key": object(), "compiled": None}


def compile_ticket_pattern(profile_pattern: str | None) -> re.Pattern | None:
    """설정·프로파일을 반영한 컴파일 패턴.

    **모듈 로드 시점에 한 번 컴파일하면 안 된다.** 예전에는 그렇게 해서,
    설정을 저장해도 서버를 재시작하기 전까지 반영되지 않았다. 캐시 키에
    설정 파일 mtime 이 들어가므로 저장 즉시 새 패턴이 쓰인다.
    """
    source, _ = resolve_pattern_source(profile_pattern)
    key = (source, _cache["mtime"])
    if _pattern_cache["key"] == key:
        return _pattern_cache["compiled"]
    compiled = None
    if source:
        try:
            compiled = re.compile(source, _TICKET_FLAGS)
        except re.error as exc:
            # 사용자 패턴과 re 의 오류 문구 둘 다 한글을 담을 수 있다 —
            # CP949 콘솔에서 print 가 죽지 않게 ASCII 로 이스케이프한다.
            _safe = f"{source!r} did not compile: {exc}".encode(
                "ascii", "backslashreplace").decode("ascii")
            print(f"[APO] ticket pattern {_safe} - "
                  f"ticket IDs will not be read.", flush=True)
    _pattern_cache["key"] = key
    _pattern_cache["compiled"] = compiled
    return compiled


def scan_comment_enabled() -> bool:
    """정책 이름 말고 comment 에서도 티켓을 찾을지.

    FireMon 등은 변경 번호를 장비 comment 에 적는 것을 표준으로 둔다. 이름만
    보면 그런 조직은 전량 미인식이 된다. 기본값 True.
    """
    val = ticket_settings().get("scan_comment")
    return True if val is None else bool(val)
