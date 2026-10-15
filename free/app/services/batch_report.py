# -*- coding: utf-8 -*-
"""일괄 보고 (MSP / Consultant 전용) — 장비별 config 여러 개를 한 번에 분석해
장비당 워크북 하나씩을 zip으로 만든다.

설계 원칙:
  1. **세션과 완전 격리.** 이 모듈은 app.config를 읽지도 쓰지도 않는다.
     화면에서 분석 중인 장비의 상태(last_parsed, user_ranges, fqdn_cache)와
     섞이는 순간 A고객 config를 B고객 기준으로 판정하는 교차 오염이 된다.
  2. **고객사별 산출물 분리.** 여러 고객 결과를 한 워크북에 합치지 않는다 —
     고객 A의 정책명이 고객 B에게 전달되는 사고를 원천 차단한다. zip 안의
     SUMMARY.txt는 컨설턴트 내부용 집계일 뿐, 정책명 등 내용은 담지 않는다.
     zip 엔트리 이름 배정도 같은 원칙을 따른다 — 이름이 정규화로 바뀐 장비가
     다른 장비의 정확한 이름을 차지하면 보고서가 엉뚱한 고객에게 간다
     (리뷰 라운드 2 critical, 실패 장비 예약은 라운드 3). 자기 이름 그대로인
     장비가 — 분석 실패조차 — 항상 이름 우선권을 갖고, 바뀐 배정은 SUMMARY에
     stem → 파일명 매핑으로 남는다.
  3. **파일명 짝짓기 규칙** (업로드한 파일 묶음에서 stem으로 매칭):
       X.conf / X.txt   — config (필수)
       X.csv            — Firewall Policy CSV (hit count / last used, 선택)
       X.proxy.csv      — Proxy Policy CSV (선택)
       X.ranges.txt     — 사용자 IP 대역, 줄/쉼표 구분 CIDR (선택)
     장비마다 입력이 다르므로 대역·통계를 전역으로 공유하지 않는다.
     같은 자리에 파일이 둘이면 **먼저 온 것이 이기고 나중 것은 기록**된다 —
     조용한 덮어쓰기는 판정 입력 변조인데 흔적이 없다(라운드 1·2).
     'X.proxy'라는 stem의 장비(config X.proxy.conf)가 있으면 'X.proxy.csv'는
     그 장비의 FW CSV로 귀속한다 — 접미사 규칙이 실제 장비 이름을 이기면
     남의 hit count로 판정하는 오귀속이 된다(라운드 2 critical).
  4. **부분 실패 허용.** 한 config가 깨져도 나머지는 만든다. 실패는
     SUMMARY.txt에 기록하고, 전부 실패했을 때만 오류로 돌려준다.

FQDN 캐시는 배치에서 쓰지 않는다 — 장비 접속 없이 파일만으로 도는 경로라
해석 스냅샷이 없고, 없는 것을 없다고 각 워크북의 커버리지 항목이 말한다.
"""
from __future__ import annotations

import hashlib
import io
import re
import unicodedata
import zipfile
from app.parsers.config_parser import config_intake_problem
from dataclasses import dataclass, field
from datetime import date, datetime


# 한 번에 처리할 config 수 상한. 파싱·분류는 CPU 작업이라 상한이 없으면
# 요청 하나가 프로세스를 수 분간 점유한다(단일 사용자 로컬 앱이라도
# 실수로 폴더 전체를 끌어넣는 경우를 막는다).
MAX_CONFIGS = 50

_RANGES_SUFFIX = ".ranges.txt"
_PROXY_CSV_SUFFIX = ".proxy.csv"
_CONFIG_EXTS = (".conf", ".txt")


@dataclass
class _Device:
    stem: str
    config_name: str = ""
    config_text: str = ""
    csv_name: str = ""
    csv_text: str = ""
    proxy_csv_name: str = ""
    proxy_csv_text: str = ""
    ranges_name: str = ""
    ranges_text: str = ""
    stats_count: int = 0
    stats_unmatched: int = 0   # 읽혔지만 이 config의 정책이 아닌 행 수
    stats_vdom_skipped: bool = False   # 다중 VDOM이라 CSV 귀속 불가 → 미적용
    stats_vdom: str = ""       # 보관소가 아는 사용량의 VDOM 귀속(있으면 적용)
    ranges_count: int = 0
    ranges_rejected: int = 0      # 주소가 하나도 없던 '줄' 수
    ranges_addr_lines: int = 0    # 주소가 있던 '줄' 수
    sha8: str = ""             # 라벨이 같아 보일 때 장비를 가르는 최후의 식별자
    entry: str = ""            # zip 엔트리 이름 (확장자 제외)
    xlsx: bytes = b""
    error: str = ""
    counts: dict = field(default_factory=dict)


# Windows에서 압축 해제가 실패하는 예약 장치 이름 — 엔트리 이름으로 못 쓴다.
_WIN_RESERVED = {"con", "prn", "aux", "nul",
                 *(f"com{i}" for i in range(1, 10)),
                 *(f"lpt{i}" for i in range(1, 10))}


def _safe_stem(name: str) -> str:
    """zip 엔트리 이름용 — 경로 구분자·제어문자를 제거한다.

    업로드 파일명은 사용자 입력이다. '..\\evil' 같은 이름이 zip 엔트리로
    들어가면 압축을 푸는 쪽에서 경로 탈출이 된다(zip-slip).
    """
    # NFKC 정규화 먼저 — 전각 슬래시(／)·두점 리더(‥) 같은 유사문자가
    # 정규화로 실제 구분자·점이 된 뒤에 걸러져야 한다(리뷰 라운드 1).
    stem = unicodedata.normalize("NFKC", name)
    stem = re.sub(r"[\\/]", "_", stem)
    # 보이지 않는 문자는 **카테고리로** 지운다(Cf = format). 개별 코드포인트를
    # 하나씩 막으면 늘 빠진 게 남는다 — 라운드 5에서 U+2028을 막았더니 라운드 6에
    # U+FEFF·U+200B·U+00AD가 나왔다. 이 문자들이 살아남으면 서로 다른 두 고객의
    # zip 파일명이 화면상 같아지고(안 보이는 차이) 매핑도 안 붙어, 컨설턴트가
    # 'ACME-FW.xlsx'를 고를 때 어느 고객 것인지 알 수 없다(라운드 6 critical).
    stem = "".join(c for c in stem if unicodedata.category(c) != "Cf")
    stem = re.sub("[\\x00-\\x1f\\x7f<>:\"|?*\\u2028\\u2029\\u0085]", "", stem)
    stem = re.sub(r"\.{2,}", "_", stem).strip(". ")   # '..' 자체도 남기지 않는다
    # **길이는 앞이 아니라 가운데를 줄여서 맞춘다.** 실무 파일명은
    # `<고객><사업><단계>-<장비명>` 순이라 장비를 가리키는 부분이 **끝**에 있다.
    # 앞에서 80자를 자르니 고객명이 긴 배치에서 HQ·DR·BR 세 대가 전부 같은
    # 이름이 됐고, 충돌 회피가 `..._F`, `..._F_1`, `..._F_2` 를 만들었다 —
    # zip 은 안전했지만 컨설턴트가 **어느 xlsx 가 어느 장비인지 알 수 없었다**
    # (라운드 47 실측). 양끝을 남기면 고객도 장비도 읽힌다.
    if len(stem) > 80:
        stem = stem[:40] + "~" + stem[-39:]
    # 밑줄·점만 남았으면 이름 구실을 못 한다 — 자리표시로 대체
    if not re.sub(r"[._\s]", "", stem):
        return "device"
    if stem.lower() in _WIN_RESERVED:
        return "_" + stem
    return stem


def _clean_line(s: str) -> str:
    """SUMMARY.txt 한 줄에 들어갈 사용자 유래 문자열 — 개행·제어문자를 치우고
    길이를 제한한다. 파일명에 개행을 넣어 가짜 [FAILED] 행을 주입하는 것을
    막는다(라운드 2). splitlines()가 행으로 취급하는 유니코드 분리자
    (U+2028/2029/0085)까지 치운다(라운드 3).

    _safe_stem과 **같은 문자 정책**을 쓴다 — 한쪽만 보이지 않는 문자를 지우면
    zip 파일명은 갈라졌는데 SUMMARY 라벨은 똑같이 보이는 상태가 되어, 어느 줄이
    어느 고객인지 알 수 없다(라운드 7 critical). RLO(U+202E)로 줄 뒷부분이
    뒤집혀 보이는 것도 같은 구멍이었다.
    """
    s = "".join(c for c in str(s) if unicodedata.category(c) != "Cf")
    return re.sub("[\\x00-\\x1f\\x7f\\u2028\\u2029\\u0085]", " ", s)[:200]


def group_uploads(files: list) -> tuple[list[_Device], list[str], list[str]]:
    """(filename, text) 목록을 장비 단위로 묶는다.

    → (devices, 무시된 파일, 재배정된 파일)
    '무시'와 '재배정'은 다른 사실이다 — 쓰인 파일이 무시 목록에 있으면
    컨설턴트가 "hit count가 반영 안 됐구나"로 잘못 읽는다(리뷰 라운드 5).
    """
    devices: dict[str, _Device] = {}
    ignored: list[str] = []
    reassigned: list[str] = []

    def dev(stem: str) -> _Device:
        if not stem:
            stem = "device"     # 파일명이 '.conf' 하나뿐인 극단 케이스
        return devices.setdefault(stem.lower(), _Device(stem=stem))

    def claim(d: _Device, name_attr: str, text_attr: str, name: str,
              text: str, kind: str) -> None:
        """같은 자리 선착순 — 진 파일은 반드시 기록한다.

        점유 판단은 내용이 아니라 **파일명**으로 한다 — 빈 파일(내용 "")도
        업로드된 파일이고, 내용으로 판단하면 빈 config가 자리를 차지하지 못한 채
        장비 목록에서 소리 없이 사라진다(라운드 3 테스트에서 실제 발견).
        """
        if getattr(d, name_attr):
            # 두 파일 이름이 같으면 "kept X — dropped X"가 되어 무엇이 버려졌는지
            # 문장으로 구분이 안 된다. 순서를 함께 적는다(라운드 7).
            kept_name = getattr(d, name_attr)
            same = " (same filename)" if name == kept_name else ""
            ignored.append(f"{name} (duplicate {kind} for '{d.stem}'{same} — "
                           f"kept the first: {kept_name})")
            return
        setattr(d, name_attr, name)
        setattr(d, text_attr, text)

    for name, text in files:
        low = name.lower()
        if low.endswith(_RANGES_SUFFIX):
            claim(dev(name[: -len(_RANGES_SUFFIX)]), "ranges_name", "ranges_text",
                  name, text, "ranges")
        elif low.endswith(_PROXY_CSV_SUFFIX):
            claim(dev(name[: -len(_PROXY_CSV_SUFFIX)]), "proxy_csv_name",
                  "proxy_csv_text", name, text, "proxy csv")
        elif low.endswith(".csv"):
            claim(dev(name[: -4]), "csv_name", "csv_text", name, text, "csv")
        elif low.endswith(_CONFIG_EXTS):
            # **확장자만 보면 메모장 파일이 장비가 된다.** `.txt`·`.conf` 라는
            # 이유로 `notes.txt` 가 `[ OK ]` 장비로 세어지고 정식 워크북까지
            # 만들어졌다 — 그 xlsx 한 장을 떼어 보내면 "지적사항 없음"으로
            # 읽힌다(라운드 46 실측). 업로드 라우트와 **같은 문턱**을 둔다.
            _bad = config_intake_problem(text)
            if _bad:
                ignored.append(f"{name} ({_bad[0].split('.')[0].lower()})")
                continue
            claim(dev(name.rsplit(".", 1)[0]), "config_name", "config_text",
                  name, text, "config")
        else:
            ignored.append(name)

    # 'X.proxy.csv'가 실제 장비 'X.proxy'(config 보유)의 FW CSV인 경우 —
    # 접미사 규칙보다 실제 장비 이름이 우선한다. 안 그러면 장비 X의 proxy
    # 정책이 장비 X.proxy의 hit count로 판정된다(리뷰 라운드 2 critical).
    for d in list(devices.values()):
        # 파일명 기준 — 빈 내용의 proxy CSV도 업로드된 파일이다(라운드 4 일관성).
        if not d.proxy_csv_name:
            continue
        owner = devices.get((d.stem + ".proxy").lower())
        if owner and owner.config_name:
            if owner.csv_name:
                ignored.append(f"{d.proxy_csv_name} (duplicate csv for "
                               f"'{owner.stem}' — kept {owner.csv_name})")
            else:
                owner.csv_name = d.proxy_csv_name
                owner.csv_text = d.proxy_csv_text
                reassigned.append(f"{d.proxy_csv_name} → used as the FW CSV of "
                                  f"device '{owner.stem}' (its name ends with .proxy)")
            d.proxy_csv_name = ""
            d.proxy_csv_text = ""

    # config 없이 CSV/ranges만 있는 stem은 장비가 아니다 — 실제 파일명으로
    # 무시 목록에 남긴다(유령 stem만 적으면 원인 추적이 안 된다, 라운드 2).
    out: list[_Device] = []
    for d in devices.values():
        if d.config_name:
            out.append(d)
        else:
            for fname in (d.csv_name, d.proxy_csv_name, d.ranges_name):
                if fname:
                    ignored.append(f"{fname} (no matching config for '{d.stem}')")
    out.sort(key=lambda d: d.stem.lower())
    return out, ignored, reassigned


def _assign_entries(devices: list[_Device]) -> None:
    """zip 엔트리 이름 배정 — 2패스.

    1패스: 정규화로 이름이 변하지 않은 장비가 자기 이름을 갖는다.
    2패스: 이름이 바뀐 장비는 남은 이름을 받되, 이미 배정된 이름과 충돌하면
           접미사를 붙인다. 이름을 '훔치는' 경우가 없어야 보고서가 엉뚱한
           고객에게 가지 않는다(리뷰 라운드 2 critical).
    """
    used: set[str] = set()
    for d in devices:
        safe = _safe_stem(d.stem)
        # used 검사는 현재 파이프라인에선 도달 불가(group_uploads가 stem.lower()로
        # 병합)지만, 없으면 라우팅이 바뀌는 순간 두 장비가 같은 이름을 갖는다.
        if safe == d.stem and safe.lower() not in used:
            # 실패한 장비도 이름은 **예약**한다(엔트리는 안 만든다) — 비워두면
            # 정규화로 이름이 바뀐 장비가 실패한 실장비의 정확한 이름을 차지해,
            # 그 고객 이름의 파일이 남의 보고서인 채 남는다(라운드 3 critical).
            used.add(safe.lower())
            if not d.error:
                d.entry = safe
    for d in devices:
        if d.error or d.entry:
            continue
        base = _safe_stem(d.stem)
        entry, i = base, 1
        while entry.lower() in used:
            entry = f"{base}_{i}"
            i += 1
        d.entry = entry
        used.add(entry.lower())


def _plural(n: int) -> str:
    return "line" if n == 1 else "lines"


def _range_warning(addr_lines: int, rejected: int) -> str:
    """워크북(고객 산출물)에 실을 대역 고지. 주소가 없던 줄이 있으면 무조건
    적고, 그런 줄이 주소가 있던 줄만큼 많으면 파일 자체를 의심하라고 덧붙인다."""
    base = (f"read from a file where {rejected} "
            f"{_plural(rejected)} contained no address")
    if rejected >= addr_lines:
        return base + "; verify this is a ranges list, not an export"
    return base


def _ranges_note(d: "_Device") -> str:
    """SUMMARY의 대역 관련 한 마디 — CSV와 같은 문법으로, **실측 수치**로 말한다.

    '대역 파일을 안 냈다'와 '냈는데 쓸 수 있는 게 없었다'는 다른 사실이다
    (라운드 6 — CSV는 이미 구분하고 있었다). 그리고 유효 항목이 하나라도
    있으면 버리지 않는다 — 라벨·주석이 섞인 실무 파일을 통째로 버리면서
    "쓸 게 없었다"고 적으면, 파일을 열어 IP를 보고 있는 운영자가 원인을
    영영 못 찾는다(라운드 7 critical).
    """
    if d.ranges_count:
        if not d.ranges_rejected:
            return ""
        note = (f" — user ranges: {d.ranges_count} found, "
                f"{d.ranges_rejected} {_plural(d.ranges_rejected)} had no address")
        if d.ranges_rejected >= d.ranges_addr_lines:
            note += " (check this file is a ranges list, not an export)"
        return note
    if d.ranges_name:
        # '비어 있었다'와 '내용은 있는데 주소가 아니었다'는 다른 사실이다 —
        # '(0 unrecognised)'는 앞 문장과 모순돼 읽힌다(라운드 7 명세 지적).
        if not d.ranges_rejected:
            return " — ranges file was empty (partial severity axis)"
        return (f" — ranges file had no usable IP/CIDR entries "
                f"({d.ranges_rejected} {_plural(d.ranges_rejected)} with no "
                f"address) — partial severity axis")
    return " — no user ranges (partial severity axis)"


def _is_netmask(tok: str) -> bool:
    """255.255.0.0 처럼 연속된 1비트 넷마스크인가. 8.8.8.8 같은 주소를
    마스크로 오인하면 대역이 엉뚱하게 넓어진다."""
    import ipaddress
    try:
        val = int(ipaddress.IPv4Address(tok))
    except ValueError:
        return False
    inverted = val ^ 0xFFFFFFFF
    return ((inverted + 1) & inverted) == 0      # 연속 1비트 검사


def _range_to_networks(tok: str) -> list[str]:
    """'10.0.0.1-10.0.0.100' 범위를 CIDR 목록으로. 못 읽으면 빈 목록."""
    import ipaddress
    if "-" not in tok:
        return []
    lo, _, hi = tok.partition("-")
    try:
        nets = ipaddress.summarize_address_range(
            ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip()))
        return [str(n) for n in nets]
    except (ValueError, TypeError):
        return []


def _addresses_in_field(field: str) -> list[str]:
    """쉼표·세미콜론으로 나눈 한 필드에서 대역 표기를 읽는다. → CIDR 문자열들

    FortiGate 사용자가 실제로 쓰는 표기를 그대로 받는다:
      10.0.0.0/8            CIDR
      10.10.0.0 255.255.0.0 주소 + 넷마스크 (장비 CLI의 기본 표기)
      10.0.0.1-10.0.0.100   범위
      10.0.0.5              단일 주소
    뒤에 붙은 라벨은 무시하고, **필드가 주소로 시작할 때만** 읽는다 — 아무 데서나
    주소를 주우면 config 파일이 통째로 '대역'이 된다(라운드 5 critical).

    주소+넷마스크를 두 개의 /32로 읽던 결함은 경고 없이 판정을 바꿨다
    (라운드 11 critical: Traffic Type 8건·Severity 4건 변동).
    """
    import ipaddress
    toks = [t.strip("\"'") for t in field.split() if t.strip("\"'")]
    if not toks:
        return []

    def net(tok: str):
        try:
            return ipaddress.ip_network(tok, strict=False)
        except ValueError:
            return None

    # 공백으로 벌어진 '10.0.0.0 / 8' 도 한 표기다.
    if len(toks) >= 3 and toks[1] == "/":
        joined = net("".join(toks[:3]))
        if joined is not None:
            return [str(joined)]

    first = net(toks[0])
    if first is None:
        # 범위 표기는 ip_network가 못 읽는다 — 별도로 본다.
        return _range_to_networks(toks[0])

    # 주소 + 넷마스크
    if len(toks) >= 2 and _is_netmask(toks[1]):
        combined = net(f"{toks[0]}/{toks[1]}")
        if combined is not None:
            return [str(combined)]

    out = [str(first)]
    for tok in toks[1:]:
        nxt = net(tok)
        if nxt is None:
            break       # 주소 뒤부터는 라벨이다
        out.append(str(nxt))
    return out


# 공개 별칭 — server.py의 단일 장비 경로가 같은 규칙을 쓴다. 사설 심볼에
# 의존하면 리팩터 때 요청 시점 ImportError로 죽는다(ACTION_PLAN_ORDER와 같은 이유).
addresses_in_field = _addresses_in_field
clean_line = _clean_line


def _parse_ranges(text: str) -> tuple[list[dict], int, int]:
    """대역 파일을 읽는다. → (ranges, 주소가 없던 줄 수, 주소가 있던 줄 수)

    단일 경로(/api/user-ranges/set)도 같은 규칙(_addresses_in_field)을 쓰지만,
    배치는 파일 하나를 통째로 삼킨다. 대역 파일 자리에 엉뚱한 파일이 오면
    그 텍스트가 수백 개의 가짜 '대역'이 되고, ip_classifier는 대역 목록이
    비어 있지 않다는 이유로 Unknown 대신 Server로 판정한다 — 대역을 준 적이
    없는데 판정 축이 켜진다(리뷰 라운드 5, 실측으로 판정 변화 확인).
    """
    kept, blank_lines, addr_lines = [], 0, 0
    for raw_line in re.split(r"[\n\r]+", text or ""):
        line = raw_line.strip().lstrip("﻿")
        # 빈 줄과 주석은 '틀린 대역'이 아니다 — 세지 않는다. 실무 파일은
        # #, ;, //, ! 를 두루 쓴다(라운드 7 실측).
        if not line or line[:1] in "#;!" or line.startswith("//"):
            continue
        # 판정 단위는 **줄**, 수집 단위는 **필드**다. 쉼표·세미콜론으로 나눈
        # 필드가 '주소로 시작할 때만' 그 필드의 주소를 취한다.
        #   "10.0.0.0/8 HQ"        → 취함(뒤는 라벨)
        #   "HQ, 10.0.0.0/8"       → 둘째 필드가 주소로 시작 → 취함
        #   "10.0.0.0/8 172.16.0.0/12" → 둘 다 취함(공백 나열도 잃지 않음)
        #   "set subnet 10.10.0.0 255.255.0.0" → 필드가 키워드로 시작 → 안 취함
        # 마지막 줄이 핵심이다. 토큰을 무차별로 훑으면 config 파일이 다시
        # 수백 개의 '대역'이 되어 판정 축이 잘못 켜진다(라운드 5 critical).
        found = 0
        for field in re.split(r"[,;]", line):
            got = _addresses_in_field(field)
            kept.extend({"cidr": c} for c in got)
            found += len(got)
        if found:
            addr_lines += 1
        else:
            blank_lines += 1    # 이 줄엔 주소가 하나도 없었다
    # 유효 항목은 절대 버리지 않는다. 판정 축이 잘못 켜지는 것을 막는 것은
    # kept == 0 조건이 이미 한다(엉뚱한 파일은 유효 항목이 0이다) — 비율로
    # 통째 폐기하면 라벨 섞인 정상 파일까지 죽는다(라운드 7 critical).
    return kept, blank_lines, addr_lines


def build_batch_zip(files: list, *, engine_ctx: dict, profile: dict,
                    apo_version: str, branding: dict | None = None,
                    today: date | None = None,
                    sha_by_name: dict | None = None,
                    filename_by_name: dict | None = None,
                    usage_by_name: dict | None = None,
                    customer_by_name: dict | None = None,
                    object_rules_by_name: dict | None = None,
                    stats_vdom_by_name: dict | None = None,
                    collect_coverage_by_name: dict | None = None
                    ) -> tuple[bytes, dict]:
    """장비별 워크북 zip을 만든다. → (zip_bytes, summary_dict)

    files: [(filename, text)] — 라우트가 디코딩까지 마친 상태로 준다.
    engine_ctx/profile: 현재 세션의 판정 기준(임계값·규칙). 기준은 컨설턴트의
    감사 기준이므로 장비 간 공유가 맞다 — 장비별로 달라야 하는 것(대역·통계·
    **객체 명명 규칙**)만 파일 짝짓기로 받는다.

    object_rules_by_name: {엔트리 파일명: {분류: [이름…]}}. 객체 이름은 그
    조직의 사실이지 컨설턴트의 기준이 아니다 — 하나를 전부에 적용하면 고객 A 의
    이름으로 고객 B 정책이 예외를 받는다(라운드 44 실측).

    stats_vdom_by_name: {엔트리 파일명: vdom}. 보관소가 이미 아는 사용량의
    VDOM 귀속. CSV 텍스트로 재직렬화하며 태그가 벗겨져, 배치가 다중 VDOM
    장비에서 "VDOM 을 모른다 — 단독으로 열어 지정하라"고 **사용자가 이미
    지정한 것을** 요구하고 사용량을 통째로 버렸다(라운드 56 계약 렌즈 —
    화면 Critical vs 배치 usage unknown 갈림).
    """
    from app.parsers.config_parser import FortiGateConfigParser
    from app.parsers.policy_csv_parser import PolicyStatsCsvParser
    from app.services.policy_renderer import build_view_model
    from app.services.reachability import detect_unreachable
    from app.services.severity_engine import evaluate_severity
    from app.services.profile_loader import describe_inactive_rules
    from app.services.workbook_exporter import build_severity_workbook, \
        ACTION_PLAN_ORDER, _vdom_of

    # "조치 필요"의 정의는 엑셀 Action Plan 시트와 같은 원천을 쓴다.
    # 여기서 따로 하드코딩하면 같은 zip 안에서 SUMMARY와 워크북 숫자가
    # 모순된다 — 리뷰 라운드 1에서 실제로 그랬다(6 vs 10).
    actionable_labels = {label for label, _ in ACTION_PLAN_ORDER}

    devices, ignored, reassigned = group_uploads(files)
    if not devices:
        raise ValueError("No config files found. Include at least one .conf/.txt "
                         "FortiGate configuration.")
    if len(devices) > MAX_CONFIGS:
        raise ValueError(f"Too many devices in one batch — limit is {MAX_CONFIGS}.")

    generated_at = (today or date.today()).strftime("%Y-%m-%d") \
        + datetime.now().strftime(" %H:%M")

    # ── 1단계: 전 장비 분석 (zip 기록은 이름 배정이 끝난 뒤에) ──────────
    ok_count = 0
    for d in devices:
        # 해시는 파싱 **전에** 낸다 — try 안에서 내면 실패한 장비의 [FAILED] 행에
        # 식별자가 없어, 보이지 않는 문자만 다른 두 고객의 실패 행이 완전히
        # 같은 문자열이 된다(라운드 8 명세 지적, 라운드 7 critical과 같은 클래스).
        _sha_full = (sha_by_name or {}).get(d.config_name) or hashlib.sha256(
            d.config_text.encode("utf-8", "ignore")).hexdigest()
        d.sha8 = _sha_full[:8]
        try:
            parsed = FortiGateConfigParser(d.config_text).parse()
            stats = {}
            if d.csv_name or d.proxy_csv_name:
                # 종류별 네임스페이스 — 단일 경로(policy-stats/import)와 동일.
                # 평평하게 합치면 FW와 proxy의 같은 번호가 서로를 덮어쓴다.
                stats = {
                    "firewall": PolicyStatsCsvParser().parse_text(d.csv_text)
                                if d.csv_text else {},
                    "proxy": PolicyStatsCsvParser().parse_text(d.proxy_csv_text)
                             if d.proxy_csv_text else {},
                }
            # '파일이 있었다'와 '통계가 읽혔다'는 다른 사실이다 — 형식이
            # 안 맞는 CSV가 조용히 무시된 채 "사용량 있음"으로 실리면 안 된다
            # (단일 경로의 csv_loaded 규칙과 동일, server.py의 같은 함정 주석).
            d.stats_count = sum(len(v) for v in stats.values()) if stats else 0
            # 한 걸음 더 — **이 config의 정책과 실제로 맞은 행**을 센다. 짝지은
            # CSV가 다른 장비 것이면 행은 잔뜩 읽히는데 판정에는 하나도 쓰이지
            # 않아, 워크북이 "Usage CSV loaded: yes"라고 적으면서 모든 정책은
            # "사용량 없음"으로 판정되는 자기모순 산출물이 나갔다(라운드 18).
            d.stats_unmatched = 0
            # 귀속 VDOM 을 먼저 안다 — 매칭 모집단이 판정 모집단(_scoped 가
            # 실제로 조인하는 그 VDOM 의 정책)과 같아야 하기 때문이다. 전
            # VDOM 합집합과 대조하면 다른 VDOM 에만 있는 번호가 "matched" 로
            # 세어져 SUMMARY 경고가 억제된다(라운드 58 계약 렌즈, 단일 경로와
            # 같은 수정).
            d.stats_vdom = str((stats_vdom_by_name or {}).get(d.config_name)
                               or "").strip()
            # **매칭 스코프는 조인(_scoped)과 같은 게이트를 지나야 한다.**
            # _scoped 는 다중 VDOM 일 때만 태그를 쓴다 — 여기만 무조건 쓰면
            # 단일 VDOM + 레거시 태그 조합에서 판정은 통계를 쓰는데 문서는
            # "안 썼다"고 적는 자기모순이 난다(B-57, 라운드 60 경계값 렌즈.
            # 라운드 62 완성도 렌즈 권고로 이번 배치 편입).
            _vdoms_b = [v for v in ((parsed.get("meta") or {}).get("vdoms")
                                    or []) if v]
            # 태그 정규화도 같은 게이트 — 단일 VDOM 이면 태그를 아예 비워,
            # 매칭·SUMMARY 노트·문서정보(stats_vdom)·zero-match 문구가 전부
            # 같은 값을 보고 같은 말을 하게 한다.
            if len(_vdoms_b) <= 1:
                d.stats_vdom = ""
            if stats:
                def _known_ids(section):
                    return {str(p.get("policy_id")) for p
                            in (parsed.get(section) or [])
                            if p.get("policy_id") is not None
                            and (not d.stats_vdom
                                 or str(p.get("vdom") or "").strip().lower()
                                 == d.stats_vdom.lower())}
                known = {"firewall": _known_ids("firewall_policy"),
                         "proxy": _known_ids("firewall_proxy_policy")}
                matched = sum(1 for ns, rows in stats.items()
                              for k in rows if k in known.get(ns, set()))
                d.stats_unmatched = d.stats_count - matched
                if d.stats_count and not matched:
                    # 판정에 한 줄도 쓰이지 않았다면 '사용량 있음'이 아니다.
                    d.stats_count = 0
            # **다중 VDOM 사용량은 귀속(VDOM)을 알 때만 쓴다.**
            # 배치 업로드는 물을 통로가 없어 귀속 불가 → 미적용을 그대로
            # 적는다(라운드 54 — 매칭 60/60 인데 "loaded: yes" 거짓 진술 차단).
            # 단, **보관소 경로는 사용자가 이미 지정한 VDOM 을 알고 있다**
            # (stats_vdom_by_name) — 그걸 버리고 "단독으로 열어 지정하라"고
            # 요구하면 화면(Critical)과 배치(usage unknown)가 갈린다(라운드
            # 56 계약 렌즈). 태그를 되살려 조인부(_scoped)에 넘긴다.
            if d.stats_count and len(_vdoms_b) > 1:
                if d.stats_vdom and d.stats_vdom.lower() in {
                        v.lower() for v in _vdoms_b}:
                    stats["_vdom"] = d.stats_vdom
                else:
                    d.stats_count = 0
                    d.stats_unmatched = 0     # 불일치가 아니라 귀속 불가다
                    d.stats_vdom_skipped = True
            user_ranges, d.ranges_rejected, d.ranges_addr_lines = \
                _parse_ranges(d.ranges_text)
            # SUMMARY 노트도 '파싱된 개수'를 본다 — 공백뿐인 ranges 파일이
            # "대역 있음"으로 위장되면 안 된다(라운드 4, CSV와 같은 규칙).
            d.ranges_count = len(user_ranges)
            context = {
                "service_groups": parsed.get("service_groups", {}),
                "user_ranges": user_ranges,
                "today": today or date.today(),
                **engine_ctx,
            }
            # 이 장비의 객체 명명 규칙이 있으면 그것으로 덮는다(항목 단위).
            # 짝짓기 키는 라우트가 넘긴 **원본 config 파일명**이다
            # (`d.config_name`). 루프 변수 `name` 은 여기 없다.
            _orules = (object_rules_by_name or {}).get(d.config_name) or {}
            if _orules:
                _cr = dict(context.get("customer_rules") or {})
                # mgmt 는 infra 로 합쳐졌다 — 엔진이 mgmt_objects 를 읽지 않는다.
                for _kind, _key in (("admin", "admin_objects"),
                                    ("high_risk", "high_risk_objects"),
                                    ("user_segment", "user_segment_objects"),
                                    ("infra", "infra_objects")):
                    if _orules.get(_kind):
                        _cr[_key] = list(_orules[_kind])
                context["customer_rules"] = _cr
            view = build_view_model(parsed, stats)
            # 승인 유효기간 유예 신호는 장비별 사실 — 단일 경로와 같은 맵을
            # 쓴다(안 넘기면 같은 정책이 배치에서만 Critical 로 남는다).
            from app.services.severity_engine import onetime_schedule_map
            _ctx_d = {**context,
                      "onetime_schedules": onetime_schedule_map(parsed)}
            fw = [{**p, **evaluate_severity(p, _ctx_d)}
                  for p in view.get("firewall_policy", [])]
            px = [{**p, **evaluate_severity(p, _ctx_d)}
                  for p in view.get("firewall_proxy_policy", [])]
            reach = detect_unreachable(parsed, None)
            meta = parsed.get("meta") or {}
            payload = {
                "firewall": fw,
                "proxy": px,
                "inactive_rules": describe_inactive_rules(profile),
                "reachability": reach,
                "report_meta": {
                    "apo_version": apo_version,
                    "generated_at": generated_at,
                    "hostname": meta.get("hostname") or "",
                    "config_version": meta.get("config_version") or "",
                    "buildno": meta.get("buildno") or "",
                    # 파일명도 사용자 입력이다 — C0 제어문자가 들어가면
                    # openpyxl이 셀을 거부해 그 장비의 보고서가 통째로 날아간다
                    # (server.py의 브랜딩 입력과 같은 함정, 리뷰 라운드 5).
                    # 보관소 경로에서는 zip 이름이 '고객사 - 장비.conf'라는 합성
                    # 라벨이다. 감사할 때 손에 든 파일과 대조하려면 **원래 올린
                    # 파일명**이 필요하므로, 아는 경우 그것을 싣는다.
                    "config_filename": _clean_line(
                        (filename_by_name or {}).get(d.config_name) or d.config_name),
                    "config_sha256": _sha_full,
                    "profile": (profile.get("meta") or {}).get("name", "default"),
                    "thresholds": engine_ctx.get("thresholds"),
                    "rules": engine_ctx.get("rules"),
                    "user_range_count": len(user_ranges),
                    # 장비 수집의 사용량 커버리지 — 단일 워크북(R70-2)과 같은
                    # 규칙. 보관소가 아는 사실을 배치만 빼면 같은 장비의 두
                    # 보고서가 다른 말을 한다(라운드 73 F1).
                    **({"collect_coverage":
                        (collect_coverage_by_name or {}).get(d.config_name)}
                       if (collect_coverage_by_name or {}).get(d.config_name)
                       else {}),
                    # **같은 장비가 배치에서 조용히 덜 위험해 보였다.**
                    # 배치는 세션의 객체 명명 규칙을 일부러 안 쓴다(라운드 44 —
                    # 고객 A 의 이름으로 고객 B 를 판정하지 않기 위해). 그런데
                    # 워크북이 그 사실을 안 적어, 단일 리포트와 나란히 놓으면
                    # 같은 기준으로 돌린 것처럼 보였다(실측: Critical 3 vs 1).
                    # 기준란에 무엇을 안 썼는지 적는다.
                    "object_rules_note":
                        "Object naming rules from the open session were not "
                        "applied — each device here is assessed on its own "
                        "configuration only. Open the device individually to "
                        "assess it with your saved object names.",
                    # 인식 못 한 줄이 하나라도 있으면 **고객 워크북**에도 적는다.
                    # 'rejected > valid'일 때만 적으면 5/5처럼 팽팽한 경우에
                    # 판정 축은 켜졌는데 고지는 없는 상태가 된다(라운드 9 실측,
                    # 라운드 7 critical과 같은 클래스).
                    **({"user_range_warning": _range_warning(
                        d.ranges_addr_lines, d.ranges_rejected)}
                       if d.ranges_rejected else {}),
                    "csv_loaded": d.stats_count > 0,
                    # 사용량이 한 VDOM 것이면 문서정보가 그 한정을 말해야
                    # 한다 — "loaded: yes" 만 적으면 전 장비 커버로 읽힌다
                    # (라운드 56, 단일 경로 W1 과 같은 규칙).
                    **({"stats_vdom": d.stats_vdom}
                       if (d.stats_count and d.stats_vdom) else {}),
                    # 워크북 스스로 어느 고객의 것인지 말한다 — zip 파일명에만
                    # 있으면 xlsx 한 장을 떼어 보내는 순간 귀속이 사라진다.
                    **({"customer": _clean_line(
                        (customer_by_name or {}).get(d.config_name, ""))}
                       if (customer_by_name or {}).get(d.config_name) else {}),
                    # 보관소 경로에서는 원래 올린 CSV의 이름·해시를 안다.
                    # 파일 업로드 경로에서는 짝지은 파일명이 곧 출처다.
                    "usage_sources": (usage_by_name or {}).get(d.config_name) or (
                        [{"filename": _clean_line(n), "rows": None}
                         for n in (d.csv_name, d.proxy_csv_name) if n]),
                    **({"branding": branding} if branding else {}),
                },
            }
            d.xlsx = build_severity_workbook(payload)

            # 조치 집계는 Action Plan 시트와 같은 중복 제거를 적용한다 —
            # 시트는 도달불가로 증명된 fw 정책을 조치 그룹에서 빼고 도달불가
            # 그룹에 싣는다. SUMMARY도 같은 셈법이어야 두 숫자가 더해서 맞는다
            # (리뷰 라운드 2 지적 — 라운드 1 수정은 라벨 정의만 맞췄었다).
            # VDOM 은 정책 번호의 일부다 — 번호만으로 제외하면 VDOM-B 의
            # 살아있는 조치 대상이 VDOM-A 의 같은 번호 도달불가 때문에
            # 실행필요 집계에서 빠진다. Action Plan 시트와 같은 (VDOM, 번호)
            # 셈법이어야 표지·시트 두 숫자가 서로 맞는다(라운드 50).
            unreachable_keys = {(_vdom_of(u), u.get("policy_id"))
                                for u in (reach.get("unreachable") or [])}
            d.counts = {
                "policies": len(fw) + len(px),
                "critical": sum(1 for p in fw + px if p.get("urgency") == 1),
                "needs_action": (
                    sum(1 for p in fw if p.get("action_label") in actionable_labels
                        and (_vdom_of(p), p.get("policy_id")) not in unreachable_keys)
                    + sum(1 for p in px
                          if p.get("action_label") in actionable_labels)),
                "not_judged": sum(1 for p in fw + px if (p.get("urgency") or 0) == 0),
                "unreachable": len(reach.get("unreachable") or []),
            }
            ok_count += 1
        except Exception as exc:   # 부분 실패 — 이 장비만 건너뛴다
            d.error = _clean_line(str(exc) or exc.__class__.__name__)
            d.counts = {}

    if ok_count == 0:
        errors = "; ".join(f"{_clean_line(d.stem)}: {d.error}"
                           for d in devices if d.error)
        raise ValueError(f"Every config failed to analyse — {errors[:1000]}")

    # ── 2단계: 이름 배정 → zip 기록 ─────────────────────────────────────
    _assign_entries(devices)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for d in devices:
            if not d.error:
                zf.writestr(f"{d.entry}.xlsx", d.xlsx)
                d.xlsx = b""    # 대형 배치에서 메모리를 두 벌 들고 있지 않는다

        # 컨설턴트 내부용 집계. 정책명 등 고객 데이터는 싣지 않는다 —
        # 이 파일이 실수로 고객에게 넘어가도 다른 고객의 내용이 새지 않게.
        lines = [f"APO batch report — {generated_at} — {apo_version}",
                 f"devices: {ok_count} succeeded / {len(devices) - ok_count} failed", ""]
        for d in devices:
            # 상태 표시를 줄 맨 앞 고정 칸으로 둔다 — 장비 이름이 줄 첫머리면
            # '[FAILED] X.conf'라는 파일명이 가짜 실패 행처럼 읽힌다(라운드 9).
            if d.error:
                lines.append(f"[FAILED] {_clean_line(d.stem)} [config {d.sha8}]: "
                             f"{d.error}")
                continue
            # config 해시는 모든 성공 행에 찍는다 — 매핑이 붙은 행에만 있으면
            # 보이지 않는 문자로 라벨이 같아진 다른 행과 대조할 수 없다(라운드 7).
            c = d.counts
            usage_note = ""
            if d.stats_count == 0:
                if d.stats_vdom_skipped:
                    # 귀속 불가는 불일치·미인식과 다른 문제다 — 해법(장비를
                    # 단독으로 열어 VDOM 을 지정)까지 말해야 막다른 길이 아니다.
                    usage_note = (" — usage CSV not applied: this configuration "
                                  "has multiple VDOMs and batch cannot tell "
                                  "which VDOM the CSV came from (open the "
                                  "device individually to specify it)")
                elif d.stats_unmatched:
                    # 행은 읽혔는데 이 config의 정책이 하나도 아니다 — 거의
                    # 언제나 다른 장비의 CSV를 짝지은 것이다. 조용히 '사용량
                    # 없음'으로 넘어가면 그 사실이 산출물 어디에도 안 남는다.
                    # V2 후 매칭 모집단은 귀속 VDOM 이다 — 전건 불일치도
                    # 다른 VDOM 에는 존재할 수 있다(라운드 62, unmatched
                    # 문장 클래스의 네 번째 형제. 단일 경로의
                    # usage_csv_no_match_in_vdom 과 같은 구분).
                    usage_note = ((f" — usage CSV ignored: none of its "
                                   f"{d.stats_unmatched} rows are policies in "
                                   f"VDOM '{d.stats_vdom}' (a different VDOM's "
                                   "or device's CSV?)") if d.stats_vdom else
                                  (f" — usage CSV ignored: none of its "
                                   f"{d.stats_unmatched} rows are policies in this "
                                   f"configuration (wrong device's CSV?)"))
                else:
                    usage_note = (" — usage CSV not recognized (0 rows parsed)"
                                  if (d.csv_name or d.proxy_csv_name)
                                  else " — no usage CSV (disuse not judged)")
            else:
                # 불일치 행과 VDOM 한정은 배타가 아니다 — elif 로 묶었더니
                # 불일치 행이 한 줄만 있어도 참인 한정 고지가 통째로 탈락했다
                # (라운드 58 경계값 렌즈). 둘 다 참이면 둘 다 말한다.
                _notes = []
                if d.stats_unmatched:
                    # V2 후 unmatched 는 "귀속 VDOM 에 없는 번호"다(라운드 60).
                    _notes.append(
                        (f"{d.stats_unmatched} usage row(s) are not policies "
                         f"in VDOM '{d.stats_vdom}'") if d.stats_vdom else
                        (f"{d.stats_unmatched} usage row(s) are not "
                         "policies in this configuration"))
                if d.stats_vdom:
                    # 적용은 됐지만 한 VDOM 것이다 — SUMMARY 도 한정을 말한다.
                    _notes.append(f"usage applies to VDOM '{d.stats_vdom}' "
                                  "only; other VDOMs are judged without "
                                  "usage data")
                if _notes:
                    usage_note = " — " + "; ".join(_notes)
            # stem과 zip 파일명이 다르면 매핑을 명시한다 — 전각 문자 등으로
            # 이름이 바뀐 장비를 SUMMARY만 보고 특정할 수 있어야 한다.
            label = f"{_clean_line(d.stem)} [config {d.sha8}]"
            # 대소문자가 아니라 **바이트로** 비교한다 — 안 보이는 문자만 다른
            # 이름은 소문자 비교로 같아 보여 매핑이 빠진다(라운드 6).
            if d.entry != d.stem:
                # 보이지 않는 문자만 다른 두 장비는 라벨이 똑같이 렌더된다 —
                # 어느 zip 파일이 이 줄인지도 함께 적어야 특정된다(라운드 7).
                label += f" [file: {_clean_line(d.entry)}.xlsx]"
            lines.append(
                f"[  OK  ] {label}: {c['policies']} policies, "
                f"{c['critical']} critical, "
                # **화면·워크북과 같은 수를 먼저 적는다.** 이 줄은 6, Action
                # Plan 시트는 13행, 개요는 13이라 같은 zip 안에서 표지 요약이
                # 시트를 부정했다(라운드 40 실측). 둘 다 참인 분해였는데
                # 라벨이 그 사실을 숨겼다 — 합계를 적고 내역을 괄호에 넣는다.
                f"{c['needs_action'] + c['unreachable']} to act on "
                f"({c['needs_action']} by finding + {c['unreachable']} "
                f"unreachable), {c['not_judged']} not judged"
                + (" — 0 policies parsed (is this a FortiGate config?)"
                   if not c["policies"] else "")
                + usage_note + _ranges_note(d))
        if reassigned:
            lines += ["", "reassigned files (used, not ignored): "
                      + ", ".join(_clean_line(i) for i in reassigned)]
        if ignored:
            lines += ["", "ignored files: "
                      + ", ".join(_clean_line(i) for i in ignored)]
        zf.writestr("SUMMARY.txt", "\n".join(lines) + "\n")

    summary = {
        "devices": len(devices),
        "succeeded": ok_count,
        "failed": len(devices) - ok_count,
        "ignored": ignored,
        "reassigned": reassigned,
    }
    return buf.getvalue(), summary
