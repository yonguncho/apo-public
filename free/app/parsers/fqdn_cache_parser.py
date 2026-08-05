"""FortiGate DNS/FQDN 덤프 파서.

지원 입력:
  - `diagnose test application dnsproxy 6`  (DNS 프록시 캐시)
  - `diagnose firewall fqdn list`           (FQDN 객체 매칭 IP — 더 정확)

파일 덤프는 형식이 지저분하고 진단/통계 라인이 섞여 있다. 여기서 IP를
FQDN에 잘못 귀속시키면 도달불가 판정이 **오탐**을 낸다("오탐 0" 보장 위반).
그래서 관대함보다 **엄격한 귀속**을 택한다:

  1. 도메인이 있는 줄 → 현재 이름(current)으로 잡는다.
  2. IP는 그 줄이 **순수 IP 레코드 라인**일 때만 current에 귀속한다.
     순수 IP 레코드 = 토큰이 전부 IPv4 / `IP(...)` 래퍼 / `ttl=<n>` 인 줄.
  3. 도메인도 아니고 순수 IP 라인도 아닌 줄(예: `server=8.8.8.8 latency=2`,
     `DNS latency info:`)을 만나면 current를 **리셋**한다 — 블록 경계로 본다.
  4. 빈 줄도 경계로 본다. 이름 없는 IP 블록이 앞 이름에 붙는 것을 막기
     위해서다. 대가로 "이름 줄 / 빈 줄 / IP 줄" 배치의 덤프에서는 그 항목을
     통째로 놓친다(미탐) — doctrine상 오탐보다 미탐이 낫고, 임포트 응답이
     인식 건수를 돌려주므로 사용자가 결과가 빈 것을 즉시 알 수 있다.
     더 정확한 소스가 필요하면 장비 직접 수집(구조화 JSON)을 쓴다.

이 규칙은 미탐(들여쓰기가 특이한 IP를 놓침)은 허용해도 오귀속(다른 IP를
FQDN에 붙임)은 구조적으로 만들지 않는다. 미탐은 스킵으로, 오탐은 금지.
"""
from __future__ import annotations

import ipaddress
import re

# 도메인: 점 포함 + 문자 TLD (IP와의 오인 방지)
_NAME_RES = [
    re.compile(r'"([A-Za-z0-9_\-\.]+\.[A-Za-z]{2,})\.?"'),
    re.compile(r'\b(?:name|fqdn)[=:]\s*([A-Za-z0-9_\-\.]+\.[A-Za-z]{2,})\b',
               re.IGNORECASE),
    re.compile(r'^\s*(?:FQDN|Name)\s*:\s*([A-Za-z0-9_\-\.]+\.[A-Za-z]{2,})',
               re.IGNORECASE),
    re.compile(r'^\s*([A-Za-z0-9_\-\.]+\.[A-Za-z]{2,})\.?\s*:'),
]
_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
# IP 레코드 토큰: IPv4 / IP(1.2.3.4) / ttl=123 / vf=0 형태의 잡토큰은 불허
_IP_WRAP_RE = re.compile(r'^IP\((\d{1,3}(?:\.\d{1,3}){3})\)$', re.IGNORECASE)
_TTL_RE = re.compile(r'^ttl=\d+$', re.IGNORECASE)


def _valid_ip(text: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError:
        return False
    return not (ip.is_unspecified or ip.is_loopback or ip.is_multicast)


def _is_octet_ok(text: str) -> bool:
    """형식상 IPv4인가(0.0.0.0도 True — 레코드 라인 판정용)."""
    try:
        ipaddress.IPv4Address(text)
        return True
    except ipaddress.AddressValueError:
        return False


def _line_record_ips(line: str) -> list[str] | None:
    """줄이 '순수 IP 레코드 라인'이면 그 안의 유효 IP 목록을, 아니면 None.

    토큰 하나라도 IPv4/IP(...)/ttl= 이 아니면 None (블록 경계 신호).
    """
    tokens = line.replace(",", " ").split()
    if not tokens:
        return None
    ips: list[str] = []
    for tok in tokens:
        m = _IP_WRAP_RE.match(tok)
        if m:
            if _valid_ip(m.group(1)):
                ips.append(m.group(1))
            continue
        if _is_octet_ok(tok):
            if _valid_ip(tok):
                ips.append(tok)
            continue
        if _TTL_RE.match(tok):
            continue
        return None                  # 잡토큰 → IP 레코드 라인 아님
    return ips


def parse_dnsproxy_dump(text: str) -> dict[str, list[str]]:
    """덤프 텍스트 -> {fqdn(소문자): [정렬된 IPv4 목록]}."""
    out: dict[str, set] = {}
    current: str | None = None
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            current = None       # 빈 줄도 블록 경계 (재비판 SUSPECT)
            continue

        name = None
        for pat in _NAME_RES:
            m = pat.search(line)
            if m:
                name = m.group(1).lower().strip(".")
                break

        if name:
            current = name
            out.setdefault(current, set())
            # 이름 줄에 붙은 IP는, 도메인을 지운 나머지가 순수 IP 레코드일 때만.
            residue = line
            for pat in _NAME_RES:
                residue = pat.sub(" ", residue)
            residue = residue.replace('"', " ").replace(":", " ")
            rec = _line_record_ips(residue)
            if rec:
                out[current].update(rec)
            continue

        rec = _line_record_ips(line)
        if rec is None:
            current = None           # 블록 경계 — 오귀속 방지의 핵심
            continue
        if current:
            out[current].update(rec)

    return {k: sorted(v) for k, v in out.items() if v}
