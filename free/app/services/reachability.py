"""정적 도달불가(shadowed) 정책 검출.

단일 config 안에서 위쪽 정책 A의 매칭 공간(인터페이스 × 출발지 × 목적지 ×
서비스)이 아래쪽 정책 B를 완전히 포함하면, B에는 어떤 트래픽도 도달하지
않는다. FortiGate는 첫 매칭 정책만 적용하기 때문이며, 이는 A의 액션이
accept든 deny든 마찬가지다(B는 아예 평가되지 않는다).

설계 원칙 — 보수적 판정:
  IP·포트 집합으로 완전히 환원되는 정책만 판정한다. FQDN·지오·ISDB·
  사용자/그룹 조건·negate 등 오프라인 config만으로 환원할 수 없는 요소가
  하나라도 있으면 그 정책은 판정을 건너뛰고 사유를 남긴다. "도달 불가"는
  "미사용 추정"보다 훨씬 강한 주장이라, 증명하지 못하면 말하지 않는다.
  이 원칙 하에서 오탐(도달 가능한데 불가로 보고)은 구조적으로 없다.

의도적 한계 (리포트 Notes에 함께 실린다):
  - shadower는 단일 정책만 본다. 여러 정책의 합집합이 가리는 경우
    (A1 ∪ A2 ⊇ B)는 조합 폭발 때문에 다루지 않는다 — 놓칠 수는 있어도
    잘못 잡지는 않는다.
  - IPv4 firewall_policy만 다룬다. IPv6·프록시 정책은 제외.
  - 경로 분석이 아니다. 라우팅·NAT·존 토폴로지는 보지 않으며, 그런 분석이
    필요한 판정(NSPM의 상관분석)은 이 도구의 범위 밖이다.

VIP(DNAT) 관련 안전성 논거 (v78 자체 검증):
  - central-NAT 모드에서는 정책이 VIP 객체를 dstaddr로 참조하지 않으므로
    이 모듈의 VIP 로직은 발동하지 않는다 — 일반 주소 분석만 적용되어 안전.
  - VIP의 extintf 바인딩은 DNAT 대상 트래픽을 *줄이는* 제약이다. 포함 판정은
    정책이 선언한 인터페이스 공간 기준이므로, 실제 매칭 공간이 그보다 작아도
    "위 정책이 전부 가린다"는 결론은 유지된다(미탐은 가능해도 오탐은 없음).
  - mappedip 하위 테이블 문법(config mappedip)은 현재 파서가 값을 남기지
    않아 환원 불가 → 스킵으로 빠진다(오탐 없음, 후속 엔트리 오염 없음 확인).
"""
from __future__ import annotations

import ipaddress
from typing import Any

# 전체 공간 표식. IP 구간·서비스 튜플 목록 대신 이 값이면 "모든 것과 매칭".
UNIVERSE = "UNIVERSE"

_FULL_V4 = [(0, (1 << 32) - 1)]

# 이 키가 정책에 설정돼 있으면 매칭 공간을 config만으로 환원할 수 없다.
_UNRESOLVABLE_POLICY_KEYS = {
    "internet-service":        "uses Internet Service (ISDB) matching",
    "internet-service-src":    "uses Internet Service (ISDB) source matching",
    "internet-service-name":   "uses Internet Service (ISDB) matching",
    "internet-service-src-name": "uses Internet Service (ISDB) source matching",
    "groups":                  "matches on user groups",
    "users":                   "matches on users",
    "srcaddr-negate":          "uses source address negation",
    "dstaddr-negate":          "uses destination address negation",
    "service-negate":          "uses service negation",
    "srcaddr6":                "uses IPv6 addresses",
    "dstaddr6":                "uses IPv6 addresses",
}


# ---------------------------------------------------------------------------
# 구간(interval) 산술 — IP 집합을 (시작, 끝) 정수 구간 목록으로 다룬다
# ---------------------------------------------------------------------------

def _merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not intervals:
        return []
    out = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def _covers(cover: list[tuple[int, int]], target: list[tuple[int, int]]) -> bool:
    """cover 구간들의 합집합이 target 구간들을 전부 포함하는가."""
    cover = _merge_intervals(cover)
    for lo, hi in _merge_intervals(target):
        ok = False
        for clo, chi in cover:
            if clo <= lo and hi <= chi:
                ok = True
                break
        if not ok:
            return False
    return True


# ---------------------------------------------------------------------------
# 주소 객체 환원
# ---------------------------------------------------------------------------

def _addr_object_intervals(item: dict) -> list[tuple[int, int]] | None:
    """firewall_address 항목 -> IP 구간 목록. 환원 불가면 None."""
    addr_type = item.get("type", "ipmask")
    try:
        if addr_type == "ipmask":
            cidr = item.get("subnet_cidr")
            if not cidr:
                # subnet 미설정 ipmask는 0.0.0.0/0 (FortiGate 기본값)
                return list(_FULL_V4)
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version != 4:
                return None
            return [(int(net.network_address), int(net.broadcast_address))]
        if addr_type == "iprange":
            start = ipaddress.ip_address(item.get("start-ip", ""))
            end = ipaddress.ip_address(item.get("end-ip", ""))
            if start.version != 4 or end.version != 4 or int(start) > int(end):
                return None
            return [(int(start), int(end))]
    except ValueError:
        return None
    # fqdn / wildcard-fqdn / geography / dynamic / mac / interface-subnet 등
    return None


def build_address_map(parsed: dict, fqdn_map: dict | None = None,
                      capture_names: set | None = None
                      ) -> dict[str, list[tuple[int, int]] | None]:
    """주소·주소그룹 이름 -> IP 구간 목록(환원 불가 시 None).

    fqdn_map(dnsproxy 캐시)이 있으면 type=fqdn 객체를 그 스냅샷 IP로
    환원한다. 이렇게 환원된 이름(과 이를 포함한 그룹)은 capture_names에
    기록된다 — 이 이름이 판정에 쓰이면 증명 등급이 'config'가 아니라
    'capture'(수집 시점 기준)로 떨어져야 하기 때문이다.
    """
    out: dict[str, Any] = {}
    fqdn_map = fqdn_map or {}
    for item in parsed.get("firewall_address", []) or []:
        name = item.get("name") or item.get("_edit") or ""
        if not name:
            continue
        iv = _addr_object_intervals(item)
        used_capture = False
        if iv is None and fqdn_map and item.get("type") == "fqdn":
            dom = str(item.get("fqdn", "")).lower().strip().strip(".")
            ips = fqdn_map.get(dom)
            if ips:
                try:
                    iv = _merge_intervals(
                        [(int(ipaddress.IPv4Address(x)),) * 2 for x in ips])
                    used_capture = True
                except ipaddress.AddressValueError:
                    iv = None
        out[name] = iv
        # 같은 이름이 config로 재정의되면(다중 VDOM 평탄화 등) capture 표식을
        # 거둔다 — 실제 판정에 쓰이는 값이 config이면 등급도 config다(재비판).
        if capture_names is not None:
            if used_capture:
                capture_names.add(name)
            else:
                capture_names.discard(name)

    groups = {
        (g.get("name") or g.get("_edit") or ""): (g.get("member") or [])
        for g in parsed.get("firewall_addrgrp", []) or []
    }

    def resolve_group(name: str, stack: frozenset[str]) -> list[tuple[int, int]] | None:
        if name in out:
            return out[name]
        members = groups.get(name)
        if members is None or name in stack:
            return None          # 미정의 객체 또는 순환 참조
        acc: list[tuple[int, int]] = []
        for m in members:
            r = resolve_group(m, stack | {name})
            if r is None:
                out[name] = None  # 멤버 하나라도 환원 불가 → 그룹 전체 불가
                return None
            if capture_names is not None and m in capture_names:
                capture_names.add(name)   # capture 멤버 포함 → 그룹도 capture
            acc.extend(r)
        out[name] = _merge_intervals(acc)
        return out[name]

    for gname in groups:
        resolve_group(gname, frozenset())
    return out


def _parse_ip_or_range(text: str):
    """'1.2.3.4' 또는 '1.2.3.4-1.2.3.10' -> (lo, hi) | None."""
    try:
        t = str(text).strip()
        if "-" in t:
            a, b = t.split("-", 1)
            lo, hi = int(ipaddress.IPv4Address(a.strip())), int(ipaddress.IPv4Address(b.strip()))
            return (lo, hi) if lo <= hi else None
        v = int(ipaddress.IPv4Address(t))
        return (v, v)
    except (ValueError, ipaddress.AddressValueError):
        return None


def build_vip_map(parsed: dict):
    """VIP·VIP그룹 이름 -> mappedip 구간 목록 (환원 불가 시 None).

    ★ extip이 아니라 mappedip인 이유: FortiGate는 정책 조회 *전에* DNAT를
    수행하므로, 정책 매칭 시점의 목적지는 이미 변환된 mappedip이다. extip으로
    비교하면 "extip만 덮고 mappedip은 못 덮는 위 정책"을 shadower로 오판해
    오탐이 생긴다 — 이 모듈의 "오탐 0" 보장을 깨는 지점이라 가장 조심해야 한다.

    보수적 제외(환원 불가 처리): port-forward VIP(서비스 포트까지 변환되어
    서비스 포함관계가 성립하지 않음), static-nat 이외의 type(load-balance/
    dns 등), mappedip 파싱 실패.
    """
    out: dict[str, Any] = {}
    for item in parsed.get("firewall_vip", []) or []:
        name = item.get("name") or item.get("_edit") or ""
        if not name:
            continue
        vtype = str(item.get("type", "static-nat")).lower()
        if vtype not in ("static-nat", ""):
            out[name] = None
            continue
        if str(item.get("portforward", "")).lower() == "enable":
            out[name] = None
            continue
        acc = []
        ok = True
        for m in item.get("mappedip", []) or []:
            r = _parse_ip_or_range(m)
            if r is None:
                ok = False
                break
            acc.append(r)
        out[name] = _merge_intervals(acc) if (ok and acc) else None

    groups = {
        (g.get("name") or g.get("_edit") or ""): (g.get("member") or [])
        for g in parsed.get("firewall_vipgrp", []) or []
    }

    def resolve_group(name: str, stack: frozenset):
        if name in out:
            return out[name]
        members = groups.get(name)
        if members is None or name in stack:
            return None
        acc = []
        for m in members:
            r = resolve_group(m, stack | {name})
            if r is None:
                out[name] = None
                return None
            acc.extend(r)
        out[name] = _merge_intervals(acc)
        return out[name]

    for gname in groups:
        resolve_group(gname, frozenset())
    return out


def collect_dns_object_names(parsed: dict) -> set:
    """FQDN·wildcard-FQDN 계열 객체 이름 — 실행 시점 DNS로만 결정되므로
    오프라인 환원이 원리적으로 불가능하다. '미정의'와 구분해 사유를 정확히
    말하기 위해 수집한다."""
    names = set()
    for item in parsed.get("firewall_address", []) or []:
        if item.get("type") in ("fqdn", "wildcard-fqdn", "geography", "dynamic"):
            n = item.get("name") or item.get("_edit")
            if n:
                names.add(n)
    for key in ("firewall_wildcard_fqdn", "firewall_wildcard_fqdn_group"):
        for item in parsed.get(key, []) or []:
            n = item.get("name") or item.get("_edit")
            if n:
                names.add(n)
    return names


def _policy_addr_intervals(names: list[str], addr_map: dict):
    """정책의 srcaddr/dstaddr 목록 -> 구간 목록, UNIVERSE, 또는 None(환원 불가)."""
    acc: list[tuple[int, int]] = []
    for n in names or []:
        if str(n).lower() in ("all", "any"):
            return UNIVERSE
        r = addr_map.get(n)
        if r is None:
            return None
        acc.extend(r)
    if not acc:
        return None
    return _merge_intervals(acc)


# ---------------------------------------------------------------------------
# 서비스 객체 환원 — (proto, dst_lo, dst_hi, src_lo, src_hi) 튜플 목록
# ---------------------------------------------------------------------------

def _parse_portranges(raw: str) -> list[tuple[int, int, int, int]] | None:
    """'80 443:1024-65535 8000-8080' -> [(dlo,dhi,slo,shi), ...]"""
    out = []
    for token in str(raw).split():
        dst, _, src = token.partition(":")
        try:
            def _rng(s, default):
                if not s:
                    return default
                lo, _, hi = s.partition("-")
                lo_i = int(lo)
                hi_i = int(hi) if hi else lo_i
                if not (0 <= lo_i <= hi_i <= 65535):
                    raise ValueError(s)
                return (lo_i, hi_i)
            dlo, dhi = _rng(dst, (0, 65535))
            slo, shi = _rng(src, (0, 65535))
        except ValueError:
            return None
        out.append((dlo, dhi, slo, shi))
    return out


def _service_object_tuples(item: dict):
    """firewall_service_custom 항목 -> 매칭 튜플 목록, UNIVERSE, 또는 None."""
    protocol = str(item.get("protocol", "TCP/UDP/SCTP")).upper()

    if protocol in ("TCP/UDP/SCTP", "TCP/UDP/UDP-LITE/SCTP"):
        tuples = []
        for proto_key, proto in (("tcp-portrange", "tcp"),
                                 ("udp-portrange", "udp"),
                                 ("sctp-portrange", "sctp")):
            raw = item.get(proto_key)
            if not raw:
                continue
            ranges = _parse_portranges(raw)
            if ranges is None:
                return None
            tuples.extend((proto, dlo, dhi, slo, shi) for dlo, dhi, slo, shi in ranges)
        if not tuples:
            # 포트레인지 없는 TCP/UDP/SCTP = 해당 3개 프로토콜 전 포트
            return [(p, 0, 65535, 0, 65535) for p in ("tcp", "udp", "sctp")]
        return tuples

    if protocol in ("ICMP", "ICMP6"):
        t = item.get("icmptype")
        if t is None or str(t) == "":
            return [("icmp", 0, 255, 0, 255)]
        try:
            ti = int(t)
        except (TypeError, ValueError):
            return None
        return [("icmp", ti, ti, 0, 255)]

    if protocol == "IP":
        num = item.get("protocol-number")
        if num is None or str(num) in ("", "0"):
            return UNIVERSE          # protocol IP + 번호 없음 = 모든 IP 프로토콜 (예: ALL)
        try:
            n = int(num)
        except (TypeError, ValueError):
            return None
        return [(f"ip{n}", 0, 0, 0, 0)]

    return None


def build_service_map(parsed: dict):
    out: dict[str, Any] = {}
    for item in parsed.get("firewall_service_custom", []) or []:
        name = item.get("name") or item.get("_edit") or ""
        if name:
            out[name] = _service_object_tuples(item)

    groups = {
        (g.get("name") or g.get("_edit") or ""): (g.get("member") or [])
        for g in parsed.get("firewall_service_group", []) or []
    }

    def resolve_group(name: str, stack: frozenset[str]):
        if name in out:
            return out[name]
        members = groups.get(name)
        if members is None or name in stack:
            return None
        acc = []
        for m in members:
            r = resolve_group(m, stack | {name})
            if r is None:
                out[name] = None
                return None
            if r == UNIVERSE:
                out[name] = UNIVERSE
                return UNIVERSE
            acc.extend(r)
        out[name] = acc
        return acc

    for gname in groups:
        resolve_group(gname, frozenset())
    return out


def _policy_service_tuples(names: list[str], svc_map: dict):
    acc = []
    for n in names or []:
        # "ALL"은 config에 정의가 있으면 그 정의를 쓴다. 정의 조회 전에
        # 우주집합으로 단정하면, ALL을 좁게 재정의한 환경에서 오탐 shadow가
        # 생겨 "오탐 0" 보장이 깨진다(감사 B1). 미정의 ALL만 FortiGate
        # 기본(전 프로토콜)으로 본다.
        if n not in svc_map and str(n).upper() == "ALL":
            return UNIVERSE
        r = svc_map.get(n)
        if r is None:
            return None
        if r == UNIVERSE:
            return UNIVERSE
        acc.extend(r)
    if not acc:
        return None
    return acc


def _service_covers(cover, target) -> bool:
    if cover == UNIVERSE:
        return True
    if target == UNIVERSE:
        return False
    for proto, dlo, dhi, slo, shi in target:
        ok = False
        for cproto, cdlo, cdhi, cslo, cshi in cover:
            if cproto == proto and cdlo <= dlo and dhi <= cdhi \
                    and cslo <= slo and shi <= cshi:
                ok = True
                break
        if not ok:
            return False
    return True


def _addr_covers(cover, target) -> bool:
    if cover == UNIVERSE:
        return True
    if target == UNIVERSE:
        return False
    return _covers(cover, target)


def _intf_covers(cover: list[str], target: list[str]) -> bool:
    cset = {str(x).lower() for x in (cover or [])}
    if "any" in cset:
        return True
    tset = {str(x).lower() for x in (target or [])}
    if "any" in tset:
        return False
    return tset <= cset


# ---------------------------------------------------------------------------
# 본 판정
# ---------------------------------------------------------------------------

def _policy_dst_space(names: list[str], addr_map: dict, vip_map: dict):
    """dstaddr 해석. (구간|UNIVERSE|None, uses_vip) 반환.

    이름이 주소와 VIP 양쪽에 존재하면 어느 쪽을 참조하는지 확정할 수 없으므로
    환원 불가로 처리한다(추측 금지).
    """
    acc: list[tuple[int, int]] = []
    uses_vip = False
    for n in names or []:
        if str(n).lower() in ("all", "any"):
            return UNIVERSE, uses_vip
        in_addr = addr_map.get(n) is not None or n in addr_map
        in_vip = n in vip_map
        if in_addr and in_vip:
            return None, uses_vip
        if in_vip:
            r = vip_map.get(n)
            if r is None:
                return None, True
            uses_vip = True
            acc.extend(r)
            continue
        r = addr_map.get(n)
        if r is None:
            return None, uses_vip
        acc.extend(r)
    if not acc:
        return None, uses_vip
    return _merge_intervals(acc), uses_vip


def _addr_fail_reason(names, addr_map: dict, vip_map: dict, dns_names: set,
                      side: str) -> str:
    """환원 실패 사유를 정확히 말한다 — 'DNS라서 원리적으로 불가'와
    '이 config에 정의가 없음'과 'VIP 형태상 불가'는 다른 사실이다."""
    for n in names or []:
        if str(n).lower() in ("all", "any"):
            continue
        if n in dns_names:
            return (f"{side} address resolves via DNS at runtime "
                    "(FQDN / wildcard-FQDN / geography) — upload a "
                    "'diagnose test application dnsproxy 6' dump to include "
                    "exact-FQDN objects")
        if n in vip_map and vip_map.get(n) is None:
            return (f"{side} address uses a VIP this analysis cannot reduce "
                    "(port-forward, load-balance, or unparsable mappedip)")
        if n in addr_map and addr_map.get(n) is None:
            return (f"{side} address object (or a member of its group) cannot "
                    "be reduced to IP ranges — typically an FQDN/geography-type "
                    "member")
        if n not in addr_map and n not in vip_map:
            return (f"{side} address references an object not defined in the "
                    "parsed configuration")
    return f"{side} address cannot be reduced to IP ranges"


def _policy_space(p: dict, addr_map: dict, svc_map: dict,
                  vip_map: dict | None = None, dns_names: set | None = None,
                  capture_names: set | None = None):
    """정책 -> 매칭 공간 dict. 환원 불가면 (None, 사유)."""
    vip_map = vip_map or {}
    dns_names = dns_names or set()
    for key, why in _UNRESOLVABLE_POLICY_KEYS.items():
        val = p.get(key)
        if val in (None, "", [], "disable"):
            continue
        return None, why
    src = _policy_addr_intervals(p.get("srcaddr"), addr_map)
    if src is None:
        return None, _addr_fail_reason(p.get("srcaddr"), addr_map, vip_map,
                                       dns_names, "source")
    dst, uses_vip = _policy_dst_space(p.get("dstaddr"), addr_map, vip_map)
    if dst is None:
        return None, _addr_fail_reason(p.get("dstaddr"), addr_map, vip_map,
                                       dns_names, "destination")
    svc = _policy_service_tuples(p.get("service"), svc_map)
    if svc is None:
        return None, "service cannot be reduced to protocol/port sets (undefined or unsupported object)"
    return {
        "srcintf": p.get("srcintf") or [],
        "dstintf": p.get("dstintf") or [],
        "src": src, "dst": dst, "svc": svc,
        # VIP 목적지는 DNAT 이후(mappedip) 공간이다. FortiGate에서 dst=VIP
        # 정책은 해당 VIP로 DNAT된 트래픽만 매칭하므로:
        #  - 이 정책은 일반(비 DNAT) 트래픽의 shadower가 될 수 없다
        #  - 이 정책을 가리는 shadower는 accept여야 한다 (deny는 match-vip
        #    없이 VIP 트래픽을 매칭하지 않는다)
        "vip_dst": uses_vip,
        # FQDN 캐시로 환원된 이름이 섞이면 이 정책의 판정은 '수집 시점 기준'
        "capture": any(n in (capture_names or set())
                       for n in (p.get("srcaddr") or []) + (p.get("dstaddr") or [])),
    }, None


def _space_covers(a: dict, b: dict) -> bool:
    return (_intf_covers(a["srcintf"], b["srcintf"])
            and _intf_covers(a["dstintf"], b["dstintf"])
            and _addr_covers(a["src"], b["src"])
            and _addr_covers(a["dst"], b["dst"])
            and _service_covers(a["svc"], b["svc"]))


def detect_unreachable(parsed: dict, fqdn_map: dict | None = None) -> dict:
    """도달 불가 정책 목록과 판정 커버리지를 반환한다.

    fqdn_map: dnsproxy 캐시(선택). 주면 FQDN 정책도 판정하되, 그 결과의
    proof는 'capture'(수집 시점 기준)로 구분된다 — config만으로 증명된
    'config' 등급과 섞지 않는다.
    """
    policies = parsed.get("firewall_policy", []) or []
    capture_names: set = set()
    addr_map = build_address_map(parsed, fqdn_map, capture_names)
    svc_map = build_service_map(parsed)
    vip_map = build_vip_map(parsed)
    dns_names = collect_dns_object_names(parsed)

    unreachable = []
    skipped = []
    checked = 0
    # (policy, space) — 위쪽에 있으면서 shadower 자격이 있는 정책들
    shadowers: list[tuple[dict, dict]] = []

    for p in policies:
        status = str(p.get("status", "enable")).lower()
        schedule = p.get("schedule") or "always"
        space, why = _policy_space(p, addr_map, svc_map, vip_map, dns_names,
                                   capture_names)

        if space is not None and status in ("enable", "enabled", ""):
            checked += 1
            for sp_pol, sp in shadowers:
                # VIP 타깃은 accept shadower만 유효 — deny는 match-vip 없이
                # DNAT 트래픽을 매칭하지 않는다 (오탐 방지)
                if space.get("vip_dst") and \
                        str(sp_pol.get("action", "")).lower() != "accept":
                    continue
                if _space_covers(sp, space):
                    proof = "capture" if (space.get("capture")
                                          or sp.get("capture")) else "config"
                    unreachable.append({
                        "proof": proof,
                        "policy_id": p.get("policy_id"),
                        "name": p.get("name", ""),
                        "shadowed_by": sp_pol.get("policy_id"),
                        "shadowed_by_name": sp_pol.get("name", ""),
                        "shadowed_by_action": sp_pol.get("action", ""),
                        "detail": (
                            "Every packet this policy could match is already matched "
                            f"by policy {sp_pol.get('policy_id')} above it "
                            "(source, destination, service, and interfaces are all contained)."
                        ),
                    })
                    break
        elif space is None and status in ("enable", "enabled", ""):
            skipped.append({"policy_id": p.get("policy_id"),
                            "name": p.get("name", ""), "reason": why})

        # shadower 자격: 환원 가능 + 활성 + 상시 스케줄 + 비 VIP 목적지.
        # 스케줄 정책은 꺼진 시간대에 아래 정책이 매칭될 수 있고, VIP 목적지
        # 정책은 DNAT된 트래픽만 매칭하므로 일반 트래픽을 가리지 못한다
        # (mappedip 공간을 일반 공간처럼 쓰면 오탐).
        if space is not None and status in ("enable", "enabled", "") \
                and str(schedule).lower() == "always" \
                and not space.get("vip_dst"):
            shadowers.append((p, space))

    return {
        "unreachable": unreachable,
        "skipped": skipped,
        "checked": checked,
        "total_enabled": sum(
            1 for p in policies
            if str(p.get("status", "enable")).lower() in ("enable", "enabled", "")),
        "capture_used": bool(fqdn_map),
        "note": (
            "Conservative static analysis: a policy is reported only when a single "
            "always-on policy above it provably matches every packet it could match. "
            "Policies using FQDN/geography/ISDB/user objects or negation are skipped "
            "(listed above), and combined shadowing by multiple policies is not "
            "evaluated — so this list can miss cases, but it does not false-positive. "
            "Routing and NAT are not considered. Findings marked proof="
            "'capture' rely on a DNS cache snapshot and are provable as of "
            "the capture time; proof='config' findings are provable from the "
            "configuration alone."
        ),
    }
