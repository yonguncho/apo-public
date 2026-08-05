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


def build_address_map(parsed: dict) -> dict[str, list[tuple[int, int]] | None]:
    """주소·주소그룹 이름 -> IP 구간 목록(환원 불가 시 None)."""
    out: dict[str, Any] = {}
    for item in parsed.get("firewall_address", []) or []:
        name = item.get("name") or item.get("_edit") or ""
        if name:
            out[name] = _addr_object_intervals(item)

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
            acc.extend(r)
        out[name] = _merge_intervals(acc)
        return out[name]

    for gname in groups:
        resolve_group(gname, frozenset())
    return out


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

def _policy_space(p: dict, addr_map: dict, svc_map: dict):
    """정책 -> 매칭 공간 dict. 환원 불가면 (None, 사유)."""
    for key, why in _UNRESOLVABLE_POLICY_KEYS.items():
        val = p.get(key)
        if val in (None, "", [], "disable"):
            continue
        return None, why
    src = _policy_addr_intervals(p.get("srcaddr"), addr_map)
    if src is None:
        return None, ("source address cannot be reduced to IP ranges "
                      "(FQDN/geography/dynamic, a VIP, or an object type this "
                      "analysis does not resolve)")
    dst = _policy_addr_intervals(p.get("dstaddr"), addr_map)
    if dst is None:
        return None, ("destination address cannot be reduced to IP ranges "
                      "(FQDN/geography/dynamic, a VIP, or an object type this "
                      "analysis does not resolve)")
    svc = _policy_service_tuples(p.get("service"), svc_map)
    if svc is None:
        return None, "service cannot be reduced to protocol/port sets (undefined or unsupported object)"
    return {
        "srcintf": p.get("srcintf") or [],
        "dstintf": p.get("dstintf") or [],
        "src": src, "dst": dst, "svc": svc,
    }, None


def _space_covers(a: dict, b: dict) -> bool:
    return (_intf_covers(a["srcintf"], b["srcintf"])
            and _intf_covers(a["dstintf"], b["dstintf"])
            and _addr_covers(a["src"], b["src"])
            and _addr_covers(a["dst"], b["dst"])
            and _service_covers(a["svc"], b["svc"]))


def detect_unreachable(parsed: dict) -> dict:
    """도달 불가 정책 목록과 판정 커버리지를 반환한다."""
    policies = parsed.get("firewall_policy", []) or []
    addr_map = build_address_map(parsed)
    svc_map = build_service_map(parsed)

    unreachable = []
    skipped = []
    checked = 0
    # (policy, space) — 위쪽에 있으면서 shadower 자격이 있는 정책들
    shadowers: list[tuple[dict, dict]] = []

    for p in policies:
        status = str(p.get("status", "enable")).lower()
        schedule = p.get("schedule") or "always"
        space, why = _policy_space(p, addr_map, svc_map)

        if space is not None and status in ("enable", "enabled", ""):
            checked += 1
            for sp_pol, sp in shadowers:
                if _space_covers(sp, space):
                    unreachable.append({
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

        # shadower 자격: 환원 가능 + 활성 + 상시 스케줄.
        # 스케줄이 있는 정책은 꺼져 있는 시간대에 아래 정책이 매칭될 수 있다.
        if space is not None and status in ("enable", "enabled", "") \
                and str(schedule).lower() == "always":
            shadowers.append((p, space))

    return {
        "unreachable": unreachable,
        "skipped": skipped,
        "checked": checked,
        "total_enabled": sum(
            1 for p in policies
            if str(p.get("status", "enable")).lower() in ("enable", "enabled", "")),
        "note": (
            "Conservative static analysis: a policy is reported only when a single "
            "always-on policy above it provably matches every packet it could match. "
            "Policies using FQDN/geography/ISDB/user objects or negation are skipped "
            "(listed above), and combined shadowing by multiple policies is not "
            "evaluated — so this list can miss cases, but it does not false-positive. "
            "Routing and NAT are not considered."
        ),
    }
