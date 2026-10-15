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
# **'모든 패킷을 받는다'는 주장은 화이트리스트로만 한다.**
# 예전에는 매칭을 좁히는 필드를 목록으로 적어 두고 그것만 없으면 만능이라고
# 했다. 그 목록은 언제나 절반짜리다 — ZTNA(`set ztna-status enable`),
# 단말 식별(`set devices "ipad"`)이 붙은 정책이 무제한 shadower 로 인정돼
# 그 아래 살아 있는 정책이 죽었다고 보고됐다(라운드 42 실측). 같은 형태의
# 목록 방어가 장비 신원 확인에서 세 번 연속 뚫린 적이 있다.
#
# 그래서 방향을 뒤집는다: **매칭을 좁히지 않는다고 확인한 키만** 적고,
# 모르는 키가 하나라도 있으면 만능이라고 말하지 않는다. 새 FortiOS 기능이
# 생기면 판정 보류로 떨어질 뿐(미탐), 오탐으로는 넘어가지 않는다.
_MATCH_NEUTRAL_POLICY_KEYS = {
    # 식별·메타
    "_edit", "policy_id", "name", "uuid", "comments", "comment", "vdom",
    "status", "action", "schedule", "srcintf", "dstintf", "srcaddr", "dstaddr",
    "service", "policyid", "global-label", "label",
    # NAT·풀 (어떤 패킷이 매칭되는지는 바꾸지 않는다)
    "nat", "ippool", "poolname", "fixedport", "natip", "nat64", "nat46",
    "permit-any-host", "permit-stun-host",
    # 로깅·검사 프로파일 (매칭 후 처리)
    "logtraffic", "logtraffic-start", "capture-packet", "auto-asic-offload",
    "inspection-mode", "ssl-ssh-profile", "av-profile", "webfilter-profile",
    "ips-sensor", "dnsfilter-profile", "emailfilter-profile", "dlp-sensor",
    "file-filter-profile", "application-list", "voip-profile", "icap-profile",
    "waf-profile", "ssh-filter-profile", "profile-protocol-options",
    "profile-type", "profile-group", "utm-status", "av-quarantine",
    "block-notification", "replacemsg-override-group", "custom-log-fields",
    "disclaimer", "webcache", "webcache-https", "wanopt", "wanopt-profile",
    "wanopt-peer", "wanopt-detection", "wanopt-passive-opt",
    # 세션·성능
    "session-ttl", "timeout-send-rst", "tcp-mss-sender", "tcp-mss-receiver",
    "traffic-shaper", "traffic-shaper-reverse", "per-ip-shaper",
    "diffserv-forward", "diffserv-reverse", "diffservcode-forward",
    "diffservcode-rev", "tcp-session-without-syn", "anti-replay",
    "dsri", "delay-tcp-npu-session", "np-acceleration", "geoip-anycast",
    # `show full-configuration` 은 기본값까지 전부 출력한다. 이 값들이
    # 화이트리스트에 없어 **모든 정책이 가림막 자격을 잃었고**, 같은 장비를
    # `show` 로 받으면 발견이 나오고 full-configuration 으로 받으면 0건이
    # 나왔다(라운드 43 실측). 전부 매칭을 좁히지 않는 값이다 —
    # reputation-minimum 0 = 필터 없음, tos-mask 0x00 = ToS 미검사,
    # vlan-cos 255 = 미지정, eif-* 는 세션 헬퍼, match-vip 는 오히려 넓힌다.
    "reputation-minimum", "reputation-direction", "tos", "tos-mask",
    "tos-negate", "vlan-cos-fwd", "vlan-cos-rev", "vlan-filter",
    "eif-check", "eif-learn", "firewall-session-dirty",
    "decrypted-traffic-mirror", "match-vip", "match-vip-only",
    "schedule-timeout", "ip-version-type", "geoip-match", "sgt-check",
    "fec", "wccp", "send-deny-packet", "fsso", "webproxy-profile",
    "webproxy-forward-server", "ztna-device-ownership", "policy-expiry",
    "email-collect", "captive-portal-exempt", "rtp-nat", "natinbound",
    "natoutbound", "radius-mac-auth-bypass", "auth-path", "identity-based-route",
}


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
                # **모르는 것을 '전부'로 되돌리면 그 객체가 만능 shadower 가
                # 된다.** 이 엔진은 오탐을 내지 않기로 했는데, 이 기본값은
                # 실패할 때마다 오탐 쪽으로 넘어진다 — 파서가 못 읽은 표기
                # 하나(`set subnet 10.1.1.0/24`)로 살아 있는 정책이 죽었다고
                # 보고됐다(라운드 42 실측). subnet 을 적어 놓았는데 못 읽은
                # 것과, 정말 안 적은 것은 다르다.
                # `subnet` 만 보면 부족하다 — `set type iprange` 줄이 없고
                # start-ip/end-ip 만 적힌 객체가 '정말 미설정' 으로 분류돼
                # 0.0.0.0/0 이 됐다(라운드 43 실측). **주소를 적으려 한 흔적이
                # 있으면** 못 읽은 것이지 미설정이 아니다.
                if any(item.get(k) is not None
                       for k in ("subnet", "start-ip", "end-ip", "fqdn",
                                 "wildcard", "sdn", "country", "interface")):
                    return None          # 값이 있는데 못 읽었다 → 판정 보류
                return list(_FULL_V4)    # 정말 미설정 → FortiGate 기본값
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


def gated_fqdn_names(parsed: dict, snapshot_vdom: str = "") -> set:
    """스냅샷을 증거로 쓰면 안 되는 FQDN 객체 **이름** 집합.

    게이트는 항목이 아니라 **이름 단위**여야 한다 — 주소 맵은 이름 키로
    평탄화되므로(마지막 항목 승리), 같은 이름이 게이트/비게이트 VDOM 양쪽에
    있으면 항목 단위 게이트는 파일 순서에 따라 우회된다: 비게이트 항목이
    나중이면 게이트 VDOM 정책이 전역 스냅샷으로 'capture 도달불가' **오탐**
    (오탐 0 위반), 역순이면 비게이트 VDOM 이 커버리지를 잃는다(라운드 65
    경계값 렌즈 실행 재현). 이름이 한 번이라도 게이트 대상이면 그 이름은
    스냅샷으로 환원하지 않는다 — 보수 방향만 남긴다.

    snapshot_vdom: 이 스냅샷이 **어느 VDOM 의 해석인가**(수집 스코프).
    v108 부터 수집이 VDOM 스코프로 조회하므로 스냅샷은 전역이 아닐 수
    있다 — 스코프 VDOM 이 자체 DNS(vdom-dns)를 쓰면 게이트가 **반전**된다
    (라운드 70 완성도 렌즈, Jayden 승인): 그 VDOM 의 해석이므로 그 VDOM
    의 FQDN 객체에는 정당한 증거이고, 다른 VDOM 객체에는 남의 DNS 라
    증거가 못 된다. 빈 값(전역/덤프/출처 미상)은 종전 규칙 그대로.
    """
    _vdd = {str(v).strip().lower()
            for v in ((parsed.get("meta") or {}).get("vdom_dns_vdoms") or [])}
    sv = str(snapshot_vdom or "").strip().lower()
    if sv and sv in _vdd:
        # 스냅샷 = 자체 DNS VDOM 의 해석 → 그 VDOM 밖에서 한 번이라도
        # 정의된 이름은 전부 게이트(이름 단위 보수 — 위 평탄화 논리와 동일).
        return {(i.get("name") or i.get("_edit") or "")
                for i in parsed.get("firewall_address", []) or []
                if i.get("type") == "fqdn"
                and str(i.get("vdom") or "").strip().lower() != sv}
    if not _vdd:
        return set()
    return {(i.get("name") or i.get("_edit") or "")
            for i in parsed.get("firewall_address", []) or []
            if i.get("type") == "fqdn"
            and str(i.get("vdom") or "").strip().lower() in _vdd}


def build_address_map(parsed: dict, fqdn_map: dict | None = None,
                      capture_names: set | None = None,
                      snapshot_vdom: str = ""
                      ) -> dict[str, list[tuple[int, int]] | None]:
    """주소·주소그룹 이름 -> IP 구간 목록(환원 불가 시 None).

    fqdn_map(dnsproxy 캐시)이 있으면 type=fqdn 객체를 그 스냅샷 IP로
    환원한다. 이렇게 환원된 이름(과 이를 포함한 그룹)은 capture_names에
    기록된다 — 이 이름이 판정에 쓰이면 증명 등급이 'config'가 아니라
    'capture'(수집 시점 기준)로 떨어져야 하기 때문이다.
    """
    out: dict[str, Any] = {}
    fqdn_map = fqdn_map or {}
    # **자체 DNS(vdom-dns)를 쓰는 VDOM 의 FQDN 객체는 스냅샷으로 환원하지
    # 않는다.** FQDN 해석은 DNS 설정을 따르는데, vdom-dns 를 켠 VDOM 은
    # 전역과 다른 서버를 쓸 수 있다 — 그 VDOM 정책의 '도달불가' 증거로
    # 전역 스냅샷을 쓰면 오탐이 될 수 있다(라운드 64, Jayden 승인: config
    # 의 vdom-dns 사실로 판정. 어느 VDOM 도 안 켰으면 해석 공통 확정이라
    # 다중 VDOM 에서도 전면 적용 — 라운드 57 의 일괄 억제를 대체).
    _gated = gated_fqdn_names(parsed, snapshot_vdom)
    for item in parsed.get("firewall_address", []) or []:
        name = item.get("name") or item.get("_edit") or ""
        if not name:
            continue
        iv = _addr_object_intervals(item)
        used_capture = False
        if (iv is None and fqdn_map and item.get("type") == "fqdn"
                and name not in _gated):
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


def dns_object_info(parsed: dict) -> dict:
    """DNS 계열 객체 이름 -> (종류, 도메인).

    사유 문장이 셋을 구분하려면 종류를 알아야 한다 — exact FQDN 은 해석
    스냅샷으로 판정할 수 있지만, wildcard-FQDN·geography 는 어떤 덤프로도
    환원되지 않는다. 같은 문장으로 답하면 하면 될 일처럼 보인다.
    """
    info: dict = {}
    for item in parsed.get("firewall_address", []) or []:
        t = item.get("type")
        if t in ("fqdn", "wildcard-fqdn", "geography", "dynamic"):
            n = item.get("name") or item.get("_edit")
            if n:
                info[n] = (t, str(item.get("fqdn", "")).strip())
    for key in ("firewall_wildcard_fqdn", "firewall_wildcard_fqdn_group"):
        for item in parsed.get(key, []) or []:
            n = item.get("name") or item.get("_edit")
            if n:
                info[n] = ("wildcard-fqdn", str(item.get("fqdn", "")).strip())
    return info


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
            # **포트 레인지가 하나도 없는 서비스는 매칭 대상이 없다.**
            # '전 포트'로 펼쳤더니 그 정책이 만능 shadower 가 되어, 실제로
            # 443 을 처리하는 아래 정책이 죽었다고 보고됐다(라운드 42 실측).
            # 여기서 틀리면 오탐이므로 판정 보류로 남긴다.
            return None
        return tuples

    if protocol in ("ICMP", "ICMP6"):
        # **ICMP 와 ICMPv6 는 다른 프로토콜이다.** 한 분기에서 다루더라도 키는
        # 갈라야 한다 — 같은 'icmp' 로 축약한 탓에 IPv4 ICMP 정책이 ICMPv6
        # 정책을 가린다고 보고했다(라운드 43 실측).
        _proto = "icmp6" if protocol == "ICMP6" else "icmp"
        t = item.get("icmptype")
        if t is None or str(t) == "":
            return [(_proto, 0, 255, 0, 255)]
        try:
            ti = int(t)
        except (TypeError, ValueError):
            return None
        # **icmpcode 를 안 보면 code 만 다른 두 서비스가 같아진다.**
        # type 8/code 0 정책이 type 8/code 1 정책을 가린다고 보고했다
        # (라운드 42 실측). FortiOS 에서 icmpcode 미설정은 전체 code,
        # 설정하면 그 code 만 매칭한다 — 소스 포트 자리를 code 로 쓴다.
        _c = item.get("icmpcode")
        if _c is None or str(_c) == "":
            return [(_proto, ti, ti, 0, 255)]
        try:
            ci = int(_c)
        except (TypeError, ValueError):
            return None
        return [(_proto, ti, ti, ci, ci)]

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
    if not tset:
        # 빈 대상 인터페이스 목록은 "any"가 아니라 **"모름"**이다(미파싱·
        # 잘린 백업). set() <= cset 이 항상 참이라 살아있는 정책이 도달불가로
        # 오판될 수 있었다 — 이 기능의 제1 약속(오탐 0) 위반 클래스(B-40).
        # 커버가 any 인 경우는 위에서 이미 참이므로, 여기 도달한 '모름'은
        # 증명이 아니다.
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
                      side: str, dns_info: dict | None = None,
                      fqdn_map: dict | None = None,
                      gated_names: set | None = None,
                      group_members: dict | None = None,
                      snapshot_vdom: str = "") -> str:
    """환원 실패 사유를 정확히 말한다 — 'DNS라서 원리적으로 불가'와
    '이 config에 정의가 없음'과 'VIP 형태상 불가'는 다른 사실이다.

    **DNS 계열 안에서도 셋을 구분한다.** 셋을 뭉뚱그려 '덤프를 올리라'고
    했더니, 장비에서 수집까지 마친 사용자가 이미 한 일을 다시 하라는 안내를
    받았다. 게다가 wildcard-FQDN·geography 는 어떤 덤프로도 환원되지 않는데
    같은 문장을 받아, 하면 될 일처럼 보였다(Jayden 실사용 지적).
    """
    dns_info = dns_info or {}
    fqdn_map = fqdn_map or {}
    gated_names = gated_names or set()
    group_members = group_members or {}
    for n in names or []:
        if str(n).lower() in ("all", "any"):
            continue
        if n in dns_names:
            kind, domain = dns_info.get(n, ("fqdn", ""))
            if kind != "fqdn":
                # 와일드카드·지역·동적 객체는 해석 스냅샷이 있어도 못 줄인다.
                return (f"{side} address is a {kind} object — it is decided at "
                        "runtime and cannot be reduced offline. A DNS capture "
                        "does not help with this type.")
            if n in gated_names:
                # vdom-dns 게이트로 제외된 이름. 문구는 **이름의 사실**만
                # 말한다 — "이 정책의 VDOM 이 vdom-dns 를 쓴다"고 쓰면 이름을
                # 공유하는 **비게이트 VDOM** 정책이 받았을 때 거짓이 되고
                # (라운드 67, 계약·동적 렌즈 수렴), 완결 지시문("stays
                # unproven. Re-collecting…")은 universal 지름길 detail 에
                # 내장될 때 증명문과 자기모순이 됐다(같은 라운드). 명사구형
                # 으로 어느 문맥에서든 참이 되게 한다.
                #
                # 게이트의 **원인이 둘이 됐다**(라운드 70, Jayden 승인):
                # 스냅샷이 자체 DNS VDOM 스코프로 수집됐으면, 제외 사유는
                # "이름이 vdom-dns VDOM 에 있어서"가 아니라 "스냅샷이 그
                # VDOM 의 해석이라 밖에서는 증거가 못 돼서"다.
                _sv = str(snapshot_vdom or "").strip()
                if _sv:
                    return (f"{side} address is the FQDN '{domain or n}' — "
                            "the loaded DNS snapshot was collected from VDOM "
                            f"'{_sv}', which uses its own DNS (vdom-dns), so "
                            "it is not used as evidence for names outside "
                            "that VDOM (their resolution may differ) and this "
                            "name cannot be reduced offline")
                return (f"{side} address is the FQDN '{domain or n}', a name "
                        "defined in a VDOM that uses its own DNS (vdom-dns) — "
                        "the device-wide DNS snapshot is not used as evidence "
                        "for this name by design (its resolution there may "
                        "differ from the global DNS), so it cannot be reduced "
                        "offline")
            if fqdn_map:
                return (f"{side} address is the FQDN '{domain or n}', and the "
                        "DNS capture in use has no entry for it. A FortiGate "
                        "resolves an FQDN object only after traffic uses it — "
                        "collect again once this rule has seen traffic.")
            return (f"{side} address is the FQDN '{domain or n}' — collect from "
                    "the device (or upload a 'diagnose test application "
                    "dnsproxy 6' dump) so APO knows what it resolves to.")
        if n in vip_map and vip_map.get(n) is None:
            return (f"{side} address uses a VIP this analysis cannot reduce "
                    "(port-forward, load-balance, or unparsable mappedip)")
        if n in addr_map and addr_map.get(n) is None:
            # 그룹 멤버에 vdom-dns 게이트 이름이 있으면 그 사실을 말한다 —
            # 일반 문구만 내면 "덤프를 올리면 되나" 로 오독된다(라운드 67
            # 계약·경계값 렌즈, 라운드 68 편입).
            _gm = set(group_members.get(n) or [])
            if _gm & gated_names:
                _sv = str(snapshot_vdom or "").strip()
                if _sv:
                    return (f"{side} address group '{n}' contains an FQDN "
                            "name outside the VDOM the loaded DNS snapshot "
                            f"was collected from (VDOM '{_sv}', which uses "
                            "its own DNS, vdom-dns) — that snapshot is not "
                            "used as evidence for such names, so the group "
                            "cannot be reduced offline")
                return (f"{side} address group '{n}' contains an FQDN name "
                        "defined in a VDOM that uses its own DNS (vdom-dns) — "
                        "the device-wide DNS snapshot is not used as evidence "
                        "for that name by design, so the group cannot be "
                        "reduced offline")
            return (f"{side} address object (or a member of its group) cannot "
                    "be reduced to IP ranges — typically an FQDN/geography-type "
                    "member")
        if n not in addr_map and n not in vip_map:
            return (f"{side} address references an object not defined in the "
                    "parsed configuration")
    return f"{side} address cannot be reduced to IP ranges"


def _may_shadow(p: dict) -> bool:
    """이 정책을 **가림막으로 믿어도 되는가.**

    가림막의 매칭 공간을 실제보다 넓게 계산하면 그대로 오탐이 된다. 우리가
    모델링하는 축(주소·서비스·인터페이스·동작·상태·스케줄) 밖에서 매칭을
    좁히는 필드가 하나라도 있으면 믿지 않는다 — ZTNA·단말 식별이 붙은 정책이
    무제한 가림막으로 인정돼 아래 살아 있는 정책이 죽었다고 보고됐다
    (라운드 42 실측).

    `_is_universal` 만 고치면 이 경로가 남는다. 두 곳이 같은 질문을 하므로
    같은 술어를 쓴다.
    """
    modelled = {"srcaddr", "dstaddr", "service", "srcintf", "dstintf",
                "action", "status", "schedule"}
    for key, val in p.items():
        if key in modelled or key in _MATCH_NEUTRAL_POLICY_KEYS:
            continue
        if val in (None, "", [], "disable"):
            continue
        return False
    return True


def _is_universal(p: dict, svc_map: dict | None = None) -> bool:
    """이 정책이 '모든 패킷'을 매칭하는가.

    그렇다면 아래 정책이 무엇을 담고 있든 — ISDB든 geography든 사용자 객체든,
    우리가 오프라인에서 환원하지 못하는 무엇이든 — 그 정책의 패킷 집합은 이
    정책의 부분집합이다. 즉 **내용을 몰라도 도달불가를 증명할 수 있다.**

    이 덕분에 ISDB 목록을 따로 임포트하지 않아도 상당수의 '판정 보류'가
    풀린다. 사용자에게 수동 임포트를 요구하기 전에 먼저 짜낼 값이었다.

    오탐 0 원칙을 지키려고 조건을 최대한 좁게 잡는다:
      - 환원 불가 요소(ISDB·negate·IPv6 등)가 이 정책 자체에 있으면 제외.
        예를 들어 internet-service가 켜져 있으면 dstaddr는 무시되므로
        'all'이어도 전체를 덮지 않는다.
      - accept만 인정. deny는 VIP로 DNAT된 트래픽을 match-vip 없이 매칭하지
        않으므로, 아래 정책이 VIP 목적지일 때 덮는다고 말할 수 없다.

    인터페이스는 여기서 보지 않는다 — 호출부가 대상 정책과 직접 비교한다.
    주소/서비스를 환원하지 못해도 인터페이스는 알 수 있기 때문이다.
    """
    # 모르는 키가 하나라도 값을 갖고 있으면 만능이라고 말하지 않는다.
    # **한 술어를 쓴다.** 라운드 42 커밋에 '두 곳이 같은 질문을 하므로 같은
    # 술어를 쓴다'고 적었는데, 실제로는 여기에 같은 화이트리스트 루프를 한 벌
    # 더 두고 있었다. 그래서 이쪽만 되돌린 변이가 527개를 전부 통과했다
    # (라운드 43 실측). 같은 말을 두 번 쓰면 한쪽만 낡는다 — 게다가 가림막
    # 목록에 들어온 정책은 이미 `_may_shadow` 를 지났으므로 이 루프는 사실상
    # 죽은 코드였다. 술어 하나로 모은다.
    if not _may_shadow(p):
        return False
    if str(p.get("action", "")).lower() != "accept":
        return False
    if str(p.get("status", "enable")).lower() not in ("enable", "enabled", ""):
        return False
    if str(p.get("schedule") or "always").lower() != "always":
        return False
    low = lambda xs: {str(x).strip().lower() for x in (xs or [])}
    if low(p.get("srcaddr")) != {"all"} or low(p.get("dstaddr")) != {"all"}:
        return False
    if low(p.get("service")) != {"all"}:
        return False
    # **'ALL' 은 이름일 뿐이다.** 고객이 `config firewall service custom` 에서
    # ALL 을 TCP/80 으로 좁혀 놓으면 그 정책은 전부를 받지 않는다. 이름만 보고
    # 단정했더니 그 아래 ISDB 정책이 죽었다고 보고됐고, 근거 문장은 'all
    # services' 라고 사실과 다르게 적혔다(라운드 42 실측). 같은 결함을 서비스
    # 환원 쪽에서는 이미 고쳐 두었는데 이 경로만 남아 있었다.
    # 'ALL' 은 FortiGate 기본 제공 서비스라 보통 config 에 안 나온다 —
    # 표에 없으면 기본 정의(전부)로 본다. **표에 있으면** 고객이 재정의한
    # 것이므로 그 정의를 따른다(라운드 42: ALL 을 TCP/80 으로 좁힌 config).
    if svc_map is not None:
        for _n in (p.get("service") or []):
            _k = str(_n)
            if _k in svc_map:
                if svc_map[_k] is not UNIVERSE:
                    return False
            elif _k.strip().lower() != "all":
                return False
    return True


def _policy_space(p: dict, addr_map: dict, svc_map: dict,
                  vip_map: dict | None = None, dns_names: set | None = None,
                  capture_names: set | None = None,
                  dns_info: dict | None = None, fqdn_map: dict | None = None,
                  gated_names: set | None = None,
                  group_members: dict | None = None,
                  snapshot_vdom: str = ""):
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
                                       dns_names, "source", dns_info, fqdn_map,
                                       gated_names, group_members,
                                       snapshot_vdom)
    dst, uses_vip = _policy_dst_space(p.get("dstaddr"), addr_map, vip_map)
    if dst is None:
        return None, _addr_fail_reason(p.get("dstaddr"), addr_map, vip_map,
                                       dns_names, "destination", dns_info,
                                       fqdn_map, gated_names, group_members,
                                       snapshot_vdom)
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


def _prep_space(sp: dict) -> dict:
    """쌍 비교에 **불변인 부분**을 정책마다 한 번만 계산해 둔다.

    `_space_covers` 는 정책 쌍마다 불리므로 호출 수가 O(n^2) 다. 그런데 그
    안에서 하던 일 대부분이 **한쪽 정책만의 함수**였다 — 인터페이스 이름
    소문자 집합, 주소 구간 병합. 실측(합성 2,000 정책): `_space_covers`
    198만 회에 `_intf_covers` 396만 회·`_merge_intervals` 398만 회로,
    같은 값을 수백 번씩 다시 만들고 있었다.

    여기서 미리 만들어 두면 비교는 집합 포함·구간 스캔만 남는다. **값은
    그대로다** — `_merge_intervals` 는 결정적이고 멱등이라 미리 하든 그때
    하든 결과가 같다. backlog B-84 의 ① 안.

    **근거를 "골든 byte-identical" 이라고 적었던 것은 틀렸다.**
    `tests/golden/generate_golden.py` 는 도달불가 검사를 아예 돌리지 않는다
    (view model·severity·워크북만 잡는다) — 골든 12개가 통과한 것은 이 코드에
    대해 아무것도 말해 주지 않았다. 실제 근거는 `tests/test_reachability.py`
    와, v128 구현을 나란히 불러 같은 입력을 먹인 차등 비교다: 67,600 쌍
    (빈 리스트·UNIVERSE·대소문자 혼합·역순 구간 포함) **불일치 0**
    (2026-09-10 실측).
    """
    if sp.get("_prepped"):
        return sp
    for k in ("srcintf", "dstintf"):
        sp["_" + k] = {str(x).lower() for x in (sp.get(k) or [])}
    for k in ("src", "dst"):
        v = sp.get(k)
        # UNIVERSE 는 문자열 센티널이라 구간 병합 대상이 아니다.
        sp["_m" + k] = None if v == UNIVERSE else _merge_intervals(v or [])
    sp["_prepped"] = True
    return sp


def _intf_covers_pre(cset: set, tset: set) -> bool:
    """`_intf_covers` 와 **같은 판정**, 입력만 미리 정규화된 집합."""
    if "any" in cset:
        return True
    if "any" in tset:
        return False
    if not tset:
        # 빈 대상은 "any" 가 아니라 "모름"이다 — 증명이 아니므로 거짓(B-40).
        return False
    return tset <= cset


def _covers_pre(cover_m, target_m) -> bool:
    """`_covers` 와 같되, 양쪽이 이미 병합된 구간이라고 가정한다."""
    for lo, hi in target_m:
        for clo, chi in cover_m:
            if clo <= lo and hi <= chi:
                break
        else:
            return False
    return True


def _addr_covers_pre(a: dict, b: dict, key: str) -> bool:
    cover, target = a[key], b[key]
    if cover == UNIVERSE:
        return True
    if target == UNIVERSE:
        return False
    return _covers_pre(a["_m" + key], b["_m" + key])


def _space_covers(a: dict, b: dict) -> bool:
    # 두 공간 모두 준비돼 있어야 한다. `_prep_space` 는 멱등이라 이미 된 것은
    # 그대로 지나간다 — 외부에서 이 함수를 직접 부르는 경우도 안전하다.
    _prep_space(a); _prep_space(b)
    return (_intf_covers_pre(a["_srcintf"], b["_srcintf"])
            and _intf_covers_pre(a["_dstintf"], b["_dstintf"])
            and _addr_covers_pre(a, b, "src")
            and _addr_covers_pre(a, b, "dst")
            and _service_covers(a["svc"], b["svc"]))


def detect_unreachable(parsed: dict, fqdn_map: dict | None = None,
                       snapshot_vdom: str = "") -> dict:
    """도달 불가 정책 목록과 판정 커버리지를 반환한다.

    fqdn_map: dnsproxy 캐시(선택). 주면 FQDN 정책도 판정하되, 그 결과의
    proof는 'capture'(수집 시점 기준)로 구분된다 — config만으로 증명된
    'config' 등급과 섞지 않는다.
    """
    policies = parsed.get("firewall_policy", []) or []
    capture_names: set = set()
    addr_map = build_address_map(parsed, fqdn_map, capture_names, snapshot_vdom)
    svc_map = build_service_map(parsed)
    vip_map = build_vip_map(parsed)
    dns_names = collect_dns_object_names(parsed)
    dns_info = dns_object_info(parsed)
    _gated = gated_fqdn_names(parsed, snapshot_vdom)   # skip 사유 전달용
    # 사유의 스코프형 문구는 **반전이 실제로 활성일 때만** — 스코프 VDOM 이
    # vdom-dns 가 아니면 게이트 원인은 종전(이름이 vdom-dns VDOM 소속)이고,
    # 스코프형 문구("collected from VDOM X, which uses its own DNS")는
    # 거짓이 된다.
    _vdd_l = {str(v).strip().lower() for v in
              ((parsed.get("meta") or {}).get("vdom_dns_vdoms") or [])}
    _sv_raw = str(snapshot_vdom or "").strip()
    _snap_vdom = _sv_raw if _sv_raw.lower() in _vdd_l else ""
    _grp_members = {
        (g.get("name") or g.get("_edit") or ""): (g.get("member") or [])
        for g in parsed.get("firewall_addrgrp", []) or []}

    unreachable = []
    skipped = []
    checked = 0
    # **믿지 못한 가림막도 흔적을 남겨야 한다.** '모르는 키가 있으면 만능이라고
    # 말하지 않는다'는 규칙은 옳지만, 그 결과가 아무 데도 안 남으면 '발견 0건'이
    # '이상 없음'으로 읽힌다 — full-configuration 백업에서 전건 보류인데 화면은
    # 초록으로 '전수 검사했다'고 말했다(라운드 43 실측).
    untrusted = []
    # (policy, space) — 위쪽에 있으면서 shadower 자격이 있는 정책들.
    # **VDOM 마다 따로 쌓는다.** FortiGate 는 VDOM 별로 독립된 정책 목록을
    # 순서대로 평가하므로, root 의 정책은 guest 의 트래픽을 매칭할 기회가
    # 아예 없다. 한 덩어리로 쌓으면 살아 있는 정책이 '도달 불가'로 찍힌다 —
    # 이 기능이 절대 하지 않기로 한 오탐이다.
    shadowers_by_vdom: dict[str, list[tuple[dict, dict]]] = {}

    for p in policies:
        status = str(p.get("status", "enable")).lower()
        schedule = p.get("schedule") or "always"
        space, why = _policy_space(p, addr_map, svc_map, vip_map, dns_names,
                                   capture_names, dns_info, fqdn_map, _gated,
                                   _grp_members, _snap_vdom)

        if space is not None and status in ("enable", "enabled", ""):
            checked += 1
            for sp_pol, sp in shadowers_by_vdom.get(p.get("vdom") or "", []):
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
                        # **VDOM 을 들려 보낸다.** 이 항목은 조치 계획의 **첫
                        # 줄**이 되는데, 워크북이 `_vdom_of(u)` 로 VDOM 을
                        # 찾으려다 이 딕셔너리에 그 칸이 없어 늘 빈손이었다.
                        # 그래서 도달불가 행만 `config vdom` 접두 없이 나갔고,
                        # 바로 아래 행들은 접두가 붙어 있어 "이건 필요 없나 보다"
                        # 로 읽혔다. 기본 SSH 세션(관리 VDOM)에서 그 명령을
                        # 붙여넣으면 **같은 번호의 다른 살아 있는 정책**이
                        # 꺼진다 — 실측에서 그 정책의 APO 등급은 'Needs review'
                        # 였다(라운드 49). 되돌릴 방법은 없다.
                        "vdom": p.get("vdom") or "",
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
            # VIP 목적지 정책은 이 지름길에서 제외한다.
            #
            # FQDN·ISDB·사용자 객체는 "무엇으로 풀리든 전체의 부분집합"이라는
            # 논증이 그대로 성립한다. 그러나 VIP는 DNAT 의미론이 얽혀서
            # (dstaddr=all이 VIP 트래픽을 매칭하는지, match-vip 여부 등) 같은
            # 논증을 쓸 수 없다. 여기서 틀리면 살아 있는 정책을 '도달 불가'로
            # 보고하게 되고, 그건 이 기능이 절대 하지 않기로 한 오탐이다.
            # 확신이 없으면 말하지 않는다 — 판정 보류로 남긴다.
            touches_vip = any(str(n) in (vip_map or {})
                              for n in (p.get("dstaddr") or []))
            # **IPv6 정책은 이 지름길에서 제외한다.**
            #
            # 지름길의 논거는 "무엇으로 풀리든 **전체의 부분집합**" 이다.
            # FQDN·ISDB·사용자 객체는 IPv4 주소로 풀리므로 성립한다. 그런데
            # **IPv6 주소는 IPv4 전체집합의 부분집합이 아니다** — `srcaddr all`
            # 인 IPv4 정책은 IPv6 패킷을 하나도 매칭하지 않는다.
            #
            # 그래서 IPv4 전면허용 정책이 그 아래 IPv6 정책을 "절대 매칭되지
            # 않는다" 고 보고했고, 상세 문장이 스스로 모순됐다 —
            # "...regardless of what its objects resolve to **(uses IPv6
            # addresses)**". 게다가 그 항목에는 `set status disable` CLI 가
            # 붙어 나간다(9라운드 F1 실측). 이 기능의 제1 약속(오탐 0)을
            # 깨뜨리면서 **실행 가능한 삭제 명령까지** 주는 자리다.
            #
            # `tests/test_reachability.py` 에 IPv6 케이스가 0건이라 회귀
            # 테스트가 이 축을 전혀 보지 않았다 — 함께 넣는다.
            uses_v6 = bool(p.get("srcaddr6") or p.get("dstaddr6"))
            # 인터페이스까지 덮는 '전부 매칭' 정책만 인정한다.
            universal = None if (touches_vip or uses_v6) else next(
                (sp for sp, _ in shadowers_by_vdom.get(p.get("vdom") or "", [])
                 if _is_universal(sp, svc_map)
                 and _intf_covers(sp.get("srcintf") or [], p.get("srcintf") or [])
                 and _intf_covers(sp.get("dstintf") or [], p.get("dstintf") or [])),
                None)
            if universal is not None:
                # 환원은 못 했지만 결론이 났으므로 '판정함'에 넣는다. 안 그러면
                # 커버리지가 "10/11 검사, 0건 보류"처럼 자기모순이 된다.
                checked += 1
                unreachable.append({
                    "proof": "config",
                    "policy_id": p.get("policy_id"),
                    "vdom": p.get("vdom") or "",
                    "name": p.get("name", ""),
                    "shadowed_by": universal.get("policy_id"),
                    "shadowed_by_name": universal.get("name", ""),
                    "shadowed_by_action": universal.get("action", ""),
                    "detail": (
                        f"Policy {universal.get('policy_id')} above it accepts every "
                        "packet on the same interfaces (any source, any destination, "
                        "all services), so this policy can never match — regardless "
                        f"of what its objects resolve to ({why})."
                    ),
                })
            else:
                skipped.append({"policy_id": p.get("policy_id"),
                                "vdom": p.get("vdom") or "",
                                "name": p.get("name", ""), "reason": why})

        # shadower 자격: 환원 가능 + 활성 + 상시 스케줄 + 비 VIP 목적지.
        # 스케줄 정책은 꺼진 시간대에 아래 정책이 매칭될 수 있고, VIP 목적지
        # 정책은 DNAT된 트래픽만 매칭하므로 일반 트래픽을 가리지 못한다
        # (mappedip 공간을 일반 공간처럼 쓰면 오탐).
        if space is not None and status in ("enable", "enabled", "") \
                and str(schedule).lower() == "always" \
                and not space.get("vip_dst"):
            if _may_shadow(p):
                shadowers_by_vdom.setdefault(p.get("vdom") or "",
                                             []).append((p, space))
            else:
                # **믿지 못한 가림막도 흔적을 남긴다.** 이 목록이 비지 않으면
                # '발견 0건'은 '이상 없음'이 아니라 '증거로 쓸 수 있는 정책이
                # 없었다'는 뜻이다(라운드 43: full-configuration 백업에서
                # 전건 보류인데 화면은 초록으로 '전수 검사'라고 말했다).
                untrusted.append({
                    "policy_id": p.get("policy_id"),
                    "vdom": p.get("vdom") or "",
                    "name": p.get("name", ""),
                    "reason": "uses policy fields APO does not model, so it is "
                              "not used as evidence that other policies are dead",
                })

    return {
        "unreachable": unreachable,
        "skipped": skipped,
        "checked": checked,
        # 가림막으로 쓰지 못한 정책 — 이 수가 크면 '발견 0건'은 '이상 없음'이
        # 아니라 '증거로 쓸 수 있는 정책이 없었다'는 뜻이다.
        "untrusted_shadowers": untrusted,
        "total_enabled": sum(
            1 for p in policies
            if str(p.get("status", "enable")).lower() in ("enable", "enabled", "")),
        "capture_used": bool(fqdn_map),
        # **advisory — 판정이 아니다.** 로깅 꺼진 정책은 도달불가/shadow 판정에
        # 일절 관여하지 않는다(위 unreachable/skipped/checked 는 이 키를 읽지
        # 않는다). config 에 이미 있는 사실을 별도 감사 신호로 실어 보낼 뿐이다.
        # 자세한 근거는 detect_logging_disabled 참고.
        "logging_disabled": detect_logging_disabled(parsed),
        "note": (
            "Scope: firewall policies only — proxy policies are not examined by "
            "this check, so they are neither reported nor counted here. "
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


# ---------------------------------------------------------------------------
# 로깅 비활성 정책 — advisory (판정불변)
# ---------------------------------------------------------------------------
# **이것은 판정이 아니라 권고다.** shadow/도달불가 판정에는 일절 영향을 주지
# 않는다 — logtraffic 은 매칭을 좁히지 않으므로 `_MATCH_NEUTRAL_POLICY_KEYS`
# 에 그대로 남아 가림막 자격 계산은 변하지 않는다(test_reachability 로 고정).
# 여기서는 같은 필드를 별도의 감사 신호로만 읽는다: `set logtraffic disable`
# 인 정책은 SIEM 사각지대라, 사고 시 무엇이 허용됐는지 기록이 없다. PCI-DSS·
# ISO 27001·ISMS-P 세 감사 체제가 공통으로 "모든 permit/deny 룰은 로깅" 을
# 요구한다(근거: IDEAS.md 2026-09-01 — AlgoSec/Tufin 도 '로깅 없는 룰' 을
# 정리 대상 이상 룰로 분류).
#
# 보수적으로 **명시적 `disable` 만** 신고한다. FortiOS 기본값은 버전마다 달라
# (구버전 utm, 신버전 all 등) config 에 없는 값을 추정하면 advisory 가
# 노이즈가 된다 — APO 는 config 가 말하지 않은 것을 말하지 않는다. 활성 정책만
# 대상 — 꺼진 정책은 실시간 사각지대가 아니다. 도달불가 판정과 같은 스코프로
# firewall_policy 만 본다(프록시 정책은 제외).

def detect_logging_disabled(parsed: dict) -> list[dict]:
    """`set logtraffic disable` 인 활성 firewall 정책 목록(advisory).

    판정에 영향을 주지 않는 권고 신호다. 각 항목: policy_id, vdom, name, action.
    """
    out: list[dict] = []
    for p in parsed.get("firewall_policy", []) or []:
        if str(p.get("status", "enable")).lower() not in ("enable", "enabled", ""):
            continue
        if str(p.get("logtraffic", "")).strip().lower() != "disable":
            continue
        out.append({
            "policy_id": p.get("policy_id"),
            "vdom": p.get("vdom") or "",
            "name": p.get("name", ""),
            "action": p.get("action", ""),
        })
    return out
