"""
ip_classifier.py — User CIDR 기반 IP 분류
User 대역 포함 = User, 그 외 = Server, 대역 미설정 = Unknown
"""
import ipaddress


def _addr_interval(text) -> tuple | None:
    """화면 표기 주소 -> (lo, hi) 정수 구간. 못 읽으면 None.

    srcaddr_display 는 CIDR 만 오는 게 아니다 — **iprange 객체는
    'a.b.c.d-e.f.g.h'**, 일부 표기는 'a.b.c.d m.m.m.m'(넷마스크)로 온다.
    CIDR 만 파싱하던 동안 iprange 유저 대역 정책이 전부 Server 로
    오분류돼 traffic_type 축의 등급이 통째로 갈렸다(라운드 78 게이트
    correctness 실행 재현 — 라운드 12 가 잡은 '대역은 설정됐는데 매칭은
    전멸'과 같은 조용한 판정 오류의 주소 쪽 얼굴).
    """
    t = str(text or "").strip()
    if not t:
        return None
    try:
        if "-" in t:
            lo_s, hi_s = t.split("-", 1)
            lo = ipaddress.IPv4Address(lo_s.strip())
            hi = ipaddress.IPv4Address(hi_s.strip())
            if int(lo) > int(hi):
                return None
            return int(lo), int(hi)
        if " " in t:
            ip_s, mask_s = t.split(None, 1)
            net = ipaddress.IPv4Network(f"{ip_s}/{mask_s.strip()}",
                                        strict=False)
            return int(net.network_address), int(net.broadcast_address)
        net = ipaddress.ip_network(t, strict=False)
        if net.version != 4:
            return None
        return int(net.network_address), int(net.broadcast_address)
    except Exception:
        return None


def classify_ip(addr_list, user_ranges: list) -> str:
    if not user_ranges:
        return "Unknown"
    # `None`·`""` 도 빈 목록과 같은 뜻이다 — 스칼라라서 `[None]` 이 되면
    # 아래 빈 검사를 비껴간다. 엔진은 `... or []` 로 넘기므로 지금 판정에는
    # 닿지 않지만, 같은 사실을 두 모양으로 답하게 두지 않는다.
    items = (addr_list if isinstance(addr_list, list)
             else ([addr_list] if addr_list else []))
    # **빈 목록은 'Server' 가 아니라 '모름'이다.**
    # (2026-09-13 Jayden 승인 — 9라운드 판정 정확성 렌즈 B)
    #
    # 루프를 한 번도 안 돌고 `return "Server"` 가 나가면
    # `classify_traffic_type([], [], ranges)` 가 `"Server-Server"` 가 된다 —
    # 주소를 **하나도 모르는데** 서버 간 통신이라고 단정하는 것이다. 엔진에는
    # 이 상황을 위한 등급 0 `Unknown traffic type — set User IP ranges first`
    # 가 이미 있는데 빈 목록이 그 길을 우회했다.
    #
    # 재현 경로 둘: ① IPv6 전용 정책(`srcaddr` 키 자체가 없다)
    #             ② 멤버가 빈 주소그룹
    # 실 고객 config 1건이 sev 4 → 0 으로 간다.
    #
    # `reachability._intf_covers` 가 **정확히 같은 클래스를 이미 고쳐 놓았다**
    # — "빈 대상 인터페이스 목록은 'any' 가 아니라 '모름'이다 … 제1 약속
    # (오탐 0) 위반 클래스(B-40)". 같은 규칙을 주소 분류에도 적용한다.
    if not items:
        return "Unknown"
    for addr in items:
        iv = _addr_interval(addr)
        if iv is None:
            continue
        lo, hi = iv
        for entry in user_ranges:
            # 항목 하나가 안 읽힌다고 **나머지 대역까지 버리면 안 된다**.
            # 예전에는 try가 이 루프를 통째로 감싸서, 목록 앞쪽에 못 읽는 값이
            # 하나 있으면 뒤의 정상 대역이 전부 무시되고 모든 주소가 Server로
            # 분류됐다 — 대역은 '설정됨'인데 매칭은 전멸하는 조용한 판정 오류였다
            # (리뷰 라운드 12 실측: 정책 9건 Server-User→Server-Server).
            try:
                cidr = entry["cidr"] if isinstance(entry, dict) else str(entry)
                net = ipaddress.ip_network(cidr, strict=False)
            except Exception:
                continue
            if net.version != 4:
                continue
            # 주소가 User 대역에 '포함'될 때만 User로 분류(구간 포함 —
            # overlaps 는 0.0.0.0/0 같은 광대역도 User 로 오분류한다).
            if (int(net.network_address) <= lo
                    and hi <= int(net.broadcast_address)):
                return "User"
    return "Server"


def classify_traffic_type(src_list, dst_list, user_ranges: list) -> str:
    """반환: "Server-Server", "Server-User", "Unknown" """
    if not user_ranges:
        return "Unknown"
    src_t = classify_ip(src_list, user_ranges)
    dst_t = classify_ip(dst_list, user_ranges)
    if "Unknown" in (src_t, dst_t):
        return "Unknown"
    if src_t == "Server" and dst_t == "Server":
        return "Server-Server"
    return "Server-User"
