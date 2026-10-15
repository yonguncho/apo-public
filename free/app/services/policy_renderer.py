from __future__ import annotations

import re
from datetime import date
from typing import Any

from .profile_loader import load_profile, to_customer_rules


# 프로파일에 적힌 패턴. 프로파일 파일은 실행 중에 바뀌지 않으므로 한 번만
# 읽는다(정책마다 YAML 을 다시 파싱하면 1,500건 화면이 눈에 띄게 느려진다).
# 화면에서 넣는 설정은 이것과 별개로 매번 확인한다 — 아래 _ticket_pattern().
_profile_pattern_cache: dict[str, object] = {"loaded": False, "value": None}


def _profile_ticket_pattern() -> str | None:
    if not _profile_pattern_cache["loaded"]:
        _profile_pattern_cache["value"] = to_customer_rules(
            load_profile()).get("ticket_id_pattern")
        _profile_pattern_cache["loaded"] = True
    return _profile_pattern_cache["value"]        # type: ignore[return-value]


def _ticket_pattern() -> re.Pattern | None:
    """지금 유효한 티켓 ID 패턴.

    출처는 **설정 화면 > 프로파일** 순이다. 설정이 없으면 프로파일
    `naming.ticket_id_pattern`(구형 customer_rules.json 도 하위호환 병합),
    그것도 없으면 None — 오탐 방지를 위해 추출 자체를 건너뛴다.

    **모듈 로드 시점에 컴파일해 두면 안 된다.** 예전에는 `_TICKET_PATTERN`
    이라는 모듈 상수였고, 그래서 설정을 저장해도 서버를 재시작하기 전까지
    반영되지 않았다. 설정 화면에서 티켓 형식을 입력하는 기능 자체가 성립하지
    않는 구조였다.
    """
    from .runtime_settings import compile_ticket_pattern
    return compile_ticket_pattern(_profile_ticket_pattern())


def reset_pattern_cache() -> None:
    """프로파일을 다시 읽게 한다(테스트·프로파일 전환용)."""
    _profile_pattern_cache["loaded"] = False
    _profile_pattern_cache["value"] = None


_YYMMDD_PATTERN = re.compile(r"^\d{6}$")


def _parse_yymmdd(token: str, past_only: bool = False) -> date | None:
    """YYMMDD -> date. 기본은 20xx 고정(만료일·스케줄 — 미래가 정상).

    past_only=True는 등록일용: 등록일은 과거일 수밖에 없으므로 20xx 해석이
    내년보다 뒤면 19xx로 본다. "991231"을 2099로 읽으면 age가 음수가 되어
    미사용 정책이 신규로 강등된다(감사 A4).
    """
    token = (token or "").strip()
    if not _YYMMDD_PATTERN.match(token):
        return None
    try:
        yy = int(token[:2])
        mm = int(token[2:4])
        dd = int(token[4:6])
        year = 2000 + yy
        if past_only and year > date.today().year + 1:
            year -= 100
        return date(year, mm, dd)
    except (ValueError, TypeError):
        return None


def extract_name_metadata(name: str, schedule: str | None = None,
                          comment: str | None = None) -> dict[str, Any]:
    """
    Policy Name format: YYMMDD_<ticket-id>_requester

    Returns dict with:
        request_date: date or None
            - first token of name when YYMMDD
            - falls back to schedule when name has no date token
        ritm: str or None (ticket ID matched via the configured ticket
            pattern, case-insensitive, normalized to upper; None when no
            pattern is configured)
        ticket_scanned: bool (False when no pattern is configured — the
            policy was not checked for a ticket, which is not the same as
            having none)
        requester: str or None (third underscore-token if present)
        is_controlled: bool (True when 'controlled' is in name, marks
            multi-firewall passthrough policy => urgency 7)
    """
    result: dict[str, Any] = {
        "request_date": None,
        "ritm": None,
        "ticket_scanned": False,
        "requester": None,
        "is_controlled": False,
    }
    name = name or ""

    if "controlled" in name.lower():
        result["is_controlled"] = True

    pattern = _ticket_pattern()
    result["ticket_scanned"] = pattern is not None
    if pattern:
        from .runtime_settings import MAX_SCAN_LEN, scan_comment_enabled
        # **길이를 자르고 매긴다.** 고급 입력으로 들어온 정규식이 검사를
        # 빠져나가더라도, 대상 문자열이 유한하면 백트래킹도 유한하다.
        haystacks = [(name or "")[:MAX_SCAN_LEN]]
        # 변경 번호를 이름이 아니라 장비 comment 에 적는 조직이 많다
        # (FireMon 은 comment 에 Change Control Number 를 넣는 것을 표준으로
        # 둔다). 이름만 보면 그런 고객은 전량 미인식이 된다.
        if comment and scan_comment_enabled():
            haystacks.append(str(comment)[:MAX_SCAN_LEN])
        for hay in haystacks:
            match = pattern.search(hay)
            if match:
                result["ritm"] = match.group().upper()
                break

    parts = [p.strip() for p in name.split("_") if p.strip()]
    if parts:
        date_from_name = _parse_yymmdd(parts[0], past_only=True)
        if date_from_name:
            result["request_date"] = date_from_name
        if len(parts) >= 3:
            result["requester"] = parts[2]

    # 스케줄(=만료일)을 등록일로 쓰지 않는다(감사 A12) — 미래 등록일이 생겨
    # age가 음수가 되고 "신규"로 오판된다. 등록일 미상은 미상으로 둔다.

    return result



def _stats_for(runtime_stats: dict, ptype: str) -> dict:
    """정책 종류별 사용량 통계를 고른다.

    FortiGate는 firewall 정책과 proxy 정책에 **각각 1번부터** 번호를 매긴다.
    그래서 두 통계를 한 딕셔너리에 합치면 proxy 7번의 hit_count·last_used·status가
    firewall 7번에 그대로 얹힌다. 살아 있는 정책이 "한 번도 안 쓰임"으로 바뀌어
    Critical·"Disable now"로 판정되고, 장비에 적용할 후보 목록에까지 올라간다
    (실 config에서 fw/proxy ID 충돌 44건 관측 — workbook_exporter 주석 참조).

    새 형태: {"firewall": {id: stats}, "proxy": {id: stats}}
    옛 형태: {id: stats}  — 종류를 알 수 없으므로 예전처럼 양쪽에 그대로 쓴다.
    호출부가 종류를 알려주지 않던 시절의 입력(구형 클라이언트·직접 API 호출)이
    조용히 깨지지 않게 하기 위한 하위호환이다.
    """
    if not isinstance(runtime_stats, dict) or not runtime_stats:
        return {}
    # `_vdom` 은 '이 CSV 가 어느 VDOM 것인가' 라는 꼬리표이지 통계가 아니다.
    runtime_stats = {k: v for k, v in runtime_stats.items() if k != "_vdom"}
    if not runtime_stats:
        return {}
    # 'firewall'/'proxy' 라는 **정책 번호**가 CSV에 한 줄 있으면 평평한 통계가
    # 종류별로 오인돼, 실제 정책 통계가 통째로 버려진다. 네임스페이스라면 값이
    # 반드시 dict-of-dict 이므로 그것까지 확인한다.
    def _is_namespace(v) -> bool:
        return isinstance(v, dict) and all(isinstance(x, dict) for x in v.values())

    if (("firewall" in runtime_stats and _is_namespace(runtime_stats["firewall"]))
            or ("proxy" in runtime_stats and _is_namespace(runtime_stats["proxy"]))):
        scoped = runtime_stats.get(ptype) or {}
        return scoped if isinstance(scoped, dict) else {}
    return runtime_stats


def build_view_model(parsed: dict[str, Any], runtime_stats: dict[str, dict[str, Any]]) -> dict[str, Any]:
    # **사용량 CSV 는 한 VDOM 것이다.** FortiGate 는 VDOM 마다 정책 번호를
    # 1번부터 다시 매기고, GUI 의 `Export to CSV` 는 **지금 서 있는 VDOM** 만
    # 내보낸다. 그런데 통계는 번호로만 키를 잡아, root 에서 뽑은 CSV 가 CORP·
    # DMZ 의 같은 번호 정책에 그대로 얹혔다 — 매칭률은 60/60 이라 "다른 장비
    # CSV" 경고도 뜨지 않았고, 워크북은 **한 번도 측정한 적 없는 정책 42건에
    # 대해 "unused (Hit=0)"** 라고 적었다(라운드 49 실측). 반대 방향도 같다:
    # 바쁜 root 12번이 죽은 CORP 12번을 살려 둔다.
    #
    # 그래서 CSV 가 어느 VDOM 것인지 아는 경우에만 그 VDOM 에 붙인다. 모르면
    # 붙이지 않는다 — 판정은 '사용량 미상'이 되고, 그건 참이다.
    # 단일 VDOM 장비에서는 아무것도 달라지지 않는다.
    _vdoms = (parsed.get("meta") or {}).get("vdoms") or []
    _multi = len([v for v in _vdoms if v]) > 1
    _stats_vdom = str((runtime_stats or {}).get("_vdom") or "").strip().lower()

    def _scoped(stats: dict, item: dict) -> dict:
        if not _multi or not stats:
            return stats
        if _stats_vdom and str(item.get("vdom") or "").strip().lower() == _stats_vdom:
            return stats
        return {}

    interface_map = _index_by_key(parsed.get("system_interface", []), "port")
    address_map = _index_by_key(parsed.get("firewall_address", []), "name")
    addrgrp_map = _index_by_key(parsed.get("firewall_addrgrp", []), "name")
    proxy_address_map = _index_by_key(parsed.get("firewall_proxy_address", []), "name")
    proxy_addrgrp_map = _index_by_key(parsed.get("firewall_proxy_addrgrp", []), "name")
    service_custom_map = _index_by_key(parsed.get("firewall_service_custom", []), "name")
    service_group_map = _index_by_key(parsed.get("firewall_service_group", []), "name")

    return {
        "meta": {
            **parsed.get("meta", {}),
            # **경고를 meta 에도 싣는다.** 최상위에만 있으면 화면의 장비 정보
            # 렌더러가 meta 만 받아 보므로 닿지 않는다 — 만들어 두고 아무도
            # 안 보면 없는 것과 같다(라운드 42: 잘린 백업에서 정책이 조용히
            # 사라졌다).
            "parse_warnings": parsed.get("parse_warnings", []),
            "policy_count": len(parsed.get("firewall_policy", [])),
            "proxy_policy_count": len(parsed.get("firewall_proxy_policy", [])),
            "multicast_policy_count": len(parsed.get("firewall_multicast_policy", [])),
            "address_count": len(parsed.get("firewall_address", [])),
            "addrgrp_count": len(parsed.get("firewall_addrgrp", [])),
            "service_custom_count": len(parsed.get("firewall_service_custom", [])),
            "service_group_count": len(parsed.get("firewall_service_group", [])),
            "proxy_address_count": len(parsed.get("firewall_proxy_address", [])),
            "proxy_addrgrp_count": len(parsed.get("firewall_proxy_addrgrp", [])),
            "interface_count": len(parsed.get("system_interface", [])),
        },
        "firewall_policy": [
            _render_policy(item, interface_map, address_map, addrgrp_map,
                           service_custom_map, service_group_map,
                           _scoped(_stats_for(runtime_stats, "firewall"), item))
            for item in parsed.get("firewall_policy", [])
        ],
        "firewall_proxy_policy": [
            _render_policy(item, interface_map, proxy_address_map, proxy_addrgrp_map,
                           service_custom_map, service_group_map,
                           _scoped(_stats_for(runtime_stats, "proxy"), item))
            for item in parsed.get("firewall_proxy_policy", [])
        ],
        "firewall_multicast_policy": [
            _render_multicast_policy(item, interface_map, address_map, addrgrp_map)
            for item in parsed.get("firewall_multicast_policy", [])
        ],
        "firewall_address": [
            {**item, "resolved": _render_address(item)}
            for item in parsed.get("firewall_address", [])
        ],
        "firewall_addrgrp": [
            {
                **grp,
                "resolved_members": _dedupe(
                    sum(
                        [_resolve_address_object(member, address_map, addrgrp_map) for member in grp.get("member", [])],
                        [],
                    )
                ),
            }
            for grp in parsed.get("firewall_addrgrp", [])
        ],
        "firewall_proxy_address": [
            {**item, "resolved": _render_address(item)}
            for item in parsed.get("firewall_proxy_address", [])
        ],
        "firewall_proxy_addrgrp": [
            {
                **grp,
                "resolved_members": _dedupe(
                    sum(
                        [_resolve_address_object(member, proxy_address_map, proxy_addrgrp_map) for member in grp.get("member", [])],
                        [],
                    )
                ),
            }
            for grp in parsed.get("firewall_proxy_addrgrp", [])
        ],
        "firewall_service_custom": [
            {
                **item,
                "resolved": _render_service(item),
            }
            for item in parsed.get("firewall_service_custom", [])
        ],
        "firewall_service_group": [
            {
                **grp,
                "resolved_members": _dedupe(
                    sum(
                        [_resolve_service_object(member, service_custom_map, service_group_map) for member in grp.get("member", [])],
                        [],
                    )
                ),
            }
            for grp in parsed.get("firewall_service_group", [])
        ],
        "system_interface": parsed.get("system_interface", []),
        "parse_warnings": parsed.get("parse_warnings", []),
    }


def _render_policy(
    item: dict[str, Any],
    interface_map: dict[str, dict[str, Any]],
    address_map: dict[str, dict[str, Any]],
    addrgrp_map: dict[str, dict[str, Any]],
    service_custom_map: dict[str, dict[str, Any]],
    service_group_map: dict[str, dict[str, Any]],
    runtime_stats: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    policy_id = item.get("policy_id")
    runtime = runtime_stats.get(str(policy_id), {})
    config_status = str(item.get("status", "enable")).strip().lower() or "enable"
    display_status = runtime.get("status") or ("Disabled" if config_status == "disable" else "Enabled")
    raw_name = item.get("name", "")
    raw_schedule = item.get("schedule", "")
    raw_comment = item.get("comments") or item.get("comment") or ""
    name_meta = extract_name_metadata(raw_name, raw_schedule, raw_comment)
    request_date = name_meta["request_date"]

    return {
        "policy_id": policy_id,
        # VDOM 은 정책 번호의 일부다. 여기서 떨구면 조치가 어느 VDOM 으로
        # 나가는지 아무도 알 수 없다(라운드 39: PUT 이 엉뚱한 VDOM 으로 갔다).
        "vdom": item.get("vdom") or "",
        "name": raw_name,
        "ritm": name_meta["ritm"],
        "ticket_scanned": name_meta["ticket_scanned"],
        "request_date": request_date.isoformat() if request_date else None,
        "requester": name_meta["requester"],
        "is_controlled": name_meta["is_controlled"],
        "srcintf_display": [_resolve_interface(name, interface_map) for name in item.get("srcintf", [])],
        "dstintf_display": [_resolve_interface(name, interface_map) for name in item.get("dstintf", [])],
        "srcaddr_display": _dedupe(sum([
            _resolve_address_object(name, address_map, addrgrp_map) for name in item.get("srcaddr", [])
        ], [])),
        "dstaddr_display": _dedupe(sum([
            _resolve_address_object(name, address_map, addrgrp_map) for name in item.get("dstaddr", [])
        ], [])),
        # 원본 객체명. display는 그룹을 구성원 IP로 펼치면서 이름을 버리는데,
        # 고객이 등록한 예외 객체 목록(admin/mgmt/infra…)은 **이름**으로
        # 매칭한다. 이름을 잃으면 그룹 객체에 대한 예외가 통째로 무력화된다
        # (2026-08-10 실장비 대조에서 발견 — 실 config 112건 누락).
        "srcaddr_names": list(item.get("srcaddr", [])),
        "dstaddr_names": list(item.get("dstaddr", [])),
        "service_display": item.get("service", []),
        "service_resolved_display": _dedupe(sum([
            _resolve_service_object(name, service_custom_map, service_group_map) for name in item.get("service", [])
        ], [])),
        "schedule": raw_schedule,
        # 룰 소명(recertification) 시트가 '업무 근거 메모가 있는가'를 판단하는 값.
        # 판정에는 쓰이지 않는다(severity_engine 은 comments 를 티켓 스캔용으로만
        # 읽는다) — normalize_policy 화이트리스트에도 없어 골든 severity 해시는
        # 불변이다. _raw 대신 최상위 필드로 두는 이유: export payload 는 클라이언트
        # 왕복분이라 _raw 생존이 불확실하고, schedule·reason 처럼 최상위 값만
        # 안정적으로 되돌아온다.
        "comment": raw_comment,
        "action": item.get("action", ""),
        "status": display_status,
        "hit_count": runtime.get("hit_count"),   # None = CSV 미로드, 0 = 실제 0
        "last_used": runtime.get("last_used") or "-",
        "_raw": item,
    }


def _render_multicast_policy(
    item: dict[str, Any],
    interface_map: dict[str, dict[str, Any]],
    address_map: dict[str, dict[str, Any]],
    addrgrp_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Multicast policies are flagged out of severity classification but listed in their own tab."""
    raw_name = item.get("name", "")
    raw_schedule = item.get("schedule", "")
    name_meta = extract_name_metadata(
        raw_name, raw_schedule, item.get("comments") or item.get("comment") or "")
    request_date = name_meta["request_date"]
    config_status = str(item.get("status", "enable")).strip().lower() or "enable"
    display_status = "Disabled" if config_status == "disable" else "Enabled"

    return {
        "policy_id": item.get("policy_id"),
        "vdom": item.get("vdom") or "",
        "name": raw_name,
        "ritm": name_meta["ritm"],
        "ticket_scanned": name_meta["ticket_scanned"],
        "request_date": request_date.isoformat() if request_date else None,
        "requester": name_meta["requester"],
        "is_controlled": name_meta["is_controlled"],
        "srcintf_display": [_resolve_interface(name, interface_map) for name in item.get("srcintf", [])],
        "dstintf_display": [_resolve_interface(name, interface_map) for name in item.get("dstintf", [])],
        "srcaddr_display": _dedupe(sum([
            _resolve_address_object(name, address_map, addrgrp_map) for name in item.get("srcaddr", [])
        ], [])),
        "dstaddr_display": _dedupe(sum([
            _resolve_address_object(name, address_map, addrgrp_map) for name in item.get("dstaddr", [])
        ], [])),
        # 원본 객체명. display는 그룹을 구성원 IP로 펼치면서 이름을 버리는데,
        # 고객이 등록한 예외 객체 목록(admin/mgmt/infra…)은 **이름**으로
        # 매칭한다. 이름을 잃으면 그룹 객체에 대한 예외가 통째로 무력화된다
        # (2026-08-10 실장비 대조에서 발견 — 실 config 112건 누락).
        "srcaddr_names": list(item.get("srcaddr", [])),
        "dstaddr_names": list(item.get("dstaddr", [])),
        "action": item.get("action", ""),
        "status": display_status,
        "schedule": raw_schedule,
        "comment": item.get("comments") or item.get("comment") or "",
        "_raw": item,
    }


def _resolve_interface(port_name: str, interface_map: dict[str, dict[str, Any]]) -> str:
    info = interface_map.get(port_name)
    if not info:
        return port_name
    return info.get("display_name") or port_name


def _resolve_grouped_object(
    name: str,
    leaf_map: dict[str, dict[str, Any]],
    group_map: dict[str, dict[str, Any]],
    render_leaf,
    memo: dict[str, list[str]] | None = None,
) -> list[str]:
    """중첩 그룹을 전개한다. 반복(iterative) + 메모이제이션.

    이전 구현은 재귀 호출마다 visited 집합을 copy()해서 넘겼다. 순환은 막았지만
    같은 그룹이 서로 다른 경로로 도달하면 매번 다시 전개돼, 각 그룹이 다음
    그룹을 두 번씩 참조하는 설정에서 2^depth로 폭발했다(888바이트 설정 파일로
    27초, 깊이 30이면 수 시간). 또 깊이만큼 파이썬 프레임을 써서 1500단
    중첩이면 RecursionError로 죽었다.

    여기서는 그룹당 한 번만 전개해 결과를 memo에 담고, 스택을 명시적으로
    관리해 재귀 깊이 제한도 받지 않는다.
    """
    if memo is None:
        memo = {}

    # (노드, 자식 처리 완료 여부) 스택. resolving은 현재 경로 = 순환 감지용.
    stack: list[tuple[str, bool]] = [(name, False)]
    resolving: set[str] = set()

    while stack:
        node, expanded = stack.pop()

        if expanded:
            # 자식들이 모두 memo에 들어온 뒤 합친다.
            members = group_map[node].get("member", [])
            out: list[str] = []
            for m in members:
                out.extend(memo.get(m, [m]))
            memo[node] = _dedupe(out)
            resolving.discard(node)
            continue

        if node in memo:
            continue
        if node in resolving:
            # 현재 전개 경로에 다시 등장 = 순환
            memo[node] = [f"[CYCLE:{node}]"]
            continue
        if node in leaf_map:
            memo[node] = [render_leaf(leaf_map[node])]
            continue
        if node not in group_map:
            memo[node] = [node]
            continue

        resolving.add(node)
        stack.append((node, True))
        for member in group_map[node].get("member", []):
            if member not in memo:
                stack.append((member, False))

    return memo.get(name, [name])


def _resolve_address_object(
    name: str,
    address_map: dict[str, dict[str, Any]],
    addrgrp_map: dict[str, dict[str, Any]],
    memo: dict[str, list[str]] | None = None,
) -> list[str]:
    return _resolve_grouped_object(name, address_map, addrgrp_map, _render_address, memo)


def _resolve_service_object(
    name: str,
    service_custom_map: dict[str, dict[str, Any]],
    service_group_map: dict[str, dict[str, Any]],
    memo: dict[str, list[str]] | None = None,
) -> list[str]:
    return _resolve_grouped_object(name, service_custom_map, service_group_map, _render_service, memo)


def _render_address(item: dict[str, Any]) -> str:
    name = str(item.get("name", "")).strip()
    addr_type = item.get("type", "ipmask")
    if addr_type == "ipmask":
        if item.get("subnet_cidr"):
            return item["subnet_cidr"]
        subnet = item.get("subnet")
        if isinstance(subnet, list) and subnet:
            return "/".join(str(x) for x in subnet)
        if subnet:
            return str(subnet)
        return name
    if addr_type == "iprange":
        return item.get("range") or name or ""
    if addr_type == "fqdn":
        return str(item.get("fqdn", "")) or name
    if addr_type == "wildcard":
        value = item.get("wildcard")
        if isinstance(value, list):
            rendered = " ".join(value)
        else:
            rendered = str(value or "")
        return rendered or name
    if addr_type == "geography":
        return f"[geography:{item.get('country', '')}]"
    if addr_type in {"wildcard-fqdn", "dynamic", "interface-subnet"}:
        return str(item.get("wildcard-fqdn") or item.get("subnet") or name)
    return name or f"[{addr_type}]"


def _render_service(item: dict[str, Any]) -> str:
    protocol = str(item.get("protocol", "TCP/UDP/SCTP"))
    parts: list[str] = []
    if item.get("tcp-portrange"):
        parts.append(f"TCP:{item['tcp-portrange']}")
    if item.get("udp-portrange"):
        parts.append(f"UDP:{item['udp-portrange']}")
    if item.get("sctp-portrange"):
        parts.append(f"SCTP:{item['sctp-portrange']}")
    if parts:
        return " | ".join(parts)
    return protocol


def _index_by_key(items: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        value = item.get(key)
        if value:
            result[str(value)] = item
    return result


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
