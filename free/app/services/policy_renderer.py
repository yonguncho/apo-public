from __future__ import annotations

import re
from datetime import date
from typing import Any

from .customer_rules_loader import load_customer_rules


def _compile_ticket_pattern() -> re.Pattern | None:
    """고객사 ITSM 티켓 ID 패턴은 customer_rules.json의 ticket_id_pattern으로 설정한다.
    설정이 없으면 오탐(false positive) 방지를 위해 티켓 ID 추출 자체를 건너뛴다
    (has_ritm=False로만 처리, 잘못된 매칭 없음)."""
    pattern = load_customer_rules().get("ticket_id_pattern")
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None


_TICKET_PATTERN = _compile_ticket_pattern()
_YYMMDD_PATTERN = re.compile(r"^\d{6}$")


def _parse_yymmdd(token: str) -> date | None:
    token = (token or "").strip()
    if not _YYMMDD_PATTERN.match(token):
        return None
    try:
        yy = int(token[:2])
        mm = int(token[2:4])
        dd = int(token[4:6])
        year = 2000 + yy
        return date(year, mm, dd)
    except (ValueError, TypeError):
        return None


def extract_name_metadata(name: str, schedule: str | None = None) -> dict[str, Any]:
    """
    Policy Name format: YYMMDD_<ticket-id>_requester

    Returns dict with:
        request_date: date or None
            - first token of name when YYMMDD
            - falls back to schedule when name has no date token
        ritm: str or None (ticket ID matched via customer_rules.json's
            ticket_id_pattern, case-insensitive, normalized to upper;
            None when no pattern is configured)
        requester: str or None (third underscore-token if present)
        is_controlled: bool (True when 'controlled' is in name, marks
            multi-firewall passthrough policy => urgency 7)
    """
    result: dict[str, Any] = {
        "request_date": None,
        "ritm": None,
        "requester": None,
        "is_controlled": False,
    }
    name = name or ""

    if "controlled" in name.lower():
        result["is_controlled"] = True

    ritm_match = _TICKET_PATTERN.search(name) if _TICKET_PATTERN else None
    if ritm_match:
        result["ritm"] = ritm_match.group().upper()

    parts = [p.strip() for p in name.split("_") if p.strip()]
    if parts:
        date_from_name = _parse_yymmdd(parts[0])
        if date_from_name:
            result["request_date"] = date_from_name
        if len(parts) >= 3:
            result["requester"] = parts[2]

    if result["request_date"] is None and schedule:
        result["request_date"] = _parse_yymmdd(str(schedule).strip())

    return result


def build_view_model(parsed: dict[str, Any], runtime_stats: dict[str, dict[str, Any]]) -> dict[str, Any]:
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
            _render_policy(item, interface_map, address_map, addrgrp_map, service_custom_map, service_group_map, runtime_stats)
            for item in parsed.get("firewall_policy", [])
        ],
        "firewall_proxy_policy": [
            _render_policy(item, interface_map, proxy_address_map, proxy_addrgrp_map, service_custom_map, service_group_map, runtime_stats)
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
    name_meta = extract_name_metadata(raw_name, raw_schedule)
    request_date = name_meta["request_date"]

    return {
        "policy_id": policy_id,
        "name": raw_name,
        "ritm": name_meta["ritm"],
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
        "service_display": item.get("service", []),
        "service_resolved_display": _dedupe(sum([
            _resolve_service_object(name, service_custom_map, service_group_map) for name in item.get("service", [])
        ], [])),
        "schedule": raw_schedule,
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
    name_meta = extract_name_metadata(raw_name, raw_schedule)
    request_date = name_meta["request_date"]
    config_status = str(item.get("status", "enable")).strip().lower() or "enable"
    display_status = "Disabled" if config_status == "disable" else "Enabled"

    return {
        "policy_id": item.get("policy_id"),
        "name": raw_name,
        "ritm": name_meta["ritm"],
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
