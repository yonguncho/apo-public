from __future__ import annotations

import re
from datetime import date
from typing import Any


_RITM_PATTERN = re.compile(r"RITM\d+", re.IGNORECASE)
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
    Policy Name format: YYMMDD_RITMxxxxxxx_requester

    Returns dict with:
        request_date: date or None
            - first token of name when YYMMDD
            - falls back to schedule when name has no date token
        ritm: str or None (matches RITM<digits> case-insensitive, normalized to upper)
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

    ritm_match = _RITM_PATTERN.search(name)
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


def _resolve_address_object(
    name: str,
    address_map: dict[str, dict[str, Any]],
    addrgrp_map: dict[str, dict[str, Any]],
    visited: set[str] | None = None,
) -> list[str]:
    if visited is None:
        visited = set()

    if name in visited:
        return [f"[CYCLE:{name}]"]
    visited.add(name)

    if name in address_map:
        return [_render_address(address_map[name])]

    if name in addrgrp_map:
        results: list[str] = []
        for member in addrgrp_map[name].get("member", []):
            results.extend(_resolve_address_object(member, address_map, addrgrp_map, visited.copy()))
        return _dedupe(results)

    return [name]


def _resolve_service_object(
    name: str,
    service_custom_map: dict[str, dict[str, Any]],
    service_group_map: dict[str, dict[str, Any]],
    visited: set[str] | None = None,
) -> list[str]:
    if visited is None:
        visited = set()
    if name in visited:
        return [f"[CYCLE:{name}]"]
    visited.add(name)

    if name in service_custom_map:
        return [_render_service(service_custom_map[name])]

    if name in service_group_map:
        results: list[str] = []
        for member in service_group_map[name].get("member", []):
            results.extend(_resolve_service_object(member, service_custom_map, service_group_map, visited.copy()))
        return _dedupe(results)

    return [name]


def _render_address(item: dict[str, Any]) -> str:
    name = str(item.get("name", "")).strip()
    addr_type = item.get("type", "ipmask")
    if addr_type == "ipmask":
        return item.get("subnet_cidr") or (name if name else str(item.get("subnet", "")))
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
