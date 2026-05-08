from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any


TARGET_SECTIONS = {
    "config firewall policy": "firewall_policy",
    "config firewall proxy-policy": "firewall_proxy_policy",
    "config firewall multicast-policy": "firewall_multicast_policy",
    "config firewall address": "firewall_address",
    "config firewall addrgrp": "firewall_addrgrp",
    "config firewall proxy-address": "firewall_proxy_address",
    "config firewall proxy-addrgrp": "firewall_proxy_addrgrp",
    "config firewall service custom": "firewall_service_custom",
    "config firewall service group": "firewall_service_group",
    "config system interface": "system_interface",
}


@dataclass
class ParseState:
    current_section: str | None = None
    current_object: dict[str, Any] | None = None
    config_stack: list[str] = field(default_factory=list)
    parsed: dict[str, Any] = field(
        default_factory=lambda: {
            "meta": {},
            "firewall_policy": [],
            "firewall_proxy_policy": [],
            "firewall_multicast_policy": [],
            "firewall_address": [],
            "firewall_addrgrp": [],
            "firewall_proxy_address": [],
            "firewall_proxy_addrgrp": [],
            "firewall_service_custom": [],
            "firewall_service_group": [],
            "system_interface": [],
            "parse_warnings": [],
        }
    )


class FortiGateConfigParser:
    def __init__(self, raw_text: str):
        self.lines = raw_text.splitlines()

    def parse(self) -> dict[str, Any]:
        state = ParseState()
        self._parse_meta(state)

        for lineno, raw_line in enumerate(self.lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("config "):
                state.config_stack.append(line)
                if line in TARGET_SECTIONS:
                    state.current_section = TARGET_SECTIONS[line]
                    state.current_object = None
                continue

            if line == "end":
                ended = state.config_stack.pop() if state.config_stack else None
                if ended in TARGET_SECTIONS:
                    state.current_section = None
                    state.current_object = None
                continue

            if state.current_section is None:
                continue

            # Ignore nested config bodies inside a target object, e.g. config secondaryip
            if len(state.config_stack) > 1:
                continue

            if line.startswith("edit "):
                edit_key = self._strip_quotes(line[5:].strip())
                state.current_object = {"_edit": edit_key}
                continue

            if line == "next":
                if state.current_object is not None:
                    normalized = self._normalize_object(state.current_section, state.current_object)
                    state.parsed[state.current_section].append(normalized)
                state.current_object = None
                continue

            if line.startswith("set ") and state.current_object is not None:
                try:
                    key, value = self._parse_set_line(line)
                    state.current_object[key] = value
                except Exception as exc:
                    state.parsed["parse_warnings"].append(
                        {"line": lineno, "content": line, "warning": str(exc)}
                    )
                continue

        # Build service_groups lookup: { "AD_AUTH": ["LDAP", "Kerberos", ...], ... }
        # Used by severity_engine.expand_services to resolve risky/AD-DNS membership.
        state.parsed["service_groups"] = build_service_group_map(
            state.parsed.get("firewall_service_group", [])
        )
        return state.parsed

    def _parse_meta(self, state: ParseState) -> None:
        for raw_line in self.lines[:50]:
            line = raw_line.strip()
            if line.startswith("#config-version="):
                state.parsed["meta"]["config_version"] = line.split("=", 1)[1]
            if line.startswith("#buildno="):
                state.parsed["meta"]["buildno"] = line.split("=", 1)[1]
            if "set hostname " in line and "hostname" not in state.parsed["meta"]:
                state.parsed["meta"]["hostname"] = self._strip_quotes(
                    line.split("set hostname", 1)[1].strip()
                )

    def _parse_set_line(self, line: str) -> tuple[str, Any]:
        m = re.match(r"set\s+(\S+)\s+(.+)$", line)
        if not m:
            raise ValueError("Invalid set line")
        key, raw_value = m.group(1), m.group(2).strip()

        quoted = re.findall(r'"([^"]+)"', raw_value)
        if quoted:
            raw_without_quotes = re.sub(r'"[^"]+"', '', raw_value).strip()
            if raw_without_quotes:
                return key, quoted + raw_without_quotes.split()
            return key, quoted[0] if len(quoted) == 1 else quoted

        parts = raw_value.split()
        if len(parts) == 1:
            return key, parts[0]
        return key, parts

    def _normalize_object(self, section: str, obj: dict[str, Any]) -> dict[str, Any]:
        item = dict(obj)

        if section in {"firewall_policy", "firewall_proxy_policy"}:
            item["policy_id"] = self._coerce_int(item.get("_edit"))
            item["name"] = item.get("name", "")
            for key in ("srcintf", "dstintf", "srcaddr", "dstaddr", "service"):
                value = item.get(key, [])
                if isinstance(value, str):
                    item[key] = [value]
                elif not isinstance(value, list):
                    item[key] = []

        elif section == "firewall_multicast_policy":
            item["policy_id"] = self._coerce_int(item.get("_edit"))
            item["name"] = item.get("name", "")
            for key in ("srcintf", "dstintf", "srcaddr", "dstaddr"):
                value = item.get(key, [])
                if isinstance(value, str):
                    item[key] = [value]
                elif not isinstance(value, list):
                    item[key] = []

        elif section in {"firewall_address", "firewall_proxy_address"}:
            item["name"] = item.get("_edit", "")
            addr_type = item.get("type", "ipmask")
            item["type"] = addr_type
            if "subnet" in item and isinstance(item["subnet"], list) and len(item["subnet"]) == 2:
                ip_str, mask_str = item["subnet"]
                item["subnet_cidr"] = self._to_cidr(ip_str, mask_str)
            if "start-ip" in item or "end-ip" in item:
                item["range"] = f'{item.get("start-ip", "")}-{item.get("end-ip", "")}'.strip("-")

        elif section in {"firewall_addrgrp", "firewall_proxy_addrgrp"}:
            item["name"] = item.get("_edit", "")
            members = item.get("member", [])
            if isinstance(members, str):
                members = [members]
            item["member"] = members

        elif section == "firewall_service_custom":
            item["name"] = item.get("_edit", "")
            for key in ("tcp-portrange", "udp-portrange", "sctp-portrange", "category"):
                value = item.get(key)
                if isinstance(value, list):
                    item[key] = " ".join(str(v) for v in value)
            item["resolved"] = self._render_service(item)

        elif section == "firewall_service_group":
            item["name"] = item.get("_edit", "")
            members = item.get("member", [])
            if isinstance(members, str):
                members = [members]
            item["member"] = members

        elif section == "system_interface":
            item["port"] = item.get("_edit", "")
            item["display_name"] = self._build_interface_display(item)

        return item

    def _build_interface_display(self, item: dict[str, Any]) -> str:
        port = item.get("_edit", "")
        alias = item.get("alias")
        if isinstance(alias, list):
            alias = alias[0] if alias else None
        if alias:
            return f"{alias}({port})"
        return port

    @staticmethod
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

    @staticmethod
    def _coerce_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _strip_quotes(value: str) -> str:
        if value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        return value

    @staticmethod
    def _to_cidr(ip_str: str, mask_str: str) -> str:
        network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
        return str(network)


def build_service_group_map(service_groups: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Convert parsed firewall_service_group list to {group_name: [members]} dict."""
    result: dict[str, list[str]] = {}
    for grp in service_groups or []:
        if not isinstance(grp, dict):
            continue
        name = (grp.get("name") or grp.get("_edit") or "").strip()
        if not name:
            continue
        members = grp.get("member", [])
        if isinstance(members, str):
            members = [members]
        result[name] = [str(m) for m in members if m]
    return result


def expand_service(service_name: str, service_groups: dict[str, list[str]]) -> list[str]:
    """Return group members if service is a group, else [service_name]."""
    if not service_name:
        return []
    if service_name in service_groups:
        return list(service_groups[service_name])
    return [service_name]


def expand_services(service_list: list[str] | str | None, service_groups: dict[str, list[str]]) -> list[str]:
    """Expand a list of services, recursively resolving group membership. Deduped."""
    if service_list is None:
        return []
    items = service_list if isinstance(service_list, list) else [service_list]
    seen: set[str] = set()
    result: list[str] = []
    stack = list(items)
    visited_groups: set[str] = set()
    while stack:
        svc = stack.pop(0)
        svc = str(svc).strip()
        if not svc or svc in seen:
            continue
        if svc in service_groups:
            if svc in visited_groups:
                continue
            visited_groups.add(svc)
            stack.extend(service_groups[svc])
            continue
        seen.add(svc)
        result.append(svc)
    return result
