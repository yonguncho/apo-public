"""장비 직접 수집 — FortiGate REST API로 config·통계·FQDN을 한 번에.

파일을 하나씩 올리는 대신, 등록된 장비(remediation과 같은 연결 정보)에
접속해 분석에 필요한 입력을 모두 읽어온다. 읽기 전용 동작이며, 쓰기는
전혀 하지 않는다(수집만 하면 read-only admin profile 토큰으로 충분).

오프라인 원칙: 이 기능은 *선택*이다. 파일 업로드 경로는 그대로 남으며,
망분리 환경에서는 여전히 export 파일 업로드로 동일하게 동작한다.

수집 항목:
  - configuration      GET monitor/system/config/backup?scope=global
  - policy 통계        GET monitor/firewall/policy      (bytes/last_used/…)
  - proxy 통계         GET monitor/firewall/proxy-policy
  - FQDN 해석 IP       GET monitor/firewall/address-fqdns
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import requests

from .remediation_service import _device_conn

_TIMEOUT = 30
# 업로드 경로에는 MAX_CONTENT_LENGTH 상한이 있는데 수집 경로에는 없었다.
# 같은 크기 기준을 적용한다(재비판 SUSPECT).
_MAX_CONFIG_BYTES = 50 * 1024 * 1024


def _get(ip, port, token, verify, path, params=None):
    url = f"https://{ip}:{port}/api/v2/{path}"
    headers = {"Authorization": f"Bearer {token}"}
    return requests.get(url, headers=headers, params=params or {},
                        verify=verify, timeout=_TIMEOUT)


def _epoch_to_date(val):
    """FortiGate last_used(epoch 초) -> 'YYYY-MM-DD'. 0/None은 미상."""
    try:
        n = int(val)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    try:
        return datetime.fromtimestamp(n, tz=timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return None


def _policy_stats_from_monitor(payload) -> dict:
    """monitor/firewall/policy 응답 -> {policy_id: {hit_count,last_used,...}}.

    응답 results는 리스트(dict) 형태. 필드명은 FortiOS 버전에 따라 조금씩
    다르므로 관대하게 집는다.
    """
    out: dict = {}
    results = (payload or {}).get("results")
    if isinstance(results, dict):
        results = list(results.values())
    for row in results or []:
        if not isinstance(row, dict):
            continue
        pid = row.get("policyid", row.get("policy_id", row.get("id")))
        if pid is None:
            continue
        hit = row.get("hit_count", row.get("hitcount"))
        last = (row.get("last_used") or row.get("last_hit")
                or row.get("last_session"))
        stats = {}
        if hit is not None:
            try:
                stats["hit_count"] = int(hit)
            except (TypeError, ValueError):
                stats["hit_count"] = None
        d = _epoch_to_date(last)
        if d:
            stats["last_used"] = d
        if stats:
            out[str(pid)] = stats
    return out


def _fqdn_map_from_monitor(payload) -> dict:
    """monitor/firewall/address-fqdns 응답 -> {fqdn(소문자): [ip,...]}."""
    out: dict = {}
    results = (payload or {}).get("results")
    if isinstance(results, dict):
        results = list(results.values())
    for row in results or []:
        if not isinstance(row, dict):
            continue
        name = (row.get("fqdn") or row.get("name") or "").lower().strip().strip(".")
        if not name:
            continue
        addrs = row.get("addrs") or row.get("addresses") or row.get("ipv4") or []
        if isinstance(addrs, str):
            addrs = [addrs]
        ips = []
        for a in addrs:
            if isinstance(a, dict):
                a = a.get("ip") or a.get("addr") or a.get("ipv4")
            a = str(a or "").strip()
            # 반드시 유효 IPv4여야 한다. 검증 없이 담으면 필드 변형 시
            # 'x'·'123456' 같은 잡값이 판정 입력으로 들어간다(재비판).
            try:
                parsed_ip = ipaddress.IPv4Address(a)
            except ipaddress.AddressValueError:
                continue
            if parsed_ip.is_unspecified or parsed_ip.is_loopback                     or parsed_ip.is_multicast:
                continue
            ips.append(str(parsed_ip))
        if ips:
            out.setdefault(name, [])
            for ip in ips:
                if ip not in out[name]:
                    out[name].append(ip)
    return {k: sorted(v) for k, v in out.items() if v}


def collect_from_device(device: dict) -> dict:
    """장비에서 config·통계·FQDN을 수집한다.

    반환: {"config_text": str, "runtime_stats": dict, "fqdn_map": dict,
           "warnings": [str]}  — config_text는 필수(없으면 예외).
    """
    ip, port, token, verify = _device_conn(device)
    if not token:
        raise ValueError("API token is required")
    warnings: list[str] = []

    # 1) configuration — 이게 없으면 분석 자체가 불가하므로 실패로 처리
    r = _get(ip, port, token, verify, "monitor/system/config/backup",
             {"scope": "global"})
    if r.status_code != 200 or not r.text.strip():
        raise ValueError(
            f"Config backup failed (HTTP {r.status_code}). The token needs "
            "read access to system configuration.")
    if len(r.content) > _MAX_CONFIG_BYTES:
        raise ValueError("Configuration backup exceeds the 50 MB limit.")
    config_text = r.text

    # 2) 정책 통계 (실패해도 config 분석은 가능 → 경고만)
    runtime_stats: dict = {}
    for path, label in (("monitor/firewall/policy", "policy"),
                        ("monitor/firewall/proxy-policy", "proxy-policy")):
        try:
            rr = _get(ip, port, token, verify, path)
            if rr.status_code == 200:
                runtime_stats.update(_policy_stats_from_monitor(rr.json()))
            else:
                warnings.append(f"{label} stats unavailable (HTTP {rr.status_code}) "
                                "— hit-count/last-used checks limited")
        except (requests.RequestException, ValueError):
            warnings.append(f"{label} stats could not be read")

    # 3) FQDN 해석 IP (선택)
    fqdn_map: dict = {}
    try:
        rf = _get(ip, port, token, verify, "monitor/firewall/address-fqdns")
        if rf.status_code == 200:
            fqdn_map = _fqdn_map_from_monitor(rf.json())
        else:
            warnings.append(f"FQDN resolutions unavailable (HTTP {rf.status_code})")
    except (requests.RequestException, ValueError):
        warnings.append("FQDN resolutions could not be read")

    return {
        "config_text": config_text,
        "runtime_stats": runtime_stats,
        "fqdn_map": fqdn_map,
        "warnings": warnings,
    }
