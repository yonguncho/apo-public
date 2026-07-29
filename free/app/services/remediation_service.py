"""
remediation_service.py
Critical/High 정책 비활성화 후보 수집, FortiGate REST API 적용,
Postman Collection JSON 및 CSV 내보내기를 담당한다.
"""
from __future__ import annotations
import csv
import io
import ipaddress
import json
import re
import socket
from datetime import date
from urllib.parse import quote

import requests

from app.services.workbook_exporter import is_formula_like

# urgency 1 = Critical / urgency 2 = High (severity_engine.py 기준)
_DISABLE_URGENCIES = {1, 2}

# 장비 주소로 허용할 형태: IPv4/IPv6 리터럴 또는 호스트명.
# 검증 없이 f-string에 넣으면 "real.fw.local@evil.example" 같은 userinfo 형태로
# 관리자 토큰이 제3의 호스트로 전송된다(표시상으로는 정상 장비처럼 보인다).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def validate_device_address(ip: str) -> str:
    """장비 주소를 검증해 URL에 넣어도 안전한 형태로 반환한다.

    부적합하면 ValueError. IPv6는 URL에서 대괄호로 감싸야 하므로 그렇게 반환한다.
    """
    addr = (ip or "").strip()
    if not addr:
        raise ValueError("Device address is required")

    try:
        parsed = ipaddress.ip_address(addr.strip("[]"))
        return f"[{parsed}]" if parsed.version == 6 else str(parsed)
    except ValueError:
        pass

    if not _HOSTNAME_RE.match(addr):
        raise ValueError("Device address must be an IP address or hostname")
    return addr


def _device_conn(device: dict) -> tuple:
    """(host, port, token, verify) 를 검증된 형태로 반환."""
    host = validate_device_address(device.get("ip", ""))
    port = int(device.get("port", 443))
    token = device.get("token", "")
    # 기본값을 True로 둔다. 방화벽 관리자 토큰이 오가는 채널이라 검증을 끄면
    # 관리망에 MITM 위치를 잡은 공격자가 토큰을 그대로 가져갈 수 있다.
    verify = bool(device.get("verify_ssl", True))
    return host, port, token, verify


def get_candidates(parsed: dict, severity_results: dict) -> dict:
    """
    비활성화 후보 목록을 두 카테고리로 반환한다.
    to_disable   : severity Critical/High이면서 현재 enable 상태인 정책
    already_disabled: config에서 이미 disable된 정책
    """
    to_disable: list[dict] = []
    already_disabled: list[dict] = []

    for ptype, key in (("firewall", "firewall"), ("proxy", "proxy")):
        for p in severity_results.get(ptype, []):
            pid   = str(p.get("policy_id") or p.get("id") or p.get("_edit") or "").strip()
            name  = p.get("name", "")
            urgency = p.get("urgency")
            risk  = p.get("risk_level", "")
            rec   = p.get("recommended_action", "")
            reason = p.get("reason", "")
            status = str(p.get("status", "enable")).lower()

            if not pid:
                continue

            base = {
                "policy_id": pid,
                "name":      name,
                "type":      ptype,
                "srcaddr":   _fmt_list(p.get("srcaddr_display") or p.get("srcaddr")),
                "dstaddr":   _fmt_list(p.get("dstaddr_display") or p.get("dstaddr")),
                "service":   _fmt_list(p.get("service_display") or p.get("service")),
                "schedule":  p.get("schedule", ""),
                "risk_level": risk,
                "urgency":   urgency,
                "recommended_action": rec,
                "reason":    reason,
            }

            if urgency not in _DISABLE_URGENCIES:
                continue  # Critical/High 외 제외
            if status in ("disable", "disabled"):
                already_disabled.append({**base, "category": "Already Disabled"})
            else:
                to_disable.append({**base, "category": "Disable Candidate"})

    # urgency 순(1→2) → policy_id 숫자 순 정렬 (문자열 정렬 시 "10" < "2" 문제 방지)
    def _pid_key(x) -> int:
        pid = str(x.get("policy_id", ""))
        return int(pid) if pid.isdigit() else 10**9

    to_disable.sort(key=lambda x: (x.get("urgency", 9), _pid_key(x)))
    already_disabled.sort(key=_pid_key)
    return {"to_disable": to_disable, "already_disabled": already_disabled}


def _fmt_list(val) -> str:
    if isinstance(val, list):
        return ", ".join(str(v) for v in val)
    return str(val or "")


# ── FortiGate API ──────────────────────────────────────────────────────────

def _get_source_ip(target_ip: str, port: int) -> str:
    """OS 라우팅 테이블 기준으로 target에 도달할 때 사용될 로컬 NIC IP를 반환한다."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, port))
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        if s is not None:
            s.close()


def test_connection(device: dict) -> dict:
    """FortiGate REST API 연결 테스트. {"ok": bool, "message": str, "source_ip": str} 반환."""
    try:
        ip, port, token, verify = _device_conn(device)
    except ValueError as exc:
        return {"ok": False, "message": str(exc), "source_ip": None}

    source_ip = _get_source_ip(ip, port)
    src_note  = f" | Your IP → FortiGate: {source_ip}" if source_ip and source_ip != "127.0.0.1" else ""

    url = f"https://{ip}:{port}/api/v2/monitor/system/status"
    try:
        r = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            verify=verify,
            timeout=6,
        )
        if r.status_code == 200:
            res = r.json().get("results", {})
            hostname = res.get("hostname") or res.get("Hostname") or "FortiGate"
            version  = res.get("version")  or res.get("Version")  or ""
            return {"ok": True,  "message": f"Connected — {hostname} ({version}){src_note}", "source_ip": source_ip}
        if r.status_code == 401:
            return {"ok": False, "message": f"Authentication failed — check API token{src_note}", "source_ip": source_ip}
        return {"ok": False, "message": f"HTTP {r.status_code}: {r.text[:100]}{src_note}", "source_ip": source_ip}
    except requests.exceptions.SSLError:
        return {"ok": False, "message": f"SSL certificate error — enable 'Skip SSL Verify'{src_note}", "source_ip": source_ip}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "message": f"Connection refused — check IP/port ({ip}:{port}){src_note}", "source_ip": source_ip}
    except Exception as exc:
        return {"ok": False, "message": f"{str(exc)[:100]}{src_note}", "source_ip": source_ip}


def disable_policies(device: dict, policies: list[dict]) -> list[dict]:
    """
    선택된 정책 목록을 FortiGate REST API로 비활성화한다.
    각 정책에 대해 {"policy_id", "name", "ok", "message"} 반환.
    """
    try:
        ip, port, token, verify = _device_conn(device)
    except ValueError as exc:
        return [{"policy_id": str(p.get("policy_id", "")), "name": p.get("name", ""),
                 "ok": False, "message": str(exc)} for p in policies]
    vdom = device.get("vdom", "root")

    results: list[dict] = []
    for p in policies:
        pid    = str(p.get("policy_id", ""))
        ptype  = p.get("type", "firewall")
        ep     = "firewall/policy" if ptype == "firewall" else "firewall/proxy-policy"
        # policy_id는 숫자만 허용한다. 검증 없이 URL에 넣으면 "../../monitor/
        # system/os/reboot" 같은 값으로 관리자 토큰을 단 채 다른 엔드포인트를
        # 호출할 수 있다(requests가 경로의 .. 를 정규화해 실제로 도달한다).
        if not pid.isdigit():
            results.append({"policy_id": pid, "name": p.get("name", ""),
                            "ok": False, "message": "Invalid policy id"})
            continue
        url = (f"https://{ip}:{port}/api/v2/cmdb/{ep}/{quote(pid, safe='')}"
               f"?vdom={quote(str(vdom), safe='')}")
        try:
            r = requests.put(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type":  "application/json",
                },
                json={"status": "disable"},
                verify=verify,
                timeout=10,
            )
            if r.status_code in (200, 201):
                results.append({"policy_id": pid, "name": p.get("name",""), "ok": True,  "message": "Disabled successfully"})
            else:
                results.append({"policy_id": pid, "name": p.get("name",""), "ok": False, "message": f"HTTP {r.status_code}: {r.text[:80]}"})
        except Exception as exc:
            results.append({"policy_id": pid, "name": p.get("name",""), "ok": False, "message": str(exc)[:80]})

    return results


# ── 내보내기 ───────────────────────────────────────────────────────────────

def export_postman(policies: list[dict], device: dict) -> str:
    """Postman Collection v2.1 JSON 문자열 반환."""
    ip    = device.get("ip", "")
    port  = int(device.get("port", 443))
    vdom  = device.get("vdom", "root")
    today = date.today().isoformat()

    # API 토큰은 파일에 쓰지 않는다. 이 컬렉션은 사용자가 이메일로 주고받거나
    # 저장소에 커밋하는 일이 잦은데, 평문 토큰이 들어 있으면 방화벽 관리자
    # 권한이 그대로 유출된다. Postman 변수로 남겨 사용자가 직접 채우게 한다.
    token_ref = "{{fortigate_token}}"

    items = []
    for p in policies:
        pid   = str(p.get("policy_id", ""))
        name  = p.get("name", pid)
        risk  = p.get("risk_level", "")
        ptype = p.get("type", "firewall")
        ep    = "firewall/policy" if ptype == "firewall" else "firewall/proxy-policy"
        raw_url = f"https://{ip}:{port}/api/v2/cmdb/{ep}/{pid}?vdom={vdom}"

        items.append({
            "name": f"[{risk}] Disable Policy {pid} — {name}",
            "request": {
                "method": "PUT",
                "header": [
                    {"key": "Authorization", "value": f"Bearer {token_ref}", "type": "text"},
                    {"key": "Content-Type",  "value": "application/json",  "type": "text"},
                ],
                "url": {
                    "raw":      raw_url,
                    "protocol": "https",
                    "host":     [ip],
                    "port":     str(port),
                    "path":     ["api", "v2", "cmdb"] + ep.split("/") + [pid],
                    "query":    [{"key": "vdom", "value": vdom}],
                },
                "body": {
                    "mode": "raw",
                    "raw": json.dumps({"status": "disable"}, indent=2),
                    "options": {"raw": {"language": "json"}},
                },
                "description": f"Reason: {p.get('reason','')} | Src: {p.get('srcintf','')} -> Dst: {p.get('dstintf','')}",
            },
            "response": [],
        })

    collection = {
        "info": {
            "name":          f"APO Remediation — Disable Policies ({today})",
            "_postman_id":   f"apo-remediation-{today}",
            "description":   (
                f"APO가 생성한 정책 비활성화 컬렉션\n"
                f"대상 장비: {ip}:{port}\n정책 수: {len(policies)}건\n\n"
                "실행 전 collection variable 'fortigate_token'에 API 토큰을 입력하세요. "
                "보안상 토큰은 이 파일에 저장하지 않습니다."
            ),
            "schema":        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [
            {"key": "base_url",        "value": f"https://{ip}:{port}"},
            {"key": "vdom",            "value": vdom},
            {"key": "fortigate_token", "value": "", "type": "secret"},
        ],
        "item": items,
    }
    return json.dumps(collection, ensure_ascii=False, indent=2)


def _csv_safe(value) -> str:
    """CSV 수식 인젝션 방어.

    정책명·사유 등은 분석 대상 config에서 온 값이라 신뢰할 수 없다. Excel은
    CSV를 열 때 =, +, -, @ 로 시작하는 셀을 수식으로 해석하므로, 그대로 쓰면
    리포트를 여는 담당자 PC에서 DDE 실행이나 데이터 유출이 일어날 수 있다.
    xlsx와 달리 CSV에는 셀 타입 개념이 없어 아포스트로피 접두로 무력화한다.
    """
    s = "" if value is None else str(value)
    return "'" + s if is_formula_like(s) else s


def export_csv(to_disable: list[dict], already_disabled: list[dict]) -> bytes:
    """UTF-8 BOM CSV 바이트 반환 (Excel 한글 호환)."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Category", "Policy ID", "Policy Name",
        "Risk Level", "Source IP", "Destination IP",
        "Service", "Schedule", "Reason",
    ])

    def row(category: str, p: dict) -> list:
        return [category] + [
            _csv_safe(p.get(f, ""))
            for f in ("policy_id", "name", "risk_level", "srcaddr",
                      "dstaddr", "service", "schedule", "reason")
        ]

    for p in to_disable:
        writer.writerow(row("Disable Candidate", p))

    for p in already_disabled:
        writer.writerow(row("Already Disabled", p))

    return ("﻿" + output.getvalue()).encode("utf-8")
