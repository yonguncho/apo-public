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


def _is_link_local(parsed) -> bool:
    """링크로컬인가 — IPv6 래핑 우회까지 본다.

    ipaddress는 '::ffff:169.254.169.254'.is_link_local을 False로 준다.
    169.254.169.254는 클라우드 메타데이터 SSRF의 표준 표적이므로, IPv4-mapped·
    6to4·Teredo로 감싼 형태도 같은 주소로 취급해 막는다(재비판 NEW-BUG).
    """
    if parsed.is_link_local:
        return True
    if parsed.version != 6:
        return False
    for attr in ("ipv4_mapped", "sixtofour", "teredo"):
        val = getattr(parsed, attr, None)
        if val is None:
            continue
        for cand in (val if isinstance(val, tuple) else (val,)):
            if cand is not None and cand.is_link_local:
                return True
    return False


def validate_device_address(ip: str) -> str:
    """장비 주소를 검증해 URL에 넣어도 안전한 형태로 반환한다.

    부적합하면 ValueError. IPv6는 URL에서 대괄호로 감싸야 하므로 그렇게 반환한다.
    """
    addr = (ip or "").strip()
    if not addr:
        raise ValueError("Device address is required")

    parsed = None
    try:
        parsed = ipaddress.ip_address(addr.strip("[]"))
    except ValueError:
        parsed = None

    if parsed is not None:
        if _is_link_local(parsed):
            raise ValueError("Link-local addresses are not allowed as a "
                             "device address")
        return f"[{parsed}]" if parsed.version == 6 else str(parsed)


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


def tls_fingerprint(host: str, port: int, timeout: float = 6.0) -> str:
    """이 주소가 지금 내미는 인증서의 SHA-256 지문(hex). 못 얻으면 "".

    **왜 검증을 끈 채로도 지문은 봐야 하는가** (B-79).
    FortiGate 는 대부분 자체 서명 인증서를 쓴다 — 화면의 'Skip SSL Verify'
    가 사실상 정상 경로다. 그 상태에서 read-only 관리자 Bearer 토큰이
    검증 없는 채널로 나가므로, 관리망에 자리를 잡은 공격자가 토큰을 그대로
    가져갈 수 있다. 그렇다고 검증을 강제하면 자체 서명 장비에서 수집·조치가
    통째로 안 된다.

    그래서 SSH 가 쓰는 길을 쓴다(TOFU): **처음 본 지문을 이 장비의 것으로
    고정하고, 다음부터 달라지면 막는다.** 첫 연결의 MITM 은 못 잡지만,
    그 뒤의 인증서 교체는 전부 잡힌다 — 지금은 아무것도 못 잡는다.
    시리얼 pin(remediation_serial)과 같은 모양이라 화면 동선도 같다.

    검증을 켠 장비에는 쓰지 않는다 — 거기서는 CA 가 이미 답을 준다.
    """
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # **여기서는 일부러 검증하지 않는다.** 목적이 '누구인지 판정'이 아니라
    # '무엇을 내밀었는지 기록'이다 — 자체 서명이라 검증하면 아무것도 못 본다.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        if not der:
            return ""
        import hashlib
        return hashlib.sha256(der).hexdigest()
    except Exception:
        # 연결 실패는 여기서 판정하지 않는다 — 본 요청이 같은 이유로 실패하며
        # 사용자에게 훨씬 정확한 사유를 준다. 지문만 '모름'으로 돌려준다.
        return ""


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
                # **VDOM 은 정책 번호의 일부다.** 워크북 각주는 "다중 VDOM 에서는
                # 정책의 VDOM 을 먼저 지정하라"고 하면서 **어느 VDOM 인지는
                # 어디에도 안 적었다** — 조치 계획에 1번이 두 줄 나오는데
                # root 의 ANY-ANY-PERMIT 인지 dmz 의 운영 정책인지 알 수 없다
                # (라운드 47 실측). API 쓰기는 막혀 있고 수동 적용에 쓰는 문서가
                # 바로 이것이다.
                "vdom":      p.get("vdom") or "",
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

    def _ask(params=None):
        return requests.get(url, headers={"Authorization": f"Bearer {token}"},
                            verify=verify, timeout=6, params=params)

    def _serial_of(payload, res):
        # **시리얼은 results 안이 아니라 응답 봉투 최상위에 실리는 게
        # FortiOS 표준이다.** results 만 보던 동안 vdom 모드 장비(OA 실장비
        # 2026-08-23)에서 "시리얼을 알려주지 않는다"로 떨어져, 조치 적용의
        # 신원 고정(pin)이 시작조차 못 했다. 두 자리 모두 본다.
        s = res.get("serial") or res.get("Serial") or ""
        if not s and isinstance(payload, dict):
            s = payload.get("serial") or ""
        return str(s).strip()

    try:
        r = _ask()
        if r.status_code == 200:
            payload = r.json()
            res = payload.get("results", {})
            if not isinstance(res, dict):
                res = {}
            hostname = res.get("hostname") or res.get("Hostname") or "FortiGate"
            version  = (res.get("version") or res.get("Version")
                        or payload.get("version") or "")
            # hostname 을 **값으로도** 돌려준다. 서버가 '지금 열어 둔 설정의
            # 장비'와 대조해야 하는데, 문장에만 섞어 두면 다시 정규식으로 뜯어야
            # 하고, 이 제품에서 그렇게 하다 깨진 자리가 이미 있다.
            # **시리얼도 값으로 돌려준다.** hostname 은 두 고객이 같은 이름을
            # 쓰는 일이 오히려 정상이라(FGT-HQ, fw01) 신원 증명이 못 된다.
            # 시리얼은 장비마다 고유하므로, 서버가 이 장비의 신원으로 고정해
            # 두고 다음 연결부터 대조한다 — 이름으로는 영영 못 하던 일이다.
            serial = _serial_of(payload, res)
            # **"장비가 시리얼을 안 준다"와 "이번에 못 읽었다"는 다른 사실이다.**
            # 둘 다 serial="" 로 뭉개면, 신원 대화상자가 "지금도 다음에도 없다"
            # 고 단정한다 — 재시도가 순간 장애로 실패한 것뿐이었다면 거짓이고,
            # 사용자는 매번 수동 확인을 영구 부담으로 받아들인다(R75-1).
            #   answered = 장비가 실제로 답했고 그 답에 시리얼이 없다
            #   failed   = 조회가 끝나지 못했다 → 시리얼 유무는 미상
            serial_probe = "answered"
            if not serial:
                # vdom 모드 장비는 무스코프 monitor 가 빈 results 를 줄 수
                # 있다(OA 실측 — v108 수집 경로와 같은 병리). 등록 VDOM
                # (없으면 root) 스코프로 한 번 더 물어본다.
                _vd = str((device or {}).get("vdom") or "").strip() or "root"
                # 재시도의 순간 장애가 바깥 except 로 빠지면, 첫 요청이 200
                # 으로 이미 증명한 연결이 "Connection refused" 로 둔갑한다
                # (라운드 74). 재시도 실패는 재시도 포기일 뿐 — 연결 성공 +
                # 시리얼 미상(v109 계약)으로 돌아간다.
                try:
                    r2 = _ask({"vdom": _vd})
                except requests.exceptions.RequestException:
                    r2 = None
                if r2 is None or r2.status_code != 200:
                    # 첫 응답(무스코프 200·빈 results)은 vdom 모드에서 부재의
                    # 증거가 못 된다 — 그래서 이 재시도가 있는 것이다. 재시도가
                    # 끝나지 못했으면 부재도 확인되지 않은 것이다.
                    serial_probe = "failed"
                else:
                    try:
                        p2 = r2.json()
                    except ValueError:
                        p2 = {}
                        serial_probe = "failed"
                    res2 = p2.get("results", {}) if isinstance(p2, dict) else {}
                    if not isinstance(res2, dict):
                        res2 = {}
                    s2 = _serial_of(p2, res2)
                    if s2:
                        serial = s2
                        serial_probe = "answered"
                        hostname = (res2.get("hostname")
                                    or res2.get("Hostname") or hostname)
                        version = (res2.get("version") or res2.get("Version")
                                   or p2.get("version") or version)
            return {"ok": True, "hostname": hostname, "fw_version": version,
                    "serial": serial, "serial_probe": serial_probe,
                    # 검증을 끈 장비에서만 지문을 본다(B-79). 검증을 켰으면
                    # CA 가 이미 답을 줬고, 여기서 또 재면 의미 없이 연결이
                    # 한 번 더 난다.
                    "tls_fingerprint": ("" if verify
                                        else tls_fingerprint(ip, port)),
                    "tls_verified": bool(verify),
                    "message": f"Connected — {hostname} ({version}){src_note}",
                    "source_ip": source_ip}
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
                # 후보 dict 는 srcintf/dstintf 를 담지 않는다(base 는 srcaddr/
                # dstaddr/vdom 만 든다). 예전 키를 읽어 설명이 늘 "Src:  -> Dst: "
                # 로 비어 나갔다 — 운영자가 어떤 정책인지 대조할 단서가 사라졌다.
                # 주소 스코프로 채우고, 정책의 VDOM 이 있으면 함께 밝힌다
                # (device 연결 vdom 이 아니라 정책별 vdom — 같은 번호 구별용).
                "description": (
                    (f"[VDOM {p.get('vdom')}] " if p.get("vdom") else "")
                    + f"Reason: {p.get('reason','')} | "
                    + f"Src: {p.get('srcaddr','')} -> Dst: {p.get('dstaddr','')}"),
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
    # 정책 종류를 반드시 적는다. 이 CSV는 운영자가 손으로 실행하는 변경 문서인데,
    # FortiGate는 firewall과 proxy 정책에 각각 1번부터 번호를 매긴다. 종류가 없으면
    # proxy 12번 행을 보고 `config firewall policy / edit 12`를 쳐서 **무관한 살아
    # 있는 정책**을 끄게 된다(실 config에서 fw/proxy ID 충돌 44건 관측).
    # **VDOM 도 정책 번호의 일부다.** 후보 레코드는 이미 `vdom` 을 들고 있고
    # 워크북은 CLI 앞에 `config vdom / edit <이름>` 을 붙이는데, 이 CSV 에는
    # 열조차 없었다 — 운영자가 관리 VDOM(기본 root)에 앉은 채
    # `config firewall policy` → `edit 12` 를 치면 root 의 12번(무관한 살아
    # 있는 정책)을 끄거나, 없으면 FortiOS 가 12번을 **새로 만들고** 정작
    # 끄려던 정책은 그대로 남는다. 파일에 VDOM 이 없으니 나중에 복구할 단서도
    # 없다(라운드 48 실측). 바로 위 주석이 fw/proxy 에 대해 말하는 사고와
    # 같은 사고다 — 종류만 고치고 VDOM 은 남겨 뒀다.
    writer.writerow([
        "Category", "Policy Type", "VDOM", "Policy ID", "Policy Name",
        "Risk Level", "Source IP", "Destination IP",
        "Service", "Schedule", "Reason", "CLI Context",
    ])

    def row(category: str, p: dict) -> list:
        ptype = "proxy" if str(p.get("type", "")).strip().lower() == "proxy" else "firewall"
        vdom = str(p.get("vdom") or "").strip()
        cli_ctx = ("config firewall proxy-policy" if ptype == "proxy"
                   else "config firewall policy")
        if vdom:
            cli_ctx = f"config vdom / edit {vdom} / {cli_ctx}"
        return [category, ptype, _csv_safe(vdom)] + [
            _csv_safe(p.get(f, ""))
            for f in ("policy_id", "name", "risk_level", "srcaddr",
                      "dstaddr", "service", "schedule", "reason")
        ] + [_csv_safe(cli_ctx)]

    for p in to_disable:
        writer.writerow(row("Disable Candidate", p))

    for p in already_disabled:
        writer.writerow(row("Already Disabled", p))

    return ("﻿" + output.getvalue()).encode("utf-8")


def export_apply_results(results: list[dict], meta: dict) -> bytes:
    """적용 결과 CSV. **되돌릴 수 없는 쓰기의 기록이 화면에만 있었다.**

    조치 적용 결과는 DOM 에만 렌더되고 새로고침하면 사라졌다 — 감사에서
    가장 먼저 요구하는 산출물인데 남기는 방법이 없었다(2026-08-25 Jayden).

    화면 표에 없던 두 가지를 함께 적는다:
      · 언제 — 파일만 보고는 언제 나간 변경인지 알 수 없다
      · 어느 장비 — hostname 은 두 고객이 같은 이름을 쓰는 일이 정상이라
        신원 증명이 못 된다(라운드 29·30). 시리얼이 이 장비의 신원이다.
    머리말을 주석행(#)으로 얹는다 — Excel 이 열 때 방해가 없고, 표 부분만
    잘라 쓰는 사람에게도 본문은 그대로 CSV 다.
    """
    output = io.StringIO()
    for label, key in (("Applied at", "applied_at"),
                       ("Device", "device"),
                       ("Device serial", "serial"),
                       ("Device address", "ip")):
        val = str(meta.get(key) or "").strip()
        # 시리얼을 못 읽었으면 빈칸이 아니라 그 사실을 적는다 — 빈칸은
        # "안 적었다"와 "확인 못 했다"를 구별하지 못한다(R75-1 과 같은 규칙).
        if not val and key == "serial":
            val = "not reported"
        if val:
            output.write(f"# {label}: {_csv_safe(val)}\n")

    writer = csv.writer(output)
    writer.writerow(["Result", "Policy Type", "VDOM", "Policy ID",
                     "Policy Name", "Message"])
    for r in results or []:
        ptype = ("proxy" if str(r.get("type", "")).strip().lower() == "proxy"
                 else "firewall")
        writer.writerow([
            "OK" if r.get("ok") else "FAILED",
            ptype,
            _csv_safe(r.get("vdom", "")),
            _csv_safe(r.get("policy_id", "")),
            _csv_safe(r.get("name", "")),
            _csv_safe(r.get("message", "")),
        ])
    return ("﻿" + output.getvalue()).encode("utf-8")
