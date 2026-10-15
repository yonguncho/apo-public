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


def _monitor_rows(payload) -> list:
    """monitor 응답의 results 를 리스트로 정규화(원시 행 수 계산용)."""
    results = (payload or {}).get("results")
    if isinstance(results, dict):
        results = list(results.values())
    return results if isinstance(results, list) else []


def _paged_monitor(ip, port, token, verify, path, params, parse) -> tuple:
    """monitor 응답의 **페이지 절단**을 방어하며 전부 수집한다.

    OA 실장비 실측(2026-08-19): 정책 1750개 장비에서 monitor/firewall/policy
    가 993행만 반환(1000 부근) — 절단된 나머지 정책은 '사용량 미상'으로
    남아, 확인된-0회(hit=0)로만 성립하는 Critical 판정이 파일 CSV 경로
    (전 정책 수록)와 갈렸다(수집 Critical 4 vs 파일 20).

    첫 요청은 **오늘과 똑같이** 파라미터 그대로 보낸다(페이지 파라미터를
    거부하는 버전 방어). 행이 있었으면 start/count 를 붙여 이어서 요청하고,
    다음 중 하나면 멈춘다 — 비-200 / 빈 페이지 / **직전 페이지와 원시 행
    동일**(start 를 무시하고 같은 행을 반복하는 버전은 이 조건이 1회 만에
    끊는다. 같은 키의 중복은 dict 병합이라 무해). 페이지 상한 20 은
    무한루프 방어다.

    반환: (첫 요청의 status_code, 병합된 dict). parse 는 payload → dict
    (pid→stats 또는 fqdn→ips)여야 한다. JSON 이 아니면 ValueError 가
    호출부로 전파된다(오늘과 같은 처리).
    """
    def _sig(rows):
        # start 무시 판별용 원시 행 서명. **파싱 결과(신규 키)로 판단하면
        # 안 된다** — 파서는 통계 없는 행을 버리므로, 한 페이지 전체가
        # 무통계 행이면 '신규 없음'으로 오인해 조기중단하고 이후 페이지를
        # 잃는다(게이트 correctness critical — 993/1750 절단의 재발 경로).
        return (len(rows), repr(rows[0]), repr(rows[-1]))

    r = _get(ip, port, token, verify, path, params)
    if r.status_code != 200:
        return r.status_code, {}
    payload = r.json()
    out = dict(parse(payload))
    rows = _monitor_rows(payload)
    raw_seen = len(rows)
    if raw_seen:
        sig_prev = _sig(rows)
        for _ in range(20):
            p = dict(params or {})
            p["start"] = raw_seen
            p["count"] = 1000
            # **후속 페이지의 실패는 이미 받은 페이지를 지킨다**(라운드 70,
            # 계약·경계값·동적실행 3렌즈 교차 발견). 여기서 예외를 전파하면
            # 1페이지 1000행까지 통째로 버려져 '사용량 미상'이 된다 — v106
            # 의 단일 요청에는 없던 유실 모드다. 첫 요청의 비-JSON 은 위에서
            # 기존과 동일하게 전파된다(구버전 오류 문구 계약 유지).
            try:
                r2 = _get(ip, port, token, verify, path, p)
            except requests.RequestException:
                break
            if r2.status_code != 200:
                break
            try:
                payload2 = r2.json()
            except ValueError:
                break
            rows2 = _monitor_rows(payload2)
            if not rows2:
                break
            sig2 = _sig(rows2)
            if sig2 == sig_prev:
                break
            out.update(parse(payload2))
            raw_seen += len(rows2)
            sig_prev = sig2
    return 200, out


def _looks_valid_ipv4(text: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError:
        return False
    return not (ip.is_unspecified or ip.is_loopback or ip.is_multicast)


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
        if isinstance(addrs, (str, bytes)):
            addrs = [addrs]
        elif isinstance(addrs, dict):
            addrs = list(addrs.values())
        elif not isinstance(addrs, (list, tuple, set)):
            continue        # 숫자 등 비-이터러블 → 이 항목 건너뜀(500 방지)
        ips = []
        for a in addrs:
            if isinstance(a, dict):
                # or 체인으로 첫 키만 보면 "ip":"0.0.0.0" 때문에 유효한
                # 형제 값을 버린다. 후보를 전부 시도한다(재비판 PASS 잔여점).
                cands = [a.get(k) for k in ("ip", "addr", "ipv4")]
            else:
                cands = [a]
            a = next((str(x).strip() for x in cands
                      if x is not None and _looks_valid_ipv4(str(x).strip())), "")
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


# 후보 엔드포인트를 두드려 **응답 형태만** 확인하는 진단.
#
# ISDB·geography는 오프라인 config만으로 환원할 수 없어 도달불가 검사에서
# 건너뛴다. REST로 가져올 수 있을 법하지만, v85에서 `dnsproxy 6` 출력 형식을
# 추정해 파서를 만들었다가 첫 실사용에서 통째로 깨진 적이 있다. 그래서 이번엔
# **실물 응답을 보기 전에는 파서를 만들지 않는다**. 이 함수는 어떤 경로가
# 200을 주고 어떤 모양인지만 보고한다.
_PROBE_PATHS = [
    # ISDB — 목록부터. 여기서 얻은 실제 id로 2단계에서 상세를 조회한다.
    ("cmdb/firewall/internet-service", None),
    ("cmdb/firewall/internet-service-name", None),
    ("monitor/firewall/internet-service-basic", None),
    # geography
    ("cmdb/firewall/address?filter=type==geography", None),
    # 참고용 — 이미 쓰는 경로가 이 장비에서도 되는지 대조
    ("monitor/firewall/address-fqdns", None),
    # 사용량 통계 — OA 실장비에서 수집 경로만 판정에 사용량이 반영되지 않는
    # 증상(파일 CSV 추가 시 동일해짐)이 보고됐다. 이 FortiOS 버전의 응답에
    # hit_count/last_used 필드가 실제로 있는지(키 구성 요약) 실물로 확인한다
    # (2026-08-19 실장비 대조 — v85 원칙: 실물 없이 파서를 고치지 않는다).
    ("monitor/firewall/policy", None),
    ("monitor/firewall/proxy-policy", None),
]

# 파라미터가 필요해 424(Failed Dependency)로 떨어진 경로들.
# 1단계에서 얻은 실제 ISDB id를 넣어 다시 시도한다.
_PROBE_WITH_ID = [
    "monitor/firewall/internet-service-details",
]
# IP 하나를 ISDB에 대조해 보는 경로 — 문서용 예시 IP를 쓴다(RFC 5737).
_PROBE_WITH_IP = [
    ("monitor/firewall/internet-service-match", {"ip": "8.8.8.8"}),
]


def _shape(payload, depth=0):
    """응답을 통째로 붙여넣게 하지 않기 위해 '형태'만 요약한다.

    파서를 쓰려면 필요한 건 원문 전체가 아니라 키 구성과 대표 레코드다.
    수십 MB짜리 ISDB 목록을 사람에게 복사시키는 건 말이 안 된다.
    """
    if isinstance(payload, dict):
        out = {}
        for k, v in list(payload.items())[:14]:
            out[k] = _shape(v, depth + 1) if depth < 3 else type(v).__name__
        return out
    if isinstance(payload, list):
        if not payload:
            return "[] (empty)"
        return {"__list_len__": len(payload),
                "__first__": _shape(payload[0], depth + 1) if depth < 3 else type(payload[0]).__name__}
    if isinstance(payload, str):
        return payload[:60] + ("…" if len(payload) > 60 else "")
    return payload


def _first_isdb_id(payload):
    """ISDB 목록 응답에서 id 하나를 꺼낸다(2단계 조회용)."""
    try:
        rows = payload.get("results") if isinstance(payload, dict) else payload
        if isinstance(rows, dict):
            rows = list(rows.values())
        for row in (rows or [])[:50]:
            if isinstance(row, dict):
                for key in ("id", "internet-service-id", "entry-id", "q_ref"):
                    if isinstance(row.get(key), int):
                        return row[key]
    except Exception:
        pass
    return None


def probe_endpoints(device: dict) -> list[dict]:
    """후보 REST 경로를 두드려 **형태만** 보고한다. 파싱하지 않는다.

    2단계로 돈다:
      1) 파라미터 없이 되는 경로들 — ISDB 목록·geography·FQDN
      2) 1단계에서 얻은 실제 ISDB id로, 파라미터가 필요해 424로 떨어지던
         상세 조회를 다시 시도

    응답 전체가 아니라 키 구성과 대표 레코드만 돌려준다. ISDB 목록은 수만
    건이라 원문을 사람에게 복사시킬 수 없다.
    """
    ip, port, token, verify = _device_conn(device)
    out = []
    isdb_id = None

    def _call(path, params=None, label=None):
        nonlocal isdb_id
        row = {"path": label or path}
        if params:
            row["params"] = params
        try:
            r = _get(ip, port, token, verify, path, params)
            row["status"] = r.status_code
            body = r.text or ""
            row["bytes"] = len(body)
            if r.status_code == 200:
                try:
                    payload = r.json()
                    row["shape"] = _shape(payload)
                    if isdb_id is None:
                        isdb_id = _first_isdb_id(payload)
                except ValueError:
                    row["shape"] = "(JSON 아님)"
                    row["sample"] = body[:300]
            else:
                # 오류 본문에 '무엇이 빠졌는지'가 들어 있는 경우가 많다
                row["sample"] = body[:300]
        except Exception as exc:
            row["status"] = None
            row["error"] = f"{type(exc).__name__}: {exc}"[:200]
        out.append(row)

    for path, params in _PROBE_PATHS:
        _call(path, params)

    # monitor 3종은 **스코프를 붙인 변형도** 두드린다 — vdom 모드 장비는
    # 미범위 호출이 빈 결과라 무스코프 probe 만으로는 실물 형태(행 수·
    # total 유무·페이지 절단 여부)를 볼 수 없다(OA 실장비 2026-08-19).
    # start/count 를 함께 보내 이 버전이 페이지 파라미터를 받는지도 본다.
    _scope = str((device or {}).get("vdom") or "").strip() or "root"
    for path in ("monitor/firewall/policy", "monitor/firewall/proxy-policy",
                 "monitor/firewall/address-fqdns"):
        _call(path, {"vdom": _scope, "start": 0, "count": 1000},
              label=f"{path}?vdom={_scope}&start=0&count=1000")

    # 2단계 — 실제 id가 있어야 의미가 있는 조회
    for path in _PROBE_WITH_ID:
        if isdb_id is None:
            out.append({"path": path, "status": "skipped",
                        "sample": "1단계에서 ISDB id를 얻지 못해 건너뜀"})
            continue
        _call(path, {"id": isdb_id}, label=f"{path}?id={isdb_id}")

    for path, params in _PROBE_WITH_IP:
        _call(path, params, label=f"{path}?ip={params.get('ip')}")

    return out


def fetch_fqdn_map(device: dict, scope_vdom: str = "",
                   allow_unscoped_fallback: bool = True) -> dict:
    """FQDN 해석만 조회한다 — config는 이미 있고 FQDN만 필요할 때.

    파일 업로드로 분석 중이어도 장비가 등록돼 있으면 덤프를 뜰 필요 없이
    이 경로로 최신 해석을 가져온다.

    scope_vdom: vdom 모드 장비면 그 VDOM 으로 스코프를 지정한다 — 미범위
    호출은 vdom 모드 장비(단일 VDOM 포함)에서 빈 결과를 줄 수 있다(OA
    실장비 실측 2026-08-19: "해석 0건" 의 원인). 스코프 결과가 비면
    무파라미터로 한 번 더(버전 차이 방어).
    """
    ip, port, token, verify = _device_conn(device)
    if not token:
        raise ValueError("API token is required")
    params = {"vdom": scope_vdom} if scope_vdom else None
    try:
        status, mapping = _paged_monitor(
            ip, port, token, verify, "monitor/firewall/address-fqdns",
            params, _fqdn_map_from_monitor)
    except ValueError:
        raise ValueError("The device returned an unexpected response for "
                         "FQDN resolutions.")
    if params and not mapping and allow_unscoped_fallback:
        try:
            st2, m2 = _paged_monitor(
                ip, port, token, verify, "monitor/firewall/address-fqdns",
                None, _fqdn_map_from_monitor)
        except ValueError:
            st2, m2 = None, {}
        if m2:
            return m2
        if status != 200 and st2 == 200:
            status = st2
    if status != 200:
        raise ValueError(
            f"FQDN resolutions unavailable (HTTP {status}). The token "
            "needs read access to firewall monitor data.")
    return mapping


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
    # 크기는 content(바이트)를 우선 보되 없는 응답 객체(커스텀 어댑터·모킹)
    # 에서도 죽지 않게 text로 폴백한다(재비판 SUSPECT).
    body = getattr(r, "content", None)
    size = len(body) if body is not None else len(r.text.encode("utf-8", "ignore"))
    if size > _MAX_CONFIG_BYTES:
        raise ValueError("Configuration backup exceeds the 50 MB limit.")
    config_text = r.text

    # 2) 정책 통계 (실패해도 config 분석은 가능 → 경고만)
    # 정책 종류별로 분리해 담는다. 합치면 proxy 7번 통계가 firewall 7번에
    # 얹혀 살아 있는 정책이 "미사용"으로 판정된다(FortiGate는 두 종류에 각각
    # 1번부터 번호를 매긴다).
    #
    # **VDOM 은 정책 번호의 일부다.** monitor/firewall/policy 는 한 VDOM 의
    # 통계만 돌려주는데, 어느 VDOM 것인지 적지 않으면 조인부(_scoped)가
    # 전 정책의 통계를 버려 판정은 전부 '사용량 미상'이 되면서 화면·워크북은
    # "사용량 있음"이라고 말한다(라운드 54 완성도 렌즈 — CSV 업로드는
    # 라운드 49 에서 물어보게 고쳤는데 이 형제 경로가 남았다). 등록 장비가
    # 이미 대상 VDOM 을 들고 있으므로 물을 필요 없이 그 VDOM 으로 요청하고
    # 결과에 꼬리표를 단다.
    # **'다중 VDOM' 판정은 파서와 같은 정의여야 한다.** 문자열 휴리스틱
    # ("config vdom" 존재)은 파서(meta.vdoms: 정책들의 VDOM 유니크 >1)와
    # 정의가 달라 — VDOM 모드인데 VDOM 이 root 하나뿐인 장비(흔하다)에서
    # 등록 vdom 이 비면 통계를 전량 폐기하고 "multiple VDOMs" 라는 사실과
    # 다른 경고를 냈고, 배너 인용문 오탐도 있었다(라운드 56 경계값 렌즈).
    # 파싱 비용(초 단위)은 원샷 수집에서 수용한다 — 조인부가 보는 것과
    # 같은 정의가 정확성의 기준이다.
    try:
        from app.parsers.config_parser import FortiGateConfigParser
        _parsed_cfg = FortiGateConfigParser(config_text).parse()
        _meta = _parsed_cfg.get("meta") or {}
        cfg_vdoms = [v for v in (_meta.get("vdoms") or []) if v]
        vdom_dns_vdoms = [v for v in (_meta.get("vdom_dns_vdoms") or []) if v]
        multi_vdom = len(cfg_vdoms) > 1
        cfg_policy_counts = {
            "firewall": len(_parsed_cfg.get("firewall_policy") or []),
            "proxy": len(_parsed_cfg.get("firewall_proxy_policy") or []),
        }
        # 다중 VDOM 커버리지 경고용 — 등록 VDOM 소속 정책 수(라운드 70:
        # 커버리지 경고가 다중 VDOM 에서 통째로 억제돼, v109 가 고친
        # 무언 절단이 다중에서만 잔존했다).
        from collections import Counter as _Counter
        cfg_policy_counts_by_vdom = {
            "firewall": _Counter(
                str(p.get("vdom") or "").strip().lower()
                for p in (_parsed_cfg.get("firewall_policy") or [])),
            "proxy": _Counter(
                str(p.get("vdom") or "").strip().lower()
                for p in (_parsed_cfg.get("firewall_proxy_policy") or [])),
        }
    except Exception:
        # 파싱이 안 되는 config 는 어차피 서버 단계에서 실패한다 — 여기서는
        # 구형 휴리스틱으로 보수 폴백만 한다.
        cfg_vdoms = []
        vdom_dns_vdoms = []
        multi_vdom = "\nconfig vdom" in ("\n" + config_text)
        cfg_policy_counts = {}
        cfg_policy_counts_by_vdom = {}
    device_vdom = str(device.get("vdom") or "").strip()
    if (multi_vdom and device_vdom and cfg_vdoms
            and device_vdom.lower() not in {v.lower() for v in cfg_vdoms}):
        # 등록한 VDOM 이 이 config 에 없다(오타/다른 장비) — 그 이름으로
        # 요청·귀속하면 틀린 스코프다. 통계를 쓰지 않고 사실을 말한다.
        warnings.append(
            f"The registered VDOM '{device_vdom}' is not a VDOM in this "
            f"configuration ({', '.join(cfg_vdoms)}) — usage statistics "
            "were not applied")
        device_vdom = ""
    # **"vdom 모드 여부"와 "VDOM 개수"는 다른 질문이다.** vdom 모드 장비는
    # VDOM 이 root 하나뿐이어도 monitor 호출에 스코프가 없으면 빈 결과를
    # 줄 수 있다 — OA 실장비 실측(2026-08-19): config 백업(scope=global 명시)
    # 만 성공하고 policy 통계·FQDN 이 전부 0건, 그래서 수집 경로만 판정에
    # 사용량이 반영되지 않았다(파일 CSV 추가 시 동일해짐). vdom 모드면
    # 단일 VDOM 이어도 그 VDOM 으로 스코프를 지정한다. 비-vdom 장비
    # (cfg_vdoms 빈)는 파라미터 없이(붙이면 거부하는 버전이 있다).
    _scope_vdom = ""
    if cfg_vdoms:
        _scope_vdom = (device_vdom
                       if device_vdom and device_vdom.lower()
                       in {v.lower() for v in cfg_vdoms}
                       else (cfg_vdoms[0] if len(cfg_vdoms) == 1 else ""))
    stats_params = {"vdom": _scope_vdom} if _scope_vdom else None
    runtime_stats: dict = {"firewall": {}, "proxy": {}}
    _ns_status: dict = {}   # 커버리지 경고용 — ns 별 최종 HTTP 상태
    for path, label, ns in (("monitor/firewall/policy", "policy", "firewall"),
                            ("monitor/firewall/proxy-policy", "proxy-policy", "proxy")):
        try:
            st, rows = _paged_monitor(ip, port, token, verify, path,
                                      stats_params, _policy_stats_from_monitor)
            runtime_stats[ns].update(rows)
            if stats_params and not multi_vdom and (
                    st != 200 or not runtime_stats[ns]):
                # 폴백은 **단일 VDOM 에 한정** — 다중 VDOM 에서 무파라미터
                # 결과는 어느 VDOM 것인지 알 수 없어 device_vdom 으로
                # 오귀속된다(리뷰 게이트 critical, 라운드 49 번짐 재도입
                # 차단). 다중에서는 스코프 결과만 신뢰(비면 빈 채로).
                # 스코프 지정이 이 버전에서 거부되거나 빈 결과면 무파라미터로
                # 한 번 더 — 어느 쪽이 답을 주는지는 버전에 달렸다(v85 원칙:
                # 실물이 답이다. 둘 다 빈 것보다 낫다).
                st2, rows2 = _paged_monitor(ip, port, token, verify, path,
                                            None, _policy_stats_from_monitor)
                if st2 == 200:
                    runtime_stats[ns].update(rows2)
                st = st if st == 200 else st2
            if st != 200:
                warnings.append(f"{label} stats unavailable (HTTP {st}) "
                                "— hit-count/last-used checks limited")
            _ns_status[ns] = st
        except (requests.RequestException, ValueError):
            warnings.append(f"{label} stats could not be read")
    # **커버리지가 모자라면 말한다.** OA 실장비에서 993/1750 절단이 조용히
    # 지나가 "수집했는데 판정이 파일과 다르다"는 미스터리가 됐다 — 행이
    # 없는 정책은 '사용량 미상'으로 남고 그건 참이지만, 몇 개가 그런지는
    # 화면이 말해 줘야 한다(데이터없음 ≠ 0/미사용).
    #
    # 라운드 70 확장 2건: (1) 다중 VDOM 도 등록 VDOM 소속 정책 수를 분모로
    # 같은 경고를 낸다 — 아니면 v109 가 고친 무언 절단이 다중에서만 잔존.
    # (2) 200 인데 0행이면 그것도 말한다 — FQDN 쪽 "returned no resolved"
    # 경고와 대칭(전엔 'unavailable'(비200)과 커버리지(부분) 사이의 사각).
    # 다중 VDOM + 등록 VDOM 없음은 제외 — 통계 전량 폐기 경고가 담당한다.
    _cov_vdom = device_vdom if (multi_vdom and device_vdom) else ""
    stats_coverage: dict = {}
    if not multi_vdom or _cov_vdom:
        for ns, label in (("firewall", "firewall"), ("proxy", "proxy")):
            if _cov_vdom:
                total = (cfg_policy_counts_by_vdom.get(ns) or {}).get(
                    _cov_vdom.lower(), 0)
            else:
                total = cfg_policy_counts.get(ns) or 0
            got = len(runtime_stats.get(ns) or {})
            if total:
                # 산출물(워크북 문서정보)로도 나가는 사실 기록(라운드 70
                # R70-2, Jayden 승인) — 경고는 1회성이지만 커버리지는 판정
                # 내내 지속되는 데이터 성질이다.
                stats_coverage[ns] = {"got": got, "total": total,
                                      **({"vdom": _cov_vdom}
                                         if _cov_vdom else {})}
            _suffix = f" in VDOM '{_cov_vdom}'" if _cov_vdom else ""
            if got and total and got < total:
                warnings.append(
                    f"usage statistics cover {got} of {total} {label} "
                    f"policies{_suffix} — policies without a row stay "
                    "'usage unknown'")
            elif total and not got and _ns_status.get(ns) == 200:
                warnings.append(
                    f"the device returned no usage rows for its {total} "
                    f"{label} policies{_suffix} — all stay 'usage unknown' "
                    "(not 'unused')")
    if multi_vdom:
        if device_vdom:
            # 조인부가 이 꼬리표로 해당 VDOM 정책에만 통계를 붙인다(라운드 49
            # 와 같은 채널). 없으면 다른 VDOM 의 같은 번호에 번진다.
            runtime_stats["_vdom"] = device_vdom
            warnings.append(
                f"Usage statistics were collected for VDOM '{device_vdom}' "
                "only — policies in the other VDOMs stay 'usage unknown'")
        else:
            # 어느 VDOM 것인지 모르는 통계는 쓰지 않는다 — 추측하면 그게
            # 라운드 49 가 막은 번짐이다.
            runtime_stats = {"firewall": {}, "proxy": {}}
            warnings.append(
                "This configuration has multiple VDOMs but the registered "
                "device does not say which one its statistics belong to — "
                "usage statistics were not applied")

    # 3) FQDN 해석 IP (선택)
    #
    # **FQDN 해석의 VDOM 경계는 config 의 vdom-dns 사실로 판정한다**(라운드
    # 64, Jayden 승인 — 라운드 57 의 일괄 억제를 대체). FortiOS 의 FQDN
    # 해석은 기본적으로 전역 DNS 를 따르므로, 어느 VDOM 도
    # `config system vdom-dns` 를 켜지 않았다면 해석은 공통이고 스냅샷을
    # 전 VDOM 에 적용해도 옳다. 켠 VDOM 이 있으면 그 VDOM 의 FQDN 객체만
    # 적용에서 제외된다(reachability.build_address_map 이 meta 를 보고
    # 제외) — 여기서는 그 사실을 경고로 말한다.
    fqdn_map: dict = {}
    _scope_is_vdom_dns = (_scope_vdom and _scope_vdom.lower() in
                          {v.lower() for v in vdom_dns_vdoms})
    if multi_vdom and vdom_dns_vdoms:
        if _scope_is_vdom_dns:
            # 스코프 VDOM 이 자체 DNS 를 쓴다 — 이 스냅샷은 그 VDOM 의
            # 해석이므로 적용 방향이 반전된다(라운드 70, Jayden 승인).
            warnings.append(
                f"FQDN resolutions were collected from VDOM '{_scope_vdom}', "
                "which uses its own DNS (vdom-dns) — they are applied to "
                "FQDN objects in that VDOM only; FQDN objects in other "
                "VDOMs stay unproven.")
        else:
            warnings.append(
                "VDOM(s) with their own DNS settings (vdom-dns): "
                f"{', '.join(vdom_dns_vdoms)} — FQDN resolutions collected "
                "from this device are not applied to FQDN objects in those "
                "VDOMs (their resolution may differ); those policies stay "
                "unproven.")
    try:
        # 통계와 같은 스코프 규칙(vdom 모드면 단일 VDOM 이어도 지정 — OA
        # 실장비 실측: 미범위 호출이 빈 결과) + 같은 무파라미터 폴백 +
        # 같은 페이지 절단 방어(해석 1000건 이상 장비).
        stf, fmap = _paged_monitor(ip, port, token, verify,
                                   "monitor/firewall/address-fqdns",
                                   stats_params, _fqdn_map_from_monitor)
        if stats_params and not multi_vdom and (stf != 200 or not fmap):
            stf2, fmap2 = _paged_monitor(ip, port, token, verify,
                                         "monitor/firewall/address-fqdns",
                                         None, _fqdn_map_from_monitor)
            if stf2 == 200 and (stf != 200 or fmap2):
                stf, fmap = stf2, fmap2
        if stf == 200:
            fqdn_map = fmap
            # **0건도 사실이고, 말해야 한다.** 200 을 받고 빈 결과가 오는 것은
            # 흔하다 — FortiGate 는 FQDN 객체를 **트래픽이 실제로 그 규칙을
            # 쓴 뒤에야** 해석해 두기 때문이다. 아무 말이 없으면 사용자는
            # 수집이 다 됐다고 믿는데, 정작 FQDN 정책은 '판정 불가'로 빠지고
            # 그 사유는 방금 한 일(수집)을 다시 하라고 시킨다(Jayden 실사용
            # 지적). 판정 입력이 비었으면 비었다고 한다.
            if not fqdn_map:
                warnings.append(
                    "The device returned no resolved FQDN addresses — a "
                    "FortiGate resolves an FQDN object only after traffic "
                    "uses it, so FQDN-based policies stay unjudged until "
                    "then")
        else:
            warnings.append(f"FQDN resolutions unavailable (HTTP {stf})")
    except (requests.RequestException, ValueError):
        warnings.append("FQDN resolutions could not be read")

    return {
        "config_text": config_text,
        "runtime_stats": runtime_stats,
        "fqdn_map": fqdn_map,
        # 이 FQDN 스냅샷이 어느 VDOM 스코프로 수집됐는가("" = 무스코프).
        # 적용부의 vdom-dns 반전 게이트 입력(라운드 70, Jayden 승인).
        "fqdn_scope_vdom": _scope_vdom,
        "stats_coverage": stats_coverage,
        "warnings": warnings,
    }
