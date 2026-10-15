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
    "config firewall vip": "firewall_vip",
    "config firewall vipgrp": "firewall_vipgrp",
    "config firewall wildcard-fqdn custom": "firewall_wildcard_fqdn",
    "config firewall wildcard-fqdn group": "firewall_wildcard_fqdn_group",
    # 승인 유효기간 판정(approval_window_days)의 1차 신호 — 이 고객은 유저-서버
    # 정책을 1년짜리 onetime 스케줄로 신청한다(2026-08-24 Jayden).
    "config firewall schedule onetime": "firewall_schedule_onetime",
    "config system interface": "system_interface",
}


# **읽지 않는 것을 조용히 넘기면, 리포트가 거짓말을 한다.**
# TARGET_SECTIONS 밖의 `config` 섹션은 통째로 건너뛰는데, 그 중 일부는
# **정책이다**. IPv6 정책이 200건 있는 백업을 올려도 화면은 그것을 세지 않고
# "정책 N건을 판정했습니다"라고만 말한다 — 읽지 않은 것이 없는 것처럼 보인다.
# 타사 환경으로 넓힐수록(IPv6·NGFW 모드·central NAT) 이 침묵이 위험해진다.
#
# 여기 있는 것만 고지한다. 판정과 무관한 섹션(`config system global` 등)까지
# 알리면 경고가 수백 줄이 되어 정작 중요한 것이 묻힌다.
UNSUPPORTED_SECTIONS = {
    "config firewall policy6":          "IPv6 policies (config firewall policy6)",
    "config firewall policy46":         "IPv4-to-IPv6 policies (config firewall policy46)",
    "config firewall policy64":         "IPv6-to-IPv4 policies (config firewall policy64)",
    "config firewall security-policy":  "NGFW-mode security policies (config firewall security-policy)",
    "config firewall central-snat-map": "central SNAT entries (config firewall central-snat-map)",
    "config firewall address6":         "IPv6 address objects (config firewall address6)",
    "config firewall addrgrp6":         "IPv6 address groups (config firewall addrgrp6)",
}


@dataclass
class ParseState:
    current_section: str | None = None
    current_object: dict[str, Any] | None = None
    config_stack: list[str] = field(default_factory=list)
    section_depth: int | None = None   # target 섹션이 열린 시점의 스택 깊이
    # **VDOM 은 정책 번호의 일부다.** FortiGate 는 VDOM 마다 1번부터 다시
    # 번호를 매기므로, VDOM 을 안 읽으면 root 의 1번과 guest 의 1번이 같은
    # 정책이 된다 — 그 상태로 조치를 내보내면 화면에서 본 적 없는 다른
    # VDOM 의 운영 정책이 꺼진다(라운드 39 실측: PUT 2건이 전부 엉뚱한
    # VDOM 으로 나갔고 화면은 '비활성화 성공'이라고 답했다).
    current_vdom: str | None = None
    vdom_depth: int | None = None      # `config vdom` 이 열린 스택 깊이
    # `config system vdom-dns` 블록 깊이 — 이 VDOM 이 자체 DNS 를 쓰는지는
    # FQDN 해석 스냅샷을 그 VDOM 정책에 적용해도 되는지를 가른다(라운드 64,
    # Jayden 승인: 추측 대신 config 사실로 판정).
    vdom_dns_depth: int | None = None
    # (섹션, _edit, vdom) → 버킷 인덱스. 중복 병합("나중이 이긴다", 라운드
    # 43)의 선형 탐색이 O(객체²)라 1.8MB 합성 config 파싱에 44.8초 중
    # 39초를 차지했다(B-53 프로파일 실측: 36M 회 dict.get). O(1) 조회로.
    edit_index: dict = field(default_factory=dict)
    # 읽지 않은 섹션을 한 번씩만 고지하기 위한 집합(같은 섹션이 VDOM 마다
    # 반복되면 경고가 VDOM 수만큼 늘어난다).
    unsupported_seen: set = field(default_factory=set)
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
            "firewall_vip": [],
            "firewall_vipgrp": [],
            "firewall_wildcard_fqdn": [],
            "firewall_wildcard_fqdn_group": [],
            "firewall_schedule_onetime": [],
            "system_interface": [],
            "parse_warnings": [],
        }
    )


import re as _re_intake


# 파서 경고 상한(B-81). 악성·기형 입력은 줄마다 경고를 만들 수 있고, 이
# 목록은 응답 JSON·워크북·화면에 그대로 실린다 — 50MB 입력이면 경고만으로
# 메모리와 응답이 부푼다. 게다가 **디스크에서 직접 읽는 경로**(재수집·배치)는
# Flask 의 업로드 상한을 지나지 않아 그 완화도 못 받는다.
#
# 1만 건은 사람이 볼 수 있는 양을 한참 넘는다 — 넘어가면 세기만 하고
# 목록은 자른다. **자른 사실을 반드시 남긴다**: 조용히 자르면 "경고 1만 건"이
# "이게 전부"로 읽힌다(이 레포가 여러 번 겪은 과소보고 사고와 같은 얼굴).
_MAX_PARSE_WARNINGS = 10000

# config 본문 상한(B-81). 업로드 상한(50MB)과 같은 값으로 맞춘다 — 여기가
# 더 빡빡하면 업로드는 통과했는데 판정에서 거부되는 모순이 생긴다.
# 실 고객 백업이 수 MB 대이므로 정상 사용에는 여유가 크다.
_MAX_CONFIG_CHARS = 50 * 1024 * 1024


def _add_warning(state, entry: dict) -> None:
    """경고를 상한 안에서 추가한다. 상한을 넘으면 세기만 한다."""
    warnings = state.parsed["parse_warnings"]
    if len(warnings) < _MAX_PARSE_WARNINGS:
        warnings.append(entry)
        return
    meta = state.parsed.setdefault("meta", {})
    meta["parse_warnings_truncated"] = meta.get("parse_warnings_truncated", 0) + 1


def config_intake_problem(raw: str):
    """이 텍스트를 FortiGate 설정으로 받아도 되는가. (사유, error_key) 또는 None.

    **규칙이 한 통로에만 있으면 나머지 통로로 들어온다.** 업로드 라우트에만
    두었더니 설정 비교와 배치 리포트가 같은 파일을 통과시켰다 — 빈 파일을
    기준으로 비교해 "정책 5건 신설"이 증적 엑셀에 사실로 적혔고, 배치는
    확장자만 보고 메모장 파일을 `[ OK ]` 장비로 세어 정식 워크북까지 만들었다
    (라운드 46 실측). 이 루프의 결론 — 목록·경로 기반 방어는 언제나 절반짜리다.

    형태만 본다: FortiGate 백업은 `config <섹션>` 블록으로 이뤄진다. 내용의
    옳고 그름이 아니라 **이 파일이 그 종류인지**만 가린다.
    """
    if not (raw or "").strip():
        return ("That file is empty. A FortiGate configuration backup was "
                "expected — check that the download finished, then upload it "
                "again.", "empty_config")
    # **크기 문턱은 여기 있어야 모든 통로를 덮는다** (B-81).
    # Flask 의 MAX_CONTENT_LENGTH(50MB)는 업로드에만 걸린다. 장비에서 수집한
    # config(server.py 의 collect 경로)와 보관소에서 되읽는 경로는 그 상한을
    # 지나지 않는다 — 응답을 무한정 흘려보내는 장비/프록시 하나면 파서가
    # 그대로 받아 문다. 이 함수는 다섯 통로가 **모두** 지나는 공통 관문이므로
    # 여기 두면 한 번에 덮인다(라운드 47 이 '캡티브 포털 응답' 을 여기서
    # 막은 것과 같은 이유).
    if len(raw) > _MAX_CONFIG_CHARS:
        _mb = _MAX_CONFIG_CHARS // (1024 * 1024)
        return (f"That configuration is too large to assess (limit {_mb} MB). "
                "A FortiGate backup this size is unusual — check that the "
                "file is a configuration backup and not a log or archive.",
                "config_too_large")
    # NOTE(보안): 앞 공백 매칭에 `\s*`(개행 포함)를 쓰면 re.MULTILINE 에서
    # 공백만 있는 줄마다 앵커가 재시작돼 O(N^2) 백트래킹(ReDoS)이 된다.
    # 작은 크래프트 파일로 요청 스레드가 정지하므로 줄 내 공백만 매칭한다.
    if not _re_intake.search(r"^[ \t]*config\s+\S+", raw, _re_intake.M):
        return ("That file does not look like a FortiGate configuration "
                "backup — APO could not find a single 'config' section in it. "
                "Upload the backup taken from the device (System > "
                "Configuration > Backup), not a log, report or partial "
                "download.", "not_a_fortigate_config")
    return None


class FortiGateConfigParser:
    def __init__(self, raw_text: str):
        self.lines = raw_text.splitlines()

    @staticmethod
    def _opens_quote(line: str) -> bool:
        """이 줄이 따옴표를 **연 채로** 끝나는가(이스케이프 인식)."""
        depth, i = 0, 0
        while i < len(line):
            c = line[i]
            if c == "\\":
                i += 2
                continue
            if c == '"':
                depth ^= 1
            i += 1
        return bool(depth)

    def parse(self) -> dict[str, Any]:
        state = ParseState()
        self._parse_meta(state)

        # **여러 줄 값 안에서는 문법을 해석하지 않는다.** replacemsg buffer·
        # certificate·automation-action 의 cli-script 는 따옴표 안에 여러 줄을
        # 담고 그 안에 `end`·`next` 텍스트가 그대로 들어간다. 그걸 문법으로
        # 읽어 **완결된 정상 파일에서 정책이 사라지고 "truncated" 거짓 경고**가
        # 떴다(라운드 47 실측). 원문 훑기에는 이미 가르쳤는데 파서에는
        # 안 가르쳐서 같은 파일을 두 곳이 다르게 읽고 있었다.
        in_multiline = False
        for lineno, raw_line in enumerate(self.lines, start=1):
            line = raw_line.strip()
            if in_multiline:
                if self._opens_quote(line):
                    in_multiline = False
                continue
            if not line or line.startswith("#"):
                continue
            if self._opens_quote(line):
                in_multiline = True
                continue

            if line.startswith("config "):
                state.config_stack.append(line)
                if line == "config vdom" and state.current_section is None:
                    # **형제 `edit` 가 여러 개 온다.** 실제 FortiOS 출력은
                    #   config vdom / edit root ... next / edit guest ... next / end
                    # 이라, '바로 다음 edit 하나'만 집어 들면 두 번째 VDOM 부터
                    # 앞 VDOM 소속으로 기록된다 — guest 정책이 root 것이 되고,
                    # root 의 any/any/all 이 guest 의 살아 있는 정책을 가렸다고
                    # 보고했다(라운드 42 실측). meta.multi_vdom 도 False 라
                    # 경고조차 안 떴다. 블록이 열린 깊이를 기억하고, 그 깊이의
                    # `edit`/`next` 를 계속 따라간다.
                    state.vdom_depth = len(state.config_stack)
                    continue
                if (line == "config system vdom-dns"
                        and state.current_section is None):
                    # VDOM 자체 DNS 여부 — FQDN 스냅샷 적용 가부의 근거
                    state.vdom_dns_depth = len(state.config_stack)
                    continue
                # 이미 target 섹션 안(중첩 config, 예: config secondaryip)이면 섹션 전환하지 않는다.
                if line in TARGET_SECTIONS and state.current_section is None:
                    state.current_section = TARGET_SECTIONS[line]
                    state.current_object = None
                    state.section_depth = len(state.config_stack)  # 이 섹션이 열린 스택 깊이 기록
                elif (line in UNSUPPORTED_SECTIONS
                        and state.current_section is None
                        and line not in state.unsupported_seen):
                    # 읽지 않는다는 사실 자체를 산출물에 남긴다(위 주석 참조).
                    state.unsupported_seen.add(line)
                    _add_warning(state, {
                        "line": lineno,
                        "content": line,
                        "warning": (
                            f"This backup contains {UNSUPPORTED_SECTIONS[line]}. "
                            "APO does not read that section, so those entries are "
                            "not part of this assessment."),
                    })
                continue

            if line == "end":
                ended = state.config_stack.pop() if state.config_stack else None
                if ended == "config vdom":
                    state.current_vdom = None
                    state.vdom_depth = None
                if ended == "config system vdom-dns":
                    state.vdom_dns_depth = None
                # target 섹션 자신의 end일 때만 섹션 종료 (중첩 블록의 end는 무시)
                if (ended in TARGET_SECTIONS
                        and state.section_depth is not None
                        and len(state.config_stack) < state.section_depth):
                    # **`next` 없이 섹션이 끝나면 그 객체가 조용히 사라졌다.**
                    # FortiOS 는 항상 `next` 를 쓰므로, 없다는 것은 백업이
                    # 잘렸다는 뜻이다(손으로 자른 config·중단된 다운로드).
                    # 잘린 객체는 필드가 빠져 있을 수 있어 판정에 넣지 않지만,
                    # **몇 개가 빠졌는지는 말해야 한다** — 말하지 않으면 그
                    # 정책은 감사에서 통째로 빠지고 아무도 모른다(라운드 42).
                    #
                    # 중첩 `config` 블록(secondaryip 등)의 end 에는 발동하지
                    # 않아야 한다. 그때는 바깥 객체가 정상적으로 열려 있다 —
                    # 처음 넣었을 때 실 고객 설정에서 경고 3건이 뜬 것이
                    # 그 오탐이었다.
                    if state.current_object is not None:
                        _add_warning(state, {
                            "line": lineno,
                            "content": f"{state.current_section} / edit "
                                       f"{state.current_object.get('_edit', '?')}",
                            "warning": "object ended without 'next' — the "
                                       "configuration looks truncated, so this "
                                       "object was not assessed",
                        })
                    state.current_section = None
                    state.current_object = None
                    state.section_depth = None
                continue

            if state.current_section is None:
                # VDOM 블록 안에서는 `edit <이름>` … `next` 가 VDOM 하나를
                # 감싼다. 그 깊이에서만 따라간다 — 더 깊은 곳의 edit 은
                # 다른 섹션의 것이다.
                if state.vdom_depth is not None                         and len(state.config_stack) == state.vdom_depth:
                    if line.startswith("edit "):
                        state.current_vdom = self._strip_quotes(line[5:].strip())
                    elif line == "next":
                        state.current_vdom = None
                # `config system vdom-dns` 안의 `set vdom-dns enable` —
                # 이 VDOM 은 자체 DNS 를 쓴다. FQDN 해석은 DNS 별로 다를 수
                # 있으므로, 전역 스냅샷을 이 VDOM 의 FQDN 객체에 적용하면
                # 안 된다(라운드 64 — B-48 을 config 사실 기반으로 해소).
                if (state.vdom_dns_depth is not None
                        and len(state.config_stack) == state.vdom_dns_depth
                        and state.current_vdom
                        and line.replace('"', "") == "set vdom-dns enable"):
                    _lst = state.parsed["meta"].setdefault("vdom_dns_vdoms", [])
                    if state.current_vdom not in _lst:
                        _lst.append(state.current_vdom)
                continue

            # target 섹션보다 더 깊은 중첩 config 본문(예: config secondaryip)은 무시.
            # 다중 VDOM 등으로 target 섹션이 depth 1이 아닐 수 있으므로 절대값 대신 섹션 깊이 기준으로 비교.
            if state.section_depth is not None and len(state.config_stack) > state.section_depth:
                continue

            if line.startswith("edit "):
                edit_key = self._strip_quotes(line[5:].strip())
                state.current_object = {"_edit": edit_key}
                continue

            if line == "next":
                if state.current_object is not None:
                    normalized = self._normalize_object(state.current_section, state.current_object)
                    if state.current_vdom:
                        normalized["vdom"] = state.current_vdom
                    # **같은 번호가 두 번 나오면 실장비에서는 한 객체다.**
                    # 손으로 병합한 백업에서 `edit 3` 이 두 번 나오면 정책을
                    # 둘로 만들었고, 워크북에 같은 번호로 상반된 판정 두 개가
                    # 실렸다(Critical/Disable now 와 Unknown/Cannot assess).
                    # 실장비에는 존재하지 않는 구조를 그린 것이다(라운드 43
                    # 실측). FortiOS 동작대로 **나중 것이 이긴다** — 그리고
                    # 덮었다는 사실을 말한다.
                    _key = str(normalized.get("_edit", ""))
                    _bucket = state.parsed[state.current_section]
                    _ikey = (state.current_section, _key,
                             normalized.get("vdom") or "")
                    _prev = state.edit_index.get(_ikey)
                    if _key and _prev is not None:
                        _add_warning(state, {
                            "line": lineno,
                            "content": f"{state.current_section} / edit {_key}",
                            "warning": "this number appears more than once — the "
                                       "later definition replaced the earlier "
                                       "one, as the device would do",
                        })
                        _bucket[_prev] = normalized
                    else:
                        if _key:
                            state.edit_index[_ikey] = len(_bucket)
                        _bucket.append(normalized)
                state.current_object = None
                continue

            if line.startswith("set ") and state.current_object is not None:
                try:
                    key, value = self._parse_set_line(line)
                    state.current_object[key] = value
                except Exception as exc:
                    # **내부 예외 문구를 감사 문서에 인쇄하지 않는다.**
                    # 예전에는 `str(exc)` 를 그대로 실어, 워크북이 경고 문장을
                    # 인쇄하기 시작한 순간 유료 산출물에 `Invalid set line` 이
                    # 찍혔다(2026-09-10 재비판 F3). 원문은 진단용 `detail` 로만
                    # 남긴다 — 워크북은 `warning` 만 읽는다.
                    _add_warning(
                        state,
                        {"line": lineno, "content": line,
                         "warning": ("A setting on this line could not be read, "
                                     "so it is not part of this assessment."),
                         "detail": str(exc)}
                    )
                continue

        # Build service_groups lookup: { "AD_AUTH": ["LDAP", "Kerberos", ...], ... }
        # Used by severity_engine.expand_services to resolve risky/AD-DNS membership.
        state.parsed["service_groups"] = build_service_group_map(
            state.parsed.get("firewall_service_group", [])
        )
        # 어떤 VDOM 이 들어 있는지 한 곳에 적어 둔다. 정책 번호가 유일하다는
        # 가정을 쓰는 쪽(조치 적용·가려짐 판정·CSV 병합)이 이걸 보고 자기
        # 가정이 성립하는지 판단할 수 있어야 한다.
        _vd = []
        for _k in ("firewall_policy", "firewall_proxy_policy",
                   "firewall_multicast_policy"):
            for _o in state.parsed.get(_k, []):
                _v = _o.get("vdom")
                if _v and _v not in _vd:
                    _vd.append(_v)
        state.parsed["meta"]["vdoms"] = _vd
        state.parsed["meta"]["multi_vdom"] = len(_vd) > 1

        # **파일이 그냥 끊긴 경우는 아무 경고도 없었다.** 위 경고는 구역이
        # `end` 로 닫힐 때만 뜨는데, 다운로드가 중간에 끊긴 백업은 `end` 자체가
        # 없어 조용히 통과했다 — 정책 5개 중 2개까지만 있는 파일이 "2 policies
        # 검토 완료"로 보고됐고, 비교에 넣으면 나머지 3개가 "정책 3건 신설"로
        # 나왔다(라운드 46 실측). 끝에서 열린 채 남은 것을 확인한다.
        # **여러 줄 값 안에서 끝나면 잘린 것이 아니다.** 원문 훑기에만 여러 줄
        # 값을 가르치고 파서에는 안 가르쳐서, `set comments "… end …"` 가 든
        # **완결된 정상 파일**에 "truncated" 라는 거짓 경고가 뜨고 정책이
        # 사라졌다(라운드 47 실측). 여기서는 경고만 다룬다 — 값 파싱은
        # `_TOKEN_RE` 가 이미 이스케이프를 정확히 처리한다.
        # **아래 두 경고는 상한(_add_warning)을 지나지 않는다.** 파일당 한 번만
        # 나고, '이 백업은 잘렸다'는 가장 중요한 사실이다. 앞에서 중복 정의
        # 경고가 상한을 채웠다는 이유로 이것이 사라지면, 잘린 백업이 멀쩡한
        # 것으로 읽힌다 — 상한을 두는 목적(부풀기 방지)과 정반대의 손해다.
        if state.current_section is not None:
            state.parsed["parse_warnings"].append({
                "line": lineno if "lineno" in dir() else 0,
                "content": f"{state.current_section}"
                           + (f" / edit {state.current_object.get('_edit', '?')}"
                              if state.current_object else ""),
                "warning": "the file ends inside this section — the backup "
                           "looks truncated, so anything after this point was "
                           "not read",
            })
            state.parsed["meta"]["truncated"] = True
        elif state.config_stack:
            # **target 섹션 밖에서 끊긴 백업은 완전 침묵이었다**(B-63).
            # `config vdom`/`config system vdom-dns` 같은 바깥 블록의 end 가
            # 유실되면 위 검사(섹션 내 잘림)에 안 걸리는데, 그 상태로는 이후
            # VDOM 의 정책·주소·vdom-dns 가 앞 VDOM 소속으로 오귀속되고
            # multi_vdom=False 로 경고 채널까지 닫힌다(라운드 65 실측: root
            # 정책이 CORP 소속, 조치계획 config vdom 접두까지 틀릴 수 있는
            # 클래스). 스택 잔량이 곧 잘림의 증거다 — 말한다.
            state.parsed["parse_warnings"].append({
                "line": 0,
                "content": " > ".join(state.config_stack[-3:]),
                "warning": "the file ends with unclosed configuration "
                           "block(s) — the backup looks truncated, and VDOM "
                           "attribution after the cut may be wrong; "
                           "re-export a complete backup",
            })
            state.parsed["meta"]["truncated"] = True
        return state.parsed

    def _parse_meta(self, state: ParseState) -> None:
        # hostname은 'config system global' 아래에 있어 50줄을 넘어갈 수 있으므로 전체를 스캔한다.
        for raw_line in self.lines:
            line = raw_line.strip()
            if line.startswith("#config-version="):
                state.parsed["meta"]["config_version"] = line.split("=", 1)[1]
            if line.startswith("#buildno="):
                state.parsed["meta"]["buildno"] = line.split("=", 1)[1]
            if "set hostname " in line and "hostname" not in state.parsed["meta"]:
                state.parsed["meta"]["hostname"] = self._strip_quotes(
                    line.split("set hostname", 1)[1].strip()
                )

    # 따옴표 토큰(이스케이프된 \" 포함)과 일반 토큰을 원래 순서대로 캡처
    # FortiOS `show full-configuration` 은 **빈 값을 홑따옴표로** 낸다
    # (`set groups ''`). 겹따옴표만 벗기던 동안 그 값이 두 글자 문자열 "''" 로
    # 남아 '설정됨'으로 읽혔다 — 사용자 그룹 조건이 없는 정책에 대해 화면이
    # '사용자 그룹으로 매칭한다'는 **사실이 아닌 사유**로 판정을 보류했고,
    # 가림막 자격도 함께 잃었다(라운드 43 실측). 빈 값은 빈 값으로 읽는다.
    _TOKEN_RE = re.compile(r'"((?:[^"\\]|\\.)*)"' r"|'((?:[^'\\]|\\.)*)'" r"|(\S+)")

    @classmethod
    def _tokenize_value(cls, raw_value: str) -> list[str]:
        tokens: list[str] = []
        for m in cls._TOKEN_RE.finditer(raw_value):
            if m.group(1) is not None:
                # 겹따옴표 값: \" 와 \\ 언이스케이프
                tokens.append(m.group(1).replace('\\"', '"').replace('\\\\', '\\'))
            elif m.group(2) is not None:
                tokens.append(m.group(2))       # 홑따옴표 값(빈 값 포함)
            else:
                tokens.append(m.group(3))
        return tokens

    def _parse_set_line(self, line: str) -> tuple[str, Any]:
        m = re.match(r"set\s+(\S+)\s+(.+)$", line)
        if not m:
            raise ValueError("Invalid set line")
        key, raw_value = m.group(1), m.group(2).strip()

        # 단일 패스 토큰화로 원래 순서 유지 + 이스케이프된 따옴표 처리
        tokens = self._tokenize_value(raw_value)
        if not tokens:
            return key, ""
        if len(tokens) == 1:
            return key, tokens[0]
        return key, tokens

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
            # FortiOS 는 `set subnet 10.1.1.0 255.255.255.0` 과
            # `set subnet 10.1.1.0/24` 를 모두 낸다. 두 토큰만 처리했더니
            # 슬래시 표기가 subnet_cidr 없이 지나갔고, 그걸 받은 쪽이
            # '미설정 = 0.0.0.0/0' 으로 해석해 그 객체가 **만능 shadower** 가
            # 됐다 — 10.1.1.0/24 정책이 10.9.9.0/24 정책을 가렸다고 보고했다
            # (라운드 42 실측, 경고 한 줄 없이).
            _sub = item.get("subnet")
            if isinstance(_sub, list) and len(_sub) == 2:
                item["subnet_cidr"] = self._to_cidr(_sub[0], _sub[1])
            elif isinstance(_sub, str) and "/" in _sub:
                item["subnet_cidr"] = _sub.strip()
            elif isinstance(_sub, list) and len(_sub) == 1 and "/" in _sub[0]:
                item["subnet_cidr"] = _sub[0].strip()
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

        elif section == "firewall_vip":
            item["name"] = item.get("_edit", "")
            # mappedip는 단일 IP·범위("a-b")·복수 표기가 가능하다. 리스트로 정규화.
            m = item.get("mappedip", [])
            item["mappedip"] = [m] if isinstance(m, str) else (m or [])

        elif section in {"firewall_vipgrp", "firewall_wildcard_fqdn_group"}:
            item["name"] = item.get("_edit", "")
            members = item.get("member", [])
            if isinstance(members, str):
                members = [members]
            item["member"] = members

        elif section == "firewall_wildcard_fqdn":
            item["name"] = item.get("_edit", "")

        elif section == "firewall_schedule_onetime":
            item["name"] = item.get("_edit", "")

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
        try:
            network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
            return str(network)
        except Exception:
            # 잘못된 IP/마스크(또는 IPv6 등)로 파싱 실패 시 파서 전체가 죽지 않도록 원본 표기
            return f"{ip_str}/{mask_str}".strip("/")


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
