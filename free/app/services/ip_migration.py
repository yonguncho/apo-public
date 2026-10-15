"""IP 값 마이그레이션 — 구 IP 를 신 IP 로 바꾼 config 를 만든다.

**이 도구의 존재 이유는 "장비에서는 못 바꾸기 때문"이다.**

FortiOS 는 참조가 걸린 것을 바꾸거나 지우지 못하게 막는다:

    Error: IP address x.x.x.x is configured as source-ip for syslog or other servers
    The entry is used by other 1 entries. Command fail. Return code -23

인터페이스 이름은 아예 못 바꾼다 — Fortinet 공식 답이 *"참조를 전부 지우고,
인터페이스를 지우고, 다시 만드세요"* 다. 그 사이 정책에 구멍이 난다(그리고
Fortinet 은 이 중단을 문서에서 경고하지 않는다).

그리고 그 차단은 **런타임 메모리 상태**다 — config 파일에는 없는 참조가
장비에서는 삭제를 막고, Fortinet 의 해결책은 "리부트하세요"다. 즉 라이브
장비에서 도는 도구(NSPM 3사·FortiManager)는 전부 같은 벽에 부딪힌다.
**config 파일을 고치면 그 계층을 통째로 건너뛴다.**

**바이트를 보존한다.** 파싱해서 다시 출력하지 않고 좌표로 그 자리만 바꾼다.
이스케이프 안 된 따옴표 하나로 장비가 부팅에 실패한 사례가 있고
(`Initialize config error 44010`), `set ... ENC ...` 값·UUID·인증서 블롭은
건드리면 안 된다. 제자리 치환은 그것들을 원리적으로 못 건드린다.

**검증이 거짓말하지 않게 하는 것이 이 모듈의 절반이다.**
2026-09-03 다중 렌즈 감사에서 `verify` 가 세 가지를 못 봤다:
①깨진 이름 참조 ②스왑/순열(신·구 집합이 같으면 아무것도 안 바꿔도 통과)
③스캐너의 무성유실 경보. 셋 다 "가장 위험한 실패를 검증이 못 보는" 형태라,
검증이 있다는 **착각만** 주고 있었다. 아래 `verify` 는 그 셋을 전부 본다.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .ip_reference_scanner import IpReference, ScanResult, scan
# 이름 전용 탐색(`_walk_names`)은 스캐너와 **같은 규칙**으로 문맥을 읽어야
# 한다 — 한쪽만 고치면 두 경로가 서로 다른 객체를 가리킨다. 그래서 규칙을
# 베끼지 않고 스캐너의 것을 그대로 쓴다(같은 패키지의 내부 함수다).
from .ip_reference_scanner import (
    _field_name,
    _is_name_ref_field,
    _quoted_spans,
    _unescaped_quotes,
)

#: 이 참조를 어떻게 할 것인가. 화면은 이 값을 사람 말로 번역해 보여준다.
ACTION_CHANGE = "change"        # 값을 바꾼다 (자동, 답이 하나)
ACTION_RENAME = "rename"        # 객체 이름을 바꾼다 (사람이 정함)
ACTION_FOLLOW = "follow"        # 위 이름을 따라간다 (자동)
ACTION_REVIEW = "review"        # 사람이 읽고 판단 (주석 등)
ACTION_UNMAPPED = "unmapped"    # 매핑표에 없다 — 폐기인가 빠뜨린 것인가
ACTION_SUPERNET = "supernet"    # 대상 대역을 **포함하는** 상위 대역 — 건드리면 안 된다

#: 판정 근거는 **코드**로 낸다. 문장을 서버에서 만들면 화면이 번역할 수 없어
#: 영어 사용자에게 한국어가 그대로 뜬다(감사에서 3,721건 실측). 화면이
#: 이 코드를 자기 언어로 옮긴다.
REASON_VALUE = "value"                    # 실제 IP 설정값
REASON_NAME = "name_contains_ip"          # 객체 이름에 IP 가 들어 있다
REASON_FOLLOW = "follows_object_name"      # 그 객체를 가리키는 참조
REASON_COMMENT = "comment_only"            # 사람이 읽는 메모
REASON_ABSENT = "not_in_mapping"           # 매핑표에 없다
REASON_RETIRED = "retired"                 # 폐기로 표시했다
REASON_SUPERNET = "supernet_contains"      # 대상을 포함하는 상위 대역
REASON_UNRESOLVED = "object_not_found"     # 그 이름의 객체 정의를 못 찾았다
REASON_KEEP_NAME = "name_unchanged"        # 이름을 그대로 두면 손댈 필요 없다
#: 사용자가 3단계에서 직접 적은 이름. **자동 제안과 구분해야 한다** —
#: 덮어썼다는 사실이 표에 보여야 승인자가 무엇을 승인하는지 안다.
REASON_USER_NAME = "user_renamed"

#: 경고 코드. 문장이 아니라 코드로 낸다(위와 같은 이유).
WARN_LOCKOUT = "lockout"                   # 바꾸면 장비 접근이 끊길 수 있다
WARN_UNRESOLVED_NAME = "unresolved_name"   # 정의를 못 찾은 이름 — 추측하지 않는다
WARN_SOURCE_CHANGED = "source_changed"     # 원문이 계획 시점과 다르다
WARN_MASK_MISALIGNED = "mask_misaligned"   # 신 IP 가 기존 넷마스크와 안 맞는다
WARN_NEW_IP_COLLISION = "new_ip_collision"  # 다른 구 IP 도 같은 신 IP 로 간다
WARN_NEW_IP_IN_USE = "new_ip_in_use"       # 신 IP 가 이미 이 config 에 있다
WARN_NAME_COLLISION = "name_collision"     # 개명 결과가 다른 객체와 같아진다
WARN_GATEWAY_OFF_SUBNET = "gateway_off_subnet"  # 게이트웨이가 그 인터페이스 대역 밖
WARN_SUPERNET_MAPPED = "supernet_mapped"   # 상위 대역을 매핑표에 넣었다 — 정책 범위가 바뀐다


@dataclass
class PlanRow:
    """변경 계획 1행 = 참조 1건."""

    ref: IpReference
    action: str
    #: 이 참조가 갖게 될 값. `None` 이면 바꾸지 않는다.
    new_text: str | None = None
    #: 왜 이렇게 판정했는가 — **코드**다. 화면이 번역한다.
    reason: str = ""
    #: 판정에 끼워 넣을 값(있으면). 화면이 문장에 채운다.
    reason_arg: str | None = None
    #: 경고 **코드** 목록.
    warnings: list[str] = field(default_factory=list)

    @property
    def old_text(self) -> str:
        return self.ref.display


@dataclass
class MigrationPlan:
    rows: list[PlanRow] = field(default_factory=list)
    #: 구 대역에 있으나 매핑표에 없는 IP. **폐기 확인 없이는 진행을 막는다.**
    unmapped_ips: list[str] = field(default_factory=list)
    #: 매핑표에서 신 값을 비운 IP = 폐기. 미매핑과 **다르게** 다룬다.
    retired_ips: list[str] = field(default_factory=list)
    #: 대상 대역을 포함하는 상위 대역. 매핑 대상이 아니다.
    supernet_ips: list[str] = field(default_factory=list)
    renamed_objects: dict[str, int] = field(default_factory=dict)
    #: 개명 표(구 이름 → 새 이름). **되돌리기에 반드시 필요하다** —
    #: `renamed_objects` 는 참조 수만 세서 새 이름을 아예 기록하지 않았고,
    #: 되돌리기 표는 IP 쌍뿐이라 이름은 원상복구 경로가 **존재하지 않았다**.
    #: 이름을 되돌리려면 FortiOS 가 막는 그 벽(참조 삭제 → 객체 삭제 →
    #: 재생성) 앞에 다시 서게 된다 — 이 도구의 존재 이유가 역방향에는
    #: 없는 셈이었다.
    renamed_names: list[dict] = field(default_factory=list)
    #: 두 구 IP 가 같은 신 IP 로 가는 경우. 객체가 합쳐진다.
    new_ip_collisions: dict[str, list[str]] = field(default_factory=dict)
    #: 신 IP 가 이미 이 config 에서 쓰이는 경우.
    new_ips_in_use: list[str] = field(default_factory=list)
    #: 개명 결과가 다른 객체 이름과 같아지는 경우. FortiOS 는 두 번째
    #: `edit "X"` 를 **첫 객체 편집**으로 처리해 하나가 사라진다.
    name_collisions: list[str] = field(default_factory=list)
    #: **원본에 이미 있던** 깨진 이름 참조. 우리가 만든 것과 구분해야 한다 —
    #: 실 백업에는 다른 VDOM·다른 장비에 정의된 참조가 흔하다.
    preexisting_dangling: set = field(default_factory=set)
    #: 원본에 **이미 중복이던** `edit` 이름 → 그 초과 개수.
    #: **집합이 아니라 개수다.** 이름 단위로 통째 면제하면 그 이름에 대해
    #: 우리가 새로 만든 중복까지 덮인다 — 실측: 원본 중복 1건을 면제하다가
    #: 개명이 만든 별개의 중복까지 `verify` 가 못 봤고 `clean=True` 가 났다.
    #: 억제는 "원래 있던 만큼만" 이어야 한다.
    preexisting_duplicates: dict = field(default_factory=dict)
    scan_result: ScanResult | None = None

    @property
    def lockout_rows(self) -> list[PlanRow]:
        return [r for r in self.rows if r.ref.is_admin_access]

    @property
    def blocking(self) -> list[str]:
        """**파일을 만들기 전에 사람이 답해야 하는 것들.**

        하나라도 있으면 라우트가 막는다. 조용히 진행하면 ISP 전환에서 IP
        하나를 놓쳐 그 서버가 죽거나, 두 객체가 하나로 합쳐진다.
        """
        out = []
        if self.unmapped_ips:
            out.append("unmapped")
        if self.retired_ips:
            out.append("retired")
        if self.new_ip_collisions:
            out.append("new_ip_collision")
        if self.name_collisions:
            out.append("name_collision")
        s = self.scan_result
        if s and (s.unterminated_quote_line or s.unclosed_config_blocks):
            out.append("config_not_fully_read")
        return out

    def summary(self) -> dict:
        by_action: dict[str, int] = {}
        for r in self.rows:
            by_action[r.action] = by_action.get(r.action, 0) + 1
        s = self.scan_result
        return {
            "rows": len(self.rows),
            "by_action": by_action,
            "will_change": sum(1 for r in self.rows if r.new_text is not None),
            "unmapped_ips": list(self.unmapped_ips),
            "retired_ips": list(self.retired_ips),
            "supernet_ips": list(self.supernet_ips),
            "lockouts": len(self.lockout_rows),
            #: 그중 **실제로 바뀌는** 것. 4단계의 "접속 경로 N곳을 바꾼다"는
            #: 이 수를 써야 한다 — 전체를 쓰면 아무것도 안 바꾸는 계획에도
            #: 빨간 경고가 뜨고, 그 근거 행은 기본 필터에 가려 찾을 수 없다.
            "lockouts_changing": sum(
                1 for r in self.lockout_rows if r.new_text is not None),
            "renamed_objects": dict(self.renamed_objects),
            "renamed_names": list(self.renamed_names),
            "new_ip_collisions": {k: list(v) for k, v in self.new_ip_collisions.items()},
            "new_ips_in_use": list(self.new_ips_in_use),
            "name_collisions": list(self.name_collisions),
            "blocking": self.blocking,
            # **스캐너의 무성유실 경보를 여기서도 낸다.** 1단계에만 있으면
            # 정작 파일을 만드는 쪽이 눈을 감는다 — 안 닫힌 따옴표 하나로
            # 반쪽만 바뀐 파일이 "검증 통과"로 나갔다(감사 실측).
            "unterminated_quote_line": s.unterminated_quote_line if s else None,
            "unclosed_config_blocks": s.unclosed_config_blocks if s else 0,
        }


def _norm_ip(text: str) -> str:
    """매핑표 대조용 정규화. `10.1.2.5/32` 와 `10.1.2.5` 를 같게 본다."""
    t = (text or "").strip()
    if "/" in t:
        t = t.split("/", 1)[0]
    try:
        return str(ipaddress.IPv4Address(t))
    except ValueError:
        return t


class MappingError(ValueError):
    """어느 행이 왜 틀렸는지 담는다. 139행 중 하나가 틀렸을 때
    "Invalid mapping" 만으로는 어디를 고칠지 알 수 없다."""

    def __init__(self, row: int, old: str, detail: str):
        self.row, self.old, self.detail = row, old, detail
        super().__init__(f"row {row} ({old}): {detail}")


def parse_mapping(rows) -> dict[str, str | None]:
    """사용자 매핑표를 정규화한다.

    받는 형태: `[(구IP, 신IP), ...]` 또는 `[{"old": ..., "new": ...}, ...]`.
    신 IP 가 비어 있으면 **폐기 후보**로 보고 `None` 을 둔다 — 그 구분이
    중요하다. "빠뜨린 것"과 "일부러 없애는 것"은 완전히 다르다.

    **구 IP 도 검증한다.** 전에는 신 IP 만 봐서 `010.1.2.5` 같은 오타가
    영원히 매칭되지 않는 죽은 키가 됐고, 사용자는 "표에 넣었는데 왜
    미매핑이냐"를 겪은 뒤 확인 체크박스를 눌러 넘어갔다.
    """
    out: dict[str, str | None] = {}
    seen_old: dict[str, int] = {}
    for i, row in enumerate(rows or [], start=1):
        if isinstance(row, dict):
            old, new = row.get("old"), row.get("new")
        else:
            old, new = (list(row) + [None, None])[:2]
        # **타입을 먼저 본다.** `(x or "").strip()` 은 x 가 숫자·리스트·dict
        # 면 AttributeError 로 500 이 된다 — 라우트가 스스로 "사용자 입력
        # 오류에 500 을 주면 안 된다"고 적어 둔 것과 어긋난다. 화면은 항상
        # 문자열을 보내므로 API 직접 호출·CSV 업로드 경로에서 터진다.
        if old is not None and not isinstance(old, str):
            raise MappingError(i, repr(old), "not a text value")
        if new is not None and not isinstance(new, str):
            raise MappingError(i, repr(old), "new value is not a text value")
        old = (old or "").strip()
        if not old:
            continue
        try:
            key = str(ipaddress.IPv4Address(old.split("/", 1)[0].strip()))
        except ValueError as exc:
            raise MappingError(i, old, str(exc)) from exc

        new = (new or "").strip() or None
        if new is not None:
            try:
                ipaddress.IPv4Address(new)
            except ValueError as exc:
                raise MappingError(i, old, str(exc)) from exc

        if key in seen_old:
            raise MappingError(
                i, old, f"duplicate of row {seen_old[key]}")
        seen_old[key] = i
        out[key] = new
    return out


def _substitute(ref: IpReference, new_ip: str) -> str:
    """이 참조가 갖게 될 새 텍스트.

    **매칭된 구간만** 바꾼다. 객체 이름에 IP 가 둘 들어 있어도
    (`DNAT_10.92.131.214_208.97.24.214`) 대상인 것만 바뀐다.
    프리픽스가 붙어 있으면(`10.1.2.0/24_SEG`) 프리픽스를 유지한다 —
    실 파일 참조의 75%가 프리픽스를 물고 있고, 빼먹으면 증발한다.
    """
    matched = ref.matched
    if "/" in matched:
        return new_ip + "/" + matched.split("/", 1)[1]
    return new_ip


def _mask_prefix(mask: str | None) -> int | None:
    if not mask:
        return None
    try:
        return bin(int(ipaddress.IPv4Address(mask))).count("1")
    except ValueError:
        return None


#: **한 네임스페이스를 공유하는 섹션들.** FortiOS 는 `firewall address` 와
#: `firewall addrgrp` 를 같은 이름 공간으로 본다 — 주소 객체와 같은 이름의
#: 그룹을 만들 수 없다. 충돌 키에 섹션을 그대로 넣었더니 이 둘이 갈려
#: `edit "SRV_X"`(주소)와 `edit "SRV_X"`(그룹)가 충돌로 안 잡혔고, 산출물에서
#: **그룹이 자기 자신을 멤버로 갖는** 상태가 나왔다.
_SHARED_NAMESPACE = {
    # Fortinet KB(Naming rules and character restrictions) 가 금지하는 조합:
    #   주소 ↔ 주소그룹 ↔ **가상 IP** ↔ 가상 IP 그룹
    #   서비스 ↔ 서비스그룹
    #   VLAN/VDOM ↔ **존**
    # **VIP 가 빠져 있었다** — IP 마이그레이션에서 공인 IP 로 이름 지어지는
    # 1순위 객체가 VIP 다(이 레포의 테스트 픽스처가 바로 그 관례를 쓴다).
    # 즉 이 도구의 주 용도인 ISP 전환에서 가장 자주 부딪히는 조합이었다.
    "config firewall addrgrp": "config firewall address",
    "config firewall vip": "config firewall address",
    "config firewall vipgrp": "config firewall address",
    "config firewall addrgrp6": "config firewall address6",
    "config firewall vip6": "config firewall address6",
    "config firewall vipgrp6": "config firewall address6",
    "config firewall vip46": "config firewall address",
    "config firewall vipgrp46": "config firewall address",
    "config firewall vip64": "config firewall address6",
    "config firewall vipgrp64": "config firewall address6",
    "config firewall service group": "config firewall service custom",
    "config system zone": "config system interface",
}
# **`address` 와 `address6` 는 합치지 않는다.** 기본 FortiOS 설정이 양쪽에
# `edit "all"` 을 갖는다 — 보유 config 107개 중 2개에서 실물로 확인했다.
# 합치면 거의 모든 장비에서 거짓 차단이 뜬다.


def _namespace(section_path) -> tuple:
    """이름이 겹치면 안 되는 범위. 섹션과 다르다(위 참조)."""
    return tuple(_SHARED_NAMESPACE.get(x, x) for x in section_path)


def _mask_misaligned(ref: IpReference, new_ip: str) -> bool:
    """**구 값은 마스크에 맞았는데 신 값만 깨지는** 경우만 참.

    `set subnet 10.1.2.0 255.255.255.0` 을 `192.168.7.9` 로 바꾸면 네트워크
    주소가 아니게 되고, FortiOS 는 이것을 조용히 다른 네트워크로 정규화한다.

    **절대 판정으로 하면 안 된다.** `set ip 10.1.2.1 255.255.255.0`(인터페이스
    자기 주소)·`set gateway`·`set mappedip` 은 원래 호스트 주소라 네트워크
    주소가 아닌 것이 정상이다. 실측 파일에서 이 경고 2건이 **2건 다 오탐**
    이었고, 하필 락아웃 배지가 붙은 가장 중요한 두 행에 겹쳐 떴다 — 가장
    먼저 봐야 할 행의 신호를 노이즈로 덮는다.

    **`/prefix` 표기도 본다.** 넷마스크가 따로 없는 `set subnet 10.0.0.0/24`
    는 프리픽스를 못 읽어 검사를 통째로 건너뛰고 있었다(미탐). FortiOS 는
    `172.16.100.128/24` 를 조용히 `172.16.100.0/24` 로 정규화해 객체 범위를
    128개 주소만큼 옮긴다.
    """
    p = _mask_prefix(ref.mask)
    if p is None and "/" in ref.matched:
        try:
            p = int(ref.matched.split("/", 1)[1])
        except ValueError:
            p = None
    if p is None or p >= 32:
        return False

    def _aligned(ip: str) -> bool:
        try:
            ipaddress.IPv4Network(f"{ip}/{p}", strict=True)
            return True
        except ValueError:
            return False

    return _aligned(_norm_ip(ref.matched)) and not _aligned(new_ip)


def _edit_block(lines: list[str], line_no: int) -> tuple[int, int]:
    """그 줄이 속한 `edit … next` 블록의 범위(0-based, 반열림)."""
    i = line_no - 1
    start = i
    while start > 0 and not lines[start].strip().startswith("edit "):
        if lines[start].strip() in ("end", "next") and start != i:
            break
        start -= 1
    end = i
    while end < len(lines) and lines[end].strip() != "next":
        end += 1
    return start, min(end + 1, len(lines))


_DEVICE_RE = re.compile(r'^\s*set (?:device|interface)\s+"?([^"\s]+)"?')


def _gateway_warnings(lines: list[str], plan: MigrationPlan) -> None:
    """**게이트웨이가 그 인터페이스 대역 밖으로 나가나.**

    인터페이스를 새 대역으로 옮기면서 게이트웨이를 옛 대역에 그대로 두면,
    재부팅 후 기본 경로가 inactive 가 되어 장비가 인터넷에서 사라진다.
    실 고객 파일에 정적 경로 8개와 인터페이스 IP 197개가 있다.

    **회귀 판정으로만 한다** — 원래 대역 안에 있던 것이 이번 변경으로 밖으로
    나가는 경우만 센다. 원래부터 어긋나 있었으면 우리가 만든 문제가 아니고,
    정상 작업마다 뜨는 경고는 진짜 경고를 죽인다(이 파일에서 넷 있었다).
    """
    # 인터페이스별 (구 IP, 신 IP, 프리픽스)
    ifaces: dict[tuple, tuple[str, str, int]] = {}
    for row in plan.rows:
        r = row.ref
        if r.field != "ip" or "config system interface" not in r.section_path:
            continue
        prefix = _mask_prefix(r.mask)
        if prefix is None or not r.edit:
            continue
        old_ip = _norm_ip(r.matched)
        ifaces[(r.vdom, r.edit)] = (old_ip, _norm_ip(row.new_text or r.matched),
                                    prefix)
    if not ifaces:
        return

    def _inside(ip: str, net_ip: str, prefix: int) -> bool:
        try:
            net = ipaddress.ip_network(f"{net_ip}/{prefix}", strict=False)
            return ipaddress.IPv4Address(ip) in net
        except ValueError:
            return False

    for row in plan.rows:
        r = row.ref
        if r.field != "gateway":
            continue
        start, end = _edit_block(lines, r.line_no)
        dev = None
        for ln in lines[start:end]:
            m = _DEVICE_RE.match(ln)
            if m:
                dev = m.group(1)
                break
        if dev is None:
            continue                      # 어느 인터페이스인지 모르면 말 안 한다
        got = ifaces.get((r.vdom, dev))
        if not got:
            continue
        old_ip, new_ip, prefix = got
        old_gw = _norm_ip(r.matched)
        new_gw = _norm_ip(row.new_text or r.matched)
        if _inside(old_gw, old_ip, prefix) and not _inside(new_gw, new_ip, prefix):
            row.warnings.append(WARN_GATEWAY_OFF_SUBNET)
            row.reason_arg = row.reason_arg or dev


def _collect_name_edit(ref: IpReference, new_text: str, edits: dict) -> None:
    """객체 이름 **안에서** 바뀌는 구간을 모은다 — 자동 RENAME 계산의 1단계.

    `edit "NAT_10.1.2.3"` 의 참조는 이름이 아니라 `10.1.2.3` 조각이라,
    새 이름을 얻으려면 이름 안 몇 번째 열이 바뀌는지를 알아야 한다.

    **같은 자리는 한 번만.** 같은 이름이 여러 줄에 정의되면 같은 치환이
    여러 번 쌓여 두 번 적용된다. **VDOM 을 키에 넣는다** — 이름만 키로
    쓰면 아무 VDOM 이든 한 번만 정의된 이름이 전 VDOM 에서 자동 변경된다.
    """
    whole = ref.enclosing_name
    if not whole:
        return
    at = ref.raw_line.find(whole)
    lo = ref.col_start - at if at >= 0 else -1
    if lo >= 0 and whole[lo:lo + len(ref.matched)] == ref.matched:
        edits.setdefault((ref.vdom, whole), {})[(lo, len(ref.matched))] = new_text


def _fold_name_edits(edits: dict) -> dict:
    """모은 구간을 **오른쪽부터** 적용해 새 이름을 만든다.

    정순으로 하면 첫 치환에서 길이가 변할 때 두 번째 오프셋이 밀린다.
    이름에 대상 IP 가 둘 있으면 `NAT_172.16.20172.16.20.31.0.9` 같은
    **존재하지 않는 문자열**이 나온다(파일 자체는 `apply_plan` 이 역순이라
    옳다 — 그래서 더 안 보인다).
    """
    out: dict[tuple[str | None, str], str] = {}
    for key, per_name in edits.items():
        name = key[1]
        for (lo, length), txt in sorted(per_name.items(), reverse=True):
            name = name[:lo] + txt + name[lo + length:]
        out[key] = name
    return out


def _auto_renames(references, mapping) -> dict[tuple[str | None, str], str]:
    """`build_plan` 의 자동 RENAME 이 내놓을 (vdom, 옛 이름) → 새 이름.

    **계산을 다시 쓰지 말고 같은 것을 쓴다.** 3단계 화면이 보여줄 제안값과
    실제 적용되는 이름이 갈리면, 표를 결재에 올린 사람이 없는 이름을
    승인하게 된다(2026-09-08 실사용 보고와 같은 종류의 결함).
    """
    edits: dict = {}
    for ref in references:
        if ref.role != "object_name" or ref.match_kind in ("supernet", "overlap"):
            continue
        mapped = mapping.get(_norm_ip(ref.matched))
        if not mapped:
            continue
        _collect_name_edit(ref, _substitute(ref, mapped), edits)
    return _fold_name_edits(edits)


def _parse_name_mapping(name_mapping) -> dict[tuple[str | None, str], str]:
    """사용자가 3단계에서 적은 객체 이름 표를 정규화한다.

    받는 형태: `[{"vdom":…, "old":…, "new":…}, …]` 또는 `{(vdom, old): new}`.

    **빈 TO-BE 는 '변경 안 함'이지 삭제가 아니다.** 자기 자신과 같은 이름도
    마찬가지로 아무 일도 일어나지 않아야 하므로 여기서 떨군다 — 아래로
    흘려보내면 `renamed` 에 항등 항목이 남아 참조가 "따라간다"고 표시되는데
    정작 바뀌는 것은 없다.
    """
    if not name_mapping:
        return {}

    items: list[tuple] = []
    if isinstance(name_mapping, dict):
        for key, new in name_mapping.items():
            if isinstance(key, (tuple, list)) and len(key) == 2:
                items.append((key[0], key[1], new))
            else:
                items.append((None, key, new))
    else:
        for row in name_mapping:
            if isinstance(row, dict):
                items.append((row.get("vdom"), row.get("old"), row.get("new")))
            else:
                cells = (list(row) + [None, None, None])[:3]
                items.append((cells[0], cells[1], cells[2]))

    out: dict[tuple[str | None, str], str] = {}
    for i, (vdom, old, new) in enumerate(items, start=1):
        # **타입을 먼저 본다.** `(x or "").strip()` 은 x 가 숫자·리스트면
        # AttributeError 로 500 이 된다 — 사용자 입력 오류에 500 을 주면
        # 안 된다는 것이 이 레포의 라우트 규칙이다(`parse_mapping` 과 같다).
        if old is not None and not isinstance(old, str):
            raise MappingError(i, repr(old), "not a text value")
        if new is not None and not isinstance(new, str):
            raise MappingError(i, repr(old), "new value is not a text value")
        if vdom is not None and not isinstance(vdom, str):
            raise MappingError(i, repr(old), "vdom is not a text value")
        old = (old or "").strip()
        new = (new or "").strip()
        if not old or not new or new == old:
            continue
        # **따옴표·개행이 든 이름은 받지 않는다.** 좌표 치환이라 적은 그대로
        # 파일에 들어가는데, 이스케이프 안 된 따옴표 하나로 장비가 부팅에
        # 실패한 사례가 있다(이 모듈 상단 `Initialize config error 44010`).
        if any(c in new for c in '"\r\n'):
            raise MappingError(i, old, "new name contains a quote or newline")
        out[((vdom or None), old)] = new
    return out


def _walk_names(lines, wanted: set) -> tuple[list[IpReference], list[tuple]]:
    """원문을 훑어 ① `wanted` 이름이 쓰인 자리 ② 모든 `edit "이름"` 을 찾는다.

    **왜 스캐너를 다시 쓸 수 없나.** `scan()` 은 IP 토큰이 있는 줄만 참조로
    낸다. `SEOUL_WEB_SRV` 처럼 이름에 IP 가 없는 객체는 `edit` 줄도
    `set dstaddr` 줄도 결과에 없어 **바꿀 좌표가 아예 없다**. 자동 RENAME 이
    "이름에 IP 가 있을 때만" 도는 이유가 이것이고, 사용자가 임의 이름을
    고치려면 이름 전용 탐색 경로가 따로 있어야 한다.

    찾는 자리는 두 가지뿐이다:
      · 정의 — `edit "OLD"` 의 따옴표 안 전체
      · 참조 — 객체 참조 필드(`_NAME_REF_FIELDS`/섹션 한정 필드)의 따옴표
        값이 `OLD` 와 **완전히 같을 때만**. 부분 일치를 허용하면 `WEB` 이
        `WEB_DB` 를 건드린다.

    VDOM 이 다르면 같은 이름이어도 다른 객체다 — 키에 VDOM 이 들어간다.
    """
    sites: list[IpReference] = []
    edit_names: list[tuple] = []

    config_stack: list[str] = []
    edit_depth_stack: list[int] = []
    edit_stack: list[str] = []
    vdom: str | None = None
    vdom_depth = 0
    in_multiline = False

    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.strip()

        # 여러 줄에 걸친 따옴표 값(인증서·PSK) 안은 설정이 아니다.
        odd_quote = len(_unescaped_quotes(raw)) % 2 == 1
        if in_multiline:
            if odd_quote:
                in_multiline = False
            continue
        if odd_quote:
            in_multiline = True
            continue
        # 주석은 FortiOS 가 실행하지 않는다. 이름을 고쳐 봐야 장비에
        # 아무 일도 안 일어나므로 건드리지 않는다(설계의 '알려야 할 한계').
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("config "):
            config_stack.append(stripped)
            edit_depth_stack.append(len(edit_stack))
            if stripped == "config vdom" and not config_stack[:-1]:
                vdom_depth = len(config_stack)
            continue
        if stripped.startswith("edit "):
            token = stripped[5:].strip()
            name = token.strip('"')
            if vdom_depth and len(config_stack) == vdom_depth:
                vdom = name
                continue
            edit_stack.append(name)
            quoted = (len(token) >= 2 and token.startswith('"')
                      and token.endswith('"'))
            if not quoted:
                # **번호 edit(`edit 101`)은 이름이 없다.** 개명 대상이 아니고
                # 전수 이름 목록에도 들어가면 안 된다(정책 번호가 이름 충돌
                # 검사에 섞인다). 섹션 이름 목록이 아니라 구조로 막는다.
                continue
            edit_names.append((vdom, tuple(config_stack), name, line_no))
            if (vdom, name) not in wanted:
                continue
            for lo, hi in _quoted_spans(raw):
                if raw[lo + 1:hi] != name:
                    continue
                sites.append(_name_site(
                    line_no, raw, vdom, config_stack, edit_stack,
                    "", name, lo + 1, hi, "object_name"))
                break
            continue
        if stripped == "next":
            if edit_stack:
                edit_stack.pop()
            continue
        if stripped == "end":
            if config_stack:
                popped = config_stack.pop()
                depth = edit_depth_stack.pop() if edit_depth_stack else 0
                del edit_stack[depth:]
                if popped == "config vdom" and not config_stack:
                    vdom, vdom_depth = None, 0
            continue

        fname = _field_name(stripped)
        if not fname or not _is_name_ref_field(fname, config_stack):
            continue
        # `set member "A" "B" "C"` — 값 하나하나가 따로 따옴표에 싸인다.
        for lo, hi in _quoted_spans(raw):
            inner = raw[lo + 1:hi]
            if (vdom, inner) in wanted:
                sites.append(_name_site(
                    line_no, raw, vdom, config_stack, edit_stack,
                    fname, inner, lo + 1, hi, "name_reference"))

    return sites, edit_names


def _name_site(line_no, raw, vdom, config_stack, edit_stack,
               fname, name, col_start, col_end, role) -> IpReference:
    """이름 한 자리를 `IpReference` 로 합성한다.

    **`matched` 는 반드시 `raw[col_start:col_end]` 와 같아야 한다.**
    `apply_plan` 이 치환 직전에 그 둘을 대조해 다르면 손대지 않는데
    (계획 이후 파일이 바뀌었다는 뜻이다), 합성 행도 그 안전검사를 그대로
    통과해야 한다. 여기서만 예외를 두면 안전망이 절반이 된다.
    """
    return IpReference(
        line_no=line_no,
        raw_line=raw,
        vdom=vdom,
        section=config_stack[-1] if config_stack else "",
        section_path=list(config_stack),
        edit=edit_stack[-1] if edit_stack else None,
        edit_path=list(edit_stack),
        edit_quoted=True,       # 따옴표 없는 edit 은 여기까지 오지 않는다
        field=fname,
        matched=name,
        # IP 토큰 매칭이 아니라 이름 매칭이다. 이름은 부분 일치를 허용하지
        # 않으므로 관계는 언제나 '완전히 같음' 하나뿐이다.
        match_kind="exact",
        col_start=col_start,
        col_end=col_end,
        role=role,
        enclosing_name=name,
    )


def _covered(ref: IpReference, spans: dict) -> bool:
    """이 참조가 **사용자가 통째로 바꾸는 이름** 안에 들어 있나.

    들어 있으면 자동 행(이름 안 IP 조각만 바꾸는 행)을 만들면 안 된다.
    같은 줄에 좌표가 겹치는 편집이 둘이면 `apply_plan` 이 뒤에 오는 것을
    `matched` 불일치로 **조용히 버린다**(WARN_SOURCE_CHANGED). 둘 중
    무엇이 살아남는지는 열 위치가 정하므로, 결과가 우연에 달리게 된다.
    """
    for lo, hi in spans.get(ref.line_no, ()):
        if ref.col_start < hi and lo < ref.col_end:
            return True
    return False


def _user_rename_rows(lines, user_renames: dict) -> tuple[list, list, dict]:
    """사용자가 적은 이름을 계획 행으로 만든다.

    돌려주는 것 셋: 행 목록 · 파일 안 모든 `edit "이름"` 목록(이름 충돌
    검사용) · **실제로 적용되는 개명 표**.

    **정의(`edit "OLD"`)를 못 찾은 개명은 통째로 버린다.** 참조만 바꾸면
    없는 객체를 가리키는 줄을 우리 손으로 만드는 셈이다. 다른 VDOM 에
    있거나, 이 백업에 없거나, 번호 edit(`edit 101`)을 적었을 때가 여기다 —
    번호 edit 은 따옴표가 없어 `_walk_names` 에서 구조적으로 걸러진다.
    """
    sites, edit_names = _walk_names(lines, set(user_renames))
    defined = {(r.vdom, r.enclosing_name)
               for r in sites if r.role == "object_name"}

    rows: list[PlanRow] = []
    for ref in sites:
        key = (ref.vdom, ref.enclosing_name)
        if key not in defined:
            continue
        new_name = user_renames[key]
        if ref.role == "object_name":
            rows.append(PlanRow(ref, ACTION_RENAME, new_name,
                                reason=REASON_USER_NAME,
                                reason_arg=ref.enclosing_name))
        else:
            rows.append(PlanRow(ref, ACTION_FOLLOW, new_name,
                                reason=REASON_FOLLOW,
                                reason_arg=ref.enclosing_name))
    applied = {k: v for k, v in user_renames.items() if k in defined}
    return rows, edit_names, applied


def _named_owner(ref: IpReference) -> tuple[str, str] | None:
    """이 참조를 소유한 **이름 객체**와 그 객체가 정의된 섹션.

    `edit_path` 를 안쪽부터 훑어 **따옴표로 감싼 가장 안쪽 이름**을 고른다.
    전부 번호면 바꿀 이름이 없으므로 `None`.

    **가장 안쪽 edit 하나만 보면 안 된다.** 대상 대역 참조가 중첩 번호
    블록 안에만 있는 객체가 실제로 있다:

        config firewall vip
            edit "PUB_WEB"
                config realservers
                    edit 1
                        set ip 10.20.40.6

    가장 안쪽은 `edit 1`(번호)이라 후보에서 빠지는데, 정작 이 IP 를 들고
    있는 **바꿀 수 있는 이름**은 바깥의 `PUB_WEB` 이다. 섹션 이름을 목록으로
    박지 않고 구조(따옴표 유무)로만 올라간다 — FortiOS 섹션은 버전마다
    늘어서 목록은 다음 버전에서 조용히 뚫린다.

    섹션은 **그 이름이 정의된 곳**을 준다. 가장 안쪽 섹션
    (`config realservers`)을 주면 관리자가 장비에서 그 객체를 찾을 수 없다.
    """
    names = ref.edit_path or []
    quoted = ref.edit_quoted_path or []
    sections = ref.edit_section_path or []

    # **레벨 정보가 없는 합성 참조를 위한 퇴로.** `_name_site` 처럼 스캐너를
    # 거치지 않고 만든 `IpReference` 는 레벨별 경로가 비어 있다. 그때는
    # 예전과 같이 가장 안쪽 것만 본다(정보가 그것뿐이다).
    if not quoted:
        if ref.edit_quoted and ref.edit:
            return ref.edit, ref.section
        return None

    for i in range(min(len(names), len(quoted)) - 1, -1, -1):
        if not quoted[i]:
            continue
        return names[i], (sections[i] if i < len(sections) else ref.section)
    return None


def rename_candidates(lines, target, mapping=None) -> list[dict]:
    """대상 대역을 건드리는 객체 중 **이름으로 식별되는 것**만 나열한다.

    3단계의 이름 AS-IS/TO-BE 표가 쓴다. 전 객체를 내면 수백 줄이 되므로
    이번 마이그레이션이 실제로 건드리는 것만 낸다.

    **번호 edit 은 구조적으로 빠진다**(`edit_quoted_path`). `config firewall
    policy`·`config router static` 은 `edit 101` 이라 바꿀 이름이 없다.
    다만 번호 블록이 **이름 객체 안에 중첩**돼 있으면 바깥 이름을 올려 준다
    (`_named_owner` 참조) — `config firewall vip` 의 `config realservers`
    처럼 값이 번호 블록에만 사는 객체가 통째로 목록에서 빠지고 있었다.

    `mapping` 을 주면 `suggested` 에 **자동 RENAME 이 내놓을 이름**을 채운다
    (없으면 `None`). 화면은 이 값을 미리 채워 두고 사용자가 고치게 한다.
    """
    res = scan(lines, target)
    auto = _auto_renames(res.references, mapping or {})

    # 스캔 순서 = 파일 순서. 아래 정렬이 안정 정렬이라 같은 이름끼리는
    # 파일에 나온 차례가 유지된다.
    #
    # **참조 하나는 객체 하나에만 센다.** 중첩 블록의 참조를 바깥 이름에도
    # 더하면서 안쪽 몫으로도 세면 같은 줄이 두 번 계산돼, 표의 "참조 N건"이
    # 관리자가 파일에서 확인할 수 있는 수와 달라진다.
    counts: dict[tuple, int] = {}
    for ref in res.references:
        owner = _named_owner(ref)
        if owner is None:
            continue
        name, section = owner
        key = (ref.vdom, name, section)
        counts[key] = counts.get(key, 0) + 1

    out = []
    for (vdom, name, section), refs in counts.items():
        suggested = auto.get((vdom, name))
        out.append({
            "vdom": vdom,
            "name": name,
            "section": section,
            "refs": refs,
            "suggested": suggested if suggested and suggested != name else None,
        })
    out.sort(key=lambda d: d["name"])
    return out


def build_plan(lines, target, mapping, name_mapping=None) -> MigrationPlan:
    """구 대역을 훑어 변경 계획을 만든다.

    `name_mapping` 은 사용자가 3단계에서 직접 적은 객체 이름 표다
    (`[{"vdom":…, "old":…, "new":…}, …]` 또는 `{(vdom, old): new}`).
    **자동 제안을 이긴다** — 사용자가 적은 것이 최종 이름이다.
    """
    res = scan(lines, target)
    plan = MigrationPlan(scan_result=res)

    # 신 IP 가 이미 이 config 에 있나 — 겹치면 두 개가 같은 주소가 된다.
    full = scan(lines, "0.0.0.0/0")
    existing = {r.matched.split("/")[0] for r in full.references}

    # 두 구 IP 가 같은 신 IP 로 가나 — 객체가 합쳐진다.
    by_new: dict[str, list[str]] = {}
    for old, new in mapping.items():
        if new:
            by_new.setdefault(_norm_ip(new), []).append(old)
    plan.new_ip_collisions = {k: sorted(v) for k, v in by_new.items() if len(v) > 1}
    plan.new_ips_in_use = sorted(
        n for n in by_new if n in existing and n not in mapping)

    renamed: dict[tuple[str | None, str], str] = {}   # (vdom, 옛이름) → 새이름
    name_edits: dict[tuple[str | None, str], list[tuple[int, int, str]]] = {}
    value_ips: set[str] = set()      # 실제 설정값으로 나타난 IP 만 매핑 대상
    supernets: set[str] = set()

    # ── 사용자가 직접 적은 이름 ────────────────────────────────────────
    # **자동 행보다 먼저 좌표를 잡는다.** 사용자가 이름을 통째로 바꾸는
    # 자리와 자동 행(이름 안 IP 조각)이 같은 줄에서 겹치면 `apply_plan` 이
    # 뒤에 오는 편집을 조용히 버린다. 겹치는 자동 행은 아예 만들지 않는다.
    user_renames = _parse_name_mapping(name_mapping)
    user_rows: list[PlanRow] = []
    edit_names: list[tuple] = []
    user_spans: dict[int, list[tuple[int, int]]] = {}
    if user_renames:
        user_rows, edit_names, user_renames = _user_rename_rows(
            lines, user_renames)
        for row in user_rows:
            user_spans.setdefault(row.ref.line_no, []).append(
                (row.ref.col_start, row.ref.col_end))

    # ── 1차: 값·이름 행 ────────────────────────────────────────────────
    for ref in res.references:
        if user_spans and _covered(ref, user_spans):
            continue          # 사용자가 이 이름을 통째로 바꾼다(위 참조).
        if ref.role == "name_reference":
            continue          # **2차 루프가 전담한다.** 여기서 처리하면
                              # 같은 참조에 모순되는 행이 두 개 생긴다.
        ip = _norm_ip(ref.matched)

        if ref.role == "comment":
            # FortiOS 가 실행하지 않는 줄이다. **미매핑으로 세지 않는다** —
            # 고칠 수 없는 것 때문에 파일 생성이 막히면, 사용자는 확인
            # 체크박스를 눌러 진짜 미매핑까지 함께 통과시킨다.
            plan.rows.append(PlanRow(ref, ACTION_REVIEW, reason=REASON_COMMENT))
            continue

        if ref.match_kind in ("supernet", "overlap"):
            # **대상 대역을 포함할 뿐인 객체다.** 바꾸면 정책 범위가 통째로
            # 달라진다(실측: `10.0.0.0/8` 이 정책 11곳에서 쓰인다).
            supernets.add(ip)
            row = PlanRow(ref, ACTION_SUPERNET, reason=REASON_SUPERNET,
                          reason_arg=ip)
            if mapping.get(ip):
                # 사용자가 실수로 채웠다. 바꾸면 이 객체를 쓰는 정책 전부의
                # 범위가 달라진다(실측: `10.0.0.0/8` 이 정책 11곳에서 쓰인다).
                row.warnings.append(WARN_SUPERNET_MAPPED)
            plan.rows.append(row)
            continue

        value_ips.add(ip)
        mapped = mapping.get(ip, "__ABSENT__")

        if mapped == "__ABSENT__":
            plan.rows.append(PlanRow(ref, ACTION_UNMAPPED,
                                     reason=REASON_ABSENT, reason_arg=ip))
            continue
        if mapped is None:
            plan.rows.append(PlanRow(ref, ACTION_UNMAPPED,
                                     reason=REASON_RETIRED, reason_arg=ip))
            continue

        new_text = _substitute(ref, mapped)

        if ref.role == "value":
            row = PlanRow(ref, ACTION_CHANGE, new_text,
                          reason=REASON_VALUE, reason_arg=ip)
            if ref.is_admin_access:
                row.warnings.append(WARN_LOCKOUT)
            if _mask_misaligned(ref, mapped):
                row.warnings.append(WARN_MASK_MISALIGNED)
            if _norm_ip(mapped) in plan.new_ip_collisions:
                row.warnings.append(WARN_NEW_IP_COLLISION)
            if _norm_ip(mapped) in plan.new_ips_in_use:
                row.warnings.append(WARN_NEW_IP_IN_USE)
            plan.rows.append(row)

        elif ref.role == "object_name":
            row = PlanRow(ref, ACTION_RENAME, new_text,
                          reason=REASON_NAME, reason_arg=ip)
            if _norm_ip(mapped) in plan.new_ip_collisions:
                row.warnings.append(WARN_NEW_IP_COLLISION)
            plan.rows.append(row)
            # 이름 안에서 바뀌는 구간을 모아 둔다. 새 이름은 아래에서
            # 한꺼번에 접는다(`_collect_name_edit`/`_fold_name_edits`).
            _collect_name_edit(ref, new_text, name_edits)

    renamed.update(_fold_name_edits(name_edits))

    # **사용자가 적은 이름이 자동 제안을 이긴다.** 3단계에서 제안값을
    # 고쳤는데 자동값이 파일에 들어가면, 화면과 산출물과 장비가 셋 다
    # 다른 이름을 말하게 된다.
    renamed.update(user_renames)

    plan.renamed_names = [
        {"vdom": v, "old": o, "new": n}
        for (v, o), n in sorted(renamed.items(), key=lambda kv: kv[0][1])
        if n != o]

    # ── 개명 결과가 다른 객체와 같아지나 ───────────────────────────────
    # **전체 파일에서 이름을 모은다.** 대상 대역으로 스코프된 스캔에서
    # 모으면 가장 잡아야 할 충돌이 구조적으로 안 보인다 — 개명 결과
    # 이름은 정의상 **신 IP** 를 품는데 신 IP 는 대상 대역 밖이기 때문이다.
    # 실측: `SRV_10.0.0.5` → `SRV_172.16.20.30` 이 기존 `SRV_172.16.20.30`
    # 과 겹치는데 경고도 차단도 없이 파일이 나갔다. FortiOS 는 두 번째
    # `edit "X"` 를 첫 객체 **편집**으로 처리하므로 객체 하나가 통째로
    # 사라지고, 그것을 쓰던 정책이 조용히 다른 대상에 붙는다.
    # **정의는 섹션째로 모으고, 비교할 때만 이름공간으로 접는다.**
    # 처음부터 접어서 모으면 `firewall address` 의 `SRV_X` 와 `firewall vip`
    # 의 `SRV_X` 가 집합에서 **하나로 합쳐져**, 둘이 같은 이름으로 개명돼도
    # 출처가 하나로 보여 충돌이 안 잡힌다. 게다가 그 둘이 "원래 중복"으로
    # 분류돼 `verify` 까지 눈을 감는다 — 합치기가 곧 은폐였다.
    all_names = {(r.vdom, tuple(r.section_path), r.enclosing_name)
                 for r in full.references
                 if r.role == "object_name" and r.enclosing_name}

    # **원본이 이미 깨져 있었는지 기억한다.** 결과 파일만 보면 원래 있던
    # 깨진 참조를 우리가 만든 것으로 보고하게 되고, 정상 작업마다 4단계가
    # 빨간 글씨를 띄운다 — 몇 번 겪으면 그 문장이 무시돼 **진짜로 우리가
    # 깨뜨린 참조**가 같이 묻힌다.
    _defined_orig = {(r.vdom, r.enclosing_name) for r in full.references
                     if r.role == "object_name" and r.enclosing_name}
    plan.preexisting_dangling = {
        (r.vdom, r.enclosing_name) for r in full.references
        if r.role == "name_reference" and r.enclosing_name
        and (r.vdom, r.enclosing_name) not in _defined_orig}

    # 중복 `edit` 도 마찬가지다 — 원본이 원래 중복이었으면 우리 잘못이
    # 아니다. **다만 "원래 있던 만큼만" 면제한다**(개수 기준).
    _orig_lines: dict[tuple, set] = {}
    for r in full.references:
        if r.role != "object_name" or not r.enclosing_name:
            continue
        k = (r.vdom, _namespace(r.section_path), r.enclosing_name)
        # **같은 줄은 중복이 아니다.** 이름 하나에 IP 가 둘 있으면 그 줄에서
        # 참조가 둘 나온다(실 파일에서 주장 16건이 전부 이것이었다).
        _orig_lines.setdefault(k, set()).add(r.line_no)
    for k, lns in _orig_lines.items():
        if len(lns) > 1:
            # **더한다.** 서로 다른 원본 이름 둘이 같은 이름으로 개명되면
            # 개명 후 키가 같아진다 — `=` 로 쓰면 나중 것이 앞 것을 덮어
            # 기준선이 실제보다 작아지고, 원본에 있던 멀쩡한 줄이 "우리가
            # 만든 중복"으로 보고된다(파일 순서에 따라 값이 달라졌다).
            key = (k[0], k[1], renamed.get((k[0], k[2]), k[2]))
            plan.preexisting_duplicates[key] = (
                plan.preexisting_duplicates.get(key, 0) + len(lns) - 1)

    # **개명 후 이름끼리 비교한다.** 개명 전 집합과 대조하면 연쇄
    # (A→B, B→C)에서 없는 충돌이 잡힌다 — 대역 내 재번호는 가장 흔한
    # 작업이라 오탐이 반복되고, 그러면 사용자가 확인 체크박스를 습관적으로
    # 켜서 **진짜 충돌까지 같은 배치로 통과시킨다.**
    _final: dict[tuple, list[str]] = {}
    for _v, _sec, _n in all_names:
        _new = renamed.get((_v, _n), _n)
        _final.setdefault((_v, _namespace(_sec), _new), []).append(_n)
    # **이름이 아니라 키로 센다.** 이름만 모아 두면 `firewall address` 에서
    # 난 충돌이 같은 이름을 가진 다른 이름공간의 행에도 옮겨 붙는다.
    _collided = {k for k, srcs in _final.items() if len(srcs) > 1}
    plan.name_collisions = sorted({k[2] for k in _collided})
    # 어느 행이 그 이름을 만드는지 표에서 보여야 한다 — 충돌하는 새 이름만
    # 나열하면 5,000행짜리 계획표에서 원본 행을 찾을 방법이 없다.
    # **섹션까지 넣는다.** `(vdom, 이름)` 만으로 붙이면 `firewall address`
    # 에서 난 충돌 경고가 같은 이름의 `service custom` 행에도, 심지어 다른
    # VDOM 의 동명 행에도 붙는다(둘 다 중복이 아닌데).
    _collided_keys = {
        (_v, _namespace(_sec), _n) for _v, _sec, _n in all_names
        if (_v, _namespace(_sec), renamed.get((_v, _n), _n)) in _collided}

    # ── 사용자가 적은 이름이 **이미 있는 이름**과 부딪히나 ─────────────
    # 위 검사는 `all_names`(= IP 참조에서 모은 이름)만 알아서 `WEB_DB` 처럼
    # **IP 가 없는 기존 객체**를 구조적으로 못 본다. 사용자는 그런 이름을
    # 얼마든지 적을 수 있고, FortiOS 는 두 번째 `edit "X"` 를 첫 객체 편집으로
    # 처리해 객체 하나를 삼킨다. 전수 `edit` 목록과 대조한다.
    #
    # **사용자 개명이 낀 것만 충돌로 본다.** 전수 목록을 무조건 위 검사에
    # 넣으면 이름공간 병합(addrgrp→address) 때문에 원본에 원래 있던 조합이
    # 거짓 충돌로 잡혀, 이름을 하나도 안 바꾸는 작업까지 막힌다. 우리가
    # 만드는 충돌만 막는다.
    if user_renames:
        _by_final: dict[tuple, set] = {}
        for _v, _sec, _n, _ln in edit_names:
            _by_final.setdefault(
                (_v, _namespace(_sec), renamed.get((_v, _n), _n)), set()).add(_n)
        for _key, _olds in _by_final.items():
            if len(_olds) < 2 or not any((_key[0], _o) in user_renames
                                         for _o in _olds):
                continue
            _collided.add(_key)
            for _o in _olds:
                _collided_keys.add((_key[0], _key[1], _o))
        plan.name_collisions = sorted({k[2] for k in _collided})

    # ── 2차: 이름 참조는 위에서 정해진 이름을 따라간다 ─────────────────
    for ref in res.references:
        if ref.role != "name_reference":
            continue
        if user_spans and _covered(ref, user_spans):
            continue          # 사용자가 이 이름을 통째로 바꾼다(위 참조).
        if ref.match_kind in ("supernet", "overlap"):
            # **1차 루프와 같은 가드다.** 없으면 이름 안의 상위 대역 토큰까지
            # 바꿔, 객체 정의는 그대로인데 정책만 바뀐 **깨진 참조**가 생긴다
            # (실측: dangling 2건인데 blocking 은 비어 있었다).
            plan.rows.append(PlanRow(ref, ACTION_SUPERNET,
                                     reason=REASON_SUPERNET,
                                     reason_arg=_norm_ip(ref.matched)))
            continue
        whole = ref.enclosing_name
        key = (ref.vdom, whole) if whole else None
        if key and key in renamed:
            ip = _norm_ip(ref.matched)
            mapped = mapping.get(ip)
            plan.rows.append(PlanRow(
                ref, ACTION_FOLLOW,
                _substitute(ref, mapped) if mapped else None,
                reason=REASON_FOLLOW, reason_arg=whole))
            plan.renamed_objects[whole] = plan.renamed_objects.get(whole, 0) + 1
        elif whole and mapping.get(_norm_ip(ref.matched)):
            # **정의를 못 찾았다.** 다른 VDOM 에 있거나 이 백업에 없거나
            # 이름이 우연히 IP 처럼 생긴 것일 수 있다. 추측하지 않는다.
            row = PlanRow(ref, ACTION_REVIEW,
                          reason=REASON_UNRESOLVED, reason_arg=whole)
            row.warnings.append(WARN_UNRESOLVED_NAME)
            plan.rows.append(row)
        else:
            plan.rows.append(PlanRow(ref, ACTION_REVIEW, reason=REASON_KEEP_NAME))

    # ── 사용자 지정 이름 행 ────────────────────────────────────────────
    # 아래 이름 충돌 경고 루프에 **함께 태운다** — 사용자가 적은 이름이야말로
    # 충돌 경고가 가장 필요한 행이다.
    for row in user_rows:
        plan.rows.append(row)
        if row.action == ACTION_FOLLOW and row.ref.enclosing_name:
            _w = row.ref.enclosing_name
            plan.renamed_objects[_w] = plan.renamed_objects.get(_w, 0) + 1

    # 정의만 되고 한 번도 안 붙던 상수였다 — 화면 사전에는 문구가 있는데
    # 엔진이 안 써서 영원히 안 뜨는 경고였다.
    if _collided_keys:
        for row in plan.rows:
            if row.action not in (ACTION_RENAME, ACTION_FOLLOW):
                continue
            _n = row.ref.enclosing_name
            if _n and (row.ref.vdom, _namespace(row.ref.section_path),
                       _n) in _collided_keys:
                row.warnings.append(WARN_NAME_COLLISION)

    _gateway_warnings(lines, plan)

    plan.unmapped_ips = sorted(
        ip for ip in value_ips
        if mapping.get(ip, "__ABSENT__") == "__ABSENT__")
    plan.retired_ips = sorted(ip for ip in value_ips if mapping.get(ip) is None
                              and ip in mapping)
    plan.supernet_ips = sorted(supernets)
    plan.rows.sort(key=lambda r: ((0 if r.ref.is_admin_access else 1),
                                  r.ref.line_no, r.ref.col_start))
    return plan


def apply_plan(lines, plan: MigrationPlan) -> list[str]:
    """계획대로 원문을 고친 새 라인 목록을 만든다.

    **뒤에서부터 바꾼다.** 앞을 먼저 바꾸면 길이가 변해 같은 줄의 뒤쪽
    좌표가 밀린다. 한 줄에 참조가 둘 이상인 경우가 실제로 있다
    (실측: addrgrp member 줄에 최대 26건).
    """
    out = list(lines)
    edits = [r for r in plan.rows if r.new_text is not None]
    for row in sorted(edits,
                      key=lambda r: (r.ref.line_no, r.ref.col_start),
                      reverse=True):
        ref = row.ref
        i = ref.line_no - 1
        if i < 0 or i >= len(out):
            continue
        line = out[i]
        # 원문이 우리가 본 것과 같은지 확인한다. 다르면 건드리지 않는다 —
        # 계획을 세운 뒤 파일이 바뀌었다는 뜻이고, 그 상태로 치환하면
        # 엉뚱한 자리를 자른다.
        if line[ref.col_start:ref.col_end] != ref.matched:
            row.warnings.append(WARN_SOURCE_CHANGED)
            continue
        out[i] = line[:ref.col_start] + row.new_text + line[ref.col_end:]
    return out


#: 객체 참조가 아니라 **사람이 읽는 자유 텍스트**인 필드. 여기 든 이름은
#: 정의를 찾을 대상이 아니다 — 스캐너의 역할 폴백이 "따옴표 안에 IP 아닌
#: 글자가 섞였으면 이름 참조"로 정하기 때문에 `set hostname "fgt-10.0.0.5"`
#: 나 IP 를 넣은 정책 이름이 전부 "깨진 참조"로 보고됐다(실측: 정상
#: 마이그레이션이 항상 clean=False 로 끝났다).
_FREE_TEXT_FIELDS = frozenset({
    "name", "hostname", "alias", "description", "comment", "comments",
    "ssid", "subject", "label",
})


def verify(new_lines, target, mapping, plan: MigrationPlan | None = None) -> dict:
    """**자기 산출물을 자기가 검사한다.**

    감사에서 이 함수가 세 가지를 못 본다는 것이 드러났다. 셋 다 고친다.

    ① **깨진 이름 참조** — 가장 위험한 실패인데 값만 보고 있었다. 정책이
       존재하지 않는 객체를 가리켜도 통과했다. 이제 결과 config 의 모든
       이름 참조가 실제 정의된 객체를 가리키는지 대조한다.
    ② **스왑/순열** — `expected` 에 모든 신 IP 를 넣어서, 신·구 집합이 같으면
       (`A→B, B→A`) 아무것도 안 바꿔도 통과했다. 이제 **계획이 바꾸겠다고
       한 좌표가 실제로 바뀌었는지**를 본다.
    ③ **무성유실** — 안 닫힌 따옴표가 있으면 재스캔도 같은 지점에서 멈춰
       "남은 값 0"이 나왔다. 이제 그 신호를 결과에 싣는다.
    """
    res = scan(new_lines, target)

    # ③ 재스캔이 파일을 끝까지 읽었나
    truncated = bool(res.unterminated_quote_line) or bool(res.unclosed_config_blocks)

    # ① 이름 참조 무결성 — 결과 파일 전체에서 본다(대상 대역 밖 이름도 포함).
    full = scan(new_lines, "0.0.0.0/0")
    defined: set[tuple[str | None, str]] = {
        (r.vdom, r.enclosing_name) for r in full.references
        if r.role == "object_name" and r.enclosing_name}
    _known_broken = plan.preexisting_dangling if plan is not None else set()
    dangling = [
        {"line_no": r.line_no, "name": r.enclosing_name, "field": r.field}
        for r in full.references
        if r.role == "name_reference" and r.enclosing_name
        and r.field not in _FREE_TEXT_FIELDS
        and (r.vdom, r.enclosing_name) not in defined
        and (r.vdom, r.enclosing_name) not in _known_broken]

    # ④ **같은 `edit "X"` 가 두 번 있나.** "이름 참조 → 정의" 방향만 보면
    #    정의가 **둘**인 것은 검사 대상이 아니다. FortiOS 는 두 번째를 첫
    #    객체 편집으로 처리하므로 객체 하나가 통째로 사라지는데, 그 상태로
    #    "전부 정상" 초록불이 떴다(감사 실측).
    _known_dup = plan.preexisting_duplicates if plan is not None else {}
    _lines_by_key: dict[tuple, set] = {}
    for r in full.references:
        if r.role != "object_name" or not r.enclosing_name:
            continue
        k = (r.vdom, _namespace(r.section_path), r.enclosing_name)
        _lines_by_key.setdefault(k, set()).add(r.line_no)
    duplicates: list[dict] = []
    for k, lns in sorted(_lines_by_key.items(), key=lambda kv: sorted(kv[1])):
        # **원래 있던 만큼만 빼고 센다.** 이름 단위로 통째 면제하면 그
        # 이름에 대해 우리가 새로 만든 중복까지 덮인다(감사 실측).
        extra = len(lns) - 1 - int(_known_dup.get(k, 0))
        if extra > 0:
            # **어느 줄이 범인인지 우리는 모른다.** 뒤쪽 줄만 지목하면,
            # 우리가 만든 중복이 앞에 오는 경우 손대지도 않은 원본 줄을
            # 범인으로 적고 우리 줄을 "첫 정의"라고 부른다(실측). FortiOS 는
            # 첫 `edit` 을 남기므로 관리자는 **모든** 줄을 봐야 한다.
            ordered = sorted(lns)
            duplicates.append({"name": k[2], "line_no": ordered[0],
                               "first_line_no": ordered[0],
                               "line_numbers": ordered,
                               "extra": extra})

    # ② 계획이 바꾸겠다고 한 것이 실제로 바뀌었나
    #
    # **원래 좌표를 그대로 쓰면 안 된다.** 같은 줄에 편집이 여럿이고 신·구
    # IP 의 길이가 다르면 앞 치환이 뒤 좌표를 민다(실측: addrgrp member 줄에
    # 편집 16건, 거짓 경보 383건). 그 줄에서 **자기보다 앞선 편집들의 길이
    # 변화를 누적**해 보정한다.
    not_applied = []
    if plan is not None:
        per_line: dict[int, list[PlanRow]] = {}
        for row in plan.rows:
            if row.new_text is not None:
                per_line.setdefault(row.ref.line_no, []).append(row)
        for line_no, rows in per_line.items():
            i = line_no - 1
            if not (0 <= i < len(new_lines)):
                continue
            shift = 0
            for row in sorted(rows, key=lambda r: r.ref.col_start):
                start = row.ref.col_start + shift
                seg = new_lines[i][start:start + len(row.new_text)]
                if seg != row.new_text:
                    not_applied.append(
                        {"line_no": line_no, "expected": row.new_text})
                shift += len(row.new_text) - (row.ref.col_end - row.ref.col_start)

    # 옛 값 잔존 — 남아 있어도 정상인 것 셋:
    #   ① 폐기로 표시한 IP  ② 새로 넣은 IP 가 구 대역 안인 경우(대역 안
    #   재배치)  ③ **상위 대역** — 대상을 포함할 뿐이라 일부러 안 바꾼다.
    #   ③을 빼먹으면 정상 작업마다 거짓 경보가 뜬다(실측 3건).
    leftover_values = [r for r in res.references if r.role == "value"]
    expected = {ip for ip, new in mapping.items() if new is None}
    expected |= {_norm_ip(new) for new in mapping.values() if new}
    if plan is not None:
        expected |= set(plan.supernet_ips)
    unexpected = [r for r in leftover_values if _norm_ip(r.matched) not in expected]

    return {
        "remaining_references": len(res.references),
        "remaining_values": len(leftover_values),
        "unexpected_values": [
            {"line_no": r.line_no, "field": r.field, "value": r.display}
            for r in unexpected],
        "dangling_name_references": dangling[:50],
        "dangling_count": len(dangling),
        "duplicate_definitions": duplicates[:50],
        #: **중복된 이름 수**(초과 정의 수가 아니다). 둘은 다른 값이고
        #: 화면 문구가 어느 쪽을 말하는지 분명해야 한다 — 같은 이름이
        #: 4줄이면 이름은 1개, 초과 정의는 3개다.
        "duplicate_count": len(duplicates),
        "duplicate_extra": sum(d["extra"] for d in duplicates),
        "not_applied": not_applied[:50],
        "not_applied_count": len(not_applied),
        "config_not_fully_read": truncated,
        "clean": not unexpected and not dangling and not not_applied
                 and not truncated and not duplicates,
    }


def reverse_mapping(mapping) -> dict:
    """되돌리기용 신→구 표(Cisco NSO 의 `reverse` 와 같은 발상).

    **충돌을 조용히 잃지 않는다.** 전에는 `{new: old}` 라 두 구 IP 가 같은
    신 IP 로 가면 앞 항목이 사라졌고, 되돌리는 근거 문서가 틀린 채로 나갔다.
    """
    out: dict[str, list[str]] = {}
    for old, new in mapping.items():
        if new:
            out.setdefault(_norm_ip(new), []).append(old)
    return {
        "pairs": {k: v[0] for k, v in out.items() if len(v) == 1},
        "collisions": {k: sorted(v) for k, v in out.items() if len(v) > 1},
        "retired": sorted(ip for ip, new in mapping.items() if new is None),
    }
