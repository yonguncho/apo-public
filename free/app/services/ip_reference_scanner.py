"""구 대역 잔존 참조 스캐너 — 주어진 IP/대역을 참조하는 모든 위치를 찾는다.

**왜 파서를 쓰지 않고 원문을 훑는가.**

세 가지 이유가 있고, 셋 다 실측에 근거한다.

1. **파서는 15개 섹션만 읽는다.** re-IP 가 건드려야 할 곳은
   `router static`(게이트웨이) · `vpn ipsec phase1`(local-gw) ·
   `system dns` · `log syslogd`(서버 IP) · `system snmp` · `user radius` 처럼
   대부분 파서 밖에 있다. 파서를 30개 섹션으로 늘리는 것은 이 기능 하나를
   위해 감당할 규모가 아니고, 늘려도 다음 FortiOS 버전에서 또 샌다.

2. **`raw_sections` 로는 대신할 수 없다.** 이름이 원문(raw)이라 원문 라인을
   들고 있을 것 같지만, 실제로는 `server.py:113` 이 섹션·edit 마다
   **SHA256 지문 16자만** 남기고 라인은 버린다. diff 용도라 그것으로 충분했던
   것이다. 여기서는 "몇 번째 줄의 무엇"을 보여줘야 하므로 쓸 수 없다.
   (검토 문서에서 "raw_sections 기계 재사용"이라고 쓴 것은 이 점을 확인하지
   않은 오류다.)

3. **2단계(바뀐 config 파일 생성)가 이 좌표를 그대로 쓴다.** 파싱해서 다시
   출력하면 들여쓰기·따옴표·주석·순서가 전부 재구성돼 원본과 달라지고,
   FortiOS 문법 구현이 한 벌 더 늘어난다(이 레포는 이미 두 벌로 사고를 냈다).
   원문 라인의 **열 위치**까지 알면 그 자리만 교체하면 되므로 나머지 바이트는
   손도 대지 않는다. 그래서 `col_start`/`col_end` 를 지금부터 기록한다.

**판정에 영향을 주지 않는다.** severity 파이프라인을 호출하지도, 그 입력을
바꾸지도 않는다. 순수 신규 읽기 전용 경로다.

**2단계 착수자에게 — 좌표는 API 밖으로 나가지 않는다.**
`/api/ip-references` 응답에는 `col_start`/`col_end`/`raw_line` 이 **없다**
(응답이 20 MiB 가 되어 뺐다). `line_no` 로 원문을 되찾는 라우트도 없다.
따라서 2단계는 **반드시 서버 안에서 `scan()` 을 다시 불러** 그 결과의 좌표로
치환해야 한다. 브라우저가 받은 JSON 으로 치환하려 들면 안 된다.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable

# ── IP 토큰 인식 ────────────────────────────────────────────────────────
# 점 4개짜리 숫자만 잡는다. 뒤에 `/24` 가 붙으면 프리픽스까지 함께 삼킨다.
#
# **경계에 `\b` 를 쓰면 안 된다.** 티켓 패턴에서 이미 당한 함정이다 — `.` 와
# `/` 는 단어 문자가 아니라서 `\b` 의 의미가 직관과 다르다. 여기서는 앞뒤로
# "숫자·점이 이어지지 않을 것"을 직접 요구한다. 이렇게 해야
# `10.1.1.10` 안에서 `10.1.1.1` 을 잘못 떼어내지 않는다.
_IP_TOKEN = re.compile(
    r"(?<![\d.])"                      # 앞에 숫자·점이 붙어 있으면 안 된다
    r"(\d{1,3}(?:\.\d{1,3}){3})"       # a.b.c.d
    r"(?:/(\d{1,2}))?"                 # 선택적 /prefix
    r"(?![\d.])"                       # 뒤에 숫자·점이 이어지면 안 된다
)

# 넷마스크로만 쓰이는 값. `set subnet 10.1.1.0 255.255.255.0` 의 뒤쪽 토큰을
# 주소로 착각해 별도 참조로 보고하면 행이 두 배가 된다.
_NETMASK_INTS = {
    (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF for p in range(0, 33)
}

# 이 값들은 "구 대역을 참조한다"고 보고하면 안 된다. 어느 대역을 넣어도
# 걸리기 때문에 전 행이 노이즈가 된다.
#   - 0.0.0.0    : 미설정·전체·기본경로의 표기
#   - 255.255.255.255 : 브로드캐스트
_ALWAYS_IGNORE = {"0.0.0.0", "255.255.255.255"}

# 값이 넷마스크 하나인 필드. 여기서만 "마스크처럼 생겼으면 주소가 아니다"가
# 성립한다 — 다른 곳에서 그 규칙을 쓰면 `224.0.0.0`(멀티캐스트)이 사라진다.
_MASK_FIELDS = {"netmask", "mask", "subnet-mask", "wildcard"}


@dataclass
class IpReference:
    """참조 1건 = 리포트의 1행."""

    line_no: int          # 1-based. 사람이 에디터에서 바로 찾아갈 수 있게.
    raw_line: str         # 원문 그대로. strip 하지 않는다(2단계 치환용).
    vdom: str | None
    section: str          # 가장 안쪽 `config ...` (예: "config firewall address")
    section_path: list[str]   # 바깥부터 전부. 중첩 config 를 잃지 않는다.
    edit: str | None      # 가장 안쪽 `edit ...` 의 이름
    edit_path: list[str]
    field: str            # `set subnet ...` -> "subnet". set 이 아니면 "".
    matched: str          # 매칭된 IP 토큰 원문 (예: "10.1.2.0")
    match_kind: str       # exact / inside / supernet / overlap
    col_start: int        # raw_line 내 IP 토큰 시작 열 (0-based)
    col_end: int          # 끝 열 (배타적)

    #: 같은 줄에서 짝을 이룬 넷마스크. `set subnet 10.1.2.0 255.255.255.0`
    #: 처럼 FortiOS 가 주소를 쓰는 가장 흔한 형태를 위한 것이다.
    #: **2단계에서 프리픽스 길이가 바뀌면 이 마스크도 함께 갈아야 하므로**
    #: 값뿐 아니라 열 위치까지 들고 있는다.
    mask: str | None = None
    mask_col_start: int | None = None
    mask_col_end: int | None = None

    #: **이 필드가 리포트의 값어치를 결정한다.** 실측(고객 백업 76,979줄)에서
    #: 참조 1,149건 중 966건(84%)이 정책의 `srcaddr`/`dstaddr` 였는데, 그건
    #: 실제 IP 가 아니라 **주소 객체의 이름**이었다 —
    #: `set dstaddr "10.0.0.83/32_app-dashboard2"`. 이 고객은 객체 이름에
    #: IP 를 박아 쓴다.
    #:
    #: 구분하지 않으면 관리자는 966줄을 전부 고쳐야 하는 줄 안다. 실제로는
    #: **객체 이름을 안 바꾸기로 하면 그 966줄은 손댈 필요가 없다.** 반대로
    #: 이름을 바꾸기로 하면 966줄을 빠짐없이 함께 바꿔야 한다. 어느 쪽이든
    #: 관리자가 결정할 사항이고, 리포트는 그 결정에 필요한 구분을 줘야 한다.
    #: `grep` 도 FortiConverter 도 이 구분을 못 한다.
    #:
    #:   value          실제 IP 설정값. 반드시 바꿔야 한다.
    #:   object_name    객체 이름에 IP 가 들어 있다. 바꿀지는 선택.
    #:   name_reference 그 이름을 가리키는 참조. 이름을 바꿀 때만 함께 바꾼다.
    #:   comment        사람이 읽는 설명. 자동 변경 대상이 아니다.
    role: str = "value"

    #: 이 참조를 감싼 **따옴표 안 전체 문자열**. `object_name` 이면 그 객체의
    #: 이름이고, `name_reference` 면 그 참조가 가리키는 객체 이름이다.
    #:
    #: **이 필드가 이름 변경의 연결 고리다.** 객체 이름을 바꾸면 그 이름을
    #: 가리키는 정책이 빠짐없이 따라가야 하는데(안 그러면 없는 객체를
    #: 가리킨다), 둘을 잇는 유일한 키가 이 문자열이다. 실 파일에서
    #: 이름 참조가 992건이라 사람이 하나씩 맞추게 하면 반드시 샌다.
    enclosing_name: str | None = None

    #: 이 참조를 감싼 `edit` 이 **따옴표로 감싸여 있었나.**
    #: `edit "SRV_A"` 는 True, `edit 101`(정책·정적경로의 번호 edit)은 False.
    #:
    #: **이름 변경이 가능한 객체인지를 가르는 유일한 구조적 신호다.**
    #: 번호 edit 은 이름이 없으므로 개명 대상이 될 수 없는데, 그것을
    #: 섹션 이름 목록(`firewall policy`, `router static`, …)으로 거르면
    #: 다음 FortiOS 버전에서 또 샌다 — 이 레포는 이름을 겨냥했다가 두 번
    #: 뚫렸다(.gitignore·CSS 선택자). 구조로 막는다.
    #:
    #: `edit` 이 없는 줄(`config system dns` 밑의 `set primary ...`)은 False.
    edit_quoted: bool = False

    #: `edit_path` 와 **같은 길이**로 짝을 이루는 레벨별 따옴표 정보.
    #:
    #: **왜 `edit_quoted`(가장 안쪽) 하나로는 모자라는가.** 값이 번호 블록
    #: 안에만 들어 있는 객체가 실제로 있다:
    #:     config firewall vip / edit "PUB_WEB"
    #:         config realservers / edit 1 / set ip 10.20.40.6
    #: 가장 안쪽 edit 은 `1`(번호)이라 "바꿀 이름이 없다"가 되지만, 바꿀
    #: 이름을 가진 객체는 바깥의 `PUB_WEB` 이다. 레벨별로 들고 있어야
    #: **바깥으로 올라가며 이름을 찾는** 것이 가능하다.
    #:
    #: `edit_quoted` 는 이 목록의 마지막 값과 같다 — **기존 필드의 의미와
    #: 값은 바뀌지 않는다.** 여기 있는 것은 그 위 레벨들의 정보뿐이다.
    edit_quoted_path: list[bool] = field(default_factory=list)

    #: `edit_path` 와 같은 길이. 각 edit 이 **정의된** 섹션(그 edit 을 밀어
    #: 넣을 때 열려 있던 가장 안쪽 `config ...`).
    #:
    #: **`section_path` 의 같은 인덱스로 대신할 수 없다.** `config vdom` 의
    #: edit 은 edit 스택에 들어가지 않아 두 경로의 깊이가 어긋나고
    #: (`config vdom` → `config firewall address` 는 섹션 2·edit 1),
    #: edit 없는 중첩 `config` 도 섹션만 한 칸 늘린다. 위 예에서
    #: `PUB_WEB` 의 정의 섹션은 `config firewall vip` 이지 가장 안쪽
    #: `config realservers` 가 아니다 — 이름 후보 목록이 객체가 실제로
    #: 사는 섹션을 말해야 관리자가 장비에서 그 줄을 찾을 수 있다.
    edit_section_path: list[str] = field(default_factory=list)

    #: 관리 접근 경로에 이 IP 가 쓰이고 있다는 표시. **자기 락아웃 경고다.**
    #: 실측에서 `config trusthost` 의 `set ipv4-trusthost 10.0.0.80` 이
    #: 대상 대역 안에 있었다 — 이 대역을 바꾸면 관리자가 장비에서 잠긴다.
    is_admin_access: bool = False

    @property
    def display(self) -> str:
        """리포트에 보여줄 값.

        **`f"{matched} {mask}"` 로 조립하면 안 된다** — 원문 구분자가 탭이나
        공백 여러 개면 없는 형태를 만들어낸다. 원문에서 잘라내면 그대로다.
        """
        if self.mask is None:
            return self.matched
        return self.raw_line[self.col_start:self.mask_col_end]

    @property
    def location(self) -> str:
        """사람이 읽는 위치 문자열."""
        bits = []
        if self.vdom:
            bits.append(f"[{self.vdom}]")
        bits.append(self.section)
        if self.edit:
            bits.append(f'edit "{self.edit}"')
        return " › ".join(bits)


@dataclass
class ScanResult:
    references: list[IpReference] = field(default_factory=list)
    total_lines: int = 0
    #: 파일 끝까지 안 닫힌 따옴표가 있으면 그 시작 줄. **무성 실패를
    #: 소리나게 만드는 장치다** — 여기 값이 있으면 그 줄 이후는 전부
    #: 따옴표 안으로 간주돼 스캔되지 않았다는 뜻이므로, 화면은 "참조 0건"
    #: 대신 "파일을 끝까지 읽지 못했다"를 보여줘야 한다.
    unterminated_quote_line: int | None = None
    #: 파일이 끝났는데 안 닫힌 `config` 블록이 남았으면 그 개수.
    #: **잘린 백업의 신호다.** `end` 가 모자라면 앞 섹션의 `edit` 이름이
    #: 뒤 섹션에 붙어 리포트가 엉뚱한 객체로 귀속시킨다. 조용히 넘기면
    #: 관리자는 그 귀속을 사실로 믿는다.
    unclosed_config_blocks: int = 0
    #: 정합성 확인용 — 이 숫자가 리포트 행 수와 맞아야 관리자가 grep 으로
    #: 직접 검증할 수 있다. 검토에서 "다른 모든 신뢰 기능을 합친 것보다
    #: 가치 있다"고 판단한 한 줄이다.
    scanned_tokens: int = 0

    def summary(self) -> dict:
        kinds: dict[str, int] = {}
        roles: dict[str, int] = {}
        for r in self.references:
            kinds[r.match_kind] = kinds.get(r.match_kind, 0) + 1
            roles[r.role] = roles.get(r.role, 0) + 1
        return {
            "total_lines": self.total_lines,
            "scanned_tokens": self.scanned_tokens,
            "reference_count": len(self.references),
            "by_kind": kinds,
            "by_role": roles,
            #: 반드시 바꿔야 하는 것만 센 수. 관리자가 실제로 마주할 작업량이다.
            #: **상위 대역은 빼야 한다** — 대상을 포함할 뿐이라 마이그레이션이
            #: 일부러 손대지 않는 것을 "바꿔야 할 일"로 세면 작업량이 부풀고,
            #: 1단계의 "…중 N건은 반드시 바꿔야 합니다" 도 함께 틀어진다.
            "must_change": sum(
                1 for r in self.references
                if r.role == "value"
                and r.match_kind not in ("supernet", "overlap")),
            #: 자기 락아웃 경고 대상.
            "admin_access": sum(1 for r in self.references if r.is_admin_access),
            "sections": sorted({r.section for r in self.references}),
            "unterminated_quote_line": self.unterminated_quote_line,
            "unclosed_config_blocks": self.unclosed_config_blocks,
        }


def parse_target(text: str) -> tuple[int, int]:
    """사용자 입력을 정수 구간 (lo, hi) 로.

    받아들이는 표기 — 관리자가 실제로 손에 들고 있는 형태를 전부 받는다.
      10.1.2.0/24              CIDR
      10.1.2.0 255.255.255.0   FortiOS `set subnet` 표기
      10.1.2.1-10.1.2.30       범위(iprange 객체 표기)
      10.1.2.5                 단일 호스트
    """
    t = (text or "").strip()
    if not t:
        # 이 문장은 라우트가 `str(exc)` 로 그대로 내보내 화면에 뜬다. 서버
        # 문장은 영어로 두고 사전이 번역하는 것이 이 레포의 관례다.
        raise ValueError("Enter an IP address or range.")

    # **`ipaddress` 의 원문 예외를 그대로 올리면 안 된다.** 라우트가 그것을
    # `str(exc)` 로 화면에 보내는데, 사전에 없는 문장이라 한국어 화면에
    # `'33' is not a valid netmask` 같은 파이썬 용어가 그대로 뜬다.
    # 빈 입력·역순 범위만 한국어이고 정작 가장 흔한 오타가 영어가 된다.
    try:
        if "-" in t:
            lo_s, _, hi_s = t.partition("-")
            lo = ipaddress.IPv4Address(lo_s.strip())
            hi = ipaddress.IPv4Address(hi_s.strip())
            if int(hi) < int(lo):
                raise ValueError("Range end is lower than range start.")
            return int(lo), int(hi)

        if " " in t:  # `10.1.2.0 255.255.255.0`
            ip_s, _, mask_s = t.partition(" ")
            net = ipaddress.IPv4Network(f"{ip_s.strip()}/{mask_s.strip()}",
                                        strict=False)
            return int(net.network_address), int(net.broadcast_address)

        net = ipaddress.IPv4Network(t, strict=False)  # `/24` 없으면 /32 로 처리
        return int(net.network_address), int(net.broadcast_address)
    except ValueError as exc:
        # 우리가 던진 문장(사전에 있음)은 그대로 올린다.
        if str(exc) == "Range end is lower than range start.":
            raise
        raise ValueError(
            "Not a valid IPv4 address or range. "
            "Use 10.1.2.0/24, 10.1.2.0 255.255.255.0 or 10.1.2.1-10.1.2.30."
        ) from exc


def _token_interval(ip_text: str, prefix: str | None) -> tuple[int, int] | None:
    try:
        if prefix is not None:
            net = ipaddress.IPv4Network(f"{ip_text}/{prefix}", strict=False)
            return int(net.network_address), int(net.broadcast_address)
        addr = ipaddress.IPv4Address(ip_text)
        return int(addr), int(addr)
    except ValueError:
        # `999.1.1.1` 처럼 자리수는 맞지만 값이 틀린 것. 조용히 버린다 —
        # config 안의 임의 문자열(인증서·설명문)에서 나올 수 있다.
        return None


def _mask_to_prefix(mask_text: str) -> int:
    """`255.255.255.0` -> 24. 연속 마스크임이 이미 확인된 값만 들어온다."""
    return bin(int(ipaddress.IPv4Address(mask_text))).count("1")


def _classify(tok: tuple[int, int], target: tuple[int, int]) -> str | None:
    """토큰 구간과 대상 구간의 관계. 무관하면 None."""
    t_lo, t_hi = tok
    g_lo, g_hi = target
    if t_lo == g_lo and t_hi == g_hi:
        return "exact"
    if t_lo >= g_lo and t_hi <= g_hi:
        return "inside"       # 대상 대역 안의 호스트/부분대역 — 가장 중요
    if t_lo <= g_lo and t_hi >= g_hi:
        return "supernet"     # 대상을 포함하는 상위 대역 — 참고용
    if t_lo <= g_hi and g_lo <= t_hi:
        return "overlap"      # 부분 겹침 — 대개 설정 실수의 신호
    return None


# 설명 필드. 여기 든 IP 는 사람이 읽는 메모지 설정값이 아니다.
# 실측에서 `set comments "목적지 10.0.0.116 삭제"` 같은 운영 메모가 나왔다.
_COMMENT_FIELDS = {"comment", "comments", "description", "desc"}

# 관리 접근 경로. 이 대역을 바꾸면 자기 자신이 잠길 수 있다.
#
# `allowaccess` 는 뺐다 — 값이 `ping https ssh` 라 IP 가 올 수 없는 죽은 항목이다.
# `ipv6-*` 도 뺐다 — `_IP_TOKEN` 이 IPv4 전용이라 도달할 수 없다.
# `trusthost1`~`trusthost10` 은 접두어로 잡는다(FortiOS 는 번호를 붙여 쓴다).
# **`source-ip` 를 여기 넣으면 안 된다.** 그것은 장비가 나가는 트래픽의
# 출발지 주소라, `log syslogd`·`system ntp`·`log fortianalyzer` 에 붙는다 —
# 전부 이 모듈이 아래 docstring 에서 명시적으로 금지한 "모니터링 손실"이지
# 자기 락아웃이 아니다. 2차 검토에서 섹션 힌트 과잉은 막았는데 필드 과잉이
# 남아 있었다. (실 백업에 `set source-ip` 가 0건이라 안 드러났다.)
_ADMIN_FIELDS = {"ipv4-trusthost", "management-ip"}
_ADMIN_FIELD_PREFIXES = ("trusthost",)
_ADMIN_SECTION_HINTS = (
    "trusthost", "system admin", "system central-management",
    # HA 전용 대역외(OOB) 관리 인터페이스. 실 파일에 있다:
    #   config system ha / config ha-mgmt-interfaces / set gateway ...
    # 이 대역을 바꾸면 OOB 관리 접속이 그대로 끊긴다.
    "ha-mgmt-interfaces",
)

# **힌트가 하위 섹션까지 삼키는 것을 막는다.**
# `system central-management` 밑의 `config server-list` 는 FortiGuard
# 업데이트·레이팅 서버지 관리 접근 경로가 아니다. 배지를 붙이면 이 모듈이
# 스스로 금지한 것(모니터링 손실과 락아웃을 섞어 신호를 희석)을 자기
# 힌트 목록으로 다시 들여오는 셈이 된다.
# `system admin` 밑의 `gui-dashboard/widget` 도 마찬가지다.
_ADMIN_SECTION_EXCLUDE = ("server-list", "gui-dashboard", "widget")


def _is_admin_context(field: str, section_path: list[str]) -> bool:
    """이 참조를 바꾸면 장비 접근을 잃을 수 있나.

    **`config_stack[-1]` 만 보면 가장 흔한 두 경로를 놓친다**(실측):
      - `config system admin / config trusthost / edit "3" / set ipv4-trusthost`
        → 가장 안쪽 섹션은 `config trusthost` 라 우연히 걸리지만,
      - `config system snmp community / config hosts / set ip ...`
        → 가장 안쪽이 `config hosts` 라 안 걸린다.
    그래서 **경로 전체**를 본다.

    그리고 `config system interface` 의 `set ip` 를 반드시 포함한다 —
    **관리자가 지금 접속해 있는 그 인터페이스야말로 대역을 바꾸면 즉시
    세션이 끊기는 자리다.** 원 정의서에 자기 락아웃이 한 줄도 없었다.

    **여기에 SNMP 호스트·syslog 서버·NTP·FortiAnalyzer 를 넣지 마라.**
    그것들은 바뀌면 모니터링이 끊기지만 관리자가 장비에서 잠기지는 않는다.
    같은 배지로 묶으면 "잠길 수 있다"는 신호가 희석돼, 정작 위험한
    인터페이스 IP 와 trusthost 를 못 보게 된다. 그 참조들도 `value` 로
    빠짐없이 보고된다 — 배지만 안 붙을 뿐이다.
    """
    # **명시적 관리 필드가 섹션 힌트보다 강하다.** 제외 검사를 먼저 두면
    # 잘린 백업에서 `config widget` 이 스택에 남았을 때 `set trusthost1` 의
    # 배지가 조용히 사라진다 — 잘렸다는 경고와 겹쳐 최악이 된다.
    # 필드가 관리 접근을 직접 말하고 있으면 어느 섹션 아래든 경고한다.
    if field in _ADMIN_FIELDS:
        return True
    if any(field.startswith(p) for p in _ADMIN_FIELD_PREFIXES):
        return True
    # 섹션 힌트로만 걸리는 것은 하위 제외 대상을 존중한다(FortiGuard 서버 등).
    if any(x in sec for sec in section_path for x in _ADMIN_SECTION_EXCLUDE):
        return False
    if any(h in sec for sec in section_path for h in _ADMIN_SECTION_HINTS):
        return True
    # 인터페이스 자신의 IP — 세션 끊김 경고.
    if field == "ip" and any("system interface" in s for s in section_path):
        return True
    return False


# 객체 이름을 가리키는 필드. 이름이 우연히 IP 하나로만 되어 있어도
# (`set dstaddr "10.1.2.5"`) 값이 아니라 참조다.
_NAME_REF_FIELDS = {
    "srcaddr", "dstaddr", "srcaddr6", "dstaddr6",
    "srcaddr-negate", "dstaddr-negate",
    "member", "poolname", "groups", "exclude-member",
    "internet-service-src-custom", "internet-service-custom",
}

# **필드 이름만으로는 못 가르는 것들.** `set dst` 가 `config router static`
# 에서는 진짜 목적지 IP(`set dst 10.1.2.0 255.255.255.0`)이고,
# `config system sdwan / config service` 에서는 주소 **객체 이름**이다.
# 필드만 보고 한쪽으로 몰면 반대쪽이 통째로 틀린다 — 라우트 목적지를
# 이름으로 보면 must_change 에서 빠지고, 이름을 값으로 보면 2단계가
# 멀쩡한 객체 참조를 깨뜨린다.
#
# 이 고객이 특히 위험하다: **주소 객체 이름을 순수 IP 로 짓는다**
# (`edit "10.88.29.0/24"` 형태가 실 파일에 448개). 그래서 "따옴표 안이
# 순수 IP 면 값"이라는 규칙이 이름을 값으로 뒤집는다.
_SECTION_NAME_REF_FIELDS = (
    ("system sdwan",     {"dst", "src", "dst-negate", "src-negate"}),
    # **7.0 이전 FortiOS 는 같은 섹션을 `virtual-wan-link` 로 낸다.**
    # 이 고객군이 쓰는 6.0/6.2/6.4 가 정확히 그 버전대라, 빠뜨리면 객체
    # 이름이 실제 IP 로 오인돼 must_change 가 부풀고 2단계가 멀쩡한 참조를
    # 깨뜨린다.
    ("virtual-wan-link", {"dst", "src", "dst-negate", "src-negate"}),
    ("central-snat-map", {"orig-addr", "dst-addr"}),
    ("phase2-interface", {"src-name", "dst-name"}),
    ("phase2",           {"src-name", "dst-name"}),
)


def _is_name_ref_field(field: str, section_path: list[str]) -> bool:
    if field in _NAME_REF_FIELDS:
        return True
    for hint, fields in _SECTION_NAME_REF_FIELDS:
        if field in fields and any(hint in s for s in section_path):
            return True
    return False


def _unescaped_quotes(line: str) -> list[int]:
    r"""이스케이프되지 않은 `"` 의 위치들.

    **`line.count('"')` 를 쓰면 안 된다.** FortiOS 는 값 안의 따옴표를 `\"`
    로 내보낸다(`set comment "19\" rack unit"`). 그걸 진짜 따옴표로 세면
    한 줄에서 홀수가 나오고, 멀티라인 판정이 뒤집혀 **그 뒤 파일 전체가
    따옴표 안으로 삼켜진다** — 참조 0건, 경고 0건, 예외 0건. 관리자는
    "구 대역 참조 없음"을 보고 마이그레이션한 뒤 기본 경로와 DNS 를 잃는다.
    이 모듈의 존재 이유가 "놓치지 않는 것"이라 무성 유실이 최악의 실패다.
    """
    # 대부분의 줄에는 백슬래시가 없다. 그럴 때는 파이썬 문자 루프를 돌 이유가
    # 없다 — `str.find` 는 C 속도다. 77,000줄 파일에서 이 분기가 1초 이상을
    # 가른다(이 함수는 **모든 줄**에서 불린다).
    if "\\" not in line:
        out = []
        p = line.find('"')
        while p != -1:
            out.append(p)
            p = line.find('"', p + 1)
        return out

    out = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "\\":
            i += 2          # 다음 글자는 이스케이프된 것 — 통째로 건너뛴다
            continue
        if ch == '"':
            out.append(i)
        i += 1
    return out


def _quoted_spans(line: str) -> list[tuple[int, int]]:
    """따옴표로 감싸인 구간들.

    **따옴표만으로 이름/값을 가르면 틀린다.** 실측에서
    `set dhcp-relay-ip "10.0.0.175"` 가 나왔다 — FortiOS 는 값에도
    따옴표를 쓴다. 그래서 따옴표는 신호 하나일 뿐이고, 아래 두 가지를 함께
    본다: ①필드가 객체 참조 필드인가 ②따옴표 안이 IP(+마스크)로만 되어
    있는가(`"10.0.0.83/32_app-dashboard2"` 는 이름, `"10.1.2.5 10.1.2.6"`
    은 값).
    """
    q = _unescaped_quotes(line)
    return [(q[i], q[i + 1]) for i in range(0, len(q) - 1, 2)]


def _is_pure_address_list(inner: str) -> bool:
    """따옴표 안이 IP(와 넷마스크)만으로 되어 있나.

    **`inner == 매칭토큰` 으로 비교하면 안 된다.** FortiOS 는 값 여러 개를
    따옴표 하나 안에 공백으로 쓴다 — `set dhcp-relay-ip "10.1.2.175
    10.1.2.176"`. 토큰 하나와 통째로 비교하면 둘 다 '이름 참조'로 빠지고,
    `must_change` 에서 사라져 관리자가 DHCP 릴레이를 놓친 채 넘어간다.
    """
    parts = inner.split()
    if not parts:
        return False
    for p in parts:
        m = _IP_TOKEN.fullmatch(p)
        if m is None:
            return False
    return True


def _enclosing_quote(pos: int, spans: list[tuple[int, int]]) -> tuple[int, int] | None:
    for lo, hi in spans:
        if lo < pos < hi:
            return lo, hi
    return None


def _field_name(stripped: str) -> str:
    """`set subnet 10.1.1.0 ...` -> "subnet". set/unset 이 아니면 빈 문자열."""
    parts = stripped.split(None, 2)
    if len(parts) >= 2 and parts[0] in ("set", "unset"):
        return parts[1]
    return ""


def scan(lines: Iterable[str], target: str | tuple[int, int]) -> ScanResult:
    """원문 라인들에서 `target` 을 참조하는 모든 위치를 찾는다.

    `lines` 는 개행이 제거된 라인 목록(파서의 `self.lines` 와 같은 형태).
    """
    tgt = parse_target(target) if isinstance(target, str) else target
    result = ScanResult()

    config_stack: list[str] = []
    #: `config` 를 열 때의 edit 깊이. **`end` 가 `edit_stack` 을 안 풀면
    #: edit 이름이 파일 끝까지 새어나간다** — `next` 없이 `end` 로 닫는
    #: config 를 만나면 `config system dns` 처럼 edit 이 없는 섹션에도
    #: 엉뚱한 객체 이름이 붙고, 2단계가 그 이름으로 위치를 검증하면
    #: 다른 객체로 귀속된다.
    edit_depth_stack: list[int] = []
    edit_stack: list[str] = []
    #: `edit_stack` 과 **같은 깊이로** 움직인다. 따로 감으면 `next` 없이
    #: 닫힌 블록에서 어긋나 번호 edit 이 이름 edit 으로 보고된다.
    edit_quoted_stack: list[bool] = []
    #: 각 edit 이 정의된 섹션. 위 둘과 **같은 깊이로** 움직인다 — 하나라도
    #: 따로 감으면 레벨이 어긋나 이름과 섹션이 다른 객체의 것으로 짝지어진다.
    edit_section_stack: list[str] = []
    vdom: str | None = None
    vdom_depth = 0

    # 여러 줄에 걸친 따옴표 값(인증서·PSK 등) 안에서는 IP 를 찾지 않는다.
    # 인증서 본문의 base64 가 우연히 점 4개 숫자처럼 보이는 일은 없지만,
    # 설명문(`set comment "구 대역 10.1.2.0 회수 예정"`)은 실제로 걸린다 —
    # 그건 오히려 보여주는 게 맞아서 한 줄짜리 따옴표는 통과시킨다.
    in_multiline = False
    ml_start = 0

    for line_no, raw in enumerate(lines, start=1):
        result.total_lines = line_no
        stripped = raw.strip()

        # **정합성 숫자는 건너뛴 줄까지 세야 한다.** 문맥 줄과 멀티라인
        # 블록을 카운트에서 빼면 이 숫자가 파일의 토큰 수가 아니게 되고,
        # 관리자가 `grep` 으로 대조할 수 없다 — 그러라고 만든 숫자인데.
        # `findall` 로 세고 나중에 `finditer` 로 또 돌면 **정규식을 두 번**
        # 돌린다(실측 4.9초 → 7.1초). 한 번만 돌려 리스트로 들고 재사용한다.
        toks = list(_IP_TOKEN.finditer(raw))
        result.scanned_tokens += len(toks)

        odd_quote = len(_unescaped_quotes(raw)) % 2 == 1
        if in_multiline:
            if odd_quote:
                in_multiline = False
            continue
        if odd_quote:
            in_multiline = True
            ml_start = line_no
            continue
        if not stripped:
            continue

        # ── 문맥 추적 ────────────────────────────────────────────────
        # 주석 줄도 문맥은 바꾸지 않지만 스캔은 한다. FortiOS 는 `#` 를
        # 조용히 건너뛰므로 주석 안의 구 IP 는 "안 고쳐진 흔적"이다.
        is_edit_line = False
        if not stripped.startswith("#"):
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
                    vdom = name          # `config vdom` 바로 아래 edit = VDOM 이름
                    continue
                edit_stack.append(name)
                # 따옴표 유무가 이름 edit 과 번호 edit 을 가르는 구조적
                # 신호다(위 `edit_quoted` 주석 참조).
                edit_quoted_stack.append(
                    len(token) >= 2 and token.startswith('"')
                    and token.endswith('"'))
                # 이 edit 을 품고 있는 섹션. **지금 기록해야 한다** — 이
                # 블록 안에서 또 `config` 가 열리면 `config_stack[-1]` 은
                # 그 안쪽으로 옮겨가 정의 섹션을 잃는다.
                edit_section_stack.append(
                    config_stack[-1] if config_stack else "")
                # **`edit` 이름도 스캔한다.** 이 고객처럼 객체 이름에 IP 를
                # 박아 쓰면(`edit "10.0.0.171/32_app-web1"`) 이름 자체가
                # 구 대역의 흔적이다. 문맥을 갱신한 뒤 아래로 흘려보낸다.
                is_edit_line = True
            elif stripped == "next":
                if edit_stack:
                    edit_stack.pop()
                    edit_quoted_stack.pop()
                    edit_section_stack.pop()
                continue
            elif stripped == "end":
                if config_stack:
                    popped = config_stack.pop()
                    # 이 config 를 열 때의 깊이로 되돌린다 — `next` 없이
                    # 닫힌 edit 이 남아 뒤 섹션을 오염시키지 않게.
                    depth = edit_depth_stack.pop() if edit_depth_stack else 0
                    del edit_stack[depth:]
                    del edit_quoted_stack[depth:]
                    del edit_section_stack[depth:]
                    # 여는 쪽에 `not config_stack[:-1]`(최상위만) 가드가 있으니
                    # 닫는 쪽도 같아야 한다. 안 그러면 중첩된 `config vdom` 이
                    # 닫힐 때 **바깥 VDOM 이름이 통째로 날아가고** 파일
                    # 나머지가 vdom=None 이 된다.
                    if popped == "config vdom" and not config_stack:
                        vdom, vdom_depth = None, 0
                continue

        # ── 토큰 스캔 ────────────────────────────────────────────────
        # **IP 가 없는 줄에서 분류 작업을 하지 않는다.** 실측(8,000 정책,
        # 96,004줄)에서 IP 토큰이 없는 줄이 83% 였고, 그 줄들에도
        # `_quoted_spans`(줄 전체 문자 루프)를 돌리고 있었다. 이 한 줄로
        # 3.83초 → 1.94초(49% 단축), 결과는 동일.
        if not toks:
            continue

        fname = _field_name(stripped)
        qspans = _quoted_spans(raw)
        admin_ctx = _is_admin_context(fname, config_stack)

        consumed: set[int] = set()   # 마스크로 흡수된 토큰의 인덱스
        for idx, m in enumerate(toks):
            if idx in consumed:
                continue
            ip_text, prefix = m.group(1), m.group(2)

            if ip_text in _ALWAYS_IGNORE:
                continue

            # ── IP + 넷마스크 짝 합치기 ──────────────────────────────
            # **이걸 안 하면 `set subnet 10.1.2.0 255.255.255.0` 이 호스트
            # 하나(/32)로 읽혀, 대상 대역과 정확히 같은 객체가 'exact' 가
            # 아니라 'inside' 로 보고된다.** 대역이 통째로 일치하는 객체는
            # 마이그레이션에서 가장 먼저 봐야 할 대상인데 등급이 내려간다.
            # FortiOS 가 주소를 쓰는 가장 흔한 형태라 반드시 짝으로 읽는다.
            mask_tok = None
            if prefix is None and idx + 1 < len(toks):
                nxt = toks[idx + 1]
                between = raw[m.end():nxt.start()]
                # 값싼 검사를 **먼저** 한다 — `_token_interval` 은 ipaddress
                # 객체를 만들어 비싸고, 대부분의 줄에서 어차피 탈락한다.
                if nxt.group(2) is None and between.strip() == "":
                    nxt_iv = _token_interval(nxt.group(1), None)
                    # `iv[0] != 0` — **`0.0.0.0` 을 마스크로 받으면 안 된다.**
                    # `set dst 10.1.2.0 0.0.0.0` 이 `/0` 으로 읽혀 전 IPv4 를
                    # 덮는 supernet 으로 보고된다. 짝 미형성 경로에는 이 가드가
                    # 있는데 짝 형성 경로에 없어 비대칭이었다.
                    if (nxt_iv is not None and nxt_iv[0] != 0
                            and nxt_iv[0] in _NETMASK_INTS):
                        mask_tok = nxt
                        consumed.add(idx + 1)

            if mask_tok is not None:
                iv = _token_interval(ip_text, str(_mask_to_prefix(mask_tok.group(1))))
            else:
                iv = _token_interval(ip_text, prefix)
            if iv is None:
                continue

            # 짝을 못 이룬 토큰이 넷마스크 값처럼 생겼다고 버리면 안 된다.
            #
            # `_NETMASK_INTS` 에는 `128.0.0.0` · `192.0.0.0` · `224.0.0.0` ·
            # `240.0.0.0` 도 들어 있다. 이것들은 넷마스크이자 **동시에 실제
            # 멀티캐스트·예약 주소**다. 실 고객 파일에 이게 있다:
            #     config firewall multicast-address
            #         edit "all"
            #             set start-ip 224.0.0.0
            #             set end-ip 239.255.255.255
            # 무조건 버리면 이 객체가 **반쪽만** 보고된다 — end-ip 는 나오고
            # start-ip 는 사라지는데 경고도 예외도 없다. 이 모듈이 스스로
            # 최악이라 부른 무성 유실이다.
            #
            # 넷마스크는 실제로 **앞 토큰의 짝으로만** 나온다. 짝을 못 이뤘다면
            # 주소로 보는 것이 맞고, 진짜 마스크 단독 표기는 필드 이름이
            # 말해 준다(`set netmask 255.255.255.0`).
            if (mask_tok is None and prefix is None
                    and iv[0] in _NETMASK_INTS and iv[0] != 0
                    and fname in _MASK_FIELDS):
                continue

            kind = _classify(iv, tgt)
            if kind is None:
                continue

            # ── 역할 판정 ────────────────────────────────────────────
            if stripped.startswith("#"):
                # **FortiOS 가 실행하지 않는 줄이다.** 이 모듈은 `#` 줄을
                # 일부러 스캔하면서 "안 고쳐진 흔적"이라 부르는데, 정작
                # `comment` 역할을 안 줘서 "실제 IP 설정값입니다 / 반드시
                # 바꾸세요"로 표시되고 작업량 카운트에 들어갔다.
                role = "comment"
            elif is_edit_line:
                role = "object_name"
            elif fname in _COMMENT_FIELDS:
                role = "comment"
            elif _is_name_ref_field(fname, config_stack):
                role = "name_reference"
            else:
                q = _enclosing_quote(m.start(), qspans)
                # 따옴표 안이 **IP(와 마스크)로만** 되어 있으면 값이고,
                # 다른 글자가 섞여 있으면 이름이다. 값 여러 개를 한 따옴표
                # 안에 공백으로 쓰는 형태(`"10.1.2.175 10.1.2.176"`)도 값이다.
                if q is not None:
                    inner = raw[q[0] + 1:q[1]].strip()
                    role = "value" if _is_pure_address_list(inner) else "name_reference"
                else:
                    role = "value"

            # ── 이름 변경의 연결 고리 ────────────────────────────────
            # 객체 이름과 그 이름을 가리키는 참조를 잇는 키. 둘 다 따옴표
            # 안 전체 문자열이 같다. `edit "A"` ↔ `set dstaddr "A"`.
            enclosing = None
            if role in ("object_name", "name_reference"):
                q2 = _enclosing_quote(m.start(), qspans)
                if q2 is not None:
                    enclosing = raw[q2[0] + 1:q2[1]]
                elif role == "object_name":
                    # 따옴표 없는 `edit 1` 형태(정책 ID 등)도 있다.
                    enclosing = edit_stack[-1] if edit_stack else None

            result.references.append(IpReference(
                line_no=line_no,
                raw_line=raw,
                vdom=vdom,
                section=config_stack[-1] if config_stack else "",
                section_path=list(config_stack),
                edit=edit_stack[-1] if edit_stack else None,
                edit_path=list(edit_stack),
                edit_quoted=edit_quoted_stack[-1] if edit_quoted_stack else False,
                edit_quoted_path=list(edit_quoted_stack),
                edit_section_path=list(edit_section_stack),
                field=fname,
                matched=m.group(0),
                match_kind=kind,
                col_start=m.start(),
                col_end=m.end(),
                mask=mask_tok.group(0) if mask_tok else None,
                mask_col_start=mask_tok.start() if mask_tok else None,
                mask_col_end=mask_tok.end() if mask_tok else None,
                role=role,
                enclosing_name=enclosing,
                # 이름·주석은 장비 접근에 쓰이지 않는다. 값일 때만 경고한다.
                is_admin_access=admin_ctx and role == "value",
            ))

    # 파일이 끝났는데 따옴표가 안 닫혀 있으면 그 뒤는 통째로 안 읽힌 것이다.
    # 조용히 넘기면 "참조 0건"이 "이상 없음"으로 읽힌다.
    if in_multiline:
        result.unterminated_quote_line = ml_start
    result.unclosed_config_blocks = len(config_stack)

    return result
