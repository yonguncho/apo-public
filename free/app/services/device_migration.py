"""장비 이관 사전 점검 — 이 설정을 저 장비에 넣으면 무엇이 깨지나.

**번역기가 아니다.** 버전 간 문법을 바꿔 주지 않는다. Fortinet 자신도
수동 이관 절차의 1번이 *"먼저 펌웨어를 맞춰라"* 이고, 모델·버전이 다른
설정 파일 임포트는 **공식 지원하지 않는다**(FortiConverter 를 쓰라고 한다).
버전별 스키마를 실물로 검증할 방법이 없는 상태에서 번역을 흉내내면
조용히 틀린 config 를 만든다 — 이 도구가 오늘 하루 종일 싸운 그 실패다.

**대신 정직하게 말한다.** 옛 장비 백업과 새 장비 백업(공장초기여도 된다)
두 개를 읽어, 복원했을 때 무엇을 잃고 무엇을 손봐야 하는지 센다.
읽기만 하므로 틀려도 파일을 망가뜨리지 않는다.

**암호화된 값은 손대지 않는다 — 그대로 옮긴다.** `ENC` 값은 펌웨어에
박힌 **고정 키**로 암호화돼 있어(CVE-2019-6693 으로 공개된 그 키) 장비가
달라도 그대로 동작한다. 좌표 기반 치환이라 원리적으로 못 건드리기도 한다.

예외는 하나: 관리자가 `private-data-encryption` 을 **켠 경우**. 그때만
대상 장비에 **같은 키를 먼저 넣어야** 복원된다. 보유 config 107개 중
켜진 것은 0개다(전부 기본값). 그 경우에만 경고한다 — "비밀을 잃는다"를
기본으로 깔면 정상 이관마다 빨간 글씨가 떠서 진짜 경고가 묻힌다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: `#config-version=FGT100F-7.0.6-FW-build0366-220606:opmode=0:vdom=0:...`
_HEADER = re.compile(
    r"^#config-version=([A-Za-z0-9]+)-([\d.]+)-FW-build(\d+)")

_EDIT = re.compile(r'^\s*edit "([^"]+)"\s*$')
_SET = re.compile(r"^(\s*set ([\w-]+)\s+)(.*?)(\s*)$")

#: 인터페이스 이름을 **값으로** 갖는 필드. 추측이 아니라 보유 config 61개에서
#: 실제로 센 것이다 — associated-interface 10,420 / srcintf 4,245 /
#: dstintf 4,141 / interface 60 / monitor 22 / device 14 / hbdev 4 /
#: session-sync-dev 4.
#: `hbdev` 는 `"port31" 100 "port32" 50` 처럼 **숫자가 끼어 있고**,
#: `monitor` 는 값이 여럿이다 — 그래서 **따옴표로 감싼 토큰만** 손댄다.
INTERFACE_FIELDS = frozenset({
    "associated-interface", "srcintf", "dstintf", "interface", "monitor",
    "device", "hbdev", "session-sync-dev",
})
#: **여기에 추측으로 더 넣지 마라.** 처음에 `member`·`external-interface`
#: 같은 것을 기억으로 넣었더니 `config firewall addrgrp` 의 `set member`
#: 가 걸려 **"새 장비에 없는 인터페이스 3,735개"** 라는 오탐이 났다
#: (주소 객체 이름이었다). `config system zone` 의 `set interface` 도
#: 인터페이스를 참조하지만 보유 config 에 zone 이 0건이라 **실물로 검증할
#: 수 없다** — 검증 못 하는 것은 넣지 않는다.

#: 장비 하드웨어에 매인 섹션. 다른 모델에 그대로 넣으면 복원이 깨지거나
#: 조용히 버려진다. 보유 config 에서 실제로 나온 것만 넣는다.
HARDWARE_SECTIONS = (
    "config switch-controller",
    "config system npu",
    "config system virtual-switch",
    "config system physical-switch",
    "config wireless-controller",
    "config system storage",
)


@dataclass
class DeviceInfo:
    model: str | None = None
    version: str | None = None
    build: str | None = None
    header_line_no: int | None = None
    header: str | None = None

    @property
    def known(self) -> bool:
        return bool(self.model and self.version)


@dataclass
class Preflight:
    old: DeviceInfo = field(default_factory=DeviceInfo)
    new: DeviceInfo = field(default_factory=DeviceInfo)
    #: 옛 장비에는 **있는데** 새 장비에 없는 인터페이스 → 참조 수.
    #: **이관이 깨뜨리는 것**만 여기 담는다.
    missing_interfaces: dict = field(default_factory=dict)
    #: 옛 설정이 참조하는데 **옛 설정에도 정의가 없는** 이름 → 참조 수.
    #: 이관과 무관한 원래 상태다(물리 포트라 명시 설정이 없을 수 있다).
    #: 섞어서 보고하면 정상 작업마다 소음이 뜨고 진짜 신호가 묻힌다.
    unresolved_in_old: dict = field(default_factory=dict)
    #: 새 장비에만 있는 인터페이스(매핑 후보로 보여 준다)
    spare_interfaces: list = field(default_factory=list)
    #: 새 장비에 있지만 옛 설정이 이미 참조하고 있어 매핑 대상에서 뺀 이름
    spare_but_referenced: list = field(default_factory=list)
    #: 그대로 실려 가는 암호화 값. **경고가 아니라 확인용**이다 —
    #: 손대지 않고 옮기며 고정 키라 새 장비에서도 동작한다.
    secrets: list = field(default_factory=list)
    #: 관리자가 자기 키로 암호화했나. `True` 면 **대상 장비에 같은 키를
    #: 먼저 넣어야** 복원된다 — 이관에서 진짜 막아야 하는 유일한 비밀 문제다.
    private_data_encryption: bool = False
    #: 새 장비에 없는 하드웨어 전용 섹션 → 줄 번호
    hardware_only: dict = field(default_factory=dict)

    @property
    def same_model(self) -> bool:
        return bool(self.old.model and self.old.model == self.new.model)

    @property
    def version_known(self) -> bool:
        """양쪽 버전을 **둘 다 아는가.**

        옛 config 에 `#config-version` 헤더가 없으면(수집 텍스트 등) 우리는
        옛 버전을 모른다. 그때 `same_version` 은 False 인데, 그것을 "다르다"
        로 읽으면 근거 없는 단정이 된다 — 모르는 것과 다른 것은 다르다.
        """
        return bool(self.old.version and self.new.version)

    @property
    def same_version(self) -> bool:
        return bool(self.old.version and self.old.version == self.new.version)

    def summary(self) -> dict:
        return {
            "old": {"model": self.old.model, "version": self.old.version,
                    "build": self.old.build},
            "new": {"model": self.new.model, "version": self.new.version,
                    "build": self.new.build},
            "same_model": self.same_model,
            "same_version": self.same_version,
            "missing_interfaces": dict(self.missing_interfaces),
            "unresolved_in_old": dict(self.unresolved_in_old),
            "spare_interfaces": list(self.spare_interfaces),
            "spare_but_referenced": list(self.spare_but_referenced),
            "version_known": self.version_known,
            "secret_count": len(self.secrets),
            "secrets": self.secrets[:50],
            "private_data_encryption": self.private_data_encryption,
            "hardware_only": dict(self.hardware_only),
            "header_replace": (
                {"from": self.old.header, "to": self.new.header}
                if self.old.header and self.new.header
                and self.old.header != self.new.header else None),
        }


def read_header(lines) -> DeviceInfo:
    """첫 줄의 `#config-version=` 에서 모델·버전·빌드를 읽는다.

    Fortinet 의 수동 이관 절차가 **이 줄을 새 장비 값으로 바꾸라**고 한다.
    없으면(수집으로 받은 텍스트 등) 모르는 채로 둔다 — 추측하지 않는다.
    """
    for i, ln in enumerate(lines[:5], start=1):
        m = _HEADER.match(ln.strip())
        if m:
            return DeviceInfo(model=m.group(1), version=m.group(2),
                              build=m.group(3), header_line_no=i,
                              header=ln.strip())
    return DeviceInfo()


def interfaces(lines) -> dict:
    """`config system interface` 에 **정의된** 이름 → 줄 번호."""
    out: dict[str, int] = {}
    stack: list[str] = []
    for i, ln in enumerate(lines, start=1):
        s = ln.strip()
        if s.startswith("config "):
            stack.append(s)
            continue
        if s == "end" and stack:
            stack.pop()
            continue
        if stack[-1:] == ["config system interface"]:
            m = _EDIT.match(ln)
            if m:
                out.setdefault(m.group(1), i)
    return out


def interface_uses(lines) -> dict:
    """인터페이스 이름이 **쓰이는** 곳 → 참조 목록.

    정의 자신(`config system interface` 안)은 세지 않는다 — 이름을 바꿀 때
    정의와 참조는 다르게 다뤄야 하기 때문이다.
    """
    uses: dict[str, list] = {}
    stack: list[str] = []
    for i, ln in enumerate(lines, start=1):
        s = ln.strip()
        if s.startswith("config "):
            stack.append(s)
            continue
        if s == "end" and stack:
            stack.pop()
            continue
        if stack[-1:] == ["config system interface"]:
            continue
        m = _SET.match(ln)
        if not m or m.group(2) not in INTERFACE_FIELDS:
            continue
        # **따옴표 토큰만.** `hbdev` 는 `"port31" 100 "port32" 50` 처럼
        # 숫자가 끼어 있고, 따옴표 없는 값은 인터페이스가 아닐 수 있다.
        for name in re.findall(r'"([^"]+)"', m.group(3)):
            uses.setdefault(name, []).append(
                {"line_no": i, "field": m.group(2),
                 "section": stack[-1] if stack else ""})
    return uses


def secrets(lines) -> list:
    """그대로 실려 가는 암호화 값 — **어디에 있는지**만.

    손대지 않고 옮긴다. 고정 키라 새 장비에서도 동작한다. 목록을 주는
    이유는 겁주기 위해서가 아니라, 이관 후 **무엇을 확인해 볼지** 알려
    주기 위해서다(VPN PSK·RADIUS 시크릿 등).
    값 자체는 담지 않는다 — 화면·메모에 비밀을 흘릴 이유가 없다.
    """
    out = []
    stack: list[str] = []
    edit = None
    for i, ln in enumerate(lines, start=1):
        s = ln.strip()
        if s.startswith("config "):
            stack.append(s)
            edit = None
            continue
        if s == "end" and stack:
            stack.pop()
            edit = None
            continue
        m = _EDIT.match(ln)
        if m:
            edit = m.group(1)
            continue
        m = _SET.match(ln)
        if m and re.search(r"\bENC\s+\S", m.group(3)):
            out.append({"line_no": i, "field": m.group(2),
                        "section": stack[-1] if stack else "",
                        "edit": edit})
    return out


def private_data_encryption(lines) -> bool:
    """관리자가 자기 키로 비밀을 암호화했나.

    **켜져 있으면** 대상 장비에 같은 키를 먼저 넣어야 복원된다. 옵트인
    기능이고 보유 config 107개 중 0개가 켜져 있다 — 그래서 이것만 경고한다.
    """
    for ln in lines:
        s = ln.strip()
        if s.startswith("set private-data-encryption "):
            return s.split()[-1] == "enable"
    return False


def hardware_sections(lines) -> dict:
    """장비 하드웨어에 매인 최상위 섹션 → 줄 번호."""
    out: dict[str, int] = {}
    depth = 0
    for i, ln in enumerate(lines, start=1):
        s = ln.strip()
        if s.startswith("config "):
            if depth == 0:
                for h in HARDWARE_SECTIONS:
                    if s.startswith(h):
                        out.setdefault(s, i)
                        break
            depth += 1
        elif s == "end" and depth:
            depth -= 1
    return out


def preflight(old_lines, new_lines) -> Preflight:
    """옛 설정을 새 장비에 넣으면 무엇이 깨지나.

    `new_lines` 는 **새 장비의 백업**이다. 공장초기 상태여도 된다 — 필요한
    것은 그 장비가 가진 인터페이스 이름과 버전뿐이다.
    """
    p = Preflight(old=read_header(old_lines), new=read_header(new_lines))

    old_if, new_if = interfaces(old_lines), interfaces(new_lines)
    uses = interface_uses(old_lines)

    # **이관이 깨뜨리는 것만 센다.** 옛 장비에 정의가 있고 새 장비에는
    # 없는 이름이 그것이다. 옛 설정에도 정의가 없던 이름은 원래 그랬던
    # 것이라 따로 담는다 — 섞으면 같은 장비끼리 대조해도 목록이 찬다.
    for name in sorted(set(old_if)):
        if name not in new_if:
            p.missing_interfaces[name] = len(uses.get(name, []))
    # 정의 없이 참조만 있는 이름. **"원래 그랬으니 괜찮다" 가 아니다** —
    # 새 장비에도 없으므로 복원 때 그 줄이 통째로 버려진다. 다만 옮기기
    # 전에 이미 끊어져 있던 것이라(현 장비에도 정의가 없다) 이관이
    # 악화시키는 것은 아니어서 막지는 않는다. 매핑표에 올려 고칠 수 있게
    # 하고, 사실대로 말한다.
    for name in sorted(set(uses) - set(old_if)):
        if name in new_if or name in RESERVED_NAMES:
            continue
        n = sum(1 for pl in uses[name]
                if not pl["section"].startswith(HARDWARE_SECTIONS))
        if n:
            p.unresolved_in_old[name] = n

    # 새 장비에는 있는데 옛 설정에는 정의도 참조도 없는 이름 — 매핑 대상으로
    # 안전하게 내줄 수 있는 것들이다.
    p.spare_interfaces = sorted(set(new_if) - set(old_if) - set(uses))
    # **뺀 이유를 말한다.** 옛 설정이 정의 없이 참조만 하는 이름(`set srcintf
    # "wan1"` 처럼)이 새 장비에 실재하면 사용자는 "있는데 왜 목록에 없지"
    # 로 끝난다. 매핑 대상에서 빼는 것은 옳다 — 그 이름으로 옮기면 원래
    # 있던 참조와 뒤섞여 어느 쪽을 가리키는지 알 수 없게 된다. 조용한 것이
    # 틀렸던 것이라 목록으로 내놓는다.
    p.spare_but_referenced = sorted((set(new_if) & set(uses)) - set(old_if))
    p.secrets = secrets(old_lines)
    p.private_data_encryption = private_data_encryption(old_lines)

    new_hw = set(hardware_sections(new_lines))
    for sec, line_no in hardware_sections(old_lines).items():
        if sec not in new_hw:
            p.hardware_only[sec] = line_no
    return p


# ── 이관 실행 ───────────────────────────────────────────────────────────
#: FortiOS 인터페이스 이름 길이 상한. 넘으면 장비가 거절한다.
MAX_NAME = 15

#: 인터페이스 자리에 오지만 **인터페이스가 아닌** 예약어.
#: `set srcintf "any"` 의 `any` 는 "전부"를 뜻한다. 실측으로만 넣는다 —
#: 코퍼스에서 정의 없이 참조만 되는 이름 7개 중 이것이 21참조/5파일이었고,
#: 항등 이관에서 "버려질 참조"로 잡히던 오탐의 유일한 원인이었다.
#: **여기에 추측으로 더 넣지 마라.** 진짜 인터페이스를 예약어로 오인하면
#: 그 이름은 매핑표에서 사라지고 조용히 버려진다.
RESERVED_NAMES = frozenset({"any"})


@dataclass
class RenameRow:
    line_no: int
    col_start: int
    col_end: int
    old: str
    new: str
    kind: str          # "header" | "definition" | "reference"
    field: str = ""
    section: str = ""


@dataclass
class RenamePlan:
    rows: list = field(default_factory=list)
    #: 사람이 답해야 하는 것. 하나라도 있으면 파일을 만들지 않는다.
    unmapped: list = field(default_factory=list)      # 새 장비에 없는데 매핑 안 함
    collisions: list = field(default_factory=list)    # 개명 결과가 기존 이름과 같아짐
    too_long: list = field(default_factory=list)      # 15자 초과
    not_on_new: list = field(default_factory=list)    # 새 이름이 새 장비에 없다

    @property
    def blocking(self) -> list:
        out = []
        if self.unmapped:
            out.append("unmapped_interface")
        if self.collisions:
            out.append("interface_collision")
        if self.too_long:
            out.append("name_too_long")
        if self.not_on_new:
            out.append("not_on_new_device")
        return out

    def summary(self) -> dict:
        by = {}
        for r in self.rows:
            by[r.kind] = by.get(r.kind, 0) + 1
        return {"rows": len(self.rows), "by_kind": by,
                "unmapped": list(self.unmapped),
                "collisions": list(self.collisions),
                "too_long": list(self.too_long),
                "not_on_new": list(self.not_on_new),
                "blocking": self.blocking}


def verify(new_config, new_interfaces) -> dict:
    """만들어진 파일에서 **새 장비가 조용히 버릴 것**을 센다.

    FortiOS 의 config 파서는 한 번만 훑고, 없는 인터페이스를 가리키는 줄을
    **말없이 버리면서도 복원 성공을 표시한다.** 그래서 "몇 줄 바꿨다" 는
    성공의 증거가 될 수 없다 — 바꾸지 *못한* 것을 세야 한다.

    미매핑을 확인하고 넘어간 경우가 정확히 이 자리다. 그 이름들은 그대로
    남고, 남은 채로 복원되면 정의도 참조도 사라진다. 그 규모를 여기서
    숫자로 만든다.

    하드웨어 전용 구역은 세지 않는다 — `config system storage` 의
    `device` 값이 `/dev/sdb1` 처럼 인터페이스가 아닌 것을 담고 있어서,
    세면 그대로 오탐이 된다(실 파일에서 확인했다).
    """
    have = set(new_interfaces)
    defined = interfaces(new_config)
    orphan_definitions = sorted(n for n in defined if n not in have)
    # **회귀 판정이다.** 정의가 있던 이름이 새 장비에 없으면 그 정의도,
    # 그것을 가리키는 참조도 복원 때 사라진다 — 이관이 만든 손실이다.
    # 반면 **정의 없이 참조만 있던** 이름은 옮기기 전에 이미 그랬다.
    # 부분 백업이면 실제 장비에는 그 포트가 있었을 수도 있어 우리는 알 수
    # 없다. 그것까지 세면 항등 이관(바이트가 완전히 같은 파일)에도 빨간
    # 경고와 `_INCOMPLETE` 가 붙는다 — 실측 71개 중 9개가 그랬다.
    # 늑대소년은 차단으로만 만들어지지 않는다. **파일 이름으로도 만들어진다.**
    lost = set(orphan_definitions)
    orphan_references: dict = {}
    dangling: dict = {}
    for name, places in interface_uses(new_config).items():
        if name in have or name in RESERVED_NAMES:
            continue
        n = sum(1 for pl in places
                if not pl["section"].startswith(HARDWARE_SECTIONS))
        if not n:
            continue
        # **넓은 셈** — 산출물이 가리키는, 새 장비에 없는 모든 이름.
        # 파서 로그가 찰지 안 찰지는 이쪽이 정한다.
        dangling[name] = n
        # **좁은 셈(회귀)** — 그중 정의가 있던 것만. 파일 이름에 딱지를
        # 붙일지는 이쪽이 정한다.
        if name in lost:
            orphan_references[name] = n
    # 원래부터 정의가 없던 이름 — 이관이 만든 것이 아니지만 새 장비에서
    # 그 줄이 안 올라가는 것은 같다. 4단계 지시문이 이것을 알아야 한다.
    pre_existing = {k: v for k, v in dangling.items()
                    if k not in orphan_references}
    return {
        "orphan_definitions": orphan_definitions,
        "orphan_definition_count": len(orphan_definitions),
        "orphan_references": dict(sorted(orphan_references.items())),
        "orphan_reference_count": sum(orphan_references.values()),
        # **`clean` 에 묶지 않는다.** 하나에 용도 둘을 묶어 두면 하나를
        # 고칠 때 다른 하나가 같이 뒤집힌다 — 실제로 그렇게 됐다.
        "pre_existing_dangling": dict(sorted(pre_existing.items())),
        "pre_existing_dangling_count": sum(pre_existing.values()),
        # **정의도 로그를 채운다.** `interface_uses` 는
        # `config system interface` 를 건너뛰므로 참조만 세면 "아무도 안
        # 가리키는 정의가 버려지는" 경우가 통째로 빠진다 — 그러면 배너는
        # "버려진다"고 하고 4단계는 "로그가 비었는지 확인하라"고 해서 한
        # 패널 안에서 모순이 난다(실 config 7,280쌍 중 261쌍).
        "log_will_be_empty": not dangling and not orphan_definitions,
        "clean": not orphan_definitions and not orphan_references,
    }


def _quoted_spans(line: str, name: str):
    """`"name"` 이 **완전한 토큰으로** 나오는 자리(따옴표 안쪽 좌표).

    부분 일치를 허용하면 `port3` 이 `port3-backup` 을 먹는다 — `-`·`_` 가
    합법 이름 문자라 단어 경계(`\b`)로도 못 막는다. 따옴표째 대조한다.
    """
    needle = '"' + name + '"'
    out, i = [], line.find(needle)
    while i >= 0:
        out.append((i + 1, i + 1 + len(name)))
        i = line.find(needle, i + len(needle))
    return out


def plan_rename(old_lines, mapping, new_header=None,
                new_interfaces=None) -> RenamePlan:
    """인터페이스 배열을 새 장비에 맞추는 계획.

    `mapping` 은 `{옛 이름: 새 이름}`. 빈 값이면 **바꾸지 않는다**(그 자리
    그대로 두겠다는 뜻). `new_interfaces` 를 주면 새 이름이 실제로 그
    장비에 있는지 대조한다 — 없는 포트로 옮기면 복원이 조용히 깨진다.
    """
    plan = RenamePlan()
    old_if = interfaces(old_lines)
    uses = interface_uses(old_lines)

    # ① 답해야 하는 것들을 **먼저** 센다. 막혔는데 계획에 행이 남으면
    #    그 계획으로 헤더만 바뀐 반쪽 산출물이 나온다.
    known_new = set(new_interfaces or [])
    targets = {}
    for old, new in (mapping or {}).items():
        new = (new or "").strip()
        if not new or new == old:
            continue
        if len(new) > MAX_NAME:
            plan.too_long.append(new)
            continue
        if known_new and new not in known_new:
            plan.not_on_new.append(new)
            continue
        targets[old] = new

    # 개명 결과가 **그대로 남는 다른 인터페이스**와 같아지나
    staying = set(old_if) - set(targets)
    for old, new in sorted(targets.items()):
        if new in staying:
            plan.collisions.append(new)
    # 두 이름이 한 이름으로
    seen = {}
    for old, new in sorted(targets.items()):
        if new in seen:
            plan.collisions.append(new)
        seen[new] = old

    # 새 장비에 없는데 매핑도 안 한 것 — 사람이 정해야 한다
    if known_new:
        for name in sorted(old_if):
            if name not in known_new and name not in targets:
                plan.unmapped.append(name)

    if plan.blocking:
        return plan          # 막히면 **행이 하나도 없다**

    # ② 헤더 — Fortinet 수동 절차의 1번이다
    if new_header:
        info = read_header(old_lines)
        if info.header and info.header != new_header:
            # **원문 좌표로 잡는다.** `read_header` 는 `strip()` 한 것을
            # 돌려주는데 `apply_rename` 은 원문과 대조해 다르면 말없이
            # 건너뛴다 — 앞뒤 공백이 있으면 "바꿨다"고 보고해 놓고 첫 줄은
            # 옛 모델 그대로인 파일이 나온다(보고와 산출물이 갈린다).
            i = info.header_line_no - 1
            body = old_lines[i].rstrip("\r\n")
            start = len(body) - len(body.lstrip())
            plan.rows.append(RenameRow(
                line_no=info.header_line_no, col_start=start,
                col_end=len(body.rstrip()),
                old=info.header, new=new_header, kind="header"))

    # ③ 정의 — `config system interface` 의 `edit "..."`
    for old, new in sorted(targets.items()):
        i = old_if.get(old)
        if not i:
            continue
        for a, b in _quoted_spans(old_lines[i - 1], old):
            plan.rows.append(RenameRow(
                line_no=i, col_start=a, col_end=b, old=old, new=new,
                kind="definition", section="config system interface"))

    # ④ 참조 — 객체·정책이 그 이름을 가리키는 곳
    for old, new in sorted(targets.items()):
        for u in uses.get(old, []):
            line = old_lines[u["line_no"] - 1]
            for a, b in _quoted_spans(line, old):
                plan.rows.append(RenameRow(
                    line_no=u["line_no"], col_start=a, col_end=b,
                    old=old, new=new, kind="reference",
                    field=u["field"], section=u["section"]))
    return plan


def apply_rename(lines, plan: RenamePlan) -> list:
    """계획을 적용한다. **뒤에서부터** — 앞을 먼저 바꾸면 좌표가 밀린다.

    매칭된 구간 밖의 바이트는 건드리지 않는다. `ENC` 값·인증서 블롭은
    참조 필드가 아니므로 **원리적으로** 손이 닿지 않는다.
    """
    out = list(lines)
    for r in sorted(plan.rows, key=lambda r: (r.line_no, r.col_start),
                    reverse=True):
        i = r.line_no - 1
        if not (0 <= i < len(out)):
            continue
        line = out[i]
        if line[r.col_start:r.col_end] != r.old:
            continue          # 원문이 계획 시점과 다르다 — 건드리지 않는다
        out[i] = line[:r.col_start] + r.new + line[r.col_end:]
    return out
