from __future__ import annotations

import json as _json
import re as _re


def parse_config_text(raw_text):
    """Parse FortiGate config text without using Flask route handlers."""
    text = raw_text if isinstance(raw_text, str) else str(raw_text or "")
    parser = FortiGateConfigParser(text)
    return parser.parse()



def _normalize_items(items):
    """Return a safe list of dictionaries for diff comparison."""
    if items is None:
        return []
    if isinstance(items, dict):
        return [items]
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    return []

def _vdom_prefix(item) -> str:
    """다중 VDOM 항목의 diff 키 접두. 단일 VDOM(필드 없음)이면 빈 문자열.

    **VDOM 은 정책 번호(그리고 객체 이름)의 일부다.** 번호·이름만 키로 잡으면
    root#1 이 guest#1 에게 맵에서 덮어써져 비교 우주에서 사라지고, 남은 한
    쌍은 서로 다른 VDOM 의 정책끼리 before/after 로 비교된다 — 이 diff 는
    감사 타임라인과 PCI-DSS 증적 워크북까지 흘러간다(라운드 54 완성도 렌즈).
    `_compute_config_diff` 가 fw/proxy 번호 충돌에 대해 이미 적어 둔 논리와
    같은 논리다.
    """
    v = str((item or {}).get("vdom") or "").strip()
    return f"{v}/" if v else ""


def _build_policy_map(items):
    result = {}
    for item in _normalize_items(items):
        pid = str(item.get("policy_id") or item.get("id") or item.get("_edit") or "").strip()
        if pid:
            result[_vdom_prefix(item) + pid] = item
    return result


def _index_named_items(items, name_key="name"):
    result = {}
    for item in _normalize_items(items):
        name = str(item.get(name_key) or item.get("_edit") or item.get("policy_id") or item.get("id") or "").strip()
        if name:
            # firewall_address 등 이름 객체도 VDOM 마다 같은 이름이 정상이다
            result[_vdom_prefix(item) + name] = item
    return result


def _simplify_policy_for_compare(policy):
    if not isinstance(policy, dict):
        return {}
    # hit_count·last_used는 런타임 통계라 diff 노이즈지만, status는 config
    # 속성이다 — 정책 활성↔비활성 전환은 검토자가 반드시 봐야 하는 변경인데
    # 무시되고 있었다(v79 감사 증적 자체 재비판에서 발견).
    ignored_keys = {"hit_count", "last_used"}
    return {k: v for k, v in policy.items() if k not in ignored_keys}




def _section_signature(items):
    result = {}
    for item in _normalize_items(items):
        key = str(item.get("name") or item.get("_edit") or item.get("policy_id") or item.get("id") or "").strip()
        if key:
            cleaned = {k: v for k, v in item.items() if k not in {"uuid"}}
            result[_vdom_prefix(item) + key] = cleaned
    return result

def _humanize_key(key) -> str:
    s = str(key or "")
    for pre in ("firewall_", "system_"):
        if s.startswith(pre):
            s = s[len(pre):]
            break
    s = s.replace("_", " ").replace("-", " ")
    return _re.sub(r"\b\w", lambda m: m.group(0).upper(), s)


def _normalize_value(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "-"
    if isinstance(value, dict):
        return _json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value).strip() or "-"


# **'바뀌었나'를 판정하는 곳은 하나여야 한다.** 예전에는 둘이었고 서로
# 달랐다: 개수를 세는 쪽(`_simplify_policy_for_compare`)은 hit_count·last_used
# 만 무시한 채 원시 dict 를 비교했고, 목록을 만드는 쪽은 uuid 도 무시하고
# 값을 정규화했다. 그 결과 uuid 만 바뀐 정책(정책을 지우고 같은 번호로 다시
# 만들면 흔하다)이 "정책 1건 변경"으로 세어지면서 변경 목록은 비어,
# **같은 문서가 '1건 변경'과 '변경된 정책 없음'을 동시에** 말했다(라운드 45).
#
# uuid·정책번호는 정체성이지 설정이 아니고, hit_count·last_used 는 런타임
# 통계라 매번 달라진다 — 둘 다 '변경'이 아니다. status 는 남긴다(활성↔비활성은
# 검토자가 반드시 봐야 한다).
_CHANGE_IGNORED_FIELDS = ("policy_id", "_edit", "uuid", "_ptype",
                          "hit_count", "last_used")


def raw_section_entries(text: str) -> dict:
    """설정 원문에서 **모든** `config` 구역과 그 항목의 지문을 뽑는다.

    비교(diff)가 `config system admin`·VPN·로그·UTM 프로파일을 한 번도 보지
    않고 "그 밖의 설정 변경 0건"이라 말하고 있었다 — 파서가 방화벽 정책·객체만
    구조화하고, 그 섹션들은 `known_sections` 라 `other_changes` 루프도 건너뛰기
    때문이다. 실측: **super_admin 계정을 추가해도 변경 0건**이었다(라운드 45).
    PCI-DSS 정기검토 증적에 그 문장이 서명돼 나간다.

    판정(severity)에는 쓰지 않는다 — 여기서 하는 일은 '무엇이 달라졌나'를
    말할 수 있을 만큼만 원문을 훑는 것이다. 의미를 해석하지 않으므로 새 섹션이
    생겨도 자동으로 따라온다(목록 기반 방어가 늘 절반짜리였다는 이 루프의 결론).

    반환: {"system admin": {"backdoor": "<본문 지문>"}, ...}
          edit 항목이 없는 구역은 {"": "<본문 지문>"} 한 칸.
    """
    import hashlib as _hl

    sections: dict[str, dict] = {}
    stack: list = []          # (섹션명, {항목: [줄]}) — 중첩 config 대응
    edit_stack: list = []     # 현재 edit 이름
    in_multiline = False      # 따옴표가 열린 채 줄이 넘어간 상태

    def _odd_quotes(line: str) -> bool:
        """이 줄이 **따옴표를 연 채로** 끝나는가.

        `count('"') % 2` 로 세면 이스케이프를 못 본다. FortiOS 가 스스로
        내보내는 `set comments "allow 3\\" test rig"` 한 줄이 홀수로 읽혀
        **그 뒤 파일 전체가 값 안으로 흡수됐다**(라운드 47 실측: 관리자 권한
        승격과 로그 서버 변경이 통째로 침묵). 바로 옆 파서는 이미
        `(?:[^"\\\\]|\\\\.)*` 로 정확히 처리하고 있었다.
        """
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

    def _flush(name, entries, vdom=""):
        """구역 하나를 결과에 넣는다.

        **VDOM 이름을 키에 넣는다.** FortiGate 는 VDOM 마다 `edit 1` 부터 다시
        번호를 매기므로, 승격만 하고 이름을 안 넣으면 root/1 과 guest/1 이
        충돌해 **나중 것이 먼저 것을 덮는다** — root VDOM 의 기본 게이트웨이를
        공격자 IP 로 바꿔도 지문이 같아 '변경 0건'이 나왔다(라운드 47 실측).
        같은 파일을 읽는 파서는 이미 `(edit, vdom)` 쌍으로 구분하고 있었다.
        """
        bucket = sections.setdefault(name, {})
        for entry, lines in entries.items():
            key = f"{vdom}/{entry}" if vdom else entry
            sig = _hl.sha256(
                "\n".join(sorted(str(x) for x in lines))
                .encode("utf-8", "ignore")).hexdigest()[:16]
            bucket[key] = sig

    def _container_vdom():
        """지금 스택에서 바깥 vdom/global 컨테이너의 edit 이름."""
        for i, (nm, _) in enumerate(stack):
            if nm.split()[0].lower() in ("vdom", "global") if nm else False:
                return edit_stack[i] if i < len(edit_stack) else ""
        return ""

    for line in (text or "").splitlines():
        s_line = line.strip()

        # **여러 줄 값 안에서는 문법을 해석하지 않는다.** replacemsg buffer·
        # certificate·automation-action 의 cli-script 는 따옴표 안에 여러 줄을
        # 담고, 그 안에 `end` 나 `config ...` 텍스트가 그대로 들어간다.
        if in_multiline:
            if stack:
                key = edit_stack[-1] if edit_stack else ""
                stack[-1][1].setdefault(key, []).append(s_line)
            if _odd_quotes(s_line):
                in_multiline = False
            continue

        # 주석 검사를 따옴표 검사보다 **앞에** 둔다. 반대로 두었더니 따옴표가
        # 홀수 개인 주석 한 줄에 훑기 전체가 죽었다(라운드 47 실측).
        if not s_line or s_line.startswith("#"):
            continue

        if _odd_quotes(s_line):
            in_multiline = True
            if stack:
                key = edit_stack[-1] if edit_stack else ""
                stack[-1][1].setdefault(key, []).append(s_line)
            continue

        low = s_line.lower()
        if low.startswith("config "):
            stack.append((s_line[len("config "):].strip(), {}))
            continue
        if low == "end":
            if stack:
                name, entries = stack.pop()
                if stack:
                    # **VDOM 설정에서는 중첩을 흡수하면 안 된다.** multi-VDOM
                    # 백업은 `config firewall policy` 가 `config vdom` 안에
                    # 있어서, 흡수하면 구역 구분이 통째로 사라지고 정책 변경이
                    # 두 번 세어졌다(라운드 46). 바깥이 vdom/global 컨테이너면
                    # 안쪽을 최상위로 올리되 **VDOM 이름을 함께** 남긴다.
                    outer = stack[-1][0].split()[0].lower() if stack[-1][0] else ""
                    if outer in ("vdom", "global"):
                        _flush(name, entries,
                               edit_stack[-1] if edit_stack else outer)
                    else:
                        stack[-1][1].setdefault(
                            edit_stack[-1] if edit_stack else "", []).append(
                                f"config {name} " + " ".join(
                                    f"{k}={v}" for k, v in sorted(entries.items())))
                else:
                    _flush(name, entries)
            continue
        if low.startswith("edit "):
            edit_stack.append(s_line[len("edit "):].strip().strip('"'))
            if stack:
                stack[-1][1].setdefault(edit_stack[-1], [])
            continue
        if low == "next":
            if edit_stack:
                edit_stack.pop()
            continue
        if stack:
            key = edit_stack[-1] if edit_stack else ""
            stack[-1][1].setdefault(key, []).append(s_line)

    # **잘린 백업의 마지막 구역을 버리지 않는다.** 파일 끝에서 스택을 비우지
    # 않아 마지막 구역이 통째로 사라졌다(라운드 46). 그런데 가장 바깥 프레임만
    # 비웠더니, 내용이 안쪽에 있는 중첩 구역(`config global` 안의
    # `config system admin`)은 여전히 사라졌다 — **절반만 고친 것이다**
    # (라운드 47 실측). 안쪽부터 전부 비운다.
    while stack:
        name, entries = stack.pop()
        _vd = edit_stack[len(stack)] if len(edit_stack) > len(stack) else ""
        _outer = stack[-1][0].split()[0].lower() if stack and stack[-1][0] else ""
        _flush(name, entries, _vd if _outer in ("vdom", "global") else "")
    return sections


def _object_summary(item) -> str:
    """객체 한 줄 요약 — **서버가 한 번 만들어 화면·파일이 같이 쓴다.**

    이것도 브라우저(`summarizeObjectValue`)와 파이썬 두 벌이었고, 우선순위가
    달라 **같은 객체를 다르게** 말했다: 별칭과 멤버를 둘 다 가진 aggregate
    인터페이스를 파일은 `PARTNER-UPLINK`, 화면은 `port3, port4` 로 적었다
    (라운드 45 실측). 값은 정책 변경 목록과 같은 이유로 한 곳에서 만든다.
    """
    if not isinstance(item, dict):
        return "-"
    if item.get("subnet_cidr"):
        return _normalize_value(item["subnet_cidr"])
    if isinstance(item.get("subnet"), (list, tuple)) and item["subnet"]:
        return " ".join(str(v) for v in item["subnet"])
    # 파서는 하이픈 키로 낸다(`start-ip`). 밑줄 키만 보던 분기는 양쪽 구현
    # 모두에서 죽은 코드였다 — 둘 다 본다.
    start = item.get("start-ip") or item.get("start_ip")
    end = item.get("end-ip") or item.get("end_ip")
    if start and end:
        return f"{start} - {end}"
    for key in ("fqdn", "wildcard_fqdn", "wildcard-fqdn"):
        if item.get(key):
            return _normalize_value(item[key])
    for key in ("member", "resolved_members"):
        if item.get(key):
            return _normalize_value(item[key])
    ports = []
    for proto in ("tcp", "udp", "sctp"):
        val = item.get(f"{proto}-portrange") or item.get(f"{proto}_portrange")
        if val:
            ports.append(f"{proto.upper()} {_normalize_value(val)}")
    if ports:
        return " / ".join(ports)
    if item.get("resolved"):
        return _normalize_value(item["resolved"])
    if item.get("alias"):
        return f"{item['alias']} ({item.get('name') or item.get('_edit') or ''})"
    detail = " | ".join(
        f"{_humanize_key(k)}: {_normalize_value(v)}"
        for k, v in sorted(item.items())
        if k not in ("name", "_edit", "uuid", "associated-interface"))
    return detail or "-"


def _changed_fields(before: dict, after: dict, ignored=()) -> list:
    """두 dict 에서 **의미 있게** 달라진 필드를 before/after 로 편다.

    비교 전에 값을 정규화한다 — 빈 문자열과 '줄 자체가 없음', 공백만 있는
    값과 없는 값은 장비에서 같은 뜻인데, 정규화 없이 비교하면 '바뀌었다'로
    잡혀 검토자가 헛것을 쫓는다.
    """
    keys = list(dict.fromkeys(list(before or {}) + list(after or {})))
    out = []
    for key in keys:
        if key in ignored:
            continue
        old_val = _normalize_value((before or {}).get(key))
        new_val = _normalize_value((after or {}).get(key))
        if old_val != new_val:
            out.append({"field": key, "label": _humanize_key(key),
                        "before": old_val, "after": new_val})
    return out


def policy_change_fields(before: dict, after: dict) -> list:
    """정책에서 바뀐 필드 — **화면·파일·개수가 모두 이 하나를 쓴다.**

    이 목록은 원래 브라우저 안에만 있었다(`buildPolicyChangeList`). 내보내기를
    붙이면서 파이썬으로 한 벌 더 쓸 뻔했는데, 그러면 '무엇이 바뀌었는가'를
    말하는 구현이 둘이 되어 화면과 감사 파일이 서로 다른 말을 하게 된다 —
    이 루프가 판정 경로에서 되풀이해 겪은 실패다. 서버가 한 번 계산해 응답에
    실으면 화면도 워크북도, **그리고 요약의 건수도** 같은 것을 읽는다.
    """
    return _changed_fields(before, after, _CHANGE_IGNORED_FIELDS)


def _compute_config_diff(old_data, new_data, old_raw: str, new_raw: str):
    """설정 두 개를 비교한다.

    **원문은 선택 인자가 아니다.** 기본값을 두었더니 호출부 두 곳 중
    한 곳(`/api/audit/timeline`)이 안 넘겨서, 원문 훑기가 그 경로에서만
    통째로 무효였다 — 하필 그 경로가 PCI-DSS 정기검토 증적을 만든다.
    `super_admin` 계정 추가가 증적 워크북에 "변경 0건"으로 서명돼 나갔다
    (라운드 46 실측). 빠뜨리면 TypeError 로 즉시 걸리게 한다.

    firewall과 proxy 정책을 **둘 다** 센다. 예전에는 firewall만 세고 proxy는
    'other changes'로 흘려보냈는데, 그 수치가 감사 증적 워크북의
    "Policies added / removed / modified" 열로 그대로 들어간다. proxy 정책을
    추가한 구간이 "정책 변경 0건"으로 기록되는 건 증적 문서로서 결함이다.

    FortiGate는 두 종류에 각각 1번부터 번호를 매기므로 키에 종류를 붙인다 —
    안 그러면 firewall 7번과 proxy 7번이 서로를 덮어쓴다.
    """
    def _policies_of(data):
        out = {}
        for section, ptype in (("firewall_policy", "firewall"),
                               ("firewall_proxy_policy", "proxy")):
            items = data.get(section) or ([] if section != "firewall_policy"
                                          else data.get("policies") or [])
            for key, pol in _build_policy_map(items).items():
                out[f"{ptype}:{key}"] = {**pol, "_ptype": ptype}
        return out

    _raw_old = raw_section_entries(old_raw)
    _raw_new = raw_section_entries(new_raw)

    old_policies = _policies_of(old_data)
    new_policies = _policies_of(new_data)

    added_policies = []
    removed_policies = []
    changed_policies = []

    for pid, policy in new_policies.items():
        if pid not in old_policies:
            added_policies.append(policy)
        else:
            # **'바뀌었다'와 '무엇이 바뀌었나'는 같은 계산에서 나와야 한다.**
            # 따로 두었더니 한쪽만 '변경'이라 말하는 문서가 나왔다(라운드 45).
            changes = policy_change_fields(old_policies[pid], policy)
            if changes:
                changed_policies.append({
                    # added/removed는 정책 객체의 int ID를 그대로 내는데 여기만
                    # 맵 키(str)를 내고 있었다(감사 C6). 타입을 맞춘다.
                    "policy_id": (int(policy.get("policy_id"))
                                  if str(policy.get("policy_id", "")).isdigit()
                                  else policy.get("policy_id")),
                    "policy_type": policy.get("_ptype", "firewall"),
                    "name": policy.get("name") or old_policies[pid].get("name") or "",
                    "before": old_policies[pid],
                    "after": policy,
                    # 화면이 브라우저에서 다시 계산하던 것 — 이제 한 곳에서 낸다.
                    "changes": changes,
                })

    for pid, policy in old_policies.items():
        if pid not in new_policies:
            removed_policies.append(policy)

    object_sections = [
        "firewall_address",
        "firewall_addrgrp",
        "firewall_proxy_address",
        "firewall_proxy_addrgrp",
        "firewall_service_custom",
        "firewall_service_group",
        "system_interface",
    ]

    added_objects = []
    removed_objects = []
    # **객체 '내용' 변경은 어디에서도 안 잡히고 있었다.** 이름과 개수만 보고
    # 추가·삭제만 셌으므로, 주소 객체 하나를 10.1.1.0/24 에서 0.0.0.0/0 으로
    # 바꾸면 '변경 0건'이 나왔다 — 방화벽에서 가장 위험한 변경이 침묵한다.
    # 정책은 한 줄도 안 건드리고 객체만 넓히는 것은 흔한 수법이자 흔한 실수다
    # (라운드 45 실측). 게다가 이 섹션들은 `known_sections` 에 있어
    # `other_changes` 루프도 건너뛴다 — 어느 경로로도 안 잡혔다.
    changed_objects = []

    for section in object_sections:
        old_map = _index_named_items(old_data.get(section) or [])
        new_map = _index_named_items(new_data.get(section) or [])

        for name, item in new_map.items():
            if name not in old_map:
                added_objects.append({
                    "section": section,
                    "name": name,
                    "item": item,
                    "summary": _object_summary(item),
                })
            else:
                # uuid 는 정체성이지 설정이 아니다 — 정책과 같은 규칙.
                fields = _changed_fields(old_map[name], item,
                                         ("uuid", "_edit", "name"))
                if fields:
                    changed_objects.append({
                        "section": section,
                        "name": name,
                        "before": old_map[name],
                        "after": item,
                        "changes": fields,
                        "summary_before": _object_summary(old_map[name]),
                        "summary_after": _object_summary(item),
                    })

        for name, item in old_map.items():
            if name not in new_map:
                removed_objects.append({
                    "section": section,
                    "name": name,
                    "item": item,
                    "summary": _object_summary(item),
                })


    known_sections = {
        "firewall_policy",
        "firewall_proxy_policy",
        "policies",
        "firewall_address",
        "firewall_addrgrp",
        "firewall_proxy_address",
        "firewall_proxy_addrgrp",
        "firewall_service_custom",
        "firewall_service_group",
        "system_interface",
    }
    other_changes = []
    # **파서가 구조화한 것만 보면 절반도 못 본다.** 파서 출력 키는 firewall_* ·
    # system_interface · meta 뿐이라, `config system admin`·VPN·로그·UTM
    # 프로파일은 여기 애초에 없었다 — 그래서 super_admin 계정을 추가해도
    # "그 밖의 변경 0건"이 나왔다(라운드 45 실측). 원문을 직접 훑어 보완한다.
    raw_sections = set(_raw_old) | set(_raw_new)
    # 정책·객체는 위에서 이미 자세히 비교했다 — 여기서 또 세면 두 번 센다.
    _covered_raw = {"firewall policy", "firewall proxy-policy", "firewall address",
                    "firewall addrgrp", "firewall proxy-address",
                    "firewall proxy-addrgrp", "firewall service custom",
                    "firewall service group", "system interface"}
    for section in sorted(raw_sections):
        if section.lower() in _covered_raw:
            continue
        old_sig = _raw_old.get(section) or {}
        new_sig = _raw_new.get(section) or {}
        added = [n for n in new_sig if n not in old_sig]
        removed = [n for n in old_sig if n not in new_sig]
        changed = [n for n in new_sig
                   if n in old_sig and new_sig[n] != old_sig[n]]
        if added or removed or changed:
            other_changes.append({
                "section": section,
                # edit 이름이 없는 구역(단일 설정 블록)은 빈 문자열 키다 —
                # 화면에 그대로 내보내면 빈칸으로 보이므로 구역명을 쓴다.
                "added": [n or section for n in added],
                "removed": [n or section for n in removed],
                "changed": [n or section for n in changed],
            })

    # 파서가 아는 섹션 중 위에서 안 다룬 것도 계속 본다(회귀 방지).
    all_sections = set(old_data.keys()) | set(new_data.keys())
    for section in sorted(all_sections):
        if section in known_sections or section == "meta":
            continue
        old_sig = _section_signature(old_data.get(section) or [])
        new_sig = _section_signature(new_data.get(section) or [])
        added = [name for name in new_sig if name not in old_sig]
        removed = [name for name in old_sig if name not in new_sig]
        changed = [name for name in new_sig if name in old_sig and new_sig[name] != old_sig[name]]
        if added or removed or changed:
            other_changes.append({
                "section": section,
                "added": added,
                "removed": removed,
                "changed": changed,
            })

    return {
        "summary": {
            "added_policies": len(added_policies),
            "removed_policies": len(removed_policies),
            "changed_policies": len(changed_policies),
            "added_objects": len(added_objects),
            "removed_objects": len(removed_objects),
            "changed_objects": len(changed_objects),
            "other_changes": len(other_changes),
        },
        "added_policies": added_policies,
        "removed_policies": removed_policies,
        "changed_policies": changed_policies,
        "added_objects": added_objects,
        "removed_objects": removed_objects,
        "changed_objects": changed_objects,
        "other_changes": other_changes,
    }
import json
import re as _re_mod
import secrets as _secrets
from pathlib import Path
from typing import Any

from flask import (Flask, g, jsonify, render_template, request,
                   send_from_directory, send_file)

from app.parsers.config_parser import (FortiGateConfigParser,
                                       config_intake_problem)
from app.parsers.policy_csv_parser import PolicyStatsCsvParser
from app.parsers.runtime_parser import RuntimeStatsParser
from app.services.policy_renderer import build_view_model

from app.services.workbook_exporter import build_workbook
from datetime import date as _date
from app.services.severity_engine import evaluate_severity, _obj_matches
from app.services.severity_engine import onetime_schedule_map as _se_onetime
from app.services.ai_analyzer import analyze_policies, analyze_single_policy, check_ollama_available
from app.services.license_checker import (
    activate, is_licensed, get_license_info,
    license_problem as _lic_problem,
    update_window_end as _lic_window_end,
)
from io import BytesIO

import sys as _sys
APO_VERSION = "v134-2026-09-21"
if getattr(_sys, 'frozen', False) and hasattr(_sys, '_MEIPASS'):
    BASE_DIR = Path(_sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).resolve().parent.parent


def _stats_count(runtime_stats) -> int:
    """사용량 통계 건수. 평평한 형태와 종류별 형태를 모두 센다.

    `_vdom` 꼬리표(라운드 55, VDOM 귀속 메타)는 정책 행이 아니다 — 세면
    평평한 통계의 건수가 1 부풀고, 발견 1(태그 오염)과 겹치면 '사용량
    있음'이 태그 하나로 제조된다(라운드 56 계약 렌즈).
    """
    if not isinstance(runtime_stats, dict):
        return 0
    if "firewall" in runtime_stats or "proxy" in runtime_stats:
        # 섞인 dict에서 평평한 항목의 '필드 수'를 정책 수로 세지 않도록 한정한다.
        return sum(len(runtime_stats.get(k) or {}) for k in ("firewall", "proxy"))
    return sum(1 for k in runtime_stats if k != "_vdom")


def _has_stat_rows(runtime_stats) -> bool:
    """실제 정책 행이 하나라도 있는가(`_vdom` 꼬리표 제외)."""
    return _stats_count(runtime_stats) > 0


def _stats_snapshot(runtime_stats) -> dict:
    """판정 근거로 쓰는 통계를 **고쳐도 되는 사본**으로 뜬다.

    "보관소에 먼저 쓰고 성공한 뒤 메모리를 바꾼다" 는 규칙은 바꾸는 대상이
    메모리와 **다른 객체**일 때만 성립한다. CSV·붙여넣기 두 경로는
    `app.config['last_runtime_stats']` 를 그대로 받아 `.update`/`.pop` 으로
    제자리에서 고친 뒤 보관소에 썼다 — 쓰기가 실패해 503 을 내도 판정 근거는
    이미 바뀌어 있었고, 마지막의 재대입은 같은 객체라 아무 일도 하지 않았다
    (리뷰 게이트 correctness, v129).

    두 단계만 복사하면 된다. 고치는 곳이 최상위와 종류별(`firewall`/`proxy`)
    딕셔너리뿐이고 정책 행 자체는 건드리지 않는다 — `deepcopy` 는 수만 행에서
    비싸다.
    """
    out: dict = {}
    for key, value in (runtime_stats or {}).items():
        out[key] = dict(value) if isinstance(value, dict) else value
    return out


_UNSET = object()   # _device_gate 의 '인자를 안 줬다'와 '빈 값을 줬다'를 가른다


def _attachment(filename: str) -> str:
    """Content-Disposition 값. 한글 파일명을 그대로 넣으면 헤더가 깨진다.

    ASCII 대체 이름과 RFC 5987 filename*를 함께 준다 — 옛 클라이언트는 앞을,
    요즘 브라우저는 뒤를 읽는다. 이름이 통째로 지워지면 모든 고객의 파일이
    한 이름으로 겹치므로(라운드 20), 글자를 버리지 않는 쪽을 택한다.
    """
    from urllib.parse import quote
    import re as _re
    # 방향 제어(RLO 등)·폭 0 문자는 보이지 않으면서 확장자 표시를 위장한다.
    # 헤더에 그대로 실으면 filename* 를 읽는 브라우저에서 '.txt.exe'가 뒤집혀
    # 보일 수 있다 — 파일명 금지 문자와 같은 급으로 지운다.
    filename = _re.sub(r"[​-‏‪-‮⁦-⁩﻿]", "",
                       filename)
    safe = _re.sub(r'[\x00-\x1f\x7f"\\/:*?<>|]+', "_", filename).strip() or "download"
    # 헤더가 수 KB로 부풀지 않게 자른다(확장자는 지킨다).
    if len(safe) > 80:
        _stem, _dot, _ext = safe.rpartition(".")
        safe = (f"{_stem[:72]}.{_ext}" if _dot and len(_ext) <= 6 else safe[:80])
    stem, dot, ext = safe.rpartition(".")
    stem = stem or safe
    ext = ext if dot else ""
    ascii_stem = stem.encode("ascii", "ignore").decode().strip(" ._")
    # 이름이 비ASCII뿐이면 대체 이름이 통째로 비어 **모든 고객이 같은 파일명**이
    # 된다 — filename* 를 못 읽는 클라이언트에서 정확히 그 사고가 다시 난다.
    # 원문에서 뽑은 짧은 지문을 붙여 구분을 지킨다.
    if len(ascii_stem) < 3 or any(ord(ch) > 127 for ch in stem):
        import hashlib as _h
        digest = _h.sha256(stem.encode("utf-8")).hexdigest()[:8]
        ascii_stem = f"{ascii_stem}_{digest}" if ascii_stem else f"apo_reports_{digest}"
    ascii_name = f"{ascii_stem}.{ext}" if ext else ascii_stem
    return (f'attachment; filename="{ascii_name}"; '
            f"filename*=UTF-8''{quote(safe, safe='')}")


def _hashlib_sha256_bytes(data: bytes) -> str:
    """원본 바이트의 SHA-256. 감사 보고서의 파일 동일성 주장은 디스크의 그
    파일과 대조 가능해야 하므로, 디코딩·개행 변환을 거친 문자열이 아니라
    바이트를 해시한다(리뷰 라운드 8)."""
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _config_sha(raw: str) -> str:
    """설정 원문의 SHA-256 앞 16자. 장비/스냅샷을 가리키는 안정된 식별자다.

    hostname은 공장 기본값 'FortiGate' 그대로인 장비가 흔해 서로 다른 고객
    장비가 같은 이름을 갖는다. 화면이 장비별로 기억하는 것(작업 완료 체크 등)을
    hostname에 걸면 그 장비들끼리 상태가 섞인다.
    """
    import hashlib
    return hashlib.sha256((raw or "").encode("utf-8", "replace")).hexdigest()[:16]


print(f"[APO] Version: {APO_VERSION}", flush=True)
print(f"[APO] Frozen: {getattr(_sys, 'frozen', False)}", flush=True)
print(f"[APO] BASE_DIR: {BASE_DIR}", flush=True)
print(f"[APO] Templates: {BASE_DIR / 'app' / 'templates'} "
      f"(exists={(BASE_DIR / 'app' / 'templates' / 'index.html').exists()})", flush=True)

# **고객 설정 파일을 임시 폴더에 두지 않는다.** frozen 에서 BASE_DIR 은
# `_MEIPASS`(실행 때마다 만들어지고 종료 때 지워지는 %TEMP% 하위)다. 거기에
# 업로드 원본과 파싱 산출물을 쌓았더니, 프로세스를 강제 종료하면 고객 설정이
# `%TEMP%\_MEI…` 에 무기한 남았다 — 이 PC 에 그런 잔존물이 48개 있었다
# (라운드 41 실측). 장비 보관소(sqlite)와 라이선스는 이미 exe 옆을 쓴다.
# 같은 자리에 둔다 — 지우는 것도, 찾는 것도 한 곳이면 된다.
if getattr(_sys, 'frozen', False):
    _DATA_ROOT = Path(_sys.executable).parent
else:
    _DATA_ROOT = BASE_DIR
IMPORT_DIR = _DATA_ROOT / "imports"
EXPORT_DIR = _DATA_ROOT / "exports"
DATA_DIR = _DATA_ROOT / "data"

# 포트는 한 곳에서 정하고 Host 검사도 그 값을 쓴다. 상수로 박아 뒀더니 다른
# 포트로 띄우는 순간 전 요청이 403 이 되어, 실기동 검증을 하려면 소스를 고쳐야
# 했다(라운드 27 지적) — 검증하기 어려운 코드는 결국 검증되지 않는다.
def _app_port() -> int:
    import os as _os
    try:
        p = int(_os.environ.get("APO_PORT") or 5000)
    except ValueError:
        return 5000
    return p if 1 <= p <= 65535 else 5000


APP_PORT = _app_port()
MAX_UPLOAD_BYTES = 50 * 1024 * 1024   # 50 MB

# 로컬 전용 앱이므로 자기 자신 외의 Host/Origin은 받지 않는다.
_ALLOWED_HOSTS = frozenset(
    f"{h}:{APP_PORT}" for h in ("127.0.0.1", "localhost", "[::1]")
) | frozenset(("127.0.0.1", "localhost", "[::1]"))
_ALLOWED_ORIGINS = frozenset(
    f"{scheme}://{h}" for scheme in ("http", "https")
    for h in (f"127.0.0.1:{APP_PORT}", f"localhost:{APP_PORT}", f"[::1]:{APP_PORT}")
)


# ── 컨테이너 배포의 접근 토큰 (B-77, 2026-08-26 Jayden 승인 — 안 A) ────────
#
# **Host 헤더는 인증 수단이 아니다.** 위 화이트리스트는 브라우저를 통한 DNS
# 리바인딩은 막지만, 비-브라우저 클라이언트는 그냥 스푸핑한다:
#   curl -H "Host: 127.0.0.1:5000" http://<노출된호스트>:5000/api/...
# exe·개발 모드는 127.0.0.1 에만 바인딩하므로 애초에 닿지 않지만, 컨테이너는
# 0.0.0.0 에 바인딩해야 포트 게시가 동작한다. 그래서 **컨테이너에서만** 토큰을
# 요구한다 — 뚫리면 고객 config 열람과 되돌릴 수 없는 정책 비활성화가 나간다.
#
# 브라우저 동선은 Jupyter 와 같다(같은 문제를 푸는 같은 모양): 첫 접속 URL 에
# ?token=… 을 붙이면 서버가 쿠키를 심고, 그 뒤로는 주소가 깨끗하다.
import os as _os_env
_DOCKER_MODE = _os_env.environ.get("APO_DOCKER") == "1"
_AUTH_COOKIE = "apo_access"
# 토큰이 너무 짧으면 요구하는 의미가 없다 — `-e APO_TOKEN=1` 을 막는다.
_MIN_TOKEN_LEN = 16


def _configured_token() -> str:
    return (_os_env.environ.get("APO_TOKEN") or "").strip()


def token_setup_error() -> str:
    """컨테이너 모드인데 토큰이 없거나 부실하면 사유. 정상이면 "".

    run.py 가 기동 전에 부르고, 서버도 요청마다 확인한다 — 한쪽만 두면
    다른 경로로 뜬 프로세스가 무인증으로 열린다.
    """
    if not _DOCKER_MODE:
        return ""
    tok = _configured_token()
    if not tok:
        return ("APO_TOKEN is required in container mode. The container "
                "listens on all interfaces, and APO has no other login — "
                "without a token anyone who can reach this port can read "
                "your firewall configuration and disable policies.\n"
                "  docker run -e APO_TOKEN=\"$(openssl rand -hex 24)\" ...\n"
                "Then open  http://127.0.0.1:5000/?token=<that value>")
    if len(tok) < _MIN_TOKEN_LEN:
        return (f"APO_TOKEN is too short ({len(tok)} characters). Use at "
                f"least {_MIN_TOKEN_LEN} — a guessable token is the same as "
                "no token on a port anyone can reach.")
    return ""


def _license_required():
    """라이선스 미보유 시 402 응답을 반환, 보유 시 None.
    유료 Export 계열 라우트의 서버측 게이트 (클라이언트 게이트 우회 차단)."""
    if not is_licensed():
        # **거절 사유를 함께 준다.** 키가 있는데 자격을 잃은 경우
        # (업데이트 창 경과·만료·기기 불일치) "라이선스를 등록하세요" 만
        # 말하면, 돈 낸 고객은 자기가 왜 막혔는지 알 수 없다. 그 안내 문구는
        # 지금까지 **키를 다시 붙여넣어야만** 나왔다.
        _why = _lic_problem()
        return jsonify({
            "error": _why or "License required. Please activate your Export license.",
            "problem": _why,
        }), 402
    return None


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "app" / "templates"),
        static_folder=str(BASE_DIR / "app" / "static"),
    )

    # 컨테이너 접근 토큰(B-77). **환경변수를 요청 시점에 읽지 않고 여기서
    # 한 번 고정한다** — 도중에 바뀌면 같은 프로세스가 요청마다 다른 정책으로
    # 답하게 되고, 테스트도 이 두 값만 뒤집어 검증한다.
    app.config['docker_mode'] = _DOCKER_MODE
    app.config['access_token'] = _configured_token()

    # 업로드 상한. 미설정 시 설정 파일 하나로 수 GB 메모리를 쓸 수 있다
    # (파싱 결과가 입력 대비 수십 배로 부풀고, 응답으로 한 번 더 직렬화된다).
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    @app.errorhandler(413)
    def _too_large(_e):
        limit_mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        # error_key — 값이 끼어드는 문장은 사전에 닿지 않는다. 서버는 값만 보내고
        # 화면이 문장을 만든다(app.js 의 SERVER_ERRORS).
        return jsonify({"error": f"File too large. Limit is {limit_mb} MB.",
                        "error_key": "file_too_large",
                        "limit_mb": limit_mb}), 413

    @app.before_request
    def _guard_origin():
        """DNS 리바인딩 / 크로스 오리진 요청 차단.

        APO는 127.0.0.1에 바인딩되지만 그것만으로는 브라우저를 통한 접근을
        막지 못한다. 공격자 페이지가 짧은 TTL로 자기 도메인을 127.0.0.1로
        재바인딩하면 브라우저는 그 페이지를 APO와 '같은 오리진'으로 취급해,
        저장된 FortiGate 관리자 토큰을 읽거나 실제 정책을 변경할 수 있다.

        - Host 화이트리스트: 재바인딩된 요청은 Host가 공격자 도메인이라 걸린다.
        - Origin 검사: multipart는 CORS 프리플라이트가 없어 JSON 라우트와 달리
          크로스 오리진 POST가 그대로 도달하므로 여기서 막는다.
        """
        host = (request.host or "").lower()
        if host not in _ALLOWED_HOSTS:
            return jsonify({"error": "Invalid Host header"}), 403

        origin = request.headers.get("Origin")
        if origin and origin.lower() not in _ALLOWED_ORIGINS:
            return jsonify({"error": "Cross-origin request rejected"}), 403
        return _guard_access_token()

    def _guard_access_token():
        """컨테이너 배포의 접근 토큰(B-77). 컨테이너가 아니면 아무 일도 안 한다.

        **Host 검사 뒤에 온다.** 앞에 두면 토큰이 틀린 요청에까지 이 앱의
        존재를 알려 줄 이유가 없다.
        """
        if not app.config.get('docker_mode'):
            return None
        want = app.config.get('access_token') or ""
        if not want:
            # run.py 가 기동을 막지만, 다른 경로로 뜬 프로세스가 있을 수 있다.
            # 그때 열어 두면 이 기능이 없는 것과 같다 — 닫는다.
            return jsonify({"error": "Server is not configured for container "
                                     "access. Set APO_TOKEN and restart."}), 503
        import hmac as _hmac
        for got in (request.cookies.get(_AUTH_COOKIE),
                    request.headers.get("X-APO-Token"),
                    request.args.get("token")):
            # 타이밍 비교 — 토큰을 한 글자씩 알아내는 경로를 열지 않는다.
            if got and _hmac.compare_digest(str(got), want):
                # 주소창의 ?token= 은 어깨너머·기록에 남는다. 한 번 확인하면
                # 쿠키로 옮기고 URL 에서 지운다(Jupyter 와 같은 동선).
                if request.args.get("token") and not request.cookies.get(_AUTH_COOKIE):
                    g._apo_set_cookie = want
                return None
        return jsonify({
            "error": "Access token required. Open this URL with ?token=… "
                     "(the value you passed as APO_TOKEN), or send it as the "
                     "X-APO-Token header.",
            "error_key": "access_token_required"}), 401

    @app.after_request
    def _issue_access_cookie(resp):
        tok = getattr(g, "_apo_set_cookie", None)
        if tok:
            # HttpOnly — 화면 스크립트가 읽을 이유가 없고, XSS 로 새는 경로를
            # 하나 줄인다. Secure 는 안 건다(로컬 배포는 http 다).
            resp.set_cookie(_AUTH_COOKIE, tok, httponly=True,
                            samesite="Lax", path="/")
        return resp

    from datetime import datetime as _dt

    @app.context_processor
    def inject_year():
        # apo_version은 정적 자산 캐시 무효화에 쓴다. 버전을 안 붙이면 업그레이드
        # 후에도 브라우저가 옛 app.js를 그대로 쓰고, 새 HTML의 화면 요소를
        # 살려낼 코드가 없어 **아무것도 안 보이는** 상태가 된다(실사용 보고:
        # v105의 일괄 보고 패널이 통째로 안 보였다).
        return {'current_year': _dt.now().year, 'apo_version': APO_VERSION}

    # ── 판정 프로파일 ──────────────────────────────────────────────────────
    # 시작 시 한 번 로드한다(APO_PROFILE 환경변수 또는 default + 구형
    # customer_rules.json 병합). UI에서 넘어온 임계값 오버라이드는
    # thresholds_override에 보관해 classify와 export가 같은 기준을 쓰게 한다.
    from app.services.profile_loader import (
        load_profile, engine_context, describe_inactive_rules, to_customer_rules,
    )
    from app.services import ruleset as ruleset_svc
    # 티켓 번호 형식은 화면에서 바꾸고 디스크에 남긴다(아래 /api/settings/ticket).
    from app.services import runtime_settings as _rs
    from app.services.runtime_settings import MAX_SCAN_LEN as _TICKET_SCAN_LEN
    import re as _re_mod
    app.config['profile'] = load_profile()
    app.config['thresholds_override'] = {}

    # UI가 조정할 수 있는 임계값. 이 밖의 키는 무시한다(임의 키 주입 방지).
    _THRESHOLD_FIELDS = {
        "dormancy_days":              ("int",  1, 3650),
        "long_dormancy_days":         ("int",  1, 7300),
        # 승인 유효기간(일). 0 = 유예 기능 끔.
        "approval_window_days":       ("int",  0, 3650),
        "use_absolute_hit_threshold": ("bool", None, None),
        "su_hit_multiplier":          ("int",  1, 100000),
        "ss_hit_threshold":           ("int",  1, 1000000),
        "ss_schedule_age_years":      ("int",  1, 20),
        "registration_fallback_year": ("int",  2000, 2100),
    }

    def _threshold_presets() -> list[dict]:
        """프리셋 정의. **값은 profiles/presets.yaml 한 곳에만 있다.**

        전에는 HTML 버튼 속성(data-dorm/data-long)에 있어서 8개 임계값 중
        2개만 바꿨다 — 'Strict' 를 눌러도 hit 임계값·승인 유예는 그대로라
        이름이 약속한 것을 지키지 못했다. 파일이 없거나 깨져도 화면은
        떠야 하므로 실패는 빈 목록이다(프리셋 없이도 직접 입력은 된다).
        """
        # **경로는 프로파일과 같은 규칙으로 찾는다.** 여기서만 __file__ 기준
        # 절대경로를 쓰면 exe 배포본(_MEIPASS·exe 옆 폴더)에서 못 찾아
        # 프리셋이 조용히 사라진다 — profiles/*.yaml 이 이미 푼 문제다.
        from app.services.profile_loader import _search_roots, _read_yaml
        raw = None
        for root in _search_roots():
            raw = _read_yaml(root / "profiles" / "presets.yaml")
            if raw:
                break
        if not raw:
            return []
        out = []
        for item in (raw.get("presets") or []):
            if not isinstance(item, dict):
                continue
            # 프리셋도 임의 키를 심을 수 없다 — 판정 입력이므로 같은 게이트.
            out.append({
                "label": str(item.get("label") or ""),
                "why":   str(item.get("why") or ""),
                "thresholds": _sanitize_thresholds(item.get("thresholds") or {}),
            })
        return [p for p in out if p["label"] and p["thresholds"]]

    def _sanitize_thresholds(raw: dict) -> dict:
        out = {}
        for key, (kind, lo, hi) in _THRESHOLD_FIELDS.items():
            if key not in raw:
                continue
            val = raw[key]
            if val is None:
                out[key] = None       # 명시적 null = 해당 판정 끔
                continue
            if kind == "bool":
                out[key] = bool(val)
                continue
            # **bool 은 정수로 세지 않는다.** 파이썬에서 bool 은 int 의
            # 서브클래스라 `int(True) == 1` 이다 — `{"dormancy_days": true}` 가
            # 조용히 통과해 '휴면 1일' 이 되고 **모든 정책이 휴면으로 판정**됐다
            # (2026-09-09 보안 렌즈 실측). 숫자 칸에 참/거짓이 온 것은 입력이
            # 잘못된 것이지 1일이 아니다.
            if isinstance(val, bool):
                continue
            try:
                num = int(val)
            except (TypeError, ValueError, OverflowError):
                # OverflowError 가 빠져 있었다 — JSON 은 `Infinity` 리터럴을
                # 허용하는데 `int(float('inf'))` 가 터져 500 이 났다(같은 실측).
                # 이 함수는 import·classify·preview 네 곳이 공유한다.
                continue
            if lo <= num <= hi:
                out[key] = num
        return out

    # 화면에서 입력받는 객체 분류 — 엔진 키와 사용자에게 보이는 이름을 한 곳에
    # 적어 둔다. 두 곳에 적으면 한쪽만 늘어난다.
    # mgmt 는 infra 로 합쳤다(둘 다 등급 6, 사유만 달랐다).
    #
    # **프로파일 경로만 고쳐서는 부족하다.** 장비별 객체 규칙은 SQLite 에
    # 따로 저장되는데(device_store), 그 경로는 to_customer_rules 의 병합을
    # 타지 않는다. 정규화하지 않으면 **예전 버전에서 '관리망' 칸에 값을 넣어
    # 둔 고객은 업그레이드 후 그 예외가 조용히 사라진다** — 예외가 빠지면
    # 등급이 올라가므로 판정변화다(게이트 correctness·spec 렌즈 검출).
    def _normalize_object_rules(rules) -> dict:
        out = dict(rules or {})
        legacy = out.pop("mgmt", None)
        if legacy:
            merged = list(out.get("infra") or [])
            for v in legacy:
                if v not in merged:
                    merged.append(v)
            out["infra"] = merged
        return out

    OBJECT_RULE_KINDS = {
        "admin":        "admin_objects",
        "high_risk":    "high_risk_objects",
        "user_segment": "user_segment_objects",
        "infra":        "infra_objects",
    }

    def _engine_ctx(with_device_rules: bool = True) -> dict:
        """판정 기준. `with_device_rules=False` 면 **세션 장비의 입력을 뺀다.**

        객체 명명 규칙은 컨설턴트의 공통 기준이 아니라 **그 장비의 사실**이다.
        배치·범위 리포트·샘플은 지금 열린 장비 것이 아닌 대상을 판정하므로,
        세션 값을 그대로 쓰면 고객 A 의 이름 규칙으로 고객 B 를 판정하게 된다 —
        실측: 같은 config 해시가 0 critical → 1 critical 로 갈렸고 산출물
        어디에도 무엇이 달랐는지 없었다(라운드 44). 임계값·규칙 토글은 공통
        기준이 맞으므로 그대로 둔다.
        """
        ctx = engine_context(app.config['profile'])
        override = app.config.get('thresholds_override') or {}
        if override:
            ctx["thresholds"] = {**ctx["thresholds"], **override}
        # **장비별 입력이 프로파일을 이긴다 — 항목 단위로.**
        # 객체 명명 관례는 고객마다 다르다. 그동안 이 목록이 납품 프로파일
        # 파일에만 있어서, 새 고객은 자기 환경을 APO 에 말할 방법이 없었다.
        #
        # 병합은 **항목을 덮어쓰는** 방식이다(합집합이 아니다). 합치면
        # 사용자가 '이 값은 우리 환경에 없다'고 지울 방법이 사라진다 —
        # 라운드 39에서 번들 기본값이 고객 프로파일을 덮어 판정이 달라진 적이
        # 있다. 비어 있는 항목은 프로파일 값을 그대로 쓴다.
        rules = (app.config.get('object_rules') or {}) if with_device_rules else {}
        if rules:
            cr = dict(ctx["customer_rules"])
            for kind, engine_key in OBJECT_RULE_KINDS.items():
                vals = rules.get(kind)
                if vals:                       # 빈 목록은 '미입력'으로 본다
                    cr[engine_key] = list(vals)
            ctx["customer_rules"] = cr
        return ctx

    @app.get("/api/profile")
    def get_profile():
        profile = app.config['profile']
        merged = _engine_ctx()
        return jsonify({
            "name": (profile.get("meta") or {}).get("name", "default"),
            "description": (profile.get("meta") or {}).get("description", ""),
            "thresholds": merged["thresholds"],
            # **'프로파일 기본값으로 되돌리기'는 되돌릴 값을 알아야 한다.**
            # thresholds 는 프로파일 ∪ 사용자값이라, 한 번이라도 판정을 돌리면
            # override 가 8개 키를 전부 채워 리셋이 방금 쓰던 값을 그대로
            # 되돌려 놓는 no-op 가 됐다(임계값 UX 조사에서 발견). 사용자 손이
            # 닿지 않은 원본을 따로 준다 — 화면이 이쪽으로 되돌린다.
            "profile_thresholds": engine_context(profile)["thresholds"],
            "presets": _threshold_presets(),
            "rules": merged["rules"],
            "inactive_rules": describe_inactive_rules(profile),
        })

    @app.post("/api/severity/preview-thresholds")
    def severity_preview_thresholds():
        """**이 값으로 바꾸면 무엇이 어떻게 달라지는가.**

        임계값은 공개 표준이 없어서 설정으로 존재하는데, 화면은 값만 받고
        결과를 안 보여줬다 — 고객이 "어떻게 넣어야 하는지 모르겠다"고 한
        이유가 이것이다(2026-08-25 Jayden). config 가 이미 메모리에 있고
        판정은 순수 함수라 서버 왕복이 싸다. **등급별 건수 델타만** 돌려준다:
        정책 행을 보내지 않으므로 응답이 가볍고, 이 경로로 남의 장비 정책이
        새어 나갈 여지도 없다.

        판정을 저장하지 않는다 — thresholds_override 를 건드리면 미리보기가
        본판정을 바꿔 버린다(값을 만지작거리는 것만으로 export 가 달라진다).
        """
        parsed = app.config.get('last_parsed')
        if not parsed:
            return jsonify({"error": "No config loaded. Upload a config file first."}), 400
        payload = request.get_json(silent=True) or {}
        cand = _sanitize_thresholds(payload.get("thresholds") or {})

        from app.services.policy_renderer import build_view_model
        runtime_stats = app.config.get('last_runtime_stats', {})
        view = build_view_model(parsed, runtime_stats)
        pols = ((view.get("firewall_policy") or [])
                + (view.get("firewall_proxy_policy") or []))

        base_ctx = {
            "service_groups": parsed.get("service_groups", {}),
            "user_ranges": app.config.get('user_ranges', []),
            "today": _date.today(),
            "onetime_schedules": _se_onetime(parsed),
            **_engine_ctx(),
        }
        # 후보 컨텍스트 — 현재 기준 위에 화면 입력값만 얹는다.
        cand_ctx = {**base_ctx,
                    "thresholds": {**base_ctx["thresholds"], **cand}}

        moved, before, after = 0, {}, {}
        for p in pols:
            b = evaluate_severity(p, base_ctx).get("urgency")
            a = evaluate_severity(p, cand_ctx).get("urgency")
            before[str(b)] = before.get(str(b), 0) + 1
            after[str(a)] = after.get(str(a), 0) + 1
            if a != b:
                moved += 1
        return jsonify({"total": len(pols), "moved": moved,
                        "before": before, "after": after})

    @app.get("/api/severity/dormancy-histogram")
    def severity_dormancy_histogram():
        """마지막 사용 경과일 분포. **'기록 없음' 이 몇 건인지가 핵심이다** —
        그 막대가 크면 휴면 기간을 365 로 두든 180 으로 두든 판정이 달라지지
        않는다. 지금은 그 사실을 화면 어디에서도 알 수 없다.
        """
        parsed = app.config.get('last_parsed')
        if not parsed:
            return jsonify({"error": "No config loaded. Upload a config file first."}), 400
        from app.services.policy_renderer import build_view_model
        view = build_view_model(parsed, app.config.get('last_runtime_stats', {}))
        pols = ((view.get("firewall_policy") or [])
                + (view.get("firewall_proxy_policy") or []))
        from app.services.severity_engine import _parse_date as _pd
        today = _date.today()
        # 경계는 화면 눈금과 같아야 한다 — 다르면 막대와 입력칸이 다른 말을 한다.
        edges = [90, 180, 365, 730]
        buckets = [0] * (len(edges) + 1)
        unknown = 0
        for p in pols:
            _lu = _pd(p.get("last_used"))
            d = (today - _lu).days if _lu else None
            if d is None:
                unknown += 1
                continue
            for i, e in enumerate(edges):
                if d < e:
                    buckets[i] += 1
                    break
            else:
                buckets[-1] += 1
        return jsonify({"total": len(pols), "edges": edges,
                        "buckets": buckets, "unknown": unknown})

    for d in (IMPORT_DIR, EXPORT_DIR, DATA_DIR):
        d.mkdir(parents=True, exist_ok=True)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/version")
    def version():
        # 절대경로 등 내부 파일시스템 정보는 노출하지 않는다.
        return jsonify({
            "version": APO_VERSION,
            "frozen": bool(getattr(_sys, 'frozen', False)),
        })

    def _store_broken(exc: Exception):
        """보관소를 **쓸 수 없는 것**과 **읽을 수 없는 것**은 다른 사고다.

        읽기전용 폴더에는 "본인 소유 폴더로 옮기세요" 가 맞는 조언이지만,
        파일이 손상된 경우(`database disk image is malformed`)에는 **틀린
        조언**이다 — 옮겨도 안 고쳐진다. 그리고 손상은 `get_device` 같은
        **읽기**에서 터지는데 `_store_unwritable` 은 쓰기만 감쌌다. 그래서
        `/api/config/parse`·`device_open`·`device_delete` 가 맨 500 을 냈다
        (9라운드 F4 실측). 사유로 갈라 준다.
        """
        msg = str(exc).lower()
        if "malformed" in msg or "not a database" in msg or "corrupt" in msg:
            print(f"[APO] device store corrupt: {exc!r}", flush=True)
            try:
                name = _store().store_path().name
            except Exception:
                name = "the device store file"
            return jsonify({
                "error": "APO could not read its device store "
                         f"({name}) — the file is damaged. Close any other "
                         "copy of APO that may be running and restart. If it "
                         "still fails, move that file aside and register your "
                         "devices again; your configuration files are not "
                         "affected.",
                "error_key": "store_corrupt", "file": name}), 503
        return _store_unwritable(exc)

    def _store_unwritable(exc: Exception):
        r"""보관소에 쓸 수 없을 때 **어디에 두면 되는지** 말한다.

        `C:\Program Files` 나 공유 폴더에 exe 를 두면 sqlite 를 만들 수 없는데
        그 예외를 잡는 곳이 없어 업로드마다 맨 500 이 났다(라운드 39 지적).
        사용자는 무엇이 잘못됐는지도, 무엇을 하면 되는지도 못 듣는다.
        """
        print(f"[APO] device store not writable: {exc!r}", flush=True)
        try:
            where = str(_store().store_path().parent)
        except Exception:
            where = "the folder next to APO.exe"
        return jsonify({
            "error": "APO could not write to its device store in "
                     f"'{where}'. Windows blocks writes in Program Files and on "
                     "some network shares. Move APO.exe to a folder you own "
                     "(for example Documents\\APO) and start it again — your "
                     "licence and devices live next to the program.",
            "error_key": "store_not_writable", "path": where}), 507

    @app.post("/api/config/parse")
    def parse_config():
        uploaded = request.files.get("config_file")
        if not uploaded:
            return jsonify({"error": "config_file is required"}), 400

        from werkzeug.utils import secure_filename
        filename = secure_filename(uploaded.filename or "") or "fortigate.conf"

        # **디스크를 거쳐 되읽지 않는다.** 예전에는 파일명만으로 정해지는 공유
        # 경로에 저장한 뒤 그 경로를 다시 읽었다. FortiGate 백업은 이름이
        # 겹치기 쉬운데(fortigate.conf), 두 요청이 같은 이름으로 동시에 들어오면
        # **한쪽이 다른 쪽의 바이트를 읽었다** — 라운드 41 실측: 8회 중 1회
        # A 고객 요청에 B 고객 설정(hostname CUST-B-FGT)이 실려 돌아왔고,
        # 4회는 절단된 0바이트를 읽었다. Flask 는 기본이 스레드 처리이고 exe 도
        # 같은 run.py 를 쓴다 — 창 두 개면 성립한다.
        # 요청이 가져온 바이트를 그대로 쓴다. 저장은 그 뒤의 일이다.
        raw_bytes = uploaded.read()
        # 파싱은 utf-8-sig로 — BOM이 붙어 있으면 첫 줄이 깨져 config_version을
        # 통째로 놓친다(라운드 7 실측).
        raw = raw_bytes.decode("utf-8-sig", errors="ignore")
        # **버려진 바이트가 있으면 세어 둔다.** `errors="ignore"` 는 UTF-8 이
        # 아닌 바이트를 조용히 삭제한다 — cp949 로 저장된 한글 주석이 통째로
        # 사라진다(실측: `set comment "장애 대응"` → `set comment " "`).
        # 읽기 전용 감사에는 무해하지만 **설정 마이그레이션은 이 텍스트로
        # 장비에 넣을 파일을 만든다.** 손도 안 댄 줄의 내용이 없어진 파일이
        # 운영에 복원된다. 되살릴 수는 없으니(그 바이트를 JSON 으로 실어
        # 나를 수도 없다) 그 사실을 알리고 확인을 받는다.

        # **빈 파일을 '설정'으로 받아들이면 모든 고객이 한 장비 행을 공유한다.**
        # device_id 는 설정 텍스트의 sha256 앞 16자인데, 빈 문자열의 해시는
        # 상수다(e3b0c44298fc1c14). 중단된 백업·클라우드 동기화 플레이스홀더로
        # 0바이트 .conf 는 실제로 생기고, 그런 파일 둘을 서로 다른 고객 이름으로
        # 올리면 같은 행에 UPSERT 돼 **A 고객의 IP 대역과 확인된 시리얼이 B 고객
        # 화면에 붙었다**(라운드 41 실측). 시리얼 고정은 조치 PUT 의 유일한
        # 방벽이다. 게다가 화면은 빈 파일에 대고 '파싱 성공'이라고 말했다.
        _bad = config_intake_problem(raw)
        if _bad:
            return jsonify({"error": _bad[0], "error_key": _bad[1]}), 400

        save_path = IMPORT_DIR / filename
        try:
            save_path.write_bytes(raw_bytes)
        except OSError as exc:
            # 보관은 편의 기능이다. 읽기 전용 위치에 설치했다고 판정까지
            # 막지는 않는다(라운드 39 지적: C:\Program Files 설치 시 500).
            print(f"[APO] could not keep a copy of the upload: {exc}", flush=True)
        # **파서 예외가 500 으로 새어 나가면 안 된다.** 파서는 깨진 줄·잘린
        # 백업에는 견디지만(경고로 남긴다), 처음 보는 문법에서 예상 못 한
        # 예외가 나면 여기서 그대로 터져 화면은 원인을 알 수 없는 500 만 본다.
        # 타사 config 로 넓힐수록 '처음 보는 문법'을 만날 확률이 올라간다.
        try:
            parser = FortiGateConfigParser(raw)
            parsed = parser.parse()
        except Exception as exc:
            print(f"[APO] could not parse the uploaded configuration: {exc!r}",
                  flush=True)
            return jsonify({
                "error": "APO could not read this configuration file. It may be "
                         "a format APO does not handle yet. Please send this file "
                         "to support if it is a valid FortiGate backup.",
                "error_key": "config_parse_failed"}), 400
        view = build_view_model(parsed, runtime_stats={})

        # **산출물 이름은 업로드 파일명만으로 정하면 안 된다.** 두 고객이 둘 다
        # `config.conf` 로 올리면 같은 경로를 공유해, 오래된 탭에 남아 있던
        # 'Download parsed JSON' 링크가 **다른 고객의 설정 전체**를 내려준다
        # (라운드 27 실측: 화면은 ACME 인데 받은 파일의 hostname 은 BETA).
        # 설정 바이트 해시를 붙여 장비마다 다른 경로가 되게 한다.
        export_name = f"{Path(filename).stem}_{_hashlib_sha256_bytes(raw_bytes)[:8]}.parsed.json"
        export_path = EXPORT_DIR / export_name
        export_path.write_text(json.dumps({"parsed": parsed, "view": view}, indent=2), encoding="utf-8")
        app.config['last_parsed'] = parsed
        app.config['last_raw_config'] = raw      # Version Advisor 기능 감지용
        # **검증을 통과한 뒤에 쓴다.** 위쪽(디코딩 직후)에서 쓰면 400 으로
        # 거부된 업로드가 열린 장비는 그대로 둔 채 이 값만 덮어쓴다. 0바이트
        # .conf 하나로(코드가 스스로 "실제로 생긴다"고 적어 둔 그 파일)
        # cp949 장비의 차단이 풀리고, 반대로 남의 cp949 메모를 잘못 올렸다
        # 거부되면 정상 장비에 유령 차단이 뜬다. 실측으로 양방향 재현됐다.
        _bom = 3 if raw_bytes[:3] == b"\xef\xbb\xbf" else 0
        app.config['last_config_decode_lost'] = max(
            0, (len(raw_bytes) - _bom) - len(raw.encode("utf-8")))
        # 감사 해시는 **원본 바이트**로 낸다. 디코딩된 문자열을 해시하면 개행
        # 변환(CRLF→LF)·BOM 제거 때문에 같은 파일이 경로마다 다른 값을 갖고
        # 디스크의 파일과도 어긋난다 — "이 보고서는 그 설정 파일에 대한 것"이라는
        # 대응이 깨진다(라운드 8 실측: 한 파일에서 해시 3개). 문서정보 나머지와
        # **같은 자리에서** 갱신해야 중간 예외 시 새 파일 해시가 옛 파일 이름과
        # 짝지어지는 일이 없다(라운드 8 명세 지적).
        app.config['last_config_sha256'] = _hashlib_sha256_bytes(raw_bytes)
        app.config['last_config_filename'] = filename   # 리포트 문서정보용
        app.config['last_runtime_stats'] = {}   # 새 Config 로드 시 CSV stats 초기화
        app.config.pop('collect_coverage', None)  # 수집 커버리지도 그 수집의 사실이다
        # **장비 프로파일 id** — 설정 파일 등록이 곧 장비 등록이다. CSV는 이
        # id를 가진 요청만 받는다. 그래야 1번 장비 config에 2번 장비 CSV가
        # 얹히는 일이 구조적으로 불가능해진다(Jayden 설계, 2026-08-13).
        did = _config_sha(raw)
        app.config['device_id'] = did
        from app.services import device_store as _store
        try:
            _store.upsert_device(
                did, name=(parsed.get("meta") or {}).get("hostname") or filename,
                # **손실 사실이 설정 텍스트와 함께 따라다녀야 한다.** 보관된
                # 장비를 다시 열면(앱을 켤 때 화면이 권하는 경로) 이 값이
                # 사라져, 한글 주석이 지워진 파일이 경고 없이 나갔다.
                decode_lost=app.config.get('last_config_decode_lost', 0),
                config_filename=filename, config_text=raw,
                config_sha256=app.config['last_config_sha256'])
        except OSError as exc:
            return _store_broken(exc)
        except Exception as exc:                     # sqlite3.OperationalError 등
            # **문자열 목록으로 거르면 다음 문구에서 또 진다.** `"readonly"`·
            # `"unable to open"` 만 잡아서 `"database disk image is malformed"`
            # 가 그물을 빠져나가 첫 화면의 첫 동작이 맨 500 이 됐다
            # (9라운드 F4 실측). 보관소 계층에서 난 예외는 전부 사유를 가려
            # 답한다 — `_store_broken` 이 손상/쓰기불가를 나눠 말한다.
            return _store_broken(exc)
        # 같은 장비를 다시 열었다면 그 장비에 붙여 둔 입력을 되살린다 —
        # 매번 CSV·대역을 다시 넣게 하면 보관소가 있는 의미가 없다.
        saved = _store.get_device(did) or {}
        if saved.get("runtime_stats"):
            app.config['last_runtime_stats'] = saved["runtime_stats"]
        app.config['user_ranges'] = saved.get("user_ranges") or []
        # **객체 명명 규칙도 그 장비의 것이다.** 앞 고객의 규칙이 남으면
        # 그 이름으로 이 고객 정책의 등급이 정해진다 — 라운드 19~21 에서
        # 사용량 출처와 대역이 정확히 그렇게 새어 나왔다. 없으면 비운다.
        # 새 config는 다른 장비일 수 있다. 이전 장비의 DNS 캐시가 남으면
        # 그 스냅샷으로 새 장비를 판정하는 혼선이 생긴다(재비판). 함께 비운다.
        # 직전 수집에 쓴 장비 연결도 이 config의 출처가 아니므로 함께 버린다 —
        # 남기면 파일로 올린 A장비 config를 B장비 FQDN으로 판정하게 된다.
        # 조치 대상 장비·감사 타임라인도 앞 장비의 것이다.
        _drop_previous_device_traces()
        # **비운 뒤에 이 장비의 것을 되살린다.** 순서가 반대면 방금 복원한
        # 값을 곧바로 지운다. 같은 이유로 아래 device_open 도 비운 뒤에 놓는다.
        app.config['object_rules'] = _normalize_object_rules(saved.get("object_rules"))
        # 비운 **다음에** 이 장비 자신의 것만 되살린다. 순서가 반대였던
        # 동안에는 복원 분기가 세 줄 뒤 pop 때문에 즉시 무효가 되어, 같은
        # 장비인데도 '파일 재업로드'와 'Open'의 FQDN 커버리지가 갈렸다.
        # 이 설정의 산출물이 무엇인지도 여기서 기록한다 — /exports 가 그것만
        # 내준다. 위에서 적었더니 바로 이 pop 에 지워져 링크가 즉시 죽었다.
        app.config['last_export_name'] = export_name
        if saved.get("fqdn_cache"):
            app.config['fqdn_cache'] = saved["fqdn_cache"]
        # 통계의 커버리지 서술도 함께 — 통계만 복원하면 'Open' 과 '같은 파일
        # 재업로드'의 워크북 문서정보가 갈린다(라운드 71). 복원은 반드시
        # _drop_previous_device_traces() **뒤**여야 한다 — collect_coverage
        # 는 _DEVICE_SCOPED_KEYS 라 앞에 두면 곧바로 지워진다(fqdn_cache 와
        # 같은 순서 규칙).
        if saved.get("runtime_stats") and saved.get("collect_coverage"):
            app.config['collect_coverage'] = saved["collect_coverage"]
        # 사용량의 출처도 마찬가지 — 값만 남고 출처가 사라지면 "이 판정의
        # 근거가 어느 파일이었나"에 아무도 답할 수 없다.
        app.config['csv_meta'] = saved.get("csv_meta") or []

        return jsonify(
            {
                "message": "Config parsed successfully",
                "filename": filename,
                # 이 설정을 가리키는 안정된 식별자. hostname은 공장 기본값
                # "FortiGate"로 남아 있는 장비가 흔해 장비 구분에 못 쓴다.
                "config_sha": _config_sha(raw),
                "device_id": app.config['device_id'],
                "device_name": (parsed.get("meta") or {}).get("hostname") or filename,
                "csv_meta": app.config.get('csv_meta') or [],
                # 이 장비의 대역도 함께 준다. 안 주면 화면 칩이 앞 장비 값을
                # 그대로 들고 있어, 마법사 대역 칸이 남의 고객 내부망으로
                # 채워지고 그대로 저장된다(라운드 21 실측).
                "user_ranges": app.config.get('user_ranges') or [],
                "session": _device_session(),
                "parsed": parsed,
                "view": view,
                "export_json": export_name,
            }
        )

    @app.post("/api/runtime/import")
    def import_runtime():
        # 이 경로도 열려 있는 장비의 행에 쓴다 — CSV 경로와 같은 게이트를 둔다.
        # 창을 두 개 띄워 서로 다른 장비를 열어 두면, 여기서 붙여넣은 사용량이
        # 의도하지 않은 장비의 판정 근거가 된다.
        parser = RuntimeStatsParser()
        merged: dict[str, dict[str, Any]] = {}

        uploaded_files = request.files.getlist("runtime_files")
        pasted_text = request.form.get("runtime_text", "")

        for file in uploaded_files:
            # Excel의 'CSV UTF-8' 저장은 BOM을 붙인다 — 첫 헤더가 깨지면 컬럼
            # 인식이 어긋난다(배치 경로와 통일, 리뷰 라운드 7).
            text = file.read().decode("utf-8-sig", errors="ignore")
            stats = parser.parse_text(text)
            merged.update(stats)

        if pasted_text.strip():
            stats = parser.parse_text(pasted_text)
            merged.update(stats)

        # **다중 VDOM 이면 이 출력이 어느 VDOM 것인지 말해야 한다.** CLI 의
        # diagnose 출력도 지금 서 있는 VDOM 의 정책만 나온다 — CSV 경로는
        # 라운드 49 에서 "추측하지 않고 물어본다"로 고쳤는데 이 형제 경로만
        # 남아, root 에서 뽑은 출력이 CORP·DMZ 의 같은 번호에 얹히거나
        # (_vdom 태그 없이 병합돼) 이미 붙은 CSV 의 VDOM 것으로 오귀속됐다
        # (라운드 54 완성도 렌즈).
        _parsed_now = app.config.get('last_parsed') or {}
        _cfg_vdoms = [v for v in ((_parsed_now.get("meta") or {}).get("vdoms")
                                  or []) if v]
        _sel_vdom = str(request.form.get("vdom", "")).strip()
        if merged and len(_cfg_vdoms) > 1:
            if not _sel_vdom:
                return jsonify({
                    "error": "This configuration has more than one VDOM "
                             f"({', '.join(_cfg_vdoms)}), and policy numbers start "
                             "again at 1 in each one. Tell APO which VDOM this "
                             "output came from — otherwise its hit counts would be "
                             "applied to same-numbered policies in the other VDOMs, "
                             "which were never measured.",
                    "error_key": "usage_csv_vdom_required",
                    "vdoms": _cfg_vdoms, "rows": len(merged)}), 409
            _match = next((v for v in _cfg_vdoms
                           if v.strip().lower() == _sel_vdom.lower()), None)
            if not _match:
                return jsonify({
                    "error": f"'{_sel_vdom}' is not a VDOM in this configuration. "
                             f"It has: {', '.join(_cfg_vdoms)}.",
                    "error_key": "usage_csv_vdom_unknown",
                    "vdom": _sel_vdom, "vdoms": _cfg_vdoms}), 409
            _sel_vdom = _match

        # 이 경로(CLI 출력 붙여넣기)는 정책 종류를 알 수 없다. 이미 종류별로
        # 나뉜 상태에 평평하게 합치면 _stats_for가 네임스페이스만 읽어 방금 넣은
        # 통계를 통째로 버린다 — 조용히 '사용량 없음'이 되어 미사용 판정으로
        # 이어지므로 가장 위험한 실패다. 종류를 모르면 양쪽에 넣는다.
        # **이 설정의 정책이 아닌 행은 받지도 저장하지도 않는다.**
        # CSV 경로만 고치고 형제인 붙여넣기를 남겼다. 여기에는 `known` 계산도,
        # 라운드 16·17 이 세운 "매칭 0건이면 거부" 게이트도 **아예 없었다** —
        # 이 config 에 없는 번호 60,000행을 붙여넣으면 경고 한 줄 없이 200 이
        # 나가고 보관소가 289B → 7.7MB(26,000배), 모든 화면이 부르는
        # `/api/devices` 가 0.02초 → 0.47초가 됐다. 그리고 남의 장비 CLI
        # 출력을 붙여넣으면 번호가 겹치는 만큼 **경고 없이 판정 근거가 된다**
        # (9라운드 F7).
        _paste_parsed = app.config.get('last_parsed') or {}
        _paste_known = {str(pp.get("policy_id"))
                        for sec in ("firewall_policy", "firewall_proxy_policy")
                        for pp in (_paste_parsed.get(sec) or [])
                        if pp.get("policy_id") is not None}
        _paste_seen = len(merged)
        if _paste_known:
            merged = {k: v for k, v in merged.items() if k in _paste_known}
            if _paste_seen and not merged:
                return jsonify({
                    "error": "None of the pasted rows match a policy number in "
                             "the configuration that is open. Check that this "
                             "output came from the same device.",
                    "error_key": "usage_no_match"}), 409
        # **사본을 고친다** — 아래 `.update` 들이 살아 있는 판정 근거를
        # 제자리에서 바꾸면 보관소 쓰기가 실패해도 메모리는 이미 오염된다.
        existing = _stats_snapshot(app.config.get('last_runtime_stats'))
        # 다른 VDOM 의 통계가 이미 있으면 갈아 끼운다 — 번호가 겹치므로
        # 합치는 순간 어느 쪽 값인지 알 수 없다(CSV 경로와 같은 규칙).
        if merged and len(_cfg_vdoms) > 1:
            _had = str(existing.get("_vdom") or "")
            # 대소문자 무시 — 태그에는 등록/원형이 섞여 들어올 수 있는데
            # (수집은 장비 등록 필드 원형, 이 경로는 config 원형으로
            # canonicalize), 이 비교만 대소문자를 구분해 같은 VDOM 의
            # 직접수집 통계를 wipe 했다(라운드 56 경계값 렌즈. 조인부
            # policy_renderer 는 양쪽을 lower 로 비교한다 — 규칙 통일).
            if _had and _had.lower() != _sel_vdom.lower():
                existing = {}
            elif not _had and _has_stat_rows(existing):
                # 무태그 기존 행(pre-v49 레거시)은 어느 VDOM 것인지 모른다.
                # 그대로 두면 아래에서 방금 고른 VDOM 태그를 **상속**받아,
                # 측정한 적 없는 정책이 "unused (Hit=0)" 로 살아난다 —
                # 라운드 49 가 막은 번짐의 레거시판(라운드 56 완성도 렌즈).
                # 귀속 불가 행은 버린다: 판정은 '사용량 미상'이 되고 그건 참이다.
                existing = {}
        if "firewall" in existing or "proxy" in existing:
            for k in ("firewall", "proxy"):
                existing.setdefault(k, {}).update(merged)
        else:
            existing.update(merged)
        if merged and len(_cfg_vdoms) > 1:
            existing["_vdom"] = _sel_vdom
        # 보관소에 먼저 쓰고 성공한 뒤 메모리를 바꾼다(CSV 경로와 같은 규칙).
        _pending = existing
        # 이 경로도 **열려 있는 장비에 붙는다**. 보관하지 않으면 화면에는
        # 사용량이 보이는데 같은 장비의 리포트는 'no usage CSV'로 나가, 같은
        # 장비의 화면과 산출물이 갈린다(라운드 14 실측).
        _did = app.config.get('device_id')
        # 붙여넣기도 '수집분에 다른 출처를 섞는' 행위다 — CSV 경로와 같은
        # 규칙으로 수집 커버리지 서술을 내린다(라운드 71: CSV 만 고치고
        # 형제 경로를 남기면 워크북이 낡은 절단을 계속 말한다).
        app.config.pop('collect_coverage', None)
        if _did:
            from app.services import device_store as _store
            try:
                _store.update_device_inputs(_did, runtime_stats=_pending,
                                            collect_coverage={})
            except Exception as exc:
                return _store_broken(exc)
        app.config['last_runtime_stats'] = _pending

        return jsonify({"runtime_stats": merged,
                        "count": _paste_seen,
                        "unmatched": _paste_seen - len(merged)})

    @app.post("/api/policy-stats/import")
    def import_policy_stats_csv():
        # CSV는 **등록된 장비에만** 붙는다. 설정 파일을 올려 장비를 등록하기
        # 전에는 받지 않고, 클라이언트가 보낸 device_id가 지금 열려 있는 장비와
        # 다르면 거부한다 — 1번 장비 config에 2번 장비 CSV가 얹히면 살아 있는
        # 정책이 '미사용'으로 뒤집혀 비활성화 후보까지 오른다(Jayden 설계).
        current_id = app.config.get('device_id')
        if not current_id:
            return jsonify({"error": "Register a device first — upload its "
                            "configuration file, then add that device's CSV."}), 409
        # 장비 확인은 before_request 가 이미 했다(기본 차단).
        parser = PolicyStatsCsvParser()
        merged: dict[str, dict[str, Any]] = {}
        uploaded_files = request.files.getlist("policy_stats_files")
        pasted_text = request.form.get("policy_stats_text", "")

        # **어떤 파일이 이 판정의 근거인지 남긴다.** 설정 파일에는 파일명과
        # SHA-256을 남기면서 사용량 CSV에는 아무것도 남기지 않았더니, 새로고침
        # 한 번에 출처가 사라지고 산출물에도 'Usage CSV loaded: yes' 한 줄만
        # 실렸다. 남의 장비 CSV를 얹은 사고를 화면에서도 보고서에서도 확인할
        # 방법이 없었다(라운드 19 실측).
        sources: list[dict] = []
        for file in uploaded_files:
            raw = file.read()
            # Excel의 'CSV UTF-8' 저장은 BOM을 붙인다 — 첫 헤더가 깨지면 컬럼
            # 인식이 어긋난다(배치 경로와 통일, 리뷰 라운드 7).
            text = raw.decode("utf-8-sig", errors="ignore")
            stats = parser.parse_text(text)
            merged.update(stats)
            sources.append({"filename": (file.filename or "upload.csv")[:120],
                            "sha256": _hashlib_sha256_bytes(raw),
                            "rows": len(stats), "_ids": set(stats)})

        if pasted_text.strip():
            stats = parser.parse_text(pasted_text)
            merged.update(stats)
            sources.append({"filename": "(pasted text)",
                            "sha256": _hashlib_sha256_bytes(
                                pasted_text.encode("utf-8", "ignore")),
                            "rows": len(stats), "_ids": set(stats)})

        # **정책이 한 줄도 안 읽히는 파일은 사용량 파일이 아니다.** 아무 파일이나
        # 받아 두었더니 config 파일을 CSV 칸에 잘못 올려도 경고가 없었고, 그
        # 파일명과 해시가 고객에게 나가는 워크북의 '사용량 근거'란에 0행짜리
        # 출처로 인쇄됐다(라운드 22 실측). 근거란에 근거 아닌 것이 실리면
        # 그 문서 전체의 신뢰가 깨진다.
        bad = [s["filename"] for s in sources if not s["rows"]]
        if bad and not merged:
            return jsonify({
                "error": "No hit count / last used rows were recognised in "
                         f"{', '.join(bad)}. Export the policy list from the "
                         "device (Policy & Objects → right-click the column "
                         "header → Export to CSV) and pick that file.",
                "error_key": "csv_no_usage_rows", "files": ", ".join(bad),
                "rows": 0, "matched": 0}), 409

        # 정책 종류별로 담는다. 평평하게 합치면 FW CSV와 Proxy CSV의 같은 번호가
        # 서로를 덮어써, 어느 파일을 먼저 올렸느냐에 따라 판정이 달라졌다.
        # 종류를 안 알려주면(구형 클라이언트·직접 호출) 예전처럼 평평하게 둔다.
        ptype = str(request.form.get("policy_type", "")).strip().lower()
        ns = {"fw": "firewall", "firewall": "firewall",
              "proxy": "proxy", "proxy-policy": "proxy"}.get(ptype)

        _parsed = app.config.get('last_parsed') or {}
        # **다중 VDOM 이면 이 CSV 가 어느 VDOM 것인지 말해야 한다.**
        # FortiGate 는 VDOM 마다 정책 번호를 1번부터 다시 매기고, GUI 의
        # `Export to CSV` 는 지금 서 있는 VDOM 만 내보낸다. 번호로만 붙이면
        # root 에서 뽑은 CSV 가 CORP·DMZ 의 같은 번호 정책에 그대로 얹히는데,
        # 매칭률이 60/60 이라 '다른 장비 CSV' 경고도 뜨지 않는다 — 워크북이
        # **한 번도 측정한 적 없는 정책 42건에 "unused (Hit=0)"** 라고 적었다
        # (라운드 49 실측). 추측하지 않고 물어본다.
        # 이 질문을 매칭 검사보다 **먼저** 한다 — 어느 VDOM 것인지 모르면
        # 무엇과 매칭해야 하는지도 모르기 때문이다(라운드 58 계약 렌즈).
        _cfg_vdoms = [v for v in ((_parsed.get("meta") or {}).get("vdoms") or []) if v]
        _sel_vdom = str(request.form.get("vdom", "")).strip()
        if len(_cfg_vdoms) > 1:
            if not _sel_vdom:
                return jsonify({
                    "error": "This configuration has more than one VDOM "
                             f"({', '.join(_cfg_vdoms)}), and policy numbers start "
                             "again at 1 in each one. Tell APO which VDOM this "
                             "export came from — otherwise its hit counts would be "
                             "applied to same-numbered policies in the other VDOMs, "
                             "which were never measured.",
                    "error_key": "usage_csv_vdom_required",
                    "vdoms": _cfg_vdoms, "rows": len(merged)}), 409
            _match = next((v for v in _cfg_vdoms
                           if v.strip().lower() == _sel_vdom.lower()), None)
            if not _match:
                return jsonify({
                    "error": f"'{_sel_vdom}' is not a VDOM in this configuration. "
                             f"It has: {', '.join(_cfg_vdoms)}.",
                    "error_key": "usage_csv_vdom_unknown",
                    "vdom": _sel_vdom, "vdoms": _cfg_vdoms}), 409
            _sel_vdom = _match

        # **이 config의 정책과 하나도 안 맞는 CSV는 받지 않는다.** 통계는 언제나
        # 합쳐지고 되돌릴 수단이 없어서, 남의 장비 CSV가 한 번 들어가면 그 장비의
        # 미사용·심각도 판정이 오염된 채로 고객 리포트까지 나간다. 경고조차 없던
        # 동안 실제로 매칭 0건인 CSV가 조용히 얹혔다(라운드 16 실측).
        #
        # **매칭 모집단은 판정 모집단과 같아야 한다.** VDOM 을 지정했으면 그
        # VDOM 의 정책 번호하고만 대조한다 — 전 VDOM 합집합과 대조하면 다른
        # VDOM 에만 있는 번호가 "matched" 로 세어져 경고·WARNING·문서정보가
        # 전부 억제되는데 판정에는 한 줄도 안 쓰인다. 극단에선 "loaded: yes —
        # VDOM 'root' only" 인데 root 전 정책이 usage unknown — 라운드 18 이
        # 막은 자기모순의 부활 경로였다(라운드 58 계약 렌즈, Jayden 승인).
        _sections = (["firewall_policy"] if ns == "firewall"
                     else ["firewall_proxy_policy"] if ns == "proxy"
                     else ["firewall_policy", "firewall_proxy_policy"])
        known = {str(p.get("policy_id")) for s in _sections
                 for p in (_parsed.get(s) or [])
                 if p.get("policy_id") is not None
                 and (not _sel_vdom
                      or str(p.get("vdom") or "").strip().lower()
                      == _sel_vdom.lower())}
        matched = [k for k in merged if k in known]
        # `known`이 비었다고 게이트를 끄면 안 된다 — proxy 정책이 없는 장비에
        # proxy CSV를 고르는 실수가 정확히 그 상태를 만들고, 그때 남의 장비
        # 통계가 무검사로 들어갔다(라운드 17 실측: usage 2 → 4).
        if merged and not matched:
            # 사전 키 규약: 값이 끼는 문장은 error_key + 완전한 리터럴로.
            if _sel_vdom:
                return jsonify({
                    "error": f"None of the policy IDs in this file exist in "
                             f"VDOM '{_sel_vdom}' of the loaded configuration. "
                             "This usually means the CSV came from a different "
                             "device or a different VDOM — nothing was imported.",
                    "error_key": "usage_csv_no_match_in_vdom",
                    "vdom": _sel_vdom,
                    "rows": len(merged), "matched": 0}), 409
            return jsonify({
                "error": "None of the policy IDs in this file exist in the loaded "
                         "configuration. This usually means the CSV came from a "
                         "different device — nothing was imported.",
                "rows": len(merged), "matched": 0}), 409
        # **사본을 고친다**(붙여넣기 경로와 같은 규칙). 바로 아래 `_vdom`
        # 떼기부터가 제자리 변형이라, 보관소 쓰기 전에 메모리가 이미 바뀌었다.
        existing = _stats_snapshot(app.config.get('last_runtime_stats'))
        # **다른 VDOM 의 CSV 를 덧붙이면 둘 다 못 쓴다.** 번호가 겹치므로
        # 합치는 순간 어느 쪽 값인지 알 수 없다. 새 VDOM 을 고르면 그 VDOM
        # 것으로 갈아 끼우고, 그 사실을 응답에 적는다.
        _replaced_vdom = ""
        if len(_cfg_vdoms) > 1:
            _had = str(existing.get("_vdom") or "")
            # 대소문자 무시 — 붙여넣기 경로와 같은 규칙(라운드 56 경계값 렌즈).
            if _had and _had.lower() != _sel_vdom.lower():
                _replaced_vdom, existing = _had, {}
            elif not _had and _has_stat_rows(existing):
                # 무태그 레거시 행은 귀속 불가 — 새 태그를 상속시키면 라운드
                # 49 번짐이 부활한다(붙여넣기 경로와 같은 방어, 라운드 56).
                _replaced_vdom, existing = "(untagged)", {}
        # `_vdom` 꼬리표는 **최상위 메타**다. 승격 복사(dict(existing))에
        # 딸려 네임스페이스 안으로 들어가면 _stats_for._is_namespace 검사가
        # str 하나에 실패해 **전체 통계를 평평한 것으로 오인 — 방금 성공했다고
        # 답한 CSV 까지 전 정책이 '사용량 미상'**이 됐다(라운드 56 계약 렌즈
        # 실행 재현). 병합 전에 떼어 두고 아래에서 조건부로 다시 단다.
        existing.pop("_vdom", None)
        # **이 설정의 정책이 아닌 행은 저장하지 않는다.**
        # 서버가 이미 "이 설정에 없는 번호" 라고 판정한 행까지 전량 보관소에
        # 넣고 있었다. 100만 행짜리를 잘못 고르면(매칭 2행 / 불일치 999,998행)
        # 보관소가 49KB → 81MB 가 되고, 모든 화면이 부르는 `/api/devices` 가
        # 0.05초 → 11.2초가 된다 — 그리고 **왜 느려졌는지 어디에서도 알 수
        # 없다**(8라운드 발견 7 실측). 사용자는 이미 "999,998행이 이 설정에
        # 없다" 는 경고를 받는다; 그 행들을 들고 있을 이유가 없다.
        # `known` 이 비면(파싱 실패 등) 거르지 않는다 — 모를 때 버리면 안 된다.
        # **거르기 전에 총 행수를 기억한다.** 요약이 `len(merged)` 로
        # "몇 건이 안 맞았는지" 를 말하므로, 먼저 걸러 버리면 그 경고가
        # 0 이 된다 — 사용자가 잘못된 파일을 골랐다는 사실 자체가 사라진다
        # (테스트가 잡았다).
        _rows_seen = len(merged)
        if known:
            merged = {k: v for k, v in merged.items() if k in known}
        if ns:
            if not ("firewall" in existing or "proxy" in existing):
                # 평평한 옛 상태 → 종류별로 승격. 기존 값을 버리면 사용자가 앞서
                # 붙여넣은 통계가 조용히 사라진다. 평평했다는 건 "종류를 몰라
                # 양쪽에 적용"이라는 뜻이므로 그대로 양쪽에 복사한 뒤 덮어쓴다.
                existing = {"firewall": dict(existing), "proxy": dict(existing)}
            existing.setdefault(ns, {}).update(merged)
        else:
            if "firewall" in existing or "proxy" in existing:
                # 이미 종류별인데 종류 없는 입력이 오면 양쪽에 넣는 수밖에 없다
                for k in ("firewall", "proxy"):
                    existing.setdefault(k, {}).update(merged)
            else:
                existing.update(merged)
        if len(_cfg_vdoms) > 1:
            existing["_vdom"] = _sel_vdom
        # **보관소에 먼저 쓰고, 성공한 뒤 메모리를 바꾼다.**
        # 8라운드가 `set_user_ranges`·`clear_policy_stats` 만 고치고 **가장 많이
        # 쓰는 두 경로**(CSV 임포트·붙여넣기)를 남겼다. 실측: 읽기전용 보관소에서
        # 임포트가 500 인데 판정 지문이 `cf8989…` → `442d04…` 로 바뀌고 정책
        # 셋의 히트가 88422 → 0 이 됐다. 장비를 다시 열면 원복된다 — **같은
        # config 가 두 기준으로 판정된다**(9라운드 F1).
        # 사용량은 대역보다 더 자주 바뀌는 판정 축이다.
        _pending_stats = existing
        # 이 장비 행에만 쓴다 — 보관소에서도 장비 경계가 유지돼야 한다.
        from app.services import device_store as _store
        # **읽기도 감싼다.** 쓰기만 감쌌더니 손상된 보관소에서 이 줄이 터져
        # 맨 500 이 났다 — 읽기전용 파일은 읽기가 되므로 그 검증에서는
        # 안 보였다(9라운드 F4 와 같은 뿌리).
        try:
            _prev = (_store.get_device(current_id) or {}).get("csv_meta") or []
        except Exception as exc:
            return _store_broken(exc)
        for s in sources:
            # **이 파일의** 매칭 수를 적는다. 배치 합계를 찍었더니 매칭 0건인
            # 남의 장비 파일이 정상 파일과 함께 올라왔을 때 'matched: 12'로
            # 기록돼, 기록만 보면 멀쩡한 파일처럼 읽혔다(라운드 20 실측).
            ids = s.pop("_ids", set())
            s_matched = len(ids & known) if known else 0
            s.update({"kind": ns or "unspecified",
                      "imported_at": _dt.now().strftime("%Y-%m-%d %H:%M"),
                      "matched": s_matched,
                      "unmatched": len(ids) - s_matched,
                      # 어느 VDOM 의 내보내기였는지도 판정 재현의 입력이다
                      # ("같은 판정을 재현하려면 값이 있어야 한다" — 자기
                      # 원칙. 라운드 56 완성도 렌즈).
                      **({"vdom": _sel_vdom} if _sel_vdom else {})})
        # 최근 것이 앞에 오게 쌓는다. 같은 파일(이름+해시)을 다시 올린 것은
        # 새 항목이 아니라 최신 임포트로 갱신한다 — 안 그러면 같은 파일 반복
        # 임포트가 목록을 밀어내 **실제 판정 근거가 조용히 사라졌다**.
        # 앞선 잘림 표시는 목록이 아니라 **누적 유실 수**로만 들고 간다. 그걸
        # 목록에 남겨 뒀더니 (a) 슬롯 하나를 계속 차지하고 (b) 다음 잘림 계산이
        # 이번 배치의 델타만 보게 돼, 실제로 14건이 사라졌는데 '+2'라고 인쇄됐다.
        # 증적 목록이 자기 완전성에 대해 확정적으로 거짓말한 셈이다(라운드 21).
        dropped_before = 0
        # 0행짜리는 근거가 아니다 — 여러 개를 한 번에 올려 다른 파일이 성공한
        # 경우에도 그 파일은 출처 목록에 넣지 않는다(위 게이트는 전부 0행일
        # 때만 막는다).
        sources = [s for s in sources if s.get("rows")]
        merged_meta, seen_keys = [], set()
        for s in sources + [p for p in _prev if isinstance(p, dict)]:
            if s.get("kind") == "note":
                dropped_before = max(dropped_before, int(s.get("dropped") or 0))
                continue
            key = (s.get("filename"), s.get("sha256"))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            merged_meta.append(s)
        csv_meta = merged_meta[:12]
        dropped = dropped_before + max(0, len(merged_meta) - 11)
        if dropped:
            # 잘렸다는 사실을 숨기면 문서정보가 '완전한 출처 목록'처럼 읽힌다.
            csv_meta = merged_meta[:11] + [{
                "filename": f"(+{dropped} older import(s) not listed)",
                "sha256": "", "rows": None, "kind": "note", "dropped": dropped,
                "imported_at": "", "matched": None, "unmatched": None}]
        app.config['csv_meta'] = csv_meta
        # CSV 를 붙였으면 '장비 수집 커버리지' 서술은 더 이상 유효 사실이
        # 아니다(수집분+CSV 혼합) — 남기면 워크북이 낡은 절단을 말한다.
        app.config.pop('collect_coverage', None)
        try:
            _store.update_device_inputs(current_id, runtime_stats=_pending_stats,
                                        csv_meta=csv_meta, collect_coverage={})
        except Exception as exc:
            return _store_broken(exc)
        app.config['last_runtime_stats'] = _pending_stats
        summary = {
            # **거르기 전 행수를 쓴다.** 화면이 `count` 와 `unmatched` 를 한
            # 문장에 함께 쓴다("{count}행 중 {unmatched}행이 이 설정에 없는
            # 정책 번호입니다"). `count` 만 거른 뒤 값으로 두었더니 "1행 중
            # 60행" 이 됐다 — 잘못된 파일을 골랐다는 사실을 지키려다 **그
            # 사실을 말하는 바로 그 문장**을 못 믿을 것으로 만들었다
            # (9라운드 F6 실측).
            "count": _rows_seen,
            # int/str 혼합 정렬 금지 — CSV에 비숫자 ID가 한 건이라도 있으면
            # int(x)와 str이 비교돼 TypeError 500이 났다(감사 C1). 튜플 키로 분리.
            "matched_policy_ids": sorted(
                merged.keys(),
                key=lambda x: (0, int(x)) if str(x).isdigit() else (1, str(x))),
            # 일부만 맞는 경우도 사용자가 알아야 한다 — 절반이 남의 장비 것이면
            # 그 절반이 이 장비의 판정을 오염시킨다.
            "matched": len(matched),
            "unmatched": _rows_seen - len(matched),
        }
        # 어느 장비에 붙였는지 응답에 실어, 화면이 "이 장비의 CSV"라고 말할 수
        # 있게 한다(같은 값을 다음 요청에서 되돌려 보내 대조에도 쓴다).
        # 어느 VDOM 것인지 화면이 말할 수 있게 한다 — 그리고 앞서 올린 다른
        # VDOM 의 통계를 갈아 끼웠다면 **그 사실을 숨기지 않는다.**
        if _sel_vdom:
            summary["vdom"] = _sel_vdom
        if _replaced_vdom:
            summary["replaced_vdom"] = _replaced_vdom
        return jsonify({"runtime_stats": merged, "summary": summary,
                        "device_id": current_id, "csv_meta": csv_meta})

    @app.delete("/api/policy-stats")
    def clear_policy_stats():
        """이 장비의 사용량 통계를 비운다.

        통계는 언제나 합쳐지므로, 잘못 올린 CSV를 되돌릴 방법이 없으면 유일한
        복구가 '장비 삭제 후 재등록'이 된다 — config 원문·대역·FQDN까지 함께
        버리는 과한 대가다.
        """
        current_id = app.config.get('device_id')
        # **보관소에 먼저 쓴다.** 반대 순서였던 탓에, 보관소 쓰기가 실패하면
        # 화면은 "지우기 실패" 를 보는데 **현재 세션의 사용량 근거는 이미
        # 사라져** 미사용 판정 축이 통째로 뒤집혔다 — 보관소에는 남아 있어
        # 화면·판정·보관소가 세 갈래로 어긋났다(8라운드 발견 2 실측).
        if current_id:
            from app.services import device_store as _store
            try:
                _store.update_device_inputs(current_id, runtime_stats={},
                                            csv_meta=[], collect_coverage={})
            except Exception as exc:
                print(f"[APO] could not clear usage data: {exc}", flush=True)
                return jsonify({
                    "error": "APO could not clear the stored usage data, so it "
                             "would come back when you reopen the device. "
                             "Nothing was changed.",
                    "error_key": "store_write_failed"}), 503
        # 되돌릴 수 없는 쓰기다 — 대상 지목은 before_request 가 강제한다.
        app.config['last_runtime_stats'] = {}
        app.config['csv_meta'] = []
        # 통계가 비면 그 통계의 커버리지 서술도 함께 내린다 — 남기면 워크북이
        # "loaded: no" 와 "Usage from device: 1 of 3" 을 동시에 말하고, Open
        # 이 낡은 서술을 복원한다(라운드 72 — CSV·붙여넣기에 이은 세 번째
        # 형제 경로. 라운드 54/71 과 같은 패턴).
        app.config.pop('collect_coverage', None)
        return jsonify({"ok": True, "device_id": current_id})

    @app.post("/api/policies/render")
    def render_policies():
        payload = request.get_json(silent=True) or {}
        parsed = payload.get("parsed")
        runtime_stats = payload.get("runtime_stats", {})
        if not parsed:
            return jsonify({"error": "parsed payload is required"}), 400

        view = build_view_model(parsed, runtime_stats)
        return jsonify({"view": view})

    @app.post("/api/export/workbook")
    def export_workbook():
        gate = _license_required()
        if gate:
            return gate
        from werkzeug.utils import secure_filename
        payload = request.get_json(silent=True) or {}
        sheets = payload.get("sheets") or {}
        # **이름은 요청이 아니라 장비가 정한다.** 화면이 상수를 보내고 있어서
        # 장비 라벨 폴백은 한 번도 쓰이지 않았고, 두 고객의 워크북이 글자 그대로
        # 같은 이름(firewall_policy_optimizer_export.xlsx)으로 떨어졌다(라운드 26
        # 실측). 정책 번호 1·2·3 은 어느 FortiGate 에나 있어, 파일만 보고는 어느
        # 방화벽의 표인지 알 수 없다.
        #
        # 내려받는 이름은 _attachment 가 RFC 5987 로 싣는다 — 다른 산출물과 같은
        # 규칙이다. secure_filename 은 한글을 통째로 지워서, 한글 고객사명이면
        # 귀속이 사라진다. 디스크에 남기는 이름에만 쓴다(경로 탈출 차단).
        download_name = f"apo_tables_{_open_device_label()}.xlsx"
        # secure_filename은 str만 받는다. JSON으로 null/숫자/객체가 오면
        # TypeError가 try 밖에서 터져 500이 되고, 콘솔에 절대경로 트레이스백이 남는다.
        stem = secure_filename(str(payload.get("workbook_name")
                                   or f"apo_tables_{_open_device_label()}"))
        output_path = EXPORT_DIR / f"{stem or 'firewall_policy_optimizer_export'}.xlsx"
        try:
            build_workbook(output_path, sheets)
        except Exception as exc:
            print(f"[APO] workbook export failed: {exc}", flush=True)
            return jsonify({"error": "Failed to build workbook export"}), 400
        return app.response_class(
            response=output_path.read_bytes(), status=200,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": _attachment(download_name)})

    @app.get("/exports/<path:filename>")
    def download_export(filename: str):
        from werkzeug.utils import secure_filename
        safe_name = secure_filename(filename)
        if not safe_name or safe_name != filename:
            return jsonify({"error": "Invalid filename"}), 400
        # 무료 산출물(파싱 결과 JSON)만 이 경로로 제공. 유료 산출물(.xlsx 등)은
        # 라이선스 게이트가 걸린 전용 라우트로만 내려가야 하므로 여기서 차단.
        if not safe_name.endswith(".parsed.json"):
            return jsonify({"error": "Not available"}), 404
        # **지금 열려 있는 장비의 산출물만 내준다.** 이 라우트는 /api/ 밖이라
        # before_request 게이트가 닿지 않아, 예전 고객 파일이 EXPORT_DIR 에
        # 쌓인 채 이름만 알면 그대로 나갔다. 이름에 해시를 붙여 뒤섞임은
        # 없어졌지만, '내가 보는 장비의 것만 받는다'는 규칙은 여기에도 같이
        # 적용해야 화면과 받은 파일이 어긋나지 않는다.
        expected = app.config.get('last_export_name')
        if not expected or safe_name != expected:
            return jsonify({
                # **따를 수 없는 안내를 하지 않는다.** '그 장비를 다시 열면
                # 받을 수 있다'고 했지만, 장비를 다시 열어도 이 파일을 다시
                # 만들지 않는다 — 파싱 산출물은 업로드 때 한 번 쓰인다
                # (라운드 41 지적).
                "error": "That download belongs to a configuration that is no "
                         "longer open. Upload that configuration again to get "
                         "a fresh copy.",
                "error_key": "export_no_longer_open",
                "open_device_id": app.config.get('device_id')}), 409
        return send_from_directory(EXPORT_DIR, safe_name, as_attachment=True)

    def _diff_uploaded_pair():
        """올라온 두 파일을 비교해 결과를 낸다 — **화면과 내보내기가 같은 함수.**

        내보내기를 붙이면서 비교를 한 번 더 쓸 뻔했다. 이 라우트에는 '같은
        장비인가' 판별(라운드 28~30)이 붙어 있는데, 그걸 복사하면 다음에 규칙이
        바뀔 때 한쪽만 고쳐진다 — 이 루프가 장비 식별에서 세 번 겪은 실패다.
        반환은 (결과, 오류응답) 이며 둘 중 하나만 값이 있다.
        """
        old_file = request.files.get("old_config")
        new_file = request.files.get("new_config")

        if not old_file or not new_file:
            return None, (jsonify({
                "error": "Both baseline and target config files are required.",
                "error_key": "diff_two_files_required"}), 400)

        try:
            old_raw = old_file.read()
            new_raw = new_file.read()
            old_text = old_raw.decode("utf-8-sig", errors="ignore")
            new_text = new_raw.decode("utf-8-sig", errors="ignore")

            # **비교에도 같은 문턱을 둔다.** 업로드 라우트에만 있던 검사라,
            # 빈 파일을 기준으로 비교해 "정책 5건 신설"이 증적 엑셀에 사실로
            # 적혔다(라운드 46 실측). 어느 쪽이 문제인지 말해 준다.
            for _label, _txt, _fn in (("baseline", old_text, old_file.filename),
                                      ("target", new_text, new_file.filename)):
                _bad = config_intake_problem(_txt)
                if _bad:
                    # 값이 끼므로 전용 error_key 를 쓴다 — 업로드 라우트의
                    # 키(`empty_config` 등)는 값이 없는 문장이라 그대로 쓰면
                    # 화면이 같은 문장을 다시 만들 수 없다.
                    return None, (jsonify({
                        "error": f"The {_label} file ({_fn or '?'}) cannot be "
                                 f"compared. {_bad[0]}",
                        "error_key": "diff_file_unusable",
                        "which": _label, "file": _fn or "?",
                        "detail": _bad[0], "reason_key": _bad[1]}), 400)

            old_data = parse_config_text(old_text)
            new_data = parse_config_text(new_text)

            result = _compute_config_diff(old_data, new_data, old_text, new_text)
            # **무엇을 비교했는지 파일이 스스로 말해야 한다.** 화면은 옆에
            # 파일 이름이 떠 있어 맥락이 있지만, 내려받은 xlsx 는 혼자 돌아다닌다.
            # 이름은 바뀔 수 있으니 바이트 해시를 함께 싣는다 — 설정 파일·감사
            # 워크북과 같은 규칙.
            import hashlib as _hl
            result["sources"] = {
                "baseline": {"filename": old_file.filename or "",
                             "sha256": _hl.sha256(old_raw).hexdigest()},
                "target": {"filename": new_file.filename or "",
                           "sha256": _hl.sha256(new_raw).hexdigest()},
            }
            # **서로 다른 방화벽을 비교하면 '변경 0건'은 의미가 없다.**
            # 고객 2곳을 도는 감사자가 내려받기 폴더에서 옆 .conf 를 고르는 것은
            # 표준적인 실수인데, 그 결과가 '이 방화벽은 지난 분기 대비 변경
            # 없음'이라는 깨끗한 정기검토 결론으로 나왔다(라운드 28 실측:
            # 두 고객 설정을 비교하고 '0 total change groups detected').
            # 이 제품은 같은 판별을 감사 증적·조치 계획에서 이미 하고 있다 —
            # 규칙은 하나인데 경로마다 적으면 한 곳이 빠진다는 이 루프의 결론이
            # 여기서도 그대로 재현됐다.
            _oh = (old_data.get("meta") or {}).get("hostname") or ""
            _nh = (new_data.get("meta") or {}).get("hostname") or ""
            result["hostnames"] = {"baseline": _oh, "target": _nh}
            if _oh and _nh and _oh.strip().lower() != _nh.strip().lower():
                result["mixed_devices"] = sorted({_oh, _nh})
            else:
                # **이름이 같다고 같은 장비가 아니다.** 두 고객이 둘 다
                # 'FGT-HQ' 를 쓰거나 둘 다 hostname 줄이 없으면, 이름 대조는
                # 아무것도 증명하지 않는데 화면은 '변경 0건 · 검토 완료'라고
                # 말했다 — 정기검토 보고서에 '이 방화벽은 변경 없음'으로
                # 실린다(라운드 29 실측). 추측하지 말고 **아는 것을 말한다**:
                # 두 파일이 스스로 무엇이라 하는지, 그리고 그걸로는 같은
                # 장비인지 가릴 수 없다는 사실.
                # **한쪽만 이름이 있는 경우를 'same_name' 으로 떨어뜨리면 안
                # 된다.** `if not (_oh or _nh)` 였더니 baseline 만 이름이 있는
                # 비교에 "둘 다 hostname 을 보고했다"는 없는 사실이 찍혔다
                # (라운드 30 실측). 한쪽에 이름이 없다는 것은 오히려 대조가
                # 필요하다는 신호다 — 세 경우를 갈라 말한다.
                result["same_name_unverified"] = {
                    "hostname": _oh or _nh,
                    "reason": ("no_hostname" if not _oh and not _nh
                               else "same_name" if _oh and _nh
                               else "one_hostname"),
                }
            return result, None
        except Exception as exc:
            print(f"[APO] config diff failed: {exc}", flush=True)
            return None, (jsonify({
                "error": "Failed to compare configs. Check that both files are "
                         "valid FortiGate configs.",
                "error_key": "diff_failed"}), 500)

    @app.post("/api/config/diff")
    def api_config_diff():
        result, err = _diff_uploaded_pair()
        return err if err else jsonify(result)

    @app.post("/api/config/diff/export")
    def api_config_diff_export():
        """비교 결과를 파일로 낸다 — **화면에만 있던 before/after 를 남긴다.**

        화면은 정책별로 무엇이 무엇으로 바뀌었는지 보여주는데 그 값이 어떤
        파일에도 안 남았다. 감사 증적 워크북 Changes 시트는 건수와 정책 번호만
        실어서, '변경분 검토했다'는 증적은 되지만 '무엇을 검토했나'에는 답하지
        못한다(백로그 B-29).

        내용은 **요청이 준 두 파일에서 다시 계산한다** — 브라우저가 들고 있던
        표를 돌려받아 찍으면 파일이 APO 의 판단을 증명하지 못한다. 같은 이유로
        파일 이름도 세션이 아니라 이 두 파일에서 나온다.
        """
        # 유료 Export 계열의 서버측 게이트 — 이 라우트만 빠져 있어 무면허로
        # diff 워크북이 내려받아졌다(리뷰 게이트 security critical, 라운드 71).
        gate = _license_required()
        if gate:
            return gate
        result, err = _diff_uploaded_pair()
        if err:
            return err
        from app.services.diff_exporter import build_diff_workbook
        try:
            xlsx_bytes = build_diff_workbook(result, {
                "apo_version": APO_VERSION,
                "generated_at": _dt.now().strftime("%Y-%m-%d %H:%M"),
                # 비교 산출물은 두 파일에서 나온다 — 특정 고객의 것이라고
                # 단정할 수 없으므로 수신처를 싣지 않는다.
                **({"branding": _branding_for("")} if _branding_for("") else {}),
            })
        except Exception as exc:
            print(f"[APO] diff workbook export failed: {exc}", flush=True)
            return jsonify({"error": "Failed to build comparison export",
                            "error_key": "diff_export_failed"}), 400
        _src = (result.get("sources") or {}).get("target") or {}
        _stem = _re.sub(r"[^A-Za-z0-9._-]+", "_",
                        Path(_src.get("filename") or "config").stem)[:60] or "config"
        _name = f"apo_config_changes_{_stem}_{(_src.get('sha256') or '')[:8]}.xlsx"
        return app.response_class(
            response=xlsx_bytes, status=200,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={"Content-Disposition": _attachment(_name)})

    app.config.setdefault('user_ranges', [])

    @app.get("/api/user-ranges")
    def get_user_ranges():
        # 대역은 판정 입력이다 — 읽기도 어느 장비의 것인지 대야 한다.
        return jsonify({"user_ranges": app.config.get('user_ranges', []),
                        "device_id": app.config.get('device_id') or ""})

    @app.post("/api/user-ranges/set")
    def set_user_ranges():
        payload = request.get_json(silent=True) or {}
        # 배치 경로와 **같은 규칙**으로 읽는다: CIDR, 주소+넷마스크(장비 CLI의
        # 기본 표기), 범위, 뒤에 붙은 라벨. 예전에는 무엇이든 그대로 저장해서,
        # 못 읽는 값 하나가 목록에 있으면 판정이 조용히 뒤집혔다(라운드 12).
        from app.services.batch_report import addresses_in_field, clean_line
        import re as _re_rng
        raw_list = payload.get("ranges", [])
        if not isinstance(raw_list, list):
            # 문자열이 오면 파이썬은 글자 단위로 순회한다 — 400으로 끊는 편이
            # "글자 10개가 거부됐다"는 응답보다 정직하다(리뷰 라운드 14).
            return jsonify({"error": "ranges must be a list"}), 400
        ranges, rejected, rejected_total, seen = [], [], 0, set()
        for raw in raw_list:
            # BOM도 배치와 같이 떼어낸다 — 안 그러면 같은 값이 경로마다 다르게
            # 읽힌다(라운드 14).
            text = str(raw).strip().lstrip("﻿")
            if not text:
                continue
            # 한 항목에 쉼표·세미콜론으로 여러 대역을 적는 경우도 배치와 똑같이
            # 읽는다 — 필드 분해를 빼먹으면 같은 입력이 경로마다 다르게 읽힌다
            # (리뷰 라운드 13).
            got = []
            for field in _re_rng.split(r"[,;]", text):
                got.extend(addresses_in_field(field))
            if got:
                # 같은 대역을 두 번 넣어도 한 번만 센다 — 파일을 두 번 임포트하면
                # 판정은 그대로인데 리포트의 "User IP ranges configured"만 부풀어
                # 감사 문서가 사실과 어긋난다(리뷰 라운드 16).
                for c in got:
                    if c not in seen:
                        seen.add(c)
                        ranges.append({"cidr": c})
                continue
            rejected_total += 1
            if len(rejected) < 20:
                # 화면에 그대로 다시 뿌려지는 값이다 — 제어문자·RLO가 섞이면
                # 상태줄이 뒤집혀 읽힌다(이 기능의 다른 문자열과 같은 규칙).
                # 목록에는 상한을 두되 총 개수는 rejected_total로 알린다.
                rejected.append(clean_line(text)[:80])
        # 대역은 판정 입력이므로 **어느 장비에 저장하는지** 화면과 서버가
        # 합의한 경우에만 저장한다. CSV와 같은 게이트다. 화면이 장비를
        # 모르는 채(재시작 직후 등) 보낸 대역이 화면에 보이지도 않는 장비의
        # 저장된 대역을 덮어쓰면, 이력이 없어 되돌릴 수 없다.
        # **이름을 대지 않으면 거부한다.** 자진 신고할 때만 막았더니, 화면이
        # 장비를 모르는 상태(복원 실패·목록 조회 실패)에서 보낸 대역이 그대로
        # 통과해 보이지도 않는 장비의 대역을 지웠다(라운드 16 실측: 4개 → 1개).
        open_id = app.config.get('device_id')
        # **보관소에 먼저 쓰고, 성공한 뒤 메모리를 바꾼다.**
        # 반대 순서였던 탓에, 보관소 쓰기가 실패하면 맨 500 이 나가는데
        # **저장되지 않은 대역이 판정에 쓰였고 증적 지문(`_judgement_basis`)
        # 에도 들어갔다**(8라운드 발견 1 실측: 500 직후 GET 은 새 값을,
        # 장비를 다시 열면 옛 값을 준다 — 같은 config 가 두 기준으로 판정된다).
        # 라운드 44 가 `object_rules` 에 대해 고친 바로 그 버그의 형제다.
        # 장비마다 사용자 대역이 다른 게 정상이고(A고객 본사와 B고객 지사),
        # 전역 하나로 두면 다음 장비를 열 때 앞 장비 기준이 그대로 따라온다.
        if open_id:
            from app.services import device_store as _store
            try:
                _store.update_device_inputs(open_id, user_ranges=ranges)
            except Exception as exc:
                print(f"[APO] could not save user ranges: {exc}", flush=True)
                return jsonify({
                    "error": "APO could not save these IP ranges to the device "
                             "store, so they would be lost when you reopen the "
                             "device. Nothing was changed.",
                    "error_key": "store_write_failed"}), 503
        app.config['user_ranges'] = ranges
        # 화면이 서버가 인정한 목록 그대로 칩을 그릴 수 있어야 한다 —
        # 클라이언트가 따로 판단하면 두 규칙이 갈라진다(리뷰 라운드 15).
        # rejected는 20개까지만 싣되 총 개수는 숨기지 않는다.
        return jsonify({"ok": True, "count": len(ranges),
                        "user_ranges": ranges,
                        "rejected": rejected, "rejected_total": rejected_total})

    # ── 객체 명명 규칙 (고객마다 다르다) ───────────────────────────────
    def _object_names() -> list[str]:
        """미리보기가 견줄 대상 — **엔진이 견주는 것과 같아야 한다.**

        엔진(`severity_engine._in_obj`)은 두 가지를 본다: 주소 객체 **이름**과
        펼쳐진 **주소값**(CIDR). 이름만 보여줬더니, 예외 목록에 CIDR 을 적은
        경우 미리보기가 '0건'이라 하면서 판정에서는 걸렸다 — 납품 프로파일이
        실제로 그렇게 쓴다(`mgmt: <호스트 CIDR>/32` 형태). 미리보기가 판정과 다른
        것을 세면 그건 미리보기가 아니라 거짓말이다.
        """
        parsed = app.config.get('last_parsed') or {}
        out: list[str] = []
        # **정책이 실제로 참조하는 것만 센다.** 설정의 모든 주소 객체를 훑었더니
        # 아무 정책도 쓰지 않는 객체까지 세어, 미리보기는 'ADMIN 2건이 걸린다'는데
        # 예외를 받은 정책은 0건이었다(라운드 44 실측). 그룹 멤버로만 있는
        # 객체도 같은 이유로 헛세어졌다 — 엔진은 정책의 src/dst 에 적힌 이름과
        # 펼쳐진 주소값만 본다(`severity_engine._in_obj`).
        try:
            from app.services.policy_renderer import build_view_model as _bvm
            view = _bvm(parsed, app.config.get('last_runtime_stats', {}))
            for key in ("firewall_policy", "firewall_proxy_policy"):
                for pol in view.get(key, []) or []:
                    # 엔진이 받는 필드와 **글자 그대로 같은 것**을 본다.
                    # `_in_obj(obj, name, src, dst, src_names, dst_names)` 의
                    # 인자가 이 넷이다(server 의 classify 호출부 참조).
                    for fld in ("srcaddr_names", "dstaddr_names",    # 원본 객체명
                                "srcaddr_display", "dstaddr_display"):  # 펼친 값
                        for v in (pol.get(fld) or []):
                            out.append(str(v))
        except Exception as exc:
            print(f"[APO] object preview could not read policies: {exc}",
                  flush=True)
        # 같은 값이 여러 정책에 나오므로 중복을 없앤다 — '몇 개 객체가 걸리나'
        # 를 세는 것이지 '몇 번 등장하나'가 아니다.
        return sorted(set(out))

    _WORD_SEP = set("_-.:/ ")

    def _match_shape(name: str, pattern: str) -> str:
        """이 일치가 **의도된 것으로 보이는가.**

        매칭은 부분문자열이다. 그게 이 예외 체계가 실제로 작동하는 방식이고
        (실 고객 설정에서 '정확히 일치'하는 객체는 0개였다), 규칙을 갑자기
        엄격하게 바꾸면 걸려 있던 예외가 통째로 사라진다.
        그래서 규칙은 그대로 두고 **무엇이 걸리는지 보여준다** — 두 글자 값이
        단어 속에 우연히 걸린 것이 실 설정에서 17건이었는데, 화면에 나오지
        않으니 아무도 몰랐다.
        """
        # 엔진(`_in_obj`)은 양쪽을 lower() 해서 견준다. 미리보기가 대소문자를
        # 구분했더니, 'admin' 을 넣은 사용자에게 '0건'이라 말하면서 판정에서는
        # 걸렸다(라운드 44 실측). 같은 규칙으로 견뎌야 미리보기다.
        name, pattern = name.lower(), pattern.lower()
        i = name.find(pattern)
        if i < 0:
            return "none"
        if name == pattern:
            return "exact"
        before = name[i - 1] if i > 0 else ""
        after = name[i + len(pattern)] if i + len(pattern) < len(name) else ""
        lb = before == "" or before in _WORD_SEP
        rb = after == "" or after in _WORD_SEP
        if lb and rb:
            return "bounded"          # xxx_ADMIN_yyy — 의도된 것으로 보인다
        return "inside_word"          # xF1y — 우연일 수 있다

    def _object_rule_preview(rules: dict) -> dict:
        """입력한 값이 **이 설정의 어떤 객체에 걸리는지** 돌려준다.

        보이지 않는 규칙은 검증할 수 없다. 이 미리보기가 없던 동안, 아무 값도
        일치하지 않아 예외가 통째로 안 걸리는 것과 두 글자 값이 단어 속에
        걸리는 것을 사용자가 알 방법이 없었다.
        """
        names = _object_names()
        out = {}
        for kind in OBJECT_RULE_KINDS:
            items = []
            for pat in (rules.get(kind) or []):
                pat = str(pat).strip()
                if not pat:
                    continue
                _low = pat.lower()
                # **미리보기가 세는 것과 엔진이 거는 것이 같아야 한다.**
                # 엔진은 짧은 패턴의 단어 속 매칭을 무시하는데(`_obj_matches`),
                # 미리보기가 그걸 '걸린다'로 세면 화면과 판정이 다른 말을 한다 —
                # 이 루프가 되풀이해 겪은 실패다. 판정 여부는 엔진 함수에 묻고,
                # 모양(정확/경계/단어속)만 여기서 분류한다.
                shapes = [(n, _match_shape(n, pat)) for n in names
                          if _low in n.lower()]
                hits = [(n, sh) for n, sh in shapes
                        if _obj_matches(_low, n.lower())]
                ignored = [(n, sh) for n, sh in shapes
                           if not _obj_matches(_low, n.lower())]
                items.append({
                    "pattern": pat,
                    "total": len(hits),
                    "exact": sum(1 for _, s in hits if s == "exact"),
                    "bounded": sum(1 for _, s in hits if s == "bounded"),
                    "inside_word": sum(1 for _, s in hits if s == "inside_word"),
                    # 단어 속에 걸렸지만 **엔진이 무시하는** 것 — 사용자가
                    # "왜 안 걸리지?" 하지 않도록 사실대로 알려 준다.
                    "ignored_inside_word": len(ignored),
                    "ignored_examples": [n for n, _ in ignored[:3]],
                    # 이름 자체는 고객 환경 정보다 — 화면에서 확인할 수 있게
                    # 몇 개만 예시로 준다(전체 목록을 응답에 싣지 않는다).
                    "examples": [n for n, _ in hits[:5]],
                    # 두세 글자 값은 단어 속에 걸리기 쉽다(실 설정 'F1' 13건).
                    "short": len(pat) <= 3,
                })
            out[kind] = items
        return out

    @app.get("/api/object-rules")
    def get_object_rules():
        rules = app.config.get('object_rules') or {}
        return jsonify({
            "kinds": list(OBJECT_RULE_KINDS),
            "rules": rules,
            # 입력하지 않은 항목은 프로파일 값이 쓰인다 — 어느 쪽이 적용
            # 중인지 화면이 말해야 한다. **프로파일 값만** 담는다(병합 결과를
            # 담으면 사용자가 입력한 값이 프로파일 값처럼 보여, '이 항목은
            # 아직 비어 있다'와 '내가 넣었다'를 구분할 수 없다).
            "profile": {k: (to_customer_rules(app.config['profile']).get(v) or [])
                        for k, v in OBJECT_RULE_KINDS.items()},
            "profile_name": (app.config['profile'].get("meta") or {}).get("name", ""),
            # 구형 납품 파일이 병합된 배포면 그 사실을 화면이 말해야 한다 —
            # 안 그러면 고객 전용 객체명이 중립 기본값처럼 보인다.
            "legacy_file": (app.config['profile'].get("meta") or {}).get("legacy_file", ""),
            # **미리보기는 실제로 적용 중인 값을 보여야 한다.** 사용자가 입력한
            # 것만 미리보던 동안, 아무것도 입력하지 않은 기본 상태에서는 화면이
            # 텅 비어 "아무것도 안 걸린다"처럼 보였다 — 그런데 그때도 프로파일
            # 기본값이 객체를 잡아 등급을 바꾸고 있었다(라운드 45 실측:
            # `ADMIN` 이 `ADMIN_PC` 를 잡아 판정이 달라졌는데 설정 화면은
            # 아무것도 안 보여 줬다). 화면 안내문은 "각 항목이 무엇을 잡는지
            # 정확히 보여준다"고 약속하고 있었다.
            "preview": _object_rule_preview(_effective_object_rules()),
            "object_count": len(_object_names()),
        })

    def _effective_object_rules() -> dict:
        """지금 판정에 **실제로 쓰이는** 이름 목록(장비 입력이 프로파일을 이긴다).

        병합 규칙은 `_engine_ctx` 와 같아야 한다 — 두 곳에 적으면 갈린다.
        """
        merged = _engine_ctx()["customer_rules"] or {}
        return {kind: list(merged.get(engine_key) or [])
                for kind, engine_key in OBJECT_RULE_KINDS.items()}

    def _has_object_names(rules) -> bool:
        """정리된 객체 규칙에 **실제 이름이 하나라도** 있는가.

        `{"admin": [], "infra": []}` 처럼 전 카테고리가 빈 문서는 장비에 쓸
        것이 없으므로, 장비를 열지 않았다고 막을 이유도 없다(임계값·티켓만
        적용하면 된다).
        """
        return any((v or []) for v in (rules or {}).values())

    def _clean_object_rules(raw):
        """입력 dict → 정리된 `{kind: [name]}`. `(rules, None)` 또는 `(None, 사유)`.

        객체 규칙을 받는 곳이 둘(화면 저장·룰 세트 임포트)이라 정리 규칙을 한
        곳에 모은다 — 두 곳에 적으면 길이 제한·중복 제거가 한쪽만 갱신된다.
        """
        if not isinstance(raw, dict):
            return None, "rules must be an object keyed by kind"
        rules = {}
        for kind in OBJECT_RULE_KINDS:
            vals = raw.get(kind)
            if vals is None:
                continue
            if isinstance(vals, str):
                vals = [v for v in vals.replace(",", chr(10)).split(chr(10))]
            if not isinstance(vals, list):
                return None, f"'{kind}' must be a list of names"
            seen, clean = set(), []
            for v in vals:
                # **문자열이 아닌 원소는 버린다.** 화면은 textarea 라 항상
                # 문자열을 보내지만 룰 세트 가져오기는 임의 JSON 을 받는다 —
                # `str(v)` 로 뭉개면 `null`·`123`·`{"a":1}` 이 각각
                # "None"·"123"·"{'a': 1}" 이라는 **객체 이름**으로 대장에
                # 영구 저장되고 룰 세트 해시에도 들어간다(2026-09-09 실측).
                if not isinstance(v, str):
                    continue
                v = v.strip()
                # 이름은 사용자가 적는 값이다. 길이만 제한하고 내용은 그대로
                # 둔다 — 고객 객체명에 한글·괄호·슬래시가 들어가는 일이 있다.
                if not v or v in seen or len(v) > 200:
                    continue
                seen.add(v)
                clean.append(v)
            rules[kind] = clean
        return rules, None

    @app.post("/api/object-rules/set")
    def set_object_rules():
        payload = request.get_json(silent=True) or {}
        raw = payload.get("rules")
        rules, err = _clean_object_rules(raw)
        if err is not None:
            # 모양 오류(키별 dict 가 아님)에서만 종류 힌트를 함께 준다 —
            # 키별 목록 오류는 어느 키가 문제인지 이미 사유에 담겨 있다.
            if not isinstance(raw, dict):
                return jsonify({"error": err, "kinds": list(OBJECT_RULE_KINDS)}), 400
            return jsonify({"error": err}), 400
        # **대장에 먼저 쓴다.** 메모리를 먼저 바꿨더니, 쓰기가 실패해 503 을
        # 돌려준 뒤에도 그 값이 판정에 쓰였다 — 화면은 '저장 안 됐다'고 말하고
        # 입력란은 옛 값을 보여주는데, 등급은 새 값으로 정해졌다(라운드 44
        # 실측). 화면이 실패라고 말한 값이 결과를 바꾸면 안 된다.
        open_id = app.config.get('device_id')
        if open_id:
            try:
                _store().update_device_inputs(open_id, object_rules=rules)
            except Exception as exc:
                print(f"[APO] could not save object rules: {exc}", flush=True)
                return jsonify({
                    "error": "APO could not save these names to the device store, "
                             "so they would be lost when you reopen the device. "
                             "Nothing was changed.",
                    "error_key": "store_write_failed"}), 503
        app.config['object_rules'] = rules
        # 저장 직후에도 **적용 중인 값**을 미리본다 — 비워 둔 항목은 프로파일
        # 값이 계속 일하고 있으므로, 사용자 입력만 보여주면 그 항목이 꺼진
        # 것처럼 보인다(GET 과 같은 규칙).
        return jsonify({"ok": True, "rules": rules,
                        "preview": _object_rule_preview(_effective_object_rules()),
                        "object_count": len(_object_names())})

    # ── 룰 세트(판정 입력 묶음) 내보내기·가져오기 ─────────────────────────────
    def _effective_ticket() -> dict:
        """지금 적용 중인 티켓 형식 — 사용자가 설정에 넣은 값(프로파일 아님).

        룰 세트는 **고객의 입력**을 이식한다. 프로파일 내장 패턴은 배포본에
        딸려 오는 것이라 룰 세트에 담지 않는다 — 담으면 받는 쪽 프로파일과
        섞여 어느 쪽이 적용됐는지 흐려진다.
        """
        tk = _rs.ticket_settings()
        # **그리고 쓰는 값을 빼도 안 된다.** 6라운드는 "안 쓰는 값을 서명했다"
        # 만 고쳤고 나머지 절반이 남았다: 프로파일 패턴은 판정을 가르는데
        # 룰 세트에 안 실려, **티켓을 읽은 판정과 안 읽은 판정의 해시가 같았다**
        # (7라운드 F3 실측 — 같은 해시인데 policy 6 이 sev 7 과 sev 0 으로 갈렸다).
        # 그 해시를 인쇄하는 Summary 는 "티켓 형식을 식별한다" 고 말한다.
        #
        # 프로파일 값을 **그대로 담지는 않는다**(받는 쪽 프로파일과 섞인다).
        # 대신 지금 실제로 쓰이는 패턴과 그 출처를 함께 적어, 해시가 그 축을
        # 반영하게 한다.
        _eff_src, _eff_origin = _rs.resolve_pattern_source(
            _ticket_profile_pattern())
        # **안 쓰는 값을 "지금 쓰는 값" 으로 서명하면 안 된다.** 정규식 직접
        # 입력을 끈 뒤로 저장된 `regex` 는 판정에 채택되지 않는데, 여기서는
        # 그대로 직렬화해 해시에 넣고 있었다 — 그 해시가 리포트 Summary 에
        # 인쇄된다. 감사 증적이 "이 정규식으로 티켓을 대조했다" 고 말하는데
        # 실제로는 티켓을 하나도 읽지 않은 상태였다(6라운드 B2 실측).
        regex = tk.get("regex") or None
        if not _rs.TICKET_REGEX_ENABLED:
            regex = None
        return {
            "prefixes": _rs.normalize_prefixes(tk.get("prefixes")),
            "regex": regex,
            "scan_comment": _rs.scan_comment_enabled(),
            # 이식용 값이 아니라 **판정 축의 지문**이다 — 받는 쪽에서 그대로
            # 쓰라는 뜻이 아니라, 두 판정이 같은 티켓 기준이었는지 대조하라는 뜻.
            "effective_pattern": _eff_src or "",
            "effective_origin": _eff_origin,
        }

    @app.get("/api/ruleset/export")
    def export_ruleset():
        """지금 적용 중인 판정 입력을 **이름 붙은 이식 가능한 룰 세트**로.

        임계값·객체 분류·티켓 형식을 한 문서로 묶고 SHA-256 을 붙인다.
        **판정을 바꾸지 않는다** — 지금 쓰는 값을 그대로 직렬화한다. 임계값은
        프로파일∪사용자값(실효값)을 담아, 받는 쪽 프로파일이 무엇이든 같은
        판정을 재현한다(MSP 가 한 기준을 여러 장비에 그대로 적용).
        """
        th = _sanitize_thresholds(_engine_ctx()["thresholds"])
        doc = ruleset_svc.build_ruleset(th, _effective_object_rules(),
                                        _effective_ticket())
        return jsonify(doc)

    # ── 룰 세트 **가져오기**: v127 에서 출하하지 않는다 ────────────────────
    # 2026-09-09 Jayden 결정. 재비판 4·5 라운드가 이 경로에서만 블로커 7건을
    # 냈고, 마지막 라운드에서도 셋이 남았다. 핵심은 **납품 형상에서 안 고쳐진
    # 것**이다: 고객 납품판은 exe 옆 `customer_rules.json` 이 객체 이름을 채우므로
    # `_has_object_names` 가 늘 참이 되어 자기 export 를 되받지 못하고,
    # `_effective_ticket()` 이 프로파일 패턴을 뺀 채 내보내므로 정상 export 를
    # 가져오면 **받는 쪽 티켓 형식이 지워져 등급이 7→1 로 갈린다**.
    # 내보내기(+Summary 해시)는 다섯 라운드 내내 깨끗해 그대로 출하한다 —
    # 감사 증적이라는 이 기능의 실제 가치는 내보내기 쪽에 있다.
    # 코드·테스트는 남긴다. v128 에서 이식 의미론(프로파일 기본값과 사용자
    # 입력의 구분, 빈 값 = '미지정')을 정리한 뒤 다시 낸다.
    RULESET_IMPORT_ENABLED = False

    def _register_ruleset_import(fn):
        return app.post("/api/ruleset/import")(fn) if RULESET_IMPORT_ENABLED else fn

    @_register_ruleset_import
    def import_ruleset():
        """룰 세트 문서를 받아 지금 세션/장비/디스크에 적용한다.

        **먼저 전부 검증한 뒤 적용한다** — 입력이 하나라도 부적격이면 아무것도
        바꾸지 않는다(반쯤 적용된 상태를 만들지 않는다). 각 입력은 화면에서
        쓰는 것과 **같은 게이트**를 탄다: 임계값은 `_sanitize_thresholds`,
        객체 분류는 `_clean_object_rules`, 티켓 정규식은 ReDoS 검사.
        """
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Not a rule set document."}), 400
        th_in = payload.get("thresholds")
        obj_in = payload.get("object_rules")
        tk_in = payload.get("ticket")
        if th_in is None and obj_in is None and tk_in is None:
            return jsonify({"error": "Not a rule set. Expected at least one of "
                            "thresholds / object_rules / ticket."}), 400

        # ── 1) 검증 (부작용 없음) ──
        # **부적격 임계값을 조용히 삼키지 않는다.** 예전에는 dict 가 아니거나
        # 살아남은 키가 0개면 `{}` 가 되고, 그 `{}` 로 override 를 통째로
        # 덮어썼다 — 오타 하나 든 파일이 200 `ok:true` 와 함께 사용자가 조정한
        # dormancy 400 을 프로파일 기본값 365 로 되돌렸다(2026-09-09 실측,
        # Jayden 배치 승인). 다른 두 필드(object_rules·ticket)는 같은 상황에서
        # 400 을 내고 있었다 — 비대칭이 이 핸들러의 약속을 깨고 있었다.
        if th_in is not None and not isinstance(th_in, dict):
            return jsonify({"error": "thresholds must be an object.",
                            "error_key": "bad_thresholds"}), 400
        thresholds = _sanitize_thresholds(th_in) if isinstance(th_in, dict) else {}
        # **빈 dict 는 '지정하지 않음' 이지 '전부 지워라' 가 아니다.**
        # 참/거짓 검사라 `{}` 가 이 가드를 빠져나가 200 과 함께 적용 중인
        # 임계값을 통째로 초기화했다(dormancy 400→365). `{"bogus":1}` 은 400
        # 인데 `{}` 는 200 이던 비대칭도 여기서 사라진다(재비판 라운드 4).
        if isinstance(th_in, dict) and not th_in:
            th_in = None
        if th_in and not thresholds:
            return jsonify({
                "error": "None of the thresholds in this rule set are usable, so "
                         "nothing was changed. Check the names and ranges.",
                "error_key": "bad_thresholds"}), 400
        rules, err = (_clean_object_rules(obj_in) if obj_in is not None
                      else ({}, None))
        if err is not None:
            # 사유(err)를 그대로 돌려준다 — set_object_rules 와 같은 처리다.
            # 이 문장들은 모양 검증용(dev-facing)이라 화면 사전을 타지 않는다.
            return jsonify({"error": err}), 400

        ticket_payload = None
        if tk_in is not None:
            if not isinstance(tk_in, dict):
                return jsonify({"error": "ticket must be an object."}), 400
            regex = tk_in.get("regex")
            if isinstance(regex, str) and regex.strip():
                ok, why = _rs.validate_regex(regex.strip())
                if not ok:
                    # settings_ticket_set 과 같은 처리 — 거부 사유(why)를 그대로
                    # 돌려준다. **번역은 사유 문장 자체가 사전 키가 되어 이뤄진다**
                    # (`bad_pattern` 은 SERVER_ERRORS 에 두지 않는다 — 두면
                    # serverMsg 가 템플릿을 쓰면서 어느 사유인지가 사라진다).
                    # validate_regex 의 문장들은 i18n.js 에 등록돼 있다.
                    return jsonify({"error": why, "error_key": "bad_pattern"}), 400
                regex = regex.strip()
            else:
                regex = None
            ticket_payload = {
                "prefixes": _rs.normalize_prefixes(tk_in.get("prefixes")),
                "regex": regex,
                "scan_comment": bool(tk_in.get("scan_comment", True)),
            }

        # ── 2) 적용 ── (검증을 다 통과했으므로 여기서 형식 오류로 멈추지 않는다)
        # 객체 규칙은 set_object_rules 와 같은 순서로 **대장에 먼저** 쓴다 —
        # 쓰기가 실패하면 판정을 바꾸지 않는다.
        open_id = app.config.get('device_id')
        # **장비가 없으면 객체 이름을 받지 않는다.** 예전에는 200 `ok:true` 를
        # 돌려주고 메모리에만 채웠는데, 대장에 못 쓰므로 바로 다음 단계(설정
        # 파일 업로드)에서 `_drop_previous_device_traces` 가 그것을 지웠다 —
        # 사용자는 자기 기준을 적용했다고 믿고 **다른 기준으로 판정받았고**
        # 화면은 아무 말도 하지 않았다(재비판 라운드 3 실측: 임계값·티켓은
        # 살아남고 객체 이름만 죽어 '반쯤 적용' 이기도 했다).
        # `object-rules/set` 이 같은 상황에서 이미 409 를 낸다 — 형제 라우트와
        # 같은 답을 준다.
        if obj_in is not None and not open_id and _has_object_names(rules):
            # `what` 을 반드시 채운다 — 화면의 SERVER_ERRORS['input_no_device']
            # 템플릿이 `{what}` 을 쓰는데 이 값이 없으면 "이  에 어느 장비의
            # 것인지가 없습니다" 처럼 **빈칸**이 인쇄되고, 정작 사용자가 들어야
            # 할 "장비를 먼저 여세요" 는 사라진다(재비판 라운드 4 실측).
            # serverMsg 는 error_key 템플릿이 있으면 서버 문장을 버린다.
            return jsonify({
                "error": "No device is open, so the object names in this rule "
                         "set have nowhere to go. Open the device first, then "
                         "import it again.",
                "error_key": "input_no_device", "what": "rule set",
                "open_device_id": None}), 409
        # **대장 쓰기 조건과 메모리 적용 조건이 같아야 한다.** 예전에는 빈
        # dict 가 falsy 라 대장 쓰기만 건너뛰고 메모리는 무조건 비웠다 —
        # `{"object_rules": {}}` 를 가져오면 이번 세션은 프로파일 기본값으로
        # 판정하고 장비를 다시 열면 옛 규칙으로 돌아가, **같은 장비·같은 config
        # 가 세션마다 다른 등급**을 받았다(2026-09-09 실측, Jayden 배치 승인).
        # 라운드 44 가 set_object_rules 에서 고친 것과 같은 형태다.
        # **영구 저장은 티켓 → 대장 순서로, 실패하면 되돌린다.**
        # 예전 순서(대장 먼저)는 티켓 저장이 실패했을 때 객체 이름이 **이미
        # 대장에 영구 기록**된 채 503 을 냈다 — 응답은 "티켓만 못 저장했다"고
        # 말하는데 실제로는 이번 세션은 옛 규칙, 장비를 다시 열면 새 규칙으로
        # 판정했다(재비판 라운드 4 실측). 객체 이름은 6/3 예외를 가르는 판정
        # 입력이라 이건 판정이 갈리는 사고다.
        # 디스크(exe 옆·사용자 폴더 둘 다 불가)가 대장보다 실패 가능성이
        # 높으므로 먼저 시도하고, 뒤가 실패하면 앞을 원복한다.
        ticket_saved_to = None
        _prev_settings = dict(_rs.load_settings()) if ticket_payload is not None else None
        if ticket_payload is not None:
            settings = dict(_prev_settings)
            settings["ticket"] = ticket_payload
            try:
                ticket_saved_to = str(_rs.save_settings(settings))
            except OSError as exc:
                # 이 시점에는 아직 아무것도 안 바꿨다 — 정확히 그렇게 말한다.
                print(f"[APO] could not save imported ticket format: {exc}",
                      flush=True)
                return jsonify({
                    "error": "The ticket format could not be saved to disk, so "
                             "nothing was changed.",
                    "error_key": "ticket_write_failed"}), 503

        if obj_in is not None and open_id:
            try:
                _store().update_device_inputs(open_id, object_rules=rules)
            except Exception as exc:
                print(f"[APO] could not save imported object rules: {exc}",
                      flush=True)
                if _prev_settings is not None:
                    # 앞 단계에서 쓴 티켓을 되돌린다 — 안 그러면 '반쯤 적용'이다.
                    try:
                        _rs.save_settings(_prev_settings)
                    except OSError:
                        print("[APO] could not roll back the ticket format",
                              flush=True)
                # set_object_rules 와 같은 문구·키를 쓴다(같은 실패, 같은 사전 항목).
                return jsonify({
                    "error": "APO could not save these names to the device store, "
                             "so they would be lost when you reopen the device. "
                             "Nothing was changed.",
                    "error_key": "store_write_failed"}), 503

        if th_in is not None:
            app.config['thresholds_override'] = thresholds
        if obj_in is not None:
            app.config['object_rules'] = rules

        applied = ruleset_svc.build_ruleset(
            _sanitize_thresholds(_engine_ctx()["thresholds"]),
            _effective_object_rules(), _effective_ticket())
        return jsonify({
            "ok": True,
            "hash": applied["hash"],
            "thresholds": applied["thresholds"],
            "object_rules": applied["object_rules"],
            "ticket_saved_to": ticket_saved_to,
            "preview": _object_rule_preview(_effective_object_rules()),
            "object_count": len(_object_names()),
        })

    # ── 티켓 번호 형식 ─────────────────────────────────────────────────────
    # 고객사마다 ITSM 번호 형식이 다르다(RITM·CHG·REQ…). 예전에는 이 값이
    # `profiles/<name>.yaml` 에만 있어서, 파일을 exe 옆에 놓아 주지 않으면
    # **이름에 티켓 번호가 박혀 있어도 전량 '티켓 없음'** 으로 판정됐다.
    # 임계값과 달리 세션이 아니라 디스크에 남긴다 — 고객사 고정값이라 매번
    # 다시 입력하게 하면 파일을 놓는 것과 견줘 나아지는 게 없다.
    def _ticket_profile_pattern() -> str:
        return (app.config['profile'].get("naming") or {}).get("ticket_id_pattern") or ""

    def _ticket_preview(pattern_str: str, scan_comment: bool) -> dict:
        """이 패턴이 **지금 열린 설정에서 몇 건을 잡는지**.

        저장하기 전에 보여 준다. 명명 규칙은 조직마다 미묘하게 달라서, 맞는지
        확인할 방법이 없으면 사용자는 저장하고 다시 점검하는 왕복을 반복해야
        한다(임계값 화면이 이미 '값 → 결과'로 푼 문제와 같은 것이다).
        """
        parsed = app.config.get('last_parsed')
        out = {"loaded": bool(parsed), "total": 0, "matched": 0, "examples": [],
               # 하나도 안 걸렸을 때 **실제 정책 이름 몇 개**를 함께 준다.
               # "0건 인식"만 보여주면 사용자는 다음에 무엇을 해야 할지 알 수
               # 없다 — 자기 이름 규칙을 보고 어느 부분이 티켓 번호인지
               # 판단할 수 있어야 한다(실사용 지적).
               "sample_names": []}
        if not parsed:
            return out
        rx = None
        if pattern_str:
            try:
                # **플래그는 runtime_settings 한 곳에서 받는다.** 여기에
                # `re.IGNORECASE` 를 다시 적어 두면, 판정 쪽 플래그가 바뀔 때
                # 이 미리보기만 옛 플래그로 남아 **판정과 다른 건수**를 말한다
                # — 이번 릴리스가 고친 브릭과 정확히 같은 형태의 사고다
                # (재비판 3라운드 발견 4). 오늘은 값이 같아 동작 차이는 없다.
                rx = _re_mod.compile(pattern_str, _rs._TICKET_FLAGS)
            except _re_mod.error:
                rx = None
        for key in ("firewall_policy", "firewall_proxy_policy"):
            for item in (parsed.get(key) or []):
                out["total"] += 1
                name = str(item.get("name") or "")
                hay = name[:_TICKET_SCAN_LEN]
                match = rx.search(hay) if rx else None
                where = "name"
                if not match and rx and scan_comment:
                    note = str(item.get("comments") or item.get("comment") or "")
                    match = rx.search(note[:_TICKET_SCAN_LEN])
                    where = "comment"
                if match:
                    out["matched"] += 1
                    if len(out["examples"]) < 3:
                        out["examples"].append({
                            "policy_id": item.get("policy_id"),
                            "ticket": match.group().upper(),
                            "found_in": where,
                        })
                elif len(out["sample_names"]) < 3 and name.strip():
                    # 안 걸린 이름을 모아 둔다 — 0건일 때 사용자가 자기 규칙을
                    # 보고 판단할 재료가 된다.
                    out["sample_names"].append(name[:60])
        return out

    @app.get("/api/settings/ticket")
    def settings_ticket_get():
        cfg = _rs.ticket_settings()
        source, origin = _rs.resolve_pattern_source(_ticket_profile_pattern())
        return jsonify({
            "prefixes": _rs.normalize_prefixes(cfg.get("prefixes")),
            "regex": str(cfg.get("regex") or ""),
            "scan_comment": _rs.scan_comment_enabled(),
            # 지금 실제로 쓰이는 패턴과 그 출처. 출처를 감추면 사용자는 자기가
            # 넣은 값이 왜 안 먹는지(또는 프로파일 값이 일하고 있는지) 모른다.
            "effective_pattern": source or "",
            "origin": origin,
            "profile_pattern": _ticket_profile_pattern(),
            "preview": _ticket_preview(source or "", _rs.scan_comment_enabled()),
        })

    @app.post("/api/settings/ticket")
    def settings_ticket_set():
        payload = request.get_json(silent=True) or {}
        prefixes = _rs.normalize_prefixes(payload.get("prefixes"))
        regex = str(payload.get("regex") or "").strip()
        scan_comment = bool(payload.get("scan_comment", True))
        if regex and not _rs.TICKET_REGEX_ENABLED:
            # **정규식 직접 입력을 껐다.** 화면에서도 칸을 없앴지만 API 는
            # 그대로 열려 있으므로 여기서 막는다 — 화면만 숨기면 옛 클라이언트·
            # 스크립트가 계속 저장할 수 있고, 그러면 끈 의미가 없다.
            return jsonify({
                "error": "Ticket formats are set with prefixes now. Enter the "
                         "prefix your tickets start with (for example RITM), "
                         "not a regular expression.",
                "error_key": "regex_disabled"}), 400
        if regex:
            ok, reason = _rs.validate_regex(regex)
            if not ok:
                # 거부 사유를 그대로 돌려준다 — "잘못된 입력"만으로는 무엇을
                # 고쳐야 할지 알 수 없다.
                return jsonify({"error": reason, "error_key": "bad_pattern"}), 400
            pattern_str = regex
        else:
            pattern_str = _rs.build_prefix_pattern(prefixes) or ""
        # **미리보기와 '실제로 쓰이는 값' 이 같은 응답 안에서 갈렸다.**
        # `preview` 는 방금 조립한 `pattern_str` 로, `effective_pattern`·`origin`
        # 은 `resolve_pattern_source`(프로파일 폴백 포함)로 계산했다. 접두어 칸이
        # 비고 프로파일 패턴이 있으면 **화면은 "인식 0건", 서버는 1건**이 된다.
        # 새로고침하면 같은 칸이 정반대 문장으로 바뀐다(7라운드 F1 실측).
        #
        # 미리보기는 **저장했을 때 실제로 쓰일 값**을 보여야 한다. 접두어가
        # 비면 폴백이 그 자리를 차지하므로 그것으로 잰다.
        effective = pattern_str or (
            _rs.resolve_pattern_source(_ticket_profile_pattern())[0] or "")
        preview = _ticket_preview(effective, scan_comment)
        # 미리보기 요청은 아무것도 저장하지 않는다.
        if payload.get("preview_only"):
            # **`origin` 을 빼면 화면이 첫 조기 return 에 걸린다** — "티켓 형식이
            # 설정되지 않았습니다" 를 인쇄하는데 실제로는 프로파일 패턴이 돌고
            # 있다. 6라운드가 고친 것과 같은 문장인데 타이핑 경로만 안 고쳐졌다
            # (7라운드 F2). legacy-regex 안내도 이 값이 있어야 뜬다.
            _, _origin = _rs.resolve_pattern_source(_ticket_profile_pattern())
            return jsonify({"ok": True, "preview": preview,
                            "effective_pattern": effective,
                            "origin": (_origin if not pattern_str
                                       else "settings-prefixes")})
        data = dict(_rs.load_settings())
        data["ticket"] = {"prefixes": prefixes, "regex": regex,
                          "scan_comment": scan_comment}
        try:
            saved_to = _rs.save_settings(data)
        except Exception as exc:
            # 저장 실패를 성공처럼 돌려주면, 사용자는 재시작 후 설정이 사라진
            # 이유를 알 수 없다(객체 규칙이 이미 같은 규칙을 쓴다).
            print(f"[APO] could not save ticket settings: {exc}", flush=True)
            return jsonify({"error": "APO could not save this setting, so it "
                            "would be lost when you restart. Nothing was changed.",
                            "error_key": "store_write_failed"}), 503
        source, origin = _rs.resolve_pattern_source(_ticket_profile_pattern())
        return jsonify({"ok": True, "preview": preview,
                        "effective_pattern": source or "", "origin": origin,
                        # 어디에 저장됐는지 화면이 말할 수 있어야 한다 —
                        # 프로그램 옆에 못 쓰면 사용자 폴더로 넘어간다.
                        "saved_to": str(saved_to)})

    def _ticket_effective() -> tuple[str, str]:
        """지금 판정에 실제로 쓰이는 티켓 패턴과 그 출처."""
        src, origin = _rs.resolve_pattern_source(_ticket_profile_pattern())
        return (src or ""), origin

    def _judgement_basis() -> str:
        """**무엇을 근거로 판정했는가**의 지문.

        점검 결과(export 는 그 시점의 스냅샷)와 조치 계획(열 때마다 서버가
        재계산)이 같은 근거로 만들어졌는지 화면이 대조할 수 있게 한다.
        둘 사이에 사용량 CSV 를 올리거나 임계값을 바꾸면 같은 정책이 한쪽에서
        High, 다른 쪽에서 Low 로 나오는데, 지금까지 화면은 그 사실을 몰랐다
        (2026-08-25 Jayden — 정책 498). 판정 로직은 두 경로가 동일하다.

        값이 아니라 지문만 비교한다 — 무엇이 달라졌는지까지 말하려면 두
        스냅샷을 다 들고 있어야 하고, 그건 '다시 점검하라' 한 줄로 충분하다.
        """
        stats = app.config.get('last_runtime_stats') or {}
        basis = {
            "config": app.config.get('last_config_sha256') or "",
            # **개수가 아니라 값이다.** 행 수만 세면, 같은 정책 집합을 새로
            # 수집해 hit_count 가 바뀐 경우 지문이 그대로다 — 그리고 그게
            # 바로 정책 498 이 두 화면에서 갈린 시나리오다(재수집 전후로
            # Hit=0 여부가 바뀌면 High↔Low). 종류별 형태
            # ({"firewall":{…},"proxy":{…}})에서는 개수가 아예 항상 2 다.
            # 메타(_로 시작)는 아래에서 따로 다룬다 — 캡처 시각처럼 판정과
            # 무관한 값이 섞이면 지문이 늘 달라져 경고가 상시로 뜬다.
            "usage": {k: v for k, v in stats.items()
                      if not str(k).startswith("_")},
            "usage_vdom": str(stats.get("_vdom") or ""),
            # **날짜도 판정 입력이다.** 만료 스케줄·승인 유효기간·휴면·연차
            # 임계값이 전부 today 로 계산된다(severity_engine). 날짜가 지문에
            # 없으면 어제 점검하고 오늘 조치 계획을 연 경우 등급이 실제로
            # 뒤집혔는데도 지문이 같아 경고가 침묵한다 — 이 기능이 막으려던
            # 바로 그 상황이다(게이트 spec 렌즈 검출).
            # 날이 바뀌면 경고가 뜨는 것은 오탐이 아니다. 그때는 정말로 다시
            # 판정해야 한다.
            "today": _date.today().isoformat(),
            # **판정 기준 전체를 넣는다 — 임계값만이 아니다.** services(위험·
            # AD/DNS·ICMP 서비스 목록)와 rules(standby 키워드 등)도 등급을
            # 가르고(severity_engine 의 svc_cfg·standby 분기), 프로파일을
            # 바꾸면 이것들이 함께 바뀐다. 임계값만 보면 프로파일 전환이
            # 지문에 안 잡혀 경고가 침묵한다(게이트 spec 렌즈).
            "engine": _engine_ctx(),
            # user_ranges 는 [{"cidr": ...}] 형태의 **dict 리스트**다(set_user_ranges
            # 참조). dict 는 정렬 비교가 안 돼 2개 이상이면 sorted 가 TypeError 로
            # 죽어, 판정을 만드는 classify·후보 라우트가 500 이 됐다 — 대역은 판정
            # 축(S-U/S-S)이라 내부 서브넷이 여럿인 정상 감사에서 화면이 통째로
            # 열리지 않았다(게이트 spec 렌즈). export(report_meta)와 같은 방식으로
            # cidr 문자열만 뽑아 순서 무관 지문을 만든다.
            "ranges": sorted(str(x.get("cidr") if isinstance(x, dict) else x)
                             for x in (app.config.get('user_ranges') or [])),
            "object_rules": app.config.get('object_rules') or {},
            # **FQDN 캐시도 판정 입력이다.** 두 화면 모두 도달불가·유보
            # 판정에 _fqdn_map() 을 쓰는데, 이 캐시는 import·fetch-device 로
            # 세션 중 바뀌면서 config·사용량·임계값 어느 것도 건드리지 않는다.
            # 그래서 FQDN 만 바뀌면 판정이 실제로 갈리는데 지문이 같았다
            # (게이트 correctness 렌즈). **캡처 시각이 아니라 맵 내용**을
            # 넣는다 — 같은 내용을 다시 수집한 것은 어긋남이 아니다.
            "fqdn": _fqdn_map() or {},
            # **같은 캐시의 스코프도 판정 입력이다.** detect_unreachable 은
            # snapshot_vdom 으로 게이트 대상 FQDN 집합을 뒤집는다
            # (reachability.gated_fqdn_names — vdom-dns 를 켠 VDOM 이 있을 때).
            # 그래서 해석 결과가 같아도 출처가 ''(덤프 import) → 'vdN'(장비
            # 수집)으로 바뀌면 도달불가·유보 판정이 갈린다. map 만 넣으면
            # 그 전환이 지문에 안 잡힌다(게이트 correctness, 잔여 구멍).
            "fqdn_vdom": _fqdn_source_vdom() or "",
        }
        return _hashlib_sha256_bytes(
            json.dumps(basis, sort_keys=True, default=str).encode("utf-8")
        )[:16]

    @app.post("/api/severity/classify")
    def severity_classify():
        # 임계값 오버라이드는 config 로드 여부와 무관하게 먼저 반영한다 —
        # 사용자가 설정을 조정해 두고 나중에 config를 올리는 순서도 유효하다.
        payload = request.get_json(silent=True) or {}
        if "thresholds" in payload:
            app.config['thresholds_override'] = _sanitize_thresholds(
                payload.get("thresholds") or {})
        # **판정을 만드는 라우트에도 같은 게이트가 필요하다.** 쓰기 경로만
        # 막아 뒀더니, 탭을 두 개 띄워 서로 다른 장비를 열면 화면 머리글은
        # A 고객인데 표에 뜨는 정책·등급은 B 고객 것이 됐다(라운드 22 실측).
        # 그 화면을 그대로 캡처해 A 보고서에 넣으면 B 고객의 정책명·주소가
        # 넘어간다 — 읽기라고 안전한 것이 아니다.
        parsed = app.config.get('last_parsed')
        if not parsed:
            return jsonify({"error": "No config loaded. Upload a config file first."}), 400
        service_groups = parsed.get("service_groups", {})
        user_ranges = app.config.get('user_ranges', [])
        context = {
            "service_groups": service_groups,
            "user_ranges": user_ranges,
            "today": _date.today(),
            # 승인 유효기간 유예의 신호(onetime 스케줄) — 모든 판정 경로가
            # 같은 맵을 받아야 한다. 한 곳만 빠지면 classify 와 후보/유보가
            # 갈린다(라운드 71 스코프 전파와 같은 규칙).
            "onetime_schedules": _se_onetime(parsed),
            **_engine_ctx(),
        }
        def classify_list(policies):
            result = []
            for p in (policies or []):
                sev = evaluate_severity(p, context)
                result.append({**p, **sev})
            return result

        from app.services.policy_renderer import build_view_model
        from app.services.reachability import detect_unreachable
        runtime_stats = app.config.get('last_runtime_stats', {})
        view = build_view_model(parsed, runtime_stats)
        return jsonify({
            # 어느 장비의 판정인지 응답이 스스로 말한다 — 화면이 대조할 수 있다.
            "device_id": app.config.get('device_id') or "",
            # 무엇을 근거로 판정했는지도 말한다 — 조치 계획이 이것과 대조한다.
            "basis": _judgement_basis(),
            "firewall": classify_list(view.get("firewall_policy", [])),
            "proxy":    classify_list(view.get("firewall_proxy_policy", [])),
            # 이번 분석에서 적용되지 않은 판정 규칙. export 시 Notes 시트로 실린다.
            "inactive_rules": describe_inactive_rules(app.config['profile']),
            # 정적 도달불가 검출. severity와 별개 축 — 등급을 바꾸지 않는다.
            "reachability": {
                **detect_unreachable(parsed, _fqdn_map(),
                                     _fqdn_source_vdom()),
                "fqdn_captured_at": _fqdn_captured_at(),
            },
        })

    # ── AI 분석 (Ollama/hermes3 로컬) ──────────────────────────────────────
    @app.get("/api/ai/status")
    def ai_status():
        available = check_ollama_available()
        return jsonify({"available": available, "model": "hermes3:latest"})

    @app.post("/api/ai/analyze")
    def ai_analyze():
        payload = request.get_json(silent=True) or {}
        policies = payload.get("policies", [])
        mode = payload.get("mode", "summary")   # "summary" | "single"
        model = payload.get("model", "hermes3:latest")
        try:
            if mode == "single" and policies:
                result = analyze_single_policy(policies[0], model)
            else:
                result = analyze_policies(policies, model)
            return jsonify({"result": result, "model": model})
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 503

    @app.post("/api/export/severity-workbook")
    def export_severity_workbook():
        gate = _license_required()
        if gate:
            return gate
        # 이 라우트는 **클라이언트가 보낸 판정**에 **서버가 들고 있는 문서정보**를
        # 붙인다. 둘이 다른 장비일 수 있다는 것이 문제다 — 실측: C 고객 판정을
        # B 고객이 열린 상태에서 보내면, 시트에는 C의 정책이, 문서정보에는 B의
        # hostname·SHA·고객사가 실린 감사 워크북이 200으로 나왔다(라운드 23).
        # 어느 장비의 판정인지 대게 하는 것은 before_request 가 강제한다.
        # config 없이 내려가는 '빈 감사 보고서'는 문서정보(SHA·장비)가 공란인
        # 채 형식만 갖춰서 더 위험하다(감사 C2). 다른 분석 라우트와 동일하게 막는다.
        if not app.config.get('last_parsed'):
            return jsonify({"error": "No config loaded. Upload a config file first."}), 400
        from app.services.workbook_exporter import build_severity_workbook
        payload = request.get_json(silent=True) or {}
        # **옛 기준으로 낸 판정에 지금 기준을 인쇄하면 안 된다.** 임계값을
        # 바꾸고 다시 판정한 뒤 **앞의** payload 를 내보내면, Assessment
        # criteria 는 새 임계값인데 Results 분포는 옛 판정이었다 — 경고 한 줄
        # 없이(7라운드 F5 실측: criteria 30/60/30 에 분포는 365 기준).
        # 재료는 이미 둘 다 있다: payload 의 `basis` 와 서버의 현재 지문.
        _sent_basis = str(payload.get("basis") or "")
        _now_basis = _judgement_basis()
        if _sent_basis and _sent_basis != _now_basis:
            return jsonify({
                "error": "These results were produced with different settings "
                         "than the ones in effect now, so the report would "
                         "state criteria that did not produce it. Run the "
                         "assessment again, then export.",
                "error_key": "stale_basis"}), 409
        # 문서 정보는 서버가 주입한다 — 감사 보고서는 "무엇을, 어떤 기준으로,
        # 언제 분석했나"를 스스로 증명해야 하고, 그 사실은 클라이언트가 아니라
        # 서버가 안다. config SHA-256이 있어야 "이 보고서는 그 설정 파일에
        # 대한 것"이라는 대응이 성립한다.
        import hashlib as _hashlib
        raw_cfg = app.config.get('last_raw_config') or ''
        meta = (app.config.get('last_parsed') or {}).get('meta', {})
        merged_ctx = _engine_ctx()
        payload["report_meta"] = {
            "apo_version": APO_VERSION,
            "generated_at": _dt.now().strftime("%Y-%m-%d %H:%M"),
            "hostname": meta.get("hostname") or "",
            "config_version": meta.get("config_version") or "",
            "buildno": meta.get("buildno") or "",
            "config_filename": app.config.get('last_config_filename') or "",
            # 파일에서 온 config는 업로드 때 계산한 **바이트 해시**를 쓴다.
            # 장비 수집분은 디스크에 파일이 없으므로 받은 텍스트로 낸다.
            "config_sha256": (app.config.get('last_config_sha256')
                              or (_hashlib.sha256(raw_cfg.encode("utf-8", "ignore")).hexdigest()
                                  if raw_cfg else "")),
            "profile": (app.config['profile'].get("meta") or {}).get("name", "default"),
            # **적용 중인 이식 기준 묶음의 식별자.** 룰 세트 기능은 이 값을
            # "감사 산출물에 박는다"고 선언해 놓고 정작 어디에도 싣지 않아,
            # 워크북을 받은 사람은 룰 세트라는 것이 있는 줄도 몰랐다
            # (2026-09-09 5렌즈 감사). 단, 이것은 **판정 지문이 아니다** —
            # 아래 임계값·대역·서비스 목록이 값으로 실리는 것이 재현 근거이고,
            # 이 해시는 "어느 기준 묶음을 적용했나"만 가리킨다(ruleset.py 참조).
            "ruleset_hash": ruleset_svc.ruleset_hash(
                ruleset_svc.canonical_ruleset(
                    _sanitize_thresholds(merged_ctx["thresholds"]),
                    _effective_object_rules(), _effective_ticket())),
            "thresholds": merged_ctx["thresholds"],
            "rules": merged_ctx["rules"],
            # 서비스 위험 목록도 판정을 가른다(위험 서비스만 / 위험+일반 혼합
            # → Critical). 배포 프로파일이 이 값을 덮어쓰므로, 없으면 이
            # 문서만으로 그 판정을 재현할 수 없다(게이트 spec 렌즈).
            "services": merged_ctx["services"],
            # 판정을 가르는 축인데 산출물에 값이 없었다 — 티켓 형식이 있으면
            # 그 정책은 sev 7 *Approved*, 없으면 sev 0 *Cannot assess* 다
            # (7라운드 F3). 임계값·대역과 같은 논리로 값과 출처를 함께 싣는다.
            "ticket_pattern": _ticket_effective()[0],
            "ticket_origin": _ticket_effective()[1],
            "user_range_count": len(app.config.get('user_ranges', [])),
            # **같은 판정을 재현하려면 값이 있어야 한다.** 개수만 적었더니,
            # 대역은 판정 축(S-U/S-S)인데 이 문서만으로는 같은 결과를 다시 낼
            # 수 없었다(라운드 43 지적). 실제 대역과 객체 명명 규칙을 싣는다.
            "user_ranges": [str(x.get("cidr") if isinstance(x, dict) else x)
                            for x in (app.config.get('user_ranges') or [])],
            "object_rules": {k: list(v) for k, v in
                             (_engine_ctx()["customer_rules"] or {}).items()
                             if k.endswith("_objects") and v},
            # 파서가 버린 것 — 정책이 빠지거나 겹쳤는데 감사 보고서가 침묵하면
            # 안 된다(라운드 43 지적: 유료 산출물 어디에도 없었다).
            "parse_warnings": list(
                (app.config.get('last_parsed') or {}).get("parse_warnings") or []),
            # 이 장비가 어느 고객사에 배정돼 있으면 문서가 스스로 말한다.
            **({"customer": _open_device_customer()}
               if _open_device_customer() else {}),
            # 종류별 dict는 비어 있어도 truthy다({"firewall":{},"proxy":{}}).
            # 실제 건수를 봐야 "사용량 데이터 있음"이 사실이 된다.
            "csv_loaded": _stats_count(app.config.get('last_runtime_stats')) > 0,
            # 사용량이 한 VDOM 것이면 문서정보가 그 한정을 말해야 한다 —
            # "loaded: yes" 만 적으면 전 장비 커버로 읽힌다(라운드 56 완성도
            # 렌즈. 배치 SUMMARY 는 라운드 55 에서 같은 규칙을 이미 받았다).
            **({"stats_vdom": str((app.config.get('last_runtime_stats') or {})
                                  .get("_vdom") or "")}
               if (app.config.get('last_runtime_stats') or {}).get("_vdom")
               else {}),
            # 어느 파일이 이 판정의 근거였는지 — 설정 파일과 같은 대우.
            "usage_sources": app.config.get('csv_meta') or [],
            # 장비 수집의 사용량 커버리지(라운드 70 R70-2) — 부분 절단이
            # "loaded: yes" 한 줄 뒤에 숨지 않게 한다.
            **({"collect_coverage": app.config.get('collect_coverage')}
               if app.config.get('collect_coverage') else {}),
        }
        # 이 장비의 고객사와 수신처가 맞을 때만 수신처를 싣는다 —
        # 안 그러면 베타 보고서 표지가 "for ACME Corp" 가 된다.
        _b = _branding_for()
        if _b:
            payload["report_meta"]["branding"] = _b
        try:
            xlsx_bytes = build_severity_workbook(payload)
        except Exception as exc:
            print(f"[APO] severity workbook export failed: {exc}", flush=True)
            return jsonify({"error": "Failed to build severity export"}), 400
        # **이 장비의 보고서라는 것이 파일명에 있어야 한다.** 모든 고객·모든
        # 장비가 severity_export.xlsx 하나로 떨어지면, 고객사 zip 에서 고친 것과
        # 똑같은 오배송 위험이 단일 조직 라이선스의 주 산출물에 그대로 남는다.
        _dev = (app.config.get('last_parsed') or {}).get("meta", {}).get("hostname") \
            or app.config.get('last_config_filename') or "device"
        # hostname 은 공장 기본값으로 남은 장비끼리 흔히 겹친다 — 장비 칩·zip
        # 엔트리와 같은 규칙으로 config 해시 앞자리를 붙여 갈라 놓는다.
        _sha8 = (app.config.get('last_config_sha256') or "")[:8]
        _name = f"apo_findings_{_dev}" + (f"_{_sha8}" if _sha8 else "") + ".xlsx"
        return app.response_class(
            response=xlsx_bytes,
            status=200,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={"Content-Disposition": _attachment(_name)}
        )

    # ── 일괄 보고 (MSP / Consultant 전용) ──────────────────────────────────
    # 장비별 config 묶음을 한 번에 분석해 장비당 워크북 하나씩 zip으로 준다.
    # 세션 상태(app.config의 last_parsed 등)는 읽지도 쓰지도 않는다 — 화면에서
    # 분석 중인 장비와 배치가 섞이면 교차 오염이다. 격리는 batch_report 모듈이
    # 보장하고, 여기서는 게이트·입출력만 다룬다.

    # ── 장비 보관소 · 고객사 ───────────────────────────────────────────────
    # 등록한 장비를 목록으로 들고, 고객사에 배정하고, 범위를 골라 리포트를 뽑는다.
    # 배정은 **보고서를 묶는 라벨**일 뿐 판정 입력이 아니다 — 어느 고객사에
    # 넣었느냐로 심각도가 달라지면 설명할 수 없는 도구가 된다.
    def _store():
        from app.services import device_store
        return device_store

    # 장비가 바뀔 때 반드시 끊어야 할 세션 키. **한 곳에만 적는다** — 경로마다
    # 따로 적었더니 업로드·Open 은 지우고 수집·삭제는 남기는 비대칭이 생겼고,
    # 그 틈으로 B 장비를 보면서 고른 정책이 A 장비에서 비활성화됐다(라운드 15
    # 실측: 화면은 B인데 disable 명령의 목적지는 10.0.0.1 = A).
    # thresholds_override 는 뺀다 — 임계값은 컨설턴트의 감사 기준이라 장비 간
    # 공유가 설계다(일괄 보고와 같은 규칙).
    # csv_meta 도 여기 속한다 — 사용량의 출처는 그 장비의 것이다. 빼 놨더니
    # 수집으로 장비를 바꾼 뒤 만든 워크북에 **앞 고객의 CSV 파일명과 해시**가
    # '이 판정의 근거'로 찍혔다(라운드 20 실측). 같은 함수가 config 해시는
    # 버리면서 그 형제만 남긴 셈이었다.
    # last_export_name 도 여기 속한다 — 그 산출물은 그 설정의 것이고, 장비가
    # 바뀌면 예전 링크는 더 이상 '지금 보는 것'이 아니다.
    # object_rules 도 여기 속한다. 이걸 빠뜨렸더니 `/api/collect/device` 가
    # 앞 고객의 명명 규칙을 그대로 들고 갔고, 고객 B 정책이 고객 A 의 이름으로
    # 예외를 받아 등급이 6 으로 내려갔다(라운드 44 실측). 장비를 바꾸는 경로가
    # 다섯인데 그중 하나만 빠져도 새어 나간다 — 그래서 이 목록이 있다.
    _DEVICE_SCOPED_KEYS = ('fqdn_cache', 'collect_device', 'remediation_device',
                           'collect_coverage',
                           'last_audit_timeline', 'csv_meta', 'last_export_name',
                           'object_rules',
                           # 장비 이관의 **대상** 백업. 이것이 남으면 소스를
                           # 갈아끼워도 옛 대상이 살아 있어, 사용자가 한 번도
                           # 본 적 없는 장비 쌍으로 파일이 만들어진다.
                           'target_raw_config')

    def _drop_previous_device_traces():
        for _k in _DEVICE_SCOPED_KEYS:
            app.config.pop(_k, None)

    def _device_session() -> dict:
        """**지금 열려 있는 장비의 전부.**

        장비가 바뀔 때 화면이 맞춰야 할 상태가 여러 곳에 흩어져 있었고, 새
        상태가 늘 때마다 어느 한 경로가 그걸 빠뜨렸다 — 라운드 19~21의 결함이
        전부 여기서 나왔다(사용량 출처가 앞 고객 것으로 남고, 대역 칩이 앞
        고객 것으로 남아 마법사가 그대로 저장했다). 그래서 **한 덩어리로**
        만들어 장비를 바꾸는 모든 응답이 이걸 싣는다. 화면도 한 함수로 받는다.
        새 상태가 생기면 여기 한 곳만 고치면 된다.
        """
        # 담는 것은 **화면이 실제로 쓰는 것만**. 안 쓰는 필드를 실어 두면
        # '한 덩어리로 주고받는다'는 말이 절반만 참이 되고, 다음에 필드가
        # 늘었을 때 화면이 조용히 무시하는 같은 실패가 되풀이된다.
        return {
            "device_id": app.config.get('device_id') or "",
            "device_name": (app.config.get('last_parsed') or {})
                           .get("meta", {}).get("hostname")
                           or app.config.get('last_config_filename') or "",
            # 여러 고객사를 다루는 도구에서 '이게 누구 장비인가'는 장비명만큼
            # 중요한 사실이다 — 자동 이어받기로 열린 아침에 특히 그렇다.
            "customer": _open_device_customer(),
            # 등록된 설정 파일명 — 화면의 '설정 파일' 슬롯이 이걸 말해야 한다.
            # 안 그러면 Config 칩은 초록인데 바로 옆 슬롯은 'No file selected'
            # 라고 해서, 한 화면 두 곳이 반대로 말한다(라운드 23 지적).
            "filename": app.config.get('last_config_filename') or "",
            "user_ranges": app.config.get('user_ranges') or [],
            "csv_meta": app.config.get('csv_meta') or [],
            "runtime_stats": app.config.get('last_runtime_stats') or {},
            "has_fqdn": bool(app.config.get('fqdn_cache')),
            # 감사 타임라인은 장비가 바뀌면 서버가 버린다. 화면이 그 사실을
            # 모르면 표와 내보내기 버튼을 그대로 두고, 누르면 400이 난다.
            "has_audit_timeline": bool(app.config.get('last_audit_timeline')),
        }

    # ── 장비 게이트: **기본 차단** ──────────────────────────────────────
    # 라우트마다 게이트를 '달아야' 하는 구조에서는 매 라운드 하나씩 빠졌다
    # (대역→CSV→붙여넣기→FQDN→판정→후보목록→조치적용…). 빠뜨리면 열리기
    # 때문이다. 여기서 뒤집는다 — /api/* 는 기본이 게이트이고, 면제는 아래
    # 이름 목록으로만 가능하다. 새 라우트를 빠뜨리면 **닫힌다**: 화면이 바로
    # 막히므로 눈에 띄고, 조용히 남의 고객 데이터가 새지 않는다.
    #
    # 면제 사유는 세 가지뿐이다:
    #   (a) 장비와 무관(라이선스·프로파일·고객사·AI·정적 파일)
    #   (b) 장비를 **바꾸는** 진입점 — 스스로 device_id 를 정한다
    #   (c) 요청이 대상을 직접 지목한다(경로 파라미터·scope+id·업로드 파일)
    _GATE_EXEMPT = frozenset({
        # (a) 장비와 무관
        "index", "static", "version_endpoint", "get_profile", "ai_status",
        "ai_analyze", "license_status", "license_activate",
        "report_branding_get", "report_branding_set", "sample_report",
        "customer_add", "customer_rename", "customer_delete",
        # (b) 장비를 바꾸는 진입점
        "parse_config", "device_open", "device_delete", "collect_device",
        # (c) 대상을 직접 지목
        "devices_list", "device_assign", "reports_scope", "batch_export",
        "api_config_diff", "api_config_diff_export", "render_policies",
        # diff 내보내기의 면제 근거: **비교 결과도 파일 이름도 요청이 올린 두
        # 파일에서만 나온다.** 열린 장비(`device_id`·`last_parsed`·`_engine_ctx`)
        # 를 읽지도 바꾸지도 않는다 — 라운드 45 에서 장비를 열어 둔 채 내보내
        # 실측 확인했다(파일명·내용·app.config 모두 불변).
        #
        # **다만 '요청에서만'은 절반만 참이다.** 화이트라벨 브랜딩(회사·수신처)
        # 은 서버 전역 상태(`data/branding.json`)에서 오고, 다른 창이 언제든
        # 바꿀 수 있다 — C 고객 백업을 비교한 문서가 B 고객 이름으로 서명될 수
        # 있다. 장비 데이터가 새지는 않지만 귀속은 갈릴 수 있으므로, 근거를
        # 사실대로 적어 둔다(라운드 45 지적).
        # verification_score 는 면제에서 뺐다. 재설계 후 이 핸들러는
        # 폼의 device_id 를 대상 결정에 쓰지 않는다 — 채점 대상은
        # 전적으로 열린 세션이다. '요청이 대상을 지목한다'는 면제
        # 근거가 사라졌으므로 게이트 안으로 되돌린다.
        # serve_export 는 여기 없다 — /api/ 밖이라 이 후크가 닿지 않는데,
        # 목록에 적어 두면 '검토해서 면제했다'는 뜻이 되어 사실과 다르다.
        # (그 라우트는 요청이 파일 stem 으로 대상을 지목하고, 경로 탈출은
        #  따로 막혀 있다.)
        #
        # 워크북·조치 CSV 내보내기는 **면제에서 뺐다**. 산출물
        # 이름에 '지금 열린 장비'를 찍기 시작한 순간, 내용은 요청이 주고
        # 이름은 세션이 주는 두 출처가 갈렸다 — 다른 창이 장비를 바꾼 뒤
        # 오래된 탭에서 내보내면 ACME 행이 담긴 파일이 BETA 이름으로 떨어졌고
        # (라운드 26 실측), 200 이라 화면은 아무 말도 하지 않았다. 이름을 붙일
        # 것이면 대상을 대야 한다.
        #
        # **export_ruleset 도 같은 이유로 면제가 아니다**(2026-09-09 재비판).
        # 한때 "get_profile 과 같다"는 근거로 면제였으나 그 비유가 틀렸다 —
        # get_profile 은 customer_rules 를 **일부러 빼고** 주는데,
        # export_ruleset 은 `_effective_object_rules()` 로 **열린 장비의 고객
        # 자산명**을 싣는다. 실측: A 를 명시(`?device_id=A`)해도 B 가 열려 있으면
        # B 고객의 자산명이 200 으로 나갔다(같은 상황에서 object-rules/set 은 409).
        # 게다가 파일명에 deviceStamp() 를 붙인 뒤라 라운드 26 의 전제조건이
        # 그대로 되살아났다 — 내용은 B, 이름은 A.
    })

    @app.before_request
    def _gate_device_scoped_requests():
        if not request.path.startswith("/api/"):
            return None
        if (request.endpoint or "").rsplit(".", 1)[-1] in _GATE_EXEMPT:
            return None
        return _device_gate(what="request")

    def _fqdn_map():
        """도달불가 판정에 넘길 **FQDN 이름→IP 표**.

        `app.config['fqdn_cache']` 는 `{"map": {...}, "captured_at": ...}` 라는
        **껍데기**다. `detect_unreachable` 은 안쪽 `map` 을 받아야 하는데,
        화면·워크북 경로만 `.get("map")` 을 하고 조치 후보 경로와 **되돌릴 수
        없는 쓰기를 막는 보류 판정**은 껍데기를 통째로 넘기고 있었다. 그러면
        모든 FQDN 조회가 빗나가는데 `capture_used` 는 여전히 True 라,
        **아무도 눈치채지 못한다**(라운드 48 실측).
        
        결과: 워크북은 "정책 1을 먼저 처리하고 백업을 다시 뜨라"며 명령을
        **일부러 비워** 내보내는데, 같은 세션의 조치 적용은 200 을 돌려주며
        그 정책에 `set status disable` PUT 을 실제 방화벽으로 보냈다.
        되돌릴 방법은 이 도구에 없다.

        그래서 꺼내는 곳을 **하나로 만든다** — 이 값은 네 곳에서 쓰이고,
        세 라운드 동안 한 곳을 고치면 다른 곳이 남았다.
        """
        return (app.config.get('fqdn_cache') or {}).get("map")

    def _fqdn_captured_at():
        return (app.config.get('fqdn_cache') or {}).get("captured_at")

    def _fqdn_source_vdom():
        # 이 스냅샷이 어느 VDOM 의 해석인가(수집 스코프). "" = 전역/덤프/미상.
        # v108 부터 수집이 VDOM 스코프로 조회하므로 적용부(gated_fqdn_names)
        # 가 이 사실을 알아야 한다 — 라운드 70, Jayden 승인.
        return str((app.config.get('fqdn_cache') or {})
                   .get("source_vdom") or "").strip()

    def _open_device_label() -> str:
        """산출물 파일명에 넣을 장비 표시 — 이름 + config 해시 앞자리.

        hostname 은 공장 기본값으로 겹치므로 해시를 함께 붙인다(장비 칩·zip
        엔트리와 같은 규칙). 이게 없으면 고객사 2곳 장비 3대를 도는 컨설턴트의
        내려받기 폴더에 같은 이름 파일이 (1),(2)로 쌓이고, 정책 번호 1·2·3은
        어느 FortiGate에나 있어 섞이면 구분할 방법이 없다(라운드 25 지적).
        """
        name = ((app.config.get('last_parsed') or {})
                .get("meta", {}).get("hostname")
                or app.config.get('last_config_filename') or "device")
        sha8 = (app.config.get('last_config_sha256') or "")[:8]
        return f"{name}_{sha8}" if sha8 else str(name)

    # 공장 기본 hostname — 이름이 같아도 **다른 장비일 수 있다**. FortiGate 는
    # 이름을 바꾸지 않으면 모델명으로 남고, `show` 는 기본값을 아예 출력하지
    # 않아 설정 파일에 hostname 줄이 없기도 하다. 그 두 경우에 이름 대조는
    # 신원 증명이 아니라 '증명한 척'이다 — 이 파일 자신이 다른 자리에서 같은
    # 이유로 hostname 을 장비 식별자로 쓰지 말라고 적어 두었다.
    # **목록을 두 번 만들었고 두 번 다 반쪽이었다.**
    #   1차: 'fortigate' 계열 정규식 → FortiWiFi-60D, FortiGate-3000D-POE,
    #        FortiGateRugged-60D 가 빠져나가 남의 방화벽에 정책 6건 발사
    #   2차: 접미사 목록(poe/dsl/kvm/aws…) → FortiGate-VM64-AWSONDEMAND,
    #        -OPC, -HYPERV, -VMWARE, -ALI, -IBM, -NUTANIX, FortiGate-VMX,
    #        -100F-BDL, -1800F-DC 가 빠져나가 **또** 발사됐다(라운드 28 실측:
    #        고객 B 장비에 PUT 3건, 고객 A 토큰까지 그쪽으로 전송)
    # 목록을 고칠 때마다 다음 목록 밖이 생긴다. 3차로 '목록을 없앤다'며
    #   'Forti 로 시작하면 인정하지 않는다'
    # 로 바꿨는데, 그건 **항목이 하나인 목록**이었다. 라운드 29 실측: FGT-HQ,
    # fw01, firewall, 시리얼형 기본값(FGT60FTK…), FMG-VM64, 전각·키릴 유사문자
    # 등 18종 중 12종이 identity=match 로 통과해 고객 B 장비에 PUT 이 나갔다.
    # MSP 표준 명명(FGT-HQ/fw01)은 두 고객이 함께 쓰는 것이 오히려 정상이다.
    #
    # **그래서 이름으로 추측하는 것을 그만둔다.** 이 파일이 세 라운드 동안
    # 반복해 적은 결론이 정답이었다 — hostname 은 장비 식별자가 아니다.
    # FortiGate 는 /monitor/system/status 에서 **시리얼**을 준다. 그것을 이
    # 장비의 신원으로 고정(pin)하고, 다음부터는 시리얼로 대조한다:
    #
    #   · 고정된 시리얼이 있고 같다        → match      (진짜 증명)
    #   · 고정된 시리얼이 있고 다르다      → mismatch   (이름과 무관하게 차단)
    #   · 고정된 시리얼이 없다             → unverifiable(첫 연결) — 막지 않고
    #                                        사용자 확인을 받은 뒤 고정한다
    #   · 이름이 서로 다르다               → mismatch   (값싼 조기 차단)
    #
    # 첫 적용 때 확인 한 번이 대가다. 그 뒤로는 IP 오타가 이름과 상관없이
    # 잡힌다 — 이름 heuristic 으로는 영영 못 하던 일이다.
    def _pinned_serial() -> tuple[str, str]:
        """**이 프로파일에서** 전에 확인한 시리얼. ("", "") = 없음.

        라운드 30에서 '새 백업마다 확인 창이 다시 뜬다'를 고치려고 같은
        hostname 의 다른 프로파일 pin 도 가져다 썼다. 그건 **이름으로 신원을
        증명한 것**이었고, 이 루프가 네 라운드 동안 하지 말라고 적어 온 바로
        그 짓이다. 결과(라운드 31 실측): 고객 A 와 B 가 둘 다 'FGT-HQ' 이면
          · A 가 IP 오타로 B 방화벽에 붙으면 B 의 pin 을 빌려 identity=match →
            **확인 창 없이** B 에 PUT 2건이 나갔다(그전에는 409 였다)
          · A 가 자기 방화벽에 붙으면 B 의 시리얼을 근거로 영구 차단되고,
            그 시리얼이 A 화면에 노출됐다
        확인 창을 없애야 할 자리에서 없애고, 있어야 할 자리에 만든 셈이다.

        그래서 **판정 근거는 이 프로파일의 pin 하나뿐이다.** 새 백업마다 확인을
        한 번 더 받는 것은 대가로 받아들인다 — 대신 그 확인 창이 **시리얼을**
        보여준다. 전에 그 시리얼을 확인한 프로파일 이름을 곁들이는 것도 해
        봤지만(라운드 31), 그 이름이 남의 고객 것일 수 있고 하필 두 고객이 같은
        이름을 쓸 때 안심시켜서 뺐다(라운드 32). 판단은 사람이 한다.
        """
        did = app.config.get('device_id')
        if not did:
            return "", ""
        try:
            own = (_store().get_device(did) or {}).get("remediation_serial")
            if own:
                return str(own), "this_device"
        except Exception:
            return "", ""
        return "", ""

    # `_serial_seen_before` 는 **뺐다.** 새 백업마다 확인을 다시 받는 부담을
    # 줄이려고 '이 시리얼을 전에 X 에서 확인했다'를 확인 창에 곁들였는데,
    # 라운드 32 실측에서 둘 다 사실로 드러났다:
    #   · 그 X 가 **다른 고객의 프로파일 이름(또는 백업 파일명)** 이라, 남의
    #     고객 이름이 이쪽 화면에 떴다
    #   · 하필 두 고객이 같은 이름을 쓸 때 "전에 확인한 그 장비"처럼 읽혀,
    #     **사고가 나는 바로 그 경우에 안심시켰다**
    # 판정에서 이름을 뺀 자리를, 사람이 판단하는 자리에 되돌려 놓은 것이다.
    # 확인 창은 시리얼만 보여주고 판단은 사람에게 맡긴다.

    def _remediation_identity() -> dict:
        """연결된 장비가 지금 열어 둔 설정의 장비인가 — 네 가지로 답한다.

        match        고정된 시리얼과 같다(진짜 증명)
        mismatch     시리얼이 다르거나 이름이 다르다 → 보낼 수 없다
        untested     연결 확인을 아직 안 했다 → 확인부터
        unverifiable 아직 이 장비의 시리얼을 모른다 → 막지는 않되, **모른다는
                     사실을 말하고** 사용자가 대상을 직접 확인하게 한다
        """
        dev = app.config.get('remediation_device') or {}
        raw_connected = (dev.get("connected_hostname") or "").strip()
        connected_serial = (dev.get("connected_serial") or "").strip()
        raw_opened = ((app.config.get('last_parsed') or {})
                      .get("meta", {}).get("hostname") or "").strip()
        # 시리얼이 비었을 때의 사유. "failed" 면 장비가 안 준 게 아니라
        # 조회가 끝나지 못한 것이다 — 판정은 같아도 **할 말이 다르다**(R75-1).
        serial_unread = (str(dev.get("connected_serial_probe") or "answered")
                         == "failed")
        out = {"connected": raw_connected, "config": raw_opened,
               "serial": connected_serial}
        if not raw_connected and not connected_serial:
            return {**out, "verdict": "untested"}
        # 이름이 서로 다르면 시리얼을 보기 전에 막는다 — 값싸고 확실하다.
        if raw_opened and raw_connected and raw_connected.lower() != raw_opened.lower():
            return {**out, "verdict": "mismatch"}
        pinned, basis = _pinned_serial()
        if pinned:
            out["pinned"] = pinned
            out["pin_basis"] = basis
            if not connected_serial:
                # **'모름'으로 강등하면 안 된다.** 이미 확인해 둔 장비인데 지금
                # 붙은 쪽이 시리얼을 말하지 않는다 — 그건 덜 의심스러운 게
                # 아니라 **더** 의심스럽다. 강등해 두는 바람에 확인 한 번으로
                # 남의 방화벽에 PUT 이 나갔다(라운드 30 실측).
                # 조회가 끝나지 못한 경우도 **막는 것은 같다**(fail-closed).
                # 다만 "이 장비는 시리얼을 안 준다"고 단정하지는 않는다.
                return {**out, "verdict": "mismatch",
                        "why": ("serial_unread_but_pinned" if serial_unread
                                else "serial_missing_but_pinned")}
            if pinned == connected_serial:
                return {**out, "verdict": "match"}
            # **이름이 같아도 다른 장비다.** 이것이 이름으로는 못 하던 판정이다.
            return {**out, "verdict": "mismatch", "why": "serial_mismatch"}
        if not connected_serial:
            return {**out, "verdict": "unverifiable",
                    "why": "serial_unread" if serial_unread else "no_serial"}
        return {**out, "verdict": "unverifiable", "why": "not_pinned_yet"}

    def _pinned_tls_fp() -> str:
        """이 프로파일에서 전에 본 인증서 지문. "" = 없음."""
        did = app.config.get('device_id')
        if not did:
            return ""
        try:
            return str((_store().get_device(did) or {}).get("tls_fingerprint") or "")
        except Exception:
            return ""

    def _tls_pin_check(res: dict) -> dict:
        """인증서 지문 TOFU 판정 (B-79). 응답에 얹을 필드를 돌려준다.

        검증을 켠 장비에는 관여하지 않는다 — CA 가 이미 답을 줬다.
        처음 보는 지문은 **고정하고 알린다**(사용자가 장비에서 대조할 수
        있게 지문을 보여준다). 고정된 값과 다르면 **막는다** — 자체 서명
        인증서가 바뀌는 것은 장비 교체 아니면 중간자다.
        """
        dev = app.config.get('remediation_device') or {}
        if not res.get("ok") or dev.get("tls_verified"):
            return {}
        now = str(dev.get("connected_tls_fp") or "")
        if not now:
            # 지문을 못 읽었다 — 판정하지 않는다. 시리얼과 같은 규칙으로
            # '못 읽었다'와 '없다'를 뭉개지 않는다(R75-1).
            return {"tls_pin": "unknown"}
        pinned = _pinned_tls_fp()
        if not pinned:
            did = app.config.get('device_id')
            if did:
                try:
                    _store().update_device_inputs(did, tls_fingerprint=now)
                except Exception as exc:
                    print(f"[APO] could not pin TLS fingerprint: {exc!r}", flush=True)
            return {"tls_pin": "new", "tls_fingerprint": now}
        if pinned != now:
            return {"tls_pin": "changed", "tls_fingerprint": now,
                    "tls_pinned": pinned}
        return {"tls_pin": "match", "tls_fingerprint": now}

    def _tls_pin_refusal():
        """적용 직전 게이트. 막아야 하면 (본문, 상태코드), 아니면 None.

        **되돌릴 수 없는 쓰기 앞에서만 막는다.** 읽기까지 막으면 자체 서명
        장비에서 아무것도 못 보게 되고, 그건 이 기능이 지키려는 것보다 큰
        손해다(라운드 26 의 '시킨 대로 해도 안 되는' 상태).
        """
        dev = app.config.get('remediation_device') or {}
        if dev.get("tls_verified"):
            return None
        now = str(dev.get("connected_tls_fp") or "")
        pinned = _pinned_tls_fp()
        if pinned and now and pinned != now:
            return (jsonify({
                "error": "The certificate at this address changed since APO "
                         "last connected. On a channel without certificate "
                         "verification that is what a man-in-the-middle looks "
                         "like, and this request would carry your FortiGate "
                         "admin token. If the device was genuinely replaced or "
                         "re-keyed, remove and register it again.",
                "error_key": "tls_fingerprint_changed",
                "identity": "mismatch", "why": "tls_fingerprint_changed",
                "connected_fingerprint": now, "expected_fingerprint": pinned}), 409)
        return None

    def _remediation_hostname_matches() -> bool | None:
        """옛 이름 — True/False/None 만 필요한 곳(화면 표시)이 쓴다."""
        v = _remediation_identity()["verdict"]
        return {"match": True, "mismatch": False}.get(v)

    def _branding_for(customer: str = None) -> dict:
        """이 산출물에 실을 브랜딩. **수신처는 대상이 맞을 때만 싣는다.**

        `prepared_for`(수신처)는 세션에 하나뿐인 전역 값인데, MSP 는 고객사를
        옮겨 다니며 같은 세션에서 여러 장비를 내보낸다. 그래서 베타 주식회사
        장비의 보고서 표지에 `for ACME Corp` 가 찍혔고, **같은 시트 안에서
        Customer 칸(베타)과 정면으로 모순**했다 — 베타에게 ACME 도 이 MSP 의
        고객이라는 사실까지 알려 준다(라운드 47 실측).

        배치 경로에는 이미 같은 가드가 있었다(`scope != "device"` 면 회사명만).
        단일 장비 경로 네 곳에 없었을 뿐이다 — 규칙은 하나인데 경로마다 적으면
        한 곳이 빠진다는 이 루프의 결론이 또 재현됐다.

        회사명(자기 브랜드)은 어느 고객 보고서에나 참이므로 유지한다.
        """
        if not _branding_allowed():
            return {}
        b = _load_branding() or {}
        if not b.get("company"):
            return {}
        target = _open_device_customer() if customer is None else customer
        want = str(b.get("prepared_for") or "").strip()
        if want and target and want.casefold() == str(target).strip().casefold():
            return {"company": b["company"], "prepared_for": want}
        return {"company": b["company"]}

    def _open_device_customer() -> str:
        """지금 열린 장비가 배정된 고객사명(없으면 빈 문자열)."""
        did = app.config.get('device_id')
        if not did:
            return ""
        try:
            d = _store().get_device(did) or {}
            if not d.get("customer_id"):
                return ""
            for c in _store().list_customers():
                if c["id"] == d["customer_id"]:
                    return c["name"]
        except Exception:
            return ""
        return ""

    def _claimed_device():
        """요청이 대는 장비 id — 쿼리·JSON·폼 어디에 있든 같은 규칙으로 읽는다.

        라우트마다 어디서 읽을지 따로 정하면 그중 하나가 틀리고, 그 하나가
        게이트를 무력화한다(이 루프에서 반복 확인된 실패 모드다).
        """
        v = request.args.get("device_id")
        if not v and request.is_json:
            # **JSON 본문이 딕셔너리가 아닐 수 있다.** `[1,2]`·`"x"`·`3` 도
            # 유효한 JSON 이라 `silent=True` 를 통과하는데, 거기에 `.get()` 을
            # 부르면 AttributeError 로 500 이 난다. 이 게이트는 before_request
            # 라서 **모든 게이트 라우트가 함께 500** 이 된다(실측).
            _body = request.get_json(silent=True)
            v = _body.get("device_id") if isinstance(_body, dict) else None
        if not v:
            v = request.form.get("device_id")
        return str(v).strip() if isinstance(v, (str, int)) and str(v).strip() else v

    def _device_gate(claimed=_UNSET, *, what):
        """판정 입력을 쓰는 요청은 **어느 장비의 것인지 대야 한다**.

        None을 돌려주면 통과, 아니면 그대로 응답한다. 이 규칙을 경로마다 따로
        적었더니 매번 한 곳이 빠졌다 — 대역·CSV·사용량 삭제를 통일한 다음
        라운드에 FQDN 이 같은 이유로 남아 있었다(라운드 18 실측: 두 탭에서
        A고객 DNS 스냅샷이 B고객 장비 행을 덮어써, B의 정책이 A의 해석으로
        '가려짐' 증명을 받았다). 규칙은 한 곳에만 적는다.
        """
        if claimed is _UNSET:
            claimed = _claimed_device()
        open_id = app.config.get('device_id')
        if not open_id:
            # 열린 장비가 없는데 특정 장비를 대면, 화면은 그 장비에 저장했다고
            # 믿지만 아무것도 저장되지 않는다. 200을 돌려주면 그 어긋남이
            # 사용자에게 보이지 않는다.
            if claimed:
                return jsonify({
                    "error": "No device is open, so that input has nowhere to go. "
                             "Open the device first.",
                    "open_device_id": None}), 409
            return None
        if (claimed or None) != open_id:
            # **두 상황을 구분해 말한다.** 하나로 뭉뚱그렸더니, 장비를 대지
            # 않았을 뿐인 요청에도 '다른 장비가 열려 있는 동안 입력했다'고
            # 답했다 — 사용자가 하지도 않은 일을 했다고 말하는 셈이다.
            if not claimed:
                return jsonify({
                    "error": f"This {what} did not say which device it is for. "
                             "APO only applies input to the device you have open.",
                    "error_key": "input_no_device", "what": what,
                    "open_device_id": open_id}), 409
            return jsonify({
                "error": f"That {what} was entered while a different device was "
                         "open. Reopen the device you meant, then try again.",
                "error_key": "input_other_device", "what": what,
                "open_device_id": open_id}), 409
        return None

    def _stats_to_csv(stats: dict) -> str:
        """보관된 통계를 CSV로 되돌린다 — 배치 엔진의 입력 형식이 CSV이므로,
        보관소와 파일 경로가 같은 파서를 지나게 해 규칙이 갈라지지 않는다.

        **파서가 읽는 컬럼은 전부 되돌려야 한다.** Status를 빠뜨렸더니 화면에서
        Disabled 로 보이던 정책이 리포트에서는 config 상태로 되돌아가 Critical 로
        승격됐다(라운드 14 실측: 12건 중 10건의 판정 사유가 바뀜). 같은 장비·같은
        CSV인데 화면과 산출물의 판정이 다르면 어느 쪽도 믿을 수 없다.

        직접 join 하지 않고 csv 모듈로 쓴다 — 값에 쉼표·따옴표·개행이 들어가면
        컬럼이 밀려 다른 정책의 hit count 가 붙는다.
        """
        import csv as _csv
        from io import StringIO
        buf = StringIO(newline="")
        writer = _csv.writer(buf, lineterminator="\n")
        writer.writerow(["Policy ID", "Hit Count", "Last Used", "Status", "Name"])
        for pid, row in (stats or {}).items():
            # Policy ID 가 'firewall'/'proxy' 인 CSV 한 줄이면 통계가 종류별로
            # 오인돼 row 가 dict 가 아닐 수 있다. 여기서 터지면 그 예외는
            # build_batch_zip 의 '장비 하나 실패는 그 장비만 실패' 설계 밖이라
            # **범위 안의 모든 장비 리포트가 함께 죽는다**.
            if not isinstance(row, dict):
                continue
            row = row or {}
            # hit_count 는 None(CSV 미로드)과 0(실제 0회)을 구분해야 한다.
            hit = row.get("hit_count")
            writer.writerow([pid, "" if hit is None else hit,
                             row.get("last_used") or "", row.get("status") or "",
                             row.get("csv_name") or ""])
        return buf.getvalue()

    @app.get("/api/devices")
    def devices_list():
        # **보관소를 못 읽는 것과 보관소가 빈 것은 다르다.** 예전에는 여기서
        # 예외가 나면 500 이 되고 화면은 조용히 '아직 아무것도 없습니다'를
        # 띄웠다 — 121대·고객사·확인된 시리얼이 들어 있는 DB 가 손상됐을 때
        # 사용자는 데이터가 사라졌다고 판단해 그 파일을 지우거나 전부 다시
        # 입력하게 된다(라운드 41 실측). 복구 가능한 것을 잃게 만드는 안내다.
        try:
            _store().list_devices()
        except Exception as exc:
            print(f"[APO] device store unreadable: {exc!r}", flush=True)
            return jsonify({
                "error": "APO could not read its device store "
                         f"({_store().store_path().name}). Your devices are "
                         "not gone from this screen because they were deleted "
                         "— the file could not be opened. Close any other copy "
                         "of APO that may be running, then restart. Do not "
                         "delete that file: it holds your devices, customers "
                         "and saved inputs.",
                "error_key": "store_unreadable", "store_error": True,
                # 화면이 같은 문장을 만들려면 파일 이름이 값으로 와야 한다.
                "file": _store().store_path().name}), 503
        return jsonify({"devices": _store().list_devices(),
                        "customers": _store().list_customers(),
                        "open_device_id": app.config.get('device_id'),
                        # 앱을 다시 켠 직후에는 열린 장비가 없다 — 그때 이어받을
                        # 후보를 알려 준다. 화면이 '등록된 것이 없다'고 말하는데
                        # 보관소에는 장비가 들어 있는 상태를 없앤다.
                        "resume_device_id": (app.config.get('device_id')
                                             or _store().most_recent_device_id())})

    @app.post("/api/devices/<device_id>/open")
    def device_open(device_id):
        """보관된 장비를 화면으로 불러온다 — 이 장비의 입력만 실린다."""
        # **읽기도 감싼다.** 읽기전용 파일은 *읽기* 는 되므로 8라운드 검증이
        # 이 구멍을 못 봤다 — 파일이 **손상**되면 여기서 터진다(9라운드 F4).
        try:
            d = _store().get_device(device_id)
        except Exception as exc:
            return _store_broken(exc)
        if not d:
            return jsonify({"error": "No such device"}), 404
        # **보관소 쓰기를 맨 앞으로 옮긴다.** 맨 뒤에 두었더니, 쓰기가 실패할 때
        # `app.config` 는 이미 이 장비로 다 바뀐 뒤였다 — **서버는 열렸다고
        # 믿고 브라우저는 아무것도 안 열렸다고 믿는** 상태가 된다. 그리고
        # 첫 화면의 자동 복원이 이 경로를 타므로, 장비 7대가 멀쩡히 있는데
        # 화면은 "불러온 설정이 없습니다" 라고 말했다(8라운드 발견 4 실측).
        # 여는 것도 '만지는' 것이라 이 기록 자체가 세션의 일부다.
        try:
            _store().touch_device(device_id)
        except Exception as exc:
            return _store_broken(exc)
        parsed = FortiGateConfigParser(d["config_text"]).parse()
        app.config['last_parsed'] = parsed
        app.config['last_raw_config'] = d["config_text"]
        app.config['last_config_sha256'] = d.get("config_sha256") or ""
        # 직전에 열었던 장비의 값이 남으면 유령 차단이 뜬다 — 항상 덮어쓴다.
        app.config['last_config_decode_lost'] = int(d.get("decode_lost") or 0)
        app.config['last_config_filename'] = d.get("config_filename") or ""
        app.config['last_runtime_stats'] = d.get("runtime_stats") or {}
        app.config['user_ranges'] = d.get("user_ranges") or []
        app.config['device_id'] = device_id
        # 다른 장비의 흔적은 반드시 끊는다. collect_device를 남기면 이 장비를
        # 보면서 누른 조치 명령이 **직전에 연결한 장비로** 나간다.
        _drop_previous_device_traces()
        # 비운 **뒤에** 이 장비의 객체 명명 규칙을 되살린다
        app.config['object_rules'] = _normalize_object_rules(d.get("object_rules"))
        if d.get("fqdn_cache"):
            app.config['fqdn_cache'] = d["fqdn_cache"]
        app.config['collect_coverage'] = d.get("collect_coverage") or {}
        app.config['csv_meta'] = d.get("csv_meta") or []
        # 여는 것도 '만지는' 것이다 — 이걸 기록하지 않으면 열어서 판정하고
        # 리포트만 뽑은 세션이 남지 않아, 다음에 앱을 켤 때 엉뚱한 장비가 열린다.
        view = build_view_model(parsed, app.config['last_runtime_stats'])
        return jsonify({"ok": True, "device_id": device_id,
                        "csv_meta": app.config['csv_meta'],
                        "device_name": d.get("name") or "",
                        "filename": d.get("config_filename") or "",
                        "config_sha": _config_sha(d["config_text"]),
                        "runtime_stats": app.config['last_runtime_stats'],
                        # **화면이 이 값으로 "CSV 를 올리세요" 를 정한다.**
                        # 안 보내면 사용량이 12행 있는데도 슬롯이 "올리세요"
                        # 라고 말한다 — 칩은 초록, 요약은 파일명·행수까지
                        # 적혀 있는 채로(7라운드 F5 실측). 파싱 응답은 이미
                        # 보내는데 장비 열기 응답만 빠져 있었고, 그래서
                        # 열기·전환·복원·충돌복구 네 경로가 전부 그랬다.
                        "stats_count": _stats_count(
                            app.config['last_runtime_stats']),
                        "user_ranges": app.config['user_ranges'],
                        "session": _device_session(),
                        "parsed": parsed, "view": view})

    def _device_files(dev: dict) -> list:
        """이 장비 때문에 디스크에 생긴 파일들.

        업로드 원본과 파싱 산출물은 그 고객의 정책 전문을 담고 있다. 장비를
        지울 때 함께 지워야 확인창 문구가 사실이 된다.
        """
        out = []
        fn = dev.get("config_filename")
        if fn:
            out.append(IMPORT_DIR / fn)
        sha8 = (dev.get("config_sha256") or "")[:8]
        if fn and sha8:
            out.append(EXPORT_DIR / f"{Path(fn).stem}_{sha8}.parsed.json")
        return [p for p in out if p.exists()]

    @app.delete("/api/devices/<device_id>")
    def device_delete(device_id):
        # 없는 장비를 지웠는데 성공을 돌려주면 화면이 일어나지 않은 삭제를
        # 보고한다 — 다른 탭에서 이미 지운 경우가 정확히 그 상황이다.
        _dev = _store().get_device(device_id)
        if not _dev:
            return jsonify({"error": "No such device"}), 404
        try:
            _store().delete_device(device_id)
        except Exception as exc:
            return _store_broken(exc)
        # **'이 컴퓨터에서 지워진다'고 말했으면 지워야 한다.** 보관소 행만
        # 지우고 업로드 원본(.conf)과 파싱 산출물(parsed.json — 정책 전문이
        # 들어 있다)은 디스크에 남겼다. 고객 오프보딩에서 그 확인창 문장이
        # 거짓이 된다(라운드 41 지적).
        _removed = []
        for _p in _device_files(_dev):
            try:
                _p.unlink()
                _removed.append(_p.name)
            except FileNotFoundError:
                pass
            except OSError as exc:
                # 못 지웠으면 지웠다고 말하지 않는다
                print(f"[APO] could not remove {_p}: {exc}", flush=True)
                return jsonify({
                    "error": "The device was removed from APO, but its uploaded "
                             f"configuration file could not be deleted from "
                             f"'{_p.parent}'. Delete it by hand — it contains "
                             "that customer's policies.",
                    "error_key": "device_files_left_behind",
                    "path": str(_p)}), 500
        if app.config.get('device_id') == device_id:
            # 열려 있던 장비를 지웠다 — 화면에 남은 판정이 지워진 장비 것이
            # 되지 않게 세션도 비운다.
            for k in ('last_parsed', 'last_raw_config', 'last_config_sha256',
                      'last_config_filename', 'device_id'):
                app.config.pop(k, None)
            _drop_previous_device_traces()
            app.config['last_runtime_stats'] = {}
            app.config['user_ranges'] = []
        return jsonify({"ok": True, "files_removed": _removed})

    @app.post("/api/customers")
    def customer_add():
        payload = request.get_json(silent=True) or {}
        try:
            return jsonify(_store().add_customer(payload.get("name", "")))
        except ValueError as e:
            # 입력 검증(중복 이름 등)은 400 이다 — 아래 보관소 오류보다
            # **먼저** 잡아야 한다. 넓게 잡았더니 "이미 있는 이름" 이
            # "저장 공간 부족" 으로 둔갑했다.
            return jsonify({"error": str(e)}), 400
        except Exception as exc:
            return _store_broken(exc)

    @app.post("/api/customers/<customer_id>/rename")
    def customer_rename(customer_id):
        payload = request.get_json(silent=True) or {}
        try:
            _store().rename_customer(customer_id, payload.get("name", ""))
        except ValueError as e:
            # 입력 검증이 보관소 오류보다 먼저다(`customer_add` 와 같은 순서).
            return jsonify({"error": str(e)}), 400
        except Exception as exc:
            return _store_broken(exc)
        return jsonify({"ok": True})

    @app.delete("/api/customers/<customer_id>")
    def customer_delete(customer_id):
        try:
            _store().delete_customer(customer_id)
        except Exception as exc:
            return _store_broken(exc)
        return jsonify({"ok": True})

    @app.post("/api/devices/<device_id>/customer")
    def device_assign(device_id):
        payload = request.get_json(silent=True) or {}
        try:
            _store().assign_device(device_id, payload.get("customer_id") or None)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as exc:
            return _store_broken(exc)
        return jsonify({"ok": True})

    @app.post("/api/reports/scope")
    def reports_scope():
        """보관된 장비로 리포트를 만든다 — 장비 1대 / 고객사 전체 / 모두.

        일괄 보고(v105)와 **같은 엔진**을 쓴다. 입력이 '업로드된 파일'에서
        '보관된 장비'로 바뀔 뿐이라, 고객사별 분리·행방 불변·SUMMARY 규칙이
        그대로 적용된다.
        """
        gate = _license_required()
        if gate:
            return gate
        info = get_license_info() or {}
        payload = request.get_json(silent=True) or {}
        scope = str(payload.get("scope", "device")).strip()
        target = payload.get("id")
        if scope not in ("device", "customer", "all"):
            return jsonify({"error": "scope must be device, customer or all"}), 400
        # id를 그대로 SQL 파라미터로 넘기면 list/dict가 왔을 때 sqlite3가
        # InterfaceError로 죽어 500이 된다 — 잘못된 요청은 400으로 답한다.
        if target is not None and not isinstance(target, (str, int)):
            return jsonify({"error": "id must be a string"}), 400
        if target is not None:
            target = str(target)
        # 여러 장비를 한 번에 묶는 건 MSP 기능이다(일괄 보고와 같은 경계).
        if scope != "device" and (info.get("tier") or "single") != "msp":
            return jsonify({"error": "Reporting across devices requires an MSP / "
                            "Consultant license."}), 403

        devices = _store().devices_for_scope(scope, target)
        if not devices:
            return jsonify({"error": "No registered devices in that scope."}), 400

        # **`scope == "device"` 만 예외로 두었더니 그 경로로 샜다.**
        # 세션의 수신처가 그 장비의 고객사와 다를 수 있는데 그대로
        # 찍혔다(라운드 47 실측). 범위든 단일이든 같은 규칙을 쓴다 —
        # 대상 고객사가 하나로 확정될 때만 수신처를 싣는다.
        def _cust_name(dev):
            cid = (dev or {}).get("customer_id")
            if not cid:
                return ""
            for c in _store().list_customers():
                if c["id"] == cid:
                    return c.get("name") or ""
            return ""

        _only = {_cust_name(d) for d in devices} if scope == "device" else set()
        branding = _branding_for(next(iter(_only)) if len(_only) == 1 else "")
        branding = branding or None

        files, sha_by_name, name_by_entry, usage_by_entry = [], {}, {}, {}
        orules_by_entry: dict = {}
        customer_by_entry: dict[str, str] = {}
        stats_vdom_by_entry: dict[str, str] = {}
        coverage_by_entry = {}
        customers = {c["id"]: c["name"] for c in _store().list_customers()}
        # **한 장비 = 한 stem**을 여기서 보장한다. 배치 엔진은 stem 으로 장비를
        # 묶으므로, stem 이 겹치면 두 장비가 한 대로 합쳐진다 — 뒤 장비의 config
        # 는 버려지고 그 장비의 CSV·대역이 앞 장비 config 에 붙어, 남의 통계로
        # 판정한 결과가 남의 해시를 달고 나간다(라운드 14 실측). 장비명은 config
        # 의 hostname 이라 공장 기본값 'FortiGate' 로 남은 장비들끼리 흔하게
        # 겹친다. 동봉 데모 파일 두 개도 hostname 이 같다.
        taken: set[str] = set()

        def _free(stem: str) -> bool:
            # 배치 엔진의 묶기 기준이 대소문자 무시이므로 여기서도 무시한다.
            # '.proxy'까지 함께 잡는 이유: stem 'X'는 'X.proxy.csv'를 내보내는데
            # 그건 stem 'X.proxy'의 FW CSV 파일명과 글자 그대로 같다. 두 장비가
            # 그렇게 이름 지어지면 한쪽의 CSV가 조용히 버려진다.
            low = stem.lower()
            return low not in taken and f"{low}.proxy" not in taken

        def _unique_stem(base: str, device_id: str) -> str:
            def _reserve(stem: str) -> str:
                low = stem.lower()
                taken.update((low, f"{low}.proxy"))
                return stem

            if _free(base):
                return _reserve(base)
            # 겹치면 장비를 가리키는 값(config 해시 앞자리)을 붙인다. 사람이
            # 읽어도 어느 장비인지 리포트의 감사 해시와 대조할 수 있다.
            for n in range(2, 1000):
                cand = f"{base} ({device_id[:8]})" if n == 2 else f"{base} ({device_id[:8]}-{n})"
                if _free(cand):
                    return _reserve(cand)
            raise ValueError("Too many devices share the same name.")

        for d in devices:
            # zip 엔트리 이름에 고객사를 앞에 붙여 묶는다. **폴더로 나누지
            # 않는 것은 의도**다 — 엔트리 이름의 경로 구분자는 압축 해제 시
            # 경로 탈출 통로가 되므로 전부 평평하게 만드는 방어를 이미 세웠고
            # (라운드 1~13), 그 방어를 리포트 편의 때문에 되돌리지 않는다.
            folder = customers.get(d.get("customer_id") or "", "Unassigned")
            stem = _unique_stem(f"{folder} - {d.get('name') or d['device_id']}",
                                d["device_id"])
            files.append((f"{stem}.conf", d["config_text"]))
            sha_by_name[f"{stem}.conf"] = d.get("config_sha256") or ""
            # 워크북 문서정보에는 합성 라벨이 아니라 실제로 등록한 파일명을 싣는다.
            if d.get("config_filename"):
                name_by_entry[f"{stem}.conf"] = d["config_filename"]
            # 사용량의 출처도 그 장비 워크북에 그대로 실린다.
            if d.get("csv_meta"):
                usage_by_entry[f"{stem}.conf"] = d["csv_meta"]
            # 워크북 스스로 어느 고객의 것인지 말하게 한다 — zip 파일명에만
            # 있으면 xlsx 한 장을 떼어 보내는 순간 귀속이 사라진다.
            if d.get("customer_id"):
                customer_by_entry[f"{stem}.conf"] = folder
            # 객체 명명 규칙도 그 장비의 사실이다 — 지금 열린 장비 것을
            # 전부에 적용하면 고객 A 의 이름으로 고객 B 가 판정된다.
            if d.get("object_rules"):
                # 구형 mgmt 칸도 여기서 infra 로 접는다 — 배치 경로만 빠지면
                # 같은 고객이 화면과 배치 리포트에서 다르게 판정된다.
                orules_by_entry[f"{stem}.conf"] = _normalize_object_rules(d["object_rules"])
            stats = d.get("runtime_stats") or {}
            # 종류를 모르는(평평한) 통계는 화면의 _stats_for 와 **같은 규칙**으로
            # 양쪽에 쓴다. 여기서만 firewall 로 몰았더니, 붙여넣기로 넣은 사용량이
            # 화면에서는 프록시 정책까지 판정하는데 리포트에서는 '사용량 없음'이
            # 되어 같은 장비의 등급이 갈렸다(라운드 15 실측: 화면 9 vs 리포트 7).
            # 종류별인지 판단하는 규칙도 화면과 같은 것을 쓴다 — 갈라지면
            # 같은 통계가 경로마다 다르게 읽힌다.
            from app.services.policy_renderer import _stats_for
            fw, px = _stats_for(stats, "firewall"), _stats_for(stats, "proxy")
            if fw:
                files.append((f"{stem}.csv", _stats_to_csv(fw)))
            if px:
                files.append((f"{stem}.proxy.csv", _stats_to_csv(px)))
            # **VDOM 귀속은 보관소가 이미 안다 — CSV 재직렬화에서 벗겨진다.**
            # 안 넘기면 배치가 다중 VDOM 장비에서 "단독으로 열어 VDOM 을
            # 지정하라"고 사용자가 이미 지정한 것을 요구하며 사용량을 통째로
            # 버린다(라운드 56 계약 렌즈 — 화면과 배치 워크북의 판정 갈림).
            _svd = str(stats.get("_vdom") or "").strip()
            if _svd:
                stats_vdom_by_entry[f"{stem}.conf"] = _svd
            # 수집 커버리지도 보관소가 아는 그 장비의 사실이다(라운드 73 F1
            # — stats_vdom 과 같은 이유로 배치에 전달).
            if d.get("collect_coverage"):
                coverage_by_entry[f"{stem}.conf"] = d["collect_coverage"]
            # 보관된 값의 형태를 믿지 않는다 — 여기서 터지면 아래 try 밖이라
            # **범위 안의 모든 장비 리포트가 함께 죽는다**. 한 장비의 실패는
            # 그 장비만의 실패로 남아야 한다.
            cidrs = [r["cidr"] for r in (d.get("user_ranges") or [])
                     if isinstance(r, dict) and isinstance(r.get("cidr"), str)]
            if cidrs:
                files.append((f"{stem}.ranges.txt", "\n".join(cidrs)))

        from app.services.batch_report import build_batch_zip
        try:
            zip_bytes, summary = build_batch_zip(
                files, engine_ctx=_engine_ctx(with_device_rules=False),
                profile=app.config['profile'],
                apo_version=APO_VERSION, branding=branding, sha_by_name=sha_by_name,
                filename_by_name=name_by_entry, usage_by_name=usage_by_entry,
                customer_by_name=customer_by_entry,
                object_rules_by_name=orules_by_entry,
                stats_vdom_by_name=stats_vdom_by_entry,
                collect_coverage_by_name=coverage_by_entry)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            print(f"[APO] scoped report failed: {exc}", flush=True)
            return jsonify({"error": "Failed to build the report."}), 400
        # 서버가 주는 이름도 범위별로 다르게 한다 — 화면 쪽에서만 이름을 붙이면
        # 자바스크립트를 거치지 않는 경로(직접 호출·프록시)에서 모든 고객의
        # zip이 같은 이름으로 떨어진다.
        _label = "all_devices"
        if scope == "customer":
            _label = customers.get(target or "", "customer")
        elif scope == "device" and devices:
            _label = devices[0].get("name") or "device"
        return app.response_class(
            response=zip_bytes, status=200, mimetype='application/zip',
            headers={"Content-Disposition": _attachment("apo_reports_"
                                                        f"{_label}.zip"),
                     "X-Batch-Result": f"{summary['succeeded']}/{summary['devices']}"})

    @app.post("/api/batch/export")
    def batch_export():
        gate = _license_required()
        if gate:
            return gate
        info = get_license_info() or {}
        if (info.get("tier") or "single") != "msp":
            # 화이트라벨과 같은 규칙 — 서버가 티어를 강제한다(클라이언트 우회 차단).
            return jsonify({"error": "Batch reporting requires an MSP / Consultant "
                            "license. A single-organisation license exports one "
                            "device at a time."}), 403
        uploads = request.files.getlist("files")
        if not uploads:
            return jsonify({"error": "No files uploaded. Select the config files "
                            "(and optional CSV / ranges files) together."}), 400
        # 이름 없는 업로드도 흔적을 남긴다 — 빈 문자열이면 ignored 목록에
        # 공백 항목으로 찍혀 무엇이 무시됐는지 알 수 없다(라운드 4).
        # utf-8-sig — Excel의 'CSV UTF-8'과 메모장이 BOM을 붙인다. 그대로 두면
        # 첫 줄의 정상 CIDR이 '주소 아님'으로 버려져 판정 축이 조용히 꺼진다
        # (리뷰 라운드 6 실측). config/CSV 파서 결과는 BOM 유무와 무관하다.
        # 감사 해시는 단일 경로와 같이 **원본 바이트**로 낸다(라운드 8).
        decoded, sha_by_name = [], {}
        for f in uploads:
            name = f.filename or "(unnamed upload)"
            data = f.read()
            decoded.append((name, data.decode("utf-8-sig", errors="ignore")))
            sha_by_name.setdefault(name, _hashlib_sha256_bytes(data))
        branding = _load_branding() if _branding_allowed() else None
        if branding and not branding.get("company"):
            branding = None
        if branding:
            # 'Prepared for'(고객사명)는 배치에서 **뺀다**. 세션에 하나뿐인 값이
            # N개 고객 산출물에 그대로 찍히면, 고객 B의 보고서 표지가 "고객 A용"
            # 이라고 말하고 B에게 A의 신원까지 알려준다 — zip 파일명 축에서
            # 막아온 교차 오염이 표지에서 재현된다(리뷰 라운드 13 critical).
            # 회사명(자기 브랜드)은 어느 고객 보고서에나 참이므로 유지한다.
            branding = {"company": branding.get("company")}
        from app.services.batch_report import build_batch_zip
        try:
            zip_bytes, summary = build_batch_zip(
                # 업로드한 파일은 지금 열린 장비가 아니다 — 세션의 명명 규칙을
                # 적용하지 않는다(라운드 44).
                decoded, engine_ctx=_engine_ctx(with_device_rules=False),
                profile=app.config['profile'],
                apo_version=APO_VERSION, branding=branding,
                sha_by_name=sha_by_name)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            print(f"[APO] batch export failed: {exc}", flush=True)
            return jsonify({"error": "Failed to build the batch report."}), 400
        return app.response_class(
            response=zip_bytes, status=200, mimetype='application/zip',
            # 날짜를 넣어 연달아 뽑아도 덮이지 않게 한다(같은 부류의 오배송).
            headers={"Content-Disposition": _attachment(
                         f"apo_batch_reports_{_date.today().isoformat()}.zip"),
                     # 헤더는 latin-1 제약이 있으므로 숫자만 싣는다.
                     "X-Batch-Result": f"{summary['succeeded']}/{summary['devices']}"})

    @app.post("/api/collect/probe")
    def collect_probe():
        """ISDB·geography 후보 엔드포인트를 두드려 응답 형태만 보고한다.

        파싱하지 않는다. v85에서 `dnsproxy 6` 출력 형식을 추정해 파서를 만들었다가
        첫 실사용에서 통째로 깨진 적이 있어, **실물 응답을 보기 전에는 파서를
        만들지 않는다**는 원칙을 세웠다. 이 라우트는 그 실물을 뜨기 위한 것이다.
        """
        payload = request.get_json(silent=True) or {}
        device, err = _resolve_device(payload)
        if err:
            return err
        from app.services.device_collector import probe_endpoints
        try:
            rows = probe_endpoints(device)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            print(f"[APO] probe failed: {exc}", flush=True)
            return jsonify({"error": "Probe failed — see the console for details."}), 502
        return jsonify({"results": rows,
                        "hint": "200을 준 경로의 sample을 개발자에게 전달하면 "
                                "그 형태에 맞는 파서를 만듭니다."})

    # ── 샘플 리포트 (무료) ────────────────────────────────────────────────
    # 이 도구의 가치는 결국 엑셀 산출물인데, 지금까지는 **사기 전에 그걸 볼
    # 방법이 없었다**. 번들된 데모 설정으로 같은 파이프라인을 돌려 실제 워크북을
    # 그대로 내려준다. 라이선스 게이트를 걸지 않는다 — 게이트를 걸면 "사기 전엔
    # 못 본다"는 문제가 그대로다.
    @app.get("/api/sample-report")
    def sample_report():
        """번들 데모 설정으로 만든 실제 감사 워크북.

        현재 세션 상태(last_parsed 등)를 **절대 건드리지 않는다**. 사용자가
        고객 설정을 열어 둔 채 샘플을 눌렀다가 작업이 날아가면 안 된다.
        """
        from app.services.workbook_exporter import build_severity_workbook
        from app.services.policy_renderer import build_view_model
        from app.services.reachability import detect_unreachable
        from app.parsers.policy_csv_parser import PolicyStatsCsvParser
        import hashlib as _hashlib

        # DATA_DIR은 사용자 데이터 경로다. 번들 자산은 app/data에 있고, frozen
        # 상태에서는 _MEIPASS 아래로 풀린다(version_advisor와 같은 규칙).
        if getattr(_sys, 'frozen', False) and hasattr(_sys, '_MEIPASS'):
            bundled = Path(_sys._MEIPASS) / "app" / "data"
        else:
            bundled = Path(__file__).resolve().parent / "data"
        cfg_path = bundled / "sample_config.conf"
        csv_path = bundled / "sample_policy_stats.csv"
        if not cfg_path.exists():
            return jsonify({"error": "Sample configuration is not bundled in this build."}), 404
        raw = cfg_path.read_text(encoding="utf-8", errors="ignore")
        parsed = FortiGateConfigParser(raw).parse()

        # 샘플 CSV는 firewall 정책 통계다. 평평하게 넘기면 proxy 정책이 같은
        # 번호의 firewall 통계를 빌려가, v91이 고친 교차오염을 **샘플 산출물에서
        # 그대로 재현**한다(샘플 config에 proxy-policy 1·2가 있다).
        runtime_stats = {"firewall": {}, "proxy": {}}
        if csv_path.exists():
            try:
                runtime_stats["firewall"] = PolicyStatsCsvParser().parse_text(
                    csv_path.read_text(encoding="utf-8-sig", errors="ignore"))
            except Exception:
                runtime_stats["firewall"] = {}

        # 샘플이 '판정 불가'로 도배되지 않도록 데모 설정의 사용자 대역을 준다.
        # **지금 열린 장비의 객체 명명 규칙은 쓰지 않는다.** 샘플은 번들된
        # 데모 설정을 판정하는 문서인데, 세션 값을 쓰면 고객 X 의 이름 규칙으로
        # 판정된 샘플이 고객 Y 에게 나간다(라운드 44 실측: 같은 샘플이
        # 18552바이트 → 17775바이트로 바뀌고 'High-risk object' 사유가 생겼다).
        context = {
            "service_groups": parsed.get("service_groups", {}),
            "user_ranges": [{"cidr": "10.10.0.0/16"}],
            "today": _date.today(),
            "onetime_schedules": _se_onetime(parsed),
            **_engine_ctx(with_device_rules=False),
        }
        view = build_view_model(parsed, runtime_stats)
        classify = lambda ps: [{**p, **evaluate_severity(p, context)} for p in (ps or [])]
        meta = parsed.get("meta", {})
        payload = {
            "firewall": classify(view.get("firewall_policy", [])),
            "proxy": classify(view.get("firewall_proxy_policy", [])),
            "inactive_rules": describe_inactive_rules(app.config['profile']),
            "reachability": {**detect_unreachable(parsed, None),
                             "fqdn_captured_at": None},
            "report_meta": {
                "apo_version": APO_VERSION,
                "generated_at": _dt.now().strftime("%Y-%m-%d %H:%M"),
                "hostname": meta.get("hostname") or "DEMO-FGT-01",
                "config_version": meta.get("config_version") or "",
                "buildno": meta.get("buildno") or "",
                "config_filename": "sample_config.conf",
                "config_sha256": _hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest(),
                "profile": (app.config['profile'].get("meta") or {}).get("name", "default"),
                "thresholds": context["thresholds"],
                "rules": context["rules"],
                "user_range_count": 1,
                # {"firewall":{},"proxy":{}}는 비어 있어도 truthy다. 번들 CSV가
                # 빠지거나 파싱에 실패해도 "사용량 있음"이라고 적히면 안 된다.
                "csv_loaded": _stats_count(runtime_stats) > 0,
                # 이게 실제 장비 보고서로 오해되면 안 된다.
                "sample": True,
            },
        }
        try:
            xlsx_bytes = build_severity_workbook(payload)
        except Exception as exc:
            print(f"[APO] sample report failed: {exc}", flush=True)
            return jsonify({"error": "Failed to build the sample report"}), 500
        return app.response_class(
            response=xlsx_bytes, status=200,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={"Content-Disposition": "attachment; filename=APO_sample_report.xlsx"})

    # ── 정확도 검증 워크플로우 ─────────────────────────────────────────────
    # 의도적으로 무료다: 이 기능의 목적은 "APO 판정을 그대로 믿지 말고
    # 표본으로 직접 검증하라"는 신뢰 구축이고, 구매 전 사용자가 해볼 수
    # 있어야 의미가 있다. 감사 산출물(유료 export)과는 성격이 다르다.
    @app.post("/api/verification/sample")
    def verification_sample():
        parsed = app.config.get('last_parsed')
        if not parsed:
            return jsonify({"error": "No config loaded. Upload a config file first."}), 400
        from app.services import verification as vf
        from app.services.policy_renderer import build_view_model as _bvm
        fmt = str(request.args.get("format", "xlsx")).lower()
        context = {
            "service_groups": parsed.get("service_groups", {}),
            "user_ranges": app.config.get('user_ranges', []),
            "today": _date.today(),
            # 승인 유효기간 유예의 신호(onetime 스케줄) — 모든 판정 경로가
            # 같은 맵을 받아야 한다. 한 곳만 빠지면 classify 와 후보/유보가
            # 갈린다(라운드 71 스코프 전파와 같은 규칙).
            "onetime_schedules": _se_onetime(parsed),
            **_engine_ctx(),
        }
        view = _bvm(parsed, app.config.get('last_runtime_stats', {}))
        results = []
        for key, ptype in (("firewall_policy", "firewall"),
                           ("firewall_proxy_policy", "proxy")):
            for pol in view.get(key, []):
                results.append({**pol, "policy_type": ptype,
                                **evaluate_severity(pol, context)})
        samples = vf.stratified_sample(results)
        # **표본이 비면 빈 표를 내려 주지 않는다.** 라운드 48 부터 등급 0
        # ('Cannot assess — set User IP ranges first')은 표본에서 뺀다 —
        # 검증자가 줄 수 있는 답이 '일치' 뿐이라 정확도를 구조적으로 부풀리기
        # 때문이다. 그런데 사용자 대역을 아직 안 넣은 설정은 **정책 전부가**
        # 등급 0 이라, 그대로 두면 칸만 있는 표가 내려간다. 왜 비었는지와
        # 무엇을 하면 되는지를 말한다.
        if not samples:
            _ungraded = sum(1 for r in results if str(r.get("urgency") or 0) == "0")
            if _ungraded:
                return jsonify({
                    "error": f"All {_ungraded} policies came out as severity 0 "
                             "(\"Cannot assess\") because APO does not know which "
                             "IP ranges are user networks, so there is nothing to "
                             "verify yet. Set the User IP ranges first, then "
                             "download the sample.",
                    "error_key": "sample_all_ungraded",
                    "n": _ungraded}), 409
            return jsonify({
                "error": "This configuration has no policies to verify.",
                "error_key": "sample_no_policies"}), 409
        rows = vf.build_rows(samples)
        # 파일 안에도 장비를 적는다 — 파일명은 받는 쪽에서 바뀐다. 다만
        # 이 표지는 **사람이 읽으라고** 적는 것이고, 판정 근거는 아래 토큰이다.
        _dev = _open_device_label()
        # **발급 사실을 서버에 남기고, 행마다 그 열쇠를 넣는다.** 이 토큰이
        # 어느 장비의 것이었는지는 사용자가 고칠 수 없는 곳(장비 저장소)에
        # 적힌다. 파일 안의 값은 그 기록을 가리키는 열쇠일 뿐이다.
        # **엑셀이 값을 바꾸지 못하게 한다.** token_hex(8) 는 전부 숫자이거나
        # `숫자+e+숫자` 꼴이 될 수 있고, 그러면 CSV 를 엑셀로 열었다 저장할 때
        # 수치·지수표기로 바뀐다(대략 1/4000). 그 표본은 되올려도 '발급한
        # 적 없는 행'이 된다. 글자로 시작하게 만들어 그 경우를 없앤다.
        _tok = "s" + _secrets.token_hex(8)
        try:
            _store().record_sample(
                _tok, app.config.get('device_id') or "",
                (parsed.get("meta") or {}).get("hostname") or "", _dev,
                row_keys=[(str(r.get("vdom") or ""),
                           str(r.get("policy_type") or ""),
                           str(r.get("policy_id") or "")) for r in rows])
        except Exception as exc:
            print(f"[APO] could not record sample: {exc}", flush=True)
            return jsonify({"error": "APO could not record this sample, so it "
                            "would not be able to tell later which device it "
                            "came from. Nothing was downloaded."}), 500
        for _r in rows:
            _r["sample_token"] = _tok
        if fmt == "csv":
            return app.response_class(
                response=vf.to_csv(rows, device=_dev), status=200, mimetype="text/csv",
                headers={"Content-Disposition":
                         _attachment(f"apo_verification_sample_{_open_device_label()}.csv")})
        return app.response_class(
            response=vf.to_xlsx(rows, device=_dev), status=200,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition":
                     _attachment(f"apo_verification_sample_{_open_device_label()}.xlsx")})

    @app.post("/api/verification/score")
    def verification_score():
        from app.services import verification as vf
        uploaded = request.files.get("worksheet")
        if not uploaded:
            return jsonify({"error": "worksheet file is required (.csv or .xlsx)"}), 400
        labels = {label: key for key, label in vf.WORKSHEET_COLUMNS}

        def _is_header(cells) -> bool:
            """이 줄이 헤더인가 — **표지행을 헤더로 읽지 않기 위해.**

            표본 첫 줄에 '# 장비 / Device: ...' 를 적기 시작한 뒤로 APO 가 만든
            CSV 를 APO 가 거부했다("upload the sheet generated by APO"). 표지를
            붙이는 쪽만 고치고 읽는 쪽을 안 고친 것이다 — 왕복하는 파일은
            양쪽을 함께 고쳐야 한다(라운드 26 실측).
            """
            return sum(1 for h in cells
                       if str(h or "").strip() in labels) >= 2

        rows = []
        # 표지행이 말하는 장비. **읽어서 대조한다** — 직전 라운드에 '파일 안에도
        # 장비를 적는다'며 써 놓고 읽지는 않았더니, 다른 고객 장비의 표본을
        # 그대로 채점해 지금 연 장비의 정확도로 보여줬다(라운드 27 실측:
        # BETA 표본을 ACME 를 연 채로 올려 '정확도 0.0%', 경고 0건).
        sheet_device = ""
        header_found = True
        name = (uploaded.filename or "").lower()
        try:
            if name.endswith(".xlsx"):
                import io as _io
                from openpyxl import load_workbook
                wb = load_workbook(_io.BytesIO(uploaded.read()), read_only=True)
                ws = wb.active
                header = None
                for raw in ws.iter_rows(values_only=True):
                    if header is None:
                        if not _is_header(raw):
                            sheet_device = sheet_device or vf.device_from_banner(raw)
                            continue        # 표지행 — 건너뛴다
                        header = [labels.get(str(h or "").strip(), str(h or "").strip())
                                  for h in raw]
                        continue
                    rows.append({header[i]: ("" if v is None else str(v))
                                 for i, v in enumerate(raw) if i < len(header)})
                header_found = header is not None
            else:
                import csv as _csv, io as _io
                raw_bytes = uploaded.read()
                # 한국 Excel의 "CSV(쉼표로 분리)" 기본 저장은 cp949다. 강제
                # utf-8(errors=replace)로 읽으면 한글 판정값("일치")이 U+FFFD로
                # 깨져 전량 '미기입'이 되는데, 오류 없이 0건 채점으로 위장된다
                # (재비판 NEW-BUG). 엄격 디코딩 + cp949 폴백으로 바꾼다.
                text = None
                for enc in ("utf-8-sig", "cp949"):
                    try:
                        text = raw_bytes.decode(enc)
                        break
                    except UnicodeDecodeError:
                        continue
                if text is None:
                    return jsonify({"error": "Could not decode the CSV. "
                                    "Save it as UTF-8 or the Korean Excel default (CP949)."}), 400
                lines = text.splitlines()
                # 헤더 줄을 찾아 그 앞(표지행)은 버린다. 구분자 추정도 헤더
                # 줄에서 해야 한다 — 표지행에는 쉼표가 없어 잘못 추정된다.
                for i, ln in enumerate(lines[:10]):
                    for d in (",", ";"):
                        cells = next(_csv.reader([ln], delimiter=d), [])
                        if _is_header(cells):
                            lines = lines[i:]
                            break
                        sheet_device = sheet_device or vf.device_from_banner(cells)
                    else:
                        continue
                    break
                text = "\n".join(lines)
                first = lines[0] if lines else ""
                delim = ";" if first.count(";") > first.count(",") else ","
                for raw in _csv.DictReader(_io.StringIO(text), delimiter=delim):
                    rows.append({labels.get((k or "").strip(), (k or "").strip()): v
                                 for k, v in raw.items()})
        except Exception:
            return jsonify({"error": "Could not read the worksheet. "
                            "Upload the file generated by APO (.csv or .xlsx)."}), 400
        if not rows:
            # **원인을 정확히 말한다.** xlsx 는 헤더를 못 찾으면 rows 가 비는데,
            # 시트에는 데이터 14행이 그대로 있다. '데이터 행이 없다'고 답했더니
            # 사용자가 없는 문제(데이터 유실)를 찾게 됐다(라운드 28 지적).
            # 같은 상황의 CSV 는 이미 헤더를 지목하고 있었다 — 규칙을 맞춘다.
            if not header_found:
                return jsonify({"error": "The header row was not found — APO "
                                "looks for the column titles it generated. "
                                "Upload the sheet generated by APO, keeping "
                                "its header row."}), 400
            return jsonify({"error": "The worksheet has no data rows."}), 400
        # 헤더가 판정 컬럼으로 매핑되지 않았으면(인코딩·구분자·양식 문제) 빈
        # 정확도 리포트로 위장하지 말고 원인을 말한다 (재비판 SUSPECT 2건).
        if not any("verdict" in r for r in rows):
            return jsonify({"error": "Worksheet columns were not recognized — "
                            "upload the sheet generated by APO, keeping its header row."}), 400
        open_dev = _open_device_label()

        # ── 이 행은 **내가 발급한 것인가** ──────────────────────────────
        # 여덟 라운드 동안 표본 안의 값으로 신원을 가리려 했다 — 장비 표지,
        # 정책 이름, 정책 번호, 그 조합. 전부 열렸다. 표지는 엑셀에서 한 줄
        # 지우면 사라지고(라운드 39), 정책 이름·번호는 다른 고객 장비에도
        # 똑같이 있다 — MSP 템플릿으로 복제된 두 장비는 번호도 이름도 전부
        # 같고(라운드 38), FortiOS 에서 `set name` 은 선택 항목이라 이름이
        # 아예 없는 장비에서는 번호 1~12 가 어느 FortiGate 에나 있다(라운드 39).
        #
        # 사용자가 고칠 수 있는 값으로는 답이 안 나온다. 그래서 **APO 가 스스로
        # 발급한 값**을 행마다 넣고, 발급 사실은 장비 저장소에 남긴다. 이제
        # 묻는 것은 하나다 — 이 행에 내가 발급한 토큰이 있고, 그 토큰이 지금
        # 연 장비의 것인가. 이름도 번호도 표지도 필요 없다.
        _seen_tokens: dict = {}
        _open_id = app.config.get('device_id') or ""
        _open_name = ((app.config.get('last_parsed') or {}).get("meta") or {}
                      ).get("hostname") or ""

        def _token_ok(tok: str):
            """이 토큰이 지금 연 장비의 것인가. (판정, 발급기록)"""
            if tok in _seen_tokens:
                return _seen_tokens[tok]
            rec = None
            try:
                rec = _store().get_sample(tok) if tok else None
            except Exception:
                rec = None
            if not rec:
                out = (False, None)
            elif rec["device_id"] == _open_id:
                out = (True, rec)
            else:
                # 같은 방화벽의 **새 백업**은 device_id 가 달라진다(설정 내용이
                # 바뀌므로). 그때 거절하면 현장에서 사람이 채운 행을 버리게
                # 된다(라운드 29 실측). 장비 이름은 양쪽 다 서버가 적은 값이라
                # 사용자가 고칠 수 없다 — 표지와 다른 점이 이것이다.
                out = (bool(_open_name) and rec["device_name"] == _open_name, rec)
            _seen_tokens[tok] = out
            return out

        scored, ignored, from_older = [], 0, ""
        # **빈 줄은 '남의 행'이 아니다.** 엑셀로 저장하면 표 아래에 빈 줄이
        # 딸려 오는 것이 예사인데, 그걸 ignored 로 세는 바람에 화면이
        # "APO 가 이 장비에 발급하지 않은 행 3건" 이라고 경고했다 — 감사
        # 산출물에 남의 행을 붙였다는 누명이다(라운드 48 실측). 게다가 이
        # 카운터는 **진짜로 버려진 행**(F4)에도 쓰여서, 고객이 무해한
        # 저장 흔적과 실제 유실을 구별할 수 없었다.
        _blank = 0
        # 토큰은 우리 것인데 신원 칸이 발급분과 안 맞는 행. '다른 장비'와
        # 구별해서 세어야 원인을 맞게 말할 수 있다.
        _key_mismatch = 0
        _dupe = set()
        for r in rows:
            if not any(str(v or "").strip() for v in r.values()):
                _blank += 1
                continue
            tok = str(r.get("sample_token") or "").strip()
            ok, rec = _token_ok(tok)
            # 같은 정책 행을 복제해 분모를 부풀릴 수 없다(1행 ×100 → judged 100).
            # **한 정책을 가리키는 열쇠는 (VDOM, 종류, 번호)다.** VDOM 을 빼면
            # 다중 VDOM 장비에서 root 1번과 guest 1번이 충돌해, APO 가 방금
            # 발급한 자기 행을 버리면서 '내가 발급하지 않은 행'이라고 화면에
            # 인쇄하고 그만큼 정확도를 부풀렸다(라운드 40 실측: 사람이 채운
            # 10행 중 3행이 사라져 참 50% 가 71.4% 로 나왔다).
            # **표의 VDOM 칸을 신원의 근거로 쓰지 않는다.** 사람이 채우는
            # 표라 빈 칸에 'root' 를 적어 넣는 것은 자연스러운 편집인데,
            # 그 칸을 열쇠에 넣었더니 APO 가 자기 발급 행을 버리면서 '내가
            # 발급한 행이 아니다'라고 인쇄했다 — 등급 한 그룹이 통째로
            # 사라지고 정확도가 0.500 에서 0.4545 로 바뀌었다(라운드 41 실측).
            # 발급 대장이 진실이다. (종류, 번호)로 발급분을 찾고, 그 번호가
            # 한 VDOM 에만 있으면 표의 값이 무엇이든 그 행으로 인정한다.
            # 두 VDOM 에 걸쳐 있을 때만 표의 값으로 가른다 — 그때는 그것이
            # 유일한 단서이고, 표본에도 VDOM 칸이 채워져 나간다.
            # **사람이 채운 표의 값은 다듬어서 견준다.** 앞뒤 공백 하나,
            # 엑셀이 바꾼 대문자 하나로 행이 통째로 버려지고는 "다른 장비의
            # 표본"이라는 엉뚱한 안내가 나갔다 — 현장에서 하루를 들여 채운
            # 50행이 복구 불가가 된다(라운드 48 실측).
            _iss = (rec or {}).get("row_keys") or set()
            _pt = str(r.get("policy_type") or "").strip().lower()
            _pid = str(r.get("policy_id") or "").strip()
            _cands = [k for k in _iss
                      if str(k[1]).strip().lower() == _pt
                      and str(k[2]).strip() == _pid]
            if len(_cands) == 1:
                key = _cands[0]
            else:
                # 여러 VDOM 에 같은 번호가 있을 때만 표의 VDOM 칸으로 가른다.
                # 열쇠는 **발급 대장의 값**을 그대로 쓴다 — 표에서 읽은 값으로
                # 튜플을 새로 만들면 대문자 하나 차이에 행이 통째로 버려진다.
                _vd = str(r.get("vdom") or "").strip().lower()
                key = next((k for k in _cands
                            if str(k[0]).strip().lower() == _vd), None)
            # **우리가 낸 행만 센다.** 토큰만 대조하면, 그 토큰이 붙은 행을
            # 복사해 정책 번호 칸만 바꾸는 것으로 분모를 얼마든지 부풀릴 수
            # 있었다 — 1개 정책 대조가 '100건 대조 정확도 100%' 로 인쇄됐다
            # (라운드 40 실측).
            #
            # **'행 목록이 있으면' 이라고 쓰면 안 된다.** 처음엔 구 버전
            # 발급분을 위한 하위호환으로 그렇게 뒀는데, 대장의 그 칸을 비우는
            # 것만으로 규칙이 통째로 꺼졌다(라운드 41 자체 실측: 14행이
            # 28행으로). 토큰을 발급한 판은 v106 이 처음이라 지켜 줄 구
            # 발급분이 애초에 없었다 — 지키지 않아도 되는 것을 지키려다
            # 규칙에 구멍을 냈다. 예외를 두면 그 예외가 규칙이 된다.
            if ok and (key is None or key not in _iss):
                ok = False
                _key_mismatch += 1
            if ok and key not in _dupe:
                _dupe.add(key)
                scored.append(r)
                if rec and rec["device_id"] != _open_id:
                    from_older = rec["label"] or ""
            else:
                ignored += 1

        if not scored:
            _any_token = any(str(r.get("sample_token") or "").strip() for r in rows)
            if not _any_token:
                return jsonify({
                    "error": "This sheet has no 표본 ID column, so APO cannot tell "
                             "which device it was made for. Download a fresh "
                             "sample for the device you have open and enter the "
                             "results in that file.",
                    "error_key": "no_sample_token",
                    "scored_rows": 0, "ignored_rows": len(rows)}), 409
            # 대장에 아예 없는 토큰과, 다른 장비에 발급된 토큰은 다른 문제다.
            # 하나로 뭉뚱그렸더니 값이 훼손된 사용자가 없는 문제(장비를 잘못
            # 열었다)를 찾게 됐다(라운드 40 지적).
            _known = any((_token_ok(str(r.get("sample_token") or "").strip())[1]
                          or {}).get("row_keys")
                         for r in rows)
            if not _known:
                return jsonify({
                    "error": "APO does not recognise the 표본 ID in this sheet. "
                             "If a spreadsheet program changed that column, "
                             "download a fresh sample and copy your results "
                             "across; otherwise this sheet came from another "
                             "APO installation.",
                    "error_key": "sample_token_unknown",
                    "scored_rows": 0, "ignored_rows": ignored}), 409
            # **'토큰은 내 것인데 신원 칸이 안 맞는다'는 다른 문제다.**
            # 예전에는 이 경우도 '다른 장비의 표본' 으로 안내했다 — 엑셀이
            # VDOM 칸을 대문자로 바꾸거나 붙여넣기로 공백이 하나 붙은 것뿐인데
            # "그 표본을 만든 장비를 여세요" 라고 말했다. 현장에서 하루를 들여
            # 채운 50행이 통째로 버려지고, 안내는 **원인을 엉뚱한 데로**
            # 가리킨다(라운드 48 실측).
            if _key_mismatch:
                return jsonify({
                    "error": "This sample was issued for the device you have "
                             f"open ('{open_dev}'), but the VDOM / policy type / "
                             "policy ID columns no longer match what APO issued, "
                             "so APO cannot tell which policy each row is about. "
                             "Those three columns are filled in by APO — restore "
                             "them (or download a fresh sample and copy your "
                             "verdicts across). Your verdicts are still valid.",
                    "error_key": "sample_row_keys_damaged",
                    "open_device": open_dev,
                    "scored_rows": 0, "ignored_rows": ignored}), 409
            return jsonify({
                "error": "The 표본 ID in this sheet was not issued for the device "
                         f"you have open ('{open_dev}'). Open the device this "
                         "sample was made for, or download a fresh sample.",
                "error_key": "sample_token_other_device",
                "open_device": open_dev,
                "scored_rows": 0, "ignored_rows": ignored}), 409

        stats = vf.compute_precision(scored)
        # 몇 행을 세고 몇 행을 버렸는지 **화면이 말한다.** 남의 행을 붙여도
        # 분모에 못 들어가지만, 사용자는 자기가 올린 행 수와 다르다는 것을
        # 알아야 한다.
        stats["scored_rows"] = len(scored)
        stats["ignored_rows"] = ignored
        # 버려진 행의 **이유**를 나눠서 돌려준다 — 하나로 뭉치면 무해한
        # 저장 흔적과 실제 유실이 같은 경고로 보인다.
        stats["blank_rows"] = _blank
        stats["key_mismatch_rows"] = _key_mismatch
        # **귀속은 이제 표지가 아니라 채점된 행에서 나온다.** 세어진 행은 전부
        # 지금 열어 둔 장비의 정책이므로, 그 장비 이름을 붙이는 것이 사실이다.
        # 표지 문자열은 사용자가 고칠 수 있어 근거로 쓰지 않는다(라운드 37:
        # 표지만 바꾼 남의 표본이 통과했다).
        stats["device"] = open_dev
        stats["attributed_by"] = "issued_token"
        # 이 표본이 **이전 백업**에서 발급된 것이면 그 사실을 말한다. 판정
        # 등급은 그때의 설정으로 매겨진 값이다.
        stats["issued_for"] = from_older
        return jsonify(stats)

    # ── 원클릭 장비 수집 (v83) — REST API로 config·통계·FQDN 일괄 ─────────
    # 파일 업로드의 대안(선택). 등록된 장비(remediation과 같은 연결 정보)에서
    # 읽기 전용으로 수집해 기존 분석 파이프라인에 그대로 주입한다.
    def _resolve_device(payload: dict):
        """요청의 연결 정보 또는 등록된 장비를 반환. (device, error_response)

        두 라우트가 같은 규칙을 쓰도록 한 곳에 둔다 — 같은 로직을 복사하면
        한쪽만 고쳐지는 사고가 난다(오늘 캐시 무효화에서 겪은 유형).
        """
        # 우선순위: 요청에 든 연결 정보 > 직전 수집에 쓴 장비 > Remediation 등록 장비.
        # collect_device를 앞에 두는 이유 — FQDN 조회는 "지금 화면의 config를 준
        # 그 장비"에서 해야 한다. Remediation에 다른 장비가 등록돼 있으면 A장비
        # config를 B장비 해석으로 판정하는 교차 오염이 된다.
        device = app.config.get('collect_device') or app.config.get('remediation_device')
        if payload.get("ip"):
            from app.services.remediation_service import validate_device_address
            try:
                port = int(payload.get("port", 443) or 443)
                if not (1 <= port <= 65535):
                    raise ValueError("port out of range")
                device = {
                    "ip": validate_device_address(payload.get("ip", "")),
                    "port": port,
                    "token": str(payload.get("token", "")).strip(),
                    "vdom": str(payload.get("vdom", "root")).strip() or "root",
                    "verify_ssl": bool(payload.get("verify_ssl", True)),
                }
            except ValueError as exc:
                return None, (jsonify({"error": str(exc) or
                                       "Invalid device address or port"}), 400)
        if not device or not device.get("token"):
            # 메뉴 이름은 현재 UI와 일치해야 한다 — "Remediation tab"은 이제 없다.
            return None, (jsonify({
                "error": "No device is connected. Collect from the device on "
                         "the Sources page first, or register one under "
                         "Action Plan → Apply changes over the API."}), 400)
        return device, None

    @app.post("/api/collect/device")
    def collect_device():
        payload = request.get_json(silent=True) or {}
        device, err = _resolve_device(payload)
        if err:
            return err

        from app.services.device_collector import collect_from_device
        import requests as _req
        try:
            data = collect_from_device(device)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except _req.exceptions.SSLError:
            return jsonify({"error": "TLS verification failed. Fix the device "
                            "certificate, or disable verification only on a "
                            "trusted management network."}), 502
        except _req.exceptions.RequestException:
            return jsonify({"error": "Could not reach the device. Check the IP, "
                            "port, and that REST API access is enabled."}), 502

        # 수집물을 파일 업로드와 동일한 상태 슬롯에 넣는다 — 이후 classify·
        # export가 출처(파일 vs 장비)를 구분할 필요 없이 그대로 동작한다.
        # **다섯 번째 통로.** 수집기는 HTTP 200 + 비어있지 않음만 본다 —
        # 캡티브 포털이나 프록시 오류 페이지가 설정으로 들어와 장비가
        # 된다(라운드 47 지적). 파일 업로드와 같은 문턱을 둔다.
        _bad = config_intake_problem(data.get("config_text") or "")
        if _bad:
            return jsonify({
                "error": "The device answered, but what came back is not "
                         f"a FortiGate configuration. {_bad[0]}",
                "error_key": "collected_not_a_config",
                "detail": _bad[0]}), 502
        parsed = FortiGateConfigParser(data["config_text"]).parse()
        # 수집도 장비 전환이다 — 업로드·Open 과 **같은 규칙으로** 앞 장비의
        # 흔적을 먼저 끊는다. 이 줄이 없던 동안에는 조치 대상 장비가 앞
        # 장비로 남아, B를 보면서 고른 정책이 A 방화벽에서 비활성화됐다.
        _drop_previous_device_traces()
        # 이 config를 준 장비를 기억한다(메모리만 — 디스크에 쓰지 않는 건
        # 토큰과 같은 규칙). 안 하면 수집 직후에도 FQDN 조회가 "No device is
        # connected"를 낸다 — 실사용에서 실제로 그랬다.
        app.config['collect_device'] = device
        app.config['last_parsed'] = parsed
        app.config['last_raw_config'] = data["config_text"]
        # **장비에서 받은 텍스트는 디코딩 손실이 없다**(JSON 으로 왔다).
        # 그래도 명시적으로 0 을 넣는다 — 직전 업로드의 값이 남으면 이 장비에
        # 유령 차단이 뜬다.
        app.config['last_config_decode_lost'] = 0
        # 이 config는 파일이 아니라 장비에서 왔다 — 직전 업로드 파일의 바이트
        # 해시가 남아 있으면 남의 파일 해시를 이 보고서에 찍는다.
        app.config.pop('last_config_sha256', None)
        app.config['last_config_filename'] =             (parsed.get("meta") or {}).get("hostname", "device") + ".conf"
        app.config['last_runtime_stats'] = data["runtime_stats"]
        # 수집도 장비 등록이다 — 파일 업로드와 같은 규칙으로 프로파일 id를 준다.
        # 수집분은 hit count까지 함께 오므로 CSV를 더 붙일 일이 드물지만,
        # 붙인다면 그 CSV도 이 장비에만 붙어야 한다.
        _did = _config_sha(data["config_text"])
        app.config['device_id'] = _did
        from app.services import device_store as _store
        _store.upsert_device(
            _did, name=(parsed.get("meta") or {}).get("hostname") or device.get("ip", "device"),
            config_filename=app.config['last_config_filename'],
            config_text=data["config_text"],
            config_sha256=_hashlib_sha256_bytes(
                data["config_text"].encode("utf-8", "ignore")))
        _saved = _store.get_device(_did) or {}
        # 사용량 출처도 **이 장비의 것**만 싣는다. 수집분은 장비에서 직접
        # 받아온 값이라 CSV 파일이 아니고, 이 장비에 예전에 붙여 둔 CSV가
        # 있으면 그것만 근거로 남는다.
        app.config['csv_meta'] = _saved.get("csv_meta") or []
        # 새 장비를 수집하면 이전 장비의 DNS 스냅샷은 무효다. 업로드 경로와
        # 같은 불변식 — 수집이 FQDN을 못 가져왔다고 이전 캐시를 남기면
        # 장비 A의 해석으로 장비 B를 판정하는 오탐이 난다(재비판 NEW-BUG).
        #
        # **이 초기화가 보관보다 먼저 와야 한다.** 순서가 뒤집혀 있던 동안에는
        # 직전 장비의 해석이 이 장비 행에 저장되고, 정작 이 장비가 준 해석은
        # 저장되지 않았다(라운드 14 실측). fqdn_cache의 map은 도달불가 판정에
        # 들어가는 입력이므로, 남의 해석으로 이 장비 정책이 '가려짐'으로
        # 증명될 수 있다.
        app.config.pop('fqdn_cache', None)
        if data["fqdn_map"]:
            app.config['fqdn_cache'] = {
                "map": data["fqdn_map"],
                "captured_at": _dt.now().strftime("%Y-%m-%d %H:%M"),
                # 어느 VDOM 스코프로 수집했는가 — vdom-dns 반전 게이트의 입력
                "source_vdom": str(data.get("fqdn_scope_vdom") or ""),
            }
        # 수집분은 방금 장비에서 받아온 값이 최신이다 — 보관된 통계로 덮지 않는다.
        # FQDN은 **빈 값이어도 쓴다**. 안 쓰면 이번 수집이 해석을 못 가져왔을 때
        # 옛 스냅샷이 행에 남아, 수집 직후 화면(커버리지 없음)과 Open 했을 때
        # (옛 해석 복원)의 근거가 갈린다.
        app.config['collect_coverage'] = data.get("stats_coverage") or {}
        _store.update_device_inputs(
            _did, runtime_stats=data["runtime_stats"],
            fqdn_cache=app.config.get('fqdn_cache') or {},
            collect_coverage=app.config['collect_coverage'])
        app.config['user_ranges'] = _saved.get("user_ranges") or []
        from app.services.policy_renderer import build_view_model as _bvm
        view = _bvm(parsed, data["runtime_stats"])
        warnings = list(data["warnings"])
        if not device.get("verify_ssl", True):
            warnings.insert(0, "TLS verification was disabled for this "
                            "collection — the API token traveled over an "
                            "unverified channel")
        return jsonify({
            "ok": True,
            "hostname": (parsed.get("meta") or {}).get("hostname", ""),
            "config_sha": _config_sha(data["config_text"]),
            "device_id": app.config['device_id'],
            "device_name": (parsed.get("meta") or {}).get("hostname")
                           or device.get("ip", "device"),
            "policies": len(view.get("firewall_policy", [])),
            # 화면은 이 값으로 "사용량 데이터가 있는가"를 판단한다. 개수만 주고
            # 본문을 빼면, 장비에서 통계를 잘 받아온 직후에도 화면은 "사용량
            # 없음"이라고 경고한다(재비판 3회전).
            "runtime_stats": data["runtime_stats"],
            # 종류별로 나뉘어 있으므로 합계를 센다(예전엔 평평한 dict였다).
            "stats_count": _stats_count(data["runtime_stats"]),
            "fqdn_count": len(data["fqdn_map"]),
            "warnings": warnings,
            "session": _device_session(),
            "view": view,
            "parsed": parsed,
        })

    # ── FQDN 캐시 (B-10) — dnsproxy 덤프로 FQDN 정책 판정 포함 ────────────
    def _fqdn_vdom_dns_warning(scope: str = "") -> str:
        """vdom-dns 를 켠 VDOM 이 있으면 그 제외 사실을 말하는 경고(없으면 "").

        수집 경로(collect_from_device)만 경고하고 이 두 경로(덤프 업로드·
        단독 조회)는 침묵해, 화면이 "Applied — assessed" 라고만 말했다
        (라운드 65, 3렌즈 수렴 — 주석은 warning 필드를 약속했는데 미구현).
        """
        _vdd = [v for v in (((app.config.get('last_parsed') or {})
                             .get("meta") or {}).get("vdom_dns_vdoms")
                            or []) if v]
        if not _vdd:
            return ""
        _sc = str(scope or "").strip()
        if _sc and _sc.lower() in {v.lower() for v in _vdd}:
            # 스냅샷이 자체 DNS VDOM 의 해석 → 적용 방향이 반전된다
            # (라운드 70, Jayden 승인).
            return (f"This snapshot was collected from VDOM '{_sc}', which "
                    "uses its own DNS (vdom-dns) — it is used as evidence "
                    "for FQDN objects in that VDOM only; FQDN objects in "
                    "other VDOMs stay unproven.")
        return ("VDOM(s) with their own DNS settings (vdom-dns): "
                + ", ".join(_vdd)
                + " — this snapshot is not used as evidence for FQDN objects "
                "in those VDOMs (their resolution may differ); those "
                "policies stay unproven.")

    @app.post("/api/fqdn-cache/import")
    def fqdn_cache_import():
        # FQDN 해석은 도달불가 판정에 들어가는 **판정 입력**이다 — 대역·CSV와
        # 같은 게이트를 지난다.
        from app.parsers.fqdn_cache_parser import parse_dnsproxy_dump
        uploaded = request.files.get("dump")
        if not uploaded:
            return jsonify({"error": "dump file is required — output of "
                            "'diagnose test application dnsproxy 6'"}), 400
        text = uploaded.read().decode("utf-8-sig", errors="ignore")
        mapping = parse_dnsproxy_dump(text)
        if not mapping:
            # 왜 실패했는지 알 수 있게 진단을 함께 준다. "인식 못 했다"만
            # 던지면 사용자가 파일이 잘못된 건지 도구가 못 읽는 건지 모른다.
            lines = text.splitlines()
            import re as _re
            has_dom = any(_re.search(r'[A-Za-z0-9\-]+\.[A-Za-z]{2,}', ln)
                          for ln in lines[:2000])
            has_ip = any(_re.search(r'\d{1,3}(?:\.\d{1,3}){3}', ln)
                         for ln in lines[:2000])
            hint = ("The file has domains and IPs but not in a layout this "
                    "parser recognizes — please send a few sample lines so "
                    "it can be supported."
                    if (has_dom and has_ip) else
                    "The file does not appear to contain FQDN entries. Run "
                    "'diagnose test application dnsproxy 6' (or 'diagnose "
                    "firewall fqdn list') and save the full console output.")
            return jsonify({
                "error": f"No FQDN→IP entries recognized. {hint}",
                # 두 갈래는 **서로 다른 문장**이라 사전 키도 갈라야 한다 —
                # 이어붙인 결과 하나를 키로 삼으면 어느 쪽도 못 맞춘다.
                "error_key": ("fqdn_unknown_layout" if (has_dom and has_ip)
                              else "fqdn_no_entries"),
                "diagnostics": {"lines": len(lines),
                                "domains_seen": has_dom,
                                "ipv4_seen": has_ip},
            }), 400
        app.config['fqdn_cache'] = {
            "map": mapping,
            "captured_at": _dt.now().strftime("%Y-%m-%d %H:%M"),
        }
        # FQDN 해석도 그 장비의 입력이다 — 보관소에 함께 남긴다.
        if app.config.get('device_id'):
            from app.services import device_store as _store
            _store.update_device_inputs(app.config['device_id'],
                                        fqdn_cache=app.config['fqdn_cache'])
        _w = _fqdn_vdom_dns_warning()
        return jsonify({"ok": True, "names": len(mapping),
                        "ips": sum(len(v) for v in mapping.values()),
                        "captured_at": app.config['fqdn_cache']["captured_at"],
                        **({"warning": _w} if _w else {})})

    @app.post("/api/fqdn-cache/fetch-device")
    def fqdn_cache_fetch_device():
        """연결된 장비에서 FQDN 해석만 가져온다 — 덤프 파일 없이."""
        payload = request.get_json(silent=True) or {}
        device, err = _resolve_device(payload)
        if err:
            return err
        # FQDN 해석의 VDOM 경계는 config 의 vdom-dns 사실로 판정한다
        # (라운드 64, Jayden 승인 — 라운드 57 의 409 일괄 차단을 대체).
        # 적용부(reachability.build_address_map)가 vdom-dns 를 켠 VDOM 의
        # FQDN 객체를 환원에서 제외하므로 수집 자체는 안전하다. 켠 VDOM 이
        # 있으면 그 사실을 응답 warning 으로 싣는다(라운드 66 — 주석만 있고
        # 필드가 없어 화면이 "Applied — assessed" 라고만 말했다).
        from app.services.device_collector import fetch_fqdn_map
        import requests as _req
        # vdom 모드 장비(단일 VDOM 포함)는 스코프 없는 조회가 빈 결과를 줄 수
        # 있다(OA 실장비 실측) — 열린 config 가 vdom 모드면 등록 VDOM(없으면
        # 유일 VDOM)으로 스코프를 지정한다.
        _cfg_vd = [v for v in (((app.config.get('last_parsed') or {})
                                .get("meta") or {}).get("vdoms") or []) if v]
        _dev_vd = str((device or {}).get("vdom") or "").strip()
        _scope = ""
        if _cfg_vd:
            _scope = (_dev_vd if _dev_vd and _dev_vd.lower()
                      in {v.lower() for v in _cfg_vd}
                      else (_cfg_vd[0] if len(_cfg_vd) == 1 else ""))
        try:
            mapping = fetch_fqdn_map(
                device, _scope,
                allow_unscoped_fallback=(len(_cfg_vd) <= 1))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except _req.exceptions.SSLError:
            return jsonify({"error": "TLS verification failed."}), 502
        except _req.exceptions.RequestException:
            return jsonify({"error": "Could not reach the device."}), 502
        if not mapping:
            return jsonify({"error": "The device reported no resolved FQDN "
                            "addresses. FQDN objects resolve only after they "
                            "have been used."}), 400
        app.config['fqdn_cache'] = {
            "map": mapping,
            "captured_at": _dt.now().strftime("%Y-%m-%d %H:%M"),
            # 어느 VDOM 스코프로 수집했는가 — vdom-dns 반전 게이트의 입력
            "source_vdom": _scope,
        }
        # FQDN 해석도 그 장비의 입력이다 — 보관소에 함께 남긴다.
        if app.config.get('device_id'):
            from app.services import device_store as _store
            _store.update_device_inputs(app.config['device_id'],
                                        fqdn_cache=app.config['fqdn_cache'])
        _w = _fqdn_vdom_dns_warning(_scope)
        return jsonify({"ok": True, "names": len(mapping),
                        "ips": sum(len(v) for v in mapping.values()),
                        "captured_at": app.config['fqdn_cache']["captured_at"],
                        **({"warning": _w} if _w else {})})

    # ── 감사 증적 (B-06) — 스냅샷 시계열 → Review Evidence ────────────────
    @app.post("/api/audit/timeline")
    def audit_timeline():
        from app.services import audit_evidence as ae
        files = request.files.getlist("snapshots")
        if len(files) < 2:
            return jsonify({"error": "Upload at least two config snapshots, "
                            "oldest first."}), 400
        if len(files) > 24:
            return jsonify({"error": "At most 24 snapshots per timeline."}), 400
        snaps, parsed_list, raw_list = [], [], []
        for f in files:
            raw = f.read()
            # **네 번째 통로.** 업로드·비교·배치에는 문턱을 뒀는데 여기엔
            # 없어서, 회의록 텍스트 두 개로 서명란이 있는 PCI-DSS 증적
            # 워크북이 만들어졌다(라운드 47 실측).
            _txt = raw.decode("utf-8-sig", errors="ignore")
            _bad = config_intake_problem(_txt)
            if _bad:
                return jsonify({
                    "error": f"Snapshot '{f.filename or '?'}' cannot be used. "
                             f"{_bad[0]}",
                    "error_key": "snapshot_unusable",
                    "file": f.filename or "?", "detail": _bad[0]}), 400
            try:
                parsed = FortiGateConfigParser(_txt).parse()
            except Exception:
                return jsonify({"error": f"Could not parse snapshot "
                                f"'{f.filename}'.",
                                "error_key": "snapshot_unparsable",
                                "file": f.filename or ""}), 400
            snaps.append(ae.snapshot_meta(f.filename or "", raw, parsed))
            parsed_list.append(parsed)
            # 원문 훑기(모든 `config` 구역 비교)가 이 경로에서도 동작하려면
            # 파싱 결과만이 아니라 원문도 들고 있어야 한다.
            raw_list.append(raw.decode("utf-8-sig", errors="ignore"))
        intervals = []
        for i in range(len(parsed_list) - 1):
            diff = _compute_config_diff(
                parsed_list[i], parsed_list[i + 1],
                raw_list[i], raw_list[i + 1])
            intervals.append({
                "from": snaps[i]["filename"],
                "to": snaps[i + 1]["filename"],
                "summary": ae.interval_summary(diff),
            })
        timeline = {"snapshots": snaps, "intervals": intervals}
        # 서로 다른 방화벽의 스냅샷이 섞이면 '변경 0건'은 의미가 없다. 서버는
        # hostname 을 정확히 파싱해 두고도 말하지 않았다 — 화면이 만들자마자
        # 알 수 있게 응답에 싣는다(산출물 표지에도 같은 사실이 적힌다).
        _hosts = sorted({s.get("hostname") for s in snaps if s.get("hostname")})
        if len(_hosts) > 1:
            timeline["mixed_devices"] = _hosts
        else:
            # **이름이 하나라고 장비가 하나인 것은 아니다.** 두 고객이 둘 다
            # 'FGT-HQ' 를 쓰거나 스냅샷에 hostname 줄이 없으면, 이 문서는
            # '한 장비의 변경 이력'이라고 단정할 근거가 없다 — 서명란이 있는
            # 문서다(라운드 29 지적). 추측 대신 아는 것을 표지에 적는다.
            # 스냅샷 일부에만 hostname 이 있으면 '전부 같은 이름을 보고했다'는
            # 사실이 아니다 — 서명란이 있는 문서다(라운드 30 실측).
            _named = sum(1 for s in snaps if s.get("hostname"))
            timeline["same_name_unverified"] = {
                "hostname": _hosts[0] if _hosts else "",
                "reason": ("no_hostname" if not _hosts
                           else "same_name" if _named == len(snaps)
                           else "one_hostname"),
                "named": _named, "total": len(snaps),
            }
        # 증적 export가 같은 데이터를 쓰도록 보관 (재업로드 불필요)
        app.config['last_audit_timeline'] = timeline
        return jsonify(timeline)

    @app.post("/api/audit/evidence-workbook")
    def audit_evidence_workbook():
        gate = _license_required()   # 감사 산출물 = 유료 export 계열
        if gate:
            return gate
        timeline = app.config.get('last_audit_timeline')
        if not timeline:
            return jsonify({"error": "Run the snapshot timeline first."}), 400
        from app.services import audit_evidence as ae
        rm = {"apo_version": APO_VERSION,
              "generated_at": _dt.now().strftime("%Y-%m-%d %H:%M")}
        # 스냅샷은 업로드한 파일들이라 특정 고객의 것이라 단정할 수 없다 —
        # 회사명만 싣는다.
        _b = _branding_for("")
        if _b:
            rm["branding"] = _b
        try:
            xlsx = ae.build_evidence_workbook(timeline, rm)
        except Exception as exc:
            print(f"[APO] evidence workbook failed: {exc}", flush=True)
            return jsonify({"error": "Failed to build evidence workbook"}), 400
        # **파일명도 표지와 같은 사실을 말해야 한다.** 서로 다른 방화벽의
        # 스냅샷으로 만든 문서인데 파일명은 열려 있는 장비 한 대만 댔다 —
        # 표지를 열기 전까지는 한 장비의 변경 이력으로 읽힌다(라운드 26 지적).
        _mixed = timeline.get("mixed_devices")
        if _mixed:
            _label = "MIXED_" + "_".join(_mixed[:2]) + ("_외" if len(_mixed) > 2 else "")
        else:
            # **파일명은 이 문서가 다룬 장비를 대야 한다.** 열려 있는 장비
            # 이름을 붙였더니, DEMO-FGT-01 을 연 채 BROKEN-FGT 스냅샷으로
            # 만든 문서가 `apo_review_evidence_DEMO-FGT-01.xlsx` 로 떨어졌다 —
            # 표지와 Snapshots 시트 전 행은 BROKEN-FGT 인데(라운드 43 실측).
            # 서명란과 PCI-DSS 인용이 있는 문서이고, 컨설턴트의 폴더에서
            # 다른 고객 것으로 정리될 수 있다.
            # 스냅샷이 이름을 말하면 그것을 쓰고, 없으면 날짜로 둔다.
            _snap_hosts = sorted({s.get("hostname") for s in
                                  (timeline.get("snapshots") or [])
                                  if s.get("hostname")})
            _label = (_snap_hosts[0] if _snap_hosts
                      else _date.today().isoformat())
        return app.response_class(
            response=xlsx, status=200,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition":
                     _attachment(f"apo_review_evidence_{_label}.xlsx")})

    # ── Version Advisor ────────────────────────────────────────────────────
    @app.get("/api/version-advisor")
    def version_advisor():
        # 이 장비의 펌웨어·활성 기능·CVE 목록도 그 고객의 정보다.
        from app.services.version_advisor import run_advisor
        parsed = app.config.get('last_parsed')
        if not parsed:
            return jsonify({"error": "No config loaded. Upload a config file first."}), 400
        meta = parsed.get("meta", {})
        raw_config = app.config.get('last_raw_config', '')
        result = run_advisor(meta, raw_config)
        return jsonify(result)

    # ── 구 대역 잔존 참조 (Re-IP 1단계) ──────────────────────────────────
    @app.post("/api/ip-references")
    def ip_references():
        """이 IP/대역을 참조하는 곳이 어디인가.

        **판정에 손대지 않는다.** severity 파이프라인을 호출하지도, 그
        입력을 바꾸지도 않는다. 원문만 읽는 순수 신규 경로다.

        원문을 훑는 이유: 파서는 15개 섹션만 읽는데 IP 대역 변경이 건드릴
        `router static`(게이트웨이)·`vpn ipsec`(local-gw)·`system dns`·
        `log syslogd` 는 전부 그 밖이다.
        """
        from app.services.ip_reference_scanner import scan

        raw_config = app.config.get('last_raw_config', '')
        if not raw_config:
            # 서버 문장은 영어로 두고 사전이 번역한다 — 값이 끼지 않는 문장은
            # 그 자체가 사전 키다(tests/test_server_error_i18n.py 가 강제).
            return jsonify({"error": "No config loaded. Upload a config file first."}), 400

        # 본문 자체가 딕셔너리가 아닐 수 있다(`[1,2]`·`"x"`·`3` 도 유효한 JSON).
        _body = request.get_json(silent=True)
        payload = _body if isinstance(_body, dict) else {}
        # **타입을 먼저 본다.** `(x or "").strip()` 은 x 가 숫자·리스트·dict 면
        # AttributeError 로 500 이 된다. 이 라우트가 스스로 "사용자 입력
        # 오류에 500 을 주면 안 된다"고 적어 놓은 것과 어긋난다.
        _t = payload.get("target")
        target = _t.strip() if isinstance(_t, str) else ""
        try:
            # 마이그레이션 경로와 **같은 방식으로** 쪼갠다 - 갈리면 이
            # 표의 줄 번호가 실제로 바뀌는 줄과 어긋난다.
            result = scan(_split_config(raw_config)[0], target)
        except ValueError as exc:
            # 사용자가 잘못 입력한 것이지 서버 오류가 아니다 — 500 을 주면
            # 화면이 "알 수 없는 오류"를 띄우고 사용자는 뭘 고칠지 모른다.
            return jsonify({"error": str(exc)}), 400

        # **상한이 없으면 20 MiB 를 보낸다**(실측: `0.0.0.0/0` → 23,550건,
        # 20.18 MiB, 약 19만 DOM 노드). 넓은 대역을 넣는 것은 가상의 입력이
        # 아니라 관리자가 "일단 다 보자"로 실제로 하는 일이다.
        #
        # 잘라내면 반드시 **잘랐다고 말한다.** 조용히 자르면 관리자는 그게
        # 전부라고 믿는다 — 이 기능에서 가장 위험한 실패는 "덜 보여주고
        # 다 보여준 척"이다.
        LIMIT = 5000
        refs = result.references

        # **줄 순서로 자르면 안 된다.** 락아웃 경고가 파일 뒤쪽에 있으면
        # 잘려 나가고, 그러면 이 기능에서 가장 위험한 정보가 조용히 사라진다
        # (실측: `0.0.0.0/0` → 참조 23,550건 중 락아웃 50건).
        # 중요한 것부터 남기고, 같은 등급 안에서는 줄 순서를 지킨다.
        #
        # **화면(app.js ROLE_UI 의 rank)과 같은 순서여야 한다.** 두 곳이
        # 갈리면 "상위 5,000건"이 화면 정렬과 다른 것을 가리켜 표가 뒤섞인다.
        # 역할을 추가하면 두 곳을 함께 고쳐야 한다.
        _RANK = {"value": 1, "object_name": 2, "name_reference": 3, "comment": 4}
        ordered = sorted(
            refs,
            key=lambda r: (0 if r.is_admin_access else 1,
                           _RANK.get(r.role, 9),
                           r.line_no),
        )
        shown = ordered[:LIMIT]

        # **화면이 채울 칸은 참조 수가 아니라 서로 다른 IP 수다.**
        # 실측: `/24` 하나에 참조 1,291건인데 서로 다른 IP 는 139개다.
        # 참조 목록을 그대로 주고 화면이 묶게 하면, 상한(5,000)에 잘린
        # 경우 호스트 목록이 불완전해진다. 전체 참조에서 서버가 만든다.
        hosts: dict[str, dict] = {}
        for r in refs:
            ip = r.matched.split("/")[0]
            h = hosts.setdefault(ip, {"ip": ip, "refs": 0, "must_change": 0,
                                      "lockout": False, "supernet": False,
                                      "sections": set()})
            h["refs"] += 1
            # **매칭 종류를 함께 본다.** 역할만 보면 상위 대역도 "반드시
            # 바꿔야 함"으로 세는데, 마이그레이션 엔진은 정확히 그 반대로
            # 상위 대역을 골라 **손대지 않는다**. 그래서 2단계 표가 입력칸을
            # 내주고, 사용자가 채우면 3단계가 조용히 무시하고, 차단도 안 하고
            # 200 으로 파일을 준다 — 관리자는 그 객체가 이전됐다고 믿는다.
            if r.match_kind in ("supernet", "overlap"):
                h["supernet"] = True
            elif r.role == "value":
                h["must_change"] += 1
            if r.is_admin_access:
                h["lockout"] = True
            h["sections"].add(r.section)

        def _host_json(h):
            return {"ip": h["ip"], "refs": h["refs"],
                    "must_change": h["must_change"], "lockout": h["lockout"],
                    # 화면이 이 행을 "손대지 않습니다"로 그리고 입력칸을
                    # 잠근다. 값을 못 넣게 하는 것이 경고보다 확실하다.
                    "supernet": h["supernet"] and not h["must_change"],
                    "sections": sorted(s for s in h["sections"] if s)[:4]}

        return jsonify({
            "target": target,
            "summary": result.summary(),
            # 락아웃 → 바꿀 값이 많은 순 → IP 순. 먼저 봐야 할 것이 위로.
            "hosts": [_host_json(h) for h in sorted(
                hosts.values(),
                key=lambda h: (0 if h["lockout"] else 1, -h["must_change"],
                               [int(p) for p in h["ip"].split(".")]))],
            "truncated": len(refs) > LIMIT,
            "shown_count": len(shown),
            # **"반드시 바꿔야 할 값"이 상한을 넘으면 그 손실을 말해야 한다.**
            # 요약은 전체(예: 5,790)를 말하는데 표에는 5,000행만 있으면
            # 사용자는 790건이 어디 갔는지 알 길이 없다. 배너가 "5,790건 중
            # 5,000건 표시"라고 쓸 수 있도록 표시분 기준 수를 함께 내린다.
            "shown_must_change": sum(
                1 for r in shown
                if r.role == "value"
                and r.match_kind not in ("supernet", "overlap")),
            "references": [{
                "line_no": r.line_no,
                "location": r.location,
                "vdom": r.vdom,
                "section": r.section,
                "edit": r.edit,
                "field": r.field,
                "value": r.display,
                "match_kind": r.match_kind,
                "role": r.role,
                "is_admin_access": r.is_admin_access,
                # `raw_line` 은 싣지 않는다. 화면이 쓰지 않는데 응답의 61%를
                # 차지했다(12.4 MiB / 20.2 MiB). 실 파일에 10,026바이트짜리
                # 한 줄이 있고 그 줄의 참조 308건이 각자 전문을 복사해 날랐다.
                # 원문이 필요하면 line_no 로 찾으면 된다.
            } for r in shown],
        })

    # ── 설정 마이그레이션 (Re-IP 2단계) ──────────────────────────────────
    _MIG_LIMIT = 5000

    def _split_config(raw):
        """줄바꿈을 **원본 그대로 되돌릴 수 있게** 쪼갠다.

        `str.splitlines()` 를 쓰면 두 가지가 조용히 깨진다 — 이 기능의
        존재 이유가 "매칭된 구간 외의 바이트는 안 건드린다"인데 둘 다
        그 약속을 정면으로 깬다.

        - **CRLF 가 전멸한다.** FortiGate GUI 로 받은 백업은 CRLF 다
          (보유 샘플 105개 중 16개). `splitlines()` -> `"\n".join()` 은
          파일 전체를 LF 로 재조립하므로 우리가 한 줄도 안 고쳐도 모든
          줄이 바뀐다. 실측: 서버는 "308줄 변경"이라 보고했는데 실제로
          달라진 줄은 **4,438줄 전부**였다. 4단계가 시키는 원본 대조가
          통째로 무의미해진다.
        - **값 안의 제어문자가 진짜 개행이 된다.** `splitlines()` 는
          `\x0b \x0c \x1c \x1d \x1e \x85 \u2028 \u2029` 에서도
          자른다. `set alias "page\x0cbreak"` 한 줄이 두 줄이 되면
          따옴표가 안 닫혀 그 뒤 파싱이 어긋난다 - 이 도구가 경고하는
          바로 그 사고를 **우리가 손도 안 댄 줄에서** 일으킨다.

        끝 개행 유무도 기억한다(없던 파일에 붙이지 않는다).
        """
        if not raw:
            return [], [], False
        trailing = raw.endswith("\n")
        body = raw[:-1] if trailing else raw
        parts = body.split("\n")
        had_cr = [seg.endswith("\r") for seg in parts]
        return ([seg[:-1] if cr else seg for seg, cr in zip(parts, had_cr)],
                had_cr, trailing)

    def _join_config(lines, had_cr, trailing):
        """`_split_config` 의 역연산. 원본 줄바꿈을 그대로 복원한다."""
        out = "\n".join(ln + ("\r" if cr else "")
                        for ln, cr in zip(lines, had_cr))
        return out + ("\n" if trailing else "")

    def _mig_inputs():
        """공통 입력 파싱. 실패하면 (None, 응답) 을 준다."""
        from app.services.ip_migration import parse_mapping

        raw_config = app.config.get('last_raw_config', '')
        if not raw_config:
            return None, (jsonify(
                {"error": "No config loaded. Upload a config file first."}), 400)

        _body = request.get_json(silent=True)
        payload = _body if isinstance(_body, dict) else {}
        _t = payload.get("target")
        target = _t.strip() if isinstance(_t, str) else ""
        try:
            mapping = parse_mapping(payload.get("mapping"))
        except (ValueError, TypeError) as exc:
            # 사용자가 잘못 넣은 것이지 서버 오류가 아니다.
            # **값이 끼는 문장은 사전 키가 될 수 없다** — 서버는 값만 보내고
            # 원문은 화면의 SERVER_ERRORS 가 만든다(이 레포의 관례).
            return None, (jsonify({
                "error": f"Invalid mapping: {exc}",
                "error_key": "migration_bad_mapping",
                "detail": str(exc)}), 400)
        return (raw_config, target, mapping, payload), None

    def _blocking_for(plan):
        """계획의 차단 + **인입 단계의 손실**.

        디코딩에서 버려진 바이트는 엔진이 알 수 없다(엔진은 문자열만 본다).
        라우트가 얹는다 — 그래야 토큰·확인·화면 표시가 한 목록을 쓴다.
        """
        out = list(plan.blocking)
        if app.config.get('last_config_decode_lost'):
            out.append("encoding_lossy")
        return out

    def _ack_token(target, mapping, blocking, name_mapping=None):
        """확인이 유효한 범위를 묶는 토큰.

        (대상 + 매핑 + **이름 매핑** + 차단 목록) 이 하나라도 달라지면
        토큰이 달라져 앞서 켠 확인이 자동으로 무효가 된다. **계획·적용 두
        라우트가 같은 값을 내야** 한다 — 계획에서 받은 토큰으로 적용이
        통과해야 하기 때문이다.

        **이름 매핑도 반드시 들어간다.** 빼면 사용자가 이름 하나를 확인한
        뒤 다른 이름으로 바꿔 적용해도 옛 확인이 통과한다 — 확인이 무엇에
        대한 것인지 알 수 없게 된다.
        """
        import hashlib as _hl
        canon = json.dumps(
            {"t": target,
             "m": sorted((k, v) for k, v in mapping.items()),
             "n": _canon_name_mapping(name_mapping),
             "b": sorted(blocking)},
            sort_keys=True, default=str)
        return _hl.sha256(canon.encode("utf-8")).hexdigest()[:32]

    def _canon_name_mapping(name_mapping):
        """이름 매핑을 토큰에 넣을 수 있게 정규화한다.

        화면이 보내는 형태(빈 TO-BE 포함, 순서 임의)가 그대로 오므로,
        **실제로 이름을 바꾸는 항목만** 정렬해 담는다. 빈 칸이 토큰을
        흔들면 아무것도 안 고쳤는데 확인이 풀린다.
        """
        out = []
        for item in (name_mapping or []):
            if not isinstance(item, dict):
                continue
            old = (item.get("old") or "").strip()
            new = (item.get("new") or "").strip()
            if old and new and new != old:
                out.append([item.get("vdom"), old, new])
        return sorted(out, key=lambda x: (str(x[0]), x[1]))

    def _renamed_index(plan):
        """(vdom, 옛 이름) → 새 이름. **적용이 실제로 쓰는 값**이다.

        새 이름을 여기서 다시 계산하면 안 된다 — `build_plan` 은 이름 안에
        대상 IP 가 둘 이상일 때 **오른쪽부터** 치환한다. 순진하게 replace 로
        만들면 그 경우 파일과 다른 이름을 표에 적게 되고, 표를 결재에 올린
        사람이 없는 이름을 승인하게 된다.
        """
        return {(d.get("vdom"), d.get("old")): d.get("new")
                for d in (plan.renamed_names or [])}

    def _row_json(row, renamed=None):
        r = row.ref
        # **이름 행은 이름 '조각'이 아니라 객체 이름 '전체'를 보여야 한다.**
        #   WHERE: edit "208.97.24.208/32_MingleProxy"
        #   AS-IS: 208.97.24.208/32      ← 조각
        #   TO-BE: 12.1.1.208/32         ← 조각. 실제 결과는
        #                                  12.1.1.208/32_MingleProxy 다.
        # 표만 보면 객체 이름이 `12.1.1.208/32` 가 되는 것으로 읽힌다.
        # 승인자가 이 표를 캡처해 결재에 올리면 **존재하지 않는 이름**을
        # 승인하는 셈이다(실사용 보고, 2026-09-08).
        _old_name = (getattr(r, "enclosing_name", None)
                     if r.role == "object_name" else None)
        _new_name = (renamed or {}).get((r.vdom, _old_name)) if _old_name else None
        return {
            "line_no": r.line_no,
            "location": r.location,
            "section": r.section,
            "edit": r.edit,
            "field": r.field,
            "role": r.role,
            "is_admin_access": r.is_admin_access,
            "action": row.action,
            "as_is": row.old_text,
            "to_be": row.new_text,
            # 이름 행에서만 채운다. 화면은 `as_is_display || as_is` 로 쓴다.
            "as_is_display": _old_name if _new_name else None,
            # **AS-IS 는 마스크를 포함하는데 TO-BE 는 IP 만이었다.**
            #   AS-IS `10.20.40.6 255.255.255.255` → TO-BE `11.11.40.6`
            # 실제 산출 줄은 `set subnet 11.11.40.6 255.255.255.255` 로
            # 마스크가 보존되는데, 표만 보면 마스크가 지워지는 것처럼 읽힌다.
            # 승인자가 이 표를 캡처해 결재에 올리면 "이 변경은 /32 를 /0 으로
            # 만든다"가 된다. 바뀌지 않는 꼬리를 함께 보여 대칭을 맞춘다.
            "to_be_display": (
                _new_name if _new_name
                else None if row.new_text is None
                else row.new_text + r.display[len(r.matched):]
                if r.display.startswith(r.matched) else row.new_text),
            # **문장이 아니라 코드로 낸다.** 서버가 한국어 문장을 만들면
            # 화면이 번역할 수 없어 영어 사용자에게 그대로 뜬다(감사에서
            # 3,721건 실측). 화면이 이 코드를 자기 언어로 옮긴다.
            "reason": row.reason,
            "reason_arg": row.reason_arg,
            "warnings": row.warnings,
        }

    @app.post("/api/ip-migration/plan")
    def ip_migration_plan():
        """구 IP → 신 IP 매핑으로 변경 계획을 만든다. **아무것도 바꾸지 않는다.**"""
        from app.services.ip_migration import build_plan

        got, err = _mig_inputs()
        if err:
            return err
        raw_config, target, mapping, _payload_plan = got
        # 3단계에서 사용자가 지정한 객체 이름. 빈 TO-BE 는 "변경 안 함"
        # 이지 삭제가 아니다 — 엔진이 걸러낸다.
        _name_map = _payload_plan.get("name_mapping") if isinstance(_payload_plan, dict) else None
        try:
            # **apply 와 같은 방식으로 쪼개야 한다.** 한쪽만 splitlines
            # 를 쓰면 값 안에 제어문자가 있는 config 에서 줄 번호가
            # 갈려, 미리보기가 가리키는 줄과 실제로 바뀌는 줄이 달라진다.
            plan = build_plan(_split_config(raw_config)[0], target, mapping,
                              name_mapping=_name_map)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        rows = plan.rows
        shown = rows[:_MIG_LIMIT]
        # **차단 목록은 한 곳에서 나와야 한다.** 요약이 엔진 목록만 쓰면
        # 인입 손실이 요약에서 빠져, 같은 응답 안에서 토큰·확인과 어긋난다.
        _summary = plan.summary()
        _summary["blocking"] = _blocking_for(plan)
        return jsonify({
            "target": target,
            "summary": _summary,
            "truncated": len(rows) > _MIG_LIMIT,
            "shown_count": len(shown),
            "rows": [_row_json(r, _renamed_index(plan)) for r in shown],
            # **미리보기에서 토큰을 준다.** 적용 응답에서만 주면, 확인을
            # 미리 켜고 누른 첫 클릭이 무조건 409 로 튕기고 화면은 "아래
            # 확인 칸을 켜세요"(이미 켜 놓은 것)라고 말한다. 사용자가
            # 배우는 교훈이 "두 번 누르면 된다"가 된다.
            "ack_token": _ack_token(target, mapping, _blocking_for(plan),
                                    _name_map),
            "decode_lost_bytes": app.config.get('last_config_decode_lost', 0),
        })

    @app.post("/api/ip-migration/apply")
    def ip_migration_apply():
        """바뀐 config 를 만들어 내려준다.

        **미매핑이 남아 있으면 막는다.** 구 대역에 있는데 매핑표에 없는 IP 는
        '폐기'인지 '빠뜨린 것'인지 도구가 알 수 없다. 조용히 진행하면 ISP
        전환에서 IP 하나를 놓쳐 그 서버가 죽는다. 사용자가 폐기임을
        확인(`confirm_unmapped`)해야 통과시킨다.
        """
        from app.services.ip_migration import (
            apply_plan, build_plan, reverse_mapping, verify)

        got, err = _mig_inputs()
        if err:
            return err
        raw_config, target, mapping, payload = got
        # 3단계에서 사용자가 지정한 객체 이름. 빈 TO-BE 는 "변경 안 함"
        # 이지 삭제가 아니다 — 엔진이 걸러낸다.
        _name_map = payload.get("name_mapping") if isinstance(payload, dict) else None
        lines, had_cr, trailing = _split_config(raw_config)
        try:
            plan = build_plan(lines, target, mapping, name_mapping=_name_map)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # **막아야 할 것이 미매핑 하나가 아니다.** 감사에서 확인된 것:
        # 신 IP 충돌(두 객체가 하나로 합쳐진다) · 이름 충돌(FortiOS 가 두 번째
        # `edit "X"` 를 첫 객체 편집으로 처리해 하나가 사라진다) · config 를
        # 끝까지 못 읽음(반쪽만 바뀐 파일이 "검증 통과"로 나갔다).
        # 사용자가 확인한 것만 통과시킨다.
        _ACK = {
            "unmapped": "confirm_unmapped",
            "retired": "confirm_unmapped",
            "new_ip_collision": "confirm_collisions",
            "name_collision": "confirm_collisions",
            "config_not_fully_read": "confirm_partial_read",
            "encoding_lossy": "confirm_partial_read",
        }
        # **확인은 그때 그 매핑에만 유효하다.** 화면의 체크박스는 한 번
        # 켜면 꺼지지 않았고, 사용자가 값을 고쳐 새 충돌이 생겨도 그 체크가
        # 살아 있어 **차단 5종 전부가 조용히 통과**했다(감사 실측).
        # 화면만 고치면 다른 클라이언트로 우회되므로 서버가 묶는다:
        # 확인은 이 매핑·이 대상·이 차단 목록에 대해 발급된 토큰과 함께
        # 와야 한다. 매핑이 바뀌면 토큰이 달라져 확인이 무효가 된다.
        _blocking = _blocking_for(plan)
        ack_token = _ack_token(target, mapping, _blocking, _name_map)
        _acked = payload.get("ack_token") == ack_token

        unacked = [b for b in _blocking
                   if not (_acked and payload.get(_ACK.get(b, "")))]
        if unacked:
            return jsonify({
                "error": "Some choices need confirming before APO will build "
                         "the file.",
                "error_key": "migration_blocked",
                "blocking": unacked,
                # 화면은 이것을 그대로 되보낸다. 값이 바뀌면 토큰도 바뀌므로
                # 옛 확인은 자동으로 무효가 된다.
                "ack_token": ack_token,
                "unmapped_ips": plan.unmapped_ips,
                "retired_ips": plan.retired_ips,
                "new_ip_collisions": plan.new_ip_collisions,
                "name_collisions": plan.name_collisions,
                "unterminated_quote_line":
                    plan.summary()["unterminated_quote_line"],
                "decode_lost_bytes":
                    app.config.get('last_config_decode_lost', 0),
                "needs_confirmation": True,
            }), 409

        new_lines = apply_plan(lines, plan)
        # **자기 산출물을 자기가 검사한다.** 계획을 함께 넘겨야 "바꾸겠다고
        # 한 것이 실제로 바뀌었나"까지 본다 — 안 넘기면 스왑/순열에서
        # 아무것도 안 바뀌어도 통과한다(감사 실측).
        check = verify(new_lines, target, mapping, plan)

        changed = sum(1 for a, b in zip(lines, new_lines) if a != b)
        # 계획과 같은 목록을 쓴다 — 갈리면 두 응답이 다른 말을 한다.
        _sum = plan.summary()
        _sum["blocking"] = _blocking
        return jsonify({
            "target": target,
            "summary": _sum,
            "changed_lines": changed,
            "total_lines": len(new_lines),
            "verification": check,
            "decode_lost_bytes": app.config.get('last_config_decode_lost', 0),
            "reverse_mapping": reverse_mapping(mapping),
            # 변경 계획을 파일로 받을 수 있어야 한다 — 승인·감사·인수인계에
            # 쓰인다(FortiManager 도 Install Preview 를 텍스트로 내려준다).
            # 화면에만 있으면 새로고침 한 번에 사라진다.
            "rows": [_row_json(r, _renamed_index(plan))
                     for r in plan.rows[:_MIG_LIMIT]],
            "rows_truncated": len(plan.rows) > _MIG_LIMIT,
            "config": _join_config(new_lines, had_cr, trailing),
            # 적용 후 반드시 확인해야 하는 것. FortiOS 는 편집된 config 의
            # 일부를 **조용히 버리면서도** 복원 성공을 표시한다(Fortinet 직원
            # 확인). 이 명령만이 그것을 드러낸다.
            "post_apply_check": "diagnose debug config-error-log read",
        })

    @app.post("/api/ip-migration/rename-candidates")
    def ip_migration_rename_candidates():
        """이름을 바꿀 수 있는 객체 목록. **아무것도 바꾸지 않는다.**

        대상 대역을 건드리는 객체만 준다 — 전 객체를 주면 수백 줄이라
        고를 수 없는 목록이 된다.

        **번호로 식별되는 것은 여기 없다.** `config firewall policy` 의
        `edit 101`, `config router static` 의 `edit 3` 은 이름이 아니라
        순번이라 바꿀 대상이 아니다. 섹션 이름을 목록으로 박지 않고
        `edit` 이 따옴표로 감싸였는지(`edit_quoted`)로 가른다 — FortiOS
        섹션은 버전마다 늘어서, 목록은 다음 섹션에서 조용히 뚫린다.
        """
        from app.services.ip_migration import rename_candidates

        got, err = _mig_inputs()
        if err:
            return err
        raw_config, target, mapping, _p = got
        try:
            rows = rename_candidates(_split_config(raw_config)[0], target, mapping)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({
            "target": target,
            "candidates": rows[:_MIG_LIMIT],
            "truncated": len(rows) > _MIG_LIMIT,
            "total": len(rows),
            # **주석·설명에 남은 옛 이름은 따라가지 않는다.** 설정값이 아니라
            # 사람이 읽는 메모라 참조 갱신에서 제외된다(`_FREE_TEXT_FIELDS`).
            # 고칠 것이 아니라 말해 줄 것이다.
            "free_text_note": True,
        })

    @app.post("/api/ip-migration/export/changes")
    def ip_migration_export_changes():
        """변경내역을 워크북으로 낸다 — 승인 결재와 감사에 올라가는 문서.

        예전에는 브라우저가 이 내용을 `.txt` 로 조립했는데, 화면 표가 쓰는
        표시값(`as_is_display`)이 아니라 원시값을 써서 **객체 이름의 조각과
        넷마스크가 지워진 값**이 결재에 올라갔다(`_row_json` 주석의
        2026-09-08 실사용 보고). 여기서 만들면 화면과 같은 값을 쓴다.

        **입력에서 다시 계산한다.** 브라우저가 들고 있던 표를 돌려받아 찍으면
        파일이 APO 의 판단을 증명하지 못한다(`/api/config/diff/export` 와 같은
        이유). 받는 것은 사용자가 넣은 매핑뿐이다.

        **라이선스 게이트를 걸지 않는다** — 마이그레이션은 무료다(B-85).
        유료 근거는 매출이 아니라 안전(장비에 쓴다)이고, 이것은 파일만 만든다.
        """
        from app.services.ip_migration import (apply_plan, build_plan,
                                               reverse_mapping, verify)
        from app.services.migration_exporter import (build_changes_csv,
                                                     build_migration_workbook)

        got, err = _mig_inputs()
        if err:
            return err
        raw_config, target, mapping, _payload = got
        # 3단계에서 사용자가 지정한 객체 이름. 빈 TO-BE 는 "변경 안 함"
        # 이지 삭제가 아니다 — 엔진이 걸러낸다.
        _name_map = _payload.get("name_mapping") if isinstance(_payload, dict) else None
        _fmt = str((_payload or {}).get("format") or "xlsx").lower()
        lines = _split_config(raw_config)[0]
        try:
            plan = build_plan(lines, target, mapping, name_mapping=_name_map)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # 확인(ack)을 요구하지 않는다 — 이건 검토용 문서다. 차단 사유가 있는
        # 상태야말로 승인자가 표를 보고 판단해야 하는 때이므로, 그때 파일을
        # 못 받게 하면 거꾸로다. 대신 그 사유는 Self-check 에 그대로 실린다.
        new_lines = apply_plan(lines, plan)
        check = verify(new_lines, target, mapping, plan)
        _sum = plan.summary()
        _sum["changed_lines"] = sum(1 for a, b in zip(lines, new_lines) if a != b)
        _sum["total_lines"] = len(new_lines)

        _renamed = _renamed_index(plan)
        _rows = [_row_json(r, _renamed) for r in plan.rows[:_MIG_LIMIT]]

        if _fmt == "csv":
            # 표 한 장만 필요한 경우 — ITSM·CMDB import, 스크립트 대사.
            # **xlsx 와 같은 `_row_display` 를 쓴다**(두 산출물이 다른 값을
            # 적으면 그게 이 작업이 고치려던 결함이다). BOM 은 한국 Excel 이
            # CP949 로 오독하지 않게 하는 유일한 장치다.
            return app.response_class(
                response=build_changes_csv(_rows), status=200,
                mimetype="text/csv; charset=utf-8",
                headers={"Content-Disposition": _attachment(
                    f"apo_migration_changes_{_open_device_label()}.csv")})

        # **`reverse_mapping()` 은 평평한 {신:구} 가 아니다.** 충돌을 조용히
        # 잃지 않으려고 `{pairs, collisions, retired}` 구조체를 준다. 그대로
        # 넘기면 Undo 시트의 '새 값' 칸에 `pairs`·`collisions` 라는 글자가
        # 찍히고 **되돌릴 옛 값이 통째로 사라진다** — 롤백 근거 문서가 거짓이
        # 된다(리뷰 게이트 correctness·spec 이 각각 잡았다).
        _rev = reverse_mapping(mapping)
        xlsx = build_migration_workbook(
            kind="IP renumbering",
            rows=_rows,
            summary=_sum,
            verification=check,
            mapping=mapping,
            # collisions 는 값이 목록이라 exporter 가 'ambiguous' 로 표시한다.
            reverse_mapping={**_rev["pairs"], **_rev["collisions"]},
            retired=_rev["retired"],
            renamed=[{"new": v, "old": k[1]} for k, v in _renamed.items()],
            rows_truncated=len(plan.rows) > _MIG_LIMIT,
            total_rows=len(plan.rows),
            source_name=app.config.get('last_config_filename') or "",
            source_sha256=app.config.get('last_config_sha256') or "",
            device_label=_open_device_label(),
            generated_at=_dt.now().strftime("%Y-%m-%d %H:%M"),
            post_apply_check="diagnose debug config-error-log read",
        )
        return app.response_class(
            response=xlsx, status=200,
            mimetype=('application/vnd.openxmlformats-officedocument'
                      '.spreadsheetml.sheet'),
            headers={"Content-Disposition": _attachment(
                f"apo_migration_changes_{_open_device_label()}.xlsx")})

    # ── 장비 이관 (모델·버전이 다른 장비로) ──────────────────────────────
    #
    # 벤더가 실제로 하는 작업 그대로다: **모델명·버전(헤더)**, **인터페이스
    # 배열**, **그 배열을 참조하는 객체·정책**을 바꾸고, **암호화된 설정은
    # 손대지 않고 그대로 옮긴다**(ENC 는 펌웨어 고정 키라 장비가 달라도
    # 동작한다 — 관리자가 private-data-encryption 을 켠 경우만 예외).
    #
    # **번역기가 아니다.** 버전 간 문법은 바꾸지 않는다 — Fortinet 자신의
    # 수동 절차 1번이 "먼저 펌웨어를 맞춰라" 이고, 버전별 스키마를 실물로
    # 검증할 방법이 없는 상태에서 흉내내면 조용히 틀린 config 를 만든다.

    def _target_lines():
        """대상(새) 장비 백업. 없으면 `None`."""
        raw = app.config.get('target_raw_config')
        return _split_config(raw)[0] if raw else None

    @app.post("/api/device-migration/target")
    def device_migration_target():
        """새 장비의 백업을 받는다. **공장초기 상태여도 된다** — 필요한
        것은 그 장비의 인터페이스 이름과 버전뿐이다.

        열린 장비(`last_raw_config`)는 **건드리지 않는다.** 이것은 비교
        대상일 뿐이고, 실수로 열린 장비를 갈아치우면 사용자는 자기가 무엇을
        이관하는지 잃는다.
        """
        from app.services.device_migration import read_header

        # **소스를 먼저 연 상태여야 한다.** 안 그러면 대상 백업은 200 으로
        # 받아 놓고 바로 뒤 사전점검이 "설정 파일을 먼저 올리세요"라고 한다 —
        # 방금 파일을 올린 자리 옆에서.
        if not app.config.get('last_raw_config', ''):
            return jsonify({
                "error": "Open the configuration you want to move first, "
                         "then upload the new device's backup here.",
                "error_key": "no_source_config"}), 400
        up = request.files.get("config_file")
        if not up:
            return jsonify({"error": "No config loaded. Upload a config file "
                                     "first."}), 400
        raw_bytes = up.read()
        if not raw_bytes.strip():
            return jsonify({"error": "That file is empty.",
                            "error_key": "empty_config"}), 400
        raw = raw_bytes.decode("utf-8-sig", errors="ignore")
        lines = _split_config(raw)[0]
        info = read_header(lines)
        if not info.known:
            # 헤더가 없으면 모델·버전을 알 수 없다 — 추측하지 않는다.
            return jsonify({
                "error": "That file has no config-version header, so APO "
                         "cannot tell which model and version it came from.",
                "error_key": "no_config_version"}), 400
        from app.services.device_migration import interfaces as _ifaces
        have = sorted(_ifaces(lines))
        if not have:
            # **인터페이스가 하나도 없으면 장비 백업이 아니다.** 그리고
            # 그것을 대상으로 받으면 `plan_rename` 의 `if known_new:` 가
            # 거짓이 되어 미매핑·없는포트 검사가 **통째로 꺼진다** —
            # 확인 한 번 없이 파일이 내려간다. 여기서 막는 것이 맞다:
            # 뒤에서 막으면 "왜 검사가 안 도나"를 아무도 모른다.
            return jsonify({
                "error": "That file lists no interfaces, so APO cannot tell "
                         "which ports the new device has. Take a backup from "
                         "the device itself — a factory-default one is fine.",
                "error_key": "no_interfaces"}), 400
        app.config['target_raw_config'] = raw
        return jsonify({"model": info.model, "version": info.version,
                        "build": info.build, "header": info.header,
                        "interfaces": have})

    @app.post("/api/device-migration/preflight")
    def device_migration_preflight():
        """이 설정을 저 장비에 넣으면 무엇이 깨지나. **읽기만 한다.**"""
        from app.services.device_migration import preflight

        raw = app.config.get('last_raw_config', '')
        if not raw:
            return jsonify(
                {"error": "No config loaded. Upload a config file first."}), 400
        new_lines = _target_lines()
        if new_lines is None:
            return jsonify({
                "error": "Upload a backup from the new device first — APO "
                         "needs to know which interfaces it has.",
                "error_key": "no_target_config"}), 400
        from app.services.device_migration import read_header as _rh
        # **화면이 "지금 대상"을 다시 세울 수 있어야 한다.** 재점검 뒤에도
        # 옛 헤더를 들고 있으면 교체 고지가 영원히 안 꺼진다.
        return jsonify({
            **preflight(_split_config(raw)[0], new_lines).summary(),
            "target_header": _rh(new_lines).header})

    def _dev_mig_inputs():
        """장비 이관의 공통 입력. 실패하면 (None, 응답) 을 준다.

        **적용과 내보내기가 같은 함수를 써야 한다.** 같은 파싱을 두 곳에
        적어 두면 하나를 고칠 때 다른 하나가 남아, 사용자가 받은 config 와
        결재에 올리는 변경내역이 **서로 다른 입력으로** 만들어진다 — 그러면
        문서가 그 파일을 증명하지 못한다. IP 흐름의 `_mig_inputs` 와 같은
        자리·같은 역할이다.
        """
        raw = app.config.get('last_raw_config', '')
        if not raw:
            return None, (jsonify(
                {"error": "No config loaded. Upload a config file first."}), 400)
        new_lines = _target_lines()
        if new_lines is None:
            return None, (jsonify({
                "error": "Upload a backup from the new device first — APO "
                         "needs to know which interfaces it has.",
                "error_key": "no_target_config"}), 400)

        body = request.get_json(silent=True)
        payload = body if isinstance(body, dict) else {}
        raw_map = payload.get("mapping")
        mapping = {}
        for row in (raw_map or []):
            if not isinstance(row, dict):
                continue
            old, new = row.get("old"), row.get("new")
            # **타입을 먼저 본다** — 숫자·리스트가 오면 500 이 된다.
            if not isinstance(old, str) or (new is not None
                                            and not isinstance(new, str)):
                # **IP 흐름의 키를 쓰면 안 된다.** 그 사전 문장은
                # "유효한 IPv4 주소" 이야기이고 `{detail}` 을 요구하는데,
                # 여기 사용자는 인터페이스를 드롭다운에서 골랐고 우리는
                # `detail` 을 안 보낸다 — IPv4 안내와 빈 `{detail}` 이 뜬다.
                return None, (jsonify({
                    "error": "One of the interface rows could not be read. "
                             "Reload the page and pick the interfaces again.",
                    "error_key": "device_migration_bad_mapping"}), 400)
            if old.strip():
                mapping[old.strip()] = (new or "").strip()
        return (raw, new_lines, payload, mapping), None

    @app.post("/api/device-migration/apply")
    def device_migration_apply():
        """인터페이스 배열을 새 장비에 맞춘 config 를 만든다."""
        from app.services.device_migration import (apply_rename, interfaces,
                                                   plan_rename, read_header,
                                                   verify)

        got, err = _dev_mig_inputs()
        if err:
            return err
        raw, new_lines, payload, mapping = got

        lines, had_cr, trailing = _split_config(raw)
        plan = plan_rename(lines, mapping,
                           new_header=read_header(new_lines).header,
                           new_interfaces=set(interfaces(new_lines)))

        # **확인은 그때 그 매핑에만 유효하다.** IP 마이그레이션과 같은
        # 규칙이다 — 값을 고쳐 새 문제가 생겨도 앞서 켠 확인이 살아 있으면
        # 차단이 조용히 통과한다.
        # **`plan.blocking` 이 아니라 `_blocking_for(plan)` 이다.** 인입
        # 디코딩에서 바이트가 사라진 config 를 IP 쪽은 `encoding_lossy` 로
        # 막는데 이 경로만 그냥 200 을 내주고 있었다 — 깨진 바이트가 박힌
        # 방화벽 config 가 아무 말 없이 다운로드됐다.
        blocking = _blocking_for(plan)

        # **토큰은 소스에도 묶는다.** 대상 헤더+매핑+차단'종류'만으로 묶으면
        # 버려지는 인터페이스가 1개든 40개든 토큰이 같다. 사용자가 A 에서
        # "1개 버림"을 확인한 뒤 B 를 열고 누르면 A 의 확인으로 B 의 40개가
        # 조용히 버려진다. 소스의 미매핑 이름을 토큰에 넣어 그것을 끊는다.
        ack_token = _ack_token(
            (read_header(new_lines).header or "")
            + "|" + ",".join(sorted(plan.unmapped)),
            mapping, blocking)
        acked = payload.get("ack_token") == ack_token

        # `unmapped_interface` 만 사람이 답할 수 있다. 충돌·이름길이·없는
        # 포트는 **확인해도 안 된다** — 장비가 거절하거나 조용히 버린다.
        # **IP 흐름과 같은 목록이어야 한다.** 여기서 빠뜨리면 그 차단은
        # 확인해도 안 풀리는 영구 차단이 된다 — 사용자는 파일을 영영 못
        # 만들고, 화면에는 번역 안 된 원시 토큰만 뜬다.
        _ANSWERABLE = {"unmapped_interface": "confirm_unmapped",
                       "encoding_lossy": "confirm_partial_read"}
        def _unacked(kinds):
            """확인으로 풀 수 있는 것만 걸러 낸다.

            **`.get(b, "")` 를 쓰면 안 된다.** 답할 수 없는 차단은 기본값이
            빈 문자열이 되어 `payload.get("")` 를 묻게 되고, 본문에 `""` 키가
            truthy 로 있으면 그 차단이 통과한다 — 실측으로 `{"": 1}` 하나에
            차단 3종이 전부 뚫렸다. **키가 없으면 답할 수 없는 것이다.**
            """
            out = []
            for b in kinds:
                key = _ANSWERABLE.get(b)
                if not (key and acked and payload.get(key)):
                    out.append(b)
            return out

        unacked = _unacked(blocking)
        if unacked:
            # **`**plan.summary()` 를 먼저 편다.** 그 안에도 `blocking` 키가
            # 있어서 뒤에 두면 방금 거른 `unacked` 를 통째로 덮어썼다 —
            # 사용자가 체크박스에 답해도 화면은 같은 문구를 영원히 되풀이했다.
            return jsonify({**plan.summary(),
                            "error": "Some choices need confirming before APO "
                                     "will build the file.",
                            "error_key": "migration_blocked",
                            "needs_confirmation": True,
                            "blocking": unacked,
                            "ack_token": ack_token,
                            "decode_lost_bytes": app.config.get(
                                'last_config_decode_lost', 0)}), 409

        # 확인을 받았으면 그 이름들은 **그대로 둔다**(매핑이 없으니 참조도
        # 안 바뀐다). 새 장비에 없는 포트를 가리키는 정책이 남으므로,
        # 4단계의 `config-error-log` 확인이 그만큼 더 중요해진다.
        plan = plan_rename(lines, mapping,
                           new_header=read_header(new_lines).header,
                           new_interfaces=None)
        # **여기도 확인을 봐야 한다.** 재계획이 만든 *새* 차단만 잡는 자리인데
        # `_blocking_for` 를 그대로 쓰면 방금 확인받은 `encoding_lossy` 가 매번
        # 다시 올라와 **영구 차단**이 된다 — 확인해도, 매핑을 바꿔도, 토큰을
        # 돌려줘도 200 이 안 나온다. 첫 검사와 **같은 필터**를 쓴다.
        again = _unacked(_blocking_for(plan))
        if again:
            return jsonify({**plan.summary(),
                            "error": "Some choices need confirming before APO "
                                     "will build the file.",
                            "error_key": "migration_blocked",
                            "needs_confirmation": True,
                            "blocking": again,
                            "ack_token": ack_token,
                            "decode_lost_bytes": app.config.get(
                                'last_config_decode_lost', 0)}), 409

        new_config = apply_rename(lines, plan)
        changed = sum(1 for a, b in zip(lines, new_config) if a != b)
        # **"몇 줄 바꿨다"는 성공의 증거가 아니다.** FortiOS 는 없는
        # 인터페이스를 가리키는 줄을 조용히 버리면서 복원 성공을 표시한다.
        # 미매핑을 확인하고 넘어간 경우가 정확히 여기다 — 그 이름들은 그대로
        # 남고, 남은 채로 복원되면 사라진다. **바꾸지 못한 것을 센다.**
        # IP 흐름은 이미 `verification` 을 내놓는데 이 경로에만 없었다.
        verification = verify(new_config, set(interfaces(new_lines)))
        return jsonify({
            "summary": plan.summary(),
            "verification": verification,
            # **화면이 추측하지 않게 사실을 보낸다.** `by_kind.header` 는
            # "치환했나"일 뿐이라, 소스와 대상 헤더가 같으면(같은 모델·같은
            # 펌웨어 — RMA 교체) 0이 된다. 그것을 "헤더가 없다"로 읽으면
            # 하지 않아도 될 수작업을 지시하게 된다.
            "source_had_header": bool(read_header(lines).header),
            # **이름은 화면이, 내용은 서버가 준다** — 그 둘이 갈리면 이름이
            # 거짓말을 한다. 다른 탭이 대상 백업을 갈아끼우면 화면이 기억하는
            # 대상과 실제로 쓰인 대상이 달라지므로, 쓴 것을 함께 보낸다.
            "target_model": read_header(new_lines).model,
            # **모델만으로는 부족하다.** 같은 모델의 다른 백업(다른 펌웨어·
            # 다른 포트 구성)으로 갈아끼우면 모델 비교로는 안 잡힌다 —
            # 실측 유해 교체 1,862건 중 308건(16.5%)이 그 경우다.
            "target_header": read_header(new_lines).header,
            "changed_lines": changed,
            "total_lines": len(new_config),
            "decode_lost_bytes": app.config.get('last_config_decode_lost', 0),
            "rows": [{"line_no": r.line_no, "kind": r.kind, "field": r.field,
                      "section": r.section, "old": r.old, "new": r.new}
                     for r in plan.rows[:_MIG_LIMIT]],
            "rows_truncated": len(plan.rows) > _MIG_LIMIT,
            "config": _join_config(new_config, had_cr, trailing),
            # 적용 후 반드시 확인해야 하는 것. FortiOS 는 편집된 config 의
            # 일부를 **조용히 버리면서도** 복원 성공을 표시한다.
            "post_apply_check": "diagnose debug config-error-log read",
            # **"비어 있으면 성공" 이라고 말하면 안 되는 경우가 있다.**
            # 미매핑을 확인하고 넘어갔으면 새 장비에 없는 포트를 가리키는
            # 줄이 남아 있어 로그는 **반드시** 찬다. IP 흐름의 판정 기준을
            # 그대로 복사하면 정상 결과를 실패로 읽거나, 반대로 그 문장을
            # 믿고 넘겨 무엇이 버려졌는지 영영 모르게 된다.
            # **`clean` 이 아니다.** `clean` 은 "이관이 무엇을 버렸나"(회귀
            # 판정 — 파일 이름 딱지용)이고, 로그가 찰지는 "산출물이 없는
            # 포트를 가리키나"(넓은 판정)가 정한다. 하나로 묶었더니 좁히는
            # 순간 4단계가 "로그가 비었는지 확인하라"고 거짓말을 했다.
            "expect_empty_log": verification["log_will_be_empty"],
        })

    #: `RenameRow.kind` → 왜 이 줄이 바뀌는가(코드). **문장이 아니라 코드다** —
    #: 서버가 한국어 문장을 만들면 화면이 번역할 수 없다(`_row_json` 과 같은 규칙).
    _DEV_REASON = {"header": "device_header_replaced",
                   "definition": "interface_renamed",
                   "reference": "reference_follows_interface"}

    def _dev_row_json(r):
        """`RenameRow` 를 exporter 의 `_row_display()` 가 읽는 모양으로 편다.

        **키를 추측하면 안 된다.** `migration_exporter._row_display()` 가
        실제로 읽는 것은 line_no / location / as_is(_display) /
        to_be(_display) / action / reason / reason_arg / warnings 뿐이고,
        이름이 하나라도 어긋나면 그 칸이 **조용히 빈 채로** 결재에 올라간다.

        AS-IS/TO-BE 는 3단계 표의 '이 장비 / 새 장비' 두 칸과 **같은 값**
        (인터페이스 이름)이다. IP 흐름에는 원시값과 표시값이 갈리는 경우가
        있어 `*_display` 가 필요했지만(이름 조각·지워진 넷마스크), 장비 이관은
        바꾸는 것이 이름 토큰 그 자체라 갈릴 것이 없다 — 그래서 여기서는
        `*_display` 를 만들지 않는다. 지어내면 두 값이 갈릴 자리만 생긴다.
        """
        # 헤더 행은 `config ...` 구역 밖(파일 첫 줄)이라 section 이 비어 있다.
        # 빈 칸으로 두면 "어디를 고쳤는지"를 답하지 못하므로 그 줄을 가리킨다.
        bits = [r.section] if r.section else ["#config-version"]
        if r.field:
            bits.append(f"set {r.field}")
        return {
            "line_no": r.line_no,
            # IP 흐름의 `IpReference.location` 과 같은 구분자를 쓴다 — 두
            # 산출물을 나란히 놓고 보는 사람이 하나만 배우면 되게.
            "location": " › ".join(bits),
            "as_is": r.old,
            "to_be": r.new,
            # 화면이 세는 세 갈래(header / definition / reference)와 같은 값.
            # 감사자는 이 칸으로 걸러 본다(Changes 시트에 필터가 걸려 있다).
            "action": r.kind,
            "reason": _DEV_REASON.get(r.kind, r.kind),
            # 참조 행에서만 채워진다 — 어떤 설정이 그 이름을 가리키는가.
            "reason_arg": r.field or None,
            # 장비 이관 계획에는 행 단위 경고가 없다. 있는 척하지 않는다.
            "warnings": (),
        }

    @app.post("/api/device-migration/export/changes")
    def device_migration_export_changes():
        """장비 이관 변경내역을 워크북으로 낸다 — 결재와 감사에 올라가는 문서.

        **IP 개번 쪽과 같은 구조다**(`/api/ip-migration/export/changes`).
        여태 장비 이관은 바뀐 `.conf` 하나만 내려줬다 — 무엇이 바뀌었는지
        증명할 수 없는 파일 하나만 남았다는 뜻이고, 화면 표는 새로고침 한
        번에 사라졌다.

        **입력에서 다시 계산한다.** 브라우저가 들고 있던 표를 돌려받아 찍으면
        파일이 APO 의 판단을 증명하지 못한다(`/api/config/diff/export` 와 같은
        이유). 받는 것은 사용자가 고른 인터페이스 매핑뿐이고, 소스 config 와
        대상 장비 백업은 서버가 들고 있는 것을 쓴다 — `apply` 와 똑같이.

        **라이선스 게이트를 걸지 않는다** — 마이그레이션은 무료다(B-85).

        **확인(ack)을 요구하지 않는다.** 차단 사유가 있는 상태야말로 승인자가
        표를 보고 판단해야 하는 때이므로, 그때 문서를 못 받게 하면 거꾸로다.
        대신 그 사유는 Self-check 시트에 그대로 싣는다.
        """
        from app.services.device_migration import (apply_rename, interfaces,
                                                   plan_rename, read_header,
                                                   verify)
        from app.services.migration_exporter import (build_changes_csv,
                                                     build_migration_workbook)

        got, err = _dev_mig_inputs()
        if err:
            return err
        raw, new_lines, payload, mapping = got
        _fmt = str(payload.get("format") or "xlsx").lower()
        lines = _split_config(raw)[0]
        _new_header = read_header(new_lines).header
        _have = set(interfaces(new_lines))

        # **`apply` 와 같은 계산이다.** 그쪽은 두 번 계획한다:
        #   ① 새 장비의 포트 목록으로 — 사람이 답해야 할 것을 알아내고,
        #   ② 확인을 받은 뒤 `new_interfaces=None` 으로 다시 —
        #      그래야 확인하고 넘어간 이름이 그대로 남은 계획이 나온다.
        # 여기서도 둘 다 돌린다. ①은 Self-check 에 실을 사유를 얻기 위한
        # 것이고, 실제로 바뀔 행은 ②에서 나온다 — 한쪽만 쓰면 산출물과
        # 문서가 다른 계획을 말하게 된다.
        gate = plan_rename(lines, mapping, new_header=_new_header,
                           new_interfaces=_have)
        plan = plan_rename(lines, mapping, new_header=_new_header,
                           new_interfaces=None)
        new_config = apply_rename(lines, plan)
        check = verify(new_config, _have)

        _rows = [_dev_row_json(r) for r in plan.rows[:_MIG_LIMIT]]
        _sum = {"rows": len(plan.rows),
                "changed_lines": sum(1 for a, b in zip(lines, new_config)
                                     if a != b),
                "total_lines": len(new_config)}

        if _fmt == "csv":
            # 표 한 장만 필요한 경우 — ITSM·CMDB import, 스크립트 대사.
            # **xlsx 와 같은 행을 쓴다.** BOM 은 한국 Excel 이 CP949 로
            # 오독하지 않게 하는 유일한 장치다(서버가 붙인다).
            return app.response_class(
                response=build_changes_csv(_rows), status=200,
                mimetype="text/csv; charset=utf-8",
                headers={"Content-Disposition": _attachment(
                    f"apo_device_migration_changes_{_open_device_label()}.csv")})

        # Self-check 시트의 라벨은 **여기서 정한다.** exporter 의 라벨 표는 IP
        # 흐름의 키만 알아서, 원시 키를 넘기면 `orphan_definition_count` 같은
        # 내부 이름이 감사 문서에 찍힌다.
        _check = {
            "Interface definitions the new device does not have":
                check["orphan_definition_count"],
            "References to those definitions": check["orphan_reference_count"],
            "Lines that were already dead before this migration":
                check["pre_existing_dangling_count"],
            # **"비어 있으면 성공"이 아닌 경우가 있다**(미매핑을 남긴 경우).
            # 참/거짓을 그대로 적는다 — 화면 4단계와 같은 값이다.
            "Parser log should be empty after restore":
                "yes" if check["log_will_be_empty"] else "no",
            # 인입 디코딩에서 사라진 바이트. 우리가 손도 안 댄 줄의 내용이
            # 없어지는 것이라 산출물의 성질이다 — 문서가 말해야 한다.
            "Bytes lost while reading the configuration":
                app.config.get('last_config_decode_lost', 0),
            "Interfaces left as they are (no match on the new device)":
                list(gate.unmapped),
            "Names that would collide": list(gate.collisions),
            "Names longer than 15 characters": list(gate.too_long),
            "New names the new device does not have": list(gate.not_on_new),
            # 이 목록이 비어 있지 않으면 `apply` 는 파일을 만들지 않는다.
            # 문서에는 남긴다 — 승인자가 볼 것이 바로 이것이다.
            "Questions that must be answered before the file is built":
                _blocking_for(gate),
            "Interface definitions that would be dropped on restore":
                check["orphan_definitions"],
        }

        # 되돌리기: 새 이름 → 옛 이름. 두 인터페이스가 한 이름으로 합쳐지면
        # (`interface_collision`) 되돌릴 짝이 둘이라 모호하다 — exporter 가
        # 목록을 받으면 'ambiguous' 로 표시한다. 감추면 복구가 조용히 틀어진다.
        _rev: dict = {}
        for _old, _new in sorted(mapping.items()):
            if _new:
                _rev.setdefault(_new, []).append(_old)

        xlsx = build_migration_workbook(
            kind="Device replacement",
            rows=_rows,
            summary=_sum,
            verification=_check,
            # **빈 TO-BE 는 매핑이 아니라 "그대로 둔다"** 이다. Mapping 시트에
            # 빈 칸으로 찍으면 "무엇으로 바꾸라는 건지" 읽을 수 없으므로 빼고,
            # 그 이름들은 위 Self-check 의 '그대로 둔 인터페이스'에 적는다.
            mapping={k: v for k, v in mapping.items() if v},
            reverse_mapping=_rev,
            # 되돌릴 대상은 주소가 아니라 **인터페이스 이름**이다. 기본 문구를
            # 그대로 두면 롤백 문서가 무엇을 되돌리라는 건지 틀리게 말한다.
            undo_label="Interfaces (new → old)",
            rows_truncated=len(plan.rows) > _MIG_LIMIT,
            total_rows=len(plan.rows),
            source_name=app.config.get('last_config_filename') or "",
            source_sha256=app.config.get('last_config_sha256') or "",
            device_label=_open_device_label(),
            # **어느 장비용으로 만든 파일인가.** 다른 창이 대상 백업을
            # 갈아끼우면 화면이 기억하는 대상과 실제로 쓰인 대상이 갈린다 —
            # 파일 자신이 말해야 몇 주 뒤에도 대조할 수 있다.
            target_label=_new_header or read_header(new_lines).model or "",
            generated_at=_dt.now().strftime("%Y-%m-%d %H:%M"),
            post_apply_check="diagnose debug config-error-log read",
        )
        return app.response_class(
            response=xlsx, status=200,
            mimetype=('application/vnd.openxmlformats-officedocument'
                      '.spreadsheetml.sheet'),
            headers={"Content-Disposition": _attachment(
                f"apo_device_migration_changes_{_open_device_label()}.xlsx")})

    # ── Remediation ───────────────────────────────────────────────────────
    app.config.setdefault('remediation_device', {})

    @app.post("/api/remediation/device")
    def remediation_device_save():
        # 이 등록은 곧 '어느 방화벽에 명령을 보낼지'다 — 보고 있는 장비와
        # 묶여야 한다.
        payload = request.get_json(silent=True) or {}
        try:
            port = int(payload.get("port", 443) or 443)
        except (TypeError, ValueError):
            return jsonify({"error": "port must be a number"}), 400
        if not (1 <= port <= 65535):
            return jsonify({"error": "port out of range"}), 400
        from app.services.remediation_service import validate_device_address
        try:
            device_ip = validate_device_address(payload.get("ip", ""))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        device = {
            "ip":         device_ip,
            "port":       port,
            "token":      str(payload.get("token", "")).strip(),
            "vdom":       str(payload.get("vdom", "root")).strip() or "root",
            # 기본값 True — 명시적으로 끄지 않는 한 TLS 검증을 수행한다.
            "verify_ssl": bool(payload.get("verify_ssl", True)),
        }
        if not device["token"]:
            return jsonify({"error": "token is required"}), 400
        # **어느 장비를 보면서 등록했는지** 함께 기록한다. 적용은 되돌릴 수 없는
        # 쓰기이므로, 화면이 그 사이에 다른 장비로 바뀌었다면 서버가 끊어야 한다
        # — 확인창 문구에만 기대면 사용자가 IP를 대조하지 않는 순간 통과한다.
        device["for_device_id"] = app.config.get('device_id')
        # 주소·토큰이 바뀌었으면 앞서 확인한 장비 이름은 무효다. 남겨 두면
        # 다른 IP 를 넣고도 옛 확인 결과로 통과한다.
        device.pop("connected_hostname", None)
        app.config['remediation_device'] = device
        return jsonify({"ok": True})

    @app.get("/api/remediation/device")
    def remediation_device_get():
        """등록된 장비를 알려준다 — 토큰은 절대 내보내지 않는다.

        되돌릴 수 없는 변경을 확인시키는 창이 입력칸 값을 읽으면, 사용자가 저장
        뒤에 칸만 고쳐 놓은 경우 실제 적용 대상과 다른 장비를 보여준다. 적용은
        서버가 들고 있는 이 값으로 나가므로, 확인창도 같은 값을 보여야 한다.
        """
        d = app.config.get('remediation_device') or {}
        return jsonify({
            "registered": bool(d.get("ip")),
            "ip": d.get("ip", ""),
            "port": d.get("port", 443),
            "vdom": d.get("vdom", ""),
        })

    @app.get("/api/remediation/device/test")
    def remediation_device_test():
        from app.services.remediation_service import test_connection
        device = app.config.get('remediation_device', {})
        if not device.get("ip"):
            return jsonify({"ok": False, "message": "No device registered"}), 400
        res = test_connection(device)
        # 연결이 된 장비가 **누구인지** 기억한다. 적용 직전에 지금 열어 둔
        # 설정의 hostname 과 대조하기 위해서다 — 이 값을 버려 두는 바람에
        # IP 를 잘못 붙여넣은 것만으로 남의 방화벽에 정책 비활성화가 나갔다
        # (라운드 25 실측: 화면은 BETA 인데 ACME-HQ-REAL 로 PUT 4건).
        if res.get("ok") and res.get("hostname"):
            device["connected_hostname"] = res["hostname"]
            device["connected_version"] = res.get("fw_version") or ""
            # 시리얼이 이 장비의 신원이다 — 이름과 달리 고객 간에 겹치지 않는다.
            device["connected_serial"] = res.get("serial") or ""
            # 시리얼이 비었을 때 **왜 비었는지**를 함께 들고 다닌다. 장비가
            # 답한 결과 없는 것과, 조회가 끝나지 못한 것을 구분하지 않으면
            # 화면이 '영영 대조할 수 없다'고 단정한다(R75-1).
            device["connected_serial_probe"] = res.get("serial_probe") or "answered"
            device["connected_tls_fp"] = res.get("tls_fingerprint") or ""
            device["tls_verified"] = bool(res.get("tls_verified"))
            app.config['remediation_device'] = device
        # **검증을 끈 채널의 인증서를 고정한다** (B-79, TOFU).
        # FortiGate 는 대부분 자체 서명이라 'Skip SSL Verify' 가 사실상 정상
        # 경로다 — 그 채널로 read-only 관리자 토큰이 나가므로, 관리망에 자리를
        # 잡은 공격자가 그대로 가져갈 수 있었다. 검증을 강제하면 자체 서명
        # 장비에서 기능이 통째로 멈추므로 SSH 가 쓰는 길을 쓴다: 처음 본
        # 지문을 이 장비의 것으로 고정하고, 다음부터 달라지면 막는다.
        _fp_state = _tls_pin_check(res)
        if _fp_state:
            res.update(_fp_state)
        # 열어 둔 설정의 장비와 이름이 다르면 그 사실을 화면에도 알린다.
        ident = _remediation_identity()
        res["config_hostname"] = ident["config"]
        res["hostname_matches"] = _remediation_hostname_matches()
        # **확인 결과를 여기서 말한다.** 적용 버튼을 누른 뒤에야 '확인할 수
        # 없다'고 하면, 그 전까지 화면은 확인된 것처럼 보인 셈이다.
        res["identity"] = ident["verdict"]
        if ident.get("why"):
            res["identity_why"] = ident["why"]
        # 화면이 **이름이 아니라 시리얼로** 말할 수 있게 값을 준다. 서버만 알고
        # 있었더니, 이름이 같은 두 장비에 '같은 이름 둘'을 대며 다르다고 하는
        # 자기모순 문장이 떴다(라운드 30 실측).
        res["serial"] = ident.get("serial") or ""
        if ident.get("pinned"):
            res["pinned"] = ident["pinned"]
        return jsonify(res)

    @app.get("/api/remediation/candidates")
    def remediation_candidates():
        # **판정 결과를 돌려주는 읽기도 게이트를 지난다.** 이 목록은 되돌릴 수
        # 없는 쓰기(/api/remediation/apply)로 이어지는 입구인데 게이트 밖이라,
        # 탭 두 개에서 A 고객 화면에 B 고객 정책(SECRET-C-PAYROLL-RULE)이
        # 그대로 떴다(라운드 23 실측). classify 만 막아 둔 것이 무의미해진다.
        from app.services.remediation_service import get_candidates
        from app.services.severity_engine import evaluate_severity
        from app.services.policy_renderer import build_view_model
        parsed = app.config.get('last_parsed')
        if not parsed:
            return jsonify({"error": "No config loaded. Upload a config file first."}), 400
        service_groups = parsed.get("service_groups", {})
        user_ranges = app.config.get('user_ranges', [])
        context = {
            "service_groups": service_groups,
            "user_ranges": user_ranges,
            "today": _date.today(),
            # 승인 유효기간 유예의 신호(onetime 스케줄) — 모든 판정 경로가
            # 같은 맵을 받아야 한다. 한 곳만 빠지면 classify 와 후보/유보가
            # 갈린다(라운드 71 스코프 전파와 같은 규칙).
            "onetime_schedules": _se_onetime(parsed),
            **_engine_ctx(),
        }
        runtime_stats = app.config.get('last_runtime_stats', {})
        view = build_view_model(parsed, runtime_stats)
        def classify(policies):
            return [{**p, **evaluate_severity(p, context)} for p in (policies or [])]
        fw_classified  = classify(view.get("firewall_policy", []))
        prx_classified = classify(view.get("firewall_proxy_policy", []))
        severity_results = {"firewall": fw_classified, "proxy": prx_classified}

        # Severity 탭과 동일한 urgency 분포 계산 → 카운트 불일치 디버그용
        all_classified = fw_classified + prx_classified
        urgency_dist = {}
        for p in all_classified:
            u = p.get("urgency", 0)
            urgency_dist[str(u)] = urgency_dist.get(str(u), 0) + 1

        candidates = get_candidates(parsed, severity_results)

        # **조치 계획이 '지금 끄지 말라'고 한 정책을 후보로 올리면 안 된다.**
        # 후보 목록은 urgency 만 보고 도달불가 축을 무시했다. 그래서 화면의
        # 조치 계획과 워크북 Action Plan 은 정책 2·3·12 에 대해 '정책 1을 먼저
        # 처리하고 새 백업으로 재판정하라'고 적는데, **같은 제품의 조치 CSV 와
        # Postman 컬렉션은 그 셋을 비활성 후보로 올렸다**(라운드 43 실측).
        # 되돌릴 수 없는 변경을 실행하는 두 산출물이 유보를 잃는 것이다.
        #
        # 판정 근거가 이 계획 자신에 기대는 정책은 따로 담는다 — 계획과 같은
        # 규칙이다(workbook_exporter._add_action_plan_sheet 참조).
        try:
            from app.services.reachability import detect_unreachable as _du
            from app.services.workbook_exporter import _vdom_of
            # classify 와 같은 스냅샷 스코프를 전달한다 — 빠지면 반전 게이트
            # (R70-1)가 이 경로에만 없어 계획과 후보가 갈린다(라운드 71).
            _reach = _du(parsed, _fqdn_map(), _fqdn_source_vdom())
        except Exception as exc:
            print(f"[APO] reachability for candidates failed: {exc}", flush=True)
            _reach = {"unreachable": []}
            from app.services.workbook_exporter import _vdom_of
        # **VDOM 은 정책 번호의 일부다.** 번호만으로 도달불가·변경을 매칭하면
        # 다른 VDOM 의 같은 번호가 거짓 선행관계를 만들어, 살아있는 정책이
        # '지금 끄지 말라'로 오유보된다(라운드 52 계약·완성도 렌즈 — 워크북은
        # 라운드 50 에서 이미 (vdom, id) 로 고쳤는데 이 화면 경로가 남았다).
        # **번호가 None 인 항목은 키에서 제외한다.** str(None)="None" 문자열이
        # 키가 되면, 워크북이 라운드 53 에서 막은 (vdom, None) 우연 매칭이 이
        # 경로에서 문자열 "None" 으로 그대로 재현된다 — 손편집 백업(비숫자
        # _edit → policy_id None)에서 무관한 정책이 유보·거절되고 "policy None
        # stays enabled" 문구가 나갔다(라운드 54 계약 렌즈 재현).
        _unreach = {(_vdom_of(u), str(u.get("policy_id"))): u
                    for u in (_reach.get("unreachable") or [])
                    if u.get("policy_id") is not None}
        _changed = ({(_vdom_of(p), str(p.get("policy_id"))) for p in candidates["to_disable"]
                     if p.get("type") != "proxy" and p.get("policy_id") is not None}
                    | {(_vdom_of(p), str(p.get("policy_id"))) for p in candidates["already_disabled"]
                       if p.get("type") != "proxy" and p.get("policy_id") is not None}
                    | set(_unreach))
        _deferred = []
        _keep = []
        for p in candidates["to_disable"]:
            _u = (_unreach.get((_vdom_of(p), str(p.get("policy_id"))))
                  if p.get("type") != "proxy" and p.get("policy_id") is not None
                  else None)
            _sh_raw = (_u or {}).get("shadowed_by")
            _sh = str(_sh_raw)
            # 가림막은 도달불가 정책과 같은 VDOM 에 있다 — 그 VDOM 으로 조회.
            # shadowed_by 가 None 이면 선행관계가 없다 — 매칭하지 않는다.
            if _u and _sh_raw is not None and (_vdom_of(_u), _sh) in _changed:
                _deferred.append({**p, "category": "Decide after the changes above",
                                  "deferred_because": _sh,
                                  "reason": (f"Unreachable only while policy {_sh} stays "
                                             f"enabled — and this plan also changes "
                                             f"policy {_sh}. Do the other rows first, "
                                             "take a fresh backup, and run APO again.")})
            else:
                _keep.append(p)
        candidates["to_disable"] = _keep
        candidates["deferred"] = _deferred
        # 이 목록은 **지금** 재계산한 것이다. 화면이 들고 있는 점검 결과가
        # 다른 근거로 만들어졌으면(그 사이 사용량 CSV·임계값이 바뀌었으면)
        # 같은 정책이 두 화면에서 다른 등급으로 보인다 — 화면이 대조한다.
        candidates["basis"] = _judgement_basis()
        candidates["_debug"] = {
            "total_policies": len(all_classified),
            "urgency_distribution": urgency_dist,
            "critical_high_total": urgency_dist.get("1", 0) + urgency_dist.get("2", 0),
        }
        return jsonify(candidates)

    def _deferred_policy_ids() -> dict:
        """'지금 끄지 말라'고 계획이 말한 정책 → 그 근거가 기대는 정책.

        판정 근거가 이 계획 자신에 기대는 정책이다. 후보 목록·조치 계획·워크북·
        쓰기가 모두 같은 답을 해야 하므로 한 곳에서 계산한다.
        """
        parsed = app.config.get('last_parsed')
        if not parsed:
            return {}
        try:
            from app.services.reachability import detect_unreachable as _du
            from app.services.workbook_exporter import _vdom_of
            # 후보·계획·쓰기가 같은 답을 해야 한다 — classify 와 동일 스코프.
            reach = _du(parsed, _fqdn_map(), _fqdn_source_vdom())
        except Exception:
            return {}
        unreach_items = reach.get("unreachable") or []
        # 이 계획이 바꾸는 정책 = 도달불가로 지목된 것 + 비활성 후보
        try:
            from app.services.remediation_service import get_candidates
            from app.services.severity_engine import evaluate_severity
            from app.services.policy_renderer import build_view_model
            ctx = {"service_groups": parsed.get("service_groups", {}),
                   "user_ranges": app.config.get('user_ranges', []),
                   "today": _date.today(),
                   "onetime_schedules": _se_onetime(parsed),
                   **_engine_ctx()}
            view = build_view_model(parsed, app.config.get('last_runtime_stats', {}))
            sev = {k: [{**p, **evaluate_severity(p, ctx)} for p in view.get(vk, [])]
                   for k, vk in (("firewall", "firewall_policy"),
                                 ("proxy", "firewall_proxy_policy"))}
            cand = get_candidates(parsed, sev)
        except Exception:
            return {}
        # **선행관계 판정은 (VDOM, 번호) 로.** 번호만 잡으면 다른 VDOM 의 같은
        # 번호가 거짓 가림막이 되어 살아있는 정책을 오유보한다(라운드 52). 가림막은
        # 도달불가 정책과 같은 VDOM 이므로 그 VDOM 으로 changed 를 조회한다.
        # 번호가 None 인 항목은 제외 — str(None)="None" 문자열 키가 되면
        # 무관한 None-id 끼리 우연 매칭된다(라운드 54, remediation_candidates 와
        # 같은 결함·같은 방어).
        changed = ({(_vdom_of(u), str(u.get("policy_id"))) for u in unreach_items
                    if u.get("policy_id") is not None}
                   | {(_vdom_of(p), str(p.get("policy_id"))) for p in cand["to_disable"]
                      if p.get("type") != "proxy" and p.get("policy_id") is not None}
                   | {(_vdom_of(p), str(p.get("policy_id"))) for p in cand["already_disabled"]
                      if p.get("type") != "proxy" and p.get("policy_id") is not None})
        # 반환 키는 번호만이면 충분하다 — _deferral_refusal 시점엔 _vdom_conflicts
        # 가 번호 모호성을 이미 막아 쓰기 가능한 번호는 VDOM 당 유일하다.
        return {str(u.get("policy_id")): str(u.get("shadowed_by"))
                for u in unreach_items
                if u.get("policy_id") is not None
                and u.get("shadowed_by") is not None
                and (_vdom_of(u), str(u.get("shadowed_by"))) in changed}

    def _deferral_refusal(policies: list):
        """계획이 '지금 끄지 말라'고 한 정책이 섞였으면 거절 payload, 아니면 None.

        **내보낸 명령은 나중에 사람이 붙여넣어 실행한다.** 이 규칙은 조치
        적용에만 걸려 있었고, 같은 정책을 그대로 인쇄하는 두 내보내기
        (Postman 컬렉션·변경 문서 CSV)는 지나갔다 — 바로 옆 `_vdom_conflicts`
        는 정확히 그 이유로 세 곳에 다 걸려 있는데, 나중에 추가된 이 규칙만
        한 곳에 남았다(라운드 48 실측).

        CSV 한 줄이 스스로 모순됐다: `Category = Disable Candidate` 인데
        같은 줄의 Reason 은 "다른 행을 먼저 처리하고 백업을 다시 뜬 뒤 APO 를
        다시 돌리라"고 적혀 있다. 그 파일대로 실행하면 가려 주던 정책이
        꺼지는 동안 보류된 정책이 되살아난다.
        """
        _def = _deferred_policy_ids()
        if not _def:
            return None
        hit = [str(p.get("policy_id")) for p in policies
               if str(p.get("type", "firewall")) != "proxy"
               and str(p.get("policy_id")) in _def]
        if not hit:
            return None
        sh = _def[hit[0]]
        return {
            "error": f"Policy {', '.join(hit)} is unreachable only while "
                     f"policy {sh} stays enabled — and policy {sh} is also "
                     "being changed. Do that one first, take a fresh "
                     "configuration backup and run APO again: these may be "
                     "live by then.",
            "error_key": "deferred_until_shadower_decided",
            "policies": hit, "shadower": sh}

    def _vdom_conflicts(policies: list) -> list[dict]:
        """요청한 정책이 등록한 VDOM 의 정책이 맞는지 **서버가 직접 대조한다.**

        FortiGate 는 VDOM 마다 정책 번호를 1번부터 다시 매긴다. VDOM 을 안 읽던
        동안 root 의 1번과 guest 의 1번이 같은 정책이었고, 조치 PUT 이
        `?vdom=<등록한 값>` 으로 나가 **화면에 뜬 적도 없는 다른 VDOM 의 운영
        정책이 꺼졌다.** 응답은 건드리지도 않은 정책 이름을 붙여 '비활성화
        성공'이라고 답했다(라운드 39 실측). 되돌릴 방법은 이 도구에 없다.

        브라우저가 보낸 vdom 을 믿지 않는다 — 대상은 서버가 연 설정에서 정한다.
        """
        # **여기서 일찍 빠져나가면 바로 아래 대조가 영영 안 돈다.**
        # `multi_vdom` 이 아니면 통째로 통과시켰더니, VDOM 이 하나뿐인 설정
        # (예: 유일 VDOM 이 'PROD-VD')에 등록 vdom='root'(폼 기본값) 로 적용해
        # PUT 2건이 전부 `?vdom=root` 로 나갔다 — 화면에 뜬 적 없는 root 의
        # 1·2번이 꺼졌고 응답은 '성공'이었다(라운드 40 실측). 더 나쁜 것은
        # 이 경로를 **APO 자신의 안내가 유도한다**는 점이다: 다중 VDOM 을
        # 막을 때 '단일 VDOM 의 설정을 올리라'고 말하기 때문이다.
        # 번호가 유일한지와 대상 VDOM 이 맞는지는 다른 질문이다. 둘 다 본다.
        parsed = app.config.get('last_parsed') or {}
        here: dict = {}
        for _k, _pt in (("firewall_policy", "firewall"),
                        ("firewall_proxy_policy", "proxy")):
            for _p in parsed.get(_k, []):
                here.setdefault((_pt, str(_p.get("policy_id"))), []).append(
                    {"vdom": _p.get("vdom") or "", "name": _p.get("name") or ""})
        want = str((app.config.get('remediation_device') or {}).get("vdom")
                   or "root")
        bad = []
        for p in policies:
            pid = str(p.get("policy_id", ""))
            key = (str(p.get("type", "firewall")), pid)
            found = here.get(key, [])
            # 화면의 정책 목록에는 VDOM 칸이 없다. 그러니 같은 번호가 두 VDOM 에
            # 있으면 **사용자가 무엇을 골랐는지 표현할 방법 자체가 없다** —
            # 서버가 골라 주면 그게 곧 라운드 39 의 사고다. 하나로 좁혀지지
            # 않으면 쓰지 않는다.
            # 설정이 VDOM 을 선언하지 않으면(`config vdom` 없는 보통 장비)
            # 정책에 vdom 이 없다 — 그때는 대조할 근거가 없으므로 묻지 않는다.
            # 선언돼 있으면 등록한 대상과 같아야 한다.
            # **두 가지 다른 문제를 한 문장으로 말하면 안 된다.**
            #   · 번호가 두 VDOM 에 있다  → 사용자가 무엇을 골랐는지 표현할
            #     방법이 없다. 서버가 골라 주면 그게 라운드 39 의 사고다.
            #   · 이 정책의 VDOM 이 등록한 대상과 다르다 → 고르는 것은
            #     문제없고, **등록을 고치면 된다.**
            # 둘을 'VDOM이 여러 개입니다'로 뭉뚱그렸더니, VDOM 이 정확히 하나인
            # 설정에 대고 "VDOM이 여러 개(PROD-VD)... 하나짜리 설정을 올리세요"
            # 라고 말했다 — 이미 올린 것이 하나짜리다. 진짜 원인도 빠져나갈
            # 방법도 화면이 한 번도 말하지 않아 고리가 됐다(라운드 41 실측).
            if len(found) != 1:
                bad.append({"policy_id": pid, "why": "ambiguous",
                            "vdoms": sorted({f["vdom"] for f in found}),
                            "names": [f["name"] for f in found],
                            "registered_vdom": want})
            elif found[0]["vdom"] and found[0]["vdom"] != want:
                bad.append({"policy_id": pid, "why": "wrong_target",
                            "vdoms": [found[0]["vdom"]],
                            "names": [found[0]["name"]],
                            "registered_vdom": want})
        return bad

    def _vdom_refusal(bad: list) -> dict:
        """무엇이 문제이고 **무엇을 하면 되는지**를 사유별로 말한다."""
        _vd = (app.config.get('last_parsed', {}).get("meta") or {}).get("vdoms", [])
        if any(b.get("why") == "ambiguous" for b in bad):
            return {
                "error": "This configuration has more than one VDOM "
                         f"({', '.join(_vd)}), and policy numbers start again "
                         "at 1 in each one. APO cannot tell which VDOM's policy "
                         "you picked, so it will not write to the firewall. "
                         "Upload the configuration of a single VDOM.",
                "error_key": "vdom_ambiguous", "vdoms": _vd, "conflicts": bad}
        want = bad[0].get("registered_vdom", "")
        theirs = bad[0].get("vdoms") or [""]
        return {
            "error": f"The policies in this configuration belong to VDOM "
                     f"'{theirs[0]}', but this device is registered with VDOM "
                     f"'{want}'. APO will not write to the firewall, because "
                     f"policy numbers mean different rules in each VDOM. "
                     f"Register the device again with VDOM '{theirs[0]}'.",
            "error_key": "vdom_wrong_target", "vdoms": _vd,
            "config_vdom": theirs[0], "registered_vdom": want, "conflicts": bad}

    @app.post("/api/remediation/apply")
    def remediation_apply():
        # **이 게이트는 매출이 아니라 안전 때문이다**(2026-09-10 Jayden 결정).
        # 이 라우트는 고객의 **운영 방화벽에 쓰기**를 하는 유일한 경로이고
        # 롤백이 없다. 무명 도구가 무명 사용자의 프로덕션 장비를 끄게 두면,
        # 사고가 났을 때 매출도 관계도 없는 상태로 평판만 잃는다. 결제한
        # 사용자는 신원이 있고, 투자했으니 신중하고, 문제 시 연락할 곳이 있다.
        #
        # **무료 사용자의 손발을 묶지는 않는다** — 화면 조치 계획이 VDOM 까지
        # 감싼 CLI 를 그대로 보여주고 복사 버튼도 있다(shell.js cliDisable).
        # 판정·후보 목록·계획은 전부 무료다. 막는 것은 '이 도구가 대신 쓰는
        # 것' 하나뿐이고, 거절 문구가 그 대안을 안내한다.
        if not is_licensed():
            return jsonify({
                "error": "Applying changes to the device needs a licence. "
                         "This is the only action that writes to your firewall "
                         "and it cannot be undone from here, so it is kept "
                         "behind a licence. You can still copy the CLI commands "
                         "from the Action Plan and run them yourself - the "
                         "assessment and the plan are free.",
                "error_key": "license_required_write",
            }), 402
        from app.services.remediation_service import disable_policies
        device = app.config.get('remediation_device', {})
        if not device.get("ip"):
            return jsonify({"error": "No device registered"}), 400
        payload = request.get_json(silent=True) or {}
        policies = payload.get("policies", [])
        if not policies:
            return jsonify({"error": "No policies selected"}), 400
        # 조치 후보는 지금 열려 있는 config에서 나온다. 등록한 대상이 그때의
        # 장비가 아니면, B에서 고른 정책 번호가 A 방화벽에서 꺼진다.
        _open = app.config.get('device_id')
        _for = device.get("for_device_id")
        if _open and _for and _open != _for:
            return jsonify({"error": "The connected device was registered while a "
                            "different configuration was open. Re-register the "
                            "device for the one you are looking at now."}), 409
        _vbad = _vdom_conflicts(policies)
        if _vbad:
            return jsonify(_vdom_refusal(_vbad)), 409
        # **계획이 '지금 끄지 말라'고 한 정책은 쓰기에서도 막는다.** 후보
        # 목록에서 유보로 옮겼지만(위 remediation_candidates), 오래된 화면이
        # 그 목록을 들고 있을 수 있다. 되돌릴 수 없는 쓰기는 화면을 믿지 않는다.
        _dbad = _deferral_refusal(policies)
        if _dbad:
            return jsonify(_dbad), 409
        # **인증서가 바뀐 채널로는 토큰을 내보내지 않는다** (B-79).
        # 검증을 끈 장비에서 자체 서명 인증서가 바뀌는 것은 장비 교체 아니면
        # 중간자다. 읽기는 막지 않고(자체 서명 장비에서 아무것도 못 보게 되면
        # 그게 더 큰 손해다) 되돌릴 수 없는 쓰기 앞에서만 막는다.
        _tbad = _tls_pin_refusal()
        if _tbad:
            return _tbad
        # **연결된 장비가 이 설정의 장비인지 확인한다.** 세션 대조(위)는 '탭이
        # 바뀐 경우'만 막는다. 실제로 더 흔한 실수 — 관리 IP 를 잘못 붙여넣기 —
        # 는 그 검사를 통째로 지나간다. 연결 확인이 이미 장비 이름을 받아
        # 왔는데 대조하지 않아, 화면은 BETA 를 보면서 ACME 방화벽의 정책 4건이
        # 꺼졌다(라운드 25 실측). 되돌릴 방법은 이 도구에 없다.
        ident = _remediation_identity()
        if ident["verdict"] == "mismatch":
            if ident.get("why") == "serial_unread_but_pinned":
                # 막는 것은 같다 — 대조할 값이 없으면 보내지 않는다. 다만
                # **읽지 못한 것**을 "장비가 안 준다"로 말하면 거짓일 수 있고,
                # 사용자는 재시도로 풀릴 일을 영구 장애로 오해한다(R75-1).
                return jsonify({
                    "error": "APO confirmed this firewall earlier as serial "
                             f"'{ident['pinned']}', but it could not read the "
                             f"serial from {device.get('ip')} this time, so it "
                             "cannot be checked against that. Test the "
                             "connection again; if it keeps failing, use the "
                             "address you confirmed before.",
                    "identity": "mismatch", "why": "serial_unread_but_pinned",
                    "error_key": "remediation_serial_unread",
                    "ip": device.get("ip"),
                    "expected_serial": ident["pinned"]}), 409
            if ident.get("why") == "serial_missing_but_pinned":
                return jsonify({
                    "error": "APO confirmed this firewall earlier as serial "
                             f"'{ident['pinned']}', but the device answering at "
                             f"{device.get('ip')} does not report a serial, so "
                             "it cannot be checked against that. Use the "
                             "address you confirmed before.",
                    "identity": "mismatch", "why": "serial_missing_but_pinned",
                    # 값이 끼어드는 문장은 사전에 닿지 않는다 — 화면이 만든다.
                    "error_key": "remediation_serial_missing",
                    "ip": device.get("ip"),
                    "expected_serial": ident["pinned"]}), 409
            if ident.get("why") == "serial_mismatch":
                # **이름이 같아도 다른 장비다.** 이름으로는 못 하던 판정이다 —
                # MSP 표준 명명(FGT-HQ, fw01)은 두 고객이 함께 쓰는 것이 정상이라
                # 이름 대조로는 이 사고를 세 라운드 연속 막지 못했다.
                return jsonify({
                    "error": "The firewall answering at "
                             f"{device.get('ip')} has serial "
                             f"'{ident['serial']}', but this device was "
                             f"confirmed as '{ident['pinned']}'. The names match "
                             "but it is a different unit — check the address.",
                    "identity": "mismatch", "why": "serial_mismatch",
                    "error_key": "remediation_serial_mismatch",
                    "ip": device.get("ip"),
                    "connected_serial": ident["serial"],
                    "expected_serial": ident["pinned"]}), 409
            return jsonify({
                "error": f"The connected firewall is '{ident['connected']}', but "
                         f"the configuration you have open is '{ident['config']}'. "
                         "Changes are not sent to a device other than the one you "
                         "are looking at. Check the IP, or open that device's "
                         "configuration first.",
                "identity": "mismatch",
                "error_key": "remediation_name_mismatch",
                "connected_hostname": ident["connected"],
                "config_hostname": ident["config"]}), 409
        if ident["verdict"] == "untested":
            return jsonify({
                "error": "Run Test Connection first — the tool confirms which "
                         "firewall answers at that address before sending any "
                         "change.",
                "identity": "untested"}), 409
        if ident["verdict"] == "unverifiable" and not payload.get(
                "confirm_unverified_target"):
            # **막지 않는다. 다만 모른다고 말한다.** 여기서 막으면 hostname 줄이
            # 없는 설정(FortiOS `show` 는 기본값을 출력하지 않는다)은 조치를
            # 영영 쓸 수 없다. 통과시키면 이름이 같은 남의 장비로 나간다.
            # 그래서 세 번째 길 — 확인할 수 없다는 사실과 실제로 응답한 장비를
            # 그대로 보여주고, 사용자가 그 대상을 명시적으로 확인하게 한다.
            # 시리얼이 없으면 '기억하겠다'는 **지키지 못할 약속**이다 — 고정할
            # 값이 없어 다음에도 같은 창이 뜬다(라운드 32 실측: 확인 후에도
            # remediation_serial 이 None 이고 문구가 그대로 반복됐다).
            if ident.get("why") == "serial_unread":
                # '다음에도 없다'는 **읽지 못한 경우엔 거짓**이다. 재시도로
                # 풀릴 수 있다는 사실까지 말해야 사용자가 매번 수동 확인을
                # 영구 부담으로 받아들이지 않는다(R75-1).
                _why = ("APO could not read the serial number from "
                        f"{device.get('ip')} this time, so it has nothing "
                        "unique to check this device by right now. Test the "
                        "connection again to retry — if the serial comes "
                        "through, APO remembers it and checks it "
                        f"automatically. Until then, confirm that "
                        f"{device.get('ip')} is the device you mean.")
            elif ident.get("why") == "no_serial":
                _why = ("This FortiGate does not report a serial number, so APO "
                        "has nothing unique to check it by — not now and not "
                        f"next time. Confirm that {device.get('ip')} is the "
                        "device you mean, every time you apply.")
            else:
                _why = ("APO has not confirmed this device before — a hostname "
                        "is not proof of identity, since two customers can both "
                        "call a firewall the same thing. Check that "
                        f"{device.get('ip')} really is "
                        f"'{ident['config'] or 'the device you are looking at'}' "
                        "and confirm to continue. APO remembers the serial and "
                        "checks it automatically from then on.")
            return jsonify({
                "error": _why,
                "identity": "unverifiable",
                "why": ident.get("why"),
                "connected_hostname": ident["connected"],
                "config_hostname": ident["config"],
                "target": {"ip": device.get("ip"), "port": device.get("port"),
                           "vdom": device.get("vdom"),
                           "serial": ident["serial"],
                           "fw_version": device.get("connected_version") or ""},
                "needs_confirmation": True}), 409
        results = disable_policies(device, policies)
        # **사용자가 확인한 대상을 이 장비의 신원으로 고정한다.** 다음부터는
        # 이름이 무엇이든 시리얼로 대조하므로, IP 오타가 조용히 통과하지 않는다.
        if ident["verdict"] == "unverifiable" and ident.get("serial") \
                and app.config.get('device_id'):
            try:
                _store().update_device_inputs(
                    app.config['device_id'],
                    remediation_serial=ident["serial"])
            except Exception as exc:
                print(f"[APO] could not pin serial: {exc}", flush=True)
        return jsonify({"results": results})

    @app.post("/api/remediation/export/postman")
    def remediation_export_postman():
        gate = _license_required()
        if gate:
            return gate
        from app.services.remediation_service import export_postman
        from io import BytesIO
        device = app.config.get('remediation_device', {})
        payload = request.get_json(silent=True) or {}
        policies = payload.get("policies", [])
        # 내보낸 명령은 나중에 사람이 붙여넣어 실행한다 — 잘못된 VDOM 을
        # 인쇄하면 시점만 늦을 뿐 결과는 조치 적용과 같다. 같은 규칙을 쓴다.
        _vbad = _vdom_conflicts(policies)
        if _vbad:
            return jsonify(_vdom_refusal(_vbad)), 409
        # 보류 규칙도 같다 — 인쇄한 명령은 결국 실행된다.
        _dbad = _deferral_refusal(policies)
        if _dbad:
            return jsonify(_dbad), 409
        if not policies:
            return jsonify({
                "error": "There is nothing to export yet — load the remediation "
                         "candidates first, then export.",
                "error_key": "no_candidates_loaded"}), 400
        # 대상 장비를 대지 않은 컬렉션은 실행할 수 없다 — 'https://:443' 로
        # 호스트가 빈 문서를 200 으로 배송하고 있었다(라운드 43 실측).
        if not (device or {}).get("ip"):
            return jsonify({
                "error": "Register and test the FortiGate first — a Postman "
                         "collection without a target address cannot be run.",
                "error_key": "no_device_registered"}), 400
        json_str = export_postman(policies, device)
        buf = BytesIO(json_str.encode("utf-8"))
        today = _date.today().isoformat()
        return app.response_class(
            response=buf.read(),
            status=200,
            mimetype="application/json",
            headers={"Content-Disposition": _attachment(
                f"apo_remediation_{_open_device_label()}_{today}.postman_collection.json")},
        )

    @app.post("/api/remediation/export/csv")
    def remediation_export_csv():
        gate = _license_required()
        if gate:
            return gate
        from app.services.remediation_service import export_csv
        from io import BytesIO
        payload = request.get_json(silent=True) or {}
        # **빈 파일을 정식 이름으로 내보내지 않는다.** '후보 불러오기'를 누르지
        # 않고 '내보내기'를 누르면 머리글만 있는 119바이트 파일이
        # `apo_remediation_{장비}_{날짜}.csv` 로 떨어졌다 — 같은 화면이 13건을
        # 보여주는 중이었고 경고도 없었다(라운드 43 실측). 변경관리 팩에
        # 들어가면 '이 장비에는 끌 정책이 없었다'는 사실 아닌 기록이 된다.
        if not (payload.get("to_disable") or payload.get("already_disabled")):
            return jsonify({
                "error": "There is nothing to export yet — load the remediation "
                         "candidates first, then export.",
                "error_key": "no_candidates_loaded"}), 400
        # 내보낸 명령은 나중에 사람이 붙여넣어 실행한다 — 잘못된 VDOM 을
        # 인쇄하면 시점만 늦을 뿐 결과는 조치 적용과 같다. 같은 규칙을 쓴다.
        _vbad = _vdom_conflicts((payload.get("to_disable") or []) + (payload.get("already_disabled") or []))
        if _vbad:
            return jsonify(_vdom_refusal(_vbad)), 409
        # **끄라고 적는 행에만 건다.** 'Already Disabled' 는 기록일 뿐이고
        # 명령을 만들지 않는다 — 거기까지 막으면 기록을 못 내보낸다.
        _dbad = _deferral_refusal(payload.get("to_disable") or [])
        if _dbad:
            return jsonify(_dbad), 409
        csv_bytes = export_csv(
            payload.get("to_disable", []),
            payload.get("already_disabled", []),
        )
        today = _date.today().isoformat()
        return app.response_class(
            response=csv_bytes,
            status=200,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": _attachment(
                f"apo_remediation_{_open_device_label()}_{today}.csv")},
        )

    @app.post("/api/remediation/export/apply-results")
    def remediation_export_apply_results():
        """적용 결과를 파일로. **되돌릴 수 없는 쓰기의 유일한 기록이 DOM 이었다.**

        새로고침하면 사라지는 자리에 감사 산출물이 있었다(2026-08-25 Jayden).
        서버에 이력을 보관하지는 않는다 — 그건 조치 이력 저장이라는 별개
        결정이고, 지금 필요한 것은 방금 화면에 뜬 것을 그대로 내려받는 것이다.
        """
        gate = _license_required()
        if gate:
            return gate
        from app.services.remediation_service import export_apply_results
        payload = request.get_json(silent=True) or {}
        results = payload.get("results")
        # 후보 CSV 와 같은 규칙 — 빈 파일을 정식 이름으로 내보내지 않는다.
        # 변경관리 팩에 들어가면 '아무것도 안 나갔다'는 사실 아닌 기록이 된다.
        if not results:
            return jsonify({
                "error": "There are no apply results to export yet — apply the "
                         "changes first, then export.",
                "error_key": "no_apply_results"}), 400
        dev = app.config.get('remediation_device') or {}
        # **시각은 서버가 찍는다.** 화면이 보낸 값을 그대로 쓰면 시계가 틀린
        # PC 나 조작된 값이 감사 기록의 시각이 된다.
        meta = {
            "applied_at": _dt.now().astimezone().isoformat(timespec="seconds"),
            "device": dev.get("connected_hostname") or _open_device_label(),
            "serial": dev.get("connected_serial") or "",
            "ip": dev.get("ip") or "",
        }
        csv_bytes = export_apply_results(results, meta)
        today = _date.today().isoformat()
        return app.response_class(
            response=csv_bytes, status=200,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": _attachment(
                f"apo_apply_results_{_open_device_label()}_{today}.csv")},
        )

    # ── License ────────────────────────────────────────────────────────────
    @app.get("/api/license/status")
    def license_status():
        info = get_license_info()
        if info:
            # **만료 예고를 준다.** 고객이 잠긴 뒤에 아는 것이 아니라 미리
            # 알아야 갱신이 일어난다(2026-09-10 상용화 검토 P0).
            _wend = _lic_window_end()
            return jsonify({"licensed": True, "email": info.get("email"),
                            "issued": info.get("issued"),
                            "exp": info.get("exp"),
                            "update_window_end": _wend.isoformat() if _wend else None,
                            # 기존 키에는 tier가 없다 → 단일 조직으로 간주(하위호환)
                            "tier": info.get("tier") or "single"})
        # **왜 안 되는지 말한다.** 키가 있는데 자격을 잃은 경우와 아예 없는
        # 경우는 다르다 — 앞의 경우 그냥 "Free" 로 보이면 돈 낸 고객이 자기가
        # 왜 무료 사용자가 됐는지 알 수 없다.
        return jsonify({"licensed": False, "problem": _lic_problem()})

    # ── 화이트라벨 브랜딩 (MSP·컨설턴트 티어 전용) ─────────────────────────
    # 컨설턴트는 고객사에 제출하는 보고서에 자기 회사명을 실어야 한다.
    # 단일 조직 티어와의 실질 구분점이므로 서버측에서 티어를 강제한다.
    # frozen exe에서 DATA_DIR는 _MEIPASS(매 실행 새로 추출·종료 시 삭제) 하위라
    # 여기 쓰면 브랜딩이 재시작마다 사라진다(재비판 NEW-BUG). 라이선스 파일과
    # 같은 원칙으로 exe 인접 경로에 영속한다.
    if getattr(_sys, 'frozen', False):
        _BRANDING_FILE = Path(_sys.executable).parent / "branding.json"
    else:
        _BRANDING_FILE = DATA_DIR / "branding.json"

    def _load_branding() -> dict:
        try:
            data = json.loads(_BRANDING_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _branding_allowed() -> bool:
        info = get_license_info()
        return bool(info) and (info.get("tier") or "single") == "msp"

    @app.get("/api/report/branding")
    def report_branding_get():
        return jsonify({"allowed": _branding_allowed(),
                        "branding": _load_branding() if _branding_allowed() else {}})

    @app.post("/api/report/branding")
    def report_branding_set():
        if not _branding_allowed():
            return jsonify({"error": "Report branding requires an MSP / Consultant "
                            "license. Single-organization licenses export unbranded "
                            "reports."}), 403
        payload = request.get_json(silent=True) or {}
        # C0 제어문자는 openpyxl이 거부해 export 전체가 400으로 죽고(재비판
        # NEW-BUG), 개행·양방향 제어문자는 셀 표시를 왜곡한다. 전부 공백 치환.
        import re as _re
        _clean = lambda v: _re.sub(
            "[\\x00-\\x1f\\x7f\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]",
            " ", str(v))[:80].strip()
        branding = {
            "company":      _clean(payload.get("company", "")),
            "prepared_for": _clean(payload.get("prepared_for", "")),
        }
        _BRANDING_FILE.parent.mkdir(parents=True, exist_ok=True)
        _BRANDING_FILE.write_text(json.dumps(branding, ensure_ascii=False),
                                  encoding="utf-8")
        return jsonify({"ok": True, "branding": branding})

    @app.post("/api/license/activate")
    def license_activate():
        payload = request.get_json(silent=True) or {}
        key = str(payload.get("key", "")).strip()
        if not key:
            return jsonify({"error": "key is required"}), 400
        try:
            data = activate(key)
            return jsonify({"ok": True, "email": data.get("email"), "issued": data.get("issued")})
        except ValueError as e:
            # LicenseMessage 는 ValueError 를 상속한다 — 사용자에게 보여도 되는
            # 문장만 이 타입으로 온다(license_checker 참조).
            return jsonify({"error": str(e)}), 400
        except OSError as exc:
            # **키가 맞아도 파일을 못 쓰면 등록이 안 된다.** 읽기 전용 위치에
            # 설치하면 여기서 맨 500 이 났다 — 돈을 낸 사람이 무엇이 잘못됐는지
            # 못 듣는 자리다(라운드 39 지적).
            print(f"[APO] licence file not writable: {exc!r}", flush=True)
            from app.services.license_checker import _license_path
            try:
                where = str(_license_path().parent)
            except Exception:
                where = "the folder next to APO.exe"
            return jsonify({
                "error": "Your key is valid, but APO could not save it in "
                         f"'{where}'. Windows blocks writes in Program Files and "
                         "on some network shares. Move APO.exe to a folder you "
                         "own (for example Documents\\APO) and enter the key "
                         "again.",
                "error_key": "licence_not_writable", "path": where}), 507

    return app
