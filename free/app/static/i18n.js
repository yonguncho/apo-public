/* APO 화면 언어 — 메뉴·제목·설명·버튼만 번역한다.
 *
 * 판정 사유, 조치 라벨, 정책/객체 이름, Last Used 같은 표 내용은 **영어로 둔다**.
 * 이유가 둘이다:
 *   1) 그 문자열들은 엔진이 만들어 엑셀 산출물에도 그대로 실린다. 화면만 한글로
 *      바꾸면 같은 판정이 두 곳에서 다른 말로 나온다 — 이번 개발에서 화면과
 *      산출물이 어긋나 생긴 사고를 여러 번 고쳤다.
 *   2) FortiGate 엔지니어는 hit count·last used·srcaddr를 영어로 읽는다.
 *      번역하면 오히려 대조가 어려워진다.
 *
 * 키는 영어 원문 자체다. 사전에 없으면 원문이 그대로 남는다(안전한 폴백).
 */
(function () {
  "use strict";

  const KO = {
    // ── 사이드바 ──
    "Overview": "개요",
    "Sources": "데이터 가져오기",
    "Findings": "점검 결과",
    "Policy findings": "정책 판정",
    "Shadowed (unreachable)": "가려진 정책",
    "FortiOS advisories": "FortiOS 권고",
    "Action Plan": "조치 계획",
    "Change review": "변경 비교",
    "Evidence": "감사 증적",
    "Config migration": "설정 마이그레이션",
    "Download the address list (CSV)": "주소 목록 내려받기 (CSV)",
    "Paste a list": "목록 붙여넣기",
    "Hide the paste box": "붙여넣기 접기",
    "Fill the table": "표에 채우기",
    "Two columns per line — the current address, then the new one. Tab, comma or spaces all work. Leave the second column empty to retire an address.": "한 줄에 두 열 — 현재 주소, 그다음 새 주소. 탭·쉼표·공백 모두 됩니다. 폐기할 주소는 둘째 열을 비우십시오.",
    "Filled {hit} of {total} rows.": "{total}행 중 {hit}행을 채웠습니다.",
    "Filled {hit} of {total} rows. {unknown} are not in this range, {bad} lines could not be read.": "{total}행 중 {hit}행을 채웠습니다. {unknown}건은 이 대역에 없고, {bad}줄은 읽지 못했습니다.",
    "Leave this alone": "그대로 두세요",
    "A wider range that merely contains your target. Changing it would move every policy that uses it.": "대상을 포함하기만 하는 상위 대역입니다. 바꾸면 이것을 쓰는 정책이 전부 옮겨집니다.",
    "A real IP setting — {arg} becomes the new value.": "실제 IP 설정값입니다 — {arg} 가 새 값이 됩니다.",
    "The object name contains {arg}.": "객체 이름에 {arg} 가 들어 있습니다.",
    "Follows the rename of \"{arg}\". Leaving it behind would point this policy at an object that no longer exists.": "\"{arg}\" 의 이름 변경을 따라갑니다. 빠뜨리면 이 정책이 없는 객체를 가리키게 됩니다.",
    "A note for humans. FortiOS never executes this line.": "사람이 읽는 메모입니다. FortiOS 는 이 줄을 실행하지 않습니다.",
    "{arg} is not in your mapping table.": "{arg} 가 매핑표에 없습니다.",
    "{arg} is marked as retired, so this setting is left as it is.": "{arg} 는 폐기로 표시돼 이 설정을 그대로 둡니다.",
    "{arg} is a wider range that contains your target — not something to renumber.": "{arg} 는 대상을 포함하는 상위 대역입니다 — 번호를 바꿀 대상이 아닙니다.",
    "No definition for \"{arg}\" was found in this configuration.": "이 설정에서 \"{arg}\" 의 정의를 찾지 못했습니다.",
    "Nothing to do here if you keep the object name.": "객체 이름을 그대로 두면 여기는 손댈 필요가 없습니다.",
    "If that name is defined in another VDOM or on another device, it has to be changed there too.": "그 이름이 다른 VDOM 이나 다른 장비에 정의돼 있으면 그쪽도 바꿔야 합니다.",
    "The source line no longer matches the plan, so it was skipped.": "원문이 계획과 달라 건너뛰었습니다.",
    "The new address does not line up with the existing netmask.": "새 주소가 기존 넷마스크와 맞지 않습니다.",
    "Another address maps to this same new value.": "다른 주소도 같은 새 값으로 지정돼 있습니다.",
    "This new address is already used elsewhere in the configuration.": "이 새 주소는 설정의 다른 곳에서 이미 쓰이고 있습니다.",
    "The renamed object would clash with another object.": "이름을 바꾸면 다른 객체와 겹칩니다.",
    "You mapped a wider range. Changing it moves every policy that uses it.": "상위 대역을 지정했습니다. 바꾸면 이것을 쓰는 정책이 전부 옮겨집니다.",
    "These addresses are in the old range but not in your table: {list}": "구 대역에 있는데 표에 없는 주소입니다: {list}",
    "These addresses have no new value, so they will be left as they are: {list}": "새 값이 없어 그대로 두게 되는 주소입니다: {list}",
    "More than one address maps to the same new value: {list}": "여러 주소가 같은 새 값으로 지정돼 있습니다: {list}",
    "Renaming would make two objects share a name. FortiOS merges them and one disappears: {list}": "이름을 바꾸면 두 객체가 같은 이름이 됩니다. FortiOS 는 둘을 합치고 하나가 사라집니다: {list}",
    "APO could not read the configuration to the end (a quote opens on line {line} and never closes), so this plan is incomplete.": "설정을 끝까지 읽지 못했습니다({line}번째 줄에서 따옴표가 열린 채 닫히지 않습니다). 이 계획은 완전하지 않습니다.",
    "Tick the confirmation boxes below if these are what you intended.": "의도한 것이 맞으면 아래 확인란을 체크하십시오.",
    "I confirm the duplicate values are intended": "중복된 값은 의도한 것입니다",
    "I understand the configuration was not read to the end": "설정을 끝까지 읽지 못했음을 이해합니다",
    "Take a fresh backup from the device now — the file you uploaded may no longer match what is running. That fresh backup is your rollback.": "지금 장비에서 백업을 새로 받으십시오 — 올린 파일이 현재 동작 중인 설정과 다를 수 있습니다. 그 새 백업이 되돌리는 수단입니다.",
    "Clear the parser log first so you are not reading an old one:": "이전 기록을 읽지 않도록 파서 로그를 먼저 지우십시오:",
    "Restore the produced file during a maintenance window. If this device is in an HA cluster, both units reboot together — the passive unit does not cover for you.": "유지보수 시간에 만들어진 파일을 복원하십시오. HA 클러스터면 두 유닛이 함께 재부팅합니다 — passive 유닛이 대신해 주지 않습니다.",
    "After the device is back up, run this and confirm it is empty:": "장비가 다시 올라온 뒤에 이것을 실행해 비어 있는지 확인하십시오:",
    "To undo, restore the backup you took in step 1. Note that this also reverts anything else changed since then. The notes file lists new → old.": "되돌리려면 1단계에서 받은 백업을 복원하십시오. 그 사이의 다른 변경도 함께 되돌아갑니다. 메모 파일에 신 → 구 표가 있습니다.",
    "{n} old values are still there.": "옛 값 {n}건이 남아 있습니다.",
    "{n} policies point at an object name that does not exist.": "정책 {n}건이 없는 객체 이름을 가리킵니다.",
    "{n} planned changes were not applied.": "계획한 변경 {n}건이 적용되지 않았습니다.",
    "The configuration could not be read to the end.": "설정을 끝까지 읽지 못했습니다.",
    "Check the plan before using this file.": "이 파일을 쓰기 전에 계획을 확인하십시오.",
    "The produced file was re-read: no old value left behind, no broken object reference, every planned change applied.": "만들어진 파일을 다시 읽었습니다: 남은 옛 값 없음, 깨진 객체 참조 없음, 계획한 변경 전부 적용됨.",
    "(before restoring)": "(복원 전)",
    "(after it comes back up)": "(다시 올라온 뒤)",
    "broken object references": "깨진 객체 참조",
    "planned changes not applied": "적용되지 않은 계획 변경",
    "Addresses left as they are (retired)": "그대로 둔 주소(폐기)",
    "Wider ranges deliberately untouched": "일부러 손대지 않은 상위 대역",
    "ambiguous — more than one source": "모호함 — 출처가 둘 이상",
    "FortiOS treats the second one as an edit of the first, so an object disappears.":
        "FortiOS 는 두 번째를 첫 객체 편집으로 처리해서, 객체 하나가 사라집니다.",
    "Left alone — this range only contains the addresses you are changing. Changing it would move every policy that uses it.":
        "손대지 않습니다 — 이 대역은 지금 바꾸는 주소들을 포함할 뿐입니다. 바꾸면 이 대역을 쓰는 정책의 범위가 전부 달라집니다.",
    "The configuration could not be read past line {line} — a quote is not closed.":
        "{line}번째 줄부터 설정을 읽지 못했습니다 — 따옴표가 닫히지 않았습니다.",
    "Their settings will be left exactly as they are.":
        "해당 설정은 그대로 둡니다.",
    "This plan changes {n} settings that the device is reached through. Before you restore, make sure you have a console or another path that does not go through them — rolling back also needs access.":
        "이 계획은 장비에 접속하는 경로 {n}곳을 바꿉니다. 복원하기 전에 콘솔이나 그 경로를 타지 않는 다른 접속 수단을 확보하세요 — 되돌리는 것도 접속이 있어야 합니다.",
    "Two objects would become one.":
        "객체 두 개가 하나로 합쳐집니다.",
    "duplicate object definitions":
        "중복 정의된 객체",
    "in an HA cluster run it on both units, then check the cluster is back with":
        "HA 구성이면 두 유닛 모두에서 실행하고, 클러스터가 다시 붙었는지 확인하세요",
    "old values still in the target range (may be normal)":
        "대상 대역에 남아 있는 옛 값 (정상일 수 있음)",
    "unexpected old values":
        "설명되지 않는 옛 값",
    "{n} addresses are marked for retirement (left blank).":
        "주소 {n}개를 폐기로 표시했습니다(빈 칸).",
    "{n} larger ranges contain the addresses you are changing. They are left alone.":
        "지금 바꾸는 주소를 포함하는 상위 대역이 {n}개 있습니다. 손대지 않습니다.",
    "{n} new addresses are each used by more than one old address.":
        "새 주소 {n}개가 각각 둘 이상의 옛 주소에서 쓰입니다.",
    "{n} object names are defined twice — FortiOS would keep only one of them.":
        "객체 이름 {n}개가 두 번 정의됩니다 — FortiOS 는 그중 하나만 남깁니다.",
    "{n} of the new addresses are already used elsewhere in this config.":
        "새 주소 중 {n}개는 이 설정의 다른 곳에서 이미 쓰이고 있습니다.",
    "{n} renamed objects would end up with a name that already exists.":
        "이름을 바꾼 객체 {n}개가 이미 있는 이름과 같아집니다.",
    "Only the first {shown} of {all} rows are listed.":
        "전체 {all}행 중 앞의 {shown}행만 적혀 있습니다.",
    "Downloaded 2 files: the configuration (.conf) and the change record ({ext}).":
        "파일 2개를 받았습니다 — 설정 파일(.conf)과 변경내역({ext}).",
    "Download the change list as CSV": "변경내역을 CSV 로 받기",
    "Rename objects (optional)": "객체 이름 바꾸기 (선택)",
    "{n} objects": "{n}개",
    "keep as it is": "그대로 둠",
    "You renamed this object.": "이 객체의 이름을 직접 지정하셨습니다.",
    "Leave a box empty to keep the name as it is. When you rename an object, every policy and group that points at it follows automatically.":
        "빈 칸으로 두면 이름을 바꾸지 않습니다. 이름을 바꾸면 그 객체를 가리키는 정책과 그룹이 모두 자동으로 따라갑니다.",
    "The old name is not replaced inside comments and descriptions — those are notes for people, not settings.":
        "주석과 설명 안의 옛 이름은 바뀌지 않습니다 — 설정값이 아니라 사람이 읽는 메모이기 때문입니다.",
    "For importing into another system. The workbook (.xlsx) is the one to file.":
        "다른 시스템에 넣을 때 씁니다. 결재·감사에 내는 것은 워크북(.xlsx)입니다.",
    "Could not build the CSV. The workbook (.xlsx) you already received has the same table.":
        "CSV 를 만들지 못했습니다. 이미 받으신 워크북(.xlsx)에 같은 표가 있습니다.",
    // 장비 이관에는 IP 흐름 같은 `.txt` 대비책이 없다 — 못 받았다는 사실을
    // 말하고 다시 누르게 한다(없는 것을 지어내 두 벌을 만들지 않는다).
    "The configuration (.conf) was downloaded, but the change record could not be built. Press the button again to try once more.":
        "설정 파일(.conf)은 받았지만 변경내역을 만들지 못했습니다. 버튼을 한 번 더 눌러 주세요.",
    "Read the self-check section below before restoring it.":
        "복원하기 전에 아래 자기검증 항목을 읽으세요.",
    "To undo: object names that were renamed (new → old)":
        "되돌리기: 이름이 바뀐 객체 (새 이름 → 옛 이름)",
    "WARNING: this file did not pass APO self-check.":
        "경고: 이 파일은 APO 자기검증을 통과하지 못했습니다.",
    "What changes, line by line":
        "무엇이 바뀌는가 (줄 단위)",
    "none":
        "없음",
    "Filled {hit} of {total} rows. {unknown} are not in this range, {bad} lines could not be read, {garbled} new values are not valid addresses.":
        "{total}행 중 {hit}행을 채웠습니다. {unknown}개는 이 대역이 아니고, {bad}줄은 읽지 못했고, {garbled}개는 올바른 주소가 아닙니다.",
    "Nothing in this configuration uses that range. Try a wider range.":
        "이 설정에서 해당 대역을 쓰는 곳이 없습니다. 더 넓은 대역으로 조회해 보세요.",
    "To undo, restore the backup you took before starting. Note that this also reverts anything else changed since then. The notes file lists new → old for both addresses and object names.":
        "되돌리려면 시작 전에 받아 둔 백업을 복원하세요. 그 이후의 다른 변경도 함께 되돌아갑니다. 메모 파일에 주소와 객체 이름의 새→옛 대응이 있습니다.",
    "This backup contains {bytes} bytes that are not UTF-8 (often Korean comments saved in another encoding). APO cannot read them, so they will be missing from the file it produces — even on lines it does not touch.":
        "이 백업에는 UTF-8 이 아닌 바이트가 {bytes}개 있습니다(다른 인코딩으로 저장된 한글 주석인 경우가 많습니다). APO 가 읽지 못하므로, 만들어지는 파일에서는 그 내용이 빠집니다 — APO 가 건드리지 않는 줄에서도 그렇습니다.",
    "{n} bytes of this backup are not UTF-8 and cannot be read.":
        "이 백업의 {n}바이트는 UTF-8 이 아니라 읽을 수 없습니다.",
    "They will be missing from the produced file, including on lines APO does not change.":
        "만들어지는 파일에서는 그 내용이 빠집니다. APO 가 바꾸지 않는 줄도 마찬가지입니다.",
    "Showing the first {shown} of {all} addresses. Use the download and paste buttons above to fill in the rest — the file contains every address.":
        "주소 {all}개 중 앞의 {shown}개만 표시합니다. 나머지는 위의 내려받기·붙여넣기 버튼으로 채우세요 — 파일에는 모든 주소가 들어 있습니다.",
    "The remaining {n} are left alone (wider ranges, comments, and addresses you did not map).":
        "나머지 {n}건은 손대지 않습니다(상위 대역, 주석, 매핑하지 않은 주소).",
    "After this change the gateway is no longer inside the subnet of interface {arg}. The route goes inactive on reboot and the device loses that path.":
        "이 변경 후 게이트웨이가 인터페이스 {arg} 의 대역 밖에 있게 됩니다. 재부팅하면 그 경로가 비활성이 되어 장비가 해당 통신 경로를 잃습니다.",
    "{n} of them are used for device access, and this plan changes {c} of those.":
        "그중 {n}건은 장비 접속에 쓰이며, 이 계획은 그중 {c}건을 바꿉니다.",
    "These rows were not used — APO could not tell what you meant:":
        "다음 줄은 반영하지 않았습니다 — 무엇을 뜻하는지 판단할 수 없습니다:",
    "These lines had no address APO could read:":
        "다음 줄에서는 읽을 수 있는 주소를 찾지 못했습니다:",
    "{n} object names end up defined more than once ({m} extra definitions) — FortiOS keeps only the first of each.":
        "객체 이름 {n}개가 두 번 이상 정의됩니다(초과 정의 {m}개) — FortiOS 는 각각의 첫 번째만 남깁니다.",
    "object names defined more than once":
        "두 번 이상 정의된 객체 이름",
    "extra definitions":
        "초과 정의",
    "lines":
        "줄",
    "(blank)":
        "(비움)",
    "These addresses are not in the range you searched:":
        "다음 주소는 조회한 대역에 없습니다:",
    "Not built yet — answer the questions above, then press the button again.":
        "아직 만들지 않았습니다 — 위 질문에 답한 뒤 버튼을 다시 누르세요.",
    "That file is empty.":
        "빈 파일입니다.",
    "That file has no config-version header, so APO cannot tell which model and version it came from.":
        "이 파일에는 config-version 헤더가 없어, 어떤 모델·버전에서 나온 것인지 알 수 없습니다.",
    "Upload a backup from the new device first — APO needs to know which interfaces it has.":
        "새 장비의 백업을 먼저 올리세요 — 그 장비에 어떤 인터페이스가 있는지 알아야 합니다.",
    "Which device are you moving to?":
        "어느 장비로 옮기나요?",
    "Match each interface to one on the new device":
        "인터페이스를 새 장비의 것과 짝지으세요",
    "Read the new device":
        "새 장비 읽기",
    "Move to another device (different model or version)":
        "다른 장비로 이관 (모델·버전이 다름)",
    "I know some interfaces have no match, and I want the file anyway.":
        "짝이 없는 인터페이스가 있다는 것을 알고, 그래도 파일을 만들겠습니다.",
    /* "On this device" · "On the new device" 를 여기서 지웠다(B-86).
       index.html:802 의 그 `<th>` 두 개에 `data-i18n` 이 없어 한 번도 쓰인 적이
       없는 죽은 키였다. 형제 이관 표 네 개(758·861·895·767행)도 전부 맨 `<th>`
       라, 이 표만 번역하면 오히려 어긋난다. **표 헤더 번역은 앱 전역 결정**이고
       그때 다섯 표를 함께 고친다 — 쓰이지 않는 키를 남겨 두면 "번역했다"는
       착각만 남는다. */
    "Every policy, address object and route that names an interface moves with it. Leave a row blank to keep that name — but if the new device has no such port, the settings that use it will not load.":
        "인터페이스 이름을 쓰는 정책·주소 객체·경로가 함께 옮겨집니다. 칸을 비우면 그 이름을 그대로 둡니다 — 다만 새 장비에 그런 포트가 없으면 그것을 쓰는 설정은 올라가지 않습니다.",
    "This configuration came from {a}, and you are moving it to {b}.":
        "이 설정은 {a} 에서 나왔고, {b} 로 옮기려 합니다.",
    "The firmware versions differ. Fortinet's own advice is to bring the new device to the same version first — APO does not translate settings between versions.":
        "펌웨어 버전이 다릅니다. Fortinet 도 새 장비를 같은 버전으로 먼저 맞추라고 권합니다 — APO 는 버전 간 설정을 번역하지 않습니다.",
    "{n} interfaces on this device do not exist on the new one. Match them below.":
        "이 장비의 인터페이스 {n}개가 새 장비에는 없습니다. 아래에서 짝지으세요.",
    "This device encrypts its secrets with your own key. Set the same key on the new device before restoring, or the secrets will not load.":
        "이 장비는 관리자가 정한 키로 비밀을 암호화합니다. 복원 전에 새 장비에 같은 키를 넣으세요. 그러지 않으면 비밀이 올라가지 않습니다.",
    "{n} encrypted settings are carried over untouched — they keep working on the new device. Worth spot-checking VPN and RADIUS after the move.":
        "암호화된 설정 {n}건은 손대지 않고 그대로 옮겨집니다 — 새 장비에서도 동작합니다. 이관 후 VPN·RADIUS 는 한 번 확인해 보세요.",
    "{n} sections belong to this hardware and have no counterpart on the new device. Review them before restoring.":
        "섹션 {n}개는 이 하드웨어에 매인 것이라 새 장비에 대응이 없습니다. 복원 전에 확인하세요.",
    "{n} names are referenced but never defined here — that was already the case before the move.":
        "이름 {n}개는 참조만 되고 여기에 정의가 없습니다 — 이관 전부터 그랬습니다.",
    "Every interface this configuration uses also exists on the new device. Nothing to match.":
        "이 설정이 쓰는 인터페이스가 새 장비에 전부 있습니다. 짝지을 것이 없습니다.",
    "Take a fresh backup from the new device now — that is your rollback.":
        "지금 새 장비에서 백업을 받아 두세요 — 그것이 되돌리기 수단입니다.",
    "Restore the produced file. The device reboots.":
        "만들어진 파일을 복원하세요. 장비가 재부팅됩니다.",
    "After it comes back up, run this and confirm it is empty:":
        "장비가 다시 올라오면 이것을 실행해 비어 있는지 확인하세요:",
    "Check the interfaces, then a few policies that use them.":
        "인터페이스를 확인하고, 그것을 쓰는 정책 몇 개를 대조하세요.",
    "The header, {d} interface definitions and {r} references moved together. Encrypted settings were not touched.":
        "헤더와 인터페이스 정의 {d}개, 참조 {r}개가 함께 옮겨졌습니다. 암호화된 설정은 건드리지 않았습니다.",
    "Choose a backup file first.":
        "백업 파일을 먼저 고르세요.",
    "Reading…":
        "읽는 중…",
    "Could not read that file.":
        "그 파일을 읽지 못했습니다.",
    "Preflight failed.":
        "사전 점검에 실패했습니다.",
    "These interfaces have no match on the new device: {list}":
        "다음 인터페이스는 새 장비에 짝이 없습니다: {list}",
    "Two interfaces would end up with the same name: {list}":
        "인터페이스 두 개가 같은 이름이 됩니다: {list}",
    "FortiOS allows at most 15 characters in an interface name: {list}":
        "FortiOS 는 인터페이스 이름을 15자까지만 받습니다: {list}",
    "The new device has no such interface: {list}":
        "새 장비에 그런 인터페이스가 없습니다: {list}",
    "Match the firmware version first. This step moves the interface layout and everything that names it — it does not translate settings between versions. Bring the new device to the same version as this one, then take a backup from it and upload it here. A factory-default backup is enough. Your encrypted settings are not touched; they are carried over exactly as they are.":
        "<strong>펌웨어 버전을 먼저 맞추세요.</strong> 이 단계는 인터페이스 배열과 그 이름을 쓰는 모든 설정을 옮기지, 버전 간 설정 문법을 번역하지는 않습니다. 새 장비를 이 장비와 같은 버전으로 맞춘 뒤 백업을 받아 여기 올리세요. 공장초기 백업이면 충분합니다. <strong>암호화된 설정은 건드리지 않습니다.</strong> 있는 그대로 옮겨집니다.",
    "These two run different firmware — {a} and {b}. Bring the new device to the same version before restoring: this migration moves the interface layout, not the settings syntax.":
        "두 장비의 펌웨어가 다릅니다 — {a} 와 {b}. 복원 전에 새 장비를 같은 버전으로 맞추세요. 이 이관은 인터페이스 배열을 옮기지 설정 문법을 번역하지 않습니다.",
    "Pick from the ports the new device has spare.":
        "새 장비에 남는 포트 중에서 고르세요.",
    "Checking what would break…":
        "무엇이 깨지는지 확인하는 중…",
    "This file has no config-version header, so APO cannot tell which version it came from. Make sure it matches the new device — this migration moves the interface layout, not the settings syntax.":
        "이 파일에는 config-version 헤더가 없어서 어느 버전에서 왔는지 알 수 없습니다. 새 장비와 같은 버전인지 직접 확인하세요 — 이 이관은 인터페이스 배열을 옮기지 설정 문법을 번역하지 않습니다.",
    "These ports exist on the new device but this configuration already refers to them, so they are not offered as targets: {list}":
        "이 포트들은 새 장비에 있지만 이 설정이 이미 참조하고 있어서 대상으로 제시하지 않습니다: {list}",
    "Not built yet — change the interface choices above, then press the button again.":
        "아직 만들지 않았습니다 — 위에서 인터페이스 선택을 바꾼 뒤 버튼을 다시 누르세요.",
    "{n} names are used here but never defined in this file, and the new device has no such port either. If they are real ports on the device you are moving from, match them below — otherwise those lines were already dead and will stay that way.":
        "이 파일에서 이름 {n}개가 쓰이기만 하고 정의되지 않았는데, 새 장비에도 그런 포트가 없습니다. 지금 장비에 실재하는 포트라면 아래에서 짝지으세요 — 아니라면 그 줄들은 원래부터 죽어 있었고 앞으로도 그렇습니다.",
    "That file lists no interfaces, so APO cannot tell which ports the new device has. Take a backup from the device itself — a factory-default one is fine.":
        "그 파일에는 인터페이스가 하나도 없어서 새 장비에 어떤 포트가 있는지 알 수 없습니다. 장비에서 직접 백업을 받아 주세요 — 공장초기 상태여도 괜찮습니다.",
    "Careful — {d} interface definitions in this file, and the {r} references to them, point at ports the new device does not have. FortiOS will drop those lines on restore without saying so. The file name is marked INCOMPLETE.":
        "주의 — 이 파일의 인터페이스 정의 {d}개와 그것을 가리키는 참조 {r}건이 새 장비에 없는 포트를 향합니다. FortiOS 는 복원할 때 그 줄들을 아무 말 없이 버립니다. 파일 이름에 INCOMPLETE 를 붙였습니다.",
    "{d} interface definitions and {r} references moved together. This file had no config-version header, so there was none to replace — set the model and version on the new device yourself. Encrypted settings were not touched.":
        "인터페이스 정의 {d}개와 참조 {r}건이 함께 옮겨졌습니다. 이 파일에는 config-version 헤더가 없어서 바꿀 것이 없었습니다 — 모델과 버전은 새 장비에서 직접 맞추세요. 암호화된 설정은 건드리지 않았습니다.",
    "After it comes back up, run this and read it — it will not be empty:":
        "장비가 올라오면 이것을 실행해 읽어 보세요 — 비어 있지 않습니다:",
    "The complaints should be the ports you chose to leave behind.":
        "지적된 것은 남겨 두기로 한 포트뿐이어야 합니다.",
    "These names were never defined in your configuration and the new device has no such port, so those lines were already dead: {list}":
        "아래 이름들은 설정에 정의된 적이 없고 새 장비에도 그런 포트가 없어서, 그 줄들은 원래부터 죽어 있던 것입니다: {list}",
    "One of the interface rows could not be read. Reload the page and pick the interfaces again.":
        "인터페이스 행 하나를 읽지 못했습니다. 페이지를 새로 고친 뒤 인터페이스를 다시 고르세요.",
    "{d} interface definitions and {r} references moved together. The header already matches the new device, so there was nothing to replace. Encrypted settings were not touched.":
        "인터페이스 정의 {d}개와 참조 {r}건이 함께 옮겨졌습니다. 헤더가 이미 새 장비와 같아서 바꿀 것이 없었습니다. 암호화된 설정은 건드리지 않았습니다.",
    "This configuration does not say which device it came from. You are moving it to {b}.":
        "이 설정에는 어느 장비에서 나왔는지 적혀 있지 않습니다. {b} 로 옮기려 합니다.",
    "Careful — {d} interfaces defined in this file do not exist on the new device. FortiOS will drop those lines on restore without saying so. The file name is marked INCOMPLETE.":
        "주의 — 이 파일에 정의된 인터페이스 {d}개가 새 장비에 없습니다. FortiOS 는 복원할 때 그 줄들을 아무 말 없이 버립니다. 파일 이름에 INCOMPLETE 를 붙였습니다.",
    "The new device changed while you were working — this file was built for {a}, not {b}.":
        "작업 중에 새 장비가 바뀌었습니다 — 이 파일은 {b} 가 아니라 {a} 용으로 만들어졌습니다.",
    "Check the new device again":
        "새 장비를 다시 확인",
    "Moving this configuration to a different model. APO matches the interface layout and everything that names it — it does not translate settings between firmware versions.":
        "이 설정을 다른 모델로 옮깁니다. APO 는 인터페이스 배열과 그 이름을 쓰는 모든 설정을 맞춰 주지만, 펌웨어 버전 간 설정 문법을 번역하지는 않습니다.",
    "Open the configuration you want to move first, then upload the new device's backup here.":
        "먼저 옮길 설정을 연 다음, 여기에 새 장비의 백업을 올리세요.",
    "Opening a device clears the migration work in progress ({n} item(s) you entered). Continue?":
        "장비를 열면 진행 중인 이관 작업이 지워집니다(입력하신 {n}건). 계속할까요?",
    "Reopening discards the migration work in progress ({n} item(s) you entered).":
        "다시 열면 진행 중인 이관 작업이 지워집니다(입력하신 {n}건).",
    "The migration work in progress ({n} item(s) you entered) is discarded as well.":
        "진행 중인 이관 작업(입력하신 {n}건)도 함께 지워집니다.",
    "The values changed. Preview again to see what will change.":
        "값이 바뀌었습니다. 무엇이 바뀌는지 다시 미리보기 하세요.",
    "Some choices need confirming before APO will build the file.": "파일을 만들기 전에 확인해야 할 항목이 있습니다.",
    "Step 1": "1단계",
    "What are you changing?": "무엇을 바꾸나요?",
    "IP address or range": "IP 주소 또는 대역",
    "Interface (not built yet)": "인터페이스 (아직 없음)",
    "Show every reference": "참조 전체 보기",
    "Hide the full reference list": "참조 목록 접기",
    "The device refuses to change an address while something still references it — Command fail. Return code -23. The official answer is to delete every reference, change it, then rebuild them, which leaves a hole in your policy while you work. Editing the configuration file changes the value and all of its references in one step.": "장비는 무언가가 그 주소를 참조하는 동안 변경을 거부합니다 — Command fail. Return code -23. 공식 해법은 참조를 전부 지우고, 바꾸고, 다시 만드는 것인데 그 사이 정책에 구멍이 납니다. 설정 파일을 고치면 값과 그 모든 참조가 한 번에 바뀝니다.",
    "Detail is not available for this address (the reference list was capped).": "이 주소의 상세는 볼 수 없습니다(참조 목록이 상한에서 잘렸습니다).",
    "Check what will change": "무엇이 바뀌는지 확인",
    "Read-only — edit in step 2.": "읽기 전용입니다 — 수정은 2단계에서 합니다.",
    "Step 4": "4단계",
    "Put it on the device": "장비에 넣기",
    "APO does not touch the device.": "APO 는 장비를 건드리지 않습니다.",
    "Build the file in step 3 first.": "먼저 3단계에서 파일을 만드십시오.",
    "Restoring a configuration reboots the device by default. Setting reboot-upon-config-restore to disable avoids the immediate reboot, but a manual reboot is still required for the configuration to take effect fully — the downtime moves, it does not disappear. Plan a maintenance window.": "설정 복원은 기본적으로 장비를 재부팅합니다. reboot-upon-config-restore 를 disable 하면 즉시 재부팅은 피하지만, 설정이 완전히 적용되려면 결국 수동 재부팅이 필요합니다 — 중단 시간은 사라지는 것이 아니라 옮겨질 뿐입니다. 유지보수 시간을 잡으십시오.",
    "Offline checks cannot see everything. Even the device's own pre-commit validation misses constraints that only appear at commit time. Treat the plan as a well-founded proposal, not a guarantee.": "오프라인 검사는 전부를 볼 수 없습니다. 장비 자신의 사전 검증조차 적용 시점에만 드러나는 제약은 놓칩니다. 이 계획은 근거 있는 제안이지 보증이 아닙니다.",
    "{changed} of {total} lines changed.": "전체 {total}줄 중 {changed}줄이 바뀌었습니다.",
    "The produced file was re-read and no old value was left behind.": "만들어진 파일을 다시 읽어 확인했고, 남아 있는 옛 값은 없습니다.",
    "{n} old values are still in the produced file — check the plan before using it.": "만들어진 파일에 옛 값 {n}건이 남아 있습니다 — 쓰기 전에 계획을 확인하십시오.",
    "Keep the original backup. It is your rollback — APO does not modify it.": "원본 백업을 보관하십시오. 그것이 되돌리는 수단입니다 — APO 는 원본을 고치지 않습니다.",
    "Restore the produced file onto the device during a maintenance window.": "유지보수 시간에 만들어진 파일을 장비에 복원하십시오.",
    "Run this and confirm it is empty:": "다음을 실행해 비어 있는지 확인하십시오:",
    "Spot-check a few of the changed lines on the device itself.": "바뀐 줄 몇 개를 장비에서 직접 확인하십시오.",
    "To undo, restore the original backup. The notes file also lists new → old.": "되돌리려면 원본 백업을 복원하십시오. 메모 파일에 신 → 구 표도 있습니다.",
    "IP references": "IP 참조 찾기",
    "Preview failed.": "계획을 만들지 못했습니다.",
    "Build failed.": "파일을 만들지 못했습니다.",
    "None of the pasted addresses matched.": "붙여넣은 주소가 목록과 맞지 않습니다.",
    "A policy that points at that object. It must move together or the policy ends up pointing at nothing.": "그 객체를 가리키는 정책입니다. 함께 바뀌지 않으면 정책이 없는 객체를 가리키게 됩니다.",
    "A real IP setting — there is only one right answer.": "실제 IP 설정값입니다 — 정답이 하나뿐입니다.",
    "APO cannot tell whether they are being retired or were missed, so it will not build the file until you confirm.": "폐기인지 빠뜨린 것인지 APO 는 알 수 없어, 확인하기 전까지 파일을 만들지 않습니다.",
    "Build the config file": "config 파일 만들기",
    "Building…": "만드는 중…",
    "Changed automatically": "자동으로 바뀝니다",
    "Changing this may cut off access to the device.": "이 값을 바꾸면 장비 접근이 끊길 수 있습니다.",
    "Check the plan, then build the file": "계획을 확인하고 파일을 만듭니다",
    "Check this after you restore the file": "파일을 복원한 뒤 반드시 확인하십시오",
    "Confirm the unmapped addresses are being retired, or map them.": "지정하지 않은 주소를 폐기로 확인하거나 값을 채우십시오.",
    "Fill in the new values above and preview the changes.": "위에서 새 값을 채우고 변경 계획을 보십시오.",
    "Follows the name above": "위 이름을 따라갑니다",
    "FortiOS silently drops parts of an edited configuration while still reporting a successful restore. This command is the only way to see what was dropped.": "FortiOS 는 편집된 설정의 일부를 조용히 버리면서도 복원 성공을 표시합니다. 무엇이 버려졌는지는 이 명령으로만 알 수 있습니다.",
    "I confirm the unmapped addresses are being retired": "지정하지 않은 주소는 폐기하는 것이 맞습니다",
    "Left untouched. Confirm whether it is being retired.": "그대로 둡니다. 폐기하는 것이 맞는지 확인하십시오.",
    "Map each address to its new value": "주소마다 새 값을 지정합니다",
    "Not changed automatically.": "자동으로 바뀌지 않습니다.",
    "Not mapped": "지정 안 됨",
    "Nothing changes with the values you entered.": "입력한 값으로는 바뀌는 것이 없습니다.",
    "Nothing is written to the device.": "장비에는 아무것도 쓰지 않습니다.",
    "Paste from spreadsheet": "표에서 붙여넣기",
    "Paste two columns (old address and new address), one pair per line.": "두 열(구 주소, 신 주소)을 한 줄에 하나씩 붙여넣으십시오.",
    "Preview the changes": "변경 계획 보기",
    "Read-only until you build.": "파일을 만들기 전까지는 읽기 전용입니다.",
    "Search a range above to list the addresses you need to map.": "위에서 대역을 조회하면 지정할 주소 목록이 나옵니다.",
    "Self-check of the produced file": "만들어진 파일 자체 검사",
    "Show only rows that change": "바뀌는 행만 보기",
    "Step 2": "2단계",
    "Step 3": "3단계",
    "The device refuses to change an address while something still references it — Command fail. Return code -23. The official answer is to delete every reference, change it, then rebuild them, which leaves a hole in your policy while you work. Editing the configuration file instead changes the value and all of its references in one step.": "장비는 무언가가 그 주소를 참조하는 동안 변경을 거부합니다 — Command fail. Return code -23. 공식 해법은 참조를 전부 지우고, 바꾸고, 다시 만드는 것인데 그 사이 정책에 구멍이 납니다. 설정 파일을 고치면 값과 그 모든 참조가 한 번에 바뀝니다.",
    "The object name contains this address, so the name changes with it. Want a different name? Change it on the device after you load the file.": "객체 이름에 이 주소가 들어 있어 이름도 함께 바뀝니다. 다른 이름을 쓰려면 파일을 올린 뒤 장비에서 바꾸십시오.",
    "To undo: new -> old": "되돌리기: 신 → 구",
    "Too many rows — showing the top {shown} of {all}.": "행이 너무 많아 전체 {all}건 중 상위 {shown}건만 표시합니다.",
    "Working…": "처리 중…",
    "Renamed automatically": "이름도 함께 바뀝니다",
    "Renaming an object shows up in Change review as one removed and one added object, not as a change — that view identifies objects by name.": "이름이 바뀐 객체는 변경 비교에서 '변경'이 아니라 '삭제 1 + 추가 1'로 보입니다 — 그 화면은 객체를 이름으로 식별하기 때문입니다.",
    "changed lines": "바뀐 줄",
    "configuration migration record": "설정 마이그레이션 기록",
    "leave blank to retire": "폐기하려면 비워 두세요",
    "old range": "구 대역",
    "old values left behind": "남아 있는 옛 값",
    "unexpected": "예상 밖",
    "{n} addresses have no new value. They will be left untouched — make sure that is what you want.": "{n}개 주소에 새 값이 없습니다. 그대로 두게 되니 의도한 것인지 확인하십시오.",
    "{n} addresses in the old range are not in your mapping table.": "구 대역의 주소 {n}개가 매핑표에 없습니다.",
    "{rows} references, of which {change} change automatically, {rename} are object names that change with them, and {follow} policies follow those names.": "참조 {rows}건 — 자동으로 바뀌는 값 {change}건, 함께 바뀌는 객체 이름 {rename}건, 그 이름을 따라가는 정책 {follow}건.",
    "The mapping table has an entry APO cannot read: {detail}. Each row needs an existing address and a valid IPv4 address to replace it with — leave the new value blank only if that address is being retired.": "매핑표에서 읽을 수 없는 항목이 있습니다: {detail}. 각 행은 기존 주소와 그것을 대체할 올바른 IPv4 주소가 있어야 합니다 — 새 값을 비우는 것은 그 주소를 폐기할 때만입니다.",
    "Some addresses in the old range are not in the mapping table. Confirm they are being retired, or map them.": "구 대역의 일부 주소가 매핑표에 없습니다. 폐기하는 것이 맞는지 확인하거나 매핑을 채우십시오.",
    "Not a valid IPv4 address or range. Use 10.1.2.0/24, 10.1.2.0 255.255.255.0 or 10.1.2.1-10.1.2.30.": "올바른 IPv4 주소나 대역이 아닙니다. 10.1.2.0/24 · 10.1.2.0 255.255.255.0 · 10.1.2.1-10.1.2.30 형식으로 입력하십시오.",
    "Change this": "반드시 바꾸세요",
    "This is a real IP setting.": "실제 IP 설정값입니다.",
    "If you skip it: this setting keeps pointing at a range that no longer exists.": "건너뛰면: 이 설정이 사라진 대역을 계속 가리킵니다.",
    "Decide whether to rename": "이름을 바꿀지 정하세요",
    "The object name contains an IP. Behaviour is unaffected.": "객체 이름에 IP가 들어 있습니다. 동작에는 영향이 없습니다.",
    "If you skip it: the name and the real IP disagree, and the next person is misled.": "건너뛰면: 이름과 실제 IP가 어긋나 다음 사람이 오해합니다.",
    "Only if you rename": "이름을 바꾼다면 함께",
    "A reference to the object name above. If you keep the name, leave this alone.": "위 객체 이름을 가리키는 참조입니다. 이름을 그대로 두면 손댈 필요 없습니다.",
    "If you skip it: renaming alone leaves this policy pointing at an object that no longer exists.": "건너뛰면: 이름만 바꿨을 때 이 정책이 없는 객체를 가리킵니다.",
    "Read and decide": "읽고 판단하세요",
    "A note for humans. Not a target for automatic change.": "사람이 읽는 메모입니다. 자동 변경 대상이 아닙니다.",
    "If you skip it: a stale note remains (no effect on behaviour).": "건너뛰면: 낡은 메모가 남습니다(동작에는 영향 없음).",
    "Exactly this range": "대역이 정확히 일치",
    "An address inside this range": "이 대역 안의 주소",
    "A wider range that contains this one": "이 대역을 포함하는 상위 대역",
    "Partially overlapping": "일부만 겹침",
    "Changing this may cut off access to the device — apply it in the same script as the gateway.": "이 값을 바꾸면 장비 접근이 끊길 수 있습니다 — 게이트웨이와 같은 스크립트로 함께 적용하세요.",
    "Nothing in this config references that range.": "이 대역을 참조하는 곳이 없습니다.",
    "No values must change. Untick the box to see the other {n} references.": "반드시 바꿔야 할 값은 없습니다. 체크를 풀면 나머지 {n}건을 봅니다.",
    "Searching…": "찾는 중…",
    "Could not reach the server.": "서버에 연결하지 못했습니다.",
    "The server replied but the response could not be read. Try again.": "서버가 응답했지만 내용을 읽지 못했습니다. 다시 시도하십시오.",
    "Lookup failed.": "조회에 실패했습니다.",
    "checked {tok} IP tokens across {lines} lines and found {refs} references, of which {must} must change.": "파일 {lines}줄에서 IP 토큰 {tok}개를 검사해 참조 {refs}건을 찾았고, 그중 {must}건은 반드시 바꿔야 합니다.",
    "{n} of them are used for device access.": "그중 {n}건은 장비 접근에 쓰입니다.",
    "A quote opened on line {n} is never closed, so everything below it was not read.": "{n}번째 줄에서 따옴표가 닫히지 않아 그 아래를 읽지 못했습니다.",
    "These results are incomplete — check whether the config file is truncated.": "아래 결과는 완전하지 않습니다 — config 파일이 잘렸는지 확인하십시오.",
    "{n} config blocks are left unclosed.": "닫히지 않은 config 블록이 {n}개 있습니다.",
    "The backup looks truncated — some entries may be attributed to the wrong section.": "백업이 중간에 잘린 것으로 보입니다 — 일부 항목이 엉뚱한 섹션으로 귀속되었을 수 있습니다.",
    "Too many references — showing the top {shown} of {all}.": "참조가 너무 많아 전체 {all}건 중 상위 {shown}건만 표시합니다.",
    "Only {shown} of {all} values that must change are visible.": "반드시 바꿔야 할 값도 {all}건 중 {shown}건만 보입니다.",
    "All values that must change are shown.": "반드시 바꿔야 할 값은 전부 표시됐습니다.",
    "Narrow the range and search again.": "대역을 좁혀서 다시 조회하십시오.",
    "Enter an IP address or range.": "IP 주소 또는 대역을 입력하십시오.",
    "Range end is lower than range start.": "범위의 끝이 시작보다 작습니다.",
    "Before you change an interface IP or move a subnet, find every place the old range is still referenced — including the sections a policy report never shows you.": "인터페이스 IP 를 바꾸거나 대역을 옮기기 전에, 구 대역이 아직 참조되는 곳을 전부 찾습니다 — 정책 리포트가 보여주지 않는 섹션까지 포함해서.",
    "Migration prep": "마이그레이션 준비",
    "Where is this range still used?": "이 대역이 아직 어디에 쓰이나요?",
    "Read-only. Nothing is changed.": "읽기 전용입니다. 아무것도 바꾸지 않습니다.",
    "Old IP or range": "구 IP 또는 대역",
    "Find references": "참조 찾기",
    "Show only what must change": "반드시 바꿔야 할 것만 보기",
    "FortiGate blocks the change when an IP is bound to source-ip, but stays silent when a VIP, IP pool, static route gateway or IPsec local-gw still points at the old address. This screen reads the raw config — including router static, vpn ipsec, system dns and log syslogd, which the policy tables never parse.": "FortiGate 는 IP 가 <strong>source-ip</strong> 에 묶여 있으면 변경을 막지만, <strong>VIP·IP pool·정적 라우트 게이트웨이·IPsec local-gw</strong> 가 구 주소를 가리켜도 조용히 넘어갑니다. 이 화면은 원문 config 를 읽습니다 — 정책 표가 파싱하지 않는 <strong>router static, vpn ipsec, system dns, log syslogd</strong> 까지 포함해서.",
    "Customers & devices": "고객사 · 장비",
    "Settings": "설정",
    "How it judges": "판정 기준",

    // ── 고객사 · 장비 ──
    "Drag a device onto a customer to assign it. Assignment only groups the reports — it never changes how a policy is judged. Each device keeps its own configuration, usage data and IP ranges.": "장비를 고객사로 끌어다 놓으면 배정됩니다. 배정은 보고서를 묶기만 할 뿐 정책 판정에는 전혀 영향을 주지 않습니다. 장비마다 자기 설정·사용량·IP 대역을 따로 보관합니다.",
    "Assign devices": "장비 배정",
    "Add customer": "고객사 추가",
    "Customers": "고객사",
    "Unassigned devices": "미배정 장비",
    "Unassigned": "미배정",
    "Assign to customer": "고객사 배정",
    "Reports": "보고서",
    "one workbook per device, packaged as a zip": "장비당 워크북 하나, zip으로 묶음",
    "All devices": "전체 장비",
    "Rename": "이름 변경",
    "Open": "열기",
    "Report": "보고서",
    "Delete": "삭제",
    "Drop a device here": "여기에 장비를 놓으세요",
    "No customers yet — add one above.": "아직 고객사가 없습니다 — 위에서 추가하세요.",
    "Every registered device is assigned.": "등록된 장비가 모두 배정되었습니다.",
    "No devices registered yet — go to Sources and register a device with its configuration file.": "아직 등록된 장비가 없습니다 — '데이터 가져오기'에서 설정 파일로 장비를 등록하세요.",
    "Type a customer name first, then press Add customer.": "고객사 이름을 먼저 입력한 뒤 '고객사 추가'를 누르세요.",
    "Customer name — this prefixes every report file for this customer.": "고객사 이름 — 이 고객사의 모든 보고서 파일 앞에 붙습니다.",
    "Clear usage data for this device": "이 장비의 사용량 데이터 지우기",
    "Open a registered device": "등록된 장비 열기",
    "Remove the hit count / last used data stored for {name}? The configuration and IP ranges stay. This only clears what is on this computer.": "{name}에 저장된 hit count / last used 데이터를 지울까요? 설정과 IP 대역은 그대로 남습니다. 이 컴퓨터에 있는 것만 지웁니다.",
    "Warning: {bad} of {all} rows are policy IDs not found in VDOM {vdom} — they may belong to another VDOM or another device. If this file came from elsewhere, use \"Clear usage data for this device\" and import the right one.":
      "경고: {all}행 중 {bad}행이 VDOM {vdom} 에 없는 정책 번호입니다 — 다른 VDOM 또는 다른 장비의 것일 수 있습니다. 다른 곳의 파일이라면 '이 장비의 사용량 데이터 지우기'로 지운 뒤 올바른 파일을 넣으세요.",
    "Warning: {bad} of {all} rows are policy IDs this configuration does not have. If this file came from another device, use \"Clear usage data for this device\" and import the right one.": "경고: {all}행 중 {bad}행이 이 설정에 없는 정책 번호입니다. 다른 장비의 파일이라면 '이 장비의 사용량 데이터 지우기'로 지운 뒤 올바른 파일을 넣으세요.",
    "This will remove all {n} saved IP range(s) from {name}. The user/server distinction stops being judged for this device. Continue?": "{name}에 저장된 IP 대역 {n}개가 모두 지워집니다. 이 장비는 사용자/서버 구분을 더 이상 판정하지 않게 됩니다. 계속할까요?",
    "this device": "이 장비",
    "DNS capture in use for this device.": "이 장비의 DNS 수집 결과를 쓰고 있습니다.",
    "No DNS capture for this device — FQDN policies cannot be judged until you upload a dnsproxy dump or fetch it from the device.": "이 장비의 DNS 수집 결과가 없습니다 — dnsproxy 덤프를 올리거나 장비에서 가져와야 FQDN 정책을 판정할 수 있습니다.",
    "Snapshots are cleared when you switch devices — select them again to rebuild the timeline.": "장비를 바꾸면 스냅샷은 지워집니다 — 다시 선택해 타임라인을 만드세요.",
    "Type an IP range first, for example 10.10.0.0/16.": "IP 대역을 먼저 입력하세요. 예: 10.10.0.0/16",
    "{n} IP range(s) saved for this device.": "이 장비에 IP 대역 {n}개를 저장했습니다.",
    "Not recognised, ignored: {list}": "인식하지 못해 무시했습니다: {list}",
    "not imported": "가져오지 못함",
    "Reopen this device": "이 장비 다시 열기",
    "Only one of the two backups records a hostname ({name}), so APO cannot confirm they are the same firewall.": "두 백업 중 하나에만 hostname({name})이 적혀 있어, 같은 방화벽인지 APO가 확인할 수 없습니다.",
    "Compared two backups; neither records a hostname, so APO cannot confirm they are the same firewall.": "백업 두 개를 비교했습니다. 둘 다 hostname이 적혀 있지 않아 같은 방화벽인지 APO가 확인할 수 없습니다.",
    "Compared two backups that both report the hostname {name}. A hostname is not unique, so this alone does not prove they are one firewall.": "hostname이 둘 다 {name}인 백업 두 개를 비교했습니다. hostname은 고유하지 않으므로 이것만으로 같은 방화벽이라는 증명은 되지 않습니다.",
    "Warning: these snapshots are from different firewalls ({list}). Differences between them are not one device’s change history.": "경고: 이 스냅샷들은 서로 다른 방화벽의 것입니다({list}). 그 차이는 한 장비의 변경 이력이 아닙니다.",
    "Another window opened a different device. {name} is still registered — reopen it to continue here.": "다른 창에서 다른 장비를 열었습니다. {name}은(는) 그대로 등록돼 있습니다 — 여기서 계속하려면 다시 여세요.",
    "Connected to {found}, but the configuration you have open is {open}. Changes are not sent to a different device — check the IP, or open that device first.": "{found}에 연결됐는데, 지금 열어 둔 설정은 {open}입니다. 다른 장비로는 변경을 보내지 않습니다 — IP를 확인하거나 그 장비를 먼저 여세요.",
    // ── 화면 설명문 ──
    // 각 화면을 처음 열었을 때 **가장 먼저 읽는 문장**이다. 사이드바와 제목만
    // 번역하고 이걸 두면 '이 화면이 무엇이고 다음에 뭘 하는지'가 영어로 남는다.
    "Every policy carries a severity and a recommended action, with the reason it was judged that way. Nothing here is inferred silently — where data is missing, the finding says so.": "모든 정책에 심각도와 권고 조치, 그리고 그렇게 판정한 근거가 함께 붙습니다. 조용히 추정하지 않습니다 — 데이터가 없으면 없다고 적습니다.",
    "The same findings, ordered as work: what to do first, the exact command for each change, and somewhere to record who did it. Disabling is reversible — deletion is not.": "같은 판정 결과를 '작업 순서'로 늘어놓습니다: 무엇을 먼저 할지, 각 변경의 정확한 명령어, 그리고 누가 했는지 적어 둘 자리. 비활성화는 되돌릴 수 있지만 삭제는 되돌릴 수 없습니다.",
    "What changed between two configuration backups of the same firewall — policies added, removed or modified, and object-level differences. For the periodic review record and accuracy measurement, use Evidence.": "같은 방화벽의 백업 두 개 사이에 무엇이 바뀌었는지 — 추가·삭제·변경된 정책과 객체 단위 차이. 정기검토 증적과 정확도 측정은 '감사 증적' 화면에서 합니다.",
    "The record a reviewer or auditor asks for: what was reviewed and when, and a way to measure how accurate these judgements actually are on your firewall.": "검토자나 감사인이 요구하는 기록: 무엇을 언제 검토했는지, 그리고 이 판정이 당신의 방화벽에서 실제로 얼마나 맞는지 재는 방법.",
    "The criteria the assessment applies. No public standard fixes these numbers — they are your organisation's audit criteria, and the report records whichever values were used.": "판정에 적용되는 기준입니다. 이 숫자를 정해 놓은 공개 표준은 없습니다 — 이건 당신 조직의 감사 기준이고, 보고서에는 실제로 쓰인 값이 그대로 기록됩니다.",
    "Analysis, severity classification, unreachable detection, change review and accuracy verification are free. Exporting reports needs a one-time licence.": "분석·심각도 판정·가려진 정책 검출·변경 비교·정확도 검증은 무료입니다. 보고서 내보내기만 1회 구매 라이선스가 필요합니다.",
    "The criteria behind every severity and action in this tool. Nothing here is configurable — adjust the numbers under Settings.": "이 도구의 모든 심각도와 조치가 어떤 기준으로 정해지는지 정리한 화면입니다. 여기서 바꾸는 것은 없습니다 — 숫자 조정은 '설정'에서 합니다.",
    "Interface language": "인터페이스 언어",
    "Approval window (days)": "승인 유효기간(일)",
    "When is a policy considered unused?": "언제부터 '미사용'으로 보나",
    "Exceptions that lower urgency": "긴급도를 낮추는 예외",
    "Low-usage (hit count) checks": "저사용(호출 수) 판정",
    "Affects: unused verdicts": "영향: 미사용 판정",
    "Affects: temporary-policy cleanup": "영향: 임시 정책 정리",
    "Affects: Critical relief": "영향: Critical 완화",
    "Affects: low-usage verdicts": "영향: 저사용 판정",
    "If the last traffic was more than this many days ago, the policy is treated as no longer in use.": "마지막 트래픽이 이 일수보다 오래됐으면 '미사용'으로 봅니다.",
    "e.g. 365 — a job that runs once a year (year-end batch) is still safe.": "예: 365 — 연 1회 도는 작업(연말 배치)은 걸리지 않습니다.",
    "A temporary (temp) policy unused for longer than this becomes a removal candidate.": "임시(temp) 정책이 이 기간 넘게 안 쓰였으면 제거 후보로 올립니다.",
    "e.g. 730 — temp rules idle for two years are proposed for removal.": "예: 730 — 2년 묵은 임시 규칙은 제거를 제안합니다.",
    "A policy still inside its approved term is not marked Critical just because usage is unknown — it stays at review. APO reads the term from a one-time schedule or a date in the policy name/comment.": "승인 기간이 아직 안 지난 정책은 사용량을 모른다는 이유만으로 Critical이 되지 않고 '검토'로 남습니다. 기간은 onetime 스케줄 또는 정책 이름·주석의 날짜에서 읽습니다.",
    "e.g. 365 — a policy opened this year gets time to prove itself. 0 = off.": "예: 365 — 올해 개통한 정책에는 시간을 줍니다. 0이면 끕니다.",
    "Judge \"barely used\" by absolute hit counts. Counters reset to zero on reboot or HA failover, so low counts are weak evidence — turn this off if your devices restart often.": "'거의 안 쓴다'를 절대 호출 수로 판정합니다. 카운터는 재부팅·HA 절체 때 0으로 리셋되므로 낮은 수는 약한 근거입니다 — 장비가 자주 재시작되면 끄세요.",
    "A user-to-server policy is low-usage when total hits are below (years since registration) × this value.": "유저→서버 정책의 총 호출이 (등록 후 연수)×이 값보다 적으면 저사용으로 봅니다.",
    "e.g. 100 — three years registered but under 300 hits is low usage.": "예: 100 — 등록 3년 차인데 300회 미만이면 저사용.",
    "A server-to-server policy is low-usage when total hits are below this value.": "서버→서버 정책의 총 호출이 이 값보다 적으면 저사용으로 봅니다.",
    "When a policy name carries no date, assume this registration year for age checks. Leave empty to skip those checks for such policies.": "정책 이름에 날짜가 없으면 이 연도에 등록된 것으로 보고 나이를 계산합니다. 비우면 그 정책들은 나이 판정을 건너뜁니다.",
    "Filter conditions": "필터 조건",
    "Probe failed — see the console for details.": "진단에 실패했습니다 — 자세한 내용은 콘솔에 있습니다.",
    "Select all files in one go — they pair up by name:": "파일을 한 번에 전부 선택하세요 — 이름으로 짝을 맞춥니다:",
    "the configuration (required)": "설정 파일 (필수)",
    "firewall hit count / last used for that device": "그 장비의 방화벽 hit count / last used",
    "the same for proxy policies": "프록시 정책용 사용량",
    "its user IP ranges, one CIDR or IP per line (labels and #, ;, ! or // comments are fine)": "그 장비의 사용자 IP 대역 — 한 줄에 하나 (라벨과 #, ;, !, // 주석 허용)",
    "Up to 50 devices and 50 MB per batch. Files matching no pattern are skipped, and SUMMARY.txt in the zip lists every device and everything skipped. Each device is analysed in isolation with your current thresholds — devices are never mixed into one workbook. FQDN policies need the single-device flow (they require a device connection).": "한 번에 장비 50대·50MB까지. 규칙에 안 맞는 파일은 건너뛰며, zip 안의 SUMMARY.txt가 모든 장비와 건너뛴 파일을 기록합니다. 각 장비는 현재 임계값으로 독립 분석되고 장비끼리 섞이지 않습니다. FQDN 정책은 장비 연결이 필요해 단일 장비 흐름을 쓰세요.",
    "Collected: {p} policies, hit count / last used for {s}, {f} FQDN resolutions.": "수집 완료: 정책 {p}건, hit count/last used {s}건, FQDN 해석 {f}건.",
    "counted as Unknown below — set User IP ranges to judge them": "아래 '판정 불가'로 집계됨 — 사용자 IP 대역을 설정하면 판정됩니다",
    "Loaded for {n} policies in VDOM '{vdom}' only — policies in other VDOMs are judged without usage data.": "VDOM '{vdom}'의 정책 {n}건에만 로드됨 — 다른 VDOM 정책은 사용량 없이 판정됩니다.",
    "Validating selected configuration files.": "선택한 설정 파일을 확인하는 중입니다.",
    "Uploading files...": "파일 올리는 중...",
    "Sending baseline and target configurations to the local parser.": "기준·대상 설정을 로컬 파서로 보내는 중입니다.",
    "Comparing configuration...": "설정 비교 중...",
    "Detecting policy, object, and system-level differences.": "정책·객체·시스템 수준의 차이를 찾는 중입니다.",
    "Rendering results...": "결과를 그리는 중...",
    "Preparing categorized comparison results.": "분류된 비교 결과를 준비하는 중입니다.",
    "Analysis completed.": "분석 완료.",
    "Analysis failed.": "분석 실패.",
    "New firewall rules": "새로 추가된 방화벽 정책",
    "Deleted firewall rules": "삭제된 방화벽 정책",
    "Modified rule attributes": "속성이 바뀐 정책",
    "New objects": "새로 추가된 객체",
    "Deleted objects": "삭제된 객체",
    "Profiles, certificates, system settings": "프로파일·인증서·시스템 설정",
    "Other Changes": "그 밖의 변경",
    "REST API key": "REST API 키",
    "New customer name": "새 고객사 이름",
    "Support": "지원 문의",
    "Set them once here — they are saved with this device.": "여기서 한 번 설정하면 이 장비에 함께 저장됩니다.",
    "User IP ranges are set on the Findings screen": "사용자 IP 대역 설정 (점검 결과 화면)",
    "All columns": "전체",
    "filter — commas mean 'any of these' (498, 499)": "입력하면 바로 걸러집니다 — 쉼표로 여러 값 (498, 499), Enter로 조건 고정",
    "value": "값",
    "ID matches exactly; other columns match rows containing the text. Conditions combine with AND.": "ID는 정확히 일치하는 정책만, 다른 컬럼은 입력한 값을 포함하는 정책만 보입니다. 조건 여러 개는 모두 만족(AND)해야 합니다.",
    "Filter: id, name, address, service, reason": "검색: 번호·이름·주소·서비스·사유",
    "A risky-service policy with unknown usage stays at review (not critical) while its schedule or dated name/comment shows it is still within this approval term. 0 turns this off": "스케줄 또는 이름·주석의 날짜로 아직 승인 기간 안임이 확인되는, 사용량 미상의 위험 서비스 정책은 심각(Critical) 대신 검토로 둡니다. 0이면 끕니다",

    // ── 개요 화면 · 상단 상태바 (shell.js) ──
    // 이 파일은 번역 통로를 아예 안 쓰고 있어서 개요가 통째로 영어였다.
    "Assessment overview": "판정 요약",
    "{name} — assessment": "{name} 판정 요약",
    "Every number below links to the findings behind it.": "아래 숫자는 모두 그 근거가 된 판정으로 이어집니다.",
    "Configuration loaded. Run the assessment to see findings.": "설정을 불러왔습니다. 점검을 실행하면 결과가 나옵니다.",
    "run the assessment to see this": "점검을 실행하면 볼 수 있습니다",
    "not enough data to judge — excluded from the counts here": "판정할 데이터가 부족합니다 — 여기 집계에서 제외됩니다",
    "every policy was judged": "모든 정책이 판정됐습니다",
    "unreachable — never match traffic": "가려짐 — 트래픽과 절대 매칭되지 않습니다",
    "checked {n} of {total} enabled firewall policies — {skipped} could not be resolved": "활성 방화벽 정책 {total}건 중 {n}건 검사 — {skipped}건은 환원하지 못했습니다",
    "all {n} enabled firewall policies checked": "활성 방화벽 정책 {n}건 모두 검사했습니다",
    "No actionable findings — run the assessment first.": "조치할 항목이 없습니다 — 먼저 판정을 실행하세요.",
    "No configuration loaded": "불러온 설정이 없습니다",
    "Connect a device or import a config file to begin": "장비에 연결하거나 설정 파일을 올려서 시작하세요",
    "Copied": "복사됨",
    "Select manually": "직접 선택하세요",
    "Copy": "복사",

    // ── 설정: 판정 임계값 ──
    // 이 화면은 스스로 '메뉴와 설명만 번역된다'고 적어 두었는데, 정작 그
    // 설명(각 임계값이 무엇을 뜻하는지)이 전부 영어로 남아 있었다.
    "Presets:": "프리셋:",
    "Dormancy period (days)": "미사용 판정 기간 (일)",
    "A policy last used longer ago than this is treated as no longer in use": "마지막 사용이 이보다 오래된 정책은 더 이상 쓰이지 않는 것으로 봅니다",
    "Long dormancy (days)": "장기 미사용 (일)",
    "Beyond this, a temp policy becomes a removal candidate": "이 기간을 넘기면 임시 정책은 삭제 후보가 됩니다",
    "Unused Server-Server policies with a schedule older than this are escalated": "스케줄이 이보다 오래된 미사용 서버-서버 정책은 등급을 올립니다",
    "Registration fallback year": "등록 연도 기본값",
    "Assumed registration year when a policy name carries no date. Leave empty to skip age-based checks for those policies": "정책 이름에 날짜가 없을 때 가정할 등록 연도. 비워 두면 그런 정책은 경과 기간 검사를 건너뜁니다",
    "Use absolute hit-count thresholds": "절대 히트카운트 임계값 사용",
    "Off by default: hit counters reset on reboot/HA failover, so low counts are weak evidence": "기본은 꺼짐: 히트카운터는 재부팅·HA 절체 때 초기화되므로 낮은 수치는 약한 근거입니다",
    "Server-User hit multiplier": "서버-사용자 히트 배수",
    "Low usage if hits < (years since registration) × this value": "히트 수가 (등록 후 경과 연수) × 이 값보다 작으면 저사용으로 봅니다",
    "Server-Server hit threshold": "서버-서버 히트 임계값",
    "Low usage if hits fall below this value": "히트 수가 이 값보다 작으면 저사용으로 봅니다",
    "Prepared by (your company)": "작성 (자사명)",
    "Prepared for (client) — leave blank to omit": "제출 대상 (고객사) — 비워 두면 표기하지 않습니다",

    // ── 입력 폼 라벨 · 빈 상태 ──
    // 라벨 안에 입력칸이 있는 경우는 텍스트만 <span data-i18n> 으로 감쌌다 —
    // label 에 직접 붙이면 textContent 를 갈아 끼우며 입력칸이 사라진다.
    "FortiGate IP / host": "FortiGate IP / 호스트",
    "Port": "포트",
    "API token (read-only)": "API 토큰 (읽기 전용)",
    "Skip TLS verification (trusted network only)": "TLS 검증 건너뛰기 (신뢰된 망에서만)",
    "IP Address": "IP 주소",
    "API Token": "API 토큰",
    "Skip SSL Verify": "SSL 검증 건너뛰기",
    "(insecure)": "(안전하지 않음)",
    "No file selected": "선택된 파일 없음",
    "No files selected": "선택된 파일 없음",
    "No snapshots selected": "선택된 스냅샷 없음",
    "Upload two FortiGate config backups to compare configuration changes.": "FortiGate 설정 백업 두 개를 올려 변경 내용을 비교하세요.",
    "Change Review Workspace": "변경 검토 작업 공간",
    "Compare a baseline configuration against a target configuration to identify policy additions, deletions, modified settings, object changes, and other configuration areas that may require review.": "기준 설정과 대상 설정을 비교해 정책 추가·삭제·설정 변경·객체 변경, 그 밖에 검토가 필요한 영역을 찾습니다.",
    "Comparison Basis": "비교 기준",
    "Baseline Configuration": "기준 설정",
    "Target Configuration": "대상 설정",

    // ── 화면 제목 · 동작 버튼 ──
    // 사이드바만 한국어이고 본문 제목·버튼이 영어로 남아 있었다. '조치 계획'을
    // 눌렀는데 제목이 'Action plan' 이면, 같은 화면이 두 이름을 갖는다.
    // (FortiGate 객체 이름 탭 — Firewall AddrGrp·Service Custom 등 — 은 제품
    //  용어이므로 표 머리글과 같은 규칙으로 영어를 유지한다.)
    // 상단 상태바 칩 — 모든 화면에 항상 보인다
    "Config": "설정",
    "Usage data": "사용량",
    "User ranges": "사용자 대역",
    "Assessed": "점검 완료",

    "Action plan": "조치 계획",
    "Config Summary": "설정 요약",
    "Policy CSV Summary": "정책 CSV 요약",
    "Severity Classification Results": "심각도 판정 결과",
    "Unreachable Policy Detection": "가려진 정책 검출",
    "Version Detection": "펌웨어 버전 점검",
    "Apply Results": "적용 결과",
    "Configuration Drift Analysis": "설정 변경 분석",
    "Results": "결과",
    "Unreachable": "가려짐",
    "Detection": "점검",
    "Export": "내보내기",
    "FW Policy CSV": "방화벽 정책 CSV",
    "Proxy Policy CSV": "프록시 정책 CSV",
    "Download Current Tab CSV": "현재 탭 CSV 내려받기",
    "Download All Tabs Excel": "전체 탭 엑셀 내려받기",
    "Export to Excel": "엑셀로 내보내기",
    "Analyze": "분석",
    "Choose Baseline": "기준 파일 선택",
    "Choose Target": "대상 파일 선택",
    "Analyze Configuration Changes": "변경 분석 실행",
    "The device answered, but what came back is not a FortiGate configuration. {detail}":
      "장비가 응답했지만 돌아온 것이 FortiGate 설정이 아닙니다. {detail}",
    "Snapshot '{file}' cannot be used. {detail}":
      "스냅샷 '{file}'은(는) 쓸 수 없습니다. {detail}",
    "On by default. Note the limit: hit counters reset on reboot/HA failover, so low counts are weak evidence — turn this off if your devices reboot often":
      "기본값은 켜짐. 한계를 참고하세요 — 사용 횟수는 재부팅·HA 페일오버로 초기화되므로 낮은 수치는 약한 근거입니다. 장비가 자주 재부팅된다면 끄세요",
    "None": "없음",
    "No newer patch versions available in DB.": "DB에 더 최신 패치 버전이 없습니다.",
    "No items for this version.": "이 버전에 해당하는 항목이 없습니다.",
    "This FortiOS branch is not in the vulnerability database — absence here is not evidence that the firmware is unaffected.":
      "이 FortiOS 브랜치는 취약점 DB에 없습니다 — 여기에 없다는 것이 이 펌웨어가 안전하다는 근거는 아닙니다.",
    "Not checked": "확인 안 함",
    "The {which} file ({file}) cannot be compared. {detail}":
      "{which} 파일({file})은 비교할 수 없습니다. {detail}",
    "Click Analyze to check this firmware against known issues.":
      "'분석'을 누르면 이 펌웨어의 알려진 문제를 확인합니다.",
    "Unreachable while policy {id} above it stays enabled — settle that one first.":
      "위쪽 정책 {id}이(가) 켜져 있는 동안에는 가려져(도달 불가) 있습니다 — 그것부터 정하세요.",
    "{n} ignored (inside a longer word): {list}": "{n}건은 단어 속에 걸려 무시함: {list}",
    "from {file} (delivered with this installation): {vals}":
      "{file} 에서 옴 (이 설치본에 포함된 파일): {vals}",
    "That file does not look like a FortiGate configuration backup — APO could not find a single 'config' section in it. Upload the backup taken from the device (System > Configuration > Backup), not a log, report or partial download.":
      "FortiGate 설정 백업으로 보이지 않습니다 — 파일에서 'config' 구역을 하나도 찾지 못했습니다. 장비에서 받은 백업(System > Configuration > Backup)을 올리세요. 로그·보고서·받다 만 파일이 아닙니다.",
    "patch level unknown":
      "패치 레벨 미상",
    "This FortiOS branch ({branch}) is not in the vulnerability database ({coverage}) — APO did not check it. Absence of findings here is not evidence that the firmware is unaffected.":
      "이 FortiOS 브랜치({branch})는 취약점 DB({coverage})에 없습니다 — APO가 확인하지 않았습니다. 여기에 지적이 없다는 것이 이 펌웨어가 안전하다는 근거는 아닙니다.",
    "Analysis complete — {cves} active CVE(s), {issues} known issue(s). Build {build} is not in the patch-level table, so this was assessed as {branch}.0 (the first release of that branch) — the real device may already be patched.":
      "분석을 마쳤습니다 — 조치 필요한 CVE {cves}건, 알려진 이슈 {issues}건. 빌드 {build}는 패치 레벨 표에 없어 {branch}.0(해당 브랜치 최초 릴리스) 기준으로 판정했습니다 — 실제 장비는 이미 패치돼 있을 수 있습니다.",
    "Message": "메시지",
    "Mismatch": "불일치",
    "Modified policy IDs": "변경된 정책 번호",
    "Objects added / removed": "추가·삭제된 객체",
    "Policies added": "추가된 정책",
    "Policies modified": "변경된 정책",
    "Policies removed": "삭제된 정책",
    "Precision": "정확도",
    "Proof": "근거",
    "Resolved": "실제 값",
    "Result": "결과",
    "Role": "역할",
    "SCTP Port Range": "SCTP 포트 범위",
    "TCP Port Range": "TCP 포트 범위",
    "UDP Port Range": "UDP 포트 범위",
    "Shadowed By": "가려짐 — 상위 정책",
    "Shadower Action": "상위 정책 동작",
    "Shadower Name": "상위 정책 이름",
    "Unfilled": "미기입",
    "Workaround": "우회 조치",
    "Advisory": "권고문",
    "Affected Range": "영향 버전",
    "Alias": "별칭",
    "Bug ID": "버그 번호",
    "CVE": "CVE",
    "Category": "분류",
    "Comment": "설명",
    "Component": "구성 요소",
    "Description": "설명",
    "Destination Address": "목적지 주소",
    "Destination Interface": "목적지 인터페이스",
    "Display Name": "표시 이름",
    "Fix Version": "수정 버전",
    "Hit Count": "사용 횟수",
    "Hold": "보류",
    "IP": "IP",
    "Last Used": "마지막 사용",
    "Match": "일치",
    "Members": "구성원",
    "Name": "이름",
    "Protocol": "프로토콜",
    "Reason": "사유",
    "Recommended Action": "권고 조치",
    "Resolved Members": "실제 구성원",
    "Risk Level": "위험도",
    "Sev": "등급",
    "Severity": "심각도",
    "Source Address": "출발지 주소",
    "Source Interface": "출발지 인터페이스",
    "Status": "상태",
    "Tags": "태그",
    "Title": "제목",
    "Traffic Type": "트래픽 유형",
    "Type": "종류",
    "Failed to import {type} CSV": "{type} CSV를 반영하지 못했습니다",
    "Import failed.": "반영하지 못했습니다.",
    "Failed to save.": "저장하지 못했습니다.",
    "{type} Policy CSV imported, but re-assessment failed — the findings still reflect the previous run. {why}":
      "{type} 정책 CSV는 반영했지만 재판정에 실패했습니다 — 화면의 결과는 아직 이전 실행의 것입니다. {why}",
    "{done} The configuration changed while applying — reload the candidates.":
      "{done} 적용 중에 설정이 바뀌었습니다 — 후보 목록을 다시 불러오세요.",
    "{done} Could not refresh the candidate list — reload it before applying anything else.":
      "{done} 후보 목록을 새로 고치지 못했습니다 — 다른 것을 적용하기 전에 다시 불러오세요.",
    "Registration saved — reopen \"Register a device\" to continue where you left off.":
      "등록 내용을 저장했습니다 — \"장비 등록\"을 다시 열면 이어서 진행할 수 있습니다.",
    "Opened {name}.": "{name}을(를) 열었습니다.",
    "Importing {type} CSV for {name}...": "{name}의 {type} CSV를 반영하는 중...",
    "Failed to import {type} CSV (network error)": "{type} CSV를 반영하지 못했습니다 (네트워크 오류)",
    "CSV apply failed: {detail}": "CSV를 반영하지 못했습니다: {detail}",
    "Analyzing configuration changes...": "설정 변경을 분석하는 중...",
    "Configuration change review completed successfully.": "설정 변경 검토를 마쳤습니다.",
    "Analysis complete — {cves} active CVE(s), {issues} known issue(s).":
      "분석을 마쳤습니다 — 조치 필요한 CVE {cves}건, 알려진 이슈 {issues}건.",
    "{n} IP range(s) in use. Click Classify to apply.": "IP 대역 {n}개를 사용 중입니다. 판정 실행을 누르면 반영됩니다.",
    "{n} IP range(s) in use — not recognised, ignored: {list}. Click Classify to apply.":
      "IP 대역 {n}개를 사용 중입니다 — 인식하지 못해 무시함: {list}. 판정 실행을 누르면 반영됩니다.",
    "{n} IP range(s) in use — not recognised, ignored: {list} (+{more} more). Click Classify to apply.":
      "IP 대역 {n}개를 사용 중입니다 — 인식하지 못해 무시함: {list} (외 {more}개). 판정 실행을 누르면 반영됩니다.",
    "Opened {name}": "{name}을(를) 열었습니다",
    "Reopened {name}": "{name}을(를) 다시 열었습니다",
    "Reopened {name} — the device you were working on": "{name}을(를) 다시 열었습니다 — 작업 중이던 장비입니다",
    "Collected from {name}": "{name}에서 수집했습니다",
    "Redefined Objects": "값이 바뀐 객체",
    "Same name, different value": "이름은 같고 값이 다름",
    "Analysis Summary": "분석 요약",
    "{n} total change groups detected": "변경 묶음 {n}건을 찾았습니다",
    "This view summarizes policy, object, and additional configuration changes between the selected baseline and target backups.":
      "기준 백업과 대상 백업 사이의 정책·객체·그 밖의 설정 변경을 요약합니다.",
    "Recommended Review Flow": "권장 검토 순서",
    "Review changed policies first.": "변경된 정책을 먼저 봅니다.",
    "Validate added or removed policies.": "추가·삭제된 정책을 확인합니다.",
    "Check object changes for IP, service, and group impact.": "객체 변경이 IP·서비스·그룹에 미치는 영향을 확인합니다.",
    "Review other configuration changes.": "그 밖의 설정 변경을 봅니다.",
    "{n} section(s)": "{n}개 구역",
    "Policy ID": "정책 번호",
    "Policy Name": "정책 이름",
    "Source": "출발지",
    "Destination": "목적지",
    "Service": "서비스",
    "Schedule": "일정",
    "Action": "동작",
    "Changed Settings": "바뀐 설정",
    "No material field change detected.": "의미 있는 필드 변경이 없습니다.",
    "Configuration Area": "설정 구역",
    "Object Name": "객체 이름",
    "Resolved Value / Detail": "실제 값 / 상세",
    "Setting": "설정 항목",
    "Before": "이전",
    "After": "이후",
    "Removed": "삭제",
    "Changed": "변경",
    "No additional configuration sections changed.": "그 밖에 바뀐 설정 구역이 없습니다.",
    "Policy and object changes may still exist in their dedicated categories.":
      "정책·객체 변경은 각 항목에서 따로 확인하세요.",
    "No address, service, or interface object was redefined.": "값이 바뀐 주소·서비스·인터페이스 객체가 없습니다.",
    /* 서버가 낸 거절 사유. 값이 끼는 것은 app.js 의 SERVER_ERRORS 가 영어
       원문을 만들고, 그 원문이 여기 키가 된다. 값이 없는 것은 서버가 보낸
       문장 자체가 키다. */
    "This {what} did not say which device it is for. APO only applies input to the device you have open.":
      "이 {what}에 어느 장비의 것인지가 없습니다. APO는 지금 열려 있는 장비에만 입력을 적용합니다.",
    "That {what} was entered while a different device was open. Reopen the device you meant, then try again.":
      "다른 장비가 열려 있는 동안 들어온 {what}입니다. 원하는 장비를 다시 연 뒤 시도하세요.",
    "No FQDN→IP entries recognized. The file has domains and IPs but not in a layout this parser recognizes — please send a few sample lines so it can be supported.":
      "FQDN→IP 항목을 인식하지 못했습니다. 도메인과 IP는 있지만 APO가 아는 형식이 아닙니다 — 샘플 몇 줄을 보내 주시면 지원하겠습니다.",
    "No FQDN→IP entries recognized. The file does not appear to contain FQDN entries. Run 'diagnose test application dnsproxy 6' (or 'diagnose firewall fqdn list') and save the full console output.":
      "FQDN→IP 항목을 인식하지 못했습니다. FQDN 항목이 없는 파일로 보입니다. 'diagnose test application dnsproxy 6'(또는 'diagnose firewall fqdn list')을 실행해 콘솔 출력을 전부 저장하세요.",
    "Could not parse snapshot '{file}'.": "스냅샷 '{file}'을(를) 읽지 못했습니다.",
    "APO could not write to its device store in '{path}'. Windows blocks writes in Program Files and on some network shares. Move APO.exe to a folder you own (for example Documents\\APO) and start it again — your licence and devices live next to the program.":
      "APO가 '{path}'에 장비 보관소를 쓰지 못했습니다. 윈도우는 Program Files와 일부 네트워크 공유 폴더에 쓰는 것을 막습니다. APO.exe를 본인 소유 폴더(예: Documents\\APO)로 옮기고 다시 실행하세요 — 라이선스와 장비는 프로그램 옆에 저장됩니다.",
    "Your key is valid, but APO could not save it in '{path}'. Windows blocks writes in Program Files and on some network shares. Move APO.exe to a folder you own (for example Documents\\APO) and enter the key again.":
      "키는 정상이지만 APO가 '{path}'에 저장하지 못했습니다. 윈도우는 Program Files와 일부 네트워크 공유 폴더에 쓰는 것을 막습니다. APO.exe를 본인 소유 폴더(예: Documents\\APO)로 옮기고 키를 다시 입력하세요.",
    "APO could not read its device store ({file}). Your devices are not gone from this screen because they were deleted — the file could not be opened. Close any other copy of APO that may be running, then restart. Do not delete that file: it holds your devices, customers and saved inputs.":
      "APO가 장비 보관소({file})를 읽지 못했습니다. 장비가 삭제돼서 화면에서 사라진 것이 아니라 파일을 열지 못한 것입니다. 실행 중인 다른 APO를 모두 닫고 다시 시작하세요. 그 파일을 지우지 마세요 — 장비·고객사·저장된 입력이 들어 있습니다.",
    "The device was removed from APO, but its uploaded configuration file could not be deleted from '{path}'. Delete it by hand — it contains that customer's policies.":
      "장비는 APO에서 지웠지만, 올렸던 설정 파일을 '{path}'에서 지우지 못했습니다. 직접 삭제하세요 — 그 고객사의 정책이 들어 있습니다.",
    "The policies in this configuration belong to VDOM '{config_vdom}', but this device is registered with VDOM '{registered_vdom}'. APO will not write to the firewall, because policy numbers mean different rules in each VDOM. Register the device again with VDOM '{config_vdom}'.":
      "이 설정의 정책은 VDOM '{config_vdom}'의 것인데, 이 장비는 VDOM '{registered_vdom}'으로 등록돼 있습니다. VDOM마다 같은 정책 번호가 다른 규칙을 뜻하므로 APO는 방화벽에 쓰지 않습니다. VDOM '{config_vdom}'으로 장비를 다시 등록하세요.",
    "Policy {policies} is unreachable only while policy {shadower} stays enabled — and policy {shadower} is also being changed. Do that one first, take a fresh configuration backup and run APO again: these may be live by then.":
      "정책 {policies}은(는) 정책 {shadower}이(가) 켜져 있는 동안에만 가려져 있습니다 — 그런데 정책 {shadower}도 함께 바꾸려 하고 있습니다. 그것을 먼저 처리하고 설정 백업을 새로 받아 APO를 다시 실행하세요. 그때는 이 정책들이 살아 있을 수 있습니다.",
    "That file is empty. A FortiGate configuration backup was expected — check that the download finished, then upload it again.":
      "파일이 비어 있습니다. FortiGate 설정 백업이 필요합니다 — 내려받기가 끝났는지 확인하고 다시 올리세요.",
    "That download belongs to a configuration that is no longer open. Upload that configuration again to get a fresh copy.":
      "그 내려받기는 지금 열려 있지 않은 설정의 것입니다. 그 설정을 다시 올리면 새로 만들어 드립니다.",
    "APO could not save these names to the device store, so they would be lost when you reopen the device. Nothing was changed.":
      "이 이름들을 장비 보관소에 저장하지 못했습니다. 그대로 두면 장비를 다시 열 때 사라지므로 아무것도 바꾸지 않았습니다.",
    "APO could not save this setting, so it would be lost when you restart. Nothing was changed.":
      "이 설정을 저장하지 못했습니다. 그대로 두면 다시 시작할 때 사라지므로 아무것도 바꾸지 않았습니다.",
    "APO could not read this configuration file. It may be a format APO does not handle yet. Please send this file to support if it is a valid FortiGate backup.":
      "이 설정 파일을 읽지 못했습니다. APO가 아직 다루지 못하는 형식일 수 있습니다. 정상적인 FortiGate 백업이라면 이 파일을 지원팀에 보내 주세요.",
    "APO does not recognise the 표본 ID in this sheet. If a spreadsheet program changed that column, download a fresh sample and copy your results across; otherwise this sheet came from another APO installation.":
      "이 시트의 표본 ID를 APO가 알지 못합니다. 스프레드시트 프로그램이 그 열을 바꿨다면 표본을 새로 내려받아 결과를 옮겨 적으세요. 그렇지 않다면 다른 APO 설치본에서 만든 시트입니다.",
    "Invalid Host header": "허용되지 않은 Host 헤더입니다.",
    "Cross-origin request rejected": "다른 오리진에서 온 요청은 받지 않습니다.",
    "Invalid filename": "잘못된 파일 이름입니다.",
    "Not available": "제공되지 않습니다.",
    "No such device": "그런 장비가 없습니다.",
    "Report branding requires an MSP / Consultant license. Single-organization licenses export unbranded reports.":
      "보고서 브랜딩은 MSP / 컨설턴트 라이선스가 필요합니다. 단일 조직 라이선스는 브랜딩 없이 내보냅니다.",
    "Load failed: {detail}": "불러오지 못했습니다: {detail}",
    "Apply failed: {detail}": "적용하지 못했습니다: {detail}",
    "Analysis failed: {detail}": "분석하지 못했습니다: {detail}",
    "{n} policies have hit count / last used from the device.":
      "정책 {n}건에 장비에서 가져온 사용 횟수·마지막 사용일이 있습니다.",
    "Download comparison (Excel)": "비교 결과 내려받기 (엑셀)",
    "Preparing download...": "내려받을 파일을 만드는 중...",
    "Select both baseline and target configuration files.":
      "기준 설정과 대상 설정을 모두 선택하세요.",
    "Failed to build comparison export": "비교 결과 파일을 만들지 못했습니다.",
    "Added Policies": "추가된 정책",
    "Removed Policies": "삭제된 정책",
    "Changed Policies": "변경된 정책",
    "Added Objects": "추가된 객체",
    "Removed Objects": "삭제된 객체",
    "Other Configuration Changes": "그 밖의 설정 변경",
    "Select snapshots (oldest first)": "스냅샷 선택 (오래된 것부터)",
    "Export Review Evidence (.xlsx)": "검토 증적 내보내기 (.xlsx)",
    "Download sample worksheet (.xlsx)": "검증 표본 내려받기 (.xlsx)",
    "Upload completed worksheet": "작성한 워크시트 올리기",
    "Show": "펼치기",
    "Standard — flag after 1 year unused": "표준 — 1년 미사용 시 지적",
    "Strict — flag after 6 months": "엄격 — 6개월 미사용 시 지적",
    "Relaxed — flag after 2 years": "완화 — 2년 미사용 시 지적",
    "Reset to profile defaults": "프로파일 기본값으로 되돌리기",
    "Save branding": "브랜딩 저장",
    "menus and descriptions only": "메뉴와 설명만 번역됩니다",
    "config → CSV → ranges → FQDN, one step at a time": "설정 → CSV → 대역 → FQDN 순서로 한 단계씩",
    "Run the assessment on the Findings page to build a work list.": "'점검 결과' 화면에서 점검을 실행하면 작업 목록이 만들어집니다.",
    "Select two configuration files and run the analysis.": "설정 파일 두 개를 고르고 분석을 실행하세요.",
    "Real output, built from a bundled demo configuration.": "동봉된 데모 설정으로 만든 실제 산출물입니다.",

    // ── 되돌릴 수 없는 장비 쓰기의 확인창 ──
    // 이 제품에서 유일하게 되돌릴 수 없는 동작이다. 여기가 영어로 남아 있으면
    // 마지막 방어선이 읽히지 않는다.
    "Confirm Policy Disable": "정책 비활성화 확인",
    // 실행 버튼도 번역한다 — 취소만 한국어였더니 방향만 뒤집힌 채 같은
    // '반쪽 번역' 상태가 남았다(라운드 27 지적).
    "Apply": "적용",
    "Apply Disable to Selected": "선택한 정책 비활성화",
    "(Connected to {name}.)": "(연결된 장비: {name})",
    "This is a different unit. It reports serial {found}, but APO confirmed this device as {expected}. Check the address.": "다른 장비입니다. 시리얼이 {found}인데, APO가 이 장비로 확인해 둔 것은 {expected}입니다. 주소를 확인하세요.",
    "APO confirmed this device as serial {expected}, but the firewall at this address does not report a serial, so it cannot be checked. Use the address you confirmed before.": "APO는 이 장비를 시리얼 {expected}로 확인해 뒀는데, 이 주소의 방화벽은 시리얼을 알려주지 않아 대조할 수 없습니다. 전에 확인한 주소를 쓰세요.",
    "serial {serial} matches the device APO confirmed.": "시리얼 {serial}이(가) APO가 확인해 둔 장비와 일치합니다.",
    "APO has not confirmed this device before. The firewall at {ip} reports serial {serial} — check that against the device itself before continuing. APO remembers it from then on.": "APO가 이 장비를 확인한 적이 없습니다. {ip}의 방화벽이 알려준 시리얼은 {serial}입니다 — 계속하기 전에 장비에서 직접 대조하세요. 그 뒤로는 APO가 기억합니다.",
    "Accuracy for {device}": "{device}의 정확도",
    "Sample precision: {pct}": "표본 정확도: {pct}",
    "Which VDOM was this CSV exported from? This configuration has: {vdoms}":
      "이 CSV는 어느 VDOM에서 내보낸 것입니까? 이 설정의 VDOM: {vdoms}",
    "Import cancelled.": "가져오기를 취소했습니다.",
    "This configuration has more than one VDOM ({vdoms}), and policy numbers start again at 1 in each one. Tell APO which VDOM this export came from — otherwise its hit counts would be applied to same-numbered policies in the other VDOMs, which were never measured.":
      "이 설정에는 VDOM이 둘 이상({vdoms}) 있고, 정책 번호는 VDOM마다 1번부터 다시 시작합니다. 이 내보내기가 어느 VDOM 것인지 알려 주세요 — 그러지 않으면 접속 횟수가 다른 VDOM의 같은 번호 정책에도 적용되는데, 그 정책들은 측정한 적이 없습니다.",
    "'{vdom}' is not a VDOM in this configuration. It has: {vdoms}.":
      "'{vdom}' 은 이 설정에 없는 VDOM 입니다. 이 설정의 VDOM: {vdoms}.",
    "Note: usage data previously loaded for VDOM {vdom} was replaced — policy numbers overlap across VDOMs, so only one VDOM's usage can be loaded at a time.":
      "참고: 앞서 불러온 VDOM {vdom} 의 사용량 데이터를 갈아 끼웠습니다 — 정책 번호가 VDOM 간에 겹치므로 한 번에 한 VDOM 의 사용량만 불러올 수 있습니다.",
    "(unattributed)": "(귀속 불명)",
    "None of the policy IDs in this file exist in VDOM '{vdom}' of the loaded configuration. This usually means the CSV came from a different device or a different VDOM — nothing was imported.":
      "이 파일의 정책 번호가 불러온 설정의 VDOM '{vdom}' 에 하나도 없습니다. 대개 다른 장비 또는 다른 VDOM 의 CSV 라는 뜻입니다 — 아무것도 가져오지 않았습니다.",
    "This device has multiple VDOMs and DNS resolution is per-VDOM — a single unscoped snapshot cannot be attributed to the right policies, so it is not used as reachability evidence. Policies with FQDN objects stay skipped (unproven), which is accurate.":
      "이 장비에는 VDOM이 둘 이상 있고 DNS 해석은 VDOM마다 다릅니다 — 범위 없는 스냅샷 하나를 어느 정책의 것인지 귀속할 수 없어 도달불가 판정의 증거로 쓰지 않습니다. FQDN 객체가 든 정책은 '판정 보류(증명 안 됨)'로 남으며, 그것이 정확한 상태입니다.",
    "All {n} policies came out as severity 0 (\"Cannot assess\") because APO does not know which IP ranges are user networks, so there is nothing to verify yet. Set the User IP ranges first, then download the sample.":
      "정책 {n}건이 모두 등급 0(\"판정 불가\")으로 나왔습니다 — 어느 IP 대역이 사용자망인지 APO가 모르기 때문입니다. 아직 검증할 것이 없습니다. 사용자 IP 대역을 먼저 설정한 뒤 표본을 내려받으세요.",
    "This configuration has no policies to verify.":
      "이 설정에는 검증할 정책이 없습니다.",
    "This sample was issued for the device you have open ('{open}'), but the VDOM / policy type / policy ID columns no longer match what APO issued, so APO cannot tell which policy each row is about. Those three columns are filled in by APO — restore them (or download a fresh sample and copy your verdicts across). Your verdicts are still valid.":
      "이 표본은 지금 열어 둔 장비('{open}')에 발급한 것이 맞습니다. 다만 VDOM / 정책 종류 / 정책 번호 칸이 발급 당시와 달라져, 각 행이 어느 정책에 대한 것인지 APO가 알 수 없습니다. 이 세 칸은 APO가 채워 넣는 값입니다 — 원래대로 되돌리거나, 표본을 새로 내려받아 적어 둔 판정을 옮겨 적으세요. 판정 자체는 그대로 유효합니다.",
    "{n} empty row(s) at the end of the sheet were skipped — this is a normal spreadsheet artifact and does not affect the numbers.":
      "표 아래의 빈 줄 {n}건을 건너뛰었습니다 — 엑셀 저장 과정에서 흔히 생기는 것으로, 수치에는 영향이 없습니다.",
    "Of those, {n} row(s) came from this sample but their VDOM / policy type / policy ID columns no longer match what APO issued, so those verdicts could not be counted.":
      "그중 {n}건은 이 표본에서 나온 행이지만 VDOM / 정책 종류 / 정책 번호 칸이 발급 당시와 달라져, 적어 주신 판정을 셀 수 없었습니다.",
    "{n} row(s) are severity 0 (\"Cannot assess\"), where the only honest answer is that APO could not judge. They are shown in the table but left out of the figure above, so they cannot inflate it.":
      "{n}건은 등급 0(\"판정 불가\")입니다 — 정직한 답이 \"APO가 판정하지 못했다\" 하나뿐이라, 표에는 남기되 위 수치에서는 뺐습니다. 그래야 수치가 부풀지 않습니다.",
    "({match} match / {mismatch} mismatch across {judged} judged samples). Held and unfilled rows are excluded from the denominator.":
      "(채점된 {judged}건 중 일치 {match}건 / 불일치 {mismatch}건). 보류·미기입 행은 분모에서 뺍니다.",
    "The sample is stratified — it takes a similar number from each severity level no matter how many policies that level actually has. So this is not the accuracy across your whole device; read the per-level rows for that.":
      "표본은 등급별로 고르게 뽑습니다 — 그 등급의 정책이 몇 건이든 비슷한 수를 가져옵니다. 그래서 이 값은 장비 전체의 정확도가 아닙니다. 등급별 줄을 보세요.",
    "{n} cell(s) had a verdict written that APO could not read, so those rows were left out. Please write 일치 / 불일치 / 보류 (match / mismatch / hold).":
      "판정을 적었지만 APO가 읽지 못한 칸이 {n}건 있어 그 행은 빠졌습니다. 일치 / 불일치 / 보류 중 하나로 적어 주세요.",
    "Levels {levels} have fewer than 5 judged samples — treat those numbers as indicative, not conclusive.":
      "등급 {levels} 은 채점된 표본이 5건 미만입니다 — 참고치로만 보세요.",
    "Your object names": "우리 환경의 객체 이름",
    "this device only": "이 장비에만 적용",
    "Save object names": "객체 이름 저장",
    "APO recognises some of your objects by name and judges them differently — management hosts stay, a DMZ zone is always Critical. Every organisation names these differently, so tell APO what yours look like. Matching is \"name contains this text\"; the preview shows exactly what each entry catches in the configuration you have open.": "APO는 일부 객체를 이름으로 알아보고 판정을 달리합니다 — 관리 호스트는 유지하고, DMZ 존은 항상 Critical입니다. <strong>이 이름은 조직마다 다르므로</strong> 우리 환경에서 어떻게 부르는지 알려 주세요. 매칭은 '이름에 이 글자가 들어가면'이고, 아래 미리보기가 지금 열어 둔 설정에서 무엇이 걸리는지 그대로 보여줍니다.",
    "Ticket number format": "티켓 번호 형식",
    "kept on this computer": "이 컴퓨터에 저장됩니다",
    "Ticket prefixes (separate with commas)": "티켓 접두어 (쉼표로 구분)",
    "What do your ticket numbers start with?": "티켓 번호는 무엇으로 시작하나요?",
    "Nothing matched. Your policy names look like this — which part is the ticket number? {names}":
      "하나도 인식되지 않았습니다. 이 설정의 정책 이름은 이렇게 생겼습니다 — 이 중 어느 부분이 티켓 번호인가요? {names}",
    "Also look in the policy comment": "정책 주석(comment)에서도 찾기",
    "Advanced — write the pattern myself": "고급 — 패턴을 직접 쓰기",
    "Leave this empty unless your ticket numbers do not start with a fixed prefix. Patterns that can hang the assessment are refused.":
      "티켓 번호가 고정된 접두어로 시작하지 않을 때만 씁니다. 판정을 멈추게 할 수 있는 패턴은 거부됩니다.",
    "Save ticket format": "티켓 형식 저장",
    "APO reads the ITSM ticket number from each policy to tell approved policies from undocumented ones. Every organisation numbers tickets differently, so tell APO what yours look like. The preview shows how many policies in the configuration you have open would be recognised.":
      "APO는 각 정책에서 ITSM 티켓 번호를 읽어 <strong>승인된 정책과 근거 없는 정책</strong>을 가릅니다. 티켓 번호 체계는 조직마다 다르므로 우리 것이 어떤 형태인지 알려 주세요. 아래 미리보기가 지금 열어 둔 설정에서 몇 건이 인식되는지 보여줍니다.",
    "No ticket format set — policies are not checked for a ticket number.":
      "티켓 형식이 설정되지 않았습니다 — 정책의 티켓 번호를 판정하지 않습니다.",
    "Upload a configuration to see how many policies this recognises.":
      "설정 파일을 올리면 몇 건이 인식되는지 보여 드립니다.",
    "{m} of {n} policies recognised.": "{n}건 중 {m}건에서 티켓을 인식했습니다.",
    "For example {ticket} on policy {id}.": "예: 정책 {id} 의 {ticket}.",
    "This comes from the profile file, not from this screen.":
      "이 값은 이 화면이 아니라 프로파일 파일에서 온 것입니다.",
    "Ticket format changed — run the assessment again.":
      "티켓 형식이 바뀌었습니다 — 다시 점검하세요.",
    "Type the text that appears inside your address object names — not the whole name, just the part that identifies it. Entering DMZ matches DMZ_WEB_01 and OA_DMZ_ZONE. Every organisation names these differently, so APO cannot guess yours. They are checked in the order below and the first match wins, so a name that fits two rows is judged by the higher one. The preview under each box shows exactly what it catches in the configuration you have open.":
      "<strong>주소 객체 이름 안에 들어가는 글자</strong>를 적으세요 — 전체 이름이 아니라 그것을 알아볼 수 있는 부분만 적으면 됩니다. <code>DMZ</code> 라고 적으면 <code>DMZ_WEB_01</code> 과 <code>OA_DMZ_ZONE</code> 이 걸립니다. 이름 규칙은 조직마다 다르므로 APO가 짐작할 수 없습니다. <strong>아래 순서대로 검사하고 먼저 걸린 것이 이깁니다</strong> — 두 칸에 모두 해당하는 이름은 위쪽 기준으로 판정됩니다. 각 칸 아래 미리보기가 지금 열어 둔 설정에서 무엇이 걸리는지 그대로 보여줍니다.",
    "Zones that must never be exposed": "절대 열려 있으면 안 되는 구역",
    "e.g. DMZ, EXTERNAL, GUEST": "예: DMZ, EXTERNAL, GUEST",
    "Admin, jump and backup servers": "관리·점프·백업 서버",
    "Kept — not proposed for removal": "유지합니다 — 삭제 후보로 올리지 않습니다",
    "e.g. ADMIN, JUMP, BASTION, BACKUP": "예: ADMIN, JUMP, BASTION, BACKUP",
    "User PCs and VDI pools": "사용자 PC·VDI 대역",
    "Judged as user-to-server traffic": "사용자 ↔ 서버 트래픽으로 판정합니다",
    "e.g. VDI, DESKTOP, OFFICE": "예: VDI, DESKTOP, OFFICE",
    "Shared infrastructure (DNS, NTP, monitoring)": "공용 인프라 (DNS·NTP·모니터링)",
    "Lowered to review": "검토 등급으로 낮춥니다",
    "e.g. DNS, NTP, ZABBIX": "예: DNS, NTP, ZABBIX",
    "Lowered to review — same result as infrastructure": "검토 등급으로 낮춥니다 — 공용 인프라와 결과가 같습니다",
    "e.g. MGMT, OOB": "예: MGMT, OOB",
    "comma separated": "쉼표로 구분",
    "Management / admin policies": "관리·운영자 정책",
    "Kept rather than removed — that access is needed": "삭제 대신 유지합니다 — 그 접근은 필요합니다",
    "Management network": "관리망",
    "Treated as infrastructure": "인프라로 취급합니다",
    "High-risk zones": "위험 존",
    "Always Critical": "항상 Critical로 봅니다",
    "User segments (VDI pools, desktops)": "사용자 세그먼트(VDI 풀, 데스크톱)",
    "Marks traffic as user-facing": "트래픽을 사용자향으로 표시합니다",
    "Infrastructure": "인프라",
    "Excluded from disuse judgements": "미사용 판정에서 제외합니다",
    "using your entries": "입력한 값을 씁니다",
    "using the profile default: {vals}": "프로파일 기본값을 씁니다: {vals}",
    "not set — this check is skipped": "미설정 — 이 판정은 건너뜁니다",
    "{n} object(s)": "객체 {n}개",
    "{n} inside a longer word": "{n}개는 더 긴 단어 속에 걸렸습니다",
    "comma separated, e.g. ADMIN, MGMT, NOC": "쉼표로 구분, 예: ADMIN, MGMT, NOC",
    "Saved. Run the assessment again to apply this.": "저장했습니다. 점검을 다시 실행하면 반영됩니다.",
    "Object names changed — run the assessment again.": "객체 이름이 바뀌었습니다 — 점검을 다시 실행하세요.",
    "Rule set": "룰 세트",
    "all your tuning in one file": "설정을 한 파일로",
    "The thresholds, object names and ticket format above are your judgement criteria. Export them as one file to keep alongside a report, so the record shows — with its SHA-256 — exactly which criteria that report was produced under. The same hash is printed on the report's Summary sheet. Exporting reads your settings; it changes nothing.":
      "위의 임계값·객체 이름·티켓 형식은 <strong>당신의</strong> 판정 기준입니다. 한 파일로 내보내 리포트와 함께 보관하면, 그 <strong>SHA-256</strong> 으로 '이 리포트가 어떤 기준으로 나왔는지'가 기록에 남습니다. 같은 해시가 리포트의 Summary 시트에도 인쇄됩니다. 내보내기는 설정을 읽기만 하며 아무것도 바꾸지 않습니다.",
    "Export rule set": "룰 세트 내보내기",
    "Export failed": "내보내지 못했습니다",
    "Exported.": "내보냈습니다.",
    "Current rule set: {hash}": "현재 룰 세트: {hash}",
    "Copy full hash": "전체 해시 복사",
    "{total} policies · {judged} judged · {shown} shown": "정책 {total}건 · 판정 {judged}건 · 표시 {shown}건",
    "That file is not a rule set (could not read JSON).": "이 파일은 룰 세트가 아닙니다 (JSON을 읽지 못했습니다).",
    "Not a rule set document.": "룰 세트 문서가 아닙니다.",
    "Not a rule set. Expected at least one of thresholds / object_rules / ticket.": "룰 세트가 아닙니다. thresholds / object_rules / ticket 중 최소 하나가 필요합니다.",
    "The ticket format could not be saved to disk, so it was not applied.": "티켓 형식을 디스크에 저장하지 못해 적용되지 않았습니다.",
    "None of the thresholds in this rule set are usable, so nothing was changed. Check the names and ranges.": "이 룰 세트의 임계값 중 쓸 수 있는 것이 없어 아무것도 바꾸지 않았습니다. 이름과 범위를 확인하세요.",
    "thresholds must be an object.": "임계값은 객체 형태여야 합니다.",
    "Applying changes to the device needs a licence. This is the only action that writes to your firewall and it cannot be undone from here, so it is kept behind a licence. You can still copy the CLI commands from the Action Plan and run them yourself - the assessment and the plan are free.": "장비에 변경을 적용하려면 라이선스가 필요합니다. 이 동작만이 고객님의 방화벽에 직접 쓰기를 하며 이 도구에서 되돌릴 수 없어, 라이선스 뒤에 두었습니다. 조치 계획의 CLI 명령을 복사해 직접 실행하실 수 있습니다 — 점검과 조치 계획은 무료입니다.",
    "Your key is saved but not currently valid — see above.": "등록된 키가 있으나 지금은 유효하지 않습니다 — 위 사유를 확인하세요.",
    "Included updates end on {date} ({days} days left).": "포함된 업데이트가 {date}에 종료됩니다(남은 기간 {days}일).",
    "Included updates ended on {date}. This version keeps working.": "포함된 업데이트가 {date}에 종료되었습니다. 이 버전은 계속 사용하실 수 있습니다.",
    "No device is open, so the object names in this rule set have nowhere to go. Open the device first, then import it again.": "열려 있는 장비가 없어 이 룰 세트의 객체 이름을 적용할 곳이 없습니다. 장비를 먼저 연 뒤 다시 가져오세요.",
    "The ticket format could not be saved to disk, so nothing was changed.": "티켓 형식을 디스크에 저장하지 못해 아무것도 바꾸지 않았습니다.",
    "This pattern takes too long on ordinary policy names. Patterns like (a{1,10})+ or ((a)*)* can take hours on a 41-character name. Use a bounded form like [A-Z]{3}\\d{3,12}.": "이 패턴은 평범한 정책 이름에서 너무 오래 걸립니다. (a{1,10})+ 나 ((a)*)* 같은 형태는 41자짜리 이름 하나에 몇 시간이 걸릴 수 있습니다. [A-Z]{3}\\d{3,12} 처럼 횟수를 제한한 형태를 쓰세요.",
    /* 티켓 정규식 거부 사유(runtime_settings.validate_regex). 서버가 사유
       문장을 error 로 그대로 주고 error_key 는 'bad_pattern' 이다 —
       SERVER_ERRORS 에 'bad_pattern' 을 두지 않으므로 serverMsg 가
       apoT(d.error) 로 되돌아온다. 즉 **이 문장들 자체가 사전 키**다.
       (설정 화면 저장·룰 세트 가져오기 두 경로가 같은 문장을 쓴다.) */
    "request": "요청",
    "APO could not read its device store ({file}) — the file is damaged. Close any other copy of APO that may be running and restart. If it still fails, move that file aside and register your devices again; your configuration files are not affected.":
      "장비 보관소({file})를 읽지 못했습니다 — 파일이 손상됐습니다. 다른 APO 창이 떠 있으면 닫고 다시 시작하세요. 그래도 안 되면 그 파일을 다른 곳으로 옮기고 장비를 다시 등록하세요. 설정 파일에는 영향이 없습니다.",
    "This backup contains sections APO does not read ({sections}), so those entries are not part of this assessment.":
      "이 백업에는 APO가 읽지 않는 섹션이 있습니다({sections}) — 그 항목들은 이번 점검에 포함되지 않습니다.",
    "None of the pasted rows match a policy number in the configuration that is open. Check that this output came from the same device.":
      "붙여넣은 행 중 지금 열려 있는 설정의 정책 번호와 맞는 것이 하나도 없습니다. 같은 장비에서 뽑은 출력인지 확인하세요.",
    "Hit count / last used has no values": "hit count / last used 에 값이 없음",
    "{n} rows matched this configuration, but none of them carry a hit count or a last-used date — check that you picked the Hit Count column, not Bytes.":
      "이 설정과 맞는 행이 {n}건 있지만 어느 행에도 hit count 나 마지막 사용일이 없습니다 — Bytes 가 아니라 Hit Count 칸을 골랐는지 확인하세요.",
    "{list} covers every address, so nothing is left to count as server traffic — Severity 3/4/5/6 will not tell users and servers apart.":
      "{list} 은(는) 모든 주소를 포함합니다 — 서버 트래픽으로 남는 것이 없어 등급 3·4·5·6 이 사용자와 서버를 구분하지 못합니다.",
    "APO could not clear the stored usage data, so it would come back when you reopen the device. Nothing was changed.":
      "저장된 사용량 데이터를 지우지 못했습니다 — 장비를 다시 열면 되돌아옵니다. 아무것도 바뀌지 않았습니다.",
    "APO could not save these IP ranges to the device store, so they would be lost when you reopen the device. Nothing was changed.":
      "이 IP 대역을 장비 보관소에 저장하지 못했습니다 — 장비를 다시 열면 사라집니다. 아무것도 바뀌지 않았습니다.",
    "Judgement reasons and recommended actions stay in English so that the screen and the Excel report use the same words — you can find on the report exactly what you saw here. Menus and descriptions follow your language.":
      "판정 사유와 권고 조치는 영어로 표시됩니다 — 화면과 엑셀 리포트가 같은 말을 써야 화면에서 본 근거를 리포트에서 그대로 찾을 수 있기 때문입니다. 메뉴와 설명은 선택한 언어를 따릅니다.",
    "Run the assessment again to apply it.": "점검을 다시 실행해야 반영됩니다.",
    "{n} IP range(s) saved — run the assessment again to apply it.":
      "IP 대역 {n}개를 저장했습니다 — 점검을 다시 실행해야 반영됩니다.",
    "These results were produced with different settings than the ones in effect now, so the report would state criteria that did not produce it. Run the assessment again, then export.":
      "이 결과는 지금 적용 중인 설정과 다른 설정으로 만들어졌습니다. 그대로 내보내면 리포트가 그 결과를 만들지 않은 기준을 적게 됩니다. 점검을 다시 실행한 뒤 내보내세요.",
    "The ticket format you saved in an older version is no longer used, and nothing has replaced it — no policy is being checked for a ticket number.":
      "예전 버전에서 저장한 티켓 형식은 더 이상 쓰지 않으며, 대신할 값도 없습니다 — 지금은 어떤 정책도 티켓 번호를 확인하지 않습니다.",
    "Enter the prefix your tickets start with (for example RITM).":
      "티켓 번호가 시작하는 접두어를 넣어 주세요(예: RITM).",
    "A pattern you saved in an older version is no longer used — enter the prefix your tickets start with instead.":
      "예전 버전에서 저장한 패턴은 더 이상 쓰지 않습니다 — 티켓 번호가 시작하는 접두어를 넣어 주세요.",
    "Ticket formats are set with prefixes now. Enter the prefix your tickets start with (for example RITM), not a regular expression.":
      "티켓 형식은 이제 접두어로 설정합니다. 정규식이 아니라 티켓 번호가 시작하는 접두어(예: RITM)를 넣어 주세요.",
    "Could not reach APO. Check that the APO window is still open, then run the assessment again.":
      "APO에 연결하지 못했습니다. APO 창이 아직 열려 있는지 확인한 뒤 점검을 다시 실행하세요.",
    "Pattern is empty.": "패턴이 비어 있습니다.",
    "That pattern is too long. Keep it under 200 characters.": "패턴이 너무 깁니다. 200자 이내로 줄여 주세요.",

    "That is not a valid regular expression. Check that brackets and parentheses are closed.": "올바른 정규식이 아닙니다. 괄호와 대괄호가 모두 닫혔는지 확인하세요.",

    "Nested quantifiers such as (x+)+ can hang the assessment on some names. Use a bounded form like [A-Z]{3}\\d{3,12} instead.":
      "(x+)+ 같은 중첩 수량자는 일부 이름에서 점검을 멈추게 할 수 있습니다. [A-Z]{3}\\d{3,12} 처럼 횟수를 제한한 형태를 쓰세요.",
    "A repeated alternation such as (a|b)* can hang the assessment. Anchor the number part with a bounded count like \\d{3,12}.":
      "(a|b)* 같은 반복 선택은 점검을 멈추게 할 수 있습니다. 숫자 부분을 \\d{3,12} 처럼 횟수를 제한해 고정하세요.",
    "Imported. Run the assessment again to apply this.": "가져왔습니다. 점검을 다시 실행하면 반영됩니다.",
    "Rule set imported — run the assessment again.": "룰 세트를 가져왔습니다 — 점검을 다시 실행하세요.",
    "Save failed": "저장하지 못했습니다",
    "checked all {n} enabled firewall policies, but {u} of them use features APO does not model, so they were not used as evidence — findings here may be incomplete": "활성 방화벽 정책 {n}건을 모두 검사했지만, 그중 {u}건은 APO가 다루지 않는 기능을 써서 근거로 쓰지 못했습니다 — 여기 발견은 완전하지 않을 수 있습니다",
    "Critical {c} · High {h} · already disabled {d}": "Critical {c}건 · High {h}건 · 이미 비활성 {d}건",
    "{n} policy(ies) held back: {ids}. Each is unreachable only while a policy this plan also changes stays enabled ({shadowers}) — decide those first, take a fresh backup and run APO again.": "{n}건을 유보했습니다: {ids}. 이 계획이 함께 바꾸는 정책({shadowers})이 켜져 있는 동안에만 가려져 있습니다 — 그 정책들을 먼저 처리하고, 설정을 새로 백업해 APO를 다시 돌리세요.",
    "There is nothing to export yet — load the remediation candidates first, then export.": "아직 내보낼 것이 없습니다 — 조치 후보를 먼저 불러온 뒤 내보내세요.",
    "Register and test the FortiGate first — a Postman collection without a target address cannot be run.": "FortiGate를 먼저 등록하고 연결을 확인하세요 — 대상 주소가 없는 Postman 컬렉션은 실행할 수 없습니다.",
    "Not read": "못 읽음",
    "{n} line(s) could not be read and {d} object(s) were skipped — this backup looks truncated, so those policies are not in the assessment. Download the configuration again.": "{n}줄을 읽지 못했고 객체 {d}개를 건너뛰었습니다 — 백업이 잘린 것 같습니다. 그 정책들은 판정에 포함되지 않았습니다. 설정을 다시 내려받으세요.",
    "This backup looks truncated — anything after the cut was not read, and VDOM attribution may be wrong. Re-export a complete backup and load it again.": "백업이 잘린 것 같습니다 — 잘린 지점 이후는 읽지 못했고, VDOM 귀속이 틀릴 수 있습니다. 완전한 백업을 다시 내보내 다시 불러오세요.",
    "{n} line(s) in this configuration could not be read — see the warnings sheet in the exported workbook.": "이 설정에서 {n}줄을 읽지 못했습니다 — 내보낸 워크북의 경고 시트를 보세요.",
    "※ Without User IP ranges configured, traffic type (Server/User) cannot be determined. Some Severity 1, 2 and 7 rules still apply (any/all policies, disabled policies, valid tickets), but every rule that depends on Server↔User direction is held back as \"not enough data\" — add your ranges for a full classification.": "※ 사용자 IP 대역을 넣지 않으면 트래픽 방향(서버/사용자)을 가릴 수 없습니다. <strong>1·2·7등급 규칙 일부는 그대로 적용</strong>되지만(any/all 정책, 비활성 정책, 유효한 티켓), 서버↔사용자 방향에 기대는 규칙은 전부 '판정할 데이터가 부족함'으로 남습니다 — 대역을 넣으면 전체 분류가 됩니다.",
    "Two exceptions sit above this table. A policy that only opens AD/DNS services (LDAP, Kerberos, DNS…) is graded 6 even with a wide source or destination, because domain controllers legitimately serve everyone. A policy that references one of your admin objects (MGMT, ADMIN…) is graded 6 or 3 rather than removed, because that access is needed. Neither exception applies when source, destination and service are all Any/All — that is an open policy, not an AD/DNS or admin policy.": "<strong>이 표보다 먼저 걸리는 예외가 두 가지 있습니다.</strong> AD/DNS 서비스(LDAP, Kerberos, DNS 등)만 여는 정책은 출발지나 목적지가 넓어도 6등급입니다 — 도메인 컨트롤러는 원래 모두에게 서비스합니다. 관리자 객체(MGMT, ADMIN 등)를 참조하는 정책은 삭제 대신 6 또는 3등급으로 둡니다 — 그 접근은 필요하기 때문입니다. 다만 출발지·목적지·서비스가 <em>모두</em> Any/All이면 두 예외 다 적용하지 않습니다. 그건 AD/DNS 정책도 관리자 정책도 아니라 그냥 열린 정책입니다.",
    "APO could not read its saved devices": "APO가 보관해 둔 장비 목록을 읽지 못했습니다",
    "Could not read the device list. Your registered devices were not deleted — the store could not be opened. Close any other copy of APO that may be running, then restart.": "장비 목록을 읽지 못했습니다. 등록한 장비가 지워진 것이 아니라, 보관 파일을 열지 못한 것입니다. APO가 다른 창에서 실행 중이면 닫고 다시 시작하세요.",
    "Scoring failed": "채점하지 못했습니다",
    "Scored.": "채점했습니다.",
    "Failed": "실패했습니다",
    "{ignored} row(s) were ignored — APO did not issue them for this device. {scored} row(s) were scored.": "{ignored}행은 APO가 이 장비에 발급한 행이 아니어서 세지 않았습니다. {scored}행을 채점했습니다.",
    "This sheet has no 표본 ID column, so APO cannot tell which device it was made for. Download a fresh sample for the device you have open and enter the results in that file.": "이 표에는 표본 ID 칸이 없어, 어느 장비에 발급한 것인지 알 수 없습니다. 지금 열어 둔 장비의 표본을 새로 내려받아 그 파일에 결과를 적어 주세요.",
    "The 표본 ID in this sheet was not issued for the device you have open ('{open}'). Open the device this sample was made for, or download a fresh sample.": "이 표의 표본 ID는 지금 열어 둔 장비('{open}')에 발급한 것이 아닙니다. 이 표본을 발급받은 장비를 열거나, 표본을 새로 내려받으세요.",
    "This sample was issued for an earlier backup of this firewall ({issued}). The grades in it were assigned from that configuration.": "이 표본은 이 방화벽의 이전 백업({issued})에 발급된 것입니다. 표 안의 등급은 그때의 설정으로 매겨진 값입니다.",
    "Apply complete — {ok} succeeded, {fail} failed. See results below.": "적용 완료 — 성공 {ok}건, 실패 {fail}건. 아래 결과를 보세요.",
    "The candidate list is recalculated from the stored configuration, so these policies stay listed until you collect the device again.": "후보 목록은 보관된 설정에서 다시 계산되므로, 장비를 새로 수집하기 전까지 이 정책들은 목록에 남습니다.",
    "The firewall at {ip} does not report a serial number, so APO has nothing unique to check it by — not now and not next time. Confirm the address yourself every time you apply.": "{ip}의 방화벽이 시리얼을 알려주지 않아, APO가 대조할 고유한 값이 없습니다 — 지금도, 다음에도 없습니다. 적용할 때마다 주소를 직접 확인하세요.",
    "Disable {n} policy(ies) on {target}: {ids}.": "{target} 장비에서 정책 {n}건을 비활성화합니다: {ids}.",
    "{shown} and {rest} more": "{shown} 외 {rest}건",
    "Candidates came from the configuration currently loaded ({src}).": "이 후보 목록은 지금 열어 둔 설정({src})에서 나왔습니다.",
    "This is applied immediately and cannot be undone from this tool.": "즉시 적용되며, 이 도구로는 되돌릴 수 없습니다.",
    "APO could not confirm that this address is the device you are looking at — the names do not distinguish them. Check {ip} yourself before continuing.": "이 주소가 지금 보고 있는 장비인지 APO가 확인하지 못했습니다 — 이름만으로는 구별되지 않습니다. 계속하기 전에 {ip}를 직접 확인하세요.",
    "This FortiGate did not report a serial number, so APO has nothing unique to match it by. Check the address before applying anything.": "이 FortiGate가 시리얼을 알려주지 않아, APO가 대조할 고유한 값이 없습니다. 무언가를 적용하기 전에 주소를 확인하세요.",
    "APO has not confirmed this device before — a hostname is not proof of identity. Check the address before applying anything; APO will remember the serial from then on.": "APO가 이 장비를 아직 확인한 적이 없습니다 — hostname은 신원 증명이 아닙니다(두 고객이 같은 이름을 쓸 수 있습니다). 적용 전에 주소를 확인하세요. 그 뒤로는 APO가 시리얼을 기억해 자동으로 대조합니다.",
    "APO could not read the serial number from this FortiGate this time, so it has nothing unique to match it by right now. Test the connection again to retry. Check the address before applying anything.": "이번에는 이 FortiGate의 시리얼을 읽지 못해, APO가 지금 대조할 고유한 값이 없습니다. 연결 확인을 다시 실행해 재시도해 보세요. 무언가를 적용하기 전에 주소를 확인하세요.",
    "APO could not read the serial number from {ip} this time, so it has nothing unique to check this device by right now. Test the connection again to retry — if the serial comes through, APO remembers it. Until then, confirm the address yourself.": "이번에는 {ip}에서 시리얼을 읽지 못해, APO가 지금 이 장비를 대조할 고유한 값이 없습니다. 연결 확인을 다시 실행해 재시도해 보세요 — 시리얼이 들어오면 APO가 기억합니다. 그 전까지는 주소를 직접 확인하세요.",
    "APO confirmed this firewall earlier as serial '{expected}', but it could not read the serial from {ip} this time, so it cannot be checked against that. Test the connection again; if it keeps failing, use the address you confirmed before.": "APO는 전에 이 방화벽을 시리얼 '{expected}'로 확인했는데, 이번에는 {ip}에서 시리얼을 읽지 못해 그 값과 대조할 수 없습니다. 연결 확인을 다시 실행해 보고, 계속 실패하면 전에 확인한 주소를 사용하세요.",

    "Usage data cleared for {name}.": "{name}의 사용량 데이터를 지웠습니다.",
    "Could not clear the usage data.": "사용량 데이터를 지우지 못했습니다.",
    "Server rejected the ranges file.": "서버가 대역 파일을 거부했습니다.",
    "Configuration changed — run the assessment again.": "설정이 바뀌었습니다 — 점검을 다시 실행하세요.",
    // 문구를 고치고 사전 키를 안 고쳤더니 이 문장만 영어로 나왔다 — 조용히,
    // 오류 없이(라운드 33에서 새 계약 테스트가 잡아냈다).
    "Reopened {name}. Findings are not stored — run the assessment to see them.": "{name}을(를) 다시 열었습니다. 판정 결과는 저장되지 않으므로 점검을 실행하면 다시 볼 수 있습니다.",
    "Opened {name}. Findings are not stored — run the assessment to see them.": "{name}을(를) 열었습니다. 판정 결과는 저장되지 않으므로 점검을 실행하세요.",
    "{n} usage rows": "사용량 {n}행",
    "no usage data": "사용량 없음",
    "{n} range(s)": "대역 {n}개",
    "no ranges": "대역 없음",
    "{n} device(s)": "장비 {n}대",
    "{d} device(s) registered, {c} customer(s).": "장비 {d}대 등록됨, 고객사 {c}곳.",
    "Delete {name}? Its config, usage CSV, user ranges and FQDN capture are removed from this computer, along with the device identity APO confirmed for remediation — you will have to confirm the target again. This cannot be undone.": "{name}을(를) 삭제할까요? 이 컴퓨터에서 설정 원문·사용량 CSV·사용자 대역·FQDN 수집분이 함께 지워지고, 조치용으로 확인해 둔 장비 신원(시리얼)도 사라집니다 — 다시 등록하면 대상을 한 번 더 확인해야 합니다. 되돌릴 수 없습니다.",
    "Delete {name}? Its devices stay registered — only the grouping is removed.": "{name}을(를) 삭제할까요? 장비는 등록된 채로 남고 묶음만 사라집니다.",

    // ── 장비 등록 마법사 ──
    "Register a device — guided": "장비 등록 — 안내에 따라",
    "Register a device": "장비 등록",
    "Continue with {name}": "{name} 이어서 하기",
    "Resume": "이어서 하기",
    "Start over": "처음부터",
    "Configuration file": "설정 파일",
    "Choose config file": "설정 파일 선택",
    "Not registered yet": "아직 등록되지 않음",
    "Firewall Policy CSV": "방화벽 정책 CSV",
    "FortiGate GUI → Policy & Objects → Firewall Policy → toolbar Export → CSV. The export contains the columns you are currently showing, so add Hit Count and Last Used to the view first.":
        "FortiGate GUI → 정책 및 개체 → 방화벽 정책 → 상단 도구막대 <Export> → CSV. 내보내기에는 **지금 화면에 보이는 열만** 담기므로, 먼저 Hit Count 와 Last Used 열을 표시에 추가하세요.",
    "No Export button? That button arrived in FortiOS 7.0.2. On older firmware you do not need this CSV — use Collect from device (reads the same numbers over the REST API), or paste CLI output on the Sources screen (diagnose firewall iprope show 100004 <policy id>).":
        "Export 버튼이 없나요? 그 버튼은 **FortiOS 7.0.2** 에서 추가됐습니다. 그 이전 펌웨어에서는 이 CSV 가 필요 없습니다 — <장비에서 수집>을 쓰거나(REST API 로 같은 값을 읽습니다), 데이터 가져오기 화면에 CLI 출력을 붙여넣으세요 (diagnose firewall iprope show 100004 <정책 번호>).",
    "Choose FW Policy CSV": "방화벽 정책 CSV 선택",
    "Not added": "아직 넣지 않음",
    "optional": "선택",
    "Choose Proxy Policy CSV": "프록시 정책 CSV 선택",
    "Your user IP ranges": "사용자 IP 대역",
    "The line between user traffic and server traffic. Without it, policies that need that distinction come back as Cannot assess.": "사용자 트래픽과 서버 트래픽을 가르는 기준입니다. 없으면 이 구분이 필요한 정책은 '판정 불가'로 나옵니다.",
    "On the device run:": "장비에서 다음 명령을 실행하세요:",
    "Copy command": "명령 복사",
    "Upload the output": "결과 올리기",
    "Save & close": "임시 저장하고 닫기",
    "Back": "이전",
    "Next": "다음",
    "Finish": "완료",
    "Step {n} of {total}": "{total}단계 중 {n}단계",
    "Registered — {name}": "등록됨 — {name}",
    "Added — {name}": "넣음 — {name}",
    "Not added (skip if unused)": "아직 넣지 않음 (사용하지 않으면 건너뛰세요)",
    "Added": "넣음",
    "device": "장비",
    "Reporting across devices needs the MSP / Consultant licence. A single device is always available from its row.": "여러 장비를 묶어 뽑으려면 MSP / 컨설턴트 라이선스가 필요합니다. 장비 한 대는 각 장비 줄에서 언제든 뽑을 수 있습니다.",

    // ── Overview ──
    "Assess a FortiGate ruleset": "FortiGate 정책 점검",
    "Connect a device": "장비 연결",
    "Import a config file": "설정 파일 가져오기",
    "Run assessment": "점검 실행",
    "Open action plan": "조치 계획 열기",
    "Severity distribution": "심각도 분포",
    "What to do": "무엇을 할 것인가",
    "Evidence coverage": "근거 충족도",
    "click a band to filter findings": "막대를 누르면 해당 등급만 봅니다",
    "by action, in working order": "조치 순서대로",
    "what limits these results right now": "지금 이 결과를 제약하는 것",
    "Policies": "정책 수",
    "Needs action": "조치 필요",
    "Critical": "심각(Critical)",
    "Shadowed": "가려짐",
    "Not judged": "판정 불가",
    "policies with a recommended change": "권고 조치가 있는 정책",
    "highest severity — all need action (some may appear under Unreachable below)": "최고 심각도 — 모두 조치 대상(일부는 아래 도달불가 그룹에 표시될 수 있음)",
    "excluded from the counts above": "위 집계에서 제외됨",

    // ── Overview 진입 화면 ──
    "APO reads a configuration and each policy's hit count / last used history, then tells you which policies are dead, over-broad, or undocumented — with the evidence behind every call. Everything runs on this machine; nothing is uploaded anywhere.":
      "APO는 설정과 정책별 hit count / last used 이력을 읽고, 어떤 정책이 죽었고 과도하게 넓고 근거 문서가 없는지 — 판정마다 근거와 함께 — 알려줍니다. 모든 분석은 이 컴퓨터 안에서만 돌고 아무것도 밖으로 전송되지 않습니다.",

    // ── Overview 진입 화면 — 준비물 3묶음 ──
    "Brought in above": "위에서 가져옴",
    "config · hit count / last used · FQDN resolutions": "config · hit count / last used · FQDN 해석",
    "Device collection brings all three at once — with files, add the policy CSV beside the config.":
      "장비 수집은 셋을 한 번에 가져옵니다 — 파일이면 config 옆에 정책 CSV를 함께 넣으세요.",
    "Entered by hand": "직접 입력",
    "The line between user and server traffic — needed whichever way the data came in.":
      "사용자 트래픽과 서버 트래픽을 가르는 기준 — 어느 경로로 가져왔든 필요합니다.",
    "Enter now": "지금 입력",
    "Then": "그 다음",
    "Run the assessment": "점검 실행",
    "Findings and the action plan open from the results.": "점검 결과와 조치 계획이 열립니다.",

    // ── Sources — 두 경로 카드 ──
    "Bring in the configuration and the per-policy hit count / last used history the assessment runs on. Either path below feeds the same analysis — the results are identical.":
      "점검의 근거가 되는 설정과 정책별 hit count / last used를 가져옵니다. 아래 두 경로 중 어느 쪽으로 넣든 분석과 결과는 완전히 같습니다.",
    "Collect from the device": "장비에서 수집",
    "recommended": "권장",
    "Pulls everything over the FortiGate REST API in one step — no export files to prepare.":
      "FortiGate REST API로 필요한 자료를 한 번에 가져옵니다 — 내보내기 파일을 준비할 필요가 없습니다.",
    "config — all policies and objects": "config — 정책과 객체 전체",
    "hit count / last used — per-policy usage history": "hit count / last used — 정책별 사용 이력",
    "FQDN resolutions — the domain → IP answers the device has cached":
      "FQDN 해석 — 장비가 캐시한 도메인 → IP",
    "A read-only API token is enough — this only reads and never changes the device. The token stays in memory and is never written to disk.":
      "읽기 전용 토큰이면 충분합니다 — 읽기만 하며 장비 설정을 바꾸지 않습니다. 토큰은 메모리에만 두고 디스크에 쓰지 않습니다.",
    "Import files": "파일로 가져오기",
    "Add the configuration first — the usage CSV is then attached to that device.":
      "설정 파일을 먼저 등록하세요 — 사용량 CSV는 그 장비에만 붙습니다.",
    "For air-gapped networks where the device cannot be reached directly. Export these from the device beforehand.":
      "장비에 직접 접속할 수 없는 폐쇄망에서 씁니다. 아래 파일을 장비에서 미리 내보내 두세요.",
    "config file — the full configuration (.conf / .txt)": "config 파일 — 전체 설정 (.conf / .txt)",
    "Firewall Policy CSV — hit count / last used per firewall policy":
      "Firewall Policy CSV — 방화벽 정책의 hit count / last used",
    "Proxy Policy CSV — only for devices that use proxy policies":
      "Proxy Policy CSV — 프록시 정책을 쓰는 장비만 해당",
    "Config alone still runs the assessment, but without hit count and last used no policy can be called unused.":
      "config만 넣어도 점검은 돌아가지만, hit count와 last used가 없으면 미사용 판정은 나오지 않습니다.",
    "lets APO disable the chosen policies on the device — skip it if you apply changes by hand":
      "선택한 정책을 APO가 장비에서 직접 비활성합니다 — 손으로 적용한다면 건너뛰세요",

    // ── Sources ──
    "Config File": "설정 파일",
    "Collect from device": "장비에서 수집",
    // stale 키 정리(v99): 마크업 원문과 한 글자라도 다르면 번역이 조용히 안 걸린다.
    "or upload DNS cache dump": "또는 DNS 캐시 덤프 업로드",
    "Import from File": "파일에서 가져오기",
    "Add": "추가",
    "Setup": "준비",
    "User IP ranges": "사용자 IP 대역",

    // ── Sources — 일괄 보고 (MSP) ──
    "Batch report": "일괄 보고",
    "MSP / Consultant — one workbook per device, downloaded as a zip":
      "MSP · 컨설턴트 — 장비당 워크북 하나, zip으로 다운로드",
    "Available with the MSP / Consultant license.": "MSP · 컨설턴트 라이선스에서 사용할 수 있습니다.",
    "See licence options": "라이선스 안내 보기",
    "Select files": "파일 선택",
    "Build batch reports": "일괄 보고서 만들기",

    // ── Findings / Action Plan ──
    // ── 임계값: 값 → 결과 연결 (2026-08-25) ──
    "These results are older than the settings above — the numbers on screen were produced with the previous values.": "화면에 남은 결과가 위 설정보다 앞섭니다 — 지금 보이는 숫자는 이전 값으로 매긴 것입니다.",
    "Classify again now": "지금 다시 점검",
    "With these values {moved} of {total} policies change grade:": "이 값으로 바꾸면 정책 {total}건 중 {moved}건의 등급이 달라집니다:",
    "With these values nothing is re-classified — all {total} policies keep their current grade.": "이 값으로 바꿔도 재분류되는 정책이 없습니다 — {total}건 모두 등급이 그대로입니다.",
    "Last used, {total} policies — {unknown} have no record.": "마지막 사용 분포, 정책 {total}건 — 그중 {unknown}건은 기록이 없습니다.",
    "Most policies have no usage record, so this value changes little — load a usage CSV first.": "대부분의 정책에 사용 기록이 없어 이 값을 바꿔도 판정이 거의 달라지지 않습니다 — 사용량 CSV를 먼저 올리세요.",
    "days": "일",
    // ── 컨테이너 접속 토큰 (B-77) ──
    "Access token required. Open this URL with ?token=… (the value you passed as APO_TOKEN), or send it as the X-APO-Token header.": "접속 토큰이 필요합니다. 주소 끝에 ?token=… 을 붙여 여세요(docker run 에 준 APO_TOKEN 값). 스크립트에서는 X-APO-Token 헤더로 보내세요.",
    "Server is not configured for container access. Set APO_TOKEN and restart.": "이 컨테이너에 접속 토큰이 설정되어 있지 않습니다. APO_TOKEN 을 지정하고 다시 시작하세요.",
    "This session uses:": "지금 쓰는 기준:",
    "This list was just recalculated, but the findings on screen (and any workbook you exported) were produced from different inputs — run the assessment again so both agree.": "이 목록은 방금 다시 계산했는데, 화면의 점검 결과(그리고 내보낸 워크북)는 다른 근거로 만들어진 것입니다 — 점검을 다시 실행해 양쪽을 맞추세요.",
    // ── 인증서 지문 고정 (B-79, TOFU) ──
    "The certificate at this address changed since APO last connected. On a channel without certificate verification that is what a man-in-the-middle looks like — changes will not be sent. If the device was genuinely replaced or re-keyed, remove and register it again.": "APO가 마지막으로 연결한 뒤 이 주소의 인증서가 바뀌었습니다. 인증서 검증을 끈 채널에서 이는 중간자 공격의 모습과 같아, 변경을 보내지 않습니다. 장비를 실제로 교체하거나 인증서를 새로 발급한 것이라면, 장비를 지우고 다시 등록하세요.",
    "first connection: certificate fingerprint {fp} is now remembered for this device. Check it on the device if this is a new network.": "첫 연결입니다. 인증서 지문 {fp}을(를) 이 장비의 것으로 기억했습니다. 처음 쓰는 망이라면 장비에서 지문을 대조해 보세요.",
    "The certificate at this address changed since APO last connected. On a channel without certificate verification that is what a man-in-the-middle looks like, and this request would carry your FortiGate admin token. If the device was genuinely replaced or re-keyed, remove and register it again.": "APO가 마지막으로 연결한 뒤 이 주소의 인증서가 바뀌었습니다. 인증서 검증을 끈 채널에서 이는 중간자 공격의 모습과 같고, 이 요청에는 FortiGate 관리자 토큰이 실립니다. 장비를 실제로 교체하거나 인증서를 새로 발급한 것이라면, 장비를 지우고 다시 등록하세요.",
    "Save results as CSV": "결과를 CSV로 저장",
    "These results are not stored — save them now if you need them for the change record.": "이 결과는 보관되지 않습니다 — 변경 기록에 필요하면 지금 저장하세요.",
    "There are no apply results to export yet — apply the changes first, then export.": "아직 내보낼 적용 결과가 없습니다 — 먼저 변경을 적용한 뒤 내보내세요.",
    "unused after {n} days": "{n}일 넘게 미사용이면 표시",
    "temp policies after {n} days": "임시 정책은 {n}일",
    "approval window {n} days": "승인 유효기간 {n}일",
    "server-user hits below years x {n}": "서버-사용자는 경과연수 × {n} 미만이면 저사용",
    "server-server hits below {n}": "서버-서버는 {n} 미만이면 저사용",
    // 프리셋 라벨(Standard/Strict/Relaxed)은 아래 설정 구역에 이미 있다 —
    // 값이 presets.yaml 로 옮겨졌을 뿐 문구는 같은 것이므로 다시 적지 않는다.
    "Most environments. A job that runs once a year is still safe.": "대부분의 환경. 1년에 한 번 도는 작업도 안전합니다.",
    "Where hit counters are trustworthy (reboots are rare) and cleanup is the priority.": "hit 카운터를 믿을 수 있고(재부팅이 드물고) 정리가 우선인 환경.",
    "Where usage data is thin or many policies serve rare batch work.": "사용량 데이터가 부족하거나, 드물게 도는 배치 정책이 많은 환경.",

    "Prioritised work list": "우선순위 작업 목록",
    "tick these off as you do the work by hand — nothing is sent to the device from here": "직접 조치하면서 진행 표시로 체크하세요 — 여기서는 장비로 아무것도 보내지 않습니다",
    "Clear checkmarks": "완료 표시 지우기",
    "Apply changes over the API": "API로 장비에 적용",
    "Device": "장비",
    "Connect the FortiGate": "FortiGate 연결",
    "Select": "선택",
    "Choose policies to disable": "비활성할 정책 선택",
    "Load Candidates": "후보 불러오기",
    "Export CSV": "CSV 내보내기",
    "Export JSON": "JSON 내보내기",
    "Save Device": "장비 저장",
    "Test Connection": "연결 확인",
    "Select All": "전체 선택",
    "Cancel": "취소",
    "Confirm": "확인",

    // ── Change review / Evidence ──
    "Configuration Change Review": "설정 변경 비교",
    "Ruleset Review Evidence": "정책 검토 증적",
    "Accuracy Verification": "정확도 검증",
    "Build timeline": "타임라인 만들기",
    "Verify": "검증",
    "Audit Trail": "감사 추적",

    // ── Settings / Reference ──
    "Assessment Thresholds": "판정 임계값",
    "License": "라이선스",
    "Language": "언어",
    "Enter a licence key": "라이선스 키 입력",
    "See a sample report": "샘플 리포트 보기",
    "See a sample report (.xlsx)": "샘플 리포트 보기 (.xlsx)",
    "Buy Now →": "구매하기 →",
    "Activate": "등록",
    "Single organisation": "단일 조직",
    "MSP / Consultant": "MSP · 컨설턴트",
    "Guide": "안내",
    "How policies are judged": "판정 기준",
    "Severity Classification Criteria": "심각도 분류 기준",

    // ── 서버가 낸 거절 · 오류 안내 ──────────────────────────────────
    // **돈 낸 사람이 막혔을 때 읽는 문장이다.** 서버 문자열은 사전에 닿지
    // 않으므로 app.js 의 serverMsg() 가 여기로 통과시킨다. 값이 끼어드는
    // 문장은 서버가 error_key 만 보내고 원문을 SERVER_ERRORS 가 만든다.
    "License required. Please activate your Export license.":
      "내보내기 라이선스가 필요합니다. 라이선스를 등록해 주세요.",
    "This configuration has more than one VDOM ({vdoms}), and policy numbers start again at 1 in each one. APO cannot tell which VDOM's policy you picked, so it will not write to the firewall. Upload the configuration of a single VDOM, or apply these changes on the device.":
      "이 설정에는 VDOM이 여러 개이고({vdoms}), 정책 번호는 VDOM마다 1번부터 다시 시작합니다. 고른 정책이 어느 VDOM의 것인지 APO가 가릴 수 없어 방화벽에 쓰지 않습니다. VDOM 하나짜리 설정을 올리거나, 이 변경은 장비에서 직접 적용하세요.",
    "That file is too large. The limit is {limit} MB per upload.":
      "파일이 너무 큽니다. 한 번에 올릴 수 있는 크기는 {limit} MB까지입니다.",
    "Reporting across devices requires an MSP / Consultant license.":
      "여러 장비를 묶어 보고서를 뽑으려면 MSP · 컨설턴트 라이선스가 필요합니다.",
    "Batch reporting requires an MSP / Consultant license. A single-organisation license exports one device at a time.":
      "일괄 보고는 MSP · 컨설턴트 라이선스 기능입니다. 단일 조직 라이선스는 한 번에 장비 한 대씩 내보냅니다.",
    "No registered devices in that scope.": "그 범위에 등록된 장비가 없습니다.",
    "No files uploaded. Select the config files (and optional CSV / ranges files) together.":
      "올린 파일이 없습니다. 설정 파일을 (필요하면 CSV·대역 파일과 함께) 한 번에 고르세요.",
    "Failed to build the report.": "보고서를 만들지 못했습니다.",
    "Failed to build the batch report.": "일괄 보고서를 만들지 못했습니다.",
    "No config loaded. Upload a config file first.":
      "불러온 설정이 없습니다. 설정 파일을 먼저 올리세요.",
    "Register a device first — upload its configuration file, then add that device's CSV.":
      "장비를 먼저 등록하세요 — 설정 파일을 올린 뒤 그 장비의 CSV를 넣습니다.",
    "No hit count / last used rows were recognised in {files}. Export the policy list from the device (Policy & Objects, right-click the column header, Export to CSV) and pick that file.":
      "{files}에서 hit count / last used 행을 하나도 읽지 못했습니다. 장비에서 정책 목록을 내보낸 파일(Policy & Objects → 컬럼 머리글 오른쪽 클릭 → Export to CSV)을 고르세요.",
    "None of the policy IDs in this file exist in the loaded configuration. This usually means the CSV came from a different device — nothing was imported.":
      "이 파일의 정책 번호가 지금 불러온 설정에 하나도 없습니다. 대개 다른 장비의 CSV라는 뜻입니다 — 아무것도 가져오지 않았습니다.",
    "No device is open, so that input has nowhere to go. Open the device first.":
      "열어 둔 장비가 없어 이 입력이 들어갈 곳이 없습니다. 장비를 먼저 여세요.",
    "This request did not say which device it is for. APO only applies input to the device you have open.":
      "이 요청이 어느 장비의 것인지 밝히지 않았습니다. APO는 지금 열어 둔 장비에만 입력을 반영합니다.",
    "That request was entered while a different device was open. Reopen the device you meant, then try again.":
      "다른 장비가 열려 있는 동안 들어온 요청입니다. 원하는 장비를 다시 연 뒤 시도하세요.",
    "That file belongs to a configuration that is no longer open. Open that device again to download its parsed configuration.":
      "이 파일은 지금 열려 있지 않은 설정의 것입니다. 그 장비를 다시 열어야 파싱 결과를 내려받을 수 있습니다.",
    "Both baseline and target config files are required.":
      "기준 설정 파일과 대상 설정 파일이 모두 필요합니다.",
    "Failed to compare configs. Check that both files are valid FortiGate configs.":
      "설정을 비교하지 못했습니다. 두 파일이 모두 정상적인 FortiGate 설정인지 확인하세요.",
    "Worksheet columns were not recognized — upload the sheet generated by APO, keeping its header row.":
      "워크시트의 컬럼을 알아보지 못했습니다 — APO가 만든 표를 머리글 줄까지 그대로 둔 채 올리세요.",
    "The header row was not found — APO looks for the column titles it generated. Upload the sheet generated by APO, keeping its header row.":
      "머리글 줄을 찾지 못했습니다 — APO는 자기가 만든 컬럼 제목을 찾습니다. APO가 만든 표를 머리글 줄까지 그대로 둔 채 올리세요.",
    "The worksheet has no data rows.": "이 워크시트에는 데이터 행이 없습니다.",
    "Could not read the worksheet. Upload the file generated by APO (.csv or .xlsx).":
      "워크시트를 읽지 못했습니다. APO가 만든 파일(.csv 또는 .xlsx)을 올리세요.",
    "Could not decode the CSV. Save it as UTF-8 or the Korean Excel default (CP949).":
      "CSV의 문자 인코딩을 읽지 못했습니다. UTF-8 또는 한글 엑셀 기본값(CP949)으로 저장해 주세요.",
    "worksheet file is required (.csv or .xlsx)":
      "워크시트 파일(.csv 또는 .xlsx)이 필요합니다.",
    "APO could not record this sample, so it would not be able to tell later which device it came from. Nothing was downloaded.":
      "이 표본을 기록해 두지 못해, 나중에 어느 장비의 것인지 가릴 수 없게 됩니다. 아무것도 내려받지 않았습니다.",
    "Run Test Connection first — the tool confirms which firewall answers at that address before sending any change.":
      "'연결 확인'을 먼저 누르세요 — 변경을 보내기 전에 그 주소에서 응답하는 방화벽이 무엇인지 확인합니다.",
    "The connected device was registered while a different configuration was open. Re-register the device for the one you are looking at now.":
      "연결된 장비는 다른 설정이 열려 있을 때 등록된 것입니다. 지금 보고 있는 설정에 맞춰 장비를 다시 등록하세요.",
    "APO confirmed this firewall earlier as serial '{expected}', but the device answering at {ip} does not report a serial, so it cannot be checked against that. Use the address you confirmed before.":
      "APO는 이 방화벽을 시리얼 '{expected}'로 확인해 뒀는데, {ip}에서 응답한 장비는 시리얼을 알려주지 않아 대조할 수 없습니다. 전에 확인한 주소를 쓰세요.",
    "The firewall answering at {ip} has serial '{serial}', but this device was confirmed as '{expected}'. The names match but it is a different unit — check the address.":
      "{ip}에서 응답한 방화벽의 시리얼은 '{serial}'인데, 이 장비는 '{expected}'로 확인돼 있습니다. 이름은 같아도 다른 장비입니다 — 주소를 확인하세요.",
    "The connected firewall is '{connected}', but the configuration you have open is '{config}'. Changes are not sent to a device other than the one you are looking at. Check the IP, or open that device's configuration first.":
      "연결된 방화벽은 '{connected}'인데, 지금 열어 둔 설정은 '{config}'입니다. 보고 있는 장비가 아닌 곳으로는 변경을 보내지 않습니다. IP를 확인하거나, 그 장비의 설정을 먼저 여세요.",
    "No device registered": "등록된 장비가 없습니다.",
    "No policies selected": "선택한 정책이 없습니다.",
    "No device is connected. Collect from the device on the Sources page first, or register one under Action Plan → Apply changes over the API.":
      "연결된 장비가 없습니다. '데이터 가져오기'에서 장비 수집을 먼저 하거나, '조치 계획 → API로 장비에 적용'에서 장비를 등록하세요.",
    "TLS verification failed. Fix the device certificate, or disable verification only on a trusted management network.":
      "TLS 검증에 실패했습니다. 장비 인증서를 고치거나, 신뢰할 수 있는 관리망에서만 검증을 끄세요.",
    "TLS verification failed.": "TLS 검증에 실패했습니다.",
    "Could not reach the device. Check the IP, port, and that REST API access is enabled.":
      "장비에 연결하지 못했습니다. IP와 포트, REST API 접근이 켜져 있는지 확인하세요.",
    "Could not reach the device.": "장비에 연결하지 못했습니다.",
    "The device reported no resolved FQDN addresses. FQDN objects resolve only after they have been used.":
      "장비가 해석된 FQDN 주소를 하나도 알려주지 않았습니다. FQDN 객체는 실제로 쓰인 뒤에야 해석됩니다.",
    "dump file is required — output of 'diagnose test application dnsproxy 6'":
      "덤프 파일이 필요합니다 — 'diagnose test application dnsproxy 6' 실행 결과",
    "Upload at least two config snapshots, oldest first.":
      "설정 스냅샷을 두 개 이상, 오래된 것부터 올리세요.",
    "At most 24 snapshots per timeline.": "타임라인 하나에 스냅샷은 24개까지입니다.",
    "Run the snapshot timeline first.": "스냅샷 타임라인을 먼저 만드세요.",
    "Failed to build evidence workbook": "증적 워크북을 만들지 못했습니다.",
    "Sample configuration is not bundled in this build.":
      "이 빌드에는 샘플 설정이 들어 있지 않습니다.",
    "Failed to build the sample report": "샘플 리포트를 만들지 못했습니다.",
    "Failed to build workbook export": "워크북을 만들지 못했습니다.",
    "Failed to build severity export": "심각도 판정 결과를 만들지 못했습니다.",
    // 라이선스 키 등록 실패 (license_checker.py)
    "That does not look like an APO licence key. Paste the whole key, including the APO2- prefix at the front.":
      "APO 라이선스 키 형식이 아닙니다. 앞의 APO2- 까지 포함해 키 전체를 붙여 넣으세요.",
    "This key uses a retired format. Please contact support (choiceguidelab@gmail.com) for a replacement key.":
      "더 이상 쓰지 않는 형식의 키입니다. 교체 키를 받으려면 지원팀(choiceguidelab@gmail.com)에 문의하세요.",
    "This key did not pass the signature check. It may have been altered in transit — copy it again from the purchase e-mail.":
      "서명 검증을 통과하지 못한 키입니다. 전달 과정에서 글자가 바뀌었을 수 있으니 구매 메일에서 다시 복사해 주세요.",
    "This key was issued for a different product.": "다른 제품에 발급된 키입니다.",
    "This computer's clock has been set back, so the expiry date on the key cannot be trusted. Set the date correctly and try again.":
      "이 컴퓨터의 시계가 과거로 되돌려져 있어 키의 만료일을 믿을 수 없습니다. 날짜를 바르게 맞춘 뒤 다시 시도하세요.",
    "This licence key has expired. Contact support (choiceguidelab@gmail.com) to renew it.":
      "만료된 라이선스 키입니다. 갱신하려면 지원팀(choiceguidelab@gmail.com)에 문의하세요.",
    "This licence key is registered to a different computer. Contact support (choiceguidelab@gmail.com) to move it to this one.":
      "다른 컴퓨터에 등록된 라이선스 키입니다. 이 컴퓨터로 옮기려면 지원팀(choiceguidelab@gmail.com)에 문의하세요.",
    "This key could not be read. Paste the whole key exactly as it was sent to you — if it still fails, contact support (choiceguidelab@gmail.com).":
      "키를 읽지 못했습니다. 받은 그대로 키 전체를 붙여 넣어 보시고, 그래도 안 되면 지원팀(choiceguidelab@gmail.com)에 문의하세요.",
    "key is required": "라이선스 키를 입력하세요.",

    // ── 화면이 만드는 실패 안내 (app.js) ────────────────────────────
    "Something went wrong.": "문제가 생겼습니다.",
    "Activation failed": "등록하지 못했습니다.",
    "Please enter your licence key.": "라이선스 키를 입력하세요.",
    "Checking the key...": "키를 확인하는 중...",
    "Registered ({email})": "등록 완료 ({email})",
    "Building the sample...": "샘플을 만드는 중...",
    "Downloaded ✓": "내려받음 ✓",
    "Could not build the sample": "샘플을 만들지 못했습니다",
    "Licence required — click to buy one or enter a key":
      "라이선스가 필요합니다 — 눌러서 구매하거나 키를 입력하세요",
    "Failed to build workbook export.": "워크북을 만들지 못했습니다.",
    "Evidence export failed.": "증적을 내보내지 못했습니다.",
    "Export failed.": "내보내지 못했습니다.",
    "CSV export failed": "CSV를 내보내지 못했습니다.",
    "JSON export failed": "JSON을 내보내지 못했습니다.",
    "Failed to generate sample.": "표본을 만들지 못했습니다.",
    "Batch export failed.": "일괄 내보내기에 실패했습니다.",
    "Report failed.": "보고서를 만들지 못했습니다.",
    "Collection failed": "수집에 실패했습니다.",
    "Timeline failed": "타임라인을 만들지 못했습니다.",
    "Import failed": "가져오지 못했습니다.",
    "Fetch failed": "가져오지 못했습니다.",
    "Could not open that device.": "그 장비를 열지 못했습니다.",
    "Could not assign that device.": "그 장비를 배정하지 못했습니다.",
    "Could not rename that customer.": "고객사 이름을 바꾸지 못했습니다.",
    "Could not add that customer.": "고객사를 추가하지 못했습니다.",
    "Could not save the device.": "장비를 저장하지 못했습니다.",
    "Could not apply the CSV to the loaded configuration.":
      "CSV를 지금 불러온 설정에 반영하지 못했습니다.",
    "The server sent no data back, so the CSV was not applied.":
      "서버가 아무 데이터도 보내지 않아 CSV를 반영하지 못했습니다.",
    "Failed to parse config": "설정을 해석하지 못했습니다.",
    "Failed to parse config (network error)": "설정을 해석하지 못했습니다 (네트워크 오류)",
    "Failed to set User IP ranges — classification aborted.":
      "사용자 IP 대역을 저장하지 못해 판정을 중단했습니다.",
    "Failed to save the IP ranges.": "IP 대역을 저장하지 못했습니다.",
    "Select at least one policy to export.": "내보낼 정책을 하나 이상 고르세요.",
    "Enter the device IP and API token.": "장비 IP와 API 토큰을 입력하세요.",
    "Connecting and collecting (config, stats, FQDNs)...":
      "연결해서 수집하는 중입니다 (설정 · 통계 · FQDN)...",
    "Parsing config...": "설정을 해석하는 중...",
    "Reading the dump...": "덤프를 읽는 중...",
    "Fetching FQDN resolutions from the device...": "장비에서 FQDN 해석 결과를 가져오는 중...",
    "Select at least two snapshots (oldest first).":
      "스냅샷을 두 개 이상 고르세요 (오래된 것부터).",
    "Building the timeline...": "타임라인을 만드는 중...",
    "Analysing each device...": "장비별로 분석하는 중...",
    "Sample downloaded. Run the listed commands on your firewall, fill in the last three columns, then upload the sheet back here.":
      "표본을 내려받았습니다. 표에 적힌 명령을 방화벽에서 실행하고 마지막 세 칸을 채운 뒤, 그 파일을 여기에 다시 올리세요.",
    "Scoring...": "채점하는 중...",
    "Classifying...": "판정하는 중...",
    "Classifying... {s}s elapsed": "판정하는 중... {s}초 경과",
    "Large configurations take longer — the shadowed-policy check compares policy pairs.": "설정이 크면 더 걸립니다 — 가려진 정책 검사는 정책들을 서로 비교합니다.",

    "No entries found in that file.": "그 파일에서 아무 항목도 찾지 못했습니다.",
    "Analysing...": "분석하는 중...",
    "Analysis failed": "분석에 실패했습니다",
    "Loading...": "불러오는 중...",
    "Load failed": "불러오지 못했습니다",
    "Applying...": "적용하는 중...",
    "Apply failed": "적용하지 못했습니다",
    "Configuration changed — load the candidates again.":
      "설정이 바뀌었습니다 — 후보를 다시 불러오세요.",
    "Device saved. Run Test Connection to verify.":
      "장비를 저장했습니다. '연결 확인'을 눌러 확인하세요.",

    // ── 데이터 가져오기 · 표 상태 ──────────────────────────────────
    "Now add the usage CSV for {name} — it will be attached to this device only.":
      "이제 {name}의 사용량 CSV를 넣으세요 — 이 장비에만 붙습니다.",
    "Loaded {name}": "{name}을(를) 불러왔습니다",
    "Uploaded {name}": "{name}을(를) 올렸습니다",
    "Download parsed JSON": "파싱 결과 JSON 내려받기",
    "{n} item(s)": "{n}건",
    "{type} Policy CSV applied to {name}: {file}":
      "{type} Policy CSV를 {name}에 반영했습니다: {file}",
    "No IP ranges configured — {u} of {t} policies came out as \"Cannot assess\". Add your ranges and run the assessment again.": "IP 대역이 설정되지 않아 정책 {t}건 중 {u}건이 '판정 불가'로 나왔습니다. 대역을 넣고 점검을 다시 실행하세요.",
    "No IP ranges configured — Severity 1/2/7 can still be assessed":
      "설정된 IP 대역이 없습니다 — 심각도 1 · 2 · 7은 그래도 판정합니다",
    "{n} / {total} selected": "{total}건 중 {n}건 선택",
    "0 / 0 selected": "0건 중 0건 선택",
    "Already Disabled": "이미 비활성",
    "Already inactive in config — no API action needed":
      "설정상 이미 꺼져 있습니다 — API로 할 일이 없습니다",
    "FortiGate Config Backup": "FortiGate 설정 백업",
    "Usage CSV": "사용량 CSV",
    "{n} row(s)": "{n}행",
    "Classification complete — {n} policies processed.":
      "판정을 마쳤습니다 — 정책 {n}건을 처리했습니다.",
    "Not recognised as IP ranges, so they were ignored: {list}":
      "IP 대역으로 인식하지 못해 무시했습니다: {list}",
    "(+{n} more)": "(외 {n}건)",
    "{n} unreachable · assessed {checked}/{total} enabled policies · {skipped} skipped":
      "가려짐 {n}건 · 활성 정책 {total}건 중 {checked}건 검사 · {skipped}건 건너뜀",
    "Never matches traffic — policy {id} above it already handles everything it could match":
      "트래픽과 절대 매칭되지 않습니다 — 위쪽의 {id}번 정책이 이 정책이 받을 수 있는 패킷을 이미 다 가져갑니다",
    " — but this plan also changes policy {id}. Decide that one first; if it is disabled, re-run the assessment before touching this policy.":
      " — 그런데 이 계획은 {id}번 정책도 바꿉니다. 그쪽을 먼저 정하세요. {id}번을 끈다면 이 정책을 손대기 전에 판정을 다시 실행해야 합니다.",

    // ── 빈 상태 ────────────────────────────────────────────────────
    "No dataset loaded": "불러온 데이터가 없습니다",
    "Select a Config File and optionally merge a Policy CSV to begin.":
      "설정 파일을 고르고, 필요하면 정책 CSV를 함께 넣어 시작하세요.",
    "No results": "결과 없음",
    "No policies match the selected criteria on this tab.":
      "이 탭에서 선택한 조건에 맞는 정책이 없습니다.",
    "No assessment yet.": "아직 판정하지 않았습니다.",
    "No comparison result yet.": "아직 비교 결과가 없습니다.",
    "Load a FortiGate config file.": "FortiGate 설정 파일을 올리세요.",
    "Import GUI policy CSV to merge Last Used, Hit Count, and Status.":
      "GUI에서 뽑은 정책 CSV를 넣으면 Last Used · Hit Count · Status가 합쳐집니다.",
    "Upload Firewall Policy CSV or Proxy Policy CSV.":
      "Firewall Policy CSV 또는 Proxy Policy CSV를 올리세요.",
    "Please load a Config file first.": "먼저 설정 파일을 올리세요.",
    "Load a Config File and click Analyze.": "설정 파일을 올린 뒤 '분석'을 누르세요.",
    "Preparing analysis...": "분석을 준비하는 중...",
    "Waiting for files.": "파일을 기다리고 있습니다.",
    "Checking…": "확인 중…",

    // ── 표 필터 · 탭 ───────────────────────────────────────────────
    "Disabled only": "비활성 정책만",
    "Last Used > 1 year": "Last Used 1년 초과",
    "Expired schedule": "스케줄 만료",
    "No ticket ID": "티켓 ID 없음",
    "Removal candidate": "삭제 후보",
    "Search within the current tab...": "현재 탭에서 검색...",
    "CIDR (e.g. 10.99.240.0/21)": "CIDR (예: 10.99.240.0/21)",
    "API access token": "API 액세스 토큰",
    "empty = skip": "비우면 건너뜀",
    "Enter your email": "이메일 주소",

    // ── Findings · 가려진 정책 ─────────────────────────────────────
    "Severity 1/2/7 can be assessed without IP ranges. Adding ranges enables full classification.":
      "심각도 1 · 2 · 7은 IP 대역 없이도 판정합니다. 대역을 넣으면 전체 등급을 판정할 수 있습니다.",
    "A policy is listed here only when a single always-on policy above it provably matches every packet it could match (source, destination, service, and interfaces all contained) — so it never takes effect. Conservative static analysis: policies using geography / ISDB / user objects or negation are skipped, not guessed. Routing and NAT are not considered.":
      "위쪽에 있는 '항상 켜진' 정책 하나가 이 정책이 받을 수 있는 <strong>모든 패킷을 이미 가져간다는 것이 증명될 때만</strong> 여기에 올립니다(출발지 · 목적지 · 서비스 · 인터페이스가 모두 포함되는 경우) — 그래서 이 정책은 한 번도 동작하지 않습니다. 판정은 보수적으로 합니다: 지역(geography) · ISDB · 사용자 객체나 부정 조건을 쓰는 정책은 추측하지 않고 건너뜁니다. 라우팅과 NAT는 고려하지 않습니다.",
    "Include FQDN policies — fetch from connected device":
      "FQDN 정책까지 판정 — 연결된 장비에서 가져오기",
    "If you collected from the device, FQDN resolutions are already included. Otherwise fetch them from a connected device, or upload the output of diagnose test application dnsproxy 6. Either way the results are re-classified automatically and marked \"DNS capture\" (provable as of capture time).":
      "장비에서 수집했다면 FQDN 해석 결과가 이미 들어 있습니다. 아니라면 연결된 장비에서 가져오거나, <code>diagnose test application dnsproxy 6</code> 실행 결과를 올리세요. 어느 쪽이든 자동으로 다시 판정하고 \"DNS capture\"로 표시합니다(수집한 그 시점까지만 증명됩니다).",
    "Active CVEs": "해당 CVE",
    "Fixes Available in Newer Versions": "상위 버전에서 해결된 항목",
    "Known Issues in Current Version": "현재 버전의 알려진 문제",

    // ── 조치 계획: 되돌릴 수 없는 작업 직전의 유일한 경고문 ─────────
    "On multi-VDOM devices, enter the policy's VDOM first (config vdom / edit <name>) before running these commands. Review each change with the policy owner — disabling is reversible, deletion is not.":
      "VDOM이 여러 개인 장비에서는 명령을 실행하기 전에 그 정책이 속한 VDOM으로 먼저 들어가세요(<code>config vdom</code> / <code>edit &lt;name&gt;</code>). 변경은 하나씩 정책 담당자와 확인하세요 — 비활성화는 되돌릴 수 있지만 삭제는 되돌릴 수 없습니다.",
    "Disable, then monitor 30–90 days before removing":
      "먼저 비활성화하고 30~90일 지켜본 뒤 삭제하세요",
    "Review candidate — confirm before removing": "검토 후보 — 삭제 전에 확인하세요",
    "Change Categories": "변경 분류",

    // ── 감사 증적 ──────────────────────────────────────────────────
    "PCI-DSS v4.0 Req 1.2.7 — review NSC configurations at least every six months":
      "PCI-DSS v4.0 Req 1.2.7 — 최소 6개월마다 NSC 설정을 검토할 것",
    "Upload two or more config snapshots (oldest first — FortiGate configs carry no backup timestamp, so the order you provide is the order recorded). APO builds a change timeline between snapshots and exports a Review Evidence workbook: each snapshot's SHA-256, changes per interval, the PCI-DSS citation, and a reviewer sign-off block. Collect snapshots with whatever you already use — Oxidized, FortiManager revisions, manual backups.":
      "설정 스냅샷을 두 개 이상 올리세요(<strong>오래된 것부터</strong> — FortiGate 설정에는 백업 시각이 적혀 있지 않아, 올린 순서를 그대로 기록합니다). APO가 스냅샷 사이의 변경 이력을 만들고 <strong>검토 증적</strong> 워크북으로 내보냅니다: 스냅샷별 SHA-256, 구간별 변경 내역, PCI-DSS 근거 조항, 검토자 서명란. 스냅샷은 지금 쓰는 방법 그대로 모으면 됩니다 — Oxidized, FortiManager 리비전, 수동 백업 무엇이든 좋습니다.",
    "Free — verify APO's calls against your firewall before you trust them":
      "무료 — 판정을 믿기 전에 실제 방화벽과 대조해 보세요",
    "Don't take this report on faith. APO draws a stratified sample across severity levels (up to 50 policies), each with what to check and the exact CLI commands to run on your FortiGate. Fill in what you actually found and whether the call matched, then upload the sheet back — APO computes per-level precision. Held or unfilled rows are excluded from the denominator, never counted as right or wrong.":
      "이 보고서를 그냥 믿지 마세요. APO가 심각도별로 골고루 표본을 뽑아(최대 50건) 정책마다 <strong>무엇을 확인할지</strong>와 FortiGate에서 실행할 <strong>정확한 CLI 명령</strong>을 함께 줍니다. 실제로 확인한 내용과 판정이 맞았는지를 적어 그 표를 다시 올리면, APO가 등급별 정확도를 계산합니다. 보류했거나 비워 둔 행은 분모에서 빠지며, 맞았다고도 틀렸다고도 세지 않습니다.",

    // ── 설정 ──────────────────────────────────────────────────────
    "Not sure what to set? Leave the defaults. They are sensible for most environments (365 days keeps once-a-year jobs like year-end batches from being flagged). These numbers exist as settings because no public standard defines them — they are your organization's audit criteria, not the tool's. Pick a preset or adjust individual values; changes apply the next time you click Classify.":
      "<strong>무엇으로 정할지 모르겠으면 기본값 그대로 두세요.</strong> 대부분의 환경에 무난한 값입니다(365일로 두면 연말 배치처럼 1년에 한 번 도는 작업이 지적되지 않습니다). 이 숫자가 설정으로 있는 이유는 값을 정해 놓은 공개 표준이 없기 때문입니다 — 도구의 기준이 아니라 당신 조직의 감사 기준입니다. 프리셋을 고르거나 값을 직접 조정하세요. 바뀐 값은 다음에 '판정 실행'을 누를 때부터 적용됩니다.",
    "Active profile:": "적용 중인 프로파일:",
    "Report branding (MSP / Consultant license) — exported reports carry your company name on the Summary page.":
      "<strong>보고서 브랜딩</strong> (MSP · 컨설턴트 라이선스) — 내보낸 보고서의 요약 페이지에 자사명이 찍힙니다.",

    // ── 상단 상태바 · 개요 (shell.js) ──────────────────────────────
    "Unnamed device": "이름 없는 장비",
    "{n} policies": "정책 {n}건",
    "Criteria: {name}": "판정 기준: {name}",
    "MSP licence": "MSP 라이선스",
    "Licensed": "라이선스 등록됨",
    "Free": "무료",
    "Could not read the licence state — exports may be locked.":
      "라이선스 상태를 읽지 못했습니다 — 내보내기가 잠겨 있을 수 있습니다.",
    "Active — {email} ({tier})": "사용 중 — {email} ({tier})",
    "No licence — exports are locked, everything else works.":
      "라이선스 없음 — 내보내기만 잠겨 있고 나머지는 모두 됩니다.",
    "MSP / Consultant — report white-labelling enabled":
      "MSP · 컨설턴트 — 보고서 화이트라벨 사용 가능",
    "$199 single organisation · $699 MSP / consultant":
      "$199 단일 조직 · $699 MSP · 컨설턴트",
    "Severity {lv} — {n} policies": "심각도 {lv} — 정책 {n}건",
    "Hit count / last used": "hit count / last used",
    "Loaded for {n} policies, but every policy still came out as 'Cannot assess' — check that the Hit Count column holds counts, not bytes.":
      "정책 {n}건에 들어왔지만 모든 정책이 '판정 불가'로 나왔습니다 — Hit Count 칸에 바이트가 아니라 횟수가 들어 있는지 확인하세요.",
    "Loaded for {n} policies — disuse can be judged.":
      "정책 {n}건에 들어와 있습니다 — 미사용 판정이 가능합니다.",
    "Hit count / last used missing": "hit count / last used 없음",
    "No per-policy usage history is loaded, so no policy can be called unused. Collect from the device or import the policy CSV.":
      "정책별 사용 이력이 없어 어떤 정책도 '미사용'이라고 말할 수 없습니다. 장비에서 수집하거나 정책 CSV를 넣으세요.",
    "User IP ranges not set": "사용자 IP 대역 미설정",
    "{n} range(s) set — server and user traffic can be told apart.":
      "대역 {n}개가 설정돼 있습니다 — 서버 트래픽과 사용자 트래픽을 구분할 수 있습니다.",
    "{n} policies cannot be assessed without knowing which ranges belong to users.":
      "어느 대역이 사용자 것인지 몰라 정책 {n}건을 판정하지 못합니다.",
    "Needed to tell server traffic from user traffic.":
      "서버 트래픽과 사용자 트래픽을 구분하는 데 필요합니다.",
    "Unreachable check coverage": "가려짐 검사 범위",
    "{n} of {total} enabled firewall policies assessed; {skipped} skipped because their objects cannot be resolved offline. Proxy policies are outside this check.":
      "활성 방화벽 정책 {total}건 중 {n}건을 검사했습니다. {skipped}건은 객체를 오프라인에서 환원할 수 없어 건너뛰었습니다. 프록시 정책은 이 검사 대상이 아닙니다.",
    "All {n} enabled firewall policies assessed. Proxy policies are outside this check.":
      "활성 방화벽 정책 {n}건을 모두 검사했습니다. 프록시 정책은 이 검사 대상이 아닙니다.",
    "FQDN resolutions": "FQDN 해석",
    "Captured {when} — FQDN findings are provable as of that time, not indefinitely.":
      "{when}에 수집했습니다 — FQDN 판정은 그 시점까지만 증명되고 그 이후는 보장하지 않습니다.",
    "Fix": "해결하기",
    "{done} of {total} done": "{total}건 중 {done}건 완료",
    "(unnamed)": "(이름 없음)",
    "proof: DNS capture": "근거: DNS 수집분",
    "No command for this action.": "이 조치에는 명령이 없습니다.",
    "Expand menu": "메뉴 펼치기",
    "Collapse menu": "메뉴 접기",
    /* 조치 그룹 설명. 그룹 **이름**(Disable now 등)은 엔진이 내는 조치 라벨이라
       여기 넣지 않는다 — 넣으면 화면과 엑셀이 같은 판정을 다른 말로 부른다.

       **이 사전이 곧 스위치다**(2026-09-10): shell.js 가 `t(g.name)` 로 그리
       므로, 여기 없는 이름은 영어로 남고 여기 있는 이름만 번역된다. 그래서
       엔진 라벨을 여기 추가하면 위 규칙이 조용히 깨진다 — 추가하지 말 것.
       반대로 shell 이 **지어낸** 이름("Decide after the changes above")은
       엑셀에 없으므로 번역해야 하는데, 번역이 사전에 있는데도 `esc(g.name)`
       이라 영어로 나가고 있었다(재비판 3라운드 F7). */
    "Reversible, and stops the risk immediately": "되돌릴 수 있고, 위험은 즉시 멈춥니다",
    "Keep the policy, drop just the risky service":
      "정책은 두고 위험한 서비스만 뺍니다",
    "Turn off, watch 30–90 days, then remove": "끄고 30~90일 지켜본 뒤 삭제합니다",
    "Configuration already prevents any match — confirm, then delete":
      "설정만으로 이미 매칭되지 않습니다 — 확인한 뒤 삭제하세요",
    "Not enough evidence to decide automatically": "자동으로 정하기에는 근거가 부족합니다",
    "Access looks legitimate but has no approval record":
      "접근 자체는 정당해 보이지만 결재 기록이 없습니다",
    "No command — confirm the policy is genuinely unused, then delete it in your change window.":
      "명령 없음 — 이 정책이 정말 쓰이지 않는지 확인한 뒤, 정해진 작업 시간에 삭제하세요.",
    "No command — a person has to decide this one. The reason above says what evidence is missing.":
      "명령 없음 — 이건 사람이 정해야 합니다. 위 사유에 어떤 근거가 없는지 적혀 있습니다.",
    "No command — raise a change record for this access so the next audit has an approval trail.":
      "명령 없음 — 다음 감사 때 결재 흔적이 남도록 이 접근에 대한 변경 기록을 만드세요.",
    "Certain from the configuration alone — this stays true until the rules change":
      "설정만으로 확실합니다 — 규칙이 바뀌기 전까지는 계속 참입니다",
    "Not provable from the configuration alone — the evidence can change over time, so re-check before removing":
      "설정만으로는 증명되지 않습니다 — 근거가 시간이 지나면 달라질 수 있으니 삭제 전에 다시 확인하세요",
    "Decide after the changes above": "위 항목을 정한 뒤에 결정",
    "These are unreachable only while the policies above stay enabled, and this plan changes those. Do the rows above first, take a fresh backup, and run APO again — these may be live by then.":
      "이 정책들은 위 정책이 켜져 있는 동안에만 가려집니다. 그런데 이 계획은 그 위 정책을 바꿉니다. 위 항목을 먼저 처리하고, 백업을 새로 뜬 뒤 APO를 다시 돌리세요 — 그때는 살아 있을 수 있습니다.",

    // ── 장비 등록 마법사 ───────────────────────────────────────────
    "Upload the device's full configuration (.conf / .txt). This registers the device — everything you add after this is attached to it.":
      "장비의 전체 설정을 올리세요(<code>.conf</code> / <code>.txt</code>). 이걸로 장비가 등록되고, 이후에 넣는 자료는 모두 이 장비에 붙습니다.",
    "Adds hit count / last used per firewall policy. Without it no policy can be called unused — severity 1/2/7 still work, the disuse axis does not.":
      "방화벽 정책별 <strong>hit count / last used</strong>가 들어옵니다. 이게 없으면 어떤 정책도 '미사용'이라고 말할 수 없습니다 — 심각도 1 · 2 · 7은 그대로 판정되지만 미사용 축은 판정되지 않습니다.",
    "FortiGate GUI → Policy & Objects → Firewall Policy → right-click the column header → Export to CSV.":
      "FortiGate GUI → Policy &amp; Objects → Firewall Policy → 컬럼 머리글에서 오른쪽 클릭 → <em>Export to CSV</em>.",
    "Only for devices that use proxy policies. If this device has none, just click Next — nothing is lost.":
      "프록시 정책을 쓰는 장비만 해당합니다. <strong>이 장비에 프록시 정책이 없으면 그냥 '다음'을 누르세요</strong> — 빠지는 것은 없습니다.",
    "One per line. CIDR (10.10.0.0/16), device notation (10.10.0.0 255.255.0.0), a range (10.0.0.1-10.0.0.100) or a single IP all work. A trailing label and # comments are fine.":
      "한 줄에 하나씩 적습니다. CIDR(<code>10.10.0.0/16</code>), 넷마스크 표기(<code>10.10.0.0 255.255.0.0</code>), 범위(<code>10.0.0.1-10.0.0.100</code>), 단일 IP 모두 됩니다. 뒤에 붙인 라벨과 <code>#</code> 주석은 그대로 두어도 됩니다.",
    "These ranges are saved with this device. Another device you register keeps its own — a head office and a branch rarely share the same user segments.":
      "이 대역은 이 장비에 저장됩니다. 다른 장비를 등록하면 그 장비는 자기 대역을 따로 갖습니다 — 본사와 지사가 같은 사용자 대역을 쓰는 경우는 드뭅니다.",
    "Lets policies that use FQDN address objects be judged. Findings from this are marked DNS capture — provable as of capture time, not indefinitely.":
      "FQDN 주소 객체를 쓰는 정책까지 판정할 수 있게 됩니다. 이걸로 나온 판정에는 <em>DNS capture</em> 표시가 붙습니다 — 수집한 그 시점까지만 증명되고 그 이후는 보장하지 않습니다.",
    "Don't have it yet? Save & close keeps what you entered so you can come back after collecting it.":
      "아직 없나요? <strong>임시 저장하고 닫기</strong>를 누르면 지금까지 입력한 것이 남아 있어, 자료를 모은 뒤 이어서 할 수 있습니다.",

    // ── 구매 모달 (판매 지점 — 여기가 영어면 번역이 끝난 것처럼 보인다) ──
    "Export License Required": "내보내기 라이선스가 필요합니다",
    "Have a license key?": "라이선스 키가 있으신가요?",
    "or": "또는",
    "Don't have a license yet?": "아직 라이선스가 없으신가요?",
    "Audit the firewalls of one organisation": "한 조직의 방화벽을 점검합니다",
    "All exports: Excel audit workbook, action plan, evidence":
      "모든 내보내기: 엑셀 감사 워크북, 조치 계획, 검토 증적",
    "1 year of updates, then keep using the version you bought":
      "1년간 업데이트 제공 — 이후에도 구매한 버전은 계속 쓸 수 있습니다",
    "Everything in Single organisation": "단일 조직의 모든 기능 포함",
    "Use across all your client organisations": "<strong>담당하는 모든 고객사에서 사용</strong>",
    "Batch report — analyse many devices in one run, one workbook each":
      "<strong>일괄 보고</strong> — 여러 장비를 한 번에 분석하고 장비마다 워크북 하나",
    "White-label reports — your company name on the workbook":
      "<strong>화이트라벨 보고서</strong> — 워크북에 자사명 표기",
    "Checkout opens in a new tab; your licence key is emailed after purchase.One-time purchase · Air-gapped network support · Everything except exporting is free forever.":
      "결제 창은 새 탭에서 열리고, 구매하면 라이선스 키가 메일로 갑니다.<br>1회 구매 · 폐쇄망 지원 · 내보내기를 뺀 모든 기능은 계속 무료입니다.",

    // ── 판정 기준 표 ───────────────────────────────────────────────
    // Action 칸(Keep · Disable now …)은 엔진이 내는 조치 라벨이라 번역하지
    // 않는다. Risk Level 칸도 Findings 화면의 등급 칩과 같은 어휘를 쓴다.
    "① Action = Deny② ICMP-only service (Ping, etc.)③ Valid change ticket (ticket ID present + schedule not expired)④ Policy name contains \"controlled\" (multi-firewall passthrough)⑤ Policy matches a configured admin object and carries no risky service":
      "① Action = Deny<br>② ICMP만 허용하는 서비스(Ping 등)<br>③ 유효한 변경 티켓(티켓 ID가 있고 스케줄이 만료되지 않음)<br>④ 정책 이름에 \"controlled\" 포함(방화벽 여러 대를 지나는 정책)<br>⑤ 설정해 둔 admin 객체와 일치하고 <em>위험 서비스가 없음</em>",
    "Two different meanings share this rating — see the Action to Take column. No risk means assessed and found fine (deny, ICMP-only). Not assessed (exempted) means an exception rule stopped the assessment; it does not mean the policy is safe. An admin policy that still permits a risky service is rated 3, not 7":
      "같은 등급에 뜻이 두 가지 섞여 있습니다 — <strong>Action to Take</strong> 칸을 보세요. <em>No risk</em>는 판정했더니 문제가 없다는 뜻입니다(deny, ICMP 전용). <em>Not assessed (exempted)</em>는 예외 규칙 때문에 판정을 멈췄다는 뜻이며, 그 정책이 안전하다는 말이 아닙니다. admin 정책이라도 위험 서비스를 열어 두었다면 7이 아니라 3입니다",
    "① Source, destination, and service are all Any/All② Source or destination Any/All + Hit Count = 0③ Source or destination Any/All + Hit Count > 0 but Last Used ≥ 1 year④ Risky service only (FTP, TELNET, TFTP, RLOGIN, RSH)⑤ Risky + normal service mixed + Hit Count = 0 or Last Used ≥ 1 year⑥ Temp keyword in name (temp, etc.) + no ticket ID + Hit Count = 0⑦ Service ALL + Hit Count = 0 or Last Used ≥ 1 year":
      "① 출발지 · 목적지 · 서비스가 <strong>모두</strong> Any/All<br>② 출발지 또는 목적지가 Any/All + Hit Count = 0<br>③ 출발지 또는 목적지가 Any/All + Hit Count &gt; 0 이지만 Last Used 1년 이상<br>④ <strong>위험 서비스만</strong> 허용(FTP, TELNET, TFTP, RLOGIN, RSH)<br>⑤ 위험 서비스와 일반 서비스가 <strong>섞임</strong> + Hit Count = 0 또는 Last Used 1년 이상<br>⑥ 이름에 임시 키워드(temp 등) + 티켓 ID 없음 + Hit Count = 0<br>⑦ Service ALL + Hit Count = 0 또는 Last Used 1년 이상",
    "① Status = Disabled② Schedule expired (YYMMDD date is in the past)③ Hit=0 + Accept + Server↔User + registered ≥ 1 year ago④ Hit=0 + Accept + Server - Server + always schedule + > 1 year":
      "① Status = Disabled<br>② 스케줄 만료(이름의 YYMMDD 날짜가 지남)<br>③ Hit=0 + Accept + Server↔User + 등록 후 1년 이상<br>④ Hit=0 + Accept + Server - Server + always 스케줄 + 1년 초과",
    "Confirm with the policy owner before removing. Already-disabled and expired policies are removal candidates; live but unused policies should be disabled and observed first":
      "삭제 전에 정책 담당자와 확인하세요. 이미 비활성이거나 스케줄이 만료된 정책은 삭제 후보이고, 살아 있지만 쓰이지 않는 정책은 먼저 비활성화해 지켜보는 것이 좋습니다",
    "① Server - User + registered > 1 year + Hit < elapsed years×100 + Last Used ≥ 1 year② Risky + normal service mixed + actively used (within 1 year)③ Source/Destination Any·All + active use (within 1yr) + Server - User④ Service ALL + active use (within 1yr) + Server - User":
      "① Server - User + 등록 후 1년 초과 + Hit &lt; 경과 연수×100 + <strong>Last Used 1년 이상</strong><br>② 위험 서비스와 일반 서비스가 <strong>섞임</strong> + <strong>최근 1년 안에 실제 사용</strong><br>③ 출발지/목적지 Any · All + 최근 1년 안에 사용 + Server - User<br>④ Service ALL + 최근 1년 안에 사용 + Server - User",
    "② Mixed risky policy: do NOT delete the entire rule — remove only the risky service/port, keep normal services":
      "② 위험 서비스가 섞인 정책: 규칙 전체를 삭제하지 마세요 — <strong>위험한 서비스 · 포트만 빼고</strong> 일반 서비스는 남깁니다",
    "① Server - Server + registered > 2 years + Hit < 50② Server - Server + registration date unknown③ Source/Destination Any·All + active use (within 1yr) + Server - Server④ Service ALL + active use (within 1yr) + Server - Server":
      "① Server - Server + 등록 후 2년 초과 + Hit &lt; 50<br>② Server - Server + 등록일 미상<br>③ 출발지/목적지 Any · All + 최근 1년 안에 사용 + Server - Server<br>④ Service ALL + 최근 1년 안에 사용 + Server - Server",
    "For active Any/All policies, recommend narrowing scope instead of immediate disable":
      "Any/All을 쓰지만 실제로 사용 중인 정책은 바로 끄기보다 범위를 좁히도록 권고합니다",
    "① Server - User + registered < 1 year + no ticket ID② Server - User + registered > 1 year + insufficient hits + Last Used < 1 year (recently active but not formally registered)③ Service ALL + active use (within 1yr) + Server - User":
      "① Server - User + 등록 후 1년 미만 + 티켓 ID 없음<br>② Server - User + 등록 후 1년 초과 + 히트 수 부족 + <strong>Last Used 1년 미만</strong>(최근에 쓰이지만 정식 등록 기록이 없음)<br>③ Service ALL + 최근 1년 안에 사용 + Server - User",
    "Keep the policy, but raise a change ticket so the access has an approval record":
      "정책은 그대로 두되, 그 접근에 결재 기록이 남도록 변경 티켓을 만드세요",
    "① AD/DNS/LDAP authentication service + Hit > 0② Server - Server + within 2 years + no ticket ID③ Server - Server + Hit ≥ 50④ A configured infrastructure or management object is included":
      "① AD/DNS/LDAP 인증 서비스 + Hit &gt; 0<br>② Server - Server + 2년 이내 + 티켓 ID 없음<br>③ Server - Server + Hit ≥ 50<br>④ 설정해 둔 인프라 또는 관리 객체가 포함됨",
    "※ Without User IP ranges configured, traffic type (Server/User) cannot be determined — Severity 1, 2, and 7 can still be assessed without IP ranges":
      "※ 사용자 IP 대역을 설정하지 않으면 트래픽 종류(Server/User)를 구분할 수 없습니다 — <strong>심각도 1 · 2 · 7은 IP 대역 없이도 판정합니다</strong>",
    "※ The periods written in this table are the default thresholds. The line above shows what this session actually uses, and each policy's Reason column shows the threshold applied to that policy.":
      "※ 이 표에 적힌 기간은 <strong>기본 임계값</strong>입니다. 지금 실제로 쓰는 값은 바로 위 줄에 있고, 정책마다 Reason 칸에 그 정책에 적용된 임계값이 적힙니다.",

    // ── 푸터 ──────────────────────────────────────────────────────
    "This software is proprietary and licensed for use by authorized users only. Unauthorized reproduction, redistribution, or reverse engineering is strictly prohibited. All configuration data is processed locally on your device and is never transmitted to external servers. Analysis results are provided for operational reference only — all policy decisions and resulting network changes are the sole responsibility of the user.":
      "이 소프트웨어는 독점 소프트웨어이며 허가받은 사용자만 사용할 수 있습니다. 무단 복제 · 재배포 · 역공학을 금합니다. 모든 설정 데이터는 이 컴퓨터 안에서만 처리되며 외부 서버로 전송되지 않습니다. 분석 결과는 운영 참고용이며, 정책 결정과 그로 인한 네트워크 변경의 책임은 전적으로 사용자에게 있습니다.",
  };

  const DICTS = { ko: KO, en: {} };
  const KEY = "apo.lang";

  function currentLang() {
    /* **저장된 선택이 없으면 브라우저 언어를 따른다.** 기본이 "en" 이라
       한국 고객이 처음 켜면 첫 화면부터 영어였고, 전환은 설정 → 언어 안에
       묻혀 있었다(데모 리허설 D-1). 사용자가 한 번이라도 고르면 그 선택이
       이긴다 — 저장값을 먼저 본다. */
    try {
      const saved = localStorage.getItem(KEY);
      if (saved) return saved;
    } catch (_) { /* 저장소가 막힌 환경 — 아래 로케일 판단으로 간다 */ }
    try {
      const nav = (navigator.language || navigator.userLanguage || "");
      if (nav.toLowerCase().startsWith("ko")) return "ko";
    } catch (_) { /* 무시 */ }
    return "en";
  }

  function apply(lang) {
    const dict = DICTS[lang] || {};
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      // 원문을 한 번만 보관한다. 이게 없으면 한→영 복귀 때 되돌릴 원본이 없다.
      if (el.dataset.i18nSrc === undefined) {
        el.dataset.i18nSrc = el.textContent.replace(/\s+/g, " ").trim();
      }
      /* **코드가 그 사이에 다른 문장을 써 넣었으면 건드리지 않는다.**
         상태 문구(#configStatus·#setLicenseState…)에는 마크업의 초기 안내문이
         적혀 있고 그걸 번역해야 첫 화면이 한국어가 되지만, 언어를 바꿨다고
         지금 표시 중인 결과가 초기 안내문으로 되돌아가면 화면이 거짓말을 한다.
         직전에 우리가 써 넣은 값과 다르면 주인이 바뀐 것이므로 비켜선다. */
      if (el.dataset.i18nOut !== undefined && el.textContent !== el.dataset.i18nOut) return;
      const src = el.dataset.i18nSrc;
      const out = dict[src] || src;
      el.textContent = out;
      el.dataset.i18nOut = out;
    });
    /* 자식 태그(<br>·<strong>·<code>)를 품은 문단. textContent 를 갈아 끼우면
       그 자식이 조용히 사라지므로 innerHTML 을 통째로 바꾼다. 키는 여전히
       영어 원문(공백 정규화한 textContent)이고, 값에만 마크업이 들어간다.
       값의 출처는 이 파일뿐이라 사용자 입력이 섞이는 경로가 아니다. */
    document.querySelectorAll("[data-i18n-rich]").forEach((el) => {
      if (el.dataset.i18nRichSrc === undefined) {
        el.dataset.i18nRichSrc = el.innerHTML;
        el.dataset.i18nRichKey = el.textContent.replace(/\s+/g, " ").trim();
      }
      if (el.dataset.i18nRichOut !== undefined
          && el.innerHTML !== el.dataset.i18nRichOut) return;
      const out = dict[el.dataset.i18nRichKey] || el.dataset.i18nRichSrc;
      el.innerHTML = out;
      el.dataset.i18nRichOut = el.innerHTML;
    });
    /* 입력칸 안내(placeholder). 화면에 보이는 문장인데 textContent 가 아니라
       속성이라 위 두 통로가 닿지 않는다. */
    document.querySelectorAll("[data-i18n-ph]").forEach((el) => {
      if (el.dataset.i18nPhSrc === undefined) {
        el.dataset.i18nPhSrc = el.getAttribute("placeholder") || "";
      }
      const src = el.dataset.i18nPhSrc;
      el.setAttribute("placeholder", dict[src] || src);
    });
    /* **값이 낀 한 줄** — "Loaded {name}", "{n} item(s)" 처럼 코드가 값과 함께
       써 넣은 문장. 위 세 통로는 HTML 에 원문이 있던 요소만 덮으므로 여기엔
       닿지 않고, 그려진 뒤로는 아무도 다시 안 그려 언어를 바꿔도 영어로
       남았다(실측: 전환 후 21곳). 원소에 **키와 값을 적어 두면** 언제든 다시
       만들 수 있다 — 화면 쪽에서는 `apoSetText(el, key, vars)` 로 쓴다. */
    document.querySelectorAll("[data-i18n-key]").forEach((el) => {
      /* **주인이 바뀌었으면 비켜선다** — 위 세 통로가 이미 지키는 규칙인데
         이 통로만 빠져 있었다. `apoSetText` 로 쓴 뒤 다른 코드가 평범한
         `textContent =` 로 덮어쓰는 곳이 40군데 있어, 언어를 바꾸면 그 새
         문장이 **옛 문장으로 되돌아갔다**(라운드 45 실측): 판정 실패가
         "판정하는 중..."으로 되살아나고, 다른 장비 CSV 경고가 통째로
         사라졌다. 되돌리는 것은 번역 안 되는 것보다 훨씬 나쁘다 — 화면이
         거짓을 말하게 된다. */
      if (el.dataset.i18nKeyOut !== undefined
          && el.textContent !== el.dataset.i18nKeyOut) {
        delete el.dataset.i18nKey;
        delete el.dataset.i18nVars;
        delete el.dataset.i18nKeyOut;
        return;
      }
      let vars = {};
      try { vars = JSON.parse(el.dataset.i18nVars || "{}"); } catch (_) {}
      el.textContent = t(el.dataset.i18nKey, vars);
      el.dataset.i18nKeyOut = el.textContent;
    });
    document.documentElement.lang = lang;
    const sel = document.getElementById("setLangSelect");
    if (sel && sel.value !== lang) sel.value = lang;
    /* data-i18n 은 HTML 에 이미 있는 요소만 덮는다. 코드가 만들어 낸 문장
       (개요 카드·상태줄·표)은 다시 그려야 바뀌므로 신호를 보낸다 — 없으면
       한국어로 바꿔도 이미 그려진 화면은 영어로 남는다. */
    document.dispatchEvent(new CustomEvent("apo:lang-changed", {
      detail: { lang } }));
  }

  function setLang(lang) {
    try { localStorage.setItem(KEY, lang); } catch (_) {}
    apply(lang);
  }

  document.addEventListener("DOMContentLoaded", () => {
    apply(currentLang());
    document.getElementById("setLangSelect")
      ?.addEventListener("change", (e) => setLang(e.target.value));
  });
  // DOMContentLoaded를 이미 지났으면 바로 적용한다(스크립트 순서 변경 대비).
  if (document.readyState !== "loading") apply(currentLang());

  /* 자바스크립트가 만드는 문구를 위한 통로. data-i18n은 HTML에 이미 있는
     요소만 덮으므로, 목록·상태줄·확인 대화처럼 코드가 만들어 내는 문장은
     이 함수를 지나야 번역된다. 사전에 없으면 원문 그대로 — 한국어 모드에서
     영어가 보일지언정 문장이 사라지지는 않는다. */
  function t(text, vars) {
    const src = String(text == null ? "" : text).replace(/\s+/g, " ").trim();
    let out = (DICTS[currentLang()] || {})[src] || src;
    if (vars) {
      Object.keys(vars).forEach((k) => {
        out = out.split(`{${k}}`).join(String(vars[k]));
      });
    }
    return out;
  }

  /* 값이 낀 한 줄을 **다시 만들 수 있는 형태로** 써 넣는다. `el.textContent =
     apoT(...)` 와 보이는 결과는 같지만, 키와 값이 원소에 남아 언어가 바뀌면
     위 네 번째 통로가 그대로 다시 만든다. */
  function setText(el, key, vars) {
    if (!el) return el;
    /* 값은 **쓸 때 문자열로 굳힌다.** `t()` 는 어떤 값이든 String() 으로
       찍지만 JSON 왕복은 그렇지 않다 — `undefined` 는 키째 사라지고
       (`{detail: undefined}` → `"{}"`), 언어를 바꾸면 치환할 값이 없어
       `"불러오지 못했습니다: {detail}"` 처럼 **자리표시자 원문이 사용자에게
       보인다**(라운드 45 실측). NaN 은 null 로 바뀌는 것도 같은 부류. */
    let safe;
    if (vars) {
      safe = {};
      Object.keys(vars).forEach((k) => { safe[k] = String(vars[k]); });
    }
    el.dataset.i18nKey = String(key == null ? "" : key);
    if (safe && Object.keys(safe).length) {
      el.dataset.i18nVars = JSON.stringify(safe);
    } else {
      delete el.dataset.i18nVars;
    }
    el.textContent = t(key, safe);
    el.dataset.i18nKeyOut = el.textContent;
    return el;
  }

  window.APO_I18N = { apply, setLang, currentLang, t, setText };
})();
