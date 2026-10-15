let currentParsed = null;
let currentView = null;
let currentRuntimeStats = {};
let activeTab = 'firewall_policy';

const configFileInput = document.getElementById('configFile');
const configPickerBtn = document.getElementById('configPickerBtn');
const selectedConfigName = document.getElementById('selectedConfigName');
const configStatus = document.getElementById('configStatus');
const policyStatsStatus = document.getElementById('policyStatsStatus');
const policyCsvSummary = document.getElementById('policyCsvSummary');

const fwCsvPickerBtn = document.getElementById('fwCsvPickerBtn');
const fwPolicyCsvFile = document.getElementById('fwPolicyCsvFile');
const selectedFwCsvName = document.getElementById('selectedFwCsvName');

const proxyCsvPickerBtn = document.getElementById('proxyCsvPickerBtn');
const proxyPolicyCsvFile = document.getElementById('proxyPolicyCsvFile');
const selectedProxyCsvName = document.getElementById('selectedProxyCsvName');

let fwCsvSummary = null;
let proxyCsvSummary = null;
const tabContent = document.getElementById('tabContent');
const downloadBox = document.getElementById('downloadBox');
const metaBox = document.getElementById('metaBox');
const tableFilter = document.getElementById('tableFilter');
const tabCount = document.getElementById('tabCount');
const downloadCsvBtn = document.getElementById('downloadCsvBtn');
const downloadWorkbookBtn = document.getElementById('downloadWorkbookBtn');
const policyOnlyFilters = document.getElementById('policyOnlyFilters');
const filterDisabled = document.getElementById('filterDisabled');
const filterHitZero = document.getElementById('filterHitZero');
const filterDormantYear = document.getElementById('filterDormantYear');
const filterExpiredSchedule = document.getElementById('filterExpiredSchedule');
const filterNoItsRequest = document.getElementById('filterNoItsRequest');
const filterDeletable = document.getElementById('filterDeletable');

function hasNoName(item) {
  return !String(item.name || '').trim();
}

// 티켓 ID는 서버가 설정된 티켓 형식(설정 화면 > 프로파일)으로 추출해
// item.ritm에 넣어준다. 여기서 특정 고객사 접두어를 하드코딩하면 다른
// 고객 환경에서 이 필터가 항상 참이 되어 결과가 왜곡된다.
function hasNoRitm(item) {
  /* **읽지 않은 것을 '없다'로 세지 않는다.** 티켓 형식이 설정되지 않으면
     추출 자체를 건너뛰므로 ritm 이 전부 비어 있다 — 그대로 두면 이 필터가
     모든 정책을 "티켓 없음"으로 골라내, 라벨이 약속한 것과 다른 것을
     보여준다. 판정 태그가 'No Ticket'과 'Ticket unchecked'를 가른 것과
     같은 규칙이다. */
  if (item.ticket_scanned === false) return false;
  return !String(item.ritm || '').trim();
}

const TAB_DEFS = {
  firewall_policy: {
    sheet: 'Firewall Policy',
    filename: 'firewall_policy',
    columns: [
      ['Policy ID', i => i.policy_id ?? ''],
      ['Name', i => i.name || ''],
      ['Status', i => i.status || ''],
      ['Source Interface', i => joinList(i.srcintf_display)],
      ['Destination Interface', i => joinList(i.dstintf_display)],
      ['Source Address', i => joinList(i.srcaddr_display)],
      ['Destination Address', i => joinList(i.dstaddr_display)],
      ['Service', i => joinList(i.service_display)],
      ['Schedule', i => i.schedule || ''],
      ['Action', i => i.action || ''],
      ['Hit Count', i => i.hit_count ?? '-'],
      ['Last Used', i => i.last_used || '-'],
    ],
  },
  firewall_proxy_policy: {
    sheet: 'Firewall Proxy Policy',
    filename: 'firewall_proxy_policy',
    columns: [
      ['Policy ID', i => i.policy_id ?? ''],
      ['Name', i => i.name || ''],
      ['Status', i => i.status || ''],
      ['Source Interface', i => joinList(i.srcintf_display)],
      ['Destination Interface', i => joinList(i.dstintf_display)],
      ['Source Address', i => joinList(i.srcaddr_display)],
      ['Destination Address', i => joinList(i.dstaddr_display)],
      ['Service', i => joinList(i.service_display)],
      ['Schedule', i => i.schedule || ''],
      ['Action', i => i.action || ''],
      ['Hit Count', i => i.hit_count ?? '-'],
      ['Last Used', i => i.last_used || '-'],
    ],
  },
  firewall_multicast_policy: {
    sheet: 'Multicast Policy',
    filename: 'firewall_multicast_policy',
    columns: [
      ['Policy ID', i => i.policy_id ?? ''],
      ['Name', i => i.name || ''],
      ['Source Interface', i => joinList(i.srcintf_display)],
      ['Destination Interface', i => joinList(i.dstintf_display)],
      ['Source Address', i => joinList(i.srcaddr_display)],
      ['Destination Address', i => joinList(i.dstaddr_display)],
      ['Action', i => i.action || ''],
      ['Status', i => i.status || ''],
      ['Schedule', i => i.schedule || ''],
      ['Comment', i => i.comment || ''],
    ],
  },
  firewall_address: {
    sheet: 'Firewall Address',
    filename: 'firewall_address',
    columns: [
      ['Name', i => i.name || ''],
      ['Type', i => i.type || ''],
      ['Resolved', i => i.resolved || ''],
      ['Comment', i => i.comment || ''],
    ],
  },
  firewall_addrgrp: {
    sheet: 'Firewall AddrGrp',
    filename: 'firewall_addrgrp',
    columns: [
      ['Name', i => i.name || ''],
      ['Members', i => joinList(i.member)],
      ['Resolved Members', i => joinList(i.resolved_members)],
      ['Comment', i => i.comment || ''],
    ],
  },
  firewall_proxy_address: {
    sheet: 'Proxy Address',
    filename: 'firewall_proxy_address',
    columns: [
      ['Name', i => i.name || ''],
      ['Type', i => i.type || ''],
      ['Resolved', i => i.resolved || ''],
      ['Comment', i => i.comment || ''],
    ],
  },
  firewall_proxy_addrgrp: {
    sheet: 'Proxy AddrGrp',
    filename: 'firewall_proxy_addrgrp',
    columns: [
      ['Name', i => i.name || ''],
      ['Members', i => joinList(i.member)],
      ['Resolved Members', i => joinList(i.resolved_members)],
      ['Comment', i => i.comment || ''],
    ],
  },
  firewall_service_custom: {
    sheet: 'Service Custom',
    filename: 'firewall_service_custom',
    columns: [
      ['Name', i => i.name || ''],
      ['Protocol', i => i.protocol || ''],
      ['TCP Port Range', i => i['tcp-portrange'] || ''],
      ['UDP Port Range', i => i['udp-portrange'] || ''],
      ['SCTP Port Range', i => i['sctp-portrange'] || ''],
      ['Resolved', i => i.resolved || ''],
      ['Category', i => i.category || ''],
      ['Comment', i => i.comment || ''],
    ],
  },
  firewall_service_group: {
    sheet: 'Service Group',
    filename: 'firewall_service_group',
    columns: [
      ['Name', i => i.name || ''],
      ['Members', i => joinList(i.member)],
      ['Resolved Members', i => joinList(i.resolved_members)],
      ['Comment', i => i.comment || ''],
    ],
  },
  system_interface: {
    sheet: 'Interface',
    filename: 'system_interface',
    columns: [
      ['Port', i => i.port || ''],
      ['Display Name', i => i.display_name || i.port || ''],
      ['Alias', i => i.alias || ''],
      ['Type', i => i.type || ''],
      ['IP', i => i.ip || ''],
      ['Role', i => i.role || ''],
    ],
  },
};

const ALL_TABS = Object.keys(TAB_DEFS);

function isPolicyTab(tab) {
  return tab === 'firewall_policy' || tab === 'firewall_proxy_policy';
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(x => x.classList.remove('active'));
    btn.classList.add('active');
    activeTab = btn.dataset.tab;
    updatePolicyFilterVisibility();
    renderActiveTab();
  });
});

[
  tableFilter,
  filterDisabled,
  filterHitZero,
  filterDormantYear,
  filterExpiredSchedule,
  filterNoItsRequest,
  filterDeletable,
].forEach(el => {
  el.addEventListener('input', renderActiveTab);
  el.addEventListener('change', renderActiveTab);
});

configPickerBtn.addEventListener('click', () => configFileInput.click());
fwCsvPickerBtn.addEventListener('click', () => fwPolicyCsvFile.click());
proxyCsvPickerBtn.addEventListener('click', () => proxyPolicyCsvFile.click());

/* ── 장비 프로파일 ────────────────────────────────────────────────────
   설정 파일 등록 = 장비 등록이다. CSV는 그 장비에만 붙는다.
   새 설정 파일을 고르는 순간 CSV 단계가 다시 잠기고 이전 장비의 CSV 표시도
   지워진다 — 그래야 1번 장비 config에 2번 장비 CSV가 얹히지 않는다. */
let currentDeviceId = null;
let currentDeviceName = '';

/* 코드가 만드는 문장의 번역 통로(모듈 전역). data-i18n은 HTML에 적힌 원문만
   덮으므로, 확인 대화·경고처럼 코드가 조립하는 문장은 여기를 지나야 한다. */
const apoT = (s, v) => (window.APO_I18N?.t ? window.APO_I18N.t(s, v) : s);

/* 화면에 **남아 있을** 한 줄은 이걸로 쓴다 — `el.textContent = apoT(...)` 는
   그 순간만 맞고, 나중에 언어를 바꾸면 영어로 남는다(아무도 다시 안 그리므로).
   이건 키와 값을 원소에 적어 두어 언어 전환이 스스로 다시 만들게 한다. */
const apoSetText = (el, s, v) => (window.APO_I18N?.setText
  ? window.APO_I18N.setText(el, s, v)
  : (el && (el.textContent = apoT(s, v)), el));

/* 코드가 **표·패널로** 그린 것은 다시 그려야 언어가 바뀐다. 그리는 함수는
   화면마다 다른 클로저 안에 있으므로, 각자 여기에 자기를 등록한다 — 등록을
   빠뜨린 화면은 영어로 남으므로, 새 화면을 만들면 한 줄 추가하는 것이 규칙.
   그리기가 실패해도(아직 데이터 없음) 다른 화면의 다시 그리기를 막지 않는다. */
function onLangChange(redraw) {
  document.addEventListener('apo:lang-changed', () => {
    try { redraw(); } catch (_) { /* 아직 그릴 것이 없는 화면 */ }
  });
}

/* ── 서버가 낸 거절 사유 → 화면 문장 ────────────────────────────────────
   **돈 낸 사람이 막혔을 때 읽는 문장이 여기다.** 서버 문자열은 사전에 닿지
   않으므로 두 통로를 쓴다:
     · 값이 끼어드는 문장 — 서버가 `error_key` 와 값만 보내고, 영어 원문은
       아래 표가 만든다. 그 원문이 사전 키다.
     · 값이 없는 문장 — 영어 원문 자체가 사전 키다. 그대로 apoT 를 지난다.
   사전에 없으면 원문이 그대로 남는다(문장이 사라지지는 않는다). */
const SERVER_ERRORS = {
  migration_bad_mapping:
    'The mapping table has an entry APO cannot read: {detail}. Each row needs an existing address and a valid IPv4 address to replace it with — leave the new value blank only if that address is being retired.',
  vdom_ambiguous:
    'This configuration has more than one VDOM ({vdoms}), and policy numbers '
    + "start again at 1 in each one. APO cannot tell which VDOM's policy you "
    + 'picked, so it will not write to the firewall. Upload the configuration '
    + 'of a single VDOM, or apply these changes on the device.',
  no_sample_token:
    'This sheet has no 표본 ID column, so APO cannot tell which device it was '
    + 'made for. Download a fresh sample for the device you have open and '
    + 'enter the results in that file.',
  sample_token_other_device:
    "The 표본 ID in this sheet was not issued for the device you have open "
    + "('{open}'). Open the device this sample was made for, or download a "
    + 'fresh sample.',
  /* **'다른 장비' 와 '칸이 상했다' 는 다른 문제다.** 엑셀이 VDOM 칸을
     대문자로 바꾼 것뿐인데 "그 표본을 만든 장비를 여세요" 라고 안내해,
     현장에서 하루를 들여 채운 50행이 통째로 버려졌다(라운드 48). */
  /* 사용자 대역을 안 넣으면 정책 전부가 '판정할 수 없음'이라 검증할 것이
     없다. 빈 표를 내려 주는 대신 무엇을 하면 되는지 말한다(라운드 48). */
  /* 다중 VDOM 에서 사용량 CSV 는 한 VDOM 것이다 — 어느 것인지 물어본다.
     안 물으면 측정한 적 없는 정책이 '미사용'으로 인쇄된다(라운드 49). */
  usage_csv_vdom_required:
    'This configuration has more than one VDOM ({vdoms}), and policy numbers '
    + 'start again at 1 in each one. Tell APO which VDOM this export came from '
    + '— otherwise its hit counts would be applied to same-numbered policies in '
    + 'the other VDOMs, which were never measured.',
  usage_csv_vdom_unknown:
    "'{vdom}' is not a VDOM in this configuration. It has: {vdoms}.",
  /* 지정 VDOM 의 정책과 하나도 안 맞는 CSV — 매칭은 판정과 같은 모집단을
     본다(라운드 59). */
  usage_csv_no_match_in_vdom:
    "None of the policy IDs in this file exist in VDOM '{vdom}' of the "
    + 'loaded configuration. This usually means the CSV came from a '
    + 'different device or a different VDOM — nothing was imported.',
  sample_all_ungraded:
    'All {n} policies came out as severity 0 ("Cannot assess") because APO does '
    + 'not know which IP ranges are user networks, so there is nothing to verify '
    + 'yet. Set the User IP ranges first, then download the sample.',
  sample_no_policies:
    'This configuration has no policies to verify.',
  sample_row_keys_damaged:
    "This sample was issued for the device you have open ('{open}'), but the "
    + 'VDOM / policy type / policy ID columns no longer match what APO issued, '
    + 'so APO cannot tell which policy each row is about. Those three columns '
    + 'are filled in by APO — restore them (or download a fresh sample and copy '
    + 'your verdicts across). Your verdicts are still valid.',
  file_too_large:
    'That file is too large. The limit is {limit} MB per upload.',
  csv_no_usage_rows:
    'No hit count / last used rows were recognised in {files}. Export the '
    + 'policy list from the device (Policy & Objects, right-click the column '
    + 'header, Export to CSV) and pick that file.',
  remediation_serial_missing:
    "APO confirmed this firewall earlier as serial '{expected}', but the "
    + 'device answering at {ip} does not report a serial, so it cannot be '
    + 'checked against that. Use the address you confirmed before.',
  /* 위와 판정은 같다(보내지 않는다). 다른 것은 **사실** 하나뿐 — 장비가 안
     준 것이 아니라 이번 조회가 끝나지 못했다. 재시도 안내가 붙는다(R75-1). */
  remediation_serial_unread:
    "APO confirmed this firewall earlier as serial '{expected}', but it could "
    + 'not read the serial from {ip} this time, so it cannot be checked '
    + 'against that. Test the connection again; if it keeps failing, use the '
    + 'address you confirmed before.',
  remediation_serial_mismatch:
    "The firewall answering at {ip} has serial '{serial}', but this device "
    + "was confirmed as '{expected}'. The names match but it is a different "
    + 'unit — check the address.',
  snapshot_unusable:
    "Snapshot '{file}' cannot be used. {detail}",
  collected_not_a_config:
    'The device answered, but what came back is not a FortiGate configuration. {detail}',
  diff_file_unusable:
    'The {which} file ({file}) cannot be compared. {detail}',
  store_not_writable:
    "APO could not write to its device store in '{path}'. Windows blocks "
    + 'writes in Program Files and on some network shares. Move APO.exe to a '
    + 'folder you own (for example Documents\\APO) and start it again — your '
    + 'licence and devices live next to the program.',
  licence_not_writable:
    "Your key is valid, but APO could not save it in '{path}'. Windows blocks "
    + 'writes in Program Files and on some network shares. Move APO.exe to a '
    + 'folder you own (for example Documents\\APO) and enter the key again.',
  store_corrupt:
    'APO could not read its device store ({file}) — the file is damaged. '
    + 'Close any other copy of APO that may be running and restart. If it '
    + 'still fails, move that file aside and register your devices again; '
    + 'your configuration files are not affected.',
  store_unreadable:
    'APO could not read its device store ({file}). Your devices are not gone '
    + 'from this screen because they were deleted — the file could not be '
    + 'opened. Close any other copy of APO that may be running, then restart. '
    + 'Do not delete that file: it holds your devices, customers and saved '
    + 'inputs.',
  device_files_left_behind:
    'The device was removed from APO, but its uploaded configuration file '
    + "could not be deleted from '{path}'. Delete it by hand — it contains "
    + "that customer's policies.",
  vdom_wrong_target:
    "The policies in this configuration belong to VDOM '{config_vdom}', but "
    + "this device is registered with VDOM '{registered_vdom}'. APO will not "
    + 'write to the firewall, because policy numbers mean different rules in '
    + "each VDOM. Register the device again with VDOM '{config_vdom}'.",
  deferred_until_shadower_decided:
    'Policy {policies} is unreachable only while policy {shadower} stays '
    + 'enabled — and policy {shadower} is also being changed. Do that one '
    + 'first, take a fresh configuration backup and run APO again: these may '
    + 'be live by then.',
  input_no_device:
    'This {what} did not say which device it is for. APO only applies input '
    + 'to the device you have open.',
  input_other_device:
    'That {what} was entered while a different device was open. Reopen the '
    + 'device you meant, then try again.',
  fqdn_unknown_layout:
    'No FQDN→IP entries recognized. The file has domains and IPs but not in a '
    + 'layout this parser recognizes — please send a few sample lines so it '
    + 'can be supported.',
  fqdn_no_entries:
    'No FQDN→IP entries recognized. The file does not appear to contain FQDN '
    + "entries. Run 'diagnose test application dnsproxy 6' (or 'diagnose "
    + "firewall fqdn list') and save the full console output.",
  snapshot_unparsable:
    "Could not parse snapshot '{file}'.",
  remediation_name_mismatch:
    "The connected firewall is '{connected}', but the configuration you have "
    + "open is '{config}'. Changes are not sent to a device other than the "
    + "one you are looking at. Check the IP, or open that device's "
    + 'configuration first.',
};

/* 응답 본문 하나에서 사용자에게 보일 한 문장을 만든다. 호출부마다 이 규칙을
   다시 적었더니 그중 몇 곳이 번역 통로를 지나지 않아, 같은 거절이 화면마다
   다른 언어로 떴다. 규칙은 한 곳에만 둔다. */
function serverMsg(data, fallback) {
  const d = data || {};
  const tpl = d.error_key ? SERVER_ERRORS[d.error_key] : null;
  if (tpl) {
    return apoT(tpl, {
      vdoms: (d.vdoms || []).join(', '),
      sheet: d.sheet_device || '?',
      open: d.open_device || '?',
      files: d.files || '',
      /* **낱말도 번역해서 끼운다.** 서버는 `what="request"` 라는 영어 낱말을
         보내는데 그대로 끼워 넣어, 한국어 화면에 "그 request은(는) 다른 장비가
         열려 있는 동안 입력됐습니다" 가 떴다 — 문장 안에 영어가 끼고 조사까지
         깨졌다(재비판 3라운드 F5). 사전에 없으면 apoT 가 원문을 돌려주므로
         새 값이 와도 지금보다 나빠지지 않는다. */
      what: d.what ? apoT(d.what) : '',
      file: d.file || '',
      which: d.which || '',
      detail: d.detail || '',
      path: d.path || '',
      policies: (d.policies || []).join(', '),
      shadower: d.shadower ?? '',
      config_vdom: d.config_vdom || '',
      registered_vdom: d.registered_vdom || '',
      /* {vdom}(단수)·{n} — 이 두 키가 빠져 usage_csv_vdom_unknown·
         usage_csv_no_match_in_vdom·sample_all_ungraded 세 문구가 화면에
         리터럴 '{vdom}'/'{n}' 으로 인쇄됐다(라운드 60, 3렌즈 수렴 실측). */
      vdom: d.vdom || '',
      n: d.n ?? '',
      limit: d.limit_mb ?? '',
      ip: d.ip || '',
      serial: d.connected_serial || '',
      expected: d.expected_serial || '',
      connected: d.connected_hostname || '',
      config: d.config_hostname || '',
    });
  }
  return d.error ? apoT(d.error) : apoT(fallback || 'Something went wrong.');
}

/* 실패 응답에서 문장을 뽑는다 — 본문이 JSON 이 아니면 넘겨받은 기본 문구. */
async function serverMsgFrom(res, fallback) {
  try { return serverMsg(await res.json(), fallback); }
  catch (_) { return apoT(fallback || 'Something went wrong.'); }
}

/* 이 장비의 사용량이 어느 파일에서 왔는지 — 서버가 보관한 값을 그대로 든다.
   화면 기억에만 두면 새로고침 한 번에 사라진다. */
let currentCsvMeta = [];

/* 이 장비에 DNS 캡처가 있는가 — 서버 session 이 주는 사실. 화면 문구를 읽어
   추측하면 번역·문구 변경에 깨지고, 실제로 그렇게 깨졌다. */
let currentDeviceHasFqdn = false;

/* ── 다른 창이 장비를 가져갔을 때 ──────────────────────────────────────
   이 앱은 한 번에 한 장비만 연다. 두 번째 창에서 다른 장비를 열면 첫 창의
   모든 동작이 409 가 되는데, 그 사실을 알려 주는 문장도 되돌릴 버튼도 없었다.
   오류가 시키는 '다시 열기'조차 드롭다운에 이미 그 장비가 선택돼 있어 수행
   불가능했다(라운드 25 실측: 화면만 보고 완주 불가).

   감지는 **한 곳에서** 한다 — 호출부마다 409 를 해석하게 하면 그중 하나가
   빠지고, 이 루프에서 그 형태로만 열 번 넘게 깨졌다. */
(() => {
  const realFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const res = await realFetch(input, init);
    if (res.status === 409) {
      const url = typeof input === 'string' ? input : (input && input.url) || '';
      if (url.includes('/api/')) {
        try {
          const data = await res.clone().json();
          if (data && Object.prototype.hasOwnProperty.call(data, 'open_device_id')) {
            showDeviceConflict(data.open_device_id);
          }
        } catch (_) { /* 본문이 JSON 이 아니면 알릴 것도 없다 */ }
      }
    }
    return res;
  };
})();

function showDeviceConflict(openId) {
  const bar = document.getElementById('deviceConflict');
  const txt = document.getElementById('deviceConflictText');
  if (!bar || !txt || !currentDeviceId || openId === currentDeviceId) return;
  txt.textContent = apoT('Another window opened a different device. {name} is '
                         + 'still registered — reopen it to continue here.',
                         { name: currentDeviceName || '' });
  /* **권하는 클릭이 무엇을 지우는지 배너에서 말한다** (B-87).
     15라운드가 확인창 가드를 붙여 조용한 손실은 막았지만, 배너는 여전히
     "reopen it to continue here" 로 클릭을 **권하기만** 했다 — 사용자는
     확인창이 뜨기 전까지 잃을 것이 있다는 사실을 모른다. NSPM 관례
     (FortiManager·Tufin)는 파괴적 동작을 **버튼이나 배너에서** 라벨링한다.
     진행 중인 것이 있을 때만 붙인다 — 없을 때 붙이면 겁만 준다. */
  const _pending = window.__apoPendingCount?.() || 0;
  if (_pending) {
    txt.textContent += ' ' + apoT(
      'Reopening discards the migration work in progress ({n} item(s) you entered).',
      { n: _pending });
  }
  bar.classList.remove('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('deviceConflictFix')?.addEventListener('click', async () => {
    if (!currentDeviceId) return;
    /* **여섯 번째 경로다.** 12~14라운드가 다섯 곳(업로드·열기·수집·전환·
       복원)에 가드를 달면서 여기만 빠뜨렸다. 이 배너는 두 번째 창이 다른
       장비를 열었을 때 뜨고 문구가 "reopen it to continue here" 로 클릭을
       권하는데, **유일한 버튼이 진행 중 작업을 한 마디 없이 지운다**
       (`adoptDeviceSession` 이 두 리셋을 부른다). */
    if (!window.__apoConfirmDiscardMigration?.()) return;
    const r = await fetch(`/api/devices/${encodeURIComponent(currentDeviceId)}/open`,
                          { method: 'POST' });
    if (!r.ok) return;
    const d = await r.json();
    adoptDeviceSession(d.session, d.device_name);
    applyLoadedConfig(d, { key: 'Reopened {name}', vars: { name: d.device_name || d.filename || '' } },
      apoT('Reopened {name}. Findings are not stored — run the assessment to '
           + 'see them.', { name: d.device_name || d.filename || '' }));
    window.__apoSetRanges?.((d.user_ranges || []).map((x) => x.cidr));
    document.getElementById('deviceConflict')?.classList.add('hidden');
    announceSourceState();
  });
});

/* 내려받을 파일 이름은 **서버가 정한 것**을 쓴다. 화면에서 따로 만들면 규칙이
   둘로 갈려, 한쪽만 고친 사이 한글 고객사 이름이 통째로 지워지거나(라운드 20)
   60자 자르기로 두 고객이 같은 이름이 됐다. RFC 5987 filename* 를 먼저 읽고,
   없으면 filename, 그것도 없으면 호출부가 준 기본값을 쓴다. */
function filenameFromResponse(res, fallback) {
  const cd = res.headers.get('Content-Disposition') || '';
  const star = /filename\*=UTF-8''([^;]+)/i.exec(cd);
  if (star) {
    try { return decodeURIComponent(star[1].trim()); } catch (_) { /* 아래로 */ }
  }
  const plain = /filename="?([^";]+)"?/i.exec(cd);
  return (plain && plain[1].trim()) || fallback;
}

/* 응답을 파일로 저장하는 **유일한 통로**. 이 함수를 지나지 않은 다운로드가
   다섯 곳 있었고, 전부 서버가 붙인 이름을 버리고 있었다 — 워크북·검증 표본은
   장비 이름 없이 두 고객 파일이 글자 그대로 같은 이름으로 떨어졌고, 조치
   CSV·Postman 은 헤더를 손으로 잘라 `_apo_..._; filename_=UTF-8''...` 같은
   깨진 이름으로 저장됐다(라운드 26 실측). 서버는 옳은 이름을 이미 보내고
   있었다. 규칙이 둘이면 한쪽만 고쳐진다. */
function saveResponseAs(blob, res, fallback) {
  /* **통로 자신이 검사한다.** 소스를 훑는 계약은 세 판 다 뚫렸고(객체 리터럴
     → 변수에 담은 가짜 응답 → 래퍼 함수), 실행 스모크는 사전 조건 때문에
     못 누르는 경로를 방치했다. 여기서 보면 **모든 경로가 지나간다** — 현재
     것도, 앞으로 늘어날 것도. 진짜 fetch 응답은 status·ok·headers.get 을
     전부 갖는다(라운드 30 실측: 9경로 중 6곳이 무방비였다). */
  const real = res && typeof res.status === 'number' && typeof res.ok === 'boolean'
    && res.headers && typeof res.headers.get === 'function';
  if (!real) {
    console.error('saveResponseAs: not a fetch response — the server-chosen '
                  + 'filename would be lost (fallback: ' + fallback + ')');
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filenameFromResponse(res, fallback);
  a.click();
  URL.revokeObjectURL(url);
}

/* 화면에서 만든 파일(서버 응답이 아닌 것)에 붙이는 장비 표시. 서버의
   _open_device_label 과 같은 목적 — 내려받기 폴더에서 (1),(2) 로 쌓였을 때
   어느 방화벽의 표인지 알 수 있어야 한다. */
function deviceStamp() {
  const name = (currentDeviceName || '').trim();
  if (!name) return '';
  /* **해시까지 붙인다.** 이름만 쓰면 hostname 이 같은 두 고객 파일이 글자
     그대로 같은 이름으로 떨어진다 — MSP 표준 명명(FGT-HQ, fw01)에서는 그게
     오히려 정상이다(라운드 30 실측: firewall_policy_FGT-HQ.csv 두 개).
     서버가 붙이는 다른 산출물은 전부 `{이름}_{해시8}` 이다 — 규칙을 맞춘다. */
  const safe = name.replace(/[\\/:*?"<>|]+/g, '-');
  const sha8 = (currentDeviceId || '').slice(0, 8);
  return sha8 ? `_${safe}_${sha8}` : `_${safe}`;
}

function setCsvStage(deviceName) {
  currentDeviceName = deviceName || '';
  const step = document.getElementById('csvStep');
  const hint = document.getElementById('csvStepHint');
  const ready = !!currentDeviceId;
  [fwCsvPickerBtn, proxyCsvPickerBtn,
   document.getElementById('csvClearBtn')].forEach((b) => {
    if (b) b.disabled = !ready;
  });
  if (step) {
    step.classList.toggle('is-locked', !ready);
    step.classList.toggle('is-ready', ready);
  }
  if (hint) {
    hint.textContent = ready
      ? apoT('Now add the usage CSV for {name} — it will be attached to this '
             + 'device only.', { name: currentDeviceName || apoT('this device') })
      : apoT('Add the configuration first — the usage CSV is then attached to '
             + 'that device.');
  }
  if (!ready) {
    if (selectedFwCsvName) selectedFwCsvName.textContent = apoT('No file selected');
    if (selectedProxyCsvName) selectedProxyCsvName.textContent = apoT('No file selected');
  }
}

function beginNewDevice() {
  /* 다음 장비의 설정 파일을 고르기 시작한 시점에 이전 장비의 CSV 상태를
     끊는다. 파싱이 끝난 뒤에 끊으면 그 사이에 CSV를 누를 수 있다. */
  currentDeviceId = null;
  if (fwPolicyCsvFile) fwPolicyCsvFile.value = '';
  if (proxyPolicyCsvFile) proxyPolicyCsvFile.value = '';
  /* 앞 장비의 대역 칩도 함께 끊는다. 남겨 두면 다음 장비 화면에 앞 고객의
     사설대역이 그대로 보이고, 마법사 대역 칸까지 그 값으로 채워진다. */
  window.__apoSetRangesLocal?.([]);
  setCsvStage('');
}

function adoptDevice(id, name) {
  currentDeviceId = id || null;
  setCsvStage(name);
}

/* **장비가 바뀔 때 화면이 맞춰야 할 것을 한 자리에서 맞춘다.**

   장비를 바꾸는 경로가 다섯(업로드·열기·수집·전환·재시작 복원)인데 각자
   필요한 상태를 따로 챙기고 있었고, 새 상태가 늘 때마다 어느 하나가 그걸
   빠뜨렸다 — 라운드 19~21의 결함이 전부 여기서 나왔다(사용량 출처가 앞
   고객 것으로 남고, 대역 칩이 앞 고객 것으로 남아 마법사가 그대로 저장).
   서버가 `session` 한 덩어리로 주고, 모든 경로가 이 함수를 지난다.
   새 상태가 생기면 서버 `_device_session()` 과 여기 두 곳만 고치면 된다. */
/* **이 장비의 것인가.** 비동기 응답이 돌아왔을 때 화면이 아직 같은 장비인지
   묻는 한 줄짜리 도구다.

   세대를 **올리는** 쪽은 완전했다(장비를 바꾸는 7개 경로 전부 올린다). 뚫린
   곳은 반대편이었다 — 세대를 **읽는** 곳이 비동기 호출부 65곳 중 5곳뿐이라,
   `adoptDeviceSession` 이 자기가 직접 쏘는 요청 세 개가 전부 무방비였다.
   그중 객체 명명 규칙은 판정 입력이라 **앞 고객 존 이름이 다음 고객 정책
   3건을 Critical 로 올렸다**(2026-09-10 실측: Critical 4→7).

   쓰는 법 — 요청 **직전에** 잡고, 화면·메모리에 쓰기 **직전에** 묻는다:
       const fresh = apoStillThisDevice();
       const d = await (await fetch(...)).json();
       if (!fresh()) return;            // 늦게 왔다. 남의 화면이다.
*/
function apoStillThisDevice() {
  const gen = window.__apoDeviceGen || 0;
  return () => gen === (window.__apoDeviceGen || 0);
}
window.apoStillThisDevice = apoStillThisDevice;

/* **축이 둘이다.** 늦은 응답을 버려야 하는 이유가 두 가지인데 카운터 하나로
   묶었더니 서로를 망가뜨렸다:

   · "장비가 바뀌었다" — 주인은 `adoptDeviceSession`. 이 함수가 **자기가 직접
     쏘는** 요청(객체 규칙·티켓 설정·룰세트 해시)이 있으므로, 다른 곳에서
     같은 카운터를 또 올리면 **그 정상 응답이 버려진다**(실제로 객체 규칙 칸이
     영영 비는 회귀가 났다).
   · "판정 입력이 바뀌었다" — 주인은 `resetSeverityResults`. 장비는 그대로인데
     객체 규칙·티켓 형식을 저장하면 여기가 돈다. 이 축을 없앴더니 화면이
     "후보를 다시 불러오세요" 라고 말한 **직후 스스로를 뒤집고**, 옛 입력으로
     계산된 조치 계획을 현재인 것처럼 제시했다(재비판 5라운드 F-E).

   그래서 쓰는 쪽이 **무엇에 의존하는지**로 고른다:
   · 장비 정체성에만 의존 → `apoStillThisDevice()` (객체 규칙, FortiOS 자문,
     티켓 설정 읽기, 감사 타임라인)
   · 판정 입력에도 의존 → `apoStillThisInput()` (조치 후보, 룰세트 해시,
     마지막사용 분포, 정책표 재렌더, 임계값 미리보기) */
function apoStillThisInput() {
  const dev = window.__apoDeviceGen || 0;
  const inp = window.__apoInputGen || 0;
  return () => dev === (window.__apoDeviceGen || 0)
            && inp === (window.__apoInputGen || 0);
}
window.apoStillThisInput = apoStillThisInput;

function adoptDeviceSession(session, fallbackName) {
  /* **세대의 주인은 이 함수 하나다.** "화면이 다른 장비의 것이 됐다" 를
     아는 곳이 여기뿐이다. 한때 `resetSeverityResults` 에서도 올렸는데,
     config 업로드 한 번에 번호가 2 오르고 그 사이에 **이 함수가 직접 쏜**
     요청이 끼어서 정상 응답이 버려졌다(규칙 칸이 영영 비었다).
     아래에서 쏘는 요청들(`__apoLoadObjRules` 등)이 올린 뒤의 번호를 잡도록
     **맨 앞에서** 올린다. */
  window.__apoDeviceGen = (window.__apoDeviceGen || 0) + 1;
  const s = session || {};
  adoptDevice(s.device_id, s.device_name || fallbackName || '');
  currentCsvMeta = Array.isArray(s.csv_meta) ? s.csv_meta : [];
  currentRuntimeStats = s.runtime_stats || {};
  currentDeviceHasFqdn = !!s.has_fqdn;
  // 대역은 화면 칩만 맞춘다 — 서버에 쓰면 그 장비의 저장분을 덮어쓴다.
  window.__apoSetRangesLocal?.((s.user_ranges || []).map((x) => x.cidr));
  /* **객체 명명 규칙도 이 장비의 것이다.** 장비를 바꿨는데 설정 화면에 앞
     고객의 값이 남아 있으면, 사용자는 그 값이 지금 판정에 쓰인다고 읽는다 —
     서버는 이미 비웠는데 화면만 남는 형태다(라운드 19~21 의 반복 결함). */
  window.__apoLoadObjRules?.();
  /* 마지막사용 분포도 **이 장비의 것이다.** 부팅 시 한 번만 읽던 탓에
     장비 게이트 409 로 비어 있었다(4라운드 발견 4). */
  window.__apoThHistogram?.();
  /* **장비 이관 카드도 이 장비의 것이다.** 안 지우면 앞 설정에서 받은
     확인·사전점검표·매핑이 그대로 남아, 사용자가 한 번도 본 적 없는
     인터페이스 목록으로 파일이 만들어진다. */
  /* **리셋이 던져도 그 뒤가 돌아야 한다.** 8라운드가 이 사슬에
     `renderHosts()`/`renderBlankNotice()` 를 넣었는데 그 둘은 요소를 옵셔널
     체이닝 없이 만진다 — 템플릿에서 id 하나만 사라져도 여기서 던지고,
     그러면 티켓 설정·FQDN 근거·감사 타임라인 정리 등 **뒤따르는 67줄이
     통째로 안 돈다.** 지금은 id 계약이 지켜 도달 불가지만 문은 열려 있다. */
  try { window.apoDevResetForNewSource?.(); } catch (e) { /* 계속 간다 */ }
  /* **IP 흐름도 이 장비의 것이다.** 안 지우면 A 고객 대역을 조회한 뒤 B
     장비를 열었을 때 A 의 참조 표·주소 계획이 그대로 남는다. 서버는 현재
     config 로 다시 계획하므로 잘못된 파일이 나오지는 않지만, 화면에 남은
     남의 IP 목록은 그 자체로 사고다. */
  try { window.apoIpResetForNewSource?.(); } catch (e) { /* 계속 간다 */ }
  /* 티켓 형식 자체는 장비와 무관하지만(이 컴퓨터의 설정이다), **미리보기는
     지금 열린 설정 기준**이라 장비를 바꾸면 다시 세어야 한다. */
  window.__apoLoadTicketSettings?.();
  /* **룰 세트 해시도 이 장비의 것이다.** 객체 규칙이 장비별이므로 장비를
     바꾸면 해시가 바뀐다. 게다가 이 요청은 이제 게이트를 타므로(열린 장비를
     대야 한다) 페이지 로드 시점의 첫 호출은 아직 device_id 가 없어 409 로
     떨어진다 — 여기서 다시 부르지 않으면 장비를 연 뒤 해시 줄이 **빈칸으로
     남는다**(재비판 라운드 2 실측). 앞 장비의 해시가 남는 문제도 함께 막는다. */
  window.__apoRefreshRulesetHash?.();
  /* FQDN 근거도 이 장비의 사실대로 말한다. 무조건 '이전 설정과 함께 지워졌다'로
     세웠더니, 같은 장비를 다시 열어 서버가 캐시를 복원했는데도 화면은 근거가
     없다고 말했다 — 판정은 그 캐시를 쓰는데(라운드 22 지적). */
  const fq = document.getElementById('fqdnDumpStatus');
  if (fq) {
    fq.textContent = s.has_fqdn
      ? apoT('DNS capture in use for this device.')
      : apoT('No DNS capture for this device — FQDN policies cannot be judged '
             + 'until you upload a dnsproxy dump or fetch it from the device.');
  }
  /* 정확도 검증은 보관된 설정으로 돌아가므로 장비만 열려 있으면 쓸 수 있다.
     판정 실행에 매달아 뒀더니 새로고침 한 번에 카드가 사라져, 채워 둔 표본을
     올릴 방법이 화면에서 없어졌다(라운드 27 실측). */
  const vc = document.getElementById('sevVerifyCard');
  if (vc) vc.style.display = s.device_id ? '' : 'none';
  /* 감사 타임라인은 장비가 바뀌면 서버가 버린다. 표를 그대로 두면 내보내기가
     400으로 실패하는데 사용자는 이유를 알 수 없다 — 화면도 함께 비운다. */
  if (!s.has_audit_timeline) {
    const ar = document.getElementById('auditResult');
    if (ar) ar.innerHTML = '';
    const ax = document.getElementById('auditExportBtn');
    if (ax) ax.style.display = 'none';
    const ast = document.getElementById('auditStatus');
    if (ast) {
      ast.textContent = apoT('Snapshots are cleared when you switch devices — '
                             + 'select them again to rebuild the timeline.');
    }
  }
  /* 장비 선택기도 지금 열린 장비를 가리킨다. 목록을 다시 읽을 때만 그렸더니
     고객사 화면에서 '열기'로 바꾼 직후 한 박자 뒤진 장비를 표시했고 —
     같은 화면이 현재 장비를 두 가지로 말했다 — 표시 중인 그 장비를 고르면
     change 가 안 떠서 **보이는 장비를 열 수 없는** 죽은 컨트롤이 됐다. */
  // 설정 슬롯도 이 장비의 사실을 말한다 — Config 칩은 초록인데 슬롯은
  // 'No file selected' 라고 하던 모순을 없앤다.
  if (selectedConfigName) {
    selectedConfigName.textContent = s.filename || apoT('No file selected');
  }
  // 이 장비를 다시 열었으니 충돌 알림은 사실이 아니다.
  if (s.device_id) document.getElementById('deviceConflict')?.classList.add('hidden');
  // 상단 상태바가 '누구 장비인가'를 말할 수 있게 한다.
  window.APO?.onCustomer?.(s.customer || '');
  /* **열린 장비가 없으면 상단 상태바도 그렇게 말해야 한다.**
     이 함수가 '장비 상태의 유일한 주인'인데 정작 상태바의 설정 슬롯은
     건드리지 않아서, 열려 있던 장비를 삭제한 뒤에도 지워진 장비의 이름·칩·
     판정 표가 그대로 남았다(라운드 28 실측). 빈 세션은 빈 화면이어야 한다.
     장비가 있을 때는 건드리지 않는다 — 그쪽 주인은 각 진입 경로의 onConfig 다. */
  if (!s.device_id) {
    window.APO?.onConfig?.(null);
    window.APO?.onUsage?.(0);
    window.APO?.onRanges?.(0);
    window.__apoResetSev?.('');
  }
  const sel = document.getElementById('deviceSwitch');
  if (sel && s.device_id) {
    if (![...sel.options].some((o) => o.value === s.device_id)) {
      const opt = document.createElement('option');
      opt.value = s.device_id;
      opt.textContent = s.device_name || s.device_id;
      sel.appendChild(opt);
    }
    sel.value = s.device_id;
  }
  renderPolicyCsvSummary();
}

/* 입력 상태가 바뀌었다고 알린다. 마법사는 이 신호로 다시 그린다 —
   자기 버튼으로 올렸는지 페이지의 원래 버튼으로 올렸는지 가리지 않는다.
   폴링으로 감시하면 사용자가 다른 경로로 올린 변화를 놓친다. */
function announceSourceState() {
  document.dispatchEvent(new CustomEvent('apo:sources-changed'));
}

setCsvStage('');

/* 사용량이 **이 설정의 정책 몇 건에 붙었는가.** 종류별 형태({firewall,proxy})와
   평평한 옛 형태를 모두 센다.

   예전에는 CSV 행 수를 셌다. 그래서 다른 장비 CSV 가 섞이면 데이터 가져오기
   화면은 "6행 중 1행이 이 설정에 없는 정책 번호"라고 정확히 경고하는데, 개요는
   같은 파일을 두고 "✓ 정책 6건에 대해 불러옴 — 미사용 판정 가능"이라는 초록
   체크를 띄웠다. 정책이 5건뿐인 설정에서 6이 나온 것이다 — 경고는 사라지고
   분모는 부풀었다(라운드 45 실측).

   판정에 실제로 쓰이는 것은 **매칭된 정책**뿐이므로 그것만 센다. */
/* **행이 있는 것과 값이 있는 것은 다르다.** 근거 패널이 말하는 축은
   *사용량* 인데 그 판단을 행 수로만 했다 — FortiGate GUI 에서 Bytes 칸을
   Hit Count 로 고르면(흔한 실수) 파서가 쓰레기를 0 이 아니라 `null` 로
   정직하게 돌리는데, 패널은 "미사용 판정이 가능합니다" 초록 체크를 줬다.
   8라운드에 전체 등급(`urgency 0`)으로 가드를 걸었지만 그것은 **다른 축**
   이라 any/any 규칙이 등급을 매기면 한 번도 안 탔다(9라운드 F5 실측:
   14건 전부 null 인데 초록). 여기서 **사용량 축의 사실**을 직접 센다. */
function _statsUsable(rs, view) {
  /* **두 수치는 같은 모집단을 세야 한다.** 처음에는 여기서 전체 dict 를
     그냥 훑었는데, `_statsCount` 는 열린 config 의 정책 번호와 교집합을
     잡고 VDOM 꼬리표까지 본다. 그래서 **이 설정에 없는 행에만 값이 있고
     매칭된 행은 전부 비었을 때** `usage > 0 && usableAll > 0` 이 되어
     초록 체크가 그대로 떴다 — 이 함수가 닫으려던 바로 그 거짓 초록이다
     (리뷰 게이트가 잡았다).

     "같은 로직을 적용" 이 아니라 **같은 코드 경로**로 만든다. 그래야 한쪽만
     고쳐져 다시 갈리는 일이 없다. */
  return _statsCount(rs, view, (row) => {
    if (!row || typeof row !== 'object') return false;
    const h = row.hit_count, u = row.last_used;
    return (h !== null && h !== undefined && h !== '' && h !== '-')
        || (u !== null && u !== undefined && u !== '' && u !== '-');
  });
}

/* `rowOk` 를 주면 **그 조건을 만족하는 행만** 센다 — 매칭·VDOM 범위 판단은
   그대로 두고 값 검사만 얹는다(`_statsUsable`). 안 주면 매칭 행 전부. */
function _statsCount(rs, view, rowOk) {
  if (!rs || typeof rs !== 'object') return 0;
  const v = view || currentView;
  /* 통계가 한 VDOM 것이면(_vdom 꼬리표) 그 VDOM 정책하고만 대조한다 —
     전 VDOM 번호와 대조하면 다른 VDOM 에만 있는 번호도 "매칭"으로 세어,
     실제 적용(한 VDOM)보다 부풀린 수에 초록 체크가 붙는다(라운드 56).
     꼬리표 자체는 정책 행이 아니므로 키에서도 뺀다. */
  const tag = String(rs._vdom || '').toLowerCase();

  const pass = (m, k) => (!rowOk || rowOk(m[k]));

  const countIn = (map, section) => {
    if (!map) return 0;
    const keys = Object.keys(map).filter(
      (k) => k !== '_vdom' && pass(map, k));
    if (!v || !Array.isArray(v[section])) return keys.length;  // 설정을 모르면 세는 대로
    const pool = tag
      ? v[section].filter((p) => String(p.vdom || '').toLowerCase() === tag)
      : v[section];
    const ids = new Set(pool.map(
      (p) => String(p.policy_id ?? p._edit ?? '')));
    return keys.filter((k) => ids.has(String(k))).length;
  };

  if (rs.firewall || rs.proxy) {
    return countIn(rs.firewall, 'firewall_policy')
         + countIn(rs.proxy, 'firewall_proxy_policy');
  }
  /* 평평한(종류 미상) 통계는 서버 조인(_stats_for)이 **양쪽**에 적용한다 —
     firewall 만 세면 proxy 정책에만 매칭되는 통계가 화면에서 "사용량 0" 으로
     보이면서 판정표는 그 통계로 active/dormant 를 말한다(라운드 58 경계값
     렌즈 실측 자기모순). 키별로 어느 한쪽이라도 매칭이면 1 로 센다. */
  const fw = countIn(rs, 'firewall_policy');
  const px = countIn(rs, 'firewall_proxy_policy');
  if (!v || !Array.isArray(v.firewall_policy)) return fw;   // 설정 미상 — 기존 그대로
  if (!px) return fw;
  const tag2 = String(rs._vdom || '').toLowerCase();
  const idsOf = (section) => {
    const pool = tag2
      ? (v[section] || []).filter((p) => String(p.vdom || '').toLowerCase() === tag2)
      : (v[section] || []);
    return new Set(pool.map((p) => String(p.policy_id ?? p._edit ?? '')));
  };
  const fwIds = idsOf('firewall_policy'), pxIds = idsOf('firewall_proxy_policy');
  return Object.keys(rs).filter((k) => k !== '_vdom' && pass(rs, k)
    && (fwIds.has(String(k)) || pxIds.has(String(k)))).length;
}

/* 상단 상태바·Overview는 shell.js가 그린다. 여기서는 "무엇이 로드됐는지"만 알린다.
   `source` 는 **번역된 문장이 아니라 {key, vars}** 다. 완성된 문장을 넘겼더니
   shell.js 가 그걸 그대로 들고 있어, 나중에 언어를 바꿔도 "Uploaded x.conf" 가
   영어로 남았다 — 그리는 쪽이 그릴 때 번역해야 다시 그리면 따라온다. */
function notifyConfigLoaded(source, filename, configSha, resetReason) {
  const meta = currentView?.meta || {};
  window.__apoResetSev?.(resetReason);
  const counted = meta.policy_count != null || meta.proxy_policy_count != null;
  window.APO?.onConfig?.({
    meta,
    filename,
    configSha,
    source,
    // 개수를 못 셌으면 0이 아니라 null — "정책 0건"으로 보이면 안 된다.
    policies: counted ? (meta.policy_count ?? 0) + (meta.proxy_policy_count ?? 0) : null,
  });
  window.APO?.onUsage?.(_statsCount(currentRuntimeStats),
    String((currentRuntimeStats || {})._vdom || ''),
    _statsUsable(currentRuntimeStats, currentView));
}

function applyLoadedConfig(data, source, resetReason) {
  currentParsed = data.parsed;
  currentView = data.view;
  /* 장비 종속 상태(사용량·출처·대역·FQDN·감사)는 **여기서 손대지 않는다** —
     adoptDeviceSession 이 session 하나로 이미 맞췄다. 여기서 또 세우면 경로마다
     호출 순서가 달라 어느 쪽이 이길지가 갈리고, 실제로 수집 경로에서 이 줄이
     session 을 덮어써 화면이 '사용량 CSV 없음'이라고 말했다(라운드 22 실측). */
  fwCsvSummary = null;
  proxyCsvSummary = null;
  if (selectedFwCsvName) selectedFwCsvName.textContent = apoT('No file selected');
  if (selectedProxyCsvName) selectedProxyCsvName.textContent = apoT('No file selected');
  /* 이 경로는 장비에서 직접 받아온 것이라 내려받을 parsed JSON이 없다. 그런데
     이전에 업로드한 파일의 링크를 그대로 두면, 새 장비의 요약 카드 밑에 이전
     고객 장비의 설정 전체를 내려받는 링크가 남는다. */
  if (downloadBox) downloadBox.innerHTML = '';
  /* 설정 파일 슬롯은 **여기서 비우지 않는다** — 주인은 adoptDeviceSession 이다.
     여기서 'No file selected' 로 되돌렸더니, 등록된 장비를 열었는데 Config
     칩은 초록이고 바로 옆 슬롯은 비었다고 말하는 모순이 남았다(라운드 23). */
  resetPolicyFilters();
  setCsvStage(currentDeviceName);   // 수집 직후에도 CSV 단계 문구를 이 장비로
  apoSetText(configStatus, source.key, source.vars);
  if (data.stats_count) {
    apoSetText(policyStatsStatus,
               '{n} policies have hit count / last used from the device.',
               { n: data.stats_count });
  } else {
    apoSetText(policyStatsStatus, 'Upload Firewall Policy CSV or Proxy Policy CSV.');
  }
  renderPolicyCsvSummary();
  renderMeta(data.view?.meta || {});
  updatePolicyFilterVisibility();
  renderActiveTab();
  notifyConfigLoaded(source, data.filename, data.config_sha, resetReason);
}

/* ── 장비 등록 마법사 ──────────────────────────────────────────────────
   config → FW CSV → Proxy CSV(건너뛰기 가능) → 사용자 IP 대역 → FQDN.

   설계 원칙 하나: **업로드를 다시 구현하지 않는다.** 각 단계는 기존 숨은
   입력(#configFile 등)을 클릭하고 기존 핸들러가 끝나기를 기다린다. 마법사가
   자기 업로드를 따로 가지면 같은 파일이 경로마다 다르게 처리되고, 그건 이
   제품에서 반복해 사고를 낸 유형이다.

   임시 저장은 **입력한 값만** 기억한다(단계 번호·대역 텍스트). 파일이
   올라갔다는 사실은 서버 상태로만 판단한다 — 안 그러면 서버가 재시작된 뒤
   "이미 등록됨"이라고 거짓말하게 된다. */
(() => {
  const wiz = document.getElementById('setupWizard');
  if (!wiz) return;
  const STEPS = 5;
  const DRAFT_KEY = 'apo.wizard.draft';
  let step = 1;

  const $ = (id) => document.getElementById(id);
  const stepEls = () => [...wiz.querySelectorAll('.wiz-step')];

  function readDraft() {
    try { return JSON.parse(localStorage.getItem(DRAFT_KEY) || 'null'); }
    catch (_) { return null; }
  }
  function writeDraft() {
    try {
      localStorage.setItem(DRAFT_KEY, JSON.stringify({
        step,
        ranges: $('wizRanges')?.value || '',
        // **어느 장비의 초안인지** 함께 적는다. 장비를 안 적었더니 A에서 쓰던
        // 초안이 B를 열어 둔 채 '이어서 하기' 한 번에 그대로 저장돼, A 고객의
        // 사설대역이 B 고객 장비의 판정 기준이 됐다(라운드 17 실측).
        deviceId: currentDeviceId || '',
        deviceName: currentDeviceName || '',
        /* 로컬 시각으로 적는다. toISOString()은 UTC라 화면의 다른 시각(임포트
           시각 등)과 몇 시간씩 어긋나고, 사용자는 미래 날짜가 찍힌 임시저장을
           보고 자기 것인지 의심하게 된다(라운드 20 지적). */
        savedAt: (() => {
          const d = new Date();
          const p = (n) => String(n).padStart(2, '0');
          return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} `
            + `${p(d.getHours())}:${p(d.getMinutes())}`;
        })(),
      }));
    } catch (_) {}
  }
  function clearDraft() {
    try { localStorage.removeItem(DRAFT_KEY); } catch (_) {}
  }

  /* 마법사가 만들어 내는 문구도 번역을 지난다 — data-i18n은 HTML에 적힌
     원문만 덮으므로, 아래처럼 코드가 textContent를 다시 쓰는 자리는 이
     통로가 없으면 한국어 모드에서 영어로 되돌아간다. */
  const t = (s, v) => (window.APO_I18N?.t ? window.APO_I18N.t(s, v) : s);

  function render() {
    $('wizStepLabel').textContent = t('Step {n} of {total}', { n: step, total: STEPS });
    stepEls().forEach((el) => {
      el.classList.toggle('hidden', Number(el.dataset.step) !== step);
    });
    $('wizProgress').innerHTML = Array.from({ length: STEPS }, (_, i) => {
      const n = i + 1;
      return `<i class="${n < step ? 'done' : n === step ? 'now' : ''}"></i>`;
    }).join('');
    $('wizBack').disabled = step === 1;
    // 1단계는 등록이 끝나야 넘어갈 수 있다 — 장비 없이 CSV 단계로 가면
    // 서버가 409로 막을 뿐 사용자는 이유를 모른다.
    $('wizNext').disabled = (step === 1 && !currentDeviceId);
    $('wizNext').textContent = t(step === STEPS ? 'Finish' : 'Next');
    /* 제목이 '장비 등록'인데 1단계가 '등록됨 — 앞 장비'로 시작하면, 지금
       이 장비를 이어서 손보는 것인지 새 장비를 넣는 것인지 알 수 없다.
       무엇을 하는 중인지 제목이 직접 말하게 한다(라운드 19 지적). */
    const title = $('wizTitle');
    if (title) {
      title.textContent = currentDeviceId
        ? t('Continue with {name}', { name: currentDeviceName || t('this device') })
        : t('Register a device');
    }
    refreshStates();
  }

  function refreshStates() {
    const cfg = $('wizConfigState');
    if (cfg) {
      cfg.textContent = currentDeviceId
        ? t('Registered — {name}', { name: currentDeviceName || t('device') })
        : t('Not registered yet');
      cfg.classList.toggle('is-done', !!currentDeviceId);
    }
    const fw = $('wizFwState');
    if (fw) {
      const name = selectedFwCsvName?.textContent || '';
      const has = name && name !== 'No file selected';
      fw.textContent = has ? t('Added — {name}', { name }) : t('Not added');
      fw.classList.toggle('is-done', !!has);
    }
    const px = $('wizProxyState');
    if (px) {
      const name = selectedProxyCsvName?.textContent || '';
      const has = name && name !== 'No file selected';
      px.textContent = has
        ? t('Added — {name}', { name }) : t('Not added (skip if unused)');
      px.classList.toggle('is-done', !!has);
    }
    const fq = $('wizFqdnState');
    if (fq) {
      /* **사실을 직접 본다.** 다른 요소의 문구를 정규식으로 읽어 판단했더니,
         (a) 번역만 해도 깨지고 (b) 서버가 그 장비의 DNS 캡처를 복원해 판정에
         쓰고 있는데도 마법사는 '아직 넣지 않음'이라고 말했다 — 같은 화면 두
         곳이 같은 사실을 반대로 말했다(라운드 24 지적). */
      const done = !!currentDeviceHasFqdn;
      fq.textContent = t(done ? 'Added' : 'Not added');
      fq.classList.toggle('is-done', done);
    }
  }

  /* 기존 입력을 그대로 클릭한다. 완료는 폴링이 아니라 상태 변경 이벤트로
     안다 — 사용자가 마법사 버튼 대신 Sources 화면의 원래 버튼으로 올려도
     마법사가 같이 갱신돼야 하고, 폴링은 그 경로를 놓친다. */
  function pickThrough(inputEl) {
    if (inputEl) inputEl.click();
  }
  document.addEventListener('apo:sources-changed', () => {
    if (wiz.classList.contains('hidden')) return;
    // 장비가 바뀌었으면 대역 칸부터 그 장비 것으로 되맞춘다.
    fillRangesFromDevice(false);
    render();
  });

  /* 초안은 **그 장비의 것일 때만** 쓴다. 장비가 다르면 이어받을 것이 없다. */
  function draftForOpenDevice() {
    const d = readDraft();
    if (!d) return null;
    /* **두 쪽이 같은 장비를 가리킬 때만** 이어받는다. 빈 값이면 확인을 건너뛰게
       했더니, 장비를 지운 뒤 만들어진 '장비 없는 초안'이 다음에 연 장비에
       그대로 적용돼 A 고객의 사설대역이 B 고객 장비의 판정 기준이 됐다
       (라운드 18 실측). 이어받을 대상이 불분명하면 이어받지 않는다. */
    if (!currentDeviceId || !d.deviceId || d.deviceId !== currentDeviceId) return null;
    return d;
  }

  function open() {
    const d = draftForOpenDevice();
    const bar = $('wizDraftBar');
    if (d && (d.ranges || d.step > 1)) {
      $('wizDraftText').textContent =
        `Unfinished registration from ${d.savedAt}${d.deviceName ? ` (${d.deviceName})` : ''}.`;
      bar.classList.remove('hidden');
    } else {
      bar.classList.add('hidden');
    }
    step = 1;
    // 열 때마다 **지금 열린 장비의 값**으로 맞춘다. 칸에 남아 있던 앞 장비의
    // 텍스트를 그대로 두면 4단계를 지나며 이 장비에 저장된다.
    fillRangesFromDevice(true);
    wiz.classList.remove('hidden');
    render();
  }

  /* 대역 칸은 **이 장비에 지금 저장된 값**을 보여준다. 마법사의 4단계는 입력한
     내용을 그대로 저장하므로, 칸이 실제 상태와 다르면 그 차이가 조용히 저장돼
     판정이 바뀐다. force=true면 작성 중이던 내용을 버리고 되돌린다. */
  /* 칸에 담긴 값이 **어느 장비의 것인지** 기억한다. 마법사를 연 뒤 1단계에서
     새 config 를 올려 장비가 바뀌면 칸도 따라와야 한다 — 안 그러면 앞 고객의
     대역이 그대로 4단계를 지나 이 장비에 저장된다(라운드 21 실측). */
  let boxDeviceId = null;

  function fillRangesFromDevice(force) {
    const box = $('wizRanges');
    if (!box) return;
    if (force || !box.value || boxDeviceId !== currentDeviceId) {
      box.value = (window.__apoGetRanges?.() || []).join('\n');
      boxDeviceId = currentDeviceId;
    }
  }
  function close() { wiz.classList.add('hidden'); }

  $('wizardOpenBtn')?.addEventListener('click', open);
  $('wizCloseBtn')?.addEventListener('click', () => { writeDraft(); close(); });
  $('wizSaveClose')?.addEventListener('click', () => {
    writeDraft();
    close();
    if (policyStatsStatus) {
      apoSetText(policyStatsStatus,
        'Registration saved — reopen "Register a device" to continue where you left off.');
    }
  });
  $('wizDraftResume')?.addEventListener('click', () => {
    const d = draftForOpenDevice();
    if (!d) return;
    if ($('wizRanges')) $('wizRanges').value = d.ranges || '';
    // 파일 단계는 서버 상태로만 판단한다 — 장비가 안 열려 있으면 1단계부터.
    step = currentDeviceId ? Math.min(Math.max(d.step || 1, 1), STEPS) : 1;
    $('wizDraftBar').classList.add('hidden');
    render();
  });
  $('wizDraftDiscard')?.addEventListener('click', () => {
    clearDraft();
    // **비우지 않고 장비의 실제 값으로 되돌린다.** 빈칸으로 두면 그대로 4단계를
    // 지나며 저장돼, '임시저장을 버린다'는 조작이 지금 열려 있는 장비의 대역을
    // 지웠다(라운드 16 실측: 1개 → 0개, 판정 Unknown 0 → 2). 버리는 대상은
    // 작성 중이던 초안이지 장비에 저장된 값이 아니다.
    fillRangesFromDevice(true);
    step = 1;
    $('wizDraftBar').classList.add('hidden');
    render();
  });

  $('wizPickConfig')?.addEventListener('click', () =>
    pickThrough(configFileInput));
  $('wizPickFw')?.addEventListener('click', () =>
    pickThrough(fwPolicyCsvFile));
  $('wizPickProxy')?.addEventListener('click', () =>
    pickThrough(proxyPolicyCsvFile));
  $('wizPickFqdn')?.addEventListener('click', () =>
    pickThrough(document.getElementById('fqdnDumpFile')));

  $('wizCopyCmd')?.addEventListener('click', async (e) => {
    try {
      await navigator.clipboard.writeText($('wizFqdnCmd').textContent.trim());
      e.currentTarget.textContent = apoT('Copied');
    } catch (_) { e.currentTarget.textContent = apoT('Select manually'); }
    setTimeout(() => { e.currentTarget.textContent = apoT('Copy command'); }, 1500);
  });

  $('wizBack')?.addEventListener('click', () => {
    if (step > 1) { step -= 1; render(); }
  });

  $('wizNext')?.addEventListener('click', async () => {
    // 대역 단계를 떠날 때 실제로 저장한다 — 화면에만 남기면 판정에 안 쓰인다.
    if (step === 4) {
      const raw = ($('wizRanges')?.value || '')
        .split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      /* 저장돼 있던 대역을 **전부** 지우는 저장은 되묻는다. 대역은 판정 입력이고
         이력이 없어 되돌릴 수 없다 — 빈칸으로 지나가는 조작 하나가 그 장비의
         판정 축을 꺼 버린다. */
      const had = (window.__apoGetRanges?.() || []).length;
      if (had && !raw.length
          && !confirm(t('This will remove all {n} saved IP range(s) from {name}. '
                        + 'The user/server distinction stops being judged for this '
                        + 'device. Continue?',
                        { n: had, name: currentDeviceName || t('this device') }))) {
        return;
      }
      try {
        const info = await window.__apoSetRanges?.(raw);
        const rej = (info && info.rejected) || [];
        $('wizRangesNote').textContent = rej.length
          ? `${info.count} range(s) saved. Not recognised, ignored: ${rej.join(', ')}`
          : `${(info && info.count) || 0} range(s) saved.`;
      } catch (err) {
        $('wizRangesNote').textContent = err.message || 'Failed to save the ranges.';
        return;
      }
      // 저장 문구에도 장비를 밝힌다 — 대역이 장비별이 된 뒤로는 "어디에
      // 저장됐는지"가 사용자가 확인해야 할 사실이다.
      if (currentDeviceName) {
        $('wizRangesNote').textContent += ` Saved with ${currentDeviceName}.`;
      }
    }
    if (step < STEPS) { step += 1; writeDraft(); render(); return; }
    clearDraft();
    close();
    // 마지막 단계에서 끝내면 바로 판정으로 이어준다 — 등록만 하고 결과를 못
    // 보는 상태로 두면 무엇을 위해 넣었는지가 흐려진다.
    window.APO?.setView?.('severity');
    if (typeof window.__apoRunClassify === 'function') await window.__apoRunClassify();
  });
})();

/* ── 고객사 · 장비 배정 ────────────────────────────────────────────────
   등록한 장비를 고객사에 끌어다 놓는다. 배정은 보고서를 묶는 라벨일 뿐
   판정 입력이 아니다 — 서버도 같은 규칙이다. */
(() => {
  const view = document.getElementById('customersView');
  if (!view) return;
  const custList = document.getElementById('custList');
  const unassigned = document.getElementById('devUnassigned');
  const status = document.getElementById('custStatus');
  let data = { devices: [], customers: [], open_device_id: null };

  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  /* 코드가 만드는 문장도 번역을 지난다. data-i18n은 HTML에 이미 있는 요소만
     덮으므로, 목록·상태줄·확인 대화는 이 통로가 없으면 한국어 모드에서 영어로
     남는다 — 되돌릴 수 없는 삭제 확인문까지 그랬다. */
  const t = (s, v) => (window.APO_I18N?.t ? window.APO_I18N.t(s, v) : s);

  function deviceChip(d) {
    const bits = [];
    // 장비명은 config의 hostname이라 공장 기본값 'FortiGate'로 남은 장비끼리
    // 흔히 겹친다. 등록한 파일명과 해시 앞자리를 함께 보여 줘야 사람이 두
    // 장비를 구분하고, 리포트의 감사 해시와도 대조할 수 있다.
    if (d.config_filename) bits.push(d.config_filename);
    if (d.config_sha256) bits.push(String(d.config_sha256).slice(0, 8));
    bits.push(d.usage_count
      ? t('{n} usage rows', { n: d.usage_count }) : t('no usage data'));
    bits.push(d.range_count
      ? t('{n} range(s)', { n: d.range_count }) : t('no ranges'));
    if (d.has_fqdn) bits.push('FQDN');
    /* 배정을 드래그로만 할 수 있으면 키보드·터치 사용자는 이 단계에서 막힌다
       — 고객사 배정은 리포트를 묶는 필수 단계라 '완주 불가'가 된다. 같은
       규칙을 쓰는 셀렉트를 함께 둔다(드래그는 그대로 동작한다). */
    const custs = Array.isArray(data && data.customers) ? data.customers : [];
    const options = [`<option value=""${d.customer_id ? '' : ' selected'}>`
      + `${esc(t('Unassigned'))}</option>`]
      .concat(custs.map((c) => `<option value="${esc(c.id)}"${
        c.id === d.customer_id ? ' selected' : ''}>${esc(c.name)}</option>`))
      .join('');
    return `<div class="dev-chip ${d.device_id === data.open_device_id ? 'is-open' : ''}"
                 draggable="true" data-device="${esc(d.device_id)}">
        <span class="dev-chip-name">${esc(d.name || d.device_id)}</span>
        <span class="dev-chip-meta">${esc(bits.join(' · '))}</span>
        <span class="dev-chip-actions">
          <select class="mini-btn" data-assign="${esc(d.device_id)}"
                  aria-label="${esc(t('Assign to customer'))}">${options}</select>
          <button type="button" class="mini-btn" data-open="${esc(d.device_id)}">${esc(t('Open'))}</button>
          <button type="button" class="mini-btn" data-report="${esc(d.device_id)}">${esc(t('Report'))}</button>
          <button type="button" class="mini-btn" data-del="${esc(d.device_id)}">${esc(t('Delete'))}</button>
        </span>
      </div>`;
  }

  function render() {
    // 서버가 예상 밖의 응답을 줘도 화면 전체가 죽으면 안 된다 — 이 렌더가
    // 예외를 던지면 app.js 로드가 통째로 중단돼 다른 화면까지 못 쓰게 된다
    // (릴리스 게이트인 jsdom 스모크가 실제로 여기서 멈췄다).
    const devices = Array.isArray(data && data.devices) ? data.devices : [];
    const custs = Array.isArray(data && data.customers) ? data.customers : [];
    const byCustomer = {};
    devices.forEach((d) => {
      (byCustomer[d.customer_id || ''] ||= []).push(d);
    });
    custList.innerHTML = custs.length
      ? custs.map((c) => `
        <div class="cust-card">
          <div class="cust-card-head">
            <span class="cust-card-name">${esc(c.name)}</span>
            <span class="cust-card-count">${esc(t('{n} device(s)', { n: c.device_count }))}</span>
            <button type="button" class="mini-btn" data-cust-report="${esc(c.id)}">${esc(t('Report'))}</button>
            <button type="button" class="mini-btn" data-cust-rename="${esc(c.id)}">${esc(t('Rename'))}</button>
            <button type="button" class="mini-btn" data-cust-del="${esc(c.id)}">${esc(t('Delete'))}</button>
          </div>
          <div class="cust-drop" data-customer="${esc(c.id)}" style="margin-top:8px">
            ${(byCustomer[c.id] || []).map(deviceChip).join('')
              || `<div class="cust-empty">${esc(t('Drop a device here'))}</div>`}
          </div>
        </div>`).join('')
      : `<div class="cust-empty">${esc(t('No customers yet — add one above.'))}</div>`;

    // 장비가 0대인데 '모두 배정됨'이라고 말하면 거짓이다. 빈 상태는 지금
    // 무엇이 없는지와 **다음에 무엇을 할지**를 같이 말해야 한다.
    unassigned.innerHTML = (byCustomer[''] || []).map(deviceChip).join('')
      || `<div class="cust-empty">${esc(t(devices.length
        ? 'Every registered device is assigned.'
        : 'No devices registered yet — go to Sources and register a device with '
          + 'its configuration file.'))}</div>`;
  }

  /* 드래그 리스너는 **한 번만** 단다. 렌더마다 붙이면 고정 요소인 미배정
     영역에 리스너가 쌓여, 장비를 한 번 놓았는데 배정 요청이 렌더 횟수만큼
     나간다(세션이 길수록 선형 증가). 위임으로 새로 그려진 칩도 커버한다. */
  view.addEventListener('dragstart', (e) => {
    const chip = e.target.closest && e.target.closest('.dev-chip');
    if (!chip || !e.dataTransfer) return;
    e.dataTransfer.setData('text/plain', chip.dataset.device);
    e.dataTransfer.effectAllowed = 'move';
  });
  view.addEventListener('dragover', (e) => {
    const zone = e.target.closest && e.target.closest('.cust-drop');
    if (!zone) return;
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  view.addEventListener('dragleave', (e) => {
    const zone = e.target.closest && e.target.closest('.cust-drop');
    if (zone) zone.classList.remove('drag-over');
  });
  /* 셀렉트로 배정 — 드래그와 **같은 함수**를 쓴다. 두 입구가 각자 요청을
     만들면 규칙이 갈라진다(이 루프에서 반복 확인된 실패 모드다). */
  view.addEventListener('change', async (e) => {
    const el = e.target;
    if (!el || !el.dataset || !el.dataset.assign) return;
    await assign(el.dataset.assign, el.value || null);
  });
  view.addEventListener('drop', async (e) => {
    const zone = e.target.closest && e.target.closest('.cust-drop');
    if (!zone || !e.dataTransfer) return;
    e.preventDefault();
    zone.classList.remove('drag-over');
    const id = e.dataTransfer.getData('text/plain');
    if (!id) return;
    await assign(id, zone.dataset.customer || null);
  });

  async function assign(deviceId, customerId) {
    const res = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/customer`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ customer_id: customerId }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      /* i18n-dynamic: 서버가 낸 거절 사유 — 쓰는 순간 번역돼 있다. */
      status.textContent = serverMsg(e, 'Could not assign that device.');
      return;
    }
    await refresh();
    /* 지금 보고 있는 장비의 고객사가 바뀌었으면 상단 상태바도 따라와야 한다 —
       배정하자마자 화면이 옛 소속을 말하면 그 표시를 믿을 수 없게 된다. */
    if (deviceId === currentDeviceId) {
      const c = (data.customers || []).find((x) => x.id === customerId);
      window.APO?.onCustomer?.(c ? c.name : '');
    }
  }

  async function refresh() {
    try {
      const res = await fetch('/api/devices');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      data = await res.json();
    } catch (err) {
      /* 조용히 return 하면 화면이 아무 설명 없이 영영 비어 있다. 등록한
         장비가 사라진 것처럼 보이는 게 이 화면에서 가장 나쁜 오해다.
         **개요 화면에도 알린다** — 보관소를 못 읽는데 첫 화면이 '아직
         아무것도 없습니다'를 띄우면, 사용자는 복구 가능한 파일을 지우거나
         전부 다시 입력한다(라운드 41 실측: 121대가 든 DB 를 손상시켰더니
         화면은 빈 설치처럼 보였다). */
      apoSetText(status, 
        'Could not read the device list. Your registered devices were not '
        + 'deleted — the store could not be opened. Close any other copy of '
        + 'APO that may be running, then restart.');
      window.APO?.onStoreError?.(status.textContent);
      return;
    }
    window.APO?.onStoreError?.('');
    render();
    renderSwitch();
    const devices = Array.isArray(data.devices) ? data.devices : [];
    const custs = Array.isArray(data.customers) ? data.customers : [];
    apoSetText(status, '{d} device(s) registered, {c} customer(s).',
               { d: devices.length, c: custs.length });
  }

  async function downloadScope(scope, id, label) {
    const st = document.getElementById('repStatus');
    st.textContent = `Building ${label} report...`;
    const res = await fetch('/api/reports/scope', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scope, id }),
    });
    if (!res.ok) {
      const msg = await serverMsgFrom(res, 'Report failed.');
      st.textContent = msg;
      /* 라이선스가 없어 막힌 것이면 **여는 방법까지** 준다. 사실만 적어 두면
         사용자는 여기서 막다른 길에 선다 — 다른 내보내기 버튼에는 이미
         라이선스 창이 연결돼 있는데 이 경로만 빠져 있었다(라운드 19 지적). */
      if (res.status === 402 || res.status === 403) {
        document.getElementById('licenseModal')?.classList.remove('hidden');
      }
      return;
    }
    /* 범위마다 파일명을 다르게 준다 — 고객사를 연달아 뽑으면 다운로드 폴더에
       같은 이름으로 쌓여 열기 전에는 구분할 수 없다. **이름은 서버가 정한
       것을 그대로 쓴다**: 화면에서 따로 만들었더니 규칙이 둘로 갈려, 한글
       고객사명이 통째로 지워지고(라운드 20) 60자 자르기로 두 고객이 같은
       이름이 되는 일이 이어졌다. */
    saveResponseAs(await res.blob(), res, 'apo_reports.zip');
    st.textContent = `Done — ${res.headers.get('X-Batch-Result') || ''} device(s). `
      + 'SUMMARY.txt inside lists every device.';
  }

  /* **합산은 한 곳에서만 한다.** 같은 식을 두 곳에 적어 뒀더니, 복원
     가드에서 dev 항을 지우는 변이가 계약 330개를 전부 통과했다. 세 번째
     카운터가 생기는 날 둘 중 하나가 빠진다 — 이 루프가 반복해서 맞은
     형태다("자리마다 다는 방식으로는 계속 샌다"). */
  window.__apoPendingCount = () =>
    (window.__apoMigPendingCount?.() || 0)
    + (window.__apoDevPendingCount?.() || 0);

  /* 진행 중인 개번 작업이 있으면 버리기 전에 묻는다. 값을 손으로 넣은
     것이라 되돌릴 방법이 없다. */
  window.__apoConfirmDiscardMigration = () => confirmDiscardMigration();

  function confirmDiscardMigration() {
    /* **두 흐름을 함께 센다.** IP 개번 값만 세면 장비 이관 사용자에게는
       확인창이 한 번도 안 뜬다(그 입력은 장비 이관 모드에서 숨겨지는
       카드 안에 있다). 문구도 "아직 파일로 만들지 않은"만 말하면 안 된다 —
       고른 대상 백업과 인터페이스 매핑도 함께 사라진다. */
    const n = window.__apoPendingCount?.() || 0;
    if (!n) return true;
    return confirm(t('Opening a device clears the migration work in progress '
                     + '({n} item(s) you entered). Continue?', { n: n }));
  }

  view.addEventListener('click', async (e) => {
    const el = e.target;
    if (el.dataset.open) {
      /* **잃을 것이 있으면 먼저 묻는다.** 이 클릭 하나에 진행 중인 개번
         작업이 통째로 날아간다 — 손으로 넣은 신 IP(/18 이면 1,494개),
         붙여넣은 계획 원문, 고른 대상 백업까지. 그 위험은 **다른** 장비를
         열 때도 똑같으므로 대상은 "같은 장비 재클릭"이 아니라 "진행 중
         입력이 있을 때"다(한 라운드 전에 표적을 잘못 잡았다). */
      if (!confirmDiscardMigration()) return;
      /* **요청은 항상 보낸다.** 화면의 기억만 보고 건너뛰면, 서버와 화면이
         어긋난 상태(APO 재시작 후 탭 생존·두 번째 창)에서 **"다시 열어라"는
         서버 지시를 수행할 방법이 사라진다** — 라운드 25 가 고친 결함을
         칩 버튼에 다시 만든 것이었다. 서버가 무엇을 열었는지는 응답이
         알려 준다. */
      const r = await fetch(`/api/devices/${encodeURIComponent(el.dataset.open)}/open`,
                            { method: 'POST' });
      if (!r.ok) { apoSetText(status, 'Could not open that device.'); return; }
      const d = await r.json();
      /* **특례를 두지 않는다.** `/open` 은 같은 장비여도
         `_drop_previous_device_traces()` 로 대상 백업·감사 타임라인·수집·
         조치·내보내기 이름을 **전부** 버린다. 그러니 화면도 항상 맞춘다.
         "같은 장비면 리셋을 건너뛴다"는 특례가 세 결함의 공통 원인이었다 —
         확인창이 지우지도 않을 것을 세어 겁줬고(toBe 는 안 지워졌다),
         세대를 안 올려 리셋이 늦은 응답에 되돌려졌고, 버려지는 키 다섯 중
         하나만 맞춰 감사 타임라인이 남아 내보내기가 400 이 됐다.
         잃는 것에 대한 보호는 **요청 전 확인창**이 맡는다. */
      adoptDeviceSession(d.session, d.device_name);
      applyLoadedConfig(d, { key: 'Opened {name}', vars: { name: d.device_name || d.filename || '' } },
        apoT('Opened {name}. Findings are not stored — run the assessment to '
             + 'see them.', { name: d.device_name || d.filename || '' }));
      window.__apoSetRanges?.((d.user_ranges || []).map((x) => x.cidr));
      apoSetText(status, 'Opened {name}.', { name: d.device_name || d.device_id });
      window.APO?.setView?.('overview');
      return;
    }
    if (el.dataset.del) {
      // 되돌릴 수 없다 — config 원문·사용량·대역·FQDN이 함께 사라진다.
      const chip = el.closest('.dev-chip');
      const label = chip?.querySelector('.dev-chip-name')?.textContent?.trim()
        || 'this device';
      /* **확인해 둔 장비 신원(시리얼)도 함께 사라진다는 것을 말한다.** 안
         말하면, 지웠다 다시 등록한 사용자는 조치 대상 확인이 왜 다시 뜨는지
         모른 채 습관적으로 누르게 된다 — 그 창이 유일한 방벽이다(라운드 30). */
      /* **진행 중인 이관 작업도 함께 사라진다** (B-88). 열려 있는 장비를
         지우면 `adoptDeviceSession({},'')` 가 손으로 넣은 신 IP·인터페이스
         매핑·고른 대상 백업까지 리셋한다. 삭제는 본질적으로 파괴 행위라
         조용한 손실은 아니지만, 확인창이 **지워지는 것 목록**을 열거하면서
         이것만 빠져 있었다 — 다른 여섯 경로와 문구를 맞춘다. */
      const _pend = window.__apoPendingCount?.() || 0;
      if (!confirm(t('Delete {name}? Its config, usage CSV, user ranges and FQDN '
                     + 'capture are removed from this computer, along with the '
                     + 'device identity APO confirmed for remediation — you will '
                     + 'have to confirm the target again. This cannot be undone.',
                     { name: label })
                   + (_pend
                      ? ' ' + t('The migration work in progress ({n} item(s) you '
                                + 'entered) is discarded as well.', { n: _pend })
                      : ''))) return;
      /* **이 탭이 실제로 보고 있는 장비**와 견준다. 캐시된 목록(data)의
         open_device_id 로만 판단했더니, 사이드바 전환기로 연 장비를 여기서
         지웠을 때 그 값이 아직 옛 장비여서 화면 정리가 통째로 건너뛰어졌다 —
         지워진 장비의 이름·칩·판정 표가 그대로 남아 있었다(라운드 28 실측). */
      const wasOpen = el.dataset.del === (currentDeviceId || data.open_device_id);
      await fetch(`/api/devices/${encodeURIComponent(el.dataset.del)}`, { method: 'DELETE' });
      /* 삭제도 **장비를 바꾸는 경로**다 — 다른 다섯 경로와 같은 함수를 지난다.
         beginNewDevice 만 부르던 동안에는 CSV 출처 패널에 지워진 고객의
         파일명·SHA 가 그대로 남았고, 같은 화면이 서로 다른 장비 셋을 동시에
         말했다(라운드 23 실측). 빈 세션을 채택해 화면을 사실에 맞춘다. */
      if (wasOpen) {
        adoptDeviceSession({}, '');
        beginNewDevice();
        restoreTried = false;
      }
      await refresh();
      return;
    }
    if (el.dataset.report) {
      const name = el.closest('.dev-chip')?.querySelector('.dev-chip-name')
        ?.textContent?.trim();
      await downloadScope('device', el.dataset.report, name || 'device');
      return;
    }
    if (el.dataset.custReport) {
      const name = el.closest('.cust-card')?.querySelector('.cust-card-name')
        ?.textContent?.trim();
      await downloadScope('customer', el.dataset.custReport, name || 'customer');
      return;
    }
    if (el.dataset.custRename) {
      // 고객사명은 모든 리포트 zip 엔트리의 접두어다 — 오타가 산출물에 박힌다.
      const card = el.closest('.cust-card');
      const was = card?.querySelector('.cust-card-name')?.textContent?.trim() || '';
      const next = prompt(t('Customer name — this prefixes every report file for '
                            + 'this customer.'), was);
      if (next === null || next.trim() === was) return;
      const res = await fetch(`/api/customers/${encodeURIComponent(el.dataset.custRename)}/rename`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: next.trim() }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        /* i18n-dynamic: 서버가 낸 거절 사유 — 쓰는 순간 번역돼 있다. */
        status.textContent = serverMsg(e, 'Could not rename that customer.');
        return;
      }
      await refresh();
      return;
    }
    if (el.dataset.custDel) {
      const label = el.closest('.cust-card')?.querySelector('.cust-card-name')
        ?.textContent?.trim() || 'this customer';
      if (!confirm(t('Delete {name}? Its devices stay registered — only the '
                     + 'grouping is removed.', { name: label }))) return;
      await fetch(`/api/customers/${encodeURIComponent(el.dataset.custDel)}`,
                  { method: 'DELETE' });
      await refresh();
    }
  });

  document.getElementById('custAddBtn')?.addEventListener('click', async () => {
    const input = document.getElementById('custNewName');
    const name = (input.value || '').trim();
    if (!name) {
      // 아무 반응 없이 삼키면 사용자는 버튼이 고장 났다고 읽는다.
      apoSetText(status, 'Type a customer name first, then press Add customer.');
      input.focus();
      return;
    }
    const res = await fetch('/api/customers', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      /* i18n-dynamic: 서버가 낸 거절 사유 — 쓰는 순간 번역돼 있다. */
      status.textContent = serverMsg(e, 'Could not add that customer.');
      return;
    }
    input.value = '';
    await refresh();
  });

  document.getElementById('repAllBtn')?.addEventListener('click',
    () => downloadScope('all', null, 'all devices'));

  /* 앱을 다시 열면 **화면이 서버가 열고 있는 장비를 그대로 채택한다.**

     이게 없으면 화면은 '설정 파일이 없다'고 말하는데 서버는 직전 장비를
     들고 있는 어긋난 상태가 된다. 그 상태에서 사용자가 IP 대역을 입력하면,
     화면에 이름조차 보이지 않는 장비의 저장된 대역이 통째로 교체된다.
     대역은 user/server 트래픽을 가르는 판정 입력이고 이력이 남지 않아
     되돌릴 수도 없다 — 다음 날 B고객 대역을 친 것이 A고객 장비의 기준을
     바꿔 놓는다. 마법사의 '임시저장 후 재개'가 재시작 뒤 1단계로 되돌아가던
     것도 같은 어긋남이었다. */
  let restoreTried = false;
  /* **`currentDeviceId` 가 비었다는 것이 "잃을 것이 없다"는 뜻은 아니다.**
     13라운드는 이 경로를 `!currentDeviceId` 가드 때문에 확인창에서 뺐는데,
     P2 가 만드는 상태가 정확히 그것이었다 — 취소로 작업을 지킨 사람이
     사이드바를 한 번 누르면 장비가 다시 열리며 **말없이 전부 지워졌다**.
     파싱 실패 경로도 같은 상태를 남긴다(14라운드 P2b). */
  async function restoreOpenDevice() {
    /* **성공했을 때만 시도를 소진한다.** 처음에 restoreTried 를 먼저 세웠더니,
       장비 목록 조회나 /open 이 한 번만 실패해도 다시는 복원을 시도하지 않아
       화면과 서버가 영영 어긋난 채로 남았다. 그 상태에서 입력한 대역이
       보이지도 않는 장비의 대역을 지웠다(라운드 16 실측). */
    if (restoreTried || currentDeviceId) return;
    /* 앱을 다시 켠 직후에는 서버에도 열린 장비가 없다. 그렇다고 빈 화면으로
       시작하면 "어제 하던 것"이 사라진 것처럼 보인다 — 보관소에는 그대로
       있는데도. 가장 최근에 손댄 장비를 이어받는다. */
    const id = data && (data.open_device_id || data.resume_device_id);
    if (!id) return;   // 목록을 못 읽었을 수도 있다 — 다음 기회에 다시 본다
    /* **진행 중 작업이 있으면 복원하지 않는다.** `currentDeviceId` 가
       비었다는 것이 "잃을 것이 없다"는 뜻은 아니다 — 파일 선택을 취소했거나
       파싱이 실패해 장비만 닫힌 상태에서도 이관 작업은 메모리에 그대로
       있다. 그때 사이드바를 한 번 누르면 여기가 돌아 **말없이 전부**
       지웠다. 복원은 "어제 하던 것"을 이어 주려는 편의이지, 지금 하던
       것을 밟을 이유가 없다. */
    if ((window.__apoPendingCount?.() || 0) > 0) return;
    try {
      const r = await fetch(`/api/devices/${encodeURIComponent(id)}/open`,
                            { method: 'POST' });
      if (!r.ok) return;
      const d = await r.json();
      restoreTried = true;
      adoptDeviceSession(d.session, d.device_name);
      applyLoadedConfig(d, { key: 'Reopened {name} — the device you were working on',
                         vars: { name: d.device_name || d.filename || '' } },
        // 설정은 바뀌지 않았다. 결과는 이 앱이 판정을 저장하지 않기 때문에
        // 비어 있는 것뿐이다 — 그 사실을 그대로 말한다.
        // 같은 문장을 두 곳에서 미묘하게 다르게 적어 두면 사전 키도 갈린다 —
        // 한쪽만 번역되고 다른 쪽은 영어로 남는다(라운드 33).
        apoT('Reopened {name}. Findings are not stored — run the assessment to '
             + 'see them.', { name: d.device_name || d.filename || '' }));
      window.__apoSetRanges?.((d.user_ranges || []).map((x) => x.cidr));
      announceSourceState();
    } catch (_) { /* 다음 갱신 때 다시 시도한다 */ }
  }

  // 장비 목록이 바뀌는 모든 지점에서 다시 읽는다. 복원도 그때마다 다시 본다 —
  // 아직 못 이어받았다면 여기가 두 번째 기회다.
  /* Sources 화면의 장비 전환 드롭다운. 목록·열기 모두 이 화면과 같은 API를
     쓰므로 규칙이 갈라지지 않는다. */
  const switchSel = document.getElementById('deviceSwitch');
  const switchRow = document.getElementById('deviceSwitchRow');
  function renderSwitch() {
    if (!switchSel || !switchRow) return;
    const devices = Array.isArray(data && data.devices) ? data.devices : [];
    switchRow.style.display = devices.length > 1 ? '' : 'none';
    const openId = (data && data.open_device_id) || currentDeviceId || '';
    switchSel.innerHTML = devices.map((d) => {
      const bits = [d.name || d.device_id];
      if (d.config_filename) bits.push(d.config_filename);
      if (d.config_sha256) bits.push(String(d.config_sha256).slice(0, 8));
      return `<option value="${esc(d.device_id)}"${
        d.device_id === openId ? ' selected' : ''}>${esc(bits.join(' · '))}</option>`;
    }).join('');
  }
  switchSel?.addEventListener('change', async () => {
    const id = switchSel.value;
    if (!id || id === currentDeviceId) return;
    /* **형제 경로에도 같은 확인이 필요하다.** 칩 Open 에만 달았더니,
       "그 위험은 다른 장비를 열 때도 똑같다"고 적어 둔 주석이 정작 다른
       장비를 여는 이 컨트롤에서는 지켜지지 않았다. */
    if (!window.__apoConfirmDiscardMigration?.()) { renderSwitch(); return; }
    const r = await fetch(`/api/devices/${encodeURIComponent(id)}/open`,
                          { method: 'POST' });
    if (!r.ok) { renderSwitch(); return; }
    const d = await r.json();
    adoptDeviceSession(d.session, d.device_name);
    applyLoadedConfig(d, { key: 'Opened {name}', vars: { name: d.device_name || d.filename || '' } },
      t('Opened {name}. Findings are not stored — run the assessment to see them.',
        { name: d.device_name || d.filename || '' }));
    window.__apoSetRanges?.((d.user_ranges || []).map((x) => x.cidr));
    // 마법사·상태 표시도 이 장비로 따라오게 한다 — 안 부르면 등록 마법사가
    // 앞 장비 상태를 그대로 보여 준다.
    announceSourceState();
    await refresh();
  });

  const refreshAndRestore = () => refresh().then(restoreOpenDevice);
  // 입력 상태가 바뀌는 모든 지점이 복원의 다음 기회다 — 고객사 화면 클릭에만
  // 걸어 두면 그 화면에 가지 않는 사용자는 계속 어긋난 채로 작업한다.
  document.addEventListener('apo:sources-changed', refreshAndRestore);
  document.querySelector('.side-item[data-view="customers"]')
    ?.addEventListener('click', refreshAndRestore);
  refreshAndRestore();
})();

/* ISDB·geography 진단 버튼(v85~v103)은 UI에서 뺐다 — 파서 개발용으로 실물
   응답 형태를 걷는 도구였지, 사용자 기능이 아니다(Jayden 지시, 2026-08-12).
   서버 라우트 /api/collect/probe는 지원 진단용으로 남겨 둔다. */

(() => {
  const btn = document.getElementById('collectBtn');
  const st = document.getElementById('collectStatus');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const ip = document.getElementById('collIp')?.value.trim();
    const token = document.getElementById('collToken')?.value.trim();
    if (!ip || !token) { if (st) st.textContent = apoT('Enter the device IP and API token.'); return; }
    /* **수집도 장비를 바꾸는 경로다** — 이후 `adoptDeviceSession` 이 진행 중
       이관 작업을 전부 지운다. 다섯 경로 중 이 자리가 빠져 있었다(13라운드 P6). */
    if (!window.__apoConfirmDiscardMigration?.()) return;
    if (st) st.textContent = apoT('Connecting and collecting (config, stats, FQDNs)...');
    btn.disabled = true;
    try {
      const res = await fetch('/api/collect/device', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          ip, token,
          port: Number(document.getElementById('collPort')?.value || 443),
          verify_ssl: !(document.getElementById('collSkipSsl')?.checked),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(serverMsg(data, 'Collection failed'));
      // 수집도 장비 등록이다 — 이후 CSV는 이 장비에만 붙는다(파일 경로와 동일).
      adoptDeviceSession(data.session, data.device_name || data.hostname || ip);
      applyLoadedConfig(data, { key: 'Collected from {name}', vars: { name: data.hostname || ip } });
      /* 수집 경로의 유일한 성공 확인 문장 — 번역 통로 밖 하드코딩이라
         한국어 모드에서 항상 영어였다(2026-08-25 전면 검토 M-1). */
      let msg = apoT('Collected: {p} policies, hit count / last used for {s}, {f} FQDN resolutions.',
                     { p: data.policies, s: data.stats_count, f: data.fqdn_count });
      /* i18n-dynamic: 서버 경고 원문 병기(관례) */
      if ((data.warnings || []).length) msg += ' Note: ' + data.warnings.join('; ');
      if (st) st.textContent = msg;
      /* 같은 장비에 적용하려는 사용자가 IP·포트를 다시 치지 않게 조치
         폼을 프리필한다(2026-08-25 M-7 — 시리얼 확인 절차는 그대로다.
         토큰은 보안상 프리필하지 않는다). 이미 값이 있으면 안 덮는다. */
      const _remIpEl = document.getElementById('remIp');
      const _remPortEl = document.getElementById('remPort');
      if (_remIpEl && !_remIpEl.value.trim()) _remIpEl.value = ip;
      if (_remPortEl && !_remPortEl.value.trim()) {
        _remPortEl.value = String(Number(document.getElementById('collPort')?.value || 443));
      }
    } catch (err) {
      if (st) st.textContent = err.message || apoT('Collection failed');
    } finally { btn.disabled = false; }
  });
})();

configFileInput.addEventListener('change', async () => {
  const file = configFileInput.files?.[0];
  if (!file) { selectedConfigName.textContent = apoT('No file selected');
               beginNewDevice(); return; }
  /* **가드는 부작용보다 앞에 있어야 한다.** 이 확인창을 `beginNewDevice()`
     뒤에 뒀더니, 취소한 사람이 작업을 메모리에 갖고도 **쓸 수 없게** 됐다 —
     `currentDeviceId` 가 이미 null 이라 이후 모든 이관 요청이
     `409 input_no_device` 로 막히고, 파일 입력값이 남아 같은 파일을 다시
     골라도 `change` 가 안 뜬다. 확인창은 진행 중 작업이 있을 때만 뜨므로
     취소하는 사람은 **정의상 지킬 것이 있는 사람**이다(14라운드 P2). */
  if (!window.__apoConfirmDiscardMigration?.()) {
    // 고른 적 없는 상태로 되돌린다 — 안 그러면 화면은 새 파일명을 보여
    // 주는데 열린 장비는 옛것이고, 재시도조차 막힌다.
    configFileInput.value = '';
    return;
  }
  selectedConfigName.textContent = file.name;
  // 새 설정 파일을 고른 순간부터 이전 장비의 CSV는 남의 것이다 — 파싱 결과를
  // 기다리지 않고 바로 잠근다.
  beginNewDevice();

  const formData = new FormData();
  formData.append('config_file', file);
  apoSetText(configStatus, 'Parsing config...');

  let res, data;
  try {
    res = await fetch('/api/config/parse', { method: 'POST', body: formData });
    data = await res.json().catch(() => ({}));
  } catch (err) {
    apoSetText(configStatus, 'Failed to parse config (network error)');
    return;
  }

  if (!res.ok) {
    /* i18n-dynamic: 서버가 낸 거절 사유 — 쓰는 순간 번역돼 있다. */
    configStatus.textContent = serverMsg(data, 'Failed to parse config');
    return;
  }

  currentParsed = data.parsed;
  currentView = data.view;
  currentRuntimeStats = {};
  // 사용량 출처도 이 장비의 것으로 교체한다. 안 바꾸면 새 장비 화면에 앞
  // 장비의 CSV 파일명이 그대로 남아, 그 파일이 이 판정의 근거인 것처럼 읽힌다.
  currentCsvMeta = Array.isArray(data.csv_meta) ? data.csv_meta : [];
  fwCsvSummary = null;
  proxyCsvSummary = null;
  if (selectedFwCsvName) selectedFwCsvName.textContent = apoT('No file selected');
  if (selectedProxyCsvName) selectedProxyCsvName.textContent = apoT('No file selected');
  resetPolicyFilters();
  apoSetText(configStatus, 'Loaded {name}', { name: data.filename });
  apoSetText(policyStatsStatus, 'Upload Firewall Policy CSV or Proxy Policy CSV.');
  renderPolicyCsvSummary();
  downloadBox.innerHTML = `<a href="/exports/${encodeURIComponent(data.export_json || '')}">`
    + escapeHtml(apoT('Download parsed JSON')) + '</a>';
  renderMeta(data.view?.meta || {});
  updatePolicyFilterVisibility();
  renderActiveTab();
  // 장비 등록 완료 — 이제 이 장비의 CSV만 받는다. 장비 종속 상태는 전부
  // 이 한 함수가 맞춘다(대역 칩도 여기 포함).
  adoptDeviceSession(data.session, data.device_name || data.filename);
  announceSourceState();
  notifyConfigLoaded({ key: 'Uploaded {name}', vars: { name: data.filename } },
                     data.filename, data.config_sha);
});

async function importPolicyCsv(file, type) {
  if (!file) return;
  const formData = new FormData();
  formData.append('policy_stats_files', file);
  /* 어느 종류의 정책 통계인지 반드시 알려야 한다. FortiGate는 firewall과
     proxy 정책에 각각 1번부터 번호를 매겨서, 종류 없이 합치면 proxy 7번의
     사용 이력이 firewall 7번에 얹힌다 — 살아 있는 정책이 "미사용"으로 바뀌어
     Critical로 판정되고 장비 적용 후보에까지 오른다. */
  formData.append('policy_type', type === 'FW' ? 'firewall' : 'proxy');
  /* 어느 장비의 CSV인지 함께 보낸다. 그 사이에 다른 설정 파일이 열렸다면
     서버가 409로 막는다 — 화면 게이트만으로는 경합을 못 막는다. */
  if (currentDeviceId) formData.append('device_id', currentDeviceId);
  /* **다중 VDOM 이면 어느 VDOM 의 내보내기인지 물어본다.** FortiGate 는 VDOM
     마다 정책 번호를 1번부터 다시 매기고 GUI 의 Export to CSV 는 지금 서 있는
     VDOM 만 내보낸다. 안 물어보면 root 의 사용량이 CORP·DMZ 의 같은 번호
     정책에 얹혀, 한 번도 측정한 적 없는 정책이 "미사용"으로 인쇄된다
     (라운드 49). 서버도 같은 이유로 거절하므로, 여기서 안 물으면 사용자는
     화면만으로는 넘어갈 수 없는 409 를 만난다. */
  const vdoms = ((currentView && currentView.meta && currentView.meta.vdoms) || [])
    .filter(Boolean);
  if (vdoms.length > 1) {
    const picked = window.prompt(apoT(
      'Which VDOM was this CSV exported from? This configuration has: {vdoms}',
      { vdoms: vdoms.join(', ') }), vdoms[0]);
    if (picked === null) {
      apoSetText(policyStatsStatus, 'Import cancelled.');
      return;
    }
    formData.append('vdom', picked);
  }
  apoSetText(policyStatsStatus, 'Importing {type} CSV for {name}...', { type, name: currentDeviceName || apoT('this device') });

  /* 이 응답은 `currentRuntimeStats` 에 **병합**된다 — 사용량 칩과 정책표
     조인이 그 dict 를 본다. 늦게 오면 앞 고객 히트카운트가 다음 장비 표에
     섞인다(재비판 4라운드 발견 5). */
  const fresh = apoStillThisInput();
  let res, data;
  try {
    res = await fetch('/api/policy-stats/import', { method: 'POST', body: formData });
    data = await res.json().catch(() => ({}));
    if (!fresh()) return;
  } catch (err) {
    apoSetText(policyStatsStatus, 'Failed to import {type} CSV (network error)', { type });
    return;
  }

  if (!res.ok) {
    const msg = serverMsg(data, apoT('Failed to import {type} CSV', { type }));
    /* i18n-dynamic: 서버가 낸 거절 사유 — 쓰는 순간 번역돼 있다. */
    policyStatsStatus.textContent = msg;
    /* 실패가 화면 밖에 있으면 없는 것과 같다 — 파일을 고른 그 슬롯이
       정상일 때와 똑같이 보였고, 사유는 뷰포트 아래 127px 지점에 있었다
       (라운드 23 실측). 슬롯 자체에 실패를 적고 그 자리로 데려간다. */
    const slot = type === 'FW' ? selectedFwCsvName : selectedProxyCsvName;
    if (slot) {
      slot.textContent = `${file.name} — ${apoT('not imported')}`;
      slot.classList.add('is-error');
    }
    policyStatsStatus.scrollIntoView({ block: 'center', behavior: 'smooth' });
    return;
  }
  [selectedFwCsvName, selectedProxyCsvName].forEach((el) =>
    el?.classList.remove('is-error'));

  // 화면 쪽 병합도 **서버와 같은 규칙**을 따른다(사용량 칩·근거 패널·정책
  // 표가 이 dict 를 본다). 라운드 58: 세 가지가 갈라져 있었다 —
  // ① `_vdom` 태그를 안 붙여 다중 VDOM 에서 /api/policies/render 조인이
  //    전량 폐기됐고(임포트 직후 표의 hit 이 전부 '-'), 칩의 한정 문장도
  //    안 떴다. ② 서버가 VDOM 교체로 wipe 한 기존 행을 화면은 보존해
  //    두 VDOM 행이 공존했다. ③ 평평(붙여넣기) 상태를 서버는 승격해
  //    보존하는데 화면은 버렸다.
  {
    const ns = type === 'FW' ? 'firewall' : 'proxy';
    const replaced = String((data.summary || {}).replaced_vdom || '');
    let cur;
    if (replaced) {
      cur = { firewall: {}, proxy: {} };          // 서버가 wipe 했다 — 화면도
    } else if (currentRuntimeStats
               && (currentRuntimeStats.firewall || currentRuntimeStats.proxy)) {
      cur = currentRuntimeStats;
    } else if (currentRuntimeStats && Object.keys(currentRuntimeStats)
               .some((k) => k !== '_vdom')) {
      /* 평평한 옛 상태(붙여넣기) → 종류별 승격. 서버(server.py 승격 규칙)와
         동일: 종류를 몰라 양쪽에 적용했던 것이므로 양쪽에 복사한다.
         `_vdom` 꼬리표는 행이 아니다 — 같이 복사하면 서버가 라운드 57 에
         막은 네임스페이스 오염의 화면판이 된다. */
      const flat = {};
      for (const k of Object.keys(currentRuntimeStats)) {
        if (k !== '_vdom') flat[k] = currentRuntimeStats[k];
      }
      cur = { firewall: flat, proxy: { ...flat } };
    } else {
      cur = { firewall: {}, proxy: {} };
    }
    currentRuntimeStats = {
      firewall: { ...(cur.firewall || {}) },
      proxy: { ...(cur.proxy || {}) },
    };
    currentRuntimeStats[ns] = { ...currentRuntimeStats[ns], ...(data.runtime_stats || {}) };
    /* 서버가 이 CSV 의 VDOM 귀속을 확정했으면 화면 통계에도 단다 —
       조인(_scoped)·칩(_statsCount)·한정 문장이 전부 이 태그를 본다. */
    const tag = String((data.summary || {}).vdom || '');
    if (tag) currentRuntimeStats._vdom = tag;
  }

  if (type === 'FW') {
    fwCsvSummary = { summary: data.summary, filename: file.name };
  } else {
    proxyCsvSummary = { summary: data.summary, filename: file.name };
  }
  if (Array.isArray(data.csv_meta)) currentCsvMeta = data.csv_meta;

  renderPolicyCsvSummary();
  // 어느 장비에 붙었는지 말한다 — 여러 장비를 연달아 등록할 때 이 한 줄이
  // "지금 이 CSV가 어디로 갔는지"를 유일하게 확인해 주는 곳이다.
  apoSetText(policyStatsStatus, 
    '{type} Policy CSV applied to {name}: {file}',
    { type, name: currentDeviceName || apoT('this device'), file: file.name });
  /* 일부만 맞는 CSV도 그대로 판정에 들어간다 — 안 맞는 행은 이 config에 없는
     정책이므로 다른 장비 파일이 섞였다는 신호다. 통계는 합쳐지기만 하고
     되돌릴 수단이 필요하므로, 사실을 말하고 지우는 방법을 함께 알린다. */
  if (data.summary && data.summary.unmatched) {
    /* V2(라운드 59) 후 unmatched 는 "지정 VDOM 에 없는 번호"다 — 다른 VDOM
       에는 존재할 수 있으므로 "이 설정에 없는"이라 단정하면 거짓이 된다
       (라운드 60 계약 렌즈). VDOM 지정 시 문장을 정확히 가른다. */
    /* i18n-dynamic: 조건부로 이어붙는 문장 — 조각마다 apoT 를 지난다. */
    policyStatsStatus.textContent += ' ' + (data.summary.vdom
      ? apoT('Warning: {bad} of {all} rows are policy IDs not found in VDOM '
        + '{vdom} — they may belong to another VDOM or another device. If '
        + 'this file came from elsewhere, use "Clear usage data for this '
        + 'device" and import the right one.',
        { bad: data.summary.unmatched, all: data.summary.count,
          vdom: data.summary.vdom })
      : apoT('Warning: {bad} of {all} rows are policy IDs this configuration does not '
        + 'have. If this file came from another device, use "Clear usage data for '
        + 'this device" and import the right one.',
        { bad: data.summary.unmatched, all: data.summary.count }));
  }
  /* 다른 VDOM(또는 귀속 불명 레거시)의 기존 통계를 갈아 끼웠다면 그 사실을
     말한다 — 서버는 라운드 57 부터 응답에 적었는데 화면이 소비하지 않아
     사용자 관점에서는 조용한 소실이었다(라운드 58 계약 렌즈). */
  /* i18n-dynamic: 조건부로 이어붙는 문장 — 조각마다 apoT 를 지난다. */
  if (data.summary && data.summary.replaced_vdom) {
    policyStatsStatus.textContent += ' ' + apoT(
      'Note: usage data previously loaded for VDOM {vdom} was replaced — '
      + 'policy numbers overlap across VDOMs, so only one VDOM\'s usage can '
      + 'be loaded at a time.',
      { vdom: data.summary.replaced_vdom === '(untagged)'
          ? apoT('(unattributed)') : `'${data.summary.replaced_vdom}'` });
  }
  window.APO?.onUsage?.(_statsCount(currentRuntimeStats),
    String((currentRuntimeStats || {})._vdom || ''),
    _statsUsable(currentRuntimeStats, currentView));
  announceSourceState();
  await rerenderWithRuntimeStats();
  /* **막대에 내용을 만들어 주는 유일한 조작이 이것이다.** 장비를 열 때만
     읽게 해 놨더니, 방금 CSV 를 올린 사용자에게 화면이 "사용량 CSV 를 먼저
     올리세요" 라고 말했다 — 서버는 이미 분포를 갖고 있었다(5라운드 F-F).
     `csvClearBtn` 도 같은 함수를 지나므로 지웠을 때도 따라온다. */
  window.__apoThHistogram?.();

  /* severity 결과가 있으면 자동 재분류 (sevData는 다른 IIFE 스코프이므로 window
     플래그로 감지). 실패는 Findings의 상태줄에만 뜨는데 사용자는 지금 Sources에
     있다 — 여기 "적용됨" 초록 문구만 보고 재판정이 됐다고 믿게 된다. 결과를
     확인해서 이 화면에도 알린다. */
  if (window.__sevHasData) {
    if (typeof window.__apoRunClassify === 'function') {
      await window.__apoRunClassify();
      if (!window.__sevHasData) {
        const why = document.getElementById('sevClassifyStatus')?.textContent || '';
        apoSetText(policyStatsStatus,
          '{type} Policy CSV imported, but re-assessment failed — the '
          + 'findings still reflect the previous run. {why}',
          { type, why });
      }
    }
  }
}

document.getElementById('csvClearBtn')?.addEventListener('click', async () => {
  const st = document.getElementById('csvClearStatus');
  const label = currentDeviceName || 'this device';
  if (!confirm(apoT('Remove the hit count / last used data stored for {name}? '
                    + 'The configuration and IP ranges stay. This only clears what '
                    + 'is on this computer.', { name: label }))) return;
  /* **가드가 아예 없었다.** 이 응답은 사용량 칩·요약·통계 메모리를 비우고
     재렌더·재판정까지 돌린다. A 에서 누른 삭제가 늦게 오면 **B 화면의
     사용량이 사라지고** "DEMO-FGT-01의 사용량 데이터를 지웠습니다" 라고
     통보한다 — B 사용자가 하지도 않은 조작이다. 서버에는 그대로 있으므로
     한 화면이 동시에 모순된다: 칩은 "없음", 바로 위 분포 막대는 "9건은
     기록 있음"(7라운드 F4 실측). */
  const fresh = apoStillThisDevice();
  try {
    const r = await fetch('/api/policy-stats', {
      method: 'DELETE', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: currentDeviceId || undefined }),
    });
    if (!fresh()) return;
    if (!r.ok) {
      throw new Error(await serverMsgFrom(r, 'Could not clear the usage data.'));
    }
    currentRuntimeStats = {};
    currentCsvMeta = [];
    fwCsvSummary = null;
    proxyCsvSummary = null;
    if (selectedFwCsvName) selectedFwCsvName.textContent = apoT('No file selected');
    if (selectedProxyCsvName) selectedProxyCsvName.textContent = apoT('No file selected');
    renderPolicyCsvSummary();
    if (st) st.textContent = apoT('Usage data cleared for {name}.', { name: label });
    apoSetText(policyStatsStatus, 'Upload Firewall Policy CSV or Proxy Policy CSV.');
    window.APO?.onUsage?.(0);
    announceSourceState();
    await rerenderWithRuntimeStats();
    window.__apoThHistogram?.();   // 지운 것도 분포에 반영된다
    // 판정이 이미 있으면 다시 낸다 — 사용량을 지웠는데 옛 판정이 남으면
    // 화면이 지금 근거로는 설명할 수 없는 결과를 보여준다.
    if (window.__sevHasData && typeof window.__apoRunClassify === 'function') {
      await window.__apoRunClassify();
    }
  } catch (err) {
    // 서버가 준 사유를 그대로 보인다 — '실패'로 뭉뚱그리면 다른 장비를 열어야
    // 한다는 사실이 사라진다.
    if (st) st.textContent = err.message || apoT('Could not clear the usage data.');
  }
});

fwPolicyCsvFile.addEventListener('change', async () => {
  const file = fwPolicyCsvFile.files?.[0];
  if (selectedFwCsvName) selectedFwCsvName.textContent = file ? file.name : 'No file selected';
  await importPolicyCsv(file, 'FW');
});

proxyPolicyCsvFile.addEventListener('change', async () => {
  const file = proxyPolicyCsvFile.files?.[0];
  if (selectedProxyCsvName) selectedProxyCsvName.textContent = file ? file.name : 'No file selected';
  await importPolicyCsv(file, 'Proxy');
});

async function rerenderWithRuntimeStats() {
  if (!currentParsed) return;
  /* **이 결과는 화면에만 남지 않는다.** `currentView` 에 들어가고, CSV·워크북
     내려받기가 그 값으로 파일을 만들면서 **이름만 지금 열린 장비로** 찍는다.
     실측(5라운드 F-A): `firewall_policy_DEMO-FGT-01_f7d6a1fb.csv`(=B) 안에
     A 의 정책과 히트카운트가 들어갔다. 화면 잔상이 아니라 산출물이다.
     `importPolicyCsv` 가 fetch 직후에만 묻고 여기는 안 물었다. */
  const fresh = apoStillThisInput();
  try {
    const renderRes = await fetch('/api/policies/render', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ parsed: currentParsed, runtime_stats: currentRuntimeStats })
    });
    if (!renderRes.ok) {
      const err = await renderRes.json().catch(() => ({}));
      /* i18n-dynamic: 서버가 낸 거절 사유 — 쓰는 순간 번역돼 있다. */
      if (policyStatsStatus) policyStatsStatus.textContent =
        serverMsg(err, apoT('Could not apply the CSV to the loaded configuration.'));
      return;
    }
    const renderData = await renderRes.json();
    if (!renderData.view) {
      apoSetText(policyStatsStatus,
                 'The server sent no data back, so the CSV was not applied.');
      return;
    }
    if (!fresh()) return;          // 늦게 왔다 — 남의 장비 정책표다
    currentView = renderData.view;
    renderMeta(renderData.view?.meta || {});
    renderActiveTab();
  } catch (e) {
    if (policyStatsStatus) apoSetText(policyStatsStatus, 'CSV apply failed: {detail}', { detail: e.message });
  }
}

function resetPolicyFilters() {
  filterDisabled.checked = false;
  filterHitZero.checked = false;
  filterDormantYear.checked = false;
  filterExpiredSchedule.checked = false;
  filterNoItsRequest.checked = false;
  filterDeletable.checked = false;
  tableFilter.value = '';
}

function renderMeta(meta) {
  const items = [
    ['Name', meta.hostname || '-'],
    ['Policies', meta.policy_count ?? 0],
    ['Proxy Policies', meta.proxy_policy_count ?? 0],
    ['Address', meta.address_count ?? 0],
    ['Addrgrp', meta.addrgrp_count ?? 0],
    ['Proxy Address', meta.proxy_address_count ?? 0],
    ['Proxy Addrgrp', meta.proxy_addrgrp_count ?? 0],
    ['Service Custom', meta.service_custom_count ?? 0],
    ['Service Group', meta.service_group_count ?? 0],
    ['Interface', meta.interface_count ?? 0],
  ];
  /* **파서가 못 읽은 것을 화면이 말한다.** `parse_warnings` 는 줄곧
     만들어졌지만 워크북 마지막 시트로만 나갔다 — 잘린 백업에서 정책이
     통째로 빠져도 화면은 아무 말이 없었고, 감사자는 그 정책이 없는 줄
     알았다(라운드 42 지적). 판정에서 빠졌다는 사실이 판정 화면에 있어야 한다. */
  const _warn = meta.parse_warnings || [];
  if (_warn.length) {
    const dropped = _warn.filter(w => /without 'next'/.test(w.warning || '')).length;
    /* **잘림은 일반 문구로 뭉개지 않는다**(라운드 70). B-63(섹션 밖 잘림 —
       VDOM 오귀속 가능)과 EOF 잘림은 "1줄을 못 읽었다"가 아니라 "백업이
       잘렸다"가 핵심인데, 이 분기가 dropped 만 보고 있어 그 경고들이
       워크북을 열어야만 보였다. 파서의 두 잘림 경고는 모두 'looks
       truncated' 를 담는다 — 그 사실로 분기한다. */
    const truncated = _warn.some(w => /looks truncated/.test(w.warning || ''));
    /* **"못 읽었다" 와 "안 읽는다" 는 다르다.** IPv6 처럼 APO 가 의도적으로
       다루지 않는 섹션까지 "읽지 못했습니다 — 워크북의 경고 시트를 보세요"
       로 뭉뚱그렸다. 그러면 ① 도구가 고장난 것처럼 보이고 ② 해법이 **유료**
       산출물을 가리킨다. 하필 동봉한 데모 설정이 이 경고를 낸다 — 처음 쓰는
       고객의 첫인상이 "벤더 데모도 깨끗이 안 읽힌다" 가 된다(8라운드 F4).
       파서가 이미 사람이 읽을 사유 문장을 만들어 두었으므로 **그 자리에서**
       보여 준다. 유료 파일을 열 필요가 없다. */
    const _unsupported = _warn.filter(
      w => /does not read that section/i.test(w.warning || ''));
    const _scopeOnly = _unsupported.length === _warn.length && !dropped && !truncated;
    if (!_scopeOnly) items.unshift([apoT('Not read'), String(_warn.length)]);
    const box = document.getElementById('configStatus');
    if (box && _scopeOnly) {
      /* 판정에서 빠진 것은 사실이므로 말은 하되, 결함이 아니라 **범위**임을
         분명히 한다. 경고색을 쓰지 않는다. */
      box.classList.remove('is-warning');
      /* **파서의 영어 문장을 그대로 쓰면 한국어 화면에 영어가 뜬다.**
         첫인상을 고치려던 수정이 첫 화면에 영어를 올렸다(9라운드 F8).
         섹션 이름(`content`)만 값으로 끼우고 문장은 여기서 만든다 —
         값이 끼므로 사전 키가 되려면 템플릿이어야 한다. */
      const _secs = _unsupported
        .map(w => String(w.content || '').replace(/^config\s+/i, '').trim())
        .filter(Boolean);
      apoSetText(box,
        'This backup contains sections APO does not read ({sections}), so '
        + 'those entries are not part of this assessment.',
        { sections: (_secs.length ? _secs : ['?']).join(', ') });
    } else if (box) {
      box.classList.add('is-warning');
      box.textContent = dropped
        ? apoT('{n} line(s) could not be read and {d} object(s) were skipped '
               + '— this backup looks truncated, so those policies are not in '
               + 'the assessment. Download the configuration again.',
               { n: _warn.length, d: dropped })
        : truncated
        ? apoT('This backup looks truncated — anything after the cut was not '
               + 'read, and VDOM attribution may be wrong. Re-export a '
               + 'complete backup and load it again.')
        : apoT('{n} line(s) in this configuration could not be read — see the '
               + 'warnings sheet in the exported workbook.', { n: _warn.length });
    }
  }
  /* **VDOM 이 여럿이면 정책 번호가 정책을 가리키지 못한다.** 목록에 VDOM 칸이
     없으므로 사용자는 '1번 정책'이 둘 있다는 것조차 알 수 없고, 그 상태로
     조치를 보내면 화면에서 본 적 없는 정책이 꺼진다(라운드 39 실측). 서버는
     쓰기를 막지만, 왜 막히는지는 여기서 미리 말한다. */
  if ((meta.vdoms || []).length > 1) {
    items.unshift(['VDOM', meta.vdoms.join(', ')]);
  }
  metaBox.innerHTML = items.map(([label, value]) => {
    const v = String(value);
    const cls = v.length > 14 ? 'stat-value long' : 'stat-value';
    return `
    <div class="stat-card">
      <span class="stat-label">${escapeHtml(label)}</span>
      <strong class="${cls}" title="${escapeHtml(v)}">${escapeHtml(v)}</strong>
    </div>`;
  }).join('');
}

function renderPolicyCsvSummary() {
  const makeCards = (label, info) => {
    if (!info) {
      return `<div class="stat-card compact">
        <span class="stat-label">${escapeHtml(label)}</span>
        <strong class="stat-value" style="font-size:13px;color:var(--muted)">Not Loaded</strong>
      </div>`;
    }
    const { summary, filename } = info;
    return `
      <div class="stat-card compact">
        <span class="stat-label">${escapeHtml(label)}</span>
        <strong class="stat-value" style="font-size:13px">${escapeHtml(filename)}</strong>
      </div>
      <div class="stat-card compact">
        <span class="stat-label">${escapeHtml(label)} Rows</span>
        <strong class="stat-value">${escapeHtml(String(summary.count ?? 0))}</strong>
      </div>`;
  };
  if (policyCsvSummary) {
    /* 서버가 보관한 출처를 먼저 그린다. 이 화면이 클라이언트 기억에만 기대던
       동안에는 새로고침 한 번에 'Not Loaded'로 바뀌면서도 사용량 칩은 켜져
       있고 표에는 값이 남아, 세 곳이 서로 다른 말을 했다. 그러면 남의 장비
       CSV를 얹은 사고를 화면에서 확인할 방법이 없다(라운드 19 실측). */
    const stored = (currentCsvMeta || []).map((s) => `
      <div class="stat-card compact">
        <span class="stat-label">${escapeHtml(apoT('Usage CSV'))}${s.kind && s.kind !== 'unspecified'
          ? ` (${escapeHtml(s.kind)})` : ''}</span>
        <strong class="stat-value" style="font-size:13px">${escapeHtml(s.filename || '')}</strong>
        <span class="stat-label" style="margin-top:4px">${escapeHtml(
          apoT('{n} row(s)', { n: s.rows ?? 0 })
          + `${s.imported_at ? ` · ${s.imported_at}` : ''}`
          + `${s.sha256 ? ` · ${String(s.sha256).slice(0, 8)}` : ''}`)}</span>
      </div>`).join('');
    policyCsvSummary.innerHTML = stored
      || (makeCards('FW Policy CSV', fwCsvSummary)
          + makeCards('Proxy Policy CSV', proxyCsvSummary));
  }
}

function renderActiveTab() {
  if (!currentView) {
    tabContent.innerHTML = '<div class="empty-state"><h3>' + escapeHtml(apoT('No dataset loaded'))
      + '</h3><p>' + escapeHtml(apoT('Select a Config File and optionally merge a Policy CSV to begin.'))
      + '</p></div>';
    tabCount.textContent = '';
    return;
  }

  const items = getFilteredItems();
  apoSetText(tabCount, '{n} item(s)', { n: items.length });

  const renderers = {
    firewall_policy: renderPolicyTable,
    firewall_proxy_policy: renderPolicyTable,
    firewall_multicast_policy: renderMulticastTable,
    firewall_address: renderAddressTable,
    firewall_proxy_address: renderAddressTable,
    firewall_addrgrp: renderAddrGrpTable,
    firewall_proxy_addrgrp: renderAddrGrpTable,
    firewall_service_custom: renderServiceCustomTable,
    firewall_service_group: renderServiceGroupTable,
    system_interface: renderInterfaceTable,
  };
  (renderers[activeTab] || (() => { tabContent.innerHTML = '<p>Unsupported tab.</p>'; }))(items);
}

function getFilteredItems(tabName = activeTab) {
  let items = [...(currentView?.[tabName] || [])];
  const q = tableFilter.value.trim().toLowerCase();
  if (q) {
    items = items.filter(item => JSON.stringify(item).toLowerCase().includes(q));
  }

  if (isPolicyTab(tabName)) {
    if (filterDisabled.checked) {
      items = items.filter(item => String(item.status || '').toLowerCase() === 'disabled');
    }
    if (filterHitZero.checked) {
      items = items.filter(item => item.hit_count != null && Number(item.hit_count) === 0);
    }

    if (filterDormantYear.checked) {
      items = items.filter(isDormantOneYear);
    }
    if (filterExpiredSchedule.checked) {
      items = items.filter(isExpiredSchedulePolicy);
    }
    if (filterNoItsRequest.checked) {
      items = items.filter(hasNoRitm);
    }
    if (filterDeletable.checked) {
      items = items.filter(item => isDisabledPolicy(item) || isExpiredSchedulePolicy(item));
    }
  }
  return items;
}

function isDisabledPolicy(item) {
  return String(item.status || '').toLowerCase() === 'disabled';
}

function isDormantOneYear(item) {
  const hit = Number(item.hit_count || 0);
  if (hit <= 0) return false;
  const dt = parseFortiDate(item.last_used);
  if (!dt) return false;
  const oneYearAgo = new Date();
  oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
  return dt < oneYearAgo;
}

function isExpiredSchedulePolicy(item) {
  const raw = String(item.schedule || '').trim();
  if (!/^\d{6}$/.test(raw)) return false;
  const yy = Number(raw.slice(0, 2));
  const mm = Number(raw.slice(2, 4));
  const dd = Number(raw.slice(4, 6));
  if (!mm || !dd) return false;
  // 서버(schedule_utils.py)와 동일하게 항상 20xx로 읽는다. 이 필드는 만료일이라
  // 1970~1999년 값이 설정될 일이 없다. 예전 코드는 70 이상을 19xx로 읽어,
  // 같은 정책을 서버는 미만료·클라이언트는 만료로 정반대 판정했다.
  const fullYear = 2000 + yy;
  const scheduleDate = new Date(fullYear, mm - 1, dd, 23, 59, 59, 999);
  return !Number.isNaN(scheduleDate.getTime()) && scheduleDate < new Date();
}

function parseFortiDate(value) {
  const raw = String(value || '').trim();
  if (!raw || raw === '-') return null;
  const isoLike = raw.replace(/\//g, '-');
  const parsed = new Date(isoLike);
  if (!Number.isNaN(parsed.getTime())) return parsed;
  const m = raw.match(/^(\d{4})[\/-](\d{2})[\/-](\d{2})\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (!m) return null;
  return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}

function updatePolicyFilterVisibility() {
  const visible = isPolicyTab(activeTab);
  policyOnlyFilters.classList.toggle('hidden', !visible);
}

function renderPolicyTable(items) {
  const rows = items.map(item => {
    return `
    <tr>
      <td>${escapeHtml(item.policy_id ?? '')}</td>
      <td>${escapeHtml(item.name || '') || '<span class="muted">-</span>'}</td>
      <td>${renderStatusBadge(item.status || '')}</td>
      <td>${renderList(item.srcintf_display)}</td>
      <td>${renderList(item.dstintf_display)}</td>
      <td>${renderList(item.srcaddr_display)}</td>
      <td>${renderList(item.dstaddr_display)}</td>
      <td>${renderList(item.service_display)}</td>
      <td>${escapeHtml(item.schedule || '')}</td>
      <td>${escapeHtml(item.action || '')}</td>
      <td>${item.hit_count != null ? escapeHtml(String(item.hit_count)) : '<span class="muted">-</span>'}</td>
      <td>${escapeHtml(item.last_used || '-')}</td>
    </tr>
  `}).join('');

  tabContent.innerHTML = tableShell(`
    <thead>
      <tr>
        <th>Policy ID</th>
        <th>Name</th>
        <th>Status</th>
        <th>Source Interface</th>
        <th>Destination Interface</th>
        <th>Source Address</th>
        <th>Destination Address</th>
        <th>Service</th>
        <th>Schedule</th>
        <th>Action</th>
        <th>Hit Count</th>
        <th>Last Used</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  `);
}

function renderMulticastTable(items) {
  const rows = items.map(item => `
    <tr>
      <td>${escapeHtml(item.policy_id ?? '')}</td>
      <td>${escapeHtml(item.name || '') || '<span class="muted">-</span>'}</td>
      <td>${renderList(item.srcintf_display)}</td>
      <td>${renderList(item.dstintf_display)}</td>
      <td>${renderList(item.srcaddr_display)}</td>
      <td>${renderList(item.dstaddr_display)}</td>
      <td>${escapeHtml(item.action || '')}</td>
      <td>${renderStatusBadge(item.status || '')}</td>
      <td>${escapeHtml(item.schedule || '')}</td>
      <td>${escapeHtml(item.comment || '')}</td>
    </tr>
  `).join('');

  tabContent.innerHTML = tableShell(`
    <thead>
      <tr>
        <th>Policy ID</th><th>Name</th>
        <th>Source Interface</th><th>Destination Interface</th>
        <th>Source Address</th><th>Destination Address</th>
        <th>Action</th><th>Status</th><th>Schedule</th><th>Comment</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  `);
}

function renderAddressTable(items) {
  const rows = items.map(item => `
    <tr>
      <td>${escapeHtml(item.name || '')}</td>
      <td>${escapeHtml(item.type || '')}</td>
      <td>${escapeHtml(item.resolved || '')}</td>
      <td>${escapeHtml(item.comment || '')}</td>
    </tr>
  `).join('');

  tabContent.innerHTML = tableShell(`
    <thead><tr><th>Name</th><th>Type</th><th>Resolved</th><th>Comment</th></tr></thead>
    <tbody>${rows}</tbody>
  `);
}

function renderAddrGrpTable(items) {
  const rows = items.map(item => `
    <tr>
      <td>${escapeHtml(item.name || '')}</td>
      <td>${renderList(item.member || [])}</td>
      <td>${renderList(item.resolved_members || [])}</td>
      <td>${escapeHtml(item.comment || '')}</td>
    </tr>
  `).join('');

  tabContent.innerHTML = tableShell(`
    <thead><tr><th>Name</th><th>Members</th><th>Resolved Members</th><th>Comment</th></tr></thead>
    <tbody>${rows}</tbody>
  `);
}

function renderServiceCustomTable(items) {
  const rows = items.map(item => `
    <tr>
      <td>${escapeHtml(item.name || '')}</td>
      <td>${escapeHtml(item.protocol || '')}</td>
      <td>${escapeHtml(item['tcp-portrange'] || '')}</td>
      <td>${escapeHtml(item['udp-portrange'] || '')}</td>
      <td>${escapeHtml(item['sctp-portrange'] || '')}</td>
      <td>${escapeHtml(item.resolved || '')}</td>
      <td>${escapeHtml(item.category || '')}</td>
      <td>${escapeHtml(item.comment || '')}</td>
    </tr>
  `).join('');

  tabContent.innerHTML = tableShell(`
    <thead><tr><th>Name</th><th>Protocol</th><th>TCP Port Range</th><th>UDP Port Range</th><th>SCTP Port Range</th><th>Resolved</th><th>Category</th><th>Comment</th></tr></thead>
    <tbody>${rows}</tbody>
  `);
}

function renderServiceGroupTable(items) {
  const rows = items.map(item => `
    <tr>
      <td>${escapeHtml(item.name || '')}</td>
      <td>${renderList(item.member || [])}</td>
      <td>${renderList(item.resolved_members || [])}</td>
      <td>${escapeHtml(item.comment || '')}</td>
    </tr>
  `).join('');

  tabContent.innerHTML = tableShell(`
    <thead><tr><th>Name</th><th>Members</th><th>Resolved Members</th><th>Comment</th></tr></thead>
    <tbody>${rows}</tbody>
  `);
}

function renderInterfaceTable(items) {
  const rows = items.map(item => `
    <tr>
      <td>${escapeHtml(item.port || '')}</td>
      <td>${escapeHtml(item.display_name || item.port || '')}</td>
      <td>${escapeHtml(item.alias || '')}</td>
      <td>${escapeHtml(item.type || '')}</td>
      <td>${escapeHtml(item.ip || '')}</td>
      <td>${escapeHtml(item.role || '')}</td>
    </tr>
  `).join('');

  tabContent.innerHTML = tableShell(`
    <thead><tr><th>Port</th><th>Display Name</th><th>Alias</th><th>Type</th><th>IP</th><th>Role</th></tr></thead>
    <tbody>${rows}</tbody>
  `);
}


function tableShell(content) {
  return `<div class="table-shell"><div class="table-wrap"><table>${content}</table></div></div>`;
}

function renderList(values) {
  const items = Array.isArray(values) ? values : [values];
  const cleaned = items.filter(Boolean);
  if (!cleaned.length) return '<span class="muted">-</span>';
  return `<div class="badge-list">${cleaned.map(v => `<span class="badge">${escapeHtml(String(v))}</span>`).join('')}</div>`;
}

function renderStatusBadge(value) {
  const normalized = String(value || '').toLowerCase();
  const cls = normalized === 'disabled' ? 'status-disabled' : 'status-enabled';
  return `<span class="status-pill ${cls}">${escapeHtml(value || '-')}</span>`;
}

function joinList(values) {
  const items = Array.isArray(values) ? values : [values];
  return items.filter(Boolean).join(' | ');
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/* 이 파일은 화면마다 IIFE 안에 `esc` 를 따로 두고, 모듈 수준에서는
   `escapeHtml` 을 쓴다. 두 이름이 같은 일을 하는데 이름만 다르니, 표 머리글을
   번역 통로에 태우면서 모듈 수준 코드에 `esc(` 를 써 넣어 **화면이 통째로
   안 그려졌다**(라운드 45 자체 발견: `ReferenceError: esc is not defined`).
   이름을 하나로 잇는다 — IIFE 안의 것은 그대로 가려 쓴다(동작 동일). */
var esc = escapeHtml;

downloadCsvBtn.addEventListener('click', async () => {
  if (!currentView) return;
  if (!(await licenseGate())) return;
  const tab = TAB_DEFS[activeTab];
  if (!tab) return;
  const items = getFilteredItems();
  const rows = [tab.columns.map(([header]) => header)];
  for (const item of items) {
    rows.push(tab.columns.map(([, getter]) => getter(item)));
  }
  const csv = rows.map(row => row.map(csvEscape).join(',')).join('\r\n');
  const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${tab.filename}${deviceStamp()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
});

downloadWorkbookBtn.addEventListener('click', async () => {
  if (!currentView) return;
  if (!(await licenseGate())) return;   // 라이선스 확인

  const payload = { workbook_name: 'firewall_policy_optimizer_export', sheets: {} };
  for (const tabName of ALL_TABS) {
    const tab = TAB_DEFS[tabName];
    const items = [...(currentView?.[tabName] || [])];
    payload.sheets[tabName] = {
      title: tab.sheet,
      headers: tab.columns.map(([header]) => header),
      rows: items.map(item => tab.columns.map(([, getter]) => getter(item))),
    };
  }

  const res = await fetch('/api/export/workbook', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // 파일 이름에 장비명이 찍히므로 **어느 장비의 표인지 대야 한다**. 대지
    // 않으면 서버는 '지금 열린 장비' 이름을 붙이는데, 그 사이 다른 창이
    // 장비를 바꿨다면 남의 이름이 찍힌 남의 표가 나간다.
    body: JSON.stringify({ ...payload, device_id: currentDeviceId || undefined }),
  });
  if (!res.ok) { await alertApiError(res, 'Failed to build workbook export.'); return; }
  saveResponseAs(await res.blob(), res, 'firewall_policy_optimizer_export.xlsx');
});

function csvEscape(value) {
  const str = String(value ?? '');
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replaceAll('"', '""')}"`;
  }
  return str;
}

renderActiveTab();
onLangChange(renderActiveTab);


/* APO License Gate & Modal */
/* 티어별 체크아웃. 웹훅은 상품명에 MSP/Consultant가 들어가면 tier=msp 키를
   발급하므로, 화면은 올바른 상품으로 보내기만 하면 된다.
   MSP URL이 아직 안 채워졌으면 스토어 첫 화면으로 보낸다 — 깨진 체크아웃보다
   낫고, 거기서 상품을 고르면 결과는 같다. */
const LEMON_CHECKOUT_URL = 'https://choiceguidelab.lemonsqueezy.com/checkout/buy/1c83b59f-7f23-4899-a173-dc43d1c7bce6';
const LEMON_CHECKOUT_URL_MSP = 'https://choiceguidelab.lemonsqueezy.com/checkout/buy/19b221bc-420d-4a41-8212-fef57fd267bd';
const LEMON_STORE_URL = 'https://choiceguidelab.lemonsqueezy.com/';

let _licensed = null;  // null=미확인, true/false
/* 자격을 잃은 이유(서버가 준 문장). 모달·설정 화면이 그대로 보여준다. */
let _licenseProblem = null;
let _pendingExportBtnId = null;  // 게이트를 띄운 export 버튼 id (활성화 후 재실행용)

// Export 대상 버튼 ID 목록 (CSV 포함 전체 게이트)

// 실패 응답의 서버측 사유({"error":...})를 사용자에게 보여준다.
// 일반 문구만 내면 402(라이선스)조차 "고장"으로 읽힌다.
async function alertApiError(res, fallback) {
  // 402(라이선스)·403(티어)·409(장비 불일치)가 전부 여기로 온다. 번역 통로를
  // 지나지 않으면 한국어 화면에서 유일하게 읽을 문장이 영어로 남는다.
  alert(await serverMsgFrom(res, fallback));
}

// 유료 게이트가 걸린 export는 전부 여기 있어야 한다 — 빠지면 잠금 표시도
// 안 붙고, 키 등록 후 원래 누르려던 export로 되돌아가지도 않는다.
const EXPORT_BTN_IDS = ['downloadCsvBtn', 'downloadWorkbookBtn', 'sevExportBtn',
                        'remExportCsvBtn', 'remExportJsonBtn', 'auditExportBtn',
                        // diff 워크북 — 서버 402 게이트(라운드 71)의 화면 반쪽.
                        // 빠지면 잠금 표시가 안 붙고 402 가 막다른 길이 된다
                        // (라운드 72).
                        'diffExportBtn'];

function setExportBtnsState(licensed) {
  EXPORT_BTN_IDS.forEach(id => {
    const btn = document.getElementById(id);
    if (!btn) return;
    if (licensed) {
      btn.classList.remove('btn-license-required');
      btn.removeAttribute('data-license-locked');
      btn.title = '';
    } else {
      btn.classList.add('btn-license-required');
      btn.setAttribute('data-license-locked', '1');
      btn.title = apoT('Licence required — click to buy one or enter a key');
    }
  });
}

async function checkLicense() {
  try {
    const r = await fetch('/api/license/status');
    const d = await r.json();
    _licensed = d.licensed === true;
    // 자격 상실 사유를 보관한다 — 모달이 그대로 보여준다.
    _licenseProblem = d.problem || null;
  } catch (_) {
    _licensed = false;
    _licenseProblem = null;
  }
  setExportBtnsState(_licensed);
  return _licensed;
}

async function licenseGate() {
  if (_licensed === null) await checkLicense();
  if (_licensed) return true;
  showLicenseModal();
  return false;
}

function showLicenseModal() {
  document.getElementById('licenseModal')?.classList.remove('hidden');
  /* **왜 막혔는지 먼저 말한다.** 자격을 잃은 유료 고객(업데이트 창 만료 등)에게
     "Export License Required" 와 구매 안내만 보여주면, 이미 돈을 낸 사람이
     자기가 왜 무료 사용자가 됐는지 알 수 없다. 서버가 사유를 주는데 모달이
     읽지 않았다(2026-09-10 재비판 F1). */
  const m0 = document.getElementById('licActivateMsg');
  if (m0) {
    const why = _licenseProblem;
    m0.textContent = why || '';
  }
  document.getElementById('licKeyInput')?.focus();
}
function hideLicenseModal() {
  // 대기 중이던 export를 남겨 두면, 나중에 Settings에서 키를 넣었을 때
  // 요청하지도 않은 워크북이 (그새 바뀐 설정으로) 내려간다.
  _pendingExportBtnId = null;
  document.getElementById('licenseModal')?.classList.add('hidden');
  const m = document.getElementById('licActivateMsg');
  if (m) m.textContent = '';
  const k = document.getElementById('licKeyInput');
  if (k) k.value = '';
}

document.getElementById('licCloseBtn')?.addEventListener('click', hideLicenseModal);
document.getElementById('licenseModal')?.addEventListener('click', e => {
  if (e.target.id === 'licenseModal') hideLicenseModal();
});

document.getElementById('licActivateBtn')?.addEventListener('click', async () => {
  const key = document.getElementById('licKeyInput')?.value.trim();
  const msg = document.getElementById('licActivateMsg');
  if (!key) { msg.textContent = apoT('Please enter your licence key.'); msg.className = 'lic-msg error'; return; }
  msg.textContent = apoT('Checking the key...'); msg.className = 'lic-msg';
  try {
    const r = await fetch('/api/license/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(serverMsg(d, 'Activation failed'));
    _licensed = true;
    _licenseProblem = null;   // 방금 활성화됐다
    setExportBtnsState(true);
    window.APO?.onLicense?.();   // 상단 상태바·Settings 표시를 즉시 갱신
    msg.textContent = apoT('Registered ({email})', { email: d.email || '' });
    msg.className = 'lic-msg success';
    const resumeId = _pendingExportBtnId;   // 게이트를 띄운 원래 export 버튼
    _pendingExportBtnId = null;
    setTimeout(() => {
      hideLicenseModal();
      // Settings에서 직접 등록한 경우엔 재개할 export가 없다. 기본값으로
      // 워크북 다운로드를 눌러버리면 요청하지도 않은 파일이 내려간다.
      if (resumeId) document.getElementById(resumeId)?.click();
    }, 1000);
  } catch (e) {
    msg.textContent = e.message;
    msg.className = 'lic-msg error';
  }
});

document.getElementById('licBuyBtn')?.addEventListener('click', () => {
  const email = document.getElementById('licEmailInput')?.value.trim();
  if (!email) {
    const inp = document.getElementById('licEmailInput');
    if (inp) { inp.focus(); inp.style.borderColor = 'rgba(214,43,32,.6)'; }
    return;
  }
  const tier = document.querySelector('input[name="apoTier"]:checked')?.value || 'single';
  const base = tier === 'msp' ? (LEMON_CHECKOUT_URL_MSP || LEMON_STORE_URL)
                              : LEMON_CHECKOUT_URL;
  // 스토어 첫 화면에는 email 프리필이 안 먹는다 — 붙이면 지저분한 쿼리만 남는다.
  const url = base.includes('/checkout/buy/')
    ? `${base}?checkout[email]=${encodeURIComponent(email)}`
    : base;
  // 팝업 차단 우회: 같은 탭에서 이동 후 바로 복귀 가능하도록 새 탭으로 직접 이동
  const a = document.createElement('a');
  a.href = url;
  a.target = '_blank';
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
});

/* 샘플 리포트 — 라이선스 없이도 산출물을 볼 수 있어야 한다. 서버가 번들
   데모 설정으로 만들어 주므로 지금 열어 둔 고객 설정은 건드리지 않는다. */
async function downloadSampleReport(btn) {
  const label = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = apoT('Building the sample...'); }
  try {
    const r = await fetch('/api/sample-report');
    if (!r.ok) throw new Error(await serverMsgFrom(r, 'Failed'));
    saveResponseAs(await r.blob(), r, 'APO_sample_report.xlsx');
    if (btn) btn.textContent = apoT('Downloaded ✓');
  } catch (e) {
    if (btn) btn.textContent = apoT('Could not build the sample');
    console.error('sample report:', e);
  } finally {
    if (btn) setTimeout(() => { btn.disabled = false; btn.textContent = label; }, 1600);
  }
}
['licSampleBtn', 'setSampleBtn'].forEach(id => {
  const b = document.getElementById(id);
  if (b) b.addEventListener('click', () => downloadSampleReport(b));
});

// 앱 시작 시 버튼 먼저 비활성화 → 라이선스 확인 후 활성화
setExportBtnsState(false);
checkLicense();

// disabled 상태 버튼 클릭 시 모달 표시 (disabled는 click 이벤트가 발생하지 않아 wrapper로 처리)
document.addEventListener('click', e => {
  const btn = e.target.closest('button[data-license-locked]');
  if (btn) { _pendingExportBtnId = btn.id; showLicenseModal(); }
});


/* APO v20 strict two-page UI and configuration review */
(function () {
  const analysisView = document.getElementById("analysisView");
  const diffView = document.getElementById("diffView");
  const switchButtons = document.querySelectorAll("[data-view]");
  const oldBtn = document.getElementById("oldConfigPickerBtn");
  const newBtn = document.getElementById("newConfigPickerBtn");
  const oldInput = document.getElementById("oldConfigFile");
  const newInput = document.getElementById("newConfigFile");
  const runBtn = document.getElementById("runDiffBtn");
  let diffState = { summary: {}, added_policies: [], removed_policies: [], changed_policies: [], added_objects: [], removed_objects: [], changed_objects: [], other_changes: [] };
  let activeDiffTab = "overview";
  function setDiffProgress(percent, title, step) {
    const wrap = document.getElementById("diffProgress");
    const bar = document.getElementById("diffProgressBar");
    const pct = document.getElementById("diffProgressPercent");
    const titleEl = document.getElementById("diffProgressTitle");
    const stepEl = document.getElementById("diffProgressStep");
    if (wrap) wrap.classList.remove("hidden");
    if (bar) bar.style.width = `${percent}%`;
    if (pct) pct.textContent = `${percent}%`;
    /* 진행 제목·단계는 여기 한 곳에서 번역한다 — 호출부 7곳의 리터럴이
       사전을 안 거쳐 화면 절반이 영어로 남았다(2026-08-25 전면 검토 M-3).
       err.message 같은 동적 문장은 사전에 없으면 원문 그대로 나온다. */
    title = apoT(title);
    step = step == null ? step : apoT(step);
    /* 진행 문구도 화면에 남는다 — 두 인자는 항상 영어 리터럴이므로
       여기 한 곳에서 번역 통로에 태운다(호출부 8곳을 다 고칠 필요 없다). */
    if (titleEl) apoSetText(titleEl, title || "");
    if (stepEl) apoSetText(stepEl, step || "");
  }
  const esc = v => String(v == null ? "" : v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const humanizeKey = key => String(key || "").replace(/^firewall_/,"").replace(/^system_/,"").replace(/_/g," ").replace(/-/g," ").replace(/\b\w/g,c=>c.toUpperCase());
  function normalizeValue(value){ if(value==null) return "-"; if(Array.isArray(value)) return value.length?value.join(", "):"-"; if(typeof value==="object") return JSON.stringify(value); const s=String(value).trim(); return s||"-"; }
  /* 객체 한 줄 요약은 **서버가 만들어 보낸다**(`i.summary`). 여기에도
     한 벌 있었는데 우선순위가 달라 같은 객체를 다르게 말했다 — 별칭과
     멤버를 둘 다 가진 인터페이스를 파일은 별칭으로, 화면은 멤버 포트로
     적었다(라운드 45). 계산은 한 곳에만 둔다. */
  /* 바뀐 필드 목록은 **서버가 계산해서 보낸다**(`item.changes`). 예전에는
     여기서 직접 만들었는데, 내보내기를 붙이면서 파이썬으로 한 벌 더 쓰게 되어
     화면과 감사 파일이 서로 다른 말을 할 자리가 생겼다. 계산은 한 곳에만 둔다. */
  /* 화면 전환은 shell.js가 소유한다. 여기서는 뷰 목록을 하드코딩하지 않고
     data-view 값과 같은 이름의 섹션을 찾아 켜기만 한다(새 뷰 추가 시 무수정). */
  const VIEW_SECTION={overview:"overviewView",analysis:"analysisView",severity:"severityView",remediation:"remediationView",diff:"diffView",evidence:"evidenceView",settings:"settingsView",reference:"referenceView",advisor:"severityView"};
  function setView(mode){ if(window.APO&&typeof window.APO.setView==="function"){ window.APO.setView(mode); return; } switchButtons.forEach(b=>b.classList.toggle("active", b.getAttribute("data-view")===mode)); document.querySelectorAll(".page-view").forEach(v=>v.classList.add("hidden")); const target=document.getElementById(VIEW_SECTION[mode]||"overviewView"); target?.classList.remove("hidden"); window.scrollTo({top:0,behavior:"smooth"}); }
  switchButtons.forEach(btn=>btn.addEventListener("click",()=>setView(btn.getAttribute("data-view"))));
  const exportBtn=document.getElementById("diffExportBtn");
  /* 내보내기는 **지금 선택된 두 파일**을 다시 올려 서버가 재계산한다. 그래서
     파일을 바꾸면 화면의 표와 내려받을 파일이 달라진다 — 그 순간 버튼을
     감춘다. 안 그러면 A·B 비교 결과를 보면서 A·C 비교 파일을 받는다. */
  function _diffInputChanged(){ if(exportBtn) exportBtn.classList.add("hidden"); }
  if(oldBtn&&oldInput){ oldBtn.addEventListener("click",()=>oldInput.click()); oldInput.addEventListener("change",()=>{ const f=oldInput.files&&oldInput.files[0]; const label=document.getElementById("selectedOldConfigName"); if(label) label.textContent=f?f.name:"No file selected"; _diffInputChanged(); });}
  if(newBtn&&newInput){ newBtn.addEventListener("click",()=>newInput.click()); newInput.addEventListener("change",()=>{ const f=newInput.files&&newInput.files[0]; const label=document.getElementById("selectedNewConfigName"); if(label) label.textContent=f?f.name:"No file selected"; _diffInputChanged(); });}
  if(exportBtn){ exportBtn.addEventListener("click",async()=>{ if(!(await licenseGate())) return;   /* 유료 export — 서버 402 와 짝(라운드 72) */ const oldFile=oldInput&&oldInput.files&&oldInput.files[0]; const newFile=newInput&&newInput.files&&newInput.files[0]; const status=document.getElementById("diffStatus"); if(!oldFile||!newFile){ apoSetText(status,"Select both baseline and target configuration files."); return;} const fd=new FormData(); fd.append("old_config",oldFile); fd.append("new_config",newFile); exportBtn.disabled=true; const _label=exportBtn.textContent; exportBtn.textContent=apoT("Preparing download..."); try{ const res=await fetch("/api/config/diff/export",{method:"POST",body:fd}); if(!res.ok) throw new Error(await serverMsgFrom(res,"Failed to build comparison export")); saveResponseAs(await res.blob(),res,"apo_config_changes.xlsx"); }catch(err){ /* i18n-dynamic: 예외 메시지 */ if(status) status.textContent=err.message; } finally { exportBtn.disabled=false; exportBtn.textContent=_label; } });}
  function renderSummary(){ const s=diffState.summary||{}; const box=document.getElementById("diffSummary"); if(!box) return; const cards=[["Added Policies",s.added_policies||0,"New firewall rules"],["Removed Policies",s.removed_policies||0,"Deleted firewall rules"],["Changed Policies",s.changed_policies||0,"Modified rule attributes"],["Added Objects",s.added_objects||0,"New objects"],["Removed Objects",s.removed_objects||0,"Deleted objects"],["Redefined Objects",s.changed_objects||0,"Same name, different value"],["Other Changes",s.other_changes||0,"Profiles, certificates, system settings"]]; box.innerHTML=cards.map(([l,v,d])=>`<div class="stat-card diff-stat-card"><span class="stat-label">${esc(apoT(l))}</span><span class="stat-value">${esc(v)}</span><span class="stat-desc">${esc(apoT(d))}</span></div>`).join("");}
  function renderOverview(){ const s=diffState.summary||{}; const total=Object.values(s).reduce((a,b)=>a+Number(b||0),0); return `<div class="diff-overview"><div class="overview-main-card"><span class="diff-eyebrow-dark">${esc(apoT("Analysis Summary"))}</span><h3>${esc(apoT("{n} total change groups detected",{n:total}))}</h3><p>${esc(apoT("This view summarizes policy, object, and additional configuration changes between the selected baseline and target backups."))}</p></div><div class="overview-guidance-card"><strong>${esc(apoT("Recommended Review Flow"))}</strong><ol><li>${esc(apoT("Review changed policies first."))}</li><li>${esc(apoT("Validate added or removed policies."))}</li><li>${esc(apoT("Check object changes for IP, service, and group impact."))}</li><li>${esc(apoT("Review other configuration changes."))}</li></ol></div></div>`;}
  function renderPolicyTable(items,title){ return `<div class="diff-section-title"><h3>${esc(apoT(title))}</h3><span>${esc(apoT("{n} item(s)",{n:items.length}))}</span></div><div class="table-wrap"><table><thead><tr><th>Policy ID</th><th>Policy Name</th><th>Source</th><th>Destination</th><th>Service</th><th>Schedule</th><th>Action</th></tr></thead><tbody>${items.map(i=>`<tr><td>${esc(i.policy_id||i.id||"-")}</td><td>${esc(i.name||"-")}</td><td>${esc(normalizeValue(i.srcaddr_display||i.srcaddr))}</td><td>${esc(normalizeValue(i.dstaddr_display||i.dstaddr))}</td><td>${esc(normalizeValue(i.service_display||i.service))}</td><td>${esc(normalizeValue(i.schedule))}</td><td>${esc(normalizeValue(i.action))}</td></tr>`).join("")}</tbody></table></div>`;}
  function renderChangedPolicies(items){ return `<div class="diff-section-title"><h3>${esc(apoT("Changed Policies"))}</h3><span>${esc(apoT("{n} item(s)",{n:items.length}))}</span></div><div class="table-wrap"><table><thead><tr><th>Policy ID</th><th>Policy Name</th><th>Changed Settings</th></tr></thead><tbody>${items.map(item=>{ const before=item.before||{}, after=item.after||{}; const changes=item.changes||[]; return `<tr><td>${esc(item.policy_id||after.policy_id||before.policy_id||"-")}</td><td>${esc(item.name||after.name||before.name||"-")}</td><td><div class="change-list">${changes.length?changes.map(c=>`<div class="change-row"><div class="change-key">${esc(c.label)}</div><div class="change-values"><span class="change-before">${esc(c.before)}</span><span class="change-arrow">→</span><span class="change-after">${esc(c.after)}</span></div></div>`).join(""):`<span class="muted-inline">${esc(apoT("No material field change detected."))}</span>`}</div></td></tr>`;}).join("")}</tbody></table></div>`;}
  function renderObjectTable(items,title){ return `<div class="diff-section-title"><h3>${esc(apoT(title))}</h3><span>${esc(apoT("{n} item(s)",{n:items.length}))}</span></div><div class="table-wrap"><table><thead><tr><th>Configuration Area</th><th>Object Name</th><th>Resolved Value / Detail</th></tr></thead><tbody>${items.map(i=>`<tr><td>${esc(humanizeKey(i.section||"-"))}</td><td>${esc(i.name||"-")}</td><td>${esc(i.summary||"-")}</td></tr>`).join("")}</tbody></table></div>`;}
  /* 이름은 그대로인데 값이 바뀐 객체. 정책을 한 줄도 안 건드리고 객체만
     넓히는 것은 흔한 수법이자 흔한 실수인데, 예전에는 어느 탭에도 안 나왔다. */
  function renderChangedObjects(items){ return `<div class="diff-section-title"><h3>${esc(apoT("Redefined Objects"))}</h3><span>${esc(items.length)} item(s)</span></div><div class="table-wrap"><table><thead><tr><th>Configuration Area</th><th>Object Name</th><th>Setting</th><th>Before</th><th>After</th></tr></thead><tbody>${items.length?items.map(o=>(o.changes||[]).map(c=>`<tr><td>${esc(humanizeKey(o.section||"-"))}</td><td>${esc(o.name||"-")}</td><td>${esc(c.label)}</td><td><span class="change-before">${esc(c.before)}</span></td><td><span class="change-after">${esc(c.after)}</span></td></tr>`).join("")).join(""):`<tr><td colspan="5"><span class="muted-inline">${esc(apoT("No address, service, or interface object was redefined."))}</span></td></tr>`}</tbody></table></div>`;}
  function renderOtherChanges(items){ return `<div class="diff-section-title"><h3>${esc(apoT("Other Configuration Changes"))}</h3><span>${esc(apoT("{n} section(s)",{n:items.length}))}</span></div><div class="other-change-grid">${items.length?items.map(i=>`<div class="other-change-card"><div class="other-change-section">${esc(humanizeKey(i.section||"-"))}</div><div class="other-change-counts"><span>${esc(apoT("Added"))}: <strong>${esc((i.added||[]).length)}</strong></span><span>${esc(apoT("Removed"))}: <strong>${esc((i.removed||[]).length)}</strong></span><span>${esc(apoT("Changed"))}: <strong>${esc((i.changed||[]).length)}</strong></span></div><div class="other-change-detail">${i.added?.length?`<div><b>${esc(apoT("Added"))}</b>: ${esc(i.added.join(", "))}</div>`:""}${i.removed?.length?`<div><b>${esc(apoT("Removed"))}</b>: ${esc(i.removed.join(", "))}</div>`:""}${i.changed?.length?`<div><b>${esc(apoT("Changed"))}</b>: ${esc(i.changed.join(", "))}</div>`:""}</div></div>`).join(""):`<div class="empty-state"><strong>${esc(apoT("No additional configuration sections changed."))}</strong><span>${esc(apoT("Policy and object changes may still exist in their dedicated categories."))}</span></div>`}</div>`;}
  function renderDiffTab(){ const target=document.getElementById("diffTabContent"); if(!target) return; if(activeDiffTab==="overview") target.innerHTML=renderOverview(); else if(activeDiffTab==="added_policies") target.innerHTML=renderPolicyTable(diffState.added_policies||[],"Added Policies"); else if(activeDiffTab==="removed_policies") target.innerHTML=renderPolicyTable(diffState.removed_policies||[],"Removed Policies"); else if(activeDiffTab==="changed_policies") target.innerHTML=renderChangedPolicies(diffState.changed_policies||[]); else if(activeDiffTab==="added_objects") target.innerHTML=renderObjectTable(diffState.added_objects||[],"Added Objects"); else if(activeDiffTab==="removed_objects") target.innerHTML=renderObjectTable(diffState.removed_objects||[],"Removed Objects"); else if(activeDiffTab==="changed_objects") target.innerHTML=renderChangedObjects(diffState.changed_objects||[]); else if(activeDiffTab==="other_changes") target.innerHTML=renderOtherChanges(diffState.other_changes||[]);}
  document.querySelectorAll("[data-diff-tab]").forEach(btn=>btn.addEventListener("click",()=>{ document.querySelectorAll("[data-diff-tab]").forEach(b=>b.classList.remove("active")); btn.classList.add("active"); activeDiffTab=btn.getAttribute("data-diff-tab")||"overview"; renderDiffTab(); }));
  onLangChange(()=>{ renderSummary(); renderDiffTab(); });
  const _diffTimers=[];
  if(runBtn){ runBtn.addEventListener("click",async()=>{ const oldFile=oldInput&&oldInput.files&&oldInput.files[0]; const newFile=newInput&&newInput.files&&newInput.files[0]; const status=document.getElementById("diffStatus"); if(!oldFile||!newFile){ if(status) apoSetText(status,"Select both baseline and target configuration files."); return;} const fd=new FormData(); fd.append("old_config",oldFile); fd.append("new_config",newFile); if(status) apoSetText(status,"Analyzing configuration changes..."); setDiffProgress(10,"Preparing analysis...","Validating selected configuration files."); /* 예약해 둔 진행 단계는 **끝나면 취소한다.** 로컬 diff 가 360ms 보다 빨리
   끝나면 예약된 65% 가 나중에 실행돼 완료 표시를 덮어써, 같은 화면이 '완료'와
   '65% 진행 중'을 동시에 말했다(라운드 27 실측: 15초 뒤에도 남아 있음). */
_diffTimers.forEach(clearTimeout); _diffTimers.length=0;
_diffTimers.push(setTimeout(()=>setDiffProgress(35,"Uploading files...","Sending baseline and target configurations to the local parser."),120)); _diffTimers.push(setTimeout(()=>setDiffProgress(65,"Comparing configuration...","Detecting policy, object, and system-level differences."),360)); try{ const res=await fetch("/api/config/diff",{method:"POST",body:fd}); const data=await res.json(); if(!res.ok) throw new Error(data.error||"Configuration comparison failed."); diffState={summary:data.summary||{},added_policies:data.added_policies||[],removed_policies:data.removed_policies||[],changed_policies:data.changed_policies||[],added_objects:data.added_objects||[],removed_objects:data.removed_objects||[],changed_objects:data.changed_objects||[],other_changes:data.other_changes||[]}; setDiffProgress(90,"Rendering results...","Preparing categorized comparison results."); renderSummary(); activeDiffTab="overview"; document.querySelectorAll("[data-diff-tab]").forEach(b=>b.classList.remove("active")); document.querySelector('[data-diff-tab="overview"]')?.classList.add("active"); renderDiffTab(); if(exportBtn) exportBtn.classList.remove("hidden"); _diffTimers.forEach(clearTimeout); _diffTimers.length=0; setDiffProgress(100,"Analysis completed.","Configuration change review completed successfully."); /* 서로 다른 방화벽을 비교했으면 '변경 0건'은 의미가 없다 — 그 결론이 정기검토 보고서에 '변경 없음'으로 실린다(라운드 28 실측). 감사 증적 화면은 같은 사실을 이미 경고하고 있었다. */ if(status){ if(data.mixed_devices){ status.classList.add("is-warning"); status.textContent="⚠ "+apoT("Warning: these snapshots are from different firewalls ({list}). Differences between them are not one device’s change history.",{list:data.mixed_devices.join(", ")}); } else if(data.same_name_unverified){ /* 이름이 같다고 같은 장비가 아니다 — 두 고객이 둘 다 'FGT-HQ' 를 쓰거나 둘 다 hostname 줄이 없으면 이름 대조는 아무것도 증명하지 않는다. 다만 이건 **정상 사용 경로**(한 방화벽의 두 백업)이기도 하므로 경고색을 쓰지 않는다 — 매번 겁주면 진짜 경고가 묻힌다. 무엇을 비교했는지 사실만 적는다. */ const u=data.same_name_unverified; status.classList.remove("is-warning"); status.textContent=(u.reason==="no_hostname" ? apoT("Compared two backups; neither records a hostname, so APO cannot confirm they are the same firewall.") : u.reason==="one_hostname" ? apoT("Only one of the two backups records a hostname ({name}), so APO cannot confirm they are the same firewall.",{name:u.hostname}) : apoT("Compared two backups that both report the hostname {name}. A hostname is not unique, so this alone does not prove they are one firewall.",{name:u.hostname})); } else { status.classList.remove("is-warning"); apoSetText(status,"Configuration change review completed successfully."); } } }catch(err){ if(exportBtn) exportBtn.classList.add("hidden"); if(status) status.textContent=err.message||"Configuration comparison failed."; setDiffProgress(100,"Analysis failed.",err.message||"Configuration comparison failed."); }});}
})();

/* APO v23 — Severity Results */
(function () {
  const TAG_COLORS = {
    "Disabled":         "tag-gray",
    "No HitCount":      "tag-gray",
    "Last Used > 1yr":  "tag-amber",
    "Expired Schedule": "tag-gray",
    "No Name":          "tag-amber",
    "No Ticket":        "tag-amber",
    "Temp Rule":        "tag-red",
    "Risky Service":    "tag-red",
    "Deny Rule":        "tag-green",
    "ICMP Only":        "tag-green",
  };
  const SEV_BG = {
    0:"#F0EEE7",1:"#FFCCCC",2:"#D3D1C7",3:"#FFE0B2",
    4:"#B5D4F4",5:"#FFF9C4",6:"#C0DD97",7:"#9FE1CB"
  };
  const SEV_TC = {
    0:"#5F5E5A",1:"#A32D2D",2:"#444441",3:"#854F0B",
    4:"#0C447C",5:"#633806",6:"#27500A",7:"#085041"
  };
  const SEV_LABELS = {
    0:"Unknown",1:"Critical",2:"High",
    3:"Medium (S-U)",4:"Medium (S-S)",5:"Low (S-U)",6:"Low (S-S)",7:"Keep"
  };

  let userRanges = [];
  let sevData = null;
  let activeSevTab = "firewall";
  let activeSevFilter = null;

  const rangeInput   = document.getElementById("sevRangeInput");
  const rangeAddBtn  = document.getElementById("sevRangeAddBtn");
  const classifyBtn  = document.getElementById("sevClassifyBtn");
  const rangeTags    = document.getElementById("sevRangeTags");
  const statusEl     = document.getElementById("sevClassifyStatus");
  const phase2Card   = document.getElementById("sevPhase2Card");
  const summaryBar   = document.getElementById("sevSummaryBar");
  const tableCard    = document.getElementById("sevTableCard");
  const tableContent = document.getElementById("sevTableContent");
  const exportBtn    = document.getElementById("sevExportBtn");

  /* 설정이 바뀌면 이전 분류 결과는 즉시 버린다.
     남겨두면 Findings에는 A장비 결과가 그대로 있는데, Export는 서버가 들고 있는
     B장비의 hostname·config SHA-256을 붙여 내보낸다. 감사 증적에 해시를 넣는
     이유가 통째로 무너진다(재비판 BLOCKER). */
  /* reason: 왜 결과가 비워졌는지. 기본값('설정이 바뀌었다')을 모든 경로에서
     쓰던 동안에는, 새로고침으로 결과가 사라진 사용자가 바뀌지도 않은 설정
     변경을 찾아 헤맸다(라운드 19 지적). 사실만 말한다. */
  function resetSeverityResults(reason) {
    sevData = null;
    window.__sevHasData = false;
    /* **앞 장비의 수치를 남기지 않는다.** 대역 0건 안내가 "336건 중 256건이
       판정 불가" 를 말하는데, 이 두 값을 안 지워서 **한 번도 판정한 적 없는
       다음 장비**에서도 앞 고객의 숫자가 사실처럼 인쇄됐다(v129 재비판 발견 1).
       이 함수는 나머지를 전부 비우면서 이 둘만 빠뜨렸다. */
    window.__apoJudgedTotal = 0;
    window.__apoUnknownCount = 0;
    activeSevFilter = null;
    activeSevTab = 'firewall';   // 탭 선택도 이전 장비의 상태다
    if (phase2Card) phase2Card.style.display = 'none';
    if (tableCard) tableCard.style.display = 'none';
    const reach = document.getElementById('sevReachCard');
    if (reach) reach.style.display = 'none';
    /* 정확도 검증 카드는 **판정 실행에 매달아 두면 안 된다.** 표본을 받아
       Excel 로 채우는 데는 시간이 걸리므로 '내려받기 → 나갔다 옴 → 올리기'가
       정상 사용 경로인데, 새로고침 한 번에 카드가 통째로 사라져 올릴 방법이
       화면에서 없어졌다(라운드 27 실측). 표본 생성도 채점도 서버가 보관된
       설정으로 하므로 판정 실행이 필요 없다 — 장비가 열려 있으면 보인다. */
    const verify = document.getElementById('sevVerifyCard');
    if (verify) verify.style.display = currentDeviceId ? '' : 'none';
    /* 카드를 숨기기만 하면 이전 장비의 표가 DOM에 그대로 남는다(페이지 저장·
       소스 보기로 드러난다). 내용까지 비운다.

       FortiOS 자문 패널은 상태를 전부 DOM에만 들고 있어서 따로 지우지 않으면
       B장비 화면에 A장비의 모델·펌웨어·CVE 목록이 그대로 남는다 — 고객이
       보고서에 캡처해 넣는 바로 그 탭이다.
       반대로 감사 타임라인(auditResult)은 별도로 올린 스냅샷들로 만든 것이라
       지금 연 설정과 무관하다. 지우면 사용자가 파일 6개를 다시 고르게 된다. */
    ['sevTableContent', 'sevSummaryBar', 'fndTotals', 'sevReachContent', 'sevReachCoverage',
     // 분포 막대는 숨기기만 해서 DOM 에 앞 장비의 "14건 중 5건" 이 남았다 —
     // 바로 위 규칙("카드를 숨기기만 하면 표가 DOM 에 남는다")의 예외였다.
     'thDormHist', 'verifyStatus',
     'verifyResult', 'advisorVersionBox', 'advisorSummaryBar', 'advisorCveTable',
     'advisorFixTable', 'advisorKnownTable', 'advisorCveCount', 'advisorFixCount',
     'advisorKnownCount'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '';
    });
    const advCard = document.getElementById('advisorResultCard');
    if (advCard) advCard.style.display = 'none';
    // 상태 문구는 비우는 게 아니라 '아직 안 함' 문구로 되돌린다 — 빈 줄만
    // 남으면 무엇을 해야 하는지 알 수 없다.
    /* **설정이 열려 있는데 "설정을 올리세요"라고 하면 안 된다.** 이 초기화는
       설정을 새로 불러올 때도 불리므로, 헤더에는 장비명·버전이 떠 있는데
       본문만 "Load a Config File" 이라 말했다(라운드 45 지적). 화면이 아는
       사실에 맞춰 다음 할 일을 알려 준다. */
    const advSt = document.getElementById('advisorStatus');
    apoSetText(advSt, currentView
      ? 'Click Analyze to check this firmware against known issues.'
      : 'Load a Config File and click Analyze.');
    /* FQDN 문구는 **여기서 쓰지 않는다.** 장비 종속 상태이므로 주인은
       adoptDeviceSession 하나다. 여기서 무조건 '지워졌다'로 덮었더니, 서버가
       그 장비의 캐시를 복원해 판정에 실제로 쓰고 있는데도(capture_used=true)
       화면은 FQDN 정책을 판정할 수 없다고 말했다(라운드 23 실측). 주인이
       둘이면 호출 순서가 이기고, 그 순서는 경로마다 다르다. */
    document.querySelectorAll('.sev-subtab-btn').forEach(b =>
      b.classList.toggle('active', b.dataset.sevTab === 'firewall'));
    /* **상태를 지우는 것과 화면을 지우는 것은 다른 일이다.** v129 는 전역
       두 개만 0 으로 만들고 끝냈는데, 장비 전환 경로는 `renderRangeTags` 가
       리셋보다 **먼저** 돈다(adoptDeviceSession → __apoSetRangesLocal →
       render, 그 다음 notifyConfigLoaded → __apoResetSev). 그래서 전역은
       0 인데 DOM 에는 앞 고객의 "14건 중 2건" 이 사실처럼 남았다 — 등급분포·
       정책표는 다 비었는데 이 한 줄만 거짓말을 했다(재비판 2라운드 발견 1).
       세 가지를 여기서 함께 끈다:

       1. 진행 타이머 — 주인이 `runClassify` 뿐이라, 판정 중에 설정을 바꾸면
          앞 장비의 "판정하는 중... 11초 경과" 가 **새 장비 화면에서 계속
          올라갔고**, 사용자가 받아야 할 유일한 지시("다시 실행하세요")를
          1초 만에 덮었다. 아래 statusEl 을 쓰기 **전에** 꺼야 한다.
       2. 판정 완료 문구의 재료 — 안 지우면 언어를 바꾸는 순간
          `onLangChange(showClassifyStatus)` 가 앞 장비의 "14건 판정 완료" 를
          되살린다(표는 0행인 채로).
       3. 대역 경고 DOM — 지운 전역으로 다시 그린다. */
    /* **판정 입력이 바뀌었다.** 장비는 그대로일 수 있다 — 객체 규칙·티켓
       형식을 저장하면 여기가 돈다. 비행 중이던 조치 후보·미리보기는 이제
       옛 입력으로 계산된 것이므로 화면에 쓰면 안 된다(5라운드 F-E). */
    window.__apoInputGen = (window.__apoInputGen || 0) + 1;
    /* **`__apoDeviceGen` 은 여기서 올리지 않는다.** 주인은
       `adoptDeviceSession` 하나다. 여기서도 올렸더니 config 업로드 한 번에
       번호가 2 오르는데, 그 사이에 `adoptDeviceSession` 이 쏜 객체 규칙
       요청이 끼어 있어 **정상 응답이 "남의 것" 으로 버려졌다** — 규칙 칸이
       영영 비었다(자기 수정이 만든 회귀, 실측으로 잡았다).
       주인이 둘이면 호출 순서가 이기고, 그 순서는 경로마다 다르다. */
    _classifyGen += 1;          // 도중에 도착할 응답은 이제 남의 것이다
    _stopClassifyProgress();
    _lastClassifyStatus = null;
    if (statusEl) {
      apoSetText(statusEl, reason
        || 'Configuration changed — run the assessment again.');
    }
    renderRangeTags();
    // shell(상단 상태·Overview·Action Plan)과 장비 적용 후보 목록도 같은 설정에
    // 딸린 결과다. 함께 버린다.
    window.APO?.onStale?.();
    window.__apoResetRemediation?.();
  }
  window.__apoResetSev = resetSeverityResults;

  /* 서버가 인정한 대역 목록을 화면에 반영한다 — **다만 아직 같은 장비일 때만.**
     세 경로(판정 중 저장·파일 임포트·`__apoSetRanges`)가 같은 코드를 각자
     갖고 있었고 셋 다 무방비였다. 14초 지연 실측: A 장비 대역이 B 화면에
     되살아났고 새로고침해도 남았다(서버에 저장됨). */
  function adoptServerRanges(info, gen) {
    if (gen !== (window.__apoDeviceGen || 0)) return false;
    userRanges.length = 0;
    (info?.user_ranges || []).forEach((r) => userRanges.push({ cidr: r.cidr }));
    renderRangeTags();
    return true;
  }

  function renderRangeTags() {
    window.APO?.onRanges?.(userRanges.length);
    if (!rangeTags) return;
    if (!userRanges.length) {
      /* **판정을 이미 돌렸다면 손실을 수치로 말한다.** "1·2·7 은 그래도
         판정합니다" 라는 문구로는 **지금 몇 건을 잃고 있는지**가 전달되지
         않는다 — 실 config 에서 76%(256/336)가 '판정 불가'로 나가는데도
         화면은 안심시키는 말만 했다(데모 리허설 TOP 1). 숫자가 있으면
         사용자는 대역을 넣는다. */
      const un = window.__apoUnknownCount || 0;
      const tot = window.__apoJudgedTotal || 0;
      rangeTags.innerHTML = '<span style="color:var(--muted);font-size:12px">'
        + escapeHtml(un && tot
            ? apoT('No IP ranges configured — {u} of {t} policies came out as "Cannot assess". Add your ranges and run the assessment again.',
                   { u: String(un), t: String(tot) })
            : apoT('No IP ranges configured — Severity 1/2/7 can still be assessed'))
        + '</span>';
      return;
    }
    /* **전 인터넷을 "사용자" 로 두면 그 축이 무의미해진다.** `0.0.0.0/0`
       (또는 `/1` 두 개)을 받고도 화면은 "서버 트래픽과 사용자 트래픽을
       구분할 수 있습니다" 라고 단언했다. 대역은 '파일에서 가져오기' 경로가
       있어 FortiGate `all` 객체가 섞여 들어오기 쉽다(8라운드 발견 6).
       모든 겹침을 계산하지는 않는다 — 실제로 보고된 두 모양만 잡는다. */
    const _broad = userRanges.filter((r) => {
      const m = /\/(\d{1,2})\s*$/.exec(String(r.cidr || ''));
      return m && Number(m[1]) <= 1;
    });
    const _broadNote = _broad.length
      ? `<div style="color:var(--warn,#9c6500);font-size:12px;margin-top:6px">`
        + escapeHtml(apoT('{list} covers every address, so nothing is left to '
                          + 'count as server traffic — Severity 3/4/5/6 will '
                          + 'not tell users and servers apart.',
                          { list: _broad.map((r) => r.cidr).join(', ') }))
        + '</div>'
      : '';
    rangeTags.innerHTML = userRanges.map((r,i) =>
      `<span class="sev-range-item">${escapeHtml(r.cidr)}<button class="sev-range-del" data-i="${i}">×</button></span>`
    ).join('') + _broadNote;
    rangeTags.querySelectorAll('.sev-range-del').forEach(btn => {
      btn.addEventListener('click', () => {
        // 지우는 것도 바로 저장한다 — 추가와 규칙이 다르면 화면과 저장이
        // 어긋나고, 어긋난 쪽이 판정에 쓰인다.
        const next = userRanges
          .filter((_, i) => i !== Number(btn.dataset.i))
          .map((r) => r.cidr);
        (window.__apoSetRanges?.(next) || Promise.resolve())
          /* 지우는 것도 판정 축을 바꾼다 — 추가와 같은 안내를 해야 한다.
             여기는 아예 아무 말도 없어서, 대역을 지우고도 화면의 낡은 결과를
             현재로 읽었다(8라운드 F2 와 같은 뿌리). */
          .then(() => {
            // 추가 경로와 **같은 요소**에 쓴다(`sevClassifyStatus`) —
            // 다른 자리에 쓰면 사용자가 보는 곳이 갈린다.
            const st = document.getElementById('sevClassifyStatus');
            if (st && window.__sevHasData) {
              window.__apoForgetClassifyStatus?.();
              apoSetText(st, 'Run the assessment again to apply it.');
            }
          })
          .catch(() => {});
      });
    });
  }

  /* 패널 상단 총계 한 줄 — 집계값을 읽어 표시만 한다(판정 로직 무관).
     정책=전체, 판정=등급이 매겨진 것(등급 0='판정 불가' 제외, Overview 의
     'Not judged' 와 같은 기준), 표시=지금 이 탭·필터로 표에 그려진 행 수. */
  function renderFndTotals() {
    const el = document.getElementById('fndTotals');
    if (!el || !sevData) return;
    const all = [...(sevData.firewall||[]), ...(sevData.proxy||[])];
    const total = all.length;
    const judged = all.filter(p => (p.urgency ?? 0) !== 0).length;
    const tabPols = sevData[activeSevTab] || [];
    const shown = activeSevFilter != null
      ? tabPols.filter(p => (p.urgency ?? 0) === activeSevFilter).length
      : tabPols.length;
    apoSetText(el, '{total} policies · {judged} judged · {shown} shown',
      { total, judged, shown });
  }

  function renderSummaryBar(data) {
    if (!phase2Card || !summaryBar) return;
    const all = [...(data.firewall||[]),...(data.proxy||[])];
    const counts = {};
    all.forEach(p => { const u=p.urgency??0; counts[u]=(counts[u]||0)+1; });
    if (!Object.keys(counts).length) { phase2Card.style.display='none'; return; }
    phase2Card.style.display='';
    summaryBar.innerHTML = Object.entries(counts).sort(([a],[b])=>Number(a)-Number(b)).map(([u,cnt]) => {
      const bg=SEV_BG[u]||SEV_BG[0], tc2=SEV_TC[u]||SEV_TC[0];
      const isAct = activeSevFilter==u;
      const label = SEV_LABELS[u] || `Sev ${u}`;
      return `<span class="sev-chip${isAct?' active':''}" data-sev="${u}" style="background:${bg};color:${tc2}"><strong>${escapeHtml(label)}</strong> ${u}: ${escapeHtml(String(cnt))}</span>`;
    }).join('');
    summaryBar.querySelectorAll('.sev-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const u = Number(chip.dataset.sev);
        activeSevFilter = (activeSevFilter==u)?null:u;
        renderSummaryBar(data); renderTable();
      });
    });
  }

  /* 등급 칩은 firewall+proxy를 합쳐 세는데 표는 한 번에 한쪽만 보여준다.
     설명이 없으면 "Critical 1: 3"을 누르고 2행짜리 표를 보게 되고, 나머지 한 건이
     어디 갔는지 알 방법이 없다. 다른 탭에 몇 건 있는지 표 위에 적는다. */
  function _otherTabNote() {
    if (activeSevFilter == null || !sevData) return '';
    const other = activeSevTab === 'firewall' ? 'proxy' : 'firewall';
    const n = (sevData[other]||[]).filter(p=>(p.urgency??0)===activeSevFilter).length;
    if (!n) return '';
    const label = other === 'proxy' ? 'Proxy Policy' : 'Firewall Policy';
    return `<div class="inline-status" style="margin-bottom:8px">${n} more polic${n===1?'y':'ies'} at this severity ${n===1?'is':'are'} on the ${label} tab.</div>`;
  }

  /* 이 정책이 **위 정책에 가려 도달 불가**인가. 그렇다면 권고 조치를 그대로
     따르면 안 된다 — 조치 계획은 이 사실을 반영해 "위 것부터 정하라"고 하는데,
     판정표만 "즉시 비활성"이라 말하면 감사자는 표를 보고 순서를 어긴다.
     등급은 바꾸지 않는다. 사실 한 줄을 덧붙일 뿐이다. */
  function _shadowNote(p, ptype) {
    /* 도달불가 검사는 firewall 정책만 본다(reachability). FortiGate 는
       fw/proxy 번호를 각각 1부터 매기므로, proxy 탭 행에 이 주석을 달면
       번호·VDOM 이 같은 firewall 도달불가가 살아있는 proxy 정책에 거짓
       지시("위 것부터 정하라")를 붙인다(라운드 54 계약·경계값 렌즈 동시 —
       실 config fw/proxy ID 충돌 44건). 워크북은 이 축을 이미 지킨다. */
    if (ptype === 'proxy') return '';
    const un = (_sevReach && _sevReach.unreachable) || [];
    /* VDOM 은 정책 번호의 일부다 — 번호만 대조하면 다른 VDOM 의 같은 번호
       도달불가가 살아있는 정책에 거짓 가림막 주석을 단다(라운드 52). 워크북
       Action Plan·Unreachable 시트는 이미 VDOM 으로 구별한다. */
    const hit = un.find((u) => String(u.policy_id) === String(p.policy_id)
                            && String(u.vdom || '') === String(p.vdom || ''));
    if (!hit) return '';
    return `<div class="shadow-note">${escapeHtml(
      apoT('Unreachable while policy {id} above it stays enabled — settle that one first.',
           { id: hit.shadowed_by }))}</div>`;
  }

  function renderTable() {
    if (!tableCard||!tableContent||!sevData) return;
    renderFndTotals();   // 탭·필터·언어 변경 모두 이 함수를 거친다
    tableCard.style.display='';
    const policies = sevData[activeSevTab]||[];
    const filtered = activeSevFilter!=null ? policies.filter(p=>(p.urgency??0)===activeSevFilter) : policies;
    if (!filtered.length) {
      tableContent.innerHTML = _otherTabNote()
        + '<div class="empty-state"><strong>' + escapeHtml(apoT('No results'))
        + '</strong><span>' + escapeHtml(apoT('No policies match the selected criteria on this tab.'))
        + '</span></div>';
      return;
    }
    const rows = filtered.map(p => {
      const u=p.urgency??0;
      const bg=SEV_BG[u]||SEV_BG[0], tc2=SEV_TC[u]||SEV_TC[0];
      const tagHtml=(p.tags||[]).map(t=>`<span class="tag-badge ${TAG_COLORS[t]||'tag-default'}">${escapeHtml(t)}</span>`).join('');
      const mkBadges=arr=>(arr||[]).map(v=>`<span class="badge">${escapeHtml(String(v))}</span>`).join('')||'-';
      return `<tr data-sev="${u}">
        <td><span class="sev-badge" style="background:${bg};color:${tc2}">${u===0?'?':u}</span></td>
        <td>${escapeHtml(p.risk_level||'')}</td>
        <td><div class="badge-list">${tagHtml||'-'}</div></td>
        <td>${escapeHtml(String(p.policy_id??''))}</td>
        <td>${escapeHtml(p.name||'')}</td>
        <td><div class="badge-list">${mkBadges(p.srcaddr_display)}</div></td>
        <td><div class="badge-list">${mkBadges(p.dstaddr_display)}</div></td>
        <td><div class="badge-list">${mkBadges(p.service_display)}</div></td>
        <td>${escapeHtml(p.action||'')}</td>
        <td>${escapeHtml(p.status||'')}</td>
        <td>${escapeHtml(String(p.hit_count??'-'))}</td>
        <td>${escapeHtml(p.last_used||'-')}</td>
        <td>${escapeHtml(p.traffic_type||'')}</td>
        <td style="font-size:11px;max-width:200px">${escapeHtml(p.reason||'')}</td>
        <td style="font-size:11px;max-width:140px">${escapeHtml(p.recommended_action||'')}${_shadowNote(p, activeSevTab)}</td>
      </tr>`;
    }).join('');
    tableContent.innerHTML=_otherTabNote()+`<table class="result-table"><thead><tr>
      <th>Sev</th><th>Risk Level</th><th>Tags</th><th>Policy ID</th><th>Name</th><th>Source</th><th>Destination</th><th>Service</th><th>Action</th><th>Status</th><th>Hit Count</th><th>Last Used</th><th>Traffic Type</th><th>Reason</th><th>Recommended Action</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
  }

  // ── 판정 임계값 설정 패널 ─────────────────────────────────────────────
  // 기본값은 활성 프로파일에서 온다. 사용자가 손대지 않으면 프로파일 값이
  // 그대로 되돌아가므로 결과가 변하지 않는다.
  const thToggle = document.getElementById('sevThresholdToggle');
  const thPanel  = document.getElementById('sevThresholdPanel');
  const thEls = {
    dormancy_days:              document.getElementById('thDormancy'),
    long_dormancy_days:         document.getElementById('thLongDormancy'),
    approval_window_days:       document.getElementById('thApproval'),
    /* ss_schedule_age_years 는 뺐다 — 판정에 쓰이지 않는 값이라 입력 카드도
       함께 제거했다(index.html 주석). 프로파일 YAML 의 키는 옛 파일 호환을
       위해 서버가 계속 받아 주지만, 화면은 받지도 보내지도 않는다. */
    registration_fallback_year: document.getElementById('thRegYear'),
    use_absolute_hit_threshold: document.getElementById('thUseAbsHit'),
    su_hit_multiplier:          document.getElementById('thSuMult'),
    ss_hit_threshold:           document.getElementById('thSsHit'),
  };
  let thLoaded = false;

  if (thToggle && thPanel) thToggle.addEventListener('click', () => {
    const open = thPanel.style.display !== 'none';
    thPanel.style.display = open ? 'none' : '';
    thToggle.textContent = open ? 'Show' : 'Hide';
  });

  /* 사용자 손이 닿지 않은 프로파일 원본 — Reset 이 되돌릴 목적지다. */
  let _thProfileDefaults = null;
  let _thPresets = [];
  function _thFill(th){
    for (const [key, el] of Object.entries(thEls)) {
      if (!el) continue;
      if (el.type === 'checkbox') el.checked = !!th[key];
      else el.value = (th[key] ?? '') === null ? '' : (th[key] ?? '');
    }
  }
  async function loadThresholdDefaults() {
    try {
      const res = await fetch('/api/profile');
      if (!res.ok) return;
      const p = await res.json();
      const nameEl = document.getElementById('sevProfileName');
      if (nameEl) nameEl.textContent = p.name || 'default';
      _thProfileDefaults = p.profile_thresholds || null;
      _thPresets = p.presets || [];
      _thRenderPresets();
      _thFill(p.thresholds || {});
      thLoaded = true;
      _thSnapshotApplied();
      _thRenderActive();
      _thLoadHistogram();
    } catch (_) { /* 프로파일 API 실패 시 서버측 프로파일 값으로 동작 */ }
  }
  loadThresholdDefaults();
  /* 룰 세트 가져오기가 임계값을 바꾸면 이 입력칸도 새로 읽어 화면과 적용값을
     맞춘다(객체 이름·티켓이 쓰는 것과 같은 훅 패턴). */
  window.__apoLoadThresholds = () => { loadThresholdDefaults(); };

  function _thRenderPresets(){
    const box = document.getElementById('thPresets');
    if (!box) return;
    box.innerHTML = _thPresets.map((p, i) =>
      `<button type="button" class="secondary-btn th-preset" data-th-preset="${i}"
        title="${esc(apoT(p.why || ''))}">${esc(apoT(p.label || ''))}</button>`).join('');
    box.querySelectorAll('.th-preset').forEach(btn =>
      btn.addEventListener('click', () => {
        /* **프리셋은 8개 값 전부를 놓는다.** 두 개만 바꾸던 동안 'Strict' 를
           눌러도 hit 임계값·승인 유예는 그대로여서 이름이 거짓이었다. */
        const p = _thPresets[Number(btn.dataset.thPreset)];
        if (p) { _thFill(p.thresholds || {}); _thOnEdit(); }
      }));
  }

  /* **Reset 은 프로파일 원본으로 되돌린다.** 전에는 /api/profile 의
     thresholds(프로파일 ∪ 사용자값)로 되돌려서, 한 번이라도 판정을 돌리면
     override 가 8개 키를 다 채워 방금 쓰던 값을 그대로 되돌려 놓는 no-op 가
     됐다 — 버튼이 있는데 아무 일도 안 하는 상태였다(임계값 UX 조사). */
  const thReset = document.getElementById('thResetBtn');
  if (thReset) thReset.addEventListener('click', () => {
    if (_thProfileDefaults) { _thFill(_thProfileDefaults); _thOnEdit(); }
    else loadThresholdDefaults();
  });

  /* ── 값 → 결과 연결 ────────────────────────────────────────────────
     세 가지를 함께 둔다. 셋 다 없어서 "어떻게 넣어야 하는지 모르겠다"가
     나왔다(2026-08-25 Jayden):
       · 미리보기  이 값이면 몇 건이 어디로 움직이는가
       · 낡음 배너 화면에 남은 결과가 지금 설정보다 앞선다는 사실
       · 히스토그램 휴면 기준을 어디에 그을지 볼 근거(특히 '기록 없음')
     **자동 재분류는 하지 않는다.** 값 편집 중 매 타이핑마다 전량 재판정이
     돌면 화면이 요동친다 — FQDN 캐시는 자동, 임계값은 버튼인 이유다. */
  const SEV_ORDER = [1, 2, 3, 4, 5, 6, 7, 0];
  let _thApplied = null;      // 마지막 Classify 에 실제로 쓴 값
  let _thPreviewTimer = null;

  function _thSnapshotApplied(){
    _thApplied = JSON.stringify(collectThresholds());
    _thShowStale(false);
    const box = document.getElementById('thPreview');
    if (box) box.classList.add('hidden');
  }
  window.__apoThSnapshot = _thSnapshotApplied;

  function _thShowStale(on){
    const el = document.getElementById('thStaleNote');
    if (el) el.classList.toggle('hidden', !on);
  }
  function _thDirty(){
    return thLoaded && _thApplied !== null
      && JSON.stringify(collectThresholds()) !== _thApplied;
  }

  async function _thRunPreview(){
    const box = document.getElementById('thPreview');
    if (!box) return;
    if (!_thDirty()) { box.classList.add('hidden'); return; }
    /* 사용자가 **휴면 기준을 어디에 그을지 정하는 근거 문장**이다. 늦게
       오면 앞 장비 수치로 "바꿔도 움직이는 정책이 없습니다" 라고 말한다
       (5라운드 F-D). 입력 축까지 본다 — 임계값이 또 바뀌었으면 이 답은
       이미 낡은 것이다. */
    const fresh = apoStillThisInput();
    try {
      const r = await fetch('/api/severity/preview-thresholds', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        // 판정을 계산하는 경로는 전부 장비 게이트를 지난다 — 탭 두 개로
        // 남의 장비 판정이 이 화면에 뜨는 것을 서버가 막는다(라운드 22).
        body: JSON.stringify({ thresholds: collectThresholds(),
                               device_id: currentDeviceId || undefined }),
      });
      if (!r.ok) { box.classList.add('hidden'); return; }
      const d = await r.json();
      if (!fresh()) return;
      if (!d.moved) {
        /* **0 건도 사실이다.** 아무 말 없이 숨기면 사용자는 미리보기가 아직
           안 돈 것인지 정말 영향이 없는 것인지 구별할 수 없다. */
        box.textContent = apoT(
          'With these values nothing is re-classified — all {total} policies keep their current grade.',
          { total: d.total });
        box.classList.remove('hidden');
        return;
      }
      const deltas = SEV_ORDER.map(u => {
        const k = String(u);
        const diff = (d.after[k] || 0) - (d.before[k] || 0);
        return diff ? `${apoT(SEV_LABELS[u] || k)} ${diff > 0 ? '+' : ''}${diff}` : null;
      }).filter(Boolean);
      box.textContent = apoT(
        'With these values {moved} of {total} policies change grade:',
        { moved: d.moved, total: d.total }) + ' ' + deltas.join(' · ');
      box.classList.remove('hidden');
    } catch (_) { box.classList.add('hidden'); }
  }

  /* Reference 화면의 등급 기준표는 기본값 고정 문구다 — 지금 쓰는 값을 그
     옆에 적어 두지 않으면 표와 판정 사유가 서로 다른 숫자를 말한다. */
  function _thRenderActive(){
    const el = document.getElementById('refActiveTh');
    if (!el || !thLoaded) return;
    const t = collectThresholds();
    const parts = [
      apoT('unused after {n} days', { n: t.dormancy_days }),
      apoT('temp policies after {n} days', { n: t.long_dormancy_days }),
    ];
    if (t.approval_window_days) {
      parts.push(apoT('approval window {n} days', { n: t.approval_window_days }));
    }
    if (t.use_absolute_hit_threshold && t.su_hit_multiplier) {
      parts.push(apoT('server-user hits below years x {n}', { n: t.su_hit_multiplier }));
    }
    if (t.use_absolute_hit_threshold && t.ss_hit_threshold) {
      parts.push(apoT('server-server hits below {n}', { n: t.ss_hit_threshold }));
    }
    el.textContent = apoT('This session uses:') + ' ' + parts.join(' · ');
    el.classList.remove('hidden');
  }

  function _thOnEdit(){
    _thRenderActive();
    _thShowStale(_thDirty() && !!window.__sevHasData);
    // 타이핑 중 매 글자마다 전량 재판정을 돌리지 않는다.
    clearTimeout(_thPreviewTimer);
    _thPreviewTimer = setTimeout(_thRunPreview, 350);
    _thDrawHistogram();
  }
  Object.values(thEls).forEach(el => {
    if (!el) return;
    el.addEventListener(el.type === 'checkbox' ? 'change' : 'input', _thOnEdit);
  });
  document.getElementById('thReclassifyBtn')?.addEventListener('click', () => {
    window.__apoRunClassify?.();
  });

  /* 마지막 사용 경과일 분포. 한 번 받아 두고 커트라인만 다시 그린다 —
     config 가 바뀌면 resetSeverityResults 경로가 다시 부른다. */
  let _thHist = null;
  async function _thLoadHistogram(){
    /* **이 막대는 한 번도 뜨지 않았다.** 유일한 호출이 모듈 초기화
       (`loadThresholdDefaults`)뿐인데, 그때는 `currentDeviceId` 가 아직
       null 이라 `device_id` 없이 나가고 장비 게이트가 409 를 낸다. 그리고
       다시 부르는 곳이 없었다 — `window.__apoThHistogram` 은 정의만 있고
       호출부가 0개였다(재비판 4라운드 발견 4). 장비를 열 때 다시 읽는다.
       서버 docstring 이 "'기록 없음' 이 몇 건인지가 핵심" 이라 말하는
       그 막대다. */
    /* **장비 축이다.** 한때 입력 축(`apoStillThisInput`)을 썼는데,
       `adoptDeviceSession` 이 이 요청을 쏜 **직후** 같은 전환 흐름의
       `resetSeverityResults` 가 입력 세대를 올려 **자기 응답이 100%
       버려졌다** — 경합이 아니라 결정론이다. 그러면 앞 장비 값이 화면에
       그대로 남는다(실패 시 지우는 코드가 없다). 리포트 Summary 에
       인쇄되는 해시를 화면이 거짓으로 말하게 된다(6라운드 F1 실측).
       이 값들은 장비 정체성에만 의존하고, 입력이 바뀌면 리셋 **뒤에**
       다시 불린다 — 그쪽이 정상 경로다. */
    const fresh = apoStillThisDevice();
    try {
      const q = currentDeviceId
        ? `?device_id=${encodeURIComponent(currentDeviceId)}` : '';
      const r = await fetch('/api/severity/dormancy-histogram' + q);
      /* **실패 갈래가 가드 밖이면 늦은 실패가 현재 데이터를 지운다.**
         장비가 열린 채 페이지를 로드하면 이 요청은 **항상 두 번** 나간다 —
         모듈 초기화가 `device_id` 없이 쏴서 게이트 409 를 받고, 그 뒤
         `adoptDeviceSession` 이 제대로 쏜다. 앞의 실패가 늦게 오면 뒤의
         정상 분포를 지운다(7라운드 F1 실측: 막대가 떴다가 사라졌다).
         세대는 정확히 작동했다 — 가드 자리만 틀렸다. */
      if (!fresh()) return;
      if (!r.ok) { _thHist = null; _thDrawHistogram(); return; }
      const got = await r.json();
      if (!fresh()) return;          // 늦게 왔다 — 앞 장비의 분포다
      _thHist = got;
    } catch (_) { if (!fresh()) return; _thHist = null; }
    _thDrawHistogram();
  }
  window.__apoThHistogram = _thLoadHistogram;

  function _thDrawHistogram(){
    const el = document.getElementById('thDormHist');
    if (!el) return;
    const h = _thHist;
    if (!h || !h.total) { el.classList.add('hidden'); return; }
    const labels = [];
    let prev = 0;
    (h.edges || []).forEach(e => { labels.push(`${prev}–${e}`); prev = e; });
    labels.push(`${prev}+`);
    const cut = Number(thEls.dormancy_days?.value || 0);
    const max = Math.max(...(h.buckets || [0]), h.unknown || 0, 1);
    /* 커트라인은 '이 눈금부터 미사용으로 본다'는 뜻이다. 막대 위에 선만
       긋고 말면 어느 쪽이 미사용인지 알 수 없어, 넘어가는 막대를 칠한다. */
    let lo = 0;
    const bars = (h.buckets || []).map((n, i) => {
      const hi = (h.edges || [])[i];
      const beyond = cut > 0 && lo >= cut;
      lo = hi == null ? lo : hi;
      return `<span class="th-bar${beyond ? ' is-beyond' : ''}"
        style="height:${Math.round((n / max) * 100) || 2}%"
        title="${esc(labels[i])} ${apoT('days')}: ${n}"></span>`;
    }).join('');
    const unk = h.unknown || 0;
    el.innerHTML = `<span class="th-hist-bars">${bars}</span>`
      + `<span class="th-hist-cap">${esc(apoT(
          'Last used, {total} policies — {unknown} have no record.',
          { total: h.total, unknown: unk }))}`
      + (unk && unk >= h.total / 2
          /* **이게 핵심 경고다.** 절반 이상이 기록 없음이면 이 값을 무엇으로
             두든 판정이 거의 안 바뀐다 — 숫자만 만지작거리게 된다. */
          ? ' ' + esc(apoT('Most policies have no usage record, so this value changes little — load a usage CSV first.'))
          : '') + '</span>';
    el.classList.remove('hidden');
  }

  // FQDN 캐시 덤프 업로드 — 업로드 후 재분류해야 반영된다
  const fqdnBtn = document.getElementById('fqdnDumpBtn');
  const fqdnFile = document.getElementById('fqdnDumpFile');
  const fqdnSt = document.getElementById('fqdnDumpStatus');
  // 캐시가 갱신되면 곧바로 재분류한다 — 위로 스크롤해 Classify를 다시
  // 누르게 하면 사용자가 반영 여부를 헷갈린다.
  async function applyFqdnCache(d, how, fresh) {
    /* **이 장비가 DNS 캡처를 갖는다고 단언하고 재판정까지 돌린다.** 늦게
       오면 B 가 캡처를 가졌다고 화면이 말하고, B 를 A 의 근거로 다시
       판정한다(4라운드 발견 5). 세대는 **호출부가** 요청 직전에 잡아
       넘긴다 — 여기서 잡으면 방금 잡은 값과 비교하는 셈이라 늘 참이다. */
    if (fresh && !fresh()) return;
    currentDeviceHasFqdn = true;
    announceSourceState();
    const head = `DNS resolutions ${how}: ${d.names} FQDNs / ${d.ips} IPs (captured ${d.captured_at}).`;
    if (fqdnSt) fqdnSt.textContent = `${head} Re-classifying...`;
    await runClassify();
    /* runClassify는 자기 오류를 삼키므로(상태줄에만 남긴다) 무조건 "적용됨"이라고
       쓰면, config가 없어 분류가 실패한 상황에서도 커버리지가 열렸다고 알린다.
       분류 결과가 실제로 생겼는지 보고 문구를 정한다. */
    if (!fqdnSt) return;
    /* vdom-dns 를 켠 VDOM 이 있으면 서버가 warning 을 실어 보낸다(라운드 66)
       — "Applied — assessed" 라고만 말하면 그 VDOM 의 FQDN 정책이 여전히
       보류라는 사실이 숨는다. i18n-dynamic: 서버 경고 원문 병기. */
    const tail = d.warning ? ` ${d.warning}` : '';
    fqdnSt.textContent = (window.__sevHasData
      ? `${head} Applied — FQDN policies are now assessed.`
      : `${head} Not applied yet — load a configuration and run the assessment.`)
      + tail;
  }

  if (fqdnBtn) fqdnBtn.addEventListener('click', () => fqdnFile?.click());
  if (fqdnFile) fqdnFile.addEventListener('change', async () => {
    const f = fqdnFile.files?.[0];
    if (!f) return;
    const fd = new FormData();
    fd.append('dump', f);
    // 어느 장비의 DNS 스냅샷인지 지목한다 — 대역·CSV와 같은 게이트.
    if (currentDeviceId) fd.append('device_id', currentDeviceId);
    if (fqdnSt) fqdnSt.textContent = apoT('Reading the dump...');
    const fresh = apoStillThisDevice();
    try {
      const res = await fetch('/api/fqdn-cache/import', {method: 'POST', body: fd});
      const d = await res.json();
      if (!res.ok) throw new Error(serverMsg(d, 'Import failed'));
      await applyFqdnCache(d, 'loaded from file', fresh);
    } catch (err) { if (fqdnSt) fqdnSt.textContent = err.message || 'Import failed'; }
    fqdnFile.value = '';
  });

  const fqdnFetch = document.getElementById('fqdnFetchBtn');
  if (fqdnFetch) fqdnFetch.addEventListener('click', async () => {
    if (fqdnSt) fqdnSt.textContent = apoT('Fetching FQDN resolutions from the device...');
    fqdnFetch.disabled = true;
    const fresh = apoStillThisDevice();
    try {
      const res = await fetch('/api/fqdn-cache/fetch-device', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ device_id: currentDeviceId || undefined }),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(serverMsg(d, 'Fetch failed'));
      await applyFqdnCache(d, 'fetched from device', fresh);
    } catch (err) { if (fqdnSt) fqdnSt.textContent = err.message || 'Fetch failed'; }
    finally { fqdnFetch.disabled = false; }
  });

  function collectThresholds() {
    const out = {};
    for (const [key, el] of Object.entries(thEls)) {
      if (!el) continue;
      if (el.type === 'checkbox') { out[key] = el.checked; continue; }
      const v = el.value.trim();
      out[key] = v === '' ? null : Number(v);
    }
    return out;
  }

  /* 판정표가 **조치 계획과 같은 사실**을 말하려면 도달불가 정보를 알아야
     한다. 같은 정책을 두고 표는 "즉시 비활성", 조치 계획은 "위 것부터
     정하라" 라고 서로 다른 지시를 하고 있었다(B-32) — 조치 계획 쪽이 옳고,
     표가 그 사실을 모르고 있었을 뿐이다. */
  let _sevReach = null;

  function renderReachability(reach) {
    const card = document.getElementById('sevReachCard');
    const content = document.getElementById('sevReachContent');
    const coverage = document.getElementById('sevReachCoverage');
    if (!card || !content) return;
    const unreachable = (reach && reach.unreachable) || [];
    const skipped = (reach && reach.skipped) || [];
    if (!reach || (!unreachable.length && !skipped.length)) { card.style.display='none'; return; }
    card.style.display='';
    if (coverage) coverage.textContent =
      apoT('{n} unreachable · assessed {checked}/{total} enabled policies · '
           + '{skipped} skipped',
           { n: unreachable.length, checked: reach.checked,
             total: reach.total_enabled, skipped: skipped.length });
    let html = '';
    if (unreachable.length) {
      const cap = reach.fqdn_captured_at;
      html += `<table class="result-table"><thead><tr>
        <th>VDOM</th><th>Policy ID</th><th>Name</th><th>Shadowed By</th><th>Shadower Name</th><th>Shadower Action</th><th>Proof</th>
      </tr></thead><tbody>` + unreachable.map(u => `<tr>
        <td>${escapeHtml(String(u.vdom??''))}</td>
        <td>${escapeHtml(String(u.policy_id??''))}</td>
        <td>${escapeHtml(u.name||'')}</td>
        <td>${escapeHtml(String(u.shadowed_by??''))}</td>
        <td>${escapeHtml(u.shadowed_by_name||'')}</td>
        <td>${escapeHtml(u.shadowed_by_action||'')}</td>
        <td>${u.proof === 'config'
              ? '<span title="Provable from the configuration alone">config</span>'
              : u.proof === 'capture'
              ? `<span title="Provable as of the DNS cache capture${cap ? ' (' + escapeHtml(cap) + ')' : ''} — FQDN resolutions can change over time">DNS capture</span>`
              /* 등급이 없거나 모르는 값이면 "config"라고 단정할 수도, 있지도
                 않은 DNS 수집을 주장할 수도 없다. 모른다고 적고 약한 쪽으로 둔다. */
              : '<span title="The proof grade could not be determined — treat this as time-limited and re-check before removing">unverified</span>'}</td>
      </tr>`).join('') + '</tbody></table>';
    } else {
      html += '<div class="empty-state"><strong>No unreachable policies found</strong><span>Among the policies that could be assessed, none is fully shadowed by a single policy above it.</span></div>';
    }
    if (skipped.length) {
      html += `<details style="margin-top:12px"><summary style="cursor:pointer;font-size:12px;color:var(--muted)">Skipped policies (${skipped.length}) — cannot be proven either way</summary>
        <table class="result-table" style="margin-top:8px"><thead><tr><th>VDOM</th><th>Policy ID</th><th>Name</th><th>Reason</th></tr></thead><tbody>` +
        skipped.map(s => `<tr><td>${escapeHtml(String(s.vdom??''))}</td><td>${escapeHtml(String(s.policy_id??''))}</td><td>${escapeHtml(s.name||'')}</td><td>${escapeHtml(s.reason||'')}</td></tr>`).join('') +
        '</tbody></table></details>';
    }
    content.innerHTML = html;
  }

  // ── 감사 증적 타임라인 (B-06) ─────────────────────────────────────
  (() => {
    const pick = document.getElementById('auditPickBtn');
    const files = document.getElementById('auditFiles');
    const names = document.getElementById('auditFileNames');
    const run = document.getElementById('auditRunBtn');
    const exp = document.getElementById('auditExportBtn');
    const st = document.getElementById('auditStatus');
    const out = document.getElementById('auditResult');
    if (!run) return;
    let hasTimeline = false;
    if (pick) pick.addEventListener('click', () => files?.click());
    if (files) files.addEventListener('change', () => {
      const list = Array.from(files.files || []);
      if (names) names.textContent = list.length
        ? list.map(f => f.name).join(' → ') : 'No snapshots selected';
    });
    run.addEventListener('click', async () => {
      const list = Array.from(files?.files || []);
      if (list.length < 2) { if (st) st.textContent = apoT('Select at least two snapshots (oldest first).'); return; }
      if (st) st.textContent = apoT('Building the timeline...');
      const fd = new FormData();
      list.forEach(f => fd.append('snapshots', f));
      /* `adoptDeviceSession` 이 장비를 바꿀 때 이 표를 **일부러 비운다**
         ("표를 그대로 두면 내보내기가 400 으로 실패하는데 사용자는 이유를
         알 수 없다"). 늦게 온 응답이 그 상태를 그대로 되돌려, 지운 표가
         336행으로 되살아나고 내보내기 버튼까지 다시 떴다(5라운드 F-B).
         **서명란이 있는 문서**를 만드는 화면이다. */
      const fresh = apoStillThisDevice();
      try {
        if (currentDeviceId) fd.append('device_id', currentDeviceId);
        const res = await fetch('/api/audit/timeline', {method: 'POST', body: fd});
        const data = await res.json();
        if (!res.ok) throw new Error(serverMsg(data, 'Timeline failed'));
        if (!fresh()) return;
        hasTimeline = true;
        if (exp) exp.style.display = '';
        /* 서로 다른 방화벽을 섞으면 '변경 0건'은 아무 의미가 없다 — 그 문서를
           받는 사람은 '이 장비는 변경 없음'으로 읽는다. 만든 자리에서 바로
           말한다. **경고는 경고로 보여야 한다**: 서명란이 있는 감사 문서를
           만드는 화면인데, 이 사실이 스냅샷 개수와 같은 급의 회색 한 줄로
           붙어 있었다(라운드 26 지적). */
        if (st) {
          st.textContent = `${data.snapshots.length} snapshots, `
            + `${data.intervals.length} interval(s).`;
          st.classList.toggle('is-warning', !!data.mixed_devices);
          if (data.mixed_devices) {
            st.textContent += ' ⚠ ' + apoT(
              'Warning: these snapshots are from different firewalls ({list}). '
              + 'Differences between them are not one device’s change history.',
              { list: data.mixed_devices.join(', ') });
          }
        }
        if (out) out.innerHTML = `<table class="result-table"><thead><tr>
          <th>#</th><th>From → To</th><th>Policies added</th><th>Policies removed</th><th>Policies modified</th><th>Objects added / removed</th><th>Other sections</th><th>Modified policy IDs</th>
        </tr></thead><tbody>` + data.intervals.map((iv, i) => {
          const s2 = iv.summary || {};
          /* **화면에 'Other sections' 열이 아예 없었다.** 엑셀에는 3건이라
             적히는데 화면 표에는 그 열 자체가 없어, 서명하는 사람이 보는
             화면이 파일보다 적게 말했다(라운드 46 실측). 관리자 계정 추가·
             VPN 신설·주소객체 확대가 화면에서 통째로 빠졌다. */
          const names = [];
          (s2.other_sections || []).forEach((o) => {
            ['added', 'removed', 'changed'].forEach((k, ki) => {
              (o[k] || []).forEach((n) => names.push(
                `${o.section}: ${'+-~'[ki]}${n}`));
            });
          });
          (s2.changed_object_names || []).forEach((n) => names.push(`object: ~${n}`));
          const chg = s2.changed_objects ? ` / ${s2.changed_objects} redefined` : '';
          return `<tr><td>${i + 1}</td>
            <td>${escapeHtml(iv.from)} → ${escapeHtml(iv.to)}</td>
            <td>${s2.added_policies}</td><td>${s2.removed_policies}</td><td>${s2.changed_policies}</td>
            <td>${s2.added_objects} added / ${s2.removed_objects} removed${escapeHtml(chg)}</td>
            <td style="font-size:11px;max-width:260px">${escapeHtml(String(s2.other_changes || 0))}${
              names.length ? ' — ' + escapeHtml(names.slice(0, 8).join('; ')) : ''}</td>
            <td style="font-size:11px;max-width:220px">${escapeHtml((s2.changed_ids || []).join(', '))}</td></tr>`;
        }).join('') + '</tbody></table>';
      } catch (err) { if (st) st.textContent = err.message || apoT('Failed'); }
    });
    if (exp) exp.addEventListener('click', async () => {
      if (!hasTimeline) return;
      if (!(await licenseGate())) return;
      const res = await fetch('/api/audit/evidence-workbook' + (currentDeviceId ? `?device_id=${encodeURIComponent(currentDeviceId)}` : ''),
        {method: 'POST'});
      if (!res.ok) { await alertApiError(res, 'Evidence export failed.'); return; }
      saveResponseAs(await res.blob(), res, 'apo_review_evidence.xlsx');
    });
  })();

  // ── 화이트라벨 브랜딩 (MSP 티어에만 노출) ─────────────────────────
  (async () => {
    try {
      const st = await (await fetch('/api/license/status')).json();
      if (!st.licensed || st.tier !== 'msp') return;
      const panel = document.getElementById('brandingPanel');
      if (!panel) return;
      panel.style.display = '';
      const b = await (await fetch('/api/report/branding')).json();
      const co = document.getElementById('brandCompany');
      const pf = document.getElementById('brandFor');
      if (co) co.value = (b.branding && b.branding.company) || '';
      if (pf) pf.value = (b.branding && b.branding.prepared_for) || '';
      const btn = document.getElementById('brandSaveBtn');
      const stEl = document.getElementById('brandStatus');
      if (btn) btn.addEventListener('click', async () => {
        const res = await fetch('/api/report/branding', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({company: co?.value || '', prepared_for: pf?.value || ''}),
        });
        if (stEl) stEl.textContent = res.ok ? 'Saved — applies to the next export.' : 'Save failed.';
      });
    } catch (_) { /* 라이선스 미보유 등 — 패널 숨김 유지 */ }
  })();

  // ── 일괄 보고 (MSP 전용) — 권한은 서버가 강제, 여기는 노출·편의만 ────
  (async () => {
    const locked = document.getElementById('batchLocked');
    const controls = document.getElementById('batchControls');
    if (!locked || !controls) return;
    let msp = false;
    try {
      const lic = await (await fetch('/api/license/status')).json();
      msp = !!lic.licensed && lic.tier === 'msp';
    } catch (_) {}
    (msp ? controls : locked).style.display = '';
    // showLicenseModal()을 그대로 쓴다 — 인라인으로 다시 구현하면 키 입력창
    // 포커스가 빠져 구매 흐름이 한 단계 늘어난다(리뷰 라운드 7).
    document.getElementById('batchSeeLicenseBtn')?.addEventListener('click',
      () => showLicenseModal());
    if (!msp) return;

    const input = document.getElementById('batchFiles');
    const pick = document.getElementById('batchPickBtn');
    const info = document.getElementById('batchPickInfo');
    const run = document.getElementById('batchRunBtn');
    const st = document.getElementById('batchStatus');
    pick?.addEventListener('click', () => input?.click());

    /* 서버의 짝짓기 규칙과 같은 계산 — 실행 전에 "몇 대가 인식됐는지"를
       보여줘야 파일명을 잘못 지은 걸 업로드 전에 알 수 있다. */
    const MAX_BATCH_DEVICES = 50;   // 서버 batch_report.MAX_CONFIGS와 같은 값
    function groupPreview(files) {
      const stems = new Set();
      let csv = 0, ranges = 0, other = 0;
      for (const f of files) {
        const n = f.name.toLowerCase();
        if (n.endsWith('.ranges.txt')) ranges += 1;
        else if (n.endsWith('.csv')) csv += 1;   // .proxy.csv 포함 — 개수 표시용
        else if (n.endsWith('.conf') || n.endsWith('.txt')) stems.add(n.replace(/\.(conf|txt)$/, ''));
        else other += 1;   // 규칙 밖 파일 — 화면에서 미리 알려준다
      }
      return { configs: stems.size, csv, ranges, other };
    }
    input?.addEventListener('change', () => {
      const files = [...(input.files || [])];
      const g = groupPreview(files);
      info.textContent = files.length
        ? `${g.configs} device config(s) · ${g.csv} usage CSV · ${g.ranges} ranges file(s)`
          + (g.other ? ` · ${g.other} file(s) will be skipped` : '')
        : 'No files selected';
      run.disabled = g.configs === 0 || g.configs > MAX_BATCH_DEVICES;
      st.textContent = !files.length ? ''
        : g.configs === 0 ? 'Include at least one .conf/.txt config file.'
        : g.configs > MAX_BATCH_DEVICES
          ? `Too many devices — the limit is ${MAX_BATCH_DEVICES} per batch.`
        : '';
    });

    run?.addEventListener('click', async () => {
      const files = [...(input.files || [])];
      if (!files.length) return;
      run.disabled = true;
      st.textContent = apoT('Analysing each device...');
      try {
        const fd = new FormData();
        files.forEach((f) => fd.append('files', f));
        const res = await fetch('/api/batch/export', { method: 'POST', body: fd });
        if (!res.ok) {
          throw new Error(await serverMsgFrom(res, 'Batch export failed.'));
        }
        saveResponseAs(await res.blob(), res, 'apo_batch_reports.zip');
        /* 실패가 있으면 'N/M'만 보고 넘어가기 쉽다 — 실패라는 말을 쓴다. */
        const rs = res.headers.get('X-Batch-Result') || '';
        const [okN, totalN] = rs.split('/').map(Number);
        const failed = (Number.isFinite(okN) && Number.isFinite(totalN)) ? totalN - okN : 0;
        st.textContent = `Done — ${rs} devices in the zip`
          + (failed > 0 ? `, ${failed} failed` : '')
          + '. SUMMARY.txt inside lists each device and anything skipped.';
      } catch (e) {
        st.textContent = e.message || 'Batch export failed.';
      } finally { run.disabled = false; }
    });
  })();

  // ── 정확도 검증 워크플로우 ─────────────────────────────────────────
  const vStatus = document.getElementById('verifyStatus');
  const vResult = document.getElementById('verifyResult');

  async function downloadSample(fmt) {
    if (vStatus) apoSetText(vStatus, 'Building the sample...');
    try {
      const res = await fetch('/api/verification/sample?format=' + fmt
        + (currentDeviceId ? '&device_id=' + encodeURIComponent(currentDeviceId) : ''),
        {method:'POST'});
      if (!res.ok) { await alertApiError(res, 'Failed to generate sample.'); if (vStatus) vStatus.textContent=''; return; }
      saveResponseAs(await res.blob(), res, 'apo_verification_sample.' + fmt);
      if (vStatus) apoSetText(vStatus, 'Sample downloaded. Run the listed commands on your firewall, fill in the last three columns, then upload the sheet back here.');
    } catch (err) { /* i18n-dynamic: 예외 메시지 */ if (vStatus) vStatus.textContent = err.message || apoT('Failed'); }
  }

  function renderPrecision(stats) {
    if (!vResult) return;
    const lv = stats.levels || {};
    const pct = v => v == null ? '-' : (v * 100).toFixed(1) + '%';
    let html = `<table class="result-table"><thead><tr>
      <th>Severity</th><th>Match</th><th>Mismatch</th><th>Hold</th><th>Unfilled</th><th>Precision</th>
    </tr></thead><tbody>` + Object.entries(lv).map(([k, d]) => `<tr>
      <td>${escapeHtml(String(k))}</td><td>${d.match}</td><td>${d.mismatch}</td>
      <td>${d.hold}</td><td>${d.unfilled}</td><td><strong>${pct(d.precision)}</strong></td>
    </tr>`).join('') + '</tbody></table>';
    const o = stats.overall || {};
    /* **어느 장비의 정확도인지 표에 적는다.** 캡처만 보면 알 수 없어, 다른
       고객 장비의 표본을 올려도 화면에는 아무 단서가 없었다(라운드 27).
       이제 세어진 행은 전부 이 장비의 정책이므로 이 이름은 사실이다 —
       표지 문자열이 아니라 채점된 행이 근거다(라운드 37). */
    if (stats.device) {
      html = `<p class="sev-guide-note"><strong>${escapeHtml(
        apoT('Accuracy for {device}', { device: stats.device }))}</strong></p>` + html;
    }
    /* 이 표본이 **이전 백업**에서 발급된 것이면 말한다 — 등급은 그때의
       설정으로 매겨진 값이다. 거절하지는 않는다(현장에서 사람이 채운 행을
       버리게 하면 안 된다, R29). */
    if (stats.issued_for) {
      html = `<p class="sev-guide-note">${escapeHtml(apoT(
        'This sample was issued for an earlier backup of this firewall '
        + '({issued}). The grades in it were assigned from that configuration.',
        { issued: stats.issued_for }))}</p>` + html;
    }
    /* **버린 행이 있으면 말한다.** 남의 행을 덧붙여도 분모에 못 들어가는 것이
       설계인데, 그 사실이 화면에 없으면 '14행을 올렸는데 왜 3행만 세었나'를
       알 수 없다(라운드 37). */
    /* **빈 줄을 '남의 행'이라 부르지 않는다.** 엑셀 저장이 표 아래에
       빈 줄을 붙이는 것은 예사인데, 그걸 "APO 가 발급하지 않은 행" 으로
       경고해 감사 산출물에 남의 행을 붙였다는 누명을 씌웠다(라운드 48). */
    if (stats.blank_rows) {
      html = `<p class="sev-guide-note">${escapeHtml(apoT(
        '{n} empty row(s) at the end of the sheet were skipped — this is a '
        + 'normal spreadsheet artifact and does not affect the numbers.',
        { n: stats.blank_rows }))}</p>` + html;
    }
    if (stats.ignored_rows) {
      html = `<p class="sev-guide-note is-warning">⚠ ${escapeHtml(apoT(
        '{ignored} row(s) were ignored — APO did not issue them for this '
        + 'device. {scored} row(s) were scored.',
        { ignored: stats.ignored_rows, scored: stats.scored_rows }))}</p>`
        + html;
    }
    if (stats.key_mismatch_rows) {
      html = `<p class="sev-guide-note is-warning">⚠ ${escapeHtml(apoT(
        'Of those, {n} row(s) came from this sample but their VDOM / policy '
        + 'type / policy ID columns no longer match what APO issued, so those '
        + 'verdicts could not be counted.',
        { n: stats.key_mismatch_rows }))}</p>` + html;
    }
    /* **'Overall' 이라고 부르면 안 된다.** 표본은 등급별로 고르게 뽑으므로,
       5등급 600건과 1등급 3건이 표본에는 비슷한 수로 들어간다. 그 둘을 합친
       비율은 이 장비의 정확도가 아니라 표본 안의 비율일 뿐인데, 'Overall
       precision' 이라 적혀 있어 그대로 인용됐다(라운드 47). 옆 문단들은 이미
       apoT 를 쓰는데 이 줄만 영어로 박혀 있던 것도 함께 고친다. */
    html += `<p class="sev-guide-note"><strong>${escapeHtml(apoT(
      'Sample precision: {pct}', { pct: pct(o.precision) }))}</strong> ${escapeHtml(apoT(
      '({match} match / {mismatch} mismatch across {judged} judged samples). '
      + 'Held and unfilled rows are excluded from the denominator.',
      { match: o.match, mismatch: o.mismatch, judged: o.judged }))}</p>`;
    html += `<p class="sev-guide-note">${escapeHtml(apoT(
      'The sample is stratified — it takes a similar number from each severity '
      + 'level no matter how many policies that level actually has. So this is '
      + 'not the accuracy across your whole device; read the per-level rows for '
      + 'that.'))}</p>`;
    /* **적었는데 못 읽은 칸을 조용히 버리지 않는다.** 집계는 이미 따로 세고
       있었는데 화면이 그 수를 말하지 않아, 14행을 채운 사람이 왜 11행만
       세어졌는지 알 수 없었다(라운드 47). */
    /* 헤드라인에서 뺀 '판정 못 함' 건수를 말한다 — 조용히 빼면 표의
       등급 0 줄과 헤드라인 분모가 안 맞는 이유를 알 수 없다. */
    if (stats.ungraded_judged) {
      html += `<p class="sev-guide-note">${escapeHtml(apoT(
        '{n} row(s) are severity 0 ("Cannot assess"), where the only honest '
        + 'answer is that APO could not judge. They are shown in the table but '
        + 'left out of the figure above, so they cannot inflate it.',
        { n: stats.ungraded_judged }))}</p>`;
    }
    if (stats.unreadable) {
      html += `<p class="sev-guide-note is-warning">⚠ ${escapeHtml(apoT(
        '{n} cell(s) had a verdict written that APO could not read, so those '
        + 'rows were left out. Please write 일치 / 불일치 / 보류 '
        + '(match / mismatch / hold).', { n: stats.unreadable }))}</p>`;
    }
    if ((stats.weak_levels || []).length) {
      html += `<p class="sev-guide-note">⚠ ${escapeHtml(apoT(
        'Levels {levels} have fewer than 5 judged samples — treat those numbers '
        + 'as indicative, not conclusive.',
        { levels: stats.weak_levels.join(', ') }))}</p>`;
    }
    vResult.innerHTML = html;
  }

  const vXlsx = document.getElementById('verifySampleXlsxBtn');
  const vCsv = document.getElementById('verifySampleCsvBtn');
  const vUpBtn = document.getElementById('verifyUploadBtn');
  const vUpFile = document.getElementById('verifyUploadFile');
  if (vXlsx) vXlsx.addEventListener('click', () => downloadSample('xlsx'));
  if (vCsv) vCsv.addEventListener('click', () => downloadSample('csv'));
  if (vUpBtn) vUpBtn.addEventListener('click', () => vUpFile?.click());
  if (vUpFile) vUpFile.addEventListener('change', async () => {
    const file = vUpFile.files?.[0];
    if (!file) return;
    if (vStatus) apoSetText(vStatus, 'Scoring...');
    /* **먼저 지운다.** 실패해도 직전 결과가 남아 있으면, 방금 올린 파일의
       점수처럼 보인다 — 감사자는 그 수치를 증적으로 캡처한다(라운드 27 실측:
       헤더행 없는 파일을 올렸는데 앞 장비의 84.6% 표가 그대로 남았다).
       장비를 바꿀 때 판정 표를 지우는 규칙이 이 패널만 예외였다. */
    if (vResult) vResult.innerHTML = '';
    const fd = new FormData();
    fd.append('worksheet', file);
    fd.append('device_id', currentDeviceId || '');
    /* **감사자가 증적으로 캡처하는 수치다.** 늦게 온 A 의 채점표가 B 화면에
       그려졌고, 표 안에 **A 장비 id 가 박혀** 있었다(6라운드 G2 실측).
       바로 위 주석이 "이 패널만 예외였다" 고 적어 둔 그 패널이다. */
    const fresh = apoStillThisDevice();
    try {
      const res = await fetch('/api/verification/score', {method:'POST', body: fd});
      const data = await res.json();
      if (!fresh()) return;
      /* **거절 안내야말로 번역돼야 한다** — 한국어 화면에서 실수했을 때
         보는 문장이 이것뿐인데 영어로 남아 있었다(라운드 38 지적). 서버는
         번역 키와 장비 이름만 보내고, 문장은 여기서 만든다. */
      if (!res.ok) throw new Error(serverMsg(data, 'Scoring failed'));
      renderPrecision(data);
      if (vStatus) apoSetText(vStatus, 'Scored.');
    } catch (err) { /* i18n-dynamic: 예외 메시지 */ if (vStatus) vStatus.textContent = err.message || apoT('Failed'); }
    vUpFile.value = '';
  });

  /* ── 객체 명명 규칙 ────────────────────────────────────────────────
     APO 는 고객 환경의 특별한 객체를 **이름으로** 알아보고 판정을 조정한다.
     그 목록이 코드와 납품 프로파일에만 있던 동안 새 고객은 자기 환경을 말할
     방법이 없었고, 두 가지가 조용히 일어났다 — 아무 값도 일치하지 않아 예외가
     통째로 안 걸리거나, 두 글자 값이 단어 속에 우연히 걸렸다(실 설정 17건).

     매칭 규칙은 그대로 둔다(실 설정에서 '정확히 일치'하는 객체가 0개였으므로
     엄격하게 바꾸면 걸려 있던 예외가 통째로 사라진다). 대신 **무엇이 걸리는지
     보여준다.** 보이지 않는 규칙은 검증할 수 없다. */
  /* **라벨은 "무엇을 넣는가", 설명은 "그러면 어떻게 판정되는가".**
     전에는 라벨이 효과를 말해서(예: "관리·운영자 정책") 무엇을 타이핑할지
     알 수 없었다 — 정책을 넣으라는 건지 객체 이름을 넣으라는 건지조차
     모호했다(실사용 지적). 실제로 넣는 것은 **주소 객체 이름에 들어가는
     글자**다.

     order 는 **severity_engine 이 실제로 검사하는 순서**다. 먼저 걸리면
     거기서 끝나므로(high_risk → admin → user_segment → infra), 같은 이름을
     두 곳에 넣으면 위쪽이 이긴다. 화면이 그 순서대로 보여주지 않으면
     사용자는 이 사실을 알 수 없다. */
  const OBJ_RULE_LABELS = {
    high_risk: {
      order: 1,
      label: 'Zones that must never be exposed',
      effect: 'Always Critical',
      example: 'e.g. DMZ, EXTERNAL, GUEST',
    },
    admin: {
      order: 2,
      label: 'Admin, jump and backup servers',
      effect: 'Kept — not proposed for removal',
      example: 'e.g. ADMIN, JUMP, BASTION, BACKUP',
    },
    user_segment: {
      order: 3,
      label: 'User PCs and VDI pools',
      effect: 'Judged as user-to-server traffic',
      example: 'e.g. VDI, DESKTOP, OFFICE',
    },
    /* 예전에는 여기에 'mgmt'(관리망) 칸이 따로 있었다. 등급이 infra 와 똑같아
       (둘 다 done(6)) 어느 칸에 넣든 결과가 같았는데 화면은 둘로 물어봐서,
       사용자가 "어디 넣지?"를 고민해야 했다 — 한 칸으로 합쳤다. 기존 설정의
       mgmt 값은 서버가 infra 로 병합해 그대로 쓴다. */
    infra: {
      order: 4,
      label: 'Shared infrastructure and management network',
      effect: 'Lowered to review',
      example: 'e.g. DNS, NTP, ZABBIX, MGMT',
    },
  };

  function objRuleOrder(kinds) {
    return [...(kinds || [])].sort(
      (a, b) => (OBJ_RULE_LABELS[a]?.order || 99) - (OBJ_RULE_LABELS[b]?.order || 99));
  }
  let _objRules = { kinds: [], rules: {}, profile: {}, preview: {} };

  function renderObjRules() {
    const box = document.getElementById('objRulesRows');
    if (!box) return;
    box.innerHTML = objRuleOrder(_objRules.kinds).map((kind, idx) => {
      const meta = OBJ_RULE_LABELS[kind] || {};
      const label = meta.label || kind;
      const why = meta.effect || '';
      const mine = (_objRules.rules || {})[kind] || [];
      const prof = (_objRules.profile || {})[kind] || [];
      const pv = ((_objRules.preview || {})[kind]) || [];
      /* 입력하지 않은 항목은 프로파일 값이 쓰인다 — 어느 쪽이 적용 중인지
         말해야 한다. '아직 비어 있다'와 '내가 넣었다'는 다른 상태다. */
      /* **어디서 온 값인지 정확히 말한다.** 구형 납품 파일
         (customer_rules.json)이 병합된 배포에서도 화면은 "profile default"
         라고만 해서, 그 고객 전용 객체명(관리자·DMZ 그룹명 등)이 중립
         기본값처럼 보였다 — 다른 현장에서 흔한 이름이 조용히 판정을
         바꾼다(라운드 45 지적). */
      const src = mine.length
        ? apoT('using your entries')
        : (prof.length
            ? (_objRules.legacy_file
                ? apoT('from {file} (delivered with this installation): {vals}',
                       { file: _objRules.legacy_file, vals: prof.join(', ') })
                : apoT('using the profile default: {vals}', { vals: prof.join(', ') }))
            : apoT('not set — this check is skipped'));
      const hits = pv.map((it) => {
        const parts = [apoT('{n} object(s)', { n: it.total })];
        if (it.inside_word) {
          parts.push('⚠ ' + apoT('{n} inside a longer word', { n: it.inside_word }));
        }
        /* **무시한 것을 숨기면 "왜 안 걸리지?" 가 된다.** 짧은 값은 단어 속에
           걸려도 판정에 안 쓰인다(F1 이 RF19 에 걸리던 것) — 그 사실과 어떤
           이름이 그랬는지 함께 보여 준다. */
        if (it.ignored_inside_word) {
          parts.push(apoT('{n} ignored (inside a longer word): {list}', {
            n: it.ignored_inside_word,
            list: (it.ignored_examples || []).join(', '),
          }));
        }
        /* 단어 속에 걸린 것이 **있었다면** — 지금 걸리든(긴 패턴)
           무시되든(짧은 패턴) — 사용자가 봐야 할 상황이다. 짧은 값이
           의도와 다르게 동작한다는 신호이므로 경고색을 유지한다. */
        const cls = (it.inside_word || it.ignored_inside_word)
          ? 'is-warning' : '';
        const ex = (it.examples || []).map(escapeHtml).join(', ');
        return `<div class="obj-rule-hit ${cls}"><code>${escapeHtml(it.pattern)}</code>
                  <span>${escapeHtml(parts.join(' · '))}</span>
                  ${ex ? `<span class="obj-rule-ex">${ex}</span>` : ''}</div>`;
      }).join('');
      /* 번호와 예시를 함께 보여준다. 번호는 검사 순서이고(위가 이긴다),
         예시가 없으면 사용자는 'ADMIN' 인지 'admin_srv_01' 인지 '10.1.1.0/24'
         인지 알 수 없다 — 실제로 넣는 것은 **이름에 들어가는 글자**다. */
      return `<label class="inline-status obj-rule-row">
          <span class="obj-rule-label">${idx + 1}. ${escapeHtml(apoT(label))}</span>
          <span class="obj-rule-why">→ ${escapeHtml(apoT(why))}</span>
          <input type="text" class="sev-user-range-input obj-rule-input"
                 data-kind="${escapeHtml(kind)}" value="${escapeHtml(mine.join(', '))}"
                 placeholder="${escapeHtml(apoT(meta.example || 'comma separated'))}" />
          <span class="obj-rule-src">${escapeHtml(src)}</span>
          ${hits}
        </label>`;
    }).join('');
  }

  window.__apoLoadObjRules = () => { loadObjRules(); };
  onLangChange(renderObjRules);

  /* **저장이 읽기를 이겨야 한다.** 장비는 그대로인데 사용자가 방금 저장한
     경우, 저장 **전에** 나간 GET 이 늦게 도착해 칸을 옛 값으로 덮었다 —
     화면은 빈 칸인데 상태줄은 "저장했습니다" 였다(6라운드 F2 실측).
     사용자가 이상해서 Save 를 다시 누르면 그 패널은 **네 칸을 함께** 보내므로
     서버의 `high_risk` 가 지워지고, 그건 "Always Critical" 이라 등급이 움직인다.

     입력 축(`apoStillThisInput`)으로 바꾸면 F1 이 재발한다 —
     `adoptDeviceSession` 이 이 요청을 쏜 뒤 리셋이 입력 세대를 올리기 때문이다.
     그래서 **저장만 올리는 전용 카운터**를 쓴다. */
  let _objRulesEpoch = 0;

  async function loadObjRules() {
    if (!currentDeviceId) {
      /* **지우지 않고 돌아가면 지워진 고객의 자산명이 칸에 남는다.**
         삭제 경로가 `adoptDeviceSession({}, '')` 로 이 함수를 부르는데 여기서
         빠져나갔다. 그 상태로 Save 를 누르면(버튼은 활성이다) 서버가 열린
         장비가 없다고 보고 **프로세스 전역**을 그 값으로 덮는다 — 그리고
         룰 세트 내보내기가 장비 없이도 눌려 그 자산명이 JSON·해시에 실린다
         (7라운드 F3 실측). */
      _objRules = {};
      renderObjRules();
      return;
    }
    const epoch = _objRulesEpoch;
    /* **판정 입력이라 누수가 등급을 움직인다.** `adoptDeviceSession` 이 전환
       때마다 직접 부르므로 사용자가 아무것도 더 누르지 않아도 경쟁이 난다.
       늦게 온 A 의 규칙이 B 화면 칸에 채워지고, 그 패널의 Save 는 네 칸을
       **함께** 보내므로 사용자가 다른 칸을 고치다 누르면 B 에 저장된다.
       `high_risk` 는 "Always Critical" 이라 실측에서 Critical 4→7 이었다. */
    const fresh = apoStillThisDevice();
    try {
      const res = await fetch('/api/object-rules?device_id='
                              + encodeURIComponent(currentDeviceId));
      if (!fresh()) return;
      if (!res.ok) return;
      const loaded = await res.json();
      if (!fresh()) return;          // 늦게 왔다 — 남의 고객 자산명이다
      if (epoch !== _objRulesEpoch) return;   // 그 사이 저장이 있었다
      _objRules = loaded;
      renderObjRules();
    } catch (err) { /* 설정 화면 한 칸이 비는 것뿐이다 */ }
  }

  document.getElementById('objRulesSaveBtn')?.addEventListener('click', async () => {
    const st = document.getElementById('objRulesStatus');
    const rules = {};
    document.querySelectorAll('.obj-rule-input').forEach((el) => {
      rules[el.dataset.kind] = el.value.split(',').map((v) => v.trim()).filter(Boolean);
    });
    // 이 저장이 비행 중이던 읽기를 이긴다(위 `_objRulesEpoch` 주석 참조).
    _objRulesEpoch += 1;
    /* **저장 응답에도 가드가 필요하다.** 읽기만 막고 쓰기 응답을 안 막았더니,
       늦게 온 A 의 저장 응답이 B 화면 칸을 A 고객 자산명으로 채우고 판정
       상태줄까지 "객체 이름이 바뀌었습니다" 로 바꿨다 — B 는 아무것도 안
       바꿨는데. 거기서 Save 를 누르면 A 자산명이 B 에 저장된다(6라운드 G1). */
    const fresh = apoStillThisDevice();
    try {
      const res = await fetch('/api/object-rules/set', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules, device_id: currentDeviceId || undefined }),
      });
      if (!res.ok) { if (st) st.textContent = await serverMsgFrom(res, apoT('Save failed')); return; }
      const d = await res.json();
      if (!fresh()) return;
      _objRules = { ..._objRules, rules: d.rules, preview: d.preview };
      renderObjRules();
      /* **판정에 쓰이는 값이 바뀌었다.** 화면에 남은 판정 결과는 옛 규칙으로
         만든 것이다 — 그렇다고 말하지 않으면 사용자는 새 규칙의 결과로 읽는다. */
      if (st) st.textContent = apoT('Saved. Run the assessment again to apply this.');
      window.__apoResetSev?.(apoT('Object names changed — run the assessment again.'));
      /* 룰 세트 해시도 이 값으로 만들어진다 — 갱신하지 않으면 카드가 옛 해시를
         보여주는데, 그 카드 본문은 '같은 해시가 리포트 Summary 에 인쇄된다' 고
         말한다(화면과 산출물이 갈린다). */
      window.__apoRefreshRulesetHash?.();
    } catch (err) { if (st) st.textContent = err.message || apoT('Save failed'); }
  });

  /* ── 티켓 번호 형식 ──────────────────────────────────────────────────
     이 값이 `profiles/<name>.yaml` 에만 있던 동안, 파일을 exe 옆에 놓아 주지
     않은 배포에서는 이름에 티켓 번호가 박혀 있어도 **전량 '티켓 없음'** 으로
     판정됐다. 이제 화면에서 받고, **무엇이 걸리는지 저장 전에 보여준다**
     (객체 이름 패널이 이미 쓰는 방식과 같다). */
  const SAMPLE_NAME_SEP = '  ·  ';   // 정책 이름 예시를 잇는 가운뎃점

  function ticketPayload() {
    return {
      prefixes: document.getElementById('ticketPrefixes')?.value || '',
      // 정규식 칸은 없앴다 — 보내지 않는다(서버도 400 으로 거절한다).
      scan_comment: !!document.getElementById('ticketScanComment')?.checked,
      /* **열린 장비를 함께 보낸다.** 이 라우트는 게이트 면제가 아니라서,
         장비를 연 뒤에는 device_id 없는 요청이 409 가 된다 — 저장도 미리보기도
         못 하고 화면은 "이 요청이 어느 장비의 것인지 말하지 않았다" 를 찍는다.
         그런데 같은 카드의 안내문은 "설정을 올려야 몇 건이 잡히는지 보인다" 며
         **업로드를 먼저 하라고 시킨다** — 그 순서를 따르면 카드를 못 쓴다.
         형제 카드(객체 이름)는 처음부터 device_id 를 보내 200 이었다.
         v126 부터 있던 결함이다(2026-09-09 재비판 라운드 6 실측). */
      device_id: currentDeviceId || undefined,
    };
  }

  function renderTicketPreview(d) {
    const el = document.getElementById('ticketPreview');
    if (!el) return;
    /* **가장 크게 잃는 고객에게 가장 적게 말하고 있었다.**
       옛 버전에서 정규식만 저장한 배포는 폴백이 없어 `effective_pattern` 이
       빈 문자열이 된다 — 그러면 아래 첫 조기 return 이 "티켓 형식이 설정되지
       않았습니다" 를 찍는다. **설정한 적이 없다고 말하는 것이다.** 그 순간
       인식률은 100% → 0% 인데. 안내를 맨 끝에 붙여 둔 탓에 조기 return 세 개
       뒤에 있었다(6라운드 B1 실측). 문구·번역은 맞았고 붙인 자리가 틀렸다.
       릴리스 노트가 "설정 화면이 알려 줍니다" 라고 출하 약속까지 했다. */
    const legacyRegexDropped =
      String(d && d.origin || '').endsWith('regex-disabled');
    const dropNote = legacyRegexDropped
      ? ' ' + apoT('A pattern you saved in an older version is no longer used — enter the prefix your tickets start with instead.')
      : '';
    if (!d || !d.effective_pattern) {
      el.textContent = (legacyRegexDropped
        ? apoT('The ticket format you saved in an older version is no longer used, and nothing has replaced it — no policy is being checked for a ticket number.')
        : apoT('No ticket format set — policies are not checked for a ticket number.'))
        + (legacyRegexDropped
           ? ' ' + apoT('Enter the prefix your tickets start with (for example RITM).') : '');
      return;
    }
    const p = d.preview || {};
    if (!p.loaded) {
      el.textContent =
        apoT('Upload a configuration to see how many policies this recognises.')
        + dropNote;
      return;
    }
    /* **0건은 막다른 길이면 안 된다.** 개수만 알려주면 사용자는 다음에 무엇을
       해야 할지 모른다 — 실제 정책 이름을 보여주며 어느 부분이 티켓 번호인지
       스스로 판단하게 한다(실사용 지적). */
    if (p.matched === 0 && (p.sample_names || []).length) {
      /* 구분자를 호출부에 직접 쓰지 않는다 — apoSetText 안의 문자열 리터럴은
         사전 검사 대상이라, 장식용 기호까지 번역 항목으로 잡힌다. */
      const names = p.sample_names.join(SAMPLE_NAME_SEP);
      el.textContent = apoT('Nothing matched. Your policy names look like this — which part is the ticket number? {names}',
                            { names }) + dropNote;
      return;
    }
    const ex = (p.examples || [])[0];
    /* 개수만 말하면 "맞게 잡은 것인지"를 알 수 없다 — 실제로 걸린 값을
       하나 보여줘야 사용자가 자기 명명 규칙과 대조할 수 있다. */
    let msg = apoT('{m} of {n} policies recognised.', { m: p.matched, n: p.total });
    if (ex) {
      msg += ' ' + apoT('For example {ticket} on policy {id}.',
                        { ticket: ex.ticket, id: ex.policy_id });
    }
    if (d.origin === 'profile') {
      /* 사용자가 아무것도 안 넣었는데 값이 일하고 있으면 그 사실을 말한다. */
      msg += ' ' + apoT('This comes from the profile file, not from this screen.');
    }
    msg += dropNote;
    apoSetText(el, msg);
  }

  let _ticketTimer = null;
  async function ticketPreviewSoon() {
    clearTimeout(_ticketTimer);
    _ticketTimer = setTimeout(async () => {
      const st = document.getElementById('ticketStatus');
      /* 읽기(GET)만 막고 이 둘은 안 막았다 — **같은 요소에 같은
         `renderTicketPreview(d)` 를 쓴다.** 인식 0건 경로가 앞 고객의
         실제 정책 이름 목록(`sample_names`)을 찍는 것도 그대로였다
         (5라운드 F-C). 장비 정체성 축이면 충분하다 — 입력이 바뀌어
         다시 미리보기가 도는 것은 정상이다. */
      const fresh = apoStillThisDevice();
      try {
        const res = await fetch('/api/settings/ticket', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...ticketPayload(), preview_only: true }),
        });
        const d = await res.json();
        if (!fresh()) return;
        if (!res.ok) {
          /* 거부 사유를 그대로 보여준다 — 무엇을 고쳐야 하는지가 사유에 있다. */
          if (st) st.textContent = apoT(d.error || 'Save failed');
          return;
        }
        if (st) st.textContent = '';
        renderTicketPreview(d);
      } catch (err) { /* 미리보기는 보조다 — 저장은 여전히 된다 */ }
    }, 300);
  }

  ['ticketPrefixes'].forEach((id) => {
    document.getElementById(id)?.addEventListener('input', ticketPreviewSoon);
  });
  document.getElementById('ticketScanComment')?.addEventListener('change', ticketPreviewSoon);

  document.getElementById('ticketSaveBtn')?.addEventListener('click', async () => {
    const st = document.getElementById('ticketStatus');
    const fresh = apoStillThisDevice();
    try {
      const res = await fetch('/api/settings/ticket', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ticketPayload()),
      });
      if (!res.ok) {
        /* **실패를 미리보기 자리에도 적는다.** 전에는 버튼 옆 작은 글씨만
           바뀌고 큰 미리보기는 "티켓 형식이 설정되지 않았습니다" 그대로
           남았다 — 저장을 눌렀는데 아무것도 안 변한 것처럼 보여, 사용자는
           성공했는지 실패했는지 알 수 없었다(실사용 보고). */
        const msg = await serverMsgFrom(res, apoT('Save failed'));
        if (st) st.textContent = msg;
        const el = document.getElementById('ticketPreview');
        if (el) apoSetText(el, msg);
        return;
      }
      const d = await res.json();
      if (!fresh()) return;          // 장비가 바뀌었다 — 남의 화면이다
      renderTicketPreview(d);
      /* **판정에 쓰이는 값이 바뀌었다.** 화면에 남은 판정 결과는 옛 형식으로
         만든 것이다 — 객체 이름과 같은 규칙. */
      if (st) st.textContent = apoT('Saved. Run the assessment again to apply this.');
      window.__apoResetSev?.(apoT('Ticket format changed — run the assessment again.'));
      /* 룰 세트 해시도 이 값으로 만들어진다 — 갱신하지 않으면 카드가 옛 해시를
         보여주는데, 그 카드 본문은 '같은 해시가 리포트 Summary 에 인쇄된다' 고
         말한다(화면과 산출물이 갈린다). */
      window.__apoRefreshRulesetHash?.();
    } catch (err) { if (st) st.textContent = err.message || apoT('Save failed'); }
  });

  async function loadTicketSettings() {
    /* 인식 0건 경로는 `sample_names` — **앞 고객의 실제 정책 이름 목록** —
       을 그대로 찍는다. 늦게 오면 그게 다음 고객 화면에 인쇄된다. */
    const fresh = apoStillThisDevice();
    try {
      // 읽기도 같은 게이트를 탄다 — 장비를 연 뒤에는 대상을 대야 한다.
      const res = await fetch('/api/settings/ticket'
        + (currentDeviceId ? `?device_id=${encodeURIComponent(currentDeviceId)}` : ''));
      if (!res.ok) return;
      const d = await res.json();
      if (!fresh()) return;
      const pre = document.getElementById('ticketPrefixes');
      if (pre) pre.value = (d.prefixes || []).join(', ');
      const cb = document.getElementById('ticketScanComment');
      if (cb) cb.checked = !!d.scan_comment;
      renderTicketPreview(d);
    } catch (err) { /* 설정 화면 한 칸이 비는 것뿐이다 */ }
  }

  window.__apoLoadTicketSettings = () => { loadTicketSettings(); };
  /* 장비를 열기 전에도 설정 화면은 볼 수 있다 — 그때도 저장된 값이 보여야
     한다(미리보기만 "설정을 올리세요"로 남는다). */
  loadTicketSettings();

  /* ── 룰 세트(판정 입력 묶음) ───────────────────────────────────────────
     임계값·객체 이름·티켓 형식을 한 파일로 묶는다. 이식(다른 장비·PC)과 증적
     (SHA-256)이 목적이고 **판정은 바꾸지 않는다**. 내보내기·가져오기 **둘 다**
     장비 범위 입력(객체 규칙 = 고객 자산명)을 다루므로 열린 장비를 함께
     보낸다(서버 게이트). 내보내기가 면제이던 동안, 다른 탭이 장비를 바꾸면
     A 를 지목해도 B 고객의 자산명이 200 으로 나갔다(2026-09-09 실측). */
  const rulesetQuery = () => (currentDeviceId
    ? `?device_id=${encodeURIComponent(currentDeviceId)}` : '');

  /* 화면에는 짧은 해시만 보이지만, 복사 버튼은 전체 64자를 줘야 한다 —
     리포트 Summary 시트에 인쇄되는 값과 글자 그대로 대조해야 하기 때문이다.
     전체 값을 여기 보관하고, 표시는 앞 12자+… 로 줄인다. */
  let _rulesetHashFull = '';
  async function refreshRulesetHash() {
    const el = document.getElementById('rulesetHash');
    if (!el) return;
    /* **먼저 전체 해시 버퍼·표시·복사 버튼을 비운다.** 이 함수는 장비를 바꿀
       때 다시 불리는데, 게이트 때문에 첫 호출이 409 로 빠지거나(아래 주석)
       응답이 늦게 오면(fresh 실패) 성공 경로에 못 닿는다. 그때 앞 장비의 값이
       남아 있으면 복사 버튼이 감사자에게 **다른 장비의 64자 해시**를 건네고,
       그건 리포트 Summary 대조를 어긋나게 한다 — 표시 텍스트에서 이미
       지적됐던 '실패 시 지우는 코드가 없다'(아래)를 복사 버튼이 두 번째
       표면에서 다시 여는 셈이다. 성공하면 바로 다시 채운다. */
    _rulesetHashFull = '';
    apoSetText(el, 'Current rule set: {hash}', { hash: '' });
    { const b0 = document.getElementById('rulesetHashCopyBtn'); if (b0) b0.hidden = true; }
    /* 이 해시는 리포트 Summary 에 그대로 인쇄된다 — 감사자가 B 의 증적으로
       A 의 해시를 대조하게 된다. */
    /* **장비 축이다.** 한때 입력 축(`apoStillThisInput`)을 썼는데,
       `adoptDeviceSession` 이 이 요청을 쏜 **직후** 같은 전환 흐름의
       `resetSeverityResults` 가 입력 세대를 올려 **자기 응답이 100%
       버려졌다** — 경합이 아니라 결정론이다. 그러면 앞 장비 값이 화면에
       그대로 남는다(실패 시 지우는 코드가 없다). 리포트 Summary 에
       인쇄되는 해시를 화면이 거짓으로 말하게 된다(6라운드 F1 실측).
       이 값들은 장비 정체성에만 의존하고, 입력이 바뀌면 리셋 **뒤에**
       다시 불린다 — 그쪽이 정상 경로다. */
    const fresh = apoStillThisDevice();
    try {
      const res = await fetch('/api/ruleset/export' + rulesetQuery());
      if (!fresh()) return;
      if (!res.ok) return;
      const d = await res.json();
      if (!fresh()) return;
      const full = d.hash || '';
      _rulesetHashFull = full;
      // git short 방식: 앞 12자 + '…'. 전체는 복사 버튼으로만.
      const shown = full ? full.slice(0, 12) + '…' : '';
      apoSetText(el, 'Current rule set: {hash}', { hash: shown });
      const copyBtn = document.getElementById('rulesetHashCopyBtn');
      if (copyBtn) copyBtn.hidden = !full;
    } catch (err) { /* 해시 한 줄이 비는 것뿐이다 */ }
  }

  /* 전체 해시는 화면에 없으니(짧게 줄였다) 복사로만 얻는다 — 보관해 둔
     64자 원본을 클립보드에 넣는다. 화면 표시값(12자)이 아니라 원본이다. */
  document.getElementById('rulesetHashCopyBtn')?.addEventListener('click', async (e) => {
    if (!_rulesetHashFull) return;
    const btn = e.currentTarget;
    try {
      await navigator.clipboard.writeText(_rulesetHashFull);
      btn.textContent = apoT('Copied');
    } catch (err) { /* 클립보드가 막힌 환경 — 조용히 둔다 */ }
    setTimeout(() => {
      const b = document.getElementById('rulesetHashCopyBtn');
      if (b) b.textContent = apoT('Copy full hash');
    }, 1500);
  });
  /* 장비를 바꾸면 adoptDeviceSession 이 이걸 다시 부른다(객체 규칙이
     장비별이라 해시가 바뀌고, 게이트 때문에 첫 호출은 409 다). */
  window.__apoRefreshRulesetHash = () => { refreshRulesetHash(); };

  document.getElementById('rulesetExportBtn')?.addEventListener('click', async () => {
    const st = document.getElementById('rulesetStatus');
    try {
      const res = await fetch('/api/ruleset/export' + rulesetQuery());
      if (!res.ok) { if (st) st.textContent = await serverMsgFrom(res, apoT('Export failed')); return; }
      const d = await res.json();
      const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      // 화면에서 만든 파일이라 서버가 이름을 정하지 않는다 — deviceStamp() 로
      // 장비를 박아 hostname 이 같은 두 고객의 룰 세트가 겹치지 않게 한다
      // (마이그레이션 save() 와 같은 규칙).
      a.href = url; a.download = 'apo-ruleset' + deviceStamp() + '.json';
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      if (st) st.textContent = apoT('Exported.');
    } catch (err) { if (st) st.textContent = err.message || apoT('Export failed'); }
  });

  /* 룰 세트 **가져오기는 v127 에서 출하하지 않는다** — 서버 라우트도 등록되지
     않고 템플릿에도 컨트롤이 없다(재비판 4·5 라운드가 이 경로에서만 블로커
     7건을 냈다). 내보내기와 Summary 해시만 낸다. v128 에서 이식 의미론을
     정리한 뒤 되살린다. */

  refreshRulesetHash();

  /* 판정 완료 줄 — 세 문장이 조건부로 이어붙는다. 이어붙인 결과를 그냥 써
     넣으면 언어를 바꿔도 그대로 남으므로, **재료를 들고 있다가 다시 만든다**
     (한 줄짜리는 apoSetText 가 같은 일을 원소 안에서 해 준다). */
  let _lastClassifyStatus = null;
  function showClassifyStatus(info) {
    if (info) _lastClassifyStatus = info;
    const d = _lastClassifyStatus;
    if (!statusEl || !d) return;
    statusEl.textContent =
      apoT('Classification complete — {n} policies processed.', { n: d.total })
      + (d.rejectedRanges.length
         ? ' ' + apoT('Not recognised as IP ranges, so they were ignored: {list}',
                      { list: d.rejectedRanges.join(', ') })
           + (d.rejectedMore > 0
              ? ' ' + apoT('(+{n} more)', { n: d.rejectedMore }) : '')
         : '');
  }
  onLangChange(() => showClassifyStatus(null));
  /* 대역 변경처럼 **같은 요소에 다른 문장을 쓰는** 곳이 이 재료를 비울 수
     있어야 한다 — 안 그러면 언어 전환이 그 문장을 옛 판정 문구로 덮는다. */
  window.__apoForgetClassifyStatus = () => { _lastClassifyStatus = null; };

  /* **판정이 오래 걸리는 동안 화면이 죽은 것처럼 보이면 안 된다.**
     정적 문구 하나만 띄우다 보니 정책 5,000건(도달불가 검사가 정책 쌍 비교라
     20초 이상)에서 사용자가 멈춘 줄 알았다 — 데모에서 가장 위험한 구간이다
     (리허설 A-1). 경과 시간을 세어 살아 있음을 보이고, 오래 걸리는 이유를
     정직하게 말한다. */
  /* **응답은 자기 화면에만 쓴다.** 판정은 오래 걸리는데(5,000 정책 20초+)
     그 사이 사용자는 버튼을 또 누르고, 뷰를 옮기고, 다른 설정을 올린다.
     세대 번호가 없으면:
       - 먼저 시작한 판정이 나중에 끝나며 **아직 도는 판정의 타이머를 끄고**
         "판정을 마쳤습니다" 를 쓴다 — 실제로는 6초 더 돌고 있었다.
       - A 장비에서 띄운 판정이 B 로 넘어간 뒤 도착해 **A 의 정책표를 B 화면에**
         그린다. 서버 게이트는 요청 시점의 장비를 보므로 이건 못 막는다.
     시작할 때 번호를 올리고, 화면에 쓰기 전에 "아직 내가 최신인가" 를 묻는다.
     초기화(`resetSeverityResults`)도 번호를 올려 도중 응답을 버린다. */
  let _classifyGen = 0;
  let _classifyTimer = null;
  function _startClassifyProgress() {
    if (!statusEl) return;
    /* **재진입하면 이전 타이머가 남는다.** 끄지 않고 덮어쓰면 옛 타이머가
       계속 살아 완료 문구를 1초 뒤 지우고 "판정하는 중"으로 되돌린다 —
       하필 이 기능이 겨냥한 시나리오(5,000 정책 20초+)가 재진입 창이 가장
       넓다. 멈춘 줄 아는 것을 고치려다 영영 안 끝난 것처럼 보이게 만들었다
       (v129 재비판 발견 2). */
    _stopClassifyProgress();
    const t0 = Date.now();
    const tick = () => {
      const s = Math.round((Date.now() - t0) / 1000);
      let msg = apoT('Classifying... {s}s elapsed', { s: String(s) });
      if (s >= 5) {
        msg += '  ' + apoT('Large configurations take longer — the shadowed-policy check compares policy pairs.');
      }
      apoSetText(statusEl, msg);
    };
    tick();
    _classifyTimer = setInterval(tick, 1000);
  }
  function _stopClassifyProgress() {
    if (_classifyTimer) { clearInterval(_classifyTimer); _classifyTimer = null; }
  }

  async function runClassify() {
    const _gen = ++_classifyGen;
    const _devGen = window.__apoDeviceGen || 0;
    _startClassifyProgress();
    try {
      const rangeRes = await fetch('/api/user-ranges/set',{
        method:'POST', headers:{'Content-Type':'application/json'},
        // 어느 장비의 대역인지 함께 보낸다 — 화면과 서버가 서로 다른 장비를
        // 보고 있으면 서버가 거부한다(CSV와 같은 게이트).
        body:JSON.stringify({ranges:userRanges.map(r=>r.cidr),
                             device_id: currentDeviceId || undefined}),
      });
      // 범위 설정이 실패했는데 분류를 계속하면 traffic type이 전부 Unknown이
      // 되어 조용히 틀린 결과가 나온다(감사 C3). 여기서 멈춘다.
      if (!rangeRes.ok) {
        // 서버가 '지금 열려 있는 장비가 다르다'고 답하면 그 사실을 그대로
        // 전한다. '저장 실패'로 뭉뚱그리면 사용자는 무엇을 해야 할지 모른다.
        throw new Error(await serverMsgFrom(
          rangeRes, 'Failed to set User IP ranges — classification aborted.'));
      }
      /* 서버가 못 읽은 대역은 판정에 안 쓰인다 — 조용히 넘어가면 사용자는
         "대역을 넣었는데 왜 Unknown이지"를 영영 모른다(라운드 12). */
      const rangeInfo = await rangeRes.json().catch(() => ({}));
      /* 서버가 인정한 목록으로 칩을 되맞춘다 — 중복을 넣었을 때 화면은 6개인데
         서버는 5개로 합쳐 두는 어긋남이 남는다(라운드 16 실측). */
      if (Array.isArray(rangeInfo.user_ranges)
          && !adoptServerRanges(rangeInfo, _devGen)) return;
      const rejectedRanges = rangeInfo.rejected || [];
      const rejectedMore = (rangeInfo.rejected_total || rejectedRanges.length)
        - rejectedRanges.length;
      // 패널 기본값을 아직 못 읽었으면 임계값을 보내지 않는다 —
      // 비어 있는 값이 프로파일 설정을 null로 덮어쓰는 것을 막는다.
      const res = await fetch('/api/severity/classify',{
        method:'POST', headers:{'Content-Type':'application/json'},
        // 판정도 어느 장비의 것인지 대고 받는다 — 탭을 두 개 띄웠을 때
        // 남의 고객 판정이 이 화면에 뜨는 것을 서버가 막는다.
        body: JSON.stringify({
          ...(thLoaded ? {thresholds: collectThresholds()} : {}),
          device_id: currentDeviceId || undefined,
        }),
      });
      const data = await res.json();
      /* **오류 문구도 번역해서 받는다.** 같은 함수의 대역 저장 경로는
         `serverMsgFrom` 을 쓰는데 판정 경로만 raw `data.error` 를 던져,
         장비 게이트 409("다른 장비가 열려 있을 때 넣은 요청입니다") 가
         한국어 화면에 영어로 떴다 — 사전에는 번역이 있었다. 기본 언어를
         ko 로 바꾼 이번 릴리스에서 데모 중 마주칠 자리다. */
      if (!res.ok) throw new Error(serverMsg(data, 'Classification failed'));
      // 내가 최신이 아니면 이 결과는 남의 화면에 그릴 것이다 — 버린다.
      if (_gen !== _classifyGen) return;
      sevData=data;
      /* 걸어 둔 등급이 이번 결과에 없으면 필터를 푼다. 그대로 두면 칩이 사라져
         해제할 수단이 없는 채 "No policies match"만 남는다 — CSV를 넣어 판정이
         좋아졌을 때 "아무것도 못 찾았다"로 읽힌다. */
      if (activeSevFilter != null) {
        const levels = new Set([...(data.firewall||[]), ...(data.proxy||[])]
          .map(p => p.urgency ?? 0));
        if (!levels.has(activeSevFilter)) activeSevFilter = null;
      }
      window.__sevHasData = true;   // CSV 임포트 후 자동 재분류 트리거용(스코프 밖 접근)
      /* **무엇을 근거로 판정했는가.** 조치 계획은 열 때마다 서버가 다시
         계산하는데, 그 사이 사용량 CSV 나 임계값이 바뀌면 같은 정책이 두
         화면에서 다른 등급으로 보인다(2026-08-25 Jayden — 정책 498 이
         조치 계획 High / export Low). 조치 계획이 이 값과 대조한다. */
      window.__sevBasis = data.basis || '';
      _sevReach = data.reachability || null;
      renderSummaryBar(data); renderTable(); renderReachability(data.reachability);
      window.APO?.onFindings?.(data);
      const vc = document.getElementById('sevVerifyCard');
      if (vc) vc.style.display='';   // 분류가 있어야 표본 추출이 의미 있다
      const total=(data.firewall||[]).length+(data.proxy||[]).length;
      /* 못 읽은 대역은 완료 문구와 **함께** 남겨야 한다 — 먼저 띄우고 완료
         문구로 덮으면 사용자는 그 경고를 한 번도 못 본다(라운드 13 실측). */
      _stopClassifyProgress();
      /* 대역 안내가 손실을 수치로 말할 수 있게 등급 0(판정 불가) 수를 남긴다. */
      const _all = (data.firewall || []).concat(data.proxy || []);
      window.__apoJudgedTotal = _all.length;
      window.__apoUnknownCount = _all.filter(p => Number(p.urgency) === 0).length;
      renderRangeTags();
      showClassifyStatus({ total, rejectedRanges, rejectedMore });
      /* **이번 판정에 실제로 쓴 값**을 기준선으로 잡는다. 이후 입력이 이와
         달라지면 화면의 결과가 설정보다 앞선다는 뜻이고, 그때 배너가 뜬다.
         성공 경로에서만 찍는다 — 실패한 시도를 기준선으로 삼으면 낡음 표시가
         영영 안 뜬다. 미리보기 비교 기준도 이 값이다. */
      _thSnapshotApplied();
      /* **임계값도 룰 세트 해시에 들어간다.** 그런데 갱신 호출부가 장비 전환·
         객체규칙 저장·티켓 저장 셋뿐이라, 임계값을 바꾸고 판정하면 화면은 옛
         해시를 계속 보여줬다. 워크북 Summary 는 새 해시를 인쇄한다 — 그 카드
         본문이 "같은 해시가 리포트 Summary 에 인쇄된다" 고 말하는데 감사자가
         화면 캡처와 워크북을 대조하면 어긋난다(7라운드 F2 실측). */
      window.__apoRefreshRulesetHash?.();
    } catch(err) {
      /* 실패한 시도는 "결과 있음"으로 남으면 안 된다 — FQDN 임포트가 그 플래그를
         보고 "적용됨"이라고 잘못 알렸다.
         단, **시작 시점에 내리면 안 된다**: 이 플래그는 CSV 임포트의 자동
         재분류 트리거이기도 해서(app.js의 importPolicyCsv), 분류가 도는 동안
         false로 두면 그사이 올린 두 번째 CSV가 재분류를 건너뛴다. 그래서
         실패했을 때만 내린다. */
      if (_gen !== _classifyGen) return;   // 지나간 시도의 오류는 알릴 곳이 없다
      _stopClassifyProgress();   // 실패해도 타이머가 남으면 안 된다
      window.__sevHasData = false;
      /* **네트워크가 끊긴 것을 브라우저 말로 전하면 안 된다.** 서버를 끄고
         판정을 돌리면 상태줄이 "Failed to fetch" 로 굳었다 — 한국어 화면의
         영어이고, 다음에 뭘 하라는 말이 없어 사용자는 버튼만 다시 누른다
         (재비판 3라운드 F6). `TypeError` 는 fetch 가 서버에 닿지도 못했을
         때다(HTTP 오류는 위에서 serverMsg 로 처리된다).
         나머지 예외는 서버가 준 문장이라 이미 번역돼 있다. */
      if (statusEl) {
        const offline = (err instanceof TypeError)
          || /failed to fetch|networkerror|load failed/i.test(err?.message || '');
        apoSetText(statusEl, offline
          ? 'Could not reach APO. Check that the APO window is still open, then run the assessment again.'
          : (err?.message || 'Failed'));
      }
    }
  }

  // 파일 가져오기 (txt 한 줄에 CIDR 하나)
  const importBtn  = document.getElementById('sevRangeImportBtn');
  const importFile = document.getElementById('sevRangeImportFile');
  if (importBtn) importBtn.addEventListener('click', () => importFile?.click());
  if (importFile) {
    importFile.addEventListener('change', () => {
      const file = importFile.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = async (e) => {
        /* 어떤 표기를 대역으로 인정할지는 **서버가 정한다**. 예전엔 여기서
           '/'가 든 줄만 통과시켜, 장비 CLI 표기(10.10.0.0 255.255.0.0)·범위·
           단일 IP가 통째로 사라지고 아무 안내도 안 나왔다. 반대로 '// HQ'
           주석은 '/'가 있다는 이유로 대역으로 등록됐다. 같은 파일이 일괄
           보고에서는 정상 처리되던 불일치다(리뷰 라운드 15). */
        const lines = (e.target.result || '').split(/\r?\n/);
        const candidates = [];
        for (const raw of lines) {
          // "10.99.240.0./21" 같은 오탈자 처리: 슬래시 직전 점 제거
          const t = raw.trim().replace(/\.+\//g, '/');
          if (!t || t.startsWith('#') || t.startsWith(';')
              || t.startsWith('!') || t.startsWith('//')) continue;
          candidates.push(t);
        }
        if (!candidates.length) {
          if (statusEl) apoSetText(statusEl, 'No entries found in that file.');
          importFile.value = '';
          return;
        }
        try {
          const _impGen = window.__apoDeviceGen || 0;
          const merged = userRanges.map((r) => r.cidr).concat(candidates);
          const res = await fetch('/api/user-ranges/set', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            // 대역을 보내는 **모든** 경로가 장비를 지목해야 한다. 이 한 곳이
            // 빠져 있어, 게이트를 조인 뒤로 파일 임포트가 항상 409로 죽었다.
            body: JSON.stringify({ ranges: merged,
                                   device_id: currentDeviceId || undefined }),
          });
          if (!res.ok) {
            throw new Error(await serverMsgFrom(
              res, 'Server rejected the ranges file.'));
          }
          const info = await res.json();
          // 서버가 인정한 목록으로 화면을 맞춘다 — 화면 칩과 판정에 쓰이는
          // 대역이 어긋나면 "칩은 있는데 왜 Unknown이지"가 된다.
          if (!adoptServerRanges(info, _impGen)) return;
          const rej = info.rejected || [];
          const shown = rej.slice(0, 5).join(', ');
          const more = (info.rejected_total || rej.length) - rej.slice(0, 5).length;
          apoSetText(statusEl,
                     rej.length
                       ? (more > 0
                          ? '{n} IP range(s) in use — not recognised, ignored: '
                            + '{list} (+{more} more). Click Classify to apply.'
                          : '{n} IP range(s) in use — not recognised, ignored: '
                            + '{list}. Click Classify to apply.')
                       : '{n} IP range(s) in use. Click Classify to apply.',
                     { n: userRanges.length, list: shown, more });
        } catch (err) {
          /* i18n-dynamic: 예외 메시지 — 브라우저·네트워크가 준 문자열이다. */
          if (statusEl) statusEl.textContent = err.message || apoT('Import failed.');
        }
        importFile.value = '';
      };
      reader.readAsText(file, 'UTF-8');
    });
  }

  if (rangeAddBtn) rangeAddBtn.addEventListener('click',()=>{
    const v=rangeInput?.value.trim();
    if(!v){
      // 아무 반응 없이 삼키면 사용자는 버튼이 고장 났다고 읽는다. 잘못된 값과
      // 빈 값의 안내가 갈라지지 않게 같은 자리에 쓴다.
      apoSetText(statusEl, 'Type an IP range first, for example 10.10.0.0/16.');
      rangeInput?.focus();
      return;
    }
    /* **바로 저장한다.** 화면에만 칩을 그려 두었더니, 저장된 것처럼 보이는데
       새로고침 한 번에 말없이 사라졌다 — 실제 저장은 '점검 실행'을 눌렀을
       때뿐이었다(라운드 23 실측: 칩은 있는데 range_count=0). 대역은 도구가
       대신 채워줄 수 없는 유일한 손입력 자료이고, 마법사 경로는 같은 값을
       그 자리에서 저장한다. 같은 자료를 넣는 두 경로가 다르게 동작하면
       화면 표시(칩)는 같으므로 사용자가 구분할 방법이 없다. */
    if (rangeInput) rangeInput.value = '';
    const next = userRanges.map((r) => r.cidr).concat(v);
    (window.__apoSetRanges?.(next) || Promise.resolve())
      .then((info) => {
        if (statusEl && info) {
          const rej = info.rejected || [];
          /* i18n-dynamic: 삼항 양쪽 모두 apoT 를 지난다. */
          /* **"저장했습니다" 로 끝내면 낡은 결과를 들고 나간다.**
             대역은 판정 축이다 — 넣기 전 결과는 그 대역 없이 만든 것이다.
             그런데 이 문구가 "대역을 넣고 점검을 다시 실행하세요" 안내를
             **덮어써서**, 시킨 대로 다 한 고객이 '판정 불가 2건' 을 그대로
             안고 나갔다(8라운드 F2 실측: 재실행하니 2건이 등급을 받았다).
             설정 파일 업로드에는 같은 안내가 있는데 대역 변경에만 없었다. */
          /* **언어를 바꾸면 다시 그려져야 한다** — `textContent` 로 쓰면
             전환 전 언어로 굳는다(`apoSetText` 가 키를 남겨 다시 번역한다).
             값이 끼는 쪽만 조립하고, 재실행 안내는 별도 키로 둔다. */
          if (rej.length) {
            apoSetText(statusEl, 'Not recognised, ignored: {list}',
                       { list: rej.join(', ') });
          } else if (window.__sevHasData) {
            /* **`_lastClassifyStatus` 를 비우지 않으면 언어 전환이 안내를
               지운다.** `onLangChange(() => showClassifyStatus(null))` 이
               옛 "판정을 마쳤습니다" 재료를 그대로 들고 있다가 같은 요소를
               덮는다 — 대역이 안 들어간 옛 판정을 "마쳤습니다" 라고 단언하게
               된다(9라운드 F2 실측). `resetSeverityResults` 는 이 함정을
               피하는데 대역 핸들러 둘만 빠졌다. */
            window.__apoForgetClassifyStatus?.();
            apoSetText(statusEl,
                       '{n} IP range(s) saved — run the assessment again to apply it.',
                       { n: (info.user_ranges || []).length });
          } else {
            apoSetText(statusEl, '{n} IP range(s) saved for this device.',
                       { n: (info.user_ranges || []).length });
          }
        }
      })
      .catch((err) => {
        /* i18n-dynamic: 예외 메시지 — 브라우저·네트워크가 준 문자열이다. */
        if (statusEl) statusEl.textContent = err.message || apoT('Failed to save.');
      });
  });
  if (rangeInput) rangeInput.addEventListener('keydown',e=>{ if(e.key==='Enter') rangeAddBtn?.click(); });
  if (classifyBtn) classifyBtn.addEventListener('click',runClassify);
  /* CSV 임포트가 재분류 '완료'를 기다려야 실패를 그 화면에 알릴 수 있다.
     버튼 click()은 핸들러의 promise를 돌려주지 않으므로 함수 자체를 노출한다. */
  window.__apoRunClassify = runClassify;

  /* 등록 마법사가 대역을 넣을 수 있는 유일한 통로. 마법사가 자기 목록을 따로
     들면 화면 칩과 판정 기준이 갈라진다 — 같은 함수를 쓰게 한다.
     서버가 인정한 목록으로 되맞추므로 표기법 해석도 한 곳에서만 일어난다. */
  window.__apoSetRanges = async function (lines) {
    const _setGen = window.__apoDeviceGen || 0;
    const merged = (lines || []).map((s) => String(s).trim()).filter(Boolean);
    const res = await fetch('/api/user-ranges/set', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ranges: merged,
                             device_id: currentDeviceId || undefined }),
    });
    if (!res.ok) {
      throw new Error(await serverMsgFrom(res, 'Failed to save the IP ranges.'));
    }
    const info = await res.json();
    adoptServerRanges(info, _setGen);
    return info;
  };
  window.__apoGetRanges = () => userRanges.map((r) => r.cidr);
  /* 서버에 쓰지 않고 화면 칩만 비운다 — 장비를 떠날 때 앞 고객의 대역이
     화면에 남지 않게 하는 용도다. 서버에 쓰면 그 장비의 저장분을 지우게 된다. */
  window.__apoSetRangesLocal = (lines) => {
    userRanges.length = 0;
    (lines || []).forEach((c) => userRanges.push({ cidr: String(c) }));
    renderRangeTags();
  };

  document.querySelectorAll('.sev-subtab-btn').forEach(btn=>{
    btn.addEventListener('click',()=>{
      document.querySelectorAll('.sev-subtab-btn').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active'); activeSevTab=btn.dataset.sevTab; renderTable();
    });
  });

  if (exportBtn) exportBtn.addEventListener('click',async()=>{
    if (!sevData) return;
    if (!(await licenseGate())) return;   // 라이선스 확인
    const res=await fetch('/api/export/severity-workbook',{
      method:'POST', headers:{'Content-Type':'application/json'},
      // 이 판정이 어느 장비의 것인지 대고 내보낸다 — 서버가 붙이는 문서정보와
      // 다른 장비면 거부된다(시트는 C 고객, 표지는 B 고객인 워크북을 막는다).
      body:JSON.stringify({ ...sevData, device_id: currentDeviceId || undefined }),
    });
    if (!res.ok){ await alertApiError(res, 'Export failed.'); return; }
    saveResponseAs(await res.blob(), res, 'apo_findings.xlsx');
  });

  renderRangeTags();
  /* 이 화면이 코드로 그리는 것 전부 — 하나라도 빠지면 언어를 바꿨을 때 그
     칸만 영어로 남는다. 각 함수는 그릴 것이 없으면 스스로 비켜선다. */
  onLangChange(() => { renderRangeTags(); renderTable(); });
})();

/* ── Version Advisor ────────────────────────────────────────────────────── */
(function(){
  const runBtn    = document.getElementById('advisorRunBtn');
  const statusEl  = document.getElementById('advisorStatus');
  const verBox    = document.getElementById('advisorVersionBox');
  const resultCard = document.getElementById('advisorResultCard');
  const esc = v => String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  function sevClass(sev){
    const m = {'Critical':'critical','High':'high','Medium':'medium','Low':'low'};
    return m[sev] || 'unknown';
  }

  /* **'조사 안 함'과 '0건'은 다르다.** 상태줄은 정직하게 "이 브랜치는 DB 에
     없다"고 말하는데, 바로 아래 카드 셋이 `None` / `No items` 라고 해서
     보고서에 캡처해 넣는 그 영역이 "CVE 0건"이라 말했다(라운드 46 실측).
     답은 0 이 아니라 '모름'이다. */
  let _advNotCovered = false;
  const _advEmptyTitle = () => (_advNotCovered ? apoT('Not checked') : apoT('None'));
  const _advEmptyNote = (whenChecked) => (_advNotCovered
    ? apoT('This FortiOS branch is not in the vulnerability database — absence '
           + 'here is not evidence that the firmware is unaffected.')
    : apoT(whenChecked));

  function renderSummaryBar(data){
    const bar = document.getElementById('advisorSummaryBar');
    if(!bar) return;
    const s = data.summary || {};
    /* **'조사 안 함'과 '0건'은 다르다.** DB 가 이 브랜치를 안 담고 있으면
       조회 결과가 비는데, 그걸 0 으로 찍으면 조사하지 않은 것이 무결점으로
       인쇄된다 — 컨설턴트는 그 숫자를 그대로 보고서에 쓴다(라운드 45 실측:
       FortiOS 7.0 장비에 "0 active CVE(s)"). 숫자 대신 '—' 를 쓴다. */
    const un = data.not_covered;
    const num = (v) => (un || v == null ? '—' : v);
    const tone = (v, bad) => (un || v == null ? '' : (v > 0 ? bad : 'tile-success'));
    bar.innerHTML = [
      ['Active CVEs', num(s.unpatched_cves), tone(s.unpatched_cves,'tile-danger')],
      ['Known Issues', num(s.known_issues), tone(s.known_issues,'tile-warning')],
      ['Fix Versions Available', num(s.upgrade_fix_versions), ''],
    ].map(([label,val,cls])=>`
      <div class="advisor-summary-tile ${esc(cls)}">
        <div class="tile-label">${esc(label)}</div>
        <div class="tile-value">${esc(val)}</div>
      </div>`).join('');
  }

  function renderCveTable(cves, containerId, showPatchedBadge){
    const el = document.getElementById(containerId);
    if(!el) return;
    if(!cves || !cves.length){
      el.innerHTML = '<div class="empty-state"><strong>' + escapeHtml(_advEmptyTitle())
        + '</strong><span>' + escapeHtml(_advEmptyNote('No items for this version.')) + '</span></div>';
      return;
    }
    el.innerHTML = `<table class="advisor-cve-table">
      <thead><tr>
        <th>Severity</th><th>Advisory</th><th>CVE</th><th>Title</th>
        <th>Affected Range</th><th>Fix Version</th><th>Workaround</th>
        ${showPatchedBadge?'<th>Status</th>':''}
      </tr></thead>
      <tbody>${cves.map(c=>`<tr>
        <td><span class="adv-sev adv-sev-${sevClass(c.severity)}">${esc(c.severity)}</span></td>
        <td style="white-space:nowrap;font-size:12px">${esc(c.advisory_id||'')}</td>
        <td style="white-space:nowrap;font-size:12px">${esc(c.cve_id||'-')}</td>
        <td>${esc(c.title||'')}</td>
        <td style="white-space:nowrap;font-size:12px">${esc(c.affected_range||'')}</td>
        <td style="white-space:nowrap"><span class="adv-fix-pill">${esc(c.fix_version||'-')}</span></td>
        <td><span class="adv-workaround">${esc(c.workaround||'-')}</span></td>
        ${showPatchedBadge?`<td><span class="adv-patched-pill">${c.is_patched?'Patched':'Active'}</span></td>`:''}
      </tr>`).join('')}</tbody>
    </table>`;
  }

  function renderBugTable(bugs, containerId){
    const el = document.getElementById(containerId);
    if(!el) return;
    if(!bugs || !bugs.length){
      el.innerHTML = '<div class="empty-state"><strong>' + escapeHtml(_advEmptyTitle())
        + '</strong><span>' + escapeHtml(_advEmptyNote('No items for this version.')) + '</span></div>';
      return;
    }
    el.innerHTML = `<table class="advisor-bug-table">
      <thead><tr><th>Bug ID</th><th>Component</th><th>Description</th></tr></thead>
      <tbody>${bugs.map(b=>`<tr>
        <td style="white-space:nowrap;font-weight:700;font-size:12px">${esc(b.bug_id)}</td>
        <td style="white-space:nowrap;font-size:12px;color:var(--muted)">${esc(b.component||'-')}</td>
        <td>${esc(b.description||'')}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  }

  function renderFixGroups(upgradeFixes){
    const el = document.getElementById('advisorFixTable');
    if(!el) return;
    if(!upgradeFixes || !upgradeFixes.length){
      el.innerHTML = '<div class="empty-state"><strong>' + escapeHtml(_advEmptyTitle())
        + '</strong><span>' + escapeHtml(_advEmptyNote('No newer patch versions available in DB.')) + '</span></div>';
      return;
    }
    el.innerHTML = upgradeFixes.map(group=>`
      <div class="advisor-fix-version-group">
        <div class="advisor-fix-version-label">Fixes in ${esc(group.version)}</div>
        <table class="advisor-bug-table">
          <thead><tr><th>Bug ID</th><th>Component</th><th>Description</th></tr></thead>
          <tbody>${(group.resolved||[]).map(b=>`<tr>
            <td style="white-space:nowrap;font-weight:700;font-size:12px">${esc(b.bug_id)}</td>
            <td style="white-space:nowrap;font-size:12px;color:var(--muted)">${esc(b.component||'-')}</td>
            <td>${esc(b.description||'')}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>`).join('');
  }

  async function runAdvisor(){
    if(statusEl) apoSetText(statusEl, 'Analysing...');
    if(verBox) verBox.innerHTML = '';
    if(resultCard) resultCard.style.display = 'none';

    /* 이 패널에는 세대 검사가 아예 없었다. 늦게 온 응답이 초기화로 비운 DOM 을
       되살리고 카드까지 다시 열어, B 장비 화면에 A 의 모델·펌웨어·CVE 31건이
       떴다 — **고객이 보고서에 캡처해 넣는 탭**이다(3라운드 F3). */
    const _fresh = apoStillThisDevice();
    try {
      const res = await fetch('/api/version-advisor'
        + (currentDeviceId ? `?device_id=${encodeURIComponent(currentDeviceId)}` : ''));
      const data = await res.json();
      if (!_fresh()) return;

      if(data.error){
        const dbg = data.debug || {};
        const meta = dbg.meta || {};
        let msg = data.error;
        if(meta.config_version) msg += ` (detected: "${meta.config_version}")`;
        else if(meta.buildno) msg += ` (buildno: ${meta.buildno}, branch unknown)`;
        else msg += ' — Missing #config-version= or #buildno= line in config file.';
        /* i18n-dynamic: 설정 파일에서 읽은 버전 문자열을 조립한 문장. */
      if(statusEl) statusEl.textContent = msg;
        return;
      }

      const vi = data.ver_info || {};
      const featureLabels = {
        ssl_vpn:'SSL VPN', ipsec_vpn:'IPsec VPN', ha:'HA',
        ldap:'LDAP', saml:'SAML', captive_portal:'Captive Portal',
        security_fabric:'Security Fabric', automation:'Automation Stitch',
        fortitoken:'FortiToken', bluetooth:'Bluetooth', ztna:'ZTNA',
        proxy:'Web Proxy', wifi:'WiFi Controller', web_filter:'Web Filter',
        ips:'IPS', antivirus:'Antivirus', app_control:'App Control',
        fortilink:'FortiLink', rest_api:'REST API',
      };
      const featureTags = Array.isArray(data.active_features) && data.active_features.length
        ? `<div class="advisor-features"><span class="adv-feat-label">Detected Features</span>${
            data.active_features.map(f=>`<span class="adv-feat-tag">${esc(featureLabels[f]||f)}</span>`).join('')
          }</div>`
        : (data.active_features === null
            ? ''
            : '<div class="advisor-features"><span class="adv-feat-label">Features</span><span class="adv-feat-none">None detected — showing all entries</span></div>');

      if(verBox){
        verBox.innerHTML = `
          <div class="summary-stats">
            <div class="stat-card"><span class="stat-label">Model</span><span class="stat-value" style="font-size:18px">${esc(vi.model||vi.model_code||'Unknown')}</span>${vi.model&&vi.model_code&&vi.model!==vi.model_code?`<span style="font-size:11px;color:var(--muted);margin-top:2px;display:block">${esc(vi.model_code)}</span>`:''}</div>
            <div class="stat-card"><span class="stat-label">Branch</span><span class="stat-value" style="font-size:18px">FortiOS ${esc(vi.branch||'-')}</span></div>
            <div class="stat-card"><span class="stat-label">Version</span><span class="stat-value" style="font-size:18px">${esc(vi.version||vi.branch||'-')}</span>${vi.patch_known===false?`<span style="font-size:11px;color:var(--warn,#b45309);margin-top:2px;display:block">${esc(apoT('patch level unknown'))}</span>`:''}</div>
            <div class="stat-card"><span class="stat-label">Build</span><span class="stat-value" style="font-size:18px">${esc(vi.build||'-')}</span></div>
          </div>
          ${featureTags}`;
      }

      _advNotCovered = !!data.not_covered;
      renderSummaryBar(data);
      renderCveTable(data.unpatched_cves||[], 'advisorCveTable', false);
      renderBugTable(data.known_issues||[], 'advisorKnownTable');
      renderFixGroups(data.upgrade_fixes||[]);

      const cveCount = document.getElementById('advisorCveCount');
      const fixCount = document.getElementById('advisorFixCount');
      const knownCount = document.getElementById('advisorKnownCount');
      const dash = (v) => (data.not_covered ? '—' : v);
      if(cveCount) cveCount.textContent = dash((data.unpatched_cves||[]).length);
      if(fixCount) fixCount.textContent = dash((data.upgrade_fixes||[]).reduce((s,g)=>s+(g.resolved||[]).length,0));
      if(knownCount) knownCount.textContent = dash((data.known_issues||[]).length);

      if(resultCard) resultCard.style.display = '';
      const s = data.summary || {};
      /* 조사하지 않았으면 그렇게 말한다. 판정을 안 한 것을 '이상 없음'으로
         적으면, 그 문장이 고객 보고서로 그대로 들어간다. */
      if (data.not_covered) {
        apoSetText(statusEl,
          'This FortiOS branch ({branch}) is not in the vulnerability database '
          + '({coverage}) — APO did not check it. Absence of findings here is '
          + 'not evidence that the firmware is unaffected.',
          { branch: vi.branch || '?', coverage: data.coverage || 'unknown' });
      } else if (data.patch_level_assumed) {
        apoSetText(statusEl,
          'Analysis complete — {cves} active CVE(s), {issues} known issue(s). '
          + 'Build {build} is not in the patch-level table, so this was assessed '
          + 'as {branch}.0 (the first release of that branch) — the real device '
          + 'may already be patched.',
          { cves: s.unpatched_cves || 0, issues: s.known_issues || 0,
            build: vi.build || '?', branch: vi.branch || '?' });
      } else {
        apoSetText(statusEl,
                   'Analysis complete — {cves} active CVE(s), {issues} known issue(s).',
                   { cves: s.unpatched_cves || 0, issues: s.known_issues || 0 });
      }

    } catch(err){
      apoSetText(statusEl, 'Analysis failed: {detail}',
                 { detail: String(err.message || err) });
    }
  }

  if(runBtn) runBtn.addEventListener('click', runAdvisor);
})();

// ── Remediation ─────────────────────────────────────────────────────────────
(function(){
  const $ = id => document.getElementById(id);
  const esc = v => String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const riskClass = r => ({Critical:'rem-risk-critical',High:'rem-risk-high',Medium:'rem-risk-medium',Low:'rem-risk-low'}[r]||'rem-risk-none');

  let _candidates = {to_disable:[], already_disabled:[]};
  let _connectionOk = false;
  // 연결은 됐지만 **그 장비가 맞는지는 확인할 수 없는** 상태. 적용을 막지는
  // 않고, 확인창이 그 사실을 말하고 사용자의 확인을 서버로 함께 보낸다.
  let _unverifiedTarget = false;
  // 확인창이 대조할 값 — 연결 확인이 받아 온 시리얼.
  let _unverifiedSerial = '';
  // 시리얼이 **왜** 없는지. 'serial_unread' = 이번 조회가 끝나지 못했다(재시도로
  // 풀릴 수 있다), 'no_serial' = 장비가 답했고 그 답에 시리얼이 없다(영구).
  // 갈라 말하지 않으면 순간 장애를 영구 제약으로 단정한다(R75-1).
  let _unverifiedWhy = '';
  // 후보 목록이 갈릴 때마다 올라간다. 비동기 확인 절차가 옛 목록을 들고
  // 되살아나는 것을 막는 유일한 수단이다.
  let _candidatesGen = 0;

  /* 설정을 새로 열면 이 목록도 버려야 한다. 여기는 화면에서 유일하게 장비에
     '쓰는' 경로다 — A장비 후보 목록이 남은 채 B장비를 열면 Select All → Apply가
     A장비의 정책 번호를 지금 등록된 장비에 적용한다. 숫자가 틀리는 정도가 아니라
     설정이 바뀐다. */
  function resetCandidates(){
    _candidates = {to_disable:[], already_disabled:[]};
    ['remActiveHeader','remCriticalSection','remHighSection','remDisabledSection']
      .forEach(id => { const el = $(id); if (el) el.style.display = 'none'; });
    // 이 카드만 class로 여닫는다(renderApplyResults가 'hidden'을 뗀다). inline
    // style로 숨기면 !important인 .hidden을 떼도 다시 안 보인다 — 장비에 실제로
    // 적용한 결과표가 통째로 사라진다.
    $('remResultCard')?.classList.add('hidden');
    _candidatesGen += 1;
    ['#remCriticalTable tbody','#remHighTable tbody','#remDisabledTable tbody'].forEach(sel => {
      const t = document.querySelector(sel); if (t) t.innerHTML = '';
    });
    // 적용 결과표도 이전 고객 것이다. 숨기기만 하면 DOM에 남는다.
    const rb = $('remResultBody'); if (rb) rb.innerHTML = '';
    const chk = $('remCheckAll'); if (chk) chk.checked = false;
    _remSelected.clear();
    // 확인 모달이 열려 있었다면 그 안의 목록도 이미 무효다. Confirm에 이전
    // 선택이 클로저로 묶여 있으므로 닫고 핸들러도 떼어 낸다.
    const modal = $('remModal');
    if (modal) { modal.classList.add('hidden'); const c = $('remModalConfirm'); if (c) c.onclick = null; }
    const st = $('remLoadStatus');
    apoSetText(st, 'Configuration changed — load the candidates again.');
    /* _connectionOk는 일부러 그대로 둔다 — 장비 등록은 서버측 상태이고 방금 연
       설정 파일과 무관하다. 위험했던 건 "A장비 후보 목록을 지금 등록된 장비에
       적용"하는 것이었고, 목록을 비웠으니 Apply는 어차피 비활성이다. */
    updateApplyBtn();
  }
  window.__apoResetRemediation = resetCandidates;

  // ── Device 등록 ──────────────────────────────────────────────────────────
  $('remSaveBtn')?.addEventListener('click', async () => {
    const payload = {
      ip:         ($('remIp')?.value||'').trim(),
      port:       parseInt($('remPort')?.value||'443'),
      vdom:       ($('remVdom')?.value||'root').trim()||'root',
      token:      ($('remToken')?.value||'').trim(),
      verify_ssl: !($('remSkipSsl')?.checked),
      // 어느 장비를 보면서 등록하는지 함께 댄다.
      device_id: currentDeviceId || undefined,
    };
    if(!payload.ip || !payload.token){ setDevStatus('IP and API Token are required.', false); return; }
    const r = await fetch('/api/remediation/device', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const d = await r.json();
    _connectionOk = false;
    updateApplyBtn();
    setDevStatus(d.ok ? apoT('Device saved. Run Test Connection to verify.')
                      : serverMsg(d, 'Could not save the device.'),
                 d.ok ? null : false);
  });

  $('remTestBtn')?.addEventListener('click', async () => {
    setDevStatus('Testing connection...', null);
    /* `resetCandidates` 는 `_connectionOk` 를 일부러 안 지운다 — 그래서 늦게
       온 A 의 연결확인이 B 화면에 넘어온다. 후보가 비어 Apply 는 잠기지만
       `confirm_unverified_target` 은 "사용자가 경고를 봤다" 는 뜻으로 서버에
       나가는데, 본 경고는 A 의 것이다(6라운드 제안). */
    const fresh = apoStillThisDevice();
    const r = await fetch('/api/remediation/device/test' + (currentDeviceId ? `?device_id=${encodeURIComponent(currentDeviceId)}` : ''));
    const d = await r.json();
    if (!fresh()) return;
    /* 연결이 됐다는 것과 **맞는 장비에 연결됐다**는 것은 다른 사실이다.
       이름이 다르면 적용은 서버가 막지만, 화면이 그 이유를 미리 말해 줘야
       사용자가 IP 를 고칠 수 있다(라운드 25: 화면은 BETA 인데 ACME 방화벽이
       응답했고, 그대로 정책 4건이 꺼졌다). */
    const mismatched = d.ok && d.identity === 'mismatch';
    /* '확인할 수 없다'는 세 번째 상태다. 이걸 성공으로 뭉뚱그리면 화면은
       'Connected — FortiGate' 라고만 하고, 사용자는 대조가 끝난 줄 안다.
       막지는 않되 여기서 말해 둬야 적용 확인창의 경고가 뜬금없지 않다. */
    _unverifiedTarget = d.ok === true && d.identity === 'unverifiable';
    _unverifiedSerial = d.serial || '';
    _unverifiedWhy    = d.identity_why || '';
    _connectionOk = d.ok === true && d.identity !== 'mismatch';
    updateApplyBtn();
    let msg = d.message || (d.ok ? 'Connected' : 'Failed');
    if (mismatched && d.identity_why === 'serial_mismatch') {
      /* **이름이 아니라 시리얼을 말한다.** 이름이 같은데 시리얼이 다른 것이
         정확히 이 판정의 존재 이유인데, 화면은 'DEMO-FGT-01에 연결됐는데 지금
         열어 둔 설정은 DEMO-FGT-01입니다' 라며 같은 이름 둘을 대고 그것을
         차이라고 제시했다(라운드 30 실측). 서버는 시리얼을 보내고 있었다. */
      msg = apoT('This is a different unit. It reports serial {found}, but APO '
                 + 'confirmed this device as {expected}. Check the address.',
                 { found: d.serial || '?', expected: d.pinned || '?' });
    } else if (mismatched && d.identity_why === 'serial_missing_but_pinned') {
      msg = apoT('APO confirmed this device as serial {expected}, but the '
                 + 'firewall at this address does not report a serial, so it '
                 + 'cannot be checked. Use the address you confirmed before.',
                 { expected: d.pinned || '?' });
    } else if (mismatched) {
      msg = apoT('Connected to {found}, but the configuration you have open is '
                 + '{open}. Changes are not sent to a different device — check the '
                 + 'IP, or open that device first.',
                 { found: d.hostname || '?', open: d.config_hostname || '?' });
    } else if (d.ok && d.identity === 'match' && d.pinned) {
      /* 첫 확인 때 '그 뒤로는 시리얼로 자동 대조한다'고 약속했다 — 그 약속이
         지금 이행 중이라는 것을 말해야 한다. 두 번째부터 경고 한 줄이 조용히
         사라지기만 하면, 무엇이 확인됐는지 알 수 없다(라운드 30 지적). */
      msg += ' — ' + apoT('serial {serial} matches the device APO confirmed.',
                          { serial: d.pinned });
    } else if (_unverifiedTarget) {
      /* 문장이 'Connected —' 로 시작하면 성공으로 읽힌다. 되돌릴 수 없는 쓰기
         직전의 유일한 경고이므로 경고를 **앞에** 세운다(라운드 29 지적). */
      msg = '⚠ ' + (d.identity_why === 'serial_unread'
        ? apoT('APO could not read the serial number from this FortiGate this '
               + 'time, so it has nothing unique to match it by right now. '
               + 'Test the connection again to retry. Check the address '
               + 'before applying anything.')
        : d.identity_why === 'no_serial'
        ? apoT('This FortiGate did not report a serial number, so APO has '
               + 'nothing unique to match it by. Check the address before '
               + 'applying anything.')
        : apoT('APO has not confirmed this device before — a hostname is not '
               + 'proof of identity. Check the address before applying '
               + 'anything; APO will remember the serial from then on.'))
        + ' ' + apoT('(Connected to {name}.)', { name: d.hostname || '?' });
    }
    /* **인증서 축은 시리얼 축과 독립이다 — else-if 사슬에 끼우면 안 된다.**
       처음엔 사슬 안에 넣었더니, 시리얼이 맞는 순간(실시리얼을 중계하는
       프록시가 딱 그 경우다) 인증서 변경 경고가 화면에서 사라지고 초록
       'serial matches' 만 떴다. 그 상태로 적용을 누르면 서버는 409 로 막는데
       사용자는 이유를 알 수 없다 — 이 기능이 '화면이 먼저 말해야 한다'고
       적어 둔 것과 정반대다(게이트 correctness 검출). 두 축을 따로 본다. */
    let _tlsWarn = false;
    if (d.tls_pin === 'changed') {
      _tlsWarn = true;
      msg = '⚠ ' + apoT(
        'The certificate at this address changed since APO last connected. '
        + 'On a channel without certificate verification that is what a '
        + 'man-in-the-middle looks like — changes will not be sent. If the '
        + 'device was genuinely replaced or re-keyed, remove and register it again.')
        + ' ' + apoT('(Connected to {name}.)', { name: d.hostname || '?' });
    } else if (d.tls_pin === 'new' && d.tls_fingerprint) {
      /* 첫 연결의 지문은 **보여줘야** 한다 — 장비에서 대조할 수 있어야
         TOFU 의 첫 연결이 의미를 갖는다(SSH 가 지문을 찍어 주는 이유).
         이건 경고가 아니라 덧붙이는 사실이라 앞 문장을 지우지 않는다. */
      msg += ' — ' + apoT(
        'first connection: certificate fingerprint {fp} is now remembered for '
        + 'this device. Check it on the device if this is a new network.',
        { fp: String(d.tls_fingerprint).slice(0, 16) + '…' });
    }
    setDevStatus(
      msg,
      (mismatched || _tlsWarn) ? false : (_unverifiedTarget ? null : d.ok),
      _unverifiedTarget || _tlsWarn);
  });

  function setDevStatus(msg, ok, warn){
    const el = $('remDeviceStatus'); if(!el) return;
    el.textContent = msg;
    // 경고는 성공도 실패도 아닌 세 번째 상태다 — 회색으로 두면 안 읽힌다.
    el.className = 'rem-status-msg ' + (warn ? 'is-warning'
      : ok === true ? 'rem-ok' : ok === false ? 'rem-err' : '');
  }

  // ── 후보 로드 ─────────────────────────────────────────────────────────────
  $('remLoadBtn')?.addEventListener('click', loadCandidates);

  async function loadCandidates(){
    const statusEl = $('remLoadStatus');
    if(statusEl) apoSetText(statusEl, 'Loading...');
    /* **이 응답이 늦게 오면 남의 장비 정책 번호를 여기에 채운다.**
       `_candidatesGen` 은 올리기만 하고 "내가 아직 최신인가" 를 묻지 않았다.
       14초 지연 실측: B 장비를 연 화면에 A 의 후보표가 채워졌고, `_candidates`
       까지 A 로 덮여 Select All → Apply 가 **A 의 정책 번호를 B 장비로**
       보낼 수 있었다 — 서버 게이트는 등록장비·VDOM·시리얼만 보고 그 번호가
       지금 열린 config 에 있는지는 안 본다. 숫자가 틀리는 정도가 아니라
       설정이 바뀐다(재비판 3라운드 F2). */
    /* **입력 축까지 본다.** 장비가 그대로여도 객체 규칙·티켓 형식을 저장하면
       이 후보 목록은 옛 입력으로 계산된 것이 된다. 그 축을 안 보던 동안,
       화면이 "후보를 다시 불러오세요" 라고 말한 **직후 스스로를 뒤집고**
       낡은 계획을 현재인 것처럼 제시했다 — Apply 로 장비에 나가는 목록이다
       (5라운드 F-E). */
    const _fresh = apoStillThisInput();
    try {
      const r = await fetch('/api/remediation/candidates'
        + (currentDeviceId ? `?device_id=${encodeURIComponent(currentDeviceId)}` : ''));
      const d = await r.json();
      if (!_fresh()) return;
      if(d.error){
        /* i18n-dynamic: 서버가 낸 거절 사유 — 쓰는 순간 번역돼 있다. */
        if(statusEl) statusEl.textContent = serverMsg(d);
        return; }
      // 목록이 갈릴 때마다 세대를 올린다 — 대기 중이던 확인창이 옛 선택으로
      // 되살아나는 것을 막는 건 이 카운터뿐이다.
      _candidatesGen += 1;
      _candidates = d;
      // 새 목록에는 아무것도 선택돼 있지 않다. Select All 체크가 남으면 다음
      // 클릭이 '해제'로 잡혀 아무 일도 안 일어난다(두 번 눌러야 한다).
      const chkAll = $('remCheckAll'); if (chkAll) chkAll.checked = false;
      _remSelected.clear();
      const critical = d.to_disable.filter(p => p.urgency === 1);
      const high     = d.to_disable.filter(p => p.urgency === 2);
      rerenderRemTables();
      const total = d.to_disable.length + d.already_disabled.length;
      /* **서버가 뺀 것을 화면이 말해야 한다.** 판정 근거가 이 계획 자신에
         기대는 정책은 후보에서 유보로 옮긴다(조치 계획·워크북과 같은 규칙).
         그 사실을 말하지 않으면 사용자는 그 정책이 사라진 줄 안다. */
      const deferred = d.deferred || [];
      let msg = apoT('Critical {c} · High {h} · already disabled {d}',
                     { c: critical.length, h: high.length,
                       d: d.already_disabled.length });
      /* **두 화면이 다른 등급을 말하면 그 사실을 말해야 한다.** 이 목록은
         지금 재계산한 것이고, 화면에 남은 점검 결과·내보낸 워크북은 점검을
         누른 그 시점의 것이다. 그 사이 사용량 CSV 를 올리거나 임계값을
         바꾸면 같은 정책이 여기서 High, 워크북에서 Low 로 나온다 — 실제로
         그 문의가 왔고(정책 498), 화면은 아무 말도 하지 않았다.
         판정 로직은 두 경로가 동일하다. 다른 것은 계산 시점뿐이다. */
      if (window.__sevHasData && window.__sevBasis && d.basis
          && window.__sevBasis !== d.basis) {
        msg += ' — ⚠ ' + apoT(
          'This list was just recalculated, but the findings on screen (and any '
          + 'workbook you exported) were produced from different inputs — run '
          + 'the assessment again so both agree.');
      }
      if (deferred.length) {
        /* 다중 VDOM 에서 번호만 적으면 어느 7번인지 모른다(라운드 54) */
        const _tag = (vdom, id) => (vdom ? vdom + '#' : '#') + id;
        /* **먼저 처리할 정책 번호를 말해야 한다.** '위 항목을 먼저 처리하라'고
           하면서 어느 항목인지는 안 적었고, 문장 끝의 괄호 ID 는 바로 앞
           명사('이 계획이 바꾸는 다른 정책')를 가리키는 것처럼 읽혀 실사용에서
           가림막 ID 로 오해됐다 — 실제로는 유보된 정책 자신의 번호다. 서버는
           deferred_because 로 가림막을 이미 보내고 있었는데 화면이 버렸다.
           두 목록에 각각 이름표를 붙여 지시대상을 없앤다. */
        const _shadowers = [...new Set(deferred
          .filter(p => p.deferred_because)
          .map(p => _tag(p.vdom, p.deferred_because)))];
        msg += ' — ' + apoT(
          '{n} policy(ies) held back: {ids}. Each is unreachable only while a '
          + 'policy this plan also changes stays enabled ({shadowers}) — decide '
          + 'those first, take a fresh backup and run APO again.',
          { n: deferred.length,
            ids: deferred.map(p => _tag(p.vdom, p.policy_id)).join(', '),
            shadowers: _shadowers.join(', ') });
      }
      /* i18n-dynamic: 위에서 apoT 로 조립한 문장 — 조각이 조건부다. */
      if(statusEl) statusEl.textContent = msg;
    } catch(e) {
      apoSetText(statusEl, 'Load failed: {detail}', { detail: e.message });
    }
  }

  /* **두 표는 같은 줄 생김새를 쓴다.** '이미 비활성' 표만 따로 손으로 써
     두었더니 Type 칸이 빠져 머리글 9칸에 행 8칸이 됐고, 값이 한 칸씩 밀려
     정책 4가 TYPE='DISABLED-old-partner-rule', DESTINATION IP='MSSQL',
     SERVICE='always' 로 인쇄됐다(라운드 40 실측). 되돌릴 수 없는 PUT 을
     누르기 직전에 보는 표다. 같은 것을 두 번 쓰면 한쪽만 낡는다. */
  /* **머리글과 행은 같은 컬럼 정의에서 나온다.** 컬럼 숨김(사용자 선택)도
     이 정의 하나로 머리글·행에 동시에 적용된다 — 따로 쓰면 한쪽만 낡아
     라운드 40 의 열-밀림이 재현된다. */
  const REM_COLS = [
    { k: 'id',     label: 'ID' },
    { k: 'type',   label: 'Type' },
    { k: 'name',   label: 'Name' },
    { k: 'risk',   label: 'Risk' },
    { k: 'src',    label: 'Source IP',      opt: true },
    { k: 'dst',    label: 'Destination IP', opt: true },
    { k: 'svc',    label: 'Service',        opt: true },
    { k: 'sched',  label: 'Schedule',       opt: true },
    { k: 'reason', label: 'Reason',         opt: true },
  ];
  /* 단일 필터 컨트롤(2026-08-24 Jayden 재지적 — 자유 검색과 컬럼 필터의
     중복 제거): _remLive 는 지금 입력 중인 조건(컬럼 'any' = 종전 자유
     검색), _remFilters 는 Enter/추가로 고정한 칩들. 전부 AND 결합.
     ID 는 정확 일치("62"가 162 에 안 걸린다), 그 외는 포함 일치. */
  let _remFilters = [];
  const _remLive = { col: 'any', val: '' };
  /* **선택의 진실은 DOM 이 아니라 이 집합이다.** 검색으로 행이 숨어도
     선택이 유지돼야 한다 — 필터를 바꿀 때 체크가 사라지면 사용자가 고른
     것과 실제 적용 대상이 갈린다(2026-08-24 검색 기능 신설과 동시 도입). */
  const _remSelected = new Set();
  const _remCollapsed = {};   // body id -> bool. 미지정이면 행수 기준 기본값.

  function _remKey(p){
    return `${p.policy_id}|${p.type||'firewall'}|${p.vdom||''}`;
  }
  function _remVisibleCols(){
    return REM_COLS;   // 컬럼 숨김 기능은 폐지 — 필터 조건으로 대체됐다
  }
  function _remColValue(p, k){
    const _ty = (p.type || 'firewall') === 'proxy' ? 'proxy' : 'firewall';
    switch (k) {
      case 'id':     return String(p.policy_id ?? '');
      case 'type':   return p.vdom ? `${_ty} (${p.vdom})` : _ty;
      case 'name':   return String(p.name ?? '');
      case 'risk':   return String(p.risk_level ?? '');
      case 'src':    return String(p.srcaddr ?? '');
      case 'dst':    return String(p.dstaddr ?? '');
      case 'svc':    return String(p.service ?? '');
      case 'sched':  return String(p.schedule ?? '');
      case 'reason': return String(p.reason ?? '');
      default:       return '';
    }
  }
  function _remCell(p, k){
    /* VDOM 도 정책 번호의 일부다 — 다중 VDOM 에서 같은 번호 두 줄을 구별할
       단서를 Type 칸에 병기한다(워크북 Action Plan 과 같은 표기, 라운드 54). */
    const _ty = (p.type || 'firewall') === 'proxy' ? 'proxy' : 'firewall';
    switch (k) {
      case 'id':     return `<td>${esc(p.policy_id)}</td>`;
      case 'type':   return `<td class="rem-td-muted">${esc(p.vdom ? `${_ty} (${p.vdom})` : _ty)}</td>`;
      case 'name':   return `<td>${esc(p.name)}</td>`;
      case 'risk':   return `<td><span class="rem-risk ${riskClass(p.risk_level)}">${esc(p.risk_level)}</span></td>`;
      case 'src':    return `<td class="rem-td-muted">${esc(p.srcaddr||'—')}</td>`;
      case 'dst':    return `<td class="rem-td-muted">${esc(p.dstaddr||'—')}</td>`;
      case 'svc':    return `<td class="rem-td-muted">${esc(p.service||'—')}</td>`;
      case 'sched':  return `<td class="rem-td-muted">${esc(p.schedule||'—')}</td>`;
      case 'reason': return `<td class="rem-td-reason">${esc(p.reason)}</td>`;
      default:       return '<td></td>';
    }
  }
  function _remRow(p, withCheck = true){
    const key = _remKey(p);
    const chk = withCheck
      ? `<td><input type="checkbox" class="rem-check"${_remSelected.has(key) ? ' checked' : ''} data-id="${esc(p.policy_id)}" data-type="${esc(p.type||'firewall')}" data-vdom="${esc(p.vdom||'')}"></td>`
      : '';
    return `<tr>${chk}${_remVisibleCols().map(c => _remCell(p, c.k)).join('')}</tr>`;
  }
  function _renderRemHeads(){
    const cols = _remVisibleCols().map(c => `<th>${esc(c.label)}</th>`).join('');
    document.querySelectorAll('tr[data-rem-head]').forEach(tr => {
      tr.innerHTML = (tr.dataset.remHead === 'check'
        ? '<th style="width:40px"></th>' : '') + cols;
    });
  }
  /* **한 조건 안에서 쉼표로 나눈 값은 OR 다.** '498, 499, 500' 을 칩 세
     개로 넣으면 AND 라 결과가 0 건이었다 — 한 정책이 동시에 498 이고 499 일
     수는 없다(Jayden 실사용 지적). 칩끼리는 그대로 AND 이므로
     'ID: 498,499' + 'Risk: High' 는 "498이나 499 이면서 High" 가 된다.
     같은 컬럼은 OR, 다른 컬럼은 AND — 필터 UI 의 일반 관례다. */
  function _remNeedles(val){
    return String(val).split(',').map(s => s.trim()).filter(Boolean);
  }
  function _remOneOk(p, col, needle){
    if (col === 'any') {
      const q = needle.toLowerCase();
      return [p.policy_id, p.vdom, p.type, p.name, p.srcaddr, p.dstaddr,
              p.service, p.schedule, p.reason, p.risk_level]
        .some(v => String(v == null ? '' : v).toLowerCase().includes(q));
    }
    const v = _remColValue(p, col);
    if (col === 'id') {
      // ID 는 정확 일치 — "62" 가 162·620 에 걸리면 필터의 의미가 없다
      return v === needle;
    }
    return v.toLowerCase().includes(needle.toLowerCase());
  }
  function _remCondOk(p, col, val){
    const needles = _remNeedles(val);
    // 값이 비었거나 쉼표뿐이면 조건이 없는 것이다 — 전부 통과.
    if (!needles.length) return true;
    return needles.some(n => _remOneOk(p, col, n));
  }
  function _remMatches(p){
    for (const f of _remFilters) {
      if (!_remCondOk(p, f.col, f.val)) return false;
    }
    return _remCondOk(p, _remLive.col, _remLive.val);
  }
  function _remFiltering(){
    // 쉼표만 남은 입력(",,")은 조건이 아니다 — _remCondOk 와 같은 기준을 쓴다.
    return !!(_remNeedles(_remLive.val).length || _remFilters.length);
  }
  function _remSetCollapsed(bodyId, collapsed){
    const body = document.getElementById(bodyId);
    if (!body) return;
    body.style.display = collapsed ? 'none' : '';
    const caret = document.querySelector(`[data-rem-body="${bodyId}"] .rem-caret`);
    if (caret) caret.textContent = collapsed ? '▸' : '▾';
  }
  function _onRemCheckChange(e){
    const cb = e.target;
    const key = `${cb.dataset.id}|${cb.dataset.type||'firewall'}|${cb.dataset.vdom||''}`;
    if (cb.checked) _remSelected.add(key); else _remSelected.delete(key);
    updateApplyBtn();
  }
  function renderCriticalTable(rows){
    const tbody = document.querySelector('#remCriticalTable tbody'); if(!tbody) return;
    tbody.innerHTML = rows.map(p => _remRow(p)).join('');
    updateApplyBtn();
    document.querySelectorAll('.rem-check').forEach(cb => cb.addEventListener('change', _onRemCheckChange));
  }
  function renderHighTable(rows){
    const tbody = document.querySelector('#remHighTable tbody'); if(!tbody) return;
    tbody.innerHTML = rows.map(p => _remRow(p)).join('');
    updateApplyBtn();
    document.querySelectorAll('.rem-check').forEach(cb => cb.addEventListener('change', _onRemCheckChange));
  }

  function _selectedKeys(){
    /* 선택 키에도 VDOM — `id|type` 만 쓰면 root#7 을 체크할 때 guest#7 까지
       payload 에 담겨, 사용자가 고르지 않은 정책 때문에 서버 409 를 만나고
       이유를 알 수 없다(라운드 54 완성도 렌즈. 쓰기 자체는 서버
       _vdom_conflicts 가 막지만 화면이 원인을 만들면 안 된다). */
    /* DOM 이 아니라 선택 집합에서 읽는다 — 검색으로 화면에서 숨은 행의
       선택도 대상에 남아야 한다(사용자가 고른 것이 진실). */
    return [..._remSelected];
  }
  function _filterBySelection(keys){
    return _candidates.to_disable.filter(p => keys.includes(`${p.policy_id}|${p.type||'firewall'}|${p.vdom||''}`));
  }

  function renderDisabledTable(rows){
    const tbody = document.querySelector('#remDisabledTable tbody'); if(!tbody) return;
    tbody.innerHTML = rows.map(p => _remRow(p, false)).join('');
  }

  /* 필터·컬럼·접기 상태로부터 세 표를 다시 그린다. 검색 중에는 카운트를
     "보이는/전체"로 적어, 접힌 행이 사라진 게 아니라 걸러진 것임을 말한다. */
  function rerenderRemTables(){
    if (!_candidates || !Array.isArray(_candidates.to_disable)) return;
    _renderRemHeads();
    const critAll = _candidates.to_disable.filter(p => p.urgency === 1);
    const highAll = _candidates.to_disable.filter(p => p.urgency === 2);
    const disAll  = _candidates.already_disabled || [];
    const crit = critAll.filter(_remMatches);
    const high = highAll.filter(_remMatches);
    const dis  = disAll.filter(_remMatches);
    renderCriticalTable(crit);
    renderHighTable(high);
    renderDisabledTable(dis);
    $('remActiveHeader').style.display    = _candidates.to_disable.length ? '' : 'none';
    $('remCriticalSection').style.display = critAll.length ? '' : 'none';
    $('remHighSection').style.display     = highAll.length ? '' : 'none';
    $('remDisabledSection').style.display = disAll.length ? '' : 'none';
    const cnt = (shown, all) => _remFiltering() ? `(${shown}/${all})` : `(${all})`;
    const cc = $('remCriticalCount'); if (cc) cc.textContent = cnt(crit.length, critAll.length);
    const hc = $('remHighCount');     if (hc) hc.textContent = cnt(high.length, highAll.length);
    const dc = $('remDisabledCount'); if (dc) dc.textContent = cnt(dis.length, disAll.length);
    /* 접기 기본값: 사용자가 만진 적 없으면 15행 초과 섹션은 접는다(수백 행이
       펼쳐진 채 시작하는 게 원 불편). 검색 중엔 결과를 봐야 하므로 펼친다. */
    const eff = (bodyId, rows) => _remFiltering()
      ? false
      : (_remCollapsed[bodyId] !== undefined ? _remCollapsed[bodyId] : rows > 15);
    _remSetCollapsed('remCriticalBody', eff('remCriticalBody', critAll.length));
    _remSetCollapsed('remHighBody',     eff('remHighBody', highAll.length));
    _remSetCollapsed('remDisabledBody', eff('remDisabledBody', disAll.length));
  }

  // 접기/펼치기 — 헤더 클릭
  document.querySelectorAll('.rem-collapsible').forEach(h => {
    h.addEventListener('click', () => {
      const bodyId = h.dataset.remBody;
      const body = document.getElementById(bodyId);
      const collapsed = body && body.style.display !== 'none';
      _remCollapsed[bodyId] = collapsed;
      _remSetCollapsed(bodyId, collapsed);
    });
  });

  // 단일 필터 컨트롤 — 컬럼 선택(전체=자유 검색) + 값 입력(즉시 반영) +
  // Enter/추가로 칩 고정(AND). 드롭다운 뒤에 숨기지 않는다(2026-08-24).
  function _remRenderFilterCol(){
    const sel = $('remFilterCol'); if (!sel) return;
    sel.innerHTML = `<option value="any">${esc(apoT('All columns'))}</option>`
      + REM_COLS.map(c => `<option value="${esc(c.k)}">${esc(c.label)}</option>`).join('');
    sel.value = _remLive.col;
  }
  function _remRenderChips(){
    const box = $('remFilterChips'); if (!box) return;
    box.innerHTML = _remFilters.map((f, i) => {
      const col = f.col === 'any' ? apoT('All columns')
        : (REM_COLS.find(c => c.k === f.col) || { label: f.col }).label;
      return `<span style="display:inline-flex;gap:6px;align-items:center;border:1px solid var(--line,#3a4152);border-radius:999px;padding:2px 10px;font-size:12px">
        ${esc(col + ' = ' + f.val)}
        <button type="button" data-rm-filter="${i}" style="border:none;background:none;color:var(--muted);cursor:pointer;font-size:13px;padding:0">✕</button>
      </span>`;
    }).join('');
    box.querySelectorAll('button[data-rm-filter]').forEach(b => {
      b.addEventListener('click', () => {
        _remFilters.splice(Number(b.dataset.rmFilter), 1);
        _remRenderChips();
        rerenderRemTables();
      });
    });
  }
  function _remPinCondition(){
    const val = String($('remSearch')?.value || '').trim();
    if (!val) return;
    _remFilters.push({ col: _remLive.col, val });
    _remLive.val = '';
    const inp = $('remSearch'); if (inp) inp.value = '';
    _remRenderChips();
    rerenderRemTables();
  }
  $('remFilterCol')?.addEventListener('change', e => {
    _remLive.col = e.target.value || 'any';
    rerenderRemTables();
  });
  $('remSearch')?.addEventListener('input', e => {
    _remLive.val = String(e.target.value || '');
    rerenderRemTables();
  });
  $('remSearch')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); _remPinCondition(); }
  });
  $('remFilterAdd')?.addEventListener('click', _remPinCondition);
  _remRenderFilterCol();

  // 전체 선택 — **지금 보이는 행**에만 적용한다. 안 보이는 행까지 선택하면
  // 사용자가 확인한 적 없는 정책이 적용 대상에 들어간다. '보이는'의 정의는
  // 두 숨김 방식 모두다: 검색 필터(행이 DOM 에서 빠짐)와 **섹션 접힘**(행은
  // DOM 에 남음 — 라운드 77 UI 렌즈: 기본 접힌 Critical 20행이 첫 Select
  // All 에 통째로 들어갔다).
  function _remVisibleChecks(){
    return [...document.querySelectorAll('.rem-check')].filter(cb => {
      const wrap = cb.closest('.rem-table-wrap');
      return !wrap || wrap.style.display !== 'none';
    });
  }
  function _remSelectAll(checked){
    _remVisibleChecks().forEach(cb => {
      cb.checked = checked;
      const key = `${cb.dataset.id}|${cb.dataset.type||'firewall'}|${cb.dataset.vdom||''}`;
      if (checked) _remSelected.add(key); else _remSelected.delete(key);
    });
    updateApplyBtn();
  }
  $('remCheckAll')?.addEventListener('change', e => _remSelectAll(e.target.checked));

  function updateApplyBtn(){
    const applyBtn  = $('remApplyBtn');
    const countEl   = $('remSelectedCount');
    const total     = (_candidates && _candidates.to_disable)
      ? _candidates.to_disable.length : 0;
    if(countEl) countEl.textContent =
      apoT('{n} / {total} selected', { n: _remSelected.size, total });
    const hasChecked = _remSelected.size > 0;
    if(applyBtn){
      const canApply = _connectionOk && hasChecked;
      applyBtn.disabled = !canApply;
      applyBtn.title = !_connectionOk
        ? 'Run Test Connection first'
        : !hasChecked ? 'Select at least one policy' : '';
    }
  }

  // ── Apply ─────────────────────────────────────────────────────────────────
  $('remApplyBtn')?.addEventListener('click', async () => {
    const selectedKeys = _selectedKeys();
    if(!selectedKeys.length) return;
    const selectedPolicies = _filterBySelection(selectedKeys);
    const gen = _candidatesGen;   // 이 목록이 뽑힌 시점
    /* 되돌릴 수 없는 장비 변경을 확인시키는 자리인데 대상이 안 적혀 있었다
       (건수만 있었다). 어디로 나가는지와 어떤 설정에서 뽑은 목록인지를 적는다.

       대상은 반드시 **서버에 등록된** 값을 쓴다. 입력칸을 읽으면, 저장한 뒤에
       칸만 고쳐 놓은 경우 실제 적용 대상과 다른 장비를 보여주게 된다. */
    /* await 동안 목록도 선택도 바뀔 수 있다. 세대 카운터는 목록 교체만 잡고
       체크박스 변경은 못 잡으므로, 확인 절차가 끝날 때까지 두 버튼을 잠근다.
       (Load Candidates가 Apply 바로 옆에 있어 실제로 누를 수 있다) */
    const applyBtn = $('remApplyBtn'), loadBtn = $('remLoadBtn');
    if (applyBtn) applyBtn.disabled = true;
    if (loadBtn) loadBtn.disabled = true;
    let dev = null;
    try { dev = await (await fetch('/api/remediation/device' + (currentDeviceId ? `?device_id=${encodeURIComponent(currentDeviceId)}` : ''))).json(); }
    catch(_) {}
    if (loadBtn) loadBtn.disabled = false;
    // 이전 상태를 스냅샷으로 되돌리면 안 된다 — 잠근 사이에 선택이 바뀌었을 수
    // 있다. 활성 여부를 계산하는 쪽(updateApplyBtn)에 맡긴다.
    updateApplyBtn();
    /* await 사이에 설정을 새로 열면 resetCandidates()가 이 목록을 무효로 만든다.
       그대로 이어서 모달을 열면 초기화가 막으려던 바로 그 상황(A장비 목록을
       B장비에 적용)이 다시 생긴다. 세대가 바뀌었으면 조용히 그만둔다. */
    if (gen !== _candidatesGen) return;
    /* 대상을 확인하지 못했으면 진행하지 않는다. 되돌릴 수 없는 변경인데
       "the registered device"라고 뭉뚱그리면 어디에 나가는지 모른 채 누르게 된다. */
    if (!dev?.registered) {
      /* 여기까지 왔다는 건 Test Connection이 통과했다는 뜻이므로(Apply는 그때만
         열린다) 대개 "저장 안 함"이 아니라 "확인 실패"다. 잘못된 지시를 하지
         않는다.

         장비 상태줄은 한 카드 위에 있어서, 거기에만 적으면 방금 버튼을 누른
         사람 눈에 안 들어온다. 누른 자리(remLoadStatus)에도 적되 후보 요약을
         지우지 않도록 앞에 덧붙인다. */
      const why = 'Could not confirm which device is registered — not applying. '
        + 'Re-run Test Connection, or save the device again if the tool restarted.';
      setDevStatus(why, false);
      const st = $('remLoadStatus');
      if (st && !st.textContent.startsWith(why)) st.textContent = why + ' ' + st.textContent;
      return;
    }
    const vdom = dev.vdom || '';
    // 브라우저를 새로고침하면 서버 상태는 남지만 화면 상태는 초기값으로 돌아간다.
    // 그때 기본 문구("No configuration loaded")를 출처로 적으면 문장이 자기모순이 된다.
    const shown = (document.getElementById('stDevice')?.textContent || '').trim();
    const src = shown && shown !== 'No configuration loaded' ? shown : '';
    // 정책이 많으면 번호를 다 늘어놓느라 모달이 버튼까지 밀어낸다. 앞 12개만.
    const idList = selectedPolicies.map(p =>
      `${(p.type || 'firewall') === 'proxy' ? 'proxy' : 'fw'} ${p.policy_id}`);
    const ids = idList.length > 12
      ? apoT('{shown} and {rest} more',
             { shown: idList.slice(0, 12).join(', '), rest: idList.length - 12 })
      : idList.join(', ');
    /* **이 창은 번역돼야 한다.** 이 제품에서 유일하게 되돌릴 수 없는 동작인데,
       '되돌릴 수 없다'는 문장만 영어로 남아 있었다 — 취소 버튼은 한국어라
       번역이 다 됐다는 잘못된 신호까지 줬다(라운드 26 실측). */
    $('remModalMsg').textContent =
      apoT('Disable {n} policy(ies) on {target}: {ids}.', {
        n: selectedPolicies.length,
        target: `${dev.ip}:${dev.port}` + (vdom ? ` (VDOM ${vdom})` : ''),
        ids })
      + (src ? '\n' + apoT(
          'Candidates came from the configuration currently loaded ({src}).',
          { src }) : '')
      /* 확인창이 **대조할 값**을 줘야 한다. 'hostname 은 신원 증명이 아니다'
         라고 말한 직후 근거로 hostname 만 내밀면, 감사자는 무엇과 무엇을 맞춰
         보라는 것인지 알 수 없다(라운드 30 지적) — 시리얼을 보여준다. */
      /* 시리얼이 없으면 '기억하겠다'는 **지키지 못할 약속**이다 — 고정할 값이
         없어 다음에도 같은 창이 뜬다(라운드 32 실측). 두 경우를 갈라 말한다. */
      /* 시리얼이 없는 이유가 **'못 읽었다'면 '다음에도 없다'는 거짓이다** —
         재시도로 풀릴 일을 영구 제약으로 단정하면 사용자는 매번 수동 확인을
         받아들이고 만다(R75-1). 세 경우를 갈라 말한다. */
      + (_unverifiedTarget ? '\n' + (_unverifiedSerial
          ? apoT('APO has not confirmed this device before. The firewall at {ip} '
                 + 'reports serial {serial} — check that against the device '
                 + 'itself before continuing. APO remembers it from then on.',
                 { ip: dev.ip, serial: _unverifiedSerial })
          : _unverifiedWhy === 'serial_unread'
          ? apoT('APO could not read the serial number from {ip} this time, so '
                 + 'it has nothing unique to check this device by right now. '
                 + 'Test the connection again to retry — if the serial comes '
                 + 'through, APO remembers it. Until then, confirm the address '
                 + 'yourself.',
                 { ip: dev.ip })
          : apoT('The firewall at {ip} does not report a serial number, so APO '
                 + 'has nothing unique to check it by — not now and not next '
                 + 'time. Confirm the address yourself every time you apply.',
                 { ip: dev.ip }))
           : '')
      + ' ' + apoT('This is applied immediately and cannot be undone from this tool.');
    $('remModal').classList.remove('hidden');
    $('remModalConfirm').onclick = () => {
      if (gen !== _candidatesGen) { $('remModal').classList.add('hidden'); return; }
      applyDisable(selectedPolicies, gen);
    };
    $('remModalCancel').onclick  = () => $('remModal').classList.add('hidden');
  });

  async function applyDisable(policies, gen){
    $('remModal').classList.add('hidden');
    const statusEl = $('remLoadStatus');
    if(statusEl) apoSetText(statusEl, 'Applying...');
    try {
      const r = await fetch('/api/remediation/apply', {
        method:'POST', headers:{'Content-Type':'application/json'},
        // 되돌릴 수 없는 쓰기다 — 어느 장비의 목록인지 대고 보낸다.
        // 대조가 불가능한 경우에는 확인창이 그 사실을 보여줬다는 것까지 함께
        // 보낸다. 서버가 그 확인 없이 보내면, 경고를 못 본 경로가 생긴다.
        body: JSON.stringify({policies, device_id: currentDeviceId || undefined,
                              confirm_unverified_target: _unverifiedTarget || undefined})
      });
      const d = await r.json();
      if(d.error){
        /* i18n-dynamic: 서버가 낸 거절 사유 — 쓰는 순간 번역돼 있다. */
        if(statusEl) statusEl.textContent = serverMsg(d);
        return; }
      /* 적용 중에 설정을 새로 열었다면 이 결과는 이미 폐기된 목록의 것이다.
         resetCandidates가 띄운 경고를 덮어쓰지 않는다. */
      const stale = (gen !== undefined && gen !== _candidatesGen);
      // 적용된 목록은 이미 소진됐다. 세대를 올려, 열려 있던 확인창이 같은
      // 선택으로 한 번 더 적용하는 일이 없게 한다.
      _candidatesGen += 1;
      renderApplyResults(d.results||[]);
      /* 방금 끈 정책이 계속 "적용 대기" 목록에 체크된 채 남아 있으면, 무엇이
         반영됐고 무엇이 안 됐는지 화면으로 구분할 수 없고 그대로 한 번 더
         누를 수 있다. 장비 기준으로 다시 읽어 온다.
         loadCandidates가 remLoadStatus를 후보 요약으로 덮으므로 완료 문구는
         그 뒤에 붙인다. */
      const ok = (d.results||[]).filter(x => x.ok).length;
      const fail = (d.results||[]).length - ok;
      /* **후보 목록이 왜 그대로인지 말한다.** 후보는 보관된 설정에서 다시
         계산되는데, 장비에 적용해도 그 설정 파일은 바뀌지 않는다. 이유를 안
         적었더니 방금 4건을 껐는데 같은 4건이 '비활성화 후보'에 남아 '안
         먹었나' 싶게 만들었다(라운드 28 지적). */
      const done = apoT('Apply complete — {ok} succeeded, {fail} failed. See '
        + 'results below.', { ok, fail })
        + (ok ? ' ' + apoT('The candidate list is recalculated from the stored '
            + 'configuration, so these policies stay listed until you collect '
            + 'the device again.') : '');
      /* 재로드 실패가 바깥 catch로 새어 나가면 "Apply failed"로 보고된다 —
         장비에는 이미 반영됐는데. 쓰기 결과와 재로드 결과를 분리한다. */
      if (stale) {
        apoSetText(statusEl,
          '{done} The configuration changed while applying — reload the '
          + 'candidates.', { done });
        return;
      }
      const before = _candidatesGen;
      await loadCandidates();
      if (_candidatesGen !== before + 1) {
        /* loadCandidates가 조기 반환했다(서버 오류 등) — 화면의 목록은 방금 적용
           이전 것 그대로다. "완료"만 적고 두면 이미 끈 정책이 계속 대기로 보인다. */
        _candidates = {to_disable:[], already_disabled:[]};
        ['remActiveHeader','remCriticalSection','remHighSection','remDisabledSection']
          .forEach(id => { const el = $(id); if (el) el.style.display = 'none'; });
        /* 섹션만 숨기면 체크된 행이 DOM에 살아남아 updateApplyBtn이 "선택 있음"
           으로 세고, Apply가 빈 목록 위에서 활성으로 남는다(누르면 "0 policy(ies)"
           확인창이 뜬다). 내용까지 비운다. */
        ['#remCriticalTable tbody','#remHighTable tbody','#remDisabledTable tbody']
          .forEach(sel => { const t = document.querySelector(sel); if (t) t.innerHTML = ''; });
        const chk = $('remCheckAll'); if (chk) chk.checked = false;
        _remSelected.clear();
        updateApplyBtn();
        apoSetText(statusEl,
          '{done} Could not refresh the candidate list — reload it before '
          + 'applying anything else.', { done });
        return;
      }
      /* i18n-dynamic: 적용 결과 건수를 앞에 붙인다 — 뒤 문장은 이미 번역돼 있다. */
      if(statusEl) statusEl.textContent = `${done} ${statusEl.textContent}`;
    } catch(e) {
      apoSetText(statusEl, 'Apply failed: {detail}', { detail: e.message });
    }
  }

  /* 방금 화면에 뜬 결과 — 내보내기가 이 값을 그대로 보낸다. 서버는 이력을
     보관하지 않으므로, 여기 없으면 파일로 만들 방법도 없다. */
  let _lastApplyResults = null;

  function renderApplyResults(results){
    const card = $('remResultCard');
    const body = $('remResultBody');
    _lastApplyResults = results || null;
    if(!card||!body) return;
    card.classList.remove('hidden');
    const ok  = results.filter(r=>r.ok).length;
    const fail= results.filter(r=>!r.ok).length;
    body.innerHTML = `
      <div class="rem-result-summary">
        <span class="rem-result-ok">Success: ${ok}</span>
        <span class="rem-result-fail">Failed: ${fail}</span>
      </div>
      <table class="rem-table">
        <thead><tr><th>Policy ID</th><th>Name</th><th>Result</th><th>Message</th></tr></thead>
        <tbody>${results.map(r=>`
          <tr class="${r.ok?'rem-row-ok':'rem-row-fail'}">
            <td>${esc(r.policy_id)}</td>
            <td>${esc(r.name)}</td>
            <td>${r.ok?'<span class="rem-ok">OK</span>':'<span class="rem-err">FAIL</span>'}</td>
            <td>${esc(r.message)}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
    card.scrollIntoView({behavior:'smooth'});
  }

  // ── Export ────────────────────────────────────────────────────────────────
  $('remExportApplyBtn')?.addEventListener('click', async () => {
    if (!(await licenseGate())) return;
    if (!_lastApplyResults || !_lastApplyResults.length) {
      alert(apoT('There are no apply results to export yet — apply the changes first, then export.'));
      return;
    }
    const r = await fetch('/api/remediation/export/apply-results', {
      method:'POST', headers:{'Content-Type':'application/json'},
      // 적용 시각·장비 시리얼은 **서버가 채운다** — 화면이 보낸 값을 쓰면
      // 시계가 틀린 PC 의 시각이 감사 기록의 시각이 된다.
      body: JSON.stringify({ results: _lastApplyResults,
                             device_id: currentDeviceId || undefined })
    });
    if(!r.ok){ await alertApiError(r, 'Export failed'); return; }
    saveResponseAs(await r.blob(), r, 'apo_apply_results.csv');
  });

  $('remExportCsvBtn')?.addEventListener('click', async () => {
    if (!(await licenseGate())) return;   // 라이선스 확인
    const r = await fetch('/api/remediation/export/csv', {
      method:'POST', headers:{'Content-Type':'application/json'},
      // 파일 이름에 장비명이 찍히므로 어느 장비의 목록인지 대야 한다.
      body: JSON.stringify({to_disable: _candidates.to_disable,
                            already_disabled: _candidates.already_disabled,
                            device_id: currentDeviceId || undefined})
    });
    if(!r.ok){ await alertApiError(r, 'CSV export failed'); return; }
    saveResponseAs(await r.blob(), r, 'remediation.csv');
  });

  $('remExportJsonBtn')?.addEventListener('click', async () => {
    if (!(await licenseGate())) return;   // 라이선스 확인
    const selectedKeys = _selectedKeys();
    if(!selectedKeys.length){ alert(apoT('Select at least one policy to export.')); return; }
    const policies = _filterBySelection(selectedKeys);
    const r = await fetch('/api/remediation/export/postman', {
      method:'POST', headers:{'Content-Type':'application/json'},
      // 내보내는 컬렉션에 장비 주소가 들어간다 — 어느 장비인지 대고 받는다.
      body: JSON.stringify({policies, device_id: currentDeviceId || undefined})
    });
    if(!r.ok){ await alertApiError(r, 'JSON export failed'); return; }
    saveResponseAs(await r.blob(), r, 'remediation.postman_collection.json');
  });
})();


/* ── 구 대역 잔존 참조 (Re-IP 1단계) ──────────────────────────────────
   **엔진 용어를 그대로 보여주면 안 된다.** value/object_name/
   name_reference 는 "엔진이 어떻게 분류했나"이지 "내가 뭘 해야 하나"가
   아니다. 같은 실수로 판정 상태 이름을 두 번 고쳤다(라운드 47, 그리고
   설정 화면의 인프라/관리망 중복). 축을 **행동**으로 잡는다. */
(function () {
  /* **문장은 영어 원문으로 둔다.** 기본 언어가 `en` 이라(i18n.js) 한글
     리터럴을 박으면 영어 사용자가 이 화면에서만 한글 표를 본다. 영어 원문
     자체가 사전 키이고, `apoT()` 가 한국어로 옮긴다 — app.js 의 다른 224개
     호출과 같은 방식이다. 이 화면만 그 통로를 안 지나고 있었다. */
  const ROLE_UI = {
    value: {
      label: 'Change this',
      note: 'This is a real IP setting.',
      skip: 'If you skip it: this setting keeps pointing at a range that no longer exists.',
      rank: 0,
    },
    object_name: {
      label: 'Decide whether to rename',
      note: 'The object name contains an IP. Behaviour is unaffected.',
      skip: 'If you skip it: the name and the real IP disagree, and the next person is misled.',
      rank: 1,
    },
    name_reference: {
      label: 'Only if you rename',
      note: 'A reference to the object name above. If you keep the name, leave this alone.',
      skip: 'If you skip it: renaming alone leaves this policy pointing at an object that no longer exists.',
      rank: 2,
    },
    comment: {
      label: 'Read and decide',
      note: 'A note for humans. Not a target for automatic change.',
      skip: 'If you skip it: a stale note remains (no effect on behaviour).',
      rank: 3,
    },
  };

  const KIND_UI = {
    exact:    'Exactly this range',
    inside:   'An address inside this range',
    supernet: 'A wider range that contains this one',
    overlap:  'Partially overlapping',
  };

  const $ = (id) => document.getElementById(id);
  let lastRefs = [];
  let lastBody = null;      // 언어 전환 시 다시 그리려면 응답을 들고 있어야 한다
  let lastTarget = '';

  /* 화면의 숫자는 **전부** 천단위 구분자를 지난다. `{n}` 치환만
     빠뜨리면 같은 값이 한 화면에서 `1,291` 과 `1291` 두 표기로 나온다. */
  const num = function (v) { return Number(v || 0).toLocaleString(); };

  /* 실패했으면 **이전 성공의 흔적을 남기지 않는다.** */
  function clearResult(key, vars) {
    lastRefs = [];
    lastBody = null;
    /* **`textContent = apoT(...)` 를 쓰면 안 된다.** 실패 상태에서는
       결과 영역이 숨겨져 있어 이 한 줄이 화면의 전부인데, 그렇게 쓰면
       언어를 바꿔도 전환 전 언어로 남는다. `apoSetText` 는 키를
       `data-i18n-key` 로 남겨 전환 시 다시 번역되게 한다(app.js:230 의 규칙). */
    if (key) apoSetText($('iprefStatus'), key, vars);
    else $('iprefStatus').textContent = '';
    $('iprefResult').classList.add('hidden');
    $('iprefWarn').classList.add('hidden');
    /* **숨기는 것과 지우는 것은 다르다.** 이 패널만 app.js 의 규칙("카드를
       숨기기만 하면 이전 장비의 표가 DOM 에 남아 페이지 저장·소스 보기로
       드러난다")을 안 지켰다. 앞 고객의 대역·객체명이 그대로 남았다(3라운드 F4). */
    ['iprefRecon', 'iprefWarn'].forEach((id) => {
      const el = $(id); if (el) el.innerHTML = '';
    });
    const tb = document.querySelector('#iprefTable tbody');
    if (tb) tb.innerHTML = '';
  }

  /* **IP 흐름도 이 장비의 것이다.** 장비를 바꿨는데 앞 고객의 참조 표가
     남아 있으면, 사용자는 그것이 지금 장비의 것이라고 읽는다 — 서버가
     현재 config 로 다시 계획해 주더라도 화면에 남은 남의 IP 목록은 그
     자체로 사고다(라운드 19~21 이 같은 형태를 반복해서 고쳤다). */
  /* **늦게 온 응답은 버린다.** 사전점검 3.3초·조회 4~6초 동안 사용자가
     장비를 바꿀 수 있고, Flask 는 기본이 `threaded=True` 라 장비 열기가 먼저
     끝난다 — 리셋이 먼저 돌고 늦은 응답이 그 위를 다시 칠한다. 입력칸은
     비어 있는데 화면이 **입력한 적 없는 대역**에 대해 단언하게 된다. */
  /* **세대는 "장비가 바뀌었나"를 뜻한다.** 올리는 것은 리셋뿐이고,
     비동기 호출자는 요청 전에 `apoGeneration()` 으로 잡아 응답 후 견주기만
     한다. 호출자가 세대를 올리면(9라운드가 `devRunPreflight` 에서 그랬다)
     같은 장비 안의 다른 요청이 서로를 무효화한다 — 업로드의 사전점검이
     진행 중일 때 재점검을 누르면 앞 것이 조용히 버려지고 "확인하는 중…"
     이 영구히 남았다. */
  let apoGen = 0;
  window.apoBumpGeneration = () => { apoGen += 1; return apoGen; };
  window.apoGeneration = () => apoGen;
  window.apoGenerationIsCurrent = (g) => g === apoGen;

  window.apoIpResetForNewSource = () => {
    window.apoBumpGeneration();
    clearResult('');
    const t = $('iprefTarget');
    if (t) t.value = '';
    window.__apoMigResetForNewSource?.();
  };

  function render() {
    const onlyMust = $('iprefOnlyMust').checked;
    /* **서버와 같은 3키로 정렬한다**(server.py 의 `_RANK` 정렬과 동일):
       ①락아웃 ②역할 ③줄번호.

       `is_admin_access` 키를 빠뜨리면 락아웃 행이 전부 `role==='value'`
       그룹에 흡수돼 줄번호 순으로 흩어진다 — 실측에서 5,000행 표의
       **마지막 행**으로 밀렸다. 절단으로 사라지진 않지만 "가장 먼저 봐야
       할 것"이라는 신호가 죽어, 관리자가 끝까지 스크롤해야 자기가 잠긴다는
       걸 본다. 서버가 굳이 락아웃을 앞으로 올려 보내는 의미가 없어진다. */
    const rows = lastRefs
      .filter((r) => !onlyMust || r.role === 'value')
      .sort((a, b) => (a.is_admin_access ? 0 : 1) - (b.is_admin_access ? 0 : 1)
                      || (ROLE_UI[a.role]?.rank ?? 9) - (ROLE_UI[b.role]?.rank ?? 9)
                      || a.line_no - b.line_no);

    const tb = $('iprefTable').querySelector('tbody');
    tb.innerHTML = '';
    for (const r of rows) {
      const ui = ROLE_UI[r.role] || { label: r.role, note: '', skip: '' };
      const tr = document.createElement('tr');

      const lock = r.is_admin_access
        ? '<div class="inline-status" style="color:#b00">⚠ ' + esc(apoT(
            'Changing this may cut off access to the device — apply it in the same script as the gateway.')) + '</div>'
        : '';

      tr.innerHTML =
        `<td>${r.line_no}</td>` +
        `<td>${esc(r.location)}</td>` +
        `<td>${esc(r.field ? 'set ' + r.field : '—')}</td>` +
        `<td><code>${esc(r.value)}</code></td>` +
        `<td>${esc(KIND_UI[r.match_kind] ? apoT(KIND_UI[r.match_kind]) : r.match_kind)}</td>` +
        `<td><strong>${esc(apoT(ui.label))}</strong>` +
        `<div class="inline-status">${esc(apoT(ui.note))}</div>` +
        `<div class="inline-status">${esc(apoT(ui.skip))}</div>${lock}</td>`;
      tb.appendChild(tr);
    }
    if (!rows.length) {
      const total = lastRefs.length;
      tb.innerHTML = '<tr><td colspan="6" class="inline-status">' + esc(
        !total ? apoT('Nothing in this config references that range.')
               : apoT('No values must change. Untick the box to see the other {n} references.',
                      { n: num(total) })) + '</td></tr>';
    }
  }

  /* **정합성 한 줄.** 관리자가 grep 으로 직접 대조할 수 있는 유일한
     주장이라, 다른 어떤 숫자보다 먼저 보여준다. */
  function renderRecon() {
    const s = lastBody.summary || {};
    $('iprefRecon').innerHTML =
      '<strong>' + esc(lastTarget) + '</strong> — ' + esc(apoT(
        'checked {tok} IP tokens across {lines} lines and found {refs} references, of which {must} must change.',
        { tok: num(s.scanned_tokens), lines: num(s.total_lines),
          refs: num(s.reference_count), must: num(s.must_change) })) +
      (s.admin_access
        ? ' <strong style="color:#b00">' + esc(apoT(
            '{n} of them are used for device access.', { n: num(s.admin_access) })) + '</strong>'
        : '');
  }

  /* **안 닫힌 따옴표·잘린 백업·절단은 반드시 소리를 내야 한다.** 조용히
     넘기면 "참조 0건"이 "이상 없음"으로 읽힌다. */
  function renderWarnings() {
    const s = lastBody.summary || {};
    const warn = $('iprefWarn');
    const alerts = [];
    if (s.unterminated_quote_line) {
      alerts.push('<strong>' + esc(apoT(
        'A quote opened on line {n} is never closed, so everything below it was not read.',
        // **줄번호에는 num() 을 쓰지 않는다.** `4,321` 은 편집기의
        // goto-line 에 그대로 붙여 넣을 수 없는데, 이 배너의 유일한
        // 용도가 '그 줄을 보라'는 것이다. 개수(unclosed_config_blocks)와
        // 좌표는 다르게 다뤄야 한다.
        { n: s.unterminated_quote_line })) + '</strong> ' + esc(apoT(
        'These results are incomplete — check whether the config file is truncated.')));
    }
    if (s.unclosed_config_blocks) {
      alerts.push('<strong>' + esc(apoT(
        '{n} config blocks are left unclosed.', { n: num(s.unclosed_config_blocks) })) +
        '</strong> ' + esc(apoT(
        'The backup looks truncated — some entries may be attributed to the wrong section.')));
    }
    if (lastBody.truncated) {
      const mcAll = s.must_change || 0;
      const mcShown = lastBody.shown_must_change || 0;
      const lost = mcAll > mcShown
        ? ' <strong>' + esc(apoT(
            'Only {shown} of {all} values that must change are visible.',
            { shown: num(mcShown), all: num(mcAll) })) + '</strong>'
        : ' ' + esc(apoT('All values that must change are shown.'));
      alerts.push('<strong>' + esc(apoT(
        'Too many references — showing the top {shown} of {all}.',
        { shown: num(lastBody.shown_count), all: num(s.reference_count) })) +
        '</strong>' + lost + ' ' + esc(apoT('Narrow the range and search again.')));
    }
    if (alerts.length) {
      warn.className = 'sev-guide-note';
      warn.style.color = '#b00';
      warn.innerHTML = alerts.map(function (a) { return '⚠ ' + a; }).join('<br>');
      warn.classList.remove('hidden');
    } else {
      warn.classList.add('hidden');
    }
  }

  /* **셋을 함께 다시 그린다.** 표만 등록하면 언어를 바꿨을 때 표는 바뀌고
     그 위아래 문장은 전환 전 언어로 남는 반쪽 화면이 된다 — 하필 이 화면이
     스스로 가장 중요하다고 적어 둔 두 문장(정합성 줄·경고 배너)이 거기
     있다. 다른 화면들도 그리기 함수를 전부 묶어 등록한다. */
  function renderAll() {
    if (!lastBody) return;
    renderRecon();
    renderWarnings();
    render();
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }

  let inFlight = false;
  $('iprefRunBtn')?.addEventListener('click', async () => {
    /* **진행 중이면 새 요청을 받지 않는다.** 응답이 4~6초라(실측
       real.conf 0.0.0.0/0 = 6.0초) 요청 두 개가 겹치기 쉽고, 그러면 늦게
       온 응답이 먼저 온 것을 덮는다 — 사용자가 받은 오류 안내가 조용히
       사라지고 다른 대상의 결과표가 대신 뜬다. 이 레포는 긴 fetch 6곳에서
       이미 같은 패턴을 쓴다. Enter 키도 이 버튼을 누르므로 함께 막힌다. */
    if (inFlight) return;
    inFlight = true;
    const runBtn = $('iprefRunBtn');
    runBtn.disabled = true;
    try {
      await runLookup();
    } finally {
      inFlight = false;
      runBtn.disabled = false;
    }
  });

  async function runLookup() {
    const target = $('iprefTarget').value.trim();
    apoSetText($('iprefStatus'), 'Searching…');
    let res;
    // **선언은 `try` 밖이다.** `const` 는 블록 스코프라 `catch` 에서
    // 안 보인다 — 거기서 참조하면 가드가 아니라 `ReferenceError`
    // 발생기가 되고, 바로 다음 줄의 '서버에 연결할 수 없습니다'가
    // 영영 안 나온다. 같은 파일의 `runLookup` 이 올바른 선례였다.
    let gen;
    try {
      // 가장 긴 창이다 — 실측 6.81초. 장비가 바뀌면 이 응답은 버린다.
      gen = window.apoGeneration?.();
      res = await fetch('/api/ip-references', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        /* **`device_id` 를 빠뜨리면 게이트가 409 로 막는다.** 이 화면은
           그것 때문에 실제 앱에서 한 번도 성공한 적이 없었다 — 설정을
           올리면 409, 안 올리면 400 이라 성공 경로가 아예 없었다.
           라우트 테스트가 `last_raw_config` 를 직접 심어 게이트를 우회하는
           바람에 안 드러났다. 다른 게이트 라우트 15곳은 전부 이걸 싣는다. */
        body: JSON.stringify({ target, device_id: currentDeviceId || undefined }),
      });
      // 기다리는 사이 장비가 바뀌었으면 이 응답은 앞 장비의 것이다 —
      // 쓰면 입력한 적 없는 대역에 대해 화면이 단언하게 된다.
      if (gen !== undefined && !window.apoGenerationIsCurrent?.(gen)) return;
    } catch (e) {
      /* **이전 결과를 지운다.** 안 지우면 새 대역을 넣고 눌렀는데 앞
         대역의 표·정합성 문장·배너가 그대로 남아, 실패를 성공으로 읽는다.
         바로 아래 !res.ok 경로는 지우고 있었다 — 두 오류 경로가 비대칭이었다. */
      clearResult('Could not reach the server.');
      return;
    }
    /* `catch(() => ({}))` 를 성공 경로에 그대로 두면 안 된다. 200 인데 본문
       파싱이 실패하면 body={} 가 되어 화면이 **현재 대역 이름을 달고**
       "참조 0건"을 단언한다 — 서버에서 두 라운드에 걸쳐 없앤 '무성 0건'이
       화면에서 부활한다. 응답이 1.5 MiB 라 전송 중 끊기는 경로는 현실적이다. */
    let body = null;
    try {
      body = await res.json();
    } catch (e) {
      if (res.ok) {
        clearResult('The server replied but the response could not be read. Try again.');
        return;
      }
      body = {};
    }
    if (!res.ok) {
      clearResult(body.error || 'Lookup failed.');
      return;
    }

    lastRefs = body.references || [];
    lastBody = body;
    lastTarget = target;
    apoSetText($('iprefStatus'), '');
    $('iprefResult').classList.remove('hidden');
    renderAll();

    /* 2단계(매핑 표)에 주소 목록을 넘긴다. **참조가 아니라 주소다** —
       실측으로 `/24` 하나에 참조 1,291건인데 주소는 139개고, 사람이 채울
       칸은 후자다. 서버가 전체 참조에서 묶어 주므로 상한에 잘려도
       목록은 온전하다. */
    if (window.apoMigrationSetHosts) {
      window.apoMigrationSetHosts(body.hosts || [], target, lastRefs);
    }
  }


  /* **1,291행짜리 표를 기본으로 펼치면 안 된다.** 2단계의 주소 표와 내용이
     거의 같아 같은 목록을 두 번 스크롤하게 된다. 특정 주소가 어디 쓰이는지는
     2단계에서 그 행만 펴면 몇 건으로 끝난다. 전체 목록은 필요할 때만 연다.
     (Cisco FMC 도 '영향 없는 변경은 표시하지 않는다'를 명문화해 두었다.) */
  $('iprefToggleBtn')?.addEventListener('click', () => {
    const wrap = $('iprefTableWrap');
    const open = wrap.classList.toggle('hidden') === false;
    $('iprefOnlyMustWrap').classList.toggle('hidden', !open);
    apoSetText($('iprefToggleBtn'),
               open ? 'Hide the full reference list' : 'Show every reference');
    if (open) render();
  });

  $('iprefOnlyMust')?.addEventListener('change', render);
  /* 코드가 그린 것은 언어가 바뀌면 다시 그려야 한다(app.js:236 의 규칙).
     **표 하나만 등록하면 안 된다** — 정합성 문장·경고 배너가 전환 전
     언어로 남아 반쪽 화면이 된다. */
  onLangChange(renderAll);
  $('iprefTarget')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') $('iprefRunBtn').click();
  });
})();


/* ── 설정 마이그레이션 (Re-IP 2단계) ──────────────────────────────────
   **이 화면은 고객 방화벽 설정 파일을 실제로 만들어 낸다.**

   FortiOS 는 참조가 걸린 것을 바꾸지 못하게 막는다(`Return code -23`).
   공식 해법은 "참조를 전부 지우고 → 바꾸고 → 다시 만들기"인데 그 사이
   정책에 구멍이 난다. config 파일을 고치면 값과 참조가 한 번에 바뀐다.

   화면 설계의 핵심: **사람이 채울 칸은 참조 수가 아니라 서로 다른 IP 수다.**
   실측으로 `/24` 하나에 참조 1,291건인데 주소는 139개다. */
(function () {
  const $ = (id) => document.getElementById(id);
  let hosts = [];          // 서버가 준 주소 목록
  /* **입력을 잃어버리면 안 된다.** 감사 실측: 대역을 다시 조회하거나
     언어를 바꾸면 손으로 넣은 값이 전부 사라졌다(`/18` 이면 1,494개).
     대상 입력칸에서 Enter 만 눌러도 조회가 돌아 같은 일이 난다. 값을
     구 IP 별로 들고 있다가 다시 그릴 때 되돌려 넣는다. */
  let toBe = {};           // 구 IP → 사용자가 넣은 신 IP
  let refsByIp = {};       // 주소별 참조(행 펼치기용)
  let applyBody = null;    // 파일 생성 응답(4단계용)
  let ackToken = null;     // 서버가 발급한 확인 토큰(매핑이 바뀌면 무효)
  let searched = false;    // 한 번이라도 대역을 조회했나(빈 목록 문구용)
  let planBody = null;     // 마지막 계획 응답
  let planTarget = '';
  let busy = false;

  /* 장비가 바뀌면 이 블록의 상태도 통째로 버린다 — 매핑표·계획·확인
     토큰은 전부 **그 장비의 것**이다. */
  /* 손으로 넣었는데 아직 파일로 만들지 않은 값의 개수. 장비를 바꾸기
     전에 물을지 판단하는 근거다. */
  window.__apoMigPendingCount = () =>
    // **이미 파일로 만들었으면 잃을 것이 없다.** `applyBody` 를 안 보면
    // 개번을 끝내고 파일을 받은 뒤에도 "아직 파일로 만들지 않은 1,494개"
    // 라는 거짓 경고가 뜬다.
    (applyBody ? 0
      : Object.values(toBe).filter((v) => String(v || '').trim()).length);

  window.__apoMigResetForNewSource = () => {
    toBe = {};
    refsByIp = {};
    applyBody = null;
    ackToken = null;
    searched = false;
    planBody = null;
    planTarget = '';
    /* **카드를 숨기면 안 된다.** `hidden` 을 벗기는 곳은 `devSetMode`
       하나뿐이고 그것이 이 리셋보다 **먼저** 불린다 — 설정 파일을 올리는
       순간(IP 이관의 필수 선행 단계) 3·4단계가 통째로 사라져 조회·매핑·
       미리보기를 해도 아무것도 안 뜬다.
       할 일은 숨기는 것이 아니라 **빈 상태로 되돌리는 것**이고, 그 선례가
       바로 위 `clearMigration` 에 네 줄로 있다. 처음엔 그 절반만 베꼈다. */
    $('migApplyBody')?.classList.add('hidden');
    $('migApplyEmpty')?.classList.remove('hidden');
    $('migPlanBody')?.classList.add('hidden');
    $('migPlanEmpty')?.classList.remove('hidden');
    // 앞 장비의 '끝까지 못 읽음' 확인칸이 새 장비 옆에 남지 않게. 헬퍼
    // (`migShowPartial`)가 아니라 직접 숨긴다 — 이 리셋은 다른 화면의 실행
    // 계약이 단독으로 떼어 내 돌린다.
    $('migPartialWrap')?.classList.add('hidden');
    /* **원천을 비워야 지워진다.** `renderHosts()` 는 `hosts` 를 다시 그릴
       뿐이라, 그 배열을 안 비우면 앞 고객 주소 목록이 그대로 다시 그려진다.
       2단계 표는 "내가 채워야 할 것"의 **유일한 권위**다 — 남의 표가 남으면
       이 장비에만 있는 주소는 칸 자체가 없어 관리자가 못 채우고 옛 대역을
       회수한다. (한 라운드 전에 "실제로 지운다"고 주석만 적었다.) */
    hosts = [];
    // 붙여넣기 상자·경고·상태줄도 앞 장비의 것이다.
    ['migPasteText', 'migPasteBad', 'migPasteStatus', 'migStatus'].forEach(
      (id) => {
        const el = $(id);
        if (!el) return;
        if ('value' in el) el.value = '';
        el.textContent = '';
      });
    // 빈 문구를 초기값으로 되돌린다 — 값을 넣은 적 없는 장비에서 "값이
    // 바뀌었습니다"가 뜨면 안 된다.
    apoSetText($('migPlanEmpty'),
               'Fill in the new values above and preview the changes.');
    const f = $('devFile');
    if (f) f.value = '';    // 앞 대상 파일명이 남아 있으면 안 된다
    renderBlankNotice();
    renderHosts();
  };

  const num = (v) => Number(v || 0).toLocaleString();

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }

  /* 조치를 **엔진 용어가 아니라 사람이 할 일**로 옮긴다. */
  const ACTION_UI = {
    change: { label: 'Changed automatically',
              note: 'A real IP setting — there is only one right answer.' },
    /* **"직접 정하세요"는 사실이 아니었다.** 이 표에는 이름을 넣을 칸이
       없고, 엔진은 이름 안의 IP 를 치환한 값을 그대로 파일에 쓴다
       (`build_plan` 이 `renamed_names` 로 미리 확정한다). 도구가 정해
       놓고 사용자에게 정하라고 말하면, 사용자는 자기가 뭘 해야 하는 줄
       알고 기다리거나 아무 일도 안 일어난 줄 안다(실사용 보고). */
    rename: { label: 'Renamed automatically',
              note: 'The object name contains this address, so the name changes '
                    + 'with it. Want a different name? Change it on the device '
                    + 'after you load the file.' },
    follow: { label: 'Follows the name above',
              note: 'A policy that points at that object. It must move together '
                    + 'or the policy ends up pointing at nothing.' },
    review: { label: 'Read and decide',
              note: 'Not changed automatically.' },
    unmapped: { label: 'Not mapped',
                note: 'Left untouched. Confirm whether it is being retired.' },
    supernet: { label: 'Leave this alone',
                note: 'A wider range that merely contains your target. Changing '
                      + 'it would move every policy that uses it.' },
  };

  /* **근거와 경고는 서버가 코드로 준다.** 서버가 문장을 만들면 화면이 번역할
     수 없어 영어 사용자에게 한국어가 그대로 뜬다(감사에서 3,721건 실측). */
  const REASON_UI = {
    value: 'A real IP setting — {arg} becomes the new value.',
    name_contains_ip: 'The object name contains {arg}.',
    /* 사용자가 3단계에서 직접 지정한 이름. 자동 제안과 구별해야 한다 —
       "도구가 정한 것"과 "사람이 정한 것"은 승인 근거가 다르다. */
    user_renamed: 'You renamed this object.',
    follows_object_name: 'Follows the rename of "{arg}". Leaving it behind would '
                         + 'point this policy at an object that no longer exists.',
    comment_only: 'A note for humans. FortiOS never executes this line.',
    not_in_mapping: '{arg} is not in your mapping table.',
    retired: '{arg} is marked as retired, so this setting is left as it is.',
    supernet_contains: '{arg} is a wider range that contains your target — not '
                       + 'something to renumber.',
    object_not_found: 'No definition for "{arg}" was found in this configuration.',
    name_unchanged: 'Nothing to do here if you keep the object name.',
  };

  const WARN_UI = {
    lockout: 'Changing this may cut off access to the device — apply it in the '
             + 'same script as the gateway.',
    unresolved_name: 'If that name is defined in another VDOM or on another '
                     + 'device, it has to be changed there too.',
    source_changed: 'The source line no longer matches the plan, so it was skipped.',
    mask_misaligned: 'The new address does not line up with the existing netmask.',
    new_ip_collision: 'Another address maps to this same new value.',
    new_ip_in_use: 'This new address is already used elsewhere in the configuration.',
    name_collision: 'The renamed object would clash with another object.',
    supernet_mapped: 'You mapped a wider range. Changing it moves every policy '
                     + 'that uses it.',
      gateway_off_subnet: 'After this change the gateway is no longer inside '
                        + 'the subnet of interface {arg}. The route goes '
                        + 'inactive on reboot and the device loses that path.',
};

  function reasonText(row) {
    const tpl = REASON_UI[row.reason];
    if (!tpl) return row.reason || '';
    return apoT(tpl, { arg: row.reason_arg || '' });
  }

  // ── 주소 목록(2단계) ───────────────────────────────────────────────
  const HOST_LIMIT = 500;

  function renderHosts() {
    const tb = $('migTable').querySelector('tbody');
    tb.innerHTML = '';
    const shown = hosts.slice(0, HOST_LIMIT);
    for (const h of shown) {
      const tr = document.createElement('tr');
      const lock = h.lockout
        ? '<div class="inline-status" style="color:#b00">⚠ ' + esc(apoT(
            'Changing this may cut off access to the device.')) + '</div>'
        : '';
      const where = (h.sections || [])
        .map((s) => s.replace(/^config /, '')).join(', ');
      /* **상위 대역에는 입력칸을 주지 않는다.** 전에는 칸을 내주고
         "반드시 바꿔야 함 1"이라고까지 표시한 뒤, 사용자가 채우면 3단계가
         조용히 무시했다(`to_be: null`). 관리자는 그 객체가 이전됐다고 믿고
         옛 대역을 회수한다. 값을 못 넣게 하는 것이 경고보다 확실하다. */
      const cell = h.supernet
        ? `<td class="inline-status">${esc(apoT(
            'Left alone — this range only contains the addresses you are '
            + 'changing. Changing it would move every policy that uses it.'))}</td>`
        : `<td><input type="text" class="text-input mig-to-be" data-ip="${esc(h.ip)}"`
          + ` value="${esc(toBe[h.ip] || '')}"`
          + ` style="min-width:150px" placeholder="${esc(apoT('leave blank to retire'))}" /></td>`;
      tr.innerHTML =
        `<td><code>${esc(h.ip)}</code>${lock}</td>` + cell +
        `<td><button type="button" class="secondary-btn mig-expand" data-ip="${esc(h.ip)}"` +
        ` style="padding:2px 8px">${num(h.refs)}</button></td>` +
        `<td>${num(h.must_change)}</td>` +
        `<td class="inline-status">${esc(where)}</td>`;
      tb.appendChild(tr);
    }
    /* 방금 조회한 사람에게 "위에서 조회하세요"라고 하면 안 된다. */
    apoSetText($('migEmpty'), searched && !hosts.length
      ? 'Nothing in this configuration uses that range. Try a wider range.'
      : 'Search a range above to list the addresses you need to map.');
    /* **자른 것을 말한다.** 말 안 하면 "다 채웠다"고 믿고 넘어간다. */
    const cap = $('migCapped');
    if (cap) {
      cap.innerHTML = hosts.length > HOST_LIMIT
        ? esc(apoT('Showing the first {shown} of {all} addresses. Use the '
                   + 'download and paste buttons above to fill in the rest — '
                   + 'the file contains every address.',
                   { shown: num(HOST_LIMIT), all: num(hosts.length) }))
        : '';
      cap.classList.toggle('hidden', hosts.length <= HOST_LIMIT);
    }
    $('migEmpty').classList.toggle('hidden', hosts.length > 0);
    $('migBody').classList.toggle('hidden', hosts.length === 0);
  }

  /* 행을 펴면 **그 주소의 참조만** 보여준다. 전체 목록(1,291건)을 볼 이유는
     거의 없고, 궁금한 것은 늘 '이 주소가 어디 쓰이나' 하나다. */
  function toggleDetail(ip, btn) {
    const tr = btn.closest('tr');
    const next = tr.nextElementSibling;
    if (next && next.classList.contains('mig-detail')) { next.remove(); return; }
    const rows = refsByIp[ip] || [];
    const det = document.createElement('tr');
    det.className = 'mig-detail';
    const body = rows.length
      ? rows.map((r) =>
          `<div class="inline-status">L${r.line_no} · ${esc(r.location)}` +
          (r.field ? ' · set ' + esc(r.field) : '') +
          ` · <code>${esc(r.value)}</code></div>`).join('')
      : `<div class="inline-status">${esc(apoT(
          'Detail is not available for this address (the reference list was capped).'))}</div>`;
    det.innerHTML = `<td colspan="5">${body}</td>`;
    tr.after(det);
  }

  document.addEventListener('click', (e) => {
    const b = e.target && e.target.closest && e.target.closest('.mig-expand');
    if (b) toggleDetail(b.dataset.ip, b);
  });

  /** 다른 화면(참조 찾기)이 조회를 끝내면 이걸 불러 준다. */
  window.apoMigrationSetHosts = function (list, target, refs) {
    hosts = list || [];
    /* 대역이 **바뀌면** 이전 입력은 의미가 없다. 같은 대역을 다시 조회한
       것이라면 유지한다 — 실수로 Enter 를 눌러도 139개가 안 날아간다. */
    if ((target || '') !== planTarget) toBe = {};
    planTarget = target || '';
    /* 주소별 참조를 미리 묶어 둔다 — 행을 펴면 **그 주소의 것만** 보여준다
       (1,291건이 아니라 7건). 참조는 상한에 잘릴 수 있으므로 없는 주소는
       상세를 못 보여준다고 말한다. */
    refsByIp = {};
    for (const r of refs || []) {
      const ip = String(r.value || '').split(' ')[0].split('/')[0];
      (refsByIp[ip] = refsByIp[ip] || []).push(r);
    }
    planBody = null;
    applyBody = null;
    ackToken = null;
    searched = true;
    /* `migUnmapped` 만 초기화에서 빠져 있었다 — 대역 A 의 "3개가 비었다"가
       대역 B 를 조회한 뒤에도 남았다. 반대로 갓 조회해 139칸이 전부 비었을
       때는 안 떴다. 참이어야 할 때 없고 거짓일 때 있었다. */
    renderBlankNotice();
    $('migApplyBody').classList.add('hidden');
    $('migApplyEmpty').classList.remove('hidden');
    $('migPlanBody').classList.add('hidden');
    $('migPlanEmpty').classList.remove('hidden');
    renderHosts();
  };

  /* **DOM 이 아니라 보관값을 기준으로 삼는다.** 표가 다시 그려지는 사이
     (언어 전환·재조회) DOM 이 잠깐 비는데, 그 순간 전송하면 전부 빈 칸으로
     간다. `toBe` 는 타이핑할 때마다 갱신되므로 화면 상태와 무관하게 옳다. */
  /* 사용자가 고친 객체 이름. **미리보기를 다시 눌러도 살아남아야 한다** —
     계획을 다시 세울 때마다 후보 표를 새로 그리는데, 입력칸에서만 읽으면
     방금 친 이름이 그때 지워진다. 대상 대역이 바뀌면 통째로 버린다(다른
     대역의 객체에 대한 이름을 들고 있을 이유가 없다). */
  let nameEdits = {};
  let nameEditsTarget = null;

  const nameKey = (vdom, name) => (vdom || '') + ' ' + name;

  function collectNameMapping() {
    return Object.values(nameEdits)
      .filter(e => e.new && e.new !== e.old)
      .map(e => ({ vdom: e.vdom, old: e.old, new: e.new }));
  }

  function renderNameCandidates(body) {
    const card = $('migNameCard');
    const tb = $('migNameTable')?.querySelector('tbody');
    if (!card || !tb) return;
    const list = (body && body.candidates) || [];
    tb.textContent = '';
    if (!list.length) { card.classList.add('hidden'); return; }
    card.classList.remove('hidden');
    apoSetText($('migNameCount'), apoT('{n} objects', { n: num(list.length) }));
    list.forEach((c) => {
      const key = nameKey(c.vdom, c.name);
      /* 자동 제안(이름 안의 IP 를 바꾼 결과)을 미리 채운다. 사용자가 고치면
         그게 이긴다 — 서버도 같은 순서로 본다. */
      const cur = nameEdits[key] ? nameEdits[key].new : (c.suggested || '');
      const tr = document.createElement('tr');
      tr.innerHTML =
        `<td><code>${esc(c.name)}</code>${c.vdom
            ? '<div class="inline-status">vdom ' + esc(c.vdom) + '</div>' : ''}</td>` +
        `<td><input type="text" class="sev-user-range-input th-input" ` +
            `data-name-new value="${esc(cur)}" ` +
            `placeholder="${esc(apoT('keep as it is'))}" /></td>` +
        `<td class="inline-status">${esc(c.section || '')}</td>` +
        `<td class="inline-status">${esc(String(c.refs == null ? '' : c.refs))}</td>`;
      const input = tr.querySelector('[data-name-new]');
      input.addEventListener('change', () => {
        nameEdits[key] = { vdom: c.vdom, old: c.name, new: input.value.trim() };
      });
      tb.appendChild(tr);
    });
  }

  async function loadNameCandidates() {
    if (nameEditsTarget !== planTarget) { nameEdits = {}; nameEditsTarget = planTarget; }
    try {
      const { res, data } = await post('/api/ip-migration/rename-candidates',
        { target: planTarget, mapping: collectMapping() });
      if (res.ok && data) renderNameCandidates(data);
    } catch (e) {
      /* 후보를 못 받아도 계획 자체는 유효하다 — 이름 칸만 안 뜬다. */
      $('migNameCard')?.classList.add('hidden');
    }
  }

  function collectMapping() {
    /* **잠근 행은 아예 안 보낸다.** 입력칸만 없애고 매핑표에는 실어 보내면
       서버가 빈 값을 '폐기'로 읽는다. 상위 대역은 1차 루프가 값 판정 전에
       걸러내므로 매핑에서 빼도 미매핑으로 잡히지 않는다. */
    return hosts.filter((h) => !h.supernet)
                .map((h) => ({ old: h.ip, new: (toBe[h.ip] || '').trim() }));
  }

  /* **값이 바뀌면 앞서 본 것·앞서 확인한 것은 전부 무효다.**

     둘 다 실제 우회로였다:
     - 확인 체크박스가 한 번도 초기화되지 않아, 미매핑 3건을 확인하고
       파일을 만든 뒤 값을 고쳐 새 충돌을 만들어도 그 체크가 살아 있어
       **차단 5종 전부가 조용히 통과**했다.
     - 3단계 계획표는 옛 매핑을 보여주는 채로 남는데 파일은 새 매핑으로
       만들어졌다. 관리자가 그 표를 승인 근거로 캡처해 인수인계하면
       **표와 파일이 다르다.**

     서버도 같이 조인다(`ack_token`) — 화면만 고치면 우회된다. */
  function invalidateOnMappingChange() {
    ackToken = null;
    /* **만든 파일도 무효가 된다.** 값이 바뀌었으면 그 파일은 더 이상 지금
       입력을 반영하지 않는다. `if (!planBody) return` **앞**에서 풀어야
       한다 — 계획을 안 본 채 값만 더 넣는 경로가 있기 때문이다.
       여기서 안 풀면 "파일을 만들었으니 잃을 것이 없다"는 판단이 그대로
       남아, 그 뒤에 넣은 값이 **아무 말 없이** 사라진다. 12라운드가 오탐을
       없애다 미탐을 만든 자리다(13라운드 P1). */
    applyBody = null;
    /* **변수만 풀면 패널이 남는다.** 같은 파일의 선례 두 곳
       (`__apoMigResetForNewSource`·`apoMigrationSetHosts`)은 둘 다 접는데
       여기만 안 접어, 값을 고치면 3단계는 "다시 미리보세요"라고 하고
       4단계는 "12,345줄 바꿨고 전부 검증됐다"고 한다 — 두 패널이 반대로
       말한다. 게다가 `renderApply` 는 `if (!applyBody) return` 으로 빠지므로
       언어를 바꿔도 그 패널만 전환 전 언어로 남는다. */
    $('migApplyBody')?.classList.add('hidden');
    $('migApplyEmpty')?.classList.remove('hidden');
    ['migConfirmUnmapped', 'migConfirmCollisions', 'migConfirmPartial']
      .forEach((id) => { const el = $(id); if (el) el.checked = false; });
    $('migPartialWrap')?.classList.add('hidden');   // 계획이 없으면 물을 것도 없다
    if (!planBody) return;
    planBody = null;
    $('migPlanBody')?.classList.add('hidden');
    $('migPlanEmpty')?.classList.remove('hidden');
    apoSetText($('migPlanEmpty'),
      'The values changed. Preview again to see what will change.');
  }

  /* 표에 없는 주소는 **비운 칸(폐기)과 다르다.** 비운 칸은 매핑표에 있고
     신 값만 없는 것이라 서버가 '폐기'로 본다. 화면은 몇 건이 비었는지를
     먼저 보여줘, 사람이 실수로 비워 둔 것을 알아채게 한다. */
  function renderBlankNotice() {
    const blanks = collectMapping().filter((m) => !m.new);
    const el = $('migUnmapped');
    if (!blanks.length) { el.classList.add('hidden'); return; }
    el.className = 'sev-guide-note';
    el.style.color = '#b00';
    el.innerHTML = '⚠ ' + esc(apoT(
      '{n} addresses have no new value. They will be left untouched — '
      + 'make sure that is what you want.', { n: num(blanks.length) }));
    el.classList.remove('hidden');
  }

  // ── 계획(3단계) ────────────────────────────────────────────────────
  function renderPlan() {
    if (!planBody) return;
    const onlyChanged = $('migOnlyChanged').checked;
    /* **손대지 않지만 경고가 붙은 행은 통과시킨다.** 이 필터가 기본
       체크라, `supernet_mapped`·`unresolved_name` 이 붙은 행(`to_be` 가
       null)이 전부 사라져 그 두 경고는 기본 화면에서 볼 방법이 없었다.
       "다른 VDOM 에 정의된 이름은 거기서도 바꿔야 한다"를 못 보면 그
       객체는 이전 후에도 옛 IP 를 가리킨다. */
    const rows = (planBody.rows || []).filter(
      (r) => !onlyChanged || r.to_be || (r.warnings || []).length);
    const tb = $('migPlanTable').querySelector('tbody');
    tb.innerHTML = '';
    for (const r of rows) {
      const ui = ACTION_UI[r.action] || { label: r.action, note: '' };
      const warn = (r.warnings || []).length
        ? '<div class="inline-status" style="color:#b00">⚠ '
          + r.warnings.map((w) => esc(apoT(WARN_UI[w] || w))).join('<br>⚠ ')
          + '</div>'
        : '';
      const tr = document.createElement('tr');
      tr.innerHTML =
        `<td>${r.line_no}</td>` +
        `<td>${esc(r.location)}<div class="inline-status">${esc(
            r.field ? 'set ' + r.field : '')}</div></td>` +
        /* 이름 행은 조각이 아니라 **객체 이름 전체**를 양쪽에 보인다.
           한쪽만 전체로 보이면 대칭이 깨져 더 헷갈린다. */
        `<td><code>${esc(r.as_is_display || r.as_is)}</code></td>` +
        `<td>${r.to_be ? '<code>' + esc(r.to_be_display || r.to_be) + '</code>'
                       : '<span class="inline-status">—</span>'}</td>` +
        `<td><strong>${esc(apoT(ui.label))}</strong></td>` +
        `<td class="inline-status">${esc(reasonText(r))}${warn}</td>`;
      tb.appendChild(tr);
    }
    if (!rows.length) {
      tb.innerHTML = '<tr><td colspan="6" class="inline-status">' +
        esc(apoT('Nothing changes with the values you entered.')) + '</td></tr>';
    }
  }

  function renderPlanRecon() {
    if (!planBody) return;
    const s = planBody.summary || {};
    $('migPlanRecon').innerHTML =
      '<strong>' + esc(planTarget) + '</strong> — ' + esc(apoT(
        '{rows} references, of which {change} change automatically, '
        + '{rename} are object names that change with them, and {follow} policies '
        + 'follow those names.',
        { rows: num(s.rows), change: num((s.by_action || {}).change),
          rename: num((s.by_action || {}).rename),
          follow: num((s.by_action || {}).follow) })) +
      (() => {
        const acc = (s.by_action || {});
        const rest = (s.rows || 0) - (acc.change || 0) - (acc.rename || 0)
                     - (acc.follow || 0);
        return rest > 0
          ? ' ' + esc(apoT('The remaining {n} are left alone (wider ranges, '
                           + 'comments, and addresses you did not map).',
                           { n: num(rest) }))
          : '';
      })() +
      (s.lockouts
        ? ' <strong style="color:#b00">' + esc(apoT(
            '{n} of them are used for device access, and this plan changes '
            + '{c} of those.',
            { n: num(s.lockouts), c: num(s.lockouts_changing) })) + '</strong>'
        : '') +
      /* **두 화면을 이어 준다.** 이름이 바뀌면 Change review 는 객체를
         이름으로 식별하므로 '변경'이 아니라 '삭제 1 + 추가 1' 로 보인다.
         그것을 모르면 같은 작업을 두 화면이 다르게 말하는 것으로 읽혀
         "뭔가 잘못됐다"고 판단하게 된다(실사용 보고). */
      ((s.by_action || {}).rename
        ? '<div class="inline-status" style="margin-top:6px">' + esc(apoT(
            'Renaming an object shows up in Change review as one removed and '
            + 'one added object, not as a change — that view identifies objects '
            + 'by name.')) + '</div>'
        : '');
  }

  function renderPlanWarn() {
    const el = $('migPlanWarn');
    if (!planBody) { el.classList.add('hidden'); return; }
    const s = planBody.summary || {};
    const alerts = [];
    const notes = [];      // 차단이 아닌 것 — 빨간 경고로 쓰면 늑대소년이 된다
    if ((s.unmapped_ips || []).length) {
      alerts.push('<strong>' + esc(apoT(
        '{n} addresses in the old range are not in your mapping table.',
        { n: num(s.unmapped_ips.length) })) + '</strong> ' + esc(apoT(
        'APO cannot tell whether they are being retired or were missed, so it '
        + 'will not build the file until you confirm.')) +
        '<div class="inline-status">' + esc(s.unmapped_ips.slice(0, 12).join(', ')) +
        (s.unmapped_ips.length > 12 ? ' …' : '') + '</div>');
    }
    if (planBody.truncated) {
      alerts.push('<strong>' + esc(apoT(
        'Too many rows — showing the top {shown} of {all}.',
        { shown: num(planBody.shown_count), all: num(s.rows) })) + '</strong>');
    }
    /* **요약에 실려 오는데 화면이 안 읽던 것들.** 미매핑·잘림 둘만 말하고
       나머지는 침묵했다 — 그중 `supernet_mapped` 와 `unresolved_name` 은
       기본 필터에까지 가려 **기본 화면에서 도달 불가능**했다. */
    if ((s.retired_ips || []).length) {
      alerts.push('<strong>' + esc(apoT(
        '{n} addresses are marked for retirement (left blank).',
        { n: num(s.retired_ips.length) })) + '</strong> ' + esc(apoT(
        'Their settings will be left exactly as they are.')));
    }
    if (Object.keys(s.new_ip_collisions || {}).length) {
      alerts.push('<strong>' + esc(apoT(
        '{n} new addresses are each used by more than one old address.',
        { n: num(Object.keys(s.new_ip_collisions).length) })) + '</strong> ' +
        esc(apoT('Two objects would become one.')));
    }
    if ((s.name_collisions || []).length) {
      alerts.push('<strong>' + esc(apoT(
        '{n} renamed objects would end up with a name that already exists.',
        { n: num(s.name_collisions.length) })) + '</strong> ' + esc(apoT(
        'FortiOS treats the second one as an edit of the first, so an object '
        + 'disappears.')) + '<div class="inline-status">' +
        esc(s.name_collisions.slice(0, 6).join(', ')) + '</div>');
    }
    if ((s.new_ips_in_use || []).length) {
      notes.push(esc(apoT(
        '{n} of the new addresses are already used elsewhere in this config.',
        { n: num(s.new_ips_in_use.length) })) + '<div class="inline-status">' +
        esc(s.new_ips_in_use.slice(0, 12).join(', ')) + '</div>');
    }
    if ((s.supernet_ips || []).length) {
      notes.push(esc(apoT(
        '{n} larger ranges contain the addresses you are changing. '
        + 'They are left alone.', { n: num(s.supernet_ips.length) })));
    }
    if (planBody.decode_lost_bytes) {
      alerts.push('<strong>' + esc(apoT(
        '{n} bytes of this backup are not UTF-8 and cannot be read.',
        { n: num(planBody.decode_lost_bytes) })) + '</strong> ' + esc(apoT(
        'They will be missing from the produced file, including on lines APO '
        + 'does not change.')));
    }
    if (s.unterminated_quote_line) {
      alerts.push('<strong>' + esc(apoT(
        'The configuration could not be read past line {line} — a quote is '
        + 'not closed.', { line: num(s.unterminated_quote_line) })) +
        '</strong>');
    }
    if (!alerts.length && !notes.length) {
      el.classList.add('hidden');
      return;
    }
    el.className = 'sev-guide-note';
    el.style.color = alerts.length ? '#b00' : '';
    el.innerHTML = [
      ...alerts.map((a) => '<span style="color:#b00">⚠ ' + a + '</span>'),
      ...notes.map((n) => '<span class="inline-status">· ' + n + '</span>'),
    ].join('<br>');
    el.classList.remove('hidden');
  }

  function renderPlanAll() {
    if (!planBody) return;
    migShowPartial(migBlockingOf(planBody).includes('config_not_fully_read'));
    renderPlanRecon();
    renderPlanWarn();
    renderPlan();
  }

  async function post(path, body) {
    const res = await fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      /* **`device_id` 를 최상위에 실어야 한다.** 빠지면 장비 게이트가
         409 로 막아 화면이 아예 동작하지 않는다(실측 전례가 있다). */
      body: JSON.stringify({ ...body, device_id: currentDeviceId || undefined }),
    });
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    return { res, data };
  }

  /** 파일을 받는 POST. **`post()` 와 같은 본문을 만들되 JSON 파싱을 안 한다.**
   *
   * 이게 없어서 실제로 당했다(2026-09-15): 워크북·CSV 내려받기를 raw `fetch`
   * 로 짜면서 `device_id` 를 빠뜨렸고, 장비 게이트가 409 로 막아 **브라우저에서
   * 워크북이 한 번도 안 내려갔다.** 매번 옛 `.txt` 폴백으로 떨어졌는데, 그
   * `.txt` 가 바로 이 작업이 없애려던 결함(원시값을 결재 문서에 적는 것)이다.
   * 파이썬 테스트와 스모크는 `device_id` 를 명시해 부르기 때문에 못 잡았다.
   * 같은 실수를 이름이 아니라 **구조**로 막는다 — 바이너리도 여기를 지난다.
   */
  async function postFile(path, body) {
    return fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, device_id: currentDeviceId || undefined }),
    });
  }

  // ── 계획 보기 ──────────────────────────────────────────────────────
  $('migPlanBtn')?.addEventListener('click', async () => {
    if (busy) return;
    busy = true;
    const btn = $('migPlanBtn');
    btn.disabled = true;
    apoSetText($('migStatus'), 'Working…');
    // **선언은 `try` 밖이다.** `const` 는 블록 스코프라 `catch` 에서
    // 안 보인다 — 거기서 참조하면 가드가 아니라 `ReferenceError`
    // 발생기가 되고, 바로 다음 줄의 '서버에 연결할 수 없습니다'가
    // 영영 안 나온다. 같은 파일의 `runLookup` 이 올바른 선례였다.
    let gen;
    try {
      gen = window.apoGeneration?.();
      const { res, data } = await post('/api/ip-migration/plan',
        { target: planTarget, mapping: collectMapping(),
          name_mapping: collectNameMapping() });
      // 기다리는 사이 장비가 바뀌었으면 이 응답은 앞 장비의 것이다 —
      // 쓰면 입력한 적 없는 대역에 대해 화면이 단언하게 된다.
      if (gen !== undefined && !window.apoGenerationIsCurrent?.(gen)) return;
      if (!res.ok || !data) {
        apoSetText($('migStatus'), serverMsg(data) || 'Preview failed.');
        planBody = null;
        $('migPlanBody').classList.add('hidden');
        $('migPlanEmpty').classList.remove('hidden');
        return;
      }
      planBody = data;
      /* **미리보기에서 받은 토큰을 들고 있는다.** 없으면 확인을 미리 켜고
         눌러도 첫 클릭이 무조건 409 로 튕기고, 화면은 "아래 확인 칸을
         켜세요"(이미 켜 놓은 것)라고 말한다. */
      ackToken = data.ack_token || null;
      /* 이름 후보는 계획이 선 뒤에 채운다 — 실패한 계획에 이름 칸을 띄우면
         바꿀 수 없는 것을 바꾸라고 하는 셈이다. 계획을 막지 않도록 await
         하지 않는다. */
      loadNameCandidates();
      apoSetText($('migStatus'), '');
      apoSetText($('migBuildStatus'), '');
      $('migPlanEmpty').classList.add('hidden');
      $('migPlanBody').classList.remove('hidden');
      renderPlanAll();
      $('migPlanCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      // 늦은 응답의 **실패**도 앞 장비의 것이다 — 리셋이 방금 비운
      // 화면에 앞 요청의 오류를 찍으면 안 된다.
      if (gen !== undefined && !window.apoGenerationIsCurrent?.(gen)) return;
      apoSetText($('migStatus'), 'Could not reach the server.');
    } finally {
      busy = false;
      btn.disabled = false;
    }
  });


  const BLOCK_UI = {
    unmapped: 'These addresses are in the old range but not in your table: {list}',
    retired: 'These addresses have no new value, so they will be left as they '
             + 'are: {list}',
    new_ip_collision: 'More than one address maps to the same new value: {list}',
    name_collision: 'Renaming would make two objects share a name. FortiOS '
                    + 'merges them and one disappears: {list}',
    config_not_fully_read: 'APO could not read the configuration to the end '
                           + '(a quote opens on line {line} and never closes), '
                           + 'so this plan is incomplete.',
    /* 우리가 손도 안 댄 줄의 내용이 없어진다 — 확인 없이 넘기면 안 된다. */
    encoding_lossy: 'This backup contains {bytes} bytes that are not UTF-8 '
                    + '(often Korean comments saved in another encoding). APO '
                    + 'cannot read them, so they will be missing from the file '
                    + 'it produces — even on lines it does not touch.',
  };

  /* **'끝까지 못 읽었다' 확인칸은 그 사실이 있을 때만 보인다.** 마크업에
     상시로 두었더니 멀쩡한 4,438줄 config 옆에도 붙어 있었고, 그 상태가
     출시 광고(2026-09-22 story.mp4 69~71초)에 그대로 찍혔다 — "파일을
     끝까지 못 읽었는데 만들어도 되나?" 를 고객이 먼저 묻게 된다. 장비
     이관의 `devShowPartial` 과 같은 구조로, 서버의 `blocking` 목록이
     `config_not_fully_read` 를 담을 때만 켠다. `.hidden` 클래스를 쓴다. */
  function migShowPartial(on) {
    $('migPartialWrap')?.classList.toggle('hidden', !on);
  }
  function migBlockingOf(data) {
    /* 미리보기는 `summary.blocking`, 적용 409 는 최상위 `blocking` 이다. */
    return (data && (data.blocking || (data.summary && data.summary.blocking))) || [];
  }

  /* 차단은 **거절이 아니라 질문**이다. 무엇을, 왜 물어보는지 보이면
     사용자가 답할 수 있다. */
  function renderBlocked(data) {
    migShowPartial(migBlockingOf(data).includes('config_not_fully_read'));
    const parts = [];
    for (const b of data.blocking || []) {
      const tpl = BLOCK_UI[b];
      if (!tpl) { parts.push(esc(b)); continue; }
      let list = '';
      if (b === 'unmapped') list = (data.unmapped_ips || []).slice(0, 12).join(', ');
      else if (b === 'retired') list = (data.retired_ips || []).slice(0, 12).join(', ');
      else if (b === 'new_ip_collision') {
        list = Object.entries(data.new_ip_collisions || {})
          .slice(0, 6).map(([k, v]) => `${k} ← ${v.join(', ')}`).join(' · ');
      } else if (b === 'name_collision') {
        list = (data.name_collisions || []).slice(0, 6).join(', ');
      }
      parts.push(esc(apoT(tpl, {
        list: list,
        line: num(data.unterminated_quote_line),
        bytes: num(data.decode_lost_bytes),
      })));
    }
    const el = $('migPlanWarn');
    el.className = 'sev-guide-note';
    el.style.color = '#b00';
    el.innerHTML = '⚠ ' + parts.join('<br>⚠ ') + '<br>' +
      esc(apoT('Tick the confirmation boxes below if these are what you intended.'));
    el.classList.remove('hidden');
    $('migPlanBody').classList.remove('hidden');
    $('migPlanEmpty').classList.add('hidden');
    apoSetText($('migStatus'), '');
    /* **버튼 옆 상태를 여기서 지운다.** 호출부에서 지우게 두면 경로가
       하나 늘 때마다 샌다 — 실사용 첫 보고가 그것이었다: 확인이 필요해
       409 가 왔는데 "만드는 중…" 이 그대로 남아, 사용자는 **버튼이 멈춘
       것**으로 봤다. 빈 문자열이 아니라 **무엇을 해야 하는지** 적는다. */
    apoSetText($('migBuildStatus'),
               'Not built yet — answer the questions above, then press the '
               + 'button again.');
    $('migPlanCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ── 파일 만들기 ────────────────────────────────────────────────────
  $('migBuildBtn')?.addEventListener('click', async () => {
    if (busy) return;
    busy = true;
    const btn = $('migBuildBtn');
    btn.disabled = true;
    /* **3단계 버튼의 상태를 2단계 칸에 찍고 있었다.** 실측 20.1초짜리
       작업인데 진행 표시도 오류도 스크롤 밖에 뜬다. 그리고 `fetch` 가
       끊기면 아무 말도 없이 'Building…' 이 영원히 남았다 — 이 IIFE 안에
       `catch` 가 JSON 파싱용 하나뿐이었다. */
    apoSetText($('migBuildStatus'), 'Building…');
    // **선언은 `try` 밖이다.** `const` 는 블록 스코프라 `catch` 에서
    // 안 보인다 — 거기서 참조하면 가드가 아니라 `ReferenceError`
    // 발생기가 되고, 바로 다음 줄의 '서버에 연결할 수 없습니다'가
    // 영영 안 나온다. 같은 파일의 `runLookup` 이 올바른 선례였다.
    let gen;
    try {
      gen = window.apoGeneration?.();
      const { res, data } = await post('/api/ip-migration/apply', {
        target: planTarget, mapping: collectMapping(),
        /* 3단계에서 고친 이름. **계획을 세울 때와 같은 값을 보내야 한다** —
           다르면 서버가 토큰 불일치로 확인을 다시 묻는다(그게 옳다). */
        name_mapping: collectNameMapping(),
        confirm_unmapped: $('migConfirmUnmapped').checked,
        confirm_collisions: $('migConfirmCollisions').checked,
        confirm_partial_read: $('migConfirmPartial').checked,
        /* 확인은 **그때 그 매핑에만** 유효하다. 서버가 발급한 토큰을 그대로
           되보내고, 값이 바뀌었으면 서버가 토큰 불일치로 다시 묻는다. */
        ack_token: ackToken,
      });
      // 기다리는 사이 장비가 바뀌었으면 이 응답은 앞 장비의 것이다 —
      // 쓰면 입력한 적 없는 대역에 대해 화면이 단언하게 된다.
      if (gen !== undefined && !window.apoGenerationIsCurrent?.(gen)) return;
      if (res.status === 409 && data && data.needs_confirmation) {
        /* **무엇을 확인해야 하는지 말한다.** "확인하세요" 만으로는 139행 중
           어디를 봐야 하는지 알 수 없다. 종류와 대상을 함께 보여준다. */
        ackToken = data.ack_token || null;
        renderBlocked(data);
        return;   // renderBlocked 가 버튼 옆 상태까지 책임진다
      }
      if (!res.ok || !data) {
        /* 서버가 `error_key` 를 보내는데 아무도 안 읽어서, 사용자는
           `Invalid mapping: row 1 (10.20.40.6): Expected 4 octets in '11.11.40'`
           같은 날것을 본다 — 사전 키가 아니라 한국어 모드에서도 영어다. */
        apoSetText($('migBuildStatus'),
                   serverMsg(data) || 'Build failed.');
        return;
      }
      applyBody = data;
      /* **성공했는데 차단 경고가 그대로 남아 있었다.** `renderBlocked` 와
         `renderPlanWarn` 이 같은 요소를 쓰는데 성공 경로가 그것을 손대지
         않았다. 4단계가 열린 뒤에도 3단계는 "확인 칸을 켜세요"라고 말한다. */
      renderPlanWarn();
      downloadMigration(data);
      apoSetText($('migStatus'), '');
      apoSetText($('migBuildStatus'), '');
      renderApply();
      $('migApplyCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      // 늦은 응답의 **실패**도 앞 장비의 것이다 — 리셋이 방금 비운
      // 화면에 앞 요청의 오류를 찍으면 안 된다.
      if (gen !== undefined && !window.apoGenerationIsCurrent?.(gen)) return;
      apoSetText($('migBuildStatus'), 'Could not reach the server.');
    } finally {
      busy = false;
      btn.disabled = false;
    }
  });

  /* **파일만 주고 끝내면 관리자가 그것을 장비에 넣다가 사고가 난다.**
     복원은 기본이 재부팅이고, FortiOS 는 편집된 config 의 일부를 조용히
     버리면서 복원 성공을 표시한다. 무엇을 해야 하는지 화면이 말해야 한다. */
  function renderApply() {
    if (!applyBody) return;
    const v = applyBody.verification || {};

    /* **화면과 메모 파일이 같은 말을 해야 한다.** 감사 실측: 화면은 "남아
       있는 옛 값 없음", 같은 다운로드의 메모는 "old values left behind: 22".
       `clean` 하나로 문장을 고르면 그렇게 된다 — 숫자를 그대로 말한다. */
    const bad = [];
    if ((v.unexpected_values || []).length) {
      bad.push(apoT('{n} old values are still there.',
                    { n: num(v.unexpected_values.length) }));
    }
    if (v.dangling_count) {
      bad.push(apoT('{n} policies point at an object name that does not exist.',
                    { n: num(v.dangling_count) }));
    }
    if (v.not_applied_count) {
      bad.push(apoT('{n} planned changes were not applied.',
                    { n: num(v.not_applied_count) }));
    }
    if (v.duplicate_count) {
      /* FortiOS 는 두 번째 `edit "X"` 를 첫 객체 **편집**으로 처리한다 —
         객체 하나가 통째로 사라지고 그것을 쓰던 정책이 조용히 다른 대상에
         붙는다. 전에는 이 상태로 "전부 정상" 초록불이 떴다. */
      bad.push(apoT('{n} object names end up defined more than once '
                    + '({m} extra definitions) — FortiOS keeps only the first '
                    + 'of each.',
                    { n: num(v.duplicate_count),
                      m: num(v.duplicate_extra) }));
    }
    if (v.config_not_fully_read) {
      bad.push(apoT('The configuration could not be read to the end.'));
    }
    $('migApplySummary').innerHTML =
      esc(apoT('{changed} of {total} lines changed.',
               { changed: num(applyBody.changed_lines),
                 total: num(applyBody.total_lines) })) + ' ' +
      (bad.length
        ? '<strong style="color:#b00">' + bad.map(esc).join(' ') + ' '
          + esc(apoT('Check the plan before using this file.')) + '</strong>'
        : esc(apoT('The produced file was re-read: no old value left behind, '
                   + 'no broken object reference, every planned change applied.')));

    /* 순서가 중요하다:
       - 업로드한 백업이 장비의 **현재** 상태라는 보장이 없다. 먼저 새로 받는다.
       - `diagnose debug config-error-log` 는 **부팅 시 config 를 파싱하면서**
         채워진다. 재부팅 **전에** 읽으면 "비어 있음 = 성공"으로 오독하고,
         이전 이벤트 로그가 남아 있으면 거짓 실패가 난다.
       - HA 쌍이면 **두 유닛이 동시에 재부팅한다**(실 고객이 a-p 쌍이다). */
    /* **되돌리기도 접속이 있어야 가능하다.** 락아웃 경고는 3단계 표의 행
       하나로만 있었고, 그 문구("같은 스크립트에 넣어라")는 CLI 로 한 줄씩
       넣는 모델의 조언이라 "파일 통째 복원 + 재부팅"인 이 작업에서는 할 수
       있는 행동이 아니다. 원격에서 SSH 로 들어와 있는 관리자가 복원을 걸면
       장비는 새 IP 로 올라오는데, 라우팅이든 앞단 NAT 든 하나만 어긋나면
       되돌릴 손이 없다 — 콘솔은 IDC 에 있고 관리자는 집이다. */
    const lockouts = (applyBody.summary || {}).lockouts_changing || 0;
    const steps = [
      ...(lockouts ? [apoT(
        'This plan changes {n} settings that the device is reached through. '
        + 'Before you restore, make sure you have a console or another path '
        + 'that does not go through them — rolling back also needs access.',
        { n: num(lockouts) })] : []),
      apoT('Take a fresh backup from the device now — the file you uploaded may '
           + 'no longer match what is running. That fresh backup is your rollback.'),
      apoT('Clear the parser log first so you are not reading an old one:')
        + ' <code>diagnose debug config-error-log clear</code>',
      apoT('Restore the produced file during a maintenance window. If this device '
           + 'is in an HA cluster, both units reboot together — the passive unit '
           + 'does not cover for you.'),
      apoT('After the device is back up, run this and confirm it is empty:')
        + ' <code>' + esc(applyBody.post_apply_check || '') + '</code>'
        // 이 명령은 **로컬 유닛만** 보여준다. HA 면 반대쪽이 조용히 깨진다.
        + ' — ' + apoT('in an HA cluster run it on both units, then check '
                       + 'the cluster is back with')
        + ' <code>get system ha status</code>',
      apoT('Spot-check a few of the changed lines on the device itself.'),
      /* **번호로 가리키면 안 된다.** 위에 락아웃 단계가 붙으면 백업이
         2번이 되어, "step 1 에서 받은 백업"이 콘솔 확보 안내를 가리킨다. */
      apoT('To undo, restore the backup you took before starting. Note that this '
           + 'also reverts anything else changed since then. The notes file lists '
           + 'new → old for both addresses and object names.'),
    ];
    $('migApplySteps').innerHTML = steps.map((t) => `<li>${t}</li>`).join('');
    $('migApplyEmpty').classList.add('hidden');
    $('migApplyBody').classList.remove('hidden');
  }

  /* 산출물 두 개를 내려준다 — 바뀐 config 와, 되돌리기·검증·적용후 확인이
     담긴 메모. 메모가 없으면 관리자는 무엇을 확인해야 하는지 모른다. */
  function downloadMigration(data) {
    const stamp = (data.target || 'migration').replace(/[^\w.-]/g, '_');
    /* **파일이 자기 상태를 말해야 한다.** 검증에 실패해도 파일명·내용
       어디에도 표시가 없어서, 3주 뒤 Downloads 폴더에서 이것만 다시 찾은
       관리자는 화면의 빨간 글씨를 볼 방법이 없다. config 본문은 건드리지
       않는다 — `#config-version` 앞에 줄을 넣으면 복원이 막힐 수 있고,
       바이트 보존 약속도 깨진다. 파일명과 메모로 말한다. */
    const clean = (data.verification || {}).clean !== false;
    save(data.config, `migrated_${stamp}${clean ? '' : '_UNVERIFIED'}`,
         '.conf', 'text/plain');

    const v = data.verification || {};
    const rv = data.reverse_mapping || {};
    const s2 = data.summary || {};
    const lines = [
      ...(clean ? [] : [
        '#####################################################################',
        '# ' + apoT('WARNING: this file did not pass APO self-check.'),
        '# ' + apoT('Read the self-check section below before restoring it.'),
        '#####################################################################',
        '']),
      '# APO — ' + apoT('configuration migration record'),
      '# ' + apoT('old range') + ': ' + data.target,
      '# ' + apoT('changed lines') + ': ' + data.changed_lines + ' / ' + data.total_lines,
      '',
      '## ' + apoT('Check this after you restore the file'),
      '#  diagnose debug config-error-log clear   ' + apoT('(before restoring)'),
      '#  ' + (data.post_apply_check || '') + '   ' + apoT('(after it comes back up)'),
      '#  ' + apoT('FortiOS silently drops parts of an edited configuration while '
                   + 'still reporting a successful restore. This command is the only '
                   + 'way to see what was dropped.'),
      '',
      '## ' + apoT('Self-check of the produced file'),
      // **라벨이 실제로 세는 것과 같아야 한다.** 아래 두 줄은 다른 것을
      // 센다: 위는 대상 대역에 남은 값 전부(폐기·대역 내 재배치·상위
      // 대역이라 남아 **있어도 정상**), 아래가 설명되지 않는 잔존이다.
      // 전에는 위를 'old values left behind' 로 찍어서, 화면이 "남은 옛 값
      // 없음"이라 말하는 같은 다운로드의 메모에 "308" 이 적혔다.
      '#  ' + apoT('old values still in the target range (may be normal)')
        + ': ' + (v.remaining_values || 0),
      '#  ' + apoT('unexpected old values') + ': '
        + ((v.unexpected_values || []).length),
      '#  ' + apoT('broken object references') + ': ' + (v.dangling_count || 0),
      '#  ' + apoT('object names defined more than once') + ': '
        + (v.duplicate_count || 0)
        + ' (' + apoT('extra definitions') + ': '
        + (v.duplicate_extra || 0) + ')',
      // **어느 줄인지 적는다.** 응답에는 있는데 아무도 안 읽고 있었다 —
      // 관리자가 실제로 보는 곳에 도달하지 못한 정보는 없는 것과 같다.
      ...((v.duplicate_definitions || []).map(
        (d) => '#    ' + d.name + '  ' + apoT('lines') + ' '
               + (d.line_numbers || [d.line_no]).join(', '))),
      '#  ' + apoT('planned changes not applied') + ': ' + (v.not_applied_count || 0),
      '',
      '## ' + apoT('To undo: object names that were renamed (new → old)'),
      // IP 는 되돌아가도 이름은 어디에도 옛 이름이 안 적혀 있었다.
      ...((s2.renamed_names || []).length
        ? (s2.renamed_names || []).map(
            (r) => '#  ' + r.new + '  →  ' + r.old
                   + (r.vdom ? '   [vdom ' + r.vdom + ']' : ''))
        : ['#  ' + apoT('none')]),
      '',
      '## ' + apoT('Addresses left as they are (retired)'),
      ...(rv.retired || []).map((ip) => '#  ' + ip),
      '',
      '## ' + apoT('Wider ranges deliberately untouched'),
      ...(s2.supernet_ips || []).map((ip) => '#  ' + ip),
      '',
      '## ' + apoT('To undo: new -> old'),
      ...Object.entries(rv.pairs || {}).map(([k, o]) => `${k}\t${o}`),
      ...Object.entries(rv.collisions || {}).map(
        ([k, olds]) => `${k}\t${olds.join(' | ')}\t# ` + apoT('ambiguous — more than one source')),
      '',
      /* **변경 계획을 파일로 남긴다.** 승인·감사·인수인계에 쓰인다
         (FortiManager 도 Install Preview 를 텍스트로 내려준다). 서버가
         응답에 실어 보내는데(실측 1.9 MB) 화면이 한 글자도 안 쓰고 있었다
         — 문서화된 목적이 미구현이었고, 화면에만 있으면 새로고침 한 번에
         사라진다. */
      '## ' + apoT('What changes, line by line'),
      '# line\tlocation\taction\tas-is\tto-be\twhy\twarnings',
      ...(data.rows || []).map((r) => [
        r.line_no, r.location || '', r.action, r.as_is || '',
        (r.to_be === null || r.to_be === undefined) ? '' : r.to_be,
        r.reason + (r.reason_arg ? ' (' + r.reason_arg + ')' : ''),
        (r.warnings || []).join(' '),
      ].join('\t')),
      ...(data.rows_truncated
        ? ['# ' + apoT('Only the first {shown} of {all} rows are listed.',
                       { shown: num((data.rows || []).length),
                         all: num(s2.rows || 0) })]
        : []),
    ];
    /* **변경내역은 서버가 만든 워크북으로 받는다.** 예전에는 위 `lines` 를
       `.txt` 로 저장했는데, 그 텍스트는 화면 표가 쓰는 표시값이 아니라 원시
       `as_is`/`to_be` 를 써서 **객체 이름의 조각과 지워진 넷마스크**를 적었다
       (2026-09-08 실사용 보고 — 승인자가 존재하지 않는 이름을 결재했다).
       그리고 정렬도 필터도 안 되는 평문이라 감사에 쓰기 나빴다.
       `lines` 는 남겨 둔다 — 워크북을 못 받았을 때의 대비책이다. */
    saveChangesWorkbook(stamp, lines);
  }

  /** 변경내역 워크북을 서버에서 받아 저장한다. 실패하면 옛 `.txt` 로 내려간다. */
  async function saveChangesWorkbook(stamp, fallbackLines) {
    /* **화면이 든 표를 되보내지 않는다.** 서버가 같은 입력으로 다시 계산해야
       파일이 APO 의 판단을 증명한다(`/api/config/diff/export` 와 같은 원칙).
       그래서 보내는 것은 사용자가 넣은 매핑과 대상뿐이다. */
    try {
      const res = await postFile('/api/ip-migration/export/changes',
        { target: planTarget, mapping: collectMapping(),
          name_mapping: collectNameMapping() });
      if (!res.ok) throw new Error('export failed: ' + res.status);
      /* **이름은 서버가 정한 것을 쓴다.** 여기서 지으면 장비 칩·zip 엔트리와
         규칙이 갈려, 장비 3대를 도는 컨설턴트의 폴더에서 (1),(2) 로 쌓인다
         (`test_every_download_uses_the_name_the_server_sent` 가 잡았다). */
      saveResponseAs(await res.blob(), res,
                     `apo_migration_changes_${stamp}.xlsx`);
      announceDownloads('.xlsx');
    } catch (e) {
      /* **조용히 포기하지 않는다.** 변경내역 없이 config 만 받으면, 무엇이
         바뀌었는지 증명할 수 없는 파일 하나만 남는다. 옛 형식이라도 준다. */
      save(fallbackLines.join('\n') + '\n', `migration_notes_${stamp}`,
           '.txt', 'text/plain');
      announceDownloads('.txt');
    }
  }

  /* 변경내역만 CSV 로 한 장 더 — 다른 시스템에 넣거나 스크립트로 대사할 때.
     **워크북을 대체하지 않는다**(감사 제출은 절이 넷이라 xlsx 여야 한다).
     한글이 깨지지 않게 BOM 을 붙이는 것은 서버가 한다. */
  $('migCsvBtn')?.addEventListener('click', async () => {
    const btn = $('migCsvBtn');
    btn.disabled = true;
    try {
      const res = await postFile('/api/ip-migration/export/changes',
        { target: planTarget, mapping: collectMapping(),
          name_mapping: collectNameMapping(), format: 'csv' });
      if (!res.ok) throw new Error('csv export failed: ' + res.status);
      saveResponseAs(await res.blob(), res, 'apo_migration_changes.csv');
      apoSetText($('migBuildStatus'), '');
    } catch (e) {
      /* 조용히 실패하면 사용자는 버튼이 죽은 줄 안다. */
      apoSetText($('migBuildStatus'),
                 apoT('Could not build the CSV. The workbook (.xlsx) you '
                      + 'already received has the same table.'));
    } finally {
      btn.disabled = false;
    }
  });

  /** **받았다고 말한다.** 여태 아무 말 없이 떨어져서, 만든 사람조차 산출물이
      없는 줄 알았다(2026-09-15). 어디에 무엇이 생겼는지 화면에 남긴다. */
  function announceDownloads(ext) {
    apoSetText($('migBuildStatus'), apoT(
      'Downloaded 2 files: the configuration (.conf) and the change record ({ext}).',
      { ext: ext }));
  }

  function save(text, base, ext, mime) {
    const blob = new Blob([text], { type: mime + ';charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.setAttribute('download', base + deviceStamp() + ext);
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }

  // ── 붙여넣기 ───────────────────────────────────────────────────────
  $('migPasteToggle')?.addEventListener('click', () => {
    const box = $('migPasteBox');
    const open = box.classList.toggle('hidden') === false;
    apoSetText($('migPasteToggle'), open ? 'Hide the paste box' : 'Paste a list');
    if (open) $('migPasteText').focus();
  });

  /* **정규화해서 맞춘다.** 화면의 주소 키는 서버가 프리픽스를 떼고 만드는데
     이 고객의 객체 이름은 `208.97.24.201/32_...` 형태다 — config 에서 뽑은
     목록을 그대로 붙여넣으면 하나도 안 맞는다(감사 실측 0/20). */
  function normIp(t) {
    const m = String(t || '').trim().match(/(\d{1,3}(?:\.\d{1,3}){3})/);
    return m ? m[1] : '';
  }

  /* **오타를 조용히 다른 값으로 바꾸면 안 된다.** `normIp` 는 IPv4 조각만
     뽑아내므로 잘못 적은 것을 말없이 고친다 — 실측:
       `11.11.40`     → ''            (빈 칸 = **폐기**로 둔갑)
       `11,11,40,6`   → ''            (폐기로 둔갑)
       `abc`          → ''            (폐기로 둔갑)
       `11.11.40.6.7` → `11.11.40.6`  (**유효한 다른 주소**로 조용히 절단)
     앞의 셋은 나중에 폐기 차단으로 잡히지만 그때 화면이 하는 말은 "새 값이
     없어 그대로 둔다" 라, 값을 넣었다고 믿는 사용자와 어긋난다. 넷째는
     어디에서도 안 걸린다. 139개를 넣는 유일한 경로가 이 파서다.
     **읽은 것과 적힌 것이 같을 때만 값으로 인정한다.** */
  /* **옛 주소 칸은 config 에서 뽑은 이름이 그대로 올 수 있다** —
     `208.97.24.201/32_SRV` 같은 형태다(주석에 적힌 실측 0/20 사건). 그래서
     IP 하나만 들어 있으면 그것을 쓴다. **둘 이상이면 되묻는다** — 어느
     것이 대상인지 알 수 없고, 화살표 표기(`10.0.0.5->11.11.11.5`)가
     여기 걸린다(그것을 '새 값 없음 = 폐기'로 읽으면 정반대 뜻이 된다). */
  /* 화면에 찍는 원문은 자른다. 상한이 한쪽에만 있어서, 3,000자짜리 칸을
     붙여넣으면 그대로 화면에 들어갔다. 비밀번호·개인정보가 섞인 줄을
     그대로 노출할 이유가 없다. */
  function cut(t) {
    /* **안 보이는 문자는 보이게 적는다.** 이 가드가 존재하는 이유가 바로
       그 문자들인데, 거절 문구에 그대로 넣으면 화면에 아무것도 안 그려져
       사용자는 **멀쩡한 주소가 거절된 것**으로 본다(`10.0.0.80 → ?`).
       무엇을 고쳐야 할지 알 방법이 없다. 코드포인트로 드러낸다. */
    const x = String(t || '').replace(
      /[\p{C}\p{M}\u115f\u1160\u3164\uffa0]/gu,
      (c) => '<U+' + c.codePointAt(0).toString(16).toUpperCase()
                      .padStart(4, '0') + '>');
    return x.length > 60 ? x.slice(0, 60) + '…' : x;
  }

  function readOld(t) {
    /* **앵커가 없으면 조용히 잘라낸다.** 앞뒤에 숫자나 점이 붙어 있으면
       그것은 IP 가 아니다 — `10.0.0.5.7` 에서 `10.0.0.5` 를 뽑으면 사용자가
       고른 호스트와 다른 객체를 개번한다. 객체 이름(`208.97.24.201/32_SRV`,
       `host-10.0.0.5`)은 뒤에 `/`·`-`·`_` 가 오므로 그대로 통과한다. */
    const raw = String(t || '');
    /* **IP 바로 양옆 문자를 본다 — 목록이 아니라 범주로.**

       세 라운드 연속 같은 사고가 났다(공백류 → 제로폭 → 결합표시·서식·
       다른 숫자 체계). 매번 **같은 885개 실물 호스트**가 같은 설정 안의
       다른 실물 호스트로 조용히 재타겟됐다. 원인은 방어가 "위험한 문자
       목록"이라 **경계 바로 옆이 샌다**는 것이다 — U+2060 까지 막고
       U+2061 이 뚫렸고, VS-16 만 막아 VS-1~15 가 뚫렸다. 전수 훑기에서
       조용히 통과하는 안 보이는 코드포인트가 1,142개였다.

       새 값 칸이 안 뚫린 이유는 거기가 목록이 아니라 `raw === ip` **등가
       검사**이기 때문이다(65,536개 중 65,527개 차단). 여기도 구조로 본다:
       IP 에 **숫자(어느 문자 체계든)·제어·서식·결합표시·채움문자**가 붙어
       있으면 그 IP 는 잘린 것이다. 이름 구분자(`/ - _ 공백 ( ) …`)는
       그대로 통과한다 — `208.97.24.201/32_SRV`, `host-10.0.0.5`. */
    const CUT = /[\p{Nd}\p{C}\p{M}\u115f\u1160\u3164\uffa0]/u;
    const FIND = /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/g;
    /* **문자 하나를 코드 단위 하나로 세면 안 된다.** `raw[i]` 는 UTF-16
       코드 단위라, BMP 밖 문자(한자 확장 B — 한국 인명에 실제로 쓰인다,
       이모지)가 짝 없는 서로게이트로 잘려 `\p{C}` 에 걸린다. 그러면
       이름 구분자는 통과시킨다는 이 검사의 전제가 깨진다(실측: BMP 밖
       131,072개 중 89,015개가 이 인공물로만 거절됐다). */
    const at = (i, back) => {
      if (back ? i <= 0 : i >= raw.length) return '';
      const c = raw.charCodeAt(back ? i - 1 : i);
      if (back && c >= 0xdc00 && c <= 0xdfff && i >= 2) return raw.slice(i - 2, i);
      if (!back && c >= 0xd800 && c <= 0xdbff) return raw.slice(i, i + 2);
      return back ? raw[i - 1] : raw[i];
    };
    let m;
    while ((m = FIND.exec(raw)) !== null) {
      const before = at(m.index, true);
      const after = at(m.index + m[0].length, false);
      if ((before && CUT.test(before)) || (after && CUT.test(after))) {
        return { ok: false, ip: '', many: true };
      }
    }
    const ips = raw.match(
      /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/g) || [];
    /* **IP 뒤에 공백, 그다음이 숫자면 잘린 것이다.** 숫자 안에 공백류가
       한 글자 끼면 IP 가 짧아지는데 그래도 IP 는 하나라 "둘" 검사에 안
       걸린다 — 같은 설정 안의 **다른 실물 호스트**를 조용히 개번한다. */
    /* **양쪽을 본다.** 오른쪽만 보면 앞이 잘린 경우(`1 10.0.0.5`)가 남은
       꼬리만으로 온전한 4옥텟이라 조용히 통과한다. */
    if (/(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}\s+\d/.test(raw)
        || /\d\s+(?![\d.])?\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/.test(raw)) {
      return { ok: false, ip: '', many: true };
    }
    // 옥텟 범위·앞자리 0 은 옛 칸에서도 본다. 없으면 "이 범위에 없다"는
    // 엉뚱한 안내를 받는다 — 틀린 것은 범위가 아니라 주소 형식이다.
    const ok1 = ips.length === 1 && ips[0].split('.').every(
      (o) => Number(o) <= 255 && (o === '0' || o[0] !== '0'));
    return { ok: ok1, ip: ok1 ? ips[0] : '', many: ips.length > 1 };
  }

  function exactIp(t) {
    const raw = String(t || '').trim();
    if (!raw) return { ok: true, ip: '' };          // 일부러 비운 칸 = 폐기
    const ip = normIp(raw);
    /* 옥텟 범위와 앞자리 0 은 여기서 잡는다. 서버가 400 으로 막긴 하지만,
       "채웠다"는 상태줄을 본 뒤 원인 모를 오류를 만나게 된다. */
    if (ip && !ip.split('.').every(
        (o) => o.length <= 3 && Number(o) <= 255
               && (o === '0' || o[0] !== '0'))) {
      return { ok: false, ip: '' };
    }
    /* 구 값 쪽은 `10.0.0.5/32` 를 받는데 새 값만 거부하면 비대칭이다 —
       사용자는 양쪽에 같은 형태를 적는다. `/32` 는 호스트 하나라 뜻이 같다. */
    if (ip && (raw === ip || raw === ip + '/32')) return { ok: true, ip: ip };
    return { ok: false, ip: ip };
  }

  /* 한 줄을 칸으로 나눈다. **세 번 고쳐 쓴 자리다** — 어느 형태를 놓쳐도
     사람이 넣은 값이 조용히 다른 값이 된다.

     · 처음: 공백으로만 나눠 → 자기가 내보낸 CSV 의 빈 칸이 사라져 새 값
       자리에 참조 수가 들어왔다(139행 중 136행 오류).
     · 다음: 쉼표가 있으면 쉼표로만 → 엑셀 복사(탭 구분)가 그대로 깨졌다.
     · 그 다음: 셋 중 하나라도 있으면 셋 다로 → **공백으로 나뉜 줄에 탭이
       하나 섞이면** 첫 칸이 쌍 전체를 삼켰다. 실측:
         `10.0.0.5 11.11.11.5\t9.9.9.9` → `10.0.0.5 → 9.9.9.9`
       9.9.9.9 도 유효한 IP 라 아무 데서도 안 걸리고 "1행 중 1행 채움"이
       떴다. 줄 끝의 탭 하나만으로도 새 값이 사라져 **폐기**가 됐다. */
  /* 한 줄을 칸으로 나눈다. **구분자를 추측하지 않는다.**

     탭이 있으면 탭, 없고 쉼표·세미콜론이 있으면 그것, 둘 다 없으면 공백.
     섞여 있어도 **한 가지로 정한다** — "셋 다로 나눈다"로 했더니 공백으로
     나뉜 줄에 탭이 하나 섞였을 때 첫 칸이 쌍 전체를 삼켰다.

     줄 끝의 빈 칸만 버린다(줄 끝 구분자 하나). 앞쪽·중간의 빈 칸은
     **자리를 뜻하므로** 버리지 않는다 — 버렸더니 옛 주소 칸이 빈 줄이
     다른 주소의 폐기로 둔갑했다. */
  /* **공백으로 나뉜 줄은 마지막 토큰이 IP 일 때만 쌍이다.**
     객체 이름에 공백이 흔하다(`10.82.10.30/32_Splunk Forwarder1`,
     `10.82.192.0/28_CSN Primary + HA`) — 무조건 토큰으로 쪼개면 그 이름들이
     전부 거절된다(실물 5,453개 중 238개, 4.36%). 마지막 토큰이 주소가
     아니면 줄 전체가 이름 하나다(= 그대로 둠). */
  function byWhitespace(text) {
    const toks = String(text).trim().split(/\s+/).filter(Boolean);
    const last = toks[toks.length - 1];
    if (toks.length < 2 || !(exactIp(last).ok && exactIp(last).ip)) {
      return [String(text).trim()];
    }
    /* **칸이 셋 이상이면 첫 칸에 주소가 있어야 한다.** 없으면 config 원문
       줄을 긁어 붙인 것이다 — `set subnet 10.0.0.5 255.255.255.255` 가
       "10.0.0.5 를 255.255.255.255 로" 로 읽히고 "1행 중 1행 채움"이 떴다.
       실물 이름은 주소로 시작한다(`10.82.192.0/28_CSN Primary + HA`). */
    if (toks.length > 2
        && !/(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/.test(toks[0])) {
      return [String(text).trim()];
    }
    return [toks.slice(0, -1).join(' '), last];
  }

  function splitRow(line) {
    const clean = (x) => x.trim().replace(/^"(.*)"$|^'(.*)'$/,
                                          (m, a, b) => (a === undefined ? b : a));
    let fields;
    if (line.indexOf('\t') >= 0) {
      fields = line.split('\t').map(clean);
    } else if (/[,;]/.test(line)) {
      fields = line.split(/[,;]/).map(clean);
    } else {
      fields = byWhitespace(line);
    }
    while (fields.length && fields[fields.length - 1] === '') fields.pop();
    /* 앞 칸이 비었는데 **버려도 칸이 둘 이상 남으면** 엑셀에서 한 칸
       왼쪽부터 복사한 것이다. 하나만 남으면 옛 주소 칸이 비어 있는
       줄이므로 버리면 안 된다 — 버렸더니 그 줄이 **다른 주소의 폐기**로
       둔갑했다(`,11.11.11.6` → 11.11.11.6 을 폐기). */
    while (fields.length > 2 && fields[0] === '') fields.shift();
    /* 줄 끝 구분자 하나 때문에 한 칸만 남았는데 그 안에 공백이 있으면,
       사실은 공백으로 나뉜 줄이다 — **같은 규칙**을 쓴다. 예전엔 여기서
       무조건 토큰으로 쪼개서, 공백 든 객체 이름이 전부 거절됐다. */
    if (fields.length === 1 && /\s/.test(fields[0])) {
      fields = byWhitespace(fields[0]);
    }
    return fields;
  }

  $('migPasteApply')?.addEventListener('click', () => {
    const text = $('migPasteText').value || '';
    // 잠긴 상위 대역은 붙여넣기로도 못 채운다 — 아니면 잠금이 표시만이 된다.
    const known = new Set(hosts.filter((h) => !h.supernet).map((h) => h.ip));
    const map = {};
    let bad = 0;
    const garbled = [];
    const unreadable = [];   // 못 읽은 **줄** — 개수만 주면 139줄에서 못 찾는다
    /* **지우는 것만으로는 부족하다.** `delete map[old]` 는 기억을 남기지
       않아, 같은 주소가 세 번째로 오면 `old in map` 이 거짓이라 그대로
       받아들인다 — 충돌을 고쳤다고 적은 그 사고가 3줄이면 되살아나고,
       화면은 오히려 **더 조용해진다**(경고 2건 → 1건). 한 번 충돌한
       주소는 그 붙여넣기 안에서 다시 받지 않는다. */
    const poisoned = new Set();
    // 구형 Mac 개행(CR 단독)도 줄이다 — 안 나누면 N 행이 한 줄로 뭉개져
    // 첫 쌍만 반영되고 나머지가 조용히 버려진다.
    /* **JS 의 `\s` 는 줄바꿈이 아닌 것까지 포함한다.** 줄은 LF·CR 로만
       나누면서 칸은 `\s+` 로 나누면, Word 의 Shift+Enter(`\x0b`)·폼피드·
       U+2028/2029 로 나뉜 목록이 **한 줄로 뭉개져 첫 쌍만 반영된다**(실측
       10종). 줄 구실을 하는 문자는 줄로 나눈다. */
    text.split(/\r\n|[\r\n\u2028\u2029]/).forEach((line) => {
      if (!line.trim()) return;
      /* 자기가 내보낸 CSV 를 다시 넣는 것이 정상 경로다(주석에 "왕복 양쪽을
         연다"고 적어 뒀다). 그 헤더 줄을 실패로 세면 매번 "1줄을 읽지
         못했습니다" 라는 거짓 보고가 붙어 진짜 실패와 구분이 안 된다. */
      // 헤더는 어디 있든 헤더다 — 앞에 빈 줄이 있으면 idx 로는 못 잡는다.
      if (/^\s*"?current_address"?\b/i.test(line)) return;
      /* **세로탭·폼피드는 줄인지 칸인지 알 수 없다.** 줄로 보면 멀쩡한
         행이 깨지고(10R), 칸으로 보면 `10.0.0.5<VT>10.0.0.6` 이 개번으로
         읽힌다(실은 폐기 두 줄이다). Word 의 Shift+Enter 가 넣는 문자다.
         실물 이름에는 0개이므로 되물어도 잃을 것이 없다. */
      if (/[\v\f\u0085]/.test(line)) {
        garbled.push(cut(line.trim()) + ' → ?');
        return;
      }
      /* **따옴표가 안 닫힌 줄은 셀이 잘린 것이다.** 줄 분리가 따옴표보다
         먼저 일어나므로 여러 줄짜리 셀이 쪼개지고, 그 조각이 1칸 줄이 되어
         **적지도 않은 주소의 폐기**로 들어갔다(실측: 메모 칸에 적힌 IP 가
         폐기 대상이 되고 "3행 중 3행 채움"이 떴다). 추측하지 않는다. */
      if ((line.match(/"/g) || []).length % 2) {
        garbled.push(cut(line.trim()) + ' → ?');
        return;
      }
      /* **빈 칸을 지우면 안 된다.** 필드를 없애면 비어 있는 새 값 자리에 그
         다음 칸(참조 수)이 들어와, 자기가 내보낸 표를 다시 넣을 때 전부
         "올바른 주소가 아님"이 된다.

         **구분자를 하나로 정하면 안 된다.** 쉼표 경로만 고쳤더니 엑셀에서
         범위를 복사한 경우(클립보드가 **탭 구분**이다)가 그대로 깨져 있었고,
         쉼표와 탭이 섞인 줄은 새로 거부됐다. 셋 중 하나라도 있으면 셋 다로
         나눈다. 없으면 공백으로. 엑셀이 다시 감싸는 따옴표도 벗긴다. */
      const parts = splitRow(line);
      if (!parts.length) return;
      const o = readOld(parts[0]);
      if (!o.ok) {
        // 주소가 둘이면 어느 쪽이 대상인지 모른다 — 숫자만 세지 말고 보여준다.
        if (o.many) { garbled.push(cut(parts[0]) + ' → ?'); }
        // 못 읽은 줄은 설정이 아닌 것을 잘못 붙여넣었을 확률이 가장
        // 높다 — 다른 경로와 같은 상한을 쓴다.
        else { bad += 1; unreadable.push(cut(line.trim())); }
        return;
      }
      const old = o.ip;
      // 내보내기가 찍은 잠금 표시 — 값이 아니다. **어느 칸에 있든** 본다
      // (공백으로 적으면 줄 전체가 한 칸이 되어 `parts[1]` 검사에 안 닿았다).
      if (parts.some((x) => x === 'LEAVE_ALONE')
          || /(^|\s)LEAVE_ALONE(\s|$)/.test(parts[0] || '')) {
        return;
      }
      let val = '';
      if (parts.length > 1) {
        /* 새 값 칸이 비었는데 **뒤쪽에 IP 가 또 있다** — 칸이 밀린 것인지
           일부러 비운 것인지 알 수 없다. 폐기로 단정하면 그 설정이 옛
           주소에 남고, 값으로 단정하면 엉뚱한 칸을 새 주소로 삼는다.
           둘 다 조용한 사고라 묻는 쪽을 고른다. */
        /* **col2 가 채워져 있어도 봐야 한다.** 이 검사를 "col2 가 빈
           경우"에만 두었더니 `10.0.0.5,1.1.1.1,10.0.0.6,2.2.2.2` 가 첫 쌍만
           읽히고 두 번째 쌍은 어디에도 안 남은 채 "1행 중 1행 채움"이 떴다.
           자기가 내보낸 표의 3~5열은 참조수·필수여부·섹션 이름이라 여기
           걸리지 않는다(실측 확인). */
        if (parts.slice(2).some((x) => exactIp(x).ok && exactIp(x).ip)) {
          garbled.push(cut(parts[0]) + ' → ?');   // cut 이 빠져 있던 자리다
          return;
        }
        const v = exactIp(parts[1]);
        if (!v.ok) {
          garbled.push(cut(parts[0]) + ' → ' + cut(parts[1]));
          return;
        }
        val = v.ip;
      }
      /* **어느 방향이든 잡아야 한다.** 이 검사를 "값이 있는 가지" 안에만
         두었더니, 값을 적은 줄 뒤에 같은 주소를 맨몸으로 한 번 더 적으면
         (`10.0.0.5`) 그 값이 빈 값 = **폐기**로 조용히 덮였다. 사람이 적은
         것과 정반대 뜻인데 화면은 "2행 중 2행 채움"이라 말했다.
         순서를 뒤집으면 잡혔다 — 반쪽만 설치된 가드였다. */
      if (poisoned.has(old)) {
        garbled.push(old + ' → ?');
        return;
      }
      if (old in map && map[old] !== val) {
        /* **둘 다 버린다.** 먼저 온 값을 남기면 그것이 그대로 적용되는데,
           사용자는 뒤에 적은 것을 의도했을 수 있다. 어느 쪽을 남겨도
           절반은 틀리므로 빼고 묻는다 — 빠지면 '미매핑'으로 막힌다. */
        // 이 파일의 267개 문장 중 이 하나만 사전을 안 거쳐, 영어 화면에
        // 한국어가 그대로 떴다.
        const blank = apoT('(blank)');
        garbled.push(old + ' → ' + (map[old] || blank) + ' / '
                     + (val || blank));
        delete map[old];
        poisoned.add(old);
        return;
      }
      map[old] = val;
    });

    let hit = 0;
    const unknown = [];
    Object.entries(map).forEach(([old, val]) => {
      if (known.has(old)) { toBe[old] = val; hit += 1; }
      else unknown.push(old);
    });
    renderHosts();

    /* **부분 실패를 조용히 넘기면 안 된다.** 전에는 하나라도 맞으면 아무
       말도 안 해서, 20행 중 1행만 반영된 채 "붙여넣었다"고 믿게 했다. */
    /* **못 읽은 줄도 사용자가 붙여넣은 줄이다.** 분모에서 빼면 세 줄을
       넣고 하나만 읽혔는데 "1행 중 1행 채움"이 뜬다 — 옆에 실패 수가
       적혀 있어도 분수는 완전한 성공으로 읽힌다. */
    const total = Object.keys(map).length + garbled.length + bad;
    apoSetText($('migPasteStatus'),
      hit === total && !bad && !garbled.length
        ? 'Filled {hit} of {total} rows.'
        : 'Filled {hit} of {total} rows. {unknown} are not in this range, '
          + '{bad} lines could not be read, {garbled} new values are not '
          + 'valid addresses.',
      { hit: num(hit), total: num(total), unknown: num(unknown.length),
        bad: num(bad), garbled: num(garbled.length) });
    /* 어느 줄이 문제였는지 말한다 — 개수만으로는 139줄에서 못 찾는다. */
    const gEl = $('migPasteBad');
    if (gEl) {
      /* **문구가 실제 원인과 달랐다.** "올바른 IPv4 주소가 아니라서"라고
         썼는데, 되묻는 이유 셋 중 둘은 주소가 멀쩡하고 **칸 경계가
         모호하거나 같은 주소가 두 번**인 경우다. 그리고 못 읽은 줄은
         개수만 줬다 — 139줄에서 그 숫자로는 못 찾는다. */
      const blocks = [];
      if (garbled.length) {
        blocks.push('<strong style="color:#b00">' + esc(apoT(
          'These rows were not used — APO could not tell what you meant:'))
          + '</strong><br>' + esc(garbled.slice(0, 10).join(' · '))
          + (garbled.length > 10 ? ' …' : ''));
      }
      if (unreadable.length) {
        blocks.push('<strong style="color:#b00">' + esc(apoT(
          'These lines had no address APO could read:')) + '</strong><br>'
          + esc(unreadable.slice(0, 10).join(' · '))
          + (unreadable.length > 10 ? ' …' : ''));
      }
      /* 세 실패 갈래 중 이것만 개수만 주고 목록이 없었다 — 바로 옆 주석이
         "개수만 주면 139줄에서 못 찾는다"고 적어 둔 그 이유 그대로다. */
      if (unknown.length) {
        blocks.push('<span class="inline-status">' + esc(apoT(
          'These addresses are not in the range you searched:')) + ' '
          + esc(unknown.slice(0, 10).join(', '))
          + (unknown.length > 10 ? ' …' : '') + '</span>');
      }
      gEl.innerHTML = blocks.join('<br>');
      gEl.classList.toggle('hidden', !blocks.length);
    }
    renderBlankNotice();
    invalidateOnMappingChange();
  });

  /* **구 IP 목록을 꺼낼 수 있어야 한다.** ISP·고객에게 보낼 목록을 손으로
     옮겨 적게 하면 139개에서 반드시 틀린다. 받아온 값은 위 붙여넣기로
     되돌아온다 — 왕복 양쪽을 연다. */
  $('migExportBtn')?.addEventListener('click', () => {
    const head = 'current_address,new_address,references,must_change,where\n';
    const body = hosts.map((h) => [
      h.ip, h.supernet ? 'LEAVE_ALONE' : (toBe[h.ip] || ''),
      h.refs, h.must_change,
      '"' + (h.sections || []).join(' ').replace(/"/g, "'") + '"',
    ].join(',')).join('\n');
    save(head + body + '\n', `addresses_${(planTarget || '').replace(/[^\w.-]/g, '_')}`,
         '.csv', 'text/csv');
  });

  $('migOnlyChanged')?.addEventListener('change', renderPlan);
  document.addEventListener('input', (e) => {
    const el = e.target;
    if (el && el.classList && el.classList.contains('mig-to-be')) {
      toBe[el.dataset.ip] = el.value.trim();
      renderBlankNotice();
      invalidateOnMappingChange();
    }
  });

  // ── 장비 이관 ──────────────────────────────────────────────────────
  //
  // 벤더가 실제로 하는 작업 그대로다: 모델명·버전(헤더), 인터페이스 배열,
  // 그 배열을 참조하는 객체·정책. **암호화된 설정은 손대지 않는다.**
  let devTarget = null;     // 새 장비 정보
  let devPre = null;        // 사전 점검 결과
  let devMap = {};          // 옛 이름 → 새 이름 (타이핑마다 갱신)
  let devAck = null;        // 확인 토큰 — 매핑이 바뀌면 무효
  let devLast = null;       // 마지막 성공 결과 — 언어 전환 때 다시 그린다
  let devLastBlocked = null; // 마지막 차단 — 이것도 코드가 그린다
  let devBusy = false;      // 중복 클릭 가드 (apply 가 실 파일에서 3초 걸린다)

  /* **모드를 바꾸면 카드를 통째로 갈아 끼운다.** 기존 IP 흐름에 조건을
     얹지 않는다 — 15라운드 다듬은 경로라 조건 하나가 곧 새 구멍이다. */
  function devSetMode() {
    const on = $('migScopeDev') && $('migScopeDev').checked;
    ['migCard', 'migPlanCard', 'migApplyCard'].forEach((id) => {
      const el = $(id);
      if (el) el.classList.toggle('hidden', on);
    });
    /* **`.hidden` 이 아니라 `.mig-off` 다.** `#iprefResult` 는 검색이
       성공해야 열리는 패널이라 자기 사정으로 `hidden` 을 갖고 있는데,
       공유 클래스를 토글하면 그것을 벗겨 버린다 — 검색한 적 없는 대역에
       "참조 없음"이라고 단정하는 화면이 된다. 접는 주체가 다르면 클래스도
       달라야 한다. */
    document.querySelectorAll('#iprefView .mig-ip-only').forEach((el) => {
      el.classList.toggle('mig-off', on);
    });
    // 장비 모드 전용 문단은 반대로 — 부제까지 숨기면 머리말이 빈다.
    document.querySelectorAll('#iprefView .mig-dev-only').forEach((el) => {
      el.classList.toggle('hidden', !on);
    });
    $('devCard')?.classList.toggle('hidden', !on);
    $('devMapCard')?.classList.toggle('hidden', !on || !devPre);
  }
  document.querySelectorAll('input[name="migScope"]').forEach((r) => {
    r.addEventListener('change', devSetMode);
  });

  /* **결과까지 지운다.** 지우지 않으면 A 장비용 파일을 만든 뒤 B 백업을
     올렸을 때 2·3단계 표만 B 로 다시 그려지고 결과 패널은 A 파일 이야기를
     계속한다("12,345줄 바꿨다 … 아래 5단계 절차"). 차단 경고도 같다. */
  /* **둘 다 잠근다.** `devBusy` 는 두 버튼이 공유하는데 한쪽만 비활성화
     하면, 막힌 쪽은 눌러도 아무 반응이 없다 — 사용자에게는 고장이다. */
  /* **켜는 경로만 있으면 안 된다.** 한 번 뜬 확인칸이 성공한 뒤에도,
     새 소스를 열어도 남아 "설정을 끝까지 읽지 못했음을 이해합니다"가 멀쩡한
     config 옆에 붙는다 — 늑대소년이다. `.hidden` 클래스를 쓴다(`hidden`
     속성은 저자 CSS 한 줄에 무력해진다). */
  function devShowPartial(on) {
    $('devPartialWrap')?.classList.toggle('hidden', !on);
  }

  /* 미매핑 확인칸도 같다 — 바로 위가 "짝지을 것이 없습니다" 인데 "일부
     인터페이스에 짝이 없다는 것을 압니다" 가 함께 떠 있으면 늑대소년이다. */
  function devShowUnmapped(on) {
    $('devUnmappedWrap')?.classList.toggle('hidden', !on);
  }

  /* CSV 버튼은 **파일을 만든 뒤에만** 뜬다. 받은 것이 없는데 "한 장 더"를
     권하면 무엇의 CSV 인지 알 수 없고, 매핑을 고치는 중이면 그 CSV 는 아직
     아무것도 증명하지 않는다. */
  function devShowCsv(on) {
    $('devCsvWrap')?.classList.toggle('hidden', !on);
  }

  function devLockButtons(on) {
    ['devUploadBtn', 'devBuildBtn'].forEach((id) => {
      const b = $(id);
      if (b) b.disabled = !!on;
    });
  }

  function devInvalidate() {
    devAck = null;
    devLast = null;
    devLastBlocked = null;
    const el = $('devConfirmUnmapped');
    if (el) el.checked = false;
    const pw = $('devConfirmPartial');
    if (pw) pw.checked = false;
    devShowPartial(false);
    devShowCsv(false);
    const r = $('devResult');
    if (r) { r.innerHTML = ''; r.classList.add('hidden'); r.style.color = ''; }
    apoSetText($('devBuildStatus'), '');
  }

  /* **소스 config 가 바뀌면 확인도 사전점검도 통째로 버린다.** 대상 백업만
     보고 무효화하면, A 설정에서 "1개 버림"을 확인한 뒤 B 설정을 열고 누를
     때 A 의 확인으로 B 의 40개가 조용히 버려진다(서버도 토큰에 소스를
     묶어 막지만, 화면이 옛 표를 계속 보여 주면 사용자는 그 40개를 한 번도
     못 본다). */
  /* **장비 이관 쪽에서 잃을 것.** 확인창이 `toBe`(IP 개번 값)만 세면
     장비 이관 사용자에게는 **구조적으로 항상 0**이다 — 그 값을 채우는
     입력은 `#migCard` 안에 있고 장비 이관 모드에서는 그 카드가 숨겨진다.
     주석은 잃는 것을 셋으로 적어 놓고 하나만 셌다. */
  window.__apoDevPendingCount = () => {
    // **이미 파일로 만들었으면 잃을 것이 없다.** IP 쪽에만 이 규칙을 쓰고
    // 여기 안 쓰면, 파일을 만들고 다음 장비로 넘어가는 정상 흐름에서
    // 이미 Downloads 에 있는 것을 "지워진다"고 말한다(13라운드 P3).
    if (devLast) return 0;
    let n = Object.values(devMap).filter((v) => String(v || '').trim()).length;
    if (devTarget || devPre) n += 1;   // 고른 대상 백업도 잃는다
    return n;
  };

  function devResetForNewSource() {
    devPre = null;
    devTarget = null;
    devMap = {};
    devInvalidate();
    const pf = $('devPreflight');
    if (pf) { pf.innerHTML = ''; pf.classList.add('hidden'); }
    const tb = $('devMapTable')?.querySelector('tbody');
    if (tb) tb.innerHTML = '';
    apoSetText($('devUploadStatus'), '');
    devSetMode();
  }
  window.apoDevResetForNewSource = devResetForNewSource;

  // ── 새 장비 백업 읽기 ──────────────────────────────────────────────
  $('devUploadBtn')?.addEventListener('click', async () => {
    if (devBusy) return;
    const f = $('devFile')?.files?.[0];
    if (!f) {
      apoSetText($('devUploadStatus'), 'Choose a backup file first.');
      return;
    }
    apoSetText($('devUploadStatus'), 'Reading…');
    devBusy = true;
    devLockButtons(true);
    // **선언은 `try` 밖이다.** `const` 는 블록 스코프라 `catch` 에서
    // 안 보인다 — 거기서 참조하면 가드가 아니라 `ReferenceError`
    // 발생기가 되고, 바로 다음 줄의 '서버에 연결할 수 없습니다'가
    // 영영 안 나온다. 같은 파일의 `runLookup` 이 올바른 선례였다.
    let gen;
    try {
      const fd = new FormData();
      fd.append('config_file', f);
      fd.append('device_id', currentDeviceId || '');
      // **이 흐름에서 가장 긴 창이다** — config 전체를 보내고 파싱한다.
      // 가드를 안 달면 리셋이 버린 `devTarget` 이 늦은 응답에 되살아나고,
      // 그 뒤에 `devRunPreflight` 가 세대를 잡아 하류 가드까지 무력해진다.
      gen = window.apoGeneration?.();
      const res = await fetch('/api/device-migration/target',
                              { method: 'POST', body: fd });
      if (gen !== undefined && !window.apoGenerationIsCurrent?.(gen)) return;
      let data = null;
      try { data = await res.json(); } catch (e) { data = null; }
      if (!res.ok || !data) {
        apoSetText($('devUploadStatus'),
                   serverMsg(data) || 'Could not read that file.');
        return;
      }
      devTarget = data;
      devMap = {};
      devInvalidate();
      // **비우지 않는다.** 사전 점검은 실 파일에서 3.3초 걸린다. 여기서
      // 상태를 지우면 그 동안 화면에 아무것도 없어 "아무 일도 안 일어난다"가
      // 된다 — 실사용 첫 보고가 정확히 그 부류였다.
      apoSetText($('devUploadStatus'), 'Checking what would break…');
      // 성공했을 때만 지운다 — 실패하면 그 안에서 쓴 사유가 화면에 남아야
      // 한다(지우면 "아무 일도 안 일어난다"가 된다).
      if (await devRunPreflight()) apoSetText($('devUploadStatus'), '');
    } catch (e) {
      // 늦은 응답의 **실패**도 앞 장비의 것이다 — 리셋이 방금 비운
      // 화면에 앞 요청의 오류를 찍으면 안 된다.
      if (gen !== undefined && !window.apoGenerationIsCurrent?.(gen)) return;
      apoSetText($('devUploadStatus'), 'Could not reach the server.');
    } finally {
      devBusy = false;
      devLockButtons(false);
    }
  });

  async function devRunPreflight() {
    const gen = window.apoGeneration?.();   // **올리지 않는다.** 잡기만 한다.
    const { res, data } = await post('/api/device-migration/preflight', {});
    // 기다리는 사이 장비가 바뀌었으면 이 응답은 앞 장비의 것이다.
    if (gen !== undefined && !window.apoGenerationIsCurrent?.(gen)) return false;
    if (!res.ok || !data) {
      apoSetText($('devUploadStatus'), serverMsg(data) || 'Preflight failed.');
      // **실패했다고 알려야 호출부가 그 문구를 안 지운다.** 안 그러면
      // 대상 백업을 올렸는데 문구도 표도 아무것도 없는 화면이 된다.
      devPre = null;
      devSetMode();
      return false;
    }
    devPre = data;
    // 재점검 경로에서 `devTarget` 이 비어 있으면 여기서 다시 세운다 —
    // 안 그러면 교체 고지가 옛 헤더를 계속 견주어 영원히 켜져 있다.
    if (!devTarget && data.target_header) devTarget = { header: data.target_header };
    devRenderPreflight();
    devRenderMap();
    devSetMode();
    return true;
  }

  /* **겁주지 않는다.** 암호화된 값은 그대로 실려 가고 새 장비에서도
     동작한다(펌웨어 고정 키). 관리자가 자기 키를 쓴 경우에만 경고다. */
  function devRenderPreflight() {
    const el = $('devPreflight');
    if (!el || !devPre) return;
    const p = devPre;
    const rows = [];
    /* 모르는 것을 `?` 로 찍으면 "이 설정은 ? 에서 나왔고" 가 된다.
       모를 때는 모른다고 말한다(실 config 115개 중 40개가 헤더 없음). */
    const from = [p.old.model, p.old.version].filter(Boolean).join(' ');
    const to = [p.new.model, p.new.version].filter(Boolean).join(' ');
    rows.push('<strong>' + esc(from
      ? apoT('This configuration came from {a}, and you are moving it to {b}.',
             { a: from, b: to })
      : apoT('This configuration does not say which device it came from. You '
             + 'are moving it to {b}.', { b: to })) + '</strong>');
    /* **전제이지 경고가 아니다.** 이 기능은 인터페이스 배열을 옮기지
       설정 문법을 번역하지 않는다 — 그러니 같은 버전이라는 것이 전제다.
       막지는 않는다(우리 코퍼스로는 버전 발산을 잴 수 없고, 근거는
       Fortinet 문서와 현업 경험이다). 대신 맨 앞에서 분명히 말한다. */
    if (p.version_known === false) {
      // **모르는 것과 다른 것은 다르다.** 옛 config 에 `#config-version`
      // 헤더가 없으면 우리는 옛 버전을 모른다. 그때 "펌웨어가 다릅니다"는
      // 근거 없는 단정이다.
      rows.splice(0, 0, '<strong>' + esc(apoT(
        'This file has no config-version header, so APO cannot tell which '
        + 'version it came from. Make sure it matches the new device — this '
        + 'migration moves the interface layout, not the settings syntax.'))
        + '</strong>');
    } else if (!p.same_version) {
      rows.splice(0, 0, '<strong>' + esc(apoT(
        'These two run different firmware — {a} and {b}. Bring the new device '
        + 'to the same version before restoring: this migration moves the '
        + 'interface layout, not the settings syntax.',
        { a: p.old.version || '?', b: p.new.version || '?' })) + '</strong>');
    }
    const miss = Object.keys(p.missing_interfaces || {}).length;
    if (miss) {
      rows.push(esc(apoT(
        '{n} interfaces on this device do not exist on the new one. '
        + 'Match them below.', { n: num(miss) })));
    }
    if (p.private_data_encryption) {
      rows.push('<strong style="color:#b00">' + esc(apoT(
        'This device encrypts its secrets with your own key. Set the same key '
        + 'on the new device before restoring, or the secrets will not load.'))
        + '</strong>');
    } else if (p.secret_count) {
      rows.push('<span class="inline-status">' + esc(apoT(
        '{n} encrypted settings are carried over untouched — they keep working '
        + 'on the new device. Worth spot-checking VPN and RADIUS after the move.',
        { n: num(p.secret_count) })) + '</span>');
    }
    const hw = Object.keys(p.hardware_only || {}).length;
    if (hw) {
      rows.push('<span class="inline-status">' + esc(apoT(
        '{n} sections belong to this hardware and have no counterpart on the '
        + 'new device. Review them before restoring.', { n: num(hw) })) +
        '<br>' + esc(Object.keys(p.hardware_only).slice(0, 6).join(' · ')) +
        '</span>');
    }
    /* **"원래 그랬다"는 거짓 위로였다.** 절반만 맞다 — 정의가 없는 것은
       사실이지만, 그 이름들은 **새 장비에도 없어서** 복원 때 그 줄이
       통째로 버려진다. 막지는 않는다(옮기기 전에 이미 정의가 없었고
       이관이 악화시키는 것이 아니다 — 막으면 실 파일 6.3% 에서 늑대소년이
       된다). 대신 사실대로 말하고 아래 표에서 고칠 수 있게 한다. */
    const un = Object.keys(p.unresolved_in_old || {}).length;
    if (un) {
      rows.push('<span class="inline-status">' + esc(apoT(
        '{n} names are used here but never defined in this file, and the '
        + 'new device has no such port either. If they are real ports on the '
        + 'device you are moving from, match them below — otherwise those '
        + 'lines were already dead and will stay that way.',
        { n: num(un) })) +
        '<br>' + esc(Object.keys(p.unresolved_in_old).slice(0, 8).join(' · ')) +
        '</span>');
    }
    /* 뺀 이유를 말한다 — 안 하면 "새 장비에 wan1 이 있는데 왜 목록에
       없지"로 끝난다. */
    const sbr = (p.spare_but_referenced || []);
    if (sbr.length) {
      rows.push('<span class="inline-status">' + esc(apoT(
        'These ports exist on the new device but this configuration already '
        + 'refers to them, so they are not offered as targets: {list}',
        { list: sbr.slice(0, 8).join(', ') })) + '</span>');
    }
    el.className = 'sev-guide-note';
    el.innerHTML = rows.join('<br>');
    el.classList.remove('hidden');
  }

  // ── 매핑 표 ────────────────────────────────────────────────────────
  function devRenderMap() {
    const tb = $('devMapTable')?.querySelector('tbody');
    if (!tb || !devPre) return;
    tb.innerHTML = '';
    /* **정의가 있는 것만 그리면 "확인할 것 없음"이 거짓이 된다.** 정의
       없이 참조만 있는 이름도 새 장비에 없으면 그 줄이 버려진다. 엔진은
       이미 정의 없는 이름의 참조만 개명하는 것을 올바로 한다 — 표가 그
       행을 안 그렸을 뿐이다. */
    const miss = Object.assign({}, devPre.unresolved_in_old || {},
                               devPre.missing_interfaces || {});
    const names = Object.keys(miss).sort((a, b) => miss[b] - miss[a]);
    devShowUnmapped(names.length > 0);
    const spare = devPre.spare_interfaces || [];
    for (const n of names) {
      const tr = document.createElement('tr');
      const opts = ['<option value=""></option>'].concat(
        spare.map((x) => `<option value="${esc(x)}"${
          devMap[n] === x ? ' selected' : ''}>${esc(x)}</option>`)).join('');
      tr.innerHTML =
        `<td><code>${esc(n)}</code></td>` +
        `<td><select class="text-input dev-to" data-if="${esc(n)}"` +
        ` style="min-width:150px">${opts}</select></td>` +
        `<td>${num(miss[n])}</td>` +
        `<td class="inline-status">${esc(
            (devPre.old.model || '') + ' → ' + (devPre.new.model || ''))}</td>`;
      tb.appendChild(tr);
    }
    const note = $('devMapNote');
    if (note) {
      note.innerHTML = names.length
        ? ''
        : esc(apoT('Every interface this configuration uses also exists on the '
                   + 'new device. Nothing to match.'));
      note.classList.toggle('hidden', !!names.length);
    }
  }

  /* 대상이 바뀌었다는 고지의 **처방**. 사전점검을 다시 돌려 3단계 표를
     새 장비 것으로 갈아 준다 — 안 그러면 "다시 확인하라"고 해 놓고 볼 수
     있는 목록이 교체 전 장비의 것뿐이다. */
  document.addEventListener('click', (e) => {
    if (e.target && e.target.id === 'devRecheck') {
      /* **매핑과 대상 기억도 함께 버린다.** `devInvalidate` 는 `devMap` 을
         안 지우므로, 교체 전에 고른 포트가 남아 새 장비에 없는 이름으로
         전송된다 — 화면 드롭다운은 비어 있는데 **확인으로 못 푸는 차단**
         (`not_on_new_device`)에 갇히고, 빠져나올 길은 대상 재업로드뿐이다.
         그리고 `devTarget` 을 안 갱신하면 파일이 새 장비용으로 맞게
         만들어진 뒤에도 "틀렸다"는 고지가 영원히 남는다. */
      devMap = {};
      devTarget = null;
      devInvalidate();
      devRunPreflight();
    }
  });

  document.addEventListener('change', (e) => {
    const el = e.target;
    if (el && el.classList && el.classList.contains('dev-to')) {
      devMap[el.dataset.if] = el.value;
      devInvalidate();
    }
  });

  /* 사용자가 고른 인터페이스 짝. **파일을 만드는 쪽과 변경내역을 받는 쪽이
     같은 함수를 써야 한다** — 두 곳에 같은 조립을 적어 두면 하나를 고칠 때
     다른 하나가 남아, 받은 config 와 결재에 올리는 문서가 다른 입력으로
     만들어진다(서버도 같은 이유로 `_dev_mig_inputs` 하나를 쓴다). */
  function devCollectMapping() {
    return Object.keys(
      Object.assign({}, devPre?.unresolved_in_old || {},
                    devPre?.missing_interfaces || {}))
      .map((o) => ({ old: o, new: devMap[o] || '' }));
  }

  // ── 파일 만들기 ────────────────────────────────────────────────────
  $('devBuildBtn')?.addEventListener('click', async () => {
    if (devBusy) return;
    apoSetText($('devBuildStatus'), 'Building…');
    devBusy = true;
    devLockButtons(true);
    // **선언은 `try` 밖이다.** `const` 는 블록 스코프라 `catch` 에서
    // 안 보인다 — 거기서 참조하면 가드가 아니라 `ReferenceError`
    // 발생기가 되고, 바로 다음 줄의 '서버에 연결할 수 없습니다'가
    // 영영 안 나온다. 같은 파일의 `runLookup` 이 올바른 선례였다.
    let gen;
    try {
      gen = window.apoGeneration?.();
      const { res, data } = await post('/api/device-migration/apply', {
        mapping: devCollectMapping(),
        confirm_unmapped: $('devConfirmUnmapped')?.checked || false,
        confirm_partial_read: $('devConfirmPartial')?.checked || false,
        ack_token: devAck,
      });
      // 기다리는 사이 장비가 바뀌었으면 이 응답은 앞 장비의 것이다 —
      // 쓰면 입력한 적 없는 대역에 대해 화면이 단언하게 된다.
      if (gen !== undefined && !window.apoGenerationIsCurrent?.(gen)) return;
      /* **409 가 전부 "확인 필요"는 아니다.** 장비 게이트(다른 창에서
         장비를 바꾼 뒤 묵은 탭에서 누른 경우)도 409 를 내는데 거기엔
         `blocking` 이 없다. 그것을 차단 화면으로 그리면 **내용 없는 경고
         삼각형 하나**와 "위 질문에 답하라"만 남는데 답할 질문이 없어
         영원한 루프가 된다. IP 흐름은 `needs_confirmation` 을 함께 본다. */
      if (res.status === 409 && data && data.needs_confirmation
          && (data.blocking || []).length) {
        devAck = data.ack_token || null;
        devRenderBlocked(data);
        return;
      }
      if (!res.ok || !data) {
        apoSetText($('devBuildStatus'),
                   serverMsg(data) || 'Build failed.');
        return;
      }
      devDownload(data);
      apoSetText($('devBuildStatus'), '');
      devRenderResult(data);
    } catch (e) {
      // 늦은 응답의 **실패**도 앞 장비의 것이다 — 리셋이 방금 비운
      // 화면에 앞 요청의 오류를 찍으면 안 된다.
      if (gen !== undefined && !window.apoGenerationIsCurrent?.(gen)) return;
      apoSetText($('devBuildStatus'), 'Could not reach the server.');
    } finally {
      devBusy = false;
      devLockButtons(false);
    }
  });

  /* 차단은 거절이 아니라 질문이다 — 무엇을 왜 묻는지 보여야 답할 수 있다.
     그리고 **버튼 옆 상태를 여기서 정리한다**(호출부에 두면 경로가 하나
     늘 때마다 샌다 — 실사용 첫 보고가 그것이었다). */
  function devRenderBlocked(data) {
    if (!data) return;
    devLastBlocked = data;   // 언어가 바뀌면 다시 그려야 한다
    devLast = null;
    // 막혔으면 파일이 없다 — 그 옆의 "CSV 로 받기"는 가리킬 것이 없다.
    devShowCsv(false);
    const parts = [];
    const B = {
      unmapped_interface: 'These interfaces have no match on the new device: {list}',
      interface_collision: 'Two interfaces would end up with the same name: {list}',
      name_too_long: 'FortiOS allows at most 15 characters in an interface name: {list}',
      not_on_new_device: 'The new device has no such interface: {list}',
      /* 우리가 손도 안 댄 줄의 내용이 없어진다 — 확인 없이 넘기면 안 된다.
         IP 흐름과 같은 문장을 쓴다. */
      encoding_lossy: 'This backup contains {bytes} bytes that are not UTF-8 '
                      + '(often Korean comments saved in another encoding). '
                      + 'APO cannot read them, so they will be missing from '
                      + 'the file it produces — even on lines it does not '
                      + 'touch.',
    };
    for (const b of data.blocking || []) {
      const tpl = B[b];
      if (!tpl) { parts.push(esc(b)); continue; }
      const list = ({
        unmapped_interface: data.unmapped,
        interface_collision: data.collisions,
        name_too_long: data.too_long,
        not_on_new_device: data.not_on_new,
      }[b] || []).slice(0, 12).join(', ');
      parts.push(esc(apoT(tpl, { list: list,
                                 bytes: num(data.decode_lost_bytes || 0) })));
    }
    const el = $('devResult');
    el.className = 'sev-guide-note';
    el.style.color = '#b00';
    el.innerHTML = '⚠ ' + parts.join('<br>⚠ ');
    el.classList.remove('hidden');
    /* 충돌·이름길이·없는 포트는 체크박스로 답할 수 있는 것이 아니다 —
       위쪽 드롭다운을 바꿔야 풀린다. 답할 수 없는 것에 "답하라"고 하면
       사용자는 없는 질문을 찾는다. */
    // 답할 수 있는 차단이 하나라도 있으면 그 확인칸을 띄운다.
    const bl = data.blocking || [];
    devShowPartial(bl.includes('encoding_lossy'));
    const answerable = bl.includes('unmapped_interface')
      || bl.includes('encoding_lossy');
    apoSetText($('devBuildStatus'), answerable
      ? 'Not built yet — answer the questions above, then press the button '
        + 'again.'
      : 'Not built yet — change the interface choices above, then press the '
        + 'button again.');
  }

  /* 로그가 빌지 안 빌지 — 한 문장. */
  function devLogStep(data, v) {
    return data.expect_empty_log !== false
      ? apoT('After it comes back up, run this and confirm it is empty:')
      : apoT('After it comes back up, run this and read it — it will not be '
             + 'empty:');
  }

  /* **왜 차는지를 빠짐없이.** 두 사유가 겹칠 수 있으므로 더한다. */
  function devLogWhy(v) {
    if (!v) return '';
    const out = [];
    if (v.orphan_reference_count || v.orphan_definition_count) {
      out.push(apoT('The complaints should be the ports you chose to leave '
                    + 'behind.'));
    }
    const dead = Object.keys(v.pre_existing_dangling || {});
    if (dead.length) {
      out.push(apoT('These names were never defined in your configuration and '
                    + 'the new device has no such port, so those lines were '
                    + 'already dead: {list}',
                    { list: dead.slice(0, 8).join(', ') }));
    }
    return out.length ? ' ' + out.map(esc).join(' ') : '';
  }

  function devRenderResult(data) {
    if (!data) return;
    devLast = data;
    devLastBlocked = null;
    devShowPartial(false);   // 답이 끝난 질문은 화면에서 내린다
    devShowCsv(true);        // 이제 "같은 표를 CSV 로" 가 가리킬 것이 있다
    const el = $('devResult');
    const s = data.summary || {};
    const by = s.by_kind || {};
    const v = data.verification || {};
    el.className = 'sev-guide-note';
    el.style.color = '';
    /* **"몇 줄 바꿨다"는 성공의 증거가 아니다.** 미매핑을 확인하고
       넘어갔으면 새 장비에 없는 포트를 가리키는 줄이 그대로 남고, FortiOS
       는 그것을 조용히 버리면서 복원 성공을 표시한다. 그 규모를 먼저
       말한다 — 안 하면 헤더 한 줄만 바뀐 파일이 성공처럼 보인다. */
    /* 화면이 기억하는 대상과 서버가 실제로 쓴 대상이 다르면 말한다 —
       다른 창에서 대상 백업을 갈아끼운 경우다. 조용히 넘기면 사용자가
       읽은 미매핑·여분포트 목록이 **다른 장비의 것**이 된다. */
    /* **헤더 전체를 견준다.** 모델만 보면 같은 모델의 다른 백업(다른
       펌웨어·다른 포트 구성)으로 갈아끼운 경우를 놓친다 — 사용자가 읽은
       사전점검이 통째로 다른 장비의 것이 되는데 조용하다.
       그리고 처방은 **실행 가능해야** 한다: 3단계 표는 저절로 다시
       그려지지 않으므로 "다시 확인하라"만 해서는 할 수 있는 일이 없다.
       사전점검을 다시 돌리는 버튼을 함께 준다. */
    const before = devTarget?.header || devPre?.new?.model;
    const now = data.target_header || data.target_model;
    const swapped = before && now && before !== now
      ? '<strong style="color:#b00">' + esc(apoT(
          'The new device changed while you were working — this file was '
          + 'built for {a}, not {b}.', { a: now, b: before }))
        /* **라벨도 `apoT` 를 지나야 한다.** `data-i18n` 은 `apply()` 가
           도는 시점에만 번역되는데, 언어 전환 순서가 `apply()` →
           `devRenderResult` 라 번역된 버튼이 곧바로 영어로 다시 그려진다 —
           빨간 한국어 경고문 옆에 영어 버튼이 붙는다.
           그리고 `ghost-btn` 은 이 앱의 CSS 에 없는 클래스였다. */
        + ' <button type="button" id="devRecheck" class="secondary-btn">'
        + esc(apoT('Check the new device again')) + '</button></strong><br>'
      : '';
    const head = swapped + (v.clean === false
      ? '<strong style="color:#b00">' + esc(v.orphan_reference_count
        ? apoT('Careful — {d} interface definitions in this file, and the {r} '
               + 'references to them, point at ports the new device does not '
               + 'have. FortiOS will drop those lines on restore without '
               + 'saying so. The file name is marked INCOMPLETE.',
               { d: num(v.orphan_definition_count || 0),
                 r: num(v.orphan_reference_count || 0) })
        // 아무도 안 가리키는 정의만 버려질 때 "그것을 가리키는 참조 0건"은
        // 거짓은 아니어도 읽는 사람을 멈칫하게 한다. 그 절을 뺀다.
        : apoT('Careful — {d} interfaces defined in this file do not exist '
               + 'on the new device. FortiOS will drop those lines on restore '
               + 'without saying so. The file name is marked INCOMPLETE.',
               { d: num(v.orphan_definition_count || 0) })) + '</strong><br>'
      : '');
    el.innerHTML = head +
      esc(apoT('{changed} of {total} lines changed.',
               { changed: num(data.changed_lines),
                 total: num(data.total_lines) })) + ' ' +
      /* **세 갈래다.** `by.header` 는 "치환했나"일 뿐이라 "헤더가 있나"의
         대역으로 쓰면 안 된다 — 소스와 대상 헤더가 글자까지 같으면(같은
         모델·같은 펌웨어, RMA 교체) 행이 0이 되는데, 그것을 "헤더가 없다"로
         읽으면 하지 않아도 될 수작업을 지시하고 위쪽 사전점검("FGT100F 에서
         나왔다")과 모순된다. 소스에 헤더가 있었는지는 **서버가 알려 준다**. */
      esc(by.header
        ? apoT('The header, {d} interface definitions and {r} references '
               + 'moved together. Encrypted settings were not touched.',
               { d: num(by.definition || 0), r: num(by.reference || 0) })
        : (data.source_had_header
          ? apoT('{d} interface definitions and {r} references moved '
                 + 'together. The header already matches the new device, so '
                 + 'there was nothing to replace. Encrypted settings were '
                 + 'not touched.',
                 { d: num(by.definition || 0), r: num(by.reference || 0) })
          : apoT('{d} interface definitions and {r} references moved '
                 + 'together. This file had no config-version header, so '
                 + 'there was none to replace — set the model and version on '
                 + 'the new device yourself. Encrypted settings were not '
                 + 'touched.',
                 { d: num(by.definition || 0), r: num(by.reference || 0) }))) +
      '<ol style="margin-top:10px"><li>' + [
        apoT('Take a fresh backup from the new device now — that is your '
             + 'rollback.'),
        apoT('Clear the parser log first so you are not reading an old one:')
          + ' <code>diagnose debug config-error-log clear</code>',
        apoT('Restore the produced file. The device reboots.'),
        /* **배타 분기가 아니라 더하는 구조다.** 두 사유가 동시에 있을
           수 있고(실 쌍 7,280 중 203), 배타로 쓰면 뒤엣것의 이름이 통째로
           사라진다 — 3분기를 만든 이유가 "그 이름을 대 줘야 구별한다"인데
           겹치는 순간 그 이유가 무너졌다. 로그가 찬다면 **왜 차는지를
           빠짐없이** 말한다. */
        devLogStep(data, v) + ' <code>'
          + esc(data.post_apply_check || '') + '</code>'
          + devLogWhy(v),
        apoT('Check the interfaces, then a few policies that use them.'),
      ].join('</li><li>') + '</li></ol>';
    el.classList.remove('hidden');
  }

  /* 이름에 남긴다. 화면은 닫히지만 파일은 Downloads 에 남아, 몇 시간
     뒤 그 파일을 복원하는 사람은 화면 경고를 본 적이 없다. IP 흐름의
     `_UNVERIFIED` 와 같은 규칙이다. */
  function devDownload(data) {
    // **서버가 쓴 대상 이름을 쓴다.** 화면이 기억하는 것으로 이름을 지으면,
    // 다른 탭이 대상을 갈아끼웠을 때 `migrated_FGT1KD.conf` 라는 이름의
    // FGT100F 용 파일이 떨어진다.
    const t = (data.target_model || devPre?.new?.model || 'device');
    const mark = data.verification && data.verification.clean === false
      ? '_INCOMPLETE' : '';
    save(data.config, `migrated_${t}${mark}`, '.conf', 'text/plain');
    /* **바뀐 config 만 주면 무엇이 바뀌었는지 증명할 수 없다.** 화면 표는
       새로고침 한 번에 사라지고, 승인·감사·인수인계에 올릴 것이 없다. IP
       개번은 2026-09-15 에 워크북으로 올라갔는데 이 경로만 남아 있었다. */
    devSaveChangesWorkbook();
  }

  /** 장비 이관 변경내역을 서버에서 받아온다(워크북 또는 CSV).
   *
   *  **화면이 든 표를 되보내지 않는다.** 서버가 같은 입력으로 다시 계산해야
   *  파일이 APO 의 판단을 증명한다(`/api/config/diff/export` 와 같은 원칙).
   *  보내는 것은 사용자가 고른 인터페이스 짝뿐이고, 소스 config 와 대상 장비
   *  백업은 서버가 들고 있는 것을 쓴다 — 파일을 만든 것과 같은 입력이다.
   *
   *  **`device_id` 를 반드시 싣는다.** 장비 게이트는 `/api/` 전체에 걸려
   *  있어서, 빠뜨리면 이 요청은 409 로 막힌다(`post()` 가 그것을 자동으로
   *  싣는 이유이고, blob 을 받아야 해서 여기서는 `post()` 를 못 쓴다).
   */
  function devExportChanges(extra) {
    return postFile('/api/device-migration/export/changes',
      Object.assign({ mapping: devCollectMapping() }, extra || {}));
  }

  /** **받았다고 말한다.** 아무 말 없이 떨어지면 만든 사람조차 산출물이 없는
      줄 안다(IP 흐름에서 2026-09-15 에 겪었다). IP 쪽과 같은 문장을 쓴다. */
  function devAnnounceDownloads(ext) {
    apoSetText($('devBuildStatus'), apoT(
      'Downloaded 2 files: the configuration (.conf) and the change record ({ext}).',
      { ext: ext }));
  }

  async function devSaveChangesWorkbook() {
    try {
      const res = await devExportChanges();
      if (!res.ok) throw new Error('export failed: ' + res.status);
      /* **이름은 서버가 정한 것을 쓴다.** 여기서 지으면 장비 칩·zip 엔트리와
         규칙이 갈려, 장비 여러 대를 도는 컨설턴트의 폴더에서 (1),(2) 로
         쌓인다(`test_every_download_uses_the_name_the_server_sent`). */
      saveResponseAs(await res.blob(), res,
                     'apo_device_migration_changes.xlsx');
      devAnnounceDownloads('.xlsx');
    } catch (e) {
      /* **조용히 포기하지 않는다.** IP 흐름에는 옛 `.txt` 조립본이 대비책으로
         남아 있지만 장비 이관에는 그런 것이 없다(여태 config 한 개만
         내려줬다). 화면 표를 `.txt` 로 찍는 대비책을 새로 만들지는 않는다 —
         그것이 바로 IP 쪽에서 원시값을 결재에 올린 결함이었다. 못 받았다는
         사실을 말하고 다시 누를 수 있게 한다. */
      apoSetText($('devBuildStatus'), apoT(
        'The configuration (.conf) was downloaded, but the change record could '
        + 'not be built. Press the button again to try once more.'));
    }
  }

  /* 변경내역만 CSV 로 한 장 더 — 다른 시스템에 넣거나 스크립트로 대사할 때.
     **워크북을 대체하지 않는다**(감사 제출은 절이 넷이라 xlsx 여야 한다).
     한글이 깨지지 않게 BOM 을 붙이는 것은 서버가 한다. */
  $('devCsvBtn')?.addEventListener('click', async () => {
    const btn = $('devCsvBtn');
    btn.disabled = true;
    try {
      const res = await devExportChanges({ format: 'csv' });
      if (!res.ok) throw new Error('csv export failed: ' + res.status);
      saveResponseAs(await res.blob(), res,
                     'apo_device_migration_changes.csv');
      apoSetText($('devBuildStatus'), '');
    } catch (e) {
      /* 조용히 실패하면 사용자는 버튼이 죽은 줄 안다. */
      apoSetText($('devBuildStatus'),
                 apoT('Could not build the CSV. The workbook (.xlsx) you '
                      + 'already received has the same table.'));
    } finally {
      btn.disabled = false;
    }
  });

  /* 코드가 그린 것은 언어가 바뀌면 **전부** 다시 그려야 한다. 표만 등록하면
     그 위아래 문장이 전환 전 언어로 남아 반쪽 화면이 된다. */
  onLangChange(() => { renderHosts(); renderPlanAll(); renderBlankNotice();
                       renderApply();
                       // 장비 이관 카드도 코드가 그린다 — 빠뜨리면 사전
                       // 점검·매핑 안내·5단계 절차가 전환 전 언어로 남아
                       // 한 카드 안에서 두 언어가 섞인다.
                       if (devPre) { devRenderPreflight(); devRenderMap(); }
                       if (devLast) devRenderResult(devLast);
                       if (devLastBlocked) devRenderBlocked(devLastBlocked); });
})();
