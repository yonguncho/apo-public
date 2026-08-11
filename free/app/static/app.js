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

// 티켓 ID는 서버가 customer_rules.json의 ticket_id_pattern으로 추출해
// item.ritm에 넣어준다. 여기서 특정 고객사 접두어를 하드코딩하면 다른
// 고객 환경에서 이 필터가 항상 참이 되어 결과가 왜곡된다.
function hasNoRitm(item) {
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

/* 상단 상태바·Overview는 shell.js가 그린다. 여기서는 "무엇이 로드됐는지"만 알린다. */
function notifyConfigLoaded(sourceLabel, filename, configSha) {
  const meta = currentView?.meta || {};
  window.__apoResetSev?.();
  const counted = meta.policy_count != null || meta.proxy_policy_count != null;
  window.APO?.onConfig?.({
    meta,
    filename,
    configSha,
    source: sourceLabel,
    // 개수를 못 셌으면 0이 아니라 null — "정책 0건"으로 보이면 안 된다.
    policies: counted ? (meta.policy_count ?? 0) + (meta.proxy_policy_count ?? 0) : null,
  });
  window.APO?.onUsage?.(Object.keys(currentRuntimeStats || {}).length);
}

function applyLoadedConfig(data, sourceLabel) {
  currentParsed = data.parsed;
  currentView = data.view;
  currentRuntimeStats = data.runtime_stats || {};
  fwCsvSummary = null;
  proxyCsvSummary = null;
  if (selectedFwCsvName) selectedFwCsvName.textContent = 'No file selected';
  if (selectedProxyCsvName) selectedProxyCsvName.textContent = 'No file selected';
  /* 이 경로는 장비에서 직접 받아온 것이라 내려받을 parsed JSON이 없다. 그런데
     이전에 업로드한 파일의 링크를 그대로 두면, 새 장비의 요약 카드 밑에 이전
     고객 장비의 설정 전체를 내려받는 링크가 남는다. */
  if (downloadBox) downloadBox.innerHTML = '';
  if (selectedConfigName) selectedConfigName.textContent = 'No file selected';
  resetPolicyFilters();
  configStatus.textContent = sourceLabel;
  policyStatsStatus.textContent = data.stats_count
    ? `${data.stats_count} policies have usage stats from the device.`
    : 'Upload Firewall Policy CSV or Proxy Policy CSV.';
  renderPolicyCsvSummary();
  renderMeta(data.view?.meta || {});
  updatePolicyFilterVisibility();
  renderActiveTab();
  notifyConfigLoaded(sourceLabel, data.filename, data.config_sha);
}

(() => {
  const btn = document.getElementById('collectBtn');
  const st = document.getElementById('collectStatus');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const ip = document.getElementById('collIp')?.value.trim();
    const token = document.getElementById('collToken')?.value.trim();
    if (!ip || !token) { if (st) st.textContent = 'Enter the device IP and API token.'; return; }
    if (st) st.textContent = 'Connecting and collecting (config, stats, FQDNs)...';
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
      if (!res.ok) throw new Error(data.error || 'Collection failed');
      applyLoadedConfig(data, `Collected from ${data.hostname || ip}`);
      let msg = `Collected: ${data.policies} policies, ${data.stats_count} usage stats, ${data.fqdn_count} FQDN resolutions.`;
      if ((data.warnings || []).length) msg += ' Note: ' + data.warnings.join('; ');
      if (st) st.textContent = msg;
    } catch (err) {
      if (st) st.textContent = err.message || 'Collection failed';
    } finally { btn.disabled = false; }
  });
})();

configFileInput.addEventListener('change', async () => {
  const file = configFileInput.files?.[0];
  selectedConfigName.textContent = file ? file.name : 'No file selected';
  if (!file) return;

  const formData = new FormData();
  formData.append('config_file', file);
  configStatus.textContent = 'Parsing config...';

  let res, data;
  try {
    res = await fetch('/api/config/parse', { method: 'POST', body: formData });
    data = await res.json().catch(() => ({}));
  } catch (err) {
    configStatus.textContent = 'Failed to parse config (network error)';
    return;
  }

  if (!res.ok) {
    configStatus.textContent = data.error || 'Failed to parse config';
    return;
  }

  currentParsed = data.parsed;
  currentView = data.view;
  currentRuntimeStats = {};
  fwCsvSummary = null;
  proxyCsvSummary = null;
  if (selectedFwCsvName) selectedFwCsvName.textContent = 'No file selected';
  if (selectedProxyCsvName) selectedProxyCsvName.textContent = 'No file selected';
  resetPolicyFilters();
  configStatus.textContent = `Loaded ${data.filename}`;
  policyStatsStatus.textContent = 'Upload Firewall Policy CSV or Proxy Policy CSV.';
  renderPolicyCsvSummary();
  downloadBox.innerHTML = `<a href="/exports/${encodeURIComponent(data.export_json || '')}">Download parsed JSON</a>`;
  renderMeta(data.view?.meta || {});
  updatePolicyFilterVisibility();
  renderActiveTab();
  notifyConfigLoaded(`Uploaded ${data.filename}`, data.filename, data.config_sha);
});

async function importPolicyCsv(file, type) {
  if (!file) return;
  const formData = new FormData();
  formData.append('policy_stats_files', file);
  policyStatsStatus.textContent = `Importing ${type} CSV...`;

  let res, data;
  try {
    res = await fetch('/api/policy-stats/import', { method: 'POST', body: formData });
    data = await res.json().catch(() => ({}));
  } catch (err) {
    policyStatsStatus.textContent = `Failed to import ${type} CSV (network error)`;
    return;
  }

  if (!res.ok) {
    policyStatsStatus.textContent = data.error || `Failed to import ${type} CSV`;
    return;
  }

  currentRuntimeStats = { ...currentRuntimeStats, ...(data.runtime_stats || {}) };

  if (type === 'FW') {
    fwCsvSummary = { summary: data.summary, filename: file.name };
  } else {
    proxyCsvSummary = { summary: data.summary, filename: file.name };
  }

  renderPolicyCsvSummary();
  policyStatsStatus.textContent = `${type} Policy CSV applied: ${file.name}`;
  window.APO?.onUsage?.(Object.keys(currentRuntimeStats || {}).length);
  await rerenderWithRuntimeStats();

  // severity 결과가 있으면 자동 재분류 (sevData는 다른 IIFE 스코프이므로 window 플래그로 감지)
  if (window.__sevHasData) {
    const runBtn = document.getElementById('sevClassifyBtn');
    if (runBtn) runBtn.click();
  }
}

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
  try {
    const renderRes = await fetch('/api/policies/render', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ parsed: currentParsed, runtime_stats: currentRuntimeStats })
    });
    if (!renderRes.ok) {
      const err = await renderRes.json().catch(() => ({}));
      if (policyStatsStatus) policyStatsStatus.textContent = `CSV apply error: ${err.error || renderRes.status}`;
      return;
    }
    const renderData = await renderRes.json();
    if (!renderData.view) {
      if (policyStatsStatus) policyStatsStatus.textContent = 'CSV apply error: No response data';
      return;
    }
    currentView = renderData.view;
    renderMeta(renderData.view?.meta || {});
    renderActiveTab();
  } catch (e) {
    if (policyStatsStatus) policyStatsStatus.textContent = `CSV apply failed: ${e.message}`;
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
    policyCsvSummary.innerHTML =
      makeCards('FW Policy CSV', fwCsvSummary) +
      makeCards('Proxy Policy CSV', proxyCsvSummary);
  }
}

function renderActiveTab() {
  if (!currentView) {
    tabContent.innerHTML = '<div class="empty-state"><h3>No dataset loaded</h3><p>Select a Config File and optionally merge a Policy CSV to begin.</p></div>';
    tabCount.textContent = '';
    return;
  }

  const items = getFilteredItems();
  tabCount.textContent = `${items.length} item(s)`;

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
  a.download = `${tab.filename}.csv`;
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
    body: JSON.stringify(payload),
  });
  if (!res.ok) { await alertApiError(res, 'Failed to build workbook export.'); return; }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'firewall_policy_optimizer_export.xlsx';
  a.click();
  URL.revokeObjectURL(url);
});

function csvEscape(value) {
  const str = String(value ?? '');
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replaceAll('"', '""')}"`;
  }
  return str;
}

renderActiveTab();


/* APO License Gate & Modal */
const LEMON_CHECKOUT_URL = 'https://choiceguidelab.lemonsqueezy.com/checkout/buy/1c83b59f-7f23-4899-a173-dc43d1c7bce6';

let _licensed = null;  // null=미확인, true/false
let _pendingExportBtnId = null;  // 게이트를 띄운 export 버튼 id (활성화 후 재실행용)

// Export 대상 버튼 ID 목록 (CSV 포함 전체 게이트)

// 실패 응답의 서버측 사유({"error":...})를 사용자에게 보여준다.
// 일반 문구만 내면 402(라이선스)조차 "고장"으로 읽힌다.
async function alertApiError(res, fallback) {
  let msg = fallback;
  try { const d = await res.json(); if (d && d.error) msg = d.error; } catch (_) {}
  alert(msg);
}

// 유료 게이트가 걸린 export는 전부 여기 있어야 한다 — 빠지면 잠금 표시도
// 안 붙고, 키 등록 후 원래 누르려던 export로 되돌아가지도 않는다.
const EXPORT_BTN_IDS = ['downloadCsvBtn', 'downloadWorkbookBtn', 'sevExportBtn',
                        'remExportCsvBtn', 'remExportJsonBtn', 'auditExportBtn'];

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
      btn.title = 'License required — click to purchase or enter key';
    }
  });
}

async function checkLicense() {
  try {
    const r = await fetch('/api/license/status');
    const d = await r.json();
    _licensed = d.licensed === true;
  } catch (_) {
    _licensed = false;
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
  if (!key) { msg.textContent = 'Please enter your license key.'; msg.className = 'lic-msg error'; return; }
  msg.textContent = 'Verifying...'; msg.className = 'lic-msg';
  try {
    const r = await fetch('/api/license/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Activation failed');
    _licensed = true;
    setExportBtnsState(true);
    window.APO?.onLicense?.();   // 상단 상태바·Settings 표시를 즉시 갱신
    msg.textContent = `Activated (${d.email})`;
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
  const url = `${LEMON_CHECKOUT_URL}?checkout[email]=${encodeURIComponent(email)}`;
  // 팝업 차단 우회: 같은 탭에서 이동 후 바로 복귀 가능하도록 새 탭으로 직접 이동
  const a = document.createElement('a');
  a.href = url;
  a.target = '_blank';
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
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
  let diffState = { summary: {}, added_policies: [], removed_policies: [], changed_policies: [], added_objects: [], removed_objects: [], other_changes: [] };
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
    if (titleEl) titleEl.textContent = title || "";
    if (stepEl) stepEl.textContent = step || "";
  }
  const esc = v => String(v == null ? "" : v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const humanizeKey = key => String(key || "").replace(/^firewall_/,"").replace(/^system_/,"").replace(/_/g," ").replace(/-/g," ").replace(/\b\w/g,c=>c.toUpperCase());
  function normalizeValue(value){ if(value==null) return "-"; if(Array.isArray(value)) return value.length?value.join(", "):"-"; if(typeof value==="object") return JSON.stringify(value); const s=String(value).trim(); return s||"-"; }
  function summarizeObjectValue(section,item){ if(!item||typeof item!=="object") return "-"; if(item.subnet_cidr) return item.subnet_cidr; if(Array.isArray(item.subnet)) return item.subnet.join(" "); if(item.start_ip&&item.end_ip) return `${item.start_ip} - ${item.end_ip}`; if(item.fqdn) return item.fqdn; if(item.wildcard_fqdn) return item.wildcard_fqdn; if(Array.isArray(item.member)) return item.member.join(", "); if(Array.isArray(item.resolved_members)&&item.resolved_members.length) return item.resolved_members.join(", "); const ports=[]; if(item.tcp_portrange) ports.push(`TCP ${item.tcp_portrange}`); if(item.udp_portrange) ports.push(`UDP ${item.udp_portrange}`); if(item.sctp_portrange) ports.push(`SCTP ${item.sctp_portrange}`); if(ports.length) return ports.join(" / "); if(item.resolved) return item.resolved; if(item.alias) return `${item.alias} (${item.name||item._edit||""})`; const detail=Object.keys(item).filter(k=>!["name","_edit","uuid","associated-interface"].includes(k)).map(k=>`${humanizeKey(k)}: ${normalizeValue(item[k])}`).join(" | "); return detail||"-"; }
  function buildPolicyChangeList(before, after){ const ignore=new Set(["policy_id","_edit","uuid"]); const keys=new Set([...Object.keys(before||{}),...Object.keys(after||{})]); const changes=[]; keys.forEach(key=>{ if(ignore.has(key)) return; const oldVal=normalizeValue(before?before[key]:null); const newVal=normalizeValue(after?after[key]:null); if(oldVal!==newVal) changes.push({label:humanizeKey(key),before:oldVal,after:newVal}); }); return changes; }
  /* 화면 전환은 shell.js가 소유한다. 여기서는 뷰 목록을 하드코딩하지 않고
     data-view 값과 같은 이름의 섹션을 찾아 켜기만 한다(새 뷰 추가 시 무수정). */
  const VIEW_SECTION={overview:"overviewView",analysis:"analysisView",severity:"severityView",remediation:"remediationView",diff:"diffView",settings:"settingsView",advisor:"severityView"};
  function setView(mode){ if(window.APO&&typeof window.APO.setView==="function"){ window.APO.setView(mode); return; } switchButtons.forEach(b=>b.classList.toggle("active", b.getAttribute("data-view")===mode)); document.querySelectorAll(".page-view").forEach(v=>v.classList.add("hidden")); const target=document.getElementById(VIEW_SECTION[mode]||"overviewView"); target?.classList.remove("hidden"); window.scrollTo({top:0,behavior:"smooth"}); }
  switchButtons.forEach(btn=>btn.addEventListener("click",()=>setView(btn.getAttribute("data-view"))));
  if(oldBtn&&oldInput){ oldBtn.addEventListener("click",()=>oldInput.click()); oldInput.addEventListener("change",()=>{ const f=oldInput.files&&oldInput.files[0]; const label=document.getElementById("selectedOldConfigName"); if(label) label.textContent=f?f.name:"No file selected"; });}
  if(newBtn&&newInput){ newBtn.addEventListener("click",()=>newInput.click()); newInput.addEventListener("change",()=>{ const f=newInput.files&&newInput.files[0]; const label=document.getElementById("selectedNewConfigName"); if(label) label.textContent=f?f.name:"No file selected"; });}
  function renderSummary(){ const s=diffState.summary||{}; const box=document.getElementById("diffSummary"); if(!box) return; const cards=[["Added Policies",s.added_policies||0,"New firewall rules"],["Removed Policies",s.removed_policies||0,"Deleted firewall rules"],["Changed Policies",s.changed_policies||0,"Modified rule attributes"],["Added Objects",s.added_objects||0,"New objects"],["Removed Objects",s.removed_objects||0,"Deleted objects"],["Other Changes",s.other_changes||0,"Profiles, certificates, system settings"]]; box.innerHTML=cards.map(([l,v,d])=>`<div class="stat-card diff-stat-card"><span class="stat-label">${esc(l)}</span><span class="stat-value">${esc(v)}</span><span class="stat-desc">${esc(d)}</span></div>`).join("");}
  function renderOverview(){ const s=diffState.summary||{}; const total=Object.values(s).reduce((a,b)=>a+Number(b||0),0); return `<div class="diff-overview"><div class="overview-main-card"><span class="diff-eyebrow-dark">Analysis Summary</span><h3>${esc(total)} total change groups detected</h3><p>This view summarizes policy, object, and additional configuration changes between the selected baseline and target backups.</p></div><div class="overview-guidance-card"><strong>Recommended Review Flow</strong><ol><li>Review changed policies first.</li><li>Validate added or removed policies.</li><li>Check object changes for IP, service, and group impact.</li><li>Review other configuration changes.</li></ol></div></div>`;}
  function renderPolicyTable(items,title){ return `<div class="diff-section-title"><h3>${esc(title)}</h3><span>${esc(items.length)} item(s)</span></div><div class="table-wrap"><table><thead><tr><th>Policy ID</th><th>Policy Name</th><th>Source</th><th>Destination</th><th>Service</th><th>Schedule</th><th>Action</th></tr></thead><tbody>${items.map(i=>`<tr><td>${esc(i.policy_id||i.id||"-")}</td><td>${esc(i.name||"-")}</td><td>${esc(normalizeValue(i.srcaddr_display||i.srcaddr))}</td><td>${esc(normalizeValue(i.dstaddr_display||i.dstaddr))}</td><td>${esc(normalizeValue(i.service_display||i.service))}</td><td>${esc(normalizeValue(i.schedule))}</td><td>${esc(normalizeValue(i.action))}</td></tr>`).join("")}</tbody></table></div>`;}
  function renderChangedPolicies(items){ return `<div class="diff-section-title"><h3>Changed Policies</h3><span>${esc(items.length)} item(s)</span></div><div class="table-wrap"><table><thead><tr><th>Policy ID</th><th>Policy Name</th><th>Changed Settings</th></tr></thead><tbody>${items.map(item=>{ const before=item.before||{}, after=item.after||{}; const changes=buildPolicyChangeList(before,after); return `<tr><td>${esc(item.policy_id||after.policy_id||before.policy_id||"-")}</td><td>${esc(item.name||after.name||before.name||"-")}</td><td><div class="change-list">${changes.length?changes.map(c=>`<div class="change-row"><div class="change-key">${esc(c.label)}</div><div class="change-values"><span class="change-before">${esc(c.before)}</span><span class="change-arrow">→</span><span class="change-after">${esc(c.after)}</span></div></div>`).join(""):'<span class="muted-inline">No material field change detected.</span>'}</div></td></tr>`;}).join("")}</tbody></table></div>`;}
  function renderObjectTable(items,title){ return `<div class="diff-section-title"><h3>${esc(title)}</h3><span>${esc(items.length)} item(s)</span></div><div class="table-wrap"><table><thead><tr><th>Configuration Area</th><th>Object Name</th><th>Resolved Value / Detail</th></tr></thead><tbody>${items.map(i=>`<tr><td>${esc(humanizeKey(i.section||"-"))}</td><td>${esc(i.name||"-")}</td><td>${esc(summarizeObjectValue(i.section,i.item||{}))}</td></tr>`).join("")}</tbody></table></div>`;}
  function renderOtherChanges(items){ return `<div class="diff-section-title"><h3>Other Configuration Changes</h3><span>${esc(items.length)} section(s)</span></div><div class="other-change-grid">${items.length?items.map(i=>`<div class="other-change-card"><div class="other-change-section">${esc(humanizeKey(i.section||"-"))}</div><div class="other-change-counts"><span>Added: <strong>${esc((i.added||[]).length)}</strong></span><span>Removed: <strong>${esc((i.removed||[]).length)}</strong></span><span>Changed: <strong>${esc((i.changed||[]).length)}</strong></span></div><div class="other-change-detail">${i.added?.length?`<div><b>Added</b>: ${esc(i.added.join(", "))}</div>`:""}${i.removed?.length?`<div><b>Removed</b>: ${esc(i.removed.join(", "))}</div>`:""}${i.changed?.length?`<div><b>Changed</b>: ${esc(i.changed.join(", "))}</div>`:""}</div></div>`).join(""):`<div class="empty-state"><strong>No additional configuration sections changed.</strong><span>Policy and object changes may still exist in their dedicated categories.</span></div>`}</div>`;}
  function renderDiffTab(){ const target=document.getElementById("diffTabContent"); if(!target) return; if(activeDiffTab==="overview") target.innerHTML=renderOverview(); else if(activeDiffTab==="added_policies") target.innerHTML=renderPolicyTable(diffState.added_policies||[],"Added Policies"); else if(activeDiffTab==="removed_policies") target.innerHTML=renderPolicyTable(diffState.removed_policies||[],"Removed Policies"); else if(activeDiffTab==="changed_policies") target.innerHTML=renderChangedPolicies(diffState.changed_policies||[]); else if(activeDiffTab==="added_objects") target.innerHTML=renderObjectTable(diffState.added_objects||[],"Added Objects"); else if(activeDiffTab==="removed_objects") target.innerHTML=renderObjectTable(diffState.removed_objects||[],"Removed Objects"); else if(activeDiffTab==="other_changes") target.innerHTML=renderOtherChanges(diffState.other_changes||[]);}
  document.querySelectorAll("[data-diff-tab]").forEach(btn=>btn.addEventListener("click",()=>{ document.querySelectorAll("[data-diff-tab]").forEach(b=>b.classList.remove("active")); btn.classList.add("active"); activeDiffTab=btn.getAttribute("data-diff-tab")||"overview"; renderDiffTab(); }));
  if(runBtn){ runBtn.addEventListener("click",async()=>{ const oldFile=oldInput&&oldInput.files&&oldInput.files[0]; const newFile=newInput&&newInput.files&&newInput.files[0]; const status=document.getElementById("diffStatus"); if(!oldFile||!newFile){ if(status) status.textContent="Select both baseline and target configuration files."; return;} const fd=new FormData(); fd.append("old_config",oldFile); fd.append("new_config",newFile); if(status) status.textContent="Analyzing configuration changes..."; setDiffProgress(10,"Preparing analysis...","Validating selected configuration files."); setTimeout(()=>setDiffProgress(35,"Uploading files...","Sending baseline and target configurations to the local parser."),120); setTimeout(()=>setDiffProgress(65,"Comparing configuration...","Detecting policy, object, and system-level differences."),360); try{ const res=await fetch("/api/config/diff",{method:"POST",body:fd}); const data=await res.json(); if(!res.ok) throw new Error(data.error||"Configuration comparison failed."); diffState={summary:data.summary||{},added_policies:data.added_policies||[],removed_policies:data.removed_policies||[],changed_policies:data.changed_policies||[],added_objects:data.added_objects||[],removed_objects:data.removed_objects||[],other_changes:data.other_changes||[]}; setDiffProgress(90,"Rendering results...","Preparing categorized comparison results."); renderSummary(); activeDiffTab="overview"; document.querySelectorAll("[data-diff-tab]").forEach(b=>b.classList.remove("active")); document.querySelector('[data-diff-tab="overview"]')?.classList.add("active"); renderDiffTab(); setDiffProgress(100,"Analysis completed.","Configuration change review completed successfully."); if(status) status.textContent="Configuration change review completed successfully."; }catch(err){ if(status) status.textContent=err.message||"Configuration comparison failed."; setDiffProgress(100,"Analysis failed.",err.message||"Configuration comparison failed."); }});}
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
  function resetSeverityResults() {
    sevData = null;
    window.__sevHasData = false;
    activeSevFilter = null;
    activeSevTab = 'firewall';   // 탭 선택도 이전 장비의 상태다
    if (phase2Card) phase2Card.style.display = 'none';
    if (tableCard) tableCard.style.display = 'none';
    const reach = document.getElementById('sevReachCard');
    if (reach) reach.style.display = 'none';
    const verify = document.getElementById('sevVerifyCard');
    if (verify) verify.style.display = 'none';
    /* 카드를 숨기기만 하면 이전 장비의 표가 DOM에 그대로 남는다(페이지 저장·
       소스 보기로 드러난다). 내용까지 비운다.

       FortiOS 자문 패널은 상태를 전부 DOM에만 들고 있어서 따로 지우지 않으면
       B장비 화면에 A장비의 모델·펌웨어·CVE 목록이 그대로 남는다 — 고객이
       보고서에 캡처해 넣는 바로 그 탭이다.
       반대로 감사 타임라인(auditResult)은 별도로 올린 스냅샷들로 만든 것이라
       지금 연 설정과 무관하다. 지우면 사용자가 파일 6개를 다시 고르게 된다. */
    ['sevTableContent', 'sevSummaryBar', 'sevReachContent', 'sevReachCoverage',
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
    const advSt = document.getElementById('advisorStatus');
    if (advSt) advSt.textContent = 'Load a Config File and click Analyze.';
    // FQDN 캐시는 서버가 두 로드 경로 모두에서 버린다. 화면의 "적용됨" 문장만
    // 남으면, 커버리지가 살아 있다고 잘못 알리는 셈이다.
    const fq = document.getElementById('fqdnDumpStatus');
    if (fq) fq.textContent = 'FQDN resolutions were cleared with the previous '
      + 'configuration. Collect from the device or upload a new dnsproxy dump '
      + 'to assess FQDN policies.';
    document.querySelectorAll('.sev-subtab-btn').forEach(b =>
      b.classList.toggle('active', b.dataset.sevTab === 'firewall'));
    if (statusEl) statusEl.textContent = 'Configuration changed — run the assessment again.';
    // shell(상단 상태·Overview·Action Plan)과 장비 적용 후보 목록도 같은 설정에
    // 딸린 결과다. 함께 버린다.
    window.APO?.onStale?.();
    window.__apoResetRemediation?.();
  }
  window.__apoResetSev = resetSeverityResults;

  function renderRangeTags() {
    window.APO?.onRanges?.(userRanges.length);
    if (!rangeTags) return;
    if (!userRanges.length) {
      rangeTags.innerHTML = '<span style="color:var(--muted);font-size:12px">No IP ranges configured — Severity 1/2/7 can still be assessed</span>';
      return;
    }
    rangeTags.innerHTML = userRanges.map((r,i) =>
      `<span class="sev-range-item">${escapeHtml(r.cidr)}<button class="sev-range-del" data-i="${i}">×</button></span>`
    ).join('');
    rangeTags.querySelectorAll('.sev-range-del').forEach(btn => {
      btn.addEventListener('click', () => {
        userRanges.splice(Number(btn.dataset.i), 1);
        renderRangeTags();
      });
    });
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

  function renderTable() {
    if (!tableCard||!tableContent||!sevData) return;
    tableCard.style.display='';
    const policies = sevData[activeSevTab]||[];
    const filtered = activeSevFilter!=null ? policies.filter(p=>(p.urgency??0)===activeSevFilter) : policies;
    if (!filtered.length) {
      tableContent.innerHTML = _otherTabNote()
        + '<div class="empty-state"><strong>No results</strong><span>No policies match the selected criteria on this tab.</span></div>';
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
        <td style="font-size:11px;max-width:140px">${escapeHtml(p.recommended_action||'')}</td>
      </tr>`;
    }).join('');
    tableContent.innerHTML=_otherTabNote()+`<table class="result-table"><thead><tr>
      <th>Sev</th><th>Risk Level</th><th>Tags</th><th>Policy ID</th><th>Name</th>
      <th>Source</th><th>Destination</th>
      <th>Service</th><th>Action</th><th>Status</th><th>Hit Count</th><th>Last Used</th>
      <th>Traffic Type</th><th>Reason</th><th>Recommended Action</th>
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
    ss_schedule_age_years:      document.getElementById('thSchedAge'),
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

  async function loadThresholdDefaults() {
    try {
      const res = await fetch('/api/profile');
      if (!res.ok) return;
      const p = await res.json();
      const nameEl = document.getElementById('sevProfileName');
      if (nameEl) nameEl.textContent = p.name || 'default';
      const th = p.thresholds || {};
      for (const [key, el] of Object.entries(thEls)) {
        if (!el) continue;
        if (el.type === 'checkbox') el.checked = !!th[key];
        else el.value = (th[key] ?? '') === null ? '' : (th[key] ?? '');
      }
      thLoaded = true;
    } catch (_) { /* 프로파일 API 실패 시 서버측 프로파일 값으로 동작 */ }
  }
  loadThresholdDefaults();

  document.querySelectorAll('.th-preset').forEach(btn => {
    btn.addEventListener('click', () => {
      if (thEls.dormancy_days) thEls.dormancy_days.value = btn.dataset.dorm;
      if (thEls.long_dormancy_days) thEls.long_dormancy_days.value = btn.dataset.long;
    });
  });
  const thReset = document.getElementById('thResetBtn');
  if (thReset) thReset.addEventListener('click', () => loadThresholdDefaults());

  // FQDN 캐시 덤프 업로드 — 업로드 후 재분류해야 반영된다
  const fqdnBtn = document.getElementById('fqdnDumpBtn');
  const fqdnFile = document.getElementById('fqdnDumpFile');
  const fqdnSt = document.getElementById('fqdnDumpStatus');
  // 캐시가 갱신되면 곧바로 재분류한다 — 위로 스크롤해 Classify를 다시
  // 누르게 하면 사용자가 반영 여부를 헷갈린다.
  async function applyFqdnCache(d, how) {
    const head = `DNS resolutions ${how}: ${d.names} FQDNs / ${d.ips} IPs (captured ${d.captured_at}).`;
    if (fqdnSt) fqdnSt.textContent = `${head} Re-classifying...`;
    await runClassify();
    /* runClassify는 자기 오류를 삼키므로(상태줄에만 남긴다) 무조건 "적용됨"이라고
       쓰면, config가 없어 분류가 실패한 상황에서도 커버리지가 열렸다고 알린다.
       분류 결과가 실제로 생겼는지 보고 문구를 정한다. */
    if (!fqdnSt) return;
    fqdnSt.textContent = window.__sevHasData
      ? `${head} Applied — FQDN policies are now assessed.`
      : `${head} Not applied yet — load a configuration and run the assessment.`;
  }

  if (fqdnBtn) fqdnBtn.addEventListener('click', () => fqdnFile?.click());
  if (fqdnFile) fqdnFile.addEventListener('change', async () => {
    const f = fqdnFile.files?.[0];
    if (!f) return;
    const fd = new FormData();
    fd.append('dump', f);
    if (fqdnSt) fqdnSt.textContent = 'Reading dump...';
    try {
      const res = await fetch('/api/fqdn-cache/import', {method: 'POST', body: fd});
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || 'Import failed');
      await applyFqdnCache(d, 'loaded from file');
    } catch (err) { if (fqdnSt) fqdnSt.textContent = err.message || 'Import failed'; }
    fqdnFile.value = '';
  });

  const fqdnFetch = document.getElementById('fqdnFetchBtn');
  if (fqdnFetch) fqdnFetch.addEventListener('click', async () => {
    if (fqdnSt) fqdnSt.textContent = 'Fetching FQDN resolutions from the device...';
    fqdnFetch.disabled = true;
    try {
      const res = await fetch('/api/fqdn-cache/fetch-device', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({}),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || 'Fetch failed');
      await applyFqdnCache(d, 'fetched from device');
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
      `${unreachable.length} unreachable · assessed ${reach.checked}/${reach.total_enabled} enabled policies · ${skipped.length} skipped`;
    let html = '';
    if (unreachable.length) {
      const cap = reach.fqdn_captured_at;
      html += `<table class="result-table"><thead><tr>
        <th>Policy ID</th><th>Name</th><th>Shadowed By</th><th>Shadower Name</th><th>Shadower Action</th><th>Proof</th>
      </tr></thead><tbody>` + unreachable.map(u => `<tr>
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
        <table class="result-table" style="margin-top:8px"><thead><tr><th>Policy ID</th><th>Name</th><th>Reason</th></tr></thead><tbody>` +
        skipped.map(s => `<tr><td>${escapeHtml(String(s.policy_id??''))}</td><td>${escapeHtml(s.name||'')}</td><td>${escapeHtml(s.reason||'')}</td></tr>`).join('') +
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
      if (list.length < 2) { if (st) st.textContent = 'Select at least two snapshots (oldest first).'; return; }
      if (st) st.textContent = 'Building timeline...';
      const fd = new FormData();
      list.forEach(f => fd.append('snapshots', f));
      try {
        const res = await fetch('/api/audit/timeline', {method: 'POST', body: fd});
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Timeline failed');
        hasTimeline = true;
        if (exp) exp.style.display = '';
        if (st) st.textContent = `${data.snapshots.length} snapshots, ${data.intervals.length} interval(s).`;
        if (out) out.innerHTML = `<table class="result-table"><thead><tr>
          <th>#</th><th>From → To</th><th>Policies added</th><th>Policies removed</th><th>Policies modified</th><th>Objects added / removed</th><th>Modified policy IDs</th>
        </tr></thead><tbody>` + data.intervals.map((iv, i) => {
          const s2 = iv.summary || {};
          return `<tr><td>${i + 1}</td>
            <td>${escapeHtml(iv.from)} → ${escapeHtml(iv.to)}</td>
            <td>${s2.added_policies}</td><td>${s2.removed_policies}</td><td>${s2.changed_policies}</td>
            <td>${s2.added_objects} added / ${s2.removed_objects} removed</td>
            <td style="font-size:11px;max-width:220px">${escapeHtml((s2.changed_ids || []).join(', '))}</td></tr>`;
        }).join('') + '</tbody></table>';
      } catch (err) { if (st) st.textContent = err.message || 'Failed'; }
    });
    if (exp) exp.addEventListener('click', async () => {
      if (!hasTimeline) return;
      if (!(await licenseGate())) return;
      const res = await fetch('/api/audit/evidence-workbook', {method: 'POST'});
      if (!res.ok) { await alertApiError(res, 'Evidence export failed.'); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'apo_review_evidence.xlsx'; a.click();
      URL.revokeObjectURL(url);
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

  // ── 정확도 검증 워크플로우 ─────────────────────────────────────────
  const vStatus = document.getElementById('verifyStatus');
  const vResult = document.getElementById('verifyResult');

  async function downloadSample(fmt) {
    if (vStatus) vStatus.textContent = 'Generating sample...';
    try {
      const res = await fetch('/api/verification/sample?format=' + fmt, {method:'POST'});
      if (!res.ok) { await alertApiError(res, 'Failed to generate sample.'); if (vStatus) vStatus.textContent=''; return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'apo_verification_sample.' + fmt; a.click();
      URL.revokeObjectURL(url);
      if (vStatus) vStatus.textContent = 'Sample downloaded. Run the listed commands on your firewall, fill in the last three columns, then upload the sheet back here.';
    } catch (err) { if (vStatus) vStatus.textContent = err.message || 'Failed'; }
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
    html += `<p class="sev-guide-note"><strong>Overall precision: ${pct(o.precision)}</strong> (${o.match} match / ${o.mismatch} mismatch across ${o.judged} judged samples). Held and unfilled rows are excluded from the denominator.</p>`;
    if ((stats.weak_levels || []).length) {
      html += `<p class="sev-guide-note">⚠ Levels ${stats.weak_levels.map(escapeHtml).join(', ')} have fewer than 5 judged samples — treat those numbers as indicative, not conclusive.</p>`;
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
    if (vStatus) vStatus.textContent = 'Scoring...';
    const fd = new FormData();
    fd.append('worksheet', file);
    try {
      const res = await fetch('/api/verification/score', {method:'POST', body: fd});
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Scoring failed');
      renderPrecision(data);
      if (vStatus) vStatus.textContent = 'Scored.';
    } catch (err) { if (vStatus) vStatus.textContent = err.message || 'Failed'; }
    vUpFile.value = '';
  });

  async function runClassify() {
    if (statusEl) statusEl.textContent='Classifying...';
    try {
      const rangeRes = await fetch('/api/user-ranges/set',{
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ranges:userRanges.map(r=>r.cidr)}),
      });
      // 범위 설정이 실패했는데 분류를 계속하면 traffic type이 전부 Unknown이
      // 되어 조용히 틀린 결과가 나온다(감사 C3). 여기서 멈춘다.
      if (!rangeRes.ok) throw new Error('Failed to set User IP ranges — classification aborted.');
      // 패널 기본값을 아직 못 읽었으면 임계값을 보내지 않는다 —
      // 비어 있는 값이 프로파일 설정을 null로 덮어쓰는 것을 막는다.
      const res = await fetch('/api/severity/classify',{
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify(thLoaded ? {thresholds: collectThresholds()} : {}),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error||'Classification failed');
      sevData=data;
      window.__sevHasData = true;   // CSV 임포트 후 자동 재분류 트리거용(스코프 밖 접근)
      renderSummaryBar(data); renderTable(); renderReachability(data.reachability);
      window.APO?.onFindings?.(data);
      const vc = document.getElementById('sevVerifyCard');
      if (vc) vc.style.display='';   // 분류가 있어야 표본 추출이 의미 있다
      const total=(data.firewall||[]).length+(data.proxy||[]).length;
      if (statusEl) statusEl.textContent=`Classification complete — ${total} policies processed.`;
    } catch(err) {
      /* 실패한 시도는 "결과 있음"으로 남으면 안 된다 — FQDN 임포트가 그 플래그를
         보고 "적용됨"이라고 잘못 알렸다.
         단, **시작 시점에 내리면 안 된다**: 이 플래그는 CSV 임포트의 자동
         재분류 트리거이기도 해서(app.js의 importPolicyCsv), 분류가 도는 동안
         false로 두면 그사이 올린 두 번째 CSV가 재분류를 건너뛴다. 그래서
         실패했을 때만 내린다. */
      window.__sevHasData = false;
      if (statusEl) statusEl.textContent=err.message||'Failed';
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
        const lines = (e.target.result || '').split(/\r?\n/);
        let added = 0;
        for (const raw of lines) {
          // "10.99.240.0./21" 같은 오탈자 처리: 슬래시 직전 점 제거
          const cidr = raw.trim().replace(/\.+\//g, '/');
          if (!cidr || !cidr.includes('/')) continue;
          userRanges.push({ cidr });
          added++;
        }
        renderRangeTags();
        if (added > 0) {
          await syncToServer();
          if (statusEl) statusEl.textContent = `${added} IP range(s) imported successfully.`;
        }
        importFile.value = '';
      };
      reader.readAsText(file, 'UTF-8');
    });
  }

  if (rangeAddBtn) rangeAddBtn.addEventListener('click',()=>{
    const v=rangeInput?.value.trim(); if(!v) return;
    userRanges.push({cidr:v}); if(rangeInput) rangeInput.value='';
    renderRangeTags();
  });
  if (rangeInput) rangeInput.addEventListener('keydown',e=>{ if(e.key==='Enter') rangeAddBtn?.click(); });
  if (classifyBtn) classifyBtn.addEventListener('click',runClassify);

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
      body:JSON.stringify(sevData),
    });
    if (!res.ok){ await alertApiError(res, 'Export failed.'); return; }
    const blob=await res.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url; a.download='severity_export.xlsx'; a.click();
    URL.revokeObjectURL(url);
  });

  renderRangeTags();
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

  function renderSummaryBar(data){
    const bar = document.getElementById('advisorSummaryBar');
    if(!bar) return;
    const s = data.summary || {};
    bar.innerHTML = [
      ['Active CVEs', s.unpatched_cves||0, s.unpatched_cves>0?'tile-danger':'tile-success'],
      ['Known Issues', s.known_issues||0, s.known_issues>0?'tile-warning':'tile-success'],
      ['Fix Versions Available', s.upgrade_fix_versions||0, ''],
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
      el.innerHTML = '<div class="empty-state"><strong>None</strong><span>No items for this version.</span></div>';
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
      el.innerHTML = '<div class="empty-state"><strong>None</strong><span>No items for this version.</span></div>';
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
      el.innerHTML = '<div class="empty-state"><strong>None</strong><span>No newer patch versions available in DB.</span></div>';
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
    if(statusEl) statusEl.textContent = 'Analyzing...';
    if(verBox) verBox.innerHTML = '';
    if(resultCard) resultCard.style.display = 'none';

    try {
      const res = await fetch('/api/version-advisor');
      const data = await res.json();

      if(data.error){
        const dbg = data.debug || {};
        const meta = dbg.meta || {};
        let msg = data.error;
        if(meta.config_version) msg += ` (detected: "${meta.config_version}")`;
        else if(meta.buildno) msg += ` (buildno: ${meta.buildno}, branch unknown)`;
        else msg += ' — Missing #config-version= or #buildno= line in config file.';
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
            <div class="stat-card"><span class="stat-label">Version</span><span class="stat-value" style="font-size:18px">${esc(vi.version||vi.branch||'-')}</span></div>
            <div class="stat-card"><span class="stat-label">Build</span><span class="stat-value" style="font-size:18px">${esc(vi.build||'-')}</span></div>
          </div>
          ${featureTags}`;
      }

      renderSummaryBar(data);
      renderCveTable(data.unpatched_cves||[], 'advisorCveTable', false);
      renderBugTable(data.known_issues||[], 'advisorKnownTable');
      renderFixGroups(data.upgrade_fixes||[]);

      const cveCount = document.getElementById('advisorCveCount');
      const fixCount = document.getElementById('advisorFixCount');
      const knownCount = document.getElementById('advisorKnownCount');
      if(cveCount) cveCount.textContent = (data.unpatched_cves||[]).length;
      if(fixCount) fixCount.textContent = (data.upgrade_fixes||[]).reduce((s,g)=>s+(g.resolved||[]).length,0);
      if(knownCount) knownCount.textContent = (data.known_issues||[]).length;

      if(resultCard) resultCard.style.display = '';
      const s = data.summary || {};
      if(statusEl) statusEl.textContent =
        `Analysis complete — ${s.unpatched_cves||0} active CVE(s), ${s.known_issues||0} known issue(s).`;

    } catch(err){
      if(statusEl) statusEl.textContent = 'Analysis failed: ' + (err.message||err);
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
    // 확인 모달이 열려 있었다면 그 안의 목록도 이미 무효다. Confirm에 이전
    // 선택이 클로저로 묶여 있으므로 닫고 핸들러도 떼어 낸다.
    const modal = $('remModal');
    if (modal) { modal.classList.add('hidden'); const c = $('remModalConfirm'); if (c) c.onclick = null; }
    const st = $('remLoadStatus');
    if (st) st.textContent = 'Configuration changed — load the candidates again.';
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
    };
    if(!payload.ip || !payload.token){ setDevStatus('IP and API Token are required.', false); return; }
    const r = await fetch('/api/remediation/device', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const d = await r.json();
    _connectionOk = false;
    updateApplyBtn();
    setDevStatus(d.ok ? 'Device saved. Run Test Connection to verify.' : (d.error||'Save failed.'), d.ok ? null : false);
  });

  $('remTestBtn')?.addEventListener('click', async () => {
    setDevStatus('Testing connection...', null);
    const r = await fetch('/api/remediation/device/test');
    const d = await r.json();
    _connectionOk = d.ok === true;
    updateApplyBtn();
    setDevStatus(d.message || (d.ok ? 'Connected' : 'Failed'), d.ok);
  });

  function setDevStatus(msg, ok){
    const el = $('remDeviceStatus'); if(!el) return;
    el.textContent = msg;
    el.className = 'rem-status-msg ' + (ok === true ? 'rem-ok' : ok === false ? 'rem-err' : '');
  }

  // ── 후보 로드 ─────────────────────────────────────────────────────────────
  $('remLoadBtn')?.addEventListener('click', loadCandidates);

  async function loadCandidates(){
    const statusEl = $('remLoadStatus');
    if(statusEl) statusEl.textContent = 'Loading...';
    try {
      const r = await fetch('/api/remediation/candidates');
      const d = await r.json();
      if(d.error){ if(statusEl) statusEl.textContent = d.error; return; }
      // 목록이 갈릴 때마다 세대를 올린다 — 대기 중이던 확인창이 옛 선택으로
      // 되살아나는 것을 막는 건 이 카운터뿐이다.
      _candidatesGen += 1;
      _candidates = d;
      // 새 목록에는 아무것도 선택돼 있지 않다. Select All 체크가 남으면 다음
      // 클릭이 '해제'로 잡혀 아무 일도 안 일어난다(두 번 눌러야 한다).
      const chkAll = $('remCheckAll'); if (chkAll) chkAll.checked = false;
      const critical = d.to_disable.filter(p => p.urgency === 1);
      const high     = d.to_disable.filter(p => p.urgency === 2);
      renderCriticalTable(critical);
      renderHighTable(high);
      renderDisabledTable(d.already_disabled);
      const hasActive = d.to_disable.length > 0;
      $('remActiveHeader').style.display   = hasActive ? '' : 'none';
      $('remCriticalSection').style.display = critical.length  ? '' : 'none';
      $('remHighSection').style.display     = high.length      ? '' : 'none';
      $('remDisabledSection').style.display = d.already_disabled.length ? '' : 'none';
      const cc = $('remCriticalCount');
      const hc = $('remHighCount');
      const dc = $('remDisabledCount');
      if(cc) cc.textContent = `(${critical.length})`;
      if(hc) hc.textContent = `(${high.length})`;
      if(dc) dc.textContent = `(${d.already_disabled.length})`;
      const total = d.to_disable.length + d.already_disabled.length;
      const msg = `Total Critical/High: ${total}  |  Critical: ${critical.length}  |  High: ${high.length}  |  Already disabled: ${d.already_disabled.length}`;
      if(statusEl) statusEl.textContent = msg;
    } catch(e) {
      if(statusEl) statusEl.textContent = 'Load failed: ' + e.message;
    }
  }

  function _remRow(p){
    return `<tr>
      <td><input type="checkbox" class="rem-check" data-id="${esc(p.policy_id)}" data-type="${esc(p.type||'firewall')}"></td>
      <td>${esc(p.policy_id)}</td>
      <td>${esc(p.name)}</td>
      <td><span class="rem-risk ${riskClass(p.risk_level)}">${esc(p.risk_level)}</span></td>
      <td class="rem-td-muted">${esc(p.srcaddr||'—')}</td>
      <td class="rem-td-muted">${esc(p.dstaddr||'—')}</td>
      <td class="rem-td-muted">${esc(p.service||'—')}</td>
      <td class="rem-td-muted">${esc(p.schedule||'—')}</td>
      <td class="rem-td-reason">${esc(p.reason)}</td>
    </tr>`;
  }
  function renderCriticalTable(rows){
    const tbody = document.querySelector('#remCriticalTable tbody'); if(!tbody) return;
    tbody.innerHTML = rows.map(_remRow).join('');
    updateApplyBtn();
    document.querySelectorAll('.rem-check').forEach(cb => cb.addEventListener('change', updateApplyBtn));
  }
  function renderHighTable(rows){
    const tbody = document.querySelector('#remHighTable tbody'); if(!tbody) return;
    tbody.innerHTML = rows.map(_remRow).join('');
    updateApplyBtn();
    document.querySelectorAll('.rem-check').forEach(cb => cb.addEventListener('change', updateApplyBtn));
  }

  function _selectedKeys(){
    return [...document.querySelectorAll('.rem-check:checked')].map(cb => `${cb.dataset.id}|${cb.dataset.type||'firewall'}`);
  }
  function _filterBySelection(keys){
    return _candidates.to_disable.filter(p => keys.includes(`${p.policy_id}|${p.type||'firewall'}`));
  }

  function renderDisabledTable(rows){
    const tbody = document.querySelector('#remDisabledTable tbody'); if(!tbody) return;
    tbody.innerHTML = rows.map(p => `
      <tr>
        <td>${esc(p.policy_id)}</td>
        <td>${esc(p.name)}</td>
        <td><span class="rem-risk ${riskClass(p.risk_level)}">${esc(p.risk_level||'—')}</span></td>
        <td class="rem-td-muted">${esc(p.srcaddr||'—')}</td>
        <td class="rem-td-muted">${esc(p.dstaddr||'—')}</td>
        <td class="rem-td-muted">${esc(p.service||'—')}</td>
        <td class="rem-td-muted">${esc(p.schedule||'—')}</td>
        <td class="rem-td-reason">${esc(p.reason)}</td>
      </tr>`).join('');
  }

  // 전체 선택
  $('remCheckAll')?.addEventListener('change', e => {
    document.querySelectorAll('.rem-check').forEach(cb => { cb.checked = e.target.checked; });
    updateApplyBtn();
  });

  function updateApplyBtn(){
    const all     = [...document.querySelectorAll('.rem-check')];
    const checked = all.filter(cb => cb.checked);
    const applyBtn    = $('remApplyBtn');
    const countEl   = $('remSelectedCount');
    if(countEl) countEl.textContent = `${checked.length} / ${all.length} selected`;
    const hasChecked = checked.length > 0;
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
    try { dev = await (await fetch('/api/remediation/device')).json(); } catch(_) {}
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
    const idList = selectedPolicies.map(p => p.policy_id);
    const ids = idList.length > 12
      ? `${idList.slice(0, 12).join(', ')} and ${idList.length - 12} more`
      : idList.join(', ');
    $('remModalMsg').textContent =
      `Disable ${selectedPolicies.length} policy(ies) on ${dev.ip}:${dev.port}`
      + (vdom ? ` (VDOM ${vdom})` : '')
      + `: ${ids}.`
      + (src ? `
Candidates came from the configuration currently loaded (${src}).` : '')
      + ` This is applied immediately and cannot be undone from this tool.`;
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
    if(statusEl) statusEl.textContent = 'Applying...';
    try {
      const r = await fetch('/api/remediation/apply', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({policies})
      });
      const d = await r.json();
      if(d.error){ if(statusEl) statusEl.textContent = d.error; return; }
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
      const done = `Apply complete — ${ok} succeeded, ${fail} failed. See results below.`;
      /* 재로드 실패가 바깥 catch로 새어 나가면 "Apply failed"로 보고된다 —
         장비에는 이미 반영됐는데. 쓰기 결과와 재로드 결과를 분리한다. */
      if (stale) {
        if(statusEl) statusEl.textContent =
          `${done} The configuration changed while applying — reload the candidates.`;
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
        updateApplyBtn();
        if(statusEl) statusEl.textContent =
          `${done} Could not refresh the candidate list — reload it before applying anything else.`;
        return;
      }
      if(statusEl) statusEl.textContent = `${done} ${statusEl.textContent}`;
    } catch(e) {
      if(statusEl) statusEl.textContent = 'Apply failed: ' + e.message;
    }
  }

  function renderApplyResults(results){
    const card = $('remResultCard');
    const body = $('remResultBody');
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
  $('remExportCsvBtn')?.addEventListener('click', async () => {
    if (!(await licenseGate())) return;   // 라이선스 확인
    const r = await fetch('/api/remediation/export/csv', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({to_disable: _candidates.to_disable, already_disabled: _candidates.already_disabled})
    });
    if(!r.ok){ await alertApiError(r, 'CSV export failed'); return; }
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = r.headers.get('Content-Disposition')?.split('filename=')[1] || 'remediation.csv';
    a.click(); URL.revokeObjectURL(url);
  });

  $('remExportJsonBtn')?.addEventListener('click', async () => {
    if (!(await licenseGate())) return;   // 라이선스 확인
    const selectedKeys = _selectedKeys();
    if(!selectedKeys.length){ alert('Select at least one policy to export.'); return; }
    const policies = _filterBySelection(selectedKeys);
    const r = await fetch('/api/remediation/export/postman', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({policies})
    });
    if(!r.ok){ await alertApiError(r, 'JSON export failed'); return; }
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = r.headers.get('Content-Disposition')?.split('filename=')[1] || 'remediation.postman_collection.json';
    a.click(); URL.revokeObjectURL(url);
  });
})();

