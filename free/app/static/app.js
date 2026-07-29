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
  metaBox.innerHTML = items.map(([label, value]) => `
    <div class="stat-card">
      <span class="stat-label">${escapeHtml(label)}</span>
      <strong class="stat-value">${escapeHtml(String(value))}</strong>
    </div>
  `).join('');
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
  const fullYear = yy >= 70 ? 1900 + yy : 2000 + yy;
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
  if (!res.ok) { alert('Failed to build workbook export.'); return; }
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
const EXPORT_BTN_IDS = ['downloadCsvBtn', 'downloadWorkbookBtn', 'sevExportBtn', 'remExportCsvBtn', 'remExportJsonBtn'];

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
    msg.textContent = `Activated (${d.email})`;
    msg.className = 'lic-msg success';
    const resumeId = _pendingExportBtnId;   // 게이트를 띄운 원래 export 버튼
    _pendingExportBtnId = null;
    setTimeout(() => {
      hideLicenseModal();
      document.getElementById(resumeId || 'downloadWorkbookBtn')?.click();
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
  function setView(mode){ switchButtons.forEach(b=>b.classList.toggle("active", b.getAttribute("data-view")===mode)); const sevView=document.getElementById("severityView"); const advView=document.getElementById("advisorView"); const remView=document.getElementById("remediationView"); const allViews=[analysisView,diffView,sevView,advView,remView]; allViews.forEach(v=>v?.classList.add("hidden")); if(mode==="diff"){ diffView?.classList.remove("hidden"); } else if(mode==="severity"){ sevView?.classList.remove("hidden"); } else if(mode==="advisor"){ advView?.classList.remove("hidden"); } else if(mode==="remediation"){ remView?.classList.remove("hidden"); } else { analysisView?.classList.remove("hidden"); } window.scrollTo({top:0,behavior:"smooth"}); }
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

  function renderRangeTags() {
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

  function renderTable() {
    if (!tableCard||!tableContent||!sevData) return;
    tableCard.style.display='';
    const policies = sevData[activeSevTab]||[];
    const filtered = activeSevFilter!=null ? policies.filter(p=>(p.urgency??0)===activeSevFilter) : policies;
    if (!filtered.length) {
      tableContent.innerHTML='<div class="empty-state"><strong>No results</strong><span>No policies match the selected criteria.</span></div>';
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
    tableContent.innerHTML=`<table class="result-table"><thead><tr>
      <th>Sev</th><th>Risk Level</th><th>Tags</th><th>Policy ID</th><th>Name</th>
      <th>Source</th><th>Destination</th>
      <th>Service</th><th>Action</th><th>Status</th><th>Hit Count</th><th>Last Used</th>
      <th>Traffic Type</th><th>Reason</th><th>Recommended Action</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
  }

  async function runClassify() {
    if (statusEl) statusEl.textContent='Classifying...';
    try {
      await fetch('/api/user-ranges/set',{
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ranges:userRanges.map(r=>r.cidr)}),
      });
      const res = await fetch('/api/severity/classify',{method:'POST'});
      const data = await res.json();
      if (!res.ok) throw new Error(data.error||'Classification failed');
      sevData=data;
      window.__sevHasData = true;   // CSV 임포트 후 자동 재분류 트리거용(스코프 밖 접근)
      renderSummaryBar(data); renderTable();
      const total=(data.firewall||[]).length+(data.proxy||[]).length;
      if (statusEl) statusEl.textContent=`Classification complete — ${total} policies processed.`;
    } catch(err) {
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
    if (!res.ok){alert('Export failed.');return;}
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
      _candidates = d;
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
  $('remApplyBtn')?.addEventListener('click', () => {
    const selectedKeys = _selectedKeys();
    if(!selectedKeys.length) return;
    const selectedPolicies = _filterBySelection(selectedKeys);
    $('remModalMsg').textContent = `${selectedPolicies.length} policy(ies) will be disabled. This will be applied to the device immediately and cannot be undone from this tool.`;
    $('remModal').classList.remove('hidden');
    $('remModalConfirm').onclick = () => applyDisable(selectedPolicies);
    $('remModalCancel').onclick  = () => $('remModal').classList.add('hidden');
  });

  async function applyDisable(policies){
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
      renderApplyResults(d.results||[]);
      if(statusEl) statusEl.textContent = 'Apply complete. See results below.';
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
    if(!r.ok){ alert('CSV export failed'); return; }
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
    if(!r.ok){ alert('JSON export failed'); return; }
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = r.headers.get('Content-Disposition')?.split('filename=')[1] || 'remediation.postman_collection.json';
    a.click(); URL.revokeObjectURL(url);
  });
})();

