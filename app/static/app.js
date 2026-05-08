let currentParsed = null;
let currentView = null;
let currentRuntimeStats = {};
let activeTab = 'firewall_policy';

const configFileInput = document.getElementById('configFile');
const policyStatsFilesInput = document.getElementById('policyStatsFiles');
const configPickerBtn = document.getElementById('configPickerBtn');
const policyCsvPickerBtn = document.getElementById('policyCsvPickerBtn');
const selectedConfigName = document.getElementById('selectedConfigName');
const selectedPolicyCsvName = document.getElementById('selectedPolicyCsvName');
const configStatus = document.getElementById('configStatus');
const policyStatsStatus = document.getElementById('policyStatsStatus');
const policyCsvSummary = document.getElementById('policyCsvSummary');
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

function hasNoRitm(item) {
  return !String(item.name || '').toUpperCase().includes('RITM');
}

function isNoItsRequest(item) {
  return hasNoName(item) || hasNoRitm(item);
}

function noItsReason(item) {
  const noName = hasNoName(item);
  const noRitm = hasNoRitm(item);
  if (noName && noRitm) return 'No Policy Name, No RITM';
  if (noName) return 'No Policy Name';
  if (noRitm) return 'No RITM';
  return '';
}

const TAB_DEFS = {
  firewall_policy: {
    sheet: 'Firewall Policy',
    filename: 'firewall_policy',
    columns: [
      ['Policy ID', i => i.policy_id ?? ''],
      ['Name', i => i.name || ''],
      ['RITM', i => i.ritm || ''],
      ['Request Date', i => i.request_date || ''],
      ['Requester', i => i.requester || ''],
      ['Controlled', i => i.is_controlled ? 'Yes' : ''],
      ['Status', i => i.status || ''],
      ['Source Interface', i => joinList(i.srcintf_display)],
      ['Destination Interface', i => joinList(i.dstintf_display)],
      ['Source Address', i => joinList(i.srcaddr_display)],
      ['Destination Address', i => joinList(i.dstaddr_display)],
      ['Service', i => joinList(i.service_display)],
      ['Schedule', i => i.schedule || ''],
      ['Action', i => i.action || ''],
      ['Hit Count', i => i.hit_count ?? 0],
      ['Last Used', i => i.last_used || '-'],
      ['No ITS Request Reason', i => noItsReason(i)],
    ],
  },
  firewall_proxy_policy: {
    sheet: 'Firewall Proxy Policy',
    filename: 'firewall_proxy_policy',
    columns: [
      ['Policy ID', i => i.policy_id ?? ''],
      ['Name', i => i.name || ''],
      ['RITM', i => i.ritm || ''],
      ['Request Date', i => i.request_date || ''],
      ['Requester', i => i.requester || ''],
      ['Controlled', i => i.is_controlled ? 'Yes' : ''],
      ['Status', i => i.status || ''],
      ['Source Interface', i => joinList(i.srcintf_display)],
      ['Destination Interface', i => joinList(i.dstintf_display)],
      ['Source Address', i => joinList(i.srcaddr_display)],
      ['Destination Address', i => joinList(i.dstaddr_display)],
      ['Service', i => joinList(i.service_display)],
      ['Schedule', i => i.schedule || ''],
      ['Action', i => i.action || ''],
      ['Hit Count', i => i.hit_count ?? 0],
      ['Last Used', i => i.last_used || '-'],
      ['No ITS Request Reason', i => noItsReason(i)],
    ],
  },
  firewall_multicast_policy: {
    sheet: 'Multicast Policy',
    filename: 'firewall_multicast_policy',
    columns: [
      ['Policy ID', i => i.policy_id ?? ''],
      ['Name', i => i.name || ''],
      ['RITM', i => i.ritm || ''],
      ['Request Date', i => i.request_date || ''],
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
policyCsvPickerBtn.addEventListener('click', () => policyStatsFilesInput.click());

configFileInput.addEventListener('change', async () => {
  const file = configFileInput.files?.[0];
  selectedConfigName.textContent = file ? file.name : 'No file selected';
  if (!file) return;

  const formData = new FormData();
  formData.append('config_file', file);
  configStatus.textContent = 'Parsing config...';

  const res = await fetch('/api/config/parse', { method: 'POST', body: formData });
  const data = await res.json();

  if (!res.ok) {
    configStatus.textContent = data.error || 'Failed to parse config';
    return;
  }

  currentParsed = data.parsed;
  currentView = data.view;
  currentRuntimeStats = {};
  resetPolicyFilters();
  configStatus.textContent = `Loaded ${data.filename}`;
  policyStatsStatus.textContent = 'Import GUI policy CSV to merge Last Used, Hit Count, and Status.';
  policyCsvSummary.innerHTML = '';
  downloadBox.innerHTML = `<a href="/exports/${data.export_json}">Download parsed JSON</a>`;
  renderMeta(data.view?.meta || {});
  updatePolicyFilterVisibility();
  renderActiveTab();
});

policyStatsFilesInput.addEventListener('change', async () => {
  const file = policyStatsFilesInput.files?.[0];
  selectedPolicyCsvName.textContent = file ? file.name : 'No file selected';
  if (!file) return;

  const formData = new FormData();
  formData.append('policy_stats_files', file);

  policyStatsStatus.textContent = 'Importing policy CSV stats...';

  const res = await fetch('/api/policy-stats/import', { method: 'POST', body: formData });
  const data = await res.json();

  if (!res.ok) {
    policyStatsStatus.textContent = data.error || 'Failed to import policy CSV stats';
    return;
  }

  currentRuntimeStats = { ...currentRuntimeStats, ...(data.runtime_stats || {}) };
  renderPolicyCsvSummary(data.summary || {}, file.name);
  policyStatsStatus.textContent = `Merged GUI policy CSV from ${file.name}`;
  await rerenderWithRuntimeStats();
});

async function rerenderWithRuntimeStats() {
  if (!currentParsed) return;
  const renderRes = await fetch('/api/policies/render', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ parsed: currentParsed, runtime_stats: currentRuntimeStats })
  });
  const renderData = await renderRes.json();
  currentView = renderData.view;
  renderMeta(renderData.view?.meta || {});
  renderActiveTab();
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

function renderPolicyCsvSummary(summary, filename) {
  const items = [
    ['File', filename || '-'],
    ['Rows Loaded', summary.count ?? 0],
    ['First Policy ID', summary.matched_policy_ids?.[0] || '-'],
    ['Last Policy ID', summary.matched_policy_ids?.slice(-1)[0] || '-'],
  ];
  policyCsvSummary.innerHTML = items.map(([label, value]) => `
    <div class="stat-card compact">
      <span class="stat-label">${escapeHtml(label)}</span>
      <strong class="stat-value">${escapeHtml(String(value))}</strong>
    </div>
  `).join('');
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
      items = items.filter(item => Number(item.hit_count || 0) === 0);
    }

    if (filterDormantYear.checked) {
      items = items.filter(isDormantOneYear);
    }
    if (filterExpiredSchedule.checked) {
      items = items.filter(isExpiredSchedulePolicy);
    }
    if (filterNoItsRequest.checked) {
      items = items.filter(isNoItsRequest);
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
    const flags = [];
    if (isExpiredSchedulePolicy(item)) flags.push('<span class="mini-flag warn">Expired schedule</span>');
    if (isDormantOneYear(item)) flags.push('<span class="mini-flag cool">Last used > 1y</span>');
    if (isNoItsRequest(item)) flags.push(`<span class="mini-flag neutral">No ITS Request: ${escapeHtml(noItsReason(item))}</span>`);
    if (isDisabledPolicy(item) || isExpiredSchedulePolicy(item)) flags.push('<span class="mini-flag danger">Deletable</span>');

    return `
    <tr>
      <td>${escapeHtml(item.policy_id ?? '')}</td>
      <td>
        <div class="policy-name-cell">
          <div>${escapeHtml(item.name || '') || '<span class="muted">-</span>'}</div>
          ${flags.length ? `<div class="flag-strip">${flags.join('')}</div>` : ''}
        </div>
      </td>
      <td>${renderStatusBadge(item.status || '')}</td>
      <td>${renderList(item.srcintf_display)}</td>
      <td>${renderList(item.dstintf_display)}</td>
      <td>${renderList(item.srcaddr_display)}</td>
      <td>${renderList(item.dstaddr_display)}</td>
      <td>${renderList(item.service_display)}</td>
      <td>${escapeHtml(item.schedule || '')}</td>
      <td>${escapeHtml(item.action || '')}</td>
      <td>${escapeHtml(String(item.hit_count ?? 0))}</td>
      <td>${escapeHtml(item.last_used || '-')}</td>
      <td>${escapeHtml(noItsReason(item))}</td>
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
        <th>No ITS Reason</th>
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
      <td>${escapeHtml(item.ritm || '')}</td>
      <td>${escapeHtml(item.request_date || '')}</td>
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
        <th>Policy ID</th><th>Name</th><th>RITM</th><th>Request Date</th>
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

downloadCsvBtn.addEventListener('click', () => {
  if (!currentView) return;
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
  if (!res.ok) {
    alert('Failed to build workbook export.');
    return;
  }
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
  function setView(mode){ switchButtons.forEach(b=>b.classList.toggle("active", b.getAttribute("data-view")===mode)); const sevView=document.getElementById("severityView"); if(mode==="diff"){ analysisView?.classList.add("hidden"); diffView?.classList.remove("hidden"); sevView?.classList.add("hidden"); } else if(mode==="severity"){ analysisView?.classList.add("hidden"); diffView?.classList.add("hidden"); sevView?.classList.remove("hidden"); } else { diffView?.classList.add("hidden"); sevView?.classList.add("hidden"); analysisView?.classList.remove("hidden"); } window.scrollTo({top:0,behavior:"smooth"}); }
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
    "No ITS Request":   "tag-amber",
    "Temp Rule":        "tag-red",
    "Risky Service":    "tag-red",
    "Deny Rule":        "tag-green",
    "ICMP Only":        "tag-green",
  };
  const SEV_BG = {
    0:"#F1EFE8",1:"#FFCCCC",2:"#D3D1C7",3:"#FFE0B2",
    4:"#B5D4F4",5:"#FFF9C4",6:"#C0DD97",7:"#9FE1CB"
  };
  const SEV_TC = {
    0:"#5F5E5A",1:"#A32D2D",2:"#444441",3:"#854F0B",
    4:"#0C447C",5:"#633806",6:"#27500A",7:"#085041"
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
  const phase1Card   = document.getElementById("sevPhase1Card");
  const phase1Bar    = document.getElementById("sevPhase1Bar");
  const phase2Card   = document.getElementById("sevPhase2Card");
  const summaryBar   = document.getElementById("sevSummaryBar");
  const tableCard    = document.getElementById("sevTableCard");
  const tableContent = document.getElementById("sevTableContent");
  const exportBtn    = document.getElementById("sevExportBtn");

  function renderRangeTags() {
    if (!rangeTags) return;
    if (!userRanges.length) {
      rangeTags.innerHTML = '<span style="color:var(--muted);font-size:12px">설정된 대역 없음 — Severity 1/2/7만 판단 가능</span>';
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

  function renderPhase1(data) {
    if (!phase1Card || !phase1Bar) return;
    const all = [...(data.firewall||[]),...(data.proxy||[]),...(data.multicast||[])];
    const tc = {};
    all.forEach(p => (p.tags||[]).forEach(t => { tc[t]=(tc[t]||0)+1; }));
    if (!Object.keys(tc).length) { phase1Card.style.display='none'; return; }
    phase1Card.style.display='';
    phase1Bar.innerHTML = Object.entries(tc).map(([tag,cnt]) => {
      const cls = TAG_COLORS[tag]||'tag-default';
      return `<span class="phase1-chip tag-badge ${cls}">${escapeHtml(tag)}: <strong>${cnt}</strong></span>`;
    }).join('');
  }

  function renderSummaryBar(data) {
    if (!phase2Card || !summaryBar) return;
    const all = [...(data.firewall||[]),...(data.proxy||[]),...(data.multicast||[])];
    const counts = {};
    all.forEach(p => { const u=p.urgency??0; counts[u]=(counts[u]||0)+1; });
    if (!Object.keys(counts).length) { phase2Card.style.display='none'; return; }
    phase2Card.style.display='';
    summaryBar.innerHTML = Object.entries(counts).sort(([a],[b])=>Number(a)-Number(b)).map(([u,cnt]) => {
      const bg=SEV_BG[u]||SEV_BG[0], tc2=SEV_TC[u]||SEV_TC[0];
      const isAct = activeSevFilter==u;
      return `<span class="sev-chip${isAct?' active':''}" data-sev="${u}" style="background:${bg};color:${tc2}"><strong>${escapeHtml(String(u))}</strong> ${escapeHtml(String(cnt))}건</span>`;
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
      tableContent.innerHTML='<div class="empty-state"><strong>결과 없음</strong><span>조건에 맞는 정책이 없습니다.</span></div>';
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
        <td>${escapeHtml(p.ritm||'')}</td>
        <td>${escapeHtml(p.request_date||'')}</td>
        <td><div class="badge-list">${mkBadges(p.srcaddr_display)}</div></td>
        <td><div class="badge-list">${mkBadges(p.dstaddr_display)}</div></td>
        <td><div class="badge-list">${mkBadges(p.service_display)}</div></td>
        <td>${escapeHtml(p.action||'')}</td>
        <td>${escapeHtml(p.status||'')}</td>
        <td>${escapeHtml(String(p.hit_count??0))}</td>
        <td>${escapeHtml(p.traffic_type||'')}</td>
        <td style="font-size:11px;max-width:200px">${escapeHtml(p.reason||'')}</td>
        <td style="font-size:11px;max-width:140px">${escapeHtml(p.recommended_action||'')}</td>
      </tr>`;
    }).join('');
    tableContent.innerHTML=`<table class="result-table"><thead><tr>
      <th>Sev</th><th>위험도</th><th>Tags</th><th>Policy ID</th><th>Name</th>
      <th>RITM</th><th>Request Date</th><th>Source</th><th>Destination</th>
      <th>Service</th><th>Action</th><th>Status</th><th>Hit Count</th>
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
      renderPhase1(data); renderSummaryBar(data); renderTable();
      const total=(data.firewall||[]).length+(data.proxy||[]).length+(data.multicast||[]).length;
      if (statusEl) statusEl.textContent=`${total}개 정책 분류 완료.`;
    } catch(err) {
      if (statusEl) statusEl.textContent=err.message||'Failed';
    }
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

  // AI 분석 (Ollama hermes3)
  const aiBtn = document.getElementById('aiAnalyzeBtn');
  const aiResult = document.getElementById('aiAnalysisResult');

  if (aiBtn) {
    aiBtn.addEventListener('click', async () => {
      if (!sevData) return;
      const allPolicies = [...(sevData.firewall||[]), ...(sevData.proxy||[]), ...(sevData.multicast||[])];
      if (!allPolicies.length) return;

      aiBtn.disabled = true;
      aiBtn.textContent = 'AI 분석 중...';
      if (aiResult) { aiResult.style.display = 'block'; aiResult.innerHTML = '<div class="ai-thinking">hermes3 분석 중... (30초~2분 소요)</div>'; }

      try {
        const res = await fetch('/api/ai/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ policies: allPolicies, mode: 'summary', model: 'hermes3:latest' }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'AI 분석 실패');
        if (aiResult) {
          aiResult.innerHTML = `<div class="ai-model-tag">hermes3:latest</div><div class="ai-text">${escapeHtml(data.result).replace(/\n/g, '<br>')}</div>`;
        }
      } catch (err) {
        if (aiResult) aiResult.innerHTML = `<div class="ai-error">${escapeHtml(err.message)}</div>`;
      } finally {
        aiBtn.disabled = false;
        aiBtn.textContent = 'AI 분석 (hermes3)';
      }
    });
  }

  renderRangeTags();
})();


// ── AI 기능 (Electron 앱 전용) ─────────────────────

async function aiExplainPolicy(policyId, policyData) {
  const btn = document.getElementById('ai-btn-' + policyId)
  if (btn) { btn.textContent = '...'; btn.disabled = true }
  try {
    const res = await fetch('/api/ai/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy_data: policyData })
    })
    const data = await res.json()
    _renderAIRow(policyId, data.explanation)
  } catch (e) {
    alert('AI unavailable. Make sure Ollama is running.')
  } finally {
    if (btn) { btn.textContent = '✦ AI'; btn.disabled = false }
  }
}

async function aiGenerateCLI(policies) {
  if (!policies || policies.length === 0) {
    alert('No policies selected.')
    return
  }
  const res = await fetch('/api/ai/cli', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policies })
  })
  const data = await res.json()
  _renderCLIModal(data.cli_commands)
}

async function aiGenerateReport() {
  const btn = document.getElementById('ai-report-btn')
  if (btn) { btn.textContent = 'Generating...'; btn.disabled = true }
  try {
    const summary = _collectSeveritySummary()
    const res = await fetch('/api/ai/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ severity_summary: summary })
    })
    const data = await res.json()
    const blob = new Blob([data.report_html], { type: 'text/html' })
    window.open(URL.createObjectURL(blob), '_blank')
  } catch (e) {
    alert('Report generation failed: ' + e.message)
  } finally {
    if (btn) { btn.textContent = '✦ AI Audit Report'; btn.disabled = false }
  }
}

function _collectSeveritySummary() {
  const summary = {}
  document.querySelectorAll('[data-severity]').forEach(el => {
    const s = el.dataset.severity
    summary[s] = (summary[s] || 0) + 1
  })
  return summary
}

function _renderAIRow(policyId, text) {
  const rowId = 'ai-row-' + policyId
  let row = document.getElementById(rowId)
  if (!row) {
    row = document.createElement('tr')
    row.id = rowId
    const src = document.getElementById('row-' + policyId)
      || document.querySelector(`[data-id="${policyId}"]`)
    if (src) src.insertAdjacentElement('afterend', row)
    else document.querySelector('tbody')?.appendChild(row)
  }
  row.innerHTML = `
    <td colspan="99"
      style="background:#0d0d1a;color:#ccc;padding:12px 20px;
             font-size:13px;border-left:3px solid #EE2228;">
      <strong style="color:#EE2228;">✦ AI Analysis</strong>
      <pre style="margin:8px 0 0;white-space:pre-wrap;
                  font-family:inherit;line-height:1.6;">${text}</pre>
      <button onclick="this.closest('tr').remove()"
        style="margin-top:8px;background:transparent;
               border:1px solid #444;color:#666;
               padding:4px 12px;border-radius:4px;
               cursor:pointer;font-size:11px;">Close</button>
    </td>`
}

function _renderCLIModal(commands) {
  document.getElementById('cli-modal')?.remove()
  const m = document.createElement('div')
  m.id = 'cli-modal'
  m.style.cssText = `
    position:fixed;inset:0;background:rgba(0,0,0,0.85);
    z-index:9999;display:flex;
    align-items:center;justify-content:center;`
  m.innerHTML = `
    <div style="background:#1a1a2e;border:1px solid #EE2228;
                border-radius:12px;padding:24px;
                max-width:640px;width:90%;
                max-height:80vh;overflow-y:auto;">
      <h3 style="color:#EE2228;margin:0 0 16px;font-size:16px;">
        ✦ FortiGate CLI Commands
      </h3>
      <pre id="cli-code"
        style="background:#0d0d1a;color:#0f0;padding:16px;
               border-radius:8px;overflow-x:auto;
               font-size:13px;line-height:1.6;margin:0 0 16px;"
      >${commands}</pre>
      <div style="display:flex;gap:12px;">
        <button onclick="
          navigator.clipboard.writeText(
            document.getElementById('cli-code').textContent
          ).then(()=>this.textContent='Copied ✓')"
          style="background:#EE2228;color:#fff;border:none;
                 padding:10px 20px;border-radius:6px;
                 cursor:pointer;font-weight:bold;">
          Copy to Clipboard
        </button>
        <button onclick="document.getElementById('cli-modal').remove()"
          style="background:transparent;border:1px solid #555;
                 color:#ccc;padding:10px 20px;
                 border-radius:6px;cursor:pointer;">
          Close
        </button>
      </div>
    </div>`
  document.body.appendChild(m)
}
