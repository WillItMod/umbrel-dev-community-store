function bytesToMiB(bytes) {
  if (bytes == null) return '-';
  return `${Math.max(0, bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function formatTHS(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '-';
  if (n === 0) return '0';
  if (Math.abs(n) < 0.01) return n.toFixed(4);
  if (Math.abs(n) < 1) return n.toFixed(3);
  if (Math.abs(n) < 10) return n.toFixed(2);
  return n.toFixed(1);
}

function formatHashrateFromTHS(v) {
  const ths = Number(v);
  if (!Number.isFinite(ths)) return '-';
  if (ths === 0) return '0 H/s';

  const abs = Math.abs(ths);
  // Convert from TH/s into a human unit.
  const units = [
    { unit: 'EH/s', scale: 1e6 },
    { unit: 'PH/s', scale: 1e3 },
    { unit: 'TH/s', scale: 1 },
    { unit: 'GH/s', scale: 1e-3 },
    { unit: 'MH/s', scale: 1e-6 },
    { unit: 'KH/s', scale: 1e-9 },
    { unit: 'H/s', scale: 1e-12 },
  ];

  for (const u of units) {
    const inUnit = abs / u.scale;
    if (inUnit >= 1 || u.unit === 'H/s') {
      const signed = ths / u.scale;
      const digits = Math.abs(signed) < 10 ? 2 : Math.abs(signed) < 100 ? 1 : 0;
      return `${signed.toFixed(digits)} ${u.unit}`;
    }
  }
  return `${formatTHS(ths)} TH/s`;
}

function formatEffortPercent(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '-';
  const abs = Math.abs(n);
  const digits = abs < 10 ? 1 : 0;
  return `${n.toFixed(digits)}%`;
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function setRing(progress) {
  const ring = document.getElementById('ring');
  const label = document.getElementById('ring-label');
  const circumference = 301.6;
  const p = Math.max(0, Math.min(1, progress || 0));
  const offset = circumference * (1 - p);
  ring.style.strokeDashoffset = `${offset}`;
  label.textContent = `${Math.round(p * 100)}%`;
}

function drawSparklineMulti(canvas, series, opts = {}) {
  const ctx = canvas.getContext('2d');
  const width = canvas.clientWidth;
  if (canvas.width !== width) canvas.width = width;
  const height = canvas.height;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const allValues = [];
  for (const s of series || []) {
    for (const p of (s && s.points) || []) {
      const v = p && typeof p.v === 'number' ? p.v : NaN;
      if (Number.isFinite(v)) allValues.push(v);
    }
  }

  if (!allValues.length) {
    ctx.fillStyle = 'rgba(148,163,184,0.6)';
    ctx.font = '12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", monospace';
    ctx.fillText('-', 8, 22);
    return;
  }

  const min = Math.min(...allValues);
  const max = Math.max(...allValues);
  const pad = 10;
  const span = max - min || 1;

  function x(i, n) {
    return pad + (i * (canvas.width - pad * 2)) / Math.max(1, n - 1);
  }
  function y(v) {
    return pad + ((max - v) * (canvas.height - pad * 2)) / span;
  }

  // grid
  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(pad, canvas.height - pad);
  ctx.lineTo(canvas.width - pad, canvas.height - pad);
  ctx.stroke();

  // lines
  ctx.lineWidth = 2;
  for (const s of series || []) {
    const points = (s && s.points) || [];
    if (!points.length) continue;
    ctx.strokeStyle = s.color || 'rgba(255,255,255,0.9)';
    ctx.beginPath();
    let started = false;
    for (let i = 0; i < points.length; i++) {
      const v = points[i] && points[i].v;
      if (!Number.isFinite(v)) {
        started = false;
        continue;
      }
      const px = x(i, points.length);
      const py = y(v);
      if (!started) {
        ctx.moveTo(px, py);
        started = true;
      } else {
        ctx.lineTo(px, py);
      }
    }
    ctx.stroke();

    // last dot (last finite point)
    for (let i = points.length - 1; i >= 0; i--) {
      const v = points[i] && points[i].v;
      if (!Number.isFinite(v)) continue;
      ctx.fillStyle = s.color || 'rgba(255,255,255,0.9)';
      ctx.beginPath();
      ctx.arc(x(i, points.length), y(v), 2.2, 0, Math.PI * 2);
      ctx.fill();
      break;
    }
  }

  // min/max labels
  ctx.fillStyle = 'rgba(148,163,184,0.65)';
  ctx.font = '11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", monospace';
  const fmt = opts.format || ((v) => String(v));
  ctx.fillText(fmt(max), pad, 14);
  ctx.fillText(fmt(min), pad, canvas.height - 4);
}

function drawSparkline(canvas, points, opts = {}) {
  const ctx = canvas.getContext('2d');
  const width = canvas.clientWidth;
  const height = canvas.height;
  if (canvas.width !== width) canvas.width = width;

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (!points.length) {
    ctx.fillStyle = 'rgba(148,163,184,0.6)';
    ctx.font = '12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace';
    ctx.fillText('-', 8, 22);
    return;
  }

  const values = points.map((p) => p.v).filter((v) => typeof v === 'number' && !Number.isNaN(v));
  if (!values.length) return;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const pad = 10;
  const span = max - min || 1;

  function x(i) {
    return pad + (i * (canvas.width - pad * 2)) / Math.max(1, points.length - 1);
  }
  function y(v) {
    return pad + ((max - v) * (canvas.height - pad * 2)) / span;
  }

  // grid
  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(pad, canvas.height - pad);
  ctx.lineTo(canvas.width - pad, canvas.height - pad);
  ctx.stroke();

  // line
  const gradient = ctx.createLinearGradient(0, canvas.height, canvas.width, 0);
  gradient.addColorStop(0, 'rgba(0,229,255,0.95)');
  gradient.addColorStop(0.5, 'rgba(255,43,214,0.95)');
  gradient.addColorStop(1, 'rgba(255,154,0,0.95)');

  ctx.strokeStyle = gradient;
  ctx.lineWidth = 2;
  ctx.beginPath();
  for (let i = 0; i < points.length; i++) {
    const px = x(i);
    const py = y(points[i].v);
    if (i === 0) ctx.moveTo(px, py);
    else ctx.lineTo(px, py);
  }
  ctx.stroke();

  // last dot
  const last = points[points.length - 1];
  ctx.fillStyle = 'rgba(255,255,255,0.9)';
  ctx.beginPath();
  ctx.arc(x(points.length - 1), y(last.v), 2.5, 0, Math.PI * 2);
  ctx.fill();

  // min/max labels
  ctx.fillStyle = 'rgba(148,163,184,0.65)';
  ctx.font = '11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace';
  const fmt = opts.format || ((v) => String(v));
  ctx.fillText(fmt(max), pad, 14);
  ctx.fillText(fmt(min), pad, canvas.height - 4);
}

async function fetchJson(url) {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${res.status}`);
  return data;
}

function showTab(tab) {
  const home = document.getElementById('view-home');
  const pool = document.getElementById('view-pool');
  const settings = document.getElementById('view-settings');
  const tHome = document.getElementById('tab-home');
  const tPool = document.getElementById('tab-pool');
  const tSet = document.getElementById('tab-settings');

  const which = tab || 'home';
  home.classList.toggle('hidden', which !== 'home');
  pool.classList.toggle('hidden', which !== 'pool');
  settings.classList.toggle('hidden', which !== 'settings');

  tHome.classList.toggle('axe-tab--active', which === 'home');
  tPool.classList.toggle('axe-tab--active', which === 'pool');
  tSet.classList.toggle('axe-tab--active', which === 'settings');

  window.__activeTab = which;
}

function escapeHtml(s) {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function getAlgo() {
  const el = document.getElementById('algo');
  const saved = localStorage.getItem('dgbAlgo');
  if (saved && el && el.value !== saved) el.value = saved;
  return (el && el.value) || saved || 'sha256';
}

function getStratumPort(algo) {
  const ports = window.__stratumPorts || {};
  const p = ports && typeof ports === 'object' ? Number(ports[algo]) : NaN;
  if (Number.isFinite(p) && p > 0) return p;
  return algo === 'scrypt' ? 5679 : 5678;
}

async function refresh() {
  try {
    const res = await fetch('/api/node', { cache: 'no-store' });
    const node = await res.json().catch(() => ({}));
    if (!res.ok) throw node;
    const warmingUp = Boolean(node && (node.warmup || node.warmupMessage));
    const progress = warmingUp ? 0 : node.verificationprogress || 0;
    const pct = Math.round(progress * 100);
    const ibd = !!node.initialblockdownload;
    const cached = !!node.cached;

    const lastSeen = Number(node.lastSeen) || 0;
    const ageS = lastSeen ? Math.max(0, Math.floor(Date.now() / 1000 - lastSeen)) : 0;
    const ageM = Math.floor(ageS / 60);
    const ageText = lastSeen ? `Last seen ${ageM}m ago` : 'Last seen unknown';

    const cacheFreshS = 180;
    const cacheOfflineS = 900;
    const cacheFresh = cached && lastSeen && ageS <= cacheFreshS;
    const cacheStale = cached && lastSeen && ageS > cacheFreshS && ageS <= cacheOfflineS;

    if (warmingUp) {
      document.getElementById('sync-text').textContent = node.warmupMessage || 'Starting';
      document.getElementById('sync-subtext').textContent = `${ageText}`.trim();
    } else if (cacheFresh || cacheStale) {
      const stateText = ibd ? `Syncing ${pct}%` : `Running`;
      document.getElementById('sync-text').textContent = cacheStale ? `${stateText} (stale)` : stateText;
      document.getElementById('sync-subtext').textContent = `${ageText} | ${node.chain ?? '-'} | ${node.subversion ?? ''}`.trim();
    } else if (cached) {
      document.getElementById('sync-text').textContent = 'Starting';
      document.getElementById('sync-subtext').textContent = `${ageText} | ${node.chain ?? '-'} | ${node.subversion ?? ''}`.trim();
    } else {
      document.getElementById('sync-text').textContent = ibd ? `Syncing ${pct}%` : `Synchronized ${pct}%`;
      document.getElementById('sync-subtext').textContent = `${node.chain ?? '-'} | ${node.subversion ?? ''}`.trim();
    }

    document.getElementById('blocks').textContent = node.blocks ?? '-';
    document.getElementById('headers').textContent = node.headers ?? '-';
    document.getElementById('peers').textContent = node.connections ?? '-';
    document.getElementById('mempool').textContent = bytesToMiB(node.mempool_bytes);
    setRing(progress);

    const pill = document.getElementById('status-pill');
    const pillText = warmingUp ? 'Starting' : cached && !(cacheFresh || cacheStale) ? 'Starting' : ibd ? 'Syncing' : 'Running';
    pill.textContent = pillText;
    pill.classList.toggle('axe-pill--ok', pillText === 'Running');
  } catch (err) {
    const reindexRequired = Boolean(err && err.reindexRequired);
    const reindexRequested = Boolean(err && err.reindexRequested);

    if (reindexRequired || reindexRequested) {
      document.getElementById('sync-text').textContent = reindexRequired ? 'Reindex required' : 'Reindex scheduled';
      document.getElementById('sync-subtext').textContent = reindexRequired
        ? 'Node was previously pruned. Restart the app to rebuild the database (chainstate reindex).'
        : 'Restart the app to rebuild the database (chainstate reindex).';
    } else {
      document.getElementById('sync-text').textContent = 'Node unavailable';
      document.getElementById('sync-subtext').textContent = 'Node is starting (after reboot) or offline.';
    }
    setRing(0);
    const pill = document.getElementById('status-pill');
    pill.textContent = reindexRequired ? 'Reindex' : 'Offline';
    pill.classList.remove('axe-pill--ok');
  }

  try {
    const algo = getAlgo();
    const pool = await fetchJson(`/api/pool?algo=${encodeURIComponent(algo)}`);
    document.getElementById('workers').textContent = pool.workers ?? '-';
    document.getElementById('hashrate').textContent = formatTHS(pool.hashrate_ths);
    document.getElementById('bestshare').textContent = formatEffortPercent(pool.effort_percent);
    document.getElementById('workers-summary').textContent = pool.workers ?? '-';
    document.getElementById('hashrate-summary').textContent = formatTHS(pool.hashrate_ths);
    document.getElementById('bestshare-summary').textContent = formatEffortPercent(pool.effort_percent);

    const h = (pool && pool.hashrates_ths) || {};
    const el1m = document.getElementById('hashrate-1m');
    const el5m = document.getElementById('hashrate-5m');
    const el15m = document.getElementById('hashrate-15m');
    const el1h = document.getElementById('hashrate-1h');
    const el6h = document.getElementById('hashrate-6h');
    const el1d = document.getElementById('hashrate-1d');
    const el7d = document.getElementById('hashrate-7d');
    if (el1m) el1m.textContent = formatHashrateFromTHS(h['1m']);
    if (el5m) el5m.textContent = formatHashrateFromTHS(h['5m']);
    if (el15m) el15m.textContent = formatHashrateFromTHS(h['15m']);
    if (el1h) el1h.textContent = formatHashrateFromTHS(h['1h']);
    if (el6h) el6h.textContent = formatHashrateFromTHS(h['6h']);
    if (el1d) el1d.textContent = formatHashrateFromTHS(h['1d']);
    if (el7d) el7d.textContent = formatHashrateFromTHS(h['7d']);

    const lg1m = document.getElementById('legend-1m');
    const lg5m = document.getElementById('legend-5m');
    const lg15m = document.getElementById('legend-15m');
    const lg1h = document.getElementById('legend-1h');
    if (lg1m) lg1m.textContent = formatHashrateFromTHS(h['1m']);
    if (lg5m) lg5m.textContent = formatHashrateFromTHS(h['5m']);
    if (lg15m) lg15m.textContent = formatHashrateFromTHS(h['15m']);
    if (lg1h) lg1h.textContent = formatHashrateFromTHS(h['1h']);
  } catch {
    document.getElementById('workers').textContent = '-';
    document.getElementById('hashrate').textContent = '-';
    document.getElementById('bestshare').textContent = '-';
    document.getElementById('workers-summary').textContent = '-';
    document.getElementById('hashrate-summary').textContent = '-';
    document.getElementById('bestshare-summary').textContent = '-';

    const ids = ['hashrate-1m', 'hashrate-5m', 'hashrate-15m', 'hashrate-1h', 'hashrate-6h', 'hashrate-1d', 'hashrate-7d'];
    for (const id of ids) {
      const el = document.getElementById(id);
      if (el) el.textContent = '-';
    }

    const legendIds = ['legend-1m', 'legend-5m', 'legend-15m', 'legend-1h'];
    for (const id of legendIds) {
      const el = document.getElementById(id);
      if (el) el.textContent = '-';
    }
  }

}

function setStratumUrl() {
  const algo = getAlgo();
  const host = window.location && window.location.hostname ? String(window.location.hostname) : '';
  if (!host) return;
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]') return;
  const url = `stratum+tcp://${host}:${getStratumPort(algo)}`;
  const ids = ['stratum-url', 'stratum-url-note'];
  for (const id of ids) {
    const el = document.getElementById(id);
    if (el) el.textContent = url;
  }
}

setStratumUrl();
refresh();
setInterval(refresh, 5000);

function shortenImageRef(s) {
  if (!s) return '-';
  const parts = String(s).split('@sha256:');
  if (parts.length === 2) return `${parts[0]}@sha256:${parts[1].slice(0, 12)}...`;
  return s;
}

async function loadPoolSettings() {
  const status = document.getElementById('pool-settings-status');
  const payoutEl = document.getElementById('payout-address');
  const payoutInput = document.getElementById('payoutAddress');
  const minerUser = document.getElementById('miner-username');
  const warn = document.getElementById('payout-warning');
  const mindiffEl = document.getElementById('mindiff');
  const startdiffEl = document.getElementById('startdiff');
  const maxdiffEl = document.getElementById('maxdiff');
  try {
    const s = await fetchJson('/api/pool/settings');
    const addr = (s && s.payoutAddress) || '';
    const configured = Boolean(s && s.configured);
    const warning = (s && s.warning) || '';
    const validationWarning = (s && s.validationWarning) || '';
    const mindiff = Number(s && s.mindiff);
    const startdiff = Number(s && s.startdiff);
    const maxdiff = Number(s && s.maxdiff);

    if (payoutEl) payoutEl.textContent = configured ? addr : 'not set';
    if (payoutInput && payoutInput.value !== addr) payoutInput.value = addr;
    if (status) status.textContent = configured ? (validationWarning || '') : warning || 'Payout address not configured.';
    if (minerUser) minerUser.textContent = configured ? `${addr}.<worker-name>` : '(set payout first)';
    if (warn) warn.classList.toggle('hidden', configured);
    if (mindiffEl && Number.isFinite(mindiff) && mindiff > 0) mindiffEl.value = String(Math.floor(mindiff));
    if (startdiffEl && Number.isFinite(startdiff) && startdiff > 0) startdiffEl.value = String(Math.floor(startdiff));
    if (maxdiffEl && Number.isFinite(maxdiff) && maxdiff >= 0) maxdiffEl.value = String(Math.floor(maxdiff));
  } catch {
    if (payoutEl) payoutEl.textContent = 'unavailable';
    if (status) status.textContent = 'Pool settings unavailable (app starting).';
    if (minerUser) minerUser.textContent = 'unavailable';
    if (warn) warn.classList.remove('hidden');
  }
}

function applyVardiffPreset(preset) {
  const mindiffEl = document.getElementById('mindiff');
  const startdiffEl = document.getElementById('startdiff');
  const maxdiffEl = document.getElementById('maxdiff');
  if (!mindiffEl || !startdiffEl || !maxdiffEl) return;

  if (preset === 'default') {
    // Recommended: reduces share spam/rejects on fast chains like DGB.
    mindiffEl.value = '1024';
    startdiffEl.value = '1024';
    maxdiffEl.value = '0';
    return;
  }
  if (preset === 'home') {
    // Home miners: decent feedback without overwhelming the pool.
    mindiffEl.value = '256';
    startdiffEl.value = '1024';
    maxdiffEl.value = '0';
    return;
  }
  if (preset === '300th') {
    // Target: keep share rate reasonable for very high hashrate miners (up to ~300 TH/s).
    mindiffEl.value = '1024';
    startdiffEl.value = '65536';
    maxdiffEl.value = '0';
    return;
  }
}

async function loadBackendInfo() {
  const el = document.getElementById('backend-info');
  if (!el) return;
  try {
    const about = await fetchJson('/api/about');
    window.__stratumPorts = about && about.stratumPorts ? about.stratumPorts : window.__stratumPorts;
    const node = about.node;
    const sub = node && node.subversion ? node.subversion : 'node unavailable';
    const dgbd = shortenImageRef(about.images && about.images.dgbd);
    const miningcore = shortenImageRef(about.images && about.images.miningcore);
    const postgres = shortenImageRef(about.images && about.images.postgres);
    const channel = about.channel ? ` | ${about.channel}` : '';
    el.textContent = `Backend: ${sub} | Miningcore (Stratum v1) | DGB: ${dgbd} | miningcore: ${miningcore} | postgres: ${postgres}${channel}`;
  } catch {
    el.textContent = 'Backend info unavailable.';
  }
}

async function loadSettings() {
  try {
    const s = await fetchJson('/api/settings');
    document.getElementById('network').value = s.network || 'mainnet';
    document.getElementById('prune').value = s.prune ?? 0;
    document.getElementById('txindex').value = String(s.txindex ?? 0);
    document.getElementById('settings-status').textContent = '';
  } catch {
    document.getElementById('settings-status').textContent = 'Settings unavailable (node may be starting).';
  }
}

function getTrail() {
  const el = document.getElementById('trail');
  const saved = localStorage.getItem('dgbTrail');
  if (saved && el && el.value !== saved) el.value = saved;
  return (el && el.value) || saved || '30m';
}

async function refreshCharts() {
  const trail = getTrail();
  try {
    const algo = getAlgo();
    const series = await fetchJson(`/api/timeseries/pool?algo=${encodeURIComponent(algo)}&trail=${encodeURIComponent(trail)}`);
    const points = (series && series.points) || [];
    const workers = points.map((p) => ({ v: Number(p.workers) || 0 }));
    drawSparkline(document.getElementById('chart-workers'), workers, { format: (v) => String(Math.round(v)) });

    const s1m = points.map((p) => ({ v: Number(p.hashrate_1m_ths) }));
    const s5m = points.map((p) => ({ v: Number(p.hashrate_5m_ths) }));
    const s15m = points.map((p) => ({ v: Number(p.hashrate_15m_ths) }));
    const s1h = points.map((p) => ({ v: Number(p.hashrate_1h_ths) }));
    drawSparklineMulti(
      document.getElementById('chart-hashrate'),
      [
        { label: '1m', color: '#00e5ff', points: s1m },
        { label: '5m', color: '#ff2bd6', points: s5m },
        { label: '15m', color: '#ff9a00', points: s15m },
        { label: '1h', color: '#22c55e', points: s1h },
      ],
      { format: (v) => v.toFixed(2) }
    );
  } catch {
    drawSparkline(document.getElementById('chart-workers'), []);
    drawSparklineMulti(document.getElementById('chart-hashrate'), []);
  }
}

let chartInterval = null;
function startChartInterval() {
  if (chartInterval) return;
  chartInterval = setInterval(() => {
    if (window.__activeTab === 'pool') refreshCharts();
  }, 30000);
}

document.getElementById('tab-home').addEventListener('click', () => showTab('home'));
document.getElementById('tab-pool').addEventListener('click', async () => {
  showTab('pool');
  startChartInterval();
  await refreshCharts();
  await refresh();
});
document.getElementById('go-pool').addEventListener('click', async () => {
  showTab('pool');
  startChartInterval();
  await refreshCharts();
  await refresh();
});
document.getElementById('tab-settings').addEventListener('click', async () => {
  showTab('settings');
  await loadSettings();
  await loadPoolSettings();
});

document.getElementById('support-jump').addEventListener('click', () => {
  showTab('settings');
  const el = document.getElementById('support-section');
  if (el && el.scrollIntoView) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
});

document.getElementById('trail').addEventListener('change', async () => {
  localStorage.setItem('dgbTrail', document.getElementById('trail').value);
  await refreshCharts();
});

document.getElementById('algo')?.addEventListener('change', async (e) => {
  const v = String(e?.target?.value || 'sha256');
  localStorage.setItem('dgbAlgo', v);
  setStratumUrl();
  await refreshCharts();
  await refresh();
});

document.getElementById('settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const status = document.getElementById('settings-status');
  status.textContent = 'Saving...';
  try {
    const body = {
      network: document.getElementById('network').value,
      prune: Number(document.getElementById('prune').value),
      txindex: document.getElementById('txindex').value === '1',
    };
    const res = await postJson('/api/settings', body);
    if (res.reindexRequired) {
      status.textContent = 'Saved. Restart the app to reindex chainstate (required after switching from pruned to archival).';
    } else {
      status.textContent = res.restartRequired ? 'Saved. Restart the app to apply.' : 'Saved.';
    }
  } catch (err) {
    status.textContent = `Error: ${err.message || err}`;
  }
});

document.getElementById('pool-settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const status = document.getElementById('pool-settings-status');
  if (status) status.textContent = 'Saving...';
  try {
    const payoutAddress = document.getElementById('payoutAddress').value;
    const mindiff = Number(document.getElementById('mindiff')?.value);
    const startdiff = Number(document.getElementById('startdiff')?.value);
    const maxdiff = Number(document.getElementById('maxdiff')?.value);
    const body = { payoutAddress, mindiff, startdiff, maxdiff };
    const res = await postJson('/api/pool/settings', body);
    if (status) status.textContent = res.restartRequired ? 'Saved. Restart the app to apply.' : 'Saved.';
    await loadPoolSettings();
  } catch (err) {
    if (status) status.textContent = `Error: ${err.message || err}`;
  }
});

document.getElementById('vardiffPreset')?.addEventListener('change', (e) => {
  const v = String(e?.target?.value || '');
  applyVardiffPreset(v);
});

document.getElementById('support-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const status = document.getElementById('support-status');
  if (status) status.textContent = 'Sending...';
  try {
    const res = await postJson('/api/support/ticket', {
      subject: document.getElementById('support-subject').value,
      message: document.getElementById('support-message').value,
      email: document.getElementById('support-email').value,
    });
    if (status) status.textContent = res.ticket ? `Sent. Ticket: ${res.ticket}` : 'Sent. Thanks!';
    document.getElementById('support-subject').value = '';
    document.getElementById('support-message').value = '';
  } catch (err) {
    if (status) status.textContent = `Error: ${err.message || err}`;
  }
});

// init
window.__activeTab = 'home';
showTab('home');
startChartInterval();
loadBackendInfo();
loadPoolSettings();
try {
  const trail = localStorage.getItem('dgbTrail');
  if (trail) document.getElementById('trail').value = trail;
} catch {}
try {
  const algo = localStorage.getItem('dgbAlgo');
  if (algo && document.getElementById('algo')) document.getElementById('algo').value = algo;
} catch {}
setStratumUrl();
