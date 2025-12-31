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

function formatBestShare(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '-';
  if (n === 0) return '0';
  const abs = Math.abs(n);
  const units = [
    { s: 'T', v: 1e12 },
    { s: 'G', v: 1e9 },
    { s: 'M', v: 1e6 },
    { s: 'K', v: 1e3 },
  ];
  for (const u of units) {
    if (abs >= u.v) {
      const scaled = n / u.v;
      const digits = Math.abs(scaled) < 10 ? 2 : Math.abs(scaled) < 100 ? 1 : 0;
      return `${scaled.toFixed(digits)}${u.s}`;
    }
  }
  return String(Math.round(n));
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

const __CASHADDR_RE = /^(?:(?:bitcoincash|bchtest|bchreg):)?[qp][0-9a-z]{41,60}$/i;
const __LEGACY_BCH_RE = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;

function __getCashaddrModalEls() {
  return {
    root: document.getElementById('cashaddr-modal'),
    cashaddr: document.getElementById('cashaddr-modal-cashaddr'),
    legacy: document.getElementById('cashaddr-modal-legacy'),
    copy: document.getElementById('cashaddr-modal-copy'),
    close: document.getElementById('cashaddr-modal-close'),
  };
}

async function __copyToClipboard(text) {
  const t = String(text || '').trim();
  if (!t) return false;
  try {
    await navigator.clipboard.writeText(t);
    return true;
  } catch {}
  try {
    const ta = document.createElement('textarea');
    ta.value = t;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {}
  return false;
}

function __showCashaddrModal({ cashaddr, legacy }) {
  const els = __getCashaddrModalEls();
  if (!els.root) return;

  if (els.cashaddr) els.cashaddr.textContent = cashaddr ? String(cashaddr) : '';
  if (els.legacy) els.legacy.textContent = legacy ? String(legacy) : '';

  if (els.copy) {
    els.copy.textContent = 'Copy';
    els.copy.onclick = async () => {
      const ok = await __copyToClipboard(legacy);
      if (ok) els.copy.textContent = 'Copied';
      setTimeout(() => {
        if (els.copy) els.copy.textContent = 'Copy';
      }, 1200);
    };
  }

  const close = () => {
    els.root.classList.add('hidden');
  };

  if (els.close) els.close.onclick = close;
  els.root.onclick = (e) => {
    if (e && e.target === els.root) close();
  };
  document.addEventListener(
    'keydown',
    (e) => {
      if (e && e.key === 'Escape' && !els.root.classList.contains('hidden')) close();
    },
    { once: true }
  );

  els.root.classList.remove('hidden');
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

async function refresh() {
  try {
    const res = await fetch('/api/node', { cache: 'no-store' });
    const node = await res.json().catch(() => ({}));
    if (!res.ok) throw node;
    const progress = node.verificationprogress || 0;
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

    if (cacheFresh || cacheStale) {
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
    const pillText = cached && !(cacheFresh || cacheStale) ? 'Starting' : ibd ? 'Syncing' : 'Running';
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
    const pool = await fetchJson('/api/pool');
    document.getElementById('workers').textContent = pool.workers ?? '-';
    document.getElementById('hashrate').textContent = formatTHS(pool.hashrate_ths);
    document.getElementById('bestshare').textContent = formatBestShare(pool.best_share);
    document.getElementById('workers-summary').textContent = pool.workers ?? '-';
    document.getElementById('hashrate-summary').textContent = formatTHS(pool.hashrate_ths);
    document.getElementById('bestshare-summary').textContent = formatBestShare(pool.best_share);

    const h = (pool && pool.hashrates_ths) || {};
    const el1m = document.getElementById('hashrate-1m');
    const el5m = document.getElementById('hashrate-5m');
    const el15m = document.getElementById('hashrate-15m');
    const el1h = document.getElementById('hashrate-1h');
    const el6h = document.getElementById('hashrate-6h');
    const el1d = document.getElementById('hashrate-1d');
    const el7d = document.getElementById('hashrate-7d');
    if (el1m) el1m.textContent = formatTHS(h['1m']);
    if (el5m) el5m.textContent = formatTHS(h['5m']);
    if (el15m) el15m.textContent = formatTHS(h['15m']);
    if (el1h) el1h.textContent = formatTHS(h['1h']);
    if (el6h) el6h.textContent = formatTHS(h['6h']);
    if (el1d) el1d.textContent = formatTHS(h['1d']);
    if (el7d) el7d.textContent = formatTHS(h['7d']);
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
  }

}

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
  try {
    const s = await fetchJson('/api/pool/settings');
    const addr = (s && s.payoutAddress) || '';
    const configured = Boolean(s && s.configured);
    const warning = (s && s.warning) || '';
    const validationWarning = (s && s.validationWarning) || '';

    if (payoutEl) payoutEl.textContent = configured ? addr : 'not set';
    if (payoutInput && payoutInput.value !== addr) payoutInput.value = addr;
    if (status) status.textContent = configured ? (validationWarning || '') : warning || 'Payout address not configured.';
    if (minerUser) minerUser.textContent = configured ? '<worker-name>' : '(set payout first)';
    if (warn) warn.classList.toggle('hidden', configured);
  } catch {
    if (payoutEl) payoutEl.textContent = 'unavailable';
    if (status) status.textContent = 'Pool settings unavailable (app starting).';
    if (minerUser) minerUser.textContent = 'unavailable';
    if (warn) warn.classList.remove('hidden');
  }
}

async function loadBackendInfo() {
  const el = document.getElementById('backend-info');
  if (!el) return;
  try {
    const about = await fetchJson('/api/about');
    const node = about.node;
    const sub = node && node.subversion ? node.subversion : 'node unavailable';
    const bchn = shortenImageRef(about.images && about.images.bchn);
    const ckpool = shortenImageRef(about.images && about.images.ckpool);
    const channel = about.channel ? ` | ${about.channel}` : '';
    el.textContent = `Backend: ${sub} | ckpool-solo (Stratum v1) | BCHN: ${bchn} | ckpool: ${ckpool}${channel}`;
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
  const saved = localStorage.getItem('bchTrail');
  if (saved && el && el.value !== saved) el.value = saved;
  return (el && el.value) || saved || '30m';
}

async function refreshCharts() {
  const trail = getTrail();
  try {
    const series = await fetchJson(`/api/timeseries/pool?trail=${encodeURIComponent(trail)}`);
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
  localStorage.setItem('bchTrail', document.getElementById('trail').value);
  await refreshCharts();
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
    const payoutTrim = String(payoutAddress || '').trim();
    const inputWasCashaddr = __CASHADDR_RE.test(payoutTrim);
    const inputWasLegacy = __LEGACY_BCH_RE.test(payoutTrim);

    const res = await postJson('/api/pool/settings', { payoutAddress });
    if (status) status.textContent = res.restartRequired ? 'Saved. Restart the app to apply.' : 'Saved.';
    await loadPoolSettings();

    const legacyFromRes = String(
      (res && res.settings && res.settings.payoutAddress ? res.settings.payoutAddress : '') || ''
    ).trim();
    const validationWarning = String(
      (res && res.settings && res.settings.validationWarning ? res.settings.validationWarning : '') || ''
    );
    const serverConverted =
      !inputWasLegacy && __LEGACY_BCH_RE.test(legacyFromRes) && legacyFromRes && legacyFromRes !== payoutTrim;
    const serverMentionsConversion = /cashaddr/i.test(validationWarning) || /converted/i.test(validationWarning);

    if (inputWasCashaddr || serverConverted || serverMentionsConversion) {
      let legacy = '';
      try {
        legacy = legacyFromRes;
      } catch {}
      if (!legacy) {
        try {
          const s = await fetchJson('/api/pool/settings');
          legacy = String((s && s.payoutAddress) || '').trim();
        } catch {}
      }
      __showCashaddrModal({ cashaddr: payoutTrim, legacy });
    }
  } catch (err) {
    if (status) status.textContent = `Error: ${err.message || err}`;
  }
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
  const trail = localStorage.getItem('bchTrail');
  if (trail) document.getElementById('trail').value = trail;
} catch {}
