function bytesToMiB(bytes) {
  if (bytes == null) return '—';
  return `${Math.max(0, bytes / (1024 * 1024)).toFixed(1)} MiB`;
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

function drawSparkline(canvas, points, opts = {}) {
  const ctx = canvas.getContext('2d');
  const width = canvas.clientWidth;
  const height = canvas.height;
  if (canvas.width !== width) canvas.width = width;

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (!points.length) {
    ctx.fillStyle = 'rgba(148,163,184,0.6)';
    ctx.font = '12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace';
    ctx.fillText('—', 8, 22);
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
  const dash = document.getElementById('view-dashboard');
  const settings = document.getElementById('view-settings');
  const tDash = document.getElementById('tab-dashboard');
  const tSet = document.getElementById('tab-settings');

  const isSettings = tab === 'settings';
  dash.classList.toggle('hidden', isSettings);
  settings.classList.toggle('hidden', !isSettings);
  tDash.classList.toggle('axe-tab--active', !isSettings);
  tSet.classList.toggle('axe-tab--active', isSettings);
}

const SERIES_MAX_POINTS = 360; // 30 minutes at 5s
const seriesWorkers = [];
const seriesHashrate = [];

function pushSeries(series, value) {
  const v = typeof value === 'number' ? value : null;
  series.push({ t: Date.now(), v: v == null ? 0 : v });
  if (series.length > SERIES_MAX_POINTS) series.splice(0, series.length - SERIES_MAX_POINTS);
}

function renderWorkersTable(items) {
  const tbody = document.getElementById('workers-tbody');
  const meta = document.getElementById('workers-meta');
  meta.textContent = `${items.length} entries`;

  if (!items.length) {
    tbody.innerHTML = '<tr><td class="px-4 py-4 text-slate-400" colspan="4">No worker data available yet.</td></tr>';
    return;
  }

  const rows = items.slice(0, 50).map((w) => {
    const worker = w.worker || w.name || w.user || w.username || '—';
    const last = w.lastshare || w.last_share || w.last || w.lastShare || '';
    const best = w.bestshare || w.best_share || w.best || '';
    const note = w.raw ? String(w.raw) : '';
    return `
      <tr class="hover:bg-white/5">
        <td class="px-4 py-3 font-mono">${escapeHtml(String(worker))}</td>
        <td class="px-4 py-3">${escapeHtml(String(last || '—'))}</td>
        <td class="px-4 py-3">${escapeHtml(String(best || '—'))}</td>
        <td class="px-4 py-3 text-slate-400">${escapeHtml(note ? note.slice(0, 120) : '—')}</td>
      </tr>
    `;
  });
  tbody.innerHTML = rows.join('');
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
    const node = await fetchJson('/api/node');
    const progress = node.verificationprogress || 0;
    const pct = Math.round(progress * 100);
    const ibd = !!node.initialblockdownload;

    document.getElementById('sync-text').textContent = ibd ? `Syncing ${pct}%` : `Synchronized ${pct}%`;
    document.getElementById('sync-subtext').textContent = `${node.chain ?? '—'} • ${node.subversion ?? ''}`.trim();

    document.getElementById('blocks').textContent = node.blocks ?? '—';
    document.getElementById('headers').textContent = node.headers ?? '—';
    document.getElementById('peers').textContent = node.connections ?? '—';
    document.getElementById('mempool').textContent = bytesToMiB(node.mempool_bytes);
    setRing(progress);

    const pill = document.getElementById('status-pill');
    pill.textContent = ibd ? 'Syncing' : 'Running';
    pill.classList.toggle('axe-pill--ok', !ibd);
  } catch {
    document.getElementById('sync-text').textContent = 'Node unavailable';
    document.getElementById('sync-subtext').textContent = 'Check that BCHN is running.';
    setRing(0);
    const pill = document.getElementById('status-pill');
    pill.textContent = 'Offline';
    pill.classList.remove('axe-pill--ok');
  }

  try {
    const pool = await fetchJson('/api/pool');
    document.getElementById('workers').textContent = pool.workers ?? '—';
    document.getElementById('hashrate').textContent = pool.hashrate_ths ?? '—';
    document.getElementById('bestshare').textContent = pool.best_share ?? '—';

    const wNum = typeof pool.workers === 'number' ? pool.workers : Number(pool.workers);
    pushSeries(seriesWorkers, Number.isFinite(wNum) ? wNum : 0);

    const hNum = typeof pool.hashrate_ths === 'number' ? pool.hashrate_ths : Number(pool.hashrate_ths);
    pushSeries(seriesHashrate, Number.isFinite(hNum) ? hNum : 0);

    drawSparkline(document.getElementById('chart-workers'), seriesWorkers, { format: (v) => String(Math.round(v)) });
    drawSparkline(document.getElementById('chart-hashrate'), seriesHashrate, { format: (v) => v.toFixed(2) });
  } catch {
    document.getElementById('workers').textContent = '—';
    document.getElementById('hashrate').textContent = '—';
    document.getElementById('bestshare').textContent = '—';
    drawSparkline(document.getElementById('chart-workers'), []);
    drawSparkline(document.getElementById('chart-hashrate'), []);
  }

  try {
    const workers = await fetchJson('/api/pool/workers');
    renderWorkersTable((workers && workers.workers) || []);
  } catch {
    renderWorkersTable([]);
  }
}

refresh();
setInterval(refresh, 5000);

async function loadSettings() {
  try {
    const s = await fetchJson('/api/settings');
    document.getElementById('network').value = s.network || 'mainnet';
    document.getElementById('prune').value = s.prune ?? 550;
    document.getElementById('txindex').value = String(s.txindex ?? 0);
    document.getElementById('settings-status').textContent = '';
  } catch {
    document.getElementById('settings-status').textContent = 'Settings unavailable (node may be starting).';
  }
}

document.getElementById('tab-dashboard').addEventListener('click', () => showTab('dashboard'));
document.getElementById('tab-settings').addEventListener('click', async () => {
  showTab('settings');
  await loadSettings();
});

document.getElementById('settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const status = document.getElementById('settings-status');
  status.textContent = 'Saving…';
  try {
    const body = {
      network: document.getElementById('network').value,
      prune: Number(document.getElementById('prune').value),
      txindex: document.getElementById('txindex').value === '1',
    };
    const res = await postJson('/api/settings', body);
    status.textContent = res.restartRequired ? 'Saved. Restart the app to apply.' : 'Saved.';
  } catch (err) {
    status.textContent = `Error: ${err.message || err}`;
  }
});
