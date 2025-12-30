function bytesToMiB(bytes) {
  if (bytes == null) return '—';
  return `${Math.max(0, bytes / (1024 * 1024)).toFixed(1)} MiB`;
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
  } catch {
    document.getElementById('workers').textContent = '—';
    document.getElementById('hashrate').textContent = '—';
    document.getElementById('bestshare').textContent = '—';
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
