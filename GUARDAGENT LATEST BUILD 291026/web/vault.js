// Vault: shows your wallets after a PIN. With the duress PIN the server answers in exactly the same way but with
// the decoy wallets only, and raises the silent alarm on its side. Nothing on this page behaves differently.
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const token = (() => { try { return localStorage.getItem('bg_token'); } catch { return null; } })();
  const MAX = 8;
  let pin = '', busy = false, idle;
  if (!token) { $('lockView').hidden = true; $('signedOut').hidden = false; return; }

  const dots = () => { $('dots').innerHTML = Array.from({ length: Math.max(4, pin.length) }, (_, i) => `<i class="${i < pin.length ? 'on' : ''}"></i>`).join(''); };
  const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'del', '0', 'ok'];
  $('pad').innerHTML = keys.map(k => `<button type="button" data-k="${k}" class="${k.length > 1 ? 'ghost' : ''}" aria-label="${k === 'del' ? 'Delete' : k === 'ok' ? 'Unlock' : k}">${k === 'del' ? '⌫' : k === 'ok' ? 'Unlock' : k}</button>`).join('');
  dots();

  // Location goes along only if the browser already allowed it, so no permission prompt can ever appear here.
  // The server ignores it unless the duress PIN was used and the owner chose to share location.
  async function location() {
    try {
      if (!navigator.permissions || !navigator.geolocation) return null;
      const p = await navigator.permissions.query({ name: 'geolocation' });
      if (p.state !== 'granted') return null;
      return await new Promise(res => navigator.geolocation.getCurrentPosition(
        x => res({ lat: x.coords.latitude, lng: x.coords.longitude, acc: x.coords.accuracy }), () => res(null), { timeout: 2500, maximumAge: 600000 }));
    } catch { return null; }
  }
  const fmt = (v, sym) => v == null ? '—' : `${Number(v).toLocaleString(undefined, { maximumFractionDigits: v < 1 ? 6 : 4 })} ${sym || ''}`;
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const short = a => a.length > 12 ? a.slice(0, 4) + '…' + a.slice(-4) : a;

  async function unlock() {
    if (busy || pin.length < 4) return;
    busy = true; $('sub').textContent = '';
    try {
      const r = await fetch('/api/duress/vault', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token }, body: JSON.stringify({ pin, location: await location() }) });
      const j = await r.json().catch(() => ({}));
      if (r.status === 401 && !j.error?.includes('PIN')) { $('lockView').hidden = true; $('signedOut').hidden = false; return; }
      if (!r.ok) { $('sub').textContent = r.status === 401 ? 'Wrong PIN' : (j.error || 'Try again'); $('dots').classList.add('shake'); setTimeout(() => $('dots').classList.remove('shake'), 400); return; }
      show(j.wallets || []);
    } catch { $('sub').textContent = 'No connection'; }
    finally { pin = ''; dots(); busy = false; }
  }
  function show(ws) {
    $('lockView').hidden = true; $('openView').hidden = false;
    $('count').textContent = ws.length === 1 ? '1 wallet' : `${ws.length} wallets`;
    $('list').innerHTML = ws.map(w => `<div class="w"><span class="ic">${esc((w.symbol || '?').slice(0, 3))}</span><div class="t"><b>${esc(w.label)}</b><small>${esc(short(w.address))}</small></div><div class="v">${esc(fmt(w.balance, w.symbol))}</div></div>`).join('');
    clearTimeout(idle); idle = setTimeout(lock, 120000);
  }
  function lock() { $('openView').hidden = true; $('lockView').hidden = false; $('list').innerHTML = ''; pin = ''; dots(); }
  $('lockBtn').onclick = lock;
  $('pad').addEventListener('click', e => {
    const k = e.target.closest('button')?.dataset.k; if (!k) return;
    if (k === 'del') pin = pin.slice(0, -1);
    else if (k === 'ok') return unlock();
    else if (pin.length < MAX) pin += k;
    dots();
  });
  document.addEventListener('keydown', e => {
    if ($('lockView').hidden) return;
    if (/^\d$/.test(e.key) && pin.length < MAX) { pin += e.key; dots(); }
    else if (e.key === 'Backspace') { pin = pin.slice(0, -1); dots(); }
    else if (e.key === 'Enter') unlock();
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden) lock(); });
})();
