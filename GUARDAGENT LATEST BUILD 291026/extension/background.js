// Extension service worker: holds the pairing token and calls your Bodyguard backend.
const DEFAULT_BACKEND = 'https://guardagent.tech';

const get = () => chrome.storage.local.get({ backend: DEFAULT_BACKEND, token: null, enabled: true, agentId: null, lockUntil: 0, stats: { checked: 0, blocked: 0, warned: 0 } });
const locked = s => (s.lockUntil || 0) * 1000 > Date.now();
// Duress time-lock: while it runs, the shield fails closed (no server = no signing) and can't be switched off.
const lockBlock = s => ({ action: 'block', locked: true, reasons: [{ severity: 'crit', code: 'duress_lockdown', text: `Security time-lock is active until ${new Date(s.lockUntil * 1000).toLocaleString()}. Transfers are held until then and nobody can shorten it.` }], summary: [] });

async function api(path, body, method = 'POST') {
  const s = await get();
  if (!s.token) return { unpaired: true };
  const r = await fetch(s.backend.replace(/\/$/, '') + path, {
    method, headers: { 'content-type': 'application/json', authorization: 'Bearer ' + s.token }, body: method === 'GET' ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(20000)
  });
  // A rejected token unpairs the shield, but a cached time-lock stays in force until it runs out.
  if (r.status === 401) { await chrome.storage.local.set({ token: null }); return { unpaired: true }; }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) return { error: j.error || 'request failed', status: r.status };
  return j;
}

async function bumpStats(res) {
  const s = await get();
  const st = s.stats || { checked: 0, blocked: 0, warned: 0 };
  st.checked++; if (res.action === 'block') st.blocked++; if (res.action === 'warn') st.warned++;
  await chrome.storage.local.set({ stats: st });
  if (res.action === 'block') { chrome.action.setBadgeText({ text: String(st.blocked) }); chrome.action.setBadgeBackgroundColor({ color: '#ff5a6b' }); }
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    const s = await get();
    // Messages from web pages (content scripts) may only ask for checks. Pairing, switching off and unpairing
    // only come from the extension's own popup.
    const fromPopup = !sender.tab && sender.id === chrome.runtime.id;
    if (!fromPopup && !['check', 'shield'].includes(msg?.type)) return reply(null);
    if (msg.type === 'check') {
      // During a time-lock nothing gets through unchecked: not switched off, not unpaired, not offline.
      if (!s.enabled && !locked(s)) return reply({ action: 'allow', disabled: true });
      if (!s.token) return reply(locked(s) ? lockBlock(s) : { action: 'allow', unpaired: true });
      const path = msg.kind === 'solana' ? '/api/firewall/solana' : '/api/firewall/evm';
      const res = await api(path, msg.payload).catch(() => ({ error: 'offline' }));
      if (res.lockdown?.until) await chrome.storage.local.set({ lockUntil: res.lockdown.until });
      if (res.unpaired) return reply(locked(s) ? lockBlock(s) : { action: 'allow', unpaired: true });
      if (res.error) return reply(locked(s) ? lockBlock(s) : { action: 'warn', error: res.error });
      await bumpStats(res);
      return reply(res);
    }
    if (msg.type === 'shield') {
      if (!s.enabled || !s.token) return reply(null);
      return reply(await api('/api/shield/check', { address: msg.address, event: msg.event, origin: msg.origin }).catch(() => null));
    }
    if (msg.type === 'pair') {
      const backend = String(msg.backend || '').replace(/\/$/, '');
      if (!/^https:\/\/[^/]+$/.test(backend) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(backend)) return reply({ error: 'Use your Bodyguard address starting with https://' });
      const r = await fetch(backend + '/api/ext/pair', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: msg.code }) }).catch(() => null);
      if (!r) return reply({ error: "Couldn't reach that server. Check the address." });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return reply({ error: j.error || 'Pairing failed.' });
      await chrome.storage.local.set({ backend, token: j.token, agentId: j.agentId, enabled: true });
      return reply({ ok: true, agentId: j.agentId });
    }
    if (msg.type === 'status') {
      if (!s.token) return reply({ paired: false, backend: s.backend, stats: s.stats });
      const me = await api('/api/ext/me', null, 'GET').catch(() => ({ error: 'offline' }));
      if (me && 'lockdownUntil' in me) await chrome.storage.local.set({ lockUntil: me.lockdownUntil || 0 });
      const fresh = await get();
      return reply({ paired: !me.unpaired, me, enabled: fresh.enabled, locked: locked(fresh), lockUntil: fresh.lockUntil, backend: s.backend, stats: s.stats });
    }
    if (msg.type === 'toggle') {
      if (!msg.enabled && locked(s)) return reply({ error: 'The shield cannot be switched off while a security time-lock is active.' });
      await chrome.storage.local.set({ enabled: !!msg.enabled }); return reply({ ok: true });
    }
    if (msg.type === 'unpair') {
      if (locked(s)) return reply({ error: 'The shield cannot be unpaired while a security time-lock is active.' }); await chrome.storage.local.set({ token: null, agentId: null }); chrome.action.setBadgeText({ text: '' }); return reply({ ok: true }); }
    reply(null);
  })();
  return true;
});

// Learn about a time-lock as soon as it starts, not only at the next signing request (an attacker might take the
// computer offline first). Checks every minute while paired.
async function refreshLock() {
  const s = await get();
  if (!s.token) return;
  const me = await api('/api/ext/me', null, 'GET').catch(() => null);
  if (me && 'lockdownUntil' in me) await chrome.storage.local.set({ lockUntil: Math.max(me.lockdownUntil || 0, (s.lockUntil || 0) * 1000 > Date.now() ? s.lockUntil : 0) });
}
chrome.alarms.create('bodyguard-lock', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(a => { if (a.name === 'bodyguard-lock') refreshLock().catch(() => {}); });
chrome.runtime.onStartup.addListener(() => refreshLock().catch(() => {}));
