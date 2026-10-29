// Bodyguard dashboard. Loaded as a file (not inline) so the page can run under a CSP with no inline scripts.
(() => {
'use strict';
const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = a => (a && a.length > 12 ? `${a.slice(0, a.startsWith('0x') ? 6 : 4)}…${a.slice(-4)}` : a || '');
const when = t => t ? new Date(t * 1000).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—';
const fmt = n => Number(n).toLocaleString('en-GB');
const store = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch {} } };
let toastT;
function toast(msg, err) { const t = $('#toast'); t.textContent = msg; t.className = 'toast show' + (err ? ' err' : ''); clearTimeout(toastT); toastT = setTimeout(() => t.className = 'toast', 4200); }

/* ---------------- API ---------------- */
const S = { token: store.get('bg_token'), me: null, agentId: store.get('bg_agent'), agent: null, provider: null, wallet: null, view: 'overview' };
async function api(path, opts = {}) {
  const r = await fetch(path, { method: opts.method || (opts.body ? 'POST' : 'GET'), headers: { 'content-type': 'application/json', ...(S.token ? { authorization: 'Bearer ' + S.token } : {}) }, body: opts.body ? JSON.stringify(opts.body) : undefined });
  const j = await r.json().catch(() => ({}));
  // Only a real session problem signs you out. A wrong PIN (Duress Mode) also answers 401, and must not.
  if (r.status === 401 && S.token && !path.startsWith('/api/auth') && !path.startsWith('/api/duress/') && !/admin tools/.test(j.error || '')) { signOut(); throw new Error('Your session ended. Sign in again.'); }
  if (!r.ok) throw new Error(j.error || 'Request failed');
  return j;
}
let duressPin = null;
const guard = fn => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };

/* ---------------- wallets ---------------- */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58(bytes) { const d = []; for (const by of bytes) { let c = by; for (let j = 0; j < d.length; j++) { c += d[j] << 8; d[j] = c % 58; c = (c / 58) | 0; } while (c) { d.push(c % 58); c = (c / 58) | 0; } } let o = ''; for (const by of bytes) { if (by === 0) o += '1'; else break; } for (let k = d.length - 1; k >= 0; k--) o += B58[d[k]]; return o; }
const std = [];
const stdApi = { register: (...w) => { w.forEach(x => { if (!std.includes(x)) std.push(x); }); return () => {}; } };
addEventListener('wallet-standard:register-wallet', e => { try { e.detail(stdApi); } catch {} });
try { dispatchEvent(new CustomEvent('wallet-standard:app-ready', { detail: stdApi })); } catch {}
function stdAdapter(w) {
  const f = w.features, chain = 'solana:mainnet'; let acct = null;
  const ser = tx => tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  return {
    async connect() { const r = await f['standard:connect'].connect(); acct = ((r && r.accounts) || w.accounts)[0]; this.publicKey = { toString: () => acct.address }; return { publicKey: this.publicKey }; },
    async signMessage(msg) { const [o] = await f['solana:signMessage'].signMessage({ account: acct, message: msg }); return { signature: o.signature }; },
    async signAllTransactions(txs) { const out = await f['solana:signTransaction'].signTransaction(...txs.map(t => ({ account: acct, transaction: ser(t), chain }))); return out.map(o => ({ serialize: () => o.signedTransaction })); }
  };
}
function walletChoices() {
  const out = [];
  const add = (name, p) => { if (p && !out.some(o => o.name === name)) out.push({ name, p }); };
  add('Phantom', window.phantom?.solana?.isPhantom ? window.phantom.solana : null);
  add('Solflare', window.solflare?.isSolflare ? window.solflare : null);
  add('Backpack', window.backpack?.isBackpack ? window.backpack : null);
  std.forEach(w => { if (w.chains?.includes('solana:mainnet') && w.features?.['standard:connect'] && w.features?.['solana:signMessage'] && !out.some(o => o.name.toLowerCase() === String(w.name).toLowerCase())) add(w.name, stdAdapter(w)); });
  return out;
}
async function connect(p) {
  const r = await p.connect();
  const pk = (r && r.publicKey) || p.publicKey;
  S.provider = p; S.wallet = pk.toString();
  return S.wallet;
}
async function signIn(choice) {
  const wallet = await connect(choice.p);
  const { message } = await api('/api/auth/nonce', { body: { wallet } });
  const res = await choice.p.signMessage(new TextEncoder().encode(message), 'utf8');
  const sig = res.signature || res;
  const { token } = await api('/api/auth/verify', { body: { wallet, signature: b58(sig instanceof Uint8Array ? sig : new Uint8Array(sig)) } });
  S.token = token; store.set('bg_token', token);
  await boot();
}
function renderSignin() {
  $('#signinView').hidden = false; $('#appView').hidden = true;
  $('#walletChip').hidden = $('#signOut').hidden = $('#agentSel').hidden = true;
  const ch = walletChoices();
  $('#walletList').innerHTML = ch.length ? ch.map((c, i) => `<div class="item"><div class="t"><b>${esc(c.name)}</b></div><button class="btn p sm" data-i="${i}">Sign in</button></div>`).join('')
    : '<div class="item"><div class="t"><b>No Solana wallet found</b><small>Install Phantom, Solflare or Backpack, then refresh. On a phone, open this page inside your wallet app.</small></div></div>';
  $$('#walletList [data-i]').forEach(b => b.onclick = guard(async () => { b.disabled = true; try { await signIn(ch[+b.dataset.i]); } finally { b.disabled = false; } }));
  $('#walletNote').textContent = 'Bodyguard will never ask for your seed phrase.';
  if (!ch.length) setTimeout(() => { if (!S.token && walletChoices().length) renderSignin(); }, 900);
}
function signOut() { api('/api/auth/logout', { body: {} }).catch(() => {}); S.token = null; store.set('bg_token', null); renderSignin(); }
$('#signOut').onclick = signOut;
async function ensureWallet() {
  if (S.provider) return S.provider;
  const ch = walletChoices();
  if (!ch.length) throw new Error('Open this page in a browser with your Solana wallet installed.');
  const c = ch.find(x => x.name === store.get('bg_wallet_name')) || ch[0];
  const w = await connect(c.p);
  if (w !== S.me.wallet) toast(`Connected ${short(w)}, which is not the wallet you signed in with.`, true);
  return S.provider;
}
let web3P;
const WEB3_CDN = 'https://cdn.jsdelivr.net/npm/@solana/web3.js@1.95.3/lib/index.iife.min.js';
// Loads the wallet library from this server's integrity-checked copy (falls back to the CDN with the same hash).
const web3 = () => window.solanaWeb3 ? Promise.resolve(window.solanaWeb3) : (web3P ||= new Promise((res, rej) => {
  const C = window.BG_CONFIG || {}, sri = C.WEB3_SRI || '', first = C.WEB3_URL || WEB3_CDN;
  const add = (src, fail) => { const s = document.createElement('script'); s.src = src; if (sri) { s.integrity = sri; s.crossOrigin = 'anonymous'; } s.onload = () => (window.solanaWeb3 ? res(window.solanaWeb3) : rej(new Error('lib'))); s.onerror = fail; document.head.append(s); };
  add(first, () => (first !== WEB3_CDN ? add(WEB3_CDN, e => { web3P = null; rej(e); }) : (web3P = null, rej(new Error('lib')))));
}));
async function rpc(method, params) { const r = await fetch('/api/rpc', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }); const j = await r.json(); if (j.error) throw new Error(j.error.message || j.error); return j.result; }
async function signAndSendAll(b64s) {
  const w3 = await web3(); const p = await ensureWallet();
  const txs = b64s.map(b => w3.Transaction.from(Uint8Array.from(atob(b), c => c.charCodeAt(0))));
  const signed = txs.length === 1 && p.signTransaction ? [await p.signTransaction(txs[0])] : await p.signAllTransactions(txs);
  const sigs = [];
  for (const s of signed) { const raw = s.serialize(); let bin = ''; raw.forEach(x => bin += String.fromCharCode(x)); sigs.push(await rpc('sendTransaction', [btoa(bin), { encoding: 'base64', preflightCommitment: 'confirmed' }])); }
  for (let i = 0; i < 40; i++) {
    const st = await rpc('getSignatureStatuses', [sigs]);
    if (st.value.every(v => v && (v.confirmationStatus === 'confirmed' || v.confirmationStatus === 'finalized' || v.err))) return { sigs, errors: st.value.filter(v => v.err).length };
    await new Promise(r => setTimeout(r, 1500));
  }
  return { sigs, errors: 0, pending: true };
}

/* ---------------- shell ---------------- */
const NAV = [
  ['grp', 'Agent'], ['overview', 'Overview'], ['brief', 'Briefing'], ['alerts', 'Alerts'], ['channels', 'Alert channels'], ['shield', 'Poisoning shield'], ['sweep', 'Spam sweep'], ['extension', 'Browser extension'], ['team', 'Team seats'],
  ['grp', 'Business'], ['org', 'Organisation'], ['screening', 'Risk Screening'], ['wallets', 'Guarded Wallets'], ['treasury', 'Treasury Watch'], ['drills', 'Scam Drills'],
  ['grp', 'Personal safety'], ['duress', 'Duress Mode'], ['freeze', 'Freeze Desk'],
  ['grp', 'Account'], ['security', 'Sign-ins & activity'],
  ['grp', 'Admin'], ['support', 'Help desk'], ['adminsec', 'Security'], ['help', 'Get help']
];
const ORG_VIEWS = ['org', 'screening', 'wallets', 'treasury', 'drills', 'duress', 'freeze', 'security', 'support', 'adminsec', 'help'];
async function boot() {
  if (!S.token) return renderSignin();
  try { S.me = await api('/api/me'); } catch { return renderSignin(); }
  $('#signinView').hidden = true; $('#appView').hidden = false;
  $('#walletChip').hidden = false; $('#walletChip').textContent = short(S.me.wallet); $('#walletChip').className = 'chip on'; $('#signOut').hidden = false;
  if (!S.me.agents.some(a => a.id === S.agentId)) S.agentId = S.me.agents[0]?.id || null;
  const sel = $('#agentSel');
  sel.hidden = S.me.agents.length < 2;
  sel.innerHTML = S.me.agents.map(a => `<option value="${a.id}" ${a.id === S.agentId ? 'selected' : ''}>Agent ${a.id} · ${esc(a.rankName)}</option>`).join('');
  sel.onchange = () => { S.agentId = sel.value; store.set('bg_agent', S.agentId); go(S.view); };
  const view = (location.hash || '#overview').slice(1).split('?')[0];
  go(NAV.some(n => n[0] === view) ? view : 'overview');
  const q = new URLSearchParams(location.search);
  if (q.get('inbox')) { toast(q.get('msg') || 'Inbox updated', q.get('inbox') !== 'connected'); history.replaceState(null, '', '/app#brief'); }
}
function rail() {
  const org = S.me.org;
  $('#rail').innerHTML = NAV.map(([id, label]) => {
    if (id === 'grp') return label === 'Admin' && !S.me.admin ? '' : label === 'Business' && !org ? '' : `<span class="k grp">${label}</span>`;
    if (id === 'support' || id === 'adminsec') return S.me.admin ? `<a href="#${id}" class="${S.view === id ? 'on' : ''}" data-v="${id}">${label}</a>` : '';
    if (id === 'security') return `<a href="#security" class="${S.view === id ? 'on' : ''}" data-v="security">${label}</a>`;
    if (id === 'help') return '<a href="/help">Get help</a>';
    // Personal-safety services are always listed, so people can find and buy them.
    if (id === 'duress' || id === 'freeze') return `<a href="#${id}" class="${S.view === id ? 'on' : ''}" data-v="${id}">${label}</a>`;
    const svc = { screening: 'screening', wallets: 'wallets', treasury: 'treasury', drills: 'drills' }[id];
    if ((svc || id === 'org') && !org) return '';
    if (svc && !org.services[svc]?.active) return '';
    if (!svc && id !== 'org' && !S.me.agents.length && id !== 'overview') return '';
    return `<a href="#${id}" class="${S.view === id ? 'on' : ''}" data-v="${id}">${label}</a>`;
  }).join('');
}
let lastHash = location.hash;
addEventListener('hashchange', () => { if (S.me && location.hash.length > 1 && location.hash !== lastHash) go(location.hash.slice(1)); });
async function go(view) {
  view = String(view).split('?')[0];
  S.view = view; if (location.hash.slice(1).split('?')[0] !== view) history.replaceState(null, '', '#' + view);
  lastHash = location.hash;
  rail();
  const main = $('#main');
  main.innerHTML = '<div class="empty">Loading…</div>';
  try {
    if (view !== 'duress') duressPin = null; // the settings PIN is forgotten as soon as you leave the page
    if (S.agentId && !ORG_VIEWS.includes(view)) S.agent = await api('/api/agent/' + S.agentId);
    await (VIEWS[view] || VIEWS.overview)(main);
  } catch (e) { main.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}
const noAgent = () => `<div class="card"><h2>No agent on this wallet</h2><p class="muted">Hire an agent from the main site with this wallet, then come back here to brief it.</p><div><a class="btn p" href="/#tiers">Hire an agent</a></div></div>`;
const alertHtml = a => `<div class="alert ${a.severity} ${a.acked_at ? 'acked' : ''}"><div class="row"><span class="sev ${a.severity}">${{ low: 'Low', med: 'Medium', high: 'High', crit: 'Critical' }[a.severity]}</span><b class="f1">${esc(a.title)}</b><span class="k">${when(a.created_at)}</span></div>
  <span class="lbl">What happened</span><p>${esc(a.what)}</p><span class="lbl">What your agent did</span><p>${esc(a.did)}</p><span class="lbl">Your move</span><p>${esc(a.move)}</p>
  <div class="row">${/^https:\/\//.test(a.data?.link || '') ? `<a href="${esc(a.data.link)}" target="_blank" rel="noopener noreferrer" class="btn g sm">View on explorer</a>` : ''}${a.acked_at ? '<span class="k">Acknowledged</span>' : `<button class="btn g sm" data-ack="${a.id}">Acknowledge</button>`}</div></div>`;
function bindAcks(root, after) { $$('[data-ack]', root).forEach(b => b.onclick = guard(async () => { await api(`/api/alerts/${b.dataset.ack}/ack`, { body: {} }); after ? after() : b.closest('.alert').classList.add('acked'); b.remove(); })); }
const policyForm = (p = {}) => `<div class="grid2"><label><span class="k">Per-transaction limit</span><input name="perTxLimit" type="number" min="0" step="any" value="${p.perTxLimit || ''}" placeholder="0 = none"></label>
  <label><span class="k">Daily limit (24h)</span><input name="dailyLimit" type="number" min="0" step="any" value="${p.dailyLimit || ''}" placeholder="0 = none"></label>
  <label><span class="k">Extra approvals above</span><input name="apAmount" type="number" min="0" step="any" value="${p.approvalsAbove?.amount || ''}" placeholder="amount"></label>
  <label><span class="k">Approvals needed</span><input name="apCount" type="number" min="1" max="10" value="${p.approvalsAbove?.approvals || 2}"></label>
  <label><span class="k">Timelock above</span><input name="tlAmount" type="number" min="0" step="any" value="${p.timelockAbove?.amount || ''}" placeholder="amount"></label>
  <label><span class="k">Timelock hours</span><input name="tlHours" type="number" min="0" value="${p.timelockAbove ? Math.round(p.timelockAbove.seconds / 3600) : 24}"></label></div>
  <label><span class="k">Approved destinations (one per line, empty = any)</span><textarea name="allowlist" rows="3">${esc((p.allowlist || []).join('\n'))}</textarea></label>
  <label><span class="k">Blocked destinations</span><textarea name="blocklist" rows="2">${esc((p.blocklist || []).join('\n'))}</textarea></label>`;
const readPolicy = f => { const v = n => f.elements[n]?.value; return { perTxLimit: v('perTxLimit'), dailyLimit: v('dailyLimit'), allowlist: v('allowlist'), blocklist: v('blocklist'),
  approvalsAbove: Number(v('apAmount')) > 0 ? { amount: v('apAmount'), approvals: v('apCount') } : null, timelockAbove: Number(v('tlAmount')) > 0 ? { amount: v('tlAmount'), seconds: Number(v('tlHours') || 0) * 3600 } : null }; };

/* ---------------- Duress Mode settings (shown only after the real PIN) ---------------- */
function renderDuress(m, v) {
  const s = v.settings, chains = ['solana', 'ethereum', 'bitcoin', 'base', 'arbitrum', 'optimism', 'polygon', 'bnb'];
  const evLabel = { setup: 'Turned on', triggered: 'DURESS PIN USED', pins_changed: 'PINs changed', settings_applied: 'Delayed change applied', test: 'Test alert sent', disabled: 'Turned off' };
  m.innerHTML = `<div class="card"><div class="row"><div class="f1"><span class="k">Personal safety</span><h2>Duress Mode</h2></div><span class="chip ${v.lockdownUntil ? '' : 'on'}" style="${v.lockdownUntil ? 'color:var(--red);border-color:var(--red)' : ''}">${v.lockdownUntil ? 'Time-lock until ' + when(v.lockdownUntil) : 'Armed'}</span></div>
    <p class="muted">Under threat, open <a href="/vault" target="_blank" rel="noopener">${esc(location.host)}/vault</a> and enter your <b>duress PIN</b>. Add that page to your phone's home screen now so it's one tap away. It looks like an ordinary wallet vault.</p>
    ${v.pending ? `<div class="verdict new"><b>${v.pending.disable ? 'Duress Mode switches off' : 'Weaker settings apply'} at ${when(v.pending.applyAt)}.</b> Changes that reduce protection wait ${v.weakenDelayHours} hours, so nobody can force you to switch it off on the spot. <button class="btn g sm" id="cancelP">Cancel the change</button></div>` : ''}</div>
    <div class="grid2"><div class="card"><div class="row"><h3 class="f1">Trusted contacts</h3><span class="k">${v.contacts.length}/5</span></div>
      <p class="muted" style="font-size:13.5px">They get an email invite and must accept before they can receive an alert.</p>
      <div class="list">${v.contacts.map(c => `<div class="item"><div class="t"><b>${esc(c.name)}</b><small>${esc(c.email)} · ${c.remove_at ? 'removed ' + when(c.remove_at) : c.status === 'confirmed' ? 'confirmed' : 'invite sent, waiting'}</small></div>${c.remove_at ? '' : `<button class="btn d sm" data-rmc="${esc(c.id)}">Remove</button>`}</div>`).join('') || '<div class="item"><div class="t"><small>No contacts yet.</small></div></div>'}</div>
      <form id="addc" class="grid2"><input name="name" placeholder="Name" required maxlength="60"><input name="email" type="email" placeholder="Email" required><div><button class="btn p sm">Invite</button> <button type="button" class="btn g sm" id="testA">Send a test alert</button></div></form></div>
    <div class="card"><h3>Lockdown</h3><form id="set" style="display:grid;gap:10px">
      <label><span class="k">Cooling-off after a duress unlock (hours)</span><input name="coolingHours" type="number" min="1" max="168" value="${s.coolingHours}"></label>
      <div class="grid2"><label><span class="k">Still allowed: SOL</span><input name="aSol" type="number" step="any" min="0" value="${s.allowance.solana}"></label><label><span class="k">EVM native coin</span><input name="aEvm" type="number" step="any" min="0" value="${s.allowance.evm}"></label></div>
      <label><span class="k">Your name for contacts</span><input name="name" value="${esc(s.name)}" maxlength="60"></label>
      <label><span class="k">Note to contacts</span><textarea name="message" rows="2" maxlength="280">${esc(s.message)}</textarea></label>
      <label class="cb"><input type="checkbox" name="shareLocation" ${s.shareLocation ? 'checked' : ''}> Share my location in a duress alert</label>
      <span class="k">Decoy wallets</span>${[0, 1, 2].map(i => { const d = s.decoyWallets[i] || {}; return `<div class="row" data-decoy><select style="width:auto">${chains.map(c => `<option ${c === (d.chain || 'solana') ? 'selected' : ''}>${c}</option>`).join('')}</select><input class="f1 mono" value="${esc(d.address || '')}" placeholder="Decoy address"><input style="width:120px" value="${esc(d.label || '')}" placeholder="Label"></div>`; }).join('')}
      <div><button class="btn p">Save</button></div></form></div></div>
    <div class="grid2"><div class="card"><h3>Change PINs</h3><form id="pins" style="display:grid;gap:10px"><input name="currentPin" type="password" inputmode="numeric" placeholder="Current real PIN" required autocomplete="off">
      <div class="grid2"><input name="realPin" type="password" inputmode="numeric" placeholder="New real PIN" required autocomplete="new-password"><input name="duressPin" type="password" inputmode="numeric" placeholder="New duress PIN" required autocomplete="new-password"></div><div><button class="btn g">Change PINs</button></div></form></div>
    <div class="card"><h3>Activity</h3><div class="list">${v.events.map(e => `<div class="item"><div class="t"><b style="${e.kind === 'triggered' ? 'color:var(--red)' : ''}">${esc(evLabel[e.kind] || e.kind)}</b><small>${when(e.created_at)}${e.data?.location ? ` · location shared` : ''}</small></div></div>`).join('') || '<div class="item"><div class="t"><small>Nothing yet.</small></div></div>'}</div>
      <div><button class="btn d sm" id="off">Switch Duress Mode off</button></div></div></div>`;
  const pin = duressPin, again = r => renderDuress(m, r);
  const cp = $('#cancelP', m); if (cp) cp.onclick = guard(async () => again(await api('/api/duress/cancel-pending', { body: { pin } })));
  $('#addc', m).onsubmit = guard(async e => { e.preventDefault(); again(await api('/api/duress/contacts', { body: { pin, name: e.target.name.value, email: e.target.email.value } })); toast('Invite sent. They need to accept it.'); });
  $('#testA', m).onclick = guard(async () => { const r = await api('/api/duress/test', { body: { pin } }); toast(`Test sent to ${r.sent} contact(s).`); });
  $$('[data-rmc]', m).forEach(b => b.onclick = guard(async () => again(await api('/api/duress/contacts/' + b.dataset.rmc, { method: 'DELETE', body: { pin } }))));
  const f = $('#set', m);
  f.shareLocation.onchange = () => { if (f.shareLocation.checked && navigator.geolocation) navigator.geolocation.getCurrentPosition(() => {}, () => { toast('Location was not allowed.', true); f.shareLocation.checked = false; }); };
  f.onsubmit = guard(async e => {
    e.preventDefault();
    const decoyWallets = $$('[data-decoy]', m).map(r => { const [a, l] = $$('input', r); return { chain: $('select', r).value, address: a.value.trim(), label: l.value }; }).filter(d => d.address);
    const r = await api('/api/duress/settings', { body: { pin, settings: { coolingHours: f.coolingHours.value, allowance: { solana: f.aSol.value, evm: f.aEvm.value }, name: f.name.value, message: f.message.value, shareLocation: f.shareLocation.checked, decoyWallets } } });
    toast(r.pending ? 'Saved. Weaker limits apply in 24 hours.' : 'Saved.'); again(r);
  });
  $('#pins', m).onsubmit = guard(async e => { e.preventDefault(); const f2 = e.target; const r = await api('/api/duress/setup', { body: { currentPin: f2.currentPin.value, realPin: f2.realPin.value, duressPin: f2.duressPin.value } }); duressPin = f2.realPin.value; toast('PINs changed.'); renderDuress(m, r); });
  $('#off', m).onclick = guard(async () => { again(await api('/api/duress/disable', { body: { pin } })); toast('Duress Mode switches off in 24 hours. You can cancel until then.'); });
}

/* ---------------- Freeze Desk case ---------------- */
async function download(path, filename) {
  const r = await fetch(path, { headers: { authorization: 'Bearer ' + S.token } });
  if (!r.ok) throw new Error('Download failed.');
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement('a'); a.href = url; a.download = filename; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
function renderCase(m, c, dir) {
  const st = { ready: 'Ready to send', queued: 'Queued', sent: 'Emailed', failed: 'Email failed', submitted: 'Submitted', acknowledged: 'Acknowledged', frozen: 'Frozen', declined: 'Declined' };
  const verify = `${location.origin}/api/evidence/verify/${c.hash}`;
  const have = new Set(c.requests.map(r => r.target));
  m.innerHTML = `<div class="card"><div class="row"><div class="f1"><span class="k">Freeze Desk · ${esc(c.status)}</span><h2>${esc(c.ref)}</h2></div><a class="btn g sm" href="#freeze">All cases</a></div>
    <small class="muted">${esc(c.title)} · locked ${esc(c.lockedAt)}</small>
    <div class="code">SHA-256 ${esc(c.hash)}</div>
    <div class="row"><a class="btn g sm" href="${esc(verify)}" target="_blank" rel="noopener">Signed receipt</a><button class="btn g sm" id="dlM">Evidence file (.json)</button><button class="btn g sm" id="dlR">All requests (.txt)</button>
    ${c.anchor ? `<a class="btn g sm" href="https://solscan.io/tx/${esc(c.anchor)}" target="_blank" rel="noopener noreferrer">On Solana ✓</a>` : '<button class="btn g sm" id="anchor">Timestamp on Solana</button>'}</div>
    <small class="muted">The evidence file is exactly what was fingerprinted: anyone can hash it and compare. Timestamping on Solana writes only the fingerprint, from your wallet, for about 0.00001 SOL.</small></div>
    <div class="card"><h3>Freeze requests</h3><div class="list">${c.requests.map(r => `<div class="item"><div class="t"><b>${esc(r.targetInfo?.name || r.target)}</b><small>${esc(st[r.status] || r.status)}${r.sent_at ? ' · ' + when(r.sent_at) : ''}${r.targetInfo?.note ? ' · ' + esc(r.targetInfo.note) : ''}</small></div>
      <div class="row"><button class="btn g sm" data-copy="${esc(r.id)}">Copy request</button>${r.targetInfo?.url ? `<a class="btn g sm" href="${esc(r.targetInfo.url)}" target="_blank" rel="noopener noreferrer">Official page ↗</a>` : ''}
      ${r.channel === 'email' && r.status !== 'sent' ? `<button class="btn p sm" data-send="${esc(r.target)}">Email now</button>` : ''}${['ready', 'failed'].includes(r.status) ? `<button class="btn g sm" data-mark="${esc(r.id)}">Mark submitted</button>` : ''}</div></div>`).join('') || '<div class="item"><div class="t"><small>No targets picked yet.</small></div></div>'}</div>
      <div class="row"><select id="addT" class="f1">${dir.targets.filter(t => !have.has(t.id)).map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('')}</select><button class="btn g sm" id="addTB">Add target</button></div></div>
    <div class="grid2"><div class="card"><h3>Timeline</h3><div class="list">${c.events.map(e => `<div class="item"><div class="t"><b style="${e.kind === 'exchange_hit' ? 'color:var(--red)' : ''}">${esc(e.text)}</b><small>${when(e.created_at)}</small></div></div>`).join('')}</div>
      <form id="note" class="row"><input class="f1" name="text" placeholder="Add a note, e.g. police reference or exchange reply"><button class="btn g sm">Add</button></form></div>
    <div class="card"><h3>Evidence</h3><div class="list">${c.manifest.transactions.map(t => `<div class="item"><div class="t"><b class="mono">${esc(short(t.hash))} · ${esc(t.chain)}</b><small>${t.verified ? 'Verified on-chain' + (t.time ? ' · ' + esc(t.time) : '') : esc(t.note || 'Not verified')}</small></div><a class="btn g sm" href="${esc(t.explorer)}" target="_blank" rel="noopener noreferrer">Explorer</a></div>`).join('')}
      ${!c.manifest.transactions.length && !c.files.length ? '<div class="item"><div class="t"><small>No transaction IDs or files were added. Add transaction IDs in a new case for on-chain verification.</small></div></div>' : ''}
      ${c.files.map(f => `<div class="item"><div class="t"><b>${esc(f.name)}</b><small class="mono">SHA-256 ${esc(f.sha256.slice(0, 24))}…</small></div><button class="btn g sm" data-file="${esc(f.id)}" data-name="${esc(f.name)}">Download</button></div>`).join('')}</div>
      <span class="k">Watching ${c.trace.watch?.length || 0} address(es) for movement · ${c.trace.hops?.length || 0} move(s) seen</span>
      <div class="row">${c.status === 'open' ? '<button class="btn d sm" id="close">Close case</button>' : '<button class="btn g sm" id="reopen">Reopen case</button>'}</div></div></div>`;
  const reload = async () => renderCase(m, await api('/api/freeze/incidents/' + c.id), dir);
  $('#dlM', m).onclick = guard(() => download(`/api/freeze/incidents/${c.id}/manifest`, `evidence-${c.ref}.json`));
  $('#dlR', m).onclick = () => { const txt = c.requests.map(r => `===== ${r.targetInfo?.name || r.target} =====\nSubject: ${r.subject}\n\n${r.body}`).join('\n\n\n'); const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([txt], { type: 'text/plain' })); a.download = `freeze-requests-${c.ref}.txt`; a.click(); };
  $$('[data-copy]', m).forEach(b => b.onclick = guard(async () => { const r = c.requests.find(x => x.id === b.dataset.copy); await navigator.clipboard.writeText(`Subject: ${r.subject}\n\n${r.body}`); toast('Copied. Paste it into their form or email.'); }));
  $$('[data-send]', m).forEach(b => b.onclick = guard(async () => { b.disabled = true; const r = await api(`/api/freeze/incidents/${c.id}/send`, { body: { targets: [b.dataset.send] } }); toast(r.results[0]?.ok ? 'Sent.' : 'Could not send. Use the official page.', !r.results[0]?.ok); reload(); }));
  $$('[data-mark]', m).forEach(b => b.onclick = guard(async () => { await api(`/api/freeze/requests/${b.dataset.mark}/mark`, { body: { status: 'submitted' } }); reload(); }));
  $$('[data-file]', m).forEach(b => b.onclick = guard(() => download(`/api/freeze/incidents/${c.id}/files/${b.dataset.file}`, b.dataset.name)));
  const addTB = $('#addTB', m); addTB.onclick = guard(async () => { const v = $('#addT', m).value; if (!v) return; renderCase(m, await api(`/api/freeze/incidents/${c.id}/targets`, { body: { targets: [v] } }), dir); });
  $('#note', m).onsubmit = guard(async e => { e.preventDefault(); renderCase(m, await api(`/api/freeze/incidents/${c.id}/note`, { body: { text: e.target.text.value } }), dir); });
  const cl = $('#close', m); if (cl) cl.onclick = guard(async () => renderCase(m, await api(`/api/freeze/incidents/${c.id}/note`, { body: { text: 'Case closed.', status: 'closed' } }), dir));
  const ro = $('#reopen', m); if (ro) ro.onclick = guard(async () => renderCase(m, await api(`/api/freeze/incidents/${c.id}/note`, { body: { text: 'Case reopened.', status: 'open' } }), dir));
  const an = $('#anchor', m);
  if (an) an.onclick = guard(async () => {
    an.disabled = true; an.textContent = 'Approve in your wallet…';
    try {
      const w3 = await web3(); const p = await ensureWallet();
      const { blockhash } = (await rpc('getLatestBlockhash', [{ commitment: 'confirmed' }])).value;
      const owner = new w3.PublicKey(S.wallet);
      const tx = new w3.Transaction({ feePayer: owner, recentBlockhash: blockhash }).add(new w3.TransactionInstruction({ programId: new w3.PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'), keys: [{ pubkey: owner, isSigner: true, isWritable: false }], data: owner.toBuffer().constructor.from(new TextEncoder().encode('bodyguard:evidence:' + c.hash)) }));
      const raw = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
      let bin = ''; raw.forEach(x => bin += String.fromCharCode(x));
      const { sigs, errors } = await signAndSendAll([btoa(bin)]);
      if (errors) throw new Error('The transaction failed on-chain.');
      renderCase(m, await api(`/api/freeze/incidents/${c.id}/anchor`, { body: { signature: sigs[0] } }), dir); toast('Fingerprint timestamped on Solana.');
    } finally { an.disabled = false; an.textContent = 'Timestamp on Solana'; }
  });
}

/* ---------------- views ---------------- */
const VIEWS = {
  async overview(m) {
    if (!S.agent) { m.innerHTML = noAgent() + (S.me.org ? '<div class="card"><h3>Business console</h3><p class="muted">Your organisation services are in the left menu.</p></div>' : ''); return; }
    const a = S.agent, L = a.limits, u = a.used;
    const { alerts } = await api(`/api/agent/${a.id}/alerts`);
    const open = alerts.filter(x => !x.acked_at && x.severity !== 'low').length;
    m.innerHTML = `<div class="card"><div class="row"><div class="f1"><span class="k">Agent</span><h1>Agent ${a.id}</h1></div><span class="chip ${a.active ? 'on' : ''}">${a.active ? 'On duty' : 'Off duty'}</span></div>
      <div class="row muted" style="font-size:14px"><span>${esc(a.rankName)}</span><span>·</span><span>${a.expiresAt ? (a.active ? 'Paid until ' : 'Expired ') + when(a.expiresAt) : 'No expiry'}</span></div>
      ${!a.active ? '<div class="row"><a class="btn p" href="/#tiers">Renew your rank</a></div>' : ''}</div>
      <div class="grid4"><div class="tile"><span class="k">Wallets</span><b>${u.wallets}/${L.wallets}</b></div><div class="tile"><span class="k">Emails</span><b>${u.emails}/${L.emails}</b></div>
      <div class="tile"><span class="k">Domains</span><b>${u.domains}/${L.domains}</b></div><div class="tile"><span class="k">Open alerts</span><b style="color:${open ? 'var(--amber)' : 'var(--g)'}">${open}</b></div></div>
      ${!a.assets.length ? `<div class="card"><h3>Brief your agent</h3><p class="muted">Your agent is waiting for its briefing. Add the wallets, emails and domains you want guarded.</p><div><a class="btn p" href="#brief">Start the briefing</a></div></div>` : ''}
      ${!a.channels.telegram && !a.channels.email ? `<div class="card"><h3>Make sure alerts reach you</h3><p class="muted">Connect Telegram or add an alert email so your agent can reach you fast.</p><div><a class="btn g" href="#channels">Set up alerts</a></div></div>` : ''}
      <div class="card"><div class="row"><h3 class="f1">Latest alerts</h3><a href="#alerts" class="k">All alerts →</a></div>${alerts.length ? alerts.slice(0, 4).map(alertHtml).join('') : '<div class="empty">No alerts yet. Your agent will report here.</div>'}</div>
      <div class="card"><h3>Patrol status</h3><div class="list">${a.assets.length ? a.assets.map(x => `<div class="item"><div class="t"><b>${esc(x.label || short(x.value))}</b><small>${esc(x.type)}${x.chain ? ' · ' + x.chain : ''} · ${x.lastChecked ? 'checked ' + when(x.lastChecked) : 'first check pending'}</small></div><span class="chip ${x.health === 'ok' ? 'on' : ''}">${x.health === 'ok' ? 'Watching' : esc(x.health || 'Starting')}</span></div>`).join('') : '<div class="item"><div class="t"><small>Nothing briefed yet.</small></div></div>'}</div></div>`;
    bindAcks(m);
  },

  async brief(m) {
    if (!S.agent) return void (m.innerHTML = noAgent());
    const a = S.agent, L = a.limits;
    const chains = L.chains.map(c => `<option value="${c}">${{ solana: 'Solana', ethereum: 'Ethereum', bitcoin: 'Bitcoin', base: 'Base', arbitrum: 'Arbitrum', optimism: 'Optimism', polygon: 'Polygon', bnb: 'BNB Chain' }[c]}</option>`).join('');
    const group = (type, title) => {
      const items = a.assets.filter(x => x.type === type);
      return `<div class="card"><div class="row"><h3 class="f1">${title}</h3><span class="k">${items.length}/${L[{ wallet: 'wallets', email: 'emails', domain: 'domains', handle: 'handles' }[type]]}</span></div>
      ${items.length ? `<div class="list">${items.map(x => `<div class="item"><div class="t"><b>${esc(x.label || x.value)}</b><small class="mono">${esc(x.chain ? x.chain + ' · ' : '')}${esc(x.value)}</small>
        ${type === 'email' ? `<small>${x.inbox ? 'Inbox connected (' + esc(x.inbox) + ')' : 'Breach radar on. Connect the inbox to read security notices and rule changes.'}</small>` : ''}</div>
        <div class="row">${type === 'email' && !x.inbox ? `${S.me.features.inboxGoogle ? `<button class="btn g sm" data-inbox="${x.id}" data-p="google">Gmail</button>` : ''}${S.me.features.inboxMicrosoft ? `<button class="btn g sm" data-inbox="${x.id}" data-p="microsoft">Outlook</button>` : ''}` : ''}
        ${type === 'email' && x.inbox ? `<button class="btn g sm" data-uninbox="${x.id}">Disconnect</button>` : ''}<button class="btn d sm" data-del="${x.id}">Remove</button></div></div>`).join('')}</div>` : '<div class="empty">None yet.</div>'}</div>`;
    };
    m.innerHTML = `<div class="card"><h2>Brief your agent</h2><p class="muted">Add what you want protected. Wallets are public addresses only: never paste a seed phrase or private key anywhere.</p>
      <form id="add" class="grid2"><label><span class="k">What</span><select name="type"><option value="wallet">Wallet</option><option value="email" ${L.emails ? '' : 'disabled'}>Email</option><option value="domain" ${L.domains ? '' : 'disabled'}>Domain</option><option value="handle" ${L.handles ? '' : 'disabled'}>Username / handle</option></select></label>
      <label id="chainWrap"><span class="k">Chain</span><select name="chain">${chains}</select></label>
      <label><span class="k">Address, email, domain or handle</span><input name="value" required autocomplete="off" spellcheck="false"></label>
      <label><span class="k">Label (optional)</span><input name="label" placeholder="e.g. Cold wallet, Kraken deposit"></label>
      <div><button class="btn p" type="submit">Add to briefing</button></div></form></div>
      ${group('wallet', 'Wallets')}${L.emails ? group('email', 'Emails') : ''}${L.domains ? group('domain', 'Domains') : ''}${L.handles ? group('handle', 'Handles (leak watch)') : ''}`;
    const f = $('#add', m);
    f.type.onchange = () => { $('#chainWrap', m).hidden = f.type.value !== 'wallet'; };
    f.onsubmit = guard(async e => { e.preventDefault(); S.agent = await api(`/api/agent/${a.id}/assets`, { body: { type: f.type.value, chain: f.chain.value, value: f.value.value, label: f.label.value } }); toast('Added. Your agent starts watching within a minute.'); go('brief'); });
    $$('[data-del]', m).forEach(b => b.onclick = guard(async () => { await api(`/api/agent/${a.id}/assets/${b.dataset.del}`, { method: 'DELETE' }); go('brief'); }));
    $$('[data-inbox]', m).forEach(b => b.onclick = guard(async () => { const r = await api(`/api/agent/${a.id}/assets/${b.dataset.inbox}/inbox/${b.dataset.p}`, { body: {} }); location.href = r.url; }));
    $$('[data-uninbox]', m).forEach(b => b.onclick = guard(async () => { await api(`/api/agent/${a.id}/assets/${b.dataset.uninbox}/inbox`, { method: 'DELETE' }); go('brief'); }));
  },

  async alerts(m) {
    if (!S.agent) return void (m.innerHTML = noAgent());
    let all = (await api(`/api/agent/${S.agent.id}/alerts`)).alerts;
    const draw = () => { m.innerHTML = `<div class="card"><h2>Alerts</h2>${all.length ? all.map(alertHtml).join('') : '<div class="empty">No alerts yet.</div>'}${all.length >= 50 ? '<button class="btn g" id="more">Load older</button>' : ''}</div>`; bindAcks(m);
      const more = $('#more', m); if (more) more.onclick = guard(async () => { const r = await api(`/api/agent/${S.agent.id}/alerts?before=${all[all.length - 1].id}`); all = all.concat(r.alerts); draw(); }); };
    draw();
  },

  async channels(m) {
    if (!S.agent) return void (m.innerHTML = noAgent());
    const a = S.agent;
    m.innerHTML = `<div class="card"><h2>Alert channels</h2><p class="muted">Medium alerts and above go to Telegram. High and critical also go to email${a.limits.push ? ' and push' : ''}.</p></div>
      <div class="card"><div class="row"><h3 class="f1">Telegram</h3><span class="chip ${a.channels.telegram ? 'on' : ''}">${a.channels.telegram ? 'Connected' : 'Not connected'}</span></div>
      <p class="muted">Fastest way to hear from your agent. Opens the Bodyguard bot; press Start.</p><div class="row"><button class="btn p" id="tg">${a.channels.telegram ? 'Reconnect' : 'Connect Telegram'}</button>${a.channels.telegram ? '<button class="btn g" id="tgOff">Disconnect</button>' : ''}</div></div>
      <div class="card"><h3>Email</h3><form id="em" class="row"><input class="f1" name="email" type="email" value="${esc(a.channels.email || '')}" placeholder="you@example.com"><button class="btn p">Save</button></form></div>
      ${a.limits.push ? `<div class="card"><div class="row"><h3 class="f1">Push on this device</h3><span class="chip ${a.channels.push ? 'on' : ''}">${a.channels.push} device${a.channels.push === 1 ? '' : 's'}</span></div><p class="muted">Notifications for high and critical alerts, even when this page is closed.</p><div><button class="btn g" id="push">Turn on push here</button></div></div>` : ''}`;
    $('#tg', m).onclick = guard(async () => { const r = await api(`/api/agent/${a.id}/telegram-link`, { body: {} }); window.open(r.url, '_blank', 'noopener'); toast('Press Start in Telegram, then come back.'); });
    const off = $('#tgOff', m); if (off) off.onclick = guard(async () => { await api(`/api/agent/${a.id}/telegram`, { method: 'DELETE' }); go('channels'); });
    $('#em', m).onsubmit = guard(async e => { e.preventDefault(); await api(`/api/agent/${a.id}/channels`, { body: { email: e.target.email.value || null } }); toast('Alert email saved.'); });
    const pb = $('#push', m);
    if (pb) pb.onclick = guard(async () => {
      if (!('serviceWorker' in navigator) || !('PushManager' in window)) throw new Error("This browser doesn't support push notifications.");
      if (!S.me.pushKey) throw new Error('Push is not switched on for this Bodyguard server yet.');
      const reg = await navigator.serviceWorker.register('/sw.js');
      const perm = await Notification.requestPermission();
      if (perm !== 'granted') throw new Error('Notifications were not allowed.');
      const key = Uint8Array.from(atob(S.me.pushKey.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((S.me.pushKey.length + 3) % 4)), c => c.charCodeAt(0));
      const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      await api(`/api/agent/${a.id}/push`, { body: { subscription: sub.toJSON() } });
      toast('Push alerts are on for this device.'); go('channels');
    });
  },

  async shield(m) {
    if (!S.agent) return void (m.innerHTML = noAgent());
    const a = S.agent;
    const d = await api(`/api/agent/${a.id}/addresses`);
    const chains = ['solana', 'ethereum', 'bitcoin', 'base', 'arbitrum', 'optimism', 'polygon', 'bnb'].filter(c => a.limits.chains.includes(c)).map(c => `<option>${c}</option>`).join('');
    m.innerHTML = `<div class="card"><h2>Poisoning shield</h2><p class="muted">Check any address before you send. It's compared with your saved addresses and everything your agent has learned from your history.</p>
      <form id="chk" class="row"><input class="f1 mono" name="address" placeholder="Paste an address to check" autocomplete="off" spellcheck="false"><button class="btn p">Check</button></form><div id="res"></div></div>
      <div class="card"><h3>Saved addresses</h3><p class="muted">Save the addresses you pay often so lookalikes stand out instantly.</p>
      <form id="save" class="grid2"><label><span class="k">Chain</span><select name="chain">${chains}</select></label><label><span class="k">Label</span><input name="label" placeholder="Kraken deposit"></label>
      <label style="grid-column:1/-1"><span class="k">Address</span><input name="address" class="mono" required></label><div><button class="btn g">Save address</button></div></form>
      <div class="list">${d.addresses.filter(x => x.source !== 'history').map(x => `<div class="item"><div class="t"><b>${esc(x.label || 'Saved')}</b><small class="mono">${esc(x.chain)} · ${esc(x.address)}</small></div>${x.source === 'user' ? `<button class="btn d sm" data-rm="${esc(x.chain)}|${esc(x.address)}">Remove</button>` : '<span class="k">Your wallet</span>'}</div>`).join('') || '<div class="item"><div class="t"><small>None saved yet.</small></div></div>'}</div>
      <span class="k">Learned from history: ${d.addresses.filter(x => x.source === 'history').length} addresses</span></div>
      <div class="card"><h3>Poisoned addresses caught</h3>${d.poisoned.length ? `<div class="list">${d.poisoned.map(p => `<div class="item"><div class="t"><b class="mono" style="color:var(--red)">${esc(short(p.address))}</b><small>Imitates ${esc(p.label || '')} ${esc(short(p.imitates || ''))} · ${when(p.created_at)}</small></div><span class="sev high">Blocked</span></div>`).join('')}</div>` : '<div class="empty">No poisoning attempts seen yet.</div>'}</div>`;
    $('#chk', m).onsubmit = guard(async e => {
      e.preventDefault();
      const r = await api('/api/shield/check', { body: { address: e.target.address.value, agentId: a.id } });
      const diff = (x, y) => { let p = 0; while (x[p] === y[p] && p < x.length) p++; let s = 0; while (s < x.length - p && x[x.length - 1 - s] === y[y.length - 1 - s]) s++; return [...x].map((c, i) => `<span class="${i < p || x.length - 1 - i < s ? 'm' : 'x'}">${esc(c)}</span>`).join(''); };
      const t = { known: `Safe: this is your ${esc(r.label)}.`, lookalike: `Lookalike of your ${esc(r.label)}. The first ${r.prefix} and last ${r.suffix} characters match but the middle doesn't. Don't send to it.`, poisoned: `Poisoned: this address already tried to trick you. It imitates your ${esc(r.label)}.`, new: 'First-time address. It doesn\'t imitate anything you use. Check it with whoever you are paying.', invalid: "That isn't a valid address." }[r.verdict];
      $('#res', m).innerHTML = `<div class="verdict ${r.verdict}">${t}</div>${r.imitates ? `<div><span class="k">You pasted</span><br><code class="addr">${diff(r.address, r.imitates)}</code></div><div><span class="k">Your real address</span><br><code class="addr">${diff(r.imitates, r.address)}</code></div>` : ''}`;
    });
    $('#save', m).onsubmit = guard(async e => { e.preventDefault(); const f = e.target; await api(`/api/agent/${a.id}/addresses`, { body: { chain: f.chain.value, address: f.address.value, label: f.label.value } }); toast('Saved.'); go('shield'); });
    $$('[data-rm]', m).forEach(b => b.onclick = guard(async () => { const [c, ad] = b.dataset.rm.split('|'); await api(`/api/agent/${a.id}/addresses/${c}/${encodeURIComponent(ad)}`, { method: 'DELETE' }); go('shield'); }));
  },

  async sweep(m) {
    if (!S.agent) return void (m.innerHTML = noAgent());
    const wallets = S.agent.assets.filter(x => x.type === 'wallet' && x.chain === 'solana');
    m.innerHTML = `<div class="card"><h2>Spam sweep</h2><p class="muted">Finds junk tokens, fake copies of real tokens, scam cNFTs and empty token accounts. You approve once, the junk is burnt, and the rent comes back to you.</p>
      ${wallets.length ? `<div class="row"><select id="w" class="f1">${wallets.map(w => `<option value="${esc(w.value)}">${esc(w.label || short(w.value))} · ${esc(short(w.value))}</option>`).join('')}</select><button class="btn p" id="scan">Scan wallet</button></div>` : '<div class="empty">Add a Solana wallet to your briefing first.</div>'}
      <div id="out"></div></div>`;
    const scan = $('#scan', m); if (!scan) return;
    scan.onclick = guard(async () => {
      scan.disabled = true; $('#out', m).innerHTML = '<div class="empty">Scanning…</div>';
      try {
        const wallet = $('#w', m).value;
        const r = await api(`/api/agent/${S.agent.id}/sweep/scan?wallet=${encodeURIComponent(wallet)}`);
        const junk = r.items.filter(i => i.spam), keep = r.items.filter(i => !i.spam);
        $('#out', m).innerHTML = `<div class="grid3"><div class="tile"><span class="k">Junk found</span><b>${junk.length}</b></div><div class="tile"><span class="k">Rent to reclaim</span><b>${(r.summary.rentLamports / 1e9).toFixed(4)} SOL</b></div><div class="tile"><span class="k">Kept</span><b>${keep.length}</b></div></div>
          ${!r.dasAvailable ? '<p class="muted" style="font-size:13px">Your RPC has no asset index (DAS), so cNFTs and token names are not shown. Use a Helius URL for full coverage.</p>' : ''}
          ${junk.length ? `<div class="list">${junk.map(i => `<label class="item cb"><div class="t row" style="flex-wrap:nowrap"><input type="checkbox" value="${esc(i.id)}" checked><div class="t"><b>${esc(i.name || short(i.mint))}</b><small>${esc(i.kind === 'cnft' ? 'cNFT' : i.kind === 'empty' ? 'Empty account' : 'Token ' + (i.amount || ''))} · ${esc(i.reason || '')}</small></div></div><span class="sev high">${esc(i.why)}</span></label>`).join('')}</div>
          <div class="row"><button class="btn p" id="go">Sweep selected</button><span class="muted" style="font-size:13px">Don't open links in junk names. The sweep never needs them.</span></div>` : '<div class="empty">This wallet is clean.</div>'}
          ${keep.length ? `<details><summary class="k" style="cursor:pointer">Kept (${keep.length})</summary><div class="list" style="margin-top:8px">${keep.map(i => `<div class="item"><div class="t"><b>${esc(i.name || short(i.mint))}</b><small>${esc(i.why)} · ${esc(i.amount || '')}</small></div></div>`).join('')}</div></details>` : ''}`;
        const goBtn = $('#go', m);
        if (goBtn) goBtn.onclick = guard(async () => {
          const ids = $$('input[type=checkbox]:checked', m).map(c => c.value);
          if (!ids.length) throw new Error('Select at least one item.');
          goBtn.disabled = true; goBtn.textContent = 'Building…';
          const b = await api(`/api/agent/${S.agent.id}/sweep/build`, { body: { wallet, ids } });
          if (!b.transactions.length) throw new Error(b.skipped[0]?.reason || 'Nothing could be swept.');
          goBtn.textContent = 'Approve in your wallet…';
          const res = await signAndSendAll(b.transactions.map(t => t.tx));
          toast(`Swept. ${(b.rentLamports / 1e9).toFixed(4)} SOL of rent is back in your wallet${b.skipped.length ? `. ${b.skipped.length} item(s) were skipped.` : '.'}`);
          scan.click();
        });
      } finally { scan.disabled = false; }
    });
  },

  async extension(m) {
    if (!S.agent) return void (m.innerHTML = noAgent());
    const { extensions } = await api(`/api/agent/${S.agent.id}/extensions`);
    m.innerHTML = `<div class="card"><h2>Browser extension</h2><p class="muted">Bodyguard Shield checks every transaction and signature before your wallet signs it, and warns you when you paste or copy a poisoned address. Works with Phantom, Solflare, Backpack, MetaMask and other EVM wallets in Chrome, Brave and Edge.</p>
      <ol class="muted" style="margin:0;padding-left:20px"><li>Install the extension: <a href="/bodyguard-shield.zip">download it</a>, unzip, open <span class="mono">chrome://extensions</span>, turn on Developer mode, press "Load unpacked" and pick the folder.</li><li>Press the button below to get a pairing code.</li><li>Open the extension, enter <span class="mono">${esc(location.origin)}</span> and the code.</li></ol>
      <div class="row"><button class="btn p" id="code">Get pairing code</button><span class="mono" id="codeOut" style="font-size:26px;letter-spacing:.2em"></span></div></div>
      <div class="card"><h3>Paired browsers</h3>${extensions.length ? `<div class="list">${extensions.map(x => `<div class="item"><div class="t"><b class="mono">${esc(x.id)}</b><small>Paired ${when(x.created_at)} · last check ${when(x.last_used)}</small></div><button class="btn d sm" data-x="${esc(x.id)}">Remove</button></div>`).join('')}</div>` : '<div class="empty">No browsers paired yet.</div>'}</div>`;
    $('#code', m).onclick = guard(async () => { const r = await api(`/api/agent/${S.agent.id}/pair-code`, { body: {} }); $('#codeOut', m).textContent = r.code; toast('Code is valid for 10 minutes.'); });
    $$('[data-x]', m).forEach(b => b.onclick = guard(async () => { await api(`/api/agent/${S.agent.id}/extensions/${b.dataset.x}`, { method: 'DELETE' }); go('extension'); }));
  },

  async team(m) {
    if (!S.agent) return void (m.innerHTML = noAgent());
    const a = S.agent;
    m.innerHTML = `<div class="card"><div class="row"><h2 class="f1">Team seats</h2><span class="k">${a.used.seats}/${a.limits.seats}</span></div>
      ${a.limits.seats > 1 ? `<p class="muted">Give teammates their own sign-in. They see alerts and the briefing; admins can change it.</p><form id="add" class="row"><input class="f1 mono" name="wallet" placeholder="Teammate's Solana wallet" required><select name="role" style="width:auto"><option value="member">Member</option><option value="admin">Admin</option></select><button class="btn p">Add</button></form>` : '<p class="muted">Team seats come with the Security Detail rank.</p>'}
      <div class="list">${a.members.map(x => `<div class="item"><div class="t"><b class="mono">${esc(short(x.wallet))}</b><small>${esc(x.role)}</small></div>${x.role !== 'owner' ? `<button class="btn d sm" data-w="${esc(x.wallet)}">Remove</button>` : ''}</div>`).join('')}</div></div>`;
    const f = $('#add', m); if (f) f.onsubmit = guard(async e => { e.preventDefault(); await api(`/api/agent/${a.id}/members`, { body: { wallet: f.wallet.value, role: f.role.value } }); go('team'); });
    $$('[data-w]', m).forEach(b => b.onclick = guard(async () => { await api(`/api/agent/${a.id}/members/${b.dataset.w}`, { method: 'DELETE' }); go('team'); }));
  },

  /* ---------------- business ---------------- */
  async org(m) {
    const o = await api('/api/org');
    const { alerts } = await api('/api/org/alerts');
    m.innerHTML = `<div class="card"><span class="k">Organisation</span><form id="nm" class="row"><input class="f1" name="name" value="${esc(o.name)}"><button class="btn g">Rename</button></form>
      <div class="grid4">${Object.entries(o.services).map(([k, s]) => `<div class="tile"><span class="k">${esc(s.name)}</span><b style="font-size:16px;color:${s.active ? 'var(--g)' : 'var(--m)'}">${s.active ? 'Active' : 'Not bought'}</b><small class="muted">${s.expires ? 'Until ' + when(s.expires) : ''}</small></div>`).join('')}</div></div>
      <div class="grid2"><div class="card"><h3>Org alert channels</h3><div class="row"><button class="btn p" id="tg">${o.channels.telegram ? 'Reconnect Telegram' : 'Connect a Telegram group'}</button></div>
      <form id="em" class="row"><input class="f1" type="email" name="email" value="${esc(o.channels.email || '')}" placeholder="security@yourcompany.com"><button class="btn g">Save</button></form></div>
      <div class="card"><h3>Members</h3><form id="mem" class="row"><input class="f1 mono" name="wallet" placeholder="Wallet" required><select name="role" style="width:auto"><option value="member">Member</option><option value="admin">Admin</option></select><button class="btn g">Add</button></form>
      <div class="list">${o.members.map(x => `<div class="item"><div class="t"><b class="mono">${esc(short(x.wallet))}</b><small>${esc(x.role)}</small></div>${x.role !== 'owner' ? `<button class="btn d sm" data-w="${esc(x.wallet)}">Remove</button>` : ''}</div>`).join('')}</div></div></div>
      <div class="card"><h3>Organisation alerts</h3>${alerts.length ? alerts.slice(0, 20).map(alertHtml).join('') : '<div class="empty">No alerts yet.</div>'}</div>`;
    $('#nm', m).onsubmit = guard(async e => { e.preventDefault(); await api('/api/org', { method: 'PATCH', body: { name: e.target.name.value } }); toast('Saved.'); });
    $('#tg', m).onclick = guard(async () => { const r = await api('/api/org/telegram-link', { body: {} }); window.open(r.url, '_blank', 'noopener'); toast('Pick your security group. The bot posts alerts there.'); });
    $('#em', m).onsubmit = guard(async e => { e.preventDefault(); await api('/api/org/channels', { body: { email: e.target.email.value || null } }); toast('Saved.'); });
    $('#mem', m).onsubmit = guard(async e => { e.preventDefault(); await api('/api/org/members', { body: { wallet: e.target.wallet.value, role: e.target.role.value } }); go('org'); });
    $$('[data-w]', m).forEach(b => b.onclick = guard(async () => { await api('/api/org/members/' + b.dataset.w, { method: 'DELETE' }); go('org'); }));
    bindAcks(m);
  },

  async screening(m) {
    const [{ keys }, { log, usage }] = await Promise.all([api('/api/org/keys'), api('/api/org/screen/log')]);
    m.innerHTML = `<div class="card"><h2>Risk Screening</h2><p class="muted">Score any wallet 0 to 100 before you accept a deposit: sanctions, mixers, exploit funds and laundering patterns.</p>
      <form id="sc" class="row"><select name="chain" style="width:auto">${['solana', 'ethereum', 'bitcoin', 'base', 'arbitrum', 'optimism', 'polygon', 'bnb'].map(c => `<option>${c}</option>`).join('')}</select><input class="f1 mono" name="address" placeholder="Address to screen" required><button class="btn p">Screen</button></form><div id="res"></div></div>
      <div class="grid2"><div class="card"><div class="row"><h3 class="f1">API keys</h3><button class="btn g sm" id="nk">New key</button></div><div id="newKey"></div>
      <div class="list">${keys.length ? keys.map(k => `<div class="item"><div class="t"><b class="mono">${esc(k.prefix)}…</b><small>${esc(k.label)} · ${k.revoked ? 'revoked' : 'last used ' + when(k.last_used)}</small></div>${k.revoked ? '' : `<button class="btn d sm" data-k="${esc(k.prefix)}">Revoke</button>`}</div>`).join('') : '<div class="item"><div class="t"><small>No keys yet.</small></div></div>'}</div></div>
      <div class="card"><h3>Usage</h3><div class="grid2"><div class="tile"><span class="k">Today</span><b>${usage.today}</b></div><div class="tile"><span class="k">30 days</span><b>${usage.month}</b></div></div>
      <span class="k">API</span><div class="code">curl -X POST ${esc(location.origin)}/api/v1/screen \\
  -H "x-api-key: YOUR_KEY" -H "content-type: application/json" \\
  -d '{"chain":"ethereum","address":"0x…"}'</div><small class="muted">Bulk: POST /api/v1/screen/bulk with {"items":[{chain,address}]} (up to 100).</small></div></div>
      <div class="card"><h3>Recent checks</h3><div class="scroll"><table><thead><tr><th>When</th><th>Chain</th><th>Address</th><th>Score</th></tr></thead><tbody>${log.slice(0, 50).map(l => `<tr><td>${when(l.created_at)}</td><td>${esc(l.chain)}</td><td class="mono">${esc(short(l.address))}</td><td><b>${l.score}</b></td></tr>`).join('') || '<tr><td colspan="4" class="muted">None yet.</td></tr>'}</tbody></table></div></div>`;
    $('#sc', m).onsubmit = guard(async e => {
      e.preventDefault(); $('#res', m).innerHTML = '<div class="empty">Screening…</div>';
      const r = await api('/api/org/screen', { body: { chain: e.target.chain.value, address: e.target.address.value } });
      const col = { low: 'var(--g)', medium: 'var(--amber)', high: 'var(--red)', severe: 'var(--red)' }[r.level];
      $('#res', m).innerHTML = `<div class="row" style="align-items:flex-end"><span class="score" style="color:${col}">${r.score}</span><span class="pill" style="color:${col};border-color:${col}">${esc(r.level)} risk</span><span class="k">${r.counterpartiesChecked ?? 0} counterparties checked</span></div>
        <div class="list">${r.factors.length ? r.factors.map(f => `<div class="item"><div class="t"><b>${esc(f.text)}</b>${f.evidence ? `<small class="mono">${f.evidence.map(short).map(esc).join(', ')}</small>` : ''}</div><span class="k">+${f.points}</span></div>`).join('') : '<div class="item"><div class="t"><b>No risk factors found.</b></div></div>'}</div>${r.note ? `<small class="muted">${esc(r.note)}</small>` : ''}`;
    });
    $('#nk', m).onclick = guard(async () => { const r = await api('/api/org/keys', { body: { label: 'API key' } }); $('#newKey', m).innerHTML = `<div class="verdict known"><b>Copy this key now:</b><br><code class="addr">${esc(r.key)}</code></div>`; });
    $$('[data-k]', m).forEach(b => b.onclick = guard(async () => { await api('/api/org/keys/' + b.dataset.k, { method: 'DELETE' }); go('screening'); }));
  },

  async wallets(m) {
    const { wallets } = await api('/api/org/wallets');
    m.innerHTML = `<div class="card"><h2>Guarded Wallets</h2><p class="muted">Squads smart accounts with guardrails. Your team keeps the keys; approvals and the time lock are enforced on-chain, and the policy engine checks every payment against your limits.</p></div>
      <div class="card"><h3>Create a guarded wallet</h3><form id="cw" style="display:grid;gap:12px">
      <div class="grid2"><label><span class="k">Name</span><input name="name" required placeholder="Ops wallet"></label><label><span class="k">Approvals needed (on-chain)</span><input name="threshold" type="number" min="1" value="2"></label></div>
      <label><span class="k">Member wallets (one per line)</span><textarea name="members" rows="3" required placeholder="${esc(S.me.wallet)}">${esc(S.me.wallet)}</textarea></label>
      <label><span class="k">On-chain time lock (hours)</span><input name="timeLock" type="number" min="0" value="0"></label>
      <span class="k">Policy</span>${policyForm()}
      <div class="row"><button class="btn p">Create on Solana</button><span class="muted" style="font-size:13px">You sign one transaction with ${esc(short(S.me.wallet))}. Squads charges its own small creation fee.</span></div></form></div>
      ${wallets.map(w => `<div class="card"><div class="row"><h3 class="f1">${esc(w.name)}</h3><span class="chip ${w.status === 'active' ? 'on' : ''}">${esc(w.status)}</span></div>
        <small class="mono muted">Multisig ${esc(w.multisig)}<br>Vault (send funds here) ${esc(w.vault)}</small><small class="muted">${w.members.length} members · ${w.threshold} approvals · time lock ${Math.round(w.timeLock / 3600)}h</small>
        ${w.status !== 'active' ? `<button class="btn g sm" data-confirm="${w.id}">I've sent it, check on-chain</button>` : `
        <details><summary class="k" style="cursor:pointer">Edit policy</summary><form data-pol="${w.id}" style="display:grid;gap:12px;margin-top:10px">${policyForm(w.policy)}<div><button class="btn g">Save policy</button></div></form></details>
        <details><summary class="k" style="cursor:pointer">Check a payment</summary><form data-chk="${w.id}" class="grid2" style="margin-top:10px"><input name="to" class="mono" placeholder="Destination" required><input name="amount" type="number" step="any" placeholder="Amount (SOL)" required><input name="approvals" type="number" min="0" placeholder="Approvals so far"><button class="btn g">Check</button></form><div data-res="${w.id}"></div></details>
        <details data-audit="${w.id}"><summary class="k" style="cursor:pointer">Audit log</summary><div class="scroll" style="margin-top:8px"></div></details>
        <small class="muted">Apps can call <span class="mono">POST /api/v1/wallets/${w.id}/check</span> with an API key before proposing a payment.</small>`}</div>`).join('')}`;
    $('#cw', m).onsubmit = guard(async e => {
      e.preventDefault(); const f = e.target; const btn = $('button', f); btn.disabled = true;
      try {
        await ensureWallet();
        const r = await api('/api/org/wallets', { body: { name: f.name.value, threshold: f.threshold.value, timeLock: Number(f.timeLock.value || 0) * 3600, members: f.members.value.split(/\s+/).filter(Boolean), policy: readPolicy(f), creator: S.wallet } });
        btn.textContent = 'Approve in your wallet…';
        const s = await signAndSendAll([r.transaction]);
        if (s.errors) throw new Error('The creation transaction failed on-chain.');
        await api(`/api/org/wallets/${r.id}/confirm`, { body: {} });
        toast('Guarded wallet created. Send funds to its vault address.'); go('wallets');
      } finally { btn.disabled = false; }
    });
    $$('[data-confirm]', m).forEach(b => b.onclick = guard(async () => { await api(`/api/org/wallets/${b.dataset.confirm}/confirm`, { body: {} }); go('wallets'); }));
    $$('[data-pol]', m).forEach(f => f.onsubmit = guard(async e => { e.preventDefault(); await api(`/api/org/wallets/${f.dataset.pol}/policy`, { method: 'PATCH', body: { policy: readPolicy(f) } }); toast('Policy saved.'); }));
    $$('[data-chk]', m).forEach(f => f.onsubmit = guard(async e => { e.preventDefault(); const r = await api(`/api/org/wallets/${f.dataset.chk}/check`, { body: { to: f.to.value, amount: f.amount.value, approvals: f.approvals.value } });
      $(`[data-res="${f.dataset.chk}"]`, m).innerHTML = `<div class="verdict ${r.decision === 'allow' ? 'known' : r.decision === 'deny' ? 'lookalike' : 'new'}"><b>${esc({ allow: 'Allowed', deny: 'Denied', needs_approval: 'Needs more approvals', timelocked: 'Time-locked' }[r.decision])}</b><br>${r.reasons.map(x => esc(x.text)).join('<br>')}</div>`; }));
    $$('[data-audit]', m).forEach(d => d.addEventListener('toggle', guard(async () => { if (!d.open) return; const { log } = await api(`/api/org/wallets/${d.dataset.audit}/audit`);
      $('.scroll', d).innerHTML = `<table><thead><tr><th>When</th><th>Decision</th><th>Details</th></tr></thead><tbody>${log.map(l => `<tr><td>${when(l.created_at)}</td><td>${esc(l.decision)}</td><td>${esc(l.reasons.map(r => r.text).join(' '))}</td></tr>`).join('') || '<tr><td colspan="3" class="muted">Nothing yet.</td></tr>'}</tbody></table>`; })));
  },

  async treasury(m) {
    const { treasuries } = await api('/api/org/treasuries');
    m.innerHTML = `<div class="card"><h2>Treasury Watch</h2><p class="muted">Round-the-clock monitoring for Squads (Solana) and Safe (EVM) multisigs. Every proposal is checked against your policy, configuration changes are escalated, and every signer's own wallet is watched for compromise.</p>
      <form id="add" style="display:grid;gap:12px"><div class="grid2"><label><span class="k">Chain</span><select name="chain">${['solana', 'ethereum', 'base', 'arbitrum', 'optimism', 'polygon', 'bnb'].map(c => `<option>${c}</option>`).join('')}</select></label><label><span class="k">Name</span><input name="name" placeholder="DAO treasury" required></label></div>
      <label><span class="k">Multisig address (Squads multisig or Safe address)</span><input name="address" class="mono" required></label><span class="k">Policy</span>${policyForm()}<div><button class="btn p">Start watching</button></div></form></div>
      ${treasuries.map(t => `<div class="card"><div class="row"><h3 class="f1">${esc(t.name)}</h3><span class="chip ${t.health === 'ok' ? 'on' : ''}">${esc(t.health)}</span></div><small class="mono muted">${esc(t.chain)} · ${esc(t.kind)} · ${esc(t.address)}</small>
        <small class="muted">${t.signers.length} signers${t.threshold ? ` · ${t.threshold} approvals` : ''} · checked ${when(t.lastChecked)}</small><div class="list">${t.signers.map(s => `<div class="item"><div class="t"><small class="mono">${esc(s)}</small></div></div>`).join('')}</div>
        <details><summary class="k" style="cursor:pointer">Edit policy</summary><form data-pol="${t.id}" style="display:grid;gap:12px;margin-top:10px">${policyForm(t.policy)}<div><button class="btn g">Save</button></div></form></details>
        ${t.kind !== 'guarded' ? `<div><button class="btn d sm" data-rm="${t.id}">Stop watching</button></div>` : ''}</div>`).join('')}`;
    $('#add', m).onsubmit = guard(async e => { e.preventDefault(); const f = e.target; await api('/api/org/treasuries', { body: { chain: f.chain.value, name: f.name.value, address: f.address.value, policy: readPolicy(f) } }); toast('Watching. First check within two minutes.'); go('treasury'); });
    $$('[data-pol]', m).forEach(f => f.onsubmit = guard(async e => { e.preventDefault(); await api('/api/org/treasuries/' + f.dataset.pol, { method: 'PATCH', body: { policy: readPolicy(f) } }); toast('Policy saved.'); }));
    $$('[data-rm]', m).forEach(b => b.onclick = guard(async () => { await api('/api/org/treasuries/' + b.dataset.rm, { method: 'DELETE' }); go('treasury'); }));
  },

  async drills(m) {
    const [o, { drills }, { templates }, chat] = await Promise.all([api('/api/org'), api('/api/org/drills'), api('/api/org/drills/templates'), api('/api/org/drill-chat')]);
    m.innerHTML = `<div class="card"><h2>Scam Drills</h2><p class="muted">Practice scams for your team and community. Landing pages never keep anything people type. Everyone who falls for it lands on short training straight away.</p></div>
      <div class="card"><h3>1. Verify your company domain</h3><p class="muted">Email drills only go to addresses on domains you prove you own.</p>
      <form id="dom" class="row"><input class="f1" name="domain" placeholder="yourcompany.com"><button class="btn g">Add domain</button></form><div id="txt"></div>
      <div class="row">${o.verifiedDomains.map(d => `<span class="chip on">${esc(d)} verified</span>`).join('')}${o.pendingDomains.map(d => `<span class="chip">${esc(d)}</span><button class="btn g sm" data-v="${esc(d)}">Verify ${esc(d)}</button>`).join('')}</div></div>
      <div class="card"><h3>2. Create a drill</h3><form id="new" style="display:grid;gap:12px"><div class="grid2"><label><span class="k">Name</span><input name="name" placeholder="Q4 team drill"></label>
      <label><span class="k">Scenario</span><select name="template">${Object.entries(templates).map(([k, t]) => `<option value="${k}">${esc(t.label)}</option>`).join('')}</select></label>
      <label><span class="k">Channel</span><select name="channel"><option value="email">Email (team)</option><option value="telegram">Telegram group (community)</option></select></label>
      <label><span class="k">From name (optional)</span><input name="fromName" placeholder="e.g. IT Support"></label></div>
      <label id="tWrap"><span class="k">People (one email per line, optional name after a comma)</span><textarea name="targets" rows="4" placeholder="alex@yourcompany.com, Alex"></textarea></label>
      <div id="cWrap" hidden class="row"><span class="chip ${chat.connected ? 'on' : ''}">${chat.connected ? 'Community group connected' : 'No community group connected'}</span><button type="button" class="btn g sm" id="linkChat">${chat.connected ? 'Change group' : 'Connect community group'}</button></div>
      <label class="cb"><input type="checkbox" name="authorised"> I am authorised by ${esc(o.name)} to run this drill on these people.</label><div><button class="btn p">Create drill</button></div></form></div>
      <div class="card"><h3>Drills</h3>${drills.length ? `<div class="list">${drills.map(d => `<div class="item"><div class="t"><b>${esc(d.name)}</b><small>${esc(d.channel)} · ${esc(d.status)} · ${d.stats.total} target(s) · ${d.stats.clicked} clicked · ${d.stats.submitted} submitted</small></div>
        <div class="row">${d.status === 'draft' ? `<button class="btn p sm" data-send="${d.id}">Send</button>` : ''}<button class="btn g sm" data-rep="${d.id}">Report</button></div></div>`).join('')}</div>` : '<div class="empty">No drills yet.</div>'}<div id="rep"></div></div>`;
    const f = $('#new', m);
    f.channel.onchange = () => { $('#tWrap', m).hidden = f.channel.value !== 'email'; $('#cWrap', m).hidden = f.channel.value === 'email'; };
    $('#linkChat', m).onclick = guard(async () => { const r = await api('/api/org/drill-chat-link', { body: {} }); window.open(r.url, '_blank', 'noopener'); toast('Pick your community group and add the bot as admin.'); });
    $('#dom', m).onsubmit = guard(async e => { e.preventDefault(); const r = await api('/api/org/domains', { body: { domain: e.target.domain.value } }); $('#txt', m).innerHTML = `<div class="code">${esc(r.instructions)}</div>`; setTimeout(() => go('drills'), 6000); });
    $$('[data-v]', m).forEach(b => b.onclick = guard(async () => { await api(`/api/org/domains/${encodeURIComponent(b.dataset.v)}/verify`, { body: {} }); toast('Domain verified.'); go('drills'); }));
    f.onsubmit = guard(async e => { e.preventDefault();
      const targets = f.targets.value.split('\n').map(l => l.trim()).filter(Boolean).map(l => { const [email, name] = l.split(',').map(s => s.trim()); return { email, name }; });
      await api('/api/org/drills', { body: { name: f.name.value, template: f.template.value, channel: f.channel.value, fromName: f.fromName.value, targets, authorised: f.authorised.checked } });
      toast('Drill created. Press Send when ready.'); go('drills'); });
    $$('[data-send]', m).forEach(b => b.onclick = guard(async () => { b.disabled = true; const r = await api(`/api/org/drills/${b.dataset.send}/send`, { body: {} }); toast(`Sent to ${r.sent}.`); go('drills'); }));
    $$('[data-rep]', m).forEach(b => b.onclick = guard(async () => {
      const r = await api(`/api/org/drills/${b.dataset.rep}/report`);
      const pct = v => v == null ? '—' : Math.round(v * 100) + '%';
      $('#rep', m).innerHTML = `<div class="card" style="margin-top:12px"><h3>${esc(r.drill.name)}</h3><div class="grid4"><div class="tile"><span class="k">Sent</span><b>${r.stats.sent}</b></div><div class="tile"><span class="k">Clicked</span><b>${r.drill.channel === 'telegram' ? r.stats.clickEvents : pct(r.rates.click)}</b></div><div class="tile"><span class="k">Would have handed over</span><b style="color:var(--red)">${r.drill.channel === 'telegram' ? r.stats.submitEvents : pct(r.rates.submit)}</b></div><div class="tile"><span class="k">Completed training</span><b>${r.stats.trained}</b></div></div>
        <span class="k">What to fix</span><ul style="margin:0;padding-left:20px">${r.fixes.map(x => `<li>${esc(x)}</li>`).join('')}</ul>
        ${r.drill.channel === 'email' ? `<div class="scroll"><table><thead><tr><th>Person</th><th>Opened</th><th>Clicked</th><th>Submitted</th><th>Quiz</th></tr></thead><tbody>${r.targets.map(t => `<tr><td>${esc(t.name || t.email)}</td><td>${t.opened_at ? '✓' : ''}</td><td>${t.clicked_at ? '✓' : ''}</td><td style="color:var(--red)">${t.submitted_at ? '✓' : ''}</td><td>${t.quiz_score ?? ''}</td></tr>`).join('')}</tbody></table></div>` : ''}</div>`;
    }));
  },

  /* ---------------- personal safety: Duress Mode ---------------- */
  async duress(m) {
    const st = await api('/api/duress');
    const chainOpts = sel => ['solana', 'ethereum', 'bitcoin', 'base', 'arbitrum', 'optimism', 'polygon', 'bnb'].map(c => `<option ${c === sel ? 'selected' : ''}>${c}</option>`).join('');
    const intro = `<div class="card"><span class="k">Personal safety</span><h2>Duress Mode</h2><p class="muted">If someone ever forces you to hand over your crypto, open your vault and enter your <b>duress PIN</b> instead of your real one. The vault shows only a small decoy wallet, your trusted contacts get a silent emergency email, and Bodyguard holds large transfers for a cooling-off period that nobody can cut short.</p>
      <p class="muted" style="font-size:13px">The time-lock is enforced wherever Bodyguard sits in the signing path: the Bodyguard Shield browser extension and Guarded Wallets. It can't stop a wallet app on another device, which is why the decoy and the silent alert matter most. Your safety comes first: hand over what you must.</p></div>`;
    if (!st.active) { m.innerHTML = intro + `<div class="card"><h3>Not active on this wallet</h3><p class="muted">Duress Mode is sold as a service. The price will be announced soon.</p><div><a class="btn p" href="/#services">See services</a></div></div>`; return; }
    if (!st.configured) {
      m.innerHTML = intro + `<div class="card"><h3>Set it up</h3><form id="setup" style="display:grid;gap:12px">
        <div class="grid2"><label><span class="k">Real PIN (4-8 digits)</span><input name="realPin" type="password" inputmode="numeric" pattern="\\d{4,8}" required autocomplete="new-password"></label>
        <label><span class="k">Duress PIN (different)</span><input name="duressPin" type="password" inputmode="numeric" pattern="\\d{4,8}" required autocomplete="new-password"></label></div>
        <label><span class="k">Your first name (shown to your contacts)</span><input name="name" maxlength="60" required></label>
        <span class="k">Decoy wallet: a wallet with a small balance the vault shows under duress</span>
        <div class="grid2"><select name="dchain">${chainOpts('solana')}</select><input name="daddr" class="mono" placeholder="Decoy wallet address" required></div>
        <div class="grid2"><label><span class="k">Cooling-off (hours)</span><input name="coolingHours" type="number" min="1" max="168" value="24"></label>
        <label><span class="k">Allowed during lockdown (SOL / EVM native)</span><div class="row"><input name="aSol" type="number" step="any" min="0" value="0.1" style="width:48%"><input name="aEvm" type="number" step="any" min="0" value="0.01" style="width:48%"></div></label></div>
        <label><span class="k">Note to your contacts (optional)</span><textarea name="message" rows="2" maxlength="280" placeholder="e.g. Call my brother on the number you have. Don't call me."></textarea></label>
        <label class="cb"><input type="checkbox" name="shareLocation"> Share my location with my contacts if I use the duress PIN (asks for permission now, never in the moment)</label>
        <div><button class="btn p">Turn on Duress Mode</button></div></form></div>`;
      const f = $('#setup', m);
      f.shareLocation.onchange = () => { if (f.shareLocation.checked && navigator.geolocation) navigator.geolocation.getCurrentPosition(() => toast('Location permission granted.'), () => { toast('Location was not allowed, so it will not be shared.', true); f.shareLocation.checked = false; }); };
      f.onsubmit = guard(async e => {
        e.preventDefault();
        const v = await api('/api/duress/setup', { body: { realPin: f.realPin.value, duressPin: f.duressPin.value, settings: { name: f.name.value, coolingHours: f.coolingHours.value, allowance: { solana: f.aSol.value, evm: f.aEvm.value }, message: f.message.value, shareLocation: f.shareLocation.checked, decoyWallets: [{ chain: f.dchain.value, address: f.daddr.value, label: 'Wallet' }] } } });
        duressPin = f.realPin.value; toast('Duress Mode is on. Now add your trusted contacts.'); renderDuress(m, v);
      });
      return;
    }
    if (duressPin) { try { return renderDuress(m, await api('/api/duress/open', { body: { pin: duressPin } })); } catch { duressPin = null; } }
    m.innerHTML = intro + `<div class="card"><h3>Enter your real PIN</h3><form id="pin" class="row"><input class="f1" name="pin" type="password" inputmode="numeric" autocomplete="off" required><button class="btn p">Open settings</button></form></div>`;
    $('#pin', m).onsubmit = guard(async e => { e.preventDefault(); const pin = e.target.pin.value; const v = await api('/api/duress/open', { body: { pin } }); duressPin = pin; renderDuress(m, v); });
  },

  /* ---------------- personal safety: Freeze Desk ---------------- */
  async freeze(m) {
    const svc = S.me.org?.services?.freeze;
    const intro = `<div class="card"><span class="k">Personal safety</span><h2>Freeze Desk</h2><p class="muted">Scammed? Speed decides whether funds can still be frozen. Fill in one form: your agent reads every transaction from the chain, locks the evidence with a SHA-256 fingerprint and a signed timestamp, writes freeze requests for the exchanges and responders you pick, and keeps tracing the money.</p>
      <p class="muted" style="font-size:13px">Nobody can promise recovery. Anyone who asks you for a fee to "recover" funds is running a second scam.</p></div>`;
    if (!svc?.active) { m.innerHTML = intro + `<div class="card"><h3>Not active on this wallet</h3><p class="muted">Freeze Desk is sold as a service. The price will be announced soon. If you need help right now, contact <a href="https://t.me/seal_911_bot" target="_blank" rel="noopener noreferrer">SEAL 911</a> (free) and your local police.</p><div><a class="btn p" href="/#services">See services</a></div></div>`; return; }
    const [{ incidents }, dir] = await Promise.all([api('/api/freeze/incidents'), api('/api/freeze/directory')]);
    const id = new URLSearchParams(location.hash.split('?')[1] || '').get('case');
    if (id) return renderCase(m, await api('/api/freeze/incidents/' + encodeURIComponent(id)), dir);
    const chains = ['solana', 'ethereum', 'bitcoin', 'base', 'arbitrum', 'optimism', 'polygon', 'bnb'];
    const row = (n, ph) => `<div class="row" data-row="${n}"><select style="width:auto">${chains.map(c => `<option>${c}</option>`).join('')}</select><input class="f1 mono" placeholder="${ph}"></div>`;
    const kinds = { responder: 'Emergency responders', police: 'Police', issuer: 'Stablecoin issuers', exchange: 'Exchanges' };
    m.innerHTML = intro + `${incidents.length ? `<div class="card"><h3>Your cases</h3><div class="list">${incidents.map(i => `<div class="item"><div class="t"><b>${esc(i.ref)} · ${esc(i.title)}</b><small>${when(i.createdAt)} · ${esc(i.status)} · <span class="mono">${esc(i.hash.slice(0, 16))}…</span></small></div><a class="btn g sm" href="#freeze?case=${esc(i.id)}">Open</a></div>`).join('')}</div></div>` : ''}
      <div class="card"><h3>Report a theft</h3><form id="fz" style="display:grid;gap:12px">
      <div class="grid2"><label><span class="k">Your name</span><input name="name" required maxlength="80"></label><label><span class="k">Email for replies</span><input name="email" type="email" required></label>
      <label><span class="k">Phone (optional)</span><input name="phone" maxlength="24"></label><label><span class="k">Country</span><input name="country" maxlength="56" placeholder="United Kingdom"></label>
      <label><span class="k">What happened</span><select name="scamType">${Object.entries(dir.scamTypes).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join('')}</select></label>
      <label><span class="k">When</span><input name="occurredAt" type="datetime-local"></label>
      <label><span class="k">Amount lost</span><input name="amount" placeholder="e.g. 12.5"></label><label><span class="k">Asset</span><input name="asset" placeholder="SOL, USDT, ETH…"></label></div>
      <label><span class="k">Describe it in your own words</span><textarea name="description" rows="5" required minlength="20" maxlength="4000" placeholder="Who contacted you, what they asked you to do, what you signed or sent, and when."></textarea></label>
      <span class="k">Your wallet(s)</span><div id="vw">${row('vw', 'Your wallet address')}</div><div><button type="button" class="btn g sm" data-add="vw">+ Wallet</button></div>
      <span class="k">Scammer / receiving address(es)</span><div id="sa">${row('sa', 'Address the funds went to')}</div><div><button type="button" class="btn g sm" data-add="sa">+ Address</button></div>
      <span class="k">Transaction IDs</span><div id="tx">${row('tx', 'Transaction hash or signature')}</div><div><button type="button" class="btn g sm" data-add="tx">+ Transaction</button></div>
      <label><span class="k">Police report reference (if you have one)</span><input name="policeRef" maxlength="80"></label>
      <label><span class="k">Screenshots or PDFs (up to 6, 2 MB each)</span><input name="files" type="file" multiple accept="image/png,image/jpeg,image/webp,application/pdf"></label><div id="fh" class="muted" style="font-size:12.5px"></div>
      <span class="k">Send freeze requests to</span>
      ${Object.entries(kinds).map(([k, label]) => `<div><small class="muted">${label}</small><div class="row" style="margin-top:4px">${dir.targets.filter(t => t.kind === k).map(t => `<label class="cb" style="width:auto;border:1px solid var(--line2);border-radius:9px;padding:6px 10px"><input type="checkbox" name="t" value="${esc(t.id)}" ${k === 'responder' ? 'checked' : ''}> ${esc(t.name)}${t.email ? ' ✉' : ''}</label>`).join('')}</div></div>`).join('')}
      <small class="muted">✉ = emailed for you. The rest get a ready-to-paste request and a link to their official form.</small>
      <label class="cb"><input type="checkbox" name="attest"> The information above is true to the best of my knowledge. I understand false reports can be a crime.</label>
      <div class="row"><button class="btn p" id="fzGo">Lock evidence and send freeze requests</button></div></form></div>`;
    const f = $('#fz', m);
    $$('[data-add]', m).forEach(b => b.onclick = () => { const box = $('#' + b.dataset.add, m); if (box.children.length < 10) box.insertAdjacentHTML('beforeend', row(b.dataset.add, box.firstElementChild.querySelector('input').placeholder)); });
    let files = [];
    f.files.onchange = guard(async () => {
      files = [];
      for (const file of [...f.files.files].slice(0, 6)) {
        if (file.size > 2 * 1024 * 1024) throw new Error(`${file.name} is over 2 MB.`);
        const buf = new Uint8Array(await file.arrayBuffer());
        const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', buf))].map(b => b.toString(16).padStart(2, '0')).join('');
        let bin = ''; for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
        files.push({ name: file.name, data: btoa(bin), hash });
      }
      $('#fh', m).innerHTML = files.map(x => `${esc(x.name)} <span class="mono">SHA-256 ${x.hash.slice(0, 20)}…</span>`).join('<br>');
    });
    const rows = n => $$(`#${n} [data-row]`, m).map(r => ({ chain: $('select', r).value, v: $('input', r).value.trim() })).filter(x => x.v);
    f.onsubmit = guard(async e => {
      e.preventDefault();
      const btn = $('#fzGo', m); btn.disabled = true; btn.textContent = 'Reading the chain and locking evidence…';
      try {
        const r = await api('/api/freeze/incidents', { body: {
          victim: { name: f.name.value, email: f.email.value, phone: f.phone.value, country: f.country.value }, scamType: f.scamType.value, occurredAt: f.occurredAt.value,
          amount: f.amount.value, asset: f.asset.value, description: f.description.value, policeRef: f.policeRef.value,
          victimWallets: rows('vw').map(x => ({ chain: x.chain, address: x.v })), scammerAddresses: rows('sa').map(x => ({ chain: x.chain, address: x.v })), transactions: rows('tx').map(x => ({ chain: x.chain, hash: x.v })),
          targets: $$('input[name=t]:checked', m).map(c => c.value), files: files.map(({ name, data }) => ({ name, data })), attest: f.attest.checked, send: true } });
        toast(`Case ${r.ref} opened. Evidence locked.`);
        history.replaceState(null, '', '#freeze?case=' + r.id); renderCase(m, r, dir);
      } finally { btn.disabled = false; btn.textContent = 'Lock evidence and send freeze requests'; }
    });
  },

  /* ---------------- account: sign-ins and activity ---------------- */
  async security(m) {
    const { sessions, activity } = await api('/api/auth/sessions');
    const LABEL = { sign_in: 'Signed in', signed_out_everywhere: 'Signed out other devices', session_revoked: 'Signed out a device', extension_paired: 'Browser extension paired', extension_removed: 'Browser extension removed', member_added: 'Team member added', member_removed: 'Team member removed' };
    m.innerHTML = `<div class="card"><h2>Signed-in devices</h2><p class="muted">Every browser that is signed in to your dashboard. If you don't recognise one, sign it out, then check your wallet for anything you didn't approve.</p>
      <div class="list">${sessions.map(x => `<div class="item"><div class="t"><b>${esc(x.device)}${x.current ? ' <span class="chip on">This device</span>' : ''}</b><small>Signed in ${when(x.createdAt)} · last active ${when(x.lastSeen)}</small></div>${x.current ? '' : `<button class="btn g sm" data-rv="${esc(x.id)}">Sign out</button>`}</div>`).join('')}</div>
      ${sessions.length > 1 ? '<div class="row"><button class="btn d" id="rvAll">Sign out every other device</button></div>' : ''}</div>
      <div class="card"><h2>Recent account activity</h2><div class="list">${activity.length ? activity.map(a => `<div class="item"><div class="t"><b>${esc(LABEL[a.action] || a.action.replace(/_/g, ' '))}</b><small>${when(a.at)}${a.device ? ' · ' + esc(a.device) : ''}</small></div></div>`).join('') : '<div class="item"><div class="t"><small>Nothing yet.</small></div></div>'}</div>
      <p class="muted">Bodyguard staff will never ask for your seed phrase, private key or a wallet signature over chat or email.</p></div>`;
    $$('[data-rv]', m).forEach(b => b.onclick = guard(async () => { await api('/api/auth/sessions/revoke', { body: { id: b.dataset.rv } }); toast('That device is signed out.'); go('security'); }));
    const all = $('#rvAll', m); if (all) all.onclick = guard(async () => { const r = await api('/api/auth/sessions/revoke', { body: { all: true } }); toast(`Signed out ${r.revoked} other device${r.revoked === 1 ? '' : 's'}.`); go('security'); });
  },

  /* ---------------- admin: security ---------------- */
  async adminsec(m) {
    if (!S.me.admin) return void (m.innerHTML = '<div class="empty">Admins only.</div>');
    const [{ bans, audit }, ipc] = await Promise.all([api('/api/admin/security'), api('/api/admin/ip-check').catch(() => null)]);
    const until = t => new Date(t * 1000).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
    m.innerHTML = `<div class="card"><h2>Blocked addresses</h2><p class="muted">Addresses are blocked automatically after attack patterns (scanner probes, signature guessing, floods). Blocks start at 15 minutes and double for repeat offenders, up to 24 hours.</p>
      <div class="list">${bans.length ? bans.map(b => `<div class="item"><div class="t"><b class="mono">${esc(b.ip)}</b><small>until ${until(b.until)} · block #${b.count} · ${esc(b.reason || '')}</small></div><button class="btn g sm" data-ub="${esc(b.ip)}">Unblock</button></div>`).join('') : '<div class="item"><div class="t"><small>No addresses are blocked right now.</small></div></div>'}</div>
      <form id="bn" class="row"><input name="ip" placeholder="IP address" maxlength="64" style="max-width:220px"><input name="minutes" type="number" min="1" max="43200" value="60" style="max-width:110px"><input name="reason" placeholder="Reason" maxlength="100" style="max-width:220px"><button class="btn d sm">Block</button></form></div>
      ${ipc ? `<div class="card"><h2>Visitor address check</h2><p class="muted">${esc(ipc.advice)}</p><div class="list"><div class="item"><div class="t"><b>Seen as <span class="mono">${esc(ipc.seenAs)}</span></b><small>X-Forwarded-For: ${esc(ipc.xForwardedFor || '—')} · X-Real-IP: ${esc(ipc.xRealIp || '—')} · socket: ${esc(ipc.socket || '—')}</small></div></div></div></div>` : ''}
      <div class="card"><h2>Security log</h2><div class="list">${audit.length ? audit.slice(0, 150).map(a => `<div class="item"><div class="t"><b>${esc(a.action.replace(/_/g, ' '))}</b><small>${when(a.created_at)}${a.actor ? ' · ' + esc(short(a.actor)) : ''}${a.subject ? ' · ' + esc(a.subject) : ''}</small><small class="mono">${esc(JSON.stringify(a.detail)).slice(0, 300)}</small></div></div>`).join('') : '<div class="item"><div class="t"><small>Nothing logged yet.</small></div></div>'}</div></div>`;
    $$('[data-ub]', m).forEach(b => b.onclick = guard(async () => { await api('/api/admin/security/unban', { body: { ip: b.dataset.ub } }); toast('Unblocked.'); go('adminsec'); }));
    $('#bn', m).onsubmit = guard(async e => { e.preventDefault(); const f = e.target; await api('/api/admin/security/ban', { body: { ip: f.ip.value, minutes: Number(f.minutes.value), reason: f.reason.value } }); toast('Blocked.'); go('adminsec'); });
  },

  /* ---------------- admin: help desk ---------------- */
  async support(m) {
    if (!S.me.admin) return void (m.innerHTML = '<div class="empty">Admins only.</div>');
    const status = new URLSearchParams(location.hash.split('?')[1] || '').get('s') || 'open';
    const { tickets } = await api('/api/admin/tickets?status=' + encodeURIComponent(status));
    m.innerHTML = `<div class="card"><h2>Help desk</h2><div class="tabs">${['open', 'answered', 'closed'].map(s => `<button data-s="${s}" class="${s === status ? 'on' : ''}">${s}</button>`).join('')}</div>
      <div class="list">${tickets.length ? tickets.map(t => `<div class="item"><div class="t"><b>${esc(t.ref)} · ${esc(t.subject)}</b><small>${esc(t.name)} &lt;${esc(t.email)}&gt; · ${esc(t.topicLabel)} · ${when(t.created_at)}${t.wallet ? ' · <span class="mono">' + esc(short(t.wallet)) + '</span>' : ''}</small></div><button class="btn g sm" data-t="${esc(t.id)}">Open</button></div>`).join('') : '<div class="item"><div class="t"><small>No tickets here.</small></div></div>'}</div></div><div id="tk"></div>`;
    $$('[data-s]', m).forEach(b => b.onclick = () => { history.replaceState(null, '', '#support?s=' + b.dataset.s); go('support'); });
    $$('[data-t]', m).forEach(b => b.onclick = guard(async () => {
      const { ticket: t, messages } = await api('/api/admin/tickets/' + b.dataset.t);
      $('#tk', m).innerHTML = `<div class="card"><div class="row"><h3 class="f1">${esc(t.ref)} · ${esc(t.subject)}</h3><span class="chip">${esc(t.status)}</span></div>
        <small class="muted">${esc(t.name)} &lt;${esc(t.email)}&gt;${t.wallet ? ' · ' + esc(t.wallet) : ''}</small>
        ${messages.map(x => `<div class="alert ${x.author === 'customer' ? '' : 'med'}"><span class="lbl">${x.author === 'customer' ? 'Customer' : 'Support'} · ${when(x.created_at)}</span><p style="white-space:pre-wrap">${esc(x.body)}</p></div>`).join('')}
        <form id="rp" style="display:grid;gap:10px"><textarea name="message" rows="5" placeholder="Reply (emailed to the customer)"></textarea><div class="row"><select name="status" style="width:auto"><option value="answered">Mark answered</option><option value="open">Keep open</option><option value="closed">Close</option></select><button class="btn p">Send</button></div></form></div>`;
      $('#rp', m).onsubmit = guard(async e => { e.preventDefault(); await api(`/api/admin/tickets/${t.id}/reply`, { body: { message: e.target.message.value, status: e.target.status.value } }); toast('Saved.'); go('support'); });
    }));
  }

};

boot();
})();
