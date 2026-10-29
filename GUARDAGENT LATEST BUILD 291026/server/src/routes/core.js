// Sign-in, hire/purchase, site config, RPC proxy, agent briefing, team seats, channels and extension pairing.
import crypto from 'node:crypto';
import { route, bad, HttpError, rateLimit, requireWallet, sessionInfo } from '../http.js';
import { log as audit, auditFor } from '../security.js';
import { config } from '../config.js';
import { run, get, all, now, json, sha256hex, randomToken, tx } from '../db.js';
import { isValidPubkey, verifyEd25519, b58decode, rpcClient } from '../lib/solana.js';
import { RANKS, SERVICES, LIMITS, ALL_CHAINS, isPriced } from '../plans.js';
import { verifyAndGrant, agentActive, serviceActive } from '../payments.js';
import { capacity, assertRoom } from '../capacity.js';
import { lockdownForAgent } from '../duress.js';
import { web3Asset, web3Buffer } from '../vendor.js';
import { agentsOfWallet, orgForWallet, orgsForWallet, ownedOrg, PERSONAL_SERVICES, requireAgent, agentForWallet, isAdmin, normalizeAddress, normalizeEmail, normalizeDomain, normalizeHandle } from '../access.js';

/* ---------------- health + site config ---------------- */
route('GET', '/api/capacity', ({ query, ip }) => {
  rateLimit('cap:' + ip, 60);
  const w = isValidPubkey(String(query.wallet || '')) ? String(query.wallet) : null;
  const c = capacity(w);
  return { open: c.open, limited: c.limited, free: c.free, max: c.max };
});

route('GET', '/api/health', () => ({ ok: true, time: now(), payments: !!(config.solana.rpc && config.solana.guardMint && config.solana.treasury) }));

route('GET', '/config.js', () => {
  const cfg = {
    GUARD_MINT: config.solana.guardMint,
    TREASURY: config.solana.treasury,
    RPC_URL: config.solana.rpc ? config.publicUrl + '/api/rpc' : undefined,
    BACKEND_URL: config.publicUrl,
    APP_URL: config.publicUrl + '/app',
    RANKS: Object.fromEntries(Object.entries(RANKS).map(([k, r]) => [k, { name: r.name, rank: r.rank, sol: r.sol, guard: r.guard }])),
    USDC_MINT: config.solana.usdcMint,
    SERVICES: Object.fromEntries(Object.entries(SERVICES).map(([k, s]) => [k, { name: s.name, usdc: s.usdc ?? null, guard: s.guard }])),
    // Self-hosted, integrity-pinned wallet library when ready (vendor.js), otherwise the CDN copy.
    WEB3_URL: web3Asset().url,
    WEB3_SRI: web3Asset().sri
  };
  return { __raw: `window.BG_CONFIG = Object.assign(window.BG_CONFIG || {}, ${JSON.stringify(cfg)});`, headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-cache' } };
});

route('GET', '/vendor/web3.js', () => {
  const buf = web3Buffer();
  if (!buf) throw new HttpError(404, 'Not ready.');
  return { __raw: buf, headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'public, max-age=31536000, immutable', 'cross-origin-resource-policy': 'same-origin' } };
});

/* ---------------- RPC proxy (keeps your RPC key server-side) ---------------- */
// Only what the site's checkout and the dashboard actually use, so nobody can run up your RPC bill through here.
const RPC_ALLOWED = new Set(['getBalance', 'getAccountInfo', 'getLatestBlockhash', 'getTokenAccountBalance', 'sendTransaction', 'getSignatureStatuses', 'getBlockHeight', 'isBlockhashValid']);
route('POST', '/api/rpc', async ({ body, ip }) => {
  rateLimit('rpc:' + ip, 60);
  if (body?.method === 'sendTransaction') rateLimit('rpcsend:' + ip, 10);
  if (body?.params != null && !Array.isArray(body.params)) throw bad('params must be a list.');
  rateLimit('rpc:all', Number(process.env.RPC_PROXY_PER_MINUTE || 3000));
  if (Array.isArray(body) || !RPC_ALLOWED.has(body?.method)) throw bad('That RPC method is not available here.');
  if (!config.solana.rpc) throw new HttpError(503, 'Solana RPC is not configured.');
  const r = await fetch(config.solana.rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: body.id ?? 1, method: body.method, params: body.params || [] }), signal: AbortSignal.timeout(25000) });
  return await r.json();
}, { limit: 64_000 });

/* ---------------- wallet sign-in ---------------- */
// Requests from a web page on another site are refused outright (a phishing page can't drive our sign-in).
function sameSite(req) {
  const o = req.headers.origin;
  if (o && o !== config.publicUrl && !config.corsOrigins.includes(o)) throw new HttpError(403, 'Sign in from the Bodyguard site itself.');
}
// The message follows the Sign-In With Solana format. Wallets such as Phantom read the domain line and warn
// loudly if the site asking for the signature is not that domain, so a look-alike site can't collect a valid
// signature for this one.
const siwsMessage = (wallet, nonce, issued, expires) => {
  const u = new URL(config.publicUrl);
  return `${u.host} wants you to sign in with your Solana account:\n${wallet}\n\nSign in to Bodyguard Agents. This request costs nothing and does not give access to your funds.\n\nURI: ${u.origin}\nVersion: 1\nChain ID: mainnet\nNonce: ${nonce}\nIssued At: ${issued}\nExpiration Time: ${expires}`;
};
route('POST', '/api/auth/nonce', ({ req, body, ip }) => {
  rateLimit('auth:' + ip, 30);
  sameSite(req);
  const wallet = String(body.wallet || '');
  if (!isValidPubkey(wallet)) throw bad("That isn't a valid Solana wallet address.");
  rateLimit('nonce:' + wallet, 10);
  const nonce = randomToken(16);
  const t = Date.now();
  const message = siwsMessage(wallet, nonce, new Date(t).toISOString(), new Date(t + 600000).toISOString());
  run('insert into nonces(nonce, wallet, message, created_at) values(?,?,?,?)', nonce, wallet, message, now());
  return { message };
});

const deviceOf = ua => {
  ua = String(ua || '');
  const os = /iPhone|iPad/.test(ua) ? 'iPhone/iPad' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Unknown device';
  const br = /Edg\//.test(ua) ? 'Edge' : /Brave/.test(ua) ? 'Brave' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'browser';
  return `${br} on ${os}`;
};
route('POST', '/api/auth/verify', ({ req, body, ip }) => {
  rateLimit('auth:' + ip, 30);
  sameSite(req);
  const wallet = String(body.wallet || '');
  // Several pending requests can exist per wallet, so nobody can cancel your sign-in by requesting one for your address.
  const pendingNonces = all('select * from nonces where wallet = ? and created_at > ? order by created_at desc limit 5', wallet, now() - 600);
  if (!pendingNonces.length) throw bad('That sign-in request expired. Try again.');
  let sig;
  const raw = String(body.signature || '');
  // A 64-byte signature is at most 88 characters in base58 or base64. Longer input is refused before decoding,
  // because decoding a huge base58 string would tie up the server.
  if (raw.length > 100) throw new HttpError(400, 'Signature format not recognised.', undefined, 'bad_signature');
  try { sig = /[+/=0OIl]/.test(raw) ? Buffer.from(raw, 'base64') : Buffer.from(b58decode(raw)); } catch { throw new HttpError(400, 'Signature format not recognised.', undefined, 'bad_signature'); }
  const n = sig.length === 64 && pendingNonces.find(x => verifyEd25519(Buffer.from(x.message, 'utf8'), sig, wallet));
  if (!n) throw new HttpError(401, "That signature doesn't match this wallet.", undefined, 'bad_signature');
  run('delete from nonces where nonce = ?', n.nonce);
  const token = randomToken(32);
  const device = deviceOf(req.headers['user-agent']);
  const known = get('select 1 from sessions where wallet = ? and ua = ?', wallet, device);
  const sid = 's_' + randomToken(9);
  run('insert into sessions(token_hash, wallet, created_at, expires_at, ua, ip, last_seen, id) values(?,?,?,?,?,?,?,?)', sha256hex(token), wallet, now(), now() + 30 * 86400, device, ip, now(), sid);
  audit('sign_in', { device, ip }, { actor: wallet, subject: 'wallet:' + wallet });
  // A sign-in from a device this wallet hasn't used before is reported to the owner, so a stolen or phished
  // sign-in is noticed quickly.
  if (!known && get('select 1 from audit_log where subject = ? and action = ? limit 1 offset 1', 'wallet:' + wallet, 'sign_in')) {
    const ag = agentsOfWallet(wallet)[0];
    if (ag) import('../alerts.js').then(({ raiseAgent }) => raiseAgent(ag.id, { severity: 'med', type: 'new_signin', dedupe: `signin:${wallet}:${device}`,
      title: 'New sign-in to your dashboard', what: `Your Bodyguard dashboard was signed in to from ${device}.`, did: 'Recorded the new device.',
      move: "If this wasn't you, open Account security in your dashboard, sign out every other session, and move funds if you signed anything you didn't recognise." })).catch(() => {});
  }
  return { token, wallet };
});

route('POST', '/api/auth/logout', ({ req }) => {
  const tok = (req.headers.authorization || '').replace('Bearer ', '');
  if (tok) run('delete from sessions where token_hash = ?', sha256hex(tok));
  return { ok: true };
});
// Account security: see every signed-in session and end the ones you don't recognise.
route('GET', '/api/auth/sessions', ({ req }) => {
  const me = sessionInfo(req);
  if (!me) throw new HttpError(401, 'Sign in with your wallet first.');
  const rows = all('select id, token_hash, ua, created_at, last_seen from sessions where wallet = ? and expires_at > ? order by coalesce(last_seen, created_at) desc limit 50', me.wallet, now());
  return { sessions: rows.map(r => ({ id: r.id || r.token_hash.slice(0, 12), device: r.ua || 'Unknown device', createdAt: r.created_at, lastSeen: r.last_seen || r.created_at, current: r.token_hash === me.hash })),
    activity: auditFor('wallet:' + me.wallet, 30).map(a => ({ action: a.action, device: a.detail.device || null, at: a.created_at })) };
});
route('POST', '/api/auth/sessions/revoke', ({ req, body }) => {
  const me = sessionInfo(req);
  if (!me) throw new HttpError(401, 'Sign in with your wallet first.');
  let n;
  if (body.all === true) n = run('delete from sessions where wallet = ? and token_hash != ?', me.wallet, me.hash).changes;
  else n = run('delete from sessions where wallet = ? and (id = ? or substr(token_hash, 1, 12) = ?) and token_hash != ?', me.wallet, String(body.id || ''), String(body.id || ''), me.hash).changes;
  audit(body.all === true ? 'signed_out_everywhere' : 'session_revoked', { count: n }, { actor: me.wallet, subject: 'wallet:' + me.wallet });
  return { revoked: n };
});

route('GET', '/api/me', ({ req }) => {
  const wallet = requireWallet(req);
  const agents = agentsOfWallet(wallet).map(a => ({ id: a.id, rank: a.rank, rankName: RANKS[a.rank]?.name, role: a.role, active: agentActive(a), expiresAt: a.expires_at, limits: LIMITS[a.rank] }));
  const org = orgForWallet(wallet);
  return {
    wallet, admin: isAdmin(wallet), agents,
    org: org ? { id: org.id, name: org.name, role: org.role, services: Object.fromEntries(Object.keys(SERVICES).map(s => {
      // Personal services only ever come from the wallet's own organisation.
      const src = PERSONAL_SERVICES.has(s) ? ownedOrg(wallet) : org;
      return [s, { active: serviceActive(src, s), ...(src ? json(src.services)[s] || {} : {}) }];
    })) } : null,
    telegramBot: config.telegram.username || null,
    pushKey: config.vapid.publicKey || null,
    features: { inboxGoogle: !!config.google.id, inboxMicrosoft: !!config.microsoft.id, payments: !!(config.solana.rpc && config.solana.guardMint && config.solana.treasury) }
  };
});

/* ---------------- hire / purchase ---------------- */
route('POST', '/api/hire', async ({ body, ip }) => {
  rateLimit('hire:' + ip, 20);
  const wallet = String(body.wallet || '');
  if (!isValidPubkey(wallet)) throw bad("That isn't a valid wallet address.");
  const kind = body.kind || (body.rank ? 'rank' : 'service');
  const id = body.id || body.rank;
  const out = await verifyAndGrant({ signature: String(body.signature || ''), wallet, kind, id });
  if (kind === 'rank') {
    const { welcomeAlert } = await import('../alerts.js');
    welcomeAlert(out.agentId).catch(() => {});
  }
  return out;
});

/* ---------------- agent + briefing ---------------- */
function agentView(a) {
  const assets = all('select id, type, chain, value, label, created_at, enabled, state from assets where agent_id = ? and internal = 0 order by created_at', a.id)
    .map(x => { const st = json(x.state); return { ...x, state: undefined, inbox: st.inbox || null, lastChecked: st.lastChecked || null, health: st.health || null }; });
  const ch = get('select telegram_chat_id, alert_email from channels where subject = ?', 'agent:' + a.id) || {};
  const members = all('select wallet, role from members where agent_id = ?', a.id);
  const pushCount = get('select count(*) c from push_subs where subject = ?', 'agent:' + a.id).c;
  const limits = LIMITS[a.rank];
  const used = { wallets: assets.filter(x => x.type === 'wallet').length, emails: assets.filter(x => x.type === 'email').length,
    domains: assets.filter(x => x.type === 'domain').length, handles: assets.filter(x => x.type === 'handle').length, seats: members.length };
  return { id: a.id, owner: a.owner, rank: a.rank, rankName: RANKS[a.rank]?.name, active: agentActive(a), expiresAt: a.expires_at, limits, used, assets, members,
    channels: { telegram: !!ch.telegram_chat_id, email: ch.alert_email || null, push: pushCount } };
}
route('GET', '/api/agent/:id', ctx => agentView(requireAgent(ctx, { allowExpired: true })));

route('POST', '/api/agent/:id/assets', ctx => {
  const a = requireAgent(ctx, { write: true });
  const L = LIMITS[a.rank];
  const { type } = ctx.body;
  let chain = null, value;
  if (type === 'wallet') {
    chain = String(ctx.body.chain || '').toLowerCase();
    if (!ALL_CHAINS.includes(chain)) throw bad('Pick a supported chain.');
    if (!L.chains.includes(chain)) throw new HttpError(403, `Your ${RANKS[a.rank].name} rank covers ${L.chains.join(', ')}. Upgrade to Guardian for every chain.`);
    value = normalizeAddress(chain, ctx.body.value);
  } else if (type === 'email') value = normalizeEmail(ctx.body.value);
  else if (type === 'domain') value = normalizeDomain(ctx.body.value);
  else if (type === 'handle') value = normalizeHandle(ctx.body.value);
  else throw bad('Choose wallet, email, domain or handle.');
  const key = { wallet: 'wallets', email: 'emails', domain: 'domains', handle: 'handles' }[type];
  const count = get('select count(*) c from assets where agent_id = ? and type = ? and internal = 0', a.id, type).c;
  if (count >= L[key]) throw new HttpError(403, L[key] === 0 ? `Your ${RANKS[a.rank].name} rank doesn't include ${key}. Upgrade to add them.` : `Your rank covers up to ${L[key]} ${key}. Remove one or upgrade.`);
  if (type === 'wallet') assertRoom(1);
  const label = String(ctx.body.label || '').replace(/[\u0000-\u001f]/g, ' ').slice(0, 60);
  try {
    run('insert into assets(agent_id, type, chain, value, label, created_at) values(?,?,?,?,?,?)', a.id, type, chain, value, label, now());
  } catch { throw bad('That is already on your agent.'); }
  if (type === 'wallet') run("insert or ignore into counterparties(agent_id, chain, address, label, source, first_seen, last_seen) values(?,?,?,?, 'self', ?, ?)", a.id, chain, value, label || 'Your wallet', now(), now());
  return agentView(a);
});

route('PATCH', '/api/agent/:id/assets/:assetId', ctx => {
  const a = requireAgent(ctx, { write: true });
  const cur = get('select type, enabled from assets where id = ? and agent_id = ?', ctx.params.assetId, a.id);
  if (cur?.type === 'wallet' && !cur.enabled && ctx.body.enabled) assertRoom(1);
  run('update assets set label = coalesce(?, label), enabled = coalesce(?, enabled) where id = ? and agent_id = ?',
    ctx.body.label != null ? String(ctx.body.label).replace(/[\u0000-\u001f]/g, ' ').slice(0, 60) : null, ctx.body.enabled != null ? (ctx.body.enabled ? 1 : 0) : null, ctx.params.assetId, a.id);
  return agentView(a);
});

route('DELETE', '/api/agent/:id/assets/:assetId', ctx => {
  const a = requireAgent(ctx, { write: true, allowExpired: true });
  // Check the asset belongs to this agent before touching its inbox token (it used to delete any agent's token by ID).
  const asset = get('select id from assets where id = ? and agent_id = ?', ctx.params.assetId, a.id);
  if (!asset) throw new HttpError(404, 'That item is not on your agent.');
  tx(() => {
    run('delete from oauth_tokens where asset_id = ?', asset.id);
    run('delete from assets where id = ? and agent_id = ?', asset.id, a.id);
  });
  return agentView(a);
});

/* ---------------- saved addresses (shield) ---------------- */
route('GET', '/api/agent/:id/addresses', ctx => {
  const a = requireAgent(ctx, { allowExpired: true });
  return {
    addresses: all('select chain, address, label, source, count, last_seen from counterparties where agent_id = ? order by (source = \'user\') desc, last_seen desc limit 500', a.id),
    poisoned: all('select chain, address, imitates, label, created_at from poison_tags where agent_id = ? order by created_at desc limit 200', a.id)
  };
});
route('POST', '/api/agent/:id/addresses', ctx => {
  const a = requireAgent(ctx, { write: true });
  const chain = String(ctx.body.chain || 'solana').toLowerCase();
  if (!ALL_CHAINS.includes(chain)) throw bad('Pick a supported chain.');
  const address = normalizeAddress(chain, ctx.body.address);
  const label = String(ctx.body.label || '').replace(/[\u0000-\u001f]/g, ' ').slice(0, 60) || 'Saved address';
  run(`insert into counterparties(agent_id, chain, address, label, source, first_seen, last_seen) values(?,?,?,?, 'user', ?, ?)
       on conflict(agent_id, chain, address) do update set label = excluded.label, source = 'user'`, a.id, chain, address, label, now(), now());
  return { ok: true };
});
route('DELETE', '/api/agent/:id/addresses/:chain/:address', ctx => {
  const a = requireAgent(ctx, { write: true, allowExpired: true });
  run("delete from counterparties where agent_id = ? and chain = ? and address = ? and source in ('user','history')", a.id, ctx.params.chain, ctx.params.address);
  return { ok: true };
});

/* ---------------- team seats ---------------- */
route('POST', '/api/agent/:id/members', ctx => {
  const a = requireAgent(ctx, { write: true });
  const w = String(ctx.body.wallet || '');
  if (!isValidPubkey(w)) throw bad("That isn't a valid Solana wallet address.");
  const caller = requireWallet(ctx.req);
  if (ctx.body.role === 'admin' && caller !== a.owner) throw new HttpError(403, 'Only the agent owner can add admins.');
  const n = get('select count(*) c from members where agent_id = ?', a.id).c;
  if (n >= LIMITS[a.rank].seats) throw new HttpError(403, LIMITS[a.rank].seats === 1 ? 'Team seats come with the Security Detail rank.' : `Your Detail has ${LIMITS[a.rank].seats} seats and they are all in use.`);
  run("insert or ignore into members(agent_id, wallet, role) values(?,?,?)", a.id, w, ctx.body.role === 'admin' ? 'admin' : 'member');
  audit('member_added', { agent: a.id, wallet: w, role: ctx.body.role === 'admin' ? 'admin' : 'member' }, { actor: caller, subject: 'agent:' + a.id });
  return agentView(a);
});
route('DELETE', '/api/agent/:id/members/:wallet', ctx => {
  const a = requireAgent(ctx, { write: true, allowExpired: true });
  if (ctx.params.wallet === a.owner) throw bad("The owner's seat can't be removed.");
  const target = get('select role from members where agent_id = ? and wallet = ?', a.id, ctx.params.wallet);
  if (target?.role === 'admin' && requireWallet(ctx.req) !== a.owner) throw new HttpError(403, 'Only the agent owner can remove an admin.');
  run('delete from members where agent_id = ? and wallet = ?', a.id, ctx.params.wallet);
  // A removed teammate's paired browsers stop working for this agent at once.
  run('delete from ext_tokens where agent_id = ? and wallet = ?', a.id, ctx.params.wallet);
  audit('member_removed', { agent: a.id, wallet: ctx.params.wallet }, { actor: requireWallet(ctx.req), subject: 'agent:' + a.id });
  return agentView(a);
});

/* ---------------- alert channels ---------------- */
route('POST', '/api/agent/:id/channels', ctx => {
  const a = requireAgent(ctx, { write: true });
  const email = ctx.body.email ? normalizeEmail(ctx.body.email) : null;
  run(`insert into channels(subject, alert_email) values(?, ?) on conflict(subject) do update set alert_email = excluded.alert_email`, 'agent:' + a.id, email);
  return agentView(a);
});
route('POST', '/api/agent/:id/telegram-link', ctx => {
  const a = requireAgent(ctx, { write: true });
  if (!config.telegram.token || !config.telegram.username) throw new HttpError(503, 'Telegram alerts are not switched on yet.');
  const code = 'a' + randomToken(9).replace(/[^A-Za-z0-9]/g, '');
  run(`insert into channels(subject, link_code) values(?, ?) on conflict(subject) do update set link_code = excluded.link_code`, 'agent:' + a.id, code);
  return { url: `https://t.me/${config.telegram.username}?start=${code}` };
});
route('DELETE', '/api/agent/:id/telegram', ctx => {
  const a = requireAgent(ctx, { write: true, allowExpired: true });
  run('update channels set telegram_chat_id = null where subject = ?', 'agent:' + a.id);
  return agentView(a);
});
route('GET', '/api/push/key', () => ({ key: config.vapid.publicKey || null }));
route('POST', '/api/agent/:id/push', ctx => {
  const a = requireAgent(ctx);
  if (!LIMITS[a.rank].push) throw new HttpError(403, 'Push alerts come with Guardian and Security Detail.');
  const s = ctx.body.subscription;
  if (!s?.endpoint || !s?.keys?.p256dh || !s?.keys?.auth) throw bad('Push subscription is incomplete.');
  // Only real browser push services, so this can't be used to make the server call arbitrary URLs.
  let host = '';
  try { const u = new URL(s.endpoint); if (u.protocol === 'https:') host = u.hostname; } catch {}
  if (!/(^|\.)(fcm\.googleapis\.com|push\.services\.mozilla\.com|notify\.windows\.com|push\.apple\.com)$/.test(host)) throw bad('That push endpoint is not from a supported browser.');
  run(`insert into push_subs(subject, endpoint, p256dh, auth, created_at) values(?,?,?,?,?)
       on conflict(endpoint) do update set subject = excluded.subject, p256dh = excluded.p256dh, auth = excluded.auth`, 'agent:' + a.id, s.endpoint, s.keys.p256dh, s.keys.auth, now());
  return { ok: true };
});
route('DELETE', '/api/agent/:id/push', ctx => {
  const a = requireAgent(ctx, { allowExpired: true });
  run('delete from push_subs where subject = ? and endpoint = ?', 'agent:' + a.id, String(ctx.body.endpoint || ''));
  return { ok: true };
});

/* ---------------- alerts feed ---------------- */
route('GET', '/api/agent/:id/alerts', ctx => {
  const a = requireAgent(ctx, { allowExpired: true });
  const before = Number(ctx.query.before) || 9e15;
  return { alerts: all('select id, severity, type, title, what, did, move, data, created_at, acked_at from alerts where subject = ? and id < ? order by id desc limit 50', 'agent:' + a.id, before).map(x => ({ ...x, data: json(x.data) })) };
});
route('POST', '/api/alerts/:alertId/ack', ctx => {
  const wallet = requireWallet(ctx.req);
  const al = get('select * from alerts where id = ?', ctx.params.alertId);
  if (!al) throw new HttpError(404, 'Alert not found.');
  const [kind, sid] = al.subject.split(':');
  if (kind === 'agent') agentForWallet(wallet, sid, { allowExpired: true });
  else if (kind === 'org') { if (!orgsForWallet(wallet).some(o => o.id === sid)) throw new HttpError(403, 'Not your alert.'); }
  else throw new HttpError(403, 'Not your alert.');
  run('update alerts set acked_at = ? where id = ?', now(), al.id);
  return { ok: true };
});

/* ---------------- browser extension pairing ---------------- */
route('POST', '/api/agent/:id/pair-code', ctx => {
  const a = requireAgent(ctx);
  const wallet = requireWallet(ctx.req);
  const code = String(crypto.randomInt(10000000, 100000000));
  run('delete from pair_codes where created_at < ?', now() - 600);
  run('insert or replace into pair_codes(code, agent_id, wallet, created_at) values(?,?,?,?)', code, a.id, wallet, now());
  return { code, expiresIn: 600 };
});
route('POST', '/api/ext/pair', ({ body, ip }) => {
  rateLimit('pair:' + ip, 10);
  rateLimit('pair:all', 120);
  const c = get('select * from pair_codes where code = ?', String(body.code || '').trim());
  if (!c || now() - c.created_at > 600) throw new HttpError(400, 'That pairing code is wrong or expired. Make a new one in your dashboard.', undefined, 'pair_fail');
  run('delete from pair_codes where code = ?', c.code);
  const token = 'ext_' + randomToken(32);
  run('insert into ext_tokens(token_hash, agent_id, wallet, created_at, last_used) values(?,?,?,?,?)', sha256hex(token), c.agent_id, c.wallet, now(), now());
  audit('extension_paired', { agent: c.agent_id }, { actor: c.wallet, subject: 'agent:' + c.agent_id });
  const a = get('select * from agents where id = ?', c.agent_id);
  return { token, agentId: a.id, rank: a.rank };
});
route('GET', '/api/ext/me', ctx => {
  const tok = (ctx.req.headers.authorization || '').replace('Bearer ', '');
  const t = tok.startsWith('ext_') && get('select * from ext_tokens where token_hash = ?', sha256hex(tok));
  if (!t) throw new HttpError(401, 'Not paired.');
  const a = get('select * from agents where id = ?', t.agent_id);
  return { agentId: a.id, rank: a.rank, rankName: RANKS[a.rank]?.name, active: agentActive(a), expiresAt: a.expires_at, lockdownUntil: lockdownForAgent(a).until || null };
});
route('GET', '/api/agent/:id/extensions', ctx => {
  const a = requireAgent(ctx, { allowExpired: true });
  return { extensions: all('select substr(token_hash,1,8) id, wallet, created_at, last_used from ext_tokens where agent_id = ?', a.id) };
});
route('DELETE', '/api/agent/:id/extensions/:tid', ctx => {
  const a = requireAgent(ctx, { write: true, allowExpired: true });
  // Unpairing a browser during a duress time-lock would switch its shield off, so it waits until the lock ends.
  if (lockdownForAgent(a).until) throw new HttpError(423, 'Paired browsers cannot be removed while a security time-lock is active.');
  const n = run('delete from ext_tokens where agent_id = ? and substr(token_hash,1,8) = ?', a.id, ctx.params.tid).changes;
  if (!n) throw new HttpError(404, 'That browser is not paired with this agent.');
  audit('extension_removed', { agent: a.id }, { actor: requireWallet(ctx.req), subject: 'agent:' + a.id });
  return { ok: true };
});
