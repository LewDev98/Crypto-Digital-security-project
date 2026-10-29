// Duress Mode, Freeze Desk, help desk, new prices and the security fixes from the audit.
import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
process.env.PORT = String(30000 + Math.floor(Math.random() * 20000));
process.env.PUBLIC_URL = `http://localhost:${process.env.PORT}`;
const sol = await import('../src/lib/solana.js');
const admin = sol.generateKeypair();
process.env.ADMIN_WALLETS = admin.publicKey;
const { b58encode } = await import('../src/lib/base58.js');
const { grantRank, grantService } = await import('../src/payments.js');
const { run, get } = await import('../src/db.js');
await import('../src/index.js');
await new Promise(r => setTimeout(r, 300));
const BASE = process.env.PUBLIC_URL;

async function call(path, { method, body, token, headers = {} } = {}) {
  const r = await fetch(BASE + path, { method: method || (body ? 'POST' : 'GET'), redirect: 'manual', headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  let json; try { json = JSON.parse(text); } catch { json = null; }
  return { status: r.status, json, text, headers: r.headers };
}
async function signIn(kp) {
  const n = await call('/api/auth/nonce', { body: { wallet: kp.publicKey } });
  return (await call('/api/auth/verify', { body: { wallet: kp.publicKey, signature: b58encode(kp.sign(Buffer.from(n.json.message))) } })).json.token;
}
const alice = sol.generateKeypair(), mallory = sol.generateKeypair();
const decoy = sol.generateKeypair().publicKey;
let ta, tm, agentId;

test('new prices are live in the site config', async () => {
  const c = await call('/config.js');
  const cfg = JSON.parse(c.text.match(/Object\.assign\(window\.BG_CONFIG \|\| \{\}, (.*)\);$/)[1]);
  assert.equal(cfg.RANKS.sentry.sol, 0.25);
  assert.equal(cfg.RANKS.sentry.guard, 500000);
  assert.equal(cfg.RANKS.guardian.sol, 0.5);
  assert.equal(cfg.RANKS.guardian.guard, 1000000);
  assert.equal(cfg.RANKS.detail.sol, 1);
  assert.equal(cfg.SERVICES.duress.usdc, null, 'Duress Mode price left blank');
  assert.equal(cfg.SERVICES.freeze.usdc, null, 'Freeze Desk price left blank');
  // Unpriced services can't be bought.
  const { verifyAndGrant } = await import('../src/payments.js');
  await assert.rejects(() => verifyAndGrant({ signature: '1'.repeat(88), wallet: alice.publicKey, kind: 'service', id: 'duress' }));
});

test('Duress Mode: setup, real and decoy vault, silent lockdown', async () => {
  ta = await signIn(alice); tm = await signIn(mallory);
  agentId = grantRank(alice.publicKey, 'guardian').id;
  await call(`/api/agent/${agentId}/assets`, { token: ta, body: { type: 'wallet', chain: 'solana', value: alice.publicKey, label: 'Main' } });
  assert.equal((await call('/api/duress/setup', { token: ta, body: { realPin: '1234', duressPin: '9999' } })).status, 402, 'needs the service');
  grantService(alice.publicKey, 'duress');
  assert.equal((await call('/api/duress/setup', { token: ta, body: { realPin: '1234', duressPin: '1234', settings: { decoyWallets: [{ chain: 'solana', address: decoy }] } } })).status, 400, 'PINs must differ');
  assert.equal((await call('/api/duress/setup', { token: ta, body: { realPin: '1234', duressPin: '9999' } })).status, 400, 'needs a decoy');
  const s = await call('/api/duress/setup', { token: ta, body: { realPin: '1234', duressPin: '9999', settings: { coolingHours: 12, decoyWallets: [{ chain: 'solana', address: decoy, label: 'Spending' }], name: 'Alice' } } });
  assert.equal(s.status, 200);
  assert.equal(s.json.settings.coolingHours, 12);
  const row = get('select * from duress where wallet = ?', alice.publicKey);
  assert.ok(!row.real_pin.includes('1234') && !row.duress_pin.includes('9999'), 'PINs are hashed');

  const real = await call('/api/duress/vault', { token: ta, body: { pin: '1234' } });
  assert.equal(real.status, 200);
  assert.ok(real.json.wallets.some(w => w.address === alice.publicKey), 'real view shows real wallets');
  assert.equal((await call('/api/duress/vault', { token: ta, body: { pin: '0000' } })).status, 401);

  const fake = await call('/api/duress/vault', { token: ta, body: { pin: '9999' } });
  assert.equal(fake.status, 200, 'duress PIN looks like a normal unlock');
  assert.deepEqual(Object.keys(fake.json), Object.keys(real.json), 'same response shape');
  assert.deepEqual(fake.json.wallets.map(w => w.address), [decoy], 'only the decoy is shown');
  await new Promise(r => setTimeout(r, 50));
  assert.ok(get('select lockdown_until from duress where wallet = ?', alice.publicKey).lockdown_until > Date.now() / 1000 + 11 * 3600, 'lockdown started');

  // Nothing about it reaches Alice's own alert feed (the attacker may hold her phone).
  const feed = (await call(`/api/agent/${agentId}/alerts`, { token: ta })).json.alerts;
  assert.ok(!feed.some(a => /duress|emergency|lock/i.test(a.title)));

  // Entering the duress PIN in the dashboard looks like a wrong PIN.
  assert.equal((await call('/api/duress/open', { token: ta, body: { pin: '9999' } })).status, 401);
  // During the lockdown, settings are frozen.
  assert.equal((await call('/api/duress/settings', { token: ta, body: { pin: '1234', settings: { coolingHours: 1 } } })).status, 423);
  assert.equal((await call('/api/duress/disable', { token: ta, body: { pin: '1234' } })).status, 423);
  // Someone else can't read or use Alice's vault.
  assert.equal((await call('/api/duress/vault', { token: tm, body: { pin: '1234' } })).status, 404);
});

test('Duress lockdown blocks big transfers in the firewall with no override, small ones pass', async () => {
  const big = await call('/api/firewall/evm', { token: ta, body: { agentId, chainId: '0x1', method: 'eth_sendTransaction', params: [{ to: '0x' + '2'.repeat(40), value: '0x' + (5n * 10n ** 18n).toString(16) }] } });
  assert.equal(big.json.action, 'block');
  assert.equal(big.json.locked, true);
  assert.equal(big.json.reasons[0].code, 'duress_lockdown');
  assert.equal(big.json.flows, undefined, 'internal figures are not sent to the browser');
  const small = await call('/api/firewall/evm', { token: ta, body: { agentId, chainId: '0x1', method: 'eth_sendTransaction', params: [{ to: '0x' + '2'.repeat(40), value: '0x' + (10n ** 15n).toString(16) }] } });
  assert.notEqual(small.json.locked, true);
  const approve = await call('/api/firewall/evm', { token: ta, body: { agentId, chainId: '0x1', method: 'eth_sendTransaction', params: [{ to: '0x' + '3'.repeat(40), data: '0x095ea7b3' + '0'.repeat(24) + '4'.repeat(40) + 'f'.repeat(64) }] } });
  assert.equal(approve.json.locked, true, 'token approvals are held');
  const login = await call('/api/firewall/evm', { token: ta, body: { agentId, chainId: '0x1', method: 'personal_sign', params: ['0x48656c6c6f', '0x' + '1'.repeat(40)] } });
  assert.notEqual(login.json.locked, true, 'sign-in messages still work');
});

test('Duress: weakening changes wait 24 hours; strengthening applies now', async () => {
  run('update duress set lockdown_until = 0 where wallet = ?', alice.publicKey);
  const weaker = await call('/api/duress/settings', { token: ta, body: { pin: '1234', settings: { coolingHours: 2 } } });
  assert.equal(weaker.status, 200);
  assert.equal(weaker.json.settings.coolingHours, 12, 'not applied yet');
  assert.equal(weaker.json.pending.settings.coolingHours, 2);
  const stronger = await call('/api/duress/settings', { token: ta, body: { pin: '1234', settings: { coolingHours: 48 } } });
  assert.equal(stronger.json.settings.coolingHours, 48);
  assert.equal(stronger.json.pending, null);
});

test('Guarded Wallets payments are held during a duress lockdown', async () => {
  grantService(alice.publicKey, 'wallets');
  const org = get('select * from orgs where owner = ?', alice.publicKey);
  run("insert into guarded_wallets(id, org_id, name, multisig, vault, members, threshold, time_lock, policy, status, created_at) values('gw_t', ?, 'Ops', 'm', 'v', '[]', 1, 0, '{}', 'active', 0)", org.id);
  assert.equal((await call('/api/org/wallets/gw_t/check', { token: ta, body: { to: decoy, amount: 1 } })).json.decision, 'allow');
  run('update duress set lockdown_until = ? where wallet = ?', Math.floor(Date.now() / 1000) + 3600, alice.publicKey);
  assert.equal((await call('/api/org/wallets/gw_t/check', { token: ta, body: { to: decoy, amount: 1 } })).json.decision, 'timelocked');
  run('update duress set lockdown_until = 0 where wallet = ?', alice.publicKey);
});

const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), crypto.randomBytes(200)]);
let caseId, caseHash;
test('Freeze Desk: evidence locked, hashed, signed and verifiable', async () => {
  const body = { attest: true, victim: { name: 'Alice', email: 'alice@example.com', country: 'UK' }, scamType: 'impersonation', amount: '12', asset: 'SOL',
    occurredAt: '2026-10-20T14:30', description: 'A fake support agent on Telegram told me to sync my wallet and then drained it.',
    victimWallets: [{ chain: 'solana', address: alice.publicKey }], scammerAddresses: [{ chain: 'ethereum', address: '0x' + 'A'.repeat(40) }],
    transactions: [{ chain: 'ethereum', hash: '0x' + 'b'.repeat(64) }], targets: ['binance', 'seal911', 'reportfraud_uk', 'nope'], files: [{ name: 'chat.png', data: PNG.toString('base64') }] };
  assert.equal((await call('/api/freeze/incidents', { token: ta, body })).status, 402, 'needs the service');
  grantService(alice.publicKey, 'freeze');
  assert.equal((await call('/api/freeze/incidents', { token: ta, body: { ...body, attest: false } })).status, 400);
  assert.equal((await call('/api/freeze/incidents', { token: ta, body: { ...body, files: [{ name: 'x.png', data: Buffer.from('<script>alert(1)</script>').toString('base64') }] } })).status, 400, 'non-image files are refused');
  assert.equal((await call('/api/freeze/incidents', { token: ta, body: { ...body, transactions: [{ chain: 'ethereum', hash: 'nope' }] } })).status, 400);
  const r = await call('/api/freeze/incidents', { token: ta, body });
  assert.equal(r.status, 200, r.text);
  caseId = r.json.id; caseHash = r.json.hash;
  assert.match(r.json.ref, /^BG-[0-9A-F]{8}$/);
  assert.equal(r.json.requests.length, 3, 'unknown targets are dropped');
  assert.ok(r.json.requests.every(q => q.status === 'ready' && q.channel === 'manual'), 'no email configured: requests are ready to paste');
  const rq = r.json.requests.find(q => q.target === 'binance');
  assert.match(rq.body, new RegExp(caseHash));
  assert.match(rq.subject, /Urgent freeze request/);
  assert.equal(r.json.files[0].sha256, crypto.createHash('sha256').update(PNG).digest('hex'));
  assert.equal(r.json.manifest.reporter.wallet, alice.publicKey);

  const man = await call(`/api/freeze/incidents/${caseId}/manifest`, { token: ta });
  assert.equal(crypto.createHash('sha256').update(man.text).digest('hex'), caseHash, 'downloaded manifest hashes to the fingerprint');
  const v = await call('/api/evidence/verify/' + caseHash);
  assert.equal(v.json.found, true);
  assert.equal(v.json.signatureValid, true);
  assert.ok(sol.verifyEd25519(Buffer.from(v.json.message), Buffer.from((await import('../src/lib/base58.js')).b58decode(v.json.signature)), v.json.publicKey));
  assert.equal(v.json.reporter, undefined, 'verification shows no private details');
  assert.equal((await call('/api/evidence/verify/' + 'c'.repeat(64))).json.found, false);
  const f = await call(`/api/freeze/incidents/${caseId}/files/${r.json.files[0].id}`, { token: ta });
  assert.equal(f.headers.get('content-type'), 'image/png');

  // Another customer can't see the case.
  grantService(mallory.publicKey, 'freeze');
  assert.equal((await call(`/api/freeze/incidents/${caseId}`, { token: tm })).status, 404);
  assert.equal((await call(`/api/freeze/incidents/${caseId}/manifest`, { token: tm })).status, 404);
  assert.equal((await call(`/api/freeze/incidents/${caseId}/files/${r.json.files[0].id}`, { token: tm })).status, 404);
});

test('Freeze Desk trace flags funds that reach a known exchange address', async () => {
  const { traceIncidents } = await import('../src/freeze.js');
  const { kvSet } = await import('../src/db.js');
  kvSet('freeze:directory', { kraken: { addresses: { bitcoin: ['bc1qexchangehotwallet0000000000000000000'] } } });
  run('update incidents set trace = ? where id = ?', JSON.stringify({ watch: [{ chain: 'bitcoin', address: 'bc1qscammer', depth: 0 }], hops: [], last: {} }), caseId);
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, o) => String(url).includes('/address/bc1qscammer/txs')
    ? new Response(JSON.stringify([{ txid: 'f'.repeat(64), status: { block_time: Math.floor(Date.now() / 1000) }, vin: [{ prevout: { scriptpubkey_address: 'bc1qscammer' } }], vout: [{ scriptpubkey_address: 'bc1qexchangehotwallet0000000000000000000', value: 5e7 }] }]))
    : realFetch(url, o);
  const raised = [];
  try { await traceIncidents({ raise: async (inc, hop, hit) => raised.push(hit?.id) }); } finally { globalThis.fetch = realFetch; }
  assert.deepEqual(raised, ['kraken']);
  const c = await call(`/api/freeze/incidents/${caseId}`, { token: ta });
  assert.ok(c.json.events.some(e => e.kind === 'exchange_hit'));
});

test('Help desk tickets: spam traps, seed-phrase guard, admin replies', async () => {
  const base = { name: 'Bob', email: 'bob@example.com', topic: 'payment', subject: 'Agent not active', message: 'I paid but my agent is not showing in the dashboard.' };
  const bot = await call('/api/support/tickets', { body: { ...base, website: 'http://spam' } });
  assert.equal(bot.json.ok, true);
  assert.equal(get('select count(*) c from tickets').c, 0, 'honeypot submissions are not stored');
  const seed = await call('/api/support/tickets', { body: { ...base, message: 'here is my phrase\nabandon ability able about above absent absorb abstract absurd abuse access accident' } });
  assert.equal(seed.status, 400);
  assert.match(seed.json.error, /recovery phrase/);
  const ok = await call('/api/support/tickets', { body: { ...base, subject: 'Agent\r\nBcc: x@evil.test' } });
  assert.equal(ok.status, 200);
  assert.match(ok.json.ref, /^BG-/);
  const t = get('select * from tickets where ref = ?', ok.json.ref);
  assert.ok(!/[\r\n]/.test(t.subject), 'no header injection');
  assert.equal((await call('/api/admin/tickets', { token: ta })).status, 403);
  const tadmin = await signIn(admin);
  const list = await call('/api/admin/tickets', { token: tadmin });
  assert.equal(list.json.tickets[0].ref, ok.json.ref);
  assert.equal(list.json.tickets[0].ip_hash, undefined);
  const st = await call(`/api/admin/tickets/${t.id}/reply`, { token: tadmin, body: { status: 'closed' } });
  assert.equal(st.status, 200);
});

test('security fixes from the audit', async () => {
  // Deleting an asset ID that belongs to someone else's agent does nothing to it.
  const aAsset = get("select id from assets where agent_id = ? and type = 'wallet'", agentId).id;
  run("insert into oauth_tokens(asset_id, provider, enc, updated_at) values(?, 'google', 'x', 0)", aAsset);
  const mAgent = grantRank(mallory.publicKey, 'sentry').id;
  assert.equal((await call(`/api/agent/${mAgent}/assets/${aAsset}`, { token: tm, method: 'DELETE' })).status, 404);
  assert.ok(get('select 1 from oauth_tokens where asset_id = ?', aAsset), "Alice's inbox token survives");
  // Guarded-wallet policy of another org can't be changed or read.
  grantService(mallory.publicKey, 'wallets');
  assert.equal((await call('/api/org/wallets/gw_t/policy', { token: tm, method: 'PATCH', body: { policy: { perTxLimit: 999 } } })).status, 404);
  // Team admins can't create more admins.
  grantRank(alice.publicKey, 'detail');
  const bob = sol.generateKeypair(); const tb = await signIn(bob);
  await call(`/api/agent/${agentId}/members`, { token: ta, body: { wallet: bob.publicKey, role: 'admin' } });
  assert.equal((await call(`/api/agent/${agentId}/members`, { token: tb, body: { wallet: sol.generateKeypair().publicKey, role: 'admin' } })).status, 403);
  // CORS: other sites don't get read access.
  const c = await fetch(BASE + '/api/health', { headers: { origin: 'https://evil.example' } });
  assert.equal(c.headers.get('access-control-allow-origin'), null);
  // New pages, clean URLs, compression, SEO files, no dotfiles.
  const help = await fetch(BASE + '/help');
  assert.equal(help.status, 200);
  assert.match(await help.text(), /help ticket|Open a ticket/i);
  const vault = await fetch(BASE + '/vault');
  assert.match(vault.headers.get('x-robots-tag') || '', /noindex/);
  assert.doesNotMatch(vault.headers.get('content-security-policy'), /script-src[^;]*unsafe-inline/);
  assert.doesNotMatch((await fetch(BASE + '/app')).headers.get('content-security-policy'), /script-src[^;]*unsafe-inline/);
  const home = await fetch(BASE + '/', { headers: { 'accept-encoding': 'gzip' } });
  assert.equal(home.headers.get('content-encoding'), 'gzip');
  for (const p of ['/robots.txt', '/sitemap.xml', '/llms.txt', '/site.webmanifest']) assert.equal((await fetch(BASE + p)).status, 200, p);
  assert.notEqual((await fetch(BASE + '/.env')).status, 200);
  assert.equal((await fetch(BASE + '/%E0%A4%A')).status, 404, 'malformed URLs do not crash');
  assert.equal((await call('/api/health', { method: 'POST', body: 'x' })).status, 404);
  setTimeout(() => process.exit(0), 50);
});
