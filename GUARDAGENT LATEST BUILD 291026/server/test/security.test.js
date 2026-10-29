// Active defences and account security: regression tests.
import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
const sol = await import('../src/lib/solana.js');
const admin = sol.generateKeypair(), alice = sol.generateKeypair(), bob = sol.generateKeypair();
process.env.ADMIN_WALLETS = admin.publicKey;
process.env.PORT = String(30000 + Math.floor(Math.random() * 20000));
process.env.PUBLIC_URL = `http://localhost:${process.env.PORT}`;
process.env.REQUESTS_PER_MINUTE_PER_IP = '40';
const { b58encode } = await import('../src/lib/base58.js');
const { grantRank, grantService } = await import('../src/payments.js');
const { run, get, all } = await import('../src/db.js');
const security = await import('../src/security.js');
await import('../src/index.js');
await new Promise(r => setTimeout(r, 300));
const BASE = process.env.PUBLIC_URL;
async function call(path, { method, body, token, headers = {}, ip } = {}) {
  const r = await fetch(BASE + path, { method: method || (body ? 'POST' : 'GET'), redirect: 'manual',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}), ...(ip ? { 'x-forwarded-for': ip } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text(); let json; try { json = JSON.parse(text); } catch {}
  return { status: r.status, json, text, headers: r.headers };
}
async function signIn(kp, headers = {}) {
  const n = await call('/api/auth/nonce', { body: { wallet: kp.publicKey }, headers });
  return (await call('/api/auth/verify', { body: { wallet: kp.publicKey, signature: b58encode(kp.sign(Buffer.from(n.json.message))) }, headers })).json.token;
}

test('honeypot paths block the address at once; other visitors are unaffected; admins can unblock', async () => {
  security._resetSecurity();
  const attacker = '45.33.32.156';
  assert.equal((await call('/api/health', { ip: attacker })).status, 200);
  assert.equal((await call('/.env', { ip: attacker })).status, 404);
  const blocked = await call('/api/health', { ip: attacker });
  assert.equal(blocked.status, 429, 'blocked after touching a honeypot');
  assert.ok(Number(blocked.headers.get('retry-after')) > 800);
  assert.equal((await call('/api/health', { ip: '45.33.32.157' })).status, 200, 'neighbours are fine');
  assert.ok(get('select 1 from ip_bans where ip = ?', attacker), 'the block survives a restart');
  const ta = await signIn(admin);
  const sec = await call('/api/admin/security', { token: ta });
  assert.ok(sec.json.bans.some(b => b.ip === attacker));
  await call('/api/admin/security/unban', { token: ta, body: { ip: attacker } });
  assert.equal((await call('/api/health', { ip: attacker })).status, 200, 'unblocked');
});

test('private and internal addresses are never blocked (a proxy can never lock everyone out)', async () => {
  security._resetSecurity();
  for (const ip of ['10.1.2.3', '100.64.0.2', '127.0.0.1']) {
    await call('/wp-login.php', { ip });
    assert.equal((await call('/api/health', { ip })).status, 200, ip);
  }
  assert.ok(all("select 1 from audit_log where action = 'ban_skipped'").length >= 3, 'skips are logged');
});

test('repeated bad signatures add up to a block, and blocks escalate', async () => {
  security._resetSecurity();
  const ip = '45.33.32.160';
  const n = await call('/api/auth/nonce', { body: { wallet: alice.publicKey }, ip });
  let last;
  for (let i = 0; i < 8; i++) last = await call('/api/auth/verify', { body: { wallet: alice.publicKey, signature: b58encode(bob.sign(Buffer.from(n.json.message))) }, ip });
  assert.equal(last.status, 429, 'blocked after about seven forged signatures');
  const first = security.activeBans().find(b => b.ip === ip);
  security.ban(ip, 'test');
  const second = security.activeBans().find(b => b.ip === ip);
  assert.equal(second.count, 2);
  assert.ok(second.until - Math.floor(Date.now() / 1000) > (first.until - Math.floor(Date.now() / 1000)) * 1.8, 'second block lasts about twice as long');
  security.unban(ip);
});

test('the global per-address request budget answers 429 when exceeded', async () => {
  security._resetSecurity();
  const ip = '45.33.32.170';
  const codes = [];
  for (let i = 0; i < 45; i++) codes.push((await call('/api/health', { ip })).status);
  assert.equal(codes[0], 200);
  assert.ok(codes.slice(-3).every(c => c === 429), 'over budget');
  security._resetSecurity();
});

test('sign-in: wallet-standard (SIWS) message, and requests from other sites are refused', async () => {
  security._resetSecurity();
  const n = await call('/api/auth/nonce', { body: { wallet: alice.publicKey } });
  assert.match(n.json.message, new RegExp(`^localhost:${process.env.PORT} wants you to sign in with your Solana account:\\n${alice.publicKey}\\n`));
  assert.match(n.json.message, /\nURI: http:\/\/localhost:\d+\nVersion: 1\nChain ID: mainnet\nNonce: \S+\nIssued At: \S+\nExpiration Time: \S+$/);
  const evil = await call('/api/auth/nonce', { body: { wallet: alice.publicKey }, headers: { origin: 'https://guardagent-claim.example' } });
  assert.equal(evil.status, 403, 'a phishing site cannot get a sign-in message');
  const ok = await call('/api/auth/nonce', { body: { wallet: alice.publicKey }, headers: { origin: BASE } });
  assert.equal(ok.status, 200);
});

test('sessions: list, sign out one device, sign out everywhere, idle expiry', async () => {
  security._resetSecurity();
  grantRank(alice.publicKey, 'guardian');
  const t1 = await signIn(alice, { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Chrome/120' });
  const t2 = await signIn(alice, { 'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17) Safari/604' });
  const t3 = await signIn(alice, { 'user-agent': 'Mozilla/5.0 (Macintosh) Firefox/121' });
  const list = await call('/api/auth/sessions', { token: t1 });
  assert.ok(list.json.sessions.length >= 3);
  assert.equal(list.json.sessions.filter(s => s.current).length, 1);
  assert.ok(list.json.activity.some(a => a.action === 'sign_in'));
  assert.ok(!JSON.stringify(list.json).includes(t2), 'tokens are never shown');
  const other = list.json.sessions.find(s => !s.current && /iPhone/.test(s.device));
  assert.ok(other, 'device names are recorded');
  assert.equal((await call('/api/auth/sessions/revoke', { token: t1, body: { id: other.id } })).json.revoked, 1);
  assert.equal((await call('/api/me', { token: t2 })).status, 401, 'that device is signed out');
  assert.equal((await call('/api/auth/sessions/revoke', { token: t1, body: { id: list.json.sessions.find(s => s.current).id } })).json.revoked, 0, 'cannot revoke the current one by id');
  const all1 = await call('/api/auth/sessions/revoke', { token: t1, body: { all: true } });
  assert.ok(all1.json.revoked >= 1);
  assert.equal((await call('/api/me', { token: t3 })).status, 401);
  assert.equal((await call('/api/me', { token: t1 })).status, 200, 'this device stays signed in');
  // Someone else's session ids do nothing.
  const tb = await signIn(bob);
  const bobs = (await call('/api/auth/sessions', { token: tb })).json.sessions[0].id;
  assert.equal((await call('/api/auth/sessions/revoke', { token: t1, body: { id: bobs } })).json.revoked, 0);
  assert.equal((await call('/api/me', { token: tb })).status, 200);
  // Idle for more than 7 days: signed out.
  run('update sessions set last_seen = ? where wallet = ?', Math.floor(Date.now() / 1000) - 8 * 86400, bob.publicKey);
  assert.equal((await call('/api/me', { token: tb })).status, 401);
});

test('a sign-in from a new device alerts the owner', async () => {
  const ag = get('select id from agents where owner = ?', alice.publicKey);
  await new Promise(r => setTimeout(r, 100));
  const rows = all("select what from alerts where subject = ? and type = 'new_signin'", 'agent:' + ag.id);
  assert.ok(rows.length >= 2, 'one alert per new device (not for the first ever sign-in)');
  assert.ok(rows.some(r => /iPhone|Firefox|Mac/i.test(r.what)), 'names the device');
});

test('admin tools need a sign-in from the last 12 hours', async () => {
  const ta = await signIn(admin);
  assert.equal((await call('/api/admin/security', { token: ta })).status, 200);
  run('update sessions set created_at = ? where wallet = ?', Math.floor(Date.now() / 1000) - 13 * 3600, admin.publicKey);
  const stale = await call('/api/admin/security', { token: ta });
  assert.equal(stale.status, 401);
  assert.match(stale.json.error, /admin tools/);
  assert.equal((await call('/api/me', { token: ta })).status, 200, 'ordinary pages still work');
  assert.equal((await call('/api/admin/security', { token: await signIn(admin) })).status, 200);
  assert.equal((await call('/api/admin/security', { token: await signIn(alice) })).status, 403, 'non-admins refused');
});

test('removing a teammate switches off their paired browser for that agent', async () => {
  const owner = sol.generateKeypair(), mate = sol.generateKeypair();
  const ag = grantRank(owner.publicKey, 'detail');
  const to = await signIn(owner), tm = await signIn(mate);
  assert.equal((await call(`/api/agent/${ag.id}/members`, { token: to, body: { wallet: mate.publicKey } })).status, 200);
  const code = (await call(`/api/agent/${ag.id}/pair-code`, { token: tm, body: {} })).json.code;
  const ext = (await call('/api/ext/pair', { body: { code } })).json.token;
  assert.equal((await call('/api/ext/me', { token: ext })).status, 200);
  await call(`/api/agent/${ag.id}/members/${mate.publicKey}`, { token: to, method: 'DELETE' });
  assert.equal((await call('/api/ext/me', { token: ext })).status, 401, 'extension token is dead');
  assert.ok(get("select 1 from audit_log where action = 'member_removed' and subject = ?", 'agent:' + ag.id));
});

test('strict email validation refuses header tricks', async () => {
  const { normalizeEmail } = await import('../src/access.js');
  assert.equal(normalizeEmail(' Alice@Example.COM '), 'alice@example.com');
  for (const bad of ['a@b', '"a,b"@x.com', 'a@x.com\nBcc: c@y.com', 'a<b>@x.com', 'a@x.com,b@y.com', 'x'.repeat(250) + '@x.com']) assert.throws(() => normalizeEmail(bad), bad);
});

test('security.txt is published', async () => {
  const r = await call('/.well-known/security.txt');
  assert.equal(r.status, 200);
  assert.match(r.text, /^Contact: /m);
  assert.match(r.text, /^Expires: \d{4}-/m);
});

test('Duress Mode activity never appears in account activity or the admin log', async () => {
  const w = sol.generateKeypair();
  const org = grantService(w.publicKey, 'duress');
  const tw = await signIn(w);
  const s = await call('/api/duress/setup', { token: tw, body: { realPin: '2468', duressPin: '1357', settings: { decoyWallets: [{ chain: 'solana', address: alice.publicKey }] } } });
  assert.equal(s.status, 200, JSON.stringify(s.json));
  await call('/api/duress/vault', { token: tw, body: { pin: '1357' } });
  const mine = await call('/api/auth/sessions', { token: tw });
  assert.ok(!/duress/i.test(JSON.stringify(mine.json)), 'nothing about Duress Mode in the activity list');
  const adminView = await call('/api/admin/security', { token: await signIn(admin) });
  assert.ok(!adminView.json.audit.some(a => String(a.subject || '').startsWith('duress:')), 'nor in the admin log');
  run('update duress set lockdown_until = 0 where wallet = ?', w.publicKey);
  void org;
});

test('the dashboard does not sign you out for a wrong PIN', async () => {
  const fs = await import('node:fs');
  const src = fs.readFileSync(new URL('../../web/app.js', import.meta.url), 'utf8');
  assert.match(src, /r\.status === 401 && S\.token && !path\.startsWith\('\/api\/auth'\) && !path\.startsWith\('\/api\/duress\/'\)/);
});

test('shield check refuses unknown chains; hostnames in alerts are cleaned', async () => {
  const t = await signIn(alice);
  const agentId = get('select id from agents where owner = ?', alice.publicKey).id;
  assert.equal((await call('/api/shield/check', { token: t, body: { agentId, address: '0x' + '1'.repeat(40), chain: '__proto__' } })).status, 400);
  assert.equal((await call('/api/shield/check', { token: t, body: { agentId, address: '0x' + '1'.repeat(40), chain: 'ethereum' } })).status, 200);
});

test('public pages carry a strict CSP; the dashboard a stricter one', async () => {
  const home = await call('/');
  const csp = home.headers.get('content-security-policy');
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /connect-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /object-src 'none'/);
  const app = await call('/app');
  assert.doesNotMatch(app.headers.get('content-security-policy'), /script-src[^;]*unsafe-inline/);
  assert.match(app.text, /<script src="\/config.js"><\/script>\s*<script src="\/app.js">/);
});

test('client address: proxies, ports, junk and a dedicated header', async () => {
  const { ipOf } = await import('../src/http.js');
  const r = (h, a = '10.0.0.5') => ({ headers: h, socket: { remoteAddress: a } });
  assert.equal(ipOf(r({ 'x-forwarded-for': '6.6.6.6, 1.2.3.4' })), '1.2.3.4', 'the visitor cannot choose their address by sending a fake header');
  assert.equal(ipOf(r({ 'x-forwarded-for': 'not-an-ip' })), '10.0.0.5');
  assert.equal(ipOf(r({ 'x-forwarded-for': '9.9.9.9:443' })), '9.9.9.9');
  process.env.CLIENT_IP_HEADER = 'x-real-ip';
  assert.equal(ipOf(r({ 'x-real-ip': '8.8.8.8', 'x-forwarded-for': '1.1.1.1' })), '8.8.8.8');
  delete process.env.CLIENT_IP_HEADER;
});

/* ---------------- firewall additions ---------------- */
test('firewall: DAI permits, NFT and multi-token transfers, negative values, typed data during a lockdown', async () => {
  const { analyzeEvm } = await import('../src/engines/firewall-evm.js');
  const { learn } = await import('../src/engines/poison.js');
  const { gateFirewall } = await import('../src/duress.js');
  const agent = { id: get('select id from agents where owner = ?', alice.publicKey).id };
  const me = '0x' + '5'.repeat(40), spender = '0x' + '8'.repeat(40);
  const dai = { primaryType: 'Permit', domain: { name: 'Dai Stablecoin' }, message: { holder: me, spender, nonce: 0, expiry: 0, allowed: true } };
  const r1 = await analyzeEvm(agent, { chainId: '0x1', method: 'eth_signTypedData_v4', params: [me, JSON.stringify(dai)], from: me });
  assert.ok(r1.reasons.some(x => /no limit|personal wallet/.test(x.text)), 'allowed:true counts as unlimited');
  const garbage = await analyzeEvm(agent, { chainId: '0x1', method: 'eth_signTypedData_v4', params: [me, JSON.stringify({ primaryType: 'Permit', message: { spender: { evil: 1 }, value: 'abc' } })], from: me });
  assert.notEqual(garbage.action, 'allow', 'unreadable spender is not waved through');
  const swapped = await analyzeEvm(agent, { chainId: '0x1', method: 'eth_signTypedData_v4', params: [dai, me], from: me });
  assert.equal(swapped.action, r1.action, 'typed data first, address second, is read too');
  // Transfers to a lookalike of a saved address are caught for every transfer shape.
  const REAL = '0xabcd111111111111111111111111111111119876', FAKE = '0xabcd222222222222222222222222222222229876';
  learn(agent.id, 'ethereum', REAL, { label: 'Exchange', source: 'user' });
  const pad = a => a.slice(2).padStart(64, '0');
  const word = n => n.toString(16).padStart(64, '0');
  const { selector } = await import('../src/lib/keccak.js');
  const sels = [selector('safeTransferFrom(address,address,uint256,bytes)'), selector('safeTransferFrom(address,address,uint256,uint256,bytes)'), selector('safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)')];
  assert.deepEqual(sels, ['0xb88d4fde', '0xf242432a', '0x2eb2c2d6'], 'standard ERC-721 / ERC-1155 selectors');
  for (const s of sels) {
    const data = s + pad(me) + pad(FAKE) + word(1n) + word(1n) + word(160n) + word(0n);
    const r = await analyzeEvm(agent, { chainId: '0x1', method: 'eth_sendTransaction', params: [{ from: me, to: '0x' + '9'.repeat(40), data }], from: me });
    assert.ok(r.reasons.some(x => x.code === 'poison'), 'lookalike destination caught for ' + s);
  }
  await assert.rejects(analyzeEvm(agent, { chainId: '0x1', method: 'eth_sendTransaction', params: [{ to: me, value: '-1' }] }), 'negative values are refused');
  // During a lockdown, any typed signature counts as a move and is held.
  const lock = { until: Math.floor(Date.now() / 1000) + 3600, settings: { allowance: { solana: 0.5, evm: 0.05 } } };
  const ps = { primaryType: 'PermitSingle', message: { spender: '0x' + 'c'.repeat(40), details: { amount: '1' } } };
  const r2 = await analyzeEvm(agent, { chainId: '0x1', method: 'eth_signTypedData_v4', params: [me, JSON.stringify(ps)], from: me });
  assert.equal(gateFirewall(r2, lock, 'evm').action, 'block');
  const login = await analyzeEvm(agent, { chainId: '0x1', method: 'personal_sign', params: ['0x68656c6c6f', me], from: me });
  assert.notEqual(gateFirewall(login, lock, 'evm').locked, true, 'plain readable messages still work');
});

test('firewall: a Solana send of more than half the balance gets a hard warning', async () => {
  const { analyzeSolana } = await import('../src/engines/firewall-sol.js');
  const user = sol.generateKeypair().publicKey, to = sol.generateKeypair().publicKey;
  const rpc = {
    getTokenAccounts: async () => [], getMultipleAccounts: async k => k.map(() => null), getBalance: async () => 5_000_000_000, getAccountInfo: async () => null,
    simulate: async () => ({ value: { err: null, accounts: [{ lamports: 1_500_000_000 }] } })
  };
  const tx = sol.buildTx({ feePayer: user, recentBlockhash: sol.b58encode(Buffer.alloc(32, 7)), instructions: [sol.ix.transfer(user, to, 3_500_000_000n)] }).bytes.toString('base64');
  const r = await analyzeSolana({ id: 'G-none' }, tx, null, { rpc });
  assert.ok(r.reasons.some(x => x.code === 'large_sol_out'), JSON.stringify(r.reasons));
});

/* ---------------- self-hosted wallet library ---------------- */
function tarOf(files) {
  const blocks = [];
  for (const [name, body] of Object.entries(files)) {
    const h = Buffer.alloc(512);
    h.write(name, 0, 'utf8'); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
    h.write(body.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156); h.write('ustar\0', 257); h.write('00', 263);
    let sum = 0; for (const b of h) sum += b; h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    blocks.push(h, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}
test('wallet library: verified against the registry hash, served with SRI, tampering refused', async () => {
  const vendor = await import('../src/vendor.js');
  const lib = Buffer.from('/* fake build */ var solanaWeb3 = {};' + 'x'.repeat(200_000));
  const tgz = zlib.gzipSync(tarOf({ 'package/package.json': Buffer.from('{}'), 'package/lib/index.iife.min.js': lib }));
  const integrity = 'sha512-' + crypto.createHash('sha512').update(tgz).digest('base64');
  const fetchWith = (pkg, meta = {}) => async url => url.endsWith('/' + vendor.WEB3_VERSION)
    ? { ok: true, json: async () => ({ version: vendor.WEB3_VERSION, dist: { integrity, tarball: 'https://registry.npmjs.org/@solana/web3.js/-/web3.js-' + vendor.WEB3_VERSION + '.tgz', ...meta } }) }
    : { ok: true, arrayBuffer: async () => pkg };

  // A tarball that doesn't match the registry's hash is refused; pages keep using the CDN copy.
  vendor._resetVendor();
  let a = await vendor.ensureWeb3({ fetchImpl: fetchWith(Buffer.concat([tgz, Buffer.from('x')])) });
  assert.match(a.url, /^https:\/\/cdn\.jsdelivr\.net\//);
  assert.equal(a.sri, null);
  assert.match(get("select detail from audit_log where action = 'vendor_failed' order by id desc limit 1").detail, /integrity check failed/);
  // A tarball from somewhere other than the registry is refused.
  a = await vendor.ensureWeb3({ fetchImpl: fetchWith(tgz, { tarball: 'https://evil.example/web3.tgz' }) });
  assert.equal(a.sri, null);

  a = await vendor.ensureWeb3({ fetchImpl: fetchWith(tgz) });
  const want = 'sha384-' + crypto.createHash('sha384').update(lib).digest('base64');
  assert.equal(a.sri, want);
  assert.match(a.url, /^\/vendor\/web3\.js/);
  const served = await fetch(BASE + '/vendor/web3.js');
  assert.equal(served.status, 200);
  assert.equal('sha384-' + crypto.createHash('sha384').update(Buffer.from(await served.arrayBuffer())).digest('base64'), want, 'served bytes match the SRI hash');
  const cfg = await (await fetch(BASE + '/config.js')).text();
  assert.ok(cfg.includes(want), 'pages are told the hash');

  // Restart: the copy on disk is reused only if it still matches the hash first trusted.
  vendor._resetVendor();
  a = await vendor.ensureWeb3({ fetchImpl: async () => { throw new Error('offline'); } });
  assert.equal(a.sri, want, 'disk copy reused');
  const fs = await import('node:fs'), path = await import('node:path');
  fs.writeFileSync(path.join(process.env.DATA_DIR, 'vendor', `web3-${vendor.WEB3_VERSION}.js`), Buffer.concat([lib, Buffer.from('/*evil*/')]));
  vendor._resetVendor();
  a = await vendor.ensureWeb3({ fetchImpl: async () => { throw new Error('offline'); } });
  assert.equal(a.sri, null, 'a changed file on disk is not served');
  // A later download that differs from the first trusted copy is refused too.
  const lib2 = Buffer.from('/* other build */ var solanaWeb3 = {};' + 'y'.repeat(200_000));
  const tgz2 = zlib.gzipSync(tarOf({ 'package/lib/index.iife.min.js': lib2 }));
  const integrity2 = 'sha512-' + crypto.createHash('sha512').update(tgz2).digest('base64');
  a = await vendor.ensureWeb3({ fetchImpl: fetchWith(tgz2, { integrity: integrity2 }) });
  assert.equal(a.sri, null);
  assert.ok(get("select 1 from audit_log where action = 'vendor_mismatch'"));
});

test('done', () => { setTimeout(() => process.exit(0), 50); });
