import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
process.env.PORT = String(30000 + Math.floor(Math.random() * 20000));
process.env.PUBLIC_URL = `http://localhost:${process.env.PORT}`;

const sol = await import('../src/lib/solana.js');
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
const kp = sol.generateKeypair();
let token, agentId;

test('wallet sign-in with a real ed25519 signature', async () => {
  const n = await call('/api/auth/nonce', { body: { wallet: kp.publicKey } });
  assert.equal(n.status, 200);
  const bad = await call('/api/auth/verify', { body: { wallet: kp.publicKey, signature: b58encode(crypto.randomBytes(64)) } });
  assert.equal(bad.status, 401);
  const n2 = await call('/api/auth/nonce', { body: { wallet: kp.publicKey } });
  const v = await call('/api/auth/verify', { body: { wallet: kp.publicKey, signature: b58encode(kp.sign(Buffer.from(n2.json.message))) } });
  assert.equal(v.status, 200);
  token = v.json.token;
  const me = await call('/api/me', { token });
  assert.equal(me.json.wallet, kp.publicKey);
  assert.equal(me.json.agents.length, 0);
});

test('hiring creates an agent and rank limits are enforced', async () => {
  const a = grantRank(kp.publicKey, 'sentry');
  agentId = a.id;
  const me = await call('/api/me', { token });
  assert.equal(me.json.agents[0].id, agentId);
  assert.equal((await call(`/api/agent/${agentId}/assets`, { token, body: { type: 'wallet', chain: 'solana', value: kp.publicKey, label: 'Main' } })).status, 200);
  assert.equal((await call(`/api/agent/${agentId}/assets`, { token, body: { type: 'wallet', chain: 'base', value: '0x' + '1'.repeat(40) } })).status, 403, 'Sentry has no Base');
  assert.equal((await call(`/api/agent/${agentId}/assets`, { token, body: { type: 'domain', value: 'example.com' } })).status, 403, 'Sentry has no domains');
  assert.equal((await call(`/api/agent/${agentId}/assets`, { token, body: { type: 'wallet', chain: 'solana', value: 'not-an-address' } })).status, 400);
  assert.equal((await call(`/api/agent/${agentId}/assets`, { token, body: { type: 'email', value: 'me@example.com' } })).status, 200);
  // Upgrade unlocks more.
  grantRank(kp.publicKey, 'guardian');
  assert.equal((await call(`/api/agent/${agentId}/assets`, { token, body: { type: 'domain', value: 'https://www.Example.org/' } })).status, 200);
  const view = (await call(`/api/agent/${agentId}`, { token })).json;
  assert.equal(view.rank, 'guardian');
  assert.ok(view.assets.some(x => x.value === 'www.example.org'));
  // Someone else can't see it.
  const other = sol.generateKeypair();
  const n = await call('/api/auth/nonce', { body: { wallet: other.publicKey } });
  const t2 = (await call('/api/auth/verify', { body: { wallet: other.publicKey, signature: b58encode(other.sign(Buffer.from(n.json.message))) } })).json.token;
  assert.equal((await call(`/api/agent/${agentId}`, { token: t2 })).status, 403);
});

test('shield check finds a lookalike of a saved address', async () => {
  await call(`/api/agent/${agentId}/addresses`, { token, body: { chain: 'solana', address: '4kVj8HqTzN2mRw6pXcL9bY3sDfA7uE5gK1nPoZ8tWq3B', label: 'Kraken deposit' } });
  const r = await call('/api/shield/check', { token, body: { agentId, address: '4kVjNr5aGtY8hLmQ2dX7cP9vS3eB6wK4jFuTz1oRWq3B' } });
  assert.equal(r.json.verdict, 'lookalike');
  assert.equal(r.json.label, 'Kraken deposit');
});

test('extension pairs with a code and its firewall answers', async () => {
  const c = await call(`/api/agent/${agentId}/pair-code`, { token, body: {} });
  assert.match(c.json.code, /^\d{8}$/);
  const p = await call('/api/ext/pair', { body: { code: c.json.code } });
  assert.equal(p.status, 200);
  assert.equal((await call('/api/ext/pair', { body: { code: c.json.code } })).status, 400, 'codes are single-use');
  const ext = p.json.token;
  const me = await call('/api/ext/me', { token: ext });
  assert.equal(me.json.agentId, agentId);
  const fw = await call('/api/firewall/evm', { token: ext, body: { chainId: '0x1', method: 'eth_sign', params: [] } });
  assert.equal(fw.json.action, 'block');
  const sh = await call('/api/shield/check', { token: ext, body: { address: '4kVjNr5aGtY8hLmQ2dX7cP9vS3eB6wK4jFuTz1oRWq3B', event: 'paste', origin: 'https://example.net' } });
  assert.equal(sh.json.verdict, 'lookalike');
  await new Promise(r => setTimeout(r, 100));
  const alerts = (await call(`/api/agent/${agentId}/alerts`, { token })).json.alerts;
  assert.ok(alerts.some(a => a.type === 'firewall_block'));
  assert.ok(alerts.some(a => a.type === 'poison_paste'));
});

test('site config, RPC proxy guard and static files', async () => {
  const c = await call('/config.js');
  assert.match(c.text, /window\.BG_CONFIG/);
  assert.equal((await call('/api/rpc', { body: { method: 'getBalance', params: [] } })).status, 503);
  assert.equal((await call('/api/hire', { body: { wallet: kp.publicKey, kind: 'rank', id: 'sentry', signature: '1'.repeat(88) } })).status, 503, 'payments off without config');
  const app = await call('/app');
  assert.match(app.text, /Bodyguard Dashboard/);
  const home = await call('/');
  assert.match(home.text, /Bodyguard Agents/);
});

test('security fixes hold', async () => {
  // Path traversal out of the web folder is refused.
  const trav = await fetch(BASE + '/..%2fserver%2fpackage.json');
  assert.notEqual(trav.status, 200);
  const trav2 = await fetch(BASE + '/%2e%2e/web-secret/x');
  assert.notEqual(trav2.status, 200);
  // Pages carry anti-framing and the dashboard a strict CSP.
  const app = await fetch(BASE + '/app');
  assert.equal(app.headers.get('x-frame-options'), 'DENY');
  assert.match(app.headers.get('content-security-policy'), /connect-src 'self'/);
  // RPC proxy refuses expensive methods.
  assert.equal((await call('/api/rpc', { body: { method: 'getProgramAccounts', params: [] } })).status, 400);
  // Push only to real browser push services.
  assert.equal((await call(`/api/agent/${agentId}/push`, { token, body: { subscription: { endpoint: 'https://169.254.169.254/latest', keys: { p256dh: 'x', auth: 'y' } } } })).status, 400);
  assert.equal((await call(`/api/agent/${agentId}/push`, { token, body: { subscription: { endpoint: 'https://fcm.googleapis.com/fcm/send/abc', keys: { p256dh: 'x', auth: 'y' } } } })).status, 200);
  // Someone requesting a sign-in for your wallet can't cancel yours.
  const mine = await call('/api/auth/nonce', { body: { wallet: kp.publicKey } });
  await call('/api/auth/nonce', { body: { wallet: kp.publicKey } });
  const v = await call('/api/auth/verify', { body: { wallet: kp.publicKey, signature: b58encode(kp.sign(Buffer.from(mine.json.message))) } });
  assert.equal(v.status, 200);
  // Base64 signatures work too.
  const m2 = await call('/api/auth/nonce', { body: { wallet: kp.publicKey } });
  assert.equal((await call('/api/auth/verify', { body: { wallet: kp.publicKey, signature: Buffer.from(kp.sign(Buffer.from(m2.json.message))).toString('base64') } })).status, 200);
});

test('Risk Screening keys and API', async () => {
  assert.equal((await call('/api/org', { token })).status, 403);
  grantService(kp.publicKey, 'screening');
  const k = await call('/api/org/keys', { token, body: { label: 'test' } });
  assert.match(k.json.key, /^bg_live_/);
  run("insert into lists(name, data, updated_at) values('ofac_eth', ?, 0) on conflict(name) do update set data = excluded.data", JSON.stringify(['0x1111111111111111111111111111111111111111']));
  (await import('../src/engines/lists.js'))._testHydrate();
  const s = await call('/api/v1/screen', { headers: { 'x-api-key': k.json.key }, body: { chain: 'ethereum', address: '0x1111111111111111111111111111111111111111' } });
  assert.equal(s.json.score, 100);
  assert.equal((await call('/api/v1/screen', { headers: { 'x-api-key': 'bg_live_wrong' }, body: { chain: 'ethereum', address: '0x1' } })).status, 401);
});

test('Scam Drill: verified domains only, safe landing page, report', async () => {
  grantService(kp.publicKey, 'drills');
  const noDomain = await call('/api/org/drills', { token, body: { template: 'wallet_verify', channel: 'email', targets: ['alex@acme.test'], authorised: true } });
  assert.equal(noDomain.status, 400);
  const org = get('select * from orgs where owner = ?', kp.publicKey);
  run('update orgs set verified_domains = ? where id = ?', JSON.stringify(['acme.test']), org.id);
  const outside = await call('/api/org/drills', { token, body: { template: 'wallet_verify', channel: 'email', targets: ['someone@gmail.com'], authorised: true } });
  assert.equal(outside.status, 400);
  const noAuth = await call('/api/org/drills', { token, body: { template: 'wallet_verify', channel: 'email', targets: ['alex@acme.test'] } });
  assert.equal(noAuth.status, 400);
  const tg = await call('/api/org/drills', { token, body: { template: 'support_dm', channel: 'telegram', authorised: true, telegramChatId: '-1001234567890' } });
  assert.equal(tg.status, 400, 'Telegram drills only go to a group the org linked itself');
  const d = await call('/api/org/drills', { token, body: { name: 'Q4', template: 'wallet_verify', channel: 'email', targets: [{ email: 'alex@acme.test', name: 'Alex' }], authorised: true } });
  assert.equal(d.status, 200);
  const t = get('select token from drill_targets where drill_id = ?', d.json.id).token;
  const click = await call('/d/c/' + t, { headers: { 'user-agent': 'Mozilla/5.0' } });
  assert.equal(click.status, 302);
  const page = await call('/d/l/' + t);
  assert.match(page.text, /el\.value = ''/, 'landing page wipes inputs before sending');
  assert.doesNotMatch(page.text, /body: JSON\.stringify\(\{[^}]*value/, 'no field values are posted');
  await call('/d/s/' + t, { body: {} });
  const learn = await call('/learn/' + t + '?caught=1');
  assert.match(learn.text, /training drill/);
  const q = await call(`/learn/${t}/quiz`, { body: { answers: [1, 1, 1, 1, 0] } });
  assert.equal(q.json.score, 4);
  const rep = await call(`/api/org/drills/${d.json.id}/report`, { token });
  assert.equal(rep.json.stats.clicked, 1);
  assert.equal(rep.json.stats.submitted, 1);
  assert.equal(rep.json.stats.trained, 1);
  setTimeout(() => process.exit(0), 50);
});
