import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
const sol = await import('../src/lib/solana.js');
const admin = sol.generateKeypair(), former = sol.generateKeypair();
process.env.ADMIN_WALLETS = admin.publicKey;
process.env.PORT = String(30000 + Math.floor(Math.random() * 20000));
process.env.PUBLIC_URL = `http://localhost:${process.env.PORT}`;

// A wallet that used to be an admin: it had a paid Sentry, then free access, and has now been removed from the list.
const { run, get } = await import('../src/db.js');
run("insert into agents(id, owner, rank, status, created_at, expires_at, settings) values('G-0001', ?, 'detail', 'active', 0, null, ?)", former.publicKey, JSON.stringify({ comp: true, compPrev: { rank: 'sentry', expires_at: 1999999999 } }));
run("insert into orgs(id, owner, name, services, created_at) values('org_old', ?, 'Old', ?, 0)", former.publicKey, JSON.stringify({ screening: { since: 0, expires: null, comp: true } }));

const { b58encode } = await import('../src/lib/base58.js');
await import('../src/index.js');
await new Promise(r => setTimeout(r, 300));
const call = (path, { body, token } = {}) => fetch(process.env.PUBLIC_URL + path, { method: body ? 'POST' : 'GET', headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }).then(async r => ({ status: r.status, json: await r.json() }));

test('admin wallet gets a free Security Detail and every business service, with no expiry', async () => {
  const n = await call('/api/auth/nonce', { body: { wallet: admin.publicKey } });
  const token = (await call('/api/auth/verify', { body: { wallet: admin.publicKey, signature: b58encode(admin.sign(Buffer.from(n.json.message))) } })).json.token;
  const me = (await call('/api/me', { token })).json;
  assert.equal(me.admin, true);
  assert.equal(me.agents.length, 1);
  assert.equal(me.agents[0].rank, 'detail');
  assert.equal(me.agents[0].active, true);
  assert.equal(me.agents[0].expiresAt, null);
  for (const s of ['wallets', 'treasury', 'screening', 'drills']) assert.equal(me.org.services[s].active, true, s);
  assert.equal((await call('/api/org/keys', { token, body: { label: 'admin' } })).status, 200, 'business consoles open without paying');
});

test('free access ends when a wallet is removed from ADMIN_WALLETS, and paid time is given back', async () => {
  const a = get("select * from agents where id = 'G-0001'");
  assert.equal(a.rank, 'sentry');
  assert.equal(a.expires_at, 1999999999);
  const o = JSON.parse(get("select services from orgs where id = 'org_old'").services);
  assert.ok(o.screening.expires && o.screening.expires <= Math.floor(Date.now() / 1000));
  setTimeout(() => process.exit(0), 50);
});
