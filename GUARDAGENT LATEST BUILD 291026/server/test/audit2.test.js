// Second security audit: regression tests for every fix.
import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
process.env.PORT = String(30000 + Math.floor(Math.random() * 20000));
process.env.PUBLIC_URL = `http://localhost:${process.env.PORT}`;
process.env.HELIUS_API_KEY = 'k'; process.env.HELIUS_WEBHOOK_SECRET = 'x'.repeat(40);
const sol = await import('../src/lib/solana.js');
const { b58encode } = await import('../src/lib/base58.js');
const { grantRank, grantService } = await import('../src/payments.js');
const { run, get } = await import('../src/db.js');
await import('../src/index.js');
await new Promise(r => setTimeout(r, 300));
const BASE = process.env.PUBLIC_URL;
async function call(path, { method, body, token, headers = {}, raw } = {}) {
  const r = await fetch(BASE + path, { method: method || (body || raw ? 'POST' : 'GET'), headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}), ...headers }, body: raw ?? (body ? JSON.stringify(body) : undefined) });
  const text = await r.text(); let json; try { json = JSON.parse(text); } catch {}
  return { status: r.status, json, text };
}
async function signIn(kp) {
  const n = await call('/api/auth/nonce', { body: { wallet: kp.publicKey } });
  return (await call('/api/auth/verify', { body: { wallet: kp.publicKey, signature: b58encode(kp.sign(Buffer.from(n.json.message))) } })).json.token;
}
const alice = sol.generateKeypair(), mallory = sol.generateKeypair();
let ta, tm, agentId;

test('sign-in refuses giant signatures instantly (no CPU stall)', async () => {
  ta = await signIn(alice); tm = await signIn(mallory);
  await call('/api/auth/nonce', { body: { wallet: alice.publicKey } });
  const t0 = Date.now();
  const r = await call('/api/auth/verify', { body: { wallet: alice.publicKey, signature: '2'.repeat(200000) } });
  assert.equal(r.status, 400);
  assert.ok(Date.now() - t0 < 1000, 'answered quickly');
  const { b58decode } = await import('../src/lib/base58.js');
  assert.throws(() => b58decode('2'.repeat(5000)));
});

test('malformed transactions are rejected by the decoder, not looped over', () => {
  assert.throws(() => sol.decodeTx(Buffer.from([0xff, 0xff, 0x7f, ...Array(300).fill(0)])), /malformed/);
  assert.throws(() => sol.decodeTx(Buffer.from([1])), /malformed/);
  assert.throws(() => sol.decodeTx(Buffer.alloc(5000)), /malformed/);
});

test('wallet_sendCalls: every call in the batch is checked, not just the first', async () => {
  agentId = grantRank(alice.publicKey, 'guardian').id;
  const safe = { to: '0x' + '2'.repeat(40), value: '0x0', data: '0x' };
  const evil = { to: '0x' + '3'.repeat(40), data: '0x095ea7b3' + '0'.repeat(24) + '4'.repeat(40) + 'f'.repeat(64) }; // unlimited approval
  run("insert into lists(name, data, updated_at) values('custom_evm', ?, 0) on conflict(name) do update set data = excluded.data", JSON.stringify(['0x' + '4'.repeat(40)]));
  (await import('../src/engines/lists.js'))._testHydrate();
  const r = await call('/api/firewall/evm', { token: ta, body: { agentId, chainId: '0x1', method: 'wallet_sendCalls', params: [{ from: '0x' + '1'.repeat(40), calls: [safe, safe, evil] }] } });
  assert.equal(r.json.action, 'block', 'the bad third call is caught');
  const big = await call('/api/firewall/evm', { token: ta, body: { agentId, chainId: '0x1', method: 'wallet_sendCalls', params: [{ calls: Array(30).fill(safe) }] } });
  assert.equal(big.json.action, 'block', 'oversized batches are held');
  const unread = await call('/api/firewall/evm', { token: ta, body: { agentId, chainId: '0x1', method: 'eth_sendTransaction', params: [{ to: '0x' + '2'.repeat(40), value: 'not-hex' }] } });
  assert.equal(unread.json.action, 'warn', 'unreadable requests warn instead of passing');
  const signTx = await call('/api/firewall/evm', { token: ta, body: { agentId, chainId: '0x1', method: 'eth_signTransaction', params: [evil] } });
  assert.equal(signTx.json.action, 'block', 'eth_signTransaction is checked like a send');
});

test('Solana: unreadable or oversized bundles never pass silently', async () => {
  const many = await call('/api/firewall/solana', { token: ta, body: { agentId, transactions: Array(11).fill('AAAA') } });
  assert.ok([400, 503].includes(many.status) || many.json.action === 'block');
  const notB64 = await call('/api/firewall/solana', { token: ta, body: { agentId, transactions: ['<script>'] } });
  assert.equal(notB64.status, 400);
});

test('Duress: browsers cannot be unpaired during a lockdown; PIN lockouts escalate', async () => {
  grantService(alice.publicKey, 'duress');
  await call('/api/duress/setup', { token: ta, body: { realPin: '1234', duressPin: '9999', settings: { decoyWallets: [{ chain: 'solana', address: mallory.publicKey }] } } });
  const c = await call(`/api/agent/${agentId}/pair-code`, { token: ta, body: {} });
  await call('/api/ext/pair', { body: { code: c.json.code } });
  const ext = (await call(`/api/agent/${agentId}/extensions`, { token: ta })).json.extensions[0];
  run('update duress set lockdown_until = ? where wallet = ?', Math.floor(Date.now() / 1000) + 3600, alice.publicKey);
  assert.equal((await call(`/api/agent/${agentId}/extensions/${ext.id}`, { token: ta, method: 'DELETE' })).status, 423);
  run('update duress set lockdown_until = 0 where wallet = ?', alice.publicKey);
  for (let i = 0; i < 5; i++) await call('/api/duress/vault', { token: ta, body: { pin: '0000' } });
  const r1 = get('select * from duress where wallet = ?', alice.publicKey);
  assert.equal(r1.lockouts, 1);
  run('update duress set blocked_until = 0 where wallet = ?', alice.publicKey);
  for (let i = 0; i < 5; i++) await call('/api/duress/vault', { token: ta, body: { pin: '0000' } });
  const r2 = get('select * from duress where wallet = ?', alice.publicKey);
  assert.equal(r2.lockouts, 2);
  assert.ok(r2.blocked_until - Date.now() / 1000 > 1700, 'second lockout is longer');
  // The duress PIN still works (and still raises the alarm) while locked out.
  assert.equal((await call('/api/duress/vault', { token: ta, body: { pin: '9999' } })).status, 200);
});

test('personal services stay personal: being added to someone else\'s org never exposes your cases', async () => {
  grantService(mallory.publicKey, 'freeze');
  const morg = get('select * from orgs where owner = ?', mallory.publicKey);
  run("insert or ignore into org_members(org_id, wallet, role) values(?,?,'member')", morg.id, alice.publicKey);
  run('update orgs set created_at = 0 where id = ?', morg.id); // make Mallory's org the oldest
  // Alice has no Freeze Desk of her own, so she can't file a case into Mallory's org.
  const body = { attest: true, victim: { name: 'Alice', email: 'a@example.com' }, description: 'Someone drained my wallet after a fake support chat.', scammerAddresses: [{ chain: 'ethereum', address: '0x' + 'a'.repeat(40) }] };
  assert.equal((await call('/api/freeze/incidents', { token: ta, body })).status, 402);
  const me = (await call('/api/me', { token: ta })).json;
  assert.equal(me.org.services.freeze.active, false, "Mallory's Freeze Desk is not shown as Alice's");
  // Alice's own duress service still works and her own org comes first.
  assert.equal(me.org.services.duress.active, true);
  // Org alerts can only be acknowledged by members of that exact org.
  run("insert into alerts(subject, severity, type, title, what, did, move, data, created_at) values(?, 'low', 't', 't', 'w', 'd', 'm', '{}', 0)", 'org:' + morg.id);
  const al = get("select id from alerts where subject = ?", 'org:' + morg.id).id;
  const stranger = await signIn(sol.generateKeypair());
  assert.equal((await call(`/api/alerts/${al}/ack`, { token: stranger, body: {} })).status, 403);
});

test('buying a lower rank never downgrades, and upgrades keep paid time', () => {
  const w = sol.generateKeypair().publicKey;
  const a = grantRank(w, 'detail');
  const before = get('select * from agents where id = ?', a.id);
  const b = grantRank(w, 'sentry');
  assert.equal(b.rank, 'detail', 'stays Security Detail');
  assert.ok(b.expires_at > before.expires_at, 'gets extra time instead');
  const w2 = sol.generateKeypair().publicKey;
  grantRank(w2, 'sentry');
  const up = grantRank(w2, 'guardian');
  assert.equal(up.rank, 'guardian');
  assert.ok(up.expires_at > Math.floor(Date.now() / 1000) + 30 * 86400, 'unused Sentry days carried over');
});

test('spam sweep only burns items flagged as junk', async () => {
  const { pickSweepItems } = await import('../src/engines/spam.js');
  const items = [
    { id: 'usdc', kind: 'token', mint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', spam: false },
    { id: 'fakeusdc', kind: 'token', mint: 'Fake111111111111111111111111111111111111111', spam: true },
    { id: 'emptyusdc', kind: 'empty', mint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', spam: true },
    { id: 'forcedusdc', kind: 'token', mint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', spam: true }
  ];
  const { chosen, skipped } = pickSweepItems(items, ['usdc', 'fakeusdc', 'emptyusdc', 'forcedusdc', 'gone']);
  assert.deepEqual(chosen.map(c => c.id), ['fakeusdc', 'emptyusdc']);
  assert.deepEqual(skipped.map(s => s.id).sort(), ['forcedusdc', 'gone', 'usdc']);
});

test('threat lists: bad downloads cannot wipe protection; admin domains survive refresh', async () => {
  const lists = await import('../src/engines/lists.js');
  run("insert into lists(name, data, updated_at) values('ofac_eth', ?, 0) on conflict(name) do update set data = excluded.data", JSON.stringify(Array.from({ length: 50 }, (_, i) => '0x' + String(i).padStart(40, '0'))));
  const realFetch = globalThis.fetch;
  globalThis.fetch = async url => new Response(String(url).includes('ETH') ? '<html>rate limited</html>' : String(url).includes('config.json') ? JSON.stringify({ blacklist: ['evil.example'], whitelist: [] }) : '');
  try { await lists.refreshLists(); } finally { globalThis.fetch = realFetch; }
  assert.equal(JSON.parse(get("select data from lists where name='ofac_eth'").data).length, 50, 'sanctions list kept');
  lists.addCustom('domain', ['drainer.example', 'not a domain']);
  globalThis.fetch = async url => new Response(String(url).includes('config.json') ? JSON.stringify({ blacklist: ['evil.example'], whitelist: [] }) : '');
  try { await lists.refreshLists(); } finally { globalThis.fetch = realFetch; }
  assert.ok(lists.isPhishingDomain('drainer.example'), 'admin-added domain survives the daily refresh');
  assert.equal(lists.isSanctioned('ethereum', undefined), false);
});

test('SSRF guard and inbox sender spoofing', async () => {
  const { isPrivateIp } = await import('../src/monitors/domains.js');
  for (const ip of ['127.0.0.1', '10.0.0.5', '169.254.169.254', '::1', '::ffff:10.0.0.1', 'fd12::1', '100.64.1.1', 'garbage']) assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700::1111']) assert.equal(isPrivateIp(ip), false, ip);
  const { classify } = await import('../src/monitors/inbox.js');
  const spoof = await classify({ from: '"security@coinbase.com" <x@evil.example>', subject: 'New sign-in from an unrecognized device', snippet: '', exchangeNotices: true });
  assert.equal(spoof.kind, 'phishing');
});

test('large bodies are refused before upload when not signed in', async () => {
  const big = 'x'.repeat(2_000_000);
  const r = await call('/api/freeze/incidents', { raw: JSON.stringify({ files: [{ data: big }] }) });
  assert.equal(r.status, 401);
  const h = await call('/hooks/helius', { raw: JSON.stringify([{ pad: big }]) });
  assert.equal(h.status, 401);
  const d = await call('/api/support/tickets', { raw: JSON.stringify({ message: 'x'.repeat(400_000) }) });
  assert.equal(d.status, 413, 'default body limit is small');
  setTimeout(() => process.exit(0), 50);
});
