// Races and payment edge cases: double-spends, replays, forged memos, wrong payers, parallel brute force.
import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
const sol = await import('../src/lib/solana.js');
process.env.PORT = String(30000 + Math.floor(Math.random() * 20000));
process.env.PUBLIC_URL = `http://localhost:${process.env.PORT}`;
process.env.SOLANA_RPC_URL = 'http://mock-rpc.local';
process.env.GUARD_MINT = sol.generateKeypair().publicKey;
process.env.TREASURY_WALLET = sol.generateKeypair().publicKey;
const MINT = process.env.GUARD_MINT, TREASURY = process.env.TREASURY_WALLET;
const buyer = sol.generateKeypair(), thief = sol.generateKeypair();
const now = () => Math.floor(Date.now() / 1000);
const ix = {
  sol: (lamports, source = buyer.publicKey, destination = TREASURY) => ({ program: 'system', programId: sol.PROGRAMS.SYSTEM, parsed: { type: 'transfer', info: { source, destination, lamports } } }),
  burn: (amount, authority = buyer.publicKey, mint = MINT) => ({ program: 'spl-token', programId: sol.PROGRAMS.TOKEN, parsed: { type: 'burnChecked', info: { account: 'x', mint, authority, tokenAmount: { amount: String(amount), decimals: 6 } } } }),
  memo: text => ({ program: 'spl-memo', programId: sol.PROGRAMS.MEMO, parsed: text })
};
const G = 10n ** 6n;
const sig = n => String(n).padStart(2, '0').replace(/0/g, 'z').repeat(44);
const TX = {};
const def = (n, ins, extra = {}) => { const s = sig(n); TX[s] = { ins, ...extra }; return s; };
const OK_RANK = def(11, [ix.sol(250_000_000), ix.burn(500000n * G), ix.memo('bodyguard:rank:sentry')]);
const SPLIT = def(12, [ix.sol(100_000_000), ix.sol(150_000_000), ix.burn(200000n * G), ix.burn(300000n * G), ix.memo('bodyguard:rank:sentry')]);
const UNDERPAY = def(13, [ix.sol(250_000_000), ix.burn(500000n * G), ix.memo('bodyguard:rank:detail')]);
const MEMO_TRAIL = def(14, [ix.sol(1_000_000_000), ix.burn(2000000n * G), ix.memo('bodyguard:rank:detail x')]);
const MEMO_OTHER_ITEM = def(15, [ix.sol(1_000_000_000), ix.burn(2000000n * G), ix.memo('bodyguard:rank:sentry')]);
const FAILED = def(16, [ix.sol(250_000_000), ix.burn(500000n * G), ix.memo('bodyguard:rank:sentry')], { err: { InstructionError: [0, 'x'] } });
const OLD = def(17, [ix.sol(250_000_000), ix.burn(500000n * G), ix.memo('bodyguard:rank:sentry')], { blockTime: now() - 8 * 86400 });
const OTHER_BURNER = def(18, [ix.sol(250_000_000), ix.burn(500000n * G, thief.publicKey), ix.memo('bodyguard:rank:sentry')]);
const OTHER_SOURCE = def(19, [ix.sol(250_000_000, thief.publicKey), ix.burn(500000n * G), ix.memo('bodyguard:rank:sentry')]);
const WRONG_MINT = def(21, [ix.sol(250_000_000), ix.burn(500000n * G, buyer.publicKey, sol.generateKeypair().publicKey), ix.memo('bodyguard:rank:sentry')]);
const NOT_SIGNER = def(22, [ix.sol(250_000_000), ix.burn(500000n * G), ix.memo('bodyguard:rank:sentry')], { payerSigner: false });
const UNPRICED = def(23, [ix.burn(1n), ix.memo('bodyguard:service:duress')]);
const RACE = def(24, [ix.sol(250_000_000), ix.burn(500000n * G), ix.memo('bodyguard:rank:sentry')]);

const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  if (!String(url).startsWith('http://mock-rpc.local')) return realFetch(url, opts);
  const { method, params } = JSON.parse(opts.body);
  const reply = result => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { headers: { 'content-type': 'application/json' } });
  if (method === 'getAccountInfo') return reply({ value: { data: { parsed: { info: { decimals: 6 } } } } });
  if (method === 'getTransaction') {
    const t = TX[params[0]];
    await new Promise(r => setTimeout(r, 20)); // make the race window real
    return reply(t ? { slot: 10, blockTime: t.blockTime ?? now(), meta: { err: t.err ?? null }, transaction: { message: { accountKeys: [{ pubkey: buyer.publicKey, signer: t.payerSigner ?? true, writable: true }], instructions: t.ins } } } : null);
  }
  return reply(null);
};
const { b58encode } = await import('../src/lib/base58.js');
const { get, all, run } = await import('../src/db.js');
await import('../src/index.js');
await new Promise(r => setTimeout(r, 300));
const BASE = process.env.PUBLIC_URL;
async function call(path, { method, body, token } = {}) {
  const r = await fetch(BASE + path, { method: method || (body ? 'POST' : 'GET'), headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text(); let json; try { json = JSON.parse(text); } catch {}
  return { status: r.status, json };
}
const hire = (signature, wallet = buyer.publicKey, id = 'sentry', kind = 'rank') => call('/api/hire', { body: { signature, wallet, kind, id } });

test('a valid payment hires once; split instructions add up', async () => {
  const r = await hire(OK_RANK);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal((await hire(SPLIT)).status, 200);
});

test('20 parallel claims of one payment: exactly one succeeds (no double-spend)', async () => {
  const fresh = sol.generateKeypair();
  TX[RACE].ins = [ix.sol(250_000_000, fresh.publicKey), ix.burn(500000n * G, fresh.publicKey), ix.memo('bodyguard:rank:sentry')];
  // the mock's payer is `buyer`, so point it at the fresh wallet for this signature
  const origPayer = buyer.publicKey; buyer.publicKey = fresh.publicKey;
  const results = await Promise.all(Array.from({ length: 20 }, () => hire(RACE, fresh.publicKey)));
  buyer.publicKey = origPayer;
  assert.equal(results.filter(r => r.status === 200).length, 1, results.map(r => r.status).join(','));
  assert.equal(all('select * from payments where signature = ?', RACE).length, 1);
  const a = get('select * from agents where owner = ?', fresh.publicKey);
  assert.ok(a.expires_at - now() <= 30 * 86400 + 5, 'credited 30 days once, not twenty times');
});

test('forged, failed, stale and borrowed payments are refused', async () => {
  (await import('../src/http.js'))._resetRateLimits();
  const cases = { UNDERPAY: [UNDERPAY, 'detail'], MEMO_TRAIL: [MEMO_TRAIL, 'detail'], MEMO_OTHER_ITEM: [MEMO_OTHER_ITEM, 'detail'], FAILED: [FAILED, 'sentry'], OLD: [OLD, 'sentry'],
    OTHER_BURNER: [OTHER_BURNER, 'sentry'], OTHER_SOURCE: [OTHER_SOURCE, 'sentry'], WRONG_MINT: [WRONG_MINT, 'sentry'], NOT_SIGNER: [NOT_SIGNER, 'sentry'] };
  for (const [name, [s, id]] of Object.entries(cases)) {
    const r = await hire(s, buyer.publicKey, id);
    assert.equal(r.status, 400, `${name} should be refused, got ${r.status} ${JSON.stringify(r.json)}`);
  }
  // Someone else claiming the buyer's (unused) payment for their own wallet.
  const fresh = def(25, [ix.sol(250_000_000), ix.burn(500000n * G), ix.memo('bodyguard:rank:sentry')]);
  assert.equal((await hire(fresh, thief.publicKey)).status, 400);
  // Unpriced services can't be bought at any price.
  assert.equal((await hire(UNPRICED, buyer.publicKey, 'duress', 'service')).status, 400);
  // Replaying an already-used payment.
  assert.equal((await hire(OK_RANK)).status, 400);
  assert.equal(get("select count(*) n from payments").n, 3);
});

test('parallel PIN guessing still locks out after five wrong tries', async () => {
  const { grantService } = await import('../src/payments.js');
  const n = await call('/api/auth/nonce', { body: { wallet: buyer.publicKey } });
  const token = (await call('/api/auth/verify', { body: { wallet: buyer.publicKey, signature: b58encode(buyer.sign(Buffer.from(n.json.message))) } })).json.token;
  grantService(buyer.publicKey, 'duress');
  await call('/api/duress/setup', { token, body: { realPin: '4321', duressPin: '8765', settings: { decoyWallets: [{ chain: 'solana', address: thief.publicKey }] } } });
  const guesses = await Promise.all(Array.from({ length: 15 }, (_, i) => call('/api/duress/vault', { token, body: { pin: String(1000 + i) } })));
  assert.equal(guesses.filter(g => g.status === 401).length, 5, guesses.map(g => g.status).join(','));
  // Even the right PIN is refused during the lockout…
  assert.equal((await call('/api/duress/vault', { token, body: { pin: '4321' } })).status, 429);
  // …but the duress PIN still raises the alarm.
  assert.equal((await call('/api/duress/vault', { token, body: { pin: '8765' } })).status, 200);
});

test('a pairing code works exactly once under parallel use', async () => {
  const n = await call('/api/auth/nonce', { body: { wallet: buyer.publicKey } });
  const token = (await call('/api/auth/verify', { body: { wallet: buyer.publicKey, signature: b58encode(buyer.sign(Buffer.from(n.json.message))) } })).json.token;
  const agent = get('select id from agents where owner = ?', buyer.publicKey).id;
  run('update duress set lockdown_until = 0 where wallet = ?', buyer.publicKey);
  const code = (await call(`/api/agent/${agent}/pair-code`, { token, body: {} })).json.code;
  const r = await Promise.all(Array.from({ length: 10 }, () => call('/api/ext/pair', { body: { code } })));
  assert.equal(r.filter(x => x.status === 200).length, 1);
  setTimeout(() => process.exit(0), 50);
});
