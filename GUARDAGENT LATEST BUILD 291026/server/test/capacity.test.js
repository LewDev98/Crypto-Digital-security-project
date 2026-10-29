import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
process.env.PORT = String(30000 + Math.floor(Math.random() * 20000));
process.env.PUBLIC_URL = `http://localhost:${process.env.PORT}`;
process.env.MAX_WALLETS = '3';
process.env.HIRE_RESERVE = '2';
process.env.RPC_ETHEREUM = 'http://mock-evm.local';

// Mock an Ethereum RPC and count how often balances are read.
const calls = {};
let block = 100;
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  if (!String(url).startsWith('http://mock-evm.local')) return realFetch(url, opts);
  const { method } = JSON.parse(opts.body);
  calls[method] = (calls[method] || 0) + 1;
  const result = { eth_blockNumber: '0x' + (block++).toString(16), eth_getLogs: [], eth_getBalance: '0x0', eth_getTransactionCount: '0x0' }[method] ?? null;
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { headers: { 'content-type': 'application/json' } });
};

const sol = await import('../src/lib/solana.js');
const { b58encode } = await import('../src/lib/base58.js');
const { grantRank } = await import('../src/payments.js');
const { pollEvm } = await import('../src/monitors/evm.js');
const { kvSet } = await import('../src/db.js');
await import('../src/index.js');
await new Promise(r => setTimeout(r, 300));
const BASE = process.env.PUBLIC_URL;
const call = (path, { body, token } = {}) => fetch(BASE + path, { method: body ? 'POST' : 'GET', headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined }).then(async r => ({ status: r.status, json: await r.json() }));
async function signIn(kp) {
  const n = await call('/api/auth/nonce', { body: { wallet: kp.publicKey } });
  return (await call('/api/auth/verify', { body: { wallet: kp.publicKey, signature: b58encode(kp.sign(Buffer.from(n.json.message))) } })).json.token;
}

test('wallet cap: sold out for new customers, renewals still open, adds refused past the cap', async () => {
  const a = sol.generateKeypair(), stranger = sol.generateKeypair();
  assert.equal((await call('/api/capacity')).json.open, true);
  const agent = grantRank(a.publicKey, 'guardian');
  const token = await signIn(a);
  const add = v => call(`/api/agent/${agent.id}/assets`, { token, body: { type: 'wallet', chain: 'ethereum', value: v } });
  assert.equal((await add('0x' + '1'.repeat(40))).status, 200);
  assert.equal((await add('0x' + '2'.repeat(40))).status, 200);
  // 1 slot left, reserve is 2: new customers see sold out, the existing customer can still renew.
  assert.equal((await call('/api/capacity')).json.open, false);
  assert.equal((await call('/api/capacity?wallet=' + stranger.publicKey)).json.open, false);
  assert.equal((await call('/api/capacity?wallet=' + a.publicKey)).json.open, true);
  assert.equal((await add('0x' + '3'.repeat(40))).status, 200);
  const over = await add('0x' + '4'.repeat(40));
  assert.equal(over.status, 403);
  assert.match(over.json.error, /full capacity/);
  // Email and domains are not capped.
  assert.equal((await call(`/api/agent/${agent.id}/assets`, { token, body: { type: 'email', value: 'me@example.com' } })).status, 200);
});

test('EVM balances are checked every EVM_BALANCE_SECONDS, not on every poll', async () => {
  calls.eth_getBalance = 0; calls.eth_getLogs = 0;
  kvSet('evm:bal:ethereum', 0);
  await pollEvm();
  const afterFirst = calls.eth_getBalance;
  assert.equal(afterFirst, 3, 'one balance read per watched EVM wallet');
  await pollEvm();
  await pollEvm();
  assert.equal(calls.eth_getBalance, afterFirst, 'no balance reads inside the 10-minute window');
  assert.ok(calls.eth_getLogs >= 9, 'token and approval checks still run on every poll');
  setTimeout(() => process.exit(0), 50);
});
