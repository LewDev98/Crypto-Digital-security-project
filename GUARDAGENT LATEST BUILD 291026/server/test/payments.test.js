import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
const sol = await import('../src/lib/solana.js');
process.env.PORT = String(30000 + Math.floor(Math.random() * 20000));
process.env.PUBLIC_URL = `http://localhost:${process.env.PORT}`;
process.env.SOLANA_RPC_URL = 'http://mock-rpc.local';
process.env.GUARD_MINT = sol.generateKeypair().publicKey;
process.env.TREASURY_WALLET = sol.generateKeypair().publicKey;
const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const treasuryUsdc = sol.ata(process.env.TREASURY_WALLET, USDC);

const buyer = sol.generateKeypair().publicKey;
const SIG_RANK = '5'.repeat(88), SIG_SVC_SOL = '6'.repeat(88), SIG_SVC_USDC = '7'.repeat(88), SIG_SVC_WRONG_DEST = '8'.repeat(88);
const ix = {
  sol: lamports => ({ program: 'system', programId: sol.PROGRAMS.SYSTEM, parsed: { type: 'transfer', info: { source: buyer, destination: process.env.TREASURY_WALLET, lamports } } }),
  usdc: (amount, destination = treasuryUsdc) => ({ program: 'spl-token', programId: sol.PROGRAMS.TOKEN, parsed: { type: 'transferChecked', info: { source: 'buyerUsdc', destination, mint: USDC, authority: buyer, tokenAmount: { amount: String(amount), decimals: 6 } } } }),
  burn: amount => ({ program: 'spl-token', programId: sol.PROGRAMS.TOKEN, parsed: { type: 'burnChecked', info: { account: 'x', mint: process.env.GUARD_MINT, authority: buyer, tokenAmount: { amount: String(amount), decimals: 6 } } } }),
  memo: text => ({ program: 'spl-memo', programId: sol.PROGRAMS.MEMO, parsed: text })
};
const TXS = {
  [SIG_RANK]: [ix.sol(750000000), ix.burn(1000000n * 10n ** 6n), ix.memo('bodyguard:rank:guardian')],
  [SIG_SVC_SOL]: [ix.sol(5_000_000_000), ix.burn(2500000n * 10n ** 6n), ix.memo('bodyguard:service:screening')],
  [SIG_SVC_USDC]: [ix.usdc(249_000_000), ix.burn(2500000n * 10n ** 6n), ix.memo('bodyguard:service:screening')],
  [SIG_SVC_WRONG_DEST]: [ix.usdc(249_000_000, sol.generateKeypair().publicKey), ix.burn(2500000n * 10n ** 6n), ix.memo('bodyguard:service:screening')]
};

// Mock only the Solana RPC.
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  if (!String(url).startsWith('http://mock-rpc.local')) return realFetch(url, opts);
  const { method, params } = JSON.parse(opts.body);
  const reply = result => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { headers: { 'content-type': 'application/json' } });
  if (method === 'getAccountInfo') return reply({ value: { data: { parsed: { info: { decimals: 6 } } } } });
  if (method === 'getTransaction') {
    const ins = TXS[params[0]];
    return reply(ins ? { slot: 10, blockTime: Math.floor(Date.now() / 1000), meta: { err: null }, transaction: { message: { accountKeys: [{ pubkey: buyer, signer: true, writable: true }], instructions: ins } } } : null);
  }
  return reply(null);
};

await import('../src/index.js');
await new Promise(r => setTimeout(r, 300));
const post = (path, body) => fetch(process.env.PUBLIC_URL + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then(async r => ({ status: r.status, json: await r.json() }));

test('agent ranks: SOL payment verified on-chain, agent created once', async () => {
  const r = await post('/api/hire', { signature: SIG_RANK, wallet: buyer, kind: 'rank', id: 'guardian' });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.match(r.json.agentId, /^G-\d{4}$/);
  assert.equal((await post('/api/hire', { signature: SIG_RANK, wallet: buyer, kind: 'rank', id: 'guardian' })).status, 400, 'a signature can only be used once');
});

test('business services: paid in USDC to the treasury, SOL is not accepted', async () => {
  const withSol = await post('/api/hire', { signature: SIG_SVC_SOL, wallet: buyer, kind: 'service', id: 'screening' });
  assert.equal(withSol.status, 400);
  assert.match(withSol.json.error, /USDC/);
  const wrongDest = await post('/api/hire', { signature: SIG_SVC_WRONG_DEST, wallet: buyer, kind: 'service', id: 'screening' });
  assert.equal(wrongDest.status, 400, 'USDC sent anywhere other than the treasury does not count');
  const ok = await post('/api/hire', { signature: SIG_SVC_USDC, wallet: buyer, kind: 'service', id: 'screening' });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.match(ok.json.orgId, /^org_/);
  setTimeout(() => process.exit(0), 50);
});
