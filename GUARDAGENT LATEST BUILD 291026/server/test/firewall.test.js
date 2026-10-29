import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';

const sol = await import('../src/lib/solana.js');
const { run } = await import('../src/db.js');
const { learn } = await import('../src/engines/poison.js');
const { analyzeSolana } = await import('../src/engines/firewall-sol.js');
const { analyzeEvm } = await import('../src/engines/firewall-evm.js');
const { analyzeParsedTx, handleFindings } = await import('../src/monitors/solana.js');
const { safeTxSummary } = await import('../src/monitors/treasury.js');

const user = sol.generateKeypair().publicKey;
const mint = sol.generateKeypair().publicKey;
const tokenAcc = sol.ata(user, mint);
const REAL = '4kVj8HqTzN2mRw6pXcL9bY3sDfA7uE5gK1nPoZ8tWq3B';
const FAKE = '4kVjNr5aGtY8hLmQ2dX7cP9vS3eB6wK4jFuTz1oRWq3B';
const agent = { id: 'G-7001' };
run("insert into agents(id, owner, rank, status, created_at) values('G-7001', ?, 'guardian', 'active', 0)", user);
run("insert into assets(agent_id, type, chain, value, label, created_at) values('G-7001','wallet','solana',?,'Main',0)", user);
learn('G-7001', 'solana', REAL, { label: 'Kraken deposit', source: 'user' });
learn('G-7001', 'ethereum', '0xabcd111111111111111111111111111111119876', { label: 'Exchange', source: 'user' });

function tokenAccountB64(owner, amount, delegate = null) {
  const b = Buffer.alloc(165);
  Buffer.from(sol.toBytes(mint)).copy(b, 0); Buffer.from(sol.toBytes(owner)).copy(b, 32); b.writeBigUInt64LE(BigInt(amount), 64);
  if (delegate) { b.writeUInt32LE(1, 72); Buffer.from(sol.toBytes(delegate)).copy(b, 76); b.writeBigUInt64LE(BigInt(amount), 121); }
  b[108] = 1; return b.toString('base64');
}
function mockRpc({ postLamports = 4_000_000_000, postToken } = {}) {
  return {
    getTokenAccounts: async (o, pid) => pid === sol.PROGRAMS.TOKEN ? [{ pubkey: tokenAcc, account: { data: { parsed: { info: { mint, tokenAmount: { amount: '1000000', decimals: 6 } } } } } }] : [],
    getMultipleAccounts: async keys => keys.map(() => ({ data: [tokenAccountB64(FAKE, 0), 'base64'] })),
    getBalance: async () => 5_000_000_000,
    getAccountInfo: async () => null,
    simulate: async () => ({ value: { err: null, accounts: [{ lamports: postLamports }, { data: [postToken || tokenAccountB64(user, 1000000), 'base64'] }] } })
  };
}
const txB64 = instructions => sol.buildTx({ feePayer: user, recentBlockhash: sol.b58encode(Buffer.alloc(32, 7)), instructions }).bytes.toString('base64');

test('Solana firewall blocks a send to a poisoned lookalike', async () => {
  const r = await analyzeSolana(agent, txB64([sol.ix.transfer(user, FAKE, 1_000_000_000n)]), 'https://example.org', { rpc: mockRpc() });
  assert.equal(r.action, 'block');
  assert.ok(r.reasons.some(x => x.code === 'poison'));
});

test('Solana firewall allows a send to a saved address', async () => {
  const r = await analyzeSolana(agent, txB64([sol.ix.transfer(user, REAL, 1_000_000_000n)]), null, { rpc: mockRpc() });
  assert.equal(r.action, 'allow');
});

test('Solana firewall blocks unlimited token delegation and owner change found in simulation', async () => {
  const approve = { programId: sol.PROGRAMS.TOKEN, keys: [{ pubkey: tokenAcc, isSigner: false, isWritable: true }, { pubkey: FAKE, isSigner: false, isWritable: false }, { pubkey: user, isSigner: true, isWritable: false }], data: Buffer.concat([Buffer.from([4]), sol.u64le(2n ** 64n - 1n)]) };
  const r = await analyzeSolana(agent, txB64([approve]), null, { rpc: mockRpc({ postToken: tokenAccountB64(FAKE, 1000000) }) });
  assert.equal(r.action, 'block');
  assert.ok(r.reasons.some(x => x.code === 'approve'));
  assert.ok(r.reasons.some(x => x.code === 'owner_change'));
});

test('Solana firewall blocks a wallet drain seen in simulation', async () => {
  const r = await analyzeSolana(agent, txB64([sol.ix.transfer(user, REAL, 4_990_000_000n)]), null, { rpc: mockRpc({ postLamports: 10_000_000 }) });
  assert.equal(r.action, 'block');
  assert.ok(r.reasons.some(x => x.code === 'drain_sol'));
});

test('EVM firewall: blind signing, free Seaport listing, poisoned transfer, unknown unlimited approval', async () => {
  assert.equal((await analyzeEvm(agent, { chainId: '0x1', method: 'eth_sign', params: ['0x0', '0x' + 'ab'.repeat(32)] })).action, 'block');
  const me = '0x' + '5'.repeat(40);
  const order = { primaryType: 'OrderComponents', message: { offerer: me, offer: [{ itemType: 2, token: '0x' + '6'.repeat(40), identifierOrCriteria: '1' }], consideration: [{ recipient: '0x' + '7'.repeat(40), startAmount: '1' }] } };
  assert.equal((await analyzeEvm(agent, { chainId: 1, method: 'eth_signTypedData_v4', params: [me, JSON.stringify(order)], from: me })).action, 'block');
  const data = '0xa9059cbb' + '0'.repeat(24) + 'abcd999999999999999999999999999999999876' + '0'.repeat(63) + '1';
  const poisoned = await analyzeEvm(agent, { chainId: 1, method: 'eth_sendTransaction', params: [{ from: me, to: '0x' + '8'.repeat(40), data }] });
  assert.equal(poisoned.action, 'block');
  assert.ok(poisoned.reasons.some(r => r.code === 'poison'));
  const approve = '0x095ea7b3' + '0'.repeat(24) + '9'.repeat(40) + 'f'.repeat(64);
  const ap = await analyzeEvm(agent, { chainId: 1, method: 'eth_sendTransaction', params: [{ from: me, to: '0x' + '8'.repeat(40), data: approve }] });
  assert.equal(ap.action, 'warn');
  const known = '0x095ea7b3' + '0'.repeat(24) + '000000000022d473030f116ddee9f6b43ac78ba3' + 'f'.repeat(64);
  assert.equal((await analyzeEvm(agent, { chainId: 1, method: 'eth_sendTransaction', params: [{ from: me, to: '0x' + '8'.repeat(40), data: known }] })).action, 'allow');
});

test('Solana monitor turns real transaction shapes into the right alerts', async () => {
  const mk = (instructions, { signer = true, pre = 5_000_000_000, post = 4_999_995_000 } = {}) => ({
    meta: { err: null, preBalances: [pre], postBalances: [post], preTokenBalances: [], postTokenBalances: [], innerInstructions: [] },
    transaction: { message: { accountKeys: [{ pubkey: user, signer }], instructions } }
  });
  const got = [];
  const raise = async (id, a) => { got.push(a); return a; };
  const asset = { id: 1, value: user, label: 'Main', agent_id: 'G-7001' };
  // incoming dust from a lookalike -> poisoning alert
  const dust = mk([{ program: 'system', programId: sol.PROGRAMS.SYSTEM, parsed: { type: 'transfer', info: { source: FAKE.replace('4kVjN', '4kVjM'), destination: user, lamports: 1 } } }], { signer: false });
  await handleFindings('G-7001', asset, 'sig1', analyzeParsedTx(dust, user), raise);
  assert.ok(got.some(a => a.type === 'sol_poison_dust'));
  // sending to a lookalike -> critical
  got.length = 0;
  const send = mk([{ program: 'system', programId: sol.PROGRAMS.SYSTEM, parsed: { type: 'transfer', info: { source: user, destination: FAKE, lamports: 2_000_000_000 } } }]);
  await handleFindings('G-7001', asset, 'sig2', analyzeParsedTx(send, user), raise);
  assert.ok(got.some(a => a.type === 'sol_poison_send' && a.severity === 'crit'));
  // unlimited approval -> critical
  got.length = 0;
  const appr = mk([{ program: 'spl-token', programId: sol.PROGRAMS.TOKEN, parsed: { type: 'approve', info: { source: tokenAcc, delegate: FAKE, owner: user, amount: (2n ** 64n - 1n).toString() } } }]);
  await handleFindings('G-7001', asset, 'sig3', analyzeParsedTx(appr, user), raise);
  assert.ok(got.some(a => a.type === 'sol_approve' && a.severity === 'crit'));
  // normal send to a saved address -> quiet
  got.length = 0;
  const ok = mk([{ program: 'system', programId: sol.PROGRAMS.SYSTEM, parsed: { type: 'transfer', info: { source: user, destination: REAL, lamports: 2_000_000_000 } } }]);
  await handleFindings('G-7001', asset, 'sig4', analyzeParsedTx(ok, user), raise);
  assert.equal(got.length, 0);
});

test('Safe transaction summary spots owner changes and transfers', () => {
  assert.equal(safeTxSummary({ dataDecoded: { method: 'addOwnerWithThreshold' } }).configChange, 'addOwnerWithThreshold');
  const t = safeTxSummary({ to: '0x' + '1'.repeat(40), value: '1000000000000000000', data: null });
  assert.equal(t.outs[0].amount, 1);
});
