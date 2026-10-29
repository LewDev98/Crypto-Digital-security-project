// Edge cases for the decision engines: duress gate, Safe decoding, freeze text, evidence receipts, settings.
import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
const { gateFirewall, cleanSettings, weakens, DEFAULT_SETTINGS } = await import('../src/duress.js');
const { safeTxSummary } = await import('../src/monitors/treasury.js');
const { requestText, buildManifest, signReceipt, receiptMessage, evidencePublicKey, validTxHash } = await import('../src/freeze.js');
const { verifyEd25519 } = await import('../src/lib/solana.js');
const { b58decode } = await import('../src/lib/base58.js');
const { evaluatePolicy, validatePolicy } = await import('../src/engines/policy.js');

const lock = { until: Math.floor(Date.now() / 1000) + 3600, settings: { ...DEFAULT_SETTINGS, allowance: { solana: 0.1, evm: 0.01 } } };
test('duress gate: small plain sends pass, everything else is held, unknowns fail closed', () => {
  const ok = gateFirewall({ action: 'allow', reasons: [], summary: ['Sends 0.05 SOL to Abcd…wxyz'], flows: { nativeOut: 0.05, simulated: true } }, lock, 'solana');
  assert.notEqual(ok.locked, true);
  const big = gateFirewall({ action: 'allow', reasons: [], summary: [], flows: { nativeOut: 2, simulated: true } }, lock, 'solana');
  assert.equal(big.locked, true, 'outflow found only by simulation is still caught');
  const unsim = gateFirewall({ action: 'allow', reasons: [], summary: ['Sends 0.01 SOL to x'], flows: { nativeOut: 0.01, simulated: false } }, lock, 'solana');
  assert.equal(unsim.locked, true, 'unsimulated Solana tx is held');
  const swap = gateFirewall({ action: 'allow', reasons: [], summary: [], flows: { nativeOut: 0, simulated: true, tokenOut: true } }, lock, 'solana');
  assert.equal(swap.locked, true, 'token outflow is held');
  const contract = gateFirewall({ action: 'allow', reasons: [], summary: [], flows: { nativeOut: 0, contractCall: true } }, lock, 'evm');
  assert.equal(contract.locked, true, 'any contract call is held on EVM');
  const sign = gateFirewall({ action: 'allow', reasons: [], summary: [], flows: { nativeOut: 0 } }, lock, 'evm');
  assert.notEqual(sign.locked, true, 'plain message signing still works');
  assert.equal(gateFirewall({ action: 'allow', reasons: [], summary: [] }, { until: 0 }, 'evm').locked, undefined, 'no lock, no change');
});

test('duress settings: validation and what counts as weakening', () => {
  assert.throws(() => cleanSettings({ coolingHours: 0 }));
  assert.throws(() => cleanSettings({ coolingHours: 500 }));
  assert.throws(() => cleanSettings({ allowance: { solana: -1 } }));
  const s = cleanSettings({ name: 'Al<script>ice\n', message: 'a\u0000b' });
  assert.ok(!/[<>\n]/.test(s.name) && !/\u0000/.test(s.message));
  const cur = cleanSettings({});
  assert.equal(weakens(cur, cleanSettings({ coolingHours: 12 }, cur)), true);
  assert.equal(weakens(cur, cleanSettings({ allowance: { evm: 5 } }, cur)), true);
  assert.equal(weakens(cur, cleanSettings({ coolingHours: 48, allowance: { solana: 0 } }, cur)), false);
});

test('Safe decoding never throws on malformed proposals (a bad proposal must not stop Treasury Watch)', () => {
  const sel = '0xa9059cbb';
  for (const tx of [{ data: sel }, { data: sel + 'zz' }, { data: sel + '0'.repeat(64) }, { value: 'abc' }, { value: '-5' }, { value: null, data: null }, { dataDecoded: { method: 'multiSend' } }, {}]) {
    assert.doesNotThrow(() => safeTxSummary(tx), JSON.stringify(tx));
  }
  const good = safeTxSummary({ to: '0x' + '1'.repeat(40), data: sel + '0'.repeat(24) + '2'.repeat(40) + (1000n).toString(16).padStart(64, '0') });
  assert.equal(good.outs[0].amount, 1000);
  assert.equal(good.outs[0].to, '0x' + '2'.repeat(40));
  assert.equal(safeTxSummary({ dataDecoded: { method: 'addOwnerWithThreshold' } }).configChange, 'addOwnerWithThreshold');
});

test('evidence: manifest hash is reproducible and receipts verify; tampering breaks them', () => {
  const { text, hash } = buildManifest({ a: 1, b: 'x' });
  assert.equal(buildManifest(JSON.parse(text)).hash, hash);
  const at = '2026-10-23T10:00:00.000Z';
  const sig = signReceipt(hash, at);
  assert.ok(verifyEd25519(Buffer.from(receiptMessage(hash, at)), Buffer.from(b58decode(sig)), evidencePublicKey()));
  assert.ok(!verifyEd25519(Buffer.from(receiptMessage(hash, '2026-10-24T10:00:00.000Z')), Buffer.from(b58decode(sig)), evidencePublicKey()), 'a changed time fails');
  assert.ok(!verifyEd25519(Buffer.from(receiptMessage('b'.repeat(64), at)), Buffer.from(b58decode(sig)), evidencePublicKey()), 'a changed hash fails');
});

test('freeze request subjects can never carry a line break (mail header injection)', () => {
  const inc = { ref: 'BG-1', manifest_hash: 'a'.repeat(64), data: { manifest: { lockedAt: 'x', reporter: { name: 'n', email: 'e@x.y' }, incident: { amount: '1\r\nBcc: evil@x.y', asset: 'SOL\n' }, victimWallets: [], scammerAddresses: [], transactions: [], files: [] }, trace: {} } };
  const { subject } = requestText(inc, { name: 'Ex', kind: 'exchange' });
  assert.ok(!/[\r\n]/.test(subject));
  assert.equal(validTxHash('ethereum', '0x' + 'A'.repeat(64)), '0x' + 'a'.repeat(64));
  assert.equal(validTxHash('ethereum', '0x' + 'a'.repeat(63)), false || null);
  assert.equal(validTxHash('bitcoin', 'g'.repeat(64)), null);
});

test('policy engine: limits, lists and odd input', () => {
  const p = validatePolicy({ perTxLimit: 10, dailyLimit: 15, allowlist: 'A B', blocklist: ['C'] });
  assert.equal(evaluatePolicy(p, { chain: 'solana', to: 'A', amount: 5 }, []).decision, 'allow');
  assert.equal(evaluatePolicy(p, { chain: 'solana', to: 'A', amount: 11 }, []).decision, 'deny');
  assert.equal(evaluatePolicy(p, { chain: 'solana', to: 'Z', amount: 1 }, []).decision, 'deny', 'not on allowlist');
  assert.equal(evaluatePolicy(p, { chain: 'solana', to: 'A', amount: 6 }, [{ amount: 10, at: Math.floor(Date.now() / 1000) - 60 }]).decision, 'deny', 'daily limit');
  assert.equal(evaluatePolicy(p, { chain: 'solana', to: 'A', amount: -100 }, []).decision, 'deny', 'negative amounts are refused');
  assert.equal(evaluatePolicy(p, { chain: 'solana', to: 'A', amount: 'abc' }, []).decision, 'deny', 'non-numbers are refused');
  assert.throws(() => validatePolicy({ perTxLimit: -5 }));
});
