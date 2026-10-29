import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const { b58encode, b58decode } = await import('../src/lib/base58.js');
const { keccakHex, topic, selector } = await import('../src/lib/keccak.js');
const sol = await import('../src/lib/solana.js');
const { isLookalike, checkAddress, learn, inspectIncoming } = await import('../src/engines/poison.js');
const { checkPaymentTx } = await import('../src/payments.js');
const { classify } = await import('../src/engines/spam.js');
const { evaluatePolicy, validatePolicy } = await import('../src/engines/policy.js');
const { scoreFrom } = await import('../src/engines/risk.js');
const lists = await import('../src/engines/lists.js');
const { run } = await import('../src/db.js');
const { encryptPayload, generateVapidKeys } = await import('../src/lib/webpush.js');
const squads = await import('../src/lib/squads.js');

test('base58 and keccak match known vectors', () => {
  assert.equal(b58encode(Buffer.from('hello world')), 'StV1DL6CwTryKyV');
  assert.equal(b58decode('11111111111111111111111111111111').length, 32);
  assert.equal(keccakHex(''), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(topic('Transfer(address,address,uint256)'), '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef');
  assert.equal(selector('approve(address,uint256)'), '0x095ea7b3');
  assert.equal(selector('setApprovalForAll(address,bool)'), '0xa22cb465');
});

test('transactions compile, sign and decode back', () => {
  const payer = sol.generateKeypair(), other = sol.generateKeypair();
  const bh = b58encode(crypto.randomBytes(32));
  const mint = sol.generateKeypair().publicKey;
  const acct = sol.ata(payer.publicKey, mint);
  const tx = sol.buildTx({ feePayer: payer.publicKey, recentBlockhash: bh, instructions: [
    sol.ix.computeUnitPrice(1000), sol.ix.transfer(payer.publicKey, other.publicKey, 12345n),
    sol.ix.burnChecked(acct, mint, payer.publicKey, 5000000n, 6), sol.ix.memo('bodyguard:rank:guardian', payer.publicKey)
  ], partialSigners: [payer] });
  const d = sol.decodeTx(tx.bytes);
  assert.equal(d.version, 'legacy');
  assert.equal(d.recentBlockhash, bh);
  assert.equal(d.staticKeys[0], payer.publicKey);
  assert.equal(d.instructions.length, 4);
  assert.ok(sol.verifyEd25519(d.message, d.signatures[0], payer.publicKey), 'signature verifies over the message');
  const burn = d.instructions[2];
  assert.equal(burn.data[0], 15);
  assert.equal(Buffer.from(burn.data).readBigUInt64LE(1), 5000000n);
  assert.equal(burn.data[9], 6);
  assert.equal(d.header.numRequiredSignatures, 1);
});

test('PDA derivation lands off-curve and ATA is deterministic', () => {
  const owner = sol.generateKeypair().publicKey, mint = sol.generateKeypair().publicKey;
  const a1 = sol.ata(owner, mint), a2 = sol.ata(owner, mint);
  assert.equal(a1, a2);
  assert.equal(sol.isOnCurve(sol.toBytes(a1)), false);
  assert.equal(sol.isOnCurve(sol.toBytes(owner)), true);
});

test('lookalike detection', () => {
  const real = '4kVj8HqTzN2mRw6pXcL9bY3sDfA7uE5gK1nPoZ8tWq3B';
  assert.ok(isLookalike('4kVjNr5aGtY8hLmQ2dX7cP9vS3eB6wK4jFuTz1oRWq3B', real));
  assert.equal(isLookalike(real, real), null);
  assert.equal(isLookalike('Hd3sWq8mZ2xKv5TnBc7LpR4yFa9eJg6uN1oMt3PiE8rQ', real), null);
  assert.ok(isLookalike('0xAbCd111111111111111111111111111111119876', '0xabcd222222222222222222222222222222229876', 'ethereum'));
});

test('poison engine uses what the agent has learned', () => {
  run("insert into agents(id, owner, rank, status, created_at) values('G-9001','x','guardian','active',0)");
  learn('G-9001', 'solana', '4kVj8HqTzN2mRw6pXcL9bY3sDfA7uE5gK1nPoZ8tWq3B', { label: 'Kraken deposit', source: 'user' });
  assert.equal(checkAddress('G-9001', 'solana', '4kVj8HqTzN2mRw6pXcL9bY3sDfA7uE5gK1nPoZ8tWq3B').verdict, 'known');
  const r = checkAddress('G-9001', 'solana', '4kVjNr5aGtY8hLmQ2dX7cP9vS3eB6wK4jFuTz1oRWq3B');
  assert.equal(r.verdict, 'lookalike'); assert.equal(r.label, 'Kraken deposit');
  assert.ok(inspectIncoming('G-9001', 'solana', '4kVjNr5aGtY8hLmQ2dX7cP9vS3eB6wK4jFuTz1oRWq3B'));
  assert.equal(checkAddress('G-9001', 'solana', '4kVjNr5aGtY8hLmQ2dX7cP9vS3eB6wK4jFuTz1oRWq3B').verdict, 'poisoned');
  assert.equal(checkAddress('G-9001', 'solana', 'Hd3sWq8mZ2xKv5TnBc7LpR4yFa9eJg6uN1oMt3PiE8rQ').verdict, 'new');
});

test('payment verification accepts only the exact purchase', () => {
  const wallet = 'W1111111111111111111111111111111111111111', treasury = 'T1111111111111111111111111111111111111111', mint = 'M1111111111111111111111111111111111111111';
  const mk = ({ memo = 'bodyguard:rank:guardian', lamports = 500000000, burn = '1000000000000', signer = wallet, err = null } = {}) => ({
    slot: 1, blockTime: Math.floor(Date.now() / 1000), meta: { err },
    transaction: { message: { accountKeys: [{ pubkey: signer, signer: true }], instructions: [
      { program: 'system', parsed: { type: 'transfer', info: { source: wallet, destination: treasury, lamports } } },
      { program: 'spl-token', parsed: { type: 'burnChecked', info: { mint, authority: wallet, tokenAmount: { amount: burn, decimals: 6 } } } },
      { program: 'spl-memo', parsed: memo }
    ] } }
  });
  const opts = { wallet, kind: 'rank', id: 'guardian', treasury, mint, requiredLamports: 500000000n, requiredRaw: 1000000n * 10n ** 6n };
  assert.ok(checkPaymentTx(mk(), opts));
  assert.throws(() => checkPaymentTx(mk({ memo: 'bodyguard:rank:sentry' }), opts), /purchase tag/);
  assert.throws(() => checkPaymentTx(mk({ lamports: 100 }), opts), /SOL/);
  assert.throws(() => checkPaymentTx(mk({ burn: '1' }), opts), /GUARD/);
  assert.throws(() => checkPaymentTx(mk({ signer: 'X1111111111111111111111111111111111111111' }), opts), /signed/);
  assert.throws(() => checkPaymentTx(mk({ err: { x: 1 } }), opts), /failed/);
  assert.throws(() => checkPaymentTx(null, opts), /not found/);
});

test('spam classifier', () => {
  assert.equal(classify({ kind: 'token', mint: 'abc', symbol: 'USDC', name: 'USD Coin' }).why, 'Fake token');
  assert.equal(classify({ kind: 'token', mint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', symbol: 'USDC' }).spam, false);
  assert.equal(classify({ kind: 'cnft', mint: 'x', name: 'Claim 5000 SOL at solrewards.xyz' }).why, 'Phishing link');
  assert.equal(classify({ kind: 'token', mint: 'y', name: 'Free airdrop voucher', symbol: 'DROP' }).why, 'Airdrop spam');
  assert.equal(classify({ kind: 'cnft', mint: 'z', name: 'Some art', collectionVerified: false }).why, 'Unsolicited cNFT');
  assert.equal(classify({ kind: 'empty', mint: 'q' }).why, 'Empty account');
  assert.equal(classify({ kind: 'token', mint: 'r', name: 'Random', symbol: 'RND' }).spam, false);
});

test('policy engine', () => {
  const p = validatePolicy({ perTxLimit: 50, dailyLimit: 100, allowlist: 'AAA BBB', approvalsAbove: { amount: 20, approvals: 2 }, timelockAbove: { amount: 40, seconds: 3600 } });
  const t = 1_000_000;
  assert.equal(evaluatePolicy(p, { to: 'AAA', amount: 10 }, [], t).decision, 'allow');
  assert.equal(evaluatePolicy(p, { to: 'CCC', amount: 10 }, [], t).decision, 'deny');
  assert.equal(evaluatePolicy(p, { to: 'AAA', amount: 60 }, [], t).decision, 'deny');
  assert.equal(evaluatePolicy(p, { to: 'AAA', amount: 30, approvals: 1 }, [], t).decision, 'needs_approval');
  assert.equal(evaluatePolicy(p, { to: 'AAA', amount: 45, approvals: 2, proposedAt: t - 60 }, [], t).decision, 'timelocked');
  assert.equal(evaluatePolicy(p, { to: 'AAA', amount: 30, approvals: 2 }, [{ amount: 80, at: t - 100 }], t).decision, 'deny');
});

test('risk scoring', () => {
  run("insert into lists(name, data, updated_at) values('ofac_eth', ?, 0) on conflict(name) do update set data = excluded.data", JSON.stringify(['0x1111111111111111111111111111111111111111']));
  lists._testHydrate();
  const clean = scoreFrom({ chain: 'ethereum', address: '0x2222222222222222222222222222222222222222', cp: { list: [{ addr: '0x3333333333333333333333333333333333333333', dir: 'in', time: 1 }], firstSeen: 1, total: 1 } });
  assert.equal(clean.level, 'low');
  assert.equal(scoreFrom({ chain: 'ethereum', address: '0x1111111111111111111111111111111111111111', cp: { list: [], total: 0 } }).score, 100);
  const exposed = scoreFrom({ chain: 'ethereum', address: '0x2222222222222222222222222222222222222222', cp: { list: [{ addr: '0x1111111111111111111111111111111111111111', dir: 'in' }, { addr: '0x910cbd523d972eb0a6f4cae4618ad62622b39dbf', dir: 'out' }], firstSeen: 1, total: 2 } });
  assert.ok(exposed.score >= 90 && exposed.factors.some(f => f.code === 'mixer') && exposed.factors.some(f => f.code === 'sanctioned_exposure'));
});

test('web push payload encrypts to RFC 8291 and decrypts on the receiver side', () => {
  const ua = crypto.createECDH('prime256v1'); const uaPub = ua.generateKeys(); const auth = crypto.randomBytes(16);
  const body = encryptPayload('{"title":"hi"}', uaPub.toString('base64url'), auth.toString('base64url'));
  const salt = body.subarray(0, 16), idlen = body[20], asPub = body.subarray(21, 21 + idlen), ct = body.subarray(21 + idlen);
  const shared = ua.computeSecret(asPub);
  const ikm = Buffer.from(crypto.hkdfSync('sha256', shared, auth, Buffer.concat([Buffer.from('WebPush: info\0'), uaPub, asPub]), 32));
  const cek = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
  const d = crypto.createDecipheriv('aes-128-gcm', cek, nonce); d.setAuthTag(ct.subarray(ct.length - 16));
  const plain = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  assert.equal(plain.subarray(0, plain.length - 1).toString(), '{"title":"hi"}');
  assert.equal(plain[plain.length - 1], 2);
  const k = generateVapidKeys(); assert.equal(Buffer.from(k.publicKey, 'base64url').length, 65);
});

test('Squads create instruction and account decoders', () => {
  const ck = sol.generateKeypair().publicKey, creator = sol.generateKeypair().publicKey, m2 = sol.generateKeypair().publicKey, treasury = sol.generateKeypair().publicKey;
  const { multisig, ix } = squads.multisigCreateV2Ix({ treasury, createKey: ck, creator, threshold: 2, members: [{ key: creator }, { key: m2 }], timeLock: 3600 });
  assert.equal(multisig, squads.multisigPda(ck));
  assert.equal(ix.keys.length, 6);
  assert.equal(ix.data.length, 8 + 1 + 2 + 4 + 2 * 33 + 4 + 1 + 1);
  assert.equal(ix.data.readUInt16LE(9), 2);
  // Build a synthetic multisig account and decode it.
  const acc = Buffer.concat([Buffer.alloc(8), Buffer.from(sol.toBytes(ck)), Buffer.alloc(32), Buffer.from([2, 0]), Buffer.from([16, 14, 0, 0]), Buffer.alloc(8), Buffer.alloc(8), Buffer.from([0]), Buffer.from([255]),
    Buffer.from([2, 0, 0, 0]), Buffer.from(sol.toBytes(creator)), Buffer.from([7]), Buffer.from(sol.toBytes(m2)), Buffer.from([3])]);
  const ms = squads.decodeMultisig(acc.toString('base64'));
  assert.equal(ms.threshold, 2); assert.equal(ms.timeLock, 3600); assert.equal(ms.members.length, 2); assert.equal(ms.members[1].key, m2);
});
