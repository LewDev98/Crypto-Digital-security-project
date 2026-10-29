// Dependency-free Solana toolkit: keys, PDAs, instruction builders, transaction
// (de)serialisation and a small JSON-RPC client.
import crypto from 'node:crypto';
import { b58encode, b58decode, isBase58 } from './base58.js';

export const PROGRAMS = {
  SYSTEM: '11111111111111111111111111111111',
  TOKEN: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
  TOKEN_2022: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
  ATA: 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
  MEMO: 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',
  MEMO_V1: 'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo',
  COMPUTE_BUDGET: 'ComputeBudget111111111111111111111111111111',
  BUBBLEGUM: 'BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY',
  SPL_NOOP: 'noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV',
  SPL_COMPRESSION: 'cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK',
  SQUADS_V4: 'SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf',
  ADDRESS_LOOKUP: 'AddressLookupTab1e1111111111111111111111111'
};
export const LAMPORTS_PER_SOL = 1_000_000_000;

/* ---------------- keys ---------------- */
export const toBytes = k => (k instanceof Uint8Array ? k : b58decode(k));
export function isValidPubkey(s) {
  if (!isBase58(s) || s.length < 32 || s.length > 44) return false;
  try { return b58decode(s).length === 32; } catch { return false; }
}

const P = 2n ** 255n - 19n;
const D = (-121665n * modInv(121666n)) % P;
const SQRT_M1 = modPow(2n, (P - 1n) / 4n);
function mod(a) { const r = a % P; return r >= 0n ? r : r + P; }
function modPow(b, e) { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = (r * b) % P; b = (b * b) % P; e >>= 1n; } return r; }
function modInv(a) { return modPow(mod(a), P - 2n); }

// True if the 32 bytes decode to a valid ed25519 point (PDAs must be off-curve).
export function isOnCurve(bytes) {
  const b = Uint8Array.from(bytes);
  const sign = b[31] >> 7;
  b[31] &= 0x7f;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(b[i]);
  if (y >= P) return false;
  const y2 = mod(y * y);
  const u = mod(y2 - 1n), v = mod(D * y2 + 1n);
  let x = mod(u * modPow(v, 3n) * modPow(mod(u * modPow(v, 7n)), (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  if (vx2 === u) { /* ok */ } else if (vx2 === mod(-u)) x = mod(x * SQRT_M1);
  else return false;
  if (x === 0n && sign === 1) return false;
  return true;
}

export function findProgramAddress(seeds, programId) {
  const pid = toBytes(programId);
  for (let bump = 255; bump >= 0; bump--) {
    const h = crypto.createHash('sha256');
    for (const s of seeds) h.update(typeof s === 'string' ? Buffer.from(s) : Buffer.from(s));
    h.update(Buffer.from([bump])); h.update(Buffer.from(pid)); h.update(Buffer.from('ProgramDerivedAddress'));
    const hash = h.digest();
    if (!isOnCurve(hash)) return [b58encode(hash), bump];
  }
  throw new Error('no viable bump');
}

export function ata(owner, mint, tokenProgram = PROGRAMS.TOKEN) {
  return findProgramAddress([toBytes(owner), toBytes(tokenProgram), toBytes(mint)], PROGRAMS.ATA)[0];
}

export function anchorDisc(name, ns = 'global') {
  return crypto.createHash('sha256').update(`${ns}:${name}`).digest().subarray(0, 8);
}

/* ---------------- keypairs (ed25519) ---------------- */
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
export function verifyEd25519(message, signature, pubkey) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(toBytes(pubkey))]), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch { return false; }
}
export function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey: b58encode(pub), privateKey, sign: msg => new Uint8Array(crypto.sign(null, Buffer.from(msg), privateKey)) };
}

/* ---------------- byte helpers ---------------- */
export function u64le(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; }
export function u32le(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; }
export function u16le(n) { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; }
export function compactU16(n) {
  const out = [];
  for (;;) { let b = n & 0x7f; n >>= 7; if (n) { out.push(b | 0x80); } else { out.push(b); break; } }
  return Uint8Array.from(out);
}
function readCompactU16(buf, off) {
  let n = 0, shift = 0, i = 0;
  for (;;) {
    if (off + i >= buf.length || i >= 3) throw new Error('malformed transaction');
    const b = buf[off + i]; n |= (b & 0x7f) << shift; i++; if (!(b & 0x80)) break; shift += 7;
  }
  return [n, i];
}

/* ---------------- instruction builders ---------------- */
export const ix = {
  transfer(from, to, lamports) {
    return { programId: PROGRAMS.SYSTEM, keys: [{ pubkey: from, isSigner: true, isWritable: true }, { pubkey: to, isSigner: false, isWritable: true }], data: Buffer.concat([u32le(2), u64le(lamports)]) };
  },
  burnChecked(account, mint, owner, amount, decimals, programId = PROGRAMS.TOKEN) {
    return { programId, keys: [{ pubkey: account, isSigner: false, isWritable: true }, { pubkey: mint, isSigner: false, isWritable: true }, { pubkey: owner, isSigner: true, isWritable: false }], data: Buffer.concat([Buffer.from([15]), u64le(amount), Buffer.from([decimals])]) };
  },
  closeAccount(account, destination, owner, programId = PROGRAMS.TOKEN) {
    return { programId, keys: [{ pubkey: account, isSigner: false, isWritable: true }, { pubkey: destination, isSigner: false, isWritable: true }, { pubkey: owner, isSigner: true, isWritable: false }], data: Buffer.from([9]) };
  },
  memo(text, signer) {
    return { programId: PROGRAMS.MEMO, keys: signer ? [{ pubkey: signer, isSigner: true, isWritable: false }] : [], data: Buffer.from(text, 'utf8') };
  },
  computeUnitPrice(microLamports) { return { programId: PROGRAMS.COMPUTE_BUDGET, keys: [], data: Buffer.concat([Buffer.from([3]), u64le(microLamports)]) }; },
  computeUnitLimit(units) { return { programId: PROGRAMS.COMPUTE_BUDGET, keys: [], data: Buffer.concat([Buffer.from([2]), u32le(units)]) }; }
};

/* ---------------- legacy transaction compile ---------------- */
export function compileLegacy({ feePayer, recentBlockhash, instructions }) {
  const metas = new Map();
  const touch = (pubkey, isSigner, isWritable) => {
    const m = metas.get(pubkey) || { pubkey, isSigner: false, isWritable: false };
    m.isSigner ||= isSigner; m.isWritable ||= isWritable; metas.set(pubkey, m);
  };
  touch(feePayer, true, true);
  for (const i of instructions) { for (const k of i.keys) touch(k.pubkey, k.isSigner, k.isWritable); touch(i.programId, false, false); }
  const all = [...metas.values()];
  const payer = all.find(m => m.pubkey === feePayer);
  const rest = all.filter(m => m !== payer);
  const order = [payer,
    ...rest.filter(m => m.isSigner && m.isWritable), ...rest.filter(m => m.isSigner && !m.isWritable),
    ...rest.filter(m => !m.isSigner && m.isWritable), ...rest.filter(m => !m.isSigner && !m.isWritable)];
  const index = new Map(order.map((m, i) => [m.pubkey, i]));
  const numSigners = order.filter(m => m.isSigner).length;
  const header = [numSigners, order.filter(m => m.isSigner && !m.isWritable).length, order.filter(m => !m.isSigner && !m.isWritable).length];
  const parts = [Uint8Array.from(header), compactU16(order.length), ...order.map(m => toBytes(m.pubkey)), toBytes(recentBlockhash), compactU16(instructions.length)];
  for (const i of instructions) {
    const idx = i.keys.map(k => index.get(k.pubkey));
    parts.push(Uint8Array.from([index.get(i.programId)]), compactU16(idx.length), Uint8Array.from(idx), compactU16(i.data.length), Uint8Array.from(i.data));
  }
  const message = Buffer.concat(parts.map(p => Buffer.from(p)));
  return { message, signers: order.slice(0, numSigners).map(m => m.pubkey) };
}

export function serializeTx(message, signers, signatures = {}) {
  const sigs = signers.map(s => Buffer.from(signatures[s] || new Uint8Array(64)));
  return Buffer.concat([Buffer.from(compactU16(signers.length)), ...sigs, message]);
}

export function buildTx({ feePayer, recentBlockhash, instructions, partialSigners = [] }) {
  const { message, signers } = compileLegacy({ feePayer, recentBlockhash, instructions });
  const signatures = {};
  for (const kp of partialSigners) signatures[kp.publicKey] = kp.sign(message);
  return { bytes: serializeTx(message, signers, signatures), message, signers };
}

/* ---------------- transaction decode (legacy + v0) ---------------- */
// Transactions come from web pages, so every length is checked against the real size before it is used:
// a crafted transaction can't make the decoder loop millions of times or read past the end.
export function decodeTx(bytes) {
  const buf = Buffer.from(bytes);
  if (buf.length < 1 || buf.length > 4096) throw new Error('malformed transaction');
  let off = 0;
  const need = n => { if (n < 0 || off + n > buf.length) throw new Error('malformed transaction'); };
  const [nSig, l1] = readCompactU16(buf, off); off += l1;
  const signatures = [];
  need(nSig * 64);
  for (let i = 0; i < nSig; i++) { signatures.push(buf.subarray(off, off + 64)); off += 64; }
  const msgStart = off;
  let version = 'legacy';
  need(1);
  if (buf[off] & 0x80) { version = buf[off] & 0x7f; off++; }
  need(3);
  const header = { numRequiredSignatures: buf[off], numReadonlySigned: buf[off + 1], numReadonlyUnsigned: buf[off + 2] }; off += 3;
  const [nKeys, l2] = readCompactU16(buf, off); off += l2;
  const staticKeys = [];
  need(nKeys * 32 + 32);
  for (let i = 0; i < nKeys; i++) { staticKeys.push(b58encode(buf.subarray(off, off + 32))); off += 32; }
  const recentBlockhash = b58encode(buf.subarray(off, off + 32)); off += 32;
  const [nIx, l3] = readCompactU16(buf, off); off += l3;
  const instructions = [];
  for (let i = 0; i < nIx; i++) {
    need(1);
    const programIdIndex = buf[off++];
    const [na, la] = readCompactU16(buf, off); off += la;
    need(na);
    const accounts = [...buf.subarray(off, off + na)]; off += na;
    const [nd, ld] = readCompactU16(buf, off); off += ld;
    need(nd);
    const data = buf.subarray(off, off + nd); off += nd;
    instructions.push({ programIdIndex, accounts, data });
  }
  const lookups = [];
  if (version !== 'legacy') {
    const [nL, ll] = readCompactU16(buf, off); off += ll;
    for (let i = 0; i < nL; i++) {
      need(32);
      const accountKey = b58encode(buf.subarray(off, off + 32)); off += 32;
      const [nw, lw] = readCompactU16(buf, off); off += lw; need(nw); const writable = [...buf.subarray(off, off + nw)]; off += nw;
      const [nr, lr] = readCompactU16(buf, off); off += lr; need(nr); const readonly = [...buf.subarray(off, off + nr)]; off += nr;
      lookups.push({ accountKey, writable, readonly });
    }
  }
  return { signatures, version, header, staticKeys, recentBlockhash, instructions, lookups, message: buf.subarray(msgStart) };
}

// Resolve every account key (static + address-lookup-table) and flags.
export async function resolveTx(decoded, rpc) {
  if (decoded.lookups.length > 8) throw new Error('too many lookup tables');
  const keys = [...decoded.staticKeys];
  const writableLookup = [], readonlyLookup = [];
  for (const l of decoded.lookups) {
    const info = await rpc.getAccountInfo(l.accountKey);
    if (!info) throw new Error('lookup table not found');
    const data = Buffer.from(info.data[0], 'base64');
    const addrs = [];
    for (let o = 56; o + 32 <= data.length; o += 32) addrs.push(b58encode(data.subarray(o, o + 32)));
    l.writable.forEach(i => writableLookup.push(addrs[i]));
    l.readonly.forEach(i => readonlyLookup.push(addrs[i]));
  }
  keys.push(...writableLookup, ...readonlyLookup);
  const h = decoded.header, nStatic = decoded.staticKeys.length;
  const isSigner = i => i < h.numRequiredSignatures;
  const isWritable = i => {
    if (i < h.numRequiredSignatures) return i < h.numRequiredSignatures - h.numReadonlySigned;
    if (i < nStatic) return i < nStatic - h.numReadonlyUnsigned;
    return i < nStatic + writableLookup.length;
  };
  const bad = decoded.instructions.some(ins => keys[ins.programIdIndex] == null || ins.accounts.some(i => keys[i] == null));
  if (bad) throw new Error('malformed transaction');
  const instructions = decoded.instructions.map(ins => ({
    programId: keys[ins.programIdIndex],
    keys: ins.accounts.map(i => ({ pubkey: keys[i], isSigner: isSigner(i), isWritable: isWritable(i) })),
    data: ins.data
  }));
  return { keys, signers: keys.slice(0, h.numRequiredSignatures), instructions, isWritable };
}

/* ---------------- token account parsing ---------------- */
export function parseTokenAccount(dataB64) {
  const d = Buffer.from(dataB64, 'base64');
  if (d.length < 165) return null;
  return {
    mint: b58encode(d.subarray(0, 32)),
    owner: b58encode(d.subarray(32, 64)),
    amount: d.readBigUInt64LE(64),
    delegate: d.readUInt32LE(72) ? b58encode(d.subarray(76, 108)) : null,
    state: d[108],
    delegatedAmount: d.readBigUInt64LE(121)
  };
}

/* ---------------- RPC ---------------- */
export function rpcClient(url) {
  let id = 0;
  async function call(method, params = [], { retries = 2 } = {}) {
    if (!url) throw new Error('SOLANA_RPC_URL is not set');
    let lastErr;
    for (let a = 0; a <= retries; a++) {
      try {
        const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }), signal: AbortSignal.timeout(20000) });
        if (res.status === 429) { await sleep(800 * (a + 1)); lastErr = new Error('rate limited'); continue; }
        const j = await res.json();
        if (j.error) { const e = new Error(j.error.message || 'rpc error'); e.code = j.error.code; e.data = j.error.data; throw e; }
        return j.result;
      } catch (e) {
        lastErr = e;
        if (e.code !== undefined && e.code !== -32005) throw e;
        await sleep(400 * (a + 1));
      }
    }
    throw lastErr;
  }
  return {
    url, call,
    getAccountInfo: async (pk, enc = 'base64') => (await call('getAccountInfo', [pk, { encoding: enc, commitment: 'confirmed' }])).value,
    getMultipleAccounts: async (pks, enc = 'base64') => (await call('getMultipleAccounts', [pks, { encoding: enc, commitment: 'confirmed' }])).value,
    getBalance: async pk => (await call('getBalance', [pk, { commitment: 'confirmed' }])).value,
    getLatestBlockhash: async () => (await call('getLatestBlockhash', [{ commitment: 'confirmed' }])).value,
    getTransaction: sig => call('getTransaction', [sig, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }]),
    getSignatures: (addr, opts = {}) => call('getSignaturesForAddress', [addr, { limit: 50, commitment: 'confirmed', ...opts }]),
    getTokenAccounts: async (owner, programId) => (await call('getTokenAccountsByOwner', [owner, { programId }, { encoding: 'jsonParsed', commitment: 'confirmed' }])).value,
    simulate: (txB64, opts = {}) => call('simulateTransaction', [txB64, { encoding: 'base64', sigVerify: false, replaceRecentBlockhash: true, commitment: 'confirmed', ...opts }]),
    sendRaw: txB64 => call('sendTransaction', [txB64, { encoding: 'base64', skipPreflight: false, preflightCommitment: 'confirmed', maxRetries: 3 }])
  };
}
export const sleep = ms => new Promise(r => setTimeout(r, ms));
export { b58encode, b58decode };
