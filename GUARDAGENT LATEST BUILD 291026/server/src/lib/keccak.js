// Keccak-256 (the Ethereum variant, not NIST SHA3). Constants are derived, not hand-typed.
const MASK = (1n << 64n) - 1n;

function rcBit(t) {
  if (t % 255 === 0) return 1;
  let r = 1;
  for (let i = 1; i <= t % 255; i++) {
    r <<= 1;
    if (r & 0x100) r ^= 0x171;
  }
  return r & 1;
}
const RC = [];
for (let i = 0; i < 24; i++) {
  let rc = 0n;
  for (let j = 0; j <= 6; j++) if (rcBit(j + 7 * i)) rc |= 1n << BigInt((1 << j) - 1);
  RC.push(rc);
}
const ROT = Array.from({ length: 5 }, () => Array(5).fill(0));
{
  let x = 1, y = 0;
  for (let t = 0; t < 24; t++) {
    ROT[x][y] = (((t + 1) * (t + 2)) / 2) % 64;
    [x, y] = [y, (2 * x + 3 * y) % 5];
  }
}
const rotl = (v, n) => (n === 0 ? v : ((v << BigInt(n)) | (v >> BigInt(64 - n))) & MASK);

function keccakF(s) {
  for (let round = 0; round < 24; round++) {
    const C = [0, 1, 2, 3, 4].map(x => s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]);
    for (let x = 0; x < 5; x++) {
      const D = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) s[x + 5 * y] ^= D;
    }
    const B = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], ROT[x][y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
      s[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y] & MASK) & B[((x + 2) % 5) + 5 * y]);
    }
    s[0] ^= RC[round];
  }
}

export function keccak256(input) {
  const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((data.length + 1) / rate) * rate);
  padded.set(data);
  padded[data.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const s = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 0; b < 8; b++) lane |= BigInt(padded[off + i * 8 + b]) << BigInt(8 * b);
      s[i] ^= lane;
    }
    keccakF(s);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) for (let b = 0; b < 8; b++) out[i * 8 + b] = Number((s[i] >> BigInt(8 * b)) & 0xffn);
  return out;
}

export const keccakHex = input => '0x' + Buffer.from(keccak256(input)).toString('hex');
export const topic = sig => keccakHex(sig);
export const selector = sig => keccakHex(sig).slice(0, 10);
