// Base58 (Bitcoin alphabet) used by Solana keys and signatures.
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const MAP = new Map([...ALPHABET].map((c, i) => [c, i]));

export function b58encode(bytes) {
  bytes = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  const digits = [];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = '';
  for (const byte of bytes) { if (byte === 0) out += '1'; else break; }
  for (let k = digits.length - 1; k >= 0; k--) out += ALPHABET[digits[k]];
  return out;
}

export function b58decode(str) {
  if (typeof str !== 'string') throw new Error('base58: expected string');
  // Decoding is quadratic: refuse anything far longer than a Solana transaction so no input can stall the server.
  if (str.length > 2500) throw new Error('base58: input too long');
  const bytes = [];
  for (const c of str) {
    const v = MAP.get(c);
    if (v === undefined) throw new Error('base58: invalid character');
    let carry = v;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (const c of str) { if (c === '1') bytes.push(0); else break; }
  return Uint8Array.from(bytes.reverse());
}

export function isBase58(str) {
  return typeof str === 'string' && /^[1-9A-HJ-NP-Za-km-z]+$/.test(str);
}
