// Self-hosted copy of the Solana web3 library used at checkout and in the dashboard.
//
// Loading wallet code from a public CDN means trusting that CDN. Instead, on start-up the server downloads the
// exact pinned version from the npm registry, checks the package against the registry's published integrity hash,
// pulls out the browser build and serves it from this site with a Subresource Integrity (SRI) hash. Pages load it
// with `integrity=…`, so a browser refuses the file if a single byte changes.
//
// The first good copy's hash is remembered. If a later download ever differs for the same version, it is refused
// and logged, and the copy already on disk keeps being served.
// If the download can't happen (no network), pages fall back to the CDN copy, as before.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { config } from './config.js';
import { kvGet, kvSet } from './db.js';
import { log } from './security.js';

export const WEB3_PKG = '@solana/web3.js';
export const WEB3_VERSION = '1.95.3'; // pinned: 1.95.6 and 1.95.7 were the compromised releases, never upgrade blindly
const ENTRY = 'package/lib/index.iife.min.js';
const CDN = `https://cdn.jsdelivr.net/npm/${WEB3_PKG}@${WEB3_VERSION}/lib/index.iife.min.js`;
const REGISTRY = 'https://registry.npmjs.org/';
const KV = 'vendor:web3';

let state = { url: CDN, sri: null, buf: null };
export const web3Asset = () => ({ url: state.url, sri: state.sri });
export const web3Buffer = () => state.buf;
export const _resetVendor = () => { state = { url: CDN, sri: null, buf: null }; };

const sri = buf => 'sha384-' + crypto.createHash('sha384').update(buf).digest('base64');
const file = () => path.join(config.dataDir, 'vendor', `web3-${WEB3_VERSION}.js`);
const looksRight = buf => buf.length > 100_000 && buf.length < 5_000_000 && buf.includes('solanaWeb3');

function use(buf) {
  state = { url: `/vendor/web3.js?v=${WEB3_VERSION}`, sri: sri(buf), buf };
}

// Minimal tar reader: returns the bytes of one entry, or null.
export function tarEntry(tar, want) {
  let off = 0, longName = null;
  while (off + 512 <= tar.length) {
    const h = tar.subarray(off, off + 512);
    if (h.every(b => b === 0)) break;
    const str = (a, b) => h.subarray(a, b).toString('utf8').replace(/\0.*$/s, '');
    const size = parseInt(str(124, 136).trim() || '0', 8);
    if (!Number.isFinite(size) || size < 0) return null;
    const type = String.fromCharCode(h[156] || 48);
    const prefix = str(345, 500);
    const name = longName || (prefix ? prefix + '/' : '') + str(0, 100);
    longName = null;
    const body = off + 512, next = body + Math.ceil(size / 512) * 512;
    if (next > tar.length) return null;
    if (type === 'L') longName = tar.subarray(body, body + size).toString('utf8').replace(/\0.*$/s, '');
    else if (type === 'x') { const m = /\d+ path=([^\n]+)\n/.exec(tar.subarray(body, body + size).toString('utf8')); if (m) longName = m[1]; }
    else if ((type === '0' || type === '\0') && name === want) return Buffer.from(tar.subarray(body, body + size));
    off = next;
  }
  return null;
}

export async function ensureWeb3({ fetchImpl = globalThis.fetch, timeoutMs = 20000 } = {}) {
  const pinned = kvGet(KV, null);
  const pin = pinned?.version === WEB3_VERSION ? pinned.sri : null;
  // 1. A copy already on disk that matches the remembered hash.
  try {
    const buf = fs.readFileSync(file());
    if (pin && sri(buf) === pin && looksRight(buf)) { use(buf); return web3Asset(); }
    if (pin) log('vendor_mismatch', { file: file(), note: 'copy on disk changed, downloading again' });
  } catch {}
  // 2. Download from the npm registry and verify.
  try {
    const signal = AbortSignal.timeout(timeoutMs);
    const metaRes = await fetchImpl(`${REGISTRY}${WEB3_PKG.replace('/', '%2f')}/${WEB3_VERSION}`, { signal, headers: { accept: 'application/json' } });
    if (!metaRes.ok) throw new Error('registry ' + metaRes.status);
    const meta = await metaRes.json();
    const integrity = String(meta?.dist?.integrity || '');
    const tarball = String(meta?.dist?.tarball || '');
    if (meta?.version !== WEB3_VERSION || !integrity.startsWith('sha512-') || !tarball.startsWith(REGISTRY)) throw new Error('unexpected registry answer');
    const tgzRes = await fetchImpl(tarball, { signal });
    if (!tgzRes.ok) throw new Error('tarball ' + tgzRes.status);
    const tgz = Buffer.from(await tgzRes.arrayBuffer());
    if (tgz.length > 30_000_000) throw new Error('tarball too large');
    const got = 'sha512-' + crypto.createHash('sha512').update(tgz).digest('base64');
    if (got !== integrity) throw new Error('package integrity check failed');
    const buf = tarEntry(zlib.gunzipSync(tgz, { maxOutputLength: 200_000_000 }), ENTRY);
    if (!buf || !looksRight(buf)) throw new Error('browser build missing from package');
    const hash = sri(buf);
    if (pin && hash !== pin) { log('vendor_mismatch', { expected: pin, got: hash }); throw new Error('download differs from the copy first trusted'); }
    fs.mkdirSync(path.dirname(file()), { recursive: true });
    fs.writeFileSync(file() + '.tmp', buf);
    fs.renameSync(file() + '.tmp', file());
    if (!pin) kvSet(KV, { version: WEB3_VERSION, sri: hash, at: Date.now() });
    use(buf);
    log('vendor_ready', { pkg: WEB3_PKG, version: WEB3_VERSION, sri: hash });
  } catch (e) {
    log('vendor_failed', { error: String(e.message || e).slice(0, 200) });
    console.warn(`[vendor] using CDN copy of ${WEB3_PKG}: ${e.message}`);
  }
  return web3Asset();
}
