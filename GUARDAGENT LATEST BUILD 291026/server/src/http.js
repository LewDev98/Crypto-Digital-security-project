// Minimal HTTP framework: routing, JSON bodies, CORS, auth helpers, rate limiting and static files.
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { config } from './config.js';
import { get, run, sha256hex, now } from './db.js';
import { isBanned, strike, withinBudget, HONEYPOTS } from './security.js';

const routes = [];
export class HttpError extends Error { constructor(status, message, extra, strikeKind) { super(message); this.status = status; this.extra = extra; this.strike = strikeKind; } }
export const bad = (m, extra) => new HttpError(400, m, extra);

export function route(method, pattern, handler, opts = {}) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:([a-zA-Z_]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$');
  routes.push({ method, re, keys, handler, opts });
}

const buckets = new Map();
// Hitting these limits is a sign of abuse (they guard sign-in, pairing, tickets and other anonymous endpoints),
// so they also count as strikes. Limits on signed-in features don't, so a busy customer is never blocked.
const ABUSE_KEYS = /^(auth|nonce|pair|ticket|rpc|rpcsend|cap|verify|dconfirm|hire):/;
export function rateLimit(key, perMinute) {
  const t = Date.now();
  const b = buckets.get(key) || { tokens: perMinute, at: t };
  b.tokens = Math.min(perMinute, b.tokens + ((t - b.at) / 60000) * perMinute);
  b.at = t;
  if (b.tokens < 1) { buckets.set(key, b); throw new HttpError(429, 'Too many requests. Slow down and try again.', undefined, ABUSE_KEYS.test(key) ? 'rate_limited' : null); }
  b.tokens -= 1; buckets.set(key, b);
}
export const _resetRateLimits = () => buckets.clear(); // tests only
setInterval(() => { const t = Date.now(); for (const [k, b] of buckets) if (t - b.at > 300000) buckets.delete(k); }, 60000).unref();

function cors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return;
  // Only this site (and any extra origins you list in CORS_ORIGINS) may call the API from a browser.
  const allowed = config.corsOrigins.includes(origin) || origin === config.publicUrl;
  if (allowed) {
    res.setHeader('access-control-allow-origin', origin);
    res.setHeader('vary', 'origin');
    res.setHeader('access-control-allow-headers', 'content-type, authorization, x-api-key');
    res.setHeader('access-control-allow-methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('access-control-max-age', '600');
  }
}

// Keys that could shadow built-in behaviour are dropped from every request body: {"toString": 1} would make
// String(value) throw, and __proto__ / constructor / prototype are classic prototype-pollution vectors.
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype', 'toString', 'valueOf', 'toJSON', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString']);
const safeReviver = (k, v) => (UNSAFE_KEYS.has(k) ? undefined : v);
async function readBody(req, limit = 256_000) {
  return new Promise((resolve, reject) => {
    let chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      // Stop reading and answer 413; the connection is closed once that answer is sent.
      if (size > limit) { if (chunks) { chunks = null; req.pause(); reject(Object.assign(new HttpError(413, 'Request too large', undefined, 'oversized'), { closeAfter: true })); } }
      else if (chunks) chunks.push(c);
    });
    req.on('end', () => chunks && resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// Behind a hosting proxy the real client IP is appended to X-Forwarded-For by the proxy; entries further left can
// be typed by anyone, so trusting them would let attackers dodge rate limits and blocks. TRUST_PROXY_HOPS is how
// many proxies you trust (1 = the last entry, the default; 2 if a CDN sits in front of the host's proxy).
// Check what your host sends with GET /api/admin/ip-check. TRUST_PROXY=0 ignores the header entirely.
// The visitor's address, as reported by the hosting proxy.
//  - CLIENT_IP_HEADER (e.g. x-real-ip on Railway, whose edge overwrites it) names one header the proxy sets itself.
//  - Otherwise X-Forwarded-For is read from the right: the last TRUST_PROXY_HOPS entries were added by proxies we
//    trust, anything further left was written by the visitor and is ignored.
//  - Anything that isn't a real IP address falls back to the connection's own address.
const cleanIp = v => { v = String(v || '').trim().replace(/^\[|\](?::\d+)?$/g, ''); if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(v)) v = v.replace(/:\d+$/, ''); return net.isIP(v) ? v : null; };
export const ipOf = req => {
  if (process.env.TRUST_PROXY !== '0') {
    const hdr = String(process.env.CLIENT_IP_HEADER || '').toLowerCase().trim();
    if (hdr) { const v = cleanIp(String(req.headers[hdr] || '').split(',')[0]); if (v) return v; }
    else {
      const parts = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
      const hops = Math.max(1, Math.min(5, Number(process.env.TRUST_PROXY_HOPS) || 1));
      if (parts.length) { const v = cleanIp(parts[Math.max(0, parts.length - hops)]); if (v) return v; }
    }
  }
  return req.socket.remoteAddress || 'unknown';
};

// Session = signed-in wallet (dashboard). Extension tokens map to an agent.
// Sessions last 30 days at most and end after 7 days without use.
const IDLE = 7 * 86400;
export function sessionInfo(req) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!tok || tok.startsWith('ext_') || tok.length > 200) return null;
  const hash = sha256hex(tok);
  const s = get('select wallet, expires_at, created_at, last_seen, id from sessions where token_hash = ?', hash);
  const t = now();
  if (!s || s.expires_at < t || (s.last_seen || s.created_at) < t - IDLE) return null;
  if (!s.last_seen || t - s.last_seen > 300) run('update sessions set last_seen = ? where token_hash = ?', t, hash);
  return { ...s, hash };
}
export function sessionWallet(req) { return sessionInfo(req)?.wallet || null; }
export function requireWallet(req) {
  const w = sessionWallet(req);
  if (!w) throw new HttpError(401, 'Sign in with your wallet first.');
  return w;
}

const SECURITY_HEADERS = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'x-frame-options': 'DENY',
  'strict-transport-security': 'max-age=31536000; includeSubDomains', 'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'cross-origin-opener-policy': 'same-origin-allow-popups' };
export { SECURITY_HEADERS };
// Signed-in pages (dashboard, vault) get a strict policy: no inline scripts at all, scripts only from this server and
// the pinned web3 CDN, and the page can only talk to this server. Even if some text slipped through unescaped, an
// injected <img onerror=…> could not run. The marketing pages get anti-framing rules without limiting wallet extensions.
const APP_CSP = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net chrome-extension: moz-extension:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";
// Public pages keep inline scripts (the landing page is one self-contained file) but can only talk to this site
// (and the public Solana RPC when no private one is set), so injected code has nowhere to send stolen data.
const CANON = (() => { try { const u = new URL(config.publicUrl); return u.protocol === 'https:' && process.env.CANONICAL_REDIRECT !== '0' ? { host: u.host, origin: u.origin } : null; } catch { return null; } })();
const ORIGIN = (() => { try { return new URL(config.publicUrl).origin; } catch { return ''; } })();
const SITE_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net chrome-extension: moz-extension:",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: blob:",
  `connect-src 'self' ${ORIGIN}${config.solana.rpc ? '' : ' https://api.mainnet-beta.solana.com'}`.trim(),
  "frame-src 'none'", "worker-src 'self'", "manifest-src 'self'",
  "frame-ancestors 'none'", "base-uri 'self'", "object-src 'none'", "form-action 'self'"
].join('; ') + (config.publicUrl.startsWith('https://') ? '; upgrade-insecure-requests' : '');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.webp': 'image/webp', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json', '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8', '.zip': 'application/zip', '.jpg': 'image/jpeg' };
// Clean URLs for pages.
const ALIASES = { '/': '/index.html', '/app': '/app.html', '/help': '/help.html', '/vault': '/vault.html' };
// Pages that hold a sign-in token: strict CSP, never indexed by search engines.
const PRIVATE = new Set(['/app.html', '/vault.html']);
const COMPRESSIBLE = /^(text\/|application\/(json|xml|manifest\+json|javascript))/;
const gzCache = new Map();

function serveStatic(req, res, urlPath) {
  let p;
  try { p = decodeURIComponent(urlPath); } catch { return false; }
  if (p.includes('\0')) return false;
  p = ALIASES[p] || p;
  const file = path.normalize(path.join(config.webDir, p));
  if (!file.startsWith(config.webDir + path.sep)) return false;
  // Never serve dotfiles (.env, .git) even if one ends up in the web folder.
  if (file.slice(config.webDir.length).split(path.sep).some(seg => seg.startsWith('.'))) return false;
  let st;
  try { st = fs.statSync(file); } catch { return false; }
  if (!st.isFile()) return false;
  const type = TYPES[path.extname(file)] || 'application/octet-stream';
  const isHtml = p.endsWith('.html');
  const etag = `W/"${st.size.toString(16)}-${Math.floor(st.mtimeMs).toString(16)}"`;
  const headers = {
    'content-type': type, etag, 'last-modified': st.mtime.toUTCString(),
    'cache-control': isHtml || p === '/sw.js' ? 'no-cache' : /\.(png|webp|jpg|ico|svg|woff2?)$/.test(p) ? 'public, max-age=86400' : 'public, max-age=300',
    ...SECURITY_HEADERS,
    ...(PRIVATE.has(p) ? { 'content-security-policy': APP_CSP, 'x-robots-tag': 'noindex, nofollow', 'permissions-policy': 'camera=(), microphone=(), geolocation=(self), payment=(), usb=()' } : isHtml ? { 'content-security-policy': SITE_CSP } : {})
  };
  if (req.headers['if-none-match'] === etag) { res.writeHead(304, headers); return res.end(), true; }
  const gzip = COMPRESSIBLE.test(type) && /\bgzip\b/.test(req.headers['accept-encoding'] || '') && st.size > 1024;
  if (gzip) {
    let c = gzCache.get(file);
    if (!c || c.mtime !== st.mtimeMs) { c = { mtime: st.mtimeMs, buf: zlib.gzipSync(fs.readFileSync(file), { level: 9 }) }; gzCache.set(file, c); }
    res.writeHead(200, { ...headers, 'content-encoding': 'gzip', vary: 'accept-encoding', 'content-length': c.buf.length });
    return res.end(req.method === 'HEAD' ? undefined : c.buf), true;
  }
  res.writeHead(200, { ...headers, 'content-length': st.size });
  if (req.method === 'HEAD') return res.end(), true;
  fs.createReadStream(file).pipe(res);
  return true;
}

export function send(res, status, body, headers = {}) {
  if (typeof body === 'string' || Buffer.isBuffer(body)) {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...SECURITY_HEADERS, 'content-security-policy': SITE_CSP, ...headers });
    return res.end(body);
  }
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-robots-tag': 'noindex', ...headers });
  res.end(JSON.stringify(body ?? {}));
}

export function createServer() {
  const server = http.createServer(async (req, res) => {
    let url;
    try { url = new URL(req.url, 'http://x'); } catch { res.writeHead(400); return res.end(); }
    const ip = ipOf(req);
    // Active defences run before anything else: blocked addresses, request floods and honeypot paths.
    const until = isBanned(ip);
    if (until) { res.writeHead(429, { 'content-type': 'application/json', 'retry-after': String(until - now()), connection: 'close' }); return res.end(JSON.stringify({ error: 'Access from your network is temporarily blocked after suspicious activity. Try again later, or contact support.' })); }
    if (!withinBudget(ip)) { strike(ip, 'budget', url.pathname); res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '60' }); return res.end(JSON.stringify({ error: 'Too many requests. Slow down and try again.' })); }
    if (HONEYPOTS.test(url.pathname)) { strike(ip, 'honeypot', url.pathname); send(res, 404, { error: 'Not found' }); return; }
    // Pages opened on another hostname (www., the raw hosting domain) move to the real address, so sign-in
    // (which only accepts the real site) works and search engines see one copy of each page.
    if (CANON && (req.method === 'GET' || req.method === 'HEAD') && !url.pathname.startsWith('/api/') && !url.pathname.startsWith('/.well-known/')) {
      const host = String(req.headers.host || '').toLowerCase();
      if (host && host !== CANON.host && !/^(localhost|127\.|\[::1\])/.test(host) && !net.isIP(host.replace(/:\d+$/, ''))) {
        res.writeHead(301, { location: CANON.origin + (req.url.startsWith('/') ? req.url : '/'), 'cache-control': 'public, max-age=3600' });
        return res.end();
      }
    }
    cors(req, res);
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    try {
      for (const r of routes) {
        if (r.method !== req.method) continue;
        const m = url.pathname.match(r.re);
        if (!m) continue;
        let params;
        try { params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])])); } catch { throw bad('Bad address.'); }
        let body = {};
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          // Routes that accept big bodies check who is calling before reading a single byte of it.
          if (r.opts.preAuth && !r.opts.preAuth(req)) { res.setHeader('connection', 'close'); throw new HttpError(401, 'Sign in first.', undefined, r.opts.preAuthStrike || 'preauth'); }
          const raw = await readBody(req, r.opts.limit);
          if (r.opts.raw) body = raw;
          else if (raw.length) {
            const ct = req.headers['content-type'] || '';
            if (ct.includes('application/x-www-form-urlencoded')) body = Object.fromEntries([...new URLSearchParams(raw.toString())].filter(([k]) => !UNSAFE_KEYS.has(k)));
            else { try { body = JSON.parse(raw.toString(), safeReviver); } catch { throw new HttpError(400, 'Body must be JSON.', undefined, 'malformed'); } }
            if (body === null || typeof body !== 'object') throw new HttpError(400, 'Body must be a JSON object.', undefined, 'malformed');
          }
        }
        const ctx = { req, res, url, params, query: Object.fromEntries([...url.searchParams].filter(([k]) => !UNSAFE_KEYS.has(k))), body, ip };
        const out = await r.handler(ctx);
        if (res.writableEnded || res.headersSent) return;
        if (out && out.__redirect) { res.writeHead(302, { location: out.__redirect }); return res.end(); }
        if (out && out.__html !== undefined) return send(res, out.status || 200, out.__html, out.headers);
        if (out && out.__raw !== undefined) { res.writeHead(out.status || 200, { 'x-content-type-options': 'nosniff', ...(out.headers || {}) }); return res.end(out.__raw); }
        return send(res, 200, out);
      }
      if ((req.method === 'GET' || req.method === 'HEAD') && !url.pathname.startsWith('/api/') && serveStatic(req, res, url.pathname)) return;
      if (url.pathname.startsWith('/api/')) strike(ip, 'api_404', req.method + ' ' + url.pathname);
      send(res, 404, { error: 'Not found' });
    } catch (e) {
      const status = e.status || 500;
      if (e.strike) strike(ip, e.strike, req.method + ' ' + url.pathname);
      else if (status === 403) strike(ip, 'forbidden', req.method + ' ' + url.pathname);
      if (!(e instanceof HttpError)) console.error('[http]', req.method, url.pathname, e);
      if (!res.headersSent) send(res, status, { error: status >= 500 ? 'Something went wrong on our side. Try again in a moment.' : e.message, ...(e.extra || {}) }, e.closeAfter || status === 401 && req.readableLength ? { connection: 'close' } : {});
      if (e.closeAfter) res.on('finish', () => req.destroy());
    }
  });
  // Slow-request protection: a client that dribbles headers or a body can't hold a connection open for minutes.
  server.headersTimeout = 20000;
  server.requestTimeout = 60000;
  server.keepAliveTimeout = 10000;
  return server;
}
