// Active defences: spots attack patterns per client address and blocks repeat offenders for a while.
//
//  - Honeypot paths (/.env, /wp-login.php, /.git/config …) are never used by real visitors, so a hit is an
//    immediate block.
//  - Every suspicious signal (bad signatures, failed webhook auth, rate-limit hits, malformed bodies, API 404
//    floods, oversized uploads …) adds strike points. 20 points within 10 minutes blocks the address, first for
//    15 minutes, doubling each time up to 24 hours.
//  - A global per-address request budget catches floods that don't trip a single endpoint's limit.
//  - Private and internal addresses are never blocked. If the host's proxy ever made every visitor look like one
//    internal address, blocking it would lock everyone out, so that case is skipped and logged instead.
//  - Every block and admin action is written to an audit log that admins can read in the dashboard.
import { run, all, get, now, json } from './db.js';
import { isPrivateIp } from './lib/net.js';

const WINDOW = 600;            // strike points count for 10 minutes
const THRESHOLD = 20;          // points that trigger a block
const BASE_BAN = 900;          // first block: 15 minutes
const MAX_BAN = 86400;         // longest block: 24 hours
const BUDGET_PER_MIN = Number(process.env.REQUESTS_PER_MINUTE_PER_IP || 600);

const strikes = new Map();     // ip -> [{ t, pts }]
const bans = new Map();        // ip -> { until, count }
const budget = new Map();      // ip -> { minute, n }

export const HONEYPOTS = /^\/(?:\.env(?:\..*)?|\.git(?:\/.*)?|\.aws\/.*|\.ssh\/.*|wp-(?:login|admin|config)[^/]*|wp-content\/.*|wp-includes\/.*|xmlrpc\.php|phpmyadmin.*|pma\/.*|admin\.php|config\.php|setup\.php|server-status|actuator(?:\/.*)?|cgi-bin\/.*|vendor\/phpunit\/.*|boaform\/.*|\.DS_Store|backup(?:\.zip|\.sql|\.tar\.gz)|db\.sql|dump\.sql|id_rsa|HNAP1|owa\/.*)$/i;

export const POINTS = {
  honeypot: THRESHOLD,         // instant block
  bad_signature: 3,            // wrong wallet signature at sign-in
  webhook_auth: 5,             // wrong secret on the Helius webhook
  rate_limited: 1,             // hit a per-endpoint rate limit
  budget: 2,                   // blew the global request budget
  malformed: 1,                // body that isn't JSON / is the wrong shape
  oversized: 3,                // body over the route's size limit
  preauth: 3,                  // big upload without signing in
  api_404: 1,                  // unknown API route (scanners)
  pair_fail: 2,                // wrong extension pairing code
  forbidden: 1                 // touching someone else's resource
};

const blockable = ip => ip && ip !== 'unknown' && !isPrivateIp(ip);

export function isBanned(ip) {
  const b = bans.get(ip);
  if (!b) return null;
  if (b.until <= now()) return null;
  return b.until;
}

export function strike(ip, kind, detail = '') {
  const pts = POINTS[kind] ?? 1;
  const t = now();
  const list = (strikes.get(ip) || []).filter(s => t - s.t < WINDOW);
  list.push({ t, pts });
  strikes.set(ip, list.slice(-200));
  if (kind === 'honeypot' || pts >= 3) log('strike', { ip, kind, detail: String(detail).slice(0, 200) });
  const score = list.reduce((s, x) => s + x.pts, 0);
  if (score >= THRESHOLD) ban(ip, `${kind} (score ${score})`);
}

export function ban(ip, reason, seconds) {
  if (!blockable(ip)) { log('ban_skipped', { ip, reason: 'private or internal address, never blocked: ' + reason }); return; }
  const prev = bans.get(ip);
  const count = (prev?.count || 0) + 1;
  const dur = seconds || Math.min(MAX_BAN, BASE_BAN * 2 ** (count - 1));
  const until = now() + dur;
  bans.set(ip, { until, count, reason });
  strikes.delete(ip);
  log('ban', { ip, reason, until, seconds: dur });
  run('insert into ip_bans(ip, until, count, reason, created_at) values(?,?,?,?,?) on conflict(ip) do update set until = excluded.until, count = excluded.count, reason = excluded.reason', ip, until, count, reason, now());
  if (onBan) onBan({ ip, reason, until, count });
}
export function unban(ip) { bans.delete(ip); strikes.delete(ip); run('delete from ip_bans where ip = ?', ip); log('unban', { ip }); }
let onBan = null;
export const setBanHandler = fn => { onBan = fn; };

// Global per-address budget. Returns false when the address is over it.
export function withinBudget(ip) {
  if (!blockable(ip)) return true;
  const m = Math.floor(Date.now() / 60000);
  const b = budget.get(ip);
  if (!b || b.minute !== m) { budget.set(ip, { minute: m, n: 1 }); return true; }
  b.n++;
  return b.n <= BUDGET_PER_MIN;
}

// Restores blocks after a restart, so a restart is not an unblock.
export function loadBans() {
  for (const b of all('select * from ip_bans where until > ?', now())) bans.set(b.ip, { until: b.until, count: b.count, reason: b.reason });
}
setInterval(() => {
  const t = now(), m = Math.floor(Date.now() / 60000);
  for (const [ip, b] of bans) if (b.until <= t - 7 * 86400) bans.delete(ip); // keep the count a week so repeat offenders escalate
  for (const [ip, l] of strikes) if (!l.some(s => t - s.t < WINDOW)) strikes.delete(ip);
  for (const [ip, b] of budget) if (b.minute < m) budget.delete(ip);
}, 60000).unref();

/* ---------------- audit log ---------------- */
// Security-relevant events and every admin action. Readable by admins; account owners see their own entries.
export function log(action, detail = {}, { actor = null, subject = null } = {}) {
  try { run('insert into audit_log(actor, subject, action, detail, created_at) values(?,?,?,?,?)', actor, subject, action, JSON.stringify(detail).slice(0, 2000), now()); } catch {}
}
export const auditFor = (subject, limit = 50) => all('select action, detail, created_at from audit_log where subject = ? order by id desc limit ?', subject, limit).map(r => ({ ...r, detail: json(r.detail) }));
// Duress Mode entries (actor 'private') are kept out of every list, so nobody can learn from a screen that it is set up.
export const recentAudit = (limit = 200) => all("select actor, subject, action, detail, created_at from audit_log where coalesce(actor, '') != 'private' order by id desc limit ?", limit).map(r => ({ ...r, detail: json(r.detail) }));
export const activeBans = () => [...bans.entries()].filter(([, b]) => b.until > now()).map(([ip, b]) => ({ ip, ...b }));
export const _resetSecurity = () => { strikes.clear(); bans.clear(); budget.clear(); };
export const banCount = () => get('select count(*) n from ip_bans where until > ?', now()).n;
