// SQLite storage using Node's built-in driver. One file, no external database needed.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';

const SCHEMA = `
pragma journal_mode = wal;
pragma foreign_keys = on;
create table if not exists kv(k text primary key, v text);
create table if not exists agents(id text primary key, owner text not null, rank text not null, status text not null default 'active',
  created_at integer, expires_at integer, settings text default '{}');
create index if not exists agents_owner on agents(owner);
create table if not exists members(agent_id text, wallet text, role text default 'member', primary key(agent_id, wallet));
create table if not exists payments(signature text primary key, wallet text, kind text, item text, lamports integer, guard_raw text,
  slot integer, created_at integer, agent_id text, org_id text);
create table if not exists sessions(token_hash text primary key, wallet text, created_at integer, expires_at integer);
create table if not exists nonces(nonce text primary key, wallet text, message text, created_at integer);
create index if not exists nonces_wallet on nonces(wallet, created_at);
create table if not exists assets(id integer primary key autoincrement, agent_id text, type text, chain text, value text, label text,
  created_at integer, state text default '{}', enabled integer default 1, internal integer default 0);
create unique index if not exists assets_uniq on assets(agent_id, type, chain, value);
create table if not exists counterparties(agent_id text, chain text, address text, label text, source text, count integer default 1,
  first_seen integer, last_seen integer, primary key(agent_id, chain, address));
create table if not exists poison_tags(agent_id text, chain text, address text, imitates text, label text, created_at integer,
  primary key(agent_id, chain, address));
create table if not exists alerts(id integer primary key autoincrement, subject text, severity text, type text, title text, what text,
  did text, move text, data text, dedupe text, created_at integer, acked_at integer, delivered text default '{}', escalations integer default 0);
create unique index if not exists alerts_dedupe on alerts(dedupe) where dedupe is not null;
create index if not exists alerts_subject on alerts(subject, created_at);
create table if not exists channels(subject text primary key, telegram_chat_id text, alert_email text, link_code text);
create table if not exists push_subs(id integer primary key autoincrement, subject text, endpoint text unique, p256dh text, auth text, created_at integer);
create table if not exists oauth_tokens(asset_id integer primary key, provider text, enc text, updated_at integer);
create table if not exists oauth_states(state text primary key, asset_id integer, provider text, created_at integer);
create table if not exists pair_codes(code text primary key, agent_id text, wallet text, created_at integer);
create table if not exists ext_tokens(token_hash text primary key, agent_id text, wallet text, created_at integer, last_used integer);
create table if not exists orgs(id text primary key, owner text, name text, services text default '{}', created_at integer,
  verified_domains text default '[]', domain_tokens text default '{}');
create table if not exists org_members(org_id text, wallet text, role text default 'member', primary key(org_id, wallet));
create table if not exists api_keys(key_hash text primary key, org_id text, label text, prefix text, created_at integer, last_used integer, revoked integer default 0);
create table if not exists screen_cache(chain text, address text, result text, created_at integer, primary key(chain, address));
create table if not exists screen_log(id integer primary key autoincrement, org_id text, chain text, address text, score integer, created_at integer);
create table if not exists guarded_wallets(id text primary key, org_id text, name text, multisig text, vault text, create_key text,
  members text, threshold integer, time_lock integer, policy text, status text, created_at integer, state text default '{}');
create table if not exists policy_log(id integer primary key autoincrement, org_id text, wallet_id text, decision text, reasons text, request text, created_at integer);
create table if not exists treasuries(id text primary key, org_id text, chain text, kind text, address text, name text, policy text,
  signers text, state text default '{}', created_at integer);
create table if not exists drills(id text primary key, org_id text, name text, channel text, template text, status text,
  created_at integer, sent_at integer, settings text default '{}');
create table if not exists drill_targets(token text primary key, drill_id text, email text, name text, sent_at integer, opened_at integer,
  clicked_at integer, submitted_at integer, trained_at integer, quiz_score integer);
create table if not exists drill_events(id integer primary key autoincrement, token text, kind text, created_at integer, ip text, ua text);
create table if not exists lists(name text primary key, data text, updated_at integer);
create table if not exists processed(sig text, asset_id integer, created_at integer, primary key(sig, asset_id));

create table if not exists duress(wallet text primary key, real_pin text, duress_pin text, settings text default '{}', lockdown_until integer default 0,
  pending text, failed integer default 0, blocked_until integer default 0, created_at integer, updated_at integer);
create table if not exists duress_contacts(id text primary key, wallet text, name text, email text, status text default 'pending', token_hash text,
  remove_at integer, created_at integer, confirmed_at integer);
create index if not exists duress_contacts_wallet on duress_contacts(wallet);
create table if not exists duress_events(id integer primary key autoincrement, wallet text, kind text, data text, created_at integer);

create table if not exists incidents(id text primary key, org_id text, wallet text, status text default 'open', title text, manifest text,
  manifest_hash text, server_sig text, anchor_sig text, data text default '{}', trace text default '{}', created_at integer, updated_at integer);
create index if not exists incidents_org on incidents(org_id, created_at);
create unique index if not exists incidents_hash on incidents(manifest_hash);
create table if not exists incident_files(id text primary key, incident_id text, name text, type text, size integer, sha256 text, enc blob, created_at integer);
create table if not exists incident_requests(id text primary key, incident_id text, target text, channel text, status text, subject text, body text,
  sent_at integer, error text, created_at integer);
create table if not exists incident_events(id integer primary key autoincrement, incident_id text, kind text, text text, data text, created_at integer);

create table if not exists tickets(id text primary key, ref text unique, name text, email text, wallet text, topic text, subject text, message text,
  status text default 'open', ip_hash text, created_at integer, updated_at integer);
create table if not exists ticket_messages(id integer primary key autoincrement, ticket_id text, author text, body text, created_at integer);

create table if not exists ip_bans(ip text primary key, until integer, count integer default 1, reason text, created_at integer);
create table if not exists audit_log(id integer primary key autoincrement, actor text, subject text, action text, detail text, created_at integer);
create index if not exists audit_subject on audit_log(subject, id);
`;

fs.mkdirSync(config.dataDir, { recursive: true });
export const db = new DatabaseSync(process.env.DB_FILE || path.join(config.dataDir, 'bodyguard.db'));
db.exec(SCHEMA);
// Columns added after a release: added in place on existing databases (safe to run every start).
const addColumn = (table, col, def) => { try { db.exec(`alter table ${table} add column ${col} ${def}`); } catch (e) { if (!/duplicate column/i.test(e.message)) throw e; } };
addColumn('duress', 'lockouts', 'integer default 0');
addColumn('sessions', 'ua', 'text');
addColumn('sessions', 'ip', 'text');
addColumn('sessions', 'last_seen', 'integer');
addColumn('sessions', 'id', 'text');
db.exec('create index if not exists sessions_wallet on sessions(wallet)');

export const run = (sql, ...p) => db.prepare(sql).run(...p);
export const get = (sql, ...p) => db.prepare(sql).get(...p);
export const all = (sql, ...p) => db.prepare(sql).all(...p);
export function tx(fn) {
  db.exec('begin');
  try { const r = fn(); db.exec('commit'); return r; } catch (e) { db.exec('rollback'); throw e; }
}

export const now = () => Math.floor(Date.now() / 1000);
export const json = (s, d = {}) => { try { return s ? JSON.parse(s) : d; } catch { return d; } };
export const kvGet = (k, d = null) => { const r = get('select v from kv where k = ?', k); return r ? json(r.v, d) : d; };
export const kvSet = (k, v) => run('insert into kv(k, v) values(?, ?) on conflict(k) do update set v = excluded.v', k, JSON.stringify(v));

export const sha256hex = s => crypto.createHash('sha256').update(s).digest('hex');
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

// AES-256-GCM for OAuth tokens at rest.
const encKey = () => crypto.createHash('sha256').update('bodyguard-enc:' + config.appSecret).digest();
export function encrypt(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', encKey(), iv);
  const data = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), data]).toString('base64');
}
export function decrypt(b64) {
  const b = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', encKey(), b.subarray(0, 12), { authTagLength: 16 });
  d.setAuthTag(b.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'));
}
// Same scheme for raw bytes (evidence files).
export function encryptBuf(buf) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', encKey(), iv);
  const data = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), data]);
}
export function decryptBuf(b) {
  b = Buffer.from(b);
  const d = crypto.createDecipheriv('aes-256-gcm', encKey(), b.subarray(0, 12), { authTagLength: 16 });
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]);
}

// Slow, salted hash for short secrets such as PINs. Returns "salt:hash" (hex). It runs on the thread pool
// (async scrypt), so a PIN check never freezes the server for everyone else.
const SCRYPT = { N: 16384, r: 8, p: 1 };
const scryptAsync = (pin, salt) => new Promise((res, rej) => crypto.scrypt(String(pin), 'bodyguard-pin:' + salt, 32, SCRYPT, (e, k) => (e ? rej(e) : res(k))));
export async function hashPin(pin, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${(await scryptAsync(pin, salt)).toString('hex')}`;
}
export async function checkPin(pin, stored) {
  if (!stored || !stored.includes(':')) { await hashPin(pin); return false; } // same work either way
  const [salt, h] = stored.split(':');
  const got = await scryptAsync(pin, salt);
  const want = Buffer.from(h, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
