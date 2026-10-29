// Duress Mode: protection against physical coercion ("wrench attacks").
//
// The account holder sets two PINs. The real PIN opens the vault view of their wallets. The duress PIN opens a
// decoy view that only shows the small wallets they chose, and silently:
//   1. alerts their trusted contacts (who confirmed by email in advance) with the time, device and, if they opted
//      in, their location;
//   2. starts a lockdown: for the cooling-off period Bodyguard blocks large transfers everywhere it sits in the
//      signing path (Bodyguard Shield in the browser, Guarded Wallets policy checks). The lockdown cannot be
//      lifted early, by anyone, so forcing the victim to "turn it off" achieves nothing.
// Nothing about a duress trigger is ever sent to the victim's own channels, because the attacker may be holding
// their phone. Changes that weaken the protection only take effect 24 hours later for the same reason.
import crypto from 'node:crypto';
import { config } from './config.js';
import { run, get, all, now, json, hashPin, checkPin, sha256hex, randomToken } from './db.js';
import { email } from './notify.js';
import { ownedOrg } from './access.js';
import { serviceActive } from './payments.js';

export const WEAKEN_DELAY = 24 * 3600;
export const MAX_CONTACTS = 5;
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const DEFAULT_SETTINGS = { coolingHours: 24, allowance: { solana: 0.1, evm: 0.01 }, decoyWallets: [], shareLocation: false, message: '', name: '' };

export const duressActive = wallet => serviceActive(ownedOrg(wallet), 'duress');
export const getDuress = wallet => get('select * from duress where wallet = ?', wallet);

export function settingsOf(row) { return { ...DEFAULT_SETTINGS, ...json(row?.settings), allowance: { ...DEFAULT_SETTINGS.allowance, ...(json(row?.settings).allowance || {}) } }; }

/** Seconds-since-epoch the lockdown runs until for any of these wallets, or 0. */
export function lockdownUntil(wallets) {
  let until = 0;
  for (const w of new Set(wallets.filter(Boolean))) {
    const r = get('select lockdown_until from duress where wallet = ?', w);
    if (r?.lockdown_until > now()) until = Math.max(until, r.lockdown_until);
  }
  return until;
}
export function lockdownForAgent(agent) {
  if (!agent) return { until: 0 };
  const wallets = [agent.owner, ...all('select wallet from members where agent_id = ?', agent.id).map(m => m.wallet)];
  const until = lockdownUntil(wallets);
  if (!until) return { until: 0 };
  const row = get('select * from duress where wallet in (' + wallets.map(() => '?').join(',') + ') and lockdown_until = ?', ...wallets, until);
  return { until, settings: settingsOf(row) };
}

/* ---------------- validation ---------------- */
export function validPin(p) { return /^\d{4,8}$/.test(String(p || '')); }

export function cleanSettings(input = {}, prev = DEFAULT_SETTINGS) {
  const s = { ...prev, allowance: { ...prev.allowance } };
  if (input.coolingHours != null) {
    const h = Math.round(Number(input.coolingHours));
    if (!Number.isFinite(h) || h < 1 || h > 168) throw new Error('Cooling-off must be between 1 and 168 hours.');
    s.coolingHours = h;
  }
  if (input.allowance) {
    for (const k of ['solana', 'evm']) if (input.allowance[k] != null) {
      const v = Number(input.allowance[k]);
      if (!Number.isFinite(v) || v < 0 || v > 1e6) throw new Error('Allowance must be a positive number.');
      s.allowance[k] = v;
    }
  }
  if (Array.isArray(input.decoyWallets)) s.decoyWallets = input.decoyWallets.slice(0, 5);
  if (input.shareLocation != null) s.shareLocation = !!input.shareLocation;
  if (input.message != null) s.message = String(input.message).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 280);
  if (input.name != null) s.name = String(input.name).replace(/[\u0000-\u001f\u007f<>]/g, ' ').trim().slice(0, 60);
  return s;
}

/** True if `next` gives less protection than `cur` (so it must wait WEAKEN_DELAY). */
export function weakens(cur, next) {
  return next.coolingHours < cur.coolingHours || next.allowance.solana > cur.allowance.solana || next.allowance.evm > cur.allowance.evm;
}

/* ---------------- PIN check (constant work for every outcome) ---------------- */
export async function matchPin(row, pin) {
  const [real, duress] = await Promise.all([checkPin(pin, row?.real_pin), checkPin(pin, row?.duress_pin)]);
  return real ? 'real' : duress ? 'duress' : null;
}

/* ---------------- the trigger ---------------- */
export async function trigger(wallet, { ua = '', location = null, source = 'vault' } = {}) {
  const row = getDuress(wallet);
  if (!row) return;
  const s = settingsOf(row);
  const t = now();
  const until = Math.max(row.lockdown_until || 0, t + s.coolingHours * 3600);
  run('update duress set lockdown_until = ?, updated_at = ? where wallet = ?', until, t, wallet);
  const loc = s.shareLocation && location && Number.isFinite(+location.lat) && Number.isFinite(+location.lng)
    ? { lat: +(+location.lat).toFixed(5), lng: +(+location.lng).toFixed(5), acc: Math.round(+location.acc || 0) } : null;
  run('insert into duress_events(wallet, kind, data, created_at) values(?,?,?,?)', wallet, 'triggered', JSON.stringify({ source, ua: String(ua).slice(0, 200), location: loc, until }), t);
  const contacts = all("select * from duress_contacts where wallet = ? and status = 'confirmed'", wallet);
  await Promise.all(contacts.map(c => email(c.email, `URGENT: ${s.name || 'Someone you know'} may need help`, duressEmailHtml(s, c, { t, ua, loc, until }), duressEmailText(s, c, { t, ua, loc, until }), config.resend.from).catch(() => false)));
  return { until };
}

const whenUtc = t => new Date(t * 1000).toUTCString().replace(' GMT', ' UTC');
function deviceOf(ua) {
  ua = String(ua);
  const os = /iPhone|iPad/.test(ua) ? 'iPhone/iPad' : /Android/.test(ua) ? 'Android phone' : /Mac OS X/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows PC' : /Linux/.test(ua) ? 'Linux computer' : 'unknown device';
  return os;
}
function duressEmailText(s, c, { t, ua, loc, until }) {
  return [`${s.name || 'A person who listed you as a trusted contact'} entered their emergency PIN in Bodyguard at ${whenUtc(t)}.`,
    'This is a silent signal that they may be being forced to hand over money or crypto.',
    loc ? `Approximate location: ${loc.lat}, ${loc.lng} (within ~${loc.acc || '?'} m) https://www.openstreetmap.org/?mlat=${loc.lat}&mlon=${loc.lng}#map=17/${loc.lat}/${loc.lng}` : 'No location was shared.',
    `Device: ${deviceOf(ua)}.`, s.message ? `Their note to you: ${s.message}` : '',
    'What to do: think before calling or messaging them, because someone may be with them and watching their phone. If you believe they are in danger, contact local emergency services (999 in the UK, 911 in the US, 112 in the EU) and give them the details above.',
    `Their large transfers protected by Bodyguard are locked until ${whenUtc(until)}.`, 'Bodyguard will never ask you for money, a seed phrase or a private key.'].filter(Boolean).join('\n\n');
}
function duressEmailHtml(s, c, ctx) {
  const lines = duressEmailText(s, c, ctx).split('\n\n');
  return `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#0a0d0b;color:#e3ebe5;padding:24px;border-radius:12px">
  <div style="font-size:12px;letter-spacing:.12em;color:#ff5a6b">BODYGUARD · EMERGENCY SIGNAL</div>
  <h2 style="margin:10px 0 14px;font-size:22px">${esc(s.name || 'Someone you know')} may need help</h2>
  ${lines.map(l => `<p style="margin:0 0 12px;line-height:1.5">${esc(l).replace(/(https:\/\/www\.openstreetmap\.org\/[^\s<]+)/, '<a href="$1" style="color:#c8ff1a">Open map</a>')}</p>`).join('')}
  <p style="font-size:11px;color:#8c998f;margin-top:20px">You get this because ${esc(s.name || 'they')} added you as a trusted contact and you confirmed it.</p></div>`;
}

/* ---------------- trusted contacts ---------------- */
export async function inviteContact(wallet, { name, email: to }) {
  const s = settingsOf(getDuress(wallet));
  const token = randomToken(24);
  const id = 'dc_' + crypto.randomBytes(6).toString('hex');
  run('insert into duress_contacts(id, wallet, name, email, status, token_hash, created_at) values(?,?,?,?,?,?,?)', id, wallet, name, to, 'pending', sha256hex(token), now());
  const link = `${config.publicUrl}/duress/confirm/${token}`;
  const who = s.name || 'A Bodyguard user';
  await email(to, `${who} asked you to be their emergency contact`,
    `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;line-height:1.5"><h2 style="margin:0 0 12px">Will you be ${esc(who)}'s emergency contact?</h2>
    <p>${esc(who)} uses Bodyguard to protect their crypto. If they are ever forced to hand it over, they can enter a secret PIN that silently sends you an alert, so you can get help.</p>
    <p>You will only hear from us if that happens. You can stop at any time.</p>
    <p><a href="${link}" style="display:inline-block;background:#c8ff1a;color:#121a00;padding:12px 18px;border-radius:8px;text-decoration:none;font-weight:bold">Review and accept</a></p>
    <p style="font-size:12px;color:#666">If you don't know this person, ignore this email and nothing will happen. Bodyguard will never ask you for money, a seed phrase or a private key.</p></div>`,
    `${who} asked you to be their emergency contact on Bodyguard. If they are ever forced to hand over their crypto, they can silently alert you. Review and accept: ${link}\n\nIf you don't know them, ignore this email.`);
  return id;
}

/* ---------------- housekeeping: apply delayed changes ---------------- */
export function applyPending() {
  const t = now();
  for (const r of all('select * from duress where pending is not null')) {
    const p = json(r.pending, null);
    if (!p || p.applyAt > t) continue;
    if (r.lockdown_until > t) continue; // never weaken during a lockdown
    if (p.disable) {
      run('delete from duress where wallet = ?', r.wallet);
      run('delete from duress_contacts where wallet = ?', r.wallet);
      run('insert into duress_events(wallet, kind, data, created_at) values(?,?,?,?)', r.wallet, 'disabled', '{}', t);
    } else {
      run('update duress set settings = ?, pending = null, updated_at = ? where wallet = ?', JSON.stringify(p.settings), t, r.wallet);
      run('insert into duress_events(wallet, kind, data, created_at) values(?,?,?,?)', r.wallet, 'settings_applied', '{}', t);
    }
  }
  for (const c of all('select * from duress_contacts where remove_at is not null and remove_at <= ?', t)) {
    const r = getDuress(c.wallet);
    if (r?.lockdown_until > t) continue;
    run('delete from duress_contacts where id = ?', c.id);
  }
  run("delete from duress_contacts where status = 'pending' and created_at < ?", t - 14 * 86400);
}

/* ---------------- firewall gate ---------------- */
const MOVE_CODES = new Set(['delegate', 'approve', 'unlimited_approval', 'set_authority', 'assign', 'owner_change', 'drain_sol', 'drain_tokens', 'token_out',
  'close_to_other', 'eoa_spender', 'blocked_spender', 'known_spender', 'permit', 'permit_batch', 'free_listing', 'eth_sign', 'blind_hash', 'decode_error', 'sim_unavailable',
  'unknown_spender', 'permit_transfer', 'large_sol_out', 'poison', 'sanctioned', 'blocked_to', 'batch_too_big']);
const num = s => Number(String(s).replace(/,/g, ''));

/** During a lockdown, turns any transaction that moves more than the allowance (or any token/approval) into a hard
 *  block. It fails closed: anything that could not be simulated or decoded is held too. */
export function gateFirewall(result, lock, family) {
  if (!lock?.until) return result;
  const allowance = family === 'solana' ? lock.settings.allowance.solana : lock.settings.allowance.evm;
  const flows = result.flows || {};
  let nativeOut = Number(flows.nativeOut) || 0, other = false;
  for (const line of result.summary || []) {
    const m = String(line).match(/^Sends ([\d.,]+) (SOL|native coin) to /);
    if (m) nativeOut = Math.max(nativeOut, num(m[1]));
    else other = true; // token transfers, approvals, permits, listings
  }
  if ((result.reasons || []).some(r => MOVE_CODES.has(r.code))) other = true;
  if (flows.tokenOut || flows.contractCall) other = true;
  if (family === 'solana' && !flows.simulated) other = true;
  if (!other && nativeOut <= allowance) return { ...result, lockdown: { until: lock.until } };
  const until = new Date(lock.until * 1000);
  return {
    action: 'block', locked: true, lockdown: { until: lock.until },
    reasons: [{ severity: 'crit', code: 'duress_lockdown', text: `Security time-lock is active until ${until.toUTCString().slice(17, 22)} UTC on ${until.toUTCString().slice(0, 11)}. Transfers above the safe limit are held until then. Nobody can shorten or switch off the time-lock, including Bodyguard.` }, ...(result.reasons || [])],
    summary: result.summary || []
  };
}
