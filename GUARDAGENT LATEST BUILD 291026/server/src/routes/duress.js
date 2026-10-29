// Duress Mode API: PIN setup, trusted contacts, the vault (real or decoy view) and the contact confirmation page.
import { route, bad, HttpError, rateLimit, requireWallet } from '../http.js';
import { config } from '../config.js';
import { run, get, all, now, json, hashPin, sha256hex } from '../db.js';
import { normalizeAddress, normalizeEmail } from '../access.js';
import { rpcClient } from '../lib/solana.js';
import { evmCall } from '../engines/firewall-evm.js';
import { EVM_CHAINS, ALL_CHAINS } from '../plans.js';
import { log as audit } from '../security.js';
import { duressActive, getDuress, settingsOf, cleanSettings, weakens, validPin, matchPin, trigger, inviteContact, DEFAULT_SETTINGS, WEAKEN_DELAY, MAX_CONTACTS } from '../duress.js';

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function entitled(ctx) {
  const wallet = requireWallet(ctx.req);
  if (!duressActive(wallet)) throw new HttpError(402, 'Duress Mode is not active on this wallet. Buy it from the Services section.');
  return wallet;
}
// One PIN attempt. A slot is reserved atomically BEFORE the (slow, async) hash runs, so parallel guesses can't
// all slip in before the counter moves: at most five answers per lockout window, however many arrive at once.
// The duress PIN is always honoured, even during a lockout, because it is a call for help.
async function pinAttempt(row, pin) {
  const t = now();
  const slot = get('update duress set failed = failed + 1 where wallet = ? and blocked_until <= ? returning failed, lockouts', row.wallet, t);
  const which = await matchPin(row, pin);
  if (which === 'duress') return 'duress';
  if (!slot || slot.failed > 5) return 'blocked';
  if (which === 'real') { run('update duress set failed = 0, lockouts = 0 where wallet = ?', row.wallet); return 'real'; }
  if (slot.failed >= 5) {
    // Five wrong PINs lock the vault; each lockout doubles (15 min, 30 min, 1 h … up to 24 h) until the right PIN is used.
    const lockouts = (slot.lockouts || 0) + 1;
    run('update duress set failed = 0, lockouts = ?, blocked_until = ? where wallet = ?', lockouts, t + Math.min(86400, 900 * 2 ** (lockouts - 1)), row.wallet);
  }
  return 'wrong';
}
// Every settings change needs the real PIN. Entering the duress PIN anywhere also fires the silent alarm, and looks
// exactly like a wrong PIN, so an attacker learns nothing.
async function requireRealPin(ctx, wallet) {
  rateLimit('duresspin:' + wallet, 20);
  const row = getDuress(wallet);
  if (!row) throw new HttpError(404, 'Set up Duress Mode first.');
  const which = await pinAttempt(row, ctx.body.pin);
  if (which === 'duress') { trigger(wallet, { ua: ctx.req.headers['user-agent'], source: 'dashboard' }).catch(() => {}); throw new HttpError(401, "That PIN didn't work."); }
  if (which === 'blocked') throw new HttpError(429, 'Too many attempts. Try again in a few minutes.');
  if (which !== 'real') throw new HttpError(401, "That PIN didn't work.");
  return row;
}
function cleanDecoys(list) {
  if (!Array.isArray(list)) return undefined;
  return list.slice(0, 5).map(d => {
    const chain = String(d?.chain || '').toLowerCase();
    if (!ALL_CHAINS.includes(chain)) throw bad('Pick a supported chain for each decoy wallet.');
    return { chain, address: normalizeAddress(chain, d.address), label: String(d.label || '').replace(/[\u0000-\u001f<>]/g, ' ').slice(0, 40) || 'Wallet' };
  });
}
function view(row) {
  const s = settingsOf(row);
  const p = json(row.pending, null);
  return {
    configured: true, settings: s, lockdownUntil: row.lockdown_until > now() ? row.lockdown_until : null,
    pending: p ? { applyAt: p.applyAt, disable: !!p.disable, settings: p.settings || null } : null,
    contacts: all('select id, name, email, status, remove_at, created_at, confirmed_at from duress_contacts where wallet = ? order by created_at', row.wallet),
    events: all('select kind, data, created_at from duress_events where wallet = ? order by id desc limit 20', row.wallet).map(e => ({ ...e, data: json(e.data) })),
    weakenDelayHours: WEAKEN_DELAY / 3600
  };
}

/* ---------------- status + setup ---------------- */
route('GET', '/api/duress', ctx => {
  const wallet = requireWallet(ctx.req);
  const row = getDuress(wallet);
  return { active: duressActive(wallet), configured: !!row };
});
route('POST', '/api/duress/open', async ctx => view(await requireRealPin(ctx, entitled(ctx))));

route('POST', '/api/duress/setup', async ctx => {
  const wallet = entitled(ctx);
  rateLimit('duresssetup:' + wallet, 10);
  const { realPin, duressPin } = ctx.body;
  if (!validPin(realPin) || !validPin(duressPin)) throw bad('PINs must be 4 to 8 digits.');
  if (String(realPin) === String(duressPin)) throw bad('Your duress PIN must be different from your real PIN.');
  const existing = getDuress(wallet);
  let settings;
  try { settings = cleanSettings({ ...(ctx.body.settings || {}), decoyWallets: cleanDecoys(ctx.body.settings?.decoyWallets) }, existing ? settingsOf(existing) : DEFAULT_SETTINGS); } catch (e) { throw bad(e.message); }
  if (existing) {
    // Changing PINs needs the current real PIN and is not allowed during a lockdown.
    const row = await requireRealPin({ ...ctx, body: { pin: ctx.body.currentPin } }, wallet);
    if (row.lockdown_until > now()) throw new HttpError(423, 'Settings are frozen until the time-lock ends.');
    run('update duress set real_pin = ?, duress_pin = ?, updated_at = ? where wallet = ?', await hashPin(realPin), await hashPin(duressPin), now(), wallet);
  } else {
    if (!settings.decoyWallets.length) throw bad('Add at least one decoy wallet: a wallet with a small balance that the vault shows when you use the duress PIN.');
    run('insert into duress(wallet, real_pin, duress_pin, settings, created_at, updated_at) values(?,?,?,?,?,?)', wallet, await hashPin(realPin), await hashPin(duressPin), JSON.stringify(settings), now(), now());
  }
  run('insert into duress_events(wallet, kind, data, created_at) values(?,?,?,?)', wallet, existing ? 'pins_changed' : 'setup', '{}', now());
  audit(existing ? 'duress_pins_changed' : 'duress_setup', {}, { actor: 'private', subject: 'duress:' + wallet }); // never shown in account activity: it would reveal Duress Mode to an attacker
  return view(getDuress(wallet));
});

route('POST', '/api/duress/settings', async ctx => {
  const wallet = entitled(ctx);
  const row = await requireRealPin(ctx, wallet);
  if (row.lockdown_until > now()) throw new HttpError(423, 'Settings are frozen until the time-lock ends.');
  const cur = settingsOf(row);
  let next;
  try { next = cleanSettings({ ...(ctx.body.settings || {}), decoyWallets: cleanDecoys(ctx.body.settings?.decoyWallets) }, cur); } catch (e) { throw bad(e.message); }
  if (!next.decoyWallets.length) throw bad('Keep at least one decoy wallet.');
  if (weakens(cur, next)) {
    // Less protection only applies after a delay, so nobody can force you to switch it off on the spot.
    run('update duress set pending = ?, updated_at = ? where wallet = ?', JSON.stringify({ settings: next, applyAt: now() + WEAKEN_DELAY }), now(), wallet);
    // The parts that don't weaken anything (decoys, note, name, location) still apply now.
    const safe = { ...next, coolingHours: cur.coolingHours, allowance: cur.allowance };
    run('update duress set settings = ? where wallet = ?', JSON.stringify(safe), wallet);
  } else run('update duress set settings = ?, pending = null, updated_at = ? where wallet = ?', JSON.stringify(next), now(), wallet);
  return view(getDuress(wallet));
});
route('POST', '/api/duress/disable', async ctx => {
  const wallet = entitled(ctx);
  const row = await requireRealPin(ctx, wallet);
  if (row.lockdown_until > now()) throw new HttpError(423, 'Settings are frozen until the time-lock ends.');
  run('update duress set pending = ? where wallet = ?', JSON.stringify({ disable: true, applyAt: now() + WEAKEN_DELAY }), wallet);
  audit('duress_disable_requested', {}, { actor: 'private', subject: 'duress:' + wallet }); // never shown in account activity: it would reveal Duress Mode to an attacker
  return view(getDuress(wallet));
});
route('POST', '/api/duress/cancel-pending', async ctx => {
  const wallet = entitled(ctx);
  await requireRealPin(ctx, wallet);
  run('update duress set pending = null where wallet = ?', wallet);
  run('update duress_contacts set remove_at = null where wallet = ?', wallet);
  return view(getDuress(wallet));
});

/* ---------------- trusted contacts ---------------- */
route('POST', '/api/duress/contacts', async ctx => {
  const wallet = entitled(ctx);
  await requireRealPin(ctx, wallet);
  rateLimit('duressinvite:' + wallet, 6);
  if (!config.resend.key) throw new HttpError(503, 'Email is not switched on for this server yet, so contacts cannot be invited.');
  const to = normalizeEmail(ctx.body.email);
  const name = String(ctx.body.name || '').replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, 60);
  if (!name) throw bad('Add the contact\'s name.');
  if (get('select count(*) c from duress_contacts where wallet = ?', wallet).c >= MAX_CONTACTS) throw bad(`Up to ${MAX_CONTACTS} trusted contacts.`);
  if (get('select 1 from duress_contacts where wallet = ? and email = ?', wallet, to)) throw bad('That contact is already on your list.');
  await inviteContact(wallet, { name, email: to });
  return view(getDuress(wallet));
});
route('DELETE', '/api/duress/contacts/:cid', async ctx => {
  const wallet = entitled(ctx);
  const row = await requireRealPin(ctx, wallet);
  const c = get('select * from duress_contacts where id = ? and wallet = ?', ctx.params.cid, wallet);
  if (!c) throw new HttpError(404, 'Contact not found.');
  if (c.status !== 'confirmed') run('delete from duress_contacts where id = ?', c.id);
  else {
    if (row.lockdown_until > now()) throw new HttpError(423, 'Contacts are frozen until the time-lock ends.');
    run('update duress_contacts set remove_at = ? where id = ?', now() + WEAKEN_DELAY, c.id);
  }
  return view(getDuress(wallet));
});
route('POST', '/api/duress/test', async ctx => {
  const wallet = entitled(ctx);
  const row = await requireRealPin(ctx, wallet);
  rateLimit('duresstest:' + wallet, 2);
  const s = settingsOf(row);
  const contacts = all("select * from duress_contacts where wallet = ? and status = 'confirmed'", wallet);
  if (!contacts.length) throw bad('No confirmed contacts yet. They need to accept the invite email first.');
  const { email } = await import('../notify.js');
  let sent = 0;
  for (const c of contacts) if (await email(c.email, `TEST ONLY: ${s.name || 'A Bodyguard user'}'s emergency alert`,
    `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;line-height:1.5"><h2>This is only a test</h2><p>${esc(s.name || 'Your contact')} is checking that their Bodyguard emergency alerts reach you. Nothing is wrong and you don't need to do anything.</p><p>If a real alert ever arrives, it will say URGENT in the subject.</p></div>`,
    `This is only a test. ${s.name || 'Your contact'} is checking that their Bodyguard emergency alerts reach you. Nothing is wrong.`).catch(() => false)) sent++;
  run('insert into duress_events(wallet, kind, data, created_at) values(?,?,?,?)', wallet, 'test', JSON.stringify({ sent }), now());
  return { sent };
});

/* ---------------- the vault: real or decoy view ---------------- */
const balCache = new Map();
async function balanceOf(chain, address) {
  const key = chain + ':' + address, hit = balCache.get(key);
  if (hit && Date.now() - hit.at < 60000) return hit.v;
  let v = null;
  try {
    if (chain === 'solana' && config.solana.rpc) v = (await rpcClient(config.solana.rpc).getBalance(address)) / 1e9;
    else if (EVM_CHAINS.includes(chain)) { const r = await evmCall(chain, 'eth_getBalance', [address, 'latest']); v = r == null ? null : Number(BigInt(r)) / 1e18; }
    else if (chain === 'bitcoin') { const r = await fetch(`${config.btcApi}/address/${address}`, { signal: AbortSignal.timeout(10000) }).then(x => x.json()); v = (r.chain_stats.funded_txo_sum - r.chain_stats.spent_txo_sum) / 1e8; }
  } catch { v = null; }
  balCache.set(key, { v, at: Date.now() });
  if (balCache.size > 5000) balCache.clear();
  return v;
}
const SYMBOL = { solana: 'SOL', ethereum: 'ETH', base: 'ETH', arbitrum: 'ETH', optimism: 'ETH', polygon: 'POL', bnb: 'BNB', bitcoin: 'BTC' };
async function walletsView(list) {
  return Promise.all(list.slice(0, 20).map(async w => ({ label: w.label || 'Wallet', chain: w.chain, address: w.address, symbol: SYMBOL[w.chain], balance: await balanceOf(w.chain, w.address) })));
}

route('POST', '/api/duress/vault', async ctx => {
  const wallet = requireWallet(ctx.req);
  rateLimit('vault:' + wallet, 20);
  const row = getDuress(wallet);
  if (!row) throw new HttpError(404, 'This vault is not set up.');
  const s = settingsOf(row);
  const which = await pinAttempt(row, ctx.body.pin);
  if (which === 'duress') {
    // Silent: the response looks exactly like a normal unlock, just with the decoy wallets.
    trigger(wallet, { ua: ctx.req.headers['user-agent'], location: ctx.body.location, source: 'vault' }).catch(e => console.warn('[duress]', e.message));
    return { wallets: await walletsView(s.decoyWallets) };
  }
  if (which === 'blocked') throw new HttpError(429, 'Too many attempts. Try again in a few minutes.');
  if (which !== 'real') throw new HttpError(401, "That PIN didn't work.");
  const real = all(`select distinct x.chain, x.value address, x.label from assets x join members m on m.agent_id = x.agent_id
    where m.wallet = ? and x.type = 'wallet' and x.internal = 0 and x.enabled = 1 order by x.created_at`, wallet);
  const seen = new Set(real.map(r => r.chain + r.address));
  const list = [...real, ...s.decoyWallets.filter(d => !seen.has(d.chain + d.address))];
  return { wallets: await walletsView(list) };
});

/* ---------------- contact confirmation page ---------------- */
const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)}</title>
<style>body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0a0d0b;color:#e3ebe5;line-height:1.55}main{max-width:520px;margin:10vh auto;padding:0 18px}
.k{font:12px ui-monospace,Menlo,monospace;letter-spacing:.14em;color:#c8ff1a;text-transform:uppercase}h1{font-size:26px;margin:10px 0}button{background:#c8ff1a;color:#121a00;border:0;border-radius:10px;padding:12px 18px;font-weight:700;font-size:15px;cursor:pointer;margin-right:8px}
button.g{background:none;color:#e3ebe5;border:1px solid #33423a}</style></head><body><main><div class="k">Bodyguard · Emergency contact</div>${body}</main></body></html>`;
const contactByToken = token => get('select c.*, d.settings from duress_contacts c left join duress d on d.wallet = c.wallet where c.token_hash = ?', sha256hex(String(token || '')));

// GET only shows the page: email link scanners open links automatically, so accepting needs a real button press.
route('GET', '/duress/confirm/:token', ctx => {
  const c = contactByToken(ctx.params.token);
  if (!c) return { __html: page('Link expired', '<h1>This link has expired.</h1><p>Ask the person to invite you again.</p>'), status: 404 };
  const who = esc(settingsOf({ settings: c.settings }).name || 'A Bodyguard user');
  const form = a => `<form method="post" style="display:inline"><input type="hidden" name="action" value="${a}"><button${a === 'stop' ? ' class="g"' : ''}>${a === 'accept' ? 'Accept' : 'Stop being a contact'}</button></form>`;
  return { __html: page('Emergency contact', c.status === 'confirmed'
    ? `<h1>You're ${who}'s emergency contact</h1><p>If they enter their secret emergency PIN, you'll get an email marked URGENT with the time and, if they chose to share it, their location.</p>${form('stop')}`
    : `<h1>Be ${who}'s emergency contact?</h1><p>${who} uses Bodyguard to protect their crypto. If someone ever forces them to hand it over, they can enter a secret PIN that silently emails you so you can get help.</p><p>We only email you if that happens. We never ask you for money or anything else.</p>${form('accept')}`), headers: { 'cache-control': 'no-store', 'x-robots-tag': 'noindex' } };
});
route('POST', '/duress/confirm/:token', ctx => {
  rateLimit('dconfirm:' + ctx.ip, 20);
  const c = contactByToken(ctx.params.token);
  if (!c) return { __html: page('Link expired', '<h1>This link has expired.</h1>'), status: 404 };
  if (ctx.body.action === 'stop') {
    run('delete from duress_contacts where id = ?', c.id);
    return { __html: page('Removed', '<h1>Done. You are no longer an emergency contact.</h1>') };
  }
  run("update duress_contacts set status = 'confirmed', confirmed_at = ? where id = ?", now(), c.id);
  return { __html: page('Thank you', '<h1>Thank you. You are now an emergency contact.</h1><p>Keep this email. You can come back to this link to stop at any time.</p>') };
});
