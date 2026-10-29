// Who can touch what: agents (owner + team seats), orgs (business services), extension tokens, admins.
import { get, all, sha256hex, now, run } from './db.js';
import { HttpError, requireWallet, sessionInfo } from './http.js';
import { agentActive, serviceActive } from './payments.js';
import { config } from './config.js';
import { isValidPubkey } from './lib/solana.js';

export function agentForWallet(wallet, agentId, { write = false, allowExpired = false } = {}) {
  const a = get('select * from agents where id = ?', agentId);
  if (!a) throw new HttpError(404, 'Agent not found.');
  const m = get('select role from members where agent_id = ? and wallet = ?', agentId, wallet);
  if (!m && a.owner !== wallet && !isAdmin(wallet)) throw new HttpError(403, 'This wallet is not on that agent.');
  if (write && m?.role === 'member') throw new HttpError(403, 'Only the agent owner can change this.');
  if (!allowExpired && !agentActive(a)) throw new HttpError(402, 'This agent is off duty. Renew your rank to switch it back on.');
  return a;
}
export function requireAgent(ctx, opts) { return agentForWallet(requireWallet(ctx.req), ctx.params.id, opts); }

export function agentsOfWallet(wallet) {
  return all(`select a.*, m.role from agents a join members m on m.agent_id = a.id where m.wallet = ? order by a.created_at`, wallet);
}

// Personal-safety services belong to the person who bought them. They only ever count on an organisation the
// wallet owns, never on one someone else added it to (anyone can be added to an org without agreeing).
export const PERSONAL_SERVICES = new Set(['duress', 'freeze']);
// The wallet's own organisation always comes first; organisations it was added to come after.
export function orgsForWallet(wallet) {
  return all(`select o.*, m.role from orgs o join org_members m on m.org_id = o.id where m.wallet = ? order by (o.owner = ?) desc, o.created_at`, wallet, wallet);
}
export function orgForWallet(wallet) { return orgsForWallet(wallet)[0] || null; }
export const ownedOrg = wallet => get(`select o.*, 'owner' role from orgs o where o.owner = ? order by o.created_at limit 1`, wallet) || null;
export function requireOrg(ctx, service) {
  const wallet = requireWallet(ctx.req);
  if (service && PERSONAL_SERVICES.has(service)) {
    const own = ownedOrg(wallet);
    if (!own || !serviceActive(own, service)) throw new HttpError(402, 'That service is not active on your wallet.');
    return { org: own, wallet };
  }
  const orgs = orgsForWallet(wallet);
  if (!orgs.length) throw new HttpError(403, 'Buy a business service to open this console.');
  const org = service ? orgs.find(o => serviceActive(o, service)) : orgs[0];
  if (!org) throw new HttpError(402, 'That service is not active on your organisation.');
  return { org, wallet };
}

// API key (Risk Screening) -> org
export function requireApiKey(ctx, service) {
  const key = ctx.req.headers['x-api-key'] || '';
  const k = key && get('select * from api_keys where key_hash = ? and revoked = 0', sha256hex(key));
  if (!k) throw new HttpError(401, 'Missing or invalid API key.');
  const org = get('select * from orgs where id = ?', k.org_id);
  if (!serviceActive(org, service)) throw new HttpError(402, 'Risk Screening is not active for this key.');
  run('update api_keys set last_used = ? where key_hash = ?', now(), k.key_hash);
  return org;
}

// Extension token or dashboard session -> agent
export function agentFromAnyAuth(ctx) {
  const h = ctx.req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (tok.startsWith('ext_')) {
    const t = get('select * from ext_tokens where token_hash = ?', sha256hex(tok));
    if (!t) throw new HttpError(401, 'This extension is not paired. Pair it again from your dashboard.');
    // The wallet that paired this browser must still be on the agent.
    const ag = get('select owner from agents where id = ?', t.agent_id);
    if (!ag || (ag.owner !== t.wallet && !get('select 1 from members where agent_id = ? and wallet = ?', t.agent_id, t.wallet))) {
      run('delete from ext_tokens where token_hash = ?', t.token_hash);
      throw new HttpError(401, 'This extension is not paired. Pair it again from your dashboard.');
    }
    run('update ext_tokens set last_used = ? where token_hash = ?', now(), t.token_hash);
    const a = get('select * from agents where id = ?', t.agent_id);
    if (!agentActive(a)) throw new HttpError(402, 'Your agent is off duty. Renew your rank to switch protection back on.');
    return a;
  }
  const wallet = requireWallet(ctx.req);
  const id = ctx.body?.agentId || ctx.query?.agentId || agentsOfWallet(wallet)[0]?.id;
  if (!id) throw new HttpError(403, 'Hire an agent to use this.');
  return agentForWallet(wallet, id);
}

export const isAdmin = w => config.adminWallets.includes(w);
// Admin tools need an admin wallet AND a sign-in from the last 12 hours, so an old or stolen long-lived session
// can't be used for admin actions.
export function requireAdmin(ctx) {
  const s = sessionInfo(ctx.req);
  if (!s) throw new HttpError(401, 'Sign in with your wallet first.');
  if (!isAdmin(s.wallet)) throw new HttpError(403, 'Admins only.');
  if (now() - s.created_at > 12 * 3600) throw new HttpError(401, 'Sign in again to use admin tools (admin sessions last 12 hours).');
  return s.wallet;
}

/* -------- validation -------- */
export function normalizeAddress(chain, value) {
  const v = String(value || '').trim();
  if (chain === 'solana') { if (!isValidPubkey(v)) throw new HttpError(400, "That isn't a valid Solana address."); return v; }
  if (chain === 'bitcoin') {
    if (!/^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(v)) throw new HttpError(400, "That isn't a valid Bitcoin address.");
    return v;
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(v)) throw new HttpError(400, "That isn't a valid EVM address (0x followed by 40 characters).");
  return v.toLowerCase();
}
export function normalizeEmail(v) {
  const s = String(v || '').trim().toLowerCase();
  // Plain addresses only: no quotes, brackets, commas or other characters that change meaning in a mail header.
  if (s.length > 254 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$/.test(s)) throw new HttpError(400, "That isn't a valid email address.");
  return s;
}
export function normalizeDomain(v) {
  let s = String(v || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
  if (!/^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(s)) throw new HttpError(400, "That isn't a valid domain.");
  return s;
}
export function normalizeHandle(v) {
  const s = String(v || '').trim().replace(/^@/, '');
  if (!/^[\w.-]{2,40}$/.test(s)) throw new HttpError(400, 'Handles can use letters, numbers, dots, dashes and underscores.');
  return s;
}
