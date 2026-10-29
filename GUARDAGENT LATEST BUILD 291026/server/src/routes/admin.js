// Admin tools (wallets in ADMIN_WALLETS): stats, threat-list additions, manual grants for support cases.
import { route, bad, rateLimit, ipOf } from '../http.js';
import { log as audit, recentAudit, activeBans, ban, unban } from '../security.js';
import { isPrivateIp } from '../lib/net.js';
import { all, get } from '../db.js';
import { requireAdmin } from '../access.js';
import { addCustom, listStats, refreshLists } from '../engines/lists.js';
import { grantRank, grantService } from '../payments.js';
import { isValidPubkey } from '../lib/solana.js';
import { capacity } from '../capacity.js';

route('GET', '/api/admin/stats', ctx => {
  requireAdmin(ctx);
  return {
    agents: all("select rank, count(*) n from agents where status = 'active' group by rank"),
    assets: all('select type, chain, count(*) n from assets group by type, chain'),
    alerts24h: all("select severity, count(*) n from alerts where created_at > strftime('%s','now') - 86400 group by severity"),
    payments: get('select count(*) n, sum(lamports) lamports from payments'),
    orgs: get('select count(*) n from orgs').n,
    lists: listStats(),
    capacity: capacity(),
    tickets: all('select status, count(*) n from tickets group by status'),
    freezeCases: get("select count(*) n from incidents where status = 'open'").n,
    duressAccounts: get('select count(*) n from duress').n
  };
});
route('POST', '/api/admin/lists', async ctx => {
  ctx.adminWallet = requireAdmin(ctx);
  const { kind, values } = ctx.body;
  if (!Array.isArray(values) || !values.length) throw bad('Send values: [...]');
  let size; try { size = addCustom(kind, values.map(String).slice(0, 5000)); } catch (e) { throw bad('kind must be solana, evm, program or domain.'); }
  audit('admin_lists', { kind, count: values.length }, { actor: ctx.adminWallet, subject: 'admin' });
  return { size };
}, { limit: 600_000 });
route('POST', '/api/admin/lists/refresh', async ctx => { requireAdmin(ctx); rateLimit('listrefresh', 2); await refreshLists(); return listStats(); });
route('POST', '/api/admin/grant', ctx => {
  const admin = requireAdmin(ctx);
  const { wallet, kind, id } = ctx.body;
  if (!isValidPubkey(String(wallet || ''))) throw bad('Invalid wallet.');
  const out = kind === 'service' ? grantService(wallet, String(id)) : grantRank(wallet, String(id));
  audit('admin_grant', { wallet, kind, id: String(id) }, { actor: admin, subject: 'admin' });
  return out;
});

/* ---------------- active defences ---------------- */
route('GET', '/api/admin/security', ctx => {
  requireAdmin(ctx);
  return { bans: activeBans(), audit: recentAudit(300) };
});
route('POST', '/api/admin/security/ban', ctx => {
  const admin = requireAdmin(ctx);
  const ip = String(ctx.body.ip || '').trim();
  if (!ip || isPrivateIp(ip)) throw bad('Give a public IP address.');
  ban(ip, 'manual: ' + String(ctx.body.reason || 'admin').slice(0, 100), Math.max(60, Math.min(30 * 86400, Number(ctx.body.minutes || 60) * 60)));
  audit('admin_ban', { ip }, { actor: admin, subject: 'admin' });
  return { bans: activeBans() };
});
route('POST', '/api/admin/security/unban', ctx => {
  const admin = requireAdmin(ctx);
  const ip = String(ctx.body.ip || '').trim().slice(0, 64);
  if (!ip) throw bad('Give the address to unblock.');
  unban(ip);
  audit('admin_unban', { ip }, { actor: admin, subject: 'admin' });
  return { bans: activeBans() };
});
// Shows what the hosting proxy sends, so you can confirm TRUST_PROXY_HOPS picks the real visitor address.
route('GET', '/api/admin/ip-check', ctx => {
  requireAdmin(ctx);
  return { seenAs: ipOf(ctx.req), xForwardedFor: ctx.req.headers['x-forwarded-for'] || null, xRealIp: ctx.req.headers['x-real-ip'] || null, socket: ctx.req.socket.remoteAddress,
    trustProxyHops: Number(process.env.TRUST_PROXY_HOPS) || 1, clientIpHeader: process.env.CLIENT_IP_HEADER || null,
    advice: 'seenAs should be YOUR public IP (check it on any "what is my IP" site). On Railway, setting CLIENT_IP_HEADER=x-real-ip is the most reliable (the edge overwrites that header). Otherwise, if seenAs shows a proxy or CDN address, set TRUST_PROXY_HOPS to 2 and check again.' };
});
