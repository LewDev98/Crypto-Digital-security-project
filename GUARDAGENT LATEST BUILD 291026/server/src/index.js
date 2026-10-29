// Bodyguard Agents server: API, website, dashboard, patrols and the Telegram bot in one process.
import { config, assertConfig } from './config.js';
import { createServer, route } from './http.js';
import './routes/core.js';
import './routes/protect.js';
import './routes/oauth.js';
import './routes/org.js';
import './routes/drills.js';
import './routes/admin.js';
import './routes/duress.js';
import './routes/freeze.js';
import './routes/support.js';
import { realtimeStatus } from './monitors/realtime.js';
import { startScheduler, status } from './scheduler.js';
import { startTelegramBot } from './notify.js';
import { requireAdmin } from './access.js';
import { ensureAdminAccess } from './admin-access.js';
import { loadBans, setBanHandler } from './security.js';
import { ensureWeb3 } from './vendor.js';
import { raiseOrg } from './alerts.js';
import { get } from './db.js';

route('GET', '/api/admin/jobs', ctx => { requireAdmin(ctx); return { jobs: status, realtime: realtimeStatus() }; });

// Active defences: restore blocks after a restart, and tell admins whenever an address gets blocked.
loadBans();
setBanHandler(({ ip, reason, until, count }) => {
  for (const w of config.adminWallets) {
    const org = get('select id from orgs where owner = ? order by created_at limit 1', w);
    if (org) raiseOrg(org.id, { severity: count > 2 ? 'high' : 'med', type: 'security_block', dedupe: `ban:${ip}:${Math.floor(Date.now() / 3600000)}`,
      title: 'Suspicious traffic blocked', what: `${ip} was blocked until ${new Date(until * 1000).toUTCString()} after ${reason}. This is block number ${count} for that address.`,
      did: 'Blocked every request from that address for the period.', move: 'Nothing to do unless this is a customer you know. Admins can lift the block in the dashboard (Admin › Security).' }).catch(() => {});
  }
});
route('GET', '/.well-known/security.txt', () => ({ __raw: `Contact: ${config.publicUrl}/help?topic=security\nExpires: ${new Date(Date.now() + 365 * 86400000).toISOString()}\nPreferred-Languages: en\nCanonical: ${config.publicUrl}/.well-known/security.txt\nPolicy: ${config.publicUrl}/help#ticket\n`, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=86400' } }));

const warnings = assertConfig();
ensureAdminAccess();
warnings.forEach(w => console.warn('[config]', w));
const server = createServer();
server.listen(config.port, () => {
  console.log(`[bodyguard] listening on :${config.port} (${config.publicUrl})`);
  if (process.env.NO_JOBS !== '1') startScheduler();
  if (process.env.NO_JOBS !== '1') startTelegramBot();
  if (process.env.NO_JOBS !== '1' && process.env.NO_VENDOR !== '1') ensureWeb3().catch(() => {});
});
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { server.close(); process.exit(0); });
