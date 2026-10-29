// Runs every patrol on its own interval. A slow job never overlaps itself.
import { config } from './config.js';
import { pollSolana, dailySweepCheck } from './monitors/solana.js';
import { pollEvm } from './monitors/evm.js';
import { pollBitcoin } from './monitors/bitcoin.js';
import { pollBreaches } from './monitors/breach.js';
import { pollDns, dailyDomainChecks } from './monitors/domains.js';
import { pollInboxes } from './monitors/inbox.js';
import { pollLeaks } from './monitors/leaks.js';
import { pollTreasuries } from './monitors/treasury.js';
import { escalate, expiryReminders } from './alerts.js';
import { refreshLists } from './engines/lists.js';
import { run, now } from './db.js';
import { syncWebhook, realtimeEnabled } from './monitors/realtime.js';
import { applyPending } from './duress.js';
import { traceIncidents } from './freeze.js';
import { raiseTrace } from './routes/freeze.js';

const jobs = [
  // With real-time webhooks on, polling becomes a 10-minute safety net instead of the main patrol.
  ['solana', pollSolana, realtimeEnabled() ? 600 : config.solana.pollSeconds],
  ['webhook-sync', syncWebhook, 120],
  ['evm', pollEvm, config.evmPollSeconds],
  ['bitcoin', pollBitcoin, 300],
  ['treasury', pollTreasuries, 120],
  ['inbox', pollInboxes, 600],
  ['dns', pollDns, 900],
  ['domains-daily', dailyDomainChecks, 3600],
  ['breach', pollBreaches, 3600],
  ['leaks', pollLeaks, 3600],
  ['sweep-check', dailySweepCheck, 3600],
  ['escalate', escalate, 120],
  ['expiry', expiryReminders, 3600],
  ['lists', refreshLists, 86400],
  ['duress', async () => applyPending(), 300],
  ['freeze-trace', () => traceIncidents({ raise: raiseTrace }), 900],
  ['cleanup', async () => {
    run('delete from sessions where expires_at < ?', now());
    run('delete from nonces where created_at < ?', now() - 3600);
    run('delete from screen_cache where created_at < ?', now() - 7 * 86400);
    run('delete from processed where created_at < ?', now() - 7 * 86400);
    run('delete from pair_codes where created_at < ?', now() - 600);
    run('delete from oauth_states where created_at < ?', now() - 900);
    run('delete from drill_events where created_at < ?', now() - 365 * 86400);
  }, 3600]
];

export const status = {};
export function startScheduler() {
  for (const [name, fn, seconds] of jobs) {
    let busy = false;
    const tick = async () => {
      if (busy) return;
      busy = true;
      const t = Date.now();
      try { await fn(); status[name] = { ok: true, at: now(), ms: Date.now() - t }; }
      catch (e) { status[name] = { ok: false, at: now(), error: e.message }; console.warn(`[job:${name}]`, e.message); }
      finally { busy = false; }
    };
    setTimeout(tick, 2000 + Math.random() * 8000);
    setInterval(tick, seconds * 1000).unref();
  }
}
