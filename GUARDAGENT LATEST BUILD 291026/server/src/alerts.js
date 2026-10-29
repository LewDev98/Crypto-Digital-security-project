// Raising alerts: dedupe, AI rewrite, store, deliver by severity and rank, escalate criticals for Security Details.
import { config } from './config.js';
import { run, get, all, now, json } from './db.js';
import { rewriteAlert } from './lib/ai.js';
import { telegram, email, pushTo, alertTelegramHtml, alertEmailHtml } from './notify.js';
import { LIMITS } from './plans.js';

const RANK_SEV = { low: 0, med: 1, high: 2, crit: 3 };

export async function raise(subject, draft) {
  if (draft.dedupe && get('select 1 from alerts where dedupe = ?', draft.dedupe)) return null;
  const a = await rewriteAlert(draft);
  const r = run(`insert or ignore into alerts(subject, severity, type, title, what, did, move, data, dedupe, created_at) values(?,?,?,?,?,?,?,?,?,?)`,
    subject, a.severity, a.type, a.title, a.what, a.did, a.move, JSON.stringify(a.data || {}), a.dedupe || null, now());
  if (!r.changes) return null;
  const alert = { id: Number(r.lastInsertRowid), subject, ...a };
  deliver(alert).catch(e => console.warn('[alerts] deliver', e.message));
  return alert;
}

export const raiseAgent = (agentId, draft) => raise('agent:' + agentId, draft);
export const raiseOrg = (orgId, draft) => raise('org:' + orgId, draft);

async function deliver(alert, { escalation = false } = {}) {
  const [kind, id] = alert.subject.split(':');
  const ch = get('select * from channels where subject = ?', alert.subject) || {};
  let rank = 'detail', label = id;
  let fallbackEmail = null;
  if (kind === 'agent') { const ag = get('select * from agents where id = ?', id); rank = ag?.rank || 'sentry'; }
  if (kind === 'org') { label = 'org'; }
  const L = LIMITS[rank] || LIMITS.sentry;
  const sev = RANK_SEV[alert.severity] ?? 1;
  const delivered = json(get('select delivered from alerts where id = ?', alert.id)?.delivered);
  const prefix = escalation ? 'Still open: ' : '';
  const shown = { ...alert, title: prefix + alert.title };
  if (ch.telegram_chat_id && sev >= 1) delivered.telegram = await telegram(ch.telegram_chat_id, alertTelegramHtml(shown, label)).catch(() => false);
  const to = ch.alert_email || fallbackEmail;
  if (to && (sev >= 2 || (sev === 1 && !ch.telegram_chat_id))) delivered.email = await email(to, `[Bodyguard] ${shown.title}`, alertEmailHtml(shown, label), `${shown.title}\n\n${alert.what}\n\n${alert.did}\n\nYour move: ${alert.move}`).catch(() => false);
  if (L.push && sev >= 2) delivered.push = await pushTo(alert.subject, { title: shown.title, body: alert.what, url: config.publicUrl + '/app#alerts', severity: alert.severity }).catch(() => 0);
  run('update alerts set delivered = ? where id = ?', JSON.stringify(delivered), alert.id);
}

// Security Detail: critical alerts repeat every 10 minutes (max 3 times) until someone acknowledges them.
export async function escalate() {
  const rows = all(`select al.* from alerts al join agents ag on al.subject = 'agent:' || ag.id
    where al.severity = 'crit' and al.acked_at is null and ag.rank = 'detail' and al.escalations < 3 and al.created_at < ? and al.created_at > ?`,
    now() - 600, now() - 6 * 3600);
  for (const al of rows) {
    if (now() - al.created_at < 600 * (al.escalations + 1)) continue;
    run('update alerts set escalations = escalations + 1 where id = ?', al.id);
    await deliver(al, { escalation: true }).catch(() => {});
  }
}

export async function welcomeAlert(agentId) {
  return raiseAgent(agentId, {
    severity: 'low', type: 'welcome', dedupe: `welcome:${agentId}:${Math.floor(now() / 86400)}`,
    title: `Agent ${agentId} reporting for duty`,
    what: 'Your payment was confirmed and your agent is now active.',
    did: 'It is waiting for its briefing: the wallets, emails and domains you want protected.',
    move: 'Open your dashboard, add what you want guarded, and connect Telegram so alerts reach you fast.'
  });
}

export async function expiryReminders() {
  const soon = all("select * from agents where status = 'active' and expires_at is not null and expires_at between ? and ?", now(), now() + 3 * 86400);
  for (const a of soon) {
    await raiseAgent(a.id, {
      severity: 'med', type: 'renewal', dedupe: `renew:${a.id}:${a.expires_at}`,
      title: 'Your agent goes off duty soon',
      what: `Agent ${a.id} is paid up until ${new Date(a.expires_at * 1000).toUTCString().slice(0, 16)}.`,
      did: 'Nothing yet. Monitoring stops when the period ends.',
      move: 'Renew your rank from the site to keep your protection running without a gap.'
    });
  }
}
