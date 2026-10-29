// Delivery channels: Telegram bot, email (Resend) and web push. Plus the Telegram bot's command loop.
import { config } from './config.js';
import { get, run, all, now } from './db.js';
import { sendPush } from './lib/webpush.js';

const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

export async function telegram(chatId, html) {
  if (!config.telegram.token || !chatId) return false;
  const r = await fetch(`https://api.telegram.org/bot${config.telegram.token}/sendMessage`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text: html, parse_mode: 'HTML', disable_web_page_preview: true }), signal: AbortSignal.timeout(15000)
  });
  return r.ok;
}

export async function email(to, subject, html, text, from = config.resend.from, { replyTo, cc, attachments } = {}) {
  if (!config.resend.key || !to) return false;
  // Subjects can carry user text: a line break must never reach a mail header.
  subject = String(subject || '').replace(/[\r\n\u0000-\u001f]+/g, ' ').slice(0, 250);
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST', headers: { authorization: `Bearer ${config.resend.key}`, 'content-type': 'application/json' },
    body: JSON.stringify({ from, to: Array.isArray(to) ? to : [to], subject, html, text, ...(replyTo ? { reply_to: replyTo } : {}), ...(cc ? { cc: Array.isArray(cc) ? cc : [cc] } : {}), ...(attachments?.length ? { attachments } : {}) }),
    signal: AbortSignal.timeout(attachments?.length ? 45000 : 15000)
  });
  if (!r.ok) console.warn('[email] send failed', r.status, await r.text().catch(() => ''));
  return r.ok;
}

export async function pushTo(subject, payload) {
  if (!config.vapid.publicKey || !config.vapid.privateKey) return 0;
  let sent = 0;
  for (const s of all('select * from push_subs where subject = ?', subject)) {
    try {
      const r = await sendPush(s, payload, config.vapid);
      if (r.gone) run('delete from push_subs where id = ?', s.id); else if (r.status < 300) sent++;
    } catch (e) { console.warn('[push]', e.message); }
  }
  return sent;
}

const SEV = { low: 'Low', med: 'Medium', high: 'High', crit: 'Critical' };
export function alertTelegramHtml(a, agentId) {
  return `<b>${SEV[a.severity]} · ${esc(a.title)}</b>\n<i>Agent ${esc(agentId || '')}</i>\n\n<b>What happened</b>\n${esc(a.what)}\n\n<b>What your agent did</b>\n${esc(a.did)}\n\n<b>Your move</b>\n${esc(a.move)}\n\n${config.publicUrl}/app#alerts`;
}
export function alertEmailHtml(a, agentId) {
  const color = { low: '#8c998f', med: '#ffbb4d', high: '#ff5a6b', crit: '#ff5a6b' }[a.severity];
  return `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#0a0d0b;color:#e3ebe5;padding:24px;border-radius:12px">
  <img src="${config.publicUrl}/icon-192.png" width="44" height="44" alt="Bodyguard" style="border-radius:10px;display:block;margin-bottom:10px">
  <div style="font-size:12px;letter-spacing:.12em;color:#c8ff1a">BODYGUARD · AGENT ${esc(agentId || '')}</div>
  <h2 style="margin:10px 0 4px;font-size:22px">${esc(a.title)}</h2>
  <div style="display:inline-block;font-size:11px;padding:2px 8px;border:1px solid ${color};color:${color};border-radius:99px">${SEV[a.severity]}</div>
  <h4 style="color:#c8ff1a;font-size:11px;letter-spacing:.14em;margin:20px 0 4px">WHAT HAPPENED</h4><p style="margin:0">${esc(a.what)}</p>
  <h4 style="color:#c8ff1a;font-size:11px;letter-spacing:.14em;margin:16px 0 4px">WHAT YOUR AGENT DID</h4><p style="margin:0">${esc(a.did)}</p>
  <h4 style="color:#c8ff1a;font-size:11px;letter-spacing:.14em;margin:16px 0 4px">YOUR MOVE</h4><p style="margin:0">${esc(a.move)}</p>
  <p style="margin-top:24px"><a href="${config.publicUrl}/app#alerts" style="color:#c8ff1a">Open your dashboard</a></p>
  <p style="font-size:11px;color:#8c998f;margin-top:20px">Bodyguard will never ask for your seed phrase or private key.</p></div>`;
}

/* ---------------- Telegram bot commands (long polling, no public URL needed) ---------------- */
async function isChatAdmin(chatId, userId) {
  if (!userId) return false;
  try {
    const r = await fetch(`https://api.telegram.org/bot${config.telegram.token}/getChatMember?chat_id=${encodeURIComponent(chatId)}&user_id=${encodeURIComponent(userId)}`, { signal: AbortSignal.timeout(10000) });
    const j = await r.json();
    return ['creator', 'administrator'].includes(j.result?.status);
  } catch { return false; }
}
export async function startTelegramBot() {
  if (!config.telegram.token) return;
  let offset = 0;
  console.log('[telegram] bot polling started');
  for (;;) {
    try {
      const r = await fetch(`https://api.telegram.org/bot${config.telegram.token}/getUpdates?timeout=50&offset=${offset}`, { signal: AbortSignal.timeout(60000) });
      const j = await r.json();
      for (const u of j.result || []) {
        offset = u.update_id + 1;
        const m = u.message; if (!m?.text) continue;
        const chat = String(m.chat.id), text = m.text.trim();
        if (/^\/start(@\w+)?(\s|$)/.test(text)) {
          const code = text.split(/\s+/)[1];
          const c = code && get('select subject from channels where link_code = ?', code);
          if (c) {
            run('update channels set telegram_chat_id = ?, link_code = null where subject = ?', chat, c.subject);
            if (c.subject.startsWith('drillchat:')) await telegram(chat, '<b>Bodyguard is connected.</b>\nYour organisation can now run Scam Drills in this group.');
            else await telegram(chat, `<b>Bodyguard alerts are on.</b>\nThis chat will get alerts for ${esc(c.subject.replace('agent:', 'agent ').replace('org:', 'organisation '))}.\nSend /stop to turn them off.`);
          } else await telegram(chat, 'Open your Bodyguard dashboard and press "Connect Telegram" to link this chat.');
        } else if (/^\/stop(@\w+)?$/.test(text)) {
          // In a group, only its admins can switch alerts off; otherwise any member could silence security alerts.
          if (m.chat.type !== 'private' && !(await isChatAdmin(chat, m.from?.id))) { await telegram(chat, 'Only an admin of this group can turn Bodyguard alerts off.'); continue; }
          run('update channels set telegram_chat_id = null where telegram_chat_id = ?', chat);
          await telegram(chat, 'Telegram alerts are off for this chat.');
        } else if (/^\/status(@\w+)?$/.test(text)) {
          const subs = all('select subject from channels where telegram_chat_id = ?', chat);
          if (!subs.length) { await telegram(chat, 'This chat is not linked to an agent.'); continue; }
          const lines = subs.map(s => {
            const id = s.subject.split(':')[1];
            const a = get('select * from agents where id = ?', id);
            const open = get('select count(*) c from alerts where subject = ? and acked_at is null and created_at > ?', s.subject, now() - 7 * 86400).c;
            return a ? `Agent ${a.id} · ${a.status === 'active' && (!a.expires_at || a.expires_at > now()) ? 'on duty' : 'off duty'} · ${open} open alerts this week` : s.subject;
          });
          await telegram(chat, lines.map(esc).join('\n'));
        }
      }
    } catch (e) { await new Promise(r => setTimeout(r, 5000)); }
  }
}
