// Help desk: anyone can open a ticket from /help; it lands in the support inbox (SUPPORT_EMAIL) with reply-to set to
// the customer, and in the admin console where admins can answer. Answers are emailed back to the customer.
import crypto from 'node:crypto';
import { route, bad, HttpError, rateLimit, sessionWallet } from '../http.js';
import { config } from '../config.js';
import { run, get, all, now, sha256hex } from '../db.js';
import { normalizeEmail, requireAdmin } from '../access.js';
import { isValidPubkey } from '../lib/solana.js';
import { email } from '../notify.js';

export const TOPICS = { payment: 'Payment or hiring', agent: 'My agent or dashboard', alerts: 'Alerts', extension: 'Browser extension', business: 'Business services',
  duress: 'Duress Mode', freeze: 'Freeze Desk', security: 'Report a security issue', other: 'Something else' };
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const clean = (v, n) => String(v ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, n);
const oneLine = (v, n) => clean(v, n).replace(/[\r\n]+/g, ' ');
// A line that is nothing but 12-24 short lowercase words (a recovery phrase), or a Solana keypair byte array.
// (Raw hex/base58 keys look the same as transaction IDs, which customers do need to send, so they are not blocked.)
const looksSecret = text => text.split(/\n/).some(line => { const w = line.trim().split(/\s+/); return [12, 15, 18, 21, 24].includes(w.length) && w.every(x => /^[a-z]{3,8}$/.test(x)); })
  || /\[\s*\d{1,3}(\s*,\s*\d{1,3}){63}\s*\]/.test(text); // a 64-byte keypair array (Solana CLI format)

route('GET', '/api/support/topics', () => ({ topics: TOPICS, x: config.xHandle }));

route('POST', '/api/support/tickets', async ctx => {
  const b = ctx.body;
  rateLimit('ticket:' + ctx.ip, 3);
  rateLimit('ticket:all', 60);
  // Bots fill the hidden field or submit instantly. Pretend it worked so they learn nothing.
  const tooFast = Number(b.startedAt) && Date.now() - Number(b.startedAt) < 3000;
  if (b.website || tooFast) return { ok: true, ref: 'BG-' + crypto.randomBytes(3).toString('hex').toUpperCase() };
  const ipHash = sha256hex('ticket:' + ctx.ip).slice(0, 24);
  if (get('select count(*) c from tickets where ip_hash = ? and created_at > ?', ipHash, now() - 3600).c >= 5) throw new HttpError(429, 'You have sent several tickets in the last hour. We will get back to you on those first.');
  const name = oneLine(b.name, 80);
  const mail = normalizeEmail(b.email);
  const topic = TOPICS[b.topic] ? b.topic : 'other';
  const subject = oneLine(b.subject, 140);
  const message = clean(b.message, 5000);
  const signedIn = sessionWallet(ctx.req);
  const wallet = signedIn || (isValidPubkey(String(b.wallet || '').trim()) ? String(b.wallet).trim() : null);
  if (!name) throw bad('Add your name.');
  if (subject.length < 4) throw bad('Add a short subject.');
  if (message.length < 15) throw bad('Tell us a little more so we can help.');
  // Protect customers from themselves: never accept something that looks like a recovery phrase.
  if (looksSecret(message)) throw bad('That looks like a recovery phrase. Never share it with anyone, including us. Remove it and send the ticket again. If you already shared it somewhere, move your funds to a new wallet now.');
  const id = 't_' + crypto.randomBytes(8).toString('hex');
  const ref = 'BG-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  run('insert into tickets(id, ref, name, email, wallet, topic, subject, message, status, ip_hash, created_at, updated_at) values(?,?,?,?,?,?,?,?,?,?,?,?)',
    id, ref, name, mail, wallet, topic, subject, message, 'open', ipHash, now(), now());
  run('insert into ticket_messages(ticket_id, author, body, created_at) values(?,?,?,?)', id, 'customer', message, now());
  const meta = `Ticket ${ref} · ${TOPICS[topic]}\nFrom: ${name} <${mail}>${wallet ? `\nWallet: ${wallet}${signedIn ? ' (signed in)' : ' (typed, not verified)'}` : ''}`;
  if (config.supportEmail) email(config.supportEmail, `[${ref}] ${subject}`, `<pre style="font:14px/1.5 Arial,sans-serif;white-space:pre-wrap">${esc(meta)}\n\n${esc(message)}</pre>`, `${meta}\n\n${message}`, config.resend.supportFrom, { replyTo: mail }).catch(() => {});
  email(mail, `We got your message [${ref}]`, `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;line-height:1.5"><h2>Thanks, ${esc(name)}. We're on it.</h2><p>Your ticket reference is <b>${ref}</b>. A member of the Bodyguard team will reply to this email address.</p><p><b>Stay safe:</b> we will never ask for your seed phrase or private key, never DM you first, and never ask you to "verify" or "sync" a wallet. Our only X account is <a href="https://x.com/${config.xHandle}">@${esc(config.xHandle)}</a>.</p><hr><p style="color:#666;font-size:13px">${esc(subject)}</p></div>`,
    `Thanks, ${name}. Your ticket reference is ${ref}. We will reply to this address. We will never ask for your seed phrase or private key.`, config.resend.supportFrom).catch(() => {});
  return { ok: true, ref };
});

/* ---------------- admin console ---------------- */
route('GET', '/api/admin/tickets', ctx => {
  requireAdmin(ctx);
  const status = ['open', 'answered', 'closed'].includes(ctx.query.status) ? ctx.query.status : null;
  return { tickets: (status ? all('select * from tickets where status = ? order by created_at desc limit 200', status) : all('select * from tickets order by created_at desc limit 200')).map(t => ({ ...t, ip_hash: undefined, topicLabel: TOPICS[t.topic] })) };
});
route('GET', '/api/admin/tickets/:tid', ctx => {
  requireAdmin(ctx);
  const t = get('select * from tickets where id = ?', ctx.params.tid);
  if (!t) throw new HttpError(404, 'Ticket not found.');
  return { ticket: { ...t, ip_hash: undefined, topicLabel: TOPICS[t.topic] }, messages: all('select author, body, created_at from ticket_messages where ticket_id = ? order by id', t.id) };
});
route('POST', '/api/admin/tickets/:tid/reply', async ctx => {
  const admin = requireAdmin(ctx);
  const t = get('select * from tickets where id = ?', ctx.params.tid);
  if (!t) throw new HttpError(404, 'Ticket not found.');
  const body = clean(ctx.body.message, 8000);
  const status = ['open', 'answered', 'closed'].includes(ctx.body.status) ? ctx.body.status : 'answered';
  if (body) {
    const ok = await email(t.email, `Re: [${t.ref}] ${t.subject}`, `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;line-height:1.55">${esc(body).replace(/\n/g, '<br>')}<hr><p style="color:#666;font-size:12px">Bodyguard support · ticket ${esc(t.ref)}. Reply to this email to continue. We will never ask for your seed phrase or private key.</p></div>`,
      `${body}\n\n-- Bodyguard support · ticket ${t.ref}`, config.resend.supportFrom, { replyTo: config.supportEmail || undefined });
    if (!ok) throw new HttpError(502, 'The reply could not be emailed. Check RESEND_API_KEY and SUPPORT_FROM_EMAIL.');
    run('insert into ticket_messages(ticket_id, author, body, created_at) values(?,?,?,?)', t.id, 'support:' + admin.slice(0, 6), body, now());
  }
  run('update tickets set status = ?, updated_at = ? where id = ?', status, now(), t.id);
  (await import('../security.js')).log('admin_ticket_reply', { ref: t.ref, status, replied: !!body }, { actor: admin, subject: 'admin' });
  return { ok: true };
});
