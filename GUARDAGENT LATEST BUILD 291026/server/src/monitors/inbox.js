// Inbox guard (Gmail and Outlook through OAuth, read-only): new forwarding rules and filters, plus the security
// notices your accounts send (Google/Microsoft sign-ins, exchange logins, withdrawals, 2FA and password changes)
// and phishing that pretends to be them.
import { config } from '../config.js';
import { get, run, now, encrypt, decrypt, json } from '../db.js';
import { LIMITS } from '../plans.js';
import { activeAssets, stateOf, saveState } from './common.js';
import { raiseAgent } from '../alerts.js';
import { classifyEmail } from '../lib/ai.js';

export const GOOGLE_SCOPES = 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.settings.basic openid email';
export const MS_SCOPES = 'offline_access User.Read Mail.Read MailboxSettings.Read';

const SENDERS = {
  account: ['accounts.google.com', 'google.com', 'accountprotection.microsoft.com', 'microsoft.com', 'appleid.apple.com', 'id.apple.com', 'x.com', 'twitter.com', 'discord.com', 'telegram.org', 'github.com', 'proton.me'],
  exchange: ['coinbase.com', 'binance.com', 'kraken.com', 'okx.com', 'bybit.com', 'kucoin.com', 'gemini.com', 'crypto.com', 'bitstamp.net', 'bitget.com', 'gate.io', 'mexc.com', 'htx.com', 'bitfinex.com', 'revolut.com', 'phantom.com', 'phantom.app', 'metamask.io', 'ledger.com', 'trezor.io']
};
const RULES = [
  { re: /(new|unrecognized|unrecognised|unusual|suspicious).{0,30}(sign[- ]?in|log[- ]?in|login|device|location|activity)|sign[- ]?in (attempt|alert)|security alert|critical security/i, kind: 'signin', sev: 'med' },
  { re: /withdraw(al)?|sent .{0,20}(btc|eth|sol|usdt|usdc)|transfer (request|confirmation)/i, kind: 'withdrawal', sev: 'high' },
  { re: /(2fa|two[- ]factor|authenticator|security key|passkey).{0,40}(disabled|removed|changed|reset|turned off|added)/i, kind: '2fa_change', sev: 'high' },
  { re: /(reset|change|changed|recover).{0,25}password|password .{0,15}(reset|changed)/i, kind: 'password_reset', sev: 'med' },
  { re: /api key (created|added)|new api key/i, kind: 'api_key', sev: 'high' },
  { re: /recovery (email|phone)|account recovery/i, kind: 'recovery', sev: 'high' }
];
// The real sender is the address inside <…>. A display name such as "security@coinbase.com" <x@evil.example>
// must never make a message look official, so the display name is ignored.
export const senderAddress = from => { const f = String(from || ''); const angle = f.match(/<([^<>\s]+@[^<>\s]+)>\s*$/); return (angle ? angle[1] : f.trim()).toLowerCase(); };
const domainOf = from => { const a = senderAddress(from); return /^[^@\s"]+@([a-z0-9.-]+)$/i.test(a) ? a.split('@')[1].replace(/\.$/, '') : ''; };
const fromMatches = (d, list) => list.some(x => d === x || d.endsWith('.' + x));

export async function classify({ from, subject, snippet, exchangeNotices }) {
  const d = domainOf(from);
  const official = fromMatches(d, SENDERS.account) || (exchangeNotices && fromMatches(d, SENDERS.exchange));
  const text = `${subject} ${snippet}`;
  const rule = RULES.find(r => r.re.test(text));
  const brandish = /(coinbase|binance|kraken|metamask|phantom|ledger|trezor|google|microsoft|apple)/i.test(`${from} ${subject}`);
  if (rule && official) return { security: true, kind: rule.kind, severity: rule.sev, official: true };
  if (rule && brandish && !official && d) return { security: true, kind: 'phishing', severity: 'high', official: false };
  if (!rule && !official) return null;
  if (official) {
    const ai = await classifyEmail({ from, subject, snippet });
    if (ai?.security) return { security: true, kind: ai.kind, severity: ai.severity === 'high' ? 'high' : 'med', official: true, summary: ai.summary };
  }
  return null;
}

/* ---------------- token handling ---------------- */
async function tokenFor(assetId) {
  const row = get('select * from oauth_tokens where asset_id = ?', assetId);
  if (!row) return null;
  const t = decrypt(row.enc);
  if (t.expires_at && t.expires_at - 60 > now()) return { ...t, provider: row.provider };
  const body = row.provider === 'google'
    ? new URLSearchParams({ client_id: config.google.id, client_secret: config.google.secret, refresh_token: t.refresh_token, grant_type: 'refresh_token' })
    : new URLSearchParams({ client_id: config.microsoft.id, client_secret: config.microsoft.secret, refresh_token: t.refresh_token, grant_type: 'refresh_token', scope: MS_SCOPES });
  const url = row.provider === 'google' ? 'https://oauth2.googleapis.com/token' : `https://login.microsoftonline.com/${config.microsoft.tenant}/oauth2/v2.0/token`;
  const r = await fetch(url, { method: 'POST', body, signal: AbortSignal.timeout(20000) });
  const j = await r.json();
  if (!r.ok) throw new Error('token refresh failed: ' + (j.error || r.status));
  const next = { ...t, access_token: j.access_token, refresh_token: j.refresh_token || t.refresh_token, expires_at: now() + (j.expires_in || 3600) };
  run('update oauth_tokens set enc = ?, updated_at = ? where asset_id = ?', encrypt(next), now(), assetId);
  return { ...next, provider: row.provider };
}
export function saveToken(assetId, provider, tok) {
  run('insert into oauth_tokens(asset_id, provider, enc, updated_at) values(?,?,?,?) on conflict(asset_id) do update set provider = excluded.provider, enc = excluded.enc, updated_at = excluded.updated_at',
    assetId, provider, encrypt({ access_token: tok.access_token, refresh_token: tok.refresh_token, expires_at: now() + (tok.expires_in || 3600) }), now());
}

const gapi = async (tok, path) => {
  const r = await fetch('https://gmail.googleapis.com/gmail/v1/users/me' + path, { headers: { authorization: 'Bearer ' + tok.access_token }, signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error('gmail ' + r.status);
  return r.json();
};
const mapi = async (tok, path) => {
  const r = await fetch('https://graph.microsoft.com/v1.0/me' + path, { headers: { authorization: 'Bearer ' + tok.access_token }, signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error('graph ' + r.status);
  return r.json();
};

async function gmailState(tok, since) {
  const [filters, fwd, auto] = await Promise.all([gapi(tok, '/settings/filters').catch(() => ({})), gapi(tok, '/settings/forwardingAddresses').catch(() => ({})), gapi(tok, '/settings/autoForwarding').catch(() => ({}))]);
  const rules = (filters.filter || []).map(f => ({ id: f.id, forward: f.action?.forward || null, desc: `${JSON.stringify(f.criteria || {})} -> ${JSON.stringify(f.action || {})}`, deletes: (f.action?.addLabelIds || []).includes('TRASH'), skipsInbox: (f.action?.removeLabelIds || []).includes('INBOX') }));
  const forwarding = [...(fwd.forwardingAddresses || []).map(a => a.forwardingEmail), ...(auto.enabled ? [auto.emailAddress] : [])].filter(Boolean);
  const list = await gapi(tok, `/messages?maxResults=25&q=${encodeURIComponent(`newer_than:2d after:${since}`)}`).catch(() => ({}));
  const messages = [];
  for (const m of (list.messages || []).slice(0, 25)) {
    const full = await gapi(tok, `/messages/${m.id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject`).catch(() => null);
    if (!full) continue;
    const h = n => full.payload?.headers?.find(x => x.name.toLowerCase() === n)?.value || '';
    messages.push({ id: m.id, from: h('from'), subject: h('subject'), snippet: full.snippet || '', at: Math.floor(Number(full.internalDate) / 1000) });
  }
  return { rules, forwarding, messages };
}
async function outlookState(tok, since) {
  const rules = (await mapi(tok, '/mailFolders/inbox/messageRules').catch(() => ({ value: [] }))).value.map(r => ({ id: r.id, forward: [...(r.actions?.forwardTo || []), ...(r.actions?.redirectTo || []), ...(r.actions?.forwardAsAttachmentTo || [])].map(x => x.emailAddress?.address).filter(Boolean).join(', ') || null,
    desc: `${r.displayName}: ${JSON.stringify(r.conditions || {})} -> ${JSON.stringify(r.actions || {})}`, deletes: !!(r.actions?.delete || r.actions?.permanentDelete), skipsInbox: !!r.actions?.moveToFolder, enabled: r.isEnabled }));
  const settings = await mapi(tok, '/mailboxSettings').catch(() => ({}));
  const iso = new Date(since * 1000).toISOString();
  const msgs = (await mapi(tok, `/messages?$top=25&$select=id,from,subject,bodyPreview,receivedDateTime&$filter=receivedDateTime ge ${iso}&$orderby=receivedDateTime desc`).catch(() => ({ value: [] }))).value;
  return { rules, forwarding: settings.automaticRepliesSetting ? [] : [], messages: msgs.map(m => ({ id: m.id, from: m.from?.emailAddress?.address || '', subject: m.subject || '', snippet: m.bodyPreview || '', at: Math.floor(new Date(m.receivedDateTime).getTime() / 1000) })) };
}

export async function pollInboxes() {
  if (!config.google.id && !config.microsoft.id) return;
  for (const asset of activeAssets('email')) {
    if (!get('select 1 from oauth_tokens where asset_id = ?', asset.id)) continue;
    const st = stateOf(asset);
    try {
      const tok = await tokenFor(asset.id);
      const since = st.inboxSince || now() - 3600;
      const s = tok.provider === 'google' ? await gmailState(tok, since) : await outlookState(tok, since);
      if (st.inboxBaseline) {
        const prevRules = new Set((st.rules || []).map(r => r.id));
        for (const r of s.rules.filter(r => !prevRules.has(r.id))) {
          const risky = r.forward || r.deletes || r.skipsInbox;
          await raiseAgent(asset.agent_id, { severity: r.forward ? 'high' : risky ? 'med' : 'low', type: 'mail_rule', dedupe: `rule:${asset.id}:${r.id}`, title: r.forward ? 'New rule forwards your email' : 'New email rule created',
            what: `A new rule appeared on ${asset.value}${r.forward ? ` that forwards mail to ${r.forward}` : r.deletes ? ' that deletes matching emails' : r.skipsInbox ? ' that hides matching emails from your inbox' : ''}. Attackers use rules like this to hide security alerts and steal reset links.`,
            did: 'Compared your mailbox rules with the last check.', move: "If you didn't create it, delete the rule, change your password, sign out other sessions and check for app passwords you didn't make.", data: { rule: r.desc.slice(0, 500) } });
        }
        const prevFwd = new Set(st.forwarding || []);
        for (const f of s.forwarding.filter(f => !prevFwd.has(f)))
          await raiseAgent(asset.agent_id, { severity: 'high', type: 'mail_forward', dedupe: `fwd:${asset.id}:${f}`, title: 'Email forwarding turned on', what: `${asset.value} now forwards to ${f}.`, did: 'Spotted the change in your mailbox settings.', move: "If this wasn't you, turn forwarding off and secure the account right away." });
      }
      const seen = new Set(st.seenMsgs || []);
      for (const m of s.messages.filter(m => !seen.has(m.id))) {
        seen.add(m.id);
        if (!st.inboxBaseline) continue;
        const c = await classify({ ...m, exchangeNotices: LIMITS[asset.rank]?.exchangeNotices });
        if (!c) continue;
        const sender = senderAddress(m.from);
        if (c.kind === 'phishing') await raiseAgent(asset.agent_id, { severity: 'high', type: 'mail_phish', dedupe: `phish:${asset.id}:${m.id}`, title: 'Fake security email in your inbox',
          what: `"${m.subject}" came from ${sender}, which is not an official address for the company it names.`, did: 'Checked the sender against the real security-notice domains.', move: "Don't click anything in it. Delete it, and if you already did click, change that account's password from the official site." });
        else await raiseAgent(asset.agent_id, { severity: c.severity, type: 'mail_notice_' + c.kind, dedupe: `notice:${asset.id}:${m.id}`, title: { signin: 'New sign-in notice', withdrawal: 'Withdrawal notice', '2fa_change': '2FA change notice', password_reset: 'Password reset notice', api_key: 'New API key notice', recovery: 'Account recovery change' }[c.kind] || 'Security notice',
          what: `${sender} sent "${m.subject}" to ${asset.value}.${c.summary ? ' ' + c.summary : ''}`, did: 'Read the security notice the moment it arrived.',
          move: c.kind === 'withdrawal' ? "If you didn't request this, log in to the exchange from its official app now, freeze withdrawals and change your password." : "If this wasn't you, change the password from the official site (not the email link) and sign out all other sessions." });
      }
      st.rules = s.rules.map(r => ({ id: r.id })); st.forwarding = s.forwarding; st.seenMsgs = [...seen].slice(-400);
      st.inboxSince = Math.max(since, ...s.messages.map(m => m.at || 0)) - 300;
      st.inboxBaseline = true; st.inbox = tok.provider; st.health = 'ok';
      saveState(asset, st);
    } catch (e) { st.health = 'inbox error: ' + e.message.slice(0, 80); saveState(asset, st); }
  }
}
