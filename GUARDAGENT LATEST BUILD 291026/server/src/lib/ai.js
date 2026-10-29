// The agent's "voice": turns rule-based findings into plain-English alerts, and classifies ambiguous
// security emails. Optional: everything still works on templates if ANTHROPIC_API_KEY is not set.
import { config } from '../config.js';

async function ask(system, user, maxTokens = 500) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': config.ai.key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: config.ai.model, max_tokens: maxTokens, system, messages: [{ role: 'user', content: user }] }),
    signal: AbortSignal.timeout(15000)
  });
  if (!res.ok) throw new Error('ai ' + res.status);
  const j = await res.json();
  const text = (j.content || []).filter(c => c.type === 'text').map(c => c.text).join('');
  const m = text.match(/\{[\s\S]*\}/);
  return m ? JSON.parse(m[0]) : null;
}

const ALERT_SYSTEM = `You are the voice of a crypto security agent called Bodyguard. You rewrite a detected security event into an alert for a non-technical person.
Rules: use only the facts given; never invent amounts, names or links; keep addresses short (first 4 and last 4 characters); no markdown; no emojis.
Return JSON only: {"title": "max 8 words", "what": "1-2 sentences on what happened", "did": "1 sentence on what the agent did", "move": "1-2 sentences, the single most useful next step"}`;

export async function rewriteAlert(draft) {
  if (!config.ai.key) return draft;
  try {
    const out = await ask(ALERT_SYSTEM, JSON.stringify({ severity: draft.severity, type: draft.type, title: draft.title, what: draft.what, did: draft.did, move: draft.move, facts: draft.data || {} }));
    const ok = k => typeof out?.[k] === 'string' && out[k].length > 3 && out[k].length < 600;
    if (!out || !['title', 'what', 'did', 'move'].every(ok)) return draft;
    // Alert facts can contain attacker-chosen text (token names, memos, email subjects). If the rewrite contains any
    // link, domain or address that was not already in our own draft, it may have been steered by that text, so the
    // rule-based draft is used instead.
    const source = [draft.title, draft.what, draft.did, draft.move].join(' ').toLowerCase();
    const risky = /https?:\/\/\S+|www\.\S+|\b[a-z0-9-]+\.(?:com|io|xyz|app|net|org|co|gg|me|finance|tech|site|online|link|top|click)\b|0x[0-9a-f]{6,}|[1-9A-HJ-NP-Za-km-z]{32,44}|@[a-z0-9_]{3,}|t\.me\//gi;
    const injected = [out.title, out.what, out.did, out.move].join(' ').match(risky) || [];
    if (injected.some(x => !source.includes(x.toLowerCase()))) return draft;
    return { ...draft, title: out.title, what: out.what, did: out.did, move: out.move };
  } catch { return draft; }
}

const EMAIL_SYSTEM = `You classify emails for a crypto security agent. Decide if the email is a security notice about the reader's own account
(sign-in, new device, password reset, 2FA change, withdrawal, API key, forwarding rule, account recovery) or a phishing attempt pretending to be one.
Return JSON only: {"security": true|false, "kind": "signin|password_reset|2fa_change|withdrawal|api_key|recovery|phishing|other", "severity": "low|med|high", "summary": "one short sentence"}`;

export async function classifyEmail({ from, subject, snippet }) {
  if (!config.ai.key) return null;
  try { return await ask(EMAIL_SYSTEM, JSON.stringify({ from, subject, snippet: String(snippet || '').slice(0, 800) }), 200); } catch { return null; }
}
