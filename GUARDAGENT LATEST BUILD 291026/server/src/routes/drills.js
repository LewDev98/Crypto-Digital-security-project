// Scam Drills: authorised phishing simulations for a team (email, only to verified company domains) and
// community drills (a tracked post in your own Telegram group), safe landing pages that never collect what is
// typed, short training with a quiz, and a report.
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { route, bad, HttpError, rateLimit } from '../http.js';
import { config } from '../config.js';
import { run, get, all, now, json, randomToken } from '../db.js';
import { requireOrg, normalizeDomain, normalizeEmail } from '../access.js';
import { email, telegram } from '../notify.js';

// Only organisation admins can run drills on people.
function requireDrillAdmin(ctx) {
  const r = requireOrg(ctx, 'drills');
  if (r.org.role === 'member') throw new HttpError(403, 'Only organisation admins can run Scam Drills.');
  return r;
}
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* Templates use fictional brands only. {{name}} {{org}} {{link}} are filled per target. */
export const TEMPLATES = {
  wallet_verify: { label: 'Wallet verification', from: 'Wallet Security Team', subject: 'Action required: verify your wallet within 24 hours',
    body: 'Hi {{name}},<br><br>We detected unusual activity linked to your wallet. To avoid a temporary freeze, verify ownership within 24 hours.<br><br><a href="{{link}}">Verify my wallet</a><br><br>Vaultline Wallet Security', landing: 'seed',
    clues: ['Real wallets never ask you to "verify" by entering your recovery phrase.', 'The 24-hour deadline is there to rush you.', 'The sender address does not match any wallet company you use.'] },
  airdrop: { label: 'Airdrop claim', from: 'Community Rewards', subject: "You're eligible: claim your community airdrop",
    body: 'Hi {{name}},<br><br>Your address qualified for the season 2 community airdrop. Claims close soon.<br><br><a href="{{link}}">Claim my allocation</a>', landing: 'connect',
    clues: ['Unexpected airdrops that need you to connect and sign are the most common drainer trick.', 'Pressure to claim "before it closes".', 'You did nothing to earn it.'] },
  exchange_login: { label: 'Exchange sign-in alert', from: 'Account Security', subject: 'New sign-in from an unrecognised device',
    body: 'Hi {{name}},<br><br>We noticed a new sign-in to your exchange account. If this was not you, secure your account now.<br><br><a href="{{link}}">This wasn\'t me</a>', landing: 'login',
    clues: ['Security emails push you to click a link instead of opening the app yourself.', 'It does not name the device, place or time in a way you can check.', 'The link goes to a site that is not the exchange.'] },
  payroll: { label: 'Payout address change', from: '{{org}} Finance', subject: "Updated payout address for this month's contributors",
    body: 'Hi {{name}},<br><br>Please review the updated treasury payout address before Friday\'s run.<br><br><a href="{{link}}">Open the document</a>', landing: 'login',
    clues: ['Changes to payout addresses should always be confirmed by voice with a known person.', 'Finance would not ask you to sign in through an email link.', 'Urgency around a payment deadline.'] },
  support_dm: { label: 'Fake support (community)', from: 'Support', subject: 'Wallet sync error',
    body: 'Hi, this is the support team. We found a sync error on your wallet. Validate it here so your funds are not frozen: {{link}}', landing: 'seed',
    clues: ['Real support never messages you first.', 'Nobody legitimate asks you to "validate" or "sync" a wallet.', 'Admins will never DM you a link.'] }
};

/* ---------------- verified domains (who may be targeted) ---------------- */
route('POST', '/api/org/domains', ctx => {
  const { org } = requireDrillAdmin(ctx);
  const d = normalizeDomain(ctx.body.domain);
  const tokens = json(org.domain_tokens);
  tokens[d] ||= 'bodyguard-verify=' + randomToken(12);
  run('update orgs set domain_tokens = ? where id = ?', JSON.stringify(tokens), org.id);
  return { domain: d, txt: tokens[d], instructions: `Add a TXT record on ${d} with the value ${tokens[d]}, then press Verify.` };
});
route('POST', '/api/org/domains/:domain/verify', async ctx => {
  const { org } = requireDrillAdmin(ctx);
  const d = normalizeDomain(ctx.params.domain);
  const tokens = json(org.domain_tokens);
  if (!tokens[d]) throw bad('Add the domain first.');
  let txt = [];
  try { txt = (await dns.resolveTxt(d)).map(r => r.join('')); } catch {}
  if (!txt.includes(tokens[d])) throw bad(`The TXT record ${tokens[d]} was not found on ${d} yet. DNS can take a few minutes.`);
  const verified = new Set(json(org.verified_domains, [])); verified.add(d);
  delete tokens[d];
  run('update orgs set verified_domains = ?, domain_tokens = ? where id = ?', JSON.stringify([...verified]), JSON.stringify(tokens), org.id);
  return { verified: [...verified] };
});

/* ---------------- campaigns ---------------- */
route('POST', '/api/org/drill-chat-link', ctx => {
  const { org } = requireDrillAdmin(ctx);
  if (!config.telegram.token || !config.telegram.username) throw new HttpError(503, 'Telegram is not switched on yet.');
  const code = 'd' + randomToken(9).replace(/[^A-Za-z0-9]/g, '');
  run('insert into channels(subject, link_code) values(?,?) on conflict(subject) do update set link_code = excluded.link_code', 'drillchat:' + org.id, code);
  return { url: `https://t.me/${config.telegram.username}?startgroup=${code}` };
});
route('GET', '/api/org/drill-chat', ctx => {
  const { org } = requireOrg(ctx, 'drills');
  return { connected: !!get('select telegram_chat_id from channels where subject = ?', 'drillchat:' + org.id)?.telegram_chat_id };
});
route('GET', '/api/org/drills/templates', () => ({ templates: Object.fromEntries(Object.entries(TEMPLATES).map(([k, t]) => [k, { label: t.label, subject: t.subject, landing: t.landing }])) }));
route('GET', '/api/org/drills', ctx => {
  const { org } = requireOrg(ctx, 'drills');
  return { drills: all('select * from drills where org_id = ? order by created_at desc', org.id).map(d => ({ ...d, settings: json(d.settings), ...stats(d.id) })) };
});
route('POST', '/api/org/drills', ctx => {
  const { org } = requireDrillAdmin(ctx);
  const tpl = TEMPLATES[ctx.body.template];
  if (!tpl) throw bad('Pick a template.');
  const channel = ctx.body.channel === 'telegram' ? 'telegram' : 'email';
  if (!ctx.body.authorised) throw bad('Confirm that you are authorised to run this drill on these people.');
  const id = 'dr_' + crypto.randomBytes(6).toString('hex');
  // The display name goes into the email From header: strip anything that could add a second address or header.
  const settings = { fromName: String(ctx.body.fromName || '').replace(/[<>"',;:\\@\r\n\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60) || null };
  if (channel === 'email') {
    const verified = json(org.verified_domains, []);
    if (!verified.length) throw bad('Verify your company domain first. Email drills can only go to addresses on domains you own.');
    if (ctx.body.targets != null && !Array.isArray(ctx.body.targets)) throw bad('targets must be a list.');
    const targets = (ctx.body.targets || []).map(t => (typeof t === 'string' ? { email: t } : t)).slice(0, 2000);
    if (!targets.length) throw bad('Add at least one person to the drill.');
    const clean = targets.map(t => ({ email: normalizeEmail(t.email), name: String(t.name || '').slice(0, 60) }));
    const outside = clean.filter(t => !verified.some(d => t.email.endsWith('@' + d) || t.email.endsWith('.' + d)));
    if (outside.length) throw bad(`These addresses are not on a verified domain: ${outside.slice(0, 5).map(t => t.email).join(', ')}.`);
    run('insert into drills(id, org_id, name, channel, template, status, created_at, settings) values(?,?,?,?,?,?,?,?)', id, org.id, String(ctx.body.name || tpl.label).slice(0, 80), channel, ctx.body.template, 'draft', now(), JSON.stringify(settings));
    for (const t of clean) run('insert into drill_targets(token, drill_id, email, name) values(?,?,?,?)', randomToken(16), id, t.email, t.name);
  } else {
    // Community drills only post in a group this organisation connected itself, never a chat ID typed in.
    const chat = get('select telegram_chat_id from channels where subject = ?', 'drillchat:' + org.id)?.telegram_chat_id;
    if (!chat) throw bad('Connect your community Telegram group first (Connect community group), then create the drill.');
    settings.telegramChatId = chat;
    run('insert into drills(id, org_id, name, channel, template, status, created_at, settings) values(?,?,?,?,?,?,?,?)', id, org.id, String(ctx.body.name || tpl.label).slice(0, 80), channel, ctx.body.template, 'draft', now(), JSON.stringify(settings));
    run('insert into drill_targets(token, drill_id, email, name) values(?,?,?,?)', randomToken(16), id, null, 'Community');
  }
  return { id, ...stats(id) };
}, { limit: 600_000 });

route('POST', '/api/org/drills/:did/send', async ctx => {
  const { org } = requireDrillAdmin(ctx);
  const d = get('select * from drills where id = ? and org_id = ?', ctx.params.did, org.id);
  if (!d) throw new HttpError(404, 'Drill not found.');
  if (d.status === 'sent') throw bad('This drill has already been sent.');
  rateLimit('drillsend:' + org.id, 4);
  const tpl = TEMPLATES[d.template];
  const settings = json(d.settings);
  const targets = all('select * from drill_targets where drill_id = ?', d.id);
  let sent = 0;
  if (d.channel === 'email') {
    if (!config.resend.key || !config.resend.drillFrom) throw new HttpError(503, 'Set RESEND_API_KEY and DRILL_FROM_EMAIL (a sending domain you own just for drills).');
    for (const t of targets) {
      const link = `${config.publicUrl}/d/c/${t.token}`;
      const fill = s => s.replaceAll('{{name}}', esc(t.name || 'there')).replaceAll('{{org}}', esc(org.name)).replaceAll('{{link}}', link);
      const fromName = (settings.fromName || tpl.from.replaceAll('{{org}}', org.name)).replace(/[<>"',;:\\@\r\n\u0000-\u001f]/g, ' ').slice(0, 60);
      const fromAddr = config.resend.drillFrom.replace(/^.*</, '').replace(/>.*$/, '');
      const html = `${fill(tpl.body)}<img src="${config.publicUrl}/d/o/${t.token}.gif" width="1" height="1" alt="">`;
      if (await email(t.email, fill(tpl.subject), html, fill(tpl.body).replace(/<[^>]+>/g, ' '), `${fromName} <${fromAddr}>`)) { run('update drill_targets set sent_at = ? where token = ?', now(), t.token); sent++; }
    }
  } else {
    const t = targets[0];
    const text = tpl.body.replaceAll('{{link}}', `${config.publicUrl}/d/c/${t.token}`).replaceAll('{{name}}', '').replaceAll('{{org}}', esc(org.name));
    if (!(await telegram(settings.telegramChatId, esc(text).replace(/&lt;br&gt;/g, '\n')))) throw bad('The bot could not post in that group. Add it as an admin and try again.');
    run('update drill_targets set sent_at = ? where token = ?', now(), t.token); sent = 1;
  }
  run("update drills set status = 'sent', sent_at = ? where id = ?", now(), d.id);
  return { sent, ...stats(d.id) };
});

function stats(drillId) {
  const s = get(`select count(*) total, count(sent_at) sent, count(opened_at) opened, count(clicked_at) clicked, count(submitted_at) submitted, count(trained_at) trained, avg(quiz_score) quiz from drill_targets where drill_id = ?`, drillId);
  const clicks = get("select count(*) c from drill_events e join drill_targets t on t.token = e.token where t.drill_id = ? and e.kind = 'click'", drillId).c;
  const submits = get("select count(*) c from drill_events e join drill_targets t on t.token = e.token where t.drill_id = ? and e.kind = 'submit'", drillId).c;
  return { stats: { ...s, clickEvents: clicks, submitEvents: submits } };
}
route('GET', '/api/org/drills/:did/report', ctx => {
  const { org } = requireOrg(ctx, 'drills');
  const d = get('select * from drills where id = ? and org_id = ?', ctx.params.did, org.id);
  if (!d) throw new HttpError(404, 'Drill not found.');
  const s = stats(d.id).stats;
  const targets = all('select email, name, sent_at, opened_at, clicked_at, submitted_at, trained_at, quiz_score from drill_targets where drill_id = ?', d.id);
  const base = d.channel === 'telegram' ? Math.max(1, s.clickEvents) : Math.max(1, s.sent);
  const clickRate = d.channel === 'telegram' ? null : s.clicked / base;
  const submitRate = d.channel === 'telegram' ? s.submitEvents / base : s.submitted / base;
  const fixes = [];
  if (clickRate != null && clickRate > 0.15) fixes.push('More than 1 in 7 people clicked. Run the training with everyone and repeat a drill in 30 days.');
  if (submitRate > 0.05) fixes.push('Some people would have handed over a recovery phrase or password. Make "no one ever needs your seed phrase" a written rule and repeat it in onboarding.');
  if (d.template === 'payroll') fixes.push('Require voice confirmation from two known people for any payout address change.');
  if (d.channel === 'telegram') fixes.push('Pin a message in your community saying admins never DM first and never send links.');
  if (!fixes.length) fixes.push('Good result. Keep running a drill every quarter so it stays that way.');
  return { drill: { ...d, settings: json(d.settings) }, stats: s, rates: { click: clickRate, submit: submitRate }, targets, fixes, clues: TEMPLATES[d.template]?.clues || [] };
});

/* ---------------- public tracking + safe landing pages ---------------- */
const GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
const ua = ctx => String(ctx.req.headers['user-agent'] || '').slice(0, 200);
function track(ctx, token, kind, column) {
  const t = get('select * from drill_targets where token = ?', token);
  if (!t) return null;
  run('insert into drill_events(token, kind, created_at, ip, ua) values(?,?,?,?,?)', token, kind, now(), crypto.createHash('sha256').update(ctx.ip).digest('hex').slice(0, 16), ua(ctx));
  if (column) run(`update drill_targets set ${column} = coalesce(${column}, ?) where token = ?`, now(), token);
  return t;
}
route('GET', '/d/o/:token', ctx => { track(ctx, ctx.params.token.replace(/\.gif$/, ''), 'open', 'opened_at'); return { __raw: GIF, headers: { 'content-type': 'image/gif', 'cache-control': 'no-store' } }; });
route('GET', '/d/c/:token', ctx => {
  if (/bot|preview|scanner|safelinks|proofpoint|mimecast|barracuda/i.test(ua(ctx))) return { __html: '<!doctype html><title>Link check</title>', status: 200 };
  const t = track(ctx, ctx.params.token, 'click', 'clicked_at');
  if (!t) return { __html: notFound(), status: 404 };
  return { __redirect: `${config.publicUrl}/d/l/${t.token}` };
});
route('GET', '/d/l/:token', ctx => {
  const t = get('select t.*, d.template from drill_targets t join drills d on d.id = t.drill_id where token = ?', ctx.params.token);
  if (!t) return { __html: notFound(), status: 404 };
  return { __html: landing(t.token, TEMPLATES[t.template]?.landing || 'login'), headers: { 'cache-control': 'no-store', 'x-robots-tag': 'noindex' } };
});
// Records only THAT the form was submitted. The page discards every value before this request is made.
route('POST', '/d/s/:token', ctx => { track(ctx, ctx.params.token, 'submit', 'submitted_at'); return { ok: true }; });

route('GET', '/learn/:token', ctx => {
  const t = get('select t.*, d.template, d.org_id from drill_targets t join drills d on d.id = t.drill_id where token = ?', ctx.params.token);
  if (!t) return { __html: notFound(), status: 404 };
  const org = get('select name from orgs where id = ?', t.org_id);
  return { __html: training(t, TEMPLATES[t.template], org?.name || 'your organisation', ctx.query.caught === '1'), headers: { 'cache-control': 'no-store', 'x-robots-tag': 'noindex' } };
});
route('POST', '/learn/:token/quiz', ctx => {
  const t = get('select * from drill_targets where token = ?', ctx.params.token);
  if (!t) throw new HttpError(404, 'Not found');
  const answers = ctx.body.answers || [];
  const score = QUIZ.reduce((s, q, i) => s + (Number(answers[i]) === q.a ? 1 : 0), 0);
  run('update drill_targets set trained_at = coalesce(trained_at, ?), quiz_score = ? where token = ?', now(), score, t.token);
  return { score, total: QUIZ.length, answers: QUIZ.map(q => q.a) };
});

const QUIZ = [
  { q: 'A support agent messages you first on Telegram offering to fix a wallet error. What do you do?', o: ['Follow their steps quickly', 'Ignore and report it. Real support never messages first', 'Ask them to prove who they are'], a: 1 },
  { q: 'Who should ever see your 12 or 24-word recovery phrase?', o: ['Wallet support', 'No one, ever', 'Only an official website'], a: 1 },
  { q: 'An email says your exchange account was accessed. Best next step?', o: ['Click "This wasn\'t me" in the email', 'Open the exchange app yourself and check there', 'Reply to the email'], a: 1 },
  { q: 'An airdrop site asks you to connect and sign to claim. Before signing you should…', o: ['Sign fast before it closes', 'Read exactly what the wallet says you are approving, and walk away if unsure', 'Approve unlimited spending to save gas'], a: 1 },
  { q: 'A colleague asks in chat to change the payout address. You…', o: ['Update it', 'Confirm by phone with them and a second known person', 'Ask for a screenshot'], a: 1 }
];

const PAGE_CSS = `body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f3f5f7;color:#16202a}main{max-width:440px;margin:48px auto;padding:0 18px}.card{background:#fff;border-radius:14px;padding:28px;box-shadow:0 10px 40px -20px #0003}h1{font-size:22px;margin:0 0 6px}p{color:#4a5866;line-height:1.5}label{display:block;font-size:13px;font-weight:600;margin:16px 0 6px}input,textarea{width:100%;box-sizing:border-box;border:1px solid #cfd8e0;border-radius:8px;padding:11px;font:inherit}button{margin-top:18px;width:100%;padding:13px;border:0;border-radius:8px;background:#2357d8;color:#fff;font-weight:600;font-size:15px;cursor:pointer}.small{font-size:12px;color:#7a8794;margin-top:18px;text-align:center}`;
function landing(token, kind) {
  const fields = kind === 'seed' ? '<label for="f1">Recovery phrase (12 or 24 words)</label><textarea id="f1" rows="3" autocomplete="off"></textarea>'
    : kind === 'connect' ? '<p>Connect your wallet to see your allocation.</p><label for="f1">Wallet address</label><input id="f1" autocomplete="off">'
    : '<label for="f1">Email</label><input id="f1" type="email" autocomplete="off"><label for="f2">Password</label><input id="f2" type="password" autocomplete="off">';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Account verification</title><style>${PAGE_CSS}</style></head>
<body><main><div class="card"><h1>${kind === 'connect' ? 'Claim your allocation' : 'Verify your account'}</h1><p>${kind === 'seed' ? 'Enter your recovery phrase to confirm wallet ownership and remove the hold.' : kind === 'connect' ? 'Your address is eligible.' : 'Sign in to secure your account.'}</p>
<form id="f" autocomplete="off">${fields}<button type="submit">${kind === 'connect' ? 'Connect and claim' : 'Continue'}</button></form><p class="small">Verification portal</p></div></main>
<script>
document.getElementById('f').addEventListener('submit', function (e) {
  e.preventDefault();
  // Training simulation: wipe every field before anything is sent. Only the fact of submission is recorded.
  this.querySelectorAll('input,textarea').forEach(function (el) { el.value = ''; });
  fetch('/d/s/${token}', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }).finally(function () { location.href = '/learn/${token}?caught=1'; });
});
</script></body></html>`;
}
function training(t, tpl, orgName, caught) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Scam Drill</title>
<style>body{margin:0;background:#0a0d0b;color:#e3ebe5;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.6}main{max-width:680px;margin:0 auto;padding:40px 18px 80px}
.k{font:12px ui-monospace,Menlo,monospace;letter-spacing:.14em;color:#c8ff1a;text-transform:uppercase}h1{font-size:32px;line-height:1.1;margin:10px 0}h2{font-size:20px;margin:34px 0 8px}
.box{border:1px solid #33423a;border-radius:12px;padding:18px;background:#111612;margin-top:16px}li{margin:6px 0}.q{margin:18px 0}.q label{display:block;padding:8px 10px;border:1px solid #243029;border-radius:8px;margin:6px 0;cursor:pointer}
button{background:#c8ff1a;color:#121a00;border:0;border-radius:10px;padding:12px 18px;font-weight:700;font-size:15px;cursor:pointer}.ok{color:#c8ff1a}.bad{color:#ff5a6b}</style></head><body><main>
<div class="k">Bodyguard Scam Drill</div>
<h1>${caught ? 'This was a training drill.' : 'Scam awareness training'}</h1>
<p>${caught ? `Nothing you typed was sent or saved. This was a practice scam run by ${esc(orgName)} with Bodyguard, so you can spot the real thing.` : `Short training from ${esc(orgName)} and Bodyguard.`}</p>
<div class="box"><b>What gave it away</b><ul>${(tpl?.clues || []).map(c => `<li>${esc(c)}</li>`).join('')}</ul></div>
<h2>The five rules</h2><ol><li>No one legitimate ever needs your recovery phrase.</li><li>Real support never messages you first.</li><li>Don't click security links in emails. Open the app or type the address yourself.</li><li>Read what your wallet says before you sign. Unlimited approvals and "free" listings are red flags.</li><li>Confirm any change to a payment address by voice with someone you know.</li></ol>
<h2>Quick check</h2><form id="quiz">${QUIZ.map((q, i) => `<div class="q"><b>${i + 1}. ${esc(q.q)}</b>${q.o.map((o, j) => `<label><input type="radio" name="q${i}" value="${j}"> ${esc(o)}</label>`).join('')}</div>`).join('')}<button type="submit">Check my answers</button></form><p id="res" role="status"></p>
<script>
document.getElementById('quiz').addEventListener('submit', async function (e) {
  e.preventDefault();
  var answers = [${QUIZ.map((_, i) => `(document.querySelector('input[name=q${i}]:checked')||{}).value`).join(',')}];
  var r = await fetch('/learn/${t.token}/quiz', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ answers: answers }) }).then(function (x) { return x.json(); });
  document.getElementById('res').innerHTML = '<b class="' + (r.score >= 4 ? 'ok' : 'bad') + '">You scored ' + r.score + ' out of ' + r.total + '.</b> ' + (r.score >= 4 ? 'Nicely done.' : 'Read the five rules again. The right answer is the second option every time.');
});
</script></main></body></html>`;
}
const notFound = () => '<!doctype html><meta charset="utf-8"><title>Not found</title><p style="font-family:sans-serif;padding:40px">This link has expired.</p>';
