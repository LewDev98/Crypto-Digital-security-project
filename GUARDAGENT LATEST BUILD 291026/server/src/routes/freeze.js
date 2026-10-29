// Freeze Desk API: one form in, evidence locked, freeze requests out, and a live trace afterwards.
import crypto from 'node:crypto';
import { route, bad, HttpError, rateLimit, sessionWallet } from '../http.js';
import { config } from '../config.js';
import { run, get, all, now, json, encryptBuf, decryptBuf, sha256hex, kvGet, kvSet } from '../db.js';
import { requireOrg, requireAdmin, normalizeEmail, normalizeAddress } from '../access.js';
import { verifyEd25519, rpcClient } from '../lib/solana.js';
import { b58decode as b58 } from '../lib/base58.js';
import { email } from '../notify.js';
import { raiseOrg } from '../alerts.js';
import { directory, targetById, fetchTx, buildManifest, signReceipt, receiptMessage, evidencePublicKey, requestText, validTxHash, CHAINS, SCAM_TYPES, isAddr } from '../freeze.js';

const MAX_FILES = 6, MAX_FILE = 2 * 1024 * 1024;
const clean = (v, n) => String(v ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, n);
const oneLine = (v, n) => clean(v, n).replace(/[\r\n]+/g, ' ');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// File type is decided by its first bytes, never by the name or what the browser claims.
function sniff(buf) {
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return { type: 'image/png', ext: 'png' };
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { type: 'image/jpeg', ext: 'jpg' };
  if (buf.subarray(0, 4).toString() === 'RIFF' && buf.subarray(8, 12).toString() === 'WEBP') return { type: 'image/webp', ext: 'webp' };
  if (buf.subarray(0, 5).toString() === '%PDF-') return { type: 'application/pdf', ext: 'pdf' };
  return null;
}
function addrList(v, max, label) {
  if (v == null) return [];
  if (!Array.isArray(v)) throw bad(`${label} must be a list.`);
  return v.slice(0, max).map(x => {
    const chain = String(x?.chain || '').toLowerCase();
    if (!CHAINS.includes(chain)) throw bad(`Pick a supported chain for each ${label.toLowerCase()} entry.`);
    try { return { chain, address: normalizeAddress(chain, x.address) }; } catch { throw bad(`${label}: "${oneLine(x?.address, 60)}" isn't a valid ${chain} address.`); }
  });
}

function incidentView(inc, { full = false } = {}) {
  const d = json(inc.data);
  const m = d.manifest || {};
  return {
    id: inc.id, ref: d.ref, status: inc.status, title: inc.title, createdAt: inc.created_at, hash: inc.manifest_hash, serverSignature: inc.server_sig, anchor: inc.anchor_sig,
    lockedAt: m.lockedAt, amount: m.incident?.amount, asset: m.incident?.asset, scamType: m.incident?.scamType,
    ...(full ? {
      manifest: m,
      files: all('select id, name, type, size, sha256 from incident_files where incident_id = ?', inc.id),
      requests: all('select id, target, channel, status, subject, body, sent_at, error from incident_requests where incident_id = ? order by created_at', inc.id).map(r => ({ ...r, targetInfo: publicTarget(targetById(r.target)) })),
      events: all('select kind, text, data, created_at from incident_events where incident_id = ? order by id desc limit 200', inc.id).map(e => ({ ...e, data: json(e.data) })),
      trace: json(inc.trace, {})
    } : {})
  };
}
const publicTarget = t => t && { id: t.id, name: t.name, kind: t.kind, url: t.url, note: t.note || '', email: !!t.email };
function own(ctx) {
  const { org, wallet } = requireOrg(ctx, 'freeze');
  const inc = get('select * from incidents where id = ? and org_id = ?', ctx.params.iid, org.id);
  if (!inc) throw new HttpError(404, 'Case not found.');
  return { org, wallet, inc };
}

async function sendRequests(inc, ids) {
  const d = json(inc.data), m = d.manifest;
  const files = all('select * from incident_files where incident_id = ?', inc.id);
  const attachments = [{ filename: `evidence-${d.ref}.json`, content: Buffer.from(inc.manifest).toString('base64') },
    ...files.map(f => ({ filename: f.name, content: decryptBuf(f.enc).toString('base64') }))];
  const out = [];
  for (const r of all('select * from incident_requests where incident_id = ?', inc.id)) {
    if (ids && !ids.includes(r.target)) continue;
    if (r.channel !== 'email' || r.status === 'sent') continue;
    const t = targetById(r.target);
    if (!t?.email) continue;
    rateLimit('freezemail:all', 120);
    const ok = await email(t.email, r.subject, `<pre style="font:13px/1.5 ui-monospace,Menlo,monospace;white-space:pre-wrap">${esc(r.body)}</pre>`, r.body, config.resend.freezeFrom,
      { replyTo: m.reporter.email, cc: m.reporter.email, attachments }).catch(() => false);
    run('update incident_requests set status = ?, sent_at = ?, error = ? where id = ?', ok ? 'sent' : 'failed', ok ? now() : null, ok ? null : 'Email could not be sent', r.id);
    run('insert into incident_events(incident_id, kind, text, data, created_at) values(?,?,?,?,?)', inc.id, ok ? 'sent' : 'send_failed', ok ? `Freeze request emailed to ${t.name}.` : `Could not email ${t.name}. Use the official form instead.`, '{}', now());
    out.push({ target: t.id, ok });
  }
  return out;
}

/* ---------------- directory ---------------- */
route('GET', '/api/freeze/directory', ctx => { requireOrg(ctx, 'freeze'); return { targets: directory().map(publicTarget), scamTypes: SCAM_TYPES }; });

/* ---------------- create a case ---------------- */
route('POST', '/api/freeze/incidents', async ctx => {
  const { org, wallet } = requireOrg(ctx, 'freeze');
  rateLimit('freeze:' + org.id, 6);
  if (get('select count(*) c from incidents where org_id = ? and created_at > ?', org.id, now() - 86400).c >= 10) throw new HttpError(429, 'You can open up to 10 cases a day. Contact support if you need more.');
  const b = ctx.body;
  if (b.attest !== true) throw bad('Confirm that the information is true to the best of your knowledge.');
  const reporter = { wallet, name: oneLine(b.victim?.name, 80), email: normalizeEmail(b.victim?.email), phone: oneLine(b.victim?.phone, 24).replace(/[^\d+\-() ]/g, ''), country: oneLine(b.victim?.country, 56) };
  if (!reporter.name) throw bad('Add your name so exchanges know who to contact.');
  const scamType = SCAM_TYPES[b.scamType] ? b.scamType : 'other';
  const victimWallets = addrList(b.victimWallets, 5, 'Your wallets');
  const scammerAddresses = addrList(b.scammerAddresses, 10, 'Scammer addresses');
  if (!Array.isArray(b.transactions ?? [])) throw bad('transactions must be a list.');
  const txIn = (b.transactions || []).slice(0, 20).map(t => {
    const chain = String(t?.chain || '').toLowerCase();
    const hash = CHAINS.includes(chain) && validTxHash(chain, t.hash);
    if (!hash) throw bad(`"${oneLine(t?.hash, 70)}" isn't a valid ${chain || ''} transaction ID.`);
    return { chain, hash };
  });
  if (!scammerAddresses.length && !txIn.length) throw bad('Add at least one scammer address or transaction ID.');
  const description = clean(b.description, 4000);
  if (description.length < 20) throw bad('Describe what happened in a few sentences.');
  const occurredAt = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2})?/.test(String(b.occurredAt || '')) ? String(b.occurredAt).slice(0, 16) : null;
  const targets = [...new Set((Array.isArray(b.targets) ? b.targets : []).map(String))].filter(id => targetById(id)).slice(0, 25);

  // Files: decode, check type by content, hash, encrypt.
  if (b.files != null && !Array.isArray(b.files)) throw bad('files must be a list.');
  const files = (b.files || []).slice(0, MAX_FILES + 1).map((f, i) => {
    if (i >= MAX_FILES) throw bad(`Attach up to ${MAX_FILES} files.`);
    const buf = Buffer.from(String(f?.data || '').replace(/^data:[^,]*,/, ''), 'base64');
    if (!buf.length || buf.length > MAX_FILE) throw bad('Each file must be under 2 MB.');
    const kind = sniff(buf);
    if (!kind) throw bad('Attach screenshots (PNG, JPG, WebP) or PDFs only.');
    const base = oneLine(f.name, 60).replace(/[^\w.\- ]/g, '_').replace(/\.[^.]*$/, '') || `evidence-${i + 1}`;
    return { name: `${base}.${kind.ext}`, type: kind.type, size: buf.length, sha256: sha256hex(buf), buf };
  });

  // The agent reads every listed transaction from the chain itself.
  const transactions = await Promise.all(txIn.map(t => fetchTx(t.chain, t.hash)));
  const lockedAt = new Date().toISOString();
  const ref = 'BG-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const manifest = {
    version: 'bodyguard-evidence/1', ref, lockedAt, reporter,
    incident: { scamType, occurredAt, amount: oneLine(b.amount, 40), asset: oneLine(b.asset, 20), policeRef: oneLine(b.policeRef, 80), description },
    victimWallets, scammerAddresses, transactions,
    files: files.map(({ name, type, size, sha256 }) => ({ name, type, size, sha256 }))
  };
  const { text, hash } = buildManifest(manifest);
  const sig = signReceipt(hash, lockedAt);
  const id = 'inc_' + crypto.randomBytes(6).toString('hex');
  // Addresses the funds went to are watched from now on.
  const watch = [...scammerAddresses];
  const mine = new Set(victimWallets.map(v => v.address.toLowerCase()));
  for (const t of transactions) for (const x of t.transfers || []) if (x.to && mine.has(String(x.from).toLowerCase()) && !mine.has(String(x.to).toLowerCase()) && isAddr(t.chain, x.to) && !watch.some(w => w.address === x.to)) watch.push({ chain: t.chain, address: EVM_LOWER(t.chain, x.to) });
  const inc = { id, org_id: org.id, wallet, status: 'open', title: `${SCAM_TYPES[scamType]}${manifest.incident.amount ? ` · ${manifest.incident.amount} ${manifest.incident.asset}` : ''}`.slice(0, 120), manifest: text, manifest_hash: hash, server_sig: sig };
  run('insert into incidents(id, org_id, wallet, status, title, manifest, manifest_hash, server_sig, data, trace, created_at, updated_at) values(?,?,?,?,?,?,?,?,?,?,?,?)',
    id, org.id, wallet, 'open', inc.title, text, hash, sig, JSON.stringify({ ref, manifest }), JSON.stringify({ watch: watch.slice(0, 8).map(w => ({ ...w, depth: 0 })), hops: [], last: {} }), now(), now());
  for (const f of files) run('insert into incident_files(id, incident_id, name, type, size, sha256, enc, created_at) values(?,?,?,?,?,?,?,?)', 'f_' + crypto.randomBytes(6).toString('hex'), id, f.name, f.type, f.size, f.sha256, encryptBuf(f.buf), now());
  run('insert into incident_events(incident_id, kind, text, data, created_at) values(?,?,?,?,?)', id, 'locked', `Evidence locked and signed. Fingerprint ${hash.slice(0, 16)}…`, JSON.stringify({ verified: transactions.filter(t => t.verified).length, total: transactions.length }), now());
  const full = { ...inc, ref, data: JSON.stringify({ ref, manifest }) };
  for (const tid of targets) {
    const t = targetById(tid);
    const { subject, body } = requestText({ ...full, data: { ref, manifest, trace: {} } }, t);
    run('insert into incident_requests(id, incident_id, target, channel, status, subject, body, created_at) values(?,?,?,?,?,?,?,?)',
      'rq_' + crypto.randomBytes(6).toString('hex'), id, tid, t.email && config.resend.key ? 'email' : 'manual', t.email && config.resend.key ? 'queued' : 'ready', subject, body, now());
  }
  if (b.send === true) await sendRequests(get('select * from incidents where id = ?', id));
  // Copy for the victim, so they hold the receipt even if they lose access to the dashboard.
  email(reporter.email, `Your Freeze Desk case ${ref}: evidence locked`, `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;line-height:1.5"><h2>Case ${esc(ref)}: evidence locked</h2><p>Your evidence was hashed and signed at ${esc(lockedAt)}.</p><p style="font:12px ui-monospace,monospace;word-break:break-all">SHA-256 ${esc(hash)}</p><p>Verify it any time: <a href="${config.publicUrl}/api/evidence/verify/${hash}">${config.publicUrl}/api/evidence/verify/${hash.slice(0, 12)}…</a></p><p>Next: file a police report and add the reference in your dashboard. Bodyguard will never ask for your seed phrase, and no one can "recover" funds for a fee. Recovery offers are a second scam.</p></div>`,
    `Case ${ref}: evidence locked at ${lockedAt}. SHA-256 ${hash}. Verify: ${config.publicUrl}/api/evidence/verify/${hash}`, config.resend.freezeFrom).catch(() => {});
  return incidentView(get('select * from incidents where id = ?', id), { full: true });
}, { limit: 12_000_000, preAuth: req => !!sessionWallet(req) });
const EVM_LOWER = (chain, a) => (chain === 'solana' || chain === 'bitcoin' ? a : String(a).toLowerCase());

/* ---------------- read, send, update ---------------- */
route('GET', '/api/freeze/incidents', ctx => {
  const { org } = requireOrg(ctx, 'freeze');
  return { incidents: all('select * from incidents where org_id = ? order by created_at desc limit 100', org.id).map(i => incidentView(i)) };
});
route('GET', '/api/freeze/incidents/:iid', ctx => incidentView(own(ctx).inc, { full: true }));
route('POST', '/api/freeze/incidents/:iid/send', async ctx => {
  const { inc } = own(ctx);
  rateLimit('freezesend:' + inc.id, 4);
  if (!config.resend.key) throw new HttpError(503, 'Email is not switched on for this server yet. Use the official forms instead.');
  const ids = Array.isArray(ctx.body.targets) ? ctx.body.targets.map(String) : null;
  return { results: await sendRequests(inc, ids), ...incidentView(inc, { full: true }) };
});
route('POST', '/api/freeze/incidents/:iid/targets', ctx => {
  const { inc } = own(ctx);
  const d = json(inc.data);
  const have = new Set(all('select target from incident_requests where incident_id = ?', inc.id).map(r => r.target));
  for (const tid of (Array.isArray(ctx.body.targets) ? ctx.body.targets : []).map(String).slice(0, 25)) {
    const t = targetById(tid);
    if (!t || have.has(tid)) continue;
    const { subject, body } = requestText({ ...inc, data: { ...d, trace: json(inc.trace) } }, t);
    run('insert into incident_requests(id, incident_id, target, channel, status, subject, body, created_at) values(?,?,?,?,?,?,?,?)',
      'rq_' + crypto.randomBytes(6).toString('hex'), inc.id, tid, t.email && config.resend.key ? 'email' : 'manual', t.email && config.resend.key ? 'queued' : 'ready', subject, body, now());
  }
  return incidentView(inc, { full: true });
});
route('POST', '/api/freeze/requests/:rid/mark', ctx => {
  const { org } = requireOrg(ctx, 'freeze');
  const r = get('select r.* from incident_requests r join incidents i on i.id = r.incident_id where r.id = ? and i.org_id = ?', ctx.params.rid, org.id);
  if (!r) throw new HttpError(404, 'Request not found.');
  const status = ['submitted', 'ready', 'acknowledged', 'frozen', 'declined'].includes(ctx.body.status) ? ctx.body.status : 'submitted';
  run('update incident_requests set status = ?, sent_at = coalesce(sent_at, ?) where id = ?', status, now(), r.id);
  run('insert into incident_events(incident_id, kind, text, data, created_at) values(?,?,?,?,?)', r.incident_id, 'request_' + status, `${targetById(r.target)?.name || r.target}: marked ${status}.`, '{}', now());
  return { ok: true };
});
route('POST', '/api/freeze/incidents/:iid/note', ctx => {
  const { inc } = own(ctx);
  const text = clean(ctx.body.text, 1000);
  if (!text) throw bad('Write a note.');
  run('insert into incident_events(incident_id, kind, text, data, created_at) values(?,?,?,?,?)', inc.id, 'note', text, '{}', now());
  if (ctx.body.status === 'closed' || ctx.body.status === 'open') run('update incidents set status = ?, updated_at = ? where id = ?', ctx.body.status, now(), inc.id);
  return incidentView(get('select * from incidents where id = ?', inc.id), { full: true });
});

/* ---------------- downloads ---------------- */
route('GET', '/api/freeze/incidents/:iid/manifest', ctx => {
  const { inc } = own(ctx);
  return { __raw: inc.manifest, headers: { 'content-type': 'application/json; charset=utf-8', 'content-disposition': `attachment; filename="evidence-${json(inc.data).ref}.json"`, 'cache-control': 'no-store' } };
});
route('GET', '/api/freeze/incidents/:iid/files/:fid', ctx => {
  const { inc } = own(ctx);
  const f = get('select * from incident_files where id = ? and incident_id = ?', ctx.params.fid, inc.id);
  if (!f) throw new HttpError(404, 'File not found.');
  return { __raw: decryptBuf(f.enc), headers: { 'content-type': f.type, 'content-disposition': `attachment; filename="${f.name}"`, 'cache-control': 'no-store', 'content-security-policy': "default-src 'none'; sandbox" } };
});

/* ---------------- public timestamp on Solana ---------------- */
route('POST', '/api/freeze/incidents/:iid/anchor', async ctx => {
  const { inc } = own(ctx);
  const sig = String(ctx.body.signature || '');
  if (!/^[1-9A-HJ-NP-Za-km-z]{64,90}$/.test(sig)) throw bad('That is not a valid transaction signature.');
  if (!config.solana.rpc) throw new HttpError(503, 'Solana RPC is not configured.');
  let t = null;
  for (let i = 0; i < 5 && !t; i++) { t = await rpcClient(config.solana.rpc).getTransaction(sig).catch(() => null); if (!t) await new Promise(r => setTimeout(r, 1500)); }
  if (!t || t.meta?.err) throw bad("That transaction isn't confirmed on Solana yet. Wait a few seconds and try again.");
  const memo = t.transaction.message.instructions.find(i => i.program === 'spl-memo' && typeof i.parsed === 'string' && i.parsed.trim() === `bodyguard:evidence:${inc.manifest_hash}`);
  if (!memo) throw bad("That transaction doesn't carry this case's evidence fingerprint.");
  run('update incidents set anchor_sig = ?, updated_at = ? where id = ?', sig, now(), inc.id);
  run('insert into incident_events(incident_id, kind, text, data, created_at) values(?,?,?,?,?)', inc.id, 'anchored', 'Evidence fingerprint written to Solana as a public timestamp.', JSON.stringify({ sig, slot: t.slot }), now());
  return incidentView(get('select * from incidents where id = ?', inc.id), { full: true });
});

/* ---------------- public verification ---------------- */
route('GET', '/api/evidence/verify/:hash', ctx => {
  rateLimit('verify:' + ctx.ip, 60);
  const h = String(ctx.params.hash).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) throw bad('Give a 64-character SHA-256 fingerprint.');
  const inc = get('select manifest_hash, server_sig, anchor_sig, data, created_at from incidents where manifest_hash = ?', h);
  if (!inc) return { found: false, hash: h };
  const lockedAt = json(inc.data).manifest?.lockedAt;
  return { found: true, hash: h, lockedAt, message: receiptMessage(h, lockedAt), signature: inc.server_sig, publicKey: evidencePublicKey(),
    signatureValid: verifyEd25519(Buffer.from(receiptMessage(h, lockedAt)), Buffer.from(b58(inc.server_sig)), evidencePublicKey()),
    solanaAnchor: inc.anchor_sig ? `https://solscan.io/tx/${inc.anchor_sig}` : null,
    note: 'Bodyguard signed this fingerprint at the time shown. Hash the evidence file you were given with SHA-256: if it matches, the file has not changed since then. The contents stay private.' };
});
route('GET', '/.well-known/bodyguard-evidence-key.json', () => ({ algorithm: 'ed25519', encoding: 'base58', publicKey: evidencePublicKey(), message: 'bodyguard-evidence/1:<sha256>:<lockedAt>' }));

/* ---------------- admin: maintain the directory ---------------- */
route('GET', '/api/admin/freeze-directory', ctx => { requireAdmin(ctx); return { targets: directory() }; });
route('POST', '/api/admin/freeze-directory', async ctx => {
  ctx.adminWallet = requireAdmin(ctx);
  const id = String(ctx.body.id || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 40);
  if (!id) throw bad('Give the target an id.');
  const over = kvGet('freeze:directory', {});
  const cur = over[id] || {};
  if (ctx.body.name != null) cur.name = oneLine(ctx.body.name, 80);
  if (ctx.body.kind != null) cur.kind = ['exchange', 'issuer', 'police', 'responder'].includes(ctx.body.kind) ? ctx.body.kind : 'exchange';
  if (ctx.body.email != null) cur.email = ctx.body.email ? normalizeEmail(ctx.body.email) : '';
  if (ctx.body.url != null) { if (ctx.body.url && !/^https:\/\/[^\s<>"]+$/.test(ctx.body.url)) throw bad('URL must start with https://'); cur.url = String(ctx.body.url).slice(0, 300); }
  if (ctx.body.note != null) cur.note = oneLine(ctx.body.note, 300);
  if (ctx.body.addresses != null) {
    const a = {};
    for (const [chain, list] of Object.entries(ctx.body.addresses || {})) {
      if (![...CHAINS, 'evm'].includes(chain) || !Array.isArray(list)) continue;
      a[chain] = list.slice(0, 2000).map(String).filter(x => isAddr(chain === 'evm' ? 'ethereum' : chain, x));
    }
    cur.addresses = a;
  }
  over[id] = cur; kvSet('freeze:directory', over);
  (await import('../security.js')).log('admin_freeze_directory', { id, email: cur.email ? 'set' : '', url: cur.url || '' }, { actor: ctx.adminWallet, subject: 'admin' });
  return { target: directory().find(t => t.id === id) };
});

/* ---------------- trace job hook ---------------- */
export async function raiseTrace(inc, hop, hit) {
  // Funds landed at a known exchange: queue a freeze request to it straight away (the victim presses send).
  if (hit && !get('select 1 from incident_requests where incident_id = ? and target = ?', inc.id, hit.id)) {
    const fresh = get('select * from incidents where id = ?', inc.id);
    const { subject, body } = requestText({ ...fresh, data: { ...json(fresh.data), trace: json(fresh.trace) } }, hit);
    run('insert into incident_requests(id, incident_id, target, channel, status, subject, body, created_at) values(?,?,?,?,?,?,?,?)',
      'rq_' + crypto.randomBytes(6).toString('hex'), inc.id, hit.id, hit.email && config.resend.key ? 'email' : 'manual', hit.email && config.resend.key ? 'queued' : 'ready', subject, body, now());
  }
  return raiseOrg(inc.org_id, {
    severity: hit ? 'crit' : 'high', type: 'freeze_trace', dedupe: `trace:${inc.id}:${hop.tx}:${hop.to}`,
    title: hit ? `Stolen funds reached ${hit.name}` : 'Stolen funds just moved',
    what: hit ? `${hop.amount} ${hop.asset} from your case ${json(inc.data).ref} landed on an address linked to ${hit.name}.` : `${hop.amount} ${hop.asset} from your case ${json(inc.data).ref} moved to a new address.`,
    did: 'Your agent logged the movement in the case timeline' + (hit ? ' and added the exchange to the freeze targets.' : ' and is now watching the new address.'),
    move: hit ? `Send the freeze request to ${hit.name} now from your Freeze Desk case. Speed matters.` : 'Open the case and forward the update to the exchanges and police you contacted.',
    data: { incident: inc.id, link: hop.chain === 'solana' ? `https://solscan.io/tx/${hop.tx}` : undefined }
  });
}
