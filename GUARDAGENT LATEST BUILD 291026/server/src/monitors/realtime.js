// Real-time Solana patrol through Helius webhooks. Helius pushes every transaction that touches a watched wallet
// or treasury within seconds; the agent judges it straight away. Polling keeps running as a slower backstop in
// case a webhook is ever missed.
import crypto from 'node:crypto';
import { config } from '../config.js';
import { all, kvGet, kvSet, now } from '../db.js';
import { route, HttpError } from '../http.js';
import { activeAssets } from './common.js';
import { processSignature } from './solana.js';
import { pollTreasuries, activeTreasuries } from './treasury.js';

const API = 'https://api.helius.xyz/v0/webhooks';
export const realtimeEnabled = () => !!(config.helius.key && config.helius.secret && config.publicUrl.startsWith('https://'));

function watchedAddresses() {
  const a = new Set(activeAssets('wallet', 'solana').map(x => x.value));
  for (const t of activeTreasuries()) {
    if (t.chain !== 'solana') continue;
    a.add(t.address);
    for (const s of JSON.parse(t.signers || '[]')) a.add(s);
  }
  return [...a].slice(0, 100000);
}

// Keeps the Helius webhook's address list in step with what agents are watching.
export async function syncWebhook() {
  if (!realtimeEnabled()) return;
  const addrs = watchedAddresses();
  const hash = crypto.createHash('sha256').update(addrs.sort().join(',')).digest('hex');
  const st = kvGet('helius:webhook', {});
  if (st.hash === hash && st.id) return;
  if (!addrs.length && !st.id) return;
  const body = { webhookURL: `${config.publicUrl}/hooks/helius`, transactionTypes: ['ANY'], accountAddresses: addrs.length ? addrs : ['11111111111111111111111111111111'], webhookType: 'raw', authHeader: config.helius.secret };
  let id = st.id;
  if (!id) {
    const list = await fetch(`${API}?api-key=${config.helius.key}`, { signal: AbortSignal.timeout(20000) }).then(r => r.json()).catch(() => []);
    id = Array.isArray(list) ? list.find(w => w.webhookURL === body.webhookURL)?.webhookID : null;
  }
  const r = await fetch(id ? `${API}/${id}?api-key=${config.helius.key}` : `${API}?api-key=${config.helius.key}`, {
    method: id ? 'PUT' : 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(20000)
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('helius webhook ' + r.status + ' ' + (j.error || ''));
  kvSet('helius:webhook', { id: j.webhookID || id, hash, count: addrs.length, at: now() });
  console.log(`[realtime] webhook watching ${addrs.length} addresses`);
}

const queue = [];
let working = false;
async function drain() {
  if (working) return;
  working = true;
  try {
    while (queue.length) {
      const { sig, keys } = queue.shift();
      const set = new Set(keys);
      const assets = activeAssets('wallet', 'solana').filter(a => set.has(a.value) && JSON.parse(a.state || '{}').baseline);
      for (const a of assets) await processSignature(a, sig).catch(e => console.warn('[realtime]', e.message));
      if (activeTreasuries().some(t => t.chain === 'solana' && (set.has(t.address) || JSON.parse(t.signers || '[]').some(s => set.has(s))))) await pollTreasuries().catch(() => {});
    }
  } finally { working = false; }
}

const safeEqual = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

route('POST', '/hooks/helius', ({ req, body }) => {
  if (!realtimeEnabled()) throw new HttpError(404, 'Not found');
  if (!safeEqual(req.headers.authorization || '', config.helius.secret)) throw new HttpError(401, 'Unauthorised');
  const txs = Array.isArray(body) ? body : [body];
  for (const t of txs.slice(0, 500)) {
    const sig = t?.transaction?.signatures?.[0] || t?.signature;
    const keys = (t?.transaction?.message?.accountKeys || []).map(k => (typeof k === 'string' ? k : k.pubkey));
    const lookups = [...(t?.meta?.loadedAddresses?.writable || []), ...(t?.meta?.loadedAddresses?.readonly || [])];
    if (sig && /^[1-9A-HJ-NP-Za-km-z]{64,90}$/.test(sig)) queue.push({ sig, keys: [...keys, ...lookups] });
  }
  if (queue.length > 20000) queue.splice(0, queue.length - 20000);
  setImmediate(drain);
  return { ok: true };
}, { limit: 5_000_000, preAuth: req => realtimeEnabled() && safeEqual(req.headers.authorization || '', config.helius.secret), preAuthStrike: 'webhook_auth' });

export const realtimeStatus = () => ({ enabled: realtimeEnabled(), ...kvGet('helius:webhook', {}), queued: queue.length });
export const _drain = drain;
