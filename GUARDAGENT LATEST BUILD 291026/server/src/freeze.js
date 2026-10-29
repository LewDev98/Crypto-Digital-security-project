// Freeze Desk: when someone is scammed, minutes decide whether stolen funds can still be frozen.
// The victim fills in one form. The agent then:
//   1. pulls every transaction they listed straight from the chain, so the facts in the report are verified;
//   2. locks the evidence: one canonical JSON manifest (incl. SHA-256 of every screenshot), hashed and signed by
//      the server with a timestamp. Anyone can check the receipt at /api/evidence/verify/<hash>, and the victim can
//      also anchor the hash on Solana from their own wallet for a public timestamp;
//   3. writes a pre-formatted freeze request for every exchange, issuer and responder they pick, emails the ones
//      with a confirmed contact address and hands over the rest ready to paste into the official form;
//   4. keeps tracing the scammer's addresses and alerts the victim when the money moves, flagging any hop that lands
//      on a known exchange address.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';
import { run, get, all, now, json, kvGet, sha256hex } from './db.js';
import { rpcClient, isValidPubkey } from './lib/solana.js';
import { b58encode } from './lib/base58.js';
import { evmCall } from './engines/firewall-evm.js';
import { EVM_CHAINS } from './plans.js';

/* ---------------- directory ---------------- */
const DIR_FILE = path.join(config.root, 'data', 'exchanges.json');
let baseDir = null;
export function directory() {
  if (!baseDir) { try { baseDir = JSON.parse(fs.readFileSync(DIR_FILE, 'utf8')).targets || []; } catch { baseDir = []; } }
  const over = kvGet('freeze:directory', {});
  const list = baseDir.map(t => ({ ...t, ...(over[t.id] || {}) }));
  for (const [id, t] of Object.entries(over)) if (!list.some(x => x.id === id) && t?.name) list.push({ id, kind: 'exchange', addresses: {}, ...t });
  return list;
}
export const targetById = id => directory().find(t => t.id === id);
export function targetForAddress(chain, address) {
  const a = chain === 'solana' || chain === 'bitcoin' ? address : String(address).toLowerCase();
  const fam = EVM_CHAINS.includes(chain) ? 'evm' : chain;
  return directory().find(t => (t.addresses?.[chain] || t.addresses?.[fam] || []).some(x => (chain === 'solana' || chain === 'bitcoin' ? x : String(x).toLowerCase()) === a));
}

/* ---------------- evidence signing key (derived from APP_SECRET) ---------------- */
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
let keyCache = null;
function evidenceKey() {
  if (keyCache) return keyCache;
  const seed = crypto.createHash('sha256').update('bodyguard-evidence-key:' + config.appSecret).digest();
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32);
  return (keyCache = { privateKey, publicKey: b58encode(pub) });
}
export const evidencePublicKey = () => evidenceKey().publicKey;
export const receiptMessage = (hash, lockedAt) => `bodyguard-evidence/1:${hash}:${lockedAt}`;
export const signReceipt = (hash, lockedAt) => b58encode(crypto.sign(null, Buffer.from(receiptMessage(hash, lockedAt)), evidenceKey().privateKey));

/* ---------------- validation ---------------- */
export const CHAINS = ['solana', 'bitcoin', ...EVM_CHAINS];
export function validTxHash(chain, h) {
  h = String(h || '').trim();
  if (chain === 'solana') return /^[1-9A-HJ-NP-Za-km-z]{64,90}$/.test(h) ? h : null;
  if (chain === 'bitcoin') return /^[0-9a-fA-F]{64}$/.test(h) ? h.toLowerCase() : null;
  return /^0x[0-9a-fA-F]{64}$/.test(h) ? h.toLowerCase() : null;
}
export function explorerTx(chain, h) {
  if (chain === 'solana') return `https://solscan.io/tx/${h}`;
  if (chain === 'bitcoin') return `https://mempool.space/tx/${h}`;
  return `${config.evm[chain]?.explorer || 'https://etherscan.io'}/tx/${h}`;
}
export function explorerAddr(chain, a) {
  if (chain === 'solana') return `https://solscan.io/account/${a}`;
  if (chain === 'bitcoin') return `https://mempool.space/address/${a}`;
  return `${config.evm[chain]?.explorer || 'https://etherscan.io'}/address/${a}`;
}

/* ---------------- on-chain facts ---------------- */
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const iso = t => (t ? new Date(t * 1000).toISOString() : null);

function solTransfers(t) {
  const keys = t.transaction.message.accountKeys.map(k => (typeof k === 'string' ? k : k.pubkey));
  const owners = {};
  for (const b of [...(t.meta?.preTokenBalances || []), ...(t.meta?.postTokenBalances || [])]) owners[keys[b.accountIndex]] = { owner: b.owner, mint: b.mint, decimals: b.uiTokenAmount?.decimals };
  const ins = [...t.transaction.message.instructions, ...(t.meta?.innerInstructions || []).flatMap(x => x.instructions)];
  const out = [];
  for (const i of ins) {
    const p = i.parsed, info = p?.info;
    if (!info) continue;
    if (i.program === 'system' && p.type === 'transfer') out.push({ from: info.source, to: info.destination, amount: Number(info.lamports) / 1e9, asset: 'SOL' });
    if ((i.program === 'spl-token' || i.program === 'spl-token-2022') && (p.type === 'transfer' || p.type === 'transferChecked')) {
      const src = owners[info.source], dst = owners[info.destination];
      const dec = info.tokenAmount?.decimals ?? src?.decimals ?? dst?.decimals ?? 0;
      const raw = info.tokenAmount?.amount ?? info.amount;
      out.push({ from: info.authority || src?.owner || info.source, to: dst?.owner || info.destination, amount: Number(raw) / 10 ** dec, asset: info.mint || src?.mint || dst?.mint || 'token' });
    }
  }
  return out.slice(0, 40);
}

export async function fetchTx(chain, hash) {
  const base = { chain, hash, explorer: explorerTx(chain, hash) };
  try {
    if (chain === 'solana') {
      if (!config.solana.rpc) return { ...base, verified: false, note: 'Solana RPC not configured' };
      const t = await rpcClient(config.solana.rpc).getTransaction(hash);
      if (!t) return { ...base, verified: false, note: 'Not found on-chain' };
      const keys = t.transaction.message.accountKeys.map(k => (typeof k === 'string' ? k : k.pubkey));
      return { ...base, verified: true, time: iso(t.blockTime), slot: t.slot, signer: keys[0], failed: !!t.meta?.err, transfers: solTransfers(t) };
    }
    if (chain === 'bitcoin') {
      const r = await fetch(`${config.btcApi}/tx/${hash}`, { signal: AbortSignal.timeout(15000) });
      if (!r.ok) return { ...base, verified: false, note: 'Not found on-chain' };
      const t = await r.json();
      const from = [...new Set(t.vin.map(v => v.prevout?.scriptpubkey_address).filter(Boolean))];
      return { ...base, verified: true, time: iso(t.status?.block_time), confirmed: !!t.status?.confirmed, transfers: t.vout.filter(o => o.scriptpubkey_address).slice(0, 40).map(o => ({ from: from.join(', '), to: o.scriptpubkey_address, amount: o.value / 1e8, asset: 'BTC' })) };
    }
    if (!config.evm[chain]?.rpc) return { ...base, verified: false, note: `${chain} RPC not configured` };
    const [t, rc] = await Promise.all([evmCall(chain, 'eth_getTransactionByHash', [hash]), evmCall(chain, 'eth_getTransactionReceipt', [hash])]);
    if (!t) return { ...base, verified: false, note: 'Not found on-chain' };
    const blk = t.blockNumber ? await evmCall(chain, 'eth_getBlockByNumber', [t.blockNumber, false]).catch(() => null) : null;
    const transfers = [];
    if (BigInt(t.value || '0x0') > 0n) transfers.push({ from: t.from, to: t.to, amount: Number(BigInt(t.value)) / 1e18, asset: 'native' });
    for (const l of rc?.logs || []) {
      if (l.topics?.[0] !== TRANSFER_TOPIC || l.topics.length !== 3) continue;
      transfers.push({ from: '0x' + l.topics[1].slice(26), to: '0x' + l.topics[2].slice(26), amountRaw: BigInt(l.data && l.data !== '0x' ? l.data : '0x0').toString(), asset: l.address.toLowerCase() });
    }
    return { ...base, verified: true, time: iso(blk ? Number(BigInt(blk.timestamp)) : null), block: t.blockNumber ? Number(BigInt(t.blockNumber)) : null, from: t.from, to: t.to, failed: rc ? rc.status === '0x0' : null, transfers: transfers.slice(0, 40) };
  } catch (e) { return { ...base, verified: false, note: 'Lookup failed: ' + String(e.message).slice(0, 80) }; }
}

/* ---------------- manifest ---------------- */
export function buildManifest(m) {
  const text = JSON.stringify(m, null, 2);
  return { text, hash: sha256hex(text) };
}

/* ---------------- freeze request text ---------------- */
export const SCAM_TYPES = { phishing: 'phishing / wallet drainer', investment: 'investment or "pig butchering" scam', impersonation: 'impersonation (fake support, fake official)', romance: 'romance scam', hack: 'account or wallet hack', poisoning: 'address-poisoning scam', coercion: 'theft under physical threat', other: 'crypto theft' };
const fmtAmt = x => (x.amountRaw ? `${x.amountRaw} (raw units) of ${x.asset}` : `${x.amount} ${x.asset}`);

export function requestText(inc, target) {
  const d = inc.data, m = d.manifest;
  const lines = [];
  lines.push(`To the ${target.name} security and compliance team,`, '');
  lines.push(`I am the victim of a ${SCAM_TYPES[m.incident.scamType] || 'crypto theft'} on ${m.incident.occurredAt || 'the date below'}. Funds were taken from my wallet and I believe they were sent to, or will pass through, ${target.kind === 'exchange' ? 'an account on your platform' : target.kind === 'issuer' ? 'addresses holding your token' : 'addresses you may be able to act on'}.`);
  lines.push(target.kind === 'police' || target.kind === 'responder'
    ? 'I am reporting this so it can be investigated and the funds traced while they can still be frozen.'
    : 'Please urgently review and freeze the funds connected to the addresses below, and preserve all records, while the police investigate.', '');
  lines.push(`Case reference: ${inc.ref}`);
  lines.push(`Evidence fingerprint (SHA-256): ${inc.manifest_hash}`);
  lines.push(`Evidence locked: ${m.lockedAt} (signed receipt: ${config.publicUrl}/api/evidence/verify/${inc.manifest_hash})`);
  if (inc.anchor_sig) lines.push(`Public timestamp on Solana: https://solscan.io/tx/${inc.anchor_sig}`);
  lines.push(`Police report reference: ${m.incident.policeRef || 'being filed'}`, '');
  lines.push('WHAT HAPPENED', m.incident.description || '(no description)', '');
  lines.push(`Amount lost: ${m.incident.amount || 'unknown'} ${m.incident.asset || ''}`.trim());
  lines.push('Victim wallet(s):', ...m.victimWallets.map(w => `  - ${w.chain}: ${w.address}`));
  lines.push('Scammer / receiving address(es):', ...m.scammerAddresses.map(w => `  - ${w.chain}: ${w.address}  ${explorerAddr(w.chain, w.address)}`));
  if (m.transactions.length) {
    lines.push('Transactions (read directly from the blockchain by Bodyguard):');
    for (const t of m.transactions) {
      lines.push(`  - ${t.chain} ${t.hash}${t.time ? ' at ' + t.time : ''}${t.verified ? '' : ' (could not be verified: ' + (t.note || 'unknown') + ')'}`, `    ${t.explorer}`);
      for (const x of (t.transfers || []).slice(0, 6)) lines.push(`      ${x.from} -> ${x.to}: ${fmtAmt(x)}`);
    }
  }
  const hops = (d.trace?.hops || []).filter(h => h.target === target.id);
  if (hops.length) lines.push('', 'Funds traced to addresses we believe belong to you:', ...hops.map(h => `  - ${h.chain}: ${h.to} (tx ${h.tx})`));
  lines.push('', 'CONTACT', `${m.reporter.name}`, `${m.reporter.email}${m.reporter.phone ? ' · ' + m.reporter.phone : ''}${m.reporter.country ? ' · ' + m.reporter.country : ''}`, '');
  lines.push(`Attachments: ${m.files.length} file(s); their SHA-256 hashes are in the evidence manifest.`);
  lines.push('I confirm the information above is true to the best of my knowledge.', '');
  lines.push(`Submitted through Bodyguard Freeze Desk (${config.publicUrl}). Bodyguard verified the on-chain transactions listed above; the description is the victim's own account. Reply to this email to reach the victim directly.`);
  const subject = `Urgent freeze request: stolen funds, case ${inc.ref}${m.incident.amount ? ` (${m.incident.amount} ${m.incident.asset || ''})`.replace(/\s+\)/, ')') : ''}`;
  return { subject: subject.replace(/[\r\n]+/g, ' ').slice(0, 200), body: lines.join('\n') };
}

/* ---------------- trace: watch the scammer's addresses ---------------- */
async function outgoing(chain, address, since) {
  const out = [];
  if (chain === 'solana' && config.solana.rpc) {
    const rpc = rpcClient(config.solana.rpc);
    const sigs = (await rpc.getSignatures(address, { limit: 15 })).filter(s => !s.err && (s.blockTime || 0) > since);
    for (const s of sigs.slice(0, 8)) {
      const t = await rpc.getTransaction(s.signature).catch(() => null);
      if (!t) continue;
      for (const x of solTransfers(t)) if (x.from === address && x.to !== address) out.push({ tx: s.signature, time: t.blockTime, to: x.to, amount: x.amount, asset: x.asset });
    }
  } else if (chain === 'bitcoin') {
    const r = await fetch(`${config.btcApi}/address/${address}/txs`, { signal: AbortSignal.timeout(15000) });
    for (const t of (r.ok ? await r.json() : []).slice(0, 10)) {
      if ((t.status?.block_time || now()) <= since) continue;
      if (!t.vin.some(v => v.prevout?.scriptpubkey_address === address)) continue;
      for (const o of t.vout) if (o.scriptpubkey_address && o.scriptpubkey_address !== address) out.push({ tx: t.txid, time: t.status?.block_time || now(), to: o.scriptpubkey_address, amount: o.value / 1e8, asset: 'BTC' });
    }
  } else if (EVM_CHAINS.includes(chain) && config.etherscanKey) {
    const q = action => `https://api.etherscan.io/v2/api?chainid=${config.evm[chain].chainId}&module=account&action=${action}&address=${address}&page=1&offset=25&sort=desc&apikey=${config.etherscanKey}`;
    const [a, b] = await Promise.all([q('txlist'), q('tokentx')].map(u => fetch(u, { signal: AbortSignal.timeout(15000) }).then(r => r.json()).catch(() => ({}))));
    for (const t of [...(Array.isArray(a.result) ? a.result : []), ...(Array.isArray(b.result) ? b.result : [])]) {
      if (Number(t.timeStamp) <= since || String(t.from).toLowerCase() !== address || !t.to) continue;
      out.push({ tx: t.hash, time: Number(t.timeStamp), to: String(t.to).toLowerCase(), amount: t.tokenDecimal ? Number(t.value) / 10 ** Number(t.tokenDecimal) : Number(t.value) / 1e18, asset: t.tokenSymbol || 'native' });
    }
  }
  return out;
}

export async function traceIncidents({ raise } = {}) {
  const t0 = now();
  for (const inc of all("select * from incidents where status = 'open' and created_at > ?", t0 - 30 * 86400)) {
    const tr = json(inc.trace, { watch: [], hops: [], last: {} });
    tr.watch ||= []; tr.hops ||= []; tr.last ||= {};
    const victims = new Set(json(inc.data).manifest?.victimWallets?.map(w => w.address.toLowerCase()) || []);
    for (const w of tr.watch.slice(0, 8)) {
      const key = w.chain + ':' + w.address;
      const since = tr.last[key] || inc.created_at - 3 * 86400;
      let moves = [];
      try { moves = await outgoing(w.chain, w.address, since); } catch { continue; }
      for (const mv of moves) {
        if (tr.hops.some(h => h.tx === mv.tx && h.to === mv.to) || victims.has(String(mv.to).toLowerCase())) continue;
        const hit = targetForAddress(w.chain, mv.to);
        const hop = { chain: w.chain, from: w.address, to: mv.to, tx: mv.tx, time: mv.time, amount: mv.amount, asset: mv.asset, depth: (w.depth || 0) + 1, target: hit?.id || null };
        tr.hops.push(hop);
        tr.last[key] = Math.max(tr.last[key] || 0, mv.time || 0);
        run('insert into incident_events(incident_id, kind, text, data, created_at) values(?,?,?,?,?)', inc.id, hit ? 'exchange_hit' : 'moved',
          hit ? `Funds reached an address linked to ${hit.name}: ${mv.amount} ${mv.asset} to ${mv.to}.` : `Funds moved on: ${mv.amount} ${mv.asset} from ${w.address} to ${mv.to}.`, JSON.stringify(hop), now());
        if (!hit && hop.depth < 2 && tr.watch.length < 8 && !tr.watch.some(x => x.chain === w.chain && x.address === mv.to)) tr.watch.push({ chain: w.chain, address: mv.to, depth: hop.depth });
        if (raise) raise(inc, hop, hit).catch(() => {});
      }
      if (!tr.last[key]) tr.last[key] = since;
    }
    run('update incidents set trace = ?, updated_at = ? where id = ?', JSON.stringify(tr), now(), inc.id);
  }
}

export const isAddr = (chain, a) => chain === 'solana' ? isValidPubkey(a) : chain === 'bitcoin' ? /^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(a) : /^0x[0-9a-fA-F]{40}$/.test(a);
