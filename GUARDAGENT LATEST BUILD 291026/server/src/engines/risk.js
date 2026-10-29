// Risk Screening: wallet risk score 0-100 with evidence. Direct sanctions hits, one-hop exposure to sanctioned,
// mixer and flagged addresses, wallet age and pass-through behaviour, across Solana, EVM chains and Bitcoin.
import { config } from '../config.js';
import { get, run, now, json } from '../db.js';
import { rpcClient } from '../lib/solana.js';
import { isSanctioned, isMixer, isBlocked } from './lists.js';
import { EVM_CHAINS } from '../plans.js';

async function evmCounterparties(chain, address) {
  if (!config.etherscanKey) return { list: [], firstSeen: null, note: 'Add ETHERSCAN_API_KEY for EVM history.' };
  const chainId = config.evm[chain].chainId;
  const q = action => `https://api.etherscan.io/v2/api?chainid=${chainId}&module=account&action=${action}&address=${address}&page=1&offset=200&sort=desc&apikey=${config.etherscanKey}`;
  const [txs, toks] = await Promise.all([q('txlist'), q('tokentx')].map(u => fetch(u, { signal: AbortSignal.timeout(20000) }).then(r => r.json()).catch(() => ({}))));
  const rows = [...(Array.isArray(txs.result) ? txs.result : []), ...(Array.isArray(toks.result) ? toks.result : [])];
  const me = address.toLowerCase();
  const list = rows.map(t => ({ addr: (t.from?.toLowerCase() === me ? t.to : t.from)?.toLowerCase(), dir: t.from?.toLowerCase() === me ? 'out' : 'in', time: Number(t.timeStamp), value: Number(t.value || 0) })).filter(x => x.addr);
  const times = rows.map(t => Number(t.timeStamp)).filter(Boolean);
  return { list, firstSeen: times.length ? Math.min(...times) : null, total: rows.length };
}

async function solCounterparties(address) {
  const rpc = rpcClient(config.solana.rpc);
  const sigs = await rpc.getSignatures(address, { limit: 100 });
  const list = [];
  for (const s of sigs.slice(0, 40)) {
    const t = await rpc.getTransaction(s.signature).catch(() => null);
    if (!t) continue;
    for (const ins of t.transaction.message.instructions) {
      const i = ins.parsed?.info;
      if (!i) continue;
      const src = i.source || i.authority, dst = i.destination;
      if (src === address && dst) list.push({ addr: dst, dir: 'out', time: t.blockTime });
      if (dst === address && src) list.push({ addr: src, dir: 'in', time: t.blockTime });
    }
  }
  const times = sigs.map(s => s.blockTime).filter(Boolean);
  return { list, firstSeen: sigs.length < 100 && times.length ? Math.min(...times) : null, total: sigs.length };
}

async function btcCounterparties(address) {
  const r = await fetch(`${config.btcApi}/address/${address}/txs`, { signal: AbortSignal.timeout(20000) });
  const txs = r.ok ? await r.json() : [];
  const list = [];
  for (const t of txs) {
    const fromMe = t.vin.some(v => v.prevout?.scriptpubkey_address === address);
    if (fromMe) t.vout.forEach(o => o.scriptpubkey_address && o.scriptpubkey_address !== address && list.push({ addr: o.scriptpubkey_address, dir: 'out', time: t.status?.block_time }));
    else t.vin.forEach(v => v.prevout?.scriptpubkey_address && list.push({ addr: v.prevout.scriptpubkey_address, dir: 'in', time: t.status?.block_time }));
  }
  const times = txs.map(t => t.status?.block_time).filter(Boolean);
  return { list, firstSeen: txs.length < 25 && times.length ? Math.min(...times) : null, total: txs.length };
}

export function scoreFrom({ chain, address, cp }) {
  const factors = [];
  let score = 0;
  const addF = (points, code, text, evidence) => { score += points; factors.push({ points, code, text, evidence }); };
  if (isSanctioned(chain, address)) return { score: 100, level: 'severe', sanctioned: true, factors: [{ points: 100, code: 'sanctioned', text: 'This address is on the OFAC sanctions list.' }] };
  if (isBlocked(chain, address)) addF(60, 'flagged', 'This address is on the Bodyguard threat list (scams, drainers or exploits).');
  const uniq = new Map();
  for (const c of cp.list) if (!uniq.has(c.addr)) uniq.set(c.addr, c);
  const sanctionedHits = [...uniq.keys()].filter(a => isSanctioned(chain, a));
  const mixerHits = [...uniq.keys()].filter(a => isMixer(chain, a));
  const flaggedHits = [...uniq.keys()].filter(a => isBlocked(chain, a));
  if (mixerHits.length) addF(50, 'mixer', `Interacted directly with a mixer (${mixerHits.length} contract${mixerHits.length > 1 ? 's' : ''}).`, mixerHits.slice(0, 5));
  if (sanctionedHits.length) addF(40, 'sanctioned_exposure', `Sent to or received from ${sanctionedHits.length} sanctioned address${sanctionedHits.length > 1 ? 'es' : ''}.`, sanctionedHits.slice(0, 5));
  if (flaggedHits.length) addF(30, 'flagged_exposure', `Transacted with ${flaggedHits.length} address${flaggedHits.length > 1 ? 'es' : ''} flagged for scams or exploits.`, flaggedHits.slice(0, 5));
  if (cp.firstSeen && now() - cp.firstSeen < 7 * 86400) addF(10, 'new_wallet', 'Wallet is less than a week old.');
  const ins = cp.list.filter(c => c.dir === 'in').length, outs = cp.list.filter(c => c.dir === 'out').length;
  if (ins >= 10 && outs >= 10 && uniq.size >= 30) {
    const span = Math.max(1, Math.max(...cp.list.map(c => c.time || 0)) - Math.min(...cp.list.map(c => c.time || now())));
    if (span < 3 * 86400) addF(10, 'pass_through', 'Funds move in and straight out to many addresses in a short time, a pattern used to launder.');
  }
  if (!cp.total) addF(0, 'no_history', 'No transaction history found, so exposure could not be measured.');
  score = Math.min(99, score);
  return { score, level: score >= 75 ? 'severe' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low', sanctioned: false, factors, counterpartiesChecked: uniq.size };
}

export async function screen(chain, address, { useCache = true } = {}) {
  chain = String(chain).toLowerCase();
  if (!['solana', 'bitcoin', ...EVM_CHAINS].includes(chain)) throw new Error('unsupported chain');
  const key = EVM_CHAINS.includes(chain) ? address.toLowerCase() : address;
  const c = useCache && get('select * from screen_cache where chain = ? and address = ?', chain, key);
  if (c && now() - c.created_at < 3600) return { ...json(c.result), cached: true };
  const cp = chain === 'solana' ? await solCounterparties(key) : chain === 'bitcoin' ? await btcCounterparties(key) : await evmCounterparties(chain, key);
  const result = { chain, address: key, ...scoreFrom({ chain, address: key, cp }), checkedAt: now(), note: cp.note };
  run('insert into screen_cache(chain, address, result, created_at) values(?,?,?,?) on conflict(chain, address) do update set result = excluded.result, created_at = excluded.created_at', chain, key, JSON.stringify(result), now());
  return result;
}
