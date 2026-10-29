// Address-poisoning shield. Scammers create addresses that share the first and last characters with one you use,
// send dust so it lands in your history, and wait for you to copy it. This compares any address against
// everything the agent knows you use.
import { all, get, run, now } from '../db.js';
import { EVM_CHAINS } from '../plans.js';

const fam = chain => (EVM_CHAINS.includes(chain) || chain === 'evm' ? 'evm' : chain);
const norm = (chain, a) => (fam(chain) === 'evm' ? String(a).toLowerCase().replace(/^0x/, '') : String(a));

export function affix(a, b) {
  let p = 0; while (p < a.length && p < b.length && a[p] === b[p]) p++;
  let s = 0; while (s < a.length - p && s < b.length - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s++;
  return { prefix: p, suffix: s };
}

// A lookalike shares the visible ends that people check, but not the full address.
export function isLookalike(candidate, known, chain = 'solana') {
  const a = norm(chain, candidate), b = norm(chain, known);
  if (!a || !b || a === b) return null;
  const { prefix, suffix } = affix(a, b);
  const hit = (prefix >= 3 && suffix >= 3) || (prefix >= 4 && suffix >= 2) || (prefix >= 2 && suffix >= 4);
  return hit ? { prefix, suffix } : null;
}

function knownFor(agentId, chain) {
  const f = fam(chain);
  const chains = f === 'evm' ? EVM_CHAINS : [chain];
  return all(`select chain, address, label, source, count from counterparties where agent_id = ? and chain in (${chains.map(() => '?').join(',')})`, agentId, ...chains);
}

export function checkAddress(agentId, chain, address) {
  const f = fam(chain);
  const n = norm(chain, address);
  const chains = f === 'evm' ? EVM_CHAINS : [chain];
  const tag = get(`select * from poison_tags where agent_id = ? and address = ? and chain in (${chains.map(() => '?').join(',')})`, agentId, f === 'evm' ? '0x' + n : address, ...chains);
  const known = knownFor(agentId, chain);
  const exact = known.find(k => norm(chain, k.address) === n);
  if (tag && !exact) {
    const real = known.find(k => norm(chain, k.address) === norm(chain, tag.imitates));
    return { verdict: 'poisoned', address, imitates: tag.imitates, label: real?.label || tag.label || 'an address you use', ...affix(n, norm(chain, tag.imitates)) };
  }
  if (exact) return { verdict: 'known', address, label: exact.label || (exact.source === 'self' ? 'Your wallet' : 'An address you have used'), source: exact.source };
  let best = null;
  for (const k of known) {
    const m = isLookalike(address, k.address, chain);
    if (m && (!best || m.prefix + m.suffix > best.prefix + best.suffix)) best = { ...m, k };
  }
  if (best) return { verdict: 'lookalike', address, imitates: best.k.address, label: best.k.label || 'an address you have used', prefix: best.prefix, suffix: best.suffix };
  return { verdict: 'new', address };
}

export function learn(agentId, chain, address, { source = 'history', label = null } = {}) {
  if (!address) return;
  const a = fam(chain) === 'evm' ? String(address).toLowerCase() : address;
  run(`insert into counterparties(agent_id, chain, address, label, source, count, first_seen, last_seen) values(?,?,?,?,?,1,?,?)
       on conflict(agent_id, chain, address) do update set count = count + 1, last_seen = excluded.last_seen`, agentId, chain, a, label, source, now(), now());
}

export function tagPoison(agentId, chain, address, imitates, label) {
  run('insert or ignore into poison_tags(agent_id, chain, address, imitates, label, created_at) values(?,?,?,?,?,?)', agentId, chain, address, imitates, label || null, now());
}

// Called by monitors when something small arrives: is the sender a lookalike of anything this agent uses?
export function inspectIncoming(agentId, chain, sender) {
  const known = knownFor(agentId, chain);
  if (known.some(k => norm(chain, k.address) === norm(chain, sender))) return null;
  for (const k of known) {
    const m = isLookalike(sender, k.address, chain);
    if (m) { tagPoison(agentId, chain, fam(chain) === 'evm' ? sender.toLowerCase() : sender, k.address, k.label); return { imitates: k.address, label: k.label, ...m }; }
  }
  return null;
}

export const short = a => (a && a.length > 12 ? `${a.slice(0, a.startsWith('0x') ? 6 : 4)}…${a.slice(-4)}` : a);
