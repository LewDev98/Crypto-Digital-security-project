// Threat-intelligence lists: phishing domains (MetaMask + Phantom), OFAC-sanctioned addresses, mixer contracts,
// known-good spenders and your own blocklist. Refreshed daily into SQLite; admins can add entries.
import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config.js';
import { run, get, now, json } from '../db.js';

const mem = { phishing: new Set(), allowDomains: new Set(), sanctioned: { evm: new Set(), bitcoin: new Set(), solana: new Set() }, blocked: { solana: new Set(), evm: new Set() }, blockedPrograms: new Set(), loadedAt: 0 };

// Mixer contracts flagged for exposure checks (Tornado Cash on Ethereum). Extend with lists you trust.
export const MIXERS = {
  evm: new Set([
    '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b', // Tornado Cash router
    '0x722122df12d4e14e13ac3b6895a86e84145b6967', // Tornado Cash proxy
    '0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc', // 0.1 ETH pool
    '0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936', // 1 ETH pool
    '0x910cbd523d972eb0a6f4cae4618ad62622b39dbf', // 10 ETH pool
    '0xa160cdab225685da1d56aa342ad8841c3b53f291'  // 100 ETH pool
  ])
};

// Spenders and operators that are normal to approve. Approvals to these are not flagged as risky on their own.
export const KNOWN_SPENDERS = new Map([
  ['0x000000000022d473030f116ddee9f6b43ac78ba3', 'Permit2 (Uniswap)'],
  ['0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad', 'Uniswap Universal Router'],
  ['0x66a9893cc07d91d95644aedd05d03f95e1dba8af', 'Uniswap Universal Router v4'],
  ['0x111111125421ca6dc452d289314280a0f8842a65', '1inch Router v6'],
  ['0xdef1c0ded9bec7f1a1670819833240f027b25eff', '0x Exchange Proxy'],
  ['0x1e0049783f008a0085193e00003d00cd54003c71', 'OpenSea Seaport conduit'],
  ['0x00000000000000adc04c56bf30ac9d3c0aaf14dc', 'Seaport 1.5'],
  ['0x0000000000000068f116a894984e2db1123eb395', 'Seaport 1.6']
]);

function localFile() {
  const f = path.join(config.root, 'data', 'blocklist.json');
  return fs.existsSync(f) ? json(fs.readFileSync(f, 'utf8'), {}) : {};
}

function hydrate() {
  const g = name => json(get('select data from lists where name = ?', name)?.data, []);
  mem.phishing = new Set([...g('phishing'), ...g('custom_domains'), ...(localFile().domains || [])].map(d => String(d).toLowerCase()));
  mem.allowDomains = new Set(g('allowDomains'));
  mem.sanctioned = { evm: new Set(g('ofac_eth').map(a => a.toLowerCase())), bitcoin: new Set(g('ofac_xbt')), solana: new Set(g('ofac_sol')) };
  const local = localFile();
  mem.blocked = { solana: new Set([...(local.solana?.addresses || []), ...g('custom_solana')]), evm: new Set([...(local.evm?.addresses || []), ...g('custom_evm')].map(a => a.toLowerCase())) };
  mem.blockedPrograms = new Set([...(local.solana?.programs || []), ...g('custom_programs')]);
  mem.loadedAt = now();
}

async function fetchText(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(30000), headers: { 'user-agent': 'bodyguard-agents' } });
  if (!r.ok) throw new Error(url + ' ' + r.status);
  return r.text();
}
// Each downloaded list is checked before it replaces the stored one: entries must look right, and a list that
// suddenly shrinks by more than half (an outage page, a truncated or tampered file) is rejected, so a bad
// download can never silently switch off sanctions or phishing protection.
const VALID = {
  evm: a => /^0x[0-9a-fA-F]{40}$/.test(a), btc: a => /^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(a),
  sol: a => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a), domain: d => /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(d)
};
function saveChecked(name, values, check, { minKeep = 0.5 } = {}) {
  const clean = [...new Set(values.map(v => String(v).trim()).filter(check))];
  const prev = json(get('select data from lists where name = ?', name)?.data, []);
  if (prev.length >= 20 && clean.length < prev.length * minKeep) throw new Error(`${name}: new list has ${clean.length} entries vs ${prev.length} before; keeping the old one`);
  save(name, clean);
}
const save = (name, data) => run('insert into lists(name, data, updated_at) values(?,?,?) on conflict(name) do update set data = excluded.data, updated_at = excluded.updated_at', name, JSON.stringify(data), now());

export async function refreshLists() {
  const jobs = [
    async () => {
      const mm = JSON.parse(await fetchText(config.lists.metamaskPhishing));
      saveChecked('phishing_mm', mm.blacklist || [], VALID.domain);
      saveChecked('allowDomains', mm.whitelist || [], VALID.domain);
    },
    async () => {
      const y = await fetchText(config.lists.phantomBlocklist);
      saveChecked('phishing_ph', [...y.matchAll(/url:\s*["']?([a-z0-9.-]+\.[a-z]{2,})/gi)].map(m => m[1].toLowerCase()), VALID.domain);
    },
    async () => { saveChecked('ofac_eth', (await fetchText(`${config.lists.ofacBase}/sanctioned_addresses_ETH.txt`)).split(/\s+/), VALID.evm, { minKeep: 0.8 }); },
    async () => { saveChecked('ofac_xbt', (await fetchText(`${config.lists.ofacBase}/sanctioned_addresses_XBT.txt`)).split(/\s+/), VALID.btc, { minKeep: 0.8 }); },
    async () => { const t = await fetchText(`${config.lists.ofacBase}/sanctioned_addresses_SOL.txt`).catch(() => null); if (t != null) saveChecked('ofac_sol', t.split(/\s+/), VALID.sol, { minKeep: 0.8 }); }
  ];
  const results = await Promise.allSettled(jobs.map(j => j()));
  const ph = [...json(get("select data from lists where name='phishing_mm'")?.data, []), ...json(get("select data from lists where name='phishing_ph'")?.data, [])];
  if (ph.length) save('phishing', [...new Set(ph)]); // admin-added domains live in custom_domains, so this never erases them
  hydrate();
  const failed = results.filter(r => r.status === 'rejected').length;
  console.log(`[lists] refreshed: ${mem.phishing.size} phishing domains, ${mem.sanctioned.evm.size + mem.sanctioned.bitcoin.size + mem.sanctioned.solana.size} sanctioned addresses${failed ? `, ${failed} sources failed` : ''}`);
}

export function addCustom(kind, values) {
  const name = { solana: 'custom_solana', evm: 'custom_evm', program: 'custom_programs', domain: 'custom_domains' }[kind];
  if (!name) throw new Error('unknown list');
  const check = { solana: VALID.sol, program: VALID.sol, evm: VALID.evm, domain: VALID.domain }[kind];
  const cur = new Set(json(get('select data from lists where name = ?', name)?.data, []));
  values.map(v => String(v).trim()).filter(check).forEach(v => cur.add(kind === 'evm' || kind === 'domain' ? v.toLowerCase() : v));
  save(name, [...cur]); hydrate();
  return cur.size;
}

const ensure = () => { if (!mem.loadedAt) hydrate(); };
export function isPhishingDomain(hostOrUrl) {
  ensure();
  if (!hostOrUrl) return false;
  let host = String(hostOrUrl).toLowerCase();
  try { if (host.includes('://')) host = new URL(host).hostname; } catch {}
  host = host.replace(/^www\./, '');
  if (mem.allowDomains.has(host)) return false;
  const parts = host.split('.');
  for (let i = 0; i < parts.length - 1; i++) if (mem.phishing.has(parts.slice(i).join('.'))) return true;
  return false;
}
export function isSanctioned(chain, address) {
  ensure();
  const fam = chain === 'bitcoin' ? 'bitcoin' : chain === 'solana' ? 'solana' : 'evm';
  if (!address) return false;
  return mem.sanctioned[fam].has(fam === 'evm' ? String(address).toLowerCase() : String(address));
}
export function isBlocked(chain, address) {
  ensure();
  if (chain === 'solana') return mem.blocked.solana.has(address) || mem.blockedPrograms.has(address);
  return mem.blocked.evm.has(String(address).toLowerCase());
}
export const isMixer = (chain, address) => chain !== 'solana' && chain !== 'bitcoin' && MIXERS.evm.has(String(address).toLowerCase());
export const listStats = () => { ensure(); return { phishing: mem.phishing.size, sanctioned: mem.sanctioned.evm.size + mem.sanctioned.bitcoin.size + mem.sanctioned.solana.size, blocked: mem.blocked.solana.size + mem.blocked.evm.size, loadedAt: mem.loadedAt }; };
export const _testHydrate = hydrate;
