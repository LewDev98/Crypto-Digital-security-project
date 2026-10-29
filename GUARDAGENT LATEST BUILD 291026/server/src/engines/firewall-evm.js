// EVM firewall for Ethereum, Base, Arbitrum, Optimism, Polygon and BNB Chain wallets.
// Decodes approvals, NFT operator grants, Permit / Permit2 signatures, Seaport listings, blind signing and
// transfers to lookalike addresses.
import { config } from '../config.js';
import { selector } from '../lib/keccak.js';
import { checkAddress, short } from './poison.js';
import { isPhishingDomain, isBlocked, isSanctioned, KNOWN_SPENDERS } from './lists.js';
import { verdict } from './firewall-sol.js';

const SEL = {
  approve: selector('approve(address,uint256)'),
  increaseAllowance: selector('increaseAllowance(address,uint256)'),
  setApprovalForAll: selector('setApprovalForAll(address,bool)'),
  transfer: selector('transfer(address,uint256)'),
  transferFrom: selector('transferFrom(address,address,uint256)'),
  safeTransferFrom: selector('safeTransferFrom(address,address,uint256)'),
  permit2Approve: selector('approve(address,address,uint160,uint48)'),
  safeTransferFromData: selector('safeTransferFrom(address,address,uint256,bytes)'),
  erc1155Transfer: selector('safeTransferFrom(address,address,uint256,uint256,bytes)'),
  erc1155Batch: selector('safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)')
};
const BIG = 2n ** 128n;
const word = (data, i) => data.slice(10 + i * 64, 10 + (i + 1) * 64);
const addrAt = (data, i) => '0x' + word(data, i).slice(24);
const uintAt = (data, i) => BigInt('0x' + (word(data, i) || '0'));
const CHAIN_BY_ID = Object.fromEntries(Object.entries(config.evm).map(([k, v]) => [v.chainId, k]));

export async function evmCall(chain, method, params) {
  const rpc = config.evm[chain]?.rpc;
  if (!rpc) return null;
  const r = await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(15000) });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}
async function isContract(chain, addr) {
  try { const code = await evmCall(chain, 'eth_getCode', [addr, 'latest']); return code == null ? null : code !== '0x'; } catch { return null; }
}

export async function analyzeEvm(agent, { chainId, method, params = [], origin, from }) {
  const reasons = [], summary = [];
  const flows = { nativeOut: 0 };
  const add = (severity, text, code) => reasons.push({ severity, text, code });
  const chain = CHAIN_BY_ID[Number(chainId)] || 'ethereum';
  if (origin && isPhishingDomain(origin)) add('crit', `${safeHost(origin)} is on known phishing lists. Close the site.`, 'phishing_site');

  const spenderRisk = async (spender, what, unlimited) => {
    const s = spender.toLowerCase();
    if (KNOWN_SPENDERS.has(s)) { summary.push(`${what} for ${KNOWN_SPENDERS.get(s)}`); if (unlimited) add('low', `Unlimited ${what.toLowerCase()} for ${KNOWN_SPENDERS.get(s)}, a well-known app.`, 'known_spender'); return; }
    if (isBlocked(chain, s) || isSanctioned(chain, s)) return add('crit', `${what} goes to ${short(s)}, an address flagged as a scammer.`, 'blocked_spender');
    const contract = await isContract(chain, s);
    if (contract === false) return add('crit', `${what} goes to ${short(s)}, a personal wallet rather than an app. Drainers use this to take your tokens later.`, 'eoa_spender');
    add(unlimited ? 'high' : 'med', `${what} for ${short(s)}, a contract Bodyguard doesn't recognise${unlimited ? ', with no limit on the amount' : ''}.`, 'unknown_spender');
  };

  if (method === 'eth_sign') flows.contractCall = true;
  if (method === 'eth_sign') add('crit', 'This site wants a blind signature that can authorise anything, including moving all your funds. Real apps almost never need this.', 'eth_sign');

  if (method === 'personal_sign') {
    const msg = String(params[0] || '');
    if (/^0x[0-9a-fA-F]{64}$/.test(msg)) add('high', 'You are being asked to sign a raw hash you cannot read. That can hide a transaction.', 'blind_hash');
  }

  if (method === 'eth_sendTransaction') {
    const t = params[0] || {};
    const to = String(t.to || '').toLowerCase();
    const data = String(t.data || t.input || '0x').toLowerCase();
    const value = BigInt(t.value || '0x0');
    if (value < 0n) throw new Error('negative value');
    flows.nativeOut = Number(value) / 1e18;
    flows.contractCall = data.length > 2;
    if (value > 0n && to) { summary.push(`Sends ${fmtEth(value)} to ${short(to)}`); destCheck(agent, chain, to, add, fmtEth(value)); }
    const sel = data.slice(0, 10);
    if (sel === SEL.approve || sel === SEL.increaseAllowance) {
      const spender = addrAt(data, 0), amount = uintAt(data, 1);
      if (amount > 0n) await spenderRisk(spender, 'Token spending approval', amount >= BIG);
    } else if (sel === SEL.setApprovalForAll) {
      const op = addrAt(data, 0), on = uintAt(data, 1) === 1n;
      if (on) await spenderRisk(op, 'Permission over every NFT in this collection', true);
    } else if (sel === SEL.transfer) {
      const dst = addrAt(data, 0);
      summary.push(`Transfers tokens to ${short(dst)}`);
      destCheck(agent, chain, dst, add, 'tokens');
    } else if (sel === SEL.transferFrom || sel === SEL.safeTransferFrom || sel === SEL.safeTransferFromData || sel === SEL.erc1155Transfer || sel === SEL.erc1155Batch) {
      const src = addrAt(data, 0), dst = addrAt(data, 1);
      if (from && src.toLowerCase() === from.toLowerCase()) { summary.push(`Transfers an asset to ${short(dst)}`); destCheck(agent, chain, dst, add, 'an asset'); }
    } else if (sel === SEL.permit2Approve) {
      const spender = addrAt(data, 1), amount = uintAt(data, 2);
      await spenderRisk(spender, 'Permit2 allowance', amount >= 2n ** 150n);
    }
    if (to && (isBlocked(chain, to) || isSanctioned(chain, to))) add('crit', `Interacts with ${short(to)}, an address flagged as malicious or sanctioned.`, 'blocked_to');
  }

  if (method === 'eth_signTypedData_v4' || method === 'eth_signTypedData_v3' || method === 'eth_signTypedData') {
    // The typed data is normally the second parameter; some apps send it first. Use whichever one is the object.
    let td = typeof params[0] === 'object' && params[0] !== null && !Array.isArray(params[0]) ? params[0] : params[1];
    if (typeof td === 'string') { try { td = JSON.parse(td); } catch { td = null; } }
    // Typed signatures can authorise token moves off-chain (permits, orders), so a time-lock treats them all as moves.
    flows.contractCall = true;
    const signer = from || [params[0], params[1]].find(x => typeof x === 'string' && /^0x[0-9a-fA-F]{40}$/.test(x));
    if (td && typeof td === 'object') await typedData(td, signer, spenderRisk, add, summary);
  }
  return { ...verdict(reasons, summary), flows };
}

// Amounts in typed data come from the site, so anything that isn't a whole number counts as "no limit".
const big = v => { try { const b = BigInt(v ?? 0); return b < 0n ? BIG : b; } catch { return BIG; } };

async function typedData(td, signer, spenderRisk, add, summary) {
  const p = td.primaryType, m = td.message && typeof td.message === 'object' ? td.message : {};
  if (m.spender !== undefined && (typeof m.spender !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(m.spender))) { add('high', 'This signature names a spender Bodyguard cannot read. Only continue if you trust this site.', 'decode_error'); return; }
  if (p === 'Permit' && m.spender) {
    summary.push('Gasless token approval (Permit)');
    // DAI-style permits say `allowed: true` instead of an amount, and that means unlimited.
    await spenderRisk(m.spender, 'Gasless token approval', m.allowed === true || big(m.value) >= BIG);
  }
  if (p === 'PermitSingle' && m.spender) await spenderRisk(m.spender, 'Permit2 allowance', big(m.details?.amount) >= 2n ** 150n);
  if (p === 'PermitBatch' && m.spender) { add('high', `Approves ${m.details?.length || 'several'} tokens at once.`, 'permit_batch'); await spenderRisk(m.spender, 'Permit2 batch allowance', true); }
  if ((p === 'PermitTransferFrom' || p === 'PermitBatchTransferFrom' || p === 'PermitWitnessTransferFrom') && m.spender) {
    summary.push('Signature that lets a contract move your tokens');
    await spenderRisk(m.spender, 'Signature transfer permission', true);
  }
  if (p === 'OrderComponents' && Array.isArray(m.offer)) {
    const me = String(signer || m.offerer || '').toLowerCase();
    const toMe = (Array.isArray(m.consideration) ? m.consideration : []).filter(c => String(c?.recipient).toLowerCase() === me).reduce((s, c) => { try { const v = BigInt(c?.startAmount ?? 0); return v > 0n ? s + v : s; } catch { return s; } }, 0n);
    const others = (Array.isArray(m.consideration) ? m.consideration : []).filter(c => String(c?.recipient).toLowerCase() !== me);
    summary.push(`Lists ${m.offer.length} item(s) for sale`);
    if (m.offer.length && toMe === 0n && others.length) add('crit', 'This listing sends your items away and pays you nothing. It is a fake "sign to verify" drainer.', 'free_listing');
  }
}

function destCheck(agent, chain, dest, add, what) {
  if (isSanctioned(chain, dest)) add('crit', `Sends ${what} to a sanctioned address.`, 'sanctioned');
  const c = checkAddress(agent.id, chain, dest);
  if (c.verdict === 'lookalike' || c.verdict === 'poisoned')
    add('crit', `Sends ${what} to ${short(dest)}, a lookalike of your ${c.label} (${short(c.imitates)}). This is address poisoning.`, 'poison');
  else if (c.verdict === 'new') add('low', `${short(dest)} is a first-time address for you. Double-check it.`, 'new_dest');
}
const fmtEth = v => `${(Number(v) / 1e18).toLocaleString('en-GB', { maximumFractionDigits: 6 })} native coin`;
const safeHost = o => { try { return new URL(String(o)).hostname.slice(0, 120); } catch { return 'This site'; } };
