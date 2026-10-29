// EVM patrol for Ethereum, Base, Arbitrum, Optimism, Polygon and BNB Chain: approvals, NFT operator grants,
// Permit2 allowances, transfers out (including by approved spenders), zero-value poisoning and balance drains.
import { config } from '../config.js';
import { kvGet, kvSet } from '../db.js';
import { topic } from '../lib/keccak.js';
import { EVM_CHAINS } from '../plans.js';
import { activeAssets, stateOf, saveState, short, label } from './common.js';
import { checkAddress, learn, inspectIncoming, tagPoison } from '../engines/poison.js';
import { isBlocked, isSanctioned, KNOWN_SPENDERS } from '../engines/lists.js';
import { raiseAgent } from '../alerts.js';

export const T = {
  transfer: topic('Transfer(address,address,uint256)'),
  approval: topic('Approval(address,address,uint256)'),
  approvalForAll: topic('ApprovalForAll(address,address,bool)'),
  p2approval: topic('Approval(address,address,address,uint160,uint48)'),
  p2permit: topic('Permit(address,address,address,uint160,uint48,uint48)')
};
const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3';
const pad = a => '0x' + a.toLowerCase().replace(/^0x/, '').padStart(64, '0');
const unpad = t => '0x' + t.slice(26).toLowerCase();
const big = h => (h && h !== '0x' ? BigInt(h.length > 66 ? h.slice(0, 66) : h) : 0n);

async function call(chain, method, params) {
  const r = await fetch(config.evm[chain].rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(25000) });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}
const isContract = async (chain, a) => { try { return (await call(chain, 'eth_getCode', [a, 'latest'])) !== '0x'; } catch { return null; } };

export async function pollEvm() {
  for (const chain of EVM_CHAINS) {
    if (!config.evm[chain].rpc) continue;
    const assets = activeAssets('wallet', chain);
    if (!assets.length) continue;
    try { await pollChain(chain, assets); } catch (e) { console.warn(`[evm:${chain}]`, e.message); }
  }
}

async function pollChain(chain, assets) {
  const latest = Number(await call(chain, 'eth_blockNumber', []));
  // A node that answers with junk must never become our saved position, or this chain would stall for good.
  if (!Number.isSafeInteger(latest) || latest <= 0) throw new Error('bad block number from RPC');
  const key = `evm:last:${chain}`;
  let from = kvGet(key, null);
  if (!Number.isSafeInteger(from) || from > latest + 100) from = latest - 3;
  from += 1;
  if (from > latest) return;
  const to = Math.min(latest, from + config.evmMaxBlockRange - 1);
  const byAddr = new Map();
  for (const a of assets) { const k = a.value.toLowerCase(); if (!byAddr.has(k)) byAddr.set(k, []); byAddr.get(k).push(a); }
  const addrs = [...byAddr.keys()];
  const range = { fromBlock: '0x' + from.toString(16), toBlock: '0x' + to.toString(16) };
  const logs = [];
  for (let i = 0; i < addrs.length; i += 40) {
    const topicsAddr = addrs.slice(i, i + 40).map(pad);
    const q = async topics => { const r = await call(chain, 'eth_getLogs', [{ ...range, topics }]); if (!Array.isArray(r)) throw new Error('bad logs from RPC'); logs.push(...r.filter(l => l && Array.isArray(l.topics) && typeof l.address === 'string' && typeof l.transactionHash === 'string')); };
    await q([[T.approval, T.approvalForAll], topicsAddr]);
    await q([T.transfer, topicsAddr]);
    await q([T.transfer, null, topicsAddr]);
    const p2 = await call(chain, 'eth_getLogs', [{ ...range, address: PERMIT2, topics: [[T.p2approval, T.p2permit], topicsAddr] }]).catch(() => []);
    if (Array.isArray(p2)) logs.push(...p2.filter(l => l && Array.isArray(l.topics) && typeof l.address === 'string' && typeof l.transactionHash === 'string'));
  }
  const txFrom = new Map();
  const senderOf = async h => { if (!txFrom.has(h)) txFrom.set(h, (await call(chain, 'eth_getTransactionByHash', [h]).catch(() => null))?.from?.toLowerCase() || null); return txFrom.get(h); };
  const explorer = config.evm[chain].explorer;

  for (const log of logs) {
    const t0 = log.topics[0];
    const link = `${explorer}/tx/${log.transactionHash}`;
    const base = (asset) => ({ data: { tx: log.transactionHash, link, chain, token: log.address } });
    if (t0 === T.approval || t0 === T.approvalForAll || (log.address.toLowerCase() === PERMIT2 && (t0 === T.p2approval || t0 === T.p2permit))) {
      const owner = unpad(log.topics[1]);
      const permit2 = log.address.toLowerCase() === PERMIT2;
      const spender = permit2 ? unpad(log.topics[3]) : unpad(log.topics[2]);
      const isNft = t0 === T.approvalForAll || (t0 === T.approval && log.topics.length === 4);
      const value = t0 === T.approvalForAll ? big(log.data) : t0 === T.approval && log.topics.length === 4 ? 1n : permit2 ? big('0x' + log.data.slice(2, 66)) : big(log.data);
      if (value === 0n) continue;
      const unlimited = value >= 2n ** 128n;
      for (const asset of byAddr.get(owner) || []) {
        if (KNOWN_SPENDERS.has(spender) && !isNft) continue;
        const flagged = isBlocked(chain, spender) || isSanctioned(chain, spender);
        const contract = flagged ? true : await isContract(chain, spender);
        const sev = flagged || contract === false ? 'crit' : (isNft || unlimited) ? 'high' : 'med';
        await raiseAgent(asset.agent_id, { ...base(asset), severity: sev, type: 'evm_approval', dedupe: `evmappr:${log.transactionHash}:${log.logIndex}:${asset.agent_id}`,
          title: isNft ? 'NFT collection permission granted' : unlimited ? 'Unlimited token approval' : 'Token approval granted',
          what: `${label(asset)} on ${config.evm[chain].name} gave ${short(spender)}${KNOWN_SPENDERS.get(spender) ? ` (${KNOWN_SPENDERS.get(spender)})` : ''} permission to move ${isNft ? 'every NFT in a collection' : unlimited ? 'an unlimited amount of a token' : 'a token'} (${short(log.address)}).`,
          did: flagged ? 'The spender is on the threat list.' : contract === false ? 'The spender is a personal wallet, not an app. Drainers do this.' : 'Checked the spender against the threat lists.',
          move: 'If you did not mean this, revoke it now with revoke.cash or your wallet\'s approvals screen.' });
      }
      continue;
    }
    if (t0 !== T.transfer || log.topics.length < 3) continue;
    const fromA = unpad(log.topics[1]), toA = unpad(log.topics[2]);
    const amount = log.topics.length === 4 ? 1n : big(log.data);
    // Outgoing
    for (const asset of byAddr.get(fromA) || []) {
      const sender = await senderOf(log.transactionHash);
      const c = checkAddress(asset.agent_id, chain, toA);
      if (sender && sender !== fromA) {
        if (amount === 0n || c.verdict === 'lookalike') {
          tagPoison(asset.agent_id, chain, toA, c.imitates || null, c.label);
          await raiseAgent(asset.agent_id, { ...base(asset), severity: 'med', type: 'evm_poison_planted', dedupe: `evmpz:${asset.agent_id}:${toA}`, title: 'Fake transfer planted in your history',
            what: `Someone else created a ${amount === 0n ? 'zero-value' : 'fake'} transfer that makes it look like ${label(asset)} sent to ${short(toA)}${c.imitates ? `, a lookalike of ${short(c.imitates)}` : ''}.`,
            did: 'Tagged the address as poisoned. The shield will block sends to it.', move: 'Never copy addresses from transaction history. Use your saved addresses.' });
        } else {
          await raiseAgent(asset.agent_id, { ...base(asset), severity: 'crit', type: 'evm_spender_drain', dedupe: `evmdd:${log.transactionHash}:${log.logIndex}`, title: 'Tokens taken by an approved spender',
            what: `${short(sender)} moved tokens (${short(log.address)}) out of ${label(asset)} to ${short(toA)} using an earlier approval. You did not send this transaction.`,
            did: 'Spotted that the transaction was not sent by your wallet.', move: 'Revoke every approval on this wallet now (revoke.cash) and move remaining assets to a fresh wallet.' });
        }
        continue;
      }
      if (c.verdict === 'lookalike' || c.verdict === 'poisoned')
        await raiseAgent(asset.agent_id, { ...base(asset), severity: 'crit', type: 'evm_poison_send', dedupe: `evmps:${log.transactionHash}:${log.logIndex}`, title: 'Funds sent to a poisoned address',
          what: `${label(asset)} sent tokens to ${short(toA)}, a lookalike of your ${c.label} (${short(c.imitates)}).`, did: 'Recognised the lookalike from your history.',
          move: 'This cannot be reversed. Save the real address in your dashboard and never copy from history.' });
      else {
        if (c.verdict === 'new' && amount > 0n)
          await raiseAgent(asset.agent_id, { ...base(asset), severity: 'med', type: 'evm_new_dest', dedupe: `evmnew:${log.transactionHash}:${log.logIndex}`, title: 'Tokens sent to a new address',
            what: `${label(asset)} sent tokens (${short(log.address)}) to ${short(toA)}, an address you haven't used before.`, did: 'Checked it against your history and the threat lists.',
            move: 'If this was you, ignore this. If not, revoke approvals and move funds now.' });
        learn(asset.agent_id, chain, toA);
      }
    }
    // Incoming dust / poisoning
    for (const asset of byAddr.get(toA) || []) {
      if (fromA === '0x0000000000000000000000000000000000000000') continue;
      const hit = inspectIncoming(asset.agent_id, chain, fromA);
      if (hit) await raiseAgent(asset.agent_id, { ...base(asset), severity: 'med', type: 'evm_poison_dust', dedupe: `evmdust:${asset.agent_id}:${fromA}`, title: 'Address-poisoning attempt',
        what: `${label(asset)} received a transfer from ${short(fromA)}, which imitates your ${hit.label || 'address'} (${short(hit.imitates)}).`,
        did: 'Tagged the lookalike. The shield will block any send to it.', move: 'Never copy addresses from your history.' });
    }
  }

  // Native coin drains (not visible in logs). Checked every EVM_BALANCE_SECONDS rather than every poll, which cuts
  // RPC calls by about 90%; token moves and approvals above are still caught on every poll.
  const balKey = `evm:bal:${chain}`;
  const doBalances = Date.now() / 1000 - kvGet(balKey, 0) >= config.evmBalanceSeconds;
  if (doBalances) kvSet(balKey, Math.floor(Date.now() / 1000));
  for (const [addr, list] of doBalances ? byAddr : []) {
    try {
      const [bal, nonce] = await Promise.all([call(chain, 'eth_getBalance', [addr, 'latest']), call(chain, 'eth_getTransactionCount', [addr, 'latest'])]);
      for (const asset of list) {
        const st = stateOf(asset);
        const b = BigInt(bal), n = Number(nonce);
        if (st.balance != null && st.nonce != null && n > st.nonce) {
          const prev = BigInt(st.balance);
          if (prev > 10n ** 16n && b * 10n < prev)
            await raiseAgent(asset.agent_id, { severity: 'high', type: 'evm_drain', dedupe: `evmdrain:${asset.id}:${n}`, title: `Most of your ${config.evm[chain].name} balance left`,
              what: `${label(asset)} went from ${(Number(prev) / 1e18).toFixed(4)} to ${(Number(b) / 1e18).toFixed(4)} in native coin.`, did: 'Flagged the size of the move.',
              move: 'If this was not you, assume the wallet is compromised and move what is left.', data: { chain, wallet: addr } });
        }
        st.balance = b.toString(); st.nonce = n; st.health = 'ok';
        saveState(asset, st);
      }
    } catch {}
  }
  kvSet(key, to);
}
