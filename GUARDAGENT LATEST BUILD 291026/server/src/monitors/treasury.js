// Treasury Watch (and Guarded Wallets): Squads multisigs on Solana and Safe multisigs on EVM chains.
// New proposals are decoded and checked against the treasury policy, configuration changes are escalated,
// and every signer's own wallet is watched for signs of compromise.
import { config } from '../config.js';
import { all, run, now, json, get } from '../db.js';
import { rpcClient, b58decode, PROGRAMS, LAMPORTS_PER_SOL, parseTokenAccount } from '../lib/solana.js';
import { decodeMultisig, decodeVaultTransaction, SQUADS_IX, vaultPda } from '../lib/squads.js';
import { evaluatePolicy } from '../engines/policy.js';
import { analyzeParsedTx } from './solana.js';
import { raiseOrg } from '../alerts.js';
import { serviceActive } from '../payments.js';
import { short } from './common.js';
import { selector } from '../lib/keccak.js';

const SAFE_NET = { ethereum: 'mainnet', base: 'base', arbitrum: 'arbitrum', optimism: 'optimism', polygon: 'polygon', bnb: 'bsc' };
const safeBase = chain => process.env[`SAFE_API_BASE_${chain.toUpperCase()}`] || (chain === 'ethereum' ? config.safe.base : `https://safe-transaction-${SAFE_NET[chain]}.safe.global`);
const save = (t, st) => run('update treasuries set state = ? where id = ?', JSON.stringify(st), t.id);

export function activeTreasuries() {
  return all('select t.*, o.services from treasuries t join orgs o on o.id = t.org_id').filter(t => serviceActive({ services: t.services }, t.kind === 'guarded' ? 'wallets' : 'treasury') || serviceActive({ services: t.services }, 'treasury'));
}

// Decode the transfers inside a Squads vault transaction so the policy can judge them.
export async function vaultTransfers(rpc, vtx, vault) {
  const outs = [];
  for (const ins of vtx.instructions) {
    const d = Buffer.from(ins.data);
    if (ins.programId === PROGRAMS.SYSTEM && d.length >= 12 && d.readUInt32LE(0) === 2 && ins.accounts[0] === vault)
      outs.push({ to: ins.accounts[1], amount: Number(d.readBigUInt64LE(4)) / LAMPORTS_PER_SOL, token: null, label: 'SOL' });
    if ((ins.programId === PROGRAMS.TOKEN || ins.programId === PROGRAMS.TOKEN_2022) && (d[0] === 3 || d[0] === 12)) {
      const raw = d.readBigUInt64LE(1);
      const src = ins.accounts[0], dst = d[0] === 3 ? ins.accounts[1] : ins.accounts[2];
      const infos = await rpc.getMultipleAccounts([src, dst]).catch(() => [null, null]);
      const sp = infos[0] && parseTokenAccount(infos[0].data[0]);
      const dp = infos[1] && parseTokenAccount(infos[1].data[0]);
      let decimals = d[0] === 12 ? d[9] : null;
      if (decimals == null && sp) { const m = await rpc.getAccountInfo(sp.mint, 'jsonParsed').catch(() => null); decimals = m?.data?.parsed?.info?.decimals ?? 0; }
      outs.push({ to: dp?.owner || dst, amount: Number(raw) / 10 ** (decimals || 0), token: sp?.mint || null, label: sp ? short(sp.mint) : 'token' });
    }
  }
  return outs;
}

async function pollSquads(t, rpc) {
  const st = json(t.state);
  const policy = json(t.policy);
  const info = await rpc.getAccountInfo(t.address);
  if (!info) { st.health = 'multisig account not found'; return save(t, st); }
  const ms = decodeMultisig(info.data[0]);
  const vault = vaultPda(t.address, 0);
  const members = ms.members.map(m => m.key).sort().join(',');
  if (st.members && st.members !== members)
    await raiseOrg(t.org_id, { severity: 'crit', type: 'treasury_members', dedupe: `tm:${t.id}:${members}`, title: `Signers changed on ${t.name}`,
      what: `The signer set of ${t.name} changed. Now: ${ms.members.map(m => short(m.key)).join(', ')} with threshold ${ms.threshold}.`, did: 'Compared the on-chain multisig with the last check.',
      move: 'If this change was not agreed by your team, assume a signer is compromised and move funds to a new multisig.', data: { multisig: t.address } });
  if (st.threshold != null && st.threshold !== ms.threshold)
    await raiseOrg(t.org_id, { severity: 'crit', type: 'treasury_threshold', dedupe: `tt:${t.id}:${ms.threshold}`, title: `Approval threshold changed on ${t.name}`,
      what: `${t.name} now needs ${ms.threshold} approvals (was ${st.threshold}).`, did: 'Caught the configuration change on-chain.', move: 'Confirm with every signer that this was intended.' });
  st.members = members; st.threshold = ms.threshold; st.vault = vault;
  run('update treasuries set signers = ? where id = ?', JSON.stringify(ms.members.map(m => m.key)), t.id);

  const sigs = await rpc.getSignatures(t.address, st.lastSig ? { until: st.lastSig, limit: 50 } : { limit: 1 });
  if (!st.lastSig) { st.lastSig = sigs[0]?.signature || null; st.health = 'ok'; return save(t, st); }
  for (const s of [...sigs].reverse()) {
    if (s.err) continue;
    const tx = await rpc.getTransaction(s.signature).catch(() => null);
    if (!tx) continue;
    for (const ins of tx.transaction.message.instructions) {
      if (ins.programId !== PROGRAMS.SQUADS_V4 || !ins.data) continue;
      const name = SQUADS_IX[Buffer.from(b58decode(ins.data)).subarray(0, 8).toString('hex')];
      const link = `https://solscan.io/tx/${s.signature}`;
      if (name === 'vault_transaction_create') {
        const txAccount = ins.accounts[1];
        const acc = await rpc.getAccountInfo(txAccount).catch(() => null);
        let outs = [];
        try { if (acc) outs = await vaultTransfers(rpc, decodeVaultTransaction(acc.data[0]), vault); } catch {}
        const history = st.history || [];
        const verdicts = outs.map(o => ({ o, v: evaluatePolicy(policy, { chain: 'solana', to: o.to, amount: o.amount, token: o.token, approvals: 0, proposedAt: tx.blockTime }, history) }));
        const denied = verdicts.filter(x => x.v.decision === 'deny');
        st.pending = { ...(st.pending || {}), [txAccount]: { denied: denied.length > 0, outs } };
        await raiseOrg(t.org_id, { severity: denied.length ? 'high' : 'low', type: 'treasury_proposal', dedupe: `tp:${s.signature}`,
          title: denied.length ? `Proposal on ${t.name} breaks your policy` : `New proposal on ${t.name}`,
          what: outs.length ? `It would send ${outs.map(o => `${o.amount} ${o.label} to ${short(o.to)}`).join('; ')}.` : 'It contains instructions other than plain transfers.',
          did: denied.length ? `Checked it against your policy: ${denied.flatMap(x => x.v.reasons.filter(r => r.result === 'deny').map(r => r.text)).join(' ')}` : 'Checked it against your policy. It is within your rules.',
          move: denied.length ? 'Signers should reject this proposal in Squads.' : 'Review it in Squads before approving.', data: { link, proposal: txAccount } });
      }
      if (name === 'vault_transaction_execute') {
        // Only the exact proposal being executed is used. (Guessing "any pending one" could blame or clear the
        // wrong proposal.) Unknown executions are still recorded, just without a policy verdict.
        const txKey = ins.accounts[2];
        const p = st.pending?.[txKey];
        if (st.pending && txKey in st.pending) delete st.pending[txKey];
        if (p?.denied) await raiseOrg(t.org_id, { severity: 'crit', type: 'treasury_exec_denied', dedupe: `ted:${s.signature}`, title: `${t.name} executed a transaction that broke policy`,
          what: 'A proposal that your policy denied has just been executed.', did: 'Linked the execution to the earlier policy check.', move: 'Find out which signers approved it and treat their keys as compromised until proven otherwise.', data: { link } });
        for (const o of p?.outs || []) (st.history ||= []).push({ amount: o.amount, token: o.token, at: tx.blockTime || now() });
        st.history = (st.history || []).filter(h => now() - h.at < 3 * 86400);
      }
      if (name === 'config_transaction_create') await raiseOrg(t.org_id, { severity: 'high', type: 'treasury_config_proposal', dedupe: `tcp:${s.signature}`, title: `Proposal to change ${t.name}'s settings`,
        what: 'Someone proposed changing signers, threshold, time lock or spending limits.', did: 'Flagged the configuration proposal.', move: 'Every signer should confirm out-of-band (call, not chat) before approving.', data: { link } });
      if (name === 'config_transaction_execute') await raiseOrg(t.org_id, { severity: 'crit', type: 'treasury_config_exec', dedupe: `tce:${s.signature}`, title: `${t.name}'s settings were changed`,
        what: 'A configuration change was executed on the multisig.', did: 'Caught the execution on-chain.', move: 'Check the new signer list and threshold in your dashboard now.', data: { link } });
      if (name === 'spending_limit_use') await raiseOrg(t.org_id, { severity: 'med', type: 'treasury_spending_limit', dedupe: `tsl:${s.signature}`, title: `Spending limit used on ${t.name}`,
        what: 'Funds left the vault through a pre-approved spending limit.', did: 'Logged the use.', move: 'Check the amount and destination are what you expect.', data: { link } });
    }
  }
  if (sigs[0]) st.lastSig = sigs[0].signature;
  // Keep the pending map small: anything older than the last 50 proposals is dropped.
  if (st.pending) st.pending = Object.fromEntries(Object.entries(st.pending).slice(-50));
  st.health = 'ok';
  save(t, st);
}

async function safeGet(chain, path) {
  const r = await fetch(safeBase(chain) + path, { headers: config.safe.key ? { authorization: `Bearer ${config.safe.key}` } : {}, signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error('safe api ' + r.status);
  return r.json();
}
const OWNER_METHODS = new Set(['addOwnerWithThreshold', 'removeOwner', 'swapOwner', 'changeThreshold', 'enableModule', 'disableModule', 'setGuard', 'setFallbackHandler', 'setup']);
const ERC20_TRANSFER = selector('transfer(address,uint256)');

// Proposals can be written by anyone allowed to propose on the Safe, so nothing here may throw: one malformed
// proposal used to stop every later check of that treasury for good.
const bigOr0 = v => { try { const b = BigInt(v ?? 0); return b > 0n ? b : 0n; } catch { return 0n; } };
export function safeTxSummary(tx) {
  tx = tx || {};
  const method = tx.dataDecoded?.method;
  if (method && OWNER_METHODS.has(method)) return { configChange: method, outs: [] };
  const outs = [];
  const v = bigOr0(tx.value);
  if (v > 0n) outs.push({ to: tx.to, amount: Number(v) / 1e18, token: null, label: 'native coin' });
  const d = String(tx.data || '').toLowerCase();
  if (d.startsWith(ERC20_TRANSFER)) {
    if (/^0xa9059cbb[0-9a-f]{128}/.test(d)) outs.push({ to: '0x' + d.slice(34, 74), amount: Number(BigInt('0x' + d.slice(74, 138))), token: String(tx.to).toLowerCase(), label: `token ${short(tx.to)} (raw units)` });
    else outs.push({ to: tx.to, amount: 0, token: null, label: 'a malformed token transfer', malformed: true });
  }
  if (method === 'multiSend') outs.push({ to: tx.to, amount: 0, token: null, label: 'a batch of calls', batch: true });
  return { configChange: null, outs };
}

async function pollSafe(t) {
  const st = json(t.state);
  const policy = json(t.policy);
  const safe = await safeGet(t.chain, `/api/v1/safes/${t.address}/`);
  const owners = (safe.owners || []).map(o => o.toLowerCase()).sort().join(',');
  if (st.owners && st.owners !== owners) await raiseOrg(t.org_id, { severity: 'crit', type: 'treasury_members', dedupe: `so:${t.id}:${owners}`, title: `Owners changed on ${t.name}`,
    what: `The owners of ${t.name} are now ${safe.owners.map(short).join(', ')} with threshold ${safe.threshold}.`, did: 'Compared the Safe with the last check.', move: 'If this was not agreed, treat a signer as compromised and move funds.' });
  st.owners = owners; st.threshold = safe.threshold;
  run('update treasuries set signers = ? where id = ?', JSON.stringify(safe.owners || []), t.id);
  const list = await safeGet(t.chain, `/api/v2/safes/${t.address}/multisig-transactions/?ordering=-nonce&limit=20`).catch(() => safeGet(t.chain, `/api/v1/safes/${t.address}/multisig-transactions/?ordering=-nonce&limit=20`));
  const seen = st.seen || {};
  for (const tx of (Array.isArray(list?.results) ? list.results : []).reverse()) {
    if (!tx || typeof tx.safeTxHash !== 'string') continue;
    const key = tx.safeTxHash;
    const prev = seen[key];
    const sum = safeTxSummary(tx);
    const link = `https://app.safe.global/transactions/tx?safe=${t.chain === 'ethereum' ? 'eth' : t.chain}:${t.address}&id=multisig_${t.address}_${key}`;
    if (!prev && st.baseline) {
      if (sum.configChange) await raiseOrg(t.org_id, { severity: 'high', type: 'treasury_config_proposal', dedupe: `sc:${key}`, title: `Proposal to change ${t.name}: ${sum.configChange}`,
        what: `Nonce ${tx.nonce} proposes ${sum.configChange} on the Safe.`, did: 'Flagged the configuration proposal.', move: 'Every signer should confirm by phone before signing.', data: { link } });
      else {
        const verdicts = sum.outs.filter(o => !o.batch).map(o => evaluatePolicy(policy, { chain: t.chain, to: o.to, amount: o.amount, token: o.token, approvals: (tx.confirmations || []).length }, st.history || []));
        const denied = verdicts.filter(v => v.decision === 'deny');
        await raiseOrg(t.org_id, { severity: denied.length ? 'high' : 'low', type: 'treasury_proposal', dedupe: `sp:${key}`, title: denied.length ? `Proposal on ${t.name} breaks your policy` : `New proposal on ${t.name}`,
          what: sum.outs.length ? `Nonce ${tx.nonce} would send ${sum.outs.map(o => `${o.amount} ${o.label} to ${short(o.to)}`).join('; ')}.` : `Nonce ${tx.nonce} calls ${short(tx.to)}${tx.dataDecoded?.method ? ` (${tx.dataDecoded.method})` : ''}.`,
          did: denied.length ? `Checked it against your policy: ${denied.flatMap(v => v.reasons.filter(r => r.result === 'deny').map(r => r.text)).join(' ')}` : 'Checked it against your policy.',
          move: denied.length ? 'Signers should not sign this. Reject it in the Safe app.' : 'Review it in the Safe app before signing.', data: { link } });
        seen[key] = { denied: denied.length > 0 };
      }
    }
    if (tx.isExecuted && !(prev && prev.executed) && st.baseline) {
      if (seen[key]?.denied || prev?.denied) await raiseOrg(t.org_id, { severity: 'crit', type: 'treasury_exec_denied', dedupe: `sx:${key}`, title: `${t.name} executed a transaction that broke policy`,
        what: `Nonce ${tx.nonce} was executed even though it broke your policy.`, did: 'Linked the execution to the earlier policy check.', move: 'Find out which owners signed and rotate their keys.', data: { link } });
      for (const o of sum.outs) (st.history ||= []).push({ amount: o.amount, token: o.token, at: Math.floor(new Date(tx.executionDate || Date.now()).getTime() / 1000) });
    }
    seen[key] = { ...(seen[key] || prev || {}), executed: !!tx.isExecuted };
  }
  st.seen = Object.fromEntries(Object.entries(seen).slice(-200));
  st.history = (st.history || []).filter(h => now() - h.at < 3 * 86400);
  st.baseline = true; st.health = 'ok';
  save(t, st);
}

// Signer compromise: watch each Solana signer's own wallet for drainer patterns.
async function signerChecks(t, rpc) {
  if (t.chain !== 'solana') return;
  const st = json(t.state);
  const signers = json(t.signers, []);
  st.signerSigs ||= {};
  for (const s of signers.slice(0, 20)) {
    try {
      const sigs = await rpc.getSignatures(s, st.signerSigs[s] ? { until: st.signerSigs[s], limit: 20 } : { limit: 1 });
      if (st.signerSigs[s]) for (const x of [...sigs].reverse()) {
        if (x.err) continue;
        const tx = await rpc.getTransaction(x.signature).catch(() => null);
        if (!tx) continue;
        const f = analyzeParsedTx(tx, s);
        const bad = f.assigned || f.authority.length || f.blocked.length || f.approvals.some(a => a.amount > 2n ** 62n) || (f.preLamports > 50_000_000 && f.postLamports < f.preLamports * 0.1);
        if (bad) await raiseOrg(t.org_id, { severity: 'crit', type: 'signer_compromise', dedupe: `sig:${t.id}:${x.signature}`, title: `Signer ${short(s)} may be compromised`,
          what: `A signer of ${t.name} just showed drainer activity on their own wallet (${f.assigned ? 'account handed to a program' : f.authority.length ? 'token ownership change' : f.blocked.length ? 'contact with a known drainer' : f.approvals.length ? 'unlimited token permission' : 'wallet emptied'}).`,
          did: 'Watches every signer wallet, not just the treasury.', move: 'Do not approve anything that signer proposes. Remove them from the multisig with the other signers as soon as possible.', data: { link: `https://solscan.io/tx/${x.signature}` } });
      }
      if (sigs[0]) st.signerSigs[s] = sigs[0].signature;
    } catch {}
  }
  save(t, { ...json(get('select state from treasuries where id = ?', t.id)?.state), signerSigs: st.signerSigs });
}

// One run at a time: the scheduler and real-time webhooks both call this, and two overlapping runs would read the
// same state and double-count spending in the policy history.
let running = null, again = false;
export async function pollTreasuries() {
  if (running) { again = true; return running; }
  running = (async () => { do { again = false; await pollTreasuriesOnce(); } while (again); })().finally(() => { running = null; });
  return running;
}
async function pollTreasuriesOnce() {
  const rpc = config.solana.rpc ? rpcClient(config.solana.rpc) : null;
  for (const t of activeTreasuries()) {
    try {
      if (t.chain === 'solana' && rpc) { await pollSquads(t, rpc); await signerChecks(t, rpc); }
      else if (t.chain !== 'solana') await pollSafe(t);
    } catch (e) { const st = json(t.state); st.health = 'error: ' + e.message.slice(0, 80); save(t, st); }
  }
}
