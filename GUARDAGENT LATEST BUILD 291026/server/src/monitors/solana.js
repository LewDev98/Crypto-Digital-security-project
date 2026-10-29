// Solana wallet patrol: new transactions on every watched address, decoded and judged.
import { config } from '../config.js';
import { rpcClient, LAMPORTS_PER_SOL, PROGRAMS } from '../lib/solana.js';
import { activeAssets, stateOf, saveState, short, label } from './common.js';
import { checkAddress, learn, inspectIncoming } from '../engines/poison.js';
import { isBlocked, isSanctioned } from '../engines/lists.js';
import { raiseAgent } from '../alerts.js';
import { scanWallet } from '../engines/spam.js';
import { now, get, run } from '../db.js';

const sol = l => (Number(l) / LAMPORTS_PER_SOL).toLocaleString('en-GB', { maximumFractionDigits: 4 });
const U64_HALF = 2n ** 63n;

// Pure analysis of a jsonParsed transaction from the point of view of one address. Exported for tests and Treasury Watch.
export function analyzeParsedTx(txr, me) {
  const keys = txr.transaction.message.accountKeys.map(k => (typeof k === 'string' ? { pubkey: k, signer: false } : k));
  const myIndex = keys.findIndex(k => k.pubkey === me);
  const signer = !!keys[myIndex]?.signer;
  const pre = txr.meta.preBalances[myIndex] ?? 0, post = txr.meta.postBalances[myIndex] ?? 0;
  const tokenOwner = new Map();
  for (const b of [...(txr.meta.preTokenBalances || []), ...(txr.meta.postTokenBalances || [])]) tokenOwner.set(keys[b.accountIndex]?.pubkey, { owner: b.owner, mint: b.mint, decimals: b.uiTokenAmount?.decimals });
  const myTokenDelta = new Map();
  for (const b of txr.meta.postTokenBalances || []) if (b.owner === me) myTokenDelta.set(b.mint, (myTokenDelta.get(b.mint) || 0n) + BigInt(b.uiTokenAmount.amount));
  for (const b of txr.meta.preTokenBalances || []) if (b.owner === me) myTokenDelta.set(b.mint, (myTokenDelta.get(b.mint) || 0n) - BigInt(b.uiTokenAmount.amount));

  const inner = (txr.meta.innerInstructions || []).flatMap(i => i.instructions);
  const ixs = [...txr.transaction.message.instructions, ...inner];
  const out = { signer, preLamports: pre, postLamports: post, solDelta: post - pre, outs: [], ins: [], approvals: [], authority: [], assigned: false, blocked: [], programs: new Set() };
  for (const ins of ixs) {
    const pid = ins.programId; out.programs.add(pid);
    if (isBlocked('solana', pid)) out.blocked.push(pid);
    const p = ins.parsed; if (!p || typeof p !== 'object') continue;
    const i = p.info || {};
    if (ins.program === 'system') {
      if (p.type === 'transfer' && i.source === me) out.outs.push({ to: i.destination, lamports: BigInt(i.lamports), asset: 'SOL' });
      if (p.type === 'transfer' && i.destination === me) out.ins.push({ from: i.source, lamports: BigInt(i.lamports), asset: 'SOL' });
      if ((p.type === 'assign' || p.type === 'assignWithSeed') && i.account === me) out.assigned = true;
    }
    if (ins.program === 'spl-token' || pid === PROGRAMS.TOKEN || pid === PROGRAMS.TOKEN_2022) {
      if (p.type === 'transfer' || p.type === 'transferChecked') {
        const srcOwner = tokenOwner.get(i.source)?.owner, dstOwner = tokenOwner.get(i.destination)?.owner;
        const amount = BigInt(i.tokenAmount?.amount ?? i.amount ?? 0);
        const mint = i.mint || tokenOwner.get(i.source)?.mint;
        const decimals = i.tokenAmount?.decimals ?? tokenOwner.get(i.source)?.decimals ?? 0;
        if (srcOwner === me) out.outs.push({ to: dstOwner || i.destination, amount, decimals, mint, asset: 'token', by: i.authority || i.multisigAuthority, delegated: (i.authority && i.authority !== me) });
        if (dstOwner === me && srcOwner !== me) out.ins.push({ from: srcOwner || i.authority || i.source, amount, mint, asset: 'token' });
      }
      if ((p.type === 'approve' || p.type === 'approveChecked') && (i.owner === me || tokenOwner.get(i.source)?.owner === me))
        out.approvals.push({ delegate: i.delegate, amount: BigInt(i.tokenAmount?.amount ?? i.amount ?? 0), mint: i.mint || tokenOwner.get(i.source)?.mint });
      if (p.type === 'setAuthority' && (i.authority === me || i.multisigAuthority === me) && i.authorityType !== 'mintTokens')
        out.authority.push({ account: i.account, type: i.authorityType, newAuthority: i.newAuthority });
    }
  }
  const tokenOut = [...myTokenDelta.values()].some(v => v < 0n), tokenIn = [...myTokenDelta.values()].some(v => v > 0n);
  out.isSwap = (tokenOut && tokenIn) || (tokenIn && out.solDelta < -5000) || (tokenOut && out.solDelta > 0);
  out.programs = [...out.programs];
  return out;
}

export async function handleFindings(agentId, asset, sig, f, raise = raiseAgent) {
  const who = label(asset);
  const link = `https://solscan.io/tx/${sig}`;
  const base = { data: { signature: sig, link, wallet: asset.value } };
  if (f.assigned) await raise(agentId, { ...base, severity: 'crit', type: 'sol_assign', dedupe: `assign:${sig}`, title: 'Wallet control handed to a program',
    what: `A transaction handed control of ${who} to another program. Funds in it can now be moved without you.`, did: 'Flagged it the moment it confirmed.',
    move: 'Move anything left to a fresh wallet from a clean device right away, and stop using this wallet.' });
  for (const a of f.authority) await raise(agentId, { ...base, severity: 'crit', type: 'sol_authority', dedupe: `auth:${sig}:${a.account}`, title: 'Token account ownership changed',
    what: `Ownership of one of your token accounts in ${who} was given to ${short(a.newAuthority)}.`, did: 'Flagged it as soon as it confirmed.',
    move: 'Assume that token account is lost. Move your other assets to a fresh wallet and revoke connections to the site you used.' });
  for (const p of f.blocked) await raise(agentId, { ...base, severity: 'crit', type: 'sol_drainer', dedupe: `blk:${sig}:${p}`, title: 'Known drainer touched your wallet',
    what: `${who} interacted with ${short(p)}, a program on the drainer list.`, did: 'Matched it against the threat list.',
    move: 'Check your balances, revoke any token delegations, and move funds to a fresh wallet if anything is missing.' });
  for (const a of f.approvals) {
    if (a.amount === 0n) continue;
    const unlimited = a.amount >= U64_HALF;
    const flagged = isBlocked('solana', a.delegate);
    await raise(agentId, { ...base, severity: flagged || unlimited ? 'crit' : 'high', type: 'sol_approve', dedupe: `appr:${sig}:${a.delegate}`, title: unlimited ? 'Unlimited token permission granted' : 'Token permission granted',
      what: `${who} gave ${short(a.delegate)} permission to move ${unlimited ? 'all of' : 'some of'} your ${short(a.mint)} tokens.`, did: flagged ? 'The delegate is on the drainer list.' : 'Flagged it so you can check you meant to.',
      move: 'If you did not mean to, revoke it now with a revoke tool such as Solscan or Phantom\'s token permissions screen.' });
  }
  if (f.signer && !f.isSwap) {
    for (const o of f.outs) {
      if (!o.to || o.to === asset.value) continue;
      const c = checkAddress(agentId, 'solana', o.to);
      const amt = o.asset === 'SOL' ? `${sol(o.lamports)} SOL` : `${(Number(o.amount) / 10 ** (o.decimals || 0)).toLocaleString('en-GB', { maximumFractionDigits: 4 })} of token ${short(o.mint)}`;
      if (c.verdict === 'lookalike' || c.verdict === 'poisoned')
        await raise(agentId, { ...base, severity: 'crit', type: 'sol_poison_send', dedupe: `psend:${sig}:${o.to}`, title: 'Funds sent to a poisoned address',
          what: `${amt} went from ${who} to ${short(o.to)}, a lookalike of your ${c.label} (${short(c.imitates)}).`, did: 'Recognised the lookalike from your history.',
          move: 'This transfer cannot be reversed. Save the real address in your dashboard and never copy addresses from transaction history.' });
      else if (isSanctioned('solana', o.to))
        await raise(agentId, { ...base, severity: 'crit', type: 'sol_sanctioned', dedupe: `sanc:${sig}`, title: 'Payment to a sanctioned address', what: `${amt} went to ${short(o.to)}, which is on the OFAC sanctions list.`, did: 'Matched it against the sanctions list.', move: 'Get legal advice before moving these funds further.' });
      else if (c.verdict === 'new' && (o.asset !== 'SOL' || o.lamports > 10_000_000n))
        await raise(agentId, { ...base, severity: 'med', type: 'sol_new_dest', dedupe: `new:${sig}:${o.to}`, title: 'Funds sent to a new address',
          what: `${amt} left ${who} for ${short(o.to)}, an address you haven't used before.`, did: 'Checked it against your history and the threat lists. Nothing matched.',
          move: 'If this was you, you can ignore this. If not, move your funds to a fresh wallet now.' });
      if (c.verdict !== 'lookalike' && c.verdict !== 'poisoned') learn(agentId, 'solana', o.to);
    }
    if (f.preLamports > 50_000_000 && f.postLamports < f.preLamports * 0.1)
      await raise(agentId, { ...base, severity: 'high', type: 'sol_drain', dedupe: `drain:${sig}`, title: 'Most of your SOL just left',
        what: `${who} went from ${sol(f.preLamports)} to ${sol(f.postLamports)} SOL in one transaction.`, did: 'Flagged the size of the move.', move: 'If you did not do this, assume the wallet is compromised and move what is left.' });
  }
  if (!f.signer) {
    for (const o of f.outs.filter(o => o.delegated))
      await raise(agentId, { ...base, severity: 'crit', type: 'sol_delegate_drain', dedupe: `dd:${sig}`, title: 'Tokens taken without your signature',
        what: `${short(o.by)} used an earlier permission to move tokens out of ${who}.`, did: 'Spotted that you did not sign this transfer.', move: 'Revoke every token permission on this wallet now and move remaining assets.' });
    for (const i of f.ins) {
      const tiny = i.asset === 'SOL' ? i.lamports < 1_000_000n : true;
      if (!tiny || !i.from) continue;
      const hit = inspectIncoming(agentId, 'solana', i.from);
      if (hit) await raise(agentId, { ...base, severity: 'med', type: 'sol_poison_dust', dedupe: `dust:${agentId}:${i.from}`, title: 'Address-poisoning attempt',
        what: `A tiny transfer reached ${who} from ${short(i.from)}, which imitates your ${hit.label || 'address'} (${short(hit.imitates)}). The first ${hit.prefix} and last ${hit.suffix} characters match.`,
        did: 'Tagged the lookalike. The shield will block any send to it.', move: 'Never copy addresses from your history. Use your saved addresses instead.' });
    }
  }
}

let rpc;
// One place that judges a signature for one watched wallet. Used by the real-time webhook and by the polling
// backstop, so a transaction is never judged twice.
export async function processSignature(asset, sig) {
  rpc ||= rpcClient(config.solana.rpc);
  // Claim the signature before any await, so the webhook and the polling backstop can't both judge it.
  if (!run('insert or ignore into processed(sig, asset_id, created_at) values(?,?,?)', sig, asset.id, now()).changes) return false;
  const t = await rpc.getTransaction(sig).catch(() => null);
  if (!t) { run('delete from processed where sig = ? and asset_id = ?', sig, asset.id); return false; } // retry next time
  if (t.meta?.err) return false;
  await handleFindings(asset.agent_id, asset, sig, analyzeParsedTx(t, asset.value));
  return true;
}

export async function pollSolana() {
  if (!config.solana.rpc) return;
  rpc ||= rpcClient(config.solana.rpc);
  for (const asset of activeAssets('wallet', 'solana')) {
    try {
      const st = stateOf(asset);
      if (!st.baseline) {
        const sigs = await rpc.getSignatures(asset.value, { limit: 25 });
        for (const s of sigs.slice(0, 25)) {
          const t = await rpc.getTransaction(s.signature).catch(() => null);
          if (!t || t.meta?.err) continue;
          const f = analyzeParsedTx(t, asset.value);
          if (f.signer) f.outs.forEach(o => o.to && o.to !== asset.value && learn(asset.agent_id, 'solana', o.to));
          else f.ins.filter(i => i.asset === 'SOL' && i.lamports < 1_000_000n && i.from).forEach(i => inspectIncoming(asset.agent_id, 'solana', i.from));
        }
        st.baseline = true; st.lastSig = sigs[0]?.signature || null; st.health = 'ok';
        saveState(asset, st); continue;
      }
      const sigs = await rpc.getSignatures(asset.value, st.lastSig ? { until: st.lastSig, limit: 50 } : { limit: 10 });
      for (const s of [...sigs].reverse()) {
        if (s.err) continue;
        await processSignature(asset, s.signature);
      }
      if (sigs[0]) st.lastSig = sigs[0].signature;
      st.health = 'ok';
      saveState(asset, st);
    } catch (e) { const st = stateOf(asset); st.health = 'error: ' + e.message.slice(0, 80); saveState(asset, st); }
  }
}

// Once a day: tell people when there is junk worth sweeping.
export async function dailySweepCheck() {
  if (!config.solana.rpc) return;
  for (const asset of activeAssets('wallet', 'solana')) {
    const st = stateOf(asset);
    if (st.sweepCheckedAt && now() - st.sweepCheckedAt < 86400) continue;
    try {
      const s = await scanWallet(asset.value);
      st.sweepCheckedAt = now();
      const prev = st.junkCount || 0;
      st.junkCount = s.summary.junk;
      saveState(asset, st);
      if (s.summary.junk > prev && s.summary.junk >= 3)
        await raiseAgent(asset.agent_id, { severity: 'low', type: 'sweep_ready', dedupe: `sweep:${asset.id}:${s.summary.junk}:${Math.floor(now() / 86400)}`, title: 'Spam sweep ready',
          what: `${label(asset)} has ${s.summary.junk} junk items${s.summary.cnfts ? `, including ${s.summary.cnfts} scam cNFTs` : ''}.`,
          did: `Bundled them so you can burn them in one approval and get back about ${(s.summary.rentLamports / LAMPORTS_PER_SOL).toFixed(4)} SOL of rent.`,
          move: "Don't open links in their names. Run the sweep from your dashboard.", data: { wallet: asset.value } });
    } catch {}
  }
}
