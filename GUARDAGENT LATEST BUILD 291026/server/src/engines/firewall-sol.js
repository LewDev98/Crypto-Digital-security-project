// Solana transaction firewall. Runs before the wallet is allowed to sign:
// 1) static decode of every instruction, 2) poisoning check on every destination, 3) a simulation that shows
// exactly what leaves the wallet, 4) threat-list checks on programs, addresses and the site asking.
import { config } from '../config.js';
import { all } from '../db.js';
import { rpcClient, decodeTx, resolveTx, parseTokenAccount, PROGRAMS, LAMPORTS_PER_SOL } from '../lib/solana.js';
import { checkAddress, short } from './poison.js';
import { isPhishingDomain, isBlocked, isSanctioned } from './lists.js';

const U64_MAX = 2n ** 64n - 1n;
const sol = l => (Number(l) / LAMPORTS_PER_SOL).toLocaleString('en-GB', { maximumFractionDigits: 4 });

export async function analyzeSolana(agent, txB64, origin, { rpc = rpcClient(config.solana.rpc) } = {}) {
  const reasons = [];
  const add = (severity, text, code) => reasons.push({ severity, text, code });
  const summary = [];
  const flows = { nativeOut: 0, simulated: false };

  if (origin && isPhishingDomain(origin)) add('crit', `${hostOf(origin)} is on known phishing lists. Close the site.`, 'phishing_site');

  const decoded = decodeTx(Buffer.from(txB64, 'base64'));
  const r = await resolveTx(decoded, rpc);
  const myWallets = new Set(all("select value from assets where agent_id = ? and type = 'wallet' and chain = 'solana'", agent.id).map(x => x.value));
  const user = r.signers.find(s => myWallets.has(s)) || r.signers[0];

  // Pre-state of the user's token accounts (both token programs).
  const tokenAccounts = new Map();
  for (const pid of [PROGRAMS.TOKEN, PROGRAMS.TOKEN_2022]) {
    try {
      for (const t of await rpc.getTokenAccounts(user, pid)) {
        const info = t.account.data.parsed.info;
        tokenAccounts.set(t.pubkey, { mint: info.mint, amount: BigInt(info.tokenAmount.amount), decimals: info.tokenAmount.decimals, program: pid });
      }
    } catch {}
  }

  const destOwnerLookups = [];
  for (const ins of r.instructions) {
    const d = Buffer.from(ins.data);
    const k = ins.keys.map(x => x.pubkey);
    if (isBlocked('solana', ins.programId)) add('crit', `Calls a program flagged as a drainer (${short(ins.programId)}).`, 'blocked_program');
    if (ins.programId === PROGRAMS.SYSTEM && d.length >= 4) {
      const t = d.readUInt32LE(0);
      if (t === 2 && d.length >= 12) {
        const lamports = d.readBigUInt64LE(4);
        if (k[0] === user) {
          summary.push(`Sends ${sol(lamports)} SOL to ${short(k[1])}`);
          destCheck(agent, k[1], add, `${sol(lamports)} SOL`);
        }
      }
      if ((t === 1 || t === 10) && k[0] === user) add('crit', 'Hands control of your wallet account to another program. This is how wallets get permanently drained.', 'assign');
    }
    if (ins.programId === PROGRAMS.TOKEN || ins.programId === PROGRAMS.TOKEN_2022) {
      const op = d[0];
      const mine = acc => tokenAccounts.has(acc);
      if ((op === 3 || op === 12) && d.length >= 9) {
        const amount = d.readBigUInt64LE(1);
        const src = k[0], dst = op === 3 ? k[1] : k[2];
        if (mine(src)) { destOwnerLookups.push({ dst, amount, src }); }
      }
      if ((op === 4 || op === 13) && d.length >= 9) {
        const amount = d.readBigUInt64LE(1);
        const src = k[0], delegate = op === 4 ? k[1] : k[2];
        if (mine(src)) {
          const ta = tokenAccounts.get(src);
          add(amount >= U64_MAX / 2n || amount >= ta.amount ? 'crit' : 'high', `Gives ${short(delegate)} permission to move ${amount >= U64_MAX / 2n ? 'all of' : 'some of'} your ${short(ta.mint)} tokens whenever it likes.`, 'approve');
        }
      }
      if (op === 6 && mine(k[0])) {
        const type = d[1];
        add('crit', type === 2 ? 'Transfers ownership of one of your token accounts to someone else.' : 'Changes who controls one of your token accounts.', 'set_authority');
      }
      if (op === 9 && mine(k[0]) && k[1] !== user) add('med', `Closes one of your token accounts and sends its rent to ${short(k[1])}.`, 'close_to_other');
    }
  }

  // Resolve owners of token destinations, then poison-check them.
  if (destOwnerLookups.length) {
    try {
      const infos = await rpc.getMultipleAccounts(destOwnerLookups.map(x => x.dst));
      destOwnerLookups.forEach((x, i) => {
        const owner = infos[i] ? parseTokenAccount(infos[i].data[0])?.owner : null;
        const ta = tokenAccounts.get(x.src);
        const amt = ta ? (Number(x.amount) / 10 ** ta.decimals).toLocaleString('en-GB', { maximumFractionDigits: 4 }) : x.amount.toString();
        summary.push(`Sends ${amt} of ${short(ta?.mint || '')} to ${short(owner || x.dst)}`);
        destCheck(agent, owner || x.dst, add, `${amt} tokens`);
      });
    } catch {}
  }

  // Simulation: what actually leaves the wallet.
  try {
    const watch = [user, ...[...tokenAccounts.keys()].slice(0, 24)];
    const pre = await rpc.getBalance(user);
    const sim = await rpc.simulate(txB64, { accounts: { encoding: 'base64', addresses: watch } });
    const v = sim.value;
    if (v.err) add('low', 'This transaction would fail if you signed it now, so nothing would happen.', 'sim_fail');
    else if (v.accounts) {
      const postSol = v.accounts[0]?.lamports ?? pre;
      const lost = BigInt(pre) - BigInt(postSol);
      flows.simulated = true;
      flows.nativeOut = lost > 0n ? Number(lost) / LAMPORTS_PER_SOL : 0;
      if (lost > 0n && pre > 0 && Number(lost) / pre > 0.9 && lost > 50_000_000n) add('crit', `Would empty your wallet: ${sol(lost)} SOL leaves and almost nothing is left.`, 'drain_sol');
      // More than half the balance leaving is worth a hard look even when the destination isn't flagged.
      else if (lost > 100_000_000n && pre > 0 && Number(lost) / pre > 0.5) add('high', `Sends ${sol(lost)} SOL, more than half of what is in this wallet. Make sure you meant to.`, 'large_sol_out');
      let drained = 0;
      [...tokenAccounts.entries()].slice(0, 24).forEach(([acc, ta], i) => {
        const after = v.accounts[i + 1];
        if (!after) { if (ta.amount > 0n) { drained++; flows.tokenOut = true; } return; }
        const p = parseTokenAccount(after.data[0]);
        if (!p) return;
        if (p.owner !== user) add('crit', `Your ${short(ta.mint)} token account would end up owned by ${short(p.owner)}.`, 'owner_change');
        if (p.delegate && p.delegatedAmount > 0n) add('high', `${short(p.delegate)} would be allowed to spend your ${short(ta.mint)} tokens.`, 'delegate');
        if (p.amount < ta.amount) flows.tokenOut = true;
        if (ta.amount > 0n && p.amount * 10n < ta.amount) drained++;
      });
      if (drained >= 3) add('crit', `Would take most of ${drained} different tokens from your wallet at once.`, 'drain_tokens');
      else if (drained > 0) add('med', `Moves most of ${drained === 1 ? 'one of your tokens' : drained + ' tokens'} out of your wallet.`, 'token_out');
    }
  } catch (e) { add('low', 'Simulation was unavailable, so this check used the transaction contents only.', 'sim_unavailable'); }

  return { ...verdict(reasons, summary), flows };
}

function destCheck(agent, dest, add, what) {
  if (isSanctioned('solana', dest)) add('crit', `Sends ${what} to a sanctioned address.`, 'sanctioned');
  if (isBlocked('solana', dest)) add('crit', `Sends ${what} to an address flagged as a scammer.`, 'blocked_dest');
  const c = checkAddress(agent.id, 'solana', dest);
  if (c.verdict === 'lookalike' || c.verdict === 'poisoned')
    add('crit', `Sends ${what} to ${short(dest)}, a lookalike of your ${c.label} (${short(c.imitates)}). The first ${c.prefix} and last ${c.suffix} characters match, the middle doesn't. This is address poisoning.`, 'poison');
  else if (c.verdict === 'new') add('low', `${short(dest)} is a first-time address for you. Double-check it.`, 'new_dest');
}

const hostOf = o => { try { return new URL(String(o)).hostname.slice(0, 120); } catch { return 'This site'; } };

export function verdict(reasons, summary = []) {
  const order = { low: 0, med: 1, high: 2, crit: 3 };
  reasons.sort((a, b) => order[b.severity] - order[a.severity]);
  const top = reasons[0]?.severity;
  return { action: top === 'crit' ? 'block' : top === 'high' ? 'warn' : 'allow', reasons, summary };
}
