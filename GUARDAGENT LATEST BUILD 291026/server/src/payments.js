// Verifies a hire/purchase transaction on-chain and grants the agent rank or business service.
import crypto from 'node:crypto';
import { config } from './config.js';
import { run, get, tx, now, json } from './db.js';
import { rpcClient, LAMPORTS_PER_SOL, PROGRAMS, sleep, ata } from './lib/solana.js';
import { RANKS, SERVICES, RANK_ORDER, isPriced, priceOf } from './plans.js';
import { bad, HttpError } from './http.js';

let decimalsCache = null;
async function guardDecimals(rpc) {
  if (decimalsCache != null) return decimalsCache;
  const info = await rpc.getAccountInfo(config.solana.guardMint, 'jsonParsed');
  const d = info?.data?.parsed?.info?.decimals;
  if (typeof d !== 'number') throw new Error('Could not read $GUARD mint decimals');
  return (decimalsCache = d);
}

// Pure check of a jsonParsed transaction. Exported for tests.
export function checkPaymentTx(txr, { wallet, kind, id, treasury, mint, requiredLamports = 0n, requiredRaw, requiredUsdc = 0n, usdcMint, maxAgeSec = 7 * 86400, nowSec = now() }) {
  if (!txr) throw new HttpError(404, 'Transaction not found yet. Wait a few seconds and try again.');
  if (txr.meta?.err) throw bad('That transaction failed on-chain, so nothing was paid.');
  const keys = txr.transaction.message.accountKeys;
  const payer = keys[0];
  const payerKey = typeof payer === 'string' ? payer : payer.pubkey;
  if (payerKey !== wallet || (typeof payer === 'object' && payer.signer === false)) throw bad('That transaction was not signed by this wallet.');
  if (txr.blockTime && nowSec - txr.blockTime > maxAgeSec) throw bad('That transaction is too old to use for a purchase.');
  let lamports = 0n, burnt = 0n, usdc = 0n, memoOk = false;
  const expectedMemo = `bodyguard:${kind}:${id}`;
  // USDC must land in the treasury's own USDC account (its associated token account, which is unique per wallet + mint).
  const treasuryUsdc = requiredUsdc > 0n ? ata(treasury, usdcMint) : null;
  for (const ins of txr.transaction.message.instructions) {
    const p = ins.parsed;
    if (ins.program === 'system' && p?.type === 'transfer' && p.info.source === wallet && p.info.destination === treasury) lamports += BigInt(p.info.lamports);
    if ((ins.program === 'spl-token' || ins.programId === PROGRAMS.TOKEN || ins.programId === PROGRAMS.TOKEN_2022) && p && (p.type === 'burnChecked' || p.type === 'burn')) {
      const auth = p.info.authority || p.info.multisigAuthority;
      if (p.info.mint === mint && auth === wallet) burnt += BigInt(p.info.tokenAmount?.amount ?? p.info.amount);
    }
    if (treasuryUsdc && (ins.program === 'spl-token' || ins.programId === PROGRAMS.TOKEN) && p && (p.type === 'transferChecked' || p.type === 'transfer')) {
      const auth = p.info.authority || p.info.multisigAuthority;
      if (p.info.destination === treasuryUsdc && auth === wallet && (p.type === 'transfer' || p.info.mint === usdcMint)) usdc += BigInt(p.info.tokenAmount?.amount ?? p.info.amount);
    }
    if (ins.program === 'spl-memo' || ins.programId === PROGRAMS.MEMO || ins.programId === PROGRAMS.MEMO_V1) {
      const text = typeof p === 'string' ? p : '';
      if (text.trim() === expectedMemo) memoOk = true;
    }
  }
  if (!memoOk) throw bad('That transaction is missing the Bodyguard purchase tag.');
  if (lamports < BigInt(requiredLamports)) throw bad('Not enough SOL was sent to the treasury for this purchase.');
  if (usdc < BigInt(requiredUsdc)) throw bad('Not enough USDC was sent to the treasury for this purchase.');
  if (burnt < BigInt(requiredRaw)) throw bad('Not enough $GUARD was burnt for this purchase.');
  return { lamports, burnt, usdc, slot: txr.slot };
}

export async function verifyAndGrant({ signature, wallet, kind, id }) {
  if (!config.solana.rpc || !config.solana.guardMint || !config.solana.treasury) throw new HttpError(503, 'Payments are not switched on yet.');
  if (!/^[1-9A-HJ-NP-Za-km-z]{64,90}$/.test(signature || '')) throw bad('That is not a valid transaction signature.');
  if (kind !== 'rank' && kind !== 'service') throw bad('Unknown purchase type.');
  const item = priceOf(kind, id);
  if (!isPriced(item)) throw bad('That item is not for sale yet.');
  if (get('select 1 from payments where signature = ?', signature)) throw bad('That transaction has already been used.');

  const rpc = rpcClient(config.solana.rpc);
  const decimals = await guardDecimals(rpc);
  let txr = null;
  for (let i = 0; i < 6 && !txr; i++) { txr = await rpc.getTransaction(signature); if (!txr) await sleep(2000); }
  // Agent ranks are paid in SOL; business services in USDC (6 decimals). Both burn $GUARD.
  const requiredLamports = BigInt(Math.round((item.sol || 0) * LAMPORTS_PER_SOL));
  const requiredUsdc = BigInt(Math.round((item.usdc || 0) * 1e6));
  const requiredRaw = BigInt(item.guard) * 10n ** BigInt(decimals);
  const res = checkPaymentTx(txr, { wallet, kind, id, treasury: config.solana.treasury, mint: config.solana.guardMint, requiredLamports, requiredRaw, requiredUsdc, usdcMint: config.solana.usdcMint });

  if (get('select 1 from payments where signature = ?', signature)) throw bad('That transaction has already been used.');
  try { return tx(() => {
    run('insert into payments(signature, wallet, kind, item, lamports, guard_raw, slot, created_at) values(?,?,?,?,?,?,?,?)',
      signature, wallet, kind, id, Number(res.lamports), res.burnt.toString(), res.slot, now());
    if (kind === 'rank') {
      const agent = grantRank(wallet, id);
      run('update payments set agent_id = ? where signature = ?', agent.id, signature);
      return { kind, id, agentId: agent.id, expiresAt: agent.expires_at };
    }
    const org = grantService(wallet, id);
    run('update payments set org_id = ? where signature = ?', org.id, signature);
    return { kind, id, orgId: org.id };
  }); } catch (e) {
    if (/UNIQUE|constraint/i.test(e.message)) throw bad('That transaction has already been used.');
    throw e;
  }
}

function newAgentId() {
  for (;;) {
    const id = 'G-' + String(crypto.randomInt(0, 10000)).padStart(4, '0');
    if (!get('select 1 from agents where id = ?', id)) return id;
  }
}

export function grantRank(wallet, rank) {
  if (!RANKS[rank]) throw bad('Unknown rank.');
  const days = config.rankDays;
  const t = now();
  const existing = get("select * from agents where owner = ? order by created_at desc limit 1", wallet);
  if (existing) {
    // Paid time is never lost. Same rank: add the days. Upgrade: the unused days of the old rank are converted at
    // the price ratio and added on. Buying a lower rank while a higher one is still running keeps the higher rank
    // and adds the new days at the same ratio, instead of silently downgrading the customer.
    const active = existing.status === 'active' && existing.expires_at && existing.expires_at > t;
    const left = active ? existing.expires_at - t : 0;
    const price = r => Number(RANKS[r]?.sol) || 1;
    const curIdx = RANK_ORDER.indexOf(existing.rank), newIdx = RANK_ORDER.indexOf(rank);
    const permanent = existing.status === 'active' && existing.expires_at == null;
    let keepRank = rank, expires;
    if (days <= 0) expires = null;
    else if (permanent) { expires = null; keepRank = newIdx > curIdx ? rank : existing.rank; }
    else if (existing.rank === rank || !active) expires = (existing.rank === rank ? Math.max(t, existing.expires_at || t) : t) + days * 86400;
    else if (newIdx > curIdx) expires = t + days * 86400 + Math.floor(left * price(existing.rank) / price(rank));
    else { keepRank = existing.rank; expires = existing.expires_at + Math.floor(days * 86400 * price(rank) / price(existing.rank)); }
    const upgraded = RANK_ORDER.indexOf(keepRank) > curIdx;
    run("update agents set rank = ?, status = 'active', expires_at = ? where id = ?", keepRank, expires, existing.id);
    return { ...existing, rank: keepRank, expires_at: expires, upgraded };
  }
  const id = newAgentId();
  const expires = days > 0 ? t + days * 86400 : null;
  run("insert into agents(id, owner, rank, status, created_at, expires_at) values(?,?,?,?,?,?)", id, wallet, rank, 'active', t, expires);
  run("insert or ignore into members(agent_id, wallet, role) values(?,?,'owner')", id, wallet);
  return { id, owner: wallet, rank, expires_at: expires };
}

export function grantService(wallet, service) {
  if (!SERVICES[service]) throw bad('Unknown service.');
  const t = now();
  let org = get('select * from orgs where owner = ?', wallet);
  if (!org) {
    const id = 'org_' + crypto.randomBytes(6).toString('hex');
    run('insert into orgs(id, owner, name, created_at) values(?,?,?,?)', id, wallet, 'My organisation', t);
    run("insert or ignore into org_members(org_id, wallet, role) values(?,?,'owner')", id, wallet);
    org = get('select * from orgs where id = ?', id);
  }
  const services = json(org.services);
  const prev = services[service]?.expires || t;
  services[service] = { since: services[service]?.since || t, expires: config.serviceDays > 0 ? Math.max(t, prev) + config.serviceDays * 86400 : null };
  run('update orgs set services = ? where id = ?', JSON.stringify(services), org.id);
  return { ...org, services };
}

export const agentActive = a => a && a.status === 'active' && (!a.expires_at || a.expires_at > now());
export const serviceActive = (org, s) => { const v = json(org?.services)[s]; return !!v && (!v.expires || v.expires > now()); };
