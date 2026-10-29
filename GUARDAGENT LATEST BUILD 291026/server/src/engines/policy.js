// Policy engine for Guarded Wallets and Treasury Watch: per-transaction and daily limits, destination
// allowlists and blocklists, extra approvals above an amount, and quiet-hours timelocks.
// Pure function so it can be tested and reused anywhere.
import { isSanctioned, isBlocked } from './lists.js';

/*
policy = {
  perTxLimit: 50,            // max units (SOL / native coin) per transaction, 0 = no limit
  dailyLimit: 200,           // rolling 24h total
  allowlist: ['addr', ...],  // if non-empty, destinations must be on it
  blocklist: ['addr', ...],
  approvalsAbove: { amount: 25, approvals: 2 },   // above this amount, needs N approvals
  tokenLimits: { '<mint or token address>': { perTx: 1000, daily: 5000 } },
  timelockAbove: { amount: 100, seconds: 86400 }  // big moves must wait before execution
}
request = { chain, to, amount, token?: '<mint>', approvals?: number, proposedAt?: unix }
history = [{ amount, token?, at }]   // executed outflows
*/
export function evaluatePolicy(policy = {}, request, history = [], nowSec = Math.floor(Date.now() / 1000)) {
  const reasons = [];
  let decision = 'allow';
  const deny = t => { reasons.push({ result: 'deny', text: t }); decision = 'deny'; };
  const hold = t => { reasons.push({ result: 'needs_approval', text: t }); if (decision === 'allow') decision = 'needs_approval'; };
  const wait = t => { reasons.push({ result: 'timelocked', text: t }); if (decision === 'allow') decision = 'timelocked'; };
  const chain = request.chain || 'solana';
  const norm = a => (chain === 'solana' || chain === 'bitcoin' ? a : String(a || '').toLowerCase());
  const to = norm(request.to);
  const amount = Number(request.amount || 0);
  if (!to) deny('No destination address.');
  // A negative or non-numeric amount would slip under every limit, so it is refused outright.
  if (!Number.isFinite(amount) || amount < 0) deny('The amount is not a valid number.');
  if (to && isSanctioned(chain, to)) deny('Destination is on the sanctions list.');
  if (to && isBlocked(chain, to)) deny('Destination is on the threat list.');
  if ((policy.blocklist || []).map(norm).includes(to)) deny('Destination is on your blocklist.');
  if ((policy.allowlist || []).length && !(policy.allowlist || []).map(norm).includes(to)) deny('Destination is not on your approved list.');

  const token = request.token || null;
  const lim = token ? policy.tokenLimits?.[token] || {} : { perTx: policy.perTxLimit, daily: policy.dailyLimit };
  const spent24h = history.filter(h => (h.token || null) === token && nowSec - h.at < 86400).reduce((s, h) => s + Number(h.amount || 0), 0);
  if (lim.perTx > 0 && amount > lim.perTx) deny(`Amount ${amount} is over the per-transaction limit of ${lim.perTx}.`);
  if (lim.daily > 0 && spent24h + amount > lim.daily) deny(`This would bring the last 24 hours to ${spent24h + amount}, over the daily limit of ${lim.daily}.`);

  const ab = policy.approvalsAbove;
  if (!token && ab?.amount > 0 && amount > ab.amount && (request.approvals || 0) < (ab.approvals || 2))
    hold(`Amounts over ${ab.amount} need ${ab.approvals || 2} approvals; this has ${request.approvals || 0}.`);
  const tl = policy.timelockAbove;
  if (!token && tl?.amount > 0 && amount > tl.amount) {
    const since = request.proposedAt ? nowSec - request.proposedAt : 0;
    if (since < (tl.seconds || 0)) wait(`Amounts over ${tl.amount} must wait ${Math.round((tl.seconds || 0) / 3600)} hours after proposal; ${Math.max(0, Math.round(((tl.seconds || 0) - since) / 3600))} hours left.`);
  }
  if (!reasons.length) reasons.push({ result: 'allow', text: 'Within every rule.' });
  return { decision, reasons, spent24h };
}

export function validatePolicy(p = {}) {
  const num = (v, name) => { if (v == null || v === '') return 0; const n = Number(v); if (!Number.isFinite(n) || n < 0) throw new Error(`${name} must be a positive number`); return n; };
  const list = v => (Array.isArray(v) ? v : String(v || '').split(/[\s,]+/)).map(s => String(s).trim()).filter(Boolean).slice(0, 500);
  return {
    perTxLimit: num(p.perTxLimit, 'Per-transaction limit'),
    dailyLimit: num(p.dailyLimit, 'Daily limit'),
    allowlist: list(p.allowlist),
    blocklist: list(p.blocklist),
    approvalsAbove: p.approvalsAbove ? { amount: num(p.approvalsAbove.amount, 'Approval amount'), approvals: Math.max(1, Math.min(10, Number(p.approvalsAbove.approvals) || 2)) } : null,
    timelockAbove: p.timelockAbove ? { amount: num(p.timelockAbove.amount, 'Timelock amount'), seconds: Math.min(30 * 86400, num(p.timelockAbove.seconds, 'Timelock')) } : null,
    tokenLimits: typeof p.tokenLimits === 'object' && p.tokenLimits ? p.tokenLimits : {}
  };
}
