// Shield (paste/send check), transaction firewall and spam sweep endpoints.
import { route, bad, HttpError, rateLimit } from '../http.js';
import { config } from '../config.js';
import { all } from '../db.js';
import { agentFromAnyAuth, requireAgent, normalizeAddress } from '../access.js';
import { checkAddress } from '../engines/poison.js';
import { analyzeSolana } from '../engines/firewall-sol.js';
import { analyzeEvm } from '../engines/firewall-evm.js';
import { scanWallet, buildSweep } from '../engines/spam.js';
import { isValidPubkey } from '../lib/solana.js';
import { raiseAgent } from '../alerts.js';
import { short } from '../engines/poison.js';
import { lockdownForAgent, gateFirewall } from '../duress.js';
import { ALL_CHAINS } from '../plans.js';

const guessChain = a => (/^0x[0-9a-fA-F]{40}$/.test(a) ? 'ethereum' : /^(bc1|[13])/.test(a) && !isValidPubkey(a) ? 'bitcoin' : 'solana');

route('POST', '/api/shield/check', ctx => {
  rateLimit('shield:' + ctx.ip, 240);
  const agent = agentFromAnyAuth(ctx);
  const raw = String(ctx.body.address || '').trim().slice(0, 200);
  const chain = ctx.body.chain || guessChain(raw);
  if (!ALL_CHAINS.includes(chain)) throw bad('Pick a supported chain.');
  let address;
  try { address = normalizeAddress(chain, raw); } catch { return { verdict: 'invalid', address: raw }; }
  const r = checkAddress(agent.id, chain, address);
  if ((r.verdict === 'lookalike' || r.verdict === 'poisoned') && ctx.body.event === 'paste') {
    raiseAgent(agent.id, {
      severity: 'high', type: 'poison_paste', dedupe: `paste:${agent.id}:${address}:${Math.floor(Date.now() / 3600000)}`,
      title: 'Poisoned address pasted',
      what: `You pasted ${short(address)}${ctx.body.origin ? ` on ${hostOf(ctx.body.origin)}` : ''}. It imitates your ${r.label} (${short(r.imitates)}).`,
      did: 'The shield warned you before anything was sent and will block sends to it.',
      move: 'Delete that address and copy the real one from your saved contacts or the original source.',
      data: { address, imitates: r.imitates, origin: hostOf(ctx.body.origin) }
    }).catch(() => {});
  }
  return { chain, ...r };
});

route('POST', '/api/firewall/solana', async ctx => {
  rateLimit('fw:' + ctx.ip, 120);
  const agent = agentFromAnyAuth(ctx);
  const txs = Array.isArray(ctx.body.transactions) ? ctx.body.transactions.slice(0, 101) : [ctx.body.transaction];
  if (!txs.length || txs.some(t => typeof t !== 'string' || t.length > 20000 || !/^[A-Za-z0-9+/=]+$/.test(t))) throw bad('Send the transaction as base64.');
  if (!config.solana.rpc) throw new HttpError(503, 'Solana RPC is not configured.');
  const results = [];
  // Every transaction in the request is checked (up to 10; more than that is held rather than half-checked).
  if (txs.length > 10) return publicResult(gateFirewall({ action: 'block', reasons: [{ severity: 'crit', text: `This request asks you to sign ${txs.length} transactions at once, too many to check safely.`, code: 'batch_too_big' }], summary: [] }, lockdownForAgent(agent), 'solana'));
  for (const t of txs) results.push(await analyzeSolana(agent, t, ctx.body.origin).catch(e => ({ action: 'warn', reasons: [{ severity: 'high', text: "Bodyguard couldn't read this transaction, so it wasn't checked. Only continue if you trust this site.", code: 'decode_error' }], summary: [] })));
  const merged = gateFirewall(mergeResults(results), lockdownForAgent(agent), 'solana');
  if (merged.action === 'block' && !merged.locked) logBlock(agent, merged, ctx.body.origin, 'Solana');
  return publicResult(merged);
}, { limit: 450_000 });

route('POST', '/api/firewall/evm', async ctx => {
  rateLimit('fw:' + ctx.ip, 120);
  const agent = agentFromAnyAuth(ctx);
  const { chainId, method, params, origin, from } = ctx.body;
  if (typeof method !== 'string') throw bad('Missing method.');
  const lock = lockdownForAgent(agent);
  const ps = Array.isArray(params) ? params : [];
  const unreadable = () => ({ action: 'warn', reasons: [{ severity: 'high', text: "Bodyguard couldn't read this request, so it wasn't checked. Only continue if you trust this site.", code: 'decode_error' }], summary: [], flows: { contractCall: true } });
  const one = async (m, p) => { try { return await analyzeEvm(agent, { chainId, method: m, params: p, origin, from }); } catch { return unreadable(); } };
  let r;
  if (method === 'wallet_sendCalls') {
    // Batches: every call is checked, and the worst verdict wins. A batch too big to check is held.
    const calls = Array.isArray(ps[0]?.calls) ? ps[0].calls : null;
    if (!calls || !calls.length) r = unreadable();
    else if (calls.length > 25) r = { action: 'block', reasons: [{ severity: 'crit', text: `This batch has ${calls.length} calls, too many to check safely. Real apps rarely need this.`, code: 'batch_too_big' }], summary: [] };
    else r = mergeResults(await Promise.all(calls.map(c => one('eth_sendTransaction', [{ ...c, from: ps[0]?.from || from }]))));
  } else if (method === 'eth_signTransaction') r = await one('eth_sendTransaction', ps);
  else r = await one(method, ps);
  r = gateFirewall(r, lock, 'evm');
  if (r.action === 'block' && !r.locked) logBlock(agent, r, origin, 'EVM');
  return publicResult(r);
});

function mergeResults(results) {
  const order = { allow: 0, warn: 1, block: 2 };
  const action = results.reduce((a, r) => (order[r.action] > order[a] ? r.action : a), 'allow');
  const flows = { nativeOut: results.reduce((n, r) => n + (Number(r.flows?.nativeOut) || 0), 0), tokenOut: results.some(r => r.flows?.tokenOut), contractCall: results.some(r => r.flows?.contractCall), simulated: results.every(r => r.flows?.simulated) };
  return { action, reasons: results.flatMap(r => r.reasons), summary: results.flatMap(r => r.summary || []), flows };
}
// Internal measurements stay on the server; the extension only needs the verdict.
const publicResult = ({ flows, ...r }) => r;
function logBlock(agent, r, origin, chainLabel) {
  raiseAgent(agent.id, {
    severity: 'high', type: 'firewall_block', dedupe: `fw:${agent.id}:${r.reasons[0]?.code}:${hostOf(origin)}:${Math.floor(Date.now() / 600000)}`,
    title: 'Dangerous transaction stopped',
    what: `A ${chainLabel} signing request${origin ? ` from ${hostOf(origin)}` : ''} was stopped before your wallet signed it. ${r.reasons[0]?.text || ''}`,
    did: 'The firewall blocked the request and showed you why.',
    move: "If you didn't start this, close the site and don't reconnect your wallet to it.",
    data: { origin: hostOf(origin), reasons: r.reasons.slice(0, 5) }
  }).catch(() => {});
}
// Site names end up in alert emails and chats, so anything that isn't a clean hostname is dropped.
const hostOf = o => { try { return new URL(String(o)).hostname.slice(0, 120); } catch { return ''; } };

/* ---------------- spam sweep ---------------- */
function sweepWallet(ctx, agent) {
  const w = String(ctx.query.wallet || ctx.body.wallet || '');
  const mine = all("select value from assets where agent_id = ? and type = 'wallet' and chain = 'solana'", agent.id).map(x => x.value);
  if (!mine.includes(w)) throw bad('Add this wallet to your agent first, then run the sweep on it.');
  return w;
}
route('GET', '/api/agent/:id/sweep/scan', async ctx => {
  const agent = requireAgent(ctx);
  rateLimit('sweep:' + agent.id, 20);
  if (!config.solana.rpc) throw new HttpError(503, 'Solana RPC is not configured.');
  return scanWallet(sweepWallet(ctx, agent));
});
route('POST', '/api/agent/:id/sweep/build', async ctx => {
  const agent = requireAgent(ctx);
  rateLimit('sweep:' + agent.id, 20);
  const ids = Array.isArray(ctx.body.ids) ? ctx.body.ids.slice(0, 120) : [];
  if (!ids.length) throw bad('Pick at least one item to sweep.');
  return buildSweep(sweepWallet(ctx, agent), ids);
});
