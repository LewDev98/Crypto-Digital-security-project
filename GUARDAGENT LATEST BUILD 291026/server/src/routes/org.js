// Business console: organisation, team, alert channels, Risk Screening (API keys + API), Guarded Wallets
// (Squads smart accounts + policy engine) and Treasury Watch.
import crypto from 'node:crypto';
import { route, bad, HttpError, rateLimit, requireWallet } from '../http.js';
import { config } from '../config.js';
import { run, get, all, now, json, sha256hex, randomToken } from '../db.js';
import { assertRoom } from '../capacity.js';
import { requireOrg, requireApiKey, orgForWallet, normalizeAddress, normalizeEmail } from '../access.js';
import { serviceActive } from '../payments.js';
import { SERVICES, EVM_CHAINS } from '../plans.js';
import { screen } from '../engines/risk.js';
import { lockdownUntil } from '../duress.js';
import { log as audit } from '../security.js';
import { evaluatePolicy, validatePolicy } from '../engines/policy.js';
import { rpcClient, generateKeypair, buildTx, ix, isValidPubkey } from '../lib/solana.js';
import { multisigCreateV2Ix, decodeProgramConfig, programConfigPda, multisigPda, vaultPda, decodeMultisig, PERM } from '../lib/squads.js';

function orgView(org) {
  const services = json(org.services);
  const ch = get('select telegram_chat_id, alert_email from channels where subject = ?', 'org:' + org.id) || {};
  return {
    id: org.id, name: org.name, owner: org.owner,
    services: Object.fromEntries(Object.keys(SERVICES).map(s => [s, { name: SERVICES[s].name, active: serviceActive(org, s), ...(services[s] || {}) }])),
    members: all('select wallet, role from org_members where org_id = ?', org.id),
    channels: { telegram: !!ch.telegram_chat_id, email: ch.alert_email || null },
    verifiedDomains: json(org.verified_domains, []), pendingDomains: Object.keys(json(org.domain_tokens))
  };
}
const writer = (org, wallet) => { const m = get('select role from org_members where org_id = ? and wallet = ?', org.id, wallet); if (!m || m.role === 'member') throw new HttpError(403, 'Only organisation admins can change this.'); };

route('GET', '/api/org', ctx => { const { org } = requireOrg(ctx); return orgView(org); });
route('PATCH', '/api/org', ctx => {
  const { org, wallet } = requireOrg(ctx); writer(org, wallet);
  run('update orgs set name = ? where id = ?', String(ctx.body.name || org.name).slice(0, 80), org.id);
  return orgView(get('select * from orgs where id = ?', org.id));
});
route('POST', '/api/org/members', ctx => {
  const { org, wallet } = requireOrg(ctx); writer(org, wallet);
  if (!isValidPubkey(String(ctx.body.wallet || ''))) throw bad("That isn't a valid Solana wallet address.");
  if (get('select count(*) c from org_members where org_id = ?', org.id).c >= 25) throw bad('Organisations can have up to 25 members.');
  const role = ctx.body.role === 'admin' ? 'admin' : 'member';
  if (role === 'admin' && wallet !== org.owner) throw new HttpError(403, 'Only the organisation owner can add admins.');
  run('insert or ignore into org_members(org_id, wallet, role) values(?,?,?)', org.id, ctx.body.wallet, role);
  audit('org_member_added', { wallet: ctx.body.wallet, role }, { actor: wallet, subject: 'org:' + org.id });
  return orgView(org);
});
route('DELETE', '/api/org/members/:wallet', ctx => {
  const { org, wallet } = requireOrg(ctx); writer(org, wallet);
  if (ctx.params.wallet === org.owner) throw bad("The owner can't be removed.");
  const target = get('select role from org_members where org_id = ? and wallet = ?', org.id, ctx.params.wallet);
  if (target?.role === 'admin' && wallet !== org.owner) throw new HttpError(403, 'Only the organisation owner can remove an admin.');
  run('delete from org_members where org_id = ? and wallet = ?', org.id, ctx.params.wallet);
  audit('org_member_removed', { wallet: ctx.params.wallet }, { actor: wallet, subject: 'org:' + org.id });
  return orgView(org);
});
route('POST', '/api/org/channels', ctx => {
  const { org, wallet } = requireOrg(ctx); writer(org, wallet);
  run('insert into channels(subject, alert_email) values(?,?) on conflict(subject) do update set alert_email = excluded.alert_email', 'org:' + org.id, ctx.body.email ? normalizeEmail(ctx.body.email) : null);
  return orgView(org);
});
route('POST', '/api/org/telegram-link', ctx => {
  const { org, wallet } = requireOrg(ctx); writer(org, wallet);
  if (!config.telegram.token || !config.telegram.username) throw new HttpError(503, 'Telegram alerts are not switched on yet.');
  const code = 'o' + randomToken(9).replace(/[^A-Za-z0-9]/g, '');
  run('insert into channels(subject, link_code) values(?,?) on conflict(subject) do update set link_code = excluded.link_code', 'org:' + org.id, code);
  return { url: `https://t.me/${config.telegram.username}?startgroup=${code}`, dm: `https://t.me/${config.telegram.username}?start=${code}` };
});
route('GET', '/api/org/alerts', ctx => {
  const { org } = requireOrg(ctx);
  return { alerts: all('select id, severity, type, title, what, did, move, data, created_at, acked_at from alerts where subject = ? order by id desc limit 100', 'org:' + org.id).map(a => ({ ...a, data: json(a.data) })) };
});

/* ================= Risk Screening ================= */
route('GET', '/api/org/keys', ctx => {
  const { org } = requireOrg(ctx, 'screening');
  return { keys: all('select prefix, label, created_at, last_used, revoked from api_keys where org_id = ? order by created_at desc', org.id) };
});
route('POST', '/api/org/keys', ctx => {
  const { org, wallet } = requireOrg(ctx, 'screening'); writer(org, wallet);
  const key = 'bg_live_' + randomToken(24);
  run('insert into api_keys(key_hash, org_id, label, prefix, created_at) values(?,?,?,?,?)', sha256hex(key), org.id, String(ctx.body.label || 'API key').slice(0, 40), key.slice(0, 14), now());
  audit('api_key_created', { prefix: key.slice(0, 14) }, { actor: wallet, subject: 'org:' + org.id });
  return { key, note: 'Copy this key now. It will not be shown again.' };
});
route('DELETE', '/api/org/keys/:prefix', ctx => {
  const { org, wallet } = requireOrg(ctx, 'screening'); writer(org, wallet);
  run('update api_keys set revoked = 1 where org_id = ? and prefix = ?', org.id, ctx.params.prefix);
  audit('api_key_revoked', { prefix: ctx.params.prefix }, { actor: wallet, subject: 'org:' + org.id });
  return { ok: true };
});
async function doScreen(org, chain, address) {
  chain = String(chain || '').toLowerCase();
  if (!['solana', 'bitcoin', ...EVM_CHAINS].includes(chain)) throw bad('chain must be solana, bitcoin, ethereum, base, arbitrum, optimism, polygon or bnb.');
  const addr = normalizeAddress(chain, address);
  const r = await screen(chain, addr);
  run('insert into screen_log(org_id, chain, address, score, created_at) values(?,?,?,?,?)', org.id, chain, addr, r.score, now());
  return r;
}
route('POST', '/api/v1/screen', async ctx => {
  const org = requireApiKey(ctx, 'screening');
  rateLimit('screen:' + org.id, 120);
  return doScreen(org, ctx.body.chain, ctx.body.address);
});
route('POST', '/api/v1/screen/bulk', async ctx => {
  const org = requireApiKey(ctx, 'screening');
  const items = Array.isArray(ctx.body.items) ? ctx.body.items.slice(0, 100) : [];
  if (!items.length) throw bad('Send items: [{chain, address}] (up to 100).');
  rateLimit('screenbulk:' + org.id, 10);
  const results = [];
  for (const it of items) results.push(await doScreen(org, it.chain, it.address).catch(e => ({ chain: it.chain, address: it.address, error: e.message })));
  return { results };
});
route('POST', '/api/org/screen', async ctx => {
  const { org } = requireOrg(ctx, 'screening');
  rateLimit('screen:' + org.id, 60);
  return doScreen(org, ctx.body.chain, ctx.body.address);
});
route('GET', '/api/org/screen/log', ctx => {
  const { org } = requireOrg(ctx, 'screening');
  return { log: all('select chain, address, score, created_at from screen_log where org_id = ? order by id desc limit 200', org.id),
    usage: { today: get('select count(*) c from screen_log where org_id = ? and created_at > ?', org.id, now() - 86400).c, month: get('select count(*) c from screen_log where org_id = ? and created_at > ?', org.id, now() - 30 * 86400).c } };
});

/* ================= Guarded Wallets ================= */
function walletView(w) { return { id: w.id, name: w.name, multisig: w.multisig, vault: w.vault, members: json(w.members, []), threshold: w.threshold, timeLock: w.time_lock, policy: json(w.policy), status: w.status, createdAt: w.created_at }; }
route('GET', '/api/org/wallets', ctx => { const { org } = requireOrg(ctx, 'wallets'); return { wallets: all('select * from guarded_wallets where org_id = ? order by created_at desc', org.id).map(walletView) }; });

route('POST', '/api/org/wallets', async ctx => {
  const { org, wallet } = requireOrg(ctx, 'wallets'); writer(org, wallet);
  if (!config.solana.rpc) throw new HttpError(503, 'Solana RPC is not configured.');
  assertRoom(1);
  if (ctx.body.members != null && !Array.isArray(ctx.body.members)) throw bad('members must be a list of wallet addresses.');
  const members = [...new Set((ctx.body.members || []).map(String).filter(Boolean))];
  if (!members.length) throw bad('Add at least one member wallet.');
  if (members.some(m => !isValidPubkey(m))) throw bad('Every member must be a valid Solana wallet address.');
  if (members.length > 20) throw bad('Up to 20 members per wallet.');
  const threshold = Math.max(1, Math.min(members.length, Number(ctx.body.threshold) || 1));
  const timeLock = Math.max(0, Math.min(90 * 86400, Number(ctx.body.timeLock) || 0));
  let policy; try { policy = validatePolicy(ctx.body.policy || {}); } catch (e) { throw bad(e.message); }
  const creator = String(ctx.body.creator || wallet);
  if (!isValidPubkey(creator)) throw bad('Creator must be a Solana wallet.');
  const rpc = rpcClient(config.solana.rpc);
  const pc = await rpc.getAccountInfo(programConfigPda());
  if (!pc) throw new HttpError(502, 'Could not read the Squads program config.');
  const { treasury } = decodeProgramConfig(pc.data[0]);
  const createKey = generateKeypair();
  const { multisig, ix: createIx } = multisigCreateV2Ix({ treasury, createKey: createKey.publicKey, creator, threshold, members: members.map(k => ({ key: k, permissions: PERM.all })), timeLock, memo: `Bodyguard Guarded Wallet: ${String(ctx.body.name || '').slice(0, 40)}` });
  const { blockhash } = await rpc.getLatestBlockhash();
  const tx = buildTx({ feePayer: creator, recentBlockhash: blockhash, instructions: [ix.computeUnitPrice(20000), createIx], partialSigners: [createKey] });
  const id = 'gw_' + crypto.randomBytes(6).toString('hex');
  const vault = vaultPda(multisig, 0);
  run('insert into guarded_wallets(id, org_id, name, multisig, vault, create_key, members, threshold, time_lock, policy, status, created_at) values(?,?,?,?,?,?,?,?,?,?,?,?)',
    id, org.id, String(ctx.body.name || 'Guarded wallet').slice(0, 60), multisig, vault, createKey.publicKey, JSON.stringify(members), threshold, timeLock, JSON.stringify(policy), 'pending', now());
  return { id, multisig, vault, transaction: tx.bytes.toString('base64'), note: 'Sign and send this transaction with the creator wallet to create the smart account on-chain.' };
});

route('POST', '/api/org/wallets/:wid/confirm', async ctx => {
  const { org } = requireOrg(ctx, 'wallets');
  const w = get('select * from guarded_wallets where id = ? and org_id = ?', ctx.params.wid, org.id);
  if (!w) throw new HttpError(404, 'Wallet not found.');
  const rpc = rpcClient(config.solana.rpc);
  const acc = await rpc.getAccountInfo(w.multisig);
  if (!acc) throw bad("The smart account isn't on-chain yet. Wait a few seconds after sending and try again.");
  const ms = decodeMultisig(acc.data[0]);
  run("update guarded_wallets set status = 'active', members = ?, threshold = ? where id = ?", JSON.stringify(ms.members.map(m => m.key)), ms.threshold, w.id);
  run("insert or ignore into treasuries(id, org_id, chain, kind, address, name, policy, signers, created_at) values(?,?,?,?,?,?,?,?,?)",
    'tr_' + w.id, org.id, 'solana', 'guarded', w.multisig, w.name, w.policy, JSON.stringify(ms.members.map(m => m.key)), now());
  return walletView(get('select * from guarded_wallets where id = ?', w.id));
});

route('PATCH', '/api/org/wallets/:wid/policy', ctx => {
  const { org, wallet } = requireOrg(ctx, 'wallets'); writer(org, wallet);
  // Scope every read and write to this organisation, so one org can never touch another's wallet by guessing an ID.
  const w = get('select * from guarded_wallets where id = ? and org_id = ?', ctx.params.wid, org.id);
  if (!w) throw new HttpError(404, 'Wallet not found.');
  let policy; try { policy = validatePolicy(ctx.body.policy || {}); } catch (e) { throw bad(e.message); }
  run('update guarded_wallets set policy = ? where id = ? and org_id = ?', JSON.stringify(policy), w.id, org.id);
  run('update treasuries set policy = ? where id = ? and org_id = ?', JSON.stringify(policy), 'tr_' + w.id, org.id);
  run('insert into policy_log(org_id, wallet_id, decision, reasons, request, created_at) values(?,?,?,?,?,?)', org.id, w.id, 'policy_updated', JSON.stringify([{ text: `Policy changed by ${wallet}` }]), JSON.stringify(policy), now());
  return walletView(get('select * from guarded_wallets where id = ? and org_id = ?', w.id, org.id));
});

function checkWalletPolicy(org, wid, body) {
  const w = get('select * from guarded_wallets where id = ? and org_id = ?', wid, org.id);
  if (!w) throw new HttpError(404, 'Wallet not found.');
  const st = json(get('select state from treasuries where id = ? and org_id = ?', 'tr_' + w.id, org.id)?.state);
  const request = { chain: 'solana', to: String(body.to || ''), amount: Number(body.amount || 0), token: body.token || null, approvals: Number(body.approvals || 0), proposedAt: body.proposedAt ? Number(body.proposedAt) : null };
  if (request.to && !isValidPubkey(request.to)) throw bad('Destination must be a Solana address.');
  const result = evaluatePolicy(json(w.policy), request, st.history || []);
  // Duress Mode: while the organisation owner's time-lock runs, every payment from a guarded wallet is held.
  const lock = lockdownUntil([org.owner]);
  if (lock) { result.decision = 'timelocked'; result.reasons.unshift({ result: 'timelocked', text: `A security time-lock is active until ${new Date(lock * 1000).toUTCString()}. Payments are held until then.` }); }
  run('insert into policy_log(org_id, wallet_id, decision, reasons, request, created_at) values(?,?,?,?,?,?)', org.id, w.id, result.decision, JSON.stringify(result.reasons), JSON.stringify(request), now());
  return { walletId: w.id, vault: w.vault, ...result };
}
route('POST', '/api/org/wallets/:wid/check', ctx => { const { org } = requireOrg(ctx, 'wallets'); return checkWalletPolicy(org, ctx.params.wid, ctx.body); });
route('POST', '/api/v1/wallets/:wid/check', ctx => { const org = requireApiKey(ctx, 'wallets'); return checkWalletPolicy(org, ctx.params.wid, ctx.body); });
route('GET', '/api/org/wallets/:wid/audit', ctx => {
  const { org } = requireOrg(ctx, 'wallets');
  if (!get('select 1 from guarded_wallets where id = ? and org_id = ?', ctx.params.wid, org.id)) throw new HttpError(404, 'Wallet not found.');
  return { log: all('select decision, reasons, request, created_at from policy_log where org_id = ? and wallet_id = ? order by id desc limit 200', org.id, ctx.params.wid).map(r => ({ ...r, reasons: json(r.reasons, []), request: json(r.request) })) };
});
// API keys also work for Guarded Wallets so apps can check policy server-to-server.
route('POST', '/api/org/wallet-keys', ctx => {
  const { org, wallet } = requireOrg(ctx, 'wallets'); writer(org, wallet);
  const key = 'bg_live_' + randomToken(24);
  run('insert into api_keys(key_hash, org_id, label, prefix, created_at) values(?,?,?,?,?)', sha256hex(key), org.id, String(ctx.body.label || 'Wallets API key').slice(0, 40), key.slice(0, 14), now());
  return { key, note: 'Copy this key now. It will not be shown again.' };
});

/* ================= Treasury Watch ================= */
function treasuryView(t) { const st = json(t.state); return { id: t.id, name: t.name, chain: t.chain, kind: t.kind, address: t.address, policy: json(t.policy), signers: json(t.signers, []), threshold: st.threshold ?? null, health: st.health || 'waiting for first check', lastChecked: st.lastChecked || null, signerEmails: json(t.policy).signerEmails || [] }; }
route('GET', '/api/org/treasuries', ctx => { const { org } = requireOrg(ctx); return { treasuries: all('select * from treasuries where org_id = ? order by created_at', org.id).map(treasuryView) }; });
route('POST', '/api/org/treasuries', async ctx => {
  const { org, wallet } = requireOrg(ctx, 'treasury'); writer(org, wallet);
  const chain = String(ctx.body.chain || 'solana').toLowerCase();
  if (chain !== 'solana' && !EVM_CHAINS.includes(chain)) throw bad('Treasury Watch supports Squads on Solana and Safe on EVM chains.');
  const address = normalizeAddress(chain, ctx.body.address);
  if (get('select count(*) c from treasuries where org_id = ?', org.id).c >= 20) throw bad('Up to 20 treasuries per organisation.');
  assertRoom(1);
  let policy; try { policy = validatePolicy(ctx.body.policy || {}); } catch (e) { throw bad(e.message); }
  let signers = [];
  if (chain === 'solana') {
    if (!config.solana.rpc) throw new HttpError(503, 'Solana RPC is not configured.');
    const acc = await rpcClient(config.solana.rpc).getAccountInfo(address);
    if (!acc) throw bad('No account found at that address. Use the Squads multisig address (not the vault).');
    try { signers = decodeMultisig(acc.data[0]).members.map(m => m.key); } catch { throw bad("That address isn't a Squads v4 multisig."); }
  }
  const id = 'tr_' + crypto.randomBytes(6).toString('hex');
  run('insert into treasuries(id, org_id, chain, kind, address, name, policy, signers, created_at) values(?,?,?,?,?,?,?,?,?)', id, org.id, chain, chain === 'solana' ? 'squads' : 'safe', address, String(ctx.body.name || 'Treasury').slice(0, 60), JSON.stringify(policy), JSON.stringify(signers), now());
  return treasuryView(get('select * from treasuries where id = ?', id));
});
route('PATCH', '/api/org/treasuries/:tid', ctx => {
  const { org, wallet } = requireOrg(ctx); writer(org, wallet);
  const t = get('select * from treasuries where id = ? and org_id = ?', ctx.params.tid, org.id);
  if (!t) throw new HttpError(404, 'Treasury not found.');
  let policy; try { policy = validatePolicy(ctx.body.policy || {}); } catch (e) { throw bad(e.message); }
  run('update treasuries set policy = ?, name = coalesce(?, name) where id = ? and org_id = ?', JSON.stringify(policy), ctx.body.name ? String(ctx.body.name).slice(0, 60) : null, t.id, org.id);
  return treasuryView(get('select * from treasuries where id = ? and org_id = ?', t.id, org.id));
});
route('DELETE', '/api/org/treasuries/:tid', ctx => {
  const { org, wallet } = requireOrg(ctx); writer(org, wallet);
  const r = run("delete from treasuries where id = ? and org_id = ? and kind != 'guarded'", ctx.params.tid, org.id);
  if (!r.changes) throw new HttpError(404, 'Treasury not found.');
  return { ok: true };
});
route('POST', '/api/org/treasuries/:tid/check', ctx => {
  const { org } = requireOrg(ctx);
  const t = get('select * from treasuries where id = ? and org_id = ?', ctx.params.tid, org.id);
  if (!t) throw new HttpError(404, 'Treasury not found.');
  return evaluatePolicy(json(t.policy), { chain: t.chain, to: ctx.body.to, amount: Number(ctx.body.amount || 0), token: ctx.body.token || null, approvals: Number(ctx.body.approvals || 0) }, json(t.state).history || []);
});
