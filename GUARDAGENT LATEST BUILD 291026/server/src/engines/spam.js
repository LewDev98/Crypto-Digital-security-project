// Spam sweep: finds junk tokens, fake copies of real tokens, scam cNFTs and empty token accounts, then builds
// transactions that burn them and close the accounts so the rent comes back. The user signs them all at once.
import { config } from '../config.js';
import { get, run, now, json } from '../db.js';
import { rpcClient, ix, buildTx, findProgramAddress, anchorDisc, PROGRAMS, toBytes, b58decode, u64le, u32le } from '../lib/solana.js';

// Canonical mints for the tokens scammers copy most. A token using one of these symbols with a different mint is fake.
export const CANONICAL = {
  USDC: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  USDT: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
  JUP: 'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN',
  BONK: 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263',
  WIF: 'EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm',
  MSOL: 'mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So',
  JITOSOL: 'J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn',
  RAY: '4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R',
  PYTH: 'HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3',
  JTO: 'jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL',
  SOL: 'So11111111111111111111111111111111111111112',
  WSOL: 'So11111111111111111111111111111111111111112'
};
const CANON_MINTS = new Set(Object.values(CANONICAL));
const verifiedSafe = it => it.kind !== 'empty' && (CANON_MINTS.has(it.mint) || verifiedCache.set.has(it.mint)); // empty accounts hold nothing, so closing them is always safe
const URLISH = /(https?:\/\/|www\.|\b[a-z0-9-]{2,}\.(com|io|xyz|app|net|org|site|online|top|live|fun|gift|claim|win|pro|info|click|link|to|me|gg|cc|ws|vip|club|tech|ai|cash|finance|exchange|example)\b)/i;
const BAIT = /\b(claim|airdrop|reward|rewards|voucher|eligible|redeem|bonus|free\s*mint|giveaway|visit|winner|prize|verify|activate|unlock|ticket|whitelist)\b/i;
const RENT = 2039280; // lamports in a standard token account

let verifiedCache = { at: 0, set: new Set() };
async function verifiedMints() {
  if (now() - verifiedCache.at < 86400 && verifiedCache.set.size) return verifiedCache.set;
  try {
    const r = await fetch(config.lists.jupiterVerified, { signal: AbortSignal.timeout(20000) });
    const j = await r.json();
    const arr = Array.isArray(j) ? j : j.tokens || j.data || [];
    verifiedCache = { at: now(), set: new Set(arr.map(t => t.id || t.address || t.mint).filter(Boolean)) };
  } catch { verifiedCache.at = now() - 86400 + 3600; }
  CANON_MINTS.forEach(m => verifiedCache.set.add(m));
  return verifiedCache.set;
}

export function classify(item, verified = new Set()) {
  const text = `${item.name || ''} ${item.symbol || ''} ${item.description || ''}`;
  const sym = String(item.symbol || '').toUpperCase().replace(/[^A-Z]/g, '');
  if (item.kind === 'empty') return { spam: true, why: 'Empty account', reason: 'Holds no tokens but locks your rent' };
  if (verified.has(item.mint) || CANON_MINTS.has(item.mint)) return { spam: false, why: 'Verified' };
  if (URLISH.test(text)) return { spam: true, why: 'Phishing link', reason: 'Its name or description points you to a website' };
  if (CANONICAL[sym] && item.mint !== CANONICAL[sym]) return { spam: true, why: 'Fake token', reason: `Copies the ${sym} name but uses a different mint` };
  if (BAIT.test(text)) return { spam: true, why: 'Airdrop spam', reason: 'Uses airdrop or reward bait' };
  if (item.kind === 'cnft' && !item.collectionVerified) return { spam: true, why: 'Unsolicited cNFT', reason: 'A compressed NFT from an unverified collection you did not ask for' };
  return { spam: false, why: 'Unverified', reason: 'Not on the verified token list' };
}

async function das(method, params) {
  const r = await fetch(config.solana.das, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 'bg', method, params }), signal: AbortSignal.timeout(30000) });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

export async function scanWallet(owner) {
  const rpc = rpcClient(config.solana.rpc);
  const verified = await verifiedMints();
  const items = [];
  const accounts = new Map();
  for (const pid of [PROGRAMS.TOKEN, PROGRAMS.TOKEN_2022]) {
    for (const t of await rpc.getTokenAccounts(owner, pid)) {
      const i = t.account.data.parsed.info;
      accounts.set(t.pubkey, { account: t.pubkey, mint: i.mint, amount: i.tokenAmount.amount, decimals: i.tokenAmount.decimals, ui: i.tokenAmount.uiAmountString, program: pid, lamports: t.account.lamports, delegate: i.delegate || null, state: i.state });
    }
  }
  const meta = new Map();
  let dasOk = true;
  try {
    for (let page = 1; page <= 5; page++) {
      const res = await das('getAssetsByOwner', { ownerAddress: owner, page, limit: 1000, displayOptions: { showFungible: true, showUnverifiedCollections: true } });
      for (const a of res.items || []) {
        const md = a.content?.metadata || {};
        const coll = (a.grouping || []).find(g => g.group_key === 'collection');
        const entry = { name: md.name, symbol: md.symbol || a.token_info?.symbol, description: md.description, image: a.content?.links?.image, collectionVerified: !!(coll && coll.verified !== false && a.creators?.some(c => c.verified)) };
        if (a.compression?.compressed) {
          const it = { id: a.id, kind: 'cnft', mint: a.id, name: entry.name || 'Compressed NFT', symbol: entry.symbol, description: entry.description, collectionVerified: entry.collectionVerified, amount: '1', rent: 0, tree: a.compression.tree };
          items.push({ ...it, ...classify(it, verified) });
        } else meta.set(a.id, entry);
      }
      if (!res.items || res.items.length < 1000) break;
    }
  } catch { dasOk = false; }

  for (const acc of accounts.values()) {
    const m = meta.get(acc.mint) || {};
    const empty = acc.amount === '0';
    const it = { id: acc.account, kind: empty ? 'empty' : 'token', mint: acc.mint, name: m.name || (empty ? 'Empty token account' : short(acc.mint)), symbol: m.symbol, description: m.description, amount: acc.ui, rawAmount: acc.amount, decimals: acc.decimals, program: acc.program, rent: acc.lamports, delegate: acc.delegate, frozen: acc.state === 'frozen' };
    const c = classify(it, verified);
    if (it.frozen) Object.assign(c, { spam: false, why: 'Frozen', reason: 'Frozen by its issuer, so it cannot be burnt' });
    items.push({ ...it, ...c });
  }
  const spam = items.filter(i => i.spam);
  return {
    owner, dasAvailable: dasOk, items,
    summary: { junk: spam.length, rentLamports: spam.reduce((s, i) => s + (i.rent || 0), 0), cnfts: spam.filter(i => i.kind === 'cnft').length }
  };
}

/* ---------------- sweep transactions ---------------- */
function treeCanopyDepth(data) {
  const maxBuffer = data.readUInt32LE(2), maxDepth = data.readUInt32LE(6);
  const treeSize = 24 + maxBuffer * (32 + 32 * maxDepth + 8) + (32 * maxDepth + 32 + 8);
  const canopyBytes = data.length - 56 - treeSize;
  const nodes = Math.max(0, Math.floor(canopyBytes / 32));
  return { maxDepth, canopyDepth: nodes > 0 ? Math.log2(nodes + 2) - 1 : 0 };
}

export async function cnftBurnIx(owner, assetId, rpc) {
  const asset = await das('getAsset', { id: assetId });
  const proof = await das('getAssetProof', { id: assetId });
  if (asset.ownership?.owner !== owner) throw new Error('not owned by this wallet');
  const tree = asset.compression.tree;
  const info = await rpc.getAccountInfo(tree);
  if (!info) throw new Error('tree not found');
  if (info.owner !== PROGRAMS.SPL_COMPRESSION) throw new Error('this cNFT uses a newer tree format that cannot be burnt here yet');
  const { maxDepth, canopyDepth } = treeCanopyDepth(Buffer.from(info.data[0], 'base64'));
  const path = (proof.proof || []).slice(0, Math.max(0, proof.proof.length - canopyDepth));
  const [treeAuthority] = findProgramAddress([toBytes(tree)], PROGRAMS.BUBBLEGUM);
  const delegate = asset.ownership.delegate || owner;
  const index = proof.node_index - 2 ** maxDepth;
  const data = Buffer.concat([anchorDisc('burn'), Buffer.from(b58decode(proof.root)), Buffer.from(b58decode(asset.compression.data_hash.trim())),
    Buffer.from(b58decode(asset.compression.creator_hash.trim())), u64le(asset.compression.leaf_id), u32le(index)]);
  return {
    programId: PROGRAMS.BUBBLEGUM,
    keys: [
      { pubkey: treeAuthority, isSigner: false, isWritable: false },
      { pubkey: owner, isSigner: true, isWritable: false },
      { pubkey: delegate, isSigner: false, isWritable: false },
      { pubkey: tree, isSigner: false, isWritable: true },
      { pubkey: PROGRAMS.SPL_NOOP, isSigner: false, isWritable: false },
      { pubkey: PROGRAMS.SPL_COMPRESSION, isSigner: false, isWritable: false },
      { pubkey: PROGRAMS.SYSTEM, isSigner: false, isWritable: false },
      ...path.map(p => ({ pubkey: p, isSigner: false, isWritable: false }))
    ],
    data
  };
}

// Only items the scan itself judged to be junk can be burnt. Whatever the browser sends, a verified or canonical
// token (USDC, SOL, JUP…) or anything not flagged is never put in a burn transaction.
export function pickSweepItems(items, ids) {
  const byId = new Map(items.map(i => [i.id, i]));
  const chosen = [], skipped = [];
  for (const id of [...new Set(ids.map(String))]) {
    const it = byId.get(id);
    if (!it) skipped.push({ id, reason: 'No longer in this wallet' });
    else if (!it.spam || verifiedSafe(it)) skipped.push({ id, reason: 'Not junk, so it was left alone' });
    else chosen.push(it);
  }
  return { chosen, skipped };
}

export async function buildSweep(owner, ids) {
  const rpc = rpcClient(config.solana.rpc);
  const scan = await scanWallet(owner);
  const { chosen, skipped } = pickSweepItems(scan.items, ids);
  const { blockhash } = await rpc.getLatestBlockhash();
  const txs = [];
  const tokens = chosen.filter(i => i.kind === 'token' || i.kind === 'empty');
  for (let i = 0; i < tokens.length; i += 6) {
    const chunk = tokens.slice(i, i + 6);
    const ins = [ix.computeUnitLimit(40000 * chunk.length + 20000), ix.computeUnitPrice(20000)];
    for (const t of chunk) {
      if (t.frozen) { skipped.push({ id: t.id, reason: 'Frozen by its issuer' }); continue; }
      if (t.kind === 'token' && BigInt(t.rawAmount) > 0n) ins.push(ix.burnChecked(t.id, t.mint, owner, BigInt(t.rawAmount), t.decimals, t.program));
      ins.push(ix.closeAccount(t.id, owner, owner, t.program));
    }
    if (ins.length > 2) txs.push({ items: chunk.map(c => c.id), rent: chunk.reduce((s, c) => s + (c.rent || 0), 0), tx: buildTx({ feePayer: owner, recentBlockhash: blockhash, instructions: ins }).bytes });
  }
  for (const c of chosen.filter(i => i.kind === 'cnft')) {
    try {
      const burn = await cnftBurnIx(owner, c.id, rpc);
      const t = buildTx({ feePayer: owner, recentBlockhash: blockhash, instructions: [ix.computeUnitPrice(20000), burn] }).bytes;
      if (t.length > 1232) { skipped.push({ id: c.id, reason: 'Proof too large to burn in one transaction' }); continue; }
      txs.push({ items: [c.id], rent: 0, tx: t });
    } catch (e) { skipped.push({ id: c.id, reason: e.message }); }
  }
  // Simulate each one; drop anything that would fail so the wallet never shows a doomed transaction.
  const ok = [];
  for (const t of txs) {
    try {
      const sim = await rpc.simulate(t.tx.toString('base64'));
      if (sim.value.err) { t.items.forEach(id => skipped.push({ id, reason: 'Would fail on-chain (often a token with special rules)' })); continue; }
    } catch {}
    ok.push({ items: t.items, rent: t.rent, tx: t.tx.toString('base64') });
  }
  return { transactions: ok, skipped, rentLamports: ok.reduce((s, t) => s + t.rent, 0) };
}

const short = a => (a ? `${a.slice(0, 4)}…${a.slice(-4)}` : '');
