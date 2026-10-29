// Loads .env (if present) and exposes typed settings. Every service switches on only when its keys exist.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envFile = path.join(ROOT, '.env');
if (fs.existsSync(envFile) && process.env.BG_NO_DOTENV !== '1') {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (!m || line.trim().startsWith('#')) continue;
    let v = m[2];
    if (!/^["']/.test(v)) v = v.replace(/\s+#.*$/, '').trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    if (process.env[m[1]] === undefined) process.env[m[1]] = v;
  }
}
const e = (k, d = '') => (process.env[k] ?? d).trim();
const n = (k, d) => { const v = Number(e(k, String(d))); return Number.isFinite(v) ? v : d; };
const list = k => e(k).split(',').map(s => s.trim()).filter(Boolean);

export const config = {
  root: ROOT,
  port: n('PORT', 8080),
  publicUrl: e('PUBLIC_URL', 'http://localhost:8080').replace(/\/$/, ''),
  appSecret: e('APP_SECRET'),
  dataDir: path.resolve(ROOT, e('DATA_DIR', './data')),
  webDir: path.resolve(ROOT, e('WEB_DIR', '../web')),
  corsOrigins: list('CORS_ORIGINS'),
  adminWallets: list('ADMIN_WALLETS'),

  solana: {
    rpc: e('SOLANA_RPC_URL'),
    das: e('DAS_RPC_URL') || e('SOLANA_RPC_URL'),
    guardMint: e('GUARD_MINT'),
    treasury: e('TREASURY_WALLET'),
    usdcMint: e('USDC_MINT', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'),
    pollSeconds: n('SOLANA_POLL_SECONDS', 45)
  },
  helius: { key: e('HELIUS_API_KEY'), secret: e('HELIUS_WEBHOOK_SECRET') },
  // Total wallets the whole service will watch (all customers, all chains, plus treasuries). 0 = no limit.
  maxWallets: n('MAX_WALLETS', 50),
  // New customers can only hire while at least this many wallet slots are free.
  hireReserve: n('HIRE_RESERVE', 5),
  rankDays: n('RANK_DAYS', 30),
  serviceDays: n('SERVICE_DAYS', 30),

  evm: {
    ethereum: { chainId: 1, rpc: e('RPC_ETHEREUM'), name: 'Ethereum', explorer: 'https://etherscan.io' },
    base: { chainId: 8453, rpc: e('RPC_BASE'), name: 'Base', explorer: 'https://basescan.org' },
    arbitrum: { chainId: 42161, rpc: e('RPC_ARBITRUM'), name: 'Arbitrum', explorer: 'https://arbiscan.io' },
    optimism: { chainId: 10, rpc: e('RPC_OPTIMISM'), name: 'Optimism', explorer: 'https://optimistic.etherscan.io' },
    polygon: { chainId: 137, rpc: e('RPC_POLYGON'), name: 'Polygon', explorer: 'https://polygonscan.com' },
    bnb: { chainId: 56, rpc: e('RPC_BNB'), name: 'BNB Chain', explorer: 'https://bscscan.com' }
  },
  evmPollSeconds: n('EVM_POLL_SECONDS', 60),
  evmMaxBlockRange: n('EVM_MAX_BLOCK_RANGE', 2000),
  // Native-coin balance checks. Token moves and approvals are still caught every EVM_POLL_SECONDS.
  evmBalanceSeconds: n('EVM_BALANCE_SECONDS', 600),
  etherscanKey: e('ETHERSCAN_API_KEY'),
  btcApi: e('BTC_API', 'https://mempool.space/api').replace(/\/$/, ''),

  hibpKey: e('HIBP_API_KEY'),
  githubToken: e('GITHUB_TOKEN'),
  google: { id: e('GOOGLE_CLIENT_ID'), secret: e('GOOGLE_CLIENT_SECRET') },
  microsoft: { id: e('MS_CLIENT_ID'), secret: e('MS_CLIENT_SECRET'), tenant: e('MS_TENANT', 'common') },

  telegram: { token: e('TELEGRAM_BOT_TOKEN'), username: e('TELEGRAM_BOT_USERNAME') },
  resend: { key: e('RESEND_API_KEY'), from: e('ALERT_FROM_EMAIL', 'Bodyguard <alerts@example.com>'), drillFrom: e('DRILL_FROM_EMAIL'),
    freezeFrom: e('FREEZE_FROM_EMAIL') || e('ALERT_FROM_EMAIL', 'Bodyguard <alerts@example.com>'),
    supportFrom: e('SUPPORT_FROM_EMAIL') || e('ALERT_FROM_EMAIL', 'Bodyguard <alerts@example.com>') },
  // Where help-desk tickets are delivered. Replies from the admin console go out from SUPPORT_FROM_EMAIL.
  supportEmail: e('SUPPORT_EMAIL'),
  xHandle: e('X_HANDLE', 'GuardagentWeb3').replace(/^@/, ''),
  vapid: { publicKey: e('VAPID_PUBLIC_KEY'), privateKey: e('VAPID_PRIVATE_KEY'), subject: e('VAPID_SUBJECT', 'mailto:security@example.com') },
  ai: { key: e('ANTHROPIC_API_KEY'), model: e('ANTHROPIC_MODEL', 'claude-sonnet-5-5') },
  safe: { base: e('SAFE_API_BASE', 'https://safe-transaction-mainnet.safe.global').replace(/\/$/, ''), key: e('SAFE_API_KEY') },

  lists: {
    ofacBase: e('OFAC_LIST_BASE', 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists'),
    metamaskPhishing: e('PHISHING_LIST_URL', 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json'),
    phantomBlocklist: e('PHANTOM_BLOCKLIST_URL', 'https://raw.githubusercontent.com/phantom/blocklist/master/blocklist.yaml'),
    jupiterVerified: e('JUP_VERIFIED_URL', 'https://lite-api.jup.ag/tokens/v2/tag?query=verified')
  }
};

export function assertConfig() {
  const warn = [];
  if (!config.appSecret || config.appSecret.length < 32) throw new Error('APP_SECRET must be set to a random string of at least 32 characters');
  if (!config.solana.rpc) warn.push('SOLANA_RPC_URL not set: payments, Solana monitoring and the sweep are off');
  if (!config.solana.guardMint || !config.solana.treasury) warn.push('GUARD_MINT / TREASURY_WALLET not set: payments are off');
  if (config.helius.key && config.helius.secret && config.helius.secret.length < 24) warn.push('HELIUS_WEBHOOK_SECRET is short and guessable. Use 32+ random characters so nobody can push fake transactions to /hooks/helius');
  if (!config.supportEmail) warn.push('SUPPORT_EMAIL not set: help tickets are stored and visible to admins, but not emailed to a support inbox');
  if (config.publicUrl.startsWith('http://') && !/localhost|127\.0\.0\.1/.test(config.publicUrl)) warn.push('PUBLIC_URL is not https: sign-in tokens and alerts would travel unencrypted');
  return warn;
}
