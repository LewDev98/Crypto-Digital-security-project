// Prices (pricing.json) and what each rank is allowed to protect.
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';

const pricing = JSON.parse(fs.readFileSync(path.join(config.root, 'pricing.json'), 'utf8'));
export const RANKS = pricing.ranks;
export const SERVICES = pricing.services;
export const RANK_ORDER = ['sentry', 'guardian', 'detail'];
export const ALL_CHAINS = ['solana', 'ethereum', 'bitcoin', 'base', 'arbitrum', 'optimism', 'polygon', 'bnb'];
export const EVM_CHAINS = ['ethereum', 'base', 'arbitrum', 'optimism', 'polygon', 'bnb'];

export const LIMITS = {
  sentry:   { wallets: 3,   chains: ['solana', 'ethereum', 'bitcoin'], emails: 2,  domains: 0,  handles: 0,  seats: 1,
              inbox: true, exchangeNotices: false, leaks: false, push: false, impersonation: false, priority: false },
  guardian: { wallets: 15,  chains: ALL_CHAINS, emails: 5,  domains: 3,  handles: 5,  seats: 1,
              inbox: true, exchangeNotices: true,  leaks: true,  push: true,  impersonation: false, priority: false },
  detail:   { wallets: 100, chains: ALL_CHAINS, emails: 25, domains: 25, handles: 25, seats: 5,
              inbox: true, exchangeNotices: true,  leaks: true,  push: true,  impersonation: true,  priority: true }
};

export const isPriced = item => !!item && (item.sol != null || item.usdc != null) && item.guard != null;
export const priceOf = (kind, id) => (kind === 'rank' ? RANKS[id] : kind === 'service' ? SERVICES[id] : null);
