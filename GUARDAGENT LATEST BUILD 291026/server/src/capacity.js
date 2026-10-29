// Site-wide wallet cap, so the service stays inside free data-provider plans until you choose to raise it.
// Counts every wallet an active agent is watching, plus every watched treasury.
import { config } from './config.js';
import { get } from './db.js';
import { HttpError } from './http.js';
import { activeAssets } from './monitors/common.js';
import { activeTreasuries } from './monitors/treasury.js';

export function capacity(wallet = null) {
  const used = activeAssets('wallet').length + activeTreasuries().length;
  const existing = !!wallet && !!(get('select 1 from members where wallet = ? limit 1', wallet) || get('select 1 from org_members where wallet = ? limit 1', wallet));
  if (!config.maxWallets) return { limited: false, max: null, used, free: null, open: true, existing };
  const free = Math.max(0, config.maxWallets - used);
  // New customers are only taken while there is room for them to add a few wallets.
  // Existing customers can always renew or upgrade.
  return { limited: true, max: config.maxWallets, used, free, open: existing || free >= config.hireReserve, existing };
}

export function assertRoom(n = 1) {
  const c = capacity();
  if (c.limited && c.used + n > c.max) {
    console.warn(`[capacity] wallet cap of ${c.max} reached. Raise MAX_WALLETS once your data plans allow it.`);
    throw new HttpError(403, "Bodyguard is at full capacity right now, so no more wallets can be added. We're expanding soon. Please try again later.");
  }
}
