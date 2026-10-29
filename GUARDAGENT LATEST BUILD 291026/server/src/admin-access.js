// Wallets in ADMIN_WALLETS get free, non-expiring access to everything: a Security Detail agent and every
// business service. Runs at startup. If a wallet is removed from ADMIN_WALLETS, its free access ends.
import crypto from 'node:crypto';
import { config } from './config.js';
import { run, get, all, now, json, tx } from './db.js';
import { SERVICES } from './plans.js';

const TOP_RANK = 'detail';

export function ensureAdminAccess() {
  const admins = new Set(config.adminWallets);
  tx(() => {
    for (const wallet of admins) {
      // Agent: top rank, never expires.
      const a = get('select * from agents where owner = ? order by created_at limit 1', wallet);
      if (a) {
        const s = json(a.settings);
        if (!s.comp) s.compPrev = { rank: a.rank, expires_at: a.expires_at };
        s.comp = true;
        run("update agents set rank = ?, status = 'active', expires_at = null, settings = ? where id = ?", TOP_RANK, JSON.stringify(s), a.id);
      } else {
        let id;
        do { id = 'G-' + String(crypto.randomInt(0, 10000)).padStart(4, '0'); } while (get('select 1 from agents where id = ?', id));
        run("insert into agents(id, owner, rank, status, created_at, expires_at, settings) values(?,?,?,'active',?,null,?)", id, wallet, TOP_RANK, now(), JSON.stringify({ comp: true }));
        run("insert or ignore into members(agent_id, wallet, role) values(?,?,'owner')", id, wallet);
      }
      // Organisation: every business service, never expires.
      let org = get('select * from orgs where owner = ?', wallet);
      if (!org) {
        const oid = 'org_' + crypto.randomBytes(6).toString('hex');
        run("insert into orgs(id, owner, name, created_at) values(?,?,'Bodyguard HQ',?)", oid, wallet, now());
        run("insert or ignore into org_members(org_id, wallet, role) values(?,?,'owner')", oid, wallet);
        org = get('select * from orgs where id = ?', oid);
      }
      const services = json(org.services);
      for (const s of Object.keys(SERVICES)) services[s] = { ...(services[s] || {}), since: services[s]?.since || now(), expires: null, comp: true };
      run('update orgs set services = ? where id = ?', JSON.stringify(services), org.id);
    }

    // Free access that no longer belongs to an admin: give back what they had paid for, or switch it off.
    for (const a of all('select * from agents')) {
      const s = json(a.settings);
      if (!s.comp || admins.has(a.owner)) continue;
      const prev = s.compPrev;
      delete s.comp; delete s.compPrev;
      run('update agents set rank = ?, expires_at = ?, settings = ? where id = ?', prev?.rank || a.rank, prev ? prev.expires_at : now(), JSON.stringify(s), a.id);
    }
    for (const o of all('select * from orgs')) {
      if (admins.has(o.owner)) continue;
      const services = json(o.services);
      let changed = false;
      for (const k of Object.keys(services)) if (services[k]?.comp) { services[k] = { ...services[k], expires: now(), comp: false }; changed = true; }
      if (changed) run('update orgs set services = ? where id = ?', JSON.stringify(services), o.id);
    }
  });
  if (admins.size) console.log(`[admin] free full access for ${admins.size} admin wallet(s)`);
}
