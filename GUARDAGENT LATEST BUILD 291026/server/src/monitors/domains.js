// Domain watch: DNS records (A, AAAA, NS, MX, TXT, CNAME), registrar and lock status via RDAP, expiry,
// TLS certificate expiry and issuer changes, and lookalike domains via certificate transparency.
// Security Details also get typo-squat detection (registered variants of your name).
import dns from 'node:dns/promises';
import tls from 'node:tls';
import { now } from '../db.js';
import { LIMITS } from '../plans.js';
import { activeAssets, stateOf, saveState } from './common.js';
import { raiseAgent } from '../alerts.js';
import { isPhishingDomain } from '../engines/lists.js';

const resolver = new dns.Resolver({ timeout: 5000, tries: 2 });
import { isPrivateIp } from '../lib/net.js';
export { isPrivateIp };
async function snapshot(d) {
  const q = async fn => { try { return (await fn()).map(x => (typeof x === 'string' ? x : Array.isArray(x) ? x.join('') : x.exchange ? `${x.priority} ${x.exchange}` : JSON.stringify(x))).sort(); } catch (e) { return e.code === 'ENODATA' || e.code === 'ENOTFOUND' ? [] : null; } };
  return { A: await q(() => resolver.resolve4(d)), AAAA: await q(() => resolver.resolve6(d)), NS: await q(() => resolver.resolveNs(d)), MX: await q(() => resolver.resolveMx(d)), TXT: await q(() => resolver.resolveTxt(d)), CNAME: await q(() => resolver.resolveCname(d)) };
}
const SEV = { A: 'crit', AAAA: 'crit', NS: 'crit', CNAME: 'high', MX: 'high', TXT: 'med' };
const WHY = { A: 'Visitors to your site may now reach a different server.', AAAA: 'Visitors to your site may now reach a different server.', NS: 'Someone may have taken over who answers for your domain.',
  CNAME: 'Your domain now points somewhere else.', MX: 'Email for your domain may now go to a different provider.', TXT: 'Verification or email-security records changed.' };

export async function pollDns() {
  for (const asset of activeAssets('domain')) {
    const st = stateOf(asset);
    try {
      const snap = await snapshot(asset.value);
      if (st.dns) {
        for (const k of Object.keys(snap)) {
          if (snap[k] === null || st.dns[k] == null) continue;
          const before = st.dns[k].join(', '), after = snap[k].join(', ');
          if (before !== after) await raiseAgent(asset.agent_id, { severity: SEV[k], type: 'dns_change', dedupe: `dns:${asset.id}:${k}:${after}`, title: `${k} record changed on ${asset.value}`,
            what: `${k} for ${asset.value} changed from ${before || 'nothing'} to ${after || 'nothing'}. ${WHY[k]}`,
            did: 'Compared it with the last known-good snapshot taken a few minutes ago.',
            move: "If your team didn't make this change, log in to your registrar now, lock the domain, restore the record and change the registrar password.",
            data: { domain: asset.value, record: k, before: st.dns[k], after: snap[k] } });
        }
      }
      st.dns = Object.fromEntries(Object.entries(snap).map(([k, v]) => [k, v ?? st.dns?.[k] ?? null]));
      st.health = 'ok';
      saveState(asset, st);
    } catch (e) { st.health = 'error: ' + e.message.slice(0, 80); saveState(asset, st); }
  }
}

async function rdap(domain) {
  const r = await fetch(`https://rdap.org/domain/${domain}`, { headers: { accept: 'application/rdap+json' }, redirect: 'follow', signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error('rdap ' + r.status);
  const j = await r.json();
  const ev = n => j.events?.find(e => e.eventAction === n)?.eventDate || null;
  const reg = (j.entities || []).find(e => (e.roles || []).includes('registrar'));
  const regName = reg?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || reg?.handle || null;
  return { status: j.status || [], expires: ev('expiration'), registrar: regName, updated: ev('last changed') };
}
// Connects to an address we resolved and checked ourselves, so DNS can't be switched to an internal address
// between the check and the connection (DNS rebinding).
async function cert(domain) {
  let ip;
  try { ip = (await resolver.resolve4(domain))[0]; } catch { return null; }
  if (!ip || isPrivateIp(ip)) return null;
  return new Promise(resolve => {
    const s = tls.connect({ host: ip, port: 443, servername: domain, timeout: 8000, rejectUnauthorized: false }, () => {
      const c = s.getPeerCertificate(); s.end();
      resolve(c && c.valid_to ? { validTo: new Date(c.valid_to).getTime() / 1000, issuer: c.issuer?.O || c.issuer?.CN || '', fingerprint: c.fingerprint256 } : null);
    });
    s.on('error', () => resolve(null)); s.on('timeout', () => { s.destroy(); resolve(null); });
  });
}
function variants(name) {
  const [label, ...rest] = name.split('.');
  const tld = rest.join('.');
  const out = new Set();
  const swaps = { o: '0', l: '1', i: '1', e: '3', a: '4', s: '5', m: 'rn' };
  for (let i = 0; i < label.length; i++) {
    out.add(label.slice(0, i) + label.slice(i + 1));
    out.add(label.slice(0, i) + label[i] + label.slice(i));
    if (swaps[label[i]]) out.add(label.slice(0, i) + swaps[label[i]] + label.slice(i + 1));
    if (i < label.length - 1) out.add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2));
  }
  out.add(label + '-app'); out.add(label + '-support'); out.add(label + 'app'); out.add('get' + label); out.add(label + '-claim'); out.add(label + '-airdrop');
  out.delete(label);
  const tlds = [...new Set([tld, 'com', 'io', 'xyz', 'app', 'org', 'net'])];
  return [...out].filter(v => v.length > 2).flatMap(v => tlds.map(t => `${v}.${t}`)).concat(tlds.filter(t => t !== tld).map(t => `${label}.${t}`)).slice(0, 220);
}

export async function dailyDomainChecks() {
  for (const asset of activeAssets('domain')) {
    const st = stateOf(asset);
    if (st.dailyAt && now() - st.dailyAt < 86400) continue;
    const d = asset.value;
    try {
      const r = await rdap(d).catch(() => null);
      if (r) {
        if (st.rdap) {
          const hadLock = (st.rdap.status || []).some(s => /client ?transfer ?prohibited/i.test(s));
          const hasLock = r.status.some(s => /client ?transfer ?prohibited/i.test(s));
          if (hadLock && !hasLock) await raiseAgent(asset.agent_id, { severity: 'high', type: 'domain_unlocked', dedupe: `unlock:${asset.id}:${r.updated}`, title: `Transfer lock removed from ${d}`,
            what: `${d} is no longer locked against transfer. That is the first step in moving a domain to another registrar.`, did: 'Spotted the status change in the registry.', move: 'If you did not unlock it, re-enable the lock and change your registrar password and 2FA today.' });
          if (st.rdap.registrar && r.registrar && st.rdap.registrar !== r.registrar) await raiseAgent(asset.agent_id, { severity: 'crit', type: 'registrar_change', dedupe: `reg:${asset.id}:${r.registrar}`, title: `${d} moved to a new registrar`,
            what: `The registrar for ${d} changed from ${st.rdap.registrar} to ${r.registrar}.`, did: 'Caught it in the registry data.', move: 'If this was not planned, contact your old registrar immediately and report an unauthorised transfer.' });
        }
        if (r.expires) {
          const days = Math.floor((new Date(r.expires).getTime() / 1000 - now()) / 86400);
          if (days <= 30 && days >= 0) await raiseAgent(asset.agent_id, { severity: days <= 7 ? 'high' : 'med', type: 'domain_expiry', dedupe: `exp:${asset.id}:${r.expires}:${days <= 7 ? 7 : 30}`, title: `${d} expires in ${days} days`,
            what: `${d} is registered until ${r.expires.slice(0, 10)}. Expired crypto domains get snapped up and used for phishing.`, did: 'Checked the registry expiry date.', move: 'Renew it now and turn on auto-renew.' });
        }
        st.rdap = r;
      }
      const c = await cert(d);
      if (c) {
        const days = Math.floor((c.validTo - now()) / 86400);
        if (days <= 14) await raiseAgent(asset.agent_id, { severity: days <= 3 ? 'high' : 'med', type: 'cert_expiry', dedupe: `cert:${asset.id}:${c.fingerprint}:${days <= 3 ? 3 : 14}`, title: `HTTPS certificate for ${d} expires in ${days} days`,
          what: `Visitors will see a security warning on ${d} when the certificate expires.`, did: 'Checked the live certificate.', move: 'Renew the certificate or check your auto-renewal.' });
        if (st.cert?.issuer && c.issuer && st.cert.issuer !== c.issuer) await raiseAgent(asset.agent_id, { severity: 'med', type: 'cert_issuer', dedupe: `issuer:${asset.id}:${c.fingerprint}`, title: `New certificate issuer on ${d}`,
          what: `The HTTPS certificate on ${d} is now issued by ${c.issuer} (was ${st.cert.issuer}).`, did: 'Compared it with yesterday.', move: 'If your team did not change providers, check your DNS and hosting accounts for unauthorised access.' });
        st.cert = c;
      }
      // Lookalikes via certificate transparency
      const label = d.split('.')[0];
      if (label.length >= 4) {
        const ct = await fetch(`https://crt.sh/?q=${encodeURIComponent('%' + label + '%')}&output=json&exclude=expired`, { signal: AbortSignal.timeout(40000) }).then(x => (x.ok ? x.json() : [])).catch(() => []);
        const names = new Set();
        for (const e of ct.slice(0, 2000)) for (const n of String(e.name_value || '').split('\n')) names.add(n.toLowerCase().replace(/^\*\./, ''));
        const mine = activeAssets('domain').filter(a => a.agent_id === asset.agent_id).map(a => a.value);
        const seen = new Set(st.ctSeen || []);
        const fresh = [...names].filter(n => n && !mine.some(m => n === m || n.endsWith('.' + m)) && !seen.has(n));
        if (st.ctBaseline && fresh.length) await raiseAgent(asset.agent_id, { severity: fresh.some(isPhishingDomain) ? 'high' : 'med', type: 'lookalike_domain', dedupe: `ct:${asset.id}:${fresh.slice(0, 5).join(',')}`,
          title: `${fresh.length} lookalike domain${fresh.length > 1 ? 's' : ''} just got certificates`,
          what: `New HTTPS certificates were issued for ${fresh.slice(0, 5).join(', ')}${fresh.length > 5 ? ` and ${fresh.length - 5} more` : ''}. Phishing sites need these before they go live.`,
          did: 'Found them in public certificate transparency logs.', move: 'Warn your community about these exact names and report them to your registrar and to the hosts they point at.', data: { domains: fresh.slice(0, 50) } });
        st.ctSeen = [...new Set([...seen, ...names])].slice(-3000); st.ctBaseline = true;
      }
      // Typo-squats (Security Detail)
      if (LIMITS[asset.rank]?.impersonation) {
        const reg = [];
        for (const v of variants(d)) {
          try { const ns = await resolver.resolveNs(v); if (ns.length) reg.push(v); } catch {}
        }
        const prev = new Set(st.typos || []);
        const fresh = reg.filter(v => !prev.has(v));
        if (st.typoBaseline && fresh.length) await raiseAgent(asset.agent_id, { severity: 'high', type: 'typosquat', dedupe: `typo:${asset.id}:${fresh.join(',')}`, title: `Typo-squat of ${d} registered`,
          what: `${fresh.slice(0, 6).join(', ')} ${fresh.length > 1 ? 'are' : 'is'} now registered. These are close misspellings of your domain.`, did: 'Checked hundreds of misspellings of your domain for new registrations.',
          move: 'Check what they host. If it copies your site, report it to the registrar and warn your community with the exact name.', data: { domains: fresh } });
        st.typos = reg; st.typoBaseline = true;
      }
      st.dailyAt = now();
      saveState(asset, st);
    } catch (e) { st.health = 'error: ' + e.message.slice(0, 80); saveState(asset, st); }
  }
}
export const _variants = variants;
