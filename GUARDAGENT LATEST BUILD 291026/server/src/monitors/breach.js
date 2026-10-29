// Breach radar (Have I Been Pwned) for every email, plus paste-site exposure for ranks with leak watch.
import { config } from '../config.js';
import { now } from '../db.js';
import { LIMITS } from '../plans.js';
import { activeAssets, stateOf, saveState } from './common.js';
import { raiseAgent } from '../alerts.js';
import { sleep } from '../lib/solana.js';

const HIBP = 'https://haveibeenpwned.com/api/v3';
async function hibp(path) {
  for (let i = 0; i < 3; i++) {
    const r = await fetch(HIBP + path, { headers: { 'hibp-api-key': config.hibpKey, 'user-agent': 'Bodyguard-Agents' }, signal: AbortSignal.timeout(20000) });
    if (r.status === 404) return [];
    if (r.status === 429) { await sleep((Number(r.headers.get('retry-after')) || 6) * 1000); continue; }
    if (!r.ok) throw new Error('hibp ' + r.status);
    return r.json();
  }
  throw new Error('hibp rate limited');
}

export async function pollBreaches() {
  if (!config.hibpKey) return;
  for (const asset of activeAssets('email')) {
    const st = stateOf(asset);
    if (st.breachCheckedAt && now() - st.breachCheckedAt < 86400) continue;
    try {
      const breaches = await hibp(`/breachedaccount/${encodeURIComponent(asset.value)}?truncateResponse=false`);
      const known = new Set(st.breaches || []);
      const fresh = breaches.filter(b => !known.has(b.Name));
      if (!st.breachBaseline && breaches.length) {
        const latest = [...breaches].sort((a, b) => (b.BreachDate || '').localeCompare(a.BreachDate || ''))[0];
        await raiseAgent(asset.agent_id, { severity: 'med', type: 'breach_history', dedupe: `bh:${asset.id}`, title: `Your email is in ${breaches.length} known breach${breaches.length > 1 ? 'es' : ''}`,
          what: `${asset.value} appears in ${breaches.length} past data breach${breaches.length > 1 ? 'es' : ''}, most recently ${latest.Title} (${latest.BreachDate}).`,
          did: 'Recorded them so you only hear about new ones from now on.',
          move: 'Change any password you used on those sites, and never reuse it on an exchange or your email account.',
          data: { breaches: breaches.map(b => ({ name: b.Title, date: b.BreachDate, data: b.DataClasses })) } });
      } else for (const b of fresh) {
        const pw = (b.DataClasses || []).some(d => /password/i.test(d));
        await raiseAgent(asset.agent_id, { severity: pw ? 'high' : 'med', type: 'breach_new', dedupe: `bn:${asset.id}:${b.Name}`, title: `New breach: ${b.Title}`,
          what: `${asset.value} was found in the ${b.Title} breach${b.BreachDate ? ` (${b.BreachDate})` : ''}. Exposed: ${(b.DataClasses || []).slice(0, 6).join(', ')}.`,
          did: 'Matched it against your briefing the day it was published.',
          move: pw ? 'Change that password everywhere you used it, starting with your email and exchange accounts, and turn on app-based 2FA.' : 'Expect targeted phishing to this email and treat unexpected "security" messages with suspicion.',
          data: { breach: b.Name, domain: b.Domain, date: b.BreachDate, classes: b.DataClasses } });
      }
      st.breaches = breaches.map(b => b.Name); st.breachBaseline = true; st.breachCheckedAt = now();
      if (LIMITS[asset.rank]?.leaks) {
        await sleep(1700);
        const pastes = await hibp(`/pasteaccount/${encodeURIComponent(asset.value)}`).catch(() => []);
        const seenP = new Set(st.pastes || []);
        for (const p of pastes) {
          const id = `${p.Source}:${p.Id}`;
          if (seenP.has(id) || !st.pasteBaseline) continue;
          await raiseAgent(asset.agent_id, { severity: 'high', type: 'leak_paste', dedupe: `paste:${asset.id}:${id}`, title: 'Your email turned up in a leak dump',
            what: `${asset.value} was posted on ${p.Source}${p.Title ? ` in "${p.Title}"` : ''}${p.Date ? ` on ${p.Date.slice(0, 10)}` : ''}, alongside ${p.EmailCount || 'other'} emails.`,
            did: 'Caught it on the paste-site watch.', move: 'Change the password for this email and anything that shares it. Watch for targeted phishing.' });
        }
        st.pastes = pastes.map(p => `${p.Source}:${p.Id}`).slice(-300); st.pasteBaseline = true;
      }
      st.health = 'ok';
      saveState(asset, st);
    } catch (e) { st.health = 'error: ' + e.message.slice(0, 80); saveState(asset, st); }
    await sleep(1700);
  }
}
