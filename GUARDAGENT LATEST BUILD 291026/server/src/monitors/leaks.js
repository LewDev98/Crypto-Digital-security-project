// Leak watch (Guardian and Security Detail): your emails, domains and handles turning up in public code on GitHub,
// which is how API keys, configs and seed phrases leak.
import { config } from '../config.js';
import { now } from '../db.js';
import { LIMITS } from '../plans.js';
import { activeAssets, stateOf, saveState } from './common.js';
import { raiseAgent } from '../alerts.js';
import { sleep } from '../lib/solana.js';

const SECRETISH = /(api[_-]?key|secret|private[_-]?key|seed|mnemonic|password|passwd|token|\.env)/i;

async function codeSearch(term) {
  const r = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(`"${term}"`)}&per_page=30`, {
    headers: { authorization: `Bearer ${config.githubToken}`, accept: 'application/vnd.github+json', 'user-agent': 'bodyguard-agents' }, signal: AbortSignal.timeout(20000) });
  if (r.status === 403 || r.status === 429) throw new Error('github rate limited');
  if (!r.ok) return [];
  return (await r.json()).items || [];
}

export async function pollLeaks() {
  if (!config.githubToken) return;
  const assets = [...activeAssets('email'), ...activeAssets('domain'), ...activeAssets('handle')].filter(a => LIMITS[a.rank]?.leaks);
  for (const asset of assets) {
    const st = stateOf(asset);
    if (st.leakAt && now() - st.leakAt < 86400) continue;
    try {
      const items = await codeSearch(asset.value);
      const seen = new Set(st.leakSeen || []);
      const fresh = items.filter(i => !seen.has(i.html_url));
      if (st.leakBaseline && fresh.length) {
        const risky = fresh.filter(i => SECRETISH.test(i.path) || SECRETISH.test(i.name));
        await raiseAgent(asset.agent_id, { severity: risky.length ? 'high' : 'med', type: 'leak_code', dedupe: `leak:${asset.id}:${fresh.map(f => f.sha).slice(0, 5).join(',')}`,
          title: risky.length ? 'Possible secret leak on GitHub' : `${asset.value} found in public code`,
          what: `${asset.value} appears in ${fresh.length} new public file${fresh.length > 1 ? 's' : ''} on GitHub, e.g. ${fresh.slice(0, 3).map(f => `${f.repository.full_name}/${f.path}`).join(', ')}${risky.length ? '. At least one looks like a config or key file' : ''}.`,
          did: 'Found it in a daily search of public code.', move: risky.length ? 'Open the files now. If any key, password or seed phrase is in them, rotate it immediately, then ask the repository owner (or GitHub) to remove it.' : 'Check the files to make sure nothing sensitive sits next to it.',
          data: { files: fresh.slice(0, 20).map(f => f.html_url) } });
      }
      st.leakSeen = [...new Set([...seen, ...items.map(i => i.html_url)])].slice(-500); st.leakBaseline = true; st.leakAt = now();
      saveState(asset, st);
    } catch (e) { if (/rate/.test(e.message)) break; }
    await sleep(7000);
  }
}
