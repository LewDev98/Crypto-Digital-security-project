// Bitcoin patrol via the mempool.space API (or your own instance): any spend from a watched address.
import { config } from '../config.js';
import { activeAssets, stateOf, saveState, short, label } from './common.js';
import { checkAddress, learn, inspectIncoming } from '../engines/poison.js';
import { isSanctioned } from '../engines/lists.js';
import { raiseAgent } from '../alerts.js';

const btc = s => (s / 1e8).toLocaleString('en-GB', { maximumFractionDigits: 8 });

export async function pollBitcoin() {
  for (const asset of activeAssets('wallet', 'bitcoin')) {
    try {
      const r = await fetch(`${config.btcApi}/address/${asset.value}/txs`, { signal: AbortSignal.timeout(20000) });
      if (!r.ok) throw new Error('btc api ' + r.status);
      const txs = await r.json();
      const st = stateOf(asset);
      const seen = new Set(st.seen || []);
      const first = !st.baseline;
      for (const t of [...txs].reverse()) {
        if (seen.has(t.txid)) continue;
        seen.add(t.txid);
        const spent = t.vin.filter(v => v.prevout?.scriptpubkey_address === asset.value).reduce((s, v) => s + v.prevout.value, 0);
        const outs = t.vout.filter(o => o.scriptpubkey_address && o.scriptpubkey_address !== asset.value);
        if (first) { if (spent) outs.forEach(o => learn(asset.agent_id, 'bitcoin', o.scriptpubkey_address)); continue; }
        if (spent > 0) {
          const dests = outs.map(o => ({ a: o.scriptpubkey_address, v: o.value }));
          const bad = dests.map(d => ({ ...d, c: checkAddress(asset.agent_id, 'bitcoin', d.a) })).filter(d => d.c.verdict === 'lookalike' || d.c.verdict === 'poisoned');
          const sanc = dests.filter(d => isSanctioned('bitcoin', d.a));
          const cold = /cold|vault|savings|hodl/i.test(asset.label || '');
          const sev = bad.length || sanc.length ? 'crit' : cold ? 'high' : 'med';
          await raiseAgent(asset.agent_id, { severity: sev, type: 'btc_spend', dedupe: `btc:${t.txid}:${asset.id}`,
            title: bad.length ? 'Bitcoin sent to a poisoned address' : sanc.length ? 'Bitcoin sent to a sanctioned address' : cold ? 'Your cold wallet moved' : 'Bitcoin left your address',
            what: `${label(asset)} spent ${btc(spent)} BTC${dests.length ? ` to ${dests.slice(0, 3).map(d => `${short(d.a)} (${btc(d.v)})`).join(', ')}` : ''}${t.status?.confirmed ? '' : '. It is still unconfirmed'}.`,
            did: bad.length ? `Recognised ${short(bad[0].a)} as a lookalike of your ${bad[0].c.label}.` : 'Checked every destination against your history and the sanctions list.',
            move: t.status?.confirmed ? 'If this was not you, move any remaining funds with keys that were never exposed.' : 'If this was not you and your wallet supports it, try to replace it with a higher-fee transaction back to yourself (RBF) right now.',
            data: { txid: t.txid, link: `https://mempool.space/tx/${t.txid}` } });
          if (!bad.length) dests.forEach(d => learn(asset.agent_id, 'bitcoin', d.a));
        } else {
          for (const v of t.vin) {
            const s = v.prevout?.scriptpubkey_address;
            const amount = t.vout.filter(o => o.scriptpubkey_address === asset.value).reduce((x, o) => x + o.value, 0);
            if (s && amount < 2000) {
              const hit = inspectIncoming(asset.agent_id, 'bitcoin', s);
              if (hit) await raiseAgent(asset.agent_id, { severity: 'med', type: 'btc_poison_dust', dedupe: `btcdust:${asset.agent_id}:${s}`, title: 'Address-poisoning attempt',
                what: `${label(asset)} got dust from ${short(s)}, which imitates your ${hit.label || 'address'} (${short(hit.imitates)}).`, did: 'Tagged the lookalike so the shield blocks it.', move: 'Never copy addresses from your history.' });
            }
          }
        }
      }
      st.baseline = true; st.seen = [...seen].slice(-200); st.health = 'ok';
      saveState(asset, st);
    } catch (e) { const st = stateOf(asset); st.health = 'error: ' + e.message.slice(0, 80); saveState(asset, st); }
  }
}
