import { all, run, now, json } from '../db.js';

export function activeAssets(type, chain = null) {
  const sql = `select s.*, a.rank, a.owner from assets s join agents a on a.id = s.agent_id
    where s.type = ? ${chain ? 'and s.chain = ?' : ''} and s.enabled = 1 and a.status = 'active' and (a.expires_at is null or a.expires_at > ?)`;
  return chain ? all(sql, type, chain, now()) : all(sql, type, now());
}
export const stateOf = a => json(a.state);
export function saveState(asset, st) {
  st.lastChecked = now();
  run('update assets set state = ? where id = ?', JSON.stringify(st), asset.id);
  asset.state = JSON.stringify(st);
}
export const short = a => (a && a.length > 12 ? `${a.slice(0, a.startsWith('0x') ? 6 : 4)}…${a.slice(-4)}` : a || '');
export const label = a => (a.label ? `${a.label} (${short(a.value)})` : short(a.value));
