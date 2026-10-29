// Connect Gmail or Outlook (read-only) to an email on the agent's briefing.
import { route, bad, HttpError } from '../http.js';
import { config } from '../config.js';
import { get, run, now, randomToken } from '../db.js';
import { requireAgent } from '../access.js';
import { GOOGLE_SCOPES, MS_SCOPES, saveToken } from '../monitors/inbox.js';

const redirect = p => `${config.publicUrl}/api/oauth/${p}/callback`;

route('POST', '/api/agent/:id/assets/:assetId/inbox/:provider', ctx => {
  const a = requireAgent(ctx, { write: true });
  const asset = get("select * from assets where id = ? and agent_id = ? and type = 'email'", ctx.params.assetId, a.id);
  if (!asset) throw bad('Add the email to your agent first.');
  const p = ctx.params.provider;
  if (p !== 'google' && p !== 'microsoft') throw bad('Choose google or microsoft.');
  const state = randomToken(18);
  run('delete from oauth_states where created_at < ?', now() - 900);
  run('insert into oauth_states(state, asset_id, provider, created_at) values(?,?,?,?)', state, asset.id, p, now());
  if (p === 'google') {
    if (!config.google.id) throw new HttpError(503, 'Gmail connection is not switched on yet.');
    const q = new URLSearchParams({ client_id: config.google.id, redirect_uri: redirect('google'), response_type: 'code', scope: GOOGLE_SCOPES, access_type: 'offline', prompt: 'consent', state, login_hint: asset.value });
    return { url: 'https://accounts.google.com/o/oauth2/v2/auth?' + q };
  }
  if (p === 'microsoft') {
    if (!config.microsoft.id) throw new HttpError(503, 'Outlook connection is not switched on yet.');
    const q = new URLSearchParams({ client_id: config.microsoft.id, redirect_uri: redirect('microsoft'), response_type: 'code', response_mode: 'query', scope: MS_SCOPES, state, login_hint: asset.value });
    return { url: `https://login.microsoftonline.com/${config.microsoft.tenant}/oauth2/v2.0/authorize?` + q };
  }
  throw bad('Choose google or microsoft.');
});

route('DELETE', '/api/agent/:id/assets/:assetId/inbox', ctx => {
  const a = requireAgent(ctx, { write: true, allowExpired: true });
  const asset = get('select * from assets where id = ? and agent_id = ?', ctx.params.assetId, a.id);
  if (asset) run('delete from oauth_tokens where asset_id = ?', asset.id);
  return { ok: true };
});

const done = (msg, ok) => ({ __redirect: `${config.publicUrl}/app?inbox=${ok ? 'connected' : 'error'}&msg=${encodeURIComponent(msg)}#brief` });

route('GET', '/api/oauth/:provider/callback', async ctx => {
  const p = ctx.params.provider;
  const st = get('select * from oauth_states where state = ? and provider = ?', String(ctx.query.state || ''), p);
  if (!st || now() - st.created_at > 900) return done('That sign-in link expired. Try connecting again.', false);
  run('delete from oauth_states where state = ?', st.state);
  if (ctx.query.error || !ctx.query.code) return done('The connection was cancelled.', false);
  const asset = get('select * from assets where id = ?', st.asset_id);
  if (!asset) return done('That email is no longer on your agent.', false);
  const tokenUrl = p === 'google' ? 'https://oauth2.googleapis.com/token' : `https://login.microsoftonline.com/${config.microsoft.tenant}/oauth2/v2.0/token`;
  const body = new URLSearchParams(p === 'google'
    ? { code: ctx.query.code, client_id: config.google.id, client_secret: config.google.secret, redirect_uri: redirect('google'), grant_type: 'authorization_code' }
    : { code: ctx.query.code, client_id: config.microsoft.id, client_secret: config.microsoft.secret, redirect_uri: redirect('microsoft'), grant_type: 'authorization_code', scope: MS_SCOPES });
  const r = await fetch(tokenUrl, { method: 'POST', body, signal: AbortSignal.timeout(20000) });
  const tok = await r.json();
  if (!r.ok || !tok.access_token) return done('The provider refused the connection.', false);
  let email = '';
  if (p === 'google' && tok.id_token) { try { email = JSON.parse(Buffer.from(tok.id_token.split('.')[1], 'base64url').toString()).email; } catch {} }
  if (p === 'microsoft') { const me = await fetch('https://graph.microsoft.com/v1.0/me', { headers: { authorization: 'Bearer ' + tok.access_token } }).then(x => x.json()).catch(() => ({})); email = me.mail || me.userPrincipalName || ''; }
  // The account that signed in must be the email on the briefing. No email back means we can't prove that, so refuse.
  if (!email) return done('The provider did not confirm which account you signed in with. Try connecting again.', false);
  if (email.toLowerCase() !== asset.value) return done(`You signed in as ${email}, but this briefing is for ${asset.value}. Sign in with the right account.`, false);
  if (!tok.refresh_token) return done('No long-term access was granted. Remove Bodyguard from your account permissions and connect again.', false);
  saveToken(asset.id, p, tok);
  return done('Inbox connected. Your agent is reading security notices now.', true);
});
