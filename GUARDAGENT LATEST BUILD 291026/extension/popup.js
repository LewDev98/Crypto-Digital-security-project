const $ = id => document.getElementById(id);
const send = m => chrome.runtime.sendMessage(m);

async function render() {
  const s = await send({ type: 'status' });
  $('pair').hidden = !!s.paired; $('on').hidden = !s.paired;
  if (!s.paired) { if (s.backend && !s.backend.includes('YOUR-')) $('backend').value = s.backend; return; }
  $('agent').textContent = s.me?.agentId || '—';
  $('rank').textContent = s.me?.active === false ? 'off duty' : (s.me?.rankName || '');
  $('enabled').checked = s.enabled !== false;
  $('statusCard').classList.toggle('off', s.enabled === false || s.me?.active === false);
  const st = s.stats || {};
  $('checked').textContent = st.checked || 0; $('warned').textContent = st.warned || 0; $('blocked').textContent = st.blocked || 0;
}

$('go').onclick = async () => {
  $('perr').textContent = '';
  let backend = $('backend').value.trim().replace(/\/$/, '');
  if (!/^https?:\/\//.test(backend)) backend = 'https://' + backend;
  const code = $('code').value.trim();
  if (!/^\d{8}$/.test(code)) { $('perr').textContent = 'Enter the 8-digit code from your dashboard.'; return; }
  let origin;
  try { origin = new URL(backend).origin; } catch { $('perr').textContent = "That address doesn't look right."; return; }
  const granted = await chrome.permissions.request({ origins: [origin + '/*'] }).catch(() => false);
  if (!granted) { $('perr').textContent = 'Allow access to your Bodyguard server so the shield can check transactions.'; return; }
  const r = await send({ type: 'pair', backend: origin, code });
  if (r?.error) { $('perr').textContent = r.error; return; }
  render();
};
$('enabled').onchange = async e => { const r = await send({ type: 'toggle', enabled: e.target.checked }); if (r?.error) alertBox(r.error); render(); };
$('unpair').onclick = async () => { const r = await send({ type: 'unpair' }); if (r?.error) alertBox(r.error); render(); };
function alertBox(t) { const el = $('oerr'); el.textContent = t; }
render();
