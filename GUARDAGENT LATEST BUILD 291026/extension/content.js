// Isolated-world bridge: relays the page's signing checks to the extension, and runs the paste/copy
// poisoning shield on every page.
(() => {
  /* ---------- signing checks + the warning screen (isolated world: the page can't read or fake it) ---------- */
  const CSS = `:host{all:initial}.wrap{position:fixed;inset:0;z-index:2147483647;display:grid;place-items:center;background:rgba(4,6,5,.82);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:16px}
  .card{background:#111612;color:#e3ebe5;border:1px solid #33423a;border-radius:16px;max-width:460px;width:100%;padding:22px;box-shadow:0 30px 90px -20px #000}
  .top{display:flex;gap:10px;align-items:center;font:600 12px ui-monospace,Menlo,monospace;letter-spacing:.12em;color:#c8ff1a;text-transform:uppercase}
  h2{margin:12px 0 6px;font-size:22px;line-height:1.2}.sev{display:inline-block;font:600 11px ui-monospace,monospace;padding:2px 8px;border-radius:99px;margin-bottom:8px}
  .block .sev{background:#ff5a6b;color:#0a0d0b}.warn .sev{border:1px solid #ffbb4d;color:#ffbb4d}ul{margin:10px 0;padding-left:18px}li{margin:6px 0;font-size:14px;line-height:1.45}
  .sum{font-size:13px;color:#8c998f;margin:8px 0}.row{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
  button{all:unset;cursor:pointer;padding:12px 16px;border-radius:10px;font-weight:600;font-size:14px;text-align:center;flex:1}
  .primary{background:#c8ff1a;color:#121a00}.ghost{border:1px solid #33423a;color:#e3ebe5}.ghost:hover{border-color:#ff5a6b;color:#ff5a6b}
  .hold{position:relative;overflow:hidden}.hold i{position:absolute;inset:0;background:rgba(255,90,107,.25);transform-origin:left;transform:scaleX(0)}
  .toast{position:fixed;right:16px;bottom:16px;z-index:2147483647;background:#111612;color:#e3ebe5;border:1px solid #ffbb4d;border-radius:10px;padding:10px 14px;font:13px system-ui,sans-serif;max-width:320px}`;
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  function mount(html) {
    const host = document.createElement('bodyguard-shield');
    const root = host.attachShadow({ mode: 'closed' });
    root.innerHTML = `<style>${CSS}</style>${html}`;
    (document.documentElement || document.body).appendChild(host);
    return { host, root };
  }
  const toasted = new Set();
  function toast(key, text) {
    if (toasted.has(key)) return; toasted.add(key);
    const { host } = mount(`<div class="toast" role="status">${esc(text)}</div>`);
    setTimeout(() => host.remove(), 5000);
  }
  function confirmUi(res) {
    return new Promise(resolve => {
      const block = res.action === 'block';
      const locked = !!res.locked; // duress time-lock: no override, by design
      const shield = '<img src="data:image/png;base64,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" width="22" height="22" alt="">';
      const reasons = (res.reasons || []).filter(r => r.severity !== 'low' || !block).slice(0, 5);
      const { host, root } = mount(`<div class="wrap ${block ? 'block' : 'warn'}" role="dialog" aria-modal="true"><div class="card">
        <div class="top">${shield} Bodyguard Shield</div>
        <h2>${locked ? 'Security time-lock is on' : block ? 'Stopped: this looks like a drainer' : 'Check this before you sign'}</h2>
        <span class="sev">${locked ? 'TIME-LOCKED' : block ? 'BLOCKED' : 'WARNING'}</span>
        <ul>${reasons.map(r => `<li>${esc(r.text)}</li>`).join('')}</ul>
        ${(res.summary || []).length ? `<div class="sum">${res.summary.slice(0, 4).map(esc).join('<br>')}</div>` : ''}
        <div class="row"><button class="primary" id="cancel">${locked ? 'OK' : "Cancel, don't sign"}</button>
        ${locked ? '' : `<button class="ghost ${block ? 'hold' : ''}" id="go">${block ? '<i></i>Hold to sign anyway' : 'I trust this, continue'}</button>`}</div></div></div>`);
      const done = v => { host.remove(); resolve(v); };
      root.getElementById('cancel').onclick = e => { if (e.isTrusted) done(false); };
      const go = root.getElementById('go');
      if (!go) { root.getElementById('cancel').focus(); return; }
      if (!block) go.onclick = e => { if (e.isTrusted) done(true); };
      else {
        let t, start; const bar = go.querySelector('i');
        const down = e => { if (!e.isTrusted) return; start = Date.now(); t = setInterval(() => { const p = Math.min(1, (Date.now() - start) / 2500); bar.style.transform = `scaleX(${p})`; if (p >= 1) { clearInterval(t); done(true); } }, 30); };
        const up = () => { clearInterval(t); bar.style.transform = 'scaleX(0)'; };
        go.addEventListener('pointerdown', down); go.addEventListener('pointerup', up); go.addEventListener('pointerleave', up);
      }
      root.getElementById('cancel').focus();
    });
  }
  // "Couldn't check" is never a silent pass: the person sees a warning and decides.
  const UNCHECKED = { action: 'warn', reasons: [{ severity: 'high', text: "Bodyguard couldn't check this request (your agent didn't answer). Only continue if you started it and trust this site." }], summary: [] };
  async function decide(kind, payload) {
    payload = { ...(payload || {}), origin: location.origin }; // set here, not trusted from the page
    let r;
    try { r = await chrome.runtime.sendMessage({ type: 'check', kind, payload }); } catch { r = { error: 'extension unavailable' }; }
    if (!r) return confirmUi(UNCHECKED);
    if (r.disabled) return true;
    if (r.unpaired) { toast('unpaired', 'Bodyguard Shield is not paired, so this was not checked. Open the extension to switch protection on.'); return true; }
    if (r.error) return confirmUi(UNCHECKED);
    if (r.action === 'allow') return true;
    return confirmUi(r);
  }

  /* ---------- private bridge to the page script (inject.js) ----------
     At document_start, before any page script exists, we hand inject.js a random key through a synchronous DOM
     event. Every answer we post back is HMAC-signed with it, so the page can't forge "allowed". The hand-over
     happens once; later "hello" events (from a page) get nothing. */
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const keyHex = [...keyBytes].map(b => b.toString(16).padStart(2, '0')).join('');
  let handedOver = false;
  const giveKey = () => { if (!handedOver) document.dispatchEvent(new CustomEvent('__bodyguard_key', { detail: keyHex })); };
  const onHello = () => giveKey();
  document.addEventListener('__bodyguard_hello', onHello, true);
  document.addEventListener('__bodyguard_ack', () => { handedOver = true; document.removeEventListener('__bodyguard_hello', onHello, true); }, { once: true, capture: true });
  giveKey();
  const hmacKey = crypto.subtle ? crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']) : Promise.reject(new Error('no subtle'));
  const busy = new Set();
  window.addEventListener('message', async e => {
    const m = e.data;
    if (e.source !== window || !m || m.__bgReq !== true || typeof m.id !== 'string' || m.id.length > 40 || busy.has(m.id) || busy.size >= 3) return;
    // Plain-http pages have no WebCrypto, so answers can't be signed and every request is refused. Say why.
    if (m.kind === 'insecure' || !crypto.subtle) return toast('insecure', 'Bodyguard Shield only checks transactions on secure (https) sites, so this request was refused. Use the https version of this site.');
    if (m.kind !== 'solana' && m.kind !== 'evm') return;
    busy.add(m.id);
    try {
      const allowed = !!(await decide(m.kind, m.payload));
      const sig = await crypto.subtle.sign('HMAC', await hmacKey, new TextEncoder().encode(`${m.id}:${allowed ? 1 : 0}`));
      const mac = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
      window.postMessage({ __bgRes: true, id: m.id, allowed, mac }, location.origin === 'null' ? '*' : location.origin);
    } catch {} finally { busy.delete(m.id); }
  });

  /* ---------- paste / copy shield ---------- */
  const looksLike = s => /^0x[0-9a-fA-F]{40}$/.test(s) || /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s) || /^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(s);
  let bubble = null;
  function show(target, r, kind) {
    if (bubble) bubble.remove();
    const host = document.createElement('bodyguard-bubble');
    const root = host.attachShadow({ mode: 'closed' });
    const rect = target && target.getBoundingClientRect ? target.getBoundingClientRect() : { left: 20, bottom: 80, width: 300 };
    const diff = (a, b) => { let p = 0; while (a[p] === b[p] && p < a.length) p++; let s = 0; while (s < a.length - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s++; return [...a].map((c, i) => `<span class="${i < p || a.length - 1 - i < s ? 'm' : 'x'}">${esc(c)}</span>`).join(''); };
    root.innerHTML = `<style>
      .b{position:fixed;z-index:2147483647;left:${Math.max(8, Math.min(rect.left, innerWidth - 380))}px;top:${Math.min(rect.bottom + 8, innerHeight - 220)}px;width:min(360px,calc(100vw - 16px));background:#111612;color:#e3ebe5;border:1px solid #ff5a6b;border-radius:12px;padding:14px;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;box-shadow:0 20px 60px -20px #000}
      .t{font:600 11px ui-monospace,monospace;letter-spacing:.12em;color:#ff5a6b;text-transform:uppercase}code{display:block;font:12.5px ui-monospace,Menlo,monospace;word-break:break-all;margin:6px 0}
      .m{color:#c8ff1a}.x{color:#ff5a6b;background:rgba(255,90,107,.15)}small{color:#8c998f}.r{display:flex;gap:8px;margin-top:10px}
      button{all:unset;cursor:pointer;padding:8px 12px;border-radius:8px;font-weight:600;font-size:13px}.p{background:#c8ff1a;color:#121a00}.g{border:1px solid #33423a}</style>
      <div class="b" role="alert"><div class="t">Bodyguard · poisoned address</div>
      <p style="margin:6px 0">${kind === 'copy' ? 'You just copied' : 'You pasted'} a lookalike of your <b>${esc(r.label)}</b>. Don't send to it.</p>
      <small>${kind === 'copy' ? 'Copied' : 'Pasted'}</small><code>${diff(r.address, r.imitates || r.address)}</code>
      <small>Your real address</small><code>${diff(r.imitates || '', r.address)}</code>
      <div class="r">${kind === 'paste' ? '<button class="p" id="clear">Remove it</button>' : ''}<button class="g" id="close">Dismiss</button></div></div>`;
    document.documentElement.appendChild(host);
    bubble = host;
    root.getElementById('close').onclick = () => host.remove();
    const c = root.getElementById('clear');
    if (c) c.onclick = () => {
      try {
        if ('value' in target) { target.value = String(target.value).replace(r.address, ''); target.dispatchEvent(new Event('input', { bubbles: true })); }
        else if (target.isContentEditable) target.textContent = target.textContent.replace(r.address, '');
      } catch {}
      host.remove();
    };
  }
  async function check(text, target, kind) {
    const s = String(text || '').trim();
    if (!looksLike(s)) return;
    let r;
    try { r = await chrome.runtime.sendMessage({ type: 'shield', address: s, event: kind, origin: location.origin }); } catch { return; }
    if (r && (r.verdict === 'lookalike' || r.verdict === 'poisoned')) show(target, { ...r, address: r.address || s }, kind);
  }
  document.addEventListener('paste', e => { if (!e.isTrusted) return; const t = e.clipboardData && e.clipboardData.getData('text'); check(t, e.target, 'paste'); }, true);
  document.addEventListener('copy', e => { if (!e.isTrusted) return; const t = String(getSelection() || ''); check(t, document.activeElement, 'copy'); }, true);
})();
