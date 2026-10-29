// Runs inside the page (MAIN world) before the site's own scripts. Wraps every Solana and EVM wallet the page can
// reach so each signing request is checked by your Bodyguard agent first.
//
// Bridge security: at document_start, before any page script exists, this script and the extension's isolated
// content script meet through a synchronous DOM event and agree a random key. Every answer after that is
// HMAC-signed with the key, so a page can't forge an "allowed" answer even though it can see the messages.
// Fail closed: if the extension doesn't answer (not ready, crashed, timed out), the request is refused.
(() => {
  if (window.__bodyguardShield) return;
  Object.defineProperty(window, '__bodyguardShield', { value: true });

  /* ---------- handshake (synchronous, document_start only) ---------- */
  let key = null, keyHex = null;
  const onKey = e => {
    if (keyHex || typeof e.detail !== 'string' || !/^[0-9a-f]{64}$/.test(e.detail)) return;
    keyHex = e.detail;
    document.removeEventListener('__bodyguard_key', onKey, true);
    document.dispatchEvent(new CustomEvent('__bodyguard_ack'));
    if (crypto.subtle) crypto.subtle.importKey('raw', hexBytes(keyHex), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']).then(k => { key = k; });
  };
  const hexBytes = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
  document.addEventListener('__bodyguard_key', onKey, true);
  document.dispatchEvent(new CustomEvent('__bodyguard_hello'));

  /* ---------- checks ---------- */
  const pending = new Map();
  window.addEventListener('message', async e => {
    const m = e.data;
    if (e.source !== window || !m || m.__bgRes !== true || !pending.has(m.id) || !key) return;
    let ok = false;
    try { ok = await crypto.subtle.verify('HMAC', key, hexBytes(String(m.mac || '').padEnd(64, '0').slice(0, 64)), new TextEncoder().encode(`${m.id}:${m.allowed ? 1 : 0}`)); } catch {}
    if (!ok) return; // forged or garbled: ignore and keep waiting for the real answer
    const done = pending.get(m.id); pending.delete(m.id); done(!!m.allowed);
  });
  const waitForKey = async () => { for (let i = 0; i < 40 && !key; i++) await new Promise(r => setTimeout(r, 75)); return !!key; };
  const rand = () => { const b = crypto.getRandomValues(new Uint8Array(12)); return [...b].map(x => x.toString(16).padStart(2, '0')).join(''); };

  /* The warning screen lives in the extension's isolated content script, not here. The page only ever learns
     "allowed" or "not allowed", never the reasons (which can include your saved-address labels). */
  async function guard(kind, payload) {
    if (!crypto.subtle) { window.postMessage({ __bgReq: true, id: 'insecure', kind: 'insecure' }, location.origin === 'null' ? '*' : location.origin); return false; } // plain http: can't verify answers
    if (!(await waitForKey())) return false; // bridge never came up: refuse rather than sign unchecked
    const id = 'r' + rand();
    return new Promise(resolve => {
      pending.set(id, resolve);
      window.postMessage({ __bgReq: true, id, kind, payload: { ...payload, origin: location.origin } }, location.origin === 'null' ? '*' : location.origin);
      // A request left open (the user walked away from the warning) is refused, never silently allowed.
      setTimeout(() => { if (pending.has(id)) { pending.delete(id); resolve(false); } }, 600000);
    });
  }
  const rejectErr = () => Object.assign(new Error('User rejected the request (blocked by Bodyguard).'), { code: 4001 });

  /* ---------- encoding helpers ---------- */
  const b64 = u8 => { let s = ''; const b = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8); for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };
  const ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function b58dec(str) {
    if (typeof str !== 'string' || str.length > 2400) return null;
    const bytes = [];
    for (const c of str) { let carry = ALPH.indexOf(c); if (carry < 0) return null; for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; } while (carry) { bytes.push(carry & 0xff); carry >>= 8; } }
    for (const c of str) { if (c === '1') bytes.push(0); else break; }
    return Uint8Array.from(bytes.reverse());
  }
  const ser = tx => {
    try {
      if (tx instanceof Uint8Array) return b64(tx);
      if (typeof tx === 'string') { const d = b58dec(tx); return d ? b64(d) : null; }
      if (tx && typeof tx.serialize === 'function') { try { return b64(tx.serialize({ requireAllSignatures: false, verifySignatures: false })); } catch { return b64(tx.serialize()); } }
    } catch {}
    return null;
  };
  // Every transaction must be readable. One unreadable item means the check runs with nothing, which the agent
  // treats as "couldn't check" (a warning, or a block during a duress time-lock), never as a pass.
  const serAll = list => { const out = (list || []).map(ser); return out.every(Boolean) ? out : []; };

  /* ---------- Solana ---------- */
  const patched = new WeakSet();
  const SOL_SIGN = { signTransaction: p => [p?.message ?? p?.transaction], signAllTransactions: p => p?.messages ?? p?.transactions ?? [], signAndSendTransaction: p => [p?.message ?? p?.transaction], signAndSendAllTransactions: p => p?.messages ?? p?.transactions ?? [] };
  function wrapSol(p, name) {
    if (!p || typeof p !== 'object' || patched.has(p)) return;
    patched.add(p);
    for (const m of ['signTransaction', 'signAllTransactions', 'signAndSendTransaction', 'signAndSendAllTransactions']) {
      const orig = p[m];
      if (typeof orig !== 'function') continue;
      const wrapped = async function (...args) {
        const list = m.includes('All') ? args[0] : [args[0]];
        if (!(await guard('solana', { transactions: serAll(list), wallet: name }))) throw rejectErr();
        return orig.apply(this, args);
      };
      try { Object.defineProperty(p, m, { value: wrapped, configurable: false, writable: true }); } catch { try { p[m] = wrapped; } catch {} }
    }
    // Phantom-style generic entry point: provider.request({ method: 'signTransaction', params: { message } }).
    if (typeof p.request === 'function') {
      const origReq = p.request;
      const wrappedReq = async function (args) {
        const pick = args && SOL_SIGN[args.method];
        if (pick && !(await guard('solana', { transactions: serAll(pick(args.params)), wallet: name }))) throw rejectErr();
        return origReq.apply(this, arguments);
      };
      try { Object.defineProperty(p, 'request', { value: wrappedReq, configurable: false, writable: true }); } catch { try { p.request = wrappedReq; } catch {} }
    }
  }
  function wrapStd(w) {
    if (!w || patched.has(w) || !w.features) return;
    patched.add(w);
    for (const [f, m] of [['solana:signTransaction', 'signTransaction'], ['solana:signAndSendTransaction', 'signAndSendTransaction']]) {
      const feat = w.features[f];
      if (!feat || typeof feat[m] !== 'function') continue;
      const orig = feat[m];
      const wrapped = async function (...inputs) {
        const txs = serAll(inputs.map(i => i && i.transaction));
        if (!(await guard('solana', { transactions: txs, wallet: w.name }))) throw rejectErr();
        return orig.apply(this, inputs);
      };
      try { Object.defineProperty(feat, m, { value: wrapped, configurable: false, writable: true }); } catch { try { feat[m] = wrapped; } catch {} }
    }
  }
  window.addEventListener('wallet-standard:register-wallet', e => { try { e.detail({ register: (...ws) => { ws.forEach(wrapStd); return () => {}; } }); } catch {} });
  const stdApi = { register: (...ws) => { ws.forEach(wrapStd); return () => {}; } };

  /* ---------- EVM ---------- */
  const SIGN = new Set(['eth_sendTransaction', 'eth_signTransaction', 'eth_signTypedData', 'eth_signTypedData_v1', 'eth_signTypedData_v3', 'eth_signTypedData_v4', 'eth_sign', 'personal_sign', 'wallet_sendCalls']);
  async function checkEvm(p, origCall, method, params, name) {
    let chainId = null;
    try { chainId = await origCall({ method: 'eth_chainId' }); } catch {}
    params = Array.isArray(params) ? params : params == null ? [] : [params];
    const from = method === 'eth_sendTransaction' || method === 'eth_signTransaction' ? params[0]?.from : method === 'wallet_sendCalls' ? params[0]?.from : method === 'personal_sign' ? params[1] : params[0];
    // Batches: every call in wallet_sendCalls is sent for checking, not just the first.
    return guard('evm', { chainId, method, params, from, wallet: name });
  }
  function wrapEvm(p, name) {
    if (!p || typeof p.request !== 'function' || patched.has(p)) return;
    patched.add(p);
    const orig = p.request;
    const origCall = a => orig.call(p, a);
    const lock = (k, v) => { try { Object.defineProperty(p, k, { value: v, configurable: false, writable: true }); } catch { try { p[k] = v; } catch {} } };
    lock('request', async function (args) {
      if (args && SIGN.has(args.method) && !(await checkEvm(p, origCall, args.method, args.params, name))) throw rejectErr();
      return orig.apply(this, arguments);
    });
    // Legacy entry points that drainers use to slip past wrappers that only cover request().
    if (typeof p.sendAsync === 'function') {
      const sa = p.sendAsync;
      lock('sendAsync', function (payload, cb) {
        const reqs = Array.isArray(payload) ? payload : [payload];
        const signing = reqs.filter(r => r && SIGN.has(r.method));
        if (!signing.length) return sa.apply(this, arguments);
        const self = this, a = arguments;
        (async () => { for (const r of signing) if (!(await checkEvm(p, origCall, r.method, r.params, name))) return false; return true; })()
          .then(ok => ok ? sa.apply(self, a) : cb && cb(rejectErr(), null));
      });
    }
    if (typeof p.send === 'function') {
      const sd = p.send;
      lock('send', function (a, b) {
        const method = typeof a === 'string' ? a : a?.method;
        const params = typeof a === 'string' ? b : a?.params;
        if (!SIGN.has(method)) return sd.apply(this, arguments);
        const self = this, args = arguments;
        const run = checkEvm(p, origCall, method, params, name).then(ok => { if (!ok) throw rejectErr(); return sd.apply(self, args); });
        if (typeof b === 'function') { run.catch(err => b(err, null)); return; }
        return run;
      });
    }
  }
  window.addEventListener('eip6963:announceProvider', e => { try { wrapEvm(e.detail.provider, e.detail.info?.name); } catch {} });

  /* ---------- find providers as they appear ---------- */
  function scan() {
    try { wrapSol(window.phantom && window.phantom.solana, 'Phantom'); } catch {}
    try { wrapSol(window.solana, 'Solana wallet'); } catch {}
    try { wrapSol(window.solflare, 'Solflare'); } catch {}
    try { wrapSol(window.backpack, 'Backpack'); } catch {}
    try { wrapSol(window.glowSolana, 'Glow'); } catch {}
    try { wrapEvm(window.ethereum, 'Ethereum wallet'); } catch {}
    try { (window.ethereum?.providers || []).forEach(p => wrapEvm(p, 'Ethereum wallet')); } catch {}
    try { wrapEvm(window.phantom && window.phantom.ethereum, 'Phantom'); } catch {}
  }
  scan();
  let n = 0;
  const iv = setInterval(() => { scan(); if (++n > 40) clearInterval(iv); }, 150);
  document.addEventListener('DOMContentLoaded', () => {
    scan();
    try { window.dispatchEvent(new CustomEvent('wallet-standard:app-ready', { detail: stdApi })); } catch {}
    try { window.dispatchEvent(new Event('eip6963:requestProvider')); } catch {}
  });
  window.addEventListener('load', scan);
})();
