// A live https site: pages opened on another hostname move to the real one; the API is left alone.
import './env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
process.env.PORT = String(30000 + Math.floor(Math.random() * 20000));
process.env.PUBLIC_URL = 'https://guardagent.example';
await import('../src/index.js');
await new Promise(r => setTimeout(r, 300));
const http = await import('node:http');
const get = (path, host) => new Promise((res, rej) => http.get({ host: '127.0.0.1', port: process.env.PORT, path, headers: { host } }, r => { r.resume(); res({ status: r.statusCode, location: r.headers.location, csp: r.headers['content-security-policy'] }); }).on('error', rej));

test('www and hosting-domain visits redirect to the real site; API calls and the real host do not', async () => {
  const w = await get('/help?x=1', 'www.guardagent.example');
  assert.equal(w.status, 301);
  assert.equal(w.location, 'https://guardagent.example/help?x=1');
  assert.equal((await get('//evil.example/x', 'bodyguard.up.railway.app')).location, 'https://guardagent.example//evil.example/x', 'never leaves the real host');
  assert.equal((await get('/api/health', 'bodyguard.up.railway.app')).status, 200);
  const real = await get('/', 'guardagent.example');
  assert.equal(real.status, 200);
  assert.match(real.csp, /upgrade-insecure-requests/);
  assert.match(real.csp, /connect-src 'self' https:\/\/guardagent\.example https:\/\/api\.mainnet-beta\.solana\.com/);
  assert.equal((await get('/', 'localhost:' + process.env.PORT)).status, 200, 'local checks still work');
  setTimeout(() => process.exit(0), 50);
});
