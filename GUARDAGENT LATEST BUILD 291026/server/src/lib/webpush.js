// Web Push (RFC 8291 aes128gcm payload encryption + RFC 8292 VAPID), no libraries.
import crypto from 'node:crypto';

const b64u = buf => Buffer.from(buf).toString('base64url');
const fromB64u = s => Buffer.from(s, 'base64url');

export function generateVapidKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = privateKey.export({ format: 'jwk' });
  const pub = Buffer.concat([Buffer.from([4]), fromB64u(jwk.x), fromB64u(jwk.y)]);
  return { publicKey: b64u(pub), privateKey: jwk.d };
}

function vapidPrivateKey(publicKeyB64u, privateKeyB64u) {
  const pub = fromB64u(publicKeyB64u);
  return crypto.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: privateKeyB64u, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) }, format: 'jwk' });
}

function vapidJwt(audience, subject, publicKey, privateKey) {
  const header = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const payload = b64u(JSON.stringify({ aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject }));
  const data = `${header}.${payload}`;
  const sig = crypto.sign('sha256', Buffer.from(data), { key: vapidPrivateKey(publicKey, privateKey), dsaEncoding: 'ieee-p1363' });
  return `${data}.${b64u(sig)}`;
}

export function encryptPayload(payload, p256dhB64u, authB64u) {
  const uaPublic = fromB64u(p256dhB64u);
  const authSecret = fromB64u(authB64u);
  const ecdh = crypto.createECDH('prime256v1');
  const asPublic = ecdh.generateKeys();
  const shared = ecdh.computeSecret(uaPublic);
  const salt = crypto.randomBytes(16);
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]);
  const ikm = Buffer.from(crypto.hkdfSync('sha256', shared, authSecret, keyInfo, 32));
  const cek = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const plain = Buffer.concat([Buffer.from(payload), Buffer.from([2])]);
  const body = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  const rs = Buffer.alloc(4); rs.writeUInt32BE(4096);
  return Buffer.concat([salt, rs, Buffer.from([asPublic.length]), asPublic, body]);
}

export async function sendPush(sub, payload, { publicKey, privateKey, subject }) {
  const endpoint = new URL(sub.endpoint);
  const jwt = vapidJwt(endpoint.origin, subject, publicKey, privateKey);
  const body = encryptPayload(typeof payload === 'string' ? payload : JSON.stringify(payload), sub.p256dh, sub.auth);
  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: { TTL: '86400', Urgency: 'high', 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', Authorization: `vapid t=${jwt}, k=${publicKey}` },
    body, signal: AbortSignal.timeout(15000)
  });
  return { status: res.status, gone: res.status === 404 || res.status === 410 };
}
