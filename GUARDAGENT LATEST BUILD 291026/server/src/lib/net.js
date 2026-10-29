// Address helpers shared by the SSRF guard (domain checks) and the intrusion detector.
import net from 'node:net';

// Never open connections to internal networks, even if a customer's domain points there.
const BLOCKED = new net.BlockList();
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]]) BLOCKED.addSubnet(a, p, 'ipv4');
for (const [a, p] of [['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64], ['2001:db8::', 32], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]]) BLOCKED.addSubnet(a, p, 'ipv6');
export const isPrivateIp = ip => {
  ip = String(ip);
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i); // IPv4-mapped IPv6: judge the IPv4 inside
  if (mapped) ip = mapped[1];
  const v = net.isIP(ip);
  if (!v) return true;
  try { return BLOCKED.check(ip, v === 6 ? 'ipv6' : 'ipv4'); } catch { return true; }
};
