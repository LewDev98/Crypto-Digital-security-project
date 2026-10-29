// Bodyguard push alerts.
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { title: 'Bodyguard alert', body: e.data && e.data.text() }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Bodyguard alert', {
    body: d.body || '', icon: '/icon-192.png', badge: '/icon-192.png', tag: d.tag || undefined,
    requireInteraction: d.severity === 'crit' || d.severity === 'high', data: { url: d.url || '/app#alerts' }
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  // Only ever open pages on this site from a notification.
  let url = '/app#alerts';
  try { const u = new URL((e.notification.data && e.notification.data.url) || '/app#alerts', self.location.origin); if (u.origin === self.location.origin) url = u.href; } catch {}
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) if (c.url.includes('/app') && 'focus' in c) { c.navigate(url); return c.focus(); }
    return clients.openWindow(url);
  }));
});
