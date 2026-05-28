const CACHE_NAME = 'proespia-v6';
const urlsToCache = [
  '/static/manifest.json',
  '/static/icons/icon-192x192.png',
  '/static/icons/icon-512x512.png',
  '/static/css/style.css',
  '/static/img/favicon-icon.png',
  '/static/img/bg-login.png',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css',
  'https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:wght@300;400;500;600;700;800&display=swap'
];

self.addEventListener('install', function(event) {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(urlsToCache);
    })
  );
});

self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(cacheNames) {
      return Promise.all(
        cacheNames.filter(function(name) {
          return name !== CACHE_NAME;
        }).map(function(name) {
          return caches.delete(name);
        })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

// ====== PUSH NOTIFICATIONS ======
self.addEventListener('push', function(event) {
  if (!event.data) {
    event.waitUntil(
      self.registration.showNotification('Proespia Gestión', { icon: '/static/icons/icon-192x192.png' })
    );
    return;
  }
  try {
    var data = event.data.json();
    var options = {
      body: data.cuerpo || '',
      icon: data.icon || '/static/icons/icon-192x192.png',
      vibrate: [200, 100, 200],
      requireInteraction: true,
      data: { url: data.url || '/' }
    };
    event.waitUntil(
      self.registration.showNotification(data.titulo || 'Proespia Gestión', options)
    );
  } catch(e) {
    event.waitUntil(
      self.registration.showNotification(event.data.text(), {
        icon: '/static/icons/icon-192x192.png',
        vibrate: [200, 100, 200]
      })
    );
  }
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  var url = event.notification.data && event.notification.data.url ? event.notification.data.url : '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
      for (var i = 0; i < clientList.length; i++) {
        var client = clientList[i];
        if (client.url.indexOf(self.location.origin) === 0 && 'focus' in client) {
          return client.focus().then(function() {
            if ('navigate' in client) { client.navigate(url); }
          });
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(url);
      }
    })
  );
});

self.addEventListener('fetch', function(event) {
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).then(function(networkResponse) {
        var cacheClone = networkResponse.clone();
        caches.open(CACHE_NAME).then(function(cache) {
          cache.put(event.request, cacheClone);
        });
        return networkResponse;
      }).catch(function() {
        return caches.match(event.request).then(function(cached) {
          return cached || caches.match('/');
        });
      })
    );
  } else {
    if (event.request.url.includes('/api/')) {
      event.respondWith(fetch(event.request));
      return;
    }
    event.respondWith(
      caches.match(event.request).then(function(response) {
        return response || fetch(event.request).then(function(networkResponse) {
          if (networkResponse && networkResponse.status === 200 && event.request.method === 'GET') {
            var cacheClone = networkResponse.clone();
            caches.open(CACHE_NAME).then(function(cache) {
              if (event.request.url.startsWith(self.location.origin) || event.request.url.startsWith('https://cdn.jsdelivr.net') || event.request.url.startsWith('https://cdnjs.cloudflare.com') || event.request.url.startsWith('https://fonts.googleapis.com') || event.request.url.startsWith('https://fonts.gstatic.com')) {
                cache.put(event.request, cacheClone);
              }
            });
          }
          return networkResponse;
        });
      })
    );
  }
});