// Archivo deshabilitado temporalmente para evitar conflictos de caché.
// Una vez que la aplicación funcione en producción, se puede volver a configurar
// un service worker específico para YumiFeel.

self.addEventListener('install', (e) => {
  // Forzar al nuevo service worker a activarse inmediatamente
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  // Eliminar cachés antiguas del proyecto 'veterinaria'
  e.waitUntil(
    caches.keys().then(keys => 
      Promise.all(keys
        .filter(key => key.startsWith('veterinaria-pwa')) // Borra solo la caché vieja
        .map(key => caches.delete(key))
      )
    ).then(() => {
      // Tomar control de todas las pestañas abiertas
      return self.clients.claim();
    })
  );
});

self.addEventListener('fetch', (e) => {
  // No usar la caché, solo ir a la red (network-first)
  // Esto asegura que siempre veamos los archivos más nuevos del servidor
  e.respondWith(
    fetch(e.request).catch(() => {
      // Opcional: podrías mostrar una página de "sin conexión" aquí
      // pero por ahora, solo dejamos que falle si no hay red.
    })
  );
});