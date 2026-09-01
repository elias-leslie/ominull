/* Ominull Service Worker
 * Provides PWA installability, shell caching, and offline support.
 * Live API routes (/api/v1/*) are always fetched live over the network.
 */
const CACHE_NAME = "ominull-shell-v1.8.1";
const STATIC_ASSETS = [
  "/",
  "/app.css",
  "/app.js",
  "/manifest.webmanifest",
  "/icon.svg",
  "/icon-192.png",
  "/icon-512.png"
];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      return cache.addAll(STATIC_ASSETS);
    }).then(function () {
      return self.skipWaiting();
    })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.map(function (key) {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(function () {
      return self.clients.claim();
    })
  );
});

self.addEventListener("fetch", function (event) {
  const url = new URL(event.request.url);

  // API endpoints, agent downloads, OIDC authentication are network-only
  if (
    event.request.method !== "GET" ||
    url.pathname.startsWith("/api/") ||
    url.pathname.startsWith("/status") ||
    url.pathname.startsWith("/agent/") ||
    url.pathname.startsWith("/oidc/")
  ) {
    return;
  }

  // HTML navigation (e.g. initial load or section changes)
  if (event.request.mode === "navigate" || url.pathname === "/") {
    event.respondWith(
      fetch(event.request).then(function (response) {
        if (response && response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(function (cache) {
            cache.put(event.request, clone);
          });
        }
        return response;
      }).catch(function () {
        return caches.match("/") || caches.match(event.request);
      })
    );
    return;
  }

  // Static shell assets: Stale-while-revalidate for fast rendering
  event.respondWith(
    caches.match(event.request).then(function (cached) {
      const liveFetch = fetch(event.request).then(function (response) {
        if (response && response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(function (cache) {
            cache.put(event.request, clone);
          });
        }
        return response;
      }).catch(function () {
        return cached;
      });

      return cached || liveFetch;
    })
  );
});
