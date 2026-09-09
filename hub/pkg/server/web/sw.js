/* Only public assets belong in persistent storage. Authenticated documents and
 * API responses are always network-only; the offline document contains no user
 * identity, credentials, or stale fleet claims. */
const HUB_VERSION = "{{HUB_VERSION}}";
const CACHE_NAME = "ominull-shell-v" + HUB_VERSION;
const STATIC_ASSETS = [
  "/app.css?v=" + HUB_VERSION,
  "/app.js?v=" + HUB_VERSION,
  "/manifest.webmanifest", "/icon.svg", "/icon-192.png", "/icon-512.png"
];
const OFFLINE_DOCUMENT = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Ominull — Offline</title><main><h1>Ominull is offline</h1><p>Current fleet state and authenticated identity are unavailable. Reconnect to the hub and sign in to continue.</p><a href="/">Try again</a></main></html>';
self.addEventListener("install", function (event) {
  event.waitUntil(caches.open(CACHE_NAME).then(function (cache) {
    return Promise.all(STATIC_ASSETS.map(async function (path) {
      const response = await fetch(path, {credentials: "omit"});
      if (!response.ok || response.redirected || (response.headers.get("Content-Type") || "").includes("text/html")) throw new Error("Public shell asset unavailable");
      await cache.put(path, response);
    }));
  }));
});
self.addEventListener("message", function (event) {
  if (!event.data || event.data.type !== "ACTIVATE_UPDATE") return;
  event.waitUntil(self.clients.matchAll({type: "window", includeUncontrolled: true}).then(function (clients) {
    // Do not replace the worker underneath another window's unsaved work.
    if (clients.length <= 1) return self.skipWaiting();
    if (event.source) event.source.postMessage({type: "UPDATE_BLOCKED"});
  }));
});
self.addEventListener("activate", function (event) {
  event.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (key) { return key.startsWith("ominull-shell-v") && key !== CACHE_NAME; }).map(function (key) { return caches.delete(key); }));
  }).then(function () { return self.clients.claim(); }));
});
self.addEventListener("fetch", function (event) {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== self.location.origin || url.pathname.startsWith("/api/") || url.pathname.startsWith("/status") || url.pathname.startsWith("/agent/") || url.pathname.startsWith("/oidc/")) return;
  if (event.request.mode === "navigate" || url.pathname === "/") {
    event.respondWith(fetch(event.request).catch(function () {
      return new Response(OFFLINE_DOCUMENT, {status: 503, headers: {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}});
    }));
    return;
  }
  // Exact allowlist: never cache arbitrary successful responses (including an
  // HTML Access/sign-in redirect served under a script URL).
  if (!STATIC_ASSETS.includes(url.pathname + url.search)) return;
  event.respondWith(caches.open(CACHE_NAME).then(async function (cache) {
    const cached = await cache.match(event.request);
    if (cached) return cached;
    const response = await fetch(event.request);
    if (response.ok && !response.redirected && !(response.headers.get("Content-Type") || "").includes("text/html")) await cache.put(event.request, response.clone());
    return response;
  }));
});
