/* PromptVeil Self-Hosted Offline Service Worker (Static Assets Cache Only) */

const CACHE_NAME = "promptveil-static-v1";

const PRECACHE_URLS = [
  "./",
  "./index.html",
  "./styles.css",
  "./favicon.svg",
  "./manifest.webmanifest",
  "./404.html",
  "./apple-touch-icon.png",
  "./icon-192.png",
  "./icon-512.png",
  "./og-image.png",
  "./css/tokens.css",
  "./css/layout.css",
  "./css/components.css",
  "./css/drawers.css",
  "./css/sections.css",
  "./css/modals.css",
  "./js/app.js",
  "./js/contacts.js",
  "./js/detector.js",
  "./js/dom.js",
  "./js/i18n.js",
  "./js/presets.js",
  "./js/privacy-proof.js",
  "./js/render-drawers.js",
  "./js/render-workbench.js",
  "./js/storage.js",
  "./js/vault.js",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== CACHE_NAME)
            .map((staleKey) => caches.delete(staleKey))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (!req || req.method !== "GET") {
    return;
  }

  const reqUrl = new URL(req.url);
  if (reqUrl.origin !== self.location.origin || reqUrl.pathname === "/health") {
    return;
  }

  event.respondWith(
    caches.match(req, { ignoreSearch: true }).then((cached) => {
      if (cached) {
        return cached;
      }
      return fetch(req)
        .then((networkRes) => {
          if (networkRes && networkRes.ok && networkRes.type === "basic") {
            const copy = networkRes.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, copy)).catch(() => {});
          }
          return networkRes;
        })
        .catch(() => {
          if (req.mode === "navigate") {
            return caches.match("./index.html");
          }
          return Response.error();
        });
    })
  );
});
