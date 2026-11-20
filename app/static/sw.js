/* PromptVeil Self-Hosted Offline Service Worker (Network-First HTML, Cache-First /dist/*, SWR Static) */

const CACHE_NAME = "promptveil-build-7d1ffd0739";

const PRECACHE_URLS = [
  "/",
  "/en/",
  "/404.html",
  "/manifest.webmanifest",
  "/favicon.svg",
  "/apple-touch-icon.png",
  "/icon-192.png",
  "/icon-512.png",
  "/og-image.png",
  "/dist/styles.OSO7ZGEU.css",
  "/dist/app.7ZFZXPFV.js",
  "/dist/i18n-en-DA7RUS5J.js",
  "/dist/i18n-ru-XC3DQG4V.js"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_URLS))
  );
});

self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }
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
  if (
    reqUrl.origin !== self.location.origin ||
    reqUrl.pathname === "/health" ||
    reqUrl.pathname === "/sw.js"
  ) {
    return;
  }

  const acceptHeader = req.headers.get("accept") || "";
  const isHtmlRequest = req.mode === "navigate" || acceptHeader.includes("text/html");

  if (isHtmlRequest) {
    event.respondWith(
      fetch(req)
        .then((networkRes) => {
          if (networkRes && networkRes.ok && networkRes.type === "basic") {
            const copy = networkRes.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, copy)).catch(() => {});
          }
          return networkRes;
        })
        .catch(async () => {
          const cached = await caches.match(req, { ignoreSearch: true });
          if (cached) return cached;
          const fallbackUrl = reqUrl.pathname.startsWith("/en") ? "/en/" : "/";
          const fallback = await caches.match(fallbackUrl);
          if (fallback) return fallback;
          return Response.error();
        })
    );
    return;
  }

  if (reqUrl.pathname.startsWith("/dist/")) {
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
          .catch(() => Response.error());
      })
    );
    return;
  }

  event.respondWith(
    caches.match(req, { ignoreSearch: true }).then((cached) => {
      const networkPromise = fetch(req)
        .then((networkRes) => {
          if (networkRes && networkRes.ok && networkRes.type === "basic") {
            const copy = networkRes.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, copy)).catch(() => {});
          }
          return networkRes;
        })
        .catch(() => cached || Response.error());

      if (cached) {
        event.waitUntil(networkPromise);
        return cached;
      }
      return networkPromise;
    })
  );
});
