/* ScamShield service worker — app-shell precache + stale-while-revalidate. */
const VERSION = "scamshield-v1";
const SHELL = [
  "/",
  "/analyze",
  "/history",
  "/icon.svg",
  "/icon-192.png",
  "/icon-512.png",
  "/apple-icon.png",
  "/manifest.webmanifest",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(VERSION)
      .then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  // Never cache analysis API responses — verdicts must always be fresh.
  if (url.pathname.startsWith("/api/")) return;

  // Static assets: stale-while-revalidate.
  if (url.pathname.startsWith("/_next/static/") || SHELL.includes(url.pathname)) {
    event.respondWith(
      caches.open(VERSION).then(async (cache) => {
        const cached = await cache.match(request);
        const fetchPromise = fetch(request)
          .then((response) => {
            if (response.ok) cache.put(request, response.clone());
            return response;
          })
          .catch(() => cached);
        return cached ?? fetchPromise;
      }),
    );
    return;
  }

  // Pages: network-first with cache fallback for offline revisits.
  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(VERSION).then((cache) => cache.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request).then((cached) => cached ?? caches.match("/"))),
  );
});
