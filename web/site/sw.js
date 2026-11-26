// Copyright 2026 John "topjohnwu" Wu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const CACHE_NAME = "samloader-web-dev";
const PRECACHE_URLS = [
  "./",
  "./index.html",
  "./styles.css",
  "./manifest.webmanifest",
  "./favicon.svg",
  "./logo.svg",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/icon-maskable-512.png",
  "./fonts/dm-sans-latin-ext.woff2",
  "./fonts/dm-sans-latin.woff2",
  "./fonts/roboto-latin-ext.woff2",
  "./fonts/roboto-latin.woff2",
  "./fonts/roboto-mono-latin-ext.woff2",
  "./fonts/roboto-mono-latin.woff2",
  "./app/app.js",
  "./app/bridge.js",
  "./app/capabilities.js",
  "./app/device.js",
  "./app/download.js",
  "./app/exclusive.js",
  "./app/flash.js",
  "./app/format.js",
  "./app/fus_bridge.js",
  "./app/logger.js",
  "./app/opfs.js",
  "./app/server.js",
  "./app/slots.js",
  "./app/state.js",
  "./ui/controls.js",
  "./ui/device.js",
  "./ui/download.js",
  "./ui/flash.js",
  "./ui/log.js",
  "./ui/server.js",
  "./ui/slots.js",
  "./ui/theme.js",
  "./ui/util.js",
  "./workers/download.js",
  "./workers/md5.js",
  "./pkg/samloader_web.js",
  "./pkg/samloader_web_bg.wasm",
];

function shouldCache(response) {
  return Boolean(
    response &&
      response.ok &&
      response.type === "basic" &&
      !/\bno-store\b/i.test(response.headers.get("Cache-Control") || "")
  );
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE_NAME);
      await Promise.allSettled(
        PRECACHE_URLS.map(async (url) => {
          const response = await fetch(url, { cache: "reload" });
          if (shouldCache(response)) {
            await cache.put(url, response);
          }
        })
      );
      await self.skipWaiting();
    })()
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(
        names
          .filter((name) => name.startsWith("samloader-web-") && name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
      await self.clients.claim();
    })()
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.endsWith("/__fus_relay") || url.pathname.endsWith(".user.js")) return;

  event.respondWith(
    (async () => {
      try {
        const response = await fetch(request);
        if (shouldCache(response)) {
          const copy = response.clone();
          event.waitUntil(
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy)).catch(() => {})
          );
        }
        return response;
      } catch {
        const cached = await caches.match(request, { ignoreVary: true });
        if (cached) return cached;

        if (request.mode === "navigate") {
          const shell =
            (await caches.match("./index.html", { ignoreVary: true })) ||
            (await caches.match("./", { ignoreVary: true }));
          if (shell) return shell;
        }
        return Response.error();
      }
    })()
  );
});
