// ==UserScript==
// @name         samloader-rs FUS Bridge
// @namespace    https://github.com/topjohnwu/samloader-rs
// @version      1.0.0
// @description  Bridges Samsung FUS requests for the samloader-rs web app (Tampermonkey)
// @author       topjohnwu
// @updateURL    https://topjohnwu.github.io/samloader-rs/samloader-fus-bridge.user.js
// @downloadURL  https://topjohnwu.github.io/samloader-rs/samloader-fus-bridge.user.js
// @match        *://*/*
// @sandbox      JavaScript
// @grant        GM.xmlHttpRequest
// @grant        unsafeWindow
// @connect      neofussvr.sslcs.cdngc.net
// @connect      cloud-neofussvr.samsungmobile.com
// @connect      fota-cloud-dn.ospserver.net
// @run-at       document-end
// ==/UserScript==

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

(function () {
  "use strict";

  if (!document.querySelector('meta[name="samloader-fus-bridge"]')) {
    return;
  }

  if (!window.location.origin || window.location.origin === "null") {
    return;
  }

  if (typeof GM === "undefined" || typeof GM.xmlHttpRequest !== "function") {
    return;
  }

  const pageWindow = typeof unsafeWindow !== "undefined" ? unsafeWindow : window;
  if (pageWindow.__samloaderFusBridge) {
    return;
  }

  const gmRequest = GM.xmlHttpRequest.bind(GM);

  function validateAllowedUrl(rawUrl) {
    if (typeof rawUrl !== "string" || !rawUrl) {
      throw new Error("Missing request URL");
    }
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch {
      throw new Error(`Invalid URL: ${rawUrl}`);
    }
    if (parsed.username || parsed.password) {
      throw new Error(`URL credentials are not allowed: ${parsed.hostname}`);
    }
    const { protocol, hostname, port } = parsed;
    if (
      protocol === "https:" &&
      (port === "" || port === "443") &&
      (hostname === "neofussvr.sslcs.cdngc.net" ||
        hostname === "fota-cloud-dn.ospserver.net")
    ) {
      return parsed.href;
    }
    if (
      protocol === "http:" &&
      (port === "" || port === "80") &&
      hostname === "cloud-neofussvr.samsungmobile.com"
    ) {
      return parsed.href;
    }
    throw new Error(`Blocked request to disallowed URL: ${parsed.origin}`);
  }

  const bridge = Object.freeze({
    version: "1.0.0",
    responseTypeStream:
      typeof GM.xmlHttpRequest.RESPONSE_TYPE_STREAM === "string"
        ? GM.xmlHttpRequest.RESPONSE_TYPE_STREAM
        : "stream",
    request(details) {
      if (!details || typeof details !== "object") {
        throw new Error("Missing request details");
      }
      const method = String(details.method || "GET").toUpperCase();
      if (method !== "GET" && method !== "POST") {
        throw new Error(`Unsupported HTTP method: ${method}`);
      }
      const url = validateAllowedUrl(details.url);
      const req = { ...details, method, url };
      delete req.user;
      delete req.password;
      const handle = gmRequest(req);
      // GM.xmlHttpRequest returns a Promise that rejects on abort/error in addition
      // to firing onabort/onerror callbacks; swallow it to avoid unhandledrejection noise.
      if (handle && typeof handle.catch === "function") {
        handle.catch(() => {});
      }
      return handle;
    },
  });

  Object.defineProperty(pageWindow, "__samloaderFusBridge", {
    value: bridge,
    configurable: false,
    enumerable: false,
    writable: false,
  });

  pageWindow.dispatchEvent(new CustomEvent("samloader-fus-bridge-ready"));
})();
