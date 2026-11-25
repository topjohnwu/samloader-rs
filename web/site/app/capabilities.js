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

// Feature and browser capability detection for flashing and Samsung FUS downloading.

function detectFlashSupport(nav) {
  return Boolean(nav && ("usb" in nav || "serial" in nav));
}

function getBrandList(nav) {
  const brands = nav?.userAgentData?.brands;
  return Array.isArray(brands) ? brands.map((b) => String(b?.brand || "")) : [];
}

function isChromiumEngine(nav) {
  const ua = String(nav?.userAgent || "");
  const brands = getBrandList(nav);
  return (
    brands.some((b) =>
      /Chromium|Google Chrome|Microsoft Edge|Opera|Brave|SamsungBrowser|Samsung Internet|Vivaldi|YaBrowser|Yandex/i.test(
        b
      )
    ) ||
    /\b(?:Chrome|Chromium|Edg|EdgA|OPR|SamsungBrowser|YaBrowser)\/\d+/i.test(ua)
  );
}

function isMobileOrAndroid(nav) {
  const uaData = nav?.userAgentData;
  if (uaData) {
    if (uaData.mobile === true) return true;
    if (/^(?:Android|iOS)$/i.test(String(uaData.platform || ""))) return true;
  }
  const ua = String(nav?.userAgent || "");
  return /\b(?:Android|Mobile|iPhone|iPad|iPod)\b/i.test(ua);
}

function isEdgeBrowser(nav) {
  const ua = String(nav?.userAgent || "");
  const brands = getBrandList(nav);
  return brands.some((b) => /Microsoft Edge/i.test(b)) || /\bEdgA?\/\d+/i.test(ua);
}

function isYandexBrowser(nav) {
  const ua = String(nav?.userAgent || "");
  const brands = getBrandList(nav);
  return brands.some((b) => /YaBrowser|Yandex/i.test(b)) || /\bYaBrowser\/\d+/i.test(ua);
}

/**
 * Checks whether the browser is Chromium-based and exposes File System Access
 * (`showDirectoryPicker`), OPFS, and Web Workers required for FUS downloading.
 */
function detectDownloadApiSupport(env) {
  const nav = env?.navigator;
  const win = env?.window;
  const WorkerCtor = env?.Worker;
  if (!nav || !win) return false;

  if (
    typeof win.showDirectoryPicker !== "function" ||
    typeof nav.storage?.getDirectory !== "function" ||
    typeof WorkerCtor === "undefined"
  ) {
    return false;
  }

  return isChromiumEngine(nav);
}

/**
 * Classifies how likely the Chromium browser supports installing Tampermonkey extensions.
 * @returns {{ extensionSupport: "supported" | "unlikely" | "unknown", isEdgeAndroid: boolean }}
 */
function detectExtensionSupport(nav) {
  if (!isChromiumEngine(nav)) {
    return { extensionSupport: "unlikely", isEdgeAndroid: false };
  }
  if (!isMobileOrAndroid(nav)) {
    return { extensionSupport: "supported", isEdgeAndroid: false };
  }
  if (isEdgeBrowser(nav)) {
    return { extensionSupport: "supported", isEdgeAndroid: true };
  }
  if (isYandexBrowser(nav)) {
    return { extensionSupport: "supported", isEdgeAndroid: false };
  }

  const ua = String(nav?.userAgent || "");
  const brands = getBrandList(nav);
  if (
    /;\s*wv\)/i.test(ua) ||
    brands.some((b) =>
      /Google Chrome|Brave|Opera|SamsungBrowser|Samsung Internet|Vivaldi/i.test(b)
    ) ||
    /\b(?:OPR|SamsungBrowser|Vivaldi)\/\d+/i.test(ua) ||
    brands.length === 0
  ) {
    return { extensionSupport: "unlikely", isEdgeAndroid: false };
  }

  return { extensionSupport: "unknown", isEdgeAndroid: false };
}

/**
 * Detects browser capabilities required by the web app.
 * @param {{ navigator?: Navigator, window?: Window, Worker?: typeof Worker }} [env=globalThis]
 * @returns {{
 *   canFlash: boolean,
 *   canDownload: boolean,
 *   extensionSupport: "supported" | "unlikely" | "unknown",
 *   isEdgeAndroid: boolean,
 * }}
 */
export function detectBrowserCapabilities(env = globalThis) {
  const nav = env?.navigator;
  const canDownload = detectDownloadApiSupport(env);
  const { extensionSupport, isEdgeAndroid } = canDownload
    ? detectExtensionSupport(nav)
    : { extensionSupport: "unlikely", isEdgeAndroid: false };

  return {
    canFlash: detectFlashSupport(nav),
    canDownload,
    extensionSupport,
    isEdgeAndroid,
  };
}
