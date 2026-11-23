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

function detectFlashSupport() {
  return typeof navigator !== "undefined" && ("usb" in navigator || "serial" in navigator);
}

/**
 * Checks whether the browser is a Chromium-based browser that can run a
 * compatible Tampermonkey FUS bridge and stream firmware downloads to disk or OPFS.
 *
 * Supported:
 * - Desktop Chromium browsers (Chrome, Edge, Brave, Opera, Vivaldi, etc.)
 * - Edge on Android
 *
 * Unsupported:
 * - Non-Chromium browsers (Firefox, Safari, etc.) and all iOS / iPadOS browsers.
 * - Stock Chrome and WebView browsers on Android (no extension support).
 * - Contexts without Worker or File System Access / OPFS support.
 */
function detectDownloadSupport() {
  if (typeof navigator === "undefined" || typeof window === "undefined") return false;

  const hasStorage =
    typeof window.showDirectoryPicker === "function" ||
    typeof navigator.storage?.getDirectory === "function";
  if (!hasStorage || typeof Worker === "undefined") {
    return false;
  }

  const ua = String(navigator.userAgent || "");

  // All iOS / iPadOS browsers use WebKit (including iPadOS desktop-mode Safari).
  const isIos =
    /iPhone|iPad|iPod/i.test(ua) ||
    (navigator.platform === "MacIntel" && Number(navigator.maxTouchPoints || 0) > 1);
  if (isIos) return false;

  // Chromium-based browsers only (Chrome, Edge, Brave, Opera, Vivaldi, Arc, etc.).
  const brands = navigator.userAgentData?.brands;
  const isChromium =
    (Array.isArray(brands) &&
      brands.some((b) =>
        /Chromium|Google Chrome|Microsoft Edge|Opera|Brave/i.test(String(b?.brand || ""))
      )) ||
    /\b(?:Chrome|Chromium|Edg|EdgA|OPR)\/\d+/i.test(ua);
  if (!isChromium) return false;

  // Stock Chrome on Android cannot install extensions; Edge on Android (EdgA) can.
  const isAndroid =
    navigator.userAgentData?.platform === "Android" || /\bAndroid\b/i.test(ua);
  if (isAndroid && !/\bEdgA\/\d+/i.test(ua)) {
    return false;
  }

  return true;
}

/**
 * Detects browser capabilities required by the web app.
 * @returns {{ canFlash: boolean, canDownload: boolean }}
 */
export function detectBrowserCapabilities() {
  return {
    canFlash: detectFlashSupport(),
    canDownload: detectDownloadSupport(),
  };
}
