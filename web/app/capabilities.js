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
 * Checks whether the browser is a desktop Chromium-based browser with File System
 * Access (`showDirectoryPicker`), OPFS, Workers, and compatible Tampermonkey support.
 */
function detectDownloadSupport() {
  if (typeof navigator === "undefined" || typeof window === "undefined") return false;

  if (
    typeof window.showDirectoryPicker !== "function" ||
    typeof navigator.storage?.getDirectory !== "function" ||
    typeof Worker === "undefined"
  ) {
    return false;
  }

  const ua = String(navigator.userAgent || "");
  const brands = navigator.userAgentData?.brands;
  return (
    (Array.isArray(brands) &&
      brands.some((b) =>
        /Chromium|Google Chrome|Microsoft Edge|Opera|Brave/i.test(String(b?.brand || ""))
      )) ||
    /\b(?:Chrome|Chromium|Edg|OPR)\/\d+/i.test(ua)
  );
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
