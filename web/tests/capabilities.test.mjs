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

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { detectBrowserCapabilities } from "../site/app/capabilities.js";

function makeEnv({
  userAgent = "",
  userAgentData = undefined,
  hasShowDirectoryPicker = true,
  hasOpfs = true,
  hasWorker = true,
  hasUsb = true,
  hasSerial = true,
} = {}) {
  const navigator = {
    userAgent,
    ...(userAgentData !== undefined ? { userAgentData } : {}),
    ...(hasOpfs ? { storage: { getDirectory: async () => ({}) } } : {}),
    ...(hasUsb ? { usb: {} } : {}),
    ...(hasSerial ? { serial: {} } : {}),
  };
  const window = {
    ...(hasShowDirectoryPicker ? { showDirectoryPicker: async () => ({}) } : {}),
  };
  return {
    navigator,
    window,
    Worker: hasWorker ? class MockWorker {} : undefined,
  };
}

describe("detectBrowserCapabilities", () => {
  test("desktop Chromium browsers are marked extension-supported", () => {
    const desktopChrome = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
        userAgentData: {
          mobile: false,
          platform: "macOS",
          brands: [
            { brand: "Chromium", version: "134" },
            { brand: "Google Chrome", version: "134" },
            { brand: "Not:A-Brand", version: "24" },
          ],
        },
      })
    );
    assert.deepEqual(desktopChrome, {
      canFlash: true,
      canDownload: true,
      extensionSupport: "supported",
      isEdgeAndroid: false,
    });

    const desktopEdge = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
        userAgentData: {
          mobile: false,
          platform: "Windows",
          brands: [
            { brand: "Chromium", version: "134" },
            { brand: "Microsoft Edge", version: "134" },
          ],
        },
      })
    );
    assert.deepEqual(desktopEdge, {
      canFlash: true,
      canDownload: true,
      extensionSupport: "supported",
      isEdgeAndroid: false,
    });

    const desktopBrave = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
        userAgentData: {
          mobile: false,
          platform: "Linux",
          brands: [
            { brand: "Chromium", version: "134" },
            { brand: "Brave", version: "134" },
          ],
        },
      })
    );
    assert.deepEqual(desktopBrave, {
      canFlash: true,
      canDownload: true,
      extensionSupport: "supported",
      isEdgeAndroid: false,
    });
  });

  test("Microsoft Edge for Android is marked extension-supported with isEdgeAndroid=true", () => {
    const edgeAndroidWithHints = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36 EdgA/134.0.0.0",
        userAgentData: {
          mobile: true,
          platform: "Android",
          brands: [
            { brand: "Chromium", version: "134" },
            { brand: "Microsoft Edge", version: "134" },
            { brand: "Not:A-Brand", version: "24" },
          ],
        },
        hasSerial: false,
      })
    );
    assert.deepEqual(edgeAndroidWithHints, {
      canFlash: true,
      canDownload: true,
      extensionSupport: "supported",
      isEdgeAndroid: true,
    });

    const edgeAndroidUaOnly = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; Android 14; SM-S928U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36 EdgA/134.0.0.0",
        hasSerial: false,
      })
    );
    assert.deepEqual(edgeAndroidUaOnly, {
      canFlash: true,
      canDownload: true,
      extensionSupport: "supported",
      isEdgeAndroid: true,
    });
  });

  test("Yandex Browser for Android is marked extension-supported", () => {
    const yandexAndroid = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; arm_64; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 YaBrowser/25.2.0.0 Mobile Safari/537.36",
        userAgentData: {
          mobile: true,
          platform: "Android",
          brands: [
            { brand: "Chromium", version: "132" },
            { brand: "YaBrowser", version: "25" },
          ],
        },
      })
    );
    assert.deepEqual(yandexAndroid, {
      canFlash: true,
      canDownload: true,
      extensionSupport: "supported",
      isEdgeAndroid: false,
    });
  });

  test("Chrome for Android phone and tablet are marked extensionSupport=unlikely", () => {
    const androidPhone = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
        userAgentData: {
          mobile: true,
          platform: "Android",
          brands: [
            { brand: "Chromium", version: "134" },
            { brand: "Google Chrome", version: "134" },
            { brand: "Not:A-Brand", version: "24" },
          ],
        },
        hasSerial: false,
      })
    );
    assert.deepEqual(androidPhone, {
      canFlash: true,
      canDownload: true,
      extensionSupport: "unlikely",
      isEdgeAndroid: false,
    });

    const androidTablet = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
        userAgentData: {
          mobile: false,
          platform: "Android",
          brands: [
            { brand: "Chromium", version: "134" },
            { brand: "Google Chrome", version: "134" },
          ],
        },
        hasSerial: false,
      })
    );
    assert.deepEqual(androidTablet, {
      canFlash: true,
      canDownload: true,
      extensionSupport: "unlikely",
      isEdgeAndroid: false,
    });
  });

  test("Samsung Internet, Brave/Opera Android, and Android WebView are marked unlikely", () => {
    const samsungInternet = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; Android 14; SM-S928U) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/132.0.0.0 Mobile Safari/537.36",
        userAgentData: {
          mobile: true,
          platform: "Android",
          brands: [
            { brand: "Chromium", version: "132" },
            { brand: "SamsungBrowser", version: "27" },
          ],
        },
      })
    );
    assert.equal(samsungInternet.extensionSupport, "unlikely");

    const braveAndroid = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
        userAgentData: {
          mobile: true,
          platform: "Android",
          brands: [
            { brand: "Chromium", version: "134" },
            { brand: "Brave", version: "134" },
          ],
        },
      })
    );
    assert.equal(braveAndroid.extensionSupport, "unlikely");

    const operaAndroid = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36 OPR/87.0.0.0",
        userAgentData: {
          mobile: true,
          platform: "Android",
          brands: [
            { brand: "Chromium", version: "132" },
            { brand: "Opera", version: "87" },
          ],
        },
      })
    );
    assert.equal(operaAndroid.extensionSupport, "unlikely");

    const androidWebView = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP1A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.0.0 Mobile Safari/537.36",
        userAgentData: {
          mobile: true,
          platform: "Android",
          brands: [{ brand: "Chromium", version: "134" }],
        },
      })
    );
    assert.equal(androidWebView.extensionSupport, "unlikely");
  });

  test("unbranded Android Chromium forks are classified as unknown", () => {
    const fork = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
        userAgentData: {
          mobile: true,
          platform: "Android",
          brands: [
            { brand: "Chromium", version: "134" },
            { brand: "Not_A Brand", version: "24" },
          ],
        },
      })
    );
    assert.deepEqual(fork, {
      canFlash: true,
      canDownload: true,
      extensionSupport: "unknown",
      isEdgeAndroid: false,
    });
  });

  test("browsers without File System Access API or non-Chromium engines disable downloading", () => {
    const olderAndroidChrome = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
        hasShowDirectoryPicker: false,
        hasSerial: false,
      })
    );
    assert.deepEqual(olderAndroidChrome, {
      canFlash: true,
      canDownload: false,
      extensionSupport: "unlikely",
      isEdgeAndroid: false,
    });

    const desktopFirefox = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0",
        hasShowDirectoryPicker: false,
        hasUsb: false,
        hasSerial: true,
      })
    );
    assert.deepEqual(desktopFirefox, {
      canFlash: true,
      canDownload: false,
      extensionSupport: "unlikely",
      isEdgeAndroid: false,
    });

    const firefoxWithoutSerial = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (Android 14; Mobile; rv:151.0) Gecko/151.0 Firefox/151.0",
        hasShowDirectoryPicker: false,
        hasUsb: false,
        hasSerial: false,
      })
    );
    assert.deepEqual(firefoxWithoutSerial, {
      canFlash: false,
      canDownload: false,
      extensionSupport: "unlikely",
      isEdgeAndroid: false,
    });

    const safariIos = detectBrowserCapabilities(
      makeEnv({
        userAgent:
          "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
        hasShowDirectoryPicker: false,
        hasUsb: false,
        hasSerial: false,
      })
    );
    assert.deepEqual(safariIos, {
      canFlash: false,
      canDownload: false,
      extensionSupport: "unlikely",
      isEdgeAndroid: false,
    });
  });
});
