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

import {
  flushStateNotifications,
  getDerivedState,
  notifyStateChange,
  state,
  subscribe,
} from "../site/app/state.js";

function makeState(overrides = {}) {
  return {
    ...structuredClone(state),
    slots: { BL: null, AP: null, CP: null, CSC: null, USERDATA: null, PIT: null },
    md5Results: {},
    partitions: [],
    archiveRows: [],
    ...overrides,
  };
}

describe("getDerivedState", () => {
  test("computes capability matrices and effectiveSource without mutating input state", () => {
    const desktop = makeState({
      capabilities: { canFlash: true, canDownload: true, extensionSupport: "supported", isEdgeAndroid: false },
      isOnline: true,
      firmwareSource: "server",
    });
    const dDesktop = getDerivedState(desktop);
    assert.equal(dDesktop.supported, true);
    assert.equal(dDesktop.effectiveSource, "server");
    assert.equal(dDesktop.isServer, true);
    assert.equal(dDesktop.isLocal, false);

    // Offline PWA falls back to local without mutating state.firmwareSource
    const offline = makeState({
      capabilities: { canFlash: true, canDownload: true, extensionSupport: "supported", isEdgeAndroid: false },
      isOnline: false,
      firmwareSource: "server",
    });
    const dOffline = getDerivedState(offline);
    assert.equal(dOffline.supported, true);
    assert.equal(dOffline.canDownloadNow, false);
    assert.equal(dOffline.effectiveSource, "local");
    assert.equal(dOffline.isServer, false);
    assert.equal(dOffline.isLocal, true);
    assert.equal(offline.firmwareSource, "server");

    // Firefox WebSerial-only (canFlash, !canDownload)
    const firefox = makeState({
      capabilities: { canFlash: true, canDownload: false, extensionSupport: "unlikely", isEdgeAndroid: false },
      firmwareSource: "server",
    });
    const dFirefox = getDerivedState(firefox);
    assert.equal(dFirefox.supported, true);
    assert.equal(dFirefox.effectiveSource, "local");
    assert.equal(dFirefox.isLocal, true);
    assert.equal(firefox.firmwareSource, "server");

    // Unsupported browser (Safari/iOS)
    const safari = makeState({
      capabilities: { canFlash: false, canDownload: false, extensionSupport: "unlikely", isEdgeAndroid: false },
    });
    const dSafari = getDerivedState(safari);
    assert.equal(dSafari.supported, false);
    assert.equal(dSafari.isServer, false);
    assert.equal(dSafari.isLocal, false);
  });

  test("gates local flashing on MD5 status, device mode, and active actions", () => {
    const file = { name: "BL.tar.md5", size: 1024 };
    const base = {
      capabilities: { canFlash: true, canDownload: false, extensionSupport: "unlikely", isEdgeAndroid: false },
      device: { mode: "download" },
      slots: { BL: file, AP: null, CP: null, CSC: null, USERDATA: null, PIT: null },
    };

    for (const status of ["queued", "verifying", "invalid"]) {
      const d = getDerivedState(makeState({ ...base, md5Results: { BL: { status } } }));
      assert.equal(d.hasPendingOrInvalidMd5, true);
      assert.equal(d.canFlashLocal, false);
    }

    for (const status of ["valid", "skipped", "ready"]) {
      const d = getDerivedState(makeState({ ...base, md5Results: { BL: { status } } }));
      assert.equal(d.hasPendingOrInvalidMd5, false);
      assert.equal(d.canFlashLocal, true);
    }

    // Normal mode device blocks flashing
    const normalDev = getDerivedState(
      makeState({ ...base, device: { mode: "normal" }, md5Results: { BL: { status: "valid" } } })
    );
    assert.equal(normalDev.hasDownloadDevice, false);
    assert.equal(normalDev.hasNormalDevice, true);
    assert.equal(normalDev.canFlashLocal, false);
  });

  test("enforces Smart CSC, zip mode, and download/flash selection rules", () => {
    const bl = { name: "BL.tar.md5", component: "bl", uncompressedSize: 100 };
    const home = { name: "HOME_CSC.tar.md5", component: "home_csc", uncompressedSize: 200 };
    const wipe = { name: "CSC.tar.md5", component: "csc", uncompressedSize: 300 };
    const smartRow = (cscChoice, checked = true) => ({
      kind: "smart_csc",
      checked,
      cscChoice,
      homeEntry: home,
      wipeEntry: wipe,
    });

    const common = {
      fusBridge: { checked: true, connected: true, version: "1.0.0", outdated: false },
      device: { mode: "download" },
      serverInspect: { model: "SM-S931U1", region: "XAA", version: "V1", info: {} },
    };

    const homeSelected = getDerivedState(
      makeState({ ...common, archiveRows: [{ kind: "single", entry: bl, checked: true }, smartRow("home_csc")] })
    );
    assert.equal(homeSelected.canDownloadOnly, true);
    assert.equal(homeSelected.canDownloadAndFlash, true);
    assert.equal(homeSelected.selectedEntriesInfo.hasCscWipe, false);
    assert.equal(homeSelected.selectedEntriesInfo.totalBytes, 300);

    const wipeSelected = getDerivedState(
      makeState({ ...common, archiveRows: [smartRow("csc")] })
    );
    assert.equal(wipeSelected.canDownloadAndFlash, true);
    assert.equal(wipeSelected.selectedEntriesInfo.hasCscWipe, true);

    const bothSelected = getDerivedState(
      makeState({ ...common, archiveRows: [smartRow("both")] })
    );
    assert.equal(bothSelected.canDownloadOnly, true);
    assert.equal(bothSelected.canDownloadAndFlash, false);
    assert.equal(bothSelected.hasBothCsc, true);
    assert.match(bothSelected.serverFlashHint, /cannot flash both CSCs/);

    const zipMode = getDerivedState(
      makeState({ ...common, serverOutputMode: "zip", archiveRows: [] })
    );
    assert.equal(zipMode.canDownloadOnly, true);
    assert.equal(zipMode.canDownloadAndFlash, false);
    assert.match(zipMode.serverFlashHint, /download-only/);
  });

  test("collects activeAdvancedLabels accurately", () => {
    const d = getDerivedState(
      makeState({
        slots: { BL: null, AP: null, CP: null, CSC: null, USERDATA: null, PIT: { name: "p.pit", size: 10 } },
        flashOptions: {
          erase: true,
          disableVerity: true,
          disableVerification: false,
          skipSizeCheck: true,
          salesCode: " xaa ",
        },
      })
    );
    assert.deepEqual(d.activeAdvancedLabels, [
      "PIT",
      "CSC XAA",
      "NAND Erase (USERDATA)",
      "Disable dm-verity",
      "Skip Size Check",
    ]);
  });

  test("batches state notifications per microtask", async () => {
    let calls = 0;
    const unsub = subscribe(() => {
      calls++;
    });
    try {
      notifyStateChange();
      notifyStateChange();
      notifyStateChange();
      assert.equal(calls, 0);
      await Promise.resolve();
      assert.equal(calls, 1);

      notifyStateChange();
      flushStateNotifications();
      assert.equal(calls, 2);
    } finally {
      unsub();
    }
  });
});
