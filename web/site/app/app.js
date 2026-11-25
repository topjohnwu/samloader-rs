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

// Entry point of the web app: initializes WASM and wires app modules to the UI panels.

import {
  getBackendOptions,
  getVersion,
  initWasm,
  isBackendSupported,
  isWebSerialSupported,
  isWebUsbSupported,
  setProgressCallback,
} from "./bridge.js";
import { detectBrowserCapabilities } from "./capabilities.js";
import { refreshPairedDevicesStatus } from "./device.js";
import { setupExclusiveGuards } from "./exclusive.js";
import { appendLog, reportError } from "./logger.js";
import { state } from "./state.js";
import {
  applyCapabilityLayout,
  renderBackendOptions,
  setAppVersion,
  setupControlsPanel,
  updateControlsState,
} from "../ui/controls.js";
import { setupDevicePanel } from "../ui/device.js";
import { handleProgressEvent, setupFlashPanel } from "../ui/flash.js";
import { setupLogPanel, setupLogScroller } from "../ui/log.js";
import { setupServerPanel } from "../ui/server.js";
import { setupSlotsPanel } from "../ui/slots.js";
import { setupThemeToggle } from "../ui/theme.js";

// Use Web Serial (vcom) by default on Windows, since WebUSB requires replacing
// Samsung/usbser.sys drivers with WinUSB, whereas Web Serial works out of the box.
function isWindows() {
  if (typeof navigator === "undefined") return false;
  const uaPlatform = navigator.userAgentData?.platform;
  if (uaPlatform && uaPlatform !== "Unknown") {
    return uaPlatform === "Windows";
  }
  return /^win/i.test(navigator.platform || "") || /\bwindows\b/i.test(navigator.userAgent || "");
}

// --- WASM & Hotplug Initialization ---
async function setupWasmAndEvents() {
  try {
    await initWasm();
    await setProgressCallback(handleProgressEvent);
    setupLogScroller();
    appendLog("WASM engine initialized successfully.");

    const version = await getVersion();
    setAppVersion(version);
    appendLog(`samloader-web version: ${version}`);

    const allBackendOptions = await getBackendOptions();
    const backendOptions = allBackendOptions.filter((b) => isBackendSupported(b.id));
    appendLog(`Available backends: ${backendOptions.map((b) => b.id).join(", ") || "none"}`);

    const canFlash = backendOptions.length > 0;
    if (state.capabilities.canFlash !== canFlash) {
      state.capabilities.canFlash = canFlash;
      applyCapabilityLayout();
      updateControlsState();
    }
    appendLog(
      `Browser capabilities: flashing=${state.capabilities.canFlash ? "supported" : "unsupported"}, downloading=${state.capabilities.canDownload ? "supported" : "unsupported"}`
    );

    if (!backendOptions.some((b) => b.id === state.selectedBackend)) {
      const preferVcom = isWindows() && backendOptions.some((b) => b.id === "vcom");
      state.selectedBackend = preferVcom ? "vcom" : (backendOptions[0]?.id ?? null);
    }
    renderBackendOptions(backendOptions, state.selectedBackend);

    if (canFlash && isWebUsbSupported()) {
      const onUsbHotplug = () => {
        if (state.selectedBackend === "nusb") {
          void refreshPairedDevicesStatus();
        }
      };
      navigator.usb.addEventListener("connect", onUsbHotplug);
      navigator.usb.addEventListener("disconnect", onUsbHotplug);
    }
    if (canFlash && isWebSerialSupported()) {
      const onSerialHotplug = () => {
        if (state.selectedBackend === "vcom") {
          void refreshPairedDevicesStatus();
        }
      };
      navigator.serial.addEventListener("connect", onSerialHotplug);
      navigator.serial.addEventListener("disconnect", onSerialHotplug);
    }

    if (state.capabilities.canFlash) {
      await refreshPairedDevicesStatus();
    }
  } catch (err) {
    reportError(`WASM Initialization Error: ${err}`);
  }
}

// --- Entry Point ---
document.addEventListener("DOMContentLoaded", () => {
  state.capabilities = detectBrowserCapabilities();
  setupThemeToggle();
  applyCapabilityLayout();

  if (!state.capabilities.canFlash && !state.capabilities.canDownload) {
    return;
  }

  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("sw.js").catch(() => {});
    });
  }

  setupExclusiveGuards();
  setupControlsPanel();
  setupLogPanel();
  setupFlashPanel();
  setupDevicePanel();
  setupSlotsPanel();
  setupServerPanel();
  void setupWasmAndEvents();
});
