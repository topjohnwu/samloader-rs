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
  setProgressCallback,
} from "./bridge.js";
import { detectBrowserCapabilities } from "./capabilities.js";
import {
  isBackendSupported,
  isWebSerialSupported,
  isWebUsbSupported,
  refreshPairedDevicesStatus,
} from "./device.js";
import { setupExclusiveGuards } from "./exclusive.js";
import { appendLog, reportError } from "./logger.js";
import { getDerivedState, notifyStateChange, state } from "./state.js";
import { setupControlsPanel } from "../ui/controls.js";
import { setupDevicePanel } from "../ui/device.js";
import { handleProgressEvent, setupFlashPanel } from "../ui/flash.js";
import { setupLogPanel } from "../ui/log.js";
import { setupOperationPanel } from "../ui/operation.js";
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

let panelsInitialized = false;

function initPanels() {
  if (panelsInitialized) return;
  panelsInitialized = true;

  if (state.capabilities.canDownload) {
    const onConnectivityChange = () => {
      const online = navigator.onLine !== false;
      if (state.isOnline === online) return;
      const hadLocalSelection = getDerivedState().hasLocalSelection;
      state.isOnline = online;
      if (online && state.capabilities.canFlash && (hadLocalSelection || state.isBusy)) {
        state.firmwareSource = "local";
      }
      notifyStateChange();
      appendLog(
        online
          ? "Internet connection restored — download features enabled."
          : "Offline mode — download features hidden."
      );
    };
    window.addEventListener("online", onConnectivityChange);
    window.addEventListener("offline", onConnectivityChange);
  }

  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("sw.js").catch(() => {});
    });
  }

  setupExclusiveGuards();
  setupControlsPanel();
  setupLogPanel();
  setupOperationPanel();
  setupFlashPanel();
  setupDevicePanel();
  setupSlotsPanel();
  setupServerPanel();
}

// --- WASM & Hotplug Initialization ---
async function setupWasmAndEvents() {
  try {
    await initWasm();
    const allBackendOptions = await getBackendOptions();
    const backendOptions = allBackendOptions.filter((b) => isBackendSupported(b.id));
    const canFlash = backendOptions.length > 0;

    if (!canFlash && !state.capabilities.canDownload) {
      return;
    }

    if (state.capabilities.canFlash !== canFlash) {
      state.capabilities.canFlash = canFlash;
    }
    initPanels();

    await setProgressCallback(handleProgressEvent);
    appendLog("WASM engine initialized successfully.");

    const version = await getVersion();
    state.appVersion = version;
    appendLog(`samloader-web version: ${version}`);
    appendLog(`Available backends: ${backendOptions.map((b) => b.id).join(", ") || "none"}`);

    const capabilityDetails = [
      `flashing=${state.capabilities.canFlash ? "supported" : "unsupported"}`,
      `downloading=${state.capabilities.canDownload ? "supported" : "unsupported"}`,
    ];
    if (state.capabilities.canDownload) {
      capabilityDetails.push(`extensions=${state.capabilities.extensionSupport}`);
      capabilityDetails.push(`online=${state.isOnline ? "yes" : "no"}`);
    }
    appendLog(`Browser capabilities: ${capabilityDetails.join(", ")}`);

    if (!backendOptions.some((b) => b.id === state.selectedBackend)) {
      const preferVcom = isWindows() && backendOptions.some((b) => b.id === "vcom");
      state.selectedBackend = preferVcom ? "vcom" : (backendOptions[0]?.id ?? null);
    }
    state.backendOptions = backendOptions;
    notifyStateChange();

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
    if (panelsInitialized) {
      reportError(`WASM Initialization Error: ${err}`);
    }
  }
}

// --- Entry Point ---
document.addEventListener("DOMContentLoaded", () => {
  state.capabilities = detectBrowserCapabilities();
  state.isOnline = typeof navigator === "undefined" || navigator.onLine !== false;
  setupThemeToggle();

  if (state.capabilities.canFlash || state.capabilities.canDownload) {
    initPanels();
  } else {
    setupControlsPanel();
  }
  void setupWasmAndEvents();
});
