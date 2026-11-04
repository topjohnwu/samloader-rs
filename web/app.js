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

// Entry point of the web app: initializes WASM and wires the page to the modules in ui/.

import {
  initWasm,
  setProgressCallback,
  setVerbose,
  getBackendOptions,
  getVersion,
  isWebUsbSupported,
  isWebSerialSupported,
} from "./bridge.js";
import { state } from "./ui/state.js";
import {
  setupLogScroller,
  setupLogPanel,
  appendLog,
  reportError,
  clearLog,
  saveLog,
} from "./ui/log.js";
import { updateControlsState, setupExclusiveGuards } from "./ui/controls.js";
import {
  renderPackageSlots,
  handleSkipMd5Change,
  clearFirmwareSelections,
  setupDropzones,
} from "./ui/slots.js";
import {
  queryAndShowDeviceInfo,
  refreshPairedDevicesStatus,
  handlePairDownload,
  handlePairNormal,
  handleRebootToDownload,
  handleRebootOdin,
  handleDumpPit,
  savePit,
} from "./ui/device.js";
import { handleProgressEvent, executeFlashProcess, setupFlashPanel } from "./ui/flash.js";
import { setupThemeToggle } from "./ui/theme.js";

// --- WASM & Event Wiring ---
async function setupWasmAndEvents() {
  try {
    await initWasm();
    await setProgressCallback(handleProgressEvent);
    setupLogScroller();
    appendLog("WASM engine initialized successfully.");

    const version = await getVersion();
    const versionEl = document.getElementById("app-version");
    if (versionEl) {
      versionEl.textContent = `v${version}`;
      versionEl.hidden = false;
    }
    appendLog(`samloader-web version: ${version}`);

    const backendOptions = await getBackendOptions();
    appendLog(`Available backends: ${backendOptions.join(", ")}`);

    const backendSelect = document.getElementById("backend-select");
    if (backendSelect) {
      backendSelect.value = state.selectedBackend;
      backendSelect.addEventListener("change", async (e) => {
        state.selectedBackend = e.target.value;
        appendLog(`Backend selected: ${state.selectedBackend}`);
        await refreshPairedDevicesStatus();
      });
    }

    const rebootModeSelect = document.getElementById("opt-reboot-mode");
    if (rebootModeSelect) {
      rebootModeSelect.value = state.rebootMode;
      rebootModeSelect.addEventListener("change", (e) => {
        state.rebootMode = e.target.value;
        appendLog(`When done: ${e.target.selectedOptions[0]?.text ?? state.rebootMode}`);
      });
    }

    if (isWebUsbSupported()) {
      const onUsbHotplug = () => {
        if (state.selectedBackend === "nusb") {
          refreshPairedDevicesStatus();
        }
      };
      navigator.usb.addEventListener("connect", onUsbHotplug);
      navigator.usb.addEventListener("disconnect", onUsbHotplug);
    }
    if (isWebSerialSupported()) {
      const onSerialHotplug = () => {
        if (state.selectedBackend === "vcom") {
          refreshPairedDevicesStatus();
        }
      };
      navigator.serial.addEventListener("connect", onSerialHotplug);
      navigator.serial.addEventListener("disconnect", onSerialHotplug);
    }
    await refreshPairedDevicesStatus();

    document.getElementById("opt-skip-md5")?.addEventListener("change", (e) => {
      handleSkipMd5Change(e.target.checked);
    });
    document.getElementById("opt-verbose")?.addEventListener("change", async (e) => {
      const enabled = e.target.checked;
      await setVerbose(enabled);
      appendLog(`Verbose logging ${enabled ? "enabled" : "disabled"}.`);
    });
    // Advanced options affect whether there is anything to flash, and their summary
    const advancedOptions = document.getElementById("advanced-options");
    advancedOptions?.addEventListener("input", updateControlsState);
    advancedOptions?.addEventListener("change", updateControlsState);

    // Pair Download Device button
    document.getElementById("btn-pair-download")?.addEventListener("click", handlePairDownload);

    // Pair Normal Device (AT) button
    document.getElementById("btn-pair-normal")?.addEventListener("click", handlePairNormal);

    // Query Device Info (DVIF)
    document.getElementById("btn-detect-device")?.addEventListener("click", async () => {
      await queryAndShowDeviceInfo();
    });

    // Reboot to Download Mode (Normal Mode device, via AT command)
    document.getElementById("btn-reboot-download")?.addEventListener("click", handleRebootToDownload);

    // Reboot to Android / Download Mode (Download Mode device, via Odin)
    document
      .getElementById("btn-odin-reboot-android")
      ?.addEventListener("click", () => handleRebootOdin("normal"));
    document
      .getElementById("btn-odin-reboot-download")
      ?.addEventListener("click", () => handleRebootOdin("download"));

    // Dump PIT Table
    document.getElementById("btn-dump-pit")?.addEventListener("click", handleDumpPit);

    // Flash Firmware Button
    document.getElementById("btn-flash-firmware")?.addEventListener("click", async () => {
      await executeFlashProcess();
    });

    // Clear All firmware selections
    document.getElementById("btn-clear-slots")?.addEventListener("click", clearFirmwareSelections);

    // Clear Terminal
    document.getElementById("btn-clear-log")?.addEventListener("click", () => {
      clearLog();
    });

    // Save Log / Save PIT
    document.getElementById("btn-save-log")?.addEventListener("click", saveLog);
    document.getElementById("btn-save-pit")?.addEventListener("click", savePit);
  } catch (err) {
    reportError(`WASM Initialization Error: ${err}`);
  }
}

// --- Entry Point ---
document.addEventListener("DOMContentLoaded", () => {
  setupThemeToggle();
  setupLogPanel();
  setupFlashPanel();
  renderPackageSlots();
  setupExclusiveGuards();
  setupDropzones();
  setupWasmAndEvents();
});
