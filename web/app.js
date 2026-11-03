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
  isWebUsbSupported,
  isWebSerialSupported,
} from "./bridge.js";
import { state } from "./ui/state.js";
import { setupLogScroller, appendLog, clearLog, saveLog } from "./ui/log.js";
import { updateControlsState, setupExclusiveGuards } from "./ui/controls.js";
import { renderPackageSlots, handleSkipMd5Change, resetSlots, setupDropzones } from "./ui/slots.js";
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
import { handleProgressEvent, executeFlashProcess } from "./ui/flash.js";

// --- WASM & Event Wiring ---
async function setupWasmAndEvents() {
  try {
    await initWasm();
    await setProgressCallback(handleProgressEvent);
    setupLogScroller();
    appendLog("WASM engine initialized successfully.");

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
        appendLog(`Reboot mode selected: ${state.rebootMode}`);
        updateControlsState();
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
    document.getElementById("opt-nand-erase")?.addEventListener("change", updateControlsState);
    document.getElementById("opt-sales-code")?.addEventListener("input", updateControlsState);

    // Pair Download Device button
    document.getElementById("btn-pair-download")?.addEventListener("click", handlePairDownload);

    // Pair Normal Device (AT) button
    document.getElementById("btn-pair-normal")?.addEventListener("click", handlePairNormal);

    // Query Device Info (DVIF)
    document.getElementById("btn-detect-device")?.addEventListener("click", async () => {
      await queryAndShowDeviceInfo();
    });

    // Reboot to Download (AT)
    document.getElementById("btn-reboot-download")?.addEventListener("click", handleRebootToDownload);

    // Reboot Device (Odin)
    document.getElementById("btn-reboot-odin")?.addEventListener("click", handleRebootOdin);

    // Dump PIT Table
    document.getElementById("btn-dump-pit")?.addEventListener("click", handleDumpPit);

    // Flash Firmware Button
    document.getElementById("btn-flash-firmware")?.addEventListener("click", async () => {
      await executeFlashProcess();
    });

    // Reset Slots
    document.getElementById("btn-reset-slots")?.addEventListener("click", resetSlots);

    // Clear Terminal
    document.getElementById("btn-clear-log")?.addEventListener("click", () => {
      clearLog();
    });

    // Save Log / Save PIT
    document.getElementById("btn-save-log")?.addEventListener("click", saveLog);
    document.getElementById("btn-save-pit")?.addEventListener("click", savePit);
  } catch (err) {
    appendLog(`WASM Initialization Error: ${err}`);
  }
}

// --- Entry Point ---
document.addEventListener("DOMContentLoaded", () => {
  renderPackageSlots();
  setupExclusiveGuards();
  setupDropzones();
  setupWasmAndEvents();
});
