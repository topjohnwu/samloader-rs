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

// Layout visibility, control enablement, and header/advanced option bindings.

import { refreshPairedDevicesStatus } from "../app/device.js";
import { setBusyChangeListener } from "../app/exclusive.js";
import { appendLog } from "../app/logger.js";
import { PACKAGE_SLOTS, SLOTS, state } from "../app/state.js";

// Lists the advanced options that differ from their defaults next to the folded
// "Advanced options" heading, so that e.g. a NAND erase is never hidden from view
function updateAdvancedSummary() {
  const el = document.getElementById("advanced-active");
  if (!el) return;
  const active = [];
  if (state.slots.PIT) active.push("PIT");
  const salesCode = document.getElementById("opt-sales-code")?.value.trim();
  if (salesCode) active.push(`CSC ${salesCode.toUpperCase()}`);
  document.querySelectorAll("#advanced-options .option-tile").forEach((tile) => {
    if (tile.querySelector("input[type=checkbox]")?.checked) {
      active.push(tile.querySelector(".option-tile-title")?.textContent ?? "");
    }
  });
  el.textContent = active.join(" · ");
  el.title = el.textContent;
  el.hidden = active.length === 0;
}

export function setAppVersion(version) {
  const versionEl = document.getElementById("app-version");
  if (versionEl) {
    versionEl.textContent = `v${version}`;
    versionEl.hidden = false;
  }
}

export function renderBackendOptions(backendOptions, selectedBackend) {
  const backendSelect = document.getElementById("backend-select");
  if (!backendSelect) return;
  backendSelect.replaceChildren(
    ...backendOptions.map(({ id, label }) => {
      const opt = document.createElement("option");
      opt.value = id;
      opt.textContent = label;
      return opt;
    })
  );
  if (selectedBackend !== null) {
    backendSelect.value = selectedBackend;
  }
  backendSelect.disabled = state.isBusy || backendOptions.length === 0;
}

// Applies static layout visibility and copy based on detected browser capabilities.
// Called once at startup and again only if capabilities change after WASM loads.
export function applyCapabilityLayout() {
  const { canFlash, canDownload } = state.capabilities;
  const supported = canFlash || canDownload;

  const brandPill = document.getElementById("brand-pill");
  if (brandPill) {
    if (canFlash && canDownload) {
      brandPill.textContent = "Downloader & Flasher";
      brandPill.hidden = false;
    } else if (canDownload) {
      brandPill.textContent = "Firmware Downloader";
      brandPill.hidden = false;
    } else if (canFlash) {
      brandPill.textContent = "Odin Web Flasher";
      brandPill.hidden = false;
    } else {
      brandPill.hidden = true;
    }
  }

  const backendGroup = document.getElementById("backend-selector-group");
  if (backendGroup) backendGroup.hidden = !canFlash;

  const connectionChip = document.getElementById("connection-chip");
  if (connectionChip) connectionChip.hidden = !canFlash;

  const deviceCard = document.getElementById("device-card");
  if (deviceCard) deviceCard.hidden = !canFlash;

  const deviceEmptyText = document.getElementById("device-empty-text");
  if (deviceEmptyText) {
    deviceEmptyText.innerHTML = canDownload
      ? "<strong>No device connected</strong> — optional for downloading, required for flashing"
      : "<strong>No device connected</strong> — connect a device to flash firmware";
  }

  const unsupportedCard = document.getElementById("unsupported-browser-card");
  if (unsupportedCard) {
    unsupportedCard.hidden = supported;
    if (!supported && typeof window !== "undefined" && !window.isSecureContext) {
      const titleEl = document.getElementById("unsupported-browser-title");
      const subEl = document.getElementById("unsupported-browser-subtitle");
      if (titleEl) titleEl.textContent = "Secure context required";
      if (subEl) {
        subEl.textContent =
          "This page must be served over HTTPS (or localhost) to access WebUSB, WebSerial, and browser storage.";
      }
    }
  }

  const slotsCard = document.getElementById("slots-card");
  if (slotsCard) slotsCard.hidden = !supported;

  const logCard = document.getElementById("log-card");
  if (logCard) logCard.hidden = !supported;

  const firmwareTitle = document.getElementById("firmware-card-title");
  if (firmwareTitle) {
    firmwareTitle.textContent = !canFlash && canDownload ? "Firmware downloader" : "Firmware & flashing";
  }

  const firmwareSubtitle = document.getElementById("firmware-card-subtitle");
  if (firmwareSubtitle) {
    if (canFlash && canDownload) {
      firmwareSubtitle.textContent =
        "Download official firmware from Samsung servers or load local Odin packages";
    } else if (canDownload) {
      firmwareSubtitle.textContent =
        "Download official firmware packages directly from Samsung servers";
    } else if (canFlash) {
      firmwareSubtitle.textContent =
        "Select local Odin packages or individual partition files to flash";
    }
  }

  const sourceSwitcher = document.getElementById("source-switcher");
  if (sourceSwitcher) sourceSwitcher.hidden = !(canFlash && canDownload);

  const advancedOptions = document.getElementById("advanced-options");
  if (advancedOptions) advancedOptions.hidden = !canFlash;

  const whenDoneGroup = document.getElementById("when-done-group");
  if (whenDoneGroup) whenDoneGroup.hidden = !canFlash;

  const downloadOnlyBtn = document.getElementById("btn-download-only");
  if (downloadOnlyBtn) {
    downloadOnlyBtn.classList.toggle("btn-primary", !canFlash);
    downloadOnlyBtn.classList.toggle("btn-outline", canFlash);
  }
}

export function updateControlsState() {
  updateAdvancedSummary();
  const { canFlash, canDownload } = state.capabilities;
  if (!canDownload && canFlash) {
    state.firmwareSource = "local";
  } else if (!canFlash && canDownload) {
    state.firmwareSource = "server";
  }

  const flashBtn = document.getElementById("btn-flash-firmware");
  const activeEntries = Object.entries(state.slots).filter(([_, f]) => f !== null);
  const eraseChk = document.getElementById("opt-nand-erase");
  const salesCodeInput = document.getElementById("opt-sales-code");
  const hasAction =
    activeEntries.length > 0 ||
    state.partitions.length > 0 ||
    Boolean(eraseChk && eraseChk.checked) ||
    Boolean(salesCodeInput && salesCodeInput.value.trim().length > 0);
  const hasPendingOrInvalidMd5 = activeEntries.some(([slot]) => {
    const res = state.md5Results[slot];
    return !res || ["queued", "verifying", "invalid"].includes(res.status);
  });
  const hasDownloadDevice = canFlash && state.device?.mode === "download";
  const isServer = canDownload && (!canFlash || state.firmwareSource === "server");
  const isLocal = canFlash && (!canDownload || state.firmwareSource === "local");
  const busy = state.isBusy;
  const serverBusy = busy || state.serverQuerying;

  // Source panels visibility
  const serverPanel = document.getElementById("server-panel");
  const localPanel = document.getElementById("local-panel");
  if (serverPanel) serverPanel.hidden = !isServer;
  if (localPanel) localPanel.hidden = !isLocal;

  document.querySelectorAll('input[name="firmware-source"]').forEach((el) => {
    el.checked = el.value === state.firmwareSource;
    el.disabled = serverBusy;
  });

  // Action bar buttons visibility & disabled state
  const dumpPitBtn = document.getElementById("btn-dump-pit");
  if (dumpPitBtn) {
    dumpPitBtn.hidden = !canFlash || (isServer && !hasDownloadDevice);
    dumpPitBtn.disabled = busy || !hasDownloadDevice;
  }

  const savePitBtn = document.getElementById("btn-save-pit");
  if (savePitBtn) {
    savePitBtn.hidden = !canFlash || !state.hasLastPit || (isServer && !hasDownloadDevice);
    savePitBtn.disabled = busy;
  }

  if (flashBtn) {
    flashBtn.hidden = !isLocal;
    flashBtn.disabled =
      !hasAction || !hasDownloadDevice || busy || hasPendingOrInvalidMd5;
  }

  const bridgeReady = canDownload && state.fusBridge.connected;
  const modelVal = document.getElementById("server-model")?.value.trim() ?? "";
  const regionVal = document.getElementById("server-region")?.value.trim() ?? "";
  const customVerVal = document.getElementById("server-custom-version")?.value.trim() ?? "";
  const sel = state.serverSelection;

  const downloadOnlyBtn = document.getElementById("btn-download-only");
  if (downloadOnlyBtn) {
    downloadOnlyBtn.hidden = !isServer;
    downloadOnlyBtn.disabled =
      !bridgeReady || !state.serverInspect || !sel.validForDownload || serverBusy;
  }

  const downloadFlashBtn = document.getElementById("btn-download-flash");
  if (downloadFlashBtn) {
    downloadFlashBtn.hidden = !(isServer && canFlash);
    downloadFlashBtn.disabled =
      !bridgeReady ||
      !hasDownloadDevice ||
      !state.serverInspect ||
      !sel.validForFlash ||
      serverBusy;
  }

  const flashHint = document.getElementById("server-flash-hint");
  if (flashHint) {
    let hintText = "";
    if (isServer && canFlash && !busy && state.serverInspect) {
      if (state.serverOutputMode === "zip") {
        hintText =
          "Full .zip archives are download-only — select Extract Components to enable Download & Flash.";
      } else if (sel.hasBothCsc) {
        hintText =
          "Download & Flash cannot flash both CSCs — choose either Keep Data (HOME_CSC) or Wipe Data (CSC).";
      } else if (!sel.hasOdinComponent) {
        hintText =
          "Select at least one Odin component (BL, AP, CP, CSC, or USERDATA) to enable Download & Flash.";
      } else if (!hasDownloadDevice) {
        hintText = "Connect a Download Mode device above to enable Download & Flash.";
      }
    }
    flashHint.textContent = hintText;
    flashHint.hidden = !hintText;
  }

  // Server panel controls
  const detectServerBtn = document.getElementById("btn-detect-server-device");
  if (detectServerBtn) {
    detectServerBtn.hidden = !canFlash || !hasDownloadDevice;
    detectServerBtn.disabled = serverBusy || !hasDownloadDevice;
  }

  const checkVersionsBtn = document.getElementById("btn-check-versions");
  if (checkVersionsBtn) {
    checkVersionsBtn.disabled =
      !bridgeReady || !modelVal || !regionVal || serverBusy;
  }

  const toggleCustomBtn = document.getElementById("btn-toggle-custom-version");
  if (toggleCustomBtn) {
    toggleCustomBtn.disabled = !bridgeReady || serverBusy;
  }

  const inspectCustomBtn = document.getElementById("btn-inspect-custom");
  if (inspectCustomBtn) {
    inspectCustomBtn.disabled =
      !bridgeReady || !modelVal || !regionVal || !customVerVal || serverBusy;
  }

  [
    "server-model",
    "server-region",
    "btn-recheck-bridge",
    "btn-reload-bridge",
    "btn-clear-opfs-cache",
  ].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.disabled = serverBusy;
  });

  ["server-version-select", "server-custom-version", "server-concurrency"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.disabled = !bridgeReady || serverBusy;
  });

  document
    .querySelectorAll(
      'input[name="server-output-mode"], .server-entry-check, input[name="server-csc-mode"]'
    )
    .forEach((el) => {
      el.disabled = serverBusy;
    });

  const downloadActionIds = [
    "btn-detect-device",
    "btn-odin-reboot-android",
    "btn-odin-reboot-download",
  ];
  downloadActionIds.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.disabled = busy || !hasDownloadDevice;
    }
  });

  // Rebooting into Download Mode over AT is the only action a Normal Mode device supports
  const rebootDownloadBtn = document.getElementById("btn-reboot-download");
  if (rebootDownloadBtn) {
    rebootDownloadBtn.disabled = busy || state.device?.mode !== "normal";
  }

  // Clears the package slots and partition files, so only offer it when there is any
  const clearSlotsBtn = document.getElementById("btn-clear-slots");
  if (clearSlotsBtn) {
    const hasSelection =
      PACKAGE_SLOTS.some(({ id }) => state.slots[id] !== null) || state.partitions.length > 0;
    clearSlotsBtn.disabled = busy || !hasSelection;
  }

  const generalControlIds = [
    "backend-select",
    "opt-reboot-mode",
    "opt-skip-md5",
    "opt-verbose",
    "btn-pair-download",
    "btn-pair-normal",
    "btn-add-partition",
    "btn-load-into-local",
    "opt-sales-code",
    "opt-nand-erase",
    "opt-disable-verity",
    "opt-disable-verification",
    "opt-skip-size-check",
  ];
  generalControlIds.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.disabled = busy || (id === "backend-select" && el.options.length === 0);
    }
  });

  SLOTS.forEach((slot) => {
    const clearBtn = document.getElementById(`clear-${slot}`);
    if (clearBtn) {
      clearBtn.disabled = busy;
    }
    const dropzone = document.getElementById(`dropzone-${slot}`);
    dropzone?.setAttribute("aria-disabled", String(busy));
  });

  document
    .querySelectorAll(
      ".partition-target-input, .partition-item .btn-clear-slot, .btn-disconnect-device"
    )
    .forEach((el) => {
      el.disabled = busy;
    });

  document.querySelectorAll(".partition-item").forEach((el) => {
    el.draggable = !busy;
  });
}

export function setupControlsPanel() {
  setBusyChangeListener(() => updateControlsState());

  document.getElementById("backend-select")?.addEventListener("change", async (e) => {
    state.selectedBackend = e.target.value;
    appendLog(`Backend selected: ${state.selectedBackend}`);
    await refreshPairedDevicesStatus();
  });

  const rebootModeSelect = document.getElementById("opt-reboot-mode");
  if (rebootModeSelect) {
    rebootModeSelect.value = state.rebootMode;
    rebootModeSelect.addEventListener("change", (e) => {
      state.rebootMode = e.target.value;
      appendLog(`When done: ${e.target.selectedOptions[0]?.text ?? state.rebootMode}`);
    });
  }

  // Advanced options affect whether there is anything to flash, and their summary
  const advancedOptions = document.getElementById("advanced-options");
  advancedOptions?.addEventListener("input", updateControlsState);
  advancedOptions?.addEventListener("change", updateControlsState);
}
