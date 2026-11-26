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

// Top-level layout visibility, header controls, advanced options, and action-bar buttons.

import { refreshPairedDevicesStatus } from "../app/device.js";
import { appendLog } from "../app/logger.js";
import { getDerivedState, notifyStateChange, state, subscribe } from "../app/state.js";

let initialized = false;

export function setupControlsPanel() {
  if (initialized) return;
  initialized = true;

  const els = {
    versionEl: document.getElementById("app-version"),
    backendGroup: document.getElementById("backend-selector-group"),
    backendSelect: document.getElementById("backend-select"),
    connectionChip: document.getElementById("connection-chip"),
    deviceCard: document.getElementById("device-card"),
    deviceEmptyHint: document.getElementById("device-empty-hint"),
    unsupportedCard: document.getElementById("unsupported-browser-card"),
    unsupportedTitle: document.getElementById("unsupported-browser-title"),
    unsupportedSub: document.getElementById("unsupported-browser-subtitle"),
    unsupportedBody: document.querySelector("#unsupported-browser-card .card-body"),
    slotsCard: document.getElementById("slots-card"),
    logCard: document.getElementById("log-card"),
    firmwareTitle: document.getElementById("firmware-card-title"),
    firmwareSubtitle: document.getElementById("firmware-card-subtitle"),
    sourceSwitcher: document.getElementById("source-switcher"),
    sourceRadios: Array.from(document.querySelectorAll('input[name="firmware-source"]')),
    advancedOptions: document.getElementById("advanced-options"),
    advancedActive: document.getElementById("advanced-active"),
    whenDoneGroup: document.getElementById("when-done-group"),
    rebootModeSelect: document.getElementById("opt-reboot-mode"),
    salesCodeInput: document.getElementById("opt-sales-code"),
    eraseChk: document.getElementById("opt-nand-erase"),
    verityChk: document.getElementById("opt-disable-verity"),
    verificationChk: document.getElementById("opt-disable-verification"),
    skipSizeChk: document.getElementById("opt-skip-size-check"),
    dumpPitBtn: document.getElementById("btn-dump-pit"),
    savePitBtn: document.getElementById("btn-save-pit"),
    flashBtn: document.getElementById("btn-flash-firmware"),
    downloadOnlyBtn: document.getElementById("btn-download-only"),
    downloadFlashBtn: document.getElementById("btn-download-flash"),
    flashHint: document.getElementById("server-flash-hint"),
  };

  let lastBackendOptions = null;

  const render = (s, d) => {
    const { canFlash, canDownload } = s.capabilities;
    const { canDownloadNow, supported, effectiveSource, isServer, isLocal, hasDownloadDevice, serverBusy } = d;

    if (els.versionEl && s.appVersion) {
      els.versionEl.textContent = `v${s.appVersion}`;
      els.versionEl.hidden = false;
    }

    if (els.backendSelect && s.backendOptions !== lastBackendOptions) {
      lastBackendOptions = s.backendOptions;
      els.backendSelect.replaceChildren(
        ...s.backendOptions.map(({ id, label }) => {
          const opt = document.createElement("option");
          opt.value = id;
          opt.textContent = label;
          return opt;
        })
      );
      if (s.selectedBackend !== null) {
        els.backendSelect.value = s.selectedBackend;
      }
    }
    if (els.backendSelect) {
      if (s.selectedBackend !== null && els.backendSelect.value !== s.selectedBackend) {
        els.backendSelect.value = s.selectedBackend;
      }
      els.backendSelect.disabled = s.isBusy || s.backendOptions.length === 0;
    }

    if (els.backendGroup) els.backendGroup.hidden = !canFlash;
    if (els.connectionChip) els.connectionChip.hidden = !canFlash;
    if (els.deviceCard) els.deviceCard.hidden = !canFlash;

    if (els.deviceEmptyHint) {
      els.deviceEmptyHint.textContent = canDownloadNow
        ? "Optional for downloading · Required for flashing"
        : "Connect a device to flash firmware";
    }

    if (els.unsupportedCard) {
      els.unsupportedCard.hidden = supported;
      if (!supported) {
        const offlineOnly = !canFlash && canDownload && !s.isOnline;
        const insecure = typeof window !== "undefined" && !window.isSecureContext;
        if (els.unsupportedTitle) {
          els.unsupportedTitle.textContent = offlineOnly
            ? "You're offline"
            : insecure
              ? "Secure context required"
              : "Browser not supported";
        }
        if (els.unsupportedSub) {
          els.unsupportedSub.textContent = offlineOnly
            ? "Firmware downloading requires an internet connection. Reconnect to check versions and download from Samsung servers."
            : insecure
              ? "This page must be served over HTTPS (or localhost) to access WebUSB, WebSerial, and browser storage."
              : "This browser does not support WebUSB/WebSerial flashing or a compatible Tampermonkey bridge for Samsung FUS downloads.";
        }
        if (els.unsupportedBody) els.unsupportedBody.hidden = offlineOnly;
      }
    }

    if (els.slotsCard) els.slotsCard.hidden = !supported;
    if (els.logCard) els.logCard.hidden = !supported;

    if (els.firmwareTitle) {
      els.firmwareTitle.textContent =
        !canFlash && canDownloadNow ? "Firmware downloader" : "Firmware & flashing";
    }
    if (els.firmwareSubtitle) {
      if (canFlash && canDownloadNow) {
        els.firmwareSubtitle.textContent =
          "Download official firmware from Samsung servers or load local Odin packages";
      } else if (canDownloadNow) {
        els.firmwareSubtitle.textContent =
          "Download official firmware packages directly from Samsung servers";
      } else if (canFlash) {
        els.firmwareSubtitle.textContent =
          "Select local Odin packages or individual partition files to flash";
      }
    }

    if (els.sourceSwitcher) els.sourceSwitcher.hidden = !(canFlash && canDownloadNow);
    for (const radio of els.sourceRadios) {
      radio.checked = radio.value === effectiveSource;
      radio.disabled = serverBusy;
    }

    if (els.advancedOptions) els.advancedOptions.hidden = !canFlash;
    if (els.advancedActive) {
      const summary = d.activeAdvancedLabels.join(" · ");
      els.advancedActive.textContent = summary;
      els.advancedActive.title = summary;
      els.advancedActive.hidden = d.activeAdvancedLabels.length === 0;
    }
    for (const el of [
      els.salesCodeInput,
      els.eraseChk,
      els.verityChk,
      els.verificationChk,
      els.skipSizeChk,
      els.rebootModeSelect,
    ]) {
      if (el) el.disabled = s.isBusy;
    }

    if (els.whenDoneGroup) els.whenDoneGroup.hidden = !canFlash;

    if (els.dumpPitBtn) {
      els.dumpPitBtn.hidden = !canFlash || (isServer && !hasDownloadDevice);
      els.dumpPitBtn.disabled = s.isBusy || !hasDownloadDevice;
    }
    if (els.savePitBtn) {
      els.savePitBtn.hidden = !canFlash || !s.hasLastPit || (isServer && !hasDownloadDevice);
      els.savePitBtn.disabled = s.isBusy;
    }
    if (els.flashBtn) {
      els.flashBtn.hidden = !isLocal;
      els.flashBtn.disabled = !d.canFlashLocal;
    }
    if (els.downloadOnlyBtn) {
      els.downloadOnlyBtn.hidden = !isServer;
      els.downloadOnlyBtn.disabled = !d.canDownloadOnly;
      els.downloadOnlyBtn.classList.toggle("btn-primary", !canFlash);
      els.downloadOnlyBtn.classList.toggle("btn-outline", canFlash);
    }
    if (els.downloadFlashBtn) {
      els.downloadFlashBtn.hidden = !(isServer && canFlash);
      els.downloadFlashBtn.disabled = !d.canDownloadAndFlash;
    }
    if (els.flashHint) {
      els.flashHint.textContent = d.serverFlashHint;
      els.flashHint.hidden = !d.serverFlashHint;
    }
  };

  els.backendSelect?.addEventListener("change", async (e) => {
    state.selectedBackend = e.target.value;
    appendLog(`Backend selected: ${state.selectedBackend}`);
    notifyStateChange();
    await refreshPairedDevicesStatus();
  });

  if (els.rebootModeSelect) {
    els.rebootModeSelect.value = state.rebootMode;
    els.rebootModeSelect.addEventListener("change", (e) => {
      state.rebootMode = e.target.value;
      appendLog(`When done: ${e.target.selectedOptions[0]?.text ?? state.rebootMode}`);
      notifyStateChange();
    });
  }

  els.salesCodeInput?.addEventListener("input", () => {
    state.flashOptions.salesCode = els.salesCodeInput.value;
    notifyStateChange();
  });
  els.eraseChk?.addEventListener("change", () => {
    state.flashOptions.erase = Boolean(els.eraseChk.checked);
    notifyStateChange();
  });
  els.verityChk?.addEventListener("change", () => {
    state.flashOptions.disableVerity = Boolean(els.verityChk.checked);
    notifyStateChange();
  });
  els.verificationChk?.addEventListener("change", () => {
    state.flashOptions.disableVerification = Boolean(els.verificationChk.checked);
    notifyStateChange();
  });
  els.skipSizeChk?.addEventListener("change", () => {
    state.flashOptions.skipSizeCheck = Boolean(els.skipSizeChk.checked);
    notifyStateChange();
  });

  subscribe(render);
  render(state, getDerivedState(state));
}
