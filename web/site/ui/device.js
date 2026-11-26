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

// Connected device UI rendering and button wiring.

import {
  disconnectDevice,
  dumpPit,
  getLastPitDownload,
  pairDownload,
  pairNormal,
  queryDeviceInfo,
  rebootOdin,
  rebootToDownload,
} from "../app/device.js";
import { getDerivedState, state, subscribe } from "../app/state.js";
import { downloadFile } from "./util.js";

function savePit() {
  const pit = getLastPitDownload();
  if (!pit) return;
  downloadFile(pit.filename, pit.data, "application/octet-stream");
}

export function setupDevicePanel() {
  const els = {
    chip: document.getElementById("connection-chip"),
    chipLabel: document.querySelector("#connection-chip .chip-label"),
    summaryEl: document.getElementById("paired-devices-summary"),
    listWrap: document.getElementById("device-list-wrap"),
    listEl: document.getElementById("device-list"),
    emptyEl: document.getElementById("device-empty-state"),
    normalPanel: document.getElementById("device-normal-panel"),
    actionsBar: document.getElementById("device-actions-bar"),
    gridEl: document.getElementById("device-info-grid"),
    boxEl: document.getElementById("device-info-box"),
    pairDownloadBtn: document.getElementById("btn-pair-download"),
    pairNormalBtn: document.getElementById("btn-pair-normal"),
    detectBtn: document.getElementById("btn-detect-device"),
    rebootDownloadBtn: document.getElementById("btn-reboot-download"),
    odinRebootAndroidBtn: document.getElementById("btn-odin-reboot-android"),
    odinRebootDownloadBtn: document.getElementById("btn-odin-reboot-download"),
    dumpPitBtn: document.getElementById("btn-dump-pit"),
    savePitBtn: document.getElementById("btn-save-pit"),
  };

  let lastRenderedDevice = undefined;
  let lastRenderedInfo = undefined;
  let disconnectBtn = null;

  const renderDeviceInfo = (info) => {
    if (!els.gridEl || !els.boxEl) return;
    if (!info) {
      els.gridEl.hidden = true;
      els.gridEl.replaceChildren();
      els.boxEl.hidden = true;
      els.boxEl.textContent = "";
      return;
    }

    if (info.fields.length > 0) {
      els.gridEl.replaceChildren();
      info.fields.forEach(([label, val]) => {
        const card = document.createElement("div");
        card.className =
          label.toLowerCase() === "storage" || val.length > 20
            ? "info-stat-card stat-wide"
            : "info-stat-card";

        const labelEl = document.createElement("span");
        labelEl.className = "info-stat-label";
        labelEl.textContent = label;

        const valEl = document.createElement("span");
        valEl.className = "info-stat-value";
        valEl.textContent = val;
        valEl.title = val;

        card.appendChild(labelEl);
        card.appendChild(valEl);
        els.gridEl.appendChild(card);
      });
      els.gridEl.hidden = false;
      els.boxEl.hidden = true;
    } else {
      els.boxEl.textContent = "Device detected (Download mode)";
      els.boxEl.hidden = false;
      els.gridEl.hidden = true;
    }
  };

  const renderDeviceRow = (dev) => {
    if (!els.listEl || !els.listWrap || !els.emptyEl) return;
    els.listEl.replaceChildren();
    disconnectBtn = null;

    if (!dev) {
      els.emptyEl.hidden = false;
      els.listWrap.hidden = true;
      return;
    }

    els.emptyEl.hidden = true;
    els.listWrap.hidden = false;

    const isNormal = dev.mode === "normal";
    if (els.normalPanel) els.normalPanel.hidden = !isNormal;
    if (els.actionsBar) els.actionsBar.hidden = isNormal;

    const row = document.createElement("div");
    row.className = "device-item";

    const left = document.createElement("div");
    left.className = "device-item-left";

    const dot = document.createElement("span");
    dot.className = `device-status-dot${isNormal ? " dot-normal" : ""}`;

    const meta = document.createElement("div");
    meta.className = "device-meta";

    const nameEl = document.createElement("span");
    nameEl.className = "device-name";
    nameEl.textContent = dev.name;

    const subEl = document.createElement("span");
    subEl.className = "device-sub";
    subEl.textContent = dev.subtitle;

    meta.appendChild(nameEl);
    meta.appendChild(subEl);
    left.appendChild(dot);
    left.appendChild(meta);

    const right = document.createElement("div");
    right.className = "device-item-right";

    const badge = document.createElement("span");
    if (dev.mode === "download") {
      badge.className = "mode-badge mode-badge-download";
      badge.textContent = "Download Mode";
    } else {
      badge.className = "mode-badge mode-badge-normal";
      badge.textContent = "Normal Mode";
    }

    disconnectBtn = document.createElement("button");
    disconnectBtn.type = "button";
    disconnectBtn.className = "btn-clear-slot btn-disconnect-device";
    disconnectBtn.title = "Disconnect device";
    disconnectBtn.setAttribute("aria-label", `Disconnect ${dev.name}`);
    disconnectBtn.innerHTML = "&times;";
    disconnectBtn.addEventListener("click", () => {
      disconnectDevice(dev);
    });

    right.appendChild(badge);
    right.appendChild(disconnectBtn);
    row.appendChild(left);
    row.appendChild(right);
    els.listEl.appendChild(row);
  };

  const render = (s, d) => {
    if (els.chip) {
      els.chip.className = `status-chip ${s.deviceChipConnected ? "chip-connected" : "chip-disconnected"}`;
    }
    if (els.chipLabel) els.chipLabel.textContent = s.deviceChipLabel;
    if (els.summaryEl) els.summaryEl.textContent = s.deviceSummaryText;

    if (s.deviceInfo !== lastRenderedInfo) {
      lastRenderedInfo = s.deviceInfo;
      renderDeviceInfo(s.deviceInfo);
    }
    if (s.device !== lastRenderedDevice) {
      lastRenderedDevice = s.device;
      renderDeviceRow(s.device);
    }

    if (disconnectBtn) disconnectBtn.disabled = s.isBusy;
    if (els.pairDownloadBtn) els.pairDownloadBtn.disabled = s.isBusy;
    if (els.pairNormalBtn) els.pairNormalBtn.disabled = s.isBusy;
    if (els.detectBtn) els.detectBtn.disabled = s.isBusy || !d.hasDownloadDevice;
    if (els.odinRebootAndroidBtn) els.odinRebootAndroidBtn.disabled = s.isBusy || !d.hasDownloadDevice;
    if (els.odinRebootDownloadBtn) els.odinRebootDownloadBtn.disabled = s.isBusy || !d.hasDownloadDevice;
    if (els.rebootDownloadBtn) els.rebootDownloadBtn.disabled = s.isBusy || !d.hasNormalDevice;
  };

  els.pairDownloadBtn?.addEventListener("click", pairDownload);
  els.pairNormalBtn?.addEventListener("click", pairNormal);
  els.detectBtn?.addEventListener("click", queryDeviceInfo);
  els.rebootDownloadBtn?.addEventListener("click", rebootToDownload);
  els.odinRebootAndroidBtn?.addEventListener("click", () => rebootOdin("normal"));
  els.odinRebootDownloadBtn?.addEventListener("click", () => rebootOdin("download"));
  els.dumpPitBtn?.addEventListener("click", dumpPit);
  els.savePitBtn?.addEventListener("click", savePit);

  subscribe(render);
  render(state, getDerivedState(state));
}
