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
  onDeviceChange,
  pairDownload,
  pairNormal,
  queryDeviceInfo,
  rebootOdin,
  rebootToDownload,
} from "../app/device.js";
import { state } from "../app/state.js";
import { updateControlsState } from "./controls.js";
import { downloadFile } from "./util.js";

function updateConnectionChip(connected, text) {
  const chip = document.getElementById("connection-chip");
  if (chip) {
    chip.className = `status-chip ${connected ? "chip-connected" : "chip-disconnected"}`;
    const label = chip.querySelector(".chip-label");
    if (label) label.textContent = text;
  }
}

function renderDeviceInfo(info) {
  const gridEl = document.getElementById("device-info-grid");
  const boxEl = document.getElementById("device-info-box");
  if (!gridEl || !boxEl) return;

  if (!info) {
    gridEl.hidden = true;
    gridEl.innerHTML = "";
    boxEl.hidden = true;
    boxEl.textContent = "";
    return;
  }

  if (info.fields.length > 0) {
    gridEl.innerHTML = "";
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
      gridEl.appendChild(card);
    });
    gridEl.hidden = false;
    boxEl.hidden = true;
  } else {
    boxEl.textContent = "Device detected (Download mode)";
    boxEl.hidden = false;
    gridEl.hidden = true;
  }
}

function renderDeviceList() {
  const listWrap = document.getElementById("device-list-wrap");
  const listEl = document.getElementById("device-list");
  const emptyEl = document.getElementById("device-empty-state");

  if (!listEl || !listWrap || !emptyEl) return;
  listEl.innerHTML = "";

  const dev = state.device;
  if (!dev) {
    emptyEl.hidden = false;
    listWrap.hidden = true;
    updateControlsState();
    return;
  }

  emptyEl.hidden = true;
  listWrap.hidden = false;

  // A Normal Mode device only supports rebooting into Download Mode over AT, while
  // every other device action needs a Download Mode (Odin) device
  const isNormal = dev.mode === "normal";
  const normalPanel = document.getElementById("device-normal-panel");
  const actionsBar = document.getElementById("device-actions-bar");
  if (normalPanel) normalPanel.hidden = !isNormal;
  if (actionsBar) actionsBar.hidden = isNormal;

  const row = document.createElement("div");
  row.className = "device-item";

  const left = document.createElement("div");
  left.className = "device-item-left";

  const dot = document.createElement("span");
  dot.className = `device-status-dot${dev.mode === "normal" ? " dot-normal" : ""}`;

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

  const disconnectBtn = document.createElement("button");
  disconnectBtn.type = "button";
  disconnectBtn.className = "btn-clear-slot btn-disconnect-device";
  disconnectBtn.title = "Disconnect device";
  disconnectBtn.setAttribute("aria-label", `Disconnect ${dev.name}`);
  disconnectBtn.innerHTML = "&times;";
  disconnectBtn.disabled = state.isBusy;
  disconnectBtn.addEventListener("click", () => {
    disconnectDevice(dev);
  });

  right.appendChild(badge);
  right.appendChild(disconnectBtn);
  row.appendChild(left);
  row.appendChild(right);
  listEl.appendChild(row);

  updateControlsState();
}

function savePit() {
  const pit = getLastPitDownload();
  if (!pit) return;
  downloadFile(pit.filename, pit.data, "application/octet-stream");
}

export function setupDevicePanel() {
  onDeviceChange((event) => {
    switch (event.type) {
      case "info":
        renderDeviceInfo(event.info);
        if (event.info) {
          updateConnectionChip(true, "Device Ready");
        }
        break;
      case "status": {
        const summaryEl = document.getElementById("paired-devices-summary");
        if (summaryEl) summaryEl.textContent = event.summaryText;
        updateConnectionChip(event.chipConnected, event.chipLabel);
        renderDeviceList();
        break;
      }
      case "pit":
        updateControlsState();
        break;
    }
  });

  document.getElementById("btn-pair-download")?.addEventListener("click", pairDownload);
  document.getElementById("btn-pair-normal")?.addEventListener("click", pairNormal);
  document.getElementById("btn-detect-device")?.addEventListener("click", queryDeviceInfo);
  document.getElementById("btn-reboot-download")?.addEventListener("click", rebootToDownload);
  document
    .getElementById("btn-odin-reboot-android")
    ?.addEventListener("click", () => rebootOdin("normal"));
  document
    .getElementById("btn-odin-reboot-download")
    ?.addEventListener("click", () => rebootOdin("download"));
  document.getElementById("btn-dump-pit")?.addEventListener("click", dumpPit);
  document.getElementById("btn-save-pit")?.addEventListener("click", savePit);
}
