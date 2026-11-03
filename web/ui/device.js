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

// The connected device panel and device operations (DVIF, PIT, reboots).

import {
  isBackendSupported,
  getPairedDevices,
  pairDownloadDevice,
  pairSamsungDevice,
  detectDownloadDevice,
  rebootToDownloadAt,
  rebootFromOdin,
  printPit,
  deviceMode,
} from "../bridge.js";
import { state } from "./state.js";
import { downloadFile } from "./util.js";
import { appendLog } from "./log.js";
import { updateControlsState, runExclusive } from "./controls.js";

// --- Device List & Hardware Info Rendering ---
function renderDeviceInfo(info) {
  const gridEl = document.getElementById("device-info-grid");
  const boxEl = document.getElementById("device-info-box");
  if (!gridEl || !boxEl) return;

  state.deviceModel = info.model ?? null;
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

function clearDeviceInfo() {
  state.deviceModel = null;
  const gridEl = document.getElementById("device-info-grid");
  const boxEl = document.getElementById("device-info-box");
  if (gridEl) {
    gridEl.hidden = true;
    gridEl.innerHTML = "";
  }
  if (boxEl) {
    boxEl.hidden = true;
    boxEl.textContent = "";
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
    badge.textContent = "Normal Mode (AT)";
  }

  const disconnectBtn = document.createElement("button");
  disconnectBtn.type = "button";
  disconnectBtn.className = "btn-clear-slot btn-disconnect-device";
  disconnectBtn.title = "Disconnect device";
  disconnectBtn.setAttribute("aria-label", `Disconnect ${dev.name}`);
  disconnectBtn.innerHTML = "&times;";
  disconnectBtn.disabled = state.isBusy;
  disconnectBtn.addEventListener("click", () => {
    handleDisconnectDevice(dev);
  });

  right.appendChild(badge);
  right.appendChild(disconnectBtn);
  row.appendChild(left);
  row.appendChild(right);
  listEl.appendChild(row);

  updateControlsState();
}

async function handleDisconnectDevice(dev) {
  if (state.isBusy) return;
  try {
    await dev.disconnect();
    appendLog(`Disconnected device: ${dev.name}`);
    await refreshPairedDevicesStatus();
  } catch (err) {
    appendLog(`Failed to disconnect device: ${err}`);
  }
}

export async function queryAndShowDeviceInfo() {
  await runExclusive(async () => {
    try {
      appendLog("Querying Download Mode device info (DVIF)...");
      const info = await detectDownloadDevice({
        backend: state.selectedBackend,
      });
      renderDeviceInfo(info);
      updateConnectionChip(true, "Device Ready");
    } catch (err) {
      appendLog(`Detection failed: ${err}`);
    }
  });
}

let refreshGen = 0;

// Identifies a paired device across refreshes. Web Serial ports have no serial number,
// but unplugging a device still triggers a refresh without it, so swapping two identical
// phones clears the device info in between.
function deviceKey(backend, d) {
  return `${backend}/${d.vendorId}:${d.productId}:${d.serialNumber ?? ""}`;
}

function hasDeviceInfo() {
  const gridEl = document.getElementById("device-info-grid");
  const boxEl = document.getElementById("device-info-box");
  return Boolean((gridEl && !gridEl.hidden) || (boxEl && !boxEl.hidden));
}

export async function refreshPairedDevicesStatus() {
  // Refreshes may overlap (e.g. a backend switch while a hotplug refresh is pending);
  // only the most recent one may update the UI.
  const gen = ++refreshGen;
  const backend = state.selectedBackend;
  const summaryEl = document.getElementById("paired-devices-summary");

  if (!isBackendSupported(backend)) {
    clearDeviceInfo();
    state.device = null;
    const label = backend === "vcom" ? "WebSerial" : "WebUSB";
    if (summaryEl) summaryEl.textContent = `${label} is not supported in this browser`;
    updateConnectionChip(false, `${label} Unavailable`);
    renderDeviceList();
    return;
  }

  let devices;
  try {
    devices = await getPairedDevices(backend);
  } catch (err) {
    if (gen === refreshGen) {
      appendLog(`Failed to enumerate paired device: ${err}`);
    }
    return;
  }
  if (gen !== refreshGen) return;

  // Prefer a Download Mode device, so a Normal Mode device that happens to be listed
  // first does not disable the Download Mode actions
  const samsung = devices
    .map((dev) => ({ dev, mode: deviceMode(dev.vendorId, dev.productId) }))
    .filter(({ mode }) => mode !== undefined);
  const { dev: d, mode } = samsung.find((s) => s.mode === "download") ?? samsung[0] ?? {};

  // Only drop the queried device info when the device itself changed or disappeared
  const key = d ? deviceKey(backend, d) : null;
  const sameDevice = key !== null && key === state.device?.key;
  if (!sameDevice) {
    clearDeviceInfo();
  }

  if (!d) {
    state.device = null;
    if (summaryEl) {
      summaryEl.textContent = "Connect a Samsung device in Download Mode or Normal Mode";
    }
    updateConnectionChip(false, "No Device");
  } else {
    const vid = d.vendorId.toString(16).padStart(4, "0");
    const pid = d.productId.toString(16).padStart(4, "0");
    const name =
      d.productName ||
      (mode === "download" ? "Samsung Download Mode Device" : "Samsung USB Device");
    const serialPart = d.serialNumber ? ` • Serial ${d.serialNumber}` : "";
    state.device = {
      key,
      name,
      subtitle: `USB VID:PID ${vid}:${pid}${serialPart}`,
      mode,
      disconnect: d.disconnect,
    };
    if (summaryEl) summaryEl.textContent = "Samsung device paired";
    const ready = sameDevice && hasDeviceInfo();
    updateConnectionChip(true, ready ? "Device Ready" : "Device Paired");
  }
  renderDeviceList();
}

export async function handlePairDownload() {
  if (state.isBusy) return;
  try {
    appendLog(`Pairing Download Mode device via ${state.selectedBackend}...`);
    await pairDownloadDevice(state.selectedBackend);
    appendLog("Download Mode device paired successfully.");
    await refreshPairedDevicesStatus();
  } catch (err) {
    appendLog(`Pairing failed: ${err}`);
  }
}

export async function handlePairNormal() {
  if (state.isBusy) return;
  try {
    appendLog(`Pairing Samsung device (Normal AT) via ${state.selectedBackend}...`);
    await pairSamsungDevice(state.selectedBackend);
    appendLog("Normal Mode Samsung device paired.");
    await refreshPairedDevicesStatus();
  } catch (err) {
    appendLog(`Pairing failed: ${err}`);
  }
}

export async function handleRebootToDownload() {
  await runExclusive(async () => {
    try {
      appendLog("Requesting reboot to Download Mode via AT interface...");
      const sent = await rebootToDownloadAt({
        backend: state.selectedBackend,
      });
      if (sent) {
        appendLog(
          "AT+SUDDLMOD=0,0 reboot command sent. Add the Download Mode device once it re-enumerates."
        );
      } else {
        appendLog("Device is already in Download Mode (no AT command needed).");
      }
    } catch (err) {
      appendLog(`Reboot command failed: ${err}`);
    }
  });
}

export async function handleRebootOdin() {
  await runExclusive(async () => {
    try {
      appendLog(`Executing Odin reboot (mode: ${state.rebootMode})...`);
      await rebootFromOdin({
        backend: state.selectedBackend,
        rebootMode: state.rebootMode,
      });
      appendLog("Odin reboot executed successfully.");
    } catch (err) {
      appendLog(`Odin reboot failed: ${err}`);
    }
  });
}

export async function handleDumpPit() {
  await runExclusive(async () => {
    try {
      appendLog("Downloading device PIT table...");
      const pit = await printPit({
        backend: state.selectedBackend,
        rebootMode: state.rebootMode,
      });
      appendLog("--- PIT Table Output ---");
      appendLog(pit.text);
      lastPit = { data: pit.data, model: state.deviceModel };
      const savePitBtn = document.getElementById("btn-save-pit");
      if (savePitBtn) savePitBtn.hidden = false;
    } catch (err) {
      appendLog(`PIT dump failed: ${err}`);
    }
  });
}

// The most recently dumped PIT, kept after the device reboots so it can still be saved.
// It is named after the device model if it was queried (DVIF) before dumping.
let lastPit = null;

export function savePit() {
  if (!lastPit) return;
  const name = (lastPit.model || "device").replace(/[^\w.-]/g, "_");
  downloadFile(`${name}.pit`, lastPit.data, "application/octet-stream");
}

function updateConnectionChip(connected, text) {
  const chip = document.getElementById("connection-chip");
  if (chip) {
    chip.className = `status-chip ${connected ? "chip-connected" : "chip-disconnected"}`;
    const label = chip.querySelector(".chip-label");
    if (label) label.textContent = text;
  }
}
