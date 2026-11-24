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

// Connected Samsung device state, enumeration, pairing, DVIF queries, PIT dumps, and reboots.

import {
  detectDownloadDevice,
  deviceMode,
  getPairedDevices,
  isBackendSupported,
  pairDownloadDevice,
  pairSamsungDevice,
  printPit,
  rebootFromOdin,
  rebootToDownloadAt,
} from "./bridge.js";
import { runExclusive } from "./exclusive.js";
import { appendLog, reportError, requestOpenLog } from "./logger.js";
import { state } from "./state.js";

const deviceListeners = new Set();

let lastDeviceInfo = null;
let refreshGen = 0;

// The most recently dumped PIT, kept after the device reboots so it can still be saved.
// It is named after the device model if it was queried (DVIF) before dumping.
let lastPit = null;

export function onDeviceChange(listener) {
  deviceListeners.add(listener);
  return () => deviceListeners.delete(listener);
}

function notifyDeviceChange(event) {
  for (const listener of deviceListeners) {
    listener(event);
  }
}

export function hasDeviceInfo() {
  return lastDeviceInfo !== null;
}

export function getLastPitDownload() {
  if (!lastPit) return null;
  const name = (lastPit.model || "device").replace(/[^\w.-]/g, "_");
  return {
    filename: `${name}.pit`,
    data: lastPit.data,
  };
}

function setDeviceInfo(info) {
  lastDeviceInfo = info ?? null;
  state.deviceModel = info?.model ?? null;
  state.deviceSalesCode = info?.salesCode ?? null;
  state.deviceBootloaderVersion = info?.bootloaderVersion ?? null;
  notifyDeviceChange({
    type: "info",
    info: lastDeviceInfo,
    dvifQueried: Boolean(info),
  });
}

// Identifies a paired device across refreshes. Web Serial ports have no serial number,
// but unplugging a device still triggers a refresh without it, so swapping two identical
// phones clears the device info in between.
function deviceKey(backend, d) {
  return `${backend}/${d.vendorId}:${d.productId}:${d.serialNumber ?? ""}`;
}

export async function disconnectDevice(dev) {
  if (state.isBusy || !dev) return;
  try {
    await dev.disconnect();
    appendLog(`Disconnected device: ${dev.name}`);
    await refreshPairedDevicesStatus();
  } catch (err) {
    reportError(`Failed to disconnect device: ${err}`);
  }
}

export async function queryDeviceInfo() {
  await runExclusive(async () => {
    try {
      appendLog("Querying Download Mode device info (DVIF)...");
      const info = await detectDownloadDevice({
        backend: state.selectedBackend,
      });
      setDeviceInfo(info);
    } catch (err) {
      reportError(`Detection failed: ${err}`);
    }
  });
}

export async function refreshPairedDevicesStatus() {
  // Refreshes may overlap (e.g. a backend switch while a hotplug refresh is pending);
  // only the most recent one may update the state.
  const gen = ++refreshGen;
  const backend = state.selectedBackend;

  if (!backend) {
    setDeviceInfo(null);
    state.device = null;
    notifyDeviceChange({
      type: "status",
      chipConnected: false,
      chipLabel: "No Backend",
      summaryText: "No USB backend is available in this build",
      dvifQueried: false,
    });
    return;
  }

  if (!isBackendSupported(backend)) {
    setDeviceInfo(null);
    state.device = null;
    const label = backend === "vcom" ? "WebSerial" : "WebUSB";
    notifyDeviceChange({
      type: "status",
      chipConnected: false,
      chipLabel: `${label} Unavailable`,
      summaryText: `${label} is not supported in this browser`,
      dvifQueried: false,
    });
    return;
  }

  let devices;
  try {
    devices = await getPairedDevices(backend);
  } catch (err) {
    if (gen === refreshGen) {
      reportError(`Failed to enumerate paired device: ${err}`);
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
    setDeviceInfo(null);
  }

  if (!d) {
    state.device = null;
    notifyDeviceChange({
      type: "status",
      chipConnected: false,
      chipLabel: "No Device",
      summaryText: "Pair a Samsung device in Download Mode or Normal Mode",
      dvifQueried: false,
    });
    return;
  }

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

  const summaryText =
    mode === "download"
      ? "Download Mode device paired"
      : "Normal Mode device paired. Reboot it into Download Mode to flash firmware";
  const ready = sameDevice && hasDeviceInfo();

  notifyDeviceChange({
    type: "status",
    chipConnected: true,
    chipLabel: ready ? "Device Ready" : "Device Paired",
    summaryText,
    dvifQueried: false,
  });
}

export async function pairDownload() {
  if (state.isBusy || !state.selectedBackend) return;
  try {
    appendLog(`Pairing Download Mode device via ${state.selectedBackend}...`);
    await pairDownloadDevice(state.selectedBackend);
    appendLog("Download Mode device paired successfully.");
    await refreshPairedDevicesStatus();
  } catch (err) {
    appendLog(`Pairing failed: ${err}`);
  }
}

export async function pairNormal() {
  if (state.isBusy || !state.selectedBackend) return;
  try {
    appendLog(`Pairing Normal Mode device via ${state.selectedBackend}...`);
    await pairSamsungDevice(state.selectedBackend);
    appendLog("Normal Mode Samsung device paired.");
    await refreshPairedDevicesStatus();
  } catch (err) {
    appendLog(`Pairing failed: ${err}`);
  }
}

export async function rebootToDownload() {
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
      reportError(`Reboot command failed: ${err}`);
    }
  });
}

// Reboots a Download Mode device over Odin into `target` ("normal" for Android, or
// "download"), independent of the "When done" setting of flashing and PIT dumps.
export async function rebootOdin(target) {
  const label = target === "download" ? "Download Mode" : "Android";
  await runExclusive(async () => {
    try {
      appendLog(`Rebooting device to ${label} via Odin...`);
      await rebootFromOdin({
        backend: state.selectedBackend,
        rebootMode: target,
      });
      appendLog(`Reboot to ${label} command sent.`);
    } catch (err) {
      reportError(`Odin reboot failed: ${err}`);
    }
  });
}

export async function dumpPit() {
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
      state.hasLastPit = true;
      notifyDeviceChange({ type: "pit" });
      // The PIT table is printed to the log, so show it
      requestOpenLog();
    } catch (err) {
      reportError(`PIT dump failed: ${err}`);
    }
  });
}
