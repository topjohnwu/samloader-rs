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
  pairDownloadDevice,
  pairSamsungDevice,
  printPit,
  rebootFromOdin,
  rebootToDownloadAt,
} from "./bridge.js";
import { runExclusive } from "./exclusive.js";
import { appendLog, reportError, requestOpenLog } from "./logger.js";
import { notifyStateChange, state } from "./state.js";

let mockPairedDevice = null;

function createMockDevice(productId) {
  return {
    vendorId: 0x04e8,
    productId,
    productName: "Samsung SM-F968B (Simulated)",
    serialNumber: "C1A2B3C4",
    disconnect: async () => {
      mockPairedDevice = null;
    },
  };
}

export function isWebUsbSupported() {
  return typeof navigator !== "undefined" && "usb" in navigator;
}

export function isWebSerialSupported() {
  return typeof navigator !== "undefined" && "serial" in navigator;
}

export function isBackendSupported(backend) {
  if (backend === "mock") return true;
  if (backend === "vcom") return isWebSerialSupported();
  if (backend === "nusb") return isWebUsbSupported();
  return false;
}

async function getPairedDevices(backend = "nusb") {
  if (backend === "mock") {
    return mockPairedDevice ? [mockPairedDevice] : [];
  }
  if (backend === "vcom") {
    if (!isWebSerialSupported()) {
      return [];
    }
    const ports = await navigator.serial.getPorts();
    return ports
      .map((port) => {
        const info = port.getInfo ? port.getInfo() : {};
        return {
          vendorId: info.usbVendorId,
          productId: info.usbProductId,
          productName: "Samsung Serial Port",
          serialNumber: undefined,
          disconnect: async () => {
            try {
              await port.close();
            } catch {
              // Port may not be open
            }
            if (typeof port.forget === "function") {
              await port.forget();
            }
          },
        };
      })
      .filter((d) => d.vendorId != null && d.productId != null);
  }
  if (backend !== "nusb" || !isWebUsbSupported()) {
    return [];
  }
  const devices = await navigator.usb.getDevices();
  return devices.map((d) => ({
    vendorId: d.vendorId,
    productId: d.productId,
    productName: d.productName,
    serialNumber: d.serialNumber,
    disconnect: async () => {
      if (d.opened) {
        try {
          await d.close();
        } catch {
          // Device may already be closing
        }
      }
      if (typeof d.forget === "function") {
        await d.forget();
      }
    },
  }));
}

let refreshGen = 0;

// The most recently dumped PIT, kept after the device reboots so it can still be saved.
// It is named after the device model if it was queried (DVIF) before dumping.
let lastPit = null;

export function hasDeviceInfo() {
  return state.deviceInfo !== null;
}

export function getLastPitDownload() {
  if (!lastPit) return null;
  const name = (lastPit.model || "device").replace(/[^\w.-]/g, "_");
  return {
    filename: `${name}.pit`,
    data: lastPit.data,
  };
}

function setDeviceInfo(info, { queried = false } = {}) {
  state.deviceInfo = info ?? null;
  state.deviceModel = info?.model ?? null;
  state.deviceSalesCode = info?.salesCode ?? null;
  state.deviceBootloaderVersion = info?.bootloaderVersion ?? null;
  if (info && state.device) {
    state.deviceChipConnected = true;
    state.deviceChipLabel = "Device Ready";
  }
  if (queried && info) {
    state.dvifQuerySeq++;
  }
  notifyStateChange();
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
      setDeviceInfo(info, { queried: true });
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
    state.deviceChipConnected = false;
    state.deviceChipLabel = "No Backend";
    state.deviceSummaryText = "No USB backend is available in this build";
    notifyStateChange();
    return;
  }

  if (!isBackendSupported(backend)) {
    setDeviceInfo(null);
    state.device = null;
    const label = backend === "vcom" ? "WebSerial" : "WebUSB";
    state.deviceChipConnected = false;
    state.deviceChipLabel = `${label} Unavailable`;
    state.deviceSummaryText = `${label} is not supported in this browser`;
    notifyStateChange();
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
    state.deviceChipConnected = false;
    state.deviceChipLabel = "No Device";
    state.deviceSummaryText = "Pair a Samsung device in Download Mode or Normal Mode";
    notifyStateChange();
    return;
  }

  if (!sameDevice) {
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
  }

  const ready = sameDevice && hasDeviceInfo();
  state.deviceChipConnected = true;
  state.deviceChipLabel = ready ? "Device Ready" : "Device Paired";
  state.deviceSummaryText =
    mode === "download"
      ? "Download Mode device paired"
      : "Normal Mode device paired. Reboot it into Download Mode to flash firmware";
  notifyStateChange();
}

export async function pairDownload() {
  if (state.isBusy || !state.selectedBackend) return;
  try {
    appendLog(`Pairing Download Mode device via ${state.selectedBackend}...`);
    await pairDownloadDevice(state.selectedBackend);
    if (state.selectedBackend === "mock") {
      mockPairedDevice = createMockDevice(0x685d);
    }
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
    if (state.selectedBackend === "mock") {
      mockPairedDevice = createMockDevice(0x6860);
    }
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
      notifyStateChange();
      // The PIT table is printed to the log, so show it
      requestOpenLog();
    } catch (err) {
      reportError(`PIT dump failed: ${err}`);
    }
  });
}
