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

import {
  initWasm,
  getBackendOptions,
  isWebUsbSupported,
  isWebSerialSupported,
  getPairedDevices,
  getPairedSerialPorts,
  pairDownloadDevice,
  pairSamsungDevice,
  detectDownloadDevice,
  rebootToDownloadAt,
  rebootFromOdin,
  printPit,
  startFlash,
} from "./bridge.js";

// --- Constants & Application State ---
const SLOTS = ["BL", "AP", "CP", "CSC", "USERDATA", "PIT"];
const SAMSUNG_VID = 0x04e8;
const DOWNLOAD_MODE_PIDS = new Set([0x6601, 0x685d, 0x68c3]);

const state = {
  selectedBackend: "nusb",
  rebootMode: "normal",
  skipMd5: false,
  devices: [],
  slots: {
    BL: null,
    AP: null,
    CP: null,
    CSC: null,
    USERDATA: null,
    PIT: null,
  },
  slotRequestIds: {
    BL: 0,
    AP: 0,
    CP: 0,
    CSC: 0,
    USERDATA: 0,
    PIT: 0,
  },
  md5Results: {},
  activeMd5Slot: null,
  isBusy: false,
};

let md5Worker = null;

// --- Helper Functions ---
function appendLog(msg) {
  const logElem = document.getElementById("log-output");
  if (logElem) {
    const timestamp = new Date().toISOString().substring(11, 19);
    logElem.textContent += `\n[${timestamp}] ${msg}`;
    const container = document.querySelector(".log-terminal");
    if (container) {
      container.scrollTop = container.scrollHeight;
    }
  }
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function classifyDeviceMode(vid, pid) {
  if (vid === SAMSUNG_VID && DOWNLOAD_MODE_PIDS.has(pid)) {
    return "download";
  }
  return "normal";
}

// --- Worker Initialization & Cancellation ---
function initMd5Worker() {
  if (md5Worker) {
    md5Worker.terminate();
  }
  state.activeMd5Slot = null;
  md5Worker = new Worker(new URL("./md5_worker.js", import.meta.url), { type: "module" });

  md5Worker.onmessage = (e) => {
    const { type, fileId, requestId, percent, message, error } = e.data;

    if (requestId !== undefined && requestId !== state.slotRequestIds[fileId]) {
      return;
    }

    const badge = document.getElementById(`md5-badge-${fileId}`);
    const bar = document.getElementById(`md5-bar-${fileId}`);

    if (type === "PROGRESS") {
      state.activeMd5Slot = fileId;
      if (badge) {
        badge.className = "badge badge-hashing";
        badge.textContent = `Verifying ${percent}%`;
      }
      if (bar) {
        bar.classList.remove("progress-bar-error");
        bar.style.width = `${percent}%`;
      }
    } else if (type === "LOG") {
      state.activeMd5Slot = fileId;
      appendLog(`[MD5] ${message}`);
    } else if (type === "SUCCESS") {
      if (state.activeMd5Slot === fileId) {
        state.activeMd5Slot = null;
      }
      state.md5Results[fileId] = { status: "valid" };
      if (badge) {
        badge.className = "badge badge-valid";
        badge.textContent = "MD5 Verified";
      }
      if (bar) {
        bar.classList.remove("progress-bar-error");
        bar.style.width = "100%";
      }
      updateControlsState();
    } else if (type === "ERROR") {
      if (state.activeMd5Slot === fileId) {
        state.activeMd5Slot = null;
      }
      state.md5Results[fileId] = { status: "invalid", error };
      if (badge) {
        badge.className = "badge badge-invalid";
        badge.textContent = "MD5 Failed";
      }
      if (bar) {
        bar.classList.add("progress-bar-error");
        bar.style.width = "100%";
      }
      appendLog(`[MD5 ERROR] ${fileId}: ${error}`);
      updateControlsState();
    }
  };

  md5Worker.onerror = (err) => {
    const errorMsg = err?.message || "MD5 worker encountered an unexpected error";
    appendLog(`[MD5 WORKER ERROR] ${errorMsg}`);
    SLOTS.forEach((slot) => {
      if (state.md5Results[slot]?.status === "verifying") {
        state.md5Results[slot] = { status: "invalid", error: errorMsg };
        const badge = document.getElementById(`md5-badge-${slot}`);
        const bar = document.getElementById(`md5-bar-${slot}`);
        if (badge) {
          badge.className = "badge badge-invalid";
          badge.textContent = "MD5 Error";
        }
        if (bar) {
          bar.classList.add("progress-bar-error");
          bar.style.width = "100%";
        }
      }
    });
    state.activeMd5Slot = null;
    updateControlsState();
  };
}

function cancelSlotMd5(slot) {
  if (state.md5Results[slot]?.status !== "verifying") {
    return;
  }
  delete state.md5Results[slot];

  if (state.activeMd5Slot === slot) {
    // Abort the in-flight WASM file hash by restarting the worker and re-queuing remaining slots
    initMd5Worker();
    SLOTS.forEach((otherSlot) => {
      if (otherSlot !== slot && state.md5Results[otherSlot]?.status === "verifying") {
        const file = state.slots[otherSlot];
        const requestId = state.slotRequestIds[otherSlot];
        const badge = document.getElementById(`md5-badge-${otherSlot}`);
        const bar = document.getElementById(`md5-bar-${otherSlot}`);
        if (badge) {
          badge.className = "badge badge-hashing";
          badge.textContent = "Queued...";
        }
        if (bar) {
          bar.classList.remove("progress-bar-error");
          bar.style.width = "0%";
        }
        if (file && md5Worker) {
          md5Worker.postMessage({
            command: "VERIFY_MD5",
            fileId: otherSlot,
            requestId,
            file,
          });
        }
      }
    });
  } else if (md5Worker) {
    md5Worker.postMessage({
      command: "CANCEL_MD5",
      fileId: slot,
    });
  }
}

// --- Slot Handling & Dropzones ---
function assignFileToSlot(slot, file) {
  if (state.isBusy) return;

  cancelSlotMd5(slot);
  state.slots[slot] = file;
  const requestId = ++state.slotRequestIds[slot];

  const slotBox = document.getElementById(`slot-box-${slot}`);
  const fileNameElem = document.getElementById(`file-name-${slot}`);
  const fileSizeElem = document.getElementById(`file-size-${slot}`);
  const clearBtn = document.getElementById(`clear-${slot}`);
  const badge = document.getElementById(`md5-badge-${slot}`);
  const bar = document.getElementById(`md5-bar-${slot}`);

  if (slotBox) slotBox.classList.add("slot-populated");
  if (fileNameElem) fileNameElem.textContent = file.name;
  if (fileSizeElem) fileSizeElem.textContent = formatBytes(file.size);
  if (clearBtn) clearBtn.hidden = false;
  if (bar) bar.classList.remove("progress-bar-error");

  if (file.name.toLowerCase().endsWith(".md5")) {
    if (state.skipMd5) {
      state.md5Results[slot] = { status: "skipped" };
      if (badge) {
        badge.className = "badge badge-valid";
        badge.textContent = "MD5 Skipped";
      }
      if (bar) bar.style.width = "100%";
      appendLog(`Loaded ${slot}: ${file.name} (${formatBytes(file.size)}) — MD5 check skipped`);
    } else {
      state.md5Results[slot] = { status: "verifying" };
      if (badge) {
        badge.className = "badge badge-hashing";
        badge.textContent = "Queued...";
      }
      if (bar) bar.style.width = "0%";
      appendLog(`Loaded ${slot}: ${file.name} (${formatBytes(file.size)}) — queued for MD5 check`);

      if (md5Worker) {
        md5Worker.postMessage({
          command: "VERIFY_MD5",
          fileId: slot,
          requestId,
          file,
        });
      }
    }
  } else {
    state.md5Results[slot] = { status: "skipped" };
    if (badge) {
      badge.className = "badge badge-valid";
      badge.textContent = "Ready";
    }
    if (bar) bar.style.width = "100%";
    appendLog(`Loaded ${slot}: ${file.name} (${formatBytes(file.size)})`);
  }

  updateControlsState();
}

function handleSkipMd5Change(skip) {
  state.skipMd5 = skip;
  appendLog(`MD5 verification ${skip ? "disabled (skipped)" : "enabled"}.`);

  if (skip) {
    // Cancel any active or queued worker tasks and mark unverified .md5 slots as skipped
    if (state.activeMd5Slot !== null) {
      initMd5Worker();
    } else if (md5Worker) {
      md5Worker.postMessage({ command: "CANCEL_MD5" });
    }

    SLOTS.forEach((slot) => {
      const file = state.slots[slot];
      const status = state.md5Results[slot]?.status;
      if (file && file.name.toLowerCase().endsWith(".md5") && status !== "valid") {
        state.slotRequestIds[slot]++;
        state.md5Results[slot] = { status: "skipped" };
        const badge = document.getElementById(`md5-badge-${slot}`);
        const bar = document.getElementById(`md5-bar-${slot}`);
        if (badge) {
          badge.className = "badge badge-valid";
          badge.textContent = "MD5 Skipped";
        }
        if (bar) {
          bar.classList.remove("progress-bar-error");
          bar.style.width = "100%";
        }
      }
    });
  } else {
    // Re-queue any .md5 slots that were previously skipped
    SLOTS.forEach((slot) => {
      const file = state.slots[slot];
      if (
        file &&
        file.name.toLowerCase().endsWith(".md5") &&
        state.md5Results[slot]?.status === "skipped"
      ) {
        const requestId = ++state.slotRequestIds[slot];
        state.md5Results[slot] = { status: "verifying" };
        const badge = document.getElementById(`md5-badge-${slot}`);
        const bar = document.getElementById(`md5-bar-${slot}`);
        if (badge) {
          badge.className = "badge badge-hashing";
          badge.textContent = "Queued...";
        }
        if (bar) {
          bar.classList.remove("progress-bar-error");
          bar.style.width = "0%";
        }
        if (md5Worker) {
          md5Worker.postMessage({
            command: "VERIFY_MD5",
            fileId: slot,
            requestId,
            file,
          });
        }
      }
    });
  }

  updateControlsState();
}

function clearSlot(slot) {
  if (state.isBusy) return;

  cancelSlotMd5(slot);
  state.slots[slot] = null;
  state.slotRequestIds[slot]++;
  delete state.md5Results[slot];

  const slotBox = document.getElementById(`slot-box-${slot}`);
  const fileNameElem = document.getElementById(`file-name-${slot}`);
  const fileSizeElem = document.getElementById(`file-size-${slot}`);
  const clearBtn = document.getElementById(`clear-${slot}`);
  const badge = document.getElementById(`md5-badge-${slot}`);
  const bar = document.getElementById(`md5-bar-${slot}`);
  const fileInput = document.getElementById(`input-${slot}`);

  if (slotBox) slotBox.classList.remove("slot-populated");
  if (fileNameElem) {
    fileNameElem.textContent = slot === "PIT" ? "Select *.pit file" : `Select ${slot}_*.tar.md5`;
  }
  if (fileSizeElem) fileSizeElem.textContent = "";
  if (clearBtn) clearBtn.hidden = true;
  if (badge) {
    badge.className = "badge badge-idle";
    badge.textContent = "Empty";
  }
  if (bar) {
    bar.classList.remove("progress-bar-error");
    bar.style.width = "0%";
  }
  if (fileInput) fileInput.value = "";

  updateControlsState();
}

function matchFileNameToSlot(filename) {
  const upper = filename.toUpperCase();
  if (upper.startsWith("BL_")) return "BL";
  if (upper.startsWith("AP_") || upper.startsWith("CODE_")) return "AP";
  if (upper.startsWith("CP_") || upper.startsWith("MODEM_")) return "CP";
  if (upper.startsWith("CSC_") || upper.startsWith("HOME_CSC_")) return "CSC";
  if (upper.startsWith("USERDATA_")) return "USERDATA";
  if (upper.endsWith(".PIT")) return "PIT";
  return null;
}

function routeFilesToSlots(fileList) {
  if (state.isBusy) return;

  const groupedBySlot = new Map();
  Array.from(fileList).forEach((file) => {
    const slot = matchFileNameToSlot(file.name);
    if (slot) {
      if (!groupedBySlot.has(slot)) {
        groupedBySlot.set(slot, []);
      }
      groupedBySlot.get(slot).push(file);
    } else {
      appendLog(
        `Could not auto-match "${file.name}" to a slot — click a specific slot to assign it.`
      );
    }
  });

  for (const [slot, matchedFiles] of groupedBySlot.entries()) {
    const chosen = matchedFiles[matchedFiles.length - 1];
    if (matchedFiles.length > 1) {
      const names = matchedFiles.map((f) => `"${f.name}"`).join(", ");
      appendLog(
        `Warning: Multiple files matched slot ${slot} (${names}); assigning "${chosen.name}".`
      );
    }
    assignFileToSlot(slot, chosen);
  }
}

function setupDropzones() {
  SLOTS.forEach((slot) => {
    const dropzone = document.getElementById(`dropzone-${slot}`);
    const fileInput = document.getElementById(`input-${slot}`);
    const clearBtn = document.getElementById(`clear-${slot}`);

    if (dropzone && fileInput) {
      dropzone.addEventListener("click", (e) => {
        if (state.isBusy) return;
        if (e.target !== clearBtn) fileInput.click();
      });

      fileInput.addEventListener("change", () => {
        if (fileInput.files && fileInput.files[0]) {
          assignFileToSlot(slot, fileInput.files[0]);
        }
        fileInput.value = "";
      });

      const slotBox = document.getElementById(`slot-box-${slot}`);
      if (slotBox) {
        slotBox.addEventListener("dragover", (e) => {
          e.preventDefault();
          if (!state.isBusy) {
            slotBox.classList.add("dragover");
          }
        });
        slotBox.addEventListener("dragleave", () => {
          slotBox.classList.remove("dragover");
        });
        slotBox.addEventListener("drop", (e) => {
          e.preventDefault();
          e.stopPropagation();
          slotBox.classList.remove("dragover");
          if (!state.isBusy && e.dataTransfer.files && e.dataTransfer.files[0]) {
            assignFileToSlot(slot, e.dataTransfer.files[0]);
          }
        });
      }
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        clearSlot(slot);
      });
    }
  });

  // Multi-file auto-assign picker
  const multiBtn = document.getElementById("btn-browse-multi");
  const multiInput = document.getElementById("input-multi-files");
  if (multiBtn && multiInput) {
    multiBtn.addEventListener("click", () => {
      if (!state.isBusy) multiInput.click();
    });
    multiInput.addEventListener("change", () => {
      if (multiInput.files && multiInput.files.length > 0) {
        routeFilesToSlots(multiInput.files);
        multiInput.value = "";
      }
    });
  }

  // Global window drop auto-router
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    if (!state.isBusy && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      routeFilesToSlots(e.dataTransfer.files);
    }
  });
}

function updateControlsState() {
  const flashBtn = document.getElementById("btn-flash-firmware");
  const activeEntries = Object.entries(state.slots).filter(([_, f]) => f !== null);
  const eraseChk = document.getElementById("opt-nand-erase");
  const salesCodeInput = document.getElementById("opt-sales-code");
  const hasAction =
    activeEntries.length > 0 ||
    Boolean(eraseChk && eraseChk.checked) ||
    Boolean(salesCodeInput && salesCodeInput.value.trim().length > 0);
  const hasPendingOrInvalidMd5 = activeEntries.some(([slot]) => {
    const res = state.md5Results[slot];
    return !res || res.status === "verifying" || res.status === "invalid";
  });

  if (flashBtn) {
    flashBtn.disabled = !hasAction || state.isBusy || hasPendingOrInvalidMd5;
  }

  const hasDownloadDevice = state.devices.some((d) => d.mode === "download");
  const downloadActionIds = ["btn-detect-device", "btn-dump-pit"];
  downloadActionIds.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.disabled = state.isBusy || !hasDownloadDevice;
    }
  });

  const rebootOdinBtn = document.getElementById("btn-reboot-odin");
  if (rebootOdinBtn) {
    rebootOdinBtn.disabled =
      state.isBusy || !hasDownloadDevice || state.rebootMode === "none";
  }

  const generalControlIds = [
    "backend-select",
    "opt-reboot-mode",
    "opt-skip-md5",
    "btn-pair-download",
    "btn-pair-normal",
    "btn-pair-download-sm",
    "btn-pair-normal-sm",
    "btn-reboot-download",
    "btn-browse-multi",
    "btn-reset-slots",
    "opt-sales-code",
    "opt-nand-erase",
    "opt-disable-verity",
    "opt-disable-verification",
    "opt-skip-size-check",
  ];
  generalControlIds.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.disabled = state.isBusy;
    }
  });

  SLOTS.forEach((slot) => {
    const clearBtn = document.getElementById(`clear-${slot}`);
    if (clearBtn) {
      clearBtn.disabled = state.isBusy;
    }
  });
}

// --- Device List & Hardware Info Rendering ---
function renderDeviceInfo(infoText) {
  const gridEl = document.getElementById("device-info-grid");
  const boxEl = document.getElementById("device-info-box");
  if (!gridEl || !boxEl) return;

  const lines = infoText
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.includes(":"));

  if (lines.length >= 2) {
    gridEl.innerHTML = "";
    lines.forEach((line) => {
      const colonIdx = line.indexOf(":");
      const label = line.substring(0, colonIdx).trim();
      const val = line.substring(colonIdx + 1).trim();
      if (!label || !val) return;

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
    boxEl.textContent = infoText;
    boxEl.hidden = false;
    gridEl.hidden = true;
  }
}

function clearDeviceInfo() {
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
  const headerPair = document.getElementById("device-header-pair");

  if (!listEl || !listWrap || !emptyEl) return;
  listEl.innerHTML = "";

  if (state.devices.length === 0) {
    emptyEl.hidden = false;
    listWrap.hidden = true;
    if (headerPair) headerPair.hidden = true;
    updateControlsState();
    return;
  }

  emptyEl.hidden = true;
  listWrap.hidden = false;
  if (headerPair) {
    headerPair.hidden = state.selectedBackend === "mock";
  }

  state.devices.forEach((dev) => {
    const row = document.createElement("div");
    row.className = "device-item";
    row.setAttribute("role", "listitem");

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

    const badge = document.createElement("span");
    if (dev.mode === "download") {
      badge.className = "mode-badge mode-badge-download";
      badge.textContent = "Download Mode";
    } else {
      badge.className = "mode-badge mode-badge-normal";
      badge.textContent = "Normal Mode (AT)";
    }

    row.appendChild(left);
    row.appendChild(badge);
    listEl.appendChild(row);
  });

  updateControlsState();
}

async function runExclusive(fn) {
  if (state.isBusy) return;
  state.isBusy = true;
  updateControlsState();
  try {
    await fn();
  } finally {
    state.isBusy = false;
    updateControlsState();
  }
}

async function queryAndShowDeviceInfo() {
  await runExclusive(async () => {
    try {
      appendLog("Querying Download Mode device info (DVIF)...");
      const info = await detectDownloadDevice({
        backend: state.selectedBackend,
        verbose: true,
        onLog: appendLog,
      });
      renderDeviceInfo(info);
      updateConnectionChip(true, "Device Ready");
    } catch (err) {
      appendLog(`Detection failed: ${err}`);
    }
  });
}

async function refreshPairedDevicesStatus() {
  const summaryEl = document.getElementById("paired-devices-summary");
  clearDeviceInfo();

  if (state.selectedBackend === "mock") {
    state.devices = [
      {
        name: "Samsung SM-F968B (Simulated Odin Bootloader)",
        subtitle: "USB VID:PID 04e8:685d • Serial C1A2B3C4",
        mode: "download",
      },
    ];
    if (summaryEl) summaryEl.textContent = "Simulated Samsung device ready for testing";
    updateConnectionChip(true, "Mock Ready");
    renderDeviceList();
    await queryAndShowDeviceInfo();
    return;
  }

  if (state.selectedBackend === "vcom") {
    if (!isWebSerialSupported()) {
      state.devices = [];
      if (summaryEl) summaryEl.textContent = "WebSerial is not supported in this browser";
      updateConnectionChip(false, "WebSerial Unavailable");
      renderDeviceList();
      return;
    }
    try {
      const ports = await getPairedSerialPorts();
      const samsungPorts = ports.filter((port) => {
        const info = port.getInfo ? port.getInfo() : {};
        return info.usbVendorId === SAMSUNG_VID && info.usbProductId != null;
      });
      state.devices = samsungPorts.map((port, idx) => {
        const info = port.getInfo();
        const vid = info.usbVendorId;
        const pid = info.usbProductId;
        const vidHex = vid.toString(16).padStart(4, "0");
        const pidHex = pid.toString(16).padStart(4, "0");
        const mode = classifyDeviceMode(vid, pid);
        return {
          name: `Samsung Serial Port #${idx + 1}`,
          subtitle: `USB VID:PID ${vidHex}:${pidHex}`,
          mode,
        };
      });
      if (state.devices.length === 0) {
        if (summaryEl) summaryEl.textContent = "Connect a Samsung device via USB serial";
        updateConnectionChip(false, "No Device");
      } else {
        if (summaryEl) summaryEl.textContent = `${state.devices.length} serial port(s) paired`;
        updateConnectionChip(true, `${state.devices.length} Port(s) Paired`);
      }
      renderDeviceList();
    } catch (err) {
      appendLog(`Failed to enumerate WebSerial ports: ${err}`);
    }
    return;
  }

  if (!isWebUsbSupported()) {
    state.devices = [];
    if (summaryEl) summaryEl.textContent = "WebUSB is not supported in this browser";
    updateConnectionChip(false, "WebUSB Unavailable");
    renderDeviceList();
    return;
  }

  try {
    const usbDevices = await getPairedDevices();
    const samsungDevices = usbDevices.filter((d) => d.vendorId === SAMSUNG_VID);
    state.devices = samsungDevices.map((d) => {
      const vid = d.vendorId.toString(16).padStart(4, "0");
      const pid = d.productId.toString(16).padStart(4, "0");
      const mode = classifyDeviceMode(d.vendorId, d.productId);
      const name =
        d.productName ||
        (mode === "download" ? "Samsung Download Mode Device" : "Samsung USB Device");
      const serialPart = d.serialNumber ? ` • Serial ${d.serialNumber}` : "";
      return {
        name,
        subtitle: `USB VID:PID ${vid}:${pid}${serialPart}`,
        mode,
      };
    });

    if (state.devices.length === 0) {
      if (summaryEl) {
        summaryEl.textContent = "Connect a Samsung device in Download Mode or Normal Mode";
      }
      updateConnectionChip(false, "No Device");
    } else {
      if (summaryEl) summaryEl.textContent = `${state.devices.length} USB device(s) paired`;
      updateConnectionChip(true, `${state.devices.length} Device(s) Paired`);
    }
    renderDeviceList();
  } catch (err) {
    appendLog(`Failed to enumerate paired USB devices: ${err}`);
  }
}

async function handlePairDownload() {
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

async function handlePairNormal() {
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

// --- WASM & Event Wiring ---
async function setupWasmAndEvents() {
  try {
    await initWasm();
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
    document.getElementById("opt-nand-erase")?.addEventListener("change", updateControlsState);
    document.getElementById("opt-sales-code")?.addEventListener("input", updateControlsState);

    // Pair Download Device buttons
    document.getElementById("btn-pair-download")?.addEventListener("click", handlePairDownload);
    document.getElementById("btn-pair-download-sm")?.addEventListener("click", handlePairDownload);

    // Pair Normal Device (AT) buttons
    document.getElementById("btn-pair-normal")?.addEventListener("click", handlePairNormal);
    document.getElementById("btn-pair-normal-sm")?.addEventListener("click", handlePairNormal);

    // Query Device Info (DVIF)
    document.getElementById("btn-detect-device")?.addEventListener("click", async () => {
      await queryAndShowDeviceInfo();
    });

    // Reboot to Download (AT)
    document.getElementById("btn-reboot-download")?.addEventListener("click", async () => {
      await runExclusive(async () => {
        try {
          appendLog("Requesting reboot to Download Mode via AT interface...");
          const sent = await rebootToDownloadAt({
            backend: state.selectedBackend,
            verbose: true,
            onLog: appendLog,
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
    });

    // Reboot Device (Odin)
    document.getElementById("btn-reboot-odin")?.addEventListener("click", async () => {
      await runExclusive(async () => {
        try {
          appendLog(`Executing Odin reboot (mode: ${state.rebootMode})...`);
          await rebootFromOdin({
            backend: state.selectedBackend,
            rebootMode: state.rebootMode,
            verbose: true,
            onLog: appendLog,
          });
          appendLog("Odin reboot executed successfully.");
        } catch (err) {
          appendLog(`Odin reboot failed: ${err}`);
        }
      });
    });

    // Dump PIT Table
    document.getElementById("btn-dump-pit")?.addEventListener("click", async () => {
      await runExclusive(async () => {
        try {
          appendLog("Downloading device PIT table...");
          const pitText = await printPit({
            backend: state.selectedBackend,
            rebootMode: state.rebootMode,
            verbose: true,
            onLog: appendLog,
          });
          appendLog("--- PIT Table Output ---");
          appendLog(pitText);
        } catch (err) {
          appendLog(`PIT dump failed: ${err}`);
        }
      });
    });

    // Flash Firmware Button
    document.getElementById("btn-flash-firmware")?.addEventListener("click", async () => {
      await executeFlashProcess();
    });

    // Reset Slots
    document.getElementById("btn-reset-slots")?.addEventListener("click", () => {
      if (state.isBusy) return;
      SLOTS.forEach(clearSlot);
      appendLog("All package slots reset.");
    });

    // Clear Terminal
    document.getElementById("btn-clear-log")?.addEventListener("click", () => {
      const logElem = document.getElementById("log-output");
      if (logElem) logElem.textContent = "-- Log Cleared --";
    });
  } catch (err) {
    appendLog(`WASM Initialization Error: ${err}`);
  }
}

function updateConnectionChip(connected, text) {
  const chip = document.getElementById("connection-chip");
  if (chip) {
    chip.className = `status-chip ${connected ? "chip-connected" : "chip-disconnected"}`;
    const label = chip.querySelector(".chip-label");
    if (label) label.textContent = text;
  }
}

async function executeFlashProcess() {
  await runExclusive(async () => {
    const statusText = document.getElementById("flash-status-text");
    const percentText = document.getElementById("flash-percent-text");
    const progressBar = document.getElementById("flash-progress-bar");

    if (progressBar) {
      progressBar.classList.remove("progress-bar-error");
      progressBar.style.width = "0%";
    }
    if (percentText) percentText.textContent = "0%";
    if (statusText) statusText.textContent = "Status: Flashing Firmware...";
    appendLog("=== Starting Flashing Session ===");

    const activeSlots = Object.entries(state.slots).filter(([_, file]) => file !== null);
    if (activeSlots.length > 0) {
      appendLog(`Active flashing slots: ${activeSlots.map(([s]) => s).join(", ")}`);
    }

    try {
      const files = {};
      for (const [slot, file] of activeSlots) {
        appendLog(`Preparing slot ${slot}: ${file.name} (${formatBytes(file.size)})...`);
        files[slot] = file;
      }

      const eraseChk = document.getElementById("opt-nand-erase");
      const disableVerityChk = document.getElementById("opt-disable-verity");
      const disableVerificationChk = document.getElementById("opt-disable-verification");
      const skipSizeCheckChk = document.getElementById("opt-skip-size-check");
      const salesCodeInput = document.getElementById("opt-sales-code");

      const options = {
        reboot: state.rebootMode,
        erase: eraseChk ? eraseChk.checked : false,
        disable_verity: disableVerityChk ? disableVerityChk.checked : false,
        disable_verification: disableVerificationChk ? disableVerificationChk.checked : false,
        skip_size_check: skipSizeCheckChk ? skipSizeCheckChk.checked : false,
        sales_code:
          salesCodeInput && salesCodeInput.value.trim()
            ? salesCodeInput.value.trim().toUpperCase()
            : undefined,
      };

      appendLog(`Executing flash via backend '${state.selectedBackend}'...`);

      await startFlash(state.selectedBackend, files, options, (eventOrMsg) => {
        if (typeof eventOrMsg === "string") {
          appendLog(eventOrMsg);
        } else if (eventOrMsg && typeof eventOrMsg === "object") {
          if (eventOrMsg.type === "progress") {
            const { percent, partition } = eventOrMsg;
            if (progressBar) progressBar.style.width = `${percent}%`;
            if (percentText) percentText.textContent = `${percent}%`;
            if (statusText && partition) {
              statusText.textContent = `Status: Flashing ${partition} (${percent}%)`;
            }
          }
        }
      });

      if (progressBar) progressBar.style.width = "100%";
      if (percentText) percentText.textContent = "100%";
      if (statusText) statusText.textContent = "Status: Flashing Complete!";
      appendLog("=== Flashing Process Finished Successfully ===");
    } catch (err) {
      if (progressBar) progressBar.classList.add("progress-bar-error");
      if (statusText) statusText.textContent = "Status: Flashing Failed!";
      appendLog(`[FLASH ERROR] ${err}`);
    }
  });
}

// --- Entry Point ---
document.addEventListener("DOMContentLoaded", () => {
  initMd5Worker();
  setupDropzones();
  setupWasmAndEvents();
});
