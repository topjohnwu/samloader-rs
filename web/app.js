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
  setProgressCallback,
  setVerbose,
  appendWasmLog,
  appendRawWasmLogs,
  clearWasmLog,
  exportWasmLogs,
  renderLogViewport,
  logLineHeight,
  getBackendOptions,
  isBackendSupported,
  isWebUsbSupported,
  isWebSerialSupported,
  getPairedDevices,
  pairDownloadDevice,
  pairSamsungDevice,
  detectDownloadDevice,
  rebootToDownloadAt,
  rebootFromOdin,
  printPit,
  prepareFlash,
} from "./bridge.js";

// --- Constants & Application State ---
const SLOTS = ["BL", "AP", "CP", "CSC", "USERDATA", "PIT"];
const SAMSUNG_VID = 0x04e8;
const DOWNLOAD_MODE_PIDS = new Set([0x6601, 0x685d, 0x68c3]);

const state = {
  selectedBackend: "nusb",
  rebootMode: "normal",
  skipMd5: false,
  device: null,
  slots: {
    BL: null,
    AP: null,
    CP: null,
    CSC: null,
    USERDATA: null,
    PIT: null,
  },
  md5Results: {},
  deviceModel: null, // Model reported by the last DVIF query of the current device
  partitions: [],
  nextPartitionId: 1,
  isBusy: false,
};

let draggedPartitionId = null;

// --- Virtualized Activity Log Scroller ---
let logStickToBottom = true;
let logFlushScheduled = false;

function flushLogViewport(stickToBottom = logStickToBottom) {
  const container = document.querySelector(".log-terminal");
  const logElem = document.getElementById("log-output");
  if (!container || !logElem) return;

  const view = renderLogViewport(container.scrollTop, container.clientHeight, stickToBottom);
  if (!view) return;

  if (view.totalHeight !== undefined) {
    logElem.style.height = `${view.totalHeight}px`;
  }
  if (view.paddingTop !== undefined) {
    logElem.style.paddingTop = `${view.paddingTop}px`;
  }
  if (view.text !== undefined) {
    logElem.textContent = view.text;
  }
  if (view.scrollToBottom) {
    container.scrollTop = container.scrollHeight;
  }
}

function scheduleLogFlush() {
  if (logFlushScheduled) return;
  logFlushScheduled = true;
  requestAnimationFrame(() => {
    logFlushScheduled = false;
    flushLogViewport(logStickToBottom);
  });
}

function setupLogScroller() {
  const container = document.querySelector(".log-terminal");
  const logElem = document.getElementById("log-output");
  if (!container || !logElem) return;

  // The virtualization in Rust assumes a fixed line height, so take it from there
  const lineHeight = logLineHeight();
  logElem.style.lineHeight = `${lineHeight}px`;

  container.addEventListener(
    "scroll",
    () => {
      const distanceFromBottom =
        container.scrollHeight - container.scrollTop - container.clientHeight;
      logStickToBottom = distanceFromBottom <= lineHeight * 1.5;
      flushLogViewport(false);
    },
    { passive: true }
  );

  flushLogViewport(true);
}

// --- Helper Functions ---
function appendLog(msg) {
  const queuedLines = appendWasmLog(msg);
  if (queuedLines) {
    // WASM is still initializing; show the queued lines until Rust takes over rendering
    const logElem = document.getElementById("log-output");
    if (logElem) {
      const separator = logElem.textContent ? "\n" : "";
      logElem.textContent += `${separator}${queuedLines.join("\n")}`;
    }
  }
}

function clearLog() {
  clearWasmLog();
  logStickToBottom = true;
  flushLogViewport(true);
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.max(0, Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function classifyDeviceMode(vid, pid) {
  if (vid === SAMSUNG_VID && DOWNLOAD_MODE_PIDS.has(pid)) {
    return "download";
  }
  return "normal";
}

// --- Slot Status ---
const SLOT_STATUS = {
  empty: { cls: "badge-idle", text: () => "Empty", width: 0 },
  queued: { cls: "badge-hashing", text: () => "Queued...", width: 0 },
  verifying: { cls: "badge-hashing", text: (p) => `Verifying ${p ?? 0}%`, width: null },
  valid: { cls: "badge-valid", text: () => "MD5 Verified", width: 100 },
  skipped: { cls: "badge-valid", text: () => "MD5 Skipped", width: 100 },
  ready: { cls: "badge-valid", text: () => "Ready", width: 100 },
  invalid: { cls: "badge-invalid", text: () => "MD5 Failed", width: 100, error: true },
};

/**
 * Records a slot's verification status and updates its badge and progress bar.
 * @param {string} slot
 * @param {keyof SLOT_STATUS} status
 * @param {number} [percent] Progress percentage, used by "verifying"
 * @param {string} [error] Error message, used by "invalid"
 */
function setSlotStatus(slot, status, percent, error) {
  const def = SLOT_STATUS[status];
  if (status === "empty") {
    delete state.md5Results[slot];
  } else {
    state.md5Results[slot] = { status, error };
  }

  const badge = document.getElementById(`md5-badge-${slot}`);
  const bar = document.getElementById(`md5-bar-${slot}`);
  if (badge) {
    badge.className = `badge ${def.cls}`;
    badge.textContent = def.text(percent);
  }
  if (bar) {
    bar.classList.toggle("progress-bar-error", Boolean(def.error));
    bar.style.width = `${def.width ?? percent ?? 0}%`;
  }
}

function isMd5File(file) {
  return file.name.toLowerCase().endsWith(".md5");
}

// --- MD5 Verification Queue ---
// Verification is I/O-bound, so slots are verified one at a time. The queue lives on the
// main thread and each verification runs in a fresh worker, so cancelling the active
// slot is simply terminating its worker.
const md5Queue = [];
let md5Active = null; // { slot, worker }

function scheduleMd5Pump() {
  // Deferred so that cancelling several slots in a row (e.g. Reset Slots) does not
  // spawn a worker for a slot that is about to be cancelled too.
  queueMicrotask(pumpMd5Queue);
}

function enqueueMd5(slot) {
  cancelMd5(slot);
  md5Queue.push(slot);
  setSlotStatus(slot, "queued");
  scheduleMd5Pump();
}

function cancelMd5(slot) {
  const idx = md5Queue.indexOf(slot);
  if (idx !== -1) {
    md5Queue.splice(idx, 1);
  }
  if (md5Active?.slot === slot) {
    md5Active.worker.terminate();
    md5Active = null;
    scheduleMd5Pump();
  }
}

function pumpMd5Queue() {
  if (md5Active || md5Queue.length === 0) return;
  const slot = md5Queue.shift();
  const file = state.slots[slot];
  if (!file) {
    scheduleMd5Pump();
    return;
  }

  const worker = new Worker(new URL("./md5_worker.js", import.meta.url), { type: "module" });
  md5Active = { slot, worker };

  const finish = (status, error) => {
    if (md5Active?.worker !== worker) return; // Cancelled; ignore late messages
    worker.terminate();
    md5Active = null;
    setSlotStatus(slot, status, 100, error);
    if (error) {
      appendLog(`[MD5 ERROR] ${slot}: ${error}`);
    }
    updateControlsState();
    pumpMd5Queue();
  };

  worker.onmessage = ({ data }) => {
    if (md5Active?.worker !== worker) return;
    switch (data.type) {
      case "PROGRESS":
        setSlotStatus(slot, "verifying", data.percent);
        break;
      case "LOG":
        appendRawWasmLogs(data.lines);
        break;
      case "SUCCESS":
        finish("valid");
        break;
      case "ERROR":
        finish("invalid", data.error);
        break;
    }
  };
  worker.onerror = (e) => {
    finish("invalid", e.message || "MD5 worker encountered an unexpected error");
  };

  setSlotStatus(slot, "verifying", 0);
  worker.postMessage({ file });
}

// --- Slot Handling & Dropzones ---
function assignFileToSlot(slot, file) {
  if (state.isBusy) return;

  cancelMd5(slot);
  state.slots[slot] = file;

  const slotBox = document.getElementById(`slot-box-${slot}`);
  const fileNameElem = document.getElementById(`file-name-${slot}`);
  const fileSizeElem = document.getElementById(`file-size-${slot}`);
  const clearBtn = document.getElementById(`clear-${slot}`);

  if (slotBox) slotBox.classList.add("slot-populated");
  if (fileNameElem) fileNameElem.textContent = file.name;
  if (fileSizeElem) fileSizeElem.textContent = formatBytes(file.size);
  if (clearBtn) clearBtn.hidden = false;

  const loaded = `Loaded ${slot}: ${file.name} (${formatBytes(file.size)})`;
  if (!isMd5File(file)) {
    setSlotStatus(slot, "ready");
    appendLog(loaded);
  } else if (state.skipMd5) {
    setSlotStatus(slot, "skipped");
    appendLog(`${loaded} — MD5 check skipped`);
  } else {
    enqueueMd5(slot);
    appendLog(`${loaded} — queued for MD5 check`);
  }

  updateControlsState();
}

function handleSkipMd5Change(skip) {
  state.skipMd5 = skip;
  appendLog(`MD5 verification ${skip ? "disabled (skipped)" : "enabled"}.`);

  SLOTS.forEach((slot) => {
    const file = state.slots[slot];
    if (!file || !isMd5File(file)) return;
    const status = state.md5Results[slot]?.status;
    if (skip && status !== "valid") {
      // Stop any queued or active verification and mark unverified slots as skipped
      cancelMd5(slot);
      setSlotStatus(slot, "skipped");
    } else if (!skip && status === "skipped") {
      enqueueMd5(slot);
    }
  });

  updateControlsState();
}

function clearSlot(slot) {
  if (state.isBusy) return;

  cancelMd5(slot);
  state.slots[slot] = null;
  setSlotStatus(slot, "empty");

  const slotBox = document.getElementById(`slot-box-${slot}`);
  const fileNameElem = document.getElementById(`file-name-${slot}`);
  const fileSizeElem = document.getElementById(`file-size-${slot}`);
  const clearBtn = document.getElementById(`clear-${slot}`);
  const fileInput = document.getElementById(`input-${slot}`);

  if (slotBox) slotBox.classList.remove("slot-populated");
  if (fileNameElem) {
    fileNameElem.textContent = slot === "PIT" ? "Select *.pit file" : `Select ${slot}_*.tar.md5`;
  }
  if (fileSizeElem) fileSizeElem.textContent = "";
  if (clearBtn) clearBtn.hidden = true;
  if (fileInput) fileInput.value = "";

  updateControlsState();
}

function formatPartitionLabel(partitionTarget) {
  const trimmed = partitionTarget.trim();
  if (!trimmed) {
    return "Auto-match by filename";
  }
  return /^\d+$/.test(trimmed)
    ? `Target Partition ID: ${trimmed}`
    : `Target Partition: ${trimmed}`;
}

function addPartitionFiles(fileList) {
  if (state.isBusy) return;
  const files = Array.from(fileList);
  if (files.length === 0) return;

  files.forEach((file) => {
    const id = state.nextPartitionId++;
    state.partitions.push({ id, file, partition: "" });
    appendLog(`Added partition file: ${file.name} (${formatBytes(file.size)})`);
  });

  renderPartitionList();
  updateControlsState();
}

function removePartitionFile(id) {
  if (state.isBusy) return;
  const idx = state.partitions.findIndex((p) => p.id === id);
  if (idx === -1) return;
  const [removed] = state.partitions.splice(idx, 1);
  appendLog(`Removed partition file: ${removed.file.name}`);
  renderPartitionList();
  updateControlsState();
}

function clearAllPartitions(silent = false) {
  if (state.isBusy) return;
  if (state.partitions.length === 0) return;
  state.partitions = [];
  if (!silent) {
    appendLog("Cleared all individual partition files.");
  }
  renderPartitionList();
  updateControlsState();
}

function clearPartitionDropIndicators(clearDragging = true) {
  document.querySelectorAll(".partition-item").forEach((el) => {
    el.classList.remove("drop-before", "drop-after");
    if (clearDragging) {
      el.classList.remove("dragging");
    }
  });
}

function reorderPartitionFile(draggedId, targetId, insertAfter) {
  if (draggedId === targetId) return;
  const fromIdx = state.partitions.findIndex((p) => p.id === draggedId);
  if (fromIdx === -1) return;

  const [moved] = state.partitions.splice(fromIdx, 1);
  const toIdx = state.partitions.findIndex((p) => p.id === targetId);
  if (toIdx === -1) {
    state.partitions.splice(fromIdx, 0, moved);
    return;
  }

  const insertIdx = insertAfter ? toIdx + 1 : toIdx;
  state.partitions.splice(insertIdx, 0, moved);
  renderPartitionList();
}

function renderPartitionList() {
  const sectionEl = document.getElementById("partition-files-section");
  const listEl = document.getElementById("partition-list");
  if (!sectionEl || !listEl) return;

  listEl.innerHTML = "";
  if (state.partitions.length === 0) {
    sectionEl.hidden = true;
    return;
  }

  sectionEl.hidden = false;

  state.partitions.forEach((entry) => {
    const item = document.createElement("div");
    item.className = "partition-item";
    item.setAttribute("role", "listitem");
    item.dataset.partitionId = String(entry.id);
    item.draggable = !state.isBusy;

    item.addEventListener("mousedown", (e) => {
      if (e.target.closest("input, button")) {
        item.draggable = false;
      } else {
        item.draggable = !state.isBusy;
      }
    });

    item.addEventListener("dragstart", (e) => {
      if (state.isBusy || state.partitions.length < 2) {
        e.preventDefault();
        return;
      }
      draggedPartitionId = entry.id;
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", String(entry.id));
      requestAnimationFrame(() => {
        item.classList.add("dragging");
      });
    });

    item.addEventListener("dragend", () => {
      draggedPartitionId = null;
      clearPartitionDropIndicators();
    });

    item.addEventListener("dragover", (e) => {
      if (draggedPartitionId === null || state.isBusy) return;
      e.preventDefault();
      e.stopPropagation();
      e.dataTransfer.dropEffect = "move";

      clearPartitionDropIndicators(false);
      if (draggedPartitionId === entry.id) return;

      const rect = item.getBoundingClientRect();
      const insertAfter = e.clientY > rect.top + rect.height / 2;
      item.classList.add(insertAfter ? "drop-after" : "drop-before");
    });

    item.addEventListener("drop", (e) => {
      if (draggedPartitionId === null || state.isBusy) return;
      e.preventDefault();
      e.stopPropagation();

      const sourceId = draggedPartitionId;
      draggedPartitionId = null;
      const rect = item.getBoundingClientRect();
      const insertAfter = e.clientY > rect.top + rect.height / 2;
      clearPartitionDropIndicators();
      reorderPartitionFile(sourceId, entry.id, insertAfter);
    });

    const replaceInput = document.createElement("input");
    replaceInput.type = "file";
    replaceInput.hidden = true;
    replaceInput.addEventListener("change", () => {
      if (!state.isBusy && replaceInput.files && replaceInput.files[0]) {
        entry.file = replaceInput.files[0];
        appendLog(`Updated partition file: ${entry.file.name} (${formatBytes(entry.file.size)})`);
        renderPartitionList();
        updateControlsState();
      }
      replaceInput.value = "";
    });

    const left = document.createElement("div");
    left.className = "slot-left";

    const dragHandle = document.createElement("span");
    dragHandle.className = "partition-drag-handle";
    dragHandle.title = "Drag to reorder";
    dragHandle.setAttribute("aria-hidden", "true");
    dragHandle.innerHTML =
      '<svg viewBox="0 0 16 16" fill="currentColor"><circle cx="5.5" cy="3.5" r="1.25"/><circle cx="10.5" cy="3.5" r="1.25"/><circle cx="5.5" cy="8" r="1.25"/><circle cx="10.5" cy="8" r="1.25"/><circle cx="5.5" cy="12.5" r="1.25"/><circle cx="10.5" cy="12.5" r="1.25"/></svg>';

    const fileTrigger = document.createElement("div");
    fileTrigger.className = "partition-file-trigger";
    fileTrigger.title = "Click to change file";
    fileTrigger.addEventListener("click", () => {
      if (!state.isBusy) replaceInput.click();
    });

    const badge = document.createElement("span");
    badge.className = "slot-badge";
    badge.textContent = "PART";

    const content = document.createElement("div");
    content.className = "dropzone-content";

    const labelEl = document.createElement("span");
    labelEl.className = "slot-label";
    labelEl.textContent = formatPartitionLabel(entry.partition);

    const fileNameEl = document.createElement("span");
    fileNameEl.className = "file-name";
    fileNameEl.textContent = entry.file.name;
    fileNameEl.title = entry.file.name;

    content.appendChild(labelEl);
    content.appendChild(fileNameEl);
    fileTrigger.appendChild(badge);
    fileTrigger.appendChild(content);
    left.appendChild(dragHandle);
    left.appendChild(fileTrigger);

    const right = document.createElement("div");
    right.className = "slot-right";

    const sizeEl = document.createElement("span");
    sizeEl.className = "file-size";
    sizeEl.textContent = formatBytes(entry.file.size);

    const targetInput = document.createElement("input");
    targetInput.type = "text";
    targetInput.className = "partition-target-input";
    targetInput.placeholder = "Partition name / ID (auto)";
    targetInput.value = entry.partition;
    targetInput.disabled = state.isBusy;
    targetInput.setAttribute(
      "aria-label",
      `Target partition name or ID for ${entry.file.name}`
    );
    targetInput.addEventListener("input", () => {
      entry.partition = targetInput.value;
      labelEl.textContent = formatPartitionLabel(entry.partition);
    });

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "btn-clear-slot";
    removeBtn.title = "Remove partition file";
    removeBtn.innerHTML = "&times;";
    removeBtn.disabled = state.isBusy;
    removeBtn.addEventListener("click", () => {
      removePartitionFile(entry.id);
    });

    right.appendChild(sizeEl);
    right.appendChild(targetInput);
    right.appendChild(removeBtn);

    item.appendChild(replaceInput);
    item.appendChild(left);
    item.appendChild(right);
    listEl.appendChild(item);
  });
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

  // Individual partition file picker
  const addPartBtn = document.getElementById("btn-add-partition");
  const partInput = document.getElementById("input-partition-files");
  if (addPartBtn && partInput) {
    addPartBtn.addEventListener("click", () => {
      if (!state.isBusy) partInput.click();
    });
    partInput.addEventListener("change", () => {
      if (partInput.files && partInput.files.length > 0) {
        addPartitionFiles(partInput.files);
        partInput.value = "";
      }
    });
  }

  const clearPartsBtn = document.getElementById("btn-clear-partitions");
  if (clearPartsBtn) {
    clearPartsBtn.addEventListener("click", () => {
      clearAllPartitions();
    });
  }

  const partListEl = document.getElementById("partition-list");
  if (partListEl) {
    partListEl.addEventListener("dragover", (e) => {
      if (draggedPartitionId === null || state.isBusy) return;
      e.preventDefault();
      e.stopPropagation();
      e.dataTransfer.dropEffect = "move";
    });
    partListEl.addEventListener("drop", (e) => {
      if (draggedPartitionId === null || state.isBusy) return;
      e.preventDefault();
      e.stopPropagation();

      const items = Array.from(partListEl.querySelectorAll(".partition-item"));
      const sourceId = draggedPartitionId;
      draggedPartitionId = null;

      let closestItem = null;
      let minDistance = Infinity;
      let insertAfter = false;

      items.forEach((el) => {
        const rect = el.getBoundingClientRect();
        const midY = rect.top + rect.height / 2;
        const dist = Math.abs(e.clientY - midY);
        if (dist < minDistance) {
          minDistance = dist;
          closestItem = el;
          insertAfter = e.clientY > midY;
        }
      });

      clearPartitionDropIndicators();
      if (closestItem) {
        const targetId = Number(closestItem.dataset.partitionId);
        if (!Number.isNaN(targetId)) {
          reorderPartitionFile(sourceId, targetId, insertAfter);
        }
      }
    });
  }

  // Prevent browser default navigation when files are dropped outside a dropzone
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());
}

function updateControlsState() {
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
  const hasDownloadDevice = state.device?.mode === "download";

  if (flashBtn) {
    flashBtn.disabled =
      !hasAction || !hasDownloadDevice || state.isBusy || hasPendingOrInvalidMd5;
  }

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
    "opt-verbose",
    "btn-pair-download",
    "btn-pair-normal",
    "btn-reboot-download",
    "btn-add-partition",
    "btn-clear-partitions",
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

  document
    .querySelectorAll(
      ".partition-target-input, .partition-item .btn-clear-slot, .btn-disconnect-device"
    )
    .forEach((el) => {
      el.disabled = state.isBusy;
    });

  document.querySelectorAll(".partition-item").forEach((el) => {
    el.draggable = !state.isBusy;
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

      if (label.toLowerCase() === "model") {
        state.deviceModel = val;
      }

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

// --- Exclusive Device Operations ---
// While an operation holds the device, keep the screen (and thus the USB link) awake,
// and warn before the tab is closed or reloaded, since that aborts the operation midway.
let wakeLock = null;

async function acquireWakeLock() {
  if (wakeLock || !navigator.wakeLock) return;
  try {
    const lock = await navigator.wakeLock.request("screen");
    lock.addEventListener("release", () => {
      if (wakeLock === lock) wakeLock = null;
    });
    wakeLock = lock;
  } catch {
    // Wake lock may be denied (e.g. battery saver); the operation proceeds without it
  }
}

async function releaseWakeLock() {
  const lock = wakeLock;
  wakeLock = null;
  try {
    await lock?.release();
  } catch {
    // Already released by the browser
  }
}

function setupExclusiveGuards() {
  window.addEventListener("beforeunload", (e) => {
    if (state.isBusy) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
  // Browsers drop the wake lock whenever the page is hidden; re-acquire it on return
  document.addEventListener("visibilitychange", () => {
    if (state.isBusy && document.visibilityState === "visible") {
      acquireWakeLock();
    }
  });
}

async function runExclusive(fn) {
  if (state.isBusy) return;
  state.isBusy = true;
  updateControlsState();
  await acquireWakeLock();
  try {
    await fn();
  } finally {
    state.isBusy = false;
    await releaseWakeLock();
    updateControlsState();
  }
}

async function queryAndShowDeviceInfo() {
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

async function refreshPairedDevicesStatus() {
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
  const samsung = devices.filter((dev) => dev.vendorId === SAMSUNG_VID);
  const d =
    samsung.find((dev) => classifyDeviceMode(dev.vendorId, dev.productId) === "download") ??
    samsung[0];

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
    const mode = classifyDeviceMode(d.vendorId, d.productId);
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

// --- Flash Progress, Speed & ETA ---
const STATS_SAMPLE_MS = 1000;
let flashStats = null;

function resetFlashStats() {
  flashStats = null;
}

// Samples the bytes sent to the device and the overall progress at most once per
// STATS_SAMPLE_MS, smoothing the transfer speed and progress rate with an
// exponential moving average
function updateFlashStats(sent, overallPercent) {
  const now = performance.now();
  if (!flashStats || sent < flashStats.sent) {
    flashStats = { time: now, sent, overallPercent, speed: null, rate: null };
    return flashStats;
  }
  const elapsedMs = now - flashStats.time;
  if (elapsedMs >= STATS_SAMPLE_MS) {
    const seconds = elapsedMs / 1000;
    const ema = (prev, value) => (prev === null ? value : prev * 0.7 + value * 0.3);
    flashStats.speed = ema(flashStats.speed, (sent - flashStats.sent) / seconds);
    flashStats.rate = ema(flashStats.rate, (overallPercent - flashStats.overallPercent) / seconds);
    flashStats.time = now;
    flashStats.sent = sent;
    flashStats.overallPercent = overallPercent;
  }
  return flashStats;
}

function formatDuration(totalSeconds) {
  const secs = Math.max(0, Math.round(totalSeconds));
  const pad = (n) => String(n).padStart(2, "0");
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

function handleProgressEvent(event) {
  if (!event || typeof event !== "object") return;
  if (event.type === "log") {
    scheduleLogFlush();
  } else if (event.type === "progress") {
    const { percent, partition, overallPercent } = event;
    const progressBar = document.getElementById("flash-progress-bar");
    const partitionBar = document.getElementById("partition-progress-bar");
    const percentText = document.getElementById("flash-percent-text");
    const statusText = document.getElementById("flash-status-text");

    if (overallPercent === undefined) {
      // Progress outside of a flash only has the current operation's percentage
      if (progressBar) progressBar.style.width = `${percent}%`;
      if (percentText) percentText.textContent = `${percent}%`;
      return;
    }

    // The main bar shows the whole flash, the thin bar below it the current partition
    const stats = updateFlashStats(event.sent, overallPercent);
    if (progressBar) progressBar.style.width = `${overallPercent}%`;
    if (partitionBar) partitionBar.style.width = `${percent}%`;
    if (percentText) percentText.textContent = `${Math.floor(overallPercent)}%`;
    if (statusText && partition) {
      const details = [`${percent}%`];
      if (stats.speed !== null) {
        details.push(`${formatBytes(stats.speed)}/s`);
      }
      if (stats.rate > 0) {
        details.push(`ETA ${formatDuration((100 - overallPercent) / stats.rate)}`);
      }
      const position = `${event.partitionIndex}/${event.partitionCount}`;
      statusText.textContent =
        `Status: Flashing ${partition} (${position}) — ${details.join(" • ")}`;
    }
  }
}

// --- File Downloads ---
function downloadFile(filename, data, type) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Revoke later, as some browsers start the download asynchronously
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

function localTimestampForFilename() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-` +
    `${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`
  );
}

function saveLog() {
  downloadFile(
    `samloader-web-${localTimestampForFilename()}.log`,
    `${exportWasmLogs()}\n`,
    "text/plain"
  );
}

// The most recently dumped PIT, kept after the device reboots so it can still be saved.
// It is named after the device model if it was queried (DVIF) before dumping.
let lastPit = null;

function savePit() {
  if (!lastPit) return;
  const name = (lastPit.model || "device").replace(/[^\w.-]/g, "_");
  downloadFile(`${name}.pit`, lastPit.data, "application/octet-stream");
}

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
    document.getElementById("btn-reboot-download")?.addEventListener("click", async () => {
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
    });

    // Reboot Device (Odin)
    document.getElementById("btn-reboot-odin")?.addEventListener("click", async () => {
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
    });

    // Dump PIT Table
    document.getElementById("btn-dump-pit")?.addEventListener("click", async () => {
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
    });

    // Flash Firmware Button
    document.getElementById("btn-flash-firmware")?.addEventListener("click", async () => {
      await executeFlashProcess();
    });

    // Reset Slots
    document.getElementById("btn-reset-slots")?.addEventListener("click", () => {
      if (state.isBusy) return;
      SLOTS.forEach(clearSlot);
      clearAllPartitions(true);
      appendLog("All package slots and partition files reset.");
    });

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
    const partitionBar = document.getElementById("partition-progress-bar");

    resetFlashStats();
    if (progressBar) {
      progressBar.classList.remove("progress-bar-error");
      progressBar.style.width = "0%";
    }
    if (partitionBar) partitionBar.style.width = "0%";
    if (percentText) percentText.textContent = "0%";
    if (statusText) statusText.textContent = "Status: Preparing Firmware...";
    appendLog("=== Starting Flashing Session ===");

    const activeSlots = Object.entries(state.slots).filter(([_, file]) => file !== null);
    if (activeSlots.length > 0) {
      appendLog(`Active flashing slots: ${activeSlots.map(([s]) => s).join(", ")}`);
    }
    if (state.partitions.length > 0) {
      appendLog(`Individual partition files: ${state.partitions.length}`);
    }

    try {
      const files = {};
      for (const [slot, file] of activeSlots) {
        appendLog(`Preparing slot ${slot}: ${file.name} (${formatBytes(file.size)})...`);
        files[slot] = file;
      }
      if (state.partitions.length > 0) {
        files.partitions = state.partitions.map((entry) => {
          const target = entry.partition.trim();
          const targetDesc = target ? `target: ${target}` : "auto-match";
          appendLog(
            `Preparing partition (${targetDesc}): ${entry.file.name} (${formatBytes(entry.file.size)})...`
          );
          return {
            file: entry.file,
            partition: target || null,
          };
        });
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

      appendLog("Validating firmware files...");
      const job = await prepareFlash(files, options);

      // Mirror the CLI: confirm before a flash that wipes the device's data
      const wipeReasons = [];
      if (job.erases_userdata()) wipeReasons.push("NAND Erase is enabled.");
      if (job.flashes_userdata()) wipeReasons.push("The flash list contains userdata.");
      if (
        wipeReasons.length > 0 &&
        !confirm(`${wipeReasons.join("\n")}\n\nThis will wipe the device's data. Continue?`)
      ) {
        job.free();
        if (statusText) statusText.textContent = "Status: Flashing Aborted";
        appendLog("Flashing aborted by user.");
        return;
      }

      if (statusText) statusText.textContent = "Status: Flashing Firmware...";
      appendLog(`Executing flash via backend '${state.selectedBackend}'...`);
      await job.execute(state.selectedBackend, false);

      if (progressBar) progressBar.style.width = "100%";
      if (partitionBar) partitionBar.style.width = "100%";
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
  setupExclusiveGuards();
  setupDropzones();
  setupWasmAndEvents();
});
