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
  device: null,
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
  partitions: [],
  nextPartitionId: 1,
  isBusy: false,
};

let md5Worker = null;
let draggedPartitionId = null;

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
    return !res || res.status === "verifying" || res.status === "invalid";
  });

  if (flashBtn) {
    flashBtn.disabled = !hasAction || state.isBusy || hasPendingOrInvalidMd5;
  }

  const hasDownloadDevice = state.device?.mode === "download";
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

  if (!isBackendSupported(state.selectedBackend)) {
    state.device = null;
    const label = state.selectedBackend === "vcom" ? "WebSerial" : "WebUSB";
    if (summaryEl) summaryEl.textContent = `${label} is not supported in this browser`;
    updateConnectionChip(false, `${label} Unavailable`);
    renderDeviceList();
    return;
  }

  try {
    const devices = await getPairedDevices(state.selectedBackend);
    const d = devices.find((dev) => dev.vendorId === SAMSUNG_VID);
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
        name,
        subtitle: `USB VID:PID ${vid}:${pid}${serialPart}`,
        mode,
        disconnect: d.disconnect,
      };
      if (summaryEl) summaryEl.textContent = "Samsung device paired";
      updateConnectionChip(true, "Device Paired");
    }
    renderDeviceList();
  } catch (err) {
    appendLog(`Failed to enumerate paired device: ${err}`);
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

function handleProgressEvent(eventOrMsg) {
  if (typeof eventOrMsg === "string") {
    appendLog(eventOrMsg);
  } else if (eventOrMsg && typeof eventOrMsg === "object" && eventOrMsg.type === "progress") {
    const { percent, partition } = eventOrMsg;
    const progressBar = document.getElementById("flash-progress-bar");
    const percentText = document.getElementById("flash-percent-text");
    const statusText = document.getElementById("flash-status-text");
    if (progressBar) progressBar.style.width = `${percent}%`;
    if (percentText) percentText.textContent = `${percent}%`;
    if (statusText && partition) {
      statusText.textContent = `Status: Flashing ${partition} (${percent}%)`;
    }
  }
}

// --- WASM & Event Wiring ---
async function setupWasmAndEvents() {
  try {
    await initWasm();
    await setProgressCallback(handleProgressEvent);
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
          const pitText = await printPit({
            backend: state.selectedBackend,
            rebootMode: state.rebootMode,
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
      clearAllPartitions(true);
      appendLog("All package slots and partition files reset.");
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

      appendLog(`Executing flash via backend '${state.selectedBackend}'...`);

      await startFlash(state.selectedBackend, files, options);

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
