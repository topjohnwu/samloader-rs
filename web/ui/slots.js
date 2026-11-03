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

// Package slots, MD5 verification, and individual partition files.

import { appendRawWasmLogs } from "../bridge.js";
import { PACKAGE_SLOTS, SLOTS, state } from "./state.js";
import { formatBytes, setBarPercent, isActivationKey } from "./util.js";
import { appendLog } from "./log.js";
import { updateControlsState } from "./controls.js";

let draggedPartitionId = null;

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
    setBarPercent(bar, def.width ?? percent ?? 0);
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
  // Deferred so that cancelling several slots in a row (e.g. Clear All) does not
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

  const worker = new Worker(new URL("../md5_worker.js", import.meta.url), { type: "module" });
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
function slotPlaceholder(slot) {
  return slot === "PIT" ? "Select *.pit file" : `Select ${slot}_*.tar.md5`;
}

export function renderPackageSlots() {
  const grid = document.getElementById("slots-grid");
  const template = document.getElementById("slot-template");
  if (!grid || !template) return;

  PACKAGE_SLOTS.forEach(({ id, badge, label }) => {
    const box = template.content.firstElementChild.cloneNode(true);
    box.id = `slot-box-${id}`;
    box.dataset.slot = id;
    box.querySelector(".slot-file-input").id = `input-${id}`;
    const dropzone = box.querySelector(".dropzone");
    dropzone.id = `dropzone-${id}`;
    dropzone.setAttribute("aria-label", `Select ${label} (${id}) package`);
    const badgeEl = box.querySelector(".slot-badge");
    badgeEl.textContent = badge;
    box.querySelector(".slot-label").textContent = label;
    const fileName = box.querySelector(".file-name");
    fileName.id = `file-name-${id}`;
    fileName.textContent = slotPlaceholder(id);
    box.querySelector(".file-size").id = `file-size-${id}`;
    box.querySelector(".badge").id = `md5-badge-${id}`;
    box.querySelector(".btn-clear-slot").id = `clear-${id}`;
    box.querySelector(".progress-bar-fill").id = `md5-bar-${id}`;
    grid.appendChild(box);
  });
}

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

export function handleSkipMd5Change(skip) {
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
    fileNameElem.textContent = slotPlaceholder(slot);
  }
  if (fileSizeElem) fileSizeElem.textContent = "";
  if (clearBtn) clearBtn.hidden = true;
  if (fileInput) fileInput.value = "";

  updateControlsState();
}

// Clears the package slots and partition files. The PIT file is an advanced option
// with its own clear button, so it is kept.
export function clearFirmwareSelections() {
  if (state.isBusy) return;
  PACKAGE_SLOTS.forEach(({ id }) => clearSlot(id));
  clearAllPartitions();
  appendLog("All package slots and partition files cleared.");
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

function clearAllPartitions() {
  if (state.isBusy) return;
  if (state.partitions.length === 0) return;
  state.partitions = [];
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

// Moves a partition file up (-1) or down (+1) with the keyboard, keeping it focused
function movePartitionFile(id, delta) {
  if (state.isBusy) return;
  const from = state.partitions.findIndex((p) => p.id === id);
  const to = from + delta;
  if (from === -1 || to < 0 || to >= state.partitions.length) return;
  const [moved] = state.partitions.splice(from, 1);
  state.partitions.splice(to, 0, moved);
  renderPartitionList();
  document.querySelector(`.partition-item[data-partition-id="${id}"]`)?.focus();
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
    item.tabIndex = 0;
    item.setAttribute("aria-label", `${entry.file.name}; Alt+Up or Alt+Down to reorder`);
    item.addEventListener("keydown", (e) => {
      if (e.target !== item || !e.altKey) return;
      if (e.key === "ArrowUp" || e.key === "ArrowDown") {
        e.preventDefault();
        movePartitionFile(entry.id, e.key === "ArrowUp" ? -1 : 1);
      }
    });

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
    fileTrigger.tabIndex = 0;
    fileTrigger.setAttribute("role", "button");
    fileTrigger.setAttribute("aria-label", `Change file ${entry.file.name}`);
    fileTrigger.addEventListener("click", () => {
      if (!state.isBusy) replaceInput.click();
    });
    fileTrigger.addEventListener("keydown", (e) => {
      if (isActivationKey(e)) {
        e.preventDefault();
        if (!state.isBusy) replaceInput.click();
      }
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

export function setupDropzones() {
  SLOTS.forEach((slot) => {
    const dropzone = document.getElementById(`dropzone-${slot}`);
    const fileInput = document.getElementById(`input-${slot}`);
    const clearBtn = document.getElementById(`clear-${slot}`);

    if (dropzone && fileInput) {
      dropzone.addEventListener("click", (e) => {
        if (state.isBusy) return;
        if (e.target !== clearBtn) fileInput.click();
      });
      dropzone.addEventListener("keydown", (e) => {
        if (e.target === dropzone && isActivationKey(e)) {
          e.preventDefault();
          if (!state.isBusy) fileInput.click();
        }
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
