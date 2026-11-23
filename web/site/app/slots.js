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

// Odin package slots, partition list state, and sequential MD5 worker verification queue.

import { formatBytes } from "./format.js";
import { appendLog, appendRawLogs } from "./logger.js";
import { PACKAGE_SLOTS, SLOTS, state } from "./state.js";

const slotListeners = new Set();

export function onSlotsChange(listener) {
  slotListeners.add(listener);
  return () => slotListeners.delete(listener);
}

function notifySlotsChange(event) {
  for (const listener of slotListeners) {
    listener(event);
  }
}

export function isMd5File(file) {
  return file.name.toLowerCase().endsWith(".md5");
}

function setSlotStatus(slot, status, percent, error) {
  if (status === "empty") {
    delete state.md5Results[slot];
  } else {
    state.md5Results[slot] = { status, error };
  }
  notifySlotsChange({ type: "status", slot, status, percent, error });
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

  const worker = new Worker(new URL("../workers/md5.js", import.meta.url), { type: "module" });
  md5Active = { slot, worker };

  const finish = (status, error) => {
    if (md5Active?.worker !== worker) return; // Cancelled; ignore late messages
    worker.terminate();
    md5Active = null;
    setSlotStatus(slot, status, 100, error);
    if (error) {
      appendLog(`[MD5 ERROR] ${slot}: ${error}`);
    }
    notifySlotsChange({ type: "controls" });
    pumpMd5Queue();
  };

  worker.onmessage = ({ data }) => {
    if (md5Active?.worker !== worker) return;
    switch (data.type) {
      case "PROGRESS":
        setSlotStatus(slot, "verifying", data.percent);
        break;
      case "LOG":
        appendRawLogs(data.lines);
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

// --- Slot Operations ---
export function assignFileToSlot(slot, file, { trustCrc = false } = {}) {
  if (state.isBusy) return;

  cancelMd5(slot);
  state.slots[slot] = file;
  notifySlotsChange({ type: "slot", slot, file });

  const loaded = `Loaded ${slot}: ${file.name} (${formatBytes(file.size)})`;
  if (!isMd5File(file)) {
    setSlotStatus(slot, "ready");
    appendLog(loaded);
  } else if (trustCrc) {
    setSlotStatus(slot, "ready");
    appendLog(`${loaded} — ZIP CRC-32 verified`);
  } else if (state.skipMd5) {
    setSlotStatus(slot, "skipped");
    appendLog(`${loaded} — MD5 check skipped`);
  } else {
    enqueueMd5(slot);
    appendLog(`${loaded} — queued for MD5 check`);
  }

  notifySlotsChange({ type: "controls" });
}

export function loadFilesIntoSlots(slotFiles) {
  if (state.isBusy) return;
  PACKAGE_SLOTS.forEach(({ id }) => clearSlot(id));
  clearAllPartitions();
  for (const [slot, file] of Object.entries(slotFiles)) {
    if (file && PACKAGE_SLOTS.some((s) => s.id === slot)) {
      assignFileToSlot(slot, file, { trustCrc: true });
    }
  }
}

export function setSkipMd5(skip) {
  state.skipMd5 = skip;
  appendLog(`MD5 verification ${skip ? "disabled (skipped)" : "enabled"}.`);

  SLOTS.forEach((slot) => {
    const file = state.slots[slot];
    if (!file || !isMd5File(file)) return;
    const status = state.md5Results[slot]?.status;
    if (skip && status !== "valid" && status !== "ready") {
      // Stop any queued or active verification and mark unverified slots as skipped
      cancelMd5(slot);
      setSlotStatus(slot, "skipped");
    } else if (!skip && status === "skipped") {
      enqueueMd5(slot);
    }
  });

  notifySlotsChange({ type: "controls" });
}

export function clearSlot(slot) {
  if (state.isBusy) return;

  cancelMd5(slot);
  state.slots[slot] = null;
  setSlotStatus(slot, "empty");
  notifySlotsChange({ type: "slot", slot, file: null });
  notifySlotsChange({ type: "controls" });
}

// Clears the package slots and partition files. The PIT file is an advanced option
// with its own clear button, so it is kept.
export function clearFirmwareSelections() {
  if (state.isBusy) return;
  PACKAGE_SLOTS.forEach(({ id }) => clearSlot(id));
  clearAllPartitions();
  appendLog("All package slots and partition files cleared.");
}

// --- Individual Partition Files ---
export function addPartitionFiles(fileList) {
  if (state.isBusy) return;
  const files = Array.from(fileList);
  if (files.length === 0) return;

  files.forEach((file) => {
    const id = state.nextPartitionId++;
    state.partitions.push({ id, file, partition: "" });
    appendLog(`Added partition file: ${file.name} (${formatBytes(file.size)})`);
  });

  notifySlotsChange({ type: "partitions" });
  notifySlotsChange({ type: "controls" });
}

export function removePartitionFile(id) {
  if (state.isBusy) return;
  const idx = state.partitions.findIndex((p) => p.id === id);
  if (idx === -1) return;
  const [removed] = state.partitions.splice(idx, 1);
  appendLog(`Removed partition file: ${removed.file.name}`);
  notifySlotsChange({ type: "partitions" });
  notifySlotsChange({ type: "controls" });
}

export function clearAllPartitions() {
  if (state.isBusy) return;
  if (state.partitions.length === 0) return;
  state.partitions = [];
  notifySlotsChange({ type: "partitions" });
  notifySlotsChange({ type: "controls" });
}

export function reorderPartitionFile(draggedId, targetId, insertAfter) {
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
  notifySlotsChange({ type: "partitions" });
}

export function movePartitionFile(id, delta) {
  if (state.isBusy) return false;
  const from = state.partitions.findIndex((p) => p.id === id);
  const to = from + delta;
  if (from === -1 || to < 0 || to >= state.partitions.length) return false;
  const [moved] = state.partitions.splice(from, 1);
  state.partitions.splice(to, 0, moved);
  notifySlotsChange({ type: "partitions" });
  return true;
}

export function replacePartitionFile(id, file) {
  if (state.isBusy || !file) return;
  const entry = state.partitions.find((p) => p.id === id);
  if (!entry) return;
  entry.file = file;
  appendLog(`Updated partition file: ${file.name} (${formatBytes(file.size)})`);
  notifySlotsChange({ type: "partitions" });
  notifySlotsChange({ type: "controls" });
}

export function setPartitionTarget(id, target) {
  const entry = state.partitions.find((p) => p.id === id);
  if (entry) {
    entry.partition = target;
  }
}
