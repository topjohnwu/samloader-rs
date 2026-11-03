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

// Enabling controls for the current state, and guarding exclusive device operations.

import { PACKAGE_SLOTS, SLOTS, state } from "./state.js";

// Lists the advanced options that differ from their defaults next to the folded
// "Advanced options" heading, so that e.g. a NAND erase is never hidden from view
function updateAdvancedSummary() {
  const el = document.getElementById("advanced-active");
  if (!el) return;
  const active = [];
  if (state.slots.PIT) active.push("PIT");
  const salesCode = document.getElementById("opt-sales-code")?.value.trim();
  if (salesCode) active.push(`CSC ${salesCode.toUpperCase()}`);
  document.querySelectorAll("#advanced-options .option-tile").forEach((tile) => {
    if (tile.querySelector("input[type=checkbox]")?.checked) {
      active.push(tile.querySelector(".option-tile-title")?.textContent ?? "");
    }
  });
  el.textContent = active.join(" · ");
  el.title = el.textContent;
  el.hidden = active.length === 0;
}

export function updateControlsState() {
  updateAdvancedSummary();
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

  const downloadActionIds = [
    "btn-detect-device",
    "btn-dump-pit",
    "btn-odin-reboot-android",
    "btn-odin-reboot-download",
  ];
  downloadActionIds.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.disabled = state.isBusy || !hasDownloadDevice;
    }
  });

  // Rebooting into Download Mode over AT is the only action a Normal Mode device supports
  const rebootDownloadBtn = document.getElementById("btn-reboot-download");
  if (rebootDownloadBtn) {
    rebootDownloadBtn.disabled = state.isBusy || state.device?.mode !== "normal";
  }

  // Clears the package slots and partition files, so only offer it when there is any
  const clearSlotsBtn = document.getElementById("btn-clear-slots");
  if (clearSlotsBtn) {
    const hasSelection =
      PACKAGE_SLOTS.some(({ id }) => state.slots[id] !== null) || state.partitions.length > 0;
    clearSlotsBtn.disabled = state.isBusy || !hasSelection;
  }

  const generalControlIds = [
    "backend-select",
    "opt-reboot-mode",
    "opt-skip-md5",
    "opt-verbose",
    "btn-pair-download",
    "btn-pair-normal",
    "btn-add-partition",
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
    const dropzone = document.getElementById(`dropzone-${slot}`);
    dropzone?.setAttribute("aria-disabled", String(state.isBusy));
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

export function setupExclusiveGuards() {
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

export async function runExclusive(fn) {
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
