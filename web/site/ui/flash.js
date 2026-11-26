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

// Flash progress bar, speed/ETA display, outcome banner, and action bar UI.

import {
  executeFlashProcess,
  setFlashHandlers,
  updateFlashStats,
} from "../app/flash.js";
import { appendLog } from "../app/logger.js";
import { state } from "../app/state.js";
import { openLog } from "./log.js";
import { announce, formatBytes, formatDuration, setBarPercent } from "./util.js";

let lastAnnouncedPartition = null;
let activeCancelHandler = null;

export function handleProgressEvent(event) {
  if (!event || typeof event !== "object") return;
  if (event.type === "log") {
    if (event.message) appendLog(event.message);
  } else if (event.type === "progress") {
    const { percent, partition, overallPercent } = event;
    const progressBar = document.getElementById("flash-progress-bar");
    const percentText = document.getElementById("flash-percent-text");
    const statusText = document.getElementById("flash-status-text");
    const detailText = document.getElementById("flash-detail-text");

    if (overallPercent === undefined) {
      // Progress outside of a flash only has the current operation's percentage
      setBarPercent(progressBar, percent);
      if (percentText) percentText.textContent = `${percent}%`;
      return;
    }

    // A single bar shows the whole flash. Partitions are weighted by size, so large
    // ones still move it steadily; the current partition is named in the text.
    const stats = updateFlashStats(event.sent, overallPercent);
    setBarPercent(progressBar, overallPercent);
    if (percentText) percentText.textContent = `${Math.floor(overallPercent)}%`;
    if (detailText) {
      const details = [];
      if (stats.speed !== null) {
        details.push(`${formatBytes(stats.speed)}/s`);
      }
      if (stats.rate > 0) {
        details.push(`About ${formatDuration((100 - overallPercent) / stats.rate)} left`);
      }
      detailText.textContent = details.join(" · ");
    }
    if (statusText && partition) {
      const position = `${event.partitionIndex} of ${event.partitionCount}`;
      if (partition !== lastAnnouncedPartition) {
        lastAnnouncedPartition = partition;
        announce(`Flashing ${partition} (${position})`);
      }
      statusText.textContent = `Flashing ${partition} (${position})`;
    }
  }
}

export function clearDownloadFileProgress() {
  const listEl = document.getElementById("download-files-progress");
  if (!listEl) return;
  listEl.replaceChildren();
  listEl.hidden = true;
}

// --- Flash & Operation Panel ---
// While downloading or flashing, the progress panel replaces the controls in the action bar,
// and the outcome is shown above them afterwards.
export function setFlashInProgress(inProgress) {
  const controls = document.getElementById("action-controls");
  const panel = document.getElementById("flash-progress-panel");
  const hint = document.getElementById("server-flash-hint");
  if (controls) controls.hidden = inProgress;
  if (panel) panel.hidden = !inProgress;
  if (hint && inProgress) hint.hidden = true;
  if (!inProgress) clearDownloadFileProgress();
}

export function setCancelOperationButton({
  visible,
  disabled = false,
  label = "Cancel",
  onCancel = null,
} = {}) {
  activeCancelHandler = visible ? onCancel : null;
  const btn = document.getElementById("btn-cancel-operation");
  if (!btn) return;
  btn.hidden = !visible;
  btn.disabled = Boolean(disabled);
  btn.textContent = label;
}

export function updateOperationProgress({ statusText, percent, detailText } = {}) {
  const progressBar = document.getElementById("flash-progress-bar");
  const percentText = document.getElementById("flash-percent-text");
  const statusEl = document.getElementById("flash-status-text");
  const detailEl = document.getElementById("flash-detail-text");
  if (typeof percent === "number") {
    const clamped = Math.max(0, Math.min(100, percent));
    setBarPercent(progressBar, clamped);
    if (percentText) percentText.textContent = `${Math.floor(clamped)}%`;
  }
  if (statusEl && statusText !== undefined) statusEl.textContent = statusText;
  if (detailEl && detailText !== undefined) detailEl.textContent = detailText;
}

export function showOperationResult(
  variant,
  message,
  { showLog = variant === "error", showLoadIntoLocal = false } = {}
) {
  const result = document.getElementById("flash-result");
  const text = document.getElementById("flash-result-text");
  const showLogBtn = document.getElementById("btn-show-log");
  const loadLocalBtn = document.getElementById("btn-load-into-local");
  if (!result || !text) return;
  result.classList.toggle("result-success", variant === "success");
  result.classList.toggle("result-error", variant === "error");
  result.classList.toggle("result-warning", variant === "warning");
  text.textContent = message;
  if (showLogBtn) showLogBtn.hidden = !showLog;
  if (loadLocalBtn) loadLocalBtn.hidden = !(showLoadIntoLocal && state.capabilities.canFlash);
  result.hidden = false;
}

export function hideFlashResult() {
  const result = document.getElementById("flash-result");
  const loadLocalBtn = document.getElementById("btn-load-into-local");
  if (loadLocalBtn) loadLocalBtn.hidden = true;
  if (result) result.hidden = true;
}

function showFlashResult(success, message) {
  showOperationResult(success ? "success" : "error", message, { showLog: !success });
}

// Brings the action bar into view, in case the page was scrolled elsewhere
export function revealActionBar() {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  document
    .querySelector(".action-bar")
    ?.scrollIntoView({ block: "nearest", behavior: reduceMotion ? "auto" : "smooth" });
}

function readFlashOptions() {
  const eraseChk = document.getElementById("opt-nand-erase");
  const disableVerityChk = document.getElementById("opt-disable-verity");
  const disableVerificationChk = document.getElementById("opt-disable-verification");
  const skipSizeCheckChk = document.getElementById("opt-skip-size-check");
  const salesCodeInput = document.getElementById("opt-sales-code");

  return {
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
}

export function setupFlashPanel() {
  setFlashHandlers({
    getOptions: readFlashOptions,
    confirmWipe: (wipeReasons) =>
      confirm(`${wipeReasons.join("\n")}\n\nThis will wipe the device's data. Continue?`),
    onStart: () => {
      lastAnnouncedPartition = null;
      setCancelOperationButton({ visible: false });
      updateOperationProgress({ statusText: "Preparing firmware...", percent: 0, detailText: "" });
      hideFlashResult();
      setFlashInProgress(true);
      revealActionBar();
    },
    onAborted: () => {
      announce("Flashing aborted");
    },
    onFlashing: () => {
      const statusText = document.getElementById("flash-status-text");
      if (statusText) statusText.textContent = "Flashing firmware...";
    },
    onSuccess: (outcomeMessage) => {
      updateOperationProgress({ percent: 100 });
      showFlashResult(true, `Flashing complete. ${outcomeMessage}`);
      announce("Flashing complete");
    },
    onError: (err) => {
      // Errors may span many lines; the banner shows the first, the log all of them
      showFlashResult(false, `Flashing failed: ${String(err).split("\n")[0]}`);
      announce("Flashing failed");
    },
    onFinally: () => {
      setCancelOperationButton({ visible: false });
      setFlashInProgress(false);
    },
  });

  document.getElementById("btn-dismiss-result")?.addEventListener("click", hideFlashResult);
  document.getElementById("btn-show-log")?.addEventListener("click", () => {
    openLog();
    document.querySelector(".log-card")?.scrollIntoView({ block: "nearest" });
  });
  document.getElementById("btn-cancel-operation")?.addEventListener("click", () => {
    activeCancelHandler?.();
  });
  document.getElementById("btn-flash-firmware")?.addEventListener("click", () => {
    void executeFlashProcess();
  });
}
