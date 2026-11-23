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

// Flashing, with overall progress, transfer speed and ETA.

import { prepareFlash } from "../bridge.js";
import { PACKAGE_SLOTS, state } from "./state.js";
import { formatBytes, setBarPercent, announce, formatDuration } from "./util.js";
import { scheduleLogFlush, appendLog, reportError, openLog } from "./log.js";
import { runExclusive } from "./controls.js";

// --- Flash Progress, Speed & ETA ---
const STATS_SAMPLE_MS = 1000;

let flashStats = null;

let lastAnnouncedPartition = null;

function resetFlashStats() {
  flashStats = null;
  lastAnnouncedPartition = null;
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

export function handleProgressEvent(event) {
  if (!event || typeof event !== "object") return;
  if (event.type === "log") {
    scheduleLogFlush();
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

// --- Flash & Operation Panel ---
// While downloading or flashing, the progress panel replaces the controls in the action bar,
// and the outcome is shown above them afterwards.
let activeCancelHandler = null;

export function setFlashInProgress(inProgress) {
  const controls = document.getElementById("action-controls");
  const panel = document.getElementById("flash-progress-panel");
  const hint = document.getElementById("server-flash-hint");
  if (controls) controls.hidden = inProgress;
  if (panel) panel.hidden = !inProgress;
  if (hint && inProgress) hint.hidden = true;
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
  if (loadLocalBtn) loadLocalBtn.hidden = !showLoadIntoLocal;
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

function rebootOutcome() {
  switch (state.rebootMode) {
    case "download":
      return "The device is rebooting to Download Mode.";
    case "none":
      return "The device stays in Download Mode.";
    default:
      return "The device is rebooting to Android.";
  }
}

export function setupFlashPanel() {
  document.getElementById("btn-dismiss-result")?.addEventListener("click", hideFlashResult);
  document.getElementById("btn-show-log")?.addEventListener("click", () => {
    openLog();
    document.querySelector(".log-card")?.scrollIntoView({ block: "nearest" });
  });
  document.getElementById("btn-cancel-operation")?.addEventListener("click", () => {
    activeCancelHandler?.();
  });
}

async function runFlashWithFiles(files, { skipWipeConfirmAlreadyAsked = false } = {}) {
  const statusText = document.getElementById("flash-status-text");
  const detailText = document.getElementById("flash-detail-text");
  const percentText = document.getElementById("flash-percent-text");
  const progressBar = document.getElementById("flash-progress-bar");

  resetFlashStats();
  setCancelOperationButton({ visible: false });
  setBarPercent(progressBar, 0);
  if (detailText) detailText.textContent = "";
  if (percentText) percentText.textContent = "0%";
  if (statusText) statusText.textContent = "Preparing firmware...";
  hideFlashResult();
  setFlashInProgress(true);
  revealActionBar();
  appendLog("=== Starting Flashing Session ===");

  const preparedFiles = { ...files };
  if (!preparedFiles.PIT && state.slots.PIT) {
    preparedFiles.PIT = state.slots.PIT;
  }

  const slotNames = PACKAGE_SLOTS.map((s) => s.id).filter((id) => preparedFiles[id]);
  if (preparedFiles.PIT) slotNames.push("PIT");
  if (slotNames.length > 0) {
    appendLog(`Active flashing slots: ${slotNames.join(", ")}`);
  }
  if (Array.isArray(preparedFiles.partitions) && preparedFiles.partitions.length > 0) {
    appendLog(`Individual partition files: ${preparedFiles.partitions.length}`);
  }

  try {
    for (const slot of slotNames) {
      const file = preparedFiles[slot];
      appendLog(`Preparing slot ${slot}: ${file.name} (${formatBytes(file.size)})...`);
    }
    if (Array.isArray(preparedFiles.partitions)) {
      for (const entry of preparedFiles.partitions) {
        const target = entry.partition?.trim();
        const targetDesc = target ? `target: ${target}` : "auto-match";
        appendLog(
          `Preparing partition (${targetDesc}): ${entry.file.name} (${formatBytes(entry.file.size)})...`
        );
      }
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
    const job = await prepareFlash(preparedFiles, options);

    // Mirror the CLI: confirm before a flash that wipes the device's data
    const wipeReasons = [];
    if (job.erases_userdata()) wipeReasons.push("NAND Erase is enabled.");
    if (job.flashes_userdata()) wipeReasons.push("The flash list contains userdata.");
    if (
      wipeReasons.length > 0 &&
      !skipWipeConfirmAlreadyAsked &&
      !confirm(`${wipeReasons.join("\n")}\n\nThis will wipe the device's data. Continue?`)
    ) {
      job.free();
      announce("Flashing aborted");
      appendLog("Flashing aborted by user.");
      return { success: false, aborted: true };
    }

    if (statusText) statusText.textContent = "Flashing firmware...";
    appendLog(`Executing flash via backend '${state.selectedBackend}'...`);
    await job.execute(state.selectedBackend, false);

    setBarPercent(progressBar, 100);
    if (percentText) percentText.textContent = "100%";
    showFlashResult(true, `Flashing complete. ${rebootOutcome()}`);
    announce("Flashing complete");
    appendLog("=== Flashing Process Finished Successfully ===");
    return { success: true, aborted: false };
  } catch (err) {
    // Errors may span many lines; the banner shows the first, the log all of them
    showFlashResult(false, `Flashing failed: ${String(err).split("\n")[0]}`);
    announce("Flashing failed");
    reportError(`[FLASH ERROR] ${err}`);
    return { success: false, aborted: false, error: err };
  } finally {
    setCancelOperationButton({ visible: false });
    setFlashInProgress(false);
  }
}

export async function executeFlashWithFiles(files, options = {}) {
  if (state.isBusy) {
    return await runFlashWithFiles(files, options);
  }
  let result = { success: false, aborted: false };
  await runExclusive(async () => {
    result = await runFlashWithFiles(files, options);
  });
  return result;
}

export async function executeFlashProcess() {
  const files = {};
  for (const [slot, file] of Object.entries(state.slots)) {
    if (file !== null) {
      files[slot] = file;
    }
  }
  if (state.partitions.length > 0) {
    files.partitions = state.partitions.map((entry) => ({
      file: entry.file,
      partition: entry.partition.trim() || null,
    }));
  }
  return await executeFlashWithFiles(files);
}
