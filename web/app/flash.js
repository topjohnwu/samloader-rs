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

// Odin flashing orchestration, wipe confirmation, and transfer speed/ETA smoothing.

import { prepareFlash } from "./bridge.js";
import { runExclusive } from "./exclusive.js";
import { formatBytes } from "./format.js";
import { appendLog, reportError } from "./logger.js";
import { PACKAGE_SLOTS, state } from "./state.js";

// --- Flash Speed & ETA ---
const STATS_SAMPLE_MS = 1000;

let flashStats = null;
let flashHandlers = {};

export function setFlashHandlers(handlers) {
  flashHandlers = handlers || {};
}

export function resetFlashStats() {
  flashStats = null;
}

// Samples the bytes sent to the device and the overall progress at most once per
// STATS_SAMPLE_MS, smoothing the transfer speed and progress rate with an
// exponential moving average
export function updateFlashStats(sent, overallPercent) {
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

export function rebootOutcome(rebootMode = state.rebootMode) {
  switch (rebootMode) {
    case "download":
      return "The device is rebooting to Download Mode.";
    case "none":
      return "The device stays in Download Mode.";
    default:
      return "The device is rebooting to Android.";
  }
}

async function runFlashWithFiles(files, { skipWipeConfirmAlreadyAsked = false } = {}) {
  resetFlashStats();
  flashHandlers.onStart?.();
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

    const options = flashHandlers.getOptions
      ? flashHandlers.getOptions()
      : { reboot: state.rebootMode };

    appendLog("Validating firmware files...");
    const job = await prepareFlash(preparedFiles, options);

    // Mirror the CLI: confirm before a flash that wipes the device's data
    const wipeReasons = [];
    if (job.erases_userdata()) wipeReasons.push("NAND Erase is enabled.");
    if (job.flashes_userdata()) wipeReasons.push("The flash list contains userdata.");
    if (
      wipeReasons.length > 0 &&
      !skipWipeConfirmAlreadyAsked &&
      flashHandlers.confirmWipe &&
      !flashHandlers.confirmWipe(wipeReasons)
    ) {
      job.free();
      flashHandlers.onAborted?.();
      appendLog("Flashing aborted by user.");
      return { success: false, aborted: true };
    }

    flashHandlers.onFlashing?.();
    appendLog(`Executing flash via backend '${state.selectedBackend}'...`);
    await job.execute(state.selectedBackend, false);

    flashHandlers.onSuccess?.(rebootOutcome(options.reboot ?? state.rebootMode));
    appendLog("=== Flashing Process Finished Successfully ===");
    return { success: true, aborted: false };
  } catch (err) {
    flashHandlers.onError?.(err);
    reportError(`[FLASH ERROR] ${err}`);
    return { success: false, aborted: false, error: err };
  } finally {
    flashHandlers.onFinally?.();
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
