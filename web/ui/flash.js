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
import { state } from "./state.js";
import { formatBytes, setBarPercent, announce, formatDuration } from "./util.js";
import { scheduleLogFlush, appendLog } from "./log.js";
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
    const partitionBar = document.getElementById("partition-progress-bar");
    const percentText = document.getElementById("flash-percent-text");
    const statusText = document.getElementById("flash-status-text");

    if (overallPercent === undefined) {
      // Progress outside of a flash only has the current operation's percentage
      setBarPercent(progressBar, percent);
      if (percentText) percentText.textContent = `${percent}%`;
      return;
    }

    // The main bar shows the whole flash, the thin bar below it the current partition
    const stats = updateFlashStats(event.sent, overallPercent);
    setBarPercent(progressBar, overallPercent);
    setBarPercent(partitionBar, percent);
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
      if (partition !== lastAnnouncedPartition) {
        lastAnnouncedPartition = partition;
        announce(`Flashing ${partition} (${position})`);
      }
      statusText.textContent =
        `Status: Flashing ${partition} (${position}) — ${details.join(" • ")}`;
    }
  }
}

export async function executeFlashProcess() {
  await runExclusive(async () => {
    const statusText = document.getElementById("flash-status-text");
    const percentText = document.getElementById("flash-percent-text");
    const progressBar = document.getElementById("flash-progress-bar");
    const partitionBar = document.getElementById("partition-progress-bar");

    resetFlashStats();
    if (progressBar) {
      progressBar.classList.remove("progress-bar-error");
      setBarPercent(progressBar, 0);
    }
    setBarPercent(partitionBar, 0);
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
        announce("Flashing aborted");
        appendLog("Flashing aborted by user.");
        return;
      }

      if (statusText) statusText.textContent = "Status: Flashing Firmware...";
      appendLog(`Executing flash via backend '${state.selectedBackend}'...`);
      await job.execute(state.selectedBackend, false);

      setBarPercent(progressBar, 100);
      setBarPercent(partitionBar, 100);
      if (percentText) percentText.textContent = "100%";
      if (statusText) statusText.textContent = "Status: Flashing Complete!";
      announce("Flashing complete");
      appendLog("=== Flashing Process Finished Successfully ===");
    } catch (err) {
      if (progressBar) progressBar.classList.add("progress-bar-error");
      if (statusText) statusText.textContent = "Status: Flashing Failed!";
      announce("Flashing failed");
      appendLog(`[FLASH ERROR] ${err}`);
    }
  });
}
