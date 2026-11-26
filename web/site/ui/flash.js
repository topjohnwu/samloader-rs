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

// Flash progress bar, speed/ETA display, and flash handler wiring.

import { executeFlashProcess, setFlashHandlers } from "../app/flash.js";
import { createTransferSpeedTracker, formatTransferMeta } from "../app/format.js";
import { appendLog } from "../app/logger.js";
import { state } from "../app/state.js";
import {
  beginOperation,
  endOperation,
  showOperationResult,
  updateOperationProgress,
} from "./operation.js";
import { announce, setBarPercent } from "./util.js";

let lastAnnouncedPartition = null;
const flashSpeedTracker = createTransferSpeedTracker({
  windowMs: 4000,
  sampleIntervalMs: 1000,
});

export function handleProgressEvent(event) {
  if (!event || typeof event !== "object") return;
  if (event.type === "log") {
    if (event.message) appendLog(event.message);
  } else if (event.type === "progress") {
    const { percent, partition, overallPercent } = event;
    const progressBar = document.getElementById("flash-progress-bar");
    const percentText = document.getElementById("flash-percent-text");

    if (overallPercent === undefined) {
      // Progress outside of a flash only has the current operation's percentage
      setBarPercent(progressBar, percent);
      if (percentText) percentText.textContent = `${percent}%`;
      return;
    }

    // A single bar shows the whole flash. Partitions are weighted by size, so large
    // ones still move it steadily; the current partition is named in the text.
    const { wireSpeed: speed, outSpeed: rate } = flashSpeedTracker.update(
      event.sent,
      overallPercent
    );
    const etaSecs =
      rate > 0 && overallPercent < 100 ? (100 - overallPercent) / rate : null;

    let statusText;
    if (partition) {
      const position = `${event.partitionIndex} of ${event.partitionCount}`;
      if (partition !== lastAnnouncedPartition) {
        lastAnnouncedPartition = partition;
        announce(`Flashing ${partition} (${position})`);
      }
      statusText = `Flashing ${partition} (${position})`;
    }

    updateOperationProgress({
      statusText,
      percent: overallPercent,
      detailText: formatTransferMeta({ speed, etaSecs }),
    });
  }
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

function resetFlashPhase() {
  lastAnnouncedPartition = null;
  flashSpeedTracker.reset();
  updateOperationProgress({ statusText: "Preparing firmware...", percent: 0, detailText: "" });
}

export function setupFlashPanel() {
  setFlashHandlers({
    getOptions: readFlashOptions,
    confirmWipe: (wipeReasons) =>
      confirm(`${wipeReasons.join("\n")}\n\nThis will wipe the device's data. Continue?`),
    onStart: () => {
      lastAnnouncedPartition = null;
      flashSpeedTracker.reset();
      beginOperation({ statusText: "Preparing firmware..." });
    },
    onPhaseStart: resetFlashPhase,
    onAborted: () => {
      announce("Flashing aborted");
    },
    onFlashing: () => {
      updateOperationProgress({ statusText: "Flashing firmware..." });
    },
    onSuccess: (outcomeMessage) => {
      updateOperationProgress({ percent: 100 });
      showOperationResult("success", `Flashing complete. ${outcomeMessage}`);
      announce("Flashing complete");
    },
    onError: (err) => {
      // Errors may span many lines; the banner shows the first, the log all of them
      showOperationResult("error", `Flashing failed: ${String(err).split("\n")[0]}`, {
        showLog: true,
      });
      announce("Flashing failed");
    },
    onFinally: () => {
      endOperation();
    },
  });

  document.getElementById("btn-flash-firmware")?.addEventListener("click", () => {
    void executeFlashProcess();
  });
}
