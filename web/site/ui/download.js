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

// OPFS cache banner, folder picker / confirmation prompts, and download progress UI.

import {
  clearOpfsStagingCache,
  executeDownloadAndFlash,
  executeDownloadOnly,
  loadLastDownloadIntoLocalSlots,
  refreshOpfsCacheInfo,
} from "../app/download.js";
import { createTransferSpeedTracker, formatTransferMeta } from "../app/format.js";
import { reportError } from "../app/logger.js";
import { getDerivedState, state, subscribe } from "../app/state.js";
import {
  beginOperation,
  clearDownloadFileRows,
  endOperation,
  hasMultipleDownloadRows,
  hideOperationResult,
  initDownloadFileRows,
  markDownloadFileDone,
  setCancelOperationButton,
  showOperationResult,
  updateDownloadFileRow,
  updateOperationProgress,
} from "./operation.js";
import { announce, formatBytes } from "./util.js";

// --- OPFS Cache Banner ---
function renderOpfsCacheBanner(info) {
  const banner = document.getElementById("opfs-cache-banner");
  const titleEl = document.getElementById("opfs-cache-title");
  const metaEl = document.getElementById("opfs-cache-meta");

  if (!banner || !info) {
    if (banner) banner.hidden = true;
    return;
  }

  const label = [info.model, info.region ? `(${info.region})` : null]
    .filter(Boolean)
    .join(" ");
  const buildDesc = info.version || info.decryptedFilename || info.buildKey;
  if (titleEl) {
    titleEl.textContent = label
      ? `Cached build: ${label} · ${buildDesc}`
      : `Cached build: ${buildDesc}`;
  }
  if (metaEl) {
    const statusLabel = info.complete ? "Ready to flash" : "Partial download — resumable";
    metaEl.textContent = `${formatBytes(info.totalBytes || 0)} · ${statusLabel}`;
  }
  banner.hidden = false;
}

// --- Download Progress & Result UI Adapter ---
function createDownloadUiCallbacks() {
  let lastAnnouncedFile = null;
  let lastFileIndex = 0;
  let lastFileWritten = 0;
  let sessionOutBytes = 0;
  const speedTracker = createTransferSpeedTracker();

  return {
    onOperationStart: () => {
      beginOperation({ statusText: "Preparing firmware..." });
    },
    onDownloadPrepare: (statusText, files = []) => {
      lastAnnouncedFile = null;
      lastFileIndex = 0;
      lastFileWritten = 0;
      sessionOutBytes = 0;
      speedTracker.reset();
      initDownloadFileRows(files);
      updateOperationProgress({ statusText, percent: 0, detailText: "" });
    },
    onCancelReady: (cancelFn) => {
      setCancelOperationButton({
        visible: true,
        disabled: false,
        label: "Cancel",
        onCancel: () => {
          setCancelOperationButton({ visible: true, disabled: true, label: "Cancelling..." });
          updateOperationProgress({ statusText: "Cancelling download and saving checkpoint..." });
          cancelFn();
        },
      });
    },
    onProgress: (data, params) => {
      const {
        fileIndex,
        fileCount,
        fileName,
        fileWritten = 0,
        fileTotal = 0,
        overallWritten = 0,
        overallTotal = 0,
        wireBytes = 0,
        percent = 0,
      } = data;

      if (fileIndex !== lastFileIndex) {
        lastFileIndex = fileIndex;
        lastFileWritten = fileWritten;
      } else {
        sessionOutBytes += Math.max(0, fileWritten - lastFileWritten);
        lastFileWritten = fileWritten;
      }

      const { wireSpeed, outSpeed } = speedTracker.update(wireBytes, sessionOutBytes);
      const calcEta = (remaining) =>
        outSpeed > 1024 && remaining > 0 ? remaining / outSpeed : null;

      const multiFile = hasMultipleDownloadRows();
      const statusText = multiFile
        ? `Downloading firmware (${fileIndex} of ${fileCount})`
        : `Downloading ${fileName || params.version}...`;

      if (fileName && fileName !== lastAnnouncedFile) {
        lastAnnouncedFile = fileName;
        announce(multiFile ? `Downloading ${fileName} (${fileIndex} of ${fileCount})` : statusText);
      }

      updateOperationProgress({
        statusText,
        percent,
        detailText: formatTransferMeta({
          written: overallWritten,
          total: overallTotal,
          speed: wireSpeed,
          etaSecs: calcEta(Math.max(0, overallTotal - overallWritten)),
        }),
      });

      updateDownloadFileRow(fileName, {
        written: fileWritten,
        total: fileTotal,
        speed: wireSpeed,
        etaSecs: calcEta(Math.max(0, fileTotal - fileWritten)),
      });
    },
    onFileDone: (data) => {
      const { fileName, skipped, size, overallWritten, overallTotal } = data || {};
      if (overallTotal > 0) {
        updateOperationProgress({
          percent: (overallWritten / overallTotal) * 100,
        });
      }
      markDownloadFileDone(fileName, { skipped, size });
    },
    onCancelled: (cancelMsg) => {
      showOperationResult("warning", cancelMsg);
      announce("Download cancelled");
    },
    onDownloadSuccess: (summary, { canLoadIntoLocal }) => {
      updateOperationProgress({ percent: 100 });
      showOperationResult("success", summary, { showLoadIntoLocal: canLoadIntoLocal });
      announce("Download complete");
    },
    onBeforeFlash: () => {
      clearDownloadFileRows();
      setCancelOperationButton({ visible: false });
    },
    onFlashAborted: () => {
      showOperationResult(
        "warning",
        "Flashing cancelled — downloaded firmware cached for retry."
      );
    },
    onOperationError: (err) => {
      const firstLine = String(err?.message || err).split("\n")[0];
      showOperationResult("error", `Download failed: ${firstLine}`, { showLog: true });
      announce("Download failed");
    },
    onOperationFinally: () => {
      endOperation();
    },
  };
}

export function setupDownloadUi() {
  const clearBtn = document.getElementById("btn-clear-opfs-cache");
  let lastCache = undefined;
  const render = (s, d) => {
    if (s.opfsCache !== lastCache) {
      lastCache = s.opfsCache;
      renderOpfsCacheBanner(s.opfsCache);
    }
    if (clearBtn) clearBtn.disabled = d.serverBusy;
  };
  subscribe(render);
  render(state, getDerivedState(state));
  void refreshOpfsCacheInfo();
}

export function handleClearOpfsCache() {
  return clearOpfsStagingCache();
}

export async function handleLoadIntoLocalFlash(onSwitchToLocal) {
  try {
    const res = await loadLastDownloadIntoLocalSlots();
    if (!res) return;
    if (res.loadedCount === 0) {
      showOperationResult(
        "warning",
        "No flashable Odin packages (.tar / .tar.md5) were found in the downloaded files."
      );
      return;
    }
    hideOperationResult();
    onSwitchToLocal?.();
  } catch (err) {
    reportError(`Failed to load downloaded files into Local Flash: ${err?.message || err}`);
  }
}

export async function handleDownloadOnly({ selectedEntries = [] } = {}) {
  await executeDownloadOnly({
    selectedEntries,
    pickDirectory: async () => {
      // Pick a directory so single-file and full-ZIP downloads can store
      // `.part.meta` sidecars for resumable transfers.
      try {
        return await window.showDirectoryPicker({ mode: "readwrite" });
      } catch (err) {
        if (err?.name !== "AbortError") {
          reportError(`Could not open save location: ${err?.message || err}`);
        }
        return false;
      }
    },
    ui: createDownloadUiCallbacks(),
  });
}

export async function handleDownloadAndFlash(selectionInfo = {}) {
  await executeDownloadAndFlash({
    ...selectionInfo,
    eraseChecked: Boolean(state.flashOptions.erase),
    confirmWipe: (wipeReasons) =>
      confirm(`${wipeReasons.join("\n")}\n\nThis will wipe the device's data. Continue?`),
    ui: createDownloadUiCallbacks(),
  });
}
