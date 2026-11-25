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
  COMPONENT_META,
  clearOpfsStagingCache,
  executeDownloadAndFlash,
  executeDownloadOnly,
  loadLastDownloadIntoLocalSlots,
  onOpfsCacheChange,
  refreshOpfsCacheInfo,
} from "../app/download.js";
import { reportError } from "../app/logger.js";
import { updateControlsState } from "./controls.js";
import {
  clearDownloadFileProgress,
  hideFlashResult,
  revealActionBar,
  setCancelOperationButton,
  setFlashInProgress,
  showOperationResult,
  updateOperationProgress,
} from "./flash.js";
import { announce, formatBytes, formatDuration, setBarPercent } from "./util.js";

// --- OPFS Cache Banner ---
function renderOpfsCacheBanner(info) {
  const banner = document.getElementById("opfs-cache-banner");
  const titleEl = document.getElementById("opfs-cache-title");
  const metaEl = document.getElementById("opfs-cache-meta");

  if (!banner || !info) {
    if (banner) banner.hidden = true;
    updateControlsState();
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
  updateControlsState();
}

// --- Download Progress & Result UI Adapter ---
function createDownloadUiCallbacks() {
  let lastAnnouncedFile = null;
  const fileRows = new Map();

  const resetFileProgressList = () => {
    fileRows.clear();
    clearDownloadFileProgress();
  };

  const initFileProgressList = (files) => {
    resetFileProgressList();
    const listEl = document.getElementById("download-files-progress");
    const tpl = document.getElementById("download-file-template");
    if (!listEl || !tpl || !Array.isArray(files) || files.length <= 1) return;

    const fragment = document.createDocumentFragment();
    for (const { name = "", component = null, uncompressedSize = 0 } of files) {
      const item = tpl.content.firstElementChild.cloneNode(true);
      item.querySelector(".download-file-badge").textContent =
        COMPONENT_META[component]?.badge ?? "FILE";
      const nameEl = item.querySelector(".download-file-name");
      nameEl.textContent = name;
      nameEl.title = name;
      item
        .querySelector(".download-file-track")
        .setAttribute("aria-label", `Progress for ${name}`);

      const metaEl = item.querySelector(".download-file-meta");
      metaEl.textContent = uncompressedSize > 0 ? formatBytes(uncompressedSize) : "";
      fragment.appendChild(item);

      fileRows.set(name, {
        item,
        statusEl: item.querySelector(".badge"),
        barEl: item.querySelector(".progress-bar-fill"),
        metaEl,
        size: uncompressedSize,
      });
    }

    listEl.appendChild(fragment);
    listEl.hidden = false;
  };

  const formatTransferMeta = (written, total, speed, etaSecs) => {
    const parts = [];
    if (total > 0) {
      parts.push(`${formatBytes(written)} / ${formatBytes(total)}`);
    }
    if (speed > 0) {
      parts.push(`${formatBytes(speed)}/s`);
    }
    if (typeof etaSecs === "number" && Number.isFinite(etaSecs)) {
      parts.push(`About ${formatDuration(etaSecs)} left`);
    }
    return parts.join(" · ");
  };

  return {
    onOperationStart: () => {
      hideFlashResult();
      setFlashInProgress(true);
      revealActionBar();
    },
    onDownloadPrepare: (statusText, files = []) => {
      lastAnnouncedFile = null;
      initFileProgressList(files);
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
        fileEtaSecs = null,
        overallWritten = 0,
        overallTotal = 0,
        percent = 0,
        wireSpeed = 0,
        etaSecs = null,
      } = data;

      const multiFile = fileRows.size > 1;
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
        detailText: formatTransferMeta(overallWritten, overallTotal, wireSpeed, etaSecs),
      });

      const row = fileRows.get(fileName);
      if (row) {
        const filePct = fileTotal > 0 ? Math.min(100, (fileWritten / fileTotal) * 100) : 100;
        row.item.className = "download-file-item is-active";
        row.statusEl.className = "badge badge-hashing";
        row.statusEl.textContent = `${Math.floor(filePct)}%`;
        setBarPercent(row.barEl, filePct);
        row.metaEl.textContent = formatTransferMeta(fileWritten, fileTotal, wireSpeed, fileEtaSecs);
      }
    },
    onFileDone: (data) => {
      const { fileName, skipped, size, overallWritten, overallTotal } = data || {};
      if (overallTotal > 0) {
        updateOperationProgress({
          percent: (overallWritten / overallTotal) * 100,
        });
      }
      const row = fileRows.get(fileName);
      if (!row) return;

      row.item.className = "download-file-item is-done";
      row.statusEl.className = "badge badge-valid";
      row.statusEl.textContent = skipped ? "Skipped" : "Done";
      setBarPercent(row.barEl, 100);

      const finalSize = formatBytes(size || row.size);
      row.metaEl.textContent = skipped ? `${finalSize} · Already complete` : finalSize;
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
      resetFileProgressList();
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
      fileRows.clear();
      setCancelOperationButton({ visible: false });
      setFlashInProgress(false);
    },
  };
}

export function setupDownloadUi() {
  onOpfsCacheChange(renderOpfsCacheBanner);
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
    hideFlashResult();
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
    eraseChecked: Boolean(document.getElementById("opt-nand-erase")?.checked),
    confirmWipe: (wipeReasons) =>
      confirm(`${wipeReasons.join("\n")}\n\nThis will wipe the device's data. Continue?`),
    ui: createDownloadUiCallbacks(),
  });
}
