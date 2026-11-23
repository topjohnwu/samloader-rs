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

// OPFS firmware cache management, worker downloads, and Download & Flash.

import {
  appendRawWasmLogs,
  clearOpfsCache,
  getOpfsBuildFiles,
  getOpfsCacheInfo,
} from "../bridge.js";
import { openBridgePort } from "../fus_bridge.js";
import { state } from "./state.js";
import { announce, formatBytes, formatDuration } from "./util.js";
import { appendLog, reportError } from "./log.js";
import { runExclusive, runExclusiveWithSetup, updateControlsState } from "./controls.js";
import { loadFilesIntoSlots } from "./slots.js";
import {
  executeFlashWithFiles,
  hideFlashResult,
  revealActionBar,
  setCancelOperationButton,
  setFlashInProgress,
  showOperationResult,
  updateOperationProgress,
} from "./flash.js";

export const COMPONENT_META = {
  bl: { badge: "BL", slot: "BL", label: "Bootloader" },
  ap: { badge: "AP", slot: "AP", label: "System / Application" },
  cp: { badge: "CP", slot: "CP", label: "Modem / Radio" },
  home_csc: { badge: "CSC", slot: "CSC", label: "Keep Data (HOME_CSC)" },
  csc: { badge: "CSC", slot: "CSC", label: "Wipe Data (CSC)" },
  userdata: { badge: "USER", slot: "USERDATA", label: "User Data (wipes data)" },
};

export async function mapEntriesToOdinSlots(
  entries,
  { resolveFile = (entry) => entry.file, onSkipCsc = null } = {}
) {
  const slotFiles = {};
  const hasHomeCsc = entries.some((entry) => entry.component === "home_csc");

  for (const entry of entries) {
    const meta = entry.component ? COMPONENT_META[entry.component] : null;
    if (!meta) continue;
    if (entry.component === "csc" && hasHomeCsc) {
      onSkipCsc?.(entry);
      continue;
    }
    const file = await resolveFile(entry);
    if (file) {
      slotFiles[meta.slot] = file;
    }
  }
  return slotFiles;
}

// --- OPFS Staging Cache Indicator ---
export async function refreshOpfsCacheBanner() {
  const banner = document.getElementById("opfs-cache-banner");
  const titleEl = document.getElementById("opfs-cache-title");
  const metaEl = document.getElementById("opfs-cache-meta");

  let info = null;
  try {
    info = await getOpfsCacheInfo();
  } catch {
    info = null;
  }
  state.opfsCache = info;

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

export async function handleClearOpfsCache() {
  if (state.isBusy || state.serverQuerying) return;
  await runExclusive(async () => {
    try {
      await clearOpfsCache();
      appendLog("Cleared OPFS firmware download cache.");
      await refreshOpfsCacheBanner();
    } catch (err) {
      reportError(`Failed to clear OPFS cache: ${err?.message || err}`);
    }
  });
}

// --- Download Worker Execution ---
export async function runDownloadWorker({ target, params }) {
  const port = await openBridgePort();
  let worker;
  try {
    worker = new Worker(new URL("../download_worker.js", import.meta.url), {
      type: "module",
    });
  } catch (err) {
    try {
      port.close();
    } catch {
      // Ignore close errors
    }
    throw err;
  }

  let lastAnnouncedFile = null;
  let cancelRequested = false;

  setCancelOperationButton({
    visible: true,
    disabled: false,
    label: "Cancel",
    onCancel: () => {
      if (cancelRequested) return;
      cancelRequested = true;
      setCancelOperationButton({ visible: true, disabled: true, label: "Cancelling..." });
      updateOperationProgress({ statusText: "Cancelling download and saving checkpoint..." });
      appendLog("Cancelling firmware download...");
      worker.postMessage({ type: "CANCEL" });
    },
  });

  return await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn) => {
      if (settled) return;
      settled = true;
      worker.terminate();
      fn();
    };

    worker.onmessage = ({ data }) => {
      if (!data || typeof data !== "object") return;
      switch (data.type) {
        case "PROGRESS": {
          if (cancelRequested) break;
          const {
            fileIndex,
            fileCount,
            fileName,
            overallWritten = 0,
            overallTotal = 0,
            percent = 0,
            wireSpeed = 0,
            etaSecs = null,
          } = data;

          const statusText =
            params.mode === "zip"
              ? `Downloading ${fileName || params.version}...`
              : `Downloading ${fileName} (${fileIndex} of ${fileCount})`;

          if (fileName && fileName !== lastAnnouncedFile) {
            lastAnnouncedFile = fileName;
            announce(statusText);
          }

          const details = [];
          if (overallTotal > 0) {
            details.push(`${formatBytes(overallWritten)} / ${formatBytes(overallTotal)}`);
          }
          if (wireSpeed > 0) {
            details.push(`${formatBytes(wireSpeed)}/s`);
          }
          if (typeof etaSecs === "number" && Number.isFinite(etaSecs)) {
            details.push(`About ${formatDuration(etaSecs)} left`);
          }

          updateOperationProgress({
            statusText,
            percent,
            detailText: details.join(" · "),
          });
          break;
        }
        case "FILE_DONE": {
          const verb = data.skipped ? "Skipped (already complete)" : "Downloaded";
          appendLog(`${verb}: ${data.fileName} (${formatBytes(data.size || 0)})`);
          break;
        }
        case "WARNING":
          appendLog(`[FUS WARNING] ${data.message}`);
          break;
        case "LOG":
          appendRawWasmLogs(data.lines);
          break;
        case "COMPLETE":
          finish(() => resolve({ status: "complete", result: data.result }));
          break;
        case "CANCELLED":
          finish(() => resolve({ status: "cancelled" }));
          break;
        case "ERROR":
          finish(() => reject(new Error(data.error || "Download failed")));
          break;
      }
    };

    worker.onerror = (e) => {
      finish(() =>
        reject(new Error(e.message || "Download worker encountered an unexpected error"))
      );
    };

    try {
      worker.postMessage(
        {
          type: "START",
          port,
          target,
          params,
          verbose: Boolean(state.verbose),
        },
        [port]
      );
    } catch (err) {
      try {
        port.close();
      } catch {
        // Ignore close errors
      }
      finish(() => reject(err));
    }
  });
}

export async function handleLoadIntoLocalFlash(onSwitchToLocal) {
  if (state.isBusy || !state.lastDownloadedDir) return;
  const { dirHandle, files } = state.lastDownloadedDir;

  try {
    const slotMapping = await mapEntriesToOdinSlots(files, {
      resolveFile: async (entry) => {
        const handle = await dirHandle.getFileHandle(entry.name);
        return await handle.getFile();
      },
      onSkipCsc: (entry) => {
        appendLog(
          `Skipped loading ${entry.name} into CSC slot (preferring HOME_CSC to preserve data).`
        );
      },
    });

    if (Object.keys(slotMapping).length === 0) {
      showOperationResult(
        "warning",
        "No flashable Odin packages (.tar / .tar.md5) were found in the downloaded files."
      );
      return;
    }

    loadFilesIntoSlots(slotMapping);
    hideFlashResult();
    onSwitchToLocal?.();
    appendLog(
      `Loaded ${Object.keys(slotMapping).length} package(s) from "${dirHandle.name}" into Local Files.`
    );
  } catch (err) {
    reportError(`Failed to load downloaded files into Local Flash: ${err?.message || err}`);
  }
}

// --- Shared Download Lifecycle Helpers ---
function createOpfsTarget(buildKey, { model, region, version, info }) {
  return {
    kind: "opfs",
    buildKey,
    meta: {
      buildKey,
      model,
      region,
      version,
      decryptedFilename: info.decryptedFilename,
      fingerprintHex: info.fingerprintHex,
    },
  };
}

async function readWantedOpfsFiles(buildKey, wantedNames) {
  const allOpfsFiles = await getOpfsBuildFiles(buildKey);
  const wanted = new Set(wantedNames);
  return wanted.size > 0 ? allOpfsFiles.filter((f) => wanted.has(f.name)) : allOpfsFiles;
}

async function executeServerOperation(logTitle, targetKind, bodyFn) {
  hideFlashResult();
  setFlashInProgress(true);
  revealActionBar();
  appendLog(logTitle);

  try {
    await bodyFn();
  } catch (err) {
    if (targetKind === "opfs") {
      await refreshOpfsCacheBanner();
    }
    const firstLine = String(err?.message || err).split("\n")[0];
    showOperationResult("error", `Download failed: ${firstLine}`, { showLog: true });
    announce("Download failed");
    reportError(`[DOWNLOAD ERROR] ${err}`);
  } finally {
    setCancelOperationButton({ visible: false });
    setFlashInProgress(false);
  }
}

async function performDownload({ target, params, statusText, cancelLog }) {
  updateOperationProgress({
    statusText,
    percent: 0,
    detailText: "",
  });

  const outcome = await runDownloadWorker({ target, params });
  if (target.kind === "opfs") {
    await refreshOpfsCacheBanner();
  }
  if (outcome.status === "cancelled") {
    const cancelMsg = "Download cancelled — progress saved for resume.";
    showOperationResult("warning", cancelMsg);
    announce("Download cancelled");
    appendLog(cancelLog || cancelMsg);
    return null;
  }

  return outcome.result;
}

// --- Download Only Action ---
export async function handleDownloadOnly({ selectedEntries = [] } = {}) {
  if (state.isBusy || state.serverQuerying) return;
  if (!state.fusBridge.connected) return;
  if (!state.serverInspect) return;

  const { model, region, version, info } = state.serverInspect;
  const mode = state.serverOutputMode === "zip" ? "zip" : "entries";

  if (mode === "entries" && selectedEntries.length === 0) return;

  await runExclusiveWithSetup(
    async () => {
      let dirHandle;
      // Pick a directory so single-file and full-ZIP downloads can store
      // `.part` / `.part.meta` sidecars for resumable transfers.
      try {
        dirHandle = await window.showDirectoryPicker({ mode: "readwrite" });
      } catch (err) {
        if (err?.name === "AbortError") {
          return false;
        }
        reportError(`Could not open save location: ${err?.message || err}`);
        return false;
      }

      state.lastDownloadedDir = null;
      return { target: { kind: "directory", dirHandle }, dirHandle };
    },
    async ({ target, dirHandle }) => {
      await executeServerOperation(
        `=== Starting Firmware Download (${model} / ${region} / ${version}) ===`,
        target.kind,
        async () => {
          const result = await performDownload({
            target,
            params: {
              model,
              region,
              version,
              mode,
              entryNames: mode === "entries" ? selectedEntries.map((e) => e.name) : undefined,
              concurrency: state.serverConcurrency,
              force: false,
            },
            statusText: "Connecting to Samsung FUS...",
          });
          if (!result) return;

          updateOperationProgress({ percent: 100 });

          const hasOdin = (result.files || []).some((f) => f.component !== null);
          const canLoadIntoLocal = hasOdin && state.capabilities.canFlash;
          if (canLoadIntoLocal) {
            state.lastDownloadedDir = { dirHandle, files: result.files };
          }
          const summary =
            result.files.length === 1
              ? `Downloaded ${result.files[0].name} to "${dirHandle.name}".`
              : `Downloaded ${result.files.length} file(s) to "${dirHandle.name}".`;
          showOperationResult("success", summary, { showLoadIntoLocal: canLoadIntoLocal });

          announce("Download complete");
          appendLog("=== Firmware Download Complete ===");
        }
      );
    }
  );
}

// --- Download & Flash Action ---
async function tryGetCompleteCachedFiles(buildKey, requiredEntries) {
  try {
    const cacheInfo = await getOpfsCacheInfo();
    if (!cacheInfo || !cacheInfo.complete || cacheInfo.buildKey !== buildKey) {
      return null;
    }
    const files = await getOpfsBuildFiles(buildKey);
    const byName = new Map(files.map((f) => [f.name, f]));
    for (const entry of requiredEntries) {
      const cached = byName.get(entry.name);
      if (!cached || !cached.file || cached.file.size !== entry.uncompressedSize) {
        return null;
      }
    }
    return requiredEntries.map((entry) => byName.get(entry.name));
  } catch {
    return null;
  }
}

export async function handleDownloadAndFlash({
  odinEntries = [],
  hasBothCsc = false,
  hasCscWipe = false,
  hasUserdata = false,
} = {}) {
  if (!state.capabilities.canFlash || !state.capabilities.canDownload) return;
  if (state.isBusy || state.serverQuerying) return;
  if (!state.fusBridge.connected) return;
  if (!state.serverInspect || state.device?.mode !== "download") return;
  if (state.serverOutputMode !== "entries") return;

  if (odinEntries.length === 0 || hasBothCsc) return;

  // Ask upfront before spending minutes downloading if this selection wipes user data
  const eraseChecked = Boolean(document.getElementById("opt-nand-erase")?.checked);
  const wipeReasons = [];
  if (hasCscWipe) {
    wipeReasons.push("CSC (wipe data) is selected instead of HOME_CSC.");
  }
  if (hasUserdata) {
    wipeReasons.push("USERDATA package is selected.");
  }
  if (eraseChecked) {
    wipeReasons.push("NAND Erase (USERDATA) is enabled.");
  }
  if (
    wipeReasons.length > 0 &&
    !confirm(`${wipeReasons.join("\n")}\n\nThis will wipe the device's data. Continue?`)
  ) {
    appendLog("Download & Flash cancelled before starting (wipe confirmation declined).");
    return;
  }
  if (state.device?.mode !== "download") {
    reportError("Download Mode device disconnected before flashing started.");
    return;
  }
  const skipWipeConfirmAlreadyAsked = wipeReasons.length > 0;

  const { model, region, version, info } = state.serverInspect;
  const buildKey = `${info.fingerprintHex}:entries`;
  state.lastDownloadedDir = null;

  await runExclusive(async () => {
    await executeServerOperation(
      `=== Starting Download & Flash (${model} / ${region} / ${version}) ===`,
      "opfs",
      async () => {
        let cachedEntries = await tryGetCompleteCachedFiles(buildKey, odinEntries);

        if (cachedEntries) {
          appendLog("Found complete OPFS firmware cache — skipping download and proceeding to flash.");
        } else {
          const result = await performDownload({
            target: createOpfsTarget(buildKey, { model, region, version, info }),
            params: {
              model,
              region,
              version,
              mode: "entries",
              entryNames: odinEntries.map((e) => e.name),
              concurrency: state.serverConcurrency,
              force: false,
            },
            statusText: "Preparing OPFS cache & connecting to Samsung FUS...",
            cancelLog: "Download cancelled — OPFS partial checkpoint kept for resume.",
          });
          if (!result) return;

          cachedEntries = await readWantedOpfsFiles(
            buildKey,
            odinEntries.map((e) => e.name)
          );
        }

        const slotFiles = await mapEntriesToOdinSlots(cachedEntries);
        if (Object.keys(slotFiles).length === 0) {
          throw new Error("Downloaded files could not be mapped to any Odin package slot.");
        }

        setCancelOperationButton({ visible: false });
        const flashRes = await executeFlashWithFiles(slotFiles, {
          skipWipeConfirmAlreadyAsked,
        });

        if (flashRes.success) {
          await clearOpfsCache();
          await refreshOpfsCacheBanner();
          appendLog("Cleared OPFS staging cache after successful flash.");
        } else {
          await refreshOpfsCacheBanner();
          if (flashRes.aborted) {
            showOperationResult(
              "warning",
              "Flashing cancelled — downloaded firmware cached for retry."
            );
          }
          appendLog("Kept OPFS firmware files so retrying Download & Flash skips re-downloading.");
        }
      }
    );
  });
}
