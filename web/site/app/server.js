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

// Samsung FUS bridge status, firmware lookup, ZIP inspection, and archive component selection.

import { fusFetchHistory, fusInspectFirmware } from "./bridge.js";
import { formatBytes } from "./format.js";
import {
  EXPECTED_BRIDGE_VERSION,
  detectFusBridge,
  getMainThreadFusTransport,
  isBridgeOutdated,
  onFusBridgeReady,
} from "./fus_bridge.js";
import { appendLog, reportError } from "./logger.js";
import { state } from "./state.js";

const serverListeners = new Set();

let archiveRows = [];
let inspectGen = 0;
let bridgeCheckInFlight = false;

export function onServerChange(listener) {
  serverListeners.add(listener);
  return () => serverListeners.delete(listener);
}

function notifyServerChange(event) {
  for (const listener of serverListeners) {
    listener(event);
  }
}

export function getArchiveRows() {
  return archiveRows;
}

// --- FUS Bridge Status & Probing ---
function applyBridgeStatus(status) {
  const prev = state.fusBridge;
  const connected = Boolean(status?.connected);
  const version = typeof status?.version === "string" ? status.version : null;
  const outdated = connected
    ? Boolean(status?.outdated ?? isBridgeOutdated(version))
    : false;
  const next = {
    checked: true,
    connected,
    version,
    outdated,
  };

  const changed =
    !prev.checked ||
    prev.connected !== next.connected ||
    prev.version !== next.version ||
    prev.outdated !== next.outdated;

  state.fusBridge = next;
  if (changed) {
    notifyServerChange({ type: "bridge", prev, next });
  }
  return { prev, next, changed };
}

export function initBridgeAnnouncementListener() {
  onFusBridgeReady((status) => {
    const { prev, next, changed } = applyBridgeStatus(status);

    if (changed && !bridgeCheckInFlight && prev.checked && !prev.connected && next.connected) {
      if (next.outdated) {
        appendLog(
          `FUS Bridge detected (${next.version ? `v${next.version}` : "unknown version"}), but v${EXPECTED_BRIDGE_VERSION} is recommended. Update the userscript and reload.`
        );
      } else {
        appendLog(`FUS Bridge detected: v${next.version ?? "?"}.`);
      }
    }
  });
}

export async function checkFusBridge() {
  bridgeCheckInFlight = true;
  try {
    const status = await detectFusBridge();
    applyBridgeStatus(status);
  } catch {
    applyBridgeStatus({ connected: false });
  } finally {
    bridgeCheckInFlight = false;
  }

  if (state.fusBridge.connected && state.fusBridge.outdated) {
    const installedLabel = state.fusBridge.version
      ? `v${state.fusBridge.version}`
      : "an unknown version";
    appendLog(
      `FUS Bridge userscript is outdated (installed ${installedLabel}; expected v${EXPECTED_BRIDGE_VERSION}). Update the userscript and click Reload Page.`
    );
  }
}

// --- Bootloader Matching ---
export function doesVersionMatchBootloader(versionStr, bootloaderVer) {
  if (!versionStr || !bootloaderVer) return false;
  const target = bootloaderVer.trim().toUpperCase();
  if (!target) return false;
  const parts = versionStr.split("/").map((p) => p.trim().toUpperCase());
  return parts[0] === target || parts[3] === target;
}

// --- Archive Row Grouping & Selection ---
function buildArchiveRows(entries) {
  const homeCsc = entries.filter((e) => e.component === "home_csc");
  const wipeCsc = entries.filter((e) => e.component === "csc");
  const combineCsc = homeCsc.length === 1 && wipeCsc.length === 1;

  let addedSmartCsc = false;
  archiveRows = [];

  for (const entry of entries) {
    if (combineCsc && (entry.component === "home_csc" || entry.component === "csc")) {
      if (!addedSmartCsc) {
        addedSmartCsc = true;
        archiveRows.push({
          kind: "smart_csc",
          checked: true,
          cscChoice: "home_csc",
          homeEntry: homeCsc[0],
          wipeEntry: wipeCsc[0],
        });
      }
      continue;
    }

    const defaultChecked = ["bl", "ap", "cp", "home_csc", "csc"].includes(entry.component);
    archiveRows.push({
      kind: "single",
      entry,
      checked: defaultChecked,
    });
  }
}

export function getSelectedEntriesInfo() {
  const selectedEntries = [];
  let hasBothCsc = false;

  for (const row of archiveRows) {
    if (!row.checked) continue;
    if (row.kind === "smart_csc") {
      if (row.cscChoice === "home_csc") {
        selectedEntries.push(row.homeEntry);
      } else if (row.cscChoice === "csc") {
        selectedEntries.push(row.wipeEntry);
      } else {
        selectedEntries.push(row.homeEntry, row.wipeEntry);
        hasBothCsc = true;
      }
    } else {
      selectedEntries.push(row.entry);
    }
  }

  if (
    !hasBothCsc &&
    selectedEntries.some((e) => e.component === "home_csc") &&
    selectedEntries.some((e) => e.component === "csc")
  ) {
    hasBothCsc = true;
  }

  const totalBytes = selectedEntries.reduce((sum, e) => sum + (e.uncompressedSize || 0), 0);
  const odinEntries = selectedEntries.filter((e) => e.component !== null);
  const hasCscWipe = selectedEntries.some((e) => e.component === "csc");
  const hasUserdata = selectedEntries.some((e) => e.component === "userdata");

  return {
    selectedEntries,
    odinEntries,
    totalBytes,
    hasBothCsc,
    hasCscWipe,
    hasUserdata,
  };
}

export function syncArchiveSelectionState() {
  const info = getSelectedEntriesInfo();
  const { selectedEntries, odinEntries, hasBothCsc } = info;

  if (!state.serverInspect) {
    state.serverSelection = {
      validForDownload: false,
      validForFlash: false,
      hasBothCsc: false,
      hasOdinComponent: false,
    };
  } else if (state.serverOutputMode === "zip") {
    state.serverSelection = {
      validForDownload: true,
      validForFlash: false,
      hasBothCsc: false,
      hasOdinComponent: false,
    };
  } else {
    state.serverSelection = {
      validForDownload: selectedEntries.length > 0,
      validForFlash: odinEntries.length > 0 && !hasBothCsc,
      hasBothCsc,
      hasOdinComponent: odinEntries.length > 0,
    };
  }

  notifyServerChange({ type: "selection", info });
}

export function setArchiveRowChecked(idx, checked) {
  const row = archiveRows[idx];
  if (!row) return;
  row.checked = Boolean(checked);
  syncArchiveSelectionState();
}

export function setSmartCscChoice(idx, choice) {
  const row = archiveRows[idx];
  if (!row || row.kind !== "smart_csc") return;
  row.cscChoice = choice;
  row.checked = true;
  syncArchiveSelectionState();
}

export function setServerOutputMode(mode) {
  state.serverOutputMode = mode === "zip" ? "zip" : "entries";
  syncArchiveSelectionState();
  notifyServerChange({ type: "output_mode", mode: state.serverOutputMode });
}

// --- Version Lookup & Inspection ---
export function clearInspectedArchive() {
  inspectGen++;
  state.serverInspect = null;
  archiveRows = [];
  notifyServerChange({ type: "inspect_cleared" });
  syncArchiveSelectionState();
}

export function clearServerHistory() {
  state.serverHistory = null;
  notifyServerChange({ type: "history_cleared" });
}

export async function checkFirmwareVersions(model, region) {
  if (state.isBusy || state.serverQuerying) return;
  if (!state.fusBridge.connected) return;
  if (!model || !region) return;

  notifyServerChange({ type: "lookup_error", message: "" });
  state.serverHistory = null;
  clearInspectedArchive();

  state.serverQuerying = true;
  notifyServerChange({ type: "querying_history", active: true });
  appendLog(`Checking Samsung FUS firmware versions for ${model} (${region})...`);

  try {
    const transport = await getMainThreadFusTransport();
    const history = await fusFetchHistory(model, region, transport);
    state.serverHistory = { ...history, model, region };

    const count =
      (history.latest ? 1 : 0) +
      (history.previous?.length ?? 0) +
      (history.beta?.length ?? 0);
    appendLog(`Found ${count} firmware version(s); latest is ${history.latest}.`);

    state.serverQuerying = false;
    notifyServerChange({ type: "history", history: state.serverHistory });
    notifyServerChange({ type: "querying_history", active: false });

    if (history.latest) {
      await inspectFirmwareVersion(model, region, history.latest);
    }
  } catch (err) {
    const msg = err?.message || String(err);
    reportError(`FUS version lookup failed: ${msg}`);
    state.serverQuerying = false;
    notifyServerChange({ type: "lookup_error", message: `Version lookup failed: ${msg}` });
    notifyServerChange({ type: "querying_history", active: false });
  }
}

export async function inspectFirmwareVersion(model, region, version) {
  if (state.isBusy) return;
  if (!model || !region || !version) return;
  if (!state.fusBridge.connected) return;

  const myGen = ++inspectGen;
  notifyServerChange({ type: "lookup_error", message: "" });
  state.serverInspect = null;
  archiveRows = [];

  state.serverQuerying = true;
  notifyServerChange({ type: "inspecting", active: true });
  syncArchiveSelectionState();
  appendLog(`Inspecting firmware ${version} for ${model} (${region})...`);

  try {
    const transport = await getMainThreadFusTransport();
    const info = await fusInspectFirmware(model, region, version, transport);
    if (myGen !== inspectGen) return;

    state.serverInspect = {
      model,
      region,
      version: info.version || version,
      info,
    };
    state.serverOutputMode = "entries";
    buildArchiveRows(info.entries || []);

    appendLog(
      `Inspected ${info.decryptedFilename} (${formatBytes(info.decryptedSize)}, ${(info.entries || []).length} entries).`
    );
    notifyServerChange({ type: "inspect_ready", inspect: state.serverInspect });
  } catch (err) {
    if (myGen !== inspectGen) return;
    const msg = err?.message || String(err);
    reportError(`FUS inspect failed: ${msg}`);
    notifyServerChange({ type: "lookup_error", message: `Inspect failed: ${msg}` });
  } finally {
    if (myGen === inspectGen) {
      state.serverQuerying = false;
      notifyServerChange({ type: "inspecting", active: false });
      syncArchiveSelectionState();
    }
  }
}
