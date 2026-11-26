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
import { notifyStateChange, state } from "./state.js";

let inspectGen = 0;
let bridgeCheckInFlight = false;

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
    notifyStateChange();
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
  const rows = [];

  for (const entry of entries) {
    if (combineCsc && (entry.component === "home_csc" || entry.component === "csc")) {
      if (!addedSmartCsc) {
        addedSmartCsc = true;
        rows.push({
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
    rows.push({
      kind: "single",
      entry,
      checked: defaultChecked,
    });
  }

  state.archiveRows = rows;
}

export function setArchiveRowChecked(idx, checked) {
  const row = state.archiveRows[idx];
  if (!row) return;
  row.checked = Boolean(checked);
  notifyStateChange();
}

export function setSmartCscChoice(idx, choice) {
  const row = state.archiveRows[idx];
  if (!row || row.kind !== "smart_csc") return;
  row.cscChoice = choice;
  row.checked = true;
  notifyStateChange();
}

export function setServerOutputMode(mode) {
  state.serverOutputMode = mode === "zip" ? "zip" : "entries";
  notifyStateChange();
}

// --- Version Lookup & Inspection ---
export function clearInspectedArchive() {
  inspectGen++;
  state.serverInspect = null;
  state.archiveRows = [];
  notifyStateChange();
}

export function clearServerHistory() {
  state.serverHistory = null;
  notifyStateChange();
}

export async function checkFirmwareVersions(model, region) {
  if (state.isBusy || state.serverQuerying) return;
  if (!state.fusBridge.connected) return;
  if (!model || !region) return;

  state.serverLookupError = "";
  state.serverHistory = null;
  clearInspectedArchive();

  state.serverQuerying = true;
  state.serverQueryPhase = "history";
  notifyStateChange();
  appendLog(`Checking Samsung FUS firmware versions for ${model} (${region})...`);

  try {
    const transport = await getMainThreadFusTransport();
    const history = await fusFetchHistory(model, region, transport);
    state.serverHistory = { ...history, model, region };
    state.serverCustomVersionOpen = !history.latest;

    const count =
      (history.latest ? 1 : 0) +
      (history.previous?.length ?? 0) +
      (history.beta?.length ?? 0);
    appendLog(`Found ${count} firmware version(s); latest is ${history.latest}.`);

    state.serverQuerying = false;
    state.serverQueryPhase = null;
    notifyStateChange();

    if (history.latest) {
      await inspectFirmwareVersion(model, region, history.latest);
    }
  } catch (err) {
    const msg = err?.message || String(err);
    reportError(`FUS version lookup failed: ${msg}`);
    state.serverQuerying = false;
    state.serverQueryPhase = null;
    state.serverLookupError = `Version lookup failed: ${msg}`;
    notifyStateChange();
  }
}

export async function inspectFirmwareVersion(model, region, version) {
  if (state.isBusy) return;
  if (!model || !region || !version) return;
  if (!state.fusBridge.connected) return;

  const myGen = ++inspectGen;
  state.serverLookupError = "";
  state.serverInspect = null;
  state.archiveRows = [];

  state.serverQuerying = true;
  state.serverQueryPhase = "inspect";
  notifyStateChange();
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
    notifyStateChange();
  } catch (err) {
    if (myGen !== inspectGen) return;
    const msg = err?.message || String(err);
    reportError(`FUS inspect failed: ${msg}`);
    state.serverLookupError = `Inspect failed: ${msg}`;
    notifyStateChange();
  } finally {
    if (myGen === inspectGen) {
      state.serverQuerying = false;
      state.serverQueryPhase = null;
      notifyStateChange();
    }
  }
}
