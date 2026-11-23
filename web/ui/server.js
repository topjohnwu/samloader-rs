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

// Samsung FUS bridge status, firmware lookup, archive inspection, and component selector.

import { fusFetchHistory, fusInspectFirmware } from "../bridge.js";
import {
  EXPECTED_BRIDGE_VERSION,
  detectFusBridge,
  getMainThreadFusTransport,
  isBridgeOutdated,
  onFusBridgeReady,
} from "../fus_bridge.js";
import { state } from "./state.js";
import { formatBytes } from "./util.js";
import { appendLog, reportError } from "./log.js";
import { updateControlsState } from "./controls.js";
import { hasDeviceInfo, queryAndShowDeviceInfo, setDeviceUpdateListener } from "./device.js";
import {
  COMPONENT_META,
  handleClearOpfsCache,
  handleDownloadAndFlash,
  handleDownloadOnly,
  handleLoadIntoLocalFlash,
  handleSaveOpfsFiles,
  refreshOpfsCacheBanner,
  revokeDownloadUrls,
} from "./download.js";

const STORAGE_SOURCE = "samloader.firmwareSource";
const STORAGE_MODEL = "samloader.serverModel";
const STORAGE_REGION = "samloader.serverRegion";
const STORAGE_CONCURRENCY = "samloader.serverConcurrency";

const SMART_CSC_CHOICES = [
  { value: "home_csc", label: "Keep Data (HOME_CSC)" },
  { value: "csc", label: "Wipe Data (CSC)" },
  { value: "both", label: "Both" },
];

let archiveRows = [];
let inspectGen = 0;
let bridgeCheckInFlight = false;

function readStorage(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key, value) {
  try {
    if (value === null || value === undefined || value === "") {
      localStorage.removeItem(key);
    } else {
      localStorage.setItem(key, String(value));
    }
  } catch {
    // Storage unavailable
  }
}

function normalizeUpperInput(input) {
  if (!input) return "";
  const start = input.selectionStart;
  const end = input.selectionEnd;
  const upper = input.value.toUpperCase();
  if (input.value !== upper) {
    input.value = upper;
    if (start !== null && end !== null) {
      try {
        input.setSelectionRange(start, end);
      } catch {
        // Ignore if input type doesn't support selection
      }
    }
  }
  return upper.trim();
}

function getLookupModel() {
  return (document.getElementById("server-model")?.value ?? "").trim().toUpperCase();
}

function getLookupRegion() {
  return (document.getElementById("server-region")?.value ?? "").trim().toUpperCase();
}

function setLookupError(msg) {
  const el = document.getElementById("server-lookup-error");
  if (!el) return;
  el.textContent = msg || "";
  el.hidden = !msg;
}

function setFirmwareSource(source, persist = true) {
  const { canFlash, canDownload } = state.capabilities;
  let normalized = source === "local" ? "local" : "server";
  if (!canDownload && canFlash) normalized = "local";
  else if (!canFlash && canDownload) normalized = "server";
  state.firmwareSource = normalized;
  if (persist && canFlash && canDownload) {
    writeStorage(STORAGE_SOURCE, normalized);
  }
  updateControlsState();
}

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
    renderBridgeBanner();
    updateControlsState();
  }
  return { prev, next, changed };
}

function setupBridgeAnnouncementListener() {
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

// --- FUS Bridge Status Banner ---
export async function checkFusBridge({ quiet = false } = {}) {
  const recheckBtn = document.getElementById("btn-recheck-bridge");
  const feedbackEl = document.getElementById("fus-bridge-feedback");
  if (!quiet) {
    if (recheckBtn) {
      recheckBtn.disabled = true;
      recheckBtn.textContent = "Checking...";
    }
    if (feedbackEl) {
      feedbackEl.textContent = "";
      feedbackEl.hidden = true;
    }
  }

  bridgeCheckInFlight = true;
  try {
    const status = await detectFusBridge();
    applyBridgeStatus(status);
  } catch {
    applyBridgeStatus({ connected: false });
  } finally {
    bridgeCheckInFlight = false;
    if (!quiet && recheckBtn) {
      recheckBtn.disabled = false;
      recheckBtn.textContent = "Recheck";
    }
  }

  if (state.fusBridge.connected && state.fusBridge.outdated) {
    const installedLabel = state.fusBridge.version
      ? `v${state.fusBridge.version}`
      : "an unknown version";
    const msg = `FUS Bridge userscript is outdated (installed ${installedLabel}; expected v${EXPECTED_BRIDGE_VERSION}). Update the userscript and click Reload Page.`;
    if (!quiet && feedbackEl) {
      feedbackEl.textContent = msg;
      feedbackEl.hidden = false;
    }
    appendLog(msg);
  } else if (!quiet && state.fusBridge.connected) {
    appendLog(`FUS Bridge detected: v${state.fusBridge.version ?? "?"}.`);
  } else if (!quiet) {
    const msg =
      "FUS Bridge not detected yet. If you just installed or updated the userscript, click Reload Page so your userscript manager activates it.";
    if (feedbackEl) {
      feedbackEl.textContent = msg;
      feedbackEl.hidden = false;
    }
    appendLog(msg);
  }
}

function renderBridgeBanner() {
  const setupEl = document.getElementById("fus-bridge-setup");
  const connectedEl = document.getElementById("fus-bridge-connected");
  const badgeTextEl = document.getElementById("fus-bridge-badge-text");
  const titleEl = document.getElementById("fus-bridge-banner-title");
  const descEl = document.getElementById("fus-bridge-banner-desc");
  const tampermonkeyStep = document.getElementById("bridge-step-tampermonkey");
  const installStepLabel = document.getElementById("bridge-install-step-label");
  const installLink = document.getElementById("link-install-userscript");
  const reloadStep = document.getElementById("bridge-reload-step");
  const feedbackEl = document.getElementById("fus-bridge-feedback");

  const { connected, version, outdated } = state.fusBridge;
  if (connected && !outdated) {
    if (setupEl) setupEl.hidden = true;
    if (feedbackEl) {
      feedbackEl.textContent = "";
      feedbackEl.hidden = true;
    }
    if (connectedEl) connectedEl.hidden = false;
    if (badgeTextEl) {
      badgeTextEl.textContent = `FUS Bridge v${version ?? EXPECTED_BRIDGE_VERSION}`;
    }
    return;
  }

  if (connectedEl) connectedEl.hidden = true;
  if (setupEl) setupEl.hidden = false;

  if (connected && outdated) {
    const installedLabel = version ? `v${version}` : "unknown version";
    if (titleEl) titleEl.textContent = "FUS Bridge Userscript Outdated";
    if (descEl) {
      descEl.textContent = `Installed userscript (${installedLabel}) is older than v${EXPECTED_BRIDGE_VERSION}. Update the userscript so this page has the latest fixes and compatibility.`;
    }
    if (tampermonkeyStep) tampermonkeyStep.hidden = true;
    if (installStepLabel) installStepLabel.textContent = "Update the bridge userscript:";
    if (installLink) installLink.textContent = "Update Userscript";
    if (reloadStep) {
      reloadStep.innerHTML =
        "Click <strong>Reload Page</strong> so your userscript manager loads the updated bridge.";
    }
  } else {
    if (titleEl) titleEl.textContent = "FUS Bridge Userscript Required";
    if (descEl) {
      descEl.textContent =
        "Samsung FUS blocks browser CORS and serves firmware binaries over plain HTTP. Install the local bridge userscript so this page can fetch firmware directly.";
    }
    if (tampermonkeyStep) tampermonkeyStep.hidden = false;
    if (installStepLabel) installStepLabel.textContent = "Install the bridge userscript:";
    if (installLink) installLink.textContent = "Install Userscript";
    if (reloadStep) {
      reloadStep.innerHTML =
        "Click <strong>Reload Page</strong> so your userscript manager injects the bridge into this tab.";
    }
  }
}

async function handleCopyUserscript(btn) {
  const originalLabel = btn.textContent;
  btn.disabled = true;
  try {
    const resp = await fetch("samloader-fus-bridge.user.js", { cache: "no-store" });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }
    const source = await resp.text();
    if (!navigator.clipboard?.writeText) {
      throw new Error("Clipboard API is unavailable in this browser context");
    }
    await navigator.clipboard.writeText(source);
    btn.textContent = "Copied!";
    appendLog("Copied samloader-fus-bridge.user.js to clipboard for manual installation.");
    setTimeout(() => {
      btn.textContent = originalLabel;
      btn.disabled = false;
    }, 2000);
  } catch (err) {
    btn.textContent = originalLabel;
    btn.disabled = false;
    reportError(`Failed to copy userscript: ${err?.message || err}`);
  }
}

// --- DVIF Auto-Fill & Bootloader Matching ---
function doesVersionMatchBootloader(versionStr, bootloaderVer) {
  if (!versionStr || !bootloaderVer) return false;
  const target = bootloaderVer.trim().toUpperCase();
  if (!target) return false;
  const parts = versionStr.split("/").map((p) => p.trim().toUpperCase());
  return parts[0] === target || parts[3] === target;
}

function updateDeviceBootloaderPill() {
  const pill = document.getElementById("server-device-bl-pill");
  if (!pill) return;
  const bl =
    state.capabilities.canFlash && state.device?.mode === "download"
      ? state.deviceBootloaderVersion
      : null;
  if (bl) {
    pill.textContent = `Device bootloader: ${bl}`;
    pill.hidden = false;
  } else {
    pill.textContent = "";
    pill.hidden = true;
  }
}

function syncLookupInputsChange() {
  const model = getLookupModel();
  const region = getLookupRegion();

  if (
    state.serverHistory &&
    (state.serverHistory.model !== model || state.serverHistory.region !== region)
  ) {
    state.serverHistory = null;
    const versionSection = document.getElementById("server-version-section");
    const versionSelect = document.getElementById("server-version-select");
    if (versionSelect?.value === "__custom__") {
      renderVersionDropdown("__custom__");
    } else {
      if (versionSection) versionSection.hidden = true;
      if (versionSelect) versionSelect.replaceChildren();
    }
  }

  if (
    state.serverInspect &&
    (state.serverInspect.model !== model || state.serverInspect.region !== region)
  ) {
    clearInspectedArchive();
  }
}

function applyDeviceFields({ overwrite = false } = {}) {
  const fields = [
    { id: "server-model", storageKey: STORAGE_MODEL, value: state.deviceModel, label: "Model" },
    { id: "server-region", storageKey: STORAGE_REGION, value: state.deviceSalesCode, label: "Region" },
  ];
  const filled = [];
  for (const { id, storageKey, value, label } of fields) {
    const input = document.getElementById(id);
    const normalized = value?.trim().toUpperCase();
    if (input && normalized && (overwrite || !input.value.trim())) {
      input.value = normalized;
      writeStorage(storageKey, normalized);
      filled.push(`${label}=${normalized}`);
    }
  }
  syncLookupInputsChange();
  return filled;
}

function refreshDeviceVersionState() {
  updateDeviceBootloaderPill();
  if (state.serverHistory) {
    renderVersionDropdown();
  }
  updateControlsState();
}

function handleDeviceUpdated({ dvifQueried }) {
  if (dvifQueried) {
    applyDeviceFields({ overwrite: false });
  }
  refreshDeviceVersionState();
}

async function handleDetectFromDevice() {
  if (state.isBusy || state.serverQuerying || state.device?.mode !== "download") return;
  setLookupError("");

  if (!hasDeviceInfo()) {
    await queryAndShowDeviceInfo();
  }

  const filled = applyDeviceFields({ overwrite: true });
  if (filled.length > 0) {
    appendLog(`Detected from device: ${filled.join(", ")}`);
  } else {
    appendLog("Connected device did not report Model or Sales Code via DVIF.");
  }

  refreshDeviceVersionState();
}

// --- Version Lookup & Inspection ---
function appendVersionOption(parent, version) {
  const opt = document.createElement("option");
  opt.value = version;
  const isInstalled = doesVersionMatchBootloader(version, state.deviceBootloaderVersion);
  opt.textContent = isInstalled ? `${version} [Installed on device]` : version;
  parent.appendChild(opt);
}

function renderVersionDropdown(preferredValue) {
  const select = document.getElementById("server-version-select");
  if (!select) return;

  const previousValue = preferredValue ?? select.value;
  select.replaceChildren();

  const history = state.serverHistory;
  if (history) {
    if (history.latest) {
      const latestGroup = document.createElement("optgroup");
      latestGroup.label = "Latest";
      appendVersionOption(latestGroup, history.latest);
      select.appendChild(latestGroup);
    }

    if (Array.isArray(history.previous) && history.previous.length > 0) {
      const prevGroup = document.createElement("optgroup");
      prevGroup.label = "Previous Stable";
      history.previous.forEach((ver) => appendVersionOption(prevGroup, ver));
      select.appendChild(prevGroup);
    }

    if (Array.isArray(history.beta) && history.beta.length > 0) {
      const betaGroup = document.createElement("optgroup");
      betaGroup.label = "Beta";
      history.beta.forEach((ver) => appendVersionOption(betaGroup, ver));
      select.appendChild(betaGroup);
    }
  }

  const customOpt = document.createElement("option");
  customOpt.value = "__custom__";
  customOpt.textContent = "Custom version…";
  select.appendChild(customOpt);

  if (
    previousValue &&
    Array.from(select.options).some((opt) => opt.value === previousValue)
  ) {
    select.value = previousValue;
  } else if (history?.latest) {
    select.value = history.latest;
  } else {
    select.value = "__custom__";
  }

  const customRow = document.getElementById("server-custom-version-row");
  if (customRow) {
    customRow.hidden = select.value !== "__custom__";
  }
}

function clearInspectedArchive() {
  inspectGen++;
  state.serverInspect = null;
  archiveRows = [];
  const loadingEl = document.getElementById("server-inspect-loading");
  const archiveEl = document.getElementById("server-archive-section");
  const listEl = document.getElementById("server-entries-list");
  if (loadingEl) loadingEl.hidden = true;
  if (archiveEl) archiveEl.hidden = true;
  if (listEl) listEl.replaceChildren();
  syncArchiveSelectionState();
}

async function handleCheckVersions(e) {
  e.preventDefault();
  if (state.isBusy || state.serverQuerying) return;
  if (!state.fusBridge.connected) return;

  const model = getLookupModel();
  const region = getLookupRegion();
  if (!model || !region) return;

  writeStorage(STORAGE_MODEL, model);
  writeStorage(STORAGE_REGION, region);
  setLookupError("");
  state.serverHistory = null;
  const versionSectionEl = document.getElementById("server-version-section");
  if (versionSectionEl) versionSectionEl.hidden = true;
  clearInspectedArchive();

  const checkBtn = document.getElementById("btn-check-versions");
  if (checkBtn) checkBtn.textContent = "Checking…";

  state.serverQuerying = true;
  updateControlsState();
  appendLog(`Checking Samsung FUS firmware versions for ${model} (${region})...`);

  try {
    const transport = await getMainThreadFusTransport();
    const history = await fusFetchHistory(model, region, transport);
    state.serverHistory = { ...history, model, region };

    if (versionSectionEl) versionSectionEl.hidden = false;
    updateDeviceBootloaderPill();
    renderVersionDropdown(history.latest);

    const count =
      (history.latest ? 1 : 0) +
      (history.previous?.length ?? 0) +
      (history.beta?.length ?? 0);
    appendLog(`Found ${count} firmware version(s); latest is ${history.latest}.`);

    if (checkBtn) checkBtn.textContent = "Check Versions";
    state.serverQuerying = false;
    updateControlsState();

    if (history.latest) {
      await inspectFirmwareVersion(model, region, history.latest);
    }
  } catch (err) {
    const msg = err?.message || String(err);
    setLookupError(`Version lookup failed: ${msg}`);
    reportError(`FUS version lookup failed: ${msg}`);
    if (checkBtn) checkBtn.textContent = "Check Versions";
    state.serverQuerying = false;
    updateControlsState();
  }
}

async function inspectFirmwareVersion(model, region, version) {
  if (state.isBusy) return;
  if (!model || !region || !version) return;
  if (!state.fusBridge.connected) return;

  const myGen = ++inspectGen;
  setLookupError("");
  state.serverInspect = null;
  archiveRows = [];

  const loadingEl = document.getElementById("server-inspect-loading");
  const archiveEl = document.getElementById("server-archive-section");
  if (archiveEl) archiveEl.hidden = true;
  if (loadingEl) loadingEl.hidden = false;

  state.serverQuerying = true;
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
    document.querySelectorAll('input[name="server-output-mode"]').forEach((el) => {
      el.checked = el.value === "entries";
    });

    buildArchiveRows(info.entries || []);
    renderArchiveSection();
    appendLog(
      `Inspected ${info.decryptedFilename} (${formatBytes(info.decryptedSize)}, ${(info.entries || []).length} entries).`
    );
  } catch (err) {
    if (myGen !== inspectGen) return;
    const msg = err?.message || String(err);
    setLookupError(`Inspect failed: ${msg}`);
    reportError(`FUS inspect failed: ${msg}`);
  } finally {
    if (myGen === inspectGen) {
      if (loadingEl) loadingEl.hidden = true;
      state.serverQuerying = false;
      syncArchiveSelectionState();
    }
  }
}

// --- Archive Component Selector ---
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

function getSelectedEntriesInfo() {
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

function syncArchiveSelectionState() {
  const { selectedEntries, odinEntries, totalBytes, hasBothCsc } = getSelectedEntriesInfo();
  const summaryEl = document.getElementById("server-entries-summary");

  if (summaryEl) {
    if (selectedEntries.length === 0) {
      summaryEl.textContent = "No components selected";
    } else {
      const noun = selectedEntries.length === 1 ? "file" : "files";
      summaryEl.textContent = `${selectedEntries.length} ${noun} selected · ${formatBytes(totalBytes)}`;
    }
  }

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

  updateControlsState();
}

function renderArchiveSection() {
  const archiveEl = document.getElementById("server-archive-section");
  const summaryEl = document.getElementById("server-archive-summary");
  const zipNoteEl = document.getElementById("server-zip-note");
  const entriesWrapEl = document.getElementById("server-entries-wrap");

  if (!archiveEl || !state.serverInspect) return;
  const { info } = state.serverInspect;

  if (summaryEl) {
    summaryEl.replaceChildren();
    const mainDiv = document.createElement("div");
    mainDiv.className = "archive-summary-main";

    const fileEl = document.createElement("span");
    fileEl.className = "archive-summary-filename";
    fileEl.textContent = info.decryptedFilename;

    const verEl = document.createElement("span");
    verEl.className = "archive-summary-version";
    verEl.textContent = `Version: ${info.version}`;

    mainDiv.appendChild(fileEl);
    mainDiv.appendChild(verEl);

    const sizeEl = document.createElement("span");
    sizeEl.className = "archive-summary-size";
    sizeEl.textContent = formatBytes(info.decryptedSize || 0);

    summaryEl.appendChild(mainDiv);
    summaryEl.appendChild(sizeEl);
  }

  const isZipMode = state.serverOutputMode === "zip";
  if (zipNoteEl) {
    zipNoteEl.hidden = !isZipMode;
    if (isZipMode) {
      const flashNote = state.capabilities.canFlash
        ? " Full .zip archives cannot be flashed directly."
        : "";
      zipNoteEl.textContent = `Downloads the full decrypted firmware archive (${info.decryptedFilename}, ${formatBytes(info.decryptedSize || 0)}) without extracting components.${flashNote}`;
    }
  }
  if (entriesWrapEl) {
    entriesWrapEl.hidden = isZipMode;
  }

  renderEntryRows();
  archiveEl.hidden = false;
  syncArchiveSelectionState();
}

function getRowDisplay(row) {
  if (row.kind === "smart_csc") {
    const activeEntries =
      row.cscChoice === "home_csc"
        ? [row.homeEntry]
        : row.cscChoice === "csc"
          ? [row.wipeEntry]
          : [row.homeEntry, row.wipeEntry];
    const activeNames = activeEntries.map((e) => e.name).join(" + ");
    return {
      badge: "CSC",
      name: activeNames,
      sub:
        row.cscChoice === "home_csc"
          ? "Keep user data (HOME_CSC)"
          : row.cscChoice === "csc"
            ? "Wipes user data (CSC)"
            : state.capabilities.canFlash
              ? "Both CSC packages (download only)"
              : "Both CSC packages",
      size: activeEntries.reduce((s, e) => s + (e.uncompressedSize || 0), 0),
      ariaLabel: `Include CSC (${activeNames})`,
      unrecognized: false,
    };
  }

  const { entry } = row;
  const meta = entry.component ? COMPONENT_META[entry.component] : null;
  return {
    badge: meta ? meta.badge : "FILE",
    name: entry.name,
    sub: meta
      ? meta.label
      : state.capabilities.canFlash
        ? "Extra archive file (download only)"
        : "Extra archive file",
    size: entry.uncompressedSize || 0,
    ariaLabel: `Include ${entry.name}`,
    unrecognized: !meta,
  };
}

function renderEntryRows() {
  const listEl = document.getElementById("server-entries-list");
  if (!listEl) return;
  listEl.replaceChildren();

  archiveRows.forEach((row, idx) => {
    const item = document.createElement("div");
    item.setAttribute("role", "listitem");

    const main = document.createElement("div");
    main.className = "server-entry-main";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.id = `server-entry-${idx}`;
    checkbox.className = "server-entry-check";

    const badge = document.createElement("span");
    badge.className = "slot-badge";

    const infoLabel = document.createElement("label");
    infoLabel.className = "server-entry-info";
    infoLabel.setAttribute("for", checkbox.id);

    const nameEl = document.createElement("span");
    nameEl.className = "server-entry-name";

    const subEl = document.createElement("span");
    subEl.className = "server-entry-sub";

    infoLabel.appendChild(nameEl);
    infoLabel.appendChild(subEl);
    main.appendChild(checkbox);
    main.appendChild(badge);
    main.appendChild(infoLabel);

    const right = document.createElement("div");
    right.className = "server-entry-right";

    const sizeEl = document.createElement("span");
    sizeEl.className = "file-size";

    const applyRowDisplay = () => {
      const display = getRowDisplay(row);
      item.className = `server-entry-row${row.checked ? " entry-selected" : ""}${display.unrecognized ? " entry-unrecognized" : ""}`;
      checkbox.checked = row.checked;
      checkbox.setAttribute("aria-label", display.ariaLabel);
      badge.textContent = display.badge;
      nameEl.textContent = display.name;
      nameEl.title = display.name;
      subEl.textContent = display.sub;
      sizeEl.textContent = formatBytes(display.size);
    };

    applyRowDisplay();

    checkbox.addEventListener("change", () => {
      row.checked = checkbox.checked;
      item.classList.toggle("entry-selected", row.checked);
      syncArchiveSelectionState();
    });

    if (row.kind === "smart_csc") {
      const cscGroup = document.createElement("div");
      cscGroup.className = "source-segmented-group source-segmented-xs";
      cscGroup.setAttribute("role", "radiogroup");
      cscGroup.setAttribute("aria-label", "CSC option");

      for (const opt of SMART_CSC_CHOICES) {
        const optLabel = document.createElement("label");
        optLabel.className = "source-segmented-option";
        const radio = document.createElement("input");
        radio.type = "radio";
        radio.name = "server-csc-mode";
        radio.value = opt.value;
        radio.checked = row.cscChoice === opt.value;
        radio.addEventListener("change", () => {
          row.cscChoice = opt.value;
          row.checked = true;
          applyRowDisplay();
          syncArchiveSelectionState();
        });
        const span = document.createElement("span");
        span.textContent = opt.label;
        optLabel.appendChild(radio);
        optLabel.appendChild(span);
        cscGroup.appendChild(optLabel);
      }

      right.appendChild(cscGroup);
    }

    right.appendChild(sizeEl);
    item.appendChild(main);
    item.appendChild(right);
    listEl.appendChild(item);
  });
}

// --- Initialization ---
export function setupServerPanel() {
  const { canFlash, canDownload } = state.capabilities;
  if (!canDownload) {
    state.firmwareSource = "local";
    updateControlsState();
    return;
  }

  // Restore persisted UI preferences
  if (canFlash) {
    const savedSource = readStorage(STORAGE_SOURCE);
    state.firmwareSource = savedSource === "local" ? "local" : "server";
  } else {
    state.firmwareSource = "server";
  }

  const modelInput = document.getElementById("server-model");
  const regionInput = document.getElementById("server-region");
  const concurrencySelect = document.getElementById("server-concurrency");

  const savedModel = readStorage(STORAGE_MODEL);
  if (modelInput && savedModel) {
    modelInput.value = savedModel.toUpperCase();
  }
  const savedRegion = readStorage(STORAGE_REGION);
  if (regionInput && savedRegion) {
    regionInput.value = savedRegion.toUpperCase();
  }
  const savedConcurrency = Number(readStorage(STORAGE_CONCURRENCY));
  if (savedConcurrency >= 1 && savedConcurrency <= 8) {
    state.serverConcurrency = savedConcurrency;
  }
  if (concurrencySelect) {
    concurrencySelect.value = String(state.serverConcurrency);
  }

  // Source switcher
  document.querySelectorAll('input[name="firmware-source"]').forEach((radio) => {
    radio.addEventListener("change", () => {
      if (radio.checked) {
        setFirmwareSource(radio.value, true);
      }
    });
  });

  // Userscript bridge reload, recheck, manual copy & OPFS cache actions
  document.getElementById("btn-reload-bridge")?.addEventListener("click", () => {
    window.location.reload();
  });
  document.getElementById("btn-recheck-bridge")?.addEventListener("click", () => {
    checkFusBridge();
  });
  document.querySelectorAll(".btn-copy-userscript").forEach((btn) => {
    btn.addEventListener("click", () => handleCopyUserscript(btn));
  });
  document.getElementById("btn-save-opfs-cache")?.addEventListener("click", handleSaveOpfsFiles);
  document.getElementById("btn-clear-opfs-cache")?.addEventListener("click", handleClearOpfsCache);

  // Lookup form inputs
  modelInput?.addEventListener("input", () => {
    normalizeUpperInput(modelInput);
    setLookupError("");
    syncLookupInputsChange();
    updateControlsState();
  });
  regionInput?.addEventListener("input", () => {
    normalizeUpperInput(regionInput);
    setLookupError("");
    syncLookupInputsChange();
    updateControlsState();
  });

  document
    .getElementById("btn-detect-server-device")
    ?.addEventListener("click", handleDetectFromDevice);

  document
    .getElementById("server-lookup-form")
    ?.addEventListener("submit", handleCheckVersions);

  // Manual custom version toggle
  document
    .getElementById("btn-toggle-custom-version")
    ?.addEventListener("click", () => {
      if (state.isBusy || state.serverQuerying) return;
      const versionSection = document.getElementById("server-version-section");
      if (versionSection) versionSection.hidden = false;
      updateDeviceBootloaderPill();
      renderVersionDropdown("__custom__");
      clearInspectedArchive();
      document.getElementById("server-custom-version")?.focus();
      updateControlsState();
    });

  // Version dropdown & custom version input
  const versionSelect = document.getElementById("server-version-select");
  const customVerInput = document.getElementById("server-custom-version");

  versionSelect?.addEventListener("change", async () => {
    const val = versionSelect.value;
    const customRow = document.getElementById("server-custom-version-row");
    if (val === "__custom__") {
      if (customRow) customRow.hidden = false;
      clearInspectedArchive();
      customVerInput?.focus();
      updateControlsState();
      return;
    }
    if (customRow) customRow.hidden = true;
    await inspectFirmwareVersion(getLookupModel(), getLookupRegion(), val);
  });

  customVerInput?.addEventListener("input", () => {
    normalizeUpperInput(customVerInput);
    updateControlsState();
  });
  customVerInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      document.getElementById("btn-inspect-custom")?.click();
    }
  });

  document
    .getElementById("btn-inspect-custom")
    ?.addEventListener("click", async () => {
      const customVer = normalizeUpperInput(customVerInput);
      if (!customVer) return;
      await inspectFirmwareVersion(getLookupModel(), getLookupRegion(), customVer);
    });

  // Output format & parallel connections
  document.querySelectorAll('input[name="server-output-mode"]').forEach((radio) => {
    radio.addEventListener("change", () => {
      if (!radio.checked) return;
      state.serverOutputMode = radio.value === "zip" ? "zip" : "entries";
      renderArchiveSection();
    });
  });

  concurrencySelect?.addEventListener("change", () => {
    const val = Number(concurrencySelect.value);
    if (val >= 1 && val <= 8) {
      state.serverConcurrency = val;
      writeStorage(STORAGE_CONCURRENCY, val);
    }
  });

  // Action bar buttons
  document
    .getElementById("btn-download-only")
    ?.addEventListener("click", () => handleDownloadOnly(getSelectedEntriesInfo()));
  document
    .getElementById("btn-download-flash")
    ?.addEventListener("click", () => handleDownloadAndFlash(getSelectedEntriesInfo()));
  document
    .getElementById("btn-load-into-local")
    ?.addEventListener("click", () => handleLoadIntoLocalFlash(() => setFirmwareSource("local", true)));

  // Sync with connected device DVIF & status updates
  setDeviceUpdateListener(handleDeviceUpdated);
  setupBridgeAnnouncementListener();
  window.addEventListener("pagehide", revokeDownloadUrls);

  updateControlsState();
  checkFusBridge({ quiet: true });
  refreshOpfsCacheBanner();
}
