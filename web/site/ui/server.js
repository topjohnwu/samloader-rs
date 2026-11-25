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

// Samsung Server panel DOM rendering, input normalization, preferences, and event wiring.

import { hasDeviceInfo, onDeviceChange, queryDeviceInfo } from "../app/device.js";
import { COMPONENT_META } from "../app/download.js";
import { EXPECTED_BRIDGE_VERSION } from "../app/fus_bridge.js";
import { appendLog } from "../app/logger.js";
import {
  checkFirmwareVersions,
  checkFusBridge,
  clearInspectedArchive,
  clearServerHistory,
  doesVersionMatchBootloader,
  getArchiveRows,
  getSelectedEntriesInfo,
  initBridgeAnnouncementListener,
  inspectFirmwareVersion,
  onServerChange,
  setArchiveRowChecked,
  setServerOutputMode,
  setSmartCscChoice,
} from "../app/server.js";
import { state } from "../app/state.js";
import { updateControlsState } from "./controls.js";
import {
  handleClearOpfsCache,
  handleDownloadAndFlash,
  handleDownloadOnly,
  handleLoadIntoLocalFlash,
  setupDownloadUi,
} from "./download.js";
import { formatBytes } from "./util.js";

const STORAGE_SOURCE = "samloader.firmwareSource";
const STORAGE_MODEL = "samloader.serverModel";
const STORAGE_REGION = "samloader.serverRegion";
const STORAGE_CONCURRENCY = "samloader.serverConcurrency";

const SMART_CSC_CHOICES = [
  { value: "home_csc", label: "Keep Data (HOME_CSC)" },
  { value: "csc", label: "Wipe Data (CSC)" },
  { value: "both", label: "Both" },
];

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

// --- FUS Bridge Status Banner ---
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

  const { connected, version, outdated } = state.fusBridge;
  if (connected && !outdated) {
    if (setupEl) setupEl.hidden = true;
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

// --- DVIF Auto-Fill & Bootloader Pill ---
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
    clearServerHistory();
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
    await queryDeviceInfo();
  }

  const filled = applyDeviceFields({ overwrite: true });
  if (filled.length > 0) {
    appendLog(`Detected from device: ${filled.join(", ")}`);
  } else {
    appendLog("Connected device did not report Model or Sales Code via DVIF.");
  }

  refreshDeviceVersionState();
}

// --- Version Dropdown & Archive Rendering ---
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

function updateSelectionSummary(info) {
  const summaryEl = document.getElementById("server-entries-summary");
  if (!summaryEl || !info) return;
  const { selectedEntries, totalBytes } = info;
  if (selectedEntries.length === 0) {
    summaryEl.textContent = "No components selected";
  } else {
    const noun = selectedEntries.length === 1 ? "file" : "files";
    summaryEl.textContent = `${selectedEntries.length} ${noun} selected · ${formatBytes(totalBytes)}`;
  }
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
  updateSelectionSummary(getSelectedEntriesInfo());
  updateControlsState();
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

  getArchiveRows().forEach((row, idx) => {
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
      setArchiveRowChecked(idx, checkbox.checked);
      item.classList.toggle("entry-selected", checkbox.checked);
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
          setSmartCscChoice(idx, opt.value);
          applyRowDisplay();
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

function handleServerEvent(event) {
  switch (event.type) {
    case "bridge":
      renderBridgeBanner();
      updateControlsState();
      break;
    case "querying_history": {
      const checkBtn = document.getElementById("btn-check-versions");
      if (checkBtn) {
        checkBtn.textContent = event.active ? "Checking…" : "Check Versions";
      }
      if (event.active) {
        const versionSectionEl = document.getElementById("server-version-section");
        if (versionSectionEl) versionSectionEl.hidden = true;
      }
      updateControlsState();
      break;
    }
    case "history": {
      const versionSectionEl = document.getElementById("server-version-section");
      if (versionSectionEl) versionSectionEl.hidden = false;
      updateDeviceBootloaderPill();
      renderVersionDropdown(event.history?.latest);
      break;
    }
    case "history_cleared": {
      const versionSection = document.getElementById("server-version-section");
      const versionSelect = document.getElementById("server-version-select");
      if (versionSelect?.value === "__custom__") {
        renderVersionDropdown("__custom__");
      } else {
        if (versionSection) versionSection.hidden = true;
        if (versionSelect) versionSelect.replaceChildren();
      }
      break;
    }
    case "inspecting": {
      const loadingEl = document.getElementById("server-inspect-loading");
      const archiveEl = document.getElementById("server-archive-section");
      if (event.active && archiveEl) archiveEl.hidden = true;
      if (loadingEl) loadingEl.hidden = !event.active;
      break;
    }
    case "inspect_ready": {
      document.querySelectorAll('input[name="server-output-mode"]').forEach((el) => {
        el.checked = el.value === "entries";
      });
      renderArchiveSection();
      break;
    }
    case "output_mode":
      renderArchiveSection();
      break;
    case "inspect_cleared": {
      const loadingEl = document.getElementById("server-inspect-loading");
      const archiveEl = document.getElementById("server-archive-section");
      const listEl = document.getElementById("server-entries-list");
      if (loadingEl) loadingEl.hidden = true;
      if (archiveEl) archiveEl.hidden = true;
      if (listEl) listEl.replaceChildren();
      break;
    }
    case "selection":
      updateSelectionSummary(event.info);
      updateControlsState();
      break;
    case "lookup_error":
      setLookupError(event.message);
      break;
  }
}

// --- Initialization ---
export function setupServerPanel() {
  const { canFlash, canDownload } = state.capabilities;
  if (!canDownload) {
    state.firmwareSource = "local";
    updateControlsState();
    return;
  }

  onServerChange(handleServerEvent);
  onDeviceChange((event) => {
    if (event.type === "info" || event.type === "status") {
      handleDeviceUpdated({ dvifQueried: Boolean(event.dvifQueried) });
    }
  });
  initBridgeAnnouncementListener();
  setupDownloadUi();

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

  // Userscript bridge reload & OPFS cache actions
  document.getElementById("btn-reload-bridge")?.addEventListener("click", () => {
    window.location.reload();
  });
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
    ?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const model = getLookupModel();
      const region = getLookupRegion();
      if (!model || !region) return;
      writeStorage(STORAGE_MODEL, model);
      writeStorage(STORAGE_REGION, region);
      await checkFirmwareVersions(model, region);
    });

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
      setServerOutputMode(radio.value);
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
    ?.addEventListener("click", () => void handleDownloadOnly(getSelectedEntriesInfo()));
  document
    .getElementById("btn-download-flash")
    ?.addEventListener("click", () => void handleDownloadAndFlash(getSelectedEntriesInfo()));
  document
    .getElementById("btn-load-into-local")
    ?.addEventListener("click", () =>
      void handleLoadIntoLocalFlash(() => setFirmwareSource("local", true))
    );

  updateControlsState();
  void checkFusBridge();
}
