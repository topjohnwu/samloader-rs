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

import { hasDeviceInfo, queryDeviceInfo } from "../app/device.js";
import { EXPECTED_BRIDGE_VERSION, hasInstalledBridge } from "../app/fus_bridge.js";
import { appendLog } from "../app/logger.js";
import {
  checkFirmwareVersions,
  checkFusBridge,
  clearInspectedArchive,
  clearServerHistory,
  doesVersionMatchBootloader,
  initBridgeAnnouncementListener,
  inspectFirmwareVersion,
  setArchiveRowChecked,
  setServerOutputMode,
  setSmartCscChoice,
} from "../app/server.js";
import {
  COMPONENT_META,
  getDerivedState,
  notifyStateChange,
  state,
  subscribe,
} from "../app/state.js";
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

function setFirmwareSource(source, persist = true) {
  const { canFlash, canDownload } = state.capabilities;
  const canDownloadNow = canDownload && state.isOnline;
  let normalized = source === "local" ? "local" : "server";
  if (!canDownloadNow && canFlash) normalized = "local";
  else if (!canFlash && canDownloadNow) normalized = "server";
  state.firmwareSource = normalized;
  if (persist && canFlash && canDownloadNow) {
    writeStorage(STORAGE_SOURCE, normalized);
  }
  notifyStateChange();
}

// --- FUS Bridge Status Banner ---
function getBridgeBannerSpec() {
  const { connected, version, outdated } = state.fusBridge;
  const { extensionSupport, isEdgeAndroid } = state.capabilities;
  const tampermonkeyHtml = isEdgeAndroid
    ? 'Install <a href="https://www.tampermonkey.net/" target="_blank" rel="noopener noreferrer">Tampermonkey</a> from Edge\'s <strong>Extensions</strong> menu.'
    : 'Install the <a href="https://www.tampermonkey.net/" target="_blank" rel="noopener noreferrer">Tampermonkey</a> extension.';

  if (connected && outdated) {
    const installedLabel = version ? `v${version}` : "unknown version";
    return {
      folded: false,
      title: "Helper Script Update Available",
      desc: `Your installed helper script (${installedLabel}) is outdated. Update to v${EXPECTED_BRIDGE_VERSION} for the latest fixes and compatibility.`,
      showTampermonkey: false,
      tampermonkeyHtml,
      installLabel: "Update the helper script:",
      installText: "Update Script",
      reloadHtml: "Click <strong>Reload Page</strong> to use the updated script.",
    };
  }

  if (extensionSupport === "supported") {
    return {
      folded: false,
      title: "Helper Script Required",
      desc: "Web browsers block direct downloads from Samsung's firmware servers. Install a small helper script with Tampermonkey so this page can download firmware directly to your device.",
      showTampermonkey: true,
      tampermonkeyHtml,
      installLabel: "Install the helper script:",
      installText: "Install Script",
      reloadHtml: "Click <strong>Reload Page</strong> to finish setup.",
    };
  }

  return {
    folded: true,
    title: "Downloads Not Supported in This Browser",
    desc:
      extensionSupport === "unlikely"
        ? "Downloading firmware directly from Samsung requires the Tampermonkey browser extension, which isn't supported in Chrome on Android. To download firmware, open this page on a computer (Chrome, Edge, Brave, or Opera) or in Microsoft Edge on Android."
        : "Downloading firmware directly from Samsung requires the Tampermonkey browser extension. If your browser doesn't support extensions, open this page on a computer (Chrome, Edge, Brave, or Opera) or in Microsoft Edge on Android.",
    showTampermonkey: true,
    tampermonkeyHtml,
    installLabel: "Install the helper script:",
    installText: "Install Script",
    reloadHtml: "Click <strong>Reload Page</strong> to finish setup.",
  };
}

function renderBridgeBanner() {
  const setupEl = document.getElementById("fus-bridge-setup");
  const connectedEl = document.getElementById("fus-bridge-connected");
  const badgeTextEl = document.getElementById("fus-bridge-badge-text");
  const titleEl = document.getElementById("fus-bridge-banner-title");
  const descEl = document.getElementById("fus-bridge-banner-desc");
  const manualToggle = document.getElementById("btn-bridge-manual-toggle");
  const stepsPanel = document.getElementById("bridge-steps-panel");
  const tampermonkeyStep = document.getElementById("bridge-step-tampermonkey");
  const installStepLabel = document.getElementById("bridge-install-step-label");
  const installLink = document.getElementById("link-install-userscript");
  const reloadStep = document.getElementById("bridge-reload-step");

  const { connected, version, outdated } = state.fusBridge;
  if (connected && !outdated) {
    if (setupEl) setupEl.hidden = true;
    if (connectedEl) connectedEl.hidden = false;
    if (badgeTextEl) {
      badgeTextEl.textContent = `Helper Script v${version ?? EXPECTED_BRIDGE_VERSION}`;
    }
    return;
  }

  if (connectedEl) connectedEl.hidden = true;
  if (!setupEl) return;
  setupEl.hidden = false;

  const spec = getBridgeBannerSpec();
  setupEl.dataset.folded = String(spec.folded);
  const manualOpen = spec.folded && setupEl.dataset.manualOpen === "true";
  if (!spec.folded) {
    delete setupEl.dataset.manualOpen;
  }

  if (manualToggle) {
    manualToggle.hidden = !spec.folded;
    manualToggle.setAttribute("aria-expanded", String(manualOpen));
  }
  if (stepsPanel) {
    stepsPanel.hidden = spec.folded && !manualOpen;
  }
  if (titleEl) titleEl.textContent = spec.title;
  if (descEl) descEl.textContent = spec.desc;
  if (tampermonkeyStep) {
    tampermonkeyStep.hidden = !spec.showTampermonkey;
    if (spec.showTampermonkey) {
      tampermonkeyStep.innerHTML = spec.tampermonkeyHtml;
    }
  }
  if (installStepLabel) installStepLabel.textContent = spec.installLabel;
  if (installLink) installLink.textContent = spec.installText;
  if (reloadStep) reloadStep.innerHTML = spec.reloadHtml;
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
  state.serverModel = model;
  state.serverRegion = region;

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
  notifyStateChange();
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

async function handleDetectFromDevice() {
  if (state.isBusy || state.serverQuerying || state.device?.mode !== "download") return;
  state.serverLookupError = "";

  if (!hasDeviceInfo()) {
    await queryDeviceInfo();
  }

  const filled = applyDeviceFields({ overwrite: true });
  if (filled.length > 0) {
    appendLog(`Detected from device: ${filled.join(", ")}`);
  } else {
    appendLog("Connected device did not report Model or Sales Code via DVIF.");
  }
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
          ? "Keep Data (HOME_CSC)"
          : row.cscChoice === "csc"
            ? "Wipe Data (CSC)"
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

  state.archiveRows.forEach((row, idx) => {
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

function renderArchiveSection(inspectChanged = true) {
  const archiveEl = document.getElementById("server-archive-section");
  const summaryEl = document.getElementById("server-archive-summary");
  const zipNoteEl = document.getElementById("server-zip-note");
  const entriesWrapEl = document.getElementById("server-entries-wrap");

  if (!archiveEl || !state.serverInspect) return;
  const { info } = state.serverInspect;

  if (inspectChanged && summaryEl) {
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

  if (inspectChanged) {
    renderEntryRows();
  }
  archiveEl.hidden = false;
}

// --- Initialization ---
export function setupServerPanel() {
  const { canFlash, canDownload } = state.capabilities;
  if (!canDownload) {
    state.firmwareSource = "local";
    return;
  }

  initBridgeAnnouncementListener();
  setupDownloadUi();

  // Restore persisted UI preferences
  if (canFlash) {
    const savedSource = readStorage(STORAGE_SOURCE);
    const preferServerByDefault =
      hasInstalledBridge() || state.capabilities.extensionSupport === "supported";
    state.firmwareSource =
      !state.isOnline || !preferServerByDefault || savedSource === "local" ? "local" : "server";
  } else {
    state.firmwareSource = "server";
  }

  const serverPanel = document.getElementById("server-panel");
  const modelInput = document.getElementById("server-model");
  const regionInput = document.getElementById("server-region");
  const concurrencySelect = document.getElementById("server-concurrency");
  const versionSection = document.getElementById("server-version-section");
  const versionSelect = document.getElementById("server-version-select");
  const customVerInput = document.getElementById("server-custom-version");
  const customRow = document.getElementById("server-custom-version-row");
  const inspectLoading = document.getElementById("server-inspect-loading");
  const archiveSection = document.getElementById("server-archive-section");
  const entriesList = document.getElementById("server-entries-list");
  const lookupErrorEl = document.getElementById("server-lookup-error");
  const detectServerBtn = document.getElementById("btn-detect-server-device");
  const checkVersionsBtn = document.getElementById("btn-check-versions");
  const toggleCustomBtn = document.getElementById("btn-toggle-custom-version");
  const inspectCustomBtn = document.getElementById("btn-inspect-custom");
  const reloadBridgeBtn = document.getElementById("btn-reload-bridge");
  const outputModeRadios = Array.from(
    document.querySelectorAll('input[name="server-output-mode"]')
  );

  const savedModel = readStorage(STORAGE_MODEL);
  if (modelInput && savedModel) {
    modelInput.value = savedModel.toUpperCase();
  }
  const savedRegion = readStorage(STORAGE_REGION);
  if (regionInput && savedRegion) {
    regionInput.value = savedRegion.toUpperCase();
  }
  state.serverModel = getLookupModel();
  state.serverRegion = getLookupRegion();

  const savedConcurrency = Number(readStorage(STORAGE_CONCURRENCY));
  if (savedConcurrency >= 1 && savedConcurrency <= 6) {
    state.serverConcurrency = savedConcurrency;
  }
  if (concurrencySelect) {
    concurrencySelect.value = String(state.serverConcurrency);
  }

  let lastBridge = null;
  let lastCaps = null;
  let lastHistory = undefined;
  let lastInspect = undefined;
  let lastOutputMode = null;
  let lastCustomOpen = null;
  let lastBootloaderVer = undefined;
  let lastDvifSeq = state.dvifQuerySeq;

  const render = (s, d) => {
    if (serverPanel) serverPanel.hidden = !d.isServer;

    if (s.dvifQuerySeq !== lastDvifSeq) {
      lastDvifSeq = s.dvifQuerySeq;
      applyDeviceFields({ overwrite: false });
    }

    if (s.fusBridge !== lastBridge || s.capabilities !== lastCaps) {
      const lateBridgeConnect =
        lastBridge?.checked && !lastBridge?.connected && s.fusBridge.connected;
      lastBridge = s.fusBridge;
      lastCaps = s.capabilities;
      renderBridgeBanner();
      if (
        lateBridgeConnect &&
        s.isOnline &&
        !s.userChoseSource &&
        s.capabilities.canFlash &&
        s.capabilities.extensionSupport !== "supported" &&
        readStorage(STORAGE_SOURCE) !== "local"
      ) {
        s.firmwareSource = "server";
        notifyStateChange();
      }
    }

    if (lookupErrorEl) {
      lookupErrorEl.textContent = s.serverLookupError || "";
      lookupErrorEl.hidden = !s.serverLookupError;
    }

    if (checkVersionsBtn) {
      checkVersionsBtn.textContent =
        s.serverQueryPhase === "history" ? "Checking…" : "Check Versions";
      checkVersionsBtn.disabled =
        !d.bridgeReady || !s.serverModel || !s.serverRegion || d.serverBusy;
    }

    if (
      s.serverHistory !== lastHistory ||
      s.deviceBootloaderVersion !== lastBootloaderVer ||
      s.serverCustomVersionOpen !== lastCustomOpen
    ) {
      const historyChanged = s.serverHistory !== lastHistory;
      lastHistory = s.serverHistory;
      lastBootloaderVer = s.deviceBootloaderVersion;
      lastCustomOpen = s.serverCustomVersionOpen;

      if (s.serverHistory) {
        if (versionSection) versionSection.hidden = false;
        const preferred = s.serverCustomVersionOpen
          ? "__custom__"
          : historyChanged
            ? s.serverHistory.latest
            : undefined;
        renderVersionDropdown(preferred);
      } else if (s.serverCustomVersionOpen) {
        if (versionSection) versionSection.hidden = false;
        renderVersionDropdown("__custom__");
      } else {
        if (versionSection) versionSection.hidden = true;
        if (versionSelect) versionSelect.replaceChildren();
      }
    }

    if (customRow && versionSelect) {
      customRow.hidden = versionSelect.value !== "__custom__" && !s.serverCustomVersionOpen;
    }

    updateDeviceBootloaderPill();

    if (inspectLoading) {
      inspectLoading.hidden = s.serverQueryPhase !== "inspect";
    }

    if (s.serverInspect !== lastInspect || s.serverOutputMode !== lastOutputMode) {
      const inspectChanged = s.serverInspect !== lastInspect;
      lastInspect = s.serverInspect;
      lastOutputMode = s.serverOutputMode;
      if (s.serverInspect) {
        for (const el of outputModeRadios) {
          el.checked = el.value === s.serverOutputMode;
        }
        renderArchiveSection(inspectChanged);
      } else {
        if (archiveSection) archiveSection.hidden = true;
        if (entriesList) entriesList.replaceChildren();
      }
    }

    if (s.serverInspect) {
      updateSelectionSummary(d.selectedEntriesInfo);
    }

    if (detectServerBtn) {
      detectServerBtn.hidden = !s.capabilities.canFlash || !d.hasDownloadDevice;
      detectServerBtn.disabled = d.serverBusy || !d.hasDownloadDevice;
    }
    if (toggleCustomBtn) {
      toggleCustomBtn.disabled = !d.bridgeReady || d.serverBusy;
    }
    if (inspectCustomBtn) {
      inspectCustomBtn.disabled =
        !d.bridgeReady ||
        !s.serverModel ||
        !s.serverRegion ||
        !s.serverCustomVersion ||
        d.serverBusy;
    }
    if (modelInput) modelInput.disabled = d.serverBusy;
    if (regionInput) regionInput.disabled = d.serverBusy;
    if (reloadBridgeBtn) reloadBridgeBtn.disabled = d.serverBusy;
    if (versionSelect) versionSelect.disabled = !d.bridgeReady || d.serverBusy;
    if (customVerInput) customVerInput.disabled = !d.bridgeReady || d.serverBusy;
    if (concurrencySelect) concurrencySelect.disabled = !d.bridgeReady || d.serverBusy;

    document
      .querySelectorAll(
        'input[name="server-output-mode"], .server-entry-check, input[name="server-csc-mode"]'
      )
      .forEach((el) => {
        el.disabled = d.serverBusy;
      });
  };

  // Source switcher
  document.querySelectorAll('input[name="firmware-source"]').forEach((radio) => {
    radio.addEventListener("change", () => {
      if (radio.checked) {
        state.userChoseSource = true;
        setFirmwareSource(radio.value, true);
      }
    });
  });

  // Userscript bridge manual toggle, reload & OPFS cache actions
  document.getElementById("btn-bridge-manual-toggle")?.addEventListener("click", () => {
    const setupEl = document.getElementById("fus-bridge-setup");
    const manualToggle = document.getElementById("btn-bridge-manual-toggle");
    const stepsPanel = document.getElementById("bridge-steps-panel");
    if (!setupEl || !manualToggle || !stepsPanel) return;
    const nextOpen = setupEl.dataset.manualOpen !== "true";
    setupEl.dataset.manualOpen = String(nextOpen);
    manualToggle.setAttribute("aria-expanded", String(nextOpen));
    stepsPanel.hidden = !nextOpen;
  });
  reloadBridgeBtn?.addEventListener("click", () => {
    window.location.reload();
  });
  document.getElementById("btn-clear-opfs-cache")?.addEventListener("click", handleClearOpfsCache);

  // Lookup form inputs
  modelInput?.addEventListener("input", () => {
    normalizeUpperInput(modelInput);
    state.serverLookupError = "";
    syncLookupInputsChange();
  });
  regionInput?.addEventListener("input", () => {
    normalizeUpperInput(regionInput);
    state.serverLookupError = "";
    syncLookupInputsChange();
  });

  detectServerBtn?.addEventListener("click", handleDetectFromDevice);

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
  toggleCustomBtn?.addEventListener("click", () => {
    if (state.isBusy || state.serverQuerying) return;
    state.serverCustomVersionOpen = true;
    clearInspectedArchive();
    notifyStateChange();
    queueMicrotask(() => customVerInput?.focus());
  });

  // Version dropdown & custom version input
  versionSelect?.addEventListener("change", async () => {
    const val = versionSelect.value;
    if (val === "__custom__") {
      state.serverCustomVersionOpen = true;
      clearInspectedArchive();
      notifyStateChange();
      queueMicrotask(() => customVerInput?.focus());
      return;
    }
    state.serverCustomVersionOpen = false;
    notifyStateChange();
    await inspectFirmwareVersion(getLookupModel(), getLookupRegion(), val);
  });

  customVerInput?.addEventListener("input", () => {
    state.serverCustomVersion = normalizeUpperInput(customVerInput);
    notifyStateChange();
  });
  customVerInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      inspectCustomBtn?.click();
    }
  });

  inspectCustomBtn?.addEventListener("click", async () => {
    const model = getLookupModel();
    const region = getLookupRegion();
    const customVer = normalizeUpperInput(customVerInput);
    state.serverCustomVersion = customVer;
    if (!model || !region || !customVer) return;
    writeStorage(STORAGE_MODEL, model);
    writeStorage(STORAGE_REGION, region);
    await inspectFirmwareVersion(model, region, customVer);
  });

  // Output format & parallel connections
  outputModeRadios.forEach((radio) => {
    radio.addEventListener("change", () => {
      if (!radio.checked) return;
      setServerOutputMode(radio.value);
    });
  });

  concurrencySelect?.addEventListener("change", () => {
    const val = Number(concurrencySelect.value);
    if (val >= 1 && val <= 6) {
      state.serverConcurrency = val;
      writeStorage(STORAGE_CONCURRENCY, val);
    }
  });

  // Action bar buttons
  document
    .getElementById("btn-download-only")
    ?.addEventListener("click", () =>
      void handleDownloadOnly(getDerivedState(state).selectedEntriesInfo)
    );
  document
    .getElementById("btn-download-flash")
    ?.addEventListener("click", () =>
      void handleDownloadAndFlash(getDerivedState(state).selectedEntriesInfo)
    );
  document
    .getElementById("btn-load-into-local")
    ?.addEventListener("click", () =>
      void handleLoadIntoLocalFlash(() => {
        state.userChoseSource = true;
        setFirmwareSource("local", true);
      })
    );

  subscribe(render);
  render(state, getDerivedState(state));
  void checkFusBridge();
}
