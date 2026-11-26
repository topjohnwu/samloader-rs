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

// Shared application state, reactive subscriptions, and pure derived selectors.

// Odin package slots, in flashing order. Their markup is rendered from #slot-template.
export const PACKAGE_SLOTS = [
  { id: "BL", badge: "BL", label: "Bootloader" },
  { id: "AP", badge: "AP", label: "System / Application" },
  { id: "CP", badge: "CP", label: "Modem / Radio" },
  { id: "CSC", badge: "CSC", label: "CSC / HOME_CSC" },
  { id: "USERDATA", badge: "USER", label: "User Data" },
];

export const SLOTS = [...PACKAGE_SLOTS.map((s) => s.id), "PIT"];

export const COMPONENT_META = {
  bl: { badge: "BL", slot: "BL", label: "Bootloader" },
  ap: { badge: "AP", slot: "AP", label: "System / Application" },
  cp: { badge: "CP", slot: "CP", label: "Modem / Radio" },
  home_csc: { badge: "CSC", slot: "CSC", label: "Keep Data (HOME_CSC)" },
  csc: { badge: "CSC", slot: "CSC", label: "Wipe Data (CSC)" },
  userdata: { badge: "USER", slot: "USERDATA", label: "User Data (wipes data)" },
};

export const state = {
  capabilities: {
    canFlash: true,
    canDownload: true,
    extensionSupport: "supported",
    isEdgeAndroid: false,
  },
  isOnline: true,
  backendOptions: [],
  selectedBackend: null,
  appVersion: null,
  rebootMode: "normal",
  skipMd5: false,
  verbose: false,
  firmwareSource: "server",
  userChoseSource: false,
  device: null,
  deviceInfo: null,
  dvifQuerySeq: 0,
  deviceChipConnected: false,
  deviceChipLabel: "No Device",
  deviceSummaryText: "Pair a Samsung device in Download Mode or Normal Mode",
  slots: Object.fromEntries(SLOTS.map((slot) => [slot, null])),
  md5Results: {},
  deviceModel: null, // Model reported by the last DVIF query of the current device
  deviceSalesCode: null, // Sales code / CSC reported by the last DVIF query
  deviceBootloaderVersion: null, // Bootloader version reported by the last DVIF query
  hasLastPit: false,
  partitions: [],
  partitionsRev: 0,
  nextPartitionId: 1,
  flashOptions: {
    erase: false,
    disableVerity: false,
    disableVerification: false,
    skipSizeCheck: false,
    salesCode: "",
  },
  isBusy: false,
  fusBridge: {
    checked: false,
    connected: false,
    version: null,
    outdated: false,
  },
  serverQuerying: false,
  serverQueryPhase: null, // null | "history" | "inspect"
  serverLookupError: "",
  serverModel: "",
  serverRegion: "",
  serverCustomVersion: "",
  serverCustomVersionOpen: false,
  serverHistory: null,
  serverInspect: null,
  archiveRows: [],
  serverOutputMode: "entries",
  serverConcurrency: 6,
  opfsCache: null,
  lastDownloadedDir: null,
};

export function getSelectedEntriesInfo(archiveRows = state.archiveRows) {
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

/**
 * Computes all derived capability, source, selection, and validation flags without mutating `s`.
 */
export function getDerivedState(s = state) {
  const { canFlash, canDownload } = s.capabilities;
  const canDownloadNow = Boolean(canDownload && s.isOnline);
  const supported = Boolean(canFlash || canDownloadNow);

  let effectiveSource;
  if (!canDownloadNow && canFlash) {
    effectiveSource = "local";
  } else if (!canFlash && canDownloadNow) {
    effectiveSource = "server";
  } else {
    effectiveSource = s.firmwareSource === "local" ? "local" : "server";
  }

  const isServer = Boolean(canDownloadNow && effectiveSource === "server");
  const isLocal = Boolean(canFlash && effectiveSource === "local");
  const hasDownloadDevice = Boolean(canFlash && s.device?.mode === "download");
  const hasNormalDevice = Boolean(canFlash && s.device?.mode === "normal");
  const bridgeReady = Boolean(canDownloadNow && s.fusBridge.connected);
  const serverBusy = Boolean(s.isBusy || s.serverQuerying);

  const activeEntries = Object.entries(s.slots).filter(([, f]) => f !== null);
  const hasLocalSelection =
    PACKAGE_SLOTS.some(({ id }) => s.slots[id] !== null) || s.partitions.length > 0;
  const salesCodeTrimmed = (s.flashOptions?.salesCode ?? "").trim();
  const hasLocalAction =
    activeEntries.length > 0 ||
    s.partitions.length > 0 ||
    Boolean(s.flashOptions?.erase) ||
    salesCodeTrimmed.length > 0;
  const hasPendingOrInvalidMd5 = activeEntries.some(([slot]) => {
    const res = s.md5Results[slot];
    return !res || ["queued", "verifying", "invalid"].includes(res.status);
  });
  const canFlashLocal = Boolean(
    isLocal && hasLocalAction && hasDownloadDevice && !s.isBusy && !hasPendingOrInvalidMd5
  );

  const selectedEntriesInfo = getSelectedEntriesInfo(s.archiveRows);
  const { selectedEntries, odinEntries } = selectedEntriesInfo;

  let validForDownload = false;
  let validForFlash = false;
  let hasBothCsc = false;
  let hasOdinComponent = false;
  if (s.serverInspect) {
    if (s.serverOutputMode === "zip") {
      validForDownload = true;
    } else {
      validForDownload = selectedEntries.length > 0;
      hasBothCsc = selectedEntriesInfo.hasBothCsc;
      hasOdinComponent = odinEntries.length > 0;
      validForFlash = hasOdinComponent && !hasBothCsc;
    }
  }

  const canDownloadOnly = Boolean(
    isServer && bridgeReady && s.serverInspect && validForDownload && !serverBusy
  );
  const canDownloadAndFlash = Boolean(
    isServer &&
      canFlash &&
      bridgeReady &&
      hasDownloadDevice &&
      s.serverInspect &&
      validForFlash &&
      !serverBusy
  );

  let serverFlashHint = "";
  if (isServer && canFlash && !s.isBusy && s.serverInspect) {
    if (s.serverOutputMode === "zip") {
      serverFlashHint =
        "Full .zip archives are download-only — select Extract Components to enable Download & Flash.";
    } else if (hasBothCsc) {
      serverFlashHint =
        "Download & Flash cannot flash both CSCs — choose either Keep Data (HOME_CSC) or Wipe Data (CSC).";
    } else if (!hasOdinComponent) {
      serverFlashHint =
        "Select at least one Odin component (BL, AP, CP, CSC, or USERDATA) to enable Download & Flash.";
    } else if (!hasDownloadDevice) {
      serverFlashHint = "Connect a Download Mode device above to enable Download & Flash.";
    }
  }

  const activeAdvancedLabels = [];
  if (s.slots.PIT) activeAdvancedLabels.push("PIT");
  if (salesCodeTrimmed) activeAdvancedLabels.push(`CSC ${salesCodeTrimmed.toUpperCase()}`);
  if (s.flashOptions?.erase) activeAdvancedLabels.push("NAND Erase (USERDATA)");
  if (s.flashOptions?.disableVerity) activeAdvancedLabels.push("Disable dm-verity");
  if (s.flashOptions?.disableVerification) activeAdvancedLabels.push("Disable AVB Verification");
  if (s.flashOptions?.skipSizeCheck) activeAdvancedLabels.push("Skip Size Check");

  return {
    canDownloadNow,
    supported,
    effectiveSource,
    isServer,
    isLocal,
    hasDownloadDevice,
    hasNormalDevice,
    bridgeReady,
    serverBusy,
    hasLocalSelection,
    hasLocalAction,
    hasPendingOrInvalidMd5,
    canFlashLocal,
    selectedEntriesInfo,
    validForDownload,
    validForFlash,
    hasBothCsc,
    hasOdinComponent,
    canDownloadOnly,
    canDownloadAndFlash,
    serverFlashHint,
    activeAdvancedLabels,
  };
}

const listeners = new Set();
let flushScheduled = false;

export function subscribe(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function flushStateNotifications() {
  flushScheduled = false;
  const derived = getDerivedState(state);
  for (const listener of Array.from(listeners)) {
    listener(state, derived);
  }
}

export function notifyStateChange() {
  if (flushScheduled) return;
  flushScheduled = true;
  queueMicrotask(flushStateNotifications);
}
