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

// Shared application state and the package slot table.

// --- Constants & Application State ---
// Odin package slots, in flashing order. Their markup is rendered from #slot-template.
export const PACKAGE_SLOTS = [
  { id: "BL", badge: "BL", label: "Bootloader" },
  { id: "AP", badge: "AP", label: "System / Application" },
  { id: "CP", badge: "CP", label: "Modem / Radio" },
  { id: "CSC", badge: "CSC", label: "CSC / HOME_CSC" },
  { id: "USERDATA", badge: "USER", label: "User Data" },
];

export const SLOTS = [...PACKAGE_SLOTS.map((s) => s.id), "PIT"];

export const state = {
  capabilities: {
    canFlash: true,
    canDownload: true,
    extensionSupport: "supported",
    isEdgeAndroid: false,
  },
  selectedBackend: null,
  rebootMode: "normal",
  skipMd5: false,
  verbose: false,
  firmwareSource: "server",
  device: null,
  slots: Object.fromEntries(SLOTS.map((slot) => [slot, null])),
  md5Results: {},
  deviceModel: null, // Model reported by the last DVIF query of the current device
  deviceSalesCode: null, // Sales code / CSC reported by the last DVIF query
  deviceBootloaderVersion: null, // Bootloader version reported by the last DVIF query
  hasLastPit: false,
  partitions: [],
  nextPartitionId: 1,
  isBusy: false,
  fusBridge: {
    checked: false,
    connected: false,
    version: null,
    outdated: false,
  },
  serverQuerying: false,
  serverHistory: null,
  serverInspect: null,
  serverOutputMode: "entries",
  serverConcurrency: 6,
  serverSelection: {
    validForDownload: false,
    validForFlash: false,
    hasBothCsc: false,
    hasOdinComponent: false,
  },
  opfsCache: null,
  lastDownloadedDir: null,
};
