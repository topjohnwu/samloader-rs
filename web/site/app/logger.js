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

// Application logging and error-reporting facade over the WASM log buffer and UI hooks.

import { appendRawWasmLogs, appendWasmLog } from "./bridge.js";

let preWasmLogHandler = null;
let openLogHandler = null;

export function setLogHandlers({ onPreWasmLog = null, onOpenLog = null } = {}) {
  preWasmLogHandler = onPreWasmLog;
  openLogHandler = onOpenLog;
}

export function appendLog(msg) {
  const queuedLines = appendWasmLog(msg);
  if (queuedLines) {
    preWasmLogHandler?.(queuedLines);
  }
}

export function appendRawLogs(lines) {
  appendRawWasmLogs(lines);
}

export function reportError(msg) {
  appendLog(msg);
  openLogHandler?.();
}

export function requestOpenLog() {
  openLogHandler?.();
}
