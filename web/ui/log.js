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

// The activity log, rendered by the virtualized log viewport in Rust.

import {
  appendWasmLog,
  clearWasmLog,
  exportWasmLogs,
  renderLogViewport,
  logLineHeight,
} from "../bridge.js";
import { downloadFile, localTimestampForFilename } from "./util.js";

// --- Virtualized Activity Log Scroller ---
let logStickToBottom = true;

let logFlushScheduled = false;

function flushLogViewport(stickToBottom = logStickToBottom) {
  const container = document.querySelector(".log-terminal");
  const logElem = document.getElementById("log-output");
  if (!container || !logElem) return;

  const view = renderLogViewport(container.scrollTop, container.clientHeight, stickToBottom);
  if (!view) return;

  if (view.totalHeight !== undefined) {
    logElem.style.height = `${view.totalHeight}px`;
  }
  if (view.paddingTop !== undefined) {
    logElem.style.paddingTop = `${view.paddingTop}px`;
  }
  if (view.text !== undefined) {
    logElem.textContent = view.text;
  }
  if (view.scrollToBottom) {
    container.scrollTop = container.scrollHeight;
  }
}

export function scheduleLogFlush() {
  if (logFlushScheduled) return;
  logFlushScheduled = true;
  requestAnimationFrame(() => {
    logFlushScheduled = false;
    flushLogViewport(logStickToBottom);
  });
}

export function setupLogScroller() {
  const container = document.querySelector(".log-terminal");
  const logElem = document.getElementById("log-output");
  if (!container || !logElem) return;

  // The virtualization in Rust assumes a fixed line height, so take it from there
  const lineHeight = logLineHeight();
  logElem.style.lineHeight = `${lineHeight}px`;

  container.addEventListener(
    "scroll",
    () => {
      const distanceFromBottom =
        container.scrollHeight - container.scrollTop - container.clientHeight;
      logStickToBottom = distanceFromBottom <= lineHeight * 1.5;
      flushLogViewport(false);
    },
    { passive: true }
  );

  flushLogViewport(true);
}

// --- Log Buffer ---
export function appendLog(msg) {
  const queuedLines = appendWasmLog(msg);
  if (queuedLines) {
    // WASM is still initializing; show the queued lines until Rust takes over rendering
    const logElem = document.getElementById("log-output");
    if (logElem) {
      const separator = logElem.textContent ? "\n" : "";
      logElem.textContent += `${separator}${queuedLines.join("\n")}`;
    }
  }
}

export function clearLog() {
  clearWasmLog();
  logStickToBottom = true;
  flushLogViewport(true);
}

export function saveLog() {
  downloadFile(
    `samloader-web-${localTimestampForFilename()}.log`,
    `${exportWasmLogs()}\n`,
    "text/plain"
  );
}
