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

// The activity log panel, rendered by the virtualized log viewport in Rust.

import {
  clearWasmLog,
  exportWasmLogs,
  lastWasmLogLine,
  logLineHeight,
  renderLogViewport,
  setVerbose,
} from "../app/bridge.js";
import { appendLog, setLogHandlers } from "../app/logger.js";
import { state } from "../app/state.js";
import { downloadFile, localTimestampForFilename } from "./util.js";

// --- Virtualized Activity Log Scroller ---
let logStickToBottom = true;
let logFlushScheduled = false;

function renderPreWasmLines(queuedLines) {
  // WASM is still initializing; show the queued lines until Rust takes over rendering
  const logElem = document.getElementById("log-output");
  if (logElem) {
    const separator = logElem.textContent ? "\n" : "";
    logElem.textContent += `${separator}${queuedLines.join("\n")}`;
  }
  const preview = document.getElementById("log-preview");
  if (preview) preview.textContent = queuedLines.at(-1) ?? "";
}

function flushLogViewport(stickToBottom = logStickToBottom) {
  const container = document.querySelector(".log-terminal");
  const logElem = document.getElementById("log-output");
  if (!container || !logElem) return;

  // Keep the latest line visible in the header while the log is folded. Before WASM
  // is initialized, renderPreWasmLines() shows the queued lines instead.
  const preview = document.getElementById("log-preview");
  const lastLine = lastWasmLogLine();
  if (preview && lastLine !== null) preview.textContent = lastLine;

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

// --- Folding ---
// The log is folded by default. It opens on errors and for output that is the result
// of an action (e.g. a PIT dump), as that would otherwise go unnoticed.
function setLogExpanded(expanded) {
  const toggle = document.getElementById("log-toggle");
  const body = document.getElementById("log-body");
  const actions = document.getElementById("log-actions");
  if (!toggle || !body) return;
  if ((toggle.getAttribute("aria-expanded") === "true") === expanded) return;

  toggle.setAttribute("aria-expanded", String(expanded));
  body.hidden = !expanded;
  if (actions) actions.hidden = !expanded;
  if (expanded) {
    // The viewport has no size while folded, so render it again at the bottom
    const container = document.querySelector(".log-terminal");
    logStickToBottom = true;
    flushLogViewport(true);
    if (container) container.scrollTop = container.scrollHeight;
  }
}

export function openLog() {
  setLogExpanded(true);
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

export function setupLogPanel() {
  setLogHandlers({
    onPreWasmLog: renderPreWasmLines,
    onOpenLog: openLog,
  });

  const toggle = document.getElementById("log-toggle");
  toggle?.addEventListener("click", () => {
    setLogExpanded(toggle.getAttribute("aria-expanded") !== "true");
  });

  document.getElementById("opt-verbose")?.addEventListener("change", async (e) => {
    const enabled = e.target.checked;
    state.verbose = enabled;
    await setVerbose(enabled);
    appendLog(`Verbose logging ${enabled ? "enabled" : "disabled"}.`);
  });

  document.getElementById("btn-clear-log")?.addEventListener("click", clearLog);
  document.getElementById("btn-save-log")?.addEventListener("click", saveLog);
}
