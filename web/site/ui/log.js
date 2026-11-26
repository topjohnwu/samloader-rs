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

// The activity log panel with fixed-line-height viewport virtualization.

import { setVerbose } from "../app/bridge.js";
import {
  appendLog,
  clearLogs,
  exportLogs,
  getLastLogLine,
  getLogLines,
  onLogChange,
  setOpenLogHandler,
} from "../app/logger.js";
import { state } from "../app/state.js";
import { downloadFile, localTimestampForFilename } from "./util.js";

const LOG_LINE_HEIGHT = 20;
const LOG_OVERSCAN = 20;

let logStickToBottom = true;
let logFlushScheduled = false;
let renderedStart = -1;
let renderedEnd = -1;
let renderedTotal = -1;

function flushLogViewport(stickToBottom = logStickToBottom) {
  const container = document.querySelector(".log-terminal");
  const logElem = document.getElementById("log-output");
  if (!container || !logElem) return;

  const preview = document.getElementById("log-preview");
  if (preview) preview.textContent = getLastLogLine();

  const lines = getLogLines();
  const totalLines = lines.length;
  const totalHeight = totalLines * LOG_LINE_HEIGHT;
  const vh = container.clientHeight > 0 ? container.clientHeight : 220;
  const effectiveScrollTop = stickToBottom
    ? Math.max(0, totalHeight - vh)
    : Math.max(0, container.scrollTop);

  const firstVisible = Math.floor(effectiveScrollTop / LOG_LINE_HEIGHT);
  const visibleCount = Math.ceil(vh / LOG_LINE_HEIGHT);
  const startIndex = Math.min(Math.max(0, firstVisible - LOG_OVERSCAN), totalLines);
  const endIndex = Math.min(firstVisible + visibleCount + LOG_OVERSCAN, totalLines);

  const heightChanged = renderedTotal !== totalLines;
  renderedTotal = totalLines;
  const sliceChanged = startIndex !== renderedStart || endIndex !== renderedEnd;

  if (!heightChanged && !sliceChanged) return;

  if (heightChanged) {
    logElem.style.height = `${totalHeight}px`;
  }
  if (sliceChanged) {
    renderedStart = startIndex;
    renderedEnd = endIndex;
    logElem.style.paddingTop = `${startIndex * LOG_LINE_HEIGHT}px`;
    logElem.textContent = lines.slice(startIndex, endIndex).join("\n");
  }
  if (stickToBottom && heightChanged) {
    container.scrollTop = container.scrollHeight;
  }
}

function scheduleLogFlush() {
  if (logFlushScheduled) return;
  logFlushScheduled = true;
  requestAnimationFrame(() => {
    logFlushScheduled = false;
    flushLogViewport(logStickToBottom);
  });
}

function setupLogScroller() {
  const container = document.querySelector(".log-terminal");
  const logElem = document.getElementById("log-output");
  if (!container || !logElem) return;

  logElem.style.lineHeight = `${LOG_LINE_HEIGHT}px`;

  container.addEventListener(
    "scroll",
    () => {
      const distanceFromBottom =
        container.scrollHeight - container.scrollTop - container.clientHeight;
      logStickToBottom = distanceFromBottom <= LOG_LINE_HEIGHT * 1.5;
      flushLogViewport(false);
    },
    { passive: true }
  );

  onLogChange(scheduleLogFlush);
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
  renderedStart = -1;
  renderedEnd = -1;
  renderedTotal = -1;
  logStickToBottom = true;
  clearLogs();
  flushLogViewport(true);
}

export function saveLog() {
  downloadFile(
    `samloader-web-${localTimestampForFilename()}.log`,
    `${exportLogs()}\n`,
    "text/plain"
  );
}

export function setupLogPanel() {
  setOpenLogHandler(openLog);
  setupLogScroller();

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
