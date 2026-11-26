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

// Application log buffer and error-reporting hooks.

const INITIAL_LOG_BANNER = "-- samloader-rs Odin Web Flasher Initialized --";
const CLEARED_LOG_BANNER = "-- Log Cleared --";

let lines = [INITIAL_LOG_BANNER];
const logListeners = new Set();
let openLogHandler = null;

function formatLogLines(msg) {
  const timestamp = new Date().toTimeString().slice(0, 8);
  const [first, ...rest] = String(msg).split("\n");
  return [`[${timestamp}] ${first}`, ...rest];
}

function notifyLogChange() {
  for (const listener of logListeners) {
    listener();
  }
}

export function onLogChange(listener) {
  logListeners.add(listener);
  return () => logListeners.delete(listener);
}

export function setOpenLogHandler(fn) {
  openLogHandler = fn;
}

export function appendLog(msg) {
  lines.push(...formatLogLines(msg));
  notifyLogChange();
}

export function clearLogs() {
  lines = [CLEARED_LOG_BANNER];
  notifyLogChange();
}

export function exportLogs() {
  return lines.join("\n");
}

export function getLastLogLine() {
  for (let i = lines.length - 1; i >= 0; i--) {
    if (lines[i].trim() !== "") return lines[i];
  }
  return "";
}

export function getLogLines() {
  return lines;
}

export function reportError(msg) {
  appendLog(msg);
  openLogHandler?.();
}

export function requestOpenLog() {
  openLogHandler?.();
}
