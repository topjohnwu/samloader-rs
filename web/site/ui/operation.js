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

// Shared action-bar operation progress, per-file download rows, cancel button, and result banner.

import { COMPONENT_META } from "../app/download.js";
import { formatTransferMeta } from "../app/format.js";
import { state } from "../app/state.js";
import { openLog } from "./log.js";
import { formatBytes, setBarPercent } from "./util.js";

let activeCancelHandler = null;
const fileRows = new Map();

export function revealActionBar() {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  document
    .querySelector(".action-bar")
    ?.scrollIntoView({ block: "nearest", behavior: reduceMotion ? "auto" : "smooth" });
}

export function setCancelOperationButton({
  visible,
  disabled = false,
  label = "Cancel",
  onCancel = null,
} = {}) {
  activeCancelHandler = visible ? onCancel : null;
  const btn = document.getElementById("btn-cancel-operation");
  if (!btn) return;
  btn.hidden = !visible;
  btn.disabled = Boolean(disabled);
  btn.textContent = label;
}

export function updateOperationProgress({ statusText, percent, detailText } = {}) {
  const progressBar = document.getElementById("flash-progress-bar");
  const percentText = document.getElementById("flash-percent-text");
  const statusEl = document.getElementById("flash-status-text");
  const detailEl = document.getElementById("flash-detail-text");
  if (typeof percent === "number") {
    const clamped = Math.max(0, Math.min(100, percent));
    setBarPercent(progressBar, clamped);
    if (percentText) percentText.textContent = `${Math.floor(clamped)}%`;
  }
  if (statusEl && statusText !== undefined) statusEl.textContent = statusText;
  if (detailEl && detailText !== undefined) detailEl.textContent = detailText;
}

export function clearDownloadFileRows() {
  fileRows.clear();
  const listEl = document.getElementById("download-files-progress");
  if (!listEl) return;
  listEl.replaceChildren();
  listEl.hidden = true;
}

export function initDownloadFileRows(files) {
  clearDownloadFileRows();
  const listEl = document.getElementById("download-files-progress");
  const tpl = document.getElementById("download-file-template");
  if (!listEl || !tpl || !Array.isArray(files) || files.length <= 1) return;

  const fragment = document.createDocumentFragment();
  for (const { name = "", component = null, uncompressedSize = 0 } of files) {
    const item = tpl.content.firstElementChild.cloneNode(true);
    item.querySelector(".download-file-badge").textContent =
      COMPONENT_META[component]?.badge ?? "FILE";
    const nameEl = item.querySelector(".download-file-name");
    nameEl.textContent = name;
    nameEl.title = name;
    item
      .querySelector(".download-file-track")
      .setAttribute("aria-label", `Progress for ${name}`);

    const metaEl = item.querySelector(".download-file-meta");
    metaEl.textContent = uncompressedSize > 0 ? formatBytes(uncompressedSize) : "";
    fragment.appendChild(item);

    fileRows.set(name, {
      item,
      statusEl: item.querySelector(".badge"),
      barEl: item.querySelector(".progress-bar-fill"),
      metaEl,
      size: uncompressedSize,
    });
  }

  listEl.appendChild(fragment);
  listEl.hidden = false;
}

export function hasMultipleDownloadRows() {
  return fileRows.size > 1;
}

export function updateDownloadFileRow(fileName, { written = 0, total = 0, speed = 0, etaSecs = null }) {
  const row = fileRows.get(fileName);
  if (!row) return;
  const filePct = total > 0 ? Math.min(100, (written / total) * 100) : 100;
  row.item.className = "download-file-item is-active";
  row.statusEl.className = "badge badge-hashing";
  row.statusEl.textContent = `${Math.floor(filePct)}%`;
  setBarPercent(row.barEl, filePct);
  row.metaEl.textContent = formatTransferMeta({ written, total, speed, etaSecs });
}

export function markDownloadFileDone(fileName, { skipped = false, size = 0 } = {}) {
  const row = fileRows.get(fileName);
  if (!row) return;
  row.item.className = "download-file-item is-done";
  row.statusEl.className = "badge badge-valid";
  row.statusEl.textContent = skipped ? "Skipped" : "Done";
  setBarPercent(row.barEl, 100);
  const finalSize = formatBytes(size || row.size);
  row.metaEl.textContent = skipped ? `${finalSize} · Already complete` : finalSize;
}

export function showOperationResult(
  variant,
  message,
  { showLog = variant === "error", showLoadIntoLocal = false } = {}
) {
  const result = document.getElementById("flash-result");
  const text = document.getElementById("flash-result-text");
  const showLogBtn = document.getElementById("btn-show-log");
  const loadLocalBtn = document.getElementById("btn-load-into-local");
  if (!result || !text) return;
  result.classList.toggle("result-success", variant === "success");
  result.classList.toggle("result-error", variant === "error");
  result.classList.toggle("result-warning", variant === "warning");
  text.textContent = message;
  if (showLogBtn) showLogBtn.hidden = !showLog;
  if (loadLocalBtn) loadLocalBtn.hidden = !(showLoadIntoLocal && state.capabilities.canFlash);
  result.hidden = false;
}

export function hideOperationResult() {
  const result = document.getElementById("flash-result");
  const loadLocalBtn = document.getElementById("btn-load-into-local");
  if (loadLocalBtn) loadLocalBtn.hidden = true;
  if (result) result.hidden = true;
}

export function beginOperation({ statusText = "Preparing..." } = {}) {
  hideOperationResult();
  setCancelOperationButton({ visible: false });
  updateOperationProgress({ statusText, percent: 0, detailText: "" });
  const controls = document.getElementById("action-controls");
  const panel = document.getElementById("flash-progress-panel");
  const hint = document.getElementById("server-flash-hint");
  if (controls) controls.hidden = true;
  if (panel) panel.hidden = false;
  if (hint) hint.hidden = true;
  revealActionBar();
}

export function endOperation() {
  setCancelOperationButton({ visible: false });
  clearDownloadFileRows();
  const controls = document.getElementById("action-controls");
  const panel = document.getElementById("flash-progress-panel");
  if (controls) controls.hidden = false;
  if (panel) panel.hidden = true;
}

export function setupOperationPanel() {
  document.getElementById("btn-dismiss-result")?.addEventListener("click", hideOperationResult);
  document.getElementById("btn-show-log")?.addEventListener("click", () => {
    openLog();
    document.querySelector(".log-card")?.scrollIntoView({ block: "nearest" });
  });
  document.getElementById("btn-cancel-operation")?.addEventListener("click", () => {
    activeCancelHandler?.();
  });
}
