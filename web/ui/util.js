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

// Formatting, download, progress bar and accessibility helpers.

// --- Formatting ---
export function formatBytes(bytes) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.max(0, Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function formatDuration(totalSeconds) {
  const secs = Math.max(0, Math.round(totalSeconds));
  const pad = (n) => String(n).padStart(2, "0");
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

// --- Progress Bars & Accessibility ---
// Sets a progress bar's fill and its container's ARIA value
export function setBarPercent(bar, percent) {
  if (!bar) return;
  bar.style.width = `${percent}%`;
  bar.parentElement?.setAttribute("aria-valuenow", String(Math.round(percent)));
}

// Announces a status change to screen readers. Used for milestones only, as the
// status line itself changes with every percent.
export function announce(message) {
  const el = document.getElementById("flash-announcer");
  if (el) el.textContent = message;
}

export function isActivationKey(e) {
  return e.key === "Enter" || e.key === " ";
}

// --- File Downloads ---
export function downloadFile(filename, data, type) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Revoke later, as some browsers start the download asynchronously
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

export function localTimestampForFilename() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-` +
    `${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`
  );
}
