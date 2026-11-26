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

// Shared byte-size, duration, and transfer speed/ETA formatting helpers.

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

/**
 * Tracks a sliding-window transfer rate over two monotonic counters (`wireBytes`, `outBytes`).
 */
export function createTransferSpeedTracker({
  windowMs = 3000,
  sampleIntervalMs = 250,
} = {}) {
  let samples = [];

  function reset() {
    samples = [];
  }

  function update(wireBytes, outBytes = wireBytes, nowMs = performance.now()) {
    const last = samples[samples.length - 1];
    if (last && (wireBytes < last.wire || outBytes < last.out)) {
      samples = [{ t: nowMs, wire: wireBytes, out: outBytes }];
      return { wireSpeed: 0, outSpeed: 0 };
    }
    if (!last || nowMs < last.t || nowMs - last.t >= sampleIntervalMs) {
      samples.push({ t: nowMs, wire: wireBytes, out: outBytes });
      while (
        samples.length > 2 &&
        (nowMs < samples[1].t || nowMs - samples[1].t >= windowMs)
      ) {
        samples.shift();
      }
    }
    const oldest = samples[0];
    const dtSecs = (nowMs - oldest.t) / 1000;
    if (dtSecs >= 0.25) {
      return {
        wireSpeed: Math.max(0, wireBytes - oldest.wire) / dtSecs,
        outSpeed: Math.max(0, outBytes - oldest.out) / dtSecs,
      };
    }
    return { wireSpeed: 0, outSpeed: 0 };
  }

  return { update, reset };
}

export function formatTransferMeta({ written = 0, total = 0, speed = 0, etaSecs = null } = {}) {
  const parts = [];
  if (total > 0) {
    parts.push(`${formatBytes(written)} / ${formatBytes(total)}`);
  }
  if (speed > 0) {
    parts.push(`${formatBytes(speed)}/s`);
  }
  if (typeof etaSecs === "number" && Number.isFinite(etaSecs) && etaSecs > 0) {
    parts.push(`About ${formatDuration(etaSecs)} left`);
  }
  return parts.join(" · ");
}
