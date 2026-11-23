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

// Exclusive operation guard, screen wake lock, and tab-close protection.

import { state } from "./state.js";

let wakeLock = null;
let busyChangeListener = null;

export function setBusyChangeListener(listener) {
  busyChangeListener = listener;
}

async function acquireWakeLock() {
  if (wakeLock || typeof navigator === "undefined" || !navigator.wakeLock) return;
  try {
    const lock = await navigator.wakeLock.request("screen");
    lock.addEventListener("release", () => {
      if (wakeLock === lock) wakeLock = null;
    });
    wakeLock = lock;
  } catch {
    // Wake lock may be denied (e.g. battery saver); the operation proceeds without it
  }
}

async function releaseWakeLock() {
  const lock = wakeLock;
  wakeLock = null;
  try {
    await lock?.release();
  } catch {
    // Already released by the browser
  }
}

export function setupExclusiveGuards() {
  if (typeof window !== "undefined") {
    window.addEventListener("beforeunload", (e) => {
      if (state.isBusy) {
        e.preventDefault();
        e.returnValue = "";
      }
    });
  }
  // Browsers drop the wake lock whenever the page is hidden; re-acquire it on return
  if (typeof document !== "undefined") {
    document.addEventListener("visibilitychange", () => {
      if (state.isBusy && document.visibilityState === "visible") {
        acquireWakeLock();
      }
    });
  }
}

export async function runExclusiveWithSetup(prepareFn, fn) {
  if (state.isBusy) return;
  state.isBusy = true;
  busyChangeListener?.(true);
  try {
    const setupResult = await prepareFn();
    if (setupResult === false) return;
    await acquireWakeLock();
    await fn(setupResult);
  } finally {
    state.isBusy = false;
    await releaseWakeLock();
    busyChangeListener?.(false);
  }
}

export async function runExclusive(fn) {
  await runExclusiveWithSetup(
    () => true,
    async () => {
      await fn();
    }
  );
}
