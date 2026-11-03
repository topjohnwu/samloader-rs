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

import { setProgressCallback, takeWasmLogs, verifyPackageMd5 } from "./bridge.js";

// Verifies the MD5 footer of a single package file, then reports the result.
// Each verification runs in its own worker; the main thread cancels it with terminate().
self.onmessage = async ({ data }) => {
  const file = data?.file;
  if (!file) {
    self.postMessage({ type: "ERROR", error: "Invalid or missing file object" });
    return;
  }

  try {
    await setProgressCallback((event) => {
      if (event?.type === "progress") {
        self.postMessage({ type: "PROGRESS", percent: event.percent });
      } else if (event?.type === "log") {
        const lines = takeWasmLogs();
        if (lines.length > 0) {
          self.postMessage({ type: "LOG", lines });
        }
      }
    });

    // Drop the initial log banner so only verification output is forwarded
    takeWasmLogs();
    await verifyPackageMd5(file);
    self.postMessage({ type: "SUCCESS" });
  } catch (err) {
    self.postMessage({ type: "ERROR", error: err?.message || String(err) });
  }
};
