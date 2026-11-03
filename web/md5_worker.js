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

let taskQueue = Promise.resolve();
const activeRequestIds = new Map();

async function handleVerifyMd5({ fileId, requestId, file }) {
  if (activeRequestIds.get(fileId) !== requestId) {
    return;
  }

  if (!file) {
    self.postMessage({
      type: "ERROR",
      fileId,
      requestId,
      error: "Invalid or missing file object",
    });
    return;
  }

  try {
    await setProgressCallback((event) => {
      if (activeRequestIds.get(fileId) !== requestId) {
        return;
      }
      if (!event || typeof event !== "object") return;
      if (event.type === "progress") {
        self.postMessage({
          type: "PROGRESS",
          fileId,
          requestId,
          bytesProcessed: event.current,
          totalBytes: event.total,
          percent: event.percent,
        });
      } else if (event.type === "log") {
        const lines = takeWasmLogs();
        if (lines.length > 0) {
          self.postMessage({
            type: "LOG",
            fileId,
            requestId,
            lines,
          });
        }
      }
    });

    takeWasmLogs();
    await verifyPackageMd5(file);

    if (activeRequestIds.get(fileId) === requestId) {
      self.postMessage({
        type: "SUCCESS",
        fileId,
        requestId,
      });
    }
  } catch (err) {
    if (activeRequestIds.get(fileId) === requestId) {
      self.postMessage({
        type: "ERROR",
        fileId,
        requestId,
        error: err?.message || String(err),
      });
    }
  }
}

self.onmessage = (event) => {
  const { command, fileId, requestId, file } = event.data || {};
  if (command === "CANCEL_MD5") {
    if (fileId) {
      activeRequestIds.delete(fileId);
    } else {
      activeRequestIds.clear();
    }
    return;
  }
  if (command !== "VERIFY_MD5") {
    return;
  }

  activeRequestIds.set(fileId, requestId);
  taskQueue = taskQueue.then(() => handleVerifyMd5({ fileId, requestId, file }));
};
