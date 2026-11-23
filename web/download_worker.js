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

import {
  initWasm,
  setProgressCallback,
  setVerbose,
  takeWasmLogs,
  fusDownload,
} from "./bridge.js";
import { createFusHttpTransport } from "./fus_bridge.js";

let activeAbortController = null;
let isRunning = false;

function flushWorkerLogs() {
  const lines = takeWasmLogs();
  if (lines.length > 0) {
    self.postMessage({ type: "LOG", lines });
  }
}

function closePortQuietly(p) {
  if (!p) return;
  try {
    p.close();
  } catch {
    // Ignore close errors
  }
}

async function handleStart({ port, target, params, verbose }) {
  if (isRunning) {
    closePortQuietly(port);
    self.postMessage({
      type: "ERROR",
      error: "A download is already running in this worker",
    });
    return;
  }
  if (!port || !target || !params) {
    closePortQuietly(port);
    self.postMessage({
      type: "ERROR",
      error: "Invalid START message: missing port, target, or download params",
    });
    return;
  }

  isRunning = true;
  const abortController = new AbortController();
  activeAbortController = abortController;
  let transport = null;
  let outgoing;

  const cleanup = () => {
    if (activeAbortController === abortController) {
      activeAbortController = null;
    }
    isRunning = false;
    try {
      transport?.dispose?.();
    } catch {
      // Ignore close errors
    }
    if (!transport) {
      closePortQuietly(port);
    }
  };

  try {
    await initWasm();
    await setProgressCallback((event) => {
      if (event?.type === "log") {
        flushWorkerLogs();
      }
    });
    await setVerbose(Boolean(verbose));
    // Drop the initial log banner so only download logs are forwarded
    takeWasmLogs();

    if (abortController.signal.aborted) {
      outgoing = { type: "CANCELLED" };
    } else {
      transport = createFusHttpTransport(port);

      const onProgress = (event) => {
        if (event && typeof event === "object") {
          switch (event.type) {
            case "progress":
              self.postMessage({ ...event, type: "PROGRESS" });
              break;
            case "file_done":
              self.postMessage({ ...event, type: "FILE_DONE" });
              break;
            case "warning":
              self.postMessage({ ...event, type: "WARNING" });
              break;
          }
        }
        flushWorkerLogs();
      };

      const result = await fusDownload(
        params,
        target,
        transport,
        onProgress,
        abortController.signal
      );

      flushWorkerLogs();
      outgoing = { type: "COMPLETE", result };
    }
  } catch (err) {
    flushWorkerLogs();
    outgoing = abortController.signal.aborted
      ? { type: "CANCELLED" }
      : { type: "ERROR", error: err?.message || String(err) };
  } finally {
    cleanup();
  }

  self.postMessage(outgoing);
}

self.onmessage = ({ data }) => {
  if (!data || typeof data !== "object") return;
  if (data.type === "START") {
    void handleStart(data);
  } else if (data.type === "CANCEL") {
    activeAbortController?.abort();
  }
};
