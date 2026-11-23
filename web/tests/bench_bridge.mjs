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

// Microbenchmark for the main-thread <-> download_worker MessagePort relay in web/fus_bridge.js.
// Run with: node web/tests/bench_bridge.mjs

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const USER_SCRIPT_PATH = path.resolve(__dirname, "../samloader-fus-bridge.user.js");

const eventTarget = new EventTarget();
globalThis.window = {
  location: { origin: "https://samloader.test" },
  addEventListener: eventTarget.addEventListener.bind(eventTarget),
  removeEventListener: eventTarget.removeEventListener.bind(eventTarget),
  dispatchEvent: eventTarget.dispatchEvent.bind(eventTarget),
};

const { createFusHttpTransport, openBridgePort } = await import("../fus_bridge.js");

let gmHandler = null;
vm.runInNewContext(fs.readFileSync(USER_SCRIPT_PATH, "utf8"), {
  window: globalThis.window,
  unsafeWindow: globalThis.window,
  document: { querySelector: () => ({}) },
  CustomEvent,
  URL,
  Object,
  String,
  Error,
  GM: {
    xmlHttpRequest: Object.assign((details) => gmHandler(details), {
      RESPONSE_TYPE_STREAM: "stream",
    }),
  },
});

async function benchStream({ totalMiB, chunkKiB }) {
  const totalBytes = totalMiB * 1024 * 1024;
  const chunkBytes = chunkKiB * 1024;
  const totalChunks = totalBytes / chunkBytes;
  const port = await openBridgePort();
  const worker = createFusHttpTransport(port);

  try {
    let emitted = 0;
    gmHandler = (details) => {
      const stream = new ReadableStream({
        pull(controller) {
          if (emitted >= totalChunks) {
            controller.close();
            return;
          }
          controller.enqueue(new Uint8Array(chunkBytes));
          emitted++;
        },
      });
      queueMicrotask(() => {
        details.onloadstart({ status: 206, readyState: 2, responseHeaders: "", response: stream });
      });
      return { abort() {} };
    };

    const t0 = performance.now();
    const h = worker(
      "GET",
      "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file=bench",
      [["Range", `bytes=0-${totalBytes - 1}`]],
      null
    );
    const resp = await h.response;

    let received = 0;
    let transfers = 0;
    let syncHits = 0;
    while (true) {
      const raw = resp.next();
      if (raw instanceof Uint8Array) syncHits++;
      const chunk = raw instanceof Promise ? await raw : raw;
      if (chunk === null) break;
      received += chunk.byteLength;
      transfers++;
    }
    const elapsedMs = performance.now() - t0;
    if (received !== totalBytes) {
      throw new Error(`Expected ${totalBytes} bytes, got ${received}`);
    }

    const mibPerSec = totalMiB / (elapsedMs / 1000);
    const avgKiB = received / transfers / 1024;
    const syncPct = ((syncHits / transfers) * 100).toFixed(1);
    console.log(
      `${totalMiB} MiB (${chunkKiB} KiB upstream chunks): ${elapsedMs.toFixed(1)} ms | ` +
        `${mibPerSec.toFixed(1)} MiB/s | ${transfers} transfers (avg ${avgKiB.toFixed(0)} KiB) | ` +
        `sync fast-path ${syncPct}%`
    );
  } finally {
    worker.dispose();
  }
}

await benchStream({ totalMiB: 64, chunkKiB: 32 });
await benchStream({ totalMiB: 64, chunkKiB: 64 });
await benchStream({ totalMiB: 64, chunkKiB: 512 });
