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

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const USER_SCRIPT_PATH = path.resolve(__dirname, "../site/samloader-fus-bridge.user.js");

const unhandled = [];
process.on("unhandledRejection", (err) => unhandled.push(err));

// Minimal window EventTarget shim so fus_bridge.js runs in Node ESM
const eventTarget = new EventTarget();
globalThis.window = {
  location: { origin: "https://samloader.test" },
  addEventListener: eventTarget.addEventListener.bind(eventTarget),
  removeEventListener: eventTarget.removeEventListener.bind(eventTarget),
  dispatchEvent: eventTarget.dispatchEvent.bind(eventTarget),
};

const {
  EXPECTED_BRIDGE_VERSION,
  createFusHttpTransport,
  detectFusBridge,
  getMainThreadFusTransport,
  isBridgeOutdated,
  onFusBridgeReady,
  openBridgePort,
  toTransferableBuffer,
} = await import("../site/app/fus_bridge.js");

let gmHandler = () => {
  throw new Error("No mock GM.xmlHttpRequest handler configured");
};

before(async () => {
  const readyEvents = [];
  onFusBridgeReady((status) => readyEvents.push(status));

  const detectPromise = detectFusBridge(500);
  const scriptCode = fs.readFileSync(USER_SCRIPT_PATH, "utf8");
  vm.runInNewContext(scriptCode, {
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

  const status = await detectPromise;
  assert.deepEqual(status, {
    connected: true,
    version: EXPECTED_BRIDGE_VERSION,
    outdated: false,
  });
  assert.deepEqual(readyEvents, [
    { connected: true, version: EXPECTED_BRIDGE_VERSION, outdated: false },
  ]);
});

after(async () => {
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(unhandled.length, 0, `Unexpected unhandled rejections: ${unhandled}`);
});

describe("samloader-fus-bridge.user.js security & discovery", () => {
  test("exposes a frozen bridge and enforces URL/method allowlist", () => {
    const bridge = globalThis.window.__samloaderFusBridge;
    assert.ok(bridge);
    assert.equal(Object.isFrozen(bridge), true);
    assert.equal(bridge.version, EXPECTED_BRIDGE_VERSION);
    const metaVersion = fs
      .readFileSync(USER_SCRIPT_PATH, "utf8")
      .match(/^\/\/\s*@version\s+(\S+)/m)?.[1];
    assert.equal(metaVersion, EXPECTED_BRIDGE_VERSION);

    assert.throws(
      () => bridge.request({ method: "DELETE", url: "https://neofussvr.sslcs.cdngc.net/x" }),
      /Unsupported HTTP method/
    );
    assert.throws(
      () => bridge.request({ method: "GET", url: "https://evil.example.com/" }),
      /Blocked request/
    );
    assert.throws(
      () => bridge.request({ method: "GET", url: "https://u:p@neofussvr.sslcs.cdngc.net/x" }),
      /credentials/
    );
    assert.throws(
      () => bridge.request({ method: "GET", url: "http://neofussvr.sslcs.cdngc.net/x" }),
      /Blocked request/
    );
    assert.throws(
      () => bridge.request({ method: "GET", url: "https://cloud-neofussvr.samsungmobile.com/x" }),
      /Blocked request/
    );
    assert.throws(
      () => bridge.request({ method: "GET", url: "https://neofussvr.sslcs.cdngc.net:8443/x" }),
      /Blocked request/
    );
  });

  test("strips user/password fields before invoking GM.xmlHttpRequest", () => {
    let seen = null;
    gmHandler = (details) => {
      seen = details;
      return { abort() {} };
    };
    globalThis.window.__samloaderFusBridge.request({
      method: "get",
      url: "https://fota-cloud-dn.ospserver.net/firmware/XAA/SM-S931U1/version.xml",
      user: "secret",
      password: "pw",
    });
    assert.equal(seen.method, "GET");
    assert.equal("user" in seen, false);
    assert.equal("password" in seen, false);
  });
  test("detects outdated, current, newer, and invalid userscript versions", () => {
    assert.equal(isBridgeOutdated("0.9.9", "1.0.0"), true);
    assert.equal(isBridgeOutdated("1.0.0", "1.0.1"), true);
    assert.equal(isBridgeOutdated("1.2", "1.2.1"), true);
    assert.equal(isBridgeOutdated(null, "1.0.0"), true);
    assert.equal(isBridgeOutdated("", "1.0.0"), true);
    assert.equal(isBridgeOutdated("invalid", "1.0.0"), true);
    assert.equal(isBridgeOutdated("1.0.0", "1.0.0"), false);
    assert.equal(isBridgeOutdated("1.0", "1.0.0"), false);
    assert.equal(isBridgeOutdated("1.0.1", "1.0.0"), false);
    assert.equal(isBridgeOutdated("2.0.0", "1.0.0"), false);
  });
});

describe("direct main-thread transport", () => {
  test("handles buffered POST XML and Content-Length normalization", async () => {
    const direct = await getMainThreadFusTransport();
    let seen = null;
    gmHandler = (details) => {
      seen = details;
      setTimeout(() => {
        details.onload({
          status: 200,
          responseHeaders: "NONCE: main-nonce\r\nContent-Type: text/xml",
          response: new TextEncoder().encode("<FUSMsg>ok</FUSMsg>").buffer,
        });
      }, 2);
      return { abort() {} };
    };

    const h = direct(
      "POST",
      "https://neofussvr.sslcs.cdngc.net/NF_DownloadBinaryInform.do",
      [
        ["User-Agent", "SMART 2.0"],
        ["Content-Length", "6"],
      ],
      new TextEncoder().encode("<req/>")
    );
    const resp = await h.response;
    assert.equal(seen.data, "<req/>");
    assert.equal(seen.headers["Content-Length"], undefined);
    assert.equal(seen.redirect, undefined);
    assert.equal(resp.status, 200);
    assert.equal(resp.next, undefined);
    assert.equal(new TextDecoder().decode(resp.body), "<FUSMsg>ok</FUSMsg>");
    assert.deepEqual(resp.headers, [
      ["NONCE", "main-nonce"],
      ["Content-Type", "text/xml"],
    ]);
  });

  test("sets Content-Length: 0 on empty POST bodies", async () => {
    const direct = await getMainThreadFusTransport();
    let seen = null;
    gmHandler = (details) => {
      seen = details;
      setTimeout(() => {
        details.onload({ status: 200, responseHeaders: "NONCE: init", response: new ArrayBuffer(0) });
      }, 2);
      return { abort() {} };
    };

    const h = direct(
      "POST",
      "https://neofussvr.sslcs.cdngc.net/NF_SmartDownloadGenerateNonce.do",
      [],
      null
    );
    const resp = await h.response;
    assert.equal(seen.data, "");
    assert.equal(seen.headers["Content-Length"], "0");
    assert.equal(resp.status, 200);
    assert.equal(resp.body, null);
  });

  test("uses buffered arraybuffer with redirect: manual for small cloud binary range requests", async () => {
    const direct = await getMainThreadFusTransport();
    let seen = null;
    gmHandler = (details) => {
      seen = details;
      setTimeout(() => {
        details.onload({
          status: 206,
          responseHeaders: "Content-Range: bytes 0-1023/4096",
          response: new Uint8Array([1, 2, 3, 4]).buffer,
        });
      }, 2);
      return { abort() {} };
    };

    const h = direct(
      "GET",
      "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file=cd",
      [["Range", "bytes=0-1023"]],
      null
    );
    const resp = await h.response;
    assert.equal(seen.redirect, "manual");
    assert.equal(seen.responseType, "arraybuffer");
    assert.equal(resp.status, 206);
    assert.equal(resp.next, undefined);
    assert.deepEqual(Array.from(new Uint8Array(resp.body)), [1, 2, 3, 4]);
  });
});

describe("worker MessagePort credit-based pull relay", () => {
  test("coalesces 24 MiB of 32 KiB chunks with byte-exact integrity and sync fast path", async () => {
    const { port } = await openBridgePort();
    const worker = createFusHttpTransport(port);
    try {
      const CHUNK_SIZE = 32 * 1024;
      const TOTAL_CHUNKS = 768; // 24 MiB
      let emitted = 0;

      gmHandler = (details) => {
        assert.equal(details.redirect, "manual");
        assert.equal(details.fetch, true);
        assert.equal(details.responseType, "stream");
        const stream = new ReadableStream({
          pull(controller) {
            if (emitted >= TOTAL_CHUNKS) {
              controller.close();
              return;
            }
            const buf = new Uint8Array(CHUNK_SIZE);
            buf.fill(emitted & 0xff);
            emitted++;
            controller.enqueue(buf);
          },
        });
        setTimeout(() => {
          details.onloadstart({ status: 206, readyState: 2, responseHeaders: "", response: stream });
        }, 2);
        return { abort() {} };
      };

      const h = worker(
        "GET",
        "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file=fast",
        [["Range", "bytes=0-25165823"]],
        null
      );
      const resp = await h.response;
      assert.equal(resp.status, 206);

      // Brief pause so initial 4 MiB credit buffers ahead, exercising sync fast path
      await new Promise((r) => setTimeout(r, 25));

      let total = 0;
      let recvChunks = 0;
      let syncHits = 0;
      while (true) {
        const raw = resp.next();
        if (raw instanceof Uint8Array) syncHits++;
        const chunk = raw instanceof Promise ? await raw : raw;
        if (chunk === null) break;
        recvChunks++;
        for (let i = 0; i < chunk.byteLength; i += CHUNK_SIZE) {
          const idx = Math.floor((total + i) / CHUNK_SIZE);
          assert.equal(chunk[i], idx & 0xff);
        }
        total += chunk.byteLength;
      }
      assert.equal(total, TOTAL_CHUNKS * CHUNK_SIZE);
      assert.ok(recvChunks <= 60, `Expected <= 60 coalesced transfers, got ${recvChunks}`);
      assert.ok(syncHits >= 2, `Expected sync fast-path hits >= 2, got ${syncHits}`);
    } finally {
      worker.dispose();
    }
  });

  test("enforces credit-based backpressure while consumer is paused", async () => {
    const { port } = await openBridgePort();
    const worker = createFusHttpTransport(port);
    try {
      let emittedMiB = 0;
      gmHandler = (details) => {
        const stream = new ReadableStream({
          pull(controller) {
            if (emittedMiB >= 12) {
              controller.close();
              return;
            }
            const buf = new Uint8Array(1024 * 1024);
            buf.fill(emittedMiB + 1);
            emittedMiB++;
            controller.enqueue(buf);
          },
        });
        setTimeout(() => {
          details.onloadstart({ status: 206, readyState: 2, responseHeaders: "", response: stream });
        }, 2);
        return { abort() {} };
      };

      const h = worker(
        "GET",
        "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file=bp",
        [["Range", "bytes=0-12582911"]],
        null
      );
      const resp = await h.response;
      await new Promise((r) => setTimeout(r, 60));
      assert.ok(emittedMiB <= 6, `Expected backpressure <= 6 MiB, got ${emittedMiB} MiB`);

      let total = 0;
      while (true) {
        const raw = resp.next();
        const chunk = raw instanceof Promise ? await raw : raw;
        if (chunk === null) break;
        total += chunk.byteLength;
      }
      assert.equal(total, 12 * 1024 * 1024);
      assert.equal(emittedMiB, 12);
    } finally {
      worker.dispose();
    }
  });

  test("flushes slow small chunks via coalescing timer without losing bytes", async () => {
    const { port } = await openBridgePort();
    const worker = createFusHttpTransport(port);
    try {
      gmHandler = (details) => {
        let step = 0;
        const stream = new ReadableStream({
          async pull(controller) {
            if (step === 0) {
              step++;
              controller.enqueue(new Uint8Array([10, 20]));
            } else if (step === 1) {
              step++;
              await new Promise((r) => setTimeout(r, 40));
              controller.enqueue(new Uint8Array([30, 40]));
            } else {
              controller.close();
            }
          },
        });
        setTimeout(() => {
          details.onloadstart({ status: 206, readyState: 2, responseHeaders: "", response: stream });
        }, 2);
        return { abort() {} };
      };

      const h = worker(
        "GET",
        "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file=slow",
        [["Range", "bytes=0-1048575"]],
        null
      );
      const resp = await h.response;
      const out = [];
      while (true) {
        const raw = resp.next();
        const chunk = raw instanceof Promise ? await raw : raw;
        if (chunk === null) break;
        out.push(...chunk);
      }
      assert.deepEqual(out, [10, 20, 30, 40]);
    } finally {
      worker.dispose();
    }
  });

  test("propagates mid-stream abort and handles 401 non-stream onload + dispose", async () => {
    const { port } = await openBridgePort();
    const worker = createFusHttpTransport(port);

    let aborted = false;
    let cancelled = false;
    gmHandler = (details) => {
      let step = 0;
      const stream = new ReadableStream({
        pull(controller) {
          if (step++ === 0) controller.enqueue(new Uint8Array([1, 2]));
          else return new Promise(() => {});
        },
        cancel() {
          cancelled = true;
        },
      });
      setTimeout(() => {
        details.onloadstart({ status: 206, readyState: 2, responseHeaders: "", response: stream });
      }, 2);
      return {
        abort() {
          aborted = true;
        },
      };
    };

    const h1 = worker(
      "GET",
      "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file=abort",
      [["Range", "bytes=0-1048575"]],
      null
    );
    await h1.response;
    await new Promise((r) => setTimeout(r, 5));
    h1.abort();
    await new Promise((r) => setTimeout(r, 25));
    assert.equal(cancelled, true);
    assert.equal(aborted, true);

    // 401 non-stream onload resolves as buffered ArrayBuffer
    gmHandler = (details) => {
      assert.equal(details.redirect, "manual");
      setTimeout(() => {
        details.onload({
          status: 401,
          responseHeaders: "NONCE: rotated",
          response: new TextEncoder().encode("Unauthorized").buffer,
        });
      }, 2);
      return { abort() {} };
    };

    const h2 = worker(
      "GET",
      "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file=401",
      [["Range", "bytes=0-1048575"]],
      null
    );
    const resp401 = await h2.response;
    assert.equal(resp401.status, 401);
    assert.equal(resp401.next, undefined);
    assert.equal(new TextDecoder().decode(resp401.body), "Unauthorized");

    // dispose() rejects post-dispose requests
    worker.dispose();
    const h3 = worker(
      "GET",
      "https://fota-cloud-dn.ospserver.net/firmware/XAA/SM-S931U1/version.xml",
      [],
      null
    );
    await assert.rejects(() => h3.response, /closed/);
  });

  test("host dispose aborts active stream even without client close message", async () => {
    const { port, dispose } = await openBridgePort();
    const worker = createFusHttpTransport(port);

    let aborted = false;
    let cancelled = false;
    gmHandler = (details) => {
      let step = 0;
      const stream = new ReadableStream({
        pull(controller) {
          if (step++ === 0) controller.enqueue(new Uint8Array([1, 2]));
          else return new Promise(() => {});
        },
        cancel() {
          cancelled = true;
        },
      });
      setTimeout(() => {
        details.onloadstart({ status: 206, readyState: 2, responseHeaders: "", response: stream });
      }, 2);
      return {
        abort() {
          aborted = true;
        },
      };
    };

    const h = worker(
      "GET",
      "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file=host-dispose",
      [["Range", "bytes=0-1048575"]],
      null
    );
    await h.response;
    await new Promise((r) => setTimeout(r, 5));

    // Simulate worker.terminate() without sending a client "close" message
    dispose();
    await new Promise((r) => setTimeout(r, 15));
    assert.equal(cancelled, true);
    assert.equal(aborted, true);
    worker.dispose();
  });
});

describe("toTransferableBuffer", () => {
  test("slices subarrays and preserves standalone full buffers", () => {
    const big = new Uint8Array([10, 20, 30, 40, 50]);
    const sub = big.subarray(1, 4);
    const sliced = toTransferableBuffer(sub);
    assert.ok(sliced instanceof ArrayBuffer);
    assert.deepEqual(Array.from(new Uint8Array(sliced)), [20, 30, 40]);

    const full = new Uint8Array([1, 2, 3]);
    assert.equal(toTransferableBuffer(full), full.buffer);
  });
});
