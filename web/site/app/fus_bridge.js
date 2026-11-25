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

/**
 * Extracts or slices a standalone transferable `ArrayBuffer` from a typed array or buffer.
 * @param {ArrayBufferView | ArrayBuffer} data
 * @returns {ArrayBuffer}
 */
export function toTransferableBuffer(data) {
  const view =
    data instanceof Uint8Array
      ? data
      : ArrayBuffer.isView(data)
        ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
        : new Uint8Array(data);
  if (
    typeof SharedArrayBuffer !== "undefined" &&
    view.buffer instanceof SharedArrayBuffer
  ) {
    return view.slice().buffer;
  }
  if (view.byteOffset === 0 && view.byteLength === view.buffer.byteLength) {
    return view.buffer;
  }
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
}

const BRIDGE_GLOBAL = "__samloaderFusBridge";
const BRIDGE_READY_EVENT = "samloader-fus-bridge-ready";
export const EXPECTED_BRIDGE_VERSION = "1.0.0";
const STREAM_MIN_RANGE_BYTES = 256 * 1024;
const STREAM_COALESCE_BYTES = 512 * 1024;
const STREAM_COALESCE_MS = 15;
const STREAM_CREDIT_WINDOW = 4 * 1024 * 1024;
const STREAM_CREDIT_REPLENISH = 2 * 1024 * 1024;

const globalActiveRequests = new Set();
let unloadListenersInstalled = false;
let mainThreadTransport = null;

function getInstalledBridge() {
  if (typeof window === "undefined") return null;
  const bridge = window[BRIDGE_GLOBAL];
  return bridge && typeof bridge === "object" && typeof bridge.request === "function"
    ? bridge
    : null;
}

/**
 * Returns whether the FUS bridge userscript is currently attached to `window`.
 * @returns {boolean}
 */
export function hasInstalledBridge() {
  return getInstalledBridge() !== null;
}

async function ensureBridge() {
  let bridge = getInstalledBridge();
  if (!bridge) {
    await detectFusBridge();
    bridge = getInstalledBridge();
    if (!bridge) {
      throw new Error(
        "FUS Bridge userscript is not connected. Install and enable the userscript, then try again."
      );
    }
  }
  return bridge;
}

function parseVersionParts(version) {
  if (typeof version !== "string") return null;
  const trimmed = version.trim().replace(/^v/i, "");
  if (!/^\d+(?:\.\d+)*$/.test(trimmed)) return null;
  return trimmed.split(".").map(Number);
}

/**
 * Returns true if `installedVersion` is missing, malformed, or older than `expectedVersion`.
 * @param {string | null | undefined} installedVersion
 * @param {string} [expectedVersion=EXPECTED_BRIDGE_VERSION]
 */
export function isBridgeOutdated(installedVersion, expectedVersion = EXPECTED_BRIDGE_VERSION) {
  const installed = parseVersionParts(installedVersion);
  const expected = parseVersionParts(expectedVersion);
  if (!expected) return false;
  if (!installed) return true;
  const len = Math.max(installed.length, expected.length);
  for (let i = 0; i < len; i++) {
    const a = installed[i] ?? 0;
    const b = expected[i] ?? 0;
    if (a !== b) return a < b;
  }
  return false;
}

function readBridgeStatus(bridge) {
  const version = typeof bridge?.version === "string" ? bridge.version : null;
  return {
    connected: true,
    version,
    outdated: isBridgeOutdated(version),
  };
}

function ensureUnloadListeners() {
  if (unloadListenersInstalled || typeof window === "undefined") return;
  unloadListenersInstalled = true;
  const abortAll = () => {
    for (const entry of Array.from(globalActiveRequests)) entry.abort();
  };
  window.addEventListener("pagehide", abortAll);
  window.addEventListener("beforeunload", abortAll);
}

/**
 * Probes the page for the `samloader-fus-bridge` Tampermonkey userscript.
 * @param {number} [timeoutMs=800]
 * @returns {Promise<{ connected: boolean, version: string | null }>}
 */
export function detectFusBridge(timeoutMs = 800) {
  if (typeof window === "undefined" || window.location.origin === "null") {
    return Promise.resolve({ connected: false, version: null, outdated: false });
  }
  const installed = getInstalledBridge();
  if (installed) return Promise.resolve(readBridgeStatus(installed));

  return new Promise((resolve) => {
    let settled = false;
    let timerId = null;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      window.removeEventListener(BRIDGE_READY_EVENT, onReady);
      if (timerId !== null) clearTimeout(timerId);
      resolve(result);
    };

    const onReady = () => {
      const bridge = getInstalledBridge();
      if (bridge) finish(readBridgeStatus(bridge));
    };

    window.addEventListener(BRIDGE_READY_EVENT, onReady);
    timerId = setTimeout(() => {
      const late = getInstalledBridge();
      finish(
        late ? readBridgeStatus(late) : { connected: false, version: null, outdated: false }
      );
    }, Math.max(0, timeoutMs));
  });
}

/**
 * Registers a listener invoked when the userscript attaches after initial page load.
 * @param {(status: { connected: boolean, version: string | null }) => void} callback
 */
export function onFusBridgeReady(callback) {
  if (typeof window === "undefined" || typeof callback !== "function") return;
  window.addEventListener(BRIDGE_READY_EVENT, () => {
    const bridge = getInstalledBridge();
    if (bridge) callback(readBridgeStatus(bridge));
  });
}

// --- GM.xmlHttpRequest Transport (Main Thread) ---

function isCloudBinaryUrl(url) {
  return typeof url === "string" && url.startsWith("http://cloud-neofussvr.samsungmobile.com/");
}

function isLargeDownloadRequest(method, url, reqHeaders) {
  if (method !== "GET" || !isCloudBinaryUrl(url)) return false;
  for (const [key, value] of Object.entries(reqHeaders)) {
    if (key.toLowerCase() === "range") {
      const m = /^bytes=(\d+)-(\d+)$/i.exec(String(value).trim());
      if (m && Number(m[2]) - Number(m[1]) + 1 <= STREAM_MIN_RANGE_BYTES) {
        return false;
      }
    }
  }
  return true;
}

function parseResponseHeaders(rawHeaders) {
  if (typeof rawHeaders !== "string" || !rawHeaders) return [];
  const result = [];
  for (const line of rawHeaders.split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    if (key) result.push([key, line.slice(idx + 1).trim()]);
  }
  return result;
}

function buildGmRequest(rawHeaders, method, body) {
  const reqHeaders = Object.create(null);
  if (Array.isArray(rawHeaders)) {
    for (const [k, v] of rawHeaders) {
      reqHeaders[String(k)] = String(v);
    }
  }

  const bytes =
    body == null || typeof body === "string"
      ? null
      : body instanceof Uint8Array
        ? body
        : new Uint8Array(body);

  let data;
  if (typeof body === "string" ? body.length > 0 : bytes && bytes.byteLength > 0) {
    // Samsung FUS POST bodies are UTF-8 XML; plain strings avoid Tampermonkey MV3 Blob quirks.
    data = typeof body === "string" ? body : new TextDecoder().decode(bytes);
    for (const k of Object.keys(reqHeaders)) {
      if (k.toLowerCase() === "content-length") delete reqHeaders[k];
    }
  } else if (method === "POST") {
    data = "";
    if (!Object.keys(reqHeaders).some((k) => k.toLowerCase() === "content-length")) {
      reqHeaders["Content-Length"] = "0";
    }
  }

  return { reqHeaders, data };
}

function extractResponseBuffer(resp) {
  const body = resp?.response;
  if (body instanceof ArrayBuffer) return body.byteLength > 0 ? body : null;
  if (ArrayBuffer.isView(body)) {
    return body.byteLength > 0 ? toTransferableBuffer(body) : null;
  }
  return null;
}

function validStatusOf(resp) {
  const code = Number(resp?.status);
  return Number.isInteger(code) && code >= 100 && code <= 599 ? code : 0;
}

/**
 * Direct main-thread transport implementing the `(method, url, headers, body) => { response, abort }`
 * contract expected by `web/src/http.rs` (and reused by `attachBridgePortHost`).
 */
function createDirectFusHttpTransport(bridge) {
  ensureUnloadListeners();
  const responseTypeStream =
    typeof bridge.responseTypeStream === "string" ? bridge.responseTypeStream : "stream";

  return function directFusHttpTransport(method = "GET", url, headers = [], body = null) {
    const upperMethod = String(method).toUpperCase();
    const { reqHeaders, data } = buildGmRequest(headers, upperMethod, body);
    const useStream = isLargeDownloadRequest(upperMethod, url, reqHeaders);

    let settled = false;
    let aborted = false;
    let reqHandle = null;
    let reader = null;
    let resolveResp;
    let rejectResp;

    const entry = {
      abort() {
        if (aborted) return;
        aborted = true;
        globalActiveRequests.delete(entry);
        if (!settled) {
          settled = true;
          rejectResp(new Error("Request aborted"));
        }
        reader?.cancel().catch(() => {});
        reader = null;
        try {
          reqHandle?.abort?.();
        } catch {
          // Ignore abort errors
        }
      },
    };

    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      globalActiveRequests.delete(entry);
      fn(arg);
    };

    const response = new Promise((resolve, reject) => {
      resolveResp = resolve;
      rejectResp = reject;
    });
    // Prevent unhandledrejection if aborted after the caller stops awaiting `response`
    response.catch(() => {});

    globalActiveRequests.add(entry);

    const details = {
      method: upperMethod,
      url,
      headers: reqHeaders,
      anonymous: false,
      // Chrome MV3 Tampermonkey adds `origin: null` to every request, routing it through its
      // webRequest wrapper where `401` stalls for 5s unless `redirect: "manual"` is set.
      ...(upperMethod === "GET" && isCloudBinaryUrl(url) ? { redirect: "manual" } : {}),
      onerror(err) {
        finish(rejectResp, new Error(err?.error || err?.statusText || err?.message || "Network request failed"));
      },
      ontimeout() {
        finish(rejectResp, new Error("Request timed out"));
      },
      onabort() {
        finish(rejectResp, new Error("Request aborted"));
      },
    };

    if (data !== undefined) details.data = data;

    const handleBufferedLoad = (resp) => {
      const status = validStatusOf(resp);
      if (!status) {
        finish(rejectResp, new Error(`Network request failed (status ${resp?.status ?? 0})`));
        return;
      }
      finish(resolveResp, {
        status,
        headers: parseResponseHeaders(resp.responseHeaders),
        body: extractResponseBuffer(resp),
      });
    };

    if (useStream) {
      details.responseType = responseTypeStream;
      details.fetch = true;
      let streamRef = null;

      const capture = (resp) => {
        if (settled || aborted || !resp) return;
        if (!streamRef && typeof resp.response?.getReader === "function") {
          streamRef = resp.response;
        }
        const status = validStatusOf(resp);
        if (status && streamRef) {
          settled = true;
          try {
            reader = streamRef.getReader();
          } catch (err) {
            globalActiveRequests.delete(entry);
            rejectResp(err);
            return;
          }
          const activeReader = reader;
          resolveResp({
            status,
            headers: parseResponseHeaders(resp.responseHeaders),
            next: async () => {
              const { done, value } = await activeReader.read();
              if (done) {
                globalActiveRequests.delete(entry);
                reader = null;
                return null;
              }
              return value;
            },
          });
        }
      };

      details.onloadstart = capture;
      details.onreadystatechange = capture;
      details.onprogress = capture;
      details.onload = (resp) => {
        capture(resp);
        if (!settled) handleBufferedLoad(resp);
      };
    } else {
      details.responseType = "arraybuffer";
      details.onload = handleBufferedLoad;
    }

    try {
      reqHandle = bridge.request(details);
      if (aborted) reqHandle?.abort?.();
    } catch (err) {
      finish(rejectResp, err instanceof Error ? err : new Error(String(err)));
    }

    return { response, abort: entry.abort };
  };
}

// --- Pull-Based MessagePort Relay (Main Thread Host <-> Download Worker Client) ---

function postSafely(port, msg, transferBuffer = null) {
  try {
    if (transferBuffer) {
      port.postMessage(msg, [transferBuffer]);
    } else {
      port.postMessage(msg);
    }
    return true;
  } catch {
    return false;
  }
}

export function attachBridgePortHost(port, bridge) {
  const direct = createDirectFusHttpTransport(bridge);
  const active = new Map();

  function handleFetch({ id, method, url, headers, body }) {
    if (id == null) return;
    active.get(id)?.abort();

    const handle = direct(method, url, headers, body);
    let finished = false;
    let nextFn = null;
    let credit = 0;
    let pumping = false;
    let pendingChunks = [];
    let pendingBytes = 0;
    let flushTimer = null;

    const clearFlushTimer = () => {
      if (flushTimer !== null) {
        clearTimeout(flushTimer);
        flushTimer = null;
      }
    };

    const flushPending = () => {
      clearFlushTimer();
      if (finished || pendingBytes === 0) {
        pendingChunks = [];
        pendingBytes = 0;
        return true;
      }
      let out;
      if (pendingChunks.length === 1) {
        out = pendingChunks[0];
      } else {
        out = new Uint8Array(pendingBytes);
        let offset = 0;
        for (const piece of pendingChunks) {
          out.set(piece, offset);
          offset += piece.byteLength;
        }
      }
      pendingChunks = [];
      pendingBytes = 0;
      const ab = toTransferableBuffer(out);
      credit -= ab.byteLength;
      if (!postSafely(port, { type: "chunk", id, data: ab }, ab)) {
        entry.abort();
        return false;
      }
      return true;
    };

    const fail = (message) => {
      if (finished) return;
      finished = true;
      clearFlushTimer();
      pendingChunks = [];
      pendingBytes = 0;
      active.delete(id);
      handle.abort();
      postSafely(port, { type: "error", id, message });
    };

    const pump = async () => {
      if (finished || pumping || !nextFn || credit <= 0) return;
      pumping = true;
      try {
        while (!finished && credit > 0) {
          const value = await nextFn();
          if (finished) return;
          if (value == null) {
            if (flushPending()) {
              finished = true;
              active.delete(id);
              postSafely(port, { type: "end", id });
            }
            return;
          }
          if (value.byteLength > 0) {
            const u8 = value instanceof Uint8Array ? value : new Uint8Array(value);
            pendingChunks.push(u8);
            pendingBytes += u8.byteLength;
            if (pendingBytes >= STREAM_COALESCE_BYTES || pendingBytes >= credit) {
              if (!flushPending()) return;
            } else if (flushTimer === null) {
              flushTimer = setTimeout(flushPending, STREAM_COALESCE_MS);
            }
          }
        }
        if (!finished) flushPending();
      } catch (err) {
        fail(err?.message || String(err) || "Stream read failed");
      } finally {
        pumping = false;
      }
    };

    const entry = {
      grant(bytes) {
        if (finished || !(bytes > 0)) return;
        credit += bytes;
        void pump();
      },
      abort() {
        if (finished) return;
        finished = true;
        clearFlushTimer();
        pendingChunks = [];
        pendingBytes = 0;
        active.delete(id);
        handle.abort();
      },
    };

    active.set(id, entry);

    handle.response
      .then(({ status, headers: respHeaders, body: respBody, next }) => {
        if (finished) {
          handle.abort();
          return;
        }
        if (typeof next === "function") {
          nextFn = next;
          if (!postSafely(port, { type: "headers", id, status, headers: respHeaders })) {
            entry.abort();
            return;
          }
          void pump();
        } else {
          finished = true;
          active.delete(id);
          const buf = respBody instanceof ArrayBuffer ? respBody : null;
          postSafely(port, { type: "response", id, status, headers: respHeaders, body: buf }, buf);
        }
      })
      .catch((err) => fail(err?.message || String(err)));
  }

  port.onmessage = ({ data: msg }) => {
    if (!msg || typeof msg !== "object") return;
    switch (msg.type) {
      case "fetch":
        handleFetch(msg);
        break;
      case "pull":
        active.get(msg.id)?.grant(msg.bytes);
        break;
      case "abort":
        active.get(msg.id)?.abort();
        break;
      case "close":
        for (const entry of Array.from(active.values())) entry.abort();
        active.clear();
        port.onmessage = null;
        try {
          port.close();
        } catch {
          // Ignore close errors
        }
        break;
    }
  };
  port.start();
}

/**
 * Opens a `MessageChannel` whose host end executes requests through the userscript bridge,
 * returning the client `MessagePort` for `workers/download.js`.
 * @returns {Promise<MessagePort>}
 */
export async function openBridgePort() {
  if (typeof window === "undefined" || window.location.origin === "null") {
    throw new Error("openBridgePort must be called from a valid window origin");
  }
  const bridge = await ensureBridge();
  const channel = new MessageChannel();
  attachBridgePortHost(channel.port1, bridge);
  return channel.port2;
}

/**
 * Creates a credit-based pull `MessagePort` transport implementing the `(method, url, headers, body) => { response, abort }`
 * contract with a 4 MiB credit window (replenished every 2 MiB) and synchronous chunk delivery when buffered.
 * Call `.dispose()` on the returned function when tearing down the transport.
 * @param {MessagePort} port
 */
export function createFusHttpTransport(port) {
  if (!port || typeof port.postMessage !== "function") {
    throw new Error("createFusHttpTransport requires a valid MessagePort");
  }

  let disposed = false;
  let nextId = 1;
  const pending = new Map();

  const grantCredit = (id, entry, bytes) => {
    if (disposed || entry.closed || entry.eof || entry.error || bytes <= 0) return;
    if (!postSafely(port, { type: "pull", id, bytes })) {
      failEntry(id, entry, new Error("FUS bridge MessagePort closed"));
    }
  };

  const accountConsumed = (id, entry, byteLength) => {
    entry.consumedSinceGrant += byteLength;
    if (entry.consumedSinceGrant >= STREAM_CREDIT_REPLENISH) {
      const bytes = entry.consumedSinceGrant;
      entry.consumedSinceGrant = 0;
      grantCredit(id, entry, bytes);
    }
  };

  const failEntry = (id, entry, err) => {
    pending.delete(id);
    if (!entry.headersSettled) {
      entry.headersSettled = true;
      entry.closed = true;
      entry.rejectHeaders(err);
      return;
    }
    if (!entry.error) entry.error = err;
    const waiter = entry.waiter;
    if (waiter) {
      entry.waiter = null;
      waiter.reject(err);
    }
  };

  const onPortMessage = ({ data: msg }) => {
    if (disposed || !msg || typeof msg !== "object") return;
    const entry = pending.get(msg.id);
    if (!entry) return;

    switch (msg.type) {
      case "response": {
        if (entry.headersSettled) return;
        entry.headersSettled = true;
        entry.closed = true;
        pending.delete(msg.id);
        entry.resolveHeaders({
          status: msg.status,
          headers: Array.isArray(msg.headers) ? msg.headers : [],
          body: msg.body ?? null,
        });
        break;
      }

      case "headers": {
        if (entry.headersSettled) return;
        entry.headersSettled = true;
        const id = msg.id;

        const next = () => {
          if (entry.error) throw entry.error;
          if (entry.chunks.length > 0) {
            const chunk = entry.chunks.shift();
            accountConsumed(id, entry, chunk.byteLength);
            return chunk;
          }
          if (entry.eof || entry.closed) return null;
          return new Promise((resolve, reject) => {
            entry.waiter = { resolve, reject };
          });
        };

        grantCredit(id, entry, STREAM_CREDIT_WINDOW);
        entry.resolveHeaders({
          status: msg.status,
          headers: Array.isArray(msg.headers) ? msg.headers : [],
          next,
        });
        break;
      }

      case "chunk": {
        if (!entry.headersSettled || entry.closed) return;
        if (msg.data != null) {
          const chunk = msg.data instanceof Uint8Array ? msg.data : new Uint8Array(msg.data);
          if (chunk.byteLength > 0) {
            if (entry.waiter) {
              const waiter = entry.waiter;
              entry.waiter = null;
              accountConsumed(msg.id, entry, chunk.byteLength);
              waiter.resolve(chunk);
            } else {
              entry.chunks.push(chunk);
            }
          }
        }
        break;
      }

      case "end": {
        pending.delete(msg.id);
        if (!entry.headersSettled) {
          entry.headersSettled = true;
          entry.closed = true;
          entry.rejectHeaders(new Error("Bridge stream ended before receiving HTTP headers"));
          return;
        }
        entry.eof = true;
        const waiter = entry.waiter;
        if (waiter) {
          entry.waiter = null;
          waiter.resolve(null);
        }
        break;
      }

      case "error": {
        failEntry(msg.id, entry, new Error(msg.message || "FUS bridge request failed"));
        break;
      }
    }
  };

  const onPortMessageError = () => {
    const err = new Error("FUS bridge MessagePort deserialization failed");
    for (const [id, entry] of Array.from(pending.entries())) failEntry(id, entry, err);
  };

  port.addEventListener("message", onPortMessage);
  port.addEventListener("messageerror", onPortMessageError);
  port.start?.();

  function fusHttpTransport(method = "GET", url, headers = [], body = null) {
    if (disposed) {
      return {
        response: Promise.reject(new Error("FUS bridge transport is closed")),
        abort() {},
      };
    }

    const id = nextId++;
    let payloadBody = null;
    if (body instanceof ArrayBuffer) {
      payloadBody = body.slice(0);
    } else if (ArrayBuffer.isView(body)) {
      payloadBody = new Uint8Array(body.buffer, body.byteOffset, body.byteLength).slice().buffer;
    } else if (typeof body === "string") {
      payloadBody = body;
    }

    const entry = {
      resolveHeaders: null,
      rejectHeaders: null,
      headersSettled: false,
      closed: false,
      eof: false,
      error: null,
      chunks: [],
      consumedSinceGrant: 0,
      waiter: null,
    };

    const response = new Promise((resolveHeaders, rejectHeaders) => {
      entry.resolveHeaders = resolveHeaders;
      entry.rejectHeaders = rejectHeaders;
    });
    response.catch(() => {});

    pending.set(id, entry);
    const transferBuf = payloadBody instanceof ArrayBuffer ? payloadBody : null;
    if (!postSafely(port, { type: "fetch", id, method, url, headers, body: payloadBody }, transferBuf)) {
      failEntry(id, entry, new Error("Failed to send fetch over FUS bridge MessagePort"));
    }

    const abort = () => {
      if (entry.closed) return;
      entry.closed = true;
      entry.chunks = [];
      const wasPending = pending.delete(id);
      if (!entry.headersSettled) {
        entry.headersSettled = true;
        entry.rejectHeaders(new Error("Request aborted"));
      } else if (entry.waiter) {
        const waiter = entry.waiter;
        entry.waiter = null;
        waiter.reject(new Error("Request aborted"));
      }
      if (wasPending) {
        postSafely(port, { type: "abort", id });
      }
    };

    return { response, abort };
  }

  fusHttpTransport.dispose = () => {
    if (disposed) return;
    disposed = true;
    port.removeEventListener("message", onPortMessage);
    port.removeEventListener("messageerror", onPortMessageError);
    postSafely(port, { type: "close" });
    const err = new Error("FUS bridge transport disposed");
    for (const [id, entry] of Array.from(pending.entries())) failEntry(id, entry, err);
    try {
      port.close();
    } catch {
      // Ignore close errors
    }
  };

  return fusHttpTransport;
}

/**
 * Returns the cached direct main-thread FUS HTTP transport function.
 * @returns {Promise<Function>}
 */
export async function getMainThreadFusTransport() {
  if (typeof window === "undefined") {
    throw new Error("getMainThreadFusTransport must be called on the main thread");
  }
  if (!mainThreadTransport) {
    mainThreadTransport = createDirectFusHttpTransport(await ensureBridge());
  }
  return mainThreadTransport;
}
