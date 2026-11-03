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

import init, {
  FlashOptions,
  append_log,
  append_raw_logs,
  clear_log,
  clear_progress_callback,
  detect_download_device,
  export_logs,
  get_backend_options,
  log_line_height,
  pair_download_device,
  pair_samsung_device,
  prepare_flash,
  print_pit,
  reboot_from_odin,
  reboot_to_download_at,
  render_log_viewport,
  set_progress_callback,
  set_verbose,
  take_logs,
  verify_package_md5,
} from "./pkg/samloader_web.js";

let initPromise = null;
let wasmReady = false;
const pendingLogs = [];
let mockPairedDevice = null;

function createMockDevice(productId) {
  return {
    vendorId: 0x04e8,
    productId,
    productName: "Samsung SM-F968B (Simulated)",
    serialNumber: "C1A2B3C4",
    disconnect: async () => {
      mockPairedDevice = null;
    },
  };
}

/**
 * Initializes the samloader-web WASM module if not already initialized.
 */
export async function initWasm() {
  if (!initPromise) {
    initPromise = init()
      .then((res) => {
        wasmReady = true;
        if (pendingLogs.length > 0) {
          append_raw_logs(pendingLogs.splice(0));
        }
        return res;
      })
      .catch((err) => {
        initPromise = null;
        wasmReady = false;
        throw err;
      });
  }
  await initPromise;
}

/**
 * Registers the thread-local callback receiving log/progress event objects.
 * @param {(event: { type: "log" } | { type: "progress", percent: number, current: number, total: number, partition: string, overallPercent?: number, partitionIndex?: number, partitionCount?: number, sent?: number }) => void} onProgress
 *   `overallPercent`, `partitionIndex`, `partitionCount` and `sent` (bytes sent to the device)
 *   are only present while flashing
 */
export async function setProgressCallback(onProgress) {
  await initWasm();
  set_progress_callback(onProgress);
}

/**
 * Clears the thread-local progress reporter.
 */
export async function clearProgressCallback() {
  await initWasm();
  clear_progress_callback();
}

/**
 * Sets whether verbose log messages are emitted by the active progress reporter.
 * @param {boolean} verbose
 */
export async function setVerbose(verbose) {
  await initWasm();
  set_verbose(Boolean(verbose));
}

/**
 * Formats a log message like the Rust log buffer does: the first line is prefixed
 * with a local `[HH:MM:SS]` timestamp, and continuation lines are kept as-is.
 * @param {string} msg
 * @returns {string[]}
 */
function formatLogLines(msg) {
  const timestamp = new Date().toTimeString().slice(0, 8);
  const [first, ...rest] = msg.split("\n");
  return [`[${timestamp}] ${first}`, ...rest];
}

/**
 * Appends a log message to the Rust log buffer, queuing it if WASM is still initializing.
 * Queued messages are timestamped at the time they are logged, not when they are flushed.
 * @param {string} msg
 * @returns {string[] | null} null if appended directly to WASM, or the formatted lines
 *   that were queued before WASM init (so callers can display them immediately)
 */
export function appendWasmLog(msg) {
  const text = String(msg);
  if (wasmReady) {
    append_log(text);
    return null;
  }
  const lines = formatLogLines(text);
  pendingLogs.push(...lines);
  return lines;
}

/**
 * Appends pre-formatted log lines (e.g. from a Web Worker) to the Rust log buffer.
 * @param {string[]} lines
 */
export function appendRawWasmLogs(lines) {
  if (wasmReady && Array.isArray(lines) && lines.length > 0) {
    append_raw_logs(lines);
  }
}

/**
 * Clears the Rust log buffer.
 */
export function clearWasmLog() {
  if (wasmReady) {
    clear_log();
  }
}

/**
 * Drains buffered log lines from the current thread's progress reporter.
 * @returns {string[]}
 */
export function takeWasmLogs() {
  if (!wasmReady) return [];
  return take_logs();
}

/**
 * Returns the full contents of the Rust log buffer.
 * @returns {string} All log lines joined with newlines, or an empty string before WASM init
 */
export function exportWasmLogs() {
  return wasmReady ? export_logs() : "";
}

/**
 * Returns the log line height in pixels used by the Rust log viewport virtualization.
 * @returns {number | null} Line height, or null if WASM is not initialized yet
 */
export function logLineHeight() {
  return wasmReady ? log_line_height() : null;
}

/**
 * Computes the visible virtualized log viewport slice in Rust.
 * @param {number} scrollTop
 * @param {number} viewportHeight
 * @param {boolean} stickToBottom
 * @returns {{ totalHeight?: number, paddingTop?: number, text?: string, scrollToBottom: boolean } | null}
 */
export function renderLogViewport(scrollTop, viewportHeight, stickToBottom) {
  if (!wasmReady) return null;
  return render_log_viewport(scrollTop, viewportHeight, stickToBottom);
}

/**
 * Returns list of available USB backend option names ("nusb", "vcom", "mock").
 * @returns {Promise<string[]>}
 */
export async function getBackendOptions() {
  await initWasm();
  return get_backend_options();
}

/**
 * Checks whether the current browser context supports WebUSB.
 */
export function isWebUsbSupported() {
  return typeof navigator !== "undefined" && "usb" in navigator;
}

/**
 * Checks whether the current browser context supports WebSerial.
 */
export function isWebSerialSupported() {
  return typeof navigator !== "undefined" && "serial" in navigator;
}

/**
 * Checks whether the current browser context supports the specified backend.
 * @param {string} backend Backend option ("nusb", "vcom", "mock")
 */
export function isBackendSupported(backend) {
  if (backend === "mock") return true;
  if (backend === "vcom") return isWebSerialSupported();
  return isWebUsbSupported();
}

/**
 * Lists currently paired devices for the specified backend with a normalized shape.
 * @param {string} [backend="nusb"] Backend option ("nusb", "vcom", "mock")
 */
export async function getPairedDevices(backend = "nusb") {
  if (backend === "mock") {
    return mockPairedDevice ? [mockPairedDevice] : [];
  }
  if (backend === "vcom") {
    if (!isWebSerialSupported()) {
      return [];
    }
    const ports = await navigator.serial.getPorts();
    return ports
      .map((port) => {
        const info = port.getInfo ? port.getInfo() : {};
        return {
          vendorId: info.usbVendorId,
          productId: info.usbProductId,
          productName: "Samsung Serial Port",
          serialNumber: undefined,
          disconnect: async () => {
            try {
              await port.close();
            } catch {
              // Port may not be open
            }
            if (typeof port.forget === "function") {
              await port.forget();
            }
          },
        };
      })
      .filter((d) => d.vendorId != null && d.productId != null);
  }
  if (!isWebUsbSupported()) {
    return [];
  }
  const devices = await navigator.usb.getDevices();
  return devices.map((d) => ({
    vendorId: d.vendorId,
    productId: d.productId,
    productName: d.productName,
    serialNumber: d.serialNumber,
    disconnect: async () => {
      if (d.opened) {
        try {
          await d.close();
        } catch {
          // Device may already be closing
        }
      }
      if (typeof d.forget === "function") {
        await d.forget();
      }
    },
  }));
}

/**
 * Prompts the browser's device picker filtered for Samsung Download Mode PIDs.
 * Must be invoked from a user gesture (click handler).
 * @param {string} [backend] Optional backend name ("nusb", "vcom", "mock")
 */
export async function pairDownloadDevice(backend) {
  await initWasm();
  await pair_download_device(backend);
  if (backend === "mock") {
    mockPairedDevice = createMockDevice(0x685d);
  }
}

/**
 * Prompts the browser's device picker filtered for any Samsung USB device (VID 0x04E8),
 * including normal-mode/AT-mode devices.
 * Must be invoked from a user gesture (click handler).
 * @param {string} [backend] Optional backend name ("nusb", "vcom", "mock")
 */
export async function pairSamsungDevice(backend) {
  await initWasm();
  await pair_samsung_device(backend);
  if (backend === "mock") {
    mockPairedDevice = createMockDevice(0x6860);
  }
}

/**
 * Detects a connected Samsung Download Mode device and queries DVIF device info.
 * @param {object} [options]
 * @param {string} [options.backend] Backend option ("nusb", "vcom", "mock")
 * @param {boolean} [options.wait=false]
 * @returns {Promise<string>}
 */
export async function detectDownloadDevice({ backend, wait = false } = {}) {
  await initWasm();
  return await detect_download_device(backend, wait);
}

/**
 * Reboots a normal-mode/AT-mode Samsung device into Download Mode via `AT+SUDDLMOD=0,0\r`.
 * @param {object} [options]
 * @param {string} [options.backend] Backend option ("nusb", "vcom", "mock")
 * @returns {Promise<boolean>} True if the AT command was sent, false if already in Download Mode
 */
export async function rebootToDownloadAt({ backend } = {}) {
  await initWasm();
  return await reboot_to_download_at(backend);
}

/**
 * Opens an Odin session on a Download Mode device and reboots it.
 * @param {object} [options]
 * @param {string} [options.backend] Backend option ("nusb", "vcom", "mock")
 * @param {"download" | "normal" | "none"} [options.rebootMode="download"]
 * @param {boolean} [options.wait=false]
 */
export async function rebootFromOdin({
  backend,
  rebootMode = "download",
  wait = false,
} = {}) {
  await initWasm();
  await reboot_from_odin(backend, rebootMode, wait);
}

/**
 * Downloads and formats the connected Download Mode device's PIT table.
 * @param {object} [options]
 * @param {string} [options.backend] Backend option ("nusb", "vcom", "mock")
 * @param {"normal" | "download" | "none"} [options.rebootMode="normal"]
 * @param {boolean} [options.wait=false]
 * @returns {Promise<{ text: string, data: Uint8Array }>} Formatted PIT table and raw PIT bytes
 */
export async function printPit({
  backend,
  rebootMode = "normal",
  wait = false,
} = {}) {
  await initWasm();
  return await print_pit(backend, rebootMode, wait);
}

/**
 * Verifies the trailing MD5 checksum appended to `.tar.md5` package files using `samloader-odin`.
 * @param {File|Blob|Uint8Array|Object} file Package file or data object
 * @returns {Promise<void>}
 */
export async function verifyPackageMd5(file) {
  await initWasm();
  return await verify_package_md5(file);
}

/**
 * Validates and indexes firmware package files without connecting to a device.
 * Inspect the returned job (e.g. to confirm data-wiping flashes), then either call
 * `job.execute(backend, wait)` to flash, or `job.free()` to discard it.
 *
 * Like the CLI, the slot alone decides how an input is used: package slots are always
 * parsed as TAR packages, `PIT` is always the PIT, and `partitions` are always raw images.
 * Any other key is rejected.
 * @param {Object} files Flash inputs. Each value is a File/Blob/Uint8Array/ArrayBuffer or `{ name, data }`.
 * @param {*} [files.BL] Bootloader package
 * @param {*} [files.AP] AP package
 * @param {*} [files.CP] CP (modem) package
 * @param {*} [files.CSC] CSC / HOME_CSC package
 * @param {*} [files.USERDATA] USERDATA package
 * @param {*} [files.PIT] PIT file
 * @param {{ file: *, partition?: string | null }[]} [files.partitions] Raw partition images,
 *   flashed to `partition` (name or numeric ID) or matched by file name if omitted
 * @param {Object} [options] Flashing options
 * @param {"download" | "normal" | "none"} [options.reboot="normal"]
 * @param {boolean} [options.erase=false]
 * @param {boolean} [options.disable_verity=false]
 * @param {boolean} [options.disable_verification=false]
 * @param {boolean} [options.skip_size_check=false]
 * @param {string} [options.sales_code]
 * @param {string[]} [options.skip] File or partition names to exclude
 * @returns {Promise<FlashJob>} Job with `flashes_userdata(): boolean`, `erases_userdata(): boolean`,
 *   `execute(backend: string, wait: boolean): Promise<void>` (consumes the job), and `free(): void`
 */
export async function prepareFlash(files, options = {}) {
  await initWasm();
  // The generated setters convert each value; unset options keep their defaults
  const flashOptions = Object.assign(new FlashOptions(), options);
  return await prepare_flash(files, flashOptions);
}
