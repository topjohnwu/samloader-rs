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
  FusDownloadOptions,
  clear_opfs_cache,
  detect_download_device,
  device_mode,
  fus_download,
  fus_fetch_history,
  fus_inspect_firmware,
  get_backend_options,
  opfs_build_files,
  opfs_cache_info,
  pair_download_device,
  pair_samsung_device,
  prepare_flash,
  print_pit,
  reboot_from_odin,
  reboot_to_download_at,
  set_progress_callback,
  set_verbose,
  verify_package_md5,
  version,
} from "../pkg/samloader_web.js";

let initPromise = null;
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
    initPromise = init().catch((err) => {
      initPromise = null;
      throw err;
    });
  }
  await initPromise;
}

/**
 * Registers the thread-local callback receiving log/progress event objects.
 * @param {(event: { type: "log", message: string } | { type: "progress", percent: number, current: number, total: number, partition: string, overallPercent?: number, partitionIndex?: number, partitionCount?: number, sent?: number }) => void} onProgress
 *   `overallPercent`, `partitionIndex`, `partitionCount` and `sent` (bytes sent to the device)
 *   are only present while flashing
 */
export async function setProgressCallback(onProgress) {
  await initWasm();
  set_progress_callback(onProgress);
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
 * Returns list of available USB backend options (`{ id, label }`), in preference order.
 * @returns {Promise<{ id: string, label: string }[]>}
 */
export async function getBackendOptions() {
  await initWasm();
  return get_backend_options();
}

/**
 * Returns the version of samloader-web, which all samloader-rs crates share.
 * @returns {Promise<string>}
 */
export async function getVersion() {
  await initWasm();
  return version();
}

/**
 * Classifies a USB device by its VID/PID, using samloader-odin's list of Download Mode PIDs.
 * Requires WASM to be initialized.
 * @param {number} vid
 * @param {number} pid
 * @returns {"download" | "normal" | undefined} undefined if it is not a Samsung device
 */
export function deviceMode(vid, pid) {
  return device_mode(vid, pid);
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
  if (backend === "nusb") return isWebUsbSupported();
  return false;
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
  if (backend !== "nusb" || !isWebUsbSupported()) {
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
 * @returns {Promise<{ model?: string, salesCode?: string, bootloaderVersion?: string, fields: [string, string][] }>} DVIF info as display
 *   label/value pairs; `fields` is empty if the device did not report any
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
const FLASH_OPTION_KEYS = new Set([
  "reboot",
  "erase",
  "disable_verity",
  "disable_verification",
  "skip_size_check",
  "sales_code",
  "skip",
]);

const FUS_DOWNLOAD_OPTION_KEYS = new Set([
  "model",
  "region",
  "version",
  "mode",
  "entryNames",
  "concurrency",
  "force",
]);

function buildWasmOptions(Ctor, input, allowedKeys) {
  if (input != null && typeof input !== "object") {
    throw new Error("Options must be an object");
  }
  const opts = new Ctor();
  try {
    if (input) {
      for (const [key, value] of Object.entries(input)) {
        if (!allowedKeys.has(key)) {
          throw new Error(`Unknown option "${key}"`);
        }
        if (value != null) {
          opts[key] = value;
        }
      }
    }
    return opts;
  } catch (err) {
    opts.free();
    throw err;
  }
}

export async function prepareFlash(files, options = {}) {
  await initWasm();
  const flashOptions = buildWasmOptions(FlashOptions, options, FLASH_OPTION_KEYS);
  return await prepare_flash(files, flashOptions);
}

/**
 * Fetches available firmware versions for a Samsung model and region CSC from FUS.
 * @param {string} model Device model (e.g. `"SM-S931U1"`)
 * @param {string} region Region / CSC code (e.g. `"XAA"`)
 * @param {Function} transport JS HTTP transport callback
 * @returns {Promise<{ latest: string, previous: string[], beta: string[] }>}
 */
export async function fusFetchHistory(model, region, transport) {
  await initWasm();
  return await fus_fetch_history(model, region, transport);
}

/**
 * Queries FUS binary info and reads the remote ZIP Central Directory for a firmware build.
 * @param {string} model Device model (e.g. `"SM-S931U1"`)
 * @param {string} region Region / CSC code (e.g. `"XAA"`)
 * @param {string} version Firmware version string (`PDA/CSC/CP` or `PDA/CSC/CP/BL`)
 * @param {Function} transport JS HTTP transport callback
 * @returns {Promise<{ version: string, filename: string, decryptedFilename: string, encryptedSize: number, decryptedSize: number, fingerprintHex: string, entries: { name: string, component: "bl" | "ap" | "cp" | "csc" | "home_csc" | "userdata" | null, compressedSize: number, uncompressedSize: number }[] }>}
 */
export async function fusInspectFirmware(model, region, version, transport) {
  await initWasm();
  return await fus_inspect_firmware(model, region, version, transport);
}

/**
 * Downloads and decrypts (or extracts) firmware from FUS into the specified browser storage target.
 * @param {{ model: string, region: string, version: string, mode: "zip" | "entries", entryNames?: string[], concurrency?: number, force?: boolean }} params
 * @param {{ kind: "opfs" | "directory", buildKey?: string, meta?: object, dirHandle?: FileSystemDirectoryHandle }} target
 * @param {Function} transport JS HTTP transport callback
 * @param {(event: object) => void} onProgress Progress/warning callback
 * @param {AbortSignal} [signal] Optional abort signal
 * @returns {Promise<{ version: string, filename: string, decryptedFilename: string, fingerprintHex: string, files: { name: string, component: string | null, size: number }[] }>}
 */
export async function fusDownload(params, target, transport, onProgress, signal) {
  await initWasm();
  if (!params || typeof params !== "object") {
    throw new Error("Download parameters must be an object");
  }
  const options = buildWasmOptions(FusDownloadOptions, params, FUS_DOWNLOAD_OPTION_KEYS);
  return await fus_download(options, target, transport, onProgress, signal);
}

/**
 * Reads the OPFS staging manifest and sums the byte sizes of cached files.
 * @returns {Promise<{ buildKey: string, model: string, region: string, version: string, decryptedFilename: string, fingerprintHex: string, totalBytes: number, complete: boolean, files: { name: string, component: string | null, size: number }[] } | null>}
 */
export async function getOpfsCacheInfo() {
  await initWasm();
  return await opfs_cache_info();
}

/**
 * Opens seekable `File` handles for every completed file in the staged OPFS build `buildKey`.
 * @param {string} buildKey
 * @returns {Promise<{ name: string, component: string | null, file: File }[]>}
 */
export async function getOpfsBuildFiles(buildKey) {
  await initWasm();
  return await opfs_build_files(buildKey);
}

/**
 * Recursively deletes the `samloader-staging/` directory in OPFS.
 */
export async function clearOpfsCache() {
  await initWasm();
  await clear_opfs_cache();
}
