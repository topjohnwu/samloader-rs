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
  detect_download_device,
  get_backend_options,
  pair_download_device,
  pair_samsung_device,
  print_pit,
  reboot_from_odin,
  reboot_to_download_at,
  start_flash,
  verify_package_md5,
} from "./pkg/samloader_web.js";

let initPromise = null;

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
 * Lists currently paired WebUSB devices in the browser.
 */
export async function getPairedDevices() {
  if (!isWebUsbSupported()) {
    return [];
  }
  return await navigator.usb.getDevices();
}

/**
 * Lists currently paired WebSerial ports in the browser.
 */
export async function getPairedSerialPorts() {
  if (!isWebSerialSupported()) {
    return [];
  }
  return await navigator.serial.getPorts();
}

/**
 * Prompts the browser's WebUSB picker filtered for Samsung Download Mode PIDs.
 * Must be invoked from a user gesture (click handler).
 * @param {string} [backend] Optional backend name ("nusb", "vcom", "mock")
 */
export async function pairDownloadDevice(backend) {
  await initWasm();
  await pair_download_device(backend);
}

/**
 * Prompts the browser's WebUSB picker filtered for any Samsung USB device (VID 0x04E8),
 * including normal-mode/AT-mode devices.
 * Must be invoked from a user gesture (click handler).
 * @param {string} [backend] Optional backend name ("nusb", "vcom", "mock")
 */
export async function pairSamsungDevice(backend) {
  await initWasm();
  await pair_samsung_device(backend);
}

/**
 * Detects a connected Samsung Download Mode device and queries DVIF device info.
 * @param {object} options
 * @param {string} [options.backend] Backend option ("nusb", "vcom", "mock")
 * @param {boolean} [options.wait=false]
 * @param {boolean} [options.verbose=false]
 * @param {(msg: string) => void} [options.onLog]
 * @returns {Promise<string>}
 */
export async function detectDownloadDevice({
  backend,
  wait = false,
  verbose = false,
  onLog = () => {},
} = {}) {
  await initWasm();
  return await detect_download_device(backend, wait, verbose, onLog);
}

/**
 * Reboots a normal-mode/AT-mode Samsung device into Download Mode via `AT+SUDDLMOD=0,0\r`.
 * @param {object} options
 * @param {string} [options.backend] Backend option ("nusb", "vcom", "mock")
 * @param {boolean} [options.verbose=false]
 * @param {(msg: string) => void} [options.onLog]
 * @returns {Promise<boolean>} True if the AT command was sent, false if already in Download Mode
 */
export async function rebootToDownloadAt({
  backend,
  verbose = false,
  onLog = () => {},
} = {}) {
  await initWasm();
  return await reboot_to_download_at(backend, verbose, onLog);
}

/**
 * Opens an Odin session on a Download Mode device and reboots it.
 * @param {object} options
 * @param {string} [options.backend] Backend option ("nusb", "vcom", "mock")
 * @param {"download" | "normal" | "none"} [options.rebootMode="download"]
 * @param {boolean} [options.wait=false]
 * @param {boolean} [options.verbose=false]
 * @param {(msg: string) => void} [options.onLog]
 */
export async function rebootFromOdin({
  backend,
  rebootMode = "download",
  wait = false,
  verbose = false,
  onLog = () => {},
} = {}) {
  await initWasm();
  await reboot_from_odin(backend, rebootMode, wait, verbose, onLog);
}

/**
 * Downloads and formats the connected Download Mode device's PIT table.
 * @param {object} options
 * @param {string} [options.backend] Backend option ("nusb", "vcom", "mock")
 * @param {"normal" | "download" | "none"} [options.rebootMode="normal"]
 * @param {boolean} [options.wait=false]
 * @param {boolean} [options.verbose=false]
 * @param {(msg: string) => void} [options.onLog]
 * @returns {Promise<string>} Formatted PIT table text
 */
export async function printPit({
  backend,
  rebootMode = "normal",
  wait = false,
  verbose = false,
  onLog = () => {},
} = {}) {
  await initWasm();
  return await print_pit(backend, rebootMode, wait, verbose, onLog);
}

/**
 * Verifies the trailing MD5 checksum appended to `.tar.md5` package files using `samloader-odin`.
 * @param {File|Blob|Uint8Array|Object} file Package file or data object
 * @param {Function} [onProgress] Callback function receiving string log messages or progress objects
 * @returns {Promise<void>}
 */
export async function verifyPackageMd5(file, onProgress = () => {}) {
  await initWasm();
  return await verify_package_md5(file, onProgress);
}

/**
 * Flashes firmware package files to a connected Samsung Download Mode device.
 * @param {string} backend Backend option ("nusb", "vcom", "mock")
 * @param {Object} files Object mapping slot names / filenames to File/Blob/Uint8Array objects or { name, data }
 * @param {Object} [options] Flashing options
 * @param {"download" | "normal" | "none"} [options.reboot="normal"]
 * @param {boolean} [options.erase=false]
 * @param {boolean} [options.disable_verity=false]
 * @param {boolean} [options.disable_verification=false]
 * @param {boolean} [options.skip_size_check=false]
 * @param {string} [options.sales_code]
 * @param {string[] | string} [options.skip]
 * @param {boolean} [options.wait=false]
 * @param {boolean} [options.verbose=true]
 * @param {Function} [onProgress] Callback function receiving string log messages or progress objects
 * @returns {Promise<void>}
 */
export async function startFlash(backend, files, options = {}, onProgress = () => {}) {
  await initWasm();
  return await start_flash(backend, files, options, onProgress);
}
