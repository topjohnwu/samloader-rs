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

#![cfg(target_arch = "wasm32")]

mod progress;
mod reader;

use futures::io::AsyncReadExt;
use samloader_odin::{
    DownloadModeReboot, FlashRequest, OdinConnection, OdinSession, PreparedFlash, RebootMode,
    UsbBackendOption, reboot_download, request_device, request_reboot_device, verify_md5_footer,
};
use samloader_pit::PitData;
use wasm_bindgen::prelude::*;

use crate::reader::{
    JsReader, extract_explicit_name_from_js, extract_explicit_partition_from_js,
    extract_reader_from_js,
};

fn parse_backend(backend: Option<&str>) -> Result<UsbBackendOption, JsValue> {
    let s = backend.unwrap_or("nusb");
    match s.to_lowercase().as_str() {
        "webusb" | "nusb" => Ok(UsbBackendOption::Nusb),
        "webserial" | "vcom" | "serial" => Ok(UsbBackendOption::Vcom),
        "mock" => Ok(UsbBackendOption::Mock),
        _ => s.parse::<UsbBackendOption>().map_err(to_js_err),
    }
}

fn parse_reboot_mode(mode: &str) -> RebootMode {
    match mode.trim().to_ascii_lowercase().as_str() {
        "download" | "redownload" => RebootMode::Download,
        "normal" | "reboot" => RebootMode::Normal,
        _ => RebootMode::None,
    }
}

fn to_js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Returns array of supported backend option names ("nusb", "vcom", "mock").
#[wasm_bindgen]
pub fn get_backend_options() -> Vec<String> {
    UsbBackendOption::ALL
        .iter()
        .map(|b| b.to_str().to_string())
        .collect()
}

/// Prompts the browser's device picker for a Samsung device in Download Mode.
#[wasm_bindgen]
pub async fn pair_download_device(backend_str: Option<String>) -> Result<(), JsValue> {
    let backend = parse_backend(backend_str.as_deref())?;
    request_device(backend).await.map_err(to_js_err)
}

/// Prompts the browser's device picker for any Samsung device in normal mode (for AT reboot).
#[wasm_bindgen]
pub async fn pair_samsung_device(backend_str: Option<String>) -> Result<(), JsValue> {
    let backend = parse_backend(backend_str.as_deref())?;
    request_reboot_device(backend).await.map_err(to_js_err)
}

/// Detects a Download Mode device and queries DVIF device info.
#[wasm_bindgen]
pub async fn detect_download_device(
    backend_str: Option<String>,
    wait: bool,
) -> Result<String, JsValue> {
    let backend = parse_backend(backend_str.as_deref())?;
    let mut connection = OdinConnection::open(backend, wait)
        .await
        .map_err(to_js_err)?;

    match connection.query_device_info().await {
        Ok(info) => Ok(format!("Device detected (Download mode)\n{info}")),
        Err(_) => Ok("Device detected (Download mode)".to_string()),
    }
}

/// Reboots a normal-mode/AT-mode Samsung device into Download Mode using `AT+SUDDLMOD=0,0\r`.
/// Returns `true` if the AT reboot command was sent, or `false` if the device is already in Download Mode.
#[wasm_bindgen]
pub async fn reboot_to_download_at(backend_str: Option<String>) -> Result<bool, JsValue> {
    let backend = parse_backend(backend_str.as_deref())?;
    match reboot_download(backend).await.map_err(to_js_err)? {
        DownloadModeReboot::Sent => Ok(true),
        DownloadModeReboot::AlreadyInDownloadMode => Ok(false),
    }
}

/// Opens an Odin session on a Download Mode device and reboots it (`download` or `normal`).
#[wasm_bindgen]
pub async fn reboot_from_odin(
    backend_str: Option<String>,
    reboot_mode: String,
    wait: bool,
) -> Result<(), JsValue> {
    let backend = parse_backend(backend_str.as_deref())?;
    let mode = parse_reboot_mode(&reboot_mode);

    let mut session = OdinSession::connect(backend, wait)
        .await
        .map_err(to_js_err)?;
    session.finish(mode).await.map_err(to_js_err)
}

/// Connects to a Download Mode device, downloads its PIT, and applies `reboot_mode`.
///
/// Returns `{ text, data }`: the formatted PIT table and the raw PIT bytes as a `Uint8Array`.
#[wasm_bindgen]
pub async fn print_pit(
    backend_str: Option<String>,
    reboot_mode: String,
    wait: bool,
) -> Result<JsValue, JsValue> {
    let backend = parse_backend(backend_str.as_deref())?;
    let mode = parse_reboot_mode(&reboot_mode);

    let mut session = OdinSession::connect(backend, wait)
        .await
        .map_err(to_js_err)?;

    let pit_res = match session.receive_pit_info().await {
        Ok(pit_bytes) => PitData::new(&pit_bytes)
            .map(|pit_data| (pit_data, pit_bytes))
            .map_err(|e| JsValue::from_str(&format!("Failed to unpack device's PIT file: {e}"))),
        Err(e) => Err(to_js_err(e)),
    };

    let finish_res = session.finish(mode).await.map_err(to_js_err);
    let (pit_data, pit_bytes) = pit_res?;
    finish_res?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"text".into(), &format!("{pit_data}").into())?;
    js_sys::Reflect::set(
        &obj,
        &"data".into(),
        &js_sys::Uint8Array::from(pit_bytes.as_slice()).into(),
    )?;
    Ok(obj.into())
}

/// Verifies the trailing MD5 checksum appended to `.tar.md5` package files using `samloader_odin`.
#[wasm_bindgen]
pub async fn verify_package_md5(file: JsValue) -> Result<(), JsValue> {
    let reader = extract_reader_from_js(&file)?;
    let filename =
        extract_explicit_name_from_js(&file).unwrap_or_else(|| "package.tar.md5".to_string());
    verify_md5_footer(reader, &filename)
        .await
        .map_err(to_js_err)
}

fn get_bool_option(options: &js_sys::Object, key: &str, default: bool) -> bool {
    js_sys::Reflect::get(options, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}

fn get_skip_option(options: &js_sys::Object) -> Vec<String> {
    let Ok(val) = js_sys::Reflect::get(options, &JsValue::from_str("skip")) else {
        return Vec::new();
    };
    if js_sys::Array::is_array(&val) {
        let arr: js_sys::Array = val.unchecked_into();
        arr.iter()
            .filter_map(|v| v.as_string())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else if let Some(s) = val.as_string() {
        s.split(',')
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect()
    } else {
        Vec::new()
    }
}

/// Odin package slots, in the order the CLI passes them to `FlashRequest::packages`.
const PACKAGE_SLOTS: [&str; 5] = ["BL", "AP", "CP", "CSC", "USERDATA"];
/// Input key for the PIT file.
const PIT_SLOT: &str = "PIT";
/// Input key for the array of individual partition images.
const PARTITIONS_KEY: &str = "partitions";

/// Returns the value of `key` in `obj`, or `None` if it is missing, `null` or `undefined`.
fn get_present(obj: &js_sys::Object, key: &str) -> Result<Option<JsValue>, JsValue> {
    let val = js_sys::Reflect::get(obj, &JsValue::from_str(key))?;
    Ok((!val.is_null() && !val.is_undefined()).then_some(val))
}

/// A validated flash, ready to be executed on a device. Created by [`prepare_flash`].
#[wasm_bindgen]
pub struct FlashJob {
    prepared: PreparedFlash<JsReader, JsReader>,
    erase: bool,
}

#[wasm_bindgen]
impl FlashJob {
    /// Returns whether the flash list writes userdata, which wipes the device's data.
    pub fn flashes_userdata(&self) -> bool {
        self.prepared.flashes_userdata()
    }

    /// Returns whether a NAND erase of USERDATA was requested, which wipes the device's data.
    pub fn erases_userdata(&self) -> bool {
        self.erase
    }

    /// Connects to a Samsung Download Mode device and executes the flash, consuming the job.
    pub async fn execute(self, backend_str: Option<String>, wait: bool) -> Result<(), JsValue> {
        let backend = parse_backend(backend_str.as_deref())?;
        let mut session = OdinSession::connect(backend, wait)
            .await
            .map_err(to_js_err)?;
        self.prepared.execute(&mut session).await.map_err(to_js_err)
    }
}

/// Validates and indexes firmware package files without connecting to a device.
#[wasm_bindgen]
pub async fn prepare_flash(
    files: js_sys::Object,
    options: js_sys::Object,
) -> Result<FlashJob, JsValue> {
    let reboot_str = js_sys::Reflect::get(&options, &JsValue::from_str("reboot"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| "normal".to_string());
    let reboot_mode = parse_reboot_mode(&reboot_str);

    let erase = get_bool_option(&options, "erase", false);
    let disable_verity = get_bool_option(&options, "disable_verity", false);
    let disable_verification = get_bool_option(&options, "disable_verification", false);
    let skip_size_check = get_bool_option(&options, "skip_size_check", false);
    let skip_targets = get_skip_option(&options);

    let sales_code = js_sys::Reflect::get(&options, &JsValue::from_str("sales_code"))
        .ok()
        .and_then(|v| v.as_string())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Like the CLI, the slot alone decides how an input is used: package slots are
    // always TAR packages (`--bl`, `--ap`, ...), the PIT slot is always the PIT
    // (`--pit`), and `partitions` are always raw images (`-p` / `-f`).
    for key in js_sys::Object::keys(&files).iter() {
        let key = key.as_string().unwrap_or_default();
        if !PACKAGE_SLOTS.contains(&key.as_str()) && key != PIT_SLOT && key != PARTITIONS_KEY {
            return Err(JsValue::from_str(&format!("Unknown flash input \"{key}\"")));
        }
    }

    let mut packages_vec: Vec<(String, JsReader)> = Vec::new();
    for slot in PACKAGE_SLOTS {
        if let Some(val) = get_present(&files, slot)? {
            let name = extract_explicit_name_from_js(&val).unwrap_or_else(|| slot.to_string());
            packages_vec.push((name, extract_reader_from_js(&val)?));
        }
    }

    let mut pit_bytes: Option<Vec<u8>> = None;
    if let Some(val) = get_present(&files, PIT_SLOT)? {
        let mut bytes = Vec::new();
        extract_reader_from_js(&val)?
            .read_to_end(&mut bytes)
            .await
            .map_err(to_js_err)?;
        pit_bytes = Some(bytes);
    }

    let mut partitions_vec: Vec<(Option<String>, String, JsReader)> = Vec::new();
    if let Some(val) = get_present(&files, PARTITIONS_KEY)? {
        if !js_sys::Array::is_array(&val) {
            return Err(JsValue::from_str("\"partitions\" must be an array"));
        }
        let arr: js_sys::Array = val.unchecked_into();
        for entry_js in arr.iter() {
            if entry_js.is_null() || entry_js.is_undefined() {
                continue;
            }
            let reader = extract_reader_from_js(&entry_js)?;
            let filename = extract_explicit_name_from_js(&entry_js)
                .ok_or_else(|| JsValue::from_str("Partition entry is missing a filename"))?;
            let target_partition = extract_explicit_partition_from_js(&entry_js);
            partitions_vec.push((target_partition, filename, reader));
        }
    }

    let mut req = FlashRequest::new()
        .erase(erase)
        .reboot_mode(reboot_mode)
        .disable_verity(disable_verity)
        .disable_verification(disable_verification)
        .skip_size_check(skip_size_check)
        .skip(&skip_targets)
        .sales_code(sales_code.as_deref());

    if let Some(pit) = pit_bytes {
        req = req.pit(pit);
    }

    let prepared = req
        .packages(packages_vec)
        .partitions(partitions_vec)
        .prepare()
        .await
        .map_err(to_js_err)?;

    Ok(FlashJob { prepared, erase })
}
