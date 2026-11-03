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

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::io::{AsyncRead, AsyncReadExt, AsyncSeek, Cursor};
use js_sys::Function;
use samloader_odin::{
    DownloadModeReboot, FlashEvent, FlashProgress, FlashRequest, OdinConnection, OdinSession,
    PreparedFlash, RebootMode, UsbBackendOption, clear_progress, reboot_download, request_device,
    request_reboot_device, set_progress, verify_md5_footer,
};
use samloader_pit::PitData;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const BLOB_STREAM_CHUNK_SIZE: u64 = 8 * 1024 * 1024; // 8 MiB read-ahead for sequential streaming
const BLOB_SMALL_CHUNK_SIZE: u64 = 64 * 1024; // 64 KiB read-ahead for small random-access reads

type ReadChunkFuture = Pin<Box<dyn Future<Output = io::Result<(u64, Vec<u8>)>>>>;

struct BlobReader {
    blob: web_sys::Blob,
    size: u64,
    pos: u64,
    sequential: u64,
    buf: Vec<u8>,
    buf_start: u64,
    pending_read: Option<ReadChunkFuture>,
}

impl BlobReader {
    fn new(blob: web_sys::Blob) -> Self {
        let size = blob.size() as u64;
        Self {
            blob,
            size,
            pos: 0,
            sequential: 0,
            buf: Vec::new(),
            buf_start: 0,
            pending_read: None,
        }
    }
}

impl AsyncSeek for BlobReader {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        let next_pos = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.size.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        };

        let Some(new_pos) = next_pos else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            )));
        };

        if new_pos != self.pos {
            self.pos = new_pos;
            self.sequential = 0;
            self.pending_read = None;
        }

        Poll::Ready(Ok(self.pos))
    }
}

impl AsyncRead for BlobReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.pos >= self.size || out.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let buf_end = self.buf_start + self.buf.len() as u64;
        if self.pos >= self.buf_start && self.pos < buf_end {
            let offset = (self.pos - self.buf_start) as usize;
            let available = self.buf.len() - offset;
            let to_copy = out.len().min(available);
            out[..to_copy].copy_from_slice(&self.buf[offset..offset + to_copy]);
            self.pos += to_copy as u64;
            self.sequential += to_copy as u64;
            return Poll::Ready(Ok(to_copy));
        }

        if self.pending_read.is_none() {
            let start = self.pos;
            let chunk_len = if self.sequential + out.len() as u64 >= BLOB_SMALL_CHUNK_SIZE {
                (out.len() as u64).max(BLOB_STREAM_CHUNK_SIZE)
            } else {
                BLOB_SMALL_CHUNK_SIZE
            };
            let end = (start + chunk_len).min(self.size);
            let slice = match self.blob.slice_with_f64_and_f64(start as f64, end as f64) {
                Ok(s) => s,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::other(format!("Blob.slice failed: {e:?}"))));
                }
            };
            let promise = slice.array_buffer();
            let fut = async move {
                let ab = JsFuture::from(promise)
                    .await
                    .map_err(|e| io::Error::other(format!("Blob.arrayBuffer failed: {e:?}")))?;
                let uint8_arr = js_sys::Uint8Array::new(&ab);
                Ok((start, uint8_arr.to_vec()))
            };
            self.pending_read = Some(Box::pin(fut));
        }

        let res = match self.pending_read.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(res) => res,
        };
        self.pending_read = None;

        let (start, data) = res?;
        self.buf_start = start;
        self.buf = data;

        if self.buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let to_copy = out.len().min(self.buf.len());
        out[..to_copy].copy_from_slice(&self.buf[..to_copy]);
        self.pos += to_copy as u64;
        self.sequential += to_copy as u64;
        Poll::Ready(Ok(to_copy))
    }
}

enum JsReader {
    Blob(BlobReader),
    Memory(Cursor<Vec<u8>>),
}

impl AsyncRead for JsReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Blob(r) => Pin::new(r).poll_read(cx, buf),
            Self::Memory(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

impl AsyncSeek for JsReader {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        match &mut *self {
            Self::Blob(r) => Pin::new(r).poll_seek(cx, pos),
            Self::Memory(r) => Pin::new(r).poll_seek(cx, pos),
        }
    }
}

const LOG_LINE_HEIGHT: f64 = 20.0;
const LOG_OVERSCAN: usize = 20;
const INITIAL_LOG_BANNER: &str = "-- samloader-rs Odin Web Flasher Initialized --";
const CLEARED_LOG_BANNER: &str = "-- Log Cleared --";

thread_local! {
    static PROGRESS: &'static WebProgress = Box::leak(Box::new(WebProgress::new()));
}

struct WebProgress {
    verbose: Cell<bool>,
    log_cb: RefCell<Option<Function>>,
    lines: RefCell<Vec<String>>,
    rendered_start: Cell<usize>,
    rendered_end: Cell<usize>,
    rendered_total: Cell<usize>,
    log_dirty: Cell<bool>,
    total_bytes: Cell<u64>,
    current_bytes: Cell<u64>,
    last_percent: Cell<Option<u32>>,
    current_partition: RefCell<String>,
}

impl WebProgress {
    fn new() -> Self {
        Self {
            verbose: Cell::new(false),
            log_cb: RefCell::new(None),
            lines: RefCell::new(vec![INITIAL_LOG_BANNER.to_string()]),
            rendered_start: Cell::new(usize::MAX),
            rendered_end: Cell::new(usize::MAX),
            rendered_total: Cell::new(usize::MAX),
            log_dirty: Cell::new(false),
            total_bytes: Cell::new(0),
            current_bytes: Cell::new(0),
            last_percent: Cell::new(None),
            current_partition: RefCell::new(String::new()),
        }
    }

    fn notify_log_dirty(&self) {
        // Coalesce log notifications so JS only schedules a single animation frame
        // per frame regardless of how many log lines are pushed in a burst.
        if !self.log_dirty.replace(true)
            && let Some(cb) = self.log_cb.borrow().as_ref()
        {
            let obj = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&obj, &"type".into(), &"log".into());
            let _ = cb.call1(&JsValue::NULL, &obj);
        }
    }

    fn push_log(&self, msg: &str) {
        let now = js_sys::Date::new_0();
        let hours = now.get_hours();
        let mins = now.get_minutes();
        let secs = now.get_seconds();

        {
            let mut lines = self.lines.borrow_mut();
            let mut parts = msg.split('\n');
            if let Some(first) = parts.next() {
                lines.push(format!("[{hours:02}:{mins:02}:{secs:02}] {first}"));
                for part in parts {
                    lines.push(part.to_string());
                }
            }
        }

        self.notify_log_dirty();
    }

    fn push_raw_lines(&self, raw_lines: Vec<String>) {
        if raw_lines.is_empty() {
            return;
        }
        self.lines.borrow_mut().extend(raw_lines);
        self.notify_log_dirty();
    }

    fn clear_logs(&self) {
        {
            let mut lines = self.lines.borrow_mut();
            lines.clear();
            lines.push(CLEARED_LOG_BANNER.to_string());
        }
        self.rendered_start.set(usize::MAX);
        self.rendered_end.set(usize::MAX);
        self.rendered_total.set(usize::MAX);
        self.log_dirty.set(false);
    }

    fn take_logs(&self) -> Vec<String> {
        self.log_dirty.set(false);
        std::mem::take(&mut *self.lines.borrow_mut())
    }

    fn render_viewport(
        &self,
        scroll_top: f64,
        viewport_height: f64,
        stick_to_bottom: bool,
    ) -> JsValue {
        self.log_dirty.set(false);

        let lines = self.lines.borrow();
        let total_lines = lines.len();
        let total_height = (total_lines as f64) * LOG_LINE_HEIGHT;
        let vh = if viewport_height > 0.0 {
            viewport_height
        } else {
            220.0
        };

        let effective_scroll_top = if stick_to_bottom {
            (total_height - vh).max(0.0)
        } else {
            scroll_top.max(0.0)
        };

        let first_visible = (effective_scroll_top / LOG_LINE_HEIGHT).floor() as usize;
        let visible_count = (vh / LOG_LINE_HEIGHT).ceil() as usize;
        let start_index = first_visible.saturating_sub(LOG_OVERSCAN).min(total_lines);
        let end_index = (first_visible + visible_count + LOG_OVERSCAN).min(total_lines);

        let height_changed = self.rendered_total.replace(total_lines) != total_lines;
        let slice_changed =
            start_index != self.rendered_start.get() || end_index != self.rendered_end.get();

        if !height_changed && !slice_changed {
            return JsValue::NULL;
        }

        let should_scroll_to_bottom = stick_to_bottom && height_changed;
        let obj = js_sys::Object::new();
        if height_changed {
            let _ = js_sys::Reflect::set(&obj, &"totalHeight".into(), &total_height.into());
        }
        if slice_changed {
            self.rendered_start.set(start_index);
            self.rendered_end.set(end_index);
            let padding_top = (start_index as f64) * LOG_LINE_HEIGHT;
            let text = lines[start_index..end_index].join("\n");
            let _ = js_sys::Reflect::set(&obj, &"paddingTop".into(), &padding_top.into());
            let _ = js_sys::Reflect::set(&obj, &"text".into(), &text.into());
        }
        let _ = js_sys::Reflect::set(
            &obj,
            &"scrollToBottom".into(),
            &should_scroll_to_bottom.into(),
        );
        obj.into()
    }

    fn emit_log(&self, msg: &str) {
        self.push_log(msg);
    }

    fn emit_progress(&self, force: bool) {
        let Some(cb) = self.log_cb.borrow().clone() else {
            return;
        };

        let total = self.total_bytes.get();
        let curr = self.current_bytes.get();
        let percent = (curr * 100)
            .checked_div(total)
            .map(|p| std::cmp::min(100, p) as u32)
            .unwrap_or(0);

        if !force && self.last_percent.get() == Some(percent) && curr < total {
            return;
        }
        self.last_percent.set(Some(percent));

        let obj = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&obj, &"type".into(), &"progress".into());
        let _ = js_sys::Reflect::set(&obj, &"percent".into(), &percent.into());
        let _ = js_sys::Reflect::set(&obj, &"current".into(), &(curr as f64).into());
        let _ = js_sys::Reflect::set(&obj, &"total".into(), &(total as f64).into());
        let _ = js_sys::Reflect::set(
            &obj,
            &"partition".into(),
            &self.current_partition.borrow().as_str().into(),
        );

        let _ = cb.call1(&JsValue::NULL, &obj);
    }
}

impl FlashProgress for WebProgress {
    fn set_length(&self, len: u64) {
        self.total_bytes.set(len);
        self.current_bytes.set(0);
        if self.last_percent.get() != Some(0) {
            self.last_percent.set(None);
            self.emit_progress(true);
        }
    }

    fn inc(&self, bytes: u64) {
        self.current_bytes.set(self.current_bytes.get() + bytes);
        self.emit_progress(false);
    }

    fn on_event(&self, event: FlashEvent<'_>) {
        match event {
            FlashEvent::WaitingForDevice => {
                self.emit_log("Waiting for device...");
            }
            FlashEvent::HandshakeStart => {
                self.emit_log("Starting Odin handshake...");
            }
            FlashEvent::HandshakeEnd => {
                self.emit_log("Odin handshake successful.");
            }
            FlashEvent::SessionStart => {
                self.emit_log("Requesting Odin session...");
            }
            FlashEvent::SessionSetup => {
                self.emit_log("Setting up Odin session...");
            }
            FlashEvent::SessionReady => {
                self.emit_log("Odin session ready.");
            }
            FlashEvent::SessionEnd => {
                self.emit_log("Ending Odin session...");
            }
            FlashEvent::Reboot { download } => {
                let target = if download {
                    "Download mode"
                } else {
                    "normal mode"
                };
                self.emit_log(&format!("Rebooting device to {target}..."));
            }
            FlashEvent::EraseStart => {
                self.emit_log("Erasing USERDATA partition...");
            }
            FlashEvent::EraseEnd { sectors } => {
                self.emit_log(&format!("USERDATA partition erased ({sectors} sectors)."));
            }
            FlashEvent::PartitionStart { name, size } => {
                *self.current_partition.borrow_mut() = name.to_string();
                self.current_bytes.set(0);
                self.total_bytes.set(size);
                self.last_percent.set(None);
                self.emit_log(&format!("Flashing {name} ({size} bytes)..."));
                self.emit_progress(true);
            }
            FlashEvent::PartitionEnd(name) => {
                self.current_partition.borrow_mut().clear();
                self.emit_log(&format!("Finished flashing {name}."));
            }
            FlashEvent::PartitionFail(name) => {
                self.current_partition.borrow_mut().clear();
                self.emit_log(&format!("Failed flashing {name}!"));
            }
            FlashEvent::Md5Start { name, size } => {
                *self.current_partition.borrow_mut() = name.to_string();
                self.current_bytes.set(0);
                self.total_bytes.set(size);
                self.last_percent.set(None);
                self.emit_log(&format!("Verifying MD5 for {name} ({size} bytes)..."));
                self.emit_progress(true);
            }
            FlashEvent::Md5End(name) => {
                self.current_partition.borrow_mut().clear();
                self.emit_log(&format!("MD5 verified for {name}."));
            }
            FlashEvent::Md5Fail(name) => {
                self.current_partition.borrow_mut().clear();
                self.emit_log(&format!("MD5 verification failed for {name}!"));
            }
            _ => {}
        }
    }

    fn println(&self, msg: &str) {
        self.emit_log(msg);
    }

    fn is_verbose(&self) -> bool {
        self.verbose.get()
    }
}

/// Registers the thread-local JavaScript callback for receiving log and progress notifications.
#[wasm_bindgen]
pub fn set_progress_callback(log_cb: Function) {
    let progress = PROGRESS.with(|&p| p);
    *progress.log_cb.borrow_mut() = Some(log_cb);
    set_progress(progress);
}

/// Clears the thread-local progress reporter.
#[wasm_bindgen]
pub fn clear_progress_callback() {
    let progress = PROGRESS.with(|&p| p);
    *progress.log_cb.borrow_mut() = None;
    clear_progress();
}

/// Sets whether verbose log messages are emitted by the active progress reporter.
#[wasm_bindgen]
pub fn set_verbose(verbose: bool) {
    PROGRESS.with(|&p| p.verbose.set(verbose));
}

/// Appends a timestamped log message to the Rust log buffer and schedules a dirty notification.
#[wasm_bindgen]
pub fn append_log(msg: &str) {
    PROGRESS.with(|&p| p.push_log(msg));
}

/// Appends pre-formatted log lines (e.g. from a Web Worker) to the Rust log buffer.
#[wasm_bindgen]
pub fn append_raw_logs(lines: Vec<String>) {
    PROGRESS.with(|&p| p.push_raw_lines(lines));
}

/// Clears the Rust log buffer and resets virtual viewport tracking.
#[wasm_bindgen]
pub fn clear_log() {
    PROGRESS.with(|&p| p.clear_logs());
}

/// Drains buffered log lines from the current thread's progress reporter (used by Web Workers).
#[wasm_bindgen]
pub fn take_logs() -> Vec<String> {
    PROGRESS.with(|&p| p.take_logs())
}

/// Computes the visible virtualized log viewport slice for the given scroll position.
#[wasm_bindgen]
pub fn render_log_viewport(
    scroll_top: f64,
    viewport_height: f64,
    stick_to_bottom: bool,
) -> JsValue {
    PROGRESS.with(|&p| p.render_viewport(scroll_top, viewport_height, stick_to_bottom))
}

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

fn extract_reader_from_js(val: &JsValue) -> Result<JsReader, JsValue> {
    if let Some(blob) = val.dyn_ref::<web_sys::Blob>() {
        return Ok(JsReader::Blob(BlobReader::new(blob.clone())));
    }
    if val.is_instance_of::<js_sys::Uint8Array>() {
        let uint8_arr: js_sys::Uint8Array = val.clone().unchecked_into();
        return Ok(JsReader::Memory(Cursor::new(uint8_arr.to_vec())));
    }
    if val.is_instance_of::<js_sys::ArrayBuffer>() {
        let uint8_arr = js_sys::Uint8Array::new(val);
        return Ok(JsReader::Memory(Cursor::new(uint8_arr.to_vec())));
    }
    if val.is_object() {
        let obj: &js_sys::Object = val.unchecked_ref();
        for key in ["file", "blob", "data"] {
            if let Ok(inner) = js_sys::Reflect::get(obj, &JsValue::from_str(key))
                && !inner.is_undefined()
                && !inner.is_null()
            {
                if let Some(blob) = inner.dyn_ref::<web_sys::Blob>() {
                    return Ok(JsReader::Blob(BlobReader::new(blob.clone())));
                }
                if inner.is_instance_of::<js_sys::Uint8Array>() {
                    let uint8_arr: js_sys::Uint8Array = inner.unchecked_into();
                    return Ok(JsReader::Memory(Cursor::new(uint8_arr.to_vec())));
                }
                if inner.is_instance_of::<js_sys::ArrayBuffer>() {
                    let uint8_arr = js_sys::Uint8Array::new(&inner);
                    return Ok(JsReader::Memory(Cursor::new(uint8_arr.to_vec())));
                }
            }
        }
        return Err(JsValue::from_str("Invalid file data object property"));
    }
    Err(JsValue::from_str(
        "Expected File, Blob, Uint8Array, ArrayBuffer, or file object",
    ))
}

fn extract_explicit_name_from_js(val: &JsValue) -> Option<String> {
    if let Some(file) = val.dyn_ref::<web_sys::File>() {
        let name = file.name();
        if !name.is_empty() {
            return Some(name);
        }
    }
    if val.is_object() {
        let obj: &js_sys::Object = val.unchecked_ref();
        if let Some(s) = js_sys::Reflect::get(obj, &JsValue::from_str("name"))
            .ok()
            .and_then(|v| v.as_string())
            .filter(|s| !s.is_empty())
        {
            return Some(s);
        }
        if let Ok(inner) = js_sys::Reflect::get(obj, &JsValue::from_str("file"))
            && let Some(file) = inner.dyn_ref::<web_sys::File>()
        {
            let name = file.name();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

fn extract_explicit_partition_from_js(val: &JsValue) -> Option<String> {
    if val.is_object() {
        let obj: &js_sys::Object = val.unchecked_ref();
        if let Some(s) = js_sys::Reflect::get(obj, &JsValue::from_str("partition"))
            .ok()
            .and_then(|v| v.as_string())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return Some(s);
        }
    }
    None
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

/// Connects to a Download Mode device, downloads and formats its PIT table, and applies `reboot_mode`.
#[wasm_bindgen]
pub async fn print_pit(
    backend_str: Option<String>,
    reboot_mode: String,
    wait: bool,
) -> Result<String, JsValue> {
    let backend = parse_backend(backend_str.as_deref())?;
    let mode = parse_reboot_mode(&reboot_mode);

    let mut session = OdinSession::connect(backend, wait)
        .await
        .map_err(to_js_err)?;

    let pit_res = match session.receive_pit_info().await {
        Ok(pit_bytes) => PitData::new(&pit_bytes)
            .map(|pit_data| format!("{pit_data}"))
            .map_err(|e| JsValue::from_str(&format!("Failed to unpack device's PIT file: {e}"))),
        Err(e) => Err(to_js_err(e)),
    };

    let finish_res = session.finish(mode).await.map_err(to_js_err);
    let formatted_pit = pit_res?;
    finish_res?;

    Ok(formatted_pit)
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

fn slot_sort_rank(key: &str) -> usize {
    match key.to_ascii_uppercase().as_str() {
        "PIT" => 0,
        "BL" => 1,
        "AP" => 2,
        "CP" => 3,
        "CSC" => 4,
        "USERDATA" => 5,
        _ => 6,
    }
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

    let keys = js_sys::Object::keys(&files);
    let mut ordered_keys: Vec<(usize, String, JsValue)> = (0..keys.length())
        .map(|i| {
            let key_js = keys.get(i);
            let key_str = key_js.as_string().unwrap_or_default();
            (i as usize, key_str, key_js)
        })
        .collect();
    ordered_keys.sort_by_key(|(idx, key, _)| (slot_sort_rank(key), *idx));

    let mut packages_vec: Vec<(String, JsReader)> = Vec::new();
    let mut partitions_vec: Vec<(Option<String>, String, JsReader)> = Vec::new();
    let mut pit_bytes: Option<Vec<u8>> = None;

    for (_, key_str, key_js) in ordered_keys {
        let val_js = js_sys::Reflect::get(&files, &key_js)?;

        if val_js.is_null() || val_js.is_undefined() {
            continue;
        }

        if key_str.eq_ignore_ascii_case("partitions") && js_sys::Array::is_array(&val_js) {
            let arr: js_sys::Array = val_js.unchecked_into();
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
            continue;
        }

        let mut reader = extract_reader_from_js(&val_js)?;
        let explicit_name = extract_explicit_name_from_js(&val_js);
        let filename = explicit_name.clone().unwrap_or_else(|| key_str.clone());
        let lower_filename = filename.to_lowercase();
        let upper_key = key_str.to_uppercase();
        let is_package_slot = ["BL", "AP", "CP", "CSC", "USERDATA"].contains(&upper_key.as_str());

        if upper_key == "PIT" || lower_filename.ends_with(".pit") {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.map_err(to_js_err)?;
            pit_bytes = Some(bytes);
        } else if lower_filename.ends_with(".tar")
            || lower_filename.ends_with(".tar.md5")
            || (explicit_name.is_none() && is_package_slot)
        {
            packages_vec.push((filename, reader));
        } else {
            let target_partition = extract_explicit_partition_from_js(&val_js).or_else(|| {
                if !is_package_slot
                    && explicit_name.is_some()
                    && !key_str.is_empty()
                    && !key_str.eq_ignore_ascii_case(&filename)
                {
                    Some(key_str)
                } else {
                    None
                }
            });
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
