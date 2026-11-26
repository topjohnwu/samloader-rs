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

//! Samsung FUS (Firmware Update Server) WASM bindings for history lookup,
//! archive inspection, and parallel resumable downloads.

use crate::http::JsHttpClient;
use crate::storage::{DownloadStorage, DownloadTarget, PartHandle};
use crate::{js_obj, to_js_err};
use futures::channel::oneshot;
use futures::future::{Either, FutureExt, Shared, select, try_join_all};
use futures::io::AsyncReadExt;
use samloader_fus::{
    Checkpoint, CheckpointMeta, CheckpointState, DataSource, DataStream, FusClient, OdinComponent,
    ParallelDataSource, ResumableAsyncRead, ResumableStream, TransferObserver, TransferWarning,
    ZipArchive, ZipEntry,
};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use web_sys::AbortSignal;

const CHECKPOINT_INTERVAL: u64 = 128 * 1024 * 1024;
const CHECKPOINT_MAX_WAIT_MS: f64 = 15_000.0;
const WRITE_BUF_SIZE: usize = 2 * 1024 * 1024;
const COALESCE_MAX_WAIT_MS: f64 = 250.0;
const PROGRESS_THROTTLE_MS: f64 = 100.0;
const SPEED_WINDOW_MS: f64 = 3000.0;
const SPEED_SAMPLE_INTERVAL_MS: f64 = 250.0;
const DEFAULT_CONCURRENCY: usize = 6;
const MIN_CONCURRENCY: usize = 1;
const MAX_CONCURRENCY: usize = 6;
const CANCELLED_ERR: &str = "Download cancelled";

fn component_to_js(name: &str) -> JsValue {
    match OdinComponent::from_entry_name(name) {
        Some(c) => JsValue::from_str(c.key()),
        None => JsValue::NULL,
    }
}

fn format_hex_16(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadMode {
    Zip,
    Entries,
}

/// Options for [`fus_download`]. Constructed in JavaScript with `new FusDownloadOptions()`
/// and set field by field.
#[wasm_bindgen]
#[derive(Default)]
pub struct FusDownloadOptions {
    /// Device model (e.g. `"SM-S931U1"`).
    #[wasm_bindgen(getter_with_clone)]
    pub model: Option<String>,
    /// Region / CSC code (e.g. `"XAA"`).
    #[wasm_bindgen(getter_with_clone)]
    pub region: Option<String>,
    /// Firmware version string (`PDA/CSC/CP` or `PDA/CSC/CP/BL`).
    #[wasm_bindgen(getter_with_clone)]
    pub version: Option<String>,
    /// Download mode: `"zip"` or `"entries"`.
    #[wasm_bindgen(getter_with_clone)]
    pub mode: Option<String>,
    /// Optional list of archive entry names to extract when `mode` is `"entries"`.
    #[wasm_bindgen(getter_with_clone, js_name = entryNames)]
    pub entry_names: Option<Vec<String>>,
    /// Parallel HTTP connection count (clamped to `1..=6`, defaults to `6`).
    pub concurrency: Option<f64>,
    /// Overwrites existing complete files and discards any partial download.
    pub force: bool,
}

#[wasm_bindgen]
impl FusDownloadOptions {
    /// Creates options with every setting at its default.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
}

struct ParsedDownloadOptions {
    model: String,
    region: String,
    version: String,
    mode: DownloadMode,
    entry_names: Option<Vec<String>>,
    concurrency: usize,
    force: bool,
}

fn parse_required_str(val: Option<&str>, name: &str) -> Result<String, JsValue> {
    let raw = val.ok_or_else(|| JsValue::from_str(&format!("Missing required '{name}'")))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(JsValue::from_str(&format!(
            "Parameter '{name}' must not be empty"
        )));
    }
    Ok(trimmed.to_string())
}

impl ParsedDownloadOptions {
    fn from_options(opts: FusDownloadOptions) -> Result<Self, JsValue> {
        let model = parse_required_str(opts.model.as_deref(), "model")?;
        let region = parse_required_str(opts.region.as_deref(), "region")?;
        let version = parse_required_str(opts.version.as_deref(), "version")?;
        let mode = match parse_required_str(opts.mode.as_deref(), "mode")?.as_str() {
            "zip" => DownloadMode::Zip,
            "entries" => DownloadMode::Entries,
            other => {
                return Err(JsValue::from_str(&format!(
                    "Invalid download mode '{other}'; expected 'zip' or 'entries'"
                )));
            }
        };
        let concurrency = match opts.concurrency {
            Some(n) => {
                if !n.is_finite() {
                    return Err(JsValue::from_str(
                        "Parameter 'concurrency' must be a finite number",
                    ));
                }
                (n.round() as i64).clamp(MIN_CONCURRENCY as i64, MAX_CONCURRENCY as i64) as usize
            }
            None => DEFAULT_CONCURRENCY,
        };
        Ok(Self {
            model,
            region,
            version,
            mode,
            entry_names: opts.entry_names,
            concurrency,
            force: opts.force,
        })
    }
}

struct CancelWatcher {
    signal: Option<AbortSignal>,
    cancelled: Option<Shared<oneshot::Receiver<()>>>,
    listener: Option<Closure<dyn FnMut()>>,
}

impl CancelWatcher {
    fn new(signal: Option<AbortSignal>) -> Result<Self, JsValue> {
        let mut cancelled = None;
        let mut listener = None;

        if let Some(sig) = &signal
            && !sig.aborted()
        {
            let (tx, rx) = oneshot::channel();
            let mut tx = Some(tx);
            let closure = Closure::<dyn FnMut()>::new(move || {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(());
                }
            });
            sig.add_event_listener_with_callback("abort", closure.as_ref().unchecked_ref())?;
            cancelled = Some(rx.shared());
            listener = Some(closure);
        }

        Ok(Self {
            signal,
            cancelled,
            listener,
        })
    }

    fn is_cancelled(&self) -> bool {
        self.signal.as_ref().is_some_and(AbortSignal::aborted)
    }

    async fn run<T>(&self, fut: impl Future<Output = T>) -> Result<T, ()> {
        if self.is_cancelled() {
            return Err(());
        }
        let Some(cancelled) = &self.cancelled else {
            return Ok(fut.await);
        };
        match select(cancelled.clone(), pin!(fut)).await {
            Either::Left(_) => Err(()),
            Either::Right((val, _)) => Ok(val),
        }
    }
}

impl Drop for CancelWatcher {
    fn drop(&mut self) {
        if let (Some(sig), Some(listener)) = (&self.signal, self.listener.take()) {
            let _ =
                sig.remove_event_listener_with_callback("abort", listener.as_ref().unchecked_ref());
        }
    }
}

async fn run_cancellable<T, E: std::fmt::Display>(
    cancel: &CancelWatcher,
    fut: impl Future<Output = Result<T, E>>,
) -> Result<T, JsValue> {
    cancel
        .run(fut)
        .await
        .map_err(|()| JsValue::from_str(CANCELLED_ERR))?
        .map_err(to_js_err)
}

fn elapsed_at_least(now_ms: f64, last_ms: f64, threshold_ms: f64) -> bool {
    now_ms < last_ms || (now_ms - last_ms) >= threshold_ms
}

struct ProgressState {
    wire_bytes: Cell<u64>,
    session_out_bytes: Cell<u64>,
    samples: RefCell<VecDeque<(f64, u64, u64)>>,
    last_emit_ms: Cell<f64>,
    overall_base: Cell<u64>,
    overall_total: Cell<u64>,
    file_index: Cell<usize>,
    file_count: Cell<usize>,
    file_name: RefCell<String>,
    file_written: Cell<u64>,
    file_total: Cell<u64>,
    resumed: Cell<bool>,
    active: Cell<bool>,
    on_progress: js_sys::Function,
}

impl ProgressState {
    #[allow(clippy::arc_with_non_send_sync)]
    fn new_arc(file_count: usize, overall_total: u64, on_progress: js_sys::Function) -> Arc<Self> {
        Arc::new(Self {
            wire_bytes: Cell::new(0),
            session_out_bytes: Cell::new(0),
            samples: RefCell::new(VecDeque::with_capacity(16)),
            last_emit_ms: Cell::new(f64::NEG_INFINITY),
            overall_base: Cell::new(0),
            overall_total: Cell::new(overall_total),
            file_index: Cell::new(0),
            file_count: Cell::new(file_count),
            file_name: RefCell::new(String::new()),
            file_written: Cell::new(0),
            file_total: Cell::new(0),
            resumed: Cell::new(false),
            active: Cell::new(false),
            on_progress,
        })
    }

    fn start_file(
        &self,
        file_index: usize,
        file_name: &str,
        file_written: u64,
        file_total: u64,
        resumed: bool,
    ) {
        self.file_index.set(file_index);
        *self.file_name.borrow_mut() = file_name.to_string();
        self.file_written.set(file_written);
        self.file_total.set(file_total);
        self.resumed.set(resumed);
        self.active.set(true);
        self.emit_progress(true);
    }

    fn set_file_written(&self, written: u64, force: bool) {
        let prev = self.file_written.replace(written);
        self.session_out_bytes.set(
            self.session_out_bytes
                .get()
                .saturating_add(written.saturating_sub(prev)),
        );
        self.emit_progress(force);
    }

    fn finish_file(&self, file_index: usize, file_name: &str, skipped: bool, size: u64) {
        if !skipped {
            self.set_file_written(size, true);
        }
        self.active.set(false);
        let overall_written = self.overall_base.get().saturating_add(size);
        self.overall_base.set(overall_written);

        let obj = js_obj! {
            "type" => "file_done",
            "fileIndex" => file_index as f64,
            "fileCount" => self.file_count.get() as f64,
            "fileName" => file_name,
            "skipped" => skipped,
            "size" => size as f64,
            "overallWritten" => overall_written as f64,
            "overallTotal" => self.overall_total.get() as f64,
        };
        let _ = self.on_progress.call1(&JsValue::NULL, &obj);
    }

    fn compute_speeds(&self, now_ms: f64, wire_bytes: u64, session_out: u64) -> (f64, f64) {
        let mut samples = self.samples.borrow_mut();
        if samples.back().is_none_or(|&(last_t, _, _)| {
            elapsed_at_least(now_ms, last_t, SPEED_SAMPLE_INTERVAL_MS)
        }) {
            samples.push_back((now_ms, wire_bytes, session_out));
            while samples.len() > 2 && elapsed_at_least(now_ms, samples[1].0, SPEED_WINDOW_MS) {
                samples.pop_front();
            }
        }
        let Some(&(oldest_t, oldest_wire, oldest_out)) = samples.front() else {
            return (0.0, 0.0);
        };
        let dt_secs = (now_ms - oldest_t) / 1000.0;
        if dt_secs >= 0.25 {
            let wire_speed = wire_bytes.saturating_sub(oldest_wire) as f64 / dt_secs;
            let out_speed = session_out.saturating_sub(oldest_out) as f64 / dt_secs;
            (wire_speed, out_speed)
        } else {
            (0.0, 0.0)
        }
    }

    fn emit_progress(&self, force: bool) {
        if !self.active.get() {
            return;
        }
        let now = js_sys::Date::now();
        if !force && !elapsed_at_least(now, self.last_emit_ms.get(), PROGRESS_THROTTLE_MS) {
            return;
        }
        self.last_emit_ms.set(now);

        let file_written = self.file_written.get();
        let file_total = self.file_total.get();
        let overall_written = self.overall_base.get().saturating_add(file_written);
        let overall_total = self.overall_total.get();
        let wire_bytes = self.wire_bytes.get();
        let (wire_speed, out_speed) =
            self.compute_speeds(now, wire_bytes, self.session_out_bytes.get());

        let percent = if overall_total > 0 {
            (overall_written as f64 / overall_total as f64) * 100.0
        } else if file_total > 0 {
            (file_written as f64 / file_total as f64) * 100.0
        } else {
            0.0
        };
        let eta = |remaining: u64| {
            if out_speed > 1024.0 && remaining > 0 {
                JsValue::from_f64(remaining as f64 / out_speed)
            } else {
                JsValue::NULL
            }
        };

        let obj = {
            let file_name = self.file_name.borrow();
            js_obj! {
                "type" => "progress",
                "fileIndex" => self.file_index.get() as f64,
                "fileCount" => self.file_count.get() as f64,
                "fileName" => file_name.as_str(),
                "fileWritten" => file_written as f64,
                "fileTotal" => file_total as f64,
                "fileEtaSecs" => eta(file_total.saturating_sub(file_written)),
                "overallWritten" => overall_written as f64,
                "overallTotal" => overall_total as f64,
                "wireBytes" => wire_bytes as f64,
                "percent" => percent,
                "wireSpeed" => wire_speed,
                "etaSecs" => eta(overall_total.saturating_sub(overall_written)),
                "resumed" => self.resumed.get(),
            }
        };
        let _ = self.on_progress.call1(&JsValue::NULL, &obj);
    }
}

impl TransferObserver for ProgressState {
    fn on_bytes(&self, wire_bytes: u64, _net_bytes: u64) {
        self.wire_bytes
            .set(self.wire_bytes.get().saturating_add(wire_bytes));
        self.emit_progress(false);
    }

    fn on_warning(&self, warning: TransferWarning) {
        let msg = match warning {
            TransferWarning::Retry {
                offset,
                attempt,
                max_attempts,
                error,
            } => format!(
                "Download error ({error}); retry {attempt}/{max_attempts} at offset {offset}"
            ),
            TransferWarning::Throttled {
                offset,
                remaining_connections,
            } => format!(
                "Connection throttled at offset {offset}; \
                 reducing to {remaining_connections} connection(s)"
            ),
            other => format!("Download warning: {other:?}"),
        };
        let obj = js_obj! {
            "type" => "warning",
            "message" => msg,
        };
        let _ = self.on_progress.call1(&JsValue::NULL, &obj);
    }
}

enum TransferError {
    Cancelled,
    Failed(String),
}

impl TransferError {
    fn into_js(self) -> JsValue {
        match self {
            Self::Cancelled => JsValue::from_str(CANCELLED_ERR),
            Self::Failed(msg) => JsValue::from_str(&msg),
        }
    }
}

struct TransferContext<'a> {
    storage: &'a DownloadStorage,
    checksum: [u8; 16],
    force: bool,
    cancel: &'a CancelWatcher,
    progress: &'a ProgressState,
}

async fn flush_buf(
    part: &mut PartHandle,
    filename: &str,
    buf: &[u8],
    filled: &mut usize,
    write_pos: &mut u64,
    progress: &ProgressState,
) -> Result<(), String> {
    let n = *filled;
    if n == 0 {
        return Ok(());
    }
    *filled = 0;
    part.write(*write_pos, &buf[..n])
        .await
        .map_err(|e| format!("Failed writing '{filename}': {e}"))?;
    *write_pos += n as u64;
    progress.set_file_written(*write_pos, false);
    Ok(())
}

async fn write_from_stream<R>(
    mut reader: R,
    part: &mut PartHandle,
    filename: &str,
    start_pos: u64,
    target_size: u64,
    ctx: &TransferContext<'_>,
) -> Result<(), TransferError>
where
    R: ResumableAsyncRead,
    R::Checkpoint: Into<CheckpointState>,
{
    let remaining = target_size.saturating_sub(start_pos);
    let buf_size = (remaining.min(WRITE_BUF_SIZE as u64) as usize).max(1);
    let mut buf = vec![0u8; buf_size];
    let mut filled = 0usize;
    let mut write_pos = start_pos;
    let mut last_persisted_offset = start_pos;
    let mut latest_cp: Option<R::Checkpoint> = None;
    let min_delta = CHECKPOINT_INTERVAL.max(1);
    let mut last_flush_ms = js_sys::Date::now();
    let mut last_checkpoint_ms = last_flush_ms;

    enum ReadOutcome {
        Cancelled,
        Data(io::Result<usize>),
    }

    let (is_cancelled, read_err): (bool, Option<io::Error>) = loop {
        let step = match ctx.cancel.run(reader.read(&mut buf[filled..])).await {
            Err(()) => ReadOutcome::Cancelled,
            Ok(res) => ReadOutcome::Data(res),
        };

        match step {
            ReadOutcome::Cancelled => break (true, None),
            ReadOutcome::Data(Ok(0)) => {
                drop(reader);
                flush_buf(
                    part,
                    filename,
                    &buf,
                    &mut filled,
                    &mut write_pos,
                    ctx.progress,
                )
                .await
                .map_err(TransferError::Failed)?;
                if write_pos != target_size {
                    return Err(TransferError::Failed(format!(
                        "Incomplete download for '{filename}': wrote {write_pos} of {target_size} bytes"
                    )));
                }
                return Ok(());
            }
            ReadOutcome::Data(Ok(n)) => {
                let new_filled = filled + n;
                if write_pos
                    .checked_add(new_filled as u64)
                    .is_none_or(|end| end > target_size)
                {
                    return Err(TransferError::Failed(format!(
                        "Stream exceeded declared target size for '{filename}'"
                    )));
                }
                filled = new_filled;

                if let Some(cp) = reader.checkpoint().filter(|cp| {
                    cp.output_offset() > last_persisted_offset && cp.output_offset() < target_size
                }) {
                    latest_cp = Some(cp);
                }

                let now = js_sys::Date::now();
                let cp_due = latest_cp.take_if(|cp| {
                    cp.output_offset() >= last_persisted_offset.saturating_add(min_delta)
                        || elapsed_at_least(now, last_checkpoint_ms, CHECKPOINT_MAX_WAIT_MS)
                });

                if let Some(cp) = cp_due {
                    let cp_offset = cp.output_offset();
                    flush_buf(
                        part,
                        filename,
                        &buf,
                        &mut filled,
                        &mut write_pos,
                        ctx.progress,
                    )
                    .await
                    .map_err(TransferError::Failed)?;
                    let meta_bytes = CheckpointMeta {
                        checksum: ctx.checksum,
                        target_size,
                        state: cp.into(),
                    }
                    .to_bytes();
                    part.save_meta(&meta_bytes).await.map_err(|e| {
                        TransferError::Failed(format!(
                            "Failed to save checkpoint for '{filename}': {e}"
                        ))
                    })?;
                    last_persisted_offset = cp_offset;
                    let done_ms = js_sys::Date::now();
                    last_flush_ms = done_ms;
                    last_checkpoint_ms = done_ms;
                } else if filled == buf.len()
                    || elapsed_at_least(now, last_flush_ms, COALESCE_MAX_WAIT_MS)
                {
                    flush_buf(
                        part,
                        filename,
                        &buf,
                        &mut filled,
                        &mut write_pos,
                        ctx.progress,
                    )
                    .await
                    .map_err(TransferError::Failed)?;
                    last_flush_ms = js_sys::Date::now();
                }
            }
            ReadOutcome::Data(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
            ReadOutcome::Data(Err(e)) => break (false, Some(e)),
        }
    };

    drop(reader);
    let allow_checkpoint = read_err
        .as_ref()
        .is_none_or(|e| e.kind() != io::ErrorKind::InvalidData);
    if allow_checkpoint
        && let Some(cp) = latest_cp.filter(|cp| cp.output_offset() > last_persisted_offset)
        && flush_buf(
            part,
            filename,
            &buf,
            &mut filled,
            &mut write_pos,
            ctx.progress,
        )
        .await
        .is_ok()
    {
        let meta_bytes = CheckpointMeta {
            checksum: ctx.checksum,
            target_size,
            state: cp.into(),
        }
        .to_bytes();
        let _ = part.save_meta(&meta_bytes).await;
    }

    if is_cancelled || ctx.cancel.is_cancelled() {
        Err(TransferError::Cancelled)
    } else {
        let err_msg =
            read_err.map_or_else(|| "Unknown stream error".to_string(), |e| e.to_string());
        Err(TransferError::Failed(format!(
            "Download failed for '{filename}': {err_msg}"
        )))
    }
}

async fn transfer_file<S>(
    source: &S,
    filename: &str,
    file_index: usize,
    ctx: &TransferContext<'_>,
) -> Result<u64, TransferError>
where
    S: ResumableStream,
    S::Checkpoint: Into<CheckpointState> + TryFrom<CheckpointState>,
{
    if ctx.cancel.is_cancelled() {
        return Err(TransferError::Cancelled);
    }

    let mut part = ctx
        .storage
        .open_part(filename, ctx.force)
        .await
        .map_err(TransferError::Failed)?;
    if ctx.cancel.is_cancelled() {
        part.close().await;
        return Err(TransferError::Cancelled);
    }

    let target_size = source.output_size();
    let transfer_res = async {
        let mut start_pos = 0u64;
        let mut resumed_cp: Option<(S::Checkpoint, Vec<u8>)> = None;
        let mut restarted = false;

        if !ctx.force {
            let existing_len = part.size().await.map_err(TransferError::Failed)?;
            let meta_bytes = part.read_meta().await.map_err(TransferError::Failed)?;
            let valid_resume = meta_bytes
                .as_deref()
                .and_then(|b| CheckpointMeta::from_bytes(b, ctx.checksum, target_size))
                .and_then(|m| S::Checkpoint::try_from(m.state).ok())
                .and_then(|cp| {
                    let dict_len = source.resume_dict_len(&cp)?;
                    let out = cp.output_offset();
                    (cp.source_offset() > 0
                        && out < target_size
                        && out <= existing_len
                        && (dict_len as u64) <= out)
                        .then_some((cp, dict_len))
                });

            if let Some((cp, dict_len)) = valid_resume {
                start_pos = cp.output_offset();
                if existing_len > start_pos {
                    part.truncate(start_pos)
                        .await
                        .map_err(TransferError::Failed)?;
                }
                let mut dict = Vec::new();
                if dict_len > 0 {
                    let dict_offset = start_pos - dict_len as u64;
                    let chunk = part
                        .read_at(dict_offset, dict_len)
                        .await
                        .map_err(TransferError::Failed)?;
                    if chunk.len() != dict_len {
                        return Err(TransferError::Failed(format!(
                            "Short resume dictionary read for '{filename}': expected {dict_len} bytes, got {}",
                            chunk.len()
                        )));
                    }
                    dict = chunk;
                }
                resumed_cp = Some((cp, dict));
            } else {
                let had_prior_state = existing_len > 0 || meta_bytes.is_some();
                if had_prior_state {
                    part.truncate(0).await.map_err(TransferError::Failed)?;
                    restarted = true;
                }
            }
        }

        if ctx.cancel.is_cancelled() {
            return Err(TransferError::Cancelled);
        }

        if restarted {
            crate::progress::emit_log(&format!(
                "Existing partial download for '{filename}' is incompatible or corrupted, restarting from scratch..."
            ));
        }

        let is_resumed = resumed_cp.is_some();
        if is_resumed {
            let pct = if target_size > 0 {
                (start_pos as f64 / target_size as f64) * 100.0
            } else {
                100.0
            };
            crate::progress::emit_log(&format!(
                "Resuming {filename} ({start_pos} / {target_size} bytes, {pct:.1}%)"
            ));
        } else {
            crate::progress::emit_log(&format!(
                "Downloading {filename} ({target_size} bytes)..."
            ));
        }

        ctx.progress
            .start_file(file_index, filename, start_pos, target_size, is_resumed);

        match resumed_cp {
            Some((cp, dict)) => {
                let reader = ctx
                    .cancel
                    .run(source.resume(&cp, &dict))
                    .await
                    .map_err(|()| TransferError::Cancelled)?
                    .map_err(|e| {
                        TransferError::Failed(format!("Failed to resume '{filename}': {e}"))
                    })?;
                drop(dict);
                write_from_stream(reader, &mut part, filename, start_pos, target_size, ctx).await
            }
            None => {
                let reader = ctx
                    .cancel
                    .run(source.open())
                    .await
                    .map_err(|()| TransferError::Cancelled)?
                    .map_err(|e| {
                        TransferError::Failed(format!("Failed to start '{filename}': {e}"))
                    })?;
                write_from_stream(reader, &mut part, filename, 0, target_size, ctx).await
            }
        }
    }
    .await;

    match transfer_res {
        Ok(()) => {
            part.finalize().await.map_err(TransferError::Failed)?;
            ctx.progress
                .finish_file(file_index, filename, false, target_size);
            Ok(target_size)
        }
        Err(err) => {
            part.close().await;
            Err(err)
        }
    }
}

fn select_entries_by_name<'a>(
    entries: &'a [ZipEntry],
    requested: Option<&[String]>,
) -> Result<Vec<&'a ZipEntry>, String> {
    let Some(names) = requested else {
        if entries.is_empty() {
            return Err("Firmware archive contains no downloadable files".to_string());
        }
        return Ok(entries.iter().collect());
    };

    if names.is_empty() {
        return Err("No archive entries selected".to_string());
    }

    let mut selected: Vec<&ZipEntry> = Vec::with_capacity(names.len());
    for raw_name in names {
        let name = raw_name.trim();
        let entry = entries
            .iter()
            .find(|e| e.name() == name)
            .or_else(|| entries.iter().find(|e| e.name().eq_ignore_ascii_case(name)))
            .ok_or_else(|| format!("Archive entry '{name}' not found in firmware package"))?;

        if !selected
            .iter()
            .any(|existing| existing.name() == entry.name())
        {
            selected.push(entry);
        }
    }
    Ok(selected)
}

fn push_downloaded_file(files_js: &js_sys::Array, name: &str, component: Option<&str>, size: u64) {
    let comp_js = match component {
        Some(c) => JsValue::from_str(c),
        None => JsValue::NULL,
    };
    files_js.push(&js_obj! {
        "name" => name,
        "component" => comp_js,
        "size" => size as f64,
    });
}

/// Fetches available firmware version history for `model` and `region` from FUS.
///
/// Returns `{ latest, previous, beta }`.
#[wasm_bindgen]
pub async fn fus_fetch_history(
    model: String,
    region: String,
    transport: js_sys::Function,
) -> Result<JsValue, JsValue> {
    let model = model.trim();
    let region = region.trim();
    if model.is_empty() || region.is_empty() {
        return Err(JsValue::from_str("Model and region must not be empty"));
    }

    let http = JsHttpClient::new(transport);
    let info = samloader_fus::fetch_history(&http, model, region)
        .await
        .map_err(to_js_err)?;

    let previous: js_sys::Array = info.previous.iter().map(JsValue::from).collect();
    let beta: js_sys::Array = info.beta.iter().map(JsValue::from).collect();

    Ok(js_obj! {
        "latest" => info.latest,
        "previous" => previous,
        "beta" => beta,
    })
}

/// Queries firmware metadata and reads the encrypted ZIP Central Directory without downloading payloads.
///
/// Returns `{ version, filename, decryptedFilename, encryptedSize, decryptedSize, fingerprintHex, entries }`.
#[wasm_bindgen]
pub async fn fus_inspect_firmware(
    model: String,
    region: String,
    version: String,
    transport: js_sys::Function,
) -> Result<JsValue, JsValue> {
    let model = model.trim();
    let region = region.trim();
    let version = version.trim();
    if model.is_empty() || region.is_empty() || version.is_empty() {
        return Err(JsValue::from_str(
            "Model, region, and version must not be empty",
        ));
    }

    let client = FusClient::with_client(JsHttpClient::new(transport))
        .await
        .map_err(to_js_err)?;
    let info = client
        .fetch_binary_info(model, region, version)
        .await
        .map_err(to_js_err)?;

    let resolved_version = info.version().to_string();
    let filename = info.filename().to_string();
    let decrypted_filename = info.decrypted_filename().to_string();
    let encrypted_size = info.encrypted_size();
    let fingerprint_hex = format_hex_16(&info.fingerprint());

    let session = client.init_download(info).await.map_err(to_js_err)?;
    let decrypted_size = session.size();
    let source = ParallelDataSource::new(session, 1);
    let archive = ZipArchive::open(source).await.map_err(to_js_err)?;

    let entries = js_sys::Array::new();
    for entry in archive.entries() {
        entries.push(&js_obj! {
            "name" => entry.name(),
            "component" => component_to_js(entry.name()),
            "compressedSize" => entry.compressed_size() as f64,
            "uncompressedSize" => entry.uncompressed_size() as f64,
        });
    }

    Ok(js_obj! {
        "version" => resolved_version,
        "filename" => filename,
        "decryptedFilename" => decrypted_filename,
        "encryptedSize" => encrypted_size as f64,
        "decryptedSize" => decrypted_size as f64,
        "fingerprintHex" => fingerprint_hex,
        "entries" => entries,
    })
}

/// Downloads and decrypts (or extracts selected entries from) a FUS firmware package with
/// resumable `SAMLOADR` v5 checkpointing and optional `AbortSignal` cancellation.
#[wasm_bindgen]
pub async fn fus_download(
    options: FusDownloadOptions,
    target: JsValue,
    transport: js_sys::Function,
    on_progress: js_sys::Function,
    signal: Option<AbortSignal>,
) -> Result<JsValue, JsValue> {
    let parsed = ParsedDownloadOptions::from_options(options)?;
    let target = DownloadTarget::from_js(&target).map_err(|e| JsValue::from_str(&e))?;

    let cancel = CancelWatcher::new(signal)?;
    if cancel.is_cancelled() {
        return Err(JsValue::from_str(CANCELLED_ERR));
    }

    let storage = DownloadStorage::open(&target);

    let client = run_cancellable(
        &cancel,
        FusClient::with_client(JsHttpClient::new(transport)),
    )
    .await?;
    let info = run_cancellable(
        &cancel,
        client.fetch_binary_info(&parsed.model, &parsed.region, &parsed.version),
    )
    .await?;

    let resolved_version = info.version().to_string();
    let filename = info.filename().to_string();
    let decrypted_filename = info.decrypted_filename().to_string();
    let checksum = info.fingerprint();
    let fingerprint_hex = format_hex_16(&checksum);
    let size_bounds = info.decrypted_size_bounds();

    let files_js = js_sys::Array::new();

    match parsed.mode {
        DownloadMode::Zip => {
            let progress = ProgressState::new_arc(1, size_bounds.1, on_progress);

            let existing_size = if parsed.force {
                None
            } else {
                run_cancellable(
                    &cancel,
                    storage.is_complete(&decrypted_filename, size_bounds.0, size_bounds.1),
                )
                .await?
            };

            if let Some(size) = existing_size {
                progress.overall_total.set(size);
                progress.finish_file(1, &decrypted_filename, true, size);
                push_downloaded_file(&files_js, &decrypted_filename, None, size);
            } else {
                let session = run_cancellable(&cancel, client.init_download(info)).await?;
                let decrypted_size = session.size();
                progress.overall_total.set(decrypted_size);

                let parallel = ParallelDataSource::new(session, parsed.concurrency)
                    .with_observer(Arc::clone(&progress));
                let stream = DataStream::new(parallel);

                let ctx = TransferContext {
                    storage: &storage,
                    checksum,
                    force: parsed.force,
                    cancel: &cancel,
                    progress: &progress,
                };
                let written = transfer_file(&stream, &decrypted_filename, 1, &ctx)
                    .await
                    .map_err(TransferError::into_js)?;

                push_downloaded_file(&files_js, &decrypted_filename, None, written);
            }
        }
        DownloadMode::Entries => {
            let progress = ProgressState::new_arc(0, 0, on_progress);

            let session = run_cancellable(&cancel, client.init_download(info)).await?;
            let parallel = ParallelDataSource::new(session, parsed.concurrency)
                .with_observer(Arc::clone(&progress));
            let archive = run_cancellable(&cancel, ZipArchive::open(parallel)).await?;

            let selected = select_entries_by_name(archive.entries(), parsed.entry_names.as_deref())
                .map_err(|e| JsValue::from_str(&e))?;

            let file_count = selected.len();
            let overall_total: u64 = selected
                .iter()
                .fold(0u64, |acc, e| acc.saturating_add(e.uncompressed_size()));
            progress.file_count.set(file_count);
            progress.overall_total.set(overall_total);

            let mut to_open = Vec::with_capacity(file_count);
            for &entry in &selected {
                if cancel.is_cancelled() {
                    return Err(JsValue::from_str(CANCELLED_ERR));
                }
                let size = entry.uncompressed_size();
                let complete = !parsed.force
                    && run_cancellable(&cancel, storage.is_complete(entry.name(), size, size))
                        .await?
                        .is_some();
                to_open.push((!complete).then_some(entry));
            }

            let streams = run_cancellable(
                &cancel,
                try_join_all(to_open.into_iter().map(|maybe_entry| {
                    let archive = &archive;
                    async move {
                        match maybe_entry {
                            Some(entry) => archive.open_entry(entry).await.map(Some).map_err(|e| {
                                format!("Failed to open archive entry '{}': {e}", entry.name())
                            }),
                            None => Ok(None),
                        }
                    }
                })),
            )
            .await?;

            let ctx = TransferContext {
                storage: &storage,
                checksum,
                force: parsed.force,
                cancel: &cancel,
                progress: &progress,
            };

            for (idx, (&entry, maybe_stream)) in selected.iter().zip(streams).enumerate() {
                if cancel.is_cancelled() {
                    return Err(JsValue::from_str(CANCELLED_ERR));
                }
                let file_index = idx + 1;
                let entry_name = entry.name();
                let component = OdinComponent::from_entry_name(entry_name).map(OdinComponent::key);

                if let Some(stream) = maybe_stream {
                    let written = transfer_file(&stream, entry_name, file_index, &ctx)
                        .await
                        .map_err(TransferError::into_js)?;
                    push_downloaded_file(&files_js, entry_name, component, written);
                } else {
                    let size = entry.uncompressed_size();
                    progress.finish_file(file_index, entry_name, true, size);
                    push_downloaded_file(&files_js, entry_name, component, size);
                }
            }
        }
    }

    Ok(js_obj! {
        "version" => resolved_version,
        "filename" => filename,
        "decryptedFilename" => decrypted_filename,
        "fingerprintHex" => fingerprint_hex,
        "files" => files_js,
    })
}
