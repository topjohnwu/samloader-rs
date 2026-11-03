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

//! Progress reporting and the virtualized activity log.

use std::cell::{Cell, RefCell};

use js_sys::Function;
use samloader_odin::{FlashEvent, FlashProgress, clear_progress, set_progress};
use wasm_bindgen::prelude::*;

/// Height of a single log line in pixels; exposed to JS via [`log_line_height`].
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
    flash: FlashTotals,
}

/// Progress across all partitions of a flash, from [`FlashEvent::FlashStart`].
///
/// Partitions are weighted by their uncompressed size. Within a partition, progress
/// is the fraction of its transfer, as LZ4 images may be sent compressed.
#[derive(Default)]
struct FlashTotals {
    /// Total uncompressed bytes of the flash; zero when no flash is in progress.
    total: Cell<u64>,
    /// Uncompressed bytes of the partitions already flashed.
    done: Cell<u64>,
    /// Uncompressed bytes of the partition being flashed.
    current: Cell<u64>,
    /// 1-based index of the partition being flashed.
    index: Cell<usize>,
    /// Number of partitions to flash.
    count: Cell<usize>,
    /// Bytes sent to the device so far, for measuring transfer speed.
    sent: Cell<u64>,
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
            flash: FlashTotals::default(),
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

        let flash = &self.flash;
        let flash_total = flash.total.get();
        if flash_total > 0 {
            let fraction = if total > 0 {
                (curr as f64 / total as f64).min(1.0)
            } else {
                0.0
            };
            let done = flash.done.get() as f64 + flash.current.get() as f64 * fraction;
            let overall = (done / flash_total as f64 * 100.0).min(100.0);
            let _ = js_sys::Reflect::set(&obj, &"overallPercent".into(), &overall.into());
            let _ = js_sys::Reflect::set(
                &obj,
                &"partitionIndex".into(),
                &(flash.index.get() as f64).into(),
            );
            let _ = js_sys::Reflect::set(
                &obj,
                &"partitionCount".into(),
                &(flash.count.get() as f64).into(),
            );
            let _ = js_sys::Reflect::set(&obj, &"sent".into(), &(flash.sent.get() as f64).into());
        }

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
        self.flash.sent.set(self.flash.sent.get() + bytes);
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
            FlashEvent::FlashStart {
                total_bytes,
                partitions,
            } => {
                let flash = &self.flash;
                flash.total.set(total_bytes);
                flash.done.set(0);
                flash.current.set(0);
                flash.index.set(0);
                flash.count.set(partitions);
                flash.sent.set(0);
            }
            FlashEvent::PartitionStart { name, size } => {
                self.flash.current.set(size);
                self.flash.index.set(self.flash.index.get() + 1);
                *self.current_partition.borrow_mut() = name.to_string();
                self.current_bytes.set(0);
                self.total_bytes.set(size);
                self.last_percent.set(None);
                self.emit_log(&format!("Flashing {name} ({size} bytes)..."));
                self.emit_progress(true);
            }
            FlashEvent::PartitionEnd(name) => {
                let flash = &self.flash;
                flash.done.set(flash.done.get() + flash.current.replace(0));
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

/// Returns the full contents of the Rust log buffer, one line per log line.
#[wasm_bindgen]
pub fn export_logs() -> String {
    PROGRESS.with(|&p| p.lines.borrow().join("\n"))
}

/// Returns the most recent non-blank log line, shown while the activity log is folded.
#[wasm_bindgen]
pub fn last_log_line() -> String {
    PROGRESS.with(|&p| {
        p.lines
            .borrow()
            .iter()
            .rev()
            .find(|line| !line.trim().is_empty())
            .cloned()
            .unwrap_or_default()
    })
}

/// Returns the height in pixels of a single log line. The log element's CSS `line-height`
/// must match it for the virtualized viewport to line up.
#[wasm_bindgen]
pub fn log_line_height() -> f64 {
    LOG_LINE_HEIGHT
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
