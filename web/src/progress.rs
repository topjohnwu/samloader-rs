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

//! Progress and log event forwarding to JavaScript.

use std::cell::{Cell, RefCell};

use js_sys::Function;
use samloader_odin::{FlashEvent, FlashProgress, set_progress};
use wasm_bindgen::prelude::*;

thread_local! {
    static PROGRESS: &'static WebProgress = Box::leak(Box::new(WebProgress::new()));
}

struct WebProgress {
    verbose: Cell<bool>,
    log_cb: RefCell<Option<Function>>,
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
            total_bytes: Cell::new(0),
            current_bytes: Cell::new(0),
            last_percent: Cell::new(None),
            current_partition: RefCell::new(String::new()),
            flash: FlashTotals::default(),
        }
    }

    fn send_log(&self, msg: &str) {
        if let Some(cb) = self.log_cb.borrow().as_ref() {
            let obj = crate::js_obj! {
                "type" => "log",
                "message" => msg,
            };
            let _ = cb.call1(&JsValue::NULL, &obj);
        }
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
                self.send_log("Waiting for device...");
            }
            FlashEvent::HandshakeStart => {
                self.send_log("Starting Odin handshake...");
            }
            FlashEvent::HandshakeEnd => {
                self.send_log("Odin handshake successful.");
            }
            FlashEvent::SessionStart => {
                self.send_log("Requesting Odin session...");
            }
            FlashEvent::SessionSetup => {
                self.send_log("Setting up Odin session...");
            }
            FlashEvent::SessionReady => {
                self.send_log("Odin session ready.");
            }
            FlashEvent::SessionEnd => {
                self.send_log("Ending Odin session...");
            }
            FlashEvent::Reboot { download } => {
                let target = if download {
                    "Download mode"
                } else {
                    "normal mode"
                };
                self.send_log(&format!("Rebooting device to {target}..."));
            }
            FlashEvent::EraseStart => {
                self.send_log("Erasing USERDATA partition...");
            }
            FlashEvent::EraseEnd { sectors } => {
                self.send_log(&format!("USERDATA partition erased ({sectors} sectors)."));
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
                self.send_log(&format!("Flashing {name} ({size} bytes)..."));
                self.emit_progress(true);
            }
            FlashEvent::PartitionEnd(name) => {
                let flash = &self.flash;
                flash.done.set(flash.done.get() + flash.current.replace(0));
                self.current_partition.borrow_mut().clear();
                self.send_log(&format!("Finished flashing {name}."));
            }
            FlashEvent::PartitionFail(name) => {
                self.current_partition.borrow_mut().clear();
                self.send_log(&format!("Failed flashing {name}!"));
            }
            FlashEvent::Md5Start { name, size } => {
                *self.current_partition.borrow_mut() = name.to_string();
                self.current_bytes.set(0);
                self.total_bytes.set(size);
                self.last_percent.set(None);
                self.send_log(&format!("Verifying MD5 for {name} ({size} bytes)..."));
                self.emit_progress(true);
            }
            FlashEvent::Md5End(name) => {
                self.current_partition.borrow_mut().clear();
                self.send_log(&format!("MD5 verified for {name}."));
            }
            FlashEvent::Md5Fail(name) => {
                self.current_partition.borrow_mut().clear();
                self.send_log(&format!("MD5 verification failed for {name}!"));
            }
            _ => {}
        }
    }

    fn println(&self, msg: &str) {
        self.send_log(msg);
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

/// Sets whether verbose log messages are emitted by the active progress reporter.
#[wasm_bindgen]
pub fn set_verbose(verbose: bool) {
    PROGRESS.with(|&p| p.verbose.set(verbose));
}

pub(crate) fn is_verbose() -> bool {
    PROGRESS.with(|&p| p.verbose.get())
}

pub(crate) fn emit_log(msg: &str) {
    PROGRESS.with(|&p| p.send_log(msg));
}
