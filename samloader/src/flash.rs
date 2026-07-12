// Copyright 2026 John "topjohnwu" Wu
// Copyright 2021-2024 Henrik Grimler
// Copyright 2010-2017 Benjamin Dobell, Glass Echidna
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

use crate::PartitionArg;
use crate::print_error;
use indicatif::{ProgressBar, ProgressStyle};
use samloader_odin::{FlashManager, FlashProgress, OdinManager, UsbBackendOption, create_backend};
use std::time::Duration;

const PROGRESS_TEMPLATE: &str =
    "{msg}\n[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

struct CliProgress {
    progress_bar: std::sync::Mutex<Option<ProgressBar>>,
    position: std::sync::atomic::AtomicU64,
    verbose: bool,
}

impl FlashProgress for CliProgress {
    fn set_length(&self, len: u64) {
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.set_length(len);
        }
    }

    fn inc(&self, bytes: u64) {
        self.position
            .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.inc(bytes);
        }
    }

    fn position(&self) -> u64 {
        self.position.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn println(&self, msg: &str) {
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.println(msg);
        } else {
            println!("{}", msg);
        }
    }

    fn println_verbose(&self, msg: &str) {
        if self.verbose {
            self.println(msg);
        }
    }

    fn start_partition(&self, name: &str, size: u64) {
        let pb = ProgressBar::no_length()
            .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
        pb.enable_steady_tick(Duration::from_secs(1));
        pb.set_message(format!("Flashing {}", name));
        if size > 0 {
            pb.set_length(size);
        }
        *self.progress_bar.lock().unwrap() = Some(pb);
    }

    fn end_partition(&self, name: &str) {
        if let Some(pb) = self.progress_bar.lock().unwrap().take() {
            pb.set_message(format!("{} flash successful", name));
            pb.finish();
            println!();
        }
    }

    fn fail_partition(&self, name: &str) {
        if let Some(pb) = self.progress_bar.lock().unwrap().take() {
            pb.abandon_with_message(format!("{} flash failed", name));
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn action_flash(
    usb_backend: UsbBackendOption,
    repartition: bool,
    verbose: bool,
    reboot_device: bool,
    wait: bool,
    skip_size_check: bool,
    skip_md5: bool,
    pit: Option<&str>,
    packages: &[String],
    partitions: &[PartitionArg],
) -> i32 {
    let progress = CliProgress {
        progress_bar: std::sync::Mutex::new(None),
        position: std::sync::atomic::AtomicU64::new(0),
        verbose,
    };

    let usb = match create_backend(usb_backend, verbose, wait) {
        Ok(u) => u,
        Err(e) => {
            print_error!("{}", e);
            return 1;
        }
    };
    let mut odin_manager = OdinManager::new(usb, verbose);

    if let Err(e) = odin_manager.init() {
        print_error!("{}", e);
        return 1;
    }

    if let Err(e) = odin_manager.begin_session() {
        print_error!("{}", e);
        return 1;
    }

    let mut flash_manager = FlashManager::new(&mut odin_manager, &progress);

    let mapped_partitions: Vec<(Option<String>, String)> = partitions
        .iter()
        .map(|p| (p.name.clone(), p.filename.clone()))
        .collect();

    if let Err(e) = flash_manager.flash(
        repartition,
        reboot_device,
        skip_size_check,
        skip_md5,
        pit,
        packages,
        &mapped_partitions,
    ) {
        print_error!("{}", e);
        return 1;
    }

    0
}
