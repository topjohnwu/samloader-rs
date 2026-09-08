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
use samloader_odin::{
    FlashEvent, FlashManager, FlashProgress, OdinConnection, UsbBackendOption, create_backend,
    set_progress,
};
use std::time::Duration;

const PROGRESS_TEMPLATE: &str =
    "{msg}\n[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

pub(crate) struct CliProgress {
    progress_bar: std::sync::Mutex<Option<ProgressBar>>,
    verbose: bool,
}

impl CliProgress {
    pub(crate) fn new(verbose: bool) -> Self {
        Self {
            progress_bar: std::sync::Mutex::new(None),
            verbose,
        }
    }
}

impl FlashProgress for CliProgress {
    fn set_length(&self, len: u64) {
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.set_length(len);
        }
    }

    fn inc(&self, bytes: u64) {
        if let Some(pb) = &*self.progress_bar.lock().unwrap() {
            pb.inc(bytes);
        }
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

    fn on_event(&self, event: FlashEvent<'_>) {
        match event {
            FlashEvent::PartitionStart { name, size } => {
                let pb = ProgressBar::no_length()
                    .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
                pb.enable_steady_tick(Duration::from_secs(1));
                pb.set_message(format!("Flashing {}", name));
                if size > 0 {
                    pb.set_length(size);
                }
                *self.progress_bar.lock().unwrap() = Some(pb);
            }
            FlashEvent::PartitionEnd(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.set_message(format!("{} flash successful", name));
                    pb.finish();
                    println!();
                }
            }
            FlashEvent::PartitionFail(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.abandon_with_message(format!("{} flash failed", name));
                }
            }
            FlashEvent::Md5Start {
                name,
                size: total_bytes,
            } => {
                let pb = ProgressBar::no_length()
                    .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
                pb.enable_steady_tick(Duration::from_secs(1));
                pb.set_message(format!("Verifying MD5 checksum for {}", name));
                if total_bytes > 0 {
                    pb.set_length(total_bytes);
                }
                *self.progress_bar.lock().unwrap() = Some(pb);
            }
            FlashEvent::Md5End(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.set_message(format!("{} MD5 verification successful", name));
                    pb.finish();
                    println!();
                }
            }
            FlashEvent::Md5Fail(name) => {
                if let Some(pb) = self.progress_bar.lock().unwrap().take() {
                    pb.abandon_with_message(format!("{} MD5 verification failed", name));
                }
            }
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
    set_progress(CliProgress::new(verbose));

    let usb = match create_backend(usb_backend, verbose, wait) {
        Ok(u) => u,
        Err(e) => {
            print_error!("{}", e);
            return 1;
        }
    };
    let mut connection = OdinConnection::new(usb);

    if let Err(e) = connection.init() {
        print_error!("{}", e);
        return 1;
    }

    let mut session = match connection.begin_session() {
        Ok(s) => s,
        Err(e) => {
            print_error!("{}", e);
            return 1;
        }
    };

    let mapped_partitions: Vec<(Option<String>, String)> = partitions
        .iter()
        .map(|p| (p.name.clone(), p.filename.clone()))
        .collect();

    let mut flash_manager = FlashManager::new(&mut session)
        .repartition(repartition)
        .auto_reboot(reboot_device)
        .skip_size_check(skip_size_check)
        .skip_md5(skip_md5)
        .packages(packages)
        .partitions(&mapped_partitions);

    if let Some(pit_path) = pit {
        flash_manager = flash_manager.pit(pit_path);
    }

    if let Err(e) = flash_manager.execute() {
        print_error!("{}", e);
        return 1;
    }

    0
}
