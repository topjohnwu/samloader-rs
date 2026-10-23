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
    FlashEvent, FlashManager, FlashProgress, OdinConnection, RebootMode, UsbBackendOption,
    create_backend, set_progress,
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

pub(crate) fn action_preflight(
    verbose: bool,
    skip_md5: bool,
    pit: &str,
    packages: &[String],
    partitions: &[PartitionArg],
) -> i32 {
    set_progress(CliProgress::new(verbose));

    let mapped_partitions: Vec<(Option<String>, String)> = partitions
        .iter()
        .map(|p| (p.name.clone(), p.filename.clone()))
        .collect();

    let result = FlashManager::new_offline()
        .skip_md5(skip_md5)
        .pit(pit)
        .packages(packages)
        .partitions(&mapped_partitions)
        .preflight();

    let report = match result {
        Ok(report) => report,
        Err(e) => {
            print_error!("{}", e);
            return 1;
        }
    };

    println!(
        "Offline preflight passed: {} partitions",
        report.partitions.len()
    );
    println!(
        "Archive selection: {}",
        if report.has_download_list {
            "Samsung download-list"
        } else {
            "all PIT-matching members"
        }
    );
    println!(
        "{:<18} {:>14} {:>14} {:>14}",
        "PARTITION", "IMAGE", "CAPACITY", "HEADROOM"
    );
    for part in report.partitions {
        let (capacity, headroom) = if part.partition_size == 0 {
            ("grow-to-end".to_string(), "n/a".to_string())
        } else {
            (
                part.partition_size.to_string(),
                part.partition_size
                    .saturating_sub(part.image_size)
                    .to_string(),
            )
        };
        println!(
            "{:<18} {:>14} {:>14} {:>14}",
            part.name, part.image_size, capacity, headroom,
        );
    }
    println!("No USB device was opened or contacted.");
    println!("Validation completed successfully (offline check-only).");
    0
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn action_flash(
    usb_backend: UsbBackendOption,
    verbose: bool,
    reboot_mode: RebootMode,
    wait: bool,
    skip_size_check: bool,
    skip_md5: bool,
    no_lz4: bool,
    pit: Option<&str>,
    packages: &[String],
    partitions: &[PartitionArg],
    csc_code: Option<&str>,
    erase: bool,
) -> i32 {
    set_progress(CliProgress::new(verbose));

    let mapped_partitions: Vec<(Option<String>, String)> = partitions
        .iter()
        .map(|p| (p.name.clone(), p.filename.clone()))
        .collect();

    // A full sparse/LZ4 size validation can take minutes. Do it before opening USB so the
    // bootloader is never left waiting in an Odin session while the host performs CPU work.
    // The normal flash path then reuses the validated logical sizes in the same process.
    let preflight_report = if let Some(pit_path) = pit
        && !skip_size_check
    {
        println!("Validating firmware completely before opening the USB device...");
        let result = FlashManager::new_offline()
            .pit(pit_path)
            .skip_md5(skip_md5)
            .packages(packages)
            .partitions(&mapped_partitions)
            .preflight();
        match result {
            Ok(report) => {
                println!(
                    "Pre-USB validation passed: {} partitions. Opening Odin session...",
                    report.partitions.len()
                );
                Some(report)
            }
            Err(e) => {
                print_error!("{}", e);
                return 1;
            }
        }
    } else {
        None
    };

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

    if no_lz4 {
        println!("Direct LZ4 transfer disabled; compressed images will be decompressed on host.");
        session.disable_lz4();
    }

    let mut flash_manager = FlashManager::new(&mut session)
        .reboot_mode(reboot_mode)
        .skip_size_check(skip_size_check)
        // A successful same-process preflight already verified every MD5 footer.
        .skip_md5(skip_md5 || preflight_report.is_some())
        .erase(erase)
        .packages(packages)
        .partitions(&mapped_partitions)
        .sales_code(csc_code);

    if let Some(pit_path) = pit {
        flash_manager = flash_manager.pit(pit_path);
    }
    if let Some(report) = &preflight_report {
        flash_manager = flash_manager.prevalidated(report);
    }

    if let Err(e) = flash_manager.execute() {
        print_error!("{}", e);
        return 1;
    }

    0
}
