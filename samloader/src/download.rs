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

use indicatif::{ProgressBar, ProgressStyle};
use samloader_fus::{
    DownloadOptions, DownloadProgress, FusClient, download_firmware, fetch_version_xml,
};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MACHINE_EMIT_INTERVAL_MS: u64 = 200;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

const PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

pub(crate) struct DownloadArgs {
    /// The model name (e.g. SM-S931U1)
    pub(crate) model: String,

    /// Region CSC code (e.g. XAA)
    pub(crate) region: String,

    /// Optional: firmware version. If None, downloads the latest.
    pub(crate) version: Option<String>,

    /// Number of parallel connections
    pub(crate) threads: u64,

    /// Optional: the output directory
    pub(crate) out_dir: Option<String>,

    /// Optional: the output file name
    pub(crate) out_file: Option<String>,

    /// Overwrite existing files and discard any partial download
    pub(crate) force: bool,

    /// Whether to enable verbose output
    pub(crate) verbose: bool,

    pub(crate) machine: bool,
}

struct ProgressWrapper<'a> {
    progress_bar: &'a ProgressBar,
    verbose: bool,
    // When on, print the download position to stdout so the desktop app can draw a progress bar.
    machine: bool,
    last_emit_ms: AtomicU64,
}

impl ProgressWrapper<'_> {
    // Pass force to print right away instead of waiting for the rate limit.
    fn emit_progress(&self, force: bool) {
        if !self.machine {
            return;
        }
        let now = now_ms();
        if !force {
            let last = self.last_emit_ms.load(Ordering::Relaxed);
            if now.saturating_sub(last) < MACHINE_EMIT_INTERVAL_MS {
                return;
            }
        }
        self.last_emit_ms.store(now, Ordering::Relaxed);
        let pos = self.progress_bar.position();
        let total = self.progress_bar.length().unwrap_or(0);
        println!("@P {pos} {total}");
        let _ = std::io::stdout().flush();
    }
}

impl DownloadProgress for ProgressWrapper<'_> {
    fn set_length(&self, len: u64) {
        self.progress_bar.set_length(len);
        self.emit_progress(true);
    }

    fn set_position(&self, pos: u64) {
        self.progress_bar.disable_steady_tick();
        self.progress_bar.set_position(pos);
        self.progress_bar.reset_elapsed();
        self.progress_bar.enable_steady_tick(Duration::from_secs(1));
        self.emit_progress(true);
    }

    fn inc(&self, bytes: u64) {
        self.progress_bar.inc(bytes);
        self.emit_progress(false);
    }

    fn position(&self) -> u64 {
        self.progress_bar.position()
    }

    fn println(&self, msg: &str) {
        if self.machine {
            println!("{msg}");
            let _ = std::io::stdout().flush();
        } else {
            self.progress_bar.println(msg);
        }
    }

    fn println_verbose(&self, msg: &str) {
        if !self.verbose {
            return;
        }
        if self.machine {
            println!("{msg}");
            let _ = std::io::stdout().flush();
        } else {
            self.progress_bar.println(msg);
        }
    }
}

pub(crate) fn action_download(args: DownloadArgs) {
    let mut client = FusClient::new().expect("Unable to establish FusClient");

    let version = match &args.version {
        Some(v) => v.clone(),
        None => {
            let version_info = client
                .fetch_history(&args.model, &args.region)
                .or_else(|_| fetch_version_xml(&args.model, &args.region))
                .expect("Failed to fetch version info");
            version_info.latest
        }
    };

    client.fetch_binary_info(&args.model, &args.region, &version);

    println!("Firmware Version: {}", client.info.version);

    let default_name = client
        .info
        .filename
        .strip_suffix(".enc4")
        .or_else(|| client.info.filename.strip_suffix(".enc2"))
        .unwrap_or(client.info.filename.as_str());

    let final_out = match (args.out_file, args.out_dir) {
        (Some(name), _) => name,
        (None, Some(dir)) => format!("{}/{}", dir, default_name),
        _ => default_name.to_string(),
    };

    println!("Downloading {} to {}", client.info.filename, final_out);

    let progress = ProgressBar::no_length()
        .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
    progress.enable_steady_tick(Duration::from_secs(1));

    let wrapper = ProgressWrapper {
        progress_bar: &progress,
        verbose: args.verbose,
        machine: args.machine,
        last_emit_ms: AtomicU64::new(0),
    };

    let options = DownloadOptions {
        threads: args.threads,
        force: args.force,
    };

    if let Err(e) = download_firmware(&client, &final_out, options, &wrapper) {
        progress.abandon();
        if args.machine {
            println!("@ERR {e}");
            let _ = std::io::stdout().flush();
        }
        eprintln!("\nERROR: Download failed: {e}");
        std::process::exit(1);
    }

    wrapper.emit_progress(true);
    if args.machine {
        println!("@DONE {final_out}");
        let _ = std::io::stdout().flush();
    }
    progress.finish();
}
