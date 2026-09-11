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
use samloader_fus::{DownloadProgress, FusClient, download_firmware, fetch_version_xml};
use std::time::Duration;

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

    /// Whether to enable verbose output
    pub(crate) verbose: bool,
}

struct ProgressWrapper<'a> {
    progress_bar: &'a ProgressBar,
    verbose: bool,
}

impl DownloadProgress for ProgressWrapper<'_> {
    fn set_length(&self, len: u64) {
        self.progress_bar.set_length(len);
    }

    fn inc(&self, bytes: u64) {
        self.progress_bar.inc(bytes);
    }

    fn position(&self) -> u64 {
        self.progress_bar.position()
    }

    fn println(&self, msg: &str) {
        self.progress_bar.println(msg);
    }

    fn println_verbose(&self, msg: &str) {
        if self.verbose {
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
    };

    if let Err(e) = download_firmware(&client, &final_out, args.threads, &wrapper) {
        progress.abandon();
        eprintln!("\nERROR: Download failed: {e}");
        std::process::exit(1);
    }

    progress.finish();
}
