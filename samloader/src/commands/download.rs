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

use crate::cli::DownloadArgs;
use indicatif::{ProgressBar, ProgressStyle};
use samloader_fus::{
    DownloadOptions, DownloadProgress, FusClient, download_firmware, fetch_history,
};
use std::error::Error;
use std::time::Duration;

const PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

struct ProgressWrapper<'a> {
    progress_bar: &'a ProgressBar,
    verbose: bool,
}

impl DownloadProgress for ProgressWrapper<'_> {
    fn set_length(&self, len: u64) {
        self.progress_bar.set_length(len);
    }

    fn set_position(&self, pos: u64) {
        self.progress_bar.disable_steady_tick();
        self.progress_bar.set_position(pos);
        self.progress_bar.reset_elapsed();
        self.progress_bar.enable_steady_tick(Duration::from_secs(1));
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

/// Downloads and decrypts a firmware from Samsung's update servers.
pub(crate) fn run(args: DownloadArgs, verbose: bool) -> Result<(), Box<dyn Error>> {
    let version = match &args.version {
        Some(v) => v.clone(),
        None => {
            let version_info = fetch_history(&args.fus.model, &args.fus.region)
                .expect("Failed to fetch version info");
            version_info.latest
        }
    };

    let mut client = FusClient::new().expect("Unable to establish FusClient");
    client.fetch_binary_info(&args.fus.model, &args.fus.region, &version);

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
        verbose,
    };

    let options = DownloadOptions {
        threads: args.threads,
        force: args.force,
    };

    if let Err(e) = download_firmware(&client, &final_out, options, &wrapper) {
        progress.abandon();
        // Keep the error apart from the abandoned progress bar
        eprintln!();
        return Err(format!("Download failed: {e}").into());
    }

    progress.finish();
    Ok(())
}
