// Copyright 2026 Google LLC
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

use clap::{Arg, Command};
use indicatif::{ProgressBar, ProgressStyle};
use samloader_fus::{DownloadArgs, FusClient, ProgressReporter, download_latest_firmware};
use std::time::Duration;

const PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

struct ProgressWrapper<'a>(&'a ProgressBar);

impl<'a> ProgressReporter for ProgressWrapper<'a> {
    fn init_length(&self, len: u64) {
        self.0.set_length(len);
        self.0.enable_steady_tick(Duration::from_secs(1));
    }

    fn increment(&self, bytes: u64) {
        self.0.inc(bytes)
    }

    fn finish(&self) {
        self.0.finish()
    }
}

fn main() {
    let matches = Command::new("samloader")
        .about("Download firmware for Samsung devices")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("model")
                .short('m')
                .long("model")
                .required(true)
                .help("The model name (e.g. SM-S931U1)"),
        )
        .arg(
            Arg::new("region")
                .short('r')
                .long("region")
                .required(true)
                .help("Region CSC code (e.g. XAA)"),
        )
        .arg(
            Arg::new("threads")
                .short('j')
                .long("threads")
                .default_value("8")
                .value_parser(clap::value_parser!(u64))
                .help("Number of parallel connections"),
        )
        .subcommand(
            Command::new("download")
                .about("Download the latest firmware")
                .arg(
                    Arg::new("out_dir")
                        .short('d')
                        .long("out-dir")
                        .help("Output directory"),
                )
                .arg(
                    Arg::new("out_file")
                        .short('o')
                        .long("out-file")
                        .help("Output file path"),
                ),
        )
        .subcommand(Command::new("check").about("Check the latest version"))
        .get_matches();

    let model = matches.get_one::<String>("model").cloned().unwrap();
    let region = matches.get_one::<String>("region").cloned().unwrap();
    let threads = *matches.get_one::<u64>("threads").unwrap();

    match matches.subcommand() {
        Some(("download", sub_m)) => {
            let out_dir = sub_m.get_one::<String>("out_dir").cloned();
            let out_file = sub_m.get_one::<String>("out_file").cloned();
            let args = DownloadArgs {
                model,
                region,
                threads,
                out_dir,
                out_file,
            };
            let pb = ProgressBar::no_length()
                .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
            let wrapper = ProgressWrapper(&pb);
            download_latest_firmware(args, Some(&wrapper));
        }
        Some(("check", _)) => {
            let mut client = FusClient::new().expect("Unable to establish FusClient");
            client.fetch_binary_info(&model, &region);
            println!("{}", client.info.version);
        }
        _ => unreachable!(),
    };
}
