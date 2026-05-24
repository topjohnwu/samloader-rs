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

mod download;

use clap::{Arg, Command};
use download::{DownloadArgs, download_latest_firmware};
use samloader_fus::FusClient;

fn main() {
    let matches = Command::new("samloader")
        .about("Download firmware for Samsung devices")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("download")
                .about("Download the latest firmware")
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
        .subcommand(
            Command::new("check-update")
                .about("Check the latest version")
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
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("download", sub_m)) => {
            let model = sub_m.get_one::<String>("model").cloned().unwrap();
            let region = sub_m.get_one::<String>("region").cloned().unwrap();
            let threads = *sub_m.get_one::<u64>("threads").unwrap();
            let out_dir = sub_m.get_one::<String>("out_dir").cloned();
            let out_file = sub_m.get_one::<String>("out_file").cloned();
            let args = DownloadArgs {
                model,
                region,
                threads,
                out_dir,
                out_file,
            };
            download_latest_firmware(args);
        }
        Some(("check-update", sub_m)) => {
            let model = sub_m.get_one::<String>("model").cloned().unwrap();
            let region = sub_m.get_one::<String>("region").cloned().unwrap();
            let mut client = FusClient::new().expect("Unable to establish FusClient");
            client.fetch_binary_info(&model, &region);
            println!("{}", client.info.version);
        }
        _ => unreachable!(),
    };
}
