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

mod actions;
mod download;
mod flash;

use clap::{Arg, ArgAction, Command};
use samloader_fus::fetch_version_info;

pub(crate) struct PartitionArg {
    pub(crate) name: Option<String>,
    pub(crate) filename: String,
}

#[macro_export]
macro_rules! print_error {
    ($($arg:tt)*) => {
        eprint!("ERROR: ");
        eprintln!($($arg)*);
    };
}

const VERBOSE_HELP: &str = "Enable verbose output";
const USB_LOG_LEVEL_HELP: &str = "Set libusb log level (none, error, warning, info, debug)";
const WAIT_HELP: &str = "Waits until a compatible device is connected.";
const REPARTITION_HELP: &str = "Repartition the device. WARNING: It's strongly recommended you specify all files at your disposal.";
const SKIP_SIZE_CHECK_HELP: &str = "Do not verify that files fit in the specified partition.";
const PIT_HELP: &str = "The PIT file to use for repartitioning or flashing.";

const DETECT_ABOUT: &str = "Indicates whether or not a download mode device can be detected.";
const DETECT_HELP: &str = r#"Indicates whether or not a download mode device can be detected.

Returns instantly per default, or waits until device is found
when --wait argument is used."#;

const DUMP_PIT_ABOUT: &str = "Dumps the connected device's PIT file to the specified output file.";
const DUMP_PIT_HELP: &str = r#"Dumps the connected device's PIT file to the specified
output file."#;
const DUMP_PIT_OUTPUT_HELP: &str = "Output file path for the dumped PIT file.";

const PRINT_PIT_ABOUT: &str = "Prints the contents of a PIT file in a human readable format.";
const PRINT_PIT_HELP: &str = r#"Prints the contents of a PIT file in a human readable format. If
a filename is not provided then Heimdall retrieves the PIT file from the
connected device."#;
const PRINT_PIT_FILE_HELP: &str = "The PIT file to print. If not provided, Heimdall retrieves the PIT file from the connected device.";

const FLASH_ABOUT: &str = "Flashes one or more firmware files to your phone.";
const FLASH_HELP: &str = r#"Flashes one or more firmware files to your phone. Partition names
(or identifiers) can be obtained by executing the print-pit action.

Example explicit flashing: samloader flash -p RECOVERY recovery.img
Example auto-matching: samloader flash -f boot.img"#;

fn main() {
    let matches = Command::new("samloader")
        .about("Download and flash firmware for Samsung devices")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .action(ArgAction::SetTrue)
                .global(true)
                .help(VERBOSE_HELP),
        )
        .arg(
            Arg::new("usb-log-level")
                .long("usb-log-level")
                .num_args(1)
                .global(true)
                .help(USB_LOG_LEVEL_HELP),
        )
        .subcommand(
            Command::new("download")
                .about("Download firmware")
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
                    Arg::new("version")
                        .short('v')
                        .long("version")
                        .help("Firmware version string (e.g. PDA/CSC/MODEM). If omitted, downloads the latest."),
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
                .about("Check available versions")
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
                    Arg::new("all")
                        .short('a')
                        .long("all")
                        .help("List all available firmware versions, sorted from old to new")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("detect")
                .about(DETECT_ABOUT)
                .long_about(DETECT_HELP)
                .arg(
                    Arg::new("wait")
                        .long("wait")
                        .action(ArgAction::SetTrue)
                        .help(WAIT_HELP),
                ),
        )
        .subcommand(
            Command::new("dump-pit")
                .about(DUMP_PIT_ABOUT)
                .long_about(DUMP_PIT_HELP)
                .arg(
                    Arg::new("output")
                        .long("output")
                        .required(true)
                        .num_args(1)
                        .help(DUMP_PIT_OUTPUT_HELP),
                )
                .arg(
                    Arg::new("wait")
                        .long("wait")
                        .action(ArgAction::SetTrue)
                        .help(WAIT_HELP),
                ),
        )
        .subcommand(
            Command::new("print-pit")
                .about(PRINT_PIT_ABOUT)
                .long_about(PRINT_PIT_HELP)
                .arg(
                    Arg::new("file")
                        .long("file")
                        .num_args(1)
                        .help(PRINT_PIT_FILE_HELP),
                )
                .arg(
                    Arg::new("wait")
                        .long("wait")
                        .action(ArgAction::SetTrue)
                        .help(WAIT_HELP),
                ),
        )
        .subcommand(
            Command::new("flash")
                .about(FLASH_ABOUT)
                .long_about(FLASH_HELP)
                .arg(
                    Arg::new("repartition")
                        .long("repartition")
                        .action(ArgAction::SetTrue)
                        .help(REPARTITION_HELP),
                )
                .arg(
                    Arg::new("wait")
                        .long("wait")
                        .action(ArgAction::SetTrue)
                        .help(WAIT_HELP),
                )
                .arg(
                    Arg::new("skip-size-check")
                        .long("skip-size-check")
                        .action(ArgAction::SetTrue)
                        .help(SKIP_SIZE_CHECK_HELP),
                )
                .arg(
                    Arg::new("skip-md5")
                        .long("skip-md5")
                        .action(ArgAction::SetTrue)
                        .help("Skip MD5 checksum verification"),
                )
                .arg(Arg::new("pit").long("pit").num_args(1).help(PIT_HELP))
                .arg(
                    Arg::new("bl")
                        .short('b')
                        .long("BL")
                        .num_args(1)
                        .help("BL tar package file"),
                )
                .arg(
                    Arg::new("ap")
                        .short('a')
                        .long("AP")
                        .num_args(1)
                        .help("AP tar package file"),
                )
                .arg(
                    Arg::new("cp")
                        .short('c')
                        .long("CP")
                        .num_args(1)
                        .help("CP tar package file"),
                )
                .arg(
                    Arg::new("csc")
                        .short('s')
                        .long("CSC")
                        .num_args(1)
                        .help("CSC/HOME_CSC tar package file"),
                )
                .arg(
                    Arg::new("userdata")
                        .short('u')
                        .long("USERDATA")
                        .num_args(1)
                        .help("USERDATA tar package file"),
                )
                .arg(
                    Arg::new("partition")
                        .short('p')
                        .long("partition")
                        .action(ArgAction::Append)
                        .num_args(2)
                        .value_names(["PARTITION", "FILE"])
                        .help("Explicit partition name/identifier and file to flash"),
                )
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .action(ArgAction::Append)
                        .num_args(1)
                        .value_name("FILE")
                        .help("Automatic partition name matching file to flash"),
                ),
        )
        .get_matches();

    let verbose = matches.get_flag("verbose");
    let usb_log_level = matches
        .get_one::<String>("usb-log-level")
        .map(|s| s.as_str())
        .unwrap_or("");

    let result = match matches.subcommand() {
        Some(("download", sub_m)) => {
            let model = sub_m.get_one::<String>("model").cloned().unwrap();
            let region = sub_m.get_one::<String>("region").cloned().unwrap();
            let version = sub_m.get_one::<String>("version").cloned();
            let threads = *sub_m.get_one::<u64>("threads").unwrap();
            let out_dir = sub_m.get_one::<String>("out_dir").cloned();
            let out_file = sub_m.get_one::<String>("out_file").cloned();
            let args = download::DownloadArgs {
                model,
                region,
                version,
                threads,
                out_dir,
                out_file,
            };
            download::action_download(args);
            0
        }
        Some(("check-update", sub_m)) => {
            let model = sub_m.get_one::<String>("model").cloned().unwrap();
            let region = sub_m.get_one::<String>("region").cloned().unwrap();
            let show_all = sub_m.get_one::<bool>("all").copied().unwrap_or(false);

            let info = fetch_version_info(&model, &region).expect("Failed to fetch version info");

            if show_all {
                for v in &info.upgrade {
                    println!("{}", v);
                }
            }
            println!("{}", info.latest);
            0
        }
        Some(("detect", sub_matches)) => {
            actions::action_detect(verbose, sub_matches.get_flag("wait"), usb_log_level)
        }
        Some(("dump-pit", sub_matches)) => actions::action_dump_pit(
            sub_matches.get_one::<String>("output").unwrap(),
            verbose,
            sub_matches.get_flag("wait"),
            usb_log_level,
        ),
        Some(("print-pit", sub_matches)) => actions::action_print_pit(
            sub_matches
                .get_one::<String>("file")
                .map(|s| s.as_str())
                .unwrap_or(""),
            verbose,
            sub_matches.get_flag("wait"),
            usb_log_level,
        ),
        Some(("flash", sub_matches)) => {
            let mut packages = Vec::new();
            if let Some(bl) = sub_matches.get_one::<String>("bl") {
                packages.push(bl.clone());
            }
            if let Some(ap) = sub_matches.get_one::<String>("ap") {
                packages.push(ap.clone());
            }
            if let Some(cp) = sub_matches.get_one::<String>("cp") {
                packages.push(cp.clone());
            }
            if let Some(csc) = sub_matches.get_one::<String>("csc") {
                packages.push(csc.clone());
            }
            if let Some(userdata) = sub_matches.get_one::<String>("userdata") {
                packages.push(userdata.clone());
            }

            let mut partitions = Vec::new();
            if let Some(args) = sub_matches.get_many::<String>("partition") {
                let args_vec: Vec<&String> = args.collect();
                let mut i = 0;
                while i < args_vec.len() {
                    if i + 1 < args_vec.len() {
                        partitions.push(PartitionArg {
                            name: Some(args_vec[i].to_uppercase()),
                            filename: args_vec[i + 1].clone(),
                        });
                        i += 2;
                    }
                }
            }
            if let Some(files) = sub_matches.get_many::<String>("file") {
                for file in files {
                    partitions.push(PartitionArg {
                        name: None,
                        filename: file.clone(),
                    });
                }
            }

            if packages.is_empty() && partitions.is_empty() {
                print_error!("No packages, files, or partitions specified for flashing.");
                std::process::exit(1);
            }

            let result = flash::action_flash(
                sub_matches.get_flag("repartition"),
                verbose,
                sub_matches.get_flag("wait"),
                usb_log_level,
                sub_matches.get_flag("skip-size-check"),
                sub_matches.get_flag("skip-md5"),
                sub_matches.get_one::<String>("pit").map(|s| s.as_str()),
                &packages,
                &partitions,
            );
            std::process::exit(result);
        }
        _ => unreachable!(),
    };

    std::process::exit(result);
}
