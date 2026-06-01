// Copyright 2026 Google LLC
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

mod detect;
mod download;
mod dump_pit;
mod flash;
mod print_pit;
mod tar_flash;

use clap::{Arg, ArgAction, Command};
use download::{DownloadArgs, download_latest_firmware};
use samloader_fus::FusClient;

pub(crate) struct PartitionArg {
    pub(crate) name: String,
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
const PARTITIONS_AND_FILES_HELP_BRIEF: &str =
    "Pairs of partition names/identifiers and filenames to flash.";

const DETECT_ABOUT: &str = "Indicates whether or not a download mode device can be detected.";
const DETECT_HELP: &str = r#"Indicates whether or not a download mode device can be detected.

Returns instantly per default, or waits until device is found
when --wait argument is used."#;

const DUMP_PIT_ABOUT: &str =
    "Downloads the connected device's PIT file to the specified output file.";
const DUMP_PIT_HELP: &str = r#"Downloads the connected device's PIT file to the specified
output file."#;
const DUMP_PIT_OUTPUT_HELP: &str = "Output file path for the downloaded PIT file.";

const PRINT_PIT_ABOUT: &str = "Prints the contents of a PIT file in a human readable format.";
const PRINT_PIT_HELP: &str = r#"Prints the contents of a PIT file in a human readable format. If
a filename is not provided then Heimdall retrieves the PIT file from the
connected device."#;
const PRINT_PIT_FILE_HELP: &str = "The PIT file to print. If not provided, Heimdall retrieves the PIT file from the connected device.";

const FLASH_ABOUT: &str = "Flashes one or more firmware files to your phone.";
const FLASH_HELP: &str = r#"Flashes one or more firmware files to your phone. Partition names
(or identifiers) can be obtained by executing the print-pit action.
Using "@" as a partition name automatically determines the destination
partition based on the filename."#;

const TAR_FLASH_ABOUT: &str = "Flashes Samsung firmware TAR/MD5 packages to your phone.";
const TAR_FLASH_HELP: &str = r#"Flashes one or more Samsung firmware TAR/MD5 packages to your phone.
The files within the packages are indexed and flashed in-memory, without
unpacking them to disk."#;

const NO_PACKAGES_ERROR: &str = "No packages specified for flashing. Please specify at least one of BL, AP, CP, CSC, or USERDATA.";

const PARTITIONS_AND_FILES_HELP: &str = r#"Pairs of partition names (or identifiers) and filenames to flash.

Flashes the specified <FILE> to the specified <PARTITION>.
If <PARTITION> is "@", the destination partition is automatically determined
from the filename (ignoring casing and optional .lz4 suffix).

Example: samloader flash RECOVERY recovery.img BOOT boot.img
Example with auto-matching: samloader flash @ recovery.img @ boot.img"#;

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
                .arg(Arg::new("pit").long("pit").num_args(1).help(PIT_HELP))
                .arg(
                    Arg::new("partitions-and-files")
                        .required(true)
                        .action(ArgAction::Append)
                        .num_args(1..)
                        .value_names(["PARTITION", "FILE"])
                        .help(PARTITIONS_AND_FILES_HELP_BRIEF)
                        .long_help(PARTITIONS_AND_FILES_HELP),
                ),
        )
        .subcommand(
            Command::new("tar-flash")
                .about(TAR_FLASH_ABOUT)
                .long_about(TAR_FLASH_HELP)
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
                        .help("CSC tar package file"),
                )
                .arg(
                    Arg::new("userdata")
                        .short('u')
                        .long("USERDATA")
                        .num_args(1)
                        .help("USERDATA tar package file"),
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
            0
        }
        Some(("check-update", sub_m)) => {
            let model = sub_m.get_one::<String>("model").cloned().unwrap();
            let region = sub_m.get_one::<String>("region").cloned().unwrap();
            let mut client = FusClient::new().expect("Unable to establish FusClient");
            client.fetch_binary_info(&model, &region);
            println!("{}", client.info.version);
            0
        }
        Some(("detect", sub_matches)) => {
            detect::action_detect(verbose, sub_matches.get_flag("wait"), usb_log_level)
        }
        Some(("dump-pit", sub_matches)) => dump_pit::action_dump_pit(
            sub_matches.get_one::<String>("output").unwrap(),
            verbose,
            sub_matches.get_flag("wait"),
            usb_log_level,
        ),
        Some(("print-pit", sub_matches)) => print_pit::action_print_pit(
            sub_matches
                .get_one::<String>("file")
                .map(|s| s.as_str())
                .unwrap_or(""),
            verbose,
            sub_matches.get_flag("wait"),
            usb_log_level,
        ),
        Some(("flash", sub_matches)) => {
            let mut partitions = Vec::new();
            if let Some(args) = sub_matches.get_many::<String>("partitions-and-files") {
                let args_vec: Vec<&String> = args.collect();
                let mut i = 0;
                while i < args_vec.len() {
                    if i + 1 < args_vec.len() {
                        partitions.push(PartitionArg {
                            name: args_vec[i].to_uppercase(),
                            filename: args_vec[i + 1].clone(),
                        });
                        i += 2;
                    } else {
                        print_error!("Partition \"{}\" is not paired with a file.", args_vec[i]);
                        std::process::exit(1);
                    }
                }
            }
            flash::action_flash(
                sub_matches.get_flag("repartition"),
                verbose,
                sub_matches.get_flag("wait"),
                usb_log_level,
                sub_matches.get_flag("skip-size-check"),
                sub_matches.get_one::<String>("pit").map(|s| s.as_str()),
                &partitions,
            )
        }
        Some(("tar-flash", sub_matches)) => {
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

            if packages.is_empty() {
                print_error!("{}", NO_PACKAGES_ERROR);
                std::process::exit(1);
            }

            tar_flash::action_tar_flash(
                sub_matches.get_flag("repartition"),
                verbose,
                sub_matches.get_flag("wait"),
                usb_log_level,
                sub_matches.get_flag("skip-size-check"),
                sub_matches.get_one::<String>("pit").map(|s| s.as_str()),
                &packages,
            )
        }
        _ => unreachable!(),
    };

    std::process::exit(result);
}
