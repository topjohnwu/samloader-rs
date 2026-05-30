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
mod download_pit;
mod flash;
mod print_pit;
mod tar_flash;

use clap::{Arg, ArgAction, Command};

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
const PACKAGES_HELP: &str = "One or more .tar or .tar.md5 firmware package files.";

const DETECT_ABOUT: &str = "Indicates whether or not a download mode device can be detected.";
const DETECT_HELP: &str = r#"Indicates whether or not a download mode device can be detected.

Returns instantly per default, or waits until device is found
when --wait argument is used."#;

const DOWNLOAD_PIT_ABOUT: &str =
    "Downloads the connected device's PIT file to the specified output file.";
const DOWNLOAD_PIT_HELP: &str = r#"Downloads the connected device's PIT file to the specified
output file."#;
const DOWNLOAD_PIT_OUTPUT_HELP: &str = "Output file path for the downloaded PIT file.";

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

const PARTITIONS_AND_FILES_HELP: &str = r#"Pairs of partition names (or identifiers) and filenames to flash.

Flashes the specified <FILE> to the specified <PARTITION>.
If <PARTITION> is "@", the destination partition is automatically determined
from the filename (ignoring casing and optional .lz4 suffix).

Example: heimdall flash RECOVERY recovery.img BOOT boot.img
Example with auto-matching: heimdall flash @ recovery.img @ boot.img"#;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let matches = Command::new("heimdall")
        .about("Heimdall - Glass Echidna")
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
            Command::new("download-pit")
                .about(DOWNLOAD_PIT_ABOUT)
                .long_about(DOWNLOAD_PIT_HELP)
                .arg(
                    Arg::new("output")
                        .long("output")
                        .required(true)
                        .num_args(1)
                        .help(DOWNLOAD_PIT_OUTPUT_HELP),
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
                    Arg::new("packages")
                        .required(true)
                        .action(ArgAction::Append)
                        .num_args(1..)
                        .value_name("PACKAGE")
                        .help(PACKAGES_HELP),
                ),
        )
        .get_matches_from(args);

    let verbose = matches.get_flag("verbose");
    let usb_log_level = matches
        .get_one::<String>("usb-log-level")
        .map(|s| s.as_str())
        .unwrap_or("");

    let result = match matches.subcommand() {
        Some(("detect", sub_matches)) => {
            detect::action_detect(verbose, sub_matches.get_flag("wait"), usb_log_level)
        }
        Some(("download-pit", sub_matches)) => download_pit::action_download_pit(
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
            let packages: Vec<String> = sub_matches
                .get_many::<String>("packages")
                .unwrap()
                .cloned()
                .collect();
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
