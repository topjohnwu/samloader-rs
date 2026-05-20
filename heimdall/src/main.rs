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

mod bridge_manager;
mod detect;
mod download_pit;
mod flash;
mod packets;
mod print_pit;
mod version;

use bridge_manager::BridgeManager;
use clap::{Arg, ArgAction, Command};

pub(crate) struct PartitionArg {
    pub(crate) name: String,
    pub(crate) filename: String,
}

#[macro_export]
macro_rules! print_warning {
    ($($arg:tt)*) => {
        eprint!("WARNING: ");
        eprintln!($($arg)*);
    };
}

#[macro_export]
macro_rules! print_error {
    ($($arg:tt)*) => {
        eprint!("ERROR: ");
        eprintln!($($arg)*);
    };
}

const DETECT_HELP: &str = r#"Indicates whether or not a download mode device can be detected.

Returns instantly per default, or waits until device is found
when --wait argument is used."#;

const DOWNLOAD_PIT_HELP: &str = r#"Downloads the connected device's PIT file to the specified
output file."#;

const PRINT_PIT_HELP: &str = r#"Prints the contents of a PIT file in a human readable format. If
a filename is not provided then Heimdall retrieves the PIT file from the
connected device."#;

const FLASH_HELP: &str = r#"Flashes one or more firmware files to your phone. Partition names
(or identifiers) can be obtained by executing the print-pit action."#;

const PARTITIONS_AND_FILES_HELP: &str = r#"Pairs of partition names (or identifiers) and filenames to flash.

Flashes the specified <FILE> to the specified <PARTITION>.
Example: heimdall flash RECOVERY recovery.img BOOT boot.img"#;

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
                .help("Enable verbose output"),
        )
        .arg(
            Arg::new("usb-log-level")
                .long("usb-log-level")
                .num_args(1)
                .global(true)
                .help("Set libusb log level (none, error, warning, info, debug)"),
        )
        .subcommand(Command::new("detect")
            .about("Indicates whether or not a download mode device can be detected.")
            .long_about(DETECT_HELP)
            .arg(Arg::new("wait").long("wait").action(ArgAction::SetTrue).help("Waits until a compatible device is connected.")))
        .subcommand(Command::new("download-pit")
            .about("Downloads the connected device's PIT file to the specified output file.")
            .long_about(DOWNLOAD_PIT_HELP)
            .arg(Arg::new("output").long("output").required(true).num_args(1).help("Output file path for the downloaded PIT file."))
            .arg(Arg::new("wait").long("wait").action(ArgAction::SetTrue).help("Waits until a compatible device is connected.")))
        .subcommand(Command::new("print-pit")
            .about("Prints the contents of a PIT file in a human readable format.")
            .long_about(PRINT_PIT_HELP)
            .arg(Arg::new("file").long("file").num_args(1).help("The PIT file to print. If not provided, Heimdall retrieves the PIT file from the connected device."))
            .arg(Arg::new("wait").long("wait").action(ArgAction::SetTrue).help("Waits until a compatible device is connected.")))
        .subcommand(Command::new("flash")
            .about("Flashes one or more firmware files to your phone.")
            .long_about(FLASH_HELP)
            .arg(Arg::new("repartition").long("repartition").action(ArgAction::SetTrue).help("Repartition the device. WARNING: It's strongly recommended you specify all files at your disposal."))
            .arg(Arg::new("wait").long("wait").action(ArgAction::SetTrue).help("Waits until a compatible device is connected."))
            .arg(Arg::new("skip-size-check").long("skip-size-check").action(ArgAction::SetTrue).help("Do not verify that files fit in the specified partition."))
            .arg(Arg::new("pit").long("pit").num_args(1).help("The PIT file to use for repartitioning or flashing."))
            .arg(Arg::new("partitions-and-files")
                .action(ArgAction::Append)
                .num_args(1..)
                .value_names(["PARTITION", "FILE"])
                .help("Pairs of partition names/identifiers and filenames to flash.")
                .long_help(PARTITIONS_AND_FILES_HELP)))
        .subcommand(Command::new("info")
            .about("Displays information about Heimdall."))
        .subcommand(Command::new("version")
            .about("Displays the version number of this binary."))
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
                sub_matches
                    .get_one::<String>("pit")
                    .map(|s| s.as_str())
                    .unwrap_or(""),
                &partitions,
            )
        }
        Some(("info", _)) => {
            version::print_full_info();
            0
        }
        Some(("version", _)) => {
            version::print_version();
            0
        }
        _ => unreachable!(),
    };

    std::process::exit(result);
}
