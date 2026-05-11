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

extern crate libpit;

use clap::{Arg, Command, ArgAction};

#[cxx::bridge(namespace = "Heimdall")]
pub mod ffi {
    struct PartitionArg {
        name: String,
        filename: String,
    }

    unsafe extern "C++" {
        include!("heimdall/source/ActionInterfaces.h");

        fn action_close_pc_screen(verbose: bool, stdout_errors: bool, usb_log_level: &str) -> i32;
        fn action_detect(verbose: bool, wait: bool, stdout_errors: bool, usb_log_level: &str) -> i32;
        fn action_download_pit(output: &str, verbose: bool, wait: bool, stdout_errors: bool, usb_log_level: &str) -> i32;
        fn action_print_pit(file: &str, verbose: bool, wait: bool, stdout_errors: bool, usb_log_level: &str) -> i32;
        fn action_flash(repartition: bool, verbose: bool, wait: bool, stdout_errors: bool, usb_log_level: &str, skip_size_check: bool, pit: &str, partitions: &Vec<PartitionArg>) -> i32;
        
        fn action_info() -> i32;
        fn action_version() -> i32;
    }
}

fn add_common_args(cmd: Command) -> Command {
    cmd.arg(Arg::new("verbose").long("verbose").action(ArgAction::SetTrue).help("Enable verbose output"))
       .arg(Arg::new("stdout-errors").long("stdout-errors").action(ArgAction::SetTrue).help("Log errors to stdout instead of stderr"))
       .arg(Arg::new("usb-log-level").long("usb-log-level").num_args(1).help("Set libusb log level (none, error, warning, info, debug)"))
}

const CLOSE_PC_SCREEN_HELP: &str = r#"Attempts to get rid off the "connect phone to PC" screen."#;

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

const FLASH_AFTER_HELP: &str = r#"Dynamic Options:
      --<partition name> <filename>
          Flashes the specified <filename> to the specified <partition name>.
          Example: heimdall flash --RECOVERY recovery.img --BOOT boot.img

      --<partition identifier> <filename>
          Flashes the specified <filename> to the specified <partition identifier>."#;

fn main() {
    let matches = Command::new("heimdall")
        .about("Heimdall - Glass Echidna")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(add_common_args(Command::new("close-pc-screen"))
            .about("Attempts to get rid off the \"connect phone to PC\" screen.")
            .long_about(CLOSE_PC_SCREEN_HELP))
        .subcommand(add_common_args(Command::new("detect"))
            .about("Indicates whether or not a download mode device can be detected.")
            .long_about(DETECT_HELP)
            .arg(Arg::new("wait").long("wait").action(ArgAction::SetTrue).help("Waits until a compatible device is connected.")))
        .subcommand(add_common_args(Command::new("download-pit"))
            .about("Downloads the connected device's PIT file to the specified output file.")
            .long_about(DOWNLOAD_PIT_HELP)
            .arg(Arg::new("output").long("output").required(true).num_args(1).help("Output file path for the downloaded PIT file."))
            .arg(Arg::new("wait").long("wait").action(ArgAction::SetTrue).help("Waits until a compatible device is connected.")))
        .subcommand(add_common_args(Command::new("print-pit"))
            .about("Prints the contents of a PIT file in a human readable format.")
            .long_about(PRINT_PIT_HELP)
            .arg(Arg::new("file").long("file").num_args(1).help("The PIT file to print. If not provided, Heimdall retrieves the PIT file from the connected device."))
            .arg(Arg::new("wait").long("wait").action(ArgAction::SetTrue).help("Waits until a compatible device is connected.")))
        .subcommand(add_common_args(Command::new("flash"))
            .about("Flashes one or more firmware files to your phone.")
            .long_about(FLASH_HELP)
            .after_help(FLASH_AFTER_HELP)
            .ignore_errors(true)
            .arg(Arg::new("repartition").long("repartition").action(ArgAction::SetTrue).help("Repartition the device. WARNING: It's strongly recommended you specify all files at your disposal."))
            .arg(Arg::new("wait").long("wait").action(ArgAction::SetTrue).help("Waits until a compatible device is connected."))
            .arg(Arg::new("skip-size-check").long("skip-size-check").action(ArgAction::SetTrue).help("Do not verify that files fit in the specified partition."))
            .arg(Arg::new("pit").long("pit").num_args(1).help("The PIT file to use for repartitioning or flashing.")))
        .subcommand(Command::new("info")
            .about("Displays information about Heimdall."))
        .subcommand(Command::new("version")
            .about("Displays the version number of this binary."))
        .get_matches();

    let result = match matches.subcommand() {
        Some(("close-pc-screen", sub_matches)) => {
            ffi::action_close_pc_screen(
                sub_matches.get_flag("verbose"),
                sub_matches.get_flag("stdout-errors"),
                sub_matches.get_one::<String>("usb-log-level").map(|s| s.as_str()).unwrap_or(""),
            )
        }
        Some(("detect", sub_matches)) => {
            ffi::action_detect(
                sub_matches.get_flag("verbose"),
                sub_matches.get_flag("wait"),
                sub_matches.get_flag("stdout-errors"),
                sub_matches.get_one::<String>("usb-log-level").map(|s| s.as_str()).unwrap_or(""),
            )
        }
        Some(("download-pit", sub_matches)) => {
            ffi::action_download_pit(
                sub_matches.get_one::<String>("output").unwrap(),
                sub_matches.get_flag("verbose"),
                sub_matches.get_flag("wait"),
                sub_matches.get_flag("stdout-errors"),
                sub_matches.get_one::<String>("usb-log-level").map(|s| s.as_str()).unwrap_or(""),
            )
        }
        Some(("print-pit", sub_matches)) => {
            ffi::action_print_pit(
                sub_matches.get_one::<String>("file").map(|s| s.as_str()).unwrap_or(""),
                sub_matches.get_flag("verbose"),
                sub_matches.get_flag("wait"),
                sub_matches.get_flag("stdout-errors"),
                sub_matches.get_one::<String>("usb-log-level").map(|s| s.as_str()).unwrap_or(""),
            )
        }
        Some(("flash", sub_matches)) => {
            let mut partitions = vec![];
            
            // Collect unparsed arguments to form partition-filename pairs
            let mut raw_args = std::env::args().skip(2).peekable();
            while let Some(arg) = raw_args.next() {
                if arg.starts_with("--") {
                    let name = arg.trim_start_matches("--");
                    // Skip known arguments
                    match name {
                        "repartition" | "verbose" | "stdout-errors" | "wait" | "skip-size-check" => continue,
                        "usb-log-level" | "pit" => {
                            raw_args.next(); // Skip value
                            continue;
                        }
                        _ => {
                            if let Some(filename) = raw_args.next() {
                                partitions.push(ffi::PartitionArg {
                                    name: name.to_string(),
                                    filename,
                                });
                            }
                        }
                    }
                }
            }
            
            ffi::action_flash(
                sub_matches.get_flag("repartition"),
                sub_matches.get_flag("verbose"),
                sub_matches.get_flag("wait"),
                sub_matches.get_flag("stdout-errors"),
                sub_matches.get_one::<String>("usb-log-level").map(|s| s.as_str()).unwrap_or(""),
                sub_matches.get_flag("skip-size-check"),
                sub_matches.get_one::<String>("pit").map(|s| s.as_str()).unwrap_or(""),
                &partitions,
            )
        }
        Some(("info", _)) => ffi::action_info(),
        Some(("version", _)) => ffi::action_version(),
        _ => unreachable!(),
    };
    
    std::process::exit(result);
}
