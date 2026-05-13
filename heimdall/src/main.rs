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

mod bridge_manager;
mod packets;
pub use crate::bridge_manager::BridgeManager;

use clap::{Arg, Command, ArgAction};

#[cxx::bridge(namespace = "Heimdall")]
pub mod ffi {
    enum InitialiseResult {
        Succeeded = 0,
        Failed,
        DeviceNotDetected,
    }

    enum FileTransferDestination {
        Phone = 0,
        Modem = 1,
    }

    struct PartitionArg {
        name: String,
        filename: String,
    }

    extern "Rust" {
        type BridgeManager;

        #[Self = "BridgeManager"]
        fn create(verbose: bool, wait_for_device: bool) -> Box<BridgeManager>;

        #[cxx_name = "SetUsbLogLevel"]
        fn set_usb_log_level(self: &mut BridgeManager, level: &str);
        #[cxx_name = "DetectDevice"]
        fn detect_device(self: &mut BridgeManager) -> bool;
        #[cxx_name = "Initialise"]
        fn initialise(self: &mut BridgeManager) -> InitialiseResult;

        #[cxx_name = "BeginSession"]
        fn begin_session(self: &mut BridgeManager) -> bool;
        #[cxx_name = "EndSession"]
        fn end_session(self: &BridgeManager) -> bool;

        #[cxx_name = "SendTotalBytes"]
        fn send_total_bytes(self: &BridgeManager, total_bytes: u64) -> bool;
        #[cxx_name = "ReceiveSessionSetupResponse"]
        fn receive_session_setup_response(self: &BridgeManager, result: &mut u32) -> bool;

        #[cxx_name = "SendPitData"]
        fn send_pit_data(self: &BridgeManager, pit_data: &PitData) -> bool;
        #[cxx_name = "DownloadPitFile"]
        fn download_pit_file(self: &BridgeManager) -> Vec<u8>;

        #[cxx_name = "SendFile"]
        unsafe fn send_file(
            self: &BridgeManager,
            file: *mut FILE,
            destination: FileTransferDestination,
            device_type: u32,
            file_identifier: u32,
        ) -> bool;
    }

    unsafe extern "C++" {
        #[namespace = ""]
        type FILE;

        include!("heimdall/source/ActionInterfaces.h");
        include!("heimdall/source/Interface.h");
        include!("heimdall/libpit/src/lib.rs.h");

        #[namespace = "libpit"]
        type PitData;

        fn action_detect(verbose: bool, wait: bool, usb_log_level: &str) -> i32;
        fn action_download_pit(output: &str, verbose: bool, wait: bool, usb_log_level: &str) -> i32;
        fn action_print_pit(file: &str, verbose: bool, wait: bool, usb_log_level: &str) -> i32;
        fn action_flash(repartition: bool, verbose: bool, wait: bool, usb_log_level: &str, skip_size_check: bool, pit: &str, partitions: &Vec<PartitionArg>) -> i32;

        fn action_info() -> i32;
        fn action_version() -> i32;
    }
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

fn add_common_args(cmd: Command) -> Command {
    cmd.arg(Arg::new("verbose").long("verbose").action(ArgAction::SetTrue).help("Enable verbose output"))
       .arg(Arg::new("usb-log-level").long("usb-log-level").num_args(1).help("Set libusb log level (none, error, warning, info, debug)"))
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

const FLASH_AFTER_HELP: &str = r#"Dynamic Options:
      --<partition name> <filename>
          Flashes the specified <filename> to the specified <partition name>.
          Example: heimdall flash --RECOVERY recovery.img --BOOT boot.img

      --<partition identifier> <filename>
          Flashes the specified <filename> to the specified <partition identifier>."#;

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let mut partitions = Vec::new();

    // Filter out partition arguments for the flash command
    if args.len() > 1 && args[1] == "flash" {
        let mut i = 2;
        while i < args.len() {
            if args[i].starts_with("--") {
                let key = args[i].trim_start_matches('-').to_string();
                if !["repartition", "wait", "skip-size-check", "pit", "verbose", "usb-log-level"].contains(&key.to_lowercase().as_str()) {
                    if i + 1 < args.len() && !args[i+1].starts_with("--") {
                        partitions.push(ffi::PartitionArg {
                            name: key.to_uppercase(),
                            filename: args[i+1].clone(),
                        });
                        args.remove(i); // Remove value
                        args.remove(i); // Remove key
                        continue;
                    }
                }
            }
            i += 1;
        }
    }

    let matches = Command::new("heimdall")
        .about("Heimdall - Glass Echidna")
        .subcommand_required(true)
        .arg_required_else_help(true)
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
            .arg(Arg::new("repartition").long("repartition").action(ArgAction::SetTrue).help("Repartition the device. WARNING: It's strongly recommended you specify all files at your disposal."))
            .arg(Arg::new("wait").long("wait").action(ArgAction::SetTrue).help("Waits until a compatible device is connected."))
            .arg(Arg::new("skip-size-check").long("skip-size-check").action(ArgAction::SetTrue).help("Do not verify that files fit in the specified partition."))
            .arg(Arg::new("pit").long("pit").num_args(1).help("The PIT file to use for repartitioning or flashing.")))
        .subcommand(Command::new("info")
            .about("Displays information about Heimdall."))
        .subcommand(Command::new("version")
            .about("Displays the version number of this binary."))
        .get_matches_from(args);

    let result = match matches.subcommand() {
        Some(("detect", sub_matches)) => {
            ffi::action_detect(
                sub_matches.get_flag("verbose"),
                sub_matches.get_flag("wait"),
                sub_matches.get_one::<String>("usb-log-level").map(|s| s.as_str()).unwrap_or(""),
            )
        }
        Some(("download-pit", sub_matches)) => {
            ffi::action_download_pit(
                sub_matches.get_one::<String>("output").unwrap(),
                sub_matches.get_flag("verbose"),
                sub_matches.get_flag("wait"),
                sub_matches.get_one::<String>("usb-log-level").map(|s| s.as_str()).unwrap_or(""),
            )
        }
        Some(("print-pit", sub_matches)) => {
            ffi::action_print_pit(
                sub_matches.get_one::<String>("file").map(|s| s.as_str()).unwrap_or(""),
                sub_matches.get_flag("verbose"),
                sub_matches.get_flag("wait"),
                sub_matches.get_one::<String>("usb-log-level").map(|s| s.as_str()).unwrap_or(""),
            )
        }
        Some(("flash", sub_matches)) => {
            ffi::action_flash(
                sub_matches.get_flag("repartition"),
                sub_matches.get_flag("verbose"),
                sub_matches.get_flag("wait"),
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
