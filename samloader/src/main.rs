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

#[cfg(not(any(feature = "rusb", feature = "nusb", feature = "serialport")))]
compile_error!("At least one USB backend must be enabled!");

mod actions;
mod download;
mod flash;

use clap::{Arg, ArgAction, Command};
use samloader_fus::{FusClient, fetch_version_xml};
use samloader_odin::UsbBackendOption;

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

// =============================================================================
// CLI String Constants
// =============================================================================

// --- Global Options ---
const VERBOSE_HELP: &str = "Enable verbose output";
const WAIT_HELP: &str = "Waits until a compatible device is connected";
const USB_BACKEND_HELP: &str = "The USB backend to use";

// --- Common Subcommand Options ---
const MODEL_HELP: &str = "The model name (e.g. SM-S931U1)";
const REGION_HELP: &str = "Region CSC code (e.g. XAA)";

// --- Download Command (`download`) ---
const VERSION_HELP: &str =
    "Firmware version string (e.g. PDA/CSC/MODEM). If omitted, downloads the latest";
const THREADS_HELP: &str = "Number of parallel connections";
const OUT_DIR_HELP: &str = "Output directory";
const OUT_FILE_HELP: &str = "Output file path";

// --- Check Update Command (`check-update`) ---
const ALL_HELP: &str =
    "List all available firmware versions, with previous and beta sorted from new to old";

// --- Detect Command (`detect`) ---
const DETECT_ABOUT: &str = "Indicates whether or not a download mode device can be detected";
const DETECT_HELP: &str = r#"Indicates whether or not a download mode device can be detected

Returns instantly per default, or waits until device is found
when --wait argument is used"#;

// --- Dump PIT Command (`dump-pit`) ---
const DUMP_PIT_ABOUT: &str = "Dumps the connected device's PIT file to the specified output file";
const DUMP_PIT_HELP: &str = r#"Dumps the connected device's PIT file to the specified
output file"#;
const DUMP_PIT_OUTPUT_HELP: &str = "Output file path for the dumped PIT file";

// --- Print PIT Command (`print-pit`) ---
const PRINT_PIT_ABOUT: &str = "Prints the contents of a PIT file in a human readable format";
const PRINT_PIT_HELP: &str = r#"Prints the contents of a PIT file in a human readable format. If
a filename is not provided then Heimdall retrieves the PIT file from the
connected device"#;
const PRINT_PIT_FILE_HELP: &str = "The PIT file to print. If not provided, Heimdall retrieves \
                                   the PIT file from the connected device";

// --- Flash Command (`flash`) ---
const FLASH_ABOUT: &str = "Flashes one or more firmware files to your phone";
const FLASH_HELP: &str = r#"Flashes one or more firmware files to your phone. Partition names
(or identifiers) can be obtained by executing the print-pit action.

Example explicit flashing: samloader flash -p RECOVERY recovery.img
Example auto-matching: samloader flash -f boot.img"#;

const NO_REBOOT_HELP: &str = "Disables automatic reboot after flashing";
const REPARTITION_HELP: &str = "Repartition the device. WARNING: It's strongly recommended \
                                you specify all files at your disposal";
const SKIP_SIZE_CHECK_HELP: &str = "Do not verify that files fit in the specified partition";
const PIT_HELP: &str = "The PIT file to use for repartitioning or flashing";
const SKIP_MD5_HELP: &str = "Skip MD5 checksum verification";
const BL_HELP: &str = "BL tar package file";
const AP_HELP: &str = "AP tar package file";
const CP_HELP: &str = "CP tar package file";
const CSC_HELP: &str = "CSC/HOME_CSC tar package file";
const USERDATA_HELP: &str = "USERDATA tar package file";
const PARTITION_HELP: &str = "Explicit partition name/identifier and file to flash";
const FILE_HELP: &str = "Automatic partition name matching file to flash";

// --- Verify MD5 Command (`verify-md5`) ---
const VERIFY_MD5_ABOUT: &str = "Verifies the MD5 checksum of one or more .tar.md5 files";
const VERIFY_MD5_FILE_HELP: &str = "The .tar.md5 files to verify";

trait FusOptionExt {
    fn fus_options(self) -> Self;
}

impl FusOptionExt for Command {
    fn fus_options(self) -> Self {
        self.arg(
            Arg::new("model")
                .short('m')
                .long("model")
                .required(true)
                .help(MODEL_HELP),
        )
        .arg(
            Arg::new("region")
                .short('r')
                .long("region")
                .required(true)
                .help(REGION_HELP),
        )
    }
}

trait OdinOptionExt {
    fn odin_options(self) -> Self;
}

impl OdinOptionExt for Command {
    fn odin_options(self) -> Self {
        self.arg(
            Arg::new("wait")
                .long("wait")
                .action(ArgAction::SetTrue)
                .help(WAIT_HELP),
        )
        .arg(
            Arg::new("no-reboot")
                .long("no-reboot")
                .action(ArgAction::SetTrue)
                .help(NO_REBOOT_HELP),
        )
    }
}

fn main() {
    let enabled_backends: &[&'static str] = &[
        #[cfg(feature = "nusb")]
        From::from(UsbBackendOption::Nusb),
        #[cfg(feature = "rusb")]
        From::from(UsbBackendOption::Libusb),
        #[cfg(feature = "serialport")]
        From::from(UsbBackendOption::Vcom),
    ];

    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "windows", feature = "serialport"))] {
            let default_backend: &str = From::from(UsbBackendOption::Vcom);
        } else {
            let default_backend: &str = enabled_backends.first().unwrap();
        }
    }

    #[allow(unused_mut)]
    let mut cmd = Command::new("samloader")
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
        // On Windows, the default USB backend is set to VCOM rather than libusb.
        // This is because libusb requires replacing the standard device driver
        // with a WinUSB/generic driver (e.g., using a utility like Zadig).
        // This manual driver swap breaks compatibility with the official
        // Samsung USB drivers, creating a poor user experience.
        // In contrast, the VCOM (Virtual COM Port/usbser.sys) implementation
        // on Windows works out-of-the-box, requires no special driver
        // modifications, and performs extremely fast.
        .arg(
            Arg::new("usb_backend")
                .long("usb-backend")
                .global(true)
                .default_value(default_backend)
                .value_parser(enabled_backends.to_vec())
                .help(USB_BACKEND_HELP),
        )
        .subcommand(
            Command::new("download")
                .about("Download firmware")
                .fus_options()
                .arg(
                    Arg::new("version")
                        .short('v')
                        .long("version")
                        .help(VERSION_HELP),
                )
                .arg(
                    Arg::new("threads")
                        .short('j')
                        .long("threads")
                        .default_value("8")
                        .value_parser(clap::value_parser!(u64))
                        .help(THREADS_HELP),
                )
                .arg(
                    Arg::new("out_dir")
                        .short('d')
                        .long("out-dir")
                        .help(OUT_DIR_HELP),
                )
                .arg(
                    Arg::new("out_file")
                        .short('o')
                        .long("out-file")
                        .help(OUT_FILE_HELP),
                ),
        )
        .subcommand(
            Command::new("check-update")
                .about("Check available versions")
                .fus_options()
                .arg(
                    Arg::new("all")
                        .short('a')
                        .long("all")
                        .help(ALL_HELP)
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
                .odin_options()
                .arg(
                    Arg::new("output")
                        .long("output")
                        .required(true)
                        .num_args(1)
                        .help(DUMP_PIT_OUTPUT_HELP),
                ),
        )
        .subcommand(
            Command::new("print-pit")
                .about(PRINT_PIT_ABOUT)
                .long_about(PRINT_PIT_HELP)
                .odin_options()
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .num_args(1)
                        .help(PRINT_PIT_FILE_HELP),
                ),
        )
        .subcommand(
            Command::new("flash")
                .about(FLASH_ABOUT)
                .long_about(FLASH_HELP)
                .odin_options()
                .arg(
                    Arg::new("repartition")
                        .long("repartition")
                        .action(ArgAction::SetTrue)
                        .help(REPARTITION_HELP),
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
                        .help(SKIP_MD5_HELP),
                )
                .arg(Arg::new("pit").long("pit").num_args(1).help(PIT_HELP))
                .arg(
                    Arg::new("bl")
                        .short('b')
                        .long("BL")
                        .num_args(1)
                        .help(BL_HELP),
                )
                .arg(
                    Arg::new("ap")
                        .short('a')
                        .long("AP")
                        .num_args(1)
                        .help(AP_HELP),
                )
                .arg(
                    Arg::new("cp")
                        .short('c')
                        .long("CP")
                        .num_args(1)
                        .help(CP_HELP),
                )
                .arg(
                    Arg::new("csc")
                        .short('s')
                        .long("CSC")
                        .num_args(1)
                        .help(CSC_HELP),
                )
                .arg(
                    Arg::new("userdata")
                        .short('u')
                        .long("USERDATA")
                        .num_args(1)
                        .help(USERDATA_HELP),
                )
                .arg(
                    Arg::new("partition")
                        .short('p')
                        .long("partition")
                        .action(ArgAction::Append)
                        .num_args(2)
                        .value_names(["PARTITION", "FILE"])
                        .help(PARTITION_HELP),
                )
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .action(ArgAction::Append)
                        .num_args(1)
                        .value_name("FILE")
                        .help(FILE_HELP),
                ),
        )
        .subcommand(
            Command::new("verify-md5").about(VERIFY_MD5_ABOUT).arg(
                Arg::new("file")
                    .required(true)
                    .num_args(1..)
                    .help(VERIFY_MD5_FILE_HELP),
            ),
        )
        .subcommand(
            Command::new("reboot-download")
                .about("Boot a connected Samsung device into download mode"),
        );

    #[cfg(target_os = "linux")]
    {
        cmd = cmd.subcommand(
            Command::new("fix-usb")
                .about("Add udev rules to fix USB device access permissions on Linux"),
        );
    }

    let matches = cmd.get_matches();

    let verbose = matches.get_flag("verbose");
    let usb_backend_str = matches.get_one::<String>("usb_backend").unwrap().as_str();
    let usb_backend = UsbBackendOption::try_from(usb_backend_str).expect("Invalid USB backend");

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
                verbose,
            };
            download::action_download(args);
            0
        }
        Some(("check-update", sub_m)) => {
            let model = sub_m.get_one::<String>("model").cloned().unwrap();
            let region = sub_m.get_one::<String>("region").cloned().unwrap();
            let show_all = sub_m.get_flag("all");

            let info = FusClient::new()
                .and_then(|client| client.fetch_history(&model, &region))
                .or_else(|_| fetch_version_xml(&model, &region))
                .expect("Failed to fetch version info");

            if show_all {
                println!("Latest Stable Version:");
                println!("{}", info.latest);

                if !info.previous.is_empty() {
                    println!();
                    println!("Previous Stable Versions (sorted from new to old):");
                    for v in &info.previous {
                        println!("{}", v);
                    }
                }

                if !info.beta.is_empty() {
                    println!();
                    println!("Beta Versions (sorted from new to old):");
                    for v in &info.beta {
                        println!("{}", v);
                    }
                }
            } else {
                println!("{}", info.latest);
            }
            0
        }
        Some(("detect", sub_matches)) => {
            actions::action_detect(usb_backend, sub_matches.get_flag("wait"))
        }
        Some(("dump-pit", sub_matches)) => actions::action_dump_pit(
            usb_backend,
            sub_matches.get_one::<String>("output").unwrap(),
            verbose,
            !sub_matches.get_flag("no-reboot"),
            sub_matches.get_flag("wait"),
        ),
        Some(("print-pit", sub_matches)) => actions::action_print_pit(
            usb_backend,
            sub_matches
                .get_one::<String>("file")
                .map(|s| s.as_str())
                .unwrap_or(""),
            verbose,
            !sub_matches.get_flag("no-reboot"),
            sub_matches.get_flag("wait"),
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
                usb_backend,
                sub_matches.get_flag("repartition"),
                verbose,
                !sub_matches.get_flag("no-reboot"),
                sub_matches.get_flag("wait"),
                sub_matches.get_flag("skip-size-check"),
                sub_matches.get_flag("skip-md5"),
                sub_matches.get_one::<String>("pit").map(|s| s.as_str()),
                &packages,
                &partitions,
            );
            std::process::exit(result);
        }
        Some(("verify-md5", sub_matches)) => {
            let files: Vec<String> = sub_matches
                .get_many::<String>("file")
                .unwrap()
                .cloned()
                .collect();
            actions::action_verify_md5(&files)
        }
        Some(("reboot-download", _sub_matches)) => {
            actions::action_reboot_download(usb_backend, verbose)
        }
        #[cfg(target_os = "linux")]
        Some(("fix-usb", _sub_matches)) => actions::action_fix_usb(),
        _ => unreachable!(),
    };

    std::process::exit(result);
}
