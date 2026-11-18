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

//! Command line interface definition.

use clap::builder::{PossibleValue, PossibleValuesParser, TypedValueParser};
use clap::{Args, Parser, Subcommand};
use samloader_fus::OdinComponent;
use samloader_odin::{PartitionTarget, RebootMode, UsbBackendOption};

// On Windows, the default USB backend is set to VCOM rather than libusb/nusb.
// This is because libusb/nusb requires replacing the standard device driver
// with a WinUSB/generic driver (e.g., using a utility like Zadig).
// This manual driver swap breaks compatibility with the official
// Samsung USB drivers, creating a poor user experience.
// In contrast, the VCOM (Virtual COM Port/usbser.sys) implementation
// on Windows works out-of-the-box, requires no special driver
// modifications, and performs extremely fast.
cfg_if::cfg_if! {
    if #[cfg(all(target_os = "windows", feature = "serialport"))] {
        const DEFAULT_BACKEND: &str = UsbBackendOption::Vcom.to_str();
    } else {
        const DEFAULT_BACKEND: &str = UsbBackendOption::ALL[0].to_str();
    }
}

/// Accepts the names of the USB backends enabled in this build.
fn usb_backend_parser() -> impl TypedValueParser<Value = UsbBackendOption> {
    PossibleValuesParser::new(UsbBackendOption::ALL.iter().map(|b| b.to_str()))
        .map(|name| UsbBackendOption::try_from(name.as_str()).expect("enabled backend"))
}

/// All recognized Samsung Odin firmware components in canonical CLI order.
pub(crate) const ALL_COMPONENTS: &[OdinComponent] = &[
    OdinComponent::Bl,
    OdinComponent::Ap,
    OdinComponent::Cp,
    OdinComponent::Csc,
    OdinComponent::HomeCsc,
    OdinComponent::Userdata,
];

/// Canonical lowercase CLI key for an [`OdinComponent`].
pub(crate) const fn component_key(component: OdinComponent) -> &'static str {
    match component {
        OdinComponent::Bl => "bl",
        OdinComponent::Ap => "ap",
        OdinComponent::Cp => "cp",
        OdinComponent::Csc => "csc",
        OdinComponent::HomeCsc => "home_csc",
        OdinComponent::Userdata => "userdata",
    }
}

fn parse_component_key(s: &str) -> Option<OdinComponent> {
    match s.to_ascii_lowercase().as_str() {
        "bl" => Some(OdinComponent::Bl),
        "ap" => Some(OdinComponent::Ap),
        "cp" => Some(OdinComponent::Cp),
        "csc" => Some(OdinComponent::Csc),
        "home_csc" | "home-csc" => Some(OdinComponent::HomeCsc),
        "userdata" => Some(OdinComponent::Userdata),
        _ => None,
    }
}

/// Accepts recognized Samsung Odin firmware component keys.
fn odin_component_parser() -> impl TypedValueParser<Value = OdinComponent> {
    PossibleValuesParser::new(ALL_COMPONENTS.iter().map(|&c| {
        let pv = PossibleValue::new(component_key(c));
        if c == OdinComponent::HomeCsc {
            pv.alias("home-csc")
        } else {
            pv
        }
    }))
    .map(|s| parse_component_key(&s).expect("valid Odin component"))
}

/// Download and flash firmware for Samsung devices
#[derive(Parser)]
#[command(version, subcommand_required = true, arg_required_else_help = true)]
pub(crate) struct Cli {
    /// Enable verbose output
    #[arg(long, global = true)]
    pub(crate) verbose: bool,

    /// The USB backend to use
    #[arg(long, global = true, default_value = DEFAULT_BACKEND, value_parser = usb_backend_parser())]
    pub(crate) usb_backend: UsbBackendOption,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Download firmware
    Download(DownloadArgs),

    /// Check available versions
    CheckUpdate(CheckUpdateArgs),

    /// Indicates whether or not a download mode device can be detected
    ///
    /// Returns instantly per default, or waits until device is found
    /// when --wait argument is used
    #[command(verbatim_doc_comment)]
    Detect(DetectArgs),

    /// Dumps the connected device's PIT file to the specified output file
    DumpPit(DumpPitArgs),

    /// Prints the contents of a PIT file in a human readable format
    ///
    /// If a filename is not provided, samloader retrieves the PIT file from the
    /// connected device
    PrintPit(PrintPitArgs),

    /// Flashes one or more firmware files to your phone
    ///
    /// Partition names (or IDs) can be obtained by executing the print-pit action.
    ///
    /// Example explicit flashing: samloader flash -p RECOVERY recovery.img
    /// Example auto-matching: samloader flash -f boot.img
    /// Example skipping partitions: samloader flash -a AP.tar.md5 --skip BOOT,vbmeta.img
    /// Example disabling AVB: samloader flash -b BL.tar.md5 --disable-verity --disable-verification
    #[command(verbatim_doc_comment)]
    Flash(FlashArgs),

    /// Verifies the MD5 checksum of one or more .tar.md5 files
    VerifyMd5(VerifyMd5Args),

    /// Boot a connected Samsung device into download mode
    RebootDownload,

    /// Add udev rules to fix USB device access permissions on Linux
    #[cfg(target_os = "linux")]
    FixUsb,
}

/// Options identifying a firmware on Samsung's update servers.
#[derive(Args)]
pub(crate) struct FusArgs {
    /// The model name (e.g. SM-S931U1)
    #[arg(short, long)]
    pub(crate) model: String,

    /// Region CSC code (e.g. XAA)
    #[arg(short, long)]
    pub(crate) region: String,
}

/// Options of commands that run an Odin session.
#[derive(Args)]
pub(crate) struct OdinArgs {
    /// Waits until a compatible device is connected
    #[arg(long)]
    pub(crate) wait: bool,

    /// Disables automatic reboot after flashing
    #[arg(long, conflicts_with = "redownload")]
    pub(crate) no_reboot: bool,

    /// Reboot the device back into Download Mode instead of normal mode
    #[arg(long)]
    pub(crate) redownload: bool,
}

impl OdinArgs {
    /// How the device reboots once the session ends.
    pub(crate) fn reboot_mode(&self) -> RebootMode {
        if self.redownload {
            RebootMode::Download
        } else if self.no_reboot {
            RebootMode::None
        } else {
            RebootMode::Normal
        }
    }
}

#[derive(Args)]
pub(crate) struct DownloadArgs {
    #[command(flatten)]
    pub(crate) fus: FusArgs,

    /// Firmware version string (e.g. PDA/CSC/MODEM). If omitted, downloads the latest
    #[arg(short, long)]
    pub(crate) version: Option<String>,

    /// Number of parallel connections
    #[arg(short = 'j', long, default_value_t = 8)]
    pub(crate) threads: u64,

    /// Do not extract the firmware archive; save the decrypted .zip file directly
    #[arg(long, conflicts_with = "select")]
    pub(crate) no_extract: bool,

    /// Comma-separated firmware components to extract (bl, ap, cp, csc, home_csc, userdata)
    #[arg(
        short,
        long,
        value_delimiter = ',',
        value_name = "KEYS",
        ignore_case = true,
        value_parser = odin_component_parser()
    )]
    pub(crate) select: Vec<OdinComponent>,

    /// Output directory (defaults to <archive_name>/ when extracting, or current directory with --no-extract)
    #[arg(short = 'd', long)]
    pub(crate) out_dir: Option<String>,

    /// Output file path (only valid with --no-extract)
    #[arg(short, long, requires = "no_extract")]
    pub(crate) out_file: Option<String>,

    /// Overwrite existing files and discard any partial download
    #[arg(short, long)]
    pub(crate) force: bool,
}

#[derive(Args)]
pub(crate) struct CheckUpdateArgs {
    #[command(flatten)]
    pub(crate) fus: FusArgs,

    /// List all available firmware versions, with previous and beta sorted from new to old
    #[arg(short, long)]
    pub(crate) all: bool,
}

#[derive(Args)]
pub(crate) struct DetectArgs {
    /// Waits until a compatible device is connected
    #[arg(long)]
    pub(crate) wait: bool,

    /// Output device diagnostics as JSON (compatible with odin4 -i)
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct DumpPitArgs {
    #[command(flatten)]
    pub(crate) odin: OdinArgs,

    /// Output file path for the dumped PIT file
    #[arg(long)]
    pub(crate) output: String,
}

#[derive(Args)]
pub(crate) struct PrintPitArgs {
    #[command(flatten)]
    pub(crate) odin: OdinArgs,

    /// The PIT file to print. If not provided, samloader retrieves the PIT file from the connected device
    #[arg(short, long)]
    pub(crate) file: Option<String>,
}

#[derive(Args)]
pub(crate) struct FlashArgs {
    #[command(flatten)]
    pub(crate) odin: OdinArgs,

    /// Perform low-level NAND hardware erase on USERDATA before flashing
    #[arg(short, long)]
    pub(crate) erase: bool,

    /// Do not verify that files fit in the specified partition
    #[arg(long)]
    pub(crate) skip_size_check: bool,

    /// Skip MD5 checksum verification
    #[arg(long)]
    pub(crate) skip_md5: bool,

    /// The PIT file to flash to the device
    #[arg(long)]
    pub(crate) pit: Option<String>,

    /// BL tar package file
    #[arg(short, long = "BL")]
    pub(crate) bl: Option<String>,

    /// AP tar package file
    #[arg(short, long = "AP")]
    pub(crate) ap: Option<String>,

    /// CP tar package file
    #[arg(short, long = "CP")]
    pub(crate) cp: Option<String>,

    /// CSC/HOME_CSC tar package file
    #[arg(short = 's', long = "CSC")]
    pub(crate) csc: Option<String>,

    /// USERDATA tar package file
    #[arg(short, long = "USERDATA")]
    pub(crate) userdata: Option<String>,

    /// Explicit partition name/ID and file to flash
    #[arg(short, long, num_args = 2, value_names = ["PARTITION", "FILE"])]
    pub(crate) partition: Vec<String>,

    /// Automatic partition name matching file to flash
    #[arg(short, long, value_name = "FILE")]
    pub(crate) file: Vec<String>,

    /// Comma-separated file or partition names to skip. Partition names also skip their _A and _B slots
    #[arg(long, value_delimiter = ',', value_name = "NAMES")]
    pub(crate) skip: Vec<String>,

    /// Sets disable-verity when flashing vbmeta
    #[arg(long)]
    pub(crate) disable_verity: bool,

    /// Sets disable-verification when flashing vbmeta
    #[arg(long)]
    pub(crate) disable_verification: bool,

    /// Flash userdata without asking for confirmation
    #[arg(long)]
    pub(crate) force: bool,

    /// Set the 3-letter CSC / Sales Code in device storage (e.g. BTU, TUR, XAA)
    #[arg(long, value_name = "CODE")]
    pub(crate) csc_code: Option<String>,
}

impl FlashArgs {
    /// The TAR packages to flash, in BL, AP, CP, CSC, USERDATA order.
    pub(crate) fn packages(&self) -> impl Iterator<Item = &str> {
        [&self.bl, &self.ap, &self.cp, &self.csc, &self.userdata]
            .into_iter()
            .flatten()
            .map(String::as_str)
    }

    /// The partition images to flash with their resolved target, if given.
    pub(crate) fn partitions(&self) -> impl Iterator<Item = (PartitionTarget, &str)> {
        let explicit = self
            .partition
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[part, file]| {
                let target = match part.parse::<u32>() {
                    Ok(id) => PartitionTarget::Id(id),
                    Err(_) => PartitionTarget::Name(part.clone()),
                };
                (target, file.as_str())
            });
        let matched = self
            .file
            .iter()
            .map(|file| (PartitionTarget::Auto, file.as_str()));
        explicit.chain(matched)
    }
}

#[derive(Args)]
pub(crate) struct VerifyMd5Args {
    /// The .tar.md5 files to verify
    #[arg(required = true, value_name = "FILE")]
    pub(crate) files: Vec<String>,
}
