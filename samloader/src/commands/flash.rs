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

use crate::cli::FlashArgs;
use crate::progress::CliProgress;
use crate::readahead::ReadaheadFile;
use crate::session::connect;
use samloader_odin::{FlashRequest, UsbBackendOption, futures::executor::block_on, set_progress};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, IsTerminal, Write};

// Asks a y/n question on the terminal, declining when stdin is closed
fn confirm(question: &str) -> bool {
    let mut stdin = io::stdin().lock();
    loop {
        print!("{} [y/n] ", question);
        let _ = io::stdout().flush();

        let mut answer = String::new();
        if stdin.read_line(&mut answer).unwrap_or(0) == 0 {
            println!();
            return false;
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => {}
        }
    }
}

// Opens a file for reading by the async flashing pipeline, reading ahead of
// the USB transfer on a helper thread
fn open(path: &str) -> Result<ReadaheadFile, String> {
    File::open(path)
        .and_then(ReadaheadFile::new)
        .map_err(|e| format!("Failed to open file \"{}\": {}", path, e))
}

/// Flashes firmware packages and partition images to the connected device.
pub(crate) fn run(
    args: FlashArgs,
    usb_backend: UsbBackendOption,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    if args.packages().next().is_none()
        && args.partition.is_empty()
        && args.file.is_empty()
        && args.csc_code.is_none()
        && !args.erase
        && !args.odin.redownload
    {
        return Err(
            "No packages, files, partitions, CSC code, erase option, or redownload \
                    option specified for flashing."
                .into(),
        );
    }

    let opened_packages = args
        .packages()
        .map(|pkg| Ok((pkg, open(pkg)?)))
        .collect::<Result<Vec<_>, String>>()?;

    let opened_partitions = args
        .partitions()
        .map(|(name, file)| Ok((name, file, open(file)?)))
        .collect::<Result<Vec<_>, String>>()?;

    let pit_bytes = match &args.pit {
        Some(pit_path) => Some(
            std::fs::read(pit_path)
                .map_err(|e| format!("Failed to read file \"{}\": {}", pit_path, e))?,
        ),
        None => None,
    };

    let mut request = FlashRequest::new()
        .reboot_mode(args.odin.reboot_mode())
        .skip_size_check(args.skip_size_check)
        .skip_md5(args.skip_md5)
        .erase(args.erase)
        .packages(opened_packages)
        .partitions(opened_partitions)
        .skip(&args.skip)
        .disable_verity(args.disable_verity)
        .disable_verification(args.disable_verification)
        .sales_code(args.csc_code.as_deref());

    if let Some(buffer) = pit_bytes {
        request = request.pit(buffer);
    }

    // Validate and index the inputs before connecting to the device
    set_progress(CliProgress::new(verbose));
    let prepared = block_on(request.prepare())?;

    if !args.force && prepared.flashes_userdata() {
        if !io::stdin().is_terminal() {
            return Err(
                "Flash list contains userdata, which will wipe the device's data. \
                        Pass --force to flash it without a terminal."
                    .into(),
            );
        }
        if !confirm("Flash list contains userdata. This will wipe the device's data. Continue?") {
            return Err("Flashing aborted by user.".into());
        }
    }

    block_on(async {
        let mut session = connect(usb_backend, args.odin.wait).await?;
        prepared.execute(&mut session).await?;
        Ok(())
    })
}
