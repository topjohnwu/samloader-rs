// Copyright 2026 John "topjohnwu" Wu
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

use crate::cli::{DumpPitArgs, OdinArgs, PrintPitArgs};
use crate::progress::CliProgress;
use crate::session::connect;
use samloader_odin::{UsbBackendOption, futures::executor::block_on, set_progress};
use samloader_pit::PitData;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};

/// Saves the PIT of the connected device to a file.
pub(crate) fn dump(
    args: DumpPitArgs,
    usb_backend: UsbBackendOption,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    let output = args.output.as_str();
    if output.is_empty() {
        println!("Output file was not specified.\n");
        return Ok(());
    }

    let mut output_file =
        File::create(output).map_err(|_| format!("Failed to open output file \"{}\"", output))?;

    with_device_pit(&args.odin, usb_backend, verbose, |pit_buffer| {
        output_file
            .write_all(&pit_buffer)
            .map_err(|e| format!("Failed to write PIT data to output file: {}", e))?;
        Ok(())
    })
}

/// Prints a PIT file, or the PIT of the connected device if no file is given.
pub(crate) fn print(
    args: PrintPitArgs,
    usb_backend: UsbBackendOption,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    if let Some(file) = args.file.as_deref().filter(|file| !file.is_empty()) {
        let mut f = File::open(file).map_err(|_| format!("Failed to open file \"{}\"", file))?;

        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)
            .map_err(|_| format!("Failed to read file \"{}\"", file))?;

        let pit_data = PitData::new(&buffer).map_err(|_| "Failed to unpack PIT file!")?;
        println!("{}", pit_data);
        return Ok(());
    }

    with_device_pit(&args.odin, usb_backend, verbose, |device_pit| {
        let pit_data =
            PitData::new(&device_pit).map_err(|_| "Failed to unpack device's PIT file!")?;
        println!("{}", pit_data);
        Ok(())
    })
}

/// Downloads the PIT of the connected device and passes it to `handle`.
///
/// The session is ended and the device rebooted as requested even if the
/// PIT could not be downloaded or handled, and the first error is returned.
fn with_device_pit(
    odin: &OdinArgs,
    usb_backend: UsbBackendOption,
    verbose: bool,
    handle: impl FnOnce(Vec<u8>) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    set_progress(CliProgress::new(verbose));

    block_on(async {
        let mut session = connect(usb_backend, odin.wait).await?;

        println!("Downloading device's PIT file");
        let handled = match session.receive_pit_info().await {
            Ok(pit) => handle(pit),
            Err(e) => Err(e.into()),
        };

        let finished = session.finish(odin.reboot_mode()).await;
        handled?;
        Ok(finished?)
    })
}
