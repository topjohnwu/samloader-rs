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

use crate::progress::CliProgress;
use samloader_odin::{
    DownloadModeReboot, UsbBackendOption, futures::executor::block_on, set_progress,
};
use std::error::Error;

/// Reboots the connected device from normal mode into Download Mode.
pub(crate) fn run(usb_backend: UsbBackendOption, verbose: bool) -> Result<(), Box<dyn Error>> {
    set_progress(CliProgress::new(verbose));
    if block_on(samloader_odin::reboot_download(usb_backend))?
        == DownloadModeReboot::AlreadyInDownloadMode
    {
        println!("Device is already in Download Mode.");
    }
    Ok(())
}
