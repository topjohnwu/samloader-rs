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

use crate::cli::DetectArgs;
use crate::progress::CliProgress;
use samloader_odin::{
    OdinConnection, UsbBackendOption, detect_device, futures::executor::block_on, set_progress,
};
use std::error::Error;

/// Reports whether a device in Download Mode is connected, and its details.
pub(crate) fn run(args: DetectArgs, usb_backend: UsbBackendOption) -> Result<(), Box<dyn Error>> {
    let DetectArgs { wait, json } = args;
    if !json {
        set_progress(CliProgress::new(false));
    }
    block_on(async {
        if !detect_device(usb_backend, wait).await {
            return Err("Failed to detect compatible download-mode device.".into());
        }

        let info = match OdinConnection::open(usb_backend, false).await {
            Ok(mut connection) => connection.query_device_info().await,
            Err(e) => Err(e),
        };
        match info {
            Ok(info) => {
                if json {
                    println!("{}", info.to_json());
                } else {
                    println!("Device detected (Download mode)");
                    print!("{}", info);
                }
            }
            Err(_) => {
                if json {
                    println!("{{\"modelName\":\"\",\"serialNumber\":\"\"}}");
                } else {
                    println!("Device detected (Download mode)");
                }
            }
        }
        Ok(())
    })
}
