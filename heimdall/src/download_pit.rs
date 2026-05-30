// Copyright 2026 Google LLC
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

use crate::print_error;
use samloader_odin::OdinManager;
use std::fs::File;
use std::io::Write;

pub(crate) fn action_download_pit(
    output: &str,
    verbose: bool,
    wait: bool,
    usb_log_level: &str,
) -> i32 {
    if output.is_empty() {
        println!("Output file was not specified.\n");
        return 0;
    }

    // Open output file
    let mut output_file = match File::create(output) {
        Ok(f) => f,
        Err(_) => {
            print_error!("Failed to open output file \"{}\"", output);
            return 1;
        }
    };

    // Download PIT file from device.
    let mut odin_manager = OdinManager::new(verbose, wait);
    odin_manager.set_usb_log_level(usb_log_level);

    if let Err(e) = odin_manager.initialise() {
        print_error!("{}", e);
        return 1;
    }

    if let Err(e) = odin_manager.begin_session() {
        print_error!("{}", e);
        return 1;
    }

    let mut success = true;

    match odin_manager.download_pit_file() {
        Ok(pit_buffer) => {
            if let Err(e) = output_file.write_all(&pit_buffer) {
                print_error!("Failed to write PIT data to output file: {}", e);
                success = false;
            }
        }
        Err(e) => {
            print_error!("{}", e);
            success = false;
        }
    }

    if let Err(e) = odin_manager.end_session() {
        print_error!("{}", e);
        success = false;
    }

    if success { 0 } else { 1 }
}
