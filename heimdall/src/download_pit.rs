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

use std::fs::File;
use std::io::Write;
use std::thread::sleep;
use std::time::Duration;
use crate::version;
use crate::BridgeManager;
use crate::InitialiseResult;
use crate::print_error;

pub fn action_download_pit(output: &str, verbose: bool, wait: bool, usb_log_level: &str) -> i32 {
    if output.is_empty() {
        println!("Output file was not specified.\n");
        return 0;
    }

    // Info
    version::print_release_info();
    sleep(Duration::from_millis(1000));

    // Open output file
    let mut output_file = match File::create(output) {
        Ok(f) => f,
        Err(_) => {
            print_error!("Failed to open output file \"{}\"", output);
            return 1;
        }
    };

    // Download PIT file from device.
    let mut bridge_manager = BridgeManager::new(verbose, wait);
    bridge_manager.set_usb_log_level(usb_log_level);

    if bridge_manager.initialise() != InitialiseResult::Succeeded || !bridge_manager.begin_session() {
        return 1;
    }

    let pit_buffer = bridge_manager.download_pit_file();

    let mut success = true;

    if !pit_buffer.is_empty() {
        if let Err(e) = output_file.write_all(&pit_buffer) {
            print_error!("Failed to write PIT data to output file: {}", e);
            success = false;
        }
    } else {
        success = false;
    }

    if !bridge_manager.end_session() {
        success = false;
    }

    if success { 0 } else { 1 }
}
