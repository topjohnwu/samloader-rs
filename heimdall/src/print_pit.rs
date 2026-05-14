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
use std::io::Read;
use std::thread::sleep;
use std::time::Duration;
use crate::version;
use crate::BridgeManager;
use crate::InitialiseResult;
use crate::print_error;
use libpit::PitData;

pub fn action_print_pit(file: &str, verbose: bool, wait: bool, usb_log_level: &str) -> i32 {
    version::print_release_info();
    sleep(Duration::from_millis(1000));

    if !file.is_empty() {
        let mut f = match File::open(file) {
            Ok(f) => f,
            Err(_) => {
                print_error!("Failed to open file \"{}\"", file);
                return 1;
            }
        };

        let mut buffer = Vec::new();
        if f.read_to_end(&mut buffer).is_err() {
            print_error!("Failed to read file \"{}\"", file);
            return 1;
        }

        match PitData::new(&buffer) {
            Ok(pit_data) => {
                pit_data.print();
                0
            }
            Err(_) => {
                print_error!("Failed to unpack PIT file!");
                1
            }
        }
    } else {
        let mut bridge_manager = BridgeManager::new(verbose, wait);
        bridge_manager.set_usb_log_level(usb_log_level);

        if bridge_manager.initialise() != InitialiseResult::Succeeded || !bridge_manager.begin_session() {
            return 1;
        }

        let device_pit = bridge_manager.download_pit_file();
        let mut success = !device_pit.is_empty();

        if success {
            match PitData::new(&device_pit) {
                Ok(pit_data) => {
                    pit_data.print();
                }
                Err(_) => {
                    print_error!("Failed to unpack device's PIT file!");
                    success = false;
                }
            }
        }

        if !bridge_manager.end_session() {
            success = false;
        }

        if success { 0 } else { 1 }
    }
}
