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
use samloader_pit::PitData;
use std::fs::File;
use std::io::Read;

pub(crate) fn action_print_pit(file: &str, verbose: bool, wait: bool, usb_log_level: &str) -> i32 {
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
                println!("{}", pit_data);
                0
            }
            Err(_) => {
                print_error!("Failed to unpack PIT file!");
                1
            }
        }
    } else {
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
        let mut device_pit_data = None;

        match odin_manager.download_pit_file() {
            Ok(device_pit) => match PitData::new(&device_pit) {
                Ok(pit_data) => {
                    device_pit_data = Some(pit_data);
                }
                Err(_) => {
                    print_error!("Failed to unpack device's PIT file!");
                    success = false;
                }
            },
            Err(e) => {
                print_error!("{}", e);
                success = false;
            }
        }

        if let Some(pit_data) = device_pit_data {
            println!("{}", pit_data);
        }

        if let Err(e) = odin_manager.end_session() {
            print_error!("{}", e);
            success = false;
        }

        if success { 0 } else { 1 }
    }
}
