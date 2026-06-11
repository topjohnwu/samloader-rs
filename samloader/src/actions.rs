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

use crate::print_error;
use samloader_odin::{
    OdinManager, RusbBackend, SerialBackend, UsbBackend, create_backend, verify_md5_footer,
};
use samloader_pit::PitData;
use std::fs::File;
use std::io::{Read, Write};

pub(crate) fn action_detect(usb_backend: &str, _verbose: bool, wait: bool) -> i32 {
    let detected = match usb_backend {
        "vcom" => SerialBackend::find_device(wait).is_ok(),
        _ => RusbBackend::find_device(wait).is_ok(),
    };
    if detected {
        println!("Device detected");
        0
    } else {
        eprintln!("ERROR: Failed to detect compatible download-mode device.");
        1
    }
}

pub(crate) fn action_dump_pit(usb_backend: &str, output: &str, verbose: bool, wait: bool) -> i32 {
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
    let usb = match create_backend(usb_backend, verbose, wait) {
        Ok(u) => u,
        Err(e) => {
            print_error!("{}", e);
            return 1;
        }
    };
    let mut odin_manager = OdinManager::new(usb, verbose);

    if let Err(e) = odin_manager.init() {
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

pub(crate) fn action_print_pit(usb_backend: &str, file: &str, verbose: bool, wait: bool) -> i32 {
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
        let usb = match create_backend(usb_backend, verbose, wait) {
            Ok(u) => u,
            Err(e) => {
                print_error!("{}", e);
                return 1;
            }
        };
        let mut odin_manager = OdinManager::new(usb, verbose);

        if let Err(e) = odin_manager.init() {
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

pub(crate) fn action_reboot_download(_verbose: bool) -> i32 {
    println!("Sending serial command...");
    match samloader_odin::reboot_download() {
        Ok(()) => {
            println!("Done");
            0
        }
        Err(e) => {
            print_error!("{}", e);
            1
        }
    }
}

pub(crate) fn action_verify_md5(files: &[String]) -> i32 {
    let mut success = true;
    for file in files {
        println!("Verifying MD5 checksum for {}...", file);
        match verify_md5_footer(file) {
            Ok(()) => {
                println!("MD5 verification successful!\n");
            }
            Err(e) => {
                print_error!("MD5 verification failed for \"{}\": {}", file, e);
                success = false;
            }
        }
    }
    if success { 0 } else { 1 }
}
