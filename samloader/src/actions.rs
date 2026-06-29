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
    OdinManager, UsbBackendOption, create_backend, detect_device, verify_md5_footer,
};
use samloader_pit::PitData;
use std::fs::File;
use std::io::{Read, Write};

pub(crate) fn action_detect(usb_backend: UsbBackendOption, wait: bool) -> i32 {
    let detected = detect_device(usb_backend, wait);
    if detected {
        println!("Device detected");
        0
    } else {
        eprintln!("ERROR: Failed to detect compatible download-mode device.");
        1
    }
}

pub(crate) fn action_dump_pit(
    usb_backend: UsbBackendOption,
    output: &str,
    verbose: bool,
    reboot_device: bool,
    wait: bool,
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

    if reboot_device && let Err(e) = odin_manager.reboot_device() {
        print_error!("{}", e);
        success = false;
    }

    if success { 0 } else { 1 }
}

pub(crate) fn action_print_pit(
    usb_backend: UsbBackendOption,
    file: &str,
    verbose: bool,
    reboot_device: bool,
    wait: bool,
) -> i32 {
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

        if reboot_device && let Err(e) = odin_manager.reboot_device() {
            print_error!("{}", e);
            success = false;
        }

        if success { 0 } else { 1 }
    }
}

pub(crate) fn action_reboot_download(usb_backend: UsbBackendOption, _verbose: bool) -> i32 {
    match samloader_odin::reboot_download(usb_backend) {
        Ok(()) => 0,
        Err(e) => {
            print_error!("{}", e);
            1
        }
    }
}

pub(crate) fn action_verify_md5(files: &[String]) -> i32 {
    let mut success = true;
    for file_path in files {
        println!("Verifying MD5 checksum for {}...", file_path);
        let file = match File::open(file_path) {
            Ok(f) => f,
            Err(e) => {
                print_error!("Failed to open file \"{}\": {}", file_path, e);
                success = false;
                continue;
            }
        };
        match verify_md5_footer(&file) {
            Ok(()) => {
                println!("MD5 verification successful!\n");
            }
            Err(e) => {
                print_error!("MD5 verification failed for \"{}\": {}", file_path, e);
                success = false;
            }
        }
    }
    if success { 0 } else { 1 }
}

#[cfg(target_os = "linux")]
const UDEV_RULES_PATH: &str = "/etc/udev/rules.d/60-samloader.rules";

#[cfg(target_os = "linux")]
pub(crate) fn action_fix_usb() -> i32 {
    if unsafe { libc::geteuid() != 0 } {
        eprintln!("ERROR: This command must be run as root (e.g., using sudo).");
        return 1;
    }

    println!("Writing udev rule to {}...", UDEV_RULES_PATH);
    let rule = "SUBSYSTEM==\"usb\", ATTR{idVendor}==\"04e8\", TAG+=\"uaccess\"\n";
    if let Err(e) = std::fs::write(UDEV_RULES_PATH, rule) {
        eprintln!("ERROR: Failed to write udev rules file: {}", e);
        return 1;
    }

    println!("Reloading and triggering udev rules...");
    let status = std::process::Command::new("udevadm")
        .arg("control")
        .arg("--reload-rules")
        .status();

    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("ERROR: Failed to reload udev rules via udevadm.");
            return 1;
        }
    }

    let status = std::process::Command::new("udevadm")
        .arg("trigger")
        .status();

    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("ERROR: Failed to trigger udev rules via udevadm.");
            return 1;
        }
    }

    println!("SUCCESS: USB udev rules successfully configured and reloaded.");
    0
}
