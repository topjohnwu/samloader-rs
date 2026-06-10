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

use crate::error::OdinError;
use rusb::{Context, DeviceHandle, UsbContext};
use std::time::Duration;

macro_rules! print_warning {
    ($($arg:tt)*) => {
        eprint!("WARNING: ");
        eprintln!($($arg)*);
    };
}

pub const VID_SAMSUNG: u16 = 0x04E8;
const PID_GALAXY_S: u16 = 0x6601;
const PID_GALAXY_S2: u16 = 0x685D;
const PID_DROID_CHARGE: u16 = 0x68C3;

const SUPPORTED_DEVICES: &[(u16, u16)] = &[
    (VID_SAMSUNG, PID_GALAXY_S),
    (VID_SAMSUNG, PID_GALAXY_S2),
    (VID_SAMSUNG, PID_DROID_CHARGE),
];

const USB_CLASS_CDC_DATA: u8 = 0x0A;

pub trait UsbTransfer {
    fn send_data(&mut self, data: &[u8], timeout: i32, retry: bool) -> bool;
    fn receive_data(&mut self, data: &mut [u8], timeout: i32, retry: bool) -> i32;
}

pub trait UsbBackend: Sized + UsbTransfer {
    type UsbDevice;

    fn new(verbose: bool, wait_for_device: bool) -> Result<Self, OdinError>;
    fn find_device(wait: bool) -> Result<Self::UsbDevice, OdinError>;
}

pub struct RusbBackend {
    verbose: bool,
    handle: DeviceHandle<Context>,

    interface_index: i32,
    in_endpoint: u8,
    out_endpoint: u8,
}

impl RusbBackend {
    fn print_device_info(device: &rusb::Device<Context>, handle: &DeviceHandle<Context>) {
        if let Ok(descriptor) = device.device_descriptor() {
            if let Ok(languages) = handle.read_languages(Duration::from_secs(1))
                && !languages.is_empty()
            {
                if let Ok(manufacturer) = handle.read_manufacturer_string_ascii(&descriptor) {
                    eprintln!("      Manufacturer: \"{}\"", manufacturer);
                }
                if let Ok(product) = handle.read_product_string_ascii(&descriptor) {
                    eprintln!("           Product: \"{}\"", product);
                }
                if let Ok(serial) = handle.read_serial_number_string_ascii(&descriptor) {
                    eprintln!("         Serial No: \"{}\"", serial);
                }
            }

            eprintln!("\n            length: {}", descriptor.length());
            eprintln!("      device class: {}", descriptor.class_code());
            eprintln!(
                "               S/N: {}",
                descriptor.serial_number_string_index().unwrap_or(0)
            );
            eprintln!(
                "           VID:PID: {:04X}:{:04X}",
                descriptor.vendor_id(),
                descriptor.product_id()
            );

            let version = descriptor.device_version();
            let bcd = (version.0 as u16) << 8 | (version.1 as u16) << 4 | (version.2 as u16);
            eprintln!("         bcdDevice: {:04X}", bcd);

            eprintln!(
                "   iMan:iProd:iSer: {}:{}:{}",
                descriptor.manufacturer_string_index().unwrap_or(0),
                descriptor.product_string_index().unwrap_or(0),
                descriptor.serial_number_string_index().unwrap_or(0)
            );
            eprintln!("          nb confs: {}", descriptor.num_configurations());
        }
    }
}

impl UsbBackend for RusbBackend {
    type UsbDevice = rusb::Device<Context>;

    fn new(verbose: bool, wait_for_device: bool) -> Result<Self, OdinError> {
        let device = Self::find_device(wait_for_device)?;

        let handle = match device.open() {
            Ok(h) => h,
            Err(e) => return Err(OdinError::DeviceAccess(e)),
        };

        if let Ok(config) = handle.active_configuration() {
            if config != 1 {
                let _ = handle.set_active_configuration(1);
            }
        } else {
            let _ = handle.set_active_configuration(1);
        }

        if verbose {
            Self::print_device_info(&device, &handle);
        }

        let config_descriptor = device
            .config_descriptor(0)
            .map_err(|_| OdinError::ConfigDescriptorRetrieval)?;

        let mut interface_index = -1;
        let mut alt_setting_index = -1;
        let mut in_endpoint = 0;
        let mut out_endpoint = 0;

        for interface in config_descriptor.interfaces() {
            for setting in interface.descriptors() {
                let mut in_endpoint_address = None;
                let mut out_endpoint_address = None;

                for endpoint in setting.endpoint_descriptors() {
                    if endpoint.direction() == rusb::Direction::In {
                        in_endpoint_address = Some(endpoint.address());
                    } else {
                        out_endpoint_address = Some(endpoint.address());
                    }
                }

                if interface_index < 0
                    && setting.num_endpoints() == 2
                    && setting.class_code() == USB_CLASS_CDC_DATA
                    && let (Some(in_addr), Some(out_addr)) =
                        (in_endpoint_address, out_endpoint_address)
                {
                    interface_index = interface.number() as i32;
                    alt_setting_index = setting.setting_number() as i32;
                    in_endpoint = in_addr;
                    out_endpoint = out_addr;
                }
            }
        }

        if interface_index < 0 {
            return Err(OdinError::InterfaceConfigurationNotFound);
        }

        println!("Claiming interface...");
        if handle.claim_interface(interface_index as u8).is_err() {
            #[cfg(target_os = "linux")]
            {
                println!("Attempt failed. Detaching driver...");
                let _ = handle.detach_kernel_driver(interface_index as u8);
                println!("Claiming interface again...");
                if handle.claim_interface(interface_index as u8).is_err() {
                    return Err(OdinError::InterfaceClaimFailed);
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(OdinError::InterfaceClaimFailed);
            }
        }

        if alt_setting_index != 0 {
            println!("Setting up interface...");
            handle
                .set_alternate_setting(interface_index as u8, alt_setting_index as u8)
                .map_err(|_| OdinError::InterfaceSetupFailed)?;
        }

        println!("Resetting device...");
        if let Err(e) = handle.reset() {
            print_warning!("Failed to reset device! Result: {}", e);
        }

        Ok(Self {
            verbose,
            handle,

            interface_index,
            in_endpoint,
            out_endpoint,
        })
    }

    fn find_device(wait: bool) -> Result<Self::UsbDevice, OdinError> {
        let context = Context::new().map_err(|e| {
            OdinError::SerialError(format!("Failed to create libusb context: {}", e))
        })?;

        if wait {
            println!("Waiting for device...");
        } else {
            println!("Detecting device...");
        }

        loop {
            if let Ok(devices) = context.devices() {
                for device in devices.iter() {
                    if let Ok(descriptor) = device.device_descriptor() {
                        for &(vid, pid) in SUPPORTED_DEVICES {
                            if descriptor.vendor_id() == vid && descriptor.product_id() == pid {
                                return Ok(device);
                            }
                        }
                    }
                }
            }

            if wait {
                std::thread::sleep(Duration::from_secs(1));
            } else {
                break;
            }
        }

        Err(OdinError::DeviceNotFound)
    }
}

impl UsbTransfer for RusbBackend {
    fn send_data(&mut self, data: &[u8], timeout: i32, retry: bool) -> bool {
        let max_attempts = if retry { 6 } else { 1 };
        for attempt in 0..max_attempts {
            if attempt > 0 {
                if self.verbose {
                    eprintln!(" Retrying...");
                }
                std::thread::sleep(Duration::from_millis(250 * attempt));
            }

            let result = self.handle.write_bulk(
                self.out_endpoint,
                data,
                Duration::from_millis(timeout as u64),
            );

            if let Ok(transferred) = result {
                return transferred == data.len();
            };

            if retry {
                print_warning!(
                    "libusb error {} whilst sending bulk transfer.",
                    result.as_ref().unwrap_err()
                );
            }
        }

        false
    }

    fn receive_data(&mut self, data: &mut [u8], timeout: i32, retry: bool) -> i32 {
        let max_attempts = if retry { 6 } else { 1 };

        for attempt in 0..max_attempts {
            if attempt > 0 {
                if self.verbose {
                    eprintln!(" Retrying...");
                }
                std::thread::sleep(Duration::from_millis(250 * attempt));
            }

            let result = self.handle.read_bulk(
                self.in_endpoint,
                data,
                Duration::from_millis(timeout as u64),
            );

            if let Ok(transferred) = result {
                return transferred as i32;
            };

            if retry {
                print_warning!(
                    "libusb error {} whilst receiving bulk transfer.",
                    result.as_ref().unwrap_err()
                );
            }
        }
        -1
    }
}

impl Drop for RusbBackend {
    fn drop(&mut self) {
        println!("Releasing device interface...");
        let _ = self.handle.release_interface(self.interface_index as u8);

        #[cfg(target_os = "linux")]
        {
            let _ = self.handle.attach_kernel_driver(self.interface_index as u8);
        }
    }
}
