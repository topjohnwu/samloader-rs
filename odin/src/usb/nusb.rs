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

use super::*;

/// USB communication backend using `nusb`.
pub struct NusbBackend {
    verbose: bool,
    device: ::nusb::Device,
    _interface: ::nusb::Interface,
    ep_in: ::nusb::Endpoint<::nusb::transfer::Bulk, ::nusb::transfer::In>,
    ep_out: ::nusb::Endpoint<::nusb::transfer::Bulk, ::nusb::transfer::Out>,
}

impl NusbBackend {
    fn print_device_info(device: &::nusb::DeviceInfo, _handle: &::nusb::Device) {
        if let Some(manufacturer) = device.manufacturer_string() {
            eprintln!("      Manufacturer: \"{}\"", manufacturer);
        }
        if let Some(product) = device.product_string() {
            eprintln!("           Product: \"{}\"", product);
        }
        if let Some(serial) = device.serial_number() {
            eprintln!("         Serial No: \"{}\"", serial);
        }

        eprintln!("\n      device class: {}", device.class());
        eprintln!(
            "           VID:PID: {:04X}:{:04X}",
            device.vendor_id(),
            device.product_id()
        );
    }
}

impl UsbBackend for NusbBackend {
    type UsbDevice = ::nusb::DeviceInfo;

    fn new(device: Self::UsbDevice, verbose: bool) -> Result<Self, OdinError> {
        let handle = device
            .open()
            .wait()
            .map_err(|e| OdinError::SerialError(format!("Failed to open device: {}", e)))?;

        // Traverse configuration and select the class USB_CLASS_CDC_DATA interface with 2 endpoints
        let mut interface_index = -1;
        let mut alt_setting_index = -1;
        let mut in_endpoint = 0;
        let mut out_endpoint = 0;

        if let Ok(config) = handle.active_configuration() {
            for interface in config.interface_alt_settings() {
                let mut in_endpoint_address = None;
                let mut out_endpoint_address = None;

                for endpoint in interface.endpoints() {
                    let addr = endpoint.address();
                    if addr & 0x80 != 0 {
                        in_endpoint_address = Some(addr);
                    } else {
                        out_endpoint_address = Some(addr);
                    }
                }

                if interface_index < 0
                    && interface.endpoints().count() == 2
                    && interface.class() == USB_CLASS_CDC_DATA
                    && let (Some(in_addr), Some(out_addr)) =
                        (in_endpoint_address, out_endpoint_address)
                {
                    interface_index = interface.interface_number() as i32;
                    alt_setting_index = interface.alternate_setting() as i32;
                    in_endpoint = in_addr;
                    out_endpoint = out_addr;
                }
            }
        }

        if interface_index < 0 {
            return Err(OdinError::InterfaceConfigurationNotFound);
        }

        if verbose {
            Self::print_device_info(&device, &handle);
        }

        let interface = handle
            .detach_and_claim_interface(interface_index as u8)
            .wait()
            .map_err(|_| OdinError::InterfaceClaimFailed)?;

        if alt_setting_index != 0 {
            interface
                .set_alt_setting(alt_setting_index as u8)
                .wait()
                .map_err(|_| OdinError::InterfaceSetupFailed)?;
        }

        let ep_in = interface
            .endpoint::<::nusb::transfer::Bulk, ::nusb::transfer::In>(in_endpoint)
            .map_err(|e| OdinError::SerialError(format!("Failed to open IN endpoint: {}", e)))?;
        let ep_out = interface
            .endpoint::<::nusb::transfer::Bulk, ::nusb::transfer::Out>(out_endpoint)
            .map_err(|e| OdinError::SerialError(format!("Failed to open OUT endpoint: {}", e)))?;

        Ok(Self {
            verbose,
            device: handle,
            _interface: interface,
            ep_in,
            ep_out,
        })
    }

    fn find_device<F>(wait: bool, mut predicate: F) -> Result<Self::UsbDevice, OdinError>
    where
        F: FnMut(u16, u16) -> bool,
    {
        let mut print_wait = false;
        loop {
            if let Ok(devices) = ::nusb::list_devices().wait() {
                for device in devices {
                    if predicate(device.vendor_id(), device.product_id()) {
                        return Ok(device);
                    }
                }
            }
            if wait && !print_wait {
                println!("Waiting for device...");
                print_wait = true;
                std::thread::sleep(Duration::from_secs(1));
            } else {
                break;
            }
        }
        Err(OdinError::DeviceNotFound)
    }
}

impl UsbTransfer for NusbBackend {
    fn reset(&mut self) {
        if let Err(e) = self.device.reset().wait() {
            print_warning!(self.verbose, "Failed to reset device! Result: {}", e);
        }
    }

    fn send_data(&mut self, data: &[u8], timeout: i32, retry: bool) -> bool {
        let max_attempts = if retry { 6 } else { 1 };
        for attempt in 0..max_attempts {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(250 * attempt));
            }
            let buf = ::nusb::transfer::Buffer::from(data.to_vec());
            let completion = self
                .ep_out
                .transfer_blocking(buf, Duration::from_millis(timeout as u64));
            if completion.status.is_ok() {
                return completion.actual_len == data.len();
            }
        }
        false
    }

    fn receive_data(&mut self, data: &mut [u8], timeout: i32, retry: bool) -> i32 {
        let max_attempts = if retry { 6 } else { 1 };
        for attempt in 0..max_attempts {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(250 * attempt));
            }
            let max_packet_size = self.ep_in.max_packet_size();
            let mut requested_len = data.len();
            if !requested_len.is_multiple_of(max_packet_size) {
                requested_len = ((requested_len / max_packet_size) + 1) * max_packet_size;
            }
            let buf = ::nusb::transfer::Buffer::new(requested_len);
            let completion = self
                .ep_in
                .transfer_blocking(buf, Duration::from_millis(timeout as u64));
            if let Ok(()) = completion.status {
                let to_copy = std::cmp::min(completion.actual_len, data.len());
                data[..to_copy].copy_from_slice(&completion.buffer[..to_copy]);
                return to_copy as i32;
            }
        }
        -1
    }
}
