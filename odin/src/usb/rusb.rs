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

use super::USB_CLASS_CDC_DATA;
use super::{UsbBackend, UsbTransfer};
use crate::compat::MaybeSend;
use crate::error::TransportError;
use ::rusb::{Context, DeviceHandle, UsbContext};
use std::time::Duration;

/// Maps a libusb transfer error.
fn transfer_error(e: ::rusb::Error) -> TransportError {
    match e {
        ::rusb::Error::Timeout => TransportError::Timeout,
        e => TransportError::backend(e),
    }
}

/// USB communication backend using `libusb` / `rusb`.
pub struct RusbBackend {
    handle: DeviceHandle<Context>,
    product: Option<String>,

    interface_index: i32,
    in_endpoint: u8,
    out_endpoint: u8,
}

impl RusbBackend {
    fn print_device_info(device: &::rusb::Device<Context>, handle: &DeviceHandle<Context>) {
        if let Ok(descriptor) = device.device_descriptor() {
            if let Ok(languages) = handle.read_languages(Duration::from_secs(1))
                && !languages.is_empty()
            {
                if let Ok(manufacturer) = handle.read_manufacturer_string_ascii(&descriptor) {
                    print_verbose!("      Manufacturer: \"{}\"", manufacturer);
                }
                if let Ok(product) = handle.read_product_string_ascii(&descriptor) {
                    print_verbose!("           Product: \"{}\"", product);
                }
                if let Ok(serial) = handle.read_serial_number_string_ascii(&descriptor) {
                    print_verbose!("         Serial No: \"{}\"", serial);
                }
            }

            print_verbose!("\n            length: {}", descriptor.length());
            print_verbose!("      device class: {}", descriptor.class_code());
            print_verbose!(
                "               S/N: {}",
                descriptor.serial_number_string_index().unwrap_or(0)
            );
            print_verbose!(
                "           VID:PID: {:04X}:{:04X}",
                descriptor.vendor_id(),
                descriptor.product_id()
            );

            let version = descriptor.device_version();
            let bcd = (version.0 as u16) << 8 | (version.1 as u16) << 4 | (version.2 as u16);
            print_verbose!("         bcdDevice: {:04X}", bcd);

            print_verbose!(
                "   iMan:iProd:iSer: {}:{}:{}",
                descriptor.manufacturer_string_index().unwrap_or(0),
                descriptor.product_string_index().unwrap_or(0),
                descriptor.serial_number_string_index().unwrap_or(0)
            );
            print_verbose!("          nb confs: {}", descriptor.num_configurations());
        }
    }
}

#[async_trait::async_trait]
impl UsbBackend for RusbBackend {
    type UsbDevice = ::rusb::Device<Context>;

    async fn new(device: Self::UsbDevice) -> Result<Self, TransportError> {
        // Locate the CDC data interface from cached descriptors before opening the
        // device, so unrelated devices are never opened or reconfigured.
        let config_descriptor = device
            .config_descriptor(0)
            .map_err(|_| TransportError::ConfigDescriptorRetrieval)?;

        let mut interface_index = -1;
        let mut alt_setting_index = -1;
        let mut in_endpoint = 0;
        let mut out_endpoint = 0;

        for interface in config_descriptor.interfaces() {
            for setting in interface.descriptors() {
                let mut in_endpoint_address = None;
                let mut out_endpoint_address = None;

                for endpoint in setting.endpoint_descriptors() {
                    if endpoint.direction() == ::rusb::Direction::In {
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
            return Err(TransportError::InterfaceConfigurationNotFound);
        }

        let handle = match device.open() {
            Ok(h) => h,
            Err(e) => return Err(TransportError::DeviceAccess(Box::new(e))),
        };

        if let Ok(config) = handle.active_configuration() {
            if config != 1 {
                let _ = handle.set_active_configuration(1);
            }
        } else {
            let _ = handle.set_active_configuration(1);
        }

        if crate::progress::is_verbose() {
            Self::print_device_info(&device, &handle);
        }

        let product = device
            .device_descriptor()
            .ok()
            .and_then(|desc| handle.read_product_string_ascii(&desc).ok());

        print_verbose!("Claiming interface...");
        if handle.claim_interface(interface_index as u8).is_err() {
            #[cfg(target_os = "linux")]
            {
                print_verbose!("Attempt failed. Detaching driver...");
                let _ = handle.detach_kernel_driver(interface_index as u8);
                print_verbose!("Claiming interface again...");
                if handle.claim_interface(interface_index as u8).is_err() {
                    return Err(TransportError::InterfaceClaimFailed);
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(TransportError::InterfaceClaimFailed);
            }
        }

        if alt_setting_index != 0 {
            print_verbose!("Setting up interface...");
            handle
                .set_alternate_setting(interface_index as u8, alt_setting_index as u8)
                .map_err(|_| TransportError::InterfaceSetupFailed)?;
        }

        Ok(Self {
            handle,
            product,

            interface_index,
            in_endpoint,
            out_endpoint,
        })
    }

    async fn find_device<'a, F>(mut predicate: F) -> Result<Self::UsbDevice, TransportError>
    where
        F: FnMut(u16, u16) -> bool + MaybeSend + 'a,
    {
        let context = Context::new().map_err(|e| {
            TransportError::Setup("Failed to create libusb context".into(), Box::new(e))
        })?;

        if let Ok(devices) = context.devices() {
            for device in devices.iter() {
                if let Ok(descriptor) = device.device_descriptor()
                    && predicate(descriptor.vendor_id(), descriptor.product_id())
                {
                    return Ok(device);
                }
            }
        }

        Err(TransportError::DeviceNotFound)
    }
}

#[async_trait::async_trait]
impl UsbTransfer for RusbBackend {
    async fn reset(&mut self) {
        if let Err(e) = self.handle.clear_halt(self.in_endpoint) {
            print_warning!("Failed to clear IN endpoint halt: {}", e);
        }
        if let Err(e) = self.handle.clear_halt(self.out_endpoint) {
            print_warning!("Failed to clear OUT endpoint halt: {}", e);
        }

        let mut buf = [0u8; 1024];
        loop {
            match self
                .handle
                .read_bulk(self.in_endpoint, &mut buf, Duration::from_millis(10))
            {
                Ok(n) if n > 0 => continue,
                _ => break,
            }
        }
    }

    async fn send(&mut self, data: &[u8], timeout: Duration) -> Result<(), TransportError> {
        let sent = self
            .handle
            .write_bulk(self.out_endpoint, data, timeout)
            .map_err(transfer_error)?;
        if sent != data.len() {
            return Err(TransportError::ShortWrite {
                sent,
                expected: data.len(),
            });
        }
        Ok(())
    }

    async fn receive(
        &mut self,
        data: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, TransportError> {
        self.handle
            .read_bulk(self.in_endpoint, data, timeout)
            .map_err(transfer_error)
    }

    fn product_name(&self) -> Option<&str> {
        self.product.as_deref()
    }
}

impl Drop for RusbBackend {
    fn drop(&mut self) {
        print_verbose!("Releasing device interface...");
        let _ = self.handle.release_interface(self.interface_index as u8);

        #[cfg(target_os = "linux")]
        {
            let _ = self.handle.attach_kernel_driver(self.interface_index as u8);
        }
    }
}
