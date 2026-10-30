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

use super::{UsbBackend, UsbTransfer};
use crate::compat::MaybeSend;
use crate::error::{OdinError, TransportError};
use std::io::{Read, Write};
use std::time::Duration;

/// Maps a serial port I/O error.
fn io_error(e: std::io::Error) -> TransportError {
    match e.kind() {
        std::io::ErrorKind::TimedOut => TransportError::Timeout,
        _ => TransportError::backend(e),
    }
}

/// Serial VCOM communication backend using virtual serial ports.
pub struct SerialBackend {
    port: Box<dyn serialport::SerialPort>,
    product: Option<String>,
}

impl SerialBackend {
    fn print_device_info(info: &serialport::UsbPortInfo) {
        if let Some(ref manufacturer) = info.manufacturer {
            print_verbose!("      Manufacturer: \"{}\"", manufacturer);
        }
        if let Some(ref product) = info.product {
            print_verbose!("           Product: \"{}\"", product);
        }
        if let Some(ref serial) = info.serial_number {
            print_verbose!("         Serial No: \"{}\"", serial);
        }
        print_verbose!("           VID:PID: {:04X}:{:04X}", info.vid, info.pid);
    }
}

#[async_trait::async_trait]
impl UsbBackend for SerialBackend {
    type UsbDevice = serialport::SerialPortInfo;

    async fn new(device: Self::UsbDevice) -> Result<Self, OdinError> {
        let info = match &device.port_type {
            serialport::SerialPortType::UsbPort(info) => info,
            _ => return Err(OdinError::DeviceNotFound),
        };

        Self::print_device_info(info);

        let product = info.product.clone();

        let port = serialport::new(&device.port_name, 115_200)
            .timeout(Duration::from_millis(1000))
            .open()
            .map_err(|e| {
                TransportError::Setup(
                    format!("Failed to open port {}", device.port_name),
                    Box::new(e),
                )
            })?;

        Ok(Self { port, product })
    }

    async fn find_device<'a, F>(mut predicate: F) -> Result<Self::UsbDevice, OdinError>
    where
        F: FnMut(u16, u16) -> bool + MaybeSend + 'a,
    {
        if let Ok(ports) = serialport::available_ports() {
            for port in ports {
                if let serialport::SerialPortType::UsbPort(ref info) = port.port_type
                    && predicate(info.vid, info.pid)
                {
                    return Ok(port);
                }
            }
        }

        Err(OdinError::DeviceNotFound)
    }
}

#[async_trait::async_trait]
impl UsbTransfer for SerialBackend {
    async fn reset(&mut self) {
        if let Err(e) = self.port.clear(serialport::ClearBuffer::All) {
            print_warning!("Failed to reset device! Result: {}", e);
        }
    }

    async fn send(&mut self, data: &[u8], timeout: Duration) -> Result<(), TransportError> {
        if let Err(e) = self.port.set_timeout(timeout) {
            print_warning!("Failed to set serial port timeout: {}", e);
        }

        let mut written = 0;
        while written < data.len() {
            match self.port.write(&data[written..]) {
                Ok(0) => {
                    return Err(TransportError::ShortWrite {
                        sent: written,
                        expected: data.len(),
                    });
                }
                Ok(n) => {
                    written += n;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => return Err(io_error(e)),
            }
        }

        let _ = self.port.flush();
        Ok(())
    }

    async fn receive(
        &mut self,
        data: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, TransportError> {
        if let Err(e) = self.port.set_timeout(timeout) {
            print_warning!("Failed to set serial port timeout: {}", e);
        }

        self.port.read(data).map_err(io_error)
    }

    fn product_name(&self) -> Option<&str> {
        self.product.as_deref()
    }
}
