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

/// Serial VCOM communication backend using virtual serial ports.
pub struct SerialBackend {
    verbose: bool,
    port: Box<dyn serialport::SerialPort>,
}

impl SerialBackend {
    fn print_device_info(info: &serialport::UsbPortInfo) {
        if let Some(ref manufacturer) = info.manufacturer {
            eprintln!("      Manufacturer: \"{}\"", manufacturer);
        }
        if let Some(ref product) = info.product {
            eprintln!("           Product: \"{}\"", product);
        }
        if let Some(ref serial) = info.serial_number {
            eprintln!("         Serial No: \"{}\"", serial);
        }
        eprintln!("           VID:PID: {:04X}:{:04X}", info.vid, info.pid);
    }
}

impl UsbBackend for SerialBackend {
    type UsbDevice = serialport::SerialPortInfo;

    fn new(device: Self::UsbDevice, verbose: bool) -> Result<Self, OdinError> {
        let info = match &device.port_type {
            serialport::SerialPortType::UsbPort(info) => info,
            _ => return Err(OdinError::DeviceNotFound),
        };

        if verbose {
            Self::print_device_info(info);
        }

        let port = serialport::new(&device.port_name, 115_200)
            .timeout(Duration::from_millis(1000))
            .open()
            .map_err(|e| {
                OdinError::SerialError(format!("Failed to open port {}: {}", device.port_name, e))
            })?;

        Ok(Self { verbose, port })
    }

    fn find_device<F>(wait: bool, mut predicate: F) -> Result<Self::UsbDevice, OdinError>
    where
        F: FnMut(u16, u16) -> bool,
    {
        let mut print_wait = false;
        loop {
            if let Ok(ports) = serialport::available_ports() {
                for port in ports {
                    if let serialport::SerialPortType::UsbPort(ref info) = port.port_type
                        && predicate(info.vid, info.pid)
                    {
                        return Ok(port);
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

impl UsbTransfer for SerialBackend {
    fn reset(&mut self) {
        if let Err(e) = self.port.clear(serialport::ClearBuffer::All) {
            print_warning!(self.verbose, "Failed to reset device! Result: {}", e);
        }
    }

    fn send_data(&mut self, data: &[u8], timeout: i32, retry: bool) -> bool {
        if let Err(e) = self.port.set_timeout(Duration::from_millis(timeout as u64)) {
            print_warning!(self.verbose, "Failed to set serial port timeout: {}", e);
        }

        let mut written = 0;
        let max_attempts = if retry { 6 } else { 1 };

        for attempt in 0..max_attempts {
            if attempt > 0 {
                print_verbose!(
                    self.verbose,
                    " Retrying (written {}/{})...",
                    written,
                    data.len()
                );
                std::thread::sleep(Duration::from_millis(250 * attempt));
            }

            while written < data.len() {
                match self.port.write(&data[written..]) {
                    Ok(0) => {
                        if retry {
                            print_warning!(self.verbose, "Serial write returned 0 bytes written");
                        }
                        break;
                    }
                    Ok(n) => {
                        written += n;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        continue;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        if retry {
                            print_warning!(self.verbose, "Serial write timed out: {}", e);
                        }
                        break;
                    }
                    Err(e) => {
                        if retry {
                            print_warning!(
                                self.verbose,
                                "Serial error whilst sending transfer: {}",
                                e
                            );
                        }
                        break;
                    }
                }
            }

            if written == data.len() {
                let _ = self.port.flush();
                return true;
            }
        }

        false
    }

    fn receive_data(&mut self, data: &mut [u8], timeout: i32, retry: bool) -> i32 {
        if let Err(e) = self.port.set_timeout(Duration::from_millis(timeout as u64)) {
            print_warning!(self.verbose, "Failed to set serial port timeout: {}", e);
        }

        let max_attempts = if retry { 6 } else { 1 };

        for attempt in 0..max_attempts {
            if attempt > 0 {
                print_verbose!(self.verbose, " Retrying...");
                std::thread::sleep(Duration::from_millis(250 * attempt));
            }

            match self.port.read(data) {
                Ok(bytes_read) => {
                    return bytes_read as i32;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    // Timed out, retry if allowed
                }
                Err(e) => {
                    if retry {
                        print_warning!(
                            self.verbose,
                            "Serial error whilst receiving transfer: {}",
                            e
                        );
                    }
                }
            }
        }
        -1
    }
}
