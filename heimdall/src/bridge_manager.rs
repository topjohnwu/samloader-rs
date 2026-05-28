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

use crate::error::BridgeError;
use crate::packets;
use crate::packets::RequestPacket;
use crate::{print_error, print_warning};
use libpit::{BinaryType, PitData};
use rusb::{Context, DeviceHandle, LogLevel, UsbContext};
use std::time::Duration;

pub(crate) struct BridgeManager {
    verbose: bool,
    wait_for_device: bool,
    context: Context,
    handle: Option<DeviceHandle<Context>>,
    usb_log_level: LogLevel,

    interface_index: i32,
    alt_setting_index: i32,
    in_endpoint: u8,
    out_endpoint: u8,

    interface_claimed: bool,

    file_transfer_sequence_max_length: usize,
    file_transfer_packet_size: usize,
    file_transfer_sequence_timeout: u32,
    lz4_supported: bool,
}

const VID_SAMSUNG: u16 = 0x04E8;
const PID_GALAXY_S: u16 = 0x6601;
const PID_GALAXY_S2: u16 = 0x685D;
const PID_DROID_CHARGE: u16 = 0x68C3;

const SUPPORTED_DEVICES: &[(u16, u16)] = &[
    (VID_SAMSUNG, PID_GALAXY_S),
    (VID_SAMSUNG, PID_GALAXY_S2),
    (VID_SAMSUNG, PID_DROID_CHARGE),
];

const FILE_TRANSFER_SEQUENCE_MAX_LENGTH_DEFAULT: usize = 800;
const FILE_TRANSFER_PACKET_SIZE_DEFAULT: usize = 0x20000;
const FILE_TRANSFER_SEQUENCE_TIMEOUT_DEFAULT: u32 = 30000;

const USB_CLASS_CDC_DATA: u8 = 0x0A;

impl BridgeManager {
    pub(crate) fn new(verbose: bool, wait_for_device: bool) -> Self {
        let context = Context::new().expect("Failed to create libusb context");
        Self {
            verbose,
            wait_for_device,
            context,
            handle: None,
            usb_log_level: LogLevel::Error,

            interface_index: -1,
            alt_setting_index: -1,
            in_endpoint: 0,
            out_endpoint: 0,

            interface_claimed: false,

            file_transfer_sequence_max_length: FILE_TRANSFER_SEQUENCE_MAX_LENGTH_DEFAULT,
            file_transfer_packet_size: FILE_TRANSFER_PACKET_SIZE_DEFAULT,
            file_transfer_sequence_timeout: FILE_TRANSFER_SEQUENCE_TIMEOUT_DEFAULT,
            lz4_supported: false,
        }
    }

    pub(crate) fn set_usb_log_level(&mut self, level: &str) {
        self.usb_log_level = match level.to_lowercase().as_str() {
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warning" => LogLevel::Warning,
            "error" => LogLevel::Error,
            "none" => LogLevel::None,
            _ => LogLevel::Error,
        };
        self.context.set_log_level(self.usb_log_level);
    }

    pub(crate) fn detect_device(&mut self) -> Result<(), BridgeError> {
        if self.wait_for_device {
            println!("Waiting for device...");
        }

        loop {
            if let Ok(devices) = self.context.devices() {
                for device in devices.iter() {
                    if let Ok(descriptor) = device.device_descriptor() {
                        for &(vid, pid) in SUPPORTED_DEVICES {
                            if descriptor.vendor_id() == vid && descriptor.product_id() == pid {
                                println!("Device detected");
                                return Ok(());
                            }
                        }
                    }
                }
            }

            if self.wait_for_device {
                std::thread::sleep(Duration::from_secs(1));
            } else {
                break;
            }
        }

        Err(BridgeError::DeviceNotFound)
    }

    fn find_device_interface(&mut self) -> Result<(), BridgeError> {
        if self.wait_for_device {
            println!("Waiting for device...");
        } else {
            println!("Detecting device...");
        }

        let mut heimdall_device = None;

        loop {
            if let Ok(devices) = self.context.devices() {
                for device in devices.iter() {
                    if let Ok(descriptor) = device.device_descriptor() {
                        for &(vid, pid) in SUPPORTED_DEVICES {
                            if descriptor.vendor_id() == vid && descriptor.product_id() == pid {
                                heimdall_device = Some(device);
                                break;
                            }
                        }
                    }
                    if heimdall_device.is_some() {
                        break;
                    }
                }
            }

            if heimdall_device.is_some() {
                break;
            }

            if self.wait_for_device {
                std::thread::sleep(Duration::from_secs(1));
            } else {
                break;
            }
        }

        let device = match heimdall_device {
            Some(d) => d,
            None => return Err(BridgeError::DeviceNotFound),
        };

        let handle = match device.open() {
            Ok(h) => h,
            Err(e) => return Err(BridgeError::DeviceAccess(e)),
        };

        if let Ok(config) = handle.active_configuration() {
            if config != 1 {
                let _ = handle.set_active_configuration(1);
            }
        } else {
            let _ = handle.set_active_configuration(1);
        }

        if self.verbose {
            if let Ok(descriptor) = device.device_descriptor() {
                if let Ok(languages) = handle.read_languages(Duration::from_secs(1)) {
                    if !languages.is_empty() {
                        if let Ok(manufacturer) = handle.read_manufacturer_string_ascii(&descriptor)
                        {
                            println!("      Manufacturer: \"{}\"", manufacturer);
                        }
                        if let Ok(product) = handle.read_product_string_ascii(&descriptor) {
                            println!("           Product: \"{}\"", product);
                        }
                        if let Ok(serial) = handle.read_serial_number_string_ascii(&descriptor) {
                            println!("         Serial No: \"{}\"", serial);
                        }
                    }
                }

                println!("\n            length: {}", descriptor.length());
                println!("      device class: {}", descriptor.class_code());
                println!(
                    "               S/N: {}",
                    descriptor.serial_number_string_index().unwrap_or(0)
                );
                println!(
                    "           VID:PID: {:04X}:{:04X}",
                    descriptor.vendor_id(),
                    descriptor.product_id()
                );

                let version = descriptor.device_version();
                let bcd = (version.0 as u16) << 8 | (version.1 as u16) << 4 | (version.2 as u16);
                println!("         bcdDevice: {:04X}", bcd);

                println!(
                    "   iMan:iProd:iSer: {}:{}:{}",
                    descriptor.manufacturer_string_index().unwrap_or(0),
                    descriptor.product_string_index().unwrap_or(0),
                    descriptor.serial_number_string_index().unwrap_or(0)
                );
                println!("          nb confs: {}", descriptor.num_configurations());
            }
        }

        let config_descriptor = device
            .config_descriptor(0)
            .map_err(|_| BridgeError::ConfigDescriptorRetrieval)?;

        self.interface_index = -1;
        self.alt_setting_index = -1;

        for interface in config_descriptor.interfaces() {
            for setting in interface.descriptors() {
                if self.verbose {
                    println!(
                        "\ninterface[{}].altsetting[{}]: num endpoints = {}",
                        interface.number(),
                        setting.setting_number(),
                        setting.num_endpoints()
                    );
                    println!(
                        "   Class.SubClass.Protocol: {:02X}.{:02X}.{:02X}",
                        setting.class_code(),
                        setting.sub_class_code(),
                        setting.protocol_code()
                    );
                }

                let mut in_endpoint_address = None;
                let mut out_endpoint_address = None;

                for (i, endpoint) in setting.endpoint_descriptors().enumerate() {
                    if self.verbose {
                        println!("       endpoint[{}].address: {:02X}", i, endpoint.address());
                        println!(
                            "           max packet size: {:04X}",
                            endpoint.max_packet_size()
                        );
                        println!("          polling interval: {:02X}", endpoint.interval());
                    }

                    if endpoint.direction() == rusb::Direction::In {
                        in_endpoint_address = Some(endpoint.address());
                    } else {
                        out_endpoint_address = Some(endpoint.address());
                    }
                }

                if self.interface_index < 0
                    && setting.num_endpoints() == 2
                    && setting.class_code() == USB_CLASS_CDC_DATA
                {
                    if let (Some(in_addr), Some(out_addr)) =
                        (in_endpoint_address, out_endpoint_address)
                    {
                        self.interface_index = interface.number() as i32;
                        self.alt_setting_index = setting.setting_number() as i32;
                        self.in_endpoint = in_addr;
                        self.out_endpoint = out_addr;
                    }
                }
            }
        }

        if self.interface_index < 0 {
            return Err(BridgeError::InterfaceConfigurationNotFound);
        }

        self.handle = Some(handle);
        Ok(())
    }

    fn claim_device_interface(&mut self) -> Result<(), BridgeError> {
        println!("Claiming interface...");

        let handle = self.handle.as_mut().unwrap();
        if handle.claim_interface(self.interface_index as u8).is_err() {
            #[cfg(target_os = "linux")]
            {
                println!("Attempt failed. Detaching driver...");
                let _ = handle.detach_kernel_driver(self.interface_index as u8);
                println!("Claiming interface again...");
                if handle.claim_interface(self.interface_index as u8).is_err() {
                    return Err(BridgeError::InterfaceClaimFailed);
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(BridgeError::InterfaceClaimFailed);
            }
        }

        self.interface_claimed = true;
        Ok(())
    }

    fn setup_device_interface(&mut self) -> Result<(), BridgeError> {
        if self.alt_setting_index == 0 {
            return Ok(());
        }

        println!("Setting up interface...");

        let handle = self.handle.as_mut().unwrap();
        handle
            .set_alternate_setting(self.interface_index as u8, self.alt_setting_index as u8)
            .map_err(|_| BridgeError::InterfaceSetupFailed)?;

        Ok(())
    }

    fn release_device_interface(&mut self) {
        println!("Releasing device interface...");

        if let Some(handle) = self.handle.as_mut() {
            let _ = handle.release_interface(self.interface_index as u8);

            #[cfg(target_os = "linux")]
            {
                let _ = handle.attach_kernel_driver(self.interface_index as u8);
            }
        }

        self.interface_claimed = false;
    }

    fn initialise_protocol(&mut self) -> Result<(), BridgeError> {
        println!("Initialising protocol...");

        {
            let handle = self.handle.as_mut().unwrap();
            println!("Resetting device...");
            if let Err(e) = handle.reset() {
                print_warning!("Failed to reset device! Result: {}", e);
            }
        }

        self.send_packet(&packets::HandshakePacket::new(), 1000)
            .map_err(|_| BridgeError::HandshakeSendFailed)?;

        let response = self
            .receive_packet::<packets::HandshakeResponse>(1000)
            .map_err(|_| BridgeError::HandshakeReceiveFailed)?;

        match response {
            packets::HandshakeResponse::Loke => {
                println!("Protocol initialisation successful.\n");
                Ok(())
            }
            packets::HandshakeResponse::Unknown(raw_data) => {
                if self.verbose {
                    return Err(BridgeError::HandshakeMismatch {
                        expected: "LOKE".to_string(),
                        received: String::from_utf8_lossy(&raw_data).into_owned(),
                    });
                }
                Err(BridgeError::UnexpectedHandshake)
            }
        }
    }

    pub(crate) fn initialise(&mut self) -> Result<(), BridgeError> {
        println!("Initialising connection...");

        self.find_device_interface()?;
        self.claim_device_interface()?;
        self.setup_device_interface()?;
        self.initialise_protocol()?;

        Ok(())
    }

    pub(crate) fn begin_session(&mut self) -> Result<(), BridgeError> {
        println!("Beginning session...");

        let packet = RequestPacket::begin_session();
        let device_default_packet_size = self
            .request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::BeginSessionFailed)?;

        self.lz4_supported = (device_default_packet_size & 0x8000) != 0;

        println!("\nSome devices may take up to 2 minutes to respond.\nPlease be patient!\n");
        std::thread::sleep(Duration::from_millis(3000));

        if device_default_packet_size != 0 {
            self.file_transfer_sequence_timeout = 120000;
            self.file_transfer_packet_size = 0x100000;
            self.file_transfer_sequence_max_length = 30;

            let packet = RequestPacket::file_part_size(self.file_transfer_packet_size as u32);
            let value = self
                .request_and_response(&packet, 3000)
                .map_err(|_| BridgeError::FilePartSizeSendFailed)?;

            if value != 0 {
                return Err(BridgeError::UnexpectedFilePartSizeResponse(value));
            }
        }

        println!("Session begun.\n");
        Ok(())
    }

    pub(crate) fn end_session(&self) -> Result<(), BridgeError> {
        println!("Ending session...");

        let packet = RequestPacket::end_session();
        self.request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::EndSessionSendFailed)?;

        println!("Rebooting device...");

        let packet = RequestPacket::reboot_device();
        self.request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::RebootDeviceSendFailed)?;

        Ok(())
    }

    fn send_bulk_transfer(&self, data: &[u8], timeout: i32, retry: bool) -> bool {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => return false,
        };

        let max_attempts = if retry { 6 } else { 1 };
        for attempt in 0..max_attempts {
            if attempt > 0 {
                if self.verbose {
                    println!(" Retrying...");
                }
                std::thread::sleep(Duration::from_millis(250 * attempt));
            }

            let result = handle.write_bulk(
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

    fn receive_bulk_transfer(&self, data: &mut [u8], timeout: i32, retry: bool) -> i32 {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => return -1,
        };

        let max_attempts = if retry { 6 } else { 1 };

        for attempt in 0..max_attempts {
            if attempt > 0 {
                if self.verbose {
                    println!(" Retrying...");
                }
                std::thread::sleep(Duration::from_millis(250 * attempt));
            }

            let result = handle.read_bulk(
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

    fn send_packet(
        &self,
        packet: &(impl packets::OutboundPacket + std::fmt::Debug),
        timeout: i32,
    ) -> Result<(), ()> {
        if self.verbose {
            println!("Sending packet: {:#04X?}", packet);
        }
        let packet_bytes = packet.pack();
        if !self.send_bulk_transfer(&packet_bytes, timeout, true) {
            return Err(());
        }
        Ok(())
    }

    fn receive_packet<T: packets::InboundPacket + std::fmt::Debug>(
        &self,
        timeout: i32,
    ) -> Result<T, BridgeError> {
        let mut buffer = vec![0u8; T::SIZE];
        let received_size = self.receive_bulk_transfer(&mut buffer, timeout, true);

        if received_size < 0 {
            return Err(BridgeError::ReceivePacketFailed);
        }

        buffer.truncate(received_size as usize);
        let parsed = T::unpack(&buffer).map_err(BridgeError::from)?;
        if self.verbose {
            println!("Received packet: {:#04X?}", parsed);
        }
        Ok(parsed)
    }

    pub(crate) fn request_and_response(
        &self,
        packet: &RequestPacket,
        timeout: i32,
    ) -> Result<u32, BridgeError> {
        self.send_packet(packet, timeout)
            .map_err(|_| BridgeError::SendPacketFailed)?;

        let response = self.receive_packet::<packets::Response>(timeout)?;
        let expected_type = packet.expected_response_type();

        if response.response_type != expected_type {
            return Err(BridgeError::ResponseTypeMismatch {
                expected: expected_type,
                received: response.response_type,
            });
        }

        Ok(response.value)
    }

    pub(crate) fn send_pit_data(&self, pit_data: &PitData) -> Result<(), BridgeError> {
        let pit_buffer_size = pit_data.get_padded_size();

        // Start file transfer
        let packet = RequestPacket::pit_file_flash();
        self.request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::PitFileTransferInitFailed)?;

        // Transfer file size
        let packet = RequestPacket::flash_part_pit_file(pit_buffer_size);
        self.request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::PitFilePartInfoSendFailed)?;

        // Create packed in-memory PIT file
        let mut pit_buffer = vec![0u8; pit_buffer_size as usize];
        pit_data.pack(&mut pit_buffer);

        // Flash pit file
        let packet = packets::FilePartPacket::new(&pit_buffer, pit_buffer_size);
        self.send_packet(&packet, 3000)
            .map_err(|_| BridgeError::SendPacketFailed)?;

        let response = self.receive_packet::<packets::Response>(3000)?;

        if response.response_type != packets::RESPONSE_TYPE_PIT_FILE {
            return Err(BridgeError::ResponseTypeMismatch {
                expected: packets::RESPONSE_TYPE_PIT_FILE,
                received: response.response_type,
            });
        }

        // End pit file transfer
        let packet = RequestPacket::end_pit_file_transfer(pit_buffer_size);
        self.request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::PitFileTransferEndSendFailed)?;

        Ok(())
    }

    fn receive_pit_file(&self) -> Result<Vec<u8>, BridgeError> {
        let packet = RequestPacket::pit_file_dump();
        let file_size = self
            .request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::PitFileSizeReceiveFailed)?;

        let mut transfer_count = file_size / 500; // ReceiveFilePartPacket::kDataSize
        if file_size % 500 != 0 {
            transfer_count += 1;
        }

        let mut buffer = Vec::with_capacity(file_size as usize);

        for i in 0..transfer_count {
            let packet = RequestPacket::dump_part_pit_file(i);
            self.send_packet(&packet, 3000)
                .map_err(|_| BridgeError::PitFilePartRequestFailed(i))?;

            let part = self
                .receive_packet::<packets::PitDataPacket>(3000)
                .map_err(|_| BridgeError::PitFilePartReceiveFailed(i))?;
            buffer.extend_from_slice(&part.data);
        }

        // End file transfer
        let packet = RequestPacket::pit_file_end();
        self.request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::PitFileEndSendFailed)?;

        Ok(buffer)
    }

    pub(crate) fn download_pit_file(&self) -> Result<Vec<u8>, BridgeError> {
        println!("Downloading device's PIT file...");

        let pit_file = self.receive_pit_file().map_err(|e| {
            print_error!("{}", e);
            BridgeError::PitDownloadFailed
        })?;

        println!("PIT file download successful.\n");
        Ok(pit_file)
    }

    pub(crate) fn is_lz4_supported(&self) -> bool {
        self.lz4_supported
    }

    pub(crate) fn send_file(
        &self,
        info: &mut crate::firmware::FirmwareFile,
    ) -> Result<(), BridgeError> {
        let packet = RequestPacket::file_transfer_flash();
        self.request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::FileTransferInitFailed)?;

        let sequences = crate::firmware::SequenceIterator::new(
            &mut info.file,
            info.file_size,
            self.file_transfer_packet_size,
            self.file_transfer_sequence_max_length,
        );

        let mut sequences = sequences.peekable();
        while let Some(sequence_data) = sequences.next() {
            let start_packet = RequestPacket::flash_part_file_transfer(sequence_data.len() as u32);

            let is_last_sequence = sequences.peek().is_none();
            let end_packet = match info.pit_entry.binary_type {
                BinaryType::ApplicationProcessor => RequestPacket::end_phone_file_transfer(
                    sequence_data.len() as u32,
                    info.pit_entry,
                    is_last_sequence,
                ),
                BinaryType::CommunicationProcessor => RequestPacket::end_modem_file_transfer(
                    sequence_data.len() as u32,
                    info.pit_entry,
                    is_last_sequence,
                ),
            };

            self.send_file_sequence(&start_packet, &end_packet, sequence_data)?;
        }

        Ok(())
    }

    pub(crate) fn send_lz4_file(
        &self,
        info: &mut crate::firmware::FirmwareLz4File,
    ) -> Result<(), BridgeError> {
        let packet = RequestPacket::lz4_file_transfer_flash();
        self.request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::FileTransferInitFailed)?;

        let sequences = crate::firmware::Lz4SequenceIterator::new(
            &mut info.file,
            &info.header,
            self.file_transfer_packet_size,
            self.file_transfer_sequence_max_length,
        );

        let mut sequences = sequences.peekable();
        while let Some((decompressed_size, sequence_data)) = sequences.next() {
            let start_packet =
                RequestPacket::flash_lz4_part_file_transfer(sequence_data.len() as u32);

            let is_last_sequence = sequences.peek().is_none();
            let end_packet = match info.pit_entry.binary_type {
                BinaryType::ApplicationProcessor => RequestPacket::end_lz4_phone_file_transfer(
                    decompressed_size as u32,
                    info.pit_entry,
                    is_last_sequence,
                ),
                BinaryType::CommunicationProcessor => RequestPacket::end_lz4_modem_file_transfer(
                    decompressed_size as u32,
                    info.pit_entry,
                    is_last_sequence,
                ),
            };

            self.send_file_sequence(&start_packet, &end_packet, sequence_data)?;
        }

        Ok(())
    }

    fn send_file_sequence(
        &self,
        start_packet: &RequestPacket,
        end_packet: &RequestPacket,
        mut sequence_data: Vec<u8>,
    ) -> Result<(), BridgeError> {
        // Pad sequence_data to full packets
        let remainder = sequence_data.len() % self.file_transfer_packet_size;
        if remainder != 0 {
            let padding = self.file_transfer_packet_size - remainder;
            sequence_data.resize(sequence_data.len() + padding, 0);
        }

        self.request_and_response(start_packet, 3000)
            .map_err(|_| BridgeError::FileTransferSequenceBeginFailed)?;

        for (file_part_index, file_buffer) in sequence_data
            .chunks(self.file_transfer_packet_size)
            .enumerate()
        {
            let mut success = false;
            for retry in 0..5 {
                if retry > 0 {
                    println!("\nRetrying...");
                }

                let packet = packets::FilePartPacket::new(
                    file_buffer,
                    self.file_transfer_packet_size as u32,
                );

                if self.send_packet(&packet, 3000).is_err() {
                    continue;
                }

                match self
                    .receive_packet::<packets::Response>(self.file_transfer_sequence_timeout as i32)
                {
                    Ok(response)
                        if response.response_type == packets::RESPONSE_TYPE_SEND_FILE_PART =>
                    {
                        if response.value as usize == file_part_index {
                            success = true;
                            break;
                        } else if retry == 0 {
                            return Err(BridgeError::FilePartIndexMismatch {
                                expected: file_part_index,
                                received: response.value,
                            });
                        }
                    }
                    _ => {}
                }
            }

            if !success {
                return Err(BridgeError::FilePartResponseReceiveFailed);
            }
        }

        self.request_and_response(end_packet, self.file_transfer_sequence_timeout as i32)
            .map_err(|_| BridgeError::FileTransferSequenceEndFailed)?;

        Ok(())
    }

    pub(crate) fn set_total_bytes(&self, total_bytes: u64) -> Result<(), BridgeError> {
        let packet = RequestPacket::total_bytes(total_bytes);
        let value = self
            .request_and_response(&packet, 3000)
            .map_err(|_| BridgeError::TotalBytesSendFailed)?;

        if value != 0 {
            return Err(BridgeError::UnexpectedTotalBytesResponse(value));
        }

        Ok(())
    }
}

impl Drop for BridgeManager {
    fn drop(&mut self) {
        if self.interface_claimed {
            self.release_device_interface();
        }
    }
}
