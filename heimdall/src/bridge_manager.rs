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

use crate::packets;
use crate::{print_error, print_warning};
use crate::{FileTransferDestination, InitialiseResult};
use libpit::PitData;
use rusb::{Context, DeviceHandle, LogLevel, UsbContext};
use std::time::Duration;

#[derive(Copy, Clone, PartialEq, Eq)]
enum EmptyTransferMode {
    None = 0x0,
    Before = 0x1,
    After = 0x2,
    BeforeAndAfter = 0x3,
}

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

    file_transfer_sequence_max_length: u32,
    file_transfer_packet_size: u32,
    file_transfer_sequence_timeout: u32,
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

const FILE_TRANSFER_SEQUENCE_MAX_LENGTH_DEFAULT: u32 = 800;
const FILE_TRANSFER_PACKET_SIZE_DEFAULT: u32 = 131072;
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

    pub(crate) fn detect_device(&mut self) -> bool {
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
                                return true;
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

        print_device_detection_failed();
        false
    }

    fn find_device_interface(&mut self) -> InitialiseResult {
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
            None => {
                print_device_detection_failed();
                return InitialiseResult::DeviceNotDetected;
            }
        };

        let handle = match device.open() {
            Ok(h) => h,
            Err(e) => {
                print_error!("Failed to access device. libusb error: {}", e);
                return InitialiseResult::Failed;
            }
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

        let config_descriptor = match device.config_descriptor(0) {
            Ok(c) => c,
            Err(_) => {
                print_error!("Failed to retrieve config descriptor");
                return InitialiseResult::Failed;
            }
        };

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
            print_error!("Failed to find correct interface configuration");
            return InitialiseResult::Failed;
        }

        self.handle = Some(handle);
        InitialiseResult::Succeeded
    }

    fn claim_device_interface(&mut self) -> bool {
        println!("Claiming interface...");

        let handle = self.handle.as_mut().unwrap();
        if handle.claim_interface(self.interface_index as u8).is_err() {
            #[cfg(target_os = "linux")]
            {
                println!("Attempt failed. Detaching driver...");
                let _ = handle.detach_kernel_driver(self.interface_index as u8);
                println!("Claiming interface again...");
                if handle.claim_interface(self.interface_index as u8).is_err() {
                    print_error!("Claiming interface failed!");
                    return false;
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                print_error!("Claiming interface failed!");
                return false;
            }
        }

        self.interface_claimed = true;
        true
    }

    fn setup_device_interface(&mut self) -> bool {
        if self.alt_setting_index == 0 {
            return true;
        }

        println!("Setting up interface...");

        let handle = self.handle.as_mut().unwrap();
        if handle
            .set_alternate_setting(self.interface_index as u8, self.alt_setting_index as u8)
            .is_err()
        {
            print_error!("Setting up interface failed!");
            return false;
        }

        println!();
        true
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
        println!();
    }

    fn initialise_protocol(&mut self) -> bool {
        println!("Initialising protocol...");

        {
            let handle = self.handle.as_mut().unwrap();
            println!("Resetting device...");
            if let Err(e) = handle.reset() {
                print_error!("Failed to reset device! Result: {}", e);
            }
        }

        if !self.send_bulk_transfer(b"ODIN".as_ptr(), 4, 1000, true) {
            print_error!("Failed to send handshake!");
        }

        let mut data_buffer = [0u8; 1024];
        let data_transferred =
            self.receive_bulk_transfer(data_buffer.as_mut_ptr(), 1024, 1000, true);

        if data_transferred == 4 && &data_buffer[0..4] == b"LOKE" {
            println!("Protocol initialisation successful.\n");
            return true;
        } else {
            if self.verbose {
                if data_transferred >= 0 {
                    print_error!(
                        "Expected: \"LOKE\"\nReceived: \"{}\"",
                        String::from_utf8_lossy(&data_buffer[0..data_transferred as usize])
                    );
                } else {
                    print_error!("Failed to receive handshake response.");
                }
            }
            print_error!("Unexpected handshake response!");
        }

        print_error!("Protocol initialisation failed!\n");
        false
    }

    pub(crate) fn initialise(&mut self) -> InitialiseResult {
        println!("Initialising connection...");

        let res = self.find_device_interface();
        if res != InitialiseResult::Succeeded {
            return res;
        }

        if !self.claim_device_interface() {
            return InitialiseResult::Failed;
        }

        if !self.setup_device_interface() {
            return InitialiseResult::Failed;
        }

        if !self.initialise_protocol() {
            return InitialiseResult::Failed;
        }

        InitialiseResult::Succeeded
    }

    pub(crate) fn begin_session(&mut self) -> bool {
        println!("Beginning session...");

        let packet = packets::BeginSessionPacket::create();
        let success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

        if !success {
            print_error!("Failed to begin session!");
            return false;
        }

        let mut response = [0u8; 8];
        let success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);
        if !success {
            return false;
        }

        let device_default_packet_size =
            match packets::Response::unpack(&response, packets::RESPONSE_TYPE_SESSION_SETUP) {
                Ok(res) => res,
                Err(_) => return false,
            };

        println!("\nSome devices may take up to 2 minutes to respond.\nPlease be patient!\n");
        std::thread::sleep(Duration::from_millis(3000));

        if device_default_packet_size != 0 {
            self.file_transfer_sequence_timeout = 120000;
            self.file_transfer_packet_size = 1048576;
            self.file_transfer_sequence_max_length = 30;

            let packet = packets::FilePartSizePacket::create(self.file_transfer_packet_size);
            let success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

            if !success {
                print_error!("Failed to send file part size packet!");
                return false;
            }

            let mut response = [0u8; 8];
            let success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);
            if !success {
                return false;
            }

            match packets::Response::unpack(&response, packets::RESPONSE_TYPE_SESSION_SETUP) {
                Ok(0) => {}
                Ok(res) => {
                    print_error!(
                        "Unexpected file part size response!\nExpected: 0\nReceived: {}",
                        res
                    );
                    return false;
                }
                Err(_) => return false,
            }
        }

        println!("Session begun.\n");
        true
    }

    pub(crate) fn end_session(&self) -> bool {
        println!("Ending session...");

        let packet = packets::SessionSetupPacket::create_end_session(0); // kRequestEndSession
        let success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

        if !success {
            println!();
            print_error!("Failed to send end session packet!");
            return false;
        }

        let mut response = [0u8; 8];
        let success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);

        if !success {
            println!();
            print_error!("Failed to receive session end confirmation!");
            return false;
        }

        println!("Rebooting device...");

        let packet = packets::SessionSetupPacket::create_end_session(1); // kRequestRebootDevice
        let success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

        if !success {
            println!();
            print_error!("Failed to send reboot device packet!");
            return false;
        }

        let mut response = [0u8; 8];
        let success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);

        if !success {
            println!();
            print_error!("Failed to receive reboot confirmation!");
            return false;
        }

        true
    }

    fn send_bulk_transfer(
        &self,
        data: *const u8,
        length: i32,
        timeout: i32,
        retry: bool,
    ) -> bool {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => return false,
        };

        let data_slice = if data.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(data, length as usize) }
        };
        let mut result = handle.write_bulk(
            self.out_endpoint,
            data_slice,
            Duration::from_millis(timeout as u64),
        );

        if result.is_err() && retry {
            let retry_delay = 250;
            if self.verbose {
                print_warning!(
                    "libusb error {} whilst sending bulk transfer.",
                    result.as_ref().unwrap_err()
                );
            }

            for i in 0..5 {
                if self.verbose {
                    println!(" Retrying...");
                }
                std::thread::sleep(Duration::from_millis(retry_delay * (i + 1)));
                result = handle.write_bulk(
                    self.out_endpoint,
                    data_slice,
                    Duration::from_millis(timeout as u64),
                );
                if result.is_ok() {
                    break;
                }
                if self.verbose {
                    print_warning!(
                        "libusb error {} whilst sending bulk transfer.",
                        result.as_ref().unwrap_err()
                    );
                }
            }
            if self.verbose {
                println!();
            }
        }

        match result {
            Ok(transferred) => transferred == length as usize,
            Err(_) => false,
        }
    }

    fn receive_bulk_transfer(
        &self,
        data: *mut u8,
        length: i32,
        timeout: i32,
        retry: bool,
    ) -> i32 {
        let handle = match self.handle.as_ref() {
            Some(h) => h,
            None => return -1,
        };

        let mut dummy_data = 0u8;
        let (data_ptr, data_len) = if data.is_null() {
            (&mut dummy_data as *mut u8, 1)
        } else {
            (data, length)
        };

        let data_slice = unsafe { std::slice::from_raw_parts_mut(data_ptr, data_len as usize) };
        let mut result = handle.read_bulk(
            self.in_endpoint,
            data_slice,
            Duration::from_millis(timeout as u64),
        );

        if result.is_err() && retry {
            let retry_delay = 250;
            if self.verbose {
                print_warning!(
                    "libusb error {} whilst receiving bulk transfer.",
                    result.as_ref().unwrap_err()
                );
            }

            for i in 0..5 {
                if self.verbose {
                    println!(" Retrying...");
                }
                std::thread::sleep(Duration::from_millis(retry_delay * (i + 1)));
                result = handle.read_bulk(
                    self.in_endpoint,
                    data_slice,
                    Duration::from_millis(timeout as u64),
                );
                if result.is_ok() {
                    break;
                }
                if self.verbose {
                    print_warning!(
                        "libusb error {} whilst receiving bulk transfer.",
                        result.as_ref().unwrap_err()
                    );
                }
            }
            if self.verbose {
                println!();
            }
        }

        match result {
            Ok(transferred) => transferred as i32,
            Err(_) => -1,
        }
    }

    fn send_packet(
        &self,
        packet: &[u8],
        timeout: i32,
        empty_transfer_mode: EmptyTransferMode,
    ) -> bool {
        if (empty_transfer_mode as u32) & (EmptyTransferMode::Before as u32) != 0
            && !self.send_bulk_transfer(std::ptr::null(), 0, 100, false)
            && self.verbose
        {
            print_warning!(
                "Empty bulk transfer before sending packet failed. Continuing anyway..."
            );
        }

        if !self.send_bulk_transfer(packet.as_ptr(), packet.len() as i32, timeout, true) {
            return false;
        }

        if (empty_transfer_mode as u32) & (EmptyTransferMode::After as u32) != 0
            && !self.send_bulk_transfer(std::ptr::null(), 0, 100, false)
            && self.verbose
        {
            print_warning!("Empty bulk transfer after sending packet failed. Continuing anyway...");
        }

        true
    }

    fn receive_packet(
        &self,
        packet: &mut [u8],
        timeout: i32,
        empty_transfer_mode: EmptyTransferMode,
    ) -> bool {
        if (empty_transfer_mode as u32) & (EmptyTransferMode::Before as u32) != 0
            && self.receive_bulk_transfer(std::ptr::null_mut(), 0, 100, false) < 0
            && self.verbose
        {
            print_warning!(
                "Empty bulk transfer before receiving packet failed. Continuing anyway..."
            );
        }

        let received_size =
            self.receive_bulk_transfer(packet.as_mut_ptr(), packet.len() as i32, timeout, true);

        if received_size < 0 {
            return false;
        }

        if received_size as usize != packet.len() {
            if self.verbose {
                print_error!(
                    "Incorrect packet size received - expected size = {}, received size = {}.",
                    packet.len(),
                    received_size
                );
            }
            return false;
        }

        if (empty_transfer_mode as u32) & (EmptyTransferMode::After as u32) != 0
            && self.receive_bulk_transfer(std::ptr::null_mut(), 0, 100, false) < 0
            && self.verbose
        {
            print_warning!(
                "Empty bulk transfer after receiving packet failed. Continuing anyway..."
            );
        }

        true
    }

    pub(crate) fn send_pit_data(&self, pit_data: &PitData) -> bool {
        let pit_buffer_size = pit_data.get_padded_size();

        // Start file transfer
        let packet = packets::PitFilePacket::create(packets::REQUEST_PIT_FILE_FLASH);
        let mut success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

        if !success {
            print_error!("Failed to initialise PIT file transfer!");
            return false;
        }

        let mut response = [0u8; 8];
        success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);

        if !success
            || packets::Response::unpack(&response, packets::RESPONSE_TYPE_PIT_FILE).is_err()
        {
            print_error!("Failed to confirm transfer initialisation!");
            return false;
        }

        // Transfer file size
        let packet = packets::FlashPartPitFilePacket::create(pit_buffer_size);
        success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

        if !success {
            print_error!("Failed to send PIT file part information!");
            return false;
        }

        success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);

        if !success
            || packets::Response::unpack(&response, packets::RESPONSE_TYPE_PIT_FILE).is_err()
        {
            print_error!("Failed to confirm sending of PIT file part information!");
            return false;
        }

        // Create packed in-memory PIT file
        let mut pit_buffer = vec![0u8; pit_buffer_size as usize];
        pit_data.pack(&mut pit_buffer);

        // Flash pit file
        let packet = packets::create_send_file_part_packet(&pit_buffer, pit_buffer_size);
        success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

        if !success {
            print_error!("Failed to send file part packet!");
            return false;
        }

        success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);

        if !success
            || packets::Response::unpack(&response, packets::RESPONSE_TYPE_PIT_FILE).is_err()
        {
            print_error!("Failed to receive PIT file part response!");
            return false;
        }

        // End pit file transfer
        let packet = packets::EndPitFileTransferPacket::create(pit_buffer_size);
        success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

        if !success {
            print_error!("Failed to send end PIT file transfer packet!");
            return false;
        }

        success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);

        if !success
            || packets::Response::unpack(&response, packets::RESPONSE_TYPE_PIT_FILE).is_err()
        {
            print_error!("Failed to confirm end of PIT file transfer!");
            return false;
        }

        true
    }

    fn receive_pit_file(&self) -> Vec<u8> {
        let packet = packets::PitFilePacket::create(packets::REQUEST_PIT_FILE_DUMP);
        let mut success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

        if !success {
            print_error!("Failed to request receival of PIT file!");
            return Vec::new();
        }

        let mut response = [0u8; 8];
        success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);
        if !success {
            print_error!("Failed to receive PIT file size!");
            return Vec::new();
        }

        let file_size = match packets::Response::unpack(&response, packets::RESPONSE_TYPE_PIT_FILE)
        {
            Ok(size) => size,
            Err(_) => {
                print_error!("Failed to receive PIT file size!");
                return Vec::new();
            }
        };

        let mut transfer_count = file_size / 500; // ReceiveFilePartPacket::kDataSize
        if file_size % 500 != 0 {
            transfer_count += 1;
        }

        let mut buffer = Vec::with_capacity(file_size as usize);

        for i in 0..transfer_count {
            let packet = packets::DumpPartPitFilePacket::create(i);
            let success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

            if !success {
                print_error!("Failed to request PIT file part #{}!", i);
                return Vec::new();
            }

            let receive_empty_transfer_mode = if i == transfer_count - 1 {
                EmptyTransferMode::After
            } else {
                EmptyTransferMode::None
            };

            let mut part_buffer = [0u8; 500]; // ReceiveFilePartPacket::kDataSize
            let received_size =
                self.receive_bulk_transfer(part_buffer.as_mut_ptr(), 500, 3000, true);

            if received_size < 0 {
                print_error!("Failed to receive PIT file part #{}!", i);
                return Vec::new();
            }

            buffer.extend_from_slice(&part_buffer[0..received_size as usize]);

            if receive_empty_transfer_mode == EmptyTransferMode::After {
                let mut dummy = 0u8;
                let _ = self.receive_bulk_transfer(&mut dummy, 0, 100, false);
            }
        }

        // End file transfer
        let packet = packets::PitFilePacket::create(packets::REQUEST_PIT_FILE_END);
        success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

        if !success {
            print_error!("Failed to send request to end PIT file transfer!");
            return Vec::new();
        }

        success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);

        if !success
            || packets::Response::unpack(&response, packets::RESPONSE_TYPE_PIT_FILE).is_err()
        {
            print_error!("Failed to receive end PIT file transfer verification!");
            return Vec::new();
        }

        buffer
    }

    pub(crate) fn download_pit_file(&self) -> Vec<u8> {
        println!("Downloading device's PIT file...");

        let pit_file = self.receive_pit_file();

        if pit_file.is_empty() {
            print_error!("Failed to download PIT file!");
        } else {
            println!("PIT file download successful.\n");
        }

        pit_file
    }

    pub(crate) fn send_file_from_reader<R: std::io::Read + std::io::Seek>(
        &self,
        reader: &mut R,
        file_size: u32,
        destination: FileTransferDestination,
        device_type: u32,
        file_identifier: u32,
    ) -> bool {
        // Start file transfer
        let packet = packets::FileTransferPacket::create(packets::REQUEST_FILE_TRANSFER_FLASH);
        let mut success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

        if !success {
            print_error!("Failed to initialise file transfer!");
            return false;
        }

        let mut response = [0u8; 8];
        success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);

        if !success
            || packets::Response::unpack(&response, packets::RESPONSE_TYPE_FILE_TRANSFER).is_err()
        {
            print_error!("Failed to confirm transfer initialisation!");
            return false;
        }

        let sequence_count =
            file_size / (self.file_transfer_sequence_max_length * self.file_transfer_packet_size);
        let mut last_sequence_size = self.file_transfer_sequence_max_length;
        let partial_packet_byte_count = file_size % self.file_transfer_packet_size;

        let mut sequence_count = sequence_count;

        if !file_size
            .is_multiple_of(self.file_transfer_sequence_max_length * self.file_transfer_packet_size)
        {
            sequence_count += 1;
            let last_sequence_bytes = file_size
                % (self.file_transfer_sequence_max_length * self.file_transfer_packet_size);
            last_sequence_size = last_sequence_bytes / self.file_transfer_packet_size;
            if partial_packet_byte_count != 0 {
                last_sequence_size += 1;
            }
        }

        let mut bytes_transferred = 0u32;
        let mut previous_percent = 0u32;
        println!("0%");

        let mut file_buffer = vec![0u8; self.file_transfer_packet_size as usize];

        for sequence_index in 0..sequence_count {
            let is_last_sequence = sequence_index == sequence_count - 1;
            let sequence_size = if is_last_sequence {
                last_sequence_size
            } else {
                self.file_transfer_sequence_max_length
            };
            let sequence_total_byte_count = sequence_size * self.file_transfer_packet_size;

            let packet = packets::FlashPartFileTransferPacket::create(sequence_total_byte_count);
            success = self.send_packet(&packet, 3000, EmptyTransferMode::After);

            if !success {
                println!();
                print_error!("Failed to begin file transfer sequence!");
                return false;
            }

            success = self.receive_packet(&mut response, 3000, EmptyTransferMode::None);

            if !success
                || packets::Response::unpack(&response, packets::RESPONSE_TYPE_FILE_TRANSFER)
                    .is_err()
            {
                println!();
                print_error!("Failed to confirm beginning of file transfer sequence!");
                return false;
            }

            for file_part_index in 0..sequence_size {
                let send_empty_transfer_mode = if file_part_index == 0 {
                    EmptyTransferMode::None
                } else {
                    EmptyTransferMode::Before
                };

                let packet_byte_count = if is_last_sequence
                    && file_part_index == sequence_size - 1
                    && partial_packet_byte_count != 0
                {
                    partial_packet_byte_count
                } else {
                    self.file_transfer_packet_size
                };

                // Read data from reader
                file_buffer.fill(0);
                if let Err(e) = reader.read_exact(&mut file_buffer[..packet_byte_count as usize]) {
                    print_error!("Failed to read from file: {}", e);
                    return false;
                }

                let packet = packets::create_send_file_part_packet(
                    &file_buffer,
                    self.file_transfer_packet_size,
                );
                success = self.send_packet(&packet, 3000, send_empty_transfer_mode);

                if !success {
                    println!();
                    print_error!("Failed to send file part packet!");
                    return false;
                }

                // Response
                success = self.receive_packet(
                    &mut response,
                    self.file_transfer_sequence_timeout as i32,
                    EmptyTransferMode::None,
                );

                if success {
                    let received_part_index = match packets::Response::unpack(
                        &response,
                        packets::RESPONSE_TYPE_SEND_FILE_PART,
                    ) {
                        Ok(idx) => idx,
                        Err(_) => {
                            success = false;
                            0
                        }
                    };
                    if success && received_part_index != file_part_index {
                        println!();
                        print_error!(
                            "Expected file part index: {} Received: {}",
                            file_part_index,
                            received_part_index
                        );
                        return false;
                    }
                }

                if !success {
                    let mut retry_success = false;
                    for _ in 0..4 {
                        println!();
                        println!("Retrying...");

                        // Rewind reader pointer
                        if let Err(e) =
                            reader.seek(std::io::SeekFrom::Start(bytes_transferred as u64))
                        {
                            print_error!("Failed to seek in file: {}", e);
                            return false;
                        }
                        if let Err(e) =
                            reader.read_exact(&mut file_buffer[..packet_byte_count as usize])
                        {
                            print_error!("Failed to read from file: {}", e);
                            return false;
                        }

                        let packet = packets::create_send_file_part_packet(
                            &file_buffer,
                            self.file_transfer_packet_size,
                        );
                        success = self.send_packet(&packet, 3000, send_empty_transfer_mode);

                        if !success {
                            continue;
                        }

                        success = self.receive_packet(
                            &mut response,
                            self.file_transfer_sequence_timeout as i32,
                            EmptyTransferMode::None,
                        );

                        if success {
                            let received_part_index = match packets::Response::unpack(
                                &response,
                                packets::RESPONSE_TYPE_SEND_FILE_PART,
                            ) {
                                Ok(idx) => idx,
                                Err(_) => {
                                    success = false;
                                    0
                                }
                            };
                            if success && received_part_index == file_part_index {
                                retry_success = true;
                                break;
                            }
                        }
                    }

                    if !retry_success {
                        println!();
                        print_error!("Failed to receive file part response!");
                        return false;
                    }
                }

                bytes_transferred += packet_byte_count;
                let current_percent =
                    (100.0f32 * (bytes_transferred as f32 / file_size as f32)) as u32;

                if current_percent != previous_percent {
                    println!("\n{}%", current_percent);
                    previous_percent = current_percent;
                }
            }

            let sequence_effective_byte_count =
                if is_last_sequence && partial_packet_byte_count != 0 {
                    self.file_transfer_packet_size * (last_sequence_size - 1)
                        + partial_packet_byte_count
                } else {
                    sequence_total_byte_count
                };

            let packet = match destination {
                FileTransferDestination::Modem => packets::EndModemFileTransferPacket::create(
                    sequence_effective_byte_count,
                    0,
                    device_type,
                    is_last_sequence,
                ),
                FileTransferDestination::Phone => packets::EndPhoneFileTransferPacket::create(
                    sequence_effective_byte_count,
                    0,
                    device_type,
                    file_identifier,
                    is_last_sequence,
                ),
            };

            success = self.send_packet(&packet, 3000, EmptyTransferMode::BeforeAndAfter);

            if !success {
                println!();
                print_error!("Failed to end file transfer sequence!");
                return false;
            }

            success = self.receive_packet(
                &mut response,
                self.file_transfer_sequence_timeout as i32,
                EmptyTransferMode::None,
            );

            if !success
                || packets::Response::unpack(&response, packets::RESPONSE_TYPE_FILE_TRANSFER)
                    .is_err()
            {
                println!();
                print_error!("Failed to confirm end of file transfer sequence!");
                return false;
            }
        }

        true
    }

    pub(crate) fn send_total_bytes(&self, total_bytes: u64) -> bool {
        let packet = packets::TotalBytesPacket::create(total_bytes);
        self.send_packet(&packet, 3000, EmptyTransferMode::After)
    }

    pub(crate) fn receive_session_setup_response(&self, result: &mut u32) -> bool {
        let mut response = [0u8; 8];
        if !self.receive_packet(&mut response, 3000, EmptyTransferMode::None) {
            return false;
        }
        match packets::Response::unpack(&response, packets::RESPONSE_TYPE_SESSION_SETUP) {
            Ok(res) => {
                *result = res;
                true
            }
            Err(_) => false,
        }
    }
}

impl Drop for BridgeManager {
    fn drop(&mut self) {
        if self.interface_claimed {
            self.release_device_interface();
        }
    }
}

fn print_device_detection_failed() {
    eprintln!("ERROR: Failed to detect compatible download-mode device.");
}
