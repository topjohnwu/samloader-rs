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
use crate::packets;
use crate::packets::{InboundPacket, PitDataPacket, RequestPacket};
use crate::usb::UsbTransfer;
use samloader_pit::BinaryType;
use std::time::Duration;

pub struct OdinManager {
    verbose: bool,
    usb: Box<dyn UsbTransfer>,

    file_transfer_sequence_max_length: usize,
    file_transfer_packet_size: usize,
    file_transfer_sequence_timeout: u32,
    lz4_supported: bool,
}

const FILE_TRANSFER_SEQUENCE_MAX_LENGTH_DEFAULT: usize = 800;
const FILE_TRANSFER_PACKET_SIZE_DEFAULT: usize = 0x20000;
const FILE_TRANSFER_SEQUENCE_TIMEOUT_DEFAULT: u32 = 30000;

impl OdinManager {
    pub fn new(usb: Box<dyn UsbTransfer>, verbose: bool) -> Self {
        Self {
            verbose,
            usb,

            file_transfer_sequence_max_length: FILE_TRANSFER_SEQUENCE_MAX_LENGTH_DEFAULT,
            file_transfer_packet_size: FILE_TRANSFER_PACKET_SIZE_DEFAULT,
            file_transfer_sequence_timeout: FILE_TRANSFER_SEQUENCE_TIMEOUT_DEFAULT,
            lz4_supported: false,
        }
    }

    pub fn init(&mut self) -> Result<(), OdinError> {
        println!("Initializing protocol...");

        self.send_string("ODIN", 1000)
            .map_err(|_| OdinError::HandshakeSendFailed)?;

        let response = self
            .receive_string(1000)
            .map_err(|_| OdinError::HandshakeReceiveFailed)?;

        if response == "LOKE" {
            println!("Protocol initialization successful.\n");
            Ok(())
        } else {
            Err(OdinError::HandshakeMismatch {
                expected: "LOKE".to_string(),
                received: response,
            })
        }
    }

    pub fn begin_session(&mut self) -> Result<(), OdinError> {
        println!("Beginning session...");

        let packet = RequestPacket::begin_session();
        let device_default_packet_size = self
            .request_and_response(&packet, 3000)
            .map_err(|_| OdinError::BeginSessionFailed)?;

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
                .map_err(|_| OdinError::FilePartSizeSendFailed)?;

            if value != 0 {
                return Err(OdinError::UnexpectedFilePartSizeResponse(value));
            }
        }

        println!("Session begun.\n");
        Ok(())
    }

    pub fn end_session(&mut self) -> Result<(), OdinError> {
        println!("Ending session...");

        let packet = RequestPacket::end_session();
        self.request_and_response(&packet, 3000)
            .map_err(|_| OdinError::EndSessionSendFailed)?;

        Ok(())
    }

    pub fn reboot_device(&mut self) -> Result<(), OdinError> {
        println!("Rebooting device...");

        let packet = RequestPacket::reboot_device();
        self.request_and_response(&packet, 3000)
            .map_err(|_| OdinError::RebootDeviceSendFailed)?;

        Ok(())
    }

    fn send_string(&mut self, s: &str, timeout: i32) -> Result<(), OdinError> {
        if self.verbose {
            eprintln!("Sending string: {:?}", s);
        }
        if !self.usb.send_data(s.as_bytes(), timeout, true) {
            return Err(OdinError::SendPacketFailed);
        }
        Ok(())
    }

    fn receive_string(&mut self, timeout: i32) -> Result<String, OdinError> {
        let mut buffer = [0u8; 1024];
        let received_size = self.usb.receive_data(&mut buffer, timeout, true);

        if received_size < 0 {
            return Err(OdinError::ReceivePacketFailed);
        }

        let mut data = buffer.to_vec();
        data.truncate(received_size as usize);
        if self.verbose {
            eprintln!("Received string data ({} bytes): {:?}", received_size, data);
        }
        Ok(String::from_utf8_lossy(&data).into_owned())
    }

    fn send_packet(
        &mut self,
        packet: &(impl packets::OutboundPacket + std::fmt::Debug),
        timeout: i32,
    ) -> Result<(), ()> {
        if self.verbose {
            eprintln!("Sending packet: {:#04X?}", packet);
        }
        let packet_bytes = packet.pack();
        if !self.usb.send_data(&packet_bytes, timeout, true) {
            return Err(());
        }
        Ok(())
    }

    fn receive_packet_with_size<T: InboundPacket + std::fmt::Debug>(
        &mut self,
        size: usize,
        timeout: i32,
    ) -> Result<T, OdinError> {
        let mut buffer = vec![0u8; size];
        let received_size = self.usb.receive_data(&mut buffer, timeout, true);

        if received_size < 0 {
            return Err(OdinError::ReceivePacketFailed);
        }

        buffer.truncate(received_size as usize);
        let parsed = T::unpack(&buffer).map_err(OdinError::ParseError)?;
        if self.verbose {
            eprintln!("Received packet: {:#04X?}", parsed);
        }
        Ok(parsed)
    }

    fn receive_packet<T: InboundPacket + std::fmt::Debug>(
        &mut self,
        timeout: i32,
    ) -> Result<T, OdinError> {
        self.receive_packet_with_size::<T>(T::SIZE, timeout)
    }

    pub(crate) fn request_and_response(
        &mut self,
        packet: &RequestPacket,
        timeout: i32,
    ) -> Result<u32, OdinError> {
        self.send_packet(packet, timeout)
            .map_err(|_| OdinError::SendPacketFailed)?;

        let response = self.receive_packet::<packets::Response>(timeout)?;
        let expected_type = packet.expected_response_type();

        if response.response_type != expected_type {
            return Err(OdinError::ResponseTypeMismatch {
                expected: expected_type,
                received: response.response_type,
            });
        }

        Ok(response.value)
    }

    pub fn send_pit_data(&mut self, pit_buffer: &[u8]) -> Result<(), OdinError> {
        let pit_buffer_size = pit_buffer.len() as u32;

        // Start file transfer
        let packet = RequestPacket::pit_file_flash();
        self.request_and_response(&packet, 3000)
            .map_err(|_| OdinError::PitFileTransferInitFailed)?;

        // Transfer file size
        let packet = RequestPacket::flash_part_pit_file(pit_buffer_size);
        self.request_and_response(&packet, 3000)
            .map_err(|_| OdinError::PitFilePartInfoSendFailed)?;

        // Flash pit file
        let packet = packets::FilePartPacket::new(pit_buffer, pit_buffer_size);
        self.send_packet(&packet, 3000)
            .map_err(|_| OdinError::SendPacketFailed)?;

        let response = self.receive_packet::<packets::Response>(3000)?;

        if response.response_type != packets::RESPONSE_TYPE_PIT_FILE {
            return Err(OdinError::ResponseTypeMismatch {
                expected: packets::RESPONSE_TYPE_PIT_FILE,
                received: response.response_type,
            });
        }

        // End pit file transfer
        let packet = RequestPacket::end_pit_file_transfer(pit_buffer_size);
        self.request_and_response(&packet, 3000)
            .map_err(|_| OdinError::PitFileTransferEndSendFailed)?;

        Ok(())
    }

    pub fn download_pit_file(&mut self) -> Result<Vec<u8>, OdinError> {
        println!("Downloading device's PIT file...");

        let packet = RequestPacket::pit_file_dump();
        let file_size = self
            .request_and_response(&packet, 3000)
            .map_err(|_| OdinError::PitFileSizeReceiveFailed)? as usize;

        let transfer_count = file_size.div_ceil(PitDataPacket::SIZE);
        let mut buffer = Vec::with_capacity(file_size);

        for i in 0..transfer_count {
            let packet = RequestPacket::dump_part_pit_file(i as u32);
            self.send_packet(&packet, 3000)
                .map_err(|_| OdinError::PitFilePartRequestFailed(i as u32))?;

            let expected_size = std::cmp::min(file_size - buffer.len(), PitDataPacket::SIZE);

            let part = self
                .receive_packet_with_size::<PitDataPacket>(expected_size, 3000)
                .map_err(|_| OdinError::PitFilePartReceiveFailed(i as u32))?;
            buffer.extend_from_slice(&part.data);
        }

        // End file transfer
        let packet = RequestPacket::pit_file_end();
        self.request_and_response(&packet, 3000)
            .map_err(|_| OdinError::PitFileEndSendFailed)?;

        println!("PIT file download successful.\n");
        Ok(buffer)
    }

    pub fn is_lz4_supported(&self) -> bool {
        self.lz4_supported
    }

    pub fn send_file(&mut self, info: &mut crate::firmware::FirmwareFile) -> Result<(), OdinError> {
        let packet = RequestPacket::file_transfer_flash();
        self.request_and_response(&packet, 3000)
            .map_err(|_| OdinError::FileTransferInitFailed)?;

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

    pub fn send_lz4_file(
        &mut self,
        info: &mut crate::firmware::FirmwareLz4File,
    ) -> Result<(), OdinError> {
        let packet = RequestPacket::lz4_file_transfer_flash();
        self.request_and_response(&packet, 3000)
            .map_err(|_| OdinError::FileTransferInitFailed)?;

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
        &mut self,
        start_packet: &RequestPacket,
        end_packet: &RequestPacket,
        sequence_data: Vec<u8>,
    ) -> Result<(), OdinError> {
        self.request_and_response(start_packet, 3000)
            .map_err(|_| OdinError::FileTransferSequenceBeginFailed)?;

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
                            return Err(OdinError::FilePartIndexMismatch {
                                expected: file_part_index,
                                received: response.value,
                            });
                        }
                    }
                    _ => {}
                }
            }

            if !success {
                return Err(OdinError::FilePartResponseReceiveFailed);
            }
        }

        self.request_and_response(end_packet, self.file_transfer_sequence_timeout as i32)
            .map_err(|_| OdinError::FileTransferSequenceEndFailed)?;

        Ok(())
    }

    pub fn set_total_bytes(&mut self, total_bytes: u64) -> Result<(), OdinError> {
        let packet = RequestPacket::total_bytes(total_bytes);
        let value = self
            .request_and_response(&packet, 3000)
            .map_err(|_| OdinError::TotalBytesSendFailed)?;

        if value != 0 {
            return Err(OdinError::UnexpectedTotalBytesResponse(value));
        }

        Ok(())
    }
}

pub fn reboot_download() -> Result<(), OdinError> {
    use std::io::Write;

    // List all available ports
    let ports = serialport::available_ports()
        .map_err(|e| OdinError::SerialError(format!("Failed to list serial ports: {}", e)))?;

    // Find first Samsung device
    let mut samsung_port = None;
    for port in ports {
        match port.port_type {
            serialport::SerialPortType::UsbPort(info) if info.vid == crate::usb::VID_SAMSUNG => {
                samsung_port = Some(port.port_name);
                break;
            }
            _ => {}
        }
    }

    let port_name = samsung_port
        .ok_or_else(|| OdinError::SerialError("No Samsung serial port found".to_string()))?;

    let cmd: &[u8] = b"AT+SUDDLMOD=0,0\r";

    // Open connection at 115200 baud with 1s timeout
    let mut port = serialport::new(&port_name, 115_200)
        .timeout(Duration::from_secs(1))
        .open()
        .map_err(|e| OdinError::SerialError(format!("Failed to open port {}: {}", port_name, e)))?;

    // Write command
    port.write_all(cmd)
        .map_err(|e| OdinError::SerialError(format!("Failed to send data: {}", e)))?;

    // Flush port output buffer
    port.flush()
        .map_err(|e| OdinError::SerialError(format!("Failed to flush serial buffer: {}", e)))?;

    Ok(())
}
