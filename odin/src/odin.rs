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

use crate::device_info::{DeviceInfo, SessionDeviceInfo};
use crate::error::{LokeError, OdinError};
use crate::packets::{self, RequestPacket};
use crate::progress;
use crate::usb::UsbTransfer;
use samloader_pit::PitEntry;
use std::time::Duration;

/// Manages the initial connection to a Samsung device in Download Mode.
///
/// At this stage, communication is restricted to raw string commands (e.g. handshake
/// strings or AT commands). Complex packet I/O requires transitioning to an [`OdinSession`]
/// via [`begin_session`](Self::begin_session).
pub struct OdinConnection {
    usb: Box<dyn UsbTransfer>,
    skip_empty_send: bool,
}

const FILE_TRANSFER_SEQUENCE_MAX_LENGTH_DEFAULT: usize = 800;
const FILE_TRANSFER_PACKET_SIZE_DEFAULT: usize = 0x20000;
const FILE_TRANSFER_SEQUENCE_TIMEOUT_DEFAULT: u32 = 30000;

impl OdinConnection {
    /// Creates a new `OdinConnection` instance with a given transport.
    ///
    /// Following official `odin4` behavior, empty packets (ZLPs) after 1024-byte
    /// request packets are skipped on Qualcomm and modern bootloaders, but are sent
    /// on older Exynos bootloaders that advertise the "Gadget Serial" USB product string.
    pub fn new(usb: Box<dyn UsbTransfer>) -> Self {
        let skip_empty_send = !usb
            .product_name()
            .is_some_and(|name| name.starts_with("Gadget Serial"));
        Self {
            usb,
            skip_empty_send,
        }
    }

    /// Returns whether empty packets are skipped after request packets.
    pub fn skip_empty_send(&self) -> bool {
        self.skip_empty_send
    }

    /// Overrides whether empty packets are skipped after request packets.
    pub fn set_skip_empty_send(&mut self, skip: bool) {
        self.skip_empty_send = skip;
    }

    /// Resets the connection transport and performs the "ODIN" / "LOKE" protocol handshake.
    pub fn init(&mut self) -> Result<(), OdinError> {
        progress::println("Initializing protocol...");

        self.usb.reset();

        self.send_string("ODIN", 1000)
            .map_err(|_| OdinError::HandshakeSendFailed)?;

        let response = self
            .receive_string(1000)
            .map_err(|_| OdinError::HandshakeReceiveFailed)?;

        if response == "LOKE" {
            progress::println("Protocol initialization successful.\n");
            Ok(())
        } else {
            Err(OdinError::HandshakeMismatch {
                expected: "LOKE".to_string(),
                received: response,
            })
        }
    }

    /// Sends a raw string message over the transport connection.
    pub fn send_string(&mut self, s: &str, timeout: i32) -> Result<(), OdinError> {
        progress::println_verbose(&format!("Sending string: {:?}", s));
        if !self.usb.send_data(s.as_bytes(), timeout, true) {
            return Err(OdinError::SendPacketFailed);
        }
        Ok(())
    }

    /// Receives a raw string message from the transport connection.
    pub fn receive_string(&mut self, timeout: i32) -> Result<String, OdinError> {
        let mut buffer = [0u8; 1024];
        let received_size = self.usb.receive_data(&mut buffer, timeout, true);

        if received_size < 0 {
            return Err(OdinError::ReceivePacketFailed);
        }

        let mut data = buffer.to_vec();
        data.truncate(received_size as usize);
        progress::println_verbose(&format!(
            "Received string data ({} bytes): {:?}",
            received_size, data
        ));
        Ok(String::from_utf8_lossy(&data).into_owned())
    }

    /// Queries the connected device for hardware and software diagnostics using the pre-handshake DVIF protocol.
    ///
    /// Can be called prior to `init()` to inspect the device without opening an Odin session.
    pub fn query_device_info(&mut self) -> Result<DeviceInfo, OdinError> {
        progress::println_verbose("Querying device info via DVIF...");
        if !self.usb.send_data(b"DVIF", 1000, false) {
            return Err(OdinError::SendPacketFailed);
        }

        let mut buffer = [0u8; 1024];
        let received_size = self.usb.receive_data(&mut buffer, 1000, false);
        if received_size <= 0 {
            return Err(OdinError::DeviceInfoUnavailable);
        }

        let s = String::from_utf8_lossy(&buffer[..received_size as usize]);
        progress::println_verbose(&format!("DVIF response ({} bytes): {}", received_size, s));
        DeviceInfo::parse(&s)
    }

    /// Begins an active flashing session, negotiating features such as packet size and LZ4 support,
    /// transitioning the connection into an [`OdinSession`].
    pub fn begin_session(self) -> Result<OdinSession, OdinError> {
        OdinSession::begin(self)
    }
}

/// An active flashing session coordinating Samsung Odin/Loke packet transfers.
pub struct OdinSession {
    connection: OdinConnection,

    file_transfer_sequence_max_length: usize,
    file_transfer_packet_size: usize,
    file_transfer_sequence_timeout: u32,
    lz4_supported: bool,
    bootloader_protocol_version: u32,
}

impl OdinSession {
    fn begin(connection: OdinConnection) -> Result<Self, OdinError> {
        progress::println("Beginning session...");

        let mut session = Self {
            connection,
            file_transfer_sequence_max_length: FILE_TRANSFER_SEQUENCE_MAX_LENGTH_DEFAULT,
            file_transfer_packet_size: FILE_TRANSFER_PACKET_SIZE_DEFAULT,
            file_transfer_sequence_timeout: FILE_TRANSFER_SEQUENCE_TIMEOUT_DEFAULT,
            lz4_supported: false,
            bootloader_protocol_version: 0,
        };

        let packet = RequestPacket::begin_session();
        let session_response = session.request_and_response(&packet, 3000)?;

        session.bootloader_protocol_version = if session_response == 0 {
            1
        } else {
            session_response >> 16
        };

        progress::println(
            "\nSome devices may take up to 2 minutes to respond.\nPlease be patient!\n",
        );
        std::thread::sleep(Duration::from_millis(3000));

        if session.bootloader_protocol_version >= 2 {
            session.lz4_supported = (session_response & 0x8000) != 0;
            session.file_transfer_sequence_timeout = 120000;
            session.file_transfer_packet_size = 0x100000;
            session.file_transfer_sequence_max_length = 30;

            let packet = RequestPacket::file_part_size(session.file_transfer_packet_size as u32);
            let value = session.request_and_response(&packet, 3000)?;

            if value != 0 {
                return Err(OdinError::Loke(LokeError::from_status(value as i32)));
            }
        }

        progress::println("Session begun.\n");
        Ok(session)
    }

    /// Ends the active flashing session on the device.
    pub fn end_session(&mut self) -> Result<(), OdinError> {
        progress::println("Ending session...");

        let packet = RequestPacket::end_session();
        let value = self.request_and_response(&packet, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        Ok(())
    }

    /// Reboots the device normally out of Download Mode.
    pub fn reboot_device(&mut self) -> Result<(), OdinError> {
        self.reboot_with_packet(&RequestPacket::reboot_device(), "Rebooting device...")
    }

    /// Reboots the device back into Download Mode.
    pub fn reboot_to_download(&mut self) -> Result<(), OdinError> {
        self.reboot_with_packet(
            &RequestPacket::reboot_to_download(),
            "Rebooting device to Download Mode...",
        )
    }

    fn reboot_with_packet(&mut self, packet: &RequestPacket, msg: &str) -> Result<(), OdinError> {
        progress::println(msg);

        // Send reboot packet using standard send_packet, which automatically
        // appends an empty packet (ZLP) for "Gadget Serial" devices (e.g. S10).
        let _ = self.send_packet(packet, 500);

        // Attempt to read from the IN endpoint to consume any response or ACK/ZLP
        // sent by the bootloader before resetting (required on devices such as A55).
        // Any timeout or disconnect error is ignored since the device is rebooting.
        let mut buffer = [0u8; 64];
        let _ = self.connection.usb.receive_data(&mut buffer, 100, false);

        Ok(())
    }

    /// Ends the session and returns the underlying connection.
    pub fn close(mut self) -> Result<OdinConnection, OdinError> {
        self.end_session()?;
        Ok(self.connection)
    }

    /// Consumes the session and returns the underlying connection without sending an end-session packet.
    pub fn into_connection(self) -> OdinConnection {
        self.connection
    }

    fn send_packet(&mut self, packet: &RequestPacket, timeout: i32) -> Result<(), ()> {
        progress::println_verbose(&format!("Sending packet: {:#04X?}", packet));
        let packet_bytes = packet.pack();
        if !self.connection.usb.send_data(&packet_bytes, timeout, true) {
            return Err(());
        }
        if !self.connection.skip_empty_send {
            self.connection.usb.send_data(&[], 100, false);
        }
        Ok(())
    }

    fn send_file_part(
        &mut self,
        packet: &packets::FilePartPacket<'_>,
        timeout: i32,
    ) -> Result<(), ()> {
        progress::println_verbose(&format!("Sending packet: {:#04X?}", packet));
        let packet_bytes = packet.as_bytes();
        if !self.connection.usb.send_data(&packet_bytes, timeout, true) {
            return Err(());
        }
        Ok(())
    }

    fn receive_response(&mut self, timeout: i32) -> Result<packets::Response, OdinError> {
        let mut buffer = [0u8; packets::Response::SIZE];
        let mut received_size = self.connection.usb.receive_data(&mut buffer, timeout, true);

        // Mirror odin4: if 0 bytes received (a ZLP was received), read again
        if received_size == 0 {
            received_size = self.connection.usb.receive_data(&mut buffer, timeout, true);
        }

        if received_size < 0 {
            return Err(OdinError::ReceivePacketFailed);
        }

        let parsed = packets::Response::parse(&buffer[..received_size as usize])
            .map_err(OdinError::ParseError)?;
        progress::println_verbose(&format!("Received packet: {:#04X?}", parsed));
        Ok(parsed)
    }

    fn request_and_response(
        &mut self,
        packet: &RequestPacket,
        timeout: i32,
    ) -> Result<u32, OdinError> {
        self.send_packet(packet, timeout)
            .map_err(|_| OdinError::SendPacketFailed)?;

        let response = self.receive_response(timeout)?;
        let expected_type = packet.expected_response_type();

        if response.is_fail() {
            return Err(OdinError::Loke(LokeError::from_status(
                response.signed_value(),
            )));
        }

        if response.response_type != expected_type {
            return Err(OdinError::ResponseTypeMismatch {
                expected: expected_type,
                received: response.response_type,
            });
        }

        if response.signed_value() < 0 {
            return Err(OdinError::Loke(LokeError::from_status(
                response.signed_value(),
            )));
        }

        Ok(response.value)
    }

    /// Flashes/uploads raw PIT data to the device.
    pub fn send_pit_data(&mut self, pit_buffer: &[u8]) -> Result<(), OdinError> {
        let pit_buffer_size = pit_buffer.len() as u32;

        // Start file transfer
        let packet = RequestPacket::pit_file_flash();
        let value = self.request_and_response(&packet, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        // Transfer file size
        let packet = RequestPacket::flash_part_pit_file(pit_buffer_size);
        let value = self.request_and_response(&packet, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        // Flash pit file
        let packet = packets::FilePartPacket::new(pit_buffer, pit_buffer_size as usize);
        self.send_file_part(&packet, 3000)
            .map_err(|_| OdinError::SendPacketFailed)?;

        let response = self.receive_response(3000)?;

        if response.is_fail() {
            return Err(OdinError::Loke(LokeError::from_status(
                response.signed_value(),
            )));
        }

        if response.response_type != packets::RESPONSE_TYPE_SEND_FILE_PART
            && response.response_type != packets::RESPONSE_TYPE_PIT_FILE
        {
            return Err(OdinError::ResponseTypeMismatch {
                expected: packets::RESPONSE_TYPE_PIT_FILE,
                received: response.response_type,
            });
        }

        if response.signed_value() < 0 {
            return Err(OdinError::Loke(LokeError::from_status(
                response.signed_value(),
            )));
        }

        // End pit file transfer
        let packet = RequestPacket::end_pit_file_transfer(pit_buffer_size);
        let value = self.request_and_response(&packet, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        Ok(())
    }

    /// Downloads/dumps the active Partition Information Table (PIT) file from the device.
    pub fn download_pit_file(&mut self) -> Result<Vec<u8>, OdinError> {
        let packet = RequestPacket::pit_file_dump();
        let file_size = self.request_and_response(&packet, 3000)? as usize;

        const PIT_CHUNK_SIZE: usize = 500;
        let transfer_count = file_size.div_ceil(PIT_CHUNK_SIZE);
        let mut buffer = Vec::with_capacity(file_size);
        let mut chunk = [0u8; PIT_CHUNK_SIZE];

        for i in 0..transfer_count {
            let packet = RequestPacket::dump_part_pit_file(i as u32);
            self.send_packet(&packet, 3000)
                .map_err(|_| OdinError::SendPacketFailed)?;

            let expected_size = std::cmp::min(file_size - buffer.len(), PIT_CHUNK_SIZE);

            let received =
                self.connection
                    .usb
                    .receive_data(&mut chunk[..expected_size], 3000, true);
            if received < 0 {
                return Err(OdinError::ReceivePacketFailed);
            }
            buffer.extend_from_slice(&chunk[..received as usize]);
        }

        // Receive empty packet after the last PIT transfer,
        // this is required for some older devices e.g. Tab S2 VE.
        let mut empty = [0u8; 1];
        self.connection.usb.receive_data(&mut empty, 100, false);

        // End file transfer
        let packet = RequestPacket::pit_file_end();
        let value = self.request_and_response(&packet, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        Ok(buffer)
    }

    /// Dumps device diagnostic and identity information using in-session Opcode 0x69.
    ///
    /// Available on bootloader protocol version >= 4. Kept as reference for mid-session inspection.
    pub fn dump_device_info(&mut self) -> Result<SessionDeviceInfo, OdinError> {
        let packet = RequestPacket::device_info_dump();
        let total_bytes = self.request_and_response(&packet, 3000)? as usize;
        if total_bytes == 0 || total_bytes > 0x100000 {
            return Err(OdinError::DeviceInfoUnavailable);
        }

        const CHUNK_SIZE: usize = 500;
        let transfer_count = total_bytes.div_ceil(CHUNK_SIZE);
        let mut buffer = Vec::with_capacity(total_bytes);
        let mut chunk = [0u8; CHUNK_SIZE];

        for i in 0..transfer_count {
            let packet = RequestPacket::dump_part_device_info(i as u32);
            self.send_packet(&packet, 3000)
                .map_err(|_| OdinError::SendPacketFailed)?;

            let expected_size = std::cmp::min(total_bytes - buffer.len(), CHUNK_SIZE);
            let received =
                self.connection
                    .usb
                    .receive_data(&mut chunk[..expected_size], 3000, false);
            if received < 0 {
                return Err(OdinError::ReceivePacketFailed);
            }
            buffer.extend_from_slice(&chunk[..received as usize]);
        }

        let packet = RequestPacket::end_device_info();
        let value = self.request_and_response(&packet, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        SessionDeviceInfo::parse(&buffer)
    }

    /// Sets the device CSC / Sales Code in bootloader parameter storage (Opcode 0x64, Subcmd 9).
    pub fn set_sales_code(&mut self, sales_code: &str) -> Result<(), OdinError> {
        let bytes = sales_code.as_bytes();
        if bytes.len() != 3 || !bytes.iter().all(|b| b.is_ascii_alphanumeric()) {
            return Err(OdinError::InvalidSalesCode(sales_code.to_string()));
        }
        let code = [bytes[0], bytes[1], bytes[2]];
        let packet = RequestPacket::session_sales_code(code);
        let value = self.request_and_response(&packet, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }
        Ok(())
    }

    /// Dispatches a low-level hardware NAND Erase for the USERDATA partition (Opcode 0x64, Subcmd 7).
    ///
    /// Instructs the device bootloader to issue a hardware flash block erase across the
    /// `USERDATA` partition range (from the starting sector of `USERDATA` to the end of user storage).
    ///
    /// Returns the number of storage sectors erased by the device.
    pub fn nand_erase(&mut self) -> Result<u32, OdinError> {
        progress::println("Erasing storage (USERDATA)...");
        let packet = RequestPacket::nand_erase();
        let erased_sectors = self.request_and_response(&packet, 60_000)?;
        progress::println(&format!(
            "Storage erased successfully ({} sectors)\n",
            erased_sectors
        ));
        Ok(erased_sectors)
    }

    /// Returns whether the negotiated device session supports flashing LZ4-compressed streams.
    pub fn is_lz4_supported(&self) -> bool {
        self.lz4_supported
    }

    /// Returns the negotiated bootloader protocol version of the connected device.
    pub fn bootloader_protocol_version(&self) -> u32 {
        self.bootloader_protocol_version
    }

    fn file_transfer_sequence_max_bytes(&self) -> usize {
        self.file_transfer_packet_size * self.file_transfer_sequence_max_length
    }

    fn send_raw_sequences<Iter, Bytes>(
        &mut self,
        sequences: Iter,
        pit_entry: &PitEntry,
    ) -> Result<(), OdinError>
    where
        Bytes: AsRef<[u8]>,
        Iter: Iterator<Item = Bytes>,
    {
        let mut sequences = sequences.peekable();
        while let Some(sequence_data) = sequences.next() {
            let sequence_data = sequence_data.as_ref();
            let init_packet = RequestPacket::file_transfer_flash(false);
            let start_packet = RequestPacket::flash_part_file_transfer(sequence_data.len() as u32);

            let is_last_sequence = sequences.peek().is_none();
            let end_packet = RequestPacket::end_file_transfer(
                sequence_data.len() as u32,
                pit_entry,
                is_last_sequence,
                false,
                self.bootloader_protocol_version,
            );

            self.send_one_sequence(&init_packet, &start_packet, &end_packet, sequence_data)?;
        }

        Ok(())
    }

    /// Flashes an uncompressed partition firmware file payload to the device.
    pub fn send_file(&mut self, info: &crate::firmware::FirmwareFile) -> Result<(), OdinError> {
        progress::set_length(info.file.len() as u64);
        let sequences = info.sequences(self.file_transfer_sequence_max_bytes());
        self.send_raw_sequences(sequences, info.pit_entry)
    }

    /// Flashes an LZ4-compressed partition firmware file payload to the device,
    /// decompressing on-the-fly if needed.
    pub fn send_lz4_file(
        &mut self,
        info: &crate::firmware::FirmwareLz4File,
    ) -> Result<(), OdinError> {
        if !self.lz4_supported || info.header.block_max_size != 1024 * 1024 {
            progress::set_length(info.header.content_size);
            let sequences = info.decompressed_sequences(self.file_transfer_sequence_max_bytes());
            return self.send_raw_sequences(sequences, info.pit_entry);
        }

        progress::set_length(info.file.len() as u64);

        let sequences = info.sequences(self.file_transfer_sequence_max_bytes());

        let mut sequences = sequences.peekable();
        while let Some((decompressed_size, sequence_data)) = sequences.next() {
            let init_packet = RequestPacket::file_transfer_flash(true);
            let start_packet = RequestPacket::flash_part_lz4_file_transfer(
                sequence_data.len() as u32,
                decompressed_size as u32,
            );

            let is_last_sequence = sequences.peek().is_none();
            let end_packet = RequestPacket::end_file_transfer(
                decompressed_size as u32,
                info.pit_entry,
                is_last_sequence,
                true,
                self.bootloader_protocol_version,
            );

            self.send_one_sequence(&init_packet, &start_packet, &end_packet, sequence_data)?;
        }

        Ok(())
    }

    fn send_one_sequence(
        &mut self,
        init_packet: &RequestPacket,
        start_packet: &RequestPacket,
        end_packet: &RequestPacket,
        sequence_data: &[u8],
    ) -> Result<(), OdinError> {
        let init_val = self.request_and_response(init_packet, 3000)?;
        if init_val != 0 {
            return Err(OdinError::Loke(LokeError::from_status(init_val as i32)));
        }

        let start_val = self.request_and_response(start_packet, 3000)?;
        if start_val != 0 {
            return Err(OdinError::Loke(LokeError::from_status(start_val as i32)));
        }

        for (file_part_index, file_buffer) in sequence_data
            .chunks(self.file_transfer_packet_size)
            .enumerate()
        {
            let mut success = false;
            for retry in 0..5 {
                if retry > 0 {
                    progress::println("\nRetrying...");
                }

                let packet =
                    packets::FilePartPacket::new(file_buffer, self.file_transfer_packet_size);

                if self.send_file_part(&packet, 3000).is_err() {
                    continue;
                }

                if let Ok(response) =
                    self.receive_response(self.file_transfer_sequence_timeout as i32)
                {
                    if response.is_fail() {
                        return Err(OdinError::Loke(LokeError::from_status(
                            response.signed_value(),
                        )));
                    }
                    if response.response_type == packets::RESPONSE_TYPE_SEND_FILE_PART {
                        if response.signed_value() < 0 {
                            return Err(OdinError::Loke(LokeError::from_status(
                                response.signed_value(),
                            )));
                        }
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
                }
            }

            if !success {
                return Err(OdinError::FilePartResponseReceiveFailed);
            }

            progress::inc(file_buffer.len() as u64);
        }

        let end_val =
            self.request_and_response(end_packet, self.file_transfer_sequence_timeout as i32)?;
        if end_val != 0 {
            return Err(OdinError::Loke(LokeError::from_status(end_val as i32)));
        }

        Ok(())
    }

    /// Sets the total expected session bytes to be flashed, allowing the device
    /// to update its progress indicator.
    pub fn set_total_bytes(&mut self, total_bytes: u64) -> Result<(), OdinError> {
        let packet = RequestPacket::total_bytes(total_bytes);
        let value = self.request_and_response(&packet, 3000)?;

        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        Ok(())
    }

    /// Performs a pre-flight dynamic partition size check on modern LOKE bootloaders.
    pub fn check_super_size(&mut self, super_used_size: u32) -> Result<(), OdinError> {
        let packet = RequestPacket::check_super_size(super_used_size);
        let value = self.request_and_response(&packet, 3000)?;

        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        Ok(())
    }
}

/// Triggers a reboot of the connected Samsung device into Download Mode via the
/// specified backend protocol.
pub fn reboot_download(usb_backend: crate::usb::UsbBackendOption) -> Result<(), OdinError> {
    use crate::usb::{UsbTransfer, VID_SAMSUNG};

    let mut backend: Box<dyn UsbTransfer> = match usb_backend {
        #[cfg(feature = "serialport")]
        crate::usb::UsbBackendOption::Vcom => {
            use crate::usb::{SerialBackend, UsbBackend};
            let device = SerialBackend::find_device(false, |vid, _| vid == VID_SAMSUNG)?;
            Ok::<Box<dyn UsbTransfer>, OdinError>(Box::new(SerialBackend::new(device, false)?))
        }
        #[cfg(feature = "nusb")]
        crate::usb::UsbBackendOption::Nusb => {
            use crate::usb::{NusbBackend, UsbBackend};
            let device = NusbBackend::find_device(false, |vid, _| vid == VID_SAMSUNG)?;
            Ok::<Box<dyn UsbTransfer>, OdinError>(Box::new(NusbBackend::new(device, false)?))
        }
        #[cfg(feature = "rusb")]
        crate::usb::UsbBackendOption::Libusb => {
            use crate::usb::{RusbBackend, UsbBackend};
            let device = RusbBackend::find_device(false, |vid, _| vid == VID_SAMSUNG)?;
            Ok::<Box<dyn UsbTransfer>, OdinError>(Box::new(RusbBackend::new(device, false)?))
        }
        #[cfg(any(feature = "mock", debug_assertions))]
        crate::usb::UsbBackendOption::Mock => {
            use crate::usb::MockBackend;
            Ok::<Box<dyn UsbTransfer>, OdinError>(Box::new(MockBackend::new(false)))
        }
    }?;

    let cmd: &[u8] = b"AT+SUDDLMOD=0,0\r";

    if !backend.send_data(cmd, 1000, false) {
        return Err(OdinError::SerialError("Failed to send data".to_string()));
    }

    Ok(())
}

/// Connects to a device in download mode and queries diagnostic info via `DVIF`.
pub fn query_device_info(
    usb_backend: crate::usb::UsbBackendOption,
    wait: bool,
) -> Result<DeviceInfo, OdinError> {
    let usb = crate::usb::create_backend(usb_backend, false, wait)?;
    let mut conn = OdinConnection::new(usb);
    conn.query_device_info()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::MockBackend;

    #[test]
    fn test_odin_mock_session_and_pit_download() {
        let backend = Box::new(MockBackend::new(true));
        let mut connection = OdinConnection::new(backend);

        // handshake with simple string in/out
        assert!(connection.init().is_ok());

        // transition connection into active packet session
        let mut session = connection.begin_session().unwrap();
        assert_eq!(session.bootloader_protocol_version(), 2);
        assert!(session.is_lz4_supported());

        // PIT dump (packet I/O)
        let pit_bytes = session.download_pit_file().unwrap();
        // Q7MQ_EUR_OPENX.pit is exactly 18492 bytes including cryptographic signature
        assert_eq!(pit_bytes.len(), 18492);

        // end session and retrieve connection
        let mut connection = session.close().unwrap();

        // connection is usable again
        assert!(connection.send_string("ODIN", 1000).is_ok());
    }

    #[test]
    fn test_odin_mock_session_reboot_to_download() {
        let backend = Box::new(MockBackend::new(true));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        // reboot to download mode
        assert!(session.reboot_to_download().is_ok());
    }

    #[test]
    fn test_odin_connection_raw_string_io() {
        let backend = Box::new(MockBackend::new(true));
        let mut connection = OdinConnection::new(backend);

        // Send raw string
        assert!(connection.send_string("ODIN", 1000).is_ok());

        // Receive raw string response
        let resp = connection.receive_string(1000).unwrap();
        assert_eq!(resp, "LOKE");
    }

    #[test]
    fn test_odin_mock_multi_sequence_transfer() {
        let backend = Box::new(MockBackend::new(false));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        let pit_entry = PitEntry {
            binary_type: samloader_pit::BinaryType::ApplicationProcessor,
            device_type: samloader_pit::DeviceType::MMC,
            identifier: 20,
            attributes: Default::default(),
            update_attributes: Default::default(),
            block_size_or_offset: 0,
            block_count: 0,
            file_offset: 0,
            file_size: 0,
            partition_name: Default::default(),
            flash_filename: Default::default(),
            fota_filename: Default::default(),
        };

        // 2 sequences of 128 KB each (matching MockBackend packet_size)
        let seq1 = vec![0xAAu8; 0x20000];
        let seq2 = vec![0xBBu8; 0x20000];
        let sequences = vec![seq1, seq2].into_iter();

        assert!(session.send_raw_sequences(sequences, &pit_entry).is_ok());

        assert!(session.close().is_ok());
    }

    #[test]
    fn test_odin_mock_begin_session_failure() {
        let backend = Box::new(MockBackend::new(false).with_fail_begin_session(-5));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        assert!(matches!(
            connection.begin_session(),
            Err(OdinError::Loke(LokeError::AuthFailure))
        ));
    }

    #[test]
    fn test_odin_mock_slice_commit_failure() {
        let backend = Box::new(MockBackend::new(false).with_fail_commit(-5));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        let pit_entry = PitEntry {
            binary_type: samloader_pit::BinaryType::ApplicationProcessor,
            device_type: samloader_pit::DeviceType::MMC,
            identifier: 20,
            attributes: Default::default(),
            update_attributes: Default::default(),
            block_size_or_offset: 0,
            block_count: 0,
            file_offset: 0,
            file_size: 0,
            partition_name: Default::default(),
            flash_filename: Default::default(),
            fota_filename: Default::default(),
        };

        let seq = vec![0xAAu8; 0x20000];
        let sequences = vec![seq].into_iter();

        assert!(matches!(
            session.send_raw_sequences(sequences, &pit_entry),
            Err(OdinError::Loke(LokeError::AuthFailure))
        ));
    }

    #[test]
    fn test_odin_mock_file_part_chunk_failure() {
        let backend = Box::new(MockBackend::new(false).with_fail_file_part(-4));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        let pit_entry = PitEntry {
            binary_type: samloader_pit::BinaryType::ApplicationProcessor,
            device_type: samloader_pit::DeviceType::MMC,
            identifier: 20,
            attributes: Default::default(),
            update_attributes: Default::default(),
            block_size_or_offset: 0,
            block_count: 0,
            file_offset: 0,
            file_size: 0,
            partition_name: Default::default(),
            flash_filename: Default::default(),
            fota_filename: Default::default(),
        };

        let seq = vec![0xAAu8; 0x20000];
        let sequences = vec![seq].into_iter();

        assert!(matches!(
            session.send_raw_sequences(sequences, &pit_entry),
            Err(OdinError::Loke(LokeError::WriteFailure))
        ));
    }

    #[test]
    fn test_odin_mock_close_session_failure() {
        let backend = Box::new(MockBackend::new(false).with_fail_end_session(-2));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let session = connection.begin_session().unwrap();
        assert!(matches!(
            session.close(),
            Err(OdinError::Loke(LokeError::WriteProtection))
        ));
    }

    #[test]
    fn test_odin_mock_check_super_size_success() {
        let backend = Box::new(MockBackend::new(false));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        assert!(session.check_super_size(27276104).is_ok());
        assert!(session.check_super_size(0).is_ok());
    }

    #[test]
    fn test_odin_mock_check_super_size_failure() {
        let backend = Box::new(MockBackend::new(false).with_fail_check_super_size(-1));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        let res = session.check_super_size(27276104);
        assert!(matches!(res, Err(OdinError::Loke(LokeError::General(-1)))));
    }

    #[test]
    fn test_odin_mock_query_device_info() {
        let backend = Box::new(MockBackend::new(false));
        let mut connection = OdinConnection::new(backend);

        let info = connection
            .query_device_info()
            .expect("Failed to query device info via DVIF");
        assert_eq!(info.model.as_deref(), Some("SM-F968B"));
        assert_eq!(info.serial_number.as_deref(), Some("C1A2B3C4"));
        assert_eq!(info.storage_capacity_gb, Some(512));
        assert_eq!(info.sales_code.as_deref(), Some("TUR"));

        // Verify connection can still be initialized and session opened after DVIF query
        assert!(connection.init().is_ok());
        let session = connection.begin_session().unwrap();
        assert!(session.close().is_ok());
    }

    #[test]
    fn test_odin_mock_dump_device_info() {
        let backend = Box::new(MockBackend::new(false));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        let info = session
            .dump_device_info()
            .expect("Failed to dump device info via opcode 0x69");
        assert_eq!(info.model.as_deref(), Some("SM-F968B"));
        assert_eq!(
            info.unique_number.as_deref(),
            Some("1501004b333230340000000000000000")
        );
        assert_eq!(info.sales_code.as_deref(), Some("TUR"));
        assert!(session.close().is_ok());
    }

    #[test]
    fn test_odin_mock_set_sales_code() {
        let backend = Box::new(MockBackend::new(false));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        assert!(session.set_sales_code("TUR").is_ok());

        // Verify invalid formats are rejected
        assert!(matches!(
            session.set_sales_code("TU"),
            Err(OdinError::InvalidSalesCode(_))
        ));
        assert!(matches!(
            session.set_sales_code("TUR1"),
            Err(OdinError::InvalidSalesCode(_))
        ));
        assert!(matches!(
            session.set_sales_code("T-R"),
            Err(OdinError::InvalidSalesCode(_))
        ));

        assert!(session.close().is_ok());
    }

    #[test]
    fn test_odin_mock_nand_erase_success() {
        let backend = Box::new(MockBackend::new(false).with_nand_erase(1_048_576));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        let sectors = session.nand_erase().expect("NAND erase failed");
        assert_eq!(sectors, 1_048_576);

        assert!(session.close().is_ok());
    }

    #[test]
    fn test_odin_mock_nand_erase_failure() {
        // Test Auth/Security failure (-5)
        let backend = Box::new(MockBackend::new(false).with_fail_nand_erase(-5));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        match session.nand_erase() {
            Err(OdinError::Loke(LokeError::AuthFailure)) => {}
            other => panic!("Expected AuthFailure, got {:?}", other),
        }

        // Test WriteProtection failure (-20, returned by sboot)
        let backend = Box::new(MockBackend::new(false).with_fail_nand_erase(-20));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        match session.nand_erase() {
            Err(OdinError::Loke(LokeError::WriteProtection)) => {}
            other => panic!("Expected WriteProtection, got {:?}", other),
        }
    }

    #[test]
    fn test_skip_empty_send_detection() {
        let gadget = Box::new(MockBackend::new(false).with_product_name("Gadget Serial"));
        let conn_gadget = OdinConnection::new(gadget);
        assert!(!conn_gadget.skip_empty_send());

        let gadget_prefix = Box::new(MockBackend::new(false).with_product_name("Gadget Serial v2"));
        let conn_gadget_prefix = OdinConnection::new(gadget_prefix);
        assert!(!conn_gadget_prefix.skip_empty_send());

        let msm = Box::new(MockBackend::new(false).with_product_name("MSM8996"));
        let conn_msm = OdinConnection::new(msm);
        assert!(conn_msm.skip_empty_send());

        let apq = Box::new(MockBackend::new(false).with_product_name("APQ8084"));
        let conn_apq = OdinConnection::new(apq);
        assert!(conn_apq.skip_empty_send());

        let generic = Box::new(MockBackend::new(false).with_product_name("SAMSUNG_Android"));
        let conn_generic = OdinConnection::new(generic);
        assert!(conn_generic.skip_empty_send());

        let none = Box::new(MockBackend::new(false));
        let conn_none = OdinConnection::new(none);
        assert!(conn_none.skip_empty_send());
    }

    #[derive(Default)]
    struct SpyTransferInner {
        sent_data: Vec<Vec<u8>>,
        read_queue: std::collections::VecDeque<Vec<u8>>,
    }

    struct SpyTransfer {
        inner: std::sync::Arc<std::sync::Mutex<SpyTransferInner>>,
        product: Option<String>,
    }

    impl UsbTransfer for SpyTransfer {
        fn reset(&mut self) {}
        fn send_data(&mut self, data: &[u8], _timeout: i32, _retry: bool) -> bool {
            self.inner.lock().unwrap().sent_data.push(data.to_vec());
            true
        }
        fn receive_data(&mut self, data: &mut [u8], _timeout: i32, _retry: bool) -> i32 {
            let mut inner = self.inner.lock().unwrap();
            if let Some(packet) = inner.read_queue.pop_front() {
                let len = std::cmp::min(data.len(), packet.len());
                data[..len].copy_from_slice(&packet[..len]);
                len as i32
            } else {
                0
            }
        }
        fn product_name(&self) -> Option<&str> {
            self.product.as_deref()
        }
    }

    #[test]
    fn test_gadget_serial_sends_empty_packets_after_control_requests() {
        let spy_inner = std::sync::Arc::new(std::sync::Mutex::new(SpyTransferInner::default()));
        let spy = Box::new(SpyTransfer {
            inner: spy_inner.clone(),
            product: Some("Gadget Serial".to_string()),
        });

        let conn = OdinConnection::new(spy);
        assert!(!conn.skip_empty_send());

        let mut session = OdinSession {
            connection: conn,
            file_transfer_sequence_max_length: 30,
            file_transfer_packet_size: 0x20000,
            file_transfer_sequence_timeout: 3000,
            lz4_supported: false,
            bootloader_protocol_version: 2,
        };

        // 1. Control request packet -> must send 1024 bytes followed by 0 bytes (ZLP)
        let req = RequestPacket::begin_session();
        assert!(session.send_packet(&req, 1000).is_ok());

        {
            let inner = spy_inner.lock().unwrap();
            assert_eq!(inner.sent_data.len(), 2);
            assert_eq!(inner.sent_data[0].len(), 1024);
            assert_eq!(inner.sent_data[1].len(), 0); // ZLP
        }

        // 2. Data chunk -> must send raw chunk bytes with NO ZLP
        let chunk_data = vec![0xABu8; 1024];
        let file_part = packets::FilePartPacket::new(&chunk_data, chunk_data.len());
        assert!(session.send_file_part(&file_part, 1000).is_ok());

        {
            let inner = spy_inner.lock().unwrap();
            assert_eq!(inner.sent_data.len(), 3);
            assert_eq!(inner.sent_data[2].len(), 1024);
        }

        // 3. Reboot device -> must send reboot packet with trailing ZLP
        assert!(session.reboot_device().is_ok());
        {
            let inner = spy_inner.lock().unwrap();
            assert_eq!(inner.sent_data.len(), 5);
            assert_eq!(inner.sent_data[3].len(), 1024);
            assert_eq!(inner.sent_data[4].len(), 0); // trailing ZLP for reboot on S10!
        }
    }

    #[test]
    fn test_non_gadget_serial_skips_empty_packets() {
        let spy_inner = std::sync::Arc::new(std::sync::Mutex::new(SpyTransferInner::default()));
        let spy = Box::new(SpyTransfer {
            inner: spy_inner.clone(),
            product: Some("MSM8996".to_string()),
        });

        let conn = OdinConnection::new(spy);
        assert!(conn.skip_empty_send());

        let mut session = OdinSession {
            connection: conn,
            file_transfer_sequence_max_length: 30,
            file_transfer_packet_size: 0x20000,
            file_transfer_sequence_timeout: 3000,
            lz4_supported: false,
            bootloader_protocol_version: 2,
        };

        // 1. Control request packet -> only sends 1024 bytes, no ZLP
        let req = RequestPacket::begin_session();
        assert!(session.send_packet(&req, 1000).is_ok());

        {
            let inner = spy_inner.lock().unwrap();
            assert_eq!(inner.sent_data.len(), 1);
            assert_eq!(inner.sent_data[0].len(), 1024);
        }

        // 2. Reboot device -> sends 1024 bytes, no ZLP
        assert!(session.reboot_device().is_ok());
        {
            let inner = spy_inner.lock().unwrap();
            assert_eq!(inner.sent_data.len(), 2);
            assert_eq!(inner.sent_data[1].len(), 1024);
        }
    }

    #[test]
    fn test_receive_response_retry_on_zero_length_packet() {
        let spy_inner = std::sync::Arc::new(std::sync::Mutex::new(SpyTransferInner::default()));

        // Push a 0-length packet first (ZLP), followed by a valid 8-byte response packet
        let mut response_bytes = Vec::new();
        response_bytes.extend_from_slice(&packets::RESPONSE_TYPE_SESSION_SETUP.to_le_bytes());
        response_bytes.extend_from_slice(&0u32.to_le_bytes());

        {
            let mut inner = spy_inner.lock().unwrap();
            inner.read_queue.push_back(vec![]); // 0-byte packet
            inner.read_queue.push_back(response_bytes); // actual 8-byte response
        }

        let spy = Box::new(SpyTransfer {
            inner: spy_inner,
            product: None,
        });

        let conn = OdinConnection::new(spy);
        let mut session = OdinSession {
            connection: conn,
            file_transfer_sequence_max_length: 30,
            file_transfer_packet_size: 0x20000,
            file_transfer_sequence_timeout: 3000,
            lz4_supported: false,
            bootloader_protocol_version: 2,
        };

        let response = session
            .receive_response(1000)
            .expect("Should retry after 0-byte packet and receive response");
        assert_eq!(response.response_type, packets::RESPONSE_TYPE_SESSION_SETUP);
        assert_eq!(response.value, 0);
    }
}
