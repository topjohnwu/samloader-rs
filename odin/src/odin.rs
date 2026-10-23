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
use crate::progress;
use crate::protocol::{CMD_PIT, Command, DataChunk, Response, STREAMING_CHUNK_ACK};
use crate::usb::UsbTransfer;
use samloader_pit::PitEntry;
use std::time::Duration;

/// Manages the initial connection to a Samsung device in Download Mode.
///
/// At this stage, communication is restricted to raw string commands (e.g. handshake
/// strings or AT commands). Complex command I/O requires transitioning to an [`OdinSession`]
/// via [`begin_session`](Self::begin_session).
pub struct OdinConnection {
    usb: Box<dyn UsbTransfer>,
    skip_empty_send: bool,
}

const MAX_SLICE_SIZE: usize = 30 * 1024 * 1024; // 30 MB (0x1E00000) staging limit in odin4
const PACKET_SIZE_DEFAULT: usize = 0x20000; // 128 KB default before negotiation
const SLICE_TIMEOUT_DEFAULT: u32 = 30000;

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

        let mut response = self
            .receive_string(1000)
            .map_err(|_| OdinError::HandshakeReceiveFailed)?;

        if response != "LOKE"
            && response.starts_with("FAIL")
            && self.receive_string(500).is_ok_and(|s| s == "LOKE")
        {
            response = "LOKE".to_string();
        }

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
            return Err(OdinError::SendCommandFailed);
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
            return Err(OdinError::SendCommandFailed);
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

/// An active flashing session coordinating Samsung Odin/Loke command transfers.
pub struct OdinSession {
    connection: OdinConnection,

    packet_size: usize,
    slice_timeout: u32,
    lz4_supported: bool,
    bootloader_protocol_version: u32,
}

impl OdinSession {
    fn begin(connection: OdinConnection) -> Result<Self, OdinError> {
        progress::println("Beginning session...");

        let mut session = Self {
            connection,
            packet_size: PACKET_SIZE_DEFAULT,
            slice_timeout: SLICE_TIMEOUT_DEFAULT,
            lz4_supported: false,
            bootloader_protocol_version: 0,
        };

        let cmd = Command::begin_session();
        // The session reply is a capability word, not a signed status. Its high bit may be
        // set to advertise direct LZ4 transfer, so it must not pass through the generic
        // signed-status check used by ordinary command replies.
        session
            .send_command(&cmd, 3000)
            .map_err(|_| OdinError::SendCommandFailed)?;
        let response = session.receive_response(3000)?;
        if response.is_fail() {
            return Err(OdinError::Loke(LokeError::from_status(
                response.signed_value(),
            )));
        }
        let expected_type = cmd.expected_response_type();
        if response.response_type != expected_type {
            return Err(OdinError::ResponseTypeMismatch {
                expected: expected_type,
                received: response.response_type,
            });
        }
        let session_response = response.value;

        // LOKE returns the negotiated protocol version in the high 16 bits.
        // Bit 15 of that field advertises direct LZ4 transfer support.
        let advertised_version = session_response >> 16;
        session.bootloader_protocol_version = if session_response == 0 {
            1
        } else {
            advertised_version & 0x7fff
        };

        progress::println(
            "\nSome devices may take up to 2 minutes to respond.\nPlease be patient!\n",
        );
        std::thread::sleep(Duration::from_millis(3000));

        if session.bootloader_protocol_version >= 2 {
            session.lz4_supported = (advertised_version & 0x8000) != 0;
            session.slice_timeout = 120000;
            session.packet_size = 0x100000;

            let cmd = Command::packet_size(session.packet_size as u32);
            let value = session.request_and_response(&cmd, 3000)?;

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

        let cmd = Command::close_connection();
        let value = self.request_and_response(&cmd, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        Ok(())
    }

    /// Reboots the device normally out of Download Mode.
    pub fn reboot_device(&mut self) -> Result<(), OdinError> {
        self.reboot_with_command(&Command::reboot_device(), "Rebooting device...")
    }

    /// Reboots the device back into Download Mode.
    pub fn reboot_to_download(&mut self) -> Result<(), OdinError> {
        self.reboot_with_command(
            &Command::reboot_to_download(),
            "Rebooting device to Download Mode...",
        )
    }

    fn reboot_with_command(&mut self, cmd: &Command, msg: &str) -> Result<(), OdinError> {
        progress::println(msg);

        // Send reboot command using standard send_command, which automatically
        // appends an empty packet (ZLP) for "Gadget Serial" devices (e.g. S10).
        let _ = self.send_command(cmd, 500);

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

    fn send_command(&mut self, cmd: &Command, timeout: i32) -> Result<(), ()> {
        progress::println_verbose(&format!("Sending command: {:#04X?}", cmd));
        let cmd_bytes = cmd.pack();
        if !self.connection.usb.send_data(&cmd_bytes, timeout, true) {
            return Err(());
        }
        if !self.connection.skip_empty_send {
            self.connection.usb.send_data(&[], 100, false);
        }
        Ok(())
    }

    fn send_chunk(&mut self, chunk: &DataChunk<'_>, timeout: i32) -> Result<(), ()> {
        progress::println_verbose(&format!("Sending chunk: {:#04X?}", chunk));
        let chunk_bytes = chunk.as_bytes();
        if !self.connection.usb.send_data(&chunk_bytes, timeout, true) {
            return Err(());
        }
        Ok(())
    }

    fn receive_response(&mut self, timeout: i32) -> Result<Response, OdinError> {
        let mut buffer = [0u8; Response::SIZE];
        let mut received_size = self.connection.usb.receive_data(&mut buffer, timeout, true);

        // Mirror odin4: if 0 bytes received (a ZLP was received), read again
        if received_size == 0 {
            received_size = self.connection.usb.receive_data(&mut buffer, timeout, true);
        }

        if received_size < 0 {
            return Err(OdinError::ReceivePacketFailed);
        }

        let parsed =
            Response::parse(&buffer[..received_size as usize]).map_err(OdinError::ParseError)?;
        progress::println_verbose(&format!("Received response: {:#04X?}", parsed));
        Ok(parsed)
    }

    fn request_and_response(&mut self, cmd: &Command, timeout: i32) -> Result<u32, OdinError> {
        self.send_command(cmd, timeout)
            .map_err(|_| OdinError::SendCommandFailed)?;

        let response = self.receive_response(timeout)?;
        let expected_type = cmd.expected_response_type();

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
    pub fn send_pit_info(&mut self, pit_buffer: &[u8]) -> Result<(), OdinError> {
        let pit_buffer_size = pit_buffer.len() as u32;

        // Start file transfer
        let cmd = Command::pit_flash();
        let value = self.request_and_response(&cmd, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        // Transfer file size
        let cmd = Command::flash_pit_slice(pit_buffer_size);
        let value = self.request_and_response(&cmd, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        // Flash pit file
        let chunk = DataChunk::new(pit_buffer, pit_buffer_size as usize);
        self.send_chunk(&chunk, 3000)
            .map_err(|_| OdinError::SendCommandFailed)?;

        let response = self.receive_response(3000)?;

        if response.is_fail() {
            return Err(OdinError::Loke(LokeError::from_status(
                response.signed_value(),
            )));
        }

        if response.response_type != STREAMING_CHUNK_ACK && response.response_type != CMD_PIT {
            return Err(OdinError::ResponseTypeMismatch {
                expected: CMD_PIT,
                received: response.response_type,
            });
        }

        if response.signed_value() < 0 {
            return Err(OdinError::Loke(LokeError::from_status(
                response.signed_value(),
            )));
        }

        // End pit file transfer
        let cmd = Command::end_pit_transfer(pit_buffer_size);
        let value = self.request_and_response(&cmd, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        Ok(())
    }

    /// Downloads/dumps the active Partition Information Table (PIT) file from the device.
    pub fn receive_pit_info(&mut self) -> Result<Vec<u8>, OdinError> {
        let cmd = Command::pit_dump();
        let file_size = self.request_and_response(&cmd, 3000)? as usize;

        const PIT_CHUNK_SIZE: usize = 500;
        let transfer_count = file_size.div_ceil(PIT_CHUNK_SIZE);
        let mut buffer = Vec::with_capacity(file_size);
        let mut chunk = [0u8; PIT_CHUNK_SIZE];

        for i in 0..transfer_count {
            let cmd = Command::dump_pit_slice(i as u32);
            self.send_command(&cmd, 3000)
                .map_err(|_| OdinError::SendCommandFailed)?;

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
        let cmd = Command::pit_end();
        let value = self.request_and_response(&cmd, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        Ok(buffer)
    }

    /// Dumps device diagnostic and identity information using in-session Opcode 0x69.
    ///
    /// Available on bootloader protocol version >= 4. Kept as reference for mid-session inspection.
    pub fn dump_device_info(&mut self) -> Result<SessionDeviceInfo, OdinError> {
        let cmd = Command::device_info_dump();
        let total_bytes = self.request_and_response(&cmd, 3000)? as usize;
        if total_bytes == 0 || total_bytes > 0x100000 {
            return Err(OdinError::DeviceInfoUnavailable);
        }

        const CHUNK_SIZE: usize = 500;
        let transfer_count = total_bytes.div_ceil(CHUNK_SIZE);
        let mut buffer = Vec::with_capacity(total_bytes);
        let mut chunk = [0u8; CHUNK_SIZE];

        for i in 0..transfer_count {
            let cmd = Command::dump_device_info_slice(i as u32);
            self.send_command(&cmd, 3000)
                .map_err(|_| OdinError::SendCommandFailed)?;

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

        let cmd = Command::end_device_info();
        let value = self.request_and_response(&cmd, 3000)?;
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
        let cmd = Command::session_sales_code(code);
        let value = self.request_and_response(&cmd, 3000)?;
        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }
        Ok(())
    }

    /// Dispatches a low-level hardware NAND Erase for the USERDATA partition (Opcode 0x64, Subcmd 7).
    ///
    /// Instructs the device bootloader to issue an active hardware flash block erase across the
    /// `USERDATA` partition range via the UEFI `EraseBlock` protocol, erasing dynamic partition
    /// metadata and user data, and returns the device erase sector size.
    pub fn nand_erase(&mut self) -> Result<u32, OdinError> {
        progress::println("Erasing storage (USERDATA)...");
        let cmd = Command::nand_erase();
        let erased_sectors = self.request_and_response(&cmd, 60_000)?;
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

    /// Disables direct LZ4 transfer for the remainder of this session.
    ///
    /// LZ4 inputs will be decompressed on the host and sent through the raw
    /// transfer path. This is useful when a bootloader's advertised LZ4
    /// capability is absent, ambiguous, or known not to interoperate.
    pub fn disable_lz4(&mut self) {
        self.lz4_supported = false;
    }

    /// Returns the negotiated bootloader protocol version of the connected device.
    pub fn bootloader_protocol_version(&self) -> u32 {
        self.bootloader_protocol_version
    }

    fn transmit_slices<Iter, Bytes>(
        &mut self,
        slices: Iter,
        pit_entry: &PitEntry,
    ) -> Result<(), OdinError>
    where
        Bytes: AsRef<[u8]>,
        Iter: Iterator<Item = Bytes>,
    {
        let mut slices = slices.peekable();
        while let Some(slice_data) = slices.next() {
            let slice_data = slice_data.as_ref();
            let init_cmd = Command::transmit_flash(false);
            let start_cmd = Command::start_slice_transmission(slice_data.len() as u32);

            let is_last_slice = slices.peek().is_none();
            let end_cmd = Command::commit_slice(
                slice_data.len() as u32,
                pit_entry,
                is_last_slice,
                false,
                self.bootloader_protocol_version,
            );

            self.transmit_slice(&init_cmd, &start_cmd, &end_cmd, slice_data)?;
        }

        Ok(())
    }

    /// Flashes an uncompressed partition firmware file payload to the device.
    pub(crate) fn send_file(
        &mut self,
        info: &crate::firmware::FirmwareFile,
    ) -> Result<(), OdinError> {
        progress::set_length(info.file.len() as u64);
        let slices = info.slices(MAX_SLICE_SIZE);
        self.transmit_slices(slices, info.pit_entry)
    }

    /// Flashes an LZ4-compressed partition firmware file payload to the device,
    /// decompressing on-the-fly if needed.
    pub(crate) fn send_lz4_file(
        &mut self,
        info: &crate::firmware::FirmwareLz4File,
    ) -> Result<(), OdinError> {
        if !self.lz4_supported || info.header.block_max_size != 1024 * 1024 {
            progress::set_length(info.header.content_size);
            let slices = info.decompressed_slices(MAX_SLICE_SIZE);
            return self.transmit_slices(slices, info.pit_entry);
        }

        progress::set_length(info.file.len() as u64);

        let slices = info.slices(MAX_SLICE_SIZE);

        let mut slices = slices.peekable();
        while let Some((decompressed_size, slice_data)) = slices.next() {
            let init_cmd = Command::transmit_flash(true);
            let start_cmd = Command::start_lz4_slice_transmission(
                slice_data.len() as u32,
                decompressed_size as u32,
            );

            let is_last_slice = slices.peek().is_none();
            let end_cmd = Command::commit_slice(
                decompressed_size as u32,
                info.pit_entry,
                is_last_slice,
                true,
                self.bootloader_protocol_version,
            );

            self.transmit_slice(&init_cmd, &start_cmd, &end_cmd, slice_data)?;
        }

        Ok(())
    }

    fn transmit_slice(
        &mut self,
        init_cmd: &Command,
        start_cmd: &Command,
        end_cmd: &Command,
        slice_data: &[u8],
    ) -> Result<(), OdinError> {
        let init_val = self.request_and_response(init_cmd, 3000)?;
        if init_val != 0 {
            return Err(OdinError::Loke(LokeError::from_status(init_val as i32)));
        }

        let start_val = self.request_and_response(start_cmd, 3000)?;
        if start_val != 0 {
            return Err(OdinError::Loke(LokeError::from_status(start_val as i32)));
        }

        for (chunk_index, chunk_buffer) in slice_data.chunks(self.packet_size).enumerate() {
            let mut success = false;
            for retry in 0..5 {
                if retry > 0 {
                    progress::println("\nRetrying...");
                }

                let chunk = DataChunk::new(chunk_buffer, self.packet_size);

                if self.send_chunk(&chunk, 3000).is_err() {
                    continue;
                }

                if let Ok(response) = self.receive_response(self.slice_timeout as i32) {
                    if response.is_fail() {
                        return Err(OdinError::Loke(LokeError::from_status(
                            response.signed_value(),
                        )));
                    }
                    if response.response_type == STREAMING_CHUNK_ACK {
                        if response.signed_value() < 0 {
                            return Err(OdinError::Loke(LokeError::from_status(
                                response.signed_value(),
                            )));
                        }
                        if response.value as usize == chunk_index {
                            success = true;
                            break;
                        } else if retry == 0 {
                            return Err(OdinError::ChunkIndexMismatch {
                                expected: chunk_index,
                                received: response.value,
                            });
                        }
                    }
                }
            }

            if !success {
                return Err(OdinError::ChunkResponseReceiveFailed);
            }

            progress::inc(chunk_buffer.len() as u64);
        }

        let end_val = self.request_and_response(end_cmd, self.slice_timeout as i32)?;
        if end_val != 0 {
            return Err(OdinError::Loke(LokeError::from_status(end_val as i32)));
        }

        Ok(())
    }

    /// Sets the total expected session bytes to be flashed, allowing the device
    /// to update its progress indicator.
    pub fn set_total_bytes(&mut self, total_bytes: u64) -> Result<(), OdinError> {
        let cmd = Command::total_bytes(total_bytes);
        let value = self.request_and_response(&cmd, 3000)?;

        if value != 0 {
            return Err(OdinError::Loke(LokeError::from_status(value as i32)));
        }

        Ok(())
    }

    /// Performs a pre-flight dynamic partition size check on modern LOKE bootloaders.
    pub fn check_super_size(&mut self, super_used_size: u32) -> Result<(), OdinError> {
        let cmd = Command::check_super_size(super_used_size);
        let value = self.request_and_response(&cmd, 3000)?;

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
    use crate::protocol::CMD_SESSION_INIT;
    use crate::usb::MockBackend;

    #[test]
    fn test_odin_mock_multi_slice_transfer() {
        let backend = Box::new(MockBackend::new(false));
        let mut connection = OdinConnection::new(backend);
        assert!(connection.init().is_ok());
        let mut session = connection.begin_session().unwrap();

        let pit_entry = PitEntry {
            binary_type: samloader_pit::BinaryType::ApplicationProcessor,
            device_type: samloader_pit::DeviceType::MMC,
            partition_id: 20,
            attributes: Default::default(),
            update_attributes: Default::default(),
            start_block: 0,
            block_count: 0,
            file_offset: 0,
            file_size: 0,
            partition_name: Default::default(),
            flash_filename: Default::default(),
            fota_filename: Default::default(),
        };

        // 2 slices of 128 KB each (matching MockBackend packet_size)
        let seq1 = vec![0xAAu8; 0x20000];
        let seq2 = vec![0xBBu8; 0x20000];
        let slices = vec![seq1, seq2].into_iter();

        assert!(session.transmit_slices(slices, &pit_entry).is_ok());

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
            packet_size: 0x20000,
            slice_timeout: 3000,
            lz4_supported: false,
            bootloader_protocol_version: 2,
        };

        // 1. Control request packet -> must send 1024 bytes followed by 0 bytes (ZLP)
        let req = Command::begin_session();
        assert!(session.send_command(&req, 1000).is_ok());

        {
            let inner = spy_inner.lock().unwrap();
            assert_eq!(inner.sent_data.len(), 2);
            assert_eq!(inner.sent_data[0].len(), 1024);
            assert_eq!(inner.sent_data[1].len(), 0); // ZLP
        }

        // 2. Data chunk -> must send raw chunk bytes with NO ZLP
        let chunk_data = vec![0xABu8; 1024];
        let chunk = DataChunk::new(&chunk_data, chunk_data.len());
        assert!(session.send_chunk(&chunk, 1000).is_ok());

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
            packet_size: 0x20000,
            slice_timeout: 3000,
            lz4_supported: false,
            bootloader_protocol_version: 2,
        };

        // 1. Control request packet -> only sends 1024 bytes, no ZLP
        let req = Command::begin_session();
        assert!(session.send_command(&req, 1000).is_ok());

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
        response_bytes.extend_from_slice(&CMD_SESSION_INIT.to_le_bytes());
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
            packet_size: 0x20000,
            slice_timeout: 3000,
            lz4_supported: false,
            bootloader_protocol_version: 2,
        };

        let response = session
            .receive_response(1000)
            .expect("Should retry after 0-byte packet and receive response");
        assert_eq!(response.response_type, CMD_SESSION_INIT);
        assert_eq!(response.value, 0);
    }

    #[test]
    fn test_handshake_recovers_from_queued_fail_response() {
        let spy_inner = std::sync::Arc::new(std::sync::Mutex::new(SpyTransferInner::default()));

        {
            let mut inner = spy_inner.lock().unwrap();
            // Queue "FAILunknown command" followed by "LOKE"
            inner.read_queue.push_back(b"FAILunknown command".to_vec());
            inner.read_queue.push_back(b"LOKE".to_vec());
        }

        let spy = Box::new(SpyTransfer {
            inner: spy_inner.clone(),
            product: None,
        });

        let mut conn = OdinConnection::new(spy);
        assert!(conn.init().is_ok());

        let inner = spy_inner.lock().unwrap();
        assert_eq!(inner.sent_data.len(), 1);
        assert_eq!(inner.sent_data[0], b"ODIN");
    }
}
