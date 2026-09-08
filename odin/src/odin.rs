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
}

#[derive(PartialEq, Eq, Copy, Clone)]
enum EmptySendKind {
    None,
    Before,
    After,
    BeforeAndAfter,
}

const FILE_TRANSFER_SEQUENCE_MAX_LENGTH_DEFAULT: usize = 800;
const FILE_TRANSFER_PACKET_SIZE_DEFAULT: usize = 0x20000;
const FILE_TRANSFER_SEQUENCE_TIMEOUT_DEFAULT: u32 = 30000;

impl OdinConnection {
    /// Creates a new `OdinConnection` instance with a given transport.
    pub fn new(usb: Box<dyn UsbTransfer>) -> Self {
        Self { usb }
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
        let session_response = session
            .request_and_response(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::BeginSessionFailed)?;

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
            let value = session
                .request_and_response(&packet, EmptySendKind::After, 3000)
                .map_err(|_| OdinError::FilePartSizeSendFailed)?;

            if value != 0 {
                return Err(OdinError::UnexpectedFilePartSizeResponse(value));
            }
        }

        progress::println("Session begun.\n");
        Ok(session)
    }

    /// Ends the active flashing session on the device.
    pub fn end_session(&mut self) -> Result<(), OdinError> {
        progress::println("Ending session...");

        let packet = RequestPacket::end_session();
        self.request_and_response(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::EndSessionSendFailed)?;

        Ok(())
    }

    /// Reboots the device normally out of Download Mode.
    pub fn reboot_device(&mut self) -> Result<(), OdinError> {
        progress::println("Rebooting device...");

        let packet = RequestPacket::reboot_device();
        progress::println_verbose(&format!("Sending packet: {:#04X?}", packet));

        // The device immediately reboots and drops the USB connection,
        // so the write may partially fail and a response will never arrive.
        // We do a fire-and-forget send with no retries and a short timeout.
        let _ = self.connection.usb.send_data(&packet.pack(), 500, false);

        // This is required for some devices e.g. A55.
        self.send_empty(100);
        self.receive_empty(100);

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

    fn send_empty(&mut self, timeout: i32) {
        self.connection.usb.send_data(&[], timeout, false);
    }

    fn receive_empty(&mut self, timeout: i32) {
        let mut buffer = [0u8; 1];
        self.connection
            .usb
            .receive_data(&mut buffer, timeout, false);
    }

    fn send_bytes(
        &mut self,
        bytes: &[u8],
        empty_send_kind: EmptySendKind,
        timeout: i32,
    ) -> Result<(), ()> {
        if empty_send_kind == EmptySendKind::Before
            || empty_send_kind == EmptySendKind::BeforeAndAfter
        {
            self.send_empty(100);
        }
        if !self.connection.usb.send_data(bytes, timeout, true) {
            return Err(());
        }
        if empty_send_kind == EmptySendKind::After
            || empty_send_kind == EmptySendKind::BeforeAndAfter
        {
            self.send_empty(100);
        }
        Ok(())
    }

    fn send_packet(
        &mut self,
        packet: &RequestPacket,
        empty_send_kind: EmptySendKind,
        timeout: i32,
    ) -> Result<(), ()> {
        progress::println_verbose(&format!("Sending packet: {:#04X?}", packet));
        let packet_bytes = packet.pack();
        self.send_bytes(&packet_bytes, empty_send_kind, timeout)
    }

    fn send_file_part(
        &mut self,
        packet: &packets::FilePartPacket<'_>,
        empty_send_kind: EmptySendKind,
        timeout: i32,
    ) -> Result<(), ()> {
        progress::println_verbose(&format!("Sending packet: {:#04X?}", packet));
        let packet_bytes = packet.as_bytes();
        self.send_bytes(&packet_bytes, empty_send_kind, timeout)
    }

    fn receive_response(&mut self, timeout: i32) -> Result<packets::Response, OdinError> {
        let mut buffer = [0u8; packets::Response::SIZE];
        let received_size = self.connection.usb.receive_data(&mut buffer, timeout, true);

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
        empty_send_kind: EmptySendKind,
        timeout: i32,
    ) -> Result<u32, OdinError> {
        self.send_packet(packet, empty_send_kind, timeout)
            .map_err(|_| OdinError::SendPacketFailed)?;

        let response = self.receive_response(timeout)?;
        let expected_type = packet.expected_response_type();

        if response.response_type != expected_type {
            return Err(OdinError::ResponseTypeMismatch {
                expected: expected_type,
                received: response.response_type,
            });
        }

        Ok(response.value)
    }

    /// Flashes/uploads raw PIT data to the device.
    pub fn send_pit_data(&mut self, pit_buffer: &[u8]) -> Result<(), OdinError> {
        let pit_buffer_size = pit_buffer.len() as u32;

        // Start file transfer
        let packet = RequestPacket::pit_file_flash();
        self.request_and_response(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::PitFileTransferInitFailed)?;

        // Transfer file size
        let packet = RequestPacket::flash_part_pit_file(pit_buffer_size);
        self.request_and_response(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::PitFilePartInfoSendFailed)?;

        // Flash pit file
        let packet = packets::FilePartPacket::new(pit_buffer, pit_buffer_size as usize);
        self.send_file_part(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::SendPacketFailed)?;

        let response = self.receive_response(3000)?;

        if response.response_type != packets::RESPONSE_TYPE_SEND_FILE_PART
            && response.response_type != packets::RESPONSE_TYPE_PIT_FILE
        {
            return Err(OdinError::ResponseTypeMismatch {
                expected: packets::RESPONSE_TYPE_PIT_FILE,
                received: response.response_type,
            });
        }

        // End pit file transfer
        let packet = RequestPacket::end_pit_file_transfer(pit_buffer_size);
        self.request_and_response(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::PitFileTransferEndSendFailed)?;

        Ok(())
    }

    /// Downloads/dumps the active Partition Information Table (PIT) file from the device.
    pub fn download_pit_file(&mut self) -> Result<Vec<u8>, OdinError> {
        let packet = RequestPacket::pit_file_dump();
        let file_size = self
            .request_and_response(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::PitFileSizeReceiveFailed)? as usize;

        const PIT_CHUNK_SIZE: usize = 500;
        let transfer_count = file_size.div_ceil(PIT_CHUNK_SIZE);
        let mut buffer = Vec::with_capacity(file_size);
        let mut chunk = [0u8; PIT_CHUNK_SIZE];

        for i in 0..transfer_count {
            let packet = RequestPacket::dump_part_pit_file(i as u32);
            self.send_packet(&packet, EmptySendKind::After, 3000)
                .map_err(|_| OdinError::PitFilePartRequestFailed(i as u32))?;

            let expected_size = std::cmp::min(file_size - buffer.len(), PIT_CHUNK_SIZE);

            let received =
                self.connection
                    .usb
                    .receive_data(&mut chunk[..expected_size], 3000, true);
            if received < 0 {
                return Err(OdinError::PitFilePartReceiveFailed(i as u32));
            }
            buffer.extend_from_slice(&chunk[..received as usize]);
        }

        // Receive empty packet after the last PIT transfer,
        // this is required for some older devices e.g. Tab S2 VE.
        self.receive_empty(100);

        // End file transfer
        let packet = RequestPacket::pit_file_end();
        self.request_and_response(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::PitFileEndSendFailed)?;

        Ok(buffer)
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
        let packet = RequestPacket::file_transfer_flash(false);
        self.request_and_response(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::FileTransferInitFailed)?;

        let mut sequences = sequences.peekable();
        while let Some(sequence_data) = sequences.next() {
            let sequence_data = sequence_data.as_ref();
            let start_packet =
                RequestPacket::flash_part_file_transfer(sequence_data.len() as u32, false);

            let is_last_sequence = sequences.peek().is_none();
            let end_packet = RequestPacket::end_file_transfer(
                sequence_data.len() as u32,
                pit_entry,
                is_last_sequence,
                false,
            );

            self.send_one_sequence(&start_packet, &end_packet, sequence_data)?;
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

        let packet = RequestPacket::file_transfer_flash(true);
        self.request_and_response(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::FileTransferInitFailed)?;

        let sequences = info.sequences(self.file_transfer_sequence_max_bytes());

        let mut sequences = sequences.peekable();
        while let Some((decompressed_size, sequence_data)) = sequences.next() {
            let start_packet =
                RequestPacket::flash_part_file_transfer(sequence_data.len() as u32, true);

            let is_last_sequence = sequences.peek().is_none();
            let end_packet = RequestPacket::end_file_transfer(
                decompressed_size as u32,
                info.pit_entry,
                is_last_sequence,
                true,
            );

            self.send_one_sequence(&start_packet, &end_packet, sequence_data)?;
        }

        Ok(())
    }

    fn send_one_sequence(
        &mut self,
        start_packet: &RequestPacket,
        end_packet: &RequestPacket,
        sequence_data: &[u8],
    ) -> Result<(), OdinError> {
        self.request_and_response(start_packet, EmptySendKind::BeforeAndAfter, 3000)
            .map_err(|_| OdinError::FileTransferSequenceBeginFailed)?;

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

                let empty_send_kind = if file_part_index == 0 {
                    EmptySendKind::None
                } else {
                    EmptySendKind::Before
                };

                if self.send_file_part(&packet, empty_send_kind, 3000).is_err() {
                    continue;
                }

                match self.receive_response(self.file_transfer_sequence_timeout as i32) {
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

            progress::inc(file_buffer.len() as u64);
        }

        self.request_and_response(
            end_packet,
            EmptySendKind::BeforeAndAfter,
            self.file_transfer_sequence_timeout as i32,
        )
        .map_err(|_| OdinError::FileTransferSequenceEndFailed)?;

        Ok(())
    }

    /// Sets the total expected session bytes to be flashed, allowing the device
    /// to update its progress indicator.
    pub fn set_total_bytes(&mut self, total_bytes: u64) -> Result<(), OdinError> {
        let packet = RequestPacket::total_bytes(total_bytes);
        let value = self
            .request_and_response(&packet, EmptySendKind::After, 3000)
            .map_err(|_| OdinError::TotalBytesSendFailed)?;

        if value != 0 {
            return Err(OdinError::UnexpectedTotalBytesResponse(value));
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
    fn test_odin_connection_raw_string_io() {
        let backend = Box::new(MockBackend::new(true));
        let mut connection = OdinConnection::new(backend);

        // Send raw string
        assert!(connection.send_string("ODIN", 1000).is_ok());

        // Receive raw string response
        let resp = connection.receive_string(1000).unwrap();
        assert_eq!(resp, "LOKE");
    }
}
