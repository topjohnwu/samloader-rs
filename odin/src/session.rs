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

//! The Odin protocol connection and session with a device in Download Mode.

use crate::device_info::{DeviceInfo, SessionDeviceInfo};
use crate::error::{LokeError, OdinError, TransportError};
use crate::progress;
use crate::protocol::{CMD_PIT, Command, DataChunk, Response, STREAMING_CHUNK_ACK};
use crate::usb::{UsbBackendOption, UsbTransfer, create_backend};
use futures::StreamExt;
use futures::stream::Stream;
use samloader_pit::PitEntry;
use std::time::Duration;

/// Manages the initial connection to a Samsung device in Download Mode.
///
/// At this stage, only the handshake ([`init`](Self::init)) and the DVIF query
/// ([`query_device_info`](Self::query_device_info)) are available. Other commands
/// require transitioning to an [`OdinSession`] via [`begin_session`](Self::begin_session).
pub struct OdinConnection {
    usb: Box<dyn UsbTransfer>,
    skip_empty_send: bool,
}

/// Maximum size of a slice, which the bootloader stages in memory before
/// committing it (30 MiB, 0x1E00000, as in odin4).
pub(crate) const MAX_SLICE_SIZE: usize = 30 * 1024 * 1024;
/// The only LZ4 block size the bootloader accepts compressed slices with.
const LZ4_PASSTHROUGH_BLOCK_SIZE: u64 = 1024 * 1024;
const PACKET_SIZE_DEFAULT: usize = 0x20000; // 128 KB default before negotiation
const SLICE_TIMEOUT_DEFAULT: Duration = Duration::from_secs(30);
/// Slice timeout on bootloader protocol version 2 and later.
const SLICE_TIMEOUT_V2: Duration = Duration::from_secs(120);
/// Timeout of most commands and their responses.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
/// Timeout of the handshake and DVIF query.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
/// Timeout of trailing empty packets (ZLPs) and reads that may not happen.
const EMPTY_PACKET_TIMEOUT: Duration = Duration::from_millis(100);

impl OdinConnection {
    /// Opens a device in Download Mode with the selected backend. If `wait` is
    /// set, waits until such a device is connected.
    pub async fn open(usb_backend: UsbBackendOption, wait: bool) -> Result<Self, OdinError> {
        Ok(Self::new(create_backend(usb_backend, wait).await?))
    }

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
    pub async fn init(&mut self) -> Result<(), OdinError> {
        progress::println("Initializing protocol...");

        self.usb.reset().await;

        self.send_string("ODIN", HANDSHAKE_TIMEOUT)
            .await
            .map_err(OdinError::HandshakeSendFailed)?;

        let mut response = self
            .receive_string(HANDSHAKE_TIMEOUT)
            .await
            .map_err(OdinError::HandshakeReceiveFailed)?;

        if response != "LOKE"
            && response.starts_with("FAIL")
            && self
                .receive_string(Duration::from_millis(500))
                .await
                .is_ok_and(|s| s == "LOKE")
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
    async fn send_string(&mut self, s: &str, timeout: Duration) -> Result<(), TransportError> {
        progress::println_verbose(&format!("Sending string: {:?}", s));
        self.usb.send(s.as_bytes(), timeout).await
    }

    /// Receives a raw string message from the transport connection.
    async fn receive_string(&mut self, timeout: Duration) -> Result<String, TransportError> {
        let mut buffer = [0u8; 1024];
        let received_size = self.usb.receive(&mut buffer, timeout).await?;

        let data = &buffer[..received_size];
        progress::println_verbose(&format!(
            "Received string data ({} bytes): {:?}",
            received_size, data
        ));
        Ok(String::from_utf8_lossy(data).into_owned())
    }

    /// Queries the connected device for hardware and software diagnostics using the pre-handshake DVIF protocol.
    ///
    /// Can be called prior to `init()` to inspect the device without opening an Odin session.
    pub async fn query_device_info(&mut self) -> Result<DeviceInfo, OdinError> {
        progress::println_verbose("Querying device info via DVIF...");
        self.usb
            .send(b"DVIF", HANDSHAKE_TIMEOUT)
            .await
            .map_err(OdinError::SendCommandFailed)?;

        let mut buffer = [0u8; 1024];
        let received_size = match self.usb.receive(&mut buffer, HANDSHAKE_TIMEOUT).await {
            Ok(size) if size > 0 => size,
            _ => return Err(OdinError::DeviceInfoUnavailable),
        };

        let s = String::from_utf8_lossy(&buffer[..received_size]);
        progress::println_verbose(&format!("DVIF response ({} bytes): {}", received_size, s));
        DeviceInfo::parse(&s)
    }

    /// Begins an active flashing session, negotiating features such as packet size and LZ4 support,
    /// transitioning the connection into an [`OdinSession`].
    pub async fn begin_session(self) -> Result<OdinSession, OdinError> {
        OdinSession::begin(self).await
    }
}

/// Specifies the device reboot behavior after a session ends.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum RebootMode {
    /// Do not reboot the device; end the session and remain in download mode.
    #[default]
    None,
    /// Reboot the device normally out of Download Mode.
    Normal,
    /// Reboot the device back into Download Mode.
    Download,
}

/// An active flashing session coordinating Samsung Odin/Loke command transfers.
pub struct OdinSession {
    connection: OdinConnection,

    packet_size: usize,
    slice_timeout: Duration,
    lz4_supported: bool,
    bootloader_protocol_version: u32,
}

impl OdinSession {
    /// Opens a device in Download Mode with the selected backend, performs the
    /// handshake and begins a session. If `wait` is set, waits until such a
    /// device is connected.
    pub async fn connect(usb_backend: UsbBackendOption, wait: bool) -> Result<Self, OdinError> {
        let mut connection = OdinConnection::open(usb_backend, wait).await?;
        connection.init().await?;
        connection.begin_session().await
    }

    async fn begin(connection: OdinConnection) -> Result<Self, OdinError> {
        progress::println("Beginning session...");

        let mut session = Self {
            connection,
            packet_size: PACKET_SIZE_DEFAULT,
            slice_timeout: SLICE_TIMEOUT_DEFAULT,
            lz4_supported: false,
            bootloader_protocol_version: 0,
        };

        let cmd = Command::begin_session();
        let session_response = session.request_and_response(&cmd, COMMAND_TIMEOUT).await?;

        session.bootloader_protocol_version = if session_response == 0 {
            1
        } else {
            session_response >> 16
        };

        progress::println(
            "\nSome devices may take up to 2 minutes to respond.\nPlease be patient!\n",
        );
        futures_timer::Delay::new(Duration::from_secs(3)).await;

        if session.bootloader_protocol_version >= 2 {
            session.lz4_supported = (session_response & 0x8000) != 0;
            session.slice_timeout = SLICE_TIMEOUT_V2;
            session.packet_size = 0x100000;

            let cmd = Command::packet_size(session.packet_size as u32);
            session.request_ok(&cmd, COMMAND_TIMEOUT).await?;
        }

        progress::println("Session begun.\n");
        Ok(session)
    }

    /// Ends the active flashing session on the device.
    pub async fn end_session(&mut self) -> Result<(), OdinError> {
        progress::println("Ending session...");

        let cmd = Command::close_connection();
        self.request_ok(&cmd, COMMAND_TIMEOUT).await
    }

    /// Ends the session, then reboots the device as requested.
    ///
    /// Like Heimdall, the session is always ended before rebooting, so the
    /// bootloader completes the session before the device goes down. The
    /// reboot is attempted even if ending the session fails, and the first
    /// error is returned.
    pub async fn finish(&mut self, reboot_mode: RebootMode) -> Result<(), OdinError> {
        let ended = self.end_session().await;
        let rebooted = match reboot_mode {
            RebootMode::Normal => self.reboot_device().await,
            RebootMode::Download => self.reboot_to_download().await,
            RebootMode::None => Ok(()),
        };
        ended.and(rebooted)
    }

    /// Reboots the device normally out of Download Mode.
    ///
    /// This does not end the session first; use [`finish`](Self::finish) to
    /// end the session and reboot.
    pub async fn reboot_device(&mut self) -> Result<(), OdinError> {
        self.reboot_with_command(&Command::reboot_device(), "Rebooting device...")
            .await
    }

    /// Reboots the device back into Download Mode.
    ///
    /// This does not end the session first; use [`finish`](Self::finish) to
    /// end the session and reboot.
    pub async fn reboot_to_download(&mut self) -> Result<(), OdinError> {
        self.reboot_with_command(
            &Command::reboot_to_download(),
            "Rebooting device to Download Mode...",
        )
        .await
    }

    async fn reboot_with_command(&mut self, cmd: &Command, msg: &str) -> Result<(), OdinError> {
        progress::println(msg);

        // Send reboot command using standard send_command, which automatically
        // appends an empty packet (ZLP) for "Gadget Serial" devices (e.g. S10).
        let _ = self.send_command(cmd, Duration::from_millis(500)).await;

        // Attempt to read from the IN endpoint to consume any response or ACK/ZLP
        // sent by the bootloader before resetting (required on devices such as A55).
        // Any timeout or disconnect error is ignored since the device is rebooting.
        let mut buffer = [0u8; 64];
        let _ = self
            .connection
            .usb
            .receive(&mut buffer, EMPTY_PACKET_TIMEOUT)
            .await;

        Ok(())
    }

    /// Ends the session and returns the underlying connection.
    pub async fn close(mut self) -> Result<OdinConnection, OdinError> {
        self.end_session().await?;
        Ok(self.connection)
    }

    /// Consumes the session and returns the underlying connection without sending an end-session packet.
    pub fn into_connection(self) -> OdinConnection {
        self.connection
    }

    async fn send_command(&mut self, cmd: &Command, timeout: Duration) -> Result<(), OdinError> {
        progress::println_verbose(&format!("Sending command: {:#04X?}", cmd));
        let cmd_bytes = cmd.pack();
        self.connection
            .usb
            .send(&cmd_bytes, timeout)
            .await
            .map_err(OdinError::SendCommandFailed)?;
        if !self.connection.skip_empty_send {
            // The command itself was sent, so a failed empty packet is not an error
            let _ = self.connection.usb.send(&[], EMPTY_PACKET_TIMEOUT).await;
        }
        Ok(())
    }

    async fn send_chunk(
        &mut self,
        chunk: &DataChunk<'_>,
        timeout: Duration,
    ) -> Result<(), OdinError> {
        progress::println_verbose(&format!("Sending chunk: {:#04X?}", chunk));
        let chunk_bytes = chunk.as_bytes();
        self.connection
            .usb
            .send(&chunk_bytes, timeout)
            .await
            .map_err(OdinError::SendCommandFailed)
    }

    async fn receive_response(&mut self, timeout: Duration) -> Result<Response, OdinError> {
        let mut buffer = [0u8; Response::SIZE];
        let mut received_size = self.receive(&mut buffer, timeout).await?;

        // Mirror odin4: if 0 bytes received (a ZLP was received), read again
        if received_size == 0 {
            received_size = self.receive(&mut buffer, timeout).await?;
        }

        let parsed =
            Response::parse(&buffer[..received_size]).map_err(OdinError::InvalidResponse)?;
        progress::println_verbose(&format!("Received response: {:#04X?}", parsed));
        Ok(parsed)
    }

    /// Receives raw data from the device.
    async fn receive(&mut self, data: &mut [u8], timeout: Duration) -> Result<usize, OdinError> {
        self.connection
            .usb
            .receive(data, timeout)
            .await
            .map_err(OdinError::ReceivePacketFailed)
    }

    async fn request_and_response(
        &mut self,
        cmd: &Command,
        timeout: Duration,
    ) -> Result<u32, OdinError> {
        self.send_command(cmd, timeout).await?;

        let response = self.receive_response(timeout).await?;
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

    /// Sends a command whose response value must be 0, and reports any
    /// other value as a LOKE error.
    async fn request_ok(&mut self, cmd: &Command, timeout: Duration) -> Result<(), OdinError> {
        match self.request_and_response(cmd, timeout).await? {
            0 => Ok(()),
            value => Err(OdinError::Loke(LokeError::from_status(value as i32))),
        }
    }

    /// Flashes/uploads raw PIT data to the device.
    pub async fn send_pit_info(&mut self, pit_buffer: &[u8]) -> Result<(), OdinError> {
        let pit_buffer_size = pit_buffer.len() as u32;

        // Start file transfer
        let cmd = Command::pit_flash();
        self.request_ok(&cmd, COMMAND_TIMEOUT).await?;

        // Transfer file size
        let cmd = Command::flash_pit_slice(pit_buffer_size);
        self.request_ok(&cmd, COMMAND_TIMEOUT).await?;

        // Flash pit file
        let chunk = DataChunk::new(pit_buffer, pit_buffer_size as usize);
        self.send_chunk(&chunk, COMMAND_TIMEOUT).await?;

        let response = self.receive_response(COMMAND_TIMEOUT).await?;

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
        self.request_ok(&cmd, COMMAND_TIMEOUT).await
    }

    /// Downloads/dumps the active Partition Information Table (PIT) file from the device.
    pub async fn receive_pit_info(&mut self) -> Result<Vec<u8>, OdinError> {
        let cmd = Command::pit_dump();
        let file_size = self.request_and_response(&cmd, COMMAND_TIMEOUT).await? as usize;

        const PIT_CHUNK_SIZE: usize = 500;
        let transfer_count = file_size.div_ceil(PIT_CHUNK_SIZE);
        let mut buffer = Vec::with_capacity(file_size);
        let mut chunk = [0u8; PIT_CHUNK_SIZE];

        for i in 0..transfer_count {
            let cmd = Command::dump_pit_slice(i as u32);
            self.send_command(&cmd, COMMAND_TIMEOUT).await?;

            let expected_size = std::cmp::min(file_size - buffer.len(), PIT_CHUNK_SIZE);

            let received = self
                .receive(&mut chunk[..expected_size], COMMAND_TIMEOUT)
                .await?;
            buffer.extend_from_slice(&chunk[..received]);
        }

        // Receive empty packet after the last PIT transfer,
        // this is required for some older devices e.g. Tab S2 VE.
        let mut empty = [0u8; 1];
        let _ = self
            .connection
            .usb
            .receive(&mut empty, EMPTY_PACKET_TIMEOUT)
            .await;

        // End file transfer
        let cmd = Command::pit_end();
        self.request_ok(&cmd, COMMAND_TIMEOUT).await?;

        Ok(buffer)
    }

    /// Dumps device diagnostic and identity information using in-session Opcode 0x69.
    ///
    /// Available on bootloader protocol version >= 4. Kept as reference for mid-session inspection.
    pub async fn dump_device_info(&mut self) -> Result<SessionDeviceInfo, OdinError> {
        let cmd = Command::device_info_dump();
        let total_bytes = self.request_and_response(&cmd, COMMAND_TIMEOUT).await? as usize;
        if total_bytes == 0 || total_bytes > 0x100000 {
            return Err(OdinError::DeviceInfoUnavailable);
        }

        const CHUNK_SIZE: usize = 500;
        let transfer_count = total_bytes.div_ceil(CHUNK_SIZE);
        let mut buffer = Vec::with_capacity(total_bytes);
        let mut chunk = [0u8; CHUNK_SIZE];

        for i in 0..transfer_count {
            let cmd = Command::dump_device_info_slice(i as u32);
            self.send_command(&cmd, COMMAND_TIMEOUT).await?;

            let expected_size = std::cmp::min(total_bytes - buffer.len(), CHUNK_SIZE);
            let received = self
                .receive(&mut chunk[..expected_size], COMMAND_TIMEOUT)
                .await?;
            buffer.extend_from_slice(&chunk[..received]);
        }

        let cmd = Command::end_device_info();
        self.request_ok(&cmd, COMMAND_TIMEOUT).await?;

        SessionDeviceInfo::parse(&buffer)
    }

    /// Sets the device CSC / Sales Code in bootloader parameter storage (Opcode 0x64, Subcmd 9).
    pub async fn set_sales_code(&mut self, sales_code: &str) -> Result<(), OdinError> {
        let code = parse_sales_code(sales_code)?;
        let cmd = Command::session_sales_code(code);
        self.request_ok(&cmd, COMMAND_TIMEOUT).await
    }

    /// Dispatches a low-level hardware NAND Erase for the USERDATA partition (Opcode 0x64, Subcmd 7).
    ///
    /// Instructs the device bootloader to issue an active hardware flash block erase across the
    /// `USERDATA` partition range via the UEFI `EraseBlock` protocol, erasing dynamic partition
    /// metadata and user data, and returns the device erase sector size.
    pub async fn nand_erase(&mut self) -> Result<u32, OdinError> {
        progress::println("Erasing storage (USERDATA)...");
        let cmd = Command::nand_erase();
        let erased_sectors = self
            .request_and_response(&cmd, Duration::from_secs(60))
            .await?;
        progress::println(&format!(
            "Storage erased successfully ({} sectors)\n",
            erased_sectors
        ));
        Ok(erased_sectors)
    }

    /// Returns whether the device reported support for LZ4-compressed slices
    /// when the session began. Compressed slices are only accepted with 1 MiB
    /// blocks; other LZ4 frames must be decompressed before sending.
    pub fn is_lz4_supported(&self) -> bool {
        self.lz4_supported
    }

    /// Returns the negotiated bootloader protocol version of the connected device.
    pub fn bootloader_protocol_version(&self) -> u32 {
        self.bootloader_protocol_version
    }

    /// Returns whether the device accepts LZ4 frames with the given maximum
    /// block size without decompressing them first.
    pub(crate) fn accepts_lz4_blocks(&self, block_max_size: u64) -> bool {
        self.lz4_supported && block_max_size == LZ4_PASSTHROUGH_BLOCK_SIZE
    }

    /// Transmits a partition image as a stream of raw slices.
    ///
    /// The next slice is read from `slices` while the current one is being
    /// sent. This only overlaps reading with the USB transfer if the stream
    /// returns `Pending` while its I/O is in progress; a stream that blocks is
    /// read to completion before the current slice is started.
    pub(crate) async fn send_slices<S, Bytes>(
        &mut self,
        pit_entry: &PitEntry,
        slices: S,
    ) -> Result<(), OdinError>
    where
        Bytes: AsRef<[u8]>,
        S: Stream<Item = std::io::Result<Bytes>>,
    {
        let mut slices = std::pin::pin!(slices);
        let mut current = slices.next().await.transpose()?;
        while let Some(slice_data) = current {
            let slice_data = slice_data.as_ref();
            let init_cmd = Command::transmit_flash(false);
            let start_cmd = Command::start_slice_transmission(slice_data.len() as u32);

            // The read is polled first, so that a blocking reader finishes
            // before the slice is started, like a sequential loop would
            let (next, sent) = futures::future::join(
                slices.next(),
                self.transmit_slice_data(&init_cmd, &start_cmd, slice_data),
            )
            .await;
            sent?;
            let next = next.transpose()?;

            // Whether this is the last slice is only needed once the data is sent
            let end_cmd = Command::commit_slice(
                slice_data.len() as u32,
                pit_entry,
                next.is_none(),
                false,
                self.bootloader_protocol_version,
            );
            self.commit_slice(&end_cmd).await?;
            current = next;
        }

        Ok(())
    }

    /// Transmits a partition image as a stream of LZ4-compressed slices, each
    /// paired with its decompressed size.
    ///
    /// Only valid if [`accepts_lz4_blocks`](Self::accepts_lz4_blocks) holds
    /// for the frame the slices come from. Like [`send_slices`](Self::send_slices),
    /// the next slice is read while the current one is being sent.
    pub(crate) async fn send_lz4_slices<S>(
        &mut self,
        pit_entry: &PitEntry,
        slices: S,
    ) -> Result<(), OdinError>
    where
        S: Stream<Item = std::io::Result<(usize, Vec<u8>)>>,
    {
        let mut slices = std::pin::pin!(slices);
        let mut current = slices.next().await.transpose()?;
        while let Some((decompressed_size, slice_data)) = current {
            let init_cmd = Command::transmit_flash(true);
            let start_cmd = Command::start_lz4_slice_transmission(
                slice_data.len() as u32,
                decompressed_size as u32,
            );

            // The read is polled first, so that a blocking reader finishes
            // before the slice is started, like a sequential loop would
            let (next, sent) = futures::future::join(
                slices.next(),
                self.transmit_slice_data(&init_cmd, &start_cmd, &slice_data),
            )
            .await;
            sent?;
            let next = next.transpose()?;

            // Whether this is the last slice is only needed once the data is sent
            let end_cmd = Command::commit_slice(
                decompressed_size as u32,
                pit_entry,
                next.is_none(),
                true,
                self.bootloader_protocol_version,
            );
            self.commit_slice(&end_cmd).await?;
            current = next;
        }

        Ok(())
    }

    /// Starts a slice transfer and sends its data in packets, leaving the slice
    /// to be committed with [`commit_slice`](Self::commit_slice).
    async fn transmit_slice_data(
        &mut self,
        init_cmd: &Command,
        start_cmd: &Command,
        slice_data: &[u8],
    ) -> Result<(), OdinError> {
        self.request_ok(init_cmd, COMMAND_TIMEOUT).await?;

        self.request_ok(start_cmd, COMMAND_TIMEOUT).await?;

        for (chunk_index, chunk_buffer) in slice_data.chunks(self.packet_size).enumerate() {
            let chunk = DataChunk::new(chunk_buffer, self.packet_size);

            self.send_chunk(&chunk, COMMAND_TIMEOUT).await?;

            let response = self
                .receive_response(self.slice_timeout)
                .await
                .map_err(|e| OdinError::ChunkResponseReceiveFailed(Box::new(e)))?;

            if response.is_fail() {
                return Err(OdinError::Loke(LokeError::from_status(
                    response.signed_value(),
                )));
            }

            if response.response_type != STREAMING_CHUNK_ACK {
                return Err(OdinError::ResponseTypeMismatch {
                    expected: STREAMING_CHUNK_ACK,
                    received: response.response_type,
                });
            }

            if response.signed_value() < 0 {
                return Err(OdinError::Loke(LokeError::from_status(
                    response.signed_value(),
                )));
            }

            if response.value as usize != chunk_index {
                return Err(OdinError::ChunkIndexMismatch {
                    expected: chunk_index,
                    received: response.value,
                });
            }

            progress::inc(chunk_buffer.len() as u64);
        }

        Ok(())
    }

    /// Commits a slice whose data was sent with
    /// [`transmit_slice_data`](Self::transmit_slice_data).
    async fn commit_slice(&mut self, end_cmd: &Command) -> Result<(), OdinError> {
        self.request_ok(end_cmd, self.slice_timeout).await
    }

    /// Sets the total expected session bytes to be flashed, allowing the device
    /// to update its progress indicator.
    pub async fn set_total_bytes(&mut self, total_bytes: u64) -> Result<(), OdinError> {
        let cmd = Command::total_bytes(total_bytes);
        self.request_ok(&cmd, COMMAND_TIMEOUT).await
    }

    /// Performs a pre-flight dynamic partition size check on modern LOKE bootloaders.
    pub async fn check_super_size(&mut self, super_used_size: u32) -> Result<(), OdinError> {
        let cmd = Command::check_super_size(super_used_size);
        self.request_ok(&cmd, COMMAND_TIMEOUT).await
    }
}

/// Validates a CSC / sales code, which must be 3 alphanumeric ASCII characters.
pub(crate) fn parse_sales_code(sales_code: &str) -> Result<[u8; 3], OdinError> {
    match *sales_code.as_bytes() {
        [a, b, c] if [a, b, c].iter().all(u8::is_ascii_alphanumeric) => Ok([a, b, c]),
        _ => Err(OdinError::InvalidSalesCode(sales_code.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CMD_SESSION_INIT;
    use crate::test_util::mock_session;
    use crate::usb::{MockBackend, MockEvent};
    use std::sync::atomic::Ordering;

    #[test]
    fn test_odin_mock_multi_slice_transfer() {
        futures::executor::block_on(async {
            let mut session = mock_session(MockBackend::new()).await;

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
            let slices = futures::stream::iter(vec![Ok(seq1.clone()), Ok(seq2)]);

            assert!(session.send_slices(&pit_entry, slices).await.is_ok());

            // Verify a mid-stream I/O error aborts the transfer with OdinError::Io
            let failing_slices = futures::stream::iter(vec![
                Ok(seq1),
                Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            ]);
            assert!(matches!(
                session.send_slices(&pit_entry, failing_slices).await,
                Err(OdinError::Io(_))
            ));

            assert!(session.close().await.is_ok());
        });
    }

    #[test]
    fn test_send_slices_reads_next_slice_while_sending() {
        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let log = backend.event_log();
            let chunks = backend.received_chunks();
            let mut session = mock_session(backend).await;
            let pit_data = crate::test_util::ab_pit_data();
            let pit_entry = crate::test_util::find_entry(&pit_data, "BOOT_A");

            // 3 slices of 2 packets each. Each read takes longer than sending a
            // slice, and records how far the transfer is once it completes.
            let packet_size = session.packet_size;
            let progress = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let slices = futures::stream::iter(0..3u8).then(|idx| {
                let (log, chunks, progress) = (log.clone(), chunks.clone(), progress.clone());
                async move {
                    for _ in 0..20 {
                        crate::usb::yield_now().await;
                    }
                    let committed = log.lock().unwrap().len();
                    progress
                        .lock()
                        .unwrap()
                        .push((chunks.load(Ordering::Relaxed), committed));
                    Ok(vec![idx; 2 * packet_size])
                }
            });
            assert!(session.send_slices(pit_entry, slices).await.is_ok());

            // Each slice is read while the previous one is sent, and is ready
            // before the previous one is committed
            assert_eq!(*progress.lock().unwrap(), [(0, 0), (2, 0), (4, 1)]);
            let last: Vec<_> = log
                .lock()
                .unwrap()
                .iter()
                .map(|e| matches!(e, MockEvent::Slice { last: true, .. }))
                .collect();
            assert_eq!(last, [false, false, true]);

            assert!(session.close().await.is_ok());
        });
    }

    #[test]
    fn test_odin_mock_set_sales_code() {
        futures::executor::block_on(async {
            let mut session = mock_session(MockBackend::new()).await;

            assert!(session.set_sales_code("TUR").await.is_ok());

            // Verify invalid formats are rejected
            assert!(matches!(
                session.set_sales_code("TU").await,
                Err(OdinError::InvalidSalesCode(_))
            ));
            assert!(matches!(
                session.set_sales_code("TUR1").await,
                Err(OdinError::InvalidSalesCode(_))
            ));
            assert!(matches!(
                session.set_sales_code("T-R").await,
                Err(OdinError::InvalidSalesCode(_))
            ));

            assert!(session.close().await.is_ok());
        });
    }

    #[test]
    fn test_finish_reboots_even_if_ending_fails() {
        futures::executor::block_on(async {
            let backend = MockBackend::new().with_fail_end_session(-1);
            let log = backend.event_log();
            let mut session = mock_session(backend).await;

            let res = session.finish(RebootMode::Normal).await;
            assert!(matches!(res, Err(OdinError::Loke(_))));
            assert_eq!(*log.lock().unwrap(), [MockEvent::Reboot]);
        });
    }

    #[test]
    fn test_skip_empty_send_detection() {
        let gadget = Box::new(MockBackend::new().with_product_name("Gadget Serial"));
        let conn_gadget = OdinConnection::new(gadget);
        assert!(!conn_gadget.skip_empty_send());

        let gadget_prefix = Box::new(MockBackend::new().with_product_name("Gadget Serial v2"));
        let conn_gadget_prefix = OdinConnection::new(gadget_prefix);
        assert!(!conn_gadget_prefix.skip_empty_send());

        let msm = Box::new(MockBackend::new().with_product_name("MSM8996"));
        let conn_msm = OdinConnection::new(msm);
        assert!(conn_msm.skip_empty_send());

        let apq = Box::new(MockBackend::new().with_product_name("APQ8084"));
        let conn_apq = OdinConnection::new(apq);
        assert!(conn_apq.skip_empty_send());

        let generic = Box::new(MockBackend::new().with_product_name("SAMSUNG_Android"));
        let conn_generic = OdinConnection::new(generic);
        assert!(conn_generic.skip_empty_send());

        let none = Box::new(MockBackend::new());
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

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl UsbTransfer for SpyTransfer {
        async fn reset(&mut self) {}
        async fn send(&mut self, data: &[u8], _timeout: Duration) -> Result<(), TransportError> {
            self.inner.lock().unwrap().sent_data.push(data.to_vec());
            Ok(())
        }
        async fn receive(
            &mut self,
            data: &mut [u8],
            _timeout: Duration,
        ) -> Result<usize, TransportError> {
            let mut inner = self.inner.lock().unwrap();
            if let Some(packet) = inner.read_queue.pop_front() {
                let len = std::cmp::min(data.len(), packet.len());
                data[..len].copy_from_slice(&packet[..len]);
                Ok(len)
            } else {
                Ok(0)
            }
        }
        fn product_name(&self) -> Option<&str> {
            self.product.as_deref()
        }
    }

    #[test]
    fn test_gadget_serial_sends_empty_packets_after_control_requests() {
        futures::executor::block_on(async {
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
                slice_timeout: COMMAND_TIMEOUT,
                lz4_supported: false,
                bootloader_protocol_version: 2,
            };

            // 1. Control request packet -> must send 1024 bytes followed by 0 bytes (ZLP)
            let req = Command::begin_session();
            assert!(session.send_command(&req, HANDSHAKE_TIMEOUT).await.is_ok());

            {
                let inner = spy_inner.lock().unwrap();
                assert_eq!(inner.sent_data.len(), 2);
                assert_eq!(inner.sent_data[0].len(), 1024);
                assert_eq!(inner.sent_data[1].len(), 0); // ZLP
            }

            // 2. Data chunk -> must send raw chunk bytes with NO ZLP
            let chunk_data = vec![0xABu8; 1024];
            let chunk = DataChunk::new(&chunk_data, chunk_data.len());
            assert!(session.send_chunk(&chunk, HANDSHAKE_TIMEOUT).await.is_ok());

            {
                let inner = spy_inner.lock().unwrap();
                assert_eq!(inner.sent_data.len(), 3);
                assert_eq!(inner.sent_data[2].len(), 1024);
            }

            // 3. Reboot device -> must send reboot packet with trailing ZLP
            assert!(session.reboot_device().await.is_ok());
            {
                let inner = spy_inner.lock().unwrap();
                assert_eq!(inner.sent_data.len(), 5);
                assert_eq!(inner.sent_data[3].len(), 1024);
                assert_eq!(inner.sent_data[4].len(), 0); // trailing ZLP for reboot on S10!
            }
        });
    }

    #[test]
    fn test_non_gadget_serial_skips_empty_packets() {
        futures::executor::block_on(async {
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
                slice_timeout: COMMAND_TIMEOUT,
                lz4_supported: false,
                bootloader_protocol_version: 2,
            };

            // 1. Control request packet -> only sends 1024 bytes, no ZLP
            let req = Command::begin_session();
            assert!(session.send_command(&req, HANDSHAKE_TIMEOUT).await.is_ok());

            {
                let inner = spy_inner.lock().unwrap();
                assert_eq!(inner.sent_data.len(), 1);
                assert_eq!(inner.sent_data[0].len(), 1024);
            }

            // 2. Reboot device -> sends 1024 bytes, no ZLP
            assert!(session.reboot_device().await.is_ok());
            {
                let inner = spy_inner.lock().unwrap();
                assert_eq!(inner.sent_data.len(), 2);
                assert_eq!(inner.sent_data[1].len(), 1024);
            }
        });
    }

    #[test]
    fn test_receive_response_retry_on_zero_length_packet() {
        futures::executor::block_on(async {
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
                slice_timeout: COMMAND_TIMEOUT,
                lz4_supported: false,
                bootloader_protocol_version: 2,
            };

            let response = session
                .receive_response(HANDSHAKE_TIMEOUT)
                .await
                .expect("Should retry after 0-byte packet and receive response");
            assert_eq!(response.response_type, CMD_SESSION_INIT);
            assert_eq!(response.value, 0);
        });
    }

    #[test]
    fn test_handshake_recovers_from_queued_fail_response() {
        futures::executor::block_on(async {
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
            assert!(conn.init().await.is_ok());

            let inner = spy_inner.lock().unwrap();
            assert_eq!(inner.sent_data.len(), 1);
            assert_eq!(inner.sent_data[0], b"ODIN");
        });
    }
}
