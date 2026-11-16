// Copyright 2026 John "topjohnwu" Wu
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

//! High-fidelity mock transport mimicking the Samsung Odin/Loke download mode protocol
//! backed by reverse-engineered ground truth from real device bootloaders.

use crate::compat::MaybeSend;
use crate::error::TransportError;
use crate::protocol::{
    CMD_CLOSE_CONNECTION, CMD_DDP, CMD_DEVINFO, CMD_PIT, CMD_SESSION_INIT, CMD_TRANSMIT,
    CloseConnectionCommand, Command, DeviceInfoCommand, DynamicPartitionCommand, PitCommand,
    STATUS_FAIL, STREAMING_CHUNK_ACK, SessionCommand, TransmitCommand,
};
use crate::usb::{UsbBackend, UsbTransfer};
use binrw::BinRead;
use std::collections::VecDeque;
use std::future::Future;
use std::io::Cursor;
use std::pin::Pin;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

/// Returns `Pending` once before completing, waking itself immediately, like
/// an I/O operation that completes right away.
pub(crate) fn yield_now() -> impl Future<Output = ()> {
    struct YieldNow(bool);

    impl Future for YieldNow {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                return Poll::Ready(());
            }
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    YieldNow(false)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Uninitialized,
    HandshakeComplete,
    SessionBegun,
    TransmitFlash,
    TransmitSlice,
    PitFlash,
}

/// A device-visible operation recorded by [`MockBackend`].
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MockEvent {
    /// USERDATA NAND erase.
    NandErase,
    /// PIT uploaded to the device.
    PitFlash,
    /// PIT dumped from the device.
    PitDump,
    /// CSC / sales code set on the device.
    SalesCode(String),
    /// A committed slice (raw or LZ4-compressed bytes as sent) for a partition.
    Slice {
        /// The numeric partition ID targeted by the slice.
        partition_id: u32,
        /// Whether the payload was sent with LZ4 compression.
        lz4: bool,
        /// Whether the slice was committed as the last one of the partition.
        last: bool,
        /// The received payload data, truncated to the announced slice size.
        data: Vec<u8>,
    },
    /// Session ended successfully (0x67, subcommand 0).
    EndSession,
    /// Reboot into normal mode requested (0x67, subcommand 1).
    Reboot,
    /// Reboot into Download Mode requested (0x67, subcommand 2).
    RebootToDownload,
}

/// Target hardware, partition table, and protocol characteristics of a simulated Samsung device.
#[derive(Debug)]
pub(crate) struct DeviceProfile {
    /// Device model string (e.g. `"SM-F968B"` or `"GT-I9305"`).
    pub(crate) model: String,
    /// Bootloader / PDA firmware build version string (e.g. `"F968BXXS7BZH3"` or `"I9305XXUEML8"`).
    pub(crate) build_version: String,
    /// Unique hardware serial number / UN string.
    pub(crate) serial_number: String,
    /// Storage Card Identification (CID) register hex string.
    pub(crate) storage_cid: String,
    /// Storage medium declared capacity in gigabytes.
    pub(crate) storage_capacity_gb: u32,
    /// Storage manufacturer / vendor name.
    pub(crate) storage_vendor: String,
    /// Storage firmware revision.
    pub(crate) storage_firmware_version: String,
    /// Storage hardware product name.
    pub(crate) storage_product_name: String,
    /// Security provisioning status flag string.
    pub(crate) provisioning_status: String,
    /// Default factory CSC / sales code.
    pub(crate) default_sales_code: String,
    /// Thermal sensor reading in Celsius.
    pub(crate) temperature_c: i32,
    /// USB device product string descriptor.
    pub(crate) usb_product_name: Option<String>,
    /// Maximum supported Odin protocol version (2 for legacy, 3 for modern).
    pub(crate) protocol_version: u32,
    /// Whether LZ4 compressed streaming is supported.
    pub(crate) lz4_supported: bool,
    /// Default packet transfer chunk size in bytes.
    pub(crate) default_packet_size: usize,
    /// Available capacity on the dynamic `super` partition in bytes.
    pub(crate) super_partition_free_space: u64,
    /// Whether the pre-handshake `DVIF` diagnostic query is recognized.
    pub(crate) supports_dvif: bool,
    /// Whether in-session binary `DeviceInfo` (Opcode 0x69) is supported.
    pub(crate) supports_device_info: bool,
    /// Whether pre-flight dynamic partition sizing (Opcode 0x6a) is supported.
    pub(crate) supports_dynamic_partition: bool,
    /// Embedded default Partition Information Table (PIT) image.
    pub(crate) default_pit: Vec<u8>,
}

impl DeviceProfile {
    /// Profile for modern Samsung flagship devices based on Galaxy Z TriFold (`SM-F968B`).
    ///
    /// Extracted directly from `BL_F968BXXS7BZH3` (`abl_odin.efi`) and `Q7MQ_EUR_OPENX.pit`:
    /// - Platform: Qualcomm Snapdragon 8 Elite (`"SM8750"`)
    /// - Storage: UFS 4.0 (`DeviceType::UFS`, 6 LUNs, 4096-byte blocks)
    /// - Protocol: Version 3 with LZ4 compression and 1 MB chunks
    /// - Features: DVIF ASCII diagnostics, binary TLV DeviceInfo (0x69), Super size check (0x6a)
    /// - USB: Skips ZLP empty packets
    pub(crate) fn sm_f968b() -> Self {
        Self {
            model: "SM-F968B".to_string(),
            build_version: "F968BXXS7BZH3".to_string(),
            serial_number: "C1A2B3C4".to_string(),
            storage_cid: "1501004b333230340000000000000000".to_string(),
            storage_capacity_gb: 512,
            storage_vendor: "SAMSUNG".to_string(),
            storage_firmware_version: "0800".to_string(),
            storage_product_name: "KLUEG8UHDB".to_string(),
            provisioning_status: "2".to_string(),
            default_sales_code: "TUR".to_string(),
            temperature_c: 32,
            usb_product_name: Some("SAMSUNG_Android".to_string()),
            protocol_version: 3,
            lz4_supported: true,
            default_packet_size: 0x20000,
            super_partition_free_space: 0x2_0000_0000, // 8 GB free in super
            supports_dvif: true,
            supports_device_info: true,
            supports_dynamic_partition: true,
            default_pit: include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-data/Q7MQ_EUR_OPENX.pit"
            ))
            .to_vec(),
        }
    }

    /// Profile for legacy Samsung Exynos devices based on Galaxy S3 LTE (`GT-I9305`).
    ///
    /// Extracted directly from `BL_I9305XXUEML8` (`sboot.bin`) and `M3_EUR_OPEN_4G.pit`:
    /// - Platform: Samsung Exynos 4412 + MDM9215 (`"Mx-MDM"`)
    /// - Storage: eMMC (`DeviceType::MMC`, flat storage, 512-byte blocks)
    /// - Protocol: Version 2, uncompressed raw chunks only, 128 KB packets
    /// - Features: No DVIF, no Opcode 0x69, no Opcode 0x6a, requires `LegacyModem` layout for CP
    /// - USB: Reports `"Gadget Serial"` product descriptor (triggers ZLP empty sends)
    #[cfg(test)]
    pub(crate) fn gt_i9305() -> Self {
        Self {
            model: "GT-I9305".to_string(),
            build_version: "I9305XXUEML8".to_string(),
            serial_number: "41290bc0".to_string(),
            storage_cid: "1501004d300000000000000000000000".to_string(),
            storage_capacity_gb: 16,
            storage_vendor: "SAMSUNG".to_string(),
            storage_firmware_version: "0001".to_string(),
            storage_product_name: "MAG2GA".to_string(),
            provisioning_status: "1".to_string(),
            default_sales_code: "BTU".to_string(),
            temperature_c: 28,
            usb_product_name: Some("Gadget Serial".to_string()),
            protocol_version: 2,
            lz4_supported: false,
            default_packet_size: 0x20000,
            super_partition_free_space: 0,
            supports_dvif: false,
            supports_device_info: false,
            supports_dynamic_partition: false,
            default_pit: include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-data/M3_EUR_OPEN_4G.pit"
            ))
            .to_vec(),
        }
    }

    /// Formats the simulated pre-handshake DVIF diagnostic response string.
    fn dvif_string(&self) -> String {
        format!(
            "@#MODEL={};UN={};CAPA={};VENDOR={};FWVER={};PRODUCT={};PROV={};SALES={};VER={};TMU_TEMP={};",
            self.model,
            self.serial_number,
            self.storage_capacity_gb,
            self.storage_vendor,
            self.storage_firmware_version,
            self.storage_product_name,
            self.provisioning_status,
            self.default_sales_code,
            self.build_version,
            self.temperature_c,
        )
    }

    /// Generates binary TLV device information encoded according to Opcode 0x69 specifications.
    fn binary_device_info(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x12345678u32.to_le_bytes()); // magic
        data.extend_from_slice(&3u32.to_le_bytes()); // 3 entries

        // Entry 0: Tag 0 (Model), offset 36 (abs 44), len 32
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&36u32.to_le_bytes());
        data.extend_from_slice(&32u32.to_le_bytes());

        // Entry 1: Tag 1 (UN/CID), offset 68 (abs 76), len 36
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&68u32.to_le_bytes());
        data.extend_from_slice(&36u32.to_le_bytes());

        // Entry 2: Tag 2 (Sales Code), offset 104 (abs 112), len 4
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&104u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());

        let mut model_bytes = self.model.as_bytes().to_vec();
        model_bytes.push(0);
        model_bytes.resize(32, 0);
        data.extend_from_slice(&model_bytes);

        let mut cid_bytes = self.storage_cid.as_bytes().to_vec();
        cid_bytes.push(0);
        cid_bytes.resize(36, 0);
        data.extend_from_slice(&cid_bytes);

        let mut sc_bytes = self.default_sales_code.as_bytes().to_vec();
        sc_bytes.push(0);
        sc_bytes.resize(4, 0);
        data.extend_from_slice(&sc_bytes);

        data
    }
}

/// A mock USB/serial transport backend that implements the Loke-Odin protocol,
/// capable of accurately simulating different Samsung device generations.
///
/// Like real USB transfers, every send and receive returns `Pending` once
/// before completing.
pub(crate) struct MockBackend {
    profile: DeviceProfile,
    state: State,
    incoming_buffer: Vec<u8>,
    outgoing_queue: VecDeque<u8>,
    current_chunk_index: u32,
    packet_size: usize,
    active_pit_data: Vec<u8>,
    current_partition_bytes: usize,
    #[cfg(test)]
    fail_end_session: Option<i32>,
    #[cfg(test)]
    fail_check_super_size: Option<i32>,
    protocol_version: u32,
    #[cfg(test)]
    product_override: Option<String>,
    #[cfg(test)]
    event_log: Arc<Mutex<Vec<MockEvent>>>,
    #[cfg(test)]
    received_chunks: Arc<AtomicUsize>,
    #[cfg(test)]
    current_slice_announced_size: Option<usize>,
    #[cfg(test)]
    current_slice_data: Vec<u8>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    /// Instantiates a new `MockBackend` configured with default `SM-F968B` characteristics.
    ///
    /// For 100% backward compatibility with existing tests, `protocol_version` defaults to 2.
    pub(crate) fn new() -> Self {
        let mut backend = Self::with_profile(DeviceProfile::sm_f968b());
        backend.protocol_version = 2;
        backend
    }

    /// Instantiates a new `MockBackend` configured with a specific `DeviceProfile`.
    pub(crate) fn with_profile(profile: DeviceProfile) -> Self {
        let active_pit = profile.default_pit.clone();
        let default_packet = profile.default_packet_size;
        let p_ver = profile.protocol_version;

        Self {
            profile,
            state: State::Uninitialized,
            incoming_buffer: Vec::new(),
            outgoing_queue: VecDeque::new(),
            current_chunk_index: 0,
            packet_size: default_packet,
            active_pit_data: active_pit,
            current_partition_bytes: 0,
            #[cfg(test)]
            fail_end_session: None,
            #[cfg(test)]
            fail_check_super_size: None,
            protocol_version: p_ver,
            #[cfg(test)]
            product_override: None,
            #[cfg(test)]
            event_log: Arc::new(Mutex::new(Vec::new())),
            #[cfg(test)]
            received_chunks: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            current_slice_announced_size: None,
            #[cfg(test)]
            current_slice_data: Vec::new(),
        }
    }

    /// Returns a handle to the log of device-visible events, shared with clones of the handle.
    #[cfg(test)]
    pub(crate) fn event_log(&self) -> Arc<Mutex<Vec<MockEvent>>> {
        Arc::clone(&self.event_log)
    }

    /// Returns a handle to the number of slice data chunks acknowledged so far,
    /// shared with clones of the handle.
    #[cfg(test)]
    pub(crate) fn received_chunks(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.received_chunks)
    }

    /// Sets an override for the simulated USB product name descriptor.
    #[cfg(test)]
    pub(crate) fn with_product_name(mut self, product: &str) -> Self {
        self.product_override = Some(product.to_string());
        self
    }

    /// Sets the bootloader protocol version reported by the mock device.
    #[cfg(test)]
    pub(crate) fn with_protocol_version(mut self, version: u32) -> Self {
        self.protocol_version = version;
        self
    }

    /// Injects an error status on end session.
    #[cfg(test)]
    pub(crate) fn with_fail_end_session(mut self, status: i32) -> Self {
        self.fail_end_session = Some(status);
        self
    }

    /// Injects an error status on dynamic partition pre-flight check.
    #[cfg(test)]
    pub(crate) fn with_fail_check_super_size(mut self, status: i32) -> Self {
        self.fail_check_super_size = Some(status);
        self
    }

    #[cfg(test)]
    fn has_event_listener(&self) -> bool {
        Arc::strong_count(&self.event_log) > 1
    }

    #[cfg(test)]
    fn record_event(&self, event: MockEvent) {
        if self.has_event_listener() {
            self.event_log.lock().unwrap().push(event);
        }
    }

    fn push_response(&mut self, response_type: u32, value: u32) {
        print_verbose!(
            "MockBackend: queueing response: response_type = {:#04X?}, value = {}",
            response_type,
            value
        );
        self.outgoing_queue.extend(&response_type.to_le_bytes());
        self.outgoing_queue.extend(&value.to_le_bytes());
    }
}

/// The mock device is always connected, so every lookup finds it regardless
/// of the requested mode, and opening it yields a fresh default mock.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl UsbBackend for MockBackend {
    type UsbDevice = ();

    async fn new(_device: Self::UsbDevice) -> Result<Self, TransportError> {
        Ok(Self::new())
    }

    async fn find_device<'a, F>(_predicate: F) -> Result<Self::UsbDevice, TransportError>
    where
        F: FnMut(u16, u16) -> bool + MaybeSend + 'a,
    {
        Ok(())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl UsbTransfer for MockBackend {
    async fn reset(&mut self) {
        print_verbose!("MockBackend: connection reset");
        self.state = State::Uninitialized;
        self.incoming_buffer.clear();
        self.outgoing_queue.clear();
        self.current_chunk_index = 0;
        self.packet_size = self.profile.default_packet_size;
        #[cfg(test)]
        {
            self.current_slice_announced_size = None;
            self.current_slice_data.clear();
        }
    }

    async fn send(&mut self, data: &[u8], _timeout: Duration) -> Result<(), TransportError> {
        yield_now().await;
        if data.is_empty() {
            return Ok(());
        }

        self.incoming_buffer.extend_from_slice(data);

        match self.state {
            State::Uninitialized => {
                if self.incoming_buffer == b"DVIF" {
                    print_verbose!("MockBackend: Received DVIF query");
                    if self.profile.supports_dvif {
                        let dvif = self.profile.dvif_string();
                        self.outgoing_queue.extend(dvif.as_bytes());
                    } else {
                        print_verbose!(
                            "MockBackend: DVIF not supported by device profile, ignoring"
                        );
                    }
                    self.incoming_buffer.clear();
                } else if self.incoming_buffer == b"ODIN" {
                    print_verbose!("MockBackend: Handshake matching ODIN -> LOKE");
                    self.state = State::HandshakeComplete;
                    self.outgoing_queue.extend(b"LOKE");
                    self.incoming_buffer.clear();
                }
            }
            State::HandshakeComplete
            | State::SessionBegun
            | State::TransmitFlash
            | State::TransmitSlice
            | State::PitFlash => {
                // If we are transmitting partition file chunks, consume raw
                // bytes of `packet_size` size.
                if self.state == State::TransmitSlice
                    && self.incoming_buffer.len() >= self.packet_size
                {
                    let chunk_size = self.packet_size;
                    print_verbose!(
                        "MockBackend: Received chunk of {} bytes (idx: {})",
                        chunk_size,
                        self.current_chunk_index
                    );
                    self.current_partition_bytes += chunk_size;
                    #[cfg(test)]
                    {
                        if self.has_event_listener() {
                            self.current_slice_data
                                .extend_from_slice(&self.incoming_buffer[..chunk_size]);
                        }
                        self.received_chunks.fetch_add(1, Ordering::Relaxed);
                    }
                    self.push_response(STREAMING_CHUNK_ACK, self.current_chunk_index);
                    self.current_chunk_index += 1;
                    self.incoming_buffer.drain(..chunk_size);
                    return Ok(());
                }

                // If we are receiving uploaded PIT bytes
                if self.state == State::PitFlash && !self.incoming_buffer.is_empty() {
                    // Check if the buffer is a 1024-byte control packet or raw PIT binary
                    if self.incoming_buffer.len() >= 1024 {
                        let mut cursor = Cursor::new(&self.incoming_buffer[..1024]);
                        if let Ok(cmd) = Command::read_le(&mut cursor) {
                            match cmd {
                                Command::Pit(PitCommand::Slice { .. }) => {
                                    self.push_response(CMD_PIT, 0);
                                    self.incoming_buffer.drain(..1024);
                                    return Ok(());
                                }
                                Command::Pit(PitCommand::End { .. }) => {
                                    self.state = State::SessionBegun;
                                    self.push_response(CMD_PIT, 0);
                                    self.incoming_buffer.drain(..1024);
                                    return Ok(());
                                }
                                _ => {}
                            }
                        }
                    }

                    // Otherwise append raw PIT bytes
                    let raw_bytes = std::mem::take(&mut self.incoming_buffer);
                    self.active_pit_data.extend_from_slice(&raw_bytes);
                    self.push_response(CMD_PIT, 0);
                    return Ok(());
                }

                // Parse standard 1024-byte control packets
                if self.incoming_buffer.len() >= 1024 {
                    let mut cursor = Cursor::new(&self.incoming_buffer[..1024]);
                    if let Ok(cmd) = Command::read_le(&mut cursor) {
                        print_verbose!("MockBackend: Received command: {:?}", cmd);
                        match cmd {
                            Command::Session(session_cmd) => match session_cmd {
                                SessionCommand::Begin { protocol_version } => {
                                    self.state = State::SessionBegun;
                                    let negotiated = self.protocol_version.min(protocol_version);
                                    let lz4_bit = if self.profile.lz4_supported {
                                        0x8000
                                    } else {
                                        0
                                    };
                                    let response_val = (negotiated << 16) | lz4_bit;
                                    self.push_response(CMD_SESSION_INIT, response_val);
                                }
                                SessionCommand::PacketSize { size } => {
                                    self.packet_size = size as usize;
                                    self.push_response(CMD_SESSION_INIT, 0);
                                }
                                SessionCommand::SalesCode { c0, c1, c2 } => {
                                    #[cfg(test)]
                                    {
                                        let code = [c0, c1, c2].map(|c| char::from(c as u8));
                                        self.record_event(MockEvent::SalesCode(
                                            code.iter().collect(),
                                        ));
                                    }
                                    #[cfg(not(test))]
                                    let _ = (c0, c1, c2);
                                    self.push_response(CMD_SESSION_INIT, 0);
                                }
                                SessionCommand::NandErase => {
                                    #[cfg(test)]
                                    self.record_event(MockEvent::NandErase);
                                    self.push_response(CMD_SESSION_INIT, 524_288);
                                }
                                _ => {
                                    self.push_response(CMD_SESSION_INIT, 0);
                                }
                            },
                            Command::Pit(pit_cmd) => match pit_cmd {
                                PitCommand::Flash => {
                                    self.state = State::PitFlash;
                                    self.active_pit_data.clear();
                                    #[cfg(test)]
                                    self.record_event(MockEvent::PitFlash);
                                    self.push_response(CMD_PIT, 0);
                                }
                                PitCommand::Dump => {
                                    #[cfg(test)]
                                    self.record_event(MockEvent::PitDump);
                                    self.push_response(CMD_PIT, self.active_pit_data.len() as u32);
                                }
                                PitCommand::Slice { slice } => {
                                    let offset = slice as usize * 500;
                                    let end = (offset + 500).min(self.active_pit_data.len());
                                    if offset < self.active_pit_data.len() {
                                        self.outgoing_queue
                                            .extend(&self.active_pit_data[offset..end]);
                                    }
                                }
                                _ => {
                                    self.push_response(CMD_PIT, 0);
                                }
                            },
                            Command::Transmit(transmit_cmd) => match transmit_cmd {
                                TransmitCommand::Flash | TransmitCommand::Lz4Flash => {
                                    self.state = State::TransmitFlash;
                                    self.current_partition_bytes = 0;
                                    self.push_response(CMD_TRANSMIT, 0);
                                }
                                TransmitCommand::Slice { .. } => {
                                    self.state = State::TransmitSlice;
                                    self.current_chunk_index = 0;
                                    #[cfg(test)]
                                    {
                                        self.current_slice_announced_size = None;
                                        self.current_slice_data.clear();
                                    }
                                    self.push_response(CMD_TRANSMIT, 0);
                                }
                                TransmitCommand::Lz4Slice {
                                    compressed_size, ..
                                } => {
                                    self.state = State::TransmitSlice;
                                    self.current_chunk_index = 0;
                                    #[cfg(test)]
                                    {
                                        self.current_slice_announced_size =
                                            Some(compressed_size as usize);
                                        self.current_slice_data.clear();
                                    }
                                    #[cfg(not(test))]
                                    let _ = compressed_size;
                                    self.push_response(CMD_TRANSMIT, 0);
                                }
                                #[cfg_attr(not(test), allow(unused_variables))]
                                TransmitCommand::End(ref commit)
                                | TransmitCommand::Lz4End(ref commit) => {
                                    #[cfg(test)]
                                    if self.has_event_listener() {
                                        let partition_id = commit.partition_id();
                                        let lz4 =
                                            matches!(&transmit_cmd, TransmitCommand::Lz4End(_));
                                        // The raw slice size announced at the start is rounded
                                        // up to 128 KB, so use the exact size from the commit.
                                        // LZ4 commits carry the decompressed size instead, so
                                        // use the announced compressed size for those.
                                        let payload_size = if lz4 {
                                            self.current_slice_announced_size
                                                .unwrap_or(self.current_slice_data.len())
                                        } else {
                                            commit.slice_size() as usize
                                        };
                                        let mut data = std::mem::take(&mut self.current_slice_data);
                                        data.truncate(payload_size);
                                        self.record_event(MockEvent::Slice {
                                            partition_id,
                                            lz4,
                                            last: commit.is_end_of_file(),
                                            data,
                                        });
                                    }

                                    self.current_partition_bytes = 0;
                                    self.state = State::SessionBegun;
                                    self.push_response(CMD_TRANSMIT, 0);
                                }
                            },
                            Command::CloseConnection(close_cmd) => match close_cmd {
                                CloseConnectionCommand::Close => {
                                    #[cfg(test)]
                                    if let Some(err) = self.fail_end_session {
                                        self.push_response(STATUS_FAIL, err as u32);
                                        self.incoming_buffer.drain(..1024);
                                        return Ok(());
                                    }
                                    self.state = State::HandshakeComplete;
                                    #[cfg(test)]
                                    self.record_event(MockEvent::EndSession);
                                    self.push_response(CMD_CLOSE_CONNECTION, 0);
                                }
                                CloseConnectionCommand::RebootDevice => {
                                    self.state = State::Uninitialized;
                                    #[cfg(test)]
                                    self.record_event(MockEvent::Reboot);
                                }
                                CloseConnectionCommand::RebootDownload => {
                                    self.state = State::Uninitialized;
                                    #[cfg(test)]
                                    self.record_event(MockEvent::RebootToDownload);
                                }
                            },
                            Command::DynamicPartition(dp_cmd) => {
                                if !self.profile.supports_dynamic_partition {
                                    // S-Boot 4.0 does not recognize Opcode 0x6a -> returns FAIL
                                    self.push_response(STATUS_FAIL, 0xffff_ffff);
                                } else {
                                    match dp_cmd {
                                        DynamicPartitionCommand::CheckSuperSize {
                                            super_used_size,
                                        } => {
                                            #[cfg(test)]
                                            if let Some(err) = self.fail_check_super_size {
                                                self.push_response(STATUS_FAIL, err as u32);
                                                self.incoming_buffer.drain(..1024);
                                                return Ok(());
                                            }
                                            if super_used_size as u64
                                                > self.profile.super_partition_free_space
                                            {
                                                self.push_response(STATUS_FAIL, 0xffff_ffff);
                                            } else {
                                                self.push_response(CMD_DDP, 0);
                                            }
                                        }
                                    }
                                }
                            }
                            Command::DeviceInfo(info_cmd) => {
                                if !self.profile.supports_device_info {
                                    // Opcode 0x69 undefined on legacy bootloaders -> returns FAIL
                                    self.push_response(STATUS_FAIL, 0xffff_ffff);
                                } else {
                                    match info_cmd {
                                        DeviceInfoCommand::Dump => {
                                            let info = self.profile.binary_device_info();
                                            self.push_response(CMD_DEVINFO, info.len() as u32);
                                        }
                                        DeviceInfoCommand::Slice { slice } => {
                                            let info = self.profile.binary_device_info();
                                            let offset = slice as usize * 500;
                                            let end = (offset + 500).min(info.len());
                                            if offset < info.len() {
                                                self.outgoing_queue.extend(&info[offset..end]);
                                            }
                                        }
                                        DeviceInfoCommand::End => {
                                            self.push_response(CMD_DEVINFO, 0);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    self.incoming_buffer.drain(..1024);
                }
            }
        }
        Ok(())
    }

    async fn receive(
        &mut self,
        data: &mut [u8],
        _timeout: Duration,
    ) -> Result<usize, TransportError> {
        yield_now().await;
        let size = std::cmp::min(data.len(), self.outgoing_queue.len());
        for item in data.iter_mut().take(size) {
            *item = self.outgoing_queue.pop_front().unwrap();
        }
        Ok(size)
    }

    fn product_name(&self) -> Option<&str> {
        #[cfg(test)]
        if let Some(product) = &self.product_override {
            return Some(product);
        }
        self.profile.usb_product_name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::OdinError;
    use crate::session::OdinConnection;
    use samloader_pit::{BinaryType, PitData};

    #[test]
    fn test_sm_f968b_modern_profile_lifecycle() {
        futures::executor::block_on(async {
            let profile = DeviceProfile::sm_f968b();
            let mut connection = OdinConnection::open(Box::new(MockBackend::with_profile(profile)));

            // 1. DVIF diagnostics prior to begin_session
            let info = connection.query_device_info().await.unwrap();
            assert_eq!(info.model.as_deref(), Some("SM-F968B"));
            assert_eq!(info.storage_capacity_gb, Some(512));
            assert_eq!(info.storage_vendor.as_deref(), Some("SAMSUNG"));
            assert_eq!(info.storage_product_name.as_deref(), Some("KLUEG8UHDB"));
            assert_eq!(info.sales_code.as_deref(), Some("TUR"));

            // 2. Handshake & Begin Session (protocol v3, LZ4 supported)
            let mut session = connection.begin_session().await.unwrap();
            assert_eq!(session.bootloader_protocol_version(), 3);
            assert!(session.is_lz4_supported());

            // 3. Download PIT (Q7MQ_EUR_OPENX.pit is 18492 bytes)
            let pit_bytes = session.receive_pit_info().await.unwrap();
            assert_eq!(pit_bytes.len(), 18492);
            let pit = PitData::new(&pit_bytes).unwrap();
            assert_eq!(pit.cpu_bl_id.to_string_lossy(), "SM8750");

            // 4. Opcode 0x69 in-session DeviceInfo
            let session_info = session.dump_device_info().await.unwrap();
            assert_eq!(session_info.model.as_deref(), Some("SM-F968B"));
            assert_eq!(session_info.sales_code.as_deref(), Some("TUR"));

            // 5. Dynamic partition check
            assert!(session.check_super_size(1024 * 1024 * 100).await.is_ok());

            // 6. Session close
            let _ = session.close().await.unwrap();
        });
    }

    #[test]
    fn test_gt_i9305_legacy_profile_lifecycle() {
        futures::executor::block_on(async {
            let profile = DeviceProfile::gt_i9305();
            let mut connection = OdinConnection::open(Box::new(MockBackend::with_profile(profile)));

            // 1. DVIF is NOT supported on legacy S-Boot -> query_device_info returns DeviceInfoUnavailable
            let err = connection.query_device_info().await.unwrap_err();
            assert!(matches!(err, OdinError::DeviceInfoUnavailable));

            // 2. Handshake & Begin session -> negotiates protocol v2, LZ4 disabled
            let mut session = connection.begin_session().await.unwrap();
            assert_eq!(session.bootloader_protocol_version(), 2);
            assert!(!session.is_lz4_supported());

            // 3. Download PIT (M3_EUR_OPEN_4G.pit is 2924 bytes, 20 entries)
            let pit_bytes = session.receive_pit_info().await.unwrap();
            assert_eq!(pit_bytes.len(), 2924);
            let pit = PitData::new(&pit_bytes).unwrap();
            assert_eq!(pit.cpu_bl_id.to_string_lossy(), "Mx-MDM");
            assert_eq!(pit.entries.len(), 20);

            // Verify key partitions from sboot / M3 PIT
            let modem_entry = pit.find_entry_by_name("RADIO").expect("RADIO entry");
            assert_eq!(modem_entry.partition_id, 10);
            assert_eq!(modem_entry.binary_type, BinaryType::ApplicationProcessor);

            // 4. In-session DeviceInfo (0x69) is rejected on legacy bootloader
            assert!(session.dump_device_info().await.is_err());

            // 5. Dynamic partition check (0x6a) is rejected on legacy bootloader
            assert!(session.check_super_size(1024).await.is_err());

            // 6. Close session
            let _ = session.close().await.unwrap();
        });
    }
}
