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

use crate::packets::{
    RESPONSE_TYPE_DEVICE_INFO, RESPONSE_TYPE_DYNAMIC_PARTITION, RESPONSE_TYPE_END_SESSION,
    RESPONSE_TYPE_FAIL, RESPONSE_TYPE_FILE_TRANSFER, RESPONSE_TYPE_PIT_FILE,
    RESPONSE_TYPE_SEND_FILE_PART, RESPONSE_TYPE_SESSION_SETUP, RequestPacket,
};
use crate::usb::UsbTransfer;
use binrw::BinRead;
use samloader_pit::PitData;
use std::collections::VecDeque;
use std::io::Cursor;

/// Simulated device reboot destination mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootMode {
    /// Standard normal Android boot.
    Normal,
    /// Recovery mode (e.g. triggered by Sprint RTN provisioning reset).
    Recovery,
    /// Re-enter download mode.
    Download,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Uninitialized,
    HandshakeComplete,
    SessionBegun,
    FileTransferFlash,
    FileTransferPart,
    PitFileFlash,
}

/// Target hardware, partition table, and protocol characteristics of a simulated Samsung device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProfile {
    /// Device model string (e.g. `"SM-F968B"` or `"GT-I9305"`).
    pub model: String,
    /// Target CPU / platform identifier declared in the PIT header (e.g. `"SM8750"` or `"Mx-MDM"`).
    pub cpu_bl_id: String,
    /// Bootloader / PDA firmware build version string (e.g. `"F968BXXS7BZH3"` or `"I9305XXUEML8"`).
    pub build_version: String,
    /// Unique hardware serial number / UN string.
    pub serial_number: String,
    /// Storage Card Identification (CID) register hex string.
    pub storage_cid: String,
    /// Storage medium declared capacity in gigabytes.
    pub storage_capacity_gb: u32,
    /// Storage manufacturer / vendor name.
    pub storage_vendor: String,
    /// Storage firmware revision.
    pub storage_firmware_version: String,
    /// Storage hardware product name.
    pub storage_product_name: String,
    /// Security provisioning status flag string.
    pub provisioning_status: String,
    /// Default factory CSC / sales code.
    pub default_sales_code: String,
    /// Thermal sensor reading in Celsius.
    pub temperature_c: i32,
    /// USB device product string descriptor.
    pub usb_product_name: Option<String>,
    /// Maximum supported Odin protocol version (2 for legacy, 3 for modern).
    pub protocol_version: u32,
    /// Whether LZ4 compressed streaming is supported.
    pub lz4_supported: bool,
    /// Default packet transfer chunk size in bytes.
    pub default_packet_size: usize,
    /// Maximum allowed packet transfer chunk size in bytes.
    pub max_packet_size: usize,
    /// Available capacity on the dynamic `super` partition in bytes.
    pub super_partition_free_space: u64,
    /// Whether the pre-handshake `DVIF` diagnostic query is recognized.
    pub supports_dvif: bool,
    /// Whether in-session binary `DeviceInfo` (Opcode 0x69) is supported.
    pub supports_device_info: bool,
    /// Whether pre-flight dynamic partition sizing (Opcode 0x6a) is supported.
    pub supports_dynamic_partition: bool,
    /// Embedded default Partition Information Table (PIT) image.
    pub default_pit: Vec<u8>,
}

#[allow(dead_code)]
impl DeviceProfile {
    /// Starts a builder initialized with the modern Galaxy Z TriFold (`SM-F968B`) profile.
    pub fn builder() -> DeviceProfileBuilder {
        DeviceProfileBuilder {
            profile: Self::sm_f968b(),
        }
    }

    /// Profile for modern Samsung flagship devices based on Galaxy Z TriFold (`SM-F968B`).
    ///
    /// Extracted directly from `BL_F968BXXS7BZH3` (`abl_odin.efi`) and `Q7MQ_EUR_OPENX.pit`:
    /// - Platform: Qualcomm Snapdragon 8 Elite (`"SM8750"`)
    /// - Storage: UFS 4.0 (`DeviceType::UFS`, 6 LUNs, 4096-byte blocks)
    /// - Protocol: Version 3 with LZ4 compression and 1 MB chunks
    /// - Features: DVIF ASCII diagnostics, binary TLV DeviceInfo (0x69), Super size check (0x6a)
    /// - USB: Skips ZLP empty packets
    pub fn sm_f968b() -> Self {
        Self {
            model: "SM-F968B".to_string(),
            cpu_bl_id: "SM8750".to_string(),
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
            max_packet_size: 0x100000,
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
    pub fn gt_i9305() -> Self {
        Self {
            model: "GT-I9305".to_string(),
            cpu_bl_id: "Mx-MDM".to_string(),
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
            max_packet_size: 0x20000,
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
    pub fn dvif_string(&self) -> String {
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
    pub fn binary_device_info(&self) -> Vec<u8> {
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

/// Fluent builder for constructing custom `DeviceProfile` instances.
#[derive(Debug, Clone)]
pub struct DeviceProfileBuilder {
    profile: DeviceProfile,
}

#[allow(dead_code)]
impl DeviceProfileBuilder {
    /// Sets the device model string.
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.profile.model = model.into();
        self
    }

    /// Sets the target platform / CPU identifier.
    pub fn cpu_bl_id(mut self, id: impl Into<String>) -> Self {
        self.profile.cpu_bl_id = id.into();
        self
    }

    /// Sets the firmware build version.
    pub fn build_version(mut self, ver: impl Into<String>) -> Self {
        self.profile.build_version = ver.into();
        self
    }

    /// Sets the hardware serial number.
    pub fn serial_number(mut self, sn: impl Into<String>) -> Self {
        self.profile.serial_number = sn.into();
        self
    }

    /// Sets the storage CID string.
    pub fn storage_cid(mut self, cid: impl Into<String>) -> Self {
        self.profile.storage_cid = cid.into();
        self
    }

    /// Sets the declared storage capacity in gigabytes.
    pub fn storage_capacity_gb(mut self, cap: u32) -> Self {
        self.profile.storage_capacity_gb = cap;
        self
    }

    /// Sets the default sales code.
    pub fn default_sales_code(mut self, code: impl Into<String>) -> Self {
        self.profile.default_sales_code = code.into();
        self
    }

    /// Sets the USB product name descriptor.
    pub fn usb_product_name(mut self, name: Option<String>) -> Self {
        self.profile.usb_product_name = name;
        self
    }

    /// Sets the maximum supported protocol version.
    pub fn protocol_version(mut self, ver: u32) -> Self {
        self.profile.protocol_version = ver;
        self
    }

    /// Sets whether LZ4 compression is supported.
    pub fn lz4_supported(mut self, supported: bool) -> Self {
        self.profile.lz4_supported = supported;
        self
    }

    /// Sets the maximum chunk packet size.
    pub fn max_packet_size(mut self, size: usize) -> Self {
        self.profile.max_packet_size = size;
        self
    }

    /// Sets the available free space on the dynamic super partition.
    pub fn super_partition_free_space(mut self, space: u64) -> Self {
        self.profile.super_partition_free_space = space;
        self
    }

    /// Sets whether pre-handshake DVIF is supported.
    pub fn supports_dvif(mut self, supported: bool) -> Self {
        self.profile.supports_dvif = supported;
        self
    }

    /// Sets whether in-session DeviceInfo (0x69) is supported.
    pub fn supports_device_info(mut self, supported: bool) -> Self {
        self.profile.supports_device_info = supported;
        self
    }

    /// Sets whether dynamic partition verification (0x6a) is supported.
    pub fn supports_dynamic_partition(mut self, supported: bool) -> Self {
        self.profile.supports_dynamic_partition = supported;
        self
    }

    /// Sets the raw default PIT binary data.
    pub fn default_pit(mut self, pit: Vec<u8>) -> Self {
        self.profile.default_pit = pit;
        self
    }

    /// Finalizes and returns the `DeviceProfile`.
    pub fn build(self) -> DeviceProfile {
        self.profile
    }
}

/// A mock USB/serial transport backend that implements the Loke-Odin protocol,
/// capable of accurately simulating different Samsung device generations.
pub struct MockBackend {
    verbose: bool,
    profile: DeviceProfile,
    state: State,
    incoming_buffer: Vec<u8>,
    outgoing_queue: VecDeque<u8>,
    current_part_index: u32,
    packet_size: usize,
    active_pit_data: Vec<u8>,
    parsed_pit: Option<PitData>,
    flashed_partitions: Vec<(u32, usize)>,
    current_partition_bytes: usize,
    fail_begin_session: Option<i32>,
    fail_commit: Option<i32>,
    fail_file_part: Option<i32>,
    fail_end_session: Option<i32>,
    fail_check_super_size: Option<i32>,
    fail_nand_erase: Option<i32>,
    nand_erase_sectors: u32,
    protocol_version: u32,
    last_sales_code: Option<[u8; 3]>,
    sprint_rtn: bool,
    last_reboot_mode: Option<RebootMode>,
    product_override: Option<String>,
    empty_send_count: usize,
    total_bytes_transferred: usize,
    strict_pit_check: bool,
}

#[allow(dead_code)]
impl MockBackend {
    /// Instantiates a new `MockBackend` configured with default `SM-F968B` characteristics.
    ///
    /// For 100% backward compatibility with existing tests, `protocol_version` defaults to 2.
    pub fn new(verbose: bool) -> Self {
        let mut backend = Self::with_profile(DeviceProfile::sm_f968b(), verbose);
        backend.protocol_version = 2;
        backend
    }

    /// Instantiates a new `MockBackend` configured with a specific `DeviceProfile`.
    pub fn with_profile(profile: DeviceProfile, verbose: bool) -> Self {
        let active_pit = profile.default_pit.clone();
        let parsed_pit = PitData::new(&active_pit).ok();
        let default_packet = profile.default_packet_size;
        let p_ver = profile.protocol_version;

        Self {
            verbose,
            profile,
            state: State::Uninitialized,
            incoming_buffer: Vec::new(),
            outgoing_queue: VecDeque::new(),
            current_part_index: 0,
            packet_size: default_packet,
            active_pit_data: active_pit,
            parsed_pit,
            flashed_partitions: Vec::new(),
            current_partition_bytes: 0,
            fail_begin_session: None,
            fail_commit: None,
            fail_file_part: None,
            fail_end_session: None,
            fail_check_super_size: None,
            fail_nand_erase: None,
            nand_erase_sectors: 524_288,
            protocol_version: p_ver,
            last_sales_code: None,
            sprint_rtn: false,
            last_reboot_mode: None,
            product_override: None,
            empty_send_count: 0,
            total_bytes_transferred: 0,
            strict_pit_check: false,
        }
    }

    /// Enables or disables strict PIT project name and TargetID verification.
    pub fn with_strict_pit_check(mut self, strict: bool) -> Self {
        self.strict_pit_check = strict;
        self
    }

    /// Returns a reference to the active `DeviceProfile`.
    pub fn profile(&self) -> &DeviceProfile {
        &self.profile
    }

    /// Sets an override for the simulated USB product name descriptor.
    pub fn with_product_name(mut self, product: &str) -> Self {
        self.product_override = Some(product.to_string());
        self
    }

    /// Returns the number of 0-length bulk packets sent to this backend.
    pub fn empty_send_count(&self) -> usize {
        self.empty_send_count
    }

    /// Returns the last sales code configured via Opcode 0x64 Subcmd 9.
    pub fn last_sales_code(&self) -> Option<[u8; 3]> {
        self.last_sales_code
    }

    /// Returns the final reboot mode requested upon ending the session.
    pub fn last_reboot_mode(&self) -> Option<RebootMode> {
        self.last_reboot_mode
    }

    /// Returns a slice of all partitions flashed during this session: `(target_id, byte_count)`.
    pub fn flashed_partitions(&self) -> &[(u32, usize)] {
        &self.flashed_partitions
    }

    /// Returns the active in-memory PIT representation, if successfully parsed.
    pub fn active_pit(&self) -> Option<&PitData> {
        self.parsed_pit.as_ref()
    }

    /// Returns the cumulative payload bytes received across all partition chunks.
    pub fn total_bytes_transferred(&self) -> usize {
        self.total_bytes_transferred
    }

    /// Sets the bootloader protocol version reported by the mock device.
    pub fn with_protocol_version(mut self, version: u32) -> Self {
        self.protocol_version = version;
        self
    }

    /// Injects an error status on begin session handshake.
    pub fn with_fail_begin_session(mut self, status: i32) -> Self {
        self.fail_begin_session = Some(status);
        self
    }

    /// Injects an error status on slice commit (end sequence packet).
    pub fn with_fail_commit(mut self, status: i32) -> Self {
        self.fail_commit = Some(status);
        self
    }

    /// Injects an error status on file part chunk receipt.
    pub fn with_fail_file_part(mut self, status: i32) -> Self {
        self.fail_file_part = Some(status);
        self
    }

    /// Injects an error status on end session.
    pub fn with_fail_end_session(mut self, status: i32) -> Self {
        self.fail_end_session = Some(status);
        self
    }

    /// Injects an error status on dynamic partition pre-flight check.
    pub fn with_fail_check_super_size(mut self, status: i32) -> Self {
        self.fail_check_super_size = Some(status);
        self
    }

    /// Injects an error status on NAND storage erase request.
    pub fn with_fail_nand_erase(mut self, status: i32) -> Self {
        self.fail_nand_erase = Some(status);
        self
    }

    /// Configures the simulated number of erased sectors returned on NAND erase.
    pub fn with_nand_erase(mut self, sectors: u32) -> Self {
        self.nand_erase_sectors = sectors;
        self
    }

    fn push_response(&mut self, response_type: u32, value: u32) {
        if self.verbose {
            eprintln!(
                "MockBackend: queueing response: response_type = {:#04X?}, value = {}",
                response_type, value
            );
        }
        self.outgoing_queue.extend(&response_type.to_le_bytes());
        self.outgoing_queue.extend(&value.to_le_bytes());
    }
}

impl UsbTransfer for MockBackend {
    fn reset(&mut self) {
        if self.verbose {
            eprintln!("MockBackend: connection reset");
        }
        self.state = State::Uninitialized;
        self.incoming_buffer.clear();
        self.outgoing_queue.clear();
        self.current_part_index = 0;
        self.packet_size = self.profile.default_packet_size;
    }

    fn send_data(&mut self, data: &[u8], _timeout: i32, _retry: bool) -> bool {
        if data.is_empty() {
            self.empty_send_count += 1;
            return true;
        }

        self.incoming_buffer.extend_from_slice(data);

        match self.state {
            State::Uninitialized => {
                if self.incoming_buffer == b"DVIF" {
                    if self.verbose {
                        eprintln!("MockBackend: Received DVIF query");
                    }
                    if self.profile.supports_dvif {
                        let dvif = self.profile.dvif_string();
                        self.outgoing_queue.extend(dvif.as_bytes());
                    } else if self.verbose {
                        eprintln!("MockBackend: DVIF not supported by device profile, ignoring");
                    }
                    self.incoming_buffer.clear();
                } else if self.incoming_buffer == b"ODIN" {
                    if self.verbose {
                        eprintln!("MockBackend: Handshake matching ODIN -> LOKE");
                    }
                    self.state = State::HandshakeComplete;
                    self.outgoing_queue.extend(b"LOKE");
                    self.incoming_buffer.clear();
                }
            }
            State::HandshakeComplete
            | State::SessionBegun
            | State::FileTransferFlash
            | State::FileTransferPart
            | State::PitFileFlash => {
                // If we are transmitting partition file chunks, consume raw
                // bytes of `packet_size` size.
                if self.state == State::FileTransferPart
                    && self.incoming_buffer.len() >= self.packet_size
                {
                    let chunk_size = self.packet_size;
                    if self.verbose {
                        eprintln!(
                            "MockBackend: Received chunk of {} bytes (idx: {})",
                            chunk_size, self.current_part_index
                        );
                    }
                    if let Some(err) = self.fail_file_part {
                        self.push_response(RESPONSE_TYPE_FAIL, err as u32);
                    } else {
                        self.current_partition_bytes += chunk_size;
                        self.total_bytes_transferred += chunk_size;
                        self.push_response(RESPONSE_TYPE_SEND_FILE_PART, self.current_part_index);
                        self.current_part_index += 1;
                    }
                    self.incoming_buffer.drain(..chunk_size);
                    return true;
                }

                // If we are receiving uploaded PIT bytes
                if self.state == State::PitFileFlash && !self.incoming_buffer.is_empty() {
                    // Check if the buffer is a 1024-byte control packet or raw PIT binary
                    if self.incoming_buffer.len() >= 1024 {
                        let mut cursor = Cursor::new(&self.incoming_buffer[..1024]);
                        if let Ok(RequestPacket::PitFile(crate::packets::PitFileRequest::End {
                            ..
                        })) = RequestPacket::read_le(&mut cursor)
                        {
                            if self.strict_pit_check && !self.active_pit_data.is_empty() {
                                match PitData::new(&self.active_pit_data) {
                                    Ok(new_pit) => {
                                        if new_pit.cpu_bl_id != self.profile.cpu_bl_id.as_str() {
                                            self.push_response(RESPONSE_TYPE_FAIL, 0xffff_ffff);
                                            self.incoming_buffer.drain(..1024);
                                            return true;
                                        }
                                        self.parsed_pit = Some(new_pit);
                                    }
                                    Err(_) => {
                                        self.push_response(RESPONSE_TYPE_FAIL, 0xffff_ffff);
                                        self.incoming_buffer.drain(..1024);
                                        return true;
                                    }
                                }
                            } else if !self.active_pit_data.is_empty() {
                                self.parsed_pit = PitData::new(&self.active_pit_data).ok();
                            }
                            self.state = State::SessionBegun;
                            self.push_response(RESPONSE_TYPE_PIT_FILE, 0);
                            self.incoming_buffer.drain(..1024);
                            return true;
                        }
                    }

                    // Otherwise append raw PIT bytes
                    let raw_bytes = std::mem::take(&mut self.incoming_buffer);
                    self.active_pit_data.extend_from_slice(&raw_bytes);
                    self.push_response(RESPONSE_TYPE_PIT_FILE, 0);
                    return true;
                }

                // Parse standard 1024-byte control packets
                if self.incoming_buffer.len() >= 1024 {
                    let mut cursor = Cursor::new(&self.incoming_buffer[..1024]);
                    if let Ok(packet) = RequestPacket::read_le(&mut cursor) {
                        if self.verbose {
                            eprintln!("MockBackend: Received request packet: {:?}", packet);
                        }
                        match packet {
                            RequestPacket::Session(session_req) => match session_req {
                                crate::packets::SessionRequest::Begin { protocol_version } => {
                                    if let Some(err) = self.fail_begin_session {
                                        self.push_response(RESPONSE_TYPE_FAIL, err as u32);
                                    } else {
                                        self.state = State::SessionBegun;
                                        let negotiated =
                                            self.protocol_version.min(protocol_version);
                                        let lz4_bit = if self.profile.lz4_supported {
                                            0x8000
                                        } else {
                                            0
                                        };
                                        let response_val = (negotiated << 16) | lz4_bit;
                                        self.push_response(
                                            RESPONSE_TYPE_SESSION_SETUP,
                                            response_val,
                                        );
                                    }
                                }
                                crate::packets::SessionRequest::FilePartSize { size } => {
                                    self.packet_size = size as usize;
                                    self.push_response(RESPONSE_TYPE_SESSION_SETUP, 0);
                                }
                                crate::packets::SessionRequest::SalesCode { c0, c1, c2 } => {
                                    let code = [c0 as u8, c1 as u8, c2 as u8];
                                    self.last_sales_code = Some(code);
                                    // Reverse-engineered Sprint RTN logic from abl_odin.efi (FUN_00058ea8):
                                    // SPR (Sprint), BST (Boost), VMU (Virgin), XAS (Sprint MVNO)
                                    if code == *b"SPR"
                                        || code == *b"BST"
                                        || code == *b"VMU"
                                        || code == *b"XAS"
                                    {
                                        self.sprint_rtn = true;
                                    }
                                    self.push_response(RESPONSE_TYPE_SESSION_SETUP, 0);
                                }
                                crate::packets::SessionRequest::NandErase => {
                                    if let Some(err) = self.fail_nand_erase {
                                        self.push_response(RESPONSE_TYPE_FAIL, err as u32);
                                    } else {
                                        self.push_response(
                                            RESPONSE_TYPE_SESSION_SETUP,
                                            self.nand_erase_sectors,
                                        );
                                    }
                                }
                                _ => {
                                    self.push_response(RESPONSE_TYPE_SESSION_SETUP, 0);
                                }
                            },
                            RequestPacket::PitFile(pit_req) => match pit_req {
                                crate::packets::PitFileRequest::Flash => {
                                    self.state = State::PitFileFlash;
                                    self.active_pit_data.clear();
                                    self.push_response(RESPONSE_TYPE_PIT_FILE, 0);
                                }
                                crate::packets::PitFileRequest::Dump => {
                                    self.push_response(
                                        RESPONSE_TYPE_PIT_FILE,
                                        self.active_pit_data.len() as u32,
                                    );
                                }
                                crate::packets::PitFileRequest::Part { part } => {
                                    let offset = part as usize * 500;
                                    let end = (offset + 500).min(self.active_pit_data.len());
                                    if offset < self.active_pit_data.len() {
                                        self.outgoing_queue
                                            .extend(&self.active_pit_data[offset..end]);
                                    }
                                }
                                _ => {
                                    self.push_response(RESPONSE_TYPE_PIT_FILE, 0);
                                }
                            },
                            RequestPacket::FileTransfer(transfer_req) => match transfer_req {
                                crate::packets::FileTransferRequest::Flash
                                | crate::packets::FileTransferRequest::Lz4Flash => {
                                    self.state = State::FileTransferFlash;
                                    self.current_partition_bytes = 0;
                                    self.push_response(RESPONSE_TYPE_FILE_TRANSFER, 0);
                                }
                                crate::packets::FileTransferRequest::Part { .. }
                                | crate::packets::FileTransferRequest::Lz4Part { .. } => {
                                    self.state = State::FileTransferPart;
                                    self.current_part_index = 0;
                                    self.push_response(RESPONSE_TYPE_FILE_TRANSFER, 0);
                                }
                                crate::packets::FileTransferRequest::End(end)
                                | crate::packets::FileTransferRequest::Lz4End(end) => {
                                    if let Some(err) = self.fail_commit {
                                        self.push_response(RESPONSE_TYPE_FAIL, err as u32);
                                    } else {
                                        let target_id = match end {
                                            crate::packets::FileTransferEnd::Unified {
                                                partition_identifier,
                                                ..
                                            } => partition_identifier,
                                            crate::packets::FileTransferEnd::LegacyModem {
                                                partition_identifier,
                                                ..
                                            } => partition_identifier,
                                        };

                                        if self.strict_pit_check
                                            && self.parsed_pit.as_ref().is_some_and(|pit| {
                                                pit.find_entry_by_id(target_id).is_none()
                                            })
                                        {
                                            self.push_response(RESPONSE_TYPE_FAIL, 0xffff_ffff);
                                            self.incoming_buffer.drain(..1024);
                                            return true;
                                        }

                                        self.flashed_partitions
                                            .push((target_id, self.current_partition_bytes));
                                        self.current_partition_bytes = 0;
                                        self.state = State::SessionBegun;
                                        self.push_response(RESPONSE_TYPE_FILE_TRANSFER, 0);
                                    }
                                }
                            },
                            RequestPacket::EndSession(end_req) => match end_req {
                                crate::packets::EndSessionRequest::EndSession => {
                                    if let Some(err) = self.fail_end_session {
                                        self.push_response(RESPONSE_TYPE_FAIL, err as u32);
                                    } else {
                                        self.state = State::HandshakeComplete;
                                        self.push_response(RESPONSE_TYPE_END_SESSION, 0);
                                    }
                                }
                                crate::packets::EndSessionRequest::RebootDevice => {
                                    self.last_reboot_mode = Some(if self.sprint_rtn {
                                        RebootMode::Recovery
                                    } else {
                                        RebootMode::Normal
                                    });
                                    self.state = State::Uninitialized;
                                }
                                crate::packets::EndSessionRequest::RebootDownload => {
                                    self.last_reboot_mode = Some(RebootMode::Download);
                                    self.state = State::Uninitialized;
                                }
                            },
                            RequestPacket::DynamicPartition(dp_req) => {
                                if !self.profile.supports_dynamic_partition {
                                    // S-Boot 4.0 does not recognize Opcode 0x6a -> returns FAIL
                                    self.push_response(RESPONSE_TYPE_FAIL, 0xffff_ffff);
                                } else {
                                    match dp_req {
                                        crate::packets::DynamicPartitionRequest::CheckSuperSize {
                                            super_used_size,
                                        } => {
                                            if let Some(err) = self.fail_check_super_size {
                                                self.push_response(RESPONSE_TYPE_FAIL, err as u32);
                                            } else if super_used_size as u64
                                                > self.profile.super_partition_free_space
                                            {
                                                self.push_response(RESPONSE_TYPE_FAIL, 0xffff_ffff);
                                            } else {
                                                self.push_response(
                                                    RESPONSE_TYPE_DYNAMIC_PARTITION,
                                                    0,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            RequestPacket::DeviceInfo(info_req) => {
                                if !self.profile.supports_device_info {
                                    // Opcode 0x69 undefined on legacy bootloaders -> returns FAIL
                                    self.push_response(RESPONSE_TYPE_FAIL, 0xffff_ffff);
                                } else {
                                    match info_req {
                                        crate::packets::DeviceInfoRequest::Dump => {
                                            let info = self.profile.binary_device_info();
                                            self.push_response(
                                                RESPONSE_TYPE_DEVICE_INFO,
                                                info.len() as u32,
                                            );
                                        }
                                        crate::packets::DeviceInfoRequest::Part { part } => {
                                            let info = self.profile.binary_device_info();
                                            let offset = part as usize * 500;
                                            let end = (offset + 500).min(info.len());
                                            if offset < info.len() {
                                                self.outgoing_queue.extend(&info[offset..end]);
                                            }
                                        }
                                        crate::packets::DeviceInfoRequest::End => {
                                            self.push_response(RESPONSE_TYPE_DEVICE_INFO, 0);
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
        true
    }

    fn receive_data(&mut self, data: &mut [u8], _timeout: i32, _retry: bool) -> i32 {
        if self.outgoing_queue.is_empty() {
            return 0;
        }
        let size = std::cmp::min(data.len(), self.outgoing_queue.len());
        for item in data.iter_mut().take(size) {
            *item = self.outgoing_queue.pop_front().unwrap();
        }
        size as i32
    }

    fn product_name(&self) -> Option<&str> {
        self.product_override
            .as_deref()
            .or(self.profile.usb_product_name.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::OdinError;
    use crate::odin::OdinConnection;
    use crate::packets::{FileTransferEnd, RequestPacket};
    use samloader_pit::{BinaryType, DeviceType};

    #[test]
    fn test_sm_f968b_modern_profile_lifecycle() {
        let profile = DeviceProfile::sm_f968b();
        let backend = Box::new(MockBackend::with_profile(profile, false));
        let mut connection = OdinConnection::new(backend);

        // 1. DVIF diagnostics prior to init
        let info = connection.query_device_info().unwrap();
        assert_eq!(info.model.as_deref(), Some("SM-F968B"));
        assert_eq!(info.storage_capacity_gb, Some(512));
        assert_eq!(info.storage_vendor.as_deref(), Some("SAMSUNG"));
        assert_eq!(info.storage_product_name.as_deref(), Some("KLUEG8UHDB"));
        assert_eq!(info.sales_code.as_deref(), Some("TUR"));

        // 2. Handshake
        assert!(connection.init().is_ok());

        // 3. Begin Session (protocol v3, LZ4 supported)
        let mut session = connection.begin_session().unwrap();
        assert_eq!(session.bootloader_protocol_version(), 3);
        assert!(session.is_lz4_supported());

        // 4. Download PIT (Q7MQ_EUR_OPENX.pit is 18492 bytes)
        let pit_bytes = session.download_pit_file().unwrap();
        assert_eq!(pit_bytes.len(), 18492);
        let pit = PitData::new(&pit_bytes).unwrap();
        assert_eq!(pit.cpu_bl_id.to_string_lossy(), "SM8750");

        // 5. Opcode 0x69 in-session DeviceInfo
        let session_info = session.dump_device_info().unwrap();
        assert_eq!(session_info.model.as_deref(), Some("SM-F968B"));
        assert_eq!(session_info.sales_code.as_deref(), Some("TUR"));

        // 6. Dynamic partition check
        assert!(session.check_super_size(1024 * 1024 * 100).is_ok());

        // 7. Session close
        let _ = session.close().unwrap();
    }

    #[test]
    fn test_gt_i9305_legacy_profile_lifecycle() {
        let profile = DeviceProfile::gt_i9305();
        assert_eq!(profile.model, "GT-I9305");
        assert_eq!(profile.cpu_bl_id, "Mx-MDM");
        assert_eq!(profile.protocol_version, 2);
        assert!(!profile.lz4_supported);
        assert_eq!(profile.usb_product_name.as_deref(), Some("Gadget Serial"));

        let backend = Box::new(MockBackend::with_profile(profile, false));
        let mut connection = OdinConnection::new(backend);

        // 1. DVIF is NOT supported on legacy S-Boot -> query_device_info returns DeviceInfoUnavailable
        let err = connection.query_device_info().unwrap_err();
        assert!(matches!(err, OdinError::DeviceInfoUnavailable));

        // 2. Handshake works with standard ODIN -> LOKE
        assert!(connection.init().is_ok());

        // 3. Begin session -> negotiates protocol v2, LZ4 disabled
        let mut session = connection.begin_session().unwrap();
        assert_eq!(session.bootloader_protocol_version(), 2);
        assert!(!session.is_lz4_supported());

        // 4. Download PIT (M3_EUR_OPEN_4G.pit is 2924 bytes, 20 entries)
        let pit_bytes = session.download_pit_file().unwrap();
        assert_eq!(pit_bytes.len(), 2924);
        let pit = PitData::new(&pit_bytes).unwrap();
        assert_eq!(pit.cpu_bl_id.to_string_lossy(), "Mx-MDM");
        assert_eq!(pit.entries.len(), 20);

        // Verify key partitions from sboot / M3 PIT
        let modem_entry = pit.find_entry_by_name("RADIO").expect("RADIO entry");
        assert_eq!(modem_entry.identifier, 10);
        assert_eq!(modem_entry.binary_type, BinaryType::ApplicationProcessor);

        // 5. In-session DeviceInfo (0x69) is rejected on legacy bootloader
        assert!(session.dump_device_info().is_err());

        // 6. Dynamic partition check (0x6a) is rejected on legacy bootloader
        assert!(session.check_super_size(1024).is_err());

        // 7. Close session
        let _ = session.close().unwrap();
    }

    #[test]
    fn test_device_profile_builder() {
        let custom_pit = DeviceProfile::gt_i9305().default_pit;
        let profile = DeviceProfile::builder()
            .model("CUSTOM-DEVICE")
            .cpu_bl_id("TEST_CPU")
            .build_version("CUSTOM_BUILD_1")
            .serial_number("SN123456")
            .storage_cid("CID0001")
            .storage_capacity_gb(256)
            .default_sales_code("XAA")
            .usb_product_name(Some("Gadget Serial".to_string()))
            .protocol_version(2)
            .lz4_supported(false)
            .max_packet_size(0x20000)
            .super_partition_free_space(1000)
            .supports_dvif(true)
            .supports_device_info(true)
            .supports_dynamic_partition(true)
            .default_pit(custom_pit)
            .build();

        assert_eq!(profile.model, "CUSTOM-DEVICE");
        assert_eq!(profile.cpu_bl_id, "TEST_CPU");
        assert_eq!(profile.storage_capacity_gb, 256);
        assert!(profile.supports_dvif);

        let dvif = profile.dvif_string();
        assert!(dvif.contains("MODEL=CUSTOM-DEVICE;"));
        assert!(dvif.contains("UN=SN123456;"));
        assert!(dvif.contains("SALES=XAA;"));

        let binary_info = profile.binary_device_info();
        assert_eq!(&binary_info[0..4], &0x12345678u32.to_le_bytes());
    }

    #[test]
    fn test_sprint_rtn_recovery_reboot_mode() {
        let mut backend = MockBackend::with_profile(DeviceProfile::sm_f968b(), false);
        // Simulate sales code SPR (Sprint)
        let sc_packet = RequestPacket::session_sales_code(*b"SPR");
        let mut sc_buf = Vec::new();
        binrw::BinWrite::write_le(&sc_packet, &mut std::io::Cursor::new(&mut sc_buf)).unwrap();
        sc_buf.resize(1024, 0);

        backend.send_data(b"ODIN", 1000, false);
        assert_eq!(backend.state, State::HandshakeComplete);

        let begin_packet = RequestPacket::begin_session();
        let mut begin_buf = Vec::new();
        binrw::BinWrite::write_le(&begin_packet, &mut std::io::Cursor::new(&mut begin_buf))
            .unwrap();
        begin_buf.resize(1024, 0);
        backend.send_data(&begin_buf, 1000, false);
        assert_eq!(backend.state, State::SessionBegun);

        backend.send_data(&sc_buf, 1000, false);
        assert_eq!(backend.last_sales_code(), Some(*b"SPR"));

        let reboot_packet = RequestPacket::reboot_device();
        let mut reboot_buf = Vec::new();
        binrw::BinWrite::write_le(&reboot_packet, &mut std::io::Cursor::new(&mut reboot_buf))
            .unwrap();
        reboot_buf.resize(1024, 0);
        backend.send_data(&reboot_buf, 1000, false);

        // Sprint sales code triggers recovery reboot!
        assert_eq!(backend.last_reboot_mode(), Some(RebootMode::Recovery));
    }

    #[test]
    fn test_flashing_partition_tracking_and_strict_pit() {
        let mut backend =
            MockBackend::with_profile(DeviceProfile::gt_i9305(), false).with_strict_pit_check(true);

        backend.send_data(b"ODIN", 1000, false);
        let mut handshake_resp = [0u8; 4];
        assert_eq!(backend.receive_data(&mut handshake_resp, 10, false), 4);
        assert_eq!(&handshake_resp, b"LOKE");

        let begin_packet = RequestPacket::begin_session();
        let mut begin_buf = Vec::new();
        binrw::BinWrite::write_le(&begin_packet, &mut std::io::Cursor::new(&mut begin_buf))
            .unwrap();
        begin_buf.resize(1024, 0);
        backend.send_data(&begin_buf, 1000, false);
        let mut resp_bytes = [0u8; 8];
        assert_eq!(backend.receive_data(&mut resp_bytes, 10, false), 8);

        // Init flash
        let flash_packet = RequestPacket::FileTransfer(crate::packets::FileTransferRequest::Flash);
        let mut flash_buf = Vec::new();
        binrw::BinWrite::write_le(&flash_packet, &mut std::io::Cursor::new(&mut flash_buf))
            .unwrap();
        flash_buf.resize(1024, 0);
        backend.send_data(&flash_buf, 1000, false);
        assert_eq!(backend.receive_data(&mut resp_bytes, 10, false), 8);

        // Send a chunk of 0x20000 bytes
        let part_packet = RequestPacket::FileTransfer(crate::packets::FileTransferRequest::Part {
            sequence_byte_count: 0x20000,
        });
        let mut part_buf = Vec::new();
        binrw::BinWrite::write_le(&part_packet, &mut std::io::Cursor::new(&mut part_buf)).unwrap();
        part_buf.resize(1024, 0);
        backend.send_data(&part_buf, 1000, false);
        assert_eq!(backend.receive_data(&mut resp_bytes, 10, false), 8);

        let chunk = vec![0xABu8; 0x20000];
        backend.send_data(&chunk, 1000, false);
        assert_eq!(backend.total_bytes_transferred(), 0x20000);
        assert_eq!(backend.receive_data(&mut resp_bytes, 10, false), 8);

        // End transfer with valid TargetID 10 (RADIO in GT-I9305 PIT)
        let end_packet = RequestPacket::FileTransfer(crate::packets::FileTransferRequest::End(
            FileTransferEnd::LegacyModem {
                sequence_byte_count: 0x20000,
                binary_type: BinaryType::ApplicationProcessor,
                device_type: DeviceType::MMC,
                is_last_sequence: 1,
                reserved: 0,
                partition_identifier: 10,
            },
        ));
        let mut end_buf = Vec::new();
        binrw::BinWrite::write_le(&end_packet, &mut std::io::Cursor::new(&mut end_buf)).unwrap();
        end_buf.resize(1024, 0);
        backend.send_data(&end_buf, 1000, false);
        assert_eq!(backend.receive_data(&mut resp_bytes, 10, false), 8);
        assert_eq!(
            u32::from_le_bytes(resp_bytes[0..4].try_into().unwrap()),
            RESPONSE_TYPE_FILE_TRANSFER
        );

        assert_eq!(backend.flashed_partitions(), &[(10, 0x20000)]);

        // Now test invalid TargetID 999 under strict PIT check -> fails
        backend.send_data(&flash_buf, 1000, false);
        assert_eq!(backend.receive_data(&mut resp_bytes, 10, false), 8);

        let bad_end_packet = RequestPacket::FileTransfer(crate::packets::FileTransferRequest::End(
            FileTransferEnd::Unified {
                sequence_byte_count: 0,
                binary_type: BinaryType::ApplicationProcessor,
                device_type: DeviceType::MMC,
                partition_identifier: 999,
                is_last_sequence: 1,
            },
        ));
        let mut bad_end_buf = Vec::new();
        binrw::BinWrite::write_le(&bad_end_packet, &mut std::io::Cursor::new(&mut bad_end_buf))
            .unwrap();
        bad_end_buf.resize(1024, 0);
        backend.send_data(&bad_end_buf, 1000, false);

        assert_eq!(backend.receive_data(&mut resp_bytes, 10, false), 8);
        let resp_type = u32::from_le_bytes(resp_bytes[0..4].try_into().unwrap());
        assert_eq!(resp_type, RESPONSE_TYPE_FAIL);
    }
}
