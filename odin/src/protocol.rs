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

//! Samsung Odin protocol command and streaming wire format definitions.
//!
//! # Transfer Architecture: Commands, Slices, and Chunks
//!
//! In Samsung's download protocol (`odin4` & `abl_odin.efi` / LOKE), flashing is structured
//! into three distinct layers:
//!
//! 1. **Control Layer ([`Command`] & [`Response`])**:
//!    Fixed-size 1024-byte command packets sent over USB bulk endpoints to negotiate
//!    session parameters, query device attributes, and orchestrate transfers. The device
//!    bootloader replies with an 8-byte response consisting of `(command_echo, value_or_status)`.
//!
//! 2. **Flashing Macro Layer (Slices)**:
//!    Large staging buffers bounded by device RAM (default 30 MB / `0x1E00000` in `odin4`).
//!    Each slice is announced with a [`TransmitCommand::Slice`] or [`TransmitCommand::Lz4Slice`]
//!    announcement (rounded up to a 128 KB boundary for raw transfers), streamed in chunks,
//!    and finally committed to physical storage with [`SliceCommit`] (`0x66`, Subcmd 3 or 7).
//!    The bootloader verifies and writes the staged RAM buffer to flash before acknowledging.
//!
//! 3. **Flashing Micro Layer (Data Chunks - [`DataChunk`])**:
//!    The physical USB transport units negotiated via [`SessionCommand::PacketSize`]
//!    (typically 1 MB / `0x100000` on USB 2.0/3.0, or 128 KB on older hardware).
//!    Chunks are streamed as raw USB bulk packets without zero-length termination packets (ZLPs).
//!    After each chunk, the bootloader returns a streaming ACK packet `(0x00, chunk_index)`.

use binrw::{BinRead, BinWrite, io::Cursor};
use samloader_pit::{BinaryType, DeviceType, PitEntry};
use std::borrow::Cow;
use std::fmt::Debug;

/// Bootloader streaming ACK opcode (0x00) echoing the received chunk index.
pub(crate) const STREAMING_CHUNK_ACK: u32 = 0x00;

/// Host command opcodes (in Heimdall historically misnamed `RESPONSE_TYPE_*`).
pub(crate) const CMD_SESSION_INIT: u32 = 0x64;
pub(crate) const CMD_PIT: u32 = 0x65;
pub(crate) const CMD_TRANSMIT: u32 = 0x66;
pub(crate) const CMD_CLOSE_CONNECTION: u32 = 0x67;
pub(crate) const CMD_DEVINFO: u32 = 0x69;
pub(crate) const CMD_DDP: u32 = 0x6a;

/// Special status code returned by Samsung LOKE bootloader indicating an error condition.
pub(crate) const STATUS_FAIL: u32 = 0xFFFFFFFF;

/// Top-level control command sent from host to device over bulk endpoint.
#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum Command {
    #[brw(magic = 0x64u32)]
    Session(SessionCommand),

    #[brw(magic = 0x65u32)]
    Pit(PitCommand),

    #[brw(magic = 0x66u32)]
    Transmit(TransmitCommand),

    #[brw(magic = 0x67u32)]
    CloseConnection(CloseConnectionCommand),

    #[brw(magic = 0x69u32)]
    DeviceInfo(DeviceInfoCommand),

    #[brw(magic = 0x6au32)]
    DynamicPartition(DynamicPartitionCommand),
}

/// Subcommands for [`CMD_SESSION_INIT`] (0x64).
#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum SessionCommand {
    /// Initialize protocol session.
    #[brw(magic = 0u32)]
    Begin { protocol_version: u32 },

    /// Announce total byte count to be flashed across the session.
    #[brw(magic = 2u32)]
    TotalBytes { total_bytes: u64 },

    /// Negotiate streaming USB chunk/packet size (e.g. 1 MB = 0x100000).
    #[brw(magic = 5u32)]
    PacketSize { size: u32 },

    /// Triggers an active hardware erase of the `userdata` partition via UEFI EraseBlock
    /// and returns the device erase sector size.
    #[brw(magic = 7u32)]
    NandErase,

    /// Sets the 3-letter target sales / CSC code.
    #[brw(magic = 9u32)]
    SalesCode { c0: u32, c1: u32, c2: u32 },
}

/// Subcommands for [`CMD_PIT`] (0x65).
#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum PitCommand {
    #[brw(magic = 0u32)]
    Flash,
    #[brw(magic = 1u32)]
    Dump,
    #[brw(magic = 2u32)]
    Slice { slice: u32 },
    #[brw(magic = 3u32)]
    End { size: u32 },
}

/// Subcommands for [`CMD_TRANSMIT`] (0x66).
#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum TransmitCommand {
    #[brw(magic = 0u32)]
    Flash,
    #[brw(magic = 2u32)]
    Slice { slice_byte_count: u32 },
    #[brw(magic = 3u32)]
    End(SliceCommit),
    #[brw(magic = 5u32)]
    Lz4Flash,
    #[brw(magic = 6u32)]
    Lz4Slice {
        compressed_size: u32,
        uncompressed_size: u32,
    },
    #[brw(magic = 7u32)]
    Lz4End(SliceCommit),
}

/// Descriptor sent to commit and flash a completed slice to physical storage.
#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum SliceCommit {
    /// Modern unified layout used by odin4 (bootloader_protocol_version >= 3).
    /// Used for both AP and CP/Modem binaries with magic = 0.
    #[brw(magic = 0u32)]
    Unified {
        slice_size: u32,
        binary_type: BinaryType,
        device_type: DeviceType,
        partition_id: u32,
        is_end_of_file: u32,
    },
    /// Legacy layout used by Odin 3 / Heimdall (bootloader_protocol_version < 3)
    /// when flashing CP / Modem partitions.
    #[brw(magic = 1u32)]
    LegacyModem {
        slice_size: u32,
        binary_type: BinaryType,
        device_type: DeviceType,
        is_end_of_file: u32,
        reserved: u32,
        partition_id: u32,
    },
}

impl SliceCommit {
    #[cfg(mock_backend)]
    pub(crate) fn partition_id(&self) -> u32 {
        match self {
            Self::Unified { partition_id, .. } => *partition_id,
            Self::LegacyModem { partition_id, .. } => *partition_id,
        }
    }

    #[cfg(mock_backend)]
    pub(crate) fn slice_size(&self) -> u32 {
        match self {
            Self::Unified { slice_size, .. } => *slice_size,
            Self::LegacyModem { slice_size, .. } => *slice_size,
        }
    }

    #[cfg(mock_backend)]
    pub(crate) fn is_end_of_file(&self) -> bool {
        match self {
            Self::Unified { is_end_of_file, .. } => *is_end_of_file != 0,
            Self::LegacyModem { is_end_of_file, .. } => *is_end_of_file != 0,
        }
    }

    pub(crate) fn new(
        slice_size: u32,
        pit_entry: &PitEntry,
        is_end_of_file: bool,
        protocol_version: u32,
    ) -> Self {
        let is_end_of_file = if is_end_of_file { 1 } else { 0 };
        if protocol_version >= 3 || pit_entry.binary_type == BinaryType::ApplicationProcessor {
            Self::Unified {
                slice_size,
                binary_type: pit_entry.binary_type,
                device_type: pit_entry.device_type,
                partition_id: pit_entry.partition_id,
                is_end_of_file,
            }
        } else {
            Self::LegacyModem {
                slice_size,
                binary_type: pit_entry.binary_type,
                device_type: pit_entry.device_type,
                is_end_of_file,
                reserved: 0,
                partition_id: pit_entry.partition_id,
            }
        }
    }
}

/// Subcommands for [`CMD_CLOSE_CONNECTION`] (0x67).
#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum CloseConnectionCommand {
    #[brw(magic = 0u32)]
    Close,
    #[brw(magic = 1u32)]
    RebootDevice,
    #[brw(magic = 2u32)]
    RebootDownload,
}

/// Subcommands for [`CMD_DEVINFO`] (0x69).
#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum DeviceInfoCommand {
    #[brw(magic = 0u32)]
    Dump,
    #[brw(magic = 1u32)]
    Slice { slice: u32 },
    #[brw(magic = 2u32)]
    End,
}

/// Subcommands for [`CMD_DDP`] (0x6a).
#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum DynamicPartitionCommand {
    #[brw(magic = 0u32)]
    CheckSuperSize { super_used_size: u32 },
}

impl Command {
    pub(crate) fn begin_session() -> Self {
        Self::Session(SessionCommand::Begin {
            protocol_version: 0x05,
        })
    }

    pub(crate) fn total_bytes(total_bytes: u64) -> Self {
        Self::Session(SessionCommand::TotalBytes { total_bytes })
    }

    pub(crate) fn packet_size(size: u32) -> Self {
        Self::Session(SessionCommand::PacketSize { size })
    }

    pub(crate) fn nand_erase() -> Self {
        Self::Session(SessionCommand::NandErase)
    }

    pub(crate) fn session_sales_code(code: [u8; 3]) -> Self {
        Self::Session(SessionCommand::SalesCode {
            c0: code[0] as u32,
            c1: code[1] as u32,
            c2: code[2] as u32,
        })
    }

    pub(crate) fn close_connection() -> Self {
        Self::CloseConnection(CloseConnectionCommand::Close)
    }

    pub(crate) fn reboot_device() -> Self {
        Self::CloseConnection(CloseConnectionCommand::RebootDevice)
    }

    pub(crate) fn reboot_to_download() -> Self {
        Self::CloseConnection(CloseConnectionCommand::RebootDownload)
    }

    pub(crate) fn pit_flash() -> Self {
        Self::Pit(PitCommand::Flash)
    }

    pub(crate) fn pit_dump() -> Self {
        Self::Pit(PitCommand::Dump)
    }

    pub(crate) fn pit_end() -> Self {
        Self::Pit(PitCommand::End { size: 0 })
    }

    pub(crate) fn flash_pit_slice(size: u32) -> Self {
        Self::Pit(PitCommand::Slice { slice: size })
    }

    pub(crate) fn dump_pit_slice(slice: u32) -> Self {
        Self::Pit(PitCommand::Slice { slice })
    }

    pub(crate) fn end_pit_transfer(size: u32) -> Self {
        Self::Pit(PitCommand::End { size })
    }

    pub(crate) fn transmit_flash(lz4: bool) -> Self {
        Self::Transmit(if lz4 {
            TransmitCommand::Lz4Flash
        } else {
            TransmitCommand::Flash
        })
    }

    pub(crate) fn start_slice_transmission(slice_byte_count: u32) -> Self {
        // In Samsung LOKE protocol and odin4 (DownloadEngine::transmitData),
        // the announced raw slice size is rounded up to a 128 KB (0x20000) boundary.
        let aligned_count = ((slice_byte_count as u64 + 0x1FFFF) & !0x1FFFF) as u32;
        Self::Transmit(TransmitCommand::Slice {
            slice_byte_count: aligned_count,
        })
    }

    pub(crate) fn start_lz4_slice_transmission(
        compressed_size: u32,
        uncompressed_size: u32,
    ) -> Self {
        Self::Transmit(TransmitCommand::Lz4Slice {
            compressed_size,
            uncompressed_size,
        })
    }

    pub(crate) fn commit_slice(
        slice_size: u32,
        pit_entry: &PitEntry,
        is_end_of_file: bool,
        lz4: bool,
        protocol_version: u32,
    ) -> Self {
        let commit = SliceCommit::new(slice_size, pit_entry, is_end_of_file, protocol_version);
        Self::Transmit(if lz4 {
            TransmitCommand::Lz4End(commit)
        } else {
            TransmitCommand::End(commit)
        })
    }

    pub(crate) fn check_super_size(super_used_size: u32) -> Self {
        Self::DynamicPartition(DynamicPartitionCommand::CheckSuperSize { super_used_size })
    }

    pub(crate) fn device_info_dump() -> Self {
        Self::DeviceInfo(DeviceInfoCommand::Dump)
    }

    pub(crate) fn dump_device_info_slice(slice: u32) -> Self {
        Self::DeviceInfo(DeviceInfoCommand::Slice { slice })
    }

    pub(crate) fn end_device_info() -> Self {
        Self::DeviceInfo(DeviceInfoCommand::End)
    }

    pub(crate) fn expected_response_type(&self) -> u32 {
        match self {
            Self::Session(_) => CMD_SESSION_INIT,
            Self::Pit(_) => CMD_PIT,
            Self::Transmit(_) => CMD_TRANSMIT,
            Self::CloseConnection(_) => CMD_CLOSE_CONNECTION,
            Self::DeviceInfo(_) => CMD_DEVINFO,
            Self::DynamicPartition(_) => CMD_DDP,
        }
    }

    pub(crate) fn pack(&self) -> [u8; 1024] {
        let mut buf = [0u8; 1024];
        let mut writer = Cursor::new(&mut buf[..]);
        self.write_le(&mut writer).expect("Failed to write command");
        buf
    }
}

/// A micro USB bulk streaming chunk (typically 1 MB = 0x100000 or 128 KB = 0x20000).
pub(crate) struct DataChunk<'a> {
    buffer: &'a [u8],
    size: usize,
}

impl<'a> Debug for DataChunk<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataChunk")
            .field("data", &format_args!("[u8; {}]", self.size))
            .finish()
    }
}

impl<'a> DataChunk<'a> {
    pub(crate) fn new(buffer: &'a [u8], size: usize) -> Self {
        Self { buffer, size }
    }

    pub(crate) fn as_bytes(&self) -> Cow<'a, [u8]> {
        if self.buffer.len() >= self.size {
            Cow::Borrowed(&self.buffer[..self.size])
        } else {
            let mut data = vec![0u8; self.size];
            data[..self.buffer.len()].copy_from_slice(self.buffer);
            Cow::Owned(data)
        }
    }
}

/// 8-byte response returned by Samsung LOKE bootloader for commands.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Response {
    pub response_type: u32,
    pub value: u32,
}

impl Response {
    pub(crate) const SIZE: usize = 8;

    pub(crate) fn parse(buffer: &[u8]) -> Result<Self, String> {
        if buffer.len() != Self::SIZE {
            return Err(format!(
                "Incorrect response size received - expected size = {}, received size = {}.",
                Self::SIZE,
                buffer.len()
            ));
        }
        let response_type = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
        let value = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        Ok(Self {
            response_type,
            value,
        })
    }

    pub(crate) fn is_fail(&self) -> bool {
        self.response_type == STATUS_FAIL
    }

    pub(crate) fn signed_value(&self) -> i32 {
        self.value as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use samloader_pit::PitData;

    #[test]
    fn test_slice_commit_layout_selection() {
        // The test PITs only have AP partitions, so one of them stands in for a modem
        let mut entries = PitData::new(crate::test_util::M3_PIT).unwrap().entries;
        let ap_entry = entries.pop().unwrap();
        let mut modem_entry = entries.pop().unwrap();
        modem_entry.binary_type = BinaryType::CommunicationProcessor;
        let (modem_id, ap_id) = (modem_entry.partition_id, ap_entry.partition_id);

        // Modern protocol (>= 3): CP/Modem uses Unified layout
        let modern_cp = SliceCommit::new(0x1E00000, &modem_entry, true, 3);
        assert!(matches!(
            modern_cp,
            SliceCommit::Unified {
                slice_size: 0x1E00000,
                partition_id,
                is_end_of_file: 1,
                ..
            } if partition_id == modem_id
        ));

        // Legacy protocol (< 3): CP/Modem uses LegacyModem layout
        let legacy_cp = SliceCommit::new(0x100000, &modem_entry, true, 2);
        assert!(matches!(
            legacy_cp,
            SliceCommit::LegacyModem {
                slice_size: 0x100000,
                partition_id,
                is_end_of_file: 1,
                ..
            } if partition_id == modem_id
        ));

        // ApplicationProcessor always uses Unified layout even on legacy protocol
        let legacy_ap = SliceCommit::new(0x100000, &ap_entry, false, 1);
        assert!(matches!(
            legacy_ap,
            SliceCommit::Unified {
                partition_id,
                is_end_of_file: 0,
                ..
            } if partition_id == ap_id
        ));
    }

    #[test]
    fn test_response_parse_and_fail_detection() {
        let ok_bytes = [0x64, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0x00];
        let resp = Response::parse(&ok_bytes).unwrap();
        assert_eq!(resp.response_type, 0x64);
        assert_eq!(resp.value, 0x00028000);
        assert!(!resp.is_fail());
        assert_eq!(resp.signed_value(), 0x00028000);

        let fail_bytes = [0xff, 0xff, 0xff, 0xff, 0xfb, 0xff, 0xff, 0xff]; // opcode -1, value -5
        let fail_resp = Response::parse(&fail_bytes).unwrap();
        assert_eq!(fail_resp.response_type, STATUS_FAIL);
        assert!(fail_resp.is_fail());
        assert_eq!(fail_resp.signed_value(), -5);
    }

    #[test]
    fn test_start_slice_transmission_128k_alignment() {
        // Test size round-up behavior to 128 KB (0x20000)
        let check_aligned = |raw_size: u32, expected_aligned: u32| {
            let cmd = Command::start_slice_transmission(raw_size);
            assert_eq!(cmd.expected_response_type(), CMD_TRANSMIT);
            let packed = cmd.pack();
            let announced_size = u32::from_le_bytes(packed[8..12].try_into().unwrap());
            assert_eq!(announced_size, expected_aligned);
        };

        check_aligned(0, 0);
        check_aligned(1, 0x20000);
        check_aligned(50_000, 0x20000);
        check_aligned(0x20000, 0x20000);
        check_aligned(0x20001, 0x40000);
        check_aligned(31_457_280, 31_457_280); // 30 MB (standard slice)
    }
}
