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

use binrw::{BinRead, BinWrite, io::Cursor};
use samloader_pit::{BinaryType, DeviceType, PitEntry};
use std::borrow::Cow;
use std::fmt::Debug;

pub(crate) const RESPONSE_TYPE_SEND_FILE_PART: u32 = 0x00;
pub(crate) const RESPONSE_TYPE_SESSION_SETUP: u32 = 0x64;
pub(crate) const RESPONSE_TYPE_PIT_FILE: u32 = 0x65;
pub(crate) const RESPONSE_TYPE_FILE_TRANSFER: u32 = 0x66;
pub(crate) const RESPONSE_TYPE_END_SESSION: u32 = 0x67;
pub(crate) const RESPONSE_TYPE_DEVICE_INFO: u32 = 0x69;
pub(crate) const RESPONSE_TYPE_DYNAMIC_PARTITION: u32 = 0x6a;

/// Special opcode returned by Samsung LOKE bootloader indicating an error condition.
pub(crate) const RESPONSE_TYPE_FAIL: u32 = 0xFFFFFFFF;

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum RequestPacket {
    #[brw(magic = 0x64u32)]
    Session(SessionRequest),

    #[brw(magic = 0x65u32)]
    PitFile(PitFileRequest),

    #[brw(magic = 0x66u32)]
    FileTransfer(FileTransferRequest),

    #[brw(magic = 0x67u32)]
    EndSession(EndSessionRequest),

    #[brw(magic = 0x69u32)]
    DeviceInfo(DeviceInfoRequest),

    #[brw(magic = 0x6au32)]
    DynamicPartition(DynamicPartitionRequest),
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum SessionRequest {
    #[brw(magic = 0u32)]
    Begin { protocol_version: u32 },
    #[brw(magic = 2u32)]
    TotalBytes { total_bytes: u64 },
    #[brw(magic = 5u32)]
    FilePartSize { size: u32 },
    #[brw(magic = 7u32)]
    NandErase,
    #[brw(magic = 9u32)]
    SalesCode { c0: u32, c1: u32, c2: u32 },
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum PitFileRequest {
    #[brw(magic = 0u32)]
    Flash,
    #[brw(magic = 1u32)]
    Dump,
    #[brw(magic = 2u32)]
    Part { part: u32 },
    #[brw(magic = 3u32)]
    End { size: u32 },
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum FileTransferRequest {
    #[brw(magic = 0u32)]
    Flash,
    #[brw(magic = 2u32)]
    Part { sequence_byte_count: u32 },
    #[brw(magic = 3u32)]
    End(FileTransferEnd),
    #[brw(magic = 5u32)]
    Lz4Flash,
    #[brw(magic = 6u32)]
    Lz4Part {
        compressed_size: u32,
        uncompressed_size: u32,
    },
    #[brw(magic = 7u32)]
    Lz4End(FileTransferEnd),
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(little)]
pub(crate) enum FileTransferEnd {
    /// Modern unified layout used by odin4 (bootloader_protocol_version >= 3).
    /// Used for both AP and CP/Modem binaries with magic = 0.
    #[brw(magic = 0u32)]
    Unified {
        sequence_byte_count: u32,
        binary_type: BinaryType,
        device_type: DeviceType,
        partition_identifier: u32,
        is_last_sequence: u32,
    },
    /// Legacy layout used by Odin 3 / Heimdall (bootloader_protocol_version < 3)
    /// when flashing CP / Modem partitions.
    #[brw(magic = 1u32)]
    LegacyModem {
        sequence_byte_count: u32,
        binary_type: BinaryType,
        device_type: DeviceType,
        is_last_sequence: u32,
        reserved: u32,
        partition_identifier: u32,
    },
}

impl FileTransferEnd {
    pub(crate) fn new(
        sequence_byte_count: u32,
        pit_entry: &PitEntry,
        is_last_sequence: bool,
        protocol_version: u32,
    ) -> Self {
        let is_last_sequence = if is_last_sequence { 1 } else { 0 };
        if protocol_version >= 3 || pit_entry.binary_type == BinaryType::ApplicationProcessor {
            Self::Unified {
                sequence_byte_count,
                binary_type: pit_entry.binary_type,
                device_type: pit_entry.device_type,
                partition_identifier: pit_entry.identifier,
                is_last_sequence,
            }
        } else {
            Self::LegacyModem {
                sequence_byte_count,
                binary_type: pit_entry.binary_type,
                device_type: pit_entry.device_type,
                is_last_sequence,
                reserved: 0,
                partition_identifier: pit_entry.identifier,
            }
        }
    }
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(little)]
pub(crate) enum EndSessionRequest {
    #[brw(magic = 0u32)]
    EndSession,
    #[brw(magic = 1u32)]
    RebootDevice,
    #[brw(magic = 2u32)]
    RebootDownload,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(little)]
pub(crate) enum DeviceInfoRequest {
    #[brw(magic = 0u32)]
    Dump,
    #[brw(magic = 1u32)]
    Part { part: u32 },
    #[brw(magic = 2u32)]
    End,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(little)]
pub(crate) enum DynamicPartitionRequest {
    #[brw(magic = 0u32)]
    CheckSuperSize { super_used_size: u32 },
}

impl RequestPacket {
    pub(crate) fn begin_session() -> Self {
        Self::Session(SessionRequest::Begin {
            protocol_version: 0x05,
        })
    }

    pub(crate) fn total_bytes(total_bytes: u64) -> Self {
        Self::Session(SessionRequest::TotalBytes { total_bytes })
    }

    pub(crate) fn file_part_size(size: u32) -> Self {
        Self::Session(SessionRequest::FilePartSize { size })
    }

    pub(crate) fn nand_erase() -> Self {
        Self::Session(SessionRequest::NandErase)
    }

    pub(crate) fn session_sales_code(code: [u8; 3]) -> Self {
        Self::Session(SessionRequest::SalesCode {
            c0: code[0] as u32,
            c1: code[1] as u32,
            c2: code[2] as u32,
        })
    }

    pub(crate) fn end_session() -> Self {
        Self::EndSession(EndSessionRequest::EndSession)
    }

    pub(crate) fn reboot_device() -> Self {
        Self::EndSession(EndSessionRequest::RebootDevice)
    }

    pub(crate) fn reboot_to_download() -> Self {
        Self::EndSession(EndSessionRequest::RebootDownload)
    }

    pub(crate) fn pit_file_flash() -> Self {
        Self::PitFile(PitFileRequest::Flash)
    }

    pub(crate) fn pit_file_dump() -> Self {
        Self::PitFile(PitFileRequest::Dump)
    }

    pub(crate) fn pit_file_end() -> Self {
        Self::PitFile(PitFileRequest::End { size: 0 })
    }

    pub(crate) fn flash_part_pit_file(size: u32) -> Self {
        Self::PitFile(PitFileRequest::Part { part: size })
    }

    pub(crate) fn dump_part_pit_file(part: u32) -> Self {
        Self::PitFile(PitFileRequest::Part { part })
    }

    pub(crate) fn end_pit_file_transfer(size: u32) -> Self {
        Self::PitFile(PitFileRequest::End { size })
    }

    pub(crate) fn file_transfer_flash(lz4: bool) -> Self {
        Self::FileTransfer(if lz4 {
            FileTransferRequest::Lz4Flash
        } else {
            FileTransferRequest::Flash
        })
    }

    pub(crate) fn flash_part_file_transfer(sequence_byte_count: u32) -> Self {
        // In Samsung LOKE protocol and odin4 (DownloadEngine::transmitData),
        // the announced raw sequence slice size is rounded up to a 128 KB (0x20000) boundary.
        let aligned_count = ((sequence_byte_count as u64 + 0x1FFFF) & !0x1FFFF) as u32;
        Self::FileTransfer(FileTransferRequest::Part {
            sequence_byte_count: aligned_count,
        })
    }

    pub(crate) fn flash_part_lz4_file_transfer(
        compressed_size: u32,
        uncompressed_size: u32,
    ) -> Self {
        Self::FileTransfer(FileTransferRequest::Lz4Part {
            compressed_size,
            uncompressed_size,
        })
    }

    pub(crate) fn end_file_transfer(
        sequence_byte_count: u32,
        pit_entry: &PitEntry,
        is_last_sequence: bool,
        lz4: bool,
        protocol_version: u32,
    ) -> Self {
        let end = FileTransferEnd::new(
            sequence_byte_count,
            pit_entry,
            is_last_sequence,
            protocol_version,
        );
        Self::FileTransfer(if lz4 {
            FileTransferRequest::Lz4End(end)
        } else {
            FileTransferRequest::End(end)
        })
    }

    pub(crate) fn check_super_size(super_used_size: u32) -> Self {
        Self::DynamicPartition(DynamicPartitionRequest::CheckSuperSize { super_used_size })
    }

    pub(crate) fn device_info_dump() -> Self {
        Self::DeviceInfo(DeviceInfoRequest::Dump)
    }

    pub(crate) fn dump_part_device_info(part: u32) -> Self {
        Self::DeviceInfo(DeviceInfoRequest::Part { part })
    }

    pub(crate) fn end_device_info() -> Self {
        Self::DeviceInfo(DeviceInfoRequest::End)
    }

    pub(crate) fn expected_response_type(&self) -> u32 {
        match self {
            Self::Session(_) => RESPONSE_TYPE_SESSION_SETUP,
            Self::PitFile(_) => RESPONSE_TYPE_PIT_FILE,
            Self::FileTransfer(_) => RESPONSE_TYPE_FILE_TRANSFER,
            Self::EndSession(_) => RESPONSE_TYPE_END_SESSION,
            Self::DeviceInfo(_) => RESPONSE_TYPE_DEVICE_INFO,
            Self::DynamicPartition(_) => RESPONSE_TYPE_DYNAMIC_PARTITION,
        }
    }

    pub(crate) fn pack(&self) -> [u8; 1024] {
        let mut buf = [0u8; 1024];
        let mut writer = Cursor::new(&mut buf[..]);
        self.write_le(&mut writer).expect("Failed to write packet");
        buf
    }
}

pub(crate) struct FilePartPacket<'a> {
    buffer: &'a [u8],
    size: usize,
}

impl<'a> Debug for FilePartPacket<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilePartPacket")
            .field("data", &format_args!("[u8; {}]", self.size))
            .finish()
    }
}

impl<'a> FilePartPacket<'a> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Response {
    pub response_type: u32,
    pub value: u32,
}

impl Response {
    pub(crate) const SIZE: usize = 8;

    pub(crate) fn parse(buffer: &[u8]) -> Result<Self, String> {
        if buffer.len() != Self::SIZE {
            return Err(format!(
                "Incorrect packet size received - expected size = {}, received size = {}.",
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
        self.response_type == RESPONSE_TYPE_FAIL
    }

    pub(crate) fn signed_value(&self) -> i32 {
        self.value as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use samloader_pit::Attribute;

    fn mock_pit_entry(
        binary_type: BinaryType,
        device_type: DeviceType,
        identifier: u32,
    ) -> PitEntry {
        PitEntry {
            binary_type,
            device_type,
            identifier,
            attributes: Attribute::default(),
            update_attributes: Default::default(),
            block_size_or_offset: 0,
            block_count: 0,
            file_offset: 0,
            file_size: 0,
            partition_name: Default::default(),
            flash_filename: Default::default(),
            fota_filename: Default::default(),
        }
    }

    #[test]
    fn test_file_transfer_end_layout_selection() {
        let modem_entry = mock_pit_entry(BinaryType::CommunicationProcessor, DeviceType::UFS, 80);
        let ap_entry = mock_pit_entry(BinaryType::ApplicationProcessor, DeviceType::MMC, 20);

        // Modern protocol (>= 3): CP/Modem uses Unified layout
        let modern_cp = FileTransferEnd::new(0x1E00000, &modem_entry, true, 3);
        assert!(matches!(
            modern_cp,
            FileTransferEnd::Unified {
                sequence_byte_count: 0x1E00000,
                partition_identifier: 80,
                is_last_sequence: 1,
                ..
            }
        ));

        // Legacy protocol (< 3): CP/Modem uses LegacyModem layout
        let legacy_cp = FileTransferEnd::new(0x100000, &modem_entry, true, 2);
        assert!(matches!(
            legacy_cp,
            FileTransferEnd::LegacyModem {
                sequence_byte_count: 0x100000,
                partition_identifier: 80,
                is_last_sequence: 1,
                ..
            }
        ));

        // ApplicationProcessor always uses Unified layout even on legacy protocol
        let legacy_ap = FileTransferEnd::new(0x100000, &ap_entry, false, 1);
        assert!(matches!(
            legacy_ap,
            FileTransferEnd::Unified {
                partition_identifier: 20,
                is_last_sequence: 0,
                ..
            }
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
        assert_eq!(fail_resp.response_type, RESPONSE_TYPE_FAIL);
        assert!(fail_resp.is_fail());
        assert_eq!(fail_resp.signed_value(), -5);
    }

    #[test]
    fn test_flash_part_file_transfer_128k_alignment() {
        // Test size round-up behavior to 128 KB (0x20000)
        let check_aligned = |raw_size: u32, expected_aligned: u32| {
            let packet = RequestPacket::flash_part_file_transfer(raw_size);
            assert_eq!(packet.expected_response_type(), RESPONSE_TYPE_FILE_TRANSFER);
            let packed = packet.pack();
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
