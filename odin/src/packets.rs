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
use std::fmt::Debug;

pub(crate) const RESPONSE_TYPE_SEND_FILE_PART: u32 = 0x00;
pub(crate) const RESPONSE_TYPE_SESSION_SETUP: u32 = 0x64;
pub(crate) const RESPONSE_TYPE_PIT_FILE: u32 = 0x65;
pub(crate) const RESPONSE_TYPE_FILE_TRANSFER: u32 = 0x66;
pub(crate) const RESPONSE_TYPE_END_SESSION: u32 = 0x67;

pub(crate) trait OutboundPacket {
    fn pack(&self) -> Vec<u8>;
}

pub(crate) trait InboundPacket: Sized {
    const SIZE: usize;
    fn unpack(buffer: &[u8]) -> Result<Self, String>;
}

#[derive(BinWrite, Debug)]
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
}

#[derive(BinWrite, Debug)]
#[brw(little)]
pub(crate) enum SessionRequest {
    #[brw(magic = 0u32)]
    Begin { protocol_version: u32 },
    #[brw(magic = 2u32)]
    TotalBytes { total_bytes: u64 },
    #[brw(magic = 5u32)]
    FilePartSize { size: u32 },
}

#[derive(BinWrite, Debug)]
#[brw(little)]
pub(crate) enum PitFileRequest {
    #[brw(magic = 0u32)]
    Flash,
    #[brw(magic = 1u32)]
    Dump,
    #[brw(magic = 2u32)]
    Part(PitFilePart),
    #[brw(magic = 3u32)]
    End { size: u32 },
}

#[derive(BinWrite, Debug)]
#[brw(little)]
pub(crate) enum PitFilePart {
    Flash { size: u32 },
    Dump { part: u32 },
}

#[derive(BinWrite, Debug)]
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
    Lz4Part { sequence_byte_count: u32 },
    #[brw(magic = 7u32)]
    Lz4End(FileTransferEnd),
}

#[derive(BinWrite, Debug)]
#[brw(little)]
pub(crate) enum FileTransferEnd {
    #[brw(magic = 0u32)]
    Phone {
        sequence_byte_count: u32,
        binary_type: BinaryType,
        device_type: DeviceType,
        partition_identifier: u32,
        is_last_sequence: u32,
    },
    #[brw(magic = 1u32)]
    Modem {
        sequence_byte_count: u32,
        binary_type: BinaryType,
        device_type: DeviceType,
        is_last_sequence: u32,
    },
}

#[derive(BinWrite, Debug)]
#[brw(little)]
pub(crate) enum EndSessionRequest {
    #[brw(magic = 0u32)]
    EndSession,
    #[brw(magic = 1u32)]
    RebootDevice,
}

impl RequestPacket {
    pub(crate) fn begin_session() -> RequestPacket {
        RequestPacket::Session(SessionRequest::Begin {
            protocol_version: 0x04,
        })
    }

    pub(crate) fn total_bytes(total_bytes: u64) -> RequestPacket {
        RequestPacket::Session(SessionRequest::TotalBytes { total_bytes })
    }

    pub(crate) fn file_part_size(size: u32) -> RequestPacket {
        RequestPacket::Session(SessionRequest::FilePartSize { size })
    }

    pub(crate) fn end_session() -> RequestPacket {
        RequestPacket::EndSession(EndSessionRequest::EndSession)
    }

    pub(crate) fn reboot_device() -> RequestPacket {
        RequestPacket::EndSession(EndSessionRequest::RebootDevice)
    }

    pub(crate) fn pit_file_flash() -> RequestPacket {
        RequestPacket::PitFile(PitFileRequest::Flash)
    }

    pub(crate) fn pit_file_dump() -> RequestPacket {
        RequestPacket::PitFile(PitFileRequest::Dump)
    }

    pub(crate) fn pit_file_end() -> RequestPacket {
        RequestPacket::PitFile(PitFileRequest::End { size: 0 })
    }

    pub(crate) fn flash_part_pit_file(size: u32) -> RequestPacket {
        RequestPacket::PitFile(PitFileRequest::Part(PitFilePart::Flash { size }))
    }

    pub(crate) fn dump_part_pit_file(part: u32) -> RequestPacket {
        RequestPacket::PitFile(PitFileRequest::Part(PitFilePart::Dump { part }))
    }

    pub(crate) fn end_pit_file_transfer(size: u32) -> RequestPacket {
        RequestPacket::PitFile(PitFileRequest::End { size })
    }

    pub(crate) fn file_transfer_flash() -> RequestPacket {
        RequestPacket::FileTransfer(FileTransferRequest::Flash)
    }

    pub(crate) fn flash_part_file_transfer(sequence_byte_count: u32) -> RequestPacket {
        RequestPacket::FileTransfer(FileTransferRequest::Part {
            sequence_byte_count,
        })
    }

    pub(crate) fn end_modem_file_transfer(
        sequence_byte_count: u32,
        pit_entry: &PitEntry,
        is_last_sequence: bool,
    ) -> RequestPacket {
        RequestPacket::FileTransfer(FileTransferRequest::End(FileTransferEnd::Modem {
            sequence_byte_count,
            binary_type: pit_entry.binary_type,
            device_type: pit_entry.device_type,
            is_last_sequence: if is_last_sequence { 1 } else { 0 },
        }))
    }

    pub(crate) fn end_phone_file_transfer(
        sequence_byte_count: u32,
        pit_entry: &PitEntry,
        is_last_sequence: bool,
    ) -> RequestPacket {
        RequestPacket::FileTransfer(FileTransferRequest::End(FileTransferEnd::Phone {
            sequence_byte_count,
            binary_type: pit_entry.binary_type,
            device_type: pit_entry.device_type,
            partition_identifier: pit_entry.identifier,
            is_last_sequence: if is_last_sequence { 1 } else { 0 },
        }))
    }

    pub(crate) fn lz4_file_transfer_flash() -> RequestPacket {
        RequestPacket::FileTransfer(FileTransferRequest::Lz4Flash)
    }

    pub(crate) fn flash_lz4_part_file_transfer(sequence_byte_count: u32) -> RequestPacket {
        RequestPacket::FileTransfer(FileTransferRequest::Lz4Part {
            sequence_byte_count,
        })
    }

    pub(crate) fn end_lz4_modem_file_transfer(
        sequence_byte_count: u32,
        pit_entry: &PitEntry,
        is_last_sequence: bool,
    ) -> RequestPacket {
        RequestPacket::FileTransfer(FileTransferRequest::Lz4End(FileTransferEnd::Modem {
            sequence_byte_count,
            binary_type: pit_entry.binary_type,
            device_type: pit_entry.device_type,
            is_last_sequence: if is_last_sequence { 1 } else { 0 },
        }))
    }

    pub(crate) fn end_lz4_phone_file_transfer(
        sequence_byte_count: u32,
        pit_entry: &PitEntry,
        is_last_sequence: bool,
    ) -> RequestPacket {
        RequestPacket::FileTransfer(FileTransferRequest::Lz4End(FileTransferEnd::Phone {
            sequence_byte_count,
            binary_type: pit_entry.binary_type,
            device_type: pit_entry.device_type,
            partition_identifier: pit_entry.identifier,
            is_last_sequence: if is_last_sequence { 1 } else { 0 },
        }))
    }

    pub(crate) fn expected_response_type(&self) -> u32 {
        match self {
            RequestPacket::Session(_) => RESPONSE_TYPE_SESSION_SETUP,
            RequestPacket::PitFile(_) => RESPONSE_TYPE_PIT_FILE,
            RequestPacket::FileTransfer(_) => RESPONSE_TYPE_FILE_TRANSFER,
            RequestPacket::EndSession(_) => RESPONSE_TYPE_END_SESSION,
        }
    }
}

impl OutboundPacket for RequestPacket {
    fn pack(&self) -> Vec<u8> {
        let mut writer = Cursor::new(Vec::with_capacity(1024));
        self.write_le(&mut writer).expect("Failed to write packet");
        let mut data = writer.into_inner();
        data.resize(1024, 0);
        data
    }
}

pub(crate) struct FilePartPacket<'a> {
    buffer: &'a [u8],
    size: u32,
}

impl<'a> Debug for FilePartPacket<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilePartPacket")
            .field("data", &format_args!("[u8; {}]", &self.size))
            .finish()
    }
}

impl<'a> FilePartPacket<'a> {
    pub(crate) fn new(buffer: &'a [u8], size: u32) -> Self {
        Self { buffer, size }
    }
}

impl<'a> OutboundPacket for FilePartPacket<'a> {
    fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; self.size as usize];
        let bytes_to_copy = std::cmp::min(self.buffer.len(), self.size as usize);
        data[..bytes_to_copy].copy_from_slice(&self.buffer[..bytes_to_copy]);
        data
    }
}

pub(crate) struct PitDataPacket {
    pub data: Vec<u8>,
}

impl Debug for PitDataPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PitDataPacket")
            .field("data", &format_args!("[u8; {}]", &self.data.len()))
            .finish()
    }
}

impl InboundPacket for PitDataPacket {
    const SIZE: usize = 500;

    fn unpack(buffer: &[u8]) -> Result<Self, String> {
        Ok(Self {
            data: buffer.to_vec(),
        })
    }
}

#[derive(BinRead, Debug)]
#[brw(little)]
pub(crate) struct Response {
    pub response_type: u32,
    pub value: u32,
}

impl InboundPacket for Response {
    const SIZE: usize = 8;

    fn unpack(buffer: &[u8]) -> Result<Self, String> {
        if buffer.len() != Self::SIZE {
            return Err(format!(
                "Incorrect packet size received - expected size = {}, received size = {}.",
                Self::SIZE,
                buffer.len()
            ));
        }
        let mut reader = Cursor::new(buffer);
        Self::read_le(&mut reader).map_err(|_| "Failed to unpack packet".to_string())
    }
}
