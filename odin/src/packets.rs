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
    Lz4Part { sequence_byte_count: u32 },
    #[brw(magic = 7u32)]
    Lz4End(FileTransferEnd),
}

#[derive(BinRead, BinWrite, Debug)]
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

impl FileTransferEnd {
    pub(crate) fn new(
        sequence_byte_count: u32,
        pit_entry: &PitEntry,
        is_last_sequence: bool,
    ) -> Self {
        let is_last_sequence = if is_last_sequence { 1 } else { 0 };
        match pit_entry.binary_type {
            BinaryType::ApplicationProcessor => Self::Phone {
                sequence_byte_count,
                binary_type: pit_entry.binary_type,
                device_type: pit_entry.device_type,
                partition_identifier: pit_entry.identifier,
                is_last_sequence,
            },
            BinaryType::CommunicationProcessor => Self::Modem {
                sequence_byte_count,
                binary_type: pit_entry.binary_type,
                device_type: pit_entry.device_type,
                is_last_sequence,
            },
        }
    }
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub(crate) enum EndSessionRequest {
    #[brw(magic = 0u32)]
    EndSession,
    #[brw(magic = 1u32)]
    RebootDevice,
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

    pub(crate) fn end_session() -> Self {
        Self::EndSession(EndSessionRequest::EndSession)
    }

    pub(crate) fn reboot_device() -> Self {
        Self::EndSession(EndSessionRequest::RebootDevice)
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

    pub(crate) fn flash_part_file_transfer(sequence_byte_count: u32, lz4: bool) -> Self {
        Self::FileTransfer(if lz4 {
            FileTransferRequest::Lz4Part {
                sequence_byte_count,
            }
        } else {
            FileTransferRequest::Part {
                sequence_byte_count,
            }
        })
    }

    pub(crate) fn end_file_transfer(
        sequence_byte_count: u32,
        pit_entry: &PitEntry,
        is_last_sequence: bool,
        lz4: bool,
    ) -> Self {
        let end = FileTransferEnd::new(sequence_byte_count, pit_entry, is_last_sequence);
        Self::FileTransfer(if lz4 {
            FileTransferRequest::Lz4End(end)
        } else {
            FileTransferRequest::End(end)
        })
    }

    pub(crate) fn expected_response_type(&self) -> u32 {
        match self {
            Self::Session(_) => RESPONSE_TYPE_SESSION_SETUP,
            Self::PitFile(_) => RESPONSE_TYPE_PIT_FILE,
            Self::FileTransfer(_) => RESPONSE_TYPE_FILE_TRANSFER,
            Self::EndSession(_) => RESPONSE_TYPE_END_SESSION,
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
}
