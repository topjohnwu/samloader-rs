// Copyright 2026 Google LLC
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

pub const CONTROL_TYPE_SESSION: u32 = 0x64;
pub const CONTROL_TYPE_PIT_FILE: u32 = 0x65;
pub const CONTROL_TYPE_FILE_TRANSFER: u32 = 0x66;
pub const CONTROL_TYPE_END_SESSION: u32 = 0x67;

pub const REQUEST_BEGIN_SESSION: u32 = 0;
pub const REQUEST_TOTAL_BYTES: u32 = 2;
pub const REQUEST_FILE_PART_SIZE: u32 = 5;

pub const REQUEST_PIT_FILE_FLASH: u32 = 0;
pub const REQUEST_PIT_FILE_DUMP: u32 = 1;
pub const REQUEST_PIT_FILE_PART: u32 = 2;
pub const REQUEST_PIT_FILE_END: u32 = 3;

pub const REQUEST_FILE_TRANSFER_FLASH: u32 = 0;
#[allow(dead_code)]
pub const REQUEST_FILE_TRANSFER_DUMP: u32 = 1;
pub const REQUEST_FILE_TRANSFER_PART: u32 = 2;
pub const REQUEST_FILE_TRANSFER_END: u32 = 3;

pub const RESPONSE_TYPE_SEND_FILE_PART: u32 = 0x00;
pub const RESPONSE_TYPE_SESSION_SETUP: u32 = 0x64;
pub const RESPONSE_TYPE_PIT_FILE: u32 = 0x65;
pub const RESPONSE_TYPE_FILE_TRANSFER: u32 = 0x66;
#[allow(dead_code)]
pub const RESPONSE_TYPE_END_SESSION: u32 = 0x67;

pub const DESTINATION_PHONE: u32 = 0x00;
pub const DESTINATION_MODEM: u32 = 0x01;

#[allow(dead_code)]
#[derive(BinWrite)]
#[brw(little)]
pub struct ControlPacket {
    pub control_type: u32,
    #[brw(pad_after = 1020)]
    pub _padding: (),
}

impl ControlPacket {
    #[allow(dead_code)]
    pub fn create(control_type: u32) -> Vec<u8> {
        to_vec(ControlPacket {
            control_type,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct SessionSetupPacket {
    pub control_type: u32,
    pub request: u32,
    #[brw(pad_after = 1016)]
    pub _padding: (),
}

impl SessionSetupPacket {
    pub fn create_end_session(request: u32) -> Vec<u8> {
        to_vec(SessionSetupPacket {
            control_type: CONTROL_TYPE_END_SESSION,
            request,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct BeginSessionPacket {
    pub control_type: u32,
    pub request: u32,
    pub protocol_version: u32,
    #[brw(pad_after = 1012)]
    pub _padding: (),
}

impl BeginSessionPacket {
    pub fn create() -> Vec<u8> {
        to_vec(BeginSessionPacket {
            control_type: CONTROL_TYPE_SESSION,
            request: REQUEST_BEGIN_SESSION,
            protocol_version: 0x04,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct TotalBytesPacket {
    pub control_type: u32,
    pub request: u32,
    pub total_bytes: u64,
    #[brw(pad_after = 1008)]
    pub _padding: (),
}

impl TotalBytesPacket {
    pub fn create(total_bytes: u64) -> Vec<u8> {
        to_vec(TotalBytesPacket {
            control_type: CONTROL_TYPE_SESSION,
            request: REQUEST_TOTAL_BYTES,
            total_bytes,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct FilePartSizePacket {
    pub control_type: u32,
    pub request: u32,
    pub size: u32,
    #[brw(pad_after = 1012)]
    pub _padding: (),
}

impl FilePartSizePacket {
    pub fn create(size: u32) -> Vec<u8> {
        to_vec(FilePartSizePacket {
            control_type: CONTROL_TYPE_SESSION,
            request: REQUEST_FILE_PART_SIZE,
            size,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct PitFilePacket {
    pub control_type: u32,
    pub request: u32,
    #[brw(pad_after = 1016)]
    pub _padding: (),
}

impl PitFilePacket {
    pub fn create(request: u32) -> Vec<u8> {
        to_vec(PitFilePacket {
            control_type: CONTROL_TYPE_PIT_FILE,
            request,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct FlashPartPitFilePacket {
    pub control_type: u32,
    pub request: u32,
    pub size: u32,
    #[brw(pad_after = 1012)]
    pub _padding: (),
}

impl FlashPartPitFilePacket {
    pub fn create(size: u32) -> Vec<u8> {
        to_vec(FlashPartPitFilePacket {
            control_type: CONTROL_TYPE_PIT_FILE,
            request: REQUEST_PIT_FILE_PART,
            size,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct DumpPartPitFilePacket {
    pub control_type: u32,
    pub request: u32,
    pub part: u32,
    #[brw(pad_after = 1012)]
    pub _padding: (),
}

impl DumpPartPitFilePacket {
    pub fn create(part: u32) -> Vec<u8> {
        to_vec(DumpPartPitFilePacket {
            control_type: CONTROL_TYPE_PIT_FILE,
            request: REQUEST_PIT_FILE_PART,
            part,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct EndPitFileTransferPacket {
    pub control_type: u32,
    pub request: u32,
    pub size: u32,
    #[brw(pad_after = 1012)]
    pub _padding: (),
}

impl EndPitFileTransferPacket {
    pub fn create(size: u32) -> Vec<u8> {
        to_vec(EndPitFileTransferPacket {
            control_type: CONTROL_TYPE_PIT_FILE,
            request: REQUEST_PIT_FILE_END,
            size,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct FileTransferPacket {
    pub control_type: u32,
    pub request: u32,
    #[brw(pad_after = 1016)]
    pub _padding: (),
}

impl FileTransferPacket {
    pub fn create(request: u32) -> Vec<u8> {
        to_vec(FileTransferPacket {
            control_type: CONTROL_TYPE_FILE_TRANSFER,
            request,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct FlashPartFileTransferPacket {
    pub control_type: u32,
    pub request: u32,
    pub sequence_byte_count: u32,
    #[brw(pad_after = 1012)]
    pub _padding: (),
}

impl FlashPartFileTransferPacket {
    pub fn create(sequence_byte_count: u32) -> Vec<u8> {
        to_vec(FlashPartFileTransferPacket {
            control_type: CONTROL_TYPE_FILE_TRANSFER,
            request: REQUEST_FILE_TRANSFER_PART,
            sequence_byte_count,
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct EndModemFileTransferPacket {
    pub control_type: u32,
    pub request: u32,
    pub destination: u32,
    pub sequence_byte_count: u32,
    pub unknown1: u32,
    pub device_type: u32,
    pub end_of_file: u32,
    #[brw(pad_after = 996)]
    pub _padding: (),
}

impl EndModemFileTransferPacket {
    pub fn create(sequence_byte_count: u32, unknown1: u32, device_type: u32, end_of_file: bool) -> Vec<u8> {
        to_vec(EndModemFileTransferPacket {
            control_type: CONTROL_TYPE_FILE_TRANSFER,
            request: REQUEST_FILE_TRANSFER_END,
            destination: DESTINATION_MODEM,
            sequence_byte_count,
            unknown1,
            device_type,
            end_of_file: if end_of_file { 1 } else { 0 },
            _padding: (),
        })
    }
}

#[derive(BinWrite)]
#[brw(little)]
pub struct EndPhoneFileTransferPacket {
    pub control_type: u32,
    pub request: u32,
    pub destination: u32,
    pub sequence_byte_count: u32,
    pub unknown1: u32,
    pub device_type: u32,
    pub file_identifier: u32,
    pub end_of_file: u32,
    #[brw(pad_after = 992)]
    pub _padding: (),
}

impl EndPhoneFileTransferPacket {
    pub fn create(sequence_byte_count: u32, unknown1: u32, device_type: u32, file_identifier: u32, end_of_file: bool) -> Vec<u8> {
        to_vec(EndPhoneFileTransferPacket {
            control_type: CONTROL_TYPE_FILE_TRANSFER,
            request: REQUEST_FILE_TRANSFER_END,
            destination: DESTINATION_PHONE,
            sequence_byte_count,
            unknown1,
            device_type,
            file_identifier,
            end_of_file: if end_of_file { 1 } else { 0 },
            _padding: (),
        })
    }
}

#[derive(BinRead)]
#[brw(little)]
pub struct Response {
    pub response_type: u32,
    pub value: u32,
}

impl Response {
    pub fn unpack(data: &[u8], expected_type: u32) -> Result<u32, u32> {
        let mut reader = Cursor::new(data);
        let response = Response::read_le(&mut reader).map_err(|_| 0u32)?;
        if response.response_type == expected_type {
            Ok(response.value)
        } else {
            Err(response.response_type)
        }
    }
}

fn to_vec<T: BinWrite>(packet: T) -> Vec<u8>
where
    for<'a> T::Args<'a>: Default,
{
    let mut writer = Cursor::new(Vec::with_capacity(1024));
    packet.write_le(&mut writer).expect("Failed to write packet");
    writer.into_inner()
}

pub fn create_send_file_part_packet(buffer: &[u8], size: u32) -> Vec<u8> {
    let mut data = vec![0u8; size as usize];
    let bytes_to_copy = std::cmp::min(buffer.len(), size as usize);
    data[..bytes_to_copy].copy_from_slice(&buffer[..bytes_to_copy]);
    data
}
