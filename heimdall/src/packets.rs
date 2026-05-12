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

pub const CONTROL_TYPE_SESSION: u32 = 0x64;
pub const CONTROL_TYPE_PIT_FILE: u32 = 0x65;
pub const CONTROL_TYPE_FILE_TRANSFER: u32 = 0x66;
pub const CONTROL_TYPE_END_SESSION: u32 = 0x67;

pub const REQUEST_BEGIN_SESSION: u32 = 0;
pub const REQUEST_DEVICE_TYPE: u32 = 1;
pub const REQUEST_TOTAL_BYTES: u32 = 2;
pub const REQUEST_FILE_PART_SIZE: u32 = 5;

pub const REQUEST_PIT_FILE_FLASH: u32 = 0;
pub const REQUEST_PIT_FILE_DUMP: u32 = 1;
pub const REQUEST_PIT_FILE_PART: u32 = 2;
pub const REQUEST_PIT_FILE_END: u32 = 3;

pub const REQUEST_FILE_TRANSFER_FLASH: u32 = 0;
pub const REQUEST_FILE_TRANSFER_DUMP: u32 = 1;
pub const REQUEST_FILE_TRANSFER_PART: u32 = 2;
pub const REQUEST_FILE_TRANSFER_END: u32 = 3;

pub const RESPONSE_TYPE_SEND_FILE_PART: u32 = 0x00;
pub const RESPONSE_TYPE_SESSION_SETUP: u32 = 0x64;
pub const RESPONSE_TYPE_PIT_FILE: u32 = 0x65;
pub const RESPONSE_TYPE_FILE_TRANSFER: u32 = 0x66;
pub const RESPONSE_TYPE_END_SESSION: u32 = 0x67;

pub const DESTINATION_PHONE: u32 = 0x00;
pub const DESTINATION_MODEM: u32 = 0x01;

pub fn pack_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset+4].copy_from_slice(&value.to_le_bytes());
}

pub fn unpack_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset+4].try_into().unwrap())
}

pub fn create_control_packet(control_type: u32) -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    pack_u32(&mut data, 0, control_type);
    data
}

pub fn create_session_setup_packet(request: u32) -> Vec<u8> {
    let mut data = create_control_packet(CONTROL_TYPE_SESSION);
    pack_u32(&mut data, 4, request);
    data
}

pub fn create_begin_session_packet() -> Vec<u8> {
    let mut data = create_session_setup_packet(REQUEST_BEGIN_SESSION);
    pack_u32(&mut data, 8, 0x04); // Odin protocol version
    data
}

pub fn create_total_bytes_packet(total_bytes: u64) -> Vec<u8> {
    let mut data = create_session_setup_packet(REQUEST_TOTAL_BYTES);
    pack_u32(&mut data, 8, total_bytes as u32);
    pack_u32(&mut data, 12, (total_bytes >> 32) as u32);
    data
}

pub fn create_file_part_size_packet(size: u32) -> Vec<u8> {
    let mut data = create_session_setup_packet(REQUEST_FILE_PART_SIZE);
    pack_u32(&mut data, 8, size);
    data
}

pub fn create_end_session_packet(request: u32) -> Vec<u8> {
    let mut data = create_control_packet(CONTROL_TYPE_END_SESSION);
    pack_u32(&mut data, 4, request);
    data
}

pub fn create_pit_file_packet(request: u32) -> Vec<u8> {
    let mut data = create_control_packet(CONTROL_TYPE_PIT_FILE);
    pack_u32(&mut data, 4, request);
    data
}

pub fn create_flash_part_pit_file_packet(size: u32) -> Vec<u8> {
    let mut data = create_pit_file_packet(REQUEST_PIT_FILE_PART);
    pack_u32(&mut data, 8, size);
    data
}

pub fn create_dump_part_pit_file_packet(part: u32) -> Vec<u8> {
    let mut data = create_pit_file_packet(REQUEST_PIT_FILE_PART);
    pack_u32(&mut data, 8, part);
    data
}

pub fn create_end_pit_file_transfer_packet(size: u32) -> Vec<u8> {
    let mut data = create_pit_file_packet(REQUEST_PIT_FILE_END);
    pack_u32(&mut data, 8, size);
    data
}

pub fn create_file_transfer_packet(request: u32) -> Vec<u8> {
    let mut data = create_control_packet(CONTROL_TYPE_FILE_TRANSFER);
    pack_u32(&mut data, 4, request);
    data
}

pub fn create_flash_part_file_transfer_packet(sequence_byte_count: u32) -> Vec<u8> {
    let mut data = create_file_transfer_packet(REQUEST_FILE_TRANSFER_PART);
    pack_u32(&mut data, 8, sequence_byte_count);
    data
}

pub fn create_end_modem_file_transfer_packet(sequence_byte_count: u32, unknown1: u32, device_type: u32, end_of_file: bool) -> Vec<u8> {
    let mut data = create_file_transfer_packet(REQUEST_FILE_TRANSFER_END);
    pack_u32(&mut data, 8, DESTINATION_MODEM);
    pack_u32(&mut data, 12, sequence_byte_count);
    pack_u32(&mut data, 16, unknown1);
    pack_u32(&mut data, 20, device_type);
    pack_u32(&mut data, 24, if end_of_file { 1 } else { 0 });
    data
}

pub fn create_end_phone_file_transfer_packet(sequence_byte_count: u32, unknown1: u32, device_type: u32, file_identifier: u32, end_of_file: bool) -> Vec<u8> {
    let mut data = create_file_transfer_packet(REQUEST_FILE_TRANSFER_END);
    pack_u32(&mut data, 8, DESTINATION_PHONE);
    pack_u32(&mut data, 12, sequence_byte_count);
    pack_u32(&mut data, 16, unknown1);
    pack_u32(&mut data, 20, device_type);
    pack_u32(&mut data, 24, file_identifier);
    pack_u32(&mut data, 28, if end_of_file { 1 } else { 0 });
    data
}

pub fn create_device_type_packet() -> Vec<u8> {
    create_session_setup_packet(REQUEST_DEVICE_TYPE)
}

pub fn create_send_file_part_packet(buffer: &[u8], size: u32) -> Vec<u8> {
    let mut data = vec![0u8; size as usize];
    let bytes_to_copy = std::cmp::min(buffer.len(), size as usize);
    data[..bytes_to_copy].copy_from_slice(&buffer[..bytes_to_copy]);
    data
}

pub struct Response {
    pub response_type: u32,
    pub value: u32,
}

pub fn unpack_response(data: &[u8], expected_type: u32) -> Result<u32, u32> {
    let received_type = unpack_u32(data, 0);
    let value = unpack_u32(data, 4);
    if received_type == expected_type {
        Ok(value)
    } else {
        Err(received_type)
    }
}
