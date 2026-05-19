// Copyright 2026 Google LLC
// Copyright 2021-2024 Henrik Grimler
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

use binrw::{binrw, io::Cursor, BinRead, BinWrite};
use modular_bitfield::prelude::*;
use std::borrow::Cow;
use std::ffi::CStr;

const FILE_IDENTIFIER: u32 = 0x12349876;
const HEADER_DATA_SIZE: u32 = 28;
const PADDED_SIZE_MULTIPLICAND: u32 = 4096;

const DATA_SIZE: usize = 132;
const PARTITION_NAM_LENGTH: usize = 32;
const FLASH_FILENAME_LENGTH: usize = 32;
const FOTA_FILENAME_LENGTH: usize = 32;

#[derive(BinRead, BinWrite, PartialEq, Eq)]
pub struct FixedString<const LEN: usize> {
    pub data: [u8; LEN],
}

impl<const LEN: usize> FixedString<LEN> {
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        match CStr::from_bytes_until_nul(&self.data) {
            Ok(cstr) => cstr.to_string_lossy(),
            Err(_) => String::from_utf8_lossy(&self.data),
        }
    }
}

impl<const LEN: usize> Default for FixedString<LEN> {
    fn default() -> Self {
        Self { data: [0u8; LEN] }
    }
}

impl<const LEN: usize> std::fmt::Display for FixedString<LEN> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

impl<const LEN: usize> PartialEq<&str> for FixedString<LEN> {
    fn eq(&self, other: &&str) -> bool {
        self.to_string_lossy() == *other
    }
}

#[derive(BinRead, BinWrite, PartialEq, Eq, Copy, Clone, Debug)]
#[brw(repr = u32)]
pub enum BinaryType {
    ApplicationProcessor = 0,
    CommunicationProcessor = 1,
}

#[derive(BinRead, BinWrite, PartialEq, Eq, Copy, Clone, Debug)]
#[brw(repr = u32)]
pub enum DeviceType {
    OneNand = 0,
    File = 1,
    MMC = 2,
    All = 3,
    UFS = 8,
}

#[bitfield(bits = 32)]
#[derive(BinRead, BinWrite, Copy, Clone, Default, PartialEq, Eq)]
#[br(map = |x: u32| Self::from_bytes(x.to_le_bytes()))]
#[bw(map = |x: &Self| u32::from_le_bytes(x.into_bytes()))]
pub struct Attribute {
    pub write: bool,
    pub stl: bool,
    #[skip]
    __: B30,
}

#[bitfield(bits = 32)]
#[derive(BinRead, BinWrite, Copy, Clone, Default, PartialEq, Eq)]
#[br(map = |x: u32| Self::from_bytes(x.to_le_bytes()))]
#[bw(map = |x: &Self| u32::from_le_bytes(x.into_bytes()))]
pub struct UpdateAttribute {
    pub fota: bool,
    pub secure: bool,
    #[skip]
    __: B30,
}

#[binrw]
#[derive(PartialEq, Eq)]
#[brw(little)]
pub struct PitEntry {
    pub binary_type: BinaryType,
    pub device_type: DeviceType,
    pub identifier: u32,
    pub attributes: Attribute,
    pub update_attributes: UpdateAttribute,
    pub block_size_or_offset: u32,
    pub block_count: u32,
    pub file_offset: u32,
    pub file_size: u32,
    pub partition_name: FixedString<PARTITION_NAM_LENGTH>,
    pub flash_filename: FixedString<FLASH_FILENAME_LENGTH>,
    pub fota_filename: FixedString<FOTA_FILENAME_LENGTH>,
}

impl PitEntry {
    pub fn partition_size(&self) -> u64 {
        let block_size = match self.device_type {
            DeviceType::MMC => 512,
            DeviceType::UFS => 4096,
            _ => {
                return 0;
            }
        };
        block_size * self.block_count as u64
    }
}

#[binrw]
#[derive(PartialEq, Eq)]
#[brw(little)]
pub struct PitData {
    #[br(temp, assert(magic == FILE_IDENTIFIER))]
    #[bw(calc = FILE_IDENTIFIER)]
    pub magic: u32,
    #[br(temp)]
    #[bw(calc = entries.len() as u32)]
    pub entry_count: u32,
    pub com_tar2: FixedString<8>,
    pub cpu_bl_id: FixedString<8>,
    pub lu_count: u16,
    #[br(pad_before = 2, count = entry_count)]
    #[bw(pad_before = 2)]
    pub entries: Vec<PitEntry>,
}

impl PitData {
    pub fn new(data: &[u8]) -> Result<Self, binrw::Error> {
        if data.len() < 8 {
            return Err(binrw::Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Buffer too small for PIT header",
            )));
        }

        let entry_count = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let expected_size = HEADER_DATA_SIZE as usize + (entry_count as usize * DATA_SIZE);

        if data.len() < expected_size {
            return Err(binrw::Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "Buffer size ({}) is smaller than declared PIT size ({})",
                    data.len(),
                    expected_size
                ),
            )));
        }

        let mut cursor = Cursor::new(&data[..expected_size]);
        Self::read(&mut cursor)
    }

    fn get_data_size(&self) -> u32 {
        HEADER_DATA_SIZE + (self.entries.len() * DATA_SIZE) as u32
    }

    pub fn get_padded_size(&self) -> u32 {
        let data_size = self.get_data_size();
        let mut padded_size = (data_size / PADDED_SIZE_MULTIPLICAND) * PADDED_SIZE_MULTIPLICAND;
        if !data_size.is_multiple_of(PADDED_SIZE_MULTIPLICAND) {
            padded_size += PADDED_SIZE_MULTIPLICAND;
        }
        padded_size
    }

    pub fn find_entry_by_name(&self, name: &str) -> Option<&PitEntry> {
        self.entries.iter().find(|e| e.partition_name == name)
    }

    pub fn find_entry_by_id(&self, id: u32) -> Option<&PitEntry> {
        self.entries.iter().find(|e| e.identifier == id)
    }

    pub fn pack(&self, data: &mut [u8]) {
        let mut cursor = Cursor::new(data);
        if let Err(e) = self.write(&mut cursor) {
            eprintln!("Failed to pack PIT: {}", e);
        }
    }
}

impl std::fmt::Display for PitData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "--- PIT Header ---")?;
        writeln!(f, "Entry Count: {}", self.entries.len())?;
        writeln!(f, "Unknown string: {}", self.com_tar2)?;
        writeln!(f, "CPU/bootloader tag: {}", self.cpu_bl_id)?;
        writeln!(f, "Logic unit count: {}", self.lu_count)?;

        for (i, entry) in self.entries.iter().enumerate() {
            writeln!(f, "\n\n--- Entry #{} ---", i)?;

            let binary_type_str = match entry.binary_type {
                BinaryType::ApplicationProcessor => "AP",
                BinaryType::CommunicationProcessor => "CP",
            };
            writeln!(
                f,
                "Binary Type: {} ({})",
                entry.binary_type as u32, binary_type_str
            )?;

            let device_type_str = match entry.device_type {
                DeviceType::OneNand => "OneNAND",
                DeviceType::File => "File/FAT",
                DeviceType::MMC => "MMC",
                DeviceType::All => "All (?)",
                DeviceType::UFS => "UFS",
            };
            writeln!(
                f,
                "Device Type: {} ({})",
                entry.device_type as u32, device_type_str
            )?;

            writeln!(f, "Identifier: {}", entry.identifier)?;

            let mut attr_str = String::new();
            if entry.attributes.stl() {
                attr_str.push_str("STL ");
            }
            if entry.attributes.write() {
                attr_str.push_str("Read/Write");
            } else {
                attr_str.push_str("Read-Only");
            }
            writeln!(
                f,
                "Attributes: {} ({})",
                u32::from_le_bytes(entry.attributes.into_bytes()),
                attr_str
            )?;

            let mut update_attr_str = String::new();
            let update_attributes_u32 = u32::from_le_bytes(entry.update_attributes.into_bytes());
            if update_attributes_u32 != 0 {
                if entry.update_attributes.fota() {
                    if entry.update_attributes.secure() {
                        update_attr_str.push_str(" (FOTA, Secure)");
                    } else {
                        update_attr_str.push_str(" (FOTA)");
                    }
                } else if entry.update_attributes.secure() {
                    update_attr_str.push_str(" (Secure)");
                }
            }
            writeln!(
                f,
                "Update Attributes: {}{}",
                update_attributes_u32, update_attr_str
            )?;

            writeln!(
                f,
                "Partition Block Size/Offset: {}",
                entry.block_size_or_offset
            )?;
            writeln!(f, "Partition Block Count: {}", entry.block_count)?;
            writeln!(f, "File Offset (Obsolete): {}", entry.file_offset)?;
            writeln!(f, "File Size (Obsolete): {}", entry.file_size)?;
            writeln!(f, "Partition Name: {}", entry.partition_name)?;
            writeln!(f, "Flash Filename: {}", entry.flash_filename)?;
            writeln!(f, "FOTA Filename: {}", entry.fota_filename)?;
        }
        writeln!(f)
    }
}
