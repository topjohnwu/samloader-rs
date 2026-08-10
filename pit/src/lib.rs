// Copyright 2026 John "topjohnwu" Wu
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

//! Crate for parsing and manipulation of Partition Information Table (PIT) files
//! used by Samsung devices.

#![deny(missing_docs)]

use binrw::{BinRead, BinWrite, binrw, io::Cursor};
use modular_bitfield::prelude::*;
use std::borrow::Cow;
use std::ffi::CStr;

const FILE_IDENTIFIER: u32 = 0x12349876;
const HEADER_DATA_SIZE: u32 = 28;

const DATA_SIZE: usize = 132;
const PARTITION_NAM_LENGTH: usize = 32;
const FLASH_FILENAME_LENGTH: usize = 32;
const FOTA_FILENAME_LENGTH: usize = 32;

/// A fixed-length null-padded ASCII/UTF-8 string used in PIT binary headers.
#[derive(BinRead, BinWrite, PartialEq, Eq)]
pub struct FixedString<const LEN: usize> {
    data: [u8; LEN],
}

impl<const LEN: usize> FixedString<LEN> {
    /// Converts the fixed-length byte buffer to a lossy standard Rust string.
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

/// Represents the target processor for the binary image.
#[derive(BinRead, BinWrite, PartialEq, Eq, Copy, Clone, Debug)]
#[brw(repr = u32)]
pub enum BinaryType {
    /// Application processor (AP / system firmware).
    ApplicationProcessor = 0,
    /// Communication processor (CP / modem baseband).
    CommunicationProcessor = 1,
}

/// Represents the physical flash/storage media type on the device.
#[derive(BinRead, BinWrite, PartialEq, Eq, Copy, Clone, Debug)]
#[brw(repr = u32)]
pub enum DeviceType {
    /// OneNAND flash storage.
    OneNand = 0,
    /// Standard file-system or FAT partition.
    File = 1,
    /// MultiMediaCard / eMMC flash storage (sector size of 512 bytes).
    MMC = 2,
    /// All storage devices.
    All = 3,
    /// Universal Flash Storage (sector size of 4096 bytes).
    UFS = 8,
}

/// Partition block properties and flags.
#[bitfield(bits = 32)]
#[derive(BinRead, BinWrite, Copy, Clone, Default, PartialEq, Eq)]
#[br(map = |x: u32| Self::from_bytes(x.to_le_bytes()))]
#[bw(map = |x: &Self| u32::from_le_bytes(x.into_bytes()))]
pub struct Attribute {
    /// Whether the partition is writable.
    pub write: bool,
    /// Whether the partition has Samsung's sector translation layer (STL).
    pub stl: bool,
    #[skip]
    __: B30,
}

/// Partition update and firmware attribute flags.
#[bitfield(bits = 32)]
#[derive(BinRead, BinWrite, Copy, Clone, Default, PartialEq, Eq)]
#[br(map = |x: u32| Self::from_bytes(x.to_le_bytes()))]
#[bw(map = |x: &Self| u32::from_le_bytes(x.into_bytes()))]
pub struct UpdateAttribute {
    /// Whether the partition is updated via FOTA.
    pub fota: bool,
    /// Whether the partition is cryptographically secured.
    pub secure: bool,
    #[skip]
    __: B30,
}

/// Represents an individual partition entry in the Partition Information Table (PIT).
#[binrw]
#[derive(PartialEq, Eq)]
#[brw(little)]
pub struct PitEntry {
    /// Target processor for the partition.
    pub binary_type: BinaryType,
    /// Flash storage media type.
    pub device_type: DeviceType,
    /// Unique identifier for the partition.
    pub identifier: u32,
    /// Block/write attributes.
    pub attributes: Attribute,
    /// Update and FOTA attributes.
    pub update_attributes: UpdateAttribute,
    /// Starting block offset or logical block size.
    pub block_size_or_offset: u32,
    /// Total block count allocated to the partition.
    pub block_count: u32,
    /// Obsolete file offset field.
    pub file_offset: u32,
    /// Obsolete file size field.
    pub file_size: u32,
    /// Name of the partition.
    pub partition_name: FixedString<PARTITION_NAM_LENGTH>,
    /// Target flashing image filename.
    pub flash_filename: FixedString<FLASH_FILENAME_LENGTH>,
    /// FOTA payload package filename.
    pub fota_filename: FixedString<FOTA_FILENAME_LENGTH>,
}

impl PitEntry {
    /// Calculates the size of the partition in bytes based on sector counts of MMC (512B) or UFS (4096B).
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

/// Represents the parsed layout and headers of a Partition Information Table (PIT).
#[binrw]
#[derive(PartialEq, Eq)]
#[brw(little)]
pub struct PitData {
    /// Magic identifier for verification (always 0x12349876).
    #[br(temp, assert(magic == FILE_IDENTIFIER))]
    #[bw(calc = FILE_IDENTIFIER)]
    pub magic: u32,
    /// Number of partition entries contained in the PIT.
    #[br(temp)]
    #[bw(calc = entries.len() as u32)]
    pub entry_count: u32,
    /// An unknown reference/config string identifier.
    pub com_tar2: FixedString<8>,
    /// CPU or bootloader target hardware tag.
    pub cpu_bl_id: FixedString<8>,
    /// Logical partition units count.
    pub lu_count: u16,
    /// The collection of partition records.
    #[br(pad_before = 2, count = entry_count)]
    #[bw(pad_before = 2)]
    pub entries: Vec<PitEntry>,
}

impl PitData {
    /// Parses binary PIT bytes into a structured `PitData` instance.
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

    /// Finds a partition entry by its string name.
    pub fn find_entry_by_name(&self, name: &str) -> Option<&PitEntry> {
        self.entries.iter().find(|e| e.partition_name == name)
    }

    /// Finds a partition entry by its numeric partition identifier.
    pub fn find_entry_by_id(&self, id: u32) -> Option<&PitEntry> {
        self.entries.iter().find(|e| e.identifier == id)
    }

    /// Packs and serializes the structured PIT representation back into standard binary bytes.
    pub fn pack(&self) -> Result<Vec<u8>, binrw::Error> {
        let mut cursor = Cursor::new(Vec::new());
        self.write(&mut cursor)?;
        Ok(cursor.into_inner())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pit_repack() {
        let original_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/Q7MQ_EUR_OPENX.pit"
        ));
        let pit_data = PitData::new(original_bytes).expect("Failed to parse original PIT");
        let repacked_bytes = pit_data.pack().expect("Failed to repack PIT");

        let entry_count = u32::from_le_bytes(original_bytes[4..8].try_into().unwrap());
        let expected_data_size = HEADER_DATA_SIZE as usize + (entry_count as usize * DATA_SIZE);

        // Verify that the packed bytes are exactly of the expected length
        assert_eq!(repacked_bytes.len(), expected_data_size);

        // Note: The original file contains an appended 512-byte Samsung cryptographic
        // signature ("SignerVer02...") at the end, which is ignored by PitData during
        // parsing and not serialized by PitData::pack(). We verify that the actual
        // PIT data itself matches the original file exactly byte-for-byte.
        assert_eq!(&repacked_bytes, &original_bytes[..expected_data_size]);
    }
}
