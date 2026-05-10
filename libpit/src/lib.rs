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

pub const FILE_IDENTIFIER: u32 = 0x12349876;
pub const HEADER_DATA_SIZE: u32 = 28;
pub const PADDED_SIZE_MULTIPLICAND: u32 = 4096;

pub const DATA_SIZE: usize = 132;
pub const PARTITION_NAME_MAX_LENGTH: usize = 32;
pub const FLASH_FILENAME_MAX_LENGTH: usize = 32;
pub const FOTA_FILENAME_MAX_LENGTH: usize = 32;

#[binrw]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct PitEntry {
    pub binary_type: u32,
    pub device_type: u32,
    pub identifier: u32,
    pub attributes: u32,
    pub update_attributes: u32,
    pub block_size_or_offset: u32,
    pub block_count: u32,
    pub file_offset: u32,
    pub file_size: u32,
    #[br(map = |x: [u8; PARTITION_NAME_MAX_LENGTH]| String::from_utf8_lossy(&x).trim_matches('\0').to_string())]
    #[bw(map = |x: &String| {
        let mut buf = [0u8; PARTITION_NAME_MAX_LENGTH];
        let bytes = x.as_bytes();
        let len = std::cmp::min(bytes.len(), PARTITION_NAME_MAX_LENGTH);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    })]
    pub partition_name: String,
    #[br(map = |x: [u8; FLASH_FILENAME_MAX_LENGTH]| String::from_utf8_lossy(&x).trim_matches('\0').to_string())]
    #[bw(map = |x: &String| {
        let mut buf = [0u8; FLASH_FILENAME_MAX_LENGTH];
        let bytes = x.as_bytes();
        let len = std::cmp::min(bytes.len(), FLASH_FILENAME_MAX_LENGTH);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    })]
    pub flash_filename: String,
    #[br(map = |x: [u8; FOTA_FILENAME_MAX_LENGTH]| String::from_utf8_lossy(&x).trim_matches('\0').to_string())]
    #[bw(map = |x: &String| {
        let mut buf = [0u8; FOTA_FILENAME_MAX_LENGTH];
        let bytes = x.as_bytes();
        let len = std::cmp::min(bytes.len(), FOTA_FILENAME_MAX_LENGTH);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    })]
    pub fota_filename: String,
}

#[binrw]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct PitData {
    #[br(temp, assert(magic == FILE_IDENTIFIER))]
    #[bw(calc = FILE_IDENTIFIER)]
    pub magic: u32,
    #[br(temp)]
    #[bw(calc = entries.len() as u32)]
    pub entry_count: u32,
    #[br(map = |x: [u8; 8]| String::from_utf8_lossy(&x).trim_matches('\0').to_string())]
    #[bw(map = |x: &String| {
        let mut buf = [0u8; 8];
        let bytes = x.as_bytes();
        let len = std::cmp::min(bytes.len(), 8);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    })]
    pub com_tar2: String,
    #[br(map = |x: [u8; 8]| String::from_utf8_lossy(&x).trim_matches('\0').to_string())]
    #[bw(map = |x: &String| {
        let mut buf = [0u8; 8];
        let bytes = x.as_bytes();
        let len = std::cmp::min(bytes.len(), 8);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    })]
    pub cpu_bl_id: String,
    pub lu_count: u16,
    #[br(pad_before = 2, count = entry_count)]
    #[bw(pad_before = 2)]
    pub entries: Vec<PitEntry>,
}

impl PitEntry {
    fn is_flashable(&self) -> bool {
        !self.partition_name.is_empty()
    }

    fn get_binary_type(&self) -> u32 {
        self.binary_type
    }
    fn set_binary_type(&mut self, val: u32) {
        self.binary_type = val;
    }

    fn get_device_type(&self) -> u32 {
        self.device_type
    }
    fn set_device_type(&mut self, val: u32) {
        self.device_type = val;
    }

    fn get_identifier(&self) -> u32 {
        self.identifier
    }
    fn set_identifier(&mut self, val: u32) {
        self.identifier = val;
    }

    fn get_attributes(&self) -> u32 {
        self.attributes
    }
    fn set_attributes(&mut self, val: u32) {
        self.attributes = val;
    }

    fn get_update_attributes(&self) -> u32 {
        self.update_attributes
    }
    fn set_update_attributes(&mut self, val: u32) {
        self.update_attributes = val;
    }

    fn get_block_size_or_offset(&self) -> u32 {
        self.block_size_or_offset
    }
    fn set_block_size_or_offset(&mut self, val: u32) {
        self.block_size_or_offset = val;
    }

    fn get_block_count(&self) -> u32 {
        self.block_count
    }
    fn set_block_count(&mut self, val: u32) {
        self.block_count = val;
    }

    fn get_file_offset(&self) -> u32 {
        self.file_offset
    }
    fn set_file_offset(&mut self, val: u32) {
        self.file_offset = val;
    }

    fn get_file_size(&self) -> u32 {
        self.file_size
    }
    fn set_file_size(&mut self, val: u32) {
        self.file_size = val;
    }

    fn get_partition_name(&self) -> String {
        self.partition_name.clone()
    }
    fn set_partition_name(&mut self, name: &str) {
        self.partition_name = name.to_string();
    }

    fn get_flash_filename(&self) -> String {
        self.flash_filename.clone()
    }
    fn set_flash_filename(&mut self, name: &str) {
        self.flash_filename = name.to_string();
    }

    fn get_fota_filename(&self) -> String {
        self.fota_filename.clone()
    }
    fn set_fota_filename(&mut self, name: &str) {
        self.fota_filename = name.to_string();
    }
}

impl PitData {
    fn new_box() -> Box<Self> {
        Box::new(Self::default())
    }

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

    fn get_padded_size(&self) -> u32 {
        let data_size = self.get_data_size();
        let mut padded_size = (data_size / PADDED_SIZE_MULTIPLICAND) * PADDED_SIZE_MULTIPLICAND;
        if data_size % PADDED_SIZE_MULTIPLICAND != 0 {
            padded_size += PADDED_SIZE_MULTIPLICAND;
        }
        padded_size
    }

    fn get_entry_count(&self) -> u32 {
        self.entries.len() as u32
    }

    fn get_lu_count(&self) -> u32 {
        self.lu_count as u32
    }

    fn get_com_tar2(&self) -> String {
        self.com_tar2.clone()
    }

    fn get_cpu_bl_id(&self) -> String {
        self.cpu_bl_id.clone()
    }

    fn get_entry(&self, index: u32) -> *const PitEntry {
        &self.entries[index as usize] as *const _
    }

    fn find_entry_by_name(&self, name: &str) -> *const PitEntry {
        self.entries
            .iter()
            .find(|e| e.partition_name == name)
            .map(|e| e as *const _)
            .unwrap_or(std::ptr::null())
    }

    fn find_entry_by_id(&self, id: u32) -> *const PitEntry {
        self.entries
            .iter()
            .find(|e| e.identifier == id)
            .map(|e| e as *const _)
            .unwrap_or(std::ptr::null())
    }

    fn unpack(&mut self, data: &[u8]) -> bool {
        match Self::new(data) {
            Ok(unpacked) => {
                *self = unpacked;
                true
            }
            Err(_) => false,
        }
    }

    fn pack(&self, data: &mut [u8]) {
        let mut cursor = Cursor::new(data);
        if let Err(e) = self.write(&mut cursor) {
            eprintln!("Failed to pack PIT: {}", e);
        }
    }

    fn matches(&self, other: &PitData) -> bool {
        self == other
    }

    pub fn print(&self) {
        println!("--- PIT Header ---");
        println!("Entry Count: {}", self.entries.len());
        println!("Unknown string: {}", self.com_tar2);
        println!("CPU/bootloader tag: {}", self.cpu_bl_id);
        println!("Logic unit count: {}", self.lu_count);

        for (i, entry) in self.entries.iter().enumerate() {
            println!("\n\n--- Entry #{} ---", i);

            let binary_type_str = match entry.binary_type {
                0 => "AP",
                1 => "CP",
                _ => "Unknown",
            };
            println!("Binary Type: {} ({})", entry.binary_type, binary_type_str);

            let device_type_str = match entry.device_type {
                0 => "OneNAND",
                1 => "File/FAT",
                2 => "MMC",
                3 => "All (?)",
                8 => "UFS",
                _ => "Unknown",
            };
            println!("Device Type: {} ({})", entry.device_type, device_type_str);

            println!("Identifier: {}", entry.identifier);

            let mut attr_str = String::new();
            if entry.attributes & 2 != 0 { // Attribute::STL
                attr_str.push_str("STL ");
            }
            if entry.attributes & 1 != 0 { // Attribute::Write
                attr_str.push_str("Read/Write");
            } else {
                attr_str.push_str("Read-Only");
            }
            println!("Attributes: {} ({})", entry.attributes, attr_str);

            let mut update_attr_str = String::new();
            if entry.update_attributes != 0 {
                if entry.update_attributes & 1 != 0 { // UpdateAttribute::Fota
                    if entry.update_attributes & 2 != 0 { // UpdateAttribute::Secure
                        update_attr_str.push_str(" (FOTA, Secure)");
                    } else {
                        update_attr_str.push_str(" (FOTA)");
                    }
                } else {
                    if entry.update_attributes & 2 != 0 {
                        update_attr_str.push_str(" (Secure)");
                    }
                }
            }
            println!("Update Attributes: {}{}", entry.update_attributes, update_attr_str);

            println!("Partition Block Size/Offset: {}", entry.block_size_or_offset);
            println!("Partition Block Count: {}", entry.block_count);
            println!("File Offset (Obsolete): {}", entry.file_offset);
            println!("File Size (Obsolete): {}", entry.file_size);
            println!("Partition Name: {}", entry.partition_name);
            println!("Flash Filename: {}", entry.flash_filename);
            println!("FOTA Filename: {}", entry.fota_filename);
        }
        println!();
    }
}

#[cxx::bridge(namespace = "libpit")]
pub mod ffi {
    #[repr(u32)]
    enum BinaryType {
        ApplicationProcessor = 0,
        CommunicationProcessor = 1,
    }

    #[repr(u32)]
    enum DeviceType {
        OneNand = 0,
        File = 1,
        MMC = 2,
        All = 3,
        UFS = 8,
    }

    #[repr(u32)]
    enum Attribute {
        Write = 1,
        STL = 2,
    }

    #[repr(u32)]
    enum UpdateAttribute {
        Fota = 1,
        Secure = 2,
    }

    extern "Rust" {
        type PitEntry;

        #[cxx_name = "IsFlashable"]
        fn is_flashable(self: &PitEntry) -> bool;

        #[cxx_name = "GetBinaryType"]
        fn get_binary_type(self: &PitEntry) -> u32;
        #[cxx_name = "SetBinaryType"]
        fn set_binary_type(self: &mut PitEntry, binary_type: u32);

        #[cxx_name = "GetDeviceType"]
        fn get_device_type(self: &PitEntry) -> u32;
        #[cxx_name = "SetDeviceType"]
        fn set_device_type(self: &mut PitEntry, device_type: u32);

        #[cxx_name = "GetIdentifier"]
        fn get_identifier(self: &PitEntry) -> u32;
        #[cxx_name = "SetIdentifier"]
        fn set_identifier(self: &mut PitEntry, identifier: u32);

        #[cxx_name = "GetAttributes"]
        fn get_attributes(self: &PitEntry) -> u32;
        #[cxx_name = "SetAttributes"]
        fn set_attributes(self: &mut PitEntry, attributes: u32);

        #[cxx_name = "GetUpdateAttributes"]
        fn get_update_attributes(self: &PitEntry) -> u32;
        #[cxx_name = "SetUpdateAttributes"]
        fn set_update_attributes(self: &mut PitEntry, update_attributes: u32);

        #[cxx_name = "GetBlockSizeOrOffset"]
        fn get_block_size_or_offset(self: &PitEntry) -> u32;
        #[cxx_name = "SetBlockSizeOrOffset"]
        fn set_block_size_or_offset(self: &mut PitEntry, block_size_or_offset: u32);

        #[cxx_name = "GetBlockCount"]
        fn get_block_count(self: &PitEntry) -> u32;
        #[cxx_name = "SetBlockCount"]
        fn set_block_count(self: &mut PitEntry, block_count: u32);

        #[cxx_name = "GetFileOffset"]
        fn get_file_offset(self: &PitEntry) -> u32;
        #[cxx_name = "SetFileOffset"]
        fn set_file_offset(self: &mut PitEntry, file_offset: u32);

        #[cxx_name = "GetFileSize"]
        fn get_file_size(self: &PitEntry) -> u32;
        #[cxx_name = "SetFileSize"]
        fn set_file_size(self: &mut PitEntry, file_size: u32);

        #[cxx_name = "GetPartitionName"]
        fn get_partition_name(self: &PitEntry) -> String;
        #[cxx_name = "SetPartitionName"]
        fn set_partition_name(self: &mut PitEntry, name: &str);

        #[cxx_name = "GetFlashFilename"]
        fn get_flash_filename(self: &PitEntry) -> String;
        #[cxx_name = "SetFlashFilename"]
        fn set_flash_filename(self: &mut PitEntry, name: &str);

        #[cxx_name = "GetFotaFilename"]
        fn get_fota_filename(self: &PitEntry) -> String;
        #[cxx_name = "SetFotaFilename"]
        fn set_fota_filename(self: &mut PitEntry, name: &str);

        type PitData;

        #[Self = "PitData"]
        #[cxx_name = "make"]
        fn new_box() -> Box<PitData>;

        #[cxx_name = "GetEntryCount"]
        fn get_entry_count(self: &PitData) -> u32;
        #[cxx_name = "GetLUCount"]
        fn get_lu_count(self: &PitData) -> u32;
        #[cxx_name = "GetDataSize"]
        fn get_data_size(self: &PitData) -> u32;
        #[cxx_name = "GetPaddedSize"]
        fn get_padded_size(self: &PitData) -> u32;
        #[cxx_name = "GetComTar2"]
        fn get_com_tar2(self: &PitData) -> String;
        #[cxx_name = "GetCpuBlId"]
        fn get_cpu_bl_id(self: &PitData) -> String;

        #[cxx_name = "GetEntry"]
        fn get_entry(self: &PitData, index: u32) -> *const PitEntry;
        #[cxx_name = "FindEntry"]
        fn find_entry_by_name(self: &PitData, name: &str) -> *const PitEntry;
        #[cxx_name = "FindEntry"]
        fn find_entry_by_id(self: &PitData, id: u32) -> *const PitEntry;

        #[cxx_name = "Unpack"]
        fn unpack(self: &mut PitData, data: &[u8]) -> bool;
        #[cxx_name = "Pack"]
        fn pack(self: &PitData, data: &mut [u8]);

        #[cxx_name = "Matches"]
        fn matches(self: &PitData, other: &PitData) -> bool;

        #[cxx_name = "Print"]
        fn print(self: &PitData);
    }
}
