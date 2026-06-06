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

use md5::Context;
use sloploader_pit::PitEntry;
use std::fs::File;
use std::io::{Read, Result as IoResult, Seek, SeekFrom};

pub fn verify_md5_footer(path: &str) -> Result<(), String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to read metadata: {}", e))?;
    let file_size = metadata.len();

    if file_size < 34 {
        return Err("File is too small to contain a valid MD5 footer".to_string());
    }

    println!("Verifying MD5 checksum for {}...", path);

    // Read the last 512 bytes of the file. Since the TAR file must end with at least
    // two blocks of zeroes, the last null byte (0x00) marks the exact boundary
    // between the TAR payload and the appended plain-text MD5 footer.
    let seek_pos = file_size.saturating_sub(512);
    file.seek(SeekFrom::Start(seek_pos))
        .map_err(|e| e.to_string())?;
    let mut last_bytes = vec![0u8; (file_size - seek_pos) as usize];
    file.read_exact(&mut last_bytes)
        .map_err(|e| e.to_string())?;

    // Find the last null byte (0x00)
    let mut last_null_idx = None;
    for i in (0..last_bytes.len()).rev() {
        if last_bytes[i] == 0 {
            last_null_idx = Some(i);
            break;
        }
    }

    let Some(null_idx) = last_null_idx else {
        return Err("Could not find a valid null separator for the MD5 footer".to_string());
    };

    let footer_start = null_idx + 1;
    let footer_bytes = &last_bytes[footer_start..];
    let footer_str = String::from_utf8_lossy(footer_bytes);
    let footer_line = footer_str.trim();

    if footer_line.len() < 32 {
        return Err("Could not find a valid MD5 checksum at the end of the file".to_string());
    }

    let expected_hex = &footer_line[..32];
    let mut expected_bytes = [0u8; 16];
    for i in 0..16 {
        let hex_byte = &expected_hex[i * 2..i * 2 + 2];
        expected_bytes[i] = u8::from_str_radix(hex_byte, 16)
            .map_err(|_| "Invalid hex character in MD5 checksum")?;
    }

    // The payload size is the exact position up to the MD5 footer text
    let payload_size = seek_pos + footer_start as u64;

    // Reset file pointer and compute MD5 over the payload only
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut context = Context::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut remaining = payload_size;

    while remaining > 0 {
        let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..to_read])
            .map_err(|e| e.to_string())?;
        context.consume(&buffer[..to_read]);
        remaining -= to_read as u64;
    }

    let calculated_digest = context.finalize();
    if calculated_digest.as_slice() != expected_bytes {
        return Err("MD5 verification failed! File is corrupted or modified.".to_string());
    }

    println!("MD5 verification successful!\n");
    Ok(())
}

pub struct TarEntryReader {
    pub file: File,
    pub start_offset: u64,
    pub size: u64,
    pub current_offset: u64,
}

impl TarEntryReader {
    pub fn new(mut file: File, start_offset: u64, size: u64) -> IoResult<Self> {
        file.seek(SeekFrom::Start(start_offset))?;
        Ok(Self {
            file,
            start_offset,
            size,
            current_offset: 0,
        })
    }
}

impl Read for TarEntryReader {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if self.current_offset >= self.size {
            return Ok(0);
        }
        let remaining = self.size - self.current_offset;
        let max_to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
        let bytes_read = self.file.read(&mut buf[..max_to_read])?;
        self.current_offset += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl Seek for TarEntryReader {
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        let new_offset = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                let target = (self.size as i64) + offset;
                if target < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid seek to a negative offset",
                    ));
                }
                target as u64
            }
            SeekFrom::Current(offset) => {
                let target = (self.current_offset as i64) + offset;
                if target < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid seek to a negative offset",
                    ));
                }
                target as u64
            }
        };

        if new_offset > self.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek past end of tar entry",
            ));
        }

        self.file
            .seek(SeekFrom::Start(self.start_offset + new_offset))?;
        self.current_offset = new_offset;
        Ok(self.current_offset)
    }
}

pub enum FirmwareSource {
    File(File),
    Tar(TarEntryReader),
}

impl Read for FirmwareSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            FirmwareSource::File(f) => f.read(buf),
            FirmwareSource::Tar(r) => r.read(buf),
        }
    }
}

impl Seek for FirmwareSource {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            FirmwareSource::File(f) => f.seek(pos),
            FirmwareSource::Tar(r) => r.seek(pos),
        }
    }
}

pub struct Lz4FrameHeader {
    pub content_size: u64,
    pub block_max_size: usize,
}

impl Lz4FrameHeader {
    pub fn from_read<R: Read>(reader: &mut R) -> Result<Self, String> {
        let mut magic_bytes = [0u8; 4];
        reader
            .read_exact(&mut magic_bytes)
            .map_err(|_| "Failed to read magic number")?;
        let magic = u32::from_le_bytes(magic_bytes);

        if magic != 0x184D2204 {
            // We only support the standard LZ4 frame magic in this context,
            // not the skippable frames (0x184D2A50 - 0x184D2A5F)
            return Err(format!("Not a valid LZ4 frame. Magic: 0x{:08X}", magic));
        }

        let mut flg_byte = [0u8; 1];
        reader
            .read_exact(&mut flg_byte)
            .map_err(|_| "Failed to read FLG byte")?;
        let flg = flg_byte[0];

        let version = (flg >> 6) & 0x03;
        if version != 1 {
            return Err(format!("Unsupported LZ4 version: {}", version));
        }

        let block_independence = ((flg >> 5) & 0x01) == 1;
        let block_checksum = ((flg >> 4) & 0x01) == 1;
        let content_size_flag = ((flg >> 3) & 0x01) == 1;
        let dict_id_flag = (flg & 0x01) == 1;

        if !content_size_flag {
            return Err("LZ4 content size must be enabled".to_string());
        }
        if block_checksum {
            return Err("LZ4 block checksum must be disabled".to_string());
        }
        if !block_independence {
            return Err("LZ4 block independence must be enabled".to_string());
        }

        let mut bd_byte = [0u8; 1];
        reader
            .read_exact(&mut bd_byte)
            .map_err(|_| "Failed to read BD byte")?;
        let bd = bd_byte[0];

        let block_max_size_code = (bd >> 4) & 0x07;
        let block_max_size = match block_max_size_code {
            4 => 64 * 1024,
            5 => 256 * 1024,
            6 => 1024 * 1024,
            7 => 4 * 1024 * 1024,
            _ => {
                return Err(format!(
                    "Invalid block max size code: {}",
                    block_max_size_code
                ));
            }
        };

        let mut content_size_bytes = [0u8; 8];
        reader
            .read_exact(&mut content_size_bytes)
            .map_err(|_| "Failed to read content size")?;
        let content_size = u64::from_le_bytes(content_size_bytes);

        if dict_id_flag {
            let mut dict_id_bytes = [0u8; 4];
            reader
                .read_exact(&mut dict_id_bytes)
                .map_err(|_| "Failed to read dictionary ID")?;
        }

        let mut hc_byte = [0u8; 1];
        reader
            .read_exact(&mut hc_byte)
            .map_err(|_| "Failed to read header checksum")?;

        Ok(Self {
            content_size,
            block_max_size,
        })
    }
}

pub struct FirmwareFile<'a> {
    pub pit_entry: &'a PitEntry,
    pub file: FirmwareSource,
    pub file_size: u64,
}

pub struct FirmwareLz4File<'a> {
    pub pit_entry: &'a PitEntry,
    pub file: FirmwareSource,
    pub header: Lz4FrameHeader,
}

pub enum FirmwareInfo<'a> {
    Normal(FirmwareFile<'a>),
    Lz4(FirmwareLz4File<'a>),
}

pub(crate) struct SequenceIterator<'a> {
    file: &'a mut FirmwareSource,
    file_size: u64,
    packet_size: usize,
    sequence_max_length: usize,
    bytes_read: u64,
}

impl<'a> Iterator for SequenceIterator<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes_read >= self.file_size {
            return None;
        }

        let remaining = self.file_size - self.bytes_read;
        let sequence_byte_count = std::cmp::min(
            remaining,
            (self.sequence_max_length * self.packet_size) as u64,
        ) as usize;

        let mut data = vec![0u8; sequence_byte_count];
        if self.file.read_exact(&mut data).is_err() {
            return None;
        }

        self.bytes_read += sequence_byte_count as u64;

        Some(data)
    }
}

impl<'a> SequenceIterator<'a> {
    pub(crate) fn new(
        file: &'a mut FirmwareSource,
        file_size: u64,
        packet_size: usize,
        sequence_max_length: usize,
    ) -> Self {
        Self {
            file,
            file_size,
            packet_size,
            sequence_max_length,
            bytes_read: 0,
        }
    }
}

pub(crate) struct Lz4SequenceIterator<'a> {
    file: &'a mut FirmwareSource,
    header: &'a Lz4FrameHeader,
    packet_size: usize,
    sequence_max_length: usize,
    remaining_decompressed: u64,
    finished: bool,
}

impl<'a> Lz4SequenceIterator<'a> {
    pub(crate) fn new(
        file: &'a mut FirmwareSource,
        header: &'a Lz4FrameHeader,
        packet_size: usize,
        sequence_max_length: usize,
    ) -> Self {
        Self {
            file,
            header,
            packet_size,
            sequence_max_length,
            remaining_decompressed: header.content_size,
            finished: false,
        }
    }
}

impl<'a> Iterator for Lz4SequenceIterator<'a> {
    type Item = (usize, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let sequence_bytes = self.sequence_max_length * self.packet_size;
        let next_decompressed_size = if self.remaining_decompressed >= sequence_bytes as u64 {
            sequence_bytes
        } else {
            self.remaining_decompressed as usize
        };
        self.remaining_decompressed -= next_decompressed_size as u64;

        let mut decompressed_size_upper_bound = 0;
        let mut sequence_data = Vec::new();

        loop {
            let mut block_size_bytes = [0u8; 4];
            if self.file.read_exact(&mut block_size_bytes).is_err() {
                self.finished = true;
                break;
            }
            let block_size = u32::from_le_bytes(block_size_bytes);

            if block_size == 0 {
                // EndMark
                self.finished = true;
                break;
            }

            decompressed_size_upper_bound += self.header.block_max_size;
            sequence_data.extend_from_slice(&block_size_bytes);

            let data_size = (block_size & 0x7FFF_FFFF) as usize;
            let mut data = vec![0u8; data_size];
            if self.file.read_exact(&mut data).is_err() {
                self.finished = true;
                break;
            }
            sequence_data.extend_from_slice(&data);

            if decompressed_size_upper_bound >= next_decompressed_size {
                break;
            }
        }

        if sequence_data.is_empty() {
            return None;
        }

        Some((next_decompressed_size, sequence_data))
    }
}
