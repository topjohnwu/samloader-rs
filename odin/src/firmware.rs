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

use fast_md5::Md5;
use memmap2::Mmap;
use samloader_pit::PitEntry;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

// This is asserted by Lz4FrameHeader so the header size is always 15
const LZ4_HEADER_SIZE: usize = 15;

pub fn verify_md5_footer(path: &str) -> Result<(), String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to read metadata: {}", e))?;
    let file_size = metadata.len();

    if file_size < 34 {
        return Err("File is too small to contain a valid MD5 footer".to_string());
    }

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
    let footer_line = footer_str.lines().last().unwrap_or_default();

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
    let payload_size = file_size - footer_line.len() as u64 - 1;

    // Reset file pointer and compute MD5 over the payload only
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut remaining = payload_size;

    while remaining > 0 {
        let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..to_read])
            .map_err(|e| e.to_string())?;
        hasher.update(&buffer[..to_read]);
        remaining -= to_read as u64;
    }

    let calculated_digest = hasher.finalize();
    if calculated_digest != expected_bytes {
        return Err("MD5 verification failed! File is corrupted or modified.".to_string());
    }

    Ok(())
}

pub struct Lz4FrameHeader {
    pub content_size: u64,
    pub block_max_size: u64,
}

pub fn parse_lz4_frame_header<R: Read>(mut reader: R) -> Result<Lz4FrameHeader, String> {
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
    if dict_id_flag {
        return Err("LZ4 dictionary ID must be disabled".to_string());
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

    let mut hc_byte = [0u8; 1];
    reader
        .read_exact(&mut hc_byte)
        .map_err(|_| "Failed to read header checksum")?;

    Ok(Lz4FrameHeader {
        content_size,
        block_max_size,
    })
}

pub struct FirmwareFile<'a> {
    pub pit_entry: &'a PitEntry,
    pub file: Mmap,
}

impl<'a> FirmwareFile<'a> {
    pub(crate) fn sequences(&self, sequence_max_bytes: usize) -> std::slice::Chunks<'_, u8> {
        self.file.chunks(sequence_max_bytes)
    }
}

pub struct FirmwareLz4File<'a> {
    pub pit_entry: &'a PitEntry,
    pub file: Mmap,
    pub content_size: u64,
    pub block_max_size: u64,
}

impl<'a> FirmwareLz4File<'a> {
    pub(crate) fn sequences(&self, sequence_max_bytes: usize) -> Lz4SequenceIterator<'_> {
        Lz4SequenceIterator {
            file: &self.file,
            block_max_size: self.block_max_size,
            max_blocks: sequence_max_bytes / (1024 * 1024),
            remaining_decompressed: self.content_size,
            bytes_read: LZ4_HEADER_SIZE,
            finished: false,
        }
    }
}

pub enum FirmwareInfo<'a> {
    Normal(FirmwareFile<'a>),
    Lz4(FirmwareLz4File<'a>),
}

pub(crate) struct Lz4SequenceIterator<'a> {
    file: &'a Mmap,
    block_max_size: u64,
    max_blocks: usize,
    remaining_decompressed: u64,
    bytes_read: usize,
    finished: bool,
}

impl<'a> Lz4SequenceIterator<'a> {
    pub(crate) fn decompressed(self) -> Lz4DecompressedSequenceIterator<'a> {
        Lz4DecompressedSequenceIterator {
            file: self.file,
            block_max_size: self.block_max_size,
            max_blocks: self.max_blocks,
            remaining_decompressed: self.remaining_decompressed,
            bytes_read: self.bytes_read,
            finished: self.finished,
        }
    }
}

impl<'a> Iterator for Lz4SequenceIterator<'a> {
    type Item = (usize, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let start_pos = self.bytes_read;
        let mut end_pos = start_pos;
        let mut num_blocks = 0;

        while num_blocks < self.max_blocks {
            if self.bytes_read + 4 > self.file.len() {
                self.finished = true;
                break;
            }
            let block_size = u32::from_le_bytes(
                self.file[self.bytes_read..self.bytes_read + 4]
                    .try_into()
                    .unwrap(),
            );

            if block_size == 0 {
                self.bytes_read += 4; // Advance past EndMark
                self.finished = true;
                break;
            }

            let data_size = (block_size & 0x7FFF_FFFF) as usize;
            if self.bytes_read + 4 + data_size > self.file.len() {
                self.finished = true;
                break;
            }

            self.bytes_read += 4 + data_size;
            end_pos = self.bytes_read;
            num_blocks += 1;
        }

        if start_pos == end_pos {
            return None;
        }

        let decompressed_size = std::cmp::min(
            self.remaining_decompressed,
            (num_blocks as u64) * self.block_max_size,
        ) as usize;
        self.remaining_decompressed -= decompressed_size as u64;

        Some((decompressed_size, &self.file[start_pos..end_pos]))
    }
}

pub struct Lz4DecompressedSequenceIterator<'a> {
    file: &'a Mmap,
    block_max_size: u64,
    max_blocks: usize,
    remaining_decompressed: u64,
    bytes_read: usize,
    finished: bool,
}

impl<'a> Iterator for Lz4DecompressedSequenceIterator<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let mut decompressed_data = Vec::new();
        let mut num_blocks = 0;

        while num_blocks < self.max_blocks {
            if self.bytes_read + 4 > self.file.len() {
                self.finished = true;
                break;
            }
            let block_size = u32::from_le_bytes(
                self.file[self.bytes_read..self.bytes_read + 4]
                    .try_into()
                    .unwrap(),
            );

            if block_size == 0 {
                self.bytes_read += 4; // Advance past EndMark
                self.finished = true;
                break;
            }

            let is_compressed = (block_size & 0x8000_0000) == 0;
            let data_size = (block_size & 0x7FFF_FFFF) as usize;
            if self.bytes_read + 4 + data_size > self.file.len() {
                self.finished = true;
                break;
            }

            let block_uncompressed_size =
                std::cmp::min(self.remaining_decompressed, self.block_max_size) as usize;
            let block_bytes = &self.file[self.bytes_read + 4..self.bytes_read + 4 + data_size];

            if is_compressed {
                let decompressed_block =
                    lz4_flex::block::decompress(block_bytes, block_uncompressed_size)
                        .map_err(|e| format!("LZ4 decompression failed: {}", e))
                        .ok()?;
                decompressed_data.extend_from_slice(&decompressed_block);
            } else {
                decompressed_data.extend_from_slice(block_bytes);
            }

            self.bytes_read += 4 + data_size;
            self.remaining_decompressed -= block_uncompressed_size as u64;
            num_blocks += 1;
        }

        if decompressed_data.is_empty() {
            return None;
        }

        Some(decompressed_data)
    }
}
