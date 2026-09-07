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
use lz4_flex::frame::FrameDecoder;
use memmap2::Mmap;
use samloader_pit::PitEntry;
use std::io::{self, Read, Seek, SeekFrom};

// This is asserted by Lz4FrameHeader so the header size is always 15
const LZ4_HEADER_SIZE: usize = 15;

/// Verifies the trailing MD5 checksum appended to `.tar.md5` package files.
pub fn verify_md5_footer<R: Read + Seek>(mut reader: R) -> io::Result<()> {
    let file_size = reader.seek(SeekFrom::End(0))?;

    if file_size < 34 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File is too small to contain a valid MD5 footer",
        ));
    }

    // Read the last 512 bytes of the file. Since the TAR file must end with at least
    // two blocks of zeroes, the last null byte (0x00) marks the exact boundary
    // between the TAR payload and the appended plain-text MD5 footer.
    let seek_pos = file_size.saturating_sub(512);
    reader.seek(SeekFrom::Start(seek_pos))?;
    let mut last_bytes = vec![0u8; (file_size - seek_pos) as usize];
    reader.read_exact(&mut last_bytes)?;

    // Find the last null byte (0x00)
    let mut last_null_idx = None;
    for i in (0..last_bytes.len()).rev() {
        if last_bytes[i] == 0 {
            last_null_idx = Some(i);
            break;
        }
    }

    let Some(null_idx) = last_null_idx else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not find a valid null separator for the MD5 footer",
        ));
    };

    let footer_start = null_idx + 1;
    let footer_bytes = &last_bytes[footer_start..];
    let mut footer_line = footer_bytes
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if footer_line.ends_with(b"\r") {
        footer_line = &footer_line[..footer_line.len() - 1];
    }

    if footer_line.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not find a valid MD5 checksum at the end of the file",
        ));
    }

    let footer_line = std::str::from_utf8(footer_line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "MD5 footer is not ASCII"))?;

    let mut expected_bytes = [0u8; 16];
    for i in 0..16 {
        let hex_byte = &footer_line[i * 2..i * 2 + 2];
        expected_bytes[i] = u8::from_str_radix(hex_byte, 16)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }

    // The payload ends immediately before the footer, after the TAR null separator.
    let payload_size = seek_pos + null_idx as u64 + 1;

    // Reset file pointer and compute MD5 over the payload only
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut remaining = payload_size;

    while remaining > 0 {
        let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..to_read])?;
        hasher.update(&buffer[..to_read]);
        remaining -= to_read as u64;
    }

    let calculated_digest = hasher.finalize();
    if calculated_digest != expected_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MD5 verification failed! File is corrupted or modified.",
        ));
    }

    Ok(())
}

/// Header containing metadata parsed from an LZ4 frame.
pub struct Lz4FrameHeader {
    /// Total size of the decompressed content in bytes.
    pub content_size: u64,
    /// Maximum size of a block in bytes.
    pub block_max_size: u64,
}

impl Lz4FrameHeader {
    /// Parses the LZ4 frame header from a reader.
    pub fn parse<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut magic_bytes = [0u8; 4];
        reader.read_exact(&mut magic_bytes)?;
        let magic = u32::from_le_bytes(magic_bytes);

        if magic != 0x184D2204 {
            // We only support the standard LZ4 frame magic in this context,
            // not the skippable frames (0x184D2A50 - 0x184D2A5F)
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Not a valid LZ4 frame. Magic: 0x{:08X}", magic),
            ));
        }

        let mut flg_byte = [0u8; 1];
        reader.read_exact(&mut flg_byte)?;
        let flg = flg_byte[0];

        let version = (flg >> 6) & 0x03;
        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported LZ4 version: {}", version),
            ));
        }

        let block_independence = ((flg >> 5) & 0x01) == 1;
        let block_checksum = ((flg >> 4) & 0x01) == 1;
        let content_checksum = ((flg >> 2) & 0x01) == 1;
        let content_size_flag = ((flg >> 3) & 0x01) == 1;
        let dict_id_flag = (flg & 0x01) == 1;

        if !content_size_flag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 content size must be enabled",
            ));
        }
        if block_checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 block checksum must be disabled",
            ));
        }
        if content_checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 content checksum must be disabled",
            ));
        }
        if !block_independence {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 block independence must be enabled",
            ));
        }
        if dict_id_flag {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZ4 dictionary ID must be disabled",
            ));
        }

        let mut bd_byte = [0u8; 1];
        reader.read_exact(&mut bd_byte)?;
        let bd = bd_byte[0];

        let block_max_size_code = (bd >> 4) & 0x07;
        let block_max_size = match block_max_size_code {
            4 => 64 * 1024,
            5 => 256 * 1024,
            6 => 1024 * 1024,
            7 => 4 * 1024 * 1024,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid block max size code: {}", block_max_size_code),
                ));
            }
        };

        let mut content_size_bytes = [0u8; 8];
        reader.read_exact(&mut content_size_bytes)?;
        let content_size = u64::from_le_bytes(content_size_bytes);

        let mut hc_byte = [0u8; 1];
        reader.read_exact(&mut hc_byte)?;

        Ok(Self {
            content_size,
            block_max_size,
        })
    }
}

/// An uncompressed firmware file mapped in memory.
pub struct FirmwareFile<'a> {
    /// PIT partition entry associated with this file.
    pub pit_entry: &'a PitEntry,
    /// Memory-mapped file content payload.
    pub file: Mmap,
}

impl<'a> FirmwareFile<'a> {
    pub(crate) fn sequences(&self, sequence_max_bytes: usize) -> std::slice::Chunks<'_, u8> {
        self.file.chunks(sequence_max_bytes)
    }
}

/// An LZ4-compressed firmware file mapped in memory.
pub struct FirmwareLz4File<'a> {
    /// PIT partition entry associated with this file.
    pub pit_entry: &'a PitEntry,
    /// Memory-mapped file content payload.
    pub file: Mmap,
    /// Metadata header of the LZ4 frame.
    pub header: Lz4FrameHeader,
}

impl<'a> FirmwareLz4File<'a> {
    pub(crate) fn sequences(&self, sequence_max_bytes: usize) -> Lz4SequenceIterator<'_> {
        Lz4SequenceIterator {
            file: &self.file,
            max_blocks: sequence_max_bytes / (1024 * 1024),
            remaining_decompressed: self.header.content_size,
            bytes_read: LZ4_HEADER_SIZE,
            finished: false,
        }
    }

    pub(crate) fn decompressed_sequences(
        &self,
        sequence_max_bytes: usize,
    ) -> Lz4DecompressedSequenceIterator<'_> {
        Lz4DecompressedSequenceIterator {
            decoder: FrameDecoder::new(&self.file[..]),
            sequence_max_bytes,
            remaining_decompressed: self.header.content_size,
        }
    }
}

/// Enum wrapping a firmware file payload variant.
pub enum FirmwareInfo<'a> {
    /// Uncompressed normal firmware file payload.
    Normal(FirmwareFile<'a>),
    /// LZ4-compressed firmware file payload.
    Lz4(FirmwareLz4File<'a>),
}

pub(crate) struct Lz4SequenceIterator<'a> {
    file: &'a Mmap,
    max_blocks: usize,
    remaining_decompressed: u64,
    bytes_read: usize,
    finished: bool,
}

impl<'a> Iterator for Lz4SequenceIterator<'a> {
    type Item = io::Result<(usize, &'a [u8])>;

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
                return Some(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "LZ4 stream is missing its end mark",
                )));
            }
            let block_size = u32::from_le_bytes(
                self.file[self.bytes_read..self.bytes_read + 4]
                    .try_into()
                    .unwrap(),
            );

            if block_size == 0 {
                self.bytes_read += 4; // Advance past EndMark
                self.finished = true;
                if self.remaining_decompressed != 0 {
                    return Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "LZ4 stream ended before the declared content size",
                    )));
                }
                break;
            }

            let data_size = (block_size & 0x7FFF_FFFF) as usize;
            if self.bytes_read + 4 + data_size > self.file.len() {
                self.finished = true;
                return Some(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "LZ4 block is truncated",
                )));
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
            (num_blocks as u64) * 1024 * 1024,
        ) as usize;
        self.remaining_decompressed -= decompressed_size as u64;

        Some(Ok((decompressed_size, &self.file[start_pos..end_pos])))
    }
}

/// Iterator that produces decompressed byte chunks from an LZ4 stream.
pub struct Lz4DecompressedSequenceIterator<'a> {
    decoder: FrameDecoder<&'a [u8]>,
    sequence_max_bytes: usize,
    remaining_decompressed: u64,
}

impl<'a> Iterator for Lz4DecompressedSequenceIterator<'a> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_decompressed == 0 {
            return None;
        }

        let buffer_size =
            std::cmp::min(self.sequence_max_bytes as u64, self.remaining_decompressed) as usize;
        let mut buffer = vec![0u8; buffer_size];
        let mut total_read = 0;

        while total_read < buffer_size {
            match self.decoder.read(&mut buffer[total_read..]) {
                Ok(0) => {
                    return Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "LZ4 stream ended before the declared content size",
                    )));
                }
                Ok(n) => total_read += n,
                Err(error) => return Some(Err(error)),
            }
        }

        self.remaining_decompressed -= total_read as u64;
        buffer.truncate(total_read);
        Some(Ok(buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn package_with_footer(line_ending: &[u8]) -> Vec<u8> {
        let mut payload = vec![0xA5; 99];
        payload.push(0);
        let mut md5 = Md5::new();
        md5.update(&payload);
        let digest = md5.finalize();
        let checksum = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        payload.extend_from_slice(checksum.as_bytes());
        payload.extend_from_slice(line_ending);
        payload
    }

    #[test]
    fn md5_footer_accepts_no_trailing_newline() {
        assert!(verify_md5_footer(Cursor::new(package_with_footer(b""))).is_ok());
    }

    #[test]
    fn md5_footer_accepts_crlf() {
        assert!(verify_md5_footer(Cursor::new(package_with_footer(b"\r\n"))).is_ok());
    }

    #[test]
    fn lz4_content_checksum_is_rejected() {
        let header = [
            0x04, 0x22, 0x4D, 0x18, // magic
            0x6C, // version, independent blocks, content size, content checksum
            0x60, // 1 MiB blocks
            0, 0, 0, 0, 0, 0, 0, 0, // content size
            0, // header checksum (not validated by this parser)
        ];

        let result = Lz4FrameHeader::parse(Cursor::new(header));
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(error.to_string().contains("content checksum"));
    }
}
