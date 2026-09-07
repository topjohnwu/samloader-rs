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

use crate::progress::{FlashEvent, FlashProgress};
use fast_md5::Md5;
use lz4_flex::frame::FrameDecoder;
use memmap2::Mmap;
use samloader_pit::PitEntry;
use std::io::{self, Read, Seek, SeekFrom};

// This is asserted by Lz4FrameHeader so the header size is always 15
const LZ4_HEADER_SIZE: usize = 15;

/// Verifies the trailing MD5 checksum appended to `.tar.md5` package files with progress callbacks.
pub fn verify_md5_footer_with_progress<R: Read + Seek>(
    mut reader: R,
    name: &str,
    progress: &dyn FlashProgress,
) -> io::Result<()> {
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
    let footer_str = String::from_utf8_lossy(footer_bytes);
    let footer_line = footer_str.lines().last().unwrap_or_default();

    if footer_line.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not find a valid MD5 checksum at the end of the file",
        ));
    }

    let expected_hex = &footer_line[..32];
    let mut expected_bytes = [0u8; 16];
    for i in 0..16 {
        let hex_byte = &expected_hex[i * 2..i * 2 + 2];
        expected_bytes[i] = u8::from_str_radix(hex_byte, 16)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }

    // The payload size is the exact position up to the MD5 footer text
    let payload_size = file_size - footer_line.len() as u64 - 1;

    progress.on_event(FlashEvent::Md5Start {
        name,
        size: payload_size,
    });

    let res = (|| -> io::Result<()> {
        // Reset file pointer and compute MD5 over the payload only
        reader.seek(SeekFrom::Start(0))?;
        let mut hasher = Md5::new();
        let mut buffer = [0u8; 128 * 1024];
        let mut remaining = payload_size;

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..to_read])?;
            hasher.update(&buffer[..to_read]);
            progress.inc(to_read as u64);
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
    })();

    if res.is_err() {
        progress.on_event(FlashEvent::Md5Fail(name));
    } else {
        progress.on_event(FlashEvent::Md5End(name));
    }

    res
}

/// Verifies the trailing MD5 checksum appended to `.tar.md5` package files.
pub fn verify_md5_footer<R: Read + Seek>(reader: R) -> io::Result<()> {
    verify_md5_footer_with_progress(reader, "", &())
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
            (num_blocks as u64) * 1024 * 1024,
        ) as usize;
        self.remaining_decompressed -= decompressed_size as u64;

        Some((decompressed_size, &self.file[start_pos..end_pos]))
    }
}

/// Iterator that produces decompressed byte chunks from an LZ4 stream.
pub struct Lz4DecompressedSequenceIterator<'a> {
    decoder: FrameDecoder<&'a [u8]>,
    sequence_max_bytes: usize,
}

impl<'a> Iterator for Lz4DecompressedSequenceIterator<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = vec![0u8; self.sequence_max_bytes];
        let mut total_read = 0;

        while total_read < self.sequence_max_bytes {
            match self.decoder.read(&mut buffer[total_read..]) {
                Ok(0) => break,
                Ok(n) => total_read += n,
                Err(_) => break,
            }
        }

        if total_read == 0 {
            return None;
        }

        buffer.truncate(total_read);
        Some(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fast_md5::Md5;
    use std::fmt::Write;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    struct TestProgress {
        started_total: AtomicU64,
        inc_bytes: AtomicU64,
        ended: AtomicBool,
        failed: AtomicBool,
    }

    impl TestProgress {
        fn new() -> Self {
            Self {
                started_total: AtomicU64::new(0),
                inc_bytes: AtomicU64::new(0),
                ended: AtomicBool::new(false),
                failed: AtomicBool::new(false),
            }
        }
    }

    impl FlashProgress for TestProgress {
        fn set_length(&self, _len: u64) {}

        fn inc(&self, bytes: u64) {
            self.inc_bytes.fetch_add(bytes, Ordering::Relaxed);
        }

        fn on_event(&self, event: FlashEvent<'_>) {
            match event {
                FlashEvent::Md5Start {
                    size: total_bytes, ..
                } => {
                    self.started_total.store(total_bytes, Ordering::Relaxed);
                }
                FlashEvent::Md5End(_) => {
                    self.ended.store(true, Ordering::Relaxed);
                }
                FlashEvent::Md5Fail(_) => {
                    self.failed.store(true, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_verify_md5_footer_success() {
        // Construct a synthetic TAR payload with zeroes padding and MD5 footer
        let payload = b"Hello, Odin TAR payload with some content!";
        let mut data = Vec::new();
        data.extend_from_slice(payload);
        // Null byte separating payload from MD5 footer text
        data.push(0);

        let mut hasher = Md5::new();
        hasher.update(&data);
        let digest = hasher.finalize();

        let hex_str = digest.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{:02x}", b);
            s
        });
        let footer = format!("{}  test.tar\n", hex_str);
        data.extend_from_slice(footer.as_bytes());

        let progress = TestProgress::new();
        let res = verify_md5_footer_with_progress(Cursor::new(&data), "test.tar", &progress);

        assert!(res.is_ok());
        let expected_total = (payload.len() + 1) as u64;
        assert_eq!(
            progress.started_total.load(Ordering::Relaxed),
            expected_total
        );
        assert_eq!(progress.inc_bytes.load(Ordering::Relaxed), expected_total);
        assert!(progress.ended.load(Ordering::Relaxed));
        assert!(!progress.failed.load(Ordering::Relaxed));

        // Also test the convenience wrapper
        assert!(verify_md5_footer(Cursor::new(&data)).is_ok());
    }

    #[test]
    fn test_verify_md5_footer_corruption() {
        let payload = b"Hello, Odin TAR payload with some content!";
        let mut data = Vec::new();
        data.extend_from_slice(payload);
        data.push(0);

        // Intentionally wrong hash
        let footer = "0123456789abcdef0123456789abcdef  test.tar\n";
        data.extend_from_slice(footer.as_bytes());

        let progress = TestProgress::new();
        let res = verify_md5_footer_with_progress(Cursor::new(&data), "test.tar", &progress);
        assert!(res.is_err());
        assert!(progress.failed.load(Ordering::Relaxed));
        assert!(!progress.ended.load(Ordering::Relaxed));

        assert!(verify_md5_footer(Cursor::new(&data)).is_err());
    }
}
