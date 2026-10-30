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

//! Multi-threaded firmware download mechanism with embedded resumable state.

use crate::FusClient;
use crate::error::Result;
use aes::cipher::BlockModeDecrypt;
use aes::cipher::inout::InOutBuf;
use fast_md5::Md5;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::Duration;

/// The chunk size of each independently tracked download block (2 MiB).
/// 2 MiB = 2,097,152 bytes = 131,072 AES-128 blocks (aligned to 16 bytes).
const BLOCK_SIZE: usize = 2 * 1024 * 1024;

/// Magic identifier placed at the trailing 8 bytes of the footer.
const FOOTER_MAGIC: &[u8; 8] = b"SAMLOADR";

/// Version of the footer layout format.
const FOOTER_VERSION: u32 = 1;

/// Length of the fixed trailing trailer: 16 (MD5) + 4 (footer_len) + 8 (magic) = 28 bytes.
const TRAILER_LEN: usize = 28;

/// Size of each worker's download buffer (a multiple of the 16-byte AES block).
const WRITE_BUF_SIZE: usize = 1024 * 1024;

#[cfg(unix)]
fn write_at(file: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, buf, offset)
}

#[cfg(windows)]
fn write_at(file: &File, mut buf: &[u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_write(buf, offset)?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_read(buf, offset)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

/// A trait for reporting firmware download progress and logging messages.
pub trait DownloadProgress: Send + Sync {
    /// Sets the total length of the progress.
    fn set_length(&self, len: u64);

    /// Sets the current progress position (e.g. when resuming a partial download).
    fn set_position(&self, pos: u64);

    /// Increments the download progress by the specified number of bytes.
    fn inc(&self, bytes: u64);

    /// Gets the current absolute byte position of the progress.
    fn position(&self) -> u64;

    /// Prints a standard log or status message.
    fn println(&self, msg: &str);

    /// Prints a verbose log or status message (implementation decides if it is shown).
    fn println_verbose(&self, msg: &str);
}

// Convenient no-op implementation for silent downloads (e.g. in tests)
impl DownloadProgress for () {
    fn set_length(&self, _len: u64) {}
    fn set_position(&self, _pos: u64) {}
    fn inc(&self, _bytes: u64) {}
    fn position(&self) -> u64 {
        0
    }
    fn println(&self, _msg: &str) {}
    fn println_verbose(&self, _msg: &str) {}
}

/// Options controlling firmware download behavior.
#[derive(Debug, Clone, Copy)]
pub struct DownloadOptions {
    /// Number of parallel download connections.
    pub threads: u64,
    /// Overwrite any existing file or partial download from scratch.
    pub force: bool,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            threads: 8,
            force: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ByteRange {
    start: u64,
    end: u64, // exclusive
}

struct FooterLayout {
    num_blocks: usize,
    bitfield_offset: usize,
    bitfield_len: usize,
    footer_len: usize,
}

impl FooterLayout {
    fn new(client: &FusClient) -> Self {
        let num_blocks = client.info.size.div_ceil(BLOCK_SIZE as u64) as usize;
        let bitfield_len = num_blocks.div_ceil(8);
        let bitfield_offset = 4 // version
            + 8 // file_size
            + 16 // key
            + 4 // block_size
            + 4 // num_blocks
            + 2 // filename_len
            + client.info.filename.len()
            + 2 // version_len
            + client.info.version.len();
        let footer_len = bitfield_offset + bitfield_len + TRAILER_LEN;

        Self {
            num_blocks,
            bitfield_offset,
            bitfield_len,
            footer_len,
        }
    }

    fn serialize_initial(&self, client: &FusClient, out: &mut [u8]) {
        assert_eq!(out.len(), self.footer_len);
        let mut cursor = 0;

        out[cursor..cursor + 4].copy_from_slice(&FOOTER_VERSION.to_le_bytes());
        cursor += 4;
        out[cursor..cursor + 8].copy_from_slice(&client.info.size.to_le_bytes());
        cursor += 8;
        out[cursor..cursor + 16].copy_from_slice(client.info.key.as_slice());
        cursor += 16;
        out[cursor..cursor + 4].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
        cursor += 4;
        out[cursor..cursor + 4].copy_from_slice(&(self.num_blocks as u32).to_le_bytes());
        cursor += 4;

        let fn_bytes = client.info.filename.as_bytes();
        out[cursor..cursor + 2].copy_from_slice(&(fn_bytes.len() as u16).to_le_bytes());
        cursor += 2;
        out[cursor..cursor + fn_bytes.len()].copy_from_slice(fn_bytes);
        cursor += fn_bytes.len();

        let ver_bytes = client.info.version.as_bytes();
        out[cursor..cursor + 2].copy_from_slice(&(ver_bytes.len() as u16).to_le_bytes());
        cursor += 2;
        out[cursor..cursor + ver_bytes.len()].copy_from_slice(ver_bytes);
        cursor += ver_bytes.len();

        // Zero out bitfield initially
        out[cursor..cursor + self.bitfield_len].fill(0);
        cursor += self.bitfield_len;

        // Checksum over header + bitfield
        let checksum = fast_md5::digest(&out[..cursor]);
        out[cursor..cursor + 16].copy_from_slice(&checksum);
        cursor += 16;

        out[cursor..cursor + 4].copy_from_slice(&(self.footer_len as u32).to_le_bytes());
        cursor += 4;
        out[cursor..cursor + 8].copy_from_slice(FOOTER_MAGIC);
        cursor += 8;

        assert_eq!(cursor, out.len());
    }
}

struct ParsedFooter {
    bitfield: Vec<u8>,
    num_blocks: usize,
}

impl ParsedFooter {
    fn read_and_validate<R: Read + Seek>(reader: &mut R, client: &FusClient) -> Option<Self> {
        let file_len = reader.seek(SeekFrom::End(0)).ok()?;
        if file_len < TRAILER_LEN as u64 {
            return None;
        }

        // Read trailing 12 bytes: footer_len (4) + magic (8)
        reader.seek(SeekFrom::End(-12)).ok()?;
        let mut tail = [0u8; 12];
        reader.read_exact(&mut tail).ok()?;
        let (footer_len_bytes, magic_bytes) = tail.split_at(4);
        if magic_bytes != FOOTER_MAGIC {
            return None;
        }
        let footer_len = u32::from_le_bytes(footer_len_bytes.try_into().unwrap()) as usize;
        if footer_len < TRAILER_LEN || footer_len as u64 > file_len {
            return None;
        }

        if file_len != client.info.size + footer_len as u64 {
            return None;
        }

        // Read entire footer
        reader.seek(SeekFrom::End(-(footer_len as i64))).ok()?;
        let mut footer_bytes = vec![0u8; footer_len];
        reader.read_exact(&mut footer_bytes).ok()?;

        let payload_len = footer_len - TRAILER_LEN;

        // Parse header fields
        let mut cursor = 0;
        let version = u32::from_le_bytes(footer_bytes.get(cursor..cursor + 4)?.try_into().ok()?);
        cursor += 4;
        if version != FOOTER_VERSION {
            return None;
        }

        let file_size = u64::from_le_bytes(footer_bytes.get(cursor..cursor + 8)?.try_into().ok()?);
        cursor += 8;
        if file_size != client.info.size {
            return None;
        }

        let key = footer_bytes.get(cursor..cursor + 16)?;
        cursor += 16;
        if key != client.info.key.as_slice() {
            return None;
        }

        let block_size = u32::from_le_bytes(footer_bytes.get(cursor..cursor + 4)?.try_into().ok()?);
        cursor += 4;
        if block_size != BLOCK_SIZE as u32 {
            return None;
        }

        let num_blocks = u32::from_le_bytes(footer_bytes.get(cursor..cursor + 4)?.try_into().ok()?);
        cursor += 4;
        let expected_num_blocks = client.info.size.div_ceil(BLOCK_SIZE as u64) as u32;
        if num_blocks != expected_num_blocks {
            return None;
        }

        let fn_len =
            u16::from_le_bytes(footer_bytes.get(cursor..cursor + 2)?.try_into().ok()?) as usize;
        cursor += 2;
        let filename = std::str::from_utf8(footer_bytes.get(cursor..cursor + fn_len)?).ok()?;
        cursor += fn_len;
        if filename != client.info.filename {
            return None;
        }

        let ver_len =
            u16::from_le_bytes(footer_bytes.get(cursor..cursor + 2)?.try_into().ok()?) as usize;
        cursor += 2;
        let ver_str = std::str::from_utf8(footer_bytes.get(cursor..cursor + ver_len)?).ok()?;
        cursor += ver_len;
        if ver_str != client.info.version {
            return None;
        }

        let bitfield_offset = cursor;
        let bitfield_len = (num_blocks as usize).div_ceil(8);
        if bitfield_offset + bitfield_len != payload_len {
            return None;
        }

        // Verify checksum assuming all bitfields are zero
        let mut hasher = Md5::new();
        hasher.update(&footer_bytes[..bitfield_offset]);
        const ZERO_CHUNK: [u8; 1024] = [0u8; 1024];
        let mut remaining = bitfield_len;
        while remaining > 0 {
            let chunk_len = remaining.min(ZERO_CHUNK.len());
            hasher.update(&ZERO_CHUNK[..chunk_len]);
            remaining -= chunk_len;
        }
        let expected_checksum = hasher.finalize();
        let stored_checksum = &footer_bytes[payload_len..payload_len + 16];
        if expected_checksum.as_slice() != stored_checksum {
            return None;
        }

        let bitfield = footer_bytes
            .get(bitfield_offset..bitfield_offset + bitfield_len)?
            .to_vec();

        Some(Self {
            bitfield,
            num_blocks: num_blocks as usize,
        })
    }
}

fn calculate_completed_bytes(bitfield: &[u8], num_blocks: usize, total_size: u64) -> u64 {
    let mut total = 0_u64;
    for blk in 0..num_blocks {
        if (bitfield[blk / 8] & (1 << (blk % 8))) != 0 {
            let blk_size = if blk == num_blocks - 1 {
                total_size - (blk as u64 * BLOCK_SIZE as u64)
            } else {
                BLOCK_SIZE as u64
            };
            total += blk_size;
        }
    }
    total
}

fn extract_uncompleted_ranges(
    bitfield: &[u8],
    num_blocks: usize,
    total_size: u64,
) -> Vec<ByteRange> {
    let mut ranges = Vec::new();
    let mut run_start: Option<usize> = None;

    for blk in 0..num_blocks {
        let is_done = (bitfield[blk / 8] & (1 << (blk % 8))) != 0;
        if !is_done {
            if run_start.is_none() {
                run_start = Some(blk);
            }
        } else if let Some(start_blk) = run_start.take() {
            let start = start_blk as u64 * BLOCK_SIZE as u64;
            let end = blk as u64 * BLOCK_SIZE as u64;
            ranges.push(ByteRange { start, end });
        }
    }
    if let Some(start_blk) = run_start.take() {
        let start = start_blk as u64 * BLOCK_SIZE as u64;
        let end = total_size;
        ranges.push(ByteRange { start, end });
    }
    ranges
}

fn partition_ranges_for_threads(ranges: &[ByteRange], threads: u64) -> Vec<ByteRange> {
    if ranges.is_empty() {
        return Vec::new();
    }
    let total_remaining: u64 = ranges.iter().map(|r| r.end - r.start).sum();
    let target_chunk = (total_remaining / threads / BLOCK_SIZE as u64).max(1) * BLOCK_SIZE as u64;

    let mut result = Vec::new();
    for r in ranges {
        let mut curr = r.start;
        while r.end - curr > target_chunk {
            result.push(ByteRange {
                start: curr,
                end: curr + target_chunk,
            });
            curr += target_chunk;
        }
        if curr < r.end {
            result.push(ByteRange {
                start: curr,
                end: r.end,
            });
        }
    }
    result
}

struct StateTracker<'a> {
    footer: &'a mut [u8],
    bitfield_offset: usize,
    total_blocks: usize,
    file_size: u64,
    /// The `.part` file and the footer's offset in it, which every changed byte is written to.
    sink: Option<(&'a File, u64)>,
}

impl<'a> StateTracker<'a> {
    fn new(
        footer: &'a mut [u8],
        bitfield_offset: usize,
        total_blocks: usize,
        file_size: u64,
    ) -> Self {
        Self {
            footer,
            bitfield_offset,
            total_blocks,
            file_size,
            sink: None,
        }
    }

    fn with_sink(mut self, file: &'a File, footer_offset: u64) -> Self {
        self.sink = Some((file, footer_offset));
        self
    }

    fn on_bytes_decrypted(
        &mut self,
        start: u64,
        prev_dec: u64,
        new_dec: u64,
    ) -> std::io::Result<()> {
        let prev_pos = start + prev_dec;
        let curr_pos = start + new_dec;
        let start_blk = (prev_pos / BLOCK_SIZE as u64) as usize;
        let end_blk = (curr_pos / BLOCK_SIZE as u64) as usize;

        for blk in start_blk..=end_blk {
            if blk >= self.total_blocks {
                break;
            }
            let blk_end = if blk == self.total_blocks - 1 {
                self.file_size
            } else {
                (blk + 1) as u64 * BLOCK_SIZE as u64
            };
            if curr_pos >= blk_end {
                let byte_idx = self.bitfield_offset + blk / 8;
                let bit_mask = 1 << (blk % 8);
                if self.footer[byte_idx] & bit_mask == 0 {
                    self.footer[byte_idx] |= bit_mask;
                    if let Some((file, footer_offset)) = self.sink {
                        write_at(
                            file,
                            &self.footer[byte_idx..=byte_idx],
                            footer_offset + byte_idx as u64,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Downloads the firmware binary in parallel across multiple threads, decrypting each piece
/// and writing it at its offset, supporting interruption and resumption via an embedded
/// `.part` footer.
pub fn download_firmware<P, PathRef>(
    client: &FusClient,
    path: PathRef,
    options: DownloadOptions,
    progress: &P,
) -> Result<()>
where
    P: DownloadProgress,
    PathRef: AsRef<Path>,
{
    let final_path = path.as_ref();
    if let Some(parent) = final_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }

    let part_path = {
        let mut s = final_path.as_os_str().to_owned();
        s.push(".part");
        std::path::PathBuf::from(s)
    };

    if options.force {
        let _ = std::fs::remove_file(final_path);
        let _ = std::fs::remove_file(&part_path);
    } else if let Ok(meta) = final_path.metadata() {
        let len = meta.len();
        if (client.info.size.saturating_sub(16)..=client.info.size).contains(&len) {
            progress.println(&format!(
                "File already exists and is complete: {}",
                final_path.display()
            ));
            return Ok(());
        }
    }

    let layout = FooterLayout::new(client);
    let total_file_len = client.info.size + layout.footer_len as u64;

    // Check if a valid partial download already exists
    let had_existing_part = part_path.exists();
    let existing_footer = if had_existing_part && !options.force {
        if let Ok(mut f) = OpenOptions::new().read(true).open(&part_path) {
            ParsedFooter::read_and_validate(&mut f, client)
        } else {
            None
        }
    } else {
        None
    };

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(existing_footer.is_none())
        .open(&part_path)?;

    let uncompleted = if let Some(ref pf) = existing_footer {
        let completed_bytes =
            calculate_completed_bytes(&pf.bitfield, pf.num_blocks, client.info.size);
        progress.println(&format!(
            "Resuming download: {:.2} GiB / {:.2} GiB ({:.1}%) already downloaded",
            completed_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            client.info.size as f64 / (1024.0 * 1024.0 * 1024.0),
            (completed_bytes as f64 / client.info.size as f64) * 100.0
        ));
        progress.set_length(client.info.size);
        progress.set_position(completed_bytes);
        extract_uncompleted_ranges(&pf.bitfield, pf.num_blocks, client.info.size)
    } else {
        if had_existing_part && !options.force {
            progress.println(
                "Existing partial download is incompatible or corrupted, restarting from scratch...",
            );
        }
        file.set_len(total_file_len)?;
        let mut initial_footer = vec![0u8; layout.footer_len];
        layout.serialize_initial(client, &mut initial_footer);
        file.seek(SeekFrom::Start(client.info.size))?;
        file.write_all(&initial_footer)?;
        file.sync_data()?;

        progress.set_length(client.info.size);
        progress.set_position(0);
        vec![ByteRange {
            start: 0,
            end: client.info.size,
        }]
    };

    let download_chunks = partition_ranges_for_threads(&uncompleted, options.threads);

    if !download_chunks.is_empty() {
        client.init_download()?;

        let mut footer = vec![0u8; layout.footer_len];
        read_at(&file, &mut footer, client.info.size)?;

        let tracker = Mutex::new(
            StateTracker::new(
                &mut footer,
                layout.bitfield_offset,
                layout.num_blocks,
                client.info.size,
            )
            .with_sink(&file, client.info.size),
        );

        let queue: VecDeque<Chunk> = download_chunks
            .iter()
            .map(|range| Chunk {
                start: range.start,
                len: range.end - range.start,
                end: if range.end == client.info.size {
                    None
                } else {
                    Some(range.end - 1)
                },
            })
            .collect();

        let n_workers = queue.len().min(options.threads as usize);
        let pool = Pool {
            inner: Mutex::new(PoolInner {
                queue,
                in_flight: 0,
                live: n_workers,
                error: None,
            }),
            available: Condvar::new(),
        };

        thread::scope(|s| {
            let pool = &pool;
            let tracker = &tracker;
            let file = &file;
            for _ in 0..n_workers {
                s.spawn(move || run_worker(pool, client, file, progress, tracker));
                thread::sleep(Duration::from_millis(100));
            }
        });

        let pool_error = pool.inner.lock().unwrap().error.take();
        drop(pool);

        if let Some(err) = pool_error {
            file.sync_data()?;
            return Err(err);
        }
    }

    // All blocks complete: read last byte to check PKCS#7 padding
    let mut last_byte = [0u8; 1];
    read_at(&file, &mut last_byte, client.info.size - 1)?;
    let last_byte = last_byte[0];
    file.sync_data()?;

    let padding = if last_byte > 0 && last_byte <= 16 {
        last_byte as u64
    } else {
        0
    };
    let final_len = client.info.size - padding;
    file.set_len(final_len)?;
    drop(file);

    if final_path.exists() {
        let _ = std::fs::remove_file(final_path);
    }
    std::fs::rename(&part_path, final_path)?;

    Ok(())
}

struct Chunk {
    start: u64,
    len: u64,
    end: Option<u64>,
}

struct Pool {
    inner: Mutex<PoolInner>,
    available: Condvar,
}

struct PoolInner {
    queue: VecDeque<Chunk>,
    in_flight: usize,
    live: usize,
    error: Option<crate::Error>,
}

enum ChunkOutcome {
    Done,
    Stalled { decrypted: u64 },
    Failed(crate::Error),
}

const MAX_STALL_RETRIES: u32 = 4;
const MAX_DEAD_STALLS: u32 = 4;

fn run_worker(
    pool: &Pool,
    client: &FusClient,
    file: &File,
    progress: &impl DownloadProgress,
    tracker: &Mutex<StateTracker<'_>>,
) {
    let mut last_progress = 0_u64;
    let mut dead_stalls = 0_u32;

    loop {
        let chunk = {
            let mut state = pool.inner.lock().unwrap();
            loop {
                if state.error.is_some() {
                    state.live -= 1;
                    pool.available.notify_all();
                    return;
                }
                if let Some(chunk) = state.queue.pop_front() {
                    state.in_flight += 1;
                    break chunk;
                }
                if state.in_flight == 0 {
                    state.live -= 1;
                    pool.available.notify_all();
                    return;
                }
                state = pool.available.wait(state).unwrap();
            }
        };

        let outcome = download_chunk(
            client,
            file,
            chunk.start,
            chunk.len,
            chunk.end,
            progress,
            tracker,
        );

        match outcome {
            ChunkOutcome::Done => {
                dead_stalls = 0;
                let mut state = pool.inner.lock().unwrap();
                state.in_flight -= 1;
                pool.available.notify_all();
            }
            ChunkOutcome::Failed(err) => {
                let mut state = pool.inner.lock().unwrap();
                if state.error.is_none() {
                    state.error = Some(err);
                }
                state.in_flight -= 1;
                state.live -= 1;
                pool.available.notify_all();
                return;
            }
            ChunkOutcome::Stalled { decrypted } => {
                let stall_off = chunk.start + decrypted;
                let remainder = Chunk {
                    start: stall_off,
                    len: chunk.len - decrypted,
                    end: chunk.end,
                };

                let mut state = pool.inner.lock().unwrap();

                if state.error.is_some() {
                    state.in_flight -= 1;
                    state.live -= 1;
                    pool.available.notify_all();
                    return;
                }

                state.in_flight -= 1;
                state.queue.push_back(remainder);

                if state.live > 1 {
                    state.live -= 1;
                    let remaining = state.live;
                    pool.available.notify_all();
                    drop(state);
                    progress.println_verbose(&format!(
                        "Connection throttled at offset {stall_off}; \
                         reducing to {remaining} connection(s)"
                    ));
                    return;
                }

                pool.available.notify_all();
                drop(state);

                let pos = progress.position();
                if pos > last_progress {
                    last_progress = pos;
                    dead_stalls = 0;
                } else {
                    dead_stalls += 1;
                    if dead_stalls > MAX_DEAD_STALLS {
                        let mut state = pool.inner.lock().unwrap();
                        state.error = Some(crate::Error::Stalled { offset: stall_off });
                        state.live -= 1;
                        pool.available.notify_all();
                        return;
                    }
                }
            }
        }
    }
}

fn download_chunk(
    client: &FusClient,
    file: &File,
    start: u64,
    len: u64,
    end: Option<u64>,
    progress: &impl DownloadProgress,
    tracker: &Mutex<StateTracker<'_>>,
) -> ChunkOutcome {
    let mut dec = client.get_decryptor();
    let mut buf = vec![0u8; WRITE_BUF_SIZE];
    // Bytes of this chunk decrypted and written to `file`.
    let mut dec_pos = 0_u64;
    let mut retries = 0_u32;

    loop {
        let mut resp = match client.download_file(Some(start + dec_pos), end) {
            Ok(resp) => resp,
            Err(e) => {
                retries += 1;
                if retries > MAX_STALL_RETRIES {
                    return ChunkOutcome::Stalled { decrypted: dec_pos };
                }
                progress.println_verbose(&format!(
                    "Request error ({e}); retry {retries}/{MAX_STALL_RETRIES} at offset {}",
                    start + dec_pos
                ));
                thread::sleep(backoff(retries));
                continue;
            }
        };

        let resume_from = dec_pos;
        // Bytes at the front of `buf` received but not yet decrypted (less than one AES block).
        let mut pending = 0_usize;

        let stall = loop {
            let want = ((buf.len() - pending) as u64).min(len - dec_pos - pending as u64) as usize;
            match resp.read(&mut buf[pending..pending + want]) {
                Ok(0) => {
                    return match tracker.lock().unwrap().on_bytes_decrypted(
                        start,
                        resume_from,
                        dec_pos,
                    ) {
                        Ok(()) => ChunkOutcome::Done,
                        Err(e) => ChunkOutcome::Failed(e.into()),
                    };
                }
                Ok(n) => pending += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => break e,
            }

            let whole = pending - pending % 16;
            let (blocks, _) = InOutBuf::from(&mut buf[..whole]).into_chunks();
            dec.decrypt_blocks_inout(blocks);
            if let Err(e) = write_at(file, &buf[..whole], start + dec_pos) {
                return ChunkOutcome::Failed(e.into());
            }
            buf.copy_within(whole..pending, 0);
            pending -= whole;

            let prev_dec = dec_pos;
            dec_pos += whole as u64;
            progress.inc(whole as u64);

            if let Err(e) = tracker
                .lock()
                .unwrap()
                .on_bytes_decrypted(start, prev_dec, dec_pos)
            {
                return ChunkOutcome::Failed(e.into());
            }
        };

        if dec_pos == len {
            return match tracker
                .lock()
                .unwrap()
                .on_bytes_decrypted(start, resume_from, dec_pos)
            {
                Ok(()) => ChunkOutcome::Done,
                Err(e) => ChunkOutcome::Failed(e.into()),
            };
        }

        if dec_pos > resume_from {
            retries = 0;
        }
        retries += 1;
        if retries > MAX_STALL_RETRIES {
            return ChunkOutcome::Stalled { decrypted: dec_pos };
        }
        progress.println_verbose(&format!(
            "Download error ({stall}); retry {retries}/{MAX_STALL_RETRIES}, \
             resuming at offset {}",
            start + dec_pos
        ));
        thread::sleep(backoff(retries));
    }
}

fn backoff(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << (attempt - 1).min(5)).min(30))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::BinaryInform;
    use std::io::Cursor;

    fn make_test_client(size: u64) -> FusClient {
        FusClient::new_mock(BinaryInform {
            version: "S931U1UES1AXB2/S931U1OYM1AXB2/S931U1UES1AXB2/S931U1UES1AXB2".to_string(),
            filename: "SM-S931U1_1_20240215120000_abcdefghij_fac.zip.enc4".to_string(),
            path: "T1/SM-S931U1/XAA/".to_string(),
            size,
            key: vec![0x42; 16],
            model_type: "SM-S931U1".to_string(),
            region: "XAA".to_string(),
        })
    }

    #[test]
    fn test_footer_layout_and_serialization() {
        let client = make_test_client(5 * 1024 * 1024); // 5 MiB -> 3 blocks (2 + 2 + 1)
        let layout = FooterLayout::new(&client);
        assert_eq!(layout.num_blocks, 3);
        assert_eq!(layout.bitfield_len, 1);

        let mut buf = vec![0u8; layout.footer_len];
        layout.serialize_initial(&client, &mut buf);

        let mut cursor = Cursor::new(vec![0u8; 5 * 1024 * 1024]);
        cursor.seek(SeekFrom::End(0)).unwrap();
        cursor.write_all(&buf).unwrap();

        let parsed = ParsedFooter::read_and_validate(&mut cursor, &client)
            .expect("Footer validation failed");
        assert_eq!(parsed.num_blocks, 3);
        assert_eq!(parsed.bitfield, vec![0]);
    }

    #[test]
    fn test_footer_validation_failures() {
        let client = make_test_client(4 * 1024 * 1024);
        let layout = FooterLayout::new(&client);
        let mut buf = vec![0u8; layout.footer_len];
        layout.serialize_initial(&client, &mut buf);

        // Tamper with magic
        let mut tampered = buf.clone();
        let len = tampered.len();
        tampered[len - 1] ^= 0xFF;
        let mut cursor = Cursor::new(vec![0u8; 4 * 1024 * 1024]);
        cursor.write_all(&tampered).unwrap();
        assert!(ParsedFooter::read_and_validate(&mut cursor, &client).is_none());

        // Tamper with checksum
        let mut tampered = buf.clone();
        tampered[len - 20] ^= 0xFF;
        let mut cursor = Cursor::new(vec![0u8; 4 * 1024 * 1024]);
        cursor.write_all(&tampered).unwrap();
        assert!(ParsedFooter::read_and_validate(&mut cursor, &client).is_none());

        // Mismatched client info (e.g. different size)
        let mut cursor = Cursor::new(vec![0u8; 4 * 1024 * 1024]);
        cursor.write_all(&buf).unwrap();
        let other_client = make_test_client(8 * 1024 * 1024);
        assert!(ParsedFooter::read_and_validate(&mut cursor, &other_client).is_none());
    }

    #[test]
    fn test_bitfield_and_range_extraction() {
        // 5 blocks: block 0 (done), block 1 (not done), block 2 (done), block 3, 4 (not done)
        let bitfield = vec![0b0000_0101]; // bit 0 and bit 2 set
        let total_size = 5 * BLOCK_SIZE as u64;
        let completed = calculate_completed_bytes(&bitfield, 5, total_size);
        assert_eq!(completed, 2 * BLOCK_SIZE as u64);

        let uncompleted = extract_uncompleted_ranges(&bitfield, 5, total_size);
        assert_eq!(
            uncompleted,
            vec![
                ByteRange {
                    start: BLOCK_SIZE as u64,
                    end: 2 * BLOCK_SIZE as u64,
                },
                ByteRange {
                    start: 3 * BLOCK_SIZE as u64,
                    end: 5 * BLOCK_SIZE as u64,
                },
            ]
        );

        let partitioned = partition_ranges_for_threads(&uncompleted, 4);
        assert_eq!(partitioned.len(), 3);
    }

    #[test]
    fn test_state_tracker_block_completion() {
        let client = make_test_client(4 * 1024 * 1024); // 2 blocks
        let layout = FooterLayout::new(&client);
        let mut footer = vec![0u8; layout.footer_len];
        layout.serialize_initial(&client, &mut footer);

        {
            let mut tracker = StateTracker::new(
                &mut footer,
                layout.bitfield_offset,
                layout.num_blocks,
                client.info.size,
            );

            // Decrypt first 1 MiB (not complete block yet)
            tracker.on_bytes_decrypted(0, 0, 1024 * 1024).unwrap();
            assert_eq!(tracker.footer[layout.bitfield_offset], 0);

            // Decrypt across 2 MiB boundary -> block 0 complete!
            tracker
                .on_bytes_decrypted(0, 1024 * 1024, BLOCK_SIZE as u64)
                .unwrap();
            assert_eq!(tracker.footer[layout.bitfield_offset], 0b01);

            // Complete block 1
            tracker
                .on_bytes_decrypted(BLOCK_SIZE as u64, 0, BLOCK_SIZE as u64)
                .unwrap();
            assert_eq!(tracker.footer[layout.bitfield_offset], 0b11);
        }

        // Verify checksum is valid immediately after block completion
        let mut cursor = Cursor::new(vec![0u8; 4 * 1024 * 1024]);
        cursor.seek(SeekFrom::End(0)).unwrap();
        cursor.write_all(&footer).unwrap();
        let parsed = ParsedFooter::read_and_validate(&mut cursor, &client)
            .expect("Footer must validate immediately after block completion");
        assert_eq!(parsed.bitfield, vec![0b11]);
    }

    #[test]
    fn test_abrupt_interruption_and_resume() {
        let client = make_test_client(10 * 1024 * 1024); // 5 blocks
        let layout = FooterLayout::new(&client);
        let mut footer = vec![0u8; layout.footer_len];
        layout.serialize_initial(&client, &mut footer);

        // First run: completes block 0 and 1, then abruptly stops (no manual flush)
        {
            let mut tracker = StateTracker::new(
                &mut footer,
                layout.bitfield_offset,
                layout.num_blocks,
                client.info.size,
            );
            tracker
                .on_bytes_decrypted(0, 0, 2 * BLOCK_SIZE as u64)
                .unwrap();
        }

        // Validate that footer is immediately valid and recognizes blocks 0 and 1
        let mut cursor = Cursor::new(vec![0u8; 10 * 1024 * 1024]);
        cursor.seek(SeekFrom::End(0)).unwrap();
        cursor.write_all(&footer).unwrap();
        let parsed = ParsedFooter::read_and_validate(&mut cursor, &client)
            .expect("Must be valid immediately after abrupt interruption");
        assert_eq!(parsed.bitfield[0] & 0b11, 0b11);
        let uncompleted =
            extract_uncompleted_ranges(&parsed.bitfield, parsed.num_blocks, client.info.size);
        assert_eq!(
            uncompleted,
            vec![ByteRange {
                start: 2 * BLOCK_SIZE as u64,
                end: 10 * 1024 * 1024,
            }]
        );

        // Second run: resumes and completes block 2 abruptly
        {
            let mut tracker = StateTracker::new(
                &mut footer,
                layout.bitfield_offset,
                layout.num_blocks,
                client.info.size,
            );
            tracker
                .on_bytes_decrypted(2 * BLOCK_SIZE as u64, 0, BLOCK_SIZE as u64)
                .unwrap();
        }

        let mut cursor = Cursor::new(vec![0u8; 10 * 1024 * 1024]);
        cursor.seek(SeekFrom::End(0)).unwrap();
        cursor.write_all(&footer).unwrap();
        let parsed2 = ParsedFooter::read_and_validate(&mut cursor, &client)
            .expect("Must be valid after second resume");
        assert_eq!(parsed2.bitfield[0] & 0b111, 0b111);
        let uncompleted2 =
            extract_uncompleted_ranges(&parsed2.bitfield, parsed2.num_blocks, client.info.size);
        assert_eq!(
            uncompleted2,
            vec![ByteRange {
                start: 3 * BLOCK_SIZE as u64,
                end: 10 * 1024 * 1024,
            }]
        );
    }

    #[test]
    fn test_state_tracker_writes_through_to_file() {
        let client = make_test_client(4 * 1024 * 1024); // 2 blocks
        let layout = FooterLayout::new(&client);
        let mut footer = vec![0u8; layout.footer_len];
        layout.serialize_initial(&client, &mut footer);

        let path =
            std::env::temp_dir().join(format!("samloader-tracker-{}.part", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.set_len(client.info.size).unwrap();
        write_at(&file, &footer, client.info.size).unwrap();

        {
            let mut tracker = StateTracker::new(
                &mut footer,
                layout.bitfield_offset,
                layout.num_blocks,
                client.info.size,
            )
            .with_sink(&file, client.info.size);
            tracker.on_bytes_decrypted(0, 0, BLOCK_SIZE as u64).unwrap();
        }

        let mut reader = File::open(&path).unwrap();
        let parsed = ParsedFooter::read_and_validate(&mut reader, &client)
            .expect("Footer on disk must validate after a block completes");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(parsed.bitfield, vec![0b01]);
    }

    #[test]
    fn test_positioned_io_round_trip() {
        let path = std::env::temp_dir().join(format!("samloader-pio-{}.bin", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        // Out of order and past the end of the file, as concurrent workers write.
        let big = vec![0xAB; 3 * 1024 * 1024 + 7];
        write_at(&file, b"world", 1_000_005).unwrap();
        write_at(&file, b"hello", 1_000_000).unwrap();
        write_at(&file, &big, 2_000_000).unwrap();

        let mut words = [0u8; 10];
        read_at(&file, &mut words, 1_000_000).unwrap();
        let mut gap = [0xFFu8; 16];
        read_at(&file, &mut gap, 500).unwrap();
        let mut back = vec![0u8; big.len()];
        read_at(&file, &mut back, 2_000_000).unwrap();
        let end = 2_000_000 + big.len() as u64;
        let past_end = read_at(&file, &mut [0u8; 4], end - 2).unwrap_err();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(&words, b"helloworld");
        assert_eq!(gap, [0u8; 16]);
        assert!(back == big);
        assert_eq!(past_end.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
