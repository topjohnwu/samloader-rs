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
use memmap2::MmapMut;
use std::collections::VecDeque;
use std::fs::OpenOptions;
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
const FOOTER_VERSION: u32 = 2;

/// Length of the fixed header: 4 (version) + 16 (info_checksum) + 4 (block_size) + 4 (num_blocks) = 28 bytes.
const HEADER_LEN: usize = 28;

/// Length of the fixed trailing trailer: 4 (footer_len) + 8 (magic) = 12 bytes.
const TRAILER_LEN: usize = 12;

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
    bitfield_len: usize,
    footer_len: usize,
}

impl FooterLayout {
    fn new(client: &FusClient) -> Self {
        let num_blocks = client.info.size.div_ceil(BLOCK_SIZE as u64) as usize;
        let bitfield_len = num_blocks.div_ceil(8);
        let footer_len = HEADER_LEN + bitfield_len + TRAILER_LEN;

        Self {
            num_blocks,
            bitfield_len,
            footer_len,
        }
    }

    fn serialize_initial(&self, client: &FusClient, out: &mut [u8]) {
        assert_eq!(out.len(), self.footer_len);
        let mut cursor = 0;

        out[cursor..cursor + 4].copy_from_slice(&FOOTER_VERSION.to_le_bytes());
        cursor += 4;
        out[cursor..cursor + 16].copy_from_slice(&client.info.checksum());
        cursor += 16;
        out[cursor..cursor + 4].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
        cursor += 4;
        out[cursor..cursor + 4].copy_from_slice(&(self.num_blocks as u32).to_le_bytes());
        cursor += 4;

        debug_assert_eq!(cursor, HEADER_LEN);

        // Zero out bitfield initially
        out[cursor..cursor + self.bitfield_len].fill(0);
        cursor += self.bitfield_len;

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
        if file_len < (HEADER_LEN + TRAILER_LEN) as u64 {
            return None;
        }

        // Read trailing 12 bytes: footer_len (4) + magic (8)
        reader.seek(SeekFrom::End(-(TRAILER_LEN as i64))).ok()?;
        let mut tail = [0u8; TRAILER_LEN];
        reader.read_exact(&mut tail).ok()?;
        let (footer_len_bytes, magic_bytes) = tail.split_at(4);
        if magic_bytes != FOOTER_MAGIC {
            return None;
        }
        let footer_len = u32::from_le_bytes(footer_len_bytes.try_into().unwrap()) as usize;
        if footer_len < HEADER_LEN + TRAILER_LEN || footer_len as u64 > file_len {
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

        let info_checksum = footer_bytes.get(cursor..cursor + 16)?;
        cursor += 16;
        if info_checksum != client.info.checksum() {
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

        debug_assert_eq!(cursor, HEADER_LEN);

        let bitfield_len = (num_blocks as usize).div_ceil(8);
        if HEADER_LEN + bitfield_len != payload_len {
            return None;
        }

        let bitfield = footer_bytes
            .get(HEADER_LEN..HEADER_LEN + bitfield_len)?
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
    bitfield: &'a mut [u8],
    total_blocks: usize,
    file_size: u64,
}

impl<'a> StateTracker<'a> {
    fn new(bitfield: &'a mut [u8], total_blocks: usize, file_size: u64) -> Self {
        Self {
            bitfield,
            total_blocks,
            file_size,
        }
    }

    fn on_bytes_decrypted(&mut self, start: u64, prev_dec: usize, new_dec: usize) {
        let prev_pos = start + prev_dec as u64;
        let curr_pos = start + new_dec as u64;
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
                let byte_idx = blk / 8;
                let bit_mask = 1 << (blk % 8);
                self.bitfield[byte_idx] |= bit_mask;
            }
        }
    }
}

/// Downloads the firmware binary in parallel across multiple threads, decrypting it in place,
/// supporting interruption and resumption via an embedded `.part` footer.
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

    let mut map = unsafe { MmapMut::map_mut(&file)? };

    let download_chunks = partition_ranges_for_threads(&uncompleted, options.threads);

    if !download_chunks.is_empty() {
        client.init_download()?;

        let (payload_map, footer_map) = map.split_at_mut(client.info.size as usize);

        let tracker = Mutex::new(StateTracker::new(
            &mut footer_map[HEADER_LEN..HEADER_LEN + layout.bitfield_len],
            layout.num_blocks,
            client.info.size,
        ));

        let mut queue = VecDeque::new();
        {
            let mut rest = payload_map;
            let mut current_offset = 0_u64;

            for range in &download_chunks {
                let skip = (range.start - current_offset) as usize;
                let (_, tail) = rest.split_at_mut(skip);
                let len = (range.end - range.start) as usize;
                let (buf, next_rest) = tail.split_at_mut(len);
                current_offset = range.end;
                rest = next_rest;

                queue.push_back(Chunk {
                    buf,
                    start: range.start,
                    end: if range.end == client.info.size {
                        None
                    } else {
                        Some(range.end - 1)
                    },
                });
            }
        }

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
            for _ in 0..n_workers {
                s.spawn(move || run_worker(pool, client, progress, tracker));
                thread::sleep(Duration::from_millis(100));
            }
        });

        let pool_error = pool.inner.lock().unwrap().error.take();
        drop(pool);

        if let Some(err) = pool_error {
            map.flush()?;
            return Err(err);
        }
    }

    // All blocks complete: read last byte to check PKCS#7 padding
    let last_byte = map[client.info.size as usize - 1];
    map.flush()?;
    drop(map);

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

struct Chunk<'a> {
    buf: &'a mut [u8],
    start: u64,
    end: Option<u64>,
}

struct Pool<'a> {
    inner: Mutex<PoolInner<'a>>,
    available: Condvar,
}

struct PoolInner<'a> {
    queue: VecDeque<Chunk<'a>>,
    in_flight: usize,
    live: usize,
    error: Option<crate::Error>,
}

enum ChunkOutcome {
    Done,
    Stalled { decrypted: usize },
}

const MAX_STALL_RETRIES: u32 = 4;
const MAX_DEAD_STALLS: u32 = 4;

fn run_worker(
    pool: &Pool<'_>,
    client: &FusClient,
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
            &mut chunk.buf[..],
            chunk.start,
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
            ChunkOutcome::Stalled { decrypted } => {
                let stall_off = chunk.start + decrypted as u64;
                let Chunk { buf, end, .. } = chunk;
                let (_done, rest) = buf.split_at_mut(decrypted);
                let remainder = Chunk {
                    buf: rest,
                    start: stall_off,
                    end,
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
    chunk: &mut [u8],
    start: u64,
    end: Option<u64>,
    progress: &impl DownloadProgress,
    tracker: &Mutex<StateTracker<'_>>,
) -> ChunkOutcome {
    let mut dec_pos = 0_usize;
    let mut retries = 0_u32;

    loop {
        let mut reader = match client.download_file(Some(start + dec_pos as u64), end) {
            Ok(reader) => reader,
            Err(e) => {
                retries += 1;
                if retries > MAX_STALL_RETRIES {
                    return ChunkOutcome::Stalled { decrypted: dec_pos };
                }
                progress.println_verbose(&format!(
                    "Request error ({e}); retry {retries}/{MAX_STALL_RETRIES} at offset {}",
                    start + dec_pos as u64
                ));
                thread::sleep(backoff(retries));
                continue;
            }
        };

        let resume_from = dec_pos;

        let stall = loop {
            match reader.read(&mut chunk[dec_pos..]) {
                Ok(0) => return ChunkOutcome::Done,
                Ok(n) => {
                    let prev_dec = dec_pos;
                    dec_pos += n;
                    progress.inc(n as u64);

                    tracker
                        .lock()
                        .unwrap()
                        .on_bytes_decrypted(start, prev_dec, dec_pos);

                    if dec_pos == chunk.len() {
                        return ChunkOutcome::Done;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => break e,
            }
        };

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
            start + dec_pos as u64
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
    use std::io::Cursor;

    #[test]
    fn test_footer_validation_failures() {
        let size = 5 * 1024 * 1024; // 3 blocks (2 + 2 + 1)
        let client = FusClient::new_mock(size);
        let layout = FooterLayout::new(&client);
        assert_eq!(layout.num_blocks, 3);
        let mut buf = vec![0u8; layout.footer_len];
        layout.serialize_initial(&client, &mut buf);

        // Appends `footer` to the downloaded data and validates it
        let validate = |footer: &[u8], client: &FusClient| {
            let mut cursor = Cursor::new(vec![0u8; size as usize]);
            cursor.seek(SeekFrom::End(0)).unwrap();
            cursor.write_all(footer).unwrap();
            ParsedFooter::read_and_validate(&mut cursor, client).is_some()
        };

        // The untampered footer is valid, so each failure below is caused by its change
        assert!(validate(&buf, &client));

        // Tamper with header/trailer fields: version, info_checksum, block_size, num_blocks, footer_len, magic
        let len = buf.len();
        for offset in [0, 4, 20, 24, len - 9, len - 1] {
            let mut tampered = buf.clone();
            tampered[offset] ^= 0xFF;
            assert!(!validate(&tampered, &client), "offset={offset}");
        }

        // Mismatched client info: different size, or any mutated BinaryInform field
        assert!(!validate(&buf, &FusClient::new_mock(2 * size)));
        let mutations: Vec<fn(&mut crate::BinaryInform)> = vec![
            |i| i.version.push('X'),
            |i| i.filename.push('X'),
            |i| i.path.push('X'),
            |i| i.key[0] ^= 0xFF,
            |i| i.model_type.push('X'),
            |i| i.region.push('X'),
        ];
        for mutate in mutations {
            let mut other_client = FusClient::new_mock(size);
            mutate(&mut other_client.info);
            assert!(!validate(&buf, &other_client));
        }
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
    fn test_state_tracker_interruption_and_resume() {
        let size = 10 * 1024 * 1024; // 5 blocks
        let client = FusClient::new_mock(size);
        let layout = FooterLayout::new(&client);
        let mut footer = vec![0u8; layout.footer_len];
        layout.serialize_initial(&client, &mut footer);

        // The footer must be valid at any time, as downloads can stop abruptly
        let validate = |footer: &[u8]| {
            let mut cursor = Cursor::new(vec![0u8; size as usize]);
            cursor.seek(SeekFrom::End(0)).unwrap();
            cursor.write_all(footer).unwrap();
            let parsed = ParsedFooter::read_and_validate(&mut cursor, &client)
                .expect("Footer must validate immediately after block completion");
            let uncompleted = extract_uncompleted_ranges(&parsed.bitfield, parsed.num_blocks, size);
            (parsed.bitfield, uncompleted)
        };

        // First run: completes blocks 0 and 1, then abruptly stops (no manual flush)
        {
            let mut tracker = StateTracker::new(
                &mut footer[HEADER_LEN..HEADER_LEN + layout.bitfield_len],
                layout.num_blocks,
                client.info.size,
            );

            // Decrypt first 1 MiB (not complete block yet)
            tracker.on_bytes_decrypted(0, 0, 1024 * 1024);
            assert_eq!(tracker.bitfield[0], 0);

            // Decrypt across the 2 MiB boundary -> block 0 complete
            tracker.on_bytes_decrypted(0, 1024 * 1024, BLOCK_SIZE);
            assert_eq!(tracker.bitfield[0], 0b01);

            // Complete block 1
            tracker.on_bytes_decrypted(BLOCK_SIZE as u64, 0, BLOCK_SIZE);
            assert_eq!(tracker.bitfield[0], 0b11);
        }

        let range = |start: usize| ByteRange {
            start: (start * BLOCK_SIZE) as u64,
            end: size,
        };
        assert_eq!(validate(&footer), (vec![0b11], vec![range(2)]));

        // Second run: resumes and completes block 2
        {
            let mut tracker = StateTracker::new(
                &mut footer[HEADER_LEN..HEADER_LEN + layout.bitfield_len],
                layout.num_blocks,
                client.info.size,
            );
            tracker.on_bytes_decrypted(2 * BLOCK_SIZE as u64, 0, BLOCK_SIZE);
        }

        assert_eq!(validate(&footer), (vec![0b111], vec![range(3)]));
    }
}
