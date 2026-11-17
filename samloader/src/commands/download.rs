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

use crate::cli::DownloadArgs;
use fast_md5::Md5;
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::MmapMut;
use samloader_fus::{BinaryInform, DownloadSession, FusClient, fetch_history};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::Duration;

const PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

/// The chunk size of each independently tracked download block (2 MiB).
/// 2 MiB = 2,097,152 bytes = 131,072 AES-128 blocks (aligned to 16 bytes).
const BLOCK_SIZE: usize = 2 * 1024 * 1024;

/// Magic identifier placed at the trailing 8 bytes of the footer.
const FOOTER_MAGIC: &[u8; 8] = b"SAMLOADR";

/// Version of the footer layout format.
const FOOTER_VERSION: u32 = 3;

/// Byte offset of the 1-byte EOF PKCS#7 padding length within the footer header.
const PADDING_OFFSET: usize = 28;

/// Length of the fixed header:
/// 4 (version) + 16 (info_checksum) + 4 (block_size) + 4 (num_blocks) + 1 (padding) = 29 bytes.
const HEADER_LEN: usize = 29;

/// Length of the fixed trailing trailer: 4 (footer_len) + 8 (magic) = 12 bytes.
const TRAILER_LEN: usize = 12;

const MAX_STALL_RETRIES: u32 = 4;
const MAX_DEAD_STALLS: u32 = 4;

#[derive(Debug)]
enum DownloadError {
    Io(io::Error),
    Stalled { offset: u64 },
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Stalled { offset } => {
                write!(
                    f,
                    "Download stalled at offset {offset}: server stopped responding"
                )
            }
        }
    }
}

impl Error for DownloadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Stalled { .. } => None,
        }
    }
}

impl From<io::Error> for DownloadError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

struct Reporter<'a> {
    pb: &'a ProgressBar,
    verbose: bool,
}

impl Reporter<'_> {
    fn set_length(&self, len: u64) {
        self.pb.set_length(len);
    }

    fn shrink_length(&self, delta: u64) {
        if let Some(len) = self.pb.length() {
            self.pb.set_length(len.saturating_sub(delta));
        }
    }

    fn set_position(&self, pos: u64) {
        self.pb.disable_steady_tick();
        self.pb.set_position(pos);
        self.pb.reset_elapsed();
        self.pb.reset_eta();
        self.pb.enable_steady_tick(Duration::from_secs(1));
    }

    fn inc(&self, bytes: u64) {
        self.pb.inc(bytes);
    }

    fn position(&self) -> u64 {
        self.pb.position()
    }

    fn println(&self, msg: &str) {
        self.pb.println(msg);
    }

    fn println_verbose(&self, msg: &str) {
        if self.verbose {
            self.pb.println(msg);
        }
    }
}

fn info_checksum(info: &BinaryInform) -> [u8; 16] {
    fn update_len_prefixed(hasher: &mut Md5, data: &[u8]) {
        hasher.update(&(data.len() as u64).to_le_bytes());
        hasher.update(data);
    }

    let mut hasher = Md5::new();
    update_len_prefixed(&mut hasher, info.version.as_bytes());
    update_len_prefixed(&mut hasher, info.filename.as_bytes());
    update_len_prefixed(&mut hasher, info.path.as_bytes());
    hasher.update(&info.size.to_le_bytes());
    hasher.update(&info.key);
    update_len_prefixed(&mut hasher, info.model_type.as_bytes());
    update_len_prefixed(&mut hasher, info.region.as_bytes());
    hasher.finalize()
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
    fn new(info: &BinaryInform) -> Self {
        let num_blocks = info.size.div_ceil(BLOCK_SIZE as u64) as usize;
        let bitfield_len = num_blocks.div_ceil(8);
        let footer_len = HEADER_LEN + bitfield_len + TRAILER_LEN;

        Self {
            num_blocks,
            bitfield_len,
            footer_len,
        }
    }

    fn serialize_initial(&self, info: &BinaryInform, out: &mut [u8]) {
        assert_eq!(out.len(), self.footer_len);
        let mut cursor = 0;

        out[cursor..cursor + 4].copy_from_slice(&FOOTER_VERSION.to_le_bytes());
        cursor += 4;
        out[cursor..cursor + 16].copy_from_slice(&info_checksum(info));
        cursor += 16;
        out[cursor..cursor + 4].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
        cursor += 4;
        out[cursor..cursor + 4].copy_from_slice(&(self.num_blocks as u32).to_le_bytes());
        cursor += 4;
        debug_assert_eq!(cursor, PADDING_OFFSET);
        out[cursor] = 0;
        cursor += 1;

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
    padding: u8,
}

impl ParsedFooter {
    fn read_and_validate<R: Read + Seek>(reader: &mut R, info: &BinaryInform) -> Option<Self> {
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

        if file_len != info.size + footer_len as u64 {
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

        let checksum = footer_bytes.get(cursor..cursor + 16)?;
        cursor += 16;
        if checksum != info_checksum(info) {
            return None;
        }

        let block_size = u32::from_le_bytes(footer_bytes.get(cursor..cursor + 4)?.try_into().ok()?);
        cursor += 4;
        if block_size != BLOCK_SIZE as u32 {
            return None;
        }

        let num_blocks = u32::from_le_bytes(footer_bytes.get(cursor..cursor + 4)?.try_into().ok()?);
        cursor += 4;
        let expected_num_blocks = info.size.div_ceil(BLOCK_SIZE as u64) as u32;
        if num_blocks != expected_num_blocks {
            return None;
        }

        debug_assert_eq!(cursor, PADDING_OFFSET);
        let padding = *footer_bytes.get(cursor)?;
        cursor += 1;
        if padding > 16 || padding as u64 > info.size {
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
            padding,
        })
    }
}

fn calculate_completed_bytes(
    bitfield: &[u8],
    num_blocks: usize,
    total_size: u64,
    padding: u8,
) -> u64 {
    let mut total = 0_u64;
    for blk in 0..num_blocks {
        if (bitfield[blk / 8] & (1 << (blk % 8))) != 0 {
            let blk_size = if blk == num_blocks - 1 {
                total_size
                    .saturating_sub(padding as u64)
                    .saturating_sub(blk as u64 * BLOCK_SIZE as u64)
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
    let threads = threads.max(1);
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
    padding: &'a mut u8,
    bitfield: &'a mut [u8],
    total_blocks: usize,
}

impl<'a> StateTracker<'a> {
    fn new(padding: &'a mut u8, bitfield: &'a mut [u8], total_blocks: usize) -> Self {
        Self {
            padding,
            bitfield,
            total_blocks,
        }
    }

    fn on_bytes_decrypted(&mut self, start: u64, prev_dec: usize, new_dec: usize) {
        let prev_pos = start + prev_dec as u64;
        let curr_pos = start + new_dec as u64;
        let start_blk = (prev_pos / BLOCK_SIZE as u64) as usize;
        let end_blk = (curr_pos / BLOCK_SIZE as u64) as usize;

        // Non-final blocks all have exact length `BLOCK_SIZE`; the final block may be
        // shortened by PKCS#7 unpadding and is marked complete in `on_eof_reached`.
        for blk in start_blk..=end_blk {
            if blk + 1 >= self.total_blocks {
                break;
            }
            let blk_end = (blk + 1) as u64 * BLOCK_SIZE as u64;
            if curr_pos >= blk_end {
                let byte_idx = blk / 8;
                let bit_mask = 1 << (blk % 8);
                self.bitfield[byte_idx] |= bit_mask;
            }
        }
    }

    fn on_eof_reached(&mut self, padding: u8) {
        *self.padding = padding;
        if self.total_blocks > 0 {
            let last = self.total_blocks - 1;
            self.bitfield[last / 8] |= 1 << (last % 8);
        }
    }
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
    error: Option<DownloadError>,
}

enum ChunkOutcome {
    Done,
    Stalled { decrypted: usize },
}

fn download_firmware(
    session: &DownloadSession,
    final_path: &Path,
    threads: u64,
    force: bool,
    progress: &Reporter<'_>,
) -> Result<(), DownloadError> {
    let info = session.info();
    let threads = threads.max(1);

    if let Some(parent) = final_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }

    let part_path = {
        let mut s = final_path.as_os_str().to_owned();
        s.push(".part");
        PathBuf::from(s)
    };

    if force {
        let _ = std::fs::remove_file(final_path);
        let _ = std::fs::remove_file(&part_path);
    }

    let layout = FooterLayout::new(info);
    let total_file_len = info.size + layout.footer_len as u64;

    // Check if a valid partial download already exists
    let had_existing_part = part_path.exists();
    let existing_footer = if had_existing_part && !force {
        if let Ok(mut f) = OpenOptions::new().read(true).open(&part_path) {
            ParsedFooter::read_and_validate(&mut f, info)
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
        let last_done = pf.num_blocks > 0
            && (pf.bitfield[(pf.num_blocks - 1) / 8] & (1 << ((pf.num_blocks - 1) % 8))) != 0;
        let effective_total = if last_done {
            info.size.saturating_sub(pf.padding as u64)
        } else {
            info.size
        };
        let completed_bytes =
            calculate_completed_bytes(&pf.bitfield, pf.num_blocks, info.size, pf.padding);
        progress.println(&format!(
            "Resuming download: {:.2} GiB / {:.2} GiB ({:.1}%) already downloaded",
            completed_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            effective_total as f64 / (1024.0 * 1024.0 * 1024.0),
            if effective_total > 0 {
                (completed_bytes as f64 / effective_total as f64) * 100.0
            } else {
                100.0
            }
        ));
        progress.set_length(effective_total);
        progress.set_position(completed_bytes);
        extract_uncompleted_ranges(&pf.bitfield, pf.num_blocks, info.size)
    } else {
        if had_existing_part && !force {
            progress.println(
                "Existing partial download is incompatible or corrupted, restarting from scratch...",
            );
        }
        file.set_len(total_file_len)?;
        let mut initial_footer = vec![0u8; layout.footer_len];
        layout.serialize_initial(info, &mut initial_footer);
        file.seek(SeekFrom::Start(info.size))?;
        file.write_all(&initial_footer)?;
        file.sync_data()?;

        progress.set_length(info.size);
        progress.set_position(0);
        if info.size > 0 {
            vec![ByteRange {
                start: 0,
                end: info.size,
            }]
        } else {
            Vec::new()
        }
    };

    let mut map = unsafe { MmapMut::map_mut(&file)? };

    let download_chunks = partition_ranges_for_threads(&uncompleted, threads);

    if !download_chunks.is_empty() {
        let (payload_map, footer_map) = map.split_at_mut(info.size as usize);

        let state_slice = &mut footer_map[PADDING_OFFSET..HEADER_LEN + layout.bitfield_len];
        let (padding_slot, bitfield) = state_slice.split_first_mut().unwrap();
        let tracker = Mutex::new(StateTracker::new(padding_slot, bitfield, layout.num_blocks));

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
                    end: if range.end == info.size {
                        None
                    } else {
                        Some(range.end - 1)
                    },
                });
            }
        }

        let n_workers = queue.len().min(threads as usize);
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
                s.spawn(move || run_worker(pool, session, progress, tracker));
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

    let padding = map[info.size as usize + PADDING_OFFSET];
    map.flush()?;
    drop(map);

    let final_len = info.size.saturating_sub(padding as u64);
    file.set_len(final_len)?;
    drop(file);

    if final_path.exists() {
        let _ = std::fs::remove_file(final_path);
    }
    std::fs::rename(&part_path, final_path)?;

    Ok(())
}

fn run_worker(
    pool: &Pool<'_>,
    session: &DownloadSession,
    progress: &Reporter<'_>,
    tracker: &Mutex<StateTracker<'_>>,
) {
    let mut last_progress = progress.position();
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
            session,
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
                        state.error = Some(DownloadError::Stalled { offset: stall_off });
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
    session: &DownloadSession,
    chunk: &mut [u8],
    start: u64,
    end: Option<u64>,
    progress: &Reporter<'_>,
    tracker: &Mutex<StateTracker<'_>>,
) -> ChunkOutcome {
    let mut dec_pos = 0_usize;
    let mut retries = 0_u32;

    loop {
        let mut reader = match session.fetch_range(Some(start + dec_pos as u64), end) {
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
                Ok(0) => {
                    if end.is_none() && chunk.len() - dec_pos <= 16 {
                        let pad = (chunk.len() - dec_pos) as u8;
                        tracker.lock().unwrap().on_eof_reached(pad);
                        if pad > 0 {
                            progress.shrink_length(pad as u64);
                        }
                        return ChunkOutcome::Done;
                    }
                    break io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "premature EOF while reading chunk",
                    );
                }
                Ok(n) => {
                    let prev_dec = dec_pos;
                    dec_pos += n;
                    progress.inc(n as u64);

                    let mut guard = tracker.lock().unwrap();
                    guard.on_bytes_decrypted(start, prev_dec, dec_pos);
                    if dec_pos == chunk.len() {
                        if end.is_none() {
                            guard.on_eof_reached(0);
                        }
                        return ChunkOutcome::Done;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
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

/// Downloads and decrypts a firmware from Samsung's update servers.
pub(crate) fn run(args: DownloadArgs, verbose: bool) -> Result<(), Box<dyn Error>> {
    let version = match &args.version {
        Some(v) => v.clone(),
        None => {
            let version_info = fetch_history(&args.fus.model, &args.fus.region)
                .map_err(|e| format!("Failed to fetch version info: {e}"))?;
            version_info.latest
        }
    };

    let client = FusClient::new().map_err(|e| format!("Unable to establish FusClient: {e}"))?;
    let info = client
        .fetch_binary_info(&args.fus.model, &args.fus.region, &version)
        .map_err(|e| format!("Failed to fetch binary info: {e}"))?;

    println!("Firmware Version: {}", info.version);

    let default_name = info
        .filename
        .strip_suffix(".enc4")
        .or_else(|| info.filename.strip_suffix(".enc2"))
        .unwrap_or(info.filename.as_str());

    let final_path = match (args.out_file, args.out_dir) {
        (Some(name), _) => PathBuf::from(name),
        (None, Some(dir)) => PathBuf::from(dir).join(default_name),
        (None, None) => PathBuf::from(default_name),
    };

    if !args.force
        && let Ok(meta) = final_path.metadata()
        && meta.is_file()
        && (info.size.saturating_sub(16)..=info.size).contains(&meta.len())
    {
        println!(
            "File already exists and is complete: {}",
            final_path.display()
        );
        return Ok(());
    }

    println!("Downloading {} to {}", info.filename, final_path.display());

    let session = client
        .init_download(info)
        .map_err(|e| format!("Failed to initialize download: {e}"))?;

    let progress = ProgressBar::no_length()
        .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
    progress.enable_steady_tick(Duration::from_secs(1));

    let reporter = Reporter {
        pb: &progress,
        verbose,
    };

    if let Err(e) = download_firmware(&session, &final_path, args.threads, args.force, &reporter) {
        progress.abandon();
        // Keep the error apart from the abandoned progress bar
        eprintln!();
        return Err(format!("Download failed: {e}").into());
    }

    progress.finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn mock_info(size: u64) -> BinaryInform {
        BinaryInform {
            version: "S931U1UES1AXB2/S931U1OYM1AXB2/S931U1UES1AXB2/S931U1UES1AXB2".to_string(),
            filename: "SM-S931U1_1_20240215120000_abcdefghij_fac.zip.enc4".to_string(),
            path: "T1/SM-S931U1/XAA/".to_string(),
            size,
            key: [0x42; 16],
            model_type: "SM-S931U1".to_string(),
            region: "XAA".to_string(),
        }
    }

    #[test]
    fn test_footer_validation_failures() {
        let size = 5 * 1024 * 1024; // 3 blocks (2 + 2 + 1)
        let info = mock_info(size);
        let layout = FooterLayout::new(&info);
        assert_eq!(layout.num_blocks, 3);
        let mut buf = vec![0u8; layout.footer_len];
        layout.serialize_initial(&info, &mut buf);

        // Appends `footer` to the downloaded data and validates it
        let validate = |footer: &[u8], info: &BinaryInform| {
            let mut cursor = Cursor::new(vec![0u8; size as usize]);
            cursor.seek(SeekFrom::End(0)).unwrap();
            cursor.write_all(footer).unwrap();
            ParsedFooter::read_and_validate(&mut cursor, info).is_some()
        };

        // The untampered footer is valid, so each failure below is caused by its change
        assert!(validate(&buf, &info));

        // Tamper with header/trailer fields:
        // version, info_checksum, block_size, num_blocks, padding (> 16), footer_len, magic
        let len = buf.len();
        for offset in [0, 4, 20, 24, PADDING_OFFSET, len - 9, len - 1] {
            let mut tampered = buf.clone();
            tampered[offset] ^= 0xFF;
            assert!(!validate(&tampered, &info), "offset={offset}");
        }

        // Mismatched binary info: different size, or any mutated BinaryInform field
        assert!(!validate(&buf, &mock_info(2 * size)));
        let mutations: Vec<fn(&mut BinaryInform)> = vec![
            |i| i.version.push('X'),
            |i| i.filename.push('X'),
            |i| i.path.push('X'),
            |i| i.key[0] ^= 0xFF,
            |i| i.model_type.push('X'),
            |i| i.region.push('X'),
        ];
        for mutate in mutations {
            let mut other_info = mock_info(size);
            mutate(&mut other_info);
            assert!(!validate(&buf, &other_info));
        }
    }

    #[test]
    fn test_bitfield_and_range_extraction() {
        // 5 blocks: block 0 (done), block 1 (not done), block 2 (done), block 3, 4 (not done)
        let bitfield = vec![0b0000_0101]; // bit 0 and bit 2 set
        let total_size = 5 * BLOCK_SIZE as u64;
        let completed = calculate_completed_bytes(&bitfield, 5, total_size, 0);
        assert_eq!(completed, 2 * BLOCK_SIZE as u64);

        // When final block (bit 4) is done with 7 bytes of stripped PKCS#7 padding
        let tail_done = vec![0b0001_0101];
        assert_eq!(
            calculate_completed_bytes(&tail_done, 5, total_size, 7),
            3 * BLOCK_SIZE as u64 - 7
        );

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
        let info = mock_info(size);
        let layout = FooterLayout::new(&info);
        let mut footer = vec![0u8; layout.footer_len];
        layout.serialize_initial(&info, &mut footer);

        // The footer must be valid at any time, as downloads can stop abruptly
        let validate = |footer: &[u8]| {
            let mut cursor = Cursor::new(vec![0u8; size as usize]);
            cursor.seek(SeekFrom::End(0)).unwrap();
            cursor.write_all(footer).unwrap();
            let parsed = ParsedFooter::read_and_validate(&mut cursor, &info)
                .expect("Footer must validate immediately after block completion");
            let uncompleted = extract_uncompleted_ranges(&parsed.bitfield, parsed.num_blocks, size);
            (parsed.bitfield, parsed.padding, uncompleted)
        };

        // First run: completes blocks 0 and 1, plus out-of-order final block 4 with 11-byte padding
        {
            let state_slice = &mut footer[PADDING_OFFSET..HEADER_LEN + layout.bitfield_len];
            let (pad_slot, bitfield) = state_slice.split_first_mut().unwrap();
            let mut tracker = StateTracker::new(pad_slot, bitfield, layout.num_blocks);

            // Decrypt first 1 MiB (not complete block yet)
            tracker.on_bytes_decrypted(0, 0, 1024 * 1024);
            assert_eq!(tracker.bitfield[0], 0);

            // Decrypt across the 2 MiB boundary -> block 0 complete
            tracker.on_bytes_decrypted(0, 1024 * 1024, BLOCK_SIZE);
            assert_eq!(tracker.bitfield[0], 0b01);

            // Complete block 1
            tracker.on_bytes_decrypted(BLOCK_SIZE as u64, 0, BLOCK_SIZE);
            assert_eq!(tracker.bitfield[0], 0b11);

            // Tail block 4 reaches EOF 11 bytes short due to PKCS#7 unpadding
            tracker.on_bytes_decrypted(4 * BLOCK_SIZE as u64, 0, BLOCK_SIZE - 11);
            assert_eq!(tracker.bitfield[0], 0b00011);
            tracker.on_eof_reached(11);
            assert_eq!(tracker.bitfield[0], 0b10011);
        }

        assert_eq!(
            validate(&footer),
            (
                vec![0b10011],
                11,
                vec![ByteRange {
                    start: 2 * BLOCK_SIZE as u64,
                    end: 4 * BLOCK_SIZE as u64,
                }]
            )
        );

        // Second run: resumes and completes block 2; persisted padding (11) remains intact
        {
            let state_slice = &mut footer[PADDING_OFFSET..HEADER_LEN + layout.bitfield_len];
            let (pad_slot, bitfield) = state_slice.split_first_mut().unwrap();
            let mut tracker = StateTracker::new(pad_slot, bitfield, layout.num_blocks);
            tracker.on_bytes_decrypted(2 * BLOCK_SIZE as u64, 0, BLOCK_SIZE);
        }

        assert_eq!(
            validate(&footer),
            (
                vec![0b10111],
                11,
                vec![ByteRange {
                    start: 3 * BLOCK_SIZE as u64,
                    end: 4 * BLOCK_SIZE as u64,
                }]
            )
        );
    }
}
