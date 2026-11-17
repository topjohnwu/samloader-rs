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
use binrw::{BinRead, BinWrite, binrw};
use fast_md5::Md5;
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::MmapMut;
use samloader_fus::{BinaryInform, DownloadSession, FusClient, fetch_history};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::Duration;

const PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

/// The chunk size of each independently tracked download block (2 MiB).
/// 2 MiB = 2,097,152 bytes = 131,072 AES-128 blocks (aligned to 16 bytes).
const BLOCK_SIZE: usize = 2 * 1024 * 1024;

/// Version of the `.part` footer layout format.
const FOOTER_VERSION: u32 = 3;

const MAX_STALL_RETRIES: u32 = 4;
const MAX_DEAD_STALLS: u32 = 4;

struct Reporter<'a> {
    pb: &'a ProgressBar,
    verbose: bool,
}

impl Reporter<'_> {
    fn log_verbose(&self, msg: fmt::Arguments<'_>) {
        if self.verbose {
            self.pb.println(msg.to_string());
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

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct ByteRange {
    start: u64,
    end: u64, // exclusive
}

/// Packed LSB-first bitfield tracking completion of `len` download blocks.
#[binrw]
#[brw(little)]
#[br(import(len: usize))]
struct BlockBits {
    #[br(count = len.div_ceil(8))]
    bytes: Vec<u8>,
    #[br(calc = len)]
    #[bw(ignore)]
    len: usize,
}

impl BlockBits {
    fn new(len: usize) -> Self {
        Self {
            bytes: vec![0; len.div_ceil(8)],
            len,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn get(&self, blk: usize) -> bool {
        blk < self.len && (self.bytes[blk / 8] & (1 << (blk % 8))) != 0
    }

    fn set(&mut self, blk: usize) -> bool {
        assert!(blk < self.len);
        let mask = 1 << (blk % 8);
        let slot = &mut self.bytes[blk / 8];
        let newly_set = (*slot & mask) == 0;
        *slot |= mask;
        newly_set
    }

    fn uncompleted_ranges(&self, total_size: u64) -> Vec<ByteRange> {
        let mut ranges = Vec::new();
        let mut run_start: Option<usize> = None;

        for blk in 0..self.len {
            if !self.get(blk) {
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
            ranges.push(ByteRange {
                start,
                end: total_size,
            });
        }
        ranges
    }
}

#[binrw]
#[brw(little, magic = b"SAMLOADR")]
#[br(import(info: &BinaryInform))]
struct Footer {
    #[br(temp, assert(version == FOOTER_VERSION))]
    #[bw(calc = FOOTER_VERSION)]
    version: u32,

    #[br(assert(checksum == info_checksum(info)))]
    checksum: [u8; 16],

    #[br(temp, assert(block_size == BLOCK_SIZE as u32))]
    #[bw(calc = BLOCK_SIZE as u32)]
    block_size: u32,

    #[br(temp, assert(num_blocks == info.size.div_ceil(BLOCK_SIZE as u64) as u32))]
    #[bw(calc = blocks.len() as u32)]
    num_blocks: u32,

    #[br(assert(padding <= 16 && padding as u64 <= info.size))]
    padding: u8,

    #[br(args(num_blocks as usize))]
    blocks: BlockBits,
}

impl Footer {
    fn new(info: &BinaryInform) -> Self {
        let num_blocks = info.size.div_ceil(BLOCK_SIZE as u64) as usize;
        Self {
            checksum: info_checksum(info),
            padding: 0,
            blocks: BlockBits::new(num_blocks),
        }
    }

    fn effective_size(&self, raw_size: u64) -> u64 {
        let n = self.blocks.len();
        if n > 0 && self.blocks.get(n - 1) {
            raw_size.saturating_sub(self.padding as u64)
        } else {
            raw_size
        }
    }

    fn completed_bytes(&self, raw_size: u64) -> u64 {
        let end = self.effective_size(raw_size);
        let n = self.blocks.len();
        (0..n)
            .filter(|&blk| self.blocks.get(blk))
            .map(|blk| {
                if blk + 1 == n {
                    end.saturating_sub(blk as u64 * BLOCK_SIZE as u64)
                } else {
                    BLOCK_SIZE as u64
                }
            })
            .sum()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        self.write(&mut cursor)
            .expect("in-memory footer serialization cannot fail");
        cursor.into_inner()
    }

    fn write_to_slice(&self, dst: &mut [u8]) {
        let mut cursor = Cursor::new(dst);
        self.write(&mut cursor)
            .expect("footer slice length matches serialized size");
        debug_assert_eq!(cursor.position() as usize, cursor.get_ref().len());
    }

    fn read_from_part<R: Read + Seek>(reader: &mut R, info: &BinaryInform) -> Option<Self> {
        let file_len = reader.seek(SeekFrom::End(0)).ok()?;
        if file_len <= info.size {
            return None;
        }
        reader.seek(SeekFrom::Start(info.size)).ok()?;
        let footer = Self::read_args(reader, (info,)).ok()?;
        (reader.stream_position().ok()? == file_len).then_some(footer)
    }
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
    footer: &'a mut Footer,
    footer_map: &'a mut [u8],
}

impl StateTracker<'_> {
    fn on_bytes_decrypted(&mut self, start: u64, prev_dec: usize, new_dec: usize) {
        let prev_pos = start + prev_dec as u64;
        let curr_pos = start + new_dec as u64;
        let start_blk = (prev_pos / BLOCK_SIZE as u64) as usize;
        let end_blk = (curr_pos / BLOCK_SIZE as u64) as usize;
        let total_blocks = self.footer.blocks.len();

        // Non-final blocks all have exact length `BLOCK_SIZE`; the final block may be
        // shortened by PKCS#7 unpadding and is marked complete in `on_eof_reached`.
        let mut changed = false;
        for blk in start_blk..=end_blk {
            if blk + 1 >= total_blocks {
                break;
            }
            let blk_end = (blk + 1) as u64 * BLOCK_SIZE as u64;
            if curr_pos >= blk_end {
                changed |= self.footer.blocks.set(blk);
            }
        }
        if changed {
            self.footer.write_to_slice(self.footer_map);
        }
    }

    fn on_eof_reached(&mut self, padding: u8) {
        self.footer.padding = padding;
        let total_blocks = self.footer.blocks.len();
        if total_blocks > 0 {
            self.footer.blocks.set(total_blocks - 1);
        }
        self.footer.write_to_slice(self.footer_map);
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
    error: Option<io::Error>,
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
) -> io::Result<()> {
    let info = session.info();
    let threads = threads.max(1);
    let pb = progress.pb;

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

    // Check if a valid partial download already exists
    let had_existing_part = part_path.exists();
    let existing_footer = if had_existing_part && !force {
        OpenOptions::new()
            .read(true)
            .open(&part_path)
            .ok()
            .and_then(|mut f| Footer::read_from_part(&mut f, info))
    } else {
        None
    };

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(existing_footer.is_none())
        .open(&part_path)?;

    let mut footer = if let Some(footer) = existing_footer {
        let effective_total = footer.effective_size(info.size);
        let completed_bytes = footer.completed_bytes(info.size);
        pb.println(format!(
            "Resuming download: {:.2} GiB / {:.2} GiB ({:.1}%) already downloaded",
            completed_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            effective_total as f64 / (1024.0 * 1024.0 * 1024.0),
            if effective_total > 0 {
                (completed_bytes as f64 / effective_total as f64) * 100.0
            } else {
                100.0
            }
        ));
        pb.set_length(effective_total);
        pb.set_position(completed_bytes);
        pb.reset_eta();
        footer
    } else {
        if had_existing_part && !force {
            pb.println(
                "Existing partial download is incompatible or corrupted, restarting from scratch...",
            );
        }
        let footer = Footer::new(info);
        file.set_len(info.size)?;
        file.seek(SeekFrom::Start(info.size))?;
        file.write_all(&footer.to_bytes())?;
        file.sync_data()?;

        pb.set_length(info.size);
        footer
    };

    pb.enable_steady_tick(Duration::from_secs(1));

    let uncompleted = footer.blocks.uncompleted_ranges(info.size);
    let mut map = unsafe { MmapMut::map_mut(&file)? };
    let download_chunks = partition_ranges_for_threads(&uncompleted, threads);

    if !download_chunks.is_empty() {
        let (payload_map, footer_map) = map.split_at_mut(info.size as usize);
        let tracker = Mutex::new(StateTracker {
            footer: &mut footer,
            footer_map,
        });

        let mut queue = VecDeque::new();
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

    map.flush()?;
    drop(map);

    file.set_len(info.size.saturating_sub(footer.padding as u64))?;
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
    let mut last_progress = progress.pb.position();
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
                    progress.log_verbose(format_args!(
                        "Connection throttled at offset {stall_off}; \
                         reducing to {remaining} connection(s)"
                    ));
                    return;
                }

                pool.available.notify_all();
                drop(state);

                let pos = progress.pb.position();
                if pos > last_progress {
                    last_progress = pos;
                    dead_stalls = 0;
                } else {
                    dead_stalls += 1;
                    if dead_stalls > MAX_DEAD_STALLS {
                        let mut state = pool.inner.lock().unwrap();
                        state.error = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "download stalled at offset {stall_off}: server stopped responding"
                            ),
                        ));
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
                progress.log_verbose(format_args!(
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
                        if pad > 0
                            && let Some(len) = progress.pb.length()
                        {
                            progress.pb.set_length(len.saturating_sub(pad as u64));
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
                    progress.pb.inc(n as u64);

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
        progress.log_verbose(format_args!(
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

    fn read_part(payload_size: u64, footer_bytes: &[u8], info: &BinaryInform) -> Option<Footer> {
        let mut part = vec![0u8; payload_size as usize];
        part.extend_from_slice(footer_bytes);
        Footer::read_from_part(&mut Cursor::new(part), info)
    }

    #[test]
    fn test_footer_validation_failures() {
        let size = 5 * 1024 * 1024; // 3 blocks (2 + 2 + 1)
        let info = mock_info(size);
        let footer = Footer::new(&info);
        assert_eq!(footer.blocks.len(), 3);
        let buf = footer.to_bytes();

        assert!(read_part(size, &buf, &info).is_some());

        // Truncated and overlong footers must fail
        assert!(read_part(size, &buf[..buf.len() - 1], &info).is_none());
        let mut overlong = buf.clone();
        overlong.push(0);
        assert!(read_part(size, &overlong, &info).is_none());

        // Tamper with magic (0), version (8), checksum (12), block_size (28),
        // num_blocks (32), and padding (36 -> 0xFF > 16)
        for offset in [0, 8, 12, 28, 32, 36] {
            let mut tampered = buf.clone();
            tampered[offset] ^= 0xFF;
            assert!(
                read_part(size, &tampered, &info).is_none(),
                "offset={offset}"
            );
        }

        // Mismatched binary info: different size, or any mutated BinaryInform field
        assert!(read_part(size, &buf, &mock_info(2 * size)).is_none());
        let mutations: &[fn(&mut BinaryInform)] = &[
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
            assert!(read_part(size, &buf, &other_info).is_none());
        }
    }

    #[test]
    fn test_bitfield_and_range_extraction() {
        let total_size = 5 * BLOCK_SIZE as u64;
        let mut footer = Footer::new(&mock_info(total_size));
        footer.blocks.set(0);
        footer.blocks.set(2);

        assert_eq!(footer.completed_bytes(total_size), 2 * BLOCK_SIZE as u64);

        let uncompleted = footer.blocks.uncompleted_ranges(total_size);
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
        assert_eq!(partition_ranges_for_threads(&uncompleted, 4).len(), 3);

        // Final block (4) completed with 7 bytes of stripped PKCS#7 padding
        footer.padding = 7;
        footer.blocks.set(4);
        assert_eq!(
            footer.completed_bytes(total_size),
            3 * BLOCK_SIZE as u64 - 7
        );
    }

    #[test]
    fn test_state_tracker_interruption_and_resume() {
        let size = 10 * 1024 * 1024; // 5 blocks
        let info = mock_info(size);
        let mut footer = Footer::new(&info);
        let mut footer_bytes = footer.to_bytes();

        let validate = |bytes: &[u8]| {
            let parsed = read_part(size, bytes, &info)
                .expect("Footer must validate immediately after block completion");
            let uncompleted = parsed.blocks.uncompleted_ranges(size);
            (parsed.blocks.bytes, parsed.padding, uncompleted)
        };

        // First run: completes blocks 0 and 1, plus out-of-order final block 4 with 11-byte padding
        {
            let mut tracker = StateTracker {
                footer: &mut footer,
                footer_map: &mut footer_bytes,
            };
            tracker.on_bytes_decrypted(0, 0, 1024 * 1024);
            assert!(!tracker.footer.blocks.get(0));

            tracker.on_bytes_decrypted(0, 1024 * 1024, BLOCK_SIZE);
            assert!(tracker.footer.blocks.get(0));

            tracker.on_bytes_decrypted(BLOCK_SIZE as u64, 0, BLOCK_SIZE);
            assert!(tracker.footer.blocks.get(1));

            tracker.on_bytes_decrypted(4 * BLOCK_SIZE as u64, 0, BLOCK_SIZE - 11);
            assert!(!tracker.footer.blocks.get(4));
            tracker.on_eof_reached(11);
            assert!(tracker.footer.blocks.get(4));
        }

        assert_eq!(
            validate(&footer_bytes),
            (
                vec![0b10011],
                11,
                vec![ByteRange {
                    start: 2 * BLOCK_SIZE as u64,
                    end: 4 * BLOCK_SIZE as u64,
                }]
            )
        );

        // Second run: resumes from disk bytes and completes block 2; persisted padding (11) remains intact
        let mut resumed = read_part(size, &footer_bytes, &info).unwrap();
        StateTracker {
            footer: &mut resumed,
            footer_map: &mut footer_bytes,
        }
        .on_bytes_decrypted(2 * BLOCK_SIZE as u64, 0, BLOCK_SIZE);

        assert_eq!(
            validate(&footer_bytes),
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
