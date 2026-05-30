// Copyright 2026 Google LLC
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

use indicatif::{ProgressBar, ProgressStyle};
use memmap2::MmapMut;
use samloader_fus::FusClient;
use samloader_fus::aes::cipher::BlockModeDecrypt;
use samloader_fus::aes::cipher::inout::InOutBuf;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Read;
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::Duration;

const PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

pub(crate) struct DownloadArgs {
    /// The model name (e.g. SM-S931U1)
    pub(crate) model: String,

    /// Region CSC code (e.g. XAA)
    pub(crate) region: String,

    /// Optional: firmware version. If None, downloads the latest.
    pub(crate) version: Option<String>,

    /// Number of parallel connections
    pub(crate) threads: u64,

    /// Optional: the output directory
    pub(crate) out_dir: Option<String>,

    /// Optional: the output file name
    pub(crate) out_file: Option<String>,
}

pub(crate) fn download_latest_firmware(args: DownloadArgs) {
    let mut client = FusClient::new().expect("Unable to establish FusClient");

    match &args.version {
        Some(version) => {
            client.fetch_binary_info_for_version(&args.model, &args.region, version);
        }
        None => {
            client.fetch_binary_info(&args.model, &args.region);
        }
    }

    println!("Firmware Version: {}", client.info.version);

    let default_name = client
        .info
        .filename
        .strip_suffix(".enc4")
        .unwrap_or(client.info.filename.as_str());

    let final_out = match (args.out_file, args.out_dir) {
        (Some(name), _) => name,
        (None, Some(dir)) => format!("{}/{}", dir, default_name),
        _ => default_name.to_string(),
    };

    println!("Downloading {} to {}", client.info.filename, final_out);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&final_out)
        .unwrap();

    // Pre-allocate file
    file.set_len(client.info.size)
        .expect("Cannot pre-allocate file");

    let mut map = unsafe { MmapMut::map_mut(&file).expect("Cannot map file") };

    client.init_download();

    // Round up to the nearest 16 byte boundary
    let chunk_size = (client.info.size / args.threads / 16 + 1) * 16;

    let progress = ProgressBar::new(client.info.size)
        .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
    progress.enable_steady_tick(Duration::from_secs(1));

    // Seed the work pool with one byte range per requested connection. Workers
    // pull ranges from here; a worker throttled to a standstill hands its
    // unfinished tail back so a surviving worker can pick it up later.
    let mut queue = VecDeque::new();
    {
        let mut chunks = map.chunks_mut(chunk_size as usize).enumerate().peekable();
        while let Some((i, buf)) = chunks.next() {
            let is_last = chunks.peek().is_none();

            let start = i as u64 * chunk_size;
            // Ensure the last range covers the remainder of the file
            let end = if is_last {
                None
            } else {
                Some(start + chunk_size - 1)
            };

            queue.push_back(Chunk { buf, start, end });
        }
    }

    // Never spawn more connections than there are ranges to download.
    let n_workers = queue.len().min(args.threads as usize);
    let pool = Pool {
        inner: Mutex::new(PoolInner {
            queue,
            in_flight: 0,
            live: n_workers,
        }),
        available: Condvar::new(),
    };

    thread::scope(|s| {
        let pool = &pool;
        let client = &client;
        let progress = &progress;
        for _ in 0..n_workers {
            s.spawn(move || run_worker(pool, client, progress));

            // Stagger connection setup to avoid hammering the server
            thread::sleep(Duration::from_millis(100));
        }
    });

    // The pool still borrows `map` through its (now-drained) work queue; drop it
    // before reading back from the mapping.
    drop(pool);

    let last_byte = *map.last().unwrap();
    map.flush().ok();
    drop(map);

    // Handle padding removal if needed
    if last_byte > 0 && last_byte <= 16 {
        let file_len = file
            .metadata()
            .ok()
            .map(|m| m.len())
            .unwrap_or(client.info.size);
        file.set_len(file_len - last_byte as u64)
            .expect("Failed to truncate file");
    }

    progress.finish();
}

/// A contiguous, not-yet-downloaded byte range mapped onto its slice of the
/// output file. `buf` is exactly the destination for `[start, end]` (or
/// `[start, EOF]` when `end` is `None`).
struct Chunk<'a> {
    buf: &'a mut [u8],
    start: u64,
    end: Option<u64>,
}

/// Shared, work-stealing pool of outstanding ranges.
///
/// The FUS server happily accepts many connections at first, then throttles the
/// transfer mid-download — some connections slow to a crawl or stall entirely.
/// Rather than abort, a worker that can no longer make progress hands the rest
/// of its range back here and exits, shrinking the connection count to whatever
/// the server is actually willing to serve. The surviving workers drain the
/// returned ranges, so the download still finishes (just with fewer threads).
struct Pool<'a> {
    inner: Mutex<PoolInner<'a>>,
    available: Condvar,
}

struct PoolInner<'a> {
    /// Ranges waiting to be downloaded.
    queue: VecDeque<Chunk<'a>>,
    /// Ranges currently being downloaded by some worker. While this is non-zero
    /// more work may still be handed back, so an idle worker must wait rather
    /// than conclude the download is finished.
    in_flight: usize,
    /// Number of worker threads still running. A throttled worker only sheds
    /// itself while this is `> 1`, so at least one connection always remains to
    /// carry the download to completion.
    live: usize,
}

enum ChunkOutcome {
    /// The whole range was downloaded and decrypted.
    Done,
    /// The connection stalled. `decrypted` bytes (a multiple of 16) of the range
    /// are complete; everything after that still needs downloading.
    Stalled { decrypted: usize },
}

/// Consecutive *no-progress* attempts tolerated on a single connection before it
/// is treated as throttled. The counter resets the moment a read advances the
/// decrypted offset, so this bounds a stall (repeated retries that keep failing
/// at the same offset) rather than the total number of blips over a long
/// download. A genuinely slow-but-alive connection delivers *some* bytes within
/// each timeout window and so never trips this.
const MAX_STALL_RETRIES: u32 = 4;

/// When only one connection is left, how many stalls in a row — with no overall
/// progress in between — to tolerate before declaring the server dead and
/// aborting, instead of retrying forever.
const MAX_DEAD_STALLS: u32 = 4;

/// A single download connection.
///
/// Repeatedly pulls a range from the pool and downloads it. When the server
/// throttles this connection to a standstill (a retry that keeps failing at the
/// same offset, detected by [`download_chunk`]), the worker hands the unfinished
/// tail back to the pool and — as long as it is not the only connection left —
/// exits. This is the dynamic decrease in thread count: connections that the
/// server has effectively cut off stop competing, and the rest carry on.
fn run_worker(pool: &Pool<'_>, client: &FusClient, progress: &ProgressBar) {
    // For the final surviving connection only: how many times in a row the whole
    // download failed to advance. Lets us give up on a truly dead server instead
    // of spinning forever once we can no longer shed connections.
    let mut last_progress = 0_u64;
    let mut dead_stalls = 0_u32;

    loop {
        // Take the next range, or wait until a throttled peer hands one back.
        // When the queue is empty and nothing is in flight, every byte is in.
        let chunk = {
            let mut state = pool.inner.lock().unwrap();
            loop {
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

        let outcome = download_chunk(client, &mut chunk.buf[..], chunk.start, chunk.end, progress);

        match outcome {
            ChunkOutcome::Done => {
                dead_stalls = 0;
                let mut state = pool.inner.lock().unwrap();
                state.in_flight -= 1;
                // A completion can be the event that drains the pool; wake idle
                // peers so they can observe it and exit.
                pool.available.notify_all();
            }
            ChunkOutcome::Stalled { decrypted } => {
                // Split the range: keep the decrypted prefix (already in the
                // file) and hand the rest back. ECB is position-independent, so
                // whichever worker resumes this tail decrypts it correctly from a
                // fresh decryptor at the 16-byte boundary `decrypted`.
                let stall_off = chunk.start + decrypted as u64;
                let Chunk { buf, end, .. } = chunk;
                let (_done, rest) = buf.split_at_mut(decrypted);
                let remainder = Chunk {
                    buf: rest,
                    start: stall_off,
                    end,
                };

                let mut state = pool.inner.lock().unwrap();
                state.in_flight -= 1;
                state.queue.push_back(remainder);

                if state.live > 1 {
                    // Other connections are still alive (and presumably making
                    // progress); shed this throttled one and let them finish the
                    // returned range.
                    state.live -= 1;
                    let remaining = state.live;
                    pool.available.notify_all();
                    drop(state);
                    progress.println(format!(
                        "Connection throttled at offset {stall_off}; reducing to {remaining} connection(s)"
                    ));
                    return;
                }

                // We are the last connection — shedding it would strand the
                // download, so keep retrying. Bail out only if nothing at all
                // comes through across several stall cycles.
                pool.available.notify_all();
                drop(state);

                let pos = progress.position();
                if pos > last_progress {
                    last_progress = pos;
                    dead_stalls = 0;
                } else {
                    dead_stalls += 1;
                    if dead_stalls > MAX_DEAD_STALLS {
                        panic!("Download stalled at offset {stall_off}: server stopped responding");
                    }
                }
            }
        }
    }
}

/// Download the byte range `[start, end]` (or `[start, EOF]` when `end` is
/// `None`) into `chunk`, decrypting in place as bytes arrive.
///
/// On a network error the request is re-issued from the last decrypted 16-byte
/// boundary instead of restarting the chunk. This resume is correct because:
///   * the firmware is served via HTTP range requests over static content, and
///   * decryption is AES-ECB, which is position-independent — every 16-byte
///     block decrypts on its own, so resuming at any block boundary is exact.
///
/// The re-fetched overlap is therefore at most the <16-byte undecrypted tail.
///
/// Returns [`ChunkOutcome::Done`] once the whole range is in, or
/// [`ChunkOutcome::Stalled`] when the connection makes no forward progress for
/// [`MAX_STALL_RETRIES`] attempts in a row — i.e. retries keep failing at the
/// same offset. That is the signal the caller uses to detect throttling and shed
/// the connection; the returned `decrypted` count says how much is already done.
fn download_chunk(
    client: &FusClient,
    chunk: &mut [u8],
    start: u64,
    end: Option<u64>,
    progress: &ProgressBar,
) -> ChunkOutcome {
    // ECB keeps no state between blocks, so one decryptor is reused across every
    // (re)connection.
    let mut dec = client.get_decryptor();
    let mut dec_pos = 0_usize; // bytes decrypted so far (always a multiple of 16)
    let mut retries = 0_u32;

    loop {
        let mut resp = match client.download_file(Some(start + dec_pos as u64), end) {
            Ok(resp) => resp,
            Err(e) => {
                retries += 1;
                if retries > MAX_STALL_RETRIES {
                    return ChunkOutcome::Stalled { decrypted: dec_pos };
                }
                progress.println(format!(
                    "Request error ({e}); retry {retries}/{MAX_STALL_RETRIES} at offset {}",
                    start + dec_pos as u64
                ));
                thread::sleep(backoff(retries));
                continue;
            }
        };

        // We re-requested from `dec_pos`; discard the undecrypted tail and resume
        // writing there. Progress only counts decrypted bytes, so the re-fetched
        // overlap is never double-counted and there is nothing to roll back.
        let resume_from = dec_pos;
        let mut dl_pos = dec_pos; // bytes received into `chunk` this connection

        let stall = loop {
            match resp.read(&mut chunk[dl_pos..]) {
                Ok(0) => return ChunkOutcome::Done, // chunk fully received and decrypted
                Ok(n) => dl_pos += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => break e, // connection dropped: resume the outer loop
            }

            let prev_dec = dec_pos;
            let (blocks, tail) = InOutBuf::from(&mut chunk[dec_pos..dl_pos]).into_chunks();
            dec.decrypt_blocks_inout(blocks);
            dec_pos = dl_pos - tail.len();
            progress.inc((dec_pos - prev_dec) as u64);
        };

        // Every byte is decrypted: the chunk is complete even though the
        // connection broke before the server signaled EOF (`Ok(0)`). Return now
        // — re-requesting from `start + len` would ask for a zero-length,
        // backwards range. This also keeps `Stalled.decrypted` strictly below the
        // chunk length, so the handoff never produces an empty range.
        if dec_pos == chunk.len() {
            return ChunkOutcome::Done;
        }

        // Reset the budget only on real decryption progress (a whole new block),
        // not on raw bytes read. This keeps isolated blips from exhausting the
        // retries while guaranteeing that a chunk which never advances still
        // terminates — `dec_pos` can only climb so many times.
        if dec_pos > resume_from {
            retries = 0;
        }
        retries += 1;
        if retries > MAX_STALL_RETRIES {
            return ChunkOutcome::Stalled { decrypted: dec_pos };
        }
        progress.println(format!(
            "Download error ({stall}); retry {retries}/{MAX_STALL_RETRIES}, resuming at offset {}",
            start + dec_pos as u64
        ));
        thread::sleep(backoff(retries));
    }
}

/// Exponential backoff capped at 30s: 1s, 2s, 4s, 8s, 16s, 30s, ...
fn backoff(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << (attempt - 1).min(5)).min(30))
}
