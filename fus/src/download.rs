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

//! Multi-threaded firmware download mechanism.

use crate::FusClient;
use crate::error::Result;
use aes::cipher::BlockModeDecrypt;
use aes::cipher::inout::InOutBuf;
use memmap2::MmapMut;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::Duration;

/// A trait for reporting firmware download progress and logging messages.
pub trait DownloadProgress: Send + Sync {
    /// Sets the total length of the progress.
    fn set_length(&self, len: u64);

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
    fn inc(&self, _bytes: u64) {}
    fn position(&self) -> u64 {
        0
    }
    fn println(&self, _msg: &str) {}
    fn println_verbose(&self, _msg: &str) {}
}

/// Downloads the firmware binary in parallel across multiple threads, decrypting it in place,
/// and writing to the file at `path`.
pub fn download_firmware<P, PathRef>(
    client: &FusClient,
    path: PathRef,
    threads: u64,
    progress: &P,
) -> Result<()>
where
    P: DownloadProgress,
    PathRef: AsRef<Path>,
{
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;

    // Pre-allocate file
    file.set_len(client.info.size)?;

    let mut map = unsafe { MmapMut::map_mut(&file)? };

    client.init_download()?;

    progress.set_length(client.info.size);

    // Round up to the nearest 16 byte boundary
    let chunk_size = (client.info.size / threads / 16 + 1) * 16;

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
        for _ in 0..n_workers {
            s.spawn(move || run_worker(pool, client, progress));

            // Stagger connection setup to avoid hammering the server
            thread::sleep(Duration::from_millis(100));
        }
    });

    // The pool still borrows `map` through its (now-drained) work queue; drop it
    // before reading back from the mapping.
    drop(pool);

    let last_byte = map.last().copied().unwrap_or(0);
    map.flush()?;
    drop(map);

    // Handle padding removal if needed
    if last_byte > 0 && last_byte <= 16 {
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(client.info.size);
        file.set_len(file_len - last_byte as u64)?;
    }

    Ok(())
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
    /// Holds the first fatal error occurred
    error: Option<crate::Error>,
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
fn run_worker(pool: &Pool<'_>, client: &FusClient, progress: &impl DownloadProgress) {
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
                // If another thread set a fatal error, exit cooperatively.
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

                // If another thread already aborted with error, just exit!
                if state.error.is_some() {
                    state.in_flight -= 1;
                    state.live -= 1;
                    pool.available.notify_all();
                    return;
                }

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
                    progress.println_verbose(&format!(
                        "Connection throttled at offset {stall_off}; \
                         reducing to {remaining} connection(s)"
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

/// Download the byte range `[start, end]` (or `[start, EOF]` when `end` is
/// `None`) into `chunk`, decrypting in place as bytes arrive.
fn download_chunk(
    client: &FusClient,
    chunk: &mut [u8],
    start: u64,
    end: Option<u64>,
    progress: &impl DownloadProgress,
) -> ChunkOutcome {
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
                progress.println_verbose(&format!(
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
                Ok(0) => {
                    break std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "download ended before the requested chunk was complete",
                    );
                }
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
        if dec_pos == chunk.len() {
            return ChunkOutcome::Done;
        }

        // Reset the budget only on real decryption progress (a whole new block),
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

/// Exponential backoff capped at 30s: 1s, 2s, 4s, 8s, 16s, 30s, ...
fn backoff(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << (attempt - 1).min(5)).min(30))
}
