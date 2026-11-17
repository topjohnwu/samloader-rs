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
use samloader_fus::{
    BinaryInform, DownloadSession, FusClient, fetch_history, futures::io::AsyncReadExt,
};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, oneshot};
use tokio::task::{JoinHandle, JoinSet};

const PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

/// The chunk size of each independently tracked download block (2 MiB).
/// 2 MiB = 2,097,152 bytes = 131,072 AES-128 blocks (aligned to 16 bytes).
const BLOCK_SIZE: usize = 2 * 1024 * 1024;

/// Version of the `.part` footer layout format.
const FOOTER_VERSION: u32 = 3;

const MAX_STALL_RETRIES: u32 = 4;
const MAX_DEAD_STALLS: u32 = 4;

#[derive(Clone)]
struct Reporter {
    pb: ProgressBar,
    verbose: bool,
}

impl Reporter {
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

#[cfg_attr(test, derive(Debug, PartialEq))]
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

fn write_at(file: &File, buf: &[u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_write(file, buf, offset)
    }
}

fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match write_at(file, buf, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            Ok(n) => {
                buf = &buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn set_sparse(file: &File, sparse: bool) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{FILE_SET_SPARSE_BUFFER, FSCTL_SET_SPARSE};

    let buf = FILE_SET_SPARSE_BUFFER { SetSparse: sparse };
    let mut returned = 0_u32;
    // Best-effort: avoids NTFS synchronously zero-filling up to `info.size` on
    // initial footer creation and out-of-order worker writes; ignored on
    // filesystems that do not support sparse files (e.g. exFAT).
    //
    // SAFETY: `file` owns a valid open `HANDLE` for the duration of the call,
    // and `buf` / `returned` outlive the synchronous `DeviceIoControl` call.
    unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            (&raw const buf).cast(),
            size_of::<FILE_SET_SPARSE_BUFFER>() as u32,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        );
    }
}

struct StateTracker {
    footer: Footer,
    footer_buf: Vec<u8>,
}

impl StateTracker {
    fn new(footer: Footer) -> Self {
        let footer_buf = footer.to_bytes();
        Self { footer, footer_buf }
    }

    fn serialize(&mut self) -> &[u8] {
        self.footer.write_to_slice(&mut self.footer_buf);
        &self.footer_buf
    }

    fn on_bytes_written(&mut self, offset: u64, len: usize) -> Option<&[u8]> {
        let prev_pos = offset;
        let curr_pos = offset + len as u64;
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
        changed.then(|| self.serialize())
    }

    fn on_eof_reached(&mut self, padding: u8) -> &[u8] {
        self.footer.padding = padding;
        let total_blocks = self.footer.blocks.len();
        if total_blocks > 0 {
            self.footer.blocks.set(total_blocks - 1);
        }
        self.serialize()
    }
}

struct WriteJob {
    offset: u64,
    len: usize,
    eof_pad: Option<u8>,
    data: Vec<u8>,
    done: oneshot::Sender<io::Result<Vec<u8>>>,
}

fn write_job(
    file: &File,
    footer_offset: u64,
    tracker: &mut StateTracker,
    job: &WriteJob,
) -> io::Result<()> {
    if job.len > 0 {
        write_all_at(file, &job.data[..job.len], job.offset)?;
    }
    let footer_bytes = match job.eof_pad {
        Some(pad) => Some(tracker.on_eof_reached(pad)),
        None if job.len > 0 => tracker.on_bytes_written(job.offset, job.len),
        None => None,
    };
    if let Some(bytes) = footer_bytes {
        write_all_at(file, bytes, footer_offset)?;
    }
    Ok(())
}

/// Spawns the dedicated disk-writer thread owning `file` and `StateTracker`.
fn spawn_disk_writer(
    file: File,
    footer: Footer,
    footer_offset: u64,
) -> (mpsc::Sender<WriteJob>, JoinHandle<(File, u8)>) {
    let (tx, rx) = mpsc::channel::<WriteJob>();
    let handle = tokio::task::spawn_blocking(move || {
        let mut tracker = StateTracker::new(footer);
        for mut job in rx {
            let res = write_job(&file, footer_offset, &mut tracker, &job)
                .map(|()| std::mem::take(&mut job.data));
            let _ = job.done.send(res);
        }
        (file, tracker.footer.padding)
    });
    (tx, handle)
}

/// Per-worker double-buffered block writer that overlaps async network reads
/// into `buf` while the disk-writer thread flushes the previous block.
struct BlockWriter {
    tx: mpsc::Sender<WriteJob>,
    buf: Vec<u8>,
    spare: Vec<u8>,
    pending: Option<oneshot::Receiver<io::Result<Vec<u8>>>>,
}

impl BlockWriter {
    fn new(tx: mpsc::Sender<WriteJob>) -> Self {
        Self {
            tx,
            buf: vec![0; BLOCK_SIZE],
            spare: vec![0; BLOCK_SIZE],
            pending: None,
        }
    }

    async fn wait_pending(&mut self) -> io::Result<()> {
        if let Some(rx) = self.pending.take() {
            self.spare = rx.await.expect("disk writer thread panicked")?;
        }
        Ok(())
    }

    async fn submit(&mut self, offset: u64, len: usize, eof_pad: Option<u8>) -> io::Result<()> {
        self.wait_pending().await?;
        if len == 0 && eof_pad.is_none() {
            return Ok(());
        }
        std::mem::swap(&mut self.buf, &mut self.spare);
        let data = std::mem::take(&mut self.spare);
        let (done, rx) = oneshot::channel();
        self.tx
            .send(WriteJob {
                offset,
                len,
                eof_pad,
                data,
                done,
            })
            .expect("disk writer thread panicked");
        self.pending = Some(rx);
        Ok(())
    }

    async fn submit_and_wait(
        &mut self,
        offset: u64,
        len: usize,
        eof_pad: Option<u8>,
    ) -> io::Result<()> {
        self.submit(offset, len, eof_pad).await?;
        self.wait_pending().await
    }
}

struct Pool {
    inner: Mutex<PoolInner>,
    available: Notify,
}

struct PoolInner {
    queue: VecDeque<ByteRange>,
    in_flight: usize,
    live: usize,
    error: Option<io::Error>,
}

enum ChunkOutcome {
    Done,
    Stalled { resume_at: u64 },
}

enum PartState {
    Fresh,
    Resumed,
    Restarted,
}

fn prepare_part_file(
    final_path: &Path,
    part_path: &Path,
    info: &BinaryInform,
    force: bool,
) -> io::Result<(File, Footer, PartState)> {
    if let Some(parent) = final_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }

    if force {
        let _ = std::fs::remove_file(final_path);
        let _ = std::fs::remove_file(part_path);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(force)
        .open(part_path)?;

    let existing_len = file.seek(SeekFrom::End(0))?;
    if !force
        && existing_len > 0
        && let Some(footer) = Footer::read_from_part(&mut file, info)
    {
        #[cfg(windows)]
        set_sparse(&file, true);
        return Ok((file, footer, PartState::Resumed));
    }

    let state = if !force && existing_len > 0 {
        file.set_len(0)?;
        PartState::Restarted
    } else {
        PartState::Fresh
    };

    #[cfg(windows)]
    set_sparse(&file, true);

    let footer = Footer::new(info);
    write_all_at(&file, &footer.to_bytes(), info.size)?;
    file.sync_data()?;

    Ok((file, footer, state))
}

fn finalize_part_file(
    file: File,
    part_path: &Path,
    final_path: &Path,
    final_size: u64,
) -> io::Result<()> {
    file.set_len(final_size)?;
    #[cfg(windows)]
    set_sparse(&file, false);
    file.sync_data()?;
    drop(file);

    if final_path.exists() {
        let _ = std::fs::remove_file(final_path);
    }
    std::fs::rename(part_path, final_path)
}

async fn download_firmware(
    session: &Arc<DownloadSession>,
    final_path: &Path,
    threads: u64,
    force: bool,
    reporter: &Reporter,
) -> io::Result<()> {
    let info = session.info();
    let threads = threads.max(1);
    let pb = &reporter.pb;

    let part_path = {
        let mut s = final_path.as_os_str().to_owned();
        s.push(".part");
        PathBuf::from(s)
    };

    let (file, footer, part_state) = {
        let final_path = final_path.to_path_buf();
        let part_path = part_path.clone();
        let session = Arc::clone(session);
        tokio::task::spawn_blocking(move || {
            prepare_part_file(&final_path, &part_path, session.info(), force)
        })
        .await
        .expect("part setup task panicked")?
    };

    match part_state {
        PartState::Resumed => {
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
        }
        PartState::Restarted => {
            pb.println(
                "Existing partial download is incompatible or corrupted, restarting from scratch...",
            );
            pb.set_length(info.size);
        }
        PartState::Fresh => {
            pb.set_length(info.size);
        }
    }

    pb.enable_steady_tick(Duration::from_secs(1));

    let uncompleted = footer.blocks.uncompleted_ranges(info.size);
    let download_chunks = partition_ranges_for_threads(&uncompleted, threads);

    let (file, padding) = if !download_chunks.is_empty() {
        let (job_tx, writer_task) = spawn_disk_writer(file, footer, info.size);

        let queue = VecDeque::from(download_chunks);
        let n_workers = queue.len().min(threads.min(usize::MAX as u64) as usize);
        let pool = Arc::new(Pool {
            inner: Mutex::new(PoolInner {
                queue,
                in_flight: 0,
                live: 0,
                error: None,
            }),
            available: Notify::new(),
        });

        let mut workers = JoinSet::new();
        for i in 0..n_workers {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            {
                let mut state = pool.inner.lock().unwrap();
                if state.error.is_some() || state.queue.is_empty() {
                    break;
                }
                state.live += 1;
            }
            let (pool_ref, session, tx, reporter) = (
                Arc::clone(&pool),
                Arc::clone(session),
                job_tx.clone(),
                reporter.clone(),
            );
            workers.spawn(async move {
                run_worker(&pool_ref, &session, BlockWriter::new(tx), &reporter).await;
            });
        }
        drop(job_tx);

        while let Some(res) = workers.join_next().await {
            res.expect("download worker task panicked");
        }

        let pool_error = pool.inner.lock().unwrap().error.take();
        drop(pool);

        let (file, padding) = writer_task.await.expect("disk writer thread panicked");
        if let Some(err) = pool_error {
            return Err(err);
        }
        (file, padding)
    } else {
        let padding = footer.padding;
        (file, padding)
    };

    let final_size = info.size.saturating_sub(padding as u64);
    let final_path = final_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        finalize_part_file(file, &part_path, &final_path, final_size)
    })
    .await
    .expect("part finalization task panicked")
}

async fn run_worker(
    pool: &Pool,
    session: &DownloadSession,
    mut bw: BlockWriter,
    reporter: &Reporter,
) {
    let info_size = session.info().size;
    let mut last_progress = reporter.pb.position();
    let mut dead_stalls = 0_u32;

    loop {
        let range = loop {
            let notified = pool.available.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            {
                let mut state = pool.inner.lock().unwrap();
                if state.error.is_some() {
                    state.live -= 1;
                    drop(state);
                    pool.available.notify_waiters();
                    return;
                }
                if let Some(range) = state.queue.pop_front() {
                    state.in_flight += 1;
                    break range;
                }
                if state.in_flight == 0 {
                    state.live -= 1;
                    drop(state);
                    pool.available.notify_waiters();
                    return;
                }
            }

            notified.await;
        };

        let end = range.end;
        let outcome = download_chunk(session, range, info_size, &mut bw, reporter).await;

        match outcome {
            Ok(ChunkOutcome::Done) => {
                dead_stalls = 0;
                let mut state = pool.inner.lock().unwrap();
                state.in_flight -= 1;
                drop(state);
                pool.available.notify_waiters();
            }
            Ok(ChunkOutcome::Stalled { resume_at }) => {
                let remainder = ByteRange {
                    start: resume_at,
                    end,
                };

                let mut state = pool.inner.lock().unwrap();

                if state.error.is_some() {
                    state.in_flight -= 1;
                    state.live -= 1;
                    drop(state);
                    pool.available.notify_waiters();
                    return;
                }

                state.in_flight -= 1;
                state.queue.push_back(remainder);

                if state.live > 1 {
                    state.live -= 1;
                    let remaining = state.live;
                    drop(state);
                    pool.available.notify_waiters();
                    reporter.log_verbose(format_args!(
                        "Connection throttled at offset {resume_at}; \
                         reducing to {remaining} connection(s)"
                    ));
                    return;
                }

                drop(state);
                pool.available.notify_waiters();

                let pos = reporter.pb.position();
                if pos > last_progress {
                    last_progress = pos;
                    dead_stalls = 0;
                } else {
                    dead_stalls += 1;
                    if dead_stalls > MAX_DEAD_STALLS {
                        let mut state = pool.inner.lock().unwrap();
                        if state.error.is_none() {
                            state.error = Some(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!(
                                    "download stalled at offset {resume_at}: server stopped responding"
                                ),
                            ));
                        }
                        state.live -= 1;
                        drop(state);
                        pool.available.notify_waiters();
                        return;
                    }
                }
            }
            Err(err) => {
                let mut state = pool.inner.lock().unwrap();
                if state.error.is_none() {
                    state.error = Some(err);
                }
                state.in_flight -= 1;
                state.live -= 1;
                drop(state);
                pool.available.notify_waiters();
                return;
            }
        }
    }
}

async fn download_chunk(
    session: &DownloadSession,
    range: ByteRange,
    info_size: u64,
    bw: &mut BlockWriter,
    reporter: &Reporter,
) -> io::Result<ChunkOutcome> {
    let http_end = (range.end < info_size).then_some(range.end - 1);
    let mut buf_offset = range.start;
    let mut buf_len = 0_usize;
    let mut retries = 0_u32;

    loop {
        let fetch_pos = buf_offset + buf_len as u64;
        let mut reader = match session.fetch_range(Some(fetch_pos), http_end).await {
            Ok(reader) => reader,
            Err(e) => {
                retries += 1;
                if retries > MAX_STALL_RETRIES {
                    bw.submit_and_wait(buf_offset, buf_len, None).await?;
                    return Ok(ChunkOutcome::Stalled {
                        resume_at: fetch_pos,
                    });
                }
                reporter.log_verbose(format_args!(
                    "Request error ({e}); retry {retries}/{MAX_STALL_RETRIES} at offset {fetch_pos}"
                ));
                tokio::time::sleep(backoff(retries)).await;
                continue;
            }
        };

        let resume_from = fetch_pos;

        let stall = loop {
            let rem_in_block = BLOCK_SIZE - (buf_offset % BLOCK_SIZE as u64) as usize;
            let target_len = (range.end - buf_offset).min(rem_in_block as u64) as usize;

            match reader.read(&mut bw.buf[buf_len..target_len]).await {
                Ok(0) => {
                    let rem_in_range = range.end - (buf_offset + buf_len as u64);
                    if http_end.is_none() && rem_in_range <= 16 {
                        let pad = rem_in_range as u8;
                        bw.submit_and_wait(buf_offset, buf_len, Some(pad)).await?;
                        if pad > 0
                            && let Some(len) = reporter.pb.length()
                        {
                            reporter.pb.set_length(len.saturating_sub(pad as u64));
                        }
                        return Ok(ChunkOutcome::Done);
                    }
                    break io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "premature EOF while reading chunk",
                    );
                }
                Ok(n) => {
                    buf_len += n;
                    reporter.pb.inc(n as u64);

                    if buf_len == target_len {
                        let next_offset = buf_offset + buf_len as u64;
                        if next_offset == range.end {
                            let eof_pad = http_end.is_none().then_some(0);
                            bw.submit_and_wait(buf_offset, buf_len, eof_pad).await?;
                            return Ok(ChunkOutcome::Done);
                        }
                        bw.submit(buf_offset, buf_len, None).await?;
                        buf_offset = next_offset;
                        buf_len = 0;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => break e,
            }
        };

        let curr_pos = buf_offset + buf_len as u64;
        if curr_pos > resume_from {
            retries = 0;
        }
        retries += 1;
        if retries > MAX_STALL_RETRIES {
            bw.submit_and_wait(buf_offset, buf_len, None).await?;
            return Ok(ChunkOutcome::Stalled {
                resume_at: curr_pos,
            });
        }
        reporter.log_verbose(format_args!(
            "Download error ({stall}); retry {retries}/{MAX_STALL_RETRIES}, \
             resuming at offset {curr_pos}"
        ));
        tokio::time::sleep(backoff(retries)).await;
    }
}

fn backoff(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << (attempt - 1).min(5)).min(30))
}

/// Downloads and decrypts a firmware from Samsung's update servers.
pub(crate) async fn run(args: DownloadArgs, verbose: bool) -> Result<(), Box<dyn Error>> {
    let version = match &args.version {
        Some(v) => v.clone(),
        None => {
            let version_info = fetch_history(&args.fus.model, &args.fus.region)
                .await
                .map_err(|e| format!("Failed to fetch version info: {e}"))?;
            version_info.latest
        }
    };

    let client = FusClient::new()
        .await
        .map_err(|e| format!("Unable to establish FusClient: {e}"))?;
    let info = client
        .fetch_binary_info(&args.fus.model, &args.fus.region, &version)
        .await
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

    let session = Arc::new(
        client
            .init_download(info)
            .await
            .map_err(|e| format!("Failed to initialize download: {e}"))?,
    );

    let reporter = Reporter {
        pb: ProgressBar::no_length()
            .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap()),
        verbose,
    };

    if let Err(e) =
        download_firmware(&session, &final_path, args.threads, args.force, &reporter).await
    {
        reporter.pb.abandon();
        // Keep the error apart from the abandoned progress bar
        eprintln!();
        return Err(format!("Download failed: {e}").into());
    }

    reporter.pb.finish();
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
        let footer = Footer::new(&info);

        let validate = |bytes: &[u8]| {
            let parsed = read_part(size, bytes, &info)
                .expect("Footer must validate immediately after block completion");
            let uncompleted = parsed.blocks.uncompleted_ranges(size);
            (parsed.blocks.bytes, parsed.padding, uncompleted)
        };

        // First run: completes blocks 0 and 1, plus out-of-order final block 4 with 11-byte padding
        let mut tracker = StateTracker::new(footer);
        assert!(tracker.on_bytes_written(0, 1024 * 1024).is_none());
        assert!(
            tracker
                .on_bytes_written(1024 * 1024, BLOCK_SIZE - 1024 * 1024)
                .is_some()
        );
        assert!(
            tracker
                .on_bytes_written(BLOCK_SIZE as u64, BLOCK_SIZE)
                .is_some()
        );
        assert!(
            tracker
                .on_bytes_written(4 * BLOCK_SIZE as u64, BLOCK_SIZE - 11)
                .is_none()
        );
        let footer_bytes = tracker.on_eof_reached(11).to_vec();

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
        let resumed = read_part(size, &footer_bytes, &info).unwrap();
        let mut tracker = StateTracker::new(resumed);
        let footer_bytes = tracker
            .on_bytes_written(2 * BLOCK_SIZE as u64, BLOCK_SIZE)
            .unwrap();

        assert_eq!(
            validate(footer_bytes),
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
