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

//! Parallel byte-range decorator layered over any [`DataSource`].

#![cfg_attr(target_arch = "wasm32", allow(clippy::arc_with_non_send_sync))]

use crate::compat::{MaybeSend, MaybeSync, WorkerSet, sleep};
use crate::data::{DataSource, resolve_range_bounds};
use crate::error::HttpError;
use futures::future::poll_fn;
use futures::io::{AsyncRead, AsyncReadExt};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::ops::RangeBounds;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

#[cfg(not(test))]
const BLOCK_SIZE: usize = 2 * 1024 * 1024;
#[cfg(test)]
const BLOCK_SIZE: usize = 64 * 1024;

const TARGET_TASK_BLOCKS: u64 = 12; // 12 x 2 MiB = 24 MiB per sub-range fetch

#[cfg(not(target_arch = "wasm32"))]
const MAX_WINDOW_BLOCKS: u64 = 512; // 1 GiB max sliding window on native
#[cfg(target_arch = "wasm32")]
const MAX_WINDOW_BLOCKS: u64 = 144; // 288 MiB max sliding window on 32-bit WASM

const MAX_STALL_RETRIES: u32 = 4;
const MAX_DEAD_STALLS: u32 = 4;

fn stagger_delay(worker_idx: usize) -> Duration {
    #[cfg(not(test))]
    {
        Duration::from_millis(100 * worker_idx as u64)
    }
    #[cfg(test)]
    {
        let _ = worker_idx;
        Duration::ZERO
    }
}

fn retry_backoff(attempt: u32) -> Duration {
    #[cfg(not(test))]
    {
        Duration::from_secs((1u64 << (attempt - 1).min(5)).min(30))
    }
    #[cfg(test)]
    {
        let _ = attempt;
        Duration::ZERO
    }
}

fn is_retryable_error(err: &io::Error) -> bool {
    if let Some(HttpError::Status(status)) = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<HttpError>())
    {
        return matches!(*status, 401 | 408 | 429 | 500..=599);
    }

    !matches!(
        err.kind(),
        io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::Unsupported
            | io::ErrorKind::NotFound
    )
}

/// Diagnostic events emitted by [`ParallelDataSource`] during retries or throttling.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferWarning {
    /// Transient stream error that will be retried with backoff.
    Retry {
        /// Byte offset within the source where retry resumes.
        offset: u64,
        /// 1-based retry attempt number.
        attempt: u32,
        /// Maximum retry attempts per worker before re-queuing.
        max_attempts: u32,
        /// Error description.
        error: String,
    },
    /// Worker exited after repeated stalls to reduce connection concurrency.
    Throttled {
        /// Byte offset where throttling occurred.
        offset: u64,
        /// Remaining active worker connections.
        remaining_connections: usize,
    },
}

/// Progress and diagnostic observer for [`ParallelDataSource`].
pub trait TransferObserver: MaybeSend + MaybeSync {
    /// Called when `wire_bytes` have been read from the underlying source.
    ///
    /// `net_bytes` (`<= wire_bytes`) is the monotonic forward progress toward the
    /// stream's length after absorbing bytes previously discarded by retries or
    /// speculative hedging.
    fn on_bytes(&self, _wire_bytes: u64, _net_bytes: u64) {}

    /// Called on retry or throttling diagnostics.
    fn on_warning(&self, _warning: TransferWarning) {}
}

impl TransferObserver for () {}

impl<O: TransferObserver + ?Sized> TransferObserver for Arc<O> {
    fn on_bytes(&self, wire_bytes: u64, net_bytes: u64) {
        (**self).on_bytes(wire_bytes, net_bytes);
    }

    fn on_warning(&self, warning: TransferWarning) {
        (**self).on_warning(warning);
    }
}

/// Parallel sliding-window wrapper around any [`DataSource`].
pub struct ParallelDataSource<S: DataSource> {
    inner: Arc<S>,
    concurrency: usize,
    observer: Arc<dyn TransferObserver>,
}

impl<S: DataSource> Clone for ParallelDataSource<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            concurrency: self.concurrency,
            observer: Arc::clone(&self.observer),
        }
    }
}

impl<S: DataSource> ParallelDataSource<S> {
    /// Wraps `source` with `concurrency` parallel workers (clamped `>= 1`).
    pub fn new(source: S, concurrency: usize) -> Self {
        Self {
            inner: Arc::new(source),
            concurrency: concurrency.max(1),
            observer: Arc::new(()),
        }
    }

    /// Configures this source to report progress and warnings to `observer`.
    pub fn with_observer<O: TransferObserver + 'static>(mut self, observer: Arc<O>) -> Self {
        self.observer = observer;
        self
    }
}

impl<S: DataSource + 'static> ParallelDataSource<S> {
    fn start_reader(&self, range: impl RangeBounds<u64>) -> ParallelReader {
        let empty_reader = || ParallelReader {
            workers: WorkerSet::empty(),
            core: None,
            current: None,
        };
        let Some(clamped) = resolve_range_bounds(range, self.inner.size()) else {
            return empty_reader();
        };
        let start = clamped.start;
        let effective_end = clamped.end;

        let rem = effective_end - start;
        let total_blks = rem.div_ceil(BLOCK_SIZE as u64);
        let n_workers = self
            .concurrency
            .min(total_blks.min(usize::MAX as u64) as usize);

        // 1.5x wave window (`1.5 * n_workers * TARGET_TASK_BLOCKS`) provides 0.5x
        // wave slack so normal per-connection jitter never stalls or triggers premature
        // socket-closing steals, while keeping -j 8 at 288 MiB (216 MiB at WASM K=6).
        let window_blocks = ((n_workers as u64)
            .saturating_mul(TARGET_TASK_BLOCKS)
            .saturating_mul(3)
            / 2)
        .clamp(24, MAX_WINDOW_BLOCKS);
        let max_pooled_bufs = usize::try_from(window_blocks)
            .unwrap_or(usize::MAX)
            .saturating_add(1);

        let core = Arc::new(SharedCore {
            base_offset: start,
            effective_end,
            observer: Arc::clone(&self.observer),
            window_blocks,
            max_pooled_bufs,
            delivered_blk: AtomicU64::new(0),
            rewind_debt: AtomicU64::new(0),
            state: Mutex::new(State {
                scheduler: Scheduler::new(total_blks, n_workers),
                reorder: ReorderQueue::new(),
                live: n_workers,
                worker_wakers: vec![None; n_workers],
                reader_waker: None,
                aborted: false,
                error: None,
            }),
        });

        let mut workers = WorkerSet::new(n_workers);
        for worker_id in 0..n_workers {
            workers.spawn(run_worker(
                Arc::clone(&self.inner),
                Arc::clone(&core),
                worker_id,
            ));
        }

        ParallelReader {
            workers,
            core: Some(core),
            current: None,
        }
    }

    async fn read_at_single_range(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let total = buf.len();
        let end = offset + total as u64;
        let mut filled = 0usize;
        let mut retries = 0u32;

        loop {
            let resume_from = filled;
            let err = match self.inner.fetch_range(offset + filled as u64..end).await {
                Ok(mut reader) => loop {
                    if filled == total {
                        return Ok(filled);
                    }
                    match reader.read(&mut buf[filled..]).await {
                        Ok(0) => {
                            break io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "premature EOF while reading range",
                            );
                        }
                        Ok(n) => filled += n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => break e,
                    }
                },
                Err(e) => e,
            };

            if !is_retryable_error(&err) {
                return Err(err);
            }
            if filled > resume_from {
                retries = 0;
            }
            retries += 1;
            if retries > MAX_STALL_RETRIES {
                return Err(err);
            }
            self.observer.on_warning(TransferWarning::Retry {
                offset: offset + filled as u64,
                attempt: retries,
                max_attempts: MAX_STALL_RETRIES,
                error: err.to_string(),
            });
            sleep(retry_backoff(retries)).await;
        }
    }
}

impl<S: DataSource + 'static> DataSource for ParallelDataSource<S> {
    fn size(&self) -> u64 {
        self.inner.size()
    }

    async fn fetch_range(
        &self,
        range: impl RangeBounds<u64> + MaybeSend,
    ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
        Ok(self.start_reader(range))
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let size = self.inner.size();
        if buf.is_empty() || offset >= size {
            return Ok(0);
        }
        let target_len = (size - offset).min(buf.len() as u64) as usize;
        if target_len <= BLOCK_SIZE {
            return self
                .read_at_single_range(&mut buf[..target_len], offset)
                .await;
        }
        let mut reader = self.start_reader(offset..offset + target_len as u64);
        let mut filled = 0;
        while filled < target_len {
            match reader.read(&mut buf[filled..target_len]).await {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(filled)
    }
}

struct CurrentBlock {
    buf: Vec<u8>,
    pos: usize,
    len: usize,
}

/// Ordered [`AsyncRead`] stream backed by a bounded parallel sliding-window worker pool.
struct ParallelReader {
    workers: WorkerSet,
    core: Option<Arc<SharedCore>>,
    current: Option<CurrentBlock>,
}

impl Drop for ParallelReader {
    fn drop(&mut self) {
        if let Some(core) = self.core.take() {
            let mut state = core.state.lock().unwrap();
            state.aborted = true;
            state.reader_waker = None;
            state.wake_all_workers();
        }
        self.workers.abort_all();
    }
}

impl AsyncRead for ParallelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some(cur) = self.current.as_mut() {
            let n = (cur.len - cur.pos).min(buf.len());
            buf[..n].copy_from_slice(&cur.buf[cur.pos..cur.pos + n]);
            cur.pos += n;
            if cur.pos == cur.len {
                let cur = self.current.take().unwrap();
                let core = self.core.as_ref().expect("active current block has core");
                core.recycle_block(cur.buf);
            }
            return Poll::Ready(Ok(n));
        }

        let Some(core) = self.core.as_ref().map(Arc::clone) else {
            return Poll::Ready(Ok(0));
        };

        enum Step {
            Ready(ReadyBlock),
            Err(io::Error),
            Eof,
            Pending,
        }

        let step = {
            let mut state = core.state.lock().unwrap();
            if let Some(err) = state.error.take() {
                state.aborted = true;
                state.reader_waker = None;
                state.wake_all_workers();
                Step::Err(err)
            } else if let Some(blk) = state.reorder.ready_queue.pop_front() {
                Step::Ready(blk)
            } else if state.reorder.next_deliver_blk >= state.scheduler.total_blks {
                // Every block in `0..total_blks` has been delivered; do not wait for
                // slow or hung hedged stragglers to exit before completing EOF.
                state.aborted = true;
                state.reader_waker = None;
                state.wake_all_workers();
                Step::Eof
            } else if state.live == 0 {
                state.aborted = true;
                state.reader_waker = None;
                Step::Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "download workers terminated before stream completion",
                ))
            } else {
                state.reader_waker = Some(cx.waker().clone());
                Step::Pending
            }
        };

        match step {
            Step::Ready(blk) => {
                debug_assert!(blk.len > 0);
                let n = blk.len.min(buf.len());
                buf[..n].copy_from_slice(&blk.buf[..n]);
                if n == blk.len {
                    core.recycle_block(blk.buf);
                } else {
                    self.current = Some(CurrentBlock {
                        buf: blk.buf,
                        pos: n,
                        len: blk.len,
                    });
                }
                Poll::Ready(Ok(n))
            }
            Step::Err(err) => {
                self.core = None;
                self.workers.abort_all();
                Poll::Ready(Err(err))
            }
            Step::Eof => {
                self.core = None;
                self.workers.abort_all();
                Poll::Ready(Ok(0))
            }
            Step::Pending => Poll::Pending,
        }
    }
}

#[derive(Clone, Copy)]
struct TaskRange {
    start_blk: u64,
    end_blk: u64,
}

#[derive(Clone, Copy)]
struct ActiveSlot {
    curr_blk: u64,
    end_blk: u64,
}

struct ReadyBlock {
    buf: Vec<u8>,
    len: usize,
}

struct Scheduler {
    total_blks: u64,
    next_dispatch_blk: u64,
    hedged_blk: Option<u64>,
    retry_queue: VecDeque<TaskRange>,
    active_slots: Vec<Option<ActiveSlot>>,
    in_flight_tasks: usize,
}

impl Scheduler {
    fn new(total_blks: u64, n_workers: usize) -> Self {
        Self {
            total_blks,
            next_dispatch_blk: 0,
            hedged_blk: None,
            retry_queue: VecDeque::new(),
            active_slots: vec![None; n_workers],
            in_flight_tasks: 0,
        }
    }

    fn is_drained(&self) -> bool {
        self.next_dispatch_blk >= self.total_blks
            && self.in_flight_tasks == 0
            && self.retry_queue.is_empty()
    }

    /// Inserts `task` into `retry_queue` ordered by lowest `start_blk` so head-of-line
    /// blocks are always prioritized first.
    fn push_retry(&mut self, task: TaskRange) {
        let pos = self
            .retry_queue
            .iter()
            .position(|existing| existing.start_blk > task.start_blk)
            .unwrap_or(self.retry_queue.len());
        self.retry_queue.insert(pos, task);
    }

    fn assign_slot(&mut self, worker_id: usize, task: TaskRange) -> Claim {
        self.active_slots[worker_id] = Some(ActiveSlot {
            curr_blk: task.start_blk,
            end_blk: task.end_blk,
        });
        self.in_flight_tasks += 1;
        Claim::Task(task)
    }

    fn take_slot(&mut self, worker_id: usize) -> Option<ActiveSlot> {
        let slot = self.active_slots[worker_id].take();
        if slot.is_some() {
            self.in_flight_tasks -= 1;
        }
        slot
    }

    fn is_block_active(&self, blk: u64) -> bool {
        self.active_slots
            .iter()
            .flatten()
            .any(|s| s.curr_blk <= blk && blk < s.end_blk)
    }

    fn claim_task(
        &mut self,
        worker_id: usize,
        live: usize,
        window_blocks: u64,
        consumed_blk: u64,
        next_deliver_blk: u64,
    ) -> Claim {
        // Priority 1: Re-queued tasks already reside inside the active window (earliest first).
        if let Some(task) = self.retry_queue.pop_front() {
            return self.assign_slot(worker_id, task);
        }

        // Priority 2: Sequential dispatch of full-sized chunks within the sliding window
        // anchored at `consumed_blk` (never fragmenting into 1-block crumbs).
        if self.next_dispatch_blk < self.total_blks {
            let rem_blks = self.total_blks - self.next_dispatch_blk;
            let active_concurrency = live.max(1) as u64;
            let step = rem_blks
                .div_ceil(active_concurrency)
                .clamp(1, TARGET_TASK_BLOCKS);
            let in_window = self.next_dispatch_blk - consumed_blk;
            let avail_in_window = window_blocks.saturating_sub(in_window);

            if avail_in_window >= step || avail_in_window >= rem_blks {
                let count = step.min(rem_blks);
                let start_blk = self.next_dispatch_blk;
                let end_blk = start_blk + count;
                self.next_dispatch_blk = end_blk;
                return self.assign_slot(worker_id, TaskRange { start_blk, end_blk });
            }
        }

        // Priority 3: Work-stealing & head-of-line hedging. Splitting an active HTTP/1.1
        // range drops its reader before `Content-Length` EOF, forcing the transport to close
        // that warm TCP socket. Therefore, only steal or hedge during:
        //   (a) Endgame (`next_dispatch_blk >= total_blks`), or
        //   (b) A genuine head-of-line straggler (`curr_blk == next_deliver_blk`) that has
        //       idled at least half of the live worker pool.
        let consumer_has_room = (next_deliver_blk - consumed_blk) < window_blocks;
        let is_endgame = self.next_dispatch_blk >= self.total_blks;
        let hol_stalled = self.in_flight_tasks <= (live / 2).max(1);
        if consumer_has_room && (is_endgame || hol_stalled) {
            let victim = self
                .active_slots
                .iter_mut()
                .filter_map(|s| s.as_mut())
                .filter(|s| {
                    let unstarted = s.end_blk.saturating_sub(s.curr_blk + 1);
                    unstarted >= 1 && (is_endgame || s.curr_blk == next_deliver_blk)
                })
                .min_by_key(|s| s.curr_blk);

            if let Some(slot) = victim {
                let unstarted = slot.end_blk - (slot.curr_blk + 1);
                let steal_len = unstarted.div_ceil(2);
                let steal_start = slot.end_blk - steal_len;
                let steal_end = slot.end_blk;
                slot.end_blk = steal_start;
                return self.assign_slot(
                    worker_id,
                    TaskRange {
                        start_blk: steal_start,
                        end_blk: steal_end,
                    },
                );
            }

            // Speculative backup read (hedge) if the single head-of-line block `next_deliver_blk`
            // has no unstarted tail left to split and is still stalling half the worker pool.
            if self.hedged_blk != Some(next_deliver_blk)
                && self
                    .active_slots
                    .iter()
                    .flatten()
                    .any(|s| s.curr_blk == next_deliver_blk && s.end_blk == next_deliver_blk + 1)
            {
                self.hedged_blk = Some(next_deliver_blk);
                return self.assign_slot(
                    worker_id,
                    TaskRange {
                        start_blk: next_deliver_blk,
                        end_blk: next_deliver_blk + 1,
                    },
                );
            }
        }

        if self.is_drained() {
            Claim::Done
        } else {
            Claim::Wait
        }
    }
}

struct ReorderQueue {
    committed_blks: u64,
    consumed_blk: u64,
    next_deliver_blk: u64,
    reorder: BTreeMap<u64, (Vec<u8>, usize)>,
    ready_queue: VecDeque<ReadyBlock>,
    buf_pool: Vec<Vec<u8>>,
}

impl ReorderQueue {
    fn new() -> Self {
        Self {
            committed_blks: 0,
            consumed_blk: 0,
            next_deliver_blk: 0,
            reorder: BTreeMap::new(),
            ready_queue: VecDeque::new(),
            buf_pool: Vec::new(),
        }
    }

    fn pool_buf(&mut self, max_pooled_bufs: usize, buf: Vec<u8>) {
        if buf.capacity() >= BLOCK_SIZE && self.buf_pool.len() < max_pooled_bufs {
            self.buf_pool.push(buf);
        }
    }

    fn is_committed(&self, blk: u64) -> bool {
        blk < self.next_deliver_blk || self.reorder.contains_key(&blk)
    }

    fn commit(
        &mut self,
        blk_idx: u64,
        buf: Vec<u8>,
        len: usize,
        max_pooled_bufs: usize,
        delivered_blk: &AtomicU64,
    ) -> (bool, u64) {
        if self.is_committed(blk_idx) {
            self.pool_buf(max_pooled_bufs, buf);
            return (false, len as u64);
        }

        self.committed_blks += 1;
        self.reorder.insert(blk_idx, (buf, len));

        let mut advanced = false;
        while let Some((buf, len)) = self.reorder.remove(&self.next_deliver_blk) {
            self.next_deliver_blk += 1;
            advanced = true;
            self.ready_queue.push_back(ReadyBlock { buf, len });
        }
        if advanced {
            delivered_blk.store(self.next_deliver_blk, Ordering::Relaxed);
        }
        (advanced, 0)
    }
}

struct State {
    scheduler: Scheduler,
    reorder: ReorderQueue,
    live: usize,
    worker_wakers: Vec<Option<Waker>>,
    reader_waker: Option<Waker>,
    aborted: bool,
    error: Option<io::Error>,
}

struct SharedCore {
    base_offset: u64,
    effective_end: u64,
    observer: Arc<dyn TransferObserver>,
    window_blocks: u64,
    max_pooled_bufs: usize,
    delivered_blk: AtomicU64,
    rewind_debt: AtomicU64,
    state: Mutex<State>,
}

fn consume_rewind_debt(debt: &AtomicU64, bytes: u64) -> u64 {
    let mut cur = debt.load(Ordering::Relaxed);
    while cur > 0 {
        let paid = cur.min(bytes);
        match debt.compare_exchange_weak(cur, cur - paid, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return bytes - paid,
            Err(actual) => cur = actual,
        }
    }
    bytes
}

impl SharedCore {
    fn block_start(&self, blk: u64) -> u64 {
        self.base_offset + blk * BLOCK_SIZE as u64
    }

    fn block_len(&self, blk: u64) -> usize {
        (self.effective_end - self.block_start(blk)).min(BLOCK_SIZE as u64) as usize
    }

    fn record_bytes(&self, bytes: u64) {
        let net = consume_rewind_debt(&self.rewind_debt, bytes);
        self.observer.on_bytes(bytes, net);
    }

    fn record_rewind(&self, bytes: u64) {
        self.rewind_debt.fetch_add(bytes, Ordering::Relaxed);
    }

    fn take_buf(&self, needed_len: usize) -> Vec<u8> {
        if let Some(mut buf) = self.state.lock().unwrap().reorder.buf_pool.pop() {
            if buf.len() < needed_len {
                buf.resize(needed_len, 0);
            }
            return buf;
        }
        vec![0u8; needed_len]
    }

    fn recycle_block(&self, buf: Vec<u8>) {
        let mut state = self.state.lock().unwrap();
        state.reorder.consumed_blk += 1;
        state.reorder.pool_buf(self.max_pooled_bufs, buf);
        state.wake_one_worker();
    }
}

enum Claim {
    Task(TaskRange),
    Wait,
    Done,
}

impl State {
    fn wake_one_worker(&mut self) {
        for slot in &mut self.worker_wakers {
            if let Some(w) = slot.take() {
                w.wake();
                break;
            }
        }
    }

    fn wake_all_workers(&mut self) {
        for slot in &mut self.worker_wakers {
            if let Some(w) = slot.take() {
                w.wake();
            }
        }
    }

    fn wake_reader(&mut self) {
        if let Some(w) = self.reader_waker.take() {
            w.wake();
        }
    }

    fn retire_worker(&mut self, worker_id: usize) {
        self.worker_wakers[worker_id] = None;
        self.live = self.live.saturating_sub(1);
        self.wake_all_workers();
        if self.live == 0 {
            self.wake_reader();
        }
    }

    fn finish_worker_slot(&mut self, worker_id: usize) {
        self.scheduler.take_slot(worker_id);
        if self.scheduler.is_drained() {
            self.wake_all_workers();
            self.wake_reader();
        } else {
            self.wake_one_worker();
        }
    }

    fn claim_task(&mut self, window_blocks: u64, worker_id: usize) -> Claim {
        if self.aborted || self.error.is_some() {
            return Claim::Done;
        }
        self.scheduler.claim_task(
            worker_id,
            self.live,
            window_blocks,
            self.reorder.consumed_blk,
            self.reorder.next_deliver_blk,
        )
    }
}

async fn next_task(core: &SharedCore, worker_id: usize) -> Option<TaskRange> {
    poll_fn(|cx| {
        let mut state = core.state.lock().unwrap();
        match state.claim_task(core.window_blocks, worker_id) {
            Claim::Task(task) => {
                state.worker_wakers[worker_id] = None;
                state.wake_one_worker();
                Poll::Ready(Some(task))
            }
            Claim::Done => {
                state.retire_worker(worker_id);
                Poll::Ready(None)
            }
            Claim::Wait => {
                state.worker_wakers[worker_id] = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    })
    .await
}

/// Commits `blk_idx` and advances the worker's `ActiveSlot`.
/// Returns `true` if the worker has completed all blocks currently owned by its slot.
fn commit_block(
    core: &SharedCore,
    worker_id: usize,
    blk_idx: u64,
    buf: Vec<u8>,
    len: usize,
) -> bool {
    let (done, duplicate_bytes) = {
        let mut state = core.state.lock().unwrap();
        let (advanced, dup) =
            state
                .reorder
                .commit(blk_idx, buf, len, core.max_pooled_bufs, &core.delivered_blk);
        if advanced {
            state.wake_reader();
            state.wake_one_worker();
        }

        let slot = state.scheduler.active_slots[worker_id]
            .as_mut()
            .expect("worker committing block owns active slot");
        let next_blk = blk_idx + 1;
        let finished = if next_blk >= slot.end_blk {
            state.finish_worker_slot(worker_id);
            true
        } else {
            slot.curr_blk = next_blk;
            false
        };
        (finished, dup)
    };
    if duplicate_bytes > 0 {
        core.record_rewind(duplicate_bytes);
    }
    done
}

struct WorkerGuard<'a> {
    core: &'a SharedCore,
    worker_id: usize,
    uncommitted_bytes: u64,
    disarmed: bool,
}

impl WorkerGuard<'_> {
    fn flush_rewind(&mut self) {
        let rewind = std::mem::take(&mut self.uncommitted_bytes);
        if rewind > 0 {
            self.core.record_rewind(rewind);
        }
    }

    fn fail_fatal(&mut self, err: io::Error, buf: &mut Option<Vec<u8>>) {
        self.flush_rewind();
        self.disarmed = true;

        let mut state = self.core.state.lock().unwrap();
        if let Some(b) = buf.take() {
            state.reorder.pool_buf(self.core.max_pooled_bufs, b);
        }
        state.scheduler.take_slot(self.worker_id);
        if state.error.is_none() {
            state.error = Some(err);
        }
        state.aborted = true;
        state.retire_worker(self.worker_id);
        state.wake_reader();
    }

    /// Handles a worker whose current task exhausted `MAX_STALL_RETRIES`: re-queues
    /// any uncovered remaining blocks, sheds excess concurrency, or fails the stream
    /// after `MAX_DEAD_STALLS` consecutive stalls without global forward progress.
    /// Returns `true` if the worker should terminate.
    fn handle_stall(
        &mut self,
        curr_blk: u64,
        curr_pos: u64,
        last_err: io::Error,
        buf: &mut Option<Vec<u8>>,
        last_committed: &mut u64,
        dead_stalls: &mut u32,
    ) -> bool {
        self.flush_rewind();

        let mut state = self.core.state.lock().unwrap();
        if let Some(b) = buf.take() {
            state.reorder.pool_buf(self.core.max_pooled_bufs, b);
        }
        let slot = state
            .scheduler
            .take_slot(self.worker_id)
            .expect("stalled worker owns active slot");

        if state.aborted || state.error.is_some() {
            self.disarmed = true;
            state.retire_worker(self.worker_id);
            return true;
        }

        let already_covered = (curr_blk + 1 == slot.end_blk)
            && (state.reorder.is_committed(curr_blk) || state.scheduler.is_block_active(curr_blk));
        if !already_covered {
            state.scheduler.push_retry(TaskRange {
                start_blk: curr_blk,
                end_blk: slot.end_blk,
            });
        }

        if state.live > 1 {
            self.disarmed = true;
            state.retire_worker(self.worker_id);
            let remaining = state.live;
            drop(state);
            self.core.observer.on_warning(TransferWarning::Throttled {
                offset: curr_pos,
                remaining_connections: remaining,
            });
            return true;
        }

        if state.reorder.committed_blks > *last_committed {
            *last_committed = state.reorder.committed_blks;
            *dead_stalls = 0;
            state.wake_all_workers();
        } else {
            *dead_stalls += 1;
            if *dead_stalls > MAX_DEAD_STALLS {
                self.disarmed = true;
                if state.error.is_none() {
                    state.error = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("download stalled at offset {curr_pos}: {last_err}"),
                    ));
                }
                state.worker_wakers[self.worker_id] = None;
                state.live = 0;
                state.wake_all_workers();
                state.wake_reader();
                return true;
            }
            state.wake_all_workers();
        }
        false
    }
}

impl Drop for WorkerGuard<'_> {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        self.flush_rewind();
        let mut state = self.core.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(slot) = state.scheduler.take_slot(self.worker_id)
            && !state.aborted
            && state.error.is_none()
        {
            state.scheduler.push_retry(TaskRange {
                start_blk: slot.curr_blk,
                end_blk: slot.end_blk,
            });
        }
        state.retire_worker(self.worker_id);
    }
}

async fn run_worker<S: DataSource + 'static>(
    source: Arc<S>,
    core: Arc<SharedCore>,
    worker_id: usize,
) {
    enum RunOutcome {
        SlotFinished,
        HedgeAborted,
        Stalled(io::Error),
    }

    let mut guard = WorkerGuard {
        core: &core,
        worker_id,
        uncommitted_bytes: 0,
        disarmed: false,
    };

    if worker_id > 0 {
        sleep(stagger_delay(worker_id)).await;
    }

    let mut last_committed = 0u64;
    let mut dead_stalls = 0u32;

    while let Some(task) = next_task(&core, worker_id).await {
        let mut curr_blk = task.start_blk;
        let mut buf = Some(core.take_buf(core.block_len(curr_blk)));
        let mut partial_len = 0usize;
        let mut retries = 0u32;
        let mut last_err: Option<io::Error> = None;

        loop {
            enum PreFetch {
                Proceed(u64),
                AlreadyDelivered,
                Abort,
            }

            let pre = {
                let state = core.state.lock().unwrap();
                if state.aborted || state.error.is_some() {
                    PreFetch::Abort
                } else if curr_blk < state.reorder.next_deliver_blk {
                    PreFetch::AlreadyDelivered
                } else {
                    PreFetch::Proceed(
                        state.scheduler.active_slots[worker_id]
                            .expect("active worker owns slot")
                            .end_blk,
                    )
                }
            };

            let current_end_blk = match pre {
                PreFetch::Abort => return,
                PreFetch::AlreadyDelivered => {
                    guard.flush_rewind();
                    let mut state = core.state.lock().unwrap();
                    if let Some(b) = buf.take() {
                        state.reorder.pool_buf(core.max_pooled_bufs, b);
                    }
                    state.finish_worker_slot(worker_id);
                    dead_stalls = 0;
                    break;
                }
                PreFetch::Proceed(end_blk) => end_blk,
            };

            let task_byte_end = core
                .base_offset
                .saturating_add(current_end_blk.saturating_mul(BLOCK_SIZE as u64))
                .min(core.effective_end);

            let fetch_pos = core.block_start(curr_blk) + partial_len as u64;
            let resume_from = fetch_pos;

            let outcome = match source.fetch_range(fetch_pos..task_byte_end).await {
                Ok(mut reader) => loop {
                    let expected_blk_len = core.block_len(curr_blk);
                    let active_buf = buf.as_mut().expect("active block buffer");

                    match reader
                        .read(&mut active_buf[partial_len..expected_blk_len])
                        .await
                    {
                        Ok(0) => {
                            break RunOutcome::Stalled(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "premature EOF while reading chunk",
                            ));
                        }
                        Ok(n) => {
                            partial_len += n;
                            guard.uncommitted_bytes += n as u64;
                            core.record_bytes(n as u64);

                            // If a speculative backup worker already finished and delivered
                            // `curr_blk`, abort this slow stream immediately so its degraded
                            // socket is closed and replaced rather than reused across waves.
                            if curr_blk < core.delivered_blk.load(Ordering::Relaxed) {
                                break RunOutcome::HedgeAborted;
                            }

                            if partial_len == expected_blk_len {
                                let finished_slot = commit_block(
                                    &core,
                                    worker_id,
                                    curr_blk,
                                    buf.take().unwrap(),
                                    partial_len,
                                );
                                guard.uncommitted_bytes = 0;
                                curr_blk += 1;
                                partial_len = 0;
                                if finished_slot {
                                    break RunOutcome::SlotFinished;
                                }
                                buf = Some(core.take_buf(core.block_len(curr_blk)));
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => break RunOutcome::Stalled(e),
                    }
                },
                Err(e) => RunOutcome::Stalled(e),
            };

            let outcome = match outcome {
                RunOutcome::Stalled(_) if curr_blk < core.delivered_blk.load(Ordering::Relaxed) => {
                    RunOutcome::HedgeAborted
                }
                other => other,
            };

            let stall_err = match outcome {
                RunOutcome::SlotFinished => {
                    dead_stalls = 0;
                    break;
                }
                RunOutcome::HedgeAborted => {
                    guard.flush_rewind();
                    let mut state = core.state.lock().unwrap();
                    if let Some(b) = buf.take() {
                        state.reorder.pool_buf(core.max_pooled_bufs, b);
                    }
                    state.finish_worker_slot(worker_id);
                    dead_stalls = 0;
                    break;
                }
                RunOutcome::Stalled(err) => err,
            };

            if !is_retryable_error(&stall_err) {
                guard.fail_fatal(stall_err, &mut buf);
                return;
            }

            let curr_pos = core.block_start(curr_blk) + partial_len as u64;
            if curr_pos > resume_from {
                retries = 0;
            }
            retries += 1;
            if retries > MAX_STALL_RETRIES {
                last_err = Some(stall_err);
                break;
            }
            core.observer.on_warning(TransferWarning::Retry {
                offset: curr_pos,
                attempt: retries,
                max_attempts: MAX_STALL_RETRIES,
                error: stall_err.to_string(),
            });
            sleep(retry_backoff(retries)).await;
        }

        if let Some(err) = last_err
            && guard.handle_stall(
                curr_blk,
                core.block_start(curr_blk) + partial_len as u64,
                err,
                &mut buf,
                &mut last_committed,
                &mut dead_stalls,
            )
        {
            return;
        }
    }
    guard.disarmed = true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on_tokio;
    use std::ops::Range;
    use std::sync::atomic::AtomicUsize;

    struct ChaosReader {
        data: Vec<u8>,
        pos: usize,
        yields_left: usize,
        yields_per_read: usize,
        step_size: usize,
        fail_after: Option<usize>,
        hang_after: Option<usize>,
    }

    impl AsyncRead for ChaosReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.yields_left > 0 {
                self.yields_left -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Some(limit) = self.hang_after
                && self.pos >= limit
            {
                return Poll::Pending;
            }
            if let Some(limit) = self.fail_after
                && self.pos >= limit
            {
                self.fail_after = None;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "simulated transient reset",
                )));
            }
            let cap = self
                .hang_after
                .map_or(self.data.len(), |l| l.min(self.data.len()));
            let n = (cap - self.pos).min(self.step_size).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            if n > 0 && self.yields_per_read > 0 {
                self.yields_left = self.yields_per_read;
            }
            Poll::Ready(Ok(n))
        }
    }

    #[derive(Clone, Copy)]
    enum ChaosMode {
        Clean,
        Flaky,
        PrematureEofOnce,
        SlowFirstWorker,
        HungTailBlock,
        InitialFails(usize),
        StuckAtOffset(usize),
        AlwaysFail,
        Fatal404,
    }

    struct ChaosSource {
        data: Vec<u8>,
        mode: ChaosMode,
        requests: Arc<Mutex<Vec<Option<Range<u64>>>>>,
        req_count: AtomicUsize,
        tail_hits: AtomicUsize,
    }

    impl ChaosSource {
        fn exact(data: Vec<u8>, mode: ChaosMode) -> Self {
            Self {
                data,
                mode,
                requests: Arc::new(Mutex::new(Vec::new())),
                req_count: AtomicUsize::new(0),
                tail_hits: AtomicUsize::new(0),
            }
        }
    }

    impl DataSource for ChaosSource {
        fn size(&self) -> u64 {
            self.data.len() as u64
        }

        async fn fetch_range(
            &self,
            range: impl RangeBounds<u64> + MaybeSend,
        ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
            let resolved = resolve_range_bounds(range, self.data.len() as u64);
            self.requests.lock().unwrap().push(resolved.clone());
            let idx = self.req_count.fetch_add(1, Ordering::Relaxed);

            match self.mode {
                ChaosMode::Clean
                | ChaosMode::PrematureEofOnce
                | ChaosMode::SlowFirstWorker
                | ChaosMode::HungTailBlock
                | ChaosMode::StuckAtOffset(_) => {}
                ChaosMode::Flaky => {
                    if idx == 0 {
                        return Err(io::Error::other("transient 503"));
                    }
                }
                ChaosMode::InitialFails(n) => {
                    if idx < n {
                        return Err(io::Error::other("transient 500"));
                    }
                }
                ChaosMode::AlwaysFail => {
                    return Err(io::Error::other("persistent 503"));
                }
                ChaosMode::Fatal404 => {
                    return Err(io::Error::other(HttpError::Status(404)));
                }
            }

            let start_off = resolved.as_ref().map_or(0, |r| r.start);
            let mut slice = match &resolved {
                Some(r) => self.data[r.start as usize..r.end as usize].to_vec(),
                None => Vec::new(),
            };
            if matches!(self.mode, ChaosMode::PrematureEofOnce) && idx == 0 && slice.len() > 128 {
                slice.truncate(128);
            }

            let (yields_left, yields_per_read, step_size) = match self.mode {
                ChaosMode::Flaky => ((idx * 3) % 7, 0, BLOCK_SIZE / 4),
                ChaosMode::SlowFirstWorker if idx == 0 => (4, 4, BLOCK_SIZE / 16),
                ChaosMode::StuckAtOffset(_) => (0, 0, BLOCK_SIZE / 4),
                _ => (0, 0, BLOCK_SIZE),
            };
            let fail_after = match self.mode {
                ChaosMode::Flaky if idx.is_multiple_of(4) && slice.len() > BLOCK_SIZE / 2 => {
                    Some(BLOCK_SIZE / 2)
                }
                ChaosMode::StuckAtOffset(stuck) => Some(stuck.saturating_sub(start_off as usize)),
                _ => None,
            };
            let hang_after = if matches!(self.mode, ChaosMode::HungTailBlock)
                && start_off as usize == BLOCK_SIZE
                && self.tail_hits.fetch_add(1, Ordering::SeqCst) == 0
            {
                Some(BLOCK_SIZE / 4)
            } else {
                None
            };

            Ok(ChaosReader {
                data: slice,
                pos: 0,
                yields_left,
                yields_per_read,
                step_size,
                fail_after,
                hang_after,
            })
        }
    }

    struct RecordingObserver {
        wire_bytes: AtomicU64,
        net_bytes: AtomicU64,
        warnings: AtomicUsize,
        throttled: AtomicUsize,
    }

    impl RecordingObserver {
        fn new() -> Self {
            Self {
                wire_bytes: AtomicU64::new(0),
                net_bytes: AtomicU64::new(0),
                warnings: AtomicUsize::new(0),
                throttled: AtomicUsize::new(0),
            }
        }
    }

    impl TransferObserver for RecordingObserver {
        fn on_bytes(&self, wire_bytes: u64, net_bytes: u64) {
            assert!(net_bytes <= wire_bytes);
            self.wire_bytes.fetch_add(wire_bytes, Ordering::Relaxed);
            self.net_bytes.fetch_add(net_bytes, Ordering::Relaxed);
        }

        fn on_warning(&self, warning: TransferWarning) {
            self.warnings.fetch_add(1, Ordering::Relaxed);
            if matches!(warning, TransferWarning::Throttled { .. }) {
                self.throttled.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[test]
    fn test_small_read_at_exact_alloc_and_empty_ranges() {
        let payload: Vec<u8> = (0..(3 * BLOCK_SIZE + 123))
            .map(|i| ((i * 7) % 251) as u8)
            .collect();
        let src = ChaosSource::exact(payload.clone(), ChaosMode::Clean);
        let reqs = Arc::clone(&src.requests);
        let obs = Arc::new(RecordingObserver::new());
        let parallel = ParallelDataSource::new(src, 4).with_observer(Arc::clone(&obs));
        assert_eq!(parallel.size(), payload.len() as u64);

        block_on_tokio(async {
            // 1. Empty slice, empty source, and empty/OOB ranges make zero fetch_range calls
            let mut empty = [];
            assert_eq!(parallel.read_at(&mut empty, 0).await.unwrap(), 0);
            #[allow(clippy::reversed_empty_ranges)]
            for r in [0..0, 20..10] {
                let mut out = Vec::new();
                parallel
                    .fetch_range(r)
                    .await
                    .unwrap()
                    .read_to_end(&mut out)
                    .await
                    .unwrap();
                assert!(out.is_empty());
            }
            let mut oob_out = Vec::new();
            parallel
                .fetch_range((payload.len() as u64)..)
                .await
                .unwrap()
                .read_to_end(&mut oob_out)
                .await
                .unwrap();
            assert!(oob_out.is_empty());
            assert!(reqs.lock().unwrap().is_empty());

            let empty_src = ChaosSource::exact(Vec::new(), ChaosMode::Clean);
            let single = ParallelDataSource::new(empty_src, 1);
            let mut empty_out = Vec::new();
            single
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut empty_out)
                .await
                .unwrap();
            assert!(empty_out.is_empty());

            // 2. Small <= BLOCK_SIZE read_at runs inline without emitting transfer wire bytes
            let mut hdr_buf = [0u8; 30];
            assert_eq!(parallel.read_at(&mut hdr_buf, 19).await.unwrap(), 30);
            assert_eq!(&hdr_buf, &payload[19..49]);
            assert_eq!(reqs.lock().unwrap().as_slice(), &[Some(19..49)]);
            assert_eq!(obs.wire_bytes.load(Ordering::Relaxed), 0);
            reqs.lock().unwrap().clear();

            // 3. Small fetch_range makes 1 exact range call, never pools < BLOCK_SIZE buffers,
            //    and drops SharedCore immediately upon reaching EOF.
            let mut reader = parallel.start_reader(19..49);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let mut hdr = Vec::new();
            reader.read_to_end(&mut hdr).await.unwrap();
            assert_eq!(hdr, &payload[19..49]);
            assert_eq!(reqs.lock().unwrap().as_slice(), &[Some(19..49)]);
            assert!(reader.core.is_none());
            assert!(core.state.lock().unwrap().reorder.buf_pool.is_empty());
            assert_eq!(core.state.lock().unwrap().reorder.consumed_blk, 1);
        });
    }

    #[test]
    fn test_premature_eof_retries_and_recovers() {
        let payload: Vec<u8> = (0..1000_usize).map(|i| (i as u8).wrapping_mul(3)).collect();
        let src = ChaosSource::exact(payload.clone(), ChaosMode::PrematureEofOnce);
        let reqs = Arc::clone(&src.requests);
        let obs = Arc::new(RecordingObserver::new());
        let parallel = ParallelDataSource::new(src, 2).with_observer(Arc::clone(&obs));

        block_on_tokio(async {
            let mut out = Vec::new();
            parallel
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(out, payload);
            assert_eq!(
                reqs.lock().unwrap().as_slice(),
                &[Some(0..1000), Some(128..1000)]
            );
            assert_eq!(obs.warnings.load(Ordering::Relaxed), 1);

            // Inline read_at also retries premature EOF and recovers cleanly
            let src2 = ChaosSource::exact(payload.clone(), ChaosMode::PrematureEofOnce);
            let obs2 = Arc::new(RecordingObserver::new());
            let p2 = ParallelDataSource::new(src2, 2).with_observer(Arc::clone(&obs2));
            let mut buf = vec![0u8; payload.len()];
            assert_eq!(p2.read_at(&mut buf, 0).await.unwrap(), payload.len());
            assert_eq!(buf, payload);
            assert_eq!(obs2.warnings.load(Ordering::Relaxed), 1);
            assert_eq!(obs2.wire_bytes.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn test_chaos_multichunk_streaming_and_buffer_recycling() {
        let payload: Vec<u8> = (0..(5 * BLOCK_SIZE + 123))
            .map(|i| ((i * 7) % 251) as u8)
            .collect();
        let src = ChaosSource::exact(payload.clone(), ChaosMode::Flaky);
        let observer = Arc::new(RecordingObserver::new());
        let parallel = ParallelDataSource::new(src, 4).with_observer(Arc::clone(&observer));

        block_on_tokio(async {
            let mut reader = parallel.start_reader(..);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let mut out = Vec::with_capacity(payload.len());
            let mut use_small = true;
            loop {
                let mut buf = vec![0u8; if use_small { 7 * 1024 } else { BLOCK_SIZE }];
                let n = reader.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
                use_small = !use_small;
            }

            // Let any aborted straggler workers run WorkerGuard::drop to flush rewind debt.
            tokio::task::yield_now().await;

            assert_eq!(out, payload);
            assert!(observer.warnings.load(Ordering::Relaxed) > 0);
            let wire = observer.wire_bytes.load(Ordering::Relaxed);
            let net = observer.net_bytes.load(Ordering::Relaxed);
            let debt = core.rewind_debt.load(Ordering::Relaxed);
            assert!(wire >= net);
            assert_eq!(net - debt, payload.len() as u64);

            let state = core.state.lock().unwrap();
            assert_eq!(state.reorder.consumed_blk, state.scheduler.total_blks);
            assert_eq!(state.scheduler.in_flight_tasks, 0);
            assert!(state.reorder.buf_pool.len() <= core.max_pooled_bufs);
        });
    }

    #[test]
    fn test_sliding_window_backpressure_and_midstream_stealing() {
        // 48 blocks with concurrency = 2 -> window_blocks = 36 (< 48).
        // Worker 0 crawls on [0..12) while Worker 1 fills the sliding window and then hits
        // backpressure (avail_in_window < step) while next_dispatch_blk < total_blks (!is_endgame),
        // triggering non-endgame head-of-line work-stealing/hedging and multi-wave advancement.
        let payload: Vec<u8> = (0..(48 * BLOCK_SIZE))
            .map(|i| ((i * 13) % 253) as u8)
            .collect();
        let src = ChaosSource::exact(payload.clone(), ChaosMode::SlowFirstWorker);
        let reqs = Arc::clone(&src.requests);
        let obs = Arc::new(RecordingObserver::new());
        let parallel = ParallelDataSource::new(src, 2).with_observer(Arc::clone(&obs));

        block_on_tokio(async {
            let mut reader = parallel.start_reader(..);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            assert_eq!(core.window_blocks, 36);
            assert!(core.state.lock().unwrap().scheduler.total_blks > core.window_blocks);

            let mut out = Vec::with_capacity(payload.len());
            reader.read_to_end(&mut out).await.unwrap();
            tokio::task::yield_now().await;
            assert_eq!(out, payload);

            // 48 blocks / 12 blocks-per-wave = 4 base waves; > 4 requests proves stealing/hedging.
            assert!(reqs.lock().unwrap().len() > 4);
            let wire = obs.wire_bytes.load(Ordering::Relaxed);
            let net = obs.net_bytes.load(Ordering::Relaxed);
            let debt = core.rewind_debt.load(Ordering::Relaxed);
            assert!(wire >= net);
            assert_eq!(net - debt, payload.len() as u64);
        });
    }

    #[test]
    fn test_drop_abort_and_worker_panic_handling() {
        let payload: Vec<u8> = (0..(12 * BLOCK_SIZE + 777))
            .map(|i| ((i * 17) % 241) as u8)
            .collect();

        block_on_tokio(async {
            // 1. Early drop aborts background tasks cleanly without hanging
            let abort_src = ChaosSource::exact(payload.clone(), ChaosMode::SlowFirstWorker);
            let abort_parallel = ParallelDataSource::new(abort_src, 4);
            let mut reader = abort_parallel.start_reader(..);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let mut small = [0u8; 1024];
            assert_eq!(reader.read(&mut small).await.unwrap(), 1024);
            assert_eq!(&small[..], &payload[..1024]);
            drop(reader);
            assert!(core.state.lock().unwrap().aborted);

            // 2. Panicking background workers unwind cleanly via WorkerGuard and surface
            //    UnexpectedEof instead of deadlocking or silently returning Ok(0).
            struct PanicSource(bool);
            impl DataSource for PanicSource {
                fn size(&self) -> u64 {
                    BLOCK_SIZE as u64
                }
                async fn fetch_range(
                    &self,
                    _range: impl RangeBounds<u64> + MaybeSend,
                ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
                    if self.0 {
                        panic!("simulated worker panic");
                    }
                    Ok(&[][..])
                }
            }
            let panic_parallel = ParallelDataSource::new(PanicSource(true), 2);
            let mut panic_out = Vec::new();
            let err = panic_parallel
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut panic_out)
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        });
    }

    #[test]
    fn test_non_retryable_error_fails_fast_and_retry_queue_orders_hol() {
        // 1. Deterministic 404 fails immediately without retrying or warning
        let payload = vec![0xAB; 2 * BLOCK_SIZE];
        let src = ChaosSource::exact(payload, ChaosMode::Fatal404);
        let reqs = Arc::clone(&src.requests);
        let obs = Arc::new(RecordingObserver::new());
        let parallel = ParallelDataSource::new(src, 2).with_observer(Arc::clone(&obs));

        block_on_tokio(async {
            let mut out = Vec::new();
            let err = parallel
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap_err();
            let status = err
                .get_ref()
                .and_then(|e| e.downcast_ref::<HttpError>())
                .expect("HttpError preserved");
            assert!(matches!(status, HttpError::Status(404)));
            assert_eq!(obs.warnings.load(Ordering::Relaxed), 0);
            assert!(reqs.lock().unwrap().len() <= 2);
        });

        // 2. Scheduler retry_queue always pops the lowest start_blk first
        let mut sched = Scheduler::new(48, 2);
        sched.push_retry(TaskRange {
            start_blk: 24,
            end_blk: 36,
        });
        sched.push_retry(TaskRange {
            start_blk: 0,
            end_blk: 12,
        });
        sched.push_retry(TaskRange {
            start_blk: 12,
            end_blk: 24,
        });
        assert!(matches!(
            sched.claim_task(0, 2, 36, 0, 0),
            Claim::Task(TaskRange {
                start_blk: 0,
                end_blk: 12
            })
        ));
        assert!(matches!(
            sched.claim_task(1, 2, 36, 0, 0),
            Claim::Task(TaskRange {
                start_blk: 12,
                end_blk: 24
            })
        ));
    }

    #[test]
    fn test_stall_retry_queue_throttling_and_timeout() {
        let payload: Vec<u8> = (0..(3 * BLOCK_SIZE + 50))
            .map(|i| (i % 199) as u8)
            .collect();

        block_on_tokio(async {
            // Case 1: 9 initial failures across 2 workers guarantees at least one worker
            // exhausts MAX_STALL_RETRIES (5 failures), triggering retry_queue + Throttled
            // warning before the surviving worker recovers.
            let obs = Arc::new(RecordingObserver::new());
            let recover_src = ChaosSource::exact(payload.clone(), ChaosMode::InitialFails(9));
            let recover_parallel =
                ParallelDataSource::new(recover_src, 2).with_observer(Arc::clone(&obs));
            let mut out = Vec::new();
            recover_parallel
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(out, payload);
            assert_eq!(obs.throttled.load(Ordering::Relaxed), 1);

            // Case 2: Persistent failures exhaust MAX_DEAD_STALLS -> TimedOut preserving cause
            let dead_src = ChaosSource::exact(payload.clone(), ChaosMode::AlwaysFail);
            let dead_parallel = ParallelDataSource::new(dead_src, 2);
            let mut dead_out = Vec::new();
            let err = dead_parallel
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut dead_out)
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert!(err.to_string().contains("persistent 503"), "err={err}");

            // Case 3: Repeated partial block reads (< BLOCK_SIZE) that reset before committing
            // a block must still hit MAX_DEAD_STALLS -> TimedOut rather than looping forever.
            let partial_obs = Arc::new(RecordingObserver::new());
            let stuck_off = BLOCK_SIZE / 2;
            let stuck_src = ChaosSource::exact(payload, ChaosMode::StuckAtOffset(stuck_off));
            let stuck_parallel =
                ParallelDataSource::new(stuck_src, 1).with_observer(Arc::clone(&partial_obs));
            let mut stuck_out = Vec::new();
            let mut reader = stuck_parallel.start_reader(..);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let stuck_err = reader.read_to_end(&mut stuck_out).await.unwrap_err();
            assert_eq!(stuck_err.kind(), io::ErrorKind::TimedOut);
            let wire = partial_obs.wire_bytes.load(Ordering::Relaxed);
            let net = partial_obs.net_bytes.load(Ordering::Relaxed);
            let debt = core.rewind_debt.load(Ordering::Relaxed);
            assert!(wire > net);
            assert_eq!(net, stuck_off as u64);
            assert_eq!(net, debt);
        });
    }

    #[test]
    fn test_hung_last_block_hedge_completes_eof_immediately() {
        let payload: Vec<u8> = (0..(2 * BLOCK_SIZE))
            .map(|i| ((i * 19) % 251) as u8)
            .collect();
        let src = ChaosSource::exact(payload.clone(), ChaosMode::HungTailBlock);
        let obs = Arc::new(RecordingObserver::new());
        let parallel = ParallelDataSource::new(src, 2).with_observer(Arc::clone(&obs));

        block_on_tokio(async {
            let mut reader = parallel.start_reader(..);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, payload);
            assert!(reader.core.is_none());

            // Let the aborted Tokio worker run WorkerGuard::drop to flush its partial rewind.
            tokio::task::yield_now().await;

            let wire = obs.wire_bytes.load(Ordering::Relaxed);
            let net = obs.net_bytes.load(Ordering::Relaxed);
            let debt = core.rewind_debt.load(Ordering::Relaxed);
            assert_eq!(wire, (2 * BLOCK_SIZE + BLOCK_SIZE / 4) as u64);
            assert_eq!(net - debt, payload.len() as u64);
        });
    }
}
