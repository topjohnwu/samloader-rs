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

const BLOCK_SIZE: usize = 2 * 1024 * 1024;

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

/// Diagnostic events emitted by [`ParallelDataSource`] during retries or throttling.
#[derive(Debug)]
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
    pub fn with_observer(mut self, observer: Arc<dyn TransferObserver>) -> Self {
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
        let Some((start, end)) = resolve_range_bounds(range) else {
            return empty_reader();
        };
        let total_size = self.inner.size();
        if total_size == 0 || start >= total_size {
            return empty_reader();
        }

        let effective_end = end.map_or(total_size, |e| e.min(total_size));
        let rem = effective_end - start;
        let total_blks = rem.div_ceil(BLOCK_SIZE as u64);
        let n_workers = self
            .concurrency
            .min(total_blks.min(usize::MAX as u64) as usize);

        // 1.5x wave window (`1.5 * concurrency * TARGET_TASK_BLOCKS`) provides 0.5x
        // wave slack so normal per-connection jitter never stalls or triggers premature
        // socket-closing steals, while keeping -j 8 at 288 MiB (216 MiB at WASM K=6).
        let window_blocks = ((self.concurrency as u64)
            .saturating_mul(TARGET_TASK_BLOCKS)
            .saturating_mul(3)
            / 2)
        .clamp(24, MAX_WINDOW_BLOCKS);
        let max_pooled_bufs = usize::try_from(window_blocks)
            .unwrap_or(usize::MAX)
            .saturating_add(self.concurrency.saturating_mul(2));

        let core = Arc::new(SharedCore {
            base_offset: start,
            effective_end,
            observer: Arc::clone(&self.observer),
            window_blocks,
            max_pooled_bufs,
            delivered_blk: AtomicU64::new(0),
            rewind_debt: AtomicU64::new(0),
            state: Mutex::new(State {
                total_blks,
                committed_blks: 0,
                consumed_blk: 0,
                next_deliver_blk: 0,
                next_dispatch_blk: 0,
                hedged_blk: None,
                reorder: BTreeMap::new(),
                retry_queue: VecDeque::new(),
                ready_queue: VecDeque::new(),
                buf_pool: Vec::new(),
                active_slots: vec![None; n_workers],
                in_flight_tasks: 0,
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
}

impl<S: DataSource + 'static> DataSource for ParallelDataSource<S> {
    fn size(&self) -> u64 {
        self.inner.size()
    }

    async fn fetch_range(
        &self,
        range: impl RangeBounds<u64> + Send,
    ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
        Ok(self.start_reader(range))
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

        loop {
            self.workers.poll_inline(cx);

            let step = {
                let mut state = core.state.lock().unwrap();
                if let Some(err) = state.error.take() {
                    state.aborted = true;
                    state.reader_waker = None;
                    state.wake_all_workers();
                    Step::Err(err)
                } else if let Some(blk) = state.ready_queue.pop_front() {
                    Step::Ready(blk)
                } else if state.next_deliver_blk >= state.total_blks {
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
                    if blk.len == 0 {
                        core.recycle_block(blk.buf);
                        continue;
                    }
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
                    return Poll::Ready(Ok(n));
                }
                Step::Err(err) => {
                    self.core = None;
                    self.workers.abort_all();
                    return Poll::Ready(Err(err));
                }
                Step::Eof => {
                    self.core = None;
                    self.workers.abort_all();
                    return Poll::Ready(Ok(0));
                }
                Step::Pending => return Poll::Pending,
            }
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

struct State {
    total_blks: u64,
    committed_blks: u64,
    consumed_blk: u64,
    next_deliver_blk: u64,
    next_dispatch_blk: u64,
    hedged_blk: Option<u64>,
    reorder: BTreeMap<u64, (Vec<u8>, usize)>,
    retry_queue: VecDeque<TaskRange>,
    ready_queue: VecDeque<ReadyBlock>,
    buf_pool: Vec<Vec<u8>>,
    active_slots: Vec<Option<ActiveSlot>>,
    in_flight_tasks: usize,
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
        if let Some(mut buf) = self.state.lock().unwrap().buf_pool.pop() {
            if buf.len() < needed_len {
                buf.resize(needed_len, 0);
            }
            return buf;
        }
        vec![0u8; needed_len]
    }

    fn recycle_block(&self, buf: Vec<u8>) {
        let mut state = self.state.lock().unwrap();
        state.consumed_blk += 1;
        state.pool_buf(self.max_pooled_bufs, buf);
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

    fn pool_buf(&mut self, max_pooled_bufs: usize, buf: Vec<u8>) {
        if buf.capacity() >= BLOCK_SIZE && self.buf_pool.len() < max_pooled_bufs {
            self.buf_pool.push(buf);
        }
    }

    fn is_dispatch_drained(&self) -> bool {
        self.next_dispatch_blk >= self.total_blks
            && self.in_flight_tasks == 0
            && self.retry_queue.is_empty()
    }

    fn assign_slot(&mut self, worker_id: usize, task: TaskRange) -> Claim {
        self.active_slots[worker_id] = Some(ActiveSlot {
            curr_blk: task.start_blk,
            end_blk: task.end_blk,
        });
        self.in_flight_tasks += 1;
        Claim::Task(task)
    }

    fn retire_worker(&mut self, worker_id: usize) {
        self.worker_wakers[worker_id] = None;
        self.live = self.live.saturating_sub(1);
        self.wake_all_workers();
        if self.live == 0 {
            self.wake_reader();
        }
    }

    fn flush_reorder(&mut self, delivered_blk: &AtomicU64) {
        let mut advanced = false;
        while let Some((buf, len)) = self.reorder.remove(&self.next_deliver_blk) {
            self.next_deliver_blk += 1;
            advanced = true;
            self.ready_queue.push_back(ReadyBlock { buf, len });
        }
        if advanced {
            delivered_blk.store(self.next_deliver_blk, Ordering::Relaxed);
            self.wake_reader();
            self.wake_one_worker();
        }
    }

    fn finish_worker_slot(&mut self, worker_id: usize) {
        if self.active_slots[worker_id].take().is_some() {
            self.in_flight_tasks -= 1;
        }
        if self.is_dispatch_drained() {
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

        // Priority 1: Re-queued tasks already reside inside the active window.
        if let Some(task) = self.retry_queue.pop_front() {
            return self.assign_slot(worker_id, task);
        }

        // Priority 2: Sequential dispatch of full-sized chunks within the sliding window
        // anchored at `consumed_blk` (never fragmenting into 1-block crumbs).
        if self.next_dispatch_blk < self.total_blks {
            let rem_blks = self.total_blks - self.next_dispatch_blk;
            let active_concurrency = self.live.max(1) as u64;
            let step = rem_blks
                .div_ceil(active_concurrency)
                .clamp(1, TARGET_TASK_BLOCKS);
            let in_window = self.next_dispatch_blk - self.consumed_blk;
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
        let consumer_has_room = (self.next_deliver_blk - self.consumed_blk) < window_blocks;
        let is_endgame = self.next_dispatch_blk >= self.total_blks;
        let hol_stalled = self.in_flight_tasks <= (self.live / 2).max(1);
        if consumer_has_room && (is_endgame || hol_stalled) {
            let next_deliver = self.next_deliver_blk;
            let victim = self
                .active_slots
                .iter_mut()
                .filter_map(|s| s.as_mut())
                .filter(|s| {
                    let unstarted = s.end_blk.saturating_sub(s.curr_blk + 1);
                    unstarted >= 1 && (is_endgame || s.curr_blk == next_deliver)
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

            // Speculative backup read (hedge) if the single head-of-line block `next_deliver`
            // has no unstarted tail left to split and is still stalling half the worker pool.
            if self.hedged_blk != Some(next_deliver)
                && self
                    .active_slots
                    .iter()
                    .flatten()
                    .any(|s| s.curr_blk == next_deliver && s.end_blk == next_deliver + 1)
            {
                self.hedged_blk = Some(next_deliver);
                return self.assign_slot(
                    worker_id,
                    TaskRange {
                        start_blk: next_deliver,
                        end_blk: next_deliver + 1,
                    },
                );
            }
        }

        if self.is_dispatch_drained() {
            Claim::Done
        } else {
            Claim::Wait
        }
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
    let mut duplicate_bytes = 0u64;
    let done = {
        let mut state = core.state.lock().unwrap();
        if blk_idx < state.next_deliver_blk || state.reorder.contains_key(&blk_idx) {
            state.pool_buf(core.max_pooled_bufs, buf);
            duplicate_bytes = len as u64;
        } else {
            state.committed_blks += 1;
            state.reorder.insert(blk_idx, (buf, len));
            state.flush_reorder(&core.delivered_blk);
        }

        let slot = state.active_slots[worker_id]
            .as_mut()
            .expect("worker committing block owns active slot");
        let next_blk = blk_idx + 1;
        if next_blk >= slot.end_blk {
            state.finish_worker_slot(worker_id);
            true
        } else {
            slot.curr_blk = next_blk;
            false
        }
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

    /// Handles a worker whose current task exhausted `MAX_STALL_RETRIES`: re-queues
    /// any uncovered remaining blocks, sheds excess concurrency, or fails the stream
    /// after `MAX_DEAD_STALLS` consecutive stalls without global forward progress.
    /// Returns `true` if the worker should terminate.
    fn handle_stall(
        &mut self,
        curr_blk: u64,
        curr_pos: u64,
        buf: &mut Option<Vec<u8>>,
        last_committed: &mut u64,
        dead_stalls: &mut u32,
    ) -> bool {
        self.flush_rewind();

        let mut state = self.core.state.lock().unwrap();
        if let Some(b) = buf.take() {
            state.pool_buf(self.core.max_pooled_bufs, b);
        }
        let slot = state.active_slots[self.worker_id]
            .take()
            .expect("stalled worker owns active slot");
        state.in_flight_tasks -= 1;

        if state.aborted || state.error.is_some() {
            self.disarmed = true;
            state.retire_worker(self.worker_id);
            return true;
        }

        let already_covered = (curr_blk + 1 == slot.end_blk)
            && (curr_blk < state.next_deliver_blk
                || state.reorder.contains_key(&curr_blk)
                || state
                    .active_slots
                    .iter()
                    .flatten()
                    .any(|s| s.curr_blk <= curr_blk && curr_blk < s.end_blk));
        if !already_covered {
            state.retry_queue.push_front(TaskRange {
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

        if state.committed_blks > *last_committed {
            *last_committed = state.committed_blks;
            *dead_stalls = 0;
            state.wake_all_workers();
        } else {
            *dead_stalls += 1;
            if *dead_stalls > MAX_DEAD_STALLS {
                self.disarmed = true;
                if state.error.is_none() {
                    state.error = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("download stalled at offset {curr_pos}: server stopped responding"),
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
        let mut state = match self.core.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(slot) = state.active_slots[self.worker_id].take() {
            state.in_flight_tasks -= 1;
            if !state.aborted && state.error.is_none() {
                state.retry_queue.push_front(TaskRange {
                    start_blk: slot.curr_blk,
                    end_blk: slot.end_blk,
                });
            }
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

        loop {
            let current_end_blk = {
                let mut state = core.state.lock().unwrap();
                if state.aborted || state.error.is_some() {
                    guard.flush_rewind();
                    guard.disarmed = true;
                    if let Some(b) = buf.take() {
                        state.pool_buf(core.max_pooled_bufs, b);
                    }
                    if state.active_slots[worker_id].take().is_some() {
                        state.in_flight_tasks -= 1;
                    }
                    state.retire_worker(worker_id);
                    return;
                }
                state.active_slots[worker_id]
                    .expect("active worker owns slot")
                    .end_blk
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
                        state.pool_buf(core.max_pooled_bufs, b);
                    }
                    state.finish_worker_slot(worker_id);
                    dead_stalls = 0;
                    break;
                }
                RunOutcome::Stalled(err) => err,
            };

            let curr_pos = core.block_start(curr_blk) + partial_len as u64;
            if curr_pos > resume_from {
                retries = 0;
            }
            retries += 1;
            if retries > MAX_STALL_RETRIES {
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

        if retries > MAX_STALL_RETRIES
            && guard.handle_stall(
                curr_blk,
                core.block_start(curr_blk) + partial_len as u64,
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
    use futures::executor::block_on;
    use std::sync::atomic::AtomicUsize;

    struct ChaosReader {
        data: Vec<u8>,
        pos: usize,
        yields_left: usize,
        yields_per_read: usize,
        step_size: usize,
        fail_after: Option<usize>,
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
            if let Some(limit) = self.fail_after
                && self.pos >= limit
            {
                self.fail_after = None;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "simulated transient reset",
                )));
            }
            let n = (self.data.len() - self.pos)
                .min(self.step_size)
                .min(buf.len());
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
        InitialFails(usize),
        StuckAtOffset(usize),
        AlwaysFail,
    }

    type ResolvedRange = Option<(u64, Option<u64>)>;

    struct ChaosSource {
        data: Vec<u8>,
        mode: ChaosMode,
        requests: Arc<Mutex<Vec<ResolvedRange>>>,
        req_count: AtomicUsize,
    }

    impl ChaosSource {
        fn exact(data: Vec<u8>, mode: ChaosMode) -> Self {
            Self {
                data,
                mode,
                requests: Arc::new(Mutex::new(Vec::new())),
                req_count: AtomicUsize::new(0),
            }
        }
    }

    impl DataSource for ChaosSource {
        fn size(&self) -> u64 {
            self.data.len() as u64
        }

        async fn fetch_range(
            &self,
            range: impl RangeBounds<u64> + Send,
        ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
            let resolved = resolve_range_bounds(range);
            self.requests.lock().unwrap().push(resolved);
            let idx = self.req_count.fetch_add(1, Ordering::Relaxed);

            match self.mode {
                ChaosMode::Clean
                | ChaosMode::PrematureEofOnce
                | ChaosMode::SlowFirstWorker
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
            }

            let len = self.data.len() as u64;
            let start_off = resolved.map_or(0, |(s, _)| s);
            let mut slice = match resolved {
                Some((start, end)) if start < len => {
                    let s = start as usize;
                    let e = end.map_or(self.data.len(), |e| e.min(len) as usize);
                    self.data[s..e].to_vec()
                }
                _ => Vec::new(),
            };
            if matches!(self.mode, ChaosMode::PrematureEofOnce) && idx == 0 && slice.len() > 128 {
                slice.truncate(128);
            }

            let (yields_left, yields_per_read, step_size) = match self.mode {
                ChaosMode::Flaky => ((idx * 3) % 7, 0, 256 * 1024),
                ChaosMode::SlowFirstWorker if idx == 0 => (4, 4, 64 * 1024),
                ChaosMode::StuckAtOffset(_) => (0, 0, 16 * 1024),
                _ => (0, 0, 256 * 1024),
            };
            let fail_after = match self.mode {
                ChaosMode::Flaky if idx.is_multiple_of(4) && slice.len() > 64_000 => Some(32_768),
                ChaosMode::StuckAtOffset(stuck) => Some(stuck.saturating_sub(start_off as usize)),
                _ => None,
            };

            Ok(ChaosReader {
                data: slice,
                pos: 0,
                yields_left,
                yields_per_read,
                step_size,
                fail_after,
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
    fn test_small_read_exact_alloc_and_empty_ranges() {
        let payload: Vec<u8> = (0..(5 * 1024 * 1024 + 123))
            .map(|i| ((i * 7) % 251) as u8)
            .collect();
        let src = ChaosSource::exact(payload.clone(), ChaosMode::Clean);
        let reqs = Arc::clone(&src.requests);
        let parallel = ParallelDataSource::new(src, 4);
        assert_eq!(parallel.size(), payload.len() as u64);

        block_on(async {
            // 1. Empty slice and empty/out-of-bounds ranges make zero fetch_range calls
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

            // 2. Small 30-byte header read makes 1 exact range call, never pools < BLOCK_SIZE
            //    buffers, and drops SharedCore immediately upon reaching EOF.
            let mut reader = parallel.start_reader(19..49);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let mut hdr = Vec::new();
            reader.read_to_end(&mut hdr).await.unwrap();
            assert_eq!(hdr, &payload[19..49]);
            assert_eq!(reqs.lock().unwrap().as_slice(), &[Some((19, Some(49)))]);
            assert!(reader.core.is_none());
            assert!(core.state.lock().unwrap().buf_pool.is_empty());
            assert_eq!(core.state.lock().unwrap().consumed_blk, 1);
        });
    }

    #[test]
    fn test_premature_eof_retries_and_recovers() {
        let payload: Vec<u8> = (0..1000_usize).map(|i| (i as u8).wrapping_mul(3)).collect();
        let src = ChaosSource::exact(payload.clone(), ChaosMode::PrematureEofOnce);
        let reqs = Arc::clone(&src.requests);
        let obs = Arc::new(RecordingObserver::new());
        let parallel = ParallelDataSource::new(src, 2)
            .with_observer(Arc::clone(&obs) as Arc<dyn TransferObserver>);

        block_on(async {
            let mut out = Vec::new();
            parallel
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(out, payload);
            // First request truncated at 128 bytes -> retried from 128..1000
            assert_eq!(
                reqs.lock().unwrap().as_slice(),
                &[Some((0, Some(1000))), Some((128, Some(1000)))]
            );
            assert_eq!(obs.warnings.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn test_chaos_multichunk_streaming_and_buffer_recycling() {
        let payload: Vec<u8> = (0..(5 * 1024 * 1024 + 123))
            .map(|i| ((i * 7) % 251) as u8)
            .collect();
        let src = ChaosSource::exact(payload.clone(), ChaosMode::Flaky);
        let observer = Arc::new(RecordingObserver::new());
        let parallel = ParallelDataSource::new(src, 4)
            .with_observer(Arc::clone(&observer) as Arc<dyn TransferObserver>);

        block_on(async {
            let mut reader = parallel.start_reader(..);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let mut out = Vec::with_capacity(payload.len());
            // Alternate odd small buffer (7 KiB) and 2 MiB buffer reads
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

            assert_eq!(out, payload);
            assert!(observer.warnings.load(Ordering::Relaxed) > 0);
            let wire = observer.wire_bytes.load(Ordering::Relaxed);
            let net = observer.net_bytes.load(Ordering::Relaxed);
            let debt = core.rewind_debt.load(Ordering::Relaxed);
            assert!(wire >= net);
            assert_eq!(net - debt, payload.len() as u64);

            let state = core.state.lock().unwrap();
            assert_eq!(state.consumed_blk, state.total_blks);
            assert_eq!(state.in_flight_tasks, 0);
            assert!(state.buf_pool.len() <= core.max_pooled_bufs);
        });
    }

    #[test]
    fn test_straggler_work_stealing() {
        // 16 blocks (32 MiB) across 4 workers -> 4 blocks (8 MiB) each initially.
        // Worker 0 crawls at 64 KiB + 4 yields/read, so fast workers 1..3 finish [4..16)
        // and steal/hedge blocks [0..4) from slow Worker 0.
        let payload: Vec<u8> = (0..(16 * BLOCK_SIZE))
            .map(|i| ((i * 13) % 253) as u8)
            .collect();
        let src = ChaosSource::exact(payload.clone(), ChaosMode::SlowFirstWorker);
        let reqs = Arc::clone(&src.requests);
        let obs = Arc::new(RecordingObserver::new());
        let parallel = ParallelDataSource::new(src, 4)
            .with_observer(Arc::clone(&obs) as Arc<dyn TransferObserver>);

        block_on(async {
            let mut reader = parallel.start_reader(..);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, payload);
            // More than 4 requests prove fast workers stole/hedged blocks from slow Worker 0
            assert!(reqs.lock().unwrap().len() > 4);
            let wire = obs.wire_bytes.load(Ordering::Relaxed);
            let net = obs.net_bytes.load(Ordering::Relaxed);
            let debt = core.rewind_debt.load(Ordering::Relaxed);
            assert!(wire >= net);
            assert_eq!(net - debt, payload.len() as u64);
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_tokio_spawn_and_drop_abort() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let payload: Vec<u8> = (0..(12 * BLOCK_SIZE + 777))
            .map(|i| ((i * 17) % 241) as u8)
            .collect();

        rt.block_on(async {
            // 1. Full streaming over multi-threaded Tokio worker tasks
            let src = ChaosSource::exact(payload.clone(), ChaosMode::Flaky);
            let parallel = ParallelDataSource::new(src, 4);
            let mut out = Vec::new();
            parallel
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(out, payload);

            // 2. Early drop aborts background tasks cleanly without hanging
            let abort_src = ChaosSource::exact(payload.clone(), ChaosMode::SlowFirstWorker);
            let abort_parallel = ParallelDataSource::new(abort_src, 4);
            let mut reader = abort_parallel.start_reader(..);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let mut small = [0u8; 1024];
            assert_eq!(reader.read(&mut small).await.unwrap(), 1024);
            assert_eq!(&small[..], &payload[..1024]);
            drop(reader);
            assert!(core.state.lock().unwrap().aborted);

            // 3. Panicking background workers unwind cleanly via WorkerGuard and surface
            //    UnexpectedEof instead of deadlocking or silently returning Ok(0).
            struct PanicSource;
            impl DataSource for PanicSource {
                fn size(&self) -> u64 {
                    BLOCK_SIZE as u64
                }
                async fn fetch_range(
                    &self,
                    _range: impl RangeBounds<u64> + Send,
                ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
                    panic!("simulated worker panic");
                    #[allow(unreachable_code)]
                    Ok(&[][..])
                }
            }
            let panic_parallel = ParallelDataSource::new(PanicSource, 2);
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
    fn test_stall_retry_queue_throttling_and_timeout() {
        let payload: Vec<u8> = (0..(3 * 1024 * 1024 + 50))
            .map(|i| (i % 199) as u8)
            .collect();

        // Case 1: 6 initial failures trigger retry_queue + Throttled warning, then recovers
        let obs = Arc::new(RecordingObserver::new());
        let recover_src = ChaosSource::exact(payload.clone(), ChaosMode::InitialFails(6));
        let recover_parallel = ParallelDataSource::new(recover_src, 2)
            .with_observer(Arc::clone(&obs) as Arc<dyn TransferObserver>);
        let mut out = Vec::new();
        block_on(async {
            recover_parallel
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
        });
        assert_eq!(out, payload);
        assert_eq!(obs.throttled.load(Ordering::Relaxed), 1);

        // Case 2: Persistent failures exhaust MAX_DEAD_STALLS -> TimedOut
        let dead_src = ChaosSource::exact(payload.clone(), ChaosMode::AlwaysFail);
        let dead_parallel = ParallelDataSource::new(dead_src, 2);
        let mut dead_out = Vec::new();
        let err = block_on(async {
            dead_parallel
                .fetch()
                .await?
                .read_to_end(&mut dead_out)
                .await
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        // Case 3: Repeated partial block reads (< BLOCK_SIZE) that reset before committing
        // a block must still hit MAX_DEAD_STALLS -> TimedOut rather than looping forever.
        let partial_obs = Arc::new(RecordingObserver::new());
        let stuck_src = ChaosSource::exact(payload, ChaosMode::StuckAtOffset(32_768));
        let stuck_parallel = ParallelDataSource::new(stuck_src, 1)
            .with_observer(Arc::clone(&partial_obs) as Arc<dyn TransferObserver>);
        let mut stuck_out = Vec::new();
        let (stuck_err, core) = block_on(async {
            let mut reader = stuck_parallel.start_reader(..);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let err = reader.read_to_end(&mut stuck_out).await.unwrap_err();
            (err, core)
        });
        assert_eq!(stuck_err.kind(), io::ErrorKind::TimedOut);
        let wire = partial_obs.wire_bytes.load(Ordering::Relaxed);
        let net = partial_obs.net_bytes.load(Ordering::Relaxed);
        let debt = core.rewind_debt.load(Ordering::Relaxed);
        assert!(wire > net);
        assert_eq!(net, 32_768);
        assert_eq!(net, debt);

        // Case 4: Empty source with concurrency = 1
        let empty_src = ChaosSource::exact(Vec::new(), ChaosMode::Clean);
        let single = ParallelDataSource::new(empty_src, 1);
        let mut empty_out = Vec::new();
        block_on(async {
            single
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut empty_out)
                .await
                .unwrap();
        });
        assert!(empty_out.is_empty());
    }

    #[test]
    fn test_hung_last_block_hedge_completes_eof_immediately() {
        // Two 2 MiB blocks with 2 workers: worker 0 finishes block 0 quickly, while
        // worker 1 reads 64 KiB of the final block (block 1) and then hangs forever
        // returning Poll::Pending. Worker 0 must hedge block 1, deliver EOF without
        // waiting for the hung worker, and unwind its partial bytes from rewind_debt.
        struct HangAfterPartial {
            data: Vec<u8>,
            pos: usize,
            hang_after: Option<usize>,
        }

        impl AsyncRead for HangAfterPartial {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                if let Some(limit) = self.hang_after
                    && self.pos >= limit
                {
                    return Poll::Pending;
                }
                let cap = self.hang_after.unwrap_or(self.data.len());
                let n = (cap.min(self.data.len()) - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Poll::Ready(Ok(n))
            }
        }

        struct HungTailSource {
            data: Vec<u8>,
            tail_hits: AtomicUsize,
        }

        impl DataSource for HungTailSource {
            fn size(&self) -> u64 {
                self.data.len() as u64
            }

            async fn fetch_range(
                &self,
                range: impl RangeBounds<u64> + Send,
            ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
                let Some((start, end)) = resolve_range_bounds(range) else {
                    return Ok(HangAfterPartial {
                        data: Vec::new(),
                        pos: 0,
                        hang_after: None,
                    });
                };
                let s = start as usize;
                let e = end.map_or(self.data.len(), |e| (e as usize).min(self.data.len()));
                // First request for block 1 reads 64 KiB then hangs permanently;
                // the backup hedge request completes immediately.
                let hang_after =
                    if s == BLOCK_SIZE && self.tail_hits.fetch_add(1, Ordering::SeqCst) == 0 {
                        Some(64 * 1024)
                    } else {
                        None
                    };
                Ok(HangAfterPartial {
                    data: self.data[s..e].to_vec(),
                    pos: 0,
                    hang_after,
                })
            }
        }

        let payload: Vec<u8> = (0..(2 * BLOCK_SIZE))
            .map(|i| ((i * 19) % 251) as u8)
            .collect();
        let src = HungTailSource {
            data: payload.clone(),
            tail_hits: AtomicUsize::new(0),
        };
        let obs = Arc::new(RecordingObserver::new());
        let parallel = ParallelDataSource::new(src, 2)
            .with_observer(Arc::clone(&obs) as Arc<dyn TransferObserver>);

        block_on(async {
            let mut reader = parallel.start_reader(..);
            let core = Arc::clone(reader.core.as_ref().unwrap());
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, payload);
            assert!(reader.core.is_none());

            // Hung worker was aborted by EOF and its 64 KiB partial read was rewound.
            let wire = obs.wire_bytes.load(Ordering::Relaxed);
            let net = obs.net_bytes.load(Ordering::Relaxed);
            let debt = core.rewind_debt.load(Ordering::Relaxed);
            assert_eq!(wire, (2 * BLOCK_SIZE + 64 * 1024) as u64);
            assert_eq!(net - debt, payload.len() as u64);
        });
    }
}
