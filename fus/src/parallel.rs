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
use std::ops::{Bound, RangeBounds};
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
    /// Called when `bytes` have been read from the underlying source.
    fn on_bytes(&self, _bytes: u64) {}
    /// Called if `bytes` previously reported to `on_bytes` were discarded on task re-queue.
    fn on_rewind(&self, _bytes: u64) {}
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
        let (min_size, max_size) = self.inner.size_bounds();
        if max_size == 0 || start >= max_size {
            return empty_reader();
        }

        let effective_end = end.map_or(max_size, |e| e.min(max_size));
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
            min_size,
            open_end: end.is_none(),
            observer: Arc::clone(&self.observer),
            window_blocks,
            max_pooled_bufs,
            delivered_blk: AtomicU64::new(0),
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
    fn size_bounds(&self) -> (u64, u64) {
        self.inner.size_bounds()
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
pub(crate) struct ParallelReader {
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
            wake_all_workers(&mut state);
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
                recycle_block(core, cur.buf);
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
                    wake_all_workers(&mut state);
                    Step::Err(err)
                } else if let Some(blk) = state.ready_queue.pop_front() {
                    Step::Ready(blk)
                } else if state.next_deliver_blk >= state.total_blks
                    && state.in_flight_tasks == 0
                    && state.retry_queue.is_empty()
                {
                    state.aborted = true;
                    state.reader_waker = None;
                    wake_all_workers(&mut state);
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
                        recycle_block(&core, blk.buf);
                        continue;
                    }
                    let n = blk.len.min(buf.len());
                    buf[..n].copy_from_slice(&blk.buf[..n]);
                    if n == blk.len {
                        recycle_block(&core, blk.buf);
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
    min_size: u64,
    open_end: bool,
    observer: Arc<dyn TransferObserver>,
    window_blocks: u64,
    max_pooled_bufs: usize,
    delivered_blk: AtomicU64,
    state: Mutex<State>,
}

enum Claim {
    Task(TaskRange),
    Wait,
    Done,
}

fn wake_one_worker(state: &mut State) {
    for slot in &mut state.worker_wakers {
        if let Some(w) = slot.take() {
            w.wake();
            break;
        }
    }
}

fn wake_all_workers(state: &mut State) {
    for slot in &mut state.worker_wakers {
        if let Some(w) = slot.take() {
            w.wake();
        }
    }
}

fn wake_reader(state: &mut State) {
    if let Some(w) = state.reader_waker.take() {
        w.wake();
    }
}

fn pool_buf(state: &mut State, max_pooled_bufs: usize, buf: Vec<u8>) {
    if buf.capacity() >= BLOCK_SIZE && state.buf_pool.len() < max_pooled_bufs {
        state.buf_pool.push(buf);
    }
}

fn recycle_block(core: &SharedCore, buf: Vec<u8>) {
    let mut state = core.state.lock().unwrap();
    state.consumed_blk += 1;
    pool_buf(&mut state, core.max_pooled_bufs, buf);
    wake_one_worker(&mut state);
}

fn claim_task(core: &SharedCore, state: &mut State, worker_id: usize) -> Claim {
    if state.aborted || state.error.is_some() {
        return Claim::Done;
    }

    // Priority 1: Re-queued tasks already reside inside the active window.
    if let Some(task) = state.retry_queue.pop_front() {
        state.active_slots[worker_id] = Some(ActiveSlot {
            curr_blk: task.start_blk,
            end_blk: task.end_blk,
        });
        state.in_flight_tasks += 1;
        return Claim::Task(task);
    }

    // Priority 2: Sequential dispatch of full-sized chunks within the sliding window
    // anchored at `consumed_blk` (never fragmenting into 1-block crumbs).
    if state.next_dispatch_blk < state.total_blks {
        let rem_blks = state.total_blks - state.next_dispatch_blk;
        let active_concurrency = state.live.max(1) as u64;
        let step = rem_blks
            .div_ceil(active_concurrency)
            .clamp(1, TARGET_TASK_BLOCKS);
        let in_window = state.next_dispatch_blk - state.consumed_blk;
        let avail_in_window = core.window_blocks.saturating_sub(in_window);

        if avail_in_window >= step || avail_in_window >= rem_blks {
            let count = step.min(rem_blks);
            let start_blk = state.next_dispatch_blk;
            let end_blk = start_blk + count;
            state.next_dispatch_blk = end_blk;
            state.active_slots[worker_id] = Some(ActiveSlot {
                curr_blk: start_blk,
                end_blk,
            });
            state.in_flight_tasks += 1;
            return Claim::Task(TaskRange { start_blk, end_blk });
        }
    }

    // Priority 3: Work-stealing & head-of-line hedging. Splitting an active HTTP/1.1
    // range drops its reader before `Content-Length` EOF, forcing the transport to close
    // that warm TCP socket. Therefore, only steal or hedge during:
    //   (a) Endgame (`next_dispatch_blk >= total_blks`), or
    //   (b) A genuine head-of-line straggler (`curr_blk == next_deliver_blk`) that has
    //       idled at least half of the live worker pool.
    let consumer_has_room = (state.next_deliver_blk - state.consumed_blk) < core.window_blocks;
    let is_endgame = state.next_dispatch_blk >= state.total_blks;
    let hol_stalled = state.in_flight_tasks <= (state.live / 2).max(1);
    if consumer_has_room && (is_endgame || hol_stalled) {
        let next_deliver = state.next_deliver_blk;
        let victim = state
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
            state.active_slots[worker_id] = Some(ActiveSlot {
                curr_blk: steal_start,
                end_blk: steal_end,
            });
            state.in_flight_tasks += 1;
            return Claim::Task(TaskRange {
                start_blk: steal_start,
                end_blk: steal_end,
            });
        }

        // Speculative backup read (hedge) if the single head-of-line block `next_deliver`
        // has no unstarted tail left to split and is still stalling half the worker pool.
        if state.hedged_blk != Some(next_deliver)
            && state
                .active_slots
                .iter()
                .flatten()
                .any(|s| s.curr_blk == next_deliver && s.end_blk == next_deliver + 1)
        {
            state.hedged_blk = Some(next_deliver);
            state.active_slots[worker_id] = Some(ActiveSlot {
                curr_blk: next_deliver,
                end_blk: next_deliver + 1,
            });
            state.in_flight_tasks += 1;
            return Claim::Task(TaskRange {
                start_blk: next_deliver,
                end_blk: next_deliver + 1,
            });
        }
    }

    if state.next_dispatch_blk >= state.total_blks
        && state.in_flight_tasks == 0
        && state.retry_queue.is_empty()
    {
        Claim::Done
    } else {
        Claim::Wait
    }
}

async fn next_task(core: &SharedCore, worker_id: usize) -> Option<TaskRange> {
    poll_fn(|cx| {
        let mut state = core.state.lock().unwrap();
        match claim_task(core, &mut state, worker_id) {
            Claim::Task(task) => {
                state.worker_wakers[worker_id] = None;
                wake_one_worker(&mut state);
                Poll::Ready(Some(task))
            }
            Claim::Done => {
                state.live = state.live.saturating_sub(1);
                state.worker_wakers[worker_id] = None;
                wake_all_workers(&mut state);
                if state.live == 0 {
                    wake_reader(&mut state);
                }
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

fn take_buf(core: &SharedCore, needed_len: usize) -> Vec<u8> {
    if let Some(mut buf) = core.state.lock().unwrap().buf_pool.pop() {
        if buf.len() < needed_len {
            buf.resize(needed_len, 0);
        }
        return buf;
    }
    vec![0u8; needed_len]
}

fn abort_worker_locked(
    core: &SharedCore,
    state: &mut State,
    worker_id: usize,
    buf: &mut Option<Vec<u8>>,
) {
    if let Some(b) = buf.take() {
        pool_buf(state, core.max_pooled_bufs, b);
    }
    if state.active_slots[worker_id].take().is_some() {
        state.in_flight_tasks -= 1;
    }
    state.worker_wakers[worker_id] = None;
    state.live = state.live.saturating_sub(1);
    wake_all_workers(state);
    if state.live == 0 {
        wake_reader(state);
    }
}

fn flush_reorder(state: &mut State, delivered_blk: &AtomicU64) {
    let mut advanced = false;
    while let Some((buf, len)) = state.reorder.remove(&state.next_deliver_blk) {
        state.next_deliver_blk += 1;
        advanced = true;
        state.ready_queue.push_back(ReadyBlock { buf, len });
    }
    if advanced {
        delivered_blk.store(state.next_deliver_blk, Ordering::Relaxed);
        wake_reader(state);
        wake_one_worker(state);
    }
}

fn finish_worker_slot(state: &mut State, worker_id: usize) {
    if state.active_slots[worker_id].take().is_some() {
        state.in_flight_tasks -= 1;
    }
    if state.next_dispatch_blk >= state.total_blks
        && state.in_flight_tasks == 0
        && state.retry_queue.is_empty()
    {
        wake_all_workers(state);
        wake_reader(state);
    } else {
        wake_one_worker(state);
    }
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
        let mut guard = core.state.lock().unwrap();
        let state = &mut *guard;
        if blk_idx < state.next_deliver_blk || state.reorder.contains_key(&blk_idx) {
            pool_buf(state, core.max_pooled_bufs, buf);
            duplicate_bytes = len as u64;
        } else {
            state.committed_blks += 1;
            state.reorder.insert(blk_idx, (buf, len));
            flush_reorder(state, &core.delivered_blk);
        }

        let slot = state.active_slots[worker_id]
            .as_mut()
            .expect("worker committing block owns active slot");
        let next_blk = blk_idx + 1;
        if next_blk >= slot.end_blk {
            finish_worker_slot(state, worker_id);
            true
        } else {
            slot.curr_blk = next_blk;
            false
        }
    };
    if duplicate_bytes > 0 {
        core.observer.on_rewind(duplicate_bytes);
    }
    done
}

fn commit_slack_eof(
    core: &SharedCore,
    worker_id: usize,
    curr_blk: u64,
    buf: Vec<u8>,
    partial_len: usize,
) {
    let mut duplicate_bytes = 0u64;
    {
        let mut guard = core.state.lock().unwrap();
        let state = &mut *guard;
        let slot = state.active_slots[worker_id]
            .take()
            .expect("worker committing slack EOF owns active slot");
        state.in_flight_tasks -= 1;

        if curr_blk < state.next_deliver_blk || state.reorder.contains_key(&curr_blk) {
            pool_buf(state, core.max_pooled_bufs, buf);
            duplicate_bytes = partial_len as u64;
        } else {
            state.committed_blks += 1;
            if partial_len > 0 {
                state.reorder.insert(curr_blk, (buf, partial_len));
            } else {
                pool_buf(state, core.max_pooled_bufs, buf);
                state.reorder.insert(curr_blk, (Vec::new(), 0));
            }
        }
        for blk in (curr_blk + 1)..slot.end_blk {
            if blk >= state.next_deliver_blk {
                state.reorder.entry(blk).or_insert((Vec::new(), 0));
            }
        }
        let min_eof_blks = curr_blk + u64::from(partial_len > 0);
        state.total_blks = state
            .total_blks
            .min(min_eof_blks.max(state.next_dispatch_blk));
        flush_reorder(state, &core.delivered_blk);
        wake_all_workers(state);
        wake_reader(state);
    }
    if duplicate_bytes > 0 {
        core.observer.on_rewind(duplicate_bytes);
    }
}

struct WorkerGuard<'a> {
    core: &'a SharedCore,
    worker_id: usize,
    disarmed: bool,
}

impl Drop for WorkerGuard<'_> {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
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
        state.worker_wakers[self.worker_id] = None;
        state.live = state.live.saturating_sub(1);
        wake_all_workers(&mut state);
        if state.live == 0 {
            wake_reader(&mut state);
        }
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
        disarmed: false,
    };

    if worker_id > 0 {
        sleep(stagger_delay(worker_id)).await;
    }

    let mut last_committed = 0u64;
    let mut dead_stalls = 0u32;

    while let Some(task) = next_task(&core, worker_id).await {
        let mut curr_blk = task.start_blk;
        let first_blk_start = core.base_offset + curr_blk * BLOCK_SIZE as u64;
        let first_expected_len =
            (core.effective_end - first_blk_start).min(BLOCK_SIZE as u64) as usize;
        let mut buf = Some(take_buf(&core, first_expected_len));
        let mut partial_len = 0usize;
        let mut retries = 0u32;

        loop {
            let current_end_blk = {
                let mut state = core.state.lock().unwrap();
                if state.aborted || state.error.is_some() {
                    guard.disarmed = true;
                    abort_worker_locked(&core, &mut state, worker_id, &mut buf);
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
            let is_open_eof = core.open_end && task_byte_end == core.effective_end;
            let range_end = (!is_open_eof).then_some(task_byte_end);

            let curr_blk_byte_start = core.base_offset + curr_blk * BLOCK_SIZE as u64;
            let fetch_pos = curr_blk_byte_start + partial_len as u64;
            let resume_from = fetch_pos;

            let sub_range = match range_end {
                Some(end) => (Bound::Included(fetch_pos), Bound::Excluded(end)),
                None => (Bound::Included(fetch_pos), Bound::Unbounded),
            };

            let outcome = match source.fetch_range(sub_range).await {
                Ok(mut reader) => loop {
                    let blk_start = core.base_offset + curr_blk * BLOCK_SIZE as u64;
                    let expected_blk_len =
                        (core.effective_end - blk_start).min(BLOCK_SIZE as u64) as usize;
                    let active_buf = buf.as_mut().expect("active block buffer");

                    match reader
                        .read(&mut active_buf[partial_len..expected_blk_len])
                        .await
                    {
                        Ok(0) => {
                            let curr_pos = blk_start + partial_len as u64;
                            if core.effective_end > core.min_size && curr_pos >= core.min_size {
                                commit_slack_eof(
                                    &core,
                                    worker_id,
                                    curr_blk,
                                    buf.take().unwrap(),
                                    partial_len,
                                );
                                break RunOutcome::SlotFinished;
                            }
                            break RunOutcome::Stalled(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "premature EOF while reading chunk",
                            ));
                        }
                        Ok(n) => {
                            partial_len += n;
                            core.observer.on_bytes(n as u64);

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
                                curr_blk += 1;
                                partial_len = 0;
                                if finished_slot {
                                    break RunOutcome::SlotFinished;
                                }
                                let next_blk_start =
                                    core.base_offset + curr_blk * BLOCK_SIZE as u64;
                                let next_expected_len = (core.effective_end - next_blk_start)
                                    .min(BLOCK_SIZE as u64)
                                    as usize;
                                buf = Some(take_buf(&core, next_expected_len));
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
                    if partial_len > 0 {
                        core.observer.on_rewind(partial_len as u64);
                    }
                    let mut state = core.state.lock().unwrap();
                    if let Some(b) = buf.take() {
                        pool_buf(&mut state, core.max_pooled_bufs, b);
                    }
                    finish_worker_slot(&mut state, worker_id);
                    dead_stalls = 0;
                    break;
                }
                RunOutcome::Stalled(err) => err,
            };

            let curr_blk_byte_start = core.base_offset + curr_blk * BLOCK_SIZE as u64;
            let curr_pos = curr_blk_byte_start + partial_len as u64;
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

        // Only reached when `retries > MAX_STALL_RETRIES` (task stalled).
        if retries > MAX_STALL_RETRIES {
            let curr_pos = core.base_offset + curr_blk * BLOCK_SIZE as u64 + partial_len as u64;
            if partial_len > 0 {
                core.observer.on_rewind(partial_len as u64);
            }

            let mut state = core.state.lock().unwrap();
            if let Some(b) = buf.take() {
                pool_buf(&mut state, core.max_pooled_bufs, b);
            }
            let slot = state.active_slots[worker_id]
                .take()
                .expect("stalled worker owns active slot");
            state.in_flight_tasks -= 1;
            state.worker_wakers[worker_id] = None;

            if state.aborted || state.error.is_some() {
                guard.disarmed = true;
                state.live = state.live.saturating_sub(1);
                wake_all_workers(&mut state);
                if state.live == 0 {
                    wake_reader(&mut state);
                }
                return;
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
                guard.disarmed = true;
                state.live -= 1;
                let remaining = state.live;
                wake_all_workers(&mut state);
                drop(state);
                core.observer.on_warning(TransferWarning::Throttled {
                    offset: curr_pos,
                    remaining_connections: remaining,
                });
                return;
            }

            if state.committed_blks > last_committed {
                last_committed = state.committed_blks;
                dead_stalls = 0;
                wake_all_workers(&mut state);
            } else {
                dead_stalls += 1;
                if dead_stalls > MAX_DEAD_STALLS {
                    guard.disarmed = true;
                    if state.error.is_none() {
                        state.error = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "download stalled at offset {curr_pos}: server stopped responding"
                            ),
                        ));
                    }
                    state.live = 0;
                    wake_all_workers(&mut state);
                    wake_reader(&mut state);
                    return;
                }
                wake_all_workers(&mut state);
            }
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
        SlowFirstWorker,
        InitialFails(usize),
        StuckAtOffset(usize),
        AlwaysFail,
    }

    type ResolvedRange = Option<(u64, Option<u64>)>;

    struct ChaosSource {
        data: Vec<u8>,
        bounds: (u64, u64),
        mode: ChaosMode,
        requests: Arc<Mutex<Vec<ResolvedRange>>>,
        req_count: AtomicUsize,
    }

    impl ChaosSource {
        fn exact(data: Vec<u8>, mode: ChaosMode) -> Self {
            let len = data.len() as u64;
            Self::with_bounds(data, (len, len), mode)
        }

        fn with_bounds(data: Vec<u8>, bounds: (u64, u64), mode: ChaosMode) -> Self {
            Self {
                data,
                bounds,
                mode,
                requests: Arc::new(Mutex::new(Vec::new())),
                req_count: AtomicUsize::new(0),
            }
        }
    }

    impl DataSource for ChaosSource {
        fn size_bounds(&self) -> (u64, u64) {
            self.bounds
        }

        async fn fetch_range(
            &self,
            range: impl RangeBounds<u64> + Send,
        ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
            let resolved = resolve_range_bounds(range);
            self.requests.lock().unwrap().push(resolved);
            let idx = self.req_count.fetch_add(1, Ordering::Relaxed);

            match self.mode {
                ChaosMode::Clean | ChaosMode::SlowFirstWorker | ChaosMode::StuckAtOffset(_) => {}
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
            let slice = match resolved {
                Some((start, end)) if start < len => {
                    let s = start as usize;
                    let e = end.map_or(self.data.len(), |e| e.min(len) as usize);
                    self.data[s..e].to_vec()
                }
                _ => Vec::new(),
            };

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
        bytes: AtomicU64,
        rewinds: AtomicU64,
        warnings: AtomicUsize,
        throttled: AtomicUsize,
    }

    impl RecordingObserver {
        fn new() -> Self {
            Self {
                bytes: AtomicU64::new(0),
                rewinds: AtomicU64::new(0),
                warnings: AtomicUsize::new(0),
                throttled: AtomicUsize::new(0),
            }
        }
    }

    impl TransferObserver for RecordingObserver {
        fn on_bytes(&self, bytes: u64) {
            self.bytes.fetch_add(bytes, Ordering::Relaxed);
        }

        fn on_rewind(&self, bytes: u64) {
            self.rewinds.fetch_add(bytes, Ordering::Relaxed);
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
        let src = ChaosSource::with_bounds(
            payload.clone(),
            (payload.len() as u64, payload.len() as u64 + 16),
            ChaosMode::Clean,
        );
        let reqs = Arc::clone(&src.requests);
        let parallel = ParallelDataSource::new(src, 4);
        assert_eq!(
            parallel.size_bounds(),
            (payload.len() as u64, payload.len() as u64 + 16)
        );

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
                .fetch_range((payload.len() as u64 + 16)..)
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
    fn test_slack_eof_single_and_multi_block_bounds() {
        // Case A: Actual len sits inside [min_size, max_size] (like PKCS#7 tail)
        let payload: Vec<u8> = (0..1000_usize).map(|i| (i as u8).wrapping_mul(3)).collect();
        let src = ChaosSource::with_bounds(payload.clone(), (990, 1006), ChaosMode::Clean);
        let parallel = ParallelDataSource::new(src, 4);

        block_on(async {
            // Read straddling actual EOF (1000) within bounds (990..=1006)
            let mut tail = [0u8; 32];
            assert_eq!(parallel.read_at(&mut tail, 989).await.unwrap(), 11);
            assert_eq!(&tail[..11], &payload[989..]);

            // Read starting at actual EOF (inside slack region [1000..1006)) yields 0
            let mut slack_only = [0u8; 16];
            assert_eq!(parallel.read_at(&mut slack_only, 1000).await.unwrap(), 0);
        });

        // Case B: Actual len == BLOCK_SIZE while max_size == BLOCK_SIZE + 16 (concurrency 1 & 4)
        let exact_block: Vec<u8> = (0..BLOCK_SIZE).map(|i| (i % 239) as u8).collect();
        for concurrency in [1, 4] {
            let edge_src = ChaosSource::with_bounds(
                exact_block.clone(),
                (BLOCK_SIZE as u64, BLOCK_SIZE as u64 + 16),
                ChaosMode::Clean,
            );
            let edge_parallel = ParallelDataSource::new(edge_src, concurrency);
            let mut slice = vec![0u8; BLOCK_SIZE + 16];
            let n = block_on(edge_parallel.read_at(&mut slice, 10)).unwrap();
            assert_eq!(n, BLOCK_SIZE - 10, "concurrency={concurrency}");
            assert_eq!(&slice[..n], &exact_block[10..]);
        }

        // Case C: Wide slack spanning multiple 2 MiB blocks across multiple workers
        let short_data: Vec<u8> = (0..150_u8).collect();
        let wide_src = ChaosSource::with_bounds(
            short_data.clone(),
            (100, 3 * BLOCK_SIZE as u64 + 500),
            ChaosMode::Clean,
        );
        let wide_parallel = ParallelDataSource::new(wide_src, 4);
        block_on(async {
            let mut out = Vec::new();
            wide_parallel
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(out, short_data);
        });
    }

    #[test]
    fn test_chaos_multichunk_streaming_and_buffer_recycling() {
        let payload: Vec<u8> = (0..(5 * 1024 * 1024 + 123))
            .map(|i| ((i * 7) % 251) as u8)
            .collect();
        let src = ChaosSource::with_bounds(
            payload.clone(),
            (payload.len() as u64 - 5, payload.len() as u64 + 11),
            ChaosMode::Flaky,
        );
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
            let net =
                observer.bytes.load(Ordering::Relaxed) - observer.rewinds.load(Ordering::Relaxed);
            assert_eq!(net, payload.len() as u64);

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
            let mut out = Vec::new();
            parallel
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(out, payload);
            // More than 4 requests prove fast workers stole/hedged blocks from slow Worker 0
            assert!(reqs.lock().unwrap().len() > 4);
            let net = obs.bytes.load(Ordering::Relaxed) - obs.rewinds.load(Ordering::Relaxed);
            assert_eq!(net, payload.len() as u64);
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
                fn size_bounds(&self) -> (u64, u64) {
                    (BLOCK_SIZE as u64, BLOCK_SIZE as u64)
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
        let stuck_err = block_on(async {
            stuck_parallel
                .fetch()
                .await?
                .read_to_end(&mut stuck_out)
                .await
        })
        .unwrap_err();
        assert_eq!(stuck_err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            partial_obs.bytes.load(Ordering::Relaxed),
            partial_obs.rewinds.load(Ordering::Relaxed)
        );

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
}
