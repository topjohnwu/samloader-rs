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

//! Shared resumable checkpoint validation and coalesced stream transfer engine.

use crate::checkpoint::{CheckpointMeta, CheckpointState};
use crate::compat::MaybeSend;
use crate::stream::{Checkpoint, ResumableAsyncRead, ResumableStream};
use futures::future::{Either, select};
use futures::io::AsyncReadExt;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::pin;

/// Validates persisted `SAMLOADR` checkpoint metadata against `checksum`,
/// `existing_len`, and `source`, returning the typed checkpoint and required
/// trailing output dictionary length if resumption is valid.
pub fn validate_resume_checkpoint<S: ResumableStream>(
    meta_bytes: &[u8],
    checksum: [u8; 16],
    existing_len: u64,
    source: &S,
) -> Option<(S::Checkpoint, usize)>
where
    S::Checkpoint: TryFrom<CheckpointState>,
{
    let target_size = source.output_size();
    let meta = CheckpointMeta::from_bytes(meta_bytes, checksum, target_size)?;
    let cp = S::Checkpoint::try_from(meta.state).ok()?;
    let dict_len = source.resume_dict_len(&cp)?;
    let out = cp.output_offset();
    (cp.source_offset() > 0 && out < target_size && out <= existing_len && (dict_len as u64) <= out)
        .then_some((cp, dict_len))
}

/// Tuning parameters for [`write_resumable_stream`].
#[derive(Debug, Clone, Copy)]
pub struct TransferConfig {
    /// Maximum in-memory write coalescing buffer size in bytes.
    pub write_buf_size: usize,
    /// Minimum output byte interval between periodic checkpoints.
    pub checkpoint_interval: u64,
    /// Maximum elapsed milliseconds before flushing buffered writes.
    pub coalesce_max_wait_ms: f64,
    /// Optional maximum elapsed milliseconds before persisting an available checkpoint.
    pub checkpoint_max_wait_ms: Option<f64>,
}

/// Destination sink for [`write_resumable_stream`].
pub trait PartSink: MaybeSend {
    /// Current monotonic or wall-clock timestamp in milliseconds.
    fn now_ms(&self) -> f64;

    /// Writes `data` at `offset` in the partial output file.
    fn write(
        &mut self,
        offset: u64,
        data: &[u8],
    ) -> impl Future<Output = io::Result<()>> + MaybeSend;

    /// Persists a serialized `SAMLOADR` checkpoint sidecar after data writes are flushed.
    fn save_checkpoint(
        &mut self,
        meta_bytes: &[u8],
    ) -> impl Future<Output = io::Result<()>> + MaybeSend;
}

/// Failure returned by [`write_resumable_stream`].
#[derive(Debug)]
pub enum TransferError {
    /// Transfer was interrupted by the caller's cancellation future.
    Cancelled,
    /// Underlying stream or sink I/O failure.
    Io(io::Error),
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("transfer cancelled"),
            Self::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for TransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cancelled => None,
            Self::Io(e) => Some(e),
        }
    }
}

impl From<io::Error> for TransferError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

fn elapsed_at_least(now_ms: f64, last_ms: f64, threshold_ms: f64) -> bool {
    now_ms < last_ms || (now_ms - last_ms) >= threshold_ms
}

async fn flush_buf<S: PartSink>(
    sink: &mut S,
    buf: &[u8],
    filled: &mut usize,
    write_pos: &mut u64,
) -> io::Result<()> {
    let n = *filled;
    if n == 0 {
        return Ok(());
    }
    *filled = 0;
    sink.write(*write_pos, &buf[..n]).await?;
    *write_pos += n as u64;
    Ok(())
}

/// Streams `reader` into `sink` starting at `start_pos`, coalescing writes,
/// persisting periodic `SAMLOADR` checkpoints, and validating exact `target_size`.
pub async fn write_resumable_stream<R, S, C>(
    mut reader: R,
    sink: &mut S,
    start_pos: u64,
    target_size: u64,
    checksum: [u8; 16],
    config: &TransferConfig,
    cancel: C,
) -> Result<(), TransferError>
where
    R: ResumableAsyncRead,
    R::Checkpoint: Into<CheckpointState>,
    S: PartSink,
    C: Future<Output = ()>,
{
    let remaining = target_size.saturating_sub(start_pos);
    // Keep `buf_size >= 1` so `reader.read` still polls EOF/CRC verification
    // even on 0-byte streams or streams already resumed at `target_size`.
    let buf_size = (remaining.min(config.write_buf_size.max(1) as u64) as usize).max(1);
    let mut buf = vec![0u8; buf_size];
    let mut filled = 0usize;
    let mut write_pos = start_pos;
    let mut last_persisted_offset = start_pos;
    let mut latest_cp: Option<R::Checkpoint> = None;
    let min_delta = config.checkpoint_interval.max(1);
    let mut last_flush_ms = sink.now_ms();
    let mut last_checkpoint_ms = last_flush_ms;

    enum ReadStep {
        Cancelled,
        Data(io::Result<usize>),
    }

    let mut cancel = pin!(cancel);

    let (is_cancelled, read_err): (bool, Option<io::Error>) = loop {
        let step = match select(cancel.as_mut(), pin!(reader.read(&mut buf[filled..]))).await {
            Either::Left(((), _)) => ReadStep::Cancelled,
            Either::Right((res, _)) => ReadStep::Data(res),
        };

        match step {
            ReadStep::Cancelled => break (true, None),
            ReadStep::Data(Ok(0)) => {
                drop(reader);
                flush_buf(sink, &buf, &mut filled, &mut write_pos).await?;
                if write_pos != target_size {
                    return Err(TransferError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("incomplete download: wrote {write_pos} of {target_size} bytes"),
                    )));
                }
                return Ok(());
            }
            ReadStep::Data(Ok(n)) => {
                let new_filled = filled + n;
                if write_pos
                    .checked_add(new_filled as u64)
                    .is_none_or(|end| end > target_size)
                {
                    return Err(TransferError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "stream exceeded declared target size",
                    )));
                }
                filled = new_filled;

                if let Some(cp) = reader.checkpoint().filter(|cp| {
                    cp.output_offset() > last_persisted_offset && cp.output_offset() < target_size
                }) {
                    latest_cp = Some(cp);
                }

                let now = sink.now_ms();
                let cp_due = latest_cp.take_if(|cp| {
                    cp.output_offset() >= last_persisted_offset.saturating_add(min_delta)
                        || config.checkpoint_max_wait_ms.is_some_and(|max_wait| {
                            elapsed_at_least(now, last_checkpoint_ms, max_wait)
                        })
                });

                if let Some(cp) = cp_due {
                    let cp_offset = cp.output_offset();
                    flush_buf(sink, &buf, &mut filled, &mut write_pos).await?;
                    let meta_bytes = CheckpointMeta {
                        checksum,
                        target_size,
                        state: cp.into(),
                    }
                    .to_bytes();
                    sink.save_checkpoint(&meta_bytes).await?;
                    last_persisted_offset = cp_offset;
                    let done_ms = sink.now_ms();
                    last_flush_ms = done_ms;
                    last_checkpoint_ms = done_ms;
                } else if filled == buf.len()
                    || elapsed_at_least(now, last_flush_ms, config.coalesce_max_wait_ms)
                {
                    flush_buf(sink, &buf, &mut filled, &mut write_pos).await?;
                    last_flush_ms = sink.now_ms();
                }
            }
            ReadStep::Data(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
            ReadStep::Data(Err(e)) => break (false, Some(e)),
        }
    };

    drop(reader);
    let allow_checkpoint = read_err
        .as_ref()
        .is_none_or(|e| e.kind() != io::ErrorKind::InvalidData);
    if allow_checkpoint
        && let Some(cp) = latest_cp.filter(|cp| cp.output_offset() > last_persisted_offset)
        && flush_buf(sink, &buf, &mut filled, &mut write_pos)
            .await
            .is_ok()
    {
        let meta_bytes = CheckpointMeta {
            checksum,
            target_size,
            state: cp.into(),
        }
        .to_bytes();
        let _ = sink.save_checkpoint(&meta_bytes).await;
    }

    if is_cancelled {
        Err(TransferError::Cancelled)
    } else {
        Err(TransferError::Io(read_err.unwrap_or_else(|| {
            io::Error::other("unknown stream error")
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::{DataStream, OffsetCheckpoint};
    use futures::channel::oneshot;
    use futures::executor::block_on;
    use futures::io::AsyncRead;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll};

    const CHECKSUM: [u8; 16] = [0x5A; 16];

    struct MemSink {
        now_ms: Arc<AtomicU64>,
        data: Vec<u8>,
        writes: usize,
        checkpoints: Vec<Vec<u8>>,
    }

    impl MemSink {
        fn new() -> Self {
            Self {
                now_ms: Arc::new(AtomicU64::new(0)),
                data: Vec::new(),
                writes: 0,
                checkpoints: Vec::new(),
            }
        }
    }

    impl PartSink for MemSink {
        fn now_ms(&self) -> f64 {
            self.now_ms.load(Ordering::Relaxed) as f64
        }

        async fn write(&mut self, offset: u64, chunk: &[u8]) -> io::Result<()> {
            self.writes += 1;
            let end = offset as usize + chunk.len();
            if self.data.len() < end {
                self.data.resize(end, 0);
            }
            self.data[offset as usize..end].copy_from_slice(chunk);
            Ok(())
        }

        async fn save_checkpoint(&mut self, meta_bytes: &[u8]) -> io::Result<()> {
            self.checkpoints.push(meta_bytes.to_vec());
            Ok(())
        }
    }

    struct ScriptedReader {
        steps: Vec<io::Result<Vec<u8>>>,
        idx: usize,
        pos: u64,
        target: u64,
        clock: Option<(Arc<AtomicU64>, u64)>,
    }

    impl AsyncRead for ScriptedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if let Some((ref clk, step_ms)) = self.clock {
                clk.fetch_add(step_ms, Ordering::Relaxed);
            }
            if self.idx >= self.steps.len() {
                return Poll::Pending;
            }
            let idx = self.idx;
            self.idx += 1;
            let next = std::mem::replace(&mut self.steps[idx], Ok(Vec::new()));
            match next {
                Ok(chunk) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    self.pos += n as u64;
                    Poll::Ready(Ok(n))
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
    }

    impl ResumableAsyncRead for ScriptedReader {
        type Checkpoint = OffsetCheckpoint;
        fn checkpoint(&self) -> Option<OffsetCheckpoint> {
            (self.pos > 0 && self.pos < self.target).then_some(OffsetCheckpoint::new(self.pos))
        }
    }

    #[test]
    fn test_validate_resume_checkpoint_and_coalescing() {
        let payload: Vec<u8> = (0..64_000).map(|i| (i * 13) as u8).collect();
        let stream = DataStream::new(payload.as_slice());

        let cp = OffsetCheckpoint::new(16_384);
        let meta = CheckpointMeta {
            checksum: CHECKSUM,
            target_size: payload.len() as u64,
            state: CheckpointState::Offset(cp),
        }
        .to_bytes();

        assert_eq!(
            validate_resume_checkpoint(&meta, CHECKSUM, 20_000, &stream),
            Some((cp, 0))
        );
        assert_eq!(
            validate_resume_checkpoint(&meta, CHECKSUM, 16_000, &stream),
            None
        );
        assert_eq!(
            validate_resume_checkpoint(&meta, [0x99; 16], 20_000, &stream),
            None
        );

        let reader = ScriptedReader {
            steps: vec![
                Ok(payload[..16_000].to_vec()),
                Err(io::Error::new(io::ErrorKind::Interrupted, "eintr")),
                Ok(payload[16_000..40_000].to_vec()),
                Ok(payload[40_000..].to_vec()),
                Ok(Vec::new()),
            ],
            idx: 0,
            pos: 0,
            target: payload.len() as u64,
            clock: None,
        };
        let mut sink = MemSink::new();
        let cfg = TransferConfig {
            write_buf_size: 128 * 1024,
            checkpoint_interval: 32 * 1024,
            coalesce_max_wait_ms: 250.0,
            checkpoint_max_wait_ms: None,
        };
        block_on(write_resumable_stream(
            reader,
            &mut sink,
            0,
            payload.len() as u64,
            CHECKSUM,
            &cfg,
            futures::future::pending(),
        ))
        .unwrap();

        assert_eq!(sink.data, payload);
        assert_eq!(sink.checkpoints.len(), 1);
        let parsed =
            CheckpointMeta::from_bytes(&sink.checkpoints[0], CHECKSUM, payload.len() as u64)
                .unwrap();
        assert_eq!(
            parsed.state,
            CheckpointState::Offset(OffsetCheckpoint::new(40_000))
        );
    }

    #[test]
    fn test_time_based_checkpoint_cancel_and_invalid_data() {
        let mut sink = MemSink::new();
        let reader = ScriptedReader {
            steps: vec![
                Ok(vec![1; 1024]),
                Ok(vec![2; 1024]),
                Ok(vec![3; 1024]),
                Ok(Vec::new()),
            ],
            idx: 0,
            pos: 0,
            target: 3072,
            clock: Some((Arc::clone(&sink.now_ms), 600)),
        };
        let cfg = TransferConfig {
            write_buf_size: 64 * 1024,
            checkpoint_interval: 10 * 1024 * 1024,
            coalesce_max_wait_ms: 250.0,
            checkpoint_max_wait_ms: Some(1_000.0),
        };
        block_on(write_resumable_stream(
            reader,
            &mut sink,
            0,
            3072,
            CHECKSUM,
            &cfg,
            futures::future::pending(),
        ))
        .unwrap();
        assert_eq!(sink.data.len(), 3072);
        assert!(!sink.checkpoints.is_empty());

        // Cancel saves latest checkpoint
        let (tx, rx) = oneshot::channel::<()>();
        let mut tx = Some(tx);
        struct CancelAfterFirst {
            tx: Option<oneshot::Sender<()>>,
            pos: u64,
        }
        impl AsyncRead for CancelAfterFirst {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                if self.pos == 0 {
                    let n = 1024.min(buf.len());
                    buf[..n].fill(0xAA);
                    self.pos += n as u64;
                    if let Some(t) = self.tx.take() {
                        let _ = t.send(());
                    }
                    return Poll::Ready(Ok(n));
                }
                Poll::Pending
            }
        }
        impl ResumableAsyncRead for CancelAfterFirst {
            type Checkpoint = OffsetCheckpoint;
            fn checkpoint(&self) -> Option<OffsetCheckpoint> {
                (self.pos > 0 && self.pos < 4096).then_some(OffsetCheckpoint::new(self.pos))
            }
        }
        let mut cancel_sink = MemSink::new();
        let err = block_on(write_resumable_stream(
            CancelAfterFirst {
                tx: tx.take(),
                pos: 0,
            },
            &mut cancel_sink,
            0,
            4096,
            CHECKSUM,
            &cfg,
            async move {
                let _ = rx.await;
            },
        ))
        .unwrap_err();
        assert!(matches!(err, TransferError::Cancelled));
        assert_eq!(cancel_sink.checkpoints.len(), 1);
        assert_eq!(cancel_sink.data, vec![0xAA; 1024]);

        // InvalidData does NOT persist checkpoint
        let bad_reader = ScriptedReader {
            steps: vec![
                Ok(vec![0xBB; 1024]),
                Err(io::Error::new(io::ErrorKind::InvalidData, "bad crc")),
            ],
            idx: 0,
            pos: 0,
            target: 4096,
            clock: None,
        };
        let mut bad_sink = MemSink::new();
        let err = block_on(write_resumable_stream(
            bad_reader,
            &mut bad_sink,
            0,
            4096,
            CHECKSUM,
            &cfg,
            futures::future::pending(),
        ))
        .unwrap_err();
        assert!(matches!(err, TransferError::Io(ref e) if e.kind() == io::ErrorKind::InvalidData));
        assert!(bad_sink.checkpoints.is_empty());
    }
}
