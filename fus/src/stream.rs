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

//! Resumable sequential streaming abstractions: [`Checkpoint`], [`ResumableAsyncRead`],
//! [`ResumableStream`], [`OffsetCheckpoint`], and [`DataStream`].

use crate::compat::{MaybeSend, MaybeSync};
use crate::data::DataSource;
use futures::io::AsyncRead;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

/// Polls `reader.poll_read(cx, buf)`, automatically retrying `ErrorKind::Interrupted`.
pub(crate) fn poll_read_retry_eintr<R: AsyncRead + Unpin>(
    reader: &mut R,
    cx: &mut Context<'_>,
    buf: &mut [u8],
) -> Poll<io::Result<usize>> {
    loop {
        match Pin::new(&mut *reader).poll_read(cx, buf) {
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

/// Mid-stream resume checkpoint emitted by a [`ResumableAsyncRead`].
pub trait Checkpoint: MaybeSend + MaybeSync {
    /// Consumed byte offset in the underlying (possibly compressed) source stream.
    fn source_offset(&self) -> u64;

    /// Produced byte offset in the output (decompressed) stream.
    fn output_offset(&self) -> u64;
}

/// Async streaming reader that verifies stream integrity and tracks mid-stream
/// [`Checkpoint`]s for resumption.
///
/// Consumed through standard [`AsyncRead`] (`read`, `copy`, `read_to_end`, etc.),
/// while [`checkpoint`](Self::checkpoint) exposes the latest resumable checkpoint
/// whose output bytes have already been delivered to the caller.
pub trait ResumableAsyncRead: AsyncRead + MaybeSend + Unpin {
    /// Resumable checkpoint type emitted by this reader.
    type Checkpoint: Checkpoint;

    /// Returns the most recent resumable [`Checkpoint`] whose output bytes in
    /// `[0..cp.output_offset())` have all been delivered by prior reads, or `None`
    /// if no mid-stream checkpoint boundary has been reached yet (or the stream has
    /// ended or encountered a fatal integrity error).
    fn checkpoint(&self) -> Option<Self::Checkpoint>;
}

/// Resumable, checkpointable sequential stream.
///
/// Implemented by [`DataStream`] (wrapping any random-access [`DataSource`] with
/// [`OffsetCheckpoint`]) and [`ZipEntrySession`](crate::ZipEntrySession) (streaming
/// decompressed, CRC-verified archive entries with [`ZipCheckpoint`](crate::ZipCheckpoint)).
pub trait ResumableStream: MaybeSend + MaybeSync {
    /// Mid-stream checkpoint type for this stream.
    type Checkpoint: Checkpoint;

    /// Exact byte length of the output stream.
    fn output_size(&self) -> u64;

    /// Total byte length of the underlying (possibly compressed) source stream.
    fn source_size(&self) -> u64;

    /// Validates that `checkpoint` is a resumable mid-stream position for this stream
    /// and returns the number of trailing output bytes (ending at `checkpoint.output_offset()`)
    /// required as the resume dictionary for [`resume`](Self::resume).
    ///
    /// Returns `None` if `checkpoint` is at the start/end, out of bounds, or incompatible
    /// with this stream. When `Some(dict_len)` is returned, callers can rely on
    /// `0 < checkpoint.source_offset()`, `checkpoint.output_offset() < self.output_size()`,
    /// and `dict_len as u64 <= checkpoint.output_offset()`.
    fn resume_dict_len(&self, checkpoint: &Self::Checkpoint) -> Option<usize>;

    /// Opens a checkpointable reader starting from the beginning of the stream.
    fn open(
        &self,
    ) -> impl Future<Output = io::Result<impl ResumableAsyncRead<Checkpoint = Self::Checkpoint>>>
    + MaybeSend;

    /// Resumes streaming from `checkpoint`.
    ///
    /// `dict` must contain at least `self.resume_dict_len(checkpoint)` trailing
    /// output bytes ending at `checkpoint.output_offset()`.
    fn resume<'a>(
        &'a self,
        checkpoint: &Self::Checkpoint,
        dict: &[u8],
    ) -> impl Future<
        Output = io::Result<impl ResumableAsyncRead<Checkpoint = Self::Checkpoint> + use<'a, Self>>,
    > + MaybeSend;
}

/// Offset-only [`Checkpoint`] for [`DataStream`] transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetCheckpoint {
    offset: u64,
}

impl OffsetCheckpoint {
    /// Creates an offset-only checkpoint at byte `offset`.
    pub const fn new(offset: u64) -> Self {
        Self { offset }
    }

    /// Serializes this checkpoint as an 8-byte little-endian offset.
    pub fn write_to(&self, writer: &mut impl io::Write) -> io::Result<()> {
        writer.write_all(&self.offset.to_le_bytes())
    }

    /// Deserializes a non-zero checkpoint previously written by [`write_to`](Self::write_to).
    pub fn read_from(reader: &mut impl io::Read) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        let offset = u64::from_le_bytes(buf);
        if offset == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "offset checkpoint must be non-zero",
            ));
        }
        Ok(Self { offset })
    }
}

impl Checkpoint for OffsetCheckpoint {
    fn source_offset(&self) -> u64 {
        self.offset
    }

    fn output_offset(&self) -> u64 {
        self.offset
    }
}

struct OffsetResumableReader<R> {
    reader: R,
    size: u64,
    offset: u64,
    eof: bool,
}

impl<R> OffsetResumableReader<R> {
    const fn new(reader: R, size: u64, offset: u64) -> Self {
        Self {
            reader,
            size,
            offset,
            eof: false,
        }
    }
}

impl<R: AsyncRead + MaybeSend + Unpin> ResumableAsyncRead for OffsetResumableReader<R> {
    type Checkpoint = OffsetCheckpoint;

    fn checkpoint(&self) -> Option<OffsetCheckpoint> {
        (!self.eof && self.offset > 0 && self.offset < self.size)
            .then_some(OffsetCheckpoint::new(self.offset))
    }
}

impl<R: AsyncRead + MaybeSend + Unpin> AsyncRead for OffsetResumableReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() || self.eof {
            return Poll::Ready(Ok(0));
        }

        let n = ready!(poll_read_retry_eintr(&mut self.reader, cx, buf))?;

        if n == 0 {
            self.eof = true;
            if self.offset < self.size {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "incomplete stream: expected {} bytes, got {}",
                        self.size, self.offset
                    ),
                )));
            }
            return Poll::Ready(Ok(0));
        }

        let Some(end) = self
            .offset
            .checked_add(n as u64)
            .filter(|&end| end <= self.size)
        else {
            self.eof = true;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("stream exceeded expected size ({} bytes)", self.size),
            )));
        };

        self.offset = end;
        Poll::Ready(Ok(n))
    }
}

/// Adapter exposing any random-access [`DataSource`] as a [`ResumableStream`]
/// with [`OffsetCheckpoint`]s.
#[derive(Debug, Clone)]
pub struct DataStream<S: DataSource>(S);

impl<S: DataSource> DataStream<S> {
    /// Wraps `source` as a checkpointable sequential stream.
    pub const fn new(source: S) -> Self {
        Self(source)
    }

    /// Consumes this adapter and returns the underlying [`DataSource`].
    pub fn into_inner(self) -> S {
        self.0
    }
}

impl<S: DataSource> ResumableStream for DataStream<S> {
    type Checkpoint = OffsetCheckpoint;

    fn output_size(&self) -> u64 {
        self.0.size()
    }

    fn source_size(&self) -> u64 {
        self.0.size()
    }

    fn resume_dict_len(&self, checkpoint: &OffsetCheckpoint) -> Option<usize> {
        (checkpoint.offset > 0 && checkpoint.offset < self.0.size()).then_some(0)
    }

    async fn open(&self) -> io::Result<impl ResumableAsyncRead<Checkpoint = OffsetCheckpoint>> {
        let size = self.0.size();
        let reader = self.0.fetch_range(..).await?;
        Ok(OffsetResumableReader::new(reader, size, 0))
    }

    async fn resume<'a>(
        &'a self,
        checkpoint: &OffsetCheckpoint,
        _dict: &[u8],
    ) -> io::Result<impl ResumableAsyncRead<Checkpoint = OffsetCheckpoint> + use<'a, S>> {
        if self.resume_dict_len(checkpoint).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid or out-of-bounds offset checkpoint",
            ));
        }
        let size = self.0.size();
        let reader = self.0.fetch_range(checkpoint.offset..).await?;
        Ok(OffsetResumableReader::new(reader, size, checkpoint.offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::io::{AsyncReadExt, Cursor};

    #[test]
    fn test_offset_checkpoint_wire_round_trip() {
        let cp = OffsetCheckpoint::new(2048);
        let mut bytes = Vec::new();
        cp.write_to(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 8);
        let decoded = OffsetCheckpoint::read_from(&mut io::Cursor::new(&bytes)).unwrap();
        assert_eq!(decoded, cp);
        assert_eq!(decoded.source_offset(), 2048);
        assert_eq!(decoded.output_offset(), 2048);

        // Zero offset and truncated input must be rejected
        assert_eq!(
            OffsetCheckpoint::read_from(&mut io::Cursor::new(&[0u8; 8]))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            OffsetCheckpoint::read_from(&mut io::Cursor::new(&[1u8; 7]))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn test_data_stream_resume_and_errors() {
        let payload: Vec<u8> = (0..4096).map(|i| ((i * 31) ^ (i >> 7)) as u8).collect();
        let stream = DataStream::new(payload.as_slice());
        assert_eq!(stream.output_size(), 4096);
        assert_eq!(stream.source_size(), 4096);

        block_on(async {
            let mut r = stream.open().await.unwrap();
            assert_eq!(r.checkpoint(), None);
            let mut head = vec![0u8; 1000];
            let n = r.read(&mut head).await.unwrap();
            let cp = r.checkpoint().unwrap();
            assert_eq!(n, 1000);
            assert_eq!(cp.source_offset(), 1000);
            assert_eq!(cp.output_offset(), 1000);
            assert_eq!(stream.resume_dict_len(&cp), Some(0));
            assert_eq!(stream.resume_dict_len(&OffsetCheckpoint::new(0)), None);
            assert_eq!(stream.resume_dict_len(&OffsetCheckpoint::new(4096)), None);
            assert_eq!(stream.resume_dict_len(&OffsetCheckpoint::new(4097)), None);

            // Returned reader does not borrow the checkpoint or dictionary past `.await`.
            let mut resumed_reader = {
                let dict = Vec::new();
                stream.resume(&cp, &dict).await.unwrap()
            };
            let mut resumed = head;
            resumed_reader.read_to_end(&mut resumed).await.unwrap();
            assert_eq!(resumed, payload);

            // Resuming at 0 or EOF is rejected with InvalidInput
            for bad in [0, 4096, 4097] {
                let err = stream
                    .resume(&OffsetCheckpoint::new(bad), &[])
                    .await
                    .err()
                    .unwrap();
                assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            }

            // Reading the final byte suppresses checkpoint() before EOF is polled
            let mut full_reader = stream.open().await.unwrap();
            let mut all = vec![0u8; 4096];
            full_reader.read_exact(&mut all).await.unwrap();
            assert_eq!(full_reader.checkpoint(), None);
            assert_eq!(full_reader.read(&mut [0u8; 8]).await.unwrap(), 0);

            // OffsetResumableReader overflow & premature EOF checks
            let mut over = OffsetResumableReader::new(Cursor::new(payload[..120].to_vec()), 100, 0);
            let mut scratch = Vec::new();
            assert_eq!(
                over.read_to_end(&mut scratch).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );

            let mut short =
                OffsetResumableReader::new(Cursor::new(payload[..150].to_vec()), 200, 0);
            scratch.clear();
            assert_eq!(
                short.read_to_end(&mut scratch).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        });
    }
}
