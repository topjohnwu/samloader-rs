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

//! General-purpose resumable sequential streaming abstractions: [`Checkpoint`],
//! [`ResumableAsyncRead`], [`ResumableStream`], and [`OffsetCheckpoint`].

use crate::compat::{MaybeSend, MaybeSync};
use crate::data::DataSource;
use binrw::binrw;
use futures::io::AsyncRead;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

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
/// Implemented automatically for every random-access [`DataSource`] (streaming raw
/// bytes with [`OffsetCheckpoint`]) as well as [`ZipEntrySession`](crate::ZipEntrySession)
/// (streaming decompressed, CRC-verified archive entries with [`ZipCheckpoint`](crate::ZipCheckpoint)).
pub trait ResumableStream: MaybeSend + MaybeSync {
    /// Mid-stream checkpoint type for this stream.
    type Checkpoint: Checkpoint;

    /// Exact byte length of the output stream.
    fn output_size(&self) -> u64;

    /// Total byte length of the underlying (possibly compressed) source stream.
    fn source_size(&self) -> u64;

    /// Validates `checkpoint` against this stream and returns the number of trailing
    /// output bytes (ending at `checkpoint.output_offset()`) required as the resume
    /// dictionary for [`resume`](Self::resume).
    ///
    /// Returns `None` if `checkpoint` is out of bounds or incompatible with this stream.
    fn resume_dict_len(&self, checkpoint: &Self::Checkpoint) -> Option<usize>;

    /// Opens a checkpointable reader starting from the beginning of the stream.
    fn open<'a>(
        &'a self,
    ) -> impl Future<
        Output = io::Result<impl ResumableAsyncRead<Checkpoint = Self::Checkpoint> + use<'a, Self>>,
    > + MaybeSend;

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

/// Offset-only [`Checkpoint`] for random-access [`DataSource`] streams.
#[binrw]
#[brw(little, magic = 0u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetCheckpoint {
    offset: u64,
}

impl OffsetCheckpoint {
    /// Creates an offset-only checkpoint at byte `offset`.
    pub const fn new(offset: u64) -> Self {
        Self { offset }
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

        let n = loop {
            match Pin::new(&mut self.reader).poll_read(cx, buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => break n,
            }
        };

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

impl<S: DataSource + ?Sized> ResumableStream for S {
    type Checkpoint = OffsetCheckpoint;

    fn output_size(&self) -> u64 {
        self.size()
    }

    fn source_size(&self) -> u64 {
        self.size()
    }

    fn resume_dict_len(&self, checkpoint: &OffsetCheckpoint) -> Option<usize> {
        (checkpoint.offset <= self.size()).then_some(0)
    }

    async fn open<'a>(
        &'a self,
    ) -> io::Result<impl ResumableAsyncRead<Checkpoint = OffsetCheckpoint> + use<'a, S>> {
        let size = self.size();
        let reader = self.fetch_range(..).await?;
        Ok(OffsetResumableReader::new(reader, size, 0))
    }

    async fn resume<'a>(
        &'a self,
        checkpoint: &OffsetCheckpoint,
        _dict: &[u8],
    ) -> io::Result<impl ResumableAsyncRead<Checkpoint = OffsetCheckpoint> + use<'a, S>> {
        let size = self.size();
        if checkpoint.offset > size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "offset checkpoint exceeds source size",
            ));
        }
        let reader = self.fetch_range(checkpoint.offset..).await?;
        Ok(OffsetResumableReader::new(reader, size, checkpoint.offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::{BinRead, BinWrite};
    use futures::executor::block_on;
    use futures::io::{AsyncReadExt, Cursor};

    #[test]
    fn test_offset_checkpoint_wire_round_trip() {
        let cp = OffsetCheckpoint::new(2048);
        let mut bytes = Vec::new();
        cp.write(&mut std::io::Cursor::new(&mut bytes)).unwrap();
        assert_eq!(bytes.len(), 9);
        assert_eq!(bytes[0], 0);
        let decoded = OffsetCheckpoint::read(&mut std::io::Cursor::new(&bytes)).unwrap();
        assert_eq!(decoded, cp);
        assert_eq!(decoded.source_offset(), 2048);
        assert_eq!(decoded.output_offset(), 2048);

        // Wrong magic tag must be rejected
        bytes[0] = 1;
        assert!(OffsetCheckpoint::read(&mut std::io::Cursor::new(&bytes)).is_err());
    }

    #[test]
    fn test_offset_resumable_stream_resume_and_errors() {
        let payload: Vec<u8> = (0..4096).map(|i| ((i * 31) ^ (i >> 7)) as u8).collect();
        assert_eq!(payload.output_size(), 4096);
        assert_eq!(payload.source_size(), 4096);

        block_on(async {
            let mut r = payload.open().await.unwrap();
            assert_eq!(r.checkpoint(), None);
            let mut head = vec![0u8; 1000];
            let n = r.read(&mut head).await.unwrap();
            let cp = r.checkpoint().unwrap();
            assert_eq!(n, 1000);
            assert_eq!(cp.source_offset(), 1000);
            assert_eq!(cp.output_offset(), 1000);
            assert_eq!(payload.resume_dict_len(&cp), Some(0));
            assert_eq!(payload.resume_dict_len(&OffsetCheckpoint::new(4097)), None);

            let mut resumed = head;
            payload
                .resume(&cp, &[])
                .await
                .unwrap()
                .read_to_end(&mut resumed)
                .await
                .unwrap();
            assert_eq!(resumed, payload);

            // Resuming right at EOF succeeds with 0 bytes, and the returned reader does not
            // borrow the checkpoint or dictionary past `.await`.
            let mut tail_reader = {
                let eof_cp = OffsetCheckpoint::new(4096);
                let dict = Vec::new();
                payload.resume(&eof_cp, &dict).await.unwrap()
            };
            let mut tail = Vec::new();
            tail_reader.read_to_end(&mut tail).await.unwrap();
            assert!(tail.is_empty());

            // Reading the final byte suppresses checkpoint() before EOF is polled
            let mut full_reader = payload.open().await.unwrap();
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
