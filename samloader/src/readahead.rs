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

//! Background readahead for files read by the async flashing pipeline.
//!
//! Once a file is read sequentially, a helper thread reads a bounded window
//! ahead of the reader with large positional reads, while the USB transfer is
//! in progress. This avoids small, latency-bound reads over network
//! filesystems.

use samloader_odin::futures::channel::mpsc;
use samloader_odin::futures::executor::block_on;
use samloader_odin::futures::io::{AsyncRead, AsyncSeek};
use samloader_odin::futures::{SinkExt, Stream};
use std::fs::File;
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread;

/// Size of each read issued by the helper thread.
const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// Chunks buffered ahead of the reader: 32 MiB, about one slice.
const WINDOW_CHUNKS: usize = 8;
/// Bytes read contiguously before the helper thread is started. Scanning
/// packages and parsing headers seeks between small reads, which must not
/// trigger readahead.
const STREAM_THRESHOLD: u64 = 1024 * 1024;
/// Forward seeks up to this distance, such as over the TAR header between two
/// package entries, keep reading ahead and discard the skipped bytes.
const MAX_SKIP: u64 = CHUNK_SIZE as u64;

type Chunk = io::Result<Vec<u8>>;

/// A file read through the async I/O traits, with readahead on a helper thread
/// for sequential reads.
///
/// Small reads that are not part of a sequential run are performed directly,
/// blocking the caller. This is fine with `block_on`, which only drives the
/// flash itself.
pub(crate) struct ReadaheadFile {
    file: Arc<File>,
    len: u64,
    pos: u64,
    /// Bytes read directly and contiguously up to `pos`.
    sequential: u64,
    worker: Option<Worker>,
    /// Set if the helper thread could not be spawned, so that reads stay direct.
    direct_only: bool,
}

impl ReadaheadFile {
    pub(crate) fn new(file: File) -> io::Result<Self> {
        let len = file.metadata()?.len();
        Ok(Self {
            file: Arc::new(file),
            len,
            pos: 0,
            sequential: 0,
            worker: None,
            direct_only: false,
        })
    }

    /// Starts a helper thread reading from the current position to the end of
    /// the file. It stops once the returned worker is dropped.
    fn spawn(&self) -> Option<Worker> {
        // The channel holds one message per sender on top of its buffer
        let (mut tx, rx) = mpsc::channel::<Chunk>(WINDOW_CHUNKS - 1);
        let file = Arc::clone(&self.file);
        let (start, len) = (self.pos, self.len);
        thread::Builder::new()
            .name("readahead".into())
            .spawn(move || {
                let mut offset = start;
                while offset < len {
                    let mut buf = vec![0u8; CHUNK_SIZE.min((len - offset) as usize)];
                    let chunk = read_full_at(&file, &mut buf, offset).map(|n| {
                        buf.truncate(n);
                        buf
                    });
                    // Stop after an error or an unexpected end of file
                    let done = !matches!(&chunk, Ok(buf) if !buf.is_empty());
                    if let Ok(buf) = &chunk {
                        offset += buf.len() as u64;
                    }
                    // Waits while the window is full, and fails once the
                    // receiver is dropped
                    if block_on(tx.send(chunk)).is_err() || done {
                        break;
                    }
                }
            })
            .ok()?;
        Some(Worker::new(rx, start))
    }
}

impl AsyncRead for ReadaheadFile {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() || this.pos >= this.len {
            return Poll::Ready(Ok(0));
        }

        if this.worker.is_none()
            && !this.direct_only
            && this.sequential + buf.len() as u64 >= STREAM_THRESHOLD
        {
            this.worker = this.spawn();
            // Without a helper thread, flashing still works with direct reads
            this.direct_only = this.worker.is_none();
        }

        let Some(worker) = &mut this.worker else {
            let res = read_at(&this.file, buf, this.pos);
            if let Ok(n) = res {
                this.pos += n as u64;
                this.sequential += n as u64;
            }
            return Poll::Ready(res);
        };

        match worker.poll_read(cx, this.pos, buf) {
            Poll::Ready(Ok(n)) => {
                this.pos += n as u64;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                // The helper thread stops after an error; retry from scratch
                this.worker = None;
                this.sequential = 0;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncSeek for ReadaheadFile {
    fn poll_seek(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        let target = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => this.len.checked_add_signed(d),
            SeekFrom::Current(d) => this.pos.checked_add_signed(d),
        };
        let Some(target) = target else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            )));
        };

        if target != this.pos {
            this.sequential = 0;
            if let Some(worker) = &this.worker
                && !(worker.stream_pos..=worker.stream_pos + MAX_SKIP).contains(&target)
            {
                this.worker = None;
            }
        }
        this.pos = target;
        Poll::Ready(Ok(target))
    }
}

/// The reader's end of a helper thread.
struct Worker {
    rx: mpsc::Receiver<Chunk>,
    chunk: Vec<u8>,
    chunk_pos: usize,
    /// File offset of `chunk[chunk_pos]`. This is never past the reader's
    /// position; bytes in between were skipped by a seek and are discarded.
    stream_pos: u64,
    /// An error received after some bytes were already returned.
    error: Option<io::Error>,
}

impl Worker {
    fn new(rx: mpsc::Receiver<Chunk>, start: u64) -> Self {
        Self {
            rx,
            chunk: Vec::new(),
            chunk_pos: 0,
            stream_pos: start,
            error: None,
        }
    }

    /// Reads buffered bytes at file offset `pos` into `buf`, returning
    /// `Pending` if none are available yet.
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        pos: u64,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(e) = self.error.take() {
            return Poll::Ready(Err(e));
        }

        let mut copied = 0;
        while copied < buf.len() {
            let avail = self.chunk.len() - self.chunk_pos;
            if avail == 0 {
                match Pin::new(&mut self.rx).poll_next(cx) {
                    Poll::Ready(Some(Ok(chunk))) if !chunk.is_empty() => {
                        self.chunk = chunk;
                        self.chunk_pos = 0;
                        continue;
                    }
                    // End of file
                    Poll::Ready(Some(Ok(_)) | None) => break,
                    Poll::Ready(Some(Err(e))) if copied == 0 => return Poll::Ready(Err(e)),
                    Poll::Ready(Some(Err(e))) => {
                        self.error = Some(e);
                        break;
                    }
                    Poll::Pending if copied == 0 => return Poll::Pending,
                    Poll::Pending => break,
                }
            }

            // Discard bytes skipped by a seek before copying
            let behind = pos + copied as u64 - self.stream_pos;
            let n = if behind > 0 {
                behind.min(avail as u64) as usize
            } else {
                let n = avail.min(buf.len() - copied);
                buf[copied..copied + n]
                    .copy_from_slice(&self.chunk[self.chunk_pos..self.chunk_pos + n]);
                copied += n;
                n
            };
            self.chunk_pos += n;
            self.stream_pos += n as u64;
        }
        Poll::Ready(Ok(copied))
    }
}

fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }
}

/// Reads until `buf` is full or the end of the file is reached.
fn read_full_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match read_at(file, &mut buf[n..], offset + n as u64) {
            Ok(0) => break,
            Ok(m) => n += m,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use samloader_odin::futures::io::{AsyncReadExt, AsyncSeekExt};
    use samloader_odin::futures::task::{ArcWake, waker};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A file in the temporary directory, removed when dropped.
    struct TempFile(PathBuf);

    impl TempFile {
        fn new(name: &str, data: &[u8]) -> Self {
            let path = std::env::temp_dir()
                .join(format!("samloader-readahead-{}-{name}", std::process::id()));
            File::create(&path).unwrap().write_all(data).unwrap();
            Self(path)
        }

        fn open(&self) -> ReadaheadFile {
            ReadaheadFile::new(File::open(&self.0).unwrap()).unwrap()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn test_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn test_reads_match_file_contents() {
        let data = test_data(20 * 1024 * 1024 + 123);
        let tmp = TempFile::new("contents", &data);
        let mut f = tmp.open();
        block_on(async {
            // Small reads are direct
            let mut header = [0u8; 512];
            f.read_exact(&mut header).await.unwrap();
            assert_eq!(header, data[..512]);
            assert!(f.worker.is_none());

            // A large read starts the helper thread
            let mut slice = vec![0u8; 5 * 1024 * 1024];
            f.read_exact(&mut slice).await.unwrap();
            assert_eq!(slice, data[512..512 + slice.len()]);
            assert!(f.worker.is_some());

            // A short forward seek keeps it
            let pos = f.seek(SeekFrom::Current(1000)).await.unwrap() as usize;
            assert!(f.worker.is_some());
            let mut slice = vec![0u8; 3 * 1024 * 1024];
            f.read_exact(&mut slice).await.unwrap();
            assert_eq!(slice, data[pos..pos + slice.len()]);

            // A backward seek drops it, and reading to the end restarts it
            f.seek(SeekFrom::Start(7)).await.unwrap();
            assert!(f.worker.is_none());
            let mut rest = Vec::new();
            f.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest, data[7..]);
        });
    }

    #[test]
    fn test_sequential_small_reads_start_readahead() {
        let data = test_data(4 * 1024 * 1024);
        let tmp = TempFile::new("sequential", &data);
        let mut f = tmp.open();
        block_on(async {
            // Like MD5 verification, reading 128 KiB at a time
            let mut buf = vec![0u8; 128 * 1024];
            let mut read = Vec::new();
            while read.len() < data.len() {
                f.read_exact(&mut buf).await.unwrap();
                read.extend_from_slice(&buf);
            }
            assert_eq!(read, data);
            assert!(f.worker.is_some());

            // Seeking between small reads, like scanning TAR headers, does not
            let mut f = tmp.open();
            for offset in (0..data.len()).step_by(512 * 1024) {
                f.seek(SeekFrom::Start(offset as u64)).await.unwrap();
                f.read_exact(&mut buf[..512]).await.unwrap();
                assert_eq!(buf[..512], data[offset..offset + 512]);
            }
            assert!(f.worker.is_none());
        });
    }

    #[test]
    fn test_long_seeks_drop_readahead() {
        let data = test_data(2 * MAX_SKIP as usize + 4096);
        let tmp = TempFile::new("seek", &data);
        let mut f = tmp.open();
        block_on(async {
            let mut buf = vec![0u8; STREAM_THRESHOLD as usize];
            f.read_exact(&mut buf).await.unwrap();
            assert!(f.worker.is_some());

            let pos = f
                .seek(SeekFrom::Current(MAX_SKIP as i64 + 1))
                .await
                .unwrap() as usize;
            assert!(f.worker.is_none());
            f.read_exact(&mut buf[..100]).await.unwrap();
            assert_eq!(buf[..100], data[pos..pos + 100]);

            assert_eq!(f.seek(SeekFrom::End(0)).await.unwrap(), data.len() as u64);
            assert_eq!(f.read(&mut buf).await.unwrap(), 0);
            assert!(
                f.seek(SeekFrom::Current(-(data.len() as i64) - 1))
                    .await
                    .is_err()
            );
        });
    }

    struct WakeFlag(AtomicBool);

    impl ArcWake for WakeFlag {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_worker_waits_without_blocking() {
        let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = waker(flag.clone());
        let mut cx = Context::from_waker(&waker);

        let (mut tx, rx) = mpsc::channel::<Chunk>(1);
        let mut worker = Worker::new(rx, 100);
        let mut buf = [0u8; 8];

        // Nothing buffered yet: Pending, and woken once a chunk arrives
        assert!(worker.poll_read(&mut cx, 100, &mut buf).is_pending());
        tx.try_send(Ok(vec![1, 2, 3, 4])).unwrap();
        assert!(flag.0.load(Ordering::SeqCst));

        // Bytes skipped by a seek are discarded, and a partial read does not wait
        let res = worker.poll_read(&mut cx, 101, &mut buf);
        assert!(matches!(res, Poll::Ready(Ok(3))));
        assert_eq!(buf[..3], [2, 3, 4]);

        // An error after some bytes is reported on the next read
        tx.try_send(Ok(vec![5])).unwrap();
        tx.try_send(Err(io::Error::other("read failed"))).unwrap();
        let res = worker.poll_read(&mut cx, 104, &mut buf);
        assert!(matches!(res, Poll::Ready(Ok(1))));
        assert!(matches!(
            worker.poll_read(&mut cx, 105, &mut buf),
            Poll::Ready(Err(_))
        ));

        // The end of the stream is the end of the file
        drop(tx);
        assert!(matches!(
            worker.poll_read(&mut cx, 105, &mut buf),
            Poll::Ready(Ok(0))
        ));
    }
}
