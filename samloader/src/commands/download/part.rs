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

//! Resumable `.part` file management, `SAMLOADR` v5 sidecar checkpoint metadata,
//! and coalesced blocking disk writing.

use binrw::{BinRead, BinWrite, binrw};
use samloader_fus::futures::future::{self, Either};
use samloader_fus::futures::io::AsyncReadExt;
use samloader_fus::{
    Checkpoint, OffsetCheckpoint, ResumableAsyncRead, ResumableStream, ZipCheckpoint,
};
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::time::{Duration, Instant};
use tokio::sync::watch;

const META_VERSION: u32 = 5;
const CHECKPOINT_INTERVAL: u64 = 32 * 1024 * 1024;
const WRITE_BUF_SIZE: usize = 2 * 1024 * 1024;
const COALESCE_MAX_WAIT: Duration = Duration::from_millis(250);

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckpointState {
    #[brw(magic = 1u8)]
    Offset(OffsetCheckpoint),
    #[brw(magic = 2u8)]
    Zip(ZipCheckpoint),
}

impl From<OffsetCheckpoint> for CheckpointState {
    fn from(cp: OffsetCheckpoint) -> Self {
        Self::Offset(cp)
    }
}

impl TryFrom<CheckpointState> for OffsetCheckpoint {
    type Error = ();

    fn try_from(state: CheckpointState) -> Result<Self, ()> {
        match state {
            CheckpointState::Offset(cp) => Ok(cp),
            _ => Err(()),
        }
    }
}

impl From<ZipCheckpoint> for CheckpointState {
    fn from(cp: ZipCheckpoint) -> Self {
        Self::Zip(cp)
    }
}

impl TryFrom<CheckpointState> for ZipCheckpoint {
    type Error = ();

    fn try_from(state: CheckpointState) -> Result<Self, ()> {
        match state {
            CheckpointState::Zip(cp) => Ok(cp),
            _ => Err(()),
        }
    }
}

#[binrw]
#[brw(little, magic = b"SAMLOADR")]
#[br(import(expected_checksum: [u8; 16], expected_size: u64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointMeta {
    #[br(temp, assert(version == META_VERSION))]
    #[bw(calc = META_VERSION)]
    version: u32,

    #[br(assert(checksum == expected_checksum))]
    checksum: [u8; 16],

    #[br(assert(target_size == expected_size))]
    target_size: u64,

    state: CheckpointState,
}

impl CheckpointMeta {
    fn to_bytes(self) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::with_capacity(64));
        self.write(&mut cursor)
            .expect("in-memory checkpoint serialization cannot fail");
        cursor.into_inner()
    }

    fn from_bytes(bytes: &[u8], expected_checksum: [u8; 16], expected_size: u64) -> Option<Self> {
        let mut cursor = Cursor::new(bytes);
        let meta = Self::read_args(&mut cursor, (expected_checksum, expected_size)).ok()?;
        (cursor.position() as usize == bytes.len()).then_some(meta)
    }
}

fn append_ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(ext);
    PathBuf::from(s)
}

pub(crate) fn part_path_for(final_path: &Path) -> PathBuf {
    append_ext(final_path, ".part")
}

fn meta_path_for(part_path: &Path) -> PathBuf {
    append_ext(part_path, ".meta")
}

fn remove_meta_files(meta_path: &Path) {
    let _ = std::fs::remove_file(meta_path);
    let _ = std::fs::remove_file(append_ext(meta_path, ".tmp"));
}

fn io_with_path(path: &Path, action: &str, err: io::Error) -> io::Error {
    io::Error::new(
        err.kind(),
        format!("failed to {action} '{}': {err}", path.display()),
    )
}

fn persist_checkpoint(
    file: &File,
    meta_path: &Path,
    checksum: [u8; 16],
    target_size: u64,
    state: CheckpointState,
) -> io::Result<()> {
    // Flush data blocks before advancing the persisted sidecar so power loss
    // cannot leave a newer checkpoint pointing past unwritten data.
    let result = (|| {
        file.sync_data()?;
        let bytes = CheckpointMeta {
            checksum,
            target_size,
            state,
        }
        .to_bytes();
        let tmp_path = append_ext(meta_path, ".tmp");
        let replace_res = (|| {
            let mut tmp = File::create(&tmp_path)?;
            tmp.write_all(&bytes)?;
            tmp.sync_data()?;
            drop(tmp);
            std::fs::rename(&tmp_path, meta_path)
        })();
        if let Err(e) = replace_res {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
        Ok(())
    })();
    result.map_err(|e| io_with_path(meta_path, "persist checkpoint for", e))
}

fn finalize_part_file(
    file: File,
    part_path: &Path,
    meta_path: &Path,
    final_path: &Path,
) -> io::Result<()> {
    file.sync_data()
        .map_err(|e| io_with_path(part_path, "sync", e))?;
    drop(file);

    // `std::fs::rename` replaces existing files atomically on both Unix and Windows
    // (`SetFileInformationByHandle` / `MoveFileExW` with replace-if-exists).
    std::fs::rename(part_path, final_path).map_err(|e| io_with_path(final_path, "finalize", e))?;
    remove_meta_files(meta_path);
    Ok(())
}

/// Resolves once `cancel_rx` becomes `true`, staying pending forever if the sender is dropped.
pub(crate) async fn wait_cancelled(cancel_rx: &mut watch::Receiver<bool>) {
    if cancel_rx.wait_for(|&cancelled| cancelled).await.is_err() {
        std::future::pending::<()>().await;
    }
}

fn cancelled_error() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "download interrupted")
}

/// Resume state resolved when opening a [`PartFile`].
pub(crate) enum ResumeState<C: Checkpoint> {
    Fresh,
    Restarted,
    Resumed { checkpoint: C, dict: Vec<u8> },
}

/// An open sequential `.part` file paired with a `.part.meta` checkpoint sidecar,
/// prepared to receive a [`ResumableAsyncRead`] and atomically rename on completion.
pub(crate) struct PartFile {
    file: File,
    part_path: PathBuf,
    meta_path: PathBuf,
    final_path: PathBuf,
    checksum: [u8; 16],
    start_pos: u64,
    target_size: u64,
}

impl PartFile {
    /// Opens or creates `<final_path>.part`, validates any persisted `SAMLOADR` v5
    /// sidecar checkpoint against `source`, and loads any required decompression dictionary.
    pub(crate) fn open<S>(
        final_path: PathBuf,
        checksum: [u8; 16],
        source: &S,
        force: bool,
    ) -> io::Result<(Self, ResumeState<S::Checkpoint>)>
    where
        S: ResumableStream,
        S::Checkpoint: TryFrom<CheckpointState>,
    {
        let target_size = source.output_size();
        let part_path = part_path_for(&final_path);
        let meta_path = meta_path_for(&part_path);

        tokio::task::block_in_place(|| {
            if let Some(parent) = final_path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)
                    .map_err(|e| io_with_path(parent, "create directory", e))?;
            }

            if force {
                // Keep any existing `final_path` intact until the replacement download finishes
                // cleanly and replaces it atomically in `finalize_part_file`.
                let _ = std::fs::remove_file(&part_path);
                remove_meta_files(&meta_path);
            }

            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(force)
                .open(&part_path)
                .map_err(|e| io_with_path(&part_path, "open", e))?;

            let existing_len = file
                .metadata()
                .map_err(|e| io_with_path(&part_path, "stat", e))?
                .len();

            let mut resume = ResumeState::Fresh;
            let mut start_pos = 0;

            if !force {
                let meta_bytes = std::fs::read(&meta_path).ok();
                let valid_resume = meta_bytes
                    .as_deref()
                    .and_then(|b| CheckpointMeta::from_bytes(b, checksum, target_size))
                    .and_then(|m| S::Checkpoint::try_from(m.state).ok())
                    .and_then(|cp| {
                        let dict_len = source.resume_dict_len(&cp)?;
                        let out = cp.output_offset();
                        (cp.source_offset() > 0
                            && out < target_size
                            && out <= existing_len
                            && (dict_len as u64) <= out)
                            .then_some((cp, dict_len))
                    });

                if let Some((cp, dict_len)) = valid_resume {
                    start_pos = cp.output_offset();
                    if existing_len > start_pos {
                        file.set_len(start_pos)
                            .map_err(|e| io_with_path(&part_path, "truncate", e))?;
                    }
                    let mut dict = vec![0u8; dict_len];
                    file.seek(SeekFrom::Start(start_pos - dict_len as u64))
                        .map_err(|e| io_with_path(&part_path, "seek", e))?;
                    if dict_len > 0 {
                        file.read_exact(&mut dict).map_err(|e| {
                            io_with_path(&part_path, "read resume dictionary from", e)
                        })?;
                    }
                    resume = ResumeState::Resumed {
                        checkpoint: cp,
                        dict,
                    };
                } else {
                    let had_prior_state = existing_len > 0 || meta_bytes.is_some();
                    remove_meta_files(&meta_path);
                    if existing_len > 0 {
                        file.set_len(0)
                            .map_err(|e| io_with_path(&part_path, "truncate", e))?;
                    }
                    if had_prior_state {
                        resume = ResumeState::Restarted;
                    }
                }
            }

            let part = Self {
                file,
                part_path,
                meta_path,
                final_path,
                checksum,
                start_pos,
                target_size,
            };
            Ok((part, resume))
        })
    }

    /// Streams all remaining chunks from `reader` directly to disk inside
    /// `block_in_place`, persisting periodic checkpoints and finalizing the file on EOF.
    pub(crate) fn write_from<R>(
        self,
        reader: R,
        cancel_rx: watch::Receiver<bool>,
        on_written: impl Fn(u64),
    ) -> io::Result<()>
    where
        R: ResumableAsyncRead,
        R::Checkpoint: Into<CheckpointState>,
    {
        self.write_from_with_interval(reader, CHECKPOINT_INTERVAL, cancel_rx, on_written)
    }

    fn write_from_with_interval<R>(
        self,
        mut reader: R,
        checkpoint_interval: u64,
        mut cancel_rx: watch::Receiver<bool>,
        on_written: impl Fn(u64),
    ) -> io::Result<()>
    where
        R: ResumableAsyncRead,
        R::Checkpoint: Into<CheckpointState>,
    {
        let handle = tokio::runtime::Handle::current();

        tokio::task::block_in_place(move || {
            let remaining = self.target_size.saturating_sub(self.start_pos);
            // Keep `buf_size >= 1` so `reader.read` still polls EOF/CRC verification
            // even on 0-byte streams or streams already resumed at `target_size`.
            let buf_size = (remaining.min(WRITE_BUF_SIZE as u64) as usize).max(1);
            let mut buf = vec![0u8; buf_size];
            let mut filled = 0usize;
            let mut write_pos = self.start_pos;
            let mut last_persisted_offset = self.start_pos;
            let mut latest_cp: Option<R::Checkpoint> = None;
            let min_delta = checkpoint_interval.max(1);
            let mut last_flush = Instant::now();
            let mut file = self.file;

            let flush_buf = |file: &mut File,
                             buf: &[u8],
                             filled: &mut usize,
                             write_pos: &mut u64|
             -> io::Result<()> {
                if *filled == 0 {
                    return Ok(());
                }
                let n = *filled;
                *filled = 0;
                file.write_all(&buf[..n])
                    .map_err(|e| io_with_path(&self.part_path, "write", e))?;
                *write_pos += n as u64;
                on_written(n as u64);
                Ok(())
            };

            let read_err: io::Error = loop {
                let read_step = handle.block_on(async {
                    match future::select(
                        pin!(wait_cancelled(&mut cancel_rx)),
                        pin!(reader.read(&mut buf[filled..])),
                    )
                    .await
                    {
                        Either::Left(_) => Err(cancelled_error()),
                        Either::Right((res, _)) => res,
                    }
                });

                match read_step {
                    Ok(0) => {
                        drop(reader);
                        flush_buf(&mut file, &buf, &mut filled, &mut write_pos)?;
                        if write_pos != self.target_size {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!(
                                    "incomplete download: wrote {write_pos} of {} bytes",
                                    self.target_size
                                ),
                            ));
                        }
                        return finalize_part_file(
                            file,
                            &self.part_path,
                            &self.meta_path,
                            &self.final_path,
                        );
                    }
                    Ok(n) => {
                        let new_filled = filled + n;
                        if write_pos
                            .checked_add(new_filled as u64)
                            .is_none_or(|end| end > self.target_size)
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "stream exceeded declared target size",
                            ));
                        }
                        filled = new_filled;

                        let mut cp_due = None;
                        if let Some(cp) = reader
                            .checkpoint()
                            .filter(|cp| cp.output_offset() < self.target_size)
                        {
                            if cp.output_offset() >= last_persisted_offset.saturating_add(min_delta)
                            {
                                cp_due = Some(cp);
                            } else {
                                latest_cp = Some(cp);
                            }
                        }

                        if let Some(cp) = cp_due {
                            let cp_offset = cp.output_offset();
                            flush_buf(&mut file, &buf, &mut filled, &mut write_pos)?;
                            persist_checkpoint(
                                &file,
                                &self.meta_path,
                                self.checksum,
                                self.target_size,
                                cp.into(),
                            )?;
                            last_persisted_offset = cp_offset;
                            latest_cp = None;
                            last_flush = Instant::now();
                        } else if filled == buf.len() || last_flush.elapsed() >= COALESCE_MAX_WAIT {
                            flush_buf(&mut file, &buf, &mut filled, &mut write_pos)?;
                            last_flush = Instant::now();
                        }
                    }
                    Err(e) => break e,
                }
            };

            drop(reader);
            if read_err.kind() != io::ErrorKind::InvalidData
                && let Some(cp) = latest_cp.filter(|cp| cp.output_offset() > last_persisted_offset)
                && flush_buf(&mut file, &buf, &mut filled, &mut write_pos).is_ok()
            {
                let _ = persist_checkpoint(
                    &file,
                    &self.meta_path,
                    self.checksum,
                    self.target_size,
                    cp.into(),
                );
            }
            Err(read_err)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use samloader_fus::futures::io::AsyncRead;
    use samloader_fus::{DataSource, DataStream};
    use std::ops::RangeBounds;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll};

    const TEST_CHECKSUM: [u8; 16] = [0x42; 16];

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "samloader-part-test-{}-{id}-{tag}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_checkpoint_meta_round_trip_and_rejection() {
        let checksum = TEST_CHECKSUM;
        let other_checksum = [0x99; 16];
        let target_size = 4096_u64;

        let offset_cp = OffsetCheckpoint::new(2048);

        let mut stored_bytes = [0u8; 13];
        stored_bytes[0] = 0; // Stored
        stored_bytes[1..9].copy_from_slice(&1536u64.to_le_bytes());
        stored_bytes[9..13].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let stored_cp = ZipCheckpoint::read(&mut Cursor::new(&stored_bytes)).unwrap();

        let mut deflate_bytes = [0u8; 23];
        deflate_bytes[0] = 1; // Deflate
        deflate_bytes[1..9].copy_from_slice(&1024u64.to_le_bytes());
        deflate_bytes[9..17].copy_from_slice(&3072u64.to_le_bytes());
        deflate_bytes[17..21].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        deflate_bytes[21] = 5;
        deflate_bytes[22] = 0x1A;
        let deflate_cp = ZipCheckpoint::read(&mut Cursor::new(&deflate_bytes)).unwrap();

        let mut last_bytes = Vec::new();
        for state in [
            CheckpointState::Offset(offset_cp),
            CheckpointState::Zip(stored_cp),
            CheckpointState::Zip(deflate_cp),
        ] {
            let meta = CheckpointMeta {
                checksum,
                target_size,
                state,
            };
            last_bytes = meta.to_bytes();

            let parsed = CheckpointMeta::from_bytes(&last_bytes, checksum, target_size).unwrap();
            assert_eq!(parsed.state, state);
        }

        // Cross-type checkpoint extraction must reject mismatches
        assert_eq!(
            OffsetCheckpoint::try_from(CheckpointState::Offset(offset_cp)),
            Ok(offset_cp)
        );
        assert_eq!(
            ZipCheckpoint::try_from(CheckpointState::Offset(offset_cp)),
            Err(())
        );
        assert_eq!(
            ZipCheckpoint::try_from(CheckpointState::Zip(deflate_cp)),
            Ok(deflate_cp)
        );
        assert_eq!(
            OffsetCheckpoint::try_from(CheckpointState::Zip(deflate_cp)),
            Err(())
        );

        // Truncated / trailing-garbage sidecar files must be rejected
        assert!(
            CheckpointMeta::from_bytes(&last_bytes[..last_bytes.len() - 1], checksum, target_size)
                .is_none()
        );
        let mut overlong = last_bytes.clone();
        overlong.push(0);
        assert!(CheckpointMeta::from_bytes(&overlong, checksum, target_size).is_none());

        // Corrupt magic (0), version (8), checksum (12), target_size (28), state tag (36), checkpoint kind (37)
        for &(off, val) in &[
            (0, 0xFF),
            (8, 0x04),
            (12, 0xFF),
            (28, 0xFF),
            (36, 0x09),
            (37, 0x09),
        ] {
            let mut tampered = last_bytes.clone();
            tampered[off] = val;
            assert!(
                CheckpointMeta::from_bytes(&tampered, checksum, target_size).is_none(),
                "offset={off}"
            );
        }

        // Checksum and target_size mismatches
        assert!(CheckpointMeta::from_bytes(&last_bytes, other_checksum, target_size).is_none());
        assert!(CheckpointMeta::from_bytes(&last_bytes, checksum, target_size + 1).is_none());
    }

    #[test]
    fn test_part_file_checkpoint_resume_and_restart() {
        struct ChunkedFailSource {
            data: Vec<u8>,
            fail_after: Option<usize>,
        }

        struct ChunkedReader {
            data: Vec<u8>,
            pos: usize,
            fail_after: Option<usize>,
        }

        impl AsyncRead for ChunkedReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                if let Some(limit) = self.fail_after
                    && self.pos >= limit
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "simulated mid-download drop",
                    )));
                }
                let max = self
                    .fail_after
                    .map_or(self.data.len(), |l| l.min(self.data.len()));
                let n = (max - self.pos).min(16 * 1024).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Poll::Ready(Ok(n))
            }
        }

        impl DataSource for ChunkedFailSource {
            fn size(&self) -> u64 {
                self.data.len() as u64
            }

            async fn fetch_range(
                &self,
                range: impl RangeBounds<u64> + Send,
            ) -> io::Result<impl AsyncRead + Send + Unpin> {
                let start = match range.start_bound() {
                    std::ops::Bound::Included(&s) => s as usize,
                    std::ops::Bound::Excluded(&s) => (s + 1) as usize,
                    std::ops::Bound::Unbounded => 0,
                };
                let slice = if start < self.data.len() {
                    self.data[start..].to_vec()
                } else {
                    Vec::new()
                };
                Ok(ChunkedReader {
                    data: slice,
                    pos: 0,
                    fail_after: self.fail_after,
                })
            }
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        let dir = TempDir::new("resume");
        let final_path = dir.0.join("firmware.zip");
        let checksum = TEST_CHECKSUM;
        let payload: Vec<u8> = (0..128_000).map(|i| ((i * 29) ^ (i >> 5)) as u8).collect();

        rt.block_on(async {
            let never_cancel = || watch::channel(false).1;

            // 1. First attempt fails after 64 KiB, leaving a valid checkpoint in .part
            let flaky = DataStream::new(ChunkedFailSource {
                data: payload.clone(),
                fail_after: Some(64 * 1024),
            });
            let (part, resume) =
                PartFile::open(final_path.clone(), checksum, &flaky, false).unwrap();
            assert!(matches!(resume, ResumeState::Fresh));
            let reader = flaky.open().await.unwrap();
            let err = part
                .write_from_with_interval(reader, 16 * 1024, never_cancel(), |_| {})
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
            assert!(!final_path.exists());
            let part_path = part_path_for(&final_path);
            let meta_path = meta_path_for(&part_path);
            assert!(part_path.exists());
            assert!(meta_path.exists());

            // Simulate an uncommitted tail written past the last persisted checkpoint;
            // resume must truncate it cleanly back to the checkpoint offset.
            std::fs::OpenOptions::new()
                .append(true)
                .open(&part_path)
                .unwrap()
                .write_all(b"uncommitted-tail")
                .unwrap();

            // 2. Second attempt resumes from persisted checkpoint and finalizes cleanly
            let healthy = DataStream::new(ChunkedFailSource {
                data: payload.clone(),
                fail_after: None,
            });
            let (part, resume) =
                PartFile::open(final_path.clone(), checksum, &healthy, false).unwrap();
            let (cp, dict) = match resume {
                ResumeState::Resumed { checkpoint, dict } => (checkpoint, dict),
                _ => panic!("expected Resumed state"),
            };
            assert!(cp.output_offset() >= 16 * 1024 && cp.output_offset() <= 64 * 1024);
            assert!(dict.is_empty());
            assert_eq!(
                std::fs::metadata(&part_path).unwrap().len(),
                cp.output_offset()
            );

            let written = Arc::new(AtomicU64::new(0));
            let written_cb = Arc::clone(&written);
            let reader = healthy.resume(&cp, &dict).await.unwrap();
            part.write_from_with_interval(reader, 16 * 1024, never_cancel(), move |n| {
                written_cb.fetch_add(n, Ordering::Relaxed);
            })
            .unwrap();
            assert_eq!(
                cp.output_offset() + written.load(Ordering::Relaxed),
                payload.len() as u64
            );
            assert!(!part_path.exists());
            assert!(!meta_path.exists());
            assert_eq!(std::fs::read(&final_path).unwrap(), payload);

            // 3. Corrupt .part file triggers Restarted; force=true starts Fresh while keeping final_path
            let corrupt_target = dir.0.join("corrupt.bin");
            std::fs::write(&corrupt_target, b"existing good file").unwrap();
            std::fs::write(part_path_for(&corrupt_target), b"corrupt data").unwrap();
            let (_, resume) =
                PartFile::open(corrupt_target.clone(), checksum, &healthy, false).unwrap();
            assert!(matches!(resume, ResumeState::Restarted));

            let (_, resume) =
                PartFile::open(corrupt_target.clone(), checksum, &healthy, true).unwrap();
            assert!(matches!(resume, ResumeState::Fresh));
            assert_eq!(
                std::fs::read(&corrupt_target).unwrap(),
                b"existing good file"
            );

            // 4. Coalescing + final checkpoint flush on transient error even when interval > written bytes
            let coalesce_target = dir.0.join("coalesce.bin");
            let write_calls = Arc::new(AtomicU64::new(0));
            let write_calls_cb = Arc::clone(&write_calls);
            let (part, _) =
                PartFile::open(coalesce_target.clone(), checksum, &healthy, false).unwrap();
            let reader = healthy.open().await.unwrap();
            part.write_from_with_interval(reader, 1024 * 1024, never_cancel(), move |_| {
                write_calls_cb.fetch_add(1, Ordering::Relaxed);
            })
            .unwrap();
            // 128_000 bytes delivered in 16 KiB chunks coalesces into a single disk write.
            assert_eq!(write_calls.load(Ordering::Relaxed), 1);

            let flush_target = dir.0.join("flush_on_err.bin");
            let (part, _) = PartFile::open(flush_target.clone(), checksum, &flaky, false).unwrap();
            let reader = flaky.open().await.unwrap();
            let err = part
                .write_from_with_interval(reader, 1024 * 1024, never_cancel(), |_| {})
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
            let (_, resume) = PartFile::open(flush_target, checksum, &healthy, false).unwrap();
            match resume {
                ResumeState::Resumed { checkpoint, .. } => {
                    assert_eq!(checkpoint.output_offset(), 64 * 1024);
                }
                _ => panic!("expected final checkpoint flushed on transient error"),
            }

            // 5. Cancellation saves checkpoint; InvalidData does not advance checkpoint
            enum AfterFirstRead {
                Cancel(watch::Sender<bool>),
                InvalidData,
            }
            struct OneShotReader {
                data: Vec<u8>,
                pos: usize,
                after: Option<AfterFirstRead>,
            }
            impl AsyncRead for OneShotReader {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    buf: &mut [u8],
                ) -> Poll<io::Result<usize>> {
                    if self.pos == 0 {
                        let n = (32 * 1024).min(self.data.len()).min(buf.len());
                        buf[..n].copy_from_slice(&self.data[..n]);
                        self.pos = n;
                        if matches!(self.after, Some(AfterFirstRead::Cancel(_)))
                            && let Some(AfterFirstRead::Cancel(tx)) = self.after.take()
                        {
                            let _ = tx.send(true);
                        }
                        return Poll::Ready(Ok(n));
                    }
                    match self.after.take() {
                        Some(AfterFirstRead::InvalidData) => Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "simulated stream corruption",
                        ))),
                        _ => Poll::Pending,
                    }
                }
            }
            impl ResumableAsyncRead for OneShotReader {
                type Checkpoint = OffsetCheckpoint;
                fn checkpoint(&self) -> Option<OffsetCheckpoint> {
                    (self.pos > 0 && self.pos < self.data.len())
                        .then_some(OffsetCheckpoint::new(self.pos as u64))
                }
            }

            let cancel_target = dir.0.join("cancelled.bin");
            let (cancel_tx, cancel_rx) = watch::channel(false);
            let (part, _) =
                PartFile::open(cancel_target.clone(), checksum, &healthy, false).unwrap();
            let err = part
                .write_from_with_interval(
                    OneShotReader {
                        data: payload.clone(),
                        pos: 0,
                        after: Some(AfterFirstRead::Cancel(cancel_tx)),
                    },
                    1024 * 1024,
                    cancel_rx,
                    |_| {},
                )
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Interrupted);
            let (_, resume) = PartFile::open(cancel_target, checksum, &healthy, false).unwrap();
            match resume {
                ResumeState::Resumed { checkpoint, .. } => {
                    assert_eq!(checkpoint.output_offset(), 32 * 1024);
                }
                _ => panic!("expected checkpoint saved on cancellation"),
            }

            let invalid_target = dir.0.join("invalid_data.bin");
            let (part, _) =
                PartFile::open(invalid_target.clone(), checksum, &healthy, false).unwrap();
            let err = part
                .write_from_with_interval(
                    OneShotReader {
                        data: payload.clone(),
                        pos: 0,
                        after: Some(AfterFirstRead::InvalidData),
                    },
                    1024 * 1024,
                    never_cancel(),
                    |_| {},
                )
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            let (_, resume) = PartFile::open(invalid_target, checksum, &healthy, false).unwrap();
            assert!(matches!(resume, ResumeState::Fresh));

            // 6. Writer error fails fast even if the reader stalls indefinitely on the next read
            let overflow_target = dir.0.join("overflow.bin");
            let big_source = DataStream::new(vec![0u8; 4 * 1024 * 1024]);
            struct OverflowThenHang {
                step: usize,
            }
            impl AsyncRead for OverflowThenHang {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    buf: &mut [u8],
                ) -> Poll<io::Result<usize>> {
                    match self.step {
                        0 | 1 => {
                            self.step += 1;
                            buf.fill(0xAA);
                            Poll::Ready(Ok(buf.len()))
                        }
                        2 => {
                            // Exceeds 4 MiB target_size; verify overflow is rejected
                            // synchronously before step 3 is ever polled.
                            self.step += 1;
                            buf.fill(0xBB);
                            Poll::Ready(Ok(buf.len()))
                        }
                        _ => Poll::Pending,
                    }
                }
            }
            impl ResumableAsyncRead for OverflowThenHang {
                type Checkpoint = OffsetCheckpoint;
                fn checkpoint(&self) -> Option<OffsetCheckpoint> {
                    None
                }
            }

            let (part, _) = PartFile::open(overflow_target, checksum, &big_source, false).unwrap();
            let err = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::task::spawn_blocking(move || {
                    part.write_from_with_interval(
                        OverflowThenHang { step: 0 },
                        CHECKPOINT_INTERVAL,
                        never_cancel(),
                        |_| {},
                    )
                }),
            )
            .await
            .expect("writer failure must fail fast without timing out")
            .unwrap()
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        });
    }

    #[test]
    fn test_part_file_loads_resume_dictionary_from_disk() {
        struct DictSource {
            inner: DataStream<Vec<u8>>,
            dict_len: usize,
        }

        impl ResumableStream for DictSource {
            type Checkpoint = OffsetCheckpoint;

            fn output_size(&self) -> u64 {
                self.inner.output_size()
            }

            fn source_size(&self) -> u64 {
                self.inner.source_size()
            }

            fn resume_dict_len(&self, checkpoint: &OffsetCheckpoint) -> Option<usize> {
                self.inner
                    .resume_dict_len(checkpoint)
                    .map(|_| self.dict_len.min(checkpoint.output_offset() as usize))
            }

            async fn open(
                &self,
            ) -> io::Result<impl ResumableAsyncRead<Checkpoint = OffsetCheckpoint>> {
                self.inner.open().await
            }

            async fn resume<'a>(
                &'a self,
                checkpoint: &OffsetCheckpoint,
                dict: &[u8],
            ) -> io::Result<impl ResumableAsyncRead<Checkpoint = OffsetCheckpoint> + use<'a>>
            {
                self.inner.resume(checkpoint, dict).await
            }
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        let dir = TempDir::new("dict");
        let final_path = dir.0.join("entry.tar");
        let checksum = TEST_CHECKSUM;
        let payload: Vec<u8> = (0..8192).map(|i| ((i * 17) ^ (i >> 3)) as u8).collect();
        let src = DictSource {
            inner: DataStream::new(payload.clone()),
            dict_len: 512,
        };

        // Pre-populate .part with first 4096 bytes and sidecar checkpoint at 4096.
        let cp = OffsetCheckpoint::new(4096);
        let meta = CheckpointMeta {
            checksum,
            target_size: payload.len() as u64,
            state: CheckpointState::Offset(cp),
        };

        let part_path = part_path_for(&final_path);
        let meta_path = meta_path_for(&part_path);
        std::fs::write(&part_path, &payload[..4096]).unwrap();
        std::fs::write(&meta_path, meta.to_bytes()).unwrap();

        rt.block_on(async {
            let (_, resume) = PartFile::open(final_path.clone(), checksum, &src, false).unwrap();
            match resume {
                ResumeState::Resumed { checkpoint, dict } => {
                    assert_eq!(checkpoint, cp);
                    assert_eq!(dict, &payload[4096 - 512..4096]);
                }
                _ => panic!("expected Resumed state with dictionary"),
            }

            // Truncated .part (shorter than persisted checkpoint offset) safely restarts.
            std::fs::write(&part_path, &payload[..1024]).unwrap();
            let (_, resume) = PartFile::open(final_path.clone(), checksum, &src, false).unwrap();
            assert!(matches!(resume, ResumeState::Restarted));
            assert!(!meta_path.exists());

            // Restore valid files so BadDictSource exercises dict_len > output_offset rejection.
            std::fs::write(&part_path, &payload[..4096]).unwrap();
            std::fs::write(&meta_path, meta.to_bytes()).unwrap();

            // A source reporting an invalid dict_len > output_offset safely restarts
            // instead of panicking on offset subtraction.
            struct BadDictSource(DataStream<Vec<u8>>);
            impl ResumableStream for BadDictSource {
                type Checkpoint = OffsetCheckpoint;

                fn output_size(&self) -> u64 {
                    self.0.output_size()
                }
                fn source_size(&self) -> u64 {
                    self.0.source_size()
                }
                fn resume_dict_len(&self, _checkpoint: &OffsetCheckpoint) -> Option<usize> {
                    Some(8192) // larger than output_offset (4096)
                }
                async fn open(
                    &self,
                ) -> io::Result<impl ResumableAsyncRead<Checkpoint = OffsetCheckpoint>>
                {
                    self.0.open().await
                }
                async fn resume<'a>(
                    &'a self,
                    checkpoint: &OffsetCheckpoint,
                    dict: &[u8],
                ) -> io::Result<impl ResumableAsyncRead<Checkpoint = OffsetCheckpoint> + use<'a>>
                {
                    self.0.resume(checkpoint, dict).await
                }
            }
            let (_, resume) = PartFile::open(
                final_path,
                checksum,
                &BadDictSource(DataStream::new(payload)),
                false,
            )
            .unwrap();
            assert!(matches!(resume, ResumeState::Restarted));

            // 0-byte stream opens, writes, and finalizes cleanly without empty-buffer stalls.
            let empty_path = dir.0.join("empty.bin");
            let empty_src = DataStream::new(Vec::<u8>::new());
            let (part, resume) =
                PartFile::open(empty_path.clone(), checksum, &empty_src, false).unwrap();
            assert!(matches!(resume, ResumeState::Fresh));
            let reader = empty_src.open().await.unwrap();
            part.write_from(reader, watch::channel(false).1, |_| {})
                .unwrap();
            assert_eq!(std::fs::read(&empty_path).unwrap(), b"");
        });
    }
}
