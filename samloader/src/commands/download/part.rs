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

//! Resumable `.part` file management, `SAMLOADR` v4 checkpoint footers, and
//! ring-buffered background disk writing.

use binrw::{BinRead, BinResult, BinWrite, Endian, binrw};
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
use tokio::sync::{mpsc, oneshot, watch};

const FOOTER_VERSION: u32 = 4;
const FOOTER_SIZE: usize = 64;
const CHECKPOINT_INTERVAL: u64 = 32 * 1024 * 1024;
const WRITE_BUF_SIZE: usize = 2 * 1024 * 1024;
const RING_SLOTS: usize = 16;
const COALESCE_MAX_WAIT: Duration = Duration::from_millis(250);

fn read_offset_cp<R: Read + Seek>(
    reader: &mut R,
    _endian: Endian,
    _args: (),
) -> BinResult<OffsetCheckpoint> {
    OffsetCheckpoint::read_from(reader).map_err(binrw::Error::Io)
}

fn write_offset_cp<W: Write + Seek>(
    cp: &OffsetCheckpoint,
    writer: &mut W,
    _endian: Endian,
    _args: (),
) -> BinResult<()> {
    cp.write_to(writer).map_err(binrw::Error::Io)
}

fn read_zip_cp<R: Read + Seek>(
    reader: &mut R,
    _endian: Endian,
    _args: (),
) -> BinResult<ZipCheckpoint> {
    ZipCheckpoint::read_from(reader).map_err(binrw::Error::Io)
}

fn write_zip_cp<W: Write + Seek>(
    cp: &ZipCheckpoint,
    writer: &mut W,
    _endian: Endian,
    _args: (),
) -> BinResult<()> {
    cp.write_to(writer).map_err(binrw::Error::Io)
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FooterState {
    #[brw(magic = 0u8)]
    Fresh,
    #[brw(magic = 1u8)]
    Offset(
        #[br(parse_with = read_offset_cp)]
        #[bw(write_with = write_offset_cp)]
        OffsetCheckpoint,
    ),
    #[brw(magic = 2u8)]
    Zip(
        #[br(parse_with = read_zip_cp)]
        #[bw(write_with = write_zip_cp)]
        ZipCheckpoint,
    ),
}

impl From<OffsetCheckpoint> for FooterState {
    fn from(cp: OffsetCheckpoint) -> Self {
        Self::Offset(cp)
    }
}

impl TryFrom<FooterState> for OffsetCheckpoint {
    type Error = ();

    fn try_from(state: FooterState) -> Result<Self, ()> {
        match state {
            FooterState::Offset(cp) => Ok(cp),
            _ => Err(()),
        }
    }
}

impl From<ZipCheckpoint> for FooterState {
    fn from(cp: ZipCheckpoint) -> Self {
        Self::Zip(cp)
    }
}

impl TryFrom<FooterState> for ZipCheckpoint {
    type Error = ();

    fn try_from(state: FooterState) -> Result<Self, ()> {
        match state {
            FooterState::Zip(cp) => Ok(cp),
            _ => Err(()),
        }
    }
}

#[binrw]
#[brw(little, magic = b"SAMLOADR")]
#[br(import(expected_checksum: [u8; 16]))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Footer {
    #[br(temp, assert(version == FOOTER_VERSION))]
    #[bw(calc = FOOTER_VERSION)]
    version: u32,

    #[br(assert(checksum == expected_checksum))]
    checksum: [u8; 16],

    state: FooterState,
}

impl Footer {
    fn new(checksum: [u8; 16]) -> Self {
        Self::with_state(checksum, FooterState::Fresh)
    }

    fn with_state(checksum: [u8; 16], state: FooterState) -> Self {
        Self { checksum, state }
    }

    fn to_bytes(self) -> [u8; FOOTER_SIZE] {
        let mut buf = [0u8; FOOTER_SIZE];
        let mut cursor = Cursor::new(&mut buf[..]);
        self.write(&mut cursor)
            .expect("footer serialization fits within FOOTER_SIZE");
        buf
    }

    fn from_bytes(bytes: &[u8; FOOTER_SIZE], expected_checksum: [u8; 16]) -> Option<Self> {
        let mut cursor = Cursor::new(&bytes[..]);
        let footer = Self::read_args(&mut cursor, (expected_checksum,)).ok()?;
        let end = cursor.position() as usize;
        if bytes[end..].iter().any(|&b| b != 0) {
            return None;
        }
        Some(footer)
    }

    fn read_from_part<R: Read + Seek>(
        reader: &mut R,
        expected_checksum: [u8; 16],
        target_size: u64,
    ) -> Option<Self> {
        let expected_len = target_size.checked_add(FOOTER_SIZE as u64)?;
        if reader.seek(SeekFrom::End(0)).ok()? != expected_len {
            return None;
        }
        reader.seek(SeekFrom::Start(target_size)).ok()?;
        let mut buf = [0u8; FOOTER_SIZE];
        reader.read_exact(&mut buf).ok()?;
        Self::from_bytes(&buf, expected_checksum)
    }
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

fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match read_at(file, buf, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to read whole buffer",
                ));
            }
            Ok(n) => {
                let (_, rest) = buf.split_at_mut(n);
                buf = rest;
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
    // Best-effort: avoids NTFS synchronously zero-filling up to `target_size` on
    // initial footer creation; ignored on filesystems without sparse support.
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

pub(crate) fn part_path_for(final_path: &Path) -> PathBuf {
    let mut s = final_path.as_os_str().to_owned();
    s.push(".part");
    PathBuf::from(s)
}

fn io_with_path(path: &Path, action: &str, err: io::Error) -> io::Error {
    io::Error::new(
        err.kind(),
        format!("failed to {action} '{}': {err}", path.display()),
    )
}

fn open_and_read_footer(
    final_path: &Path,
    part_path: &Path,
    expected_checksum: [u8; 16],
    target_size: u64,
    force: bool,
) -> io::Result<(File, u64, Option<Footer>)> {
    if let Some(parent) = final_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| io_with_path(parent, "create directory", e))?;
    }

    if force {
        // Keep any existing `final_path` intact until the replacement download finishes
        // cleanly and replaces it atomically in `finalize_part_file`.
        let _ = std::fs::remove_file(part_path);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(force)
        .open(part_path)
        .map_err(|e| io_with_path(part_path, "open", e))?;

    let existing_len = file
        .seek(SeekFrom::End(0))
        .map_err(|e| io_with_path(part_path, "seek", e))?;
    let footer = if !force && existing_len > 0 {
        Footer::read_from_part(&mut file, expected_checksum, target_size)
    } else {
        None
    };

    Ok((file, existing_len, footer))
}

fn persist_checkpoint(
    file: &File,
    part_path: &Path,
    checksum: [u8; 16],
    target_size: u64,
    state: FooterState,
    sync_footer: bool,
) -> io::Result<()> {
    // Flush data blocks before advancing the persisted footer so power loss cannot
    // leave a newer checkpoint pointing past unwritten data.
    let result = (|| {
        file.sync_data()?;
        let footer = Footer::with_state(checksum, state);
        write_all_at(file, &footer.to_bytes(), target_size)?;
        if sync_footer {
            file.sync_data()?;
        }
        Ok(())
    })();
    result.map_err(|e| io_with_path(part_path, "persist checkpoint for", e))
}

fn finalize_part_file(
    file: File,
    part_path: &Path,
    final_path: &Path,
    final_size: u64,
) -> io::Result<()> {
    file.set_len(final_size)
        .map_err(|e| io_with_path(part_path, "truncate", e))?;
    #[cfg(windows)]
    set_sparse(&file, false);
    file.sync_data()
        .map_err(|e| io_with_path(part_path, "sync", e))?;
    drop(file);

    // `std::fs::rename` replaces existing files atomically on both Unix and Windows
    // (`SetFileInformationByHandle` / `MoveFileExW` with replace-if-exists).
    std::fs::rename(part_path, final_path).map_err(|e| io_with_path(final_path, "finalize", e))
}

/// Resolves once `cancel_rx` becomes `true`, staying pending forever if the sender is dropped.
pub(crate) async fn wait_cancelled(cancel_rx: &mut watch::Receiver<bool>) {
    if cancel_rx.wait_for(|&cancelled| cancelled).await.is_err() {
        std::future::pending::<()>().await;
    }
}

enum StopReason {
    WriterDead,
    Cancelled,
}

async fn wait_stop(
    writer_dead_rx: &mut oneshot::Receiver<()>,
    cancel_rx: &mut watch::Receiver<bool>,
) -> StopReason {
    match future::select(writer_dead_rx, pin!(wait_cancelled(cancel_rx))).await {
        Either::Left(_) => StopReason::WriterDead,
        Either::Right(_) => StopReason::Cancelled,
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

enum WriteMsg {
    Data(Vec<u8>, usize, Option<FooterState>),
    Checkpoint(FooterState),
    Eof,
}

/// An open `.part` file prepared to receive a [`ResumableAsyncRead`] and atomically
/// rename to its final destination upon verified completion.
pub(crate) struct PartFile {
    file: File,
    part_path: PathBuf,
    final_path: PathBuf,
    checksum: [u8; 16],
    start_pos: u64,
    target_size: u64,
}

enum SetupAction {
    KeepFresh,
    ReadDict { start_pos: u64, dict_len: usize },
    InitFresh { restarted: bool },
}

fn finish_part_setup(
    file: File,
    part_path: &Path,
    action: SetupAction,
    checksum: [u8; 16],
    target_size: u64,
) -> io::Result<(File, Vec<u8>)> {
    if matches!(action, SetupAction::InitFresh { restarted: true }) {
        file.set_len(0)
            .map_err(|e| io_with_path(part_path, "truncate", e))?;
    }
    #[cfg(windows)]
    set_sparse(&file, true);

    let dict = match action {
        SetupAction::KeepFresh => Vec::new(),
        SetupAction::ReadDict {
            start_pos,
            dict_len,
        } => {
            let mut dict = vec![0u8; dict_len];
            if dict_len > 0 {
                read_exact_at(&file, &mut dict, start_pos - dict_len as u64)
                    .map_err(|e| io_with_path(part_path, "read resume dictionary from", e))?;
            }
            dict
        }
        SetupAction::InitFresh { .. } => {
            write_all_at(&file, &Footer::new(checksum).to_bytes(), target_size)
                .map_err(|e| io_with_path(part_path, "initialize", e))?;
            file.sync_data()
                .map_err(|e| io_with_path(part_path, "sync", e))?;
            Vec::new()
        }
    };
    Ok((file, dict))
}

impl PartFile {
    /// Opens or creates `<final_path>.part`, validates any persisted `SAMLOADR` v4
    /// checkpoint against `source`, and loads any required decompression dictionary.
    pub(crate) async fn open<S>(
        final_path: PathBuf,
        checksum: [u8; 16],
        source: &S,
        force: bool,
    ) -> io::Result<(Self, ResumeState<S::Checkpoint>)>
    where
        S: ResumableStream,
        S::Checkpoint: TryFrom<FooterState>,
    {
        let target_size = source.output_size();
        let part_path = part_path_for(&final_path);

        let open_final = final_path.clone();
        let open_part = part_path.clone();
        let (file, existing_len, existing_footer) = tokio::task::spawn_blocking(move || {
            open_and_read_footer(&open_final, &open_part, checksum, target_size, force)
        })
        .await
        .expect("part open task panicked")?;

        let restarted = !force && existing_len > 0;
        let (action, resume_cp) = match existing_footer.map(|f| f.state) {
            Some(FooterState::Fresh) => (SetupAction::KeepFresh, None),
            Some(state) => match S::Checkpoint::try_from(state) {
                Ok(cp) => match source.resume_dict_len(&cp) {
                    Some(dict_len)
                        if cp.source_offset() > 0
                            && cp.output_offset() < target_size
                            && (dict_len as u64) <= cp.output_offset() =>
                    {
                        let start_pos = cp.output_offset();
                        (
                            SetupAction::ReadDict {
                                start_pos,
                                dict_len,
                            },
                            Some(cp),
                        )
                    }
                    _ => (SetupAction::InitFresh { restarted }, None),
                },
                Err(_) => (SetupAction::InitFresh { restarted }, None),
            },
            None => (SetupAction::InitFresh { restarted }, None),
        };

        let is_restarted = matches!(action, SetupAction::InitFresh { restarted: true });
        let needs_blocking = cfg!(windows)
            || match &action {
                SetupAction::KeepFresh => false,
                SetupAction::ReadDict { dict_len, .. } => *dict_len > 0,
                SetupAction::InitFresh { .. } => true,
            };

        let (file, dict) = if needs_blocking {
            let setup_part = part_path.clone();
            tokio::task::spawn_blocking(move || {
                finish_part_setup(file, &setup_part, action, checksum, target_size)
            })
            .await
            .expect("part setup task panicked")?
        } else {
            finish_part_setup(file, &part_path, action, checksum, target_size)?
        };

        let (resume, start_pos) = match resume_cp {
            Some(checkpoint) => {
                let start_pos = checkpoint.output_offset();
                (ResumeState::Resumed { checkpoint, dict }, start_pos)
            }
            None if is_restarted => (ResumeState::Restarted, 0),
            None => (ResumeState::Fresh, 0),
        };

        let part = Self {
            file,
            part_path,
            final_path,
            checksum,
            start_pos,
            target_size,
        };
        Ok((part, resume))
    }

    /// Streams all remaining chunks from `reader` onto a dedicated blocking writer thread,
    /// persisting periodic checkpoints and finalizing the file on EOF.
    pub(crate) async fn write_from<R>(
        self,
        reader: R,
        cancel_rx: watch::Receiver<bool>,
        on_written: impl Fn(u64) + Send + 'static,
    ) -> io::Result<()>
    where
        R: ResumableAsyncRead,
        R::Checkpoint: Into<FooterState>,
    {
        self.write_from_with_interval(reader, CHECKPOINT_INTERVAL, cancel_rx, on_written)
            .await
    }

    async fn write_from_with_interval<R>(
        self,
        mut reader: R,
        checkpoint_interval: u64,
        mut cancel_rx: watch::Receiver<bool>,
        on_written: impl Fn(u64) + Send + 'static,
    ) -> io::Result<()>
    where
        R: ResumableAsyncRead,
        R::Checkpoint: Into<FooterState>,
    {
        let start_pos = self.start_pos;
        let target_size = self.target_size;
        let remaining = target_size.saturating_sub(start_pos);
        // Keep `buf_size >= 1` so `reader.read` still polls EOF/CRC verification
        // even on 0-byte streams or streams already resumed at `target_size`.
        let buf_size = (remaining.min(WRITE_BUF_SIZE as u64) as usize).max(1);
        let slots = (remaining.div_ceil(buf_size as u64) as usize).clamp(1, RING_SLOTS);
        let (data_tx, mut data_rx) = mpsc::channel::<WriteMsg>(slots);
        let (free_tx, mut free_rx) = mpsc::channel::<Vec<u8>>(slots);
        let (writer_alive_tx, mut writer_dead_rx) = oneshot::channel::<()>();
        for _ in 0..slots {
            free_tx
                .try_send(vec![0u8; buf_size])
                .expect("fresh bounded channel has capacity for slots");
        }

        let writer_handle = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let _writer_alive = writer_alive_tx;
            let mut write_pos = self.start_pos;

            while let Some(msg) = data_rx.blocking_recv() {
                match msg {
                    WriteMsg::Data(buf, n, state) => {
                        let blk_len = n as u64;
                        let end_pos = write_pos
                            .checked_add(blk_len)
                            .filter(|&end| end <= self.target_size)
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "stream exceeded declared target size",
                                )
                            })?;
                        write_all_at(&self.file, &buf[..n], write_pos)
                            .map_err(|e| io_with_path(&self.part_path, "write", e))?;
                        write_pos = end_pos;

                        let _ = free_tx.blocking_send(buf);
                        on_written(blk_len);

                        if let Some(state) = state {
                            persist_checkpoint(
                                &self.file,
                                &self.part_path,
                                self.checksum,
                                self.target_size,
                                state,
                                false,
                            )?;
                        }
                    }
                    WriteMsg::Checkpoint(state) => {
                        persist_checkpoint(
                            &self.file,
                            &self.part_path,
                            self.checksum,
                            self.target_size,
                            state,
                            true,
                        )?;
                    }
                    WriteMsg::Eof => {
                        if write_pos != self.target_size {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!(
                                    "incomplete download: wrote {write_pos} of {} bytes",
                                    self.target_size
                                ),
                            ));
                        }
                        finalize_part_file(
                            self.file,
                            &self.part_path,
                            &self.final_path,
                            write_pos,
                        )?;
                        return Ok(());
                    }
                }
            }
            Ok(())
        });

        let read_res: io::Result<()> = async {
            let mut last_persisted_offset = start_pos;
            let mut latest_cp: Option<R::Checkpoint> = None;
            let min_delta = checkpoint_interval.max(1);
            let mut pending_flush: Option<(Vec<u8>, usize)> = None;
            let mut flush_cp = false;

            let loop_res: io::Result<()> = 'outer: loop {
                let mut buf = match future::select(
                    pin!(wait_stop(&mut writer_dead_rx, &mut cancel_rx)),
                    pin!(free_rx.recv()),
                )
                .await
                {
                    Either::Left((StopReason::WriterDead, _)) | Either::Right((None, _)) => {
                        break 'outer Ok(());
                    }
                    Either::Left((StopReason::Cancelled, _)) => {
                        flush_cp = true;
                        break 'outer Err(cancelled_error());
                    }
                    Either::Right((Some(buf), _)) => buf,
                };

                let mut filled = 0;
                let mut hit_eof = false;
                let mut pending_state: Option<FooterState> = None;
                let fill_start = Instant::now();

                while filled < buf.len() {
                    let read_step = match future::select(
                        pin!(wait_stop(&mut writer_dead_rx, &mut cancel_rx)),
                        pin!(reader.read(&mut buf[filled..])),
                    )
                    .await
                    {
                        Either::Left((StopReason::WriterDead, _)) => break 'outer Ok(()),
                        Either::Left((StopReason::Cancelled, _)) => {
                            if filled > 0 {
                                pending_flush = Some((buf, filled));
                            }
                            flush_cp = true;
                            break 'outer Err(cancelled_error());
                        }
                        Either::Right((res, _)) => res,
                    };

                    match read_step {
                        Ok(0) => {
                            hit_eof = true;
                            break;
                        }
                        Ok(n) => {
                            filled += n;
                            if let Some(cp) = reader
                                .checkpoint()
                                .filter(|cp| cp.output_offset() < target_size)
                            {
                                let cp_offset = cp.output_offset();
                                if cp_offset >= last_persisted_offset.saturating_add(min_delta) {
                                    last_persisted_offset = cp_offset;
                                    latest_cp = None;
                                    pending_state = Some(cp.into());
                                    break;
                                }
                                latest_cp = Some(cp);
                            }
                            if fill_start.elapsed() >= COALESCE_MAX_WAIT {
                                break;
                            }
                        }
                        Err(e) => {
                            if e.kind() != io::ErrorKind::InvalidData {
                                if filled > 0 {
                                    pending_flush = Some((buf, filled));
                                }
                                flush_cp = true;
                            }
                            break 'outer Err(e);
                        }
                    }
                }

                if filled > 0
                    && data_tx
                        .send(WriteMsg::Data(buf, filled, pending_state))
                        .await
                        .is_err()
                {
                    break 'outer Ok(());
                }
                if hit_eof {
                    let _ = data_tx.send(WriteMsg::Eof).await;
                    break 'outer Ok(());
                }
            };

            if let Some((buf, filled)) = pending_flush {
                let _ = data_tx.send(WriteMsg::Data(buf, filled, None)).await;
            }
            if flush_cp
                && let Some(cp) = latest_cp.filter(|cp| cp.output_offset() > last_persisted_offset)
            {
                let _ = data_tx.send(WriteMsg::Checkpoint(cp.into())).await;
            }
            loop_res
        }
        .await;

        drop(reader);
        drop(data_tx);
        let write_res = writer_handle.await.expect("disk writer thread panicked");
        write_res.and(read_res)
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

    fn read_part(target_size: u64, footer_bytes: &[u8], checksum: [u8; 16]) -> Option<Footer> {
        let mut part = vec![0u8; target_size as usize];
        part.extend_from_slice(footer_bytes);
        Footer::read_from_part(&mut Cursor::new(part), checksum, target_size)
    }

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
    fn test_footer_v4_round_trip_and_rejection() {
        let checksum = TEST_CHECKSUM;
        let other_checksum = [0x99; 16];
        let target_size = 4096_u64;

        let offset_cp = OffsetCheckpoint::new(2048);

        let mut stored_bytes = [0u8; 13];
        stored_bytes[0] = 0; // Stored
        stored_bytes[1..9].copy_from_slice(&1536u64.to_le_bytes());
        stored_bytes[9..13].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let stored_cp = ZipCheckpoint::read_from(&mut Cursor::new(&stored_bytes)).unwrap();

        let mut deflate_bytes = [0u8; 23];
        deflate_bytes[0] = 1; // Deflate
        deflate_bytes[1..9].copy_from_slice(&1024u64.to_le_bytes());
        deflate_bytes[9..17].copy_from_slice(&3072u64.to_le_bytes());
        deflate_bytes[17..21].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        deflate_bytes[21] = 5;
        deflate_bytes[22] = 0x1A;
        let deflate_cp = ZipCheckpoint::read_from(&mut Cursor::new(&deflate_bytes)).unwrap();

        let mut last_bytes = [0u8; FOOTER_SIZE];
        for state in [
            FooterState::Fresh,
            FooterState::Offset(offset_cp),
            FooterState::Zip(stored_cp),
            FooterState::Zip(deflate_cp),
        ] {
            let mut footer = Footer::new(checksum);
            footer.state = state;
            last_bytes = footer.to_bytes();
            assert_eq!(last_bytes.len(), FOOTER_SIZE);

            let parsed = read_part(target_size, &last_bytes, checksum).unwrap();
            assert_eq!(parsed.state, state);
        }

        // Cross-type checkpoint extraction must reject mismatches
        assert_eq!(
            OffsetCheckpoint::try_from(FooterState::Offset(offset_cp)),
            Ok(offset_cp)
        );
        assert_eq!(
            ZipCheckpoint::try_from(FooterState::Offset(offset_cp)),
            Err(())
        );
        assert_eq!(
            ZipCheckpoint::try_from(FooterState::Zip(deflate_cp)),
            Ok(deflate_cp)
        );
        assert_eq!(
            OffsetCheckpoint::try_from(FooterState::Zip(deflate_cp)),
            Err(())
        );

        // Truncated / overlong part files must be rejected
        assert!(read_part(target_size, &last_bytes[..FOOTER_SIZE - 1], checksum).is_none());
        let mut overlong = last_bytes.to_vec();
        overlong.push(0);
        assert!(read_part(target_size, &overlong, checksum).is_none());

        // Corrupt magic (0), version (8), checksum (12), state tag (28), checkpoint kind (29), trailing padding (63)
        for &(off, val) in &[
            (0, 0xFF),
            (8, 0x03),
            (12, 0xFF),
            (28, 0x09),
            (29, 0x09),
            (FOOTER_SIZE - 1, 0x01),
        ] {
            let mut tampered = last_bytes;
            tampered[off] = val;
            assert!(
                read_part(target_size, &tampered, checksum).is_none(),
                "offset={off}"
            );
        }

        // Checksum mismatch
        assert!(read_part(target_size, &last_bytes, other_checksum).is_none());
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
            let (part, resume) = PartFile::open(final_path.clone(), checksum, &flaky, false)
                .await
                .unwrap();
            assert!(matches!(resume, ResumeState::Fresh));
            let reader = flaky.open().await.unwrap();
            let err = part
                .write_from_with_interval(reader, 16 * 1024, never_cancel(), |_| {})
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
            assert!(!final_path.exists());
            assert!(part_path_for(&final_path).exists());

            // 2. Second attempt resumes from persisted checkpoint and finalizes cleanly
            let healthy = DataStream::new(ChunkedFailSource {
                data: payload.clone(),
                fail_after: None,
            });
            let (part, resume) = PartFile::open(final_path.clone(), checksum, &healthy, false)
                .await
                .unwrap();
            let (cp, dict) = match resume {
                ResumeState::Resumed { checkpoint, dict } => (checkpoint, dict),
                _ => panic!("expected Resumed state"),
            };
            assert!(cp.output_offset() >= 16 * 1024 && cp.output_offset() <= 64 * 1024);
            assert!(dict.is_empty());

            let written = Arc::new(AtomicU64::new(0));
            let written_cb = Arc::clone(&written);
            let reader = healthy.resume(&cp, &dict).await.unwrap();
            part.write_from_with_interval(reader, 16 * 1024, never_cancel(), move |n| {
                written_cb.fetch_add(n, Ordering::Relaxed);
            })
            .await
            .unwrap();
            assert_eq!(
                cp.output_offset() + written.load(Ordering::Relaxed),
                payload.len() as u64
            );
            assert!(!part_path_for(&final_path).exists());
            assert_eq!(std::fs::read(&final_path).unwrap(), payload);

            // 3. Corrupt .part file triggers Restarted; force=true starts Fresh while keeping final_path
            let corrupt_target = dir.0.join("corrupt.bin");
            std::fs::write(&corrupt_target, b"existing good file").unwrap();
            std::fs::write(part_path_for(&corrupt_target), b"corrupt data").unwrap();
            let (_, resume) = PartFile::open(corrupt_target.clone(), checksum, &healthy, false)
                .await
                .unwrap();
            assert!(matches!(resume, ResumeState::Restarted));

            let (_, resume) = PartFile::open(corrupt_target.clone(), checksum, &healthy, true)
                .await
                .unwrap();
            assert!(matches!(resume, ResumeState::Fresh));
            assert_eq!(
                std::fs::read(&corrupt_target).unwrap(),
                b"existing good file"
            );

            // 4. Coalescing + final checkpoint flush on transient error even when interval > written bytes
            let coalesce_target = dir.0.join("coalesce.bin");
            let write_calls = Arc::new(AtomicU64::new(0));
            let write_calls_cb = Arc::clone(&write_calls);
            let (part, _) = PartFile::open(coalesce_target.clone(), checksum, &healthy, false)
                .await
                .unwrap();
            let reader = healthy.open().await.unwrap();
            part.write_from_with_interval(reader, 1024 * 1024, never_cancel(), move |_| {
                write_calls_cb.fetch_add(1, Ordering::Relaxed);
            })
            .await
            .unwrap();
            // 128_000 bytes delivered in 16 KiB chunks coalesces into a single disk write.
            assert_eq!(write_calls.load(Ordering::Relaxed), 1);

            let flush_target = dir.0.join("flush_on_err.bin");
            let (part, _) = PartFile::open(flush_target.clone(), checksum, &flaky, false)
                .await
                .unwrap();
            let reader = flaky.open().await.unwrap();
            let err = part
                .write_from_with_interval(reader, 1024 * 1024, never_cancel(), |_| {})
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
            let (_, resume) = PartFile::open(flush_target, checksum, &healthy, false)
                .await
                .unwrap();
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
            let (part, _) = PartFile::open(cancel_target.clone(), checksum, &healthy, false)
                .await
                .unwrap();
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
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Interrupted);
            let (_, resume) = PartFile::open(cancel_target, checksum, &healthy, false)
                .await
                .unwrap();
            match resume {
                ResumeState::Resumed { checkpoint, .. } => {
                    assert_eq!(checkpoint.output_offset(), 32 * 1024);
                }
                _ => panic!("expected checkpoint saved on cancellation"),
            }

            let invalid_target = dir.0.join("invalid_data.bin");
            let (part, _) = PartFile::open(invalid_target.clone(), checksum, &healthy, false)
                .await
                .unwrap();
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
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            let (_, resume) = PartFile::open(invalid_target, checksum, &healthy, false)
                .await
                .unwrap();
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
                            // Exceeds 4 MiB target_size; fill the slot so it flushes to the
                            // writer while the reader grabs the second slot and hangs on step 3.
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

            let (part, _) = PartFile::open(overflow_target, checksum, &big_source, false)
                .await
                .unwrap();
            let err = tokio::time::timeout(
                Duration::from_secs(2),
                part.write_from_with_interval(
                    OverflowThenHang { step: 0 },
                    CHECKPOINT_INTERVAL,
                    never_cancel(),
                    |_| {},
                ),
            )
            .await
            .expect("writer failure must wake stalled reader without timing out")
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

        // Pre-populate .part with first 4096 bytes and an offset checkpoint at 4096.
        let cp = OffsetCheckpoint::new(4096);
        let mut footer = Footer::new(checksum);
        footer.state = FooterState::Offset(cp);

        let mut part_bytes = vec![0u8; payload.len()];
        part_bytes[..4096].copy_from_slice(&payload[..4096]);
        part_bytes.extend_from_slice(&footer.to_bytes());
        std::fs::write(part_path_for(&final_path), &part_bytes).unwrap();

        rt.block_on(async {
            let (_, resume) = PartFile::open(final_path.clone(), checksum, &src, false)
                .await
                .unwrap();
            match resume {
                ResumeState::Resumed { checkpoint, dict } => {
                    assert_eq!(checkpoint, cp);
                    assert_eq!(dict, &payload[4096 - 512..4096]);
                }
                _ => panic!("expected Resumed state with dictionary"),
            }

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
            .await
            .unwrap();
            assert!(matches!(resume, ResumeState::Restarted));

            // 0-byte stream opens, writes, and finalizes cleanly without empty-buffer stalls.
            let empty_path = dir.0.join("empty.bin");
            let empty_src = DataStream::new(Vec::<u8>::new());
            let (part, resume) = PartFile::open(empty_path.clone(), checksum, &empty_src, false)
                .await
                .unwrap();
            assert!(matches!(resume, ResumeState::Fresh));
            let reader = empty_src.open().await.unwrap();
            part.write_from(reader, watch::channel(false).1, |_| {})
                .await
                .unwrap();
            assert_eq!(std::fs::read(&empty_path).unwrap(), b"");
        });
    }
}
