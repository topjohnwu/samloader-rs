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

mod part;
mod progress;

use crate::cli::{ALL_COMPONENTS, DownloadArgs, OdinComponent, component_key};
use part::{CheckpointState, PartFile, ResumeState, part_path_for, wait_cancelled};
use progress::{CliObserver, FileLabel};
use samloader_fus::futures::future::{self, Either, try_join_all};
use samloader_fus::{
    BinaryInform, Checkpoint, DataStream, DownloadSession, FusClient, ParallelDataSource,
    ReqwestClient, ResumableStream, ZipArchive, ZipEntry,
};
use std::error::Error;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use tokio::sync::watch;

fn is_complete(path: &Path, size_bounds: (u64, u64)) -> bool {
    let (min_size, max_size) = size_bounds;
    !part_path_for(path).exists()
        && path
            .metadata()
            .is_ok_and(|meta| meta.is_file() && (min_size..=max_size).contains(&meta.len()))
}

struct CancelGuard {
    rx: watch::Receiver<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl CancelGuard {
    fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = tx.send(true);
            }
        });
        Self { rx, task }
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn cancellable_io<T>(
    cancel_rx: &mut watch::Receiver<bool>,
    fut: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match future::select(pin!(wait_cancelled(cancel_rx)), pin!(fut)).await {
        Either::Left(_) => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "download interrupted",
        )),
        Either::Right((res, _)) => res,
    }
}

async fn init_parallel_source(
    client: FusClient<ReqwestClient>,
    info: BinaryInform,
    concurrency: usize,
    observer: &Arc<CliObserver>,
) -> Result<ParallelDataSource<DownloadSession<ReqwestClient>>, Box<dyn Error>> {
    let session = client
        .init_download(info)
        .await
        .map_err(|e| format!("Failed to initialize download: {e}"))?;
    Ok(ParallelDataSource::new(session, concurrency).with_observer(Arc::clone(observer)))
}

fn select_entries<'a>(
    entries: &'a [ZipEntry],
    select: &[OdinComponent],
) -> Result<Vec<&'a ZipEntry>, String> {
    if select.is_empty() {
        return Ok(entries.iter().collect());
    }

    let mut list = Vec::new();
    for (i, &component) in select.iter().enumerate() {
        if select[..i].contains(&component) {
            continue;
        }
        let before = list.len();
        list.extend(
            entries
                .iter()
                .filter(|e| OdinComponent::from_entry_name(e.name()) == Some(component)),
        );
        if list.len() == before {
            let avail: Vec<_> = ALL_COMPONENTS
                .iter()
                .copied()
                .filter(|&c| {
                    entries
                        .iter()
                        .any(|e| OdinComponent::from_entry_name(e.name()) == Some(c))
                })
                .map(component_key)
                .collect();
            let avail_list = if avail.is_empty() {
                "none".to_string()
            } else {
                avail.join(", ")
            };
            return Err(format!(
                "Component '{}' not found in firmware archive (available: {avail_list})",
                component_key(component)
            ));
        }
    }
    Ok(list)
}

async fn transfer_file<S>(
    source: &S,
    final_path: PathBuf,
    checksum: [u8; 16],
    force: bool,
    observer: &CliObserver,
    label: Option<FileLabel<'_>>,
    cancel_rx: &mut watch::Receiver<bool>,
) -> Result<(), Box<dyn Error>>
where
    S: ResumableStream,
    S::Checkpoint: Into<CheckpointState> + TryFrom<CheckpointState>,
{
    if *cancel_rx.borrow() {
        return Err("Download interrupted".into());
    }

    let target_size = source.output_size();
    let (part, resume) = PartFile::open(final_path, checksum, source, force)?;

    let (resumed_wire, resumed_out) = match &resume {
        ResumeState::Resumed { checkpoint, .. } => {
            (checkpoint.source_offset(), checkpoint.output_offset())
        }
        ResumeState::Fresh | ResumeState::Restarted => (0, 0),
    };

    let progress = observer.start_transfer(
        label,
        target_size,
        source.source_size().saturating_sub(resumed_wire),
        resumed_out,
        matches!(resume, ResumeState::Restarted),
    );

    let write_cancel = cancel_rx.clone();
    let res = async {
        match resume {
            ResumeState::Resumed { checkpoint, dict } => {
                let reader = cancellable_io(cancel_rx, source.resume(&checkpoint, &dict)).await?;
                drop(dict);
                part.write_from(reader, write_cancel, progress.on_written())
            }
            ResumeState::Fresh | ResumeState::Restarted => {
                let reader = cancellable_io(cancel_rx, source.open()).await?;
                part.write_from(reader, write_cancel, progress.on_written())
            }
        }
    }
    .await;

    match res {
        Ok(()) => {
            progress.finish();
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::Interrupted && *cancel_rx.borrow() => {
            progress.interrupt();
            Err("Download interrupted".into())
        }
        Err(e) => {
            progress.abandon();
            Err(format!("Download failed: {e}").into())
        }
    }
}

async fn download_raw(
    client: FusClient<ReqwestClient>,
    info: BinaryInform,
    args: &DownloadArgs,
    concurrency: usize,
    checksum: [u8; 16],
    observer: Arc<CliObserver>,
) -> Result<(), Box<dyn Error>> {
    let zip_name = info.decrypted_filename();
    let final_path = match (&args.out_file, &args.out_dir) {
        (Some(name), _) => PathBuf::from(name),
        (None, Some(dir)) => PathBuf::from(dir).join(zip_name),
        (None, None) => PathBuf::from(zip_name),
    };

    if !args.force && is_complete(&final_path, info.decrypted_size_bounds()) {
        println!(
            "File already exists and is complete: {}",
            final_path.display()
        );
        return Ok(());
    }

    println!(
        "Downloading {} to {}",
        info.filename(),
        final_path.display()
    );

    let parallel = init_parallel_source(client, info, concurrency, &observer).await?;
    let stream = DataStream::new(parallel);
    let mut cancel = CancelGuard::new();

    transfer_file(
        &stream,
        final_path,
        checksum,
        args.force,
        &observer,
        None,
        &mut cancel.rx,
    )
    .await
}

async fn download_archive(
    client: FusClient<ReqwestClient>,
    info: BinaryInform,
    args: &DownloadArgs,
    concurrency: usize,
    checksum: [u8; 16],
    observer: Arc<CliObserver>,
) -> Result<(), Box<dyn Error>> {
    let out_dir = match &args.out_dir {
        Some(dir) => PathBuf::from(dir),
        None => {
            let zip_name = info.decrypted_filename();
            let zip_stem = zip_name
                .strip_suffix(".zip")
                .or_else(|| zip_name.strip_suffix(".ZIP"))
                .unwrap_or(zip_name);
            PathBuf::from(zip_stem)
        }
    };

    let filename = info.filename().to_owned();
    let parallel = init_parallel_source(client, info, concurrency, &observer).await?;
    let archive = ZipArchive::open(parallel)
        .await
        .map_err(|e| format!("Failed to open firmware archive: {e}"))?;

    let selected = select_entries(archive.entries(), &args.select)?;

    let mut to_open = Vec::new();
    for entry in selected {
        let final_path = out_dir.join(entry.name());
        let size = entry.uncompressed_size();
        if !args.force && is_complete(&final_path, (size, size)) {
            println!(
                "File already exists and is complete: {}",
                final_path.display()
            );
            continue;
        }
        to_open.push((entry, final_path));
    }

    if to_open.is_empty() {
        return Ok(());
    }

    let pending = try_join_all(to_open.into_iter().map(|(entry, final_path)| {
        let archive = &archive;
        async move {
            let stream = archive
                .open_entry(entry)
                .await
                .map_err(|e| format!("Failed to open archive entry '{}': {e}", entry.name()))?;
            Ok::<_, String>((stream, final_path))
        }
    }))
    .await?;

    let total = pending.len();
    println!(
        "Downloading {filename} ({total} file(s)) to {}\n",
        out_dir.display()
    );

    let mut cancel = CancelGuard::new();
    for (index, (stream, final_path)) in pending.into_iter().enumerate() {
        let label = FileLabel {
            name: stream.entry().name(),
            index,
            total,
        };
        transfer_file(
            &stream,
            final_path,
            checksum,
            args.force,
            &observer,
            Some(label),
            &mut cancel.rx,
        )
        .await?;
    }

    Ok(())
}

/// Downloads and decrypts (and by default extracts) a firmware from Samsung's update servers.
pub(crate) async fn run(args: DownloadArgs, verbose: bool) -> Result<(), Box<dyn Error>> {
    let client = FusClient::new()
        .await
        .map_err(|e| format!("Unable to establish FusClient: {e}"))?;
    let version = match &args.version {
        Some(v) => v.clone(),
        None => {
            let version_info = client
                .fetch_history(&args.fus.model, &args.fus.region)
                .await
                .map_err(|e| format!("Failed to fetch version info: {e}"))?;
            version_info.latest
        }
    };
    let info = client
        .fetch_binary_info(&args.fus.model, &args.fus.region, &version)
        .await
        .map_err(|e| format!("Failed to fetch binary info: {e}"))?;

    println!("Firmware Version: {}", info.version());

    let concurrency = args.threads.max(1).min(usize::MAX as u64) as usize;
    let checksum = info.fingerprint();
    let observer = Arc::new(CliObserver::new(verbose));

    if args.no_extract {
        download_raw(client, info, &args, concurrency, checksum, observer).await
    } else {
        download_archive(client, info, &args, concurrency, checksum, observer).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use samloader_fus::futures::executor::block_on;

    fn build_empty_zip(names: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for &name in names {
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len() as u16;
            let local_offset = out.len() as u32;

            // Local File Header (30 bytes + name)
            out.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
            out.extend_from_slice(&20_u16.to_le_bytes());
            out.extend_from_slice(&[0u8; 20]); // flags, method=STORE, time/date, crc, sizes
            out.extend_from_slice(&name_len.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(name_bytes);

            // Central Directory File Header (46 bytes + name)
            cd.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
            cd.extend_from_slice(&20_u16.to_le_bytes());
            cd.extend_from_slice(&20_u16.to_le_bytes());
            cd.extend_from_slice(&[0u8; 20]); // flags, method=STORE, time/date, crc, sizes
            cd.extend_from_slice(&name_len.to_le_bytes());
            cd.extend_from_slice(&[0u8; 12]); // extra, comment, disk, attrs
            cd.extend_from_slice(&local_offset.to_le_bytes());
            cd.extend_from_slice(name_bytes);
        }

        let cd_offset = out.len() as u32;
        let cd_size = cd.len() as u32;
        out.extend_from_slice(&cd);

        // End of Central Directory (22 bytes)
        let count = names.len() as u16;
        out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out
    }

    #[test]
    fn test_select_entries_order_dedup_and_missing_error() {
        let zip = build_empty_zip(&[
            "BL_test.tar.md5",
            "AP_test.tar.md5",
            "HOME_CSC_test.tar.md5",
            "SS_DL.dll",
        ]);
        let archive = block_on(ZipArchive::open(zip)).unwrap();
        let entries = archive.entries();

        // Empty selection returns all entries in archive order.
        let all: Vec<_> = select_entries(entries, &[])
            .unwrap()
            .into_iter()
            .map(ZipEntry::name)
            .collect();
        assert_eq!(
            all,
            [
                "BL_test.tar.md5",
                "AP_test.tar.md5",
                "HOME_CSC_test.tar.md5",
                "SS_DL.dll"
            ]
        );

        // Explicit selection preserves requested order and deduplicates repeated keys.
        let picked: Vec<_> = select_entries(
            entries,
            &[
                OdinComponent::HomeCsc,
                OdinComponent::Bl,
                OdinComponent::HomeCsc,
            ],
        )
        .unwrap()
        .into_iter()
        .map(ZipEntry::name)
        .collect();
        assert_eq!(picked, ["HOME_CSC_test.tar.md5", "BL_test.tar.md5"]);

        // Missing component returns a descriptive error listing available components.
        let err = select_entries(entries, &[OdinComponent::Cp]).unwrap_err();
        assert!(err.contains("'cp'"), "err={err}");
        assert!(err.contains("bl, ap, home_csc"), "err={err}");
    }

    #[test]
    fn test_is_complete_respects_active_part_file() {
        let dir = std::env::temp_dir().join(format!(
            "samloader-download-complete-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let file = dir.join("fw.zip");
        std::fs::write(&file, vec![0u8; 100]).unwrap();
        assert!(is_complete(&file, (90, 100)));
        assert!(!is_complete(&file, (101, 200)));

        // Presence of a sibling `.part` file means an interrupted `--force` download
        // is still in progress and must not be skipped as complete.
        let part = part_path_for(&file);
        std::fs::write(&part, b"in-progress").unwrap();
        assert!(!is_complete(&file, (90, 100)));

        std::fs::remove_file(&part).unwrap();
        assert!(is_complete(&file, (90, 100)));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
