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

mod footer;

use crate::cli::{ALL_COMPONENTS, DownloadArgs, component_key};
use footer::{
    Footer, FooterState, PartResume, PartTarget, binary_checksum, finalize_part_file,
    prepare_part_file, write_all_at,
};
use indicatif::style::ProgressTracker;
use indicatif::{FormattedDuration, HumanBytes, ProgressBar, ProgressState, ProgressStyle};
use samloader_fus::futures::io::{AsyncRead, AsyncReadExt};
use samloader_fus::{
    DataSource, FusClient, OdinComponent, ParallelDataSource, TransferObserver, TransferWarning,
    ZipArchive, ZipEntryReader, ZipEntrySession, fetch_history,
};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const RAW_PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";
const FILE_PROGRESS_TEMPLATE: &str =
    "{msg}\n[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

const CHECKPOINT_INTERVAL: u64 = 32 * 1024 * 1024;
const WRITE_BUF_SIZE: usize = 2 * 1024 * 1024;
const RING_SLOTS: usize = 16;
const SPEED_SMOOTHING_SECS: f64 = 3.0;

fn exp_weight(age_secs: f64) -> f64 {
    0.1_f64.powf(age_secs / SPEED_SMOOTHING_SECS)
}

#[derive(Clone)]
struct RateEstimator {
    smoothed: f64,
    double_smoothed: f64,
    prev_bytes: u64,
    prev_time: Instant,
    start_time: Instant,
}

impl RateEstimator {
    fn new(now: Instant) -> Self {
        Self {
            smoothed: 0.0,
            double_smoothed: 0.0,
            prev_bytes: 0,
            prev_time: now,
            start_time: now,
        }
    }

    fn reset(&mut self, bytes: u64, now: Instant) {
        self.smoothed = 0.0;
        self.double_smoothed = 0.0;
        self.prev_bytes = bytes;
        self.prev_time = now;
        self.start_time = now;
    }

    fn record(&mut self, bytes: u64, now: Instant) {
        if bytes <= self.prev_bytes || now <= self.prev_time {
            return;
        }
        let dt = (now - self.prev_time).as_secs_f64();
        let instant_rate = (bytes - self.prev_bytes) as f64 / dt;
        let w = exp_weight(dt);
        self.smoothed = self.smoothed * w + instant_rate * (1.0 - w);

        let total_w = 1.0 - exp_weight((now - self.start_time).as_secs_f64());
        if total_w > f64::EPSILON {
            let norm_smoothed = self.smoothed / total_w;
            self.double_smoothed = self.double_smoothed * w + norm_smoothed * (1.0 - w);
        }
        self.prev_bytes = bytes;
        self.prev_time = now;
    }

    fn bytes_per_sec(&self, now: Instant) -> f64 {
        let total_w =
            1.0 - exp_weight(now.saturating_duration_since(self.start_time).as_secs_f64());
        if total_w <= f64::EPSILON {
            return 0.0;
        }
        let dt = now.saturating_duration_since(self.prev_time).as_secs_f64();
        let rw = exp_weight(dt);
        let sps = self.smoothed * rw / total_w;
        let dsps = self.double_smoothed * rw + sps * (1.0 - rw);
        dsps / total_w
    }
}

struct TransferStats {
    wire_bytes: AtomicU64,
    net_comp_bytes: AtomicU64,
    rewind_debt: AtomicU64,
    rem_total_comp: AtomicU64,
    est: Mutex<RateEstimator>,
}

impl TransferStats {
    fn new() -> Self {
        Self {
            wire_bytes: AtomicU64::new(0),
            net_comp_bytes: AtomicU64::new(0),
            rewind_debt: AtomicU64::new(0),
            rem_total_comp: AtomicU64::new(0),
            est: Mutex::new(RateEstimator::new(Instant::now())),
        }
    }

    fn begin_file(&self, rem_total_comp: u64) {
        self.wire_bytes.store(0, Ordering::Relaxed);
        self.net_comp_bytes.store(0, Ordering::Relaxed);
        self.rewind_debt.store(0, Ordering::Relaxed);
        self.rem_total_comp.store(rem_total_comp, Ordering::Relaxed);
        self.est.lock().unwrap().reset(0, Instant::now());
    }
}

#[derive(Clone)]
struct WireSpeedTracker {
    stats: Arc<TransferStats>,
}

impl WireSpeedTracker {
    fn new(stats: Arc<TransferStats>) -> Self {
        Self { stats }
    }

    fn eta_tracker(&self) -> impl ProgressTracker + use<> {
        let stats = Arc::clone(&self.stats);
        move |state: &ProgressState, w: &mut dyn fmt::Write| {
            let eta = if state.is_finished() {
                Duration::ZERO
            } else {
                let rem_total = stats.rem_total_comp.load(Ordering::Relaxed);
                let done_comp = stats.net_comp_bytes.load(Ordering::Relaxed);
                let rem_comp = rem_total.saturating_sub(done_comp);
                let rate = stats.est.lock().unwrap().bytes_per_sec(Instant::now());
                if rate >= 1.0 {
                    Duration::from_secs_f64((rem_comp as f64 / rate).min(u32::MAX as f64))
                } else {
                    Duration::ZERO
                }
            };
            let _ = write!(w, "{}", FormattedDuration(eta));
        }
    }
}

impl ProgressTracker for WireSpeedTracker {
    fn clone_box(&self) -> Box<dyn ProgressTracker> {
        Box::new(self.clone())
    }

    fn tick(&mut self, state: &ProgressState, now: Instant) {
        if !state.is_finished() {
            self.stats
                .est
                .lock()
                .unwrap()
                .record(self.stats.wire_bytes.load(Ordering::Relaxed), now);
        }
    }

    fn reset(&mut self, _state: &ProgressState, now: Instant) {
        self.stats
            .est
            .lock()
            .unwrap()
            .reset(self.stats.wire_bytes.load(Ordering::Relaxed), now);
    }

    fn write(&self, state: &ProgressState, w: &mut dyn fmt::Write) {
        let rate = if state.is_finished() {
            let secs = state.elapsed().as_secs_f64();
            if secs > 0.0 {
                self.stats.wire_bytes.load(Ordering::Relaxed) as f64 / secs
            } else {
                0.0
            }
        } else {
            self.stats.est.lock().unwrap().bytes_per_sec(Instant::now())
        };
        let _ = write!(w, "{}/s", HumanBytes(rate as u64));
    }
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

struct CliObserver {
    pb: Mutex<Option<ProgressBar>>,
    stats: Arc<TransferStats>,
    verbose: bool,
}

impl CliObserver {
    fn new(verbose: bool) -> Self {
        Self {
            pb: Mutex::new(None),
            stats: Arc::new(TransferStats::new()),
            verbose,
        }
    }

    fn start_file(&self, template: &str, rem_total_comp: u64) -> ProgressBar {
        self.stats.begin_file(rem_total_comp);
        let speed_tracker = WireSpeedTracker::new(Arc::clone(&self.stats));
        let eta_tracker = speed_tracker.eta_tracker();
        let style = ProgressStyle::with_template(template)
            .unwrap()
            .with_key("bytes_per_sec", speed_tracker)
            .with_key("eta_precise", eta_tracker);
        let pb = ProgressBar::no_length().with_style(style);
        *self.pb.lock().unwrap() = Some(pb.clone());
        pb
    }

    fn clear_file(&self) {
        *self.pb.lock().unwrap() = None;
    }
}

impl TransferObserver for CliObserver {
    fn on_bytes(&self, bytes: u64) {
        self.stats.wire_bytes.fetch_add(bytes, Ordering::Relaxed);
        let net = consume_rewind_debt(&self.stats.rewind_debt, bytes);
        if net > 0 {
            self.stats.net_comp_bytes.fetch_add(net, Ordering::Relaxed);
        }
    }

    fn on_rewind(&self, bytes: u64) {
        self.stats.rewind_debt.fetch_add(bytes, Ordering::Relaxed);
    }

    fn on_warning(&self, warning: TransferWarning) {
        if !self.verbose {
            return;
        }
        let msg = match warning {
            TransferWarning::Retry {
                offset,
                attempt,
                max_attempts,
                error,
            } => format!(
                "Download error ({error}); retry {attempt}/{max_attempts} at offset {offset}"
            ),
            TransferWarning::Throttled {
                offset,
                remaining_connections,
            } => format!(
                "Connection throttled at offset {offset}; \
                 reducing to {remaining_connections} connection(s)"
            ),
        };
        if let Some(pb) = self.pb.lock().unwrap().clone() {
            pb.println(msg);
        } else {
            eprintln!("{msg}");
        }
    }
}

struct PartWriter {
    file: File,
    part_path: PathBuf,
    final_path: PathBuf,
    footer: Footer,
    start_pos: u64,
    min_size: u64,
    target_size: u64,
}

enum WriteMsg {
    Data(Vec<u8>, usize, Option<FooterState>),
    Eof,
}

enum ChunkReader<'a, R> {
    Raw { reader: R, offset: u64 },
    Entry(ZipEntryReader<'a>),
}

impl<R: AsyncRead + Unpin> ChunkReader<'_, R> {
    async fn read_chunk(
        &mut self,
        buf: &mut [u8],
        want_checkpoint: bool,
    ) -> io::Result<(usize, Option<FooterState>)> {
        match self {
            Self::Raw { reader, offset } => {
                let n = loop {
                    match reader.read(buf).await {
                        Ok(n) => break n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                };
                if n == 0 {
                    return Ok((0, None));
                }
                *offset += n as u64;
                let state = want_checkpoint.then_some(FooterState::Raw(*offset));
                Ok((n, state))
            }
            Self::Entry(reader) => {
                let (n, cp) = reader.read_chunk(buf, want_checkpoint).await?;
                Ok((n, cp.map(FooterState::Entry)))
            }
        }
    }
}

async fn stream_to_writer<R: AsyncRead + Unpin>(
    mut reader: ChunkReader<'_, R>,
    mut w: PartWriter,
    pb: ProgressBar,
) -> io::Result<()> {
    let (data_tx, mut data_rx) = mpsc::channel::<WriteMsg>(RING_SLOTS);
    let (free_tx, mut free_rx) = mpsc::channel::<Vec<u8>>(RING_SLOTS);
    for _ in 0..RING_SLOTS {
        free_tx
            .try_send(vec![0u8; WRITE_BUF_SIZE])
            .expect("fresh bounded channel has capacity for RING_SLOTS");
    }

    let writer_handle = tokio::task::spawn_blocking(move || -> io::Result<()> {
        let mut write_pos = w.start_pos;
        let mut footer_buf = Vec::new();

        while let Some(msg) = data_rx.blocking_recv() {
            match msg {
                WriteMsg::Data(buf, n, state) => {
                    let blk_len = n as u64;
                    let end_pos = write_pos
                        .checked_add(blk_len)
                        .filter(|&end| end <= w.target_size)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "stream exceeded declared target size",
                            )
                        })?;
                    write_all_at(&w.file, &buf[..n], write_pos)?;
                    write_pos = end_pos;

                    let _ = free_tx.blocking_send(buf);
                    pb.inc(blk_len);

                    if let Some(state) = state {
                        w.footer.state = state;
                        w.footer.write_to_vec(&mut footer_buf);
                        write_all_at(&w.file, &footer_buf, w.target_size)?;
                    }
                }
                WriteMsg::Eof => {
                    if write_pos < w.min_size {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "incomplete download: wrote {write_pos} of at least {} bytes",
                                w.min_size
                            ),
                        ));
                    }
                    finalize_part_file(w.file, &w.part_path, &w.final_path, write_pos)?;
                    if write_pos < w.target_size {
                        pb.set_length(write_pos);
                    }
                    pb.set_position(write_pos);
                    return Ok(());
                }
            }
        }
        Ok(())
    });

    let read_res: io::Result<()> = async {
        let mut since_checkpoint = 0u64;
        loop {
            let Some(mut buf) = free_rx.recv().await else {
                break;
            };
            let want_cp = since_checkpoint >= CHECKPOINT_INTERVAL;
            let (n, state) = reader.read_chunk(&mut buf, want_cp).await?;
            if n == 0 {
                let _ = data_tx.send(WriteMsg::Eof).await;
                break;
            }
            if state.is_some() {
                since_checkpoint = 0;
            } else {
                since_checkpoint += n as u64;
            }
            if data_tx.send(WriteMsg::Data(buf, n, state)).await.is_err() {
                break;
            }
        }
        Ok(())
    }
    .await;

    drop(reader);
    drop(data_tx);
    let write_res = writer_handle.await.expect("disk writer thread panicked");
    write_res.and(read_res)
}

enum TransferTarget<'a, S: DataSource> {
    Raw {
        source: &'a S,
        min_size: u64,
        target_size: u64,
    },
    Entry {
        session: ZipEntrySession<'a, S>,
        index: usize,
        total: usize,
    },
}

async fn transfer_file<S: DataSource>(
    observer: &CliObserver,
    target: TransferTarget<'_, S>,
    final_path: PathBuf,
    checksum: [u8; 16],
    force: bool,
) -> Result<(), Box<dyn Error>> {
    let (min_size, target_size, comp_size, part_target) = match &target {
        TransferTarget::Raw {
            min_size,
            target_size,
            ..
        } => (
            *min_size,
            *target_size,
            *target_size,
            PartTarget::Raw {
                target_size: *target_size,
            },
        ),
        TransferTarget::Entry { session, .. } => {
            let e = session.entry();
            (
                e.uncompressed_size(),
                e.uncompressed_size(),
                e.compressed_size(),
                PartTarget::Entry(e.clone()),
            )
        }
    };

    let setup_path = final_path.clone();
    let (file, part_path, footer, part_resume) = tokio::task::spawn_blocking(move || {
        prepare_part_file(&setup_path, checksum, &part_target, force)
    })
    .await
    .expect("part setup task panicked")?;

    let (resumed_comp, resumed_uncomp, restarted) = match &part_resume {
        PartResume::Fresh => (0, 0, false),
        PartResume::Restarted => (0, 0, true),
        PartResume::Raw(offset) => (*offset, *offset, false),
        PartResume::Entry { checkpoint, .. } => (
            checkpoint.compressed_offset(),
            checkpoint.uncompressed_offset(),
            false,
        ),
    };

    let label = match &target {
        TransferTarget::Entry {
            session,
            index,
            total,
        } => Some((session.entry().name(), *index, *total)),
        TransferTarget::Raw { .. } => None,
    };

    let rem_total_comp = comp_size.saturating_sub(resumed_comp);
    let template = if label.is_some() {
        FILE_PROGRESS_TEMPLATE
    } else {
        RAW_PROGRESS_TEMPLATE
    };
    let pb = observer.start_file(template, rem_total_comp);
    pb.set_length(target_size);

    if let Some((name, idx, total)) = label {
        pb.set_message(format!("[{}/{total}] Extracting {name}", idx + 1));
    }

    if restarted {
        pb.println(
            "Existing partial download is incompatible or corrupted, restarting from scratch...",
        );
    }
    if resumed_uncomp > 0 {
        let pct = if target_size > 0 {
            (resumed_uncomp as f64 / target_size as f64) * 100.0
        } else {
            100.0
        };
        pb.println(format!(
            "Resuming: {} / {} ({pct:.1}%) already on disk",
            HumanBytes(resumed_uncomp),
            HumanBytes(target_size),
        ));
        pb.set_position(resumed_uncomp);
    }
    pb.enable_steady_tick(Duration::from_secs(1));

    let writer = PartWriter {
        file,
        part_path,
        final_path,
        footer,
        start_pos: resumed_uncomp,
        min_size,
        target_size,
    };
    let res: io::Result<()> = async {
        match (target, part_resume) {
            (TransferTarget::Raw { source, .. }, resume) => {
                let offset = match resume {
                    PartResume::Raw(off) => off,
                    _ => 0,
                };
                let reader = source.fetch_range(offset..).await?;
                stream_to_writer(ChunkReader::Raw { reader, offset }, writer, pb.clone()).await
            }
            (TransferTarget::Entry { session, .. }, resume) => {
                let reader = match resume {
                    PartResume::Entry { checkpoint, dict } => {
                        session.resume(&checkpoint, &dict).await?
                    }
                    _ => session.fetch().await?,
                };
                stream_to_writer(
                    ChunkReader::<samloader_fus::futures::io::Empty>::Entry(reader),
                    writer,
                    pb.clone(),
                )
                .await
            }
        }
    }
    .await;
    observer.clear_file();

    if let Err(e) = res {
        if let Some((name, idx, total)) = label {
            pb.abandon_with_message(format!("[{}/{total}] Failed to extract {name}", idx + 1));
        } else {
            pb.abandon();
        }
        eprintln!();
        return Err(format!("Download failed: {e}").into());
    }

    if let Some((name, idx, total)) = label {
        pb.set_message(format!("[{}/{total}] Extracted {name}", idx + 1));
        pb.finish();
        if idx + 1 < total {
            eprintln!();
        }
    } else {
        pb.finish();
    }

    Ok(())
}

/// Downloads and decrypts (and by default extracts) a firmware from Samsung's update servers.
pub(crate) async fn run(args: DownloadArgs, verbose: bool) -> Result<(), Box<dyn Error>> {
    let version = match &args.version {
        Some(v) => v.clone(),
        None => {
            let version_info = fetch_history(&args.fus.model, &args.fus.region)
                .await
                .map_err(|e| format!("Failed to fetch version info: {e}"))?;
            version_info.latest
        }
    };

    let client = FusClient::new()
        .await
        .map_err(|e| format!("Unable to establish FusClient: {e}"))?;
    let info = client
        .fetch_binary_info(&args.fus.model, &args.fus.region, &version)
        .await
        .map_err(|e| format!("Failed to fetch binary info: {e}"))?;

    println!("Firmware Version: {}", info.version);

    let zip_name = info
        .filename
        .strip_suffix(".enc4")
        .or_else(|| info.filename.strip_suffix(".enc2"))
        .unwrap_or(info.filename.as_str())
        .to_string();

    let concurrency = args.threads.max(1).min(usize::MAX as u64) as usize;
    let checksum = binary_checksum(&info);
    let observer = Arc::new(CliObserver::new(verbose));

    if args.no_extract {
        let final_path = match (&args.out_file, &args.out_dir) {
            (Some(name), _) => PathBuf::from(name),
            (None, Some(dir)) => PathBuf::from(dir).join(&zip_name),
            (None, None) => PathBuf::from(&zip_name),
        };

        if !args.force
            && let Ok(meta) = final_path.metadata()
            && meta.is_file()
            && (info.size.saturating_sub(16)..=info.size).contains(&meta.len())
        {
            println!(
                "File already exists and is complete: {}",
                final_path.display()
            );
            return Ok(());
        }

        println!("Downloading {} to {}", info.filename, final_path.display());

        let session = client
            .init_download(info)
            .await
            .map_err(|e| format!("Failed to initialize download: {e}"))?;
        let (min_size, target_size) = session.size_bounds();
        let parallel =
            ParallelDataSource::new(session, concurrency).with_observer(Arc::clone(&observer) as _);

        return transfer_file(
            &observer,
            TransferTarget::Raw {
                source: &parallel,
                min_size,
                target_size,
            },
            final_path,
            checksum,
            args.force,
        )
        .await;
    }

    let out_dir = match &args.out_dir {
        Some(dir) => PathBuf::from(dir),
        None => {
            let zip_stem = zip_name
                .strip_suffix(".zip")
                .or_else(|| zip_name.strip_suffix(".ZIP"))
                .unwrap_or(&zip_name);
            PathBuf::from(zip_stem)
        }
    };

    let filename = info.filename.clone();
    let session = client
        .init_download(info)
        .await
        .map_err(|e| format!("Failed to initialize download: {e}"))?;
    let parallel =
        ParallelDataSource::new(session, concurrency).with_observer(Arc::clone(&observer) as _);
    let archive = ZipArchive::open(parallel)
        .await
        .map_err(|e| format!("Failed to open firmware archive: {e}"))?;

    let selected: Vec<_> = if args.select.is_empty() {
        archive.entries().iter().collect()
    } else {
        let mut list = Vec::new();
        for (i, &component) in args.select.iter().enumerate() {
            if args.select[..i].contains(&component) {
                continue;
            }
            let before = list.len();
            list.extend(
                archive
                    .entries()
                    .iter()
                    .filter(|e| OdinComponent::from_entry_name(e.name()) == Some(component)),
            );
            if list.len() == before {
                let avail: Vec<_> = ALL_COMPONENTS
                    .iter()
                    .copied()
                    .filter(|c| {
                        archive
                            .entries()
                            .iter()
                            .any(|e| OdinComponent::from_entry_name(e.name()) == Some(*c))
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
                )
                .into());
            }
        }
        list
    };

    let mut pending = Vec::new();
    for entry in selected {
        let final_path = out_dir.join(entry.name());
        if !args.force
            && let Ok(meta) = final_path.metadata()
            && meta.is_file()
            && meta.len() == entry.uncompressed_size()
        {
            println!(
                "File already exists and is complete: {}",
                final_path.display()
            );
            continue;
        }
        let sess = archive
            .open_entry(entry)
            .await
            .map_err(|e| format!("Failed to open archive entry '{}': {e}", entry.name()))?;
        pending.push((sess, final_path));
    }

    if pending.is_empty() {
        return Ok(());
    }

    let total_files = pending.len();
    println!(
        "Downloading {filename} ({total_files} file(s)) to {}\n",
        out_dir.display()
    );

    for (idx, (session, final_path)) in pending.into_iter().enumerate() {
        transfer_file(
            &observer,
            TransferTarget::Entry {
                session,
                index: idx,
                total: total_files,
            },
            final_path,
            checksum,
            args.force,
        )
        .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_observer_multi_file_compression_split_and_resumed_speed() {
        let gib = 1024 * 1024 * 1024_u64;
        let mib = 1024 * 1024_u64;
        let obs = CliObserver::new(false);

        // File 1: 30 GiB uncompressed (10 GiB compressed, 3:1 ratio), resumed with
        // 30 MiB uncompressed (10 MiB compressed) remaining.
        let target_uncomp = 30 * gib;
        let resumed_uncomp = target_uncomp - 30 * mib;
        let pb1 = obs.start_file(FILE_PROGRESS_TEMPLATE, 10 * mib);
        pb1.set_draw_target(indicatif::ProgressDrawTarget::hidden());
        pb1.set_length(target_uncomp);
        pb1.set_position(resumed_uncomp);
        pb1.reset_eta();

        obs.on_bytes(4 * mib);
        assert_eq!(obs.stats.wire_bytes.load(Ordering::Relaxed), 4 * mib);
        assert_eq!(obs.stats.net_comp_bytes.load(Ordering::Relaxed), 4 * mib);

        obs.on_rewind(mib);
        obs.on_bytes(512 * 1024);
        assert_eq!(obs.stats.net_comp_bytes.load(Ordering::Relaxed), 4 * mib);
        assert_eq!(
            obs.stats.wire_bytes.load(Ordering::Relaxed),
            4 * mib + 512 * 1024
        );

        obs.on_bytes(512 * 1024 + 6 * mib);
        assert_eq!(obs.stats.net_comp_bytes.load(Ordering::Relaxed), 10 * mib);
        assert_eq!(obs.stats.wire_bytes.load(Ordering::Relaxed), 11 * mib);

        pb1.inc(30 * mib);
        assert_eq!(pb1.position(), target_uncomp);
        pb1.set_elapsed(Duration::from_secs(2));
        pb1.finish();
        obs.clear_file();

        let tracker = WireSpeedTracker::new(Arc::clone(&obs.stats));
        let mut formatted1 = String::new();
        pb1.update(|state| tracker.write(state, &mut formatted1));
        assert!(
            formatted1.starts_with("5.5") && formatted1.ends_with("MiB/s"),
            "unexpected file 1 final speed: {formatted1}"
        );

        // File 2: Advancing the same CliObserver to the next file resets counters cleanly
        let pb2 = obs.start_file(FILE_PROGRESS_TEMPLATE, 8 * mib);
        pb2.set_draw_target(indicatif::ProgressDrawTarget::hidden());
        pb2.set_length(16 * mib);
        assert_eq!(obs.stats.wire_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(obs.stats.net_comp_bytes.load(Ordering::Relaxed), 0);

        obs.on_bytes(8 * mib);
        pb2.inc(16 * mib);
        pb2.set_elapsed(Duration::from_secs(1));
        pb2.finish();
        obs.clear_file();

        let mut formatted2 = String::new();
        pb2.update(|state| tracker.write(state, &mut formatted2));
        assert!(
            formatted2.starts_with("8.0") && formatted2.ends_with("MiB/s"),
            "unexpected file 2 final speed: {formatted2}"
        );
    }

    #[test]
    fn test_rate_estimator_short_window_convergence() {
        let mib = 1024 * 1024_u64;
        let t0 = Instant::now();
        let mut est = RateEstimator::new(t0);
        let mut total = 0_u64;

        // 5 seconds at 400 MiB/s (sampled at 1 Hz)
        for sec in 1..=5 {
            total += 400 * mib;
            est.record(total, t0 + Duration::from_secs(sec));
        }
        let burst = est.bytes_per_sec(t0 + Duration::from_secs(5)) / mib as f64;
        assert!((burst - 400.0).abs() < 1.0, "burst={burst}");

        // Drop abruptly to 80 MiB/s: within 5s, 3s double-EWA converges near 80 MiB/s
        for sec in 6..=10 {
            total += 80 * mib;
            est.record(total, t0 + Duration::from_secs(sec));
        }
        let settled = est.bytes_per_sec(t0 + Duration::from_secs(10)) / mib as f64;
        assert!(
            (80.0..=120.0).contains(&settled),
            "expected rapid convergence near 80 MiB/s, got {settled}"
        );
    }
}
