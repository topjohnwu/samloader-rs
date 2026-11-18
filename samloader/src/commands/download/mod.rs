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

use crate::cli::DownloadArgs;
use footer::{
    FOOTER_SIZE, Footer, PartState, finalize_part_file, prepare_part_file, raw_checksum,
    write_all_at,
};
use indicatif::style::ProgressTracker;
use indicatif::{FormattedDuration, HumanBytes, ProgressBar, ProgressState, ProgressStyle};
use samloader_fus::futures::io::{AsyncRead, AsyncReadExt};
use samloader_fus::{
    DataSource, FusClient, ParallelDataSource, TransferObserver, TransferWarning, fetch_history,
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

const PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

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

#[derive(Clone)]
struct WireSpeedTracker {
    wire_bytes: Arc<AtomicU64>,
    est: Arc<Mutex<RateEstimator>>,
}

impl WireSpeedTracker {
    fn new(wire_bytes: Arc<AtomicU64>) -> Self {
        Self {
            wire_bytes,
            est: Arc::new(Mutex::new(RateEstimator::new(Instant::now()))),
        }
    }

    fn eta_tracker(&self) -> impl ProgressTracker + use<> {
        let est = Arc::clone(&self.est);
        move |state: &ProgressState, w: &mut dyn fmt::Write| {
            let eta = if state.is_finished() {
                Duration::ZERO
            } else {
                let rem = state.len().unwrap_or(0).saturating_sub(state.pos());
                let rate = est.lock().unwrap().bytes_per_sec(Instant::now());
                if rate >= 1.0 {
                    Duration::from_secs_f64((rem as f64 / rate).min(u32::MAX as f64))
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
            self.est
                .lock()
                .unwrap()
                .record(self.wire_bytes.load(Ordering::Relaxed), now);
        }
    }

    fn reset(&mut self, _state: &ProgressState, now: Instant) {
        self.est
            .lock()
            .unwrap()
            .reset(self.wire_bytes.load(Ordering::Relaxed), now);
    }

    fn write(&self, state: &ProgressState, w: &mut dyn fmt::Write) {
        let rate = if state.is_finished() {
            let secs = state.elapsed().as_secs_f64();
            if secs > 0.0 {
                self.wire_bytes.load(Ordering::Relaxed) as f64 / secs
            } else {
                0.0
            }
        } else {
            self.est.lock().unwrap().bytes_per_sec(Instant::now())
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
    pb: ProgressBar,
    wire_bytes: Arc<AtomicU64>,
    rewind_debt: AtomicU64,
    verbose: bool,
}

impl CliObserver {
    fn new(pb: ProgressBar, wire_bytes: Arc<AtomicU64>, verbose: bool) -> Self {
        Self {
            pb,
            wire_bytes,
            rewind_debt: AtomicU64::new(0),
            verbose,
        }
    }
}

impl TransferObserver for CliObserver {
    fn on_bytes(&self, bytes: u64) {
        self.wire_bytes.fetch_add(bytes, Ordering::Relaxed);
        let net = consume_rewind_debt(&self.rewind_debt, bytes);
        if net > 0 {
            self.pb.inc(net);
        }
    }

    fn on_rewind(&self, bytes: u64) {
        self.rewind_debt.fetch_add(bytes, Ordering::Relaxed);
    }

    fn on_warning(&self, warning: TransferWarning) {
        if !self.verbose {
            return;
        }
        match warning {
            TransferWarning::Retry {
                offset,
                attempt,
                max_attempts,
                error,
            } => {
                self.pb.println(format!(
                    "Download error ({error}); retry {attempt}/{max_attempts} at offset {offset}"
                ));
            }
            TransferWarning::Throttled {
                offset,
                remaining_connections,
            } => {
                self.pb.println(format!(
                    "Connection throttled at offset {offset}; \
                     reducing to {remaining_connections} connection(s)"
                ));
            }
        }
    }
}

struct ActiveWriter {
    file: File,
    part_path: PathBuf,
    final_path: PathBuf,
    footer: Footer,
    footer_buf: [u8; FOOTER_SIZE],
    min_size: u64,
    target_size: u64,
    write_pos: u64,
    since_checkpoint: u64,
}

enum WriteMsg {
    Data(Vec<u8>, usize),
    Eof,
}

fn format_gib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

async fn stream_to_writer<R: AsyncRead + Unpin>(
    mut reader: R,
    mut w: ActiveWriter,
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
        while let Some(msg) = data_rx.blocking_recv() {
            match msg {
                WriteMsg::Data(buf, n) => {
                    let blk_len = n as u64;
                    let end_pos = w
                        .write_pos
                        .checked_add(blk_len)
                        .filter(|&end| end <= w.target_size)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "stream exceeded declared target size",
                            )
                        })?;
                    write_all_at(&w.file, &buf[..n], w.write_pos)?;
                    w.write_pos = end_pos;
                    let _ = free_tx.blocking_send(buf);

                    w.since_checkpoint += blk_len;
                    if w.since_checkpoint >= CHECKPOINT_INTERVAL {
                        w.footer.offset = w.write_pos;
                        w.footer.write_to_slice(&mut w.footer_buf);
                        write_all_at(&w.file, &w.footer_buf, w.target_size)?;
                        w.since_checkpoint = 0;
                    }
                }
                WriteMsg::Eof => {
                    if w.write_pos < w.min_size {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "incomplete download: wrote {} of at least {} bytes",
                                w.write_pos, w.min_size
                            ),
                        ));
                    }
                    finalize_part_file(w.file, &w.part_path, &w.final_path, w.write_pos)?;
                    if w.write_pos < w.target_size {
                        pb.set_length(w.write_pos);
                    }
                    pb.set_position(w.write_pos);
                    return Ok(());
                }
            }
        }
        Ok(())
    });

    let read_res: io::Result<()> = async {
        loop {
            let Some(mut buf) = free_rx.recv().await else {
                break;
            };
            let n = loop {
                match reader.read(&mut buf).await {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            };
            if n == 0 {
                let _ = data_tx.send(WriteMsg::Eof).await;
                break;
            }
            if data_tx.send(WriteMsg::Data(buf, n)).await.is_err() {
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

/// Downloads and decrypts a firmware from Samsung's update servers.
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
        .unwrap_or(info.filename.as_str());

    let final_path = match (&args.out_file, &args.out_dir) {
        (Some(name), _) => PathBuf::from(name),
        (None, Some(dir)) => PathBuf::from(dir).join(zip_name),
        (None, None) => PathBuf::from(zip_name),
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

    let info_ref = session.info();
    let checksum = raw_checksum(info_ref);
    let (min_size, target_size) = session.size_bounds();
    let force = args.force;
    let setup_path = final_path.clone();
    let (file, part_path, footer, part_state) = tokio::task::spawn_blocking(move || {
        prepare_part_file(&setup_path, checksum, target_size, force)
    })
    .await
    .expect("part setup task panicked")?;

    let resumed_bytes = footer.offset;
    let wire_bytes = Arc::new(AtomicU64::new(0));
    let speed_tracker = WireSpeedTracker::new(Arc::clone(&wire_bytes));
    let eta_tracker = speed_tracker.eta_tracker();
    let style = ProgressStyle::with_template(PROGRESS_TEMPLATE)
        .unwrap()
        .with_key("bytes_per_sec", speed_tracker)
        .with_key("eta_precise", eta_tracker);
    let pb = ProgressBar::no_length().with_style(style);
    if part_state == PartState::Restarted {
        pb.println(
            "Existing partial download is incompatible or corrupted, restarting from scratch...",
        );
    }
    if resumed_bytes > 0 {
        let pct = if target_size > 0 {
            (resumed_bytes as f64 / target_size as f64) * 100.0
        } else {
            100.0
        };
        pb.println(format!(
            "Resuming download: {:.2} GiB / {:.2} GiB ({pct:.1}%) already downloaded",
            format_gib(resumed_bytes),
            format_gib(target_size),
        ));
        pb.set_length(target_size);
        pb.set_position(resumed_bytes);
        pb.reset_eta();
    } else {
        pb.set_length(target_size);
    }
    pb.enable_steady_tick(Duration::from_secs(1));

    let concurrency = args.threads.max(1).min(usize::MAX as u64) as usize;
    let observer = Arc::new(CliObserver::new(pb.clone(), wire_bytes, verbose));
    let parallel = ParallelDataSource::new(session, concurrency).with_observer(observer);

    let writer = ActiveWriter {
        file,
        part_path,
        final_path,
        footer,
        footer_buf: [0u8; FOOTER_SIZE],
        min_size,
        target_size,
        write_pos: resumed_bytes,
        since_checkpoint: 0,
    };

    let res: io::Result<()> = async {
        let reader = parallel.fetch_range(resumed_bytes..).await?;
        stream_to_writer(reader, writer, pb.clone()).await
    }
    .await;

    if let Err(e) = res {
        pb.abandon();
        eprintln!();
        return Err(format!("Download failed: {e}").into());
    }

    pb.finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_observer_rewind_debt_and_resumed_speed() {
        let wire_bytes = Arc::new(AtomicU64::new(0));
        let tracker = WireSpeedTracker::new(Arc::clone(&wire_bytes));
        let style = ProgressStyle::with_template(PROGRESS_TEMPLATE)
            .unwrap()
            .with_key("bytes_per_sec", tracker.clone());
        let pb = ProgressBar::hidden().with_style(style);

        // Simulate resuming a 10 GiB file with 10 MiB remaining
        let gib = 1024 * 1024 * 1024_u64;
        let mib = 1024 * 1024_u64;
        let target_size = 10 * gib;
        let resumed_bytes = target_size - 10 * mib;
        pb.set_length(target_size);
        pb.set_position(resumed_bytes);
        pb.reset_eta();

        let obs = CliObserver::new(pb.clone(), Arc::clone(&wire_bytes), false);

        // 1. Rewind debt keeps pb.position() monotonic while wire_bytes counts all wire traffic
        obs.on_bytes(4 * mib);
        assert_eq!(pb.position(), resumed_bytes + 4 * mib);
        assert_eq!(wire_bytes.load(Ordering::Relaxed), 4 * mib);

        obs.on_rewind(mib);
        assert_eq!(pb.position(), resumed_bytes + 4 * mib); // never steps backward

        obs.on_bytes(512 * 1024);
        assert_eq!(pb.position(), resumed_bytes + 4 * mib); // absorbed into debt
        assert_eq!(wire_bytes.load(Ordering::Relaxed), 4 * mib + 512 * 1024);

        obs.on_bytes(512 * 1024 + 6 * mib);
        assert_eq!(pb.position(), target_size);
        assert_eq!(wire_bytes.load(Ordering::Relaxed), 11 * mib); // 10 MiB net + 1 MiB rewound

        // 2. Final rendered speed reflects session wire bytes (~5.5 MiB/s over 2s), not 10 GiB / 2s
        pb.set_elapsed(Duration::from_secs(2));
        pb.finish();

        let mut formatted = String::new();
        pb.update(|state| tracker.write(state, &mut formatted));
        assert!(
            formatted.starts_with("5.5") && formatted.ends_with("MiB/s"),
            "unexpected final speed: {formatted}"
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
