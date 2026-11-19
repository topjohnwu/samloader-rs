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

//! Terminal progress bars, wire-speed estimation, and [`TransferObserver`] integration
//! for firmware downloads.

use indicatif::style::ProgressTracker;
use indicatif::{
    FormattedDuration, HumanBytes, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle,
};
use samloader_fus::{TransferObserver, TransferWarning};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const RAW_PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";
const FILE_PROGRESS_TEMPLATE: &str =
    "{msg}\n[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

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

struct TransferMetrics {
    rem_total_comp: u64,
    wire_bytes: AtomicU64,
    net_comp_bytes: AtomicU64,
    est: Mutex<RateEstimator>,
}

impl TransferMetrics {
    fn new(rem_total_comp: u64) -> Self {
        Self {
            rem_total_comp,
            wire_bytes: AtomicU64::new(0),
            net_comp_bytes: AtomicU64::new(0),
            est: Mutex::new(RateEstimator::new(Instant::now())),
        }
    }

    fn record_bytes(&self, wire_bytes: u64, net_bytes: u64) {
        self.wire_bytes.fetch_add(wire_bytes, Ordering::Relaxed);
        if net_bytes > 0 {
            self.net_comp_bytes.fetch_add(net_bytes, Ordering::Relaxed);
        }
    }

    fn eta(&self, state: &ProgressState) -> Duration {
        if state.is_finished() {
            return Duration::ZERO;
        }
        let done_comp = self.net_comp_bytes.load(Ordering::Relaxed);
        let rem_comp = self.rem_total_comp.saturating_sub(done_comp);
        let rate = self.est.lock().unwrap().bytes_per_sec(Instant::now());
        if rate >= 1.0 {
            Duration::from_secs_f64((rem_comp as f64 / rate).min(u32::MAX as f64))
        } else {
            Duration::ZERO
        }
    }

    fn speed(&self, state: &ProgressState) -> f64 {
        if state.is_finished() {
            let secs = state.elapsed().as_secs_f64();
            if secs > 0.0 {
                self.wire_bytes.load(Ordering::Relaxed) as f64 / secs
            } else {
                0.0
            }
        } else {
            self.est.lock().unwrap().bytes_per_sec(Instant::now())
        }
    }
}

#[derive(Clone)]
struct SpeedTracker {
    metrics: Arc<TransferMetrics>,
}

impl SpeedTracker {
    fn new(metrics: Arc<TransferMetrics>) -> Self {
        Self { metrics }
    }

    fn eta_tracker(&self) -> impl ProgressTracker + use<> {
        let metrics = Arc::clone(&self.metrics);
        move |state: &ProgressState, w: &mut dyn fmt::Write| {
            let _ = write!(w, "{}", FormattedDuration(metrics.eta(state)));
        }
    }
}

impl ProgressTracker for SpeedTracker {
    fn clone_box(&self) -> Box<dyn ProgressTracker> {
        Box::new(self.clone())
    }

    fn tick(&mut self, state: &ProgressState, now: Instant) {
        if !state.is_finished() {
            self.metrics
                .est
                .lock()
                .unwrap()
                .record(self.metrics.wire_bytes.load(Ordering::Relaxed), now);
        }
    }

    fn reset(&mut self, _state: &ProgressState, now: Instant) {
        self.metrics
            .est
            .lock()
            .unwrap()
            .reset(self.metrics.wire_bytes.load(Ordering::Relaxed), now);
    }

    fn write(&self, state: &ProgressState, w: &mut dyn fmt::Write) {
        let _ = write!(w, "{}/s", HumanBytes(self.metrics.speed(state) as u64));
    }
}

/// Display metadata for an extracted archive entry progress bar.
#[derive(Clone, Copy)]
pub(crate) struct FileLabel<'a> {
    pub(crate) name: &'a str,
    pub(crate) index: usize,
    pub(crate) total: usize,
}

struct ActiveTransfer {
    pb: ProgressBar,
    metrics: Arc<TransferMetrics>,
}

/// Shared [`TransferObserver`] routing wire-byte metrics and verbose warnings to the
/// currently active [`TransferProgress`].
pub(crate) struct CliObserver {
    active: Mutex<Option<ActiveTransfer>>,
    verbose: bool,
}

impl CliObserver {
    pub(crate) fn new(verbose: bool) -> Self {
        Self {
            active: Mutex::new(None),
            verbose,
        }
    }

    /// Creates an isolated progress bar for a single file transfer and attaches it to
    /// this observer until the returned [`TransferProgress`] is finished, abandoned,
    /// or dropped.
    pub(crate) fn start_transfer<'a>(
        &'a self,
        label: Option<FileLabel<'a>>,
        target_size: u64,
        rem_total_comp: u64,
        resumed_out: u64,
        restarted: bool,
    ) -> TransferProgress<'a> {
        self.start_transfer_with_target(
            label,
            target_size,
            rem_total_comp,
            resumed_out,
            restarted,
            ProgressDrawTarget::stderr(),
        )
    }

    fn start_transfer_with_target<'a>(
        &'a self,
        label: Option<FileLabel<'a>>,
        target_size: u64,
        rem_total_comp: u64,
        resumed_out: u64,
        restarted: bool,
        target: ProgressDrawTarget,
    ) -> TransferProgress<'a> {
        let metrics = Arc::new(TransferMetrics::new(rem_total_comp));
        let speed_tracker = SpeedTracker::new(Arc::clone(&metrics));
        let eta_tracker = speed_tracker.eta_tracker();
        let template = if label.is_some() {
            FILE_PROGRESS_TEMPLATE
        } else {
            RAW_PROGRESS_TEMPLATE
        };
        let style = ProgressStyle::with_template(template)
            .unwrap()
            .with_key("bytes_per_sec", speed_tracker)
            .with_key("eta_precise", eta_tracker);

        let pb = ProgressBar::with_draw_target(Some(target_size), target).with_style(style);

        if let Some(label) = label {
            pb.set_message(format!(
                "[{}/{}] Extracting {}",
                label.index + 1,
                label.total,
                label.name
            ));
        }

        if restarted {
            pb.println(
                "Existing partial download is incompatible or corrupted, restarting from scratch...",
            );
        }
        if resumed_out > 0 {
            let pct = if target_size > 0 {
                (resumed_out as f64 / target_size as f64) * 100.0
            } else {
                100.0
            };
            pb.println(format!(
                "Resuming: {} / {} ({pct:.1}%) already on disk",
                HumanBytes(resumed_out),
                HumanBytes(target_size),
            ));
            pb.set_position(resumed_out);
        }
        if !pb.is_hidden() {
            pb.enable_steady_tick(Duration::from_secs(1));
        }

        *self.active.lock().unwrap() = Some(ActiveTransfer {
            pb: pb.clone(),
            metrics: Arc::clone(&metrics),
        });

        TransferProgress {
            observer: self,
            pb,
            metrics,
            label,
            target_size,
        }
    }
}

impl TransferObserver for CliObserver {
    fn on_bytes(&self, wire_bytes: u64, net_bytes: u64) {
        if let Some(active) = self.active.lock().unwrap().as_ref() {
            active.metrics.record_bytes(wire_bytes, net_bytes);
        }
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
        let pb = self.active.lock().unwrap().as_ref().map(|a| a.pb.clone());
        if let Some(pb) = pb {
            pb.println(msg);
        } else {
            eprintln!("{msg}");
        }
    }
}

/// RAII handle owning a single file's [`ProgressBar`] and isolated transfer metrics.
///
/// Detaches automatically from [`CliObserver`] when finished, abandoned, or dropped.
pub(crate) struct TransferProgress<'a> {
    observer: &'a CliObserver,
    pb: ProgressBar,
    metrics: Arc<TransferMetrics>,
    label: Option<FileLabel<'a>>,
    target_size: u64,
}

impl TransferProgress<'_> {
    /// Returns a thread-safe callback that advances the progress bar as output bytes
    /// are written to disk.
    pub(crate) fn on_written(&self) -> impl Fn(u64) + Send + 'static {
        let pb = self.pb.clone();
        move |bytes| pb.inc(bytes)
    }

    /// Marks the transfer complete and finishes the bar at `target_size`.
    pub(crate) fn finish(self) {
        self.detach();
        self.pb.set_position(self.target_size);
        if let Some(label) = self.label {
            self.pb.set_message(format!(
                "[{}/{}] Extracted {}",
                label.index + 1,
                label.total,
                label.name
            ));
            self.pb.finish();
            if label.index + 1 < label.total && !self.pb.is_hidden() {
                eprintln!();
            }
        } else {
            self.pb.finish();
        }
    }

    /// Abandons the progress bar after a transfer error.
    pub(crate) fn abandon(self) {
        self.detach();
        if let Some(label) = self.label {
            self.pb.abandon_with_message(format!(
                "[{}/{}] Failed to extract {}",
                label.index + 1,
                label.total,
                label.name
            ));
        } else {
            self.pb.abandon();
        }
        if !self.pb.is_hidden() {
            eprintln!();
        }
    }

    fn detach(&self) {
        let mut active = self.observer.active.lock().unwrap();
        if active
            .as_ref()
            .is_some_and(|a| Arc::ptr_eq(&a.metrics, &self.metrics))
        {
            *active = None;
        }
    }
}

impl Drop for TransferProgress<'_> {
    fn drop(&mut self) {
        self.detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_observer_multi_file_isolation_and_resumed_speed() {
        let gib = 1024 * 1024 * 1024_u64;
        let mib = 1024 * 1024_u64;
        let obs = CliObserver::new(false);

        // Bytes reported outside any active transfer (e.g., ZIP Central Directory reads)
        // are safely ignored.
        obs.on_bytes(64 * 1024, 64 * 1024);

        // File 1: 30 GiB uncompressed (resumed with 30 MiB uncompressed / 10 MiB compressed left).
        let target_uncomp = 30 * gib;
        let resumed_uncomp = target_uncomp - 30 * mib;
        let p1 = obs.start_transfer_with_target(
            Some(FileLabel {
                name: "AP.tar.md5",
                index: 0,
                total: 2,
            }),
            target_uncomp,
            10 * mib,
            resumed_uncomp,
            false,
            ProgressDrawTarget::hidden(),
        );
        let pb1 = p1.pb.clone();
        let m1 = Arc::clone(&p1.metrics);

        obs.on_bytes(4 * mib, 4 * mib);
        assert_eq!(m1.wire_bytes.load(Ordering::Relaxed), 4 * mib);
        assert_eq!(m1.net_comp_bytes.load(Ordering::Relaxed), 4 * mib);

        // Verify live ETA tracker reflects remaining compressed bytes (6 MiB) / wire rate (2 MiB/s) = 3s.
        {
            let now = Instant::now();
            let mut est = m1.est.lock().unwrap();
            est.reset(0, now - Duration::from_secs(2));
            est.record(4 * mib, now);
        }
        let eta1 = SpeedTracker::new(Arc::clone(&m1)).eta_tracker();
        let mut live_eta = String::new();
        pb1.update(|state| eta1.write(state, &mut live_eta));
        assert_eq!(live_eta, "00:00:03");

        // Simulate 1 MiB of retried wire traffic (wire increases, net does not).
        obs.on_bytes(mib, 0);
        obs.on_bytes(6 * mib, 6 * mib);
        assert_eq!(m1.wire_bytes.load(Ordering::Relaxed), 11 * mib);
        assert_eq!(m1.net_comp_bytes.load(Ordering::Relaxed), 10 * mib);

        let on_written1 = p1.on_written();
        on_written1(30 * mib);
        assert_eq!(pb1.position(), target_uncomp);
        pb1.set_elapsed(Duration::from_secs(2));
        p1.finish();
        assert!(obs.active.lock().unwrap().is_none());

        let mut finished_eta = String::new();
        pb1.update(|state| eta1.write(state, &mut finished_eta));
        assert_eq!(finished_eta, "00:00:00");

        // File 2: Starts with completely fresh, isolated metrics.
        let p2 = obs.start_transfer_with_target(
            Some(FileLabel {
                name: "BL.tar.md5",
                index: 1,
                total: 2,
            }),
            16 * mib,
            8 * mib,
            0,
            false,
            ProgressDrawTarget::hidden(),
        );
        let pb2 = p2.pb.clone();
        let m2 = Arc::clone(&p2.metrics);
        assert_eq!(m2.wire_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(m2.net_comp_bytes.load(Ordering::Relaxed), 0);

        obs.on_bytes(8 * mib, 8 * mib);
        p2.on_written()(16 * mib);
        pb2.set_elapsed(Duration::from_secs(1));
        p2.finish();
        assert!(obs.active.lock().unwrap().is_none());

        // File 1's finished speed remains intact (5.5 MiB/s) even after File 2 completed!
        let tracker1 = SpeedTracker::new(m1);
        let mut formatted1 = String::new();
        pb1.update(|state| tracker1.write(state, &mut formatted1));
        assert!(
            formatted1.starts_with("5.5") && formatted1.ends_with("MiB/s"),
            "unexpected file 1 final speed: {formatted1}"
        );

        let tracker2 = SpeedTracker::new(m2);
        let mut formatted2 = String::new();
        pb2.update(|state| tracker2.write(state, &mut formatted2));
        assert!(
            formatted2.starts_with("8.0") && formatted2.ends_with("MiB/s"),
            "unexpected file 2 final speed: {formatted2}"
        );

        // Dropping an unfinished TransferProgress detaches automatically via RAII.
        {
            let _p3 = obs.start_transfer_with_target(
                None,
                1024,
                1024,
                0,
                false,
                ProgressDrawTarget::hidden(),
            );
            assert!(obs.active.lock().unwrap().is_some());
        }
        assert!(obs.active.lock().unwrap().is_none());
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
