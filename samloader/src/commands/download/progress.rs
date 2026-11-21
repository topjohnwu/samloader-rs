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

//! Terminal progress bars, sliding-window speed/ETA estimation, and [`TransferObserver`]
//! integration for firmware downloads.

use indicatif::{
    FormattedDuration, HumanBytes, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle,
};
use samloader_fus::{TransferObserver, TransferWarning};
use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

const RAW_PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";
const FILE_PROGRESS_TEMPLATE: &str =
    "{msg}\n[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

const SPEED_WINDOW: Duration = Duration::from_secs(3);
const SAMPLE_STEP: Duration = Duration::from_millis(250);

#[derive(Clone, Copy)]
struct RateSample {
    at: Instant,
    wire: u64,
    net: u64,
    out: u64,
}

#[derive(Clone, Copy)]
struct Rates {
    wire_bps: f64,
    net_bps: f64,
    out_bps: f64,
}

struct RateWindow {
    samples: VecDeque<RateSample>,
}

impl RateWindow {
    fn new(now: Instant, initial_out: u64) -> Self {
        let mut samples = VecDeque::with_capacity(16);
        samples.push_back(RateSample {
            at: now,
            wire: 0,
            net: 0,
            out: initial_out,
        });
        Self { samples }
    }

    fn record(&mut self, now: Instant, wire: u64, net: u64, out: u64) {
        if self
            .samples
            .back()
            .is_none_or(|last| now.saturating_duration_since(last.at) >= SAMPLE_STEP)
        {
            self.samples.push_back(RateSample {
                at: now,
                wire,
                net,
                out,
            });
            while self.samples.len() > 2
                && now.saturating_duration_since(self.samples[1].at) >= SPEED_WINDOW
            {
                self.samples.pop_front();
            }
        }
    }

    fn rates(&self, now: Instant, wire: u64, net: u64, out: u64) -> Rates {
        let Some(oldest) = self.samples.front() else {
            return Rates {
                wire_bps: 0.0,
                net_bps: 0.0,
                out_bps: 0.0,
            };
        };
        let dt = now.saturating_duration_since(oldest.at).as_secs_f64();
        if dt <= f64::EPSILON {
            return Rates {
                wire_bps: 0.0,
                net_bps: 0.0,
                out_bps: 0.0,
            };
        }
        Rates {
            wire_bps: wire.saturating_sub(oldest.wire) as f64 / dt,
            net_bps: net.saturating_sub(oldest.net) as f64 / dt,
            out_bps: out.saturating_sub(oldest.out) as f64 / dt,
        }
    }
}

struct TransferMetrics {
    rem_total_comp: u64,
    wire_bytes: AtomicU64,
    net_comp_bytes: AtomicU64,
    window: Mutex<RateWindow>,
}

impl TransferMetrics {
    fn new(rem_total_comp: u64, resumed_out: u64) -> Self {
        Self {
            rem_total_comp,
            wire_bytes: AtomicU64::new(0),
            net_comp_bytes: AtomicU64::new(0),
            window: Mutex::new(RateWindow::new(Instant::now(), resumed_out)),
        }
    }

    fn record_bytes(&self, wire_bytes: u64, net_bytes: u64) {
        self.wire_bytes.fetch_add(wire_bytes, Ordering::Relaxed);
        if net_bytes > 0 {
            self.net_comp_bytes.fetch_add(net_bytes, Ordering::Relaxed);
        }
    }

    fn sample_rates(&self, state: &ProgressState, now: Instant) -> Rates {
        let wire = self.wire_bytes.load(Ordering::Relaxed);
        let net = self.net_comp_bytes.load(Ordering::Relaxed);
        let out = state.pos();
        let mut window = self.window.lock().unwrap();
        window.record(now, wire, net, out);
        window.rates(now, wire, net, out)
    }

    fn eta(&self, state: &ProgressState, now: Instant) -> Option<Duration> {
        if state.is_finished() {
            return Some(Duration::ZERO);
        }
        let done_comp = self.net_comp_bytes.load(Ordering::Relaxed);
        let rem_comp = self.rem_total_comp.saturating_sub(done_comp);
        let rem_out = state.len().unwrap_or(0).saturating_sub(state.pos());
        let rates = self.sample_rates(state, now);

        let (remaining, rate) = if rem_comp > 0 {
            // Use net compressed goodput so retried traffic does not make ETA optimistic.
            (rem_comp, rates.net_bps)
        } else if rem_out > 0 {
            // Network prefetch finished; estimate remaining decompression/disk drain time.
            (rem_out, rates.out_bps)
        } else {
            return Some(Duration::ZERO);
        };

        (rate >= 1.0)
            .then(|| Duration::from_secs_f64((remaining as f64 / rate).min(u32::MAX as f64)))
    }

    fn speed(&self, state: &ProgressState, now: Instant) -> f64 {
        if state.is_finished() {
            let secs = state.elapsed().as_secs_f64();
            if secs > 0.0 {
                self.wire_bytes.load(Ordering::Relaxed) as f64 / secs
            } else {
                0.0
            }
        } else {
            self.sample_rates(state, now).wire_bps
        }
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
    active: RwLock<Option<ActiveTransfer>>,
    verbose: bool,
}

impl CliObserver {
    pub(crate) fn new(verbose: bool) -> Self {
        Self {
            active: RwLock::new(None),
            verbose,
        }
    }

    /// Creates an isolated progress bar for a single file transfer and attaches it to
    /// this observer until the returned [`TransferProgress`] is finished, abandoned,
    /// interrupted, or dropped.
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
        let metrics = Arc::new(TransferMetrics::new(rem_total_comp, resumed_out));
        let speed_metrics = Arc::clone(&metrics);
        let eta_metrics = Arc::clone(&metrics);
        let template = if label.is_some() {
            FILE_PROGRESS_TEMPLATE
        } else {
            RAW_PROGRESS_TEMPLATE
        };
        let style = ProgressStyle::with_template(template)
            .unwrap()
            .with_key(
                "bytes_per_sec",
                move |state: &ProgressState, w: &mut dyn fmt::Write| {
                    let speed = speed_metrics.speed(state, Instant::now());
                    let _ = write!(w, "{}/s", HumanBytes(speed as u64));
                },
            )
            .with_key(
                "eta_precise",
                move |state: &ProgressState, w: &mut dyn fmt::Write| match eta_metrics
                    .eta(state, Instant::now())
                {
                    Some(dur) => {
                        let _ = write!(w, "{}", FormattedDuration(dur));
                    }
                    None => {
                        let _ = w.write_str("--:--:--");
                    }
                },
            );

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
            pb.set_position(resumed_out);
            pb.println(format!(
                "Resuming: {} / {} ({pct:.1}%) already on disk",
                HumanBytes(resumed_out),
                HumanBytes(target_size),
            ));
        }
        if !pb.is_hidden() {
            pb.enable_steady_tick(Duration::from_secs(1));
        }

        *self.active.write().unwrap() = Some(ActiveTransfer {
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
        if let Some(active) = self.active.read().unwrap().as_ref() {
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
            other => format!("Download warning: {other:?}"),
        };
        let pb = self.active.read().unwrap().as_ref().map(|a| a.pb.clone());
        if let Some(pb) = pb {
            pb.println(msg);
        } else {
            eprintln!("{msg}");
        }
    }
}

/// RAII handle owning a single file's [`ProgressBar`] and isolated transfer metrics.
///
/// Detaches automatically from [`CliObserver`] when finished, abandoned, interrupted,
/// or dropped.
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
        self.abandon_with("Failed to extract");
    }

    /// Abandons the progress bar after user interruption (e.g. Ctrl-C).
    pub(crate) fn interrupt(self) {
        self.abandon_with("Interrupted");
    }

    fn abandon_with(self, verb: &str) {
        self.detach();
        if let Some(label) = self.label {
            self.pb.abandon_with_message(format!(
                "[{}/{}] {verb} {}",
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
        let mut active = self.observer.active.write().unwrap();
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

    fn format_eta(pb: &ProgressBar, metrics: &TransferMetrics, now: Instant) -> String {
        let mut out = String::new();
        pb.update(|state| match metrics.eta(state, now) {
            Some(dur) => {
                use fmt::Write;
                let _ = write!(out, "{}", FormattedDuration(dur));
            }
            None => out.push_str("--:--:--"),
        });
        out
    }

    fn format_speed(pb: &ProgressBar, metrics: &TransferMetrics, now: Instant) -> String {
        let mut out = String::new();
        pb.update(|state| {
            use fmt::Write;
            let _ = write!(out, "{}/s", HumanBytes(metrics.speed(state, now) as u64));
        });
        out
    }

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

        // Before any bytes/rate arrive, ETA displays "--:--:--" instead of "00:00:00".
        assert_eq!(format_eta(&pb1, &m1, Instant::now()), "--:--:--");

        // Simulate 4 MiB net compressed + 4 MiB retried wire traffic (8 MiB wire total over 2s).
        // Net goodput is 2 MiB/s -> remaining 6 MiB compressed yields ETA of 3s (not skewed by retries).
        obs.on_bytes(4 * mib, 4 * mib);
        obs.on_bytes(4 * mib, 0);
        assert_eq!(m1.wire_bytes.load(Ordering::Relaxed), 8 * mib);
        assert_eq!(m1.net_comp_bytes.load(Ordering::Relaxed), 4 * mib);

        let now = Instant::now();
        *m1.window.lock().unwrap() = RateWindow::new(now - Duration::from_secs(2), resumed_uncomp);
        assert_eq!(format_eta(&pb1, &m1, now), "00:00:03");
        assert!(format_speed(&pb1, &m1, now).starts_with("4.0"));

        // Network finishes prefetching remaining 6 MiB compressed while 20 MiB of output
        // still remain to drain at 10 MiB/s -> ETA falls back to output drain rate (2s).
        obs.on_bytes(6 * mib, 6 * mib);
        assert_eq!(m1.wire_bytes.load(Ordering::Relaxed), 14 * mib);
        assert_eq!(m1.net_comp_bytes.load(Ordering::Relaxed), 10 * mib);
        let on_written1 = p1.on_written();
        on_written1(10 * mib);
        *m1.window.lock().unwrap() = RateWindow::new(now - Duration::from_secs(1), resumed_uncomp);
        assert_eq!(format_eta(&pb1, &m1, now), "00:00:02");

        on_written1(20 * mib);
        assert_eq!(pb1.position(), target_uncomp);
        pb1.set_elapsed(Duration::from_secs(2));
        p1.finish();
        assert!(obs.active.read().unwrap().is_none());
        assert_eq!(format_eta(&pb1, &m1, Instant::now()), "00:00:00");

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
        assert!(obs.active.read().unwrap().is_none());

        // File 1's finished speed remains intact (7.0 MiB/s) even after File 2 completed!
        let formatted1 = format_speed(&pb1, &m1, Instant::now());
        assert!(
            formatted1.starts_with("7.0") && formatted1.ends_with("MiB/s"),
            "unexpected file 1 final speed: {formatted1}"
        );

        let formatted2 = format_speed(&pb2, &m2, Instant::now());
        assert!(
            formatted2.starts_with("8.0") && formatted2.ends_with("MiB/s"),
            "unexpected file 2 final speed: {formatted2}"
        );

        // Interrupting or dropping an unfinished TransferProgress detaches automatically.
        let p_int = obs.start_transfer_with_target(
            None,
            1024,
            1024,
            0,
            false,
            ProgressDrawTarget::hidden(),
        );
        assert!(obs.active.read().unwrap().is_some());
        p_int.interrupt();
        assert!(obs.active.read().unwrap().is_none());

        {
            let _p3 = obs.start_transfer_with_target(
                None,
                1024,
                1024,
                0,
                false,
                ProgressDrawTarget::hidden(),
            );
            assert!(obs.active.read().unwrap().is_some());
        }
        assert!(obs.active.read().unwrap().is_none());
    }

    #[test]
    fn test_rate_window_high_frequency_convergence_and_stall() {
        let mib = 1024 * 1024_u64;
        let t0 = Instant::now();
        let mut window = RateWindow::new(t0, 0);
        let mut total = 0_u64;

        // 5 seconds at 400 MiB/s sampled at 20 Hz (every 50 ms, faster than SAMPLE_STEP).
        for step in 1..=100 {
            total += 20 * mib;
            let now = t0 + Duration::from_millis(50 * step);
            window.record(now, total, total, total);
        }
        let burst = window
            .rates(t0 + Duration::from_secs(5), total, total, total)
            .wire_bps
            / mib as f64;
        assert!((burst - 400.0).abs() < 1.0, "burst={burst}");

        // Drop abruptly to 80 MiB/s at 20 Hz: after 3s, sliding window must still slide
        // and settle directly at 80 MiB/s (not stay anchored at t0).
        for step in 101..=160 {
            total += 4 * mib;
            let now = t0 + Duration::from_millis(50 * step);
            window.record(now, total, total, total);
        }
        let settled = window
            .rates(t0 + Duration::from_secs(8), total, total, total)
            .wire_bps
            / mib as f64;
        assert!(
            (settled - 80.0).abs() < 1.0,
            "expected convergence at 80 MiB/s, got {settled}"
        );

        // Complete stall for 3s drops rate back to 0 B/s.
        for step in 161..=220 {
            let now = t0 + Duration::from_millis(50 * step);
            window.record(now, total, total, total);
        }
        let stalled = window
            .rates(t0 + Duration::from_secs(11), total, total, total)
            .wire_bps;
        assert_eq!(stalled, 0.0);
    }
}
