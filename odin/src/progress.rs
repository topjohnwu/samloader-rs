// Copyright 2026 John Wu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::compat::{MaybeSend, MaybeSync};

/// Events reported by the crate, from connecting to a device to flashing and
/// verifying firmware.
///
/// Lower layers report their progress as events rather than messages, so
/// frontends decide how to present it.
#[derive(Debug)]
#[non_exhaustive]
pub enum FlashEvent<'a> {
    /// No device is connected yet, and it is being waited for.
    WaitingForDevice,
    /// The Odin handshake with the device has started.
    HandshakeStart,
    /// The Odin handshake has succeeded.
    HandshakeEnd,
    /// An Odin session is being requested from the device.
    SessionStart,
    /// The device accepted the session, which is now being set up. Some
    /// devices take up to 2 minutes to respond from here on.
    SessionSetup,
    /// The session is ready for commands.
    SessionReady,
    /// The session is being ended.
    SessionEnd,
    /// The device is being rebooted.
    Reboot {
        /// Whether the device reboots into Download Mode rather than normally.
        download: bool,
    },
    /// The USERDATA partition is being erased.
    EraseStart,
    /// The USERDATA partition has been erased.
    EraseEnd {
        /// The number of erased sectors reported by the device.
        sectors: u32,
    },
    /// Partition flashing has started.
    PartitionStart {
        /// Name of the partition being flashed.
        name: &'a str,
        /// Size of the partition payload in bytes.
        size: u64,
    },
    /// Partition flashing completed successfully.
    PartitionEnd(&'a str),
    /// Partition flashing failed.
    PartitionFail(&'a str),
    /// MD5 verification for a package has started.
    Md5Start {
        /// Name of the package file being verified.
        name: &'a str,
        /// Total payload size to hash in bytes.
        size: u64,
    },
    /// MD5 verification completed successfully.
    Md5End(&'a str),
    /// MD5 verification failed.
    Md5Fail(&'a str),
}

/// A trait for reporting partition flash/upload progress and status messages.
///
/// Besides progress and lifecycle events, reporters also receive the crate's log
/// and diagnostic messages. This is deliberate: frontends such as a web app can
/// show them in their own UI, which the `log` crate makes difficult on WASM as
/// its loggers must be `Send + Sync` and cannot hold JavaScript callbacks.
///
/// Implementations must be `Send + Sync` on non-WASM targets. On WASM, these
/// bounds are lifted so implementations can hold JavaScript values.
pub trait FlashProgress: MaybeSend + MaybeSync {
    /// Sets the total length of the progress (in bytes).
    fn set_length(&self, _len: u64) {}

    /// Increments the progress by the specified number of bytes.
    fn inc(&self, _bytes: u64) {}

    /// Prints a standard log or status message.
    fn println(&self, _msg: &str) {}

    /// Prints a verbose log or status message (implementation decides if it is shown).
    fn println_verbose(&self, _msg: &str) {}

    /// Returns whether verbose messages are shown. Used to skip collecting
    /// diagnostics that are expensive to obtain (e.g. USB string descriptors).
    fn is_verbose(&self) -> bool {
        false
    }

    /// Prints a verbose diagnostic message from the USB device and transport layers.
    /// Defaults to [`println_verbose`](Self::println_verbose).
    fn eprintln_verbose(&self, msg: &str) {
        self.println_verbose(msg);
    }

    /// Handles a flashing or verification lifecycle event.
    fn on_event(&self, _event: FlashEvent<'_>) {}
}

impl FlashProgress for () {}

#[cfg(not(target_arch = "wasm32"))]
static GLOBAL_PROGRESS: std::sync::RwLock<Option<Box<dyn FlashProgress>>> =
    std::sync::RwLock::new(None);

// Reporters are not required to be `Sync` on WASM, so they cannot be stored in
// a static. Instead, each thread has its own reporter.
#[cfg(target_arch = "wasm32")]
thread_local! {
    static GLOBAL_PROGRESS: std::cell::RefCell<Option<Box<dyn FlashProgress>>> =
        const { std::cell::RefCell::new(None) };
}

/// Sets the global progress reporter.
///
/// The reporter is global rather than passed to each operation, so progress can be
/// reported from anywhere in the crate, down to individual USB transfers. This
/// assumes a single flash at a time per process. On WASM, the reporter is only
/// active on the calling thread, allowing one flash per thread.
pub fn set_progress(progress: impl FlashProgress + 'static) {
    replace_progress(Some(Box::new(progress)));
}

/// Clears the global progress reporter, reverting to no-op.
pub fn clear_progress() {
    replace_progress(None);
}

#[cfg(not(target_arch = "wasm32"))]
fn replace_progress(progress: Option<Box<dyn FlashProgress>>) {
    let mut lock = GLOBAL_PROGRESS.write().unwrap();
    *lock = progress;
}

#[cfg(target_arch = "wasm32")]
fn replace_progress(progress: Option<Box<dyn FlashProgress>>) {
    // Drop the previous reporter after releasing the borrow, in case its
    // destructor reports progress.
    let _old = GLOBAL_PROGRESS.replace(progress);
}

/// Invokes a closure with a reference to the active global progress reporter,
/// falling back to a no-op reporter if none is configured.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn with_progress<R>(f: impl FnOnce(&dyn FlashProgress) -> R) -> R {
    if let Ok(guard) = GLOBAL_PROGRESS.read()
        && let Some(p) = guard.as_deref()
    {
        return f(p);
    }
    f(&())
}

/// Invokes a closure with a reference to the active global progress reporter,
/// falling back to a no-op reporter if none is configured.
#[cfg(target_arch = "wasm32")]
pub(crate) fn with_progress<R>(f: impl FnOnce(&dyn FlashProgress) -> R) -> R {
    GLOBAL_PROGRESS.with_borrow(|p| match p.as_deref() {
        Some(p) => f(p),
        None => f(&()),
    })
}

/// Sets the total length of the active progress (in bytes).
pub(crate) fn set_length(len: u64) {
    with_progress(|p| p.set_length(len));
}

/// Increments the active progress by the specified number of bytes.
pub(crate) fn inc(bytes: u64) {
    with_progress(|p| p.inc(bytes));
}

/// Prints a standard message through the active progress reporter.
pub(crate) fn println(msg: &str) {
    with_progress(|p| p.println(msg));
}

/// Prints a verbose message through the active progress reporter.
pub(crate) fn println_verbose(msg: &str) {
    with_progress(|p| p.println_verbose(msg));
}

/// Returns whether verbose messages are shown through the active progress reporter.
#[cfg(feature = "rusb")]
pub(crate) fn is_verbose() -> bool {
    with_progress(|p| p.is_verbose())
}

/// Prints a verbose diagnostic message from the USB device and transport layers
/// through the active progress reporter.
pub(crate) fn eprintln_verbose(msg: &str) {
    with_progress(|p| p.eprintln_verbose(msg));
}

/// Dispatches a flashing lifecycle event through the active progress reporter.
pub(crate) fn on_event(event: FlashEvent<'_>) {
    with_progress(|p| p.on_event(event));
}

#[cfg(test)]
pub(crate) static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
